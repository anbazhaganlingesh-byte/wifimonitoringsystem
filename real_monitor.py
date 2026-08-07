"""
Phase 2 real hotspot device monitor (Windows).

Replaces simulator.py's fabricated devices with actual devices discovered
on the local network. Runs in a background thread on the same interval
pattern the old simulator used, and writes into the same Device table --
no other code (routes, templates, dashboard.js) needs to change.

Two discovery strategies, tried in order:

  1. Active ARP sweep via scapy. Fast and reliable, but needs Npcap
     installed and usually needs the app run from an elevated
     ("Run as administrator") terminal on Windows.
  2. Fallback: a plain ping sweep across the local /24 using the OS
     `ping` command (no admin rights needed) to populate Windows' ARP
     cache, then parsing `arp -a`. Slower, and only finds devices that
     answer a ping, but works without elevation.

Note: this only *detects* devices (IP, MAC, hostname, connected/
disconnected). Actually cutting a device's access or logging real site
visits would require integrating with your router/hostapd -- that part
is still simulated, same as before.
"""

import ipaddress
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from models import db, Device

# Matches lines from Windows `arp -a` output, e.g.:
#   192.168.4.10          aa-bb-cc-00-11-01     dynamic
ARP_LINE_RE = re.compile(
    r'^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)',
    re.MULTILINE,
)

IGNORED_MACS = {'ff-ff-ff-ff-ff-ff', '00-00-00-00-00-00'}

# How many consecutive scans a device can go "missing" before we actually
# mark it disconnected. Ping replies are unreliable (firewalls, doze mode,
# sleeping Wi-Fi radios), so a single miss doesn't mean much on its own --
# this absorbs that noise instead of flapping the status every scan.
MISS_THRESHOLD = 2


class RealNetworkMonitor:
    def __init__(self, app, interval_seconds=5):
        self.app = app
        self.interval = interval_seconds
        self.running = False
        self._thread = None
        self._local_mac = None
        self._miss_counts = {}  # mac -> consecutive scans missed

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        with self.app.app_context():
            print("[real_monitor] started -- scanning local subnet every "
                  f"{self.interval}s")
            while self.running:
                try:
                    self._tick()
                except Exception as exc:  # keep the monitor alive on transient errors
                    print(f"[real_monitor] scan error: {exc}")
                time.sleep(self.interval)

    # ---------- one scan pass ----------

    def _tick(self):
        local_hostname = socket.gethostname().lower()
        exclude_ips = self._local_ips()
        subnets = self._local_subnets()  # {subnet: our own IP on that subnet}

        raw = {}
        for subnet, iface_ip in subnets.items():
            sub_raw = self._scan_scapy(subnet, iface_ip)
            source = 'scapy'
            if sub_raw is None:
                sub_raw = self._scan_ping_arp(subnet)
                source = 'ping+arp'
            print(f"[real_monitor] ({source}) raw ARP results on {subnet} "
                  f"via {iface_ip}: {sub_raw if sub_raw else '(none)'}")
            raw.update(sub_raw)

        print(f"[real_monitor] excluding self IPs: {exclude_ips}")

        found = {
            mac: ip for mac, ip in raw.items()
            if mac not in IGNORED_MACS and ip not in exclude_ips
        }

        seen_macs = set()
        for mac, ip in found.items():
            mac_fmt = mac.upper().replace('-', ':')
            hostname = self._resolve_hostname(ip)
            # Extra safety net: a resolved hostname matching this machine's
            # own hostname means we're looking at ourselves on a second
            # adapter, not a real client -- skip it.
            if hostname and hostname.lower() == local_hostname:
                print(f"[real_monitor] skipping {ip} ({mac_fmt}) -- "
                      f"hostname '{hostname}' matches this machine")
                continue
            seen_macs.add(mac_fmt)
            self._miss_counts[mac_fmt] = 0
            self._upsert_device(mac_fmt, ip, hostname)
            print(f"[real_monitor] client: {ip} {mac_fmt} "
                  f"hostname={hostname or '(none)'}")

        print(f"[real_monitor] {len(seen_macs)} real client(s) this pass")

        # Only flip a device to disconnected after it's been missing for
        # several scans in a row -- a single missed ping is normal noise,
        # not proof the device left the network.
        for dev in Device.query.filter_by(status='connected').all():
            if dev.mac in seen_macs:
                continue
            misses = self._miss_counts.get(dev.mac, 0) + 1
            self._miss_counts[dev.mac] = misses
            if misses >= MISS_THRESHOLD:
                dev.status = 'disconnected'

        db.session.commit()

    def _upsert_device(self, mac_fmt, ip, hostname):
        dev = Device.query.filter_by(mac=mac_fmt).first()

        if not dev:
            dev = Device(
                mac=mac_fmt,
                ip=ip,
                hostname=hostname or "Unknown Device",
                status='connected',
            )
            db.session.add(dev)
        else:
            dev.ip = ip
            dev.status = 'connected'
            dev.last_seen = datetime.utcnow()
            if hostname:
                dev.hostname = hostname
            elif not dev.hostname:
                dev.hostname = "Unknown Device"

    @staticmethod
    def _resolve_hostname(ip):
        """Reverse-DNS lookup. Most consumer routers don't register these,
        so this often comes back empty -- that's expected, not a bug."""
        try:
            socket.setdefaulttimeout(0.5)
            name, _, _ = socket.gethostbyaddr(ip)
            return name.split('.')[0]
        except Exception:
            return None
        finally:
            socket.setdefaulttimeout(None)

    @staticmethod
    def _local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except Exception:
            return socket.gethostbyname(socket.gethostname())
        finally:
            s.close()

    @staticmethod
    def _local_ips():
        """Every IPv4 address bound to this machine, across every adapter --
        Wi-Fi/Ethernet uplink *and* the Mobile Hotspot's own virtual adapter
        (always 192.168.137.1 on Windows). Used so the host machine never
        shows up in the dashboard as if it were a connected client."""
        ips = {RealNetworkMonitor._local_ip()}
        try:
            hostname = socket.gethostname()
            _, _, addrs = socket.gethostbyname_ex(hostname)
            ips.update(addrs)
        except Exception:
            pass
        try:
            output = subprocess.run(
                ['ipconfig'], capture_output=True, text=True, timeout=5
            ).stdout
            ips.update(re.findall(r'IPv4 Address[.\s]*:\s*([\d.]+)', output))
        except Exception:
            pass
        return ips

    @staticmethod
    def _local_subnets():
    	"""
    	Scan only the Windows Mobile Hotspot network (192.168.137.0/24).
    	"""
    	hotspot_net = ipaddress.ip_network("192.168.137.0/24")
    	return {
        	hotspot_net: "192.168.137.1"
    	}

	# ---------- strategy 1: scapy active ARP sweep ----------

    def _scan_scapy(self, subnet, iface_ip=None):
        try:
            from scapy.all import ARP, Ether, srp
        except Exception:
            return None  # scapy not installed -- fall back silently

        # Without this, scapy picks one "default" adapter for every scan,
        # so requests meant for the Mobile Hotspot's virtual adapter can
        # silently go out a completely different physical NIC and never
        # reach any connected phone. Resolving the actual Windows adapter
        # name for our IP on this subnet and binding to it fixes that.
        iface_name = None
        if iface_ip:
            try:
                from scapy.arch.windows import get_windows_if_list
                for iface in get_windows_if_list():
                    if iface_ip in iface.get('ips', []):
                        iface_name = iface.get('name')
                        break
                if not iface_name:
                    print(f"[real_monitor] no adapter found for {iface_ip} -- "
                          "scanning with scapy's default interface instead")
            except Exception as exc:
                print(f"[real_monitor] couldn't resolve adapter for "
                      f"{iface_ip}: {exc}")

        try:
            request = ARP(pdst=str(subnet))
            broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
            kwargs = {'timeout': 2, 'verbose': False}
            if iface_name:
                kwargs['iface'] = iface_name
            answered, _ = srp(broadcast / request, **kwargs)
        except Exception as exc:
            # Usually means Npcap is missing or the process isn't elevated
            print(f"[real_monitor] scapy scan unavailable ({exc}); "
                  "falling back to ping+arp. Run as Administrator to enable it.")
            return None

        return {received.hwsrc.lower(): received.psrc for _, received in answered}

    # ---------- strategy 2: ping sweep + `arp -a` (no admin needed) ----------

    def _scan_ping_arp(self, subnet):
        hosts = [str(h) for h in subnet.hosts()]
        with ThreadPoolExecutor(max_workers=64) as pool:
            list(pool.map(self._ping_once, hosts))

        try:
            output = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True, timeout=10
            ).stdout
        except Exception as exc:
            print(f"[real_monitor] 'arp -a' failed: {exc}")
            return {}

        results = {}
        for ip, mac, entry_type in ARP_LINE_RE.findall(output):
            if entry_type.lower() != 'dynamic':
                continue
            results[mac.lower()] = ip
        return results

    @staticmethod
    def _ping_once(ip):
        try:
            subprocess.run(
                ['ping', '-n', '2', '-w', '300', ip],
                capture_output=True, timeout=3,
            )
        except Exception:
            pass
        # Many phones (especially iOS) silently drop ICMP echo requests
        # even while fully connected and active, so ping alone misses
        # them. But ARP resolution happens at layer 2 before any IP-level
        # protocol even runs -- so attempting a TCP connection (even one
        # that gets refused or times out) still forces Windows to ARP the
        # target and populate the cache we read afterward. This catches
        # devices ping alone would miss.
        for port in (80, 443, 445, 62078):  # 62078 = iOS lockdownd
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    s.connect_ex((ip, port))
            except Exception:
                pass