"""
Phase 1 virtual hotspot simulator.

In the final version, this module is replaced by real hostapd/dnsmasq log
parsing running on a Raspberry Pi. For now it fabricates realistic device
connect/disconnect events and DNS-style visits so the rest of the system
(database, dashboard, blocking logic) can be built and demoed end-to-end.
"""

import random
import threading
import time
from datetime import datetime

from models import db, Device, Visit, BlockRule

# Fake/demo devices used to be seeded here (Rahuls-iPhone, Priya-Laptop, etc.)
# so the dashboard had something to show during early development. That
# fabricated seed list has been removed — the simulator now only acts on
# whatever devices already exist in the database (e.g. real ones added by
# real_monitor.py once that's implemented). It no longer invents any of
# its own.
VIRTUAL_DEVICES = []

DOMAIN_POOL = [
    "youtube.com", "facebook.com", "instagram.com", "wikipedia.org",
    "github.com", "whatsapp.com", "netflix.com", "amazon.in",
    "twitter.com", "linkedin.com", "reddit.com", "spotify.com",
    "google.com", "stackoverflow.com", "chatgpt.com", "flipkart.com",
]


class HotspotSimulator:
    def __init__(self, app, interval_seconds=4):
        self.app = app
        self.interval = interval_seconds
        self.running = False
        self._thread = None

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
            self._ensure_devices()
            while self.running:
                try:
                    self._tick()
                except Exception as exc:  # keep the simulator alive on transient errors
                    print(f"[simulator] tick error: {exc}")
                time.sleep(self.interval)

    def _ensure_devices(self):
        for vd in VIRTUAL_DEVICES:
            dev = Device.query.filter_by(mac=vd['mac']).first()
            if not dev:
                dev = Device(
                    mac=vd['mac'],
                    hostname=vd['hostname'],
                    ip=self._random_ip(),
                    status='disconnected',
                )
                db.session.add(dev)
        db.session.commit()

    @staticmethod
    def _random_ip():
        return f"192.168.4.{random.randint(10, 250)}"

    def _tick(self):
        devices = Device.query.all()
        blocked_domains = {r.target for r in BlockRule.query.filter_by(rule_type='domain').all()}
        blocked_macs = {r.target for r in BlockRule.query.filter_by(rule_type='device').all()}

        for dev in devices:
            roll = random.random()

            if dev.status == 'disconnected':
                if roll < 0.25:
                    dev.status = 'connected'
                    dev.ip = self._random_ip()
                    dev.last_seen = datetime.utcnow()
                continue

            # currently connected
            if roll < 0.08:
                dev.status = 'disconnected'
                continue

            dev.last_seen = datetime.utcnow()
            domain = random.choice(DOMAIN_POOL)
            is_blocked = (
                domain in blocked_domains
                or dev.mac in blocked_macs
                or dev.is_blocked
            )
            db.session.add(Visit(device_id=dev.id, domain=domain, blocked=is_blocked))

        db.session.commit()
