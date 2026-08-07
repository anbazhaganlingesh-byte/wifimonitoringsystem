# GuardSpot — Hotspot Access Manager (Phase 1)

A secure web dashboard for monitoring devices on a WiFi hotspot and simulating
website/device blocking, built as a semester project. This is **Phase 1**:
a virtual hotspot simulator stands in for a real Raspberry Pi + hostapd/dnsmasq
setup, and "blocking" updates the database/UI only — it does not yet touch
real network traffic. Phase 2 swaps the simulator for real DNS log parsing
and real `iptables`/`nftables` enforcement.

## What it does

- Simulates devices connecting/disconnecting to a hotspot (IP, MAC, hostname)
- Simulates DNS-style browsing activity per device
- Stores everything in a database (devices, visit history, block rules, audit log)
- Lets an authenticated admin block a **website** or a **device** — status
  updates instantly in the UI as "Blocked (Simulation)"
- Full audit trail of every login and every block/unblock action

## Project structure

```
guardspot/
├── app.py              # Flask app, routes, auth, API
├── models.py           # Database models (SQLAlchemy)
├── simulator.py         # Virtual hotspot / device simulator (Phase 1 stand-in)
├── forms.py             # Login form (CSRF-protected)
├── config.py            # App configuration from environment variables
├── requirements.txt
├── .env.example          # Copy to .env and fill in
├── templates/
│   ├── base.html
│   ├── login.html
│   └── dashboard.html
└── static/
    ├── css/style.css
    └── js/dashboard.js
```

## Setup

1. **Install Python 3.10+** if you don't have it already.

2. **Create a virtual environment and install dependencies:**
   ```bash
   cd guardspot
   python3 -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Open `.env` and set:
   - `SECRET_KEY` — generate with `python -c "import os; print(os.urandom(24).hex())"`
   - `ADMIN_USERNAME` / `ADMIN_PASSWORD` — your admin login. If you leave
     `ADMIN_PASSWORD` blank, the app will generate one for you and print it
     to the terminal the first time it starts — copy it down immediately.

4. **Run the app:**
   ```bash
   python app.py
   ```
   Visit **http://localhost:5000** in your browser and log in.

   Within a few seconds you should see virtual devices connecting and
   generating browsing activity automatically — that's the simulator
   running in the background.

## Using it

- **Devices table** — shows every device that has ever connected, live
  status, IP/MAC, and last-seen time. Click **View history** to see its
  recent "visited" domains.
- **Block a Website** — type a domain (e.g. `youtube.com`) and click Block.
  Any future simulated visits to that domain, from any device, are marked
  "Blocked (Simulation)". Remove it any time from the rule list.
- **Device Block toggle** — blocks/unblocks a specific device entirely,
  regardless of which domain it "visits".
- **Audit Log** — every login, logout, block, and unblock action, with who
  did it, from which IP, and when.

## Security features (for your report)

- **Password hashing** — admin password is stored as a salted hash
  (`werkzeug.security.generate_password_hash`), never in plaintext.
- **No hardcoded default credentials** — if you don't set one, a random
  one-time password is generated at first run instead of shipping a
  guessable default like `admin/admin`.
- **CSRF protection** — every state-changing request (login, block, unblock)
  requires a CSRF token (Flask-WTF), checked server-side.
- **Session security** — session cookies are `HttpOnly` and `SameSite=Lax`;
  `SESSION_COOKIE_SECURE` can be turned on once deployed behind HTTPS.
- **Login rate limiting** — 5 failed login attempts from an IP triggers a
  5-minute lockout, mitigating brute-force attempts.
- **Server-side input validation** — domain names are validated against a
  strict regex before being stored as a block rule.
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, and
  `Referrer-Policy` set on every response.
- **Audit logging** — every sensitive action is recorded with actor, IP,
  and timestamp for accountability.

## Moving to Phase 2 (real enforcement)

To turn this into a real system on a Raspberry Pi:
1. Replace `simulator.py` with a service that tails `dnsmasq`'s DNS log and
   writes real `Visit` rows (same database schema already supports this).
2. Replace the block/unblock handlers' database-only logic with actual
   `iptables`/`nftables` rule changes, keeping the same API shape so the
   frontend needs no changes.
3. Deploy behind HTTPS (e.g. Caddy or nginx with a Let's Encrypt cert) and
   set `FORCE_HTTPS=true` in `.env`.
# wifimonitoringsystem
