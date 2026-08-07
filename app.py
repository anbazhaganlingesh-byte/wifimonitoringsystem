import os
import re
import time

from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from models import db, AdminUser, Device, Visit, BlockRule, AuditLog
from forms import LoginForm
from real_monitor import RealNetworkMonitor

csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = 'login'

# In-memory login attempt tracker: ip -> {"count": int, "lock_until": float|None}
# Fine for a single-process semester project; swap for Redis if you ever scale this out.
_failed_attempts = {}

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        db.create_all()
        _ensure_admin(app)

    monitor = RealNetworkMonitor(app)
    monitor.start()

    # ---------- auth helpers ----------

    @login_manager.user_loader
    def load_user(user_id):
        return AdminUser.query.get(int(user_id))

    def _is_locked(ip):
        rec = _failed_attempts.get(ip)
        return bool(rec and rec['lock_until'] and time.time() < rec['lock_until'])

    def _register_failure(ip):
        rec = _failed_attempts.setdefault(ip, {'count': 0, 'lock_until': None})
        rec['count'] += 1
        if rec['count'] >= app.config['MAX_LOGIN_ATTEMPTS']:
            rec['lock_until'] = time.time() + app.config['LOCKOUT_SECONDS']
            rec['count'] = 0

    def _clear_failures(ip):
        _failed_attempts.pop(ip, None)

    def _log(actor, action, ip):
        db.session.add(AuditLog(actor=actor, action=action, ip_address=ip))
        db.session.commit()

    def _device_json(d):
        return {
            'id': d.id,
            'mac': d.mac,
            'ip': d.ip,
            'hostname': d.hostname,
            'status': d.status,
            'is_blocked': d.is_blocked,
            'last_seen': d.last_seen.strftime('%Y-%m-%d %H:%M:%S') if d.last_seen else None,
        }

    # ---------- pages ----------

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = LoginForm()
        client_ip = request.remote_addr

        if _is_locked(client_ip):
            flash('Too many failed attempts. Please wait a few minutes before trying again.', 'danger')
            return render_template('login.html', form=form)

        if form.validate_on_submit():
            username = form.username.data.strip()
            user = AdminUser.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, form.password.data):
                _clear_failures(client_ip)
                login_user(user)
                _log(user.username, 'LOGIN_SUCCESS', client_ip)
                return redirect(url_for('dashboard'))

            _register_failure(client_ip)
            _log(username or 'unknown', 'LOGIN_FAILED', client_ip)
            flash('Invalid username or password.', 'danger')

        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        _log(current_user.username, 'LOGOUT', request.remote_addr)
        logout_user()
        return redirect(url_for('login'))

    @app.route('/')
    @login_required
    def dashboard():
        return render_template('dashboard.html', username=current_user.username)

    # ---------- read-only API ----------

    @app.route('/api/devices')
    @login_required
    def api_devices():
        devices = Device.query.order_by(Device.status.desc(), Device.hostname).all()
        return jsonify([_device_json(d) for d in devices])

    @app.route('/api/devices/<int:device_id>/history')
    @login_required
    def api_device_history(device_id):
        device = Device.query.get_or_404(device_id)
        visits = (
            Visit.query.filter_by(device_id=device.id)
            .order_by(Visit.timestamp.desc())
            .limit(50)
            .all()
        )
        return jsonify({
            'device': _device_json(device),
            'history': [
                {
                    'domain': v.domain,
                    'timestamp': v.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'blocked': v.blocked,
                }
                for v in visits
            ],
        })

    @app.route('/api/blocklist')
    @login_required
    def api_blocklist():
        rules = BlockRule.query.order_by(BlockRule.created_at.desc()).all()
        return jsonify([
            {
                'id': r.id,
                'type': r.rule_type,
                'target': r.target,
                'created_at': r.created_at.strftime('%Y-%m-%d %H:%M'),
            }
            for r in rules
        ])

    @app.route('/api/stats')
    @login_required
    def api_stats():
        total_devices = Device.query.count()
        connected = Device.query.filter_by(status='connected').count()
        blocked_rules = BlockRule.query.count()
        total_visits = Visit.query.count()
        blocked_visits = Visit.query.filter_by(blocked=True).count()
        return jsonify({
            'total_devices': total_devices,
            'connected': connected,
            'blocked_rules': blocked_rules,
            'total_visits': total_visits,
            'blocked_visits': blocked_visits,
        })

    # ---------- write API (simulated enforcement) ----------

    @app.route('/api/block-domain', methods=['POST'])
    @login_required
    def api_block_domain():
        data = request.get_json(force=True, silent=True) or {}
        domain = (data.get('domain') or '').strip().lower()
        if not DOMAIN_RE.match(domain):
            return jsonify({'error': 'Invalid domain name'}), 400
        if not BlockRule.query.filter_by(rule_type='domain', target=domain).first():
            db.session.add(BlockRule(rule_type='domain', target=domain))
            db.session.commit()
        _log(current_user.username, f'BLOCK_DOMAIN:{domain}', request.remote_addr)
        return jsonify({'status': 'ok', 'domain': domain, 'blocked': True})

    @app.route('/api/unblock-domain', methods=['POST'])
    @login_required
    def api_unblock_domain():
        data = request.get_json(force=True, silent=True) or {}
        domain = (data.get('domain') or '').strip().lower()
        BlockRule.query.filter_by(rule_type='domain', target=domain).delete()
        db.session.commit()
        _log(current_user.username, f'UNBLOCK_DOMAIN:{domain}', request.remote_addr)
        return jsonify({'status': 'ok', 'domain': domain, 'blocked': False})

    @app.route('/api/block-device', methods=['POST'])
    @login_required
    def api_block_device():
        data = request.get_json(force=True, silent=True) or {}
        device = Device.query.get(data.get('device_id'))
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        device.is_blocked = True
        db.session.commit()
        _log(current_user.username, f'BLOCK_DEVICE:{device.mac}', request.remote_addr)
        return jsonify({'status': 'ok'})

    @app.route('/api/unblock-device', methods=['POST'])
    @login_required
    def api_unblock_device():
        data = request.get_json(force=True, silent=True) or {}
        device = Device.query.get(data.get('device_id'))
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        device.is_blocked = False
        db.session.commit()
        _log(current_user.username, f'UNBLOCK_DEVICE:{device.mac}', request.remote_addr)
        return jsonify({'status': 'ok'})

    @app.route('/api/audit-log')
    @login_required
    def api_audit_log():
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(30).all()
        return jsonify([
            {
                'actor': l.actor,
                'action': l.action,
                'ip_address': l.ip_address,
                'timestamp': l.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
            for l in logs
        ])

    # ---------- security headers ----------

    @app.after_request
    def set_security_headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['Referrer-Policy'] = 'same-origin'
        return resp

    return app


def _ensure_admin(app):
    """Create the first admin account on startup.

    Deliberately avoids ever hardcoding a default password: if ADMIN_PASSWORD
    isn't set in .env, a random one-time password is generated and printed to
    the console once, so there is no shared/guessable default credential.
    """
    if AdminUser.query.first():
        return

    username = app.config['ADMIN_USERNAME']
    password = app.config['ADMIN_PASSWORD']

    if not password:
        password = os.urandom(6).hex()
        print('=' * 64)
        print('No ADMIN_PASSWORD found in .env — generated a one-time password:')
        print(f'  Username: {username}')
        print(f'  Password: {password}')
        print('Save this now. Set ADMIN_PASSWORD in .env to make it permanent.')
        print('=' * 64)

    admin = AdminUser(username=username, password_hash=generate_password_hash(password))
    db.session.add(admin)
    db.session.commit()


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
