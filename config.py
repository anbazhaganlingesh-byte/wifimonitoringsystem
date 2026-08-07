import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # SECRET_KEY signs session cookies and CSRF tokens.
    # Always set this via .env in a real deployment; falling back to a random
    # value here just means sessions won't survive a restart if you forget.
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24).hex()

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///guardspot.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    # Intentionally no default password here — see _ensure_admin() in app.py.
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Flip this on when you deploy behind HTTPS (e.g. on the Pi with a cert):
    SESSION_COOKIE_SECURE = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'

    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes idle logout

    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_SECONDS = 300  # 5 minute lockout after too many failed logins
