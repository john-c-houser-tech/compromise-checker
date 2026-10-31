"""Setting Django up from the checker's home, and running it."""

from __future__ import annotations

import ipaddress
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit

from checker.files import atomic_write
from checker.product import product_name

HERE = Path(__file__).resolve().parent
SESSION_SECONDS = 8 * 3600
LOCAL_NAMES = ["127.0.0.1", "localhost", "[::1]"]


def secret_key(home: Path) -> str:
    """Signs sessions: made once, owner-only, kept with the other keys."""
    path = home / "keys" / "web-secret.txt"
    if not path.exists():
        atomic_write(path, secrets.token_urlsafe(64) + "\n")
    return path.read_text().strip()


def is_local(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def django_settings(home: Path, public_url: str | None = None, tls: bool = False) -> dict:
    """Every setting in one place. Behind a proxy, `public_url` is the address people use:
    only it is accepted as a Host and as a form's origin, and over https cookies are
    https-only."""
    parts = urlsplit(public_url) if public_url else None
    secure = tls or bool(parts and parts.scheme == "https")
    return {
        "DEBUG": False,
        "SECRET_KEY": secret_key(home),
        "ALLOWED_HOSTS": [parts.hostname] if parts else LOCAL_NAMES,
        "CSRF_TRUSTED_ORIGINS": [f"{parts.scheme}://{parts.netloc}"] if parts else [],
        "ROOT_URLCONF": "checker.web.urls",
        "INSTALLED_APPS": [
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "django.contrib.sessions",
            "checker.web",
        ],
        "MIDDLEWARE": [
            "checker.web.middleware.security_headers",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.common.CommonMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ],
        "DATABASES": {
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": str(home / "web.db")}
        },
        "TEMPLATES": [
            {
                "BACKEND": "django.template.backends.jinja2.Jinja2",
                "DIRS": [str(HERE / "templates")],
                "OPTIONS": {"environment": "checker.web.templating.environment"},
            }
        ],
        "AUTH_PASSWORD_VALIDATORS": [
            {
                "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
                "OPTIONS": {"min_length": 12},
            },
            {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
            {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
            {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
        ],
        "LOGIN_URL": "/login",
        "SESSION_COOKIE_AGE": SESSION_SECONDS,
        "SESSION_EXPIRE_AT_BROWSER_CLOSE": True,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Strict",
        "SESSION_COOKIE_SECURE": secure,
        "CSRF_COOKIE_HTTPONLY": True,
        "CSRF_COOKIE_SAMESITE": "Strict",
        "CSRF_COOKIE_SECURE": secure,
        "DATA_UPLOAD_MAX_MEMORY_SIZE": 64 * 1024,
        "DEFAULT_AUTO_FIELD": "django.db.models.BigAutoField",
        "USE_TZ": True,
        "LOGGING_CONFIG": None,
    }


def configure(home: Path, public_url: str | None = None, tls: bool = False) -> None:
    """Once per process. The accounts database is made or brought up to date, owner-only."""
    import django
    from django.conf import settings
    from django.core.management import call_command

    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = home / "web.db"
    if not database.exists():
        database.touch(mode=0o600)
    settings.configure(**django_settings(home, public_url, tls))
    django.setup()
    call_command("migrate", verbosity=0, interactive=False)


def listen_problem(bind: str, public_url: str | None, tls: bool) -> str | None:
    """Why this address mustn't be listened on: passwords and evidence would cross a
    network in the clear. A proxy on this machine provides the TLS for a local address."""
    host = bind.rpartition(":")[0] or bind
    if is_local(host) or tls:
        return None
    return (
        f"{bind} can be reached from other machines, and logins and evidence would cross the"
        " network unencrypted: give --tls-cert and --tls-key, or listen on 127.0.0.1 behind a"
        " proxy that provides TLS"
    )


def server_options(bind: str, tls_cert: str | None, tls_key: str | None) -> dict:
    options = {
        "bind": bind,
        # One process: it holds nothing shared but the databases, and threads suffice.
        "workers": 1,
        "threads": 4,
        "timeout": 120,
        # An access log would hold setup links; nothing about a request needs keeping.
        "accesslog": None,
        # gunicorn's own management socket: nothing here uses it, so nothing listens.
        "control_socket_disable": True,
    }
    if tls_cert and tls_key:
        options.update(certfile=tls_cert, keyfile=tls_key)
    return options


def serve(
    home: Path,
    bind: str,
    public_url: str | None = None,
    tls_cert: str | None = None,
    tls_key: str | None = None,
) -> int:
    from gunicorn.app.base import BaseApplication

    tls = bool(tls_cert and tls_key)
    problem = listen_problem(bind, public_url, tls)
    if problem:
        print(f"checker: {problem}", file=sys.stderr)
        return 2
    configure(home, public_url, tls)

    from django.core.wsgi import get_wsgi_application

    from checker.web.accounts import setup_link  # needs Django set up

    scheme = "https" if tls else "http"
    address = public_url or f"{scheme}://{bind}"
    link = setup_link(address)
    if link:
        print("No account yet. Open this link, once, within an hour, to create the first one:")
        print(f"  {link}")
    print(f"{product_name()} is at {address}", flush=True)  # before the server takes over
    wsgi = get_wsgi_application()

    class Server(BaseApplication):
        def load_config(self):
            for name, value in server_options(bind, tls_cert, tls_key).items():
                if name in self.cfg.settings:  # an older gunicorn has no control socket
                    self.cfg.set(name, value)

        def load(self):
            return wsgi

    Server().run()
    return 0
