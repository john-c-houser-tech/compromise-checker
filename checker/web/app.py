"""Setting Django up from the checker's home, and running it."""

from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import socket
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
    os.chmod(path, 0o600)  # a restored backup may have come back wider
    return path.read_text().strip()


def is_local(host: str) -> bool:
    """Only this machine can reach it: a loopback address, or a name that resolves
    to nothing else (a changed hosts file mustn't widen where it listens)."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if host != "localhost":
        return False
    try:
        found = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    return bool(found) and all(ipaddress.ip_address(a.partition("%")[0]).is_loopback for a in found)


def public_url_problem(public_url: str) -> str | None:
    """What's wrong with the address people use. Plain http to another machine would
    send passwords and evidence in the clear; a wildcard would turn off the Host check."""
    try:
        parts = urlsplit(public_url)
        host, username = parts.hostname, parts.username
    except ValueError:
        return f"--public-url isn't a URL: {public_url}"
    if parts.scheme not in ("http", "https") or not host:
        return f"--public-url must look like https://checker.example: {public_url}"
    if "*" in host or host.startswith(".") or username is not None:
        return f"--public-url must name one host, with no wildcard or login: {public_url}"
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return f"--public-url can't have a path: {public_url}"
    if parts.scheme == "http" and not is_local(host):
        return (
            "--public-url must be https unless it is this machine: logins and evidence would"
            f" cross the network unencrypted: {public_url}"
        )
    return None


def django_settings(home: Path, public_url: str | None = None, tls: bool = False) -> dict:
    """Every setting in one place. Behind a proxy, `public_url` is the address people use:
    only it is accepted as a Host and as a form's origin, and over https cookies are
    https-only."""
    parts = urlsplit(public_url) if public_url else None
    secure = tls or bool(parts and parts.scheme == "https")
    host = parts.hostname if parts else None
    if host and ":" in host:
        host = f"[{host}]"
    prefix = "__Host-" if secure else ""  # bound to this host, https only, over any port
    return {
        "DEBUG": False,
        "SECRET_KEY": secret_key(home),
        "ALLOWED_HOSTS": [host] if parts else LOCAL_NAMES,
        "CSRF_TRUSTED_ORIGINS": [f"{parts.scheme}://{parts.netloc}"] if parts else [],
        # Behind a proxy every peer is the proxy: see views.client_address.
        "CHECKER_BEHIND_PROXY": bool(parts),
        "ROOT_URLCONF": "checker.web.urls",
        "INSTALLED_APPS": [
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "django.contrib.sessions",
            "checker.web",
        ],
        "MIDDLEWARE": [
            "checker.web.middleware.security_headers",
            "checker.web.middleware.small_forms_only",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.common.CommonMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ],
        "DATABASES": {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": str(home / "web.db"),
                # Writers queue up: two tabs mustn't get "database is locked".
                "OPTIONS": {"transaction_mode": "IMMEDIATE", "timeout": 20},
            }
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
        "SESSION_COOKIE_NAME": f"{prefix}checker_session",
        "CSRF_COOKIE_NAME": f"{prefix}checker_csrf",
        "CSRF_FAILURE_VIEW": "checker.web.views.csrf_failed",
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
    os.chmod(database, 0o600)  # a restored backup may have come back wider
    # Anonymous requests mustn't be able to fill a log: wrong Hosts and refused forms
    # say nothing, and paths (which can hold a setup link) stay out of it.
    logging.getLogger("django.request").setLevel(logging.ERROR)
    logging.getLogger("django.security").setLevel(logging.CRITICAL)
    settings.configure(**django_settings(home, public_url, tls))
    django.setup()
    call_command("migrate", verbosity=0, interactive=False)


def listen_problem(bind: str, public_url: str | None, tls: bool) -> str | None:
    """Why this address mustn't be listened on. The host is read the way the server
    will read it, so an odd spelling can't pass here and listen everywhere there."""
    from gunicorn.util import parse_address

    if public_url and (problem := public_url_problem(public_url)):
        return problem
    try:
        where = parse_address(bind)
    except (RuntimeError, ValueError) as exc:
        return f"--bind isn't an address: {bind} ({exc})"
    if isinstance(where, str | int | bytes):  # a unix socket or a file descriptor
        return f"--bind must be an address and a port: {bind}"
    if is_local(where[0]):
        return None
    if not tls:
        return (
            f"{bind} can be reached from other machines, and logins and evidence would cross"
            " the network unencrypted: give --tls-cert, --tls-key and --public-url, or listen"
            " on 127.0.0.1 behind a proxy that provides TLS"
        )
    if not public_url:
        return (
            f"{bind} can be reached from other machines: give --public-url with the address"
            " people will use, since no other address is accepted"
        )
    return None


# A request's body must arrive by then: a few slow senders mustn't hold every thread.
BODY_TIMEOUT_SECONDS = 10


def read_timeout(wsgi):
    """Bounds reading a request's body, which gunicorn's own timeouts don't."""

    def application(environ, start_response):
        connection = environ.get("gunicorn.socket")
        if connection is not None:
            connection.settimeout(BODY_TIMEOUT_SECONDS)
        return wsgi(environ, start_response)

    return application


def server_options(bind: str, tls_cert: str | None, tls_key: str | None) -> dict:
    options = {
        "bind": bind,
        # One process: it holds nothing shared but the databases, and threads suffice.
        "workers": 1,
        "threads": 8,
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
    wsgi = read_timeout(get_wsgi_application())

    class Server(BaseApplication):
        def load_config(self):
            for name, value in server_options(bind, tls_cert, tls_key).items():
                if name in self.cfg.settings:  # an older gunicorn has no control socket
                    self.cfg.set(name, value)

        def load(self):
            return wsgi

    Server().run()
    return 0
