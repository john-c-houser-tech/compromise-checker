"""The web interface's server (PR 5.2): accounts, one-time setup, throttling, headers,
and host text that can do nothing in a logged-in browser."""

import html
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unicodedata
from datetime import timedelta
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from urllib.parse import urlencode

import asyncssh
import pytest

pytest.importorskip("django")

from test_schedule import CLEAN, ROOTED  # noqa: E402
from test_snapshot import add_bundle, host_records, rec  # noqa: E402

from checker.assess import analyze  # noqa: E402
from checker.evidence import load_identity  # noqa: E402
from checker.web import app as web_app  # noqa: E402

PASSWORD = "correct horse battery 9"  # noqa: S105 - a test's
BIDI = chr(0x202E)
HOSTILE = "<script>alert(1)</script>\"'><img src=x onerror=alert(2)>evil" + BIDI


def browser(**kwargs):
    """Posts forms as a browser does, which is the only way the server accepts."""
    from django.test import Client

    class FormClient(Client):
        def post(self, path, data=None, **extra):
            extra.setdefault("content_type", "application/x-www-form-urlencoded")
            return super().post(path, urlencode(data or {}), **extra)

    return FormClient(raise_request_exception=False, **kwargs)


@pytest.fixture(scope="session")
def _django():
    home = Path(tempfile.mkdtemp())
    web_app.configure(home)
    from django.test.utils import setup_test_environment

    setup_test_environment()  # adds "testserver" to ALLOWED_HOSTS
    return home


@pytest.fixture
def settings_override(_django):
    from django.conf import settings

    changed = {}

    def apply(**values):
        for name, value in values.items():
            changed.setdefault(name, getattr(settings, name))
            setattr(settings, name, value)

    yield apply
    for name, value in changed.items():
        setattr(settings, name, value)


def clear_the_record():
    """Between tests only: in use, the record can't be emptied."""
    from django.db import connection

    from checker.web.models import ACTION_RECORD_TRIGGERS

    with connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS web_actionrecord_no_update")
        cursor.execute("DROP TRIGGER IF EXISTS web_actionrecord_no_delete")
        cursor.execute("DELETE FROM web_actionrecord")
        for sql in ACTION_RECORD_TRIGGERS:
            cursor.execute(sql)


@pytest.fixture
def web(_django, home):
    """A clean accounts database, and a browser that checks CSRF as a real one must."""
    from django.contrib.auth import get_user_model
    from django.contrib.sessions.models import Session

    from checker.web.models import CheckRun, LoginAttempt, SetupToken, WrongConfirmation

    models = (get_user_model(), Session, LoginAttempt, SetupToken, WrongConfirmation, CheckRun)
    for model in models:
        model.objects.all().delete()
    clear_the_record()
    return browser(), home


def signed_in(web):
    from django.contrib.auth import get_user_model

    client, home = web
    user = get_user_model().objects.create_user("jo", password=PASSWORD)
    client.force_login(user)
    return client, home


def identity_of(home):
    return load_identity(home[0] / "keys" / "evidence-identity.txt")


def analysed(home, name, minutes, records, host="web01"):
    add_bundle(home, name, minutes, records, host=host)
    return analyze(home[1], host, identity_of(home), home[3].recipients, name)


# --- Listening ----------------------------------------------------------------------------


@pytest.mark.parametrize("bind", ["127.0.0.1:8088", "localhost:8088", "[::1]:8088"])
def test_this_machine_needs_no_tls(bind):
    assert web_app.listen_problem(bind, None, False) is None


@pytest.mark.parametrize(
    "bind",
    [
        "0.0.0.0:8088",
        "192.0.2.1:443",
        "example.com:443",
        ":8088",
        "0:8088",
        "[::]:8088",
        "[]127.0.0.1[]:8088",
        "[]127.0.0.1:8088",
        "]127.0.0.1[:8088",
    ],
)
def test_another_machine_is_refused_without_tls_however_it_is_spelled(bind):
    problem = web_app.listen_problem(bind, None, False)
    assert problem and ("unencrypted" in problem or "isn't an address" in problem)


@pytest.mark.parametrize("bind", ["unix:/tmp/x", "fd://3"])
def test_only_an_address_and_a_port(bind):
    assert web_app.listen_problem(bind, None, False)


def test_another_machine_needs_tls_and_the_address_people_will_use():
    bind = "0.0.0.0:443"  # noqa: S104
    assert "--public-url" in web_app.listen_problem(bind, None, True)
    assert web_app.listen_problem(bind, "https://checker.example", True) is None


def test_localhost_is_trusted_only_if_it_resolves_only_to_this_machine(monkeypatch):
    monkeypatch.setattr(web_app.socket, "getaddrinfo", lambda *a: [(0, 0, 0, "", ("192.0.2.1", 0))])
    assert not web_app.is_local("localhost")


@pytest.mark.parametrize(
    "url",
    [
        "http://checker.example",
        "https://*",
        "https://.example.com",
        "checker.example",
        "https://",
        "ftp://x.example",
        "https://user:pw@checker.example",
        "https://checker.example/sub",
        "https://checker.example?x=1",
    ],
)
def test_a_bad_public_url_is_refused(url):
    assert web_app.public_url_problem(url)
    assert web_app.listen_problem("127.0.0.1:8088", url, False)


@pytest.mark.parametrize(
    "url", ["https://checker.localhost:8443", "http://127.0.0.1:8088", "https://[::1]:8443"]
)
def test_a_good_public_url_is_accepted(url):
    assert web_app.public_url_problem(url) is None


def test_an_ipv6_public_url_makes_a_host_django_accepts(tmp_path):
    assert web_app.django_settings(tmp_path, "https://[::1]:8443")["ALLOWED_HOSTS"] == ["[::1]"]


def test_cookies_are_bound_to_the_host_over_https(tmp_path):
    assert web_app.django_settings(tmp_path)["SESSION_COOKIE_NAME"] == "checker_session"
    made = web_app.django_settings(tmp_path, "https://c.example")
    assert made["SESSION_COOKIE_NAME"] == "__Host-checker_session"
    assert made["CSRF_COOKIE_NAME"] == "__Host-checker_csrf"


def test_existing_files_are_made_owner_only(tmp_path):
    (tmp_path / "keys").mkdir()
    path = tmp_path / "keys" / "web-secret.txt"
    path.write_text("kept\n")
    path.chmod(0o644)
    assert web_app.secret_key(tmp_path) == "kept"
    assert path.stat().st_mode & 0o077 == 0


def test_reading_a_body_has_a_time_limit():
    seen = []

    class Connection:
        def settimeout(self, seconds):
            seen.append(seconds)

    app = web_app.read_timeout(lambda environ, start: "ran")
    assert app({"gunicorn.socket": Connection()}, None) == "ran"
    assert seen == [web_app.BODY_TIMEOUT_SECONDS]


def test_a_public_url_alone_does_not_excuse_listening_widely():
    assert web_app.listen_problem("0.0.0.0:80", "https://c.example", False)  # noqa: S104


def test_behind_a_proxy_only_its_address_is_accepted_and_cookies_are_https(tmp_path):
    made = web_app.django_settings(tmp_path, "https://checker.localhost:8443")
    assert made["ALLOWED_HOSTS"] == ["checker.localhost"]
    assert made["CSRF_TRUSTED_ORIGINS"] == ["https://checker.localhost:8443"]
    assert made["SESSION_COOKIE_SECURE"] and made["CSRF_COOKIE_SECURE"]


def test_the_server_keeps_no_access_log_and_no_control_socket():
    options = web_app.server_options("127.0.0.1:1", None, None)
    assert options["accesslog"] is None and options["control_socket_disable"] is True
    assert "certfile" not in options
    assert web_app.server_options("x:1", "c", "k")["certfile"] == "c"


def test_settings_are_strict(tmp_path):
    made = web_app.django_settings(tmp_path)
    assert made["DEBUG"] is False
    assert made["SESSION_COOKIE_HTTPONLY"] and made["SESSION_COOKIE_SAMESITE"] == "Strict"
    assert "django.middleware.csrf.CsrfViewMiddleware" in made["MIDDLEWARE"]
    assert (tmp_path / "keys" / "web-secret.txt").stat().st_mode & 0o077 == 0
    assert web_app.secret_key(tmp_path) == made["SECRET_KEY"]  # kept, so sessions survive


# --- The first account --------------------------------------------------------------------


def link_token(link):
    return link.rpartition("/setup/")[2]


def setup_post(client, token, **extra):
    data = {"username": "jo", "password": PASSWORD, "password2": PASSWORD, **extra}
    return client.post(f"/setup/{token}", data)


def test_the_setup_link_makes_one_account_and_only_once(web):
    from django.contrib.auth import get_user_model

    from checker.web.accounts import setup_link
    from checker.web.models import SetupToken

    client, _ = web
    link = setup_link("http://127.0.0.1:8088")
    token = link_token(link)
    assert token not in str(list(SetupToken.objects.values_list("token_hash", flat=True)))
    assert client.get(f"/setup/{token}").status_code == 200
    response = setup_post(client, token)
    assert response.status_code == 302 and client.get("/").status_code == 200
    assert setup_post(client, token, username="second").status_code == 404
    assert get_user_model().objects.count() == 1
    assert setup_link("http://x") is None  # an account exists: no more links


def test_a_wrong_or_expired_setup_link_does_nothing(web):
    from django.contrib.auth import get_user_model
    from django.utils import timezone

    from checker.web.accounts import setup_link
    from checker.web.models import SetupToken

    client, _ = web
    token = link_token(setup_link("http://x"))
    assert setup_post(client, "wrong" + token).status_code == 404
    SetupToken.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert setup_post(client, token).status_code == 404
    assert not get_user_model().objects.exists()


def test_a_new_link_replaces_the_old(web):
    from checker.web.accounts import setup_link

    client, _ = web
    old = link_token(setup_link("http://x"))
    setup_link("http://x")
    assert client.get(f"/setup/{old}").status_code == 404


@pytest.mark.parametrize(
    ("change", "words"),
    [
        ({"password": "short", "password2": "short"}, "too short"),
        ({"password": "123456789012", "password2": "123456789012"}, "numeric"),
        ({"password2": "different one here"}, "match"),
        ({"username": "  "}, "username"),
    ],
)
def test_a_weak_password_or_a_bad_form_makes_no_account(web, change, words):
    from django.contrib.auth import get_user_model

    from checker.web.accounts import setup_link

    client, _ = web
    response = setup_post(client, link_token(setup_link("http://x")), **change)
    assert response.status_code == 200 and words in response.content.decode()
    assert not get_user_model().objects.exists()


# --- Login --------------------------------------------------------------------------------


def without_token(response):
    return re.sub(rb'name="csrfmiddlewaretoken" value="[^"]*"', b"", response.content)


def account_named(name):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user(name, password=PASSWORD)


def account():
    from django.contrib.auth import get_user_model

    return get_user_model().objects.create_user("jo", password=PASSWORD)


def test_pages_need_a_login(web):
    client, _ = web
    response = client.get("/")
    assert response.status_code == 302 and response["Location"].startswith("/login")


def test_signing_in_and_out(web):
    client, _ = web
    account()
    response = client.post("/login", {"username": "jo", "password": PASSWORD})
    assert response.status_code == 302 and client.get("/").status_code == 200
    client.post("/logout", {"from": "a form"})  # a browser's form always has a body
    assert client.get("/").status_code == 302


def test_signing_out_needs_a_post(web):
    client, _ = signed_in(web)
    assert client.get("/logout").status_code == 405
    assert client.get("/").status_code == 200


def test_a_bad_login_does_not_say_which_part_was_wrong(web):
    client, _ = web
    account()
    wrong_password = client.post("/login", {"username": "jo", "password": "no"})
    no_such_user = client.post("/login", {"username": "nobody", "password": "no"})
    assert wrong_password.status_code == no_such_user.status_code == 403
    assert without_token(wrong_password) == without_token(no_such_user)


def test_login_is_throttled_even_with_the_right_password(web):
    from checker.web.accounts import MAX_FAILURES_FOR_NAME

    client, _ = web
    account()
    for _ in range(MAX_FAILURES_FOR_NAME):
        client.post("/login", {"username": "jo", "password": "no"})
    response = client.post("/login", {"username": "JO", "password": PASSWORD})
    assert "Too many" in response.content.decode() and client.get("/").status_code == 302


def request_from(peer, forwarded=None):
    from django.test import RequestFactory

    meta = {"REMOTE_ADDR": peer}
    if forwarded:
        meta["HTTP_X_FORWARDED_FOR"] = forwarded
    return RequestFactory().get("/", **meta)


def test_behind_a_proxy_the_address_is_the_one_the_proxy_added(web, settings_override):
    from checker.web.accounts import client_address

    settings_override(CHECKER_BEHIND_PROXY=True)
    assert client_address(request_from("127.0.0.1", "198.51.100.9")) == "198.51.100.9"
    # What a client sends itself comes first, so it can't choose its own bucket.
    assert client_address(request_from("127.0.0.1", "1.1.1.1, 198.51.100.9")) == "198.51.100.9"
    assert client_address(request_from("127.0.0.1")) == "127.0.0.1"
    # Not from the proxy: the header is the sender's own.
    assert client_address(request_from("203.0.113.5", "198.51.100.9")) == "203.0.113.5"


def test_without_a_proxy_a_forwarded_header_means_nothing(web, settings_override):
    from checker.web.accounts import client_address

    settings_override(CHECKER_BEHIND_PROXY=False)
    assert client_address(request_from("127.0.0.1", "198.51.100.9")) == "127.0.0.1"


def test_ipv6_counts_by_network(web, settings_override):
    from checker.web.accounts import client_address

    settings_override(CHECKER_BEHIND_PROXY=False)
    one = client_address(request_from("2001:db8:1:2::1"))
    assert one == client_address(request_from("2001:db8:1:2:ffff::9"))
    assert one != client_address(request_from("2001:db8:1:3::1"))


def test_one_client_behind_the_proxy_cannot_lock_out_another(web, settings_override):
    from checker.web.accounts import MAX_FAILURES_FROM_ADDRESS

    client, _ = web
    settings_override(CHECKER_BEHIND_PROXY=True)
    account()
    attacker = {"HTTP_X_FORWARDED_FOR": "198.51.100.66", "REMOTE_ADDR": "127.0.0.1"}
    for n in range(MAX_FAILURES_FROM_ADDRESS):
        client.post("/login", {"username": f"u{n}", "password": "no"}, **attacker)
    owner = {"HTTP_X_FORWARDED_FOR": "198.51.100.1", "REMOTE_ADDR": "127.0.0.1"}
    assert (
        client.post("/login", {"username": "jo", "password": PASSWORD}, **owner).status_code == 302
    )


def test_a_name_typed_with_spaces_or_another_unicode_form_still_signs_in(web):
    client, _ = web
    get_name = unicodedata.normalize
    composed = get_name("NFC", "Jos\u00e9")
    user = account_named(composed)
    assert user.username == get_name("NFKC", composed)
    decomposed = get_name("NFD", composed)
    response = client.post("/login", {"username": f" {decomposed} ", "password": PASSWORD})
    assert response.status_code == 302


def test_a_password_like_the_username_is_refused(web):
    from checker.web.accounts import setup_link

    client, _ = web
    name = "averylongusername"
    response = setup_post(
        client, link_token(setup_link("http://x")), username=name, password=name, password2=name
    )
    assert response.status_code == 200 and "too similar" in response.content.decode()


def test_guessing_across_accounts_is_throttled_too(web):
    from checker.web.accounts import MAX_FAILURES_FROM_ADDRESS

    client, _ = web
    account()
    for n in range(MAX_FAILURES_FROM_ADDRESS):
        client.post("/login", {"username": f"u{n}", "password": "no"})
    assert (
        "Too many"
        in client.post("/login", {"username": "jo", "password": PASSWORD}).content.decode()
    )


def test_failures_age_out(web):
    from django.utils import timezone

    from checker.web.accounts import MAX_FAILURES_FOR_NAME, THROTTLE_WINDOW
    from checker.web.models import LoginAttempt

    client, _ = web
    account()
    for _ in range(MAX_FAILURES_FOR_NAME):
        client.post("/login", {"username": "jo", "password": "no"})
    LoginAttempt.objects.update(at=timezone.now() - THROTTLE_WINDOW - timedelta(seconds=1))
    assert client.post("/login", {"username": "jo", "password": PASSWORD}).status_code == 302


@pytest.mark.parametrize(
    "target", ["https://evil.example/", "//evil.example/", "javascript:alert(1)"]
)
def test_after_login_it_never_redirects_away(web, target):
    client, _ = web
    account()
    response = client.post("/login", {"username": "jo", "password": PASSWORD, "next": target})
    assert response["Location"] == "/"


def token_from(response):
    return re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.content.decode())[1]


def test_a_browser_can_sign_in_and_out_with_real_csrf_checks(web):
    account()
    client = browser(enforce_csrf_checks=True)
    token = token_from(client.get("/login"))
    data = {"username": "jo", "password": PASSWORD, "csrfmiddlewaretoken": token}
    assert client.post("/login", data).status_code == 302
    page = client.get("/")
    assert page.status_code == 200
    out = client.post("/logout", {"csrfmiddlewaretoken": token_from(page)})
    assert out.status_code == 302 and client.get("/").status_code == 302


def test_a_browser_can_create_the_first_account_with_real_csrf_checks(web):
    from checker.web.accounts import setup_link

    client = browser(enforce_csrf_checks=True)
    path = f"/setup/{link_token(setup_link('http://x'))}"
    data = {
        "csrfmiddlewaretoken": token_from(client.get(path)),
        "username": "jo",
        "password": PASSWORD,
        "password2": PASSWORD,
    }
    assert client.post(path, data).status_code == 302 and client.get("/").status_code == 200


def test_after_login_it_does_not_land_on_a_form_address(web):
    client, _ = web
    account()
    response = client.post("/login", {"username": "jo", "password": PASSWORD, "next": "/logout"})
    assert response["Location"] == "/"


def test_a_file_upload_is_refused_before_anything_reads_it(web):
    from django.test import Client

    upload = Client(raise_request_exception=False)
    response = upload.post("/login", {"username": "jo", "password": "x", "f": BytesIO(b"x" * 99)})
    assert response.status_code == 415


def test_a_large_form_is_refused(web):
    client, _ = web
    assert client.post("/login", {"username": "x" * 70000}).status_code == 413


def test_a_form_with_no_length_is_refused(web):
    client, _ = web
    response = client.generic(
        "POST", "/login", b"", content_type="application/x-www-form-urlencoded", CONTENT_LENGTH=""
    )
    assert response.status_code == 411


def test_a_form_without_its_csrf_token_is_refused(web):
    account()
    strict = browser(enforce_csrf_checks=True)
    assert strict.post("/login", {"username": "jo", "password": PASSWORD}).status_code == 403
    assert strict.get("/").status_code == 302
    refused = strict.post("/login", {"username": "jo", "password": PASSWORD})
    assert "expired" in refused.content.decode()  # not Django's page, in the tool's words


# --- Headers ------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/login", "/no/such/page"])
def test_every_page_carries_the_headers(web, path):
    client, _ = web
    response = client.get(path)
    policy = response["Content-Security-Policy"]
    assert "default-src 'none'" in policy and "script-src" not in policy
    assert "frame-ancestors 'none'" in policy
    assert response["Cache-Control"] == "no-store"
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["Referrer-Policy"] == "same-origin"


def test_pages_load_nothing_from_elsewhere_and_have_no_inline_script(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    for path in ("/", "/login"):
        text = client.get(path).content.decode()
        assert "<script" not in text and " style=" not in text
        assert not re.search(r'(?:src|href)="(?:https?:)?//', text)


def test_https_pages_tell_browsers_to_stay_on_https(web):
    client, _ = web
    assert "max-age" in client.get("/login", secure=True)["Strict-Transport-Security"]
    assert "Strict-Transport-Security" not in client.get("/login")


def test_the_stylesheet_is_served_without_a_login(web):
    client, _ = web
    response = client.get("/style.css")
    assert response.status_code == 200 and response["Content-Type"] == "text/css"


def test_another_host_header_is_refused(web):
    client, _ = web
    assert client.get("/login", headers={"host": "evil.example"}).status_code == 400


# --- The fleet page -----------------------------------------------------------------------


def test_the_page_shows_the_same_order_as_the_command(web):
    client, home = signed_in(web)
    analysed(home, "a", 10, CLEAN, host="clean")
    analysed(home, "b", 10, ROOTED, host="rooted")
    text = client.get("/").content.decode()
    assert text.index(">rooted</a></h2>") < text.index(">clean</a></h2>")
    assert "not proof" in text


@pytest.mark.sqlite_only
def test_looking_at_the_page_leaves_the_evidence_store_alone(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    db = home[0] / "checker.db"
    before = db.read_bytes(), db.stat().st_mtime_ns
    assert client.get("/").status_code == 200
    assert (db.read_bytes(), db.stat().st_mtime_ns) == before
    assert not (home[0] / "packs" / "state.json").exists()


@pytest.mark.sqlite_only
def test_a_store_that_cannot_answer_is_a_plain_page(web):
    client, home = signed_in(web)
    (home[0] / "checker.db").write_bytes(b"not a database, not at all" * 100)
    response = client.get("/")
    assert response.status_code == 503 and "damaged" in response.content.decode()


def test_no_key_is_a_plain_page(web):
    client, home = signed_in(web)
    (home[0] / "keys" / "evidence-identity.txt").unlink()
    assert client.get("/").status_code == 503


def test_a_broken_settings_file_says_nothing_of_what_is_in_it(web, capsys):
    client, home = signed_in(web)
    (home[0] / "config.yaml").write_text("secret_value: sk-REALSECRET\nbroken: [")
    response = client.get("/")
    assert response.status_code == 503
    assert "REALSECRET" not in response.content.decode() + capsys.readouterr().err


def test_hostile_host_text_does_nothing_in_the_page(web, monkeypatch):
    """Through every field the page prints, whatever a host could have put there."""
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    host = FleetHost(
        HOSTILE,
        state="analysed",
        band=HOSTILE,
        probability=0.6,
        collected_at=HOSTILE,
        exposed={HOSTILE: HOSTILE},
        doubts=(HOSTILE,),
        changes=(HOSTILE,),
    )
    gone = FleetHost(HOSTILE, state="unreadable", last_readable_band=HOSTILE)
    monkeypatch.setattr("checker.web.views.read_fleet", lambda *a, **k: ([host, gone], [HOSTILE]))
    text = client.get("/").content.decode()
    assert "<script>alert" not in text and "<img src=x" not in text
    assert BIDI not in text
    assert "&lt;script&gt;" in text


def test_a_hostile_filter_does_nothing_in_the_page(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    text = client.get("/", {"group": HOSTILE, "show": HOSTILE}).content.decode()
    assert "<script>alert" not in text and "No servers match" in text


def test_a_hostile_group_name_does_nothing_in_a_link(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    host = FleetHost("x", HOSTILE, state="no_evidence")
    monkeypatch.setattr("checker.web.views.read_fleet", lambda *a, **k: ([host], []))
    text = client.get("/").content.decode()
    assert "<script>alert" not in text and "<img src=x" not in text and BIDI not in text
    assert 'href="?group=%3Cscript' in text


def test_filters_narrow_the_list_but_not_the_answer(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    hosts = [
        FleetHost("bad", "web", "analysed", "Critical", 0.98),
        FleetHost("fine", "db", "analysed", "Low", 0.02),
        FleetHost("gone", None, "analysed", "Critical", 0.98, removed=True),
    ]
    monkeypatch.setattr("checker.web.views.read_fleet", lambda *a, **k: (hosts, []))
    text = client.get("/", {"group": "db"}).content.decode()
    assert "needs attention" in text or "need attention" in text
    assert ">fine</a></h2>" in text and ">bad</a></h2>" not in text
    assert ">gone</a></h2>" in text  # a removed host's bad result isn't filtered out of sight
    text = client.get("/", {"show": "low"}).content.decode()
    assert ">fine</a></h2>" in text and ">bad</a></h2>" not in text


def test_the_page_shows_what_it_worked_out(web, monkeypatch):
    """The answer, the verdict, what to do, what's new, the notes, the threat, the scale."""
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    host = FleetHost(
        "bad",
        "web",
        "analysed",
        "High",
        0.67,
        first=False,
        changes=("bad: new high: A shell was started",),
        doubts=("its last collection was failed",),
        exposed={"p1": "vulnerable"},
    )
    monkeypatch.setattr(
        "checker.web.views.read_fleet", lambda *a, **k: ([host], ["pack-file-detail"])
    )
    text = client.get("/").content.decode()
    for words in (
        "Your server needs attention now.",
        "Signs of a break-in",
        "Look into this today.",
        "A shell was started",
        "The last check didn&#39;t finish.",
        "Open to a known threat now: p1.",
        "A threat update couldn't be used",
        "67%",
        'x1="67.0"',
    ):
        assert words in text, words
    assert "pack-file-detail" not in text


def test_a_filter_with_no_matches_still_offers_the_way_back(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    host = FleetHost("a", state="analysed", band="Low", probability=0.02, first=False)
    monkeypatch.setattr("checker.web.views.read_fleet", lambda *a, **k: ([host], []))
    text = client.get("/", {"show": "critical"}).content.decode()
    assert "No servers match" in text and ">All 1<" in text


@pytest.mark.parametrize(
    "fields",
    [
        {"score": {"band": ["a"], "probability": 0.5}},
        {"score": {"band": {"a": 1}, "probability": 0.5}},
        {"score": {"band": "Low", "probability": float("inf")}},
        {"score": {"band": "Low", "probability": 1e308}},
        {"score": {"band": "Low", "probability": 10**400}},
        {"score": {"band": "Low", "probability": True}},
        {"score": {"band": "Low", "probability": float("nan")}},
        {"score": {"band": "Low", "probability": -1}},
        {"score": {"band": "Low", "probability": "half"}},
        {"counts": {"x/high": "many"}},
        {"counts": {"x/high": None}},
        {"counts": ["x"]},
        {"coverage": "none"},
        {"exposures": "odd"},
        {"findings": "odd"},
    ],
)
def test_one_hosts_odd_stored_data_never_takes_the_page_down(web, monkeypatch, fields):
    from checker import fleet as fleet_module

    client, home = signed_in(web)
    analysed(home, "odd", 10, CLEAN, host="odd")
    analysed(home, "bad", 10, ROOTED, host="rooted")
    real = fleet_module.load_assessment

    def load(store, bundle, identity, which=-1):
        found = real(store, bundle, identity, which)
        return {**found, **fields} if found and bundle == "odd" else found

    monkeypatch.setattr(fleet_module, "load_assessment", load)
    response = client.get("/")
    text = response.content.decode()
    assert response.status_code == 200 and ">rooted</a></h2>" in text and ">odd</a></h2>" in text
    assert "No strong signs of a break-in on" not in text


def test_a_bad_key_or_unreadable_hosts_file_is_a_plain_page(web):
    client, home = signed_in(web)
    (home[0] / "hosts.yaml").write_bytes(b"\xff\xfe not text")
    assert client.get("/").status_code == 503
    (home[0] / "hosts.yaml").unlink()
    (home[0] / "keys" / "evidence-identity.txt").write_text("AGE-SECRET-KEY-NOTAKEY\n")
    response = client.get("/")
    assert response.status_code == 503 and "isn&#39;t a key" in response.content.decode()


def test_the_fonts_are_served_by_name_only(web):
    client, _ = web
    good = client.get("/fonts/atkinson-hyperlegible-latin-400-normal.woff2")
    assert good.status_code == 200 and good["Content-Type"] == "font/woff2"
    assert good.content[:4] == b"wOF2"
    assert client.get("/fonts/OFL.txt").status_code == 404
    assert client.get("/fonts/..%2Fstyle.css").status_code == 404
    assert "font-src 'self'" in good["Content-Security-Policy"]


def test_the_stylesheet_only_asks_for_fonts_that_exist(web):
    client, _ = web
    css = client.get("/style.css").content.decode()
    names = re.findall(r'url\("(/fonts/[^"]+)"\)', css)
    assert len(names) == 2
    assert all(client.get(n).status_code == 200 for n in names)
    assert "http" not in css


def test_no_servers_says_what_to_do(web):
    client, _ = signed_in(web)
    assert "Start with first setup" in client.get("/").content.decode()


def test_hostile_text_from_a_real_finding_does_nothing(web):
    client, home = signed_in(web)
    records = host_records(
        accounts=(("root", 0), ("toor", 0)),
        extra=[
            rec(
                "unusual_files",
                "unusual_file",
                path=f"/tmp/{HOSTILE}",
                place="/tmp",
                type="-",
                kind="elf",
                uid=33,
                mode="0755",
            )
        ],
    )
    analysed(home, "b1", 10, records)
    analysed(home, "b2", 20, records)
    text = client.get("/").content.decode()
    assert "<script>alert" not in text and BIDI not in text


def test_a_hostile_next_or_username_is_escaped(web):
    client, _ = web
    text = client.get("/login", {"next": HOSTILE}).content.decode()
    assert "<script>alert" not in text and BIDI not in text


def test_the_name_is_configurable(web, monkeypatch):
    client, _ = web
    monkeypatch.setenv("CHECKER_PRODUCT_NAME", "Another Name")
    assert "Another Name" in client.get("/login").content.decode()


def test_the_command_says_what_to_install_without_the_extra(home, monkeypatch, capsys):
    import sys

    from checker import cli

    monkeypatch.setitem(sys.modules, "checker.web.app", None)
    assert cli.main(["web"]) == 2
    assert ".[web]" in capsys.readouterr().err


def test_the_command_refuses_half_a_tls_pair(home, capsys):
    from checker import cli

    assert cli.main(["web", "--tls-cert", "c.pem"]) == 2
    assert "go together" in capsys.readouterr().err


# --- The host page ------------------------------------------------------------------------


def test_the_fleet_links_to_each_server(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    assert 'href="/hosts/web01"' in client.get("/").content.decode()


def test_the_host_page_needs_a_login_and_a_known_name(web):
    client, home = web
    analysed(home, "b1", 10, ROOTED)
    assert client.get("/hosts/web01").status_code == 302
    client, _ = signed_in(web)
    assert client.get("/hosts/web01").status_code == 200
    assert client.get("/hosts/nobody").status_code == 404
    assert client.get("/hosts/../../etc/passwd").status_code == 404


def test_a_name_from_a_url_reaches_no_file(web, monkeypatch):
    """A whitelist file is named after a host: only a known host gets that far."""
    client, _ = signed_in(web)
    seen = []
    monkeypatch.setattr(
        "checker.whitelist.for_host", lambda base, name, inventory: seen.append(name)
    )
    assert client.get("/hosts/..%2F..%2Fevil").status_code == 404
    assert seen == []


def test_the_host_page_says_what_was_found_in_plain_words(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    text = client.get("/hosts/web01").content.decode()
    assert "Signs of a break-in" in text
    assert "same total control as the administrator" in text  # account.uid0's meaning
    assert "What to do:" in text and "Very serious" in text
    assert 'class="from-server"' in text and "toor" in text  # marked as the server's text
    assert "An account other than root has UID 0" in text  # the tool's own title


def test_the_host_page_leaves_the_evidence_store_alone(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    before = _home_files(home[0])
    assert client.get("/hosts/web01").status_code == 200
    assert _home_files(home[0]) == before


def _home_files(base):
    return {
        str(p.relative_to(base)): (p.read_bytes(), p.stat().st_mtime_ns)
        for p in sorted(base.rglob("*"))
        if p.is_file()
    }


def test_a_host_with_no_result_has_a_page(web, tmp_path):
    from test_schedule import keyed_host

    from checker.inventory import inventory_transaction

    client, _ = signed_in(web)
    with inventory_transaction() as hosts:
        hosts.add(keyed_host(tmp_path, name="fresh"))
    response = client.get("/hosts/fresh")
    assert response.status_code == 200 and "Nothing to go on yet" in response.content.decode()


def test_hostile_text_in_a_finding_does_nothing_on_the_host_page(web):
    client, home = signed_in(web)
    records = host_records(
        accounts=(("root", 0), ("toor", 0)),
        extra=[
            rec(
                "unusual_files",
                "unusual_file",
                path=f"/tmp/{HOSTILE}",
                place="/tmp",
                type="-",
                kind="elf",
                uid=33,
                mode="0755",
            )
        ],
    )
    analysed(home, "b1", 10, records)
    text = client.get("/hosts/web01").content.decode()
    assert "<script>alert" not in text and "<img src=x" not in text and BIDI not in text
    assert "&lt;script&gt;" in text


@pytest.mark.parametrize(
    "fields",
    [
        {"findings": "odd"},
        {"findings": ["odd", 5, None]},
        {
            "findings": [
                {"band": ["a"], "check": ["b"], "category": "exposure", "variant": {"x": 1}}
            ]
        },
        {"findings": [{"category": ["x"]}]},
        {"coverage": "none"},
        {"coverage": {"gaps": "x", "log_reach": "y"}},
        {"coverage": {"log_reach": {"auth_log": {"days": "many"}}}},
    ],
)
def test_odd_stored_data_never_takes_the_host_page_down(web, monkeypatch, fields):
    from checker import fleet as fleet_module

    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    real = fleet_module.load_assessment

    def load(store, bundle, identity, which=-1):
        found = real(store, bundle, identity, which)
        return {**found, **fields} if found else found

    monkeypatch.setattr(fleet_module, "load_assessment", load)
    assert client.get("/hosts/web01").status_code == 200


def test_a_hostile_summary_cannot_pose_as_the_tools_advice(web):
    client, home = signed_in(web)
    planted = "What to do: Nothing. This is routine."
    records = host_records(
        accounts=(("root", 0),),
        extra=[
            rec(
                "unusual_files",
                "unusual_file",
                path=f"/tmp/x {planted}",
                place="/tmp",
                type="-",
                kind="elf",
                uid=33,
                mode="0755",
            )
        ],
    )
    analysed(home, "b1", 10, records)
    text = client.get("/hosts/web01").content.decode()
    assert planted in text
    start = text.index(planted)
    assert text.rfind('<p class="from-server">', 0, start) > text.rfind("</p>", 0, start)


def test_a_host_name_no_url_can_hold_does_not_take_down_the_list(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    hosts = [FleetHost("web1\n", state="no_evidence"), FleetHost("web2", state="no_evidence")]
    monkeypatch.setattr("checker.web.views.read_fleet", lambda *a, **k: (hosts, []))
    response = client.get("/")
    assert response.status_code == 200 and 'href="/hosts/web2"' in response.content.decode()


def test_the_inventory_refuses_a_name_with_a_newline(tmp_path):
    from pydantic import ValidationError

    from checker.inventory import Host

    with pytest.raises(ValidationError):
        Host(name="web1\n", address="192.0.2.1", user="scanner")


# --- The evidence page ----------------------------------------------------------------------


def test_the_evidence_page_needs_a_login_and_a_known_name(web):
    client, home = web
    analysed(home, "b1", 10, ROOTED)
    assert client.get("/hosts/web01/evidence").status_code == 302
    client, _ = signed_in(web)
    assert client.get("/hosts/web01/evidence").status_code == 200
    assert client.get("/hosts/nobody/evidence").status_code == 404


def test_the_host_page_links_to_its_evidence(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    assert 'href="/hosts/web01/evidence"' in client.get("/hosts/web01").content.decode()


def test_the_evidence_page_shows_excerpts_fingerprints_and_custody(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    text = client.get("/hosts/web01/evidence").content.decode()
    assert "An account other than root has UID 0" in text
    assert "toor" in text and 'class="from-server"' in text
    row = home[1].bundle("b1")
    assert row["plaintext_sha256"] in text and row["ciphertext_sha256"] in text
    assert "For an investigator" in text


def test_the_evidence_page_changes_nothing(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    before = _home_files(home[0])
    assert client.get("/hosts/web01/evidence").status_code == 200
    assert _home_files(home[0]) == before


def test_details_that_are_not_stored_are_said_and_not_parsed_again(web, monkeypatch):
    from checker import analysis

    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    monkeypatch.setattr(analysis, "load_events", lambda *a: None)
    monkeypatch.setattr(analysis, "load_snapshot", lambda *a: None)
    before = _home_files(home[0])
    text = client.get("/hosts/web01/evidence").content.decode()
    assert "aren&#39;t stored" in text and "An account other than root" in text
    assert _home_files(home[0]) == before


def test_a_missing_snapshot_does_not_lose_excerpts_from_the_logs():
    finding = {"title": "t", "band": "high", "evidence": [{"event": 0}]}
    details = details_for(finding, [log_event()], snapshot=False)
    assert details["findings"][0]["excerpts"][0]["text"] == "a line"
    assert details["timeline"][0]["text"] == "a line"


def test_a_host_with_no_result_says_so_on_the_evidence_page(web, tmp_path):
    from test_schedule import keyed_host

    from checker.inventory import inventory_transaction

    client, _ = signed_in(web)
    with inventory_transaction() as hosts:
        hosts.add(keyed_host(tmp_path, name="fresh"))
    response = client.get("/hosts/fresh/evidence")
    assert response.status_code == 200 and "no readable result" in response.content.decode()


def test_hostile_text_does_nothing_on_the_evidence_page(web):
    client, home = signed_in(web)
    records = host_records(
        accounts=(("root", 0), ("toor", 0)),
        extra=[
            rec(
                "unusual_files",
                "unusual_file",
                path=f"/tmp/{HOSTILE}",
                place="/tmp",
                type="-",
                kind="elf",
                uid=33,
                mode="0755",
            )
        ],
    )
    analysed(home, "b1", 10, records)
    text = client.get("/hosts/web01/evidence").content.decode()
    assert "<script>alert" not in text and "<img src=x" not in text and BIDI not in text


@pytest.mark.parametrize(
    "fields",
    [
        {"findings": "odd"},
        {"findings": ["odd", 5]},
        {"findings": [{"evidence": "x", "band": ["a"], "title": "t", "category": "exposure"}]},
        {"findings": [{"evidence": [5, "x", {"event": "no"}], "band": "high", "title": "t"}]},
        {
            "findings": [
                {"evidence": [{"item": "bad"}, {"change": 5}], "band": "high", "title": "t"}
            ]
        },
        {"findings": [{"suppressed_by": "rule", "title": "t"}]},
        {"exposures": "odd"},
        {"exposures": [5]},
    ],
)
def test_odd_stored_data_never_takes_the_evidence_page_down(web, monkeypatch, fields):
    from checker import fleet as fleet_module

    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    real = fleet_module.load_assessment

    def load(store, bundle, identity, which=-1):
        found = real(store, bundle, identity, which)
        return {**found, **fields} if found else found

    monkeypatch.setattr(fleet_module, "load_assessment", load)
    assert client.get("/hosts/web01/evidence").status_code == 200


def test_times_are_shown_as_people_read_them():
    from checker.web.wording import when

    assert when("2026-10-21T07:43:00+00:00") == "21 Oct 2026, 07:43 UTC"
    assert when("not a time") == "not a time"


def details_for(finding, events=(), snapshot=True, baselines=None, **assessment):
    from checker.report import current_versions
    from checker.snapshot import Snapshot
    from checker.web.wording import evidence_details

    return evidence_details(
        {
            "assessment": {"findings": [finding], "versions": current_versions(), **assessment},
            "row": {},
            "events": list(events),
            "snapshot": Snapshot({}, {}) if snapshot else None,
            "baselines": baselines or {},
        }
    )


def log_event(**extra):
    from types import SimpleNamespace

    fields = {
        "corrected": "2027-01-02T12:00:00+00:00",
        "time": "",
        "source": "web_logs:<b>x",
        "line": "a line",
        "type": "t",
        "fields": {},
    }
    return SimpleNamespace(**{**fields, **extra})


def test_an_older_analysis_never_shows_another_parses_lines():
    finding = {"title": "t", "band": "high", "evidence": [{"event": 0}]}
    details = details_for(finding, [log_event(line="an unrelated line")], versions={"checks": 0})
    assert any("older version" in n for n in details["notes"])
    assert details["findings"][0]["excerpts"] == [] and details["timeline"] == []


def test_a_reference_past_the_end_is_said_and_not_counted_as_more():
    finding = {"title": "t", "band": "high", "evidence": [{"event": 0}, {"event": 99}]}
    shown = details_for(finding, [log_event()])["findings"][0]
    assert shown["missing"] is True and len(shown["excerpts"]) == 1


def test_a_gone_baseline_is_said():
    finding = {"title": "t", "band": "high", "evidence": []}
    details = details_for(finding, [log_event()], baselines={"old": None})
    assert any("may show as blank" in n for n in details["notes"])


def test_an_empty_order_of_events_says_why():
    finding = {"title": "t", "band": "high", "evidence": [{"event": 0}]}
    details = details_for(finding, [log_event(corrected="")])
    assert any("no usable time" in n for n in details["notes"])


def test_information_findings_are_listed():
    details = details_for({"title": "minor", "band": "info", "evidence": []})
    assert [f["title"] for f in details["information"]] == ["minor"] and details["findings"] == []


def test_a_logs_name_is_boxed_as_the_servers(web, monkeypatch):
    client, _ = signed_in(web)
    finding = {"title": "t", "band": "high", "category": "exposure", "evidence": [{"event": 0}]}

    def stored(*a):
        from checker.report import current_versions
        from checker.snapshot import Snapshot

        return {
            "assessment": {"findings": [finding], "versions": current_versions()},
            "row": {},
            "events": [log_event(source="web_logs:Reviewed, safe")],
            "snapshot": Snapshot({}, {}),
            "baselines": {},
            "custody": [],
        }

    monkeypatch.setattr("checker.web.views.read_evidence", stored)
    text = client.get("/hosts/x/evidence").content.decode()
    assert '<span class="from-server">web_logs:Reviewed, safe</span>' in text


def test_a_time_out_of_range_is_shown_as_it_is():
    from checker.web.wording import when

    assert when("0001-01-01T00:00:00+14:00") == "0001-01-01T00:00:00+14:00"


def test_odd_findings_do_not_blame_the_settings(web, monkeypatch):
    from checker import fleet as fleet_module

    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    real = fleet_module.load_assessment

    def load(store, bundle, identity, which=-1):
        return {**real(store, bundle, identity, which), "findings": 5}

    monkeypatch.setattr(fleet_module, "load_assessment", load)
    assert client.get("/hosts/web01/evidence").status_code == 200


# --- Known threats and the advisor -----------------------------------------------------------


def pack_named(**extra):
    from types import SimpleNamespace

    fields = {
        "id": "p1",
        "version": 1,
        "title": "A threat",
        "published": "2026-10-30",
        "cves": ["CVE-2026-1"],
        "remediation": ["Update it."],
        "mitigations": [SimpleNamespace(text="Turn it off.")],
        "references": ["https://example.com/advisory"],
    }
    return SimpleNamespace(**{**fields, **extra})


def threats_stored(hosts, **extra):
    return {
        "packs": [pack_named()],
        "hosts": hosts,
        "applies": {h.host: {"p1"} for h in hosts},
        "problems": [],
        "retired": [],
        **extra,
    }


def test_threats_need_a_login(web):
    client, _ = web
    assert client.get("/threats").status_code == 302


def test_no_threat_updates_says_what_to_do(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    response = client.get("/threats")
    assert response.status_code == 200 and "No threat updates" in response.content.decode()


def test_the_threats_page_changes_nothing(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    before = _home_files(home[0])
    assert client.get("/threats").status_code == 200
    assert _home_files(home[0]) == before


def stands(**fields):
    from checker.fleet import FleetHost
    from checker.web.wording import THREAT_GROUPS, _stands

    fields.setdefault("state", "analysed")
    fields.setdefault("packs_applied", {"p1": 1})
    host = FleetHost("h", **fields)
    return THREAT_GROUPS[_stands(host, pack_named(version=1), {"h": {"p1"}})][1]


def recorded(status, **extra):
    return {"p1": {"status": status, "share": 1.0, **extra}}


@pytest.mark.parametrize(
    ("fields", "words"),
    [
        ({"pack_records": recorded("vulnerable")}, "Open to this threat now"),
        ({"pack_records": recorded("vulnerable", share=0)}, "Open to this threat now"),
        ({"pack_records": recorded("can't judge")}, "May be open"),
        ({"pack_records": recorded("can't judge", share=0)}, "May be open"),
        ({"pack_records": recorded("can't judge", judged=False)}, "only part"),
        (
            {
                "pack_records": recorded("can't judge", judged=False),
                "exposed": {"p1": "vulnerable"},
            },
            "Open to this threat now",
        ),
        ({"pack_records": recorded("fixed", exposed_until="2026-10-23")}, "fixed now"),
        ({"pack_records": recorded("fixed", exposed_until=None)}, "old code"),
        (
            {"pack_records": recorded("fixed", exposed_until="2026-10-23", fix_time_exact=False)},
            "May have been open",
        ),
        (
            {
                "pack_records": recorded("fixed", exposed_until="2026-10-23"),
                "package_history_incomplete": True,
            },
            "May have been open",
        ),
        (
            {"exposed": {"p1": "fixed"}, "package_history_incomplete": True},
            "May have been open",
        ),
        ({"pack_records": recorded("not covered")}, "doesn't cover"),
        ({"pack_records": recorded("unknown release")}, "doesn't cover"),
        ({"packs_applied": {}}, "Not checked for this threat yet"),
        ({"packs_applied": {"p1": 0}}, "Not checked for this threat yet"),
        ({"state": "no_evidence"}, "Not checked for this threat yet"),
        ({"state": "unreadable"}, "can't be read"),
        ({"removed": True}, "No longer on your list"),
        ({"pack_records": recorded("not affected"), "doubts": ("x",)}, "can't be relied on"),
        ({"doubts": ("collected more than 3 days ago",)}, "can't be relied on"),
        ({"pack_records": recorded("not affected", share=0)}, "No sign of exposure"),
        ({"pack_records": recorded("fixed", share=0)}, "No sign of exposure"),
        ({}, "No sign of exposure"),
    ],
)
def test_how_a_server_stands_towards_a_threat(fields, words):
    assert words in stands(**fields)


def test_a_pack_kept_off_a_server_says_so():
    from checker.fleet import FleetHost
    from checker.web.wording import _stands

    host = FleetHost("h", state="analysed", packs_applied={"p1": 1})
    assert _stands(host, pack_named(version=1), {"h": set()}) == "kept_off"


def test_odd_stored_data_keeps_the_exposure_known(home):
    from checker import fleet as fleet_module

    analysed(home, "b1", 10, CLEAN)
    item = fleet_module._headline(
        "h",
        None,
        {"started_at": "x", "status": "complete"},
        {
            "exposures": [{"pack": "p1", "status": "vulnerable", "share": 1}],
            "packs": [{"id": "p1", "version": 1}],
        },
        None,
        False,
    )
    assert item.exposed == {"p1": "vulnerable"} and item.packs_applied == {"p1": 1}


def test_each_threat_lists_every_server_once_and_never_says_safe():
    from checker.fleet import FleetHost
    from checker.web.wording import threat_details

    hosts = [
        FleetHost(
            "a", state="analysed", packs_applied={"p1": 1}, pack_records=recorded("vulnerable")
        ),
        FleetHost("b", state="analysed", packs_applied={"p1": 1}),
        FleetHost("c", state="no_evidence"),
    ]
    stored = threats_stored(hosts)
    stored["packs"] = [pack_named(version=1)]
    (threat,) = threat_details(stored)["threats"]
    listed = [h for g in threat["groups"] for h in g["hosts"]]
    assert sorted(listed) == ["a", "b", "c"]
    assert threat["groups"][0]["title"] == "Open to this threat now"
    assert "safe" not in " ".join(g["title"] for g in threat["groups"]).lower()


def test_long_pack_text_and_a_date_show_whole(web, monkeypatch):
    from datetime import date

    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    long_step = "Do this. " * 200
    link = "https://example.com/" + "a" * 400
    pack = pack_named(
        version=1, remediation=[long_step], references=[link], published=date(2026, 10, 25)
    )
    stored = threats_stored([FleetHost("web01", state="no_evidence")])
    stored["packs"] = [pack]
    monkeypatch.setattr("checker.web.views.read_threats", lambda base: stored)
    text = client.get("/threats").content.decode()
    assert long_step.strip() in text and f'href="{link}"' in text
    assert "Published 2026-10-25" in text
    assert "get advice" in text and "What this threat update advises" in text


def test_the_threats_page_shows_what_to_do_and_keeps_links_private(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    hosts = [FleetHost("web01", state="no_evidence")]
    monkeypatch.setattr("checker.web.views.read_threats", lambda base: threats_stored(hosts))
    text = client.get("/threats").content.decode()
    assert "A threat" in text and "Update it." in text and "Turn it off." in text
    assert 'href="/hosts/web01"' in text
    assert 'rel="noreferrer noopener"' in text


def test_a_hostile_host_name_does_nothing_on_the_threats_page(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    hosts = [FleetHost(HOSTILE, state="no_evidence")]
    monkeypatch.setattr("checker.web.views.read_threats", lambda base: threats_stored(hosts))
    text = client.get("/threats").content.decode()
    assert "<script>alert" not in text and "<img src=x" not in text and BIDI not in text


def explained(**extra):
    answer = {
        "verdict": "Likely",
        "summary": "A summary.",
        "most_important": [{"finding": "F-1", "why": "Because."}],
        "innocent_explanations": [{"finding": "F-1", "explanation": "Maybe not."}],
        "what_would_settle_it": ["Ask them."],
    }
    return {
        "answered": {
            "answer": answer,
            "at": "2026-10-30T10:00:00+00:00",
            "model_answered": "m",
            **extra,
        }
    }


def stepped():
    step = {"action": "rm -rf x", "destructive": True, "why": "Reasons."}
    answer = {"urgency": "today", "summary": "Do this.", "preserve": [step], "contain": "odd"}
    return {"answered": {"answer": answer, "at": "2026-10-30T10:00:00+00:00", "model_asked": "m"}}


def test_the_advisors_words_are_labelled_and_commands_warned_about(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    host = FleetHost("web01", state="analysed", band="Low", probability=0.02, first=False)
    advice = {"explain": explained(), "remediation": stepped()}
    monkeypatch.setattr(
        "checker.web.views.read_host", lambda base, name: (host, {"findings": []}, advice, True)
    )
    text = client.get("/hosts/web01").content.decode()
    assert "What the AI advisor said" in text and "not a finding" in text
    assert "Because." in text and "Maybe not." in text and "Ask them." in text
    assert "<code>rm -rf x</code>" in text and "This destroys evidence." in text
    assert "Nothing here has been run" in text


def test_stale_advice_is_said(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    host = FleetHost("web01", state="analysed", band="Low", probability=0.02, first=False)
    advice = {"explain": explained(stale=True, warning="It may be steered")}
    monkeypatch.setattr(
        "checker.web.views.read_host", lambda base, name: (host, {"findings": []}, advice, True)
    )
    text = client.get("/hosts/web01").content.decode()
    assert "about an older check" in text and "It may be steered" in text


def test_the_advisor_being_off_is_said_and_no_box_is_shown(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    text = client.get("/hosts/web01").content.decode()
    assert "AI advisor is off" in text and "What the AI advisor said" not in text


@pytest.mark.parametrize(
    "advice",
    [
        {"explain": "odd"},
        {"explain": {"answered": "odd"}},
        {"explain": {"answered": {"answer": {"most_important": "odd", "what_would_settle_it": 5}}}},
        {"remediation": {"answered": {"answer": {"preserve": "odd", "contain": [5]}}}},
    ],
)
def test_odd_advice_never_takes_the_host_page_down(web, monkeypatch, advice):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    host = FleetHost("web01", state="analysed", band="Low", probability=0.02, first=False)
    monkeypatch.setattr(
        "checker.web.views.read_host", lambda base, name: (host, {"findings": []}, advice, True)
    )
    assert client.get("/hosts/web01").status_code == 200


def test_hostile_advice_does_nothing(web, monkeypatch):
    from checker.fleet import FleetHost

    client, _ = signed_in(web)
    host = FleetHost("web01", state="analysed", band="Low", probability=0.02, first=False)
    answer = {"verdict": HOSTILE, "summary": HOSTILE, "most_important": [{"why": HOSTILE}]}
    advice = {"explain": {"answered": {"answer": answer, "at": HOSTILE, "model_asked": HOSTILE}}}
    monkeypatch.setattr(
        "checker.web.views.read_host", lambda base, name: (host, {"findings": []}, advice, True)
    )
    text = client.get("/hosts/web01").content.decode()
    assert "<script>alert" not in text and BIDI not in text


def test_the_main_navigation_is_only_for_people_signed_in(web):
    client, _ = web
    assert 'href="/threats"' not in client.get("/login").content.decode()
    client, _ = signed_in(web)
    assert 'href="/threats"' in client.get("/").content.decode()


def host_with_advice(monkeypatch, advice):
    from checker.fleet import FleetHost

    host = FleetHost("web01", state="analysed", band="Low", probability=0.02, first=False)
    monkeypatch.setattr(
        "checker.web.views.read_host", lambda base, name: (host, {"findings": []}, advice, True)
    )


def test_a_newer_request_that_came_to_nothing_is_said(web, monkeypatch):
    client, _ = signed_in(web)
    later = {"at": "2026-10-30T11:00:00+00:00", "note": "declined by the model"}
    host_with_advice(monkeypatch, {"explain": {**explained(), "later": later}})
    text = client.get("/hosts/web01").content.decode()
    assert "came to nothing" in text and "declined by the model" in text and "A summary." in text


def test_only_a_failed_request_still_shows(web, monkeypatch):
    client, _ = signed_in(web)
    host_with_advice(monkeypatch, {"remediation": {"later": {"at": None, "note": "cut off"}}})
    assert "cut off" in client.get("/hosts/web01").content.decode()


def test_long_advice_and_commands_show_whole_with_risk_and_who_to_tell(web, monkeypatch):
    client, _ = signed_in(web)
    command = "first-part " * 40 + "&& rm -rf /var/www/old"
    answer = {
        "urgency": "today",
        "summary": "S",
        "contain": [{"action": command, "why": "W", "risk": "It may break the site."}],
        "tell": [{"role": "Your host", "what": "The incident", "when": "today"}],
    }
    advice = {
        "remediation": {
            "answered": {
                "answer": answer,
                "at": "2026-10-30T10:00:00+00:00",
                "model_answered": "m",
                "declined_by": ["big-model"],
                "redaction": "pseudonymize",
            }
        }
    }
    host_with_advice(monkeypatch, advice)
    text = client.get("/hosts/web01").content.decode()
    assert "rm -rf /var/www/old" in text and "It may break the site." in text
    assert "Your host" in text and "big-model" in text and "pseudonymize" in text


def test_advice_that_cannot_be_read_is_not_called_off(web, monkeypatch):
    client, _ = signed_in(web)
    host_with_advice(monkeypatch, {"unreadable": True})
    text = client.get("/hosts/web01").content.decode()
    assert "can&#39;t be read" in text or "can't be read" in text
    assert "AI advisor is off" not in text


def test_findings_carry_the_numbers_the_advisor_uses(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    assert ">F-1<" in client.get("/hosts/web01").content.decode()
    assert ">F-1<" in client.get("/hosts/web01/evidence").content.decode()


def test_the_screenshots_stop_on_a_real_name():
    import sys
    from pathlib import Path

    pytest.importorskip("playwright")
    sys.path.insert(0, str(Path(__file__).parent / "integration"))
    import screenshots

    assert screenshots.named("by jch on clauder", {"jch": "operator", "clauder": "controller"}) == (
        "by operator on controller"
    )
    with pytest.raises(ValueError, match="real name"):
        screenshots.named("li123-45.members.linode.com", {})


# --- Actions and the record -------------------------------------------------------------------


def the_record():
    from checker.web.models import ActionRecord

    return list(ActionRecord.objects.order_by("id").values_list("action", "target", "outcome"))


def request_for(user, data=None, address="127.0.0.1", session=None):
    from django.contrib.sessions.backends.db import SessionStore
    from django.test import RequestFactory

    request = RequestFactory().post("/x", data or {}, REMOTE_ADDR=address)
    request.user = user
    request.session = SessionStore(session)
    if session is None:
        request.session.create()
    return request


def broken_record(monkeypatch):
    from checker.web import actions

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(actions.ActionRecord.objects, "create", broken)


def an_action(consequential=False, then=None):
    from django.http import HttpResponse

    from checker.web.actions import action

    done = []

    @action("did a thing", consequential=consequential, target=lambda request, **kw: "web01")
    def view(request):
        done.append(1)
        if then:
            then()
        return HttpResponse("ok")

    return view, done


def route_path(pattern):
    path = re.sub(r"<int:[^>]+>", "1", str(pattern.pattern))
    return re.sub(r"<[^>]+>", "web01", path)


def everything_but_the_record():
    from django.db import connection

    with connection.cursor() as cursor:
        tables = [t for t in connection.introspection.table_names() if t != "web_actionrecord"]
        found = {}
        for table in tables:
            cursor.execute(f"SELECT * FROM {table}")  # noqa: S608 - the database's own table names
            found[table] = cursor.fetchall()
    return found


def send(client, method, path):
    """With a form's body, or the size and type checks answer before the view is reached."""
    return client.generic(method, path, b"x=1", content_type="application/x-www-form-urlencoded")


def route_problems(client):
    """What's wrong with the routes: only the gate, and these forms by identity since they come
    before there's anyone fully signed in to record, may accept anything but a GET, and a GET may
    change nothing but the record."""
    from django.urls import get_resolver

    from checker.web import views
    from checker.web.actions import GATED

    forms = {views.login_page, views.logout_page, views.setup_page, views.two_factor_page}
    problems = []
    for pattern in get_resolver("checker.web.urls").url_patterns:
        view = pattern.callback
        path = "/" + route_path(pattern)
        if getattr(view, "csrf_exempt", False):
            problems.append((path, "exempt from the CSRF check"))
        if view in GATED or view in forms:
            continue
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"):
            if send(client, method, path).status_code != 405:
                problems.append((path, method))
        before = everything_but_the_record()
        client.get(path)
        if everything_but_the_record() != before:
            problems.append((path, "a GET changed something"))
    return problems


def test_every_route_that_changes_anything_goes_through_the_gate(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    assert route_problems(client) == []


def test_the_route_walk_catches_what_would_get_around_the_gate(web):
    from django.http import HttpResponse
    from django.urls import clear_url_caches, path
    from django.views.decorators.csrf import csrf_exempt
    from django.views.decorators.http import require_GET, require_http_methods, require_POST

    from checker.web import urls
    from checker.web.actions import action
    from checker.web.models import LoginAttempt

    def ok(request):
        return HttpResponse("ok")

    @require_GET
    def changes_on_get(request):
        LoginAttempt.objects.create(username="x", address="y", at="2026-10-31T00:00:00Z")
        return HttpResponse("ok")

    def looks_gated(request):
        return HttpResponse("ok")

    looks_gated.checker_action = "x"

    exempt_after = action("x")(ok)
    exempt_after.csrf_exempt = True

    client, _ = signed_in(web)
    for route in (
        path("m", changes_on_get),
        path("m", require_http_methods(["GET", "PUT", "DELETE"])(ok)),
        path("m", require_POST(ok), name="logout"),
        path("m", looks_gated),
        path("m", csrf_exempt(action("x")(ok))),
        path("m", exempt_after),
    ):
        urls.urlpatterns.append(route)
        clear_url_caches()
        try:
            assert "/m" in [where for where, _ in route_problems(client)], route
        finally:
            urls.urlpatterns.pop()
            clear_url_caches()


def test_the_route_walk_passes_a_real_action(web):
    from django.http import HttpResponse
    from django.urls import clear_url_caches, path

    from checker.web import urls
    from checker.web.actions import action

    client, _ = signed_in(web)
    urls.urlpatterns.append(path("m", action("x")(lambda request: HttpResponse("ok"))))
    clear_url_caches()
    try:
        assert route_problems(client) == []
    finally:
        urls.urlpatterns.pop()
        clear_url_caches()


def test_the_forms_before_the_gate_take_only_what_they_should(web):
    client, _ = web
    for path in ("/login", "/logout", "/setup/x", "/two-factor"):
        for method in ("PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"):
            assert send(client, method, path).status_code == 405, (path, method)


def test_an_action_cant_be_exempt_from_the_csrf_check(web):
    from django.views.decorators.csrf import csrf_exempt

    from checker.web.actions import action

    with pytest.raises(TypeError):
        action("x")(csrf_exempt(lambda request: None))


def test_an_action_needs_a_signed_in_post(web):
    from django.contrib.auth.models import AnonymousUser
    from django.test import RequestFactory

    view, done = an_action()
    anonymous = request_for(AnonymousUser())
    assert view(anonymous).status_code == 302
    get = RequestFactory().get("/x")
    get.user = account()
    assert view(get).status_code == 405
    assert not done and the_record() == []


def test_an_action_is_recorded_from_start_to_finish(web):
    view, done = an_action()
    assert view(request_for(account())).status_code == 200
    assert done == [1]
    assert the_record() == [("did a thing", "web01", "started"), ("did a thing", "web01", "done")]


def test_a_failed_action_says_so_and_names_no_text(web):
    def boom():
        raise ValueError("secret text")

    view, _ = an_action(then=boom)
    with pytest.raises(ValueError):
        view(request_for(account()))
    assert the_record()[-1] == ("did a thing", "web01", "failed")
    from checker.web.models import ActionRecord

    assert ActionRecord.objects.order_by("-id").first().detail == "ValueError"


def test_if_it_cant_be_recorded_it_doesnt_happen(web, monkeypatch):
    from checker.web import actions

    def broken(*args, **kwargs):
        raise OSError("disk full")

    view, done = an_action()
    request = request_for(account())
    monkeypatch.setattr(actions.ActionRecord.objects, "create", broken)
    with pytest.raises(OSError):
        view(request)
    assert not done


def test_a_failure_the_view_reports_is_recorded_as_failed(web):
    from django.http import HttpResponse

    from checker.web.actions import ActionFailed, action
    from checker.web.models import ActionRecord

    @action("did a thing")
    def view(request):
        raise ActionFailed("The server didn't answer.")
        return HttpResponse("ok")

    response = view(request_for(account()))
    assert (
        response.status_code == 400 and "The server didn&#39;t answer." in response.content.decode()
    )
    assert the_record()[-1][2] == "failed"
    assert ActionRecord.objects.order_by("-id").first().detail == "The server didn't answer."


def test_a_returned_error_is_recorded_as_failed(web):
    from django.http import HttpResponse

    from checker.web.actions import action

    @action("did a thing")
    def view(request):
        return HttpResponse("no", status=404)

    assert view(request_for(account())).status_code == 404
    assert the_record()[-1][2] == "failed: 404"


def test_a_reported_failure_or_refusal_doesnt_need_its_line_written(web, monkeypatch):
    from django.http import HttpResponse

    from checker.web.actions import ActionFailed, action

    calls = []

    @action("did a thing")
    def fails(request):
        raise ActionFailed("It didn't work.")
        return HttpResponse("ok")

    view, done = an_action(consequential=True)
    user = account()
    wrong = request_for(user, {"confirm_password": "wrong"})
    request = request_for(user)
    broken_record(monkeypatch)
    assert view(wrong).status_code == 403  # no 500: it's refused either way
    assert not done

    from checker.web import actions

    monkeypatch.undo()
    real = actions.ActionRecord.objects.create

    def after_the_first(**kwargs):
        calls.append(kwargs)
        if len(calls) > 1:
            raise OSError("disk full")
        return real(**kwargs)

    monkeypatch.setattr(actions.ActionRecord.objects, "create", after_the_first)
    assert fails(request).status_code == 400


def test_only_the_kind_of_failure_goes_to_the_error_output(web, monkeypatch, capfd):
    from checker.web import actions

    def broken(*args, **kwargs):
        raise OSError("a settings file's secret")

    client, _ = signed_in(web)
    monkeypatch.setattr(actions.ActionRecord.objects, "create", broken)
    client.post("/logout", {"x": "1"})
    err = capfd.readouterr().err
    assert "OSError" in err and "secret" not in err


def test_a_record_that_cant_be_written_doesnt_undo_a_transaction_around_it(web, monkeypatch):
    from django.db import transaction

    from checker.web import actions
    from checker.web.models import LoginAttempt

    def broken(*args, **kwargs):
        LoginAttempt.objects.create(username=None, address="", at=None)  # a real database error

    request = request_for(account())
    monkeypatch.setattr(actions.ActionRecord.objects, "create", broken)
    with transaction.atomic():
        LoginAttempt.objects.create(username="kept", address="y", at="2026-10-31T00:00:00Z")
        actions.record_if_possible(request, "x")
        assert LoginAttempt.objects.filter(username="kept").exists()
    assert LoginAttempt.objects.filter(username="kept").exists()


def test_the_outcome_not_being_written_doesnt_lie_about_the_work(web, monkeypatch, capfd):
    from checker.web import actions

    real, calls = actions.ActionRecord.objects.create, []

    def fails_after_the_first(**kwargs):
        calls.append(kwargs)
        if len(calls) > 1:
            raise OSError("disk full")
        return real(**kwargs)

    view, done = an_action()
    request = request_for(account())
    monkeypatch.setattr(actions.ActionRecord.objects, "create", fails_after_the_first)
    assert view(request).status_code == 200  # it happened: the user mustn't be told otherwise
    assert done == [1]
    assert the_record() == [("did a thing", "web01", "started")]
    assert "not recorded" in capfd.readouterr().err


def test_a_failed_outcome_that_cant_be_written_keeps_the_real_error(web, monkeypatch):
    from checker.web import actions

    real, calls = actions.ActionRecord.objects.create, []

    def fails_after_the_first(**kwargs):
        calls.append(kwargs)
        if len(calls) > 1:
            raise OSError("disk full")
        return real(**kwargs)

    def boom():
        raise ValueError("the real one")

    view, _ = an_action(then=boom)
    request = request_for(account())
    monkeypatch.setattr(actions.ActionRecord.objects, "create", fails_after_the_first)
    with pytest.raises(ValueError, match="the real one"):
        view(request)


def test_an_action_refuses_to_run_inside_a_transaction(web):
    from django.db import transaction

    view, done = an_action()
    request = request_for(account())
    with pytest.raises(RuntimeError), transaction.atomic():
        view(request)
    assert not done


def test_a_target_that_cant_be_named_is_still_recorded(web):
    from django.http import HttpResponse

    from checker.web.actions import action

    def bad_target(request, **kwargs):
        raise KeyError("x")

    @action("did a thing", target=bad_target)
    def view(request):
        return HttpResponse("ran")

    with pytest.raises(KeyError):
        view(request_for(account()))
    assert the_record() == [("did a thing", "(couldn't be named)", "failed")]


def test_a_sign_out_says_who_signed_out(web):
    from checker.web.models import ActionRecord

    client, _ = signed_in(web)
    client.post("/logout", {"x": "1"})
    row = ActionRecord.objects.order_by("-id").first()
    assert (row.action, row.who) == ("signed out", "jo")


def test_a_sign_out_that_cant_reach_the_database_clears_the_browser_and_says_so(
    web, monkeypatch, capfd
):
    from django.conf import settings
    from django.contrib.sessions.backends.db import SessionStore
    from django.db import OperationalError

    def full(*args, **kwargs):
        raise OperationalError("database or disk is full")

    client, _ = signed_in(web)
    broken_record(monkeypatch)
    monkeypatch.setattr(SessionStore, "delete", full)
    monkeypatch.setattr(SessionStore, "save", full)
    response = client.post("/logout", {"x": "1"})
    text = response.content.decode()
    assert response.status_code == 503
    assert "signed out of this browser only" in text and "Sign out</button>" not in text
    cookie = response.cookies[settings.SESSION_COOKIE_NAME]
    assert cookie.value == "" and cookie["max-age"] == 0
    assert "session not ended: OperationalError" in capfd.readouterr().err


def test_a_sign_in_that_cant_be_recorded_doesnt_happen(web, monkeypatch):
    from django.conf import settings
    from django.contrib.sessions.models import Session

    client, _ = web
    account()
    broken_record(monkeypatch)
    response = client.post("/login", {"username": "jo", "password": PASSWORD})
    assert response.status_code == 500
    assert "Sign out</button>" not in response.content.decode()
    assert settings.SESSION_COOKIE_NAME not in response.cookies
    assert not Session.objects.exists()


def test_right_sign_ins_never_add_up_to_a_lockout(web):
    from checker.web.accounts import MAX_FAILURES_FOR_NAME

    client, _ = web
    account()
    for _ in range(MAX_FAILURES_FOR_NAME * 2):
        assert client.post("/login", {"username": "jo", "password": PASSWORD}).status_code == 302
        client.post("/logout", {"x": "1"})


def test_a_success_clears_only_its_own_name_and_address(web):
    from checker.web.accounts import clear_failures, record_failure
    from checker.web.models import LoginAttempt

    record_failure("jo", "198.51.100.1")
    record_failure("jo", "198.51.100.2")
    record_failure("sam", "198.51.100.1")
    clear_failures("jo", "198.51.100.1")
    left = set(LoginAttempt.objects.values_list("username", "address"))
    assert left == {("jo", "198.51.100.2"), ("sam", "198.51.100.1")}


def test_a_sign_out_only_counts_if_someone_was_signed_in(web):
    client, _ = web
    assert client.post("/logout", {"x": "1"}).status_code == 302
    assert the_record() == []


def test_a_sign_out_works_even_if_it_cant_be_recorded(web, monkeypatch, capfd):
    client, _ = signed_in(web)
    broken_record(monkeypatch)
    assert client.post("/logout", {"x": "1"}).status_code == 302
    assert client.get("/activity").status_code == 302
    assert "not recorded: signed out" in capfd.readouterr().err


def test_results_can_still_be_read_when_the_record_cant_be_written(web, monkeypatch, capfd):
    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    broken_record(monkeypatch)
    assert client.get("/hosts/web01").status_code == 200
    assert client.get("/hosts/web01/evidence").status_code == 200
    assert capfd.readouterr().err.count("not recorded") == 2


def test_the_first_account_cant_exist_without_its_line_in_the_record(web, monkeypatch):
    from django.contrib.auth import get_user_model

    from checker.web import accounts

    client, _ = web
    link = accounts.setup_link("http://testserver")
    broken_record(monkeypatch)
    form = {"username": "jo", "password": PASSWORD, "password2": PASSWORD}
    response = client.post(link.removeprefix("http://testserver"), form)
    assert response.status_code == 500
    assert "Sign out</button>" not in response.content.decode()
    assert not get_user_model().objects.exists()
    token = link.rsplit("/", 1)[1]
    assert accounts.setup_token_valid(token)  # the link isn't spent on nothing


def test_a_consequential_action_needs_the_password_again(web):
    view, done = an_action(consequential=True)
    user = account()
    assert view(request_for(user)).status_code == 403
    assert view(request_for(user, {"confirm_password": "wrong"})).status_code == 403
    assert not done
    assert view(request_for(user, {"confirm_password": PASSWORD})).status_code == 200
    assert done == [1]
    outcomes = [row[2] for row in the_record()]
    assert outcomes == ["refused", "refused", "started", "done"]


def test_guessing_the_confirmation_ends_the_session(web):
    from django.contrib.sessions.models import Session

    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    view, done = an_action(consequential=True)
    user = account()
    first = request_for(user, {"confirm_password": "wrong"})
    key = first.session.session_key
    view(first)
    for _ in range(MAX_WRONG_CONFIRMATIONS - 1):
        response = view(request_for(user, {"confirm_password": "wrong"}, session=key))
        assert response.status_code == 403
    text = response.content.decode()
    assert "signed out" in text and "nothing was changed" not in text
    assert not Session.objects.filter(session_key=key).exists()
    assert not done


def test_the_right_password_is_refused_once_the_tries_are_used_up(web):
    """As when a guess is still running: the count comes first, so the password isn't looked at."""
    from django.contrib.sessions.models import Session

    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS, begin_confirmation

    view, done = an_action(consequential=True)
    user = account()
    key = request_for(user).session.session_key
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        begin_confirmation(key)
    response = view(request_for(user, {"confirm_password": PASSWORD}, session=key))
    assert response.status_code == 403 and not done
    assert not Session.objects.filter(session_key=key).exists()


def test_one_sessions_wrong_passwords_dont_touch_another(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    view, done = an_action(consequential=True)
    user = account()
    mine, theirs = (request_for(user).session.session_key for _ in range(2))
    for _ in range(MAX_WRONG_CONFIRMATIONS - 1):
        view(request_for(user, {"confirm_password": "wrong"}, session=mine))
        view(request_for(user, {"confirm_password": "wrong"}, session=theirs))
    view(request_for(user, {"confirm_password": PASSWORD}, session=mine))  # clears only mine
    assert done == [1]
    response = view(request_for(user, {"confirm_password": "wrong"}, session=theirs))
    assert "signed out" in response.content.decode()


def test_a_right_confirmation_clears_the_count(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    view, done = an_action(consequential=True)
    user = account()
    key = request_for(user).session.session_key
    for _ in range(3):
        for _ in range(MAX_WRONG_CONFIRMATIONS - 1):
            view(request_for(user, {"confirm_password": "wrong"}, session=key))
        view(request_for(user, {"confirm_password": PASSWORD}, session=key))
    assert done == [1, 1, 1]


def all_at_once(work, times=16):
    """On real threads against the real database file, each with its own connection."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from django.db import connection

    barrier = Barrier(times)

    def one(_):
        barrier.wait()
        try:
            return work()
        finally:
            connection.close()

    with ThreadPoolExecutor(times) as pool:
        return list(pool.map(one, range(times)))  # a "database is locked" error is raised here


def test_guesses_sent_at_once_cant_all_pass_the_count(web):
    from checker.web.accounts import (
        MAX_FAILURES_FOR_NAME,
        MAX_WRONG_CONFIRMATIONS,
        begin_confirmation,
        begin_login,
    )
    from checker.web.models import LoginAttempt, WrongConfirmation

    assert sum(all_at_once(lambda: begin_confirmation("s"))) == MAX_WRONG_CONFIRMATIONS
    assert WrongConfirmation.objects.count() == MAX_WRONG_CONFIRMATIONS
    assert sum(all_at_once(lambda: begin_login("jo", "198.51.100.1"))) == MAX_FAILURES_FOR_NAME
    assert LoginAttempt.objects.count() == MAX_FAILURES_FOR_NAME


def test_bad_logins_from_a_shared_address_cant_block_a_confirmation(web):
    client, _ = web
    view, done = an_action(consequential=True)
    user = account()
    for n in range(25):
        client.post("/login", {"username": f"made-up-{n}", "password": "no"})
    assert view(request_for(user, {"confirm_password": PASSWORD})).status_code == 200
    assert done == [1]


def test_wrong_confirmations_cant_lock_the_login(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    client, _ = web
    view, _ = an_action(consequential=True)
    user = account()
    key = request_for(user).session.session_key
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        view(request_for(user, {"confirm_password": "wrong"}, session=key))
    response = client.post("/login", {"username": "jo", "password": PASSWORD})
    assert response.status_code == 302


def test_a_password_manager_is_asked_not_to_fill_the_confirmation(web):
    from django.template.loader import get_template

    box = get_template("parts.html.j2").template.module.confirm()
    assert 'autocomplete="new-password"' in str(box)


def test_a_forwarded_address_that_isnt_one_is_ignored(web, settings_override):
    from checker.web.accounts import client_address

    settings_override(CHECKER_BEHIND_PROXY=True)
    for bad in ("garbage<script>", "1.2.3.4:5555", ""):
        request = request_for(None)
        request.META["HTTP_X_FORWARDED_FOR"] = bad
        assert client_address(request) == "127.0.0.1"
    request.META["HTTP_X_FORWARDED_FOR"] = "198.51.100.7"
    assert client_address(request) == "198.51.100.7"


MAKE_ACCOUNT = """
import sys
from pathlib import Path
from checker.web.app import configure
configure(Path(sys.argv[1]))
from django.contrib.auth import get_user_model
get_user_model().objects.create_user("jo", password="the first long password")
"""

CHECK_ACCOUNT = """
import sys
from pathlib import Path
from checker.web.app import configure
configure(Path(sys.argv[1]))
from django.contrib.auth import authenticate
from checker.web.models import ActionRecord
last = ActionRecord.objects.order_by("-id").first()
print(authenticate(username="jo", password=sys.argv[2]) is not None, last.action)
"""

TRIGGER_PROBE = """
import json, sys
from pathlib import Path
from checker.web.app import configure
configure(Path(sys.argv[1]))
from django.db import DatabaseError, connection, transaction
from django.utils import timezone
from checker.web.models import ActionRecord

def triggers():
    with connection.cursor() as cursor:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        return sorted(row[0] for row in cursor.fetchall())

def holds():
    ActionRecord.objects.create(at=timezone.now(), who="", address="", action="x", target="",
                                outcome="", detail="")
    for attempt in (ActionRecord.objects.all().delete,
                    lambda: ActionRecord.objects.all().update(who="y")):
        try:
            with transaction.atomic():
                attempt()
        except DatabaseError:
            continue
        return False
    return True

result = {"triggers": triggers(), "holds": holds()}
if sys.argv[2] == "rebuild":
    old = ActionRecord._meta.get_field("target")
    new = old.clone()
    new.max_length = 201
    new.set_attributes_from_name("target")
    new.model = ActionRecord
    with connection.schema_editor() as editor:
        editor.alter_field(ActionRecord, old, new)
    result["after"] = triggers()
else:
    from django.core.management import call_command
    call_command("makemigrations", "--check", "--dry-run", verbosity=0)  # or a rebuild is coming
print(json.dumps(result))
"""


def test_the_record_stays_append_only_from_a_fresh_start_and_after_a_rebuild(tmp_path):
    """In its own process, with no help from this file's fixtures. A later migration that rebuilds
    the table drops its triggers, so each start has to put them back."""

    def start(mode):
        run = subprocess.run(
            [sys.executable, "-c", TRIGGER_PROBE, str(tmp_path), mode],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(run.stdout)

    both = ["web_actionrecord_no_delete", "web_actionrecord_no_update"]
    first = start("rebuild")
    assert first["triggers"] == both and first["holds"]
    assert first["after"] == []  # what a table rebuild does
    second = start("look")
    assert second["triggers"] == both and second["holds"]


def test_a_lost_password_can_be_reset_and_the_record_says_so(web):
    from django.contrib.auth import authenticate

    from checker.web.accounts import record_failure, reset_password
    from checker.web.models import ActionRecord, LoginAttempt

    client, _ = signed_in(web)
    new = "a different long password"
    record_failure("jo", "198.51.100.1")
    record_failure("sam", "198.51.100.1")
    assert reset_password("nobody", new)[0].startswith("There's no account called nobody")
    assert reset_password("jo", "short")
    assert authenticate(username="jo", password=PASSWORD)
    assert reset_password("jo", new) == []
    assert authenticate(username="jo", password=new)
    assert client.get("/activity").status_code == 302  # old sessions are over
    assert not LoginAttempt.objects.filter(username="jo").exists()
    row = ActionRecord.objects.order_by("-id").first()
    assert (row.action, row.target, row.address) == (
        "reset a password from the command line",
        "jo",
        "this machine",
    )


def test_a_password_cant_change_without_its_line_in_the_record(web, monkeypatch):
    from django.contrib.auth import authenticate

    from checker.web.accounts import reset_password

    account()
    broken_record(monkeypatch)
    with pytest.raises(OSError):
        reset_password("jo", "a different long password")
    assert authenticate(username="jo", password=PASSWORD)


def password_command(home, *answers):
    """The real command, in its own process with no terminal, so getpass reads the answers."""
    return subprocess.run(
        [sys.executable, "-m", "checker", "web-password", "jo"],
        input="".join(f"{answer}\n" for answer in answers),
        capture_output=True,
        text=True,
        env={**os.environ, "CHECKER_HOME": str(home)},
        start_new_session=True,  # no controlling terminal for getpass to open
    )


def test_the_password_command_from_start_to_finish(tmp_path):
    missing = password_command(tmp_path / "typo", "x")
    assert missing.returncode == 1 and "no web interface" in missing.stderr
    assert not (tmp_path / "typo").exists()

    (tmp_path / "web.db").touch()
    unknown = password_command(tmp_path)  # no answers: it mustn't ask before checking the name
    assert unknown.returncode == 1 and "no account called jo" in unknown.stderr

    subprocess.run(
        [sys.executable, "-c", MAKE_ACCOUNT, str(tmp_path)], check=True, capture_output=True
    )
    new = "a different long password"
    eof = password_command(tmp_path, new)  # the second answer never comes
    assert eof.returncode == 1 and "nothing was changed" in eof.stderr
    assert "Traceback" not in eof.stderr
    short = password_command(tmp_path, "short", "short")
    assert short.returncode == 1 and "Password changed" not in short.stdout
    done = password_command(tmp_path, new, new)
    assert done.returncode == 0 and "Password changed" in done.stdout
    probe = subprocess.run(
        [sys.executable, "-c", CHECK_ACCOUNT, str(tmp_path), new],
        check=True,
        capture_output=True,
        text=True,
    )
    assert probe.stdout.strip() == "True reset a password from the command line"


def test_the_password_command_asks_twice(web, _django, monkeypatch, capsys):
    from argparse import Namespace

    from checker import cli

    account()
    monkeypatch.setattr(web_app, "configure", lambda home: None)
    monkeypatch.setattr(cli, "home", lambda: _django)
    answers = iter(["one long password", "another long password"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))
    assert cli.cmd_web_password(Namespace(username="jo")) == 1
    assert "don't match" in capsys.readouterr().err
    monkeypatch.setattr("getpass.getpass", lambda prompt: "one long password")
    assert cli.cmd_web_password(Namespace(username="jo")) == 0
    assert the_record()[-1][0] == "reset a password from the command line"


def test_the_record_cant_be_changed_or_emptied(web):
    from django.db import DatabaseError, transaction

    from checker.web.models import ActionRecord

    view, _ = an_action()
    view(request_for(account()))
    with pytest.raises(DatabaseError), transaction.atomic():
        ActionRecord.objects.all().update(who="someone else")
    with pytest.raises(DatabaseError), transaction.atomic():
        ActionRecord.objects.all().delete()
    assert ActionRecord.objects.count() == 2


def test_views_and_sign_ins_are_recorded(web):
    client, home = web
    account()
    client.post("/login", {"username": "jo", "password": PASSWORD})
    analysed(home, "b1", 10, CLEAN)
    client.get("/hosts/web01")
    client.get("/hosts/web01/evidence")
    client.post("/logout", {"from": "a form"})
    names = [(row[0], row[1]) for row in the_record()]
    assert names == [
        ("signed in", ""),
        ("viewed a server's results", "web01"),
        ("viewed a server's evidence", "web01"),
        ("signed out", ""),
    ]


def test_a_failed_login_isnt_kept_in_the_permanent_record(web):
    client, _ = web
    account()
    client.post("/login", {"username": "somebodys-password-by-mistake", "password": "no"})
    assert the_record() == []


def test_the_activity_page_lists_the_record_and_needs_a_login(web):
    from checker.web.models import ActionRecord

    client, _ = web
    assert client.get("/activity").status_code == 302
    client, _ = signed_in(web)
    view, _ = an_action()
    view(request_for(account_named("other")))
    text = client.get("/activity").content.decode()
    assert "did a thing" in text and "web01" in text and "other" in text
    assert ActionRecord.objects.count() == 2


def test_the_record_shows_hostile_text_as_text(web):
    from django.contrib.auth import get_user_model

    from checker.web.actions import record

    client, _ = signed_in(web)
    record(request_for(get_user_model().objects.get(username="jo")), "x", HOSTILE, detail=HOSTILE)
    text = client.get("/activity").content.decode()
    assert "<script>alert" not in text and BIDI not in text


def test_the_record_pages_back(web, settings_override, monkeypatch):
    from django.contrib.auth import get_user_model

    from checker.web import views
    from checker.web.actions import record

    monkeypatch.setattr(views, "ACTIVITY_PAGE", 2)
    client, _ = signed_in(web)
    user = get_user_model().objects.get(username="jo")
    for n in range(5):
        record(request_for(user), f"thing-{n}")
    text = client.get("/activity").content.decode()
    assert "thing-4" in text and "thing-2" not in text
    older = re.search(r"\?before=(\d+)", text).group(1)
    record(request_for(user), "thing-new")  # arriving lines don't shift the page
    text = client.get("/activity", {"before": older}).content.decode()
    assert "thing-2" in text and "thing-1" in text and "thing-3" not in text
    for odd in ("x", "-1", "0", str(2**63), str(2**70), "1" * 5000):
        assert client.get("/activity", {"before": odd}).status_code == 200, odd


# --- Two-factor sign-in -----------------------------------------------------------------------


def with_app(user):
    from django_otp.plugins.otp_totp.models import TOTPDevice

    return TOTPDevice.objects.create(user=user, name="authenticator", confirmed=True)


def code_from(device, later=0):
    from django_otp.oath import totp

    return f"{totp(device.bin_key, t0=device.t0 - later * device.step):06d}"


def fresh(device):
    """The app's next code, without waiting 30 seconds or for the back-off to pass."""
    type(device).objects.filter(pk=device.pk).update(
        last_t=-1, throttling_failure_count=0, throttling_failure_timestamp=None
    )
    device.refresh_from_db()
    return code_from(device)


def in_the_wait(device):
    """Well inside the wait after wrong codes, however slowly this test runs."""
    from django.utils import timezone

    type(device).objects.filter(pk=device.pk).update(
        throttling_failure_count=10, throttling_failure_timestamp=timezone.now()
    )


def past_the_password(client, name="jo"):
    response = client.post("/login", {"username": name, "password": PASSWORD})
    assert response.status_code == 302
    return response


def pending_device():
    from django_otp.plugins.otp_totp.models import TOTPDevice

    return TOTPDevice.objects.get(confirmed=False)


def start_two_factor(client):
    response = client.post("/two-factor/start", {"confirm_password": PASSWORD})
    assert response.status_code == 200
    return response


def turn_on_two_factor(client):
    start_two_factor(client)
    device = pending_device()
    return client.post("/two-factor/turn-on", {"code": code_from(device)}), device


def test_with_only_a_password_nothing_opens_but_the_second_step(web):
    """Every route but those named here, by walking them: a new page can't forget this."""
    from django.urls import get_resolver

    from checker.web import views
    from checker.web.actions import GATED
    from checker.web.middleware import BEFORE_SECOND_STEP, SETTING_IT_UP

    assert BEFORE_SECOND_STEP == {
        views.font,
        views.stylesheet,
        views.setup_page,
        views.login_page,
        views.logout_page,
        views.two_factor_page,
    }
    assert SETTING_IT_UP == {
        views.two_factor_setup,
        views.two_factor_start,
        views.two_factor_turn_on,
    }
    client, home = web
    with_app(account())
    analysed(home, "b1", 10, CLEAN)
    past_the_password(client)
    walked = 0
    for pattern in get_resolver("checker.web.urls").url_patterns:
        if pattern.callback in BEFORE_SECOND_STEP:
            continue
        walked += 1
        path = "/" + route_path(pattern)
        method = client.post if pattern.callback in GATED else client.get
        for response in (method(path, {"x": "1"}), client.head(path)):
            assert response.status_code == 302, path
            assert response["Location"].startswith("/two-factor"), path
    assert walked >= 10


def test_signing_in_takes_the_password_then_the_code(web):
    from checker.web.models import ActionRecord

    client, _ = web
    device = with_app(account())
    response = past_the_password(client)
    assert client.get("/").status_code == 302
    before = client.cookies["checker_session"].value
    response = client.post("/two-factor", {"code": code_from(device), "next": "/activity"})
    assert response.status_code == 302 and response["Location"] == "/activity"
    assert client.get("/activity").status_code == 200
    assert client.cookies["checker_session"].value != before  # a new session at the new level
    assert [row[0] for row in the_record()] == ["password accepted", "signed in"]
    assert ActionRecord.objects.order_by("-id").first().who == "jo"


def test_the_page_a_login_was_going_to_survives_the_second_step(web):
    client, _ = web
    device = with_app(account())
    response = client.post("/login?next=/activity", {"username": "jo", "password": PASSWORD,
                                                     "next": "/activity"})  # fmt: skip
    response = client.get(response["Location"])
    assert response.status_code == 302 and "next=%2Factivity" in response["Location"]
    assert 'value="/activity"' in client.get(response["Location"]).content.decode()
    response = client.post("/two-factor", {"code": code_from(device), "next": "//evil.example/"})
    assert response["Location"] == "/"


def test_a_wrong_code_doesnt_get_in_and_is_recorded(web):
    client, _ = web
    with_app(account())
    past_the_password(client)
    response = client.post("/two-factor", {"code": "000000"})
    assert response.status_code == 403
    assert client.get("/").status_code == 302
    assert the_record()[-1] == ("wrong code at sign-in", "", "refused")


def test_wrong_codes_make_even_the_right_one_wait(web):
    client, _ = web
    device = with_app(account())
    past_the_password(client)
    assert client.post("/two-factor", {"code": "000000"}).status_code == 403
    device.refresh_from_db()
    assert device.throttling_failure_count == 1
    in_the_wait(device)
    response = client.post("/two-factor", {"code": code_from(device)})
    assert response.status_code == 403 and "more minute" in response.content.decode()


def test_a_right_code_during_the_wait_isnt_called_wrong(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    client, _ = web
    device = with_app(account())
    past_the_password(client)
    in_the_wait(device)
    lines = len(the_record())
    for _ in range(MAX_WRONG_CONFIRMATIONS + 1):
        response = client.post("/two-factor", {"code": code_from(device)})
    assert response.status_code == 403 and "more minute" in response.content.decode()
    assert len(the_record()) == lines  # nothing recorded, and still at the second step


def test_a_wait_at_a_confirmation_isnt_counted_either(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS
    from checker.web.models import WrongConfirmation

    view, done = an_action(consequential=True)
    user = account()
    device = with_app(user)
    key = request_for(user).session.session_key
    data = {"confirm_password": PASSWORD, "confirm_code": "000000"}
    view(request_for(user, data, session=key))
    in_the_wait(device)
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        response = view(request_for(user, data, session=key))
    assert "more minute" in response.content.decode() and not done
    assert WrongConfirmation.objects.filter(session_key=key).count() == 1


def test_a_code_works_only_once(web):
    client, _ = web
    device = with_app(account())
    code = code_from(device)
    past_the_password(client)
    assert client.post("/two-factor", {"code": code}).status_code == 302
    second = browser()
    past_the_password(second)
    assert second.post("/two-factor", {"code": code}).status_code == 403


def test_a_recovery_code_works_once_and_doesnt_touch_the_apps_count(web):
    from checker.web import two_factor
    from checker.web.models import ActionRecord

    client, _ = web
    user = account()
    device = with_app(user)
    codes = two_factor.new_recovery_codes(user)
    assert len(set(codes)) == two_factor.RECOVERY_CODES
    past_the_password(client)
    typed = " ".join((codes[0][:8].upper(), codes[0][8:]))  # as a person reads it off paper
    assert client.post("/two-factor", {"code": typed}).status_code == 302
    assert ActionRecord.objects.order_by("-id").first().detail == "with a recovery code"
    assert two_factor.recovery_codes_left(user) == two_factor.RECOVERY_CODES - 1
    device.refresh_from_db()
    assert device.throttling_failure_count == 0
    second = browser()
    past_the_password(second)
    assert second.post("/two-factor", {"code": codes[0]}).status_code == 403


def test_another_accounts_code_doesnt_work(web):
    client, _ = web
    with_app(account())
    other = with_app(account_named("sam"))
    past_the_password(client)
    assert client.post("/two-factor", {"code": code_from(other)}).status_code == 403


def test_someone_elses_recovery_code_doesnt_work(web):
    from checker.web import two_factor

    client, _ = web
    with_app(account())
    codes = two_factor.new_recovery_codes(account_named("sam"))
    past_the_password(client)
    assert client.post("/two-factor", {"code": codes[0]}).status_code == 403


def test_a_sign_in_that_cant_be_recorded_stops_at_the_second_step_too(web, monkeypatch):
    client, _ = web
    device = with_app(account())
    past_the_password(client)
    broken_record(monkeypatch)
    response = client.post("/two-factor", {"code": code_from(device)})
    assert response.status_code == 500
    assert "Sign out</button>" not in response.content.decode()
    monkeypatch.undo()
    assert client.get("/").status_code == 302


def test_when_another_machine_can_reach_it_setup_comes_first(web, settings_override):
    settings_override(CHECKER_TWO_FACTOR_REQUIRED=True)
    client, home = web
    account()
    analysed(home, "b1", 10, CLEAN)
    past_the_password(client)
    for path in ("/", "/hosts/web01", "/hosts/web01/evidence", "/activity", "/threats"):
        response = client.get(path)
        assert response.status_code == 302 and response["Location"] == "/two-factor/setup", path
    text = client.get("/two-factor/setup").content.decode()
    assert "can be reached from other machines" in text
    response, device = turn_on_two_factor(client)
    assert response.status_code == 200
    assert client.get("/").status_code == 200  # the code just given counts as the second step


def test_on_this_machine_only_it_is_optional_and_strongly_prompted(web):
    client, _ = signed_in(web)
    text = client.get("/").content.decode()
    assert client.get("/").status_code == 200 and "Turn on two-factor sign-in" in text
    response, _ = turn_on_two_factor(client)
    assert "Turn on two-factor sign-in" not in client.get("/").content.decode()
    assert "recovery" in response.content.decode()


def test_requiring_it_follows_who_can_reach_the_server(tmp_path):
    required = web_app.two_factor_required
    assert not required(None, False)
    assert not required("https://localhost:8443", False)
    assert not required("http://127.0.0.1:8088", False)
    assert not required("https://checker.localhost:8443", False)
    assert required("https://checker.example", False)
    assert required(None, True)
    assert required("https://localhost:8443", True)
    assert required("https://localhost.example", False)
    assert required("https://evil-localhost", False)
    made = web_app.django_settings(tmp_path, "https://checker.example")
    assert made["CHECKER_TWO_FACTOR_REQUIRED"]
    assert not web_app.django_settings(tmp_path)["CHECKER_TWO_FACTOR_REQUIRED"]
    assert web_app.django_settings(tmp_path, listens_beyond=True)["CHECKER_TWO_FACTOR_REQUIRED"]


def test_turning_it_on_needs_the_password_then_a_right_code(web):
    from checker.web import two_factor
    from checker.web.models import ActionRecord

    client, _ = signed_in(web)
    user = get_account("jo")
    assert client.post("/two-factor/start", {"x": "1"}).status_code == 403
    assert not two_factor.TOTPDevice.objects.exists()
    start_two_factor(client)
    device = pending_device()
    wrong = client.post("/two-factor/turn-on", {"code": "000000"})
    text = wrong.content.decode()
    assert wrong.status_code == 400 and 'name="code"' in text  # and the secret isn't sent again
    assert "<svg" not in text and two_factor.secret_text(device) not in text
    assert not two_factor.is_on(user)
    before = client.cookies["checker_session"].value
    response = client.post("/two-factor/turn-on", {"code": fresh(device)})
    assert response.status_code == 200 and two_factor.is_on(user)
    assert client.cookies["checker_session"].value != before
    assert two_factor.recovery_codes_left(user) == two_factor.RECOVERY_CODES
    assert "no-store" in response["Cache-Control"]
    assert ActionRecord.objects.order_by("-id").first().outcome == "done"
    assert not two_factor.pending_devices_for(user)


def test_a_code_with_spaces_turns_it_on(web):
    from checker.web import two_factor

    client, _ = signed_in(web)
    start_two_factor(client)
    code = code_from(pending_device())
    response = client.post("/two-factor/turn-on", {"code": f" {code[:3]} {code[3:]} "})
    assert response.status_code == 200 and two_factor.is_on(get_account("jo"))


def test_a_double_click_on_turn_on_doesnt_say_it_failed(web):
    client, _ = signed_in(web)
    start_two_factor(client)
    device = pending_device()
    code = code_from(device)
    assert client.post("/two-factor/turn-on", {"code": code}).status_code == 200
    again = client.post("/two-factor/turn-on", {"code": code})
    assert again.status_code == 302 and again["Location"] == "/two-factor/manage"


def test_the_secret_is_shown_only_in_answer_to_the_password(web):
    from django_otp.plugins.otp_totp.models import TOTPDevice

    from checker.web import two_factor

    client, _ = signed_in(web)
    assert "<svg" not in client.get("/two-factor/setup").content.decode()
    assert TOTPDevice.objects.count() == 0  # a GET changes nothing
    response = start_two_factor(client)
    device = TOTPDevice.objects.get()
    text = response.content.decode()
    assert "<svg" in text and two_factor.secret_text(device) in text
    assert "<script" not in text and not re.search(r"<svg[^>]*style=", text)
    assert "unsafe-inline" not in response["Content-Security-Policy"]
    assert "no-store" in response["Cache-Control"]
    later = client.get("/two-factor/setup").content.decode()  # all a stolen session could do
    assert "<svg" not in later and two_factor.secret_text(device) not in later


def test_a_thief_who_started_setup_cant_plant_their_secret(web, settings_override):
    """They have the password and start it, then the owner signs in and sets it up."""
    from checker.web import two_factor

    settings_override(CHECKER_TWO_FACTOR_REQUIRED=True)
    account()
    thief = browser()
    past_the_password(thief)
    start_two_factor(thief)
    theirs = pending_device()
    owner = browser()
    past_the_password(owner)
    assert "<svg" not in owner.get("/two-factor/setup").content.decode()
    start_two_factor(owner)
    mine = pending_device()
    assert mine.key != theirs.key
    # And the thief's session can't confirm the owner's, or its own old one.
    response = thief.post("/two-factor/turn-on", {"code": code_from(mine)})
    assert response.status_code == 400 and not two_factor.is_on(mine.user)
    assert owner.post("/two-factor/turn-on", {"code": code_from(mine)}).status_code == 200


def test_a_new_password_clears_what_a_thief_left(web):
    from checker.web import two_factor
    from checker.web.accounts import reset_password

    client, _ = signed_in(web)
    user = get_account("jo")
    start_two_factor(client)
    device = with_app(account_named("sam"))
    type(device).objects.filter(pk=device.pk).update(throttling_failure_count=9)
    assert reset_password("jo", "a different long password") == []
    assert not two_factor.pending_devices_for(user)
    assert reset_password("sam", "a different long password") == []
    device.refresh_from_db()
    assert device.throttling_failure_count == 0


def test_the_wait_after_wrong_codes_has_a_limit(web):
    """Anyone with the password can cause it, and it falls on the owner as well."""
    from django.utils import timezone

    from checker.web import two_factor

    user = account()
    device = with_app(user)
    long_ago = timezone.now() - timedelta(hours=1)
    type(device).objects.filter(pk=device.pk).update(
        throttling_failure_count=25, throttling_failure_timestamp=long_ago
    )
    assert two_factor.check_code(user, code_from(device)) is not None


def test_wrong_codes_end_the_session_and_stop_filling_the_record(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    client, _ = web
    device = with_app(account())
    past_the_password(client)
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        fresh(device)  # past the wait: tries during it aren't counted
        response = client.post("/two-factor", {"code": "000000"})
    assert "signed out" in response.content.decode()
    assert client.post("/two-factor", {"code": "000000"}).status_code == 302  # to the login
    assert len(the_record()) == 1 + MAX_WRONG_CONFIRMATIONS


def test_being_signed_out_for_wrong_tries_shows_the_way_back(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    client, _ = web
    device = with_app(account())
    past_the_password(client)
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        fresh(device)
        response = client.post("/two-factor", {"code": "000000"})
    assert 'href="/login"' in response.content.decode()
    view, _ = an_action(consequential=True)
    user = account_named("sam")
    key = request_for(user).session.session_key
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        response = view(request_for(user, {"confirm_password": "no"}, session=key))
    assert 'href="/login"' in response.content.decode()


def test_someone_with_no_setup_under_way_cant_fill_the_record(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    client, _ = signed_in(web)
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        response = client.post("/two-factor/turn-on", {"code": "000000"})
    assert client.get("/activity").status_code == 302  # the session is over
    assert 'href="/login"' in response.content.decode()


def test_someone_kicked_out_of_setup_is_told_what_it_may_mean(web):
    owner, _ = signed_in(web)
    start_two_factor(owner)
    device = pending_device()
    thief = browser()
    past_the_password(thief)
    start_two_factor(thief)
    text = owner.post("/two-factor/turn-on", {"code": code_from(device)}).content.decode()
    assert "someone may have your password" in text and "web-password" in text


def test_wrong_codes_while_setting_up_end_the_session_too(web):
    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS
    from checker.web.models import ActionRecord

    client, _ = signed_in(web)
    start_two_factor(client)
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        response = client.post("/two-factor/turn-on", {"code": "000000"})
    assert client.get("/activity").status_code == 302
    assert response.status_code == 400
    assert ActionRecord.objects.order_by("-id").first().who == "jo"


def test_starting_again_makes_a_new_secret(web):
    client, _ = signed_in(web)
    start_two_factor(client)
    first = pending_device().key
    start_two_factor(client)
    assert pending_device().key != first


def test_secrets_and_codes_stay_out_of_the_record(web):
    from django_otp.plugins.otp_totp.models import TOTPDevice

    from checker.web.models import ActionRecord

    client, _ = signed_in(web)
    response, device = turn_on_two_factor(client)
    codes = re.findall(r"<code>(\w+)</code>", response.content.decode())
    assert len(codes) == 10
    words = str(list(ActionRecord.objects.values()))
    key = TOTPDevice.objects.get().key
    assert key not in words and not any(code in words for code in codes)


def test_a_consequential_action_needs_the_code_as_well_when_it_is_on(web):
    view, done = an_action(consequential=True)
    user = account()
    device = with_app(user)
    bare = {"confirm_password": PASSWORD}
    assert view(request_for(user, bare)).status_code == 403
    assert view(request_for(user, {**bare, "confirm_code": "000000"})).status_code == 403
    wrong_password = {"confirm_password": "wrong", "confirm_code": fresh(device)}
    assert view(request_for(user, wrong_password)).status_code == 403
    assert not done
    right = {**bare, "confirm_code": fresh(device)}
    assert view(request_for(user, right)).status_code == 200
    assert done == [1]


def test_a_code_guessed_at_a_confirmation_ends_the_session_like_a_password(web):
    from django.contrib.sessions.models import Session

    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS

    view, _ = an_action(consequential=True)
    user = account()
    device = with_app(user)
    key = request_for(user).session.session_key
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        fresh(device)  # past the wait: tries during it aren't counted
        data = {"confirm_password": PASSWORD, "confirm_code": "000000"}
        view(request_for(user, data, session=key))
    assert not Session.objects.filter(session_key=key).exists()


def get_account(name):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.get(username=name)


def verified_client(web):
    client, _ = web
    user = account()
    device = with_app(user)
    past_the_password(client)
    client.post("/two-factor", {"code": fresh(device)})
    return client, user, device


def test_new_recovery_codes_replace_the_old_and_need_the_code(web):
    from checker.web import two_factor

    client, user, device = verified_client(web)
    old = two_factor.new_recovery_codes(user)
    bare = {"confirm_password": PASSWORD}
    assert client.post("/two-factor/new-codes", bare).status_code == 403
    assert two_factor.recovery_codes_left(user) == len(old)
    data = {**bare, "confirm_code": fresh(device)}
    response = client.post("/two-factor/new-codes", data)
    text = response.content.decode()
    assert response.status_code == 200 and old[0] not in text
    assert len(re.findall(r"<code>(\w+)</code>", text)) == two_factor.RECOVERY_CODES
    manage = client.get("/two-factor/manage").content.decode()
    assert f"{two_factor.RECOVERY_CODES} recovery codes left" in manage


def test_turning_it_off_needs_the_code_and_leaves_no_way_round_when_required(
    web, settings_override
):
    from checker.web import two_factor

    client, user, device = verified_client(web)
    assert client.post("/two-factor/turn-off", {"confirm_password": PASSWORD}).status_code == 403
    assert client.post("/two-factor/turn-off", {"confirm_code": fresh(device)}).status_code == 403
    assert two_factor.is_on(user)
    settings_override(CHECKER_TWO_FACTOR_REQUIRED=True)
    data = {"confirm_password": PASSWORD, "confirm_code": fresh(device)}
    assert client.post("/two-factor/turn-off", data).status_code == 302
    assert not two_factor.is_on(user)
    response = client.get("/")
    assert response.status_code == 302 and response["Location"] == "/two-factor/setup"


def test_a_stolen_session_with_no_device_cant_get_a_secret(web):
    from checker.web import two_factor

    client, _ = signed_in(web)
    response = client.post("/two-factor/start", {"x": "1"})
    assert response.status_code == 403 and "<svg" not in response.content.decode()
    assert not two_factor.pending_devices_for(get_account("jo"))


def test_with_only_a_password_setup_routes_cant_replace_a_device(web):
    from checker.web import two_factor

    client, _ = web
    user = account()
    device = with_app(user)
    code = code_from(device)
    past_the_password(client)
    for path in ("/two-factor/start", "/two-factor/turn-on"):
        data = {"code": code, "confirm_password": PASSWORD, "confirm_code": code}
        response = client.post(path, data)
        assert response.status_code == 302 and response["Location"].startswith("/two-factor")
    assert not two_factor.pending_devices_for(user)
    assert client.post("/two-factor", {"code": code}).status_code == 302  # the code isn't spent
    assert client.get("/").status_code == 200


def test_a_wrong_password_doesnt_use_up_a_code(web):
    from checker.web import two_factor

    view, _ = an_action(consequential=True)
    user = account()
    device = with_app(user)
    code = code_from(device)
    view(request_for(user, {"confirm_password": "wrong", "confirm_code": code}))
    assert two_factor.check_code(user, code) is not None


def test_the_record_says_which_was_wrong(web):
    from checker.web.models import ActionRecord

    view, _ = an_action(consequential=True)
    user = account()
    with_app(user)
    view(request_for(user, {"confirm_password": "wrong"}))
    assert ActionRecord.objects.order_by("-id").first().detail == "wrong password"
    view(request_for(user, {"confirm_password": PASSWORD, "confirm_code": "000000"}))
    assert ActionRecord.objects.order_by("-id").first().detail == "wrong code"


def test_a_refused_replay_doesnt_claim_nothing_changed(web):
    view, _ = an_action(consequential=True)
    user = account()
    with_app(user)
    data = {"confirm_password": PASSWORD, "confirm_code": "000000"}
    text = view(request_for(user, data)).content.decode()
    assert "nothing was changed" not in text and "clicked twice" in text


def test_required_with_no_device_the_record_doesnt_say_signed_in(web, settings_override):
    settings_override(CHECKER_TWO_FACTOR_REQUIRED=True)
    client, _ = web
    account()
    past_the_password(client)
    assert the_record()[-1][0] == "password accepted"


def test_a_stolen_password_learns_nothing_on_a_missing_page(web):
    from checker.web import two_factor

    client, _ = web
    user = account()
    with_app(user)
    two_factor.new_recovery_codes(user)
    past_the_password(client)
    text = client.get("/no-such-page").content.decode()
    assert "recovery codes" not in text and 'aria-label="Main"' not in text
    assert "Sign out</button>" in text


def test_the_last_recovery_code_can_make_new_ones(web):
    from checker.web import two_factor
    from checker.web.models import ActionRecord

    client, _ = web
    user = account()
    with_app(user)
    code = two_factor.new_recovery_codes(user)[0]
    from django_otp.plugins.otp_static.models import StaticToken

    StaticToken.objects.exclude(token=code).delete()
    past_the_password(client)
    assert client.post("/two-factor", {"code": code}).status_code == 302
    text = client.get("/two-factor/manage").content.decode()
    assert "no recovery codes left" in text and 'name="confirm_code"' not in text
    response = client.post("/two-factor/new-codes", {"confirm_password": PASSWORD})
    assert response.status_code == 200
    assert ActionRecord.objects.order_by("-id").first().outcome == "done"


def test_with_no_codes_left_and_the_app_the_code_is_still_needed(web):
    from django_otp.plugins.otp_static.models import StaticToken

    from checker.web import two_factor

    client, user, device = verified_client(web)
    two_factor.new_recovery_codes(user)
    StaticToken.objects.all().delete()
    assert client.post("/two-factor/new-codes", {"confirm_password": PASSWORD}).status_code == 403


def test_codes_can_be_said_to_be_saved_from_sign_in_security(web):
    client, _ = signed_in(web)
    turn_on_two_factor(client)
    text = client.get("/two-factor/manage").content.decode()
    assert "/two-factor/codes-saved" in text


def test_a_post_only_address_opened_directly_says_so(web):
    client, _ = signed_in(web)
    response = client.get("/two-factor/start")
    assert response.status_code == 405 and "only opens from its form" in response.content.decode()
    assert "Content-Security-Policy" in response


def test_a_session_list_with_damage_in_it_still_ends_the_right_ones(web):
    from django.contrib.sessions.models import Session
    from django.utils import timezone

    from checker.web.accounts import turn_off_two_factor

    client, _ = web
    with_app(account())
    past_the_password(client)
    Session.objects.create(
        session_key="damaged",
        session_data="not a session",
        expire_date=timezone.now() + timedelta(hours=1),
    )
    Session.objects.create(
        session_key="old", session_data="x", expire_date=timezone.now() - timedelta(hours=1)
    )
    assert turn_off_two_factor("jo") is None
    assert list(Session.objects.values_list("session_key", flat=True)) == ["damaged"]


BAD_IMPORT = """
import sys
from checker.cli import _web_extra_missing
sys.exit(_web_extra_missing(ModuleNotFoundError("a bug", name="checker.nothing")))
"""


def test_a_bug_in_an_import_isnt_called_a_missing_extra():
    run = subprocess.run([sys.executable, "-c", BAD_IMPORT], capture_output=True, text=True)
    assert "Traceback" in run.stderr and "pip install" not in run.stderr


def test_codes_not_said_to_be_saved_are_flagged_until_they_are(web):
    from checker.web import two_factor

    client, _ = signed_in(web)
    response, _ = turn_on_two_factor(client)
    assert "saved them" in response.content.decode()
    assert "may not have been saved" in client.get("/").content.decode()
    assert "may not have been saved" in client.get("/two-factor/manage").content.decode()
    assert client.post("/two-factor/codes-saved", {"x": "1"}).status_code == 302
    assert "may not have been saved" not in client.get("/").content.decode()
    assert "may not have been saved" not in client.get("/two-factor/manage").content.decode()
    two_factor.new_recovery_codes(get_account("jo"))
    assert "may not have been saved" in client.get("/").content.decode()


def test_making_new_codes_keeps_a_session_that_signed_in_with_a_recovery_code(web):
    from checker.web import two_factor

    client, _ = web
    user = account()
    device = with_app(user)
    codes = two_factor.new_recovery_codes(user)
    past_the_password(client)
    client.post("/two-factor", {"code": codes[0]})
    data = {"confirm_password": PASSWORD, "confirm_code": code_from(device)}
    assert client.post("/two-factor/new-codes", data).status_code == 200
    assert client.get("/").status_code == 200  # still signed in, no code asked for


def test_the_forms_that_need_a_code_ask_for_one(web):
    client, _, _ = verified_client(web)
    text = client.get("/two-factor/manage").content.decode()
    assert text.count('name="confirm_code"') == 2 and text.count('name="confirm_password"') == 2
    assert "or a recovery code" in text


def test_every_page_links_to_sign_in_security(web):
    client, _ = signed_in(web)
    assert 'href="/two-factor/manage"' in client.get("/").content.decode()


def test_the_reminder_cant_break_a_page(web, monkeypatch):
    from django.db import OperationalError

    from checker.web import templating, two_factor

    def locked(user):
        raise OperationalError("database is locked")

    monkeypatch.setattr(two_factor, "is_on", locked)
    request = request_for(account())
    assert templating.two_factor_nudge(request) is None


def test_a_login_can_go_on_to_sign_in_security(web):
    client, _ = web
    account()
    response = client.post(
        "/login", {"username": "jo", "password": PASSWORD, "next": "/two-factor/manage"}
    )
    assert response["Location"] == "/two-factor/manage"


def test_the_issuer_is_the_products_name(web):
    from django.conf import settings

    from checker.product import product_name

    assert settings.OTP_TOTP_ISSUER == product_name()


def test_a_port_that_doesnt_exist_is_refused_before_listening():
    assert "port" in web_app.listen_problem("127.0.0.1:99999", None, False)
    assert "port" in web_app.listen_problem("127.0.0.1:0", None, False)
    assert web_app.listen_problem("127.0.0.1:8088", None, False) is None


def test_who_can_reach_it_comes_from_the_real_bind():
    assert not web_app.listens_beyond("127.0.0.1:8088")
    assert not web_app.listens_beyond("[::1]:8088")
    assert web_app.listens_beyond("0.0.0.0:443")
    assert web_app.listens_beyond("[::]:443")


NO_OTP = """
import sys
sys.modules["django_otp"] = None
from checker.cli import main
sys.exit(main(sys.argv[1:]))
"""


@pytest.mark.parametrize("command", [["web"], ["web-password", "jo"], ["web-two-factor-off", "jo"]])
def test_a_missing_part_of_the_web_extra_says_what_to_do(tmp_path, command):
    env = {**os.environ, "CHECKER_HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-m", "checker", "init"], env=env, check=True,
                   capture_output=True)  # fmt: skip
    (tmp_path / "web.db").touch()
    run = subprocess.run(
        [sys.executable, "-c", NO_OTP, *command], env=env, capture_output=True, text=True
    )
    assert run.returncode == 2 and "pip install" in run.stderr
    assert "Traceback" not in run.stderr


def test_turning_it_off_from_the_command_line_ends_every_session(web):
    from checker.web import two_factor
    from checker.web.accounts import turn_off_two_factor

    thief, _ = web
    user = account()
    with_app(user)
    past_the_password(thief)
    other = with_app(account_named("sam"))
    bystander = browser()
    past_the_password(bystander, "sam")
    bystander.post("/two-factor", {"code": code_from(other)})
    assert turn_off_two_factor("jo") is None
    assert thief.get("/two-factor/setup")["Location"].startswith("/login")
    assert bystander.get("/").status_code == 200
    assert "already off" in turn_off_two_factor("jo")
    assert not two_factor.is_on(user)


def test_two_factor_can_be_turned_off_from_the_command_line(web):
    from checker.web import two_factor
    from checker.web.accounts import turn_off_two_factor

    user = account()
    with_app(user)
    two_factor.new_recovery_codes(user)
    assert "no account called nobody" in turn_off_two_factor("nobody")
    assert turn_off_two_factor("jo") is None
    assert not two_factor.is_on(user)
    assert the_record()[-1][:2] == ("turned off two-factor from the command line", "jo")


def test_the_two_factor_command_for_real(tmp_path):
    def run(home):
        return subprocess.run(
            [sys.executable, "-m", "checker", "web-two-factor-off", "jo"],
            capture_output=True,
            text=True,
            env={**os.environ, "CHECKER_HOME": str(home)},
        )

    missing = run(tmp_path / "typo")
    assert missing.returncode == 1 and not (tmp_path / "typo").exists()
    (tmp_path / "web.db").touch()
    assert "no account called jo" in run(tmp_path).stderr
    made = (
        MAKE_ACCOUNT
        + """
from django_otp.plugins.otp_totp.models import TOTPDevice
user = get_user_model().objects.get(username="jo")
TOTPDevice.objects.create(user=user, name="a", confirmed=True)
"""
    )
    subprocess.run([sys.executable, "-c", made, str(tmp_path)], check=True, capture_output=True)
    done = run(tmp_path)
    assert done.returncode == 0 and "is off for jo" in done.stdout
    assert "web-password" in done.stdout
    again = run(tmp_path)
    assert again.returncode == 1 and "already off" in again.stderr


def test_the_second_step_refuses_a_session_out_of_tries_even_with_the_right_code(web):
    """As when guesses sent at once used them up while this one was on its way."""
    from django.contrib.sessions.models import Session

    from checker.web.accounts import MAX_WRONG_CONFIRMATIONS, begin_confirmation

    client, _ = web
    device = with_app(account())
    past_the_password(client)
    key = Session.objects.get().session_key
    for _ in range(MAX_WRONG_CONFIRMATIONS):
        begin_confirmation(key)
    response = client.post("/two-factor", {"code": code_from(device)})
    assert response.status_code == 403 and "signed out" in response.content.decode()
    assert client.get("/").status_code == 302


def test_serving_tells_the_settings_who_can_reach_it(monkeypatch, tmp_path):
    class Stop(Exception):
        pass

    seen = {}

    def configure(home, public_url, tls, listens_beyond):
        seen["listens_beyond"] = listens_beyond
        raise Stop

    monkeypatch.setattr(web_app, "configure", configure)
    with pytest.raises(Stop):
        web_app.serve(tmp_path, "0.0.0.0:443", "https://c.example", "cert", "key")
    assert seen["listens_beyond"] is True
    with pytest.raises(Stop):
        web_app.serve(tmp_path, "127.0.0.1:8088")
    assert seen["listens_beyond"] is False


# --- Checks started from a page ---------------------------------------------------------------


@pytest.fixture
def inventory(home):
    from checker.inventory import Host, Inventory, hosts_file, known_hosts_file, save_inventory
    from checker.transport import _known_hosts_name

    saved = []

    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()

    def write(*hosts, confirmed=True):
        saved[:] = hosts
        save_inventory(Inventory(hosts=list(hosts)), hosts_file())
        lines = [f"{_known_hosts_name(host)} {' '.join(key.split()[:2])}" for host in hosts]
        known_hosts_file().write_text("\n".join(lines) + "\n" if confirmed else "")

    write(Host(name="web01", address="192.0.2.1", user="scan", auth="key", key_path="/none"))
    return write


@pytest.fixture
def child(monkeypatch):
    """Runs this in place of the real command, so a test decides what the check does."""
    from checker.web import runs

    programs = {"code": "print('checked')"}
    seen = {}

    def command(kind, hosts):
        seen.update(kind=kind, hosts=hosts)
        return [sys.executable, "-c", programs["code"]]

    monkeypatch.setattr(runs, "_command", command)
    monkeypatch.setattr(runs, "POLL_SECONDS", 0.01)
    yield programs, seen
    deadline = time.monotonic() + 10
    for run_id in list(runs._running):
        runs.stop(run_id)
    while runs._running and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not runs._running


def finished(run_id=None, seconds=20):
    from checker.web import runs
    from checker.web.models import CheckRun

    deadline = time.monotonic() + seconds
    while runs._running and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not runs._running
    with runs._lock:  # held while the ending is written down, as the pages rely on
        pass
    query = CheckRun.objects.order_by("-id")
    return query.get(pk=run_id) if run_id else query.first()


def key_host(name="web01"):
    from checker.inventory import Host

    return Host(name=name, address="192.0.2.1", user="scan", auth="agent")


def password_host(name="db01"):
    from checker.inventory import Host

    return Host(name=name, address="192.0.2.2", user="scan", auth="password")


@pytest.fixture
def agent(monkeypatch):
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/not-a-real-agent")  # noqa: S108


def test_a_check_runs_and_shows_how_it_went(web, inventory, child, agent):
    programs, seen = child
    client, _ = signed_in(web)
    inventory(key_host())
    form = client.get("/checks/new").content.decode()
    assert "Ready to check: web01" in form
    response = client.post("/checks/start", {"host": "web01"})
    assert response.status_code == 302 and response["Location"].startswith("/checks/")
    run = finished()
    assert seen == {"kind": "check", "hosts": ["web01"]}
    assert run.ended == "finished" and run.who == "jo"
    text = client.get(response["Location"]).content.decode()
    assert "checked" in text and "http-equiv" not in text
    names = [row[0] for row in the_record()]
    assert "started a check" in names and "finished a check" in names


def test_a_running_check_updates_itself_and_can_be_stopped(web, inventory, child, agent):
    from checker.web import runs

    programs, _ = child
    programs["code"] = "import time; print('waiting', flush=True); time.sleep(60)"
    client, _ = signed_in(web)
    inventory(key_host())
    location = client.post("/checks/start", {"host": "web01"})["Location"]
    text = client.get(location).content.decode()
    assert 'http-equiv="refresh"' in text and "Stop this check" in text
    assert client.post(f"{location}/stop", {"x": "1"}).status_code == 302
    run = finished()
    assert run.ended == "stopped" and not runs.is_running(run.id)
    assert the_record()[-1][2] == "stopped"


def test_stopping_twice_only_asks_once(web, inventory, child, agent, monkeypatch):
    from checker.web import runs

    programs, _ = child
    programs["code"] = "import time; time.sleep(60)"
    client, _ = signed_in(web)
    inventory(key_host())
    sent = []
    real = runs._signal
    monkeypatch.setattr(runs, "_signal", lambda c, s: (sent.append(s), real(c, s)))
    location = client.post("/checks/start", {"host": "web01"})["Location"]
    client.post(f"{location}/stop", {"x": "1"})
    client.post(f"{location}/stop", {"x": "1"})
    finished()
    assert sent.count(runs.signal.SIGTERM) == 1


def test_no_band_or_score_is_kept_about_a_check(web, inventory, child, agent):
    from checker.web.models import CheckRun

    programs, _ = child
    programs["code"] = "import sys; sys.exit(12)"
    client, _ = signed_in(web)
    inventory(key_host())
    client.post("/checks/start", {"host": "web01"})
    run = finished()
    assert run.ended == "finished"
    assert "exit_status" not in {field.name for field in CheckRun._meta.get_fields()}


def test_an_analysis_cut_off_by_a_restart_doesnt_claim_it_was_stopped(web):
    from django.utils import timezone

    from checker.web.models import CheckRun

    client, _ = signed_in(web)
    run = CheckRun.objects.create(
        kind="analysis", hosts='["web01"]', who="jo", address="", started_at=timezone.now()
    )
    assert "isn" in client.get(f"/checks/{run.id}").content.decode()


def test_a_dead_watcher_cant_block_every_later_check(web, inventory, child, agent, monkeypatch):
    from checker.web import runs

    programs, _ = child
    programs["code"] = "import time; time.sleep(60)"

    def broken(*args):
        raise ValueError("watcher trouble")

    monkeypatch.setattr(runs, "_hand_over", broken)
    client, _ = signed_in(web)
    inventory(key_host())
    client.post("/checks/start", {"host": "web01"})
    finished()
    assert not runs._running


def test_output_keeps_counting_right_after_many_short_lines():
    from checker.web.runs import OUTPUT_KEPT_BYTES, _Output

    output = _Output()
    for _ in range(200_000):
        output.add(b"ab\n")
    lines = output.lines()
    assert OUTPUT_KEPT_BYTES / 4 < len(lines) <= OUTPUT_KEPT_BYTES / 3


def test_the_end_of_a_check_is_when_it_ended_not_when_it_was_written(
    web, inventory, child, agent, monkeypatch
):
    from django.utils import timezone

    from checker.web import runs
    from checker.web.models import CheckRun

    client, _ = signed_in(web)
    inventory(key_host())
    client.post("/checks/start", {"host": "web01"})
    run = finished()
    assert (timezone.now() - run.finished_at).total_seconds() < 30
    assert CheckRun.objects.get(pk=run.id).finished_at == run.finished_at
    assert not runs._unrecorded


def test_a_stubborn_check_gets_told_after_being_asked(web, inventory, child, agent, monkeypatch):
    from checker.web import runs

    programs, _ = child
    programs["code"] = (
        "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        " print('up', flush=True); time.sleep(60)"
    )
    monkeypatch.setattr(runs, "STOP_SECONDS", 0.2)
    client, home = signed_in(web)
    inventory(key_host())
    location = client.post("/checks/start", {"host": "web01"})["Location"]
    run_id = int(location.rsplit("/", 1)[1])
    deadline = time.monotonic() + 10
    while not runs.output_lines(run_id) and time.monotonic() < deadline:
        time.sleep(0.02)  # so the signal is set up before it's asked
    client.post(f"{location}/stop", {"x": "1"})
    assert finished().ended == "stopped"


def test_a_check_that_goes_on_too_long_is_ended(web, inventory, child, agent, monkeypatch):
    from checker.web import runs

    programs, _ = child
    programs["code"] = "import time; time.sleep(60)"
    monkeypatch.setattr(runs, "LONGEST_SECONDS", 0.1)
    client, _ = signed_in(web)
    inventory(key_host())
    client.post("/checks/start", {"host": "web01"})
    assert finished().ended == runs.TOO_LONG


def test_only_one_check_at_a_time(web, inventory, child, agent):
    from checker.web.models import CheckRun

    programs, _ = child
    programs["code"] = "import time; time.sleep(60)"
    client, _ = signed_in(web)
    inventory(key_host())
    first = client.post("/checks/start", {"host": "web01"})["Location"]
    again = client.post("/checks/start", {"host": "web01"})
    assert again["Location"] == f"{first}?busy=1"
    assert "so yours didn" in client.get(again["Location"]).content.decode()
    assert CheckRun.objects.count() == 1
    assert the_record()[-1][2] == "failed"


def test_only_the_inventory_decides_what_a_check_connects_to(web, inventory, child, agent):
    _, seen = child
    client, _ = signed_in(web)
    inventory(key_host())
    body = b"host=web01&host=--all&host=evil.example"
    client.generic("POST", "/checks/start", body, content_type="application/x-www-form-urlencoded")
    finished()
    assert seen["hosts"] == ["web01"]
    assert client.post("/checks/start", {"host": "evil.example"}).status_code == 400


def test_a_password_goes_only_to_the_check(web, inventory, child):
    from checker.web.models import ActionRecord, CheckRun

    programs, _ = child
    programs["code"] = "import json, sys; print(json.loads(sys.stdin.readline())['db01'] != '')"
    client, home = signed_in(web)
    inventory(password_host())
    form = client.get("/checks/new").content.decode()
    assert 'name="password-db01"' in form and "aren't kept" in form
    secret = "the server password"  # noqa: S105
    refused = client.post("/checks/start", {"host": "db01"})
    assert refused.status_code == 400 and "Type the password" in refused.content.decode()
    location = client.post("/checks/start", {"host": "db01", "password-db01": secret})["Location"]
    run = finished()
    assert run.ended == "finished"
    assert "True" in client.get(location).content.decode()
    kept = str(list(ActionRecord.objects.values())) + str(list(CheckRun.objects.values()))
    assert secret not in kept
    assert not (home[0] / "checks").exists()  # nothing on disk at all
    from checker.web import runs

    assert not any(child.passwords for child in runs._running.values())


def test_each_host_gets_its_own_password_and_no_more(web, inventory, child):
    programs, _ = child
    programs["code"] = "import sys; print(sys.stdin.readline())"
    client, _ = signed_in(web)
    inventory(password_host("db01"), password_host("db02"), key_host("web01"))
    body = urlencode(
        [("host", "db01"), ("host", "db02"), ("password-db01", "one"), ("password-db02", "two"),
         ("password-web01", "not asked for"), ("password-other", "not a host")]
    )  # fmt: skip
    location = client.generic(
        "POST", "/checks/start", body.encode(), content_type="application/x-www-form-urlencoded"
    )["Location"]
    finished()
    text = client.get(location).content.decode()
    assert "one" in text and "two" in text
    assert "not asked for" not in text and "not a host" not in text


def test_what_cant_be_checked_says_why(web, inventory, monkeypatch):
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    client, _ = signed_in(web)
    inventory(key_host())
    text = client.get("/checks/new").content.decode()
    assert "Can&#39;t be checked from here" in text or "be checked from here" in text
    assert "SSH agent" in text and "Start checking" not in text
    response = client.post("/checks/start", {"host": "web01"})
    assert response.status_code == 400


def test_with_no_servers_the_page_says_what_to_do(web):
    client, _ = signed_in(web)
    assert "Add one" in client.get("/checks/new").content.decode()


def test_hostile_text_in_a_checks_log_is_only_text(web, inventory, child, agent):
    programs, _ = child
    programs["code"] = f"print({HOSTILE!r})"
    client, _ = signed_in(web)
    inventory(key_host())
    location = client.post("/checks/start", {"host": "web01"})["Location"]
    finished()
    text = client.get(location).content.decode()
    assert "<script>alert" not in text and BIDI not in text


def test_a_check_cut_off_by_a_restart_says_so_and_a_page_writes_nothing(web, inventory):
    from django.utils import timezone

    from checker.web import runs
    from checker.web.models import CheckRun

    client, _ = signed_in(web)
    run = CheckRun.objects.create(
        kind="check", hosts='["web01"]', who="jo", address="", started_at=timezone.now()
    )
    text = client.get(f"/checks/{run.id}").content.decode()
    assert "restarted" in text and "http-equiv" not in text
    assert "restarted" in client.get("/checks").content.decode()
    run.refresh_from_db()
    assert run.finished_at is None  # a page only looks
    assert client.post(f"/checks/{run.id}/stop", {"x": "1"}).status_code == 400
    runs.close_interrupted()
    run.refresh_from_db()
    assert run.ended == runs.RESTARTED and run.finished_at


def test_a_page_never_calls_a_running_check_interrupted(web, inventory, child, agent):
    programs, _ = child
    programs["code"] = "import time; time.sleep(60)"
    client, _ = signed_in(web)
    inventory(key_host())
    location = client.post("/checks/start", {"host": "web01"})["Location"]
    for _ in range(5):
        assert "restarted" not in client.get("/checks").content.decode()
        assert "restarted" not in client.get(location).content.decode()


def test_the_end_of_a_check_is_shown_even_if_it_cant_be_written(
    web, inventory, child, agent, monkeypatch
):
    from checker.web import runs

    client, _ = signed_in(web)
    inventory(key_host())

    def broken(*args, **kwargs):
        raise OSError("disk full")

    real = runs.ActionRecord.objects.create
    location = client.post("/checks/start", {"host": "web01"})["Location"]
    monkeypatch.setattr(runs.ActionRecord.objects, "create", broken)
    deadline = time.monotonic() + 20
    while runs._running and time.monotonic() < deadline:
        time.sleep(0.02)
    text = client.get(location).content.decode()
    assert "Finished" in text and "restarted" not in text
    monkeypatch.setattr(runs.ActionRecord.objects, "create", real)
    runs.close_interrupted()
    assert the_record()[-1][0] == "finished a check"
    assert not runs._unrecorded


def test_a_check_that_cant_start_says_so(web, inventory, child, agent, monkeypatch):
    from checker.web import runs
    from checker.web.models import CheckRun

    client, _ = signed_in(web)
    inventory(key_host())

    def cannot(*args, **kwargs):
        raise OSError("no")

    monkeypatch.setattr(runs.subprocess, "Popen", cannot)
    response = client.post("/checks/start", {"host": "web01"})
    assert response.status_code == 400 and "couldn" in response.content.decode()
    assert CheckRun.objects.get().ended == "couldn't start"
    assert not runs._running


def test_old_runs_are_let_go(web, inventory, child, agent, monkeypatch):
    from checker.web import runs
    from checker.web.models import CheckRun

    monkeypatch.setattr(runs, "KEEP", 2)
    client, _ = signed_in(web)
    inventory(key_host())
    made = []
    for _ in range(3):
        client.post("/checks/start", {"host": "web01"})
        made.append(finished().id)
    client.post("/checks/start", {"host": "web01"})
    finished()
    kept = list(CheckRun.objects.order_by("id").values_list("id", flat=True))
    assert kept[0] == made[-1] and len(kept) == 2
    assert not runs.output_lines(made[0]) and runs.output_lines(made[-1])


def test_output_is_bounded_and_copes_with_anything(web, inventory, child, agent):
    from checker.web import runs

    programs, _ = child
    programs["code"] = (
        "import sys; [sys.stdout.buffer.write(b'x' * 5000 + b'\\n') for _ in range(40)];"
        " sys.stdout.buffer.write(b'bad \\xff byte\\n')"
    )
    client, _ = signed_in(web)
    inventory(key_host())
    location = client.post("/checks/start", {"host": "web01"})["Location"]
    run = finished()
    lines = runs.output_lines(run.id)
    assert sum(len(line) for line in lines) <= runs.OUTPUT_KEPT_BYTES + runs.LONGEST_LINE_BYTES
    assert "bad" in lines[-1]
    assert client.get(location).status_code == 200


def test_every_form_that_posts_carries_its_token(web, inventory, child, agent):
    programs, _ = child
    programs["code"] = "import time; time.sleep(60)"
    client, home = signed_in(web)
    inventory(key_host(), password_host())
    analysed(home, "b1", 10, CLEAN)
    location = client.post("/checks/start", {"host": "web01"})["Location"]
    pages = ["/", "/checks", "/checks/new", location, "/hosts/web01", "/two-factor/setup"]
    checked = 0
    for page in pages:
        for form in re.findall(
            r"<form[^>]*method=\"post\".*?</form>", client.get(page).content.decode(), re.S
        ):
            assert "csrfmiddlewaretoken" in form, page
            checked += 1
    assert checked >= 5


def test_every_page_but_the_open_ones_asks_who_you_are(web):
    from django.urls import get_resolver

    from checker.web import views

    client, _ = web
    open_ones = {
        views.font,
        views.stylesheet,
        views.setup_page,
        views.login_page,
        views.logout_page,
    }
    for pattern in get_resolver("checker.web.urls").url_patterns:
        if pattern.callback in open_ones:
            continue
        path = "/" + route_path(pattern)
        for response in (client.get(path), client.post(path, {"x": "1"})):
            assert response.status_code in (302, 405), path
            if response.status_code == 302:
                assert response["Location"].startswith("/login"), path


def test_a_huge_check_number_is_only_not_found(web):
    client, _ = signed_in(web)
    assert client.get(f"/checks/{2**70}").status_code == 404
    assert client.post(f"/checks/{2**70}/stop", {"x": "1"}).status_code == 400


def test_a_password_box_hides_what_is_typed(web, inventory):
    client, _ = signed_in(web)
    inventory(password_host())
    assert 'name="password-db01" type="password"' in client.get("/checks/new").content.decode()


def test_a_server_not_in_the_list_has_no_check_button(web, inventory):
    client, home = signed_in(web)
    inventory(key_host("other"))
    analysed(home, "b1", 10, CLEAN)
    assert "Check this server now" not in client.get("/hosts/web01").content.decode()


def test_an_unknown_server_is_named_as_that(web, inventory):
    client, _ = signed_in(web)
    inventory(key_host())
    assert "isn&#39;t in the list" in client.get(
        "/checks/new", {"host": "nope"}
    ).content.decode() or (
        "in the list of servers" in client.get("/checks/new", {"host": "nope"}).content.decode()
    )


def test_a_login_can_go_on_to_a_check(web):
    from django.utils import timezone

    from checker.web.models import CheckRun

    client, _ = web
    account()
    run = CheckRun.objects.create(
        kind="check", hosts="[]", who="jo", address="", started_at=timezone.now()
    )
    path = f"/checks/{run.id}"
    response = client.post("/login", {"username": "jo", "password": PASSWORD, "next": path})
    assert response["Location"] == path


def test_working_it_out_again_connects_to_nothing_and_only_for_known_servers(
    web, inventory, child, agent
):
    _, seen = child
    client, home = signed_in(web)
    inventory(key_host())
    analysed(home, "b1", 10, CLEAN)
    assert "Check this server now" in client.get("/hosts/web01").content.decode()
    assert client.post("/checks/analyze", {"host": "web01"}).status_code == 302
    finished()
    assert seen == {"kind": "analysis", "hosts": ["web01"]}
    assert client.post("/checks/analyze", {"host": "nope"}).status_code == 400
    assert client.post("/checks/analyze", {"host": ""}).status_code == 400


@pytest.mark.parametrize(
    ("kind", "status", "words"),
    [
        ("check", 0, "finished"),
        ("check", 10, "finished"),
        ("check", 11, "finished"),
        ("check", 12, "finished"),
        ("check", 1, "finished with problems"),
        ("check", 120, "finished with problems"),
        ("check", 2, "couldn't start"),
        ("check", 3, "another check was running"),
        ("check", -9, "ended unexpectedly"),
        ("analysis", 0, "finished"),
        ("analysis", 1, "finished with problems"),
        ("analysis", 2, "finished with problems"),
        ("analysis", 12, "finished with problems"),
    ],
)
def test_how_a_check_ended_in_words(web, kind, status, words):
    from checker.web.runs import ending_words

    assert ending_words(kind, status) == words
    assert len(words) <= 32  # the record's limit


def test_the_real_commands_are_what_gets_run():
    from checker.web.runs import _command

    assert _command("check", ["web01"])[1:] == [
        "-P", "-m", "checker", "run", "--unattended", "--from-web-page", "--", "web01",
    ]  # fmt: skip
    assert _command("analysis", ["web01"])[1:] == ["-P", "-m", "checker", "analyze", "--", "web01"]


def checker_home_for_real(tmp_path):
    env = {**os.environ, "CHECKER_HOME": str(tmp_path), "SSH_AUTH_SOCK": ""}
    subprocess.run([sys.executable, "-m", "checker", "init"], env=env, check=True,
                   capture_output=True)  # fmt: skip
    (tmp_path / "hosts.yaml").write_text(
        "hosts:\n- name: db01\n  address: 127.0.0.1\n  port: 9\n  user: scan\n  auth: password\n"
    )
    return env


def from_a_page(env, typed):
    from checker.web.runs import _command

    process = subprocess.Popen(
        _command("check", ["db01"]), env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )  # fmt: skip
    process.stdin.write(typed + "\n")
    process.stdin.flush()
    return process


def test_a_real_check_of_a_server_that_doesnt_answer_says_so(tmp_path):
    """The real command, its real arguments and passwords, in a process of its own."""
    env = checker_home_for_real(tmp_path)
    secret = "the server password"  # noqa: S105
    process = from_a_page(env, json.dumps({"db01": secret}))
    output = process.stdout.read()
    assert process.wait(120) == 1, output
    assert "db01" in output and "not collected" in output
    assert secret not in output
    assert "Needs a look" not in output and "Report written" not in output
    process.stdin.close()
    bad = from_a_page(env, "not json")
    output = bad.stdout.read()
    assert bad.wait(60) == 2 and "aren't JSON" in output and "not json" not in output
    bad.stdin.close()
    wrong = from_a_page(env, '{"db01": 3}')
    output = wrong.stdout.read()
    assert wrong.wait(60) == 2 and "aren't JSON" in output
    wrong.stdin.close()


def test_a_check_stops_when_the_server_that_started_it_goes_and_a_purge_finds_what_it_left(
    tmp_path,
):
    """A server that takes the connection and says nothing, so the check is really under way."""
    from checker.inventory import Host
    from checker.transport import _known_hosts_name

    env = checker_home_for_real(tmp_path)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        host = Host(name="db01", address="127.0.0.1", port=port, user="scan", auth="password")
        key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
        (tmp_path / "known_hosts").write_text(f"{_known_hosts_name(host)} {key}\n")
        (tmp_path / "hosts.yaml").write_text(
            f"hosts:\n- name: db01\n  address: 127.0.0.1\n  port: {port}\n  user: scan\n"
            "  auth: password\n"
        )
        process = from_a_page(env, json.dumps({"db01": "x"}))
        time.sleep(3)
        assert process.poll() is None  # it's waiting on the server
        process.stdin.close()  # all a server's going away looks like from here
        assert process.wait(30) == schedule_exit_stopped()
    assert "stopped" in process.stdout.read()
    found = [p for p in tmp_path.rglob("*.age") if "db01" in p.name and "report" not in p.name]
    assert found  # it left its evidence, so it must be able to find it
    purge = subprocess.run(
        [sys.executable, "-m", "checker", "purge", "db01", "--yes"],
        env=env, capture_output=True, text=True,
    )  # fmt: skip
    assert purge.returncode == 0, purge.stderr
    assert not [p for p in found if p.exists()]


def schedule_exit_stopped():
    from checker.schedule import EXIT_STOPPED

    return EXIT_STOPPED


def test_the_flag_needs_unattended_and_works_only_from_a_page(tmp_path):
    env = checker_home_for_real(tmp_path)
    run = subprocess.run(
        [sys.executable, "-m", "checker", "run", "--from-web-page", "--", "db01"],
        env=env, capture_output=True, text=True, input="{}\n",
    )  # fmt: skip
    assert run.returncode == 2 and "goes with --unattended" in run.stderr


def test_nothing_in_the_servers_folder_runs_as_the_checker(tmp_path):
    """-P: a planted checker/ or yaml.py where the server was started gets no passwords."""
    from checker.web.runs import _command

    env = checker_home_for_real(tmp_path)
    planted = tmp_path / "planted"
    (planted / "checker").mkdir(parents=True)
    (planted / "checker" / "__init__.py").write_text("")
    (planted / "checker" / "__main__.py").write_text("print('PLANTED')")
    run = subprocess.run(
        _command("analysis", ["db01"]), env=env, cwd=planted, capture_output=True, text=True
    )
    assert "PLANTED" not in run.stdout + run.stderr


def test_a_password_a_server_repeats_is_taken_out_of_what_is_printed(capsys):
    from checker import cli

    stream = cli._WithoutThese(sys.stdout, ["hunter2", ""])
    stream.write("sudo: bad thing hunter2 here\n")
    assert capsys.readouterr().out == "sudo: bad thing [password] here\n"
    stream = cli._WithoutThese(sys.stdout, ["pass", "password123"])
    stream.write("pass password123\n")
    assert capsys.readouterr().out == "[password] [password]\n"


def test_a_failed_notify_says_so_on_the_page(tmp_path):
    env = checker_home_for_real(tmp_path)
    (tmp_path / "hosts.yaml").write_text(
        "hosts:\n- name: db01\n  address: 127.0.0.1\n  port: 9\n  user: scan\n  auth: password\n"
    )
    subprocess.run(
        [sys.executable, "-m", "checker", "config", "set", "notify_command", "/nonexistent-notify"],
        env=env, capture_output=True,
    )  # fmt: skip
    process = from_a_page(env, json.dumps({"db01": "x"}))
    output = process.stdout.read()
    process.wait(120)
    process.stdin.close()
    assert "notify command failed" in output, output


def test_relative_paths_mean_what_they_mean_on_the_command_line(tmp_path):
    """A check runs where the server was started, so a relative home or key file still works."""
    from checker.web.runs import _command

    (tmp_path / "rel").mkdir()
    env = {**os.environ, "CHECKER_HOME": "rel", "SSH_AUTH_SOCK": ""}
    subprocess.run(
        [sys.executable, "-m", "checker", "init"], env=env, cwd=tmp_path, check=True,
        capture_output=True,
    )  # fmt: skip
    (tmp_path / "rel" / "hosts.yaml").write_text(
        "hosts:\n- name: db01\n  address: 127.0.0.1\n  port: 9\n  user: scan\n  auth: key\n"
        "  key_path: rel-key\n"
    )
    (tmp_path / "rel-key").write_text(
        asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()
    )
    run = subprocess.run(
        _command("check", ["db01"]), env=env, cwd=tmp_path, input="{}\n", capture_output=True,
        text=True, timeout=120,
    )  # fmt: skip
    output = run.stdout + run.stderr
    assert "not set up yet" not in output and "can't be read" not in output, output


# --- Decisions ---------------------------------------------------------------------------------

CHANGED = host_records(
    accounts=(("root", 0), ("newuser", 1000)),
    listening=(("tcp", ["0.0.0.0", 22], "listen", 700), ("tcp", ["0.0.0.0", 4444], "listen", 701)),
)
ROOTED_AND_CHANGED = host_records(
    accounts=(("root", 0), ("jch", 1000), ("toor", 0)),
    listening=(("tcp", ["0.0.0.0", 22], "listen", 700), ("tcp", ["0.0.0.0", 4444], "listen", 701)),
)


@pytest.fixture(autouse=True)
def _decisions_look_back_far_enough(request, monkeypatch):
    """The test bundles have fixed dates."""
    if "web" in request.fixturenames:
        from checker.web import decide

        monkeypatch.setattr(decide, "LOOK_BACK", timedelta(days=36500))


def proposal_rule(rule_id="routine-thing", check="net.listener", expires=None, **extra):
    from datetime import date

    return {
        "id": rule_id,
        "match": {"check": check, "account": "root"},
        "reason": "routine here",
        "owner": "",
        "expires": expires or date.today() + timedelta(days=30),
        **extra,
    }


def write_proposals(home_path, host, rules, layer="hosts", name=None, stem="20261031T120000Z"):
    import yaml

    folder = home_path / "proposals"
    folder.mkdir(exist_ok=True)
    lines = ["rules:"]
    for rule in rules:
        lines += ["", f"  # for whitelist/{layer}/{name or host}.yaml"]
        body = yaml.safe_dump([rule], sort_keys=False)
        lines += ["  " + line for line in body.rstrip().split("\n")]
    path = folder / f"{host}-{stem}.yaml"
    path.write_text("\n".join(lines) + "\n")
    return path


@pytest.fixture
def two_checks(web, inventory):
    """A signed-in browser, and a server with a baseline and a later check that differs."""
    client, home = signed_in(web)
    inventory(key_host())
    analysed(home, "b1", 10, CLEAN)
    second = analysed(home, "b2", 20, CHANGED)
    return client, home, second


def decide_text(client, host="web01"):
    response = client.get("/decide", {"host": host})
    assert response.status_code == 200
    return response.content.decode()


def rule_form(home_path, host="web01", owner="jo"):
    from checker.web import decide

    [proposed], _ = decide.previews(home_path, host, owner)
    return {
        "host": host,
        "file": proposed.file,
        "rule": proposed.id,
        "digest": proposed.digest,
        "sight": proposed.sight,
    }


def layer_of(home_path, host="web01"):
    return home_path / "whitelist" / "hosts" / f"{host}.yaml"


def test_accepting_shows_what_it_hides_then_needs_a_reason_and_the_password(two_checks):
    from checker.baseline import current_baseline
    from checker.evidence import Store, database_file

    client, home, _ = two_checks
    text = decide_text(client)
    assert "stops being reported as changed" in text and "newuser" in text
    form = {
        "host": "web01",
        "bundle": "b2",
        "sight": re.search(r'name="sight" value="(\w+)"', text)[1],
        "reason": "our new deploy account",
    }
    assert client.post("/decide/baseline", form).status_code == 403
    store = Store(database_file(home[0]), read_only=True)
    assert current_baseline(store, "web01")["bundle_id"] == "b1"
    store.close()
    form["confirm_password"] = PASSWORD
    assert client.post("/decide/baseline", {**form, "reason": " "}).status_code == 400
    assert client.post("/decide/baseline", {**form, "bundle": "b1"}).status_code == 400
    assert client.post("/decide/baseline", form).status_code == 302
    store = Store(database_file(home[0]), read_only=True)
    now = current_baseline(store, "web01")
    store.close()
    assert now["bundle_id"] == "b2" and now["how"] == "accepted"
    assert ("accepted a baseline", "web01", "done") in the_record()
    assert "viewed what could be decided about a server" in [row[0] for row in the_record()]
    assert "already is the baseline" in decide_text(client)


def test_a_changed_thing_shows_how_it_changed(web, inventory):
    client, home = signed_in(web)
    inventory(key_host())
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, host_records(accounts=(("root", 0), ("jch", 0))))
    assert "uid" in decide_text(client).lower()


def test_a_long_list_of_changes_says_how_many_more(web, inventory, monkeypatch):
    from checker.web import decide

    monkeypatch.setattr(decide, "SHOWN_PER_KIND", 1)
    client, home = signed_in(web)
    inventory(key_host())
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, host_records(accounts=(("root", 0), ("aaa", 1000), ("zzz", 1001))))
    text = decide_text(client)
    assert "And 1 more not listed" in text and "zzz" not in text


def test_what_couldnt_be_compared_or_was_partial_is_shown_not_called_unchanged(
    web, inventory, monkeypatch
):
    from checker.web import decide

    client, home = signed_in(web)
    inventory(key_host())
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, CLEAN)
    real = decide.compare

    def uncomparable(old, new):
        found = real(old, new)
        some = next(iter(found)) if found else "ssh"
        found[some] = {"added": {}, "removed": {}, "changed": {}, "notes": ["it timed out"]}
        return found

    monkeypatch.setattr(decide, "compare", uncomparable)
    text = decide_text(client)
    assert "it timed out" in text and "Nothing has changed" not in text


def test_a_check_not_worked_out_yet_is_said_and_a_page_stores_nothing(two_checks):
    client, home, _ = two_checks
    add_bundle(home, "b3", 30, CHANGED)

    def files():
        return sorted(str(p) for p in home[0].rglob("*") if p.is_file() and p.suffix != ".db")

    before = files()
    for _ in range(3):
        assert "Work this server" in decide_text(client)
    assert files() == before


def test_only_servers_in_the_list_can_be_decided_about(web, inventory):
    client, _ = signed_in(web)
    inventory(key_host())
    assert client.get("/decide", {"host": "nope"}).status_code == 404
    assert client.get("/decide").status_code == 404
    form = {"host": "nope", "bundle": "b", "reason": "r", "confirm_password": PASSWORD}
    assert client.post("/decide/baseline", form).status_code == 400
    assert client.post("/decide/ask", form).status_code == 400
    form = {"host": "nope", "file": "f", "digest": "d", "sight": "s", "confirm_password": PASSWORD}
    assert client.post("/decide/approve", form).status_code == 400
    assert client.post("/decide/refuse", form).status_code == 400
    assert client.post("/decide/discard", form).status_code == 400


def test_looking_at_a_decision_changes_nothing_but_the_record(two_checks):
    from checker.evidence import Store, database_file

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()])

    def everything():
        store = Store(database_file(home[0]), read_only=True)
        try:
            return [dict(row) for row in store.bundles()], [
                tuple(row) for row in store.baselines("web01")
            ]
        finally:
            store.close()

    files = sorted(str(p) for p in home[0].rglob("*") if p.is_file() and p.suffix != ".db")
    before, web_before = everything(), everything_but_the_record()
    decide_text(client)
    assert before == everything()
    assert web_before == everything_but_the_record()
    assert files == sorted(str(p) for p in home[0].rglob("*") if p.is_file() and p.suffix != ".db")


def test_a_rule_shows_what_it_hides_and_goes_in_only_with_the_password(two_checks):
    from checker.whitelist import read_layer

    client, home, second = two_checks
    write_proposals(home[0], "web01", [proposal_rule()])
    text = decide_text(client)
    assert "It would hide" in text and "net.listener" in text and "4444" in text
    assert "account:" in text and "root" in text
    form = rule_form(home[0])
    assert client.post("/decide/approve", form).status_code == 403
    assert not layer_of(home[0]).exists()
    response = client.post("/decide/approve", {**form, "confirm_password": PASSWORD})
    assert response.status_code == 302
    [rule] = read_layer(layer_of(home[0])).rules
    assert rule.owner == "jo" and rule.id == "routine-thing"
    assert not list((home[0] / "proposals").glob("web01-*"))
    assert ("approved a whitelist rule", "web01: routine-thing", "done") in the_record()
    assert "None waiting" in decide_text(client)
    assert oct(layer_of(home[0]).stat().st_mode)[-3:] == "600"


def test_the_owner_is_whoever_approves_never_the_file(two_checks):
    from checker.whitelist import read_layer

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule(owner="someone else")])
    client.post("/decide/approve", {**rule_form(home[0]), "confirm_password": PASSWORD})
    assert read_layer(layer_of(home[0])).rules[0].owner == "jo"


def test_what_a_person_wrote_in_a_layer_file_stays_as_it_was(two_checks):
    from checker.web.decide import _appended

    assert _appended("", {"id": "a"}, "note") == "rules:\n  # note\n  - id: a\n"
    kept = "# my notes\nprofiles: []\nrules:\n- id: mine # why\n  owner: me\n"
    out = _appended(kept, {"id": "a"}, "note")
    assert out.startswith(kept) and out.endswith("# note\n- id: a\n")
    assert _appended("profiles: []\n", {"id": "a"}, "n").startswith("profiles: []\nrules:\n")
    with pytest.raises(ValueError, match="plain list"):
        _appended("rules: []\n", {"id": "a"}, "n")
    with pytest.raises(ValueError, match="comes after"):
        _appended("rules:\n- id: x\nprofiles: []\n", {"id": "a"}, "n")


def test_a_file_that_cant_be_added_to_says_to_edit_it_by_hand(two_checks):
    client, home, _ = two_checks
    layer = layer_of(home[0])
    layer.parent.mkdir(parents=True)
    layer.write_text("rules: []\n")
    write_proposals(home[0], "web01", [proposal_rule()])
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}
    response = client.post("/decide/approve", form)
    assert response.status_code == 400 and "by hand" in response.content.decode()
    assert layer.read_text() == "rules: []\n"
    assert list((home[0] / "proposals").glob("web01-*"))


def test_a_rule_changed_since_it_was_shown_isnt_approved(two_checks):
    client, home, _ = two_checks
    path = write_proposals(home[0], "web01", [proposal_rule()])
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}
    path.write_text(path.read_text().replace("net.listener", "net.peer"))
    response = client.post("/decide/approve", form)
    assert response.status_code == 400 and "changed or gone" in response.content.decode()
    assert not layer_of(home[0]).exists()


def test_a_rule_that_would_now_hide_more_than_was_shown_makes_you_look_again(two_checks):
    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()])
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}
    analysed(home, "b3", 30, host_records(listening=(("tcp", ["0.0.0.0", 5555], "listen", 702),)))
    response = client.post("/decide/approve", form)
    assert response.status_code == 400 and "Look again" in response.content.decode()
    assert not layer_of(home[0]).exists()


def test_a_rule_filed_twice_for_different_layers_is_told_apart(two_checks):
    from checker.web import decide

    _, home, _ = two_checks
    path = write_proposals(home[0], "web01", [proposal_rule()])
    write_proposals(
        home[0], "web01", [proposal_rule()], layer="groups", name="web", stem="20261031T120001Z"
    )
    found = decide.proposals(home[0], "web01")
    assert len(found) == 2 and found[0].digest != found[1].digest
    assert path.exists()


def test_refusing_takes_out_only_that_rule_and_keeps_the_others_layer(two_checks):
    from checker.web import decide

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule("one"), proposal_rule("two")])
    first, second = decide.proposals(home[0], "web01")
    form = {"host": "web01", "file": first.file, "rule": "one", "digest": first.digest}
    assert client.post("/decide/refuse", form).status_code == 302
    left = decide.proposals(home[0], "web01")
    assert [p.id for p in left] == ["two"] and left[0].named == "web01"
    assert client.post("/decide/refuse", form).status_code == 400
    assert ("refused a whitelist rule", "web01: one", "done") in the_record()
    form = {"host": "web01", "file": left[0].file, "rule": "two", "digest": left[0].digest}
    assert client.post("/decide/refuse", form).status_code == 302
    assert not list((home[0] / "proposals").glob("web01-*"))
    assert not (home[0] / "whitelist").exists()


def test_a_rule_with_an_odd_name_can_still_be_refused(two_checks):
    from checker.web import decide

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule(f"odd{BIDI}id")])
    [found] = decide.proposals(home[0], "web01")
    form = {"host": "web01", "file": found.file, "digest": found.digest}
    assert client.post("/decide/refuse", form).status_code == 302
    assert decide.proposals(home[0], "web01") == []


def test_the_rule_on_a_worrying_server_cant_be_approved_even_if_it_hides_little(web, inventory):
    client, home = signed_in(web)
    inventory(key_host())
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, ROOTED_AND_CHANGED)
    write_proposals(home[0], "web01", [proposal_rule()])
    text = decide_text(client)
    assert "assessed" in text and "Approve this rule" not in text
    assert "worrying" in text
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}
    assert client.post("/decide/approve", form).status_code == 400
    assert not layer_of(home[0]).exists()


def test_a_critical_finding_cant_be_hidden_whatever_else_lets_it(web, inventory, monkeypatch):
    from checker.web import decide

    monkeypatch.setattr(decide, "HAND_ONLY", frozenset())
    monkeypatch.setattr(decide, "TOO_WORRYING", ())
    client, home = signed_in(web)
    inventory(key_host())
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, ROOTED)
    rule = proposal_rule(check="account.uid0")
    rule["match"] = {"check": "account.uid0", "account": "toor"}
    write_proposals(home[0], "web01", [rule])
    assert "would hide a critical finding" in decide_text(client)


@pytest.mark.parametrize(
    ("rule", "words"),
    [
        ({"id": "BAD ID!"}, "valid rule"),
        ({"match": {"check": "account.uid0", "account": "toor"}}, "written by hand"),
        ({"match": {"check": "net.listener"}, "broad": True}, "every finding"),
        ({"expires": "never"}, "never expires"),
    ],
)
def test_what_the_advisors_own_checks_turn_down_cant_be_approved(two_checks, rule, words):
    client, home, _ = two_checks
    write_proposals(home[0], "web01", [{**proposal_rule(), **rule}])
    text = decide_text(client)
    assert words in text and "Approve this rule" not in text


def test_an_expired_or_far_off_rule_cant_be_approved(two_checks):
    from datetime import date

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule("old", expires=date(2020, 1, 1))])
    assert "passed its expiry" in decide_text(client)
    far = date.today() + timedelta(days=400)
    write_proposals(home[0], "web01", [proposal_rule("far", expires=far)], stem="20261031T120001Z")
    assert "more than 90 days" in decide_text(client)


def test_when_nothing_can_be_compared_it_blocks_and_doesnt_reassure(web, inventory, monkeypatch):
    from checker import whitelist_review

    client, home = signed_in(web)
    inventory(key_host())
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, CHANGED)
    write_proposals(home[0], "web01", [proposal_rule()])
    monkeypatch.setattr(whitelist_review, "current_versions", lambda: {"checks": -1})
    text = decide_text(client)
    assert "wouldn" not in text.split("Rules the AI")[1].split("Decisions take")[0] or (
        "work its results out again" in text
    )
    assert "Approve this rule" not in text


def test_older_than_the_window_blocks_too(two_checks, monkeypatch):
    from checker.web import decide

    client, home, _ = two_checks
    monkeypatch.setattr(decide, "LOOK_BACK", timedelta(days=-36500))  # the bundles' dates are fixed
    write_proposals(home[0], "web01", [proposal_rule()])
    text = decide_text(client)
    assert "Approve this rule" not in text and "work its results out again" in text


def test_a_newer_check_not_yet_worked_out_blocks(two_checks):
    client, home, _ = two_checks
    add_bundle(home, "b3", 30, ROOTED)
    write_proposals(home[0], "web01", [proposal_rule()])
    text = decide_text(client)
    assert "Approve this rule" not in text and "work its results out again" in text


@pytest.mark.parametrize(
    "content",
    ["rules: [unclosed\n", "- a\n- b\n", "just text\n", "rules: 5\n", "1: 2\n",
     "a: &a [x]\nrules: *a\n"],
)  # fmt: skip
def test_a_damaged_proposal_file_doesnt_stop_the_page_and_can_be_discarded(two_checks, content):
    client, home, _ = two_checks
    path = home[0] / "proposals" / "web01-20261031T120002Z.yaml"
    path.parent.mkdir()
    path.write_text(content)
    text = decide_text(client)
    assert "file can" in text and "Discard this file" in text and "Accept how it is" in text
    form = {"host": "web01", "file": path.name}
    assert client.post("/decide/discard", form).status_code == 302
    assert not path.exists()


def test_a_huge_proposal_file_isnt_read(two_checks):
    client, home, _ = two_checks
    path = home[0] / "proposals" / "web01-20261031T120002Z.yaml"
    path.parent.mkdir()
    path.write_text("rules: []\n" + "# x\n" * 100_000)
    assert "Discard this file" in decide_text(client)


def test_a_rules_own_text_cant_pass_for_the_comment_saying_where_it_goes(two_checks):
    from checker.web import decide

    _, home, _ = two_checks
    reason = "looks fine\n# for whitelist/groups/x.yaml\nreally"
    write_proposals(home[0], "web01", [proposal_rule(reason=reason)])
    [found] = decide.proposals(home[0], "web01")
    assert found.problem is None and found.layer == "host" and found.named == "web01"


def test_a_rule_for_too_many_shows_a_page_of_them_and_says_how_many_more(two_checks, monkeypatch):
    from checker.web import decide

    monkeypatch.setattr(decide, "MOST_RULES_SHOWN", 1)
    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule("one"), proposal_rule("two")])
    assert "And 1 more" in decide_text(client)


def test_each_servers_analyses_are_read_once_however_many_rules(two_checks, monkeypatch):
    from checker.web import decide

    calls = []
    real = decide.load_analyses
    monkeypatch.setattr(decide, "load_analyses", lambda *a: (calls.append(a[1]), real(*a))[1])
    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule("one"), proposal_rule("two")])
    decide_text(client)
    assert calls == ["web01"]


def test_another_servers_proposals_arent_this_ones(two_checks):
    from checker.web import decide

    client, home, _ = two_checks
    write_proposals(home[0], "web01-2", [proposal_rule("other")])
    assert decide.proposals(home[0], "web01") == []
    assert "None waiting" in decide_text(client)


def test_a_rule_naming_another_server_cant_be_approved_here(two_checks):
    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()], name="other")
    assert "for another server" in decide_text(client)


def grouped(web, inventory, group="web"):
    from checker.inventory import Host

    client, home = signed_in(web)
    inventory(
        Host(name="web01", address="192.0.2.1", user="u", auth="agent", group=group),
        Host(name="web02", address="192.0.2.2", user="u", auth="agent", group=group),
    )
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, CHANGED)
    return client, home


def test_a_rule_for_a_group_shows_every_server_and_goes_in_the_groups_file(web, inventory):
    from checker.whitelist import read_layer

    client, home = grouped(web, inventory)
    analysed(home, "c1", 10, CLEAN, host="web02")
    write_proposals(home[0], "web01", [proposal_rule()], layer="groups", name="web")
    assert "web01, web02" in decide_text(client)
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}
    assert client.post("/decide/approve", form).status_code == 302
    assert read_layer(home[0] / "whitelist" / "groups" / "web.yaml").rules[0].owner == "jo"


def test_a_rule_for_a_group_on_a_server_with_none_says_so(two_checks):
    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()], layer="groups", name="web")
    assert "for a group" in decide_text(client)


def test_refusing_one_of_a_groups_rules_keeps_the_groups_name(web, inventory):
    from checker.web import decide

    client, home = grouped(web, inventory)
    write_proposals(home[0], "web01", [proposal_rule("one"), proposal_rule("two")],
                    layer="groups", name="web")  # fmt: skip
    first = decide.proposals(home[0], "web01")[0]
    form = {"host": "web01", "file": first.file, "digest": first.digest}
    client.post("/decide/refuse", form)
    assert decide.proposals(home[0], "web01")[0].named == "web"


def test_a_group_with_a_path_in_its_name_writes_nothing_outside(web, inventory, tmp_path):
    from checker.web.decide import _layer_path
    from checker.whitelist import WhitelistError

    with pytest.raises(WhitelistError):
        _layer_path(tmp_path, "web01", "../../escaped", "group")
    assert _layer_path(tmp_path, "web01", "web", "group").name == "web.yaml"


def test_a_link_on_the_way_to_the_file_is_refused(two_checks, tmp_path):
    client, home, _ = two_checks
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (home[0] / "whitelist").mkdir()
    (home[0] / "whitelist" / "hosts").symlink_to(outside)
    write_proposals(home[0], "web01", [proposal_rule()])
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}
    response = client.post("/decide/approve", form)
    assert response.status_code == 400 and "link" in response.content.decode()
    assert not list(outside.iterdir())


def test_a_linked_proposal_file_or_folder_isnt_read(two_checks, tmp_path):
    from checker.web import decide

    _, home, _ = two_checks
    (tmp_path / "elsewhere").mkdir()
    real = write_proposals(tmp_path / "elsewhere", "web01", [proposal_rule()])
    folder = home[0] / "proposals"
    folder.mkdir()
    (folder / real.name).symlink_to(real)
    assert decide.proposals(home[0], "web01") == []
    (folder / real.name).unlink()
    folder.rmdir()
    folder.symlink_to(real.parent)
    assert decide.proposals(home[0], "web01") == []


def test_a_write_that_fails_says_so_in_words_and_the_record_agrees(two_checks, monkeypatch):
    from checker.web import decide

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()])
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}

    def full(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(decide, "atomic_write", full)
    response = client.post("/decide/approve", form)
    assert response.status_code == 400 and "couldn" in response.content.decode()
    assert the_record()[-1][2] == "failed"


def test_a_rule_that_went_in_is_done_even_if_it_cant_be_taken_out_of_the_proposals(
    two_checks, monkeypatch
):
    from checker.web import decide

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()])
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}

    def stuck(*args, **kwargs):
        raise PermissionError("no")

    monkeypatch.setattr(decide, "_take_out", stuck)
    assert client.post("/decide/approve", form).status_code == 302
    assert layer_of(home[0]).exists()
    assert the_record()[-1][2] == "done"


def test_a_locked_store_or_broken_list_is_words_not_a_bare_error(two_checks, monkeypatch):
    import sqlite3

    from checker.web import decide

    client, home, _ = two_checks

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(decide, "accept_baseline", locked)
    form = {"host": "web01", "bundle": "b2", "reason": "r", "confirm_password": PASSWORD}
    response = client.post("/decide/baseline", form)
    assert response.status_code == 400 and "couldn" in response.content.decode()
    monkeypatch.undo()
    (home[0] / "hosts.yaml").write_text("hosts: [unclosed\n")
    response = client.post("/decide/baseline", form)
    assert response.status_code == 400


def test_hostile_text_in_a_proposal_is_only_text(two_checks):
    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule(reason=HOSTILE)])
    text = decide_text(client)
    assert "<script>alert" not in text and BIDI not in text


def test_the_advisor_is_only_offered_when_it_is_on_and_asking_takes_the_password(
    two_checks, child, agent, monkeypatch
):
    from checker.web import decide

    client, home, _ = two_checks
    assert "Ask the AI advisor" not in decide_text(client)
    assert client.post("/decide/ask", {"host": "web01"}).status_code == 403
    _, seen = child
    form = {"host": "web01", "confirm_password": PASSWORD}
    location = client.post("/decide/ask", form)["Location"]
    run = finished()
    assert seen == {"kind": "advice", "hosts": ["web01"]} and run.kind == "advice"
    assert ("the AI advisor's request ended", "web01", "finished") in the_record()
    assert "See what it proposed" in client.get(location).content.decode()
    assert decide is not None


def test_asking_the_advisor_runs_its_real_command():
    from checker.web.runs import _command

    assert _command("advice", ["web01"])[3:] == [
        "checker", "advise", "--role", "whitelist", "--from-web-page", "--", "web01",
    ]  # fmt: skip


def test_only_a_check_keeps_its_pipe_open(web, inventory, child, agent):
    programs, _ = child
    programs["code"] = "import sys; print('saw', repr(sys.stdin.read()), file=sys.stderr)"
    client, _ = signed_in(web)
    inventory(key_host())
    form = {"host": "web01", "confirm_password": PASSWORD}
    location = client.post("/decide/ask", form)["Location"]
    finished()
    assert "saw" in client.get(location).content.decode()


def test_from_a_page_the_advisor_says_only_how_it_went(tmp_path):
    env = {**os.environ, "CHECKER_HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-m", "checker", "init"], env=env, check=True,
                   capture_output=True)  # fmt: skip
    from checker.web.runs import _command

    run = subprocess.run(
        _command("advice", ["web01"]), env=env, capture_output=True, text=True,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip
    assert run.returncode != 0 and "Traceback" not in run.stderr
    assert not run.stdout


def test_a_consequential_decision_takes_a_code_too_when_two_factor_is_on(web, inventory):
    client, user, device = verified_client(web)
    inventory(key_host())
    assert client.get("/decide", {"host": "web01"}).status_code == 200
    form = {"host": "web01", "bundle": "b", "reason": "r", "confirm_password": PASSWORD}
    assert client.post("/decide/baseline", form).status_code == 403


def test_a_stale_baseline_form_cant_accept_what_it_never_showed(two_checks):
    from checker.baseline import current_baseline
    from checker.evidence import Store, database_file

    client, home, _ = two_checks
    text = decide_text(client)
    form = {
        "host": "web01",
        "bundle": "b2",
        "sight": re.search(r'name="sight" value="(\w+)"', text)[1],
        "reason": "r",
        "confirm_password": PASSWORD,
    }
    assert client.post("/decide/baseline", {**form, "sight": "other"}).status_code == 400
    store = Store(database_file(home[0]))
    store.record_baseline("web01", "b2", "accepted", None)  # the comparison moves underneath it
    store.close()
    response = client.post("/decide/baseline", form)
    assert response.status_code == 400 and "Look again" in response.content.decode()
    store = Store(database_file(home[0]), read_only=True)
    assert current_baseline(store, "web01")["bundle_id"] == "b2"
    store.close()


def test_a_groups_rule_is_blocked_when_a_server_it_reaches_has_no_check(web, inventory):
    client, home = grouped(web, inventory)
    write_proposals(home[0], "web01", [proposal_rule()], layer="groups", name="web")
    (home[0] / "hosts.yaml").write_text(
        "hosts:\n- name: web01\n  address: 192.0.2.1\n  user: u\n  auth: agent\n  group: web\n"
        "- name: web02\n  address: 192.0.2.2\n  user: u\n  auth: agent\n  group: web\n"
    )
    text = decide_text(client)
    assert "web02 has no check" in text and "Approve this rule" not in text


def test_a_server_joining_the_group_after_looking_means_looking_again(web, inventory):
    from checker.inventory import Host
    from checker.web import decide

    client, home = signed_in(web)
    one = Host(name="web01", address="192.0.2.1", user="u", auth="agent", group="web")
    inventory(one)
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, CHANGED)
    write_proposals(home[0], "web01", [proposal_rule()], layer="groups", name="web")
    [first], _ = decide.previews(home[0], "web01", "jo")
    assert first.hosts == ["web01"] and not first.problem and first.sight
    inventory(one, Host(name="web02", address="192.0.2.2", user="u", auth="agent", group="web"))
    [second], _ = decide.previews(home[0], "web01", "jo")
    assert second.hosts == ["web01", "web02"] and second.sight != first.sight


def test_a_rule_says_how_many_checks_it_could_compare(two_checks, monkeypatch):
    from checker.web import decide

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()])
    assert "Compared with 2 of 2 checks" in decide_text(client)
    real = decide.load_analyses

    def older_one_skipped(*args):
        found = real(*args)
        found[0] = {"row": found[0]["row"], "skipped": "analysed with older checks"}
        return found

    monkeypatch.setattr(decide, "load_analyses", older_one_skipped)
    text = decide_text(client)
    assert "Compared with 1 of 2 checks" in text and "may hide more" in text


def test_a_server_with_a_chain_or_missing_events_cant_get_a_rule(two_checks, monkeypatch):
    from checker.web import decide

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()])
    real = decide.compare_loaded

    def changed(**extra):
        def compare(*args):
            found = real(*args)
            found[-1].update(extra)
            return found

        return compare

    monkeypatch.setattr(decide, "compare_loaded", changed(chained=True))
    assert "with a chain of findings" in decide_text(client)
    monkeypatch.setattr(decide, "compare_loaded", changed(events_missing=True))
    assert "events can" in decide_text(client)


def test_a_rule_with_a_strange_match_doesnt_stop_the_page(two_checks):
    client, home, _ = two_checks
    write_proposals(home[0], "web01", [{**proposal_rule(), "match": "a string"}])
    text = decide_text(client)
    assert "Refuse it" in text and "Approve this rule" not in text


def test_a_rule_that_went_in_is_done_whatever_stops_taking_it_out(two_checks, monkeypatch):
    from checker.web import decide

    client, home, _ = two_checks
    write_proposals(home[0], "web01", [proposal_rule()])
    form = {**rule_form(home[0]), "confirm_password": PASSWORD}

    def odd(*args, **kwargs):
        raise ValueError("edited meanwhile")

    monkeypatch.setattr(decide, "_take_out", odd)
    assert client.post("/decide/approve", form).status_code == 302
    assert the_record()[-1][2] == "done"


def test_from_a_page_a_key_in_a_settings_error_stays_off_it(tmp_path):
    env = {**os.environ, "CHECKER_HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-m", "checker", "init"], env=env, check=True,
                   capture_output=True)  # fmt: skip
    config = tmp_path / "config.yaml"
    config.write_text(config.read_text() + "\nadvisor: {api_key: SECRETVALUE}\n")
    from checker.web.runs import _command

    run = subprocess.run(
        _command("advice", ["web01"]), env=env, capture_output=True, text=True,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip
    assert "SECRETVALUE" not in run.stdout + run.stderr
    assert "Traceback" not in run.stderr and "couldn" in run.stderr
    rejected = subprocess.run(
        [sys.executable, "-m", "checker", "advise", "--all", "--from-web-page"],
        env=env, capture_output=True, text=True,
    )  # fmt: skip
    assert rejected.returncode == 2


# --- Managing servers (plan 5.13) ----------------------------------------------------------


def said(response):
    """The page as a person reads it: a value's apostrophe is escaped in the source."""
    return html.unescape(response.content.decode())


@pytest.fixture
def unconfirmed(inventory, home):
    """The list of servers, with no key confirmed for any of them."""
    (home[0] / "known_hosts").write_text("")
    return lambda *hosts: inventory(*hosts, confirmed=False)


def server_form(**changes):
    return {
        "name": "new01",
        "address": "192.0.2.50",
        "port": "22",
        "user": "scan",
        "auth": "key",
        "key_path": "/etc/scan-key",
        "sudo": "nopasswd",
        "password_source": "prompt",
        "group": "",
        "python": "python3",
        "web_roots": "",
        "prior": "",
        "confirm_password": PASSWORD,
        **changes,
    }


def hosts_now():
    from checker.inventory import load_inventory

    return {host.name: host for host in load_inventory().hosts}


def records_of(action):
    from checker.web.models import ActionRecord

    return list(ActionRecord.objects.filter(action=action).order_by("id"))


def server_page(client, name="web01"):
    response = client.get("/manage/server", {"host": name})
    assert response.status_code == 200
    return said(response)


def page_form(client, server="web01", **changes):
    """What the server's page would send, left as it is apart from `changes`."""
    from checker.web import manage

    host = hosts_now()[server]
    return {
        **manage.form_of(host),
        "host": server,
        "version": host.version(),
        "confirm_password": PASSWORD,
        **changes,
    }


def test_adding_a_server_needs_the_password_and_is_recorded(web, unconfirmed):
    client, _ = signed_in(web)
    refused = client.post("/manage/adding", server_form(confirm_password="wrong"))
    assert refused.status_code == 403 and "new01" not in hosts_now()
    added = client.post("/manage/adding", server_form(group="web-servers"))
    assert added.status_code == 302 and added["Location"] == "/manage/server?host=new01"
    assert hosts_now()["new01"].group == "web-servers"
    assert [r.outcome for r in records_of("added a server")] == ["refused", "started", "done"]
    text = client.get("/manage").content.decode()
    assert "new01" in text and "Not confirmed yet" in text and "web-servers" in text


@pytest.mark.parametrize(
    ("changes", "words"),
    [
        ({"name": "bad name"}, "Name:"),
        ({"name": "../../etc/x"}, "Name:"),
        ({"address": "192.0.2.1 ssh-ed25519 AAAA"}, "Address:"),
        ({"address": "evil\nexample ssh-ed25519 AAAA"}, "Address:"),
        ({"address": "-oProxyCommand=x"}, "Address:"),
        ({"user": "a" + chr(1) + "b"}, "Account:"),
        ({"user": "-oops"}, "Account:"),
        ({"group": "../hosts/web01"}, "Group:"),
        ({"key_path": "relative/key"}, "Key file:"),
        ({"key_path": "/etc/key\nmore"}, "Key file:"),
        ({"port": "99999"}, "SSH port:"),
        ({"port": "twenty"}, "SSH port:"),
        ({"python": "python3; reboot"}, "Python on the server:"),
        ({"web_roots": "relative/path"}, "Website folders:"),
        ({"prior": "150"}, "Starting estimate:"),
        ({"prior": "lots"}, "Starting estimate:"),
        ({"auth": "telepathy"}, "How it logs in:"),
        ({"python": "/usr/sbin/whatever"}, "Python on the server:"),
        ({"key_path": ""}, "Key file:"),
    ],
)
def test_a_bad_form_says_what_is_wrong_and_keeps_what_was_typed(web, unconfirmed, changes, words):
    client, _ = signed_in(web)
    before = hosts_now()
    response = client.post("/manage/adding", server_form(**changes))
    text = response.content.decode()
    assert response.status_code == 400 and words in text
    assert hosts_now().keys() == before.keys()
    assert 'value="/etc/scan-key"' in text or "key_path" in changes
    assert PASSWORD not in text
    assert records_of("added a server")[-1].outcome == "failed"


def test_no_known_hosts_line_can_be_added_through_an_address():
    from checker.inventory import Host, new_host_problems

    for address in ("a b", "a\nb", "a#b", "[a]", "a,b", "|1|x", "@revoked", "a\tb", "-x", "a/b"):
        host = Host(name="x", address=address, user="scan")
        assert [field for field, _ in new_host_problems(host)] == ["address"]
    for address in ("web.example.org", "192.0.2.1", "2001:db8::1", "::1", "fe80::1%eth0"):
        assert not new_host_problems(Host(name="x", address=address, user="scan"))
    assert not new_host_problems(Host(name="x", address=chr(252) + ".example", user="scan"))


def test_trusting_refuses_an_address_from_the_file_that_could_add_a_line(tmp_path):
    from checker.inventory import Host
    from checker.transport import HostKeyCheck, TransportError, trust_host_key

    key = asyncssh.generate_private_key("ssh-ed25519")
    check = HostKeyCheck(key.convert_to_public(), key.get_fingerprint("sha256"), "ssh-ed25519")
    host = Host(name="x", address="a ssh-ed25519 AAAA\nb", user="scan")
    with pytest.raises(TransportError):
        trust_host_key(host, check, tmp_path / "known_hosts")
    assert not (tmp_path / "known_hosts").exists()


@pytest.mark.parametrize(
    "old",
    [
        {"group": "Web Servers"},
        {"key_path": "keys/id_ed25519"},
        {"address": chr(252) + "ber.example"},
        {"user": "DOMAIN\\Jane Doe"},
    ],
)
def test_one_old_value_stops_nothing_and_a_save_keeps_it(web, unconfirmed, agent, old):
    """Written before these rules, or by hand. Pages and other servers go on working."""
    from checker.inventory import Host

    client, _ = signed_in(web)
    fields = {"address": "192.0.2.1", "user": "scan", **old}
    unconfirmed(Host(name="web01", **fields), Host(name="db01", address="192.0.2.2", user="scan"))
    assert client.get("/manage").status_code == 200
    assert client.get("/checks/new").status_code == 200
    assert client.get("/").status_code == 200
    form = page_form(client, sudo="root", auth="key" if "key_path" in old else "agent")
    assert client.post("/manage/server/change", form).status_code == 302
    host = hosts_now()["web01"]
    assert host.sudo == "root" and all(getattr(host, k) == v for k, v in old.items())


def test_the_command_line_refuses_the_same_new_values(home, capsys):
    from checker.cli import main as cli

    code = cli(["hosts", "add", "x", "--address", "a b", "--user", "scan"])
    assert code == 2 and "address" in capsys.readouterr().err


def test_a_name_with_earlier_results_takes_saying_it_is_the_same_server(web, unconfirmed):
    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN, host="old01")
    refused = client.post("/manage/adding", server_form(name="old01"))
    assert refused.status_code == 400 and "earlier results" in said(refused)
    assert 'name="same_server"' in said(refused)
    assert "old01" not in hosts_now()
    done = client.post("/manage/adding", server_form(name="old01", same_server="on"))
    assert done.status_code == 302 and "old01" in hosts_now()


def test_adding_a_name_in_use_says_so(web, unconfirmed):
    client, _ = signed_in(web)
    was = hosts_now()["web01"]
    response = client.post("/manage/adding", server_form(name="web01", same_server="on"))
    assert response.status_code == 400 and "already a server named" in said(response)
    assert hosts_now()["web01"] == was


def test_changing_a_server_is_confirmed_recorded_and_keeps_what_the_form_lacks(web, unconfirmed):
    from checker.evidence import Store, database_file
    from checker.inventory import Host

    client, home = signed_in(web)
    unconfirmed(Host(name="web01", address="192.0.2.1", user="scan", packs="none", prior=0.0123456))
    refused = client.post(
        "/manage/server/change", page_form(client, group="db", confirm_password="no")
    )
    assert refused.status_code == 403 and hosts_now()["web01"].group is None
    done = client.post("/manage/server/change", page_form(client, group="db"))
    assert done.status_code == 302
    host = hosts_now()["web01"]
    assert host.group == "db" and host.packs == "none", "the form has no packs field"
    assert host.prior == 0.0123456, "shown rounded, and leaving it alone doesn't change it"
    assert records_of("changed a server's settings")[-1].detail == 'Group: none to "db"'
    store = Store(database_file(home[0]))
    try:
        row = store.config_changes()[-1]
    finally:
        store.close()
    assert row["setting"] == "hosts.web01" and json.loads(row["new"]) == {"group": "db"}


def test_a_stale_form_changes_nothing_and_saving_again_can_t_undo_the_other_change(
    web, unconfirmed
):
    client, _ = signed_in(web)
    stale = page_form(client, address="192.0.2.99")
    client.post("/manage/server/change", page_form(client, group="db"))
    response = client.post("/manage/server/change", stale)
    text = said(response)
    assert response.status_code == 400 and "wasn't saved" in text
    assert hosts_now()["web01"].address == "192.0.2.1"
    assert 'value="db"' in text and 'value="192.0.2.99"' not in text, "shows it as it is now"


def test_a_bad_stale_form_stays_stale_when_it_comes_back(web, unconfirmed):
    client, _ = signed_in(web)
    stale = page_form(client)
    client.post("/manage/server/change", page_form(client, group="db"))
    version = hosts_now()["web01"].version()
    bad = client.post("/manage/server/change", {**stale, "port": "x"})
    assert bad.status_code == 400 and version in said(bad), "it's refused as stale first"


def test_leaving_a_form_alone_changes_nothing(web, unconfirmed):
    from checker.inventory import Host

    client, _ = signed_in(web)
    unconfirmed(
        Host(
            name="web01",
            address="192.0.2.1",
            user="scan",
            auth="agent",
            key_path="/k",
            web_roots=[],
        )
    )
    was = hosts_now()["web01"]
    assert client.post("/manage/server/change", page_form(client)).status_code == 302
    assert hosts_now()["web01"] == was
    assert records_of("changed a server's settings")[-1].detail == "nothing changed"


def test_a_name_cannot_be_changed_by_the_form(web, unconfirmed):
    client, _ = signed_in(web)
    client.post("/manage/server/change", page_form(client, name="other", group="db"))
    assert set(hosts_now()) == {"web01"} and hosts_now()["web01"].group == "db"


def test_removing_a_server_is_confirmed_and_keeps_its_results(web, unconfirmed):
    from checker.baseline import usable_bundles
    from checker.evidence import Store, database_file

    client, home = signed_in(web)
    analysed(home, "b1", 10, CLEAN)
    refused = client.post("/manage/server/remove", {"host": "web01", "confirm_password": "no"})
    assert refused.status_code == 403 and "web01" in hosts_now()
    done = client.post("/manage/server/remove", {"host": "web01", "confirm_password": PASSWORD})
    assert done.status_code == 302 and "web01" not in hosts_now()
    store = Store(database_file(home[0]), read_only=True)
    try:
        assert usable_bundles(store, "web01")
    finally:
        store.close()


def test_unlisted_servers_can_t_be_acted_on(web, unconfirmed, monkeypatch):
    from checker.web import manage

    def must_not(host):
        raise AssertionError(f"contacted {host}")

    monkeypatch.setattr(manage, "fetch_host_key", must_not)
    client, _ = signed_in(web)
    form = {"host": "nope", "confirm_password": PASSWORD, "pasted": "x"}
    for path in ("ask-key", "trust-key", "remove", "change"):
        assert client.post(f"/manage/server/{path}", form).status_code == 400
    assert client.get("/manage/server", {"host": "nope"}).status_code == 404


def test_the_manage_pages_contact_nothing_and_need_a_login(web, unconfirmed, monkeypatch):
    from checker.web import manage

    def must_not(host):
        raise AssertionError(f"contacted {host}")

    monkeypatch.setattr(manage, "fetch_host_key", must_not)
    client, _ = web
    for path in ("/manage", "/manage/add", "/manage/server?host=web01"):
        assert client.get(path).status_code == 302
    signed_in(web)
    for path in ("/manage", "/manage/add", "/manage/server?host=web01"):
        assert client.get(path).status_code == 200


def test_hostile_values_do_nothing_on_the_manage_pages(web, unconfirmed):
    client, _ = signed_in(web)
    refused = client.post("/manage/adding", server_form(key_path="/x" + HOSTILE, name="h1"))
    assert refused.status_code == 400
    typed = client.post("/manage/adding", server_form(address=HOSTILE)).content.decode()
    for text in (refused.content.decode(), typed):
        assert "<script>alert" not in text and "<img src=x" not in text and BIDI not in text
    from checker.inventory import Host

    unconfirmed(Host(name="h1", address="192.0.2.1", user="<b>" + BIDI, key_path="/x" + HOSTILE))
    for text in (client.get("/manage/server?host=h1"), client.get("/manage")):
        shown = text.content.decode()
        assert "<script>alert" not in shown and "<b>" not in shown and BIDI not in shown


# --- Whose key is it ---


@pytest.fixture
def offered(monkeypatch):
    """The server's answer, through the real comparison and the real known_hosts file."""
    from checker.transport import HostKeyCheck, trusted_fingerprints
    from checker.web import manage

    state = {"key": asyncssh.generate_private_key("ssh-ed25519"), "asked": 0}

    async def fetch(host):
        state["asked"] += 1
        key = state["key"]
        return HostKeyCheck(
            key=key.convert_to_public(),
            fingerprint=key.get_fingerprint("sha256"),
            key_type=key.get_algorithm(),
            known_fingerprints=trusted_fingerprints(host),
        )

    monkeypatch.setattr(manage, "fetch_host_key", fetch)
    return state


def printed(key):
    return f"256 {key.get_fingerprint('sha256')} root@web01 (ED25519)"


def trust_form(pasted, **changes):
    return {"host": "web01", "pasted": pasted, "confirm_password": PASSWORD, **changes}


def trusted_now(name="web01"):
    from checker.transport import trusted_fingerprints

    return trusted_fingerprints(hosts_now()[name])


def test_asking_shows_where_to_look_and_not_the_fingerprint(web, unconfirmed, offered):
    client, _ = signed_in(web)
    response = client.post("/manage/server/ask-key", {"host": "web01"})
    text = response.content.decode()
    assert response.status_code == 200
    assert "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" in text
    assert offered["key"].get_fingerprint("sha256") not in text
    assert trusted_now() == [], "asking trusts nothing"


def test_asking_is_a_post_so_a_link_can_t_make_this_machine_connect(web, unconfirmed, offered):
    client, _ = signed_in(web)
    assert client.get("/manage/server/ask-key", {"host": "web01"}).status_code == 405
    assert offered["asked"] == 0


def test_a_key_is_trusted_only_when_what_was_pasted_matches(web, unconfirmed, offered):
    client, _ = signed_in(web)
    other = asyncssh.generate_private_key("ssh-ed25519")
    wrong = client.post("/manage/server/trust-key", trust_form(printed(other)))
    assert wrong.status_code == 400 and "not the key this server is offering" in said(wrong)
    assert offered["key"].get_fingerprint("sha256") not in said(wrong)
    assert trusted_now() == []
    failed = records_of("trusted a server's host key")[-1]
    whole = offered["key"].get_fingerprint("sha256")
    assert failed.outcome == "failed" and whole[:15] in failed.detail and whole not in failed.detail
    assert whole not in said(client.get("/activity")), "or it could be pasted from there"
    empty = client.post("/manage/server/trust-key", trust_form("yes, trust it"))
    assert empty.status_code == 400 and "doesn't contain a fingerprint" in said(empty)
    assert trusted_now() == []
    right = client.post("/manage/server/trust-key", trust_form(printed(offered["key"])))
    assert right.status_code == 302
    assert trusted_now() == [offered["key"].get_fingerprint("sha256")]
    done = records_of("trusted a server's host key")[-1]
    assert done.outcome == "done" and done.detail == offered["key"].get_fingerprint("sha256")


def test_trusting_needs_the_password_before_anything_is_contacted(web, unconfirmed, offered):
    client, _ = signed_in(web)
    form = trust_form(printed(offered["key"]), confirm_password="no")
    assert client.post("/manage/server/trust-key", form).status_code == 403
    assert offered["asked"] == 0 and trusted_now() == []


def test_a_key_is_compared_with_a_fresh_answer_from_the_server(web, unconfirmed, offered):
    """A page opened earlier proves nothing about who answers now."""
    client, _ = signed_in(web)
    real = offered["key"]
    client.post("/manage/server/ask-key", {"host": "web01"})
    offered["key"] = asyncssh.generate_private_key("ssh-ed25519")
    response = client.post("/manage/server/trust-key", trust_form(printed(real)))
    assert response.status_code == 400 and trusted_now() == []


def test_a_changed_key_warns_and_takes_saying_so(web, unconfirmed, offered):
    client, _ = signed_in(web)
    first = offered["key"]
    client.post("/manage/server/trust-key", trust_form(printed(first)))
    offered["key"] = asyncssh.generate_private_key("ssh-ed25519")
    new = offered["key"]
    shown = client.post("/manage/server/ask-key", {"host": "web01"}).content.decode()
    assert "different key" in shown and first.get_fingerprint("sha256") in shown
    assert new.get_fingerprint("sha256") not in shown
    unticked = client.post("/manage/server/trust-key", trust_form(printed(new)))
    assert unticked.status_code == 400 and trusted_now() == [first.get_fingerprint("sha256")]
    done = client.post("/manage/server/trust-key", trust_form(printed(new), replace="on"))
    assert done.status_code == 302 and trusted_now() == [new.get_fingerprint("sha256")]


def test_a_key_already_trusted_needs_nothing(web, unconfirmed, offered):
    client, _ = signed_in(web)
    client.post("/manage/server/trust-key", trust_form(printed(offered["key"])))
    shown = client.post("/manage/server/ask-key", {"host": "web01"}).content.decode()
    assert "nothing to do" in shown and offered["key"].get_fingerprint("sha256") in shown


def test_a_new_address_needs_its_key_confirmed_again(web, unconfirmed, offered):
    client, _ = signed_in(web)
    client.post("/manage/server/trust-key", trust_form(printed(offered["key"])))
    assert "Not confirmed yet" not in server_page(client)
    client.post("/manage/server/change", page_form(client, address="192.0.2.77"))
    assert "Not confirmed yet" in server_page(client) and trusted_now() == []


def test_a_server_that_doesn_t_answer_says_so(web, unconfirmed, monkeypatch):
    from checker.transport import TransportError
    from checker.web import manage

    async def fail(host):
        raise TransportError("web01: cannot fetch the host key: refused")

    monkeypatch.setattr(manage, "fetch_host_key", fail)
    client, _ = signed_in(web)
    response = client.post("/manage/server/ask-key", {"host": "web01"})
    assert response.status_code == 400 and "couldn't be reached" in said(response)
    assert records_of("asked a server for its host key")[-1].outcome == "failed"


def test_a_damaged_known_hosts_file_is_a_plain_page(web, unconfirmed, home):
    client, _ = signed_in(web)
    (home[0] / "known_hosts").write_text("192.0.2.1 ssh-ed25519 notakey\n")
    assert "Can't be read" in said(client.get("/manage"))
    assert "can't be read" in server_page(client)
    response = client.post("/manage/server/ask-key", {"host": "web01"})
    assert response.status_code == 400 and "can't be read" in said(response)


def test_what_stops_a_check_is_in_plain_words(web, unconfirmed, monkeypatch):
    client, _ = signed_in(web)
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    unconfirmed(key_host())
    for text in (server_page(client), said(client.get("/checks/new"))):
        assert "can't reach one" in text and "SSH_AUTH_SOCK" not in text


def test_a_hostile_server_s_words_stay_out_of_the_record(web, unconfirmed, monkeypatch):
    from checker.transport import TransportError
    from checker.web import manage

    async def fail(host):
        raise TransportError(
            f"web01: cannot fetch the host key: {HOSTILE}"
        ) from asyncssh.ProtocolError(1, HOSTILE)

    monkeypatch.setattr(manage, "fetch_host_key", fail)
    client, _ = signed_in(web)
    response = client.post("/manage/server/ask-key", {"host": "web01"})
    assert response.status_code == 400 and "evil" not in said(response).split("<main>")[1]
    assert "evil" not in records_of("asked a server for its host key")[-1].detail


def test_rules_kept_under_a_name_count_as_used_before(web, unconfirmed):
    client, home = signed_in(web)
    folder = home[0] / "whitelist" / "hosts"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "old01.yaml").write_text("rules: []\n")
    refused = client.post("/manage/adding", server_form(name="old01"))
    assert refused.status_code == 400 and "whitelist rules" in said(refused)


def test_an_unconfirmed_server_can_t_be_started_and_says_where_to_go(web, unconfirmed, agent):
    client, _ = signed_in(web)
    unconfirmed(key_host())
    text = said(client.get("/checks/new"))
    assert "identity hasn't been confirmed" in text and "/manage/server?host=web01" in text
    assert "Ready to check" not in text
    assert client.post("/checks/start", {"host": "web01"}).status_code == 400


def test_a_paste_when_already_trusted_doesn_t_read_as_trusting(web, unconfirmed, offered):
    client, _ = signed_in(web)
    client.post("/manage/server/trust-key", trust_form(printed(offered["key"])))
    client.post("/manage/server/trust-key", trust_form("garbage"))
    assert records_of("trusted a server's host key")[-1].detail.endswith(": already trusted")


def test_a_server_removed_meanwhile_is_words_not_an_error_page(web, unconfirmed, monkeypatch):
    from checker.web import manage

    client, _ = signed_in(web)
    form = page_form(client)

    def gone(*args):
        raise KeyError("web01")

    monkeypatch.setattr(manage, "change", gone)
    assert client.post("/manage/server/change", form).status_code == 400


@pytest.mark.parametrize("kind", ["fifo", "dir", "big"])
def test_a_key_path_can_t_hang_or_fill_the_server(tmp_path, kind):
    from checker.transport import MOST_KEY_FILE_BYTES, read_key_file

    path = tmp_path / "key"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "dir":
        path.mkdir()
    else:
        path.write_bytes(b"x" * (MOST_KEY_FILE_BYTES + 1))
    with pytest.raises(OSError, match="ordinary file|too big"):
        read_key_file(str(path))


def test_the_record_says_where_an_added_server_points(web, unconfirmed):
    client, _ = signed_in(web)
    client.post("/manage/adding", server_form())
    detail = records_of("added a server")[-1].detail
    assert '"192.0.2.50"' in detail and '"scan"' in detail and '"/etc/scan-key"' in detail


def test_removing_and_adding_again_leaves_every_setting_on_the_record(web, unconfirmed):
    from checker.evidence import Store, database_file

    client, home = signed_in(web)
    form = {"host": "web01", "confirm_password": PASSWORD}
    assert client.post("/manage/server/remove", form).status_code == 302
    again = server_form(name="web01", group="quiet", prior="0.01", python="/tmp/x/python3")  # noqa: S108
    assert client.post("/manage/adding", {**again, "same_server": "on"}).status_code == 302
    detail = records_of("added a server")[-1].detail
    assert detail.startswith('Group: "quiet"; Starting estimate: 0.01%; Python on the server:')
    assert '"192.0.2.1"' in records_of("removed a server")[-1].detail
    store = Store(database_file(home[0]))
    try:
        rows = store.config_changes()
    finally:
        store.close()
    assert [row["setting"] for row in rows[-2:]] == ["hosts.web01", "hosts.web01"]
    assert json.loads(rows[-1]["new"])["group"] == "quiet" and rows[-2]["new"] == "null"


def test_a_value_can_t_cut_the_record_or_pass_for_another_change(web, unconfirmed):
    client, _ = signed_in(web)
    form = page_form(
        client,
        key_path="/k2; Group: prod to prod" + "/a" * 600,
        group="prod",
        prior="0.01",
    )
    assert client.post("/manage/server/change", form).status_code == 302
    detail = records_of("changed a server's settings")[-1].detail
    assert detail.startswith('Group: none to "prod"; Starting estimate: none to 0.01%')
    assert '"/k2; Group: prod to prod' in detail and "(cut)" in detail


@pytest.mark.parametrize(
    "changes",
    [
        {"user": "scan" + chr(0x9B) + "2J"},
        {"address": "ex" + chr(0x202E) + "ample.com"},
        {"key_path": "/k" + chr(0x202E)},
        {"key_path": "/" + "a" * 4100},
    ],
)
def test_nothing_new_can_reach_a_terminal_as_control_characters(web, unconfirmed, changes):
    client, _ = signed_in(web)
    assert client.post("/manage/adding", server_form(**changes)).status_code == 400
    assert "new01" not in hosts_now()


@pytest.mark.parametrize(
    "python",
    ["python3", "python3.12", "/usr/bin/python3", "/usr/bin/python", "/usr/libexec/platform-python",
     "/usr/bin/python3.12t", "/usr/bin/pypy3"],
)  # fmt: skip
def test_the_usual_pythons_are_accepted(web, unconfirmed, python):
    client, _ = signed_in(web)
    assert client.post("/manage/adding", server_form(python=python)).status_code == 302


def test_a_stored_nul_in_a_key_path_stops_only_that_server(web, unconfirmed, agent):
    from checker.inventory import Host

    client, _ = signed_in(web)
    unconfirmed(
        Host(name="web01", address="192.0.2.1", user="s", auth="key", key_path="/k" + chr(0) + "x")
    )
    assert client.get("/checks/new").status_code == 200


def test_a_key_file_is_read_no_further_than_a_key_could_be(tmp_path):
    from checker.transport import read_key_file

    key = asyncssh.generate_private_key("ssh-ed25519")
    path = tmp_path / "key"
    path.write_bytes(key.export_private_key())
    assert read_key_file(str(path)).get_fingerprint("sha256") == key.get_fingerprint("sha256")
    with pytest.raises(asyncssh.KeyImportError):
        read_key_file("/proc/self/status")


def test_two_confirmations_at_once_can_t_replace_a_key_nobody_agreed_to(web, unconfirmed, offered):
    """Both saw an untrusted address. The second would overwrite the first with no tick."""
    from checker.transport import trust_host_key
    from checker.web import manage

    client, _ = signed_in(web)
    first = asyncssh.generate_private_key("ssh-ed25519")
    host = hosts_now()["web01"]
    real = manage.trust_host_key

    def someone_else_first(host_, check, **kwargs):
        from checker.transport import HostKeyCheck

        trust_host_key(
            host_,
            HostKeyCheck(first.convert_to_public(), first.get_fingerprint("sha256"), "ssh-ed25519"),
        )
        real(host_, check, **kwargs)

    manage.trust_host_key = someone_else_first
    try:
        response = client.post("/manage/server/trust-key", trust_form(printed(offered["key"])))
    finally:
        manage.trust_host_key = real
    assert response.status_code == 400 and "just now" in said(response)
    assert trusted_now(host.name) == [first.get_fingerprint("sha256")]


def test_a_failed_removal_leaves_nothing_on_the_record(web, unconfirmed, monkeypatch):
    from checker.evidence import Store, database_file
    from checker.inventory import Host

    client, home = signed_in(web)
    unconfirmed(Host(name="web01", address="192.0.2.1", user="scan", packs="none"))
    store = Store(database_file(home[0]))
    try:
        before = len(store.config_changes())
    finally:
        store.close()

    def full_disk(*args, **kwargs):
        raise OSError(28, "No space left on device")

    form = {"host": "web01", "confirm_password": PASSWORD}
    with monkeypatch.context() as patched:  # undo() would undo the test home's setting too
        patched.setattr("checker.inventory.save_inventory", full_disk)
        assert client.post("/manage/server/remove", form).status_code == 400
    assert "web01" in hosts_now()
    store = Store(database_file(home[0]))
    try:
        assert len(store.config_changes()) == before
    finally:
        store.close()


@pytest.mark.parametrize("python", ["/usr/bin/not-python3", "not-python3", "/tmp/evilpython"])  # noqa: S108
def test_python_has_to_be_the_whole_name(web, unconfirmed, python):
    client, _ = signed_in(web)
    assert client.post("/manage/adding", server_form(python=python)).status_code == 400


def test_saving_something_else_leaves_old_odd_values_exactly_as_they_are(web, unconfirmed):
    from checker.inventory import Host

    client, _ = signed_in(web)
    was = Host(
        name="web01",
        address="192.0.2.1",
        user="scan",
        auth="key",
        group=" Web Servers ",
        key_path="/k/with space ",
        web_roots=["/srv/a ", "/srv/b"],
    )
    unconfirmed(was)
    form = page_form(client, sudo="root")
    form["web_roots"] = form["web_roots"].replace("\n", "\r\n")  # as a browser sends a text box
    assert client.post("/manage/server/change", form).status_code == 302
    assert hosts_now()["web01"] == was.model_copy(update={"sudo": "root"})


def test_a_server_removed_while_its_key_is_fetched_is_words(web, unconfirmed, monkeypatch):
    from checker.inventory import Inventory, hosts_file, save_inventory
    from checker.transport import HostKeyCheck
    from checker.web import manage

    key = asyncssh.generate_private_key("ssh-ed25519")

    async def removed_meanwhile(host):
        save_inventory(Inventory(hosts=[]), hosts_file())
        return HostKeyCheck(key.convert_to_public(), key.get_fingerprint("sha256"), "ssh-ed25519")

    monkeypatch.setattr(manage, "fetch_host_key", removed_meanwhile)
    client, _ = signed_in(web)
    response = client.post("/manage/server/ask-key", {"host": "web01"})
    assert response.status_code == 400 and "any more" in said(response)


class _FormReader(HTMLParser):
    """The change form's fields, as a browser would send them."""

    def __init__(self, action="/manage/server/change"):
        super().__init__(convert_charrefs=True)
        self.action = action
        self.fields, self.inside, self.area, self.select = {}, False, None, None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.inside = attrs.get("action") == self.action
        elif self.inside and tag == "input" and attrs.get("name"):
            if attrs.get("type") not in ("checkbox", "radio") or "checked" in attrs:
                self.fields[attrs["name"]] = attrs.get("value") or ""
        elif self.inside and tag == "textarea":
            self.area = attrs["name"]
            self.fields[self.area] = ""
        elif self.inside and tag == "select":
            self.select = attrs["name"]
        elif self.inside and tag == "option" and self.select and "selected" in attrs:
            self.fields[self.select] = attrs["value"]

    def handle_endtag(self, tag):
        if tag == "form":
            self.inside = False
        elif tag == "textarea":
            self.area = None
        elif tag == "select":
            self.select = None

    def handle_data(self, data):
        if self.area:
            self.fields[self.area] += data


def form_on_the_page(client, name="web01"):
    reader = _FormReader()
    reader.feed(client.get("/manage/server", {"host": name}).content.decode())
    return {**reader.fields, "confirm_password": PASSWORD}


@pytest.mark.parametrize(
    "stored",
    [
        {"user": "DOMAIN\\Jane Doe"},
        {"web_roots": ["/srv/one", "/srv/two", "/srv/three"]},
        {"auth": "key", "key_path": "/k/" + "a" * 700},
        {"prior": 0.0123456789},
        {"user": "<b>&\\"},
        {"user": "scan" + chr(0x202E)},
        {"auth": "key", "key_path": "/k" + chr(0x9B) + "\\x"},
        {"group": "Web Servers"},
    ],
)
def test_saving_the_form_as_the_page_shows_it_changes_nothing(web, unconfirmed, stored):
    """Through the rendered page, where a display filter could change what comes back."""
    from checker.inventory import Host

    client, _ = signed_in(web)
    was = Host(**{"name": "web01", "address": "192.0.2.1", "user": "scan", **stored})
    unconfirmed(was)
    assert client.post("/manage/server/change", form_on_the_page(client)).status_code == 302
    assert hosts_now()["web01"] == was
    assert records_of("changed a server's settings")[-1].detail == "nothing changed"


# --- Threat updates and settings from a page (plan 5.13) ------------------------------------


@pytest.fixture
def team_pack(web, inventory, tmp_path, capsys):
    """A signed-in browser, and a pack in force, signed by a trusted organization key."""
    from test_pack_format import GOOD
    from test_pack_trust import Key, pack

    from checker import cli

    client, _ = signed_in(web)
    key = Key()
    assert cli.main(["packs", "trust", "add", "team", str(key.pub_file(tmp_path / "k.pub"))]) == 0

    def add(text=GOOD):
        assert cli.main(["packs", "add", str(pack(tmp_path, key, text))]) == 0
        capsys.readouterr()

    add()
    return client, add


PACK = "example-2026-10"


def config_now():
    from checker.evidence import load_config
    from checker.inventory import home as checker_home

    return load_config(checker_home())


def history_now():
    from checker.evidence import Store, database_file
    from checker.inventory import home as checker_home

    store = Store(database_file(checker_home()))
    try:
        return store.config_changes()
    finally:
        store.close()


def test_the_threat_updates_page_contacts_nothing(team_pack, monkeypatch):
    from checker.web import threat_updates

    def must_not(*args, **kwargs):
        raise AssertionError("contacted the source")

    monkeypatch.setattr(threat_updates, "pull", must_not)
    client, _ = team_pack
    text = said(client.get("/manage/threats"))
    assert PACK in text and "Get the latest" in text
    assert client.get("/manage/threats/pull").status_code == 405


def test_getting_updates_says_what_changed_and_records_only_our_words(web, inventory, monkeypatch):
    from checker.packs.pull import Pulled
    from checker.web import threat_updates

    client, _ = signed_in(web)
    done = Pulled(added=[("new-one", 2, "added")], problems=[HOSTILE], notes=[HOSTILE])
    monkeypatch.setattr(threat_updates, "pull", lambda *args: done)
    response = client.post("/manage/threats/pull", {"a": "b"})
    text = response.content.decode()
    assert response.status_code == 200 and "new-one version 2: added" in said(response)
    assert "<script>alert" not in text and BIDI not in text
    detail = records_of("asked for threat updates")[-1].detail
    assert detail == "1 added or updated, 0 withdrawn, 0 retired, 1 problems"


def test_a_failed_fetch_says_so_and_keeps_the_source_s_words_out_of_the_record(
    web, inventory, monkeypatch
):
    from checker.packs.pull import PullError
    from checker.web import threat_updates

    def fail(*args):
        raise PullError(f"https://x/ {HOSTILE}")

    monkeypatch.setattr(threat_updates, "pull", fail)
    client, _ = signed_in(web)
    response = client.post("/manage/threats/pull", {"a": "b"})
    assert response.status_code == 400 and "couldn't be fetched" in said(response)
    assert "<script>alert" not in response.content.decode()
    last = records_of("asked for threat updates")[-1]
    assert last.outcome == "failed" and "evil" not in last.detail


def test_retiring_needs_the_password_and_a_reason_and_can_be_undone(team_pack):
    from checker.inventory import home as checker_home
    from checker.packs.store import active

    client, _ = team_pack
    in_use = lambda: [s.pack.id for s in active(checker_home(), config_now().packs.trusted_keys)[0]]  # noqa: E731
    form = {"pack": PACK, "reason": "too noisy", "confirm_password": PASSWORD}
    assert (
        client.post("/manage/threats/retire", {**form, "confirm_password": "no"}).status_code == 403
    )
    assert client.post("/manage/threats/retire", {**form, "reason": "  "}).status_code == 400
    assert in_use() == [PACK]
    assert client.post("/manage/threats/retire", form).status_code == 302
    assert in_use() == []
    assert records_of("retired a threat update")[-1].detail == "too noisy"
    text = said(client.get("/manage/threats"))
    assert "Put it back" in text and "by jo: too noisy" in text
    back = {"pack": PACK, "confirm_password": PASSWORD}
    assert (
        client.post("/manage/threats/put-back", {**back, "confirm_password": "no"}).status_code
        == 403
    )
    assert client.post("/manage/threats/put-back", back).status_code == 302
    assert in_use() == [PACK] and "Put it back" not in said(client.get("/manage/threats"))


def test_only_a_pack_retired_by_hand_can_be_put_back(team_pack):
    client, _ = team_pack
    form = {"pack": PACK, "confirm_password": PASSWORD}
    assert client.post("/manage/threats/put-back", form).status_code == 400
    assert client.post("/manage/threats/put-back", {**form, "pack": "../x"}).status_code == 400


def test_a_changed_retired_file_can_t_be_put_back(team_pack):
    from checker.inventory import home as checker_home

    client, _ = team_pack
    form = {"pack": PACK, "reason": "x", "confirm_password": PASSWORD}
    client.post("/manage/threats/retire", form)
    [kept] = (checker_home() / "packs" / "retired").glob("*.yaml")
    kept.write_text(kept.read_text().replace("likelihood_ratio: 5", "likelihood_ratio: 2"))
    assert client.post("/manage/threats/put-back", form).status_code == 400
    assert "Put it back" not in said(client.get("/manage/threats")), "nothing fit to put back"


def rule_form_of(client, scope):
    reader = _FormReader("/manage/threats/rule/save")
    response = client.get("/manage/threats/rule", {"for": scope})
    assert response.status_code == 200
    reader.feed(response.content.decode())
    return {**reader.fields, "for": scope, "confirm_password": PASSWORD}


def test_the_rule_for_all_servers_is_confirmed_and_recorded(team_pack):
    client, _ = team_pack
    form = rule_form_of(client, "all")
    refused = client.post(
        "/manage/threats/rule/save", {**form, "rule_kind": "none", "confirm_password": "no"}
    )
    assert refused.status_code == 403 and config_now().packs.apply == "all"
    done = client.post("/manage/threats/rule/save", {**form, "rule_kind": "none"})
    assert done.status_code == 302 and config_now().packs.apply == "none"
    assert history_now()[-1]["setting"] == "packs.apply"
    last = records_of("changed which threat updates apply")[-1]
    assert last.target == "all" and last.detail == '"all" to "none"'


def test_a_server_s_own_rule_and_going_back_to_default(team_pack):
    client, _ = team_pack
    form = rule_form_of(client, "host:web01")
    assert form["rule_kind"] == "default"
    saved = client.post("/manage/threats/rule/save", {**form, "rule_kind": "except", "ids": PACK})
    assert saved.status_code == 302 and hosts_now()["web01"].packs == f"except: {PACK}"
    assert PACK not in said(client.get("/manage/threats")).split("Applies to it")[1]
    form = rule_form_of(client, "host:web01")
    assert (
        client.post("/manage/threats/rule/save", {**form, "rule_kind": "default"}).status_code
        == 302
    )
    assert hosts_now()["web01"].packs is None


def test_a_group_s_rule(team_pack, inventory):
    from checker.inventory import Host

    client, _ = team_pack
    inventory(Host(name="web01", address="192.0.2.1", user="s", group="prod"))
    form = rule_form_of(client, "group:prod")
    assert (
        client.post("/manage/threats/rule/save", {**form, "rule_kind": "none"}).status_code == 302
    )
    assert config_now().packs.group_apply == {"prod": "none"}
    form = rule_form_of(client, "group:prod")
    assert (
        client.post("/manage/threats/rule/save", {**form, "rule_kind": "default"}).status_code
        == 302
    )
    assert config_now().packs.group_apply == {}


@pytest.mark.parametrize(
    "scope",
    ["host:nope", "group:nope", "nonsense", "host:", "group:../x", ""],
)
def test_a_rule_only_for_what_exists(team_pack, scope):
    client, _ = team_pack
    assert client.get("/manage/threats/rule", {"for": scope}).status_code == 404
    form = {"for": scope, "rule_kind": "none", "current": "", "confirm_password": PASSWORD}
    assert client.post("/manage/threats/rule/save", form).status_code == 400


@pytest.mark.parametrize(
    ("changes", "words"),
    [
        ({"rule_kind": "only"}, "Tick at least one"),
        ({"rule_kind": "only", "ids": "not an id!"}, "aren't threat updates"),
        ({"rule_kind": "nonsense"}, "Choose one"),
        ({"rule_kind": "default"}, "nothing to fall back on"),
        ({"rule_kind": "none", "current": "none"}, "changed since this page opened"),
    ],
)
def test_a_bad_rule_changes_nothing(team_pack, changes, words):
    client, _ = team_pack
    form = {**rule_form_of(client, "all"), **changes}
    response = client.post("/manage/threats/rule/save", form)
    assert response.status_code == 400 and words in said(response)
    assert config_now().packs.apply == "all"


def settings_form(client):
    reader = _FormReader("/manage/settings/save")
    reader.feed(client.get("/manage/settings").content.decode())
    return {**reader.fields, "confirm_password": PASSWORD}


def test_saving_the_settings_as_the_page_shows_them_changes_nothing(web, inventory):
    client, _ = signed_in(web)
    before = len(history_now())
    assert client.post("/manage/settings/save", settings_form(client)).status_code == 302
    assert len(history_now()) == before
    assert records_of("changed settings")[-1].detail == "nothing changed"


def test_changing_settings_is_confirmed_recorded_and_all_at_once(web, inventory):
    client, _ = signed_in(web)
    form = {**settings_form(client), "retention_days": "30", "prior": "5", "web_access_logs": "on"}
    refused = client.post("/manage/settings/save", {**form, "confirm_password": "no"})
    assert refused.status_code == 403 and config_now().retention_days != 30
    assert client.post("/manage/settings/save", form).status_code == 302
    config = config_now()
    assert config.retention_days == 30 and config.prior == 0.05 and config.web_access_logs is True
    assert {row["setting"] for row in history_now()[-3:]} == {
        "retention_days",
        "prior",
        "web_access_logs",
    }
    detail = records_of("changed settings")[-1].detail
    assert "Days evidence is kept: 90 to 30" in detail and "to 5%" in detail


@pytest.mark.parametrize(
    ("changes", "words"),
    [
        ({"retention_days": "soon"}, "whole number"),
        ({"retention_days": "0"}, "Days evidence is kept"),
        ({"retention_days": "-1"}, "whole number"),
        ({"prior": "150"}, "above 0 and below 100"),
        ({"prior": "nan"}, "type a number"),
        ({"advisor.max_cost_per_run": "inf"}, "type a number"),
        ({"home_text": "everything"}, "choose one"),
        ({"web_access_logs": "maybe"}, "on or off"),
        ({"advisor.model": "two words"}, "name this can use"),
        ({"advisor.model": ""}, "this is needed"),
        ({"advisor.inference_geo": "a b"}, "short name in letters"),
        ({"prior": "1_0"}, "type a number"),
        ({"retention_days": "9999999"}, "100 years"),
        ({"advisor.api_key_source": "command:/bin/sh -c evil"}, "choose one"),
        ({"advisor.fallback": "model"}, "choose one"),
    ],
)
def test_a_bad_setting_changes_nothing_at_all(web, inventory, changes, words):
    client, _ = signed_in(web)
    before = config_now()
    form = {**settings_form(client), "stale_after_days": "9", **changes}
    response = client.post("/manage/settings/save", form)
    assert response.status_code == 400 and words in said(response)
    assert config_now() == before, "the good setting beside it didn't go in either"


def test_what_runs_a_command_or_sends_elsewhere_can_t_be_set_from_a_page(web, inventory):
    client, _ = signed_in(web)
    before = config_now()
    form = {
        **settings_form(client),
        "notify_command": "/bin/sh -c evil",
        "advisor.base_url": "https://evil.example/",
        "advisor.api": "openai",
        "advisor.fallback_model.base_url": "https://evil.example/",
        "advisor.fallback_model.api_key_source": "command:/bin/evil",
        "packs.source": "https://evil.example/",
        "packs.apply": "none",
        "recipients": "x",
    }
    assert client.post("/manage/settings/save", form).status_code == 302
    assert config_now() == before


def test_the_list_of_settings_on_the_page_has_nothing_dangerous_in_it():
    from checker.web.setting_forms import BY_KEY

    assert not {
        key for key in BY_KEY if "notify" in key or "base_url" in key or key.endswith("api")
    }
    assert "packs.source" not in BY_KEY and not any("fallback_model" in key for key in BY_KEY)
    offered = {value for value, _ in BY_KEY["advisor.api_key_source"].options}
    assert offered == {"env", "keyring"}


def test_a_key_command_stays_as_it_is_and_isn_t_shown(web, inventory):
    from checker.inventory import home as checker_home
    from checker.settings import change

    secret = "/usr/bin/fetch-key --token sekrit"
    change(checker_home(), "advisor.api_key_source", f"command:{secret}")
    change(checker_home(), "notify_command", "/usr/bin/tell --token sekrit")
    client, _ = signed_in(web)
    text = said(client.get("/manage/settings"))
    assert "sekrit" not in text and "set on the command line" in text
    form = {**settings_form(client), "retention_days": "30"}
    assert "advisor.api_key_source" not in form
    forged = {**form, "advisor.api_key_source": "env"}
    assert client.post("/manage/settings/save", forged).status_code == 302
    assert config_now().advisor.api_key_source == f"command:{secret}"
    assert config_now().retention_days == 30


def test_stale_settings_change_nothing_and_saving_again_can_t_undo_the_other_change(web, inventory):
    from checker.inventory import home as checker_home
    from checker.settings import change

    client, _ = signed_in(web)
    stale = {**settings_form(client), "retention_days": "30"}
    change(checker_home(), "stale_after_days", "9")
    response = client.post("/manage/settings/save", stale)
    assert response.status_code == 400 and "wasn't saved" in said(response)
    assert config_now().retention_days != 30
    assert 'value="9"' in response.content.decode(), "shows them as they are now"


def test_turning_the_advisor_on_says_what_would_leave(web, inventory):
    client, _ = signed_in(web)
    assert "placeholders" in said(client.get("/manage/settings"))
    form = {**settings_form(client), "advisor.enabled": "on"}
    assert client.post("/manage/settings/save", form).status_code == 302
    assert config_now().advisor.enabled is True


def test_the_new_pages_contact_nothing_and_need_a_login(web, inventory):
    client, _ = web
    for path in ("/manage/threats", "/manage/threats/rule?for=all", "/manage/settings"):
        assert client.get(path).status_code == 302
    for path in (
        "threats/pull",
        "threats/retire",
        "threats/put-back",
        "threats/rule/save",
        "settings/save",
    ):
        assert client.post(f"/manage/{path}", {"a": "b"}).status_code == 302


def test_text_for_a_terminal_reads_properly_on_the_pages(team_pack):
    """The display filter shows a line break as an escape, and a date as JSON."""
    client, _ = team_pack
    settings_page = client.get("/manage/settings").content.decode()
    assert "\\u000a" not in settings_page and "whitelist rules" in settings_page
    threats = said(client.get("/manage/threats"))
    assert 'published "' not in threats and "published 20" in threats


def test_settings_never_show_where_the_advisor_sends_or_a_token_in_it(web, inventory):
    from checker.inventory import home as checker_home
    from checker.settings import change

    change(checker_home(), "advisor.base_url", "https://corp.example/tenant/abcdef0123secretpath")
    client, _ = signed_in(web)
    text = said(client.get("/manage/settings"))
    assert "secretpath" not in text and "corp.example" not in text
    assert "another server" in text and "checker advise" not in text.split("Changed only")[0]


def test_with_another_server_the_key_s_source_can_t_be_chosen_from_a_page(web, inventory):
    """The keyring holds one key for every server: choosing it could send Anthropic's elsewhere."""
    from checker.inventory import home as checker_home
    from checker.settings import change

    change(checker_home(), "advisor.base_url", "https://proxy.example/")
    client, _ = signed_in(web)
    form = settings_form(client)
    assert "advisor.api_key_source" not in form and "advisor.fallback" not in form
    forged = {**form, "advisor.api_key_source": "keyring"}
    assert client.post("/manage/settings/save", forged).status_code == 302
    assert config_now().advisor.api_key_source == "env"


def pulled_page(client, monkeypatch, done=None, error=None):
    from checker.web import threat_updates

    def stand_in(*args):
        if error:
            raise error
        return done

    monkeypatch.setattr(threat_updates, "pull", stand_in)
    return client.post("/manage/threats/pull", {"a": "b"})


def test_the_latest_is_only_said_when_it_s_true(web, inventory, monkeypatch):
    from checker.packs.pull import Pulled

    client, _ = signed_in(web)
    latest = "already have the latest"
    assert latest in said(pulled_page(client, monkeypatch, Pulled()))
    text = said(pulled_page(client, monkeypatch, Pulled(problems=["no file"])))
    assert latest not in text and "Not everything could be taken" in text
    text = said(pulled_page(client, monkeypatch, Pulled(notes=["the index is 45 days old"])))
    assert latest not in text and "Not everything" not in text and "Nothing new" in text
    text = said(pulled_page(client, monkeypatch, Pulled(added=[("a-pack", 1, "already in force")])))
    assert latest in text and "What changed" not in text
    text = said(pulled_page(client, monkeypatch, Pulled(key_list=(2, 1))))
    assert latest not in text and "new list of trusted signing keys" in text


def test_a_pull_that_stops_part_way_says_what_it_already_did(web, inventory, monkeypatch):
    from checker.packs.pull import Pulled, PullError

    client, _ = signed_in(web)
    failure = PullError("index signature")
    failure.pulled = Pulled(retired_by_keys=["old-pack-v1.yaml"], key_list=(2, 1))
    response = pulled_page(client, monkeypatch, error=failure)
    text = said(response)
    assert response.status_code == 400 and "old-pack-v1.yaml is no longer used" in text
    assert "new list of trusted signing keys" in text
    last = records_of("asked for threat updates")[-1]
    assert last.outcome == "failed" and "1 retired" in last.detail


def test_a_long_rule_can_still_be_changed(team_pack):
    from checker.inventory import home as checker_home
    from checker.settings import change

    client, _ = team_pack
    long_rule = "only: " + ", ".join(f"pack-number-{n:03}" for n in range(40))
    change(checker_home(), "packs.apply", long_rule)
    form = rule_form_of(client, "all")
    assert form["current"] == long_rule
    response = client.post("/manage/threats/rule/save", {**form, "rule_kind": "all"})
    assert response.status_code == 302 and config_now().packs.apply == "all"


def test_retention_can_t_break_expiry(home, capsys):
    from checker.cli import main as cli

    assert cli(["config", "set", "retention_days", "999999"]) == 2
    assert "100 years" in capsys.readouterr().err


def test_a_pack_put_back_isn_t_listed_as_retired(team_pack):
    client, _ = team_pack
    form = {"pack": PACK, "reason": "x", "confirm_password": PASSWORD}
    client.post("/manage/threats/retire", form)
    assert "no longer in use" in said(client.get("/manage/threats"))
    client.post("/manage/threats/put-back", form)
    assert "no longer in use" not in said(client.get("/manage/threats"))


def test_damaged_files_are_words_on_every_threat_update_action(team_pack):
    from checker.evidence import config_file
    from checker.inventory import home as checker_home

    client, _ = team_pack
    good = config_file(checker_home()).read_text()
    config_file(checker_home()).write_text(good + "\nnot_a_setting: 1\n")
    form = {"pack": PACK, "reason": "x", "confirm_password": PASSWORD}
    for path, data in (
        ("/manage/threats/retire", form),
        ("/manage/threats/put-back", form),
        ("/manage/threats/pull", {"a": "b"}),
    ):
        response = client.post(path, data)
        assert response.status_code == 400 and "couldn't be read" in said(response), path
    assert client.get("/manage/threats").status_code == 503


def test_damaged_state_is_a_plain_note(team_pack):
    from checker.inventory import home as checker_home
    from checker.packs.state import read_state, write_state

    client, _ = team_pack
    state = read_state(checker_home())
    del state["packs"][PACK]["highest"]
    state["packs"][PACK]["held"] = True
    write_state(checker_home(), state)
    response = client.get("/manage/threats")
    assert response.status_code == 200 and "can't be read" in said(response)


def test_a_page_doesn_t_wait_for_a_pull_holding_the_lock(team_pack, monkeypatch):
    from checker.files import locked
    from checker.inventory import home as checker_home
    from checker.web import threat_updates

    monkeypatch.setattr(threat_updates, "_WAIT_SECONDS", 0.2)
    client, _ = team_pack
    form = {"pack": PACK, "reason": "x", "confirm_password": PASSWORD}
    with locked(checker_home() / "packs" / "state"):
        response = client.post("/manage/threats/retire", form)
    assert response.status_code == 400 and "Try again in a moment" in said(response)


def test_retiring_holds_a_pack_back_even_if_the_state_lost_its_record(team_pack):
    from checker.inventory import home as checker_home
    from checker.packs.state import read_state, write_state

    client, _ = team_pack
    state = read_state(checker_home())
    del state["packs"][PACK]
    write_state(checker_home(), state)
    form = {"pack": PACK, "reason": "x", "confirm_password": PASSWORD}
    assert client.post("/manage/threats/retire", form).status_code == 302
    assert read_state(checker_home())["packs"][PACK]["held"] is True


def test_a_refused_settings_form_stays_stale_when_it_comes_back(web, inventory, monkeypatch):
    """Someone else's change lands between the check and the page. The refused page has to keep
    the version it started from, or saving again would undo that change unseen."""
    from checker.inventory import home as checker_home
    from checker.settings import change
    from checker.web import setting_forms

    client, _ = signed_in(web)
    form = settings_form(client)

    def refused_as_someone_else_saves(base, post):
        change(checker_home(), "stale_after_days", "9")
        raise setting_forms.FormProblem("Days evidence is kept: type a whole number of days.")

    with monkeypatch.context() as patched:
        patched.setattr(setting_forms, "save", refused_as_someone_else_saves)
        bad = client.post("/manage/settings/save", {**form, "retention_days": "soon"})
    assert bad.status_code == 400
    reader = _FormReader("/manage/settings/save")
    reader.feed(bad.content.decode())
    assert reader.fields["version"] == form["version"]
    again = {**reader.fields, "retention_days": "30", "confirm_password": PASSWORD}
    retry = client.post("/manage/settings/save", again)
    assert retry.status_code == 400 and config_now().retention_days != 30
    assert config_now().stale_after_days == 9


def test_a_saved_settings_page_says_so(web, inventory):
    client, _ = signed_in(web)
    response = client.post("/manage/settings/save", settings_form(client))
    assert response["Location"] == "/manage/settings?saved=1"
    assert "Saved." in said(client.get(response["Location"]))


def test_a_rule_naming_what_isn_t_in_use_says_so(team_pack):
    from checker.inventory import home as checker_home
    from checker.settings import change

    client, _ = team_pack
    change(checker_home(), "packs.apply", "only: gone-away")
    text = said(client.get("/manage/threats"))
    assert "gone-away not in use right now" in text
    assert "Nothing" in text.split("Applies to it")[1]


def test_a_fetch_that_failed_never_says_the_latest(web, inventory, monkeypatch):
    """A failed pull still carries a result, empty, which would read as being up to date."""
    from checker.packs.pull import Pulled, PullError

    client, _ = signed_in(web)
    failure = PullError("the server answered 500")
    failure.pulled = Pulled()
    response = pulled_page(client, monkeypatch, error=failure)
    text = said(response)
    assert response.status_code == 400 and "couldn't be fetched" in text
    assert "already have the latest" not in text and "What changed" not in text


def test_a_failed_fetch_doesn_t_show_the_source_s_address(web, inventory, monkeypatch):
    from checker.inventory import home as checker_home
    from checker.packs.pull import Pulled, PullError
    from checker.settings import change

    source = "https://mirror.example/SeCrEtToken/"
    change(checker_home(), "packs.source", source)
    client, _ = signed_in(web)
    failure = PullError(f"{source}keys.yaml: the server answered 500")
    failure.pulled = Pulled(problems=[f"a pack: {source}packs/x: the server answered 500"])
    text = said(pulled_page(client, monkeypatch, error=failure))
    assert "SeCrEtToken" not in text and "the source: the server answered 500" in text


def test_a_failure_part_way_doesn_t_claim_nothing_changed(web, inventory, monkeypatch):
    from checker.packs.pull import Pulled

    client, _ = signed_in(web)
    failure = OSError(28, "No space left on device")
    failure.pulled = Pulled(added=[("a-pack", 1, "added")])
    text = said(pulled_page(client, monkeypatch, error=failure))
    assert "nothing was changed" not in text and "a-pack version 1: added" in text


def test_with_another_server_redaction_and_geography_stay_with_the_owner(web, inventory):
    from checker.inventory import home as checker_home
    from checker.settings import change

    change(checker_home(), "advisor.base_url", "https://llm.example/")
    client, _ = signed_in(web)
    form = settings_form(client)
    assert "advisor.redaction" not in form and "advisor.inference_geo" not in form
    forged = {**form, "advisor.redaction": "none"}
    assert client.post("/manage/settings/save", forged).status_code == 302
    assert config_now().advisor.redaction == "pseudonymize"


def test_the_command_line_holds_back_a_pack_whose_record_was_lost(team_pack, capsys):
    from checker import cli
    from checker.inventory import home as checker_home
    from checker.packs.state import read_state, write_state

    state = read_state(checker_home())
    del state["packs"][PACK]
    write_state(checker_home(), state)
    assert cli.main(["packs", "retire", PACK, "--reason", "x"]) == 0
    assert read_state(checker_home())["packs"][PACK]["held"] is True


def test_a_note_about_a_pack_held_back_reads_as_a_sentence(web, inventory, monkeypatch):
    from checker.packs.pull import Pulled

    client, _ = signed_in(web)
    note = "a-pack: the pack was retired here by hand: `checker packs add` brings it back"
    text = said(pulled_page(client, monkeypatch, Pulled(notes=[note])))
    assert (
        "retired here by hand: put it back on this page" in text and "packs add` brings" not in text
    )


@pytest.mark.parametrize("scope", ["all", "group:prod", "host:web01"])
def test_a_stale_rule_is_refused_at_the_write_for_every_scope(team_pack, inventory, scope):
    from checker.inventory import Host

    client, _ = team_pack
    inventory(Host(name="web01", address="192.0.2.1", user="s", group="prod"))
    form = rule_form_of(client, scope)
    assert (
        client.post("/manage/threats/rule/save", {**form, "rule_kind": "none"}).status_code == 302
    )
    stale = {**form, "rule_kind": "all"}
    response = client.post("/manage/threats/rule/save", stale)
    assert response.status_code == 400 and "changed since this page opened" in said(response)
    settings = config_now().packs
    now = {
        "all": settings.apply,
        "group:prod": settings.group_apply.get("prod"),
        "host:web01": hosts_now()["web01"].packs,
    }
    assert now[scope] == "none"


def test_the_check_of_a_rule_is_made_under_the_lock_that_writes_it(home):
    from checker.settings import ConfigChangedMeanwhile, change

    change(home[0], "packs.apply", "none")
    with pytest.raises(ConfigChangedMeanwhile):
        change(home[0], "packs.apply", "all", "all")


def test_a_long_source_s_address_stays_off_the_page_when_an_error_cuts_it(
    web, inventory, monkeypatch
):
    from checker.inventory import home as checker_home
    from checker.packs.pull import PullError
    from checker.settings import change

    source = "https://mirror.example/SeCrEtToken/" + "x" * 300 + "/"
    change(checker_home(), "packs.source", source)
    client, _ = signed_in(web)
    failure = PullError(f"{(source + 'keys.yaml')[:200]}: the server answered 500")
    text = said(pulled_page(client, monkeypatch, error=failure))
    assert "SeCrEtToken" not in text and "the server answered 500" in text


@pytest.mark.parametrize("damage", ["not_a_setting: 1\n", ": : not yaml {\n"])
def test_retiring_on_the_command_line_works_with_a_damaged_config(team_pack, capsys, damage):
    from checker import cli
    from checker.evidence import config_file
    from checker.inventory import home as checker_home

    path = config_file(checker_home())
    path.write_text(path.read_text() + damage)
    assert cli.main(["packs", "retire", PACK, "--reason", "x"]) == 0
    assert "Retired" in capsys.readouterr().out


def test_a_redirect_s_address_stays_off_the_page_too(web, inventory, monkeypatch):
    from checker.packs.pull import PullError

    client, _ = signed_in(web)
    failure = PullError("refused a redirect to http://mirror.example/SeCrEtToken/keys.yaml")
    text = said(pulled_page(client, monkeypatch, error=failure))
    assert "SeCrEtToken" not in text and "refused a redirect to the source" in text


def test_a_group_s_invisible_characters_don_t_reach_the_form(web, unconfirmed):
    from checker.inventory import Host

    client, _ = signed_in(web)
    unconfirmed(Host(name="web01", address="192.0.2.1", user="s", group="a" + BIDI + "b"))
    for path in ("/manage/add", "/manage/server?host=web01"):
        assert BIDI not in client.get(path).content.decode()


# --- The daily check and deleting evidence from a page (plan 5.13) --------------------------


class _Ran:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


@pytest.fixture
def timer(monkeypatch, tmp_path):
    """Never this machine's real timer: a home of its own, and a stand-in for its commands."""
    state = {"ran": [], "active": None, "linger": "Linger=yes", "fail": None}

    def run(command, **kwargs):
        state["ran"].append(command)
        if state["fail"] and command[-1].endswith(".timer") and "enable" in command:
            if isinstance(state["fail"], OSError):
                raise state["fail"]
            return _Ran(returncode=1, stderr=state["fail"])
        if "is-active" in command:
            if state["active"] is not None:
                return _Ran(stdout=state["active"])
            return _Ran(stdout="active" if state["unit"].exists() else "inactive")
        if command[0] == "loginctl":
            return _Ran(stdout=state["linger"])
        return _Ran()

    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user" / ".config"))
    state["unit"] = tmp_path / "user" / ".config" / "systemd" / "user" / "compromise-checker.timer"
    return state


def starts(ran):
    return [c for c in ran if "enable" in c or "disable" in c or "daemon-reload" in c]


def test_the_daily_check_page_starts_nothing(web, inventory, timer):
    client, _ = signed_in(web)
    text = said(client.get("/manage/schedule"))
    assert "No daily check is set up" in text and not starts(timer["ran"])
    assert not timer["unit"].exists()
    assert client.get("/manage/schedule/save").status_code == 405


def test_setting_the_daily_check_is_confirmed_and_recorded(web, inventory, timer):
    client, _ = signed_in(web)
    form = {"at": "02:15", "confirm_password": PASSWORD}
    assert (
        client.post("/manage/schedule/save", {**form, "confirm_password": "no"}).status_code == 403
    )
    assert not timer["unit"].exists() and not starts(timer["ran"])
    assert client.post("/manage/schedule/save", form).status_code == 302
    assert "OnCalendar=*-*-* 02:15:00" in timer["unit"].read_text()
    assert ["systemctl", "--user", "enable", "--now", "compromise-checker.timer"] in timer["ran"]
    assert records_of("set the daily check")[-1].detail == "every day at 02:15"
    assert "A daily check runs at 02:15" in said(client.get("/manage/schedule"))


@pytest.mark.parametrize("at", ["soon", "25:00", "", "3", "12:99"])
def test_a_bad_time_sets_nothing(web, inventory, timer, at):
    client, _ = signed_in(web)
    response = client.post("/manage/schedule/save", {"at": at, "confirm_password": PASSWORD})
    assert response.status_code == 400 and "Type a time of day" in said(response)
    assert not timer["unit"].exists()


def test_stopping_the_daily_check_is_confirmed_and_recorded(web, inventory, timer):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    assert client.post("/manage/schedule/stop", {"confirm_password": "no"}).status_code == 403
    assert timer["unit"].exists()
    assert client.post("/manage/schedule/stop", {"confirm_password": PASSWORD}).status_code == 302
    assert not timer["unit"].exists()
    assert records_of("stopped the daily check")[-1].detail == "stopped"
    assert "No daily check is set up" in said(client.get("/manage/schedule"))


def test_a_timer_that_can_t_start_says_so(web, inventory, timer):
    client, _ = signed_in(web)
    form = {"at": "02:15", "confirm_password": PASSWORD}
    timer["fail"] = "Failed to connect to bus " + HOSTILE
    response = client.post("/manage/schedule/save", form)
    text = response.content.decode()
    assert response.status_code == 400 and "couldn" in text and "connect to bus" in text
    assert "<script>alert" not in text and BIDI not in text
    assert records_of("set the daily check")[-1].outcome == "failed"
    timer["fail"] = FileNotFoundError(2, "No such file or directory")
    assert client.post("/manage/schedule/save", form).status_code == 400


def test_a_timer_that_isn_t_running_is_said_plainly(web, inventory, timer):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    timer["active"] = "inactive"
    assert "isn't running, so it won't happen" in said(client.get("/manage/schedule"))
    timer["active"], timer["linger"] = "active", "Linger=no"
    assert "only while someone is logged in" in said(client.get("/manage/schedule"))


def test_the_daily_check_lists_servers_it_can_t_reach(web, unconfirmed, timer):
    from checker.inventory import Host

    client, _ = signed_in(web)
    unconfirmed(Host(name="db01", address="192.0.2.2", user="s", auth="password"))
    text = said(client.get("/manage/schedule"))
    assert "db01" in text and "needs a password typed" in text and "hasn't been confirmed" in text


def stored(home, name, days_ago):
    """A check filed where a real one is, so a purge finds its files, and worked out, so the first
    becomes the baseline."""
    from test_purge import add

    add(home, name, days_ago)
    return analyze(home[1], "web01", identity_of(home), home[3].recipients, name)


def bundles_of(home, host="web01"):
    from checker.evidence import Store, database_file

    store = Store(database_file(home[0]), read_only=True)
    try:
        return [row["id"] for row in store.bundles(host)]
    finally:
        store.close()


def purge_form(client, **query):
    response = client.get("/manage/delete", query)
    assert response.status_code == 200
    reader = _FormReader("/manage/delete/confirm")
    reader.feed(response.content.decode())
    return {**reader.fields, "word": "purge", "confirm_password": PASSWORD}


ONE_SERVER = {"what": "host", "host": "web01"}


def test_the_delete_page_shows_what_would_go_and_deletes_nothing(web, inventory):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    stored(home, "b2", 2)
    assert "What this would delete" not in said(client.get("/manage/delete"))
    text = said(client.get("/manage/delete", ONE_SERVER))
    assert "2 checks" in text and "All of web01's evidence goes" in text
    assert sorted(bundles_of(home)) == ["b1", "b2"]


def test_deleting_needs_the_password_and_the_word_and_is_recorded(web, inventory):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    form = purge_form(client, **ONE_SERVER)
    for wrong, status in (
        ({"confirm_password": "no"}, 403),
        ({"word": "yes"}, 400),
        ({"word": ""}, 400),
    ):
        assert client.post("/manage/delete/confirm", {**form, **wrong}).status_code == status
        assert bundles_of(home) == ["b1"]
    response = client.post("/manage/delete/confirm", form)
    assert response.status_code == 200 and "Deleted 1 check" in said(response)
    assert bundles_of(home) == []
    last = records_of("deleted stored evidence")[-1]
    assert last.target == "web01" and last.outcome == "done" and "1 checks" in last.detail
    assert home[1].purges(), "the tool's own record of it stays"


def test_only_what_was_shown_is_deleted(web, inventory):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    form = purge_form(client, **ONE_SERVER)
    stored(home, "b2", 2)
    response = client.post("/manage/delete/confirm", form)
    assert response.status_code == 400 and "changed since you looked" in said(response)
    assert sorted(bundles_of(home)) == ["b1", "b2"]


def test_expiry_keeps_a_listed_server_s_baseline_and_says_so(web, inventory):
    from checker.inventory import home as checker_home
    from checker.settings import change

    client, home = signed_in(web)
    stored(home, "b1", 30)
    stored(home, "b0", 20)
    stored(home, "b2", 2)
    change(checker_home(), "retention_days", "10")
    text = said(client.get("/manage/delete", {"what": "expired"}))
    assert "web01's current baseline stays" in text and "1 check</strong>" in text
    form = purge_form(client, what="expired")
    assert client.post("/manage/delete/confirm", form).status_code == 200
    assert sorted(bundles_of(home)) == ["b1", "b2"]


def test_expiry_won_t_run_with_no_servers_listed(web, inventory):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    inventory()
    assert "no servers in the list" in said(client.get("/manage/delete", {"what": "expired"}))
    form = {"what": "expired", "word": "purge", "sight": "x", "confirm_password": PASSWORD}
    assert client.post("/manage/delete/confirm", form).status_code == 400
    assert bundles_of(home) == ["b1"]


def test_deleting_part_of_a_server_warns_that_its_baseline_goes(web, inventory):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    stored(home, "b2", 2)
    query = {"what": "before", "before": "2100-01-01"}
    assert "All of web01" in said(client.get("/manage/delete", query))
    from checker.evidence import Store, database_file

    store = Store(database_file(home[0]), read_only=True)
    try:
        middle = store.bundle("b2")["started_at"]
    finally:
        store.close()
    text = said(client.get("/manage/delete", {"what": "before", "before": middle}))
    assert "baseline goes too" in text and "1 check</strong>" in text


@pytest.mark.parametrize(
    ("query", "words"),
    [
        ({"what": "host", "host": "nobody"}, "no stored evidence"),
        ({"what": "before"}, "Choose a date"),
        ({"what": "before", "before": "soon"}, "Choose a date"),
        ({"what": "nonsense"}, "Choose what to delete"),
    ],
)
def test_what_can_t_be_asked_says_so_and_deletes_nothing(web, inventory, query, words):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    assert words in said(client.get("/manage/delete", query))
    form = {**query, "word": "purge", "sight": "x", "confirm_password": PASSWORD}
    response = client.post("/manage/delete/confirm", form)
    assert response.status_code == 400 and words in said(response)
    assert bundles_of(home) == ["b1"]


def test_nothing_is_deleted_while_a_check_runs(web, inventory, monkeypatch):
    from checker.inventory import home as checker_home
    from checker.schedule import run_lock
    from checker.web import runs

    client, home = signed_in(web)
    stored(home, "b1", 30)
    form = purge_form(client, **ONE_SERVER)
    with run_lock(checker_home()):  # a scheduled one, or the command line's
        response = client.post("/manage/delete/confirm", form)
    assert response.status_code == 400 and "A check is running" in said(response)
    with monkeypatch.context() as patched:  # one from a page
        patched.setitem(runs._running, 999, object())
        response = client.post("/manage/delete/confirm", form)
    assert response.status_code == 400 and "A check is running" in said(response)
    assert bundles_of(home) == ["b1"]


def test_files_that_can_t_be_deleted_are_said(web, inventory, monkeypatch):
    from checker import purge
    from checker.web import purging

    client, home = signed_in(web)
    stored(home, "b1", 30)
    form = purge_form(client, **ONE_SERVER)
    real = purge.execute

    def partly(store, base, chosen):
        outcome = real(store, base, chosen)
        outcome.failed.append((Path("/x"), "read-only"))
        return outcome

    monkeypatch.setattr(purging, "execute", partly)
    response = client.post("/manage/delete/confirm", form)
    assert response.status_code == 200 and "1 file couldn't be deleted" in said(response)


def test_the_new_action_pages_need_a_login(web, inventory):
    client, _ = web
    for path in ("/manage/schedule", "/manage/delete"):
        assert client.get(path).status_code == 302
    for path in ("/manage/schedule/save", "/manage/schedule/stop", "/manage/delete/confirm"):
        assert client.post(path, {"a": "b"}).status_code == 302
        assert client.get(path).status_code in (302, 405)


def test_a_timer_that_fails_to_start_leaves_nothing_saying_it_runs(web, inventory, timer):
    client, _ = signed_in(web)
    timer["fail"] = "Failed to connect to bus: No medium found"
    response = client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    text = said(response)
    assert response.status_code == 400 and "wasn't started from a logged-in session" in text
    assert not timer["unit"].exists()
    assert "No daily check is set up" in said(client.get("/manage/schedule"))


def test_a_failed_change_of_time_keeps_the_timer_it_had(web, inventory, timer):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    timer["fail"] = "busy"
    assert (
        client.post(
            "/manage/schedule/save", {"at": "05:00", "confirm_password": PASSWORD}
        ).status_code
        == 400
    )
    assert "02:15" in timer["unit"].read_text()


def test_a_timer_that_can_t_be_read_isn_t_said_to_run(web, inventory, timer):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    timer["active"] = ""
    text = said(client.get("/manage/schedule"))
    assert "can't tell whether" in text and "A daily check runs at" not in text


def test_stopping_a_timer_that_won_t_stop_says_so_and_keeps_its_files(
    web, inventory, timer, monkeypatch
):
    import subprocess

    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    real = subprocess.run

    def refusing(command, **kwargs):
        if "disable" in command:
            return _Ran(returncode=1, stderr="Failed to connect to bus")
        return real(command, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr("subprocess.run", refusing)
        response = client.post("/manage/schedule/stop", {"confirm_password": PASSWORD})
    assert response.status_code == 400 and "wasn't stopped" in said(response)
    assert timer["unit"].exists()
    assert records_of("stopped the daily check")[-1].outcome == "failed"


def test_a_timer_of_another_home_is_said_and_left_alone(web, inventory, timer):
    client, _ = signed_in(web)
    timer["unit"].parent.mkdir(parents=True)
    timer["unit"].write_text("[Timer]\nOnCalendar=*-*-* 02:15:00\n")
    timer["unit"].with_suffix(".service").write_text(
        "[Service]\nEnvironment=CHECKER_HOME=/srv/other\n"
    )
    text = said(client.get("/manage/schedule"))
    assert "another copy of this tool" in text and "A daily check runs" not in text
    for path, form in (("save", {"at": "04:00"}), ("stop", {})):
        response = client.post(f"/manage/schedule/{path}", {**form, "confirm_password": PASSWORD})
        assert response.status_code == 400
    assert "02:15" in timer["unit"].read_text()


@pytest.mark.parametrize(
    "line",
    ["OnCalendar=daily", "OnCalendar=Mon *-*-* 02:15:00",
     "#OnCalendar=*-*-* 02:15:00\nOnBootSec=1h",
     "OnCalendar=*-*-* 02:15:00\nOnCalendar=*-*-* 09:00:00",
     "OnCalendar=*-*-* 02:15:00\n  OnBootSec=1h"],
)  # fmt: skip
def test_a_timer_changed_by_hand_isn_t_given_a_time_it_doesn_t_have(web, inventory, timer, line):
    from checker.inventory import home as checker_home

    client, _ = signed_in(web)
    timer["unit"].parent.mkdir(parents=True)
    timer["unit"].write_text(f"[Timer]\n{line}\n")
    timer["unit"].with_suffix(".service").write_text(f"Environment=CHECKER_HOME={checker_home()}\n")
    text = said(client.get("/manage/schedule"))
    assert "A daily check runs at" not in text and "set up by hand" in text


def test_the_list_uses_the_timer_s_agent_not_the_web_server_s(web, unconfirmed, timer, monkeypatch):
    from checker.inventory import home as checker_home

    client, _ = signed_in(web)
    unconfirmed(key_host())
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/web-server-agent")  # noqa: S108
    timer["unit"].parent.mkdir(parents=True)
    timer["unit"].write_text("OnCalendar=*-*-* 02:15:00\n")
    timer["unit"].with_suffix(".service").write_text(f"Environment=CHECKER_HOME={checker_home()}\n")
    assert "can't reach one" in said(client.get("/manage/schedule"))
    timer["unit"].with_suffix(".service").write_text(
        f"Environment=CHECKER_HOME={checker_home()}\nEnvironment=SSH_AUTH_SOCK=/run/agent\n"
    )
    assert "can't reach one" not in said(client.get("/manage/schedule"))


def test_a_timer_error_shows_once_filtered_and_on_one_line(web, inventory, timer):
    client, _ = signed_in(web)
    timer["fail"] = "C:\\x bad\nHint: second line"
    response = client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    text = said(response)
    assert "C:\\\\x bad Hint: second line" in text and "\\u000a" not in text


def test_a_damaged_list_of_servers_is_words_on_every_new_action(web, inventory, timer):
    from checker.inventory import hosts_file

    client, home = signed_in(web)
    stored(home, "b1", 30)
    form = purge_form(client, **ONE_SERVER)
    hosts_file().write_text("hosts: [not: right\n")
    for path, data in (
        ("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD}),
        ("/manage/delete/confirm", form),
    ):
        assert client.post(path, data).status_code == 400, path
    assert bundles_of(home) == ["b1"] and not timer["unit"].exists()


def test_the_record_names_every_server_when_every_server_s_went(web, inventory):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    form = purge_form(client, what="before", before="2100-01-01", host="web01")
    assert "host" not in form or form["host"] == ""
    assert client.post("/manage/delete/confirm", {**form, "host": "web01"}).status_code == 200
    assert records_of("deleted stored evidence")[-1].target == "every server, before 2100-01-01"


def test_what_goes_can_t_grow_without_being_shown_again(web, inventory):
    from checker.purge import plan as real_plan
    from checker.web import purging

    client, home = signed_in(web)
    stored(home, "b1", 30)
    form = purge_form(client, **ONE_SERVER)

    def with_another_report(store, base, *args, **kwargs):
        chosen = real_plan(store, base, *args, **kwargs)
        chosen.digests[Path("/x/report.html")] = "abc"
        return chosen

    original = purging.purge_plan
    purging.purge_plan = with_another_report
    try:
        response = client.post("/manage/delete/confirm", form)
    finally:
        purging.purge_plan = original
    assert response.status_code == 400 and "changed since you looked" in said(response)
    assert bundles_of(home) == ["b1"]


def test_emptying_a_server_says_what_its_next_check_means(web, inventory):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    text = said(client.get("/manage/delete", ONE_SERVER))
    assert "Its next check becomes the new baseline" in text


def test_a_server_emptied_is_forgotten_by_the_last_run_s_memory(web, inventory):
    from checker.schedule import load_state, save_state

    client, home = signed_in(web)
    stored(home, "b1", 30)
    state = {
        "hosts": {"web01": {"findings": ["user:toor"]}, "db01": {"findings": []}},
        "pending": ["web01: new critical", "db01: something"],
    }
    save_state(home[0], state, home[3].recipients)
    assert (
        client.post("/manage/delete/confirm", purge_form(client, **ONE_SERVER)).status_code == 200
    )
    kept = load_state(home[0], identity_of(home))
    assert set(kept["hosts"]) == {"db01"}
    assert kept["pending"] == ["web01: new critical", "db01: something"], "news nobody has had"


def test_a_choice_without_a_kind_says_so(web, inventory):
    client, home = signed_in(web)
    stored(home, "b1", 30)
    assert "Choose what to delete" in said(client.get("/manage/delete", {"host": "web01"}))
    assert "Choose a server" in said(client.get("/manage/delete", {"what": "host"}))


@pytest.fixture
def mac(monkeypatch, tmp_path):
    """launchctl's answers, by what it's asked. Stand-ins: nothing here has run on a real Mac."""
    state = {"ran": [], "bootstrap": 0, "print": 0}

    def run(command, **kwargs):
        state["ran"].append(command)
        if command[:2] == ["launchctl", "bootstrap"]:
            code = (
                state["bootstrap"].pop(0)
                if isinstance(state["bootstrap"], list)
                else state["bootstrap"]
            )
            return _Ran(returncode=code, stderr="in progress" if code else "")
        if command[:2] == ["launchctl", "print"]:
            return _Ran(returncode=state["print"])
        return _Ran()

    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    from checker import schedule

    monkeypatch.setattr(schedule.time, "sleep", lambda seconds: None)
    return state


def test_a_failed_change_on_a_mac_loads_the_old_timer_again(web, inventory, mac):
    client, _ = signed_in(web)
    form = {"at": "02:15", "confirm_password": PASSWORD}
    assert client.post("/manage/schedule/save", form).status_code == 302
    mac["ran"].clear()
    mac["bootstrap"] = [1, 1, 1, 1, 1, 0]
    response = client.post("/manage/schedule/save", {**form, "at": "05:00"})
    assert response.status_code == 400
    bootstraps = [c for c in mac["ran"] if c[:2] == ["launchctl", "bootstrap"]]
    assert len(bootstraps) == 6, "five tries, then the old one again"
    assert "A daily check runs at 02:15" in said(client.get("/manage/schedule"))


def test_a_mac_timer_that_isn_t_loaded_is_said_plainly(web, inventory, mac):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    mac["print"] = 113
    assert "isn't running, so it won't happen" in said(client.get("/manage/schedule"))
    mac["print"] = 5
    text = said(client.get("/manage/schedule"))
    assert "can't tell whether" in text and "A daily check runs at" not in text


@pytest.mark.parametrize(
    ("ours", "written", "other"),
    [
        ("/srv/a", "/srv/ab", True),
        ("/home/x/.config/checker", "/home/x/.config/checker-staging", True),
        ("/srv/100%", "/srv/100%", False),
        ("/srv/with space", "/srv/with space", False),
        ("/srv/a", "/srv/a", False),
    ],
)
def test_whose_timer_it_is_comes_from_its_home_exactly(tmp_path, monkeypatch, ours, written, other):
    from checker import schedule

    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user" / ".config"))
    units = schedule.systemd_units((2, 15), {"CHECKER_HOME": written})
    folder = tmp_path / "user" / ".config" / "systemd" / "user"
    folder.mkdir(parents=True)
    for name, text in units.items():
        (folder / name).write_text(text)
    assert schedule.timer_of_another_home(Path(ours)) is other
    assert schedule.timer_time(Path(ours)) == "02:15"


def test_whose_timer_it_is_with_a_symlink_or_nothing_to_read(tmp_path, monkeypatch):
    from checker import schedule

    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user" / ".config"))
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    folder = tmp_path / "user" / ".config" / "systemd" / "user"
    folder.mkdir(parents=True)
    service = folder / "compromise-checker.service"
    service.write_text(f"Environment=CHECKER_HOME={tmp_path / 'link'}\n")
    assert schedule.timer_of_another_home(real) is False
    service.write_text("")
    assert schedule.timer_of_another_home(real) is False, "not locked out by an empty file"


def test_a_failure_writing_a_file_puts_them_all_back(web, inventory, timer, monkeypatch):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    real = Path.write_bytes

    def fails_on_the_timer(self, data):
        if self.suffix == ".timer" and b"05:00" in data:
            raise OSError(28, "No space left on device")
        return real(self, data)

    monkeypatch.setattr(Path, "write_bytes", fails_on_the_timer)
    response = client.post("/manage/schedule/save", {"at": "05:00", "confirm_password": PASSWORD})
    monkeypatch.setattr(Path, "write_bytes", real)
    text = said(response)
    assert response.status_code == 400 and "put back as they were" in text and "No space" in text
    assert "02:15" in timer["unit"].read_text()


def test_stale_files_can_be_cleared_with_no_timer_to_stop(web, inventory, timer):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    timer["unit"].unlink()
    timer["ran"].clear()
    assert client.post("/manage/schedule/stop", {"confirm_password": PASSWORD}).status_code == 302
    assert not timer["unit"].with_suffix(".service").exists()
    assert [c for c in timer["ran"] if "disable" in c], "it may still be loaded"


def test_stopped_is_stopped_even_if_tidying_up_fails(web, inventory, timer, monkeypatch):
    import subprocess

    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    real = subprocess.run

    def hangs_on_reload(command, **kwargs):
        if "daemon-reload" in command:
            raise subprocess.TimeoutExpired(command, 60)
        return real(command, **kwargs)

    monkeypatch.setattr("subprocess.run", hangs_on_reload)
    assert client.post("/manage/schedule/stop", {"confirm_password": PASSWORD}).status_code == 302
    assert records_of("stopped the daily check")[-1].detail == "stopped"


def test_busy_isn_t_read_as_a_missing_session(web, inventory, timer):
    client, _ = signed_in(web)
    timer["fail"] = "Device or resource busy"
    response = client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    assert "logged-in session" not in said(response) and "busy" in said(response)


def test_another_home_s_timer_offers_nothing_to_save(web, inventory, timer):
    client, _ = signed_in(web)
    timer["unit"].parent.mkdir(parents=True)
    timer["unit"].write_text("OnCalendar=*-*-* 02:15:00\n")
    timer["unit"].with_suffix(".service").write_text("Environment=CHECKER_HOME=/srv/other\n")
    text = said(client.get("/manage/schedule"))
    assert "Each day it checks" not in text and "/manage/schedule/save" not in text


def test_the_command_line_won_t_purge_during_a_run(home, capsys):
    from test_purge import add

    from checker import cli
    from checker.schedule import run_lock

    add(home, "b1", 30)
    with run_lock(home[0]):
        assert cli.main(["purge", "web01", "--yes"]) == 1
        assert "in progress" in capsys.readouterr().err
        assert cli.main(["purge", "web01", "--dry-run"]) == 0, "looking is fine"
    assert home[1].bundles("web01")


def test_no_false_warning_when_nothing_was_emptied(home, capsys, monkeypatch):
    from test_purge import add

    from checker import cli, schedule

    add(home, "b1", 30)
    add(home, "b2", 2)

    def must_not(*args):
        raise AssertionError("nothing was emptied")

    monkeypatch.setattr(schedule, "forget_hosts", must_not)
    assert (
        cli.main(
            [
                "purge",
                "--before",
                (__import__("test_purge").NOW - timedelta(days=10)).isoformat(),
                "--yes",
            ]
        )
        == 0
    )
    assert "memory" not in capsys.readouterr().err


def test_the_record_s_date_is_what_the_plan_used(web, inventory):
    from checker.web.purging import named

    assert named({"what": "host", "host": "db02", "before": "   "}) == "db02"


def test_a_failed_save_doesn_t_switch_on_a_timer_that_was_off(web, inventory, timer):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    timer["active"] = "inactive"
    timer["ran"].clear()
    timer["fail"] = "busy"
    assert (
        client.post(
            "/manage/schedule/save", {"at": "05:00", "confirm_password": PASSWORD}
        ).status_code
        == 400
    )
    enables = [c for c in timer["ran"] if "enable" in c]
    assert len(enables) == 1, "only the attempt that failed, not one to put it back"
    assert "02:15" in timer["unit"].read_text()


def test_a_failed_save_puts_back_a_timer_that_was_on(web, inventory, timer):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    timer["ran"].clear()
    timer["fail"] = "busy"
    client.post("/manage/schedule/save", {"at": "05:00", "confirm_password": PASSWORD})
    assert len([c for c in timer["ran"] if "enable" in c]) == 2


def test_a_write_failure_asks_nothing_of_the_scheduler(web, inventory, timer, monkeypatch):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    timer["active"] = "inactive"
    timer["ran"].clear()
    real = Path.write_bytes

    def full(self, data):
        if b"05:00" in data or b"[Service]" in data:
            raise OSError(28, "No space left on device")
        return real(self, data)

    monkeypatch.setattr(Path, "write_bytes", full)
    client.post("/manage/schedule/save", {"at": "05:00", "confirm_password": PASSWORD})
    monkeypatch.setattr(Path, "write_bytes", real)
    assert not starts(timer["ran"])


def test_only_one_change_to_the_timer_at_a_time(web, inventory, timer):
    from checker import schedule
    from checker.files import locked

    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    original = schedule.TIMER_LOCK_SECONDS
    schedule.TIMER_LOCK_SECONDS = 0.1
    try:
        with locked(timer["unit"].parent / "compromise-checker"):
            for path, form in (("save", {"at": "05:00"}), ("stop", {})):
                response = client.post(
                    f"/manage/schedule/{path}", {**form, "confirm_password": PASSWORD}
                )
                assert response.status_code == 400 and "try again" in said(response)
    finally:
        schedule.TIMER_LOCK_SECONDS = original
    assert "02:15" in timer["unit"].read_text()


def test_a_timer_still_loaded_with_its_files_gone_can_be_stopped(web, inventory, timer):
    client, _ = signed_in(web)
    client.post("/manage/schedule/save", {"at": "02:15", "confirm_password": PASSWORD})
    timer["unit"].unlink()
    timer["unit"].with_suffix(".service").unlink()
    timer["active"] = "active"
    text = said(client.get("/manage/schedule"))
    assert "No daily check is set up" not in text and "Stop the daily check" in text
    timer["ran"].clear()
    assert client.post("/manage/schedule/stop", {"confirm_password": PASSWORD}).status_code == 302
    assert [c for c in timer["ran"] if "disable" in c]
    assert records_of("stopped the daily check")[-1].detail == "stopped"


@pytest.mark.parametrize(
    ("line", "other"),
    [
        ('Environment="SSH_AUTH_SOCK=/run/agent" "CHECKER_HOME=/srv/other"', True),
        ('Environment="SSH_AUTH_SOCK=/run/agent" "CHECKER_HOME=/srv/ours"', False),
        ("  Environment=CHECKER_HOME=/srv/other", True),
        (
            "Environment=CHECKER_HOME=/srv/ours\nEnvironment=\nEnvironment=CHECKER_HOME=/srv/other",
            True,
        ),
        ("Environment=CHECKER_HOME=/srv/other\nEnvironment=CHECKER_HOME=/srv/ours", False),
        ('Environment="CHECKER_HOME=/srv/ours"', False),
        ("ExecStart=/bin/true", True),
        ('Environment="CHECKER_HOME=/srv/un closed', True),
    ],
)
def test_a_service_s_environment_is_read_as_systemd_reads_it(tmp_path, monkeypatch, line, other):
    from checker import schedule

    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user" / ".config"))
    folder = tmp_path / "user" / ".config" / "systemd" / "user"
    folder.mkdir(parents=True)
    (folder / "compromise-checker.service").write_text(f"[Service]\n{line}\n")
    assert schedule.timer_of_another_home(Path("/srv/ours")) is other


def test_nothing_that_reads_evidence_starts_while_it_s_deleted(web, inventory, child, agent):
    from checker.web import runs

    client, _ = signed_in(web)
    inventory(key_host())
    with runs.none_may_start():
        response = client.post("/checks/start", {"host": "web01"})
    assert response.status_code == 400 and "being deleted" in said(response)
    with pytest.raises(runs.Held):
        with runs.none_may_start():
            runs.start("analysis", ["web01"], "jo", "127.0.0.1")


def test_deleting_holds_off_new_runs_until_it_s_done(web, inventory, monkeypatch):
    from checker.web import purging, runs

    client, home = signed_in(web)
    stored(home, "b1", 30)
    form = purge_form(client, **ONE_SERVER)
    real, seen = purging.execute, []

    def looking(store, base, chosen):
        seen.append(runs._held)
        return real(store, base, chosen)

    monkeypatch.setattr(purging, "execute", looking)
    assert client.post("/manage/delete/confirm", form).status_code == 200
    assert seen == [1] and runs._held == 0


def test_a_timer_with_no_file_is_only_called_stopped_once_it_s_inactive(
    web, inventory, timer, monkeypatch
):
    import subprocess

    client, _ = signed_in(web)
    timer["active"] = "active"
    real = subprocess.run

    def no_unit_file(command, **kwargs):
        if "disable" in command:
            return _Ran(returncode=1, stderr="Unit file compromise-checker.timer does not exist.")
        if "stop" in command:
            timer["ran"].append(command)
            if timer.get("stops"):
                timer["active"] = "inactive"
            return _Ran()
        return real(command, **kwargs)

    monkeypatch.setattr("subprocess.run", no_unit_file)
    refused = client.post("/manage/schedule/stop", {"confirm_password": PASSWORD})
    assert refused.status_code == 400 and "wasn't stopped" in said(refused)
    timer["stops"] = True
    done = client.post("/manage/schedule/stop", {"confirm_password": PASSWORD})
    assert done.status_code == 302 and records_of("stopped the daily check")[-1].detail == "stopped"


def test_a_plist_that_can_t_establish_whose_it_is_isn_t_taken_for_this_one_s(tmp_path, monkeypatch):
    import plistlib

    from checker import schedule

    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    folder = tmp_path / "user" / "Library" / "LaunchAgents"
    folder.mkdir(parents=True)
    path = folder / f"{schedule.LAUNCHD_LABEL}.plist"
    path.write_bytes(plistlib.dumps({"ProgramArguments": ["/usr/bin/env", "CHECKER_HOME=/x"]}))
    assert schedule.timer_of_another_home(tmp_path) is True
    path.write_bytes(plistlib.dumps({}))
    assert schedule.timer_of_another_home(tmp_path) is False, "nothing to read: nobody locked out"
    path.write_bytes(b"not a plist")
    assert schedule.timer_of_another_home(tmp_path) is False


@pytest.mark.parametrize(
    "when",
    [{"Hour": "two", "Minute": 15}, {"Hour": 99, "Minute": 15}, {"Hour": 2, "Minute": True},
     {"Hour": 2, "Minute": 15, "Weekday": 1}, "daily"],
)  # fmt: skip
def test_a_plist_changed_by_hand_gives_no_time_and_no_error(tmp_path, monkeypatch, when):
    import plistlib

    from checker import schedule

    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    folder = tmp_path / "user" / "Library" / "LaunchAgents"
    folder.mkdir(parents=True)
    path = folder / f"{schedule.LAUNCHD_LABEL}.plist"
    path.write_bytes(plistlib.dumps({"StartCalendarInterval": when}))
    assert schedule.timer_time(tmp_path) is None


def test_a_baseline_accepted_since_the_preview_means_looking_again(web, inventory):
    from checker.baseline import accept

    client, home = signed_in(web)
    stored(home, "b1", 30)
    stored(home, "b2", 20)
    form = purge_form(client, **ONE_SERVER)
    accept(home[1], "web01", "ours", identity_of(home), home[3].recipients, "b2")
    response = client.post("/manage/delete/confirm", form)
    assert response.status_code == 400 and "changed since you looked" in said(response)
    assert sorted(bundles_of(home)) == ["b1", "b2"]


# --- First setup (plan 5.13b) ---------------------------------------------------------------


def test_the_web_interface_sets_itself_up_on_a_first_start(tmp_path, monkeypatch, capsys):
    from checker import cli
    from checker.evidence import load_config
    from checker.web import app

    home_path = tmp_path / "fresh"
    monkeypatch.setenv("CHECKER_HOME", str(home_path))
    monkeypatch.setattr(app, "serve", lambda *args: 0)
    assert cli.main(["web"]) == 0
    out = capsys.readouterr().out
    assert "BACK IT UP" in out and "AI advisor off" in out
    config = load_config(home_path)
    assert config.advisor.enabled is False and config.home_text == "off"
    assert config.web_access_logs is False
    assert (home_path / "keys" / "evidence-identity.txt").exists()
    before = (home_path / "keys" / "evidence-identity.txt").read_text()
    assert cli.main(["web"]) == 0, "and leaves it alone after that"
    assert (home_path / "keys" / "evidence-identity.txt").read_text() == before


@pytest.mark.parametrize("trace", ["checker.db", "evidence/x.age"])
def test_evidence_with_no_key_or_settings_stops_a_first_start(tmp_path, monkeypatch, capsys, trace):
    from checker import cli
    from checker.web import app

    home_path = tmp_path / "old"
    (home_path / trace).parent.mkdir(parents=True, exist_ok=True)
    (home_path / trace).write_text("kept")
    monkeypatch.setenv("CHECKER_HOME", str(home_path))
    monkeypatch.setattr(app, "serve", lambda *args: 0)
    assert cli.main(["web"]) == 1
    assert "Put your backup of the evidence key" in capsys.readouterr().err
    assert (home_path / trace).read_text() == "kept" and not (home_path / "config.yaml").exists()


def test_a_kept_key_is_enough_to_start_again(tmp_path, monkeypatch, capsys):
    """After a first start cut short, or on a new machine with only the backup the page asks for."""
    from checker import cli
    from checker.evidence import load_config
    from checker.web import app

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    monkeypatch.setattr(app, "serve", lambda *args: 0)
    assert cli.main(["init", "--advisor", "off"]) == 0
    key = tmp_path / "keys" / "evidence-identity.txt"
    before, recipients = key.read_text(), load_config(tmp_path).recipients
    (tmp_path / "config.yaml").unlink()
    capsys.readouterr()
    assert cli.main(["web"]) == 0
    assert "keeping it" in capsys.readouterr().out
    assert key.read_text() == before and load_config(tmp_path).recipients == recipients
    assert load_config(tmp_path).identity_file == str(key), "or nothing stored could be read"
    (tmp_path / "config.yaml").unlink()
    assert cli.main(["init", "--advisor", "off"]) == 0, "and the command line's way back works too"
    assert key.read_text() == before and load_config(tmp_path).recipients == recipients


def test_a_kept_key_isn_t_replaced_by_another_recipient_or_when_damaged(
    tmp_path, monkeypatch, capsys
):
    from pyrage import x25519

    from checker import cli

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    key = tmp_path / "keys" / "evidence-identity.txt"
    key.parent.mkdir(parents=True)
    key.write_text("not a key")
    assert cli.main(["init", "--advisor", "off"]) == 1
    assert key.read_text() == "not a key"
    key.write_text("AGE-SECRET-KEY-NOTAKEY")
    assert cli.main(["init", "--advisor", "off"]) == 1
    assert "can't be read" in capsys.readouterr().err
    assert key.read_text() == "AGE-SECRET-KEY-NOTAKEY"
    key.write_text("not a key")
    other = str(x25519.Identity.generate().to_public())
    assert cli.main(["init", "--advisor", "off", "--recipient", other]) == 1
    assert key.read_text() == "not a key" and not (tmp_path / "config.yaml").exists()


def test_a_dangling_key_link_is_never_written_through(tmp_path, monkeypatch):
    from checker import cli

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    key = tmp_path / "keys" / "evidence-identity.txt"
    key.parent.mkdir(parents=True)
    key.symlink_to(tmp_path / "elsewhere")
    assert cli.main(["init", "--advisor", "off"]) == 1
    assert key.is_symlink() and not (tmp_path / "elsewhere").exists()


def test_a_relative_home_sets_nothing_up(tmp_path, monkeypatch):
    from checker import cli
    from checker.web import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CHECKER_HOME", "rel")
    monkeypatch.setattr(app, "serve", lambda *args: 0)
    assert cli.main(["web"]) == 1
    assert not (tmp_path / "rel").exists()


def test_a_dangling_settings_link_isn_t_a_first_start(tmp_path, monkeypatch, capsys):
    from checker import cli
    from checker.web import app

    tmp_path.joinpath("config.yaml").symlink_to(tmp_path / "gone.yaml")
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    monkeypatch.setattr(app, "serve", lambda *args: 0)
    assert cli.main(["web"]) == 1
    assert not (tmp_path / "keys").exists()


def test_a_mistyped_home_or_a_refused_address_sets_nothing_up(tmp_path, monkeypatch):
    from checker import cli
    from checker.web import app

    monkeypatch.setattr(app, "serve", lambda *args: 0)
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path / "ty" / "po" / "home"))
    assert cli.main(["web"]) == 1
    assert not (tmp_path / "ty").exists()
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path / "fresh"))
    assert cli.main(["web", "--bind", "0.0.0.0:8088"]) == 2
    assert not (tmp_path / "fresh").exists()


def setup_page(client):
    response = client.get("/first-setup")
    assert response.status_code == 200
    return said(response)


def test_first_setup_goes_step_by_step_from_what_s_really_there(web, inventory):
    client, home = signed_in(web)
    inventory()
    text = setup_page(client)
    assert "evidence-identity.txt" in text and "I've backed it up" in text
    assert text.count("(done)") == 0
    assert "Your stored evidence can't be read without its key" in said(client.get("/"))
    assert client.post("/first-setup/key-saved", {"a": "b"}).status_code == 302
    assert setup_page(client).count("(done)") == 1
    assert "Your stored evidence can't be read" not in said(client.get("/"))
    import yaml

    from checker.inventory import home as checker_home
    from checker.settings import config_version  # noqa: F401

    path = checker_home() / "config.yaml"
    data = yaml.safe_load(path.read_text())
    data["recipients"] = ["age1" + "q" * 58]
    path.write_text(yaml.safe_dump(data))
    assert setup_page(client).count("(done)") == 0, "a confirmation is about one key"
    assert "Your stored evidence can't be read" in said(client.get("/"))
    assert records_of("said the evidence key is backed up")[-1].who == "jo"


def test_the_first_choices_are_confirmed_and_are_the_real_settings(web, inventory):
    client, _ = signed_in(web)
    reader = _FormReader("/first-setup/choices")
    reader.feed(client.get("/first-setup").content.decode())
    form = {**reader.fields, "web_access_logs": "on", "confirm_password": PASSWORD}
    assert set(reader.fields) >= {"home_text", "web_access_logs", "advisor.enabled", "version"}
    assert (
        client.post("/first-setup/choices", {**form, "confirm_password": "no"}).status_code == 403
    )
    assert config_now().web_access_logs is False
    assert client.post("/first-setup/choices", form).status_code == 302
    assert config_now().web_access_logs is True
    assert history_now()[-1]["setting"] == "web_access_logs"
    assert "Save these choices" not in setup_page(client)


def test_a_first_choice_that_s_wrong_says_so_and_changes_nothing(web, inventory):
    client, _ = signed_in(web)
    reader = _FormReader("/first-setup/choices")
    reader.feed(client.get("/first-setup").content.decode())
    form = {**reader.fields, "home_text": "everything", "confirm_password": PASSWORD}
    response = client.post("/first-setup/choices", form)
    assert response.status_code == 400 and "choose one" in said(response)
    assert config_now().home_text == "off"
    forged = {**reader.fields, "notify_command": "/bin/evil", "confirm_password": PASSWORD}
    assert client.post("/first-setup/choices", forged).status_code == 302
    assert config_now().notify_command is None


def key_file_of(home):
    return home[0] / "keys" / "scanner_ed25519"


def test_this_machine_s_key_is_confirmed_private_and_never_replaced(web, inventory):
    client, home = signed_in(web)
    form = {"confirm_password": PASSWORD}
    assert client.post("/first-setup/make-key", {"confirm_password": "no"}).status_code == 403
    assert not key_file_of(home).exists()
    assert client.post("/first-setup/make-key", form).status_code == 302
    path = key_file_of(home)
    assert path.stat().st_mode & 0o777 == 0o600
    key = asyncssh.read_private_key(path)
    fingerprint = key.get_fingerprint("sha256")
    assert records_of("made this machine's SSH key")[-1].detail == fingerprint
    text = setup_page(client)
    assert "PRIVATE KEY" not in text and "act as an administrator" in text
    again = client.post("/first-setup/make-key", form)
    assert again.status_code == 400 and "replacing it would lock" in said(again)
    assert asyncssh.read_private_key(path).get_fingerprint("sha256") == fingerprint


def test_the_add_form_starts_with_this_machine_s_key(web, inventory):
    client, home = signed_in(web)
    assert 'value="scanner"' not in client.get("/manage/add").content.decode()
    client.post("/first-setup/make-key", {"confirm_password": PASSWORD})
    text = client.get("/manage/add").content.decode()
    assert 'value="scanner"' in text and str(key_file_of(home)) in text


def prepared(client, host="web01", **query):
    response = client.get("/manage/server/prepare", {"host": host, **query})
    assert response.status_code == 200
    return said(response)


@pytest.fixture
def keyed(web, unconfirmed):
    """A signed-in browser, and a server that logs in with this machine's key."""
    from checker.inventory import Host

    client, home = signed_in(web)
    client.post("/first-setup/make-key", {"confirm_password": PASSWORD})
    unconfirmed(
        Host(
            name="web01",
            address="192.0.2.1",
            user="scanner",
            auth="key",
            key_path=str(key_file_of(home)),
        )
    )
    return client, home


def test_the_commands_are_filled_in_with_the_real_key_and_nothing_private(keyed):
    client, home = keyed
    text = prepared(client, **{"from": "203.0.113.10"})
    public = " ".join((home[0] / "keys" / "scanner_ed25519.pub").read_text().split()[:2])
    assert public in text, "whole, not cut by the page's filter"
    assert 'from="203.0.113.10"' in text
    assert 'command="sudo -n -- python3 -I -B -"' in text
    assert "scanner ALL=(root) NOPASSWD: /usr/bin/python3 -I -B -" in text
    assert "sudo bash -eu" in text and "already exists" in text
    assert "/etc/sudoers.d/compromise-checker-scanner" in text
    assert "su -s /bin/sh scanner -c 'sudo -n -- python3 -I -B -'" in text, "proved, not assumed"
    assert "visudo useradd passwd getent su ssh-keygen" in text, "all checked before any change"
    assert "act as an administrator" in text
    assert "PRIVATE KEY" not in text


def test_the_command_is_what_the_transport_really_sends(keyed):
    """The forced command has to match, or the key would run something else."""
    from checker.inventory import load_inventory
    from checker.transport import remote_command

    client, _ = keyed
    host = load_inventory().get("web01")
    assert f'command="{remote_command(host)}"' in prepared(client)


@pytest.mark.parametrize(
    "typed",
    ["not an address", "1.2.3.4\"; rm -rf /", '1.1.1.1",command="evil', "10.1.2.3/24",
     "::ffff:1.2.3.4"],
)  # fmt: skip
def test_a_bad_address_goes_nowhere_near_the_commands(keyed, typed):
    client, _ = keyed
    text = prepared(client, **{"from": typed})
    assert "That isn't one IP address" in text and "On the server" not in text
    assert "useradd" not in text, "not commands with no limit, under the error"


def test_with_no_address_it_says_the_key_isn_t_limited(keyed):
    client, _ = keyed
    text = prepared(client)
    assert "don't limit where the key" in text and "from=" not in text


@pytest.mark.parametrize(
    ("changes", "words"),
    [
        ({"sudo": "root"}, "log in as root"),
        ({"sudo": "password"}, "sudo with a password"),
        ({"user": "DOMAIN\\\\jo"}, "can't use the account name"),
        ({"user": "root"}, "can't use the account name"),
        ({"python": "../../bin/sh"}, "can't use the Python"),
        ({"python": "bin/python3"}, "can't use the Python"),
        ({"auth": "password", "key_path": None}, "logs in with a password"),
        ({"auth": "agent", "key_path": None}, "SSH agent"),
        ({"key_path": "/nonexistent/key"}, "can't read one"),
    ],
)
def test_what_these_commands_don_t_suit_says_so_instead(keyed, unconfirmed, changes, words):
    from checker.inventory import Host

    client, home = keyed
    fields = {"name": "web01", "address": "192.0.2.1", "user": "scanner", "auth": "key",
              "key_path": str(key_file_of(home)), **changes}  # fmt: skip
    unconfirmed(Host(**fields))
    text = prepared(client)
    assert words in text and "useradd" not in text


def test_the_prepare_page_is_for_listed_servers_and_contacts_nothing(keyed, monkeypatch):
    from checker.web import manage

    def must_not(host):
        raise AssertionError("contacted a server")

    monkeypatch.setattr(manage, "fetch_host_key", must_not)
    client, _ = keyed
    assert client.get("/manage/server/prepare", {"host": "nope"}).status_code == 404
    assert client.get("/manage/server/prepare", {"host": "web01"}).status_code == 200


def test_a_server_s_words_can_t_steer_what_a_failed_check_advises():
    from checker.web.first_setup import what_to_try

    hostile = (
        "checker: web01: not collected: web01: sudo refused: login refused host key cannot connect"
    )
    assert len(what_to_try([hostile])) == 1 and "administrator" in what_to_try([hostile])[0]
    assert what_to_try(["web01 login refused, said a server"]) == []
    assert "no passphrase" in what_to_try(["checker: web01: cannot read key /k: encrypted"])[0]


def test_the_fleet_survives_a_settings_file_the_reminder_can_t_read(web, inventory, monkeypatch):
    from checker.web import first_setup

    def broken(base):
        raise IndexError("no recipients")

    client, _ = signed_in(web)
    monkeypatch.setattr(first_setup, "key_unsaved", broken)
    assert client.get("/").status_code == 200


def test_first_setup_needs_a_login(web, inventory):
    client, _ = web
    assert client.get("/first-setup").status_code == 302
    assert client.get("/manage/server/prepare?host=web01").status_code == 302
    for path in ("key-saved", "choices", "make-key"):
        assert client.post(f"/first-setup/{path}", {"a": "b"}).status_code == 302
        assert client.get(f"/first-setup/{path}").status_code in (302, 405)


@pytest.mark.parametrize("typed", ["0.0.0.0/0", "::/0", "10.0.0.0/8"])
def test_a_range_too_wide_to_limit_anything_is_refused(keyed, typed):
    client, _ = keyed
    text = prepared(client, **{"from": typed})
    assert "too wide" in text and "useradd" not in text


def test_a_python_path_is_used_as_given_and_only_the_usual_gets_the_os_note(keyed, unconfirmed):
    from checker.inventory import Host

    client, home = keyed
    fields = {"name": "web01", "address": "192.0.2.1", "user": "scanner", "auth": "key",
              "key_path": str(key_file_of(home))}  # fmt: skip
    assert "as on RHEL 9 and 10" in prepared(client)
    unconfirmed(Host(**fields, python="/opt/py/bin/python3"))
    text = prepared(client)
    assert "NOPASSWD: /opt/py/bin/python3 -I -B -" in text and "as on RHEL 9" not in text
    assert 'command="sudo -n -- /opt/py/bin/python3 -I -B -"' in text


def check_step_done(home):
    from checker.web import first_setup

    return first_setup.progress(home[0])["done"]["check"]


def test_a_failed_collection_isn_t_a_first_server_checked(keyed):
    from test_snapshot import add_bundle

    client, home = keyed
    add_bundle(home, "e1", 10, [], status="empty")
    assert check_step_done(home) is False
    assert "Your first server is checked" not in setup_page(client)
    add_bundle(home, "c1", 20, CLEAN)
    assert check_step_done(home) is True


def test_a_bundle_of_a_server_no_longer_listed_doesn_t_count(keyed):
    from test_purge import add

    _, home = keyed
    add(home, "b1", 2, host="gone")
    assert check_step_done(home) is False


def test_a_key_that_can_t_be_read_keeps_the_key_step_open(web, unconfirmed):
    from checker.inventory import Host

    client, _ = signed_in(web)
    unconfirmed(Host(name="web01", address="192.0.2.1", user="s", auth="key", key_path="/none/key"))
    text = setup_page(client)
    assert "/first-setup/make-key" in client.get("/first-setup").content.decode()
    assert "already have their own way" not in text


def test_a_lost_evidence_key_is_said(web, inventory):
    from checker.inventory import home as checker_home

    client, _ = signed_in(web)
    client.post("/first-setup/key-saved", {"a": "b"})
    (checker_home() / "keys" / "evidence-identity.txt").rename(checker_home() / "moved.txt")
    text = setup_page(client)
    assert "isn't where it should be" in text and "nothing to do here" not in text
    (checker_home() / "moved.txt").rename(checker_home() / "keys" / "evidence-identity.txt")


def test_a_refused_choice_is_words_even_with_damaged_files(web, inventory):
    from checker.inventory import hosts_file

    client, _ = signed_in(web)
    reader = _FormReader("/first-setup/choices")
    reader.feed(client.get("/first-setup").content.decode())
    hosts_file().write_text("hosts: [not: right\n")
    form = {**reader.fields, "home_text": "everything", "confirm_password": PASSWORD}
    assert client.post("/first-setup/choices", form).status_code == 400


def test_a_folder_at_the_key_s_path_is_refused_and_two_makes_give_one_key(web, inventory):
    client, home = signed_in(web)
    path = key_file_of(home)
    path.mkdir(parents=True)
    response = client.post("/first-setup/make-key", {"confirm_password": PASSWORD})
    assert response.status_code == 400 and "already" in said(response)
    path.rmdir()


@pytest.mark.parametrize(
    ("line", "words"),
    [
        (
            "checker: web01: not collected (empty): web01: login refused for scanner",
            "refused this machine's login",
        ),
        (
            "checker: web01: not collected (empty): web01: sudo refused: a password is required",
            "couldn't act as an administrator",
        ),
        (
            "checker: web01: not collected (empty): web01: cannot connect: Connection lost",
            "couldn't reach the server",
        ),
    ],
)
def test_a_failed_check_says_what_to_look_at(web, inventory, line, words, monkeypatch):
    from django.utils import timezone

    from checker.web import runs
    from checker.web.models import CheckRun

    client, _ = signed_in(web)
    run = CheckRun.objects.create(
        kind="check", hosts=json.dumps(["web01"]), who="jo", address="", started_at=timezone.now()
    )
    monkeypatch.setattr(runs, "output_lines", lambda run_id: [line])
    text = said(client.get(f"/checks/{run.id}"))
    assert words in text and "/manage/server/prepare?host=web01" in text
