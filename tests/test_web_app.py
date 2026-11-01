"""The web interface's server (PR 5.2): accounts, one-time setup, throttling, headers,
and host text that can do nothing in a logged-in browser."""

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


def test_looking_at_the_page_leaves_the_evidence_store_alone(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    db = home[0] / "checker.db"
    before = db.read_bytes(), db.stat().st_mtime_ns
    assert client.get("/").status_code == 200
    assert (db.read_bytes(), db.stat().st_mtime_ns) == before
    assert not (home[0] / "packs" / "state.json").exists()


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
    assert "Add your first server" in client.get("/").content.decode()


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
    from checker.inventory import Host, Inventory, hosts_file, save_inventory

    saved = []

    def write(*hosts):
        saved[:] = hosts
        save_inventory(Inventory(hosts=list(hosts)), hosts_file())

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
    assert "checker hosts add" in client.get("/checks/new").content.decode()


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
        assert process.wait(30) == schedule_exit_failed()
    assert "stopped" in process.stdout.read()
    found = [p for p in tmp_path.rglob("*.age") if "db01" in p.name and "report" not in p.name]
    assert found  # it left its evidence, so it must be able to find it
    purge = subprocess.run(
        [sys.executable, "-m", "checker", "purge", "db01", "--yes"],
        env=env, capture_output=True, text=True,
    )  # fmt: skip
    assert purge.returncode == 0, purge.stderr
    assert not [p for p in found if p.exists()]


def schedule_exit_failed():
    from checker.schedule import EXIT_FAILED

    return EXIT_FAILED


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
