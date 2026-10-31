"""The web interface's server (PR 5.2): accounts, one-time setup, throttling, headers,
and host text that can do nothing in a logged-in browser."""

import re
import tempfile
import unicodedata
from datetime import timedelta
from io import BytesIO
from pathlib import Path
from urllib.parse import urlencode

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


@pytest.fixture
def web(_django, home):
    """A clean accounts database, and a browser that checks CSRF as a real one must."""
    from django.contrib.auth import get_user_model
    from django.contrib.sessions.models import Session

    from checker.web.models import LoginAttempt, SetupToken

    for model in (get_user_model(), Session, LoginAttempt, SetupToken):
        model.objects.all().delete()
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
    from checker.web.views import client_address

    settings_override(CHECKER_BEHIND_PROXY=True)
    assert client_address(request_from("127.0.0.1", "198.51.100.9")) == "198.51.100.9"
    # What a client sends itself comes first, so it can't choose its own bucket.
    assert client_address(request_from("127.0.0.1", "1.1.1.1, 198.51.100.9")) == "198.51.100.9"
    assert client_address(request_from("127.0.0.1")) == "127.0.0.1"
    # Not from the proxy: the header is the sender's own.
    assert client_address(request_from("203.0.113.5", "198.51.100.9")) == "203.0.113.5"


def test_without_a_proxy_a_forwarded_header_means_nothing(web, settings_override):
    from checker.web.views import client_address

    settings_override(CHECKER_BEHIND_PROXY=False)
    assert client_address(request_from("127.0.0.1", "198.51.100.9")) == "127.0.0.1"


def test_ipv6_counts_by_network(web, settings_override):
    from checker.web.views import client_address

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
    assert "checker[web]" in capsys.readouterr().err


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
