"""The web interface's server (PR 5.2): accounts, one-time setup, throttling, headers,
and host text that can do nothing in a logged-in browser."""

import re
import tempfile
from datetime import timedelta
from pathlib import Path

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


@pytest.fixture(scope="session")
def _django():
    home = Path(tempfile.mkdtemp())
    web_app.configure(home)
    from django.test.utils import setup_test_environment

    setup_test_environment()  # adds "testserver" to ALLOWED_HOSTS
    return home


@pytest.fixture
def web(_django, home):
    """A clean accounts database, and a browser that checks CSRF as a real one must."""
    from django.contrib.auth import get_user_model
    from django.contrib.sessions.models import Session
    from django.test import Client

    from checker.web.models import LoginAttempt, SetupToken

    for model in (get_user_model(), Session, LoginAttempt, SetupToken):
        model.objects.all().delete()
    return Client(raise_request_exception=False), home


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


@pytest.mark.parametrize("bind", ["0.0.0.0:8088", "192.0.2.1:443", "example.com:443"])  # noqa: S104
def test_another_machine_is_refused_without_tls(bind):
    assert "unencrypted" in web_app.listen_problem(bind, None, False)
    assert web_app.listen_problem(bind, None, True) is None


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
    client.post("/logout")
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
    from django.test import Client

    account()
    browser = Client(enforce_csrf_checks=True, raise_request_exception=False)
    token = token_from(browser.get("/login"))
    data = {"username": "jo", "password": PASSWORD, "csrfmiddlewaretoken": token}
    assert browser.post("/login", data).status_code == 302
    page = browser.get("/")
    assert page.status_code == 200
    out = browser.post("/logout", {"csrfmiddlewaretoken": token_from(page)})
    assert out.status_code == 302 and browser.get("/").status_code == 302


def test_a_browser_can_create_the_first_account_with_real_csrf_checks(web):
    from django.test import Client

    from checker.web.accounts import setup_link

    browser = Client(enforce_csrf_checks=True, raise_request_exception=False)
    path = f"/setup/{link_token(setup_link('http://x'))}"
    data = {
        "csrfmiddlewaretoken": token_from(browser.get(path)),
        "username": "jo",
        "password": PASSWORD,
        "password2": PASSWORD,
    }
    assert browser.post(path, data).status_code == 302 and browser.get("/").status_code == 200


def test_a_form_without_its_csrf_token_is_refused(web):
    from django.test import Client

    _, _home = web
    account()
    strict = Client(enforce_csrf_checks=True, raise_request_exception=False)
    assert strict.post("/login", {"username": "jo", "password": PASSWORD}).status_code == 403
    assert strict.get("/").status_code == 302


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
    assert response["Referrer-Policy"] == "no-referrer"


def test_pages_load_nothing_from_elsewhere_and_have_no_inline_script(web):
    client, home = signed_in(web)
    analysed(home, "b1", 10, ROOTED)
    for path in ("/", "/login"):
        text = client.get(path).content.decode()
        assert "<script" not in text and " style=" not in text
        assert not re.search(r'(?:src|href)="(?:https?:)?//', text)


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
    assert text.index("<h2>rooted") < text.index("<h2>clean")
    assert "estimate, not proof" in text


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
