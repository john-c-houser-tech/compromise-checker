"""The HTML report (PR 1.8): confidential, self-contained, and safe with
whatever text a host sent."""

import json
import re
import tempfile
import threading
import time
from pathlib import Path

import pytest
from test_snapshot import add_bundle, host_records, rec

from checker import cli
from checker.evidence import EvidenceError, seal_text
from checker.report import read_report, visible, write_report

HOSTILE = "<script>alert(1)</script>evil\u202egnp.exe"


def records_with_hostile_names():
    return host_records(
        accounts=(("root", 0), ("jch", 1000), ("toor", 0)),
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
            ),
        ],
    )


def test_visible_shows_invisible_characters():
    assert visible("a\u202eb\x1bc\u200bd") == "a\\u202eb\\u001bc\\u200bd"
    assert visible("x" * 10, 4) == "xxxx…"
    assert visible({"k": 1}) == '{"k": 1}'


def test_the_report_is_confidential_self_contained_and_escaped(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "b2", 10, records_with_hostile_names())
    path = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    html = read_report(path, identity)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct(path.parent.stat().st_mode & 0o777) == "0o700"
    assert "CONFIDENTIAL" in html and "probability is an estimate" in html
    assert "default-src 'none'" in html
    # Nothing loaded from anywhere: no script, no remote URL.
    assert "<script" not in html
    assert not re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:|//)""", html)
    # The host's text is escaped and its invisible characters shown.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;evil\\u202egnp.exe" in html
    assert "\u202e" not in html
    # The findings, coverage and custody are there.
    assert "An account other than root has UID 0" in html
    assert "A program in a scratch directory" in html
    assert "Chain of custody" in html and "analysed" in html
    actions = [r["action"] for r in store.custody_of("b2")]
    assert actions[-1] == "reported"


def test_change_evidence_shows_before_and_after(home):
    base, store, identity, config = home

    def service(shell):
        return rec(
            "accounts",
            "account",
            name="www-data",
            uid=33,
            gid=33,
            home="/var/www",
            shell=shell,
            password="shadowed",
            line=9,
        )

    add_bundle(home, "b1", 0, host_records(extra=[service("/usr/sbin/nologin")]))
    add_bundle(
        home,
        "b2",
        10,
        host_records(
            sudoers="root ALL=(ALL) ALL\neve ALL=(ALL) NOPASSWD: ALL\n",
            extra=[service("/bin/bash")],
        ),
    )
    html = read_report(
        write_report(store, ["web01"], identity, config.recipients, base / "reports"), identity
    )
    assert "added: /etc/sudoers: eve ALL=(ALL) NOPASSWD: ALL" in html
    assert "changed: www-data: shell: /usr/sbin/nologin → /bin/bash" in html


def test_a_stale_assessment_is_redone(home, monkeypatch):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    assert cli.main(["analyze", "web01"]) == 0
    before = len(store.assessments("b1"))
    import checker.report

    monkeypatch.setattr(checker.report, "CHECKS_VERSION", 999)
    write_report(store, ["web01"], identity, config.recipients, base / "reports")
    assert len(store.assessments("b1")) == before + 1


def test_cli_report(home, capsys):
    base = home[0]
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "d1", 0, host_records(), host="db01")
    assert cli.main(["report", "--all"]) == 0
    out = capsys.readouterr().out
    written = re.search(r"Report written to (\S+)", out).group(1)
    assert "2-hosts" in written and written.endswith(".html.age")
    assert f"To read it: checker report --open {written}" in out
    target = base / "mine.html"
    assert cli.main(["report", "web01", "--output", str(target)]) == 1  # not .age: refused
    assert "ends in .html.age" in capsys.readouterr().err
    assert cli.main(["report", "web01", "--output", str(target), "--plain"]) == 0
    assert "web01" in target.read_text() and "not encrypted" in capsys.readouterr().out
    assert cli.main(["report", "nowhere"]) == 1


def test_an_existing_output_file_becomes_owner_only(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    target = base / "shared.html.age"
    target.write_text("old")
    target.chmod(0o644)
    write_report(store, ["web01"], identity, config.recipients, base / "reports", output=target)
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_visible_escapes_everything_that_hides_or_disguises():
    hidden = "r\u0338o\ufe0fo\u3164t\u00a0x\u2800y\U000e0080z"
    assert visible(hidden) == ("r\\u0338o\\ufe0fo\\u3164t\\u00a0x\\u2800y\\U000e0080z")
    # A host can't fake an escape: its own backslash is doubled.
    assert visible("evil\\u202egnp.exe") == "evil\\\\u202egnp.exe"
    # Cut on whole escapes, the limit counting what is shown.
    cut = visible("x" * 297 + "\u202e" * 5)
    assert cut == "x" * 297 + "…" and len(visible("\u202e" * 100, 30)) <= 31


def test_a_lone_surrogate_from_a_host_cannot_break_the_report(home):
    base, store, identity, config = home
    manifest = {"modules_planned": ["accounts", "a\ud800\u202e"], "masking_version": "\u202e6"}
    summary = seal_text(json.dumps({"manifest": manifest}), config.recipients)
    add_bundle(home, "b1", 0, host_records(), summary=summary)
    target = base / "r.html.age"
    target.write_text("previous report")
    write_report(store, ["web01"], identity, config.recipients, base / "reports", output=target)
    html = read_report(target, identity)
    assert "a\\ud800\\u202e" in html and "\\u202e6" in html and "\u202e" not in html


def test_a_bundle_must_be_the_hosts_and_usable(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "d1", 0, host_records(), host="db01")
    assert cli.main(["analyze", "db01"]) == 0
    import pytest

    from checker.evidence import EvidenceError

    with pytest.raises(EvidenceError, match="from db01"):
        write_report(store, ["web01"], identity, config.recipients, base / "reports", "d1")
    assert [r["action"] for r in store.custody_of("d1")][-1] != "reported"


def test_the_output_is_replaced_not_followed(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    victim = base / "victim.txt"
    victim.write_text("keep me")
    victim.chmod(0o644)
    link = base / "out.html.age"
    link.symlink_to(victim)
    write_report(store, ["web01"], identity, config.recipients, base / "reports", output=link)
    assert victim.read_text() == "keep me" and oct(victim.stat().st_mode & 0o777) == "0o644"
    assert not link.is_symlink() and oct(link.stat().st_mode & 0o777) == "0o600"
    loose = base / "reports"
    loose.mkdir(mode=0o755)
    loose.chmod(0o755)
    write_report(store, ["web01"], identity, config.recipients, loose)
    assert oct(loose.stat().st_mode & 0o777) == "0o700"


def test_an_assessment_from_an_older_parser_is_redone(home, monkeypatch):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    assert cli.main(["analyze", "web01"]) == 0
    import checker.report

    versions = checker.report.current_versions()
    monkeypatch.setattr(checker.report, "current_versions", lambda: dict(versions, parser=99))
    before = len(store.assessments("b1"))
    write_report(store, ["web01"], identity, config.recipients, base / "reports")
    assert len(store.assessments("b1")) == before + 1


def test_cli_report_into_a_missing_directory(home, capsys):
    add_bundle(home, "b1", 0, host_records())
    assert cli.main(["report", "web01", "--output", str(home[0] / "no" / "such" / "r.html")]) == 1
    assert "checker:" in capsys.readouterr().err


def test_the_report_says_when_the_advisor_is_off(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    off = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    assert "AI advisor: off." in read_report(off, identity)
    on = write_report(
        store, ["web01"], identity, config.recipients, base / "reports", advisor_enabled=True
    )
    assert "AI advisor: off." not in read_report(on, identity)


# --- Encrypted at rest -------------------------------------------------------------------


def test_a_report_is_encrypted_to_the_evidence_key(home):
    import hashlib

    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    path = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    data = path.read_bytes()
    assert path.name.endswith(".html.age") and data.startswith(b"age-encryption.org/")
    assert b"web01" not in data and "web01" in read_report(path, identity)
    entry = json.loads(store.custody_of("b1")[-1]["detail"])
    assert entry == {"report_sha256": hashlib.sha256(data).hexdigest(), "encrypted": True}


def test_a_report_for_another_key_cant_be_read(home):
    import pytest
    from pyrage import x25519

    from checker.evidence import EvidenceError

    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    path = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    with pytest.raises(EvidenceError, match="cannot decrypt"):
        read_report(path, x25519.Identity.generate())


def fetch(url, host=None):
    """A request to the viewer, past any proxy: (status, headers, body)."""
    import urllib.error
    import urllib.request

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"Host": host} if host else {})  # noqa: S310
    try:
        with opener.open(request, timeout=5) as answer:
            return answer.status, dict(answer.headers), answer.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {}, ""


def test_a_report_is_shown_from_memory_and_only_at_its_address(home, tmp_path, monkeypatch):
    from checker.report import CSP, view

    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    path = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    before = {p for p in Path(tempfile.gettempdir()).iterdir()}
    threads = threading.active_count()
    seen = {}

    def browser(url):
        seen["url"] = url
        seen["page"] = fetch(url)
        port = url.split(":")[2].split("/")[0]
        seen["elsewhere"] = fetch(f"http://127.0.0.1:{port}/report.html")[0]
        seen["rebound"] = fetch(url, host=f"evil.example:{port}")[0]
        return True

    said = []
    view(path, identity, browser=browser, ask=lambda q: "", say=said.append, screen=True)
    status, headers, page = seen["page"]
    assert status == 200 and "web01" in page
    assert headers["Cache-Control"] == "no-store" and headers["Content-Security-Policy"] == CSP
    assert seen["elsewhere"] == 404 and seen["rebound"] == 404  # a guess, or DNS rebinding
    assert seen["url"].startswith("http://127.0.0.1:") and len(seen["url"].split("/")[3]) >= 40
    assert "nothing is written in plain" in said[0]
    with pytest.raises(OSError):
        fetch(seen["url"])  # stopped with Enter
    assert {p for p in Path(tempfile.gettempdir()).iterdir()} - before == set()
    for _ in range(50):  # the server's thread ends with it
        if threading.active_count() == threads:
            break
        time.sleep(0.02)
    assert threading.active_count() == threads


def test_with_no_screen_it_says_how_to_reach_it(home):
    from checker.report import view

    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    path = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    said, pages = [], []

    def ask(question):
        url = said[0].split(" at ")[1].split("\n")[0]
        pages.append(fetch(url)[2])
        return ""

    def no_browser(url):
        raise AssertionError("no browser is started with no screen")

    view(path, identity, browser=no_browser, ask=ask, say=said.append, screen=False)
    assert "ssh -L " in said[0] and "web01" in pages[0]


def test_with_no_terminal_it_is_shown_for_a_while(home):
    from checker.report import NO_TERMINAL_SECONDS, view

    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    path = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    waited = []

    def no_terminal(question):
        raise EOFError

    view(path, identity, browser=lambda url: True, ask=no_terminal, wait=waited.append,
         say=lambda line: None, screen=True)  # fmt: skip
    assert waited == [NO_TERMINAL_SECONDS]


def test_a_text_browser_isnt_started():
    import webbrowser

    from checker import report

    class Text(webbrowser.GenericBrowser):
        def open(self, url, new=0, autoraise=True):
            raise AssertionError("a text browser would take the terminal")

    original = webbrowser.get
    webbrowser.get = lambda: Text("lynx")
    try:
        assert report._launch("http://127.0.0.1:1/x") is False
    finally:
        webbrowser.get = original


def test_a_screen_is_a_display_or_a_mac_not_over_ssh():
    from checker.report import has_screen

    assert has_screen({"DISPLAY": ":0"}, "linux") and has_screen({"WAYLAND_DISPLAY": "w"}, "linux")
    assert not has_screen({}, "linux")
    assert has_screen({}, "darwin") and not has_screen({"SSH_CONNECTION": "x"}, "darwin")


def test_the_newest_report_is_found_by_time_then_name(home):
    import os

    from checker.report import latest_report

    folder = home[0] / "reports"
    folder.mkdir()
    for name in ("report-a-20261030T010000Z.html", "report-a-20261030T020000Z.html.age",
                 ".report-x.tmp", "notes.html"):  # fmt: skip
        (folder / name).write_text("x")
        os.utime(folder / name, (1000, 1000))
    (folder / "report-z-link.html.age").symlink_to(folder / "notes.html")
    assert latest_report(folder).name == "report-a-20261030T020000Z.html.age"
    from checker.report import _newest

    older, newer = (
        folder / "report-a-20261030T010000Z.html",
        folder / "report-a-20261030T020000Z.html.age",
    )
    assert _newest([older, newer]) == newer == _newest([newer, older])  # same second: by name


def test_output_names_say_what_they_hold(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    with pytest.raises(EvidenceError, match=r"ends in \.html\.age"):
        write_report(store, ["web01"], identity, config.recipients, base, output=base / "r.age")
    with pytest.raises(EvidenceError, match="can't end in .age"):
        write_report(store, ["web01"], identity, config.recipients, base,
                     output=base / "r.html.age", plain=True)  # fmt: skip


def test_open_from_the_command_line(home, monkeypatch, capsys):
    from checker import report

    base, store, identity, config = home
    assert cli.main(["report", "--open"]) == 1
    assert "no report yet" in capsys.readouterr().err
    add_bundle(home, "b1", 0, host_records())
    assert cli.main(["report", "web01"]) == 0
    shown = []
    monkeypatch.setattr(report, "view", lambda path, key, **kw: shown.append((path, key)))
    assert cli.main(["report", "--open"]) == 0
    assert shown[0][0].name.endswith(".html.age") and shown[0][1] is not None
    assert cli.main(["report", "--open", "--plain"]) == 2
    assert cli.main(["report", "--open", str(base / "checker.db")]) == 1
    assert "not a report" in capsys.readouterr().err
    assert cli.main(["report", "--open", "web01.html"]) == 1
    assert "checker report HOST" in capsys.readouterr().err
    plain = base / "p.html"
    assert cli.main(["report", "web01", "--plain", "--output", str(plain)]) == 0
    monkeypatch.setattr("checker.cli._identity", lambda *a: pytest.fail("no key for plain"))
    assert cli.main(["report", "--open", str(plain)]) == 0
    assert shown[-1] == (plain, None)

    def interrupted(path, key, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(report, "view", interrupted)
    assert cli.main(["report", "--open", str(plain)]) == 130


def report_args(home, **extra):
    base, store, identity, config = home
    return (store, ["web01"], identity, config.recipients, base / "reports"), extra


def test_a_pdf_report_is_a_pdf_encrypted_unless_plain(home):
    pytest.importorskip("weasyprint")
    add_bundle(home, "b1", 10, host_records())
    args, _ = report_args(home)
    path = write_report(*args, kind="pdf")
    assert path.name.endswith(".pdf.age") and not path.read_bytes().startswith(b"%PDF")
    plain = write_report(*args, kind="pdf", plain=True)
    assert plain.name.endswith(".pdf") and plain.read_bytes().startswith(b"%PDF")
    assert plain.stat().st_mode & 0o077 == 0
    custody = home[1].custody_of("b1")
    assert sum(1 for c in custody if c["action"] == "reported") == 2


def test_a_pdf_fetches_nothing_even_if_its_html_asks(tmp_path, monkeypatch):
    pytest.importorskip("weasyprint")
    from weasyprint.urls import URLFetcher

    from checker.report import pdf_from_html

    fetched = []
    real = URLFetcher.__call__

    def spy(self, url):
        fetched.append(url)
        return real(self, url)

    monkeypatch.setattr(URLFetcher, "__call__", spy)
    secret = tmp_path / "secret.png"
    secret.write_bytes(b"not for the report")
    data = pdf_from_html(
        f'<img src="{secret.as_uri()}"><img src="https://evil.example/x.png">'
        '<link rel=stylesheet href="https://evil.example/x.css">'
    )
    assert data.startswith(b"%PDF") and b"not for the report" not in data
    assert fetched  # asked, and refused


def test_a_pdf_with_hostile_text_is_still_a_pdf(home):
    pytest.importorskip("weasyprint")
    add_bundle(home, "b1", 10, records_with_hostile_names())
    args, _ = report_args(home)
    assert write_report(*args, kind="pdf", plain=True).read_bytes().startswith(b"%PDF")


def test_pdf_output_names_are_checked(home):
    args, _ = report_args(home)
    with pytest.raises(EvidenceError, match=r"\.pdf\.age"):
        write_report(*args, output=home[0] / "x.html.age", kind="pdf")


def test_the_command_writes_a_pdf_and_open_refuses_the_format(home, capsys):
    pytest.importorskip("weasyprint")
    add_bundle(home, "b1", 10, host_records())
    assert cli.main(["report", "web01", "--format", "pdf"]) == 0
    assert "age -d" in capsys.readouterr().out
    assert cli.main(["report", "--open", "--format", "pdf"]) == 2
    capsys.readouterr()


def test_without_the_pdf_extra_it_says_what_to_install(monkeypatch):
    import sys

    from checker.report import pdf_from_html

    monkeypatch.setitem(sys.modules, "weasyprint", None)
    with pytest.raises(EvidenceError, match="checker\\[pdf\\]"):
        pdf_from_html("<p>x</p>")
