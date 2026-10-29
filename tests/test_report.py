"""The HTML report (PR 1.8): confidential, self-contained, and safe with
whatever text a host sent."""

import json
import re

from test_snapshot import add_bundle, host_records, rec

from checker import cli
from checker.evidence import seal_text
from checker.report import visible, write_report

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
    html = path.read_text()
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
    html = write_report(store, ["web01"], identity, config.recipients, base / "reports").read_text()
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
    assert "2-hosts" in written and "confidential" in out
    target = base / "mine.html"
    assert cli.main(["report", "web01", "--output", str(target)]) == 0
    assert target.exists() and "web01" in target.read_text()
    assert cli.main(["report", "nowhere"]) == 1


def test_an_existing_output_file_becomes_owner_only(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    target = base / "shared.html"
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
    target = base / "r.html"
    target.write_text("previous report")
    write_report(store, ["web01"], identity, config.recipients, base / "reports", output=target)
    html = target.read_text()
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
    link = base / "out.html"
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
    assert "AI advisor: off." in off.read_text()
    on = write_report(
        store, ["web01"], identity, config.recipients, base / "reports", advisor_enabled=True
    )
    assert "AI advisor: off." not in on.read_text()
