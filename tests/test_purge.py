"""Purge and retention (PR 2.0, policy §8): the one sanctioned way to delete
stored evidence, with a record of what went; automatic expiry keeps each
host's current baseline."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pyrage
import pytest
from pyrage import x25519
from test_snapshot import host_records, stream

from checker import cli
from checker.assess import analyze
from checker.baseline import accept, changes, current_baseline
from checker.inventory import Host, inventory_transaction
from checker.purge import execute, leftovers, parse_before, plan
from checker.report import write_report

NOW = datetime.now(UTC).replace(microsecond=0)


def add(home, name, days_ago, host="web01"):
    """A stored bundle collected `days_ago` days ago, filed where `collect`
    files it, with its sidecar."""
    base, store, _, config = home
    keys = [x25519.Recipient.from_str(r) for r in config.recipients]
    plain = stream(host_records())
    cipher = pyrage.encrypt(plain, keys)
    folder = base / "evidence" / host
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.age"
    path.write_bytes(cipher)
    path.with_suffix(".json").write_text("{}")
    started = (NOW - timedelta(days=days_ago)).isoformat()
    store.record_bundle(
        {
            "id": name,
            "host": host,
            "run_id": name,
            "path": str(path),
            "started_at": started,
            "ended_at": started,
            "status": "complete",
            "collector_version": "t",
            "collector_sha256": "x",
            "plaintext_sha256": hashlib.sha256(plain).hexdigest(),
            "plaintext_bytes": len(plain),
            "ciphertext_sha256": hashlib.sha256(cipher).hexdigest(),
            "ciphertext_bytes": len(cipher),
            "recipients": json.dumps(config.recipients),
            "session": None,
            "summary": None,
            "problem": None,
        }
    )
    return path


def analysed(home, host="web01"):
    """Analyse each of the host's bundles, oldest first, so each has events,
    a snapshot and an assessment on disk, and the first is the baseline."""
    _, store, identity, config = home
    for row in store.bundles(host):
        analyze(store, host, identity, config.recipients, row["id"])


def files_of(home, name, host="web01"):
    base = home[0]
    return sorted(p.name for p in (base / "evidence" / host).glob(f"{name}.*"))


def triggers(store):
    return {
        r[0] for r in store._db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    }


def rows(store, table, bundle_id):
    column = "id" if table == "bundles" else "bundle_id"
    query = f"SELECT COUNT(*) FROM {table} WHERE {column} = ?"  # noqa: S608 - test names
    return store._db.execute(query, (bundle_id,)).fetchone()[0]


TABLES = ("bundles", "custody", "derived", "baselines", "assessments")


# --- what goes, and the record of it -----------------------------------------------


def test_purging_a_host_removes_its_rows_and_files_and_records_only_identifiers(home):
    base, store, _, _ = home
    add(home, "b1", 30)
    add(home, "b2", 20)
    add(home, "other", 20, host="db01")
    analysed(home)
    assert len(files_of(home, "b1")) >= 5  # bundle, sidecar, events, snapshot, assessment
    before = triggers(store)

    chosen = plan(store, base, {"web01", "db01"}, 90, host="web01")
    assert [r["id"] for r in chosen.bundles] == ["b1", "b2"]
    assert chosen.baselines == {"web01": "emptied"}
    outcome = execute(store, base, chosen)

    assert outcome.failed == []
    for name in ("b1", "b2"):
        assert all(rows(store, table, name) == 0 for table in TABLES)
        assert files_of(home, name) == []
    assert not (base / "evidence" / "web01").exists()
    assert rows(store, "bundles", "other") == 1 and files_of(home, "other", "db01")
    assert triggers(store) == before
    (record,) = store.purges()
    assert json.loads(record["scope"])["host"] == "web01"
    assert json.loads(record["bundles"]) == [["b1", "web01"], ["b2", "web01"]]
    assert json.loads(record["counts"])["bundles"] == 2
    assert json.loads(record["baselines"]) == {"web01": "emptied"}


def test_append_only_holds_again_after_a_purge_and_purges_are_append_only(home):
    base, store, _, _ = home
    add(home, "b1", 30)
    add(home, "b2", 20)
    execute(store, base, plan(store, base, set(), 90, host="web01", before=NOW - timedelta(25)))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("DELETE FROM bundles")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("UPDATE custody SET action = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("DELETE FROM purges")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("UPDATE purges SET scope = '{}'")


def test_a_failed_purge_changes_nothing_and_leaves_the_triggers(home):
    base, store, _, _ = home
    add(home, "b1", 30)
    analysed(home)
    before = triggers(store)
    with pytest.raises(TypeError):
        store.purge(["b1"], {"bad": {1, 2}}, {})  # fails at the last step, the record
    assert triggers(store) == before
    assert all(rows(store, table, "b1") for table in ("bundles", "custody", "baselines"))
    assert store.purges() == []
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("DELETE FROM bundles")


def test_an_unknown_bundle_purges_nothing(home):
    _, store, _, _ = home
    add(home, "b1", 30)
    with pytest.raises(Exception, match="no bundle 'nope'"):
        store.purge(["b1", "nope"], {}, {})
    assert rows(store, "bundles", "b1") == 1


def test_before_takes_only_older_bundles_of_every_host(home):
    base, store, _, _ = home
    add(home, "old", 40)
    add(home, "new", 10)
    add(home, "db-old", 40, host="db01")
    chosen = plan(store, base, set(), 90, before=NOW - timedelta(days=30))
    assert sorted(r["id"] for r in chosen.bundles) == ["db-old", "old"]
    assert chosen.baselines == {"db01": "emptied"}


def test_parse_before():
    assert parse_before("2026-07-01") == datetime(2026, 7, 1, tzinfo=UTC)
    assert parse_before("2026-07-01T10:00:00+02:00").utcoffset() == timedelta(hours=2)
    with pytest.raises(ValueError, match="not a date"):
        parse_before("last tuesday")


def test_a_plan_needs_a_scope_and_expired_excludes_before(home):
    base, store, _, _ = home
    with pytest.raises(ValueError, match="say what"):
        plan(store, base, set(), 90)
    with pytest.raises(ValueError, match="can't be combined"):
        plan(store, base, set(), 90, before=NOW, expired=True)


# --- baselines -----------------------------------------------------------------------


def test_expiry_keeps_the_current_baseline_of_an_inventoried_host(home):
    base, store, identity, config = home
    add(home, "b1", 200)
    add(home, "b2", 150)
    add(home, "b3", 5)
    analysed(home)
    assert current_baseline(store, "web01")["bundle_id"] == "b1"

    chosen = plan(store, base, {"web01"}, 90, expired=True)
    assert [r["id"] for r in chosen.bundles] == ["b2"]
    assert [r["id"] for r in chosen.kept] == ["b1"]
    assert chosen.baselines == {}
    execute(store, base, chosen)
    assert current_baseline(store, "web01")["bundle_id"] == "b1"
    assert files_of(home, "b1") and not files_of(home, "b2")

    # Once a newer baseline is accepted, the old one expires as usual.
    accept(store, "web01", "Reviewed", identity, config.recipients, "b3")
    chosen = plan(store, base, {"web01"}, 90, expired=True)
    assert [r["id"] for r in chosen.bundles] == ["b1"] and chosen.kept == []
    execute(store, base, chosen)
    assert current_baseline(store, "web01")["bundle_id"] == "b3"


def test_expiry_takes_the_baseline_of_a_host_no_longer_in_the_inventory(home):
    base, store, _, _ = home
    add(home, "b1", 200)
    add(home, "b2", 5)
    analysed(home)
    chosen = plan(store, base, set(), 90, expired=True)
    assert [r["id"] for r in chosen.bundles] == ["b1"]
    assert chosen.baselines == {"web01": "moved"}


def test_an_explicit_purge_moves_the_baseline_and_the_next_analysis_says_so(home):
    base, store, identity, config = home
    add(home, "b1", 40)
    add(home, "b2", 20)
    add(home, "b3", 10)
    analysed(home)
    chosen = plan(store, base, {"web01"}, 90, before=NOW - timedelta(days=30))
    assert chosen.baselines == {"web01": "moved"}
    execute(store, base, chosen)
    assert current_baseline(store, "web01") is None

    found = changes(store, "web01", identity, config.recipients)
    assert found.after_purge and not found.first
    assert found.baseline_id == "b2"
    assert current_baseline(store, "web01")["how"] == "after purge"
    assert any("earlier baseline was purged" in note for note in found.notes)
    assessment = analyze(store, "web01", identity, config.recipients)
    assert any("earlier baseline was purged" in note for note in assessment["notes"])
    assert not any("first analysis" in note for note in assessment["notes"])


def test_a_host_purged_whole_starts_afresh(home):
    base, store, identity, config = home
    add(home, "b1", 40)
    analysed(home)
    execute(store, base, plan(store, base, {"web01"}, 90, host="web01"))
    add(home, "b9", 1)
    found = changes(store, "web01", identity, config.recipients)
    assert found.first and not found.after_purge


# --- reports and leftovers ---------------------------------------------------------------


def test_reports_showing_a_purged_bundle_go_and_others_stay(home):
    base, store, identity, config = home
    add(home, "b1", 40)
    add(home, "other", 40, host="db01")
    analysed(home)
    analysed(home, "db01")
    mine = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    both = base / "reports" / "report-2-hosts-x.html.age"
    write_report(
        store, ["web01", "db01"], identity, config.recipients, base / "reports", None, both
    )
    theirs = base / "reports" / "report-db01-x.html"  # plain: found by its hash all the same
    write_report(
        store, ["db01"], identity, config.recipients, base / "reports", None, theirs, plain=True
    )
    link = base / "reports" / "report-link.html"
    link.symlink_to(mine)

    chosen = plan(store, base, {"web01", "db01"}, 90, host="web01")
    assert sorted(chosen.reports) == sorted([mine, both])
    execute(store, base, chosen)
    assert not mine.exists() and not both.exists()
    assert theirs.exists() and link.is_symlink()


def test_files_left_by_an_interrupted_purge_go_at_the_next(home):
    base, store, _, _ = home
    add(home, "b1", 40)
    analysed(home)
    store.purge(["b1"], {"host": "web01"}, {"web01": "emptied"})  # rows gone, files not
    stranded = files_of(home, "b1")
    assert stranded and len(leftovers(store, base)) == len(stranded)

    outcome = execute(store, base, plan(store, base, set(), 90, host="nothing-here"))
    assert outcome.counts["bundles"] == 0
    assert files_of(home, "b1") == [] and leftovers(store, base) == []


@pytest.mark.parametrize("plain", [False, True])
def test_a_report_a_purge_couldnt_delete_goes_at_the_next(home, monkeypatch, plain):
    base, store, identity, config = home
    add(home, "b1", 40)
    analysed(home)
    report = write_report(
        store, ["web01"], identity, config.recipients, base / "reports", plain=plain
    )
    real = Path.unlink

    def stuck(self, *args, **kwargs):
        if self == report:
            raise PermissionError(13, "Permission denied")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", stuck)
    outcome = execute(store, base, plan(store, base, set(), 90, host="web01"))
    assert [p for p, _ in outcome.failed] == [report]
    monkeypatch.setattr(Path, "unlink", real)
    assert leftovers(store, base) == [report]
    execute(store, base, plan(store, base, set(), 90, host="nothing-here"))
    assert not report.exists() and leftovers(store, base) == []


def test_bundles_outside_the_evidence_folder_are_listed_not_touched(home, tmp_path):
    base, store, _, _ = home
    path = add(home, "b1", 40)
    elsewhere = tmp_path.parent / f"{tmp_path.name}-outside"
    elsewhere.mkdir()
    moved = elsewhere / path.name
    path.rename(moved)
    store._db.execute("DROP TRIGGER bundles_no_update")
    store._db.execute("UPDATE bundles SET path = ? WHERE id = 'b1'", (str(moved),))
    chosen = plan(store, base, set(), 90, host="web01")
    assert chosen.outside == [str(moved)] and chosen.files == []


# --- the command -------------------------------------------------------------------------


def inventory(*names):
    with inventory_transaction() as hosts:
        for name in names:
            hosts.add(Host(name=name, address="192.0.2.1", user="scanner"))


def test_cli_dry_run_and_refusal_delete_nothing(home, capsys):
    _, store, _, _ = home
    add(home, "b1", 40)
    assert cli.main(["purge", "web01", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "To purge: 1 bundle(s)" in out and "Dry run" in out
    assert cli.cmd_purge(cli.build_parser().parse_args(["purge", "web01"]), lambda _: "y") == 1
    assert "Nothing deleted" in capsys.readouterr().out
    assert rows(store, "bundles", "b1") == 1 and files_of(home, "b1")


def test_cli_purges_after_the_word_and_warns_when_a_baseline_moves(home, capsys):
    _, store, _, _ = home
    inventory("web01")
    add(home, "b1", 40)
    add(home, "b2", 10)
    analysed(home)
    args = cli.build_parser().parse_args(["purge", "--before", (NOW - timedelta(30)).isoformat()])
    assert cli.cmd_purge(args, lambda _: "purge") == 0
    out = capsys.readouterr().out
    assert "web01's baseline goes too" in out and "Purged 1 bundle(s)" in out
    assert rows(store, "bundles", "b1") == 0 and rows(store, "bundles", "b2") == 1


def test_cli_expired_keeps_the_baseline_and_says_so(home, capsys):
    _, store, _, _ = home
    inventory("web01")
    add(home, "b1", 200)
    add(home, "b2", 150)
    add(home, "b3", 5)
    analysed(home)
    assert cli.main(["purge", "--expired", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Kept: b1, web01's current baseline" in out and "Purged 1 bundle(s)" in out
    assert cli.main(["purge", "--expired", "--yes"]) == 0
    assert "Nothing to purge" in capsys.readouterr().out


def test_cli_rejects_bad_requests(home, capsys):
    add(home, "b1", 40)
    assert cli.main(["purge"]) == 2
    assert cli.main(["purge", "--expired", "--before", "2026-01-01"]) == 2
    assert cli.main(["purge", "--before", "soon"]) == 2
    assert cli.main(["purge", "db99", "--yes"]) == 2
    err = capsys.readouterr().err
    assert "say what" in err and "can't be combined" in err and "not a date" in err
    assert "no stored bundles for db99" in err


def test_analyze_reminds_about_expired_evidence(home, capsys):
    inventory("web01")
    add(home, "b1", 200)
    add(home, "b2", 150)
    add(home, "b3", 5)
    analysed(home)
    assert cli.main(["analyze", "web01"]) == 0
    out = capsys.readouterr().out
    assert "1 bundle(s) are older than the 90-day retention period" in out


# --- from the review of 2.0 ------------------------------------------------------------


class FailingAt:
    """The store's connection, failing at the first statement matching."""

    def __init__(self, db, text):
        self._db, self._text = db, text

    def execute(self, sql, *args):
        if self._text in sql:
            raise sqlite3.OperationalError("injected")
        return self._db.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._db, name)


def test_a_purge_failing_midway_leaves_rows_and_triggers(home):
    base, store, _, _ = home
    add(home, "b1", 30)
    analysed(home)
    before = triggers(store)
    real = store._db
    store._db = FailingAt(real, "DELETE FROM custody")  # after the triggers are dropped
    try:
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            store.purge(["b1"], {"host": "web01"}, {"web01": "emptied"})
    finally:
        store._db = real
    assert triggers(store) == before
    assert all(rows(store, table, "b1") for table in ("bundles", "custody", "baselines"))
    assert store.purges() == []


def test_an_older_accepted_baseline_does_not_come_back_after_a_purge(home):
    base, store, identity, config = home
    for name, days in (("b1", 40), ("b2", 30), ("b3", 20), ("b4", 10)):
        add(home, name, days)
    analysed(home)  # b1 first
    accept(store, "web01", "Upgrade", identity, config.recipients, "b4")
    accept(store, "web01", "Back to b2", identity, config.recipients, "b2")
    chosen = plan(store, base, {"web01"}, 90, before=NOW - timedelta(days=25))
    assert [r["id"] for r in chosen.bundles] == ["b1", "b2"]
    assert chosen.baselines == {"web01": "moved"}
    execute(store, base, chosen)
    assert current_baseline(store, "web01")["bundle_id"] == "b4"  # the surviving older row

    found = changes(store, "web01", identity, config.recipients)
    assert found.after_purge and found.baseline_id == "b3"
    assert current_baseline(store, "web01")["how"] == "after purge"
    again = changes(store, "web01", identity, config.recipients)  # chosen once, then kept
    assert not again.after_purge and again.baseline_id == "b3"
    assert any("earlier baseline was purged" in note for note in again.notes)


def test_a_baseline_set_after_planning_stops_the_purge(home):
    base, store, identity, config = home
    add(home, "b1", 200)
    add(home, "b2", 5)
    chosen = plan(store, base, {"web01"}, 90, expired=True)  # no baseline yet
    assert [r["id"] for r in chosen.bundles] == ["b1"]
    changes(store, "web01", identity, config.recipients)  # b1 becomes the baseline
    with pytest.raises(Exception, match="changed while the purge was being planned"):
        execute(store, base, chosen)
    assert rows(store, "bundles", "b1") == 1 and files_of(home, "b1")
    assert store.purges() == []


def test_cli_expired_refuses_without_an_inventory(home, capsys):
    _, store, _, _ = home
    add(home, "b1", 200)
    add(home, "b2", 5)
    analysed(home)
    assert cli.main(["purge", "--expired", "--yes"]) == 2
    assert "--expired needs the inventory" in capsys.readouterr().err
    assert rows(store, "bundles", "b1") == 1


def test_cli_reports_a_locked_database_without_a_traceback(home, capsys, monkeypatch):
    add(home, "b1", 40)

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("checker.evidence.Store.purge", locked)
    assert cli.main(["purge", "web01", "--yes"]) == 1
    assert "database is locked" in capsys.readouterr().err


def test_the_reminder_never_breaks_the_command(home, capsys):
    base = home[0]
    (base / "config.yaml").write_text("retention_days: [not, a, number]\n")
    cli._expired_notice(base)
    assert capsys.readouterr().out == ""


def test_retention_days_must_be_positive():
    from pydantic import ValidationError

    from checker.evidence import Config

    with pytest.raises(ValidationError):
        Config(recipients=["x"], retention_days=0)
