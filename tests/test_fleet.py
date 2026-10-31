"""The fleet view (PR 5.1): most worrying first, what changed, what is out
of date, from what is stored, with nothing written."""

import hashlib

from test_schedule import CLEAN, ROOTED, keyed_host
from test_snapshot import add_bundle

from checker import cli
from checker.assess import analyze
from checker.evidence import load_identity
from checker.fleet import fleet, fleet_host, sort_key
from checker.inventory import inventory_transaction

BIDI = chr(0x202E)


def identity_of(home):
    return load_identity(home[0] / "keys" / "evidence-identity.txt")


def analysed(home, name, minutes, records, host="web01"):
    base, store, _, config = home
    add_bundle(home, name, minutes, records, host=host)
    return analyze(store, host, identity_of(home), config.recipients, name)


def test_a_host_with_nothing_collected_is_listed_and_says_so(home):
    (only,) = fleet(home[1], identity_of(home), {"web01": "web"})
    assert only.state == "no_evidence" and only.group == "web" and only.band is None


def test_collected_but_not_analysed_says_so(home):
    add_bundle(home, "b1", 10, CLEAN)
    item = fleet_host(home[1], "web01", identity_of(home))
    assert item.state == "not_analysed" and item.collected_at


def test_most_worrying_first_and_unknown_never_sinks(home):
    analysed(home, "a", 10, ROOTED, host="rooted")
    analysed(home, "b", 10, CLEAN, host="clean")
    names = [h.host for h in fleet(home[1], identity_of(home), {"never": None})]
    assert names == ["rooted", "never", "clean"]


def test_a_first_analysis_has_no_changes_to_show(home):
    analysed(home, "b1", 10, ROOTED)
    item = fleet_host(home[1], "web01", identity_of(home))
    assert item.first and item.changes == () and item.band == "High"


def test_what_changed_since_the_analysis_before(home):
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, ROOTED)
    item = fleet_host(home[1], "web01", identity_of(home))
    assert not item.first and item.band_before == "Low" and item.band == "Critical"
    assert any("new critical" in line for line in item.changes)


def test_findings_gone_are_counted(home):
    analysed(home, "b1", 10, ROOTED)
    analysed(home, "b2", 20, CLEAN)
    assert fleet_host(home[1], "web01", identity_of(home)).gone >= 1


def test_a_newer_unanalysed_collection_keeps_the_old_result_and_says_so(home):
    analysed(home, "b1", 10, ROOTED)
    add_bundle(home, "b2", 20, CLEAN)
    item = fleet_host(home[1], "web01", identity_of(home))
    # A known problem must not vanish because a collection hasn't been analysed.
    assert item.band == "High" and "newer collection" in item.out_of_date[0]


def test_a_failed_last_collection_shows_beside_the_result(home):
    analysed(home, "b1", 10, CLEAN)
    add_bundle(home, "b2", 20, CLEAN, status="failed")
    item = fleet_host(home[1], "web01", identity_of(home))
    assert item.last_failed[0] == "failed" and item.band == "Low"
    assert item.out_of_date == ()


def test_a_tampered_analysis_is_said_not_replaced_by_an_older_one(home):
    analysed(home, "b1", 10, ROOTED)
    analysed(home, "b2", 20, CLEAN)
    with open(home[1].assessments("b2")[-1]["path"], "ab") as f:
        f.write(b"x")
    item = fleet_host(home[1], "web01", identity_of(home))
    assert item.state == "unreadable" and item.band is None


def test_out_of_date_reasons_match_what_the_report_acts_on(home, monkeypatch):
    analysed(home, "b1", 10, CLEAN)
    monkeypatch.setattr("checker.report.current_versions", lambda: {"checks": -1})
    item = fleet_host(home[1], "web01", identity_of(home))
    assert any("older version" in r for r in item.out_of_date)


def test_another_prior_is_out_of_date(home):
    analysed(home, "b1", 10, CLEAN)
    item = fleet_host(home[1], "web01", identity_of(home), prior_for=lambda _: (0.5, "host"))
    assert any("starting probability" in r for r in item.out_of_date)


def test_looking_writes_nothing(home):
    analysed(home, "b1", 10, ROOTED)
    db = home[0] / "checker.db"
    counts = _table_counts(home[1])
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    fleet(home[1], identity_of(home), {"web01": None}, prior_for=lambda _: (0.5, "host"))
    assert _table_counts(home[1]) == counts
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def _table_counts(store):
    names = [r[0] for r in store._db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    return {n: store._db.execute(f"SELECT count(*) FROM {n}").fetchone()[0] for n in names}  # noqa: S608


def test_the_order_handles_a_band_it_does_not_know(home):
    from checker.fleet import FleetHost

    assert sort_key(FleetHost("x", band="Odd"))[0] == sort_key(FleetHost("x"))[0]


def test_the_command_shows_the_fleet_and_filters_by_group(home, tmp_path, capsys):
    with inventory_transaction() as hosts:
        hosts.add(keyed_host(tmp_path, group="web"))
        hosts.add(keyed_host(tmp_path, name="db01", group="db"))
    analysed(home, "b1", 10, ROOTED)
    assert cli.main(["fleet"]) == 0
    out = capsys.readouterr().out
    assert out.index("web01  High") < out.index("db01  nothing collected yet")
    assert cli.main(["fleet", "--group", "db"]) == 0
    out = capsys.readouterr().out
    assert "db01" in out and "web01" not in out


def test_host_text_in_a_host_name_is_made_visible(home, capsys):
    analysed(home, "b1", 10, CLEAN, host="a" + BIDI + "b")
    assert cli.main(["fleet"]) == 0
    out = capsys.readouterr().out
    assert BIDI not in out and "a\\u202eb" in out


def test_an_empty_group_says_so(home, capsys):
    assert cli.main(["fleet", "--group", "nope"]) == 0
    assert "No hosts in group nope." in capsys.readouterr().out
