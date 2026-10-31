"""Applying the packs in force (plan 4.6): `checker analyze`, `checker
report` and `checker run` all apply them; a pack that can't be used is a
gap, not silence; a run says when a pack newly finds a host exposed or a
detection firing. The pack is the format tests' made-up one."""

import pytest
from test_pack_exposure import records
from test_pack_format import GOOD
from test_pack_trust import Key, pack
from test_schedule import collector, keyed_host, one_run
from test_snapshot import add_bundle

from checker import cli, schedule
from checker.assess import load_assessment
from checker.evidence import load_config
from checker.inventory import inventory_transaction
from checker.packs.store import in_force

VULNERABLE = records("8.3.6-0ubuntu0.24.04.5")  # before the pack's fix


@pytest.fixture
def ours(home, tmp_path, capsys):
    """An organization key, trusted, and a way to add a pack it signs."""
    key = Key()
    assert cli.main(["packs", "trust", "add", "team", str(key.pub_file(tmp_path / "k.pub"))]) == 0

    def add(text=GOOD):
        assert cli.main(["packs", "add", str(pack(tmp_path, key, text))]) == 0
        capsys.readouterr()

    capsys.readouterr()
    return add


@pytest.fixture
def fleet(home, tmp_path):
    with inventory_transaction() as hosts:
        hosts.add(keyed_host(tmp_path))
    return home


def latest(home):
    _, store, identity, _ = home
    return load_assessment(store, store.bundles("web01")[-1]["id"], identity)


def test_analyze_applies_the_packs_in_force_and_says_so(home, ours, capsys):
    add_bundle(home, "b1", 0, VULNERABLE)
    ours()
    assert cli.main(["analyze", "web01"]) in (0, 1)
    out = capsys.readouterr().out
    assert "Packs      example-2026-10 v2" in out
    assert "prior raised to 9%: exposed to example-2026-10 v2 (100% of its window)" in out
    assert latest(home)["packs"] == [{"id": "example-2026-10", "version": 2}]


def test_a_pack_that_cant_be_used_is_said_and_is_a_gap(home, ours, capsys):
    add_bundle(home, "b1", 0, VULNERABLE)
    ours()
    kept = home[0] / "packs" / "active" / "example-2026-10-v2.yaml"
    kept.write_text(GOOD.replace("likelihood_ratio: 5", "likelihood_ratio: 2"))
    assert cli.main(["analyze", "web01"]) in (0, 1)
    err = capsys.readouterr().err
    assert "checker: threat pack not applied: example-2026-10 version 2:" in err
    assessment = latest(home)
    assert assessment["packs"] == []
    assert any(g.startswith("threat pack not applied: example-2026-10") for g in
               assessment["coverage"]["gaps"])  # fmt: skip


def test_trouble_reading_the_packs_is_a_reason_not_a_crash(home, monkeypatch):
    def broken(*args):
        raise PermissionError("no")

    monkeypatch.setattr("checker.packs.store.active", broken)
    assert in_force(home[0], []) == ([], ["the packs couldn't be read: PermissionError: no"])


def test_a_report_analyses_again_when_the_packs_changed(home, ours, capsys):
    add_bundle(home, "b1", 0, VULNERABLE)
    assert cli.main(["analyze", "web01"]) in (0, 1)
    assert latest(home)["packs"] == []
    ours()
    assert cli.main(["report", "web01"]) == 0
    assert latest(home)["packs"] == [{"id": "example-2026-10", "version": 2}]
    # And again without it, once it is retired.
    assert cli.main(["packs", "retire", "example-2026-10", "--reason", "test"]) == 0
    assert "`checker analyze --all`" in capsys.readouterr().out
    assert cli.main(["report", "web01"]) == 0
    assert latest(home)["packs"] == []


def test_analyze_all_applies_a_pack_added_since_to_every_host(home, ours):
    add_bundle(home, "b1", 0, VULNERABLE)
    add_bundle(home, "c1", 0, VULNERABLE, host="web02")
    assert cli.main(["analyze", "--all"]) in (0, 1)
    ours()
    assert cli.main(["analyze", "--all"]) in (0, 1)
    _, store, identity, _ = home
    for host in ("web01", "web02"):
        row = store.bundles(host)[-1]
        assert load_assessment(store, row["id"], identity)["packs"][0]["id"] == "example-2026-10"


# --- A run -----------------------------------------------------------------------------------


def test_a_pack_added_between_runs_that_finds_a_host_exposed_needs_a_look(fleet, ours):
    collect = collector(fleet, VULNERABLE)
    first = one_run(fleet, collect)
    assert not any("threat pack" in line for line in first.alerting)
    ours()
    second = one_run(fleet, collect)
    assert "web01: exposed to threat pack example-2026-10 v2 (vulnerable now)" in second.alerting
    assert latest(fleet)["packs"] == [{"id": "example-2026-10", "version": 2}]
    # Said once: the next run, still exposed, is quiet about it.
    third = one_run(fleet, collect)
    assert not any("threat pack" in line for line in third.alerting)


def test_a_pack_that_cant_be_used_fails_the_run_and_is_told(fleet, ours):
    ours()
    kept = fleet[0] / "packs" / "active" / "example-2026-10-v2.yaml"
    kept.write_text(GOOD.replace("likelihood_ratio: 5", "likelihood_ratio: 2"))
    result = one_run(fleet, collector(fleet, VULNERABLE))
    assert any(p.startswith("threat pack not applied: example-2026-10") for p in result.problems)
    assert "1 threat pack(s) not applied (`checker packs list`)" in result.alerting
    assert result.exit_status() == schedule.EXIT_FAILED
    assert any(g.startswith("threat pack not applied") for g in
               latest(fleet)["coverage"]["gaps"])  # fmt: skip


def test_with_no_pack_a_run_says_nothing_of_packs(fleet):
    result = one_run(fleet, collector(fleet, VULNERABLE))
    assert result.problems == [] and not any("pack" in line for line in result.alerting)
    assert load_config(fleet[0]).packs.trusted_keys == []


# --- What counts as news ---------------------------------------------------------------------


def scored(*raised_by, findings=()):
    return {"score": {"band": "Low", "probability": 0.05, "raised_by": list(raised_by)},
            "findings": list(findings), "checks": []}  # fmt: skip


def exposed(status="vulnerable", pack="p-2026", version=1):
    return {"pack": pack, "version": version, "status": status, "share": 1.0}


def detection(band="medium", suppressed=None):
    return {"check": "pack.detection", "band": band, "title": "Workers crashing",
            "variant": "p-2026/fpm-crash", "entities": [], "suppressed_by": suppressed}  # fmt: skip


def news(before, after):
    return schedule.alerts("h", schedule.remembered(before), after)


def test_exposure_is_news_once_per_pack():
    assert news(scored(), scored(exposed())) == [
        "h: exposed to threat pack p-2026 v1 (vulnerable now)"
    ]
    assert news(scored(exposed()), scored(exposed(version=2))) == []  # a new version, same pack
    assert news(scored(exposed()), scored(exposed(), exposed(pack="q-2026"))) == [
        "h: exposed to threat pack q-2026 v1 (vulnerable now)"
    ]
    assert news(None, scored(exposed("fixed"))) == [
        "h: exposed to threat pack p-2026 v1 (exposed while the threat was active, fixed since)"
    ]
    assert news(scored(), scored(exposed("can't judge"))) == [
        "h: exposed to threat pack p-2026 v1 (can't be judged, so counted as exposed)"
    ]
    # No longer exposed, then exposed again: news again.
    assert news(scored(), scored(exposed())) and schedule.remembered(scored())["exposed"] == []


def test_a_packs_detection_is_news_whatever_its_band():
    assert news(scored(), scored(findings=[detection()])) == [
        "h: new medium: Workers crashing (threat pack p-2026)"
    ]
    assert news(scored(findings=[detection()]), scored(findings=[detection()])) == []
    assert news(scored(), scored(findings=[detection(suppressed="rule")])) == []
    assert news(scored(findings=[detection("low")]), scored(findings=[detection("high")])) == [
        "h: now high (was low): Workers crashing (threat pack p-2026)"
    ]


def test_an_older_runs_memory_without_exposure_counts_as_none():
    before = schedule.remembered(scored())
    del before["exposed"]
    assert schedule.alerts("h", before, scored(exposed())) == [
        "h: exposed to threat pack p-2026 v1 (vulnerable now)"
    ]
