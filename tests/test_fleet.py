"""The fleet view (PR 5.1): most worrying first, what changed, what is out
of date, from what is stored, with nothing written."""

import hashlib
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from pyrage import x25519
from test_purge import add as add_to_evidence
from test_schedule import CLEAN, ROOTED, keyed_host
from test_snapshot import START, add_bundle

from checker import cli
from checker import fleet as fleet_module
from checker.assess import analyze, events_of, load_assessment
from checker.evidence import EvidenceError, Store, load_identity, store_unreadable
from checker.fleet import STALE_AFTER, FleetHost, fleet, fleet_host, sort_key
from checker.inventory import inventory_transaction
from checker.packs.trust import shipped_newer
from checker.report import host_report, out_of_date, reassess, whitelist_hash
from checker.schedule import _identity_of
from checker.scoring import DEFAULT_PRIOR
from checker.settings import change as set_setting

BIDI = chr(0x202E)
SOON = START + timedelta(minutes=30)


REAL_BLIND = fleet_module._BLIND


@pytest.fixture(autouse=True)
def _sees_logs(monkeypatch):
    """The test records hold no log events, which a real host's do: only the
    tests about being blind are blind."""
    monkeypatch.setattr(fleet_module, "_BLIND", ())


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
    names = [h.host for h in fleet(home[1], identity_of(home), {"never": None}, now=SOON)]
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


def test_a_newer_unanalysed_collection_keeps_the_old_result_and_says_so(home):
    analysed(home, "b1", 10, ROOTED)
    add_bundle(home, "b2", 20, CLEAN)
    item = fleet_host(home[1], "web01", identity_of(home))
    # A known problem must not vanish because a collection hasn't been analysed.
    assert item.band == "High" and "newer collection" in item.out_of_date[0]


def test_a_failed_last_collection_shows_and_a_low_result_is_not_trusted(home):
    analysed(home, "b1", 10, CLEAN)
    add_bundle(home, "b2", 20, CLEAN, status="failed")
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.last_failed[0] == "failed" and item.band == "Low"
    assert item.doubts == ("its last collection was failed",)


def test_a_result_with_nothing_recent_behind_it_is_not_reassuring(home):
    analysed(home, "good", 10, CLEAN, host="fresh")
    analysed(home, "old", 10, CLEAN, host="stale")
    fresh = fleet_host(home[1], "fresh", identity_of(home), now=SOON)
    assert fresh.doubts == ()
    later = SOON + STALE_AFTER
    stale = fleet_host(home[1], "stale", identity_of(home), now=later)
    assert "days ago" in stale.doubts[0]
    assert sort_key(stale)[0] < sort_key(fresh)[0]  # above a Low anyone can vouch for


def test_doubt_never_moves_a_serious_result_down(home):
    analysed(home, "b1", 10, ROOTED)
    add_bundle(home, "b2", 20, CLEAN, status="failed")
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.band == "High" and sort_key(item)[0] == 1


def test_the_order_has_elevated_between_unknown_and_low():
    known = [FleetHost("c", band=b) for b in ("Low", "Elevated", "High", "Critical")]
    known.append(FleetHost("u"))
    assert [i.band for i in sorted(known, key=sort_key)] == [
        "Critical",
        "High",
        None,
        "Elevated",
        "Low",
    ]


def test_a_tampered_latest_analysis_comes_first_and_says_what_it_last_said(home):
    analysed(home, "b1", 10, ROOTED)
    analysed(home, "b2", 20, CLEAN)
    analysed(home, "z", 10, ROOTED, host="another")
    analysed(home, "z2", 20, ROOTED, host="another")
    with open(home[1].assessments("b2")[-1]["path"], "ab") as f:
        f.write(b"x")
    hosts = fleet(home[1], identity_of(home), {}, now=SOON)
    assert hosts[0].host == "web01"
    assert hosts[0].state == "unreadable" and hosts[0].band is None
    assert hosts[0].last_readable_band == "High"  # never shown as current


def test_an_older_analysis_unreadable_leaves_the_latest_alone(home):
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, ROOTED)
    with open(home[1].assessments("b1")[-1]["path"], "ab") as f:
        f.write(b"x")
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.state == "analysed" and item.before_unreadable and not item.first
    assert item.out_of_date == ()


def test_findings_missing_from_a_partial_collection_are_not_called_gone(home):
    analysed(home, "b1", 10, ROOTED)
    add_bundle(home, "b2", 20, CLEAN, status="partial")
    analyze(home[1], "web01", identity_of(home), home[3].recipients, "b2")
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.collection_status == "partial" and item.resolved == 0 and item.not_seen >= 1
    assert "this collection was partial" in item.doubts


def test_findings_missing_from_a_whole_collection_are_resolved(home):
    analysed(home, "b1", 10, ROOTED)
    analysed(home, "b2", 20, CLEAN)
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.resolved >= 1 and item.not_seen == 0 and item.suppressed == 0


def test_a_finding_now_suppressed_is_not_called_resolved():
    finding = {"check": "c", "title": "t", "suppressed_by": "rule"}
    key = _identity_of(finding)
    other = _identity_of({"check": "d", "title": "t"})
    assert fleet_module._gone({"findings": {key: "critical"}}, {"findings": [finding]}, True) == (
        0,
        1,
        0,
    )
    assert fleet_module._gone({"findings": {other: "high"}}, {"findings": []}, True) == (1, 0, 0)


def test_a_group_listed_in_part_with_a_new_count_is_the_same_finding():
    before = {"check": "c", "entities": ["a"], "entities_complete": False, "summary": "3 of 40"}
    after = {**before, "summary": "3 of 41"}
    assert _identity_of(before) != _identity_of(after)
    gone = fleet_module._gone(
        {"findings": {_identity_of(before): "critical"}}, {"findings": [after]}, True
    )
    assert gone == (0, 0, 0)


def test_a_capped_group_whose_listed_members_shift_is_the_same_finding():
    before = {
        "check": "c",
        "entities": ["a", "b"],
        "entities_complete": False,
        "summary": "2 of 25",
    }
    after = {"check": "c", "entities": ["b", "z"], "entities_complete": False, "summary": "2 of 26"}
    gone = fleet_module._gone(
        {"findings": {_identity_of(before): "high"}}, {"findings": [after]}, True
    )
    assert gone == (0, 0, 0)


def test_entities_in_common_are_the_same_finding_and_none_in_common_are_not():
    was = {"check": "c", "entities": ["a", "b"]}
    assert fleet_module._gone(
        {"findings": {_identity_of(was): "high"}},
        {"findings": [{"check": "c", "entities": ["b", "c"]}]},
        True,
    ) == (0, 0, 0)
    assert fleet_module._gone(
        {"findings": {_identity_of(was): "high"}},
        {"findings": [{"check": "c", "entities": ["x"]}]},
        True,
    ) == (1, 0, 0)


def test_being_blind_stays_a_doubt_after_the_first_day(home, monkeypatch):
    monkeypatch.setattr(fleet_module, "_BLIND", REAL_BLIND)
    gap = "no authentication log events: logins and sudo can't be checked"
    analysed(home, "b1", 10, ROOTED)
    second = analysed(home, "b2", 20, CLEAN)
    analysed(home, "b3", 30, CLEAN)
    blind = {"coverage": {"gaps": [*second["coverage"]["gaps"], gap]}}
    patched(monkeypatch, {"b2": blind, "b3": blind})
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert gap in item.doubts and sort_key(item)[0] == 2


def test_being_blind_at_the_first_analysis_is_a_doubt(home, monkeypatch):
    monkeypatch.setattr(fleet_module, "_BLIND", REAL_BLIND)
    gap = "no system journal events: kernel messages and shutdowns can't be checked"
    analysed(home, "b1", 10, CLEAN)
    patched(monkeypatch, {"b1": {"coverage": {"gaps": [gap]}}})
    assert gap in fleet_host(home[1], "web01", identity_of(home), now=SOON).doubts


def test_other_threat_packs_mean_a_finding_is_not_resolved(home, monkeypatch):
    analysed(home, "b1", 10, ROOTED)
    analysed(home, "b2", 20, CLEAN)
    patched(monkeypatch, {"b1": {"packs": [{"id": "p1", "version": 1}]}})
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.resolved == 0 and item.not_seen >= 1


def test_a_removed_host_is_not_called_out_of_date_by_settings_it_no_longer_has(home):
    analysed(home, "b1", 10, CLEAN)
    item = fleet_host(
        home[1],
        "web01",
        identity_of(home),
        prior_for=lambda _: (0.5, "configuration"),
        whitelist_for=lambda _: _Whitelist(),
        now=SOON,
        removed=True,
    )
    assert item.out_of_date == () and item.doubts == ()


def patched(monkeypatch, changes):
    """Stored analyses with some fields changed, by bundle."""
    real = fleet_module.load_assessment

    def load(store, bundle, identity, which=-1):
        found = real(store, bundle, identity, which)
        return {**found, **changes.get(bundle, {})} if found else found

    monkeypatch.setattr(fleet_module, "load_assessment", load)


def exposure(status, judged=True):
    share = 1 if judged and status != "not exposed" else 0
    return [{"pack": "p1", "version": 1, "status": status, "share": share, "judged": judged}]


def test_a_failed_check_is_a_standing_doubt_and_its_findings_are_not_resolved(home, monkeypatch):
    analysed(home, "b1", 10, ROOTED)
    analysed(home, "b2", 20, CLEAN)
    patched(monkeypatch, {"b2": {"checks": [{"check": "account.uid0", "status": "failed: boom"}]}})
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.resolved == 0 and item.not_seen >= 1
    assert any("couldn't run: account.uid0" in d for d in item.doubts)
    assert sort_key(item)[0] == 2


def test_seeing_less_than_before_is_a_doubt_and_its_findings_are_not_resolved(home, monkeypatch):
    analysed(home, "b1", 10, ROOTED)
    wiped = analysed(home, "b2", 20, CLEAN)
    gaps = [*wiped["coverage"]["gaps"], "no authentication log events: logins can't be checked"]
    patched(monkeypatch, {"b2": {"coverage": {"gaps": gaps}}})
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert any("no authentication log events" in d for d in item.doubts)
    assert item.resolved == 0 and item.not_seen >= 1


def test_a_new_packs_own_note_is_not_seeing_less(home, monkeypatch):
    analysed(home, "b1", 10, CLEAN)
    second = analysed(home, "b2", 20, CLEAN)
    gaps = [
        *second["coverage"]["gaps"],
        "pack p1 v1: mitigation m is in place in the settings read",
    ]
    patched(monkeypatch, {"b2": {"coverage": {"gaps": gaps}}})
    assert fleet_host(home[1], "web01", identity_of(home), now=SOON).doubts == ()


@pytest.mark.parametrize(
    ("blind_for", "doubted"),
    [(2, True), (1, True), (9, False)],  # still news on day two; how the host is by day nine
)
def test_seeing_less_stays_a_doubt_until_it_is_how_the_host_is(
    home, monkeypatch, blind_for, doubted
):
    names = [f"b{n}" for n in range(10)]
    gaps = {}
    for n, name in enumerate(names):
        gaps[name] = analysed(home, name, 10 * (n + 1), CLEAN)["coverage"]["gaps"]
    gap = "module web_logs: timeout"
    patched(monkeypatch, {n: {"coverage": {"gaps": [*gaps[n], gap]}} for n in names[-blind_for:]})
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert any("see less" in d for d in item.doubts) is doubted


def test_a_date_in_the_future_vouches_for_nothing():
    later = (SOON + timedelta(days=400)).isoformat()
    assert fleet_module._old(later, SOON, STALE_AFTER)
    assert not fleet_module._old((SOON + timedelta(hours=1)).isoformat(), SOON, STALE_AFTER)


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        (0.5, 0.5),
        (0, 0.0),
        (1, 1.0),
        (True, None),
        (-1, None),
        (1.5, None),
        (10**400, None),
        (float("nan"), None),
        (float("inf"), None),
        ("half", None),
        (None, None),
    ],
)
def test_only_a_real_probability_is_kept(value, kept):
    assert fleet_module._probability(value) == kept


def test_a_gap_differing_only_in_a_number_is_not_new(home):
    analysed(home, "b1", 10, CLEAN)
    analysed(home, "b2", 20, CLEAN)  # a clock offset differs between these
    assert fleet_host(home[1], "web01", identity_of(home), now=SOON).doubts == ()


def test_rescoring_with_other_checks_says_nothing_about_the_host(home, monkeypatch):
    analysed(home, "b1", 10, ROOTED)
    analysed(home, "b2", 20, CLEAN)
    patched(monkeypatch, {"b1": {"versions": {"checks": 0}}})
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.resolved == 0 and item.not_seen >= 1


@pytest.mark.parametrize(
    "steps",
    [
        (exposure("vulnerable"), exposure("can't judge", False), exposure("can't judge", False)),
        (exposure("vulnerable"), exposure("can't judge", False)),
    ],
)
def test_a_known_exposure_survives_however_many_listings_cannot_judge_it(home, monkeypatch, steps):
    names = [f"b{n}" for n in range(len(steps))]
    for n, name in enumerate(names):
        analysed(home, name, 10 * (n + 1), CLEAN)
    patched(monkeypatch, {n: {"exposures": s} for n, s in zip(names, steps, strict=True)})
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.exposed == {"p1": "vulnerable"} and item.unjudged == ("p1",)


def test_an_exposure_judged_again_as_vulnerable_is_not_news(home, monkeypatch):
    for n, name in enumerate(("b1", "b2", "b3")):
        analysed(home, name, 10 * (n + 1), CLEAN)
    patched(
        monkeypatch,
        {
            "b1": {"exposures": exposure("vulnerable")},
            "b2": {"exposures": exposure("can't judge", False)},
            "b3": {"exposures": exposure("vulnerable")},
        },
    )
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert not any("exposed to threat pack" in line for line in item.changes)


def test_a_changed_whitelist_makes_a_low_result_doubtful(home):
    analysed(home, "b1", 10, CLEAN)
    item = fleet_host(
        home[1], "web01", identity_of(home), whitelist_for=lambda _: _Whitelist(), now=SOON
    )
    assert "the whitelist has changed" in item.doubts and sort_key(item)[0] == 2


def test_changed_packs_make_a_low_result_doubtful(home):
    analysed(home, "b1", 10, CLEAN)
    item = fleet_host(
        home[1], "web01", identity_of(home), packs_for=lambda _: ([], ["bad"]), now=SOON
    )
    assert any("packs" in d for d in item.doubts) and sort_key(item)[0] == 2


def test_newer_checks_are_said_but_do_not_alarm_the_fleet(home, monkeypatch):
    analysed(home, "b1", 10, CLEAN)
    monkeypatch.setattr("checker.report.current_versions", lambda: {"checks": -1})
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.out_of_date and item.doubts == () and sort_key(item)[0] == 4


def test_a_doubted_elevated_result_moves_up_and_a_newer_collection_is_a_doubt(home):
    item = FleetHost("x", band="Elevated", state="analysed", doubts=("why",))
    assert sort_key(item)[0] == 2
    analysed(home, "b1", 10, CLEAN)
    add_bundle(home, "b2", 20, CLEAN)
    fresh = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert "a newer collection hasn't been analysed" in fresh.doubts


def test_a_date_that_cannot_be_read_counts_as_old():
    assert fleet_module._old("not a date", SOON, STALE_AFTER)


def test_serious_findings_come_first_among_low_results():
    plain = FleetHost("a", band="Low", state="analysed", probability=0.03)
    hidden = FleetHost(
        "b", band="Low", state="analysed", probability=0.02, counts={"hygiene/critical": 2}
    )
    assert sorted([plain, hidden], key=sort_key) == [hidden, plain]


def test_the_previous_collection_is_what_a_rescored_one_is_compared_with(home):
    analysed(home, "b1", 10, ROOTED)
    earlier = analysed(home, "b2", 20, CLEAN)
    reassess(
        home[1],
        home[1].bundle("b2"),
        home[3].recipients,
        earlier,
        (0.0002, "host"),
        None,
        events_of(home[1], home[1].bundle("b2"), identity_of(home), home[3].recipients),
    )
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert item.band_before == "High" and item.rescored_from is None


def test_rescoring_one_collection_is_not_a_first_analysis(home):
    analysed(home, "b1", 10, ROOTED)
    earlier = load_assessment(home[1], "b1", identity_of(home))
    reassess(
        home[1],
        home[1].bundle("b1"),
        home[3].recipients,
        earlier,
        (0.0001, "host"),
        None,
        events_of(home[1], home[1].bundle("b1"), identity_of(home), home[3].recipients),
    )
    item = fleet_host(home[1], "web01", identity_of(home), now=SOON)
    assert not item.first and item.band_before == "High"
    assert item.band != "High" and item.rescored_from == "High"


def test_one_hosts_broken_whitelist_leaves_the_fleet_listed(home):
    analysed(home, "a", 10, ROOTED, host="rooted")
    analysed(home, "b", 10, CLEAN, host="clean")

    def whitelist(name):
        if name == "clean":
            raise EvidenceError("bad yaml")

    hosts = fleet(home[1], identity_of(home), {}, whitelist_for=whitelist, now=SOON)
    assert [h.host for h in hosts] == ["rooted", "clean"]
    assert "its whitelist can't be read" in hosts[1].out_of_date
    assert "the whitelist has changed" not in hosts[1].out_of_date  # it can't say
    assert hosts[1].band == "Low"


def test_trouble_working_out_the_details_keeps_the_band(home, monkeypatch):
    analysed(home, "a", 10, ROOTED, host="rooted")
    analysed(home, "b", 10, CLEAN, host="odd")
    monkeypatch.setattr(fleet_module, "out_of_date", _boom_on_low(fleet_module.out_of_date))
    hosts = {h.host: h for h in fleet(home[1], identity_of(home), {}, now=SOON)}
    assert hosts["odd"].band == "Low" and hosts["odd"].doubts
    assert hosts["rooted"].band == "High"


def test_trouble_before_any_band_is_read_is_loud_not_fatal(home, monkeypatch):
    analysed(home, "a", 10, ROOTED, host="rooted")

    def broken(*args):
        raise ValueError("odd")

    monkeypatch.setattr(fleet_module, "usable_bundles", broken)
    (only,) = fleet(home[1], identity_of(home), {})
    assert only.state == "unreadable" and only.unreadable_why == "internal"


def test_a_missing_file_is_not_called_tampering(home):
    analysed(home, "b1", 10, ROOTED)
    Path(home[1].assessments("b1")[-1]["path"]).unlink()
    assert fleet_host(home[1], "web01", identity_of(home)).unreadable_why == "missing"


def test_a_hash_mismatch_says_so(home):
    analysed(home, "b1", 10, ROOTED)
    with open(home[1].assessments("b1")[-1]["path"], "ab") as f:
        f.write(b"x")
    assert fleet_host(home[1], "web01", identity_of(home)).unreadable_why == "mismatch"
    assert "tampered" in fleet_module.UNREADABLE["mismatch"]


def test_the_wrong_key_is_one_error_not_every_host_tampered_with(home):
    analysed(home, "b1", 10, ROOTED)
    analysed(home, "c1", 10, CLEAN, host="other")
    wrong = x25519.Identity.generate()
    with pytest.raises(EvidenceError, match="right one"):
        fleet(home[1], wrong, {})


def test_a_store_that_cannot_answer_is_one_error(home, monkeypatch):
    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(home[1], "bundles", locked)
    analysed_name = {"web01": None}
    with pytest.raises(EvidenceError, match="busy"):
        fleet(home[1], identity_of(home), analysed_name)


@pytest.mark.parametrize(
    ("text", "words"),
    [
        ("attempt to write a readonly database", "bundle list"),
        ("database is locked", "busy"),
        ("no such table: purges", "older version"),
        ("file is not a database", "damaged"),
    ],
)
def test_each_store_trouble_says_what_to_do(text, words):
    assert words in store_unreadable(sqlite3.OperationalError(text))


def test_a_damaged_store_is_a_plain_error_from_the_command(home, capsys):
    (home[0] / "checker.db").write_bytes(b"not a database, not at all" * 100)
    assert cli.main(["fleet"]) == 1
    assert "damaged" in capsys.readouterr().err


def test_an_empty_store_is_a_plain_error_from_the_command(home, capsys):
    (home[0] / "checker.db").write_bytes(b"")
    assert cli.main(["fleet"]) == 1
    assert "older version" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["hosts.yaml", "config.yaml"])
def test_a_broken_settings_file_is_a_plain_error_from_the_command(home, capsys, name):
    (home[0] / name).write_text("a: [unclosed")
    assert cli.main(["fleet"]) == 1
    assert capsys.readouterr().err.startswith("checker: ")


def test_the_command_passes_the_whitelist_and_the_prior(home, tmp_path, capsys):
    with inventory_transaction() as hosts:
        hosts.add(keyed_host(tmp_path, prior=0.5))
    analysed(home, "b1", 10, CLEAN)
    folder = home[0] / "whitelist" / "hosts"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "web01.yaml").write_text("rules: [unclosed")
    assert cli.main(["fleet"]) == 0
    out = capsys.readouterr().out
    assert "its whitelist can't be read" in out and "starting probability" in out


def test_the_command_passes_the_packs(home, capsys, monkeypatch):
    analysed(home, "b1", 10, CLEAN)
    monkeypatch.setattr(
        "checker.packs.store.in_force_read_only", lambda *args: ([], ["a pack is broken"])
    )
    assert cli.main(["fleet"]) == 0
    captured = capsys.readouterr()
    assert "threat packs in force have changed" in captured.out
    assert "a pack is broken" in captured.err


def test_the_command_uses_the_stale_after_setting(home, capsys):
    analysed(home, "b1", -60 * 24 * 200, CLEAN)  # 200 days before the fixtures' start
    assert cli.main(["fleet"]) == 0
    assert "days ago" in capsys.readouterr().out
    set_setting(home[0], "stale_after_days", "100000")
    assert cli.main(["fleet"]) == 0
    assert "days ago" not in capsys.readouterr().out


def test_a_doubt_under_a_serious_result_does_not_excuse_it(home, capsys):
    analysed(home, "b1", 10, ROOTED)
    add_bundle(home, "b2", 20, CLEAN, status="failed")
    assert cli.main(["fleet"]) == 0
    out = capsys.readouterr().out
    assert "may have changed since: its last collection was failed" in out
    assert "can't be relied on" not in out


def test_a_host_no_longer_in_the_inventory_says_so_and_is_not_called_old(home, tmp_path, capsys):
    with inventory_transaction() as hosts:
        hosts.add(keyed_host(tmp_path, name="kept"))
    analysed(home, "b1", 10, CLEAN, host="gone")
    assert cli.main(["fleet"]) == 0
    out = capsys.readouterr().out
    assert "checker purge gone" in out and "days ago" not in out


def _boom_on_low(real):
    def check(assessment, *args, **kwargs):
        if assessment["host"] == "odd":
            raise TypeError("odd stored data")
        return real(assessment, *args, **kwargs)

    return check


def test_only_failed_collections_are_not_called_nothing_collected(home):
    add_bundle(home, "b1", 10, CLEAN, status="failed")
    item = fleet_host(home[1], "web01", identity_of(home))
    assert item.state == "collections_failed" and item.last_failed[0] == "failed"


def test_a_host_whose_evidence_was_purged_says_so(home):
    add_to_evidence(home, "b1", 40)
    home[1].record_baseline("web01", "b1", "first", None)
    assert cli.cmd_purge(cli.build_parser().parse_args(["purge", "web01"]), lambda _: "purge") == 0
    assert not home[1].bundles("web01")
    assert fleet_host(home[1], "web01", identity_of(home)).state == "purged"


def test_a_group_filter_does_not_hide_a_host_no_longer_in_the_inventory(home):
    analysed(home, "b", 10, ROOTED, host="removed")
    names = [h.host for h in fleet(home[1], identity_of(home), {"a": "x", "b": "y"}, group="x")]
    assert sorted(names) == ["a", "removed"]


@pytest.mark.parametrize(
    ("change", "kwargs"),
    [("versions", {}), ("prior", {}), ("problems", {"pack_problems": ["gone"]})],
)
def test_what_the_fleet_calls_out_of_date_is_what_the_report_redoes(
    home, monkeypatch, change, kwargs
):
    analysed(home, "b1", 10, CLEAN)
    prior = (0.5, "host") if change == "prior" else (DEFAULT_PRIOR, "default")
    if change == "versions":
        monkeypatch.setattr("checker.report.current_versions", lambda: {"checks": -1})
    assessment = load_assessment(home[1], "b1", identity_of(home))
    analyse, rescore = out_of_date(assessment, prior, None, None, kwargs.get("pack_problems"))
    assert analyse or rescore
    before = len(home[1].assessments("b1"))
    host_report(
        home[1],
        "web01",
        identity_of(home),
        home[3].recipients,
        None,
        prior,
        None,
        None,
        kwargs.get("pack_problems"),
    )
    assert len(home[1].assessments("b1")) == before + 1


def test_nothing_out_of_date_means_the_report_redoes_nothing(home):
    assessment = analysed(home, "b1", 10, CLEAN)
    prior = (assessment["score"]["prior"], assessment["score"]["prior_source"])
    assert out_of_date(assessment, prior) == ([], [])
    host_report(home[1], "web01", identity_of(home), home[3].recipients, None, prior)
    assert len(home[1].assessments("b1")) == 1


class _Whitelist:
    def __init__(self, digest="d", expired=()):
        self._digest, self._expired = digest, list(expired)

    def digest(self):
        return self._digest

    def expired(self):
        return self._expired


def test_a_whitelist_changed_or_expired_means_scoring_again(home):
    analysed(home, "b1", 10, CLEAN)
    assessment = load_assessment(home[1], "b1", identity_of(home))
    assert out_of_date(assessment, None, _Whitelist(), check_packs=False) == (
        [],
        ["the whitelist has changed"],
    )
    assessment["whitelist"] = {"digest": "d", "hash": "d", "expired": []}
    with_hash = whitelist_hash(assessment)
    assert out_of_date(assessment, None, _Whitelist(with_hash, ["rule"]), check_packs=False) == (
        [],
        ["a whitelist rule has expired"],
    )


def _tree(base):
    return {
        str(p.relative_to(base)): (
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "directory",
            p.stat().st_mtime_ns,
        )
        for p in sorted(base.rglob("*"))
    }


def test_the_command_writes_nothing_anywhere_in_the_home(home, capsys):
    analysed(home, "b1", 10, ROOTED)
    assert shipped_newer(home[0])  # a fresh home: a run would adopt the key list now
    before = _tree(home[0])
    assert cli.main(["fleet"]) == 0
    assert _tree(home[0]) == before
    assert not (home[0] / "packs" / "state.json").exists()


def test_the_command_does_not_upgrade_an_old_database(home, capsys):
    analysed(home, "b1", 10, ROOTED)
    home[1]._db.execute("ALTER TABLE advice DROP COLUMN endpoint")
    home[1]._db.commit()
    before = _tree(home[0])
    assert cli.main(["fleet"]) == 0
    assert _tree(home[0]) == before


def test_the_command_on_a_home_not_set_up_creates_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path / "new"))
    assert cli.main(["fleet"]) == 1
    assert "not set up yet" in capsys.readouterr().err
    assert not (tmp_path / "new").exists()


def test_the_read_only_store_refuses_a_write(home):
    store = Store(home[0] / "checker.db", read_only=True)
    with pytest.raises(sqlite3.OperationalError):
        store._db.execute("DELETE FROM bundles")
    store.close()


def test_hostile_titles_and_pack_names_reach_the_terminal_visible(home, capsys, monkeypatch):
    analysed(home, "b1", 10, CLEAN)
    hostile = "evil" + BIDI + chr(27) + "[31m"

    def fake(*args, **kwargs):
        return [
            FleetHost(
                hostile,
                state="analysed",
                band="High",
                probability=0.6,
                exposed={hostile: "vulnerable"},
                unjudged=(hostile,),
            )
        ]

    monkeypatch.setattr(fleet_module, "fleet", fake)
    assert cli.main(["fleet"]) == 0
    out = capsys.readouterr().out
    assert BIDI not in out and chr(27) not in out


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
