"""Scoring (PR 2.1, DESIGN.md §11): likelihood ratios, the prior, caps, the
probability and its band, and the separate hygiene and exposure rating."""

import math

import pytest
from test_snapshot import add_bundle, host_records

from checker import cli
from checker.assess import analyze, load_assessment, prior_for
from checker.evidence import Config
from checker.inventory import Host, Inventory
from checker.report import write_report
from checker.scoring import (
    BAND_RATIOS,
    EXTRA,
    logit,
    percent,
    probability_band,
    score,
)

COMPROMISE = "compromise indicator"


def f(check="x.check", band="high", category=COMPROMISE, entities=(), **extra):
    return {
        "check": check,
        "title": f"{check} {band}",
        "category": category,
        "band": band,
        "entities": list(entities),
        "uncertain": None,
        **extra,
    }


def odds(p):
    return p / (1 - p)


# --- the model ---------------------------------------------------------------------------


def test_the_designs_worked_numbers(monkeypatch):
    # DESIGN.md §11.3: prior 2%, one LR 20 → 29%; add an LR 5 → 67%.
    assert score([f(band="high")], 0.02)["probability"] == pytest.approx(0.29, abs=0.005)
    monkeypatch.setitem(__import__("checker.scoring").scoring.OVERRIDES, ("y.check", None), 5.0)
    both = score([f(band="high"), f(check="y.check", band="medium")], 0.02)
    assert both["probability"] == pytest.approx(0.67, abs=0.005)


def test_no_findings_is_the_prior():
    result = score([], 0.02)
    assert result["probability"] == pytest.approx(0.02)
    assert result["band"] == "Low" and result["contributors"] == []


def test_only_compromise_indicators_move_the_probability():
    findings = [
        f(band="critical", category="hygiene"),
        f(band="high", category="exposure"),
        f(band="info"),
    ]
    result = score(findings, 0.02)
    assert result["probability"] == pytest.approx(0.02)
    assert result["hygiene_and_exposure"] == {
        "band": "critical",
        "counts": {"hygiene": {"critical": 1}, "exposure": {"high": 1}},
    }


def test_each_finding_carries_its_ratio_and_contribution():
    findings = [f(band="medium"), f(check="y", band="info")]
    score(findings, 0.02)
    assert findings[0]["ratio"] == BAND_RATIOS["medium"]
    assert findings[0]["contribution"] == pytest.approx(math.log(4), abs=1e-4)
    assert findings[1]["ratio"] == 1.0 and findings[1]["contribution"] == 0


def test_uncertain_findings_count_half():
    sure = score([f(band="high")], 0.02)["log_odds"]
    unsure = score([f(band="high", uncertain="not fully collected")], 0.02)["log_odds"]
    assert unsure - logit(0.02) == pytest.approx((sure - logit(0.02)) / 2, abs=1e-3)


def test_suppressed_findings_dont_count():
    result = score([f(band="critical", suppressed_by={"rule": "x"})], 0.02)
    assert result["probability"] == pytest.approx(0.02)


def test_one_file_seen_by_two_checks_counts_once_plus_a_little():
    # A set-user-ID shell in /tmp: files.scratch and files.privileged.
    findings = [
        f("files.scratch", "high", entities=["path:/tmp/.sh"]),
        f("files.privileged", "high", entities=["path:/tmp/.sh"]),
    ]
    result = score(findings, 0.02)
    assert result["log_odds"] - logit(0.02) == pytest.approx(math.log(20) + EXTRA, abs=1e-3)
    assert [c["capped"] for c in result["contributors"]] == [None, "group"]


def test_groups_join_through_a_shared_process_transitively():
    findings = [
        f("a", "high", entities=["pid:7"]),
        f("b", "high", entities=["pid:7", "path:/tmp/x"]),
        f("c", "high", entities=["path:/tmp/x"]),
    ]
    result = score(findings, 0.02)
    assert result["log_odds"] - logit(0.02) == pytest.approx(math.log(20) + EXTRA, abs=1e-3)


def test_one_account_in_two_findings_is_two_signals():
    # A new key for root and a direct root login are different evidence.
    findings = [
        f("ssh.authorized_keys", "high", entities=["account:root"]),
        f("ssh.login", "medium", entities=["account:root"]),
    ]
    result = score(findings, 0.02)
    assert result["log_odds"] - logit(0.02) == pytest.approx(math.log(20 * 4), abs=1e-3)


def test_a_family_adds_at_most_a_doubling_however_many_it_finds():
    many = [f("ssh.login", "medium", entities=[f"address:198.51.100.{i}"]) for i in range(50)]
    result = score(many, 0.02)
    assert result["log_odds"] - logit(0.02) == pytest.approx(math.log(4) + EXTRA, abs=1e-3)
    assert all(c["capped"] == "family" for c in result["contributors"][1:])


def test_contributors_are_largest_first_with_shares_summing_to_one():
    result = score([f("a", "medium"), f("b", "critical"), f("c", "low")], 0.02)
    assert [c["check"] for c in result["contributors"]] == ["b", "a", "c"]
    assert sum(c["share"] for c in result["contributors"]) == pytest.approx(1, abs=1e-3)


@pytest.mark.parametrize(
    ("p", "band"),
    [(0.0, "Low"), (0.0999, "Low"), (0.10, "Elevated"), (0.5, "High"), (0.9, "Critical")],
)
def test_probability_bands(p, band):
    assert probability_band(p) == band


def test_a_prior_must_be_a_probability():
    with pytest.raises(ValueError):
        score([], 0)
    with pytest.raises(ValueError):
        score([], 1)


def test_what_typical_findings_add_up_to():
    # From a 2% prior (odds 0.0204): one high → 29%, one critical → 67%,
    # two highs → 89%, a high and a critical → 98%.
    assert score([f("a", "high")], 0.02)["band"] == "Elevated"
    assert score([f("a", "critical")], 0.02)["band"] == "High"
    assert score([f("a", "high"), f("b", "high")], 0.02)["band"] == "High"
    assert score([f("a", "high"), f("b", "critical")], 0.02)["band"] == "Critical"


# --- priors ------------------------------------------------------------------------------


def test_the_prior_comes_from_the_host_then_its_group_then_the_configuration():
    config = Config(recipients=["x"], prior=0.03, group_priors={"web": 0.05})
    inventory = Inventory(
        hosts=[
            Host(name="a", address="192.0.2.1", user="u", group="web", prior=0.2),
            Host(name="b", address="192.0.2.2", user="u", group="web"),
            Host(name="c", address="192.0.2.3", user="u", group="db"),
        ]
    )
    assert prior_for("a", config, inventory) == (0.2, "host")
    assert prior_for("b", config, inventory) == (0.05, "group web")
    assert prior_for("c", config, inventory) == (0.03, "configuration")
    assert prior_for("gone", config, inventory) == (0.03, "configuration")


def test_priors_are_checked():
    with pytest.raises(ValueError):
        Config(recipients=["x"], prior=1.5)
    with pytest.raises(ValueError):
        Config(recipients=["x"], group_priors={"web": 0})
    with pytest.raises(ValueError):
        Host(name="a", address="192.0.2.1", user="u", prior=-0.1)


# --- assessments, the command and the report ----------------------------------------------


def test_an_assessment_is_scored_and_stored_with_its_score(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0))))
    assessment = analyze(store, "web01", identity, config.recipients, prior=(0.05, "host"))
    assert assessment["format"] == 2 and assessment["versions"]["scoring"] == 1
    scored = assessment["score"]
    assert scored["prior"] == 0.05 and scored["prior_source"] == "host"
    assert scored["contributors"][0]["check"] == "account.uid0"
    assert scored["band"] in ("High", "Critical")
    assert load_assessment(store, "b2", identity)["score"] == scored


def test_cli_prints_the_score(home, capsys):
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0))))
    assert cli.main(["analyze", "web01"]) == 0
    out = capsys.readouterr().out
    assert "probability of compromise" in out and "(prior 2%, configuration)" in out
    assert "An account other than root has UID 0 (×100)" in out


def test_the_report_shows_the_score_and_rescores_for_a_new_prior(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    analyze(store, "web01", identity, config.recipients)
    path = write_report(store, ["web01"], identity, config.recipients, base / "reports")
    html = path.read_text()
    assert "Probability of compromise" in html and "2% Low" in html
    before = len(store.assessments("b1"))
    write_report(
        store,
        ["web01"],
        identity,
        config.recipients,
        base / "reports",
        priors=lambda _: (0.5, "host"),
    )
    assert len(store.assessments("b1")) == before + 1
    assert load_assessment(store, "b1", identity)["score"]["prior"] == 0.5


# --- from the review of 2.1a --------------------------------------------------------------


def test_the_score_never_depends_on_the_order_of_the_findings():
    import itertools

    findings = [
        f("files.scratch", "high", entities=["path:/tmp/.sh"]),
        f("files.privileged", "high", entities=["path:/tmp/.sh"]),
        f("files.privileged", "high", entities=["path:/usr/local/bin/x"]),
        f("ssh.login", "medium", entities=["address:198.51.100.1"]),
        f("ssh.login", "medium", entities=["address:198.51.100.2"], uncertain="partial"),
    ]
    results = {
        score([dict(x) for x in order], 0.02)["log_odds"]
        for order in itertools.permutations(findings)
    }
    assert len(results) == 1
    # The shell is one behaviour (high + a doubling); the second privileged
    # file is another, in full; the logins are a medium and its family's
    # doubling at most.
    expected = math.log(20) + EXTRA + math.log(20) + math.log(4) + math.log(4) / 2
    assert results.pop() - logit(0.02) == pytest.approx(expected, abs=1e-3)


def test_only_findings_a_cap_cut_are_marked():
    findings = [f("a", "high"), f("a", "low")]  # the low adds less than a doubling
    result = score(findings, 0.02)
    assert [c["capped"] for c in result["contributors"]] == [None, None]


def test_the_rating_leaves_out_suppressed_findings():
    findings = [f(band="high", category="hygiene", suppressed_by={"rule": "x"})]
    assert score(findings, 0.02)["hygiene_and_exposure"] == {"band": "none", "counts": {}}


@pytest.mark.parametrize(
    ("p", "shown"),
    [
        (0.4999, "49%"),
        (0.8994, "89%"),
        (0.0996, "9%"),
        (0.02, "2%"),
        (0.004, "0.4%"),
        (0.0004, "<0.1%"),
        (0.9999, "99%"),
    ],
)
def test_percentages_never_cross_a_band_edge(p, shown):
    assert percent(p) == shown
    if shown[0] != "<":
        assert probability_band(float(shown.rstrip("%")) / 100) == probability_band(p)


def inventory_with(**prior):
    from checker.inventory import inventory_transaction

    with inventory_transaction() as hosts:
        hosts.add(Host(name="web01", address="192.0.2.1", user="scanner", **prior))


def test_cli_analyze_and_report_use_the_hosts_prior(home, capsys):
    base, store, identity, config = home
    inventory_with(prior=0.2)
    add_bundle(home, "b1", 0, host_records())
    assert cli.main(["analyze", "web01"]) == 0
    assert "(prior 20%, host)" in capsys.readouterr().out
    assert cli.main(["report", "web01", "--output", str(base / "r.html")]) == 0
    assert "from a prior of 20% (host)" in (base / "r.html").read_text()


def test_hosts_add_keeps_its_prior(home):
    from checker.inventory import load_inventory

    args = ["hosts", "add", "web01", "--address", "192.0.2.1", "--user", "u", "--prior", "0.05"]
    assert cli.main(args) == 0
    assert load_inventory().get("web01").prior == 0.05


def test_an_invalid_inventory_is_an_error_not_a_traceback(home, capsys):
    from checker.inventory import hosts_file

    add_bundle(home, "b1", 0, host_records())
    hosts_file().write_text("hosts:\n- {name: web01, address: 192.0.2.1, user: u, prior: 1.5}\n")
    assert cli.main(["analyze", "web01"]) == 1
    err = capsys.readouterr().err
    assert "the inventory" in err and "is invalid" in err
    assert cli.main(["report", "web01"]) == 1
    assert "is invalid" in capsys.readouterr().err


def test_the_index_summary_holds_the_probability_and_band(home):
    import json as _json

    from checker.evidence import open_text

    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    analyze(store, "web01", identity, config.recipients)
    summary = _json.loads(open_text(store.assessments("b1")[-1]["summary"], identity))
    assert summary["band"] == "Low" and summary["probability"] == pytest.approx(0.02)


def test_a_new_prior_rescores_without_running_the_checks(home, monkeypatch):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    analyze(store, "web01", identity, config.recipients)

    def no_analysis(*args, **kwargs):
        raise AssertionError("the checks ran again")

    monkeypatch.setattr("checker.report.analyze", no_analysis)
    write_report(
        store,
        ["web01"],
        identity,
        config.recipients,
        base / "reports",
        priors=lambda _: (0.3, "group web"),
    )
    latest = load_assessment(store, "b1", identity)["score"]
    assert (latest["prior"], latest["prior_source"]) == (0.3, "group web")


def test_a_format_1_assessment_is_analysed_again(home):
    from checker.assess import store_assessment

    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    old = analyze(store, "web01", identity, config.recipients)
    del old["score"], old["format"]
    old["versions"] = {"checks": 1, "parser": old["versions"]["parser"], "snapshot": 1}
    store_assessment(store, store.bundle("b1"), config.recipients, old)
    write_report(store, ["web01"], identity, config.recipients, base / "reports")
    assert load_assessment(store, "b1", identity)["format"] == 2


def test_contributor_titles_are_escaped(home):
    from checker.report import host_report, render

    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0))))
    report = host_report(store, "web01", identity, config.recipients)
    report.assessment["score"]["contributors"][0]["title"] = "<script>alert(1)</script>"
    html = render([report], ("op", "ctl"))
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
