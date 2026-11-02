"""Every finding the tool can make has plain words, and none overclaims (PR 5.4)."""

import importlib
import pkgutil

import pytest

pytest.importorskip("django")

import checker.checks as checks  # noqa: E402
from checker.web.finding_words import (  # noqa: E402
    BAND_WORDS,
    BY_TITLE,
    BY_VARIANT,
    SECTIONS,
    WORDS,
    words_for,
)
from checker.web.wording import host_details  # noqa: E402

for module in pkgutil.iter_modules(checks.__path__):
    importlib.import_module(f"checker.checks.{module.name}")


def test_every_check_has_plain_words():
    """A new check must not reach people in the tool's jargon."""
    missing = {c.id for c in checks.REGISTRY} - set(WORDS)
    assert not missing


def test_no_words_for_checks_that_do_not_exist():
    assert not set(WORDS) - {c.id for c in checks.REGISTRY}


def test_each_variant_named_exists():
    variants = {c.id: set(c.variants or ()) for c in checks.REGISTRY}
    for check, variant in BY_VARIANT:
        assert variant in variants[check], (check, variant)


def test_every_band_and_category_has_words():
    assert set(BAND_WORDS) == set(checks.BANDS)
    assert set(SECTIONS) == set(checks.CATEGORIES)


@pytest.mark.parametrize(
    "text",
    [
        t
        for pair in [*WORDS.values(), *BY_VARIANT.values(), *(w for _, _, w in BY_TITLE)]
        for t in pair
    ],
)
def test_plain_words_are_sentences_with_no_jargon_and_no_verdict(text):
    assert text[0].isupper() and text.endswith(".")
    lowered = text.lower()
    for word in (
        "uid",
        "sudo",
        "ssh",
        "daemon",
        "shell",
        "root",
        "pam",
        "kernel",
        "you are safe",
        "is clean",
    ):
        assert word not in lowered.split(), (word, text)


def test_each_title_named_is_still_one_the_checks_write():
    from pathlib import Path

    source = "".join(p.read_text() for p in Path(checks.__file__).parent.glob("*.py"))
    for _, start, _ in BY_TITLE:
        assert start in source, start


@pytest.mark.parametrize(
    ("check", "title", "words"),
    [
        (
            "process.executable",
            "A process still running a replaced program (restart)",
            "normal after updates",
        ),
        (
            "package.changed",
            "The package managers' checksum lists changed since",
            "Installs and updates",
        ),
        ("files.web", "A secrets or repository file inside a web root", "download"),
        ("account.uid0", "Accounts sharing a UID", "identity number"),
    ],
)
def test_routine_findings_do_not_blame_attackers(check, title, words):
    assert words in words_for(check, None, title)[0]


def test_a_title_is_not_trusted_for_a_different_check():
    assert (
        words_for("account.uid0", None, "A secrets or repository file")[0]
        == WORDS["account.uid0"][0]
    )


def test_restarting_is_never_advised_without_the_evidence_warning():
    for _meaning, todo in [*WORDS.values(), *BY_VARIANT.values(), *(w for _, _, w in BY_TITLE)]:
        if "Restart" in todo:
            assert "get advice" in todo or "unless" in todo, todo


def test_a_variant_wins_over_the_check():
    assert "did no harm" in words_for("web.exploit", "refused")[0]
    assert words_for("web.exploit", "other") == WORDS["web.exploit"]


@pytest.mark.parametrize("check", [["a"], {"a": 1}, None, 5, "no.such"])
def test_odd_values_get_the_fallback(check):
    assert words_for(check, None)[0]


def finding(**extra):
    return {"check": "account.uid0", "category": "compromise indicator", "band": "low", **extra}


def test_findings_are_split_by_kind_and_most_serious_first():
    details = host_details(
        {
            "findings": [
                finding(band="low"),
                finding(band="critical"),
                finding(category="hygiene", band="medium"),
            ]
        }
    )
    assert [s["title"] for s in details["sections"]][0] == "Signs of a break-in"
    assert [f["band_words"] for f in details["sections"][0]["findings"]] == [
        "Very serious",
        "Minor",
    ]
    assert details["sections"][1]["title"].startswith("Weak spots")
    assert details["caveat"] is None


def test_information_is_folded_and_hidden_findings_are_apart():
    details = host_details(
        {"findings": [finding(band="info"), finding(band="high", suppressed_by="rule1")]}
    )
    assert len(details["sections"][0]["minor"]) == 1 and details["sections"][0]["findings"] == []
    assert len(details["suppressed"]) == 1


def test_no_warnings_is_said_without_claiming_nothing_happened():
    assert "doesn't prove" in host_details({"findings": []})["caveat"]


def test_only_information_still_carries_the_caveat():
    details = host_details({"findings": [finding(band="info")]})
    assert "doesn't prove" in details["caveat"]


def test_all_hidden_does_not_read_as_nothing_found():
    details = host_details({"findings": [finding(band="critical", suppressed_by="r")]})
    assert "1 hidden" in details["caveat"] and "doesn't prove" not in details["caveat"]
    assert details["suppressed"][0]["band_words"] == "Very serious"


def test_a_finding_a_threat_raised_is_never_folded_and_comes_first():
    details = host_details(
        {"findings": [finding(band="high"), finding(band="info", raised_by_pack="p1")]}
    )
    shown = details["sections"][0]["findings"]
    assert shown[0]["raised_by"] == "p1" and details["sections"][0]["minor"] == []


def test_a_finding_in_no_known_category_still_shows():
    details = host_details({"findings": [finding(category="new kind", band="high")]})
    assert details["sections"][0]["title"] == "Other findings"
    assert details["caveat"] is None


def test_a_maintenance_window_lowering_a_finding_is_said():
    details = host_details({"findings": [finding(band="info", maintenance={"band": "high"})]})
    assert details["sections"][0]["minor"][0]["lowered"] is True


def test_no_analysis_has_nothing_to_show_and_does_not_claim_nothing_was_found():
    assert host_details(None)["caveat"] is None


@pytest.mark.parametrize("days", [float("nan"), float("inf"), "x", True])
def test_odd_log_reach_is_not_a_crash(days):
    assert host_details({"coverage": {"log_reach": {"auth_log": {"days": days}}}})["reach"] is None


def test_logs_under_a_day_are_said():
    reach = host_details({"coverage": {"log_reach": {"auth_log": {"days": 0.4}}}})["reach"]
    assert "less than a day" in reach and "cleared" in reach


def test_how_far_the_logs_go_back():
    reach = {"auth_log": {"days": 3.5}, "auth_journal": {"days": 40.2}, "web": {"days": 900}}
    assert "40 days" in host_details({"coverage": {"log_reach": reach}})["reach"]


def test_gaps_in_plain_words_and_unknown_ones_as_they_are():
    gaps = ["no authentication log events: x", "the host's clock is -1200 s off", "something new"]
    shown = host_details({"coverage": {"gaps": gaps}})["gaps"]
    assert shown[0].startswith("Any record of logins") and "clock is off" in shown[1]
    assert shown[2] == "something new"
