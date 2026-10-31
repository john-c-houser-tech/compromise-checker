"""Every finding the tool can make has plain words, and none overclaims (PR 5.4)."""

import importlib
import pkgutil

import pytest

pytest.importorskip("django")

import checker.checks as checks  # noqa: E402
from checker.web.finding_words import BAND_WORDS, BY_VARIANT, SECTIONS, WORDS, words_for  # noqa: E402
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
    "text", [t for pair in [*WORDS.values(), *BY_VARIANT.values()] for t in pair]
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


def test_a_variant_wins_over_the_check():
    assert "refused" in words_for("web.exploit", "refused")[0]
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
    assert details["nothing_found"] is False


def test_information_is_folded_and_hidden_findings_are_apart():
    details = host_details(
        {"findings": [finding(band="info"), finding(band="high", suppressed_by="rule1")]}
    )
    assert len(details["sections"][0]["minor"]) == 1 and details["sections"][0]["findings"] == []
    assert len(details["suppressed"]) == 1


def test_nothing_found_is_said():
    assert host_details({"findings": []})["nothing_found"] is True


def test_no_analysis_has_nothing_to_show_and_does_not_claim_nothing_was_found():
    assert host_details(None)["nothing_found"] is False


def test_how_far_the_logs_go_back():
    reach = {"auth_log": {"days": 3.5}, "auth_journal": {"days": 40.2}, "web": {"days": 900}}
    assert host_details({"coverage": {"log_reach": reach}})["reach"] == 40


def test_gaps_in_plain_words_and_unknown_ones_as_they_are():
    gaps = ["no authentication log events: x", "the host's clock is -1200 s off", "something new"]
    shown = host_details({"coverage": {"gaps": gaps}})["gaps"]
    assert shown[0].startswith("Any record of logins") and "clock is off" in shown[1]
    assert shown[2] == "something new"
