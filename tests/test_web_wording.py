"""What the page tells someone who has never read a log (PR 5.3). Above all, it must
never sound more reassuring than the evidence."""

from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("django")

from checker.fleet import UNREADABLE, FleetHost  # noqa: E402
from checker.web.wording import DOUBTS, ago, headline, plain_doubt, row, rows_for  # noqa: E402

NOW = datetime(2027, 1, 2, 12, tzinfo=UTC)


def analysed(band, **extra):
    return FleetHost("h", state="analysed", band=band, probability=0.5, **extra)


@pytest.mark.parametrize(
    ("band", "tone", "words"),
    [
        ("Critical", "critical", "Strong signs"),
        ("High", "high", "Signs of a break-in"),
        ("Elevated", "elevated", "warning signs"),
        ("Low", "low", "No strong signs"),
    ],
)
def test_each_band_in_plain_words(band, tone, words):
    made = row(analysed(band), NOW)
    assert made.tone == tone and words in made.verdict


def test_no_verdict_claims_a_server_is_clean_or_safe():
    for band in ("Critical", "High", "Elevated", "Low"):
        made = row(analysed(band), NOW)
        text = f"{made.verdict} {made.action}".lower()
        assert "clean" not in text and "safe" not in text and "no break-in" not in text


@pytest.mark.parametrize("band", ["Low", "Elevated"])
def test_doubt_takes_the_reassurance_away(band):
    made = row(analysed(band, doubts=("collected more than 3 days ago",)), NOW)
    assert made.tone == "unknown" and "fresh check" in made.action
    assert "hasn't been checked recently" in made.notes[0]


@pytest.mark.parametrize("band", ["High", "Critical"])
def test_doubt_never_softens_a_serious_result(band):
    plain = row(analysed(band), NOW)
    made = row(analysed(band, doubts=("its last collection was failed",)), NOW)
    assert made.tone == plain.tone and made.verdict == plain.verdict
    assert made.action.startswith(plain.action) and "may have changed" in made.action


@pytest.mark.parametrize(
    "state",
    ["not_analysed", "no_evidence", "collections_failed", "purged"],
)
def test_no_result_never_reads_as_fine(state):
    made = row(FleetHost("h", state=state), NOW)
    assert made.tone == "unknown" and made.verdict == "Nothing to go on yet" and made.action


@pytest.mark.parametrize("why", list(UNREADABLE))
def test_an_unreadable_result_is_loud_and_says_why(why):
    made = row(FleetHost("h", state="unreadable", unreadable_why=why), NOW)
    assert made.tone == "critical"
    assert made.notes[0].lower() == UNREADABLE[why].lower()


def test_the_last_readable_result_is_not_shown_as_the_current_one():
    made = row(FleetHost("h", state="unreadable", last_readable_band="High"), NOW)
    assert made.verdict == "This result can't be read"
    assert any("last result that could be read" in n for n in made.notes)


@pytest.mark.parametrize(
    ("doubt", "words"),
    [
        ("its last collection was failed", "didn't finish"),
        ("this collection was partial (module x: timeout)", "part of this server"),
        ("a newer collection hasn't been analysed", "newer check"),
        ("collected more than 3 days ago", "checked recently"),
        ("checks that couldn't run: a", "couldn't run"),
        ("it can see less than before: x", "covers their tracks"),
        ("no authentication log events: y", "logins"),
        ("no system journal events: y", "own log"),
        ("the whitelist has changed", "Settings have changed"),
        ("a whitelist rule has expired", "Settings have changed"),
        ("the threat packs in force have changed", "Settings have changed"),
        ("the host's starting probability has changed", "Settings have changed"),
        ("its whitelist can't be read", "accepted activity"),
        ("part of its analysis couldn't be worked out", "couldn't be worked out"),
    ],
)
def test_each_doubt_the_tool_gives_has_plain_words(doubt, words):
    assert words in plain_doubt(doubt)


def test_a_doubt_with_no_wording_is_still_shown():
    assert plain_doubt("something new") == "something new"


def test_every_reason_for_doubt_in_the_fleet_has_a_wording():
    """A new reason added to the fleet view must not reach people in the tool's jargon."""
    import re
    from pathlib import Path

    from checker import fleet, report

    text = Path(fleet.__file__).read_text() + Path(report.__file__).read_text()
    starts = [start for start, _ in DOUBTS]
    said = re.findall(r'doubts(?:\.append\(|\s*=\s*\()f?"([^"{]+)', text)
    said += re.findall(r'(?:analyse|rescore|reasons)\.append\(f?"([^"{]+)', text)
    assert said
    for reason in said:
        assert any(reason.startswith(s) or s.startswith(reason) for s in starts), reason


def test_several_settings_reasons_are_said_once():
    doubts = ("the whitelist has changed", "the host's starting probability has changed")
    assert len(row(analysed("Low", doubts=doubts), NOW).notes) == 1


def test_warnings_not_seen_are_not_called_gone():
    made = row(analysed("Low", not_seen=2), NOW)
    assert any("doesn't mean they've gone" in n for n in made.notes)
    assert not any("gone since" in n for n in made.notes)


def test_warnings_hidden_by_a_list_are_said():
    assert any("hidden" in n for n in row(analysed("Low", suppressed=1), NOW).notes)


def test_new_findings_are_listed_and_the_band_move_said_once():
    host = analysed(
        "Critical",
        band_before="Low",
        changes=("h: Low to Critical (98.8%)", "h: new critical: An account has UID 0"),
    )
    made = row(host, NOW)
    assert made.changes == ("An account has UID 0",)
    assert any("At the check before: no strong signs" in n for n in made.notes)


def test_a_finding_whose_title_says_to_is_still_listed():
    made = row(analysed("High", changes=("h: new high: A login to root from a new address",)), NOW)
    assert made.changes == ("A login to root from a new address",)


def test_exposure_lines_are_said_once():
    line = "h: exposed to threat pack p1 v1 (vulnerable now)"
    host = analysed("High", changes=(line,), exposed={"p1": "vulnerable"})
    made = row(host, NOW)
    assert made.changes == () and len(made.exposures) == 1


def test_a_line_in_no_usual_form_is_shown_not_dropped():
    assert row(analysed("High", changes=("odd line",)), NOW).changes == ("odd line",)


def test_exposures_in_plain_words():
    host = analysed("Low", exposed={"p1": "vulnerable", "p2": "fixed", "p3": "can't judge"})
    text = " ".join(row(host, NOW).exposures)
    assert "open to this threat now: p1" in text
    assert "is fixed now: p2" in text and "can't tell: p3" in text


@pytest.mark.parametrize(
    ("before", "words"),
    [
        (timedelta(minutes=5), "within the last hour"),
        (timedelta(hours=1), "1 hour ago"),
        (timedelta(hours=5), "5 hours ago"),
        (timedelta(days=1), "1 day ago"),
        (timedelta(days=11), "11 days ago"),
    ],
)
def test_how_long_ago(before, words):
    assert words in ago((NOW - before).isoformat(), NOW)


def test_a_date_that_cannot_be_read_says_nothing():
    assert ago("not a date", NOW) == "" and ago(None, NOW) == ""


@pytest.mark.parametrize(
    ("bands", "words", "tone"),
    [
        (["Critical", "Low", "Low"], "1 of your 3 servers needs attention now.", "critical"),
        (["Critical", "High", "Low"], "2 of your 3 servers need attention now.", "critical"),
        (["Critical"], "Your server needs attention now.", "critical"),
        (["Elevated", "Low"], "1 of your 2 servers has some warning signs.", "elevated"),
        (["Low", "Low"], "No strong signs of a break-in on your 2 servers.", "low"),
        (["Low"], "No strong signs of a break-in on your server.", "low"),
    ],
)
def test_the_answer_at_the_top(bands, words, tone):
    assert headline(rows_for([analysed(b) for b in bands], NOW)) == (words, tone)


def test_the_answer_never_reassures_past_a_server_nobody_can_vouch_for():
    rows = rows_for([analysed("Low"), FleetHost("x", state="no_evidence")], NOW)
    assert headline(rows) == ("1 of your 2 servers can't be vouched for right now.", "unknown")
    doubted = rows_for([analysed("Low", doubts=("collected more than 3 days ago",))], NOW)
    assert headline(doubted)[1] == "unknown"


def test_a_serious_server_leads_even_with_others_unknown():
    rows = rows_for([FleetHost("x", state="no_evidence"), analysed("High")], NOW)
    assert headline(rows)[1] == "critical"


def test_no_servers():
    assert headline([]) == ("No servers yet.", "unknown")


def test_an_unreadable_result_makes_the_answer_urgent():
    rows = rows_for([FleetHost("x", state="unreadable"), analysed("Low")], NOW)
    assert "1 of your 2 servers needs attention" in headline(rows)[0]
