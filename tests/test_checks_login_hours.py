"""Logins at unusual hours (Phase 3 decision 4, PR 3.2b)."""

from datetime import UTC, datetime, timedelta

import pytest

from checker.checks import Context, run_checks
from checker.checks.accounts import _hour_ranges, login_hours
from checker.events import Event
from checker.snapshot import Section, Snapshot

START = datetime(2026, 9, 1, tzinfo=UTC)


def login(day, hour, user="jch", address="192.0.2.5", own=False, port=None):
    moment = (START + timedelta(days=day, hours=hour)).isoformat()
    fields = {"user": user, "address": address, "port": port or 40000 + day * 24 + hour}
    return Event(moment, moment, "auth_journal", "ssh.login.accepted", fields, own_session=own)


def snap():
    return Snapshot({"masking_version": 6, "full": True}, {"accounts": Section({})})


def office_hours(days=30, user="jch"):
    """A month of logins between 08:00 and 11:00 UTC."""
    return [login(d, 8 + d % 4, user) for d in range(days)]


def context(current, earlier=(), previous_day=30):
    previous = (START + timedelta(days=previous_day)).isoformat()
    return Context(
        "web01", "b2", list(current), snap(),
        earlier_events=lambda: [list(earlier)], previous_time=previous,
    )  # fmt: skip


def test_a_login_at_an_unusual_hour_is_a_low_finding():
    history = office_hours()
    late = login(31, 3)
    found = login_hours(context(history + [late, login(32, 9)], earlier=history))
    (finding,) = found
    assert finding.check == "ssh.login_hours" and finding.band == "low"
    assert finding.category == "compromise indicator"
    assert finding.summary.startswith("jch: 1 login(s) at 03:00 UTC; usually 07-12 UTC")
    assert finding.entities == ["account:jch"]
    assert len(finding.evidence) == 1


def test_overlapping_bundles_count_each_login_once():
    # 6 distinct logins over 25 days, logged by both bundles: counted twice
    # they would pass for 12 and be judged.
    days = (0, 5, 10, 15, 20, 25)
    history = [login(day, 9) for day in days]
    again = [login(day, 9) for day in days]  # the earlier bundle's own copies
    ctx = context(history + [login(31, 3)], earlier=again)
    assert login_hours(ctx) == []
    assert ctx.gaps == [
        "login hours not judged for 1 account: fewer than 10 logins or 21 days of history"
    ]


def test_too_short_a_history_is_a_coverage_gap_not_a_finding():
    history = [login(d % 5, 8, port=1000 + d) for d in range(20)]  # 20 logins in 5 days
    ctx = context(history + [login(31, 3)])
    assert login_hours(ctx) == [] and "not judged for 1 account" in ctx.gaps[0]


def test_the_margin_covers_summer_time():
    history = office_hours()
    assert login_hours(context(history + [login(31, 12), login(31, 7)])) == []


def test_only_logins_since_the_previous_collection_are_judged():
    history = office_hours()
    old_odd = login(29, 3)  # before the previous collection: history, not judged
    found = login_hours(context(history + [old_odd, login(31, 15)]))
    assert [f.summary.split(";")[0] for f in found] == ["jch: 1 login(s) at 15:00 UTC"]
    assert login_hours(context(history + [old_odd])) == []


def test_the_tools_own_logins_and_its_scanner_account_dont_count():
    history = office_hours() + office_hours(user="scanner")
    own = login(31, 2, user="scanner", own=True)
    later_scanner = login(31, 23, user="scanner")  # a past run's login, seen in the logs
    ctx = context(history + [own, later_scanner, login(31, 9)])
    assert login_hours(ctx) == [] and ctx.gaps == []  # the scanner isn't judged at all


def test_a_new_account_isnt_judged_by_this_check():
    ctx = context(office_hours() + [login(31, 3, user="newbie")])
    assert login_hours(ctx) == [] and "not judged for 1 account" in ctx.gaps[0]


def test_the_gap_reaches_the_coverage_through_run_checks():
    ctx = context([login(31, 3)])
    run_checks(ctx)
    assert any(g.startswith("login hours not judged") for g in ctx.gaps)


def test_hour_ranges():
    assert _hour_ranges({8, 9, 10, 17}) == "08-10, 17"
    assert _hour_ranges({23, 0, 1, 12}) == "23-01, 12"
    assert _hour_ranges(set(range(24))) == "00-23"


def test_a_checks_gap_is_stored_in_the_assessments_coverage(home, monkeypatch):
    from test_snapshot import add_bundle, host_records

    import checker.assess

    real = checker.assess.evaluate

    def with_a_gap(context, *args, **kwargs):
        context.gaps.append("login hours not judged for 2 accounts: test")
        return real(context, *args, **kwargs)

    monkeypatch.setattr(checker.assess, "evaluate", with_a_gap)
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    assessment = checker.assess.analyze(store, "web01", identity, config.recipients)
    assert "login hours not judged for 2 accounts: test" in assessment["coverage"]["gaps"]


# --- What the review of 3.2b found ---------------------------------------------------------------


def test_copies_with_different_corrected_times_are_one_login():
    """Each bundle corrects the host's clock by its own measured offset."""

    def copy(day, offset_us):
        event = login(day, 9)
        shifted = datetime.fromisoformat(event.corrected) + timedelta(microseconds=offset_us)
        return Event(event.time, shifted.isoformat(), "auth_log", event.type, event.fields)

    current = [login(0, 9), login(22, 9), login(31, 3)]
    earlier = [copy(day, n) for n in range(1, 5) for day in (0, 22)]  # 4 more bundles
    ctx = context(current, earlier=earlier)
    assert login_hours(ctx) == [] and "not judged for 1 account" in ctx.gaps[0]


def test_each_login_is_judged_against_the_logins_before_it():
    """Three 03:00 logins: the first two are odd; by the third, 03:00 has
    come on two days and is usual. Later logins mustn't make earlier ones
    usual."""
    month = office_hours()
    ctx = Context("web01", "b1", month + [login(d, 3) for d in (31, 32, 33)], snap())
    (finding,) = login_hours(ctx)
    assert finding.summary.startswith("jch: 2 login(s) at 03:00")


def test_a_first_analysis_can_flag():
    month = office_hours()
    ctx = Context("web01", "b1", month + [login(31, 3)], snap())  # no previous collection
    found = login_hours(ctx)
    assert [f.summary.split(";")[0] for f in found] == ["jch: 1 login(s) at 03:00 UTC"]


def test_the_scanner_known_from_the_session_isnt_judged_even_behind_nat():
    history = [login(d, 2, user="scanner") for d in range(30)]  # unmarked: NAT
    ctx = context(history + [login(31, 14, user="scanner")])
    assert len(login_hours(ctx)) == 1  # without knowing, it looks odd
    ctx = context(history + [login(31, 14, user="scanner")])
    ctx.scanner = "scanner"
    assert login_hours(ctx) == []


def test_an_account_the_tool_once_used_is_still_judged_later():
    past_run = login(10, 2, user="root", own=True)  # once collected as root
    earlier = [past_run] + office_hours(user="root")
    ctx = context(office_hours(user="root") + [login(31, 3, user="root")], earlier=earlier)
    assert [f.entities for f in login_hours(ctx)] == [["account:root"]]


def test_past_runs_own_logins_dont_count_as_history():
    runs = [login(10, 2, user="jch", own=True), login(11, 2, user="jch", own=True)]
    again = [login(10, 2, user="jch"), login(11, 2, user="jch")]  # later logs, unmarked
    found = login_hours(context(office_hours() + again + [login(31, 2)], earlier=runs))
    assert len(found) == 1  # 02:00 isn't usual just because past runs logged in then


def test_one_odd_login_doesnt_make_its_hour_usual():
    history = office_hours() + [login(29, 3)]
    first = Context("web01", "b1", history + [login(31, 3)], snap())
    (finding,) = login_hours(first)
    assert finding.summary.startswith("jch: 2 login(s) at 03:00")  # both, not just the first


@pytest.mark.sqlite_only
def test_analyze_tells_the_check_the_session_user(home, monkeypatch):
    import json as jsonlib

    from test_snapshot import add_bundle, host_records

    import checker.assess
    from checker.evidence import seal_text

    seen = {}
    real = checker.assess.evaluate

    def capture(context, *args, **kwargs):
        seen["scanner"] = context.scanner
        return real(context, *args, **kwargs)

    monkeypatch.setattr(checker.assess, "evaluate", capture)
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    row = dict(store.bundle("b1"))
    store._db.execute("DROP TRIGGER bundles_no_update")
    store._db.execute(
        "UPDATE bundles SET session = ? WHERE id = 'b1'",
        (seal_text(jsonlib.dumps({"user": "scanner"}), config.recipients),),
    )
    store._db.commit()
    assert row["id"] == "b1"
    checker.assess.analyze(store, "web01", identity, config.recipients)
    assert seen["scanner"] == "scanner"
