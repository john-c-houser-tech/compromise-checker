"""Logins at unusual hours (Phase 3 decision 4, PR 3.2b)."""

from datetime import UTC, datetime, timedelta

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
    history = office_hours() + [login(29, 3)]  # an odd hour before the last collection
    assert all(
        f.summary.startswith("jch: 1 login(s) at 04")
        for f in login_hours(context(history + [login(31, 4)]))
    )
    assert login_hours(context(history)) == []


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
