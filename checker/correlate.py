"""Correlation (DESIGN.md §11.3, plan 2.3): findings and events that belong
together in time.

Two uses:

- **Whitelist conditions** (`correlated_with`): a finding is suppressed
  only when every event behind it is followed (or preceded) by an expected
  event: a login from a new address, then that same account's
  `sudo -u deploy git pull` within 30 seconds.
- **Chains**: findings that together tell an attack's story (a new account
  given privilege and then used; a guessed password followed by a new key
  or privilege) earn a bonus in the score, once per chain, on top of what
  each finding counts alone.

Times are the corrected event times (docs/events.md). A finding about
state (a snapshot change) has no time of its own: it joins a chain only
when it is new since the previous bundle, and its place in the order is
not checked."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from checker.events import Event

# Event types a whitelist condition may name (docs/events.md).
EVENT_TYPES = frozenset(
    """
    ssh.login.accepted ssh.login.failed ssh.invalid_user ssh.login.too_many_failures
    ssh.login.abandoned session.opened session.closed auth.failure sudo.command sudo.failed
    sudo.denied su.switch su.failed account.created account.deleted account.modified
    account.renamed account.locked account.unlocked account.password_changed group.created
    group.member_added group.member_removed group.members_set logind.session_new
    logind.session_end system.shutdown_requested system.shutdown unit.started unit.stopped
    unit.failed login.session login.ended
    """.split()
)
MAX_WITHIN = timedelta(days=1)  # for whitelist conditions
_DURATION = re.compile(r"([1-9]\d{0,5})([smhd])")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
MAX_COMMAND = 2048


def parse_duration(text: str) -> timedelta:
    match = _DURATION.fullmatch(str(text).strip())
    if not match:
        raise ValueError("a duration such as 30s, 10m, 2h or 1d")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def time_of(text: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(text) if text else None
    except ValueError:
        return None


def command_matches(pattern: str, text: str) -> bool:
    """The whole command against a pattern: `*` any run of characters
    (spaces and slashes too), `?` one, the rest literal. Without
    backtracking, so a crafted command costs at most len × len."""
    if len(text) > MAX_COMMAND:
        return False
    previous = [True] + [False] * len(text)
    for p in pattern:
        current = [previous[0] and p == "*"] + [False] * len(text)
        for k in range(1, len(text) + 1):
            if p == "*":
                current[k] = previous[k] or current[k - 1]
            else:
                current[k] = previous[k - 1] and (p == "?" or p == text[k - 1])
        previous = current
    return previous[-1]


# --- Whitelist conditions ----------------------------------------------------------------


def correlated(condition, finding: dict[str, Any], events: list[Event] | None) -> bool:
    """Every event the finding cites has a partner event: of the condition's
    type, not the tool's own, within its time, on the side it says, by the
    same account (and from the same address, when asked), running a
    matching command when it names one. No events, or a finding citing
    none: no match."""
    if not events:
        return False
    cited = [
        events[ref["event"]]
        for ref in finding.get("evidence") or []
        if isinstance(ref.get("event"), int) and 0 <= ref["event"] < len(events)
    ]
    if not cited:
        return False
    within = parse_duration(condition.within)
    partners = [e for e in events if e.type == condition.event and not e.own_session]
    return all(_partnered(condition, e, partners, within) for e in cited)


def _partnered(condition, event: Event, partners: list[Event], within: timedelta) -> bool:
    at = time_of(event.corrected)
    if at is None:
        return False
    for other in partners:
        if other is event:
            continue  # an event is never its own partner
        when = time_of(other.corrected)
        if when is None:
            continue
        gap = when - at
        if condition.direction == "after" and not timedelta(0) <= gap <= within:
            continue
        if condition.direction == "before" and not -within <= gap <= timedelta(0):
            continue
        if condition.direction == "either" and abs(gap) > within:
            continue
        if "account" in condition.same and (
            not event.fields.get("user") or other.fields.get("user") != event.fields.get("user")
        ):
            continue
        if "address" in condition.same and (
            not event.fields.get("address")
            or other.fields.get("address") != event.fields.get("address")
        ):
            continue
        if condition.command is not None and not command_matches(
            condition.command, str(other.fields.get("command") or "")
        ):
            continue
        return True
    return False


# --- Chains ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    """Findings of these checks (and, if given, variants) about the
    account, or events of this type by it."""

    title: str
    checks: tuple[str, ...] = ()
    event: str | None = None


@dataclass(frozen=True)
class Chain:
    id: str
    title: str
    steps: tuple[Step, ...]
    within: timedelta
    ratio: float  # the bonus likelihood ratio, once per chain


CHAINS = (
    Chain(
        "new-account-escalated-used",
        "A new account or key, given privilege, then used to log in",
        (
            Step(
                "a new account or key",
                ("account.changes", "account.log_changes", "ssh.authorized_keys"),
            ),
            Step("privilege for it", ("sudo.rules", "group.privileged")),
            Step("a login by it", event="ssh.login.accepted"),
        ),
        timedelta(days=7),
        5.0,
    ),
    Chain(
        "guessed-then-entrenched",
        "A guessed login, then a new key or privilege for that account",
        (
            Step("a login after repeated failures", ("ssh.guessed",)),
            Step(
                "a new key or privilege",
                ("ssh.authorized_keys", "sudo.rules", "group.privileged"),
            ),
        ),
        timedelta(hours=24),
        5.0,
    ),
)


@dataclass
class Found:
    chain: Chain
    account: str
    findings: list[int] = field(default_factory=list)
    events: list[int] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain.id,
            "title": self.chain.title,
            "account": self.account,
            "ratio": self.chain.ratio,
            "findings": self.findings,
            "events": self.events,
        }


def _accounts(finding: dict[str, Any]) -> set[str]:
    return {e.split(":", 1)[1] for e in finding.get("entities") or [] if e.startswith("account:")}


def find_chains(
    findings: list[dict[str, Any]], events: list[Event], chains=CHAINS
) -> list[dict[str, Any]]:
    """Each chain at most once (for the first account, by name, that
    completes it). Suppressed findings don't count: a whitelisted step is
    explained."""
    found = []
    live = [(i, f) for i, f in enumerate(findings) if not f.get("suppressed_by")]
    for chain in chains:
        accounts = sorted(set().union(*(_accounts(f) for _, f in live)) if live else set())
        for account in accounts:
            hit = _complete(chain, account, live, events)
            if hit is not None:
                found.append(hit.as_dict())
                break
    return found


def _complete(chain: Chain, account: str, live, events: list[Event]) -> Found | None:
    hit = Found(chain, account)
    anchor: datetime | None = None
    for number, step in enumerate(chain.steps):
        if step.event is not None:
            candidates = [
                (i, time_of(e.corrected))
                for i, e in enumerate(events)
                if e.type == step.event and not e.own_session and e.fields.get("user") == account
            ]
            candidates = [
                (i, t)
                for i, t in candidates
                if t is not None and (anchor is None or anchor <= t <= anchor + chain.within)
            ]
            if not candidates:
                return None
            hit.events.append(candidates[0][0])
            continue
        matching = []
        for i, f in live:
            if f["check"] not in step.checks or account not in _accounts(f):
                continue
            when = time_of(f.get("first_seen"))
            if when is None:
                if f.get("new"):  # state, changed since the previous bundle
                    matching.append((i, None))
            elif anchor is None or anchor - chain.within <= when <= anchor + chain.within:
                matching.append((i, when))
        if not matching:
            return None
        hit.findings.append(matching[0][0])
        if number == 0 or anchor is None:
            timed = [t for _, t in matching if t is not None]
            anchor = min(timed) if timed else anchor
    return hit


def chain_contribution(found: dict[str, Any]) -> float:
    return math.log(found["ratio"])
