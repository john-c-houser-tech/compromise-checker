"""Correlation (DESIGN.md §11.3, plan 2.3): findings and events that belong
together in time.

Two uses:

- **Whitelist conditions** (`correlated_with`): a finding is suppressed
  only when every event behind it has a partner event: a login from a new
  address, then that same account's `sudo -u deploy git pull` within 30
  seconds. A condition lowers the score, so its partner must be real: an
  event the journal recorded from the program that writes it, running as
  root. A line anyone can write with `logger -t sudo` is not a partner.
- **Chains**: findings that together tell an attack's story (a new account
  given privilege and then used; a guessed password followed by a new key
  or privilege) earn a bonus in the score, once per chain, on top of what
  each finding counts alone.

Times are the corrected event times (docs/events.md). A finding about
state (a snapshot change) has no time of its own: it joins a chain only
when it is new since the previous bundle."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from checker.events import Event

# Event types a condition may name, the programs that write them (as the
# journal knows them, _COMM, not the name a message gives itself), and the
# fields they carry for `same`.
WRITERS: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
for _types, _programs, _fields in (
    ("sudo.command sudo.failed sudo.denied", "sudo", "account"),
    ("su.switch su.failed", "su", "account"),
    (
        "ssh.login.accepted ssh.login.failed ssh.invalid_user ssh.login.too_many_failures"
        " ssh.login.abandoned",
        "sshd sshd-session sshd-auth",
        "account address",
    ),
    (
        "session.opened session.closed",
        "sshd sshd-session sudo su login cron crond systemd",
        "account",
    ),
    (
        "account.created account.deleted account.modified account.renamed account.locked"
        " account.unlocked account.password_changed",
        "useradd userdel usermod passwd chpasswd chage",
        "account",
    ),
    (
        "group.created group.member_added group.member_removed group.members_set",
        "groupadd groupmod gpasswd usermod useradd",
        "account",
    ),
    ("logind.session_new logind.session_end", "systemd-logind", "account"),
):
    for _type in _types.split():
        WRITERS[_type] = (frozenset(_programs.split()), frozenset(_fields.split()))
EVENT_TYPES = frozenset(WRITERS)
SAME_FIELD = {"account": "user", "address": "address"}

MAX_WITHIN = timedelta(days=1)  # for whitelist conditions
MAX_PARTNERS = 5000  # more candidate partners than this: the condition fails closed
MAX_COMMAND = 2048
_DURATION = re.compile(r"([1-9]\d{0,5})([smhd])")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_duration(text: str) -> timedelta:
    match = _DURATION.fullmatch(str(text).strip())
    if not match:
        raise ValueError("a duration such as 30s, 10m, 2h or 1d")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def time_of(text: str | None) -> datetime | None:
    """An ISO time with its offset; a naive one can't be placed, so None."""
    try:
        moment = datetime.fromisoformat(text) if text else None
    except ValueError:
        return None
    return moment if moment is not None and moment.tzinfo is not None else None


def command_matches(pattern: str, text: str) -> bool:
    """The whole command against a pattern: `*` any run of characters
    (spaces and slashes too), `?` one, the rest literal. Without
    backtracking: at most len × len."""
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


def trusted(event: Event) -> bool:
    """Recorded by the journal from the program that writes this kind of
    event, running as root. An event from a log file alone, or one whose
    sender only named itself after the program, is not."""
    writers = WRITERS.get(event.type)
    if writers is None:
        return False
    return (
        event.fields.get("journal_comm") in writers[0]
        and str(event.fields.get("journal_uid")) == "0"
    )


# --- Whitelist conditions ----------------------------------------------------------------


class Partners:
    """A condition's candidate partners in one bundle's events, worked out
    once (type, provenance, command), however many findings it is tried
    on."""

    def __init__(self, condition, events: list[Event]) -> None:
        self.condition = condition
        self.within = parse_duration(condition.within)
        found = []
        for i, e in enumerate(events):
            if e.type != condition.event or e.own_session or not trusted(e):
                continue
            when = time_of(e.corrected)
            if when is None:
                continue
            found.append((i, e, when))
            if len(found) > MAX_PARTNERS:
                break
        self.failed_closed = len(found) > MAX_PARTNERS
        if self.failed_closed:
            found = []
        if condition.command is not None:
            found = [
                (i, e, t)
                for i, e, t in found
                if command_matches(condition.command, str(e.fields.get("command") or ""))
            ]
        self.found = found


def correlated(
    condition, finding: dict[str, Any], events: list[Event] | None, cache: dict | None = None
) -> bool:
    """Every event the finding cites has a partner: a trusted event of the
    condition's type, not the tool's own, within its time on the side it
    says, by the same account (and from the same address, when asked),
    running a matching command when it names one, and not itself one of
    the events the finding cites. No events, or a finding citing none: no
    match."""
    if not events:
        return False
    cited_at = [
        ref["event"]
        for ref in finding.get("evidence") or []
        if isinstance(ref.get("event"), int) and 0 <= ref["event"] < len(events)
    ]
    if not cited_at:
        return False
    if cache is None:
        cache = {}
    key = id(condition)
    if key not in cache:
        cache[key] = Partners(condition, events)
    partners = cache[key]
    cited = set(cited_at)
    return all(_partnered(partners, events[i], cited) for i in cited_at)


def _partnered(partners: Partners, event: Event, cited: set[int]) -> bool:
    condition = partners.condition
    at = time_of(event.corrected)
    if at is None:
        return False
    wanted = {}
    for name in condition.same:
        value = event.fields.get(SAME_FIELD[name])
        if not value:
            return False  # nothing to be the same as
        wanted[SAME_FIELD[name]] = value
    for index, other, when in partners.found:
        if index in cited:
            continue  # a finding's own events don't vouch for each other
        gap = when - at
        if condition.direction == "after" and not timedelta(0) <= gap <= partners.within:
            continue
        if condition.direction == "before" and not -partners.within <= gap <= timedelta(0):
            continue
        if condition.direction == "either" and abs(gap) > partners.within:
            continue
        if any(other.fields.get(f) != v for f, v in wanted.items()):
            continue
        return True
    return False


# --- Chains ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    """Findings of these (check, variant) kinds about the account (a
    variant of None: any of the check's), or events of this type by it."""

    title: str
    kinds: tuple[tuple[str, str | None], ...] = ()
    event: str | None = None

    def takes(self, finding: dict[str, Any]) -> bool:
        check = finding["check"]
        return (check, finding.get("variant")) in self.kinds or (check, None) in self.kinds


@dataclass(frozen=True)
class Chain:
    id: str
    title: str
    steps: tuple[Step, ...]
    within: timedelta
    ratio: float  # the bonus likelihood ratio, once per chain


PRIVILEGE = (
    ("sudo.rules", None),
    ("group.privileged", None),
    ("account.log_changes", "group_member_added"),
    ("account.log_changes", "group_members_set"),
)

CHAINS = (
    Chain(
        "new-account-escalated-used",
        "A new account or key, given privilege, then used to log in",
        (
            Step(
                "a new account or key",
                (
                    ("account.changes", "new"),
                    ("account.changes", "root_group"),
                    ("account.log_changes", "created"),
                    ("ssh.authorized_keys", "new_key"),
                ),
            ),
            Step("privilege for it", PRIVILEGE),
            Step("a login by it", event="ssh.login.accepted"),
        ),
        timedelta(days=7),
        5.0,
    ),
    Chain(
        "guessed-then-entrenched",
        "A guessed login, then a new key or privilege for that account",
        (
            Step("a login after repeated failures", (("ssh.guessed", None),)),
            Step("a new key or privilege", (("ssh.authorized_keys", "new_key"), *PRIVILEGE)),
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


def _counted(finding: dict[str, Any]) -> bool:
    """What the score counts: compromise indicators, not suppressed, not
    informational (a maintenance window may have made them so)."""
    return (
        finding.get("category") == "compromise indicator"
        and not finding.get("suppressed_by")
        and finding.get("band") != "info"
    )


def find_chains(
    findings: list[dict[str, Any]],
    events: list[Event],
    previous_time: str | None = None,
    chains=CHAINS,
) -> list[dict[str, Any]]:
    """Each chain at most once (for the first account, by name, that
    completes it), from the findings the score counts. The tool's own
    account (the one its current session logged in as) never completes
    one: its earlier visits' logins are in the logs too."""
    own = {e.fields.get("user") for e in events if e.own_session and e.type == "ssh.login.accepted"}
    live = [(i, f) for i, f in enumerate(findings) if _counted(f)]
    accounts = sorted(set().union(*(_accounts(f) for _, f in live)) - own) if live else []
    found = []
    for chain in chains:
        for account in accounts:
            hit = _complete(chain, account, live, events, time_of(previous_time))
            if hit is not None:
                found.append(hit.as_dict())
                break
    return found


def _complete(chain, account, live, events, previous: datetime | None) -> Found | None:
    hit = Found(chain, account)
    anchor: datetime | None = None
    used_events: set[int] = set()
    for step in chain.steps:
        if step.event is not None:
            # After the chain's first timed step; with none, after the
            # previous bundle (the state steps are new since then).
            after = anchor if anchor is not None else previous
            if after is None:
                return None
            login = None
            for i, e in enumerate(events):
                if e.type != step.event or e.own_session or e.fields.get("user") != account:
                    continue
                when = time_of(e.corrected)
                if when is not None and after <= when <= after + chain.within:
                    login = i
                    break
            if login is None:
                return None
            hit.events.append(login)
            continue
        matching = []
        for i, f in live:
            if not step.takes(f) or account not in _accounts(f) or i in hit.findings:
                continue
            cites = {r["event"] for r in f.get("evidence") or [] if "event" in r}
            if cites & used_events:
                continue  # one log line is one step, not two
            when = time_of(f.get("first_seen"))
            if when is None:
                if f.get("new"):  # state, changed since the previous bundle
                    matching.append((i, None, cites))
            elif anchor is None or anchor - chain.within <= when <= anchor + chain.within:
                matching.append((i, when, cites))
        if not matching:
            return None
        index, when, cites = matching[0]
        hit.findings.append(index)
        used_events |= cites
        if anchor is None and when is not None:
            anchor = when
    return hit


def chain_contribution(found: dict[str, Any]) -> float:
    return math.log(found["ratio"])
