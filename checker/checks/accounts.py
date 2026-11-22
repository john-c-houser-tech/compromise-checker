"""Accounts and authentication (DESIGN.md §8.3)."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from checker.checks import (
    COMPROMISE,
    HYGIENE,
    Context,
    Finding,
    check,
    parse_time,
    span,
)
from checker.checks.web import WEB_USERS

SYSTEM_UID_MAX = 999  # service accounts: 1-999 (login.defs SYS_UID_MAX)
NO_LOGIN = ("nologin", "false", "sync", "shutdown", "halt")
ROOT_GROUPS = {
    "root",
    "wheel",
    "sudo",
    "admin",
    "docker",
    "lxd",
    "incus-admin",
    "libvirt",
    "disk",
    "kmem",
    "shadow",
}
LOG_GROUPS = {"adm", "systemd-journal"}
# A "too many failures" line repeats the last attempt, so it isn't counted.
FAILURES = ("ssh.login.failed", "ssh.invalid_user", "auth.failure")
GUESSES_BEFORE_SUCCESS = 5
GUESSING_WINDOW = timedelta(hours=24)
SENSITIVE_SSHD = {
    "permitrootlogin",
    "port",
    "listenaddress",
    "authorizedkeysfile",
    "authorizedkeyscommand",
    "authorizedkeyscommanduser",
    "authorizedprincipalsfile",
    "authorizedprincipalscommand",
    "trustedusercakeys",
    "passwordauthentication",
    "permitemptypasswords",
    "kbdinteractiveauthentication",
    "challengeresponseauthentication",
    "usepam",
    "forcecommand",
    "permituserenvironment",
    "acceptenv",
    "gatewayports",
    "permittunnel",
    "allowusers",
    "allowgroups",
    "denyusers",
    "denygroups",
    "include",
    "match",
    "subsystem",
}


def base_name(key: str) -> str:
    return key.split(" #", 1)[0]


def can_log_in(shell: str | None) -> bool:
    """An empty shell field means /bin/sh; None: not known."""
    if shell is None:
        return False
    return not str(shell).rsplit("/", 1)[-1].startswith(NO_LOGIN)


# A password status that lets someone log in: a hash, or none at all.
OPENS = {"set", "empty"}


def is_service(uid) -> bool:
    return isinstance(uid, int) and (0 < uid <= SYSTEM_UID_MAX or uid == 65534)


# --- Accounts -------------------------------------------------------------------------


@check("account.uid0", "Accounts with UID 0 besides root; duplicate names and UIDs")
def uid0(context: Context) -> list[Finding]:
    accounts = context.items("accounts")
    uncertain = context.uncertain("accounts")
    findings = []
    by_uid = defaultdict(list)
    for key, item in accounts.items():
        by_uid[item.get("uid")].append(key)
        if key != base_name(key):
            findings.append(
                Finding(
                    "account.uid0",
                    "An account name listed twice",
                    COMPROMISE,
                    "high",
                    f"{base_name(key)} appears again (UID {item.get('uid')}); the system uses"
                    " the first entry",
                    [f"account:{base_name(key)}"],
                    [{"item": ["accounts", key]}, {"item": ["accounts", base_name(key)]}],
                    uncertain=uncertain,
                )
            )
        elif item.get("uid") == 0 and key != "root":
            findings.append(
                Finding(
                    "account.uid0",
                    "An account other than root has UID 0",
                    COMPROMISE,
                    "critical",
                    f"{key} has UID 0: it is root under another name",
                    [f"account:{key}"],
                    [{"item": ["accounts", key]}],
                    uncertain=uncertain,
                )
            )
    for uid, keys in sorted(by_uid.items(), key=lambda x: str(x[0])):
        names = sorted({base_name(k) for k in keys})
        if uid != 0 and len(names) > 1:
            findings.append(
                Finding(
                    "account.uid0",
                    "Accounts sharing a UID",
                    COMPROMISE,
                    "medium",
                    f"UID {uid}: {', '.join(names)}",
                    [f"account:{n}" for n in names],
                    [{"item": ["accounts", k]} for k in keys],
                    uncertain=uncertain,
                )
            )
    return findings


@check(
    "account.changes",
    "New and removed accounts; service accounts able to log in",
    needs_baseline=True,
    variants=("new", "removed", "root_group", "service_login"),
)
def account_changes(context: Context) -> list[Finding]:
    diff = context.changes("accounts")
    uncertain = context.uncertain("accounts")
    findings = []
    for key, item in diff["added"].items():
        if key != base_name(key):
            continue  # a duplicate name: account.uid0 reports it
        findings.append(
            Finding(
                "account.changes",
                "A new account",
                COMPROMISE,
                "medium",
                f"{key} (UID {item.get('uid')}, shell {item.get('shell')})",
                [f"account:{key}"],
                [context.change_ref("accounts", key, "added")],
                new=context.new_since_previous("accounts", key),
                uncertain=uncertain,
                variant="new",
            )
        )
    if diff["comparable"]:
        for key in diff["removed"]:
            findings.append(
                Finding(
                    "account.changes",
                    "An account was removed",
                    COMPROMISE,
                    "low",
                    key,
                    [f"account:{base_name(key)}"],
                    [context.change_ref("accounts", key, "removed")],
                    new=context.new_since_previous("accounts", key),
                    variant="removed",
                )
            )
    accounts = context.items("accounts")
    privileged_gids = {
        item.get("gid"): base_name(key)
        for key, item in context.items("groups").items()
        if base_name(key) in ROOT_GROUPS | LOG_GROUPS and item.get("gid") is not None
    }
    privileged_gids.setdefault(0, "root")

    def primary(key: str, gid, how: str, summary: str) -> None:
        group = privileged_gids[gid]
        findings.append(
            Finding(
                "account.changes",
                "A new account whose primary group is root-equivalent"
                if how == "added"
                else "An account's primary group became root-equivalent",
                COMPROMISE,
                "high" if group in ROOT_GROUPS else "medium",
                summary.format(group=group),
                [f"account:{key}", f"group:{group}"],
                [context.change_ref("accounts", key, how)],
                new=context.new_since_previous("accounts", key),
                uncertain=uncertain,
                variant="root_group",
            )
        )

    for key, item in diff["added"].items():
        if key == base_name(key) and item.get("gid") in privileged_gids:
            primary(
                key, item["gid"], "added", f"{key}: primary group {{group}} (GID {item['gid']})"
            )
    for key, fields in diff["changed"].items():
        item = accounts.get(key, {})
        uid = item.get("uid")
        if "gid" in fields and fields["gid"][1] in privileged_gids:
            old, new = fields["gid"]
            primary(key, new, "changed", f"{key}: primary group now {{group}} (GID {old} → {new})")
        if not is_service(uid):
            continue
        gained = []
        if (
            "shell" in fields
            and can_log_in(fields["shell"][1])
            and not can_log_in(fields["shell"][0])
        ):
            gained.append(f"a login shell ({fields['shell'][1] or '/bin/sh'})")
        status = fields.get("shadow_status")
        if status and status[1] in OPENS and status[0] not in OPENS:
            gained.append("no password at all" if status[1] == "empty" else "a password")
        elif "password" in fields:  # a hash (or nothing) written into /etc/passwd itself
            old, new = ((p or {}).get("status") for p in fields["password"])
            if new in OPENS and old not in OPENS:
                gained.append(
                    "no password at all" if new == "empty" else "a password in /etc/passwd"
                )
        if gained:
            findings.append(
                Finding(
                    "account.changes",
                    "A service account can now log in",
                    COMPROMISE,
                    "medium",
                    f"{key} (UID {uid}) gained {' and '.join(gained)}",
                    [f"account:{key}"],
                    [context.change_ref("accounts", key, "changed")],
                    new=context.new_since_previous("accounts", key),
                    uncertain=uncertain,
                    variant="service_login",
                )
            )
    return findings


LOG_CHANGE_VARIANTS = (
    "created",
    "deleted",
    "modified",
    "renamed",
    "locked",
    "unlocked",
    "group_created",
    "group_member_added",
    "group_member_removed",
    "group_members_set",
)


NO_LOGIN_SHELL = re.compile(r"(?:^|/)(?:nologin|false)$")
# How close to a package's install an account it made is logged.
PACKAGE_WINDOW = timedelta(minutes=15)


def _package_installs(context: Context) -> list[datetime]:
    times = []
    for item in context.items("packages").values():
        try:
            times.append(datetime.fromtimestamp(float(item["installed"]), UTC))
        except (KeyError, TypeError, ValueError, OverflowError):
            continue
    return times


def _package_account(context: Context, event, installs: list[datetime]) -> bool:
    """A package's own account: logged within minutes of a package being
    installed (no terminal is no proof: any script has none), a system UID,
    and no login shell, both as logged and as it is now. Such an account,
    or such an account's group membership, is low: the install is the
    change worth knowing (software.packages). Packages create the web
    accounts too (nginx, apache on RHEL), but a web account joining a group
    is never a package's: it is what a web shell would gain."""
    fields = event.fields
    user = fields.get("user")
    if event.type != "account.created" and user in WEB_USERS:
        return False
    at = parse_time(event.corrected)
    if at is None or not any(abs(at - t) <= PACKAGE_WINDOW for t in installs):
        return False
    current = context.items("accounts").get(user) or {}
    uid = fields.get("uid") if fields.get("uid") is not None else current.get("uid")
    try:
        if uid is None or not 0 < int(uid) <= SYSTEM_UID_MAX:
            return False
    except (TypeError, ValueError):
        return False
    if event.type == "account.created":
        if fields.get("origin") != "none":
            return False  # made at a terminal (or not said): someone's hand
        if not NO_LOGIN_SHELL.search(str(fields.get("shell") or "")):
            return False
    shells = [s for s in (current.get("shell"),) if s] or [fields.get("shell")]
    return all(s and NO_LOGIN_SHELL.search(str(s)) for s in shells)


_LOGGED = ("account.", "group.")


def _logged(event) -> tuple[Any, ...]:
    """An event as its log line has it, the same in every bundle that read that line (the
    host's own time, not one corrected by that run's measured clock offset)."""
    return (event.source, event.type, event.time, event.line)


@check(
    "account.log_changes",
    "Account and group changes recorded in the logs",
    variants=LOG_CHANGE_VARIANTS,
)
def log_changes(context: Context) -> list[Finding]:
    findings = []
    installs = _package_installs(context)
    # What the baseline's own result was given: an event it logged too was shown there.
    shown = {_logged(e) for e in context.baseline_events() if e.type.startswith(_LOGGED)}
    for index, event in context.of("account.", "group."):
        if event.type == "account.password_changed":
            continue  # account.password reports it
        f = event.fields
        group = f.get("group")
        privileged = group in ROOT_GROUPS and event.type in (
            "group.member_added",
            "group.members_set",
        )
        band = (
            "high"
            if privileged
            else "medium"
            if event.type in ("account.created", "group.member_added")
            and not _package_account(context, event, installs)
            else "low"
        )
        # In the baseline bundle's own logs too: its result showed it, and the accounts and
        # groups it left are the baseline's to compare with. Still in the logs at every later
        # check, it would count again each time. A privileged change still does. One the
        # baseline didn't log (its log reading cut short, a source it lacked) still counts.
        before_baseline = _logged(event) in shown
        if before_baseline and not privileged:
            band = "info"
        who = f.get("user") or ""
        summary = (
            event.type.split(".", 1)[1].replace("_", " ")
            + ": "
            + " ".join(
                str(v)
                for v in (
                    who,
                    f"group {group}" if group else "",
                    f"UID {f['uid']}" if f.get("uid") else "",
                )
                if v
            )
        )
        if before_baseline and not privileged:
            summary = summary.strip() + " (before the baseline)"
        findings.append(
            Finding(
                "account.log_changes",
                "An account or group was changed (from the logs)",
                COMPROMISE,
                band,
                summary.strip(),
                [
                    e
                    for e in (f"account:{who}" if who else "", f"group:{group}" if group else "")
                    if e
                ],
                [{"event": index}],
                event.corrected,
                event.corrected,
                variant=event.type.replace("account.", "").replace("group.", "group_"),
            )
        )
    return findings


_SUDO_USER = re.compile(r"[a-z_][a-z0-9_.-]{0,31}\$?")


def _sudo_who(rule: str) -> list[str]:
    """Everyone a sudoers line grants to, as entities, so a chain can follow
    the account and a whitelist rule must cover them all: its user list
    (`eve, bob ALL=…`, `%wheel ALL=…`), when every member is a plain user
    or `%group`. A list with anything else (an alias, `ALL`, `#uid`,
    `+netgroup`, `!negation`) names no one plainly: no entities, so only a
    broad rule can match it."""
    head = rule.split("=", 1)[0]
    if not head.strip() or head.split(None, 1)[0] in ("Defaults", "#include", "#includedir"):
        return []
    users = re.sub(r"\s*,\s*", ",", head.strip()).split(None, 1)[0]
    found = []
    for member in users.split(","):
        if member.startswith("%") and _SUDO_USER.fullmatch(member[1:]):
            found.append(f"group:{member[1:]}")
        elif _SUDO_USER.fullmatch(member):
            found.append(f"account:{member}")
        else:
            return []
    return found


@check("sudo.rules", "New sudo rights", needs_baseline=True)
def sudo_rules(context: Context) -> list[Finding]:
    diff = context.changes("sudo_rules")
    uncertain = context.uncertain("sudo_rules")
    findings = []
    for key, item in diff["added"].items():
        rule = key.split(": ", 1)[-1]
        nopasswd = "NOPASSWD" in rule.upper()
        findings.append(
            Finding(
                "sudo.rules",
                "A new sudo rule" + (" without a password (NOPASSWD)" if nopasswd else ""),
                COMPROMISE,
                "high",
                f"{item.get('path')}: {rule}",
                [f"path:{item.get('path')}", *_sudo_who(rule)],
                [context.change_ref("sudo_rules", key, "added")],
                new=context.new_since_previous("sudo_rules", key),
                uncertain=uncertain,
            )
        )
    return findings


@check("group.privileged", "New members of root-equivalent groups", needs_baseline=True)
def privileged_groups(context: Context) -> list[Finding]:
    diff = context.changes("groups")
    uncertain = context.uncertain("groups")
    findings = []
    added_members: dict[str, tuple[list[str], str]] = {}
    for key, item in diff["added"].items():
        added_members[key] = (item.get("members") or [], "added")
    for key, fields in diff["changed"].items():
        if "members" in fields:
            old, new = fields["members"]
            added_members[key] = (sorted(set(new or []) - set(old or [])), "changed")
    for key, (members, how) in sorted(added_members.items()):
        group = base_name(key)
        if not members or group not in ROOT_GROUPS | LOG_GROUPS:
            continue
        root = group in ROOT_GROUPS
        findings.append(
            Finding(
                "group.privileged",
                "New members of a root-equivalent group"
                if root
                else "New members of a log-reading group",
                COMPROMISE,
                "high" if root else "medium",
                f"{group}: {', '.join(members)}",
                [f"group:{group}"] + [f"account:{m}" for m in members],
                [context.change_ref("groups", key, how)],
                new=context.new_since_previous("groups", key),
                uncertain=uncertain,
            )
        )
    return findings


# --- SSH keys and logins ----------------------------------------------------------------


@check(
    "ssh.authorized_keys",
    "New, changed or unattributed authorized SSH keys",
    variants=("unattributed", "new_key", "options"),
)
def authorized_keys(context: Context) -> list[Finding]:
    findings = []
    uncertain = context.uncertain("authorized_keys")
    for key, item in context.items("authorized_keys").items():
        if item.get("account") is None or item.get("unattributed"):
            findings.append(
                Finding(
                    "ssh.authorized_keys",
                    "An authorized key that belongs to no local account",
                    HYGIENE,
                    "medium",
                    f"{item.get('fingerprint')} in {item.get('path')}",
                    [f"key:{item.get('fingerprint')}", f"path:{item.get('path')}"],
                    [{"item": ["authorized_keys", key]}],
                    variant="unattributed",
                )
            )
    diff = context.changes("authorized_keys")
    if diff is None:
        return findings
    for key, item in diff["added"].items():
        owner = item.get("account") or item.get("home") or "?"
        findings.append(
            Finding(
                "ssh.authorized_keys",
                "A new authorized SSH key",
                COMPROMISE,
                "high",
                f"{owner}: {item.get('type')} {item.get('fingerprint')} in {item.get('path')}",
                [f"account:{owner}", f"key:{item.get('fingerprint')}"],
                [context.change_ref("authorized_keys", key, "added")],
                new=context.new_since_previous("authorized_keys", key),
                uncertain=uncertain,
                variant="new_key",
            )
        )
    for key, fields in diff["changed"].items():
        owner = key.split(" ", 1)[0]
        findings.append(
            Finding(
                "ssh.authorized_keys",
                "An authorized SSH key's options changed",
                COMPROMISE,
                "medium",
                f"{key}: {', '.join(sorted(fields))}",
                [f"account:{owner}"],
                [context.change_ref("authorized_keys", key, "changed")],
                new=context.new_since_previous("authorized_keys", key),
                uncertain=uncertain,
                variant="options",
            )
        )
    return findings


_RHOST = re.compile(r"\brhost=(\S+)")


def _address(event) -> str | None:
    if event.type == "auth.failure":
        match = _RHOST.search(str(event.fields.get("rest") or ""))
        return match.group(1) if match else None
    return event.fields.get("address")


@check("ssh.guessed", "Failed logins followed by success from the same source")
def guessed(context: Context) -> list[Finding]:
    """One wrong password is logged several times (sshd's line, PAM's, an
    invalid-user line): attempts are counted once per connection port and
    second, and PAM's failures only for addresses sshd logged none for."""
    sshd: dict[str, dict] = defaultdict(dict)
    pam: dict[str, dict] = defaultdict(dict)
    for index, event in context.of(*FAILURES):
        address = _address(event)
        moment = parse_time(event.corrected)
        if not address or moment is None:
            continue
        target = pam if event.type == "auth.failure" else sshd
        key = (event.fields.get("port"), moment.replace(microsecond=0))
        target[address].setdefault(key, (moment, index))
    failures = {
        address: sorted((sshd.get(address) or pam.get(address)).values())
        for address in set(sshd) | set(pam)
    }
    findings = []
    for index, event in context.of("ssh.login.accepted"):
        address, moment = event.fields.get("address"), parse_time(event.corrected)
        if not address or moment is None:
            continue
        before = [
            i for t, i in failures.get(address, []) if moment - GUESSING_WINDOW <= t <= moment
        ]
        if len(before) < GUESSES_BEFORE_SUCCESS:
            continue
        user = event.fields.get("user", "?")
        findings.append(
            Finding(
                "ssh.guessed",
                "A login succeeded after repeated failures from the same address",
                COMPROMISE,
                "high",
                f"{user} from {address}: {len(before)} failures in the 24 hours before",
                [f"account:{user}", f"address:{address}"],
                [{"event": i} for i in before[-20:]] + [{"event": index}],
                context.events[before[0]].corrected,
                event.corrected,
            )
        )
    return findings


@check(
    "ssh.login",
    "Direct root logins; logins from sources never seen before",
    variants=("root_login", "new_address"),
)
def logins(context: Context) -> list[Finding]:
    accepted = list(context.of("ssh.login.accepted"))
    findings = []
    for index, event in accepted:
        if event.fields.get("user") == "root":
            address = event.fields.get("address", "?")
            findings.append(
                Finding(
                    "ssh.login",
                    "A direct root login over SSH",
                    COMPROMISE,
                    "medium",
                    f"root from {address} ({event.fields.get('method')})",
                    ["account:root", f"address:{address}"],
                    [{"event": index}],
                    event.corrected,
                    event.corrected,
                    variant="root_login",
                )
            )
    if not accepted:
        return findings
    seen = {
        e.fields.get("address")
        for events in context.earlier_events()
        for e in events
        if e.type == "ssh.login.accepted" and not e.own_session
    }
    if not seen:
        return findings  # no earlier login to know "never seen before" from
    new = defaultdict(list)
    for index, event in accepted:
        address = event.fields.get("address")
        if address and address not in seen:
            new[address].append((index, event))
    for address, hits in sorted(new.items()):
        users = sorted({e.fields.get("user", "?") for _, e in hits})
        first, last = span([e for _, e in hits])
        findings.append(
            Finding(
                "ssh.login",
                "Logins from an address never seen before",
                COMPROMISE,
                "medium",
                f"{address}: {len(hits)} login(s) as {', '.join(users)}",
                [f"address:{address}"] + [f"account:{u}" for u in users],
                [{"event": i} for i, _ in hits],
                first,
                last,
                variant="new_address",
            )
        )
    return findings


# Logins at unusual hours (DESIGN.md §8.3; Phase 3 decision 4): each
# account's usual hours, learned from the host's own history.
HOURS_MIN_DAYS = 21  # history an account needs before its hours are judged
HOURS_MIN_LOGINS = 10
HOURS_MARGIN = 1  # an hour either side of a usual one is usual too (summer time)
HOURS_MIN_DAYS_SEEN = 2  # an hour is usual once logins at it came on two days


def _login_key(event) -> tuple:
    """One login, however many bundles logged it: by the host's own clock,
    which every copy shares (each bundle corrects times by its own measured
    offset, and keeps whichever source's copy it merged)."""
    f = event.fields
    when = (event.time or event.corrected or "")[:19]
    return (when, f.get("user"), f.get("address"), f.get("port"))


def _usual_hours(past: list[datetime]) -> set[int]:
    days_by_hour: dict[int, set] = defaultdict(set)
    for moment in past:
        days_by_hour[moment.hour].add(moment.date())
    seen = [h for h, days in days_by_hour.items() if len(days) >= HOURS_MIN_DAYS_SEEN]
    return {(h + shift) % 24 for h in seen for shift in range(-HOURS_MARGIN, HOURS_MARGIN + 1)}


@check("ssh.login_hours", "Logins at hours unusual for the account")
def login_hours(context: Context) -> list[Finding]:
    """Judged are the logins since the previous collection (all of them on
    a first analysis), each against the account's logins before it, from
    every stored bundle, once each. An hour is usual once logins at it came
    on two separate days. Past runs' own logins don't count (each bundle
    marked its own); the account this run logged in as is not judged
    (scheduled runs log in at any hour)."""
    previous = parse_time(context.previous_time)
    current = []
    for index, event in context.of("ssh.login.accepted"):
        moment = parse_time(event.corrected)
        if event.own_session or moment is None or not event.fields.get("user"):
            continue
        if previous is None or moment > previous:
            current.append((index, event, moment.astimezone(UTC)))
    exempt = {
        e.fields.get("user")
        for e in context.events
        if e.type == "ssh.login.accepted" and e.own_session
    } | ({context.scanner} if context.scanner else set())
    current = [c for c in current if c[1].fields.get("user") not in exempt]
    if not current:
        return []
    every = [e for events in [*context.earlier_events(), context.events] for e in events]
    logins = [e for e in every if e.type == "ssh.login.accepted"]
    own = {_login_key(e) for e in logins if e.own_session}
    history: dict[str, dict[tuple, datetime]] = defaultdict(dict)
    for event in logins:
        key, moment = _login_key(event), parse_time(event.corrected)
        if event.own_session or key in own or moment is None:
            continue
        history[event.fields.get("user")].setdefault(key, moment.astimezone(UTC))
    findings, unjudged = [], set()
    odd: dict[str, list[tuple[int, datetime]]] = defaultdict(list)
    profile: dict[str, tuple[set[int], int, int]] = {}
    for index, event, moment in current:
        user = event.fields["user"]
        key = _login_key(event)
        past = sorted(m for k, m in history.get(user, {}).items() if m < moment and k != key)
        if len(past) < HOURS_MIN_LOGINS or (past[-1] - past[0]) < timedelta(days=HOURS_MIN_DAYS):
            unjudged.add(user)
            continue
        usual = _usual_hours(past)
        if moment.hour not in usual:
            odd[user].append((index, moment))
            profile[user] = (usual, len(past), (past[-1] - past[0]).days)
    for user, hits in sorted(odd.items()):
        usual, count, days = profile[user]
        hours = sorted({m.hour for _, m in hits})
        findings.append(
            Finding(
                "ssh.login_hours",
                "Logins at hours unusual for the account",
                COMPROMISE,
                "low",
                f"{user}: {len(hits)} login(s) at {', '.join(f'{h:02d}:00' for h in hours)} UTC;"
                f" usually {_hour_ranges(usual) or 'no hour yet'} UTC ({count} logins over"
                f" {days} days)",
                [f"account:{user}"],
                [{"event": i} for i, _ in hits[:20]],
                hits[0][1].isoformat(),
                hits[-1][1].isoformat(),
            )
        )
    unjudged -= set(odd)
    if unjudged:
        n = len(unjudged)
        context.gaps.append(
            f"login hours not judged for {n} account{'s' if n != 1 else ''}:"
            f" fewer than {HOURS_MIN_LOGINS} logins or {HOURS_MIN_DAYS} days of history"
        )
    return findings


def _hour_ranges(hours: set[int]) -> str:
    """{8, 9, 10, 17} as "08-10, 17"."""
    ranges, run = [], []
    for hour in sorted(hours):
        if run and hour == run[-1] + 1:
            run.append(hour)
        else:
            if run:
                ranges.append(run)
            run = [hour]
    if run:
        ranges.append(run)
    if len(ranges) > 1 and ranges[0][0] == 0 and ranges[-1][-1] == 23:
        ranges[0] = ranges.pop() + ranges[0]  # across midnight
    return ", ".join(f"{r[0]:02d}" if len(r) == 1 else f"{r[0]:02d}-{r[-1]:02d}" for r in ranges)


@check("account.password", "su use, password changes and refused sudo")
def su_and_passwords(context: Context) -> list[Finding]:
    kinds = {
        "su.switch": ("su was used", "info"),
        "su.failed": ("su failed", "low"),
        "account.password_changed": ("A password was changed", "info"),
        "sudo.failed": ("sudo failed (wrong password)", "low"),
        "sudo.denied": ("sudo refused a command", "low"),
    }
    groups = defaultdict(list)
    for index, event in context.of(*kinds):
        f = event.fields
        who = f.get("user", "?")
        target = f.get("target") or f.get("runas") or ""
        groups[(event.type, who, target)].append((index, event))
    findings = []
    for (kind, who, target), hits in sorted(groups.items()):
        title, band = kinds[kind]
        first, last = span([e for _, e in hits])
        findings.append(
            Finding(
                "account.password",
                title,
                COMPROMISE,
                band,
                f"{who}{' → ' + target if target else ''}: {len(hits)} time(s)",
                [f"account:{who}"] + ([f"account:{target}"] if target else []),
                [{"event": i} for i, _ in hits],
                first,
                last,
            )
        )
    return findings


# --- sshd and PAM configuration ------------------------------------------------------------


@check("sshd.config", "sshd configuration changes", needs_baseline=True)
def sshd_config(context: Context) -> list[Finding]:
    diff = context.changes("sshd_config")
    uncertain = context.uncertain("sshd_config")
    findings = []
    hows = [("added", diff["added"])]
    if diff["comparable"]:
        hows.append(("removed", diff["removed"]))
    for how, items in hows:
        for key, item in items.items():
            keyword = item.get("keyword", "?")
            where = f" [Match {item['match']}]" if item.get("match") else ""
            findings.append(
                Finding(
                    "sshd.config",
                    f"An sshd setting was {how}",
                    COMPROMISE,
                    "high" if keyword in SENSITIVE_SSHD else "medium",
                    f"{item.get('path')}{where}: {keyword} {item.get('value')}",
                    [f"path:{item.get('path')}"],
                    [context.change_ref("sshd_config", key, how)],
                    new=context.new_since_previous("sshd_config", key),
                    uncertain=uncertain,
                )
            )
    return findings


def pam_module(line: str) -> str | None:
    """The module a PAM line loads (`pam_exec.so`), if it loads one."""
    rest = line.split(": ", 1)[-1].strip()
    if rest.startswith("@"):
        return None
    tokens = rest.lstrip("-").split()
    if len(tokens) < 3:
        return None
    if tokens[1].startswith("["):  # a bracketed control: [success=1 default=ignore]
        closing = next((i for i, t in enumerate(tokens) if t.endswith("]")), None)
        if closing is None or closing + 1 >= len(tokens):
            return None
        return tokens[closing + 1].rsplit("/", 1)[-1]
    if tokens[1] in ("include", "substack"):
        return None
    return tokens[2].rsplit("/", 1)[-1]


DISTRIBUTIONS = {"ubuntu": "Ubuntu", "rocky": "Rocky Linux", "almalinux": "AlmaLinux"}


def official_result(context: Context, path: str, modules: dict) -> dict[str, Any] | None:
    """This file's result from checking it against the distribution's own
    package (checker.official, #189), if it is for this very file (the hash
    it compared is the one collected now)."""
    result = ((context.official or {}).get("files") or {}).get(path)
    if not isinstance(result, dict):
        return None
    item = modules.get(path) or {}
    if item.get("sha256"):
        return result if result.get("sha256") == item["sha256"] else None
    link = item.get("link_target")
    return result if link and result.get("link_target") == link else None


def _distribution(context: Context) -> str:
    system = (context.items("host").get("os") or {}).get("id")
    return (
        DISTRIBUTIONS.get(system, "the distribution")
        if isinstance(system, str)
        else ("the distribution")
    )


def _a(name: str) -> str:
    return ("an " if name[:1] in "AEIOUaeiou" else "a ") + name


# Changes the verifier, which compares content only, can't judge.
NOT_CONTENT = {"mode", "uid", "gid"}
CONTENT = {"sha256", "content_sha256", "size", "inode", "link_target"}


def _unsafe(item: dict) -> str | None:
    """What makes a PAM module dangerous whatever its content (anyone who
    can write it can change what logging in does), or None. Links are left
    out: their own mode is always 0777 and their owner can't change where
    they lead."""
    if item.get("type") == "l":
        return None
    problems = []
    try:
        mode = int(str(item.get("mode")), 8)
    except ValueError:
        mode = None
    if mode is not None and mode & 0o022:
        problems.append("writable by others than root")
    if mode is not None and mode & 0o7000:
        problems.append("setuid, setgid or sticky")
    for field in ("uid", "gid"):
        if isinstance(item.get(field), int) and item[field] != 0:
            problems.append(f"{field} {item[field]}, not root")
    return ", ".join(problems) or None


def _why_not_checked(context: Context, path: str, modules: dict, outcome: str | None) -> str:
    raw = ((context.official or {}).get("files") or {}).get(path)
    if outcome == "absent":
        return "its package has no such file"
    if outcome == "link":
        return "its package has a link there, not a file"
    if outcome == "ghost":
        return "its package lists it as a file made on the server, not one it ships"
    if isinstance(raw, dict) and raw.get("outcome") == "not_checked":
        return str(raw.get("reason") or "not checked")
    if isinstance(raw, dict):
        return "the result was for another copy of the file"
    item = modules.get(path) or {}
    if not item.get("sha256") and not item.get("link_target"):
        return "it has no hash to compare (not a regular file or link, or too large)"
    return "it wasn't among the files checked"


def _pam_module_finding(context, path, how, fields, result, modules) -> Finding | None:
    """The finding for one changed or new PAM module, or None when the
    distribution's own package explains it as an ordinary update (counted
    into one low finding)."""
    distribution = _distribution(context)
    ref = [context.change_ref("pam", path, how)]
    new = context.new_since_previous("pam", path)
    outcome = (result or {}).get("outcome")
    package = f"{(result or {}).get('package')} {(result or {}).get('version')}"
    unsafe = _unsafe(modules.get(path) or {})
    if _held(result):  # (its mode changed only, or the file came back after a check between)
        return _held_finding(context, path, result, ref, unsafe)
    if outcome == "matched" and not unsafe:
        older = result.get("older_than_baseline")
        older_seen = result.get("older_than_seen")
        if older is False and older_seen is False and not result.get("new_package"):
            return None
        if older is True or older_seen is True:
            title, variant = f"PAM was moved back to an older {distribution} package", "downgrade"
            than = (
                f"the baseline's {result.get('baseline_version')}"
                if older is True
                else f"{result.get('newest_seen')}, seen since the baseline"
            )
            why = f"{package}, older than {than}"
        elif result.get("new_package"):
            title, variant = (
                f"A PAM module from {_a(distribution)} package installed since the baseline",
                "new_package",
            )
            why = package
        else:
            title, variant = (
                f"A PAM module from {distribution}'s package, its version not compared",
                "version_unknown",
            )
            why = f"{package}; the baseline's version isn't known, or can't be compared"
        return Finding(
            "pam.changes", title, COMPROMISE, "medium", f"{path}: {why}", [f"path:{path}"],
            ref, new=new, variant=variant,
        )  # fmt: skip
    if outcome == "differs":
        return Finding(
            "pam.changes",
            f"A PAM module differs from {distribution}'s package for the installed version",
            COMPROMISE, "high", f"{path}: not the file in {package}", [f"path:{path}"],
            ref, new=new, variant="differs",
        )  # fmt: skip
    note = ""
    if outcome == "matched":  # the package's own content, in a dangerous state
        note = f" (its content is {distribution}'s, but it is {unsafe})"
    else:
        if unsafe:
            note = f" (it is {unsafe})"
        if context.official is not None and (CONTENT & set(fields or {}) or how == "added"):
            note += (
                f" (not checked against {distribution}'s package: "
                f"{_why_not_checked(context, path, modules, outcome)})"
            )
    if how == "added":
        return Finding(
            "pam.changes", "A new file in a PAM module directory", COMPROMISE, "high",
            path + note, [f"path:{path}"], ref, new=new, uncertain=context.uncertain("pam"),
            variant="added",
        )  # fmt: skip
    return Finding(
        "pam.changes", "A PAM module file changed", COMPROMISE, "high",
        f"{path}: {', '.join(sorted(fields))}{note}", [f"path:{path}"], ref, new=new,
        variant="changed",
    )  # fmt: skip


# The signed package contradicts the server (#216): a different file, no such
# file (the server claims an owner that doesn't ship it), or a link there.
WHAT_THE_PACKAGE_SAYS = {
    "differs": "not the file in {package}",
    "absent": "{package}, which the server says owns it, has no such file",
    "link": "{package} has a link there, not a file",
}


def _unchanged_modules_that_differ(context: Context, reported: set[str]) -> list[Finding]:
    """High findings for modules that aren't their package's file although
    they haven't changed since the baseline, or there is no baseline yet
    (#189, V.7): swapped before the baseline was taken, so only the
    distribution's own package can show it."""
    modules = context.items("pam")
    distribution = _distribution(context)
    found = []
    for path, result in sorted(((context.official or {}).get("files") or {}).items()):
        if not isinstance(result, dict) or result.get("how") != "unchanged" or path in reported:
            continue  # (a module changed in mode only is the change's finding)
        outcome = result.get("outcome")
        if outcome not in WHAT_THE_PACKAGE_SAYS or official_result(context, path, modules) is None:
            continue
        package = f"{result.get('package')} {result.get('version')}"
        says = WHAT_THE_PACKAGE_SAYS[outcome].format(package=package)
        if isinstance(result.get("owner_changed"), dict):
            says += f" ({_owner_change_words(result['owner_changed'])}; checked as the baseline's)"
        if context.since_baseline is not None:
            when = "unchanged since the baseline: it was already so when the baseline was taken"
        elif context.no_baseline == "no baseline yet":
            when = "found at the first check, before any baseline"
        else:
            when = "found without a comparison with the baseline"
        found.append(
            Finding(
                "pam.changes",
                f"A PAM module differs from {distribution}'s package for the installed version",
                COMPROMISE,
                "high",
                f"{path}: {says}; {when}",
                [f"path:{path}"],
                [{"item": ["pam", path]}],
                variant="differs",
            )  # fmt: skip
        )
    return found


def _owner_words(owner: Any) -> str:
    if owner == "several":
        return "more than one package"
    if not isinstance(owner, dict):
        return "no package"
    arch = owner.get("arch")
    return f"{owner.get('package')}{':' + arch if arch else ''}"


def _owner_change_words(change: dict) -> str:
    return (
        f"the package records name {_owner_words(change.get('now'))} as its owner,"
        f" not {_owner_words(change.get('baseline'))} as at the baseline"
    )


def _held(result: Any) -> bool:
    """A result #217 reports in its own right: an owner change, or a file
    an earlier check found wasn't its package's that this one doesn't show
    again (a mismatch now is `differs` as ever)."""
    return (
        isinstance(result, dict)
        and result.get("outcome") not in WHAT_THE_PACKAGE_SAYS
        and (isinstance(result.get("owner_changed"), dict) or result.get("reported_before") is True)
    )


def _held_finding(context: Context, path: str, result: dict, ref: list, unsafe=None) -> Finding:
    """An owner change is held to the baseline's owner: medium, high once
    the file was reported (or when it is dangerous whatever its content); a
    file reported before and not shown again, high (`differs`), until a
    check finds it is its package's own."""
    distribution = _distribution(context)
    change = result.get("owner_changed") if isinstance(result.get("owner_changed"), dict) else None
    before = result.get("reported_before") is True
    outcome = result.get("outcome")
    whose = "the baseline's owner" if change else "its package"
    if outcome == "matched":
        checked = f"it is the file in {whose} {result.get('package')} {result.get('version')}"
    elif outcome == "ghost":
        checked = f"{whose} lists it as a file made on the server"
    else:
        checked = f"not checked against {whose}: {result.get('reason')}"
    parts = [_owner_change_words(change)] if change else []
    parts.append(checked)
    if before:
        parts.append(f"an earlier check found it wasn't the file in {distribution}'s package")
    if unsafe:
        parts.append(f"it is {unsafe}")
    if change:
        title, variant = (
            "A PAM module's owning package changed, its content didn't",
            "owner_changed",
        )
        new = result.get("new_owner_change") is not False
    else:
        title = f"A PAM module found to differ from {distribution}'s package, not checked again"
        variant, new = "differs", False
    return Finding(
        "pam.changes",
        title,
        COMPROMISE,
        "high" if before or unsafe else "medium",
        f"{path}: " + "; ".join(parts),
        [f"path:{path}"],
        ref,
        new=new or result.get("no_longer_shown") is True,
        variant=variant,
    )


def _owner_changes(context: Context, reported: set[str]) -> list[Finding]:
    """Unchanged modules #217 reports (`_held`): how root would hide a module
    swapped before the baseline. Changed ones are reported by the change's
    finding, which says the same (`_pam_module_finding`)."""
    modules = context.items("pam")
    found = []
    for path, result in sorted(((context.official or {}).get("files") or {}).items()):
        if not isinstance(result, dict) or result.get("how") != "unchanged" or path in reported:
            continue
        if _held(result) and official_result(context, path, modules) is not None:
            found.append(_held_finding(context, path, result, [{"item": ["pam", path]}]))
    return found


# What the collector says when the owner list is incomplete for reasons honest
# servers have too (collector.OUT_OF_TIME, collector.NO_PACKAGE_RECORDS).
HONEST_GAPS = (
    "the package records couldn't be read in the time allowed",
    "no dpkg or rpm records were found",
)
PACKAGES_CUT = "the package list wasn't collected whole"  # checker.official's reason


def _packages_unread(context: Context) -> list[Finding]:
    """Modules left unchecked because the package list wasn't collected
    whole (#224): low when the time allowed ran out, else medium (a list
    padded past its limit would leave every module so)."""
    files = ((context.official or {}).get("files") or {}).values()
    count = sum(1 for r in files if isinstance(r, dict) and r.get("reason") == PACKAGES_CUT)
    if not count:
        return []

    def gaps_of(snapshot) -> list[str]:
        section = snapshot.sections.get("packages") if snapshot is not None else None
        return [str(g) for g in (section.gaps if section is not None else [])]

    gaps = gaps_of(context.snapshot)
    # Low only for a timeout the baseline had too (root can bring one on).
    earlier = gaps_of(context.baseline_snapshot)
    timed_out = (
        bool(gaps)
        and all("time" in g for g in gaps)
        and any("time" in g for g in earlier)
        and context.baseline_snapshot is not context.snapshot
    )
    return [
        Finding(
            "pam.changes",
            "The server's package list wasn't collected whole, so PAM modules weren't checked",
            COMPROMISE,
            "low" if timed_out else "medium",
            f"{count} PAM module file(s) not checked: "
            + ("; ".join(gaps[:3]) or "no reason given"),
            [],
            [],
            variant="packages_unread",
        )
    ]


# A package manager's file mid-update (dpkg's .dpkg-new, rpm's ";1a2b3c4d"):
# no package lists it, and PAM loads it only if a line names it.
UPDATE_TEMPORARY = re.compile(r"(?:\.dpkg-(?:new|tmp|dist|old)|;[0-9a-f]{8})\Z")


def _unhashed_modules(context: Context, reported: set[str]) -> list[Finding]:
    """Files in a PAM module directory that couldn't be checked against a
    package, said in their own right: a regular file the collector didn't
    hash (larger than its limit, refused, unreadable; distribution modules
    are far below the limit: high, out of time only medium), a device file
    there (one can be mapped like a module: high), and a directory listing
    cut short or not entered all the way down (medium)."""
    from checker.official import MODULE_PATH

    found = []
    section = context.snapshot.sections.get("pam")
    for gap in section.gaps if section is not None else []:
        if str(gap).startswith("walk of "):
            found.append(
                Finding(
                    "pam.changes",
                    "A PAM module directory wasn't listed whole",
                    COMPROMISE,
                    "medium",
                    str(gap),
                    [],
                    [],
                    variant="unhashed",
                )  # fmt: skip
            )
    for path, item in sorted(context.items("pam").items()):
        if path in reported or not MODULE_PATH.fullmatch(path):
            continue
        if item.get("type") in ("b", "c"):
            found.append(
                Finding(
                    "pam.changes",
                    "A device file in a PAM module directory",
                    COMPROMISE,
                    "high",
                    f"{path}: device {item.get('device')}",
                    [f"path:{path}"],
                    [{"item": ["pam", path]}],
                    variant="unhashed",
                )  # fmt: skip
            )
            continue
        if item.get("type") != "-" or item.get("sha256"):
            continue
        why = str(item.get("hash_skipped") or "no hash was sent")
        found.append(
            Finding(
                "pam.changes",
                "A file in a PAM module directory that couldn't be checked",
                COMPROMISE,
                "medium" if why == "time limit" else "high",
                f"{path}: {why}" + (f" ({item['size']} bytes)" if item.get("size") else ""),
                [f"path:{path}"],
                [{"item": ["pam", path]}],
                variant="unhashed",
            )
        )
    return found


def _pam_owner_records(context: Context, reported: set[str]) -> list[Finding]:
    """What the server's owner records leave out or can't vouch for:
    - a list cut at its limit, which no real system reaches (a few hundred
      PAM module files): high, since the modules past it can't be checked;
    - a list left incomplete by records that couldn't be read: medium;
    - a PAM module no package lists, in a complete owner list, or listed only
      under names dpkg and rpm never make: high, even when the scan for
      unowned files didn't send it (its own limit can be filled);
    - an unchanged module whose package isn't installed once, or isn't in
      the distribution's signed lists (a vendor's package, or a made-up one):
      medium (`owner_unverified`), high when more packages list it than the
      collector sends."""
    from checker.official import MODULE_PATH

    owners = context.snapshot.live.get("pam_owners")
    if not isinstance(owners, dict):
        return []
    distribution = _distribution(context)
    found = []
    if owners.get("cut") == "limit":
        found.append(
            Finding(
                "pam.changes",
                "More PAM module files than any system has: not all their owners were recorded",
                COMPROMISE,
                "high",
                f"{len(owners.get('owners') or {})} owner records sent, the collector's limit",
                [],
                [],
                variant="owners_cut",
            )  # fmt: skip
        )
    elif owners.get("complete") is not True:
        # (Out of time, a list unreadable, a record dropped: the owner-less
        # check below can't run, so this is said in its own right. Out of
        # time, or no package manager at all, happens on honest servers: low.)
        problems = [str(p) for p in owners.get("problems") or []]
        # Low only when the baseline had the same gap: root can bring on a
        # timeout by padding the records, so one that is new stays medium.
        before = (
            (context.baseline_snapshot.live.get("pam_owners") or {}).get("problems") or []
            if context.baseline_snapshot is not None
            else []
        )
        honest = (
            bool(problems)
            and all(p in HONEST_GAPS for p in problems)
            and set(problems) <= {str(p) for p in before}
        )
        found.append(
            Finding(
                "pam.changes",
                "The server's package records couldn't all be read",
                COMPROMISE,
                "low" if honest else "medium",
                "; ".join(problems)
                or "the owner list is incomplete, and the collector didn't say why",
                [],
                [],
                variant="owners_unread",
            )  # fmt: skip
        )
    listed = owners.get("owners") or {}
    complete = owners.get("complete") is True
    unowned = context.items("unowned_executables")
    for path, item in sorted(context.items("pam").items()):
        # Any name: PAM loads a module by its path, whatever it ends in.
        if path in unowned:
            continue
        # Regular files: the scan for unowned files looks at those only, so a
        # link (an agent's installer may make one) isn't reported this way.
        if not MODULE_PATH.fullmatch(path) or not item.get("sha256") or item.get("type") == "l":
            continue
        record = listed.get(path)
        if UPDATE_TEMPORARY.search(path) and record is None and complete:
            found.append(
                Finding(
                    "pam.changes",
                    "A package manager's temporary file in a PAM module directory",
                    COMPROMISE,
                    "medium",
                    f"{path}: no package lists it (an update was running, or a file named so)",
                    [f"path:{path}"],
                    [{"item": ["pam", path]}],
                )  # fmt: skip
            )
            continue
        if isinstance(record, dict) and record.get("odd"):
            why = "its package records name it only with names dpkg and rpm never make"
        elif record is None and complete:
            why = "no package lists it"
        else:
            continue
        found.append(
            Finding(
                "pam.changes",
                "A PAM module that no package installed",
                COMPROMISE,
                "high",
                f"{path}: {why}",
                [f"path:{path}"],
                [{"item": ["pam", path]}],
            )  # fmt: skip
        )
    modules = context.items("pam")
    groups: dict[tuple, list[str]] = {}
    for path, result in sorted(((context.official or {}).get("files") or {}).items()):
        if (
            not isinstance(result, dict)
            or result.get("how") != "unchanged"
            or path in reported
            or result.get("unverified") not in ("package", "version")
            or _held(result)
            or result.get("outcome") != "not_checked"
            or official_result(context, path, modules) is None
        ):
            continue
        key = (
            result["unverified"],
            str(result.get("package") or "several packages"),
            str(result.get("version") or ""),
            str(result.get("reason") or "not checked"),
            result.get("claims_cut") is True,
        )
        groups.setdefault(key, []).append(path)
    # One finding per package: one package ships many modules.
    for (kind, package, version, why, cut), paths in sorted(groups.items()):
        if cut:
            why += "; more packages list it than the collector sends"
        shown = ", ".join(paths[:5]) + (f" and {len(paths) - 5} more" if len(paths) > 5 else "")
        if kind == "package":
            title = (
                f"PAM modules whose package isn't one of {distribution}'s signed packages,"
                " or isn't installed"
            )
            band, variant = ("high" if cut else "medium"), "owner_unverified"
        else:
            title = f"PAM modules from {_a(distribution)} package version that couldn't be checked"
            band, variant = "low", "version_unverified"
        found.append(
            Finding(
                "pam.changes",
                title,
                COMPROMISE,
                band,
                f"{package} {version}".strip() + f": {why}: {len(paths)} file(s): {shown}",
                [f"path:{p}" for p in paths],
                [{"item": ["pam", p]} for p in paths],
                variant=variant,
            )  # fmt: skip
        )
    return found


def _pam_modules_updated(context: Context, explained: list) -> Finding:
    """One low finding for every module the distribution's own packages
    explain: an ordinary update, not one strong sign per file."""
    distribution = _distribution(context)

    def words(r):
        before, now = r.get("baseline_version"), r.get("version")
        if before == now:
            return f"{r.get('package')} {now} (the same version, its files replaced)"
        return f"{r.get('package')} {before} -> {now}"

    packages = sorted({words(r) for _, _, r in explained})
    return Finding(
        "pam.changes",
        f"PAM modules updated by {distribution}'s own packages",
        COMPROMISE,
        "low",
        f"{len(explained)} file(s), each the same as in the signed package: {', '.join(packages)}",
        [f"path:{path}" for path, _, _ in explained],
        [context.change_ref("pam", path, how) for path, how, _ in explained],
        new=any(context.new_since_previous("pam", path) for path, _, _ in explained),
        variant="official_update",
    )


@check(
    "pam.changes",
    "PAM: pam_exec lines, configuration changes, unknown modules",
    variants=(
        "official_update",
        "downgrade",
        "new_package",
        "version_unknown",
        "differs",
        "owner_changed",
        "owners_cut",
        "owners_unread",
        "owner_unverified",
        "version_unverified",
        "packages_unread",
        "unhashed",
        "added",
        "changed",
    ),  # fmt: skip
)
def pam_changes(context: Context) -> list[Finding]:
    findings = []
    rules = context.items("pam_rules")
    diff = context.changes("pam_rules")
    added = diff["added"] if diff else {}
    for key, item in rules.items():
        if pam_module(key) == "pam_exec.so" and key not in added:
            findings.append(
                Finding(
                    "pam.changes",
                    "PAM runs a program (pam_exec)",
                    COMPROMISE,
                    "medium",
                    key,
                    [f"path:{item.get('path')}"],
                    [{"item": ["pam_rules", key]}],
                )
            )
    if diff is not None:
        uncertain = context.uncertain("pam_rules")
        hows = [("added", diff["added"])]
        if diff["comparable"]:
            hows.append(("removed", diff["removed"]))
        for how, items in hows:
            for key, item in items.items():
                module = pam_module(key)
                findings.append(
                    Finding(
                        "pam.changes",
                        f"A PAM line was {how}"
                        + (" that runs a program (pam_exec)" if module == "pam_exec.so" else ""),
                        COMPROMISE,
                        "high",
                        key,
                        [f"path:{item.get('path')}"] + ([f"module:{module}"] if module else []),
                        [context.change_ref("pam_rules", key, how)],
                        new=context.new_since_previous("pam_rules", key),
                        uncertain=uncertain,
                    )
                )
        modules = context.items("pam")
        explained: list[tuple[str, str, dict]] = []
        reported: set[str] = set()
        for how, entries in (
            ("added", (context.changes("pam") or {}).get("added", {})),
            ("changed", (context.changes("pam") or {}).get("changed", {})),
        ):
            for path, fields in entries.items():
                if "/security/" not in path:
                    continue
                # A change in content, or a mode or owner change that leaves the
                # module dangerous (a harmless one, a package's own, is no sign).
                if how == "changed" and not (
                    CONTENT & set(fields)
                    or (NOT_CONTENT & set(fields) and _unsafe(modules.get(path) or {}))
                ):
                    continue
                result = official_result(context, path, modules)
                reported.add(path)
                finding = _pam_module_finding(context, path, how, fields, result, modules)
                if finding is None:
                    explained.append((path, how, result))
                else:
                    findings.append(finding)
        if explained:
            findings.append(_pam_modules_updated(context, explained))
    findings += _unchanged_modules_that_differ(context, reported if diff is not None else set())
    findings += _owner_changes(context, reported if diff is not None else set())
    findings += _pam_owner_records(context, reported if diff is not None else set())
    findings += _packages_unread(context)
    findings += _unhashed_modules(context, reported if diff is not None else set())
    for path in context.items("unowned_executables"):
        # Any name: PAM loads a module by its path.
        if "/security/" in path and not UPDATE_TEMPORARY.search(path):
            findings.append(
                Finding(
                    "pam.changes",
                    "A PAM module that no package installed",
                    COMPROMISE,
                    "high",
                    path,
                    [f"path:{path}"],
                    [{"item": ["unowned_executables", path]}],
                )
            )
    return findings
