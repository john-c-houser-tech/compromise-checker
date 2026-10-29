"""Accounts and authentication (DESIGN.md §8.3)."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta

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
    and no login shell, both as logged and as it is now; a web account is
    never one (a web shell's account). Such an account, or such an
    account's group membership, is low: the install is the change worth
    knowing (software.packages)."""
    fields = event.fields
    user = fields.get("user")
    if user in WEB_USERS:
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


@check(
    "account.log_changes",
    "Account and group changes recorded in the logs",
    variants=LOG_CHANGE_VARIANTS,
)
def log_changes(context: Context) -> list[Finding]:
    findings = []
    installs = _package_installs(context)
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


@check("pam.changes", "PAM: pam_exec lines, configuration changes, unknown modules")
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
        for path in (context.changes("pam") or {}).get("added", {}):
            if "/security/" in path:
                findings.append(
                    Finding(
                        "pam.changes",
                        "A new file in a PAM module directory",
                        COMPROMISE,
                        "high",
                        path,
                        [f"path:{path}"],
                        [context.change_ref("pam", path, "added")],
                        new=context.new_since_previous("pam", path),
                        uncertain=context.uncertain("pam"),
                    )
                )
        for path, fields in (context.changes("pam") or {}).get("changed", {}).items():
            if "/security/" in path and (
                {"sha256", "content_sha256", "size", "inode"} & set(fields)
            ):
                findings.append(
                    Finding(
                        "pam.changes",
                        "A PAM module file changed",
                        COMPROMISE,
                        "high",
                        f"{path}: {', '.join(sorted(fields))}",
                        [f"path:{path}"],
                        [context.change_ref("pam", path, "changed")],
                        new=context.new_since_previous("pam", path),
                    )
                )
    for path in context.items("unowned_executables"):
        if "/security/" in path and path.endswith(".so"):
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
