"""Normalized events from a bundle (DESIGN.md §6): one per log record that
a check could use, with its time on the host's clock and corrected to the
controller's, typed fields, and the (already masked) line it came from.

Events can always be regenerated from the bundle; the tool's own session
on the host is recognised and marked (`own_session`) rather than dropped."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from checker.protocol import Error, Manifest, Record, SourceEnd, SourceStart, Trailer

PARSER_VERSION = 5  # 3: system.clock_changed; 4: unit.starting, unit.finished; 5: mail
MAX_EVENT_LINE = 2048  # characters of the source line kept on each event

_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) "
    r"(?P<host>\S+) (?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) "
    r"(?P<host>\S+) (?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)


@dataclass
class Event:
    time: str | None  # ISO 8601 on the host's clock (None: no usable time)
    corrected: str | None  # the same, corrected by the host's measured clock offset
    source: str  # module, and the file for a log ("auth_log:/var/log/secure")
    type: str
    fields: dict[str, Any] = field(default_factory=dict)
    program: str | None = None
    line: str = ""
    own_session: bool = False
    also_in: list[str] = field(default_factory=list)  # other sources that logged it too

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- What a log message means ------------------------------------------------------

_RULES: list[tuple[str | None, re.Pattern[str], str]] = [
    # (program, pattern, event type); program None matches any.
    (
        "sshd",
        re.compile(
            r"^Accepted (?P<method>\S+) for (?P<user>.+?) from (?P<address>\S+) port (?P<port>\d+)"
            r"(?: ssh2)?(?:: (?P<key_type>\S+) (?P<fingerprint>\S+))?"
        ),
        "ssh.login.accepted",
    ),
    (
        "sshd",
        re.compile(
            r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) "
            r"from (?P<address>\S+) port (?P<port>\d+)"
        ),
        "ssh.login.failed",
    ),
    (
        "sshd",
        re.compile(r"^Invalid user (?P<user>.*?) from (?P<address>\S+)(?: port (?P<port>\d+))?"),
        "ssh.invalid_user",
    ),
    (
        "sshd",
        re.compile(
            r"^(?:error: )?maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
            r"(?P<user>.*?) from (?P<address>\S+) port (?P<port>\d+)"
        ),
        "ssh.login.too_many_failures",
    ),
    (
        "sshd",
        re.compile(
            r"^(?:Connection closed by|Disconnected from) (?:authenticating|(?P<invalid>invalid)) "
            r"user (?P<user>.*?) (?P<address>\S+) port (?P<port>\d+)"
        ),
        "ssh.login.abandoned",
    ),
    (
        None,
        re.compile(
            r"^pam_unix\((?P<service>[^:]+):session\): session (?P<action>opened|closed) "
            r"for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>[^\s(]+))?"
        ),
        "session",
    ),
    (
        None,
        re.compile(
            r"^(?P<module>pam_unix|pam_sss)\((?P<service>[^:]+):auth\): authentication failure;"
            r"(?P<rest>.*)$"
        ),
        "auth.failure",
    ),
    (
        # A refusal or failure puts its reason first ("3 incorrect password
        # attempts", "command not allowed", "user NOT in sudoers").
        "sudo",
        re.compile(
            r"^\s*(?P<user>\S+) : (?:(?P<reason>[^;=]+?) ; )?(?P<details>(?:\S+=[^;]*; )*)"
            r"COMMAND=(?P<command>.*)$"
        ),
        "sudo.command",
    ),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : (?P<reason>user NOT in sudoers)"), "sudo.denied"),
    ("su", re.compile(r"^FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+)"), "su.failed"),
    ("su", re.compile(r"^\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)"), "su.switch"),
    (
        "useradd",
        re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)"),
        "account.created",
    ),
    ("userdel", re.compile(r"^delete user '(?P<user>[^']+)'"), "account.deleted"),
    (
        "usermod",
        re.compile(r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"),
        "group.member_added",
    ),
    (
        "usermod",
        re.compile(r"^delete '(?P<user>[^']+)' from (?:shadow )?group '(?P<group>[^']+)'"),
        "group.member_removed",
    ),
    (
        "usermod",
        re.compile(r"^change user name '(?P<old_user>[^']+)' to '(?P<user>[^']+)'"),
        "account.renamed",
    ),
    ("usermod", re.compile(r"^(?P<action>lock|unlock) user '(?P<user>[^']+)'"), "account.lock"),
    ("usermod", re.compile(r"^change user '(?P<user>[^']+)'"), "account.modified"),
    (
        "gpasswd",
        re.compile(r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)"),
        "group.member_added",
    ),
    (
        "gpasswd",
        re.compile(r"^user (?P<user>\S+) removed by (?P<by>\S+) from group (?P<group>\S+)"),
        "group.member_removed",
    ),
    (
        "gpasswd",
        re.compile(r"^members of group (?P<group>\S+) set by (?P<by>\S+) to (?P<members>.*)$"),
        "group.members_set",
    ),
    ("groupadd", re.compile(r"^new group: name=(?P<group>[^,]+)"), "group.created"),
    (None, re.compile(r"password changed for (?P<user>\S+)"), "account.password_changed"),
    (
        "systemd-logind",
        # systemd 256 and later quote both: New session '5' of user 'jch' with …
        re.compile(
            r"^New session '?(?P<session>[^\s']+?)'? of user '?(?P<user>[^\s']+?)'?\.?(?:\s|$)"
        ),
        "logind.session_new",
    ),
    (
        "systemd-logind",
        re.compile(
            r"^(?:Removed session '?(?P<session>[^\s'.]+)"
            r"|Session '?(?P<session2>[^\s'.]+)'? logged out)"
        ),
        "logind.session_end",
    ),
    (
        "systemd-logind",
        re.compile(
            r"^(?:System is (?P<what>rebooting|powering down)"
            r"|The system will (?P<what2>reboot|power off|halt|suspend) now"
            r"|Power key pressed)"
        ),
        "system.shutdown_requested",
    ),
    (
        "kernel",
        re.compile(r"Out of memory: Killed process (?P<pid>\d+) \((?P<comm>[^)]+)\)"),
        "kernel.oom_kill",
    ),
    (
        "kernel",
        re.compile(r"(?P<comm>\S+)\[(?P<pid>\d+)\]: segfault at"),
        "kernel.segfault",
    ),
    ("kernel", re.compile(r"(?:BUG: |Oops|general protection fault)"), "kernel.oops"),
    ("kernel", re.compile(r"blocked for more than \d+ seconds"), "kernel.hung_task"),
    ("kernel", re.compile(r"(?:mce: |Machine check)"), "kernel.machine_check"),
    (
        "kernel",
        re.compile(
            r"(?P<module>[\w-]+): (?:module verification failed|loading out-of-tree module"
            r"|module license '[^']*' taints kernel)"
        ),
        "kernel.module_taint",
    ),
    (
        "systemd-coredump",
        re.compile(r"Process (?P<pid>\d+) \((?P<comm>[^)]+)\) of user (?P<uid>\d+) dumped core"),
        "process.core_dump",
    ),
    (
        "systemd",
        re.compile(r"^(?P<unit>\S+\.(?:service|timer|socket|mount|scope)): Failed with result"),
        "unit.failed",
    ),
    ("systemd", re.compile(r"^Started (?P<what>.+?)\.?$"), "unit.started"),
    ("systemd", re.compile(r"^Stopped (?P<what>.+?)\.?$"), "unit.stopped"),
    ("systemd", re.compile(r"^Time has been changed$"), "system.clock_changed"),
    # Oneshot services (the automatic updaters) log Starting… and Finished…,
    # never Started.
    ("systemd", re.compile(r"^Starting (?P<what>.+?)(?:\.\.\.|…)$"), "unit.starting"),
    ("systemd", re.compile(r"^Finished (?P<what>.+?)\.?$"), "unit.finished"),
    (
        "systemd",
        re.compile(r"^Reached target (?P<target>(?:System )?(?:Shutdown|Reboot|Power-Off)\S*)"),
        "system.shutdown",
    ),
]
_SUDO_DETAIL = re.compile(r"(TTY|PWD|USER)=([^;]*?) ;")


def classify(program: str | None, message: str) -> tuple[str, dict[str, Any]] | None:
    """(event type, fields) for a log message a check can use, else None."""
    name = (program or "").rsplit("/", 1)[-1]
    for wanted, pattern, kind in _RULES:
        if wanted is not None and name != wanted and not name.startswith(wanted + "-"):
            continue
        match = pattern.search(message)
        if not match:
            continue
        fields = {k: v for k, v in match.groupdict().items() if v is not None}
        if "port" in fields and fields["port"].isdigit():
            fields["port"] = int(fields["port"])
        if kind == "system.shutdown_requested" and "what2" in fields:
            fields["what"] = fields.pop("what2")
        if kind == "logind.session_end" and "session2" in fields:
            fields["session"] = fields.pop("session2")
        if kind == "account.lock":
            kind = "account.locked" if fields.pop("action") == "lock" else "account.unlocked"
        if kind == "sudo.command":
            reason = fields.get("reason", "")
            if reason:  # refused or failed: the command did not run
                failed = "incorrect password" in reason or "password is required" in reason
                kind = "sudo.failed" if failed else "sudo.denied"
            details = dict(_SUDO_DETAIL.findall(fields.pop("details", "") + " ;"))
            # sudo's USER= is who the command runs as, not who ran sudo.
            names = {"TTY": "tty", "PWD": "pwd", "USER": "runas"}
            fields.update({names[k]: v.strip() for k, v in details.items()})
        if kind in ("ssh.login.failed", "ssh.login.too_many_failures", "ssh.login.abandoned"):
            fields["invalid_user"] = bool(fields.pop("invalid", None))
        if kind == "session":
            kind = "session." + fields.pop("action")
        return kind, fields
    return None


# --- Mail (DESIGN.md §8.9) ---------------------------------------------------------------

# Postfix's daemons log as postfix/<daemon> (postfix-<instance>/<daemon>
# for a second instance). Every address arrives fingerprinted (h:…@domain).
_POSTFIX = re.compile(r"^postfix[\w.-]*/(?P<daemon>[\w-]+)$")
_POSTFIX_PICKUP = re.compile(r"^(?P<queue_id>\w+): uid=(?P<uid>\d+) from=<(?P<sender>[^>]*)>")
_POSTFIX_DELIVERY = re.compile(
    r"^(?P<queue_id>\w+): to=<(?P<recipient>[^>]*)>,(?: orig_to=<[^>]*>,)? "
    r"relay=(?P<relay>[^,\s]+),.*? status=(?P<status>sent|deferred|bounced|expired)\b"
)
# Postfix's agents that deliver into mailboxes on the host itself, and the
# relays that say so (Dovecot's LMTP socket, private/…).
_LOCAL_AGENTS = {"local", "virtual", "lmtp"}
_LOCAL_RELAYS = ("local", "virtual", "private/", "dovecot")
_DELIVERY_STATUS = {
    "sent": "mail.sent",
    "deferred": "mail.deferred",
    "bounced": "mail.bounced",
    "expired": "mail.bounced",
}
_EXIM = re.compile(
    r"^(?P<date>\d{4}-\d\d-\d\d) (?P<clock>\d\d:\d\d:\d\d)(?:\.\d+)?(?: (?P<zone>[+-]\d{4}))?"
    r"(?: \[(?P<pid>\d+)\])? (?P<queue_id>\S+) (?P<flag><=|=>|->|\*\*|==) (?P<address>\S+)"
    r"(?P<rest>.*)$"
)
_EXIM_FLAGS = {"=>": "mail.sent", "->": "mail.sent", "==": "mail.deferred", "**": "mail.bounced"}
_EXIM_HOST = re.compile(r" H=(\S+(?: \[[^\]]+\])?)")
_EXIM_FIELD = re.compile(r" (U|P|R|T)=(\S+)")


def _domain(address: str) -> str:
    return address.rpartition("@")[2].lower() if "@" in address else ""


def classify_mail(program: str | None, message: str) -> tuple[str, dict[str, Any]] | None:
    """(event type, fields) for a Postfix log message about outgoing mail:
    a local submission (pickup, with the submitting UID), and each
    delivery attempt sent, deferred or bounced."""
    daemon = _POSTFIX.match(program or "")
    if daemon is None:
        return None
    if daemon["daemon"] == "pickup":
        found = _POSTFIX_PICKUP.search(message)
        if found:
            fields = found.groupdict()
            fields["uid"] = int(fields["uid"])
            return "mail.submitted", fields
        return None
    found = _POSTFIX_DELIVERY.search(message)
    if found is None:
        return None
    fields = found.groupdict()
    status = fields.pop("status")
    fields["domain"] = _domain(fields["recipient"])
    if daemon["daemon"] in _LOCAL_AGENTS or fields["relay"].startswith(_LOCAL_RELAYS):
        fields["local"] = True  # delivered into a mailbox here: not outgoing
    return _DELIVERY_STATUS[status], fields


def classify_exim(line: str) -> tuple[str, dict[str, Any], dict[str, str]] | None:
    """(event type, fields, the line's date parts) for an Exim main log line
    about outgoing mail: a local submission (P=local, with the submitting
    user) and each delivery sent, deferred or bounced."""
    found = _EXIM.match(line)
    if found is None:
        return None
    rest = found["rest"]
    named = dict(_EXIM_FIELD.findall(rest))
    when = {k: found[k] for k in ("date", "clock", "zone") if found[k]}
    if found["flag"] == "<=":
        if not named.get("P", "").startswith("local") or "U" not in named:
            return None  # mail received from elsewhere, not submitted here
        fields = {"queue_id": found["queue_id"], "user": named["U"], "sender": found["address"]}
        return "mail.submitted", fields, when
    host = _EXIM_HOST.search(rest)
    fields = {
        "queue_id": found["queue_id"],
        "recipient": found["address"],
        "relay": host.group(1) if host else named.get("T", "local"),
        "domain": _domain(found["address"]),
    }
    if host is None and found["flag"] in ("=>", "->"):
        fields["local"] = True  # no remote host: a local delivery
    return _EXIM_FLAGS[found["flag"]], fields, when


# --- Times ---------------------------------------------------------------------------


def host_zone(localtime_link: str | None) -> tuple[tzinfo, bool]:
    """The host's zone from its /etc/localtime link (…/zoneinfo/Area/City);
    (UTC, True) when it can't be known — the bool says it was assumed."""
    if localtime_link and "zoneinfo/" in localtime_link:
        name = localtime_link.split("zoneinfo/", 1)[1]
        try:
            return ZoneInfo(name), False
        except (ZoneInfoNotFoundError, ValueError):
            pass
    return UTC, True


def resolve_syslog_years(
    parsed: list[tuple[int, int, str]], newest: datetime, zone: tzinfo
) -> list[tuple[datetime | None, bool]]:
    """Years for traditional syslog dates (no year), each with whether it is
    uncertain. Lines are in time order and the last is no later than the
    file's modification time (`newest`), so walking back from the end, the
    year steps back whenever the month goes up (December before January),
    and a last line dated after the file's time belongs to the year before.

    Only December before January is a sure year boundary: any other step
    back (a log quiet across New Year, or a clock that jumped, as on a VM
    that boots on a wrong date until NTP corrects it), a line dated after
    the one following it in the same month, and a last line more than 31
    days before the file's time mark the times from there back uncertain."""
    out: list[tuple[datetime | None, bool]] = [(None, True)] * len(parsed)
    local_newest = newest.astimezone(zone)
    year, later, uncertain = local_newest.year, None, False
    for i in range(len(parsed) - 1, -1, -1):
        month, day, clock = parsed[i]
        if later is None:
            if month > local_newest.month:
                year -= 1
                uncertain = month != 12 or local_newest.month != 1
        elif month > later[0]:
            year -= 1
            uncertain = uncertain or (month, later[0]) != (12, 1)
        elif (month, day, clock) > later:
            uncertain = True  # out of order within a month: the clock went back
        later = (month, day, clock)
        try:
            hour, minute, second = (int(x) for x in clock.split(":"))
            moment = datetime(year, month, day, hour, minute, second, tzinfo=zone)
        except ValueError:  # 29 February in the wrong year, a damaged line
            out[i] = (None, True)
            continue
        if i == len(parsed) - 1 and local_newest - moment > timedelta(days=31):
            uncertain = True
        out[i] = (moment, uncertain)
    return out


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


# --- Building events from a bundle ------------------------------------------------------


class EventBuilder:
    """A bundle walk consumer (checker.bundle.Consumer) that produces
    events. `controller_started` is when the controller started the run
    (its clock), from which the host's clock offset is measured."""

    def __init__(self, controller_started: datetime | None = None) -> None:
        self.controller_started = controller_started
        self.events: list[Event] = []
        self.manifest_data: Manifest | None = None
        self.zone: tzinfo = UTC
        self.zone_assumed = True
        self.offset = timedelta(0)
        self.offset_known = False
        self.problems: list[str] = []
        # Per open auth_log source: the classified lines with traditional
        # syslog dates, waiting for the source's end to learn their years.
        self._syslog: dict[int, list[tuple[tuple[int, int, str], tuple]]] = {}

    # Consumer interface
    def manifest(self, manifest: Manifest) -> None:
        self.manifest_data = manifest
        if self.controller_started is not None:
            # The collector's start on the host's clock against the
            # controller's: the difference is the host's clock offset (the
            # program starts within seconds of the session).
            self.offset = manifest.started_at - self.controller_started
            self.offset_known = True

    def record(self, record: Record) -> None:
        if record.module == "host_facts" and record.name == "clock":
            self.zone, self.zone_assumed = host_zone(record.data.get("localtime_link"))
        elif record.module == "login_records" and record.name == "login_record":
            self._login_record(record.data)

    def source_start(self, start: SourceStart) -> None:
        if _log_kind(start) is not None:
            self._syslog[start.source_id] = []

    def line(self, start: SourceStart, line: bytes) -> None:
        text = line.decode("utf-8", "replace")
        kind = _log_kind(start)
        if kind == "exim":
            self._exim_line(start, text)
        elif kind is not None:
            self._log_line(start, text)
        elif start.module in ("auth_journal", "system_journal"):
            self._journal_line(start, text)
        elif start.module == "mail" and start.kind == "command":
            self._journal_line(start, text, "mail_journal", classify_mail)
        elif start.module == "boots":
            self._boot_line(start, text)

    def source_end(self, start: SourceStart, end: SourceEnd) -> None:
        if start.source_id in self._syslog:
            self._flush_syslog(start)

    def source_cut(self, start: SourceStart) -> None:
        if start.source_id in self._syslog:
            self._flush_syslog(start, cut=True)

    def error(self, error: Error) -> None:
        pass

    def trailer(self, trailer: Trailer) -> None:
        pass

    # Helpers
    def _add(self, moment, source, kind, fields, program=None, line=""):
        """Add one event. Classified fields are this event's own dict."""
        corrected = moment - self.offset if (moment is not None and self.offset_known) else moment
        self.events.append(
            Event(
                time=_iso(moment),
                corrected=_iso(corrected),
                source=source,
                type=kind,
                fields=fields,
                program=program,
                line=line[:MAX_EVENT_LINE],
            )
        )

    def _log_line(self, start: SourceStart, text: str) -> None:
        source, rules = _log_source(start)
        match = _RFC3339.match(text)
        if match:
            try:
                moment = datetime.fromisoformat(match["ts"].replace("Z", "+00:00"))
            except ValueError:
                moment = None
            self._message(
                moment, source, match["prog"], match["msg"], match["pid"], text, rules=rules
            )
            return
        match = _SYSLOG.match(text)
        if match and match["mon"] in _MONTHS:
            # Classified now, so only lines that are events wait for their year.
            found = rules(match["prog"], match["msg"])
            if found is None:
                return
            key = (_MONTHS[match["mon"]], int(match["day"]), match["time"])
            pending = (match["prog"], match["pid"], found, text[:MAX_EVENT_LINE])
            self._syslog.setdefault(start.source_id, []).append((key, pending))

    def _flush_syslog(self, start: SourceStart, cut: bool = False) -> None:
        pending = self._syslog.pop(start.source_id, [])
        if not pending:
            return
        # A cut-off source has no later line than its last that arrived;
        # its modification time still bounds it.
        mtime = (start.meta or {}).get("mtime")
        try:
            newest = datetime.fromisoformat(mtime) if mtime else None
        except ValueError:
            newest = None
        if newest is None and self.manifest_data is not None:
            newest = self.manifest_data.started_at
        if newest is None:
            newest = datetime.now(UTC)
        years = resolve_syslog_years([key for key, _ in pending], newest, self.zone)
        source, _ = _log_source(start)
        for (moment, uncertain), (_, (program, pid, found, text)) in zip(
            years, pending, strict=True
        ):
            extra: dict[str, Any] = {"year_inferred": True}
            if uncertain:
                extra["time_uncertain"] = True
            if cut:
                extra["source_cut"] = True
            self._emit(moment, source, program, found, pid, text, extra)

    def _exim_line(self, start: SourceStart, text: str) -> None:
        found = classify_exim(text.rstrip("\n"))
        if found is None:
            return
        kind, fields, when = found
        try:
            moment = datetime.fromisoformat(f"{when['date']}T{when['clock']}")
            if "zone" in when:
                moment = datetime.fromisoformat(
                    f"{when['date']}T{when['clock']}{when['zone'][:3]}:{when['zone'][3:]}"
                )
            else:  # Exim logs local time unless told otherwise
                moment = moment.replace(tzinfo=self.zone)
        except ValueError:
            moment = None
        self._add(moment, f"mail_log:{start.name}", kind, fields, "exim", text)

    def _message(self, moment, source, program, message, pid, text, extra=None, rules=None):
        found = (rules or classify)(program, message)
        if found is not None:
            self._emit(moment, source, program, found, pid, text, extra)

    def _emit(self, moment, source, program, found, pid, text, extra=None):
        kind, fields = found
        if pid:
            fields.setdefault("pid", int(pid))
        if extra:
            fields.update(extra)
        self._add(moment, source, kind, fields, program, text)

    def _journal_line(self, start: SourceStart, text: str, source=None, rules=None) -> None:
        try:
            entry = json.loads(text)
        except ValueError:
            return
        if not isinstance(entry, dict):
            return
        message = entry.get("MESSAGE")
        if isinstance(message, list):  # bytes that weren't valid UTF-8
            message = bytes(b for b in message if isinstance(b, int) and 0 <= b < 256).decode(
                "utf-8", "replace"
            )
        if not isinstance(message, str):
            return
        stamp = entry.get("_SOURCE_REALTIME_TIMESTAMP") or entry.get("__REALTIME_TIMESTAMP")
        try:
            moment = datetime.fromtimestamp(int(stamp) / 1e6, UTC) if stamp else None
        except (ValueError, OverflowError, OSError):
            moment = None
        if entry.get("_TRANSPORT") == "kernel":
            program = "kernel"
        elif str(entry.get("_PID")) == "1":
            program = "systemd"
        else:
            program = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
        extra = {}
        for key, name in (("_AUDIT_SESSION", "audit_session"), ("_BOOT_ID", "boot_id")):
            if isinstance(entry.get(key), str):
                extra[name] = entry[key]
        # Fields the journal itself sets ("trusted"): who really logged it,
        # whatever name the message gives itself.
        for key, name in (
            ("_SYSTEMD_UNIT", "systemd_unit"),
            ("_COMM", "journal_comm"),
            ("_UID", "journal_uid"),
        ):
            if isinstance(entry.get(key), str):
                extra[name] = entry[key]
        pid = entry.get("SYSLOG_PID") or entry.get("_PID")
        pid = pid if isinstance(pid, str) and pid.isdigit() else None
        self._message(moment, source or start.module, program, message, pid, message, extra, rules)

    _BOOT = re.compile(
        r"^\s*(?P<index>-?\d+)\s+(?P<boot_id>[0-9a-f]{32})\s+(?:\w{3}\s+)?"
        r"(?P<first>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?: \S+)?\s+(?:\w{3}\s+|—\s*)?"
        r"(?P<last>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)?"
    )

    def _boot_line(self, start: SourceStart, text: str) -> None:
        match = self._BOOT.match(text)
        if not match:
            return
        try:
            first = datetime.fromisoformat(match["first"]).replace(tzinfo=self.zone)
        except ValueError:
            first = None
        fields = {"index": int(match["index"]), "boot_id": match["boot_id"]}
        if match["last"]:
            fields["last_entry"] = match["last"]
        self._add(first, "boots", "system.boot_journal", fields, None, text)

    _UTMP_EVENTS = {
        "user_process": "login.session",
        "dead_process": "login.ended",
        "boot_time": "system.boot",
        "login_process": "login.prompt",
    }

    def _login_record(self, data: dict[str, Any]) -> None:
        path = data.get("path") or ""
        failed = path.rsplit("/", 1)[-1].startswith("btmp")
        kind = "login.failed" if failed else self._UTMP_EVENTS.get(data.get("type"))
        if data.get("type") == "run_level" and data.get("user") == "shutdown":
            kind = "system.shutdown_record"
        if kind is None:
            return
        try:
            moment = datetime.fromisoformat(data["time"]) if data.get("time") else None
        except ValueError:
            moment = None
        fields = {
            k: data[k]
            for k in ("user", "line", "host", "address", "pid")
            if data.get(k) not in (None, "")
        }
        self._add(moment, f"login_records:{path}", kind, fields)


def _log_kind(start: SourceStart) -> str | None:
    """Which kind of log file a source is: "syslog" (the authentication
    logs, and syslog's or Postfix's mail logs), "exim" (Exim's main log),
    or None (not a log file read for events)."""
    if start.module == "auth_log":
        return "syslog"
    if start.module == "mail" and start.kind == "file" and start.name.startswith("/var/log/"):
        return "exim" if start.name.startswith("/var/log/exim") else "syslog"
    return None


def _log_source(start: SourceStart):
    """An event's source name for a log file, and the rules for its lines."""
    if start.module == "mail":
        return f"mail_log:{start.name}", classify_mail
    return f"auth_log:{start.name}", classify


# --- One record logged to several places -------------------------------------------------

# Fields only one kind of source carries, or that describe how an event was
# read rather than what was logged: left out when comparing.
_SOURCE_ONLY = {
    "audit_session",
    "boot_id",
    "systemd_unit",
    "journal_comm",
    "journal_uid",
    "year_inferred",
    "time_uncertain",
    "source_cut",
}


def merge_duplicates(events: list[Event]) -> list[Event]:
    """The same record often reaches a bundle twice or three times: sshd and
    sudo lines in both /var/log/secure (or auth.log) and the journal, logind
    lines in both journal reads. Events alike to the second, in type,
    process and fields are one record: the source that has the most of them
    is kept (the journal, on a tie, for its trusted fields) and the others
    are named in `also_in`. Mail lines reach both syslog's mail log and the
    journal the same way. Counting per source keeps real repeats."""
    groups: dict[tuple, dict[str, list[Event]]] = {}
    alone: list[Event] = []
    for event in events:
        if event.time is None:
            alone.append(event)
            continue
        fields = {k: v for k, v in event.fields.items() if k not in _SOURCE_ONLY}
        key = (event.time[:19], event.type, json.dumps(fields, sort_keys=True, default=str))
        groups.setdefault(key, {}).setdefault(event.source, []).append(event)
    kept = alone
    for by_source in groups.values():
        best = max(
            by_source,
            key=lambda src: (
                len(by_source[src]),
                not src.startswith(("auth_log:", "mail_log:")),
                src,
            ),
        )
        others = sorted(src for src in by_source if src != best)
        for event in by_source[best]:
            event.also_in = others
            kept.append(event)
    return kept


# --- The tool's own session ---------------------------------------------------------------

SELF_WINDOW = timedelta(minutes=5)
# How soon after its own SSH login a systemd user manager it started logs.
_USER_MANAGER_DELAY = timedelta(seconds=30)


def _collector_command(session: dict[str, Any]) -> tuple[str, str] | None:
    """(python's file name, the arguments after it) of the collector's
    command, as sudo logs it: the command resolved to a full path, then the
    arguments joined by spaces."""
    command = session.get("command")
    if not command:
        return None
    argv = shlex.split(command)
    if "--" in argv:
        argv = argv[argv.index("--") + 1 :]
    if len(argv) < 2:
        return None
    return argv[0].rsplit("/", 1)[-1], " ".join(argv[1:])


def _is_collector(logged: str, expected: tuple[str, str] | None) -> bool:
    if expected is None:  # a session stored before commands were recorded
        program, _, args = logged.partition(" ")
        return program.rsplit("/", 1)[-1].startswith("python") and (
            args == "-I -B -" or args.startswith('-I -B -c import sys;sys.stderr.write("[checker-')
        )
    name, args = expected
    head, sep, tail = logged.partition(" ")
    return bool(sep) and tail == args and head.rsplit("/", 1)[-1] == name


def _public(address: str | None) -> bool:
    try:
        return address is not None and ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def mark_own_session(events: list[Event], session: dict[str, Any] | None) -> int:
    """Mark the events the tool's own connection caused, each tied to that
    connection rather than to its account or time alone:

    - its SSH login: the session's user, from its source port (and address,
      when the controller's own is public, so no NAT can change it), with
      the key that logged in;
    - the PAM session (and any login record) of that sshd process;
    - the logind session whose number is the audit session the journal
      itself gave that PAM session — never a number read from a message —
      and its session scope's start and stop;
    - its sudo of exactly the collector's command (in that audit session,
      when the journal says), and that sudo process's PAM session; and the
      collector's own listing of the account's sudo rules;
    - a systemd user manager for the user starting within seconds of it.

    Returns how many were marked."""
    if not session:
        return 0
    user = session.get("user")
    try:
        started = datetime.fromisoformat(str(session.get("started_at")))
        ended = datetime.fromisoformat(str(session.get("ended_at") or session.get("started_at")))
    except ValueError:
        return 0
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    if ended.tzinfo is None:
        ended = ended.replace(tzinfo=UTC)
    low, high = started - SELF_WINDOW, ended + SELF_WINDOW
    port = session.get("local_port")
    address = session.get("local_address") if _public(session.get("local_address")) else None
    used_key = session.get("client_key_fingerprint")
    offered = set(session.get("offered_key_fingerprints") or []) | {used_key}
    offered.discard(None)
    expected = _collector_command(session)

    def moment(event: Event) -> datetime | None:
        if event.corrected is None:
            return None
        found = datetime.fromisoformat(event.corrected)
        return found if low <= found <= high else None

    candidates = [e for e in events if moment(e) is not None]
    marked = 0

    def mark(event: Event) -> None:
        nonlocal marked
        if not event.own_session:
            event.own_session = True
            marked += 1

    # 1. The SSH login itself, and the sshd process that logged it.
    sshd_pids: set[int] = set()
    logins: list[datetime] = []
    for event in candidates:
        f = event.fields
        if event.type not in ("ssh.login.accepted", "ssh.login.failed") or f.get("user") != user:
            continue
        if port is None or f.get("port") != port:
            continue
        if address is not None and f.get("address") != address:
            continue
        keys = {used_key} if event.type == "ssh.login.accepted" else offered
        if f.get("fingerprint") is not None and f["fingerprint"] not in keys:
            continue
        mark(event)
        if isinstance(f.get("pid"), int):
            sshd_pids.add(f["pid"])
        if event.type == "ssh.login.accepted":
            logins.append(moment(event))

    # 2. That process's PAM session and login records; the audit session the
    # journal gave them.
    audit_sessions: set[str] = set()
    for event in candidates:
        f = event.fields
        if f.get("pid") not in sshd_pids:
            continue
        if (event.type in ("session.opened", "session.closed") and f.get("service") == "sshd") or (
            event.type in ("login.session", "login.ended") and f.get("user") == user
        ):
            mark(event)
            if f.get("audit_session") not in (None, "4294967295"):
                audit_sessions.add(f["audit_session"])

    # 3. logind's session of that number (from logind itself, when the
    # journal says who logged it), and its scope.
    scopes = {f"session-{n}.scope" for n in audit_sessions} | {
        f"Session {n} of User {user}" for n in audit_sessions
    }
    for event in candidates:
        f = event.fields
        if event.type in ("logind.session_new", "logind.session_end"):
            if str(f.get("session")) not in audit_sessions:
                continue
            if event.type == "logind.session_new" and f.get("user") != user:
                continue
            trusted = f.get("journal_comm"), f.get("journal_uid")
            if "journal_comm" in f and trusted != ("systemd-logind", "0"):
                continue
            mark(event)
        elif event.type in ("unit.started", "unit.stopped") and f.get("what") in scopes:
            mark(event)

    # 4. Its sudo of the collector, and that sudo process's PAM session.
    sudo_pids: set[int] = set()
    for event in candidates:
        f = event.fields
        if event.type != "sudo.command" or f.get("user") != user:
            continue
        if f.get("runas", "root") != "root" or f.get("tty", "unknown") != "unknown":
            continue
        if not _is_collector(f.get("command") or "", expected):
            continue
        if "audit_session" in f and f["audit_session"] not in audit_sessions:
            continue
        mark(event)
        if isinstance(f.get("pid"), int):
            sudo_pids.add(f["pid"])
    for event in candidates:
        f = event.fields
        if (
            event.type in ("session.opened", "session.closed")
            and f.get("service") == "sudo"
            and f.get("pid") in sudo_pids
        ):
            mark(event)

    # 4b. The collector's own `sudo -ll -U <account>` (plan 2.7b): root
    # listing the session's account's rules, from that audit session when
    # the journal says, once the collector itself is known to have run.
    if sudo_pids:
        for event in candidates:
            f = event.fields
            if event.type != "sudo.command" or f.get("user") != "root":
                continue
            if (f.get("command") or "").split() not in (["list"], ["list", user]):
                continue
            if f.get("runas", "root") not in ("root", user) or f.get("tty", "unknown") != "unknown":
                continue
            if "audit_session" in f and f["audit_session"] not in audit_sessions:
                continue
            mark(event)

    # 5. The user manager systemd starts for a first login.
    for event in candidates:
        f = event.fields
        if (
            event.type == "session.opened"
            and f.get("service") == "systemd-user"
            and f.get("user") == user
            and any(timedelta(0) <= moment(event) - at <= _USER_MANAGER_DELAY for at in logins)
        ):
            mark(event)
    return marked
