"""Normalized events from a bundle (DESIGN.md §6): one per log record that
a check could use, with its time on the host's clock and corrected to the
controller's, typed fields, and the (already masked) line it came from.

Events can always be regenerated from the bundle; the tool's own session
on the host is recognised and marked (`own_session`) rather than dropped."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from checker.protocol import Error, Manifest, Record, SourceEnd, SourceStart, Trailer

PARSER_VERSION = 1
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
        None,
        re.compile(
            r"^pam_unix\((?P<service>[^:]+):session\): session (?P<action>opened|closed) "
            r"for user (?P<user>[^\s(]+)"
        ),
        "session",
    ),
    (
        None,
        re.compile(r"^pam_unix\((?P<service>[^:]+):auth\): authentication failure;(?P<rest>.*)$"),
        "auth.failure",
    ),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : user NOT in sudoers"), "sudo.denied"),
    (
        "sudo",
        re.compile(r"^\s*(?P<user>\S+) : (?P<details>(?:\S+=[^;]*; )*)COMMAND=(?P<command>.*)$"),
        "sudo.command",
    ),
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
    ("usermod", re.compile(r"^change user '(?P<user>[^']+)'"), "account.modified"),
    ("groupadd", re.compile(r"^new group: name=(?P<group>[^,]+)"), "group.created"),
    (None, re.compile(r"password changed for (?P<user>\S+)"), "account.password_changed"),
    (
        "systemd-logind",
        re.compile(r"^New session (?P<session>\S+) of user (?P<user>[^\s.]+)"),
        "logind.session_new",
    ),
    (
        "systemd-logind",
        re.compile(r"^(?:Removed session|Session) (?P<session>[^\s.]+)(?: logged out)?"),
        "logind.session_end",
    ),
    (
        "systemd-logind",
        re.compile(r"^(?:System is (?P<what>rebooting|powering down)|Power key pressed)"),
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
        if kind == "sudo.command":
            details = dict(_SUDO_DETAIL.findall(fields.pop("details", "") + " ;"))
            # sudo's USER= is who the command runs as, not who ran sudo.
            names = {"TTY": "tty", "PWD": "pwd", "USER": "runas"}
            fields.update({names[k]: v.strip() for k, v in details.items()})
        if kind == "ssh.login.failed":
            fields["invalid_user"] = bool(fields.pop("invalid", None))
        if kind == "session":
            kind = "session." + fields.pop("action")
        return kind, fields
    return None


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
) -> list[datetime | None]:
    """Years for traditional syslog dates (no year). Lines are in time order
    and the last is no later than the file's modification time (`newest`),
    so walking back from the end, the year steps back whenever the month
    goes up (December before January) — and a last line dated after the
    file's time belongs to the year before."""
    out: list[datetime | None] = [None] * len(parsed)
    local_newest = newest.astimezone(zone)
    year, later_month = local_newest.year, None
    for i in range(len(parsed) - 1, -1, -1):
        month, day, clock = parsed[i]
        if later_month is None:
            if month > local_newest.month:
                year -= 1
        elif month > later_month:
            year -= 1
        later_month = month
        try:
            hour, minute, second = (int(x) for x in clock.split(":"))
            out[i] = datetime(year, month, day, hour, minute, second, tzinfo=zone)
        except ValueError:  # 29 February in the wrong year, a damaged line
            out[i] = None
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
        self._syslog: dict[int, list[tuple[tuple[int, int, str], dict[str, Any]]]] = {}
        self._raw_lines: dict[int, int] = {}

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
        if start.module == "auth_log":
            self._syslog[start.source_id] = []

    def line(self, start: SourceStart, line: bytes) -> None:
        text = line.decode("utf-8", "replace")
        if start.module == "auth_log":
            self._log_line(start, text)
        elif start.module in ("auth_journal", "system_journal"):
            self._journal_line(start, text)
        elif start.module == "boots":
            self._boot_line(start, text)

    def source_end(self, start: SourceStart, end: SourceEnd) -> None:
        if start.module == "auth_log":
            self._flush_syslog(start)

    def error(self, error: Error) -> None:
        pass

    def trailer(self, trailer: Trailer) -> None:
        pass

    # Helpers
    def _add(self, moment, source, kind, fields, program=None, line=""):
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
        source = f"auth_log:{start.name}"
        match = _RFC3339.match(text)
        if match:
            try:
                moment = datetime.fromisoformat(match["ts"].replace("Z", "+00:00"))
            except ValueError:
                moment = None
            self._message(moment, source, match["prog"], match["msg"], match["pid"], text)
            return
        match = _SYSLOG.match(text)
        if match and match["mon"] in _MONTHS:
            key = (_MONTHS[match["mon"]], int(match["day"]), match["time"])
            self._syslog[start.source_id].append((key, {"match": match.groupdict(), "text": text}))

    def _flush_syslog(self, start: SourceStart) -> None:
        pending = self._syslog.pop(start.source_id, [])
        if not pending:
            return
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
        source = f"auth_log:{start.name}"
        for moment, (_, item) in zip(years, pending, strict=True):
            m = item["match"]
            self._message(moment, source, m["prog"], m["msg"], m["pid"], item["text"])

    def _message(self, moment, source, program, message, pid, text, extra=None):
        found = classify(program, message)
        if found is None:
            return
        kind, fields = found
        if pid:
            fields.setdefault("pid", int(pid))
        if extra:
            fields.update(extra)
        self._add(moment, source, kind, fields, program, text)

    def _journal_line(self, start: SourceStart, text: str) -> None:
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
        if isinstance(entry.get("_SYSTEMD_UNIT"), str):
            extra["systemd_unit"] = entry["_SYSTEMD_UNIT"]
        pid = entry.get("SYSLOG_PID") or entry.get("_PID")
        pid = pid if isinstance(pid, str) and pid.isdigit() else None
        self._message(moment, start.module, program, message, pid, message, extra)

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


# --- The tool's own session ---------------------------------------------------------------

SELF_WINDOW = timedelta(minutes=5)


def mark_own_session(events: list[Event], session: dict[str, Any] | None) -> int:
    """Mark the events the tool's own session caused: its SSH login (by key
    fingerprint or source port), its PAM and logind sessions, its sudo of
    the collector, its login records, and journal entries in its audit
    session. Returns how many were marked."""
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
    fingerprints = {session.get("client_key_fingerprint")} | set(
        session.get("offered_key_fingerprints") or []
    )
    fingerprints.discard(None)
    port = session.get("local_port")
    marked = 0
    audit_sessions: set[str] = set()

    def within(event: Event) -> bool:
        if event.corrected is None:
            return False
        moment = datetime.fromisoformat(event.corrected)
        return low <= moment <= high

    for event in events:
        if not within(event):
            continue
        f = event.fields
        own = False
        if event.type in ("ssh.login.accepted", "ssh.login.failed") and f.get("user") == user:
            own = (f.get("fingerprint") in fingerprints) or (
                port is not None and f.get("port") == port
            )
        elif event.type in ("session.opened", "session.closed") and f.get("user") == user:
            own = f.get("service") in ("sshd", "sudo", "systemd-user")
        elif event.type == "sudo.command" and f.get("user") == user:
            own = "python3 -I -B -" in (f.get("command") or "") or "python3 -I -B -c" in (
                f.get("command") or ""
            )
        elif event.type in ("logind.session_new",) and f.get("user") == user:
            own = True
            audit_sessions.add(str(f.get("session")))
        elif event.type in ("login.session", "login.ended") and f.get("user") == user:
            own = True
        if own:
            event.own_session = True
            marked += 1
    if audit_sessions:
        for event in events:
            if not event.own_session and event.fields.get("audit_session") in audit_sessions:
                if within(event):
                    event.own_session = True
                    marked += 1
    return marked
