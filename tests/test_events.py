"""Bundles into events (PR 1.6a): message rules, syslog years, the walk
of a real (synthetic) bundle, and the tool's own session."""

import base64
import gzip
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pyrage
import pytest
from pyrage import x25519

from checker import cli
from checker.analysis import load_events, parse_bundle, store_events
from checker.bundle import walk_bundle
from checker.events import (
    Event,
    EventBuilder,
    classify,
    host_zone,
    mark_own_session,
    merge_duplicates,
    resolve_syslog_years,
)
from checker.evidence import (
    EvidenceError,
    Store,
    database_file,
    initialise,
    load_identity,
    seal_text,
)

# --- Message rules ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("program", "message", "kind", "fields"),
    [
        (
            "sshd",
            "Accepted publickey for jch from 203.0.113.5 port 52114 ssh2: ED25519 SHA256:abc",
            "ssh.login.accepted",
            {
                "method": "publickey",
                "user": "jch",
                "address": "203.0.113.5",
                "port": 52114,
                "key_type": "ED25519",
                "fingerprint": "SHA256:abc",
            },
        ),
        (
            "sshd",
            "Failed password for invalid user [MASKED:unknown_user] from 198.51.100.7"
            " port 4711 ssh2",
            "ssh.login.failed",
            {
                "method": "password",
                "user": "[MASKED:unknown_user]",
                "address": "198.51.100.7",
                "port": 4711,
                "invalid_user": True,
            },
        ),
        (
            "sshd",
            "Invalid user [MASKED:unknown_user] from 198.51.100.7 port 4711",
            "ssh.invalid_user",
            {"user": "[MASKED:unknown_user]", "address": "198.51.100.7", "port": 4711},
        ),
        (
            "sshd",
            "pam_unix(sshd:session): session opened for user jch(uid=1000) by (uid=0)",
            "session.opened",
            {"service": "sshd", "user": "jch"},
        ),
        (
            "sudo",
            "     jch : TTY=pts/0 ; PWD=/home/jch ; USER=root ;"
            " COMMAND=/usr/bin/systemctl restart x",
            "sudo.command",
            {
                "user": "jch",
                "tty": "pts/0",
                "pwd": "/home/jch",
                "runas": "root",
                "command": "/usr/bin/systemctl restart x",
            },
        ),
        (
            "sudo",
            "  amy : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
            "sudo.denied",
            {"user": "amy", "reason": "user NOT in sudoers", "command": "/bin/sh"},
        ),
        ("sudo", "  amy : user NOT in sudoers ; TTY=pts/1", "sudo.denied", {"user": "amy"}),
        (
            "sudo",
            "jch : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
            "sudo.failed",
            {"user": "jch", "reason": "3 incorrect password attempts", "runas": "root"},
        ),
        (
            "sudo",
            "jch : a password is required ; TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/bin/id",
            "sudo.failed",
            {"user": "jch", "command": "/bin/id"},
        ),
        (
            "sudo",
            "jch : command not allowed ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
            "sudo.denied",
            {"user": "jch", "reason": "command not allowed"},
        ),
        (
            "sshd",
            "error: maximum authentication attempts exceeded for root from 198.51.100.7"
            " port 4711 ssh2 [preauth]",
            "ssh.login.too_many_failures",
            {"user": "root", "address": "198.51.100.7", "port": 4711, "invalid_user": False},
        ),
        (
            "sshd",
            "Connection closed by authenticating user root 198.51.100.7 port 4711 [preauth]",
            "ssh.login.abandoned",
            {"user": "root", "address": "198.51.100.7", "port": 4711},
        ),
        (
            "sshd",
            "Disconnected from invalid user [MASKED:unknown_user] 198.51.100.7 port 4711",
            "ssh.login.abandoned",
            {"invalid_user": True},
        ),
        (
            "sshd",
            "pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh"
            " ruser= rhost=198.51.100.7 user=jch",
            "auth.failure",
            {"module": "pam_sss", "service": "sshd"},
        ),
        (
            "sudo",
            "pam_unix(sudo:session): session opened for user root(uid=0) by scanner(uid=1001)",
            "session.opened",
            {"service": "sudo", "user": "root", "by": "scanner"},
        ),
        (
            "gpasswd",
            "user bob added by root to group wheel",
            "group.member_added",
            {"user": "bob", "by": "root", "group": "wheel"},
        ),
        (
            "gpasswd",
            "user bob removed by root from group wheel",
            "group.member_removed",
            {"user": "bob", "group": "wheel"},
        ),
        (
            "usermod",
            "change user name 'a' to 'b'",
            "account.renamed",
            {"old_user": "a", "user": "b"},
        ),
        ("usermod", "lock user 'bob' password", "account.locked", {"user": "bob"}),
        ("usermod", "unlock user 'bob' password", "account.unlocked", {"user": "bob"}),
        (
            "usermod",
            "delete 'bob' from group 'wheel'",
            "group.member_removed",
            {"user": "bob", "group": "wheel"},
        ),
        (
            "su",
            "(to root) jch on pts/0",
            "su.switch",
            {"target": "root", "user": "jch", "tty": "pts/0"},
        ),
        (
            "useradd",
            "new user: name=backdoor, UID=0, GID=0",
            "account.created",
            {"user": "backdoor", "uid": "0"},
        ),
        (
            "usermod",
            "add 'eve' to group 'sudo'",
            "group.member_added",
            {"user": "eve", "group": "sudo"},
        ),
        (
            "passwd",
            "pam_unix(passwd:chauthtok): password changed for root",
            "account.password_changed",
            {"user": "root"},
        ),
        (
            "systemd-logind",
            "New session 42 of user scanner.",
            "logind.session_new",
            {"session": "42", "user": "scanner"},
        ),
        (
            "systemd-logind",
            "New session 42 of user john.doe.",
            "logind.session_new",
            {"session": "42", "user": "john.doe"},
        ),
        (
            "systemd-logind",  # systemd 256 and later
            "New session '5' of user 'john.doe' with class 'user' and type 'tty'.",
            "logind.session_new",
            {"session": "5", "user": "john.doe"},
        ),
        ("systemd-logind", "Removed session '5'.", "logind.session_end", {"session": "5"}),
        (
            "systemd-logind",  # systemd 256 and later
            "The system will reboot now!",
            "system.shutdown_requested",
            {"what": "reboot"},
        ),
        ("systemd-logind", "Removed session c12.", "logind.session_end", {"session": "c12"}),
        (
            "systemd-logind",
            "Session 5 logged out. Waiting for processes to exit.",
            "logind.session_end",
            {"session": "5"},
        ),
        (
            "kernel",
            "Out of memory: Killed process 812 (php-fpm) total-vm:1kB",
            "kernel.oom_kill",
            {"pid": "812", "comm": "php-fpm"},
        ),
        (
            "kernel",
            "php-fpm[4242]: segfault at 0 ip 00 sp 00 error 4",
            "kernel.segfault",
            {"comm": "php-fpm", "pid": "4242"},
        ),
        (
            "kernel",
            "rootkit: loading out-of-tree module taints kernel.",
            "kernel.module_taint",
            {"module": "rootkit"},
        ),
        (
            "systemd",
            "nginx.service: Failed with result 'exit-code'.",
            "unit.failed",
            {"unit": "nginx.service"},
        ),
        (
            "systemd",
            "Reached target System Reboot.",
            "system.shutdown",
            {"target": "System Reboot."},
        ),
    ],
)
def test_message_rules(program, message, kind, fields):
    found = classify(program, message)
    assert found is not None, message
    assert found[0] == kind
    for key, value in fields.items():
        if value is None:
            continue
        assert found[1][key] == value, (key, found[1])
    if kind == "sudo.command":
        assert found[1]["user"] == "jch"


def test_unrelated_messages_are_not_events():
    for program, message in (
        ("sshd", "Received disconnect from 1.2.3.4 port 5: 11: Bye Bye"),
        ("sshd", "Accepted publickey for jch"),  # no source: not this line's format
        ("cron", "pam_unix(cron:session): session opened"),  # no user
        ("nginx", "Accepted connection"),
        ("kernel", "eth0: link up"),
        ("systemd-logind", "Session closing is not a session event"),
    ):
        assert classify(program, message) is None, message


# --- Times ------------------------------------------------------------------------------


def test_syslog_years_across_new_year():
    newest = datetime(2027, 1, 2, 12, 0, tzinfo=UTC)
    parsed = [(12, 31, "23:59:00"), (1, 1, "00:00:30"), (1, 2, "11:00:00")]
    resolved = resolve_syslog_years(parsed, newest, UTC)
    assert [d.year for d, _ in resolved] == [2026, 2027, 2027]
    assert not any(uncertain for _, uncertain in resolved)  # December before January


def test_syslog_years_that_may_be_wrong_say_so():
    newest = datetime(2026, 10, 25, tzinfo=UTC)
    # A VM that booted dated 1 January, then NTP corrected it: the October
    # lines before it are put a year back, and said to be uncertain.
    resolved = resolve_syslog_years(
        [(10, 20, "10:00:00"), (1, 1, "00:00:05"), (10, 24, "09:00:00")], newest, UTC
    )
    assert [u for _, u in resolved] == [True, False, False]
    # A clock that went back within a month.
    resolved = resolve_syslog_years([(10, 20, "10:00:00"), (10, 5, "00:00:05")], newest, UTC)
    assert [u for _, u in resolved] == [True, False]
    # A log whose last line is long before its file's time.
    [(_, uncertain)] = resolve_syslog_years([(3, 1, "10:00:00")], newest, UTC)
    assert uncertain


def test_syslog_line_after_the_file_time_is_last_year():
    newest = datetime(2026, 3, 1, tzinfo=UTC)
    [(moment, uncertain)] = resolve_syslog_years([(12, 15, "10:00:00")], newest, UTC)
    assert moment.year == 2025 and uncertain  # a quiet log: two and a half months


def test_impossible_dates_are_none():
    newest = datetime(2027, 3, 1, tzinfo=UTC)  # 2027 has no 29 February
    assert resolve_syslog_years([(2, 29, "10:00:00")], newest, UTC) == [(None, True)]


def test_host_zone():
    zone, assumed = host_zone("../usr/share/zoneinfo/Europe/Berlin")
    assert zone == ZoneInfo("Europe/Berlin") and not assumed
    assert host_zone(None) == (UTC, True)
    assert host_zone("/usr/share/zoneinfo/Nowhere/Atlantis") == (UTC, True)


# --- A synthetic bundle, end to end ------------------------------------------------------

HOST_START = datetime(2027, 1, 2, 12, 0, 30, tzinfo=UTC)  # the host's clock
CONTROLLER_START = HOST_START - timedelta(seconds=30)  # host 30 s fast


def stream(records):
    lines = []
    for record in records:
        lines.append(json.dumps(record, default=str).encode())
    return gzip.compress(b"\n".join(lines) + b"\n")


def source(source_id, module, name, text, meta=None, kind="file", cut=False):
    data = text.encode()
    records = [
        {
            "type": "source_start",
            "source_id": source_id,
            "module": module,
            "kind": kind,
            "name": name,
            "meta": meta or {},
        },
        {
            "type": "chunk",
            "source_id": source_id,
            "seq": 0,
            "encoding": "base64",
            "data": base64.b64encode(data).decode(),
        },
    ]
    if cut:  # the stream ends inside this source
        return records
    return records + [
        {
            "type": "source_end",
            "source_id": source_id,
            "chunks": 1,
            "bytes": len(data),
            "truncated": False,
        },
    ]


def at(seconds):
    """A journal timestamp, `seconds` after the host's start."""
    return str(int((HOST_START + timedelta(seconds=seconds)).timestamp() * 1e6))


def synthetic_records():
    manifest = {
        "type": "manifest",
        "protocol": 1,
        "collector_version": "t",
        "run_id": "r1",
        "started_at": HOST_START.isoformat(),
        "host": {
            "hostname": "web01",
            "os_id": "ubuntu",
            "os_version_id": "24.04",
            "os_pretty_name": "Ubuntu",
            "kernel": "6.8",
            "machine": "x86_64",
            "boot_id": None,
        },
        "python": {"version": "3.12", "executable": "/usr/bin/python3"},
        "effective_uid": 0,
        "settings": {},
        "modules_planned": [],
    }
    records = [
        manifest,
        {
            "type": "record",
            "module": "host_facts",
            "name": "clock",
            "data": {
                "utc": HOST_START.isoformat(),
                "tzname": ["UTC", "UTC"],
                "localtime_link": "/usr/share/zoneinfo/Etc/UTC",
            },
        },
    ]
    secure = (
        "Dec 31 23:59:00 web01 sshd[10]: Accepted password for jch from 203.0.113.5"
        " port 5000 ssh2\n"
        "Jan  2 12:00:05 web01 sshd[11]: Accepted publickey for scanner from 192.0.2.50 port 41000"
        " ssh2: ED25519 SHA256:scannerkey\n"
        "Jan  2 12:00:06 web01 sudo[12]:  scanner : PWD=/ ; USER=root ;"
        " COMMAND=/usr/bin/python3 -I -B -\n"
        "Jan  2 12:00:07 web01 sshd[13]: Failed password for root from 198.51.100.9"
        " port 6000 ssh2\n"
        "garbage that is not a log line\n"
    )
    records += source(
        1,
        "auth_log",
        "/var/log/secure",
        secure,
        {"mtime": (HOST_START + timedelta(seconds=10)).isoformat()},
    )
    # The same sshd and sudo lines again from the journal, with what the
    # journal itself knows: the audit session sshd's PAM session gave it.
    auth = "\n".join(
        json.dumps(entry)
        for entry in (
            {
                "MESSAGE": "Accepted publickey for scanner from 192.0.2.50 port 41000"
                " ssh2: ED25519 SHA256:scannerkey",
                "SYSLOG_IDENTIFIER": "sshd",
                "_PID": "11",
                "_COMM": "sshd",
                "__REALTIME_TIMESTAMP": at(-25),
            },
            {
                "MESSAGE": "pam_unix(sshd:session): session opened for user scanner(uid=1001)"
                " by (uid=0)",
                "SYSLOG_IDENTIFIER": "sshd",
                "_PID": "11",
                "_AUDIT_SESSION": "77",
                "__REALTIME_TIMESTAMP": at(-25),
            },
            {
                "MESSAGE": " scanner : PWD=/ ; USER=root ; COMMAND=/usr/bin/python3 -I -B -",
                "SYSLOG_IDENTIFIER": "sudo",
                "_PID": "12",
                "_AUDIT_SESSION": "77",
                "__REALTIME_TIMESTAMP": at(-24),
            },
            {
                "MESSAGE": "pam_unix(sudo:session): session opened for user root(uid=0)"
                " by scanner(uid=1001)",
                "SYSLOG_IDENTIFIER": "sudo",
                "_PID": "12",
                "_AUDIT_SESSION": "77",
                "__REALTIME_TIMESTAMP": at(-24),
            },
            # Another local user, eve (audit session 78), forging logind's
            # message for her own session, then using sudo.
            {
                "MESSAGE": "New session 78 of user scanner.",
                "SYSLOG_IDENTIFIER": "systemd-logind",
                "_COMM": "logger",
                "_UID": "1002",
                "_PID": "900",
                "_AUDIT_SESSION": "78",
                "__REALTIME_TIMESTAMP": at(-23),
            },
            {
                "MESSAGE": " eve : TTY=pts/3 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/useradd -o"
                " -u 0 backdoor",
                "SYSLOG_IDENTIFIER": "sudo",
                "_PID": "901",
                "_AUDIT_SESSION": "78",
                "__REALTIME_TIMESTAMP": at(-22),
            },
        )
    )
    records += source(3, "auth_journal", "journalctl", auth, kind="command")
    journal = "\n".join(
        json.dumps(entry)
        for entry in (
            {
                "MESSAGE": "New session 77 of user scanner.",
                "SYSLOG_IDENTIFIER": "systemd-logind",
                "_COMM": "systemd-logind",
                "_UID": "0",
                "_PID": "500",
                "__REALTIME_TIMESTAMP": at(-25),
            },
            {
                "MESSAGE": "Out of memory: Killed process 812 (php-fpm)",
                "_TRANSPORT": "kernel",
                "__REALTIME_TIMESTAMP": str(
                    int((HOST_START - timedelta(days=1)).timestamp() * 1e6)
                ),
            },
        )
    )
    records += source(2, "system_journal", "journalctl", journal, kind="command")
    records.append(
        {
            "type": "record",
            "module": "login_records",
            "name": "login_record",
            "data": {
                "path": "/var/log/btmp",
                "type": "login_process",
                "user": "[MASKED:unknown_user]",
                "host": "198.51.100.9",
                "time": (HOST_START - timedelta(hours=1)).isoformat(),
            },
        }
    )
    records.append(
        {
            "type": "trailer",
            "finished_at": HOST_START.isoformat(),
            "duration_seconds": 1,
            "status": "complete",
            "counts": {"records": 2, "sources": 3, "chunks": 3, "errors": 0},
            "modules": {},
        }
    )
    return records


SESSION = {
    "host": "web01",
    "address": "192.0.2.10",
    "port": 22,
    "user": "scanner",
    "sudo": "nopasswd",
    "started_at": CONTROLLER_START.isoformat(),
    "ended_at": (CONTROLLER_START + timedelta(seconds=20)).isoformat(),
    "client_key_fingerprint": "SHA256:scannerkey",
    "local_address": "10.0.0.5",  # private: NAT may change it, so not compared
    "local_port": 41000,
    "command": "sudo -n -- python3 -I -B -",
}


@pytest.fixture
def stored_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    config, identity_path = initialise(tmp_path)
    identity = load_identity(identity_path)
    keys = [x25519.Recipient.from_str(r) for r in config.recipients]
    plain = stream(synthetic_records())
    cipher = pyrage.encrypt(plain, keys)
    bundle = tmp_path / "evidence/web01/b1.age"
    bundle.parent.mkdir(parents=True)
    bundle.write_bytes(cipher)
    store = Store(database_file(tmp_path))
    store.record_bundle(
        {
            "id": "b1",
            "host": "web01",
            "run_id": "r1",
            "path": str(bundle),
            "started_at": CONTROLLER_START.isoformat(),
            "ended_at": CONTROLLER_START.isoformat(),
            "status": "complete",
            "collector_version": "t",
            "collector_sha256": "x",
            "plaintext_sha256": hashlib.sha256(plain).hexdigest(),
            "plaintext_bytes": len(plain),
            "ciphertext_sha256": hashlib.sha256(cipher).hexdigest(),
            "ciphertext_bytes": 1,
            "recipients": json.dumps(config.recipients),
            "session": seal_text(json.dumps(SESSION), config.recipients),
            "summary": None,
            "problem": None,
        }
    )
    yield store, store.bundle("b1"), identity, config
    store.close()


def test_events_from_a_bundle(stored_bundle):
    store, row, identity, _ = stored_bundle
    parsed = parse_bundle(row, identity)
    by_type = {}
    for event in parsed.events:
        by_type.setdefault(event.type, []).append(event)
    # The December line belongs to last year; corrected times take the
    # host's 30 seconds off.
    jch = by_type["ssh.login.accepted"][0]
    assert jch.fields["user"] == "jch" and jch.time.startswith("2026-12-31T23:59:00")
    assert jch.corrected.startswith("2026-12-31T23:58:30")
    assert parsed.summary["clock_offset_seconds"] == 30
    assert not parsed.summary["time_zone_assumed"]
    # The tool's own session: its login (port and key), that sshd's PAM
    # session, the logind session of its audit session, its sudo of the
    # collector and that sudo's PAM session.
    own = sorted((e.type, e.fields.get("service")) for e in parsed.events if e.own_session)
    assert own == [
        ("logind.session_new", None),
        ("session.opened", "sshd"),
        ("session.opened", "sudo"),
        ("ssh.login.accepted", None),
        ("sudo.command", None),
    ]
    assert parsed.summary["own_session"] == 5
    # eve's forged logind message and her sudo stay findings.
    eve = [e for e in parsed.events if e.fields.get("audit_session") == "78"]
    assert len(eve) == 2 and not any(e.own_session for e in eve)
    # Lines in both /var/log/secure and the journal are one event each, the
    # journal's (with its audit session), the file named in also_in.
    [accepted] = [
        e
        for e in parsed.events
        if e.fields.get("user") == "scanner" and e.type == "ssh.login.accepted"
    ]
    assert accepted.source == "auth_journal" and accepted.also_in == ["auth_log:/var/log/secure"]
    assert len(by_type["sudo.command"]) == 2  # scanner's, once; eve's
    assert parsed.summary["clock_offset_basis"] == "run start"
    assert parsed.summary["own_login_found"] is None  # this session has no auth_method
    assert [e.fields["user"] for e in by_type["ssh.login.failed"]] == ["root"]
    assert by_type["kernel.oom_kill"][0].fields["comm"] == "php-fpm"
    assert by_type["login.failed"][0].fields["user"] == "[MASKED:unknown_user]"
    assert not parsed.summary["problem"]


def test_events_are_stored_encrypted_and_reloaded(stored_bundle, tmp_path):
    store, row, identity, config = stored_bundle
    parsed = parse_bundle(row, identity)
    target = store_events(store, row, config.recipients, parsed)
    assert b"scanner" not in target.read_bytes()  # encrypted
    again = load_events(store, row, identity)
    assert [e.as_dict() for e in again.events] == [e.as_dict() for e in parsed.events]
    actions = [r["action"] for r in store.custody_of("b1")]
    assert actions == ["collected", "parsed"]
    target.write_bytes(target.read_bytes()[:-1] + b"x")
    with pytest.raises(Exception, match="recorded hash"):
        load_events(store, row, identity)


def test_cli_events(stored_bundle, capsys):
    assert cli.main(["events", "b1"]) == 0
    out = capsys.readouterr().out
    assert "Events     " in out
    assert "ssh.login.failed" in out and "198.51.100.9" in out
    listed = out.split("Clock", 1)[1]
    assert "SHA256:scannerkey" not in listed and "python3" not in listed  # own session hidden
    assert "comm=logger" in listed  # the forged logind line is not
    assert cli.main(["events", "b1", "--own", "--type", "sudo."]) == 0
    out = capsys.readouterr().out
    assert "[own session]" in out and "ssh.login" not in out.split("Clock", 1)[1]


# --- The own-session filter on its edges ----------------------------------------------------


def make(kind, minute, **fields):
    moment = (CONTROLLER_START + timedelta(minutes=minute, seconds=5)).isoformat()
    return Event(time=moment, corrected=moment, source="t", type=kind, fields=fields)


def test_own_login_needs_its_port_and_key_and_time():
    events = [
        make("ssh.login.accepted", 0, user="scanner", port=41000, fingerprint="SHA256:scannerkey"),
        make("ssh.login.accepted", 0, user="scanner", port=41000),  # password: no key logged
        # The scanner's key, stolen, used from elsewhere during the scan.
        make("ssh.login.accepted", 0, user="scanner", port=1, fingerprint="SHA256:scannerkey"),
        # Its port, but another key.
        make("ssh.login.accepted", 0, user="scanner", port=41000, fingerprint="SHA256:other"),
        make("ssh.login.accepted", 0, user="jch", port=41000),  # someone else
        make("ssh.login.accepted", 60, user="scanner", port=41000),  # an hour later
    ]
    assert mark_own_session(events, SESSION) == 2
    assert [e.own_session for e in events] == [True, True, False, False, False, False]


def test_own_login_address_is_compared_when_it_is_public():
    session = dict(SESSION, local_address="100.25.0.77")
    events = [
        make("ssh.login.accepted", 0, user="scanner", port=41000, address="100.25.0.77"),
        make("ssh.login.accepted", 0, user="scanner", port=41000, address="198.51.100.1"),
    ]
    mark_own_session(events, session)
    assert [e.own_session for e in events] == [True, False]


def test_another_login_to_the_scanner_account_stays_a_finding():
    """Someone with the scanner's credentials during the scan: their PAM,
    logind and wtmp sessions and their sudo are tied to their connection,
    not ours, so none is marked."""
    events = [
        make("ssh.login.accepted", 0, user="scanner", port=41000, pid=11),
        make("session.opened", 0, service="sshd", user="scanner", pid=11, audit_session="77"),
        make("logind.session_new", 0, session="77", user="scanner", comm="systemd-logind", uid="0"),
        make(
            "sudo.command",
            0,
            user="scanner",
            runas="root",
            command="/usr/bin/python3 -I -B -",
            pid=12,
            audit_session="77",
        ),
        make("session.opened", 0, service="sudo", user="root", by="scanner", pid=12),
        # Theirs, by password from another port.
        make("ssh.login.accepted", 1, user="scanner", port=50000, pid=21),
        make("session.opened", 1, service="sshd", user="scanner", pid=21, audit_session="80"),
        make("logind.session_new", 1, session="80", user="scanner", comm="systemd-logind", uid="0"),
        make("login.session", 1, user="scanner", pid=21),
        make(
            "sudo.command",
            1,
            user="scanner",
            runas="root",
            command="/usr/bin/python3 -I -B -",
            pid=22,
            audit_session="80",
        ),
        make(
            "sudo.command",
            1,
            user="scanner",
            runas="root",
            tty="unknown",
            command="/usr/bin/python3 -I -B -c import os; os.system('id')",
            pid=23,
        ),
        make("session.opened", 1, service="sudo", user="root", by="scanner", pid=22),
    ]
    assert mark_own_session(events, SESSION) == 5
    assert [e.own_session for e in events] == [True] * 5 + [False] * 7


def test_the_collector_command_is_matched_exactly():
    password_mode = dict(
        SESSION,
        sudo="password",
        command="sudo -k -S -p '[checker-sudo-ab]' -- /usr/libexec/platform-python -I -B -c"
        ' \'import sys;sys.stderr.write("[checker-ready-ab]"+"\\n")\'',
    )
    ours = 'import sys;sys.stderr.write("[checker-ready-ab]"+"\\n")'
    events = [
        make(
            "sudo.command",
            0,
            user="scanner",
            command=f"/usr/libexec/platform-python -I -B -c {ours}",
        ),
        make("sudo.command", 0, user="scanner", command=f"/usr/bin/python3 -I -B -c {ours}"),
        make(
            "sudo.command",
            0,
            user="scanner",
            command="/usr/libexec/platform-python -I -B -c " + ours.replace("-ab", "-zz"),
        ),
        make("sudo.command", 0, user="scanner", command="/usr/libexec/platform-python -I -B -"),
        make(
            "sudo.command",
            0,
            user="scanner",
            runas="jch",
            command=f"/usr/libexec/platform-python -I -B -c {ours}",
        ),
    ]
    mark_own_session(events, password_mode)
    assert [e.own_session for e in events] == [True, False, False, False, False]


def test_a_logind_session_number_from_a_message_is_not_trusted():
    """Only the audit session the journal gave our sshd's PAM session
    counts, and logind's line must come from logind itself."""
    events = [
        make("ssh.login.accepted", 0, user="scanner", port=41000, pid=11),
        make("session.opened", 0, service="sshd", user="scanner", pid=11, audit_session="77"),
        make("logind.session_new", 0, session="78", user="scanner", comm="systemd-logind", uid="0"),
        make("logind.session_new", 0, session="77", user="scanner", comm="logger", uid="1002"),
        make("logind.session_new", 0, session="77", user="scanner", comm="systemd-logind", uid="0"),
        make("unit.started", 0, what="Session 77 of User scanner"),
        make("unit.started", 0, what="Session 78 of User scanner"),
        make("account.created", 0, user="backdoor", uid="0", audit_session="77"),
    ]
    mark_own_session(events, SESSION)
    assert [e.own_session for e in events] == [True, True, False, False, True, True, False, False]


def test_root_mode_marks_only_its_own_connection():
    session = dict(SESSION, user="root", sudo="root", command="python3 -I -B -")
    events = [
        make("ssh.login.accepted", 0, user="root", port=41000, pid=11),
        make("session.opened", 0, service="sshd", user="root", pid=11),
        make("ssh.login.accepted", 0, user="root", port=41001, pid=31),
        make("session.opened", 0, service="sshd", user="root", pid=31),
        make("session.opened", 0, service="sudo", user="root", pid=32),
    ]
    mark_own_session(events, session)
    assert [e.own_session for e in events] == [True, True, False, False, False]


def test_the_user_manager_is_marked_only_just_after_our_login():
    events = [
        make("ssh.login.accepted", 0, user="scanner", port=41000, pid=11),
        make("session.opened", 0, service="systemd-user", user="scanner", pid=40),
        make("session.opened", 2, service="systemd-user", user="scanner", pid=41),
    ]
    mark_own_session(events, SESSION)
    assert [e.own_session for e in events] == [True, True, False]


def test_no_session_marks_nothing():
    events = [make("ssh.login.accepted", 0, user="scanner", port=41000)]
    assert mark_own_session(events, None) == 0


def test_builder_without_controller_time_keeps_host_time():
    builder = EventBuilder()
    assert builder.offset_known is False


# --- Duplicates, cut-off sources, bundle hashes, storage ------------------------------------


def test_duplicates_merge_but_real_repeats_stay():
    def ev(source, second, **fields):
        moment = f"2027-01-02T12:00:{second:02d}+00:00"
        return Event(moment, moment, source, "ssh.login.failed", dict(fields))

    events = [
        # Two real failures in one second on one connection, logged to the
        # file and the journal.
        ev("auth_log:/var/log/secure", 1, user="root", port=6000, pid=13, year_inferred=True),
        ev("auth_log:/var/log/secure", 1, user="root", port=6000, pid=13, year_inferred=True),
        ev("auth_journal", 1, user="root", port=6000, pid=13, comm="sshd"),
        ev("auth_journal", 1, user="root", port=6000, pid=13, comm="sshd"),
        ev("auth_journal", 2, user="root", port=6000, pid=13, comm="sshd"),  # journal only
        ev("auth_log:/var/log/secure", 3, user="root", port=6001, pid=14),  # file only
    ]
    kept = merge_duplicates(events)
    assert len(kept) == 4
    assert [e.source for e in kept[:2]] == ["auth_journal"] * 2
    assert kept[0].also_in == ["auth_log:/var/log/secure"]
    assert kept[2].also_in == [] and kept[3].source.startswith("auth_log:")
    # The journal dropped one (rate limiting): the file's two are kept.
    events = [
        ev("auth_log:/var/log/secure", 4, user="root", port=7000, pid=15),
        ev("auth_log:/var/log/secure", 4, user="root", port=7000, pid=15),
        ev("auth_journal", 4, user="root", port=7000, pid=15),
    ]
    kept = merge_duplicates(events)
    assert [e.source for e in kept] == ["auth_log:/var/log/secure"] * 2
    assert kept[0].also_in == ["auth_journal"]


def test_a_bundle_cut_off_inside_a_log_still_gives_its_events(tmp_path):
    secure = (
        "Jan  2 12:00:05 web01 sshd[11]: Accepted password for root from 203.0.113.9 port 1 ssh2\n"
        "Jan  2 12:00:06 web01 useradd[14]: new user: name=backdoor, UID=0, GID=0\n"
        "Jan  2 12:00:07 web01 sshd[11]: Accepted password for r"  # cut mid-line
    )
    records = synthetic_records()[:2] + source(
        1, "auth_log", "/var/log/secure", secure, {"mtime": HOST_START.isoformat()}, cut=True
    )
    identity = x25519.Identity.generate()
    bundle = tmp_path / "cut.age"
    bundle.write_bytes(pyrage.encrypt(stream(records), [identity.to_public()]))
    builder = EventBuilder()
    walked = walk_bundle(bundle, identity, builder)
    kinds = [(e.type, e.fields.get("source_cut")) for e in builder.events]
    assert kinds == [("ssh.login.accepted", True), ("account.created", True)]
    assert walked.problem == "stream ended without a trailer"


def test_a_replaced_bundle_is_not_parsed(stored_bundle, tmp_path):
    store, row, identity, config = stored_bundle
    keys = [x25519.Recipient.from_str(r) for r in config.recipients]
    # Anyone with the public key can make a valid bundle: the hash says it
    # isn't the one on record.
    Path(row["path"]).write_bytes(pyrage.encrypt(stream(synthetic_records()[:2]), keys))
    with pytest.raises(EvidenceError, match="recorded hash"):
        parse_bundle(row, identity)
    # The same content encrypted again is still not the file on record.
    Path(row["path"]).write_bytes(pyrage.encrypt(stream(synthetic_records()), keys))
    with pytest.raises(EvidenceError, match="doesn't match its recorded hash: not parsed"):
        parse_bundle(row, identity)


def test_a_new_parse_is_written_before_it_is_recorded(stored_bundle):
    store, row, identity, config = stored_bundle
    first = store_events(store, row, config.recipients, parse_bundle(row, identity))
    assert oct(first.stat().st_mode & 0o777) == "0o600"
    parsed = parse_bundle(row, identity)
    parsed.events.pop()
    second = store_events(store, row, config.recipients, parsed)
    assert second != first and not first.exists()  # replaced only once recorded
    assert len(load_events(store, row, identity).events) == len(parsed.events)
    assert not list(Path(row["path"]).parent.glob("*.tmp"))


def test_clock_offset_is_measured_from_the_first_data(stored_bundle):
    store, row, identity, config = stored_bundle
    # The password prompt took two minutes: the run started then, but the
    # collector's first bytes came only after.
    session = dict(SESSION, first_data_at=(HOST_START - timedelta(seconds=1)).isoformat())
    row = dict(row, session=seal_text(json.dumps(session), config.recipients))
    parsed = parse_bundle(row, identity)
    assert parsed.summary["clock_offset_seconds"] == 1
    assert parsed.summary["clock_offset_basis"] == "first data"


def test_an_own_login_not_found_is_said(stored_bundle, capsys):
    store, row, identity, config = stored_bundle
    found = dict(SESSION, auth_method="publickey")
    row_found = dict(row, session=seal_text(json.dumps(found), config.recipients))
    assert parse_bundle(row_found, identity).summary["own_login_found"] is True
    # Behind NAT the host saw another source port.
    natted = dict(found, local_port=50001)
    row_natted = dict(row, session=seal_text(json.dumps(natted), config.recipients))
    parsed = parse_bundle(row_natted, identity)
    assert parsed.summary["own_login_found"] is False
    assert not any(e.own_session for e in parsed.events)
