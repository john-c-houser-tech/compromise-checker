"""Bundles into events (PR 1.6a): message rules, syslog years, the walk
of a real (synthetic) bundle, and the tool's own session."""

import base64
import gzip
import json
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pyrage
import pytest
from pyrage import x25519

from checker import cli
from checker.analysis import load_events, parse_bundle, store_events
from checker.events import (
    Event,
    EventBuilder,
    classify,
    host_zone,
    mark_own_session,
    resolve_syslog_years,
)
from checker.evidence import Store, database_file, initialise, load_identity, seal_text

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
        ("sudo", "  amy : user NOT in sudoers ; TTY=pts/1", "sudo.denied", {"user": "amy"}),
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
    ):
        assert classify(program, message) is None, message


# --- Times ------------------------------------------------------------------------------


def test_syslog_years_across_new_year():
    newest = datetime(2027, 1, 2, 12, 0, tzinfo=UTC)
    parsed = [(12, 31, "23:59:00"), (1, 1, "00:00:30"), (1, 2, "11:00:00")]
    years = [d.year for d in resolve_syslog_years(parsed, newest, UTC)]
    assert years == [2026, 2027, 2027]


def test_syslog_line_after_the_file_time_is_last_year():
    newest = datetime(2026, 3, 1, tzinfo=UTC)
    [moment] = resolve_syslog_years([(12, 15, "10:00:00")], newest, UTC)
    assert moment.year == 2025


def test_impossible_dates_are_none():
    newest = datetime(2027, 3, 1, tzinfo=UTC)  # 2027 has no 29 February
    assert resolve_syslog_years([(2, 29, "10:00:00")], newest, UTC) == [None]


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


def source(source_id, module, name, text, meta=None, kind="file"):
    data = text.encode()
    return [
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
        {
            "type": "source_end",
            "source_id": source_id,
            "chunks": 1,
            "bytes": len(data),
            "truncated": False,
        },
    ]


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
    journal = "\n".join(
        json.dumps(entry)
        for entry in (
            {
                "MESSAGE": "New session 77 of user scanner.",
                "SYSLOG_IDENTIFIER": "systemd-logind",
                "_PID": "500",
                "__REALTIME_TIMESTAMP": str(
                    int((HOST_START + timedelta(seconds=5)).timestamp() * 1e6)
                ),
            },
            {
                "MESSAGE": "pam_unix(sudo:session): session opened for user root(uid=0)"
                " by scanner(uid=1001)",
                "SYSLOG_IDENTIFIER": "sudo",
                "_AUDIT_SESSION": "77",
                "__REALTIME_TIMESTAMP": str(
                    int((HOST_START + timedelta(seconds=6)).timestamp() * 1e6)
                ),
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
            "counts": {"records": 2, "sources": 2, "chunks": 2, "errors": 0},
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
    "local_port": 41000,
}


@pytest.fixture
def stored_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    config, identity_path = initialise(tmp_path)
    identity = load_identity(identity_path)
    keys = [x25519.Recipient.from_str(r) for r in config.recipients]
    plain = stream(synthetic_records())
    bundle = tmp_path / "evidence/web01/b1.age"
    bundle.parent.mkdir(parents=True)
    bundle.write_bytes(pyrage.encrypt(plain, keys))
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
            "plaintext_sha256": "x",
            "plaintext_bytes": len(plain),
            "ciphertext_sha256": "x",
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
    # The tool's own session: its login (by key and port), its sudo, its
    # logind session and the journal entries of that audit session.
    own = {e.type for e in parsed.events if e.own_session}
    assert own == {"ssh.login.accepted", "sudo.command", "logind.session_new", "session.opened"}
    assert parsed.summary["own_session"] == 4
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
    assert "scanner" not in out.split("Clock", 1)[1]  # own session hidden
    assert cli.main(["events", "b1", "--own", "--type", "sudo."]) == 0
    out = capsys.readouterr().out
    assert "[own session]" in out and "ssh.login" not in out.split("Clock", 1)[1]


# --- The own-session filter on its edges ----------------------------------------------------


def make(kind, minute, **fields):
    moment = (CONTROLLER_START + timedelta(minutes=minute)).isoformat()
    return Event(time=moment, corrected=moment, source="t", type=kind, fields=fields)


def test_own_session_needs_its_key_or_port_and_its_time():
    events = [
        make("ssh.login.accepted", 0, user="scanner", port=41000),  # its port
        make("ssh.login.accepted", 0, user="scanner", port=1, fingerprint="SHA256:scannerkey"),
        make("ssh.login.accepted", 0, user="scanner", port=2, fingerprint="SHA256:other"),
        make("ssh.login.accepted", 0, user="jch", port=41000),  # someone else
        make("ssh.login.accepted", 60, user="scanner", port=41000),  # an hour later
        make("sudo.command", 0, user="scanner", command="/bin/bash"),  # not the collector
    ]
    assert mark_own_session(events, SESSION) == 2
    assert [e.own_session for e in events] == [True, True, False, False, False, False]


def test_no_session_marks_nothing():
    events = [make("ssh.login.accepted", 0, user="scanner", port=41000)]
    assert mark_own_session(events, None) == 0


def test_builder_without_controller_time_keeps_host_time():
    builder = EventBuilder()
    assert builder.offset_known is False
