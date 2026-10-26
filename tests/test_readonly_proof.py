"""The read-only proof's audit parsing and safety (the proof itself runs by hand).

Records are in `ausearch --raw` form, shaped like the real runs on Ubuntu
24.04 and Rocky 9 (2026-10-26).
"""

import asyncio
import importlib.util
import os
import signal
import sys
import time
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "readonly_proof", Path(__file__).parent / "integration" / "readonly_proof.py"
)
proof = importlib.util.module_from_spec(_spec)
sys.modules["readonly_proof"] = proof  # dataclasses look their module up while loading
_spec.loader.exec_module(proof)

X86 = "c000003e"
SYSCALLS = {
    (X86, "2"): "open",
    (X86, "49"): "bind",
    (X86, "82"): "rename",
    (X86, "83"): "mkdir",
    (X86, "91"): "fchmod",
    (X86, "257"): "openat",
    (X86, "258"): "mkdirat",
    (X86, "266"): "symlinkat",
}
NUMBERS = {name: number for (_, number), name in SYSCALLS.items()}
_serial = 0


def quoted_or_hex(value: str) -> str:
    """How audit writes a value: quoted, or hex if it has spaces or oddities."""
    if all(c.isalnum() or c in "/._-:@" for c in value):
        return f'"{value}"'
    return value.encode().hex().upper()


def event(comm, exe, syscall, *paths, cwd=None):
    global _serial
    _serial += 1
    stamp = f"msg=audit(1792968000.{_serial:03d}:{_serial})"
    lines = [
        f"type=SYSCALL {stamp}: arch={X86} syscall={NUMBERS[syscall]} success=yes exit=0"
        f" auid=1000 uid=0 comm={quoted_or_hex(comm)} exe={quoted_or_hex(exe)}"
        ' key="cc-write"'
    ]
    if cwd:
        lines.append(f"type=CWD {stamp}: cwd={quoted_or_hex(cwd)}")
    for n, (name, kind) in enumerate(paths):
        lines.append(f"type=PATH {stamp}: item={n} name={quoted_or_hex(name)} nametype={kind}")
    return "\n".join(lines) + "\n"


def judge(text):
    return proof.classify(proof.parse_audit(text, SYSCALLS))


SUDO, SSHD, SYSTEMD = "/usr/bin/sudo", "/usr/sbin/sshd", "/usr/lib/systemd/systemd"
SESSION = "".join(
    [
        event("sudo", SUDO, "openat", ("/run/sudo/ts/", "PARENT"), ("/run/sudo/ts/u", "CREATE")),
        event("sshd", SSHD, "openat", ("/var/log/wtmp", "NORMAL")),
        event("systemd", SYSTEMD, "mkdirat", ("/run/user/1000/systemd", "CREATE")),
        event(
            "systemd",
            SYSTEMD,
            "symlinkat",
            ("5e45d22cda4d", "UNKNOWN"),
            ("/run/user/1000/systemd/units/x", "CREATE"),
        ),
        event("sshd", SSHD, "rename", ("/run/", "PARENT"), ("/run/motd.dynamic", "CREATE")),
        event(
            "sshd",
            SSHD,
            "openat",
            ("/home/scanner/.cache/", "PARENT"),
            ("/home/scanner/.cache/motd.legal-displayed", "CREATE"),
        ),
        event("sudo", SUDO, "bind"),
        event("systemd", SYSTEMD, "fchmod"),
    ]
)


def test_ordinary_login_and_session_setup_is_disclosed():
    verdict = judge(SESSION)
    assert verdict.collector == [] and verdict.unexpected == []
    assert len(verdict.disclosed) == 7  # PARENT entries and the link's content don't count
    assert verdict.sockets == ["sudo (/usr/bin/sudo) bind"]


def test_any_write_by_the_collector_fails():
    python = event("python3", "/usr/bin/python3.12", "openat", ("/dev/null", "NORMAL"))
    assert judge(SESSION + python).collector == ["python3 (/usr/bin/python3.12) openat /dev/null"]


def test_an_undisclosed_write_by_login_machinery_fails():
    verdict = judge(SESSION + event("sshd", SSHD, "openat", ("/etc/passwd", "NORMAL")))
    assert verdict.unexpected == ["sshd (/usr/sbin/sshd) openat /etc/passwd"]


def test_a_filename_with_spaces_is_read_whole():
    # Hex-encoded by audit; must not be mistaken for the disclosed /var/log/wtmp.
    verdict = judge(event("sshd", SSHD, "openat", ("/var/log/wtmp backup", "CREATE")))
    assert verdict.unexpected == ["sshd (/usr/sbin/sshd) openat /var/log/wtmp backup"]


def test_a_process_name_with_spaces_is_not_lost():
    worker = event("python worker", "/usr/bin/python3.12", "openat", ("/srv/x", "CREATE"))
    assert judge(worker).collector == ["python worker (/usr/bin/python3.12) openat /srv/x"]


def test_relative_symlink_destinations_are_resolved_and_judged():
    link = event(
        "sshd", SSHD, "symlinkat", ("target", "UNKNOWN"), ("evil", "CREATE"), cwd="/etc/cron.d"
    )
    assert judge(link).unexpected == ["sshd (/usr/sbin/sshd) symlinkat /etc/cron.d/evil"]


def test_pathless_permission_changes_count_only_from_the_session_manager():
    verdict = judge(SESSION + event("sshd", SSHD, "fchmod"))
    assert verdict.unexpected == ["sshd (/usr/sbin/sshd) fchmod (no path)"]


def test_dot_dot_cannot_climb_out_of_a_disclosed_prefix():
    escape = event("sshd", SSHD, "openat", ("../../../etc/passwd", "CREATE"), cwd="/run/user/1000")
    assert judge(escape).unexpected == [
        "sshd (/usr/sbin/sshd) openat /run/user/1000/../../../etc/passwd"
    ]


def test_audit_rule_changes_are_not_events():
    rule_added = (
        "type=CONFIG_CHANGE msg=audit(1792968000.500:500): auid=0 ses=1 op=add_rule"
        ' key="cc-write" list=4 res=1\n'
    )
    assert judge(rule_added + SESSION).unexpected == []


def test_sigterm_cancels_the_task_so_cleanup_runs():
    cleaned = []

    async def job():
        proof._cancel_on_sigterm()
        try:
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            cleaned.append(True)
            raise
        finally:
            asyncio.get_running_loop().remove_signal_handler(signal.SIGTERM)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(job())
    assert cleaned == [True]


def test_an_event_without_its_syscall_record_is_an_error():
    orphan = 'type=PATH msg=audit(1792968000.999:999): item=0 name="/etc/x" nametype=CREATE\n'
    with pytest.raises(ValueError, match="no SYSCALL record"):
        proof.parse_audit(orphan, SYSCALLS)


def test_no_events_parse_to_nothing():
    assert proof.parse_audit("<no matches>\n", SYSCALLS) == []


async def test_cancelling_during_creation_still_deletes_the_server():
    deleted = []

    class SlowApi:
        def create(self, *args):
            time.sleep(0.3)  # the request is already on its way
            return {"id": 42, "label": "cc-test-x"}

        def delete(self, linode_id):
            deleted.append(linode_id)

    task = asyncio.ensure_future(proof._create_server(SlowApi(), "a", "b", "c", "d"))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert deleted == [42]
