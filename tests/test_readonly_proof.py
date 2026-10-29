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
    (X86, "259"): "mknodat",
    (X86, "265"): "linkat",
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
    for n, (name, kind, *dev) in enumerate(paths):
        device = f" dev={dev[0]}" if dev else ""
        lines.append(
            f"type=PATH {stamp}: item={n} name={quoted_or_hex(name)}{device} nametype={kind}"
        )
    return "\n".join(lines) + "\n"


MEMORY, DISK = "00:2a", "fd:01"  # tmpfs (/run/user/…), and a disk


def judge(text, memory=frozenset({MEMORY})):
    return proof.classify(proof.parse_audit(text, SYSCALLS), set(memory))


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


def test_landscape_s_login_summary_is_login_machinery_but_only_in_its_own_folders():
    py = "/usr/bin/python3.14"
    writes = event(
        "landscape-sysin", py, "openat", ("/var/log/landscape/sysinfo.log", "NORMAL")
    ) + event("landscape-sysin", py, "bind")
    verdict = judge(SESSION + writes)
    assert verdict.collector == [] and verdict.unexpected == []
    elsewhere = event("landscape-sysin", py, "openat", ("/etc/passwd", "NORMAL"))
    assert judge(elsewhere).unexpected == [f"landscape-sysin ({py}) openat /etc/passwd"]
    # The collector can't pass for it by name alone: python3 is still the collector.
    assert judge(event("python3", py, "bind")).collector


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


def test_the_user_managers_placeholders_and_generators_are_disclosed():
    """systemd 256+: at login the user manager makes its placeholder nodes
    through a directory handle (bare names, on the runtime area's tmpfs),
    and the user-unit generators link units into their output directory."""
    generator = "/usr/lib/systemd/user-generators/systemd-xdg-autostart-generator"
    text = "".join(
        [
            event("systemd", SYSTEMD, "mkdirat", ("inaccessible", "CREATE", MEMORY), cwd="/"),
            event("systemd", SYSTEMD, "mknodat", ("chr", "CREATE", MEMORY), cwd="/"),
            event("systemd", SYSTEMD, "linkat", ("", "CREATE", MEMORY), cwd="/"),
            # Ubuntu 26.04: an unnamed file linked into the runtime area.
            event(
                "systemd",
                SYSTEMD,
                "linkat",
                ("", "NORMAL", MEMORY),
                ("/run/user/1000/systemd/inaccessible/reg", "CREATE", MEMORY),
                cwd="/",
            ),
            event(
                "systemd-xdg-aut",
                generator,
                "symlinkat",
                ("/x.desktop", "UNKNOWN"),
                ("../app-x@autostart.service", "CREATE", MEMORY),
                cwd="/",
            ),
        ]
    )
    verdict = judge(text)
    assert verdict.unexpected == [] and len(verdict.disclosed) == 5  # one linkat / twice


def test_placeholders_and_generators_excuse_nothing_on_a_disk():
    generator = "/usr/lib/systemd/user-generators/x"
    verdict = judge(
        # The names, but absolute (a real /sock in /), or on a disk.
        event("systemd", SYSTEMD, "mknodat", ("/sock", "CREATE", MEMORY), cwd="/")
        + event("systemd", SYSTEMD, "mkdirat", ("dir", "CREATE", DISK), cwd="/")
        # A generator's link anywhere but its in-memory output.
        + event("x", generator, "symlinkat", ("t", "UNKNOWN"), ("/etc/cron.d/evil", "CREATE", DISK))
        + event("x", generator, "symlinkat", ("t", "UNKNOWN"), ("evil", "CREATE", DISK), cwd="/")
        # A relative name joined to a runtime-area cwd but written on a disk
        # (through an /etc directory handle).
        + event("sshd", SSHD, "openat", ("passwd", "CREATE", DISK), cwd="/run/user/1000")
    )
    assert sorted(verdict.unexpected) == [
        "sshd (/usr/sbin/sshd) openat /run/user/1000/passwd",
        "systemd (/usr/lib/systemd/systemd) mkdirat /dir",
        "systemd (/usr/lib/systemd/systemd) mknodat /sock",
        "x (/usr/lib/systemd/user-generators/x) symlinkat /etc/cron.d/evil",
        "x (/usr/lib/systemd/user-generators/x) symlinkat /evil",
    ]


def test_the_end_of_run_sweep_deletes_only_this_runs_servers():
    class Fake:
        deleted = []

        def tagged(self):
            mine = proof.run_label("rocky9")
            return [
                {"id": 1, "label": mine},
                {"id": 2, "label": mine + "x"},  # also this run's (same prefix)
                {"id": 3, "label": "cc-test-zzzzzz-rocky9-ab12"},  # another run's
            ]

        def delete(self, linode_id):
            if linode_id == 1:
                raise RuntimeError("404: already gone")
            self.deleted.append(linode_id)

    api = Fake()
    proof.sweep_run(api)
    assert api.deleted == [2]  # the failed delete didn't stop it; run 3 untouched


def test_placeholder_names_are_accepted_from_the_session_manager_only():
    verdict = judge(
        event("sshd", SSHD, "mknodat", ("chr", "CREATE", MEMORY), cwd="/")
        + event("systemd", SYSTEMD, "mknodat", ("evil", "CREATE", MEMORY), cwd="/")
        + event("systemd", SYSTEMD, "openat", ("dir", "CREATE", DISK), cwd="/")
    )
    assert verdict.unexpected == [
        "sshd (/usr/sbin/sshd) mknodat /chr",
        "systemd (/usr/lib/systemd/systemd) mknodat /evil",
        "systemd (/usr/lib/systemd/systemd) openat /dir",
    ]
    collector = event("python3", "/usr/bin/python3", "mknodat", ("chr", "CREATE"), cwd="/")
    assert judge(collector).collector == ["python3 (/usr/bin/python3) mknodat /chr"]


def test_in_memory_comes_from_the_mount_table_not_the_device_number():
    mountinfo = "\n".join(
        [
            "25 1 0:22 / /run rw - tmpfs tmpfs rw",
            "26 25 0:42 / /run/user/1000 rw - tmpfs tmpfs rw",
            "27 1 0:31 / / rw - btrfs /dev/vda2 rw",  # anonymous device, on disk
            "28 1 253:1 / /boot rw - xfs /dev/vda1 rw",
        ]
    )
    memory = proof.memory_devices(mountinfo)
    assert memory == {"00:16", "00:2a"}
    btrfs = event("systemd", SYSTEMD, "mknodat", ("chr", "CREATE", "00:1f"), cwd="/")
    assert judge(btrfs, memory).unexpected == ["systemd (/usr/lib/systemd/systemd) mknodat /chr"]
    # Without a mount table nothing is in memory: relative names aren't excused.
    tmpfs = event("systemd", SYSTEMD, "mknodat", ("chr", "CREATE", MEMORY), cwd="/")
    assert judge(tmpfs, set()).unexpected == ["systemd (/usr/lib/systemd/systemd) mknodat /chr"]
