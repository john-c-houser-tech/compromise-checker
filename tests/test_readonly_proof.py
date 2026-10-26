"""The read-only proof's audit parsing (the proof itself runs by hand).

The samples are shaped like the `ausearch -i` output from the first real run
on Ubuntu 24.04 and Rocky 9 (2026-10-26).
"""

import importlib.util
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "readonly_proof", Path(__file__).parent / "integration" / "readonly_proof.py"
)
proof = importlib.util.module_from_spec(_spec)
sys.modules["readonly_proof"] = proof  # dataclasses look their module up while loading
_spec.loader.exec_module(proof)


def event(comm, exe, syscall, *paths):
    lines = [
        f"type=PATH msg=audit(10/26/2026 00:40:01.000:9) : item={n} name={name} nametype={kind}"
        for n, (name, kind) in enumerate(paths)
    ]
    lines.append(
        f"type=SYSCALL msg=audit(10/26/2026 00:40:01.000:9) : arch=x86_64 syscall={syscall}"
        f" success=yes exit=0 comm={comm} exe={exe} key=cc-write"
    )
    return "----\n" + "\n".join(lines) + "\n"


SESSION = (
    event(
        "sudo",
        "/usr/bin/sudo",
        "openat",
        ("/run/sudo/ts/", "PARENT"),
        ("/run/sudo/ts/scanner", "CREATE"),
    )
    + event("sshd", "/usr/sbin/sshd", "openat", ("/var/log/wtmp", "NORMAL"))
    + event("systemd", "/usr/lib/systemd/systemd", "mkdirat", ("/run/user/1000/systemd", "CREATE"))
    + event("systemd", "/usr/lib/systemd/systemd", "symlinkat", ("5e45d22cda4d", "UNKNOWN"))
    + event(
        "sshd", "/usr/sbin/sshd", "rename", ("/run/", "PARENT"), ("/run/motd.dynamic", "CREATE")
    )
    + event(
        "sshd",
        "/usr/sbin/sshd",
        "openat",
        ("/home/scanner/.cache/", "PARENT"),
        ("/home/scanner/.cache/motd.legal-displayed", "CREATE"),
    )
    + event("sudo", "/usr/bin/sudo", "bind")
    + event("systemd", "/usr/lib/systemd/systemd", "fchmod")
)


def test_ordinary_login_and_session_setup_is_disclosed():
    verdict = proof.classify(proof.parse_audit(SESSION))
    assert verdict.collector == []
    assert verdict.unexpected == []
    assert len(verdict.disclosed) == 6  # PARENT entries and the link's content don't count
    assert verdict.sockets == ["sudo (/usr/bin/sudo) bind"]


def test_any_write_by_the_collector_fails():
    text = SESSION + event("python3", "/usr/bin/python3.12", "openat", ("/dev/null", "NORMAL"))
    verdict = proof.classify(proof.parse_audit(text))
    assert verdict.collector == ["python3 (/usr/bin/python3.12) openat /dev/null"]


def test_an_undisclosed_write_by_login_machinery_fails():
    text = SESSION + event("sshd", "/usr/sbin/sshd", "openat", ("/etc/passwd", "NORMAL"))
    verdict = proof.classify(proof.parse_audit(text))
    assert verdict.unexpected == ["sshd (/usr/sbin/sshd) openat /etc/passwd"]


def test_pathless_permission_changes_count_only_from_the_session_manager():
    text = SESSION + event("sshd", "/usr/sbin/sshd", "fchmod")
    verdict = proof.classify(proof.parse_audit(text))
    assert verdict.unexpected == ["sshd (/usr/sbin/sshd) fchmod (no path)"]


def test_no_events_means_no_writes():
    verdict = proof.classify(proof.parse_audit("<no matches>\n"))
    assert (verdict.collector, verdict.unexpected, verdict.disclosed) == ([], [], [])
