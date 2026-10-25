"""The read-only proof's audit parsing (the proof itself runs by hand)."""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "readonly_proof", Path(__file__).parent / "integration" / "readonly_proof.py"
)
proof = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(proof)

AUDIT = """----
type=PATH msg=audit(10/25/2026 23:04:05.123:456) : item=0 name=/run/sudo/ts/scanner nametype=CREATE
type=SYSCALL msg=audit(10/25/2026 23:04:05.123:456) : arch=x86_64 syscall=openat success=yes \
comm=sudo exe=/usr/bin/sudo key=cc-write
----
type=PATH msg=audit(10/25/2026 23:04:05.200:457) : item=0 name=/var/log/wtmp nametype=NORMAL
type=SYSCALL msg=audit(10/25/2026 23:04:05.200:457) : arch=x86_64 syscall=openat success=yes \
comm=sshd exe=/usr/sbin/sshd key=cc-write
----
type=PATH msg=audit(10/25/2026 23:04:06.000:458) : item=0 name=/tmp/x nametype=CREATE
type=SYSCALL msg=audit(10/25/2026 23:04:06.000:458) : arch=x86_64 syscall=openat success=yes \
comm=python3 exe=/usr/bin/python3.12 key=cc-write
----
type=PATH msg=audit(10/25/2026 23:04:07.000:459) : item=0 name=/dev/null nametype=NORMAL
type=SYSCALL msg=audit(10/25/2026 23:04:07.000:459) : arch=x86_64 syscall=openat success=yes \
comm=python3 exe=/usr/bin/python3.12 key=cc-write
"""


def test_login_traces_are_disclosed_and_any_collector_write_is_not():
    disclosed, unexpected = proof.classify(proof.parse_audit(AUDIT))
    assert [line.split()[0] for line in disclosed] == ["sshd", "sudo"]
    # The collector must write nothing at all, not even somewhere harmless.
    assert unexpected == [
        "python3 (/usr/bin/python3.12) openat /dev/null",
        "python3 (/usr/bin/python3.12) openat /tmp/x",
    ]


def test_no_events_means_no_writes():
    assert proof.classify(proof.parse_audit("<no matches>\n")) == ([], [])
