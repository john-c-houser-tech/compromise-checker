"""What the web page says about the machine the tool runs on (installation plan, I.4): whether its
SSH still accepts passwords, and whether an update is waiting for a restart. The web interface
can't find either out itself, since SSH's settings are root's to read, so a small service the
installer sets up writes them down as root every hour:

    python -I -m checker.machine_status /var/lib/compromise-checker-status/machine.json

It uses only the standard library and reads nothing but SSH's settings and the system's own note
of a restart. The page reads what it wrote, and shows nothing it can't make sense of."""

import json
import os
import shutil
import subprocess  # noqa: S404
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

STATUS = Path("/var/lib/compromise-checker-status/machine.json")
REBOOT_REQUIRED = Path("/run/reboot-required")  # Ubuntu's note that an update needs a restart
FACTS = ("ssh_passwords", "restart_needed")
_SSH_UNITS = ("ssh.service", "sshd.service", "ssh.socket")
_SECONDS = 120


def _run(*command: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_SECONDS,
            cwd="/",
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def passwords_from(sshd_t: str) -> bool:
    """From `sshd -T`. Its first value for a setting is the one in force, and OpenSSH 10 writes
    the names with capitals where older ones don't."""
    found: dict[str, str] = {}
    for line in sshd_t.splitlines():
        key, _, value = line.strip().partition(" ")
        found.setdefault(key.lower(), value.strip().lower())
    return (
        found.get("passwordauthentication", "yes") != "no"
        or found.get("kbdinteractiveauthentication", "yes") != "no"
    )


def ssh_passwords() -> bool | None:
    """None when SSH isn't running here, or its settings can't be read."""
    running = False
    for unit in _SSH_UNITS:
        done = _run("systemctl", "is-active", unit)
        running = running or (done is not None and done.stdout.strip() == "active")
    sshd = shutil.which("sshd", path="/usr/sbin:/usr/bin") or "/usr/sbin/sshd"
    if not running or not Path(sshd).exists():
        return None
    shown = _run(sshd, "-T")
    if shown is None or shown.returncode != 0:
        return None
    return passwords_from(shown.stdout)


def restart_needed() -> bool | None:
    if REBOOT_REQUIRED.exists():
        return True
    dnf = shutil.which("dnf", path="/usr/bin:/bin")
    if dnf is None:
        return False  # Ubuntu, with no note of one
    done = _run(dnf, "-C", "-q", "needs-restarting", "-r")  # from what's installed, not the network
    if done is None:
        return None
    return {0: False, 1: True}.get(done.returncode)


def collect() -> dict:
    return {
        "checked": datetime.now(UTC).isoformat(timespec="seconds"),
        "ssh_passwords": ssh_passwords(),
        "restart_needed": restart_needed(),
    }


def write(path: Path, status: dict) -> None:
    """Whole or not at all, readable by the web interface's account."""
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".machine-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as out:
            json.dump(status, out, sort_keys=True)
            out.write("\n")
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def read(path: Path | None = None) -> dict:
    """Only the facts, and only as true or false: anything else is as good as not known."""
    try:
        found = json.loads((path or STATUS).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(found, dict):
        return {}
    return {fact: found[fact] for fact in FACTS if isinstance(found.get(fact), bool)}


def notices(path: Path | None = None) -> list[str]:
    """The facts that call for a notice on the page."""
    status = read(path)
    return [fact for fact in FACTS if status.get(fact) is True]


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    path = Path(arguments[0]) if arguments else STATUS
    write(path, collect())
    return 0


if __name__ == "__main__":
    sys.exit(main())
