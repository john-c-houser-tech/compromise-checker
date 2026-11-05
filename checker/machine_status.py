"""What the web page says about the machine the tool runs on (installation plan, I.4): whether its
SSH still accepts passwords, and whether an update is waiting for a restart. The web interface
can't find either out itself, since SSH's settings are root's to read, so a small service the
installer sets up writes them down as root every hour:

    python -I -S .../checker/machine_status.py /var/lib/compromise-checker-status/machine.json

Run as a file, without -m and with -S, so nothing but the standard library is loaded as root.

It uses only the standard library and reads nothing but SSH's settings, the system's own note
of a restart and, to know whether the first account exists, the count of accounts in the web
interface's own file. The page reads what it wrote, and shows nothing it can't make sense of. On a
machine set up from Linode's form, it also takes the installer's note with the first-setup link off
the console once that account exists."""

import contextlib
import json
import os
import shutil
import subprocess  # noqa: S404
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

STATUS = Path("/var/lib/compromise-checker-status/machine.json")
# What the installer leaves behind (release/install.py): that it finished, and whether it set up a
# web address. Without the second, the tool is on a machine people use from itself, often a PC.
INSTALLED = Path("/opt/compromise-checker/installed")
WEB_ADDRESS = Path("/opt/compromise-checker/web-address.json")
REBOOT_REQUIRED = Path("/run/reboot-required")  # Ubuntu's note that an update needs a restart
FACTS = ("ssh_passwords", "restart_needed")
STALE = timedelta(hours=3)  # the service runs hourly: older than this, it has stopped
_SSH_UNITS = ("ssh.service", "sshd.service", "ssh.socket", "sshd.socket")
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
    # Ubuntu starts SSH on demand, and until it has, sshd won't show its settings without this.
    with contextlib.suppress(OSError):
        Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
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
    return restart_from(done.returncode, done.stdout)


def restart_from(code: int, said: str) -> bool | None:
    """dnf also ends with 1 when it fails, so its words have to agree."""
    if code == 1 and "Reboot is required" in said:
        return True
    if code == 0 and "Reboot should not be necessary" in said:
        return False
    return None


ISSUE = Path("/etc/issue")  # what the console shows above the login prompt
WEB_DB = Path("/var/lib/compromise-checker/data/web.db")
NOTICE_START = "# --- Compromise Checker ---"
NOTICE_END = "# --- end of the Compromise Checker note ---"


def has_an_account(web_db: Path = WEB_DB) -> bool | None:
    """Whether the web interface has its first account, read from its own file as root; None if
    that can't be told (no file yet, or the accounts live in PostgreSQL)."""
    import sqlite3

    if not web_db.is_file():
        return None
    try:
        connection = sqlite3.connect(f"file:{web_db}?mode=ro", uri=True, timeout=5)
        try:
            # The file is the account's: a query made to spin would hold root here, so it's cut
            # short.
            connection.set_progress_handler(lambda: 1, 100_000)
            (count,) = connection.execute("SELECT count(*) FROM auth_user").fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return None
    return count > 0


def without_notice(text: str) -> str:
    """The console text with the installer's note taken out, if it's there."""
    start = text.find(NOTICE_START)
    end = text.find(NOTICE_END)
    if start < 0 or end < start:
        return text
    end += len(NOTICE_END)
    if end < len(text) and text[end] == "\n":
        end += 1
    return text[:start] + text[end:]


def clear_console_notice(issue: Path = ISSUE, web_db: Path = WEB_DB) -> bool:
    """The installer's note, with the first-setup link, comes off the console once the first account
    exists (installation plan I6: "removed once used"). Whether it was removed now."""
    try:
        text = issue.read_text(encoding="utf-8")
    except OSError:
        return False
    if NOTICE_START not in text or not has_an_account(web_db):
        return False
    with contextlib.suppress(OSError):
        write_text(issue, without_notice(text))
        refresh_console_prompts()
        return True
    return False


CONSOLE_GETTYS = ("serial-getty@ttyS0.service", "getty@tty1.service")  # Lish, and the screen


def idle_getty(unit: str) -> bool:
    """A login prompt waiting, not someone's session: the prompt shows the old text until it's
    drawn again, but a session mustn't be cut."""
    shown = _run("systemctl", "show", "-p", "MainPID", "--value", unit)
    pid = shown.stdout.strip() if shown is not None else ""
    if not pid.isdigit() or pid == "0":
        return False
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip() == "agetty"
    except OSError:
        return False


def refresh_console_prompts() -> list[str]:
    """Draw the console's login prompt again where it's only a prompt, so the change shows now."""
    refreshed = []
    for unit in CONSOLE_GETTYS:
        if idle_getty(unit):
            _run("systemctl", "restart", unit)
            refreshed.append(unit)
    return refreshed


def write_text(path: Path, text: str) -> None:
    """In place: the service's unit opens /etc/issue alone to writing, not /etc, so a new file
    couldn't be moved over it. It's a few lines read at the next login prompt."""
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "w", encoding="utf-8") as out:
        out.write(text)


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


def read(path: Path | None = None, now: datetime | None = None) -> dict:
    """Only the facts, and only as true or false: anything else is as good as not known. "stale"
    is true when the service hasn't written for a while, so they may be out of date."""
    try:
        found = json.loads((path or STATUS).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(found, dict):
        return {}
    facts = {fact: found[fact] for fact in FACTS if isinstance(found.get(fact), bool)}
    try:
        checked = datetime.fromisoformat(found["checked"])
    except (KeyError, TypeError, ValueError):
        checked = None
    if checked is None or checked.tzinfo is None or (now or datetime.now(UTC)) - checked > STALE:
        facts["stale"] = True
    return facts


def install_route(installed: Path | None = None, web_address: Path | None = None) -> str | None:
    """How the installer set this machine up: "web" with a web address, "local" for use from this
    machine only, or None when the installer didn't set it up (or hasn't finished)."""
    try:
        if not (installed or INSTALLED).is_file():
            return None
        marker = json.loads((web_address or WEB_ADDRESS).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return "local"
    except (OSError, ValueError):
        return None
    # The installer leaves the marker behind, without a name, when a web address was taken down
    # and something couldn't be undone: that machine has no web address.
    named = isinstance(marker, dict) and isinstance(marker.get("name"), str) and marker["name"]
    return "web" if named else "local"


def notices(path: Path | None = None) -> list[str]:
    """What calls for a notice on the page: each fact that's true, then "stale" if they may be out
    of date."""
    status = read(path)
    found = [fact for fact in FACTS if status.get(fact) is True]
    return found + (["stale"] if status.get("stale") else [])


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    path = Path(arguments[0]) if arguments else STATUS
    write(path, collect())
    if path == STATUS:  # the real machine's file, which the unit names; a test's path isn't
        clear_console_notice()
    return 0


if __name__ == "__main__":
    sys.exit(main())
