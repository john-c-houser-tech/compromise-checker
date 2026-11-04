"""The root service that installs a newer release (installation plan I.6, decision I3). It's the
one way anything that starts at a web page reaches root, so it takes no instructions from there.

The web interface, or `checker update`, leaves a release and its dependencies' wheels in the tool's
own folder and writes a request file. A systemd path unit starts this when that file exists. This
service removes the file without reading it, and then works from scratch: it copies the release
into a folder only root can write, checking every file against the signed manifest as it's copied
(checker.releases.stage_release), refuses anything not newer than the running version, installs the
new version beside the old one with exactly the dependencies the signed list names, and only then
moves the `current` link. The web interface is restarted and given a minute to answer. If it
doesn't, the link goes back, the old version is restarted, and the new one is removed. The outcome
goes in a file the page reads, and the previous version is kept so that a bad one can be undone by
hand as well. Nothing here contacts the network: the health check talks to this machine only.

Run as `.../current/bin/python -I -P -m checker.update_service`, so it's the installed version's
own code, with nothing from the folder it's started in."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess  # noqa: S404 - systemctl, venv and pip, with fixed arguments
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from checker import releases

PROGRAM = Path("/opt/compromise-checker")
ACCOUNT_HOME = Path("/var/lib/compromise-checker")
UPDATES = ACCOUNT_HOME / "data" / "updates"  # the tool's account writes here; root only reads
UNIT = "compromise-checker-web.service"
PORT = 8088
ANSWER_SECONDS = 60
STATUS_SCRIPT = PROGRAM / "machine_status.py"  # the hourly root service's script, kept current
WHEELS = "wheels"
REQUEST = "request"
OUTCOME = "outcome.json"


class Failed(Exception):
    """Why the update stopped, in words for the page and the journal."""


def say(text: str) -> None:
    print(text, flush=True)


def _run(*command: str, timeout: int = 1200) -> subprocess.CompletedProcess:
    done = subprocess.run(  # noqa: S603
        command,
        check=False,
        text=True,
        errors="replace",
        capture_output=True,
        cwd="/",
        timeout=timeout,
    )
    if done.returncode:
        said = (done.stderr or done.stdout).strip()[-600:]
        raise Failed(f"{command[0]} {command[1]} failed: {said}")
    return done


def write_outcome(folder: Path, data: dict) -> None:
    """Readable by the tool's account, whole or not at all."""
    data = {**data, "at": datetime.now(UTC).isoformat(timespec="seconds")}
    fresh = folder / f".{OUTCOME}.new"
    descriptor = os.open(fresh, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8") as out:
        json.dump(data, out, sort_keys=True)
        out.write("\n")
    os.chmod(fresh, 0o644)
    os.replace(fresh, folder / OUTCOME)


def running_version(program: Path = PROGRAM) -> str:
    """From the manifest kept beside the running version, or failing that the folder's name."""
    current = program / "current"
    try:
        manifest = releases.read_manifest(
            (current / releases.MANIFEST).read_bytes(), (current / releases.SIGNATURE).read_bytes()
        )
        return manifest.version
    except (OSError, releases.ReleaseError):
        pass
    try:
        name = Path(os.readlink(current)).name
        releases.version_key(name)
        return name
    except (OSError, releases.ReleaseError):
        raise Failed("the running version can't be told: nothing is installed") from None


def offered(incoming: Path) -> Path:
    """The one release folder the tool's account left to be installed."""
    try:
        found = [
            entry
            for entry in incoming.iterdir()
            if entry.is_dir() and not entry.is_symlink() and releases._VERSION.fullmatch(entry.name)
        ]
    except OSError:
        found = []
    if len(found) != 1:
        words = (
            "nothing is waiting to be installed"
            if not found
            else "more than one release is waiting"
        )
        raise Failed(words)
    return found[0]


def copy_wheels(source: Path, target: Path) -> None:
    """Plain files only, by name, into root's own folder, where pip then checks each against the
    hash the signed list gives. A link or anything else planted there is left behind."""
    target.mkdir(mode=0o700)
    for entry in source.iterdir():
        if not (entry.is_file() and not entry.is_symlink() and entry.name.endswith(".whl")):
            continue
        if not releases._FILE_NAME.fullmatch(entry.name):
            continue
        descriptor = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as original, (target / entry.name).open("xb") as copy:
            shutil.copyfileobj(original, copy)


def base_python() -> str:
    """The system Python this version was built on: the new one is built on the same."""
    return str(Path(sys.base_prefix) / "bin" / "python3")


def build(staged: Path, version: str, program: Path = PROGRAM) -> Path:
    """The new version in its own folder, from the staged files alone."""
    target = program / "versions" / version
    if target.exists() or target.is_symlink():
        shutil.rmtree(target, ignore_errors=True)
    _run(base_python(), "-I", "-m", "venv", str(target))
    pip = (str(target / "bin" / "python"), "-I", "-m", "pip", "--isolated", "--no-input")
    quiet = ("--quiet", "--no-cache-dir", "--disable-pip-version-check", "--no-index")
    _run(
        *pip,
        "install",
        *quiet,
        "--require-hashes",
        "--only-binary",
        ":all:",
        "--find-links",
        str(staged / WHEELS),
        "-r",
        str(staged / releases.REQUIREMENTS),
    )
    _run(*pip, "install", *quiet, "--no-deps", str(staged / releases.wheel_name(version)))
    for name in (releases.MANIFEST, releases.SIGNATURE):
        shutil.copyfile(staged / name, target / name)
        os.chmod(target / name, 0o644)
    return target


def status_script_of(target: Path) -> Path:
    found = _run(
        str(target / "bin" / "python"),
        "-I",
        "-c",
        "import sysconfig; print(sysconfig.get_paths()['purelib'])",
    ).stdout.strip()
    script = Path(found) / "checker" / "machine_status.py"
    if not script.is_file():
        raise Failed("the new version has no machine_status.py")
    return script


def point_current(program: Path, target: Path) -> None:
    link = program / "current"
    fresh = program / ".current.new"
    if fresh.is_symlink() or fresh.exists():
        fresh.unlink()
    fresh.symlink_to(target)
    fresh.replace(link)


def answers(port: int = PORT, seconds: float = ANSWER_SECONDS) -> bool:
    """Whether the web interface answers HTTP on this machine: any status counts, since behind a
    proxy it refuses requests that don't come through the proxy."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", "/login")
            connection.getresponse().read(1)
            return True
        except (OSError, http.client.HTTPException):
            time.sleep(2)
        finally:
            connection.close()
    return False


def keep_only(program: Path, *names: str) -> None:
    """The versions to keep: the new one and the one before it."""
    versions = program / "versions"
    for entry in versions.iterdir():
        if entry.name not in names:
            shutil.rmtree(entry, ignore_errors=True)


def install(updates: Path | None = None, program: Path | None = None, unit: str = UNIT) -> dict:
    """One attempt. Returns the outcome, which is also written for the page."""
    updates = updates or UPDATES
    program = program or PROGRAM
    request = updates / REQUEST
    try:
        request.unlink()  # not read: what to install is worked out from what's there
    except FileNotFoundError:
        return {"outcome": "nothing", "words": "there was no request"}
    except OSError as exc:
        raise Failed(f"the request couldn't be removed: {exc}") from None
    before = running_version(program)
    source = offered(updates / "incoming")
    staged = program / "staged" / source.name
    staged.parent.mkdir(mode=0o700, exist_ok=True)
    if staged.exists() or staged.is_symlink():
        shutil.rmtree(staged, ignore_errors=True)
    say(f"Checking version {source.name} against what the release key signed.")
    manifest = releases.stage_release(source, staged, newer_than=before)
    if not (source / WHEELS).is_dir() or (source / WHEELS).is_symlink():
        raise Failed("the release's dependencies weren't fetched")
    copy_wheels(source / WHEELS, staged / WHEELS)
    version = manifest.version
    say(f"Installing version {version} beside {before}.")
    previous = Path(os.readlink(program / "current"))
    target = program / "versions" / version
    old_script = STATUS_SCRIPT.read_bytes() if STATUS_SCRIPT.is_file() else None
    try:
        build(staged, version, program)
        script = status_script_of(target)
        shutil.copyfile(script, STATUS_SCRIPT)
        os.chmod(STATUS_SCRIPT, 0o644)
        point_current(program, target)
        _run("systemctl", "restart", unit, timeout=120)
        if not answers():
            raise Failed(f"version {version} didn't answer within {ANSWER_SECONDS} seconds")
    except (Failed, OSError, subprocess.TimeoutExpired) as exc:
        say(f"Going back to {before}: {exc}")
        point_current(program, previous)
        if old_script is not None:
            STATUS_SCRIPT.write_bytes(old_script)
        _run("systemctl", "restart", unit, timeout=120)
        shutil.rmtree(target, ignore_errors=True)
        shutil.rmtree(staged, ignore_errors=True)
        shutil.rmtree(source, ignore_errors=True)
        return {"outcome": "rolled back", "version": version, "from": before, "words": str(exc)}
    keep_only(program, version, previous.name)
    shutil.rmtree(staged, ignore_errors=True)
    shutil.rmtree(source, ignore_errors=True)
    say(f"Version {version} is installed and answering.")
    return {"outcome": "installed", "version": version, "from": before, "words": ""}


def main(argv: list[str] | None = None) -> int:
    updates = Path(argv[0]) if argv else UPDATES
    try:
        outcome = install(updates)
    except Failed as exc:
        outcome = {"outcome": "failed", "words": str(exc)}
    except releases.ReleaseError as exc:
        outcome = {"outcome": "refused", "words": str(exc)}
    except (OSError, subprocess.TimeoutExpired) as exc:
        outcome = {"outcome": "failed", "words": f"{type(exc).__name__}: {exc}"}
    say(f"{outcome['outcome']}: {outcome.get('words') or outcome.get('version', '')}")
    try:
        write_outcome(updates, outcome)
    except OSError as exc:
        say(f"The outcome couldn't be written for the page: {exc}")
    if outcome["outcome"] == "refused":
        shutil.rmtree(updates / "incoming", ignore_errors=True)
    return 0 if outcome["outcome"] in ("installed", "nothing") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
