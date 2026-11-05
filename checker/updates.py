"""Newer releases of the tool (installation plan I.6, decision I3): finding out that one exists,
and getting it ready for the root service that installs it.

Finding out: GitHub's public list of this repository's releases says which versions exist. Nothing
in that list is trusted. The newest version it names is only reported once that release's manifest
has been downloaded and its signature checked against the release key (checker.releases), so what
the page shows is what the release key signed: the version, when it was published, and whether it
fixes a security problem. A pre-release is only offered to a machine that's already on one. The
check runs as the tool's own account, once a day when someone with full access opens a page, or
when they ask, and can be turned off in the settings (policy §10). A newer release being withheld
can't be detected (docs/releasing.md); the page shows how old the newest it can see is.

Getting it ready: still as the tool's account, the release's files are downloaded into this
machine's own folder, checked against the signed manifest, and the dependencies' wheels fetched so
that root never touches the network. Then a request file is written. The root service
(checker.update_service) reads nothing from that file: it checks the whole release again from
scratch, in a folder of its own, before installing it. The same path serves `checker update --from`
for a release copied over by hand."""

from __future__ import annotations

import contextlib
import json
import re
import shutil
import subprocess  # noqa: S404 - pip, with fixed arguments
import sys
import tempfile
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from checker import __version__, releases
from checker.evidence import load_config
from checker.files import LockBusy, atomic_write, locked
from checker.packs.pull import PullError, fetch

REPOSITORY = "john-c-houser-tech/compromise-checker"
RELEASES_LIST = f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=30"
DOWNLOADS = f"https://github.com/{REPOSITORY}/releases/download"
PROGRAM = Path("/opt/compromise-checker")  # where the installer puts the tool (release/install.py)
CHECK_EVERY = timedelta(hours=24)
MAX_LIST_BYTES = 2 * 1024 * 1024
MAX_CANDIDATES = 6  # manifests looked at before saying the check couldn't be completed
WHEELS = "wheels"
REQUEST = "request"
CHECKED = "check.json"
PROGRESS = "progress.json"
OUTCOME_FILE = Path("/var/lib/compromise-checker-update/outcome.json")  # the root service's
PIP_SECONDS = 1200
_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_lock = threading.Lock()  # one check or preparation at a time in this process


class UpdateError(Exception):
    """Why a newer version couldn't be found or prepared, in the tool's own words."""


Fetch = Callable[[str, int], bytes | None]


# --- What's installed -----------------------------------------------------------------------------


def updates_folder(base: Path) -> Path:
    return base / "updates"


def installed_manifest(program: Path | None = None) -> releases.Manifest | None:
    """The signed manifest the installer or the update service kept beside the running version:
    the only record of whether this machine is on a pre-release. None when the tool wasn't
    installed that way (a developer's checkout, say)."""
    folder = (program or PROGRAM) / "current"
    try:
        data = (folder / releases.MANIFEST).read_bytes()
        signature = (folder / releases.SIGNATURE).read_bytes()
        return releases.read_manifest(data, signature)
    except (OSError, releases.ReleaseError):
        return None


def installed(program: Path | None = None) -> dict[str, Any]:
    manifest = installed_manifest(program)
    return {
        "version": manifest.version if manifest else __version__,
        "prerelease": manifest.prerelease if manifest else None,
        "by_installer": manifest is not None,
    }


# --- Finding out ----------------------------------------------------------------------------------


def versions_listed(listing: bytes) -> list[str]:
    """The versions GitHub's list names, newest first, drafts left out. Only the shape is read: a
    version is a hint of where to look for a signed manifest, never a fact about it."""
    try:
        found = json.loads(listing)
    except ValueError as exc:
        raise UpdateError("GitHub's list of releases couldn't be read") from exc
    if not isinstance(found, list):
        raise UpdateError("GitHub's list of releases couldn't be read")
    versions = set()
    for entry in found:
        if not isinstance(entry, dict) or entry.get("draft") is True:
            continue
        tag = entry.get("tag_name")
        if isinstance(tag, str) and _TAG.fullmatch(tag):
            versions.add(tag[1:])
    return sorted(versions, key=releases.version_key, reverse=True)


def _manifest_of(version: str, fetch: Fetch) -> releases.Manifest | None:
    """A release's signed manifest from where it's published, None if it isn't there."""
    data = fetch(f"{DOWNLOADS}/v{version}/{releases.MANIFEST}", releases.MAX_MANIFEST_BYTES)
    signature = fetch(f"{DOWNLOADS}/v{version}/{releases.SIGNATURE}", releases.MAX_SIGNATURE_BYTES)
    if data is None or signature is None:
        return None
    return releases.read_manifest(data, signature)


def newest(
    running: dict[str, Any], fetch: Fetch = fetch, listing_url: str = RELEASES_LIST
) -> dict[str, Any] | None:
    """The newest release this machine may move to, as its signed manifest says, or None if there's
    nothing newer. Pre-releases count only for a machine already on one."""
    listing = fetch(listing_url, MAX_LIST_BYTES)
    if listing is None:
        raise UpdateError("GitHub has no list of releases for this tool")
    mine = releases.version_key(running["version"])
    looked = 0
    for version in versions_listed(listing):
        if releases.version_key(version) <= mine:
            break
        if looked == MAX_CANDIDATES:  # not "nothing newer": the search stopped short
            raise UpdateError(
                f"more than {MAX_CANDIDATES} newer releases are listed, which is more than one"
                " check looks at"
            )
        looked += 1
        manifest = _manifest_of(version, fetch)
        if manifest is None:
            continue
        if manifest.version != version:
            raise UpdateError(f"the release published as {version} says it's {manifest.version}")
        if manifest.prerelease and not running["prerelease"]:
            continue
        return {
            "version": manifest.version,
            "published": manifest.published,
            "prerelease": manifest.prerelease,
            "security_fix": manifest.security_fix,
        }
    return None


def _newer(version: Any, than: str) -> bool:
    """Whether a found version is newer than the running one. A running version that isn't a plain
    one (a developer's checkout) can't be compared, so what was found stands."""
    try:
        mine = releases.version_key(than)
    except releases.ReleaseError:
        return True
    try:
        return releases.version_key(str(version)) > mine
    except releases.ReleaseError:
        return False


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


BUSY = "another check or update is under way"
ACTIVE = ("getting", "checking", "dependencies")


@contextlib.contextmanager
def _working(base: Path):
    """One check or preparation at a time on this machine, across processes: the page's thread and
    `checker update` in a terminal share the folder. Raises UpdateError at once if busy."""
    try:
        with locked(_made(updates_folder(base)) / "work", wait=0):
            yield
    except LockBusy:
        raise UpdateError(BUSY) from None


def nobody_working(base: Path) -> bool:
    """Whether the lock is free. It's taken for an instant to find out, so a check or preparation
    starting in that instant is told it's busy and tries again later: narrow, and harmless."""
    try:
        with locked(_made(updates_folder(base)) / "work", wait=0):
            return True
    except LockBusy:
        return False


def check(base: Path, fetch: Fetch = fetch, program: Path | None = None) -> dict[str, Any]:
    """Look now, and write down what was found, or why nothing could be: the page reads that."""
    with _working(base):
        running = installed(program)
        found: dict[str, Any] = {"checked": _now(), "installed": running["version"]}
        try:
            found["newest"] = newest(running, fetch)
        except (PullError, releases.ReleaseError, UpdateError) as exc:
            found["newest"] = None
            found["problem"] = _plain(str(exc))
        _write(updates_folder(base) / CHECKED, found)
    return found


def check_now(base: Path) -> dict[str, Any]:
    """For the page's button: claimed before any network is touched, so a row of clicks can't
    each start a download. Raises UpdateError if a check or preparation is already running."""
    if not _lock.acquire(blocking=False):
        raise UpdateError(BUSY)
    try:
        return check(base)
    finally:
        _lock.release()


def _plain(words: str) -> str:
    return words[:500]


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, exist_ok=True)
    atomic_write(path, json.dumps(data, sort_keys=True) + "\n", 0o600)


def _read(path: Path) -> dict[str, Any]:
    try:
        found = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def _when(text: Any) -> datetime | None:
    try:
        when = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    return when if when.tzinfo else None


def due(base: Path, now: datetime | None = None) -> bool:
    """Whether a daily check is wanted now: on in the settings, and none in the last day."""
    try:
        if not load_config(base).updates.check:
            return False
    except Exception:  # noqa: BLE001 - unreadable settings: no check, and the page says so itself
        return False
    checked = _when(_read(updates_folder(base) / CHECKED).get("checked"))
    return checked is None or (now or datetime.now(UTC)) - checked > CHECK_EVERY


def check_in_background(base: Path) -> bool:
    """Start a check unless one is running, here or in a terminal; the page shows what the last one
    found."""
    if not _lock.acquire(blocking=False):
        return False
    if not nobody_working(base):
        _lock.release()
        return False

    def work() -> None:
        try:
            check(base)
        except UpdateError:  # busy after all: nothing written, so the next page tries again
            return
        except Exception as exc:  # noqa: BLE001 - a thread's error has nowhere else to go
            print(
                f"checker web: the check for updates failed: {type(exc).__name__}",
                file=sys.stderr,
            )
            with contextlib.suppress(Exception):  # written down, so the next page doesn't retry
                _write(
                    updates_folder(base) / CHECKED,
                    {
                        "checked": _now(),
                        "newest": None,
                        "problem": "something went wrong in the tool",
                    },
                )
        finally:
            _lock.release()

    threading.Thread(target=work, name="update-check", daemon=True).start()
    return True


# --- Getting a release ready ----------------------------------------------------------------------


def status(
    base: Path, program: Path | None = None, outcome_file: Path | None = None
) -> dict[str, Any]:
    """Everything the Updates page shows, from files alone."""
    folder = updates_folder(base)
    checked = _read(folder / CHECKED)
    running = installed(program)
    try:
        enabled = load_config(base).updates.check
    except Exception:  # noqa: BLE001 - the page says the settings can't be read elsewhere
        enabled = None
    newest_found = checked.get("newest")
    if not isinstance(newest_found, dict) or not newest_found.get("version"):
        newest_found = None
    elif not _newer(newest_found["version"], running["version"]):
        newest_found = None  # found before an update that has since been installed
    progress = _read(folder / PROGRESS)
    if progress.get("state") in ACTIVE and nobody_working(base):
        # Left by a web process that stopped part way: nothing is still working on it.
        progress = {
            **progress,
            "state": "failed",
            "words": "whatever was getting it stopped part way: the web interface restarted, or"
            " a terminal command was interrupted. Try again.",
        }
    outcome = _read(outcome_file or OUTCOME_FILE)
    # An outcome from before the release now being got ready is about an earlier update.
    if str(outcome.get("at", "")) < str(progress.get("at", "")):
        outcome = {}
    return {
        **running,
        "enabled": enabled,
        "checked": _when(checked.get("checked")),
        "newest": newest_found,
        "problem": checked.get("problem") if isinstance(checked.get("problem"), str) else None,
        "progress": progress,
        "outcome": outcome,
        "requested": (folder / REQUEST).exists(),
    }


def notice(base: Path, program: Path | None = None) -> dict[str, Any] | None:
    """What every page says to people with full access: a newer version, if one is known."""
    found = status(base, program)["newest"]
    return found if found else None


def _progress(base: Path, version: str, state: str, words: str = "") -> None:
    data = {"at": _now(), "version": version, "state": state, "words": _plain(words)}
    _write(updates_folder(base) / PROGRESS, data)


def _wheels(
    python: str, requirements: Path, into: Path, run=subprocess.run, wheelhouse: Path | None = None
) -> None:
    """The dependencies' wheels, each checked by pip against the hash the signed list gives, so
    root installs from this machine and never from the network. With a wheelhouse copied over
    beside the release, for a machine without internet, pip takes them from there instead, still
    by hash and only the names the signed list has."""
    into.mkdir(mode=0o700)
    offline = ["--no-index", "--find-links", str(wheelhouse)] if wheelhouse else []
    command = [
        python,
        "-I",
        "-m",
        "pip",
        "--isolated",
        "--no-input",
        "download",
        "--quiet",
        "--no-cache-dir",
        "--disable-pip-version-check",
        "--require-hashes",
        "--only-binary",
        ":all:",
        *offline,
        "-r",
        str(requirements),
        "-d",
        str(into),
    ]
    try:
        done = run(command, capture_output=True, text=True, errors="replace", timeout=PIP_SECONDS)
    except subprocess.TimeoutExpired:
        raise UpdateError(
            f"the dependencies couldn't be fetched within {PIP_SECONDS // 60} minutes"
        ) from None
    if done.returncode:
        raise UpdateError(f"the dependencies couldn't be fetched: {done.stderr.strip()[-800:]}")


def prepare(
    base: Path,
    version: str | None = None,
    source: Path | None = None,
    fetch: Fetch = fetch,
    program: Path | None = None,
    python: str = sys.executable,
    run=subprocess.run,
) -> releases.Manifest:
    """Get a release ready for the root service and ask it to install: from where releases are
    published, or from `source`, a folder someone copied one into. Refuses anything not newer than
    what's running. Raises UpdateError with the reason."""
    running = installed(program)
    folder = updates_folder(base)
    incoming = folder / "incoming"
    if version is None and source is None:
        raise UpdateError("say which version, or where the release is")
    shown = version or "the release"
    with _working(base):
        _progress(base, shown, "getting")
        manifest = _prepare(base, version, source, fetch, running, folder, incoming, python, run)
    return manifest


def _prepare(base, version, source, fetch, running, folder, incoming, python, run):
    shown = version or "the release"
    try:
        with tempfile.TemporaryDirectory(prefix=".incoming-", dir=_made(folder)) as work:
            fetched = Path(work)
            if source is None:
                _download(version or "", fetched, fetch)
            else:
                _copy_in(source, fetched)
            _progress(base, shown, "checking")
            incoming.mkdir(mode=0o700, exist_ok=True)
            for old in incoming.iterdir():  # one at a time: an earlier one that never went
                shutil.rmtree(old, ignore_errors=True)
            data, signature = (fetched / releases.MANIFEST), (fetched / releases.SIGNATURE)
            manifest = releases.read_manifest(data.read_bytes(), signature.read_bytes())
            target = incoming / manifest.version
            releases.stage_release(
                fetched, target, newer_than=running["version"], expected_version=version
            )
            if manifest.prerelease and running["prerelease"] is False:
                shutil.rmtree(target, ignore_errors=True)
                raise UpdateError(
                    f"{manifest.version} is a pre-release, and this machine is on a final version"
                )
            _progress(base, manifest.version, "dependencies")
            wheelhouse = source / WHEELS if source is not None else None
            if wheelhouse is not None and not wheelhouse.is_dir():
                wheelhouse = None
            _wheels(python, target / releases.REQUIREMENTS, target / WHEELS, run, wheelhouse)
    except (PullError, releases.ReleaseError, OSError) as exc:
        _progress(base, shown, "failed", str(exc))
        raise UpdateError(_plain(str(exc))) from None
    except UpdateError as exc:
        _progress(base, shown, "failed", str(exc))
        raise
    _progress(base, manifest.version, "handed over")
    atomic_write(folder / REQUEST, f"{manifest.version}\n", 0o600)
    return manifest


def prepare_in_background(base: Path, version: str) -> bool:
    """For the page: getting a release and its dependencies takes minutes. The progress file says
    how far it got, and the page reads that. False if a check or preparation is already running,
    here or in a terminal."""
    if not _lock.acquire(blocking=False):
        return False
    if not nobody_working(base):
        _lock.release()
        return False

    def work() -> None:
        try:
            prepare(base, version)
        except UpdateError as exc:
            # Written down by prepare for the page, unless it was busy after all: then nothing is
            # written, since the file is the running preparation's.
            print(f"checker web: the update wasn't prepared: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - a thread's error has nowhere else to go
            print(
                f"checker web: preparing the update failed: {type(exc).__name__}", file=sys.stderr
            )
            _progress(base, version, "failed", "something went wrong in the tool")
        finally:
            _lock.release()

    threading.Thread(target=work, name="update-prepare", daemon=True).start()
    return True


def _made(folder: Path) -> Path:
    folder.mkdir(mode=0o700, exist_ok=True)
    return folder


def _download(version: str, into: Path, fetch: Fetch) -> None:
    """A release's files, by the names its signed manifest gives: the manifest first, so nothing is
    fetched that it doesn't name, and each file at most as large as it says."""
    if not version:
        raise UpdateError("say which version")
    releases.version_key(version)  # a version, not a path
    where = f"{DOWNLOADS}/v{version}"
    data = fetch(f"{where}/{releases.MANIFEST}", releases.MAX_MANIFEST_BYTES)
    signature = fetch(f"{where}/{releases.SIGNATURE}", releases.MAX_SIGNATURE_BYTES)
    if data is None or signature is None:
        raise UpdateError(f"version {version} isn't published where releases are")
    manifest = releases.read_manifest(data, signature)
    (into / releases.MANIFEST).write_bytes(data)
    (into / releases.SIGNATURE).write_bytes(signature)
    for name, expected in manifest.files.items():
        content = fetch(f"{where}/{name}", expected.size)
        if content is None:
            raise UpdateError(f"{name} isn't published with version {version}")
        (into / name).write_bytes(content)


def _copy_in(source: Path, into: Path) -> None:
    """Only what a release's manifest names, from a folder someone else may have written to."""
    data = (source / releases.MANIFEST).read_bytes()
    signature = (source / releases.SIGNATURE).read_bytes()
    manifest = releases.read_manifest(data, signature)
    (into / releases.MANIFEST).write_bytes(data)
    (into / releases.SIGNATURE).write_bytes(signature)
    for name in manifest.files:
        with (source / name).open("rb") as original, (into / name).open("xb") as copy:
            shutil.copyfileobj(original, copy)


def cancel(base: Path) -> bool:
    """Take back a request the root service hasn't acted on yet."""
    request = updates_folder(base) / REQUEST
    try:
        request.unlink()
    except FileNotFoundError:
        return False
    return True


def words_for(state: dict[str, Any]) -> str:
    """One line of progress for the page or the terminal."""
    found = state.get("state")
    version = state.get("version", "")
    return {
        "getting": f"Getting version {version}.",
        "checking": f"Checking version {version} against what the release key signed.",
        "dependencies": f"Fetching version {version}'s dependencies.",
        "handed over": (
            f"Version {version} is ready, and the update service has been asked to install it."
        ),
        "failed": f"Version {version} couldn't be prepared: {state.get('words', '')}",
    }.get(found or "", "")
