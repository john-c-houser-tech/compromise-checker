"""Build a release of the tool, for the maintainer to sign by hand (docs/releasing.md).

    release.py lock [--package NAME] [--check]   write or check the exact dependency lists
    release.py build --prerelease                build dist/release-VERSION/ from the tagged commit
    release.py verify DIRECTORY [--key FILE]     check a signed release as an install would

Nothing here signs or publishes, and no key is read. The wheel is built from what's committed, never
from the working folder, with a pinned build tool and none of the maintainer's own settings. It's
built twice under different conditions, and its files are compared with the commit's. The same
commit should give the same bytes, so anyone can rebuild a release and compare it."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # noqa: S404
import sys
import tarfile
import tempfile
import venv
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from checker import __version__  # noqa: E402
from checker.packs.signing import SignatureError, public_key  # noqa: E402
from checker.releases import (  # noqa: E402
    MANIFEST,
    REQUIREMENTS,
    SIGNATURE,
    Manifest,
    ReleaseError,
    read_release,
    release_keys,
    sha256_of,
    wheel_name,
)

LOCK = ROOT / "release" / "requirements.lock"
BUILD_LOCK = ROOT / "release" / "build-requirements.lock"
# What an installed machine has: the web interface and everything it offers. keyring isn't here,
# since a machine with nobody at it has no keyring to unlock, and nor are developers' tools.
EXTRAS = ("web", "postgres", "pdf", "advisor")
BUILD_TOOL = "setuptools>=80"
OLDEST_PYTHON = "3.12"
_FINAL = re.compile(r"\d+\.\d+\.\d+")


class Refused(Exception):
    """Why a release can't be built; the message says what to do."""


def _run(*command: str | Path, cwd: Path | None = None, env: dict | None = None) -> str:
    done = subprocess.run(  # noqa: S603
        [str(part) for part in command],
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    if done.returncode:
        raise Refused(f"{command[0]} {command[1]} failed:\n{done.stdout}{done.stderr}")
    return done.stdout


def _git(*arguments: str) -> str:
    return _run("git", *arguments, cwd=ROOT).strip()


def _compile(
    source: list[str], target: Path, stdin: str | None = None, freshen: tuple[str, ...] = ()
) -> None:
    """uv writes every hash of every version it picks, for all platforms and Python versions the
    tool supports, so the one list serves any machine. It keeps what's already in `target` unless
    told otherwise, so `freshen` says what may move."""
    done = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "uv",
            "pip",
            "compile",
            *source,
            *freshen,
            "--universal",
            "--python-version",
            OLDEST_PYTHON,
            "--generate-hashes",
            "--no-header",
            "--no-annotate",
            "--quiet",
            "--output-file",
            str(target),
        ],
        input=stdin,
        check=False,
        text=True,
        capture_output=True,
        cwd=ROOT,
    )
    if done.returncode:
        raise Refused(f"uv pip compile failed:\n{done.stderr}")


def _project_source() -> list[str]:
    return ["pyproject.toml", *[part for extra in EXTRAS for part in ("--extra", extra)]]


def lock(packages: tuple[str, ...] = ()) -> None:
    """Every dependency moves to its newest version, or only the ones named."""
    freshen = (
        tuple(part for name in packages for part in ("--upgrade-package", name))
        if packages
        else ("--upgrade",)
    )
    LOCK.parent.mkdir(exist_ok=True)
    _compile(_project_source(), LOCK, freshen=freshen)
    if not packages:
        _compile(["-"], BUILD_LOCK, stdin=f"{BUILD_TOOL}\n", freshen=freshen)
    print(f"Wrote {LOCK.relative_to(ROOT)} and {BUILD_LOCK.relative_to(ROOT)}. Review what moved.")


def check_lock() -> None:
    """The list still meets pyproject.toml: nothing moves unless it has to, so any change means the
    project asks for something the list doesn't give."""
    with tempfile.TemporaryDirectory(prefix="checker-lock-") as work:
        fresh = Path(work) / "requirements.lock"
        shutil.copy(LOCK, fresh)
        _compile(_project_source(), fresh)
        if fresh.read_bytes() != LOCK.read_bytes():
            raise Refused("the list no longer matches pyproject.toml: run scripts/release.py lock")
    print("The list matches pyproject.toml.")


def collector_version(text: str) -> str:
    found = re.search(r'^COLLECTOR_VERSION = "([^"]+)"$', text, re.MULTILINE)
    if not found:
        raise Refused("can't find the collector's version")
    return found.group(1)


def check_ready(version: str, collector: str, status: str, trial: bool) -> None:
    """A real release is of a final version, with nothing uncommitted that could confuse what it
    holds. A trial, for CI and for checking this script, may be of anything."""
    if collector != version:
        raise Refused(f"the tool says {version} and the collector says {collector}")
    if trial:
        return
    if not _FINAL.fullmatch(version):
        raise Refused(f"{version} isn't a release version: set one such as 0.1.0 first")
    if status:
        raise Refused(f"there are uncommitted changes, so commit or remove them:\n{status}")


def check_source(version: str, commit: str, tagged: str | None, on_main: bool) -> None:
    """What gets signed is what `main` has, under the tag that names it."""
    if tagged is None:
        raise Refused(f"there's no tag v{version} here: tag this commit first, without pushing it")
    if tagged != commit:
        raise Refused(f"v{version} is commit {tagged}, and this is {commit}")
    if not on_main:
        raise Refused("this commit isn't on origin/main: fetch it, or release from main")


def check_keys() -> None:
    """A release with no key in it could never be updated by the button."""
    try:
        keys = release_keys()
    except SignatureError as exc:
        raise Refused(f"RELEASE_KEYS can't be read: {exc}") from None
    if not keys:
        raise Refused("RELEASE_KEYS is empty, so machines could never check an update")


def _tag_commit(version: str) -> str | None:
    done = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--verify", "--quiet", f"refs/tags/v{version}^{{commit}}"],  # noqa: S607
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    return done.stdout.strip() if done.returncode == 0 else None


def _on_main(commit: str) -> bool:
    done = subprocess.run(  # noqa: S603
        ["git", "merge-base", "--is-ancestor", commit, "origin/main"],  # noqa: S607
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    return done.returncode == 0


def _clean_env(home: Path, tz: str, epoch: str) -> dict:
    """Only what a build needs. Anything else that's passed along (PYTHONPATH, a user's pip or
    distutils settings) could change what's built, without changing the commit."""
    return {
        "PATH": os.defpath,
        "HOME": str(home),
        "TZ": tz,
        "LC_ALL": "C.UTF-8",
        "SOURCE_DATE_EPOCH": epoch,
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
    }


def _build_wheel(python: Path, source: Path, out: Path, env: dict) -> Path:
    out.mkdir()
    _run(
        python,
        "-I",
        "-m",
        "pip",
        "--isolated",
        "wheel",
        "--no-deps",
        "--no-build-isolation",
        "--quiet",
        "--wheel-dir",
        out,
        source,
        env=env,
    )
    wheels = list(out.glob("*.whl"))
    if len(wheels) != 1:
        raise Refused(f"expected one wheel, and got {[w.name for w in wheels]}")
    return wheels[0]


def build_wheel(commit: str, work: Path) -> tuple[Path, Path]:
    """The wheel for `commit`, and a copy of the commit's files to compare it with. It's built
    twice, in fresh copies with a different home and time zone: different bytes mean the result
    depends on something other than the commit. Permissions are fixed, since they end up in the
    wheel."""
    tool = work / "tool"
    venv.create(tool, with_pip=True)
    python = tool / "bin" / "python"
    _run(python, "-m", "pip", "install", "--quiet", "--require-hashes", "-r", BUILD_LOCK)
    when = _git("show", "-s", "--format=%ct", commit)
    wheels, sources = [], []
    before = os.umask(0o022)
    try:
        for attempt, tz in (("one", "UTC"), ("two", "Asia/Tokyo")):
            source = work / attempt
            source.mkdir()
            archive = work / f"{attempt}.tar"
            _git(
                "-c", "tar.umask=0022", "archive", "--format=tar", "--output", str(archive), commit
            )
            with tarfile.open(archive) as tar:
                tar.extractall(source, filter="data")
            sources.append(source)
            home = work / f"{attempt}-home"
            home.mkdir()
            env = _clean_env(home, tz, when)
            wheels.append(_build_wheel(python, source, work / f"{attempt}-out", env))
    finally:
        os.umask(before)
    if sha256_of(wheels[0]) != sha256_of(wheels[1]):
        raise Refused("two builds of the same commit differ, so this release couldn't be checked")
    return wheels[0], sources[0]


def check_wheel(wheel: Path, version: str, source: Path) -> None:
    """The wheel holds exactly the commit's `checker` folder, byte for byte, plus the package's own
    description. That's what stops a file going missing, and what stops one getting in."""
    if wheel.name != wheel_name(version):
        raise Refused(f"the wheel is called {wheel.name}, not {wheel_name(version)}")
    description = f"checker-{version}.dist-info/"
    with zipfile.ZipFile(wheel) as package:
        held = {
            info.filename: package.read(info)
            for info in package.infolist()
            if not info.is_dir() and not info.filename.startswith(description)
        }
        if not any(name.startswith(description) for name in package.namelist()):
            raise Refused("the wheel has no package description")
    wanted = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in (source / "checker").rglob("*")
        if path.is_file()
    }
    extra = sorted(set(held) - set(wanted))
    if extra:
        raise Refused(f"the wheel holds what the commit doesn't: {', '.join(extra)}")
    missing = sorted(set(wanted) - set(held))
    if missing:
        raise Refused(f"the wheel doesn't hold {', '.join(missing)}")
    changed = sorted(name for name in held if held[name] != wanted[name])
    if changed:
        raise Refused(f"the wheel differs from the commit in {', '.join(changed)}")


def write_manifest(
    directory: Path,
    version: str,
    commit: str,
    prerelease: bool,
    security_fix: bool,
    published: str,
    trial: bool = False,
) -> Path:
    """A trial's manifest says format 0, which no machine reads, even if someone signs it."""
    files = {
        path.name: {"sha256": sha256_of(path), "size": path.stat().st_size}
        for path in sorted(directory.iterdir())
        if path.is_file() and path.name not in (MANIFEST, SIGNATURE)
    }
    body = {
        "schema": 0 if trial else 1,
        "version": version,
        "commit": commit,
        "published": published,
        "prerelease": prerelease,
        "security_fix": security_fix,
        "files": files,
    }
    if not trial:
        Manifest.model_validate(body)  # never write one that a machine would refuse to read
    path = directory / MANIFEST
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return path


def clear_way(dist: Path, version: str, trial: bool) -> Path:
    """Where the build goes. A trial has its own folder, so it can never touch a signed release."""
    directory = dist / f"{'trial' if trial else 'release'}-{version}"
    if directory.exists():
        if not trial:
            raise Refused(f"{directory} already exists: move it away if you mean to build again")
        shutil.rmtree(directory)
    dist.mkdir(exist_ok=True)
    return directory


def build(prerelease: bool, security_fix: bool, trial: bool) -> Path:
    collector = (ROOT / "checker" / "collector" / "collector.py").read_text(encoding="utf-8")
    check_ready(__version__, collector_version(collector), _git("status", "--porcelain"), trial)
    commit = _git("rev-parse", "HEAD")
    if not trial:
        check_source(__version__, commit, _tag_commit(__version__), _on_main(commit))
        check_keys()
    directory = clear_way(ROOT / "dist", __version__, trial)
    published = datetime.now(UTC).date().isoformat()
    with tempfile.TemporaryDirectory(prefix="checker-release-") as work:
        wheel, source = build_wheel(commit, Path(work))
        check_wheel(wheel, __version__, source)
        # Put together apart and moved into place, so a failed build leaves nothing to sign.
        staged = Path(tempfile.mkdtemp(prefix=".staged-", dir=directory.parent))
        try:
            shutil.copy(wheel, staged / wheel.name)
            (staged / REQUIREMENTS).write_bytes((source / "release/requirements.lock").read_bytes())
            write_manifest(
                staged, __version__, commit, prerelease, security_fix, published, trial=trial
            )
            staged.chmod(0o755)
            staged.rename(directory)
        except BaseException:
            shutil.rmtree(staged, ignore_errors=True)
            raise
    return directory


def publish_command(directory: Path, version: str, prerelease: bool) -> str:
    flag = " --prerelease" if prerelease else ""
    return f'gh release create v{version} --verify-tag{flag} --title "{version}" {directory}/*'


def verify(directory: Path, key_file: Path | None = None) -> None:
    """A release that changes the key is signed by the old one, which its own commit no longer
    lists: `key_file` names what the machines it's for trust."""
    try:
        keys = [public_key(key_file.read_text(encoding="utf-8"))] if key_file else None
    except (OSError, SignatureError) as exc:
        raise Refused(f"can't use that key: {exc}") from None
    manifest = read_release(directory, keys)
    kind = "pre-release" if manifest.prerelease else "release"
    print(
        f"Good: {kind} {manifest.version} of commit {manifest.commit}, signed by the release key."
    )
    print("To publish it, once the tag is pushed:")
    print(f"    {publish_command(directory, manifest.version, manifest.prerelease)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    locking = commands.add_parser("lock", help="write the exact dependency lists")
    locking.add_argument("--package", action="append", default=[], help="move only this one")
    locking.add_argument("--check", action="store_true", help="only check it meets pyproject.toml")
    making = commands.add_parser("build", help="build the release from the tagged commit")
    kind = making.add_mutually_exclusive_group(required=True)
    kind.add_argument("--prerelease", action="store_true", help="a beta: finals don't move to it")
    kind.add_argument("--final", action="store_true", help="a final release")
    making.add_argument("--security-fix", action="store_true", help="tell machines to hurry")
    making.add_argument("--trial", action="store_true", help="for checking only, never for signing")
    checking = commands.add_parser("verify", help="check a signed release as an install would")
    checking.add_argument("directory", type=Path)
    checking.add_argument("--key", type=Path, help="a public key file to check against instead")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "lock":
            check_lock() if arguments.check else lock(tuple(arguments.package))
        elif arguments.command == "verify":
            verify(arguments.directory, arguments.key)
        else:
            directory = build(arguments.prerelease, arguments.security_fix, arguments.trial)
            print(f"Built {directory.relative_to(ROOT)}. To sign it, see docs/releasing.md.")
    except (Refused, ReleaseError) as exc:
        print(f"Not done: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
