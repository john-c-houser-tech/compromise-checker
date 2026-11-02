"""Build a release of the tool, for the maintainer to sign by hand (docs/releasing.md).

    release.py lock                 write the exact dependency lists, with hashes
    release.py build --prerelease   build dist/release-VERSION/ from the commit checked out
    release.py verify DIRECTORY     check a signed release as an install would

Nothing here signs or publishes, and no key is read. The wheel is built from what's committed, never
from the working folder, with a pinned build tool, and it's built twice to show that the same commit
gives the same bytes, so anyone can rebuild a release and compare it."""

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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from checker import __version__  # noqa: E402
from checker.releases import (  # noqa: E402
    MANIFEST,
    REQUIREMENTS,
    SIGNATURE,
    Manifest,
    ReleaseError,
    read_release,
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
_WHEEL_MUST_HOLD = (
    "checker/collector/collector.py",
    "checker/packs/keys/keys.yaml",
    "checker/packs/keys/keys.yaml.minisig",
    "checker/web/templates/first_setup.html.j2",
    "checker/profiles/base.yaml",
)


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


def _compile(source: list[str], target: Path, stdin: str | None = None) -> None:
    """uv writes every hash of every version it picks, for all platforms and Python versions the
    tool supports, so the one list serves any machine."""
    target.parent.mkdir(exist_ok=True)
    done = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "uv",
            "pip",
            "compile",
            *source,
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


def lock() -> None:
    extras = [part for extra in EXTRAS for part in ("--extra", extra)]
    _compile(["pyproject.toml", *extras], LOCK)
    _compile(["-"], BUILD_LOCK, stdin=f"{BUILD_TOOL}\n")
    print(f"Wrote {LOCK.relative_to(ROOT)} and {BUILD_LOCK.relative_to(ROOT)}. Review what moved.")


def collector_version(text: str) -> str:
    found = re.search(r'^COLLECTOR_VERSION = "([^"]+)"$', text, re.MULTILINE)
    if not found:
        raise Refused("can't find the collector's version")
    return found.group(1)


def check_ready(version: str, collector: str, status: str, trial: bool) -> None:
    """A real release is of a final version, with nothing uncommitted that could confuse what it
    holds. A trial, for CI and for checking this script, may be of anything, and a machine would
    refuse its manifest if it's of a version such as 0.1.0.dev0."""
    if collector != version:
        raise Refused(f"the tool says {version} and the collector says {collector}")
    if trial:
        return
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise Refused(f"{version} isn't a release version: set one such as 0.1.0 first")
    if status:
        raise Refused(f"there are uncommitted changes, so commit or remove them:\n{status}")


def _build_wheel(python: Path, source: Path, out: Path, env: dict) -> Path:
    out.mkdir()
    _run(
        python,
        "-m",
        "pip",
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


def build_wheel(commit: str, work: Path) -> Path:
    """The wheel for `commit`, built twice in fresh copies. Different bytes mean something outside
    the commit got in, and then nobody could check this release by rebuilding it."""
    tool = work / "tool"
    venv.create(tool, with_pip=True)
    python = tool / "bin" / "python"
    _run(python, "-m", "pip", "install", "--quiet", "--require-hashes", "-r", BUILD_LOCK)
    when = _git("show", "-s", "--format=%ct", commit)
    env = {**os.environ, "SOURCE_DATE_EPOCH": when, "PYTHONHASHSEED": "0"}
    env.pop("PIP_CONSTRAINT", None)
    wheels = []
    for attempt in ("one", "two"):
        source = work / attempt
        source.mkdir()
        archive = work / f"{attempt}.tar"
        _git("archive", "--format=tar", "--output", str(archive), commit)
        with tarfile.open(archive) as tar:
            tar.extractall(source, filter="data")
        wheels.append(_build_wheel(python, source, work / f"{attempt}-out", env))
    if sha256_of(wheels[0]) != sha256_of(wheels[1]):
        raise Refused("two builds of the same commit differ, so this release couldn't be checked")
    return wheels[0]


def check_wheel(wheel: Path, version: str) -> None:
    """What CI has always asked of the package, and what an install can't do without."""
    if wheel.name != wheel_name(version):
        raise Refused(f"the wheel is called {wheel.name}, not {wheel_name(version)}")
    import zipfile

    with zipfile.ZipFile(wheel) as package:
        names = set(package.namelist())
    missing = [name for name in _WHEEL_MUST_HOLD if name not in names]
    if missing:
        raise Refused(f"the wheel doesn't hold {', '.join(missing)}")


def write_manifest(
    directory: Path, version: str, commit: str, prerelease: bool, security_fix: bool
) -> Path:
    files = {
        path.name: {"sha256": sha256_of(path), "size": path.stat().st_size}
        for path in sorted(directory.iterdir())
        if path.is_file() and path.name not in (MANIFEST, SIGNATURE)
    }
    body = {
        "schema": 1,
        "version": version,
        "commit": commit,
        "prerelease": prerelease,
        "security_fix": security_fix,
        "files": files,
    }
    if re.fullmatch(r"\d+\.\d+\.\d+", version):
        Manifest.model_validate(body)  # never write one that a machine would refuse to read
    path = directory / MANIFEST
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return path


def build(prerelease: bool, security_fix: bool, trial: bool) -> Path:
    collector = (ROOT / "checker" / "collector" / "collector.py").read_text(encoding="utf-8")
    check_ready(__version__, collector_version(collector), _git("status", "--porcelain"), trial)
    commit = _git("rev-parse", "HEAD")
    directory = ROOT / "dist" / f"release-{__version__}"
    if directory.exists():
        if not trial:
            raise Refused(f"{directory} already exists: move it away if you mean to build again")
        shutil.rmtree(directory)
    directory.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="checker-release-") as work:
        wheel = build_wheel(commit, Path(work))
        check_wheel(wheel, __version__)
        # Put together apart and moved into place, so a failed build leaves nothing to sign.
        staged = Path(tempfile.mkdtemp(prefix=".staged-", dir=directory.parent))
        try:
            shutil.copy(wheel, staged / wheel.name)
            committed = _git("show", f"{commit}:release/requirements.lock")
            (staged / REQUIREMENTS).write_text(committed + "\n", encoding="utf-8")
            write_manifest(staged, __version__, commit, prerelease, security_fix)
            staged.chmod(0o755)
            staged.rename(directory)
        except BaseException:
            shutil.rmtree(staged, ignore_errors=True)
            raise
    return directory


def verify(directory: Path) -> None:
    manifest = read_release(directory)
    kind = "pre-release" if manifest.prerelease else "release"
    print(
        f"Good: {kind} {manifest.version} of commit {manifest.commit}, signed by the release key."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("lock", help="write the exact dependency lists")
    making = commands.add_parser("build", help="build the release from the commit checked out")
    kind = making.add_mutually_exclusive_group(required=True)
    kind.add_argument("--prerelease", action="store_true", help="a beta: finals don't move to it")
    kind.add_argument("--final", action="store_true", help="a final release")
    making.add_argument("--security-fix", action="store_true", help="tell machines to hurry")
    making.add_argument("--trial", action="store_true", help="for checking only, never for signing")
    checking = commands.add_parser("verify", help="check a signed release as an install would")
    checking.add_argument("directory", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "lock":
            lock()
        elif arguments.command == "verify":
            verify(arguments.directory)
        else:
            directory = build(arguments.prerelease, arguments.security_fix, arguments.trial)
            print(f"Built {directory.relative_to(ROOT)}. To sign it, see docs/releasing.md.")
    except (Refused, ReleaseError) as exc:
        print(f"Not done: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
