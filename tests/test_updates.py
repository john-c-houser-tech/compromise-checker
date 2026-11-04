"""Finding a newer release and getting it ready (installation plan I.6), with nothing fetched."""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_pack_trust import Key

from checker import releases, updates
from checker.evidence import initialise
from checker.packs.pull import PullError

KEY = Key()
REPO_LIST = updates.RELEASES_LIST


def _release(directory: Path, version: str, prerelease=False, security_fix=False) -> dict:
    """A signed release in `directory`, as tests of checker.releases make one."""
    directory.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, content in (
        (releases.wheel_name(version), b"wheel " + version.encode()),
        (releases.REQUIREMENTS, b"django==5.2 --hash=sha256:0\n"),
        (releases.INSTALLER, b"print('install')\n"),
    ):
        (directory / name).write_bytes(content)
        files[name] = {"sha256": releases.sha256_of(directory / name), "size": len(content)}
    manifest = {
        "schema": 1,
        "version": version,
        "commit": "a" * 40,
        "published": "2026-11-20",
        "prerelease": prerelease,
        "security_fix": security_fix,
        "files": files,
    }
    data = json.dumps(manifest).encode()
    (directory / releases.MANIFEST).write_bytes(data)
    (directory / releases.SIGNATURE).write_bytes(KEY.sign(data))
    return manifest


@pytest.fixture
def trusted(monkeypatch):
    monkeypatch.setattr(releases, "RELEASE_KEYS", (KEY.line,))


def listing(*entries) -> bytes:
    return json.dumps(
        [{"tag_name": tag, "draft": draft, "prerelease": pre} for tag, draft, pre in entries]
    ).encode()


def published(work: Path, *versions, **flags) -> dict[str, bytes]:
    """Files as GitHub would serve them, by URL."""
    served = {}
    for version in versions:
        folder = work / version
        _release(folder, version, **flags.get(version, {}))
        for path in folder.iterdir():
            served[f"{updates.DOWNLOADS}/v{version}/{path.name}"] = path.read_bytes()
    return served


def fetcher(served: dict[str, bytes], asked: list | None = None):
    def fetch(url: str, limit: int):
        if asked is not None:
            asked.append(url)
        found = served.get(url)
        if found is not None and len(found) > limit:
            raise PullError("too large")
        return found

    return fetch


def installed_at(program: Path, version: str, prerelease=False) -> None:
    current = program / "versions" / version
    _release(current, version, prerelease=prerelease)
    (program / "current").symlink_to(current)


def test_versions_listed_reads_only_the_shape_of_github_s_list():
    text = listing(("v0.1.0", False, True), ("v0.2.0", False, False), ("v0.3.0", True, False))
    assert updates.versions_listed(text) == ["0.2.0", "0.1.0"], "drafts left out, newest first"
    odd = json.dumps([{"tag_name": "0.4.0"}, {"tag_name": "v1.2"}, 3, {"tag_name": "v9.9.9x"}])
    assert updates.versions_listed(odd.encode()) == []
    tens = listing(("v0.10.0", False, False), ("v0.9.0", False, False))
    assert updates.versions_listed(tens)[0] == "0.10.0"
    for bad in (b"not json", b'{"a": 1}'):
        with pytest.raises(updates.UpdateError):
            updates.versions_listed(bad)


def test_the_newest_is_what_the_release_key_signed_and_nothing_from_the_list(tmp_path, trusted):
    served = published(tmp_path, "0.2.0", "0.3.0", **{"0.3.0": {"security_fix": True}})
    served[REPO_LIST] = listing(("v0.3.0", False, False), ("v0.2.0", False, False))
    running = {"version": "0.1.0", "prerelease": False}
    found = updates.newest(running, fetcher(served))
    assert found == {
        "version": "0.3.0",
        "published": "2026-11-20",
        "prerelease": False,
        "security_fix": True,
    }
    # A tag the list names but whose files aren't there is passed over.
    served[REPO_LIST] = listing(("v0.4.0", False, False), ("v0.3.0", False, False))
    assert updates.newest(running, fetcher(served))["version"] == "0.3.0"
    # Nothing newer than what runs.
    assert updates.newest({"version": "0.3.0", "prerelease": False}, fetcher(served)) is None
    # A manifest signed by someone else is a refusal, not a version.
    other = Key()
    data = json.loads(served[f"{updates.DOWNLOADS}/v0.3.0/release.json"])
    served[f"{updates.DOWNLOADS}/v0.3.0/release.json.minisig"] = other.sign(
        json.dumps(data).encode()
    )
    with pytest.raises(releases.ReleaseError):
        updates.newest(running, fetcher(served))


def test_a_release_published_under_another_version_s_tag_is_refused(tmp_path, trusted):
    served = published(tmp_path, "0.2.0")
    for name in ("release.json", "release.json.minisig"):
        served[f"{updates.DOWNLOADS}/v0.9.0/{name}"] = served[f"{updates.DOWNLOADS}/v0.2.0/{name}"]
    served[REPO_LIST] = listing(("v0.9.0", False, False))
    with pytest.raises(updates.UpdateError, match="says it's 0.2.0"):
        updates.newest({"version": "0.1.0", "prerelease": False}, fetcher(served))


def test_pre_releases_are_only_for_a_machine_on_one(tmp_path, trusted):
    served = published(tmp_path, "0.2.0", "0.3.0", **{"0.3.0": {"prerelease": True}})
    served[REPO_LIST] = listing(("v0.3.0", False, True), ("v0.2.0", False, False))
    final = {"version": "0.1.0", "prerelease": False}
    assert updates.newest(final, fetcher(served))["version"] == "0.2.0"
    on_one = {"version": "0.1.0", "prerelease": True}
    assert updates.newest(on_one, fetcher(served))["version"] == "0.3.0"
    # The list's own pre-release flag means nothing: the manifest's does.
    served[REPO_LIST] = listing(("v0.3.0", False, False), ("v0.2.0", False, False))
    assert updates.newest(final, fetcher(served))["version"] == "0.2.0"


def test_only_a_few_manifests_are_looked_at(tmp_path, trusted):
    served = {REPO_LIST: listing(*((f"v0.{n}.0", False, False) for n in range(9, 1, -1)))}
    asked = []
    assert updates.newest({"version": "0.1.0", "prerelease": False}, fetcher(served, asked)) is None
    assert len([url for url in asked if url.endswith("release.json")]) == updates.MAX_CANDIDATES


def test_no_list_or_a_huge_one_is_said_so(tmp_path, trusted):
    with pytest.raises(updates.UpdateError, match="no list"):
        updates.newest({"version": "0.1.0", "prerelease": False}, fetcher({}))
    with pytest.raises(PullError):
        updates.newest(
            {"version": "0.1.0", "prerelease": False},
            fetcher({REPO_LIST: b"[" + b" " * updates.MAX_LIST_BYTES + b"]"}),
        )


def test_what_is_installed_comes_from_the_kept_manifest(tmp_path, trusted):
    program = tmp_path / "opt"
    assert updates.installed(program) == {
        "version": updates.__version__,
        "prerelease": None,
        "by_installer": False,
    }
    installed_at(program, "0.1.0", prerelease=True)
    assert updates.installed(program) == {
        "version": "0.1.0",
        "prerelease": True,
        "by_installer": True,
    }
    # A manifest signed by another key is no record at all.
    (program / "current" / releases.SIGNATURE).write_bytes(Key().sign(b"x"))
    assert updates.installed(program)["by_installer"] is False


@pytest.fixture
def base(tmp_path):
    home = tmp_path / "home"
    initialise(home)
    return home


def test_a_check_writes_down_what_it_found_or_why_not(base, tmp_path, trusted):
    program = tmp_path / "opt"
    installed_at(program, "0.1.0")
    served = published(tmp_path, "0.2.0")
    served[REPO_LIST] = listing(("v0.2.0", False, False))
    found = updates.check(base, fetcher(served), program)
    assert found["newest"]["version"] == "0.2.0" and found["installed"] == "0.1.0"
    status = updates.status(base, program)
    assert status["newest"]["version"] == "0.2.0" and status["checked"] is not None
    assert status["problem"] is None and status["enabled"] is True
    assert updates.notice(base, program)["version"] == "0.2.0"
    assert (base / "updates" / "check.json").stat().st_mode & 0o777 == 0o600

    def broken(url, limit):
        raise PullError("the network is down")

    found = updates.check(base, broken, program)
    assert found["newest"] is None and "network is down" in found["problem"]
    assert updates.notice(base, program) is None
    assert "network is down" in updates.status(base, program)["problem"]


def test_a_check_is_due_once_a_day_unless_turned_off(base, tmp_path, trusted):
    now = datetime(2026, 11, 20, 12, tzinfo=UTC)
    assert updates.due(base, now), "never checked"
    served = {REPO_LIST: listing()}
    updates.check(base, fetcher(served), tmp_path / "opt")
    checked = datetime.fromisoformat(
        json.loads((base / "updates" / "check.json").read_text())["checked"]
    )
    assert not updates.due(base, checked + timedelta(hours=23))
    assert updates.due(base, checked + timedelta(hours=25))
    from checker.settings import change

    change(base, "updates.check", "off")
    assert not updates.due(base, checked + timedelta(days=30))
    assert updates.status(base, tmp_path / "opt")["enabled"] is False


def test_a_background_check_runs_once_at_a_time(base, tmp_path, trusted, monkeypatch):
    import threading

    started = threading.Event()
    release = threading.Event()
    seen = []

    def slow(home, fetch=None, program=None):
        seen.append(home)
        started.set()
        release.wait(5)

    monkeypatch.setattr(updates, "check", slow)
    assert updates.check_in_background(base)
    assert started.wait(5)
    assert not updates.check_in_background(base), "one at a time"
    release.set()
    for _ in range(100):
        if updates._lock.acquire(blocking=False):
            updates._lock.release()
            break
        threading.Event().wait(0.02)
    assert seen == [base]


def no_pip(command, **kwargs):
    Path(command[command.index("-d") + 1], "dep-1.0-py3-none-any.whl").write_bytes(b"dep")
    return subprocess.CompletedProcess(command, 0, "", "")


def test_preparing_downloads_checks_and_hands_over(base, tmp_path, trusted):
    program = tmp_path / "opt"
    installed_at(program, "0.1.0")
    served = published(tmp_path, "0.2.0")
    asked = []
    manifest = updates.prepare(
        base, "0.2.0", fetch=fetcher(served, asked), program=program, python="py", run=no_pip
    )
    assert manifest.version == "0.2.0"
    folder = base / "updates"
    assert (folder / "request").read_text() == "0.2.0\n"
    staged = folder / "incoming" / "0.2.0"
    assert sorted(p.name for p in staged.iterdir()) == sorted(
        [*manifest.files, releases.MANIFEST, releases.SIGNATURE, "wheels"]
    )
    assert (staged / "wheels" / "dep-1.0-py3-none-any.whl").read_bytes() == b"dep"
    assert asked[0].endswith("/v0.2.0/release.json"), "the manifest first"
    assert all(url.startswith(f"{updates.DOWNLOADS}/v0.2.0/") for url in asked)
    assert updates.status(base, program)["requested"] is True
    assert updates.status(base, program)["progress"]["state"] == "handed over"
    assert "ready" in updates.words_for(updates.status(base, program)["progress"])
    assert updates.cancel(base) and not updates.cancel(base)
    assert updates.status(base, program)["requested"] is False


def test_preparing_refuses_what_is_not_newer_or_not_asked_for(base, tmp_path, trusted):
    program = tmp_path / "opt"
    installed_at(program, "0.2.0")
    served = published(tmp_path, "0.2.0", "0.1.0", "0.3.0")
    for version, words in (("0.2.0", "isn't newer"), ("0.1.0", "isn't newer")):
        with pytest.raises(updates.UpdateError, match=words):
            updates.prepare(base, version, fetch=fetcher(served), program=program, run=no_pip)
        assert not (base / "updates" / "request").exists()
        assert not list((base / "updates" / "incoming").iterdir())
    with pytest.raises(updates.UpdateError, match="isn't published"):
        updates.prepare(base, "0.9.0", fetch=fetcher(served), program=program, run=no_pip)
    with pytest.raises(updates.UpdateError):
        updates.prepare(base, "../etc", fetch=fetcher(served), program=program, run=no_pip)
    assert updates.status(base, program)["progress"]["state"] == "failed"
    with pytest.raises(updates.UpdateError, match="say which"):
        updates.prepare(base, None, None, fetch=fetcher(served), program=program, run=no_pip)


def test_a_changed_file_or_a_pre_release_for_a_final_machine_is_refused(base, tmp_path, trusted):
    program = tmp_path / "opt"
    installed_at(program, "0.1.0")
    served = published(tmp_path, "0.2.0", "0.3.0", **{"0.3.0": {"prerelease": True}})
    served[f"{updates.DOWNLOADS}/v0.2.0/{releases.REQUIREMENTS}"] = b"evil==1 --hash=sha256:0\n"
    with pytest.raises(updates.UpdateError, match="requirements.lock"):
        updates.prepare(base, "0.2.0", fetch=fetcher(served), program=program, run=no_pip)
    with pytest.raises(updates.UpdateError, match="pre-release"):
        updates.prepare(base, "0.3.0", fetch=fetcher(served), program=program, run=no_pip)
    assert not list((base / "updates" / "incoming").iterdir())
    assert not (base / "updates" / "request").exists()


def test_a_release_copied_over_by_hand_takes_the_same_path(base, tmp_path, trusted):
    program = tmp_path / "opt"
    installed_at(program, "0.1.0")
    source = tmp_path / "copied"
    _release(source, "0.2.0")
    (source / "extra.txt").write_text("not in the manifest")
    manifest = updates.prepare(base, source=source, program=program, run=no_pip)
    assert manifest.version == "0.2.0"
    staged = base / "updates" / "incoming" / "0.2.0"
    assert not (staged / "extra.txt").exists(), "only what the manifest names"
    assert (base / "updates" / "request").exists()


def test_pip_s_failure_is_said_in_words(base, tmp_path, trusted):
    program = tmp_path / "opt"
    installed_at(program, "0.1.0")
    served = published(tmp_path, "0.2.0")

    def failing(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, "", "THESE PACKAGES DO NOT MATCH THE HASHES")

    with pytest.raises(updates.UpdateError, match="DO NOT MATCH"):
        updates.prepare(base, "0.2.0", fetch=fetcher(served), program=program, run=failing)
    assert not (base / "updates" / "request").exists()
