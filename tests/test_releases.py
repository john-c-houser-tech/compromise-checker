"""Signed releases (installation plan I2): the manifest, its signature, the files it lists, and the
checks made before a release is built. Keys here are throwaway ones."""

import copy
import importlib.util
import json
import re
import tomllib
from pathlib import Path

import pytest
from test_pack_trust import Key

from checker import __version__, releases
from checker.releases import (
    MANIFEST,
    REQUIREMENTS,
    SIGNATURE,
    ReleaseError,
    read_manifest,
    read_release,
    sha256_of,
    wheel_name,
)

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("release_script", ROOT / "scripts" / "release.py")
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)

VERSION = "1.2.3"
COMMIT = "a" * 40


def body(**changes) -> dict:
    whole = {
        "schema": 1,
        "version": VERSION,
        "commit": COMMIT,
        "prerelease": True,
        "security_fix": False,
        "files": {
            wheel_name(VERSION): {"sha256": "0" * 64, "size": 1},
            REQUIREMENTS: {"sha256": "1" * 64, "size": 2},
        },
    }
    whole.update(changes)
    return whole


def signed(key: Key, whole: dict) -> tuple[bytes, bytes]:
    data = json.dumps(whole).encode()
    return data, key.sign(data)


def public(key: Key, tmp_path: Path) -> list:
    return [releases.public_key(key.pub_file(tmp_path / "key.pub").read_text())]


def a_release(directory: Path, key: Key, **changes) -> None:
    directory.mkdir(exist_ok=True)
    (directory / wheel_name(VERSION)).write_bytes(b"the wheel")
    (directory / REQUIREMENTS).write_text("the list\n")
    script.write_manifest(directory, VERSION, COMMIT, True, False)
    data = (directory / MANIFEST).read_bytes()
    (directory / SIGNATURE).write_bytes(key.sign(data))


def test_a_good_manifest_is_read(tmp_path):
    key = Key()
    manifest = read_manifest(*signed(key, body()), public(key, tmp_path))
    assert (manifest.version, manifest.prerelease, manifest.security_fix) == (VERSION, True, False)
    assert manifest.commit == COMMIT


def test_another_key_or_a_changed_manifest_is_refused(tmp_path):
    key, other = Key(), Key()
    with pytest.raises(ReleaseError, match="isn't trusted"):
        read_manifest(*signed(other, body()), public(key, tmp_path))
    data, signature = signed(key, body())
    with pytest.raises(ReleaseError, match="doesn't match"):
        read_manifest(data.replace(b"1.2.3", b"9.9.9"), signature, public(key, tmp_path))


def test_a_pack_root_key_is_not_a_release_key():
    from checker.packs.trust import ROOT_KEYS

    assert not set(ROOT_KEYS) & set(releases.RELEASE_KEYS)


def test_with_no_release_key_nothing_is_trusted(monkeypatch):
    monkeypatch.setattr(releases, "RELEASE_KEYS", ())
    key = Key()
    with pytest.raises(ReleaseError, match="no release key"):
        read_manifest(*signed(key, body()))


def test_the_shipped_keys_can_be_read():
    assert all(key.key_id for key in releases.release_keys())


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": 2},
        {"schema": True},
        {"version": "1.2"},
        {"version": "1.2.3.dev0"},
        {"version": "01.2.3"},
        {"version": "1.2.3\n"},
        {"commit": "abc"},
        {"prerelease": "no"},
        {"prerelease": 0},
        {"security_fix": 1},
        {"extra": "unknown"},
        {"files": {}},
        {"files": {REQUIREMENTS: {"sha256": "1" * 64, "size": 2}}},
        {"files": {wheel_name(VERSION): {"sha256": "0" * 64, "size": 1}}},
    ],
)
def test_a_signed_manifest_that_is_wrong_is_still_refused(tmp_path, changes):
    key = Key()
    with pytest.raises(ReleaseError, match="can't be read"):
        read_manifest(*signed(key, body(**changes)), public(key, tmp_path))


@pytest.mark.parametrize("name", ["../evil", "/etc/passwd", "a/b", ".hidden", "bad\nname", ""])
def test_a_file_name_cannot_leave_the_release(tmp_path, name):
    key = Key()
    files = {**body()["files"], name: {"sha256": "2" * 64, "size": 3}}
    with pytest.raises(ReleaseError, match="plain file name"):
        read_manifest(*signed(key, body(files=files)), public(key, tmp_path))


@pytest.mark.parametrize(
    "entry",
    [
        {"sha256": "A" * 64, "size": 1},
        {"sha256": "0" * 63, "size": 1},
        {"sha256": "0" * 64, "size": -1},
    ],
)
def test_a_bad_hash_or_size_is_refused(tmp_path, entry):
    key = Key()
    files = copy.deepcopy(body()["files"])
    files[REQUIREMENTS] = entry
    with pytest.raises(ReleaseError, match="can't be read"):
        read_manifest(*signed(key, body(files=files)), public(key, tmp_path))


def test_a_manifest_that_is_not_json_or_is_too_large_is_refused(tmp_path):
    key = Key()
    data = b"not json"
    with pytest.raises(ReleaseError, match="can't be read"):
        read_manifest(data, key.sign(data), public(key, tmp_path))
    data = b" " * (releases.MAX_MANIFEST_BYTES + 1)
    with pytest.raises(ReleaseError, match="too large"):
        read_manifest(data, key.sign(data), public(key, tmp_path))


def test_a_whole_release_checks_out(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    assert read_release(tmp_path / "r", public(key, tmp_path)).version == VERSION


@pytest.mark.parametrize("name", [wheel_name(VERSION), REQUIREMENTS])
def test_a_changed_file_is_refused_even_at_the_same_size(tmp_path, name):
    key = Key()
    a_release(tmp_path / "r", key)
    path = tmp_path / "r" / name
    path.write_bytes(b"x" * path.stat().st_size)
    with pytest.raises(ReleaseError, match="wrong hash"):
        read_release(tmp_path / "r", public(key, tmp_path))
    path.write_bytes(b"x" * (path.stat().st_size + 1))
    with pytest.raises(ReleaseError, match="wrong size"):
        read_release(tmp_path / "r", public(key, tmp_path))


def test_a_missing_or_linked_file_is_refused(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    path = tmp_path / "r" / REQUIREMENTS
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(path.read_bytes())
    path.unlink()
    with pytest.raises(ReleaseError, match="missing"):
        read_release(tmp_path / "r", public(key, tmp_path))
    path.symlink_to(elsewhere)
    with pytest.raises(ReleaseError, match="missing, or isn't a plain file"):
        read_release(tmp_path / "r", public(key, tmp_path))


def test_a_missing_signature_is_refused(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    (tmp_path / "r" / SIGNATURE).unlink()
    with pytest.raises(ReleaseError, match="can't read the release"):
        read_release(tmp_path / "r", public(key, tmp_path))


def test_sha256_of_a_known_file(tmp_path):
    path = tmp_path / "f"
    path.write_bytes(b"abc")
    assert sha256_of(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# --- Before a build ----------------------------------------------------------------------------


def test_a_real_release_needs_a_final_version_and_a_clean_tree():
    script.check_ready("0.1.0", "0.1.0", "", trial=False)
    with pytest.raises(script.Refused, match="isn't a release version"):
        script.check_ready("0.1.0.dev0", "0.1.0.dev0", "", trial=False)
    with pytest.raises(script.Refused, match="uncommitted"):
        script.check_ready("0.1.0", "0.1.0", " M checker/cli.py", trial=False)
    with pytest.raises(script.Refused, match="the collector says"):
        script.check_ready("0.1.0", "0.1.1", "", trial=False)


def test_a_trial_may_be_of_anything_but_the_versions_must_still_agree():
    script.check_ready("0.1.0.dev0", "0.1.0.dev0", " M checker/cli.py", trial=True)
    with pytest.raises(script.Refused, match="the collector says"):
        script.check_ready("0.1.0.dev0", "0.1.0", "", trial=True)


def test_the_tool_and_collector_agree_today():
    text = (ROOT / "checker" / "collector" / "collector.py").read_text(encoding="utf-8")
    assert script.collector_version(text) == __version__


def test_a_wheel_missing_what_an_install_needs_is_refused(tmp_path):
    import zipfile

    wheel = tmp_path / wheel_name(VERSION)
    with zipfile.ZipFile(wheel, "w") as package:
        package.writestr("checker/__init__.py", "")
    with pytest.raises(script.Refused, match="doesn't hold"):
        script.check_wheel(wheel, VERSION)
    with pytest.raises(script.Refused, match="is called"):
        script.check_wheel(wheel, "9.9.9")


def test_a_signature_or_old_manifest_is_not_listed_in_a_new_manifest(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    path = script.write_manifest(tmp_path / "r", VERSION, COMMIT, True, False)
    assert set(json.loads(path.read_text())["files"]) == {wheel_name(VERSION), REQUIREMENTS}


# --- The lists -------------------------------------------------------------------------------


def _pinned(path: Path) -> dict[str, list[str]]:
    """The list as pip reads it: a name, an exact version, and its hashes."""
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    found = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name = re.match(r"([A-Za-z0-9._-]+)==[A-Za-z0-9.!+_-]+", line)
        assert name, f"not pinned to one version: {line[:60]}"
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", line)
        assert hashes, f"no hash for {name.group(1)}"
        found[name.group(1).lower().replace("_", "-")] = hashes
    return found


@pytest.mark.parametrize("path", [script.LOCK, script.BUILD_LOCK])
def test_every_entry_in_the_lists_is_pinned_with_a_hash(path):
    assert _pinned(path)


def test_the_list_holds_everything_the_extras_ask_for():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    wanted = list(project["dependencies"])
    for extra in script.EXTRAS:
        wanted += project["optional-dependencies"][extra]
    locked = _pinned(script.LOCK)
    for requirement in wanted:
        name = re.match(r"[A-Za-z0-9._-]+", requirement).group(0).lower().replace("_", "-")
        assert name in locked, f"{name} isn't in the list: run scripts/release.py lock"


def test_the_list_needs_no_developer_tools():
    locked = _pinned(script.LOCK)
    assert not {"pytest", "ruff", "playwright", "keyring"} & set(locked)


def test_the_build_tool_is_pinned():
    assert "setuptools" in _pinned(script.BUILD_LOCK)
