"""Signed releases (installation plan I2): the manifest, its signature, the files it lists, and the
checks made before a release is built. Keys here are throwaway ones."""

import copy
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import tomllib
import zipfile
from pathlib import Path

import pytest
import yaml
from test_pack_trust import Key

from checker import __version__, releases
from checker.releases import (
    INSTALLER,
    MANIFEST,
    REQUIREMENTS,
    SIGNATURE,
    ReleaseError,
    read_manifest,
    read_release,
    sha256_of,
    stage_release,
    version_key,
    wheel_name,
)

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("release_script", ROOT / "scripts" / "release.py")
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)

VERSION = "1.2.3"
COMMIT = "a" * 40
PUBLISHED = "2026-11-02"


def body(**changes) -> dict:
    whole = {
        "schema": 1,
        "version": VERSION,
        "commit": COMMIT,
        "published": PUBLISHED,
        "prerelease": True,
        "security_fix": False,
        "files": {
            wheel_name(VERSION): {"sha256": "0" * 64, "size": 1},
            REQUIREMENTS: {"sha256": "1" * 64, "size": 2},
            INSTALLER: {"sha256": "3" * 64, "size": 3},
        },
    }
    whole.update(changes)
    return whole


def signed(key: Key, whole: dict) -> tuple[bytes, bytes]:
    data = json.dumps(whole).encode()
    return data, key.sign(data)


def public(key: Key, tmp_path: Path) -> list:
    return [releases.public_key(key.pub_file(tmp_path / "key.pub").read_text())]


def a_release(directory: Path, key: Key, version: str = VERSION) -> Path:
    directory.mkdir(exist_ok=True)
    (directory / wheel_name(version)).write_bytes(b"the wheel")
    (directory / REQUIREMENTS).write_text("the list\n")
    (directory / INSTALLER).write_text("the installer\n")
    script.write_manifest(directory, version, COMMIT, True, False, PUBLISHED)
    (directory / SIGNATURE).write_bytes(key.sign((directory / MANIFEST).read_bytes()))
    return directory


def test_a_good_manifest_is_read(tmp_path):
    key = Key()
    manifest = read_manifest(*signed(key, body()), public(key, tmp_path))
    assert (manifest.version, manifest.prerelease, manifest.security_fix) == (VERSION, True, False)
    assert (manifest.commit, manifest.published) == (COMMIT, PUBLISHED)


def test_another_key_or_a_changed_manifest_is_refused(tmp_path):
    key, other = Key(), Key()
    with pytest.raises(ReleaseError, match="isn't trusted"):
        read_manifest(*signed(other, body()), public(key, tmp_path))
    data, signature = signed(key, body())
    with pytest.raises(ReleaseError, match="doesn't match"):
        read_manifest(data.replace(b"1.2.3", b"9.9.9"), signature, public(key, tmp_path))


def test_no_key_that_signs_packs_is_a_release_key():
    from checker.packs.trust import ROOT_KEYS, SHIPPED

    listed = yaml.safe_load((SHIPPED / "keys.yaml").read_text(encoding="utf-8"))
    pack_keys = {entry["public_key"] for entry in listed["pack_keys"]}
    assert pack_keys, "the shipped key list should name pack keys"
    assert not (set(ROOT_KEYS) | pack_keys) & set(releases.RELEASE_KEYS)


def test_with_no_release_key_nothing_is_trusted(monkeypatch):
    monkeypatch.setattr(releases, "RELEASE_KEYS", ())
    key = Key()
    with pytest.raises(ReleaseError, match="no release key"):
        read_manifest(*signed(key, body()))


def test_the_release_key_is_in_place():
    assert [key.key_id for key in releases.release_keys()] == ["341D1ADD02E941AB"]


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": 0},
        {"schema": 2},
        {"schema": True},
        {"version": "1.2"},
        {"version": "1.2.3.dev0"},
        {"version": "01.2.3"},
        {"version": "1.2.3\n"},
        {"commit": "abc"},
        {"published": "soon"},
        {"published": "2026-13-45"},
        {"published": "20261102"},
        {"prerelease": "no"},
        {"prerelease": 0},
        {"security_fix": 1},
        {"extra": "unknown"},
        {"files": {}},
        {"files": {REQUIREMENTS: {"sha256": "1" * 64, "size": 2}}},
        {"files": {wheel_name(VERSION): {"sha256": "0" * 64, "size": 1}}},
        {
            "files": {
                wheel_name(VERSION): {"sha256": "0" * 64, "size": 1},
                REQUIREMENTS: {"sha256": "1" * 64, "size": 2},
            }
        },
    ],
)
def test_a_signed_manifest_that_is_wrong_is_still_refused(tmp_path, changes):
    key = Key()
    with pytest.raises(ReleaseError, match="can't be read"):
        read_manifest(*signed(key, body(**changes)), public(key, tmp_path))


@pytest.mark.parametrize(
    "name", ["../evil", "/etc/passwd", "a/b", ".hidden", "bad\nname", "", MANIFEST, SIGNATURE]
)
def test_a_file_name_cannot_leave_the_release_or_replace_what_vouches_for_it(tmp_path, name):
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


@pytest.mark.parametrize("name", [MANIFEST, SIGNATURE])
def test_what_vouches_for_a_release_must_be_a_plain_file_too(tmp_path, name):
    key = Key()
    a_release(tmp_path / "r", key)
    path = tmp_path / "r" / name
    elsewhere = tmp_path / "elsewhere"
    path.rename(elsewhere)
    path.symlink_to(elsewhere)
    with pytest.raises(ReleaseError, match="isn't a plain file"):
        read_release(tmp_path / "r", public(key, tmp_path))
    path.unlink()
    os.mkfifo(path)  # would hang for ever if it were simply opened and read
    with pytest.raises(ReleaseError, match="isn't a plain file"):
        read_release(tmp_path / "r", public(key, tmp_path))


def test_a_huge_signature_is_not_read_whole(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    (tmp_path / "r" / SIGNATURE).write_bytes(b"x" * 100_000)
    with pytest.raises(ReleaseError, match="too large"):
        read_release(tmp_path / "r", public(key, tmp_path))


def test_a_missing_signature_is_refused(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    (tmp_path / "r" / SIGNATURE).unlink()
    with pytest.raises(ReleaseError, match="missing"):
        read_release(tmp_path / "r", public(key, tmp_path))


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
def test_an_unreadable_file_is_a_refusal_and_not_a_crash(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    (tmp_path / "r" / REQUIREMENTS).chmod(0)
    with pytest.raises(ReleaseError, match="missing, or isn't a plain file"):
        read_release(tmp_path / "r", public(key, tmp_path))


def test_sha256_of_a_known_file(tmp_path):
    path = tmp_path / "f"
    path.write_bytes(b"abc")
    assert sha256_of(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# --- Old releases ------------------------------------------------------------------------------


def test_versions_compare_as_numbers():
    assert version_key("0.10.0") > version_key("0.9.0")
    with pytest.raises(ReleaseError, match="isn't a version"):
        version_key("0.1.0.dev0")


def test_an_old_or_equal_release_is_refused_when_the_caller_says_so(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    keys = public(key, tmp_path)
    assert read_release(tmp_path / "r", keys, newer_than="1.2.2").version == VERSION
    assert read_release(tmp_path / "r", keys, newer_than="1.1.10").version == VERSION
    for installed in (VERSION, "1.2.4", "1.10.0"):
        with pytest.raises(ReleaseError, match="isn't newer"):
            read_release(tmp_path / "r", keys, newer_than=installed)


def test_a_different_version_from_the_one_asked_for_is_refused(tmp_path):
    key = Key()
    a_release(tmp_path / "r", key)
    keys = public(key, tmp_path)
    assert read_release(tmp_path / "r", keys, expected_version=VERSION).version == VERSION
    with pytest.raises(ReleaseError, match="not 9.9.9"):
        read_release(tmp_path / "r", keys, expected_version="9.9.9")


# --- Staging -----------------------------------------------------------------------------------


def test_staging_gives_a_private_copy_of_exactly_what_was_checked(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    keys = public(key, tmp_path)
    target = tmp_path / "stage"
    assert stage_release(source, target, keys).version == VERSION
    assert (target.stat().st_mode & 0o777) == 0o700
    (source / wheel_name(VERSION)).write_bytes(b"swapped afterwards")
    assert read_release(target, keys).version == VERSION
    assert (target / wheel_name(VERSION)).read_bytes() == b"the wheel"


def test_staging_a_bad_release_leaves_nothing(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    (source / REQUIREMENTS).write_text("the LIST\n")
    target = tmp_path / "stage"
    with pytest.raises(ReleaseError, match="wrong hash"):
        stage_release(source, target, public(key, tmp_path))
    assert not target.exists()


def test_staging_a_refused_release_makes_nothing(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    target = tmp_path / "stage"
    with pytest.raises(ReleaseError, match="isn't newer"):
        stage_release(source, target, public(key, tmp_path), newer_than=VERSION)
    assert not target.exists()


def test_staging_leaves_nothing_beside_the_target_when_refused(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    (source / REQUIREMENTS).write_text("the LIST\n")
    parent = tmp_path / "parent"
    parent.mkdir()
    with pytest.raises(ReleaseError):
        stage_release(source, parent / "stage", public(key, tmp_path))
    assert list(parent.iterdir()) == []


def test_a_stop_part_way_never_leaves_part_of_a_release_at_the_target(tmp_path, monkeypatch):
    key = Key()
    source = a_release(tmp_path / "r", key)
    target = tmp_path / "stage"

    def stopped(*_):
        raise SystemExit("stopped")

    monkeypatch.setattr(releases.os, "rename", stopped)
    with pytest.raises(SystemExit):
        stage_release(source, target, public(key, tmp_path))
    assert not target.exists()


def test_a_full_disk_is_not_reported_as_a_bad_source(tmp_path, monkeypatch):
    key = Key()
    source = a_release(tmp_path / "r", key)

    def full(*_):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(releases.os, "fsync", full)
    with pytest.raises(ReleaseError, match="can't copy the release"):
        stage_release(source, tmp_path / "stage", public(key, tmp_path))
    assert not (tmp_path / "stage").exists()


def test_a_failure_after_the_move_leaves_nothing_in_the_way_of_trying_again(tmp_path, monkeypatch):
    key = Key()
    source = a_release(tmp_path / "r", key)
    target = tmp_path / "stage"
    keys = public(key, tmp_path)
    real_sync = releases._sync

    def failing(path):
        if path == target.parent:
            raise OSError(5, "Input/output error")
        real_sync(path)

    monkeypatch.setattr(releases, "_sync", failing)
    with pytest.raises(ReleaseError, match="can't copy the release"):
        stage_release(source, target, keys)
    assert not target.exists()
    monkeypatch.setattr(releases, "_sync", real_sync)
    assert stage_release(source, target, keys).version == VERSION


def test_staging_will_not_use_a_link_that_exists(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    target = tmp_path / "stage"
    target.symlink_to(tmp_path / "nowhere")
    with pytest.raises(ReleaseError, match="already exists"):
        stage_release(source, target, public(key, tmp_path))
    assert target.is_symlink()


def test_staging_will_not_use_a_folder_that_exists(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    target = tmp_path / "stage"
    target.mkdir()
    (target / "planted").write_text("x")
    with pytest.raises(ReleaseError, match="already exists"):
        stage_release(source, target, public(key, tmp_path))
    assert (target / "planted").read_text() == "x"


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


def test_a_real_release_is_of_the_tagged_commit_on_main():
    script.check_source("0.1.0", COMMIT, COMMIT, COMMIT)
    with pytest.raises(script.Refused, match="no tag"):
        script.check_source("0.1.0", COMMIT, None, COMMIT)
    with pytest.raises(script.Refused, match="v0.1.0 is commit"):
        script.check_source("0.1.0", COMMIT, "b" * 40, COMMIT)
    with pytest.raises(script.Refused, match="origin/main is"):
        script.check_source("0.1.0", COMMIT, COMMIT, "b" * 40)
    with pytest.raises(script.Refused, match="origin/main is"):
        script.check_source("0.1.0", COMMIT, COMMIT, None)


def test_the_newest_commit_on_main_comes_from_github_and_not_the_last_fetch(monkeypatch):
    asked = []

    def git(*arguments):
        asked.append(arguments)
        return f"{COMMIT}\trefs/heads/main"

    monkeypatch.setattr(script, "_git", git)
    assert script._main_tip() == COMMIT
    assert asked == [("ls-remote", "origin", "refs/heads/main")]


def test_if_github_cannot_be_asked_nothing_is_built(monkeypatch):
    def git(*_):
        raise script.Refused("git ls-remote failed")

    monkeypatch.setattr(script, "_git", git)
    with pytest.raises(script.Refused, match="ls-remote"):
        script._main_tip()
    monkeypatch.setattr(script, "_git", lambda *_: "")
    assert script._main_tip() is None
    with pytest.raises(script.Refused, match="origin/main is None"):
        script.check_source("0.1.0", COMMIT, COMMIT, script._main_tip())


def test_a_real_release_needs_a_key_to_ship(monkeypatch):
    monkeypatch.setattr(releases, "RELEASE_KEYS", ())
    monkeypatch.setattr(script, "release_keys", releases.release_keys)
    with pytest.raises(script.Refused, match="empty"):
        script.check_keys()
    monkeypatch.setattr(releases, "RELEASE_KEYS", ("not a key",))
    with pytest.raises(script.Refused, match="can't be read"):
        script.check_keys()
    monkeypatch.setattr(releases, "RELEASE_KEYS", (Key().line,))
    script.check_keys()


def test_the_tool_and_collector_agree_today():
    text = (ROOT / "checker" / "collector" / "collector.py").read_text(encoding="utf-8")
    assert script.collector_version(text) == __version__


def _source_and_wheel(tmp_path: Path, files: dict[str, bytes]) -> tuple[dict, Path]:
    source = {"checker/a.py": b"a", "checker/b.css": b"b"}
    wheel = tmp_path / wheel_name(VERSION)
    with zipfile.ZipFile(wheel, "w") as package:
        for name, data in files.items():
            package.writestr(name, data)
    return source, wheel


DESCRIPTION = {f"checker-{VERSION}.dist-info/METADATA": b"m"}


def test_a_wheel_matching_the_commit_is_accepted(tmp_path):
    files = {"checker/a.py": b"a", "checker/b.css": b"b", **DESCRIPTION}
    source, wheel = _source_and_wheel(tmp_path, files)
    script.check_wheel(wheel, VERSION, source)


@pytest.mark.parametrize(
    ("files", "why"),
    [
        ({"checker/a.py": b"a", **DESCRIPTION}, "doesn't hold checker/b.css"),
        (
            {"checker/a.py": b"a", "checker/b.css": b"b", "checker/c.py": b"c", **DESCRIPTION},
            "doesn't: checker/c.py",
        ),
        (
            {"checker/a.py": b"a", "checker/b.css": b"b", "other.py": b"c", **DESCRIPTION},
            "doesn't: other.py",
        ),
        ({"checker/a.py": b"X", "checker/b.css": b"b", **DESCRIPTION}, "differs from the commit"),
        ({"checker/a.py": b"a", "checker/b.css": b"b"}, "no package description"),
    ],
)
def test_a_wheel_that_is_not_the_commit_is_refused(tmp_path, files, why):
    source, wheel = _source_and_wheel(tmp_path, files)
    with pytest.raises(script.Refused, match=why):
        script.check_wheel(wheel, VERSION, source)


def test_a_wheel_of_the_wrong_name_is_refused(tmp_path):
    source, wheel = _source_and_wheel(tmp_path, DESCRIPTION)
    with pytest.raises(script.Refused, match="is called"):
        script.check_wheel(wheel, "9.9.9", source)


def test_a_manifest_does_not_list_itself_or_its_signature(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    path = script.write_manifest(source, VERSION, COMMIT, True, False, PUBLISHED)
    listed = set(json.loads(path.read_text())["files"])
    assert listed == {wheel_name(VERSION), REQUIREMENTS, INSTALLER}


def test_the_installer_is_told_its_version_once():
    source = (ROOT / "release" / "install.py").read_bytes()
    assert b'VERSION = "1.2.3"' in script.installer_for(source, "1.2.3")
    assert b"@VERSION@" not in script.installer_for(source, "1.2.3")
    with pytest.raises(script.Refused, match="one place"):
        script.installer_for(b"no such line", "1.2.3")


def test_a_signed_trial_is_still_never_accepted(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    script.write_manifest(source, VERSION, COMMIT, True, False, PUBLISHED, trial=True)
    (source / SIGNATURE).write_bytes(key.sign((source / MANIFEST).read_bytes()))
    with pytest.raises(ReleaseError, match="format 0"):
        read_release(source, public(key, tmp_path))


def test_a_trial_never_touches_a_signed_release(tmp_path):
    release = tmp_path / f"release-{VERSION}"
    release.mkdir()
    (release / SIGNATURE).write_text("signed")
    trial = script.clear_way(tmp_path, VERSION, trial=True)
    assert trial.name == f"trial-{VERSION}"
    trial.mkdir()
    (trial / "old").write_text("x")
    assert not script.clear_way(tmp_path, VERSION, trial=True).exists()
    assert (release / SIGNATURE).read_text() == "signed"


def test_a_real_build_will_not_replace_a_release(tmp_path):
    (tmp_path / f"release-{VERSION}").mkdir()
    with pytest.raises(script.Refused, match="already exists"):
        script.clear_way(tmp_path, VERSION, trial=False)


def test_a_build_gets_none_of_the_maintainers_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/planted")
    monkeypatch.setenv("PIP_INDEX_URL", "https://planted.example")
    env = script._clean_env(tmp_path, "UTC", "1")
    assert "PYTHONPATH" not in env
    assert not [name for name in env if name.startswith(("PIP_", "DIST_"))]
    assert env["HOME"] == str(tmp_path)


def test_verify_can_check_against_a_key_the_commit_no_longer_lists(tmp_path, capsys):
    old, _new = Key(), Key()
    source = a_release(tmp_path / "r", old)
    assert script.verify(source, old.pub_file(tmp_path / "old.pub")) is None
    assert "--prerelease" in capsys.readouterr().out


def test_the_publish_command_matches_the_release_and_names_each_file(tmp_path):
    key = Key()
    data, signature = signed(key, body())
    manifest = read_manifest(data, signature, public(key, tmp_path))
    command = script.publish_command(Path("d"), manifest)
    assert "--prerelease" in command
    assert not command.endswith("*")
    for name in (wheel_name(VERSION), REQUIREMENTS, INSTALLER, MANIFEST, SIGNATURE):
        assert f"d/{name}" in command
    final = read_manifest(*signed(key, body(prerelease=False)), public(key, tmp_path))
    assert "--prerelease" not in script.publish_command(Path("d"), final)


def test_the_publish_command_survives_a_space_in_the_folder_name(tmp_path):
    key = Key()
    manifest = read_manifest(*signed(key, body()), public(key, tmp_path))
    command = script.publish_command(Path("/tmp/release files"), manifest)
    assert f"/tmp/release files/{MANIFEST}" in shlex.split(command)


def test_the_pasted_line_pins_the_installer_and_shuts_out_what_is_beside_it(tmp_path):
    key = Key()
    manifest = read_manifest(*signed(key, body()), public(key, tmp_path))
    line = script.pasted_line(manifest, "a" * 64)
    assert f'/v{VERSION}/{INSTALLER} -o "$d/{INSTALLER}"' in line
    assert f'"{"a" * 64}  $d/{INSTALLER}" | sha256sum -c -' in line
    assert f'sudo python3 -I "$d/{INSTALLER}"' in line
    assert line.index("sha256sum") < line.index("sudo")


def _pasted_run(tmp_path, content: bytes, wanted_hash: str, installer_exit: int = 0):
    """The line itself, in a real shell, with stand-ins for what reaches the network and root."""
    key = Key()
    manifest = read_manifest(*signed(key, body()), public(key, tmp_path))
    tools = tmp_path / "tools"
    tools.mkdir()
    payload = tmp_path / "payload"
    payload.write_bytes(content)
    ran = tmp_path / "sudo-ran"
    (tools / "curl").write_text(f'#!/bin/sh\nfor a; do t="$a"; done\ncp {payload} "$t"\n')
    (tools / "sudo").write_text(f'#!/bin/sh\necho "$@" > {ran}\nexit {installer_exit}\n')
    (tools / "curl").chmod(0o755)
    (tools / "sudo").chmod(0o755)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    done = subprocess.run(
        ["/bin/bash", "-c", script.pasted_line(manifest, wanted_hash)],
        env={"PATH": f"{tools}:/usr/bin:/bin", "TMPDIR": str(scratch)},
        capture_output=True,
        text=True,
        check=False,
    )
    return done, ran, scratch


def test_the_pasted_line_runs_the_installer_and_cleans_up(tmp_path):
    good = hashlib.sha256(b"the installer").hexdigest()
    done, ran, scratch = _pasted_run(tmp_path, b"the installer", good)
    assert done.returncode == 0, done.stderr
    assert ran.read_text().startswith("python3 -I ")
    assert list(scratch.iterdir()) == []


def test_the_pasted_line_stops_at_a_bad_hash_and_says_so(tmp_path):
    good = hashlib.sha256(b"the installer").hexdigest()
    done, ran, scratch = _pasted_run(tmp_path, b"something else", good)
    assert done.returncode != 0
    assert not ran.exists()
    assert list(scratch.iterdir()) == []


def test_the_pasted_line_passes_on_the_installers_result(tmp_path):
    good = hashlib.sha256(b"the installer").hexdigest()
    done, _, scratch = _pasted_run(tmp_path, b"the installer", good, installer_exit=23)
    assert done.returncode == 23
    assert list(scratch.iterdir()) == []


def test_verify_refuses_a_folder_holding_anything_else(tmp_path):
    key = Key()
    source = a_release(tmp_path / "r", key)
    (source / "stray.key").write_text("x")
    with pytest.raises(script.Refused, match=r"stray\.key"):
        script.verify(source, key.pub_file(tmp_path / "key.pub"))


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


def _commands(monkeypatch, tmp_path) -> list[list[str]]:
    seen = []

    class Done:
        returncode = 0
        stderr = ""

    def run(command, **_):
        seen.append(command)
        return Done()

    monkeypatch.setattr(script.subprocess, "run", run)
    monkeypatch.setattr(script, "LOCK", tmp_path / "release" / "requirements.lock")
    monkeypatch.setattr(script, "BUILD_LOCK", tmp_path / "release" / "build.lock")
    monkeypatch.setattr(script, "ROOT", tmp_path)
    return seen


def test_refreshing_the_lists_really_moves_old_pins(monkeypatch, tmp_path):
    seen = _commands(monkeypatch, tmp_path)
    (tmp_path / "pyproject.toml").write_text('[build-system]\nrequires = ["setuptools>=80"]\n')
    script.lock()
    assert len(seen) == 2
    assert all("--upgrade" in command for command in seen)


def test_one_package_can_move_alone(monkeypatch, tmp_path):
    seen = _commands(monkeypatch, tmp_path)
    script.lock(("django",))
    assert len(seen) == 1
    assert "--upgrade" not in seen[0]
    assert seen[0][seen[0].index("--upgrade-package") + 1] == "django"


def test_checking_the_lists_moves_nothing_it_does_not_have_to(monkeypatch, tmp_path):
    seen = _commands(monkeypatch, tmp_path)
    script.LOCK.parent.mkdir()
    script.LOCK.write_text("the list\n")
    script.BUILD_LOCK.write_text("the tool\n")
    (tmp_path / "pyproject.toml").write_text('[build-system]\nrequires = ["setuptools>=80"]\n')
    script.check_lock()
    assert len(seen) == 2
    assert not {"--upgrade", "--upgrade-package"} & {part for one in seen for part in one}


ONE_PIN = "pyyaml==6.0.3 ; python_version >= '3.12' \\\n    --hash=sha256:{}\n"


def test_a_new_file_for_a_pinned_version_is_not_a_change():
    assert script.pins(ONE_PIN.format("a" * 64)) == script.pins(ONE_PIN.format("b" * 64))


def test_a_new_version_or_marker_is_a_change():
    assert script.pins(ONE_PIN.format("a" * 64)) != script.pins(
        ONE_PIN.format("a" * 64).replace("6.0.3", "6.0.4")
    )
    assert script.pins(ONE_PIN.format("a" * 64)) != script.pins(
        ONE_PIN.format("a" * 64).replace("3.12", "3.13")
    )


def test_the_build_tool_comes_from_pyproject():
    assert "setuptools" in script._build_requirements()
