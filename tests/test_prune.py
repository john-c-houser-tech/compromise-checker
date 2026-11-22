"""Pruning the verifier's caches (issue #217): checker/verify/prune.py."""

from __future__ import annotations

import os
import time

import pytest

from checker.verify import MISSING_FOR, deb, prune

DAY = 24 * 3600
NOW = 2_000_000_000.0


@pytest.fixture(autouse=True)
def _fresh_process():
    prune._last.clear()
    yield
    prune._last.clear()


def _file(folder, name, age, data=b"x"):
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / name
    path.write_bytes(data)
    os.utime(path, (NOW - age, NOW - age))
    return path


def _lists(tmp_path):
    return tmp_path / "cache" / "signed-lists"


def _results(tmp_path):
    return tmp_path / "cache" / "official-files"


def test_signed_lists_unused_for_30_days_are_removed(tmp_path):
    old_index = _file(_lists(tmp_path), "index-" + "a" * 64, 31 * DAY)
    old_release = _file(_lists(tmp_path), "inrelease-" + "b" * 40, 31 * DAY)
    recent = _file(_lists(tmp_path), "index-" + "c" * 64, 29 * DAY)
    prune.prune_caches(tmp_path, now=NOW)
    assert not old_index.exists() and not old_release.exists()
    assert recent.exists()


def test_missing_markers_past_their_day_and_left_over_parts_are_removed(tmp_path):
    stale = _file(_results(tmp_path), "d" * 64 + ".missing", MISSING_FOR + 60)
    live = _file(_results(tmp_path), "e" * 64 + ".missing", MISSING_FOR - 60)
    result = _file(_results(tmp_path), "f" * 64 + ".json", 400 * DAY)  # verified: kept
    old_part = _file(_results(tmp_path), ".part-abc", 2 * DAY)
    writing = _file(_lists(tmp_path), ".part-def", 60)  # another run writing it now
    left = _file(_lists(tmp_path), ".part-ghi", 2 * DAY)
    prune.prune_caches(tmp_path, now=NOW)
    assert not stale.exists() and not old_part.exists() and not left.exists()
    assert live.exists() and result.exists() and writing.exists()


def test_other_names_links_and_folders_are_left_alone(tmp_path):
    folder = _lists(tmp_path)
    other = _file(folder, "notes.txt", 400 * DAY)
    target = _file(tmp_path / "elsewhere", "index-target", 400 * DAY)
    (folder / ("index-" + "1" * 64)).symlink_to(target)
    (folder / ("index-" + "2" * 64)).mkdir()
    os.utime(folder / ("index-" + "2" * 64), (NOW - 400 * DAY,) * 2)
    prune.prune_caches(tmp_path, now=NOW)
    assert other.exists() and target.exists()
    assert (folder / ("index-" + "1" * 64)).is_symlink()
    assert (folder / ("index-" + "2" * 64)).is_dir()


def test_a_linked_or_shared_folder_isnt_pruned(tmp_path):
    real = tmp_path / "real"
    old = _file(real, "index-" + "a" * 64, 400 * DAY)
    (tmp_path / "cache").mkdir()
    _lists(tmp_path).symlink_to(real)
    prune.prune_caches(tmp_path, now=NOW)
    assert old.exists()  # never through a link
    shared = tmp_path / "shared"
    kept = _file(shared, "index-" + "a" * 64, 400 * DAY)
    shared.chmod(0o777)
    assert prune.prune(shared, NOW, lambda name: True, DAY) == 0
    assert kept.exists()


def test_a_missing_cache_is_fine(tmp_path):
    prune.prune_caches(tmp_path / "nowhere", now=NOW)


def test_pruned_at_most_once_a_day_in_a_process(tmp_path):
    prune.prune_caches(tmp_path, now=NOW)
    later = _file(_lists(tmp_path), "index-" + "a" * 64, 31 * DAY + 3600)
    prune.prune_caches(tmp_path, now=NOW + 3600)  # the next host in the same run
    assert later.exists()
    prune.prune_caches(tmp_path, now=NOW + DAY + 1)
    assert not later.exists()


def test_a_read_keeps_a_list_another_30_days_but_not_the_archive_s_release(tmp_path):
    folder = _lists(tmp_path)
    then = time.time() - 29 * DAY  # _kept reads the real clock
    index = _file(folder, "index-" + "a" * 64, 0)
    archive = _file(folder, "inrelease-" + "b" * 40, 0)
    for path in (index, archive):
        os.utime(path, (then, then))
    ubuntu = deb.Ubuntu(None, lists_dir=folder)
    assert ubuntu._kept(index.name, None, 100) == b"x"  # by hash, or a dated copy
    assert ubuntu._kept(archive.name, 3600, 100) is None  # the archive's: too old to use
    assert time.time() - index.stat().st_mtime < 60
    assert archive.stat().st_mtime == then  # its time is its age


def test_the_verifier_prunes_when_it_is_built(tmp_path):
    from checker.evidence import Verify
    from checker.official import verifier_for

    old = _file(_lists(tmp_path), "index-" + "a" * 64, 0)
    os.utime(old, (time.time() - 31 * DAY,) * 2)
    assert verifier_for(Verify(), tmp_path) is not None
    assert not old.exists()
    assert verifier_for(Verify(enabled=False), tmp_path / "off") is None
