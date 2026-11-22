"""Removing what the verifier's caches no longer use (issue #217).

`cache/signed-lists` gains a Packages index each time Ubuntu's archive
changes (several times a day for -security and -updates) and an
InRelease for each dated copy asked about; nothing else ever removed
them. `cache/official-files` keeps `.missing` markers that stop counting
after a day. Both folders can hold `.part-` files a crash left behind.

Rules, applied at most once a day for each folder in a process:
- signed lists not used for `UNUSED_FOR` (a read resets a list's time,
  `deb.Ubuntu._kept`; the archive's own InRelease isn't reset, since its
  time is its age, and it counts as stale after hours anyway);
- `.missing` markers past `MISSING_FOR`;
- `.part-` files older than `PART_FOR`.

Only regular files directly in the folder, looked at and removed through
the folder's own descriptor, no link followed. A folder that isn't this
user's, or a file that can't be removed, is left alone: the worst a
leftover costs is disk, and the worst a removed list costs is a download.
Verified results (`.json`) are kept; they are small, and they let an
unchanged server be checked without a download.
"""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

UNUSED_FOR = 30 * 24 * 3600  # seconds a signed list is kept unused
PART_FOR = 24 * 3600  # seconds before a half-written file counts as left behind
EVERY = 24 * 3600  # seconds between prunings of one folder in a process

_last: dict[str, float] = {}  # folder -> when this process last pruned it


def prune_caches(home: Path, now: float | None = None) -> None:
    """Prune the verifier's caches under `home` (CHECKER_HOME), at most
    once a day for each folder in this process."""
    from checker.verify import MISSING_FOR

    now = time.time() if now is None else now
    cache = home / "cache"
    _once(
        cache / "signed-lists",
        now,
        lambda name: name.startswith(("index-", "inrelease-")),
        UNUSED_FOR,
    )
    _once(cache / "official-files", now, lambda name: name.endswith(".missing"), MISSING_FOR)


def _once(folder: Path, now: float, kept_file, kept_for: float) -> None:
    key = os.fspath(folder)
    if now - _last.get(key, float("-inf")) < EVERY:
        return
    _last[key] = now
    prune(folder, now, kept_file, kept_for)


def prune(folder: Path, now: float, kept_file, kept_for: float) -> int:
    """Remove the files `kept_file(name)` picks whose time is older than
    `kept_for`, and `.part-` files older than `PART_FOR`. Returns how many
    were removed."""
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return 0  # not there yet, or not a folder
    removed = 0
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return 0  # not this user's alone: not ours to clear
        with os.scandir(fd) as entries:
            names = [entry.name for entry in entries]
        for name in names:
            if name.startswith(".part-"):
                limit = PART_FOR
            elif kept_file(name):
                limit = kept_for
            else:
                continue
            try:
                found = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(found.st_mode) or now - found.st_mtime <= limit:
                    continue
                os.unlink(name, dir_fd=fd)
                removed += 1
            except OSError:
                continue
    except OSError:
        pass
    finally:
        os.close(fd)
    return removed
