"""Small, safe file updates for the tool's own state (inventory, known hosts).

Updates are read-modify-write, so concurrent `checker` commands must not
interleave: `locked()` holds an exclusive lock on a sidecar file for the whole
transaction, and `atomic_write()` replaces the file through a temporary file
of its own, so a reader never sees half a file and writers never share one.
"""

import fcntl
import os
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class LockBusy(Exception):
    """Something else held the lock for as long as the caller would wait."""


@contextmanager
def locked(path: Path, wait: float | None = None) -> Iterator[None]:
    """Hold an exclusive lock for a read-modify-write of `path`. `wait`: raise LockBusy after that
    many seconds, for callers that mustn't hang, such as a web page."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        if wait is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            deadline = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise LockBusy(str(path)) from None
                    time.sleep(0.1)
        yield
    finally:
        os.close(fd)  # closing releases the lock


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Replace `path` with `text` in one step, through a unique temporary file."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
