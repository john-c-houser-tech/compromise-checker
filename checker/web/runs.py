"""Checks started from a page (plan 5.11). Each is the command line's own run, in a process of its
own: a check takes minutes and reads what a compromised server sends, and neither belongs in the
server. One at a time, here and across the machine by the run's own lock. Passwords go to the
process on its standard input and are held nowhere else."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from django.db import close_old_connections, connection
from django.utils import timezone

from checker.web.models import ActionRecord, CheckRun

KEEP = 50  # runs, and their logs
LONGEST_SECONDS = (
    4 * 3600
)  # a prompt nobody can answer, on an agent's pop-up, mustn't last for ever
STOP_SECONDS = 10  # from being asked nicely to being told
LOG_SHOWN_BYTES = 64 * 1024
POLL_SECONDS = 0.25

_running: dict[int, _Child] = {}
_lock = threading.Lock()


class AlreadyRunning(Exception):
    def __init__(self, run_id: int):
        super().__init__(run_id)
        self.run_id = run_id


class _Child:
    def __init__(self, process: subprocess.Popen):
        self.process = process
        self.stopping_since: float | None = None


def _command(kind: str, hosts: list[str]) -> list[str]:
    checker = [sys.executable, "-m", "checker"]
    if kind == "analysis":
        return [*checker, "analyze", "--", *hosts]
    return [*checker, "run", "--unattended", "--passwords-on-stdin", "--", *hosts]


def log_path(base: Path, run_id: int) -> Path:
    return base / "checks" / f"{run_id}.log"


def start(base: Path, kind: str, hosts: list[str], who: str, address: str, passwords=None) -> int:
    """The new run's id. Raises AlreadyRunning. `passwords` reach only the child."""
    with _lock:
        if _running:
            raise AlreadyRunning(next(iter(_running)))
        run = CheckRun.objects.create(
            kind=kind,
            hosts=json.dumps(hosts),
            who=who[:150],
            address=address[:64],
            started_at=timezone.now(),
        )
        path = log_path(base, run.id)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            process = subprocess.Popen(  # noqa: S603 - this tool, and names from the inventory
                _command(kind, hosts),
                stdin=subprocess.PIPE,
                stdout=descriptor,
                stderr=subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
                start_new_session=True,  # so stopping it reaches all it started
            )
        finally:
            os.close(descriptor)
        _running[run.id] = _Child(process)
    threading.Thread(target=_handover_and_watch, args=(run.id, passwords), daemon=True).start()
    _forget_old(base)
    return run.id


def _handover_and_watch(run_id: int, passwords) -> None:
    child = _running[run_id]
    try:
        child.process.stdin.write(json.dumps(passwords or {}).encode())
        child.process.stdin.close()
    except OSError:  # it has already gone: its exit status says so
        pass
    passwords = None
    started = time.monotonic()
    while child.process.poll() is None:
        if time.monotonic() - started > LONGEST_SECONDS:
            _signal(child, signal.SIGTERM)
            child.stopping_since = child.stopping_since or time.monotonic()
        if child.stopping_since and time.monotonic() - child.stopping_since > STOP_SECONDS:
            _signal(child, signal.SIGKILL)
        time.sleep(POLL_SECONDS)
    _finish(run_id, child)


def _signal(child: _Child, which: int) -> None:
    try:
        os.killpg(child.process.pid, which)
    except ProcessLookupError:
        pass


def _finish(run_id: int, child: _Child) -> None:
    close_old_connections()
    status = child.process.returncode
    words = "stopped" if child.stopping_since else ending_words(_kind_of(run_id), status)
    try:
        run = CheckRun.objects.get(pk=run_id)
        run.finished_at = timezone.now()
        run.exit_status = status
        run.ended = words
        run.save()
        ActionRecord.objects.create(
            at=run.finished_at,
            who=run.who,
            address=run.address,
            action=f"finished a {run.kind}",
            target=", ".join(json.loads(run.hosts))[:200],
            outcome=words[:32],
            detail="",
        )
    except Exception as exc:  # noqa: BLE001 - it's over either way, and the page must say so
        print(f"checker web: a check's end not recorded: {type(exc).__name__}", file=sys.stderr)
    finally:
        with _lock:
            _running.pop(run_id, None)
        connection.close()


def _kind_of(run_id: int) -> str:
    return CheckRun.objects.filter(pk=run_id).values_list("kind", flat=True).first() or "check"


def ending_words(kind: str, status: int) -> str:
    from checker import schedule

    if status < 0:
        return "ended unexpectedly"
    if status == schedule.EXIT_BUSY and kind == "check":
        return "another check was already running"
    if status == schedule.EXIT_SETUP and kind == "check":
        return "couldn't start"
    if status == schedule.EXIT_FAILED or (kind == "analysis" and status != 0):
        return "finished with problems"
    return "finished"


def stop(run_id: int) -> bool:
    """Whether it was running here to be stopped."""
    child = _running.get(run_id)
    if child is None:
        return False
    child.stopping_since = child.stopping_since or time.monotonic()
    _signal(child, signal.SIGTERM)
    return True


def is_running(run_id: int) -> bool:
    return run_id in _running


def settle_interrupted() -> None:
    """Runs this server knows nothing of were started before it last restarted. Such a child may
    still finish its work; the results pages will show it if so."""
    for run in CheckRun.objects.filter(finished_at=None):
        if run.id not in _running:
            run.finished_at = timezone.now()
            run.ended = "the server restarted during this, so how it ended isn't known"
            run.save()


def log_lines(base: Path, run_id: int) -> list[str]:
    """The end of it. It can quote what a server sent, so pages treat it as hostile."""
    try:
        with open(log_path(base, run_id), "rb") as log:
            log.seek(0, os.SEEK_END)
            log.seek(max(0, log.tell() - LOG_SHOWN_BYTES))
            return log.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []


def _forget_old(base: Path) -> None:
    keep = CheckRun.objects.order_by("-id").values_list("id", flat=True)[:KEEP]
    old = CheckRun.objects.exclude(id__in=list(keep))
    for run_id in old.values_list("id", flat=True):
        log_path(base, run_id).unlink(missing_ok=True)
    old.delete()
