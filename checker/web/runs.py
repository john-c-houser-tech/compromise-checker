"""Checks started from a page (plan 5.11). Each is the command line's own run, in a process of its
own: a check takes minutes and reads what a compromised server sends, and neither belongs in the
server. One at a time, here and across the machine by the run's own lock. Passwords go to the
process on its standard input and are held nowhere else, and a check stops when that closes, so it
can't outlive this server and hold the lock with nobody able to stop it. What it reports is kept in
memory: a page's output has no place on disk, where a purge wouldn't find it."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque

from django.db import DatabaseError, close_old_connections, connection
from django.utils import timezone

from checker.web.models import ActionRecord, CheckRun

KEEP = 50  # runs, and what they reported
LONGEST_SECONDS = 4 * 3600  # a prompt nobody can answer, on an agent's pop-up, mustn't last
STOP_SECONDS = 60  # from being asked nicely to being told: sealing evidence can take a while
OUTPUT_KEPT_BYTES = 64 * 1024
LONGEST_LINE_BYTES = 4096
POLL_SECONDS = 0.25
RESTARTED = "the server restarted, so this was stopped"
RESTARTED_ANALYSIS = "the server restarted during this, so how it ended isn't known"
TOO_LONG = "ran too long, so it was stopped"
FINISHED = {
    "check": "finished a check",
    "analysis": "finished an analysis",
    "advice": "the AI advisor's request ended",
}

_running: dict[int, _Child] = {}
_output: dict[int, _Output] = {}
_unrecorded: dict[int, tuple[object, str]] = {}  # when and how it ended, until that's written down
_lock = threading.Lock()


class AlreadyRunning(Exception):
    def __init__(self, run_id: int):
        super().__init__(run_id)
        self.run_id = run_id


class _Output:
    """The end of what a run reported."""

    def __init__(self):
        self._lines: deque[tuple[int, str]] = deque()
        self._size = 0

    def add(self, raw: bytes) -> None:
        self._lines.append((len(raw), raw.decode("utf-8", "replace").rstrip("\r\n")))
        self._size += len(raw)
        while self._size > OUTPUT_KEPT_BYTES and len(self._lines) > 1:
            self._size -= self._lines.popleft()[0]

    def lines(self) -> list[str]:
        return [line for _, line in self._lines]


class _Child:
    def __init__(self, process: subprocess.Popen, passwords: dict | None):
        self.process = process
        self.passwords = passwords
        self.stopping_since: float | None = None
        self.ran_too_long = False


def _command(kind: str, hosts: list[str]) -> list[str]:
    # -P: nothing in the folder this server was started from gets to run with the passwords.
    checker = [sys.executable, "-P", "-m", "checker"]
    if kind == "analysis":
        return [*checker, "analyze", "--", *hosts]
    if kind == "advice":
        return [*checker, "advise", "--role", "whitelist", "--from-web-page", "--", *hosts]
    return [*checker, "run", "--unattended", "--from-web-page", "--", *hosts]


def start(kind: str, hosts: list[str], who: str, address: str, passwords=None) -> int:
    """The new run's id. Raises AlreadyRunning. `passwords` reach only the child."""
    with _lock:
        if _running:
            raise AlreadyRunning(next(iter(_running)))
        close_interrupted()
        run = CheckRun.objects.create(
            kind=kind,
            hosts=json.dumps(hosts),
            who=who[:150],
            address=address[:64],
            started_at=timezone.now(),
        )
        # The others print findings, which aren't for keeping: only their problems are read.
        reading_all = kind == "check"
        try:
            process = subprocess.Popen(  # noqa: S603 - this tool, and names from the inventory
                _command(kind, hosts),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE if reading_all else subprocess.DEVNULL,
                stderr=subprocess.STDOUT if reading_all else subprocess.PIPE,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
                start_new_session=True,  # so stopping it reaches all it started
            )
        except OSError:
            run.finished_at, run.ended = timezone.now(), "couldn't start"
            run.save()
            raise
        child = _Child(process, passwords)
        _running[run.id] = child
        _output[run.id] = _Output()
        try:
            threading.Thread(target=_watch, args=(run.id,), daemon=True).start()
        except RuntimeError:  # no thread to be had: nobody would ever watch it
            _signal(child, signal.SIGKILL)
            del _running[run.id]
            run.finished_at, run.ended = timezone.now(), "couldn't start"
            run.save()
            raise OSError("no thread for a check") from None
    _forget_old()
    return run.id


def _hand_over(child: _Child) -> None:
    """Then a check's pipe stays open: its closing is how it knows this server has gone. The others
    don't read it, and anything that asked them a question mustn't wait for an answer."""
    passwords, child.passwords = child.passwords, None
    if passwords is None:
        _close_quietly(child.process.stdin)
        return
    try:
        child.process.stdin.write(json.dumps(passwords or {}).encode() + b"\n")
        child.process.stdin.flush()
    except OSError:  # it has already gone: its exit status says so
        pass


def _read_output(stream, output: _Output) -> None:
    for raw in iter(lambda: stream.readline(LONGEST_LINE_BYTES), b""):
        output.add(raw)


def _watch(run_id: int) -> None:
    child = _running[run_id]
    try:
        _watch_child(child, _output[run_id])
    except Exception as exc:  # noqa: BLE001 - it must end, or no check could ever start again
        print(f"checker web: a check's watcher failed: {type(exc).__name__}", file=sys.stderr)
        _signal(child, signal.SIGKILL)
        child.process.wait()
    finally:
        _finish(run_id, child)


def _watch_child(child: _Child, output: _Output) -> None:
    _hand_over(child)
    stream = child.process.stdout or child.process.stderr
    reader = threading.Thread(target=_read_output, args=(stream, output), daemon=True)
    reader.start()
    started = time.monotonic()
    told = False
    while child.process.poll() is None:
        if not child.stopping_since and time.monotonic() - started > LONGEST_SECONDS:
            child.ran_too_long = True
            _stop_child(child)
        if (
            not told
            and child.stopping_since
            and time.monotonic() - child.stopping_since > STOP_SECONDS
        ):
            _signal(child, signal.SIGKILL)
            told = True
        time.sleep(POLL_SECONDS)
    if child.stopping_since:
        _signal(child, signal.SIGKILL)  # anything it started that outlived it
    reader.join(5)


def _signal(child: _Child, which: int) -> None:
    try:
        os.killpg(child.process.pid, which)
    except (ProcessLookupError, PermissionError):
        pass


def _stop_child(child: _Child) -> None:
    if not child.stopping_since:
        child.stopping_since = time.monotonic()
        _signal(child, signal.SIGTERM)


def _finish(run_id: int, child: _Child) -> None:
    status = child.process.returncode
    try:
        close_old_connections()
        if child.ran_too_long:
            words = TOO_LONG
        elif child.stopping_since:
            words = "stopped"
        else:
            words = ending_words(_kind_of(run_id), status)
    except Exception:  # noqa: BLE001 - it's over whatever else is wrong, and the page must say so
        words = "finished, but how it went couldn't be read"
    try:
        with _lock:
            _unrecorded[run_id] = (timezone.now(), words)
            _running.pop(run_id, None)
            _write_down_endings()
        _close_quietly(child.process.stdin)
    finally:
        connection.close()


def _close_quietly(stream) -> None:
    try:
        stream.close()
    except OSError:
        pass


def _write_down_endings() -> None:
    """On a full disk they wait in memory, and the pages still show them."""
    for run_id, (when, words) in list(_unrecorded.items()):
        try:
            run = CheckRun.objects.filter(pk=run_id).first()
            if run is not None:
                run.finished_at, run.ended = when, words
                run.save()
                ActionRecord.objects.create(
                    at=run.finished_at,
                    who=run.who,
                    address=run.address,
                    action=FINISHED[run.kind],
                    target=", ".join(json.loads(run.hosts))[:200],
                    outcome=words[:32],
                    detail="",
                )
            del _unrecorded[run_id]
        except Exception as exc:  # noqa: BLE001 - tried again at the next chance
            print(f"checker web: a check's end not recorded: {type(exc).__name__}", file=sys.stderr)
            return


def _kind_of(run_id: int) -> str:
    return CheckRun.objects.filter(pk=run_id).values_list("kind", flat=True).first() or "check"


def ending_words(kind: str, status: int) -> str:
    from checker import schedule

    if status < 0:
        return "ended unexpectedly"
    if kind != "check":
        return "finished" if status == 0 else "finished with problems"
    if status == schedule.EXIT_BUSY:
        return "another check was running"
    if status == schedule.EXIT_SETUP:
        return "couldn't start"
    return "finished" if status in {0, *schedule.EXIT_BAND.values()} else "finished with problems"


def stop(run_id: int) -> bool:
    """Whether it was running here to be stopped."""
    child = _running.get(run_id)
    if child is None:
        return False
    _stop_child(child)
    return True


def is_running(run_id: int) -> bool:
    return run_id in _running


def _restarted_words(kind: str) -> str:
    return RESTARTED if kind == "check" else RESTARTED_ANALYSIS


def state_of(run: CheckRun) -> str:
    """Read only: pages that show a check change nothing. A check this server isn't watching was
    started before it last restarted, and its pipe closing stopped it. Under the lock, so a run
    starting or ending this moment isn't mistaken for that."""
    if run.ended:
        return run.ended
    with _lock:
        if run.id in _unrecorded:
            return _unrecorded[run.id][1]
        if run.id in _running:
            return "running"
        fresh = CheckRun.objects.filter(pk=run.id).values_list("ended", flat=True).first()
    return fresh or _restarted_words(run.kind)


def close_interrupted() -> None:
    """Writes down what `state_of` already says. Called with the lock held, at a start."""
    _write_down_endings()
    for run in CheckRun.objects.filter(finished_at=None):
        if run.id not in _running and run.id not in _unrecorded:
            run.finished_at, run.ended = timezone.now(), _restarted_words(run.kind)
            run.save()


def output_lines(run_id: int) -> list[str]:
    """It can quote what a server sent, so pages treat it as hostile."""
    output = _output.get(run_id)
    return output.lines() if output else []


def _forget_old() -> None:
    try:
        keep = list(CheckRun.objects.order_by("-id").values_list("id", flat=True)[:KEEP])
        CheckRun.objects.exclude(id__in=keep).delete()
        for run_id in set(_output) - set(keep):
            _output.pop(run_id, None)
    except DatabaseError as exc:  # the check has started: this can wait for the next one
        print(f"checker web: old checks not let go: {type(exc).__name__}", file=sys.stderr)
