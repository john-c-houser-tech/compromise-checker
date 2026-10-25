"""Compromise Checker collector.

This file is streamed over SSH to `python3 -I -B -` on the target and runs
there. It is never imported by the controller. Rules for this file
(DESIGN.md §2, §3.2, §5):

- Python 3.9 compatible (RHEL 9's python3) and standard library only.
- Read-only: it never writes, renames, deletes or changes anything on the
  target, and it writes nothing to disk.
- Output goes to stdout only; diagnostics to stderr.

The controller appends one line, `main(<settings as a JSON string>)`, to the
text it streams, so the collector takes no arguments, files or environment
variables. The stream it writes is specified in docs/collector-protocol.md;
what each module reads, and why, is in docs/collector-modules.md.
"""

import base64
import datetime
import gzip
import json
import os
import platform
import re
import socket
import stat
import sys
import time
import zlib

# Optional standard modules: some minimal Python builds leave them out, and a
# missing one must cost only the feature that needs it, never the run.
try:
    import bz2
except ImportError:
    bz2 = None
try:
    import lzma
except ImportError:
    lzma = None
try:
    import ctypes
except ImportError:
    ctypes = None

COLLECTOR_VERSION = "0.1.0.dev0"
PROTOCOL = 1
MASKING_VERSION = 1

# Every path the collector reads goes through path(). Only the test suite
# changes ROOT, to point the collector at a directory of fixture files; the
# controller's settings cannot.
ROOT = "/"

CHUNK_BYTES = 64 * 1024


def path(absolute):
    if ROOT == "/":
        return absolute
    return os.path.join(ROOT, absolute.lstrip("/"))


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def iso_from_timestamp(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).isoformat()


def parse_time(value):
    """ISO 8601 time to datetime. Python 3.9's fromisoformat() rejects "Z"."""
    if not isinstance(value, str):
        raise ValueError("not a string")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.datetime.fromisoformat(value)


# --- Output stream --------------------------------------------------------------


class Stream:
    """The result stream: gzip-compressed JSON Lines on a binary file."""

    def __init__(self, out):
        self._out = out
        self._gzip = gzip.GzipFile(fileobj=out, mode="wb")
        self.counts = {"records": 0, "sources": 0, "chunks": 0, "errors": 0}
        self._next_source_id = 1

    def emit(self, obj):
        line = json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n"
        self._gzip.write(line.encode("utf-8"))
        kind = obj["type"]
        if kind == "record":
            self.counts["records"] += 1
        elif kind == "source_start":
            self.counts["sources"] += 1
        elif kind == "chunk":
            self.counts["chunks"] += 1
        elif kind == "error":
            self.counts["errors"] += 1

    def flush(self):
        """Push everything emitted so far to the controller now."""
        self._gzip.flush()
        self._out.flush()

    def record(self, module, name, data):
        self.emit({"type": "record", "module": module, "name": name, "data": data})

    def error(self, module, message):
        self.emit({"type": "error", "module": module, "message": message})

    def new_source_id(self):
        source_id = self._next_source_id
        self._next_source_id += 1
        return source_id

    def close(self):
        self._gzip.close()


# --- Secret masking (DESIGN.md §3.4; the list is published in the policy §7) ----

MASK = b"[MASKED:%s]"


def _rule(kind, context, secret):
    """A masking rule: `context` locates the secret, `secret` is what gets
    replaced. Text already masked by an earlier rule is never matched again."""
    return kind, re.compile(context + rb"(?!\[MASKED:)(" + secret + rb")")


# Specific formats first, so the generic key=value rule doesn't relabel a
# value that is already masked.
MASKING_RULES = [
    _rule("aws_access_key", rb"\b", rb"(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _rule("github_token", rb"\b", rb"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,}"),
    _rule("slack_token", rb"\b", rb"xox[abprs]-[A-Za-z0-9-]{10,}"),
    _rule("stripe_key", rb"\b", rb"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    _rule("anthropic_key", rb"\b", rb"sk-ant-[A-Za-z0-9_-]{20,}"),
    _rule("jwt", rb"\b", rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _rule("url_password", rb"[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:", rb"[^\s@/]+(?=@)"),
    _rule("auth_header", rb"(?i)authorization:\s*(?:bearer|basic|token)?\s*", rb"[^\s\"']+"),
    _rule("bearer_token", rb"(?i)\bbearer\s+", rb"[A-Za-z0-9._~+/=-]{8,}"),
    _rule("mysql_password", rb"\b(?:mysql|mariadb|mysqldump|mysqladmin)\b[^\n]*?\s-p", rb"\S+"),
    _rule("password", rb"(?i)--?(?:password|passwd|pass|token|secret|api-?key)[= ]", rb"\S+"),
    _rule(
        "password",
        # The key starts a word that isn't inside a PAM "(service:type)" label,
        # and "pwd" counts only in lower case, so sudo's "PWD=" (its working
        # directory) is kept.
        rb"(?<![(\w.-])[A-Za-z0-9_.-]*(?:(?i:password|passwd|secret|token|api[_-]?key|apikey|"
        rb"access[_-]?key|auth(?!orization))|pwd)[A-Za-z0-9_.-]*[\"']?\s*[=:]\s*[\"']?",
        rb"[^\s\"'&,;]+",
    ),
]

_PEM_BEGIN = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_END = re.compile(rb"-----END [A-Z0-9 ]*PRIVATE KEY-----")


class Masker:
    """Masks secrets line by line. Holds state across lines for key blocks."""

    def __init__(self):
        self.counts = {}
        self._in_key_block = False

    def _count(self, kind, n=1):
        self.counts[kind] = self.counts.get(kind, 0) + n

    def line(self, data):
        """Mask one line (bytes, with its newline). Returns the masked bytes."""
        if self._in_key_block:
            if _PEM_END.search(data):
                self._in_key_block = False
            return b""
        begin = _PEM_BEGIN.search(data)
        if begin:
            self._count("private_key")
            if not _PEM_END.search(data, begin.end()):
                self._in_key_block = True
            newline = b"\n" if data.endswith(b"\n") else b""
            return data[: begin.start()] + MASK % b"private_key" + newline
        for kind, pattern in MASKING_RULES:
            marker = MASK % kind.encode("ascii")
            pieces, last, hits = [], 0, 0
            for match in pattern.finditer(data):
                pieces.append(data[last : match.start(1)])
                pieces.append(marker)
                last = match.end(1)
                hits += 1
            if hits:
                pieces.append(data[last:])
                data = b"".join(pieces)
                self._count(kind, hits)
        return data


def mask_text(data):
    """Mask a whole block of bytes. Returns (masked bytes, counts by kind)."""
    masker = Masker()
    out = b"".join(masker.line(line) for line in data.splitlines(keepends=True))
    return out, masker.counts


# --- Limits ----------------------------------------------------------------------


class ModuleTimeout(Exception):
    pass


class Run:
    """What a module needs: the stream, the settings, and its time budget."""

    def __init__(self, stream, settings, deadline):
        self.stream = stream
        self.settings = settings
        self.since = parse_time(settings["since"])
        self.source_bytes = int(settings["limits"]["source_bytes"])
        self.deadline = deadline

    def out_of_time(self):
        return time.monotonic() >= self.deadline

    def check_time(self):
        if self.out_of_time():
            raise ModuleTimeout()


# --- Reading files safely ------------------------------------------------------------

_OPENERS = {".gz": ("gzip", lambda raw: gzip.GzipFile(fileobj=raw))}
if lzma is not None:
    _OPENERS[".xz"] = ("xz", lzma.LZMAFile)
if bz2 is not None:
    _OPENERS[".bz2"] = ("bzip2", bz2.BZ2File)
_DECOMPRESS_ERRORS = (OSError, EOFError, zlib.error) + ((lzma.LZMAError,) if lzma else ())


def open_regular_file(absolute):
    """Open a regular file for reading without following a final symlink,
    without blocking on FIFOs or devices, and without updating its access
    time where the kernel allows that. Returns (file object, fstat result).
    Raises OSError, or ValueError for anything that is not a regular file."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    noatime = getattr(os, "O_NOATIME", 0)
    try:
        fd = os.open(path(absolute), flags | noatime)
    except PermissionError:
        # O_NOATIME needs file ownership or CAP_FOWNER; retry without it.
        fd = os.open(path(absolute), flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("not a regular file")
        # Back to blocking reads now we know it is a regular file.
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb"), info
    except BaseException:
        os.close(fd)
        raise


def file_meta(info, compression):
    return {
        "size": info.st_size,
        "mtime": iso_from_timestamp(info.st_mtime),
        "ctime": iso_from_timestamp(info.st_ctime),
        "mode": format(stat.S_IMODE(info.st_mode), "04o"),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "inode": info.st_ino,
        "compressed": compression,
    }


def describe_unreadable(absolute):
    """Facts about a path that could not be read as a regular file."""
    details = {"path": absolute}
    try:
        info = os.lstat(path(absolute))
    except OSError as exc:
        details["error"] = str(exc)
        return details
    details["file_type"] = stat.filemode(info.st_mode)[0]
    details["mode"] = format(stat.S_IMODE(info.st_mode), "04o")
    details["uid"], details["gid"] = info.st_uid, info.st_gid
    if stat.S_ISLNK(info.st_mode):
        try:
            details["link_target"] = os.readlink(path(absolute))
        except OSError as exc:
            details["error"] = str(exc)
    return details


def send_file(run, module, absolute):
    """Send one file as a source: decompressed, masked, chunked, capped.
    Returns True if sent, False if it could not be read (recorded instead).
    Raises ModuleTimeout after closing the source cleanly if time runs out."""
    try:
        raw, info = open_regular_file(absolute)
    except (OSError, ValueError) as exc:
        details = describe_unreadable(absolute)
        details["reason"] = str(exc)
        run.stream.record(module, "unreadable_file", details)
        return False

    compression, opener = None, None
    for suffix, (name, cls) in _OPENERS.items():
        if absolute.endswith(suffix):
            compression, opener = name, cls
    stream = run.stream
    source_id = stream.new_source_id()
    stream.emit(
        {
            "type": "source_start",
            "source_id": source_id,
            "module": module,
            "kind": "file",
            "name": absolute,
            "meta": file_meta(info, compression),
        }
    )

    masker = Masker()
    chunks, total, pending, pending_original = 0, 0, [], 0
    truncated_reason, error, timed_out = None, None, False

    def flush_pending():
        nonlocal chunks, pending, pending_original
        if not pending:
            return
        data = b"".join(pending)
        try:
            data.decode("utf-8")
            encoding, payload = "utf-8", data.decode("utf-8")
        except UnicodeDecodeError:
            encoding, payload = "base64", base64.b64encode(data).decode("ascii")
        stream.emit(
            {
                "type": "chunk",
                "source_id": source_id,
                "seq": chunks,
                "encoding": encoding,
                "data": payload,
            }
        )
        chunks += 1
        pending, pending_original = [], 0

    try:
        with raw:
            reader = opener(raw) if opener else raw
            with reader:
                while True:
                    if run.out_of_time():
                        truncated_reason, timed_out = "time", True
                        break
                    room = run.source_bytes - total
                    if room <= 0:
                        if reader.read(1):
                            truncated_reason = "size"
                        break
                    line = reader.readline(min(room, CHUNK_BYTES))
                    if not line:
                        break
                    total += len(line)
                    if pending_original + len(line) > CHUNK_BYTES:
                        flush_pending()
                    pending.append(masker.line(line))
                    pending_original += len(line)
    except _DECOMPRESS_ERRORS as exc:
        error = f"{type(exc).__name__}: {exc}"
    flush_pending()

    end = {
        "type": "source_end",
        "source_id": source_id,
        "chunks": chunks,
        "bytes": total,
        "truncated": truncated_reason is not None,
        "masked": masker.counts,
    }
    if truncated_reason:
        end["truncated_reason"] = truncated_reason
    if error:
        end["error"] = error
    stream.emit(end)
    if timed_out:
        raise ModuleTimeout()
    return True


def read_small(absolute, limit=65536):
    """Read a small text file (configuration, /proc) or return None."""
    try:
        raw, _ = open_regular_file(absolute)
    except (OSError, ValueError):
        return None
    with raw:
        return raw.read(limit).decode("utf-8", errors="replace")


# --- Priority ---------------------------------------------------------------------

# ioprio_set syscall numbers by machine (see the kernel's syscall tables).
_IOPRIO_SET = {"x86_64": 251, "aarch64": 30, "ppc64le": 273, "s390x": 282}
_IOPRIO_CLASS_IDLE, _IOPRIO_CLASS_SHIFT, _IOPRIO_WHO_PROCESS = 3, 13, 1


def lower_priority():
    """Drop to the lowest CPU and I/O priority, so the collector does not
    disturb the server's normal work. Never fails the run."""
    result = {"nice": None, "io": "unchanged"}
    try:
        os.nice(19)
        result["nice"] = os.getpriority(os.PRIO_PROCESS, 0)
    except OSError:
        pass
    number = _IOPRIO_SET.get(platform.machine())
    if number is not None and ctypes is not None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            value = _IOPRIO_CLASS_IDLE << _IOPRIO_CLASS_SHIFT
            if libc.syscall(number, _IOPRIO_WHO_PROCESS, 0, value) == 0:
                result["io"] = "idle"
        except (OSError, AttributeError):
            pass
    return result


# --- Modules ------------------------------------------------------------------------


def read_os_release():
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        text = read_small(candidate)
        if text is None:
            continue
        values = {}
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() and not key.startswith("#"):
                values[key.strip()] = value.strip().strip("\"'")
        return values
    return {}


def read_boot_id():
    text = read_small("/proc/sys/kernel/random/boot_id")
    return text.strip() if text else None


def host_identity():
    release = read_os_release()
    uname = platform.uname()
    return {
        "hostname": socket.gethostname(),
        "os_id": release.get("ID"),
        "os_version_id": release.get("VERSION_ID"),
        "os_pretty_name": release.get("PRETTY_NAME"),
        "kernel": uname.release,
        "machine": uname.machine,
        "boot_id": read_boot_id(),
    }


def module_host_facts(run):
    """Who and what this host is, its clock, and its basic security settings."""
    record = run.stream.record
    module = "host_facts"
    uname = platform.uname()

    record(module, "os_release", read_os_release())
    record(
        module,
        "uname",
        {
            "sysname": uname.system,
            "nodename": uname.node,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        },
    )

    machine_id = read_small("/etc/machine-id")
    record(module, "machine_id", {"machine_id": machine_id.strip() if machine_id else None})

    uptime = read_small("/proc/uptime")
    boot_time = None
    for line in (read_small("/proc/stat") or "").splitlines():
        if line.startswith("btime "):
            boot_time = iso_from_timestamp(int(line.split()[1]))
    record(
        module,
        "uptime",
        {
            "seconds": float(uptime.split()[0]) if uptime else None,
            "boot_time": boot_time,
            "boot_id": read_boot_id(),
        },
    )

    try:
        localtime = os.readlink(path("/etc/localtime"))
    except OSError:
        localtime = None
    record(
        module,
        "clock",
        {"utc": now_iso(), "tzname": list(time.tzname), "localtime_link": localtime},
    )

    tainted = read_small("/proc/sys/kernel/tainted")
    record(module, "kernel_taint", {"value": int(tainted) if tainted else None})

    selinux = read_small("/sys/fs/selinux/enforce")
    apparmor = read_small("/sys/module/apparmor/parameters/enabled")
    record(
        module,
        "mandatory_access_control",
        {
            "selinux": None
            if selinux is None
            else ("enforcing" if selinux.strip() == "1" else "permissive"),
            "apparmor_enabled": None if apparmor is None else apparmor.strip() == "Y",
        },
    )

    memory_kb = None
    for line in (read_small("/proc/meminfo") or "").splitlines():
        if line.startswith("MemTotal:"):
            memory_kb = int(line.split()[1])
    record(module, "hardware", {"cpus": os.cpu_count(), "memory_kb": memory_kb})


# Authentication logs: RHEL family writes /var/log/secure (rotated with a date
# suffix), Ubuntu writes /var/log/auth.log (rotated .1, .2.gz, ...).
_AUTH_LOG = re.compile(r"^(?:secure|auth\.log)(?:[-.][\w.-]+)?$")


def module_auth_log(run):
    """The authentication log and its rotated copies, within the look-back window."""
    module = "auth_log"
    try:
        names = os.listdir(path("/var/log"))
    except OSError as exc:
        run.stream.error(module, f"cannot list /var/log: {exc}")
        return
    candidates = []
    for name in names:
        if not _AUTH_LOG.match(name):
            continue
        absolute = "/var/log/" + name
        try:
            info = os.lstat(path(absolute))
        except OSError:
            continue
        candidates.append((info.st_mtime, absolute))

    since = run.since.timestamp()
    sent = skipped = 0
    for mtime, absolute in sorted(candidates):
        run.check_time()
        if mtime < since:
            skipped += 1  # last written before the window: nothing in it is new
            continue
        if send_file(run, module, absolute):
            sent += 1
    run.stream.record(
        module,
        "summary",
        {"files_found": len(candidates), "files_sent": sent, "files_before_window": skipped},
    )


# Collection modules, by name, in their default order.
MODULES = {
    "host_facts": module_host_facts,
    "auth_log": module_auth_log,
}


# --- Settings and the run -------------------------------------------------------------


def settings_problems(settings):
    """Return a list of reasons to refuse these settings (empty if fine)."""
    if not isinstance(settings, dict):
        return ["settings must be a JSON object"]
    problems = []
    if settings.get("protocol") != PROTOCOL:
        problems.append(
            f"protocol {settings.get('protocol')!r} requested, this collector speaks {PROTOCOL}"
        )
    if not isinstance(settings.get("run_id"), str) or not settings.get("run_id"):
        problems.append("run_id must be a non-empty string")
    try:
        parsed = parse_time(settings.get("since"))
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        problems.append("since must be an ISO 8601 time with a UTC offset")
    modules = settings.get("modules")
    if modules is not None:
        if not isinstance(modules, list) or not all(isinstance(m, str) for m in modules):
            problems.append("modules must be null or a list of names")
        else:
            unknown = [m for m in modules if m not in MODULES]
            if unknown:
                problems.append("unknown modules: " + ", ".join(unknown))
    limits = settings.get("limits")
    if not isinstance(limits, dict):
        problems.append("limits must be an object")
    else:
        for key in ("overall_seconds", "module_seconds", "source_bytes"):
            value = limits.get(key)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                problems.append(f"limits.{key} must be a positive number")
    return problems


def main(settings_json, out=None):
    """Run one collection and write the result stream. Returns the exit status."""
    started = time.monotonic()
    priority = lower_priority()
    stream = Stream(out if out is not None else sys.stdout.buffer)
    try:
        settings = json.loads(settings_json)
    except ValueError as exc:
        settings = None
        problems = [f"settings are not valid JSON: {exc}"]
    else:
        problems = settings_problems(settings)

    run_id = settings.get("run_id") if isinstance(settings, dict) else None
    planned = []
    if not problems:
        requested = settings.get("modules")  # omitted or null: all; []: none
        planned = list(MODULES) if requested is None else requested

    stream.emit(
        {
            "type": "manifest",
            "protocol": PROTOCOL,
            "collector_version": COLLECTOR_VERSION,
            "run_id": run_id if isinstance(run_id, str) else None,
            "started_at": now_iso(),
            "host": host_identity(),
            "python": {"version": platform.python_version(), "executable": sys.executable},
            "effective_uid": os.geteuid(),
            "settings": settings if isinstance(settings, dict) else None,
            "modules_planned": planned,
            "masking_version": MASKING_VERSION,
            "priority": priority,
        }
    )
    # The controller timestamps the manifest's arrival to measure clock offset
    # (protocol §3.1), and an interrupted run should still leave a manifest.
    stream.flush()

    results = {}
    if problems:
        for problem in problems:
            stream.error(None, "refused: " + problem)
        status = "refused"
    else:
        limits = settings["limits"]
        overall_deadline = started + limits["overall_seconds"]
        for name in planned:
            module_started = time.monotonic()
            if module_started >= overall_deadline:
                results[name] = {"status": "skipped", "seconds": 0.0}
                continue
            deadline = min(overall_deadline, module_started + limits["module_seconds"])
            try:
                MODULES[name](Run(stream, settings, deadline))
                outcome = "ok"
            except ModuleTimeout:
                stream.error(name, "time limit reached; module stopped early")
                outcome = "timeout"
            except Exception as exc:  # one module failing must not stop the rest
                stream.error(name, f"{type(exc).__name__}: {exc}")
                outcome = "error"
            results[name] = {
                "status": outcome,
                "seconds": round(time.monotonic() - module_started, 3),
            }
            stream.flush()
        status = "complete" if all(r["status"] == "ok" for r in results.values()) else "partial"

    stream.emit(
        {
            "type": "trailer",
            "finished_at": now_iso(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "status": status,
            "counts": dict(stream.counts),
            "modules": results,
        }
    )
    stream.close()
    return 0
