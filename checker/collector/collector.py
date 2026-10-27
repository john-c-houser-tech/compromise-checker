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
import hashlib
import json
import os
import platform
import re
import shlex
import signal
import socket
import stat
import subprocess
import sys
import threading
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
try:
    import resource
except ImportError:
    resource = None

COLLECTOR_VERSION = "0.1.0.dev0"
PROTOCOL = 1
MASKING_VERSION = 2

# Every path the collector reads goes through path(). Only the test suite
# changes ROOT, to point the collector at a directory of fixture files; the
# controller's settings cannot.
ROOT = "/"

CHUNK_BYTES = 64 * 1024
# Lines are masked whole, never in pieces, so a secret can't straddle a read.
# A line longer than this is not sent at all (fail closed): it is replaced by
# a marker saying how long it was.
MAX_LINE = 1024 * 1024


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


# A whole quoted value, escaped quotes included, so `password="two words"`
# can't leave its second word behind.
_QUOTED = rb'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\''

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
    _rule(
        "mysql_password",
        rb"\b(?:mysql|mariadb|mysqldump|mysqladmin)\b[^\n]*?\s-p",
        _QUOTED + rb"|\S+",
    ),
    _rule(
        "password",
        rb"(?i)--?(?:password|passwd|pass|token|secret|api-?key)[= ]",
        _QUOTED + rb"|\S+",
    ),
    _rule(
        "password",
        # The key starts a word that isn't inside a PAM "(service:type)" label,
        # and "pwd" counts only in lower case, so sudo's "PWD=" (its working
        # directory) is kept.
        rb"(?<![(\w.-])[A-Za-z0-9_.-]*(?:(?i:password|passwd|secret|token|api[_-]?key|apikey|"
        rb"access[_-]?key|auth(?!orization))|pwd)[A-Za-z0-9_.-]*[\"']?\s*[=:]\s*",
        _QUOTED + rb"|[^\s\"'&,;]+",
    ),
]

_PEM_BEGIN = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_END = re.compile(rb"-----END [A-Z0-9 ]*PRIVATE KEY-----")
# Inside a key block, only lines that look like key material stay in it: a
# base64 run alone on the line, or a long one ending a line that has a log
# prefix (a key logged line by line); a PEM header; or a blank line. Any
# other line ends the block and is masked normally, so a fake "BEGIN" line
# can hide nothing but base64 — never the log lines after it.
_KEY_LINE = re.compile(rb"^(\s*)[A-Za-z0-9+/=]+(\s*)$")
_KEY_TAIL = re.compile(rb"^(.*\s)[A-Za-z0-9+/=]{16,}(\s*)$")
_KEY_HEADER = re.compile(rb"(?:^|\s)(?:Proc-Type|DEK-Info):\s")
# Longer than any real PEM private key (a 16384-bit RSA key is under 200).
MAX_KEY_LINES = 256


class Masker:
    """Masks secrets line by line. Holds state across lines for key blocks."""

    def __init__(self):
        self.counts = {}
        self._in_key_block = False
        self._key_lines = 0

    def _count(self, kind, n=1):
        self.counts[kind] = self.counts.get(kind, 0) + n

    def _key_material(self, data):
        """Inside a key block: the masked line if `data` looks like key
        material, or None if it doesn't (or the block has run too long)."""
        if self._key_lines >= MAX_KEY_LINES:
            return None
        if not data.strip() or _KEY_HEADER.search(data) or _KEY_LINE.match(data):
            self._key_lines += 1
            return b""  # part of the key, already replaced by its marker
        match = _KEY_TAIL.match(data)
        if match is None:
            return None
        # A key logged line by line: keep the log prefix, which is evidence.
        self._key_lines += 1
        return match.group(1) + MASK % b"private_key" + match.group(2)

    def oversized(self, length):
        """Stand-in for a line too long to mask safely."""
        self._count("oversized_line")
        return b"[MASKED:oversized_line %d bytes]\n" % length

    def line(self, data):
        """Mask one whole line (bytes, with its newline). Returns the masked bytes."""
        if self._in_key_block:
            end = _PEM_END.search(data)
            if end:
                self._in_key_block = False
                before = data[: end.start()]
                if before.strip():
                    before = self._key_material(before + b"\n")
                    before = before[:-1] if before is not None else data[: end.start()]
                data = before + data[end.end() :]  # the rest goes through the rules
                if not data.strip():
                    return b""
            else:
                masked = self._key_material(data)
                if masked is not None:
                    return masked
                # Not key material: the block was never a real key. Mask this
                # line normally, and count the unterminated block as evidence.
                self._in_key_block = False
                self._count("private_key_unterminated")
        begin = _PEM_BEGIN.search(data)
        if begin:
            self._count("private_key")
            end = _PEM_END.search(data, begin.end())
            if end:
                rest = data[end.end() :]
            else:
                self._in_key_block, self._key_lines = True, 0
                rest = b"\n" if data.endswith(b"\n") else b""
            # The text before the key still goes through every rule below.
            data = data[: begin.start()] + MASK % b"private_key" + rest
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
# Compressed formats this collector recognises. One it can't open is never
# sent raw: compressed bytes would slip past masking.
_COMPRESSED = {
    ".gz": "gzip",
    ".xz": "xz",
    ".bz2": "bzip2",
    ".zst": "zstd",
    ".lz4": "lz4",
    ".Z": "compress",
}
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


class SourceWriter:
    """Sends one source's content: whole lines, already masked, in chunks of
    up to CHUNK_BYTES original bytes, stopping at the per-source byte cap."""

    def __init__(self, run, module, kind, name, meta):
        self.stream = run.stream
        self.cap = run.source_bytes
        self.masker = Masker()
        self.source_id = self.stream.new_source_id()
        self.chunks, self.total = 0, 0
        self._pending, self._pending_original = [], 0
        self.stream.emit(
            {
                "type": "source_start",
                "source_id": self.source_id,
                "module": module,
                "kind": kind,
                "name": name,
                "meta": meta,
            }
        )

    def add(self, masked, length):
        """Queue one masked line of `length` original bytes. Returns False,
        sending nothing, when the line would take the source over its cap."""
        if self.total + length > self.cap:
            return False
        self.total += length
        if self._pending_original + length > CHUNK_BYTES:
            self._flush()
        self._pending.append(masked)
        self._pending_original += length
        return True

    def _flush(self):
        if not self._pending:
            return
        data = b"".join(self._pending)
        try:
            encoding, payload = "utf-8", data.decode("utf-8")
        except UnicodeDecodeError:
            encoding, payload = "base64", base64.b64encode(data).decode("ascii")
        self.stream.emit(
            {
                "type": "chunk",
                "source_id": self.source_id,
                "seq": self.chunks,
                "encoding": encoding,
                "data": payload,
            }
        )
        self.chunks += 1
        self._pending, self._pending_original = [], 0

    def finish(self, truncated_reason=None, error=None, extra=None):
        self._flush()
        end = {
            "type": "source_end",
            "source_id": self.source_id,
            "chunks": self.chunks,
            "bytes": self.total,
            "truncated": truncated_reason is not None,
            "masked": self.masker.counts,
        }
        if truncated_reason:
            end["truncated_reason"] = truncated_reason
        if error:
            end["error"] = error
        if extra:
            end.update(extra)
        self.stream.emit(end)


def pump_lines(run, writer, reader, transform=None):
    """Copy whole lines from `reader` to `writer`, masking each one (through
    `transform(line, masker)` when given). Returns why it stopped early —
    "time" or "size" — or None at the end of the input."""
    masker = writer.masker
    while True:
        if run.out_of_time():
            return "time"
        line = reader.readline(MAX_LINE + 1)
        if not line:
            return None
        length = len(line)
        if length > MAX_LINE:
            # Too long to mask safely: skip to its end, send a marker.
            while not line.endswith(b"\n") and not run.out_of_time():
                if writer.total + length > writer.cap:
                    return "size"  # nothing of it is sent either way
                line = reader.readline(MAX_LINE)
                if not line:
                    break
                length += len(line)
            masked = masker.oversized(length)
        elif transform is not None:
            masked = transform(line, masker)
        else:
            masked = masker.line(line)
        if not writer.add(masked, length):
            return "size"  # whole lines only: the one that doesn't fit is left out


def send_file(run, module, absolute):
    """Send one file as a source: decompressed, masked, chunked, capped.
    Returns True if sent, False if it could not be read (recorded instead).
    Raises ModuleTimeout after closing the source cleanly if time runs out."""
    suffix = os.path.splitext(absolute)[1]
    if suffix in _COMPRESSED and suffix not in _OPENERS:
        details = describe_unreadable(absolute)
        details["reason"] = (
            f"{_COMPRESSED[suffix]}-compressed and this server's Python cannot decompress it;"
            " not sent, because compressed bytes would bypass secret masking"
        )
        run.stream.record(module, "unreadable_file", details)
        return False
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
    writer = SourceWriter(run, module, "file", absolute, file_meta(info, compression))
    truncated_reason, error = None, None
    try:
        with raw:
            reader = opener(raw) if opener else raw
            with reader:
                truncated_reason = pump_lines(run, writer, reader)
    except _DECOMPRESS_ERRORS as exc:
        error = f"{type(exc).__name__}: {exc}"
    writer.finish(truncated_reason, error)
    if truncated_reason == "time":
        raise ModuleTimeout()
    return True


def read_small(absolute, limit=65536):
    """Read a small text file (configuration, /proc) or return None."""
    try:
        raw, _ = open_regular_file(absolute)
    except (OSError, ValueError):
        return None
    try:
        with raw:
            return raw.read(limit).decode("utf-8", errors="replace")
    except OSError:  # opened but unreadable (I/O error): treat as missing
        return None


def hash_file(run, absolute, expect=None):
    """SHA-256 of a regular file, read safely. With `expect` (an lstat
    result), the file opened must be that same file. Returns (hex digest,
    None) or (None, reason)."""
    try:
        raw, info = open_regular_file(absolute)
    except (OSError, ValueError) as exc:
        return None, str(exc)
    digest = hashlib.sha256()
    with raw:
        if expect is not None and (info.st_dev, info.st_ino) != (expect.st_dev, expect.st_ino):
            return None, "replaced while being read"
        try:
            while True:
                if run.out_of_time():
                    return None, "time limit"
                block = raw.read(CHUNK_BYTES)
                if not block:
                    break
                digest.update(block)
        except OSError as exc:
            return None, str(exc)
    return digest.hexdigest(), None


# --- Walking directories -----------------------------------------------------------


def _open_directory(absolute):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(path(absolute), flags | getattr(os, "O_NOATIME", 0))
    except PermissionError:
        return os.open(path(absolute), flags)


def _join(directory, name):
    return directory.rstrip("/") + "/" + name


class Walk:
    """A bounded walk of one directory tree. It never follows a symbolic
    link, never descends into another file system, and stops at its depth,
    entry and time limits; `summary()` then says what was cut short, so a gap
    is never mistaken for "nothing there".

    Iterating yields one dict per entry, the top directory first. Regular
    files up to `hash_bytes` are hashed: all of them with hash_files="all",
    only those with an execute bit with "executable", none with None. The top
    is depth 0; a directory at `max_depth` is listed but not descended. When
    time runs out the walk just stops; the caller records the summary and
    then calls run.check_time()."""

    def __init__(
        self, run, top, max_depth=8, max_entries=20000, hash_bytes=1 << 20, hash_files="executable"
    ):
        self.run = run
        self.top = top
        self.max_depth = max_depth
        self.max_entries = max_entries
        self.hash_bytes = hash_bytes
        self.hash_files = hash_files
        self.entries = 0
        self.errors = 0
        self.not_descended = {"depth": 0, "other_filesystem": 0}
        self.truncated_reason = None

    def summary(self):
        return {
            "top": self.top,
            "entries": self.entries,
            "errors": self.errors,
            "not_descended": dict(self.not_descended),
            "truncated": self.truncated_reason is not None,
            "truncated_reason": self.truncated_reason,
        }

    def _entry(self, absolute, info, link_target=None):
        entry = {
            "path": absolute,
            "type": stat.filemode(info.st_mode)[0],
            "mode": format(stat.S_IMODE(info.st_mode), "04o"),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "size": info.st_size,
            "nlink": info.st_nlink,
            "inode": info.st_ino,
            "mtime": iso_from_timestamp(info.st_mtime),
            "ctime": iso_from_timestamp(info.st_ctime),
        }
        if link_target is not None:
            entry["link_target"] = link_target
        if stat.S_ISREG(info.st_mode) and self._wants_hash(info):
            if info.st_size > self.hash_bytes:
                entry["hash_skipped"] = f"larger than {self.hash_bytes} bytes"
            else:
                digest, problem = hash_file(self.run, absolute, expect=info)
                if digest:
                    entry["sha256"] = digest
                else:
                    entry["hash_skipped"] = problem
        return entry

    def _wants_hash(self, info):
        if self.hash_files == "all":
            return True
        return self.hash_files == "executable" and bool(info.st_mode & 0o111)

    def _stop(self):
        """True, with the reason recorded, once a limit is reached."""
        if self.run.out_of_time():
            self.truncated_reason = "time"
        elif self.entries >= self.max_entries:
            self.truncated_reason = "entries"
        return self.truncated_reason is not None

    def _counted(self, entry):
        self.entries += 1
        if "error" in entry:
            self.errors += 1
        return entry

    def __iter__(self):
        try:
            top_info = os.lstat(path(self.top))
        except OSError as exc:
            yield self._counted({"path": self.top, "error": str(exc)})
            return
        link_target = None
        if stat.S_ISLNK(top_info.st_mode):
            try:
                link_target = os.readlink(path(self.top))
            except OSError as exc:
                yield self._counted({"path": self.top, "error": str(exc)})
                return
        top_entry = self._entry(self.top, top_info, link_target)
        if stat.S_ISDIR(top_info.st_mode) and self.max_depth <= 0:
            top_entry["not_descended"] = "depth"
            self.not_descended["depth"] += 1
        yield self._counted(top_entry)
        if "not_descended" in top_entry or not stat.S_ISDIR(top_info.st_mode):
            return
        device = top_info.st_dev
        # Each directory is opened by path, so it must still be the directory
        # that was listed (same device and inode): if a parent was swapped for
        # a symbolic link meanwhile, the path leads somewhere else, and the
        # walk records that instead of following it.
        pending = [(self.top, 0, (top_info.st_dev, top_info.st_ino))]
        while pending:
            if self._stop():
                return
            directory, depth, identity = pending.pop()
            try:
                fd = _open_directory(directory)
            except OSError as exc:
                yield self._counted({"path": directory, "error": str(exc)})
                continue
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != identity:
                    yield self._counted({"path": directory, "error": "replaced during the walk"})
                    continue
                with os.scandir(fd) as listing:
                    for item in listing:
                        if self._stop():
                            return
                        absolute = _join(directory, item.name)
                        try:
                            info = item.stat(follow_symlinks=False)
                            link_target = None
                            if stat.S_ISLNK(info.st_mode):
                                link_target = os.readlink(item.name, dir_fd=fd)
                        except OSError as exc:
                            yield self._counted({"path": absolute, "error": str(exc)})
                            continue
                        entry = self._entry(absolute, info, link_target)
                        if stat.S_ISDIR(info.st_mode):
                            if info.st_dev != device:
                                entry["not_descended"] = "other_filesystem"
                                self.not_descended["other_filesystem"] += 1
                            elif depth + 1 >= self.max_depth:
                                entry["not_descended"] = "depth"
                                self.not_descended["depth"] += 1
                            else:
                                pending.append((absolute, depth + 1, (info.st_dev, info.st_ino)))
                        yield self._counted(entry)
            except OSError as exc:  # the listing failed part-way
                yield self._counted({"path": directory, "error": str(exc)})
            finally:
                os.close(fd)


# --- Running allow-listed commands -------------------------------------------------

# The only commands the collector may run (DESIGN.md §5.4), each by absolute
# path. Settings can't add to this list or change it; every run records the
# command line, the executable's hash, the exit status and its error output.
COMMANDS = {
    "journalctl": ("/usr/bin/journalctl", "/bin/journalctl"),
}
# A fixed, minimal environment: nothing from the login session reaches a command.
_COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"}
_STDERR_KEEP = 4096


class CommandFailed(Exception):
    """A command ran but failed: the module's collection is incomplete."""


def find_command(name):
    """The executable for an allow-listed command, if it is safe to run: a
    regular file owned by root (or by the collector's own user, for tests)
    that only its owner can change. Returns (absolute path, stat result,
    None) or (None, None, reason)."""
    reasons = []
    for candidate in COMMANDS[name]:
        try:
            info = os.stat(path(candidate))
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            reasons.append(candidate + " is not a regular file")
        elif info.st_uid not in (0, os.geteuid()):
            reasons.append(candidate + " is not owned by root")
        elif info.st_mode & 0o022:
            reasons.append(candidate + " is writable by group or others")
        else:
            return candidate, info, None
    return None, None, "; ".join(reasons) or "not installed"


def run_command(run, module, name, args, transform=None):
    """Run an allow-listed command and send its output as a source, masked
    line by line like a file. The command is killed when the module's time
    runs out or its output reaches the size cap. Returns its exit code, or
    None if it could not be run (recorded instead). After closing the
    source, raises ModuleTimeout if time ran out, or CommandFailed if the
    command exited with a non-zero status of its own accord."""
    executable, info, problem = find_command(name)
    if executable is None:
        run.stream.record(module, "command_unavailable", {"command": name, "reason": problem})
        return None
    digest, _ = hash_file(run, executable)
    meta = file_meta(info, None)
    del meta["compressed"]
    meta.update({"argv": [executable] + list(args), "executable_sha256": digest})
    try:
        # Not subprocess.DEVNULL: that opens /dev/null read-write, which is an
        # open-for-write on the target (the read-only proof flags it).
        no_input = os.open(os.devnull, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        run.stream.record(module, "command_unavailable", {"command": name, "reason": str(exc)})
        return None
    try:
        process = subprocess.Popen(  # noqa: S603 - allow-listed executable, fixed arguments
            [path(executable)] + list(args),
            stdin=no_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_COMMAND_ENV,
            cwd="/",
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        run.stream.record(module, "command_unavailable", {"command": name, "reason": str(exc)})
        return None
    finally:
        os.close(no_input)

    finished_reading = threading.Event()
    killed = {"time": False}

    def kill_group():
        # The whole process group, even after its leader has exited: a child
        # still holding the pipes would otherwise keep the readers waiting.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass

    def on_deadline():
        if not finished_reading.is_set():
            killed["time"] = True
        kill_group()

    watchdog = threading.Timer(max(0.0, run.deadline - time.monotonic()), on_deadline)
    watchdog.daemon = True
    watchdog.start()
    # Drain error output alongside, so a full pipe can't stall the command.
    errors = {"kept": b"", "more": False}

    def drain():
        for block in iter(lambda: process.stderr.read(CHUNK_BYTES), b""):
            room = _STDERR_KEEP - len(errors["kept"])
            if len(block) > room:
                errors["more"] = True
            errors["kept"] += block[: max(room, 0)]

    drainer = threading.Thread(target=drain, daemon=True)
    drainer.start()

    writer = SourceWriter(run, module, "command", shlex.join(meta["argv"]), meta)
    try:
        with process.stdout:
            truncated_reason = pump_lines(run, writer, process.stdout, transform)
            if truncated_reason is not None:
                kill_group()
    finally:
        exit_code = process.wait()
        # Error output can stay open after stdout closes; the watchdog still
        # ends it at the deadline.
        drainer.join(timeout=max(0.0, run.deadline - time.monotonic()) + 5)
        finished_reading.set()
        watchdog.cancel()
        kill_group()  # nothing the command started outlives it
        process.stderr.close()
    if killed["time"]:
        truncated_reason = "time"
    stderr = errors["kept"]
    if (errors["more"] or truncated_reason) and not stderr.endswith(b"\n"):
        errors["more"] = True
    if errors["more"]:
        # Cut at the cap: withhold the partial last line, which masking might
        # not recognise once cut.
        stderr = stderr[: stderr.rfind(b"\n") + 1]
    stderr, stderr_masked = mask_text(stderr)
    for kind, count in stderr_masked.items():
        writer.masker.counts[kind] = writer.masker.counts.get(kind, 0) + count
    extra = {"exit_code": exit_code, "stderr": stderr.decode("utf-8", errors="replace")}
    if errors["more"]:
        extra["stderr_truncated"] = True
    writer.finish(truncated_reason, extra=extra)
    if truncated_reason == "time":
        raise ModuleTimeout()
    if truncated_reason is None and exit_code != 0:
        raise CommandFailed(f"{name} exited with status {exit_code}")
    return exit_code


# --- Resource use -------------------------------------------------------------------


def resource_usage():
    """Peak memory (KiB) and CPU time of the collector and, separately, of
    the commands it ran. None where this Python lacks `resource`."""
    if resource is None:
        return None
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "peak_rss_kb": own.ru_maxrss,
        "cpu_seconds": round(own.ru_utime + own.ru_stime, 3),
        "commands_peak_rss_kb": children.ru_maxrss,
        "commands_cpu_seconds": round(children.ru_utime + children.ru_stime, 3),
    }


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
    module = "host_facts"

    def record(module, name, data):
        run.check_time()  # between facts, so the deadline holds here too
        run.stream.record(module, name, data)

    run.check_time()
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
    # If /var/log can't be listed, let the error end the module: main() then
    # marks it "error" and the run "partial", rather than "ok" with no logs.
    names = os.listdir(path("/var/log"))
    candidates = []
    for name in names:
        if not _AUTH_LOG.match(name):
            continue
        absolute = "/var/log/" + name
        try:
            info = os.lstat(path(absolute))
        except OSError:
            continue
        candidates.append((info.st_mtime, absolute, stat.S_ISREG(info.st_mode)))

    since = run.since.timestamp()
    sent = skipped = 0
    for mtime, absolute, regular in sorted(candidates):
        run.check_time()
        # Only a regular file can be "old news". Anything else (a link to
        # /dev/null, a pipe) is always described: the replacement is evidence.
        if regular and mtime < since:
            skipped += 1  # last written before the window: nothing in it is new
            continue
        if send_file(run, module, absolute):
            sent += 1
    run.stream.record(
        module,
        "summary",
        {"files_found": len(candidates), "files_sent": sent, "files_before_window": skipped},
    )


# The journal fields the checks use. Others (the full command line, say) are
# never requested; journalctl adds its cursor, times and boot id itself.
JOURNAL_FIELDS = (
    "_SOURCE_REALTIME_TIMESTAMP",
    "_HOSTNAME",
    "_TRANSPORT",
    "SYSLOG_FACILITY",
    "SYSLOG_IDENTIFIER",
    "SYSLOG_PID",
    "PRIORITY",
    "MESSAGE",
    "_PID",
    "_UID",
    "_GID",
    "_COMM",
    "_EXE",
    "_SYSTEMD_UNIT",
    "_AUDIT_SESSION",
    "_AUDIT_LOGINUID",
)
# Syslog facilities 4 (auth) and 10 (authpriv): what /var/log/secure and
# auth.log hold. Matches on the same field are alternatives.
JOURNAL_AUTH_MATCHES = ("SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10")


def _field_masker(masker, field):
    """One Masker per journal field for the whole source, so a private key
    logged across several entries' MESSAGE stays masked to its end, while
    one field's state never affects another's."""
    fields = masker.__dict__.setdefault("journal_fields", {})
    if field not in fields:
        fields[field] = Masker()
    return fields[field]


def _mask_bytes(masker, field, data):
    field_masker = _field_masker(masker, field)
    before = dict(field_masker.counts)
    masked = b"".join(field_masker.line(line) for line in data.splitlines(keepends=True))
    for kind, count in field_masker.counts.items():
        added = count - before.get(kind, 0)
        if added:
            masker.counts[kind] = masker.counts.get(kind, 0) + added
    return masked


def _mask_journal_value(value, masker, field):
    """Mask one decoded journal field. journalctl writes a field that is not
    valid UTF-8 as an array of byte values, and a field that occurs more than
    once as an array of values; both are masked item by item."""
    if isinstance(value, str):
        masked = _mask_bytes(masker, field, value.encode("utf-8", errors="surrogatepass"))
        return masked.decode("utf-8", errors="replace")
    if isinstance(value, list):
        if value and all(isinstance(b, int) and 0 <= b <= 255 for b in value):
            return list(_mask_bytes(masker, field, bytes(value)))
        return [_mask_journal_value(item, masker, field) for item in value]
    return value


def mask_journal_line(line, masker):
    """Mask one line of `journalctl --output=json`. Masking works on the
    decoded values, never on the JSON text, where escaping would hide quotes
    from the rules and a rule could swallow JSON delimiters. A line that
    can't be parsed is not sent (fail closed)."""
    try:
        entry = json.loads(line)
    except ValueError:
        entry = None
    if not isinstance(entry, dict):
        masker.counts["unparsed_line"] = masker.counts.get("unparsed_line", 0) + 1
        return b"[MASKED:unparsed_line %d bytes]\n" % len(line)
    entry = {key: _mask_journal_value(value, masker, key) for key, value in entry.items()}
    try:
        return (json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    except UnicodeEncodeError:  # a lone surrogate in a field name
        masker.counts["unparsed_line"] = masker.counts.get("unparsed_line", 0) + 1
        return b"[MASKED:unparsed_line %d bytes]\n" % len(line)


def module_auth_journal(run):
    """Authentication messages from the systemd journal, within the window."""
    args = [
        "--output=json",
        "--no-pager",
        "--quiet",
        # Without --all, JSON output replaces any field over 4 KiB with null,
        # silently; the collector's own line limit handles long ones instead.
        "--all",
        f"--since=@{int(run.since.timestamp())}",
        "--output-fields=" + ",".join(JOURNAL_FIELDS),
    ]
    run_command(
        run,
        "auth_journal",
        "journalctl",
        args + list(JOURNAL_AUTH_MATCHES),
        transform=mask_journal_line,
    )


# Collection modules, by name, in their default order.
MODULES = {
    "host_facts": module_host_facts,
    "auth_log": module_auth_log,
    "auth_journal": module_auth_journal,
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
            "commands_allowed": {name: list(paths) for name, paths in COMMANDS.items()},
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
            "resources": resource_usage(),
        }
    )
    stream.close()
    return 0
