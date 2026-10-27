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
import binascii
import datetime
import glob
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
# base64 token alone on the line; a PEM header; a blank line; or, when the
# key began after a log prefix (a key logged line by line), a line whose
# message is one base64 token straight after that same program tag. Any
# other line ends the block and is masked normally, so a fake "BEGIN" line
# can hide nothing but base64 — never the log lines after it.
_BASE64 = rb"[A-Za-z0-9+/]+={0,2}"  # "=" only as padding at the end
_KEY_LINE = re.compile(rb"^(\s*)" + _BASE64 + rb"(\s*)$")
_KEY_HEADER = re.compile(rb"(?:^|\s)(?:Proc-Type|DEK-Info):\s")
# Longer than any real PEM private key (a 16384-bit RSA key is under 200).
MAX_KEY_LINES = 256


class Masker:
    """Masks secrets line by line. Holds state across lines for key blocks."""

    def __init__(self):
        self.counts = {}
        self._in_key_block = False
        self._key_lines = 0
        self._key_tail = None  # continuation pattern for a key logged after a prefix

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
        match = self._key_tail.match(data) if self._key_tail else None
        if match is None:
            return None
        # A key logged line by line: keep the log prefix, which is evidence,
        # masked by the ordinary rules like any other text.
        self._key_lines += 1
        return self._apply_rules(match.group(1)) + MASK % b"private_key" + match.group(2)

    def _start_key_block(self, prefix):
        """Enter a key block. With a log prefix before the BEGIN marker, its
        last word (the program tag, such as "app[1]:") is what continuation
        lines must carry."""
        self._in_key_block, self._key_lines, self._key_tail = True, 0, None
        words = prefix.split()
        if words:
            self._key_tail = re.compile(
                rb"^((?:.*\s)?" + re.escape(words[-1]) + rb"\s+)" + _BASE64 + rb"(\s*)$"
            )

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
                self._start_key_block(data[: begin.start()])
                rest = b"\n" if data.endswith(b"\n") else b""
            # The text before the key still goes through every rule below.
            data = data[: begin.start()] + MASK % b"private_key" + rest
        return self._apply_rules(data)

    def _apply_rules(self, data):
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
        self._protected = None

    def protected(self):
        """Inodes of files whose contents are never sent (see protected_inodes)."""
        if self._protected is None:
            self._protected = protected_inodes()
        return self._protected

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
        if not line.endswith(b"\n") and len(line) <= MAX_LINE and run.out_of_time():
            # Cut off by the deadline (a command killed mid-line): masking
            # might not recognise a secret's unfinished end, so withhold it.
            return "time"
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
    if (info.st_dev, info.st_ino) in run.protected():
        # The file actually opened — through any link or hard link — is one
        # collected as status or metadata only: never send its text.
        raw.close()
        details = describe_unreadable(absolute)
        details["reason"] = "is (or links to) a protected file; its contents are never sent"
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


# --- Accounts and access (DESIGN.md §8.3) ------------------------------------------

ACCOUNT_FILE_BYTES = 8 * 1024 * 1024
CONFIG_FILE_BYTES = 1024 * 1024
MAX_INCLUDE_DEPTH = 8
MAX_DIR_FILES = 1024


def path_facts(absolute):
    """Type, owner, mode, size and times of a path, without following a final
    symbolic link (its target is recorded instead). None if it doesn't exist."""
    try:
        info = os.lstat(path(absolute))
    except FileNotFoundError:
        return None
    except OSError as exc:
        return {"path": absolute, "error": str(exc)}
    facts = {
        "path": absolute,
        "type": stat.filemode(info.st_mode)[0],
        "mode": format(stat.S_IMODE(info.st_mode), "04o"),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "size": info.st_size,
        "inode": info.st_ino,
        "mtime": iso_from_timestamp(info.st_mtime),
        "ctime": iso_from_timestamp(info.st_ctime),
    }
    if stat.S_ISLNK(info.st_mode):
        try:
            facts["link_target"] = os.readlink(path(absolute))
        except OSError as exc:
            facts["error"] = str(exc)
    return facts


def glob_absolute(pattern):
    """Paths matching a glob pattern, as absolute paths on the target."""
    matches = glob.glob(path(pattern))
    if ROOT == "/":
        return sorted(matches)
    root = ROOT.rstrip("/")
    return sorted("/" + match[len(root) :].lstrip("/") for match in matches)


def _hash_algorithm(value):
    """Name the password hash scheme from its prefix. Never returns any part
    of the hash itself."""
    if value.startswith("$"):
        ident = value.split("$")[1] if value.count("$") >= 2 else ""
        return {
            "1": "md5",
            "2a": "bcrypt",
            "2b": "bcrypt",
            "2x": "bcrypt",
            "2y": "bcrypt",
            "5": "sha256",
            "6": "sha512",
            "7": "scrypt",
            "y": "yescrypt",
            "gy": "gost-yescrypt",
            "sha1": "sha1",
            "md5": "sun-md5",
        }.get(ident, "unknown")
    if len(value) == 13 and re.match(r"^[./0-9A-Za-z]{13}$", value):
        return "des"
    if len(value) == 20 and value.startswith("_"):
        return "bsdi-des"
    return "unknown"


def password_status(field):
    """What a password field says, never what it holds: "empty" (anyone can
    log in), "no_password" (none set, e.g. "*" or "!!"), "locked" (a hash
    behind "!"), or "set"; with the hash algorithm where there is one."""
    if field == "":
        return {"status": "empty"}
    locked = field.startswith("!")
    value = field.lstrip("!")
    if value == "" or value.startswith("*"):
        return {"status": "no_password"}
    return {"status": "locked" if locked else "set", "algorithm": _hash_algorithm(value)}


def _days(value):
    try:
        return int(value)
    except ValueError:
        return None


def _date_from_days(days):
    if days is None or days < 0:
        return None
    try:
        return (datetime.date(1970, 1, 1) + datetime.timedelta(days=days)).isoformat()
    except OverflowError:
        return None


def read_accounts():
    """Accounts from /etc/passwd as dicts (name, uid, gid, home, shell, and
    the password field's status), plus the numbers of malformed lines.
    None if the file can't be read."""
    text = read_small("/etc/passwd", ACCOUNT_FILE_BYTES)
    if text is None:
        return None, []
    accounts, malformed = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7 or not fields[0]:
            malformed.append(number)
            continue
        name, password_field, uid, gid, _gecos, home, shell = fields
        account = {
            "name": name,
            "uid": _days(uid),
            "gid": _days(gid),
            "home": home,
            "shell": shell,
            "line": number,
        }
        # "x": the password is in /etc/shadow. Anything else is the password
        # field itself (a hash in /etc/passwd is a finding), reduced to its status.
        shadowed = password_field == "x"  # noqa: S105 - the marker, not a password
        account["password"] = (
            {"status": "shadowed"} if shadowed else password_status(password_field)
        )
        accounts.append(account)
    return accounts, malformed


# Files collected only as status or metadata (policy §7): account files
# that hold password hashes, old hashes, and shell history. send_file refuses them by inode, so no
# configuration link or hard link can carry their contents out.
PROTECTED_FILES = (
    "/etc/passwd",  # can hold hashes too; read only through read_accounts()
    "/etc/passwd-",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/security/opasswd",
)


def protected_inodes():
    candidates = list(PROTECTED_FILES)
    accounts, _ = read_accounts()
    for home in discover_homes(accounts)[0]:
        candidates.extend(_join(home["home"], name) for name in HISTORY_FILES)
    inodes = set()
    for absolute in candidates:
        try:
            info = os.stat(path(absolute))
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode):
            inodes.add((info.st_dev, info.st_ino))
    return inodes


HISTORY_FILES = (
    ".bash_history",
    ".zsh_history",
    ".histfile",
    ".sh_history",
    ".ash_history",
    ".history",
    ".local/share/fish/fish_history",
    ".mysql_history",
    ".psql_history",
    ".python_history",
    ".sqlite_history",
)


# Home directories are found on disk as well as in /etc/passwd: domain
# accounts (SSSD, LDAP, Active Directory, winbind) log in through NSS without
# appearing there, and their keys and history count just the same. NSS itself
# is not asked: with SSSD's defaults it lists no domain users, and a lookup
# can reach the directory server and write SSSD's cache on the target.
HOME_ROOTS = ("/home",)
MAX_HOME_ENTRIES = 20000
_SSSD_HOMEDIR = re.compile(
    r"^\s*(override_homedir|fallback_homedir|homedir_substring)\s*=\s*(.+?)\s*$", re.I
)


def sssd_home_roots():
    """Fixed leading part of SSSD's home directory templates, e.g. /home for
    /home/%d/%u. Only these settings are read; nothing of sssd.conf, which
    can hold a bind password, is ever sent."""
    roots = []
    for absolute in ["/etc/sssd/sssd.conf"] + glob_absolute("/etc/sssd/conf.d/*.conf"):
        for line in (read_small(absolute, CONFIG_FILE_BYTES) or "").splitlines():
            match = _SSSD_HOMEDIR.match(line)
            if not match:
                continue
            value = match.group(2).replace("%H", "/home")
            fixed = []
            for part in value.split("/")[1:]:
                if "%" in part or not part:
                    break
                fixed.append(part)
            root = "/" + "/".join(fixed)
            if value.startswith("/") and root != "/" and root not in roots:
                roots.append(root)
    return roots


def _looks_like_home(directory):
    return any(os.path.lexists(path(_join(directory, name))) for name in (".ssh",) + HISTORY_FILES)


def discover_homes(accounts, run=None):
    """Every home directory: each /etc/passwd account's, plus unlisted ones
    found on disk — a directory one or two levels below a home root (/home,
    the parents of regular users' homes, SSSD's templates) holding .ssh or a
    shell history file. Returns (homes, summary): each home is {"home",
    "accounts", "source"}, with "owner_uid" for an unlisted one."""
    homes = {}
    for account in accounts or ():
        if account["home"]:
            entry = homes.setdefault(
                account["home"], {"home": account["home"], "accounts": [], "source": "passwd"}
            )
            entry["accounts"].append(account["name"])
    roots = list(HOME_ROOTS)
    for account in accounts or ():
        parent = os.path.dirname(account["home"].rstrip("/"))
        if (account["uid"] or 0) >= 1000 and parent not in ("", "/") and parent not in roots:
            roots.append(parent)
    roots.extend(root for root in sssd_home_roots() if root not in roots)

    examined, truncated = 0, False
    pending = [(root, 1) for root in roots]
    while pending and not truncated:
        directory, depth = pending.pop(0)
        try:
            fd = _open_directory(directory)
        except OSError:
            continue
        try:
            with os.scandir(fd) as listing:
                names = sorted(e.name for e in listing if e.is_dir(follow_symlinks=False))
        except OSError:
            names = []
        finally:
            os.close(fd)
        for name in names:
            examined += 1
            if examined > MAX_HOME_ENTRIES or (run is not None and run.out_of_time()):
                truncated = True
                break
            child = _join(directory, name)
            if child in homes:
                continue
            if _looks_like_home(child):
                try:
                    owner = os.lstat(path(child)).st_uid
                except OSError:
                    continue
                homes[child] = {
                    "home": child,
                    "accounts": [],
                    "source": "directory",
                    "owner_uid": owner,
                }
            elif depth < 2:
                pending.append((child, depth + 1))  # e.g. /home/<domain>/<user>
    summary = {
        "roots": roots,
        "examined": examined,
        "truncated": truncated,
        "unlisted": sorted(h for h, e in homes.items() if e["source"] == "directory"),
    }
    return [homes[h] for h in sorted(homes)], summary


def module_accounts(run):
    """Local accounts, groups and password status (never hashes), and facts
    about shell history files (never their contents)."""
    module = "accounts"
    record = run.stream.record
    for absolute in ("/etc/passwd", "/etc/group", "/etc/shadow"):
        facts = path_facts(absolute)
        if facts is not None:
            record(module, "account_file", facts)

    accounts, malformed = read_accounts()
    if accounts is None:
        raise OSError("/etc/passwd could not be read")
    for account in accounts:
        record(module, "account", account)
    if malformed:
        # Line numbers only: a malformed line could hold anything.
        record(module, "malformed_lines", {"path": "/etc/passwd", "lines": malformed})
    run.check_time()

    text = read_small("/etc/group", ACCOUNT_FILE_BYTES)
    if text is None:
        details = describe_unreadable("/etc/group")
        details["reason"] = "could not be read"
        record(module, "unreadable_file", details)
    bad = []
    for number, line in enumerate((text or "").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 4 or not fields[0]:
            bad.append(number)
            continue
        members = [m for m in fields[3].split(",") if m]
        record(
            module,
            "group",
            {"name": fields[0], "gid": _days(fields[2]), "members": members, "line": number},
        )
    if bad:
        record(module, "malformed_lines", {"path": "/etc/group", "lines": bad})
    run.check_time()

    # /etc/shadow is reduced to status here, on the server: the hashes are
    # never sent (policy §7; decision 1 of the Phase 1 plan).
    text = read_small("/etc/shadow", ACCOUNT_FILE_BYTES)
    if text is None:
        details = describe_unreadable("/etc/shadow")
        details["reason"] = "could not be read"
        record(module, "unreadable_file", details)
    else:
        bad = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            fields = line.split(":")
            if len(fields) != 9 or not fields[0]:
                bad.append(number)
                continue
            last_change, expire = _days(fields[2]), _days(fields[7])
            data = {"name": fields[0], "line": number}
            data.update(password_status(fields[1]))
            data.update(
                {
                    "last_change_days": last_change,
                    "last_change": _date_from_days(last_change),
                    "min_days": _days(fields[3]),
                    "max_days": _days(fields[4]),
                    "warn_days": _days(fields[5]),
                    "inactive_days": _days(fields[6]),
                    "expire_days": expire,
                    "expire": _date_from_days(expire),
                }
            )
            record(module, "password_status", data)
        if bad:
            record(module, "malformed_lines", {"path": "/etc/shadow", "lines": bad})
    run.check_time()

    homes, summary = discover_homes(accounts, run)
    record(module, "homes", summary)
    for home in homes:
        run.check_time()
        for name in HISTORY_FILES:
            facts = path_facts(_join(home["home"], name))
            if facts is not None:
                facts["accounts"] = home["accounts"]
                if home["source"] == "directory":
                    facts.update({"home_source": "directory", "owner_uid": home["owner_uid"]})
                record(module, "shell_history", facts)


_SUDO_INCLUDE = re.compile(r"^\s*[#@](include|includedir)\s+(.+?)\s*$")


def resolve_links(absolute):
    """`absolute` with every symbolic link resolved, as a path on the
    target; None if it leads outside the test fixture root."""
    resolved = os.path.realpath(path(absolute))
    if ROOT == "/":
        return resolved
    root = ROOT.rstrip("/")
    if not resolved.startswith(root + "/"):
        return None
    return resolved[len(root) :]


def send_config_file(run, module, absolute):
    """Send a configuration file the way its program reads it: through
    symbolic links (RHEL's authselect and crypto-policies use them by
    design). A link is recorded, then its resolved target is sent, still only
    if that is a regular file. Returns the path sent, or None."""
    facts = path_facts(absolute)
    if facts is not None and facts.get("type") == "l":
        resolved = resolve_links(absolute)
        facts["resolved"] = resolved
        run.stream.record(module, "config_link", facts)
        if resolved is None:
            return None
        absolute = resolved
    return absolute if send_file(run, module, absolute) else None


def read_config_text(run, module, absolute):
    """A configuration file's text, for finding its directives. Only the
    first CONFIG_FILE_BYTES are searched; a longer file gets a record saying
    its directives may be incomplete."""
    text = read_small(absolute, CONFIG_FILE_BYTES) or ""
    try:
        size = os.stat(path(absolute)).st_size
    except OSError:
        size = 0
    if size > CONFIG_FILE_BYTES:
        run.stream.record(
            module,
            "directives_incomplete",
            {"path": absolute, "size": size, "searched_bytes": CONFIG_FILE_BYTES},
        )
    return text


def _sudo_include_path(target, including):
    target = target.strip()
    if len(target) >= 2 and target[0] == target[-1] == '"':
        target = target[1:-1]
    target = re.sub(r"\\(.)", r"\1", target)  # sudo's escapes: "\ " is a space, "\\" a backslash
    target = target.replace("%h", socket.gethostname().split(".")[0])
    if not target.startswith("/"):  # relative to the including file (sudo 1.9.1+)
        target = _join(os.path.dirname(including), target)
    return target


def _sudo_reads(name):
    """Whether sudo reads a file of this name from an included directory: it
    skips names ending in "~" or containing a "."."""
    return not name.endswith("~") and "." not in name


def module_sudoers(run):
    """/etc/sudoers and everything it includes, masked."""
    module = "sudoers"
    seen = set()
    pending = [("/etc/sudoers", 0)]
    while pending:
        run.check_time()
        absolute, depth = pending.pop(0)
        if absolute in seen:
            continue
        seen.add(absolute)
        sent = send_config_file(run, module, absolute)
        if sent is None:
            continue
        text = read_config_text(run, module, sent)
        for line in text.splitlines():
            match = _SUDO_INCLUDE.match(line)
            if not match:
                continue
            target = _sudo_include_path(match.group(2), absolute)
            if depth + 1 > MAX_INCLUDE_DEPTH:
                run.stream.record(
                    module, "include_not_followed", {"path": target, "reason": "depth"}
                )
                continue
            if match.group(1) == "include":
                pending.append((target, depth + 1))
                continue
            try:
                names = sorted(os.listdir(path(target)))
            except OSError as exc:
                run.stream.record(
                    module, "include_dir", {"path": target, "from": absolute, "error": str(exc)}
                )
                continue
            run.stream.record(
                module,
                "include_dir",
                {
                    "path": target,
                    "from": absolute,
                    "files": [{"name": n, "sudo_reads": _sudo_reads(n)} for n in names],
                    "truncated": len(names) > MAX_DIR_FILES,
                },
            )
            # Every file is sent, including those sudo skips: evidence either way.
            pending.extend((_join(target, n), depth + 1) for n in names[:MAX_DIR_FILES])


# --- SSH ------------------------------------------------------------------------------

_SSH_KEY_TYPE = re.compile(
    r"^(?:(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp(?:256|384|521))"
    r"(?:-cert-v01@openssh\.com)?"
    r"|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)(?:-cert-v01)?@openssh\.com)$"
)
# Public-key fields after the nonce in a certificate, by plain key type
# (OpenSSH PROTOCOL.certkeys): what the plain key's blob is rebuilt from.
_CERT_KEY_FIELDS = {
    "ssh-rsa": 2,
    "ssh-dss": 4,
    "ecdsa-sha2-nistp256": 2,
    "ecdsa-sha2-nistp384": 2,
    "ecdsa-sha2-nistp521": 2,
    "ssh-ed25519": 1,
    "sk-ecdsa-sha2-nistp256@openssh.com": 3,
    "sk-ssh-ed25519@openssh.com": 2,
}
# Options sshd accepts in authorized_keys; a line with any other is ignored.
SSH_KEY_OPTIONS = frozenset(
    "agent-forwarding cert-authority command environment expiry-time from"
    " no-agent-forwarding no-port-forwarding no-pty no-touch-required no-user-rc"
    " no-x11-forwarding permitlisten permitopen port-forwarding principals pty restrict"
    " tunnel user-rc verify-required x11-forwarding".split()
)
# Variable names whose values are secrets (as in the masking rules).
_SECRET_NAME = re.compile(
    r"(?i:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth(?!orization))|pwd"
)
DEFAULT_AUTHORIZED_KEYS = (".ssh/authorized_keys", ".ssh/authorized_keys2")
MAX_KEY_FILE_BYTES = 1024 * 1024


def _split_token(text):
    """The first whitespace-delimited token, treating "quoted strings" (with
    backslash escapes) as part of it, and the rest of the text."""
    quoted, escaped = False, False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char in " \t" and not quoted:
            return text[:index], text[index:].lstrip(" \t")
    return text, ""


def _mask_str(text):
    return mask_text(text.encode("utf-8"))[0].decode("utf-8", "replace")


def ssh_key_options(options):
    """authorized_keys options as a list of {"name", "value"}, each value
    decoded as sshd decodes it and only then masked, so a quoted secret
    can't leave a fragment behind. An option sshd doesn't know (which makes
    it ignore the line) is masked and marked "known": false."""
    items, current, quoted, escaped = [], "", False, False
    for char in options + ",":
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            items.append(current)
            current = ""
            continue
        current += char
    result = []
    for item in items:
        if not item:
            continue
        name, has_value, value = item.partition("=")
        name = name.strip().lower()
        if name not in SSH_KEY_OPTIONS:
            # sshd ignores the line; nothing of an unknown option is sent.
            result.append({"known": False, "length": len(item)})
            continue
        option = {"name": name}
        if has_value:
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1].replace('\\"', '"')  # sshd's only escape
            if name == "environment" and "=" in value:
                variable, _, setting = value.partition("=")
                upper = variable.upper()
                # MYSQL_PWD and the like; PWD and OLDPWD are directories.
                pwd = upper.endswith("PWD") and upper not in ("PWD", "OLDPWD")
                if pwd or _SECRET_NAME.search(variable):
                    value = variable + "=[MASKED:password]"
                else:
                    value = variable + "=" + _mask_str(setting)
            else:
                value = _mask_str(value)
            option["value"] = value
        result.append(option)
    return result


def _ssh_string_end(blob, start):
    """End of the length-prefixed string at `start`; ValueError if it overruns."""
    if start + 4 > len(blob):
        raise ValueError("truncated")
    end = start + 4 + int.from_bytes(blob[start : start + 4], "big")
    if end > len(blob):
        raise ValueError("truncated")
    return end


def plain_key_blob(blob, cert_type):
    """The plain public key inside a certificate, which is what OpenSSH
    fingerprints (`ssh-keygen -l`, sshd's logs). None if it can't be read."""
    if cert_type.startswith("sk-"):  # the plain type keeps its @openssh.com
        plain = cert_type.replace("-cert-v01", "")
    else:
        plain = cert_type.replace("-cert-v01@openssh.com", "")
    count = _CERT_KEY_FIELDS.get(plain)
    if count is None:
        return None
    try:
        position = _ssh_string_end(blob, 0)  # the certificate type
        position = _ssh_string_end(blob, position)  # the nonce
        start = position
        for _ in range(count):
            position = _ssh_string_end(blob, position)
    except ValueError:
        return None
    name = plain.encode("ascii")
    return len(name).to_bytes(4, "big") + name + blob[start:position]


def parse_authorized_key(line):
    """One authorized_keys line as facts: key type, SHA-256 fingerprint (as
    sshd logs it), options and comment. None if it isn't a public key line.
    The key itself is never returned."""
    first, rest = _split_token(line.strip())
    options = None
    if not _SSH_KEY_TYPE.match(first):
        options = first
        first, rest = _split_token(rest)
        if not _SSH_KEY_TYPE.match(first):
            return None
    blob_text, comment = _split_token(rest)
    try:
        blob = base64.b64decode(blob_text, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(blob) < 4:
        return None
    length = int.from_bytes(blob[:4], "big")
    if length > len(blob) - 4:
        return None
    embedded = blob[4 : 4 + length].decode("ascii", errors="replace")
    if not _SSH_KEY_TYPE.match(embedded):
        return None  # not a key inside: never echo what it holds
    certificate = "-cert-v01" in embedded
    key_blob = plain_key_blob(blob, embedded) if certificate else blob
    if key_blob is None:
        return None
    fingerprint = base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
    key = {"type": first, "fingerprint": "SHA256:" + fingerprint, "key_bytes": len(blob)}
    if certificate:
        key["certificate"] = True  # fingerprint of the key inside, as OpenSSH gives it
    if embedded != first:
        key["embedded_type"] = embedded  # the line's type and the key's disagree
    if options is not None:
        key["options"] = ssh_key_options(options)
    comment = comment.strip()
    if comment:
        key["comment"] = _mask_str(comment)
    return key


def _expand_key_path(pattern, account):
    """An AuthorizedKeysFile pattern for one account, or None if it uses a
    token this collector doesn't know."""
    out, index = [], 0
    while index < len(pattern):
        char = pattern[index]
        if char == "%" and index + 1 < len(pattern):
            letter = pattern[index + 1]
            value = {"%": "%", "h": account["home"], "u": account["name"]}.get(letter)
            if letter == "h" and not account["home"]:
                return None
            if letter == "U":
                value = str(account["uid"])
            if value is None:
                return None
            out.append(value)
            index += 2
            continue
        out.append(char)
        index += 1
    expanded = "".join(out)
    if expanded.startswith("~/"):
        expanded = _join(account["home"], expanded[2:])
    if not expanded.startswith("/"):
        expanded = _join(account["home"], expanded)
    return expanded


def links_on_path(absolute):
    """Every symbolic link among the components of `absolute`, the last one
    included, as {"path", "target"} dicts in order from the root."""
    links, current = [], ""
    for part in absolute.strip("/").split("/"):
        current += "/" + part
        try:
            if stat.S_ISLNK(os.lstat(path(current)).st_mode):
                links.append({"path": current, "target": os.readlink(path(current))})
        except OSError:
            break
    return links


def send_authorized_keys(run, module, account, absolute, extra=None):
    """Facts about one authorized_keys file: the file, then one record per key.

    Symbolic links are followed, as sshd follows them: a key reached through
    a link grants access like any other, so it must be listed. The links are
    recorded. Following them is safe because nothing but public keys'
    fingerprints, options and comments is ever taken from the file."""
    record = run.stream.record
    target = absolute
    links = links_on_path(absolute)
    if links:
        target = resolve_links(absolute)
        record(
            module,
            "authorized_keys_link",
            {"account": account["name"], "path": absolute, "resolved": target, "links": links},
        )
        if target is None:
            return
    try:
        raw, info = open_regular_file(target)
    except (OSError, ValueError) as exc:
        details = describe_unreadable(target)
        details.update({"account": account["name"], "reason": str(exc)})
        record(module, "unreadable_file", details)
        return
    with raw:
        if (info.st_dev, info.st_ino) in run.protected():
            details = describe_unreadable(target)
            details.update(
                {
                    "account": account["name"],
                    "reason": "is (or links to) a protected file; its contents are never read",
                }
            )
            record(module, "unreadable_file", details)
            return
        try:
            data = raw.read(MAX_KEY_FILE_BYTES + 1)
        except OSError as exc:
            record(module, "unreadable_file", {"path": absolute, "reason": str(exc)})
            return
    truncated = len(data) > MAX_KEY_FILE_BYTES
    if truncated:
        # Whole lines only: an unfinished one might not mask correctly.
        data = data[: data.rfind(b"\n", 0, MAX_KEY_FILE_BYTES) + 1]
    keys, not_keys = 0, []
    for number, line in enumerate(data.splitlines(), 1):
        text = line.decode("utf-8", errors="replace")
        if not text.strip() or text.lstrip().startswith("#"):
            continue
        key = parse_authorized_key(text)
        if key is None:
            not_keys.append(number)  # line numbers only: it could be anything
            continue
        key.update({"account": account["name"], "path": absolute, "line": number})
        key.update(extra or {})
        if target != absolute:
            key["resolved"] = target
        record(module, "authorized_key", key)
        keys += 1
    facts = file_meta(info, None)
    del facts["compressed"]
    facts.update(
        {
            "account": account["name"],
            "path": absolute,
            "resolved": target,
            "keys": keys,
            "lines_not_keys": not_keys,
            "truncated": truncated,
        }
    )
    facts.update(extra or {})
    record(module, "authorized_keys_file", facts)


class SshdConfig:
    """Reads sshd_config as sshd does: Include lines are expanded in place,
    the first global AuthorizedKeysFile wins, and a Match block lasts to the
    next Match line or the end of its file. Every file read is sent."""

    def __init__(self, run, module):
        self.run, self.module = run, module
        self.sent = {}  # path → the path actually sent (links resolved), or None
        self.global_keys = None  # None: not set, so sshd's defaults apply
        self.match_keys = []

    def read(self, absolute, depth, in_match):
        self.run.check_time()
        if depth > MAX_INCLUDE_DEPTH:
            self.run.stream.record(
                self.module, "include_not_followed", {"path": absolute, "reason": "depth"}
            )
            return
        # Each file is sent once; one included twice is still read again in
        # its new place, as sshd would.
        if absolute not in self.sent:
            self.sent[absolute] = send_config_file(self.run, self.module, absolute)
        if self.sent[absolute] is None:
            return
        text = read_config_text(self.run, self.module, self.sent[absolute])
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = re.split(r"[\s=]+", stripped, maxsplit=1)
            keyword = parts[0].lower()
            try:
                args = shlex.split(parts[1], comments=True) if len(parts) == 2 else []
            except ValueError:
                args = parts[1].split()
            if keyword == "match":
                in_match = True
            elif keyword == "include":
                for pattern in args:
                    if not pattern.startswith("/"):
                        pattern = "/etc/ssh/" + pattern
                    for match in glob_absolute(pattern):
                        self.read(match, depth + 1, in_match)
            elif keyword == "authorizedkeysfile" and args:
                if in_match:
                    self.match_keys.extend(a for a in args if a not in self.match_keys)
                elif self.global_keys is None:
                    self.global_keys = args


def module_ssh(run):
    """sshd_config and its includes (masked), and every account's authorized
    keys as fingerprints, options and comments — never the keys themselves."""
    module = "ssh"
    config = SshdConfig(run, module)
    config.read("/etc/ssh/sshd_config", 0, False)
    if config.global_keys is None:
        global_patterns = list(DEFAULT_AUTHORIZED_KEYS)
    else:
        global_patterns = [p for p in config.global_keys if p.lower() != "none"]
    patterns = list(global_patterns)
    for value in config.match_keys:
        if value.lower() != "none" and value not in patterns:
            patterns.append(value)
    run.stream.record(
        module,
        "authorized_keys_locations",
        {
            "patterns": patterns,
            "global": global_patterns,
            "global_set": config.global_keys is not None,
            # Locations set inside Match blocks apply only to some logins;
            # their keys are collected too, since any of them may be used.
            "match": config.match_keys,
        },
    )

    accounts, _ = read_accounts()
    if accounts is None:
        raise OSError("/etc/passwd could not be read")
    homes, _ = discover_homes(accounts, run)
    owners = []  # (account-like dict, extra fields for its records)
    owners.extend((account, None) for account in accounts)
    for home in homes:
        ssh_dir = path_facts(_join(home["home"], ".ssh"))
        if ssh_dir is not None:
            ssh_dir["accounts"] = home["accounts"]
            if home["source"] == "directory":
                ssh_dir.update({"home_source": "directory", "owner_uid": home["owner_uid"]})
            run.stream.record(module, "ssh_dir", ssh_dir)
        if home["source"] == "directory":
            # A home with no local account (a domain user's): its name is
            # unknown, so only locations that don't need one apply.
            unlisted = {"name": None, "home": home["home"], "uid": home["owner_uid"]}
            extra = {
                "home_source": "directory",
                "home": home["home"],
                "owner_uid": home["owner_uid"],
            }
            owners.append((unlisted, extra))

    read = set()
    for account, extra in owners:
        run.check_time()
        candidates = []
        for pattern in patterns:
            expanded = _expand_key_path(pattern, account)
            if expanded is not None and expanded not in candidates:
                candidates.append(expanded)
        for candidate in candidates:
            try:
                os.lstat(path(candidate))
            except FileNotFoundError:
                continue
            except OSError:
                pass  # described as unreadable below
            read.add(candidate)
            send_authorized_keys(run, module, account, candidate, extra)

    # Absolute per-user locations (/etc/ssh/keys/%u): files there that no
    # local account accounts for may belong to domain users; list them too.
    for pattern in patterns:
        if not pattern.startswith("/") or not re.search(r"%[uU]", pattern):
            continue
        template = pattern.replace("%%", "\0")
        if re.search(r"%[^uU]", template):
            continue
        wildcard = re.sub(r"%[uU]", "*", template).replace("\0", "%")
        for candidate in glob_absolute(wildcard):
            if candidate not in read:
                run.check_time()
                read.add(candidate)
                nobody = {"name": None, "home": "", "uid": None}
                send_authorized_keys(run, module, nobody, candidate, {"unattributed": True})


# --- PAM ----------------------------------------------------------------------------

PAM_MODULE_DIRS = (
    "/usr/lib64/security",
    "/usr/lib/security",
    "/usr/lib/*/security",
    "/lib64/security",
    "/lib/security",
    "/lib/*/security",
)


def module_pam(run):
    """PAM configuration (masked) and a hashed listing of the PAM module
    directories, so an added or replaced module shows."""
    module = "pam"
    names = []
    if path_facts("/etc/pam.conf") is not None:
        names.append("/etc/pam.conf")
    try:
        entries = sorted(os.listdir(path("/etc/pam.d")))
    except OSError as exc:
        run.stream.record(module, "unreadable_file", {"path": "/etc/pam.d", "reason": str(exc)})
        entries = []
    names.extend("/etc/pam.d/" + name for name in entries[:MAX_DIR_FILES])
    run.stream.record(
        module,
        "config_dir",
        {"path": "/etc/pam.d", "entries": len(entries), "truncated": len(entries) > MAX_DIR_FILES},
    )
    for absolute in names:
        run.check_time()
        send_config_file(run, module, absolute)

    seen = set()
    for pattern in PAM_MODULE_DIRS:
        for found in glob_absolute(pattern):
            # Walk the real directory: Walk never follows a link at its top,
            # and the inode seen must be the one walked.
            directory = resolve_links(found)
            if directory is None:
                continue
            try:
                info = os.lstat(path(directory))
            except OSError:
                continue
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) in seen:
                continue  # /lib is often a link to /usr/lib: list each directory once
            seen.add((info.st_dev, info.st_ino))
            walk = Walk(
                run, directory, max_depth=2, max_entries=5000, hash_bytes=8 << 20, hash_files="all"
            )
            for entry in walk:
                run.stream.record(module, "module_file", entry)
            run.stream.record(module, "walk_summary", walk.summary())
            run.check_time()


# Collection modules, by name, in their default order.
MODULES = {
    "host_facts": module_host_facts,
    "auth_log": module_auth_log,
    "auth_journal": module_auth_journal,
    "accounts": module_accounts,
    "sudoers": module_sudoers,
    "ssh": module_ssh,
    "pam": module_pam,
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
