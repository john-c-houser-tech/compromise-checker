"""Reading a stored bundle: decrypted straight into the reader, never to
disk, and walked record by record and line by line (DESIGN.md §6)."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Protocol

import pyrage
from pyrage import x25519

from checker.evidence import EvidenceError
from checker.protocol import (
    Chunk,
    Error,
    Manifest,
    ProtocolError,
    Record,
    SourceEnd,
    SourceStart,
    StreamReader,
    Trailer,
)

# A line longer than this is cut where it reaches it (the collector already
# withholds lines over 1 MiB, so only a broken source gets here).
MAX_LINE = 2 * 1024 * 1024


class Consumer(Protocol):
    """What a bundle walk calls, in stream order."""

    def manifest(self, manifest: Manifest) -> None: ...
    def record(self, record: Record) -> None: ...
    def source_start(self, start: SourceStart) -> None: ...
    def line(self, start: SourceStart, line: bytes) -> None: ...
    def source_end(self, start: SourceStart, end: SourceEnd) -> None: ...
    def error(self, error: Error) -> None: ...
    def trailer(self, trailer: Trailer) -> None: ...


class _Walk:
    """The writer pyrage decrypts into: decompresses, checks the protocol,
    joins each source's chunks into whole lines and calls the consumer."""

    def __init__(self, consumer: Consumer) -> None:
        self.consumer = consumer
        self.reader = StreamReader()
        self.open: dict[int, tuple[SourceStart, bytearray]] = {}
        self.problem: str | None = None

    def write(self, data: bytes) -> int:
        if self.problem is None:
            try:
                for item in self.reader.feed(data):
                    self._dispatch(item)
            except ProtocolError as exc:
                self.problem = str(exc)
        return len(data)

    def flush(self) -> None:
        pass

    def finish(self) -> None:
        if self.problem is not None:
            return
        try:
            for item in self.reader.finish():
                self._dispatch(item)
        except ProtocolError as exc:
            self.problem = str(exc)
        for start, pending in self.open.values():  # cut off: what arrived still counts
            if pending:
                self.consumer.line(start, bytes(pending))
        self.open.clear()

    def _dispatch(self, item: Any) -> None:
        if isinstance(item, Manifest):
            self.consumer.manifest(item)
        elif isinstance(item, Record):
            self.consumer.record(item)
        elif isinstance(item, SourceStart):
            self.open[item.source_id] = (item, bytearray())
            self.consumer.source_start(item)
        elif isinstance(item, Chunk):
            start, pending = self.open[item.source_id]
            data = (
                base64.b64decode(item.data)
                if item.encoding == "base64"
                else item.data.encode("utf-8", "surrogateescape")
            )
            pending.extend(data)
            *lines, rest = bytes(pending).split(b"\n")
            for line in lines:
                self.consumer.line(start, line)
            if len(rest) > MAX_LINE:
                self.consumer.line(start, rest[:MAX_LINE])
                rest = b""
            self.open[item.source_id] = (start, bytearray(rest))
        elif isinstance(item, SourceEnd):
            start, pending = self.open.pop(item.source_id)
            if pending:
                self.consumer.line(start, bytes(pending))
            self.consumer.source_end(start, item)
        elif isinstance(item, Error):
            self.consumer.error(item)
        elif isinstance(item, Trailer):
            self.consumer.trailer(item)


def walk_bundle(path: Path, identity: x25519.Identity, consumer: Consumer) -> str | None:
    """Decrypt a bundle into `consumer`. Returns the protocol problem that
    stopped the walk early, if any (what came before it was delivered)."""
    walk = _Walk(consumer)
    try:
        with open(path, "rb") as source:
            pyrage.decrypt_io(source, walk, [identity])
    except (pyrage.DecryptError, OSError) as exc:
        raise EvidenceError(f"cannot decrypt {path}: {exc}") from exc
    walk.finish()
    return walk.problem
