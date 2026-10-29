"""The collector protocol, controller side (docs/collector-protocol.md).

These models are the authoritative definition of the settings sent to the
collector and of every record in the stream it returns. A contract test runs
the real collector and validates its output against them.
"""

import base64
import binascii
import hashlib
import json
import zlib
from collections.abc import Iterable, Iterator
from datetime import datetime
from importlib.resources import files
from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

PROTOCOL = 1

HomeText = Literal["off", "privileged", "all"]
# Whose program starts are collected from the audit log (policy §7): the
# web server's accounts; also root, service and administrator accounts;
# or, with that, every account.
ExecRecords = Literal["web", "privileged", "all"]
MAX_WEB_ROOTS = 64
MAX_WEB_USERS = 64
_ACCOUNT_NAME = r"^[A-Za-z0-9_.][A-Za-z0-9_.@\\$-]{0,255}$"


def check_web_roots(value: list[str] | None) -> list[str] | None:
    """Web roots as the collector takes them: absolute paths, no ".." or
    NUL, at most MAX_WEB_ROOTS of them. None means the collector's defaults."""
    if value is None:
        return None
    if len(value) > MAX_WEB_ROOTS:
        raise ValueError(f"at most {MAX_WEB_ROOTS} web roots")
    for root in value:
        if not root.startswith("/") or "\0" in root or ".." in root.split("/") or len(root) > 4096:
            raise ValueError(f"not an absolute path without '..': {root!r}")
    return value


class _Model(BaseModel):
    # Unknown fields are allowed so a newer collector can add optional fields
    # without breaking an older controller (protocol doc §4).
    model_config = ConfigDict(extra="allow", frozen=True)


# --- Settings (controller → collector) ---------------------------------------


class Limits(_Model):
    overall_seconds: float = Field(gt=0)
    module_seconds: float = Field(gt=0)
    source_bytes: int = Field(gt=0)


class Settings(_Model):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: Literal[1] = PROTOCOL
    run_id: str = Field(min_length=1)
    since: AwareDatetime
    modules: list[str] | None = None
    limits: Limits
    # Text of home start-up files and user units (policy §7): never, only
    # privileged accounts' homes, or every home. Hashes are always sent.
    home_text: HomeText = "off"
    # Directories listed for web shells (DESIGN.md §8.6); None: the
    # collector's common defaults, a list (even empty) replaces them.
    web_roots: list[str] | None = None
    # The organization's mail key (policy §7): mail log addresses are
    # fingerprinted with it on the server. None: no mail log is sent. The
    # manifest shows only its identifier, and repr never shows it.
    mail_key: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$", repr=False)
    # Why the controller didn't send the key to this host, if it didn't.
    mail_key_withheld: str | None = Field(default=None, max_length=300)
    # Web access logs, opt-in (policy §7); error logs are always collected.
    web_access_logs: bool = False
    exec_records: ExecRecords = "web"
    # Web-server accounts beyond www-data, apache, nginx and the like.
    web_users: list[Annotated[str, Field(pattern=_ACCOUNT_NAME)]] = Field(
        default=[], max_length=MAX_WEB_USERS
    )

    @field_validator("web_roots")
    @classmethod
    def _valid_web_roots(cls, value: list[str] | None) -> list[str] | None:
        return check_web_roots(value)


# --- Stream records (collector → controller) ----------------------------------


class Host(_Model):
    hostname: str
    os_id: str | None
    os_version_id: str | None
    os_pretty_name: str | None
    kernel: str
    machine: str
    boot_id: str | None


class PythonInfo(_Model):
    version: str
    executable: str


class Manifest(_Model):
    type: Literal["manifest"]
    protocol: int
    collector_version: str
    run_id: str | None
    started_at: datetime
    host: Host
    python: PythonInfo
    effective_uid: int
    settings: dict[str, Any] | None
    modules_planned: list[str]
    masking_version: int | None = None
    priority: dict[str, Any] | None = None
    commands_allowed: dict[str, list[str]] | None = None


class Record(_Model):
    type: Literal["record"]
    module: str
    name: str
    data: dict[str, Any]


class SourceStart(_Model):
    type: Literal["source_start"]
    source_id: int = Field(ge=1)
    module: str
    kind: Literal["file", "command", "proc"]
    name: str
    meta: dict[str, Any] = {}


class Chunk(_Model):
    type: Literal["chunk"]
    source_id: int = Field(ge=1)
    seq: int = Field(ge=0)
    encoding: Literal["utf-8", "base64"]
    data: str

    @model_validator(mode="after")
    def _payload_matches_encoding(self) -> "Chunk":
        if self.encoding == "base64":
            try:
                base64.b64decode(self.data, validate=True)
            except binascii.Error:
                raise PydanticCustomError(
                    "invalid_base64", "chunk data is not valid base64"
                ) from None
        return self


class SourceEnd(_Model):
    type: Literal["source_end"]
    source_id: int = Field(ge=1)
    chunks: int = Field(ge=0)
    bytes: int = Field(ge=0)
    truncated: bool
    truncated_reason: str | None = None
    masked: dict[str, int] = {}
    error: str | None = None
    # Commands only: how the command ended (negative: killed by that signal)
    # and the start of its error output, masked.
    exit_code: int | None = None
    stderr: str | None = None
    stderr_truncated: bool = False


class Error(_Model):
    type: Literal["error"]
    module: str | None
    message: str


class Counts(_Model):
    records: int
    sources: int
    chunks: int
    errors: int


class ModuleResult(_Model):
    status: Literal["ok", "error", "timeout", "skipped"]
    seconds: float


class Trailer(_Model):
    type: Literal["trailer"]
    finished_at: datetime
    duration_seconds: float
    status: Literal["complete", "partial", "refused"]
    counts: Counts
    modules: dict[str, ModuleResult]
    resources: dict[str, Any] | None = None


StreamRecord = Annotated[
    Manifest | Record | SourceStart | Chunk | SourceEnd | Error | Trailer,
    Field(discriminator="type"),
]
_record_adapter: TypeAdapter[StreamRecord] = TypeAdapter(StreamRecord)


# --- Building the program sent to the target ----------------------------------


def collector_source() -> str:
    """The collector program text, exactly as shipped."""
    return (files("checker") / "collector" / "collector.py").read_text(encoding="utf-8")


def collector_sha256(source: str | None = None) -> str:
    """The collector's fingerprint: SHA-256 of the program text sent (doc §1)."""
    text = collector_source() if source is None else source
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_program(settings: Settings, source: str | None = None) -> str:
    """Collector text plus the final `main(...)` call carrying the settings."""
    text = collector_source() if source is None else source
    # Both layers ASCII-only: the inner JSON escapes non-ASCII characters
    # (a Python literal would turn an outer \U escape pair into two lone
    # surrogates), and an ASCII JSON string literal is also a valid Python
    # string literal, so nothing inside the settings can break out of the call.
    settings_json = json.dumps(settings.model_dump(mode="json"), ensure_ascii=True)
    call = "main(" + json.dumps(settings_json, ensure_ascii=True) + ")"
    return text.rstrip("\n") + "\n\n" + call + "\n"


# --- Reading the stream --------------------------------------------------------


class ProtocolError(ValueError):
    """The stream breaks the protocol: malformed, out of order, or inconsistent."""


class IncompleteStream(ProtocolError):
    """The stream ended without a trailer."""


def _known_field_names() -> frozenset[str]:
    models = (Manifest, Host, PythonInfo, Record, SourceStart, Chunk, SourceEnd, Error, Trailer)
    names = {name for model in (*models, Counts, ModuleResult) for name in model.model_fields}
    return frozenset(names)


def _describe(exc: ValidationError) -> str:
    """A validation failure without any of the offending input: only field
    names this protocol defines, and Pydantic's error *codes*. Its messages
    and anything else in a location (dictionary keys, an invalid type tag)
    can quote the input, and this text is stored unencrypted."""
    known = _known_field_names()
    problems = []
    for error in exc.errors(include_input=False, include_url=False, include_context=False):
        parts = [
            str(part) if isinstance(part, int) or part in known else "?" for part in error["loc"]
        ]
        problems.append(f"{'.'.join(parts) or 'record'}: {error['type']}")
    return "; ".join(problems[:5])


# The largest single record the reader will hold while waiting for its end.
# Real records are far smaller (a chunk carries at most a 1 MiB line, about
# 6 MiB once JSON-escaped); anything bigger is refused, not buffered.
MAX_RECORD = 16 * 1024 * 1024
_INFLATE_STEP = 1024 * 1024


class StreamChecker:
    """Validates decompressed JSON Lines one line at a time, checking order
    and consistency, so a stream can be checked as it arrives."""

    def __init__(self) -> None:
        self.manifest: Manifest | None = None
        self.trailer: Trailer | None = None
        self._open_source: SourceStart | None = None
        self._next_seq = 0
        self._seen_source_ids: set[int] = set()
        self._number = 0
        self.counts = {"records": 0, "sources": 0, "chunks": 0, "errors": 0}

    def feed_line(self, raw: bytes) -> StreamRecord | None:
        """Check one line; returns its record (None for a blank line)."""
        self._number += 1
        number = self._number
        if not raw.strip():
            return None
        if self.trailer is not None:
            raise ProtocolError(f"line {number}: data after the trailer")
        try:
            data = json.loads(raw)
        except ValueError as exc:  # JSONDecodeError messages carry positions, not content
            raise ProtocolError(f"line {number}: not valid JSON ({exc})") from None
        try:
            record = _record_adapter.validate_python(data)
        except ValidationError as exc:
            # Never quote the input: it can be evidence, and this message is
            # stored unencrypted.
            raise ProtocolError(f"line {number}: {_describe(exc)}") from None

        counts, open_source = self.counts, self._open_source
        if self.manifest is None:
            if not isinstance(record, Manifest):
                raise ProtocolError(f"line {number}: first record must be the manifest")
            if record.protocol != PROTOCOL:
                raise ProtocolError(f"unsupported protocol version {record.protocol}")
            self.manifest = record
        elif isinstance(record, Manifest):
            raise ProtocolError(f"line {number}: second manifest")
        elif open_source is not None and not isinstance(record, Chunk | SourceEnd):
            raise ProtocolError(f"line {number}: source {open_source.source_id} not ended")
        elif isinstance(record, Record):
            counts["records"] += 1
        elif isinstance(record, Error):
            counts["errors"] += 1
        elif isinstance(record, SourceStart):
            if record.source_id in self._seen_source_ids:
                raise ProtocolError(f"line {number}: source_id {record.source_id} reused")
            self._seen_source_ids.add(record.source_id)
            self._open_source, self._next_seq = record, 0
            counts["sources"] += 1
        elif isinstance(record, Chunk):
            if open_source is None or record.source_id != open_source.source_id:
                raise ProtocolError(f"line {number}: chunk for a source that is not open")
            if record.seq != self._next_seq:
                raise ProtocolError(
                    f"line {number}: chunk seq {record.seq}, expected {self._next_seq}"
                )
            self._next_seq += 1
            counts["chunks"] += 1
        elif isinstance(record, SourceEnd):
            if open_source is None or record.source_id != open_source.source_id:
                raise ProtocolError(f"line {number}: end of a source that is not open")
            if record.chunks != self._next_seq:
                raise ProtocolError(
                    f"line {number}: source {record.source_id} says {record.chunks} chunks, "
                    f"stream had {self._next_seq}"
                )
            self._open_source = None
        elif isinstance(record, Trailer):
            self.trailer = record
            # Only the counters this reader knows; newer ones are allowed (doc §4).
            declared = {key: getattr(record.counts, key) for key in counts}
            if declared != counts:
                raise ProtocolError(f"trailer counts {declared} do not match stream {counts}")
        return record

    def finish(self) -> None:
        if self.trailer is None:
            raise IncompleteStream("stream ended without a trailer")


def parse_lines(lines: Iterable[bytes]) -> Iterator[StreamRecord]:
    """Validate decompressed JSON Lines, checking order and consistency."""
    checker = StreamChecker()
    for raw in lines:
        record = checker.feed_line(raw)
        if record is not None:
            yield record
    checker.finish()


class StreamReader:
    """Decompresses and checks a stream fed in arbitrary pieces, as it
    arrives over SSH or out of a decrypting bundle."""

    def __init__(self) -> None:
        self.checker = StreamChecker()
        self._inflate = zlib.decompressobj(wbits=31)  # gzip
        self._partial = b""

    def feed(self, data: bytes) -> Iterator[StreamRecord]:
        """Yields records as each bounded step is decoded, so a read packed
        with many small records is never held in memory all at once."""
        pending = data
        while pending:
            if self._inflate.eof:
                raise ProtocolError("data after the end of the gzip stream")
            try:
                # Inflate in bounded steps: a small, highly compressed input
                # must not be able to expand all at once.
                text = self._inflate.decompress(pending, _INFLATE_STEP)
            except zlib.error as exc:
                raise ProtocolError(f"not a valid gzip stream: {exc}") from exc
            pending = self._inflate.unconsumed_tail
            if self._inflate.eof and self._inflate.unused_data:
                raise ProtocolError("data after the end of the gzip stream")
            yield from self._lines(text)

    def _lines(self, text: bytes) -> Iterator[StreamRecord]:
        *lines, partial = (self._partial + text).split(b"\n")
        if len(partial) > MAX_RECORD:
            raise ProtocolError(f"a record longer than {MAX_RECORD} bytes")
        self._partial = partial
        for raw in lines:
            record = self.checker.feed_line(raw)
            if record is not None:
                yield record

    def finish(self) -> list[StreamRecord]:
        # A cut-off stream is incomplete, whatever its half-received last line says.
        if not self._inflate.eof:
            raise IncompleteStream("gzip stream cut off before its end")
        records = []
        if self._partial:
            record = self.checker.feed_line(self._partial)
            self._partial = b""
            if record is not None:
                records.append(record)
        self.checker.finish()
        return records


def read_stream(compressed: bytes) -> list[StreamRecord]:
    """Decompress and validate a whole stream held in memory."""
    if compressed[:2] != b"\x1f\x8b":
        raise ProtocolError("not a valid gzip stream: no gzip header")
    reader = StreamReader()
    records = list(reader.feed(compressed))
    return records + reader.finish()
