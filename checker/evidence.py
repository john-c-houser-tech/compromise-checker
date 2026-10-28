"""Evidence bundles (DESIGN.md §3.4, §5.1 step 5, §6).

A bundle is one collection from one host, stored exactly as it arrived:
encrypted with `age` to the organization's key as it streams in, so no
plaintext evidence ever touches the controller's disk; hashed before and
after encryption; checked against the protocol on the way; and recorded with
an append-only chain of custody. Bundles are never modified once written.
"""

import asyncio
import getpass
import hashlib
import json
import os
import socket
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyrage
import yaml
from pydantic import BaseModel, ConfigDict, Field
from pyrage import x25519

from checker.files import atomic_write, locked
from checker.protocol import (
    Error,
    HomeText,
    IncompleteStream,
    Manifest,
    ProtocolError,
    SourceEnd,
    SourceStart,
    StreamReader,
    StreamRecord,
    Trailer,
)


class EvidenceError(Exception):
    """Something about stored evidence is wrong or missing; the message says what."""


# --- Configuration -------------------------------------------------------------


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipients: list[str]  # age public keys bundles are encrypted to
    identity_file: str | None = None  # where the matching private key is, if here
    retention_days: int = Field(default=90, ge=1)
    # Opt-in chosen in `checker init` (policy §7); see protocol HomeText.
    home_text: HomeText = "off"


def config_file(home: Path) -> Path:
    return home / "config.yaml"


def database_file(home: Path) -> Path:
    return home / "checker.db"


def load_config(home: Path) -> Config:
    path = config_file(home)
    if not path.exists():
        raise EvidenceError(f"not set up yet: run `checker init` (no {path})")
    return Config.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


def initialise(
    home: Path, recipient: str | None = None, home_text: HomeText = "off"
) -> tuple[Config, Path | None]:
    """Create the tool's directory, evidence key and database. With
    `recipient`, bundles are encrypted to that key and its private half stays
    wherever the organization keeps it; otherwise a key pair is made here."""
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    # One init at a time: two interleaved could publish a key in the config
    # whose private half the other had just replaced, leaving evidence unreadable.
    with locked(config_file(home)):
        if config_file(home).exists():
            raise EvidenceError(f"already set up ({config_file(home)}); nothing changed")
        return _initialise(home, recipient, home_text)


def _initialise(
    home: Path, recipient: str | None, home_text: HomeText
) -> tuple[Config, Path | None]:
    identity_path = None
    if recipient:
        try:
            x25519.Recipient.from_str(recipient)
        except pyrage.RecipientError as exc:
            raise EvidenceError(f"not an age public key: {recipient}") from exc
        recipients = [recipient]
    else:
        identity = x25519.Identity.generate()
        identity_path = home / "keys" / "evidence-identity.txt"
        identity_path.parent.mkdir(exist_ok=True, mode=0o700)
        public = str(identity.to_public())
        atomic_write(
            identity_path,
            f"# Compromise Checker evidence key. Created {datetime.now(UTC):%Y-%m-%d}.\n"
            f"# public key: {public}\n"
            "# Without this file, stored evidence cannot be read. Back it up safely.\n"
            f"{identity}\n",
        )
        recipients = [public]
    config = Config(
        recipients=recipients,
        identity_file=str(identity_path) if identity_path else None,
        home_text=home_text,
    )
    Store(database_file(home)).close()
    atomic_write(config_file(home), yaml.safe_dump(config.model_dump(), sort_keys=False))
    return config, identity_path


def load_identity(path: Path) -> x25519.Identity:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise EvidenceError(f"cannot read the evidence key {path}: {exc}") from exc
    for line in lines:
        if line.startswith("AGE-SECRET-KEY-"):
            return x25519.Identity.from_str(line.strip())
    raise EvidenceError(f"no age private key in {path}")


# --- What a bundle contains ---------------------------------------------------------


@dataclass
class Summary:
    """The shape of a collection, without its content: enough to list and
    check bundles without decrypting them again."""

    manifest: dict[str, Any] | None = None
    trailer: dict[str, Any] | None = None
    sources: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    records: dict[str, int] = field(default_factory=dict)
    dropped: dict[str, int] = field(default_factory=dict)
    _open: dict[int, dict[str, Any]] = field(default_factory=dict, repr=False)

    # Bounded: a target controls how many sources, errors and record names it
    # sends, so beyond these limits entries are counted, not kept. The bundle
    # itself still holds everything.
    MAX_SOURCES = 10_000
    MAX_ERRORS = 1_000
    MAX_RECORD_NAMES = 1_000
    MAX_MESSAGE = 500

    def _drop(self, kind: str) -> None:
        self.dropped[kind] = self.dropped.get(kind, 0) + 1

    def add(self, record: StreamRecord) -> None:
        if isinstance(record, Manifest):
            self.manifest = record.model_dump(mode="json", exclude={"settings"})
        elif isinstance(record, Trailer):
            self.trailer = record.model_dump(mode="json")
        elif isinstance(record, SourceStart):
            self._open[record.source_id] = {
                "module": record.module,
                "kind": record.kind,
                "name": record.name,
                "size": record.meta.get("size"),
            }
        elif isinstance(record, SourceEnd):
            source = self._open.pop(record.source_id, {})
            source.update(
                bytes=record.bytes,
                truncated=record.truncated,
                truncated_reason=record.truncated_reason,
                masked=record.masked,
                error=record.error,
            )
            if len(self.sources) < self.MAX_SOURCES:
                self.sources.append(source)
            else:
                self._drop("sources")
        elif isinstance(record, Error):
            if len(self.errors) < self.MAX_ERRORS:
                message = record.message[: self.MAX_MESSAGE]
                self.errors.append({"module": record.module, "message": message})
            else:
                self._drop("errors")
        elif record.type == "record":
            key = f"{record.module}.{record.name}"[:200]
            if key in self.records or len(self.records) < self.MAX_RECORD_NAMES:
                self.records[key] = self.records.get(key, 0) + 1
            else:
                self._drop("record_names")

    def as_dict(self) -> dict[str, Any]:
        # A source cut off before its end still belongs in the summary.
        unfinished = [
            dict(source, bytes=None, masked=None, truncated=True, truncated_reason="unfinished")
            for source in self._open.values()
        ]
        return {
            "manifest": self.manifest,
            "trailer": self.trailer,
            "sources": self.sources + unfinished,
            "errors": self.errors,
            "records": self.records,
            "dropped": self.dropped,
        }


class _Observer:
    """Hashes plaintext and checks it against the protocol as it passes."""

    def __init__(self) -> None:
        self.sha256 = hashlib.sha256()
        self.bytes = 0
        self.reader = StreamReader()
        self.summary = Summary()
        self.problem: str | None = None

    def write(self, data: bytes) -> int:
        self.sha256.update(data)
        self.bytes += len(data)
        if self.problem is None:
            try:
                for record in self.reader.feed(data):
                    self.summary.add(record)
            except ProtocolError as exc:
                self.problem = str(exc)
        return len(data)

    def flush(self) -> None:
        pass

    def status(self) -> str:
        """complete / partial / refused (the collector's own word), or
        incomplete (cut off), broken (breaks the protocol), empty (no data)."""
        if self.problem is not None:
            return "broken"
        if self.bytes == 0:
            return "empty"
        try:
            for record in self.reader.finish():
                self.summary.add(record)
        except IncompleteStream:
            return "incomplete"
        except ProtocolError as exc:
            self.problem = str(exc)
            return "broken"
        return self.summary.trailer["status"]


class _HashingFile:
    def __init__(self, f) -> None:
        self._f = f
        self.sha256 = hashlib.sha256()
        self.bytes = 0

    def write(self, data: bytes) -> int:
        self.sha256.update(data)
        self.bytes += len(data)
        return self._f.write(data)

    def flush(self) -> None:
        self._f.flush()


@dataclass
class Sealed:
    """A finished bundle: where it is, what it hashes to, what it held."""

    path: Path
    status: str
    plaintext_sha256: str
    plaintext_bytes: int
    ciphertext_sha256: str
    ciphertext_bytes: int
    summary: Summary
    problem: str | None


class BundleWriter:
    """Receives a collection as it streams in and stores it encrypted.

    Plaintext goes through an OS pipe straight into `age` encryption in a
    worker thread; it is never written to disk. `write` waits for each piece
    to be accepted, so a slow disk slows the download instead of filling
    memory."""

    def __init__(self, path: Path, recipients: list[str]) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._file = open(path, "xb")  # noqa: SIM115 - closed in seal()
        os.chmod(path, 0o600)
        self._out = _HashingFile(self._file)
        self.observer = _Observer()
        keys = [x25519.Recipient.from_str(r) for r in recipients]
        read_fd, write_fd = os.pipe()
        self._pipe = os.fdopen(write_fd, "wb")
        self._failure: BaseException | None = None

        def encrypt() -> None:
            try:
                with os.fdopen(read_fd, "rb") as source:
                    pyrage.encrypt_io(source, self._out, keys)
            except BaseException as exc:  # reported by seal()
                self._failure = exc

        self._thread = threading.Thread(target=encrypt, name=f"encrypt {path.name}")
        self._thread.start()

    async def write(self, data: bytes) -> None:
        self.observer.write(data)
        await asyncio.to_thread(self._write_through, data)

    def _write_through(self, data: bytes) -> None:
        self._pipe.write(data)
        self._pipe.flush()

    def seal(self) -> Sealed:
        self._pipe.close()
        self._thread.join()
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()
        if self._failure is not None:
            raise EvidenceError(f"encrypting {self.path} failed: {self._failure}")
        status = self.observer.status()
        return Sealed(
            path=self.path,
            status=status,
            plaintext_sha256=self.observer.sha256.hexdigest(),
            plaintext_bytes=self.observer.bytes,
            ciphertext_sha256=self._out.sha256.hexdigest(),
            ciphertext_bytes=self._out.bytes,
            summary=self.observer.summary,
            problem=self.observer.problem,
        )


def judge(
    content_status: str, manifest: dict[str, Any] | None, run_id: str, exit_status: int | None
) -> tuple[str, str | None]:
    """The final status of a collection, from its content and how it ended.
    Used both when it is stored and when it is verified, so they agree."""
    if content_status not in ("complete", "partial", "refused"):
        return content_status, None
    echoed = (manifest or {}).get("run_id")
    if echoed != run_id and not (echoed is None and content_status == "refused"):
        # The echo exists so a stream can't be filed under the wrong run (protocol §2).
        return "broken", "the stream's run id is not this run's"
    if exit_status != 0:
        # Protocol §1: anything but a clean exit means the stream may be incomplete.
        return "incomplete", f"the collector's exit status was {exit_status}"
    return content_status, None


def open_bundle(path: Path, identity: x25519.Identity) -> _Observer:
    """Decrypt a bundle straight into the checker (never to disk)."""
    observer = _Observer()
    try:
        with open(path, "rb") as source:
            pyrage.decrypt_io(source, observer, [identity])
    except (pyrage.DecryptError, OSError) as exc:
        # A damaged file surfaces as an OSError ("decryption error") mid-stream.
        raise EvidenceError(f"cannot decrypt {path}: {exc}") from exc
    return observer


def seal_text(text: str | None, recipients: list[str]) -> bytes | None:
    """Encrypt a small piece of text (an index column) to the evidence key."""
    if text is None:
        return None
    keys = [x25519.Recipient.from_str(r) for r in recipients]
    return pyrage.encrypt(text.encode("utf-8"), keys)


def open_text(blob: bytes | None, identity: x25519.Identity) -> str | None:
    if blob is None:
        return None
    try:
        return pyrage.decrypt(blob, [identity]).decode("utf-8")
    except (pyrage.DecryptError, OSError) as exc:
        raise EvidenceError(f"cannot decrypt a stored detail: {exc}") from exc


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


# --- The store ------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS bundles (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    run_id TEXT NOT NULL,
    path TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    status TEXT NOT NULL,
    collector_version TEXT,
    collector_sha256 TEXT NOT NULL,
    plaintext_sha256 TEXT NOT NULL,
    plaintext_bytes INTEGER NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    ciphertext_bytes INTEGER NOT NULL,
    recipients TEXT NOT NULL,
    -- age-encrypted to the evidence key, like the bundle itself: what was
    -- collected, connection details and error text are evidence too.
    session BLOB,
    summary BLOB,
    problem BLOB
);
CREATE TABLE IF NOT EXISTS custody (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id TEXT NOT NULL REFERENCES bundles(id),
    at TEXT NOT NULL,
    action TEXT NOT NULL,
    operator TEXT NOT NULL,
    controller TEXT NOT NULL,
    detail TEXT
);
-- What the controller derived from a bundle (events, snapshots): files
-- encrypted to the evidence key like the bundle, regenerable from it, so
-- replaced when a newer parser runs (not append-only, unlike the bundle).
CREATE TABLE IF NOT EXISTS derived (
    bundle_id TEXT NOT NULL REFERENCES bundles(id),
    kind TEXT NOT NULL,
    parser_version INTEGER NOT NULL,
    path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    items INTEGER NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    summary BLOB,
    PRIMARY KEY (bundle_id, kind)
);
-- Each host's baseline over time: the snapshot later ones are compared
-- with (DESIGN.md §7). The first is set automatically; each later one is an
-- operator's accepted change, with who, where and (encrypted) why.
CREATE TABLE IF NOT EXISTS baselines (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    bundle_id TEXT NOT NULL REFERENCES bundles(id),
    at TEXT NOT NULL,
    how TEXT NOT NULL,
    operator TEXT NOT NULL,
    controller TEXT NOT NULL,
    reason BLOB
);
-- Each analysis of a bundle: the checks' findings, encrypted beside the
-- bundle. Kept, not replaced: a re-analysis with newer checks or another
-- baseline doesn't erase what an earlier one said.
CREATE TABLE IF NOT EXISTS assessments (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id TEXT NOT NULL REFERENCES bundles(id),
    host TEXT NOT NULL,
    at TEXT NOT NULL,
    checks_version INTEGER NOT NULL,
    baseline_id TEXT,
    path TEXT NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    summary BLOB
);
-- Each purge (policy §8): what it removed, by identifiers and counts only,
-- so a deleted bundle still shows it existed and why it is gone. Never
-- purged itself.
CREATE TABLE IF NOT EXISTS purges (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    operator TEXT NOT NULL,
    controller TEXT NOT NULL,
    scope TEXT NOT NULL,
    bundles TEXT NOT NULL,
    counts TEXT NOT NULL,
    baselines TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS purges_no_update BEFORE UPDATE ON purges
    BEGIN SELECT RAISE(ABORT, 'purges are append-only'); END;
CREATE TRIGGER IF NOT EXISTS purges_no_delete BEFORE DELETE ON purges
    BEGIN SELECT RAISE(ABORT, 'purges are append-only'); END;
"""


# Append-only, enforced by the database itself (DESIGN.md §3.4). Only
# `purge` lifts it, inside its own transaction (Store.purge).
APPEND_ONLY = (
    ("bundles", "bundles are"),
    ("custody", "custody is"),
    ("baselines", "baselines are"),
    ("assessments", "assessments are"),
)


def _append_only_triggers() -> list[str]:
    statements = []
    for table, label in APPEND_ONLY:
        for action in ("update", "delete"):
            statements.append(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action} BEFORE {action.upper()}"
                f" ON {table} BEGIN SELECT RAISE(ABORT, '{label} append-only'); END"
            )
    return statements


BUNDLE_COLUMNS = (
    "id",
    "host",
    "run_id",
    "path",
    "started_at",
    "ended_at",
    "status",
    "collector_version",
    "collector_sha256",
    "plaintext_sha256",
    "plaintext_bytes",
    "ciphertext_sha256",
    "ciphertext_bytes",
    "recipients",
    "session",
    "summary",
    "problem",
)
_INSERT_BUNDLE = "INSERT INTO bundles ({}) VALUES ({})".format(  # noqa: S608 - fixed names
    ", ".join(BUNDLE_COLUMNS), ", ".join(f":{name}" for name in BUNDLE_COLUMNS)
)


def who_and_where() -> tuple[str, str]:
    return getpass.getuser(), socket.gethostname()


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fresh = not path.exists()
        self._db = sqlite3.connect(path)
        if fresh:
            os.chmod(path, 0o600)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        # So INSERT OR REPLACE's implicit delete fires the append-only triggers.
        self._db.execute("PRAGMA recursive_triggers = ON")
        self._db.executescript(_SCHEMA + "".join(f"{sql};\n" for sql in _append_only_triggers()))

    def close(self) -> None:
        self._db.close()

    def record_bundle(self, row: dict[str, Any]) -> None:
        if set(row) != set(BUNDLE_COLUMNS):
            raise ValueError(f"bundle row fields differ from the schema: {sorted(row)}")
        operator, controller = who_and_where()
        with self._db:
            self._db.execute(_INSERT_BUNDLE, row)
            self._custody(row["id"], "collected", operator, controller, {"status": row["status"]})

    def custody(self, bundle_id: str, action: str, detail: dict[str, Any] | None = None) -> None:
        operator, controller = who_and_where()
        with self._db:
            self._custody(bundle_id, action, operator, controller, detail)

    def _custody(self, bundle_id, action, operator, controller, detail) -> None:
        self._db.execute(
            "INSERT INTO custody (bundle_id, at, action, operator, controller, detail)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                bundle_id,
                datetime.now(UTC).isoformat(),
                action,
                operator,
                controller,
                json.dumps(detail) if detail is not None else None,
            ),
        )

    def bundle(self, bundle_id: str) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM bundles WHERE id = ?", (bundle_id,)).fetchone()
        if row is None:
            raise EvidenceError(f"no bundle {bundle_id!r}")
        return row

    def bundles(self, host: str | None = None) -> list[sqlite3.Row]:
        if host:
            query = "SELECT * FROM bundles WHERE host = ? ORDER BY started_at"
            return self._db.execute(query, (host,)).fetchall()
        return self._db.execute("SELECT * FROM bundles ORDER BY started_at").fetchall()

    def record_derived(self, row: dict[str, Any]) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO derived (bundle_id, kind, parser_version, path,"
                " created_at, items, ciphertext_sha256, summary) VALUES (:bundle_id, :kind,"
                " :parser_version, :path, :created_at, :items, :ciphertext_sha256, :summary)",
                row,
            )

    def derived(self, bundle_id: str, kind: str) -> sqlite3.Row | None:
        return self._db.execute(
            "SELECT * FROM derived WHERE bundle_id = ? AND kind = ?", (bundle_id, kind)
        ).fetchone()

    def record_baseline(self, host: str, bundle_id: str, how: str, reason: bytes | None) -> None:
        """A new baseline for `host` (how: first, accepted or after purge), with its
        custody entry, in one transaction."""
        operator, controller = who_and_where()
        with self._db:
            self._db.execute(
                "INSERT INTO baselines (host, bundle_id, at, how, operator, controller, reason)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (host, bundle_id, datetime.now(UTC).isoformat(), how, operator, controller, reason),
            )
            self._custody(bundle_id, "baseline", operator, controller, {"how": how})

    def record_assessment(self, row: dict[str, Any]) -> None:
        operator, controller = who_and_where()
        with self._db:
            self._db.execute(
                "INSERT INTO assessments (bundle_id, host, at, checks_version, baseline_id, path,"
                " ciphertext_sha256, summary) VALUES (:bundle_id, :host, :at, :checks_version,"
                " :baseline_id, :path, :ciphertext_sha256, :summary)",
                row,
            )
            self._custody(
                row["bundle_id"],
                "analysed",
                operator,
                controller,
                {"checks_version": row["checks_version"], "baseline": row["baseline_id"]},
            )

    def assessments(self, bundle_id: str) -> list[sqlite3.Row]:
        return self._db.execute(
            "SELECT * FROM assessments WHERE bundle_id = ? ORDER BY seq", (bundle_id,)
        ).fetchall()

    def hosts(self) -> list[str]:
        return [r[0] for r in self._db.execute("SELECT DISTINCT host FROM bundles ORDER BY host")]

    def baselines(self, host: str) -> list[sqlite3.Row]:
        return self._db.execute(
            "SELECT * FROM baselines WHERE host = ? ORDER BY seq", (host,)
        ).fetchall()

    def custody_of(self, bundle_id: str) -> list[sqlite3.Row]:
        return self._db.execute(
            "SELECT * FROM custody WHERE bundle_id = ? ORDER BY seq", (bundle_id,)
        ).fetchall()

    def purge_state(self, host: str) -> list[Any]:
        """What a purge plan for `host` depends on: its current baseline
        (the latest row's sequence number) and how many bundles it has."""
        latest = self._db.execute(
            "SELECT MAX(seq) FROM baselines WHERE host = ?", (host,)
        ).fetchone()[0]
        count = self._db.execute("SELECT COUNT(*) FROM bundles WHERE host = ?", (host,)).fetchone()
        return [latest, count[0]]

    def purge(
        self,
        bundle_ids: list[str],
        scope: dict[str, Any],
        baselines: dict[str, str],
        expect: dict[str, list[Any]] | None = None,
    ) -> dict[str, int]:
        """Delete these bundles and everything recorded about them, and add
        a `purges` row saying what went (policy §8): the one sanctioned way
        to delete. The append-only triggers are dropped and recreated inside
        the same transaction, so a failure leaves them, and every row, in
        place. `baselines` maps each host whose baseline goes to what
        happens to it ("moved" or "emptied"). `expect` is each affected
        host's purge_state when the purge was planned: if another command
        changed it since (a new baseline, a new bundle), nothing is deleted.
        Returns the rows deleted per table."""
        if not bundle_ids:
            raise ValueError("nothing to purge")
        operator, controller = who_and_where()
        marks = ", ".join("?" for _ in bundle_ids)
        hosts = {}
        counts: dict[str, int] = {}
        self._db.execute("BEGIN IMMEDIATE")
        try:
            for row in self._db.execute(
                f"SELECT id, host FROM bundles WHERE id IN ({marks})",  # noqa: S608 - placeholders
                bundle_ids,
            ):
                hosts[row["id"]] = row["host"]
            if set(hosts) != set(bundle_ids):
                missing = sorted(set(bundle_ids) - set(hosts))
                raise EvidenceError(f"no bundle {missing[0]!r} to purge")
            for host, state in (expect or {}).items():
                if self.purge_state(host) != list(state):
                    raise EvidenceError(
                        f"{host}'s stored evidence changed while the purge was being planned"
                        " (a new bundle or baseline); nothing was deleted: run it again"
                    )
            for table, _ in APPEND_ONLY:
                for action in ("update", "delete"):
                    self._db.execute(f"DROP TRIGGER {table}_no_{action}")
            for table, column in (
                ("assessments", "bundle_id"),
                ("derived", "bundle_id"),
                ("baselines", "bundle_id"),
                ("custody", "bundle_id"),
                ("bundles", "id"),
            ):
                counts[table] = self._db.execute(
                    f"DELETE FROM {table} WHERE {column} IN ({marks})",  # noqa: S608 - fixed names
                    bundle_ids,
                ).rowcount
            for sql in _append_only_triggers():
                self._db.execute(sql)
            self._db.execute(
                "INSERT INTO purges (at, operator, controller, scope, bundles, counts, baselines)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(),
                    operator,
                    controller,
                    json.dumps(scope),
                    json.dumps(sorted([b, hosts[b]] for b in bundle_ids)),
                    json.dumps(counts),
                    json.dumps(baselines),
                ),
            )
            self._db.commit()
        except BaseException:
            self._db.rollback()
            raise
        return counts

    def purges(self) -> list[sqlite3.Row]:
        return self._db.execute("SELECT * FROM purges ORDER BY seq").fetchall()

    def baseline_purged(self, host: str, since: str | None = None) -> bool:
        """The host's current baseline was purged (after `since`, the time
        of its latest remaining baseline row) and its bundles weren't all:
        its next baseline is chosen again, and says why. An older baseline
        row that survived the purge doesn't come back into force."""
        for row in reversed(self.purges()):
            what = json.loads(row["baselines"]).get(host)
            if what is not None:
                return what == "moved" and (since is None or row["at"] > since)
        return False


def bundle_id(host: str, started: datetime, run_id: str) -> str:
    return f"{host}-{started:%Y%m%dT%H%M%SZ}-{run_id[:8]}"


def bundle_path(home: Path, host: str, identifier: str) -> Path:
    return home / "evidence" / host / f"{identifier}.age"


SIDECAR_FIELDS = (
    "id",
    "host",
    "run_id",
    "started_at",
    "ended_at",
    "collector_sha256",
    "plaintext_sha256",
    "ciphertext_sha256",
)


def write_sidecar(sealed: Sealed, row: dict[str, Any]) -> Path:
    """A small unencrypted note beside the bundle: only identifiers, times and
    hashes, so a bundle can be checked without the database or the key."""
    sidecar = sealed.path.with_suffix(".json")
    atomic_write(sidecar, json.dumps({key: row[key] for key in SIDECAR_FIELDS}, indent=2) + "\n")
    return sidecar


def check_sidecar(path: Path, row: sqlite3.Row) -> list[tuple[str, bool]]:
    """Compare a bundle's sidecar with its database row, field by field.
    Never raises: a missing or damaged sidecar is a failed check."""
    try:
        note = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [("sidecar present", False)]
    except (OSError, ValueError) as exc:
        return [(f"sidecar readable ({type(exc).__name__})", False)]
    if not isinstance(note, dict):
        return [("sidecar is a JSON object", False)]
    return [
        (f"sidecar {key} agrees with the database", note.get(key) == row[key])
        for key in SIDECAR_FIELDS
    ]
