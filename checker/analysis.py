"""Turning a stored bundle into events and a snapshot, stored encrypted
beside it (DESIGN.md §6)."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyrage
from pyrage import x25519

from checker.bundle import Tee, walk_bundle
from checker.events import (
    PARSER_VERSION,
    Event,
    EventBuilder,
    mark_own_session,
    merge_duplicates,
)
from checker.evidence import EvidenceError, Store, open_text, seal_text
from checker.snapshot import SNAPSHOT_VERSION, Snapshot, SnapshotBuilder


@dataclass
class Parsed:
    events: list[Event]
    summary: dict[str, Any]
    snapshot: Snapshot | None = None


def derived_path(bundle_path: Path, kind: str, cipher: bytes) -> Path:
    # Named by content, so a new parse never overwrites the one on record.
    digest = hashlib.sha256(cipher).hexdigest()[:16]
    return bundle_path.with_name(bundle_path.name.removesuffix(".age") + f".{kind}-{digest}.age")


def parse_bundle(row: Any, identity: x25519.Identity) -> Parsed:
    """Events and the snapshot from one stored bundle, the tool's own
    session marked. The bundle must still be the one recorded: its hashes
    are checked."""
    session_text = open_text(row["session"], identity)
    session = json.loads(session_text) if session_text else None
    # The controller's side of the clock-offset measurement: when the
    # collector's first bytes (its manifest) arrived; for sessions stored
    # before that was recorded, the run's start.
    reference, basis = row["started_at"], "run start"
    if session and session.get("first_data_at"):
        reference, basis = session["first_data_at"], "first data"
    builder = EventBuilder(controller_started=datetime.fromisoformat(reference))
    state = SnapshotBuilder()
    walked = walk_bundle(Path(row["path"]), identity, Tee(builder, state))
    if walked.ciphertext_sha256 != row["ciphertext_sha256"]:
        raise EvidenceError(f"bundle {row['id']} doesn't match its recorded hash: not parsed")
    if walked.plaintext_sha256 != row["plaintext_sha256"]:
        raise EvidenceError(f"bundle {row['id']}'s content doesn't match its recorded hash")
    events = merge_duplicates(builder.events)
    own = mark_own_session(events, session, builder.sudo_lookup)
    events.sort(key=lambda e: (e.corrected or "", e.source))
    counts: dict[str, int] = {}
    for event in events:
        counts[event.type] = counts.get(event.type, 0) + 1
    # Whether the tool's own SSH login was found among the logs: if not
    # (behind NAT the host sees another source port, say), it and what
    # follows from it stay findings rather than being hidden on a guess.
    own_login = None
    if session and session.get("auth_method"):
        own_login = any(e.own_session and e.type == "ssh.login.accepted" for e in events)
    summary = {
        "events": len(events),
        "own_session": own,
        "own_login_found": own_login,
        "types": counts,
        "clock_offset_seconds": builder.offset.total_seconds() if builder.offset_known else None,
        "clock_offset_basis": basis if builder.offset_known else None,
        "time_zone": str(builder.zone),
        "time_zone_assumed": builder.zone_assumed,
        "problem": walked.problem,
    }
    return Parsed(events, summary, state.finish())


def store_parsed(store: Store, row: Any, recipients: list[str], parsed: Parsed) -> Path:
    """Encrypt the events (gzip JSON Lines) and the snapshot (gzip JSON)
    beside the bundle and index them; a newer parse replaces an older one.
    Returns the events file."""
    target = _store_derived(
        store,
        row,
        recipients,
        "events",
        PARSER_VERSION,
        b"".join(json.dumps(e.as_dict()).encode() + b"\n" for e in parsed.events),
        len(parsed.events),
        parsed.summary,
    )
    detail = {"parser_version": PARSER_VERSION, "events": len(parsed.events)}
    if parsed.snapshot is not None:
        snapshot = parsed.snapshot
        _store_derived(
            store,
            row,
            recipients,
            "snapshot",
            SNAPSHOT_VERSION,
            json.dumps(snapshot.as_dict()).encode(),
            snapshot.items(),
            {
                "sections": {
                    name: {"items": len(s.items), "complete": s.complete}
                    for name, s in snapshot.sections.items()
                }
            },
        )
        detail.update(snapshot_version=SNAPSHOT_VERSION, snapshot_items=snapshot.items())
    store.custody(row["id"], "parsed", detail)
    return target


def _store_derived(store, row, recipients, kind, version, content, items, summary) -> Path:
    keys = [x25519.Recipient.from_str(r) for r in recipients]
    cipher = pyrage.encrypt(gzip.compress(content), keys)
    target = derived_path(Path(row["path"]), kind, cipher)
    previous = store.derived(row["id"], kind)
    # Written whole and to disk before it is recorded; the one it replaces
    # is removed only after. A crash in between leaves a spare file, never
    # a record pointing at the wrong one.
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # this very parse is already stored
        pass
    else:
        with os.fdopen(fd, "wb") as out:
            out.write(cipher)
            out.flush()
            os.fsync(out.fileno())
    store.record_derived(
        {
            "bundle_id": row["id"],
            "kind": kind,
            "parser_version": version,
            "path": str(target),
            "created_at": datetime.now(UTC).isoformat(),
            "items": items,
            "ciphertext_sha256": hashlib.sha256(cipher).hexdigest(),
            "summary": seal_text(json.dumps(summary), recipients),
        }
    )
    if previous is not None and previous["path"] != str(target):
        Path(previous["path"]).unlink(missing_ok=True)
    return target


def _load_derived(store, row, identity, kind, version) -> tuple[bytes, dict[str, Any]] | None:
    derived = store.derived(row["id"], kind)
    if derived is None or derived["parser_version"] != version:
        return None
    try:
        cipher = Path(derived["path"]).read_bytes()
    except FileNotFoundError:
        return None  # to be parsed again
    if hashlib.sha256(cipher).hexdigest() != derived["ciphertext_sha256"]:
        raise EvidenceError(
            f"the stored {kind} of {row['id']} doesn't match its recorded hash;"
            " `checker events --reparse` parses the bundle again"
        )
    try:
        plain = gzip.decompress(pyrage.decrypt(cipher, [identity]))
    except (pyrage.DecryptError, OSError) as exc:
        raise EvidenceError(f"cannot decrypt the stored {kind}: {exc}") from exc
    return plain, json.loads(open_text(derived["summary"], identity) or "{}")


def load_events(store: Store, row: Any, identity: x25519.Identity) -> Parsed | None:
    """The stored events of a bundle, if a current parse is stored."""
    found = _load_derived(store, row, identity, "events", PARSER_VERSION)
    if found is None:
        return None
    plain, summary = found
    events = [Event(**json.loads(line)) for line in plain.splitlines() if line]
    return Parsed(events, summary)


def load_snapshot(store: Store, row: Any, identity: x25519.Identity) -> Snapshot | None:
    """The stored snapshot of a bundle, if a current one is stored."""
    found = _load_derived(store, row, identity, "snapshot", SNAPSHOT_VERSION)
    return Snapshot.from_dict(json.loads(found[0])) if found else None


def snapshot_of(
    store: Store, row: Any, identity: x25519.Identity, recipients: list[str]
) -> Snapshot:
    """A bundle's snapshot: the stored one, else parsed (and stored) now."""
    snapshot = load_snapshot(store, row, identity)
    if snapshot is None:
        parsed = parse_bundle(row, identity)
        store_parsed(store, row, recipients, parsed)
        snapshot = parsed.snapshot
    return snapshot
