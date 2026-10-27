"""Turning a stored bundle into events (and, later, snapshots), stored
encrypted beside it (DESIGN.md §6)."""

from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyrage
from pyrage import x25519

from checker.bundle import walk_bundle
from checker.events import PARSER_VERSION, Event, EventBuilder, mark_own_session
from checker.evidence import EvidenceError, Store, open_text, seal_text


@dataclass
class Parsed:
    events: list[Event]
    summary: dict[str, Any]


def events_path(bundle_path: Path) -> Path:
    return bundle_path.with_name(bundle_path.name.removesuffix(".age") + ".events.age")


def parse_bundle(row: Any, identity: x25519.Identity) -> Parsed:
    """Events from one stored bundle, the tool's own session marked."""
    started = datetime.fromisoformat(row["started_at"])
    builder = EventBuilder(controller_started=started)
    problem = walk_bundle(Path(row["path"]), identity, builder)
    session_text = open_text(row["session"], identity)
    session = json.loads(session_text) if session_text else None
    own = mark_own_session(builder.events, session)
    builder.events.sort(key=lambda e: (e.corrected or "", e.source))
    counts: dict[str, int] = {}
    for event in builder.events:
        counts[event.type] = counts.get(event.type, 0) + 1
    summary = {
        "events": len(builder.events),
        "own_session": own,
        "types": counts,
        "clock_offset_seconds": builder.offset.total_seconds() if builder.offset_known else None,
        "time_zone": str(builder.zone),
        "time_zone_assumed": builder.zone_assumed,
        "problem": problem,
    }
    return Parsed(builder.events, summary)


def store_events(store: Store, row: Any, recipients: list[str], parsed: Parsed) -> Path:
    """Encrypt the events (gzip JSON Lines) beside the bundle and index them;
    a newer parse replaces an older one."""
    target = events_path(Path(row["path"]))
    plain = gzip.compress(b"".join(json.dumps(e.as_dict()).encode() + b"\n" for e in parsed.events))
    keys = [x25519.Recipient.from_str(r) for r in recipients]
    cipher = pyrage.encrypt(plain, keys)
    partial = target.with_suffix(".tmp")
    partial.write_bytes(cipher)
    partial.chmod(0o600)
    partial.replace(target)
    store.record_derived(
        {
            "bundle_id": row["id"],
            "kind": "events",
            "parser_version": PARSER_VERSION,
            "path": str(target),
            "created_at": datetime.now(UTC).isoformat(),
            "items": len(parsed.events),
            "ciphertext_sha256": hashlib.sha256(cipher).hexdigest(),
            "summary": seal_text(json.dumps(parsed.summary), recipients),
        }
    )
    store.custody(
        row["id"], "parsed", {"parser_version": PARSER_VERSION, "events": len(parsed.events)}
    )
    return target


def load_events(store: Store, row: Any, identity: x25519.Identity) -> Parsed | None:
    """The stored events of a bundle, if a current parse is stored."""
    derived = store.derived(row["id"], "events")
    if derived is None or derived["parser_version"] != PARSER_VERSION:
        return None
    cipher = Path(derived["path"]).read_bytes()
    if hashlib.sha256(cipher).hexdigest() != derived["ciphertext_sha256"]:
        raise EvidenceError(f"stored events for {row['id']} don't match their recorded hash")
    try:
        plain = gzip.decompress(pyrage.decrypt(cipher, [identity]))
    except (pyrage.DecryptError, OSError) as exc:
        raise EvidenceError(f"cannot decrypt the stored events: {exc}") from exc
    events = [Event(**json.loads(line)) for line in plain.splitlines() if line]
    summary = json.loads(open_text(derived["summary"], identity) or "{}")
    return Parsed(events, summary)
