"""Analysing a host's bundle (DESIGN.md §6): the checks over its events, its
snapshot and its changes since the baseline, with what the collection could
not see (principle 8), stored as an encrypted assessment."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyrage
from pyrage import x25519

from checker.analysis import load_events, parse_bundle, snapshot_of, store_parsed
from checker.baseline import changes, usable_bundles
from checker.checks import CHECKS_VERSION, Context, run_checks
from checker.events import Event
from checker.evidence import EvidenceError, Store, open_text, seal_text
from checker.snapshot import FULL, Snapshot

# Logs whose reach (how far back they go) the coverage reports.
LOG_SOURCES = ("auth_log", "auth_journal", "system_journal", "login_records")
LARGE_CLOCK_OFFSET = 120  # seconds


def events_of(store: Store, row: Any, identity, recipients: list[str]) -> list[Event]:
    parsed = load_events(store, row, identity)
    if parsed is None:
        parsed = parse_bundle(row, identity)
        store_parsed(store, row, recipients, parsed)
    return parsed.events


def coverage(
    row: Any, identity, events: list[Event], events_summary: dict, snapshot: Snapshot
) -> dict[str, Any]:
    """What this collection could not see, or saw only in part."""
    summary = json.loads(open_text(row["summary"], identity) or "{}")
    manifest = summary.get("manifest") or {}
    trailer = summary.get("trailer") or {}
    planned = set(manifest.get("modules_planned") or [])
    gaps: list[str] = []
    if row["status"] != "complete":
        gaps.append(f"the bundle is {row['status']}")
    missing = sorted((FULL | set(LOG_SOURCES) | {"boots"}) - planned) if planned else []
    if missing:
        gaps.append("not collected: " + ", ".join(missing))
    for module, result in sorted((trailer.get("modules") or {}).items()):
        if result.get("status") != "ok":
            gaps.append(f"module {module}: {result.get('status')}")
    for source in summary.get("sources") or []:
        if source.get("truncated"):
            gaps.append(
                f"{source.get('module')} {source.get('name')}: cut short"
                f" ({source.get('truncated_reason') or 'truncated'})"
            )
    for error in (summary.get("errors") or [])[:20]:
        gaps.append(f"error in {error.get('module')}: {error.get('message')}")
    for name, section in snapshot.sections.items():
        if not section.complete:
            gaps.append(f"{name} incomplete: " + "; ".join(section.gaps[:3]))
    reach = {}
    for prefix in LOG_SOURCES:
        times = sorted(
            e.corrected
            for e in events
            if e.corrected and (e.source == prefix or e.source.startswith(prefix + ":"))
        )
        if times:
            first, last = datetime.fromisoformat(times[0]), datetime.fromisoformat(times[-1])
            reach[prefix] = {
                "from": times[0],
                "to": times[-1],
                "days": round((last - first).total_seconds() / 86400, 1),
            }
    if not any(p in reach for p in ("auth_log", "auth_journal")):
        gaps.append("no authentication log events: logins and sudo can't be checked")
    if "system_journal" not in reach:
        gaps.append("no system journal events: kernel messages and shutdowns can't be checked")
    if not any(e.type in ("system.boot_journal", "system.boot") for e in events):
        gaps.append("no boot list or boot records: reboots can't be classified")
    offset = events_summary.get("clock_offset_seconds")
    if offset is not None and abs(offset) > LARGE_CLOCK_OFFSET:
        gaps.append(f"the host's clock is {offset:+.0f} s off the controller's")
    if events_summary.get("time_zone_assumed"):
        gaps.append("the host's time zone is unknown: UTC assumed for syslog dates")
    if events_summary.get("own_login_found") is False:
        gaps.append(
            "this tool's own SSH login was not recognised (NAT?): it and what followed from"
            " it are listed as findings"
        )
    return {"gaps": gaps, "log_reach": reach}


def analyze(
    store: Store,
    host: str,
    identity: x25519.Identity,
    recipients: list[str],
    bundle_id: str | None = None,
) -> dict[str, Any]:
    """Run every check on a host's bundle (by default its latest) and store
    the assessment; returns it."""
    found = changes(store, host, identity, recipients, bundle_id)
    row = store.bundle(found.bundle_id)
    snapshot = snapshot_of(store, row, identity, recipients)
    parsed = load_events(store, row, identity)
    if parsed is None:
        parsed = parse_bundle(row, identity)
        store_parsed(store, row, recipients, parsed)
    since_baseline = since_previous = None
    previous_time = None
    no_baseline = "no baseline yet"
    notes = list(found.notes)
    for comparison in found.comparisons:
        if comparison.newer:
            notes.append(
                f"the baseline ({comparison.bundle_id}) is newer than this bundle: change-based"
                " checks didn't run"
            )
            no_baseline = "the baseline is newer than this bundle"
            continue
        if comparison.label == "baseline":
            since_baseline = comparison.differences
        else:
            since_previous = comparison.differences
            previous_time = store.bundle(comparison.bundle_id)["started_at"]
            if comparison.bundle_id == found.baseline_id:
                since_baseline = comparison.differences
    if found.baseline_id == row["id"] and not found.first:
        no_baseline = "this bundle is the baseline"
    if found.first:
        notes.append(
            "this is the host's first analysis and its baseline: change-based checks start"
            " from the next one"
        )

    def earlier() -> list[list[Event]]:
        rows = [r for r in usable_bundles(store, host) if r["started_at"] < row["started_at"]]
        return [events_of(store, r, identity, recipients) for r in rows]

    context = Context(
        host=host,
        bundle_id=row["id"],
        events=parsed.events,
        snapshot=snapshot,
        baseline_id=found.baseline_id,
        since_baseline=since_baseline,
        since_previous=since_previous,
        earlier_events=earlier,
        previous_time=previous_time,
        no_baseline=no_baseline,
    )
    findings, ran = run_checks(context)
    counts: dict[str, int] = {}
    for finding in findings:
        key = f"{finding.category}/{finding.band}"
        counts[key] = counts.get(key, 0) + 1
    assessment = {
        "host": host,
        "bundle_id": row["id"],
        "analysed_at": datetime.now(UTC).isoformat(),
        "checks_version": CHECKS_VERSION,
        "baseline_id": found.baseline_id,
        "baseline_set_now": found.baseline_set_now,
        "notes": notes,
        "counts": counts,
        "findings": [f.as_dict() for f in findings],
        "checks": ran,
        "coverage": coverage(row, identity, parsed.events, parsed.summary, snapshot),
    }
    store_assessment(store, row, recipients, assessment)
    return assessment


def store_assessment(store: Store, row: Any, recipients: list[str], assessment: dict) -> Path:
    """Encrypt the assessment beside the bundle and record it (append-only:
    each analysis is kept, so a re-analysis with new checks doesn't erase
    what an earlier one said)."""
    keys = [x25519.Recipient.from_str(r) for r in recipients]
    cipher = pyrage.encrypt(gzip.compress(json.dumps(assessment).encode()), keys)
    digest = hashlib.sha256(cipher).hexdigest()
    target = Path(row["path"]).with_name(
        Path(row["path"]).name.removesuffix(".age") + f".assessment-{digest[:16]}.age"
    )
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as out:
            out.write(cipher)
            out.flush()
            os.fsync(out.fileno())
    store.record_assessment(
        {
            "bundle_id": row["id"],
            "host": row["host"],
            "at": assessment["analysed_at"],
            "checks_version": CHECKS_VERSION,
            "baseline_id": assessment["baseline_id"],
            "path": str(target),
            "ciphertext_sha256": digest,
            "summary": seal_text(json.dumps(assessment["counts"]), recipients),
        }
    )
    return target


def load_assessment(store: Store, bundle_id: str, identity: x25519.Identity) -> dict | None:
    """The latest stored assessment of a bundle."""
    rows = store.assessments(bundle_id)
    if not rows:
        return None
    row = rows[-1]
    cipher = Path(row["path"]).read_bytes()
    if hashlib.sha256(cipher).hexdigest() != row["ciphertext_sha256"]:
        raise EvidenceError(f"the stored assessment of {bundle_id} doesn't match its recorded hash")
    return json.loads(gzip.decompress(pyrage.decrypt(cipher, [identity])))
