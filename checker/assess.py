"""Analysing a host's bundle (DESIGN.md §6): the checks over its events, its
snapshot and its changes since the baseline, with what the collection could
not see (principle 8), stored as an encrypted assessment."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pyrage
from pyrage import x25519

from checker.analysis import load_events, parse_bundle, snapshot_of, store_parsed
from checker.baseline import changes, usable_bundles
from checker.checks import CHECKS_VERSION, Context, run_checks
from checker.correlate import find_chains
from checker.events import PARSER_VERSION, Event
from checker.evidence import Config, EvidenceError, Store, open_text, seal_text
from checker.inventory import Inventory
from checker.scoring import DEFAULT_PRIOR, SCORING_VERSION, score
from checker.snapshot import FULL, SNAPSHOT_VERSION, Snapshot
from checker.whitelist import Whitelist

# Logs whose reach (how far back they go) the coverage reports.
LOG_SOURCES = ("auth_log", "auth_journal", "system_journal", "login_records")
# Event sources whose reach is reported too, though no module has their name.
REACH_ONLY = ("mail_log", "mail_journal")
LARGE_CLOCK_OFFSET = 120  # seconds
# 2: scored (prior, each finding's ratio and contribution, the score).
ASSESSMENT_FORMAT = 2


def prior_for(host: str, config: Config, inventory: Inventory) -> tuple[float, str]:
    """The prior a host's score starts from, and where it comes from: the
    host's own in the inventory, its group's, or the configuration's."""
    entry = next((h for h in inventory.hosts if h.name == host), None)
    if entry is not None and entry.prior is not None:
        return entry.prior, "host"
    if entry is not None and entry.group in config.group_priors:
        return config.group_priors[entry.group], f"group {entry.group}"
    return config.prior, "configuration"


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
    for prefix in LOG_SOURCES + REACH_ONLY:
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
    gaps += web_gaps(snapshot)
    withheld = snapshot.live.get("mail_logs_withheld")
    if withheld:
        gaps.append(f"mail logs not collected ({withheld.get('reason')}): outgoing mail unchecked")
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


def web_gaps(snapshot: Snapshot) -> list[str]:
    """What the web checks couldn't see: access logs not chosen at setup,
    no audit log for program starts, logs in a format not recognised."""
    gaps: list[str] = []
    web = snapshot.live.get("web_logs_summary")
    if web and not web.get("access_logs_opted_in") and web.get("access_found"):
        gaps.append(
            "web access logs not collected (not chosen at setup): web checks use error logs,"
            " processes and audit records only"
        )
    if snapshot.live.get("exec_records_unavailable"):
        gaps.append(
            "no audit log: earlier program starts by web accounts can't be checked"
            " (docs/auditd-web.rules sets auditd up for them)"
        )
    elif (snapshot.live.get("exec_records_summary") or {}).get("starts") == 0:
        gaps.append(
            "no program starts in the audit log: auditd isn't recording them, so earlier"
            " ones by web accounts can't be checked (docs/auditd-web.rules)"
        )
    requests = snapshot.live.get("web_requests") or {}
    for name, unparsed in sorted((requests.get("unparsed") or {}).items()):
        if unparsed * 2 > (requests.get("lines") or {}).get(name, 0):
            gaps.append(f"web log format not recognised: {name} ({unparsed} lines)")
    return gaps


def count(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Findings by category and band, suppressed ones left out."""
    counts: dict[str, int] = {}
    for finding in findings:
        if finding.get("suppressed_by"):
            continue
        key = f"{finding['category']}/{finding['band']}"
        counts[key] = counts.get(key, 0) + 1
    return counts


def evaluate(
    context: Context,
    prior: tuple[float, str],
    whitelist: Whitelist | None = None,
    today: date | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any] | None]:
    """The checks over a context, the whitelist over their findings, and the
    score: the findings (as stored, suppressed ones marked), which checks
    ran, the score, and what the whitelist did. What `analyze` stores, and
    what the golden reports pin (tests/golden)."""
    findings, ran = run_checks(context)
    found = [f.as_dict() for f in findings]
    applied = whitelist.apply(found, today, context.events) if whitelist is not None else None
    chains = find_chains(found, context.events, context.previous_time)
    scored = score(found, prior[0], chains) | {"prior_source": prior[1], "chains": chains}
    return found, ran, scored, applied


def analyze(
    store: Store,
    host: str,
    identity: x25519.Identity,
    recipients: list[str],
    bundle_id: str | None = None,
    prior: tuple[float, str] = (DEFAULT_PRIOR, "default"),
    whitelist: Whitelist | None = None,
) -> dict[str, Any]:
    """Run every check on a host's bundle (by default its latest), score
    the findings from `prior` (value, source) and store the assessment;
    returns it."""
    found = changes(store, host, identity, recipients, bundle_id)
    row = store.bundle(found.bundle_id)
    snapshot = snapshot_of(store, row, identity, recipients)
    parsed = load_events(store, row, identity)
    if parsed is None:
        parsed = parse_bundle(row, identity)
        store_parsed(store, row, recipients, parsed)
    since_baseline = since_previous = None
    previous_time = None
    previous_snapshot = None
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
            previous_snapshot = snapshot_of(
                store, store.bundle(comparison.bundle_id), identity, recipients
            )
            if comparison.bundle_id == found.baseline_id:
                since_baseline = comparison.differences
    baseline_time = baseline_snapshot = None
    if since_baseline is not None and found.baseline_id:
        baseline_row = store.bundle(found.baseline_id)
        baseline_time = baseline_row["started_at"]
        baseline_snapshot = snapshot_of(store, baseline_row, identity, recipients)
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
        previous_snapshot=previous_snapshot,
        baseline_time=baseline_time,
        baseline_snapshot=baseline_snapshot,
    )
    found_dicts, ran, scored, applied = evaluate(context, prior, whitelist)
    counts = count(found_dicts)
    assessment = {
        "format": ASSESSMENT_FORMAT,
        "host": host,
        "bundle_id": row["id"],
        "analysed_at": datetime.now(UTC).isoformat(),
        "checks_version": CHECKS_VERSION,
        "versions": {
            "checks": CHECKS_VERSION,
            "parser": PARSER_VERSION,
            "snapshot": SNAPSHOT_VERSION,
            "scoring": SCORING_VERSION,
        },
        "baseline_id": found.baseline_id,
        "baseline_set_now": found.baseline_set_now,
        "previous_time": previous_time,
        "notes": notes,
        "counts": counts,
        "score": scored,
        "whitelist": applied,
        "findings": found_dicts,
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
            "summary": seal_text(
                json.dumps(
                    {
                        "counts": assessment["counts"],
                        "probability": (assessment.get("score") or {}).get("probability"),
                        "band": (assessment.get("score") or {}).get("band"),
                    }
                ),
                recipients,
            ),
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
