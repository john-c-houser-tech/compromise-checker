"""Reviewing whitelist changes against stored evidence (DESIGN.md §9.2):
what a proposed file would hide or reveal before it is saved, and which
rules have stopped earning their place."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from checker.analysis import load_events
from checker.assess import load_assessment
from checker.baseline import usable_bundles
from checker.correlate import find_chains
from checker.evidence import Store
from checker.report import current_versions
from checker.scoring import score
from checker.whitelist import Whitelist, reapply

EXPIRING = timedelta(days=30)


def compare(
    store: Store,
    host: str,
    identity,
    current: Whitelist | None,
    proposed: Whitelist | None,
    since: datetime,
) -> list[dict[str, Any]]:
    """For each of the host's bundles collected since `since` with a stored
    (scored) assessment: the score under the current and the proposed
    whitelist, and the findings the proposal would hide, reveal, or move
    into or out of a maintenance window. The stored assessments are read,
    never changed."""
    return compare_loaded(load_analyses(store, host, identity, since), current, proposed)


def load_analyses(store: Store, host: str, identity, since: datetime) -> list[dict[str, Any]]:
    """What comparing needs, decrypted once however many rules are then compared. Read only: a
    bundle not parsed yet isn't parsed here (that would store its events); correlated rules and
    chains then see none."""
    loaded = []
    for row in usable_bundles(store, host):
        if datetime.fromisoformat(row["started_at"]) < since:
            continue
        stored = load_assessment(store, row["id"], identity)
        if stored is None or "score" not in stored:
            continue
        if stored.get("versions") != current_versions():
            # Its findings cite events by number in an older parse: they
            # can't be paired with today's events. `analyze` makes it current.
            loaded.append({"row": row, "skipped": "analysed with older checks"})
            continue
        parsed = load_events(store, row, identity)
        loaded.append(
            {
                "row": row,
                "stored": stored,
                "events": parsed.events if parsed else [],
                "events_missing": parsed is None,
            }
        )
    return loaded


def compare_loaded(
    loaded: list[dict[str, Any]], current: Whitelist | None, proposed: Whitelist | None
) -> list[dict[str, Any]]:
    results = []
    for item in loaded:
        row = item["row"]
        if "skipped" in item:
            results.append({"bundle": row["id"], "skipped": item["skipped"]})
            continue
        stored, events = item["stored"], item["events"]
        prior = stored["score"]["prior"]
        before = json.loads(json.dumps(stored["findings"]))
        after = json.loads(json.dumps(stored["findings"]))
        reapply(before, current, events=events)
        reapply(after, proposed, events=events)
        previous = stored.get("previous_time")
        chains = find_chains(before, events, previous)
        was = score(before, prior, chains)
        now = score(after, prior, find_chains(after, events, previous))
        hidden, revealed, rebanded = [], [], []
        for b, a in zip(before, after, strict=True):
            if not b.get("suppressed_by") and a.get("suppressed_by"):
                hidden.append(_line(a, f"by {a['suppressed_by']['rule']}"))
            elif b.get("suppressed_by") and not a.get("suppressed_by"):
                revealed.append(_line(a, f"was {b['suppressed_by']['rule']}"))
            if b["band"] != a["band"]:
                rebanded.append(_line(a, f"{b['band']} -> {a['band']}"))
        results.append(
            {
                "bundle": row["id"],
                "collected": row["started_at"],
                "before": (was["probability"], was["band"]),
                "after": (now["probability"], now["band"]),
                "hidden": hidden,
                "revealed": revealed,
                "rebanded": rebanded,
                "chained": bool(chains),
                "events_missing": item.get("events_missing", False),
            }
        )
    return results


def _line(finding: dict[str, Any], note: str) -> str:
    return f"{finding['band']} {finding['check']}: {finding['summary'][:120]} ({note})"


def stale(
    store: Store,
    identity,
    sets: dict[str, Whitelist | None],
    days: int = 90,
    now: datetime | None = None,
) -> dict[str, list[str]]:
    """Across hosts (`sets`: each host's current whitelist): live rules that
    match no stored finding of the last `days` days (the current set applied
    to the stored findings, so a rule added since counts too), and rules and
    windows expired, or expiring within 30 days. A rule counts once, by its
    file and id, however many hosts share it; a set no host uses (a group
    file with no hosts) matches nothing."""
    now = now or datetime.now(UTC)
    since = now - timedelta(days=days)
    today = now.date()
    rules: dict[tuple[str, str], str] = {}
    used: set[tuple[str, str]] = set()
    expired, expiring = set(), set()
    for host, merged in sets.items():
        if merged is None:
            continue
        for placed in [*merged.rules, *merged.windows]:
            name = f"{placed.rule.id} ({placed.layer}, {placed.file})"
            if placed.rule.expires != "never":
                if placed.rule.expires < today:
                    expired.add(f"{name}: expired {placed.rule.expires}")
                    continue
                if placed.rule.expires <= today + EXPIRING:
                    expiring.add(f"{name}: expires {placed.rule.expires}")
        live = {(p.file, p.rule.id): p for p in merged.rules if p.live(today)}
        for key, placed in live.items():
            rules[key] = f"{placed.rule.id} ({placed.layer}, {placed.file})"
        for row in usable_bundles(store, host):
            if datetime.fromisoformat(row["started_at"]) < since:
                continue
            stored = load_assessment(store, row["id"], identity)
            if not stored or stored.get("versions") != current_versions():
                continue  # its event numbers belong to an older parse
            findings = json.loads(json.dumps(stored["findings"]))
            parsed = load_events(store, row, identity)
            reapply(findings, merged, today, parsed.events if parsed else [])
            for finding in findings:
                rule = finding.get("suppressed_by")
                if rule:
                    used.add((rule["file"], rule["rule"]))
    return {
        "stale": sorted(name for key, name in rules.items() if key not in used),
        "expired": sorted(expired),
        "expiring": sorted(expiring),
    }
