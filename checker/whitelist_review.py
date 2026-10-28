"""Reviewing whitelist changes against stored evidence (DESIGN.md §9.2):
what a proposed file would hide or reveal before it is saved, and which
rules have stopped earning their place."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from checker.assess import load_assessment
from checker.baseline import usable_bundles
from checker.evidence import Store
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
    results = []
    for row in usable_bundles(store, host):
        if datetime.fromisoformat(row["started_at"]) < since:
            continue
        stored = load_assessment(store, row["id"], identity)
        if stored is None or "score" not in stored:
            continue
        prior = stored["score"]["prior"]
        before = json.loads(json.dumps(stored["findings"]))
        after = json.loads(json.dumps(stored["findings"]))
        reapply(before, current)
        reapply(after, proposed)
        was, now = score(before, prior), score(after, prior)
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
            if not stored:
                continue
            findings = json.loads(json.dumps(stored["findings"]))
            reapply(findings, merged, today)
            for finding in findings:
                rule = finding.get("suppressed_by")
                if rule:
                    used.add((rule["file"], rule["rule"]))
    return {
        "stale": sorted(name for key, name in rules.items() if key not in used),
        "expired": sorted(expired),
        "expiring": sorted(expiring),
    }
