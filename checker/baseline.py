"""Baselines (DESIGN.md §7): a host's first analysed bundle is its baseline;
later snapshots are compared with the previous one and with the baseline,
which an operator moves forward by accepting a reviewed change."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pyrage import x25519

from checker.analysis import snapshot_of
from checker.evidence import EvidenceError, Store, seal_text
from checker.snapshot import compare

# Bundles a snapshot can come from: the collector ran and sent data, even if
# it was cut off (its sections then say they are incomplete).
USABLE = ("complete", "partial", "incomplete")


@dataclass
class Comparison:
    label: str  # "previous" or "baseline"
    bundle_id: str
    differences: dict[str, dict[str, Any]]


@dataclass
class Changes:
    host: str
    bundle_id: str
    baseline_id: str
    first: bool  # this bundle is the host's first baseline, set just now
    comparisons: list[Comparison] = field(default_factory=list)


def usable_bundles(store: Store, host: str) -> list[Any]:
    return [row for row in store.bundles(host) if row["status"] in USABLE]


def current_baseline(store: Store, host: str) -> Any | None:
    rows = store.baselines(host)
    return rows[-1] if rows else None


def _pick(store: Store, host: str, bundle_id: str | None) -> Any:
    if bundle_id is not None:
        row = store.bundle(bundle_id)
        if row["host"] != host:
            raise EvidenceError(f"bundle {bundle_id} is from {row['host']}, not {host}")
        if row["status"] not in USABLE:
            raise EvidenceError(f"bundle {bundle_id} is {row['status']}: it has no snapshot")
        return row
    rows = usable_bundles(store, host)
    if not rows:
        raise EvidenceError(f"no usable bundle for {host}")
    return rows[-1]


def changes(
    store: Store,
    host: str,
    identity: x25519.Identity,
    recipients: list[str],
    bundle_id: str | None = None,
) -> Changes:
    """What changed on `host` in a bundle (by default its latest) since the
    bundle before it and since the baseline. With no baseline yet, the
    host's oldest usable bundle becomes it (and the result says so)."""
    target = _pick(store, host, bundle_id)
    baseline = current_baseline(store, host)
    first = False
    if baseline is None:
        oldest = usable_bundles(store, host)[0]
        snapshot_of(store, oldest, identity, recipients)  # it must have one
        store.record_baseline(host, oldest["id"], "first", None)
        baseline = current_baseline(store, host)
        first = oldest["id"] == target["id"]
    result = Changes(host, target["id"], baseline["bundle_id"], first)
    new = snapshot_of(store, target, identity, recipients)
    earlier = [r for r in usable_bundles(store, host) if r["started_at"] < target["started_at"]]
    others = []
    if earlier:
        others.append(("previous", earlier[-1]))
    if baseline["bundle_id"] != target["id"] and (
        not earlier or baseline["bundle_id"] != earlier[-1]["id"]
    ):
        others.append(("baseline", store.bundle(baseline["bundle_id"])))
    for label, row in others:
        old = snapshot_of(store, row, identity, recipients)
        result.comparisons.append(Comparison(label, row["id"], compare(old, new)))
    return result


def accept(
    store: Store,
    host: str,
    reason: str,
    identity: x25519.Identity,
    recipients: list[str],
    bundle_id: str | None = None,
) -> Any:
    """Make a bundle's snapshot (by default the host's latest) the host's
    baseline, recording who accepted it, from where, and why (encrypted)."""
    if not reason.strip():
        raise EvidenceError("a reason is required to accept a baseline")
    row = _pick(store, host, bundle_id)
    snapshot_of(store, row, identity, recipients)  # it must have one
    store.record_baseline(host, row["id"], "accepted", seal_text(reason.strip(), recipients))
    return row
