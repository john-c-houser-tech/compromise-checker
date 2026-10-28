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
    # The other bundle is newer than this one (a baseline accepted later
    # than the bundle asked about): the differences still run from the
    # older to the newer.
    newer: bool = False


@dataclass
class Changes:
    host: str
    bundle_id: str
    baseline_id: str
    baseline_set_now: bool  # the host had no baseline: this call set it
    # It had one, but `purge` removed it: this call chose the next.
    after_purge: bool = False
    comparisons: list[Comparison] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def first(self) -> bool:
        """This bundle is the host's first baseline, set just now."""
        return self.baseline_set_now and not self.after_purge and self.baseline_id == self.bundle_id


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
    set_now, after_purge, notes = False, False, []
    if baseline is None:
        after_purge = store.baseline_purged(host)
        # The oldest full collection; a run limited to some modules can't
        # stand for the whole host. If there is none, the oldest at all.
        rows = usable_bundles(store, host)
        chosen = next(
            (r for r in rows if snapshot_of(store, r, identity, recipients).meta.get("full")),
            None,
        )
        if chosen is None:
            chosen = rows[0]
            notes.append(
                "no bundle of this host collected every module, so the baseline covers only"
                " what its bundle collected"
            )
        store.record_baseline(host, chosen["id"], "after purge" if after_purge else "first", None)
        baseline = current_baseline(store, host)
        set_now = True
    if baseline["how"] == "after purge":
        # On every analysis against it, not only the one that chose it.
        notes.append(
            f"the host's earlier baseline was purged; {baseline['bundle_id']}, then its oldest"
            " remaining bundle, is the baseline, so changes made before it don't show"
        )
    result = Changes(host, target["id"], baseline["bundle_id"], set_now, after_purge, notes=notes)
    snapshot = snapshot_of(store, target, identity, recipients)
    earlier = [r for r in usable_bundles(store, host) if r["started_at"] < target["started_at"]]
    others = []
    if earlier:
        others.append(("previous", earlier[-1]))
    if baseline["bundle_id"] != target["id"] and (
        not earlier or baseline["bundle_id"] != earlier[-1]["id"]
    ):
        others.append(("baseline", store.bundle(baseline["bundle_id"])))
    for label, row in others:
        other = snapshot_of(store, row, identity, recipients)
        newer = row["started_at"] > target["started_at"]
        differences = compare(snapshot, other) if newer else compare(other, snapshot)
        result.comparisons.append(Comparison(label, row["id"], differences, newer))
    return result


def accept(
    store: Store,
    host: str,
    reason: str,
    identity: x25519.Identity,
    recipients: list[str],
    bundle_id: str | None = None,
) -> tuple[Any, list[str]]:
    """Make a bundle's snapshot (by default the host's latest) the host's
    baseline, recording who accepted it, from where, and why (encrypted).
    Returns the bundle and anything the operator should know."""
    if not reason.strip():
        raise EvidenceError("a reason is required to accept a baseline")
    row = _pick(store, host, bundle_id)
    if not snapshot_of(store, row, identity, recipients).meta.get("full"):
        raise EvidenceError(
            f"bundle {row['id']} collected only some modules; a baseline must cover them all"
        )
    notes = []
    current = current_baseline(store, host)
    if current is not None and store.bundle(current["bundle_id"])["started_at"] > row["started_at"]:
        notes.append(f"it is older than the baseline it replaces ({current['bundle_id']})")
    if row["status"] != "complete":
        notes.append(f"it is {row['status']}; its incomplete sections compare as such")
    store.record_baseline(host, row["id"], "accepted", seal_text(reason.strip(), recipients))
    return row, notes
