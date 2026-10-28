"""Golden reports (plan 2.1b): stored inputs of real analyses, and the
assessment they must produce, so any change to the checks, the ratios or
(later) the whitelists shows up as a diff in CI.

A case is what `analyze` reads for one bundle: its events and snapshot,
the snapshots of its previous bundle and its baseline, and the events of
earlier bundles. Cases come from throwaway servers (the detection proof's
`--golden DIR`), so nothing in them is about a real system; and because
the repository is public, every public address in them, the controller's
own above all, is replaced by a documentation address before they are
written. Run `python scripts/update_golden.py` after a deliberate change
to write the new expectations and see what moved."""

from __future__ import annotations

import gzip
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from checker.analysis import load_events, parse_bundle, snapshot_of, store_parsed
from checker.assess import evaluate
from checker.baseline import current_baseline, usable_bundles
from checker.checks import Context
from checker.events import Event
from checker.evidence import Store
from checker.snapshot import Snapshot, compare

CASES = Path(__file__).resolve().parent.parent / "golden"
CASE_FORMAT = 1
PRIOR = (0.02, "golden")


# --- Export ------------------------------------------------------------------------------


def export_case(
    store: Store,
    host: str,
    identity,
    recipients: list[str],
    bundle_id: str,
    name: str,
    protect: list[str],
    directory: Path = CASES,
) -> tuple[Path, list[str]]:
    """Write one case: the inputs `analyze` uses for this bundle, with every
    public address replaced. `protect` lists addresses that must not
    survive (the controller's, the server's); finding one is an error.
    Returns the file and any address-like text left, for a person to
    look at before committing."""
    rows = usable_bundles(store, host)
    target = store.bundle(bundle_id)
    earlier = [r for r in rows if r["started_at"] < target["started_at"]]
    previous = earlier[-1] if earlier else None
    baseline = current_baseline(store, host)
    baseline_id = baseline["bundle_id"] if baseline else bundle_id
    case: dict[str, Any] = {
        "format": CASE_FORMAT,
        "name": name,
        "host": host,
        "target": bundle_id,
        "previous": previous["id"] if previous else None,
        "baseline": baseline_id,
        "earlier": [r["id"] for r in earlier],
        "started": {},
        "snapshots": {},
        "events": {},
    }
    for row in [*earlier, target]:
        case["started"][row["id"]] = row["started_at"]
        case["events"][row["id"]] = [e.as_dict() for e in _events(store, row, identity, recipients)]
    for wanted in {bundle_id, baseline_id, *(r["id"] for r in earlier[-1:])}:
        case["snapshots"][wanted] = snapshot_of(
            store, store.bundle(wanted), identity, recipients
        ).as_dict()
    text = scrub(json.dumps(case, sort_keys=True), protect)
    for address in protect:
        if address in text or _dashed(address) in text:
            raise ValueError(f"a protected address survived scrubbing in case {name}")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json.gz"
    path.write_bytes(gzip.compress(text.encode(), mtime=0))
    write_expected(path)
    return path, leftover_addresses(text)


def _events(store, row, identity, recipients) -> list[Event]:
    parsed = load_events(store, row, identity)
    if parsed is None:
        parsed = parse_bundle(row, identity)
        store_parsed(store, row, recipients, parsed)
    return parsed.events


_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _public(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    return address if address.is_global else None


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _dashed(address: str) -> str:
    return address.replace(".", "-").replace(":", "-")


def scrub(text: str, protect: list[str]) -> str:
    """Every public address in the case's values, and the protected ones,
    replaced everywhere (also as a reverse-DNS name's dashed form) by a
    documentation address, consistently, so the case still links the same
    address across events and snapshots."""
    found = {str(a) for s in _strings(json.loads(text)) if (a := _public(s))}
    for s in _strings(json.loads(text)):
        for token in _IPV4.findall(s):
            if (a := _public(token)) and _looks_like_an_address(s, token):
                found.add(str(a))
    found |= set(protect)
    v4 = sorted(a for a in found if ":" not in a)
    v6 = sorted(a for a in found if ":" in a)
    mapping = {
        a: f"203.0.113.{10 + i}" if i < 240 else f"198.51.100.{i - 230}" for i, a in enumerate(v4)
    }
    mapping |= {a: f"2001:db8::{i + 1:x}" for i, a in enumerate(v6)}
    for real in sorted(mapping, key=len, reverse=True):
        fake = mapping[real]
        text = re.sub(rf"(?<![\w.:]){re.escape(real)}(?![\w:]|\.\d)", fake, text)
        text = text.replace(_dashed(real), _dashed(fake))
    return text


def _looks_like_an_address(text: str, token: str) -> bool:
    """A dotted quad in a log line or setting, not a version number: it
    follows a word that introduces an address, or a separator."""
    before = text[: text.index(token)].rstrip()
    return bool(re.search(r"(from|to|rhost=|host=|addr=|address|@|=|\[|\(|,|^)$", before))


def leftover_addresses(text: str) -> list[str]:
    """Dotted quads still in the case that parse as public addresses: version
    numbers, usually; a person checks them before the case is committed."""
    return sorted({t for t in _IPV4.findall(text) if _public(t)})


# --- Running -----------------------------------------------------------------------------


def load_case(path: Path) -> dict[str, Any]:
    case = json.loads(gzip.decompress(path.read_bytes()))
    if case.get("format") != CASE_FORMAT:
        raise ValueError(f"{path.name}: case format {case.get('format')}, not {CASE_FORMAT}")
    return case


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    """What `analyze` would make of the case's bundle: the same comparisons
    and context, through the same `evaluate`."""
    target, previous, baseline = case["target"], case["previous"], case["baseline"]
    snapshots = {k: Snapshot.from_dict(v) for k, v in case["snapshots"].items()}
    events = {k: [Event(**e) for e in v] for k, v in case["events"].items()}
    snapshot = snapshots[target]
    since_previous = compare(snapshots[previous], snapshot) if previous else None
    if baseline == target:
        since_baseline, no_baseline = None, "this bundle is the baseline"
    elif baseline == previous:
        since_baseline, no_baseline = since_previous, "no baseline yet"
    else:
        since_baseline, no_baseline = compare(snapshots[baseline], snapshot), "no baseline yet"
    context = Context(
        host=case["host"],
        bundle_id=target,
        events=events[target],
        snapshot=snapshot,
        baseline_id=baseline,
        since_baseline=since_baseline,
        since_previous=since_previous,
        earlier_events=lambda: [events[i] for i in case["earlier"]],
        previous_time=case["started"][previous] if previous else None,
        no_baseline=no_baseline,
    )
    findings, ran, scored = evaluate(context, PRIOR)
    return {"findings": findings, "checks": ran, "score": scored}


def expected_path(case_path: Path) -> Path:
    return case_path.with_name(case_path.name.removesuffix(".json.gz") + ".expected.json")


def write_expected(case_path: Path) -> dict[str, Any]:
    result = run_case(load_case(case_path))
    expected_path(case_path).write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return result


def cases() -> list[Path]:
    return sorted(CASES.glob("*.json.gz"))
