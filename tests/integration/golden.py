"""Golden reports (plan 2.1b): stored inputs of real analyses, and the
assessment they must produce, so any change to the checks, the ratios or
(later) the whitelists shows up as a diff in CI.

A case is what `analyze` reads for one bundle: its events and snapshot,
the snapshots of its previous bundle and its baseline, and the events of
earlier bundles. Cases come from throwaway servers (the detection proof's
`--golden DIR`), so nothing in them is about a real system; and because
the repository is public, every public address in them, the controller's
own above all, is replaced by a documentation address before they are
written, and the export fails if any public address survives in a form
it knows or if the replacement changed what the checks find. Cases hold
parsed events and snapshots, so they pin the checks and scoring, not the
parsers. Run `python scripts/update_golden.py` after a deliberate change
to write the new expectations and see what moved."""

from __future__ import annotations

import gzip
import ipaddress
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from checker.analysis import load_events, parse_bundle, snapshot_of, store_parsed
from checker.assess import evaluate
from checker.baseline import changes, usable_bundles
from checker.checks import Context
from checker.events import Event
from checker.evidence import Store
from checker.snapshot import Snapshot, compare
from checker.whitelist import Layer, build

CASES = Path(__file__).resolve().parent.parent / "golden"
CASE_FORMAT = 1
PRIOR = (0.02, "golden")
# Whitelist expiry is judged on this day, so the expectations don't change
# with the calendar.
TODAY = date(2026, 10, 28)
PROOF_WHITELIST = Path(__file__).resolve().parent / "proof-whitelist.yaml"


def proof_layers(host: str) -> list[list[Any]]:
    """The proofs' own whitelist as a case's host layer."""
    data = yaml.safe_load(PROOF_WHITELIST.read_text(encoding="utf-8"))
    return [[f"host {host}", "tests/integration/proof-whitelist.yaml", data]]


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
) -> Path:
    """Write one case: the inputs `analyze` uses for this bundle, chosen the
    way `analyze` chooses them (baseline.changes), with every public
    address replaced. Fails if a protected address (the controller's, the
    server's) or any public address survives in any form, or if replacing
    them changed what the checks find."""
    found = changes(store, host, identity, recipients, bundle_id)
    if any(c.newer for c in found.comparisons):
        raise ValueError(f"{name}: the baseline is newer than the bundle; not a useful case")
    target = store.bundle(bundle_id)
    previous = next((c.bundle_id for c in found.comparisons if c.label == "previous"), None)
    earlier = [r for r in usable_bundles(store, host) if r["started_at"] < target["started_at"]]
    no_baseline = (
        "this bundle is the baseline"
        if found.baseline_id == bundle_id and not found.first
        else "no baseline yet"
    )
    case: dict[str, Any] = {
        "format": CASE_FORMAT,
        "name": name,
        "host": host,
        "target": bundle_id,
        "previous": previous,
        "baseline": found.baseline_id,
        "no_baseline": no_baseline,
        "earlier": [r["id"] for r in earlier],
        "whitelist": proof_layers(host),
        "started": {},
        "snapshots": {},
        "events": {},
    }
    for row in [*earlier, target]:
        case["started"][row["id"]] = row["started_at"]
        case["events"][row["id"]] = [e.as_dict() for e in _events(store, row, identity, recipients)]
    for wanted in {bundle_id, found.baseline_id, *([previous] if previous else [])}:
        case["snapshots"][wanted] = snapshot_of(
            store, store.bundle(wanted), identity, recipients
        ).as_dict()
    real = json.dumps(case, sort_keys=True)
    text = scrub(real, protect)
    check_scrubbed(text, protect)
    if shape(run_case(json.loads(real))) != shape(run_case(json.loads(text))):
        raise ValueError(
            f"{name}: replacing the addresses changed what the checks find (a check that"
            " tells public addresses from others?); not a faithful case"
        )
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json.gz"
    path.write_bytes(gzip.compress(text.encode(), mtime=0))
    write_expected(path)
    return path


def shape(result: dict[str, Any]) -> list[tuple]:
    """What the checks found, apart from the address text in summaries."""
    return sorted(
        (f["check"], f["band"], f["category"], f.get("variant"), f["ratio"])
        for f in result["findings"]
    ) + [("probability", result["score"]["probability"])]


def _events(store, row, identity, recipients) -> list[Event]:
    parsed = load_events(store, row, identity)
    if parsed is None:
        parsed = parse_bundle(row, identity)
        store_parsed(store, row, recipients, parsed)
    return parsed.events


# An IPv4 address: a following ":" is allowed (address:port).
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d]|\.\d)")
# IPv6 candidates (validated by ipaddress): hex groups and colons, any case,
# compressed or not, possibly ending in an IPv4 address.
_IPV6 = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{1,4})?(?![\w:.])"
)


def _public(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    if not address.is_global:
        return None
    if address.version == 6:
        # "::1:323" is chrony's loopback listener written as address:port,
        # not a public address; a public address with a port stays public.
        head, _, port = text.rpartition(":")
        if port.isdigit() and int(port) <= 65535 and _parses_not_global(head):
            return None
    return address


def _parses_not_global(text: str) -> bool:
    try:
        return not ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def _dashed(address: str) -> str:
    return address.replace(".", "-").replace(":", "-")


def _hex_forms(address: str) -> list[str]:
    """How /proc/net writes an IPv4 address (both byte orders)."""
    try:
        packed = ipaddress.ip_address(address).packed
    except ValueError:
        return []
    return [packed.hex().upper(), packed[::-1].hex().upper()] if len(packed) == 4 else []


def scrub(text: str, protect: list[str]) -> str:
    """Every public IPv4 and IPv6 address anywhere in the text (values, log
    lines, settings, address:port), and the protected ones, replaced by a
    documentation address, consistently (the same address always becomes
    the same documentation one, so the case still links it across events
    and snapshots), also in a reverse-DNS name's dashed form. Version
    numbers that happen to parse as public addresses are replaced too:
    leaking nothing matters more than keeping them."""
    found: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
    for token in _IPV4.findall(text) + _IPV6.findall(text) + list(protect):
        if (address := _public(token)) is not None:
            found[token] = address
    canonical = sorted({str(a) for a in found.values()}, key=lambda a: (":" in a, a))
    fakes: dict[str, str] = {}
    v4 = v6 = 0
    for address in canonical:
        if ":" in address:
            v6 += 1
            fakes[address] = f"2001:db8::{v6:x}"
        else:
            fakes[address] = f"203.0.113.{v4 + 1}" if v4 < 250 else f"198.51.100.{v4 - 249}"
            v4 += 1
    for token in sorted(found, key=len, reverse=True):
        fake = fakes[str(found[token])]
        pattern = _IPV6.pattern if ":" in token else _IPV4.pattern
        text = re.sub(
            pattern, lambda m, t=token, f=fake: f if m.group(0) == t else m.group(0), text
        )
        dashed = _dashed(token)
        text = re.sub(rf"(?<![\d])(?<!\d-){re.escape(dashed)}(?![\d])(?!-\d)", _dashed(fake), text)
    return text


def check_scrubbed(text: str, protect: list[str]) -> None:
    """The post-condition: no public address in any form we know of, and
    no protected one, plain, dashed or in /proc/net hex."""
    left = sorted({t for t in _IPV4.findall(text) + _IPV6.findall(text) if _public(t) is not None})
    if left:
        raise ValueError(f"public addresses survived scrubbing: {left[:5]}")
    upper = text.upper()
    for address in protect:
        forms = [address, _dashed(address), *_hex_forms(address)]
        if any(form.upper() in upper for form in forms if form):
            raise ValueError("a protected address survived scrubbing")


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
        since_baseline = None
    elif baseline == previous:
        since_baseline = since_previous
    else:
        since_baseline = compare(snapshots[baseline], snapshot)
    no_baseline = case["no_baseline"]
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
        previous_snapshot=snapshots[previous] if previous else None,
    )
    whitelist = build(
        [
            (label, file, Layer.model_validate(data))
            for label, file, data in case.get("whitelist", [])
        ]
    )
    findings, ran, scored, applied = evaluate(context, PRIOR, whitelist, TODAY)
    return {"findings": findings, "checks": ran, "score": scored, "whitelist": applied}


def expected_path(case_path: Path) -> Path:
    return case_path.with_name(case_path.name.removesuffix(".json.gz") + ".expected.json")


def write_expected(case_path: Path) -> dict[str, Any]:
    case = load_case(case_path)
    result = run_case(case)
    expected_path(case_path).write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    for mode in ADVISOR_MODES:
        advisor_path(case_path, mode).write_text(advisor_text(case, result, mode))
    return result


# What the advisor would be sent for the case (Phase 3, PR 3.1): any change
# to the request shows up as a diff, like a change to the findings.
ADVISOR_MODES = ("pseudonymize", "strict")


def advisor_path(case_path: Path, mode: str) -> Path:
    return case_path.with_name(case_path.name.removesuffix(".json.gz") + f".advisor-{mode}.json")


def advisor_text(case: dict[str, Any], result: dict[str, Any], mode: str) -> str:
    from checker.advisor.case import build_case, known_identifiers, redact

    target = case["target"]
    snapshots = {k: Snapshot.from_dict(v) for k, v in case["snapshots"].items()}
    events = [Event(**e) for e in case["events"][target]]
    built = build_case(case["host"], result, events, snapshots[target], snapshots)
    known = known_identifiers(
        case["host"], snapshots[target], result["findings"], events, result["score"]["chains"]
    )
    payload, _ = redact(built, mode, known)
    return json.dumps(payload, indent=1, ensure_ascii=False) + "\n"


def cases() -> list[Path]:
    return sorted(CASES.glob("*.json.gz"))


def orphans() -> list[Path]:
    """Expectations whose case is gone."""
    have = {expected_path(p) for p in cases()}
    have |= {advisor_path(p, mode) for p in cases() for mode in ADVISOR_MODES}
    stored = [*CASES.glob("*.expected.json"), *CASES.glob("*.advisor-*.json")]
    return [p for p in sorted(stored) if p not in have]
