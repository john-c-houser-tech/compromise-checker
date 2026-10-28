"""Purge (policy §8): delete stored evidence for a host or a date range, or
everything past the retention period, with a record of what went.

Automatic expiry (`--expired`) keeps each inventoried host's current
baseline bundle, however old: later analyses compare with it, and letting
it expire would make a change nobody accepted (a backdoor added after the
baseline) disappear once enough time passed. It goes when a newer baseline
is accepted, or when the host leaves the inventory. An explicit purge (a
host, or `--before`) removes what it names, baselines included, and says
so: the host's next analysis then takes its oldest remaining bundle as the
baseline."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from checker.baseline import current_baseline
from checker.evidence import Store


@dataclass
class Plan:
    scope: dict[str, Any]
    bundles: list[Any] = field(default_factory=list)  # bundle rows, oldest first
    # Host: "moved" (its baseline goes, other bundles stay) or "emptied".
    baselines: dict[str, str] = field(default_factory=dict)
    kept: list[Any] = field(default_factory=list)  # expired baselines kept
    files: list[Path] = field(default_factory=list)
    reports: list[Path] = field(default_factory=list)
    outside: list[str] = field(default_factory=list)  # paths not under the evidence folder
    # Each affected host's Store.purge_state when planned; the purge itself
    # re-checks it, so a baseline set meanwhile isn't purged unprotected.
    expect: dict[str, list[Any]] = field(default_factory=dict)


def parse_before(text: str) -> datetime:
    """A date (midnight UTC) or a full time; one without a zone is UTC."""
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"not a date: {text!r} (use YYYY-MM-DD)") from None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _started(row: Any) -> datetime:
    return datetime.fromisoformat(row["started_at"])


def plan(
    store: Store,
    base: Path,
    inventory: set[str],
    retention_days: int,
    host: str | None = None,
    before: datetime | None = None,
    expired: bool = False,
    now: datetime | None = None,
    files: bool = True,
) -> Plan:
    """What a purge would delete. Nothing is changed. Without `files`, only
    the bundles (a count, without hashing every report)."""
    if expired and before is not None:
        raise ValueError("--expired and --before can't be combined")
    if not (host or before or expired):
        raise ValueError("say what to purge: a host, --before DATE or --expired")
    now = now or datetime.now(UTC)
    scope: dict[str, Any] = {}
    if host:
        scope["host"] = host
    if before is not None:
        scope["before"] = before.isoformat()
    if expired:
        before = now - timedelta(days=retention_days)
        scope.update(expired=True, retention_days=retention_days, before=before.isoformat())
    result = Plan(scope)
    for name in [host] if host else store.hosts():
        rows = store.bundles(name)
        doomed = [r for r in rows if before is None or _started(r) < before]
        baseline = current_baseline(store, name)
        if (
            expired
            and baseline is not None
            and name in inventory
            and any(r["id"] == baseline["bundle_id"] for r in doomed)
        ):
            result.kept.extend(r for r in doomed if r["id"] == baseline["bundle_id"])
            doomed = [r for r in doomed if r["id"] != baseline["bundle_id"]]
        if not doomed:
            continue
        result.expect[name] = store.purge_state(name)
        result.bundles.extend(doomed)
        gone = {r["id"] for r in doomed}
        if len(gone) == len(rows):
            result.baselines[name] = "emptied"
        elif baseline is not None and baseline["bundle_id"] in gone:
            result.baselines[name] = "moved"
    result.bundles.sort(key=_started)
    if not files:
        return result
    evidence = (base / "evidence").resolve()
    for row in result.bundles:
        path = Path(row["path"])
        if not path.resolve().is_relative_to(evidence):
            result.outside.append(str(path))
            continue
        result.files.extend(_bundle_files(path, row["id"]))
    result.reports = _reports(store, base, [r["id"] for r in result.bundles])
    return result


def _bundle_files(path: Path, bundle_id: str) -> list[Path]:
    """The bundle, its sidecar, and what was derived from it (events,
    snapshots, assessments, including older versions a newer parser
    replaced): every file in its folder named after the bundle."""
    if not path.parent.is_dir():
        return []
    return sorted(
        p for p in path.parent.iterdir() if p.name.startswith(f"{bundle_id}.") and not p.is_dir()
    )


def _reports(store: Store, base: Path, bundle_ids: list[str]) -> list[Path]:
    """Reports in the reports folder that show any of these bundles: found
    by the hash each report left in the custody of the bundles it covers. A
    report written elsewhere (`--output`) is the operator's to delete."""
    digests = set()
    for bundle_id in bundle_ids:
        for entry in store.custody_of(bundle_id):
            if entry["action"] == "reported" and entry["detail"]:
                digests.add(json.loads(entry["detail"]).get("report_sha256"))
    folder = base / "reports"
    if not digests or not folder.is_dir():
        return []
    found = []
    for path in sorted(folder.glob("report-*.html")):
        if path.is_file() and not path.is_symlink() and _sha256(path) in digests:
            found.append(path)
    return found


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class Outcome:
    counts: dict[str, int]
    deleted: list[Path]
    failed: list[tuple[Path, str]]


def execute(store: Store, base: Path, chosen: Plan) -> Outcome:
    """Delete the rows (one transaction, recorded in `purges`), then the
    files. A crash between the two leaves files no row refers to; every
    purge also removes those (leftovers), even when it has nothing new to
    delete."""
    if chosen.bundles:
        counts = store.purge(
            [r["id"] for r in chosen.bundles],
            chosen.scope | {"files_planned": len(chosen.files)},
            chosen.baselines,
            chosen.expect,
        )
    else:
        counts = {"bundles": 0}
    counts["reports"] = len(chosen.reports)
    deleted, failed = _delete(chosen.files + chosen.reports + leftovers(store, base))
    _remove_empty_folders(base, chosen.bundles)
    return Outcome(counts, deleted, failed)


def leftovers(store: Store, base: Path) -> list[Path]:
    """Files of bundles an earlier purge removed from the database but
    couldn't delete from disk."""
    evidence = base / "evidence"
    present = {r["id"] for r in store.bundles()}
    found: list[Path] = []
    for row in store.purges():
        for bundle_id, host in json.loads(row["bundles"]):
            if bundle_id in present:
                continue
            folder = evidence / host
            if folder.is_dir() and not folder.is_symlink():
                found.extend(
                    p
                    for p in folder.iterdir()
                    if p.name.startswith(f"{bundle_id}.") and not p.is_dir()
                )
    return sorted(set(found))


def _delete(paths: list[Path]) -> tuple[list[Path], list[tuple[Path, str]]]:
    deleted, failed = [], []
    for path in dict.fromkeys(paths):
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            failed.append((path, exc.strerror or type(exc).__name__))
        else:
            deleted.append(path)
    return deleted, failed


def _remove_empty_folders(base: Path, rows: list[Any]) -> None:
    for host in {r["host"] for r in rows}:
        folder = base / "evidence" / host
        try:
            folder.rmdir()  # only if empty
        except OSError:
            pass


def expired_count(store: Store, base: Path, inventory: set[str], retention_days: int) -> int:
    """How many bundles `purge --expired` would delete now."""
    return len(plan(store, base, inventory, retention_days, expired=True, files=False).bundles)
