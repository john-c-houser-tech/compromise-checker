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

import fnmatch
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
    proposals: list[Path] = field(default_factory=list)  # the advisor's whitelist proposals
    # Each report's and proposal's hash when planned: one that changes before
    # the purge runs (another report written at its name) is left alone.
    digests: dict[Path, str] = field(default_factory=dict)
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
    only: set[str] | None = None,
) -> Plan:
    """What a purge would delete. Nothing is changed. Without `files`, only
    the bundles (a count, without hashing every report); with `only`, only
    those hosts' bundles."""
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
    names = [host] if host else store.hosts()
    for name in names if only is None else [n for n in names if n in only]:
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
    ids = [r["id"] for r in result.bundles]
    result.reports = _reports(store, base, ids)
    result.proposals = _proposals(store, base, ids)
    for path in result.reports + result.proposals:
        if (digest := _hash(path)) is not None:
            result.digests[path] = digest
    result.reports = [p for p in result.reports if p in result.digests]
    result.proposals = [p for p in result.proposals if p in result.digests]
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
    return _derived(store, base / "reports", "report-*", bundle_ids, "reported", "report_sha256")


def _derived(
    store: Store, folder: Path, pattern: str, bundle_ids: list[str], action: str, key: str
) -> list[Path]:
    """Files in `folder` made from any of these bundles: found by the hash
    each left in the custody of the bundles it was made from."""
    digests = {_detail(entry).get(key) for entry in _entries(store, bundle_ids, action)}
    if not digests or not folder.is_dir() or folder.is_symlink():
        return []
    found = []
    for path in sorted(folder.glob(pattern)):
        if path.is_file() and not path.is_symlink() and _hash(path) in digests:
            found.append(path)
    return found


def _proposals(store: Store, base: Path, bundle_ids: list[str]) -> list[Path]:
    """The advisor's whitelist proposal files made from any of these
    bundles: found by the name each left in their custody, not its hash,
    since the operator is told to edit the file (its owner). A name is only
    ever a plain file name in the proposals folder."""
    folder = base / "proposals"
    if not folder.is_dir() or folder.is_symlink():
        return []
    found = []
    for entry in _entries(store, bundle_ids, "proposed"):
        name = _detail(entry).get("file")
        if not isinstance(name, str) or not _plain_name(name, "*.yaml"):
            continue
        path = folder / name
        if path.is_file() and not path.is_symlink():
            found.append(path)
    return sorted(set(found))


def _plain_name(name: str, pattern: str) -> bool:
    return (
        name == Path(name).name
        and name not in ("", ".", "..")
        and "\\" not in name
        and fnmatch.fnmatchcase(name, pattern)
    )


def _entries(store: Store, bundle_ids: list[str], action: str) -> list[Any]:
    return [
        entry
        for bundle_id in bundle_ids
        for entry in store.custody_of(bundle_id)
        if entry["action"] == action and entry["detail"]
    ]


def _detail(entry: Any) -> dict[str, Any]:
    try:
        detail = json.loads(entry["detail"])
    except ValueError:
        return {}
    return detail if isinstance(detail, dict) else {}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def _hash(path: Path) -> str | None:
    """The file's sha256, or None when it can't be read (gone, or not ours
    to read): such a file is never taken for one that was planned."""
    try:
        return _sha256(path)
    except OSError:
        return None


@dataclass
class Outcome:
    counts: dict[str, int]
    deleted: list[Path]
    failed: list[tuple[Path, str]]
    changed: list[Path] = field(default_factory=list)  # left: not what was planned


def execute(store: Store, base: Path, chosen: Plan) -> Outcome:
    """Delete the rows (one transaction, recorded in `purges`), then the
    files. A crash between the two leaves files no row refers to; every
    purge also removes those (leftovers), even when it has nothing new to
    delete."""
    planned = chosen.reports + chosen.proposals
    now = {path: _hash(path) for path in planned}
    changed = [p for p in planned if now[p] is not None and now[p] != chosen.digests.get(p)]
    reports = [p for p in chosen.reports if now[p] == chosen.digests.get(p)]
    proposals = [p for p in chosen.proposals if now[p] == chosen.digests.get(p)]
    if chosen.bundles:
        # The reports and proposals are named in the record, with their
        # hashes, so a purge that can't delete one now (or is cut short) is
        # finished by the next: once the custody rows go, nothing else leads
        # to them.
        derived = [
            [path.relative_to(base).as_posix(), chosen.digests[path]]
            for path in reports + proposals
        ]
        counts = store.purge(
            [r["id"] for r in chosen.bundles],
            chosen.scope
            | {
                "files_planned": len(chosen.files),
                "reports": len(reports),
                "proposals": len(proposals),
                "derived": derived,
            },
            chosen.baselines,
            chosen.expect,
        )
    else:
        counts = {"bundles": 0}
    counts["reports"] = len(reports)
    counts["proposals"] = len(proposals)
    deleted, failed = _delete(chosen.files + reports + proposals + leftovers(store, base))
    _remove_empty_folders(base, chosen.bundles)
    return Outcome(counts, deleted, failed, changed)


def leftovers(store: Store, base: Path) -> list[Path]:
    """Files of bundles an earlier purge removed from the database but
    couldn't delete from disk, and the reports and proposals it named,
    each only while it still has the hash it had then."""
    evidence = base / "evidence"
    present = {r["id"] for r in store.bundles()}
    found: list[Path] = []
    for row in store.purges():
        found.extend(_derived_left(base, row))
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


def _derived_left(base: Path, row: Any) -> list[Path]:
    try:
        derived = json.loads(row["scope"]).get("derived")
    except (ValueError, AttributeError):
        return []
    if not isinstance(derived, list):
        return []
    found = []
    for item in derived:
        if not (isinstance(item, list) and len(item) == 2):
            continue
        where, digest = item
        if not (isinstance(where, str) and isinstance(digest, str)):
            continue
        folder_name, _, name = where.partition("/")
        patterns = {
            # plain, encrypted
            "reports": tuple(
                f"report-*.{kind}{end}" for kind in ("html", "pdf", "json") for end in ("", ".age")
            ),
            "proposals": ("*.yaml",),
        }.get(folder_name, ())
        if not any(_plain_name(name, pattern) for pattern in patterns):
            continue
        folder = base / folder_name
        path = folder / name
        if folder.is_symlink() or path.is_symlink() or not path.is_file():
            continue
        if _hash(path) == digest:
            found.append(path)
    return found


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
