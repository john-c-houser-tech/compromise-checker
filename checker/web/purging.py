"""Deleting stored evidence from a page (plan 5.13): what would go is worked out and shown, without
changing anything, then worked out again when it's confirmed. If that differs, the person looks
again. It calls what `checker purge` calls."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from markupsafe import escape

from checker.evidence import EvidenceError, Store, database_file, load_config
from checker.inventory import hosts_file, load_inventory
from checker.purge import execute, leftovers, parse_before
from checker.purge import plan as purge_plan
from checker.schedule import Busy, run_lock

SHOWN = 100
THE_WORD = "purge"  # noqa: S105 - what's typed to confirm, as on the command line
_CHANGED = (
    "What this would delete has changed since you looked, so nothing was deleted. Look again."
)


class PurgeProblem(Exception):
    """Why it can't go ahead, in words for the page."""


def named(params) -> str:
    """What it's asked to delete, for the record."""
    what = params.get("what", "")
    if what == "expired":
        return "past the retention period"
    host, before = params.get("host", ""), params.get("before", "")
    return " ".join(part for part in (host, f"before {before}" if before else "") if part)


def _plan(store: Store, base: Path, params) -> Any:
    """The plan for what the form asks; PurgeProblem for what can't be asked."""
    config = load_config(base)
    inventory = {host.name for host in load_inventory(hosts_file(base)).hosts}
    what = params.get("what", "")
    host, before_text = params.get("host", ""), params.get("before", "").strip()
    before = None
    if what in ("host", "before") and before_text:
        try:
            before = parse_before(before_text)
        except (ValueError, TypeError):
            raise PurgeProblem("Choose a date, such as 2026-07-01.") from None
    if what == "expired":
        if not inventory:
            raise PurgeProblem(
                "There are no servers in the list, so this would delete every server's baseline."
                " Delete a removed server's evidence by name instead."
            )
        return purge_plan(store, base, inventory, config.retention_days, expired=True)
    if what == "host":
        if host not in store.hosts():
            raise PurgeProblem("There's no stored evidence for that server.")
        return purge_plan(store, base, inventory, config.retention_days, host, before)
    if what == "before":
        if before is None:
            raise PurgeProblem("Choose a date, such as 2026-07-01.")
        return purge_plan(store, base, inventory, config.retention_days, None, before)
    raise PurgeProblem("Choose what to delete.")


def _sight(chosen: Any, left: list[Path]) -> str:
    """What was shown, to compare with when it's confirmed."""
    return hashlib.sha256(
        json.dumps(
            [
                [row["id"] for row in chosen.bundles],
                sorted(chosen.baselines.items()),
                [row["id"] for row in chosen.kept],
                len(left),
            ]
        ).encode()
    ).hexdigest()


def _preview(chosen: Any, left: list[Path]) -> dict[str, Any]:
    rows = [(row["started_at"], row["host"]) for row in chosen.bundles]
    return {
        "checks": len(rows),
        "shown": rows[:SHOWN],
        "more": max(0, len(rows) - SHOWN),
        "reports": len(chosen.reports),
        "proposals": len(chosen.proposals),
        "leftovers": len(left),
        "moved": sorted(host for host, what in chosen.baselines.items() if what == "moved"),
        "emptied": sorted(host for host, what in chosen.baselines.items() if what == "emptied"),
        "kept": sorted({row["host"] for row in chosen.kept}),
        "outside": bool(chosen.outside),
        "nothing": not (rows or left),
        "sight": _sight(chosen, left),
    }


def page(base: Path, params) -> dict[str, Any]:
    """The choices, and if one is made, what it would delete. Nothing here changes anything."""
    config = load_config(base)
    what = params.get("what", "")
    context: dict[str, Any] = {
        "retention_days": config.retention_days,
        "what": what,
        "host": escape(params.get("host", "")),
        "before": escape(params.get("before", "")),
        "preview": None,
        "cant": "",
        "hosts": [],
    }
    if not database_file(base).exists():
        return context
    store = Store(database_file(base), read_only=True)
    try:
        listed = {host.name for host in load_inventory(hosts_file(base)).hosts}
        context["hosts"] = [
            {"value": escape(name), "listed": name in listed} for name in sorted(store.hosts())
        ]
        if what:
            try:
                chosen = _plan(store, base, params)
                context["preview"] = _preview(chosen, leftovers(store, base))
            except PurgeProblem as exc:
                context["cant"] = str(exc)
    finally:
        store.close()
    return context


def run(base: Path, params, check_running: bool) -> dict[str, Any]:
    """What was deleted. Refused unless the word was typed and it's still what was shown."""
    if params.get("word", "").strip() != THE_WORD:
        raise PurgeProblem(f"Type {THE_WORD} in the box to say you mean it. Nothing was deleted.")
    if check_running:
        raise PurgeProblem("A check is running. Try again when it has finished.")
    try:
        with run_lock(base):
            store = Store(database_file(base))
            try:
                chosen = _plan(store, base, params)
                left = leftovers(store, base)
                if _sight(chosen, left) != params.get("sight", ""):
                    raise PurgeProblem(_CHANGED)
                if chosen.outside:
                    raise PurgeProblem(
                        "Some of this is stored outside the evidence folder, so nothing was"
                        " deleted. Whoever looks after this machine needs to look at it."
                    )
                if not (chosen.bundles or left):
                    raise PurgeProblem("There's nothing to delete.")
                outcome = execute(store, base, chosen)
            finally:
                store.close()
    except Busy:
        raise PurgeProblem("A check is running. Try again when it has finished.") from None
    except (EvidenceError, OSError, sqlite3.Error, ValueError) as exc:
        print(f"checker web: a purge failed: {type(exc).__name__}", file=sys.stderr)
        raise PurgeProblem(
            "That couldn't be done, or what it would delete changed as it started. Look again."
        ) from None
    return {
        "checks": outcome.counts.get("bundles", 0),
        "files": len(outcome.deleted),
        "failed": len(outcome.failed),
        "changed": len(outcome.changed),
        "moved": sorted(host for host, what in chosen.baselines.items() if what == "moved"),
        "summary": (
            f"{outcome.counts.get('bundles', 0)} checks, {len(outcome.deleted)} files deleted,"
            f" {len(outcome.failed)} couldn't be deleted, {len(outcome.changed)} left as changed"
        ),
    }
