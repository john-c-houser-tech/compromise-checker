"""Decisions a person makes about a host (plan 5.12): accepting its baseline, and approving or
refusing the AI advisor's whitelist rules. Each can hide a real change, so what it would hide is
worked out and shown first, and worked out again when it's confirmed. Both call what the command
line calls; a rule approved here goes into the same layer file a person would edit by hand."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from checker.advisor.proposals import _comment, proposals_directory
from checker.baseline import accept, current_baseline, snapshot_of, usable_bundles
from checker.evidence import EvidenceError, Store, database_file
from checker.files import atomic_write
from checker.fleet import _settings
from checker.snapshot import compare
from checker.whitelist import (
    Layer,
    Rule,
    Whitelist,
    WhitelistError,
    _StrictLoader,
    build,
    directory,
    layer_files,
    read_layer,
)
from checker.whitelist_review import compare as compare_whitelists

SHOWN_PER_KIND = 20
LOOK_BACK = timedelta(days=30)  # enough to see what a rule does, and a page mustn't take minutes
TOO_WORRYING = ("High", "Critical")
_writing = threading.Lock()  # one process: two tabs mustn't each read a file and write it back


@dataclass
class BaselineChoice:
    bundle: str
    collected: str
    current: str | None
    current_at: str | None
    changes: list[dict[str, Any]] = field(default_factory=list)
    problem: str | None = None


@dataclass
class Proposed:
    file: str
    id: str
    layer: str  # "host" or "group"
    rule: dict[str, Any]
    digest: str
    problem: str | None = None
    hides: list[str] = field(default_factory=list)
    reveals: list[str] = field(default_factory=list)
    before: tuple | None = None
    after: tuple | None = None
    hosts: list[str] = field(default_factory=list)


def baseline_choice(base: Path, host: str) -> BaselineChoice | None:
    """The latest collection, and what changed since the current baseline: what accepting it would
    make normal. Read only: a page looks, so if something isn't worked out yet it says so."""
    settings = _settings(base)
    store = Store(database_file(base), read_only=True)
    try:
        rows = usable_bundles(store, host)
        if not rows:
            return None
        latest = rows[-1]
        baseline = current_baseline(store, host)
        choice = BaselineChoice(
            latest["id"],
            latest["started_at"],
            baseline["bundle_id"] if baseline else None,
            baseline["at"] if baseline else None,
        )
        if baseline is None or baseline["bundle_id"] == latest["id"]:
            return choice
        try:
            recipients = settings.config.recipients
            old = snapshot_of(
                store, store.bundle(baseline["bundle_id"]), settings.identity, recipients
            )
            new = snapshot_of(store, latest, settings.identity, recipients)
        except sqlite3.OperationalError:  # it would have to store a parse: that's for a check
            choice.problem = "Work this server's results out again first, so this can be compared."
            return choice
        for name, diff in compare(old, new).items():
            counts = {kind: len(diff[kind]) for kind in ("added", "removed", "changed")}
            if not any(counts.values()):
                continue
            choice.changes.append(
                {
                    "name": name,
                    "counts": counts,
                    "added": _some(diff["added"]),
                    "removed": _some(diff["removed"]),
                    "changed": _some(diff["changed"]),
                    "notes": [str(note) for note in diff["notes"]],
                }
            )
        return choice
    finally:
        store.close()


def _some(items: Any) -> list[str]:
    """A section's differences are by the name of each thing that differs."""
    named = items.keys() if isinstance(items, dict) else items
    return [str(name) for name in list(named)[:SHOWN_PER_KIND]]


def accept_baseline(base: Path, host: str, bundle: str, reason: str, who: str) -> list[str]:
    """Only the collection that was shown: anything newer hasn't been looked at."""
    settings = _settings(base)
    store = Store(database_file(base))
    try:
        rows = usable_bundles(store, host)
        if not rows or rows[-1]["id"] != bundle:
            raise EvidenceError(
                "There's been a newer check since this page was opened. Look again."
            )
        said = (
            f"{reason.strip()} (accepted from the web interface by {who})" if reason.strip() else ""
        )
        _, notes = accept(store, host, said, settings.identity, settings.config.recipients, bundle)
    finally:
        store.close()
    return notes


def _digest(rule: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(rule, sort_keys=True, default=str).encode()).hexdigest()


def _proposal_paths(base: Path, host: str) -> list[Path]:
    """This host's by the exact form the advisor names them: `web` mustn't find `web-2`'s."""
    folder = proposals_directory(base)
    if folder.is_symlink() or not folder.is_dir():
        return []
    safe = re.escape(re.sub(r"[^A-Za-z0-9._-]", "_", host))
    named = re.compile(rf"{safe}-\d{{8}}T\d{{6}}Z(-\d+)?\.yaml")
    return sorted(
        path
        for path in folder.iterdir()
        if named.fullmatch(path.name) and path.is_file() and not path.is_symlink()
    )


def _read_proposals(path: Path) -> list[tuple[str, dict[str, Any]]]:
    """(layer, rule) in order. The file says each rule's layer in the comment above it."""
    text = path.read_text(encoding="utf-8")
    data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - a SafeLoader subclass
    rules = (data or {}).get("rules") or []
    layers = re.findall(r"^\s*# for whitelist/(hosts|groups)/", text, re.M)
    if len(layers) != len(rules) or not all(isinstance(rule, dict) for rule in rules):
        raise ValueError("it doesn't look as the advisor writes them")
    return [("group" if la == "groups" else "host", r) for la, r in zip(layers, rules, strict=True)]


def proposals(base: Path, host: str) -> list[Proposed]:
    found = []
    for path in _proposal_paths(base, host):
        try:
            for layer, rule in _read_proposals(path):
                found.append(Proposed(path.name, str(rule.get("id")), layer, rule, _digest(rule)))
        except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
            # Set aside, and shown as that: never a page that fails, and never a rule half read.
            found.append(
                Proposed(path.name, "?", "host", {}, "", f"can't be read ({type(exc).__name__})")
            )
    return found


def _candidate(rule: dict[str, Any], owner: str) -> Rule:
    return Rule.model_validate({**rule, "owner": owner})


def _set_with(base: Path, host: str, group: str | None, layer: str, rule: Rule) -> Whitelist | None:
    """What this host's set would be with the rule added to its layer."""
    label = f"group {group}" if layer == "group" else f"host {host}"
    target = _layer_path(base, host, group, layer)
    files = dict(layer_files(base, host, group))
    layers = []
    for name in ("global", f"group {group}" if group else None, f"host {host}"):
        here = files.get(name)
        if name == label:
            current = read_layer(target) if target.is_file() else Layer()
            changed = current.model_copy(update={"rules": [*current.rules, rule]})
            layers.append((name, str(target), changed))
        elif here:
            layers.append((name, str(here), read_layer(here)))
    return build(layers)


def _layer_path(base: Path, host: str, group: str | None, layer: str) -> Path:
    if layer == "group":
        if not group:
            raise WhitelistError(f"{host} has no group in the list of servers")
        return directory(base) / "groups" / f"{group}.yaml"
    return directory(base) / "hosts" / f"{host}.yaml"


def preview(base: Path, host: str, proposed: Proposed, owner: str) -> Proposed:
    """Fills in what the rule would do on each server its layer reaches, or why it can't go in."""
    if proposed.problem:
        return proposed
    settings = _settings(base)
    groups = {h.name: h.group for h in settings.inventory.hosts}
    group = groups.get(host)
    try:
        rule = _candidate(proposed.rule, owner)
    except ValidationError as exc:
        proposed.problem = "it isn't a valid rule: " + "; ".join(
            str(error["msg"]) for error in exc.errors()
        )
        return proposed
    if rule.expires != "never" and isinstance(rule.expires, date):
        if rule.expires < datetime.now(UTC).date():
            proposed.problem = "it has passed its expiry date"
            return proposed
    if proposed.layer == "group" and not group:
        proposed.problem = "it's for a group, and this server has none"
        return proposed
    proposed.hosts = (
        sorted(name for name, g in groups.items() if g == group)
        if proposed.layer == "group"
        else [host]
    )
    store = Store(database_file(base), read_only=True)
    try:
        since = datetime.now(UTC) - LOOK_BACK
        for name in proposed.hosts:
            current = settings.whitelist_for(name)
            changed = _set_with(base, name, groups.get(name), proposed.layer, rule)
            results = [
                r
                for r in compare_whitelists(store, name, settings.identity, current, changed, since)
                if not r.get("skipped")
            ]
            for result in results:
                for line in result["hidden"]:
                    if line not in proposed.hides:
                        proposed.hides.append(line)
                for line in result["revealed"]:
                    if line not in proposed.reveals:
                        proposed.reveals.append(line)
            if results and name == host:
                proposed.before, proposed.after = results[-1]["before"], results[-1]["after"]
            worried = next((r for r in results[-1:] if r["before"][1] in TOO_WORRYING), None)
            if worried and not proposed.problem:
                proposed.problem = (
                    f"{name} is assessed {worried['before'][1]}: rules for routine activity are"
                    " for a server that looks clean"
                )
    except (WhitelistError, EvidenceError) as exc:
        proposed.problem = str(exc)
    finally:
        store.close()
    if not proposed.problem and any(
        line.split(" ")[0].lower() == "critical" for line in proposed.hides
    ):
        proposed.problem = "it would hide a critical finding"
    return proposed


def find(base: Path, host: str, file: str, rule_id: str, digest: str) -> Proposed | None:
    """The very rule that was shown: the same file, id and content."""
    for proposed in proposals(base, host):
        if (proposed.file, proposed.id, proposed.digest) == (file, rule_id, digest):
            return proposed
    return None


def _appended(text: str, rule: dict[str, Any], note: str) -> str:
    """The layer file's text with one more rule, leaving what a person wrote there as it was, their
    comments included. Raises ValueError when it can't be done safely, for editing by hand."""
    lines = text.split("\n")
    if text.strip() and not any(line.startswith("rules:") for line in lines):
        text = text.rstrip("\n") + "\nrules:\n"
    elif not text.strip():
        text = "rules:\n"
    lines = text.rstrip("\n").split("\n")
    start = next(i for i, line in enumerate(lines) if line.startswith("rules:"))
    if lines[start].split("#")[0].strip() != "rules:":
        raise ValueError("its rules aren't written as a plain list")
    if any(line and not line[0].isspace() and line[0] not in "#-" for line in lines[start + 1 :]):
        raise ValueError("something else comes after its rules")
    items = [line for line in lines[start + 1 :] if line.lstrip().startswith("- ")]
    indent = len(items[0]) - len(items[0].lstrip()) if items else 2
    body = yaml.safe_dump([rule], sort_keys=False, allow_unicode=False, width=float("inf"))
    added = [" " * indent + f"# {note}"]
    added += [" " * indent + line for line in body.rstrip("\n").split("\n")]
    return "\n".join([*lines, *added]) + "\n"


def approve(base: Path, host: str, file: str, rule_id: str, digest: str, who: str) -> str:
    """Puts the rule in its layer file and takes it out of the proposals; which server or group it
    now covers. Worked out afresh here: what was shown may no longer be true. Raises ValueError with
    words for the page."""
    with _writing:
        proposed = find(base, host, file, rule_id, digest)
        if proposed is None:
            raise ValueError("That rule has changed or gone since this page was opened.")
        preview(base, host, proposed, who)
        if proposed.problem:
            raise ValueError(f"That rule can't go in: {proposed.problem}.")
        settings = _settings(base)
        group = {h.name: h.group for h in settings.inventory.hosts}.get(host)
        target = _layer_path(base, host, group, proposed.layer)
        if target.is_symlink():
            raise ValueError(f"{target} is a link: edit it by hand.")
        rule = {**proposed.rule, "owner": who}
        old = target.read_text(encoding="utf-8") if target.is_file() else ""
        note = f"Approved from the web interface by {_comment(who, 80)}"
        before = yaml.safe_load(old) or {}
        try:
            text = _appended(old, rule, note)
            after = yaml.safe_load(text) or {}
            wanted = {**before, "rules": [*(before.get("rules") or []), rule]}
            if after != wanted:
                raise ValueError("it didn't read back as the same rules and one more")
            Layer.model_validate(yaml.load(text, Loader=_StrictLoader))  # noqa: S506 - a SafeLoader
        except (ValueError, yaml.YAMLError) as exc:
            raise ValueError(
                f"{target.name} can't be added to automatically ({exc}): edit it by hand."
            ) from None
        atomic_write(target, text)
        _take_out(base, host, file, digest)
    return group if proposed.layer == "group" else host


def refuse(base: Path, host: str, file: str, rule_id: str, digest: str) -> None:
    with _writing:
        if find(base, host, file, rule_id, digest) is None:
            raise ValueError("That rule has changed or gone since this page was opened.")
        _take_out(base, host, file, digest)


def _take_out(base: Path, host: str, file: str, digest: str) -> None:
    path = next((p for p in _proposal_paths(base, host) if p.name == file), None)
    if path is None:
        return
    left = [(la, r) for la, r in _read_proposals(path) if _digest(r) != digest]
    if not left:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        return
    lines = ["# Whitelist proposals from the AI advisor: advice, not rules.", "", "rules:"]
    for layer, rule in left:
        where = "groups" if layer == "group" else "hosts"
        lines += ["", f"  # for whitelist/{where}/{_comment(host, 80)}.yaml"]
        body = yaml.safe_dump([rule], sort_keys=False, allow_unicode=False, width=float("inf"))
        lines += ["  " + line for line in body.rstrip("\n").split("\n")]
    atomic_write(path, "\n".join(lines) + "\n")
