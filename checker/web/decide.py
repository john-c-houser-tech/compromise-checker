"""Decisions a person makes about a host (plan 5.12): accepting its baseline, and approving or
refusing the AI advisor's whitelist rules. Each can hide a real change, so what it would hide is
worked out and shown first, and worked out again when it's confirmed: if that differs from what was
shown, the person looks again. When it can't be worked out, that blocks it: no news mustn't read as
good news. Both call what the command line calls; a rule approved here goes into the same layer file
a person would edit by hand."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import sys
import threading
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from checker.advisor.proposals import HAND_ONLY, MAX_DAYS, _comment, proposals_directory
from checker.analysis import load_snapshot
from checker.baseline import accept, current_baseline, usable_bundles
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
from checker.whitelist_review import compare_loaded, load_analyses

SHOWN_PER_KIND = 50
MOST_RULES_SHOWN = 20
MOST_PROPOSAL_BYTES = 256 * 1024
LOOK_BACK = timedelta(days=30)  # enough to see what a rule does, and a page mustn't take minutes
TOO_WORRYING = ("High", "Critical")
_GROUP = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_writing = threading.Lock()  # one process: two tabs mustn't each read a file and write it back


@dataclass
class BaselineChoice:
    bundle: str
    collected: str
    current: str | None
    current_at: str | None
    changes: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    problem: str | None = None


@dataclass
class Proposed:
    file: str
    id: str
    layer: str  # "host" or "group"
    named: str  # the layer's name in the file: the host's, or its group's
    rule: dict[str, Any]
    digest: str
    problem: str | None = None
    hides: list[str] = field(default_factory=list)
    reveals: list[str] = field(default_factory=list)
    before: tuple | None = None
    after: tuple | None = None
    hosts: list[str] = field(default_factory=list)
    sight: str = ""  # what was shown, to compare with when it's confirmed


def _described(kind: str, items: Any) -> tuple[list[str], int]:
    """Up to the limit, and how many more: an intruder chooses names, and so where they sort."""
    if isinstance(items, dict):
        lines = [
            f"{name}: " + ", ".join(f"{f} {pair[0]!r} to {pair[1]!r}" for f, pair in value.items())
            if kind == "changed"
            else str(name)
            for name, value in items.items()
        ]
    else:
        lines = [str(item) for item in items]
    return lines[:SHOWN_PER_KIND], max(0, len(lines) - SHOWN_PER_KIND)


def baseline_choice(base: Path, host: str) -> BaselineChoice | None:
    """The latest collection, and what changed since the current baseline: what accepting it would
    make normal. Read only, and nothing is parsed here: if it isn't worked out yet, it says so."""
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
        if latest["status"] != "complete":
            choice.notes.append(
                f"This check is {latest['status']}: what it couldn't see can't be compared later."
            )
        if baseline is None or baseline["bundle_id"] == latest["id"]:
            return choice
        accepted = store.bundle(baseline["bundle_id"])
        if accepted["started_at"] > latest["started_at"]:
            choice.notes.append("This check is older than the baseline it would replace.")
        old = load_snapshot(store, accepted, settings.identity)
        new = load_snapshot(store, latest, settings.identity)
        if old is None or new is None:
            choice.problem = "Work this server's results out again first, so this can be compared."
            return choice
        for name, diff in compare(old, new).items():
            counts = {kind: len(diff[kind]) for kind in ("added", "removed", "changed")}
            notes = [str(note) for note in diff["notes"]]
            if not any(counts.values()) and not notes:
                continue
            shown = {kind: _described(kind, diff[kind]) for kind in counts}
            choice.changes.append(
                {
                    "name": name,
                    "counts": counts,
                    "added": shown["added"][0],
                    "removed": shown["removed"][0],
                    "changed": shown["changed"][0],
                    "more": sum(more for _, more in shown.values()),
                    "notes": notes,
                }
            )
        return choice
    finally:
        store.close()


def accept_baseline(base: Path, host: str, bundle: str, reason: str, who: str) -> None:
    """Only the collection that was shown: anything newer hasn't been looked at."""
    settings = _settings(base)
    store = Store(database_file(base))
    try:
        rows = usable_bundles(store, host)
        if not rows or rows[-1]["id"] != bundle:
            raise EvidenceError("There's been a newer check since this page opened. Look again.")
        said = reason.strip()
        said = f"{said} (accepted from the web interface by {who})" if said else ""
        accept(store, host, said, settings.identity, settings.config.recipients, bundle)
    finally:
        store.close()


def _digest(layer: str, rule: dict[str, Any], index: int) -> str:
    text = json.dumps([layer, index, rule], sort_keys=True, default=str)
    return hashlib.sha256(text.encode()).hexdigest()


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


def _read_proposals(path: Path) -> list[tuple[str, str, dict[str, Any]]]:
    """(layer, its name, rule) in order. The file says each rule's layer in the comment above it,
    found from where the rule really starts: a rule's own text can't pass for one."""
    if path.stat().st_size > MOST_PROPOSAL_BYTES:
        raise ValueError("it's too big")
    text = path.read_text(encoding="utf-8")
    if any(isinstance(event, yaml.AliasEvent) for event in yaml.parse(text)):
        raise ValueError("the advisor's files have no aliases")
    data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - a SafeLoader subclass
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise ValueError("it doesn't look as the advisor writes them")
    nodes = yaml.compose(text, Loader=yaml.SafeLoader)
    starts = next(
        value.value for key, value in nodes.value if getattr(key, "value", None) == "rules"
    )
    lines = text.split("\n")
    found = []
    for rule, node in zip(rules, starts, strict=True):
        where = None
        at = node.start_mark.line - 1
        while at >= 0 and lines[at].lstrip().startswith("#"):
            where = where or re.fullmatch(
                r"\s*# for whitelist/(hosts|groups)/([^/]+)\.yaml", lines[at]
            )
            at -= 1
        if where is None:
            raise ValueError("a rule doesn't say which file it's for")
        found.append(("group" if where[1] == "groups" else "host", where[2], rule))
    return found


def proposals(base: Path, host: str) -> list[Proposed]:
    found = []
    for path in _proposal_paths(base, host):
        try:
            for index, (layer, named, rule) in enumerate(_read_proposals(path)):
                found.append(
                    Proposed(
                        path.name,
                        str(rule.get("id")),
                        layer,
                        named,
                        rule,
                        _digest(layer, rule, index),
                    )  # fmt: skip
                )
        except Exception as exc:  # noqa: BLE001 - never a page that fails, or a rule half read
            print(f"checker web: a proposal file: {type(exc).__name__}", file=sys.stderr)
            found.append(Proposed(path.name, "", "host", "", {}, "", "this file can't be read"))
    return found


def _rule_problem(proposed: Proposed, rule: Rule, group: str | None, host: str) -> str | None:
    """What the advisor's own checks would say now. The file may have been edited, or be old."""
    if rule.match.check in HAND_ONLY:
        return f"rules for {rule.match.check} are only ever written by hand"
    if rule.broad:
        return "it would hide every finding of its check, which only a person writing it can mean"
    if not isinstance(rule.expires, date):
        return "it never expires"
    today = datetime.now(UTC).date()
    if rule.expires < today:
        return "it has passed its expiry date"
    if rule.expires > today + timedelta(days=MAX_DAYS):
        return f"it expires more than {MAX_DAYS} days away"
    if proposed.layer == "group":
        if not group:
            return "it's for a group, and this server has none"
        if proposed.named != group:
            return "it's for another group"
    elif proposed.named != host:
        return "it's for another server"
    return None


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
        if not _GROUP.fullmatch(group):
            raise WhitelistError("this server's group has a name that can't be a file's")
        return directory(base) / "groups" / f"{group}.yaml"
    return directory(base) / "hosts" / f"{host}.yaml"


def _links_on_the_way(base: Path, target: Path) -> Path | None:
    """A link in whitelist/ could send a rule anywhere. The home itself is its owner's to place."""
    path = target
    while path != base and path != path.parent:
        if path.is_symlink():
            return path
        path = path.parent
    return None


class _Previewing:
    """One page's worth: settings and each server's analyses are read once, whatever the number of
    rules."""

    def __init__(self, base: Path, host: str, owner: str):
        self.base, self.host, self.owner = base, host, owner
        self.settings = _settings(base)
        self.groups = {h.name: h.group for h in self.settings.inventory.hosts}
        self.store = Store(database_file(base), read_only=True)
        self._loaded: dict[str, list] = {}

    def close(self) -> None:
        self.store.close()

    def _analyses(self, name: str) -> list:
        if name not in self._loaded:
            since = datetime.now(UTC) - LOOK_BACK
            self._loaded[name] = load_analyses(self.store, name, self.settings.identity, since)
        return self._loaded[name]

    def preview(self, proposed: Proposed) -> Proposed:
        """Fills in what the rule would do on each server it reaches, or why it can't go in."""
        if proposed.problem:
            return proposed
        host, group = self.host, self.groups.get(self.host)
        try:
            rule = Rule.model_validate({**proposed.rule, "owner": self.owner})
        except ValidationError as exc:
            words = "; ".join(str(error["msg"]) for error in exc.errors())
            proposed.problem = f"it isn't a valid rule: {words}"
            return proposed
        proposed.problem = _rule_problem(proposed, rule, group, host)
        if proposed.problem:
            return proposed
        proposed.hosts = (
            sorted(name for name, g in self.groups.items() if g == group)
            if proposed.layer == "group"
            else [host]
        )
        try:
            compared = sum(self._one_server(proposed, rule, name) for name in proposed.hosts)
        except (WhitelistError, EvidenceError) as exc:
            proposed.problem = str(exc)
            return proposed
        if not compared and not proposed.problem:
            proposed.problem = "what it would hide can't be worked out"
        if not proposed.problem and any(
            line.split(" ")[0].lower() == "critical" for line in proposed.hides
        ):
            proposed.problem = "it would hide a critical finding"
        proposed.sight = hashlib.sha256(
            json.dumps([proposed.hides, proposed.reveals, proposed.after]).encode()
        ).hexdigest()
        return proposed

    def _one_server(self, proposed: Proposed, rule: Rule, name: str) -> int:
        """How many of its analyses could be compared. Its newest check has to be one of them, and
        has to look clean."""
        rows = usable_bundles(self.store, name)
        if not rows:
            return 0
        current = self.settings.whitelist_for(name)
        changed = _set_with(self.base, name, self.groups.get(name), proposed.layer, rule)
        results = compare_loaded(self._analyses(name), current, changed)
        scored = [r for r in results if not r.get("skipped")]
        if not scored or scored[-1]["bundle"] != rows[-1]["id"]:
            proposed.problem = proposed.problem or (
                f"{name}'s latest check hasn't been worked out with these checks, so what the rule"
                " would hide isn't known: work its results out again first"
            )
        for result in scored:
            proposed.hides += [line for line in result["hidden"] if line not in proposed.hides]
            proposed.reveals += [
                line for line in result["revealed"] if line not in proposed.reveals
            ]
        if scored:
            if name == self.host:
                proposed.before, proposed.after = scored[-1]["before"], scored[-1]["after"]
            band = scored[-1]["before"][1]
            if band in TOO_WORRYING:
                proposed.problem = proposed.problem or (
                    f"{name} is assessed {band}: rules for routine activity are for a server that"
                    " looks clean"
                )
        return len(scored)


def previews(base: Path, host: str, owner: str) -> tuple[list[Proposed], int]:
    """The rules waiting, as far as a page shows them, and how many more there are."""
    found = proposals(base, host)
    working = _Previewing(base, host, owner)
    try:
        return [working.preview(one) for one in found[:MOST_RULES_SHOWN]], max(
            0, len(found) - MOST_RULES_SHOWN
        )
    finally:
        working.close()


def find(base: Path, host: str, file: str, digest: str) -> Proposed | None:
    """The very rule that was shown: the same file, place, layer and content."""
    if not digest:
        return None
    for proposed in proposals(base, host):
        if (proposed.file, proposed.digest) == (file, digest):
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


def approve(base: Path, host: str, file: str, digest: str, sight: str, who: str) -> None:
    """Puts the rule in its layer file and takes it out of the proposals. Worked out afresh here,
    and it has to be what was shown. Raises ValueError with words for the page."""
    with _writing:
        proposed = find(base, host, file, digest)
        if proposed is None:
            raise ValueError("That rule has changed or gone since this page was opened.")
        working = _Previewing(base, host, who)
        try:
            working.preview(proposed)
            group = working.groups.get(host)
        finally:
            working.close()
        if proposed.problem:
            raise ValueError(f"That rule can't go in: {proposed.problem}.")
        if proposed.sight != sight:
            raise ValueError("What this rule would hide has changed since you looked. Look again.")
        target = _layer_path(base, host, group, proposed.layer)
        if _links_on_the_way(base, target):
            raise ValueError(f"{target.name} is reached through a link: edit it by hand.")
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
        try:
            _take_out(base, host, file, digest)
        except OSError as exc:  # it did go in, which is what matters: it shows as a clash for now
            print(f"checker web: a proposal not taken out: {type(exc).__name__}", file=sys.stderr)


def refuse(base: Path, host: str, file: str, digest: str) -> None:
    with _writing:
        if find(base, host, file, digest) is None:
            raise ValueError("That rule has changed or gone since this page was opened.")
        _take_out(base, host, file, digest)


def discard(base: Path, host: str, file: str) -> None:
    """A whole file that can't be read, so none of its rules can be refused."""
    with _writing:
        path = next((p for p in _proposal_paths(base, host) if p.name == file), None)
        if path is None:
            raise ValueError("That file has gone since this page was opened.")
        path.unlink()


def _take_out(base: Path, host: str, file: str, digest: str) -> None:
    path = next((p for p in _proposal_paths(base, host) if p.name == file), None)
    if path is None:
        return
    left = [
        (layer, named, rule)
        for index, (layer, named, rule) in enumerate(_read_proposals(path))
        if _digest(layer, rule, index) != digest
    ]
    if not left:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        return
    lines = ["# Whitelist proposals from the AI advisor: advice, not rules.", "", "rules:"]
    for layer, named, rule in left:
        where = "groups" if layer == "group" else "hosts"
        lines += ["", f"  # for whitelist/{where}/{named}.yaml"]
        body = yaml.safe_dump([rule], sort_keys=False, allow_unicode=False, width=float("inf"))
        lines += ["  " + line for line in body.rstrip("\n").split("\n")]
    atomic_write(path, "\n".join(lines) + "\n")
