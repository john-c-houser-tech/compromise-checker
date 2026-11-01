"""Threat packs from a page (plan 5.13): getting them, retiring one and putting it back, and which
apply where. A person calls them threat updates. These call what the command line calls. Adding a
pack file, and trusting an organization's own signing key, stay on the command line: this server
takes plain forms only, and which keys may sign is not a decision for a form."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from checker.evidence import EvidenceError, load_config
from checker.inventory import hosts_file, load_inventory
from checker.packs.choice import MAX_IDS, choose, normal, parse, rule_for
from checker.packs.pull import PullError, pull, staleness
from checker.packs.state import StateError, read_state
from checker.packs.store import (
    StoreError,
    held_back,
    in_force_read_only,
    packs_lock,
    put_back,
    retire,
    retired,
)
from checker.packs.trust import TrustError
from checker.settings import GROUP_APPLY, change, change_host_packs
from checker.web.manage import recorded

_pulling = threading.Lock()  # a pull can take a while, and a second adds nothing
LONGEST_REASON = 500
SCOPE_WORDS = {"the host's": "its own", "the configuration's": "the rule for all servers"}


class UpdateProblem(Exception):
    """What went wrong, in words for the page."""


def _in_words(rule: str, packs: list[Any]) -> str:
    kind, ids = parse(rule)
    if kind == "all":
        return "every update"
    if kind == "none":
        return "no updates"
    named = ", ".join(ids)
    return f"only {named}" if kind == "only" else f"every update except {named}"


def overview(base: Path) -> dict[str, Any]:
    config = load_config(base)
    inventory = load_inventory(hosts_file(base))
    packs, problems = in_force_read_only(base, config.packs.trusted_keys)
    groups = sorted(
        {host.group for host in inventory.hosts if host.group} | set(config.packs.group_apply)
    )
    servers = []
    for host in inventory.hosts:
        rule, source = rule_for(host.name, config, inventory)
        applied, _ = choose(packs, rule, source)
        servers.append(
            {
                "name": host.name,
                "own": host.packs is not None,
                "from": SCOPE_WORDS.get(source, source),
                "applied": [pack.id for pack in applied],
                "kept_off": [pack.id for pack in packs if pack not in applied],
            }
        )
    try:
        last = staleness(read_state(base))
        held = held_back(base)
    except StateError:
        last, held = None, []
    return {
        "packs": packs,
        "problems": problems,
        "last_pull": last,
        "held": held,
        "retired": retired(base),
        "all_rule": _in_words(config.packs.apply, packs),
        "groups": [
            {
                "name": group,
                "rule": _in_words(config.packs.group_apply[group], packs)
                if group in config.packs.group_apply
                else None,
                "members": [h.name for h in inventory.hosts if h.group == group],
            }
            for group in groups
        ],
        "servers": servers,
    }


def pull_now(base: Path) -> dict[str, Any]:
    from checker.checks import load_checks

    if not _pulling.acquire(blocking=False):
        raise UpdateProblem("Updates are already being fetched. Look again in a moment.")
    try:
        with packs_lock(base):
            config = load_config(base)
            done = pull(base, config.packs.trusted_keys, load_checks(), config.packs.source)
    except (PullError, EvidenceError, OSError, StateError, TrustError) as exc:
        raise UpdateProblem(str(exc)) from None
    finally:
        _pulling.release()
    return {
        "added": done.added,
        "withdrawn": done.withdrawn,
        "retired_by_keys": done.retired_by_keys,
        "notes": done.notes,
        "problems": done.problems,
        "changed": done.changed(),
        # Our own words: what a source says about itself isn't for the permanent record.
        "summary": (
            f"{len(done.added)} added or updated, {len(done.withdrawn)} withdrawn,"
            f" {len(done.retired_by_keys)} retired, {len(done.problems)} problems"
        ),
    }


def retire_by_hand(base: Path, pack_id: str, reason: str, who: str) -> None:
    said = " ".join(reason.split())
    if not said:
        raise UpdateProblem("Say why it's being retired, so the record explains it.")
    if len(said) > LONGEST_REASON:
        raise UpdateProblem(f"Keep the reason under {LONGEST_REASON} characters.")
    try:
        with packs_lock(base):
            config = load_config(base)
            packs, _ = in_force_read_only(base, config.packs.trusted_keys)
            if pack_id not in {pack.id for pack in packs}:
                raise UpdateProblem("That threat update isn't in use any more.")
            retire(base, pack_id, f"retired by hand by {who}: {said}", by_hand=True)
    except (StoreError, StateError, EvidenceError, OSError) as exc:
        raise UpdateProblem(str(exc)) from None


def put_back_by_hand(base: Path, pack_id: str) -> None:
    from checker.checks import load_checks

    try:
        with packs_lock(base):
            config = load_config(base)
            put_back(base, config.packs.trusted_keys, pack_id, load_checks())
    except (StoreError, StateError, EvidenceError, OSError) as exc:
        raise UpdateProblem(str(exc)) from None


def _scope(base: Path, scope: str) -> tuple[str, str] | None:
    """("all", ""), ("group", name) or ("host", name), if it exists."""
    if scope == "all":
        return "all", ""
    kind, _, name = scope.partition(":")
    inventory = load_inventory(hosts_file(base))
    if kind == "host" and any(host.name == name for host in inventory.hosts):
        return "host", name
    if kind == "group":
        config = load_config(base)
        known = {h.group for h in inventory.hosts if h.group} | set(config.packs.group_apply)
        if name in known:
            return "group", name
    return None


def _current(base: Path, kind: str, name: str) -> str | None:
    config = load_config(base)
    if kind == "all":
        return config.packs.apply
    if kind == "group":
        return config.packs.group_apply.get(name)
    return load_inventory(hosts_file(base)).get(name).packs


def rule_form(base: Path, scope: str) -> dict[str, Any] | None:
    found = _scope(base, scope)
    if found is None:
        return None
    kind, name = found
    config = load_config(base)
    inventory = load_inventory(hosts_file(base))
    current = _current(base, kind, name)
    rule_kind, ids = parse(current) if current else ("default", ())
    packs, _ = in_force_read_only(base, config.packs.trusted_keys)
    in_force = {pack.id for pack in packs}
    choices = [{"id": p.id, "title": p.title, "ticked": p.id in ids} for p in packs]
    # Named by the rule but not in use now: still part of it, so still shown.
    choices += [{"id": i, "title": "", "ticked": True} for i in ids if i not in in_force]
    if kind == "all":
        following = [
            h.name
            for h in inventory.hosts
            if h.packs is None and h.group not in config.packs.group_apply
        ]
    elif kind == "group":
        following = [h.name for h in inventory.hosts if h.group == name and h.packs is None]
    else:
        following = [name]
    return {
        "scope": scope,
        "kind": kind,
        "name": name,
        "rule_kind": rule_kind,
        "current": current or "",
        "choices": choices,
        "following": following,
    }


def save_rule(base: Path, scope: str, post) -> str:
    """What changed, for the record."""
    found = _scope(base, scope)
    if found is None:
        raise UpdateProblem("That server or group isn't in the list any more.")
    kind, name = found
    current = _current(base, kind, name)
    if (current or "") != post.get("current", ""):
        raise UpdateProblem("This rule changed since this page opened. Look again.")
    wanted = post.get("rule_kind", "")
    ids = list(dict.fromkeys(post.getlist("ids")))
    if wanted == "default":
        if kind == "all":
            raise UpdateProblem("The rule for all servers has nothing to fall back on.")
        rule = None
    elif wanted in ("all", "none"):
        rule = wanted
    elif wanted in ("only", "except"):
        if not ids:
            raise UpdateProblem("Tick at least one threat update for that choice.")
        if len(ids) > MAX_IDS:
            raise UpdateProblem(f"Tick at most {MAX_IDS}.")
        rule = f"{wanted}: {', '.join(ids)}"
    else:
        raise UpdateProblem("Choose one of the options.")
    try:
        rule = None if rule is None else normal(rule)
    except ValueError:
        raise UpdateProblem("Those aren't threat updates this tool knows.") from None
    try:
        if kind == "all":
            old, new, _ = change(base, "packs.apply", rule)
        elif kind == "group":
            old, new, _ = change(base, f"{GROUP_APPLY}{name}", rule or "default")
        else:
            old, new = change_host_packs(base, name, rule)
    except KeyError:
        raise UpdateProblem("That server isn't in the list any more.") from None
    except EvidenceError as exc:
        raise UpdateProblem(str(exc)) from None
    return f"{recorded('', old)} to {recorded('', new)}"
