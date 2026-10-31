"""Which threat packs in force apply to a host (plan 4.6, John 2026-10-30:
an organization may keep a pack off some hosts). A rule is one of

    all                every pack in force (the default)
    none               no pack
    only: a, b         only these packs (by id)
    except: a, b       every pack in force but these

set for a host in the inventory (`packs:`), for a group in the
configuration (`packs.group_apply`), or for every host there
(`packs.apply`); the host's wins, then its group's, as with the prior. A
pack named that isn't in force is allowed: it can be listed before it
arrives. A pack held back is said in the analysis, as a coverage gap."""

from __future__ import annotations

import re
from typing import Any

_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
MAX_IDS = 50


def parse(text: str) -> tuple[str, tuple[str, ...]]:
    """A rule as (kind, pack ids); ValueError says what is wrong with it."""
    words = " ".join(str(text).split())
    if words in ("all", "none"):
        return words, ()
    kind, colon, rest = words.partition(":")
    kind = kind.strip()
    if not colon or kind not in ("only", "except"):
        raise ValueError(f"not a pack rule: {text!r}; all, none, only: <ids> or except: <ids>")
    ids = tuple(i.strip() for i in rest.split(",") if i.strip())
    if not ids:
        raise ValueError(f"{kind}: names no pack")
    if len(ids) > MAX_IDS:
        raise ValueError(f"{kind}: at most {MAX_IDS} packs")
    for pack_id in ids:
        if not _ID.fullmatch(pack_id):
            raise ValueError(f"not a pack id: {pack_id!r}")
    return kind, ids


def normal(text: str) -> str:
    """A rule written the one way it is kept (`only: a, b`)."""
    kind, ids = parse(text)
    return kind if not ids else f"{kind}: {', '.join(dict.fromkeys(ids))}"


def rule_for(host: str, config: Any, inventory: Any) -> tuple[str, str]:
    """The rule for a host and where it comes from: the host's own, its
    group's, or the configuration's."""
    entry = next((h for h in inventory.hosts if h.name == host), None)
    if entry is not None and entry.packs is not None:
        return entry.packs, "the host's"
    groups = config.packs.group_apply
    if entry is not None and entry.group in groups:
        return groups[entry.group], f"group {entry.group}'s"
    return config.packs.apply, "the configuration's"


def choose(packs: list[Any], rule: str, source: str) -> tuple[list[Any], list[str]]:
    """The packs a rule applies, and a line for each it holds back."""
    kind, ids = parse(rule)
    if kind == "all":
        return list(packs), []
    named = set(ids)
    keep = {"none": lambda p: False, "only": lambda p: p.id in named}.get(
        kind, lambda p: p.id not in named
    )
    applied = [p for p in packs if keep(p)]
    held = [
        f"{p.id} version {p.version}: held back by {source} setting (packs: {normal(rule)})"
        for p in packs
        if not keep(p)
    ]
    return applied, held


def for_host(
    host: str, config: Any, inventory: Any, found: tuple[list[Any], list[str]]
) -> tuple[list[Any], list[str]]:
    """The packs a host's analysis applies, from those in force and why
    any can't be used (checker.packs.store.in_force), and every reason one
    in force or kept isn't applied to it."""
    packs, problems = found
    applied, held = choose(packs, *rule_for(host, config, inventory))
    return applied, [*problems, *held]
