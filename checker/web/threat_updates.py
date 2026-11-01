"""Threat packs from a page (plan 5.13): getting them, retiring one and putting it back, and which
apply where. A person calls them threat updates. These call what the command line calls. Adding a
pack file, and trusting an organization's own signing key, stay on the command line: this server
takes plain forms only, and which keys may sign is not a decision for a form."""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

import yaml
from markupsafe import escape
from pydantic import ValidationError

from checker.evidence import EvidenceError, load_config
from checker.files import LockBusy
from checker.inventory import hosts_file, load_inventory
from checker.packs.choice import MAX_IDS, choose, normal, parse, rule_for
from checker.packs.format import PackError
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
from checker.settings import (
    GROUP_APPLY,
    ConfigChangedMeanwhile,
    HostChangedMeanwhile,
    change,
    change_host_packs,
)
from checker.web.manage import recorded

_ADDRESS = re.compile(r"https?://\S*?(?=:?(?:\s|$))", re.IGNORECASE)
_pulling = threading.Lock()  # a pull can take a while, and a second adds nothing
_WAIT_SECONDS = 5  # for the packs lock: a pull holds it for minutes, and pages mustn't queue up
_BUSY = "Threat updates are being fetched or changed. Try again in a moment."
_CANT_READ = (
    "The threat updates' files or the settings couldn't be read or written, so this stopped."
)
_PUT_BACK = "put it back on this page, if it's offered there"
# What damaged files raise on the way: the page says so in words.
_DAMAGED = (
    EvidenceError,
    OSError,
    StateError,
    TrustError,
    PackError,
    ValidationError,
    yaml.YAMLError,
    KeyError,
    AttributeError,
    TypeError,
    ValueError,
)
LONGEST_REASON = 500
SCOPE_WORDS = {"the host's": "its own", "the configuration's": "the rule for all servers"}


class UpdateProblem(Exception):
    """What went wrong, in words for the page, and what a pull had done by then."""

    def __init__(self, words: str, done: dict[str, Any] | None = None):
        super().__init__(words)
        self.done = done


def _in_words(rule: str, packs: list[Any]) -> str:
    kind, ids = parse(rule)
    if kind == "all":
        return "every update"
    if kind == "none":
        return "no updates"
    named = ", ".join(ids)
    said = f"only {named}" if kind == "only" else f"every update except {named}"
    in_force = {pack.id for pack in packs}
    missing = [pack_id for pack_id in ids if pack_id not in in_force]
    return f"{said} ({', '.join(missing)} not in use right now)" if missing else said


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
            }
        )
    state_problem = False
    try:
        last = staleness(read_state(base))
        held = held_back(base)
    except _DAMAGED:
        last, held, state_problem = None, [], True
    return {
        "packs": packs,
        "problems": problems,
        "last_pull": last,
        "held": held,
        "state_problem": state_problem,
        "retired": [(pack, version, " ".join(why.split())) for pack, version, why in retired(base)],
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


def _without_addresses(words: str) -> str:
    """A source's address can hold a secret, and the settings page doesn't show it. Any address, as
    errors can cut it short, or name where it redirected to, which can repeat the secret."""
    return _ADDRESS.sub("the source", words)


def _outcome(done) -> dict[str, Any]:
    # Already in force isn't news: it's how a pull reads when the state lost its record.
    added = [item for item in done.added if item[2] != "already in force"]
    changed = bool(added or done.withdrawn or done.key_list or done.retired_by_keys)
    notes = [
        _without_addresses(note).replace("`checker packs add` brings it back", _PUT_BACK)
        for note in done.notes
    ]
    problems = [_without_addresses(words) for words in done.problems]
    return {
        "key_list": done.key_list,
        "added": added,
        "withdrawn": done.withdrawn,
        "retired_by_keys": done.retired_by_keys,
        "notes": notes,
        "problems": problems,
        "changed": changed,
        "up_to_date": not (changed or problems or notes),
        # Our own words: what a source says about itself isn't for the permanent record.
        "summary": (
            f"{len(added)} added or updated, {len(done.withdrawn)} withdrawn,"
            f" {len(done.retired_by_keys)} retired, {len(problems)} problems"
            + (", new signing key list" if done.key_list else "")
        ),
    }


def _part_way(exc: Exception) -> dict[str, Any] | None:
    """What a pull that stopped had already done, if anything: an empty result isn't news, and
    would read as being up to date."""
    done = getattr(exc, "pulled", None)
    if done is None:
        return None
    outcome = _outcome(done)
    return None if outcome["up_to_date"] else outcome


def pull_now(base: Path) -> dict[str, Any]:
    from checker.checks import load_checks

    if not _pulling.acquire(blocking=False):
        raise UpdateProblem(_BUSY)
    try:
        with packs_lock(base, _WAIT_SECONDS):
            config = load_config(base)
            done = pull(base, config.packs.trusted_keys, load_checks(), config.packs.source)
    except LockBusy:
        raise UpdateProblem(_BUSY) from None
    except PullError as exc:
        raise UpdateProblem(_without_addresses(str(exc)), _part_way(exc)) from None
    except _DAMAGED as exc:
        raise UpdateProblem(_CANT_READ, _part_way(exc)) from None
    finally:
        _pulling.release()
    return _outcome(done)


def retire_by_hand(base: Path, pack_id: str, reason: str, who: str) -> None:
    said = " ".join(reason.split())
    if not said:
        raise UpdateProblem("Say why it's being retired, so the record explains it.")
    if len(said) > LONGEST_REASON:
        raise UpdateProblem(f"Keep the reason under {LONGEST_REASON} characters.")
    try:
        with packs_lock(base, _WAIT_SECONDS):
            config = load_config(base)
            organization = config.packs.trusted_keys
            packs, _ = in_force_read_only(base, organization)
            if pack_id not in {pack.id for pack in packs}:
                raise UpdateProblem("That threat update isn't in use any more.")
            retire(base, pack_id, f"retired by hand by {who}: {said}", True, organization)
    except LockBusy:
        raise UpdateProblem(_BUSY) from None
    except StoreError as exc:
        raise UpdateProblem(str(exc)) from None
    except _DAMAGED:
        raise UpdateProblem(_CANT_READ) from None


def put_back_by_hand(base: Path, pack_id: str) -> None:
    from checker.checks import load_checks

    try:
        with packs_lock(base, _WAIT_SECONDS):
            config = load_config(base)
            put_back(base, config.packs.trusted_keys, pack_id, load_checks())
    except LockBusy:
        raise UpdateProblem(_BUSY) from None
    except StoreError as exc:
        raise UpdateProblem(str(exc)) from None
    except _DAMAGED:
        raise UpdateProblem(_CANT_READ) from None


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
        # Escaped here, so the page's filter doesn't cut a long one and call it changed.
        "current": escape(current or ""),
        "scope_field": escape(scope),
        "choices": choices,
        "following": following,
    }


def save_rule(base: Path, scope: str, post) -> str:
    """What changed, for the record."""
    found = _scope(base, scope)
    if found is None:
        raise UpdateProblem("That server or group isn't in the list any more.")
    kind, name = found
    wanted = post.get("rule_kind", "")
    seen = post.get("current", "")  # compared under the lock each change holds as it writes
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
            old, new, _ = change(base, "packs.apply", rule, seen)
        elif kind == "group":
            old, new, _ = change(base, f"{GROUP_APPLY}{name}", rule or "default", seen)
        else:
            old, new = change_host_packs(base, name, rule, seen)
    except (ConfigChangedMeanwhile, HostChangedMeanwhile):
        raise UpdateProblem("This rule changed since this page opened. Look again.") from None
    except KeyError:
        raise UpdateProblem("That server isn't in the list any more.") from None
    except EvidenceError as exc:
        raise UpdateProblem(str(exc)) from None
    return f"{recorded('', old)} to {recorded('', new)}"
