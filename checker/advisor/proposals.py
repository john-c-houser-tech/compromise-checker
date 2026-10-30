"""Whitelist proposals from the AI advisor (Phase 3 plan, PR 3.3): which of
its rules are safe to offer a person, judged against the host's real
findings (its placeholders already turned back into names), and the file
they are offered in.

A proposal is offered only when, in this order:

1. it is a valid whitelist rule (checker/whitelist.py's own model) that
   narrows its check, expires within 90 days, and whose id isn't in use;
2. its check is not one that can raise a critical finding (HAND_ONLY):
   a rule for such a check could hide a critical finding later;
3. it hides every finding it names, none of them already suppressed,
   critical or part of a chain (decision 7: those only by hand), all of
   one variant, which the rule names;
4. it is exact where it can be: a path or exe pattern only when several
   named findings need it, no wider than their common directory; a network
   only when several named addresses need it, no wider than /24 (/64); no
   named entity that itself holds a wildcard character;
5. it hides nothing else, now or in any stored assessment of the host, and
   for a group rule of any host in the group; and nothing it would hide
   there is critical or part of a chain.

Nothing here writes a whitelist: accepted rules go to a proposal file a
person reviews, completes (the owner is left empty, so the rule is refused
until someone vouches for it) and copies in. The file is read back before
it is kept: it must hold exactly the accepted rules, so text from a host
can't add one.
"""

from __future__ import annotations

import ipaddress
import os
import posixpath
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from checker.correlate import CHAINS
from checker.report import visible
from checker.whitelist import Rule, matches

MAX_DAYS = 90
OWNER_PLACEHOLDER = "proposal"  # only for validating; the file leaves it empty
# Checks whose rules are only ever written by hand:
# - those that can raise a critical finding (tests/test_advisor_proposals.py
#   keeps the list complete): a rule could hide one later;
# - every check a chain is made of: a suppressed finding takes no part in a
#   chain (correlate.find_chains), so a rule could stop one forming later;
# - web.exploit: what an attack was isn't one of its entities, so a rule for
#   a refused scan would hide a later answered one from the same network.
CRITICAL_CHECKS = {
    "account.uid0",
    "kernel.taint",
    "package.changed",
    "persistence.ld_preload",
    "process.hidden",
}
CHAIN_CHECKS = {check for chain in CHAINS for step in chain.steps for check, _ in step.kinds}
HAND_ONLY = CRITICAL_CHECKS | CHAIN_CHECKS | {"web.exploit"}
# Entity kinds a rule must name when its findings carry them (program is a
# process's own name, which it sets itself: it narrows nothing).
MUST_NAME = ("account", "group", "key", "module", "package", "address", "path", "exe",
             "container", "image")  # fmt: skip
# Interpreters run whatever script they are given: as an exe they narrow
# nothing by themselves.
INTERPRETERS = re.compile(
    r"(?:^|/)(?:python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node(?:js)?|java|php[0-9.]*(?:-fpm)?"
    r"|bash|dash|sh|zsh|ksh|busybox|lua[0-9.]*|deno|bun)$"
)
FINDING_ID = re.compile(r"F-([1-9][0-9]{0,5})")
WILDCARDS = re.compile(r"[*?]")
WIDEST = {4: 24, 6: 64}  # the widest network a proposal may name


@dataclass
class Judged:
    proposal: dict[str, Any]
    accepted: bool
    reason: str = ""  # why it was set aside
    rule: dict[str, Any] | None = None  # as it goes in the file
    hides: list[str] = field(default_factory=list)  # F-ids, with their summaries


class ProposalFileError(Exception):
    """The file didn't read back as exactly the accepted rules."""


def _rule(proposal: dict[str, Any], today: date) -> Rule:
    days = proposal.get("expires_in_days")
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= MAX_DAYS:
        raise ValueError(f"its expiry must be 1 to {MAX_DAYS} days away (got {days})")
    match = {k: v for k, v in (proposal.get("match") or {}).items() if v not in (None, "")}
    return Rule.model_validate(
        {
            "id": proposal.get("id"),
            "match": match,
            "reason": proposal.get("reason") or "",
            "owner": OWNER_PLACEHOLDER,
            "expires": today + timedelta(days=days),
        }
    )


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    where = ".".join(str(p) for p in error["loc"])
    return f"not a valid rule ({where}: {error['msg'].removeprefix('Value error, ')})"


def _entities(finding: dict[str, Any], kind: str) -> list[str]:
    return [
        str(e).partition(":")[2]
        for e in finding.get("entities") or []
        if str(e).startswith(kind + ":")
    ]


def _identity(finding: dict[str, Any]) -> tuple:
    """A finding the same as another, wherever it was found: its check,
    variant, title (what kind of thing it is) and entities."""
    return (
        finding.get("check"),
        finding.get("variant"),
        finding.get("title"),
        tuple(sorted(str(e) for e in finding.get("entities") or [])),
    )


def _exactness(rule: Rule, named: list[dict[str, Any]]) -> str | None:
    """Why the rule is wider than its findings need, or None."""
    for kind in MUST_NAME:
        if any(_entities(f, kind) for f in named) and getattr(rule.match, kind) is None:
            return f"it must name the findings' {kind} (they carry one)"
    for kind in ("path", "exe"):
        pattern = getattr(rule.match, kind)
        values = [v for f in named for v in _entities(f, kind)]
        if any(WILDCARDS.search(v) for v in values):
            return f"a named {kind} holds a wildcard character itself: only by hand"
        if pattern is None or not WILDCARDS.search(pattern):
            continue
        if "**" in pattern:
            return f"its {kind} pattern uses **: only by hand"
        if len(set(values)) < 2:
            return f"its {kind} is a pattern where the exact value does"
        directory, _, last = pattern.rpartition("/")
        if WILDCARDS.search(directory):
            return f"its {kind} pattern has a wildcard above its last part"
        if {posixpath.dirname(v) for v in values} != {directory}:
            return f"its {kind} pattern must stay in the findings' one directory"
        if not last.strip("*?"):
            return f"its {kind} pattern's last part is wildcards alone"
    exe = rule.match.exe
    if exe is not None and INTERPRETERS.search(exe) and rule.match.account is None:
        return "its exe is an interpreter, which runs any script: name the account too"
    if rule.match.address is not None:
        network = ipaddress.ip_network(rule.match.address)
        if network.prefixlen < WIDEST[network.version]:
            return f"its network is wider than /{WIDEST[network.version]}"
        if network.prefixlen < network.max_prefixlen:
            values = [v for f in named for v in _entities(f, "address")]
            if rule.match.address not in values and len(set(values)) < 2:
                return "its address is a network where the single address does"
    return None


def _pool_problem(rule: Rule, assessment: dict[str, Any], named_ids: set, where: str) -> str | None:
    found = assessment.get("findings") or []
    chained = {
        i
        for c in (assessment.get("score") or {}).get("chains") or []
        for i in c.get("findings") or []
    }
    for index, finding in enumerate(found):
        if not matches(rule.match, finding):
            continue
        if finding.get("band") == "critical" or index in chained:
            return f"it would hide a critical or chained finding in {where}"
        if _identity(finding) not in named_ids:
            return f"it would also hide, in {where}: {str(finding.get('summary'))[:120]}"
    return None


def judge(
    proposals: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    events: list,
    others: list[dict[str, Any]],
    group_others: list[dict[str, Any]],
    rule_ids: set[str],
    today: date | None = None,
    group: str | None = None,
    band: str | None = None,
) -> list[Judged]:
    """`findings` are the assessment's (F-n is findings[n-1]); `others` are
    the host's other stored assessments, `group_others` those of the other
    hosts in its group; `rule_ids` the ids their whitelists use."""
    today = today or datetime.now(UTC).date()
    in_chain = {i for chain in chains for i in chain.get("findings") or []}
    results, taken = [], set(rule_ids)
    if band in ("High", "Critical") or chains:
        # Tidying noise is for a host that looks clean: on one that may be
        # compromised, a rule hides most where it matters most.
        why = "the host is assessed " + (band if band in ("High", "Critical") else "with a chain")
        return [
            Judged(p, False, f"{why}: no proposals until it has been investigated")
            for p in proposals
        ]
    for proposal in proposals:
        try:
            rule = _rule(proposal, today)
        except ValidationError as exc:
            results.append(Judged(proposal, False, _first_error(exc)))
            continue
        except ValueError as exc:
            results.append(Judged(proposal, False, str(exc)))
            continue
        problem = None
        if rule.id in taken:
            problem = f"its id {rule.id!r} is already used"
        elif proposal.get("layer") not in ("host", "group"):
            problem = "its layer must be host or group"
        elif proposal.get("layer") == "group" and not group:
            problem = "it is for the group, and the host is in none"
        elif rule.match.check in HAND_ONLY:
            problem = f"{rule.match.check} can raise critical findings: its rules are only by hand"
        named: list[int] = []
        for fid in proposal.get("findings") or []:
            found = FINDING_ID.fullmatch(str(fid))
            index = int(found.group(1)) - 1 if found else -1
            if not 0 <= index < len(findings):
                problem = problem or f"{fid} isn't a finding of this assessment"
            elif index not in named:
                named.append(index)
        if not named:
            problem = problem or "it names no finding"
        for index in named:
            if problem:
                break
            finding, fid = findings[index], f"F-{index + 1}"
            if finding.get("suppressed_by"):
                problem = f"{fid} is already suppressed by {finding['suppressed_by'].get('rule')}"
            elif finding.get("band") == "critical":
                problem = f"{fid} is critical: never whitelisted by proposal, only by hand"
            elif index in in_chain:
                problem = f"{fid} is part of a chain: never whitelisted by proposal"
            elif not matches(rule.match, finding, events):
                problem = f"it doesn't hide {fid}"
        if not problem:
            variants = {findings[i].get("variant") for i in named}
            if len(variants) > 1:
                problem = "it names findings of different variants"
            elif rule.match.variant != next(iter(variants)):
                problem = f"it must name the findings' variant ({next(iter(variants))})"
        if not problem:
            problem = _exactness(rule, [findings[i] for i in named])
        if not problem:
            extra = [
                f"F-{i + 1}"
                for i, f in enumerate(findings)
                if i not in named and matches(rule.match, f, events)
            ]
            if extra:
                problem = f"it would also hide {', '.join(extra)}, which it doesn't name"
        if not problem:
            named_ids = {_identity(findings[i]) for i in named}
            pools = [("another of the host's assessments", others)]
            if proposal.get("layer") == "group":
                pools.append(("another host in the group", group_others))
            for where, pool in pools:
                for assessment in pool:
                    problem = _pool_problem(rule, assessment, named_ids, where)
                    if problem:
                        break
                if problem:
                    break
        if problem:
            results.append(Judged(proposal, False, problem))
            continue
        taken.add(rule.id)
        as_filed = rule.model_dump(mode="json", exclude_none=True, exclude={"broad"})
        as_filed["owner"] = ""
        as_filed["match"] = rule.match.model_dump(mode="json", exclude_none=True)
        results.append(
            Judged(
                proposal,
                True,
                rule=as_filed,
                hides=[f"F-{i + 1}: {findings[i].get('summary', '')}" for i in named],
            )
        )
    return results


def _comment(text: Any, limit: int = 150) -> str:
    """Text for a comment line: shown escaped (line breaks of every kind
    become visible escapes), so it can't end the comment."""
    shown = str(visible(text, limit))
    return re.sub(r"[\r\n\x0b\x0c\x85\u2028\u2029]", " ", shown)


def proposals_directory(home: Path) -> Path:
    """Beside, not inside, whitelist/: a proposal isn't a layer file."""
    return home / "proposals"


def write_file(
    home: Path, host: str, group: str | None, judged: list[Judged], advice_at: str
) -> Path | None:
    """The proposal file, owner-only like the evidence (it names the host's
    accounts and paths); None when nothing was accepted. Read back before it
    is kept: it must hold exactly the accepted rules."""
    accepted = [j for j in judged if j.accepted]
    if not accepted:
        return None
    lines = [
        f"# Whitelist proposals for {_comment(host, 80)} from the AI advisor"
        f" ({_comment(advice_at, 40)} UTC).",
        "# Advice, not rules: nothing here is in effect. Review each one; set its",
        "# owner (who vouches for it: an empty one is refused); copy it into the",
        "# layer file named above it, with `checker whitelist test` first.",
        "# Each was checked: it hides only the findings it names, none of them",
        "# critical or part of a chain, on this host's stored assessments"
        + (" and its group's." if group else "."),
        "",
        "rules:",
    ]
    for item in accepted:
        layer = item.proposal.get("layer", "host")
        target = (
            f"whitelist/groups/{_comment(group, 80)}.yaml"
            if layer == "group"
            else f"whitelist/hosts/{_comment(host, 80)}.yaml"
        )
        lines += ["", f"  # for {target}"]
        for hidden in item.hides:
            lines.append(f"  # hides {_comment(hidden)}")
        body = yaml.safe_dump([item.rule], sort_keys=False, allow_unicode=False, width=float("inf"))
        lines += ["  " + line for line in body.rstrip("\n").split("\n")]
    text = "\n".join(lines) + "\n"
    if yaml.safe_load(text) != {"rules": [item.rule for item in accepted]}:
        raise ProposalFileError("the proposal file didn't read back as the accepted rules")
    directory = proposals_directory(home)
    if directory.is_symlink():
        raise ProposalFileError(f"{directory} is a link: proposals aren't written through one")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    for attempt in range(100):
        path = directory / f"{safe_host}-{stamp}{f'-{attempt + 1}' if attempt else ''}.yaml"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
        return path
    raise ProposalFileError("no free name for the proposal file")
