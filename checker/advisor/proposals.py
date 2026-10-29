"""Whitelist proposals from the AI advisor (Phase 3 plan, PR 3.3): which of
its rules are safe to offer a person, judged against the host's real
findings (its placeholders already turned back into names), and the file
they are offered in.

A proposal is offered only when, in this order:

1. it is a valid whitelist rule (checker/whitelist.py's own model) that
   narrows its check, expires within 90 days, and whose id the host's
   whitelist doesn't use already;
2. it hides every finding it names, none of them already suppressed;
3. none of those is in the critical band or part of a chain: those are
   never whitelisted by proposal, only by hand (decision 7);
4. it hides nothing else, in any stored assessment of the host, and for a
   group rule of any host in the group.

Nothing here writes a whitelist: accepted rules go to a proposal file a
person reviews, completes (the owner is left empty, so `checker whitelist
check` refuses the rule until someone vouches for it) and copies in.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from checker.files import atomic_write
from checker.whitelist import Rule, matches

MAX_DAYS = 90
OWNER_PLACEHOLDER = "proposal"  # only for validating; the file leaves it empty


@dataclass
class Judged:
    proposal: dict[str, Any]
    accepted: bool
    reason: str = ""  # why it was rejected
    rule: dict[str, Any] | None = None  # as it goes in the file
    hides: list[str] = field(default_factory=list)  # F-ids, with their summaries


def _rule(proposal: dict[str, Any], today: date) -> Rule:
    days = proposal.get("expires_in_days")
    if not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
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


def judge(
    proposals: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    events: list,
    others: list[list[dict[str, Any]]],
    group_others: list[list[dict[str, Any]]],
    rule_ids: set[str],
    today: date | None = None,
    group: str | None = None,
) -> list[Judged]:
    """`findings` are the assessment's (F-n is findings[n-1]); `others` are
    the host's other stored assessments' findings, `group_others` the other
    hosts' in its group; `rule_ids` the ids its whitelist uses."""
    today = today or datetime.now(UTC).date()
    in_chain = {i for chain in chains for i in chain.get("findings") or []}
    results, taken = [], set(rule_ids)
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
        elif proposal.get("layer") == "group" and not group:
            problem = "it is for the group, and the host is in none"
        named = []
        for fid in proposal.get("findings") or []:
            try:
                index = int(str(fid).removeprefix("F-")) - 1
            except ValueError:
                index = -1
            if not 0 <= index < len(findings):
                problem = problem or f"{fid} isn't a finding of this assessment"
                continue
            named.append(index)
        if not named:
            problem = problem or "it names no finding"
        for index in named:
            finding = findings[index]
            fid = f"F-{index + 1}"
            if problem:
                break
            if finding.get("suppressed_by"):
                problem = f"{fid} is already suppressed by {finding['suppressed_by'].get('rule')}"
            elif finding.get("band") == "critical":
                problem = f"{fid} is critical: never whitelisted by proposal, only by hand"
            elif index in in_chain:
                problem = f"{fid} is part of a chain: never whitelisted by proposal"
            elif not matches(rule.match, finding, events):
                problem = f"it doesn't hide {fid}"
        if not problem:
            extra = [
                f"F-{i + 1}"
                for i, f in enumerate(findings)
                if i not in named and matches(rule.match, f, events)
            ]
            if extra:
                problem = f"it would also hide {', '.join(extra)}, which it doesn't name"
        if not problem:
            pools = [("another of the host's assessments", others)]
            if proposal.get("layer") == "group":
                pools.append(("a finding on another host in the group", group_others))
            for where, pool in pools:
                for listed in pool:
                    hidden = [f for f in listed if matches(rule.match, f)]
                    named_checks = {(findings[i]["check"], findings[i]["summary"]) for i in named}
                    unexplained = [
                        f for f in hidden if (f["check"], f.get("summary")) not in named_checks
                    ]
                    if unexplained:
                        problem = f"it would also hide {where}: {unexplained[0]['summary'][:120]}"
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


def write_file(
    home: Path, host: str, group: str | None, judged: list[Judged], advice_at: str
) -> Path | None:
    """The proposal file, owner-only like the evidence (it names the host's
    accounts and paths); None when nothing was accepted."""
    accepted = [j for j in judged if j.accepted]
    if not accepted:
        return None
    directory = home / "whitelist" / "proposals"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"{host}-{stamp}.yaml"
    lines = [
        f"# Whitelist proposals for {host} from the AI advisor ({advice_at} UTC).",
        "# Advice, not rules: nothing here is in effect. Review each one; set its",
        "# owner (who vouches for it: `checker whitelist check` refuses an empty one);",
        "# copy it into the layer file named above it; `checker whitelist test` first.",
        "# The file is itself a valid whitelist layer once every owner is set.",
        "# Each was checked: it hides only the findings it names, none of them",
        "# critical or part of a chain, on this host's stored assessments"
        + (" and the group's hosts." if group else "."),
    ]
    lines += ["", "rules:"]
    for item in accepted:
        layer = item.proposal.get("layer", "host")
        target = (
            f"whitelist/groups/{group}.yaml"
            if layer == "group"
            else (f"whitelist/hosts/{host}.yaml")
        )
        lines += ["", f"  # for {target}"]
        for hidden in item.hides:
            lines.append(f"  # hides {hidden[:150]}")
        body = yaml.safe_dump([item.rule], sort_keys=False, allow_unicode=True)
        lines += ["  " + line for line in body.rstrip("\n").split("\n")]
    atomic_write(path, "\n".join(lines) + "\n")
    return path
