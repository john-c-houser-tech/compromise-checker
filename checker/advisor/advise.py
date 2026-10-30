"""`checker advise`: one role's request for a host's current assessment,
from the case file to the stored, restored answer (Phase 3 plan, PR 3.2).

The steps, each visible to the operator: build the case and redact it;
estimate its size here (nothing is sent to estimate it) and show the
estimated cost, asking first above the configured limit; send; check the
answer against the case; turn the placeholders back into names; store the
request and what came of it encrypted, append-only, for every request
that was sent, whatever came of it. Nothing here changes a score, a
whitelist or a setting.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from checker.advisor.case import case_for_host, redact
from checker.advisor.client import (
    MAX_TOKENS,
    AdvisorError,
    Outcome,
    build_request,
    make_client,
    send,
)
from checker.advisor.keys import KeySourceError, read_api_key
from checker.advisor.prices import cost, estimate, tokens_in
from checker.advisor.roles import CHECKS, FINDING_ID, InvalidAnswer
from checker.evidence import Config, open_text, seal_text


@dataclass
class Advice:
    status: str  # answered, declined, invalid, cut off, not sent
    outcome: Outcome | None
    answer: dict[str, Any] | None  # restored, for the operator
    note: str = ""
    judged: list | None = None  # whitelist proposals, each accepted or why not
    file: Path | None = None  # where the accepted ones were written


def _restore(value: Any, restore: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return restore(value)
    if isinstance(value, list):
        return [_restore(v, restore) for v in value]
    if isinstance(value, dict):
        return {k: _restore(v, restore) for k, v in value.items()}
    return value


def advise(
    store,
    host: str,
    identity,
    config: Config,
    inventory,
    prior,
    whitelist,
    *,
    role: str = "explain",
    bundle_id: str | None = None,
    client=None,
    confirm: Callable[[str], bool] | None = None,
    say: Callable[[str], None] = print,
    home: Path | None = None,
) -> Advice:
    """Ask the advisor about a host's current assessment. `confirm` is
    asked (with the estimate) when a run would cost more than the limit or
    its cost is unknown; without it, such a run isn't sent."""
    advisor = config.advisor
    if not advisor.enabled:
        raise AdvisorError(
            "the advisor is off: `checker config set advisor.enabled on` turns it on"
            " (`checker advise HOST --show` shows what it would send)"
        )
    built, known, which = case_for_host(
        store, host, identity, config.recipients, inventory, prior, whitelist, bundle_id
    )
    payload, pseudonyms = redact(built, advisor.redaction, known)
    request = build_request(payload, role, advisor)
    tokens = tokens_in(json.dumps(request.body, ensure_ascii=False))
    with_fallback = advisor.fallback == "anthropic"
    priced = estimate(advisor.model, tokens, MAX_TOKENS, with_fallback)
    if priced is None:
        line = f"About {tokens} input tokens to {advisor.model}; no price is known for that model."
        reason = "not sent: no price is known for the model, and it wasn't confirmed"
    else:
        rerun = ", counting a possible re-run on a fallback model" if with_fallback else ""
        line = (
            f"About {tokens} input tokens to {advisor.model} (estimated here; nothing sent"
            f" yet): at most about ${priced[0]:.2f} for the input and ${priced[1]:.2f} for"
            f" the answer{rerun}; usually much less."
        )
        reason = "not sent: the estimate is above advisor.max_cost_per_run, and it wasn't confirmed"
    say(line)
    if priced is None or sum(priced) > advisor.max_cost_per_run:
        if confirm is None or not confirm(f"{line} Send it? [y/N] "):
            return Advice("not sent", None, None, reason)
    if client is None:
        try:
            client = make_client(read_api_key(advisor.api_key_source))
        except KeySourceError as exc:
            raise AdvisorError(f"no API key: {exc}") from None

    def record(
        outcome: Outcome | None, status: str, raw, answer, note: str, request_id=None
    ) -> None:
        asked = outcome.model_asked if outcome else advisor.model
        store.record_advice(
            {
                "bundle_id": which["bundle_id"],
                "host": host,
                "assessed_at": which["assessed_at"] or "",
                "role": role,
                "at": datetime.now(UTC).isoformat(timespec="seconds"),
                "status": status,
                "redaction": advisor.redaction,
                "model_asked": asked,
                "model_answered": outcome.model_answered if outcome else None,
                "declined_by": json.dumps(outcome.declined_by)
                if outcome and outcome.declined_by
                else None,
                "refusal_category": outcome.refusal_category if outcome else None,
                "effort": advisor.effort,
                "request_id": outcome.request_id if outcome else request_id,
                "usage": json.dumps(
                    {"total": outcome.usage, "per_model": outcome.iterations} if outcome else {}
                ),
                "estimated_cost": cost(
                    outcome.model_answered or asked, outcome.usage, outcome.iterations
                )
                if outcome
                else None,
                "request": seal_text(
                    json.dumps(request.shown(), ensure_ascii=False), config.recipients
                ),
                "answer": seal_text(
                    json.dumps({"raw": raw, "restored": answer, "note": note}, ensure_ascii=False),
                    config.recipients,
                ),
            }
        )

    try:
        outcome = send(client, request, role)
    except AdvisorError as exc:
        if exc.sent:  # it may have reached the provider: recorded all the same
            record(None, "failed", None, None, str(exc), exc.request_id)
        raise
    except BaseException:  # Ctrl-C: it has left and may be billed
        record(None, "interrupted", None, None, "interrupted before the answer came")
        raise
    status, answer, note = outcome.status, None, ""
    raw = outcome.answer.model_dump() if outcome.answer is not None else None
    if outcome.status == "answered":
        ids = {f["id"] for f in payload.get("findings") or []}
        try:
            CHECKS[role](outcome.answer, ids, which["band"], _quoted(payload))
        except InvalidAnswer as exc:
            status, note = "invalid", f"the answer was set aside: it {exc}"
        else:
            answer = _restore(raw, pseudonyms.restore) if pseudonyms is not None else raw
    judged, written = None, None
    if status == "answered" and role == "whitelist":
        try:
            judged, written = _proposals(
                store, host, identity, inventory, whitelist, which, answer, home
            )
        except Exception as exc:  # the answer was paid for: kept, whatever happens next
            note = f"the proposals couldn't be judged: {type(exc).__name__}: {exc}"
            record(outcome, "invalid", raw, answer, note)
            raise AdvisorError(note) from exc
        answer = dict(
            answer,
            judged=[
                {"id": j.proposal.get("id"), "accepted": j.accepted, "reason": j.reason,
                 "hides": j.hides}
                for j in judged
            ],
            file=str(written) if written else None,
        )  # fmt: skip
    elif outcome.status == "declined":
        note = (
            "the request was declined by the model's safety checks"
            + (f" ({outcome.refusal_category})" if outcome.refusal_category else "")
            + (", and by the fallback too" if len(outcome.declined_by) > 1 else "")
        )
    elif outcome.status == "cut off":
        note = "the answer was cut off at its length limit"
    elif outcome.status == "unreadable":
        note = "the answer didn't fit the requested form"
    record(outcome, status, raw, answer, note)
    return Advice(status, outcome, answer, note, judged, written)


def _proposals(store, host, identity, inventory, whitelist, which, answer, home):
    """Role 2's rules judged against the real findings (checker.advisor.
    proposals), and the file the accepted ones go to."""
    from checker.advisor.proposals import judge, write_file
    from checker.assess import load_assessment
    from checker.baseline import usable_bundles
    from checker.inventory import home as default_home
    from checker.whitelist import WhitelistError
    from checker.whitelist import for_host as whitelist_for_host

    base = home or default_home()
    report = which["report"]
    group = which["group"]

    def assessments(name: str, skip: str | None = None) -> list[dict]:
        found = []
        for row in usable_bundles(store, name):
            if row["id"] != skip and (assessment := load_assessment(store, row["id"], identity)):
                found.append(assessment)
        return found

    others = assessments(host, skip=which["bundle_id"])
    group_others: list[dict] = []

    def ids(whitelist) -> set[str]:
        """Every id a rule could clash with when copied in: rules, windows,
        and the ones a layer disables."""
        if whitelist is None:
            return set()
        found = {placed.rule.id for placed in [*whitelist.rules, *whitelist.windows]}
        return found | {str(d.get("id")) for d in whitelist.disabled}

    rule_ids = ids(whitelist)
    if group:
        for entry in inventory.hosts:
            if entry.group == group and entry.name != host:
                group_others += assessments(entry.name)
                try:
                    theirs = whitelist_for_host(base, entry.name, inventory)
                except WhitelistError:
                    theirs = None
                rule_ids |= ids(theirs)
    judged = judge(
        answer.get("proposals") or [],
        report.assessment["findings"],
        (report.assessment.get("score") or {}).get("chains") or [],
        report.events,
        others,
        group_others,
        rule_ids,
        group=group,
        band=which["band"],
    )
    written = write_file(base, host, group, judged, datetime.now(UTC).strftime("%Y-%m-%d %H:%M"))
    return judged, written


def _quoted(payload: dict[str, Any]) -> set[str]:
    """F-n strings in the case's host text, which an answer may quote."""
    found: set[str] = set()

    def walk(value: Any, host: bool) -> None:
        if isinstance(value, str):
            if host:
                found.update(FINDING_ID.findall(value))
        elif isinstance(value, list):
            for item in value:
                walk(item, host)
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, host or key in ("from_host", "os", "kernel", "account"))

    walk(payload, False)
    return found


def latest_advice(
    store, host: str, identity, bundle_id: str, assessed_at: str | None
) -> dict[str, dict[str, Any]]:
    """For the report, per role: the latest answer about this bundle, else
    the host's latest answer about another (either marked stale when it
    read another collection or assessment than the report shows), and,
    when a later request about this bundle came to nothing, that too."""
    shown: dict[str, dict[str, Any]] = {}
    rows = store.advice_for_host(host)
    # Other bundles' rows first, this bundle's last: this bundle's win.
    rows = [r for r in rows if r["bundle_id"] != bundle_id] + [
        r for r in rows if r["bundle_id"] == bundle_id
    ]
    for row in rows:
        record = dict(row)
        record.pop("request", None)
        saved = json.loads(open_text(row["answer"], identity) or "{}")
        record["answer"] = saved.get("restored")
        record["note"] = saved.get("note") or ""
        record["declined_by"] = json.loads(row["declined_by"]) if row["declined_by"] else []
        record["stale"] = row["bundle_id"] != bundle_id or row["assessed_at"] != assessed_at
        entry = shown.setdefault(row["role"], {})
        if record["answer"] is not None:
            entry["answered"] = record
            entry.pop("later", None)
        elif row["bundle_id"] == bundle_id:
            entry["later"] = record
    return shown
