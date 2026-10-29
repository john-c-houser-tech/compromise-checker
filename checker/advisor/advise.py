"""`checker advise`: one role's request for a host's current assessment,
from the case file to the stored, restored answer (Phase 3 plan, PR 3.2).

The steps, each visible to the operator: build the case and redact it;
count its tokens and show the estimated cost, asking first above the
configured limit; send; check the answer against the case; turn the
placeholders back into names; store the request and the answer encrypted,
append-only. Nothing here changes a score, a whitelist or a setting.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from checker.advisor.case import case_for_host, redact
from checker.advisor.client import (
    MAX_TOKENS,
    AdvisorError,
    Outcome,
    build_request,
    count_tokens,
    make_client,
    send,
)
from checker.advisor.keys import KeySourceError, read_api_key
from checker.advisor.prices import cost, estimate
from checker.advisor.roles import CHECKS, InvalidAnswer
from checker.evidence import Config, open_text, seal_text


@dataclass
class Advice:
    status: str  # answered, declined, invalid, cut off, not sent
    outcome: Outcome | None
    answer: dict[str, Any] | None  # restored, for the operator
    note: str = ""


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
    if client is None:
        try:
            client = make_client(read_api_key(advisor.api_key_source))
        except KeySourceError as exc:
            raise AdvisorError(f"no API key: {exc}") from None
    tokens = count_tokens(client, request, role)
    priced = estimate(advisor.model, tokens, MAX_TOKENS)
    if priced is None:
        line = f"{tokens} input tokens to {advisor.model}; no price is known for that model."
    else:
        line = (
            f"{tokens} input tokens to {advisor.model}: about ${priced[0]:.2f}, plus up to"
            f" ${priced[1]:.2f} for the answer (usually much less)."
        )
    say(line)
    if priced is None or sum(priced) > advisor.max_cost_per_run:
        if confirm is None or not confirm(f"{line} Send it? [y/N] "):
            return Advice("not sent", None, None, "not sent: above the cost limit, not confirmed")
    outcome = send(client, request, role)
    status, answer, note = outcome.status, None, ""
    raw = outcome.answer.model_dump() if outcome.answer is not None else None
    if outcome.status == "answered":
        ids = {f["id"] for f in payload.get("findings") or []}
        try:
            CHECKS[role](outcome.answer, ids, which["band"])
        except InvalidAnswer as exc:
            status, note = "invalid", f"the answer was set aside: it {exc}"
        else:
            answer = _restore(raw, pseudonyms.restore) if pseudonyms is not None else raw
    elif outcome.status == "declined":
        note = (
            "the request was declined by the model's safety checks"
            + (f" ({outcome.refusal_category})" if outcome.refusal_category else "")
            + (", and by the fallback too" if len(outcome.declined_by) > 1 else "")
        )
    elif outcome.status == "cut off":
        note = "the answer was cut off at its length limit"
    answered_by = outcome.model_answered or outcome.model_asked
    store.record_advice(
        {
            "bundle_id": which["bundle_id"],
            "host": host,
            "assessed_at": which["assessed_at"] or "",
            "role": role,
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
            "status": status,
            "redaction": advisor.redaction,
            "model_asked": outcome.model_asked,
            "model_answered": outcome.model_answered,
            "declined_by": json.dumps(outcome.declined_by) if outcome.declined_by else None,
            "refusal_category": outcome.refusal_category,
            "effort": advisor.effort,
            "request_id": outcome.request_id,
            "usage": json.dumps(outcome.usage),
            "estimated_cost": cost(answered_by, outcome.usage),
            "request": seal_text(json.dumps(request, ensure_ascii=False), config.recipients),
            "answer": seal_text(
                json.dumps({"raw": raw, "restored": answer, "note": note}, ensure_ascii=False),
                config.recipients,
            ),
        }
    )
    return Advice(status, outcome, answer, note)


def latest_advice(store, bundle_id: str, identity) -> dict[str, dict[str, Any]]:
    """The latest record per role for a bundle, decrypted, for the report."""
    latest: dict[str, dict[str, Any]] = {}
    for row in store.advice(bundle_id):
        record = dict(row)
        answer = json.loads(open_text(row["answer"], identity) or "{}")
        record.pop("request", None)
        record["answer"] = answer.get("restored")
        record["note"] = answer.get("note") or ""
        record["declined_by"] = json.loads(row["declined_by"]) if row["declined_by"] else []
        latest[row["role"]] = record
    return latest
