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

    def record(outcome: Outcome | None, status: str, raw, answer, note: str) -> None:
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
                "request_id": outcome.request_id if outcome else None,
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
        # It may have reached the provider: recorded all the same.
        record(None, "failed", None, None, str(exc))
        raise
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
    elif outcome.status == "unreadable":
        note = "the answer didn't fit the requested form"
    record(outcome, status, raw, answer, note)
    return Advice(status, outcome, answer, note)


def latest_advice(
    store, host: str, identity, bundle_id: str, assessed_at: str | None
) -> dict[str, dict[str, Any]]:
    """For the report, per role: the latest answer for the host (marked
    stale when it read another bundle or an earlier assessment of this
    one), and, when a later request came to nothing, that too."""
    shown: dict[str, dict[str, Any]] = {}
    for row in store.advice_for_host(host):
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
        else:
            entry["later"] = record
    return shown
