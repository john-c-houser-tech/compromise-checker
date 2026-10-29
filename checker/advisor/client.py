"""The only code that sends anything to the AI provider (Phase 3 plan, PR
3.2). It sends what `checker.advisor.case.redact` returned, with the fixed
system prompt and one role's question, and gives back what came of it:
an answer that fits the role's schema, or why there is none. Checking the
answer against the case, restoring its placeholders and storing it are
the caller's.

Declines (decision 3): with `advisor.fallback: anthropic` a request the
model's safety checks decline is re-run, server side, on the model
Anthropic recommends for that kind of decline; the outcome names the
model that declined and the one that answered, from the response. With
`off`, a decline is recorded and nothing more happens. Only a decline
triggers a fallback, never an outage or an error.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from checker.advisor.roles import ROLES, SYSTEM_PROMPT
from checker.evidence import Advisor

MAX_TOKENS = 16_000
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AdvisorError(Exception):
    """The request couldn't be made or didn't finish; the message says why."""


@dataclass
class Outcome:
    status: str  # answered, declined, cut off
    model_asked: str
    model_answered: str | None = None
    declined_by: list[str] = field(default_factory=list)  # models that declined, in order
    refusal_category: str | None = None
    answer: Any = None  # the role's schema, before checking and restoring
    request_id: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)


def build_request(payload: dict[str, Any], role: str, advisor: Advisor) -> dict[str, Any]:
    """The request's parameters, as `--show` prints them and `send` sends
    them: the system prompt and the case first, both marked for caching,
    then the role's question."""
    _, question = ROLES[role]
    request: dict[str, Any] = {
        "model": advisor.model,
        "max_tokens": MAX_TOKENS,
        "system": [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "The case file:\n"
                        + json.dumps(payload, indent=1, ensure_ascii=False),
                        "cache_control": {"type": "ephemeral"},
                    },
                    {"type": "text", "text": question},
                ],
            }
        ],
        "output_config": {"effort": advisor.effort},
    }
    if advisor.inference_geo:
        request["inference_geo"] = advisor.inference_geo
    if advisor.fallback == "anthropic":
        request["fallbacks"] = "default"
        request["betas"] = [FALLBACK_BETA]
    return request


def make_client(api_key: str):
    try:
        import anthropic
    except ImportError as exc:
        raise AdvisorError(
            "the advisor needs the Anthropic SDK: pip install 'checker[advisor]'"
        ) from exc
    return anthropic.Anthropic(api_key=api_key)


def count_tokens(client, request: dict[str, Any], role: str) -> int:
    schema, _ = ROLES[role]
    try:
        counted = client.messages.count_tokens(
            model=request["model"],
            system=request["system"],
            messages=request["messages"],
            output_format=schema,
        )
    except Exception as exc:  # noqa: BLE001 - the SDK's error kinds, explained below
        raise AdvisorError(_explain(exc)) from None
    return counted.input_tokens


def send(client, request: dict[str, Any], role: str) -> Outcome:
    schema, _ = ROLES[role]
    try:
        response = client.beta.messages.parse(**request, output_format=schema)
    except Exception as exc:  # noqa: BLE001
        raise AdvisorError(_explain(exc)) from None
    outcome = Outcome(
        status="answered",
        model_asked=request["model"],
        model_answered=getattr(response, "model", None),
        request_id=getattr(response, "_request_id", None) or getattr(response, "id", None),
        usage=_usage(getattr(response, "usage", None)),
    )
    for block in getattr(response, "content", None) or []:
        if getattr(block, "type", None) == "fallback":
            declined = getattr(getattr(block, "from_", None), "model", None)
            if declined:
                outcome.declined_by.append(declined)
    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        outcome.status = "declined"
        outcome.refusal_category = getattr(details, "category", None)
        if outcome.model_answered and outcome.model_answered not in outcome.declined_by:
            outcome.declined_by.append(outcome.model_answered)
        outcome.model_answered = None
        return outcome
    if response.stop_reason == "max_tokens":
        outcome.status = "cut off"
        return outcome
    outcome.answer = getattr(response, "parsed_output", None)
    if outcome.answer is None:
        raise AdvisorError("the answer didn't fit the requested form")
    return outcome


def _usage(usage) -> dict[str, Any]:
    if usage is None:
        return {}
    keep = (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "inference_geo",
    )
    return {key: getattr(usage, key, None) for key in keep if getattr(usage, key, None) is not None}


def _explain(exc: Exception) -> str:
    """The SDK's errors in plain words, most specific first; never the key."""
    try:
        import anthropic
    except ImportError:
        return str(exc)
    if isinstance(exc, anthropic.AuthenticationError):
        return "the API key was refused (authentication failed)"
    if isinstance(exc, anthropic.PermissionDeniedError):
        return "the API key may not use this model or feature"
    if isinstance(exc, anthropic.NotFoundError):
        return "the model or endpoint was not found (check advisor.model)"
    if isinstance(exc, anthropic.RateLimitError):
        return "rate limited by the provider; try again later"
    if isinstance(exc, anthropic.BadRequestError):
        return f"the provider refused the request: {getattr(exc, 'message', exc)}"
    if isinstance(exc, anthropic.APIStatusError):
        return f"the provider answered with an error ({exc.status_code}); try again later"
    if isinstance(exc, anthropic.APIConnectionError):
        return "could not reach the provider (network)"
    return f"the request failed: {type(exc).__name__}"
