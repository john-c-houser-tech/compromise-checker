"""The only code that sends anything to the AI provider (Phase 3 plan, PR
3.2). It sends what `checker.advisor.case.redact` returned, with the fixed
system prompt and one role's question, and gives back what came of it:
an answer that fits the role's schema, or why there is none. Checking the
answer against the case, restoring its placeholders and storing it are
the caller's.

The response is read in this order, because a decline, a fallback or a
cut-off answer can each come with partial text: first whether it was
declined (`stop_reason: refusal`), then the fallback blocks and the usage
per model, then whether it was cut off, and only then the answer, which
is the last text after the last fallback block.

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

from pydantic import ValidationError

from checker.advisor.roles import ROLES, SYSTEM_PROMPT
from checker.advisor.roles import question as role_question
from checker.evidence import Advisor

MAX_TOKENS = 16_000
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AdvisorError(Exception):
    """The request couldn't be made or didn't finish; the message says why.
    `sent` says whether it may have reached the provider (False: it
    certainly didn't), and `request_id` is the provider's, when it gave one."""

    def __init__(self, message: str, sent: bool = False, request_id: str | None = None):
        super().__init__(message)
        self.sent = sent
        self.request_id = request_id


@dataclass
class Outcome:
    status: str  # answered, declined, cut off, unreadable
    model_asked: str
    model_answered: str | None = None
    declined_by: list[str] = field(default_factory=list)  # models that declined, in order
    refusal_category: str | None = None
    answer: Any = None  # the role's schema, before checking and restoring
    request_id: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    # Usage per model that ran (the asked model, then any fallback), for cost.
    iterations: list[dict[str, Any]] = field(default_factory=list)


def output_format(role: str) -> dict[str, Any]:
    """The role's schema as the API takes it (the SDK's own conversion, as
    `messages.parse` makes it)."""
    from anthropic.lib._parse._transform import to_json_output_format

    schema, _ = ROLES[role]
    return dict(to_json_output_format(schema))


@dataclass
class Request:
    body: dict[str, Any]
    betas: list[str]

    def shown(self) -> dict[str, Any]:
        """As `--show` prints it: the beta header and the body, exactly."""
        return {"anthropic-beta": self.betas, "body": self.body}


def build_request(payload: dict[str, Any], role: str, advisor: Advisor) -> Request:
    """The request, as `--show` prints it and `send` sends it: the system
    prompt and the case first, both marked for caching, then the role's
    question; the answer's schema in output_config."""
    question = role_question(role)
    body: dict[str, Any] = {
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
        "output_config": {"effort": advisor.effort, "format": output_format(role)},
    }
    if advisor.inference_geo:
        body["inference_geo"] = advisor.inference_geo
    betas = []
    if advisor.fallback == "anthropic":
        body["fallbacks"] = "default"
        betas.append(FALLBACK_BETA)
    return Request(body, betas)


def make_client(api_key: str):
    try:
        import anthropic
    except ImportError as exc:
        raise AdvisorError(
            "the advisor needs the Anthropic SDK: pip install 'checker[advisor]'"
        ) from exc
    # No automatic retries: a request that timed out may still be answered
    # and billed, and a retry would bill it again past the confirmed
    # estimate. A rate-limited run is simply run again.
    return anthropic.Anthropic(api_key=api_key, max_retries=0)


def _model(part) -> str | None:
    return getattr(part, "model", None) if part is not None else None


def send(client, request: Request, role: str) -> Outcome:
    schema, _ = ROLES[role]
    try:
        kwargs = dict(request.body)
        if request.betas:
            kwargs["betas"] = request.betas
        response = client.beta.messages.create(**kwargs)
    except Exception as exc:  # noqa: BLE001 - the SDK's error kinds, explained below
        raise AdvisorError(
            _explain(exc), _may_have_left(exc), getattr(exc, "request_id", None)
        ) from None
    outcome = Outcome(
        status="answered",
        model_asked=request.body["model"],
        model_answered=getattr(response, "model", None),
        request_id=getattr(response, "_request_id", None) or getattr(response, "id", None),
        usage=_usage(getattr(response, "usage", None)),
        iterations=_iterations(getattr(response, "usage", None)),
    )
    content = list(getattr(response, "content", None) or [])
    last_fallback = -1
    for index, block in enumerate(content):
        if getattr(block, "type", None) == "fallback":
            last_fallback = index
            declined = _model(getattr(block, "from_", None))
            if declined and declined not in outcome.declined_by:
                outcome.declined_by.append(declined)
    # Each model that ran, in order: the one asked, then each fallback's
    # target. A hop the usage reports without a model is that one.
    chain = [outcome.model_asked] + [
        _model(getattr(content[i], "to", None)) for i in range(len(content))
        if getattr(content[i], "type", None) == "fallback"
    ]  # fmt: skip
    for index, hop in enumerate(outcome.iterations):
        if not hop.get("model") and index < len(chain):
            hop["model"] = chain[index]
    # A fallback-served turn may carry no fallback block: the usage per
    # model says so too.
    for hop in outcome.iterations[:-1]:
        if hop.get("model") and hop["model"] not in outcome.declined_by:
            outcome.declined_by.append(hop["model"])
    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        outcome.status = "declined"
        outcome.refusal_category = getattr(details, "category", None)
        last = [outcome.model_answered, chain[-1] if len(chain) > 1 else None]
        if outcome.iterations:
            last.append(outcome.iterations[-1].get("model"))
        for model in last:
            if model and model not in outcome.declined_by:
                outcome.declined_by.append(model)
        outcome.model_answered = None
        return outcome
    if response.stop_reason in ("max_tokens", "model_context_window_exceeded"):
        outcome.status = "cut off"
        return outcome
    texts = [
        block.text
        for block in content[last_fallback + 1 :]
        if getattr(block, "type", None) == "text" and getattr(block, "text", "")
    ]
    if not texts:
        outcome.status = "unreadable"
        return outcome
    try:
        outcome.answer = schema.model_validate_json(texts[-1])
    except ValidationError:
        outcome.status = "unreadable"
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


def _iterations(usage) -> list[dict[str, Any]]:
    """Usage per model that ran (`message`, `fallback_message` entries)."""
    hops = []
    for item in getattr(usage, "iterations", None) or []:
        if getattr(item, "type", None) not in ("message", "fallback_message"):
            continue
        hop = {"model": getattr(item, "model", None), "type": item.type}
        for key in (
            "input_tokens",
            "output_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
        ):
            hop[key] = getattr(item, key, None) or 0
        hops.append(hop)
    return hops


def _may_have_left(exc: Exception) -> bool:
    """Whether a failed request may have reached the provider: an error it
    answered, or a lost connection or timeout (it may be running there);
    not one the SDK raised before sending."""
    try:
        import anthropic
    except ImportError:
        return False
    return isinstance(exc, anthropic.APIError)


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
    return f"the request couldn't be made ({type(exc).__name__}: {str(exc)[:200]})"
