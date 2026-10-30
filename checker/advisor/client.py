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
triggers a fallback, never an outage or an error. With `model`, the
caller re-runs the request on `advisor.fallback_model` (`fallback_request`).

The OpenAI-compatible API (PR 3.7) is for local servers (Ollama, llama.cpp,
vLLM) and other vendors: the same system prompt, case and question, with
the answer's schema as `response_format`, which those servers enforce
(Ollama's Anthropic-style endpoint ignores it, checked 2026-10-29). Ollama
also cuts a request longer than the model's context without saying so,
keeping the end: the answer would then read only part of the case. So the
tokens the server says it read are compared with the request's length,
and a request read only in part is reported as cut off, not answered.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from checker.advisor.prices import server_fallback, tokens_in
from checker.advisor.roles import ROLES, SYSTEM_PROMPT
from checker.advisor.roles import question as role_question
from checker.evidence import Advisor, FallbackModel, is_local

MAX_TOKENS = 16_000
ANTHROPIC_API = "https://api.anthropic.com"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# A local model on a laptop's processor reads a large case in minutes and
# writes its answer more slowly still.
OPENAI_TIMEOUT = 3600
# The request's length estimated here errs high (two characters a token);
# real cases run about 2.4 to 2.8, and English prose about 4. A server that
# says it read fewer than this share of the estimate cut the request short
# (Ollama keeps about half its context when it cuts).
READ_AT_LEAST = 0.45


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
    note: str = ""  # why it was cut off, when the reason is more than its length
    endpoint: str | None = None  # the server that answered; None: Anthropic's own


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
    api: str = "anthropic"
    base_url: str | None = None  # None: Anthropic's own

    def shown(self) -> dict[str, Any]:
        """As `--show` prints it: where it goes (unless Anthropic's own),
        the beta header and the body, exactly."""
        if self.api == "openai":
            return {"endpoint": f"{self.base_url}/chat/completions", "body": self.body}
        shown: dict[str, Any] = {"anthropic-beta": self.betas, "body": self.body}
        if self.base_url:
            shown = {"endpoint": f"{self.base_url}/v1/messages", **shown}
        return shown


def build_request(payload: dict[str, Any], role: str, advisor: Advisor) -> Request:
    """The request, as `--show` prints it and `send` sends it: the system
    prompt and the case first, both marked for caching, then the role's
    question; the answer's schema in output_config."""
    if advisor.api == "openai":
        return _openai_request(payload, role, advisor.model, advisor.base_url)
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
    if advisor.fallback == "anthropic" and server_fallback(advisor.model):
        body["fallbacks"] = "default"
        betas.append(FALLBACK_BETA)
    return Request(body, betas, base_url=advisor.base_url)


def fallback_request(payload: dict[str, Any], role: str, advisor: Advisor) -> Request:
    """The same case and question for `advisor.fallback_model` (decision 3:
    the same redaction and placeholders), in its own API's form."""
    fallback: FallbackModel = advisor.fallback_model
    if fallback.api == "openai":
        return _openai_request(payload, role, fallback.model, fallback.base_url)
    # Anthropic's own API keeps the organization's inference geography;
    # another server can't honour it.
    settings = advisor.model_copy(
        update={"api": "anthropic", "model": fallback.model, "base_url": fallback.base_url,
                "fallback": "off",
                "inference_geo": None if fallback.base_url else advisor.inference_geo}
    )  # fmt: skip
    return build_request(payload, role, settings)


def _openai_request(payload: dict[str, Any], role: str, model, base_url) -> Request:
    """The OpenAI-compatible form: the same system prompt, case and
    question, the schema as response_format. No effort, caching or
    fallback: those are Anthropic's."""
    schema = output_format(role)["schema"]
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "The case file:\n"
                + json.dumps(payload, indent=1, ensure_ascii=False)
                + "\n\n"
                + role_question(role),
            },
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": role, "strict": True, "schema": schema},
        },
    }
    return Request(body, [], api="openai", base_url=base_url)


def make_client(api_key: str | None, api: str = "anthropic", base_url: str | None = None):
    try:
        import anthropic
    except ImportError as exc:
        raise AdvisorError(
            "the advisor needs the Anthropic SDK: pip install 'checker[advisor]'"
        ) from exc
    import httpx2  # the SDK's own HTTP client

    # A server on this machine is reached directly, never through a proxy
    # from the environment (which would carry the case off the machine): an
    # explicit transport, since the SDK's client mounts the environment's
    # proxies whatever trust_env says. Redirects are never followed (they
    # would resend the case elsewhere).
    direct: dict[str, Any] = {"follow_redirects": False}
    if is_local(base_url):
        direct |= {"trust_env": False, "transport": httpx2.HTTPTransport()}
    if api == "openai":
        headers = {"authorization": f"Bearer {api_key}"} if api_key else {}
        return httpx2.Client(
            base_url=base_url,
            headers=headers,
            timeout=httpx2.Timeout(OPENAI_TIMEOUT, connect=10),
            **direct,
        )
    if base_url and os.environ.get("ANTHROPIC_CUSTOM_HEADERS") is not None:
        # The SDK adds that variable's headers to every request, and they
        # may hold a key meant for Anthropic or a gateway.
        raise AdvisorError(
            f"ANTHROPIC_CUSTOM_HEADERS is set: its headers would go to {base_url} too;"
            " unset it to use that server"
        )
    # No automatic retries: a request that timed out may still be answered
    # and billed, and a retry would bill it again past the confirmed
    # estimate. A rate-limited run is simply run again. The key and the
    # address are always given, so the SDK never takes either from the
    # environment (ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, profiles,
    # ANTHROPIC_BASE_URL): an empty key for a server that takes none. No
    # tracing: spans could carry the case.
    return anthropic.Anthropic(
        api_key=api_key or "",
        base_url=base_url or ANTHROPIC_API,
        max_retries=0,
        open_telemetry=False,
        http_client=anthropic.DefaultHttpxClient(**direct),
    )


def _model(part) -> str | None:
    return getattr(part, "model", None) if part is not None else None


def send(client, request: Request, role: str) -> Outcome:
    if request.api == "openai":
        return _send_openai(client, request, role)
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
        endpoint=request.base_url,
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


def _send_openai(client, request: Request, role: str) -> Outcome:
    """An OpenAI-compatible server's answer, read in the same order:
    declined, then cut off (by length, or by the server reading only part
    of the request), then the answer."""
    import httpx2

    schema, _ = ROLES[role]
    where = request.base_url
    try:
        response = client.post("/chat/completions", json=request.body)
    except httpx2.ConnectError:
        raise AdvisorError(f"could not reach {where} (is the server running?)") from None
    except httpx2.TimeoutException:
        raise AdvisorError(f"{where} didn't answer within {OPENAI_TIMEOUT} s", sent=True) from None
    except Exception as exc:  # noqa: BLE001 - any other failure may have been after sending
        raise AdvisorError(
            f"the request to {where} failed ({type(exc).__name__})", sent=True
        ) from None
    request_id = response.headers.get("x-request-id")
    if response.status_code != 200:
        raise AdvisorError(_explain_status(response, where), True, request_id)
    try:
        data = response.json()
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = data.get("usage") or {}
        if not all(isinstance(part, dict) for part in (choice, message, usage)):
            raise TypeError
    except (ValueError, AttributeError, TypeError, IndexError, KeyError, RecursionError):
        raise AdvisorError(
            f"{where} answered with something that isn't a chat answer", True, request_id
        ) from None
    model = data.get("model") or request.body["model"]
    outcome = Outcome(
        status="answered",
        model_asked=request.body["model"],
        model_answered=model if isinstance(model, str) else request.body["model"],
        request_id=request_id or (data.get("id") if isinstance(data.get("id"), str) else None),
        usage={
            mine: usage[theirs]
            for mine, theirs in (
                ("input_tokens", "prompt_tokens"),
                ("output_tokens", "completion_tokens"),
            )
            if isinstance(usage.get(theirs), int)
        },  # fmt: skip
        endpoint=where,
    )
    if message.get("refusal") or choice.get("finish_reason") == "content_filter":
        outcome.status = "declined"
        outcome.refusal_category = "content_filter" if not message.get("refusal") else None
        outcome.declined_by = [outcome.model_answered]
        outcome.model_answered = None
        return outcome
    # The messages' text only: the schema and JSON's own quoting aren't
    # counted as prompt by the server.
    expected = tokens_in("".join(m["content"] for m in request.body["messages"]))
    read = outcome.usage.get("input_tokens")
    if read is not None and read < expected * READ_AT_LEAST:
        outcome.status = "cut off"
        outcome.note = (
            f"the server read only {read} tokens of a request of about {expected}: the"
            " model's context is too small for this case, and the server cut it short"
            " (with Ollama, give the model a larger num_ctx)"
        )
        return outcome
    if choice.get("finish_reason") == "length":
        outcome.status = "cut off"
        return outcome
    text = message.get("content")
    if not isinstance(text, str) or not text.strip():
        outcome.status = "unreadable"
        return outcome
    try:
        outcome.answer = schema.model_validate_json(text)
    except ValidationError:
        outcome.status = "unreadable"
    return outcome


def _explain_status(response, where: str) -> str:
    code = response.status_code
    if 300 <= code < 400:
        return f"{where} redirected the request ({code}), which isn't followed: check base_url"
    if code == 401:
        return f"{where} refused the API key (authentication failed)"
    if code == 403:
        return f"{where} doesn't allow this key to use this model"
    if code == 404:
        return f"{where} doesn't know the model, or the address is wrong (check model and base_url)"
    if code == 429:
        return f"rate limited by {where}; try again later"
    if 400 <= code < 500:
        try:
            error = response.json().get("error")
            said = error.get("message") if isinstance(error, dict) else error
        except (ValueError, AttributeError, RecursionError):
            said = None
        said = _printable(said) if said else ""
        return f"{where} refused the request ({code})" + (f": {said}" if said else "")
    return f"{where} answered with an error ({code}); try again later"


def _printable(text) -> str:
    """A server's own words, shown on a terminal: printable ASCII only."""
    return "".join(c if " " <= c <= "~" else "?" for c in str(text)[:300])


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
        return f"the provider refused the request: {_printable(getattr(exc, 'message', exc))}"
    if isinstance(exc, anthropic.APIStatusError) and 300 <= exc.status_code < 400:
        return (
            f"the provider redirected the request ({exc.status_code}), which isn't followed:"
            " check base_url"
        )
    if isinstance(exc, anthropic.APIStatusError):
        return f"the provider answered with an error ({exc.status_code}); try again later"
    if isinstance(exc, anthropic.APIConnectionError):
        return "could not reach the provider (network)"
    return f"the request couldn't be made ({type(exc).__name__}: {_printable(exc)})"
