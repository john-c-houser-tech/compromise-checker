"""Changing settings after `checker init` (`checker config`), and what each
choice means in words, as `init` and `config show` print it.

Only the settings listed in SETTABLE can be changed here; lists and maps
(group priors, web users) are edited in `config.yaml` by hand. Every change
is validated as `init` validates it and recorded in the database's
append-only `config_changes` table. The file is written back whole, so
comments added to it by hand don't survive a change.
"""

import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from checker.advisor.keys import ENVIRONMENT_VARIABLE, KEYRING_USERNAME, key_places
from checker.advisor.prices import PRICES, server_fallback
from checker.evidence import (
    Config,
    EvidenceError,
    Store,
    config_file,
    database_file,
    is_local,
    load_config,
)
from checker.files import atomic_write, locked

EXEC_RECORDS = {
    "web": "the web server's accounts",
    "privileged": "the web server's, root, service and administrator accounts",
    "all": "every account",
}
HOME_TEXT = {
    "off": "not collected (hashes only)",
    "privileged": "collected, masked, for root, service and administrator accounts",
    "all": "collected, masked, for every account",
}
REDACTION = {
    "pseudonymize": (
        "server names, IP addresses, usernames, email addresses and SSH key fingerprints"
        " are replaced with placeholders such as USER-2-7f3a before sending, and restored"
        " here when the answer returns"
    ),
    "strict": "only the kinds of finding, counts, scores and kinds of coverage gap are sent",
    "none": "excerpts are sent as collected (after secret masking)",
}

# What a request carries, by redaction mode: what the advisor's question
# and summary say leaves the organization.
SENT = {
    "pseudonymize": (
        "findings, their scores, short masked excerpts of the evidence behind them, the"
        " related whitelist rules and coverage gaps"
    ),
    "none": (
        "findings, their scores, short masked excerpts of the evidence behind them, the"
        " related whitelist rules and coverage gaps"
    ),
    "strict": "only the kinds of finding, their counts and scores, and the kinds of coverage gap",
}
SENT_DETAIL = {
    "pseudonymize": (
        "Server names, IP addresses, usernames, email addresses and SSH key fingerprints"
        " are replaced with placeholders first."
    ),
    "none": (
        "Excerpts are sent as collected, after secret masking, with server names, IP"
        " addresses, usernames and email addresses in them."
    ),
    "strict": "No names, addresses or excerpts are sent.",
}


ANTHROPIC = "to Anthropic, with your organization's own API key"


def recipient(api: str, base_url: str | None) -> str:
    """Who receives a request, in words: Anthropic, this machine, or
    another server (and whether the way there is encrypted)."""
    if not base_url:
        return ANTHROPIC if api == "anthropic" else "to the OpenAI-compatible API"
    if is_local(base_url):
        return f"to a server on this machine (loopback), at {base_url}"
    kind = "Anthropic-compatible" if api == "anthropic" else "OpenAI-compatible"
    plain = ", not encrypted on the way (http)" if base_url.startswith("http:") else ""
    return f"to the server at {base_url} ({kind} API{plain})"


def recipients(advisor) -> str:
    """Who receives the case: the model's server, and the fallback model's
    when declined requests go to one."""
    to = recipient(advisor.api, advisor.base_url)
    if advisor.fallback == "model":
        fallback = advisor.fallback_model
        to += (
            f", and, when a request is declined, {recipient(fallback.api, fallback.base_url)}"
            f" for the fallback model, {fallback.model}"
        )
    return to


def advisor_question(redaction: str, to: str = ANTHROPIC) -> str:
    """What `init` says before asking, and `config set advisor.enabled on`
    after turning it on: what would leave, under this redaction mode, and
    to whom."""
    text = (
        "The optional AI advisor can explain findings, propose whitelist rules for you"
        " to review, suggest better coverage and advise on remediation. When you run"
        f" `checker advise`, it sends {SENT[redaction]} {to}. {SENT_DETAIL[redaction]}"
        " It never connects to your servers and never changes a score or a setting."
        " Everything else in the tool works without it (security and privacy policy §9)."
    )
    return textwrap.fill(text, 78)


def key_source_words(
    source: str, places: tuple[str, str] = (ENVIRONMENT_VARIABLE, KEYRING_USERNAME)
) -> str:
    variable, username = places
    if source == "env":
        return f"the {variable} environment variable"
    if source == "keyring":
        return f"the OS keyring (service compromise-checker, username {username})"
    if source == "none":
        return "nowhere: the server takes no key"
    return f"the output of `{source.removeprefix('command:')}`"


def describe(config: Config) -> list[str]:
    """Each choice in words: what is collected, and what may leave."""
    lines = [
        "Text of start-up files and user units in home directories: " + HOME_TEXT[config.home_text],
        "Web access logs: "
        + ("collected, masked" if config.web_access_logs else "not collected (error logs only)"),
        f"Program starts from the audit log, for: {EXEC_RECORDS[config.exec_records]}",
    ]
    advisor = config.advisor
    if not advisor.enabled:
        lines.append(
            "AI advisor: off. Nothing is sent anywhere but the SSH sessions to your servers."
        )
        return lines
    to = recipient(advisor.api, advisor.base_url)
    main_places = key_places(advisor.api, advisor.base_url)
    lines += [
        f"AI advisor: on, model {advisor.model}"
        + (f", effort {advisor.effort}" if advisor.api == "anthropic" else "")
        + (
            ", no API key (the server takes none)."
            if advisor.api_key_source == "none"
            else f", API key from {key_source_words(advisor.api_key_source, main_places)}."
        ),
        f"  Sent only when you run `checker advise`: {SENT[advisor.redaction]},"
        + (" to Anthropic with your own account." if to == ANTHROPIC else f" {to}."),
        f"  Redaction: {advisor.redaction}: {REDACTION[advisor.redaction]}.",
        *(
            [
                f"  Explaining quiet hosts (Low, no chain, nothing medium or worse) in"
                f" `checker advise --all`: the triage model, {advisor.triage_model}"
                + _triage_doubt(advisor)
                + (
                    "; it has no server-side fallback, so its declines aren't re-run"
                    if advisor.fallback == "anthropic" and not server_fallback(advisor.triage_model)
                    else ""
                )
                + "."
            ]
            if advisor.triage_model
            else []
        ),
        "  `checker config check-key` checks the key can be read, without sending anything.",
        f"  Asks before a run whose likely cost is above ${advisor.max_cost_per_run:.2f}"
        " (the most it can cost is shown too), or whose cost isn't known.",
        "  If the model's safety checks decline a request: " + _on_decline(advisor),
    ]
    if advisor.inference_geo:
        elsewhere = advisor.base_url or (
            advisor.fallback == "model"
            and (advisor.fallback_model.api != "anthropic" or advisor.fallback_model.base_url)
        )
        lines.append(
            f"  Inference geography: {advisor.inference_geo}"
            + (
                " (Anthropic's own API keeps to it; other servers aren't asked to)."
                if elsewhere
                else "."
            )
        )
    return lines


def _triage_doubt(advisor) -> str:
    """A triage model that may not be served where it would be sent."""
    model = advisor.triage_model or ""
    if advisor.api == "openai" and model.startswith("claude-"):
        return f" (a Claude name, sent to {advisor.base_url}: check that server has it)"
    if advisor.api == "anthropic" and not advisor.base_url and model not in PRICES:
        return " (no price is known for it: runs will ask, and Anthropic may not know it)"
    return ""


def _on_decline(advisor) -> str:
    if advisor.fallback == "anthropic" and not server_fallback(advisor.model):
        return f"nothing more is sent: {advisor.model} has no server-side fallback."
    if advisor.fallback == "anthropic":
        return (
            "it is re-run on the model Anthropic recommends for that kind of decline"
            " (same provider and account), and the report names both."
        )
    if advisor.fallback == "model":
        fallback = advisor.fallback_model
        places = key_places(fallback.api, fallback.base_url, fallback=True)
        return (
            f"the same request, with the same redaction, is re-run on {fallback.model},"
            f" sent {recipient(fallback.api, fallback.base_url)}, with its key from"
            f" {key_source_words(fallback.api_key_source, places)}; the report names both."
        )
    return "nothing more is sent; the report says it was declined."


# --- Changing a setting ----------------------------------------------------------


def _bool(text: str) -> bool:
    words = {"on": True, "yes": True, "true": True, "off": False, "no": False, "false": False}
    if text.lower() not in words:
        raise ValueError("must be on or off")
    return words[text.lower()]


def _optional(text: str) -> str | None:
    return None if text.lower() in ("", "none") else text


@dataclass(frozen=True)
class Setting:
    path: tuple[str, ...]
    parse: Any  # text -> value; the model validates the value
    help: str


SETTABLE: dict[str, Setting] = {
    ".".join(s.path): s
    for s in (
        Setting(("home_text",), str, "off, privileged or all"),
        Setting(("web_access_logs",), _bool, "on or off"),
        Setting(("exec_records",), str, "web, privileged or all"),
        Setting(("retention_days",), int, "days evidence is kept (default 90)"),
        Setting(("prior",), float, "prior probability of compromise (default 0.02)"),
        Setting(("advisor", "enabled"), _bool, "on or off"),
        Setting(("advisor", "model"), str, "the model's name (default claude-opus-5-5)"),
        Setting(
            ("advisor", "triage_model"),
            _optional,
            "for quiet hosts in `advise --all`, e.g. claude-haiku-5-5; none: the model",
        ),
        Setting(("advisor", "effort"), str, "low, medium, high, xhigh or max"),
        Setting(("advisor", "redaction"), str, "pseudonymize, strict or none"),
        Setting(("advisor", "api_key_source"), str, "env, keyring, none or command:<command>"),
        Setting(("advisor", "inference_geo"), _optional, "e.g. us, or none"),
        Setting(
            ("advisor", "max_cost_per_run"),
            float,
            "US dollars, checked against the likely cost (default 1.00)",
        ),
        Setting(("advisor", "api"), str, "anthropic (default) or openai (OpenAI-compatible)"),
        Setting(("advisor", "base_url"), _optional, "the server's address, or none: Anthropic's"),
        Setting(("advisor", "fallback"), str, "on a decline: anthropic (default), model or off"),
        Setting(("advisor", "fallback_model", "model"), _optional, "the fallback model's name"),
        Setting(("advisor", "fallback_model", "api"), str, "anthropic or openai"),
        Setting(("advisor", "fallback_model", "base_url"), _optional, "its server, or none"),
        Setting(
            ("advisor", "fallback_model", "api_key_source"),
            str,
            "env, keyring, none or command:<command>",
        ),
    )
}


def _get(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    for name in path:
        data = data[name]
    return data


def value_of(config: Config, key: str) -> Any:
    return _get(config.model_dump(), SETTABLE[key].path)


def message(exc: ValidationError, key: str) -> str:
    error = exc.errors()[0]
    return f"{key}: {error['msg'].removeprefix('Value error, ')}"


def change(home: Path, key: str, text: str) -> tuple[Any, Any, Config]:
    """Set `key` to the value `text` names: validated against the whole
    configuration, recorded, then written. Returns (old, new, config); a
    value equal to the current one changes and records nothing."""
    setting = SETTABLE.get(key)
    if setting is None:
        raise EvidenceError(f"no setting {key!r}; settable: {', '.join(SETTABLE)}")
    try:
        value = setting.parse(text)
    except ValueError as exc:
        raise EvidenceError(f"{key}: {exc}") from None
    path = config_file(home)
    with locked(path):
        current = load_config(home)
        data = current.model_dump()
        old = _get(data, setting.path)
        parent = _get(data, setting.path[:-1])
        parent[setting.path[-1]] = value
        try:
            config = Config.model_validate(data)
        except ValidationError as exc:
            raise EvidenceError(message(exc, key)) from None
        new = _get(config.model_dump(), setting.path)
        if new == old:
            return old, new, current
        before = path.read_text(encoding="utf-8")
        store = Store(database_file(home))
        try:
            store.record_config_change(
                key,
                old,
                new,
                lambda: atomic_write(path, yaml.safe_dump(config.model_dump(), sort_keys=False)),
                lambda: atomic_write(path, before),
            )
        finally:
            store.close()
    return old, new, config
