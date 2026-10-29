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

from checker.evidence import (
    Config,
    EvidenceError,
    Store,
    config_file,
    database_file,
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
        "server names, IP addresses, usernames and email addresses are replaced with"
        " placeholders such as HOST-3 or USER-2 before sending, and restored here when"
        " the answer returns"
    ),
    "strict": "only the kinds of finding, counts and scores are sent",
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
    "strict": "only the kinds of finding, their counts and scores, and coverage gaps",
}
SENT_DETAIL = {
    "pseudonymize": (
        "Server names, IP addresses, usernames and email addresses are replaced with"
        " placeholders first."
    ),
    "none": (
        "Excerpts are sent as collected, after secret masking, with server names, IP"
        " addresses, usernames and email addresses in them."
    ),
    "strict": "No names, addresses or excerpts are sent.",
}


def advisor_question(redaction: str) -> str:
    """What `init` says before asking, and `config set advisor.enabled on`
    after turning it on: what would leave, under this redaction mode."""
    text = (
        "The optional AI advisor can explain findings, propose whitelist rules for you"
        " to review, suggest better coverage and advise on remediation. When you run"
        f" `checker advise`, it sends {SENT[redaction]} to Anthropic, with your"
        f" organization's own API key. {SENT_DETAIL[redaction]} It never connects to a"
        " server and never changes a score or a setting. Everything else in the tool"
        " works without it (security and privacy policy §9)."
    )
    return textwrap.fill(text, 78)


def key_source_words(source: str) -> str:
    if source == "env":
        return "the ANTHROPIC_API_KEY environment variable"
    if source == "keyring":
        return "the OS keyring (service compromise-checker, username advisor-api-key)"
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
    lines += [
        f"AI advisor: on, model {advisor.model}, effort {advisor.effort}, API key from"
        f" {key_source_words(advisor.api_key_source)}.",
        f"  Sent only when you run `checker advise`: {SENT[advisor.redaction]}, to"
        " Anthropic with your own account.",
        f"  Redaction: {advisor.redaction}: {REDACTION[advisor.redaction]}.",
        "  `checker config check-key` checks the key can be read, without sending anything.",
        f"  Asks before a run estimated above ${advisor.max_cost_per_run:.2f}.",
    ]
    if advisor.inference_geo:
        lines.append(f"  Inference geography: {advisor.inference_geo}.")
    return lines


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
        Setting(("advisor", "effort"), str, "low, medium, high, xhigh or max"),
        Setting(("advisor", "redaction"), str, "pseudonymize, strict or none"),
        Setting(("advisor", "api_key_source"), str, "env, keyring or command:<command>"),
        Setting(("advisor", "inference_geo"), _optional, "e.g. us, or none"),
        Setting(("advisor", "max_cost_per_run"), float, "US dollars (default 1.00)"),
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
