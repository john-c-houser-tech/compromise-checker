"""Settings from a page (plan 5.13). Only those listed here: a setting that runs a command, or that
sends data or keys to another address, stays on the command line, since from a form it would let
anyone with an account run programs on this machine or collect the API key. Those show here as
read-only, without their values where a value could hold a secret."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from markupsafe import escape

from checker.evidence import MODEL_NAME, EvidenceError, is_local, load_config
from checker.settings import (
    ANTHROPIC,
    EXEC_RECORDS,
    HOME_TEXT,
    ConfigChangedMeanwhile,
    advisor_question,
    change_many,
    config_version,
    value_of,
)
from checker.web.manage import FormProblem, _shown, recorded

_MODEL = re.compile(MODEL_NAME)
_GEOGRAPHY = re.compile(r"[a-z]{2,16}")
_NUMBER = re.compile(r"[0-9]+(\.[0-9]+)?")
_LONGEST_WHOLE = 7  # the digits a number of days could need


class ChangedMeanwhile(FormProblem):
    """Someone changed the settings since the form was opened."""


@dataclass(frozen=True)
class Field:
    key: str
    label: str
    help: str
    kind: str  # choice, onoff, whole, percent, money, model, geography
    options: tuple[tuple[str, str], ...] = ()
    optional: bool = False


def _capitalized(words: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple((key, f"{key}: {text}") for key, text in words.items())


SECTIONS: tuple[tuple[str, str, tuple[Field, ...]], ...] = (
    (
        "What's collected",
        "More evidence finds more, and holds more of your organization's data. Each change applies"
        " from the next check.",
        (
            Field(
                "home_text",
                "Text of start-up files in home directories",
                "They show what runs when someone logs in, and can hold personal details.",
                "choice",
                _capitalized(HOME_TEXT),
            ),
            Field(
                "web_access_logs",
                "Web access logs",
                "Show which pages were requested, and by which addresses.",
                "onoff",
            ),
            Field(
                "exec_records",
                "Program starts from the audit log",
                "Which accounts' program starts are collected.",
                "choice",
                _capitalized(EXEC_RECORDS),
            ),
        ),
    ),
    (
        "Keeping and judging",
        "",
        (
            Field(
                "retention_days",
                "Days evidence is kept",
                "A purge deletes what's older. Lowering this means more goes at the next one.",
                "whole",
            ),
            Field(
                "stale_after_days",
                "Days before a check counts as old",
                "Raise it if you check less often than daily.",
                "whole",
            ),
            Field(
                "prior",
                "Starting estimate, in percent",
                "How likely a server is to be hacked before any evidence. A lower one makes the"
                " same findings look less worrying. A group's or a server's own comes first.",
                "percent",
            ),
        ),
    ),
    (
        "AI advisor",
        "It only ever advises. Nothing is sent until someone asks it to look at a server.",
        (
            Field("advisor.enabled", "AI advisor", "", "onoff"),
            Field(
                "advisor.redaction",
                "What's hidden before sending",
                "The note above describes the choice saved now.",
                "choice",
                (
                    ("pseudonymize", "Names and addresses replaced with placeholders"),
                    ("strict", "Only kinds of finding, counts and scores are sent"),
                    ("none", "Nothing but secrets: excerpts go as collected"),
                ),
            ),
            Field("advisor.model", "Model", "", "model"),
            Field(
                "advisor.effort",
                "Effort",
                "Higher costs more.",
                "choice",
                tuple((v, v) for v in ("low", "medium", "high", "xhigh", "max")),
            ),
            Field(
                "advisor.max_cost_per_run",
                "Ask first above this likely cost, in US dollars",
                "",
                "money",
            ),
            Field(
                "advisor.triage_model",
                "Cheaper model for quiet servers",
                "Optional. Used when several servers are explained at once.",
                "model",
                optional=True,
            ),
            Field(
                "advisor.inference_geo",
                "Where the model runs",
                "Optional, such as us.",
                "geography",
                optional=True,
            ),
            Field(
                "advisor.fallback",
                "If the model's safety checks decline a request",
                "",
                "choice",
                (
                    ("anthropic", "Try the model Anthropic recommends for it"),
                    ("off", "Send nothing more, and say it was declined"),
                ),
            ),
            Field(
                "advisor.api_key_source",
                "Where its API key comes from",
                "On this machine. The key itself never goes in a form.",
                "choice",
                (
                    ("env", "An environment variable of the web server"),
                    ("keyring", "This machine's keyring"),
                ),
            ),
        ),
    ),
)
BY_KEY = {field.key: field for _, _, fields in SECTIONS for field in fields}


def _as_text(field: Field, value: Any) -> str:
    if field.kind == "onoff":
        return "on" if value else "off"
    if field.kind == "percent":
        return f"{value * 100:.6g}"
    if field.kind == "money":
        return f"{value:.2f}"
    return "" if value is None else str(value)


# With the advisor pointed at another server, these decide what reaches it. The keyring holds the
# same key for every server, so choosing it from a form could send Anthropic's key there, and how
# much is hidden from a server the owner chose is the owner's to say. The geography is Anthropic's.
_ANTHROPIC_ONLY = (
    "advisor.api_key_source",
    "advisor.fallback",
    "advisor.redaction",
    "advisor.inference_geo",
)


def _can_edit(field: Field, value: Any, config) -> bool:
    """A value the form can't offer was set on the command line, and stays there."""
    advisor = config.advisor
    elsewhere = advisor.base_url or advisor.api != "anthropic" or advisor.fallback == "model"
    if field.key in _ANTHROPIC_ONLY and elsewhere:
        return False
    return field.kind != "choice" or str(value) in {option for option, _ in field.options}


def _going_to(advisor) -> str:
    """Who receives a request, in fixed words: an address can hold a secret."""
    if not advisor.base_url and advisor.api == "anthropic":
        to = ANTHROPIC
    elif is_local(advisor.base_url):
        to = "to a server on this machine"
    else:
        to = "to another server, set on the command line"
    if advisor.fallback == "model":
        to += ", and, when a request is declined, to a second model set on the command line"
    return to


def page(base: Path, typed=None, version: str | None = None) -> dict[str, Any]:
    """`typed` and `version`: what a refused form held, and what it started from. If that's old,
    saving again is refused, rather than undoing what someone else did."""
    config = load_config(base)
    sections = []
    for title, note, fields in SECTIONS:
        shown = []
        for field in fields:
            value = value_of(config, field.key)
            editable = _can_edit(field, value, config)
            text = _as_text(field, value)
            if typed is not None and editable and field.key in typed:
                text = typed.get(field.key, "")
            shown.append(
                {
                    "key": field.key,
                    "label": field.label,
                    "help": field.help,
                    "kind": field.kind,
                    "options": field.options,
                    "editable": editable,
                    "value": escape(_shown(text)),
                }
            )
        sections.append({"title": title, "note": note, "fields": shown})
    advisor = config.advisor
    return {
        "sections": sections,
        "version": version or config_version(config),
        # One line, as a page flows it: the text is wrapped for a terminal.
        "what_leaves": " ".join(
            advisor_question(
                advisor.redaction, _going_to(advisor), "someone asks it to look at a server"
            ).split()
        ),
        "elsewhere": _command_line_only(config),
    }


FIRST_CHOICES = (
    "home_text",
    "web_access_logs",
    "exec_records",
    "advisor.enabled",
    "advisor.redaction",
)


def first_choices(base: Path) -> dict[str, Any]:
    """The choices `checker init` asks about, as the settings page shows them."""
    found = page(base)
    fields = {field["key"]: field for section in found["sections"] for field in section["fields"]}
    return {
        "fields": [fields[key] for key in FIRST_CHOICES],
        "version": found["version"],
        "what_leaves": found["what_leaves"],
    }


def _command_line_only(config) -> list[tuple[str, str]]:
    """Whether they're set, not what they say: a command or an address can hold a secret."""
    advisor = config.advisor
    goes_to = (
        "Anthropic"
        if not advisor.base_url and advisor.api == "anthropic"
        else "this machine"
        if is_local(advisor.base_url)
        else "another server"
    )
    return [
        ("Notify command", "set" if config.notify_command else "not set"),
        ("Where the AI advisor's requests go", goes_to),
        (
            "A second model for declined requests",
            "set" if advisor.fallback == "model" else "not set",
        ),
        ("An API key read by running a command", "yes" if _is_command(advisor) else "no"),
        ("Where threat updates come from", "changed" if _source_changed(config) else "as shipped"),
    ]


def _is_command(advisor) -> bool:
    sources = (advisor.api_key_source, advisor.fallback_model.api_key_source)
    return any(str(source).startswith("command:") for source in sources)


def _source_changed(config) -> bool:
    return config.packs.source != type(config.packs)().source


def _typed_value(field: Field, text: str) -> str:
    """As `checker config set` takes it, or FormProblem."""
    text = text.strip()
    wrong = f"{field.label}: "
    if field.kind == "choice":
        if text not in {option for option, _ in field.options}:
            raise FormProblem(wrong + "choose one of the options.")
    elif field.kind == "onoff":
        if text not in ("on", "off"):
            raise FormProblem(wrong + "choose on or off.")
    elif field.kind == "whole":
        if not text.isascii() or not text.isdigit() or len(text) > _LONGEST_WHOLE:
            raise FormProblem(wrong + "type a whole number of days.")
    elif field.kind in ("percent", "money"):
        if not _NUMBER.fullmatch(text):
            raise FormProblem(wrong + "type a number.")
        number = float(text)
        if not math.isfinite(number):
            raise FormProblem(wrong + "type a number.")
        if field.kind == "percent":
            if not 0 < number < 100:
                raise FormProblem(wrong + "type a percentage above 0 and below 100.")
            return str(number / 100)
    elif not text:
        if not field.optional:
            raise FormProblem(wrong + "this is needed.")
        return "none"
    elif field.kind == "geography":
        text = text.lower()
        if not _GEOGRAPHY.fullmatch(text):
            raise FormProblem(wrong + "a short name in letters, such as us.")
    elif not _MODEL.fullmatch(text):
        raise FormProblem(wrong + "that doesn't look like a name this can use.")
    return text


def save(base: Path, post) -> dict[str, tuple[Any, Any]]:
    """Each setting that changed, as (old, new). Only what's in this file's list is read from the
    form, and only what differs from what the form was showing."""
    config = load_config(base)
    meanwhile = (
        "Someone changed the settings since this page opened, so what you typed wasn't saved."
    )
    version = post.get("version", "")
    if config_version(config) != version:
        raise ChangedMeanwhile(f"{meanwhile} These are the settings now.")
    texts = {}
    for key, field in BY_KEY.items():
        if key not in post:
            continue
        value = value_of(config, key)
        if not _can_edit(field, value, config):
            continue
        typed = post.get(key, "")
        if typed == _shown(_as_text(field, value)):
            continue
        texts[key] = _typed_value(field, typed)
    if not texts:
        return {}
    try:
        return change_many(base, texts, version)
    except ConfigChangedMeanwhile:
        raise ChangedMeanwhile(f"{meanwhile} These are the settings now.") from None
    except EvidenceError as exc:
        raise FormProblem(_readable(str(exc))) from None


def _readable(words: str) -> str:
    """The configuration's words, under the label the page used."""
    key, colon, rest = words.partition(":")
    field = BY_KEY.get(key.strip())
    return f"{field.label}:{rest}." if colon and field else words


def changes_in_words(changed: dict[str, tuple[Any, Any]]) -> str:
    if not changed:
        return "nothing changed"
    return "; ".join(
        f"{BY_KEY[key].label}: {recorded(key, old)} to {recorded(key, new)}"
        for key, (old, new) in changed.items()
    )
