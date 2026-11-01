"""Servers from a page (plan 5.13): adding, changing and removing them, and checking who they are.

A server's name can't change, since its evidence is filed under it. A host key is trusted only when
the person pastes the fingerprint from the server itself and it matches what the server offers. The
page doesn't show the offered fingerprint first: copying it from here into the box would prove
nothing, and someone in the middle would have sent it."""

from __future__ import annotations

import asyncio
import json
import re
import socket
import threading
from pathlib import Path
from typing import Any

import asyncssh
from markupsafe import Markup, escape
from pydantic import ValidationError

from checker.baseline import usable_bundles
from checker.evidence import Store, database_file
from checker.inventory import Host, hosts_file, load_inventory, new_host_problems
from checker.report import visible
from checker.schedule import host_problems_in_plain_words
from checker.settings import HostChangedMeanwhile, add_host, change_host
from checker.transport import (
    HostKeyCheck,
    TransportError,
    TrustedKeysChanged,
    fetch_host_key,
    trust_host_key,
    trusted_fingerprints,
)
from checker.whitelist import directory

LABELS = {
    "name": "Name",
    "address": "Address",
    "port": "SSH port",
    "user": "Account",
    "auth": "How it logs in",
    "key_path": "Key file",
    "sudo": "How it gets administrator rights",
    "password_source": "Where the password comes from",
    "group": "Group",
    "python": "Python on the server",
    "web_roots": "Website folders",
    "prior": "Starting estimate",
}
FORM_FIELDS = tuple(LABELS)
# Words of ours, in place of a validator's, which can repeat what was typed or speak in fractions.
PLAIN = {
    "prior": "type a percentage above 0 and below 100",
    "web_roots": "full paths, starting with /, without ..",
}
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
# From a page this names what runs as root on a server, so it has to be Python by name at least.
_PYTHON = re.compile(
    r"(?:(?:/[A-Za-z0-9._-]+)*/)?(?:python(?:3(?:\.[0-9]+t?)?)?|platform-python|pypy3)"
)
LONGEST_PASTE = 16 * 1024
ANY_KEY_COMMAND = 'for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done'
_asking = threading.BoundedSemaphore(2)  # a server that doesn't answer holds a page for 15 seconds


class FormProblem(ValueError):
    """What's wrong, in words for the page."""


class EarlierResults(FormProblem):
    """The name was used before: the form then asks whether it's the same server."""


class ChangedMeanwhile(FormProblem):
    """Someone changed the server since the form was opened."""


class KeyUnavailable(Exception):
    """Why the server's key couldn't be fetched, in words for the page."""


def rows(base: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Every server, and which are in each group."""
    hosts = load_inventory(hosts_file(base)).hosts
    found = []
    for host in hosts:
        state = trust_of(host)
        found.append(
            {
                "name": host.name,
                "where": where_it_is(host),
                "group": host.group,
                "trusted": state == "trusted",
                "unreadable": state == "unreadable",
            }
        )
    names = sorted({host.group for host in hosts if host.group})
    groups = [
        {"name": name, "members": [host.name for host in hosts if host.group == name]}
        for name in names
    ]
    return found, groups


def where_it_is(host: Host) -> str:
    return f"{host.user}@{host.address}" + (f":{host.port}" if host.port != 22 else "")


def group_names(base: Path) -> list[str]:
    return sorted({h.group for h in load_inventory(hosts_file(base)).hosts if h.group})


def trust_of(host: Host) -> str:
    """ "trusted", "none" or "unreadable", from this machine's file alone."""
    try:
        return "trusted" if trusted_fingerprints(host) else "none"
    except (OSError, ValueError, asyncssh.Error):  # a damaged key line is a ValueError
        return "unreadable"


def check_blockers(host: Host) -> list[str]:
    """Why a check started from a page can't go ahead, in words for it."""
    state = trust_of(host)
    first = {
        "none": ["Its identity hasn't been confirmed yet. Open it to do that."],
        "unreadable": ["The file of trusted keys on this machine can't be read."],
    }.get(state, [])
    return first + host_problems_in_plain_words(host)


def has_results(base: Path, name: str) -> bool:
    if not database_file(base).exists():
        return False
    store = Store(database_file(base), read_only=True)
    try:
        return bool(usable_bundles(store, name))
    finally:
        store.close()


def _used_before(base: Path, name: str) -> bool:
    """Results would be compared with a new server's, and rules would hide its findings."""
    return has_results(base, name) or (directory(base) / "hosts" / f"{name}.yaml").exists()


def blank_form() -> dict[str, str]:
    return {**dict.fromkeys(FORM_FIELDS, ""), "port": "22", "python": "python3"} | {
        "auth": "key",
        "sudo": "nopasswd",
        "password_source": "prompt",
    }


def _percent(prior: float | None) -> str:
    return "" if prior is None else f"{prior * 100:.6g}"


def _shown(text: str) -> str:
    """A value as a form holds it: as it is, so that saving sends it back unchanged, unless it has
    characters that shouldn't reach a page. Those show escaped, and `_left_alone` keeps the stored
    value when the escaped form comes back."""
    if all(line.isprintable() for line in text.split("\n")):
        return text
    return str(visible(text, len(text) * 10 + 1))


def form_of(host: Host) -> dict[str, str]:
    return {
        "name": host.name,
        "address": _shown(host.address),
        "port": str(host.port),
        "user": _shown(host.user),
        "auth": host.auth,
        "key_path": _shown(host.key_path or ""),
        "sudo": host.sudo,
        "password_source": host.password_source,
        "group": _shown(host.group or ""),
        "python": _shown(host.python),
        "web_roots": _shown("\n".join(host.web_roots or [])),
        "prior": _percent(host.prior),
    }


def for_the_page(values: dict[str, str]) -> dict[str, Markup]:
    """Escaped here and marked so, since the pages' filter for server text would change the value:
    it doubles backslashes, flattens lines and cuts long text, and the form would save that."""
    return {field: escape(_shown(value)) for field, value in values.items()}


def form_values(post) -> dict[str, str]:
    """What was typed, to show again if it can't be used."""
    return {field: post.get(field, "") for field in FORM_FIELDS}


def _prior(text: str, kept: Host | None) -> float | None:
    if not text:
        return None
    if kept is not None and text == _percent(kept.prior):
        return kept.prior  # shown rounded: leaving it alone mustn't change it
    try:
        return float(text) / 100
    except ValueError:
        raise FormProblem(f"{LABELS['prior']}: {PLAIN['prior']}.") from None


def _left_alone(post, kept: Host | None, field: str) -> bool:
    """A browser sends a text box's line endings as CRLF, so that alone isn't a change."""
    return kept is not None and post.get(field, "").replace("\r\n", "\n") == form_of(kept)[field]


def _web_roots(post, kept: Host | None) -> list[str] | None:
    if _left_alone(post, kept, "web_roots"):
        return kept.web_roots  # including none at all, which the empty box also shows
    return [line.strip() for line in post.get("web_roots", "").splitlines() if line.strip()] or None


def host_from_form(post, kept: Host | None = None) -> Host:
    """A valid host, or FormProblem. Settings the form doesn't show stay as they are."""
    text = {field: post.get(field, "").strip() for field in FORM_FIELDS}
    # An old value with spaces around it stays exactly as it is unless someone changes it.
    for field in ("address", "user", "key_path", "group", "python"):
        if _left_alone(post, kept, field):
            text[field] = getattr(kept, field) or ""
    try:
        port = int(text["port"] or "22")
    except ValueError:
        raise FormProblem(f"{LABELS['port']}: type a number, usually 22.") from None
    if text["auth"] == "key" and not text["key_path"]:
        raise FormProblem(f"{LABELS['key_path']}: this is needed when it logs in with a key file.")
    data = {
        **(kept.model_dump() if kept else {}),
        "name": kept.name if kept else text["name"],
        "address": text["address"],
        "port": port,
        "user": text["user"],
        "auth": text["auth"],
        "key_path": text["key_path"] or None,
        "sudo": text["sudo"],
        "password_source": text["password_source"] or "prompt",
        "group": text["group"] or None,
        "python": text["python"] or "python3",
        "web_roots": _web_roots(post, kept),
        "prior": _prior(text["prior"], kept),
    }
    try:
        host = Host.model_validate(data)
    except ValidationError as exc:
        raise FormProblem(_words(exc)) from None
    problems = new_host_problems(host, kept)
    if (kept is None or kept.python != host.python) and not _PYTHON.fullmatch(host.python):
        problems.append(("python", "python3, python3.12 or a full path ending in one of those"))
    if problems:
        raise FormProblem(" ".join(f"{LABELS[field]}: {words}." for field, words in problems))
    return host


def _words(exc: ValidationError) -> str:
    """Never the error's own text, which repeats what was typed."""
    said = []
    for error in exc.errors():
        field = str(error["loc"][0]) if error["loc"] else ""
        message = PLAIN.get(field) or str(error["msg"]).removeprefix("Value error, ")
        if error["type"] in ("missing", "string_type"):
            message = "this is needed"
        said.append(f"{LABELS.get(field, field)}: {message}")
    return " ".join(f"{line}." for line in said)


def add(base: Path, host: Host, same_server: bool = False) -> None:
    """A name used before takes saying it's the same server: its old results and rules would be
    taken for this one's."""
    if not same_server and _used_before(base, host.name):
        raise EarlierResults(
            f"There are earlier results or whitelist rules for a server named {host.name}. If this"
            " is that same server, tick the box to say so. If not, give it another name, since new"
            " results would be compared with the old ones and those rules would hide its findings."
        )
    add_host(base, host, FormProblem(f"There's already a server named {host.name}."))


def change(base: Path, name: str, post, version: str) -> dict[str, tuple[Any, Any]]:
    """Each setting that changed, as (old, new)."""
    kept = load_inventory(hosts_file(base)).get(name)
    meanwhile = (
        "Someone changed this server's settings since this page opened, so what you typed wasn't"
        " saved. These are its settings now."
    )
    if kept.version() != version:
        raise ChangedMeanwhile(meanwhile)
    try:
        return change_host(base, host_from_form(post, kept), version)
    except HostChangedMeanwhile:
        raise ChangedMeanwhile(meanwhile) from None


# What hides findings first: the record is cut at its limit, and only it names the person.
_RECORD_ORDER = ("group", "prior", "python", "address", "port", "user", "sudo", "auth")
_LONGEST_RECORDED = 120


def recorded(field: str, value: Any) -> str:
    """Quoted, so a value can't pass for another clause, and short, so the rest still fits."""
    if value is None:
        return "none"
    if field == "prior":
        return f"{_percent(value)}%"
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= _LONGEST_RECORDED else f"{text[:_LONGEST_RECORDED]}...(cut)"


def _in_record_order(fields) -> list[str]:
    return sorted(fields, key=lambda f: _RECORD_ORDER.index(f) if f in _RECORD_ORDER else 99)


def changes_in_words(changed: dict[str, tuple[Any, Any]]) -> str:
    if not changed:
        return "nothing changed"
    return "; ".join(
        f"{LABELS.get(field, field)}: {recorded(field, changed[field][0])}"
        f" to {recorded(field, changed[field][1])}"
        for field in _in_record_order(changed)
    )


def settings_in_words(host: Host) -> str:
    """Everything set on it that isn't the default, for the record of adding or removing it."""
    settings = host.model_dump(mode="json", exclude_defaults=True, exclude={"name"})
    return "; ".join(
        f"{LABELS.get(field, field)}: {recorded(field, settings[field])}"
        for field in _in_record_order(settings)
    )


def _why_not(cause: BaseException | None) -> str:
    """Fixed words: what a server says about itself isn't for the permanent record."""
    if isinstance(cause, TimeoutError):
        return "It didn't answer in time. Check its address and port, and that it's running."
    if isinstance(cause, socket.gaierror):
        return "That name can't be found. Check its address."
    if isinstance(cause, ConnectionRefusedError):
        return "It refused the connection. Check the port, and that SSH is running there."
    if isinstance(cause, asyncssh.Error):
        return "Something answered, but it didn't finish as an SSH server would. Check the port."
    return "It couldn't be reached. Check its address and port, and that it's running."


def ask_for_key(host: Host) -> HostKeyCheck:
    try:
        trusted_fingerprints(host)
    except (OSError, ValueError, asyncssh.Error):  # a damaged key line is a ValueError
        raise KeyUnavailable("The file of trusted keys on this machine can't be read.") from None
    if not _asking.acquire(blocking=False):
        raise KeyUnavailable("Other servers are being asked for their keys. Try again in a moment.")
    try:
        return asyncio.run(fetch_host_key(host))
    except TransportError as exc:
        raise KeyUnavailable(_why_not(exc.__cause__)) from None
    except (OSError, ValueError):  # an address that can't be a name, such as a..b
        raise KeyUnavailable("That address can't be used. Check it.") from None
    finally:
        _asking.release()


def _key_file_word(algorithm: str) -> str | None:
    if algorithm == "ssh-ed25519":
        return "ed25519"
    if algorithm.startswith("ecdsa-"):
        return "ecdsa"
    if algorithm.startswith(("ssh-rsa", "rsa-")):
        return "rsa"
    return None


def offer_of(check: HostKeyCheck) -> dict[str, Any]:
    """What the page may say about the key. The fingerprint only once it's known to be trusted."""
    word = _key_file_word(check.key_type)
    return {
        "status": check.status,
        "key_type": check.key_type,
        "command": f"ssh-keygen -lf /etc/ssh/ssh_host_{word}_key.pub" if word else ANY_KEY_COMMAND,
        "known": list(check.known_fingerprints),
        "fingerprint": check.fingerprint if check.status == "same" else "",
    }


def trust(host: Host, check: HostKeyCheck, pasted: str, replace: bool) -> bool:
    """Only the key the person has seen on the server, and a changed one only when they say so.
    Whether anything was written: a key already trusted needs nothing."""
    if check.status == "same":
        return False
    if len(pasted) > LONGEST_PASTE:
        raise FormProblem("That's too long to be what the command printed.")
    found = _FINGERPRINT.findall(pasted)
    if not found:
        raise FormProblem(
            "That doesn't contain a fingerprint. Paste the line the command printed, which has"
            " SHA256: in it."
        )
    if check.fingerprint not in found:
        raise FormProblem(
            "That is not the key this server is offering, so it was not trusted. Either the command"
            " was run on a different server or for a different key file, or something between here"
            " and the server is pretending to be it. Don't go on until you know which."
        )
    if check.status == "changed" and not replace:
        raise FormProblem("This replaces the key trusted before: tick the box to say you mean it.")
    try:
        trust_host_key(host, check, unchanged=True)
    except TrustedKeysChanged:
        raise FormProblem(
            "Someone else confirmed a key for this server just now, so this one wasn't saved."
            " Ask the server for its key again."
        ) from None
    except TransportError:
        raise FormProblem("This server's address can't go in the file of trusted keys.") from None
    return True
