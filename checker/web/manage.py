"""Servers from a page (plan 5.13): adding, changing and removing them, and checking who they are.

A server's name can't change, since its evidence is filed under it. A host key is trusted only when
the person pastes the fingerprint from the server itself and it matches what the server offers. The
page doesn't show the offered fingerprint first: copying it from here into the box would prove
nothing, and someone in the middle would have sent it."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import asyncssh
from pydantic import ValidationError

from checker.baseline import usable_bundles
from checker.evidence import Store, database_file
from checker.inventory import Host, hosts_file, inventory_transaction, load_inventory
from checker.schedule import host_problems_in_plain_words
from checker.settings import HostChangedMeanwhile, change_host
from checker.transport import (
    HostKeyCheck,
    TransportError,
    fetch_host_key,
    trust_host_key,
    trusted_fingerprints,
)

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
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
LONGEST_PASTE = 16 * 1024
ANY_KEY_COMMAND = 'for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done'


class FormProblem(ValueError):
    """What's wrong, in words for the page."""


class EarlierResults(FormProblem):
    """The name has results already: the form then asks whether it's the same server."""


class KeyUnavailable(Exception):
    """Why the server's key couldn't be fetched, in words for the page."""


def rows(base: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Every server, and which are in each group."""
    hosts = load_inventory(hosts_file(base)).hosts
    found = [
        {
            "name": host.name,
            "where": f"{host.user}@{host.address}" + (f":{host.port}" if host.port != 22 else ""),
            "group": host.group,
            "trusted": trust_of(host) == "trusted",
            "unreadable": trust_of(host) == "unreadable",
        }
        for host in hosts
    ]
    names = sorted({host.group for host in hosts if host.group})
    groups = [
        {"name": name, "members": [host.name for host in hosts if host.group == name]}
        for name in names
    ]
    return found, groups


def group_names(base: Path) -> list[str]:
    return sorted({h.group for h in load_inventory(hosts_file(base)).hosts if h.group})


def trust_of(host: Host) -> str:
    """ "trusted", "none" or "unreadable", from this machine's file alone."""
    try:
        return "trusted" if trusted_fingerprints(host) else "none"
    except (OSError, ValueError, asyncssh.Error):  # a damaged key line is a ValueError
        return "unreadable"


def what_stops_it(host: Host) -> list[str]:
    return host_problems_in_plain_words(host)


def has_results(base: Path, name: str) -> bool:
    if not database_file(base).exists():
        return False
    store = Store(database_file(base), read_only=True)
    try:
        return bool(usable_bundles(store, name))
    finally:
        store.close()


def blank_form() -> dict[str, str]:
    return {**dict.fromkeys(FORM_FIELDS, ""), "port": "22", "python": "python3"} | {
        "auth": "key",
        "sudo": "nopasswd",
        "password_source": "prompt",
    }


def _percent(prior: float | None) -> str:
    return "" if prior is None else f"{prior * 100:.6g}"


def form_of(host: Host) -> dict[str, str]:
    return {
        "name": host.name,
        "address": host.address,
        "port": str(host.port),
        "user": host.user,
        "auth": host.auth,
        "key_path": host.key_path or "",
        "sudo": host.sudo,
        "password_source": host.password_source,
        "group": host.group or "",
        "python": host.python,
        "web_roots": "\n".join(host.web_roots or []),
        "prior": _percent(host.prior),
    }


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
        raise FormProblem(f"{LABELS['prior']}: type a percentage, such as 2.") from None


def host_from_form(post, kept: Host | None = None) -> Host:
    """A valid host, or FormProblem. Settings the form doesn't show stay as they are."""
    text = {field: post.get(field, "").strip() for field in FORM_FIELDS}
    auth = text["auth"]
    try:
        port = int(text["port"] or "22")
    except ValueError:
        raise FormProblem(f"{LABELS['port']}: type a number, usually 22.") from None
    data = {
        **(kept.model_dump() if kept else {}),
        "name": kept.name if kept else text["name"],
        "address": text["address"],
        "port": port,
        "user": text["user"],
        "auth": auth,
        "key_path": text["key_path"] or None if auth == "key" else None,
        "sudo": text["sudo"],
        "password_source": text["password_source"] or "prompt",
        "group": text["group"] or None,
        "python": text["python"] or "python3",
        "web_roots": [line.strip() for line in text["web_roots"].splitlines() if line.strip()]
        or None,
        "prior": _prior(text["prior"], kept),
    }
    try:
        return Host.model_validate(data)
    except ValidationError as exc:
        raise FormProblem(_words(exc)) from None


def _words(exc: ValidationError) -> str:
    """Never the error's own text, which repeats what was typed."""
    said = []
    for error in exc.errors():
        field = str(error["loc"][0]) if error["loc"] else ""
        message = str(error["msg"]).removeprefix("Value error, ")
        if error["type"] == "missing" or (error["type"] == "string_type"):
            message = "this is needed"
        said.append(f"{LABELS.get(field, field)}: {message}")
    return " ".join(f"{line}." for line in said)


def add(base: Path, host: Host, same_server: bool = False) -> None:
    """A name with results already means those results would be taken for this server's, so it
    takes saying that it's the same one."""
    if not same_server and has_results(base, host.name):
        raise EarlierResults(
            f"There are earlier results for a server named {host.name}. If this is that same"
            " server, tick the box to say so. If not, give it another name, since new results would"
            " be compared with the old ones."
        )
    try:
        with inventory_transaction(hosts_file(base)) as inventory:
            inventory.add(host)
    except ValueError as exc:
        if isinstance(exc, ValidationError):
            raise
        raise FormProblem(f"There's already a server named {host.name}.") from None


def change(base: Path, name: str, post, version: str) -> list[str]:
    """The settings that changed."""
    kept = load_inventory(hosts_file(base)).get(name)
    new = host_from_form(post, kept)
    try:
        return change_host(base, new, version)
    except (HostChangedMeanwhile, KeyError):
        raise FormProblem(
            "This server's settings changed since this page opened. Look again."
        ) from None


def ask_for_key(host: Host) -> HostKeyCheck:
    try:
        return asyncio.run(fetch_host_key(host))
    except TransportError as exc:
        raise KeyUnavailable(
            f"It didn't answer, so check its address and port and that it's running. ({exc})"
        ) from None
    except (OSError, ValueError, asyncssh.Error):  # a damaged key line is a ValueError
        raise KeyUnavailable("The file of trusted keys on this machine can't be read.") from None


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


def trust(host: Host, check: HostKeyCheck, pasted: str, replace: bool) -> None:
    """Only the key the person has seen on the server, and a changed one only when they say so."""
    if check.status == "same":
        return
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
    trust_host_key(host, check)
