"""First setup (plan 5.13b): a guided path for someone who has never done this. Progress is worked
out from what's really there, not stored apart from it, apart from the two things only a person can
say: that the evidence key is backed up, and that the choices were made."""

from __future__ import annotations

import ipaddress
import re
import shlex
from pathlib import Path
from typing import Any

import asyncssh
from markupsafe import escape

from checker.evidence import Store, database_file, load_config
from checker.files import atomic_write
from checker.inventory import Host, hosts_file, load_inventory
from checker.transport import read_key_file, trusted_fingerprints
from checker.web import setting_forms
from checker.web.models import ActionRecord

KEY_SAVED = "said the evidence key is backed up"
CHOSE = "made the first setup choices"
_PLAIN_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class KeyExists(Exception):
    """There's a key already: making another would lock this machine out of its servers."""


def key_path(base: Path) -> Path:
    return base / "keys" / "scanner_ed25519"


def key_path_if_made(base: Path) -> str:
    return str(key_path(base)) if key_path(base).is_file() else ""


def _said(action: str) -> bool:
    return ActionRecord.objects.filter(action=action, outcome="done").exists()


def key_unsaved(base: Path) -> bool:
    """Whether to remind them. Only if the key is here to lose."""
    return _evidence_key(base) is not None and not _said(KEY_SAVED)


def _evidence_key(base: Path) -> Path | None:
    path = base / "keys" / "evidence-identity.txt"
    return path if path.is_file() else None


def make_key(base: Path) -> str:
    """This machine's key for its servers: with no passphrase, so daily checks can use it, in a file
    only this account can read. Never replaces one. Returns its fingerprint, for the record."""
    path = key_path(base)
    if path.exists():
        raise KeyExists("There's a key already, and replacing it would lock this machine out.")
    key = asyncssh.generate_private_key("ssh-ed25519", comment="compromise-checker")
    public = key.export_public_key("openssh").decode("ascii")
    atomic_write(path, key.export_private_key("openssh").decode("ascii"), 0o600)
    atomic_write(path.with_name(path.name + ".pub"), public, 0o644)
    return key.get_fingerprint("sha256")


def _public_key(host: Host) -> str | None:
    """The line for authorized_keys, without its options. Never the private part."""
    if host.auth != "key" or not host.key_path:
        return None
    try:
        key = read_key_file(host.key_path)
        return " ".join(key.export_public_key("openssh").decode("ascii").split()[:2])
    except (OSError, ValueError, asyncssh.Error):
        return None


def _any_results(base: Path) -> bool:
    if not database_file(base).exists():
        return False
    store = Store(database_file(base), read_only=True)
    try:
        return bool(store.bundles())
    finally:
        store.close()


def _unconfirmed(hosts: list[Host]) -> list[str]:
    found = []
    for host in hosts:
        try:
            if not trusted_fingerprints(host):
                found.append(host.name)
        except (OSError, ValueError, asyncssh.Error):
            found.append(host.name)
    return found


def progress(base: Path) -> dict[str, Any]:
    hosts = load_inventory(hosts_file(base)).hosts
    evidence_key = _evidence_key(base)
    made = key_path(base).is_file()
    unconfirmed = _unconfirmed(hosts)
    public = key_path(base).with_name(key_path(base).name + ".pub")
    done = {
        "backup": evidence_key is None or _said(KEY_SAVED),
        "choices": _said(CHOSE),
        "key": made or bool(hosts),
        "server": bool(hosts),
        "ready": bool(hosts) and not unconfirmed,
        "check": _any_results(base),
    }
    order = ("backup", "choices", "key", "server", "ready", "check")
    return {
        "done": done,
        "current": next((step for step in order if not done[step]), None),
        "evidence_key": str(evidence_key) if evidence_key else "",
        "key_file": str(key_path(base)),
        "made": made,
        "public_key": escape(public.read_text().strip()) if made and public.is_file() else "",
        "hosts": [host.name for host in hosts],
        "unconfirmed": unconfirmed,
        "choices": setting_forms.first_choices(base),
        "retention_days": load_config(base).retention_days,
    }


def _from_option(typed: str) -> tuple[str, str]:
    """(an address fit for authorized_keys, what's wrong with what was typed)."""
    text = typed.strip()
    if not text:
        return "", ""
    try:
        network = ipaddress.ip_network(text, strict=False)
        return str(network.network_address if network.num_addresses == 1 else network), ""
    except ValueError:
        return "", "That isn't an IP address. Type one, such as 203.0.113.10."


def commands_for(base: Path, host: Host, typed_from: str) -> dict[str, Any]:
    """What to paste on the server, for what's supported here: a plain account, logging in with one
    key, with one sudo rule. Anything else is for the full guide, rather than a command that fails.
    Everything shown is escaped here, since the pages' filter would cut these long lines."""
    address, problem = _from_option(typed_from)
    public = _public_key(host)
    context: dict[str, Any] = {
        "typed_from": escape(typed_from.strip()),
        "from_problem": problem,
        "address": address,
        "public": bool(public),
        "plain_account": bool(_PLAIN_ACCOUNT.fullmatch(host.user)),
        "uses_sudo_rule": host.sudo == "nopasswd",
        "python": "",
        "commands": "",
        "removal": "",
    }
    if not (public and context["plain_account"] and context["uses_sudo_rule"]):
        return context
    python = host.python if host.python.startswith("/") else f"/usr/bin/{host.python}"
    user = host.user
    options = ["restrict"]
    if address:
        options.append(f'from="{address}"')
    # `sudo` finds the same interpreter by name, as the transport asks for it.
    options.append(f'command="sudo -n -- {host.python} -I -B -"')
    line = f"{','.join(options)} {public} compromise-checker"
    rule = f"{user} ALL=(root) NOPASSWD: {python} -I -B -"
    commands = f"""# 1. The account: no password, so it can only log in with the key.
sudo useradd --create-home --shell /bin/sh --comment "Compromise Checker" {user}
sudo passwd -l {user}

# 2. Its key.
sudo install -d -m 700 -o {user} -g {user} /home/{user}/.ssh
echo {shlex.quote(line)} | sudo tee /home/{user}/.ssh/authorized_keys > /dev/null
sudo chown {user}:{user} /home/{user}/.ssh/authorized_keys
sudo chmod 600 /home/{user}/.ssh/authorized_keys

# 3. The one thing it may run as an administrator.
echo {shlex.quote(rule)} | sudo tee /etc/sudoers.d/compromise-checker > /dev/null
sudo chmod 440 /etc/sudoers.d/compromise-checker
sudo visudo -cf /etc/sudoers.d/compromise-checker
"""
    removal = f"""sudo rm /etc/sudoers.d/compromise-checker
sudo userdel --remove {user}
"""
    context.update(commands=escape(commands), removal=escape(removal), python=python)
    return context
