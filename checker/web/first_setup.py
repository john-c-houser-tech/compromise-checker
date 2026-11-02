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

from checker.baseline import usable_bundles
from checker.evidence import Store, database_file, load_config, store_exists
from checker.files import atomic_write, locked
from checker.inventory import Host, hosts_file, load_inventory
from checker.transport import read_key_file, trusted_fingerprints
from checker.web import setting_forms
from checker.web.models import ActionRecord

KEY_SAVED = "said the evidence key is backed up"
CHOSE = "made the first setup choices"
_PLAIN_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_PYTHON_NAME = re.compile(r"python3(\.[0-9]+)?")
_PYTHON_PATH = re.compile(r"(/[A-Za-z0-9._-]+)+")
_COMMENT = "Compromise Checker"
SHORTEST_V4, SHORTEST_V6 = 16, 48  # a range wider than this hardly limits anything
WHAT_TO_TRY = (
    (
        "login refused",
        "The server refused this machine's login. The account may not be set up yet, the key it"
        " has may be a different one, or the address in its commands may not be this machine's.",
    ),
    (
        "sudo refused",
        "This machine logged in, but couldn't act as an administrator. The sudo rule may be"
        " missing, or Python may be somewhere else on that server.",
    ),
    (
        "cannot connect",
        "This machine couldn't reach the server. Check its address and port, and that it's on.",
    ),
    (
        "cannot read key",
        "The key file for this server can't be read. It has to be a key with no passphrase, in a"
        " file this tool's account can read, or use an SSH agent instead.",
    ),
    (
        "host key",
        "The server's identity hasn't been confirmed, or it has changed. Confirm it on the"
        " server's page.",
    ),
)


class KeyExists(Exception):
    """There's a key already: making another would lock this machine out of its servers."""


def key_path(base: Path) -> Path:
    return base / "keys" / "scanner_ed25519"


def key_path_if_made(base: Path) -> str:
    return str(key_path(base)) if key_path(base).is_file() else ""


def _said(action: str, target: str | None = None) -> bool:
    found = ActionRecord.objects.filter(action=action, outcome="done")
    return found.filter(target=target).exists() if target is not None else found.exists()


def this_key(base: Path) -> str:
    """Which key a confirmation of its backup is about: one made since hasn't been backed up."""
    return load_config(base).recipients[0]


def key_unsaved(base: Path) -> bool:
    """Whether to remind them. If it's here to lose, or was and is lost."""
    named = _evidence_key(base)
    return named is not None and (not named.is_file() or not _said(KEY_SAVED, this_key(base)))


def _evidence_key(base: Path) -> Path | None:
    """Where the settings say the private key is. None if it's kept away from this machine."""
    named = load_config(base).identity_file
    return Path(named) if named else None


def make_key(base: Path) -> str:
    """This machine's key for its servers: with no passphrase, so daily checks can use it, in a file
    only this account can read. Never replaces one. Returns its fingerprint, for the record."""
    path = key_path(base)
    with locked(path):
        if path.is_symlink() or path.exists():
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


def _checked(base: Path, hosts: list[Host]) -> bool:
    """Whether a server in the list has a check that collected something. A failed connection
    records a check too, with nothing in it."""
    if not store_exists(base):
        return False
    store = Store(database_file(base), read_only=True)
    try:
        return any(usable_bundles(store, host.name) for host in hosts)
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


def _needs_a_key(hosts: list[Host]) -> bool:
    """A server that's meant to log in with a key file whose key can't be read."""
    return any(host.auth == "key" and _public_key(host) is None for host in hosts)


def progress(base: Path) -> dict[str, Any]:
    hosts = load_inventory(hosts_file(base)).hosts
    evidence_key = _evidence_key(base)
    lost = evidence_key is not None and not evidence_key.is_file()
    made = key_path(base).is_file()
    unconfirmed = _unconfirmed(hosts)
    done = {
        "backup": evidence_key is None or (not lost and _said(KEY_SAVED, this_key(base))),
        "choices": _said(CHOSE),
        "key": made or (bool(hosts) and not _needs_a_key(hosts)),
        "server": bool(hosts),
        "ready": bool(hosts) and not unconfirmed,
        "check": _checked(base, hosts),
    }
    order = ("backup", "choices", "key", "server", "ready", "check")
    return {
        "done": done,
        "current": next((step for step in order if not done[step]), None),
        "evidence_key": str(evidence_key) if evidence_key else "",
        "evidence_key_lost": lost,
        "key_file": str(key_path(base)),
        "made": made,
        "hosts": [host.name for host in hosts],
        "unconfirmed": unconfirmed,
        "choices": setting_forms.first_choices(base),
        "retention_days": load_config(base).retention_days,
    }


def what_to_try(lines: list[str]) -> list[str]:
    """A check's own words, and what they mean for someone setting up a server. Only the tool's own
    lines, and only the first phrase in each: what comes after it can be the server's words."""
    found = set()
    for line in lines:
        text = str(line)
        if not text.startswith("checker:"):
            continue
        places = [(text.find(phrase), phrase) for phrase, _ in WHAT_TO_TRY if phrase in text]
        if places:
            found.add(min(places)[1])
    return [advice for phrase, advice in WHAT_TO_TRY if phrase in found]


def _from_option(typed: str) -> tuple[str, str]:
    """(an address fit for authorized_keys, what's wrong with what was typed)."""
    text = typed.strip()
    if not text:
        return "", ""
    wrong = "That isn't one IP address. Type one, such as 203.0.113.10."
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        return "", wrong
    if getattr(network.network_address, "ipv4_mapped", None) or "%" in text:
        return "", wrong
    if network.prefixlen < (SHORTEST_V4 if network.version == 4 else SHORTEST_V6):
        return "", "That range is too wide to limit anything. Type this machine's address."
    return str(network.network_address if network.num_addresses == 1 else network), ""


def commands_for(base: Path, host: Host, typed_from: str) -> dict[str, Any]:
    """What to paste on the server, for what's supported here: a new, plain account, logging in with
    one key, with one sudo rule. One block that stops at the first thing wrong, since pasting line
    by line would carry on past a failure. Anything else is for the full guide, rather than a
    command that does harm. Everything shown is escaped here, since the pages' filter would cut
    these long lines."""
    address, problem = _from_option(typed_from)
    public = _public_key(host)
    named = _PYTHON_NAME.fullmatch(host.python)
    usable_python = bool(named or _PYTHON_PATH.fullmatch(host.python))
    plain = bool(_PLAIN_ACCOUNT.fullmatch(host.user)) and host.user != "root"
    context: dict[str, Any] = {
        "typed_from": escape(typed_from.strip()),
        "from_problem": problem,
        "address": address,
        "public": bool(public),
        "plain_account": plain,
        "usable_python": usable_python,
        "usual_python": host.python == "python3",
        "uses_sudo_rule": host.sudo == "nopasswd",
        "python": "",
        "commands": "",
        "removal": "",
    }
    if problem or not (public and plain and usable_python and context["uses_sudo_rule"]):
        return context  # a refused address: not commands with no limit under the error
    python = f"/usr/bin/{host.python}" if named else host.python
    user = host.user
    options = ["restrict"]
    if address:
        options.append(f'from="{address}"')
    # `sudo` finds the same interpreter by name, as the transport asks for it.
    options.append(f'command="sudo -n -- {host.python} -I -B -"')
    line = f"{','.join(options)} {public} compromise-checker"
    rule = f"{user} ALL=(root) NOPASSWD: {python} -I -B -"
    rule_file = f"/etc/sudoers.d/compromise-checker-{user}"
    commands = f"""sudo bash -eu <<'END_OF_SETUP'
stop() {{ echo "STOPPED: $1"; exit 1; }}
nothing="so nothing was changed."
for needed in visudo useradd passwd getent su ssh-keygen; do
  command -v "$needed" > /dev/null || stop "$needed isn't installed here, $nothing"
done
# Stop if this account is someone's, or a home is waiting for it with someone's files.
id {user} > /dev/null 2>&1 && stop "the account {user} already exists, $nothing"
home_base=$(useradd -D | sed -n 's/^HOME=//p')
[ ! -e "$home_base/{user}" ] || stop "$home_base/{user} already exists, $nothing"
# Stop if sudo would find a different Python from the one the rule names.
found=$(command -v {host.python} || true)
[ -n "$found" ] || stop "there's no {host.python} here, $nothing"
[ "$(readlink -f "$found")" = "$(readlink -f {python})" ] \\
  || stop "another Python comes before {python} here, $nothing"
# The rule, checked before anything is made.
rule=$(mktemp)
trap 'rm -f "$rule"' EXIT
echo {shlex.quote(rule)} > "$rule"
visudo -cf "$rule" > /dev/null || stop "the sudo rule didn't check out, $nothing"

# The account: no password, so it can only log in with the key.
useradd --create-home --shell /bin/sh --comment "{_COMMENT}" {user}
passwd -l {user} > /dev/null
home=$(getent passwd {user} | cut -d: -f6)

# Its key.
install -d -m 700 -o {user} -g {user} "$home/.ssh"
echo {shlex.quote(line)} > "$home/.ssh/authorized_keys"
chown {user}:{user} "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"
# Where SELinux is on, sshd can only read these with the right label.
if command -v restorecon > /dev/null; then restorecon -R "$home/.ssh"; fi
ssh-keygen -lf "$home/.ssh/authorized_keys" > /dev/null 2>&1 \\
  && [ "$(wc -l < "$home/.ssh/authorized_keys")" = 1 ] \\
  || stop "the key was damaged in pasting. Take this away again, then paste it unwrapped."

# The one thing it may run as an administrator, and proof that it can.
install -m 440 -o root -g root "$rule" {rule_file}
su -s /bin/sh {user} -c 'sudo -n -- {host.python} -I -B -' < /dev/null \\
  || stop "sudo refused it. Take this away again, and see docs/scanner-account.md."
echo "Set up. Now confirm its identity on the server's page."
END_OF_SETUP
"""
    removal = f"""sudo bash -eu <<'END_OF_REMOVAL'
# Only the account these commands made, which they marked.
if [ "$(getent passwd {user} | cut -d: -f5)" != "{_COMMENT}" ]; then
  echo "STOPPED: {user} isn't an account these commands made, so nothing was changed."
  exit 1
fi
rm -f {rule_file}
userdel --remove {user}
echo "Taken away."
END_OF_REMOVAL
"""
    context.update(commands=escape(commands), removal=escape(removal), python=python)
    return context
