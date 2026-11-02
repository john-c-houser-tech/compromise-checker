"""Where the tool keeps its files, and the inventory of hosts it may check.

Only hosts listed here are ever contacted (security and privacy policy §3).
"""

import hashlib
import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from checker.files import atomic_write, locked
from checker.protocol import check_web_roots

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
# What can't be in an address: a known_hosts line is words, with these as its own syntax.
UNSAFE_IN_ADDRESS = re.compile(r"[\s\x00-\x1f\x7f,*?!|#@\[\]/\\]")


def home() -> Path:
    """The tool's directory: $CHECKER_HOME, else ~/.config/checker."""
    configured = os.environ.get("CHECKER_HOME")
    if configured:
        return Path(configured)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "checker"


def hosts_file(base: Path | None = None) -> Path:
    return (base or home()) / "hosts.yaml"


def known_hosts_file(base: Path | None = None) -> Path:
    return (base or home()) / "known_hosts"


class Host(BaseModel):
    """One server the tool may check, and how to log in to it."""

    model_config = ConfigDict(extra="forbid")

    name: str
    address: str
    port: int = Field(default=22, ge=1, le=65535)
    user: str
    # agent: keys from the SSH agent; key: one private key file;
    # password: SSH password (from a prompt or the OS keyring).
    auth: Literal["agent", "key", "password"] = "agent"
    key_path: str | None = None
    # root: log in as root, no sudo; nopasswd: `sudo -n`; password: sudo asks.
    sudo: Literal["root", "nopasswd", "password"] = "nopasswd"
    password_source: Literal["prompt", "keyring"] = "prompt"  # noqa: S105 - not a password
    group: str | None = None
    python: str = "python3"
    # Web roots to list for web shells instead of the common defaults.
    web_roots: list[str] | None = None
    # This host's prior probability of compromise, if not its group's or
    # the configuration's (DESIGN.md §11.2).
    prior: float | None = Field(default=None, gt=0, lt=1)
    # Which threat packs in force apply to it, if not its group's or the
    # configuration's rule (checker.packs.choice): all, none, only: <ids>
    # or except: <ids>.
    packs: str | None = None

    @field_validator("name")
    @classmethod
    def _valid_name(cls, value: str) -> str:
        if not _NAME.fullmatch(value):
            raise ValueError("letters, digits, '.', '_' and '-' only; at most 63 characters")
        return value

    @field_validator("python")
    @classmethod
    def _valid_python(cls, value: str) -> str:
        # Part of the remote command line, so no spaces or shell syntax.
        if not re.fullmatch(r"[A-Za-z0-9/._-]+", value):
            raise ValueError("a plain interpreter name or path")
        return value

    @field_validator("packs")
    @classmethod
    def _valid_packs(cls, value: str | None) -> str | None:
        from checker.packs.choice import normal

        return None if value is None else normal(value)

    @field_validator("web_roots")
    @classmethod
    def _valid_web_roots(cls, value: list[str] | None) -> list[str] | None:
        return check_web_roots(value)

    def needs_password(self) -> bool:
        return self.auth == "password" or self.sudo == "password"

    def version(self) -> str:
        """Changes when anything about the host does: what a form was filled in against."""
        text = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(text.encode()).hexdigest()


def new_host_problems(host: Host, before: Host | None = None) -> list[tuple[str, str]]:
    """(field, what's wrong) with what's being set on a host. Stricter than a stored host has to be:
    one old value in the file mustn't stop every server at load, so only what's new is judged."""

    def changed(field: str) -> bool:
        return before is None or getattr(before, field) != getattr(host, field)

    problems = []
    address = host.address
    if changed("address") and (
        not address
        or len(address) > 253
        or address[0] == "-"
        or UNSAFE_IN_ADDRESS.search(address)
        or not address.isprintable()
    ):
        problems.append(("address", "a host name or IP address, and nothing else"))
    user = host.user
    if changed("user") and (
        not user
        or len(user) > 256
        or user != user.strip()
        or user[0] == "-"
        or not user.isprintable()  # it's printed in a terminal by `checker hosts list`
    ):
        problems.append(("user", "an account name, as the server knows it"))
    if changed("group") and host.group is not None and not _NAME.fullmatch(host.group):
        # A group's whitelist is a file named after it.
        problems.append(("group", "letters, digits, '.', '_' and '-' only; at most 63 characters"))
    path = host.key_path
    if (
        changed("key_path")
        and path is not None
        and (not path.startswith(("/", "~/")) or len(path) > 4096 or not path.isprintable())
    ):
        problems.append(("key_path", "a full path, starting with / or ~/"))
    return problems


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hosts: list[Host] = []

    @model_validator(mode="after")
    def _unique_names(self) -> "Inventory":
        # Results are keyed by host name; a duplicate would silently lose one.
        seen: set[str] = set()
        for host in self.hosts:
            if host.name in seen:
                raise ValueError(f"host name {host.name!r} appears more than once")
            seen.add(host.name)
        return self

    def get(self, name: str) -> Host:
        for host in self.hosts:
            if host.name == name:
                return host
        raise KeyError(f"no host named {name!r} in the inventory")

    def add(self, host: Host) -> None:
        if any(existing.name == host.name for existing in self.hosts):
            raise ValueError(f"a host named {host.name!r} is already in the inventory")
        self.hosts.append(host)

    def remove(self, name: str) -> None:
        self.get(name)
        self.hosts = [host for host in self.hosts if host.name != name]


def load_inventory(path: Path | None = None) -> Inventory:
    path = path or hosts_file()
    if not path.exists():
        return Inventory()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Inventory.model_validate(data)


def save_inventory(inventory: Inventory, path: Path | None = None) -> None:
    path = path or hosts_file()
    data = inventory.model_dump(mode="json", exclude_defaults=True)
    data.setdefault("hosts", [])
    atomic_write(path, yaml.safe_dump(data, sort_keys=False))


@contextmanager
def inventory_transaction(path: Path | None = None) -> Iterator[Inventory]:
    """Load, change and save the inventory under one lock, so concurrent
    commands can't overwrite each other's changes. Nothing is saved if the
    block raises."""
    path = path or hosts_file()
    with locked(path):
        inventory = load_inventory(path)
        yield inventory
        save_inventory(inventory, path)
