"""Where the tool keeps its files, and the inventory of hosts it may check.

Only hosts listed here are ever contacted (security and privacy policy §3).
"""

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

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


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
        if not _NAME.match(value):
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
