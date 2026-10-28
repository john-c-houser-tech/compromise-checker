"""Whitelists (DESIGN.md §9): rules that suppress findings an operator has
reviewed and explained, with a reason, an owner and an expiry.

Files, in the tool's directory (layered, narrowest last):

    whitelist/global.yaml
    whitelist/groups/<group>.yaml
    whitelist/hosts/<host>.yaml

Each holds `profiles` (shipped rule sets to apply), `rules`, and `disable`
(switch off a rule from a wider layer, with a reason). A suppressed finding
is kept, with the rule that suppressed it, and contributes nothing to the
score (checker/scoring.py).

Rules match typed fields only (the check, its variant, and the finding's
entities), never free text from the host, and path patterns are anchored:
a name an intruder chose can't make a narrow rule match more than it says."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from checker.checks import load_checks

PROFILES = Path(__file__).parent / "profiles"
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
# The entity kinds a rule can name: Finding.entities are "<kind>:<value>".
ENTITY_FIELDS = ("account", "group", "key", "module", "package", "program")


class WhitelistError(Exception):
    """A whitelist file is invalid; the message says which file and where."""


class Match(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check: str
    variant: str | None = None
    account: str | None = None
    group: str | None = None
    key: str | None = None
    module: str | None = None
    package: str | None = None
    program: str | None = None
    address: str | None = None  # an address or a network
    path: str | None = None  # an anchored glob: * within a directory, ** across

    @field_validator("address")
    @classmethod
    def _network(cls, value: str | None) -> str | None:
        if value is not None:
            ipaddress.ip_network(value, strict=False)  # ValueError → validation error
        return value

    @field_validator("path")
    @classmethod
    def _absolute(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("/"):
            raise ValueError("a path pattern must start with /")
        return value

    @model_validator(mode="after")
    def _known_check(self) -> Match:
        checks = load_checks()
        if self.check not in checks:
            raise ValueError(f"no check {self.check!r}")
        variants = checks[self.check].variants
        if self.variant is not None and self.variant not in variants:
            known = ", ".join(variants) if variants else "none"
            raise ValueError(
                f"{self.check} has no variant {self.variant!r} (its variants: {known})"
            )
        return self

    def entity_fields(self) -> dict[str, str]:
        return {
            name: getattr(self, name)
            for name in (*ENTITY_FIELDS, "address", "path")
            if getattr(self, name) is not None
        }


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    match: Match
    reason: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    expires: date | Literal["never"]
    # A rule naming no account, address, path… suppresses every finding of
    # its check (or variant): allowed only when said explicitly.
    broad: bool = False

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("lower-case letters, digits, '.', '_' and '-'; at most 63")
        return value

    @field_validator("reason", "owner")
    @classmethod
    def _said(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must say something")
        return value.strip()

    @model_validator(mode="after")
    def _narrow_or_broad(self) -> Rule:
        if not self.match.entity_fields() and not self.broad:
            raise ValueError(
                "matches every finding of its check: name an account, address, path…,"
                " or set `broad: true` to mean it"
            )
        return self


class Disable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    reason: str = Field(min_length=1)
    owner: str = Field(min_length=1)


class Layer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profiles: list[str] = []
    rules: list[Rule] = []
    disable: list[Disable] = []


@dataclass
class Placed:
    """A rule and where it came from."""

    rule: Rule
    layer: str  # "profile base", "global", "group web", "host web01"
    file: str

    def as_dict(self) -> dict[str, Any]:
        return {"layer": self.layer, "file": self.file, **self.rule.model_dump(mode="json")}


@dataclass
class Whitelist:
    rules: list[Placed] = field(default_factory=list)  # narrowest layer first
    disabled: list[dict[str, Any]] = field(default_factory=list)

    def digest(self) -> str:
        canonical = json.dumps(
            {"rules": [p.as_dict() for p in self.rules], "disabled": self.disabled},
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def apply(self, findings: list[dict[str, Any]], today: date | None = None) -> dict[str, Any]:
        """Mark each finding a live rule matches with `suppressed_by` (the
        first match, narrowest layer first); returns what the assessment
        records: the set's hash, its rules, the expired ones, and counts."""
        today = today or datetime.now(UTC).date()
        live = [p for p in self.rules if p.rule.expires == "never" or p.rule.expires >= today]
        expired = [p for p in self.rules if p not in live]
        matched: dict[str, int] = {}
        for finding in findings:
            finding.pop("suppressed_by", None)
            for placed in live:
                if matches(placed.rule.match, finding):
                    finding["suppressed_by"] = {
                        "rule": placed.rule.id,
                        "layer": placed.layer,
                        "file": placed.file,
                        "reason": placed.rule.reason,
                        "owner": placed.rule.owner,
                    }
                    key = f"{placed.layer}/{placed.rule.id}"
                    matched[key] = matched.get(key, 0) + 1
                    break
        return {
            "hash": self.digest(),
            "rules": [p.as_dict() for p in self.rules],
            "disabled": self.disabled,
            "expired": [f"{p.layer}/{p.rule.id}" for p in expired],
            "matched": matched,
            "suppressed": sum(1 for f in findings if f.get("suppressed_by")),
        }


# --- Matching ----------------------------------------------------------------------------


def matches(match: Match, finding: dict[str, Any]) -> bool:
    if finding.get("check") != match.check:
        return False
    if match.variant is not None and finding.get("variant") != match.variant:
        return False
    entities: dict[str, list[str]] = {}
    for entity in finding.get("entities") or []:
        kind, _, value = str(entity).partition(":")
        entities.setdefault(kind, []).append(value)
    for name in ENTITY_FIELDS:
        wanted = getattr(match, name)
        if wanted is not None and wanted not in entities.get(name, []):
            return False
    if match.address is not None:
        network = ipaddress.ip_network(match.address, strict=False)
        if not any(_in(value, network) for value in entities.get("address", [])):
            return False
    if match.path is not None:
        pattern = path_pattern(match.path)
        if not any(
            _clean(value) and pattern.fullmatch(value) for value in entities.get("path", [])
        ):
            return False
    return True


def _in(value: str, network) -> bool:
    try:
        return ipaddress.ip_address(value) in network
    except ValueError:
        return False


def _clean(path: str) -> bool:
    """Only plain absolute paths match a pattern: `/var/www/**` must not
    match `/var/www/../../etc/shadow`, nor a name hiding a control or
    newline character."""
    if not path.startswith("/") or "//" in path:
        return False
    if any(part in (".", "..") for part in path.split("/")[1:]):
        return False
    return not any(ord(c) < 32 or ord(c) == 127 for c in path)


def path_pattern(glob: str) -> re.Pattern[str]:
    """Anchored: `*` and `?` stay within one directory, `**` crosses."""
    out = []
    i = 0
    while i < len(glob):
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out), re.DOTALL)


# --- Loading -----------------------------------------------------------------------------


def directory(home: Path) -> Path:
    return home / "whitelist"


def layer_files(home: Path, host: str, group: str | None) -> list[tuple[str, Path]]:
    """(label, file) from the widest layer to the narrowest; missing files
    are left out."""
    base = directory(home)
    candidates = [("global", base / "global.yaml")]
    if group:
        candidates.append((f"group {group}", base / "groups" / f"{group}.yaml"))
    candidates.append((f"host {host}", base / "hosts" / f"{host}.yaml"))
    return [(label, path) for label, path in candidates if path.is_file()]


def read_layer(path: Path) -> Layer:
    """One file, validated strictly; an error says the file and the line."""
    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise WhitelistError(f"{path}: not valid YAML: {exc}") from None
    try:
        return Layer.model_validate(data or {})
    except ValidationError as exc:
        problems = []
        for error in exc.errors():
            where = ".".join(str(p) for p in error["loc"])
            line = _line(text, error["loc"])
            at = f" (line {line})" if line else ""
            problems.append(f"{where}{at}: {error['msg']}")
        raise WhitelistError(f"{path}: " + "; ".join(problems)) from None


def _line(text: str, location: tuple) -> int | None:
    """The line of a validation error's location in the YAML, as near as
    the location goes (validators add their own names to it)."""
    try:
        node = yaml.compose(text)
    except yaml.YAMLError:
        return None
    found = node
    for step in location:
        if isinstance(found, yaml.MappingNode) and isinstance(step, str):
            nxt = next((v for k, v in found.value if k.value == step), None)
        elif isinstance(found, yaml.SequenceNode) and isinstance(step, int):
            nxt = found.value[step] if step < len(found.value) else None
        else:
            nxt = None
        if nxt is None:
            break
        found = nxt
    return found.start_mark.line + 1 if found is not None else None


def profile_file(name: str) -> Path:
    if not _ID.fullmatch(name):
        raise WhitelistError(f"no profile {name!r}")
    path = PROFILES / f"{name}.yaml"
    if not path.is_file():
        known = ", ".join(sorted(p.stem for p in PROFILES.glob("*.yaml"))) or "none yet"
        raise WhitelistError(f"no profile {name!r} (profiles: {known})")
    return path


def build(layers: list[tuple[str, str, Layer]]) -> Whitelist:
    """Merge layers given widest first: profiles each layer names, then its
    rules; `disable` removes a rule of a wider layer. Rule ids are unique in
    the merged set."""
    placed: list[Placed] = []
    disabled: list[dict[str, Any]] = []
    for label, file, layer in layers:
        for name in layer.profiles:
            path = profile_file(name)
            for rule in read_layer(path).rules:
                placed.append(Placed(rule, f"profile {name}", str(path)))
        for item in layer.disable:
            before = len(placed)
            placed = [p for p in placed if p.rule.id != item.id]
            if len(placed) == before:
                raise WhitelistError(f"{file}: disable {item.id!r}: no such rule in a wider layer")
            disabled.append(
                {"id": item.id, "by": label, "reason": item.reason, "owner": item.owner}
            )
        for rule in layer.rules:
            if any(p.rule.id == rule.id for p in placed):
                raise WhitelistError(
                    f"{file}: rule id {rule.id!r} is already used in a wider layer"
                )
            placed.append(Placed(rule, label, file))
    placed.reverse()  # narrowest first: its rule is the one named when several match
    return Whitelist(placed, disabled)


def load(home: Path, host: str, group: str | None) -> Whitelist:
    """The merged whitelist for a host; raises WhitelistError if any of its
    files is invalid (analysis refuses to run with an invalid set)."""
    layers = [
        (label, str(path), read_layer(path)) for label, path in layer_files(home, host, group)
    ]
    return build(layers)


def check_all(home: Path) -> list[str]:
    """Every whitelist file in the directory, validated; the errors."""
    errors = []
    base = directory(home)
    for path in sorted(base.rglob("*.yaml")) if base.is_dir() else []:
        try:
            layer = read_layer(path)
            for name in layer.profiles:
                read_layer(profile_file(name))
        except WhitelistError as exc:
            errors.append(str(exc))
    return errors


def for_host(home: Path, host: str, inventory) -> Whitelist:
    """load() with the host's group from the inventory (none if the host
    isn't in it)."""
    entry = next((h for h in inventory.hosts if h.name == host), None)
    return load(home, host, entry.group if entry else None)
