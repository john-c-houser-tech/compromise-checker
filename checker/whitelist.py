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
entities), never free text from the host. A rule matches a finding only
if it covers every entity of each kind it names, so one known file can't
vouch for a group that also holds an unknown one. Path patterns are
anchored, match only plain absolute paths, and are matched without
backtracking, so a name an intruder chose can neither widen a rule nor
stall the analysis. A process's own name (`program`) is something the
process chose, so it never makes a rule narrow on its own."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from checker.checks import load_checks

PROFILES = Path(__file__).parent / "profiles"
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
# Entity kinds matched exactly: Finding.entities are "<kind>:<value>".
EXACT_FIELDS = ("account", "group", "key", "module", "package", "program")
PATTERN_FIELDS = ("path", "exe")  # anchored patterns
# Fields that make a rule narrow. `program` is a process's own name, which
# it can set to anything (prctl), so it narrows nothing by itself.
NARROWING = ("account", "group", "key", "module", "package", "address", "path", "exe")
MAX_PATH = 4096


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
    address: str | None = None  # an address or a network, host bits zero
    path: str | None = None  # an anchored pattern: * within a directory, ** across
    exe: str | None = None  # a process's executable, as a path pattern

    @field_validator("address")
    @classmethod
    def _network(cls, value: str | None) -> str | None:
        if value is not None:
            # strict: 203.0.113.10/24 is a typo, not the whole /24.
            ipaddress.ip_network(value, strict=True)
        return value

    @field_validator("path", "exe")
    @classmethod
    def _pattern(cls, value: str | None) -> str | None:
        if value is not None:
            check_pattern(value)
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
            for name in (*EXACT_FIELDS, "address", *PATTERN_FIELDS)
            if getattr(self, name) is not None
        }

    def narrow(self) -> bool:
        """Names something that limits it: not only the check, a process's
        own name, every address (/0) or every path (/**)."""
        for name in NARROWING:
            value = getattr(self, name)
            if value is None:
                continue
            if name == "address" and ipaddress.ip_network(value).prefixlen == 0:
                continue
            if name in PATTERN_FIELDS and all(s == "**" for s in value.strip("/").split("/")):
                continue
            return True
        return False


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    match: Match
    reason: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    expires: date | Literal["never"]
    # A rule that doesn't narrow (see Match.narrow) suppresses every finding
    # of its check (or variant): allowed only when said explicitly.
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
        if not self.match.narrow() and not self.broad:
            raise ValueError(
                "matches every finding of its check (it names nothing that narrows it: a"
                " program name, every address or every path doesn't): name an account,"
                " address, path, exe…, or set `broad: true` to mean it"
            )
        return self


class Disable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    reason: str = Field(min_length=1)
    owner: str = Field(min_length=1)


WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_CLOCK = re.compile(r"([01]\d|2[0-3]):[0-5]\d")
# What a maintenance window turns into information: findings planned work
# explains (reboots now; package changes with plan 2.6), by check and
# variant.
MAINTENANCE = {("system.reboot", "unclean"), ("system.reboot", "unexplained")}


class Window(BaseModel):
    """Planned maintenance: weekly (`every` days, `from`–`to` in `tz`), or
    once (`start`–`end`, with their UTC offsets). Reboots inside it are
    informational."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    every: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]] | None = None
    start_time: str | None = Field(default=None, alias="from")
    end_time: str | None = Field(default=None, alias="to")
    tz: str = "UTC"
    start: datetime | None = None
    end: datetime | None = None
    reason: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    expires: date | Literal["never"]

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("lower-case letters, digits, '.', '_' and '-'; at most 63")
        return value

    @field_validator("start_time", "end_time", mode="before")
    @classmethod
    def _clock(cls, value: Any) -> Any:
        if isinstance(value, int):
            # YAML reads an unquoted 02:00 as a number (sexagesimal).
            raise ValueError("quote clock times: '02:00'")
        if value is not None and not _CLOCK.fullmatch(str(value)):
            raise ValueError("a clock time, HH:MM")
        return value

    @field_validator("tz")
    @classmethod
    def _zone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError(
                f"no time zone {value!r} (use e.g. UTC, America/Los_Angeles)"
            ) from None
        return value

    @model_validator(mode="after")
    def _one_form(self) -> Window:
        weekly = self.every is not None or self.start_time is not None or self.end_time is not None
        once = self.start is not None or self.end is not None
        if weekly == once:
            raise ValueError("either weekly (every, from, to) or once (start, end)")
        if weekly:
            if not self.every or self.start_time is None or self.end_time is None:
                raise ValueError("a weekly window needs every, from and to")
            if self.start_time == self.end_time:
                raise ValueError("from and to are the same time")
        else:
            if self.start is None or self.end is None:
                raise ValueError("a one-off window needs start and end")
            if self.start.tzinfo is None or self.end.tzinfo is None:
                raise ValueError("start and end need their UTC offset (2026-11-01T02:00:00-07:00)")
            if self.end <= self.start:
                raise ValueError("end is not after start")
        return self

    def covers(self, moment: datetime) -> bool:
        if self.start is not None and self.end is not None:
            return self.start <= moment < self.end
        local = moment.astimezone(ZoneInfo(self.tz))
        clock = local.strftime("%H:%M")
        day = WEEKDAYS[local.weekday()]
        before = WEEKDAYS[(local.weekday() - 1) % 7]
        days = self.every or []
        if self.start_time < self.end_time:
            return day in days and self.start_time <= clock < self.end_time
        # Across midnight: the evening of a listed day, or the morning after.
        return (day in days and clock >= self.start_time) or (
            before in days and clock < self.end_time
        )


class Layer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profiles: list[str] = []
    rules: list[Rule] = []
    disable: list[Disable] = []
    maintenance: list[Window] = []


@dataclass
class Placed:
    """A rule, or a maintenance window, and where it came from."""

    rule: Rule | Window
    layer: str  # "profile base", "global", "group web", "host web01"
    file: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "file": self.file,
            **self.rule.model_dump(mode="json", by_alias=True, exclude_none=True),
        }

    def live(self, today: date) -> bool:
        return self.rule.expires == "never" or self.rule.expires >= today


@dataclass
class Whitelist:
    rules: list[Placed] = field(default_factory=list)  # narrowest layer first
    disabled: list[dict[str, Any]] = field(default_factory=list)
    windows: list[Placed] = field(default_factory=list)  # maintenance

    def digest(self) -> str:
        canonical = json.dumps(
            {
                "rules": [p.as_dict() for p in self.rules],
                "disabled": self.disabled,
                "windows": [p.as_dict() for p in self.windows],
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def expired(self, today: date | None = None) -> list[str]:
        today = today or datetime.now(UTC).date()
        return [f"{p.layer}/{p.rule.id}" for p in [*self.rules, *self.windows] if not p.live(today)]

    def _maintenance(self, findings: list[dict[str, Any]], today: date) -> int:
        """Planned work: a finding a live window covers, of a kind planned
        work explains, becomes informational, keeping its band to show."""
        live = [p for p in self.windows if p.live(today)]
        changed = 0
        for finding in findings:
            # Applied afresh each time: undo an earlier application first.
            earlier = finding.pop("maintenance", None)
            if earlier:
                finding["band"] = earlier["band"]
            if (finding.get("check"), finding.get("variant")) not in MAINTENANCE:
                continue
            when = _moment(finding.get("last_seen") or finding.get("first_seen"))
            window = next((p for p in live if when and p.rule.covers(when)), None)
            if window is None:
                continue
            finding["maintenance"] = {
                "window": window.rule.id,
                "layer": window.layer,
                "reason": window.rule.reason,
                "band": finding["band"],
            }
            finding["band"] = "info"
            changed += 1
        return changed

    def apply(self, findings: list[dict[str, Any]], today: date | None = None) -> dict[str, Any]:
        """Mark each finding a live rule matches with `suppressed_by` (the
        first match, narrowest layer first); returns what the assessment
        records: the set's hash, its rules, the expired ones, and counts."""
        today = today or datetime.now(UTC).date()
        maintenance = self._maintenance(findings, today)
        live = [p for p in self.rules if p.live(today)]
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
            "as_of": today.isoformat(),
            "rules": [p.as_dict() for p in self.rules],
            "disabled": self.disabled,
            "expired": self.expired(today),
            "matched": matched,
            "suppressed": sum(1 for f in findings if f.get("suppressed_by")),
            "windows": [p.as_dict() for p in self.windows],
            "maintenance": maintenance,
        }


def reapply(
    findings: list[dict[str, Any]], whitelist: Whitelist | None, today: date | None = None
) -> dict[str, Any] | None:
    """Stored findings under another whitelist (or none): earlier
    suppressions and maintenance undone, then this one applied."""
    if whitelist is not None:
        return whitelist.apply(findings, today)
    for finding in findings:
        finding.pop("suppressed_by", None)
        earlier = finding.pop("maintenance", None)
        if earlier:
            finding["band"] = earlier["band"]
    return None


def _moment(text: str | None) -> datetime | None:
    try:
        moment = datetime.fromisoformat(text) if text else None
    except ValueError:
        return None
    if moment is not None and moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment


# --- Matching ----------------------------------------------------------------------------


def matches(match: Match, finding: dict[str, Any]) -> bool:
    """Every field the rule gives must match, and must cover every entity of
    its kind the finding names (one known file doesn't vouch for another in
    the same finding); a finding whose entity list is partial matches no
    rule that names an entity."""
    if finding.get("check") != match.check:
        return False
    if match.variant is not None and finding.get("variant") != match.variant:
        return False
    named = match.entity_fields()
    if named and finding.get("entities_complete") is False:
        return False
    entities: dict[str, list[str]] = {}
    for entity in finding.get("entities") or []:
        kind, _, value = str(entity).partition(":")
        entities.setdefault(kind, []).append(value)
    for name, wanted in named.items():
        values = entities.get(name, [])
        if not values:
            return False
        if name in EXACT_FIELDS:
            ok = all(v == wanted for v in values)
        elif name == "address":
            network = ipaddress.ip_network(wanted)
            ok = all(_in(v, network) for v in values)
        else:
            ok = all(path_matches(wanted, v) for v in values)
        if not ok:
            return False
    return True


def _in(value: str, network) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.version == network.version and address in network


_HIDDEN = {"Cc", "Cf", "Zl", "Zp"}


def clean(path: str) -> bool:
    """Only plain absolute paths match a pattern: `/var/www/**` must not
    match `/var/www/../../etc/shadow`, `/var/www/./x`, `/var/www//x`, nor a
    name hiding a control, format (bidi) or line-separator character."""
    if not path.startswith("/") or len(path) > MAX_PATH or "//" in path:
        return False
    if any(part in (".", "..") for part in path.split("/")[1:]):
        return False
    return not any(unicodedata.category(c) in _HIDDEN for c in path)


def check_pattern(pattern: str) -> None:
    """A pattern: absolute; `**` only as a whole segment; at most four `**`;
    no hidden characters."""
    if not pattern.startswith("/"):
        raise ValueError("a path pattern must start with /")
    if len(pattern) > MAX_PATH or any(unicodedata.category(c) in _HIDDEN for c in pattern):
        raise ValueError("a path pattern must be plain text")
    segments = pattern.split("/")[1:]
    for segment in segments:
        if "**" in segment and segment != "**":
            raise ValueError("** stands only for whole directories: /a/**/b, not /a/x**")
    if segments.count("**") > 4:
        raise ValueError("at most four ** in a pattern")


def path_matches(pattern: str, path: str) -> bool:
    """Anchored: `*` and `?` stay within one directory, `**` is any number
    of whole directories, anything else is literal. Matched segment by
    segment with memoised dynamic programming, never a backtracking regex,
    so a long or crafted name costs at most len(pattern) × len(path)."""
    if not clean(path):
        return False
    pats = pattern.split("/")[1:]
    parts = path.split("/")[1:]
    # after[j]: pats[i:] matches parts[j:], filled from the last pattern
    # segment back to the first (no recursion, however deep the path).
    after = [False] * len(parts) + [True]
    for i in range(len(pats) - 1, -1, -1):
        now = [False] * (len(parts) + 1)
        for j in range(len(parts), -1, -1):
            if pats[i] == "**":
                now[j] = after[j] or (j < len(parts) and now[j + 1])
            else:
                now[j] = j < len(parts) and after[j + 1] and _segment(pats[i], parts[j])
        after = now
    return after[0]


def _segment(pattern: str, name: str) -> bool:
    """One directory's name against `*` and `?`, in O(len × len)."""
    previous = [True] + [False] * len(name)
    for p in pattern:
        current = [previous[0] and p == "*"] + [False] * len(name)
        for k in range(1, len(name) + 1):
            if p == "*":
                current[k] = previous[k] or current[k - 1]
            else:
                current[k] = previous[k - 1] and (p == "?" or p == name[k - 1])
        previous = current
    return previous[-1]


# --- Loading -----------------------------------------------------------------------------


class _StrictLoader(yaml.SafeLoader):
    """safe_load, refusing a key given twice in one mapping (a reviewer sees
    the first, YAML keeps the last)."""


def _no_duplicates(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"the key {key!r} is given twice", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)


def directory(home: Path) -> Path:
    return home / "whitelist"


def layer_files(home: Path, host: str, group: str | None) -> list[tuple[str, Path]]:
    """(label, file) from the widest layer to the narrowest. A missing file
    is left out; one that exists but isn't a readable regular file, or one
    named `.yml`, is an error: skipping it could bring back rules it
    switches off."""
    base = directory(home)
    candidates = [("global", base / "global.yaml")]
    if group:
        candidates.append((f"group {group}", base / "groups" / f"{group}.yaml"))
    candidates.append((f"host {host}", base / "hosts" / f"{host}.yaml"))
    found = []
    for label, path in candidates:
        other = path.with_suffix(".yml")
        if other.exists() or other.is_symlink():
            raise WhitelistError(f"{other}: whitelist files are named .yaml")
        if path.is_symlink() and not path.exists():
            raise WhitelistError(f"{path}: a link to nothing")
        if path.exists() and not path.is_file():
            raise WhitelistError(f"{path}: not a regular file")
        if path.is_file():
            found.append((label, path))
    return found


def read_layer(path: Path) -> Layer:
    """One file, validated strictly; an error says the file and the line."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise WhitelistError(f"{path}: can't be read: {exc}") from None
    try:
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - a SafeLoader subclass
    except (yaml.YAMLError, ValueError) as exc:
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
    """Merge layers given widest first: the profiles each layer names, then
    its rules; `disable` removes a rule of a wider layer, which no narrower
    layer or profile may bring back. Rule ids are unique in the merged set."""
    placed: list[Placed] = []  # rules and windows: one namespace of ids
    disabled: list[dict[str, Any]] = []
    switched_off: dict[str, str] = {}

    def add(rule: Rule | Window, label: str, file: str) -> None:
        if rule.id in switched_off:
            raise WhitelistError(
                f"{file}: rule {rule.id!r} was switched off by {switched_off[rule.id]}"
            )
        if any(p.rule.id == rule.id for p in placed):
            raise WhitelistError(f"{file}: rule id {rule.id!r} is already used in the set")
        placed.append(Placed(rule, label, file))

    for label, file, layer in layers:
        for name in layer.profiles:
            path = profile_file(name)
            profile = read_layer(path)
            for rule in [*profile.rules, *profile.maintenance]:
                add(rule, f"profile {name}", str(path))
        for item in layer.disable:
            before = len(placed)
            placed = [p for p in placed if p.rule.id != item.id]
            if len(placed) == before:
                raise WhitelistError(f"{file}: disable {item.id!r}: no such rule in a wider layer")
            switched_off[item.id] = label
            disabled.append(
                {"id": item.id, "by": label, "reason": item.reason, "owner": item.owner}
            )
        for rule in [*layer.rules, *layer.maintenance]:
            add(rule, label, file)
    placed.reverse()  # narrowest first: its rule is the one named when several match
    rules = [p for p in placed if isinstance(p.rule, Rule)]
    windows = [p for p in placed if isinstance(p.rule, Window)]
    return Whitelist(rules, disabled, windows)


def load(home: Path, host: str, group: str | None) -> Whitelist | None:
    """The merged whitelist for a host, None when no file applies to it.
    Raises WhitelistError if any of its files is invalid (analysis refuses
    to run with an invalid set)."""
    files = layer_files(home, host, group)
    if not files:
        return None
    return build([(label, str(path), read_layer(path)) for label, path in files])


def load_with(
    home: Path, host: str, group: str | None, layer: str, replacement: Path
) -> Whitelist | None:
    """load(), with `replacement` read in place of the host's `layer` file
    ("global", "group" or "host"), whether or not that file exists: what a
    proposed change would make the host's set."""
    if layer == "group" and not group:
        raise WhitelistError(f"{host} has no group in the inventory")
    label = {"global": "global", "group": f"group {group}", "host": f"host {host}"}[layer]
    files = {name: path for name, path in layer_files(home, host, group)}
    files[label] = replacement
    order = ["global", f"group {group}" if group else None, f"host {host}"]
    return build(
        [(name, str(files[name]), read_layer(files[name])) for name in order if name in files]
    )


def for_host(home: Path, host: str, inventory) -> Whitelist | None:
    """load() with the host's group from the inventory (none if the host
    isn't in it)."""
    entry = next((h for h in inventory.hosts if h.name == host), None)
    return load(home, host, entry.group if entry else None)


def check_all(home: Path, inventory) -> list[str]:
    """Every file in the whitelist directory valid, and every set it makes
    buildable: for each inventory host, each group file (with no host), and
    each host file of a host no longer in the inventory."""
    errors = []
    base = directory(home)
    if base.exists():
        for path in sorted(base.rglob("*")):
            if path.is_dir() and not path.is_symlink():
                continue
            if path.suffix != ".yaml" or not path.is_file():
                errors.append(f"{path}: not a whitelist file (regular files named .yaml only)")
                continue
            try:
                read_layer(path)
            except WhitelistError as exc:
                errors.append(str(exc))
    if errors:
        return errors
    sets = [(h.name, h.group) for h in inventory.hosts]
    known = {h.name for h in inventory.hosts}
    sets += [("(no host)", p.stem) for p in sorted((base / "groups").glob("*.yaml"))]
    sets += [(p.stem, None) for p in sorted((base / "hosts").glob("*.yaml")) if p.stem not in known]
    for host, group in sets:
        try:
            load(home, host, group)
        except WhitelistError as exc:
            errors.append(f"{host}{f' (group {group})' if group else ''}: {exc}")
    return errors
