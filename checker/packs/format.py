"""The threat-pack format (DESIGN.md §10.1): a dated, versioned file that
teaches the tool about one threat. A pack is data, never code: nothing in
it is run or evaluated, and its patterns are plain globs (`*` and `?`).

This module stands alone: it needs only pydantic and PyYAML and imports
nothing else from the tool, so the pack application (plans/phase4, "After
Phase 4") validates its drafts exactly as the tool reads them.

    format: 1
    id: php2shell-2026-10
    version: 1
    title: "PHP2Shell: PHP remote code execution"
    published: 2026-10-25
    cves: [CVE-2026-109618, CVE-2026-109619]
    exposure:
      window_start: 2026-10-20T00:00:00Z
      first_seen_in_wild: 2026-10-21T07:43:00Z
      likelihood_ratio: 5      # a host exposed through the whole window
      packages:
        - release: "ubuntu:24.04"
          names: [php8.3-fpm, libapache2-mod-php8.3]
          fixed: "8.3.6-0ubuntu0.24.04.6"
          source: https://ubuntu.com/security/notices/USN-0000-1
      stale_code: {programs: ["php-fpm*"]}
    mitigations:
      - id: upload-progress-off
        setting: {kind: php_ini, name: session.upload_progress.enabled}
        expect: "off"
        covers: [CVE-2026-115560]
        text: Turn off upload progress tracking until PHP is fixed.
    detections:
      - id: worker-child
        check: web.worker_child_process
        likelihood_ratio: 10
    remediation:
      - Upgrade PHP to a fixed package and restart every PHP worker.
    references:
      - https://www.cisa.gov/...

Detections name a check built into the tool; the bounded matching
language a pack can use for its own detections (decision D1) comes with
plan 4.5 and widens this schema before the format is first published.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

FORMAT = 1
MAX_BYTES = 256 * 1024
MAX_DEPTH = 12
MAX_LR = 10.0  # no pack outweighs the core checks (decision D3)
FAMILIES = ("ubuntu", "rhel")  # Rocky Linux and AlmaLinux are matched as rhel

_ID = r"[a-z0-9][a-z0-9-]{0,62}"
_RELEASE = re.compile(r"(ubuntu):(\d{2}\.\d{2})|(rhel):(\d{1,2})")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,99}")
_VERSION = re.compile(r"[A-Za-z0-9.+~:^_-]{1,100}")
_GLOB = re.compile(r"[A-Za-z0-9._+@*?/-]{1,64}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_CHECK = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_SETTING = re.compile(r"[A-Za-z0-9_.-]{1,100}")

Text = Annotated[str, Field(min_length=1, max_length=2000)]


class PackError(Exception):
    """A pack isn't valid; the message says where and why, one problem per line."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise ValueError("must be a UTC time (ending in Z)")
    return value


class Package(_Strict):
    """Affected packages on one distribution release, and the first version
    the vendor fixed there, in the vendor's own numbering."""

    release: str  # "ubuntu:24.04", "rhel:9"
    names: list[str] = Field(min_length=1, max_length=50)  # binary package names
    fixed: str
    source: str  # where the fixed version came from (the vendor's advisory)

    @field_validator("release")
    @classmethod
    def _release(cls, value: str) -> str:
        if not _RELEASE.fullmatch(value):
            raise ValueError("a release is ubuntu:YY.MM or rhel:N, e.g. ubuntu:24.04, rhel:9")
        return value

    @field_validator("names")
    @classmethod
    def _names(cls, value: list[str]) -> list[str]:
        for name in value:
            if not _PACKAGE.fullmatch(name):
                raise ValueError(f"not a package name: {name!r}")
        if len(set(value)) != len(value):
            raise ValueError("a package is named twice")
        return value

    @field_validator("fixed")
    @classmethod
    def _fixed(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError(f"not a package version: {value!r}")
        return value

    @field_validator("source")
    @classmethod
    def _source(cls, value: str) -> str:
        return _https(value)


class StaleCode(_Strict):
    """Services that keep running vulnerable code after the fix is
    installed, until restarted: matched by process name."""

    programs: list[str] = Field(min_length=1, max_length=10)

    @field_validator("programs")
    @classmethod
    def _programs(cls, value: list[str]) -> list[str]:
        for glob in value:
            if not _GLOB.fullmatch(glob) or glob.count("*") > 3:
                raise ValueError(f"not a program pattern (letters, digits, * and ?): {glob!r}")
        return value


class Exposure(_Strict):
    window_start: datetime  # when the threat became usable (details out)
    first_seen_in_wild: datetime | None = None
    window_end: datetime | None = None  # none: still active
    # How much likelier compromise is for a host exposed through the whole
    # window; a host exposed for part of it gets that share (decision D3).
    likelihood_ratio: float = Field(gt=1, le=MAX_LR)
    packages: list[Package] = Field(min_length=1, max_length=100)
    stale_code: StaleCode | None = None

    @field_validator("window_start", "first_seen_in_wild", "window_end")
    @classmethod
    def _times(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value)

    @model_validator(mode="after")
    def _order(self) -> Exposure:
        if self.first_seen_in_wild and self.first_seen_in_wild < self.window_start:
            raise ValueError("first_seen_in_wild is before window_start")
        if self.window_end and self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        releases = [p.release for p in self.packages]
        if len(set(releases)) != len(releases):
            raise ValueError("a release is listed twice: one entry per release")
        return self


class Setting(_Strict):
    """A setting the collector reads. `php_ini`: a directive in an installed
    PHP's ini files (decision D4)."""

    kind: Literal["php_ini"]
    name: str

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _SETTING.fullmatch(value):
            raise ValueError(f"not a setting name: {value!r}")
        return value


class Mitigation(_Strict):
    id: str = Field(pattern=rf"^{_ID}$")
    setting: Setting
    expect: str = Field(min_length=1, max_length=100)  # compared without case; on/off forms equal
    covers: list[str] = Field(default=[], max_length=20)  # CVEs it also covers
    text: Text

    @field_validator("covers")
    @classmethod
    def _covers(cls, value: list[str]) -> list[str]:
        return [_cve(c) for c in value]


class Detection(_Strict):
    """A check built into the tool, weighted as the pack says inside the
    exposure window (and as usual outside it)."""

    id: str = Field(pattern=rf"^{_ID}$")
    check: str
    likelihood_ratio: float = Field(gt=1, le=200)  # the core checks' own ceiling

    @field_validator("check")
    @classmethod
    def _check(cls, value: str) -> str:
        if not _CHECK.fullmatch(value):
            raise ValueError(f"not a check id: {value!r}")
        return value


class Pack(_Strict):
    format: Literal[1]
    id: str = Field(pattern=rf"^{_ID}$")
    version: int = Field(ge=1, le=10_000)
    title: str = Field(min_length=1, max_length=200)
    published: date
    cves: list[str] = Field(default=[], max_length=50)
    exposure: Exposure
    mitigations: list[Mitigation] = Field(default=[], max_length=20)
    detections: list[Detection] = Field(default=[], max_length=50)
    remediation: list[Text] = Field(min_length=1, max_length=20)
    references: list[str] = Field(min_length=1, max_length=30)

    @field_validator("cves")
    @classmethod
    def _cves(cls, value: list[str]) -> list[str]:
        value = [_cve(c) for c in value]
        if len(set(value)) != len(value):
            raise ValueError("a CVE is listed twice")
        return value

    @field_validator("references")
    @classmethod
    def _references(cls, value: list[str]) -> list[str]:
        return [_https(url) for url in value]

    @model_validator(mode="after")
    def _unique_ids(self) -> Pack:
        for kind, items in (("mitigation", self.mitigations), ("detection", self.detections)):
            ids = [item.id for item in items]
            if len(set(ids)) != len(ids):
                raise ValueError(f"a {kind} id is used twice")
        return self


def _cve(value: str) -> str:
    if not _CVE.fullmatch(value):
        raise ValueError(f"not a CVE id: {value!r}")
    return value


def _https(value: str) -> str:
    if (
        not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[^\s]*)?", value)
        or len(value) > 500
    ):
        raise ValueError(f"not an https address: {value!r}")
    return value


# --- Reading ---------------------------------------------------------------------------------


class _Loader(yaml.SafeLoader):
    """safe_load, refusing a key given twice in one mapping (a reviewer
    sees the first, YAML keeps the last)."""


def _no_duplicates(loader: _Loader, node: yaml.MappingNode, deep: bool = False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"the key {key!r} is given twice", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)


def _shape(text: str) -> None:
    """Before the YAML is built: no aliases (a few lines can expand to
    gigabytes) and no deeper nesting than a pack needs."""
    depth = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            raise PackError(f"line {event.start_mark.line + 1}: aliases (*name) aren't allowed")
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_DEPTH:
                raise PackError(f"line {event.start_mark.line + 1}: nested too deeply")
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1


def read(data: bytes) -> Pack:
    """A pack from its file's bytes, checked; PackError says what's wrong.
    (Its signature is checked before this, by whoever trusts it.)"""
    if len(data) > MAX_BYTES:
        raise PackError(f"larger than {MAX_BYTES // 1024} KiB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackError(f"not UTF-8 text ({exc.reason} at byte {exc.start})") from None
    try:
        _shape(text)
        loaded = yaml.load(text, Loader=_Loader)  # noqa: S506 - a SafeLoader subclass
    except yaml.YAMLError as exc:
        raise PackError(f"not valid YAML: {exc}") from None
    if not isinstance(loaded, dict):
        raise PackError("a pack is a mapping of fields (format, id, version, …)")
    if loaded.get("format") != FORMAT:
        raise PackError(
            f"format {loaded.get('format')!r}: this version of the tool reads format {FORMAT}"
        )
    try:
        return Pack.model_validate(loaded)
    except ValidationError as exc:
        raise PackError("\n".join(_problem(e) for e in exc.errors())) from None


def _problem(error: dict) -> str:
    where = ".".join(str(p) for p in error["loc"]) or "the pack"
    return f"{where}: {error['msg'].removeprefix('Value error, ')}"
