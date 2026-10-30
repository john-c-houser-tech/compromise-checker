"""The threat-pack format (DESIGN.md §10.1): a dated, versioned file that
teaches the tool about one threat. A pack is data, never code: nothing in
it is run or evaluated, and its patterns are plain globs (`*` and `?`).

This module stands alone: it needs only pydantic and PyYAML, and from the
tool only the version ordering (checker.packs.versions, itself standing
alone), so the pack application (plans/phase4, "After Phase 4")
validates its drafts exactly as the tool reads them.

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
          binary_names: [php8.3-fpm, libapache2-mod-php8.3]
          fixed: "8.3.6-0ubuntu0.24.04.6"
          source: https://ubuntu.com/security/notices/USN-0000-1
        - release: "ubuntu:24.04"          # the same release, another repository
          binary_names: [php8.3-fpm]
          versions: "*+deb.sury.org*"      # only installed versions like this
          fixed: "8.3.27-1+ubuntu24.04.1+deb.sury.org+1"
          source: https://launchpad.net/~ondrej/+archive/ubuntu/php
        - release: "rhel:9"
          binary_names: [php-fpm]
          versions: "8.1.*"                # one module stream
          fixed: null                      # no fix yet: every one is affected
          source: https://access.redhat.com/security/cve/CVE-2026-109618
      stale_code: {programs: ["php-fpm*"]}
    mitigations:
      - id: upload-progress-off
        setting: {kind: php_ini, name: session.upload_progress.enabled}
        expect: "off"
        default: "on"                      # PHP's own, when no file sets it
        covers: [CVE-2026-115560]
        text: Turn off upload progress tracking until PHP is fixed.
    detections:
      - id: worker-child                   # a check built into the tool
        check: web.worker_child
        likelihood_ratio: 10
      - id: fpm-crash                      # the pack's own rule over events
        title: PHP-FPM workers crashing
        counts: while_exposed              # an attempt: harmless once fixed
        needs: [web_error_log]
        events:
          any_of:
            - type: web.error
              fields: {message: {glob: "*child * exited on signal 11*"}}
            - type: kernel.segfault
              fields: {comm: {prefix: php-fpm}}
          count: {at_least: 3, within: 10m}
        likelihood_ratio: 8
      - id: ini-in-web-root                # the pack's own rule over the snapshot
        title: A .user.ini added to a web root
        snapshot:
          section: web_files
          key: {glob: "*/.user.ini"}
          state: added
        likelihood_ratio: 4
    remediation:
      - Upgrade PHP to a fixed package and restart every PHP worker.
    references:
      - https://www.cisa.gov/...

An installed package is matched by its binary name (the collector knows no
source names) and, where an entry says, by a glob on its installed version:
the way to tell apart repositories (Ubuntu's archive, the Sury PPA) and
streams (RHEL's PHP modules) that ship the same name on one release. When
a package matches several entries (an entry with no pattern matches every
version), it is vulnerable if any of them says so: the Ubuntu archive's
fixed version can't vouch for a Sury build that sorts above it.

A fixed version carries the vendor's revision (dpkg) or release (rpm):
"8.3.6" alone would count every distribution build of 8.3.6 as fixed,
backported fix or not.

Detections (decision D1, plan 4.5; checker/packs/detect.py) count only
for a host the pack's threat reached: while it ran a vulnerable version
(`counts: while_exposed`, for an attack attempt, harmless once fixed), or
from then on, fix or not (`since_exposed`, the default: someone already
inside stays). One names a check built into the tool (never a pack's own),
whose findings then weigh as the pack says, up to the core's critical
ratio, 100, and at most one band above their own; or it is the pack's own
rule, up to the high band's, 20, so a pack can't outweigh the core checks:
over events (up to five matchers,
each an event type, exact or a prefix ending in ".", and its fields; at
least so many within a span, apart for each value of a field such as the
source network) or over the snapshot (items of a section present, absent,
or added, changed or removed since the baseline; never the sections
exposure is judged from). Only some web requests become events (5xx,
attack markers, scripts, sensitive paths). Values are matched as text:
exactly, by prefix, or by a glob with `*` and `?`, never by a regular
expression. `needs` names data a detection can't work without (rules over
web requests, web errors and program starts need theirs anyway); a host
whose collection lacks it gets a coverage gap, not silence.

YAML is read as YAML 1.2 reads it: `off`, `no` and `yes` stay text, a
leading zero doesn't make a number octal, and `1:30` isn't sixty-based.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal, get_args

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

FORMAT = 1
MAX_BYTES = 256 * 1024
MAX_DEPTH = 12
MAX_PROBLEMS = 20
MAX_LR = 10.0  # no pack outweighs the core checks (decision D3)

_ID = r"[a-z0-9][a-z0-9-]{0,62}"
_RELEASE = re.compile(r"ubuntu:\d{2}\.\d{2}|rhel:\d{1,2}")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,99}")
_VERSION = re.compile(r"[A-Za-z0-9.+~:^_-]{1,100}")
_VERSION_GLOB = re.compile(r"[A-Za-z0-9.+~:^_*?-]{1,100}")
_GLOB = re.compile(r"[A-Za-z0-9._+@*?/-]{1,64}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_CHECK = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_SETTING = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOST = re.compile(rf"(?:{_LABEL}\.)+[A-Za-z]{{2,63}}")
_LOCAL_HOSTS = ("localhost", "localhost.localdomain")

# Characters that hide or disguise text (controls, format characters such
# as bidi overrides, unassigned and private ones, line and paragraph
# separators, and every space but the plain one): never in a pack, whose
# text is shown in terminals and reports.
_HIDING = {"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"}


def _plain(value: str) -> str:
    for c in value:
        if unicodedata.category(c) in _HIDING or (unicodedata.category(c) == "Zs" and c != " "):
            raise ValueError(f"holds a hidden or control character (U+{ord(c):04X})")
    return value


Plain = Annotated[str, AfterValidator(_plain)]
Text = Annotated[str, Field(min_length=1, max_length=2000), AfterValidator(_plain)]


class PackError(Exception):
    """A pack isn't valid; the message says where and why, one problem per line."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _time(value: Any) -> Any:
    """A UTC time, written so YAML reads it as one."""
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
            raise ValueError("must be a UTC time, ending in Z: 2026-10-20T00:00:00Z")
        return value
    raise ValueError("write a UTC time with seconds, unquoted: 2026-10-20T00:00:00Z")


def _day(value: Any) -> Any:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    raise ValueError("write a date alone, unquoted: 2026-10-25")


def _https(value: str) -> str:
    """An https address on a public host name: no user part, no address
    literal or local host, a real port, nothing hidden."""
    if len(value) > 500:
        raise ValueError("an address longer than 500 characters")
    found = re.fullmatch(r"https://([^/:?#\s]+)(?::(\d{1,5}))?([/?#]\S*)?", _plain(value))
    host = found and found.group(1)
    if (
        not found
        or not _HOST.fullmatch(host)
        or host.lower() in _LOCAL_HOSTS
        or (found.group(2) and not 0 < int(found.group(2)) <= 65535)
    ):
        raise ValueError(f"not an https address on a public host name: {value!r}")
    return value


class Package(_Strict):
    """Affected binary packages on one distribution release, optionally only
    those whose installed version matches `versions`, and the first version
    the vendor fixed there, in its own numbering; `fixed: null` when there is
    no fix yet, so every matching version is affected."""

    release: str  # "ubuntu:24.04", "rhel:9" (Rocky Linux and AlmaLinux as rhel)
    binary_names: list[str] = Field(min_length=1, max_length=50)
    versions: str | None = None  # a glob on the installed version
    fixed: str | None
    source: str  # the vendor's advisory the fixed version came from

    @field_validator("release")
    @classmethod
    def _release(cls, value: str) -> str:
        if not _RELEASE.fullmatch(value):
            raise ValueError("a release is ubuntu:YY.MM or rhel:N, e.g. ubuntu:24.04, rhel:9")
        return value

    @field_validator("binary_names")
    @classmethod
    def _names(cls, value: list[str]) -> list[str]:
        for name in value:
            if not _PACKAGE.fullmatch(name):
                raise ValueError(f"not a package name: {name!r}")
        if len(set(value)) != len(value):
            raise ValueError("a package is named twice")
        return value

    @field_validator("versions")
    @classmethod
    def _versions(cls, value: str | None) -> str | None:
        if value is not None and (not _VERSION_GLOB.fullmatch(value) or value.count("*") > 3):
            raise ValueError(f"not a version pattern (version characters, * and ?): {value!r}")
        return value

    @field_validator("fixed")
    @classmethod
    def _fixed(cls, value: str | None) -> str | None:
        if value is not None and not _VERSION.fullmatch(value):
            raise ValueError(f"not a package version: {value!r}")
        if value is not None and not re.search(r"[^-]-[^-]+$", value.split(":", 1)[-1]):
            raise ValueError(
                f"a fixed version needs the vendor's revision or release, as installed"
                f" (8.3.6-0ubuntu0.24.04.6, not 8.3.6): {value!r}"
            )
        return value

    @field_validator("source")
    @classmethod
    def _source(cls, value: str) -> str:
        return _https(value)

    @model_validator(mode="after")
    def _family(self) -> Package:
        """The fixed version as the release's own package manager reads it."""
        from checker.packs.versions import VersionError, compare

        if self.fixed is not None:
            family = "dpkg" if self.release.startswith("ubuntu:") else "rpm"
            try:
                compare(family, self.fixed, self.fixed)
            except VersionError as exc:
                raise ValueError(f"{self.release}: {exc}") from None
        return self


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

    @field_validator("window_start", mode="before")
    @classmethod
    def _start(cls, value: Any) -> Any:
        return _time(value)

    @field_validator("first_seen_in_wild", "window_end", mode="before")
    @classmethod
    def _times(cls, value: Any) -> Any:
        return None if value is None else _time(value)

    @model_validator(mode="after")
    def _order(self) -> Exposure:
        if self.first_seen_in_wild and self.first_seen_in_wild < self.window_start:
            raise ValueError("first_seen_in_wild is before window_start")
        if self.window_end and self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        if (
            self.window_end
            and self.first_seen_in_wild
            and self.window_end < self.first_seen_in_wild
        ):
            raise ValueError("window_end is before first_seen_in_wild")
        seen: dict[tuple[str, str | None], set[str]] = {}
        for package in self.packages:
            names = seen.setdefault((package.release, package.versions), set())
            if names & set(package.binary_names):
                raise ValueError(
                    f"{package.release}: a package is in two entries with the same versions"
                    " pattern: give each its own pattern"
                )
            names |= set(package.binary_names)
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
    # Compared without regard to case; on/off, yes/no, true/false and 1/0
    # are each the same.
    expect: Annotated[str, Field(min_length=1, max_length=100), AfterValidator(_plain)]
    # What the setting is when no file sets it (PHP's built-in default;
    # session.upload_progress.enabled's is On). Without it, a setting set
    # nowhere can't be judged.
    default: Annotated[str, Field(max_length=100), AfterValidator(_plain)] | None = None
    covers: list[str] = Field(default=[], max_length=20)  # CVEs it also covers
    text: Text

    @field_validator("covers")
    @classmethod
    def _covers(cls, value: list[str]) -> list[str]:
        value = [_cve(c) for c in value]
        if len(set(value)) != len(value):
            raise ValueError("a CVE is listed twice")
        return value

    @model_validator(mode="after")
    def _says_the_default(self) -> Mitigation:
        # A setting set nowhere is the default; without it, the commonest
        # case (Ubuntu's php.ini leaves most settings commented out) can't
        # be judged.
        if self.setting.kind == "php_ini" and self.default is None:
            raise ValueError("a php_ini mitigation says the setting's default (PHP's own)")
        return self


# Detections (decision D1): data the engine matches, never code.
MAX_CHECK_LR = 100.0  # the core's critical band: a check's findings weigh no more
MAX_OWN_LR = 20.0  # the high band: a pack's own rule weighs no more
MAX_GLOB_STARS = 10
MAX_SPAN_SECONDS = 7 * 86400
_FIELD = re.compile(r"[a-z][a-z0-9_]{0,39}")
_EVENT_TYPE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*\.?")
_SECTION = re.compile(r"[a-z][a-z0-9_]{0,39}")
_VARIANT = re.compile(r"[a-z][a-z0-9_]{0,39}")
_DURATION = re.compile(r"([1-9][0-9]{0,6})([smhd])")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
# What a detection can say it needs, each judged from the collection.
# Two are never there: request_content_type is in no log format the tool
# reads (DESIGN.md §10.2's multipart POSTs), and every_web_request because
# only some requests become events (5xx, attack markers, scripts, sensitive
# paths; the rest are counted per network): a detection needing either is
# always a coverage gap. Rules over web.request, web.error and process.exec
# need their logs whether they say so or not.
Need = Literal[
    "web_access_log", "web_error_log", "process_starts", "request_content_type",
    "every_web_request",
]  # fmt: skip
NEEDS = get_args(Need)
# Snapshot sections a pack's own rule can't read: what its exposure and
# mitigations are judged from, so exposure can't pass for compromise.
EXPOSURE_SECTIONS = ("packages", "package_history", "php_settings", "web_config", "host")
MatchText = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_plain)]


class Match(_Strict):
    """A value matched as text: exactly, by its start, or by a glob (`*`
    any run of characters, `?` one; nothing else is special)."""

    equals: MatchText | None = None
    prefix: MatchText | None = None
    glob: MatchText | None = None

    @model_validator(mode="after")
    def _one(self) -> Match:
        given = [v for v in (self.equals, self.prefix, self.glob) if v is not None]
        if len(given) != 1:
            raise ValueError("give one of equals, prefix or glob")
        if self.glob is not None and self.glob.count("*") > MAX_GLOB_STARS:
            raise ValueError(f"a glob has at most {MAX_GLOB_STARS} '*'")
        return self


def _fields(value: dict[str, Match]) -> dict[str, Match]:
    for name in value:
        if not _FIELD.fullmatch(name):
            raise ValueError(f"not a field name: {name!r}")
    return value


Fields = Annotated[dict[str, Match], Field(max_length=8), AfterValidator(_fields)]


class EventMatch(_Strict):
    type: str  # exact, or a prefix ending in "." ("web.")
    fields: Fields = {}

    @field_validator("type")
    @classmethod
    def _type(cls, value: str) -> str:
        if len(value) > 60 or not _EVENT_TYPE.fullmatch(value):
            raise ValueError(f"not an event type: {value!r}")
        return value


class Count(_Strict):
    at_least: int = Field(ge=1, le=10_000)
    within: str | None = None  # "30s", "10m", "2h", "1d"; none: the whole time exposed

    @field_validator("within")
    @classmethod
    def _within(cls, value: str | None) -> str | None:
        if value is not None and span_seconds(value) is None:
            raise ValueError(f"not a span of at most 7 days, like 10m or 2h: {value!r}")
        return value


def span_seconds(text: str) -> int | None:
    found = _DURATION.fullmatch(text)
    if not found:
        return None
    seconds = int(found[1]) * _UNIT_SECONDS[found[2]]
    return seconds if seconds <= MAX_SPAN_SECONDS else None


class EventRule(_Strict):
    any_of: list[EventMatch] = Field(min_length=1, max_length=5)
    count: Count = Count(at_least=1)
    by: str | None = None  # a field: counted apart for each of its values

    @field_validator("by")
    @classmethod
    def _by(cls, value: str | None) -> str | None:
        if value is not None and not _FIELD.fullmatch(value):
            raise ValueError(f"not a field name: {value!r}")
        return value


class SnapshotRule(_Strict):
    section: str
    key: Match | None = None
    fields: Fields = {}
    # present, absent: in the snapshot now; added, changed, removed: since
    # the baseline.
    state: Literal["present", "absent", "added", "changed", "removed"]

    @field_validator("section")
    @classmethod
    def _section(cls, value: str) -> str:
        if not _SECTION.fullmatch(value):
            raise ValueError(f"not a snapshot section: {value!r}")
        if value in EXPOSURE_SECTIONS:
            raise ValueError(
                f"{value} is what exposure is judged from: a detection can't read it (exposure"
                " isn't compromise)"
            )
        return value


class Detection(_Strict):
    """A check built into the tool (`check`, optionally one `variant`),
    whose findings weigh as the pack says; or the pack's own rule (`events`
    or `snapshot`, with a `title`). `counts`: `while_exposed`, only while
    the host ran a vulnerable version (an attack attempt, harmless once
    fixed), or `since_exposed`, from when the host first became exposed to
    the collection, fix or not (someone already inside stays)."""

    id: str = Field(pattern=rf"^{_ID}$")
    check: str | None = None
    variant: str | None = None
    title: Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_plain)] | None = None
    events: EventRule | None = None
    snapshot: SnapshotRule | None = None
    needs: list[Need] = Field(default=[], max_length=len(NEEDS))
    counts: Literal["while_exposed", "since_exposed"] = "since_exposed"
    likelihood_ratio: float = Field(gt=1, le=MAX_CHECK_LR)

    @field_validator("check")
    @classmethod
    def _check(cls, value: str | None) -> str | None:
        if value is not None and not _CHECK.fullmatch(value):
            raise ValueError(f"not a check id: {value!r}")
        if value is not None and value.startswith("pack."):
            # The packs' own findings: naming them would lift every pack's
            # detections past their cap.
            raise ValueError(f"a detection can't name a pack check: {value!r}")
        return value

    @field_validator("variant")
    @classmethod
    def _variant(cls, value: str | None) -> str | None:
        if value is not None and not _VARIANT.fullmatch(value):
            raise ValueError(f"not a variant: {value!r}")
        return value

    @model_validator(mode="after")
    def _one_kind(self) -> Detection:
        kinds = [k for k in ("check", "events", "snapshot") if getattr(self, k) is not None]
        if len(kinds) != 1:
            raise ValueError("a detection is one of: check, events, snapshot")
        if self.variant is not None and self.check is None:
            raise ValueError("variant goes with check")
        if self.check is not None and self.title is not None:
            raise ValueError("a check's findings keep their own title: title goes with events"
                             " or snapshot")  # fmt: skip
        if self.check is None:
            if self.title is None:
                raise ValueError("a pack's own detection has a title")
            if self.likelihood_ratio > MAX_OWN_LR:
                raise ValueError(
                    f"a pack's own detection's likelihood_ratio is at most {MAX_OWN_LR:g}"
                )
        if len(set(self.needs)) != len(self.needs):
            raise ValueError("a need is listed twice")
        return self


class Pack(_Strict):
    format: Literal[1]
    id: str = Field(pattern=rf"^{_ID}$")
    version: int = Field(ge=1, le=10_000)
    title: Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_plain)]
    published: date
    cves: list[str] = Field(default=[], max_length=50)
    exposure: Exposure
    mitigations: list[Mitigation] = Field(default=[], max_length=20)
    detections: list[Detection] = Field(default=[], max_length=50)
    remediation: list[Text] = Field(min_length=1, max_length=20)
    references: list[str] = Field(min_length=1, max_length=30)

    @field_validator("published", mode="before")
    @classmethod
    def _published(cls, value: Any) -> Any:
        return _day(value)

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


# --- Reading ---------------------------------------------------------------------------------

_INT = "tag:yaml.org,2002:int"
_FLOAT = "tag:yaml.org,2002:float"
_BOOL = "tag:yaml.org,2002:bool"


class _Loader(yaml.SafeLoader):
    """safe_load with YAML 1.2's plain types (true/false only; decimal
    integers; no sixty-based numbers), refusing a key given twice in one
    mapping (a reviewer sees the first, YAML keeps the last), a key that
    isn't text, and merge keys."""


_Loader.yaml_implicit_resolvers = {
    first: [(tag, rx) for tag, rx in resolvers if tag not in (_INT, _FLOAT, _BOOL)]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Loader.add_implicit_resolver(_BOOL, re.compile(r"^(?:true|false)$"), list("tf"))
_Loader.add_implicit_resolver(_INT, re.compile(r"^[-+]?[0-9]+$"), list("-+0123456789"))
_Loader.add_implicit_resolver(
    _FLOAT,
    re.compile(r"^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?$"),
    list("-+.0123456789"),
)


def _decimal(loader: _Loader, node: yaml.ScalarNode) -> int:
    text = loader.construct_scalar(node)
    if not re.fullmatch(r"[-+]?[0-9]{1,18}", text):
        raise yaml.constructor.ConstructorError(
            None, None, f"not a decimal integer: {text[:40]!r}", node.start_mark
        )
    return int(text)


def _number(loader: _Loader, node: yaml.ScalarNode) -> float:
    text = loader.construct_scalar(node)
    if len(text) > 40 or not re.fullmatch(
        r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?", text
    ):
        raise yaml.constructor.ConstructorError(
            None, None, f"not a number: {text[:40]!r}", node.start_mark
        )
    return float(text)


def _keys(loader: _Loader, node: yaml.MappingNode, deep: bool = False):
    seen = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise yaml.constructor.ConstructorError(
                None, None, "merge keys (<<) aren't allowed", key_node.start_mark
            )
        if not (isinstance(key_node, yaml.ScalarNode) and key_node.tag == "tag:yaml.org,2002:str"):
            raise yaml.constructor.ConstructorError(
                None, None, "a key must be text", key_node.start_mark
            )
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"the key {key!r} is given twice", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_Loader.add_constructor(_INT, _decimal)
_Loader.add_constructor(_FLOAT, _number)
_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _keys)


def _shape(text: str) -> None:
    """Before the YAML is built: no aliases (a few lines can expand to
    gigabytes) and no deeper nesting than a pack needs."""
    depth = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            raise PackError(
                f"line {event.start_mark.line + 1}: aliases (*name) aren't allowed"
                " (quote a value that starts with *)"
            )
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_DEPTH:
                raise PackError(f"line {event.start_mark.line + 1}: nested too deeply")
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1


# What a malformed file can raise from inside PyYAML's constructors (a date
# that doesn't exist, an odd explicit tag) besides YAMLError.
_READ_ERRORS = (yaml.YAMLError, ValueError, TypeError, KeyError, AttributeError, OverflowError)


def load(data: bytes) -> Any:
    """A small YAML file read as this module reads packs (size, aliases,
    depth, repeated keys, YAML 1.2 types); PackError if it can't be."""
    if len(data) > MAX_BYTES:
        raise PackError(f"larger than {MAX_BYTES // 1024} KiB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackError(f"not UTF-8 text ({exc.reason} at byte {exc.start})") from None
    try:
        _shape(text)
        return yaml.load(text, Loader=_Loader)  # noqa: S506 - a SafeLoader subclass
    except _READ_ERRORS as exc:
        raise PackError(_safe(f"not valid YAML: {exc}")) from None


def problems(exc: ValidationError) -> str:
    """A validation error's problems, one per line, at most MAX_PROBLEMS."""
    errors = exc.errors()
    lines = [_problem(e) for e in errors[:MAX_PROBLEMS]]
    if len(errors) > MAX_PROBLEMS:
        lines.append(f"…and {len(errors) - MAX_PROBLEMS} more")
    return "\n".join(lines)


def read(data: bytes) -> Pack:
    """A pack from its file's bytes, checked; PackError says what's wrong.
    (Its signature is checked before this, by whoever trusts it.)"""
    loaded = load(data)
    if not isinstance(loaded, dict):
        raise PackError("a pack is a mapping of fields (format, id, version, …)")
    if "format" not in loaded:
        raise PackError(f"no format field: this version of the tool reads format {FORMAT}")
    if type(loaded["format"]) is not int or loaded["format"] != FORMAT:
        raise PackError(
            _safe(f"format {loaded['format']!r}: this version of the tool reads format {FORMAT}")
        )
    try:
        return Pack.model_validate(loaded)
    except ValidationError as exc:
        raise PackError(problems(exc)) from None


def _safe(text: str) -> str:
    """Text from the file, made safe to print: hidden characters escaped."""
    return "".join(
        f"\\u{ord(c):04x}"
        if unicodedata.category(c) in _HIDING or (unicodedata.category(c) == "Zs" and c != " ")
        else c
        for c in text
    )


def _problem(error: dict) -> str:
    where = ".".join(str(p) for p in error["loc"]) or "the pack"
    return _safe(f"{where}: {error['msg'].removeprefix('Value error, ')}")
