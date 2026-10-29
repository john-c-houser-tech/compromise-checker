"""The advisor's case file (Phase 3 plan, PR 3.1): what the advisor would
see of one assessment, built in one place and redacted in one place. The
client (3.2) sends only what `redact` returns; nothing else in the tool
talks to the provider.

The case is JSON. Everything that came from a server (summaries, entities,
evidence excerpts, coverage gaps) sits under a `from_host` key: the system
prompt says such values are evidence to examine, never instructions, and
JSON's own string escaping means host text can't end its value early. That
text is shown as the report shows it, with control, bidirectional and
invisible characters as escapes like \\u202e.

Redaction (DESIGN.md §3.5, policy §9):

- *pseudonymize*: account names (people's: UID 1000 and up, other UID 0
  accounts, and names from log lines and findings that aren't the host's
  system accounts), host names (the host's own, the inventory's, names
  under the host's domain, remote names in log fields), email addresses
  IP addresses and SSH key fingerprints become HOST-n, USER-n, DOMAIN-n,
  EMAIL-n, IP-n and KEY-n.
  Placeholders are made fresh for each run and never stored (decision 2);
  `restore` turns them back in the answer. Loopback and unspecified
  addresses are kept; private and reserved ones are marked as such.
- *strict*: the kinds of finding, their counts and scores, and coverage
  gaps (pseudonymized); no names, addresses or excerpts.
- *none*: as built (after the collector's secret masking).

Limits: names a host mentions only in free text (another company's domain
in a log line, a person's name in a comment) are not recognised, and the
whitelist's reasons are sent as written apart from the names above.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from checker.checks import BANDS
from checker.report import excerpts, visible
from checker.snapshot import Snapshot

CASE_FORMAT = 1
MAX_CASE_CHARS = 200_000  # about 60 k tokens
MAX_EXCERPT = 1000  # characters of one piece of host text
TOP_CONTRIBUTORS = 10
GENERIC_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "localhost6",
    "localhost6.localdomain6",
    "ip6-localhost",
    "ip6-loopback",
}
# Event fields that hold an account name, and a host name.
ACCOUNT_FIELDS = ("user", "by", "target", "old_user")
HOST_FIELDS = ("host", "client", "relay")
# Values the code writes, never the host: left as they are.
STRUCTURAL = {"check", "variant", "band", "category", "redaction", "chain"}
MIN_ACCOUNT = 2  # one-letter names would match English words


def _text(value: Any, limit: int = MAX_EXCERPT) -> str:
    return str(visible(value, limit))


# --- Building ----------------------------------------------------------------------------


def _finding(index: int, finding: dict, events, snapshot, baselines) -> dict[str, Any]:
    suppressed = finding.get("suppressed_by") or {}
    shown = [
        {key: _text(value) for key, value in piece.items() if value}
        for piece in excerpts(finding, events, snapshot, baselines)
    ]
    return {
        "id": f"F-{index + 1}",
        "check": finding["check"],
        "variant": finding.get("variant"),
        "band": finding["band"],
        "category": finding["category"],
        "new": bool(finding.get("new")),
        "contribution": finding.get("contribution"),
        "suppressed_by": suppressed.get("rule"),
        "title": _text(finding["title"]),
        "from_host": {
            "summary": _text(finding["summary"]),
            "entities": [_text(e, 200) for e in finding.get("entities", [])],
            "entities_complete": finding.get("entities_complete", True),
            "excerpts": shown,
            "uncertain": _text(finding["uncertain"]) if finding.get("uncertain") else None,
            "first_seen": finding.get("first_seen"),
            "last_seen": finding.get("last_seen"),
        },
    }


def _host_facts(snapshot: Snapshot) -> dict[str, Any]:
    section = snapshot.sections.get("host")
    items = section.items if section else {}
    os_ = items.get("os") or {}
    return {
        "os": " ".join(str(v) for v in (os_.get("id"), os_.get("version_id")) if v) or None,
        "kernel": (items.get("kernel") or {}).get("release"),
    }


def build_case(
    host: str,
    assessment: dict[str, Any],
    events: list,
    snapshot: Snapshot,
    baselines: dict[str, Snapshot | None],
    group: str | None = None,
    max_chars: int = MAX_CASE_CHARS,
) -> dict[str, Any]:
    """One assessment as the advisor would see it, before redaction.
    Findings that matter most come first (not suppressed before suppressed,
    then by band and contribution); past `max_chars` the rest are listed by
    check and count only, and the case says it is partial."""
    findings = assessment["findings"]
    score = assessment.get("score") or {}
    order = {band: i for i, band in enumerate(BANDS)}
    ranked = sorted(
        range(len(findings)),
        key=lambda i: (
            bool(findings[i].get("suppressed_by")),
            order.get(findings[i]["band"], len(order)),
            -(findings[i].get("contribution") or 0),
            i,
        ),
    )
    entries, omitted, size = [], Counter(), 0
    for i in ranked:
        entry = _finding(i, findings[i], events, snapshot, baselines)
        length = len(json.dumps(entry, ensure_ascii=False))
        if size + length > max_chars:
            omitted[findings[i]["check"]] += 1
            continue
        entries.append(entry)
        size += length
    applied = assessment.get("whitelist") or {}
    used = {key.split("/", 1)[1] for key in (applied.get("matched") or {})}
    rules = [
        {
            "id": rule["id"],
            "layer": rule.get("layer"),
            "match": rule.get("match"),
            "reason": _text(rule.get("reason")),
            "expires": rule.get("expires"),
        }
        for rule in applied.get("rules") or []
        if rule.get("id") in used
    ]
    coverage = assessment.get("coverage") or {}
    return {
        "case_format": CASE_FORMAT,
        "redaction": "none",
        "host": {"name": host, "group": group, **_host_facts(snapshot)},
        "assessment": {
            "probability": score.get("probability"),
            "band": score.get("band"),
            "prior": score.get("prior"),
            "prior_source": score.get("prior_source"),
            "hygiene_and_exposure": score.get("hygiene_and_exposure"),
            "top_contributors": [
                f"F-{c['finding'] + 1}"
                for c in (score.get("contributors") or [])[:TOP_CONTRIBUTORS]
            ],
        },
        "findings": entries,
        "omitted": {"findings": sum(omitted.values()), "by_check": dict(sorted(omitted.items()))}
        if omitted
        else None,
        "chains": [
            {
                "chain": chain["chain"],
                "title": _text(chain.get("title")),
                "findings": [f"F-{i + 1}" for i in chain.get("findings", [])],
                "account": chain.get("account"),
            }
            for chain in score.get("chains") or []
        ],
        "whitelist_rules": rules,
        "from_host": {
            "coverage_gaps": [_text(gap) for gap in coverage.get("gaps", [])],
            "log_reach_days": {
                source: reach.get("days")
                for source, reach in sorted((coverage.get("log_reach") or {}).items())
            },
            "notes": [_text(note) for note in assessment.get("notes", [])],
        },
    }


# --- What to pseudonymize -----------------------------------------------------------------


@dataclass
class Known:
    """The names the redaction looks for (addresses and emails are found
    by their shape)."""

    accounts: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)


def _hostname(value: str) -> str | None:
    name = value.split("[", 1)[0].strip().rstrip(".").lower()
    if not name or name in GENERIC_HOSTNAMES or not re.search(r"[a-z]", name):
        return None
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", name):
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    return None


def known_identifiers(
    host: str,
    snapshot: Snapshot,
    findings: list[dict[str, Any]],
    events: list,
    chains: list[dict[str, Any]] = (),
    inventory: list[tuple[str, str, str]] = (),
) -> Known:
    """People's accounts and the hosts' names in this assessment.
    `inventory` is (name, address, login user) for every host."""
    known = Known()
    system: set[str] = set()
    section = snapshot.sections.get("accounts")
    for name, item in (section.items if section else {}).items():
        uid = (item or {}).get("uid")
        if isinstance(uid, int) and (uid >= 1000 and uid != 65534 or uid == 0 and name != "root"):
            known.accounts.add(name)
        else:
            system.add(name)

    def account(name: Any) -> None:
        if isinstance(name, str) and name not in system and name != "root":
            if len(name) >= MIN_ACCOUNT:
                known.accounts.add(name)

    def hostname(value: Any) -> None:
        if isinstance(value, str) and (name := _hostname(value)):
            known.hosts.add(name)

    for finding in findings:
        for entity in finding.get("entities", []):
            kind, _, value = entity.partition(":")
            if kind == "account":
                account(value)
        for ref in finding.get("evidence", []):
            index = ref.get("event")
            if isinstance(index, int) and 0 <= index < len(events):
                fields = events[index].fields or {}
                for key in ACCOUNT_FIELDS:
                    account(fields.get(key))
                for key in HOST_FIELDS:
                    hostname(fields.get(key))
    for chain in chains:
        account(chain.get("account"))
    hostname(host)
    hostname(snapshot.meta.get("hostname") or "")
    for name, address, user in inventory:
        hostname(name)
        hostname(address)
        account(user)
    for name in list(known.hosts):
        labels = name.split(".")
        if len(labels) >= 3:
            known.domains.add(".".join(labels[1:]))
    return known


# --- Pseudonyms ----------------------------------------------------------------------------

_IPV4 = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d]|\.\d)"
_IPV4_DASHED = r"(?<!\d)(?<!\d-)\d{1,3}(?:-\d{1,3}){3}(?!\d)(?!-\d)"
_IPV6 = (
    r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{1,4})?(?![\w:.])"
)
_EMAIL = r"(?<![\w.%+:-])[\w.%+:-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
# An SSH key's fingerprint links its owner across requests like a name does.
_KEY = r"SHA256:[A-Za-z0-9+/]{43}=?"
TOKEN = re.compile(r"\b(HOST|DOMAIN|USER|EMAIL|IP|KEY)-(\d+)\b")


def _forms(names: set[str]) -> list[str]:
    """Each name as collected and as shown (escaped), longest first, so the
    longer of two overlapping names wins."""
    forms = {form for name in names for form in (name, str(visible(name, 10_000)))}
    return sorted(forms, key=lambda f: (-len(f), f))


class Pseudonyms:
    """One run's placeholders: the same name always gets the same one
    within the run; a new run starts again (decision 2)."""

    def __init__(self, known: Known) -> None:
        self.originals: dict[str, str] = {}
        self.address_kinds: dict[str, str] = {}
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: Counter[str] = Counter()
        self._domains = {d.lower() for d in known.domains}
        self._accounts = {f: n for n in known.accounts for f in (n, str(visible(n, 10_000)))}
        parts = [f"(?P<key>{_KEY})", f"(?P<email>{_EMAIL})"]
        if known.hosts or known.domains:
            hosts = "|".join(re.escape(h) for h in _forms(known.hosts))
            domains = "|".join(re.escape(d) for d in _forms(known.domains))
            names = "|".join(
                p for p in (f"(?:[A-Za-z0-9-]+\\.)*(?:{domains})" if domains else "", hosts) if p
            )
            parts.append(f"(?P<host>(?i:(?<![\\w.-])(?:{names})(?![\\w-]|\\.[A-Za-z0-9-])))")
        parts += [f"(?P<ip6>{_IPV6})", f"(?P<ip4>{_IPV4})", f"(?P<ip4d>{_IPV4_DASHED})"]
        if self._accounts:
            accounts = "|".join(re.escape(a) for a in _forms(set(self._accounts)))
            parts.append(f"(?P<user>(?<![\\w.-])(?:{accounts})(?![\\w-]))")
        self._pattern = re.compile("|".join(parts))

    def _token(self, kind: str, original: str, key: str | None = None) -> str:
        key = key if key is not None else original
        token = self._tokens.get((kind, key))
        if token is None:
            self._counts[kind] += 1
            token = f"{kind}-{self._counts[kind]}"
            self._tokens[(kind, key)] = token
            self.originals[token] = original
        return token

    def _address(self, text: str) -> str:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return text
        if address.is_loopback or address.is_unspecified:
            return text
        token = self._token("IP", str(address))
        if address.is_link_local:
            self.address_kinds[token] = "link-local"
        elif not address.is_global:
            self.address_kinds[token] = "private or reserved"
        return token

    def _replace(self, match: re.Match[str]) -> str:
        text = match.group(0)
        if match.lastgroup == "key":
            return self._token("KEY", text)
        if match.lastgroup == "email":
            return self._token("EMAIL", text, text.lower())
        if match.lastgroup == "host":
            kind = "DOMAIN" if text.lower() in self._domains else "HOST"
            return self._token(kind, text, text.lower())
        if match.lastgroup in ("ip4", "ip6"):
            return self._address(text)
        if match.lastgroup == "ip4d":
            replaced = self._address(text.replace("-", "."))
            return text if replaced == text.replace("-", ".") else replaced
        return self._token("USER", self._accounts.get(text, text), self._accounts.get(text, text))

    def apply(self, text: str) -> str:
        return self._pattern.sub(self._replace, text)

    def restore(self, text: str) -> str:
        """The answer with each placeholder turned back into its name; one
        this run never made is left visible, never guessed."""

        def back(match: re.Match[str]) -> str:
            original = self.originals.get(match.group(0))
            return original if original is not None else f"[unknown {match.group(0)}]"

        return TOKEN.sub(back, text)


def _walk(value: Any, apply, key: str | None = None) -> Any:
    if isinstance(value, str):
        return value if key in STRUCTURAL else apply(value)
    if isinstance(value, list):
        return [_walk(v, apply, key) for v in value]
    if isinstance(value, dict):
        return {k: _walk(v, apply, k) for k, v in value.items()}
    return value


def strict_view(case: dict[str, Any]) -> dict[str, Any]:
    """Only the kinds of finding, their counts and scores, and coverage
    gaps: no names, entities, excerpts, summaries or rule text."""
    assessment = case["assessment"]
    findings = case["findings"]
    return {
        "case_format": case["case_format"],
        "redaction": "strict",
        "assessment": {
            key: assessment.get(key)
            for key in ("probability", "band", "prior", "hygiene_and_exposure", "top_contributors")
        },
        "findings": [
            {
                "id": f["id"],
                "check": f["check"],
                "variant": f["variant"],
                "band": f["band"],
                "category": f["category"],
                "new": f["new"],
                "contribution": f["contribution"],
                "suppressed": f["suppressed_by"] is not None,
            }
            for f in findings
        ],
        "omitted": case.get("omitted"),
        "chains": [{"chain": c["chain"], "findings": c["findings"]} for c in case["chains"]],
        "from_host": {"coverage_gaps": case["from_host"]["coverage_gaps"]},
    }


def redact(
    case: dict[str, Any], mode: str, known: Known
) -> tuple[dict[str, Any], Pseudonyms | None]:
    """The case as it may leave, under the redaction mode, and the run's
    placeholders (None under *none*: nothing to restore)."""
    if mode == "none":
        return copy.deepcopy(case), None
    if mode not in ("pseudonymize", "strict"):
        raise ValueError(f"unknown redaction mode {mode!r}")
    pseudonyms = Pseudonyms(known)
    source = strict_view(case) if mode == "strict" else case
    redacted = _walk(source, pseudonyms.apply)
    redacted["redaction"] = mode
    if pseudonyms.address_kinds:
        redacted["address_kinds"] = dict(pseudonyms.address_kinds)
    return redacted, pseudonyms


# --- From stored evidence ----------------------------------------------------------------


def case_for_host(
    store,
    host: str,
    identity,
    recipients: list[str],
    inventory,
    prior: tuple[float, str],
    whitelist,
    bundle_id: str | None = None,
) -> tuple[dict[str, Any], Known]:
    """The case for a host's latest (or a given) bundle, from the same
    current assessment the report shows (analysed or reassessed first if
    the checks, whitelist or prior changed)."""
    from checker.report import host_report

    report = host_report(store, host, identity, recipients, bundle_id, prior, whitelist)
    entry = next((h for h in inventory.hosts if h.name == host), None)
    built = build_case(
        host,
        report.assessment,
        report.events,
        report.snapshot,
        report.baselines,
        group=entry.group if entry else None,
    )
    known = known_identifiers(
        host,
        report.snapshot,
        report.assessment["findings"],
        report.events,
        (report.assessment.get("score") or {}).get("chains") or [],
        [(h.name, h.address, h.user) for h in inventory.hosts],
    )
    return built, known
