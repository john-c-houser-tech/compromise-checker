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

- *pseudonymize*: people's account names (UID 1000 and up, other UID 0
  accounts, accounts with a home under /home, names from log fields and
  findings that aren't system accounts, and the part after /home/ in any
  path, and the user before @ an address), host names (the host's own and
  the inventory's, whatever their spelling, short and full; names under
  any of the organization's domains, parent domains included; remote names
  in log fields; the host part of user@host), the host's group, email
  addresses, IP
  addresses and SSH key fingerprints become placeholders such as
  USER-2-7f3a (USER, HOST, DOMAIN, GROUP, EMAIL, IP, KEY), made fresh for
  each run with a random tag and never stored (decision 2); `restore`
  turns them back in the answer. A host's short and full names are one
  host. Text on the host already shaped like a placeholder is changed
  first (its hyphens become U+2011), and can't guess the tag anyway, so it
  can't pass for a placeholder or be restored as a person. Loopback and
  unspecified addresses are kept; private and reserved ones are marked.
- *strict*: the kinds of finding, their counts and scores, and the kinds
  of coverage gap (from a fixed list, GAP_KINDS): only the code's own
  words, no host text at all.
- *none*: as built (after the collector's secret masking).

Limits: names a host mentions only in free text (another company's domain
in a log line, a person's name in a comment) are not recognised; an
account whose name is also an ordinary word or path part (ORDINARY_WORDS:
`log`, `git`, `admin`…) is replaced only where it stands as a name (a
whole value, after "account:", "/home/", "user=", "USER=", "user ",
"for ", "by ", "sudo: ", "su: ", "(to ", "owner ", or before "@"), so that
`log` doesn't turn /var/log into a placeholder (hosts and groups named
like ordinary words likewise, in their own name places, and a one-label
domain such as `corp` only at the end of a longer name); and the whitelist's
reasons are sent as written apart from the names above (so they
shouldn't name people).
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import secrets
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from checker.assess import LOG_SOURCES, REACH_ONLY
from checker.checks import BANDS
from checker.report import excerpts, visible
from checker.snapshot import FULL, SECTIONS, Snapshot

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
    "localdomain",
    # Values PAM and sshd put where a remote host goes.
    "notty",
    "unknown",
    "none",
}
# Accounts every installation of some distribution or cloud image has:
# not a person's, whatever their UID, and kept so that "ubuntu 24.04"
# stays readable.
GENERIC_ACCOUNTS = {
    "root",
    "nobody",
    "ubuntu",
    "debian",
    "ec2-user",
    "cloud-user",
    "centos",
    "rocky",
    "almalinux",
    "fedora",
    "opc",
    "admin",
}
# System accounts from distributions' base packages, kept when a log line
# names one but the host's account list didn't come.
SYSTEM_ACCOUNTS = GENERIC_ACCOUNTS | {
    "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp",
    "proxy", "www-data", "backup", "list", "irc", "gnats", "sshd", "messagebus",
    "syslog", "apache", "nginx", "postfix", "mysql", "postgres", "polkitd", "chrony",
    "dbus", "systemd-network", "systemd-resolve", "systemd-timesync", "_apt", "adm",
    "halt", "shutdown", "operator", "ftp", "tss", "dnsmasq", "landscape", "pollinate",
    "fwupd-refresh", "usbmux", "lxd", "uuidd", "tcpdump", "rpc", "rpcuser", "sssd",
    "unbound", "redis", "memcache", "clamav", "named", "bind", "ntp", "avahi",
}  # fmt: skip
# Two-label names whose second label is a public top-level domain: no
# domain of the organization's to derive from them.
COMMON_TLDS = {"com", "org", "net", "gov", "edu", "mil", "int", "io", "info", "biz", "app", "dev"}
# Second-level labels under a country code that are public suffixes too
# (gov.uk, co.nz): never an organization's own domain.
PUBLIC_SECOND_LEVELS = {"co", "com", "gov", "govt", "org", "net", "ac", "edu", "mil", "nhs"}
# Event fields that hold account names, and host names.
ACCOUNT_FIELDS = ("user", "by", "target", "old_user", "members")
HOST_FIELDS = ("host", "client", "relay", "address")
# Values the code writes, never the host: left as they are (by path; a
# whitelist rule's own "check" key is the organization's text and is
# redacted).
SKIP_PATHS = {
    ("redaction",),
    ("assessment", "band"),
    ("findings", "check"),
    ("findings", "variant"),
    ("findings", "band"),
    ("findings", "category"),
    ("findings", "title"),
    ("chains", "chain"),
    ("chains", "title"),
}


def _text(value: Any, limit: int = MAX_EXCERPT) -> str:
    return str(visible(value, limit))


def _number(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


# --- Building ----------------------------------------------------------------------------


def _finding(index: int, finding: dict, events, snapshot, baselines) -> dict[str, Any]:
    suppressed = finding.get("suppressed_by") or {}
    shown = [
        {key: _text(value) for key, value in piece.items() if value}
        for piece in excerpts(finding, events, snapshot, baselines)
    ]
    return {
        "id": f"F-{index + 1}",
        "check": str(finding.get("check")),
        "variant": finding.get("variant"),
        "band": finding.get("band"),
        "category": finding.get("category"),
        "new": bool(finding.get("new")),
        "contribution": _number(finding.get("contribution")),
        "suppressed_by": suppressed.get("rule") if isinstance(suppressed, dict) else None,
        "title": _text(finding.get("title")),
        "from_host": {
            "summary": _text(finding.get("summary")),
            "entities": [_text(e, 200) for e in finding.get("entities") or []],
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
    os_text = " ".join(str(v) for v in (os_.get("id"), os_.get("version_id")) if v)
    kernel = (items.get("kernel") or {}).get("release")
    return {
        "os": _text(os_text, 200) if os_text else None,
        "kernel": _text(kernel, 200) if kernel else None,
    }


def _clip(value: Any) -> Any:
    """Host or organization text inside a structure (a rule's match), each
    string shown and cut as the rest is."""
    if isinstance(value, str):
        return _text(value, 200)
    if isinstance(value, list):
        return [_clip(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _clip(v) for k, v in value.items()}
    return value


def _size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False))


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
    then by band and contribution); past `max_chars` for the whole case the
    rest are listed by check and count only, and the case says it is
    partial."""
    findings = assessment.get("findings") or []
    score = assessment.get("score") or {}
    order = {band: i for i, band in enumerate(BANDS)}
    ranked = sorted(
        range(len(findings)),
        key=lambda i: (
            bool(findings[i].get("suppressed_by")),
            order.get(findings[i].get("band"), len(order)),
            -(_number(findings[i].get("contribution")) or 0),
            i,
        ),
    )
    applied = assessment.get("whitelist") or {}
    used = {str(key).split("/", 1)[-1] for key in (applied.get("matched") or {})}
    rules = [
        {
            "id": _clip(rule.get("id")),
            "layer": _clip(rule.get("layer")),
            "match": _clip(rule.get("match")),
            "reason": _text(rule.get("reason")),
            "expires": _clip(rule.get("expires")),
        }
        for rule in applied.get("rules") or []
        if isinstance(rule, dict) and rule.get("id") in used
    ]
    coverage = assessment.get("coverage") or {}
    case = {
        "case_format": CASE_FORMAT,
        "redaction": "none",
        "host": {"name": _text(host, 200), "group": _clip(group), **_host_facts(snapshot)},
        "assessment": {
            "probability": score.get("probability"),
            "band": score.get("band"),
            "prior": score.get("prior"),
            "prior_source": _clip(score.get("prior_source")),
            "hygiene_and_exposure": score.get("hygiene_and_exposure"),
            "top_contributors": [],
        },
        "findings": [],
        "omitted": None,
        "chains": [
            {
                "chain": chain.get("chain"),
                "title": _text(chain.get("title")),
                "findings": [
                    f"F-{i + 1}" for i in chain.get("findings") or [] if isinstance(i, int)
                ],
                "account": _clip(chain.get("account")),
            }
            for chain in score.get("chains") or []
            if isinstance(chain, dict)
        ],
        "whitelist_rules": rules,
        "from_host": {
            "coverage_gaps": [_text(gap) for gap in coverage.get("gaps") or []],
            "log_reach_days": {
                source: (reach or {}).get("days")
                for source, reach in sorted((coverage.get("log_reach") or {}).items())
            },
            "notes": [_text(note) for note in assessment.get("notes") or []],
        },
    }
    # Room left for findings once everything else is counted, with a margin
    # for the omitted list and the contributors.
    budget = max_chars - _size(case) - 2_000
    omitted: Counter[str] = Counter()
    for i in ranked:
        entry = _finding(i, findings[i], events, snapshot, baselines)
        length = _size(entry) + 2
        if length > budget:
            omitted[entry["check"]] += 1
            continue
        case["findings"].append(entry)
        budget -= length
    if omitted:
        case["omitted"] = {
            "findings": sum(omitted.values()),
            "by_check": dict(sorted(omitted.items())),
        }
    included = {f["id"] for f in case["findings"]}
    for chain in case["chains"]:  # only findings the case holds can be cited
        chain["findings"] = [f for f in chain["findings"] if f in included]
    top = []
    for contributor in score.get("contributors") or []:
        index = contributor.get("finding")
        if isinstance(index, int):
            if f"F-{index + 1}" in included:
                top.append(f"F-{index + 1}")
        elif contributor.get("check"):
            top.append(str(contributor["check"]))  # a chain's bonus: "chain:<name>"
        if len(top) == TOP_CONTRIBUTORS:
            break
    case["assessment"]["top_contributors"] = top
    return case


# --- What to pseudonymize -----------------------------------------------------------------


@dataclass
class Known:
    """The names the redaction looks for (addresses, emails, key
    fingerprints and home directories are found by their shape)."""

    accounts: set[str] = field(default_factory=set)
    system: set[str] = field(default_factory=lambda: set(SYSTEM_ACCOUNTS))
    hosts: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    # One-label domains (corp, lan): matched only as the end of a longer
    # name (db01.corp), never alone, where they are ordinary words.
    suffixes: set[str] = field(default_factory=set)
    groups: set[str] = field(default_factory=set)


def _hostname(value: str) -> str | None:
    """A host name in a log field ("name[address]" too), or None for an
    address, a generic name or something else."""
    name = value.split("[", 1)[0].strip().rstrip(".").lower()
    if not name or name in GENERIC_HOSTNAMES or not re.search(r"[^\W\d_]", name):
        return None
    if not re.fullmatch(r"[\w-]+(?:\.[\w-]+)*", name):
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    return None


def _qualified(name: str) -> bool:
    """A name with a domain: dotted, its last label starting with a letter
    (web01.corp, not ubuntu24.04)."""
    labels = name.split(".")
    return len(labels) >= 2 and re.match(r"[^\W\d_]", labels[-1]) is not None


def _uid(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def known_identifiers(
    host: str,
    snapshot: Snapshot,
    findings: list[dict[str, Any]],
    events: list,
    chains: list[dict[str, Any]] = (),
    inventory: list[tuple[str, str, str, str | None]] = (),
) -> Known:
    """People's accounts and the hosts' names in this assessment.
    `inventory` is (name, address, login user, group) for every host."""
    known = Known()
    section = snapshot.sections.get("accounts")
    items = section.items if section is not None else {}
    for name, item in (items if isinstance(items, dict) else {}).items():
        if not isinstance(name, str) or not name:
            continue
        item = item if isinstance(item, dict) else {}
        uid = _uid(item.get("uid"))
        home = str(item.get("home") or "")
        if name in SYSTEM_ACCOUNTS:  # a service's well-known name, whatever its UID
            known.system.add(name)
        elif uid is None or (uid >= 1000 and uid != 65534) or uid == 0 or home.startswith("/home/"):
            known.accounts.add(name)
        else:
            known.system.add(name)

    def account(value: Any) -> None:
        if not isinstance(value, str):
            return
        for name in re.split(r"[,\s]+", value):
            if name and name not in known.system:
                known.accounts.add(name)

    def hostname(value: Any) -> None:
        if isinstance(value, str) and (name := _hostname(value)):
            known.hosts.add(name)

    def always(value: Any) -> None:
        """The inventory's and the host's own names: whatever their spelling."""
        if isinstance(value, str) and value.strip():
            name = value.strip().rstrip(".").lower()
            try:
                ipaddress.ip_address(name)
            except ValueError:
                generic = GENERIC_HOSTNAMES | GENERIC_ACCOUNTS
                if name not in generic:
                    known.hosts.add(name)
                    # Its short name too: syslog writes it in every line.
                    if _qualified(name) and name.split(".")[0] not in generic:
                        known.hosts.add(name.split(".")[0])

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        for entity in finding.get("entities") or []:
            kind, _, value = str(entity).partition(":")
            if kind == "account":
                account(value)
            elif kind == "host":
                hostname(value)
        for ref in finding.get("evidence") or []:
            index = ref.get("event") if isinstance(ref, dict) else None
            if isinstance(index, int) and 0 <= index < len(events):
                fields = events[index].fields or {}
                for key in ACCOUNT_FIELDS:
                    account(fields.get(key))
                for key in HOST_FIELDS:
                    hostname(fields.get(key))
    for chain in chains or []:
        if isinstance(chain, dict):
            account(chain.get("account"))
    always(host)
    always(snapshot.meta.get("hostname"))
    for row in inventory or []:
        name, address, user, group = (tuple(row) + (None,) * 4)[:4]
        always(name)
        hostname(address)
        account(user)
        if isinstance(group, str) and group:
            known.groups.add(group)
    for name in list(known.hosts):
        if not _qualified(name):
            continue
        labels = name.split(".")
        # Every parent domain that is the organization's: it.example.gov
        # and example.gov, not gov or gov.uk.
        for start in range(1, len(labels) - 1):
            suffix = labels[start:]
            public = len(suffix) == 2 and len(suffix[1]) == 2 and suffix[0] in PUBLIC_SECOND_LEVELS
            if not public:
                known.domains.add(".".join(suffix))
        last = labels[-1]
        if len(labels) == 2 and last not in COMMON_TLDS and len(last) > 2:
            known.suffixes.add(last)
    return known


# --- Pseudonyms ----------------------------------------------------------------------------

ALNUM = r"[^\W_]"  # a letter or digit, in any script
# Anything that could hold an address: hex digits, colons and dots, not
# right after a letter or digit. Each candidate is parsed; see
# Pseudonyms._addresses.
_ADDRESS_RUN = rf"(?<!{ALNUM})(?=[0-9A-Fa-f.]*[:.])[0-9A-Fa-f:.]+"
_IPV4_DASHED = r"(?<!\d)(?<!\d-)\d{1,3}(?:-\d{1,3}){3}(?!\d)(?!-\d)"
# A dotted quad glued to letters (host203.0.113.5); one with a leading
# zero there is a version (0ubuntu0.24.04.4), not an address.
_GLUED_IPV4 = r"(?<=[^\W\d])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)"
_EMAIL = (  # the last label starts with a letter: root@127.0.0.1 is no address
    r"(?<![\w.%+:-])[\w.%+:-]+@[\w-]+(?:\.[\w-]+)*\.[^\W\d_][\w-]*"
)
# A user name before @ and an address (ssh alice@203.0.113.5): the
# address is the next pass's.
_AT_ADDRESS = (
    r"(?<![\w.%+-])(?P<atip_user>[\w.+-]*[^\W\d_][\w.+-]*)"
    r"(?=@(?:\d{1,3}\.\d|\[?[0-9A-Fa-f]{0,4}::?[0-9A-Fa-f]))"
)
# user@machine without a dot after the @ (SSH key comments, prompts).
_AT = (
    r"(?<![\w.%+-])(?P<at_user>[\w.+-]+)@"
    r"(?P<at_host>(?=[\w-]*[^\W\d_])[^\W_][\w-]*)(?![\w-])(?!\.[\w-])"
)
# An SSH key's fingerprint links its owner across requests like a name does.
_KEY = r"SHA256:[A-Za-z0-9+/]{43}=?(?![A-Za-z0-9+/=])"
# The part of a path that is an account's name.
_HOME = (
    r"(?:(?<=/home/)|(?<=/var/mail/)|(?<=/var/spool/mail/)|(?<=/var/spool/cron/)"
    r"|(?<=/var/spool/cron/crontabs/))(?P<home>[^/\s\"'`()\[\]:,;=]+)"
)
# Where an account name stands as a name: an account whose name is also an
# ordinary word is replaced only here.
_NAME_PLACES = (
    "(?:(?<=account:)|(?<=/home/)|(?<=user=)|(?<=USER=)|(?<=user )|(?<=for )|(?<=by )"
    "|(?<=sudo: )|(?<=su: )|(?<=\\(to )|(?<=owner ))"
)
# Where a host name stands as a name: a host whose name is also an
# ordinary word is replaced only here.
_HOST_PLACES = (
    "(?:(?<=host=)|(?<=rhost=)|(?<=from )|(?<=on )|(?<=to )|(?<=host )|(?<=@)|(?<=hostname ))"
)
MAX_ADDRESS = 45  # characters in the longest written IPv6 address
# Placeholders made in one pass are sealed (one private-use character
# each, which host text never holds: it is shown escaped) so that a later
# pass can't take part of one for an address or a name.
SEAL_BASE = 0xF0000
# Directories of the spools above that are no account's.
SPOOL_DIRS = {"atjobs", "atspool", "crontabs", "lpd"}
# Account names that are also ordinary words or path parts: replaced only
# where they stand as a name, so that `log` doesn't wreck /var/log.
ORDINARY_WORDS = {
    "a", "an", "as", "at", "be", "by", "do", "go", "id", "if", "in", "ip", "is", "it",
    "me", "my", "no", "of", "ok", "on", "or", "so", "to", "up", "us", "we", "sh", "su",
    "all", "and", "any", "api", "app", "are", "bin", "box", "but", "can", "dev", "did",
    "end", "etc", "for", "get", "git", "has", "her", "him", "his", "how", "its", "key",
    "let", "lib", "log", "man", "may", "new", "not", "now", "off", "old", "one", "opt",
    "our", "out", "own", "pid", "pts", "put", "ran", "run", "see", "set", "she", "srv",
    "ssh", "sys", "tcp", "the", "tmp", "too", "top", "try", "tty", "two", "udp", "use",
    "usr", "var", "was", "way", "web", "who", "why", "yes", "yet", "you", "boot", "data",
    "user", "test", "deploy", "backup", "mail", "home", "root", "admin", "guest", "build",
    "proxy", "share", "local", "cache", "spool", "service", "system", "www",
}  # fmt: skip
TOKEN_KINDS = ("HOST", "DOMAIN", "GROUP", "USER", "EMAIL", "IP", "KEY")
# Anything shaped like a placeholder, tagged or not: host text like this is
# defanged before redaction, so it can't pass for one.
TOKEN_SHAPED = re.compile(
    rf"(?<![A-Z])({'|'.join(TOKEN_KINDS)})-(\d+)(?:-([0-9a-z]+))?(?![0-9a-z])"
)
NB_HYPHEN = chr(0x2011)
CUT = "…"


def _forms(names: set[str]) -> list[str]:
    """Each name as collected and as shown (escaped), longest first, so the
    longer of two overlapping names wins."""
    forms = {form for name in names for form in (name, str(visible(name, 10_000)))}
    return sorted(forms, key=lambda f: (-len(f), f))


def _alternation(names: set[str]) -> str:
    return "|".join(re.escape(n) for n in _forms(names))


def _parse(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An address, also with leading zeros in IPv4 (203.000.113.009), and
    an IPv4-mapped IPv6 address as its IPv4 address."""
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        parts = [int(p) for p in text.split(".")]
        return ipaddress.IPv4Address(".".join(map(str, parts))) if max(parts) <= 255 else None
    if ":" not in text:
        return None
    try:
        address = ipaddress.IPv6Address(text)
    except ValueError:
        return None
    return address.ipv4_mapped or address


def new_tag() -> str:
    return secrets.token_hex(2)


class Pseudonyms:
    """One run's placeholders, like USER-2-7f3a: the same name always gets
    the same one within the run; a new run starts again, with a new random
    tag (decision 2), which text planted on a host can't guess, so it can't
    pass for a placeholder or be restored as a person."""

    def __init__(self, known: Known, tag: str | None = None) -> None:
        self.tag = tag if tag is not None else new_tag()
        self.originals: dict[str, str] = {}
        self.address_kinds: dict[str, str] = {}
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: Counter[str] = Counter()
        self._system = set(known.system)
        self._sealed: list[str] = []
        self._domains = {d.lower() for d in known.domains if d}
        self._groups = {g for g in known.groups if g}
        self._hosts = {h.lower() for h in known.hosts if h}
        accounts = {a for a in known.accounts if a}
        # Every spelling of an account (as collected, as shown, lowercased).
        self._accounts: dict[str, str] = {}
        for name in accounts:
            for form in (name, str(visible(name, 10_000))):
                self._accounts[form] = name
                self._accounts.setdefault(form.lower(), name)
        anywhere = {n for n in accounts if n.lower() not in ORDINARY_WORDS}
        placed = accounts - anywhere
        self._placed = {form for n in placed for form in (n, str(visible(n, 10_000)))}
        self._identifiers = {n.lower() for n in accounts} | self._hosts | self._domains
        ordinary = ORDINARY_WORDS | GENERIC_ACCOUNTS
        hosts_anywhere = {h for h in self._hosts if h not in ordinary}
        hosts_placed = self._hosts - hosts_anywhere
        self._hosts_placed = hosts_placed
        names = []
        alternatives = []
        if self._domains:
            alternatives.append(f"(?:[\\w-]+\\.)*(?:{_alternation(self._domains)})")
        suffixes = {x.lower() for x in known.suffixes if x}
        if suffixes:
            alternatives.append(f"(?:[\\w-]+\\.)+(?:{_alternation(suffixes)})")
        if hosts_anywhere:
            alternatives.append(f"(?:{_alternation(hosts_anywhere)})(?:\\.[\\w-]+)*")
        if alternatives:
            joined = "|".join(alternatives)
            names.append(f"(?P<host>(?i:(?<!{ALNUM})(?:{joined})(?!{ALNUM})))")
        if hosts_placed:
            names.append(
                f"(?P<hostplaced>(?i:{_HOST_PLACES}(?:{_alternation(hosts_placed)})(?!{ALNUM})))"
            )
        names.append(_HOME)
        if anywhere:
            names.append(f"(?P<user>(?i:(?<!{ALNUM})(?:{_alternation(anywhere)})(?!{ALNUM})))")
        if placed:
            alternation = _alternation(placed)
            names.append(
                f"(?P<placed>{_NAME_PLACES}(?:{alternation})(?!{ALNUM})"
                f"|(?<!{ALNUM})(?:{alternation})(?=@)|(?<=sudo: )(?:{alternation}))"
            )
        groups_anywhere = {g for g in self._groups if g.lower() not in ordinary}
        groups_placed = self._groups - groups_anywhere
        if groups_anywhere:
            names.append(f"(?P<group>(?<!{ALNUM})(?:{_alternation(groups_anywhere)})(?!{ALNUM}))")
        if groups_placed:
            names.append(
                "(?P<groupplaced>(?:(?<=group )|(?<=group=))"
                f"(?:{_alternation(groups_placed)})(?!{ALNUM}))"
            )
        # Three passes, each over what the one before left: fingerprints and
        # email addresses whole; then addresses; then names, so that a run
        # of hex digits that was no address can't hide a name (abba, dc01).
        self._shapes = re.compile(
            f"(?P<key>{_KEY})|(?P<email>{_EMAIL})|(?P<at>{_AT})|(?P<atip>{_AT_ADDRESS})"
        )
        self._address_pattern = re.compile(
            f"(?P<addr>{_ADDRESS_RUN})|(?P<ip4d>{_IPV4_DASHED})|(?P<glued>{_GLUED_IPV4})"
        )
        self._names = re.compile("|".join(names)) if names else None
        self._token_pattern = re.compile(
            rf"(?<![A-Z])(?:{'|'.join(TOKEN_KINDS)})-\d+-{re.escape(self.tag)}(?![0-9a-z])"
        )

    def _token(self, kind: str, original: str, key: str | None = None) -> str:
        """The placeholder, sealed until the passes are done."""
        return self._seal(self._raw_token(kind, original, key))

    def _raw_token(self, kind: str, original: str, key: str | None = None) -> str:
        key = key if key is not None else original
        token = self._tokens.get((kind, key))
        if token is None:
            self._counts[kind] += 1
            token = f"{kind}-{self._counts[kind]}-{self.tag}"
            self._tokens[(kind, key)] = token
            self.originals[token] = original
        return token

    def _seal(self, token: str) -> str:
        self._sealed.append(token)
        return chr(SEAL_BASE + len(self._sealed) - 1)

    def _unseal(self, text: str) -> str:
        top = SEAL_BASE + len(self._sealed)
        return "".join(
            self._sealed[ord(c) - SEAL_BASE] if SEAL_BASE <= ord(c) < top else c for c in text
        )

    def _is_token(self, text: str) -> bool:
        return self._token_pattern.fullmatch(text) is not None

    def _user(self, text: str) -> str:
        name = self._accounts.get(text) or self._accounts.get(text.lower()) or text
        return self._token("USER", name)

    def _canonical(self, lowered: str) -> str:
        """The one name a host goes by: a full name as itself; a short name,
        or another full name with the same first label (prod-db.localdomain),
        as the only known full name starting with it."""
        if lowered in self._hosts and "." in lowered:
            return lowered
        first = lowered.split(".")[0]
        full = [h for h in self._hosts if "." in h and h.split(".")[0] == first]
        if len(full) == 1:
            return full[0]
        if lowered in self._hosts or first not in self._hosts:
            return lowered
        return first

    def _host(self, text: str) -> str:
        lowered = text.lower()
        if lowered in self._domains:
            return self._token("DOMAIN", text, lowered)
        name = self._canonical(lowered)
        return self._token("HOST", name, name)

    def _address_token(self, address) -> str:
        if address.is_loopback or address.is_unspecified:
            return str(address)
        token = self._raw_token("IP", str(address))
        if address.is_link_local:
            self.address_kinds[token] = "link-local"
        elif not address.is_global:
            self.address_kinds[token] = "private or reserved"
        return self._seal(token)

    def _addresses(self, run: str) -> str:
        """The addresses in a run of hex digits, colons and dots, left to
        right: at each place one can start (the run's start, after a colon
        or dot, or at a digit after a hex letter), the longest piece up to
        MAX_ADDRESS characters that is one, ending at the run's end or
        before a colon or dot. Loopback and unspecified addresses are kept
        as written."""
        ends = [i for i in range(1, len(run)) if run[i] in ":."] + [len(run)]
        out, start, done = [], 0, 0
        while start < len(run):
            can_start = (
                start == 0
                or run[start - 1] in ":."
                or (run[start].isdigit() and run[start - 1].isalpha())
            )
            found = None
            if can_start:
                for end in reversed(ends):
                    if end <= start or end > start + MAX_ADDRESS:
                        continue
                    piece = run[start:end]
                    if ":::" in piece or ".." in piece:
                        continue
                    if ":" not in piece and piece.count(".") != 3:
                        continue
                    if (address := _parse(piece)) is not None:
                        found = (end, address)
                        break
            if found is None:
                start += 1
                continue
            end, address = found
            out.append(run[done:start])
            if address.is_loopback or address.is_unspecified:
                out.append(run[start:end])
            else:
                out.append(self._address_token(address))
            start = done = end
        out.append(run[done:])
        return "".join(out)

    def _shape(self, match: re.Match[str]) -> str:
        text = match.group(0)
        if match.lastgroup == "key":
            return self._token("KEY", text)
        if match.lastgroup == "email":
            return self._token("EMAIL", text, text.lower())
        if match.lastgroup == "atip":
            ordinary = text in self._system or text.lower() in ORDINARY_WORDS | GENERIC_ACCOUNTS
            return text if ordinary else self._user(text)
        user, machine = match.group("at_user"), match.group("at_host")
        if user not in self._system and user.lower() not in ORDINARY_WORDS:
            user = self._user(user)
        if machine.lower() not in GENERIC_HOSTNAMES:
            machine = self._host(machine)
        return f"{user}@{machine}"

    def _address(self, match: re.Match[str]) -> str:
        text = match.group(0)
        if match.lastgroup == "addr":
            return self._addresses(text)
        if match.lastgroup == "glued" and re.search(r"(?:^|\.)0\d", text):
            return text  # a version, not an address
        address = _parse(text.replace("-", "."))
        if address is None or address.is_loopback or address.is_unspecified:
            return text
        return self._address_token(address)

    def _name(self, match: re.Match[str]) -> str:
        text = match.group(0)
        if self._is_token(text):
            return text
        if match.lastgroup in ("host", "hostplaced"):
            return self._host(text)
        if match.lastgroup == "home":
            if text in self._system or text in SPOOL_DIRS or self._is_token(text):
                return text
            return self._user(text)
        if match.lastgroup in ("user", "placed"):
            return self._user(text)
        return self._token("GROUP", text)  # group, groupplaced

    def _cut_tail(self, text: str) -> str:
        """A value cut short may end in part of a name ("js…"): that part
        goes too."""
        if not text.endswith(CUT):
            return text
        offset = max(0, len(text) - 200)
        match = re.search(r"(\w[\w.:-]+)" + CUT + "$", text[offset:])
        if not match or self._is_token(match.group(1)):
            return text
        part = match.group(1).lower()
        if any(name.startswith(part) for name in self._identifiers) or re.fullmatch(
            r"[0-9a-f:.]+", part
        ):
            return text[: offset + match.start(1)] + "[cut]" + CUT
        return text

    def apply(self, text: str) -> str:
        text = TOKEN_SHAPED.sub(lambda m: m.group(0).replace("-", NB_HYPHEN), text)
        if text in self._placed or text in self._accounts:
            return self._unseal(self._user(text))
        if text in self._groups:
            return self._unseal(self._token("GROUP", text))
        if text.lower() in self._hosts_placed:
            return self._unseal(self._host(text))
        text = self._shapes.sub(self._shape, text)
        text = self._address_pattern.sub(self._address, text)
        if self._names is not None:
            text = self._names.sub(self._name, text)
        return self._unseal(self._cut_tail(text))

    def restore(self, text: str) -> str:
        """The answer with each of this run's placeholders turned back into
        its name; a placeholder-shaped string this run never made is left
        visible, never guessed."""

        def back(match: re.Match[str]) -> str:
            original = self.originals.get(match.group(0))
            return original if original is not None else f"[unknown {match.group(0)}]"

        return TOKEN_SHAPED.sub(back, text)


def _walk(value: Any, apply, path: tuple[str, ...] = ()) -> Any:
    if isinstance(value, str):
        return value if path in SKIP_PATHS else apply(value)
    if isinstance(value, list):
        return [_walk(v, apply, path) for v in value]
    if isinstance(value, dict):
        return {k: _walk(v, apply, (*path, k)) for k, v in value.items()}
    return value


# The kinds of coverage gap, as strict mode sends them: fixed words, with
# at most a module or section name this tool defines (a name in a gap comes
# from the bundle, which the host wrote, so any other is "another").
KNOWN_NAMES = (
    frozenset(FULL)
    | frozenset(SECTIONS)
    | frozenset(LOG_SOURCES)
    | frozenset(REACH_ONLY)
    | {"boots", "web_logs", "mail_log", "containers"}
)
GAP_KINDS: list[tuple[str, str]] = [
    (r"the bundle is ", "the bundle is not complete"),
    (r"not collected: ", "modules not collected"),
    (r"module ([a-z_]+): ", "a module did not finish: {}"),
    (r"([a-z_]+) .*: cut short", "a source was cut short: {}"),
    (r"error in ([a-z_]+)", "an error in a module: {}"),
    (r"([a-z_]+) incomplete", "a section is incomplete: {}"),
    (r"no authentication log events", "no authentication log events"),
    (r"no system journal events", "no system journal events"),
    (r"no boot list", "no boot list or boot records"),
    (r"containers not inventoried", "containers not inventoried"),
    (r"\d+ running container", "running containers no state file described"),
    (r"mail logs not collected", "mail logs not collected"),
    (r"the host's clock is ", "the host's clock is off"),
    (r"the host's time zone is unknown", "the host's time zone is unknown"),
    (r"this tool's own SSH login was not recognised", "this tool's own login not recognised"),
    (r"web access logs not collected", "web access logs not collected"),
    (r"no audit log", "no audit log"),
    (r"no program starts in the audit log", "no program starts in the audit log"),
    (r"web log format not recognised", "a web log format not recognised"),
    (r"login hours not judged", "login hours not judged for some accounts (too little history)"),
]


def gap_kind(gap: str) -> str:
    for pattern, kind in GAP_KINDS:
        if match := re.match(pattern, gap):
            names = [n if n in KNOWN_NAMES else "another" for n in match.groups()]
            return kind.format(*names)
    return "another gap"


def strict_view(case: dict[str, Any]) -> dict[str, Any]:
    """Only the kinds of finding, their counts and scores, and the kinds of
    coverage gap: no names, entities, excerpts, summaries or rule text."""
    assessment = case.get("assessment") or {}
    return {
        "case_format": case.get("case_format"),
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
            for f in case.get("findings") or []
        ],
        "omitted": case.get("omitted"),
        "chains": [
            {"chain": c.get("chain"), "findings": c.get("findings")}
            for c in case.get("chains") or []
        ],
        "coverage_gaps": sorted(
            {gap_kind(str(g)) for g in (case.get("from_host") or {}).get("coverage_gaps") or []}
        ),
    }


def redact(
    case: dict[str, Any], mode: str, known: Known, tag: str | None = None
) -> tuple[dict[str, Any], Pseudonyms | None]:
    """The case as it may leave, under the redaction mode, and the run's
    placeholders (None under *none*: nothing to restore). `tag` fixes the
    placeholders' tag (golden tests); otherwise it is random."""
    if not isinstance(case, dict):
        raise ValueError("not a case file")
    if mode == "none":
        return copy.deepcopy(case), None
    if mode not in ("pseudonymize", "strict"):
        raise ValueError(f"unknown redaction mode {mode!r}")
    pseudonyms = Pseudonyms(known if known is not None else Known(), tag)
    if mode == "strict":
        # Nothing in it is host text: only the code's own words and numbers.
        return strict_view(case), pseudonyms
    redacted = _walk(case, pseudonyms.apply)
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
) -> tuple[dict[str, Any], Known, dict[str, Any]]:
    """The case for a host's latest (or a given) bundle, from the same
    current assessment the report shows (analysed or reassessed first if
    the checks, whitelist or prior changed), its names to redact, and
    which assessment it is (bundle, when assessed, band)."""
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
        [(h.name, h.address, h.user, h.group) for h in inventory.hosts],
    )
    which = {
        "bundle_id": report.row["id"],
        "assessed_at": report.assessment.get("analysed_at"),
        "band": (report.assessment.get("score") or {}).get("band"),
        "group": entry.group if entry else None,
        "report": report,  # the real findings, events and chains, for proposals
    }
    return built, known, which
