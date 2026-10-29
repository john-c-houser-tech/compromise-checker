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
  path), host names (the host's own and the inventory's, whatever their
  spelling, names under the host's domain, remote names in log fields,
  the host part of user@host), the host's group, email addresses, IP
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
`log` doesn't turn /var/log into a placeholder; and the whitelist's
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
COMMON_TLDS = {"com", "org", "net", "gov", "edu", "mil", "int", "io", "us", "uk", "de", "info"}
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
    return {
        "os": " ".join(str(v) for v in (os_.get("id"), os_.get("version_id")) if v) or None,
        "kernel": (items.get("kernel") or {}).get("release"),
    }


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
            "id": rule.get("id"),
            "layer": rule.get("layer"),
            "match": rule.get("match"),
            "reason": _text(rule.get("reason")),
            "expires": rule.get("expires"),
        }
        for rule in applied.get("rules") or []
        if isinstance(rule, dict) and rule.get("id") in used
    ]
    coverage = assessment.get("coverage") or {}
    case = {
        "case_format": CASE_FORMAT,
        "redaction": "none",
        "host": {"name": host, "group": group, **_host_facts(snapshot)},
        "assessment": {
            "probability": score.get("probability"),
            "band": score.get("band"),
            "prior": score.get("prior"),
            "prior_source": score.get("prior_source"),
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
                "account": chain.get("account"),
            }
            for chain in score.get("chains") or []
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
    for name, item in (section.items if section else {}).items():
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
                if name not in GENERIC_HOSTNAMES:
                    known.hosts.add(name)
                    # Its short name too: syslog writes it in every line.
                    if _qualified(name) and name.split(".")[0] not in GENERIC_HOSTNAMES:
                        known.hosts.add(name.split(".")[0])

    for finding in findings:
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
    for chain in chains:
        account(chain.get("account"))
    always(host)
    always(snapshot.meta.get("hostname"))
    for name, address, user, group in inventory:
        always(name)
        hostname(address)
        account(user)
        if group:
            known.groups.add(group)
    for name in list(known.hosts):
        if not _qualified(name):
            continue
        labels = name.split(".")
        if len(labels) >= 3:
            known.domains.add(".".join(labels[1:]))
        elif len(labels) == 2 and labels[1] not in COMMON_TLDS:
            known.domains.add(labels[1])
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
TOKEN_SHAPED = re.compile(rf"(?<![A-Z])({'|'.join(TOKEN_KINDS)})-(\d+)(?:-([0-9a-z]+))?\b")
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
        self._domains = {d.lower() for d in known.domains}
        self._groups = set(known.groups)
        # Each host's first label, so that a host's short name and its
        # longer names (prod-db, prod-db.localdomain) are one host.
        self._host_key = {h.lower(): h.lower().split(".")[0] for h in known.hosts}
        # Every spelling of an account (as collected, as shown, lowercased).
        self._accounts: dict[str, str] = {}
        for name in known.accounts:
            for form in (name, str(visible(name, 10_000))):
                self._accounts[form] = name
                self._accounts.setdefault(form.lower(), name)
        anywhere = {n for n in known.accounts if n.lower() not in ORDINARY_WORDS}
        placed = known.accounts - anywhere
        self._placed = {form for n in placed for form in (n, str(visible(n, 10_000)))}
        self._identifiers = {n.lower() for n in known.accounts | known.hosts | known.domains}
        names = []
        if known.hosts or known.domains:
            hosts = "|".join(
                p
                for p in (
                    f"(?:[\\w-]+\\.)*(?:{_alternation(known.domains)})" if known.domains else "",
                    f"(?:{_alternation(known.hosts)})(?:\\.[\\w-]+)*" if known.hosts else "",
                )
                if p
            )
            names.append(f"(?P<host>(?i:(?<!{ALNUM})(?<!\\.)(?:{hosts})(?!{ALNUM})))")
        names.append(_HOME)
        if anywhere:
            names.append(f"(?P<user>(?i:(?<!{ALNUM})(?:{_alternation(anywhere)})(?!{ALNUM})))")
        if placed:
            alternation = _alternation(placed)
            names.append(
                f"(?P<placed>{_NAME_PLACES}(?:{alternation})(?!{ALNUM})"
                f"|(?<!{ALNUM})(?:{alternation})(?=@)|(?<=sudo: )(?:{alternation}))"
            )
        if known.groups:
            names.append(f"(?P<group>(?<=group )(?:{_alternation(known.groups)})(?!{ALNUM}))")
        # Three passes, each over what the one before left: fingerprints and
        # email addresses whole; then addresses; then names, so that a run
        # of hex digits that was no address can't hide a name (abba, dc01).
        self._shapes = re.compile(f"(?P<key>{_KEY})|(?P<email>{_EMAIL})|(?P<at>{_AT})")
        self._address_pattern = re.compile(
            f"(?P<addr>{_ADDRESS_RUN})|(?P<ip4d>{_IPV4_DASHED})|(?P<glued>{_GLUED_IPV4})"
        )
        self._names = re.compile("|".join(names)) if names else None
        self._token_pattern = re.compile(
            rf"(?<![A-Z])(?:{'|'.join(TOKEN_KINDS)})-\d+-{re.escape(self.tag)}\b"
        )

    def _token(self, kind: str, original: str, key: str | None = None) -> str:
        key = key if key is not None else original
        token = self._tokens.get((kind, key))
        if token is None:
            self._counts[kind] += 1
            token = f"{kind}-{self._counts[kind]}-{self.tag}"
            self._tokens[(kind, key)] = token
            self.originals[token] = original
        return token

    def _is_token(self, text: str) -> bool:
        return self._token_pattern.fullmatch(text) is not None

    def _user(self, text: str) -> str:
        name = self._accounts.get(text) or self._accounts.get(text.lower()) or text
        return self._token("USER", name)

    def _host(self, text: str) -> str:
        lowered = text.lower()
        if lowered in self._domains:
            return self._token("DOMAIN", text, lowered)
        first = lowered.split(".")[0]
        known = next((k for k, v in self._host_key.items() if v == first), None)
        return self._token("HOST", known or lowered, first if known else lowered)

    def _address_token(self, address) -> str:
        if address.is_loopback or address.is_unspecified:
            return str(address)
        token = self._token("IP", str(address))
        if address.is_link_local:
            self.address_kinds[token] = "link-local"
        elif not address.is_global:
            self.address_kinds[token] = "private or reserved"
        return token

    def _addresses(self, run: str) -> str:
        """The addresses in a run of hex digits, colons and dots: the
        longest piece of it that is one (starting at the run's start, after
        a colon or dot, or at a digit after a hex letter; ending at its end
        or before a colon or dot), then the same for what is left on either
        side. Loopback and unspecified addresses are kept as written."""
        if len(run) > 100:
            return run
        starts = [0] + [
            i
            for i in range(1, len(run))
            if run[i - 1] in ":." or (run[i].isdigit() and run[i - 1].isalpha())
        ]
        ends = [len(run)] + [i for i in range(1, len(run)) if run[i] in ":."]
        spans = sorted(
            ((s, e) for s in starts for e in ends if e > s),
            key=lambda span: (span[0] - span[1], span[0]),
        )
        for start, end in spans:
            address = _parse(run[start:end])
            if address is None:
                continue
            middle = (
                run[start:end]
                if address.is_loopback or address.is_unspecified
                else self._address_token(address)
            )
            return self._addresses(run[:start]) + middle + self._addresses(run[end:])
        return run

    def _shape(self, match: re.Match[str]) -> str:
        text = match.group(0)
        if match.lastgroup == "key":
            return self._token("KEY", text)
        if match.lastgroup == "email":
            return self._token("EMAIL", text, text.lower())
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
        if match.lastgroup == "host":
            return self._host(text)
        if match.lastgroup == "home":
            if text in self._system or text in SPOOL_DIRS or self._is_token(text):
                return text
            return self._user(text)
        if match.lastgroup in ("user", "placed"):
            return self._user(text)
        return self._token("GROUP", text)

    def _cut_tail(self, text: str) -> str:
        """A value cut short may end in part of a name ("js…"): that part
        goes too."""
        match = re.search(r"(\w[\w.:-]+)" + CUT + "$", text)
        if not match or self._is_token(match.group(1)):
            return text
        part = match.group(1).lower()
        if any(name.startswith(part) for name in self._identifiers) or re.fullmatch(
            r"[0-9a-f:.]+", part
        ):
            return text[: match.start(1)] + "[cut]" + CUT
        return text

    def apply(self, text: str) -> str:
        text = TOKEN_SHAPED.sub(lambda m: m.group(0).replace("-", NB_HYPHEN), text)
        if text in self._placed or text in self._accounts:
            return self._user(text)
        if text in self._groups:
            return self._token("GROUP", text)
        text = self._shapes.sub(self._shape, text)
        text = self._address_pattern.sub(self._address, text)
        if self._names is not None:
            text = self._names.sub(self._name, text)
        return self._cut_tail(text)

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
# at most a module or section name the collector itself defines.
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
]


def gap_kind(gap: str) -> str:
    for pattern, kind in GAP_KINDS:
        if match := re.match(pattern, gap):
            return kind.format(*match.groups())
    return "another gap"


def strict_view(case: dict[str, Any]) -> dict[str, Any]:
    """Only the kinds of finding, their counts and scores, and the kinds of
    coverage gap: no names, entities, excerpts, summaries or rule text."""
    assessment = case["assessment"]
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
            for f in case["findings"]
        ],
        "omitted": case.get("omitted"),
        "chains": [{"chain": c["chain"], "findings": c["findings"]} for c in case["chains"]],
        "coverage_gaps": sorted({gap_kind(g) for g in case["from_host"]["coverage_gaps"]}),
    }


def redact(
    case: dict[str, Any], mode: str, known: Known, tag: str | None = None
) -> tuple[dict[str, Any], Pseudonyms | None]:
    """The case as it may leave, under the redaction mode, and the run's
    placeholders (None under *none*: nothing to restore). `tag` fixes the
    placeholders' tag (golden tests); otherwise it is random."""
    if mode == "none":
        return copy.deepcopy(case), None
    if mode not in ("pseudonymize", "strict"):
        raise ValueError(f"unknown redaction mode {mode!r}")
    pseudonyms = Pseudonyms(known, tag)
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
        [(h.name, h.address, h.user, h.group) for h in inventory.hosts],
    )
    return built, known
