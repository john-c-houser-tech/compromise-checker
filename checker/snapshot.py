"""A host's state at collection time, from a bundle (DESIGN.md §6), and the
differences between two such snapshots (§7).

A snapshot is a set of sections — accounts, sudo rules, authorized keys,
persistence files, listening sockets… — each a map from a stable key (a
name, a path) to that item's facts. Each section also says whether it is
complete: a module that failed, ran out of time or was cut short, a file it
couldn't read, leaves its section incomplete, and a comparison then never
reports what is merely missing from it as removed."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from checker.protocol import Error, Manifest, Record, SourceEnd, SourceStart, Trailer

SNAPSHOT_VERSION = 11
# 5: network; 6: logging, history flags; 7: software; 8: mail; 9: web; 10: containers;
# 11: the folders web servers serve

# Section: (what it holds, the collector modules it comes from).
SECTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "host": (
        "operating system, kernel, machine id, kernel taint and module policy",
        ("host_facts", "kernel_modules"),
    ),
    "accounts": ("accounts, with their password status", ("accounts",)),
    "groups": ("groups and their members", ("accounts",)),
    "shell_history": ("shell history files (size and times)", ("accounts",)),
    "sudo_rules": ("sudoers lines, per file", ("sudoers",)),
    "sudo_files": ("sudoers files", ("sudoers",)),
    "authorized_keys": ("authorized SSH keys, by fingerprint", ("ssh",)),
    "sshd_config": ("sshd configuration lines, per file and Match block", ("ssh",)),
    "ssh_files": ("sshd configuration files, key files and .ssh directories", ("ssh",)),
    "pam": ("PAM configuration and module files", ("pam",)),
    "pam_rules": ("PAM configuration lines, per file", ("pam",)),
    "cron": ("cron and at files", ("cron",)),
    "systemd": ("systemd units, drop-ins and generators", ("systemd",)),
    "startup": ("start-up scripts and shell start-up files", ("startup",)),
    "hooks": ("package-manager hooks and udev rules", ("hooks",)),
    "crash_dumps": ("crash dumps", ("crash_dumps",)),
    "kernel_modules": ("loaded kernel modules", ("kernel_modules",)),
    "package_changes": ("package files that differ from their package", ("package_verify",)),
    "checksum_store": ("the package managers' own checksum lists", ("package_verify",)),
    "privileged_files": (
        "set-user-ID, set-group-ID, capability and device files, in system directories and"
        " elsewhere",
        ("system_files", "unusual_files"),
    ),
    "unowned_executables": (
        "executables in system directories that no package installed",
        ("system_files",),
    ),
    "unusual_files": ("unusual files in writable and web directories", ("unusual_files",)),
    "web_files": ("executable or script files in web roots", ("unusual_files",)),
    "listeners": ("listening and raw sockets, with their programs", ("processes",)),
    "peers": (
        "outbound connections open at collection, by program and remote network and port",
        ("processes",),
    ),
    "network_files": (
        "resolver, hosts, TCP-wrapper and firewall configuration files",
        ("network",),
    ),
    "interfaces": ("network interfaces: flags, state, bridges", ("network",)),
    "firewall_rules": ("the firewall's loaded rules, line by line", ("network",)),
    "log_config": ("journald, rsyslog, audit and SELinux configuration files", ("logging_state",)),
    "packages": ("installed packages: version, architecture, install time", ("software",)),
    "software_files": ("package repositories (text) and signing keys (hashes)", ("software",)),
    "global_packages": ("Python and Node packages installed system-wide by hand", ("software",)),
    "logging": (
        "SELinux and AppArmor state, journald storage, logging services and security agents"
        " running",
        ("logging_state", "processes"),
    ),
    "mail_files": ("Postfix and Exim configuration files", ("mail",)),
    "web_config": ("nginx, Apache and PHP-FPM configuration files", ("web_logs",)),
    "web_served": (
        "the folders nginx and Apache serve (root, alias, DocumentRoot, Alias), per file",
        ("web_logs",),
    ),
    "containers": (
        "Docker and Podman containers: image, privilege, capabilities, namespaces, devices, mounts",
        ("containers",),
    ),
    "mail_config": (
        "mail server settings: relay host, trusted networks, relay restrictions, services",
        ("mail",),
    ),
}

# Every module the sections come from: a bundle that planned them all is a
# full collection.
FULL = frozenset(m for _, modules in SECTIONS.values() for m in modules)

# Sections holding masked text, hashes of it, or masked names: a new masking
# version can change them without any change on the host.
_MASKED = {
    "software_files",
    "log_config",
    "firewall_rules",
    "network_files",
    "sudo_rules",
    "pam_rules",
    "sshd_config",
    "sudo_files",
    "ssh_files",
    "pam",
    "cron",
    "systemd",
    "startup",
    "hooks",
    "authorized_keys",
    "unusual_files",
    "web_files",
    "listeners",
    "shell_history",
    "mail_files",
    "mail_config",
    "web_config",
    "web_served",
    "containers",
}

# Which section a module's text sources and file records go to.
_FILE_SECTIONS = {
    "sudoers": "sudo_files",
    "ssh": "ssh_files",
    "pam": "pam",
    "cron": "cron",
    "systemd": "systemd",
    "startup": "startup",
    "hooks": "hooks",
    "crash_dumps": "crash_dumps",
    "network": "network_files",
    "logging_state": "log_config",
    "software": "software_files",
    "mail": "mail_files",  # configuration only: mail logs are read for events
    "web_logs": "web_config",  # configuration only: web logs are read for events
}
_FILE_RECORDS = {
    "file",
    "module_file",
    "config_link",
    "home_startup_file",
    "authorized_keys_file",
    "ssh_dir",
    "include_dir",
}
# What changes in the firewall's output without the rules changing:
# counters, quotas used, timeouts running down, last-used times, and a big
# set's elements (a blocklist): left out of the compared lines.
_VOLATILE = (
    (re.compile(r"\bcounter packets \d+ bytes \d+"), "counter"),
    (re.compile(r"\bpackets \d+ bytes \d+"), ""),
    (re.compile(r"\bused \d+ \w+"), ""),
    (re.compile(r"\bexpires \S+"), ""),
    (re.compile(r"\blast used \S+(?: ago)?"), ""),
    (re.compile(r"\[\d+:\d+\]"), ""),
    (re.compile(r"\[\d+ elements, sha256 [0-9a-f]+\]"), "[a large set: elements not compared]"),
)
# Chains other software rewrites all the time (Docker, Kubernetes, CNI
# plugins, fail2ban): one line saying they're there, not their rules.
# DOCKER-USER is where administrators put their own rules: compared.
_MANAGED_CHAIN = re.compile(
    r"^(?!DOCKER-USER$)(?:DOCKER|KUBE-|cali-|CILIUM|f2b-|FLANNEL|CNI-|LIBVIRT_|ts-)",
    re.IGNORECASE,
)
_NFT_TABLE = re.compile(r"^table (\S+ \S+) \{$")
_NFT_CHAIN = re.compile(r"^(chain|set|map|flowtable|counter|quota) (\S+) \{$")


def firewall_lines(lines: list[str]) -> list[str]:
    """The loaded rules as comparable lines, each with where it is (an nft
    table and chain or set, an iptables table), so the same rule added to
    another chain is a change; volatile parts, comments and blank lines left
    out, spaces collapsed; a line repeated in one place numbered."""
    out: list[str] = []
    seen: dict[str, int] = {}
    table = block = ""
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        for pattern, replacement in _VOLATILE:
            text = pattern.sub(replacement, text)
        text = " ".join(text.split())
        if match := _NFT_TABLE.match(text):
            table, block = match.group(1), ""
        elif match := _NFT_CHAIN.match(text):
            block = f"{match.group(1)} {match.group(2)}"
        elif text.startswith("*"):  # iptables-save: a table
            table, block = text[1:], ""
        elif text == "}":
            if block:
                block = ""
            else:
                table = ""
            continue
        chain = block.split(" ", 1)[1] if block.startswith("chain ") else ""
        if text.startswith(("-A ", "-I ")):  # iptables-save: the chain is in the line
            chain = text.split()[1]
        if chain and _MANAGED_CHAIN.match(chain):
            text = "(managed by other software: rules not compared)"
        where = " / ".join(p for p in (table, block or (f"chain {chain}" if chain else "")) if p)
        key = f"[{where}] {text}" if where else text
        if text.startswith("(managed") and key in seen:
            continue
        seen[key] = seen.get(key, 0) + 1
        out.append(key if seen[key] == 1 else f"{key} #{seen[key]}")
    return out


def remote_network(address: str) -> str | None:
    """A remote address's network (/24 for IPv4, /48 for IPv6); None for
    loopback, link-local and unspecified addresses."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
        return None
    prefix = 24 if parsed.version == 4 else 48
    return str(ipaddress.ip_network(f"{parsed}/{prefix}", strict=False))


# Packages of which several versions are installed at once.
VERSIONED_PACKAGES = {
    "gpg-pubkey",
    "kernel",
    "kernel-core",
    "kernel-modules",
    "kernel-modules-core",
    "kernel-modules-extra",
    "kernel-devel",
    "kernel-uek",
    "installonlypkg",
}
# A start-up file that switches shell history off for everyone.
HISTORY_OFF = re.compile(
    r"^\s*(?:export\s+|declare\s+-x\s+|readonly\s+)?(?:unset\s+(?:-v\s+)?HISTFILE\b"
    r"|HISTFILE=[\"']?/dev/null[\"']?(?:\s|;|$)|HISTSIZE=[\"']?0[\"']?(?:\s|;|$)"
    r"|HISTFILESIZE=[\"']?0[\"']?(?:\s|;|$)|set\s+\+o\s+history\b)"
)
# Files a shell reads at start: only these can switch history off for users.
SHELL_STARTUP = re.compile(
    r"^/etc/(?:profile|profile\.d/.*|bash\.bashrc|bashrc|zsh/.*|zshrc|zprofile|environment)$"
)
LOGGING_SERVICES = {"auditd", "rsyslogd", "systemd-journald", "syslog-ng", "journald"}
SECURITY_AGENTS = {
    "fail2ban-server",
    "wazuh-agentd",
    "wazuh-modulesd",
    "ossec-agentd",
    "osqueryd",
    "falcon-sensor",
    "auditbeat",
    "crowdsec",
    "clamd",
    "ds_agent",
    "wdavdaemon",
    "s1-agent",
    "elastic-agent",
}
_INTERPRETER = re.compile(r"^(?:python[\d.]*|perl[\d.]*|ruby[\d.]*|node|bash|sh)$")


def _runs(process: dict[str, Any]) -> tuple[str, str]:
    """(name, path) of the file a process runs; for an interpreter, its
    script."""
    exe = str(process.get("exe") or "").removesuffix(" (deleted)")
    name = exe.rsplit("/", 1)[-1]
    if _INTERPRETER.match(name):
        args = str(process.get("cmdline") or "").split()
        script = next((a for a in args[1:] if not a.startswith("-")), "")
        if script.startswith("/"):
            return script.rsplit("/", 1)[-1], script
    return name, exe


_JOURNALD_DIRS = (
    "/etc/systemd/journald.conf.d/",
    "/run/systemd/journald.conf.d/",
    "/usr/lib/systemd/journald.conf.d/",
)


def journald_storage(settings: list[tuple[str, list[str]]]) -> str | None:
    """journald's effective Storage=, as systemd reads it: the main file
    (/etc over /usr/lib), then the *.conf drop-ins of all three folders in
    file-name order, a name in /etc masking it in /run and /usr/lib, and
    /run masking /usr/lib; the last setting wins."""
    by_path = dict(settings)
    main = next(
        (
            by_path[p]
            for p in ("/etc/systemd/journald.conf", "/usr/lib/systemd/journald.conf")
            if p in by_path
        ),
        [],
    )
    dropins: dict[str, list[str]] = {}
    for folder in reversed(_JOURNALD_DIRS):  # /usr/lib first, /etc last: it masks
        for path, lines in settings:
            name = path[len(folder) :]
            if path.startswith(folder) and name.endswith(".conf") and "/" not in name:
                dropins[name] = lines
    storage = None
    for lines in [main] + [dropins[n] for n in sorted(dropins)]:
        for line in lines:
            text = line.split("#", 1)[0].strip()
            if text.startswith("Storage="):
                storage = text.split("=", 1)[1].strip()
    return storage


# Records that mean some of a module's data is missing.
_GAPS = {
    "packages_pending",
    "malformed_header",
    "unreadable_file",
    "listing_truncated",
    "phase_time_limit",
    "incomplete_file",
    "not_examined",
    "directives_incomplete",
}


def _gap_sections(module: str, name: str, data: dict[str, Any]) -> set[str] | None:
    """The sections a gap leaves incomplete, where a module feeds several,
    judged by what kind of record reported it; None: all of them (a gap
    in the module as a whole: an error, a summary cut short)."""
    if not name:
        return None
    path = data.get("path")
    if module == "accounts":
        if path not in ("/etc/passwd", "/etc/shadow", "/etc/group"):
            return {"shell_history"}  # home directories: only history comes from them
        return {"groups"} if path == "/etc/group" else {"accounts"}
    if module == "ssh":
        # Key files are reported with their account (or found through the
        # homes); everything else is sshd's own configuration.
        if name in ("homes", "authorized_keys_file") or "account" in data or "home" in data:
            return {"authorized_keys", "ssh_files"}
        return {"sshd_config", "ssh_files"}
    if module == "pam":
        # /etc/pam.d and pam.conf hold the lines; the module directories
        # (walked, or not examined) hold the module files.
        if name in ("config_dir", "source") or str(path or "").startswith("/etc/"):
            return {"pam_rules", "pam"}
        return {"pam"}
    if module == "web_logs":
        # Only its configuration is a section: logs and audit records are
        # coverage, reported there.
        return {"web_config", "web_served"} if str(path or "").startswith("/etc/") else set()
    if module == "mail" and str(path or "").startswith("/var/log/"):
        return set()  # a mail log: the coverage reports it, the settings are whole
    if module == "unusual_files":
        return {"unusual_files", "web_files", "privileged_files"}
    if module == "system_files":
        return {"privileged_files", "unowned_executables"}
    if module == "software":
        if data.get("section") in ("packages", "software_files", "global_packages"):
            return {data["section"]}
        if name in ("packages_pending", "malformed_header") or path == "/var/lib/dpkg/status":
            return {"packages"}
        return {"software_files"}
    if module == "network":
        if name in ("command_unavailable", "command_failed", "set_unterminated", "source") or (
            name == "not_examined" and path == "nft list ruleset"
        ):
            return {"firewall_rules"}
        if path == "/sys/class/net":
            return {"interfaces"}
        return {"network_files"}
    return None


@dataclass
class Section:
    items: dict[str, dict[str, Any]] = field(default_factory=dict)
    complete: bool = True
    gaps: list[str] = field(default_factory=list)

    def gap(self, why: str) -> None:
        self.complete = False
        if why not in self.gaps and len(self.gaps) < 20:
            self.gaps.append(why)


@dataclass
class Snapshot:
    meta: dict[str, Any]
    sections: dict[str, Section]
    # What was running at collection time (processes, sockets) and the
    # modules' summaries: read by the checks, never compared — it changes
    # by itself between any two runs.
    live: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "sections": {
                name: {"complete": s.complete, "gaps": s.gaps, "items": s.items}
                for name, s in self.sections.items()
            },
            "live": self.live,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Snapshot:
        return cls(
            data["meta"],
            {
                name: Section(s["items"], s["complete"], s["gaps"])
                for name, s in data["sections"].items()
            },
            data.get("live") or {},
        )

    def items(self) -> int:
        return sum(len(s.items) for s in self.sections.values())


def _meta(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k != "path"}


# --- Text the collector sent ---------------------------------------------------------


def _without_comment(line: str) -> str:
    """A sudoers line up to its comment. `#` starts one, except in
    `#include`/`#includedir` and before digits (`#1000` is a user ID), and
    when escaped (`\\#`)."""
    for i, char in enumerate(line):
        if char != "#" or (i and line[i - 1] == "\\"):
            continue
        rest = line[i + 1 :]
        if rest[:1].isdigit() or (not line[:i].strip() and rest.startswith("include")):
            continue
        return line[:i]
    return line


def sudoers_lines(lines: list[str]) -> list[str]:
    """The lines sudo acts on: comments and blank lines dropped (but not
    `#include` or a `#UID` user), continuations joined, spaces collapsed.
    A comment ends at its line's end, backslash or not, as in sudo."""
    out: list[str] = []
    pending = ""
    for raw in lines:
        line = _without_comment(raw).rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line = (pending + line).strip()
        pending = ""
        if line:
            out.append(" ".join(line.split()))
    if pending.strip():
        out.append(" ".join(pending.split()))
    return out


def pam_lines(lines: list[str]) -> list[str]:
    """PAM configuration lines as Linux-PAM reads them: a `#` anywhere
    starts a comment, continuations joined, spaces collapsed."""
    out: list[str] = []
    pending = ""
    for raw in lines:
        line = raw.split("#", 1)[0].rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line = (pending + line).strip()
        pending = ""
        if line:
            out.append(" ".join(line.split()))
    if pending.strip():
        out.append(" ".join(pending.split()))
    return out


_SSHD_LINE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9]*)\s*(?:=\s*|\s+)(?P<value>.*?)\s*$")


def sshd_lines(lines: list[str]) -> list[tuple[str, str, str]]:
    """(Match block or "", keyword in lower case, value) for each sshd
    setting; a Match line opens a block for the rest of the file."""
    out = []
    block = ""
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _SSHD_LINE.match(stripped)
        if not match:
            out.append((block, "?", " ".join(stripped.split())))
            continue
        key, value = match["key"].lower(), " ".join(match["value"].split())
        if key == "match":
            block = "" if value.lower() == "all" else value
        out.append((block, key, value))
    return out


# nginx's root and alias, several to a line or inside a block on one line.
_NGINX_SERVED = re.compile(r"(?:^|[{;\s])(root|alias)\s+(\"[^\"]*\"|'[^']*'|[^\s;{}]+)\s*;")
# Apache's: the folder is the last argument (Alias's first is the URL).
_APACHE_SERVED = re.compile(
    r"^\s*(DocumentRoot|Alias|ScriptAlias|AliasMatch|ScriptAliasMatch)\s+(.*?)\s*$", re.I
)


def web_served(path: str, lines: list[str]) -> list[tuple[str, str]]:
    """(directive, folder as written) for each folder a web server's
    configuration file serves. Folders with a variable, or relative to the
    server's own prefix, are kept as written: the check can't place them."""
    out = []
    nginx = path.startswith("/etc/nginx/")
    if not nginx and not path.startswith(("/etc/apache2/", "/etc/httpd/")):
        return out  # PHP-FPM's: it serves nothing itself
    for raw in lines:
        line = raw.split("#", 1)[0] if nginx else raw
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if nginx:
            found = [(m[1], m[2]) for m in _NGINX_SERVED.finditer(line)]
        else:
            match = _APACHE_SERVED.match(line)
            try:
                args = shlex.split(match[2]) if match else []
            except ValueError:  # an unclosed quote
                args = match[2].split()
            found = [(match[1], args[-1])] if args else []
        out.extend((directive.lower(), folder.strip("\"'")) for directive, folder in found)
    return out


# --- Building one ----------------------------------------------------------------------------


class SnapshotBuilder:
    """A bundle walk consumer (checker.bundle.Consumer) that builds the
    snapshot; `finish` returns it once the walk is done."""

    def __init__(self) -> None:
        self.sections: dict[str, Section] = {}
        self.manifest_data: Manifest | None = None
        self.trailer_data: Trailer | None = None
        self._text: dict[int, tuple[Any, list[str] | None]] = {}
        self._processes: dict[int, str] = {}
        self.live: dict[str, Any] = {"processes": [], "sockets": []}
        self._sockets: list[dict[str, Any]] = []
        self._password: dict[str, dict[str, Any]] = {}
        self._gaps: dict[str, list[tuple[str, set[str] | None]]] = {}
        self._names: dict[str, dict[str, int]] = {}
        self._unread: list[tuple[str, dict[str, Any]]] = []
        self._settings: list[tuple[str, list[str]]] = []  # logging configuration text
        self._mail_text: list[tuple[str, list[str]]] = []  # mail configuration text
        self._mac: dict[str, Any] | None = None

    def section(self, name: str) -> Section:
        return self.sections.setdefault(name, Section())

    def _module_gap(self, module: str, why: str, name: str = "", data: Any = None) -> None:
        self._gaps.setdefault(module, []).append((why, _gap_sections(module, name, data or {})))

    # Consumer interface
    def manifest(self, manifest: Manifest) -> None:
        self.manifest_data = manifest

    def record(self, record: Record) -> None:
        module, name, data = record.module, record.name, record.data
        if name == "unreadable_file" and module in _FILE_SECTIONS and data.get("path"):
            self._unread.append((module, data))  # settled once every file is listed
        elif name in _GAPS:
            where = data.get("path") or data.get("phase") or ""
            self._module_gap(module, f"{name}: {where}", name, data)
        elif name == "walk_summary":
            if data.get("truncated"):
                self._module_gap(module, f"walk of {data.get('top')} cut short", name, data)
            skipped = data.get("not_descended") or {}
            # Walks of writable places cross into other filesystems by design
            # (DESIGN.md §8.6); anywhere else, a mount on top hides what's under it.
            deeper = skipped.get("depth") or 0
            if module != "unusual_files":
                deeper += skipped.get("other_filesystem") or 0
            if deeper:
                why = f"walk of {data.get('top')}: {deeper} directories not entered"
                self._module_gap(module, why, name, data)
        elif name == "homes" and data.get("complete") is False:
            self._module_gap(module, "not every home directory was examined", name, data)
        elif data.get("truncated") is True and name in (
            "authorized_keys_file",
            "include_dir",
            "config_dir",
        ):
            self._module_gap(module, f"{name} cut short: {data.get('path')}", name, data)
        handler = getattr(self, f"_on_{module}", None)
        if handler is not None:
            handler(name, data)
        if module in ("mail", "web_logs") and not str(data.get("path") or "").startswith("/etc/"):
            pass  # logs aren't configuration
        elif module in _FILE_SECTIONS and name in _FILE_RECORDS and data.get("path"):
            item = self.section(_FILE_SECTIONS[module]).items.setdefault(data["path"], {})
            item.update(_meta(data))
            item.setdefault("record", name)
            if data["path"].startswith("/run/"):
                # Remade at every boot (transient units, generators' output):
                # its content, owner and mode matter, not its inode and times.
                for volatile in ("inode", "ctime", "mtime"):
                    item.pop(volatile, None)

    def source_start(self, start: SourceStart) -> None:
        if start.kind == "command" and start.module == "network":
            # The firewall's loaded rules (nft, iptables-legacy-save).
            self._text[start.source_id] = ((start, hashlib.sha256()), [])
            return
        wanted = start.kind == "file" and start.module in _FILE_SECTIONS
        if start.module in ("mail", "web_logs") and not start.name.startswith("/etc/"):
            wanted = False  # a log, read for events
        lines: list[str] | None = (
            []
            if start.module
            in ("sudoers", "ssh", "pam", "startup", "logging_state", "mail", "web_logs")
            else None
        )
        if wanted:
            self._text[start.source_id] = ((start, hashlib.sha256()), lines)

    def line(self, start: SourceStart, line: bytes) -> None:
        held = self._text.get(start.source_id)
        if held is None:
            return
        (_, digest), lines = held
        digest.update(line + b"\n")
        if lines is not None:
            lines.append(line.decode("utf-8", "replace"))

    def source_end(self, start: SourceStart, end: SourceEnd) -> None:
        self._close_text(start, cut=end.truncated)

    def source_cut(self, start: SourceStart) -> None:
        self._close_text(start, cut=True)

    def error(self, error: Error) -> None:
        if error.module:
            self._module_gap(error.module, "error: " + error.message[:200])

    def trailer(self, trailer: Trailer) -> None:
        self.trailer_data = trailer

    # Text sources
    def _close_text(self, start: SourceStart, cut: bool) -> None:
        held = self._text.pop(start.source_id, None)
        if held is None:
            return
        (_, digest), lines = held
        if start.kind == "command":
            program = (start.name.split(" ", 1)[0]).rsplit("/", 1)[-1]
            section = self.section("firewall_rules")
            for text in firewall_lines(lines or []):
                section.items[f"{program}: {text}"] = {"program": program}
            if cut:
                self._module_gap("network", f"{program} output cut short", "source", {})
            return
        section = _FILE_SECTIONS[start.module]
        item = self.section(section).items.setdefault(start.name, {})
        for key, value in (start.meta or {}).items():
            item.setdefault(key, value)
        item["content_sha256"] = digest.hexdigest()
        if cut:
            item["content_cut"] = True
            # A web server's file names its section by path, as its records do.
            where = {"path": start.name} if start.module == "web_logs" else {}
            self._module_gap(start.module, f"{start.name} cut short", "source", where)
        if lines is None:
            return
        if start.module == "startup":
            if SHELL_STARTUP.match(start.name) and any(HISTORY_OFF.search(x) for x in lines):
                item["disables_history"] = True
            return
        if start.module == "logging_state":
            self._settings.append((start.name, lines))
            return
        if start.module == "mail":
            self._mail_text.append((start.name, lines))
            return
        if start.module == "web_logs":
            served = self.section("web_served")
            for directive, folder in web_served(start.name, lines):
                served.items[f"{start.name}: {directive} {folder}"] = {
                    "path": start.name,
                    "directive": directive,
                    "folder": folder,
                }
            return
        if start.module == "sudoers":
            rules = self.section("sudo_rules")
            # Keyed by text: a line moved within its file isn't a change; the
            # same line twice is one rule.
            for text in sudoers_lines(lines):
                rules.items[f"{start.name}: {text}"] = {"path": start.name}
        elif start.module == "pam":
            rules = self.section("pam_rules")
            for text in pam_lines(lines):
                rules.items[f"{start.name}: {text}"] = {"path": start.name}
        else:
            config = self.section("sshd_config")
            for block, key, value in sshd_lines(lines):
                where = f" [Match {block}]" if block else ""
                config.items[f"{start.name}{where}: {key} {value}"] = {
                    "path": start.name,
                    "match": block or None,
                    "keyword": key,
                    "value": value,
                }

    # Records, by module
    def _on_host_facts(self, name: str, data: dict[str, Any]) -> None:
        host = self.section("host").items
        if name == "os_release":
            host["os"] = {"id": data.get("ID"), "version_id": data.get("VERSION_ID")}
        elif name == "uname":
            host["kernel"] = {"release": data.get("release"), "machine": data.get("machine")}
        elif name == "machine_id":
            host["machine_id"] = {"value": data.get("machine_id")}
        elif name == "kernel_taint":
            host["kernel_taint"] = {"value": data.get("value")}
        elif name == "mandatory_access_control":
            host["mandatory_access_control"] = dict(data)

    def _occurrence(self, kind: str, name: str) -> str:
        """The item key for the nth entry of a name: the system uses the
        first, so it keeps the plain name; later ones (a duplicate name is
        itself suspicious) are `name #2` and so on."""
        seen = self._names.setdefault(kind, {})
        seen[name] = seen.get(name, 0) + 1
        return name if seen[name] == 1 else f"{name} #{seen[name]}"

    def _on_accounts(self, name: str, data: dict[str, Any]) -> None:
        if name == "account" and data.get("name"):
            key = self._occurrence("account", data["name"])
            item = {k: data.get(k) for k in ("uid", "gid", "home", "shell", "password")}
            item.update(self._password.get(key, {}))
            self.section("accounts").items[key] = item
        elif name == "password_status" and data.get("name"):
            key = self._occurrence("password_status", data["name"])
            status = {f"shadow_{k}": v for k, v in data.items() if k not in ("name", "line")}
            self._password[key] = status
            account = self.section("accounts").items.get(key)
            if account is not None:
                account.update(status)
        elif name == "group" and data.get("name"):
            members = sorted(m for m in data.get("members") or [] if m)
            self.section("groups").items[self._occurrence("group", data["name"])] = {
                "gid": data.get("gid"),
                "members": members,
            }
        elif name == "shell_history" and data.get("path"):
            self.section("shell_history").items[data["path"]] = _meta(data)

    def _on_ssh(self, name: str, data: dict[str, Any]) -> None:
        if name == "authorized_key" and data.get("fingerprint"):
            owner = data.get("account") or data.get("home") or "?"
            key = f"{owner} {data['fingerprint']} {data.get('path')}"
            item = {k: v for k, v in data.items() if k != "line"}
            self.section("authorized_keys").items[key] = item

    def _on_sudoers(self, name: str, data: dict[str, Any]) -> None:
        pass  # files and include directories: see _FILE_RECORDS

    def _on_kernel_modules(self, name: str, data: dict[str, Any]) -> None:
        if name == "kernel_module" and data.get("name"):
            item = {k: data.get(k) for k in ("size", "taint", "sys_taint")}
            self.section("kernel_modules").items[data["name"]] = item
        elif name == "module_policy":
            self.section("host").items["module_policy"] = dict(data)

    def _on_package_verify(self, name: str, data: dict[str, Any]) -> None:
        if name in ("package_file_changed", "conffile_changed") and data.get("path"):
            # rpm reports each difference apart (owner, then mode…): one item
            # per file holding all of them, in `results`.
            item = self.section("package_changes").items.setdefault(
                data["path"], {"configuration": name == "conffile_changed", "results": []}
            )
            for key, value in _meta(data).items():
                if key != "result":
                    item.setdefault(key, value)
            if data.get("result") not in item["results"]:
                item["results"].append(data.get("result"))
                item["results"].sort(key=str)
        elif name == "checksum_store" and data.get("path"):
            self.section("checksum_store").items[data["path"]] = _meta(data)
        elif name == "package_verify_summary":
            self.section("package_changes")
            if data.get("complete") is False:
                self._module_gap("package_verify", "not every package's files were checked")

    def _on_system_files(self, name: str, data: dict[str, Any]) -> None:
        if name == "privileged_file" and data.get("path"):
            self.section("privileged_files").items[data["path"]] = _meta(data)
        elif name == "unowned_executable" and data.get("path"):
            self.section("unowned_executables").items[data["path"]] = _meta(data)
        elif name == "system_files_summary":
            self.live["system_files_summary"] = data
        if name == "system_files_summary" and data.get("truncated"):
            self._module_gap("system_files", f"cut short: {data.get('truncated_reason')}")

    def _on_unusual_files(self, name: str, data: dict[str, Any]) -> None:
        sections = {
            "unusual_file": "unusual_files",
            "web_file": "web_files",
            "privileged_file": "privileged_files",
        }
        if name in sections and data.get("path"):
            item = _meta(data)
            if name == "privileged_file":
                # Found outside the system directories; a file right in /
                # comes without a place.
                item.setdefault("place", "/")
            self.section(sections[name]).items[data["path"]] = item

    def _on_software(self, name: str, data: dict[str, Any]) -> None:
        if name == "package" and data.get("name"):
            key = f"{data['name']} {data.get('arch') or ''}".strip()
            if data["name"] in VERSIONED_PACKAGES:
                # Several at once: rpm's imported keys (each a gpg-pubkey,
                # no architecture), kernels installed side by side.
                key = f"{key} {data.get('version')}"
            self.section("packages").items[key] = {
                k: data.get(k) for k in ("manager", "version", "installed")
            }
        elif name == "signing_key" and data.get("path"):
            self.section("software_files").items[data["path"]] = dict(
                _meta(data), record="signing_key"
            )
        elif name == "global_package" and data.get("name"):
            self.section("global_packages").items[f"{data['kind']}: {data['name']}"] = {
                "version": data.get("version"),
                "where": data.get("where"),
            }

    def _on_logging_state(self, name: str, data: dict[str, Any]) -> None:
        if name == "log_file":
            self.live.setdefault("log_files", []).append(data)
        elif name == "log_manifest" and data.get("truncated"):
            # Not a gap of the compared sections: the listing is live data,
            # and the checks know not to read a missing log as deleted.
            self.live["log_manifest_truncated"] = True
        elif name == "audit_records":
            self.live["audit_records"] = data.get("lines") or []
            if data.get("truncated"):
                self._module_gap("logging_state", "audit records cut short", name, data)
        elif name == "mac_state":
            self._mac = data

    def _logging(self) -> None:
        """The compared state anti-forensics changes: SELinux's mode and
        configured mode, journald's storage, AppArmor's profiles, and which
        logging services and security agents are running (by the file they
        run)."""
        planned = self._planned()
        if "logging_state" not in planned:
            return
        section = self.section("logging")
        mac = self._mac or {}
        configured = None
        for path, lines in self._settings:
            if path == "/etc/selinux/config":
                for line in lines:
                    text = line.split("#", 1)[0].strip()
                    if text.startswith("SELINUX="):
                        configured = text.split("=", 1)[1].strip()
        storage = journald_storage(self._settings)
        section.items["selinux"] = {"mode": mac.get("selinux"), "configured": configured}
        section.items["journald"] = {"storage": storage or "auto (default)"}
        apparmor = mac.get("apparmor")
        if apparmor is not None:
            profiles = apparmor.get("profiles") or {}
            section.items["apparmor"] = {"loaded": True, "profiles": len(profiles)}
            for name, mode in profiles.items():
                section.items[f"apparmor: {name}"] = {"mode": mode}
        results = self.trailer_data.modules if self.trailer_data else {}
        listing = results.get("processes")
        if "processes" not in planned or listing is None or listing.status != "ok":
            # Without a full process listing, nothing can be said about what
            # runs: no service or agent items (the checks see `unknown`).
            section.items["services"] = {"known": False}
            return
        running: dict[str, set[str]] = {}
        for process in self.live.get("processes", []):
            if process.get("kernel_thread"):
                continue
            name, exe = _runs(process)
            if name in LOGGING_SERVICES | SECURITY_AGENTS:
                running.setdefault(name, set()).add(exe)
        for name, exes in sorted(running.items()):
            kind = "service" if name in LOGGING_SERVICES else "agent"
            # The file it runs: a copy of sleep named auditd in /dev/shm
            # changes it.
            section.items[f"{kind}: {name}"] = {"running": True, "exe": ", ".join(sorted(exes))}

    def _on_containers(self, name: str, data: dict[str, Any]) -> None:
        if name == "container" and data.get("name"):
            # By name: a redeploy replaces a container's ID, not what it is.
            key = f"{data.get('runtime')}: {data['name']}"
            mounts = data.get("mounts") or []
            item = {
                "image": data.get("image"),
                # A bind mount by host path; a volume (no host path) by where it goes.
                "mounts": sorted(
                    f"{m.get('source')} -> {m.get('destination')} ({'rw' if m.get('rw') else 'ro'})"
                    if m.get("source")
                    else f"{m.get('type') or 'volume'} -> {m.get('destination')}"
                    for m in mounts
                    if isinstance(m, dict)
                ),
                # Host paths it mounts, kept apart so a ":" in a destination
                # can't hide one.
                "mount_sources": sorted(
                    {m["source"] for m in mounts if isinstance(m, dict) and m.get("source")}
                ),
            }
            if "privileged" in data:  # its host configuration was read
                item.update(
                    {
                        "privileged": bool(data.get("privileged")),
                        "capabilities": sorted(set(data.get("capabilities") or [])),
                        "host_pid": bool(data.get("host_pid")),
                        "host_network": bool(data.get("host_network")),
                        "host_ipc": bool(data.get("host_ipc")),
                        "devices": sorted(d for d in data.get("devices") or [] if d),
                        "security_opt": sorted(data.get("security_opt") or []),
                    }
                )
            self.section("containers").items[key] = item
            # Its ID and running state: seen, not compared.
            self.live.setdefault("containers", []).append(data)
        elif name == "containers_summary":
            self.live["containers_summary"] = data
        elif name in ("containers_unreadable", "containers_cut"):
            self._module_gap("containers", f"{name}: {data.get('path')}", name, data)

    def _on_web_logs(self, name: str, data: dict[str, Any]) -> None:
        if name in (
            "web_logs_summary",
            "exec_records_summary",
            "exec_records_unavailable",
            "web_accounts",
        ):
            self.live[name] = data
            if name == "exec_records_summary" and data.get("truncated"):
                self._module_gap("web_logs", "audit log read cut short", name, {})

    def _on_mail(self, name: str, data: dict[str, Any]) -> None:
        if name == "mail_queue":
            self.live.setdefault("mail_queues", []).append(data)
            if data.get("cut") or data.get("errors"):
                self.live["mail_queue_incomplete"] = True
        elif name in ("mail_servers", "mail_log_summary", "mail_logs_withheld"):
            self.live[name] = data

    def _mail(self) -> None:
        """Postfix's and Exim's settings, one item each, by program and name."""
        if "mail" not in self._planned():
            return
        section = self.section("mail_config")
        for path, lines in self._mail_text:
            if path.endswith("/main.cf"):
                found = [(f"postfix: {n}", v) for n, v in postfix_settings(lines)]
            elif path.endswith("/master.cf"):
                found = [(f"postfix service: {n}", v) for n, v in postfix_services(lines)]
            elif "/exim" in path:
                found = [(f"exim: {n}", v) for n, v in exim_settings(path, lines)]
            else:
                continue
            for key, value in found:
                if key in section.items and section.items[key]["path"] != path:
                    key = f"{key} ({path})"
                section.items[key] = {"value": value, "path": path}

    def _on_network(self, name: str, data: dict[str, Any]) -> None:
        if name == "interface" and data.get("name"):
            # A container's veth pair is renamed with every restart: seen
            # (live), not compared.
            if not str(data["name"]).startswith("veth"):
                self.section("interfaces").items[data["name"]] = {
                    k: data.get(k)
                    for k in ("promiscuous", "state", "type", "bridge", "bridge_port", "master")
                }
            # Counters change all the time: seen, never compared.
            self.live.setdefault("interfaces", []).append(data)
        elif name == "routes":
            self.live.setdefault("routes", []).append(data)
        elif name == "firewall_loaded":
            self.live["firewall_loaded"] = data
        elif name in ("command_unavailable", "command_failed", "set_unterminated"):
            self._module_gap(
                "network", f"{name}: {data.get('command')} {data.get('reason') or ''}", name, data
            )

    def _on_processes(self, name: str, data: dict[str, Any]) -> None:
        if name in ("process", "hidden_process") and isinstance(data.get("pid"), int):
            self._processes[data["pid"]] = data.get("comm") or "?"
            self.live["processes"].append(dict(data, hidden=name == "hidden_process"))
        elif name == "socket":
            self._sockets.append(data)
            self.live["sockets"].append(data)
        elif name == "process_summary":
            self.live["process_summary"] = data
            if data.get("sockets_truncated"):
                self._module_gap("processes", "socket list cut short")
            if data.get("listing_complete") is False:
                self._module_gap("processes", "process list incomplete")

    # The end
    def _listeners(self) -> None:
        if not self._sockets and "processes" not in self._planned():
            return
        section = self.section("listeners")
        for sock in self._sockets:
            protocol = str(sock.get("protocol") or "?")
            remote = sock.get("remote") or []
            listening = (
                str(sock.get("state") or "").lower() == "listen"
                or (protocol.startswith("udp") and len(remote) == 2 and remote[1] == 0)
                or protocol.startswith(("raw", "packet"))
            )
            if not listening:
                continue
            local = sock.get("local")
            if protocol == "packet":  # no address: what it captures, and where
                where = "type={} ethertype={} interface={}".format(
                    sock.get("type"), sock.get("ethertype"), sock.get("interface")
                )
            elif isinstance(local, list) and len(local) == 2:
                where = f"{local[0]}:{local[1]}"
            else:
                where = str(local)
            key = f"{protocol} {where} netns={sock.get('netns')}"
            # Several sockets can share a key (SO_REUSEPORT, two sniffers on
            # one interface): one item holding all of their owners.
            item = section.items.setdefault(key, {"uids": [], "programs": [], "sockets": 0})
            item["sockets"] += 1
            item["uids"] = sorted(set(item["uids"]) | {sock.get("uid")}, key=str)
            programs = {self._processes.get(pid, "?") for pid in sock.get("pids") or []}
            item["programs"] = sorted(set(item["programs"]) | programs)

    def _peers(self) -> None:
        """Outgoing connections open at collection, by program and remote
        network (/24, /48) and port: a new destination is new for that
        program, not a new ephemeral address."""
        if not self._sockets and "processes" not in self._planned():
            return
        section = self.section("peers")
        # A connection accepted on one of the host's listening ports came in:
        # its remote port is the client's, not a destination.
        listening = {
            (str(s.get("protocol")), (s.get("local") or [None, None])[1], s.get("netns"))
            for s in self._sockets
            if str(s.get("state") or "").lower() == "listen"
        }
        for sock in self._sockets:
            local = sock.get("local") or [None, None]
            port = local[1] if len(local) == 2 else None
            if (str(sock.get("protocol")), port, sock.get("netns")) in listening:
                continue
            # Open connections only, held by a process: a closing socket
            # (TIME_WAIT and the like) has no owner and comes and goes.
            if str(sock.get("state") or "").lower() not in ("established", "syn_sent"):
                continue
            if not sock.get("pids"):
                continue
            protocol = str(sock.get("protocol") or "?")
            remote = sock.get("remote") or []
            if not protocol.startswith("tcp") or len(remote) != 2 or not remote[1]:
                continue
            if str(sock.get("state") or "").lower() == "listen":
                continue
            network = remote_network(str(remote[0]))
            if network is None:
                continue
            programs = sorted({self._processes.get(pid, "?") for pid in sock.get("pids") or []})
            for program in programs:
                key = f"{program} {network} port {remote[1]}"
                section.items.setdefault(key, {"program": program})
                # How many: changes all the time (pools, keep-alives), not compared.
                counts = self.live.setdefault("peer_connections", {})
                counts[key] = counts.get(key, 0) + 1

    def _planned(self) -> set[str]:
        return set(self.manifest_data.modules_planned) if self.manifest_data else set()

    def _settle_unread(self) -> None:
        """A file whose content wasn't read (refused: hard-linked, say — RHEL
        hard-links identical .pyc files) but which its walk still listed
        is marked on its item: its inode, size and times still show any
        change. Only one not listed at all leaves its section incomplete."""
        for module, data in self._unread:
            item = self.sections.get(_FILE_SECTIONS[module], Section()).items.get(data["path"])
            if item is not None and "inode" in item:
                item["content_unread"] = data.get("reason") or "unreadable"
            else:
                self._module_gap(
                    module, f"unreadable_file: {data['path']}", "unreadable_file", data
                )

    def finish(self) -> Snapshot:
        self._settle_unread()
        self._listeners()
        self._peers()
        self._logging()
        self._mail()
        planned = self._planned()
        results = self.trailer_data.modules if self.trailer_data else {}
        for section_name, (_, modules) in SECTIONS.items():
            if not any(m in planned for m in modules):
                self.sections.pop(section_name, None)  # not collected this time
                continue
            section = self.section(section_name)
            for module in modules:
                if module not in planned:
                    section.gap(f"{module} not collected")
                    continue
                result = results.get(module)
                if self.trailer_data is None:
                    section.gap("the bundle ended before its trailer")
                elif result is None:
                    section.gap(f"{module} has no result")
                elif result.status != "ok":
                    section.gap(f"{module}: {result.status}")
                for why, sections in self._gaps.get(module, []):
                    if sections is None or section_name in sections:
                        section.gap(why)
        manifest = self.manifest_data
        meta = {
            "snapshot_version": SNAPSHOT_VERSION,
            "collector_version": manifest.collector_version if manifest else None,
            "masking_version": manifest.masking_version if manifest else None,
            "host_time": manifest.started_at.isoformat() if manifest else None,
            "hostname": manifest.host.hostname if manifest else None,
            "modules_planned": sorted(planned),
            "full": FULL <= planned,
        }
        return Snapshot(meta, dict(sorted(self.sections.items())), self.live)


# --- Mail server settings (DESIGN.md §8.9) ------------------------------------------------------


def postfix_settings(lines: list[str]) -> list[tuple[str, str]]:
    """main.cf's `name = value` settings, continuation lines (starting with
    white space) joined; comment lines (starting with #) left out."""
    found: list[tuple[str, str]] = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace() and found:
            name, value = found[-1]
            found[-1] = (name, f"{value} {line.strip()}".strip())
            continue
        name, sep, value = line.partition("=")
        if sep and name.strip() and " " not in name.strip():
            found.append((name.strip(), value.strip()))
    return found


def postfix_services(lines: list[str]) -> list[tuple[str, str]]:
    """master.cf's services: ("service type", the rest of its definition)."""
    found: list[tuple[str, list[str]]] = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace() and found:
            found[-1][1].extend(line.split())
            continue
        words = line.split()
        if len(words) >= 2:
            found.append((f"{words[0]} {words[1]}", words[2:]))
    return [(name, " ".join(rest)) for name, rest in found]


_EXIM_DEBIAN = re.compile(r"^(dc_\w+)=(['\"]?)(.*)\2\s*$")
_EXIM_LIST = re.compile(r"^\s*((?:host|domain|address|localpart)list)\s+(\w+)\s*=\s*(.*?)\s*$")
_EXIM_OPTION = re.compile(
    r"^\s*(route_list|route_data|local_interfaces|daemon_smtp_ports)"
    r"\s*=\s*(.*?)\s*$"
)


def exim_settings(path: str, lines: list[str]) -> list[tuple[str, str]]:
    """Debian's update-exim4.conf.conf (dc_ settings), and from Exim's own
    configuration its named lists and the options naming relays, listening
    addresses and ports."""
    found = []
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        if path.endswith("update-exim4.conf.conf"):
            match = _EXIM_DEBIAN.match(line.strip())
            if match:
                found.append((match[1], match[3]))
            continue
        match = _EXIM_LIST.match(line)
        if match:
            found.append((f"{match[1]} {match[2]}", match[3]))
            continue
        match = _EXIM_OPTION.match(line)
        if match:
            found.append((match[1], match[2]))
    return found


# --- Comparing two ---------------------------------------------------------------------------


def compare(old: Snapshot, new: Snapshot) -> dict[str, dict[str, Any]]:
    """Per section: items added, removed and changed (field by field), and
    whether the comparison can be trusted. A section incomplete on either
    side is still compared, but marked not comparable with the reasons:
    what is missing from it may only be missing from the collection."""
    out: dict[str, dict[str, Any]] = {}
    masking_changed = old.meta.get("masking_version") != new.meta.get("masking_version")
    for name in sorted(set(old.sections) | set(new.sections)):
        before, after = old.sections.get(name), new.sections.get(name)
        notes: list[str] = []
        if before is None or after is None:
            # A run limited to some modules: nothing to compare, nothing
            # removed or added.
            out[name] = {
                "added": {},
                "removed": {},
                "changed": {},
                "comparable": False,
                "notes": ["collected in only one of the two; not compared"],
            }
            continue
        for label, side in (("earlier", before), ("later", after)):
            if side is not None and not side.complete:
                notes.append(f"{label} incomplete: " + "; ".join(side.gaps[:3]))
        if masking_changed and name in _MASKED:
            notes.append("masking changed between the two; text may differ without a change")
        a, b = before.items, after.items
        changed = {}
        for key in sorted(set(a) & set(b)):
            fields = {
                f: [a[key].get(f), b[key].get(f)]
                for f in sorted(set(a[key]) | set(b[key]))
                if a[key].get(f) != b[key].get(f)
            }
            if fields:
                changed[key] = fields
        result = {
            "added": {k: b[k] for k in sorted(set(b) - set(a))},
            "removed": {k: a[k] for k in sorted(set(a) - set(b))},
            "changed": changed,
            "comparable": not notes,
            "notes": notes,
        }
        if result["added"] or result["removed"] or result["changed"] or notes:
            out[name] = result
    return out
