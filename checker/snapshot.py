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
import re
from dataclasses import dataclass, field
from typing import Any

from checker.protocol import Error, Manifest, Record, SourceEnd, SourceStart, Trailer

SNAPSHOT_VERSION = 1

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
}

# Every module the sections come from: a bundle that planned them all is a
# full collection.
FULL = frozenset(m for _, modules in SECTIONS.values() for m in modules)

# Sections holding masked text, hashes of it, or masked names: a new masking
# version can change them without any change on the host.
_MASKED = {
    "sudo_rules",
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
# Records that mean some of a module's data is missing.
_GAPS = {
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
    if module == "unusual_files":
        return {"unusual_files", "web_files", "privileged_files"}
    if module == "system_files":
        return {"privileged_files", "unowned_executables"}
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

    def as_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "sections": {
                name: {"complete": s.complete, "gaps": s.gaps, "items": s.items}
                for name, s in self.sections.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Snapshot:
        return cls(
            data["meta"],
            {
                name: Section(s["items"], s["complete"], s["gaps"])
                for name, s in data["sections"].items()
            },
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
        self._sockets: list[dict[str, Any]] = []
        self._password: dict[str, dict[str, Any]] = {}
        self._gaps: dict[str, list[tuple[str, set[str] | None]]] = {}
        self._names: dict[str, dict[str, int]] = {}

    def section(self, name: str) -> Section:
        return self.sections.setdefault(name, Section())

    def _module_gap(self, module: str, why: str, name: str = "", data: Any = None) -> None:
        self._gaps.setdefault(module, []).append((why, _gap_sections(module, name, data or {})))

    # Consumer interface
    def manifest(self, manifest: Manifest) -> None:
        self.manifest_data = manifest

    def record(self, record: Record) -> None:
        module, name, data = record.module, record.name, record.data
        if name in _GAPS:
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
        if module in _FILE_SECTIONS and name in _FILE_RECORDS and data.get("path"):
            item = self.section(_FILE_SECTIONS[module]).items.setdefault(data["path"], {})
            item.update(_meta(data))
            item.setdefault("record", name)
            if data["path"].startswith("/run/"):
                # Remade at every boot (transient units, generators' output):
                # its content, owner and mode matter, not its inode and times.
                for volatile in ("inode", "ctime", "mtime"):
                    item.pop(volatile, None)

    def source_start(self, start: SourceStart) -> None:
        wanted = start.kind == "file" and start.module in _FILE_SECTIONS
        lines: list[str] | None = [] if start.module in ("sudoers", "ssh") else None
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
        section = _FILE_SECTIONS[start.module]
        item = self.section(section).items.setdefault(start.name, {})
        for key, value in (start.meta or {}).items():
            item.setdefault(key, value)
        item["content_sha256"] = digest.hexdigest()
        if cut:
            item["content_cut"] = True
            self._module_gap(start.module, f"{start.name} cut short", "source", {})
        if lines is None:
            return
        if start.module == "sudoers":
            rules = self.section("sudo_rules")
            # Keyed by text: a line moved within its file isn't a change; the
            # same line twice is one rule.
            for text in sudoers_lines(lines):
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
            item = dict(data, configuration=name == "conffile_changed")
            self.section("package_changes").items[data["path"]] = _meta(item)
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
        elif name == "system_files_summary" and data.get("truncated"):
            self._module_gap("system_files", f"cut short: {data.get('truncated_reason')}")

    def _on_unusual_files(self, name: str, data: dict[str, Any]) -> None:
        sections = {
            "unusual_file": "unusual_files",
            "web_file": "web_files",
            "privileged_file": "privileged_files",
        }
        if name in sections and data.get("path"):
            self.section(sections[name]).items[data["path"]] = _meta(data)

    def _on_processes(self, name: str, data: dict[str, Any]) -> None:
        if name in ("process", "hidden_process") and isinstance(data.get("pid"), int):
            self._processes[data["pid"]] = data.get("comm") or "?"
        elif name == "socket":
            self._sockets.append(data)
        elif name == "process_summary":
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

    def _planned(self) -> set[str]:
        return set(self.manifest_data.modules_planned) if self.manifest_data else set()

    def finish(self) -> Snapshot:
        self._listeners()
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
        return Snapshot(meta, dict(sorted(self.sections.items())))


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
