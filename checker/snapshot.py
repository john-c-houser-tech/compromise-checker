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
    "privileged_files": ("set-user-ID, set-group-ID and capability files", ("system_files",)),
    "unusual_files": ("unusual files in writable and web directories", ("unusual_files",)),
    "listeners": ("listening and raw sockets, with their programs", ("processes",)),
}

# Sections built from masked text: a new masking version can change them
# without any change on the host.
_FROM_TEXT = {"sudo_rules", "sshd_config"}
_TEXT_HASHED = {"sudo_files", "ssh_files", "pam", "cron", "systemd", "startup", "hooks"}

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
_GAPS = {"unreadable_file", "listing_truncated", "phase_time_limit", "incomplete_file"}


def _gap_sections(module: str, path: str | None) -> set[str] | None:
    """The sections a gap at `path` leaves incomplete, where a module feeds
    several; None: all of them."""
    if module == "accounts" and path:
        if path in ("/etc/passwd", "/etc/shadow"):
            return {"accounts"}
        if path == "/etc/group":
            return {"groups"}
        return {"shell_history"}
    if module == "ssh" and path:
        if path.startswith("/etc/ssh/"):
            return {"sshd_config", "ssh_files"}
        return {"authorized_keys", "ssh_files"}
    if module == "sudoers":
        return {"sudo_rules", "sudo_files"}
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


def sudoers_lines(lines: list[str]) -> list[str]:
    """The lines sudo acts on: comments and blank lines dropped (but not
    `#include`, a directive), continuations joined, spaces collapsed."""
    out: list[str] = []
    pending = ""
    for raw in lines:
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line = (pending + line).strip()
        pending = ""
        if not line or (line.startswith("#") and not line.startswith(("#include", "#includedir"))):
            continue
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

    def section(self, name: str) -> Section:
        return self.sections.setdefault(name, Section())

    def _module_gap(self, module: str, why: str, path: str | None = None) -> None:
        self._gaps.setdefault(module, []).append((why, _gap_sections(module, path)))

    # Consumer interface
    def manifest(self, manifest: Manifest) -> None:
        self.manifest_data = manifest

    def record(self, record: Record) -> None:
        module, name, data = record.module, record.name, record.data
        if name in _GAPS:
            where = data.get("path") or data.get("phase") or ""
            self._module_gap(module, f"{name}: {where}", data.get("path"))
        elif name == "walk_summary" and data.get("truncated"):
            self._module_gap(module, f"walk of {data.get('top')} cut short")
        elif name == "homes" and data.get("complete") is False:
            self._module_gap(module, "not every home directory was examined")
        handler = getattr(self, f"_on_{module}", None)
        if handler is not None:
            handler(name, data)
        if module in _FILE_SECTIONS and name in _FILE_RECORDS and data.get("path"):
            item = self.section(_FILE_SECTIONS[module]).items.setdefault(data["path"], {})
            item.update(_meta(data))
            item.setdefault("record", name)

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
            self._module_gap(start.module, f"{start.name} cut short", start.name)
        if lines is None:
            return
        if start.module == "sudoers":
            rules = self.section("sudo_rules")
            # Keyed by text: a line moved within its file isn't a change.
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

    def _on_accounts(self, name: str, data: dict[str, Any]) -> None:
        if name == "account" and data.get("name"):
            item = {k: data.get(k) for k in ("uid", "gid", "home", "shell", "password")}
            item.update(self._password.get(data["name"], {}))
            self.section("accounts").items[data["name"]] = item
        elif name == "password_status" and data.get("name"):
            status = {f"shadow_{k}": v for k, v in data.items() if k not in ("name", "line")}
            self._password[data["name"]] = status
            account = self.section("accounts").items.get(data["name"])
            if account is not None:
                account.update(status)
        elif name == "group" and data.get("name"):
            members = sorted(m for m in data.get("members") or [] if m)
            self.section("groups").items[data["name"]] = {
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
        elif name == "system_files_summary" and data.get("truncated"):
            self._module_gap("system_files", "cut short")

    def _on_unusual_files(self, name: str, data: dict[str, Any]) -> None:
        if name == "unusual_file" and data.get("path"):
            self.section("unusual_files").items[data["path"]] = _meta(data)

    def _on_processes(self, name: str, data: dict[str, Any]) -> None:
        if name == "process" and isinstance(data.get("pid"), int):
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
                sock.get("state") == "LISTEN"
                or (protocol.startswith("udp") and len(remote) == 2 and remote[1] == 0)
                or protocol.startswith(("raw", "packet"))
            )
            if not listening:
                continue
            local = sock.get("local")
            where = (
                f"{local[0]}:{local[1]}" if isinstance(local, list) and len(local) == 2 else local
            )
            key = f"{protocol} {where} netns={sock.get('netns')}"
            programs = sorted({self._processes.get(pid, "?") for pid in sock.get("pids") or []})
            section.items[key] = {"uid": sock.get("uid"), "programs": programs}

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
            notes.append("collected in only one of the two")
        for label, side in (("earlier", before), ("later", after)):
            if side is not None and not side.complete:
                notes.append(f"{label} incomplete: " + "; ".join(side.gaps[:3]))
        if masking_changed and name in _FROM_TEXT | _TEXT_HASHED:
            notes.append("masking changed between the two; text may differ without a change")
        a = before.items if before else {}
        b = after.items if after else {}
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
