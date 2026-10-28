"""System binary integrity (DESIGN.md §8.5): ★ package files changed,
set-user-ID and capability files, executables no package installed."""

from __future__ import annotations

import re

from checker.checks import COMPROMISE, HYGIENE, Context, Finding, check

# What an intruder replaces to hide or to keep access.
CRITICAL = {
    "ps",
    "ls",
    "ss",
    "netstat",
    "top",
    "find",
    "lsof",
    "w",
    "who",
    "last",
    "lastlog",
    "pstree",
    "sshd",
    "sshd-session",
    "sshd-auth",
    "ssh",
    "login",
    "sudo",
    "su",
    "passwd",
    "chsh",
    "crontab",
    "bash",
    "sh",
    "dash",
    "systemd",
    "init",
    "journalctl",
    "rsyslogd",
    "auditd",
    "ip",
    "ifconfig",
    "kill",
    "pgrep",
    "pkill",
    "md5sum",
    "sha256sum",
    "rpm",
    "dpkg",
}
CRITICAL_LIBRARY = re.compile(
    r"/(?:ld-linux[^/]*|libc\.so[^/]*|libpam[^/]*|libaudit[^/]*|libsystemd[^/]*|pam_[^/]+\.so)$"
)
PROGRAM_DIRS = re.compile(r"/(?:s?bin|libexec|lib(?:32|64|x32)?)/")
# Device nodes systemd makes to mask paths (InaccessiblePaths=).
SYSTEMD_OWN = ("/run/systemd/inaccessible/",)
# Capabilities that amount to root, or to reading or changing anything.
ROOT_CAPABILITIES = (
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_chown",
    "cap_fowner",
    "cap_bpf",
    "cap_sys_rawio",
)


def _critical(path: str) -> bool:
    return (bool(PROGRAM_DIRS.search(path)) and path.rsplit("/", 1)[-1] in CRITICAL) or bool(
        CRITICAL_LIBRARY.search(path)
    )


def _owners_known(context: Context) -> bool:
    summary = context.snapshot.live.get("system_files_summary") or {}
    return bool(summary.get("owners")) and summary.get("owners_complete") is not False


@check("package.changed", "System files that differ from their package")
def package_changed(context: Context) -> list[Finding]:
    findings = []
    uncertain = context.uncertain("package_changes")
    for path, item in context.items("package_changes").items():
        result = item.get("result")
        package = item.get("package") or "?"
        if item.get("configuration"):
            if result in ("changed", "missing"):
                findings.append(
                    Finding(
                        "package.changed",
                        "A package's configuration file was edited",
                        HYGIENE,
                        "info",
                        f"{path} ({package}): {result}",
                        [f"path:{path}", f"package:{package}"],
                        [{"item": ["package_changes", path]}],
                    )
                )
            continue
        if result not in ("changed", "missing"):
            continue  # unreadable or refused: coverage, not a finding
        if _critical(path):
            title, band = "A critical system program or library differs from its package", "high"
        elif PROGRAM_DIRS.search(path) or ".so" in path.rsplit("/", 1)[-1]:
            title, band = "A system program or library differs from its package", "medium"
        else:
            title, band = "A package file differs from its package", "low"
        findings.append(
            Finding(
                "package.changed",
                title,
                COMPROMISE,
                band,
                f"{path} ({package}): {result}"
                + (f", {item['reason']}" if item.get("reason") else ""),
                [f"path:{path}", f"package:{package}"],
                [{"item": ["package_changes", path]}],
                uncertain=uncertain,
            )
        )
    diff = context.changes("checksum_store")
    if diff is not None and (diff["added"] or diff["changed"] or diff["removed"]):
        touched = len(diff["added"]) + len(diff["changed"]) + len(diff["removed"])
        findings.append(
            Finding(
                "package.changed",
                "The package managers' checksum lists changed since the baseline",
                COMPROMISE,
                "low",
                f"{touched} list file(s): expected after package installs and updates; a rewrite"
                " to hide a replaced file would show here too",
                [],
                [
                    context.change_ref("checksum_store", k, how)
                    for how in ("added", "changed", "removed")
                    for k in list(diff[how])[:20]
                ],
                uncertain=context.uncertain("checksum_store"),
            )
        )
    return findings


@check(
    "files.privileged", "Set-user-ID, set-group-ID and capability files; device nodes out of place"
)
def privileged(context: Context) -> list[Finding]:
    findings = []
    owners = _owners_known(context)
    diff = context.changes("privileged_files")
    added = diff["added"] if diff else {}
    uncertain = context.uncertain("privileged_files")
    for path, item in context.items("privileged_files").items():
        if "error" in item or path.startswith(SYSTEMD_OWN):
            continue  # a walk error (a coverage gap), or systemd's own placeholders
        special = item.get("setuid") or item.get("setgid")
        capabilities = str(item.get("capabilities") or "")
        root_capability = any(c in capabilities for c in ROOT_CAPABILITIES)
        device = item.get("type") in ("b", "c")
        outside = bool(item.get("place"))  # found outside the system directories
        unowned = not outside and owners and not item.get("package")
        is_new = path in added
        what = ", ".join(
            w
            for w in (
                "set-user-ID" if item.get("setuid") else "",
                "set-group-ID" if item.get("setgid") else "",
                f"capabilities {capabilities}" if capabilities else "",
                "a device node" if device else "",
                f"owner UID {item.get('uid')}" if special else "",
            )
            if w
        )
        if is_new:
            title, band = "A new privileged file since the baseline", "high"
        elif outside and (special or root_capability or device):
            title, band = "A privileged file outside the system directories", "high"
        elif unowned and (special or root_capability):
            title, band = "A privileged file no package installed", "high"
        elif "capabilities_unreadable" in item:
            title, band = "A file whose capabilities can't be read", "medium"
        else:
            continue  # a package's own set-user-ID program: ordinary
        findings.append(
            Finding(
                "files.privileged",
                title,
                COMPROMISE,
                band,
                f"{path}: {what or 'privileged'}"
                + (f" (package {item['package']})" if item.get("package") else ""),
                [f"path:{path}"],
                [
                    context.change_ref("privileged_files", path, "added")
                    if is_new
                    else {"item": ["privileged_files", path]}
                ],
                new=is_new and context.new_since_previous("privileged_files", path),
                uncertain=uncertain if is_new else None,
            )
        )
    return findings


@check("files.unowned", "Executables in system directories that no package installed")
def unowned(context: Context) -> list[Finding]:
    if not _owners_known(context):
        return []  # nothing can be called unowned when ownership wasn't loaded
    findings = []
    diff = context.changes("unowned_executables")
    added = diff["added"] if diff else {}
    for path, item in context.items("unowned_executables").items():
        local = bool(item.get("local"))
        is_new = path in added
        # Reported on every analysis, not only when new: the baseline's own
        # bundle may never have been analysed.
        if is_new:
            band = "medium" if local else "high"
        else:
            band = "info" if local else "medium"
        findings.append(
            Finding(
                "files.unowned",
                (
                    "A new executable no package installed"
                    if is_new
                    else "An executable no package installed"
                )
                + (" (in /usr/local or /opt)" if local else ""),
                COMPROMISE,
                band,
                path + (f" (SHA-256 {item['sha256'][:16]}…)" if item.get("sha256") else ""),
                [f"path:{path}"],
                [
                    context.change_ref("unowned_executables", path, "added")
                    if is_new
                    else {"item": ["unowned_executables", path]}
                ],
                new=is_new and context.new_since_previous("unowned_executables", path),
            )
        )
    return findings
