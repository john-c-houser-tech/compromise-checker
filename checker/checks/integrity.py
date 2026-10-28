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


# Files packages generate after installing (so no package lists them).
GENERATED = re.compile(r"/(?:dist|site)-packages/.*\.(?:cache|pyc)$|/__pycache__/")


def _generated(path: str) -> bool:
    return bool(GENERATED.search(path))


def _owners_known(context: Context) -> bool:
    summary = context.snapshot.live.get("system_files_summary") or {}
    return bool(summary.get("owners")) and summary.get("owners_complete") is not False


def _mode(text) -> int | None:
    try:
        return int(str(text), 8)
    except ValueError:
        return None


def _difference(path: str, item: dict) -> tuple[str, str, str] | None:
    """(title, band, detail) for how a package file differs, the worst of
    its results; None when it only couldn't be checked."""
    results = set(item.get("results") or [item.get("result")])
    critical = _critical(path)
    program = critical or bool(PROGRAM_DIRS.search(path)) or ".so" in path.rsplit("/", 1)[-1]
    worst = None

    def consider(title, band, detail):
        nonlocal worst
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if worst is None or order[band] < order[worst[1]]:
            worst = (title, band, detail)

    if results & {"changed", "missing"}:
        what = "changed" if "changed" in results else "missing"
        if critical:
            consider(
                "A critical system program or library differs from its package", "critical", what
            )
        elif program:
            consider("A system program or library differs from its package", "medium", what)
        else:
            consider("A package file differs from its package", "low", what)
    if "mode" in results:
        consider(*_mode_change(path, item, critical))
    if "capabilities" in results:
        consider(
            "A package file's capabilities changed",
            "high",
            f"capabilities {item.get('expected_capabilities')} → {item.get('capabilities')}",
        )
    if "link" in results:
        consider(
            "A package's link points elsewhere",
            "high" if program else "medium",
            "its link target differs from the package's",
        )
    if results & {"owner", "group"}:
        consider(
            "A package file's owner or group changed",
            "high" if critical else "medium",
            f"owner {item.get('expected_owner') or item.get('expected_group')} →"
            f" {item.get('owner') or item.get('group')}",
        )
    return worst


# Files whose contents are secret: reading them is the harm.
SECRET_FILES = re.compile(r"^/etc/(?:g?shadow-?|sudoers(?:\.d/.*)?|ssh/ssh_host_.*_key)$")
# Directories kept private (opening them exposes what is inside).
PRIVATE_DIRS = re.compile(r"^/(?:root|home/[^/]+|etc/ssl/private|etc/sudoers\.d|var/lib/[^/]+)$")


def _mode_change(path: str, item: dict, critical: bool) -> tuple[str, str, str]:
    """How a package file's mode changed, rated by what it allows now."""
    now, expected = _mode(item.get("mode")), _mode(item.get("expected_mode"))
    detail = f"mode {item.get('expected_mode')} → {item.get('mode')}"
    if now is None or expected is None:
        return "A package file's mode changed (it couldn't be read)", "medium", detail
    gained = now & ~expected
    directory = (expected & 0o170000) == 0o040000
    if (now ^ expected) & 0o170000:
        return "A package file's type changed", "high" if critical else "medium", detail
    if gained & 0o6000:
        return "A package file gained set-user-ID or set-group-ID", "high", detail
    if directory and expected & 0o1000 and not now & 0o1000:
        return "A shared directory lost its sticky bit", "high", detail
    if gained & 0o022:
        return (
            "A package file became writable by its group or everyone",
            "high" if critical else "medium",
            detail,
        )
    if gained & 0o044 and not directory:
        secret = bool(SECRET_FILES.search(path))
        return (
            "A package file became readable by its group or everyone",
            "high" if secret or critical else "medium",
            detail,
        )
    if gained & 0o055 and directory and PRIVATE_DIRS.search(path):
        return "A private directory was opened to others", "medium", detail
    # Execute or read bits on an ordinary directory (an image shipping
    # /boot/efi 755 where the package says 700), or permissions tightened.
    return "A package file's mode changed", "low", detail


@check("package.changed", "System files that differ from their package")
def package_changed(context: Context) -> list[Finding]:
    findings = []
    uncertain = context.uncertain("package_changes")
    for path, item in context.items("package_changes").items():
        package = item.get("package") or "?"
        results = set(item.get("results") or [item.get("result")])
        if item.get("configuration"):
            if results - {"unreadable", "refused"}:
                findings.append(
                    Finding(
                        "package.changed",
                        "A package's configuration file was edited",
                        HYGIENE,
                        "info",
                        f"{path} ({package}): {', '.join(sorted(results, key=str))}",
                        [f"path:{path}", f"package:{package}"],
                        [{"item": ["package_changes", path]}],
                    )
                )
            continue
        found = _difference(path, item)
        if found is None:
            continue  # unreadable or refused: coverage, not a finding
        title, band, detail = found
        findings.append(
            Finding(
                "package.changed",
                title,
                COMPROMISE,
                band,
                f"{path} ({package}): {detail}"
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
    # The scratch places and web roots are listed whole (unusual_file,
    # web_file), so the privileged search skips them: a set-user-ID shell in
    # /tmp is only there. Every listed file carrying privilege counts.
    candidates: dict[str, tuple[str, dict]] = {}
    for section in ("unusual_files", "web_files", "privileged_files"):
        for path, item in context.items(section).items():
            privileged = item.get("setuid") or item.get("setgid") or item.get("capabilities")
            if section == "privileged_files" or privileged:
                candidates[path] = (section, item)
    # A file can sit in a different section at the baseline (a scratch
    # place listed whole one time, cut short the next): it is new only if
    # no section had it then.
    added, removed, changed = set(), set(), {}
    for section in ("unusual_files", "web_files", "privileged_files"):
        diff = context.changes(section)
        if diff:
            added |= set(diff["added"])
            removed |= set(diff["removed"])
            changed[section] = diff["changed"]
    for path, (section, item) in sorted(candidates.items()):
        if "error" in item or path.startswith(SYSTEMD_OWN):
            continue  # a walk error (a coverage gap), or systemd's own placeholders
        special = item.get("setuid") or item.get("setgid")
        capabilities = str(item.get("capabilities") or "")
        root_capability = any(c in capabilities for c in ROOT_CAPABILITIES)
        device = item.get("type") in ("b", "c")
        outside = bool(item.get("place"))  # found outside the system directories
        unowned = not outside and owners and not item.get("package")
        is_new = path in added and path not in removed
        uncertain = context.uncertain(section)
        # More privilege on a file already listed: a capability added to
        # ping, a set-user-ID bit (dpkg doesn't record capabilities).
        gained = sorted(
            f
            for f in ("capabilities", "setuid", "setgid")
            if changed.get(section, {}).get(path, {}).get(f, [None, None])[1]
        )
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
        elif gained:
            title, band = f"A file gained {' and '.join(gained)} since the baseline", "high"
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
                    context.change_ref(section, path, "added" if is_new else "changed")
                    if is_new or gained
                    else {"item": [section, path]}
                ],
                new=(is_new or bool(gained)) and context.new_since_previous(section, path),
                uncertain=uncertain if is_new or gained else None,
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
        if _generated(path):
            local = True  # made by a package after install: reported apart, like /usr/local
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
