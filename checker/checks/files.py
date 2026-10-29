"""Files in unusual places (DESIGN.md §8.6): ★ executables in scratch
directories, deceptive names, files under /dev, ★ web shells, back-dated
files."""

from __future__ import annotations

import posixpath
import re

from checker.checks import COMPROMISE, EXPOSURE, Context, Finding, check

SCRATCH = ("/tmp", "/var/tmp", "/dev/shm")
DECEPTIVE = {
    "dots_or_spaces_only": ("a name of only dots or spaces", "high"),
    "leading_or_trailing_space": ("a name with a leading or trailing space", "high"),
    "kernel_thread_name": ("a name posing as a kernel thread", "high"),
    "system_name": ("a system program's name", "high"),
    "control_characters": ("control characters in its name", "medium"),
}
SCRIPT = re.compile(r"\.(?:php\d?|phtml|phar|shtml|cfm|jsp|jspx|aspx?|ashx|cgi|pl|py|sh|rb)$", re.I)
# shell.php.jpg: Apache runs it when a handler maps .php (AddHandler), the
# extension anywhere in the name. Only extensions mapped that way: .pl,
# .py, .sh and .rb run only as CGI scripts, and .pl is also Polish
# (validators.pl.xlf, in every Symfony application).
HANDLED = re.compile(r"\.(?:php\d?|phtml|phar|shtml|cfm|jsp|jspx|aspx?|ashx|cgi)\.", re.I)
UPLOADS = re.compile(r"/(?:uploads?|files|media|images?|tmp|cache|wp-content/uploads)/", re.I)
SECRET_FILES = {".env", ".htpasswd", ".git", ".svn", ".user.ini"}


def _leaves(path: str, item: dict) -> bool:
    """A link that leads out of its web root to somewhere a web server
    shouldn't serve: not to a system program or library (a venv's python),
    nor to the distribution's shared data (RHEL's nginx links its stock
    page and logos into /usr/share/testpage and /usr/share/pixmaps)."""
    target = str(item.get("link_target"))
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    root = str(item.get("place") or "/").rstrip("/") + "/"
    if resolved.startswith(root):
        return False
    return not resolved.startswith(
        ("/usr/bin/", "/usr/lib", "/usr/local/bin/", "/bin/", "/lib", "/usr/share/")
    )


def _executable(item: dict) -> bool:
    try:
        return bool(int(str(item.get("mode") or "0"), 8) & 0o111)
    except ValueError:
        return False


def _runnable(item: dict) -> bool:
    return item.get("type") == "-" and (item.get("kind") in ("elf", "script") or _executable(item))


def _group(item: dict, path: str) -> str:
    """The directory a scratch finding is reported under: the entry
    directly in its place (a whole unpacked tree is one finding)."""
    place = str(item.get("place") or "")
    rest = path[len(place) :].lstrip("/") if path.startswith(place) else path
    return place.rstrip("/") + "/" + rest.split("/", 1)[0]


def _grouped(check_id, title, category, band, section, members, detail) -> Finding:
    paths = sorted(members)
    shown = ", ".join(detail(p) for p in paths[:3]) + (
        f" and {len(paths) - 3} more" if len(paths) > 3 else ""
    )
    return Finding(
        check_id,
        title,
        category,
        band,
        shown,
        [f"path:{p}" for p in paths[:20]],
        [{"item": [section, p]} for p in paths[:50]],
        entities_complete=len(paths) <= 20,
    )


@check("files.scratch", "Programs and scripts in /tmp, /var/tmp and /dev/shm")
def scratch(context: Context) -> list[Finding]:
    """Recognised by their first bytes (an ELF header, `#!`), not by an
    execute bit, which unpacked files carry for no reason; grouped by the
    directory they sit in under the scratch place."""
    groups: dict[tuple[str, str], list[str]] = {}
    items = context.items("unusual_files")
    for path, item in items.items():
        if item.get("place") in SCRATCH and item.get("type") == "-" and item.get("kind"):
            groups.setdefault((_group(item, path), item["kind"]), []).append(path)
    findings = []
    for (group, kind), paths in sorted(groups.items()):
        elf = kind == "elf"
        finding = _grouped(
            "files.scratch",
            ("A program in a scratch directory" if elf else "A script in a scratch directory")
            + (f" ({len(paths)} in {group})" if len(paths) > 1 else ""),
            COMPROMISE,
            "high" if elf else "medium",
            "unusual_files",
            paths,
            lambda p: f"{p} (owner UID {items[p].get('uid')})",
        )
        finding.uncertain = context.uncertain("unusual_files")
        findings.append(finding)
    return findings


@check("files.deceptive", "Names chosen to hide or to pass for system ones")
def deceptive(context: Context) -> list[Finding]:
    findings = []
    for section in ("unusual_files", "web_files"):
        for path, item in context.items(section).items():
            flags = [f for f in item.get("name_flags") or [] if f in DECEPTIVE]
            if "system_name" in flags and (
                item.get("type") != "-" or "/bin/" in path or "/sbin/" in path
            ):
                # A venv's bin/python link, a build's bin/: where such names belong.
                flags.remove("system_name")
            if not flags:
                continue
            band = "high" if any(DECEPTIVE[f][1] == "high" for f in flags) else "medium"
            findings.append(
                Finding(
                    "files.deceptive",
                    "A file or directory with a deceptive name",
                    COMPROMISE,
                    band,
                    f"{path!r}: " + "; ".join(DECEPTIVE[f][0] for f in flags),
                    [f"path:{path}"],
                    [{"item": [section, path]}],
                )
            )
    return findings


@check("files.dev", "Files under /dev that don't belong")
def dev(context: Context) -> list[Finding]:
    findings = []
    for path, item in context.items("unusual_files").items():
        if item.get("type") in ("b", "c") and item.get("place") != "/dev":
            # mknod /dev/shm/.k c 1 1: a copy of /dev/mem anyone may read.
            findings.append(
                Finding(
                    "files.dev",
                    "A device node outside /dev",
                    COMPROMISE,
                    "high",
                    f"{path} (type {item.get('type')}, owner UID {item.get('uid')})",
                    [f"path:{path}"],
                    [{"item": ["unusual_files", path]}],
                )
            )
            continue
        if item.get("place") != "/dev":
            continue
        regular = item.get("type") == "-"
        findings.append(
            Finding(
                "files.dev",
                "A regular file under /dev"
                if regular
                else "A hidden or misplaced entry under /dev",
                COMPROMISE,
                "high" if regular else "medium",
                f"{path} (type {item.get('type')}, size {item.get('size')})",
                [f"path:{path}"],
                [{"item": ["unusual_files", path]}],
            )
        )
    return findings


@check("files.web", "Web shells: new scripts in web roots, scripts in upload directories")
def web(context: Context) -> list[Finding]:
    findings = []
    diff = context.changes("web_files")
    added = diff["added"] if diff else {}
    uncertain = context.uncertain("web_files")
    for path, item in context.items("web_files").items():
        name = path.rsplit("/", 1)[-1]
        double = not SCRIPT.search(name) and HANDLED.search(name) is not None
        script = double or SCRIPT.search(name) is not None or item.get("kind") == "script"
        reason = None
        if path in added and (script or _runnable(item)):
            reason, band = "A new script in a web root", "high"
        elif item.get("kind") == "elf":
            reason, band = "A program in a web root", "high"
        elif script and UPLOADS.search(path):
            reason, band = "A script in an upload directory", "high"
        elif script and double:
            reason, band = "A script hidden behind a second extension", "high"
        elif item.get("link_target") and _leaves(path, item):
            reason, band = "A link out of the web root", "medium"
        elif name in SECRET_FILES:
            findings.append(
                Finding(
                    "files.web",
                    "A secrets or repository file inside a web root",
                    EXPOSURE,
                    "medium",
                    f"{path}: a web server may serve it",
                    [f"path:{path}"],
                    [{"item": ["web_files", path]}],
                )
            )
            continue
        if reason is None:
            continue
        findings.append(
            Finding(
                "files.web",
                reason,
                COMPROMISE,
                band,
                path + (f" (SHA-256 {item['sha256'][:16]}…)" if item.get("sha256") else ""),
                [f"path:{path}"],
                [
                    context.change_ref("web_files", path, "added")
                    if path in added
                    else {"item": ["web_files", path]}
                ],
                new=path in added and context.new_since_previous("web_files", path),
                uncertain=uncertain if path in added else None,
            )
        )
    return findings


@check("files.backdated", "Programs and scripts whose modification time was set back")
def backdated(context: Context) -> list[Finding]:
    """Files unpacked from an archive keep its old times too, so this is
    weak on its own: programs and scripts only, grouped by directory, low."""
    findings = []
    for section in ("unusual_files", "web_files"):
        items = context.items(section)
        groups: dict[str, list[str]] = {}
        odd = []
        for path, item in items.items():
            if item.get("changed_after_modified_seconds") and item.get("kind"):
                groups.setdefault(_group(item, path), []).append(path)
            elif item.get("time_out_of_range"):
                odd.append(path)
        for group, paths in sorted(groups.items()):
            findings.append(
                _grouped(
                    "files.backdated",
                    "A program or script whose modification time is long before its change time"
                    + (f" ({len(paths)} in {group})" if len(paths) > 1 else ""),
                    COMPROMISE,
                    "low",
                    section,
                    paths,
                    lambda p, items=items: (
                        f"{p} (changed {items[p]['changed_after_modified_seconds'] // 86400} days"
                        " after its stated modification)"
                    ),
                )
            )
        for path in odd:
            findings.append(
                Finding(
                    "files.backdated",
                    "A file with an impossible time",
                    COMPROMISE,
                    "low",
                    path,
                    [f"path:{path}"],
                    [{"item": [section, path]}],
                )
            )
    return findings
