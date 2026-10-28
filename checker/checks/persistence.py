"""Persistence (DESIGN.md §8.4): cron and at, systemd units and timers,
start-up scripts and shell start-up files, package-manager hooks and udev
rules; ★ /etc/ld.so.preload and the loader variables in any process."""

from __future__ import annotations

from checker.checks import COMPROMISE, Context, Finding, check

SECTIONS = ("cron", "systemd", "startup", "hooks")
# A change in any of these means what runs, or as whom.
CONTENT = {"content_sha256", "sha256", "target_sha256", "size", "link_target", "type"}
OWNERSHIP = {"mode", "uid", "gid"}
# Installed by packages, so updates change them: a change matters less.
VENDOR = ("/usr/lib/", "/lib/", "/usr/share/")
AT_SPOOLS = ("/var/spool/at/", "/var/spool/cron/atjobs/")
HOMES = ("/home/", "/root/")


def _band(path: str, installing: bool) -> str:
    """High for the loader's own configuration; low for a file packages
    install when the package lists changed too (an update); else medium."""
    if path in ("/etc/ld.so.preload", "/etc/ld.so.conf"):
        return "high"
    if path.startswith(VENDOR) and installing:
        return "low"
    return "medium"


def _installing(context: Context) -> bool:
    """Whether packages were installed or updated since the baseline (their
    checksum lists changed)."""
    diff = context.changes("checksum_store") or {}
    return any(diff.get(kind) for kind in ("added", "changed", "removed"))


def _in_home(path: str, item: dict) -> bool:
    # Collected from a home directory (wherever it is), or under /home, /root.
    return bool(item.get("home")) or path.startswith(HOMES)


def _is_file(item: dict) -> bool:
    return item.get("type") != "d"


def _transient_scope(path: str) -> bool:
    # Every login and `systemd-run --scope` makes one: only services and
    # timers made at run time are a way to keep something running.
    return path.startswith("/run/systemd/transient/") and not path.endswith(
        (".service", ".timer", ".socket", ".path")
    )


@check("persistence.ld_preload", "/etc/ld.so.preload and loader variables in processes")
def ld_preload(context: Context) -> list[Finding]:
    findings = []
    item = context.items("startup").get("/etc/ld.so.preload")
    if item is not None and _is_file(item) and (item.get("size") or 0) > 0:
        findings.append(
            Finding(
                "persistence.ld_preload",
                "/etc/ld.so.preload loads a library into every program",
                COMPROMISE,
                "high",
                f"/etc/ld.so.preload ({item.get('size')} bytes)",
                ["path:/etc/ld.so.preload"],
                [{"item": ["startup", "/etc/ld.so.preload"]}],
            )
        )
    for process in context.snapshot.live.get("processes", []):
        loader = process.get("loader_environment") or {}
        risky = {k: v for k, v in loader.items() if k in ("LD_PRELOAD", "LD_AUDIT")}
        if not risky:
            continue
        pid = process.get("pid")
        findings.append(
            Finding(
                "persistence.ld_preload",
                "A process runs with LD_PRELOAD or LD_AUDIT",
                COMPROMISE,
                "high",
                f"{process.get('comm')} (pid {pid}): "
                + ", ".join(f"{k}={v}" for k, v in sorted(risky.items())),
                [f"program:{process.get('comm')}", f"pid:{pid}"],
                [{"live": ["processes", pid]}],
            )
        )
    return findings


@check(
    "persistence.changes",
    "New and changed cron, systemd, start-up and hook files",
    needs_baseline=True,
)
def changes(context: Context) -> list[Finding]:
    findings = []
    installing = _installing(context)
    for section in SECTIONS:
        diff = context.changes(section)
        uncertain = context.uncertain(section)
        for path, item in diff["added"].items():
            if not _is_file(item) or _transient_scope(path):
                continue
            findings.append(
                Finding(
                    "persistence.changes",
                    f"A new {section} file",
                    COMPROMISE,
                    _band(path, installing),
                    path,
                    [f"path:{path}"],
                    [context.change_ref(section, path, "added")],
                    new=context.new_since_previous(section, path),
                    uncertain=uncertain,
                )
            )
        for path, fields in diff["changed"].items():
            current = context.items(section).get(path, {})
            if not _is_file(current):
                continue
            what = sorted(set(fields) & (CONTENT | OWNERSHIP))
            if not what:
                continue  # only its times or inode: touched, not changed
            findings.append(
                Finding(
                    "persistence.changes",
                    f"A {section} file changed",
                    COMPROMISE,
                    _band(path, installing),
                    f"{path}: {', '.join(what)}",
                    [f"path:{path}"],
                    [context.change_ref(section, path, "changed")],
                    new=context.new_since_previous(section, path),
                    uncertain=uncertain,
                )
            )
    return findings


@check("persistence.at_jobs", "Queued at jobs")
def at_jobs(context: Context) -> list[Finding]:
    findings = []
    for path, item in context.items("cron").items():
        name = path.rsplit("/", 1)[-1]
        if path.startswith(AT_SPOOLS) and _is_file(item) and not name.startswith("."):
            findings.append(
                Finding(
                    "persistence.at_jobs",
                    "A queued at job",
                    COMPROMISE,
                    "medium",
                    f"{path} (owner UID {item.get('uid')})",
                    [f"path:{path}"],
                    [{"item": ["cron", path]}],
                )
            )
    return findings


@check("persistence.homes", "User units, autostart entries and lingering users")
def homes(context: Context) -> list[Finding]:
    """Home files are hashes only by default (policy §7), so a first look
    can only name them; later analyses report any change."""
    findings = []
    for path, item in context.items("systemd").items():
        if _in_home(path, item) and _is_file(item) and "/systemd/user" in path:
            findings.append(
                Finding(
                    "persistence.homes",
                    "A user's own systemd unit",
                    COMPROMISE,
                    "info",
                    path,
                    [f"path:{path}"],
                    [{"item": ["systemd", path]}],
                )
            )
        elif path.startswith("/var/lib/systemd/linger/") and _is_file(item):
            user = path.rsplit("/", 1)[-1]
            findings.append(
                Finding(
                    "persistence.homes",
                    "A user's units start at boot (linger)",
                    COMPROMISE,
                    "low",
                    user,
                    [f"account:{user}"],
                    [{"item": ["systemd", path]}],
                )
            )
    for path, item in context.items("startup").items():
        if _in_home(path, item) and _is_file(item) and "/.config/autostart/" in path:
            findings.append(
                Finding(
                    "persistence.homes",
                    "A user's autostart entry",
                    COMPROMISE,
                    "info",
                    path,
                    [f"path:{path}"],
                    [{"item": ["startup", path]}],
                )
            )
    return findings
