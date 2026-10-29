"""Live process state (DESIGN.md §8.7): ★ processes running from deleted
or memory-only files, from scratch directories, posing as kernel threads,
hidden from /proc's listing; ★ shells talking to a network socket; miners;
code mapped from deleted or memory-only files."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import datetime

from checker.checks import COMPROMISE, HYGIENE, Context, Finding, check

# Places anyone can write: /dev/mqueue and /run/lock are world-writable too.
SCRATCH = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/dev/mqueue/",
    "/run/lock/",
    "/var/lock/",
    "/var/crash/",
    "/run/user/",
)
SYSTEM = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/opt/")
HOMES = ("/home/", "/root/")
SHELLS = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "fish",
    "ash",
    "busybox",
    "perl",
    "ruby",
    "php",
    "lua",
    "awk",
    "gawk",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
}
MINERS = {"xmrig", "xmr-stak", "kdevtmpfsi", "kinsing", "minerd", "cpuminer", "ccminer", "nbminer"}
MINING_PORTS = {3333, 4444, 5555, 6666, 7777, 8888, 9999, 14433, 14444, 45560, 45700}
BUSY = 0.5  # CPU seconds per second of life: half a core, sustained
SETTLED = 600  # seconds alive before a CPU share means anything


def _is_shell(process: dict) -> bool:
    """By its name, its program's name, or its argv[0]: a copied bash
    called httpd still runs as bash."""
    names = {
        str(process.get("comm") or ""),
        str(process.get("exe") or "").removesuffix(" (deleted)").rsplit("/", 1)[-1],
        str(process.get("cmdline") or "").split(" ", 1)[0].rsplit("/", 1)[-1].lstrip("-"),
    }
    return any(n in SHELLS or n.startswith("python") for n in names)


def _updated_since(context: Context, process: dict, mapping: str | None = None) -> bool:
    """Whether the package lists changed after the process loaded the
    deleted file (its program, or `mapping`): then an update replaced it
    under the process. A process forked without a new program ((sd-pam)
    from systemd) inherits what an ancestor loaded — but only an ancestor
    that has the very same deleted file loaded proves it; one that runs
    the same program may have started it afresh (sshd re-executes itself
    for each connection), so then the process's own start counts."""
    times = [
        str(item.get("mtime"))
        for item in context.items("checksum_store").values()
        if item.get("mtime")
    ]
    processes = {p.get("pid"): p for p in context.snapshot.live.get("processes", [])}

    def holds(candidate: dict) -> bool:
        # A fork without a new program (the same exe), holding the file too:
        # one that started a program loaded its libraries afresh.
        exe = str(candidate.get("exe") or "")
        same_program = bool(exe) and exe == str(process.get("exe") or "")
        if mapping is not None:
            return same_program and mapping in (candidate.get("suspicious_mappings") or [])
        return same_program

    starts, current, seen = [process.get("start_time")], process, set()
    while current.get("ppid") in processes and current.get("ppid") not in seen:
        seen.add(current.get("ppid"))
        current = processes[current.get("ppid")]
        if not holds(current):
            break  # the chain of inheritance stops here
        starts.append(current.get("start_time"))
    # (sd-pam) is forked from PID 1's child before it becomes the user
    # manager: it holds what PID 1 loaded, though its listed parent (the
    # user manager, a fresh program) doesn't.
    first = processes.get(1)
    if first is not None and first is not process and holds(first):
        starts.append(first.get("start_time"))
    try:
        loaded = min(datetime.fromisoformat(str(t)) for t in starts if t)
        return any(datetime.fromisoformat(t) > loaded for t in times)
    except ValueError:
        return False


# The collector as sudo runs it: python -I -B - (or -c with the bootstrap).
COLLECTOR = re.compile(r"(?:^|/)python[\d.]*\s+-I\s+-B\s+-(?:c\b|\s|$)")


def own_processes(context: Context) -> set[int]:
    """The tool's own processes: its sshd session process and everything
    under it. Found from the running collector (root, its exact command
    line), up its parents to the sshd session process — which must be one
    whose login the logs show as the tool's own, and a child of the sshd
    listener. A forged log line alone can't make anything the tool's own:
    it would have to name a session that really runs the collector."""
    logged = {
        e.fields.get("pid")
        for e in context.events
        if e.own_session and e.type == "ssh.login.accepted" and isinstance(e.fields.get("pid"), int)
    }
    processes = {p.get("pid"): p for p in context.snapshot.live.get("processes", [])}
    roots = set()
    for process in processes.values():
        uids = process.get("uids") or []
        if not COLLECTOR.search(str(process.get("cmdline") or "")) or (uids[1:2] or [None])[0] != 0:
            continue
        seen, pid = set(), process.get("ppid")
        while pid in processes and pid not in seen and pid != 1:
            seen.add(pid)
            current = processes[pid]
            parent = processes.get(current.get("ppid"), {})
            if (
                pid in logged
                and str(current.get("comm") or "").startswith("sshd")
                and str(parent.get("comm") or "").startswith("sshd")
            ):
                roots.add(pid)
                break
            pid = current.get("ppid")
    children = defaultdict(list)
    for process in processes.values():
        children[process.get("ppid")].append(process.get("pid"))
    own, stack = set(), list(roots)
    while stack:
        pid = stack.pop()
        if pid in own:
            continue
        own.add(pid)
        stack.extend(children.get(pid, []))
    return own


def _processes(context: Context):
    own = own_processes(context)
    for process in context.snapshot.live.get("processes", []):
        if process.get("pid") not in own:
            yield process


def _finding(check_id, title, band, process, detail, category=COMPROMISE) -> Finding:
    pid = process.get("pid")
    comm = process.get("comm") or "?"
    exe = str(process.get("exe") or "")
    return Finding(
        check_id,
        title,
        category,
        band,
        f"{comm} (pid {pid}): {detail}",
        # comm is a name the process chose; exe is the file it runs.
        [f"program:{comm}", f"pid:{pid}"] + ([f"exe:{exe}"] if exe else []),
        [{"live": ["processes", pid]}],
        process.get("start_time"),
        process.get("start_time"),
        uncertain=None,
    )


@check("process.hidden", "Processes hidden from /proc's listing")
def hidden(context: Context) -> list[Finding]:
    return [
        _finding(
            "process.hidden",
            "A process hidden from /proc's listing (what ps sees)",
            "critical",
            p,
            f"answers a direct lookup but isn't listed; exe {p.get('exe')},"
            f" command {str(p.get('cmdline') or '')[:120]}",
        )
        for p in _processes(context)
        if p.get("hidden")
    ]


@check(
    "process.executable",
    "Processes running from deleted, memory-only or scratch files, or posing as kernel threads",
)
def executable(context: Context) -> list[Finding]:
    findings = []
    for p in _processes(context):
        exe = str(p.get("exe") or "")
        path = exe.removesuffix(" (deleted)")
        if p.get("exe_memfd"):
            findings.append(
                _finding("process.executable", "A process running from memory only", "high", p, exe)
            )
        elif path.startswith(SCRATCH):
            findings.append(
                _finding(
                    "process.executable",
                    "A process running from a scratch directory",
                    "high",
                    p,
                    exe,
                )
            )
        elif p.get("exe_deleted"):
            if path.startswith(HOMES):
                findings.append(
                    _finding(
                        "process.executable", "A process whose program was deleted", "high", p, exe
                    )
                )
            elif path.startswith(SYSTEM) and _updated_since(context, p):
                # A package update replaced it under a running service.
                findings.append(
                    _finding(
                        "process.executable",
                        "A process still running a replaced program (restart it after the update)",
                        "low",
                        p,
                        exe,
                        HYGIENE,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "process.executable",
                        "A process whose program was deleted",
                        "medium",
                        p,
                        exe,
                    )
                )
        cmdline = str(p.get("cmdline") or "").strip()
        name = cmdline or str(p.get("comm") or "")
        if not p.get("kernel_thread") and name.startswith("[") and name.endswith("]") and exe:
            findings.append(
                _finding(
                    "process.executable",
                    "A process posing as a kernel thread",
                    "high",
                    p,
                    f"called {name!r} but runs {exe}",
                )
            )
    return findings


@check("process.reverse_shell", "Shells whose input or output is a network socket")
def reverse_shell(context: Context) -> list[Finding]:
    network = {
        str(s.get("inode")): s
        for s in context.snapshot.live.get("sockets", [])
        if str(s.get("protocol") or "").startswith(("tcp", "udp"))
    }
    findings = []
    for p in _processes(context):
        streams = p.get("std_streams") or {}
        stdin, stdout = (streams.get(fd) or {} for fd in ("0", "1"))
        same = (
            stdin.get("kind") == stdout.get("kind") == "socket"
            and stdin.get("inode") == stdout.get("inode")
            and str(stdin.get("inode")) in network
        )
        if not _is_shell(p) and not same:
            continue
        for fd, stream in sorted(streams.items()):
            sock = network.get(str(stream.get("inode")))
            if stream.get("kind") != "socket" or sock is None:
                continue
            remote = sock.get("remote") or ["?", "?"]
            findings.append(
                _finding(
                    "process.reverse_shell",
                    "A shell talking to a network socket (a reverse shell)",
                    "high",
                    p,
                    f"{'stdin' if fd == '0' else 'stdout' if fd == '1' else 'stderr'} is"
                    f" {sock.get('protocol')} to {remote[0]}:{remote[1]}",
                )
            )
            break
    return findings


def _global(address) -> bool:
    try:
        return ipaddress.ip_address(str(address)).is_global
    except ValueError:
        return False


def _alive_seconds(process: dict, now: datetime | None) -> float | None:
    try:
        started = datetime.fromisoformat(str(process.get("start_time")))
    except ValueError:
        return None
    return (now - started).total_seconds() if now else None


@check("process.miner", "Cryptocurrency miners")
def miner(context: Context) -> list[Finding]:
    try:
        now = datetime.fromisoformat(str(context.snapshot.meta.get("host_time")))
    except ValueError:
        now = None
    ports_of = defaultdict(set)
    for s in context.snapshot.live.get("sockets", []):
        remote = s.get("remote") or []
        if (
            len(remote) == 2
            and str(s.get("state") or "").lower() == "established"
            and _global(remote[0])
        ):
            for pid in s.get("pids") or []:
                ports_of[pid].add(remote[1])
    findings = []
    for p in _processes(context):
        names = {str(p.get("comm") or ""), str(p.get("exe") or "").rsplit("/", 1)[-1]}
        if names & MINERS:
            findings.append(
                _finding("process.miner", "A known miner is running", "high", p, str(p.get("exe")))
            )
            continue
        alive = _alive_seconds(p, now)
        if not alive or alive < SETTLED:
            continue
        share = (p.get("cpu_seconds") or 0) / alive
        pool = ports_of.get(p.get("pid"), set()) & MINING_PORTS
        if share >= BUSY and pool:
            findings.append(
                _finding(
                    "process.miner",
                    "Sustained high CPU with a connection to a mining-pool port",
                    "high",
                    p,
                    f"{share:.1f} cores on average, connected to port(s)"
                    f" {', '.join(map(str, sorted(pool)))}",
                )
            )
    return findings


@check(
    "process.injected",
    "Code mapped from deleted, memory-only or scratch files",
    variants=("scratch", "deleted", "libffi", "memory", "replaced"),
)
def injected(context: Context) -> list[Finding]:
    """A library injected with dlopen or ptrace shows as an executable
    mapping from a scratch place, a deleted file or a memory-only one. A
    system library deleted under a running service is an update the
    service hasn't been restarted for."""
    findings = []
    for p in _processes(context):
        paths = sorted({str(m) for m in p.get("suspicious_mappings") or []})
        if not paths:
            continue
        bare = [x.removesuffix(" (deleted)") for x in paths]
        replaced = all(
            _updated_since(context, p, mapping)
            for mapping in paths
            if mapping.removesuffix(" (deleted)").startswith(SYSTEM)
        )
        if any(x.startswith(SCRATCH + HOMES) for x in bare):
            title, band, category, variant = (
                "A process has code mapped from a scratch or home file",
                "high",
                COMPROMISE,
                "scratch",
            )
        elif any(not x.startswith((*SYSTEM, "/memfd:")) for x in bare) or (
            not replaced and any(x.startswith(SYSTEM) for x in bare)
        ):
            title, band, category, variant = (
                "A process has code mapped from a deleted file",
                "high",
                COMPROMISE,
                "deleted",
            )
        elif all(x.startswith("/memfd:libffi") for x in bare):
            # libffi makes its closures this way (firewalld on RHEL); the
            # name is the creator's choice, so it isn't dropped.
            title, band, category, variant = (
                "A process has libffi code mapped from memory only",
                "low",
                COMPROMISE,
                "libffi",
            )
        elif any(x.startswith("/memfd:") for x in bare):
            # JITs and libffi use memory-only code too, so less sure.
            title, band, category, variant = (
                "A process has code mapped from memory only",
                "medium",
                COMPROMISE,
                "memory",
            )
        else:
            title, band, category, variant = (
                "A process still uses replaced system libraries (restart it after the update)",
                "low",
                HYGIENE,
                "replaced",
            )
        finding = _finding("process.injected", title, band, p, ", ".join(paths[:5]), category)
        finding.variant = variant
        findings.append(finding)
    return findings
