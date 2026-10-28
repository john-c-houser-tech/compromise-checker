"""Live process state (DESIGN.md §8.7): ★ processes running from deleted
or memory-only files, from scratch directories, posing as kernel threads,
hidden from /proc's listing; ★ shells talking to a network socket; miners;
code mapped from deleted or memory-only files."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from checker.checks import COMPROMISE, HYGIENE, Context, Finding, check

SCRATCH = ("/tmp/", "/var/tmp/", "/dev/shm/")  # noqa: S108 - places on the target, as data
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


def _is_shell(comm: str) -> bool:
    return comm in SHELLS or comm.startswith("python")


def own_processes(context: Context) -> set[int]:
    """The tool's own: its sshd process and everything it started (sudo,
    the collector), from the PIDs its own SSH login was logged with."""
    roots = {
        e.fields.get("pid")
        for e in context.events
        if e.own_session and e.type == "ssh.login.accepted" and isinstance(e.fields.get("pid"), int)
    }
    children = defaultdict(list)
    for process in context.snapshot.live.get("processes", []):
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
    return Finding(
        check_id,
        title,
        category,
        band,
        f"{comm} (pid {pid}): {detail}",
        [f"program:{comm}", f"pid:{pid}"],
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
            "high",
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
            elif path.startswith(("/usr/", "/bin/", "/sbin/", "/lib", "/opt/")):
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
        comm = str(p.get("comm") or "")
        if not _is_shell(comm):
            continue
        for fd, stream in sorted((p.get("std_streams") or {}).items()):
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
        if len(remote) == 2 and str(s.get("state") or "").lower() == "established":
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


@check("process.injected", "Code mapped from deleted, memory-only or scratch files")
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
        if any(x.startswith(SCRATCH + HOMES) for x in bare):
            title, band, category = (
                "A process has code mapped from a scratch or home file",
                "high",
                COMPROMISE,
            )
        elif any(not x.startswith(("/usr/", "/lib", "/opt/", "/memfd:")) for x in bare):
            title, band, category = (
                "A process has code mapped from a deleted file",
                "high",
                COMPROMISE,
            )
        elif any(x.startswith("/memfd:") for x in bare):
            # JITs and libffi use memory-only code too, so less sure.
            title, band, category = (
                "A process has code mapped from memory only",
                "medium",
                COMPROMISE,
            )
        else:
            title, band, category = (
                "A process still uses replaced system libraries (restart it after the update)",
                "low",
                HYGIENE,
            )
        findings.append(
            _finding("process.injected", title, band, p, ", ".join(paths[:5]), category)
        )
    return findings
