"""Kernel and system health (DESIGN.md §8.1)."""

from __future__ import annotations

from collections import defaultdict

from checker.checks import COMPROMISE, HYGIENE, Context, Finding, check, span

# Services whose loss blinds or weakens defence: their OOM kill matters more.
SECURITY_SERVICES = {
    "sshd",
    "auditd",
    "rsyslogd",
    "syslog-ng",
    "systemd-journal",
    "systemd-journald",
    "fail2ban-server",
    "crowdsec",
    "wazuh-agentd",
    "ossec-agentd",
    "falco",
    "osqueryd",
    "auditbeat",
    "filebeat",
    "clamd",
    "firewalld",
}
REPEATED = 3  # segfaults of one program before they look like attempts

# /proc/sys/kernel/tainted bits (Documentation/admin-guide/tainted-kernels).
TAINT_BITS = {
    0: ("P", "proprietary module loaded"),
    1: ("F", "module force-loaded"),
    2: ("S", "kernel running on an out-of-spec system"),
    3: ("R", "module force-unloaded"),
    4: ("M", "machine check exception"),
    5: ("B", "bad page referenced"),
    6: ("U", "taint requested by user space"),
    7: ("D", "kernel died recently (oops or BUG)"),
    8: ("A", "ACPI table overridden"),
    9: ("W", "kernel warning"),
    10: ("C", "staging driver loaded"),
    11: ("I", "platform firmware bug worked around"),
    12: ("O", "out-of-tree module loaded"),
    13: ("E", "unsigned module loaded"),
    14: ("L", "soft lockup"),
    15: ("K", "kernel live-patched"),
    16: ("X", "auxiliary taint"),
    17: ("T", "built with struct randomization"),
    18: ("N", "in-kernel test"),
}
MODULE_FLAGS = {"P", "F", "R", "O", "E"}  # set by loading or unloading a module


def taint_flags(value) -> set[str]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return set()
    return {flag for bit, (flag, _) in TAINT_BITS.items() if number >> bit & 1}


def describe(flags: set[str]) -> str:
    names = {flag: text for flag, text in TAINT_BITS.values()}
    return "; ".join(f"{flag}: {names[flag]}" for flag in sorted(flags))


def network_programs(context: Context) -> set[str]:
    return {p for item in context.items("listeners").values() for p in item.get("programs", [])}


@check("kernel.oom_kill", "Out-of-memory kills")
def oom_kills(context: Context) -> list[Finding]:
    by_program = defaultdict(list)
    for index, event in context.of("kernel.oom_kill"):
        by_program[event.fields.get("comm", "?")].append((index, event))
    findings = []
    for program, hits in sorted(by_program.items()):
        security = program in SECURITY_SERVICES
        first, last = span([e for _, e in hits])
        findings.append(
            Finding(
                "kernel.oom_kill",
                "A security or logging service was killed for lack of memory"
                if security
                else "Processes were killed for lack of memory",
                COMPROMISE if security else HYGIENE,
                "medium" if security else "low",
                f"{program}: killed {len(hits)} time(s)",
                [f"program:{program}"],
                [{"event": i} for i, _ in hits],
                first,
                last,
            )
        )
    return findings


@check("kernel.segfault", "Segfaults, repeated or in network-facing services")
def segfaults(context: Context) -> list[Finding]:
    by_program = defaultdict(list)
    for index, event in context.of("kernel.segfault"):
        by_program[event.fields.get("comm", "?")].append((index, event))
    exposed = network_programs(context)
    findings = []
    for program, hits in sorted(by_program.items()):
        facing = program in exposed
        if not facing and len(hits) < REPEATED:
            continue
        first, last = span([e for _, e in hits])
        repeated = len(hits) >= REPEATED
        findings.append(
            Finding(
                "kernel.segfault",
                "A network-facing service crashed repeatedly"
                if facing and repeated
                else "A network-facing service crashed"
                if facing
                else "A program crashed repeatedly",
                COMPROMISE if facing else HYGIENE,
                "medium" if facing and repeated else "low",
                f"{program}: {len(hits)} segfault(s)"
                + (" (it holds a listening socket)" if facing else ""),
                [f"program:{program}"],
                [{"event": i} for i, _ in hits],
                first,
                last,
            )
        )
    return findings


@check("kernel.errors", "Kernel oopses, hung tasks and machine checks")
def kernel_errors(context: Context) -> list[Finding]:
    kinds = {
        "kernel.oops": ("Kernel oops or BUG", COMPROMISE, "low"),
        "kernel.hung_task": ("Hung tasks", HYGIENE, "low"),
        "kernel.machine_check": ("Hardware machine-check errors", HYGIENE, "low"),
    }
    findings = []
    for kind, (title, category, band) in kinds.items():
        hits = list(context.of(kind))
        if not hits:
            continue
        first, last = span([e for _, e in hits])
        findings.append(
            Finding(
                "kernel.errors",
                title,
                category,
                band,
                f"{len(hits)} message(s)",
                [],
                [{"event": i} for i, _ in hits],
                first,
                last,
            )
        )
    return findings


@check("kernel.taint", "Kernel taint: out-of-tree or unsigned modules, taint changes")
def kernel_taint(context: Context) -> list[Finding]:
    findings = []
    host = context.items("host")
    flags = taint_flags((host.get("kernel_taint") or {}).get("value"))
    modules = context.items("kernel_modules")
    module_flags = {f for item in modules.values() for f in str(item.get("taint") or "")}
    # A module flag with no loaded module to explain it: the module may
    # have hidden itself from the module list (a rootkit).
    unexplained = (flags & MODULE_FLAGS & {"O", "E", "P"}) - module_flags
    if unexplained and modules:
        # A tainting load in the logs of a module no longer loaded explains
        # it innocently (taint stays until reboot); without one, it doesn't.
        gone = sorted(
            {e.fields.get("module", "?") for _, e in context.of("kernel.module_taint")}
            - set(modules)
        )
        findings.append(
            Finding(
                "kernel.taint",
                "Kernel taint that no loaded module explains",
                COMPROMISE,
                "medium" if gone else "high",
                f"tainted by a module ({describe(unexplained)}), but no listed module carries"
                " that flag: "
                + (
                    f"the logs show {', '.join(gone)} loaded and since unloaded"
                    if gone
                    else "a module may be hiding itself from the module list"
                ),
                [],
                [{"item": ["host", "kernel_taint"]}],
                uncertain=context.uncertain("kernel_modules"),
            )
        )
    # Changes since the baseline.
    diff = context.changes("host")
    if diff is not None:
        change = diff["changed"].get("kernel_taint", {}).get("value")
        if change:
            new = taint_flags(change[1]) - taint_flags(change[0])
            if new:
                findings.append(
                    Finding(
                        "kernel.taint",
                        "The kernel became tainted since the baseline",
                        COMPROMISE,
                        "high" if new & MODULE_FLAGS else "low",
                        f"new taint: {describe(new)}",
                        [],
                        [context.change_ref("host", "kernel_taint", "changed")],
                        new=context.new_since_previous("host", "kernel_taint"),
                    )
                )
    added = (context.changes("kernel_modules") or {}).get("added", {})
    for name, item in sorted(modules.items()):
        taint = set(str(item.get("taint") or "")) & {"O", "E", "P", "F"}
        if not taint:
            continue
        # Reported on every analysis, not only when new: the baseline's own
        # bundle may never have been analysed.
        is_new = name in added
        findings.append(
            Finding(
                "kernel.taint",
                "An out-of-tree, unsigned or proprietary kernel module "
                + ("was loaded since the baseline" if is_new else "is loaded"),
                COMPROMISE,
                "high" if is_new else "medium",
                f"{name}: {describe(taint)}",
                [f"module:{name}"],
                [
                    context.change_ref("kernel_modules", name, "added")
                    if is_new
                    else {"item": ["kernel_modules", name]}
                ],
                new=is_new and context.new_since_previous("kernel_modules", name),
            )
        )
    # The logs' own account of a tainting load (a module since unloaded too).
    for index, event in context.of("kernel.module_taint"):
        name = event.fields.get("module", "?")
        findings.append(
            Finding(
                "kernel.taint",
                "The kernel log shows a tainting module load",
                COMPROMISE,
                "medium",
                f"{name}: {event.line[:160]}",
                [f"module:{name}"],
                [{"event": index}],
                event.corrected,
                event.corrected,
            )
        )
    return findings


@check("kernel.core_dump", "Core dumps of network-facing services")
def core_dumps(context: Context) -> list[Finding]:
    exposed = network_programs(context)
    findings = []
    for index, event in context.of("process.core_dump"):
        program = event.fields.get("comm", "?")
        facing = program in exposed
        findings.append(
            Finding(
                "kernel.core_dump",
                "A network-facing service dumped core" if facing else "A process dumped core",
                COMPROMISE if facing else HYGIENE,
                "medium" if facing else "info",
                f"{program} (pid {event.fields.get('pid')})",
                [f"program:{program}"],
                [{"event": index}],
                event.corrected,
                event.corrected,
            )
        )
    for path in sorted((context.changes("crash_dumps") or {}).get("added", {})):
        findings.append(
            Finding(
                "kernel.core_dump",
                "A new crash dump file",
                HYGIENE,
                "low",
                path,
                [f"path:{path}"],
                [context.change_ref("crash_dumps", path, "added")],
                new=context.new_since_previous("crash_dumps", path),
            )
        )
    return findings
