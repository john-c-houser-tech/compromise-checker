"""Network and data transfer (DESIGN.md §8.8): new listeners and
destinations, the cloud metadata address, directory services reached from
web-server accounts, SSH tunnels, resolver and firewall changes, interfaces
in promiscuous mode, and weak signs of data leaving.

Connections are a sample: only those open when the collector looked.
Without firewall or proxy logs, transfer evidence is weak, and the
findings say so."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from checker.checks import COMPROMISE, Context, Finding, check
from checker.checks.processes import own_processes

METADATA = "169.254.169.254"
# Programs that talk to a cloud's metadata service for a living.
CLOUD_AGENTS = {
    "cloud-init",
    "amazon-ssm-agen",  # comm is cut at 15 characters
    "amazon-ssm-agent",
    "ssm-agent-worke",
    "google_guest_ag",
    "google_guest_agent",
    "google_osconfig",
    "waagent",
    "walinuxagent",
    "qemu-ga",
    "linode-agent",
    "oci-utils",
    "aliyun-service",
}
# Directory services a web tier has no business reaching (§8.8 ★).
DIRECTORY_PORTS = {
    445: "SMB",
    389: "LDAP",
    636: "LDAPS",
    88: "Kerberos",
    3268: "LDAP GC",
    3269: "LDAP GC",
    5985: "WinRM",
    5986: "WinRM",
}
WEB_USERS = {"www-data", "apache", "nginx", "httpd", "lighttpd", "wwwrun"}
TOR_PORTS = {9001, 9030, 9050, 9051, 9150}
CAPTURE_TOOLS = {
    "tcpdump",
    "dumpcap",
    "tshark",
    "wireshark",
    "suricata",
    "zeek",
    "snort",
    "ntopng",
    "darkstat",
    "iftop",
    "nethogs",
    "arpwatch",
    "keepalived",
}
DOWNLOADERS = {
    "curl",
    "wget",
    "scp",
    "sftp",
    "rsync",
    "rclone",
    "ftp",
    "lftp",
    "nc",
    "ncat",
    "socat",
    "aria2c",
}
ARCHIVE = re.compile(r"\.(?:zip|tar|tgz|tar\.gz|tar\.bz2|tar\.xz|tbz2|txz|7z|rar|gz|xz|bz2)$")
LARGE_ARCHIVE = 50 * 1024 * 1024
SSH_FORWARD = re.compile(r"(?:^|\s)-[a-zA-Z]*[LRD](?:\s|\d|$)")


def _accounts_by_uid(context: Context) -> dict[int, str]:
    return {
        item.get("uid"): name.split(" ", 1)[0]
        for name, item in context.items("accounts").items()
        if isinstance(item.get("uid"), int)
    }


def _processes(context: Context) -> dict[int, dict[str, Any]]:
    own = own_processes(context)
    return {
        p["pid"]: p
        for p in context.snapshot.live.get("processes", [])
        if isinstance(p.get("pid"), int) and p["pid"] not in own
    }


# Documentation ranges never carry real traffic; they stand in for public
# addresses in tests and in the golden cases, whose real public addresses
# are replaced by them (tests/integration/golden.py).
DOCUMENTATION = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return parsed.is_global or any(
        parsed.version == n.version and parsed in n for n in DOCUMENTATION
    )


def _open(sock: dict[str, Any]) -> bool:
    remote = sock.get("remote") or []
    return (
        str(sock.get("protocol") or "").startswith("tcp")
        and len(remote) == 2
        and bool(remote[1])
        and str(sock.get("state") or "").lower() in ("established", "syn_sent")
    )


def _holders(sock, processes):
    return [processes[pid] for pid in sock.get("pids") or [] if pid in processes]


def _name(process: dict[str, Any]) -> str:
    return str(process.get("comm") or "?")


def _user(process, users) -> str:
    uids = process.get("uids") or []
    effective = uids[1] if len(uids) > 1 else (uids[0] if uids else None)
    return users.get(effective, str(effective))


def _socket_finding(check_id, title, band, process, sock, detail, variant, users):
    remote = sock.get("remote") or ["?", "?"]
    pid = process.get("pid")
    exe = str(process.get("exe") or "")
    return Finding(
        check_id,
        title,
        COMPROMISE,
        band,
        f"{_name(process)} (pid {pid}, {_user(process, users)}): {detail}"
        f" {remote[0]} port {remote[1]}, {sock.get('state')}",
        [f"program:{_name(process)}", f"pid:{pid}", f"address:{remote[0]}"]
        + ([f"exe:{exe}"] if exe else [])
        + [f"account:{_user(process, users)}"],
        [{"live": ["processes", pid]}],
        process.get("start_time"),
        process.get("start_time"),
        variant=variant,
    )


@check("net.listener", "New listening ports", needs_baseline=True)
def listeners(context: Context) -> list[Finding]:
    diff = context.changes("listeners")
    uncertain = context.uncertain("listeners")
    return [
        Finding(
            "net.listener",
            "A new listening port",
            COMPROMISE,
            "low",
            f"{key}: {', '.join(item.get('programs') or ['?'])}",
            [f"program:{p}" for p in item.get("programs") or []],
            [context.change_ref("listeners", key, "added")],
            new=context.new_since_previous("listeners", key),
            uncertain=uncertain,
        )
        for key, item in diff["added"].items()
    ]


@check(
    "net.peer",
    "New outgoing destinations; Tor",
    needs_baseline=True,
    variants=("new_destination", "tor"),
)
def peers(context: Context) -> list[Finding]:
    diff = context.changes("peers")
    uncertain = context.uncertain("peers")
    findings = []
    for key, item in diff["added"].items():
        port = int(key.rsplit(" ", 1)[-1]) if key.rsplit(" ", 1)[-1].isdigit() else None
        tor = port in TOR_PORTS or item.get("program") == "tor"
        findings.append(
            Finding(
                "net.peer",
                "An outgoing connection over a Tor port" if tor else "A new outgoing destination",
                COMPROMISE,
                "medium" if tor else "low",
                f"{key} (open at collection)",
                [f"program:{item.get('program')}"],
                [context.change_ref("peers", key, "added")],
                new=context.new_since_previous("peers", key),
                uncertain=uncertain,
                variant="tor" if tor else "new_destination",
            )
        )
    return findings


@check("net.metadata", "The cloud metadata address reached by an unexpected program")
def metadata(context: Context) -> list[Finding]:
    processes, users = _processes(context), _accounts_by_uid(context)
    findings = []
    for sock in context.snapshot.live.get("sockets", []):
        remote = sock.get("remote") or []
        if not _open(sock) or str(remote[0]) not in (METADATA, f"::ffff:{METADATA}"):
            continue
        for process in _holders(sock, processes):
            if _name(process) in CLOUD_AGENTS:
                continue
            findings.append(
                _socket_finding(
                    "net.metadata",
                    "A program other than the cloud agent reached the metadata address",
                    "medium",
                    process,
                    sock,
                    "connected to",
                    None,
                    users,
                )
            )
    return findings


@check("net.directory", "Directory services reached from a web-server account")
def directory(context: Context) -> list[Finding]:
    """★ A web worker reaching SMB, LDAP, Kerberos or WinRM: the way from a
    web shell into a Windows domain. Judged by the process's account, not a
    host role, so a domain-joined server's own lookups don't count."""
    processes, users = _processes(context), _accounts_by_uid(context)
    findings = []
    for sock in context.snapshot.live.get("sockets", []):
        remote = sock.get("remote") or []
        if not _open(sock) or remote[1] not in DIRECTORY_PORTS:
            continue
        for process in _holders(sock, processes):
            if _user(process, users) not in WEB_USERS:
                continue
            findings.append(
                _socket_finding(
                    "net.directory",
                    f"A web-server account reached {DIRECTORY_PORTS[remote[1]]}",
                    "high",
                    process,
                    sock,
                    "connected to",
                    None,
                    users,
                )
            )
    return findings


@check("net.tunnel", "SSH tunnels: forwarding clients and sessions holding listeners")
def tunnels(context: Context) -> list[Finding]:
    processes, users = _processes(context), _accounts_by_uid(context)
    findings = []
    for process in processes.values():
        cmdline = str(process.get("cmdline") or "")
        program = cmdline.split(" ", 1)[0].rsplit("/", 1)[-1]
        if program == "ssh" and SSH_FORWARD.search(cmdline):
            findings.append(
                Finding(
                    "net.tunnel",
                    "An SSH client forwarding ports (a tunnel)",
                    COMPROMISE,
                    "medium",
                    f"ssh (pid {process.get('pid')}, {_user(process, users)}): {cmdline[:160]}",
                    [
                        f"pid:{process.get('pid')}",
                        "program:ssh",
                        f"account:{_user(process, users)}",
                    ],
                    [{"live": ["processes", process.get("pid")]}],
                    process.get("start_time"),
                    process.get("start_time"),
                    variant=None,
                )
            )
    # A remote forward (ssh -R into this host): an sshd session process,
    # not the listener itself, holding a listening socket.
    for sock in context.snapshot.live.get("sockets", []):
        if str(sock.get("state") or "").lower() != "listen":
            continue
        for process in _holders(sock, processes):
            if _name(process) not in ("sshd", "sshd-session"):
                continue
            parent = processes.get(process.get("ppid"))
            if parent is None or _name(parent) not in ("sshd", "sshd-session"):
                continue  # the listener, not a session
            local = sock.get("local") or ["?", "?"]
            findings.append(
                Finding(
                    "net.tunnel",
                    "An SSH session listening on a port (a remote forward)",
                    COMPROMISE,
                    "medium",
                    f"sshd session (pid {process.get('pid')}) listening on {local[0]}"
                    f" port {local[1]}",
                    [f"pid:{process.get('pid')}", "program:sshd"],
                    [{"live": ["processes", process.get("pid")]}],
                    process.get("start_time"),
                    process.get("start_time"),
                )
            )
    return findings


@check(
    "net.config",
    "Changes to hosts, resolver, TCP wrappers and the firewall",
    needs_baseline=True,
    variants=("file", "firewall"),
)
def config(context: Context) -> list[Finding]:
    findings = []
    files = context.changes("network_files")
    for how in ("added", "removed", "changed"):
        for path in files[how]:
            findings.append(
                Finding(
                    "net.config",
                    f"A network configuration file was {how}",
                    COMPROMISE,
                    "medium",
                    path,
                    [f"path:{path}"],
                    [context.change_ref("network_files", path, how)],
                    new=context.new_since_previous("network_files", path),
                    uncertain=context.uncertain("network_files"),
                    variant="file",
                )
            )
    rules = context.changes("firewall_rules")
    for how in ("added", "removed"):
        lines = sorted(rules[how])
        if not lines:
            continue
        # One finding per direction: a reloaded ruleset changes many lines.
        shown = "; ".join(lines[:3]) + (f" and {len(lines) - 3} more" if len(lines) > 3 else "")
        findings.append(
            Finding(
                "net.config",
                f"Firewall rules {how} since the baseline",
                COMPROMISE,
                "medium",
                f"{len(lines)} rule line(s) {how}: {shown}"[:400],
                [],
                [context.change_ref("firewall_rules", key, how) for key in lines[:50]],
                new=any(context.new_since_previous("firewall_rules", k) for k in lines),
                uncertain=context.uncertain("firewall_rules"),
                variant="firewall",
                entities_complete=False,
            )
        )
    return findings


@check("net.promiscuous", "Interfaces in promiscuous mode (capturing all traffic)")
def promiscuous(context: Context) -> list[Finding]:
    processes = _processes(context)
    capturing = {
        _name(p)
        for sock in context.snapshot.live.get("sockets", [])
        if str(sock.get("protocol")) == "packet"
        for p in _holders(sock, processes)
    }
    known = capturing & CAPTURE_TOOLS
    findings = []
    for name, item in context.items("interfaces").items():
        if not item.get("promiscuous") or item.get("bridge_port") or item.get("bridge"):
            continue  # a bridge's ports are promiscuous by design
        findings.append(
            Finding(
                "net.promiscuous",
                "An interface in promiscuous mode",
                COMPROMISE,
                "low" if known else "medium",
                f"{name}"
                + (
                    f" (a capture tool is running: {', '.join(sorted(known))})"
                    if known
                    else "; programs holding packet sockets: "
                    + (", ".join(sorted(capturing)) or "none")
                ),
                [],
                [{"item": ["interfaces", name]}],
            )
        )
    return findings


@check(
    "net.transfer",
    "Weak signs of data leaving: large archives in scratch places, download tools talking out",
    variants=("archive", "tool", "counters"),
)
def transfer(context: Context) -> list[Finding]:
    """Each weak alone (low): mostly material for chains. The finding says
    when no strong source (firewall or proxy logs) exists."""
    findings = []
    for path, item in context.items("unusual_files").items():
        if (item.get("size") or 0) >= LARGE_ARCHIVE and ARCHIVE.search(path.lower()):
            findings.append(
                Finding(
                    "net.transfer",
                    "A large archive in a scratch place",
                    COMPROMISE,
                    "low",
                    f"{path} ({item.get('size') // (1024 * 1024)} MB)",
                    [f"path:{path}"],
                    [{"item": ["unusual_files", path]}],
                    variant="archive",
                )
            )
    processes, users = _processes(context), _accounts_by_uid(context)
    for sock in context.snapshot.live.get("sockets", []):
        remote = sock.get("remote") or []
        if not _open(sock) or not _public(str(remote[0])):
            continue
        for process in _holders(sock, processes):
            if _name(process) not in DOWNLOADERS:
                continue
            findings.append(
                _socket_finding(
                    "net.transfer",
                    "A transfer tool talking to a public address",
                    "low",
                    process,
                    sock,
                    "connected to",
                    "tool",
                    users,
                )
            )
    for interface in context.snapshot.live.get("interfaces", []):
        rx, tx = interface.get("rx_bytes") or 0, interface.get("tx_bytes") or 0
        if (
            tx > 10 * max(rx, 1)
            and tx > 1024**3
            and not str(interface.get("name")).startswith("lo")
        ):
            findings.append(
                Finding(
                    "net.transfer",
                    "An interface has sent far more than it received",
                    COMPROMISE,
                    "low",
                    f"{interface.get('name')}: sent {tx // 1024**2} MB, received"
                    f" {rx // 1024**2} MB since boot (normal for a server that serves files)",
                    [],
                    [],
                    variant="counters",
                )
            )
    return findings
