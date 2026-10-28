"""Network and data transfer (DESIGN.md §8.8): new listeners and
destinations, the cloud metadata address, directory services reached from
web-server accounts, SSH tunnels, resolver and firewall changes, interfaces
in promiscuous mode, and weak signs of data leaving.

Connections are a sample: only those open when the collector looked.
Without firewall or proxy logs, transfer evidence is weak.

A process's name (`comm`) is whatever it says it is: who a process is, for
these checks, is the file it runs (`exe`, and for an interpreter, the
script it was given)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from checker.checks import COMPROMISE, Context, Finding, check
from checker.checks.processes import own_processes

METADATA = {"169.254.169.254", "fd00:ec2::254"}
# Cloud agents that talk to the metadata service for a living, by the name
# of the file they run (or, run by an interpreter, of their script).
CLOUD_AGENTS = {
    "cloud-init",
    "amazon-ssm-agent",
    "ssm-agent-worker",
    "ssm-session-worker",
    "amazon-cloudwatch-agent",
    "ecs-agent",
    "google_guest_agent",
    "google_osconfig_agent",
    "otelopscol",
    "waagent",
    "walinuxagent",
    "qemu-ga",
    "droplet-agent",
    "do-agent",
    "oracle-cloud-agent",
    "aliyun-service",
}
INTERPRETERS = re.compile(r"^(?:python[\d.]*|perl[\d.]*|ruby[\d.]*|node|bash|sh)$")
SYSTEM_DIRS = ("/usr/", "/opt/", "/snap/", "/bin/", "/sbin/", "/lib/")
# Directory services a web tier has no business reaching (§8.8 ★): SMB and
# WinRM high; LDAP and Kerberos medium, since web apps that log users in
# against a directory (Nextcloud, Moodle, Redmine…) use them all the time.
DIRECTORY_PORTS = {
    445: ("SMB", "high"),
    5985: ("WinRM", "high"),
    5986: ("WinRM", "high"),
    389: ("LDAP", "medium"),
    636: ("LDAPS", "medium"),
    3268: ("LDAP GC", "medium"),
    3269: ("LDAP GC", "medium"),
    88: ("Kerberos", "medium"),
}
WEB_USERS = {"www-data", "apache", "nginx", "httpd", "lighttpd", "wwwrun"}
TOR_PORTS = {9001, 9030}
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
ARCHIVE = re.compile(
    r"\.(?:zip|tar|tgz|tar\.gz|tar\.bz2|tar\.xz|tar\.zst|tbz2|txz|7z|rar|gz|xz|bz2|zst|lz4"
    r"|cpio|part)$"
)
LARGE_ARCHIVE = 50 * 1024 * 1024
# Bridges for containers and VMs: what they "send" goes into the guests.
VIRTUAL_BRIDGES = re.compile(r"^(?:lo|docker\d*|br-|cni|cbr|virbr|lxdbr|podman|flannel|veth)")
# ssh's options that take an argument (man ssh), and those that forward.
SSH_ARG_OPTIONS = set("BbcDEeFIiJLlmOoPpRSWw")
SSH_FORWARDS = set("LRDWJ")
SSH_FORWARD_KEYS = {"localforward", "remoteforward", "dynamicforward", "proxyjump", "tunnel"}
X11_PORTS = range(6000, 6100)
OPEN_STATES = ("established", "syn_sent", "close_wait")
DOCUMENTATION = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


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


def _address(text: str):
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return parsed


def _public(text: str) -> bool:
    """Public, or a documentation range: those never carry real traffic and
    stand in for public addresses in tests and in the golden cases."""
    parsed = _address(text)
    if parsed is None:
        return False
    return parsed.is_global or any(
        parsed.version == n.version and parsed in n for n in DOCUMENTATION
    )


def _open(sock: dict[str, Any]) -> bool:
    remote = sock.get("remote") or []
    return (
        str(sock.get("protocol") or "").startswith("tcp")
        and len(remote) == 2
        and bool(remote[1])
        and str(sock.get("state") or "").lower() in OPEN_STATES
    )


def _holders(sock, processes) -> list[dict[str, Any]]:
    """The processes holding a socket; when none is visible (gone, hidden,
    in another namespace), a stand-in carrying the socket's owner."""
    held = [processes[pid] for pid in sock.get("pids") or [] if pid in processes]
    if held:
        return held
    return [{"pid": None, "comm": "an unseen process", "uids": [sock.get("uid")] * 2}]


def _name(process: dict[str, Any]) -> str:
    return str(process.get("comm") or "?")


def _runs(process: dict[str, Any]) -> tuple[str, str]:
    """(the file it runs, its name): for an interpreter, the script it was
    given, so `python3 /usr/sbin/waagent` is waagent."""
    exe = str(process.get("exe") or "").removesuffix(" (deleted)")
    name = exe.rsplit("/", 1)[-1]
    if INTERPRETERS.match(name):
        args = str(process.get("cmdline") or "").split()
        script = next((a for a in args[1:] if not a.startswith("-")), "")
        if script.startswith("/"):
            return script, script.rsplit("/", 1)[-1]
    return exe, name


def _user(process, users) -> str:
    uids = process.get("uids") or []
    effective = uids[1] if len(uids) > 1 else (uids[0] if uids else None)
    return users.get(effective, str(effective))


def _socket_finding(check_id, title, band, process, sock, users, variant=None):
    remote = sock.get("remote") or ["?", "?"]
    pid = process.get("pid")
    exe = str(process.get("exe") or "")
    user = _user(process, users)
    return Finding(
        check_id,
        title,
        COMPROMISE,
        band,
        f"{_name(process)} (pid {pid}, {user}{', ' + exe if exe else ''}): connected to"
        f" {remote[0]} port {remote[1]}, {sock.get('state')}",
        [f"address:{remote[0]}", f"account:{user}"]
        + ([f"pid:{pid}", f"program:{_name(process)}"] if pid is not None else [])
        + ([f"exe:{exe}"] if exe else []),
        [{"live": ["processes", pid]}] if pid is not None else [],
        process.get("start_time"),
        process.get("start_time"),
        variant=variant,
    )


def _without_netns(key: str) -> str:
    return key.rsplit(" netns=", 1)[0]


@check("net.listener", "New listening ports", needs_baseline=True)
def listeners(context: Context) -> list[Finding]:
    diff = context.changes("listeners")
    uncertain = context.uncertain("listeners")
    users = _accounts_by_uid(context)
    # A container restarted has a new network namespace: the same port in
    # another namespace isn't a new listener.
    gone = {_without_netns(k) for k in diff["removed"]}
    findings = []
    for key, item in diff["added"].items():
        if _without_netns(key) in gone:
            continue
        where = _without_netns(key).split(" ", 1)[-1]
        local = where.rsplit(":", 1)[0] if ":" in where else where
        findings.append(
            Finding(
                "net.listener",
                "A new listening port",
                COMPROMISE,
                "low",
                f"{key}: {', '.join(item.get('programs') or ['?'])}",
                [f"program:{p}" for p in item.get("programs") or []]
                + ([f"address:{local}"] if _address(local) else [])
                + [f"account:{users.get(u, u)}" for u in item.get("uids") or []],
                [context.change_ref("listeners", key, "added")],
                new=context.new_since_previous("listeners", key),
                uncertain=uncertain,
            )
        )
    return findings


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
        parts = key.split(" ")
        network = parts[1] if len(parts) > 1 else ""
        port = parts[-1]
        tor = item.get("program") == "tor"
        relay_port = port.isdigit() and int(port) in TOR_PORTS
        findings.append(
            Finding(
                "net.peer",
                "Tor in use" if tor else "A new outgoing destination",
                COMPROMISE,
                "medium" if tor else "low",
                f"{key} (open at collection"
                + ("; a Tor relay port" if relay_port and not tor else "")
                + ")",
                [f"program:{item.get('program')}"]
                + ([f"address:{network.split('/')[0]}"] if "/" in network else []),
                [context.change_ref("peers", key, "added")],
                new=context.new_since_previous("peers", key),
                uncertain=uncertain,
                variant="tor" if tor else "new_destination",
            )
        )
    return findings


@check("net.metadata", "The cloud metadata address reached by an unexpected program")
def metadata(context: Context) -> list[Finding]:
    """A known agent (by the file it runs, in a system directory) isn't
    reported; another root program in a system directory is low (an SDK
    using the instance's role does this); anything else is medium."""
    processes, users = _processes(context), _accounts_by_uid(context)
    findings = []
    for sock in context.snapshot.live.get("sockets", []):
        remote = sock.get("remote") or []
        if not _open(sock) or str(_address(str(remote[0]))) not in METADATA:
            continue
        for process in _holders(sock, processes):
            path, name = _runs(process)
            in_system = path.startswith(SYSTEM_DIRS)
            if name in CLOUD_AGENTS and in_system:
                continue
            band = "low" if in_system and _user(process, users) == "root" else "medium"
            findings.append(
                _socket_finding(
                    "net.metadata",
                    "A program other than the cloud agent reached the metadata address",
                    band,
                    process,
                    sock,
                    users,
                )
            )
    return findings


@check(
    "net.directory",
    "Directory services reached from a web-server account",
    variants=("smb_winrm", "ldap_kerberos"),
)
def directory(context: Context) -> list[Finding]:
    """★ A web worker reaching SMB or WinRM: the way from a web shell into a
    Windows domain (high). LDAP and Kerberos medium: web apps that log
    users in against a directory use them. Judged by the process's account,
    not a host role, so a domain-joined server's own lookups don't count."""
    processes, users = _processes(context), _accounts_by_uid(context)
    findings = []
    for sock in context.snapshot.live.get("sockets", []):
        remote = sock.get("remote") or []
        if not _open(sock) or remote[1] not in DIRECTORY_PORTS:
            continue
        service, band = DIRECTORY_PORTS[remote[1]]
        for process in _holders(sock, processes):
            if _user(process, users) not in WEB_USERS:
                continue
            findings.append(
                _socket_finding(
                    "net.directory",
                    f"A web-server account reached {service}",
                    band,
                    process,
                    sock,
                    users,
                    "smb_winrm" if band == "high" else "ldap_kerberos",
                )
            )
    return findings


def ssh_forwarding(cmdline: str) -> str | None:
    """The forwarding option an ssh command line uses, if any: parsed as ssh
    parses it, up to the destination (`ssh host ls -lR` forwards nothing)."""
    args = cmdline.split()[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-") or arg in ("-", "--"):
            return None  # the destination: the rest is the remote command
        letters = arg[1:]
        for k, letter in enumerate(letters):
            if letter not in SSH_ARG_OPTIONS:
                continue
            attached = letters[k + 1 :]
            value = attached or (args[i + 1] if i + 1 < len(args) else "")
            if not attached:
                i += 1
            if letter in SSH_FORWARDS:
                return f"-{letter} {value}"
            if letter == "o":
                key = value.split("=", 1)[0].strip().split(" ")[0].lower()
                if key in SSH_FORWARD_KEYS:
                    return f"-o {value}"
            break
        i += 1
    return None


@check("net.tunnel", "SSH tunnels: forwarding clients and sessions holding listeners")
def tunnels(context: Context) -> list[Finding]:
    processes, users = _processes(context), _accounts_by_uid(context)
    findings = []
    for process in processes.values():
        path, name = _runs(process)
        cmdline = str(process.get("cmdline") or "")
        argv0 = cmdline.split(" ", 1)[0].rsplit("/", 1)[-1]
        if "ssh" not in (name, argv0, _name(process)):
            continue
        forwarding = ssh_forwarding(cmdline)
        if forwarding is None:
            continue
        user = _user(process, users)
        findings.append(
            Finding(
                "net.tunnel",
                "An SSH client forwarding ports (a tunnel)",
                COMPROMISE,
                "medium",
                f"ssh (pid {process.get('pid')}, {user}): {forwarding}; {cmdline[:160]}",
                [f"pid:{process.get('pid')}", "program:ssh", f"account:{user}"]
                + ([f"exe:{path}"] if path else []),
                [{"live": ["processes", process.get("pid")]}],
                process.get("start_time"),
                process.get("start_time"),
            )
        )
    # A remote forward (ssh -R into this host): an sshd session process,
    # not the listener itself, holding a listening socket. X11 forwarding
    # listens on loopback ports 6000+ too, and is left out.
    for sock in context.snapshot.live.get("sockets", []):
        if str(sock.get("state") or "").lower() != "listen":
            continue
        local = sock.get("local") or ["?", "?"]
        address = _address(str(local[0]))
        if address is not None and address.is_loopback and local[1] in X11_PORTS:
            continue
        for process in _holders(sock, processes):
            if _name(process) not in ("sshd", "sshd-session"):
                continue
            parent = processes.get(process.get("ppid"))
            if parent is None or _name(parent) not in ("sshd", "sshd-session"):
                continue  # the listener, not a session
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
        # (Chains Docker, Kubernetes and fail2ban manage are summarised in
        # the snapshot, so their churn doesn't reach here.)
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


# Who rewrites a "managed" chain (checker/snapshot.py collapses their rules):
# a chain named so while its owner isn't running is a disguise.
CHAIN_OWNERS = (
    ("docker", ("dockerd",)),
    ("kube-", ("kube-proxy", "kubelet", "k3s", "k3s-server", "k3s-agent")),
    ("cali-", ("calico-node",)),
    ("cilium", ("cilium-agent",)),
    ("f2b-", ("fail2ban-server",)),
    ("flannel", ("flanneld",)),
    ("cni-", ("kubelet", "containerd", "crio", "podman", "k3s")),
    ("libvirt_", ("libvirtd", "virtqemud", "virtnetworkd")),
    ("ts-", ("tailscaled",)),
)
_MANAGED_KEY = re.compile(r"/ chain (\S+)\] \(managed by other software")


@check(
    "net.managed_chain",
    "Firewall chains named like Docker's, Kubernetes' or fail2ban's whose owner isn't running",
)
def managed_chains(context: Context) -> list[Finding]:
    """Their rules aren't compared (they change all the time), so the name
    must be earned: the program that writes such chains must be running."""
    running = {_runs(p)[1] for p in _processes(context).values()}
    findings = []
    for key in context.items("firewall_rules"):
        match = _MANAGED_KEY.search(key)
        if not match:
            continue
        chain = match.group(1)
        owners = next(
            (names for prefix, names in CHAIN_OWNERS if chain.lower().startswith(prefix)), ()
        )
        if not owners or running & set(owners):
            continue
        findings.append(
            Finding(
                "net.managed_chain",
                "A firewall chain named like another program's, which isn't running",
                COMPROMISE,
                "medium",
                f"{chain}: named like {owners[0]}'s chains, whose rules aren't compared, but"
                f" {' or '.join(owners)} isn't running",
                [],
                [{"item": ["firewall_rules", key]}],
            )
        )
    return findings


@check("net.promiscuous", "Interfaces in promiscuous mode (capturing all traffic)")
def promiscuous(context: Context) -> list[Finding]:
    processes = _processes(context)
    capturing = {
        _runs(p)[1]
        for sock in context.snapshot.live.get("sockets", [])
        if str(sock.get("protocol")) == "packet"
        for p in _holders(sock, processes)
    }
    known = capturing & CAPTURE_TOOLS
    findings = []
    for name, item in context.items("interfaces").items():
        if not item.get("promiscuous"):
            continue
        if item.get("bridge_port") or item.get("bridge") or item.get("master"):
            continue  # bridges, their ports, bonds, Open vSwitch: by design
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
    "Weak signs of data leaving: large archives in scratch places, transfer tools talking out",
    variants=("archive", "tool", "counters"),
)
def transfer(context: Context) -> list[Finding]:
    """Each weak alone (low): mostly material for chains."""
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
            if _runs(process)[1] not in DOWNLOADERS:
                continue
            findings.append(
                _socket_finding(
                    "net.transfer",
                    "A transfer tool talking to a public address",
                    "low",
                    process,
                    sock,
                    users,
                    "tool",
                )
            )
    for interface in context.snapshot.live.get("interfaces", []):
        name = str(interface.get("name"))
        rx, tx = interface.get("rx_bytes") or 0, interface.get("tx_bytes") or 0
        if VIRTUAL_BRIDGES.match(name):
            continue
        if tx > 10 * max(rx, 1) and tx > 1024**3:
            findings.append(
                Finding(
                    "net.transfer",
                    "An interface has sent far more than it received",
                    COMPROMISE,
                    "low",
                    f"{name}: sent {tx // 1024**2} MB, received {rx // 1024**2} MB since boot"
                    " (normal for a server that serves files)",
                    [],
                    [{"item": ["interfaces", name]}],
                    variant="counters",
                )
            )
    return findings
