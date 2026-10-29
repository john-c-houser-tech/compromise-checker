"""Read-only proof on real servers (Phase 0, PR 0.7).

Creates a throwaway Linode per distribution, sets up the scanner account
exactly as docs/scanner-account.md says, records every file write made by
the scanner's login session with auditd, runs a real `checker collect`
against it, and fails if anything was written outside the traces disclosed
in the security and privacy policy §5. Every server it creates is deleted,
and servers left behind by a crashed run are swept up next time.

Run by hand, not in CI: it spends money (a Nanode is $0.0075 an hour) and
needs a Linode API token with Linodes: Read/Write only, from $LINODE_TOKEN or
1Password: name the item and vault in $CC_LINODE_OP_ITEM and $CC_LINODE_OP_VAULT.

    python tests/integration/readonly_proof.py [--distro ubuntu24.04 rocky9 | all] [--keep]
"""

import argparse
import asyncio
import importlib.util
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncssh

from checker.analysis import parse_bundle
from checker.assess import analyze
from checker.bundle import walk_bundle
from checker.collect import collect_hosts
from checker.events import classify as classify_message
from checker.evidence import (
    Store,
    database_file,
    initialise,
    load_config,
    load_identity,
    mail_key,
    open_bundle,
)
from checker.inventory import Host
from checker.protocol import Limits
from checker.transport import fetch_host_key, trust_host_key
from checker.whitelist import load as whitelist_load

API = "https://api.linode.com/v4"
TAG = "compromise-checker-test"
LABEL_PREFIX = "cc-test-"
NANODE = "g6-nanode-1"
IMAGES = {
    "ubuntu24.04": "linode/ubuntu24.04",
    "ubuntu22.04": "linode/ubuntu22.04",
    "ubuntu26.04": "linode/ubuntu26.04",
    "rocky9": "linode/rocky9",
    "rocky10": "linode/rocky10",
    "alma9": "linode/almalinux9",
    "alma10": "linode/almalinux10",
}
# Where the token lives in 1Password, if $LINODE_TOKEN isn't set.
OP_ITEM = os.environ.get("CC_LINODE_OP_ITEM")
OP_VAULT = os.environ.get("CC_LINODE_OP_VAULT")
SWEEP_AFTER = timedelta(hours=2)

# Writes a login (sshd, PAM, systemd, sudo) is allowed to cause: the traces
# the security and privacy policy §5 discloses. The collector itself must
# write nothing at all; anything else is a failure.
DISCLOSED = [
    (re.compile(r"^/run/sudo/ts/"), "sudo's timestamp record (memory)"),
    (re.compile(r"^/var/(db|lib)/sudo/lectured/"), "sudo's one-time notice marker"),
    (re.compile(r"^/(var/)?run/utmp$"), "login records"),
    (re.compile(r"^/var/log/(wtmp|btmp|lastlog)$"), "login records"),
    (re.compile(r"^/var/lib/(wtmpdb|lastlog)/"), "login records"),
    (re.compile(r"^/dev/kmsg$"), "a kernel log record"),
    (re.compile(r"^/dev/(null|tty|console)$"), "a device (nothing stored)"),
    (re.compile(r"^/run/user/\d+(/|$)"), "session setup: per-login runtime area (memory)"),
    (re.compile(r"^/sys/fs/cgroup/"), "session setup: control groups (kernel memory)"),
    (re.compile(r"^/proc/(self|thread-self|\d+)/"), "session setup: process settings (memory)"),
    (re.compile(r"^/sys/fs/selinux/"), "session setup: SELinux checks (kernel memory)"),
    (re.compile(r"^/run/motd\.dynamic(\.new)?$"), "Ubuntu login message (memory)"),
    (
        re.compile(r"^/home/[^/]+/\.cache(/motd\.legal-displayed)?$"),
        "Ubuntu login-message marker, first login only (disk)",
    ),
    (
        re.compile(r"^/var/(lib|log)/landscape(/|$)"),
        "Ubuntu login message: Landscape's system summary cache and log (disk)",
    ),
    (
        re.compile(r"^/boot/grub2/grubenv(\.\d+)?$"),
        "RHEL 9+ session: GRUB's boot-success flag (disk)",
    ),
    (
        re.compile(r"^/var/spool/postfix/maildrop/"),
        "sudo's mail to the administrators, queued for local delivery (disk)",
    ),
]
# The login message's Landscape system summary runs on Python too; its own
# writes are login machinery, judged by path like the rest, never the
# collector's.
_LOGIN_PYTHON = ("landscape-sysin",)
# Socket calls the audit rule also catches; they create no file.
_SOCKET_CALLS = {"bind", "connect", "sendto", "sendmsg"}
# Attribute changes on an already-open file carry no path in the audit log.
# Accepted only from systemd's per-user session manager, which creates and
# then locks down its own runtime sockets and directories at login.
_FD_ATTRIBUTE_CALLS = {"fchmod", "fchown", "fsetxattr"}
_SESSION_MANAGER = "/usr/lib/systemd/systemd"
# systemd 256 and later: at login the user's session manager makes the
# placeholder nodes it masks paths with (InaccessiblePaths=) inside its own
# runtime area, through a directory handle, so the audit log has only the
# bare names. Accepted only from the session manager, only these names.
_PLACEHOLDER_CALLS = {"mkdirat", "mknodat", "linkat"}
_PLACEHOLDER_NAMES = {"/", "/inaccessible", "/dir", "/reg", "/chr", "/blk", "/fifo", "/sock"}
# The user-unit generators write links into their output directory under
# /run/user/<uid>/systemd, also through a handle.
_USER_GENERATORS = "/usr/lib/systemd/user-generators/"
PLACEHOLDERS = "session setup: the user manager's placeholder nodes in its runtime area (memory)"
# At a later login the user manager runs the generators again, first
# removing their earlier output (links and .wants directories), through a
# handle on that same in-memory directory.
_GENERATOR_OUTPUT = re.compile(r"^/?[^/]+(\.(service|target|socket|timer|path|mount)|\.wants)$")
REGENERATED = "session setup: the user manager clearing its generators' earlier output (memory)"


# --- Linode API ------------------------------------------------------------------


def linode_token() -> str:
    token = os.environ.get("LINODE_TOKEN")
    if token:
        return token
    if not (OP_ITEM and OP_VAULT):
        sys.exit("Set LINODE_TOKEN, or CC_LINODE_OP_ITEM and CC_LINODE_OP_VAULT for 1Password.")
    for field_name in ("token", "credential", "password"):
        command = ["op", "item", "get", OP_ITEM, "--vault", OP_VAULT]
        command += ["--fields", f"label={field_name}", "--reveal"]
        result = subprocess.run(command, capture_output=True, text=True)  # noqa: S603
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    sys.exit(f"No LINODE_TOKEN and no 1Password item {OP_ITEM!r} readable with `op`.")


class Linode:
    def __init__(self, token: str) -> None:
        self._token = token

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(  # noqa: S310 - fixed https URL
            API + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                text = response.read().decode()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"Linode API {method} {path}: {exc.code} {exc.read().decode()}"
            ) from exc
        return json.loads(text) if text else {}

    def create(self, label: str, image: str, region: str, public_key: str) -> dict:
        return self.call(
            "POST",
            "/linode/instances",
            {
                "label": label,
                "type": NANODE,
                "region": region,
                "image": image,
                "root_pass": secrets.token_urlsafe(32),  # required; never used (key login only)
                "authorized_keys": [public_key],
                "tags": [TAG],
                "booted": True,
            },
        )

    def get(self, linode_id: int) -> dict:
        return self.call("GET", f"/linode/instances/{linode_id}")

    def delete(self, linode_id: int) -> None:
        self.call("DELETE", f"/linode/instances/{linode_id}")

    def find(self, label: str) -> dict | None:
        return next((n for n in self.tagged() if n["label"] == label), None)

    def tagged(self) -> list[dict]:
        return [
            node
            for node in self.call("GET", "/linode/instances?page_size=500")["data"]
            if TAG in node["tags"] and node["label"].startswith(LABEL_PREFIX)
        ]


def sweep(api: Linode) -> None:
    """Delete test servers left behind by an earlier run that died."""
    now = datetime.now(UTC)
    for node in api.tagged():
        created = datetime.fromisoformat(node["created"]).replace(tzinfo=UTC)
        if now - created > SWEEP_AFTER:
            print(f"sweep: deleting leftover {node['label']} (created {node['created']})")
            api.delete(node["id"])


# Every server a run makes carries this run's token in its label, so the
# end-of-run sweep deletes its own and never another run's.
RUN = secrets.token_hex(3)


def run_label(distro: str) -> str:
    return f"{LABEL_PREFIX}{RUN}-{distro.replace('.', '')}-{secrets.token_hex(2)}"


def sweep_run(api: Linode) -> None:
    """At the end of a run, delete any of its servers still there (one
    whose creation answer was lost, a run cut short). One failed delete
    doesn't stop the others."""
    for node in api.tagged():
        if node["label"].startswith(f"{LABEL_PREFIX}{RUN}-"):
            print(f"sweep: deleting {node['label']}, left by this run")
            try:
                api.delete(node["id"])
            except Exception as exc:  # already gone, or the API is down: say so
                print(f"sweep: could not delete {node['label']}: {exc}")


# --- One distribution -------------------------------------------------------------------


@dataclass
class Result:
    distro: str
    passed: bool = False
    status: str = ""
    sources: list[str] = field(default_factory=list)
    audit: "Verdict | None" = None
    seconds: float | None = None
    peak_rss_kb: int | None = None
    home_text_files: int = 0
    missing: list[str] = field(default_factory=list)
    # The controller's own parse of the bundle (1.6): what a snapshot must
    # hold on any server, and (informational) whether the tool's own login
    # was recognised — behind NAT it can't be, by design.
    snapshot: list[str] = field(default_factory=list)  # must stay empty
    snapshot_incomplete: list[str] = field(default_factory=list)
    own_login_found: bool | None = None
    own_events: int = 0
    events: int = 0
    # `checker analyze` on a fresh server: no check may fail; its findings
    # (informational) show the false alarms a clean server raises.
    checks_failed: list[str] = field(default_factory=list)  # must stay empty
    findings: list[str] = field(default_factory=list)
    # Decision 2 (plan 2.4): reading the firewall never loads a kernel
    # module. Modules loaded or unloaded during the collection: must stay
    # empty. And which firewall was loaded, so which commands ran.
    modules_changed: list[str] = field(default_factory=list)
    modules_other: list[str] = field(default_factory=list)  # informational
    firewall_loaded: dict | None = None
    # Plan 2.7: mail events parsed (must be some), and anything that must
    # never leave the server found in the bundle: the mail key, or the
    # mailed address's local part (must stay empty).
    mail_events: int = 0
    # Plan 2.7b: real `sudo -ll` output read as the collector reads it (off,
    # then on once the scanner's input is logged), and sudo's log line for
    # the lookup parsed as the own-session marking expects: problems found
    # (must stay empty).
    sudo_listing: list[str] = field(default_factory=list)
    root_mail: list[str] = field(default_factory=list)  # informational
    sudo_mail: str = ""  # sudo's security mail to root, if any
    mail_leaks: list[str] = field(default_factory=list)
    error: str | None = None


HOME_PATHS = ("/home/", "/root/")
# Evidence every real server must yield, so a pass also shows these reads
# happened: (module, record name) counts, and modules that must send a source.
EXPECTED_RECORDS = (
    ("login_records", "login_record"),
    ("kernel_modules", "kernel_module"),
    ("startup", "home_startup_file"),
    ("package_verify", "checksum_store"),
    ("system_files", "privileged_file"),  # passwd, su and the like on any server
    ("unusual_files", "walk_summary"),  # /tmp exists everywhere
    ("processes", "process"),
    ("processes", "socket"),  # sshd listens on every server
    ("network", "interface"),
    ("network", "firewall_loaded"),
    ("logging_state", "log_file"),
    ("logging_state", "audit_records"),
    ("logging_state", "mac_state"),
    ("software", "package"),
    ("software", "signing_key"),
    ("mail", "mail_servers"),
    ("mail", "mail_queue"),  # Postfix, installed by the setup
    ("web_logs", "web_logs_summary"),
    ("web_logs", "exec_record"),  # the web account's program start, by the shipped rules
    ("containers", "container"),  # Docker's on Ubuntu, Podman's on the RHEL family
)
EXPECTED_SOURCES = ("system_journal", "boots", "auth_journal", "mail")
# The address the setup mails: its local part must never leave the server.
PROOF_MAIL_LOCAL = "proofmail"
# A value the setup puts in web requests' query strings and referrers:
# it must never leave the server either (policy §7).
PROOF_WEB_SECRET = "proofwebsecret"

SETUP = r"""
set -eu
if ! command -v auditctl >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    (apt-get update -qq && apt-get install -y -qq auditd) >/dev/null \
        || dnf install -y -q audit >/dev/null
fi
systemctl enable --now auditd >/dev/null 2>&1 || service auditd start >/dev/null
# A firewall as servers often have one: on Ubuntu, ufw enabled and Docker
# running a container (iptables-nft rules: nft_compat is loaded, and the
# collector lists them; the module check guards that it loads nothing);
# firewalld is already on Rocky and Alma (native nftables).
if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp >/dev/null && ufw --force enable >/dev/null
    (apt-get install -y -qq docker.io >/dev/null 2>&1 \
        && systemctl enable --now docker >/dev/null 2>&1 \
        && docker run -d --name cc-proof-web docker.io/library/nginx:alpine >/dev/null 2>&1) \
        || echo "proof setup: Docker not started" >&2
fi
# Containers for the containers module (plan 2.9): Docker's above on Ubuntu;
# Podman with one running container on the RHEL family.
if ! command -v ufw >/dev/null 2>&1; then
    dnf install -y -q podman >/dev/null
    podman run -d --name cc-proof-pod docker.io/library/alpine:latest sleep 7200 >/dev/null
fi
# The scanner account, exactly as docs/scanner-account.md sets it up.
useradd --create-home --shell /bin/sh --comment "Compromise Checker" scanner
passwd -l scanner >/dev/null
install -d -m 700 -o scanner -g scanner /home/scanner/.ssh
printf '%s\n' 'restrict,from="{controller}",command="sudo -n -- python3 -I -B -" {scanner_key}' \
    > /home/scanner/.ssh/authorized_keys
chown scanner:scanner /home/scanner/.ssh/authorized_keys
chmod 600 /home/scanner/.ssh/authorized_keys
echo 'scanner ALL=(root) NOPASSWD: /usr/bin/python3 -I -B -' > /etc/sudoers.d/compromise-checker
chmod 440 /etc/sudoers.d/compromise-checker
visudo -cf /etc/sudoers.d/compromise-checker >/dev/null
# Record every write, rename, delete or attribute change by the scanner's session.
uid=$(id -u scanner)
for arch in b64 b32; do
    auditctl -a always,exit -F arch=$arch -F perm=wa -F auid="$uid" -F success=1 -k cc-write \
        >/dev/null
done
# Something for the persistence modules to find: a user crontab, a queued
# at job, a start-up file and a user unit in a home.
export DEBIAN_FRONTEND=noninteractive
if ! command -v at >/dev/null 2>&1 || ! command -v crontab >/dev/null 2>&1; then
    (apt-get install -y -qq cron at) >/dev/null 2>&1 || dnf install -y -q cronie at >/dev/null
fi
systemctl enable --now atd >/dev/null 2>&1 || true
useradd --create-home --shell /bin/bash proofuser
echo '*/30 * * * * /usr/bin/true proof' | crontab -u proofuser -
(cd /tmp && echo 'echo proof' | PROOF_SECRET=not-for-the-checker at now + 2 hours >/dev/null 2>&1)
install -d -o proofuser /home/proofuser/.config/systemd/user
printf '[Service]\nExecStart=/usr/bin/true\n' > /home/proofuser/.config/systemd/user/proof.service
echo 'export PROOF=1' >> /home/proofuser/.bashrc
# A mail server, and mail for the mail module to find (plan 2.7): its log
# lines name proofmail, which must arrive only as a fingerprint.
if command -v apt-get >/dev/null 2>&1; then
    echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
    echo "postfix postfix/mailname string proof.example" | debconf-set-selections
    apt-get install -y -qq postfix >/dev/null
else
    dnf install -y -q postfix >/dev/null
fi
systemctl enable --now postfix >/dev/null 2>&1
printf 'Subject: proof\n\nproof\n' \
    | runuser -u proofuser -- /usr/sbin/sendmail proofmail@example.org
printf 'Subject: proof\n\nproof\n' | /usr/sbin/sendmail root
sleep 5
# A web server and PHP-FPM (plan 2.8), audit rules for the web accounts'
# program starts (docs/auditd-web.rules, lines for accounts that exist),
# requests with a secret in their query strings and referrer, and one
# program started by the web account.
if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx php-fpm >/dev/null
else
    dnf install -y -q nginx php-fpm >/dev/null
fi
systemctl enable --now nginx >/dev/null 2>&1
fpm=$(systemctl list-unit-files 'php*-fpm.service' --no-legend | awk '{print $1; exit}')
[ -n "$fpm" ] && systemctl enable --now "$fpm" >/dev/null 2>&1 || true
for account in www-data apache nginx; do
    if id -u "$account" >/dev/null 2>&1; then
        for arch in b64 b32; do
            auditctl -a always,exit -F arch=$arch -S execve,execveat \
                -F euid="$account" -k cc-web-exec >/dev/null
        done
    fi
done
for path in '/?token=proofwebsecret' '/missing.php?id=proofwebsecret' '/x?f=../../etc/passwd'; do
    curl -s -o /dev/null -e 'https://ref.example/page?u=proofwebsecret' \
        "http://127.0.0.1$path" || true
done
web=$(id -u www-data >/dev/null 2>&1 && echo www-data || echo nginx)
runuser -u "$web" -- /usr/bin/date >/dev/null  # recorded, and nothing a check flags
# Something for the collector to find in the authentication log.
logger -p authpriv.notice "compromise-checker read-only proof: marker" || true
"""


async def wait_for_ssh(host: Host, known: Path, deadline: float) -> None:
    while True:
        try:
            check = await fetch_host_key(host, known)
            trust_host_key(host, check, known)  # first use: a brand-new throwaway server
            return
        except Exception:
            if time.monotonic() > deadline:
                raise
            await asyncio.sleep(5)


_RECORD = re.compile(r"^type=(\w+) msg=audit\(([\d.]+:\d+)\):\s*(.*)$")
_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
# Fields audit hex-encodes when the value has spaces or unusual characters.
_ENCODED = {"name", "comm", "exe", "cwd", "proctitle"}


def _value(key: str, raw: str) -> str | None:
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw == "(null)":
        return None
    if key in _ENCODED and re.fullmatch(r"(?:[0-9A-F]{2})+", raw):
        return bytes.fromhex(raw).decode("utf-8", errors="replace")
    return raw


def parse_audit(text: str, syscalls: dict[tuple[str, str], str] | None = None) -> list[dict]:
    """Events from `ausearch --raw`, which keeps every value intact: names with
    spaces or odd characters arrive hex-encoded instead of split. Each event
    has comm, exe, syscall (named via `syscalls`, keyed by arch and number)
    and its PATH records with their types, made absolute against the event's
    working directory — which is only a guess for a relative name used
    through a directory handle (mkdirat with a dirfd): each path also keeps
    its raw name and its device, so a rule can tell."""
    records: dict[str, dict] = {}
    order: list[str] = []
    for line in text.splitlines():
        match = _RECORD.match(line.strip())
        if not match:
            continue
        kind, serial, rest = match.groups()
        if kind not in ("SYSCALL", "PATH", "CWD"):
            continue  # e.g. CONFIG_CHANGE from adding the audit rules, PROCTITLE, EOE
        fields = {key: _value(key, raw) for key, raw in _FIELD.findall(rest)}
        if serial not in records:
            records[serial] = {"syscall": None, "paths": [], "cwd": None}
            order.append(serial)
        event = records[serial]
        if kind == "SYSCALL":
            number = fields.get("syscall", "?")
            event["syscall"] = (syscalls or {}).get((fields.get("arch", ""), number), number)
            event["comm"] = fields.get("comm") or "?"
            event["exe"] = fields.get("exe") or "?"
        elif kind == "CWD":
            event["cwd"] = fields.get("cwd")
        elif kind == "PATH":
            event["paths"].append((fields.get("name"), fields.get("nametype"), fields.get("dev")))
    events = []
    for serial in order:
        event = records[serial]
        if event["syscall"] is None:
            raise ValueError(f"audit event {serial} has no SYSCALL record")
        paths = []
        for raw, kind, dev in event["paths"]:
            if raw is None:
                continue
            name = raw
            if not raw.startswith("/") and kind != "UNKNOWN" and event["cwd"]:
                name = event["cwd"].rstrip("/") + "/" + raw
            paths.append((name, kind, {"raw": raw, "dev": dev}))
        events.append(
            {
                "syscall": event["syscall"],
                "comm": event["comm"],
                "exe": event["exe"],
                "cwd": event["cwd"],
                "paths": paths,
            }
        )
    return events


@dataclass
class Verdict:
    collector: list[str] = field(default_factory=list)  # must stay empty
    unexpected: list[str] = field(default_factory=list)  # must stay empty
    disclosed: list[str] = field(default_factory=list)
    sockets: list[str] = field(default_factory=list)  # informational


# Filesystems that live in memory, as the session's runtime areas do. A
# device number alone can't tell: btrfs, overlayfs, NFS and FUSE use
# anonymous (major 0) devices too.
MEMORY_FILESYSTEMS = {
    "tmpfs",
    "ramfs",
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devtmpfs",
    "devpts",
    "mqueue",
    "securityfs",
    "debugfs",
    "tracefs",
    "configfs",
    "bpf",
    "pstore",
    "hugetlbfs",
    "fusectl",
}


def memory_devices(mountinfo: str) -> set[str]:
    """The devices of the in-memory filesystems in /proc/self/mountinfo,
    written as audit writes them (hex major:minor, `00:2a`)."""
    devices = set()
    for line in mountinfo.splitlines():
        fields = line.split()
        if " - " not in line or len(fields) < 3:
            continue
        fstype = line.split(" - ", 1)[1].split()[0]
        major, _, minor = fields[2].partition(":")
        if fstype in MEMORY_FILESYSTEMS and major.isdigit() and minor.isdigit():
            devices.add(f"{int(major):02x}:{int(minor):02x}")
    return devices


def _in_memory(info: dict, memory: set[str]) -> bool:
    """On an in-memory filesystem, by the server's own mount table; with
    none known, nothing is (fail closed)."""
    return str(info.get("dev") or "").lower() in memory


def _in_memory_relative(info: dict, memory: set[str]) -> bool:
    return not info["raw"].startswith("/") and _in_memory(info, memory)


def classify(events: list[dict], memory: set[str] | None = None) -> Verdict:
    """Every event lands in exactly one place; nothing is silently dropped.
    `memory`: the devices of the server's in-memory filesystems."""
    memory = memory or set()
    verdict = Verdict()
    for event in events:
        who = f"{event['comm']} ({event['exe']}) {event['syscall']}"
        login_python = event["comm"] in _LOGIN_PYTHON
        if not login_python and (event["comm"].startswith("python") or "python" in event["exe"]):
            # The collector itself must write nothing at all.
            paths = [path for path, _, _ in event["paths"]] or ["-"]
            verdict.collector.extend(f"{who} {path}" for path in paths)
            continue
        targets = [
            path
            for path, kind, _ in event["paths"]
            if kind != "PARENT"  # only names the directory looked in
            and not (kind == "UNKNOWN" and event["syscall"].startswith("symlink"))  # link content
        ]
        facts = {path: info for path, _, info in event["paths"]}
        if not targets:
            if event["syscall"] in _SOCKET_CALLS:
                verdict.sockets.append(who)
            elif event["syscall"] in _FD_ATTRIBUTE_CALLS and event["exe"] == _SESSION_MANAGER:
                verdict.disclosed.append(
                    f"{who} (open file)  — session setup: permissions on its own runtime files"
                )
            elif event["exe"] in _OWN_FILE_WRITERS and event["syscall"] in _OWN_FILE_CALLS:
                verdict.disclosed.append(f"{who} (open file)  — {_OWN_FILE_WRITERS[event['exe']]}")
            else:
                verdict.unexpected.append(f"{who} (no path)")
            continue
        if (
            event["exe"].startswith(_USER_GENERATORS)
            and event["syscall"].startswith("symlink")
            and all(_in_memory_relative(facts[path], memory) for path in targets)
        ):
            verdict.disclosed.extend(
                f"{who} {path}  — session setup: a user-unit generator's output (memory)"
                for path in targets
            )
            continue
        if (
            event["exe"] == _SESSION_MANAGER
            and event["syscall"] in ("unlinkat", "unlink", "rmdir")
            and all(
                _GENERATOR_OUTPUT.match(path) and _in_memory_relative(facts[path], memory)
                for path in targets
            )
        ):
            verdict.disclosed.extend(f"{who} {path}  — {REGENERATED}" for path in targets)
            continue
        placeholder = event["exe"] == _SESSION_MANAGER and event["syscall"] in _PLACEHOLDER_CALLS
        for path in targets:
            # A ".." could climb out of a disclosed prefix (/run/user/1000/../../etc):
            # never match those against the list.
            if (
                placeholder
                and path in _PLACEHOLDER_NAMES
                and _in_memory_relative(facts[path], memory)
            ):
                reason = PLACEHOLDERS
            elif ".." in path.split("/"):
                reason = None
            elif (
                not facts[path]["raw"].startswith("/")
                and not _in_memory(facts[path], memory)
                and (event["exe"], event.get("cwd")) not in _CWD_RELATIVE
            ):
                # A relative name through an unknown directory handle, on a
                # disk: where it really is can't be told, so it isn't excused.
                reason = None
            else:
                reason = next((why for pattern, why in DISCLOSED if pattern.search(path)), None)
            if reason:
                verdict.disclosed.append(f"{who} {path}  — {reason}")
            else:
                verdict.unexpected.append(f"{who} {path}")
    for name in ("collector", "unexpected", "disclosed", "sockets"):
        setattr(verdict, name, sorted(set(getattr(verdict, name))))
    return verdict


# Audit arch codes for the syscall tables `ausyscall` knows.
_ARCHES = {"c000003e": "x86_64", "40000003": "i386", "c00000b7": "aarch64"}


async def _syscall_names(conn) -> dict[tuple[str, str], str]:
    names = {}
    for code, arch in _ARCHES.items():
        dump = await conn.run(f"ausyscall {arch} --dump", timeout=60)
        for line in dump.stdout.splitlines():
            number, _, name = line.partition("\t")
            if number.isdigit() and name:
                names[(code, number)] = name.strip()
    return names


async def _create_server(api: Linode, *args) -> dict:
    """Create a server even if this run is cancelled meanwhile: the API call
    can't be stopped once sent, so wait for its answer and delete what it
    made before letting the cancellation through."""
    creating = asyncio.ensure_future(asyncio.to_thread(api.create, *args))
    try:
        return await asyncio.shield(creating)
    except (TimeoutError, OSError, RuntimeError) as exc:
        # The answer was lost (a timeout, a 5xx), not necessarily the
        # request: if the server was made, it has this run's unique label.
        # A 4xx means it was refused: nothing was made.
        if isinstance(exc, RuntimeError) and not re.search(r": 5\d\d ", str(exc)):
            raise
        label = args[0]
        try:
            for _ in range(12):
                await asyncio.sleep(5)
                node = await asyncio.to_thread(api.find, label)
                if node is not None:
                    print(f"create failed to answer, but {label} exists (id {node['id']})")
                    return node
        except asyncio.CancelledError:
            try:
                node = await asyncio.to_thread(api.find, label)
                if node is not None:
                    await asyncio.to_thread(api.delete, node["id"])
            except Exception as cleanup:  # the final sweep still runs
                print(f"cancelled: could not check for {label}: {cleanup}")
            raise
        raise
    except asyncio.CancelledError:
        try:
            node = await creating
        except Exception:
            raise  # nothing was created
        else:
            await asyncio.to_thread(api.delete, node["id"])
            print(f"cancelled: deleted {node['label']} just after creating it")
        raise


FIREWALL_MODULES = re.compile(
    r"(nf_|nft_|xt_|x_tables|ip6?t_|ip6?table_|ip6?_tables|ebt|arpt|ipt_)"
)


async def _kernel_modules(conn) -> set[str]:
    """The kernel's loaded modules, by name."""
    listed = await conn.run("cut -d' ' -f1 /proc/modules", check=True, timeout=60)
    return set(listed.stdout.split())


async def prove(api: Linode, distro: str, region: str, keep: bool, work: Path) -> Result:
    result = Result(distro)
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key_file = work / f"{distro}-scanner"
    scanner_key.write_private_key(scanner_key_file)
    label = run_label(distro)
    try:
        node = await _create_server(
            api, label, IMAGES[distro], region, root_key.export_public_key().decode().strip()
        )
    except Exception as exc:  # this distribution fails; the others go on
        result.error = f"could not create the server: {type(exc).__name__}: {exc}"
        return result
    print(f"{distro}: created {label} (id {node['id']})")
    try:
        deadline = time.monotonic() + 600
        while node["status"] != "running":
            if time.monotonic() > deadline:
                raise TimeoutError("server did not start within 10 minutes")
            await asyncio.sleep(5)
            node = await asyncio.to_thread(api.get, node["id"])
        address = node["ipv4"][0]
        known = work / f"{distro}-known_hosts"
        root = Host(name=f"{distro}-root", address=address, user="root", sudo="root")
        await wait_for_ssh(root, known, deadline)
        print(f"{distro}: {address} is up")

        async with asyncssh.connect(
            address,
            username="root",
            client_keys=[root_key],
            known_hosts=str(known),
            agent_path=None,
            gss_host=None,
            config=None,
        ) as conn:
            controller = (await conn.run("echo $SSH_CLIENT", check=True, timeout=60)).stdout
            controller = controller.split()[0]
            scanner_public = scanner_key.export_public_key().decode().strip()
            setup = SETUP.replace("{controller}", controller).replace(
                "{scanner_key}", scanner_public
            )
            await conn.run(setup, check=True, timeout=600)
            print(f"{distro}: scanner account and audit rules in place")

            home = work / f"{distro}-home"
            # The widest setting, so the proof covers every read the collector can make.
            config, _ = initialise(home, home_text="all", web_access_logs=True, exec_records="all")
            scanner = Host(
                name=distro,
                address=address,
                user="scanner",
                auth="key",
                key_path=str(scanner_key_file),
                sudo="nopasswd",
            )
            loaded_before = await _kernel_modules(conn)
            # Each login mounts a fresh in-memory runtime area, gone once
            # the session ends: sample the mount table throughout, so every
            # session's in-memory devices are known when the writes are judged.
            seen_mounts: list[str] = []

            async def sample_mounts() -> None:
                while True:
                    sampled = await conn.run("cat /proc/self/mountinfo", timeout=60)
                    seen_mounts.append(sampled.stdout or "")
                    await asyncio.sleep(1)

            sampler = asyncio.create_task(sample_mounts())
            # Twice: the mail key goes only to a host whose earlier
            # collection showed sudo doesn't log its input (plan 2.7), so
            # the second collection is the one that reads the mail logs.
            runs = []
            for _ in range(2):
                [outcome] = await collect_hosts(
                    home,
                    config,
                    [scanner],
                    known_hosts=known,
                    limits=Limits(overall_seconds=600, module_seconds=300, source_bytes=1 << 28),
                )
                runs.append(outcome)
            # A third, with sudo told to take rules from SSSD too (its
            # library installed, SSSD itself not running): the collector's
            # own `sudo -ll` look-up runs inside an audited collection, and
            # must find the directory not answering (plan 2.7b).
            await conn.run(DIRECTORY_SUDO, check=True, timeout=600)
            [third] = await collect_hosts(
                home,
                config,
                [scanner],
                known_hosts=known,
                limits=Limits(overall_seconds=600, module_seconds=300, source_bytes=1 << 28),
            )
            await asyncio.sleep(10)  # let local mail be delivered
            # Informational: what sudo mailed the administrators, if anything.
            subjects = await conn.run(
                "cat /var/mail/root /var/spool/mail/root 2>/dev/null | grep -a '^Subject:'"
                " | sort | uniq -c",
                timeout=60,
            )
            result.root_mail = subjects.stdout.strip().splitlines()[:10]
            # Mail queued in the scanner's session is disclosed only as
            # sudo's to the administrators: its messages must be there, and
            # say what sudo reported.
            bodies = await conn.run(
                "cat /var/mail/root /var/spool/mail/root 2>/dev/null"
                " | grep -a -A12 '^Subject: \\*\\*\\* SECURITY information'",
                timeout=60,
            )
            result.sudo_mail = bodies.stdout[:4000]
            result.status = outcome.status
            if outcome.error:
                result.error = outcome.error
            if runs[0].status != "complete":  # fails the proof: status must be "complete"
                result.status = f"first {runs[0].status}, second {outcome.status}"
            loaded_after = await _kernel_modules(conn)
            changed = sorted(
                [f"+{m}" for m in loaded_after - loaded_before]
                + [f"-{m}" for m in loaded_before - loaded_after]
            )
            # Only firewall modules could come from the collector's listing;
            # anything else (udev, the session) is reported, not failed.
            result.modules_changed = [m for m in changed if FIREWALL_MODULES.match(m[1:])]
            result.modules_other = [m for m in changed if m not in result.modules_changed]
            await asyncio.sleep(2)  # let auditd flush

            # --input-logs: without a terminal, ausearch would otherwise wait
            # to read audit records from stdin. --raw keeps every value intact.
            audit = await conn.run(
                "ausearch --input-logs -k cc-write --raw < /dev/null", timeout=120
            )
            if audit.exit_status not in (0, 1) or (
                audit.exit_status == 1 and "no matches" not in audit.stderr
            ):
                raise RuntimeError(f"ausearch failed ({audit.exit_status}): {audit.stderr.strip()}")
            syscalls = await _syscall_names(conn)
            events = parse_audit(audit.stdout, syscalls)
            if not events:
                # A login always causes some writes; none means no usable evidence.
                raise RuntimeError("the audit log holds no events for the scanner's session")
            sampler.cancel()
            mounts = await conn.run("cat /proc/self/mountinfo", check=True, timeout=60)
            memory = memory_devices(mounts.stdout)
            for sample in seen_mounts:
                memory |= memory_devices(sample)
            result.audit = classify(events, memory)
            # After the collections, so nothing here is in their evidence.
            result.sudo_listing = await check_sudo_listing(conn)

        bundle = home / "evidence" / distro / f"{outcome.bundle_id}.age"
        if bundle.exists():
            opened = open_bundle(bundle, load_identity(Path(config.identity_file)))
            opened.status()
            trailer = opened.summary.trailer or {}
            result.seconds = trailer.get("duration_seconds")
            # The collector reports its own peak memory (getrusage) in the trailer.
            result.peak_rss_kb = (trailer.get("resources") or {}).get("peak_rss_kb")
            result.sources = [
                f"{s['name']} ({s['bytes']:,} bytes, masked {s['masked'] or 'nothing'})"
                for s in opened.summary.sources
            ]
            # The setup planted home start-up files and home_text is "all":
            # their text must have been read, or the proof covers less than
            # it claims.
            result.home_text_files = sum(
                1
                for s in opened.summary.sources
                if s.get("module") == "startup" and s["name"].startswith(HOME_PATHS)
            )
            counts = opened.summary.records
            result.missing = [f"{m}.{n}" for m, n in EXPECTED_RECORDS if not counts.get(f"{m}.{n}")]
            with_sources = {s.get("module") for s in opened.summary.sources if s.get("bytes")}
            result.missing += [f"{m} (source)" for m in EXPECTED_SOURCES if m not in with_sources]
            check_parse(result, home, outcome.bundle_id, Path(config.identity_file), scanner_key)
            result.sudo_listing += check_directory_lookup(
                home, third.bundle_id, Path(config.identity_file)
            )
        audit = result.audit
        result.passed = (
            result.status == "complete"
            and audit is not None
            and not audit.collector
            and not audit.unexpected
            and result.home_text_files > 0
            and not result.missing
            and not result.snapshot
            and not result.checks_failed
            and not result.modules_changed
            and result.mail_events > 0
            and not result.sudo_listing
            and (not _queued_mail(audit) or "SECURITY information" in result.sudo_mail)
            and not result.mail_leaks
            # On Ubuntu, ufw (and Docker) put the rules through nft_compat:
            # that path must really have been exercised.
            and (
                not distro.startswith("ubuntu")
                or (
                    (result.firewall_loaded or {}).get("nft_compat") is True
                    and any(s.startswith("/usr/sbin/nft") for s in result.sources)
                )
            )
        )
    except Exception as exc:  # report it; the server is still deleted below
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        if keep:
            print(
                f"{distro}: --keep: leaving {label} running (id {node['id']}); delete it yourself"
            )
        else:
            await asyncio.to_thread(api.delete, node["id"])
            print(f"{distro}: deleted {label}")
    return result


# Sections every server's snapshot must have, complete, when collected as root.
COMPLETE_SECTIONS = (
    "host",
    "accounts",
    "groups",
    "sudo_rules",
    "sudo_files",
    "authorized_keys",
    "sshd_config",
    "kernel_modules",
    "listeners",
    "privileged_files",
)


PROOF_WHITELIST = Path(__file__).resolve().parent / "proof-whitelist.yaml"


def proof_whitelist(home: Path, host: str):
    """The proofs' own whitelist (their setup, explained), installed as the
    host's whitelist file in the proof's home, as an operator would."""
    target = home / "whitelist" / "hosts" / f"{host}.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(PROOF_WHITELIST.read_text(encoding="utf-8"), encoding="utf-8")
    return whitelist_load(home, host, None)


COLLECTOR_FILE = Path(__file__).resolve().parents[2] / "checker" / "collector" / "collector.py"
DIRECTORY_SUDO = r"""
set -eu
if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libsss-sudo >/dev/null
else
    dnf install -y -q libsss_sudo >/dev/null
fi
nss=$(readlink -f /etc/nsswitch.conf)
sed -i '/^[[:space:]]*sudoers[[:space:]]*:/d' "$nss"
echo 'sudoers: files sss' >> "$nss"
"""


# Writes with no path, on a file the program itself opened: GRUB's
# boot-success flag (grubenv) and postdrop's queue file.
_OWN_FILE_WRITERS = {
    "/usr/sbin/grub2-set-bootflag": "RHEL session: GRUB's boot-success flag (disk)",
    "/usr/sbin/postdrop": "sudo's mail to the administrators, queued for local delivery (disk)",
}
_OWN_FILE_CALLS = {"ftruncate", "fchmod", "fchown", "fsync", "write"}
# Programs that work relative to a folder of their own (postdrop changes to
# Postfix's queue directory): their relative names are read against it.
_CWD_RELATIVE = {("/usr/sbin/postdrop", "/var/spool/postfix")}


def _queued_mail(audit) -> bool:
    """Whether anything was queued for local mail in the scanner's session."""
    return any("/var/spool/postfix/maildrop/" in line for line in audit.disclosed)


class _LookupRecord:
    """A bundle walk keeping the sudoers module's sudo_input_logging record."""

    def __init__(self) -> None:
        self.data = None

    def record(self, record) -> None:
        if (record.module, record.name) == ("sudoers", "sudo_input_logging"):
            self.data = record.data

    def __getattr__(self, name):
        return lambda *args: None


def check_directory_lookup(home: Path, bundle_id: str, identity_file: Path) -> list[str]:
    """The third collection's: the look-up ran, found SSSD not answering and
    left the state unknown (no key), and its log line is the tool's own."""
    store = Store(database_file(home))
    identity = load_identity(identity_file)
    try:
        row = store.bundle(bundle_id)
        found = _LookupRecord()
        walk_bundle(Path(row["path"]), identity, found)
        parsed = parse_bundle(row, identity)
    finally:
        store.close()
    data = found.data or {}
    problems = []
    if data.get("state") != "unknown" or "responder" not in str(data.get("directory_lookup")):
        problems.append(f"directory look-up: {data}")
    if not data.get("lookup_command"):
        problems.append("the look-up didn't run")
    listings = [
        e
        for e in parsed.events
        if e.type == "sudo.command" and (e.fields.get("command") or "").split() == ["list"]
    ]
    if listings and not any(e.own_session for e in listings):
        problems.append(f"sudo's look-up line wasn't marked as the tool's own: {listings[:2]}")
    return problems


SUDO_LISTING = r"""
set -u
sudo -n -ll -U scanner > /root/cc-list-off 2>/root/cc-list-off.err; echo "off status $?"
echo 'Defaults:scanner log_input' > /etc/sudoers.d/zz-cc-proof-input
chmod 440 /etc/sudoers.d/zz-cc-proof-input
sudo -n -ll -U scanner > /root/cc-list-on 2>/root/cc-list-on.err; echo "on status $?"
echo 'Defaults!/usr/bin/python3 log_input' > /etc/sudoers.d/zz-cc-proof-input
sudo -n -ll -U scanner > /root/cc-list-cmnd 2>/root/cc-list-cmnd.err; echo "cmnd status $?"
echo 'scanner ALL=(root) NOPASSWD: LOG_INPUT: /usr/bin/true' > /etc/sudoers.d/zz-cc-proof-input
sudo -n -ll -U scanner > /root/cc-list-tag 2>/root/cc-list-tag.err; echo "tag status $?"
rm -f /etc/sudoers.d/zz-cc-proof-input
sleep 2
"""


def _collector_module():
    spec = importlib.util.spec_from_file_location("collector_for_proof", COLLECTOR_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def check_sudo_listing(conn) -> list[str]:
    """The collector's reading of real `sudo -ll` output, and sudo's log
    line for such a lookup, on this distribution."""
    problems = []
    statuses = (await conn.run(SUDO_LISTING, check=True, timeout=120)).stdout
    version = (await conn.run("sudo --version | head -1", timeout=60)).stdout
    # sudo-rs (Ubuntu 26.04) has no input logging: it ignores log_input and
    # LOG_INPUT, so every listing must read "off".
    sudo_rs = "sudo-rs" in version
    if any(f"{n} status 0" not in statuses for n in ("off", "on", "cmnd", "tag")):
        problems.append(f"sudo -ll failed: {statuses.strip()}")
    collector = _collector_module()
    for name, expected in (("off", "off"), ("on", "on"), ("cmnd", "on"), ("tag", "on")):
        expected = "off" if sudo_rs else expected
        listing = (await conn.run(f"cat /root/cc-list-{name}", check=True, timeout=60)).stdout
        found = collector.sudo_list_logs_input(listing)
        if found != expected:
            problems.append(f"listing read as {found!r}, expected {expected!r}: {listing[:300]!r}")
    logged = await conn.run(
        "journalctl -q --no-pager -o cat _COMM=sudo | grep 'COMMAND=list' | tail -1", timeout=60
    )
    line = logged.stdout.strip()
    kind = classify_message("sudo", line)
    # Root's listing is seldom logged at all; a line, if there is one, must
    # be one the own-session marking recognises.
    if not line:
        pass
    elif kind is None or kind[0] != "sudo.command" or kind[1].get("user") != "root":
        problems.append(f"sudo's lookup line isn't parsed as root's sudo.command: {line!r}")
    elif (kind[1].get("command") or "").split() not in (["list"], ["list", "scanner"]):
        problems.append(f"sudo's lookup line names an unexpected command: {line!r}")
    return problems


class MailLeaks:
    """A bundle walk that looks for text that must never leave a server: the
    mail key, and the mailed address's local part (policy §7)."""

    def __init__(self, needles: list[str]) -> None:
        self.needles = [n.encode() for n in needles]
        self.found: list[str] = []

    def _look(self, where: str, data: bytes) -> None:
        for needle in self.needles:
            if needle.lower() in data.lower() and len(self.found) < 20:
                self.found.append(f"{needle.decode()[:12]}… in {where}")

    def manifest(self, manifest) -> None:
        self._look("the manifest", manifest.model_dump_json().encode())

    def record(self, record) -> None:
        self._look(f"record {record.module}.{record.name}", json.dumps(record.data).encode())

    def source_start(self, start) -> None:
        pass

    def line(self, start, line: bytes) -> None:
        self._look(f"source {start.name}", line)

    def source_end(self, start, end) -> None:
        pass

    def source_cut(self, start) -> None:
        pass

    def error(self, error) -> None:
        self._look("an error", error.message.encode())

    def trailer(self, trailer) -> None:
        pass


def check_parse(result: Result, home: Path, bundle_id: str, identity_file: Path, key) -> None:
    """Parse the bundle as the controller does and check its snapshot holds
    what the setup put on the server."""
    store = Store(database_file(home))
    identity = load_identity(identity_file)
    try:
        row = store.bundle(bundle_id)
        parsed = parse_bundle(row, identity)
        assessment = analyze(
            store,
            row["host"],
            identity,
            load_config(home).recipients,
            whitelist=proof_whitelist(home, row["host"]),
        )
    finally:
        store.close()
    result.checks_failed = [
        f"{c['check']}: {c['status']}"
        for c in assessment["checks"]
        if c["status"].startswith("failed")
    ]
    result.findings = [
        f"{f['band']} {f['category']}: {f['title']} — {f['summary'][:120]}"
        for f in assessment["findings"]
        if f["band"] != "info" and not f.get("suppressed_by")
    ]
    result.events = len(parsed.events)
    result.mail_events = sum(1 for e in parsed.events if e.type.startswith("mail."))
    leaks = MailLeaks([mail_key(home), PROOF_MAIL_LOCAL, PROOF_WEB_SECRET])
    walk_bundle(Path(row["path"]), identity, leaks)
    result.mail_leaks = leaks.found
    if parsed.snapshot is not None:
        result.firewall_loaded = parsed.snapshot.live.get("firewall_loaded")
    result.own_events = parsed.summary.get("own_session") or 0
    result.own_login_found = parsed.summary.get("own_login_found")
    sections = parsed.snapshot.sections
    result.snapshot_incomplete = [
        f"{name}: {'; '.join(s.gaps[:2])}" for name, s in sections.items() if not s.complete
    ]
    problems = result.snapshot
    for name in COMPLETE_SECTIONS:
        if name not in sections:
            problems.append(f"no {name} section")
        elif not sections[name].complete:
            problems.append(f"{name} incomplete: {'; '.join(sections[name].gaps[:2])}")
    if sections.get("accounts") and not {"root", "scanner"} <= set(sections["accounts"].items):
        problems.append("accounts lack root or scanner")
    rules = sections.get("sudo_rules")
    if rules and not any("scanner ALL=(root) NOPASSWD" in k for k in rules.items):
        problems.append("the scanner's sudoers rule is not among the sudo rules")
    fingerprint = key.get_fingerprint("sha256")
    keys = sections.get("authorized_keys")
    if keys and not any(
        i.get("account") == "scanner" and i.get("fingerprint") == fingerprint
        for i in keys.items.values()
    ):
        problems.append("the scanner's key is not among the authorized keys")
    if sections.get("sshd_config") is not None and not sections["sshd_config"].items:
        problems.append("no sshd settings")
    listeners = sections.get("listeners")
    if listeners and not any(":22 " in k + " " for k in listeners.items):
        problems.append("nothing listening on port 22")


def _count_reasons(lines: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in lines:
        reason = line.rsplit("  — ", 1)[-1]
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def report(results: list[Result]) -> bool:
    print()
    for r in results:
        print(
            f"=== {r.distro}: {'PASS' if r.passed else 'FAIL'}  (bundle status: {r.status or '-'})"
        )
        if r.error:
            print(f"  error: {r.error}")
        if r.seconds is not None:
            print(f"  collector ran {r.seconds} s, peak memory {r.peak_rss_kb or '?'} KB")
            print(f"  home start-up files read as text (home_text=all): {r.home_text_files}")
            if not r.home_text_files:
                print("  FAIL: no home start-up text was read, so those reads went unproven")
            for what in r.missing:
                print(f"  FAIL: no {what} collected, so that read went unproven")
            print(f"  mail events parsed: {r.mail_events}")
            if not r.mail_events:
                print("  FAIL: no mail event parsed, so the mail log reads went unproven")
            for subject in r.root_mail:
                print(f"  mail to root during the run: {subject}")
            if r.audit is not None and _queued_mail(r.audit):
                if "SECURITY information" in r.sudo_mail:
                    print("  sudo's mail to root (what queued mail in the session was):")
                    for line in r.sudo_mail.splitlines()[:20]:
                        print(f"    {line}")
                else:
                    print(
                        "  FAIL: mail was queued in the scanner's session, and none of it is sudo's"
                    )
            for problem in r.sudo_listing:
                print(f"  FAIL: sudo listing: {problem}")
            for leak in r.mail_leaks:
                print(f"  FAIL: left the server unmasked: {leak}")
            print(
                f"  parsed: {r.events} events, {r.own_events} from this tool's own session;"
                f" own login recognised: {r.own_login_found}"
                + (
                    " (NAT on the way changes the source port)"
                    if r.own_login_found is False
                    else ""
                )
            )
            for problem in r.snapshot:
                print(f"  FAIL: snapshot: {problem}")
            for gap in r.snapshot_incomplete:
                print(f"  snapshot section incomplete: {gap}")
            for failed in r.checks_failed:
                print(f"  FAIL: check {failed}")
            print(f"  firewall loaded (so its rules were listed): {r.firewall_loaded}")
            if r.distro.startswith("ubuntu") and not (r.firewall_loaded or {}).get("nft_compat"):
                print(
                    "  FAIL: ufw/Docker rules weren't in place, so the nft_compat path"
                    " went unproven"
                )
            if r.modules_changed:
                print(f"  FAIL: firewall modules changed during collection: {r.modules_changed}")
            else:
                print("  firewall modules unchanged by the collection")
            if r.modules_other:
                print(f"  other modules changed meanwhile (not the collector's): {r.modules_other}")
            print(f"  findings on a fresh server (false alarms to tune): {len(r.findings)}")
            for finding in r.findings:
                print(f"    {finding}")
        for source in r.sources:
            print(f"  collected {source}")
        audit = r.audit
        if audit is None:
            continue
        if audit.collector:
            for line in audit.collector:
                print(f"  COLLECTOR WROTE: {line}")
        else:
            print("  the collector wrote nothing")
        for line in audit.unexpected:
            print(f"  UNEXPECTED write: {line}")
        print(f"  {len(audit.disclosed)} disclosed login/session writes:")
        for reason, count in _count_reasons(audit.disclosed).items():
            print(f"    {count:4} × {reason}")
        if audit.sockets:
            print(f"  ({len(audit.sockets)} socket calls by login machinery, not file writes)")
    return all(r.passed for r in results)


def _cancel_on_sigterm() -> None:
    """Treat SIGTERM like Ctrl-C: cancel the running task, so every cleanup
    (deleting servers, finishing a creation already sent) runs before the
    event loop stops."""
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, asyncio.current_task().cancel)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--distro", nargs="+", default=["ubuntu24.04", "rocky9"], choices=[*IMAGES, "all"]
    )
    parser.add_argument("--region", default="us-sea")
    parser.add_argument("--keep", action="store_true", help="don't delete the servers")
    args = parser.parse_args()
    if "all" in args.distro:
        args.distro = list(IMAGES)  # the whole matrix Linode offers (no RHEL there)
    _cancel_on_sigterm()

    api = Linode(linode_token())
    await asyncio.to_thread(sweep, api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-proof-") as work:
            results = await asyncio.gather(
                *(prove(api, distro, args.region, args.keep, Path(work)) for distro in args.distro)
            )
    finally:
        if not args.keep:
            await asyncio.to_thread(sweep_run, api)
    return 0 if report(list(results)) else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)  # progress shows up as it happens
    raise SystemExit(asyncio.run(main()))
