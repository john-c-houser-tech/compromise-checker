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

    python tests/integration/readonly_proof.py [--distro ubuntu24.04 rocky9] [--keep]
"""

import argparse
import asyncio
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
from checker.collect import collect_hosts
from checker.evidence import (
    Store,
    database_file,
    initialise,
    load_config,
    load_identity,
    open_bundle,
)
from checker.inventory import Host
from checker.protocol import Limits
from checker.transport import fetch_host_key, trust_host_key

API = "https://api.linode.com/v4"
TAG = "compromise-checker-test"
LABEL_PREFIX = "cc-test-"
NANODE = "g6-nanode-1"
IMAGES = {
    "ubuntu24.04": "linode/ubuntu24.04",
    "ubuntu22.04": "linode/ubuntu22.04",
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
]
# Socket calls the audit rule also catches; they create no file.
_SOCKET_CALLS = {"bind", "connect", "sendto", "sendmsg"}
# Attribute changes on an already-open file carry no path in the audit log.
# Accepted only from systemd's per-user session manager, which creates and
# then locks down its own runtime sockets and directories at login.
_FD_ATTRIBUTE_CALLS = {"fchmod", "fchown", "fsetxattr"}
_SESSION_MANAGER = "/usr/lib/systemd/systemd"


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
)
EXPECTED_SOURCES = ("system_journal", "boots", "auth_journal")

SETUP = r"""
set -eu
if ! command -v auditctl >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    (apt-get update -qq && apt-get install -y -qq auditd) >/dev/null \
        || dnf install -y -q audit >/dev/null
fi
systemctl enable --now auditd >/dev/null 2>&1 || service auditd start >/dev/null
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
    working directory."""
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
            event["paths"].append((fields.get("name"), fields.get("nametype")))
    events = []
    for serial in order:
        event = records[serial]
        if event["syscall"] is None:
            raise ValueError(f"audit event {serial} has no SYSCALL record")
        paths = []
        for name, kind in event["paths"]:
            if name is None:
                continue
            if not name.startswith("/") and kind != "UNKNOWN" and event["cwd"]:
                name = event["cwd"].rstrip("/") + "/" + name
            paths.append((name, kind))
        events.append(
            {
                "syscall": event["syscall"],
                "comm": event["comm"],
                "exe": event["exe"],
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


def classify(events: list[dict]) -> Verdict:
    """Every event lands in exactly one place; nothing is silently dropped."""
    verdict = Verdict()
    for event in events:
        who = f"{event['comm']} ({event['exe']}) {event['syscall']}"
        if event["comm"].startswith("python") or "python" in event["exe"]:
            # The collector itself must write nothing at all.
            paths = [path for path, _ in event["paths"]] or ["-"]
            verdict.collector.extend(f"{who} {path}" for path in paths)
            continue
        targets = [
            path
            for path, kind in event["paths"]
            if kind != "PARENT"  # only names the directory looked in
            and not (kind == "UNKNOWN" and event["syscall"].startswith("symlink"))  # link content
        ]
        if not targets:
            if event["syscall"] in _SOCKET_CALLS:
                verdict.sockets.append(who)
            elif event["syscall"] in _FD_ATTRIBUTE_CALLS and event["exe"] == _SESSION_MANAGER:
                verdict.disclosed.append(
                    f"{who} (open file)  — session setup: permissions on its own runtime files"
                )
            else:
                verdict.unexpected.append(f"{who} (no path)")
            continue
        for path in targets:
            # A ".." could climb out of a disclosed prefix (/run/user/1000/../../etc):
            # never match those against the list.
            if ".." in path.split("/"):
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
    except asyncio.CancelledError:
        try:
            node = await creating
        except Exception:
            raise  # nothing was created
        else:
            await asyncio.to_thread(api.delete, node["id"])
            print(f"cancelled: deleted {node['label']} just after creating it")
        raise


async def prove(api: Linode, distro: str, region: str, keep: bool, work: Path) -> Result:
    result = Result(distro)
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key_file = work / f"{distro}-scanner"
    scanner_key.write_private_key(scanner_key_file)
    label = f"{LABEL_PREFIX}{distro.replace('.', '')}-{secrets.token_hex(3)}"
    node = await _create_server(
        api, label, IMAGES[distro], region, root_key.export_public_key().decode().strip()
    )
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
            config, _ = initialise(home, home_text="all")
            scanner = Host(
                name=distro,
                address=address,
                user="scanner",
                auth="key",
                key_path=str(scanner_key_file),
                sudo="nopasswd",
            )
            [outcome] = await collect_hosts(
                home,
                config,
                [scanner],
                known_hosts=known,
                limits=Limits(overall_seconds=600, module_seconds=300, source_bytes=1 << 28),
            )
            result.status = outcome.status
            if outcome.error:
                result.error = outcome.error
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
            result.audit = classify(events)

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


def check_parse(result: Result, home: Path, bundle_id: str, identity_file: Path, key) -> None:
    """Parse the bundle as the controller does and check its snapshot holds
    what the setup put on the server."""
    store = Store(database_file(home))
    identity = load_identity(identity_file)
    try:
        row = store.bundle(bundle_id)
        parsed = parse_bundle(row, identity)
        assessment = analyze(store, row["host"], identity, load_config(home).recipients)
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
        if f["band"] != "info"
    ]
    result.events = len(parsed.events)
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
    parser.add_argument("--distro", nargs="+", default=["ubuntu24.04", "rocky9"], choices=IMAGES)
    parser.add_argument("--region", default="us-sea")
    parser.add_argument("--keep", action="store_true", help="don't delete the servers")
    args = parser.parse_args()
    _cancel_on_sigterm()

    api = Linode(linode_token())
    await asyncio.to_thread(sweep, api)
    with tempfile.TemporaryDirectory(prefix="cc-proof-") as work:
        results = await asyncio.gather(
            *(prove(api, distro, args.region, args.keep, Path(work)) for distro in args.distro)
        )
    return 0 if report(list(results)) else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)  # progress shows up as it happens
    raise SystemExit(asyncio.run(main()))
