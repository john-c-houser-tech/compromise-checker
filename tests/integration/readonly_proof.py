"""Read-only proof on real servers (Phase 0, PR 0.7).

Creates a throwaway Linode per distribution, sets up the scanner account
exactly as docs/scanner-account.md says, records every file write made by
the scanner's login session with auditd, runs a real `checker collect`
against it, and fails if anything was written outside the traces disclosed
in the security and privacy policy §5. Every server it creates is deleted,
and servers left behind by a crashed run are swept up next time.

Run by hand, not in CI: it spends money (a Nanode is $0.0075 an hour) and
needs a Linode API token with Linodes: Read/Write only, from $LINODE_TOKEN or
1Password (item "Linode Personal Access Token" in vault "Linode" by default).

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

from checker.collect import collect_hosts
from checker.evidence import initialise, load_identity, open_bundle
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
# Where the token lives in 1Password (override with $CC_LINODE_OP_ITEM / $CC_LINODE_OP_VAULT).
OP_ITEM = os.environ.get("CC_LINODE_OP_ITEM", "Linode Personal Access Token")
OP_VAULT = os.environ.get("CC_LINODE_OP_VAULT", "Linode")
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
    error: str | None = None


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
# Something for the collector to find in the authentication log.
logger -p authpriv.notice "compromise-checker read-only proof: marker" || true
# Sample the collector's memory while it runs.
nohup sh -c 'while :; do ps -eo rss=,comm= | awk "\$2 ~ /^python/ {print \$1}"; sleep 0.2; done' \
    < /dev/null > /root/cc-rss.log 2>/dev/null &
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


def parse_audit(text: str) -> list[dict]:
    """Events from `ausearch -i`: each with comm, exe, syscall and the paths it
    changed (a PATH record's PARENT entries only name the directory looked in)."""
    events = []
    for block in text.split("----"):
        syscall = re.search(r"type=SYSCALL .*?syscall=(\S+).*? comm=(\S+) exe=(\S+)", block)
        if not syscall:
            continue
        paths = []
        for name, kind in re.findall(r"type=PATH .*?name=(\S+)(?: .*?nametype=(\S+))?", block):
            if kind != "PARENT" and name != "(null)":
                paths.append(name.strip('"'))
        events.append(
            {
                "syscall": syscall.group(1),
                "comm": syscall.group(2).strip('"'),
                "exe": syscall.group(3).strip('"'),
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
    verdict = Verdict()
    for event in events:
        who = f"{event['comm']} ({event['exe']}) {event['syscall']}"
        if event["comm"].startswith("python") or "python" in event["exe"]:
            # The collector itself must write nothing at all.
            verdict.collector.extend(f"{who} {path}" for path in event["paths"] or ["-"])
            continue
        if not event["paths"]:
            if event["syscall"] in _SOCKET_CALLS:
                verdict.sockets.append(who)
            elif event["syscall"] in _FD_ATTRIBUTE_CALLS and event["exe"] == _SESSION_MANAGER:
                verdict.disclosed.append(
                    f"{who} (open file)  — session setup: permissions on its own runtime files"
                )
            else:
                verdict.unexpected.append(f"{who} (no path)")
            continue
        for path in event["paths"]:
            if not path.startswith("/") and event["syscall"].startswith("symlink"):
                continue  # a symbolic link's content, not a location
            reason = next((why for pattern, why in DISCLOSED if pattern.search(path)), None)
            if reason:
                verdict.disclosed.append(f"{who} {path}  — {reason}")
            else:
                verdict.unexpected.append(f"{who} {path}")
    for name in ("collector", "unexpected", "disclosed", "sockets"):
        setattr(verdict, name, sorted(set(getattr(verdict, name))))
    return verdict


async def prove(api: Linode, distro: str, region: str, keep: bool, work: Path) -> Result:
    result = Result(distro)
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key_file = work / f"{distro}-scanner"
    scanner_key.write_private_key(scanner_key_file)
    label = f"{LABEL_PREFIX}{distro.replace('.', '')}-{secrets.token_hex(3)}"
    node = await asyncio.to_thread(
        api.create, label, IMAGES[distro], region, root_key.export_public_key().decode().strip()
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
            config, _ = initialise(home)
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
            # to read audit records from stdin.
            audit = await conn.run(
                "ausearch --input-logs -k cc-write -i < /dev/null 2>/dev/null || true",
                timeout=120,
            )
            result.audit = classify(parse_audit(audit.stdout))
            rss = await conn.run("sort -n /root/cc-rss.log | tail -1", timeout=60)
            result.peak_rss_kb = int(rss.stdout.strip() or 0) or None

        bundle = home / "evidence" / distro / f"{outcome.bundle_id}.age"
        if bundle.exists():
            opened = open_bundle(bundle, load_identity(Path(config.identity_file)))
            opened.status()
            trailer = opened.summary.trailer or {}
            result.seconds = trailer.get("duration_seconds")
            result.sources = [
                f"{s['name']} ({s['bytes']:,} bytes, masked {s['masked'] or 'nothing'})"
                for s in opened.summary.sources
            ]
        audit = result.audit
        result.passed = (
            result.status == "complete"
            and audit is not None
            and not audit.collector
            and not audit.unexpected
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


def _stop_on_sigterm() -> None:
    """Treat SIGTERM like Ctrl-C, so the servers are always deleted."""

    def handler(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handler)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--distro", nargs="+", default=["ubuntu24.04", "rocky9"], choices=IMAGES)
    parser.add_argument("--region", default="us-sea")
    parser.add_argument("--keep", action="store_true", help="don't delete the servers")
    args = parser.parse_args()
    _stop_on_sigterm()

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
