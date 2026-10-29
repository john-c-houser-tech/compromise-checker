"""Detection proof: on throwaway servers, each scripted compromise behaviour
must produce its expected finding (Phase 1 plan, 1.9).

For each distribution: a fresh Linode with the scanner account (as the
read-only proof sets it up), a first collection (the baseline), then the
behaviours below done as root, a second collection, and `checker analyze`.
Every behaviour must show as its finding, at its band or higher. The
servers are deleted afterwards, so nothing needs undoing.

    LINODE_TOKEN=… python tests/integration/detection_proof.py [--distro ubuntu24.04 rocky9 | all]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh
import golden
import readonly_proof as proof

from checker.assess import analyze
from checker.baseline import usable_bundles
from checker.collect import collect_hosts
from checker.evidence import Store, database_file, initialise, load_config, load_identity
from checker.inventory import Host
from checker.protocol import Limits

BANDS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# The behaviours, done as root after the baseline. {root_key} is a public
# key made for this run. Long-running processes are started with setsid so
# they outlive this SSH session.
ATTACKS = r"""
set -u
fail() { echo "ATTACK FAILED: $1" >&2; }
# A second UID 0 account.
useradd -o -u 0 -g 0 -M -s /bin/bash cc-toor || fail uid0
# A new key for root.
install -d -m 700 /root/.ssh && echo '{root_key} cc-proof-backdoor' >> /root/.ssh/authorized_keys \
    || fail key
# A cron job, and a systemd timer with its service.
echo '*/5 * * * * root /usr/bin/true cc-proof' > /etc/cron.d/cc-proof || fail cron
printf '[Unit]\nDescription=cc proof\n[Service]\nExecStart=/usr/bin/true\n' \
    > /etc/systemd/system/cc-proof.service || fail service
printf '[Timer]\nOnCalendar=hourly\n[Install]\nWantedBy=timers.target\n' \
    > /etc/systemd/system/cc-proof.timer || fail timer
# /etc/ld.so.preload, with a real and harmless library (libm), so every
# program still runs.
lib=$(ldconfig -p | awk '/libm\.so\.6 .*x86-64/ {print $NF; exit}')
[ -n "$lib" ] && echo "$lib" > /etc/ld.so.preload || fail preload
# A set-user-ID copy of a shell in /tmp.
cp /bin/bash /tmp/.cc-sh && chmod 4755 /tmp/.cc-sh || fail suid
# A process running from a deleted program (in root's home, not a scratch
# place, so it is the deletion that has to be noticed).
cp "$(command -v sleep)" /root/cc-sleep && setsid -f /root/cc-sleep 7200 </dev/null >/dev/null 2>&1
sleep 1; rm -f /root/cc-sleep
pgrep -f '^/root/cc-sleep 7200' >/dev/null || fail deleted-program
# A shell whose input and output are a TCP socket (to a local listener).
setsid -f python3 -c 'import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 4444)); s.listen(1); c, _ = s.accept(); time.sleep(7200)' \
    </dev/null >/dev/null 2>&1
# Wait until it is really listening (127.0.0.1:4444 is 0100007F:115C in
# /proc/net/tcp, state 0A), not merely started.
for _ in $(seq 20); do
    grep -q ' 0100007F:115C 00000000:0000 0A ' /proc/net/tcp && break
    sleep 0.5
done
grep -q ' 0100007F:115C 00000000:0000 0A ' /proc/net/tcp || fail listener
# Only its input on the socket (output elsewhere), so it is the shell's
# name that has to be recognised, not one socket on both streams. A failed
# redirection doesn't stop bash, so it exits itself.
setsid -f bash -c \
    'exec 0<>/dev/tcp/127.0.0.1/4444 1>/dev/null 2>&1 || exit 1; while :; do sleep 3600; done' \
    </dev/null >/dev/null 2>&1
sleep 1
shell=$(pgrep -f 'dev/tcp/127.0.0.1/4444' | head -1)
[ -n "$shell" ] && readlink "/proc/$shell/fd/0" | grep -q '^socket:' || fail reverse-shell
# sshd configured to allow root login (not reloaded: the file is the evidence).
mkdir -p /etc/ssh/sshd_config.d
grep -qi '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config \
    || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/00-cc-proof.conf || fail sshd
# A pam_exec line (runs /bin/true at each login).
echo 'session optional pam_exec.so quiet /bin/true' >> /etc/pam.d/sshd || fail pam
# --- Network (2.4b) ---
# A shell holding a connection to the cloud metadata address.
setsid -f bash -c 'exec 3<>/dev/tcp/169.254.169.254/80 || exit 1; sleep 7200' \
    </dev/null >/dev/null 2>&1
# A web-server account reaching SMB: a local listener on port 445 (so the
# connection is really established, whatever the network does), and
# www-data connecting to it.
id www-data >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin www-data
setsid -f python3 -c 'import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 445)); s.listen(1); c, _ = s.accept(); time.sleep(7200)' \
    </dev/null >/dev/null 2>&1
for _ in $(seq 20); do
    grep -q ' 0100007F:01BD 00000000:0000 0A ' /proc/net/tcp && break
    sleep 0.5
done
setsid -f runuser -u www-data -- bash -c \
    'exec 3<>/dev/tcp/127.0.0.1/445 || exit 1; sleep 7200' </dev/null >/dev/null 2>&1
# An SSH remote forward into this host, with a key made for it.
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/cc_tunnel \
    && cat /root/.ssh/cc_tunnel.pub >> /root/.ssh/authorized_keys \
    && ssh -f -N -o StrictHostKeyChecking=no -o BatchMode=yes -i /root/.ssh/cc_tunnel \
        -R 127.0.0.1:2222:127.0.0.1:22 root@127.0.0.1 || fail ssh-tunnel
# /etc/hosts redirecting a name.
echo '203.0.113.66 github.com' >> /etc/hosts || fail hosts
sleep 2
# By their sockets: bash replaces itself with its last command (sleep), so
# its own command line is gone.
ss -tnH state established dst 169.254.169.254 | grep -q . || fail metadata
ss -tnH state established dst 127.0.0.1:445 | grep -q . || fail directory
pgrep -f 'R 127.0.0.1:2222' >/dev/null || fail ssh-tunnel-running
# --- Anti-forensics (2.5) ---
# Root's history sent to /dev/null.
ln -sf /dev/null /root/.bash_history || fail history
# auditd stopped (RHEL refuses `systemctl stop auditd`; `service` works).
systemctl stop auditd 2>/dev/null || service auditd stop >/dev/null 2>&1 || fail auditd
# SELinux to permissive (RHEL family), or AppArmor's profiles unloaded (Ubuntu).
if command -v setenforce >/dev/null 2>&1 && [ -e /sys/fs/selinux/enforce ]; then
    setenforce 0 || fail selinux
elif command -v aa-teardown >/dev/null 2>&1; then
    aa-teardown >/dev/null 2>&1 || fail apparmor
else
    fail mac-unavailable
fi
# The login records emptied.
: > /var/log/wtmp || fail wtmp
sleep 2
"""


@dataclass
class Expected:
    behaviour: str
    check: str
    marker: str  # in the finding's summary (lower case compared)
    band: str  # at least this
    title: str = ""  # and this in its title, where the check has several rules


def expectations(root_fingerprint: str) -> list[Expected]:
    return [
        Expected("a second UID 0 account", "account.uid0", "cc-toor", "high"),
        Expected("a new authorized key for root", "ssh.authorized_keys", root_fingerprint, "high"),
        Expected("a cron job added", "persistence.changes", "/etc/cron.d/cc-proof", "medium"),
        Expected(
            "a systemd timer added",
            "persistence.changes",
            "/etc/systemd/system/cc-proof.timer",
            "medium",
        ),
        Expected("/etc/ld.so.preload set", "persistence.ld_preload", "/etc/ld.so.preload", "high"),
        Expected("a set-user-ID shell in /tmp", "files.privileged", "/tmp/.cc-sh", "high"),
        Expected(
            "a process running from a deleted program",
            "process.executable",
            "/root/cc-sleep (deleted)",
            "high",
            "deleted",
        ),
        Expected(
            "a shell with its input on a socket",
            "process.reverse_shell",
            "bash (pid",
            "high",
            "shell",
        ),
        Expected("sshd allowing root login", "sshd.config", "permitrootlogin yes", "high"),
        Expected("a pam_exec line added", "pam.changes", "pam_exec.so", "high"),
        Expected(
            "a shell reaching the metadata address", "net.metadata", "169.254.169.254", "medium"
        ),
        Expected("a web-server account reaching SMB", "net.directory", "port 445", "high"),
        Expected("an SSH remote forward", "net.tunnel", "-r 127.0.0.1:2222", "medium", "client"),
        Expected(
            "the SSH session holding the forward",
            "net.tunnel",
            "port 2222",
            "medium",
            "session",
        ),
        Expected("/etc/hosts rewritten", "net.config", "/etc/hosts", "medium"),
        Expected(
            "root's history linked to /dev/null",
            "history.disabled",
            "/root/.bash_history",
            "high",
            "/dev/null",
        ),
        Expected("auditd stopped", "logs.stopped", "", "high"),
        Expected("SELinux or AppArmor turned down", "mac.disabled", "", "high"),
        Expected("the login records emptied", "logs.cleared", "/var/log/wtmp", "high"),
    ]


@dataclass
class Result:
    distro: str
    passed: bool = False
    found: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)  # findings no behaviour explains
    error: str | None = None


def judge(findings: list[dict], expected: list[Expected]) -> tuple[list, list, list]:
    # A suppressed finding doesn't count: the proof's whitelist covers its
    # own setup only, and a behaviour it hid would be a miss.
    findings = [f for f in findings if not f.get("suppressed_by")]
    found, missing, explained = [], [], set()
    for want in expected:
        hits = [
            (i, f)
            for i, f in enumerate(findings)
            if f["check"] == want.check
            and want.marker.lower() in f["summary"].lower()
            and want.title.lower() in f["title"].lower()
            and BANDS[f["band"]] >= BANDS[want.band]
        ]
        if hits:
            explained.update(i for i, _ in hits)
            i, f = hits[0]
            found.append(f"{want.behaviour}: {f['band']} {f['title']} — {f['summary'][:100]}")
        else:
            same = [f for f in findings if f["check"] == want.check]
            # The one about this behaviour (found, but too low), else any of its check.
            near = [f for f in same if want.marker.lower() in f["summary"].lower()] or same
            missing.append(
                f"{want.behaviour}: no {want.check} finding with {want.marker!r} at {want.band}+"
                + (f" (saw: {near[0]['band']} {near[0]['summary'][:80]})" if near else "")
            )
    other = [
        f"{f['band']} {f['check']}: {f['title']} — {f['summary'][:100]}"
        for i, f in enumerate(findings)
        if i not in explained and f["band"] in ("critical", "high", "medium")
    ]
    return found, missing, other


async def collect(home: Path, config, scanner: Host, known: Path):
    [outcome] = await collect_hosts(
        home,
        config,
        [scanner],
        known_hosts=known,
        limits=Limits(overall_seconds=600, module_seconds=300, source_bytes=1 << 28),
    )
    if outcome.status not in ("complete", "partial"):
        raise RuntimeError(f"collection {outcome.status}: {outcome.error}")
    return outcome


async def detect(
    api, distro: str, region: str, keep: bool, work: Path, golden_dir: Path | None = None
) -> Result:
    result = Result(distro)
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
    backdoor = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key_file = work / f"{distro}-scanner"
    scanner_key.write_private_key(scanner_key_file)
    label = proof.run_label(distro)
    try:
        node = await proof._create_server(
            api, label, proof.IMAGES[distro], region, root_key.export_public_key().decode().strip()
        )
    except Exception as exc:
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
        await proof.wait_for_ssh(
            Host(name=f"{distro}-root", address=address, user="root", sudo="root"),
            known,
            deadline,
        )
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
            setup = proof.SETUP.replace("{controller}", controller.split()[0]).replace(
                "{scanner_key}", scanner_key.export_public_key().decode().strip()
            )
            await conn.run(setup, check=True, timeout=600)
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
            await collect(home, config, scanner, known)
            print(f"{distro}: baseline collected; planting the behaviours")
            attacks = ATTACKS.replace("{root_key}", backdoor.export_public_key().decode().strip())
            # On standard input, not as `bash -c <script>`: otherwise the
            # script's own shell would carry every pattern its pgrep checks
            # look for, and they would always succeed.
            done = await conn.run("bash -s", input=attacks, timeout=300)
            for line in done.stderr.splitlines():
                if line.startswith("ATTACK FAILED"):
                    result.missing.append(line)
        await collect(home, config, scanner, known)
        store = Store(database_file(home))
        try:
            identity = load_identity(Path(config.identity_file))
            recipients = load_config(home).recipients
            assessment = analyze(
                store, distro, identity, recipients, whitelist=proof.proof_whitelist(home, distro)
            )
            if golden_dir is not None:
                # The fresh server (the first bundle, its own baseline) and
                # the compromised one (the second, against it).
                protect = [controller.split()[0], address, *node.get("ipv6", "").split("/")[:1]]
                rows = usable_bundles(store, distro)
                first, last = rows[0]["id"], rows[-1]["id"]
                for name, bundle in ((f"fresh-{distro}", first), (f"detection-{distro}", last)):
                    path = golden.export_case(
                        store,
                        distro,
                        identity,
                        recipients,
                        bundle,
                        name,
                        [p for p in protect if p],
                        golden_dir,
                    )
                    print(f"{distro}: golden case {path}")
        finally:
            store.close()
        failed = [c for c in assessment["checks"] if c["status"].startswith("failed")]
        result.missing += [f"check {c['check']} {c['status']}" for c in failed]
        found, missing, other = judge(
            assessment["findings"], expectations(backdoor.get_fingerprint("sha256"))
        )
        result.found, result.other = found, other
        result.missing += missing
        result.passed = not result.missing
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        if keep:
            print(f"{distro}: --keep: leaving {label} running (id {node['id']})")
        else:
            try:
                await asyncio.to_thread(api.delete, node["id"])
                print(f"{distro}: deleted {label}")
            except Exception as exc:  # the end-of-run sweep tries again
                print(f"{distro}: could not delete {label}: {exc}")
    return result


def report(results: list[Result]) -> bool:
    print()
    for r in results:
        print(f"=== {r.distro}: {'PASS' if r.passed and not r.error else 'FAIL'}")
        if r.error:
            print(f"  error: {r.error}")
        for line in r.found:
            print(f"  detected  {line}")
        for line in r.missing:
            print(f"  MISSED    {line}")
        if r.other:
            print("  other medium and high findings (the proof's own setup, or to look at):")
            for line in r.other:
                print(f"    {line}")
    return all(r.passed and not r.error for r in results)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--distro", nargs="+", default=["ubuntu24.04", "rocky9"], choices=[*proof.IMAGES, "all"]
    )
    parser.add_argument("--region", default="us-sea")
    parser.add_argument("--keep", action="store_true", help="don't delete the servers")
    parser.add_argument(
        "--golden",
        metavar="DIR",
        type=Path,
        help="also write golden cases (tests/golden) for each distribution, addresses replaced",
    )
    args = parser.parse_args()
    if "all" in args.distro:
        args.distro = list(proof.IMAGES)
    proof._cancel_on_sigterm()
    api = proof.Linode(proof.linode_token())
    await asyncio.to_thread(proof.sweep, api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-detect-") as work:
            results = await asyncio.gather(
                *(
                    detect(api, d, args.region, args.keep, Path(work), args.golden)
                    for d in args.distro
                )
            )
    finally:
        if not args.keep:
            await asyncio.to_thread(proof.sweep_run, api)
    return 0 if report(list(results)) else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(asyncio.run(main()))
