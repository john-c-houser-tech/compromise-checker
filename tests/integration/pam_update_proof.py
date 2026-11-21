"""PAM update proof (#189, V.6): on throwaway servers, a real PAM update must
read as one low finding, and a swapped module as high.

For each distribution: a fresh Linode with the scanner account (as the
read-only proof sets it up); PAM moved back to an older official version and
a first collection (the baseline); PAM updated the ordinary way, a second
collection and `checker analyze` with verification on (as `checker run`
does); then pam_permit.so copied over pam_unix.so, a third collection and
analysis. Expected:

- after the update: one low `pam.changes` finding (official_update) and no
  medium or high one;
- after the swap: a high `pam.changes` finding (differs) for pam_unix.so.

The servers are deleted afterwards.

    python tests/integration/pam_update_proof.py [--distro ubuntu24.04 rocky9]
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
import detection_proof as detection
import readonly_proof as proof

from checker.assess import analyze
from checker.evidence import Store, database_file, initialise, load_config, load_identity
from checker.inventory import Host
from checker.official import verifier_for

STOP_UPDATES = {
    "ubuntu24.04": "systemctl stop unattended-upgrades apt-daily.timer apt-daily-upgrade.timer"
    " apt-daily.service apt-daily-upgrade.service 2>/dev/null; true",
    "rocky9": "systemctl stop dnf-makecache.timer dnf-automatic.timer 2>/dev/null; true",
}
APT = "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 -y -q"
PAM_PACKAGES = "libpam0g libpam-modules libpam-modules-bin libpam-runtime"
# Back to an older official version: Ubuntu's release pocket, Rocky's vault.
OLDER = {
    "ubuntu24.04": (
        "set -e; apt-get update -q >/dev/null;"
        " v=$(apt-cache madison libpam-modules"
        " | awk -F'|' '$3 ~ / noble\\/main/ {gsub(/ /, \"\", $2); print $2; exit}');"
        ' [ -n "$v" ] || { echo "no release version found" >&2; exit 1; };'
        f' {APT} install --allow-downgrades $(for p in {PAM_PACKAGES}; do echo "$p=$v"; done)'
        " >/dev/null; dpkg-query -W libpam-modules"
    ),
    # Only when no newer pam is waiting already (dnf check-update says 100 when one is).
    "rocky9": (
        "dnf -q check-update pam >/dev/null; [ $? -eq 100 ] || rpm -Uvh --oldpackage"
        " https://dl.rockylinux.org/vault/rocky/9.8/BaseOS/x86_64/os/Packages/p/"
        "pam-1.5.1-28.el9.x86_64.rpm >/dev/null; rpm -q pam"
    ),
}
UPDATE = {
    "ubuntu24.04": f"set -e; {APT} install --only-upgrade {PAM_PACKAGES} >/dev/null;"
    " dpkg-query -W libpam-modules",
    "rocky9": "set -e; dnf -y -q upgrade pam >/dev/null; rpm -q pam",
}
MODULES = {"ubuntu24.04": "/usr/lib/x86_64-linux-gnu/security", "rocky9": "/usr/lib64/security"}


@dataclass
class Result:
    distro: str
    passed: bool = False
    lines: list[str] = field(default_factory=list)
    error: str | None = None


def pam(assessment: dict) -> list[dict]:
    return [f for f in assessment["findings"] if f["check"] == "pam.changes"]


async def run(conn, command: str, what: str) -> str:
    done = await conn.run(command, timeout=1200)
    if done.exit_status != 0:
        raise RuntimeError(f"{what} failed: {(done.stderr or done.stdout)[-500:]}")
    return done.stdout.strip()


async def prove(api, distro: str, region: str, work: Path) -> Result:
    result = Result(distro)
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
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
            address, username="root", client_keys=[root_key], known_hosts=str(known),
            agent_path=None, gss_host=None, config=None,
        ) as conn:  # fmt: skip
            controller = (await conn.run("echo $SSH_CLIENT", check=True, timeout=60)).stdout
            setup = proof.SETUP.replace("{controller}", controller.split()[0]).replace(
                "{scanner_key}", scanner_key.export_public_key().decode().strip()
            )
            await proof.set_up(conn, setup, distro)
            await run(conn, STOP_UPDATES[distro], "stopping automatic updates")
            older = await run(conn, OLDER[distro], "moving PAM back")
            result.lines.append(f"baseline at {older.split()[-1]}")
            home = work / f"{distro}-home"
            config, _ = initialise(home)
            scanner = Host(
                name=distro, address=address, user="scanner", auth="key",
                key_path=str(scanner_key_file), sudo="nopasswd",
            )  # fmt: skip
            store = Store(database_file(home))
            identity = load_identity(Path(config.identity_file))
            recipients = load_config(home).recipients

            def analysed():
                started = time.monotonic()
                found = analyze(
                    store, distro, identity, recipients,
                    whitelist=proof.proof_whitelist(home, distro),
                    verifier=verifier_for(load_config(home).verify, home),
                )  # fmt: skip
                return found, time.monotonic() - started

            try:
                await detection.collect(home, config, scanner, known)
                analysed()  # the baseline
                updated = await run(conn, UPDATE[distro], "updating PAM")
                result.lines.append(f"updated to {updated.split()[-1]}")
                await detection.collect(home, config, scanner, known)
                after, seconds = analysed()
                found = pam(after)
                counts = (after.get("official_files") or {}).get("counts")
                result.lines.append(
                    f"update: {[(f['band'], f.get('variant')) for f in found]},"
                    f" results {counts}, {seconds:.1f} s, {after['score']['band']}"
                    f" ({after['score']['probability']:.4f})"
                )
                update_ok = [f.get("variant") for f in found] == ["official_update"] and all(
                    f["band"] == "low" for f in found
                )
                if not update_ok:
                    result.lines += [f"  {f['band']}: {f['title']}: {f['summary']}" for f in found]
                swap = f"cp {MODULES[distro]}/pam_permit.so {MODULES[distro]}/pam_unix.so"
                await run(conn, swap, "swapping pam_unix.so")
                await detection.collect(home, config, scanner, known)
                swapped, seconds = analysed()
                differs = [
                    f for f in pam(swapped)
                    if f.get("variant") == "differs" and f["band"] == "high"
                    and "pam_unix.so" in f["summary"]
                ]  # fmt: skip
                result.lines.append(
                    f"swap: {[(f['band'], f.get('variant')) for f in pam(swapped)]},"
                    f" {seconds:.1f} s, {swapped['score']['band']}"
                    f" ({swapped['score']['probability']:.4f})"
                )
                result.passed = update_ok and len(differs) == 1
            finally:
                store.close()
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            await asyncio.to_thread(api.delete, node["id"])
            print(f"{distro}: deleted {label}")
        except Exception as exc:  # the end-of-run sweep tries again
            print(f"{distro}: could not delete {label}: {exc}")
    return result


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--distro", nargs="+", default=["ubuntu24.04", "rocky9"], choices=list(OLDER)
    )
    parser.add_argument("--region", default="us-sea")
    args = parser.parse_args()
    proof._cancel_on_sigterm()
    api = proof.Linode(proof.linode_token())
    await asyncio.to_thread(proof.sweep, api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-pam-") as work:
            results = await asyncio.gather(
                *(prove(api, d, args.region, Path(work)) for d in args.distro)
            )
    finally:
        await asyncio.to_thread(proof.sweep_run, api)
    print()
    for r in results:
        print(f"=== {r.distro}: {'PASS' if r.passed and not r.error else 'FAIL'}")
        if r.error:
            print(f"  error: {r.error}")
        for line in r.lines:
            print(f"  {line}")
    return 0 if all(r.passed and not r.error for r in results) else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    sys.exit(asyncio.run(main()))
