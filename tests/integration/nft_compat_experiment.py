"""The nft_compat experiment (plan 2.4b, approved by John 2026-10-28): can a
host's iptables-nft rules (ufw, Docker) be listed without the kernel loading
a module?

On throwaway Ubuntu servers with ufw enabled and Docker running a
container (both put rules through nft_compat), it lists the rules with
`nft list ruleset`, `iptables-nft-save` and `ip6tables-nft-save`, several
times each, and compares the kernel's module list before and after every
single run. Any module loaded or unloaded around a listing is a failure:
the collector then keeps the gap.

    python tests/integration/nft_compat_experiment.py [--distro ubuntu24.04 …]

Uses the read-only proof's Linode handling (token, labels, sweeps)."""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh
import readonly_proof as proof

from checker.inventory import Host

DISTROS = ("ubuntu22.04", "ubuntu24.04", "ubuntu26.04")
ROUNDS = 5
LISTINGS = ("nft list ruleset", "nft -j list ruleset", "iptables-nft-save", "ip6tables-nft-save")

SETUP = r"""
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq docker.io nftables >/dev/null
systemctl enable --now docker >/dev/null
docker run -d --name cc-web -p 8080:80 docker.io/library/nginx:alpine >/dev/null
ufw allow 22/tcp >/dev/null
ufw allow 8080/tcp >/dev/null
ufw --force enable >/dev/null
sleep 5
"""


@dataclass
class Result:
    distro: str
    passed: bool = False
    compat_loaded: bool = False
    xt_rules: int = 0  # translated xtables lines in nft's output
    changes: list[str] = field(default_factory=list)
    listings: dict[str, str] = field(default_factory=dict)  # command: exit status / size
    error: str | None = None


async def modules(conn) -> set[str]:
    listed = await conn.run("cut -d' ' -f1 /proc/modules", check=True, timeout=60)
    return set(listed.stdout.split())


async def experiment(api, distro: str, region: str, work: Path) -> Result:
    result = Result(distro)
    root_key = asyncssh.generate_private_key("ssh-ed25519")
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
        deadline = time.monotonic() + 900
        while node["status"] != "running":
            if time.monotonic() > deadline:
                raise TimeoutError("server did not start within 15 minutes")
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
            await conn.run(SETUP, check=True, timeout=900)
            print(f"{distro}: ufw enabled, Docker running a container")
            result.compat_loaded = "nft_compat" in await modules(conn)
            for number in range(ROUNDS):
                for command in LISTINGS:
                    before = await modules(conn)
                    done = await conn.run(f"{command} 2>&1", timeout=120)
                    after = await modules(conn)
                    out = done.stdout or ""
                    result.listings[command] = f"exit {done.exit_status}, {len(out)} bytes"
                    if command.startswith("nft") and number == 0:
                        result.xt_rules = out.count("xt ") + out.count("# xt_")
                    for name in sorted(after - before):
                        result.changes.append(f"round {number + 1}, {command}: +{name}")
                    for name in sorted(before - after):
                        result.changes.append(f"round {number + 1}, {command}: -{name}")
        result.passed = result.compat_loaded and not result.changes
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            await asyncio.to_thread(api.delete, node["id"])
            print(f"{distro}: deleted {label}")
        except Exception as exc:  # the end-of-run sweep tries again
            print(f"{distro}: could not delete {label}: {exc}")
    return result


def report(results: list[Result]) -> bool:
    print()
    for r in results:
        print(f"=== {r.distro}: {'CLEAN' if r.passed else 'NOT CLEAN'}")
        if r.error:
            print(f"  error: {r.error}")
        print(f"  nft_compat loaded: {r.compat_loaded}; translated xtables lines: {r.xt_rules}")
        for command, outcome in r.listings.items():
            print(f"  {command}: {outcome}")
        for change in r.changes:
            print(f"  MODULE CHANGED: {change}")
        if not r.changes and not r.error:
            print(f"  no module loaded or unloaded around {ROUNDS} rounds of each listing")
    return all(r.passed and not r.error for r in results)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--distro", nargs="+", default=list(DISTROS), choices=DISTROS)
    parser.add_argument("--region", default="us-sea")
    args = parser.parse_args()
    proof._cancel_on_sigterm()
    api = proof.Linode(proof.linode_token())
    await asyncio.to_thread(proof.sweep, api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-nftcompat-") as work:
            results = await asyncio.gather(
                *(experiment(api, d, args.region, Path(work)) for d in args.distro)
            )
    finally:
        await asyncio.to_thread(proof.sweep_run, api)
    return 0 if report(list(results)) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
