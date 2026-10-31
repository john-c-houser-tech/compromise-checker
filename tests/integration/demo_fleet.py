"""The demo fleet (plan 5.7, W4): real collections and real analyses from throwaway servers,
for the screenshots. Nothing here is mocked: the attacks are the detection proof's behaviours,
really done on servers made for it, and the vulnerable PHP is an older vendor build. The servers
are deleted afterwards. The home it fills holds their real addresses and the controller's, so it
stays out of the repository; screenshots.py scrubs every page it photographs.

Costs Linode time (about 3 cents): run only with John's approval.

    LINODE_TOKEN=… python tests/integration/demo_fleet.py --home DIR --pack PATH/PACK.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import asyncssh
import detection_proof as detection
import php2shell_proof as php
import readonly_proof as proof

from checker import cli
from checker.baseline import usable_bundles
from checker.collect import collect_hosts
from checker.evidence import Store, database_file, initialise
from checker.inventory import Host, inventory_transaction

# The proof's names read as test scaffolding in a picture: the behaviours are the same.
DEMO_NAMES = (
    ("cc-toor", "sysmaint"),
    ("cc-proof-backdoor", "root@vps-4417"),
    ("cc-proof", "sysupdate"),
    ("ccadmin", "deploy2"),
    ("cc-sleep", "kworkerd"),
    ("cc-", "sys-"),
)
SMALL_ATTACK = r"""
set -u
useradd -m -s /bin/bash deploy2
install -d -m 700 -o deploy2 -g deploy2 /home/deploy2/.ssh
echo '{admin_key} deploy2@laptop' > /home/deploy2/.ssh/authorized_keys
chown deploy2:deploy2 /home/deploy2/.ssh/authorized_keys
echo 'deploy2 ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy2
echo '*/10 * * * * root /usr/bin/true sysupdate' > /etc/cron.d/sysupdate
"""


@dataclass(frozen=True)
class Member:
    name: str
    group: str
    distro: str
    role: str  # attacked, small, vulnerable or clean


FLEET = (
    Member("shop-web-1", "web", "ubuntu24.04", "attacked"),
    Member("shop-web-2", "web", "ubuntu24.04", "vulnerable"),
    Member("db-1", "database", "rocky9", "small"),
    Member("mail-1", "mail", "ubuntu24.04", "clean"),
    Member("app-1", "web", "rocky9", "clean"),
)
UNREACHABLE = "old-box"


def demo_names(script: str) -> str:
    for old, new in DEMO_NAMES:
        script = script.replace(old, new)
    return script


async def member_run(
    api, member: Member, home: Path, config, region: str, work: Path, protect: set
):
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
    other = asyncssh.generate_private_key("ssh-ed25519")
    admin = asyncssh.generate_private_key("ssh-ed25519")
    key_file = work / f"{member.name}-scanner"
    scanner_key.write_private_key(key_file)
    label = proof.run_label(member.name)
    node = await proof._create_server(
        api, label, proof.IMAGES[member.distro], region,
        root_key.export_public_key().decode().strip(),
    )  # fmt: skip
    print(f"{member.name}: created (id {node['id']})")
    try:
        deadline = time.monotonic() + 600
        while node["status"] != "running":
            if time.monotonic() > deadline:
                raise TimeoutError("server did not start within 10 minutes")
            await asyncio.sleep(5)
            node = await asyncio.to_thread(api.get, node["id"])
        address = node["ipv4"][0]
        protect.update([address, *(node.get("ipv6", "").split("/")[:1])])
        known = work / f"{member.name}-known_hosts"
        root = Host(name=f"{member.name}-root", address=address, user="root", sudo="root")
        await proof.wait_for_ssh(root, known, deadline)
        connect = {"known_hosts": str(known), "agent_path": None, "gss_host": None, "config": None}
        async with asyncssh.connect(
            address, username="root", client_keys=[root_key], **connect
        ) as conn:
            controller = (await conn.run("echo $SSH_CLIENT", check=True, timeout=60)).stdout
            protect.add(controller.split()[0])
            setup = proof.SETUP.replace("{controller}", controller.split()[0]).replace(
                "{scanner_key}", scanner_key.export_public_key().decode().strip()
            )
            await conn.run(setup, check=True, timeout=600)
            await conn.run(detection.WEB_SETUP, check=True, timeout=120)
            if member.role == "vulnerable":
                await conn.run(php.SCENARIOS["ubuntu-own"].install, check=True, timeout=600)
            scanner = Host(
                name=member.name,
                address=address,
                user="scanner",
                auth="key",
                key_path=str(key_file),
                sudo="nopasswd",
                group=member.group,
            )
            with inventory_transaction() as hosts:
                hosts.add(scanner)
            proof.proof_whitelist(home, member.name)
            await detection.collect(home, config, scanner, known)
            print(f"{member.name}: first check collected")
            keys = {
                "{root_key}": other.export_public_key().decode().strip(),
                "{admin_key}": admin.export_public_key().decode().strip(),
            }
            script = None
            if member.role == "attacked":
                script = demo_names(detection.ATTACKS)
            elif member.role == "small":
                script = SMALL_ATTACK
            if script:
                for name, value in keys.items():
                    script = script.replace(name, value)
                await conn.run("bash -s", input=script, timeout=900)
                print(f"{member.name}: behaviours done")
        if member.role in ("attacked", "small"):
            account = "deploy2"
            async with asyncssh.connect(
                address, username=account, client_keys=[admin], **connect
            ) as logged_in:
                await logged_in.run("true", timeout=60)
        await detection.collect(home, config, scanner, known)
        print(f"{member.name}: second check collected")
    finally:
        await asyncio.to_thread(api.delete, node["id"])
        print(f"{member.name}: server deleted")


def analyse_in_order(home: Path) -> None:
    """Each collection in turn, as a daily run would: the first sets the baseline, and the
    next shows what changed."""
    store = Store(database_file(home))
    try:
        for host in store.hosts():
            for row in usable_bundles(store, host):
                with contextlib.redirect_stdout(io.StringIO()):
                    cli.main(["analyze", host, "--bundle", row["id"]])
    finally:
        store.close()


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument(
        "--pack", type=Path, required=True, help="a signed pack (its .minisig beside it)"
    )
    parser.add_argument("--region", default="us-sea")
    args = parser.parse_args()
    if args.home.exists() and any(args.home.iterdir()):
        sys.exit(f"{args.home} isn't empty: give a new folder")
    os.environ["CHECKER_HOME"] = str(args.home)
    config, _ = initialise(args.home, web_access_logs=True)
    if cli.main(["packs", "add", str(args.pack)]) != 0:
        return 1
    proof._cancel_on_sigterm()
    api = proof.Linode(proof.linode_token())
    await asyncio.to_thread(proof.sweep, api)
    protect: set[str] = set()
    failed = 0
    try:
        with tempfile.TemporaryDirectory(prefix="cc-demo-") as work:
            results = await asyncio.gather(
                *(
                    member_run(api, m, args.home, config, args.region, Path(work), protect)
                    for m in FLEET
                ),
                return_exceptions=True,
            )
        for member, result in zip(FLEET, results, strict=True):
            if isinstance(result, BaseException):
                failed += 1
                print(f"{member.name}: FAILED: {type(result).__name__}: {result}")
    finally:
        await asyncio.to_thread(proof.sweep_run, api)
    # A server that can't be reached, on a documentation address: every check fails.
    gone = Host(
        name=UNREACHABLE, address="192.0.2.10", user="scanner", auth="agent", sudo="nopasswd"
    )
    with inventory_transaction() as hosts:
        hosts.add(gone)
    try:
        await asyncio.wait_for(collect_hosts(args.home, config, [gone]), 60)
    except Exception as exc:  # noqa: BLE001 - its failing is the point
        print(f"{UNREACHABLE}: {type(exc).__name__}")
    (args.home / "demo-protect.json").write_text(json.dumps(sorted(p for p in protect if p)))
    analyse_in_order(args.home)
    cli.main(["fleet"])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(asyncio.run(main()))
