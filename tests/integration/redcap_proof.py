"""The REDCap pack on real servers (plan A.6, plans/application-exposure-plan-2026-11-26.md):
each stage of a throwaway Linode must be judged as the stage says. No exploit is run and no
REDCap code is used: the install is a fake tree in REDCap's layout (entry points, `redcap_vX.Y.Z`
version folders holding dummy PHP files, an `edocs/` upload folder), made on the server.

Stages, each collected and analysed with the tool's real limits:

1. vulnerable: one install, its newest version folder 17.3.9.
2. staging folder: the campaign's `/var/tmp/.syslog-<hash>` folder appears.
3. fixed: 17.3.10 is unpacked beside 17.3.9 (old folders stay, as REDCap's upgrade leaves them).
4. busy, with UAT: a second install, `redcap-uat` on 17.3.9, and enough uploads in the first
   install's `edocs/` to cut the web roots' walk short at its entry limit.
5. busy, UAT fixed: 17.3.10 unpacked in the UAT install too.

The pack is read as a file, unsigned: this proves what it judges, before it is merged. Its
version folder patterns are sent as the controller sends those of the packs in force. The
servers are deleted afterwards.

    python tests/integration/redcap_proof.py --pack PATH/PACK.yaml
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
import readonly_proof as proof

import checker.collect as collecting
from checker.analysis import snapshot_of
from checker.assess import analyze
from checker.collect import DEFAULT_LIMITS, collect_hosts
from checker.evidence import Store, database_file, initialise, load_config, load_identity
from checker.inventory import Host
from checker.packs.applications import patterns
from checker.packs.format import read

PACK_ID = "redcap-2026-09"
SITE = "/var/www/html/redcap"
UAT = "/var/www/html/redcap-uat"
# More than the collector's 200,000-entry limit for a web root, with what the installs hold.
UPLOADS = 205_000


@dataclass(frozen=True)
class Scenario:
    name: str
    distro: str
    install: str  # a web server and PHP-FPM, as a REDCap host has


SCENARIOS = {
    "ubuntu": Scenario(
        "ubuntu",
        "ubuntu24.04",
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get -y -q -o DPkg::Lock::Timeout=300 update\n"
        "apt-get -y -q -o DPkg::Lock::Timeout=300 install nginx php-fpm\n",
    ),
    "rocky": Scenario("rocky", "rocky9", "dnf -y -q install nginx php-fpm\n"),
}

# Made on the server with its own python3: the tree, by folder names and dummy files only.
TREE = r"""
python3 -I - "$@" <<'PY'
import os, sys
what, site, version, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
def write(path, data=b"<?php // a stand-in for the proof, not REDCap's code\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
if what == "entry":
    entries = ("index.php", "surveys/index.php", "api/index.php", "temp/cache/.keep", "edocs/.keep")
    for name in entries:
        write(f"{site}/{name}")
elif what == "version":
    for n in range(count):
        write(f"{site}/redcap_v{version}/Classes/Part{n % 20}/File{n}.php")
elif what == "uploads":
    for n in range(count):
        write(f"{site}/edocs/{n % 400:03d}/20261127_{n:06d}_upload.pdf", b"%PDF-1.4\n")
PY
"""


def tree(what: str, site: str, version: str = "-", count: int = 0) -> str:
    return f"set -- {what} {site} {version} {count}\n" + TREE


@dataclass
class Result:
    scenario: str
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    timings: list[str] = field(default_factory=list)
    error: str | None = None


def facts(assessment: dict, snapshot) -> dict:
    exposure = next(e for e in assessment["exposures"] if e["pack"] == PACK_ID)
    return {
        "exposure": exposure,
        "installs": {a["path"]: a for a in exposure.get("applications", [])},
        "variants": {
            f.get("variant") for f in assessment["findings"] if f["check"] == "pack.exposure"
        },
        "detections": {
            f["variant"].partition("/")[2]
            for f in assessment["findings"]
            if f["check"] == "pack.detection"
        },
        "gaps": assessment["coverage"]["gaps"],
        "score": assessment["score"],
        "walk": (snapshot.live.get("web_walks") or {}).get("/var/www") or {},
        "time_limit": bool(snapshot.live.get("web_time_limit")),
        "said": [f["summary"] for f in assessment["findings"] if f["check"] == "pack.exposure"],
    }


def expect(result: Result, stage: str, claims: list[tuple[str, bool]], seen: dict) -> None:
    installs = ", ".join(
        f"{p} {a.get('version')} {a.get('status')}" for p, a in sorted(seen["installs"].items())
    )
    summary = (
        f"status {seen['exposure']['status']}, share {seen['exposure']['share']},"
        f" judged {seen['exposure'].get('judged')}, partial {seen['exposure'].get('partial')},"
        f" installs [{installs}], detections {sorted(seen['detections'])},"
        f" walk {seen['walk']}, time limit {seen['time_limit']},"
        f" prior {seen['score'].get('raised_prior')}"
    )
    print(f"{result.scenario}: {stage}: {summary}")
    for line in seen["said"]:
        print(f"{result.scenario}:   {line[:300]}")
    for claim, held in claims:
        (result.passed if held else result.failed).append(f"{stage}: {claim}")
    if not all(held for _, held in claims):
        result.failed.append(f"{stage}: saw {summary}")


def status_of(seen: dict, path: str) -> str | None:
    return (seen["installs"].get(path) or {}).get("status")


async def prove(api, scenario: Scenario, pack, region: str, work: Path) -> Result:
    result = Result(scenario.name)
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
    key_file = work / f"{scenario.name}-scanner"
    scanner_key.write_private_key(key_file)
    label = proof.run_label(f"redcap-{scenario.name}")
    try:
        node = await proof._create_server(
            api, label, proof.IMAGES[scenario.distro], region,
            root_key.export_public_key().decode().strip(),
        )  # fmt: skip
    except Exception as exc:
        result.error = f"could not create the server: {type(exc).__name__}: {exc}"
        return result
    print(f"{scenario.name}: created {label} (id {node['id']})")
    try:
        deadline = time.monotonic() + 600
        while node["status"] != "running":
            if time.monotonic() > deadline:
                raise TimeoutError("server did not start within 10 minutes")
            await asyncio.sleep(5)
            node = await asyncio.to_thread(api.get, node["id"])
        address = node["ipv4"][0]
        known = work / f"{scenario.name}-known_hosts"
        root = Host(name=f"{scenario.name}-root", address=address, user="root", sudo="root")
        await proof.wait_for_ssh(root, known, deadline)
        async with asyncssh.connect(
            address, username="root", client_keys=[root_key], known_hosts=str(known),
            agent_path=None, gss_host=None, config=None,
        ) as conn:  # fmt: skip
            controller = (await conn.run("echo $SSH_CLIENT", check=True, timeout=60)).stdout
            setup = proof.SETUP.replace("{controller}", controller.split()[0]).replace(
                "{scanner_key}", scanner_key.export_public_key().decode().strip()
            )
            await proof.set_up(conn, setup, scenario.name)
            home = work / f"{scenario.name}-home"
            config, _ = initialise(home)
            scanner = Host(
                name=scenario.name, address=address, user="scanner", auth="key",
                key_path=str(key_file), sudo="nopasswd",
            )  # fmt: skip

            async def shell(script: str) -> None:
                done = await conn.run(proof.strict(script), timeout=1800)
                if done.exit_status != 0:
                    raise RuntimeError(f"on the server: {done.stderr[-600:]}")

            async def look(stage: str) -> dict:
                started = time.monotonic()
                [outcome] = await collect_hosts(
                    home, config, [scanner], known_hosts=known, limits=DEFAULT_LIMITS
                )
                took = time.monotonic() - started
                result.timings.append(f"{stage}: collection {took:.0f} s ({outcome.status})")
                if outcome.status not in ("complete", "partial"):
                    raise RuntimeError(f"collection {outcome.status}: {outcome.error}")
                store = Store(database_file(home))
                try:
                    identity = load_identity(Path(config.identity_file))
                    recipients = load_config(home).recipients
                    assessment = analyze(
                        store, scenario.name, identity, recipients, packs=[pack],
                        whitelist=proof.proof_whitelist(home, scenario.name),
                    )  # fmt: skip
                    row = store.bundle(assessment["bundle_id"])
                    return facts(assessment, snapshot_of(store, row, identity, recipients))
                finally:
                    store.close()

            await shell(scenario.install)
            await shell(tree("entry", SITE) + tree("version", SITE, "17.3.9", 600))
            seen = await look("vulnerable")
            expect(result, "vulnerable", [
                ("reads vulnerable", seen["exposure"]["status"] == "vulnerable"),
                ("the install is 17.3.9, vulnerable",
                 status_of(seen, SITE) == "vulnerable"
                 and seen["installs"][SITE]["version"] == "17.3.9"),
                ("it is a finding", "vulnerable" in seen["variants"]),
                ("the prior is raised",
                 (seen["score"].get("raised_prior") or 0) > seen["score"]["prior"]),
                ("the newest-folder note is said",
                 any("newest version folder" in g for g in seen["gaps"])),
                ("the walk was whole", seen["walk"].get("whole") is True),
                ("no detection fires", not seen["detections"]),
            ], seen)  # fmt: skip

            await shell("mkdir -p /var/tmp/.syslog-a224be51\n")
            seen = await look("staging folder")
            expect(result, "staging folder", [
                ("the staging folder fires", "staging-folder" in seen["detections"]),
            ], seen)  # fmt: skip
            await shell("rmdir /var/tmp/.syslog-a224be51\n")

            await shell(tree("version", SITE, "17.3.10", 600))
            seen = await look("fixed")
            expect(result, "fixed", [
                ("reads fixed", seen["exposure"]["status"] == "fixed"),
                ("the install is 17.3.10, fixed, the old folder still there",
                 status_of(seen, SITE) == "fixed"
                 and seen["installs"][SITE]["versions_seen"] == ["17.3.9", "17.3.10"]),
                ("the fix has a time", bool(seen["installs"][SITE].get("fixed_since"))),
                ("the exposure has an end", seen["exposure"]["exposed_until"] is not None),
                ("was exposed is said", "was_exposed" in seen["variants"]),
            ], seen)  # fmt: skip

            await shell(
                tree("entry", UAT) + tree("version", UAT, "17.3.9", 600)
                + tree("uploads", SITE, "-", UPLOADS)
                # Fresh files sit in the page cache: dropped, so the walk reads the
                # disk as a real server's daily collection would.
                + "sync\necho 3 > /proc/sys/vm/drop_caches\n"
            )  # fmt: skip
            seen = await look("busy, with UAT")
            expect(result, "busy, with UAT", [
                ("the walk was cut short", seen["walk"].get("whole") is False),
                ("not by the time limit", not seen["time_limit"]),
                ("the version folders were walked first and whole",
                 seen["walk"].get("first_whole") is True),
                ("every folder down to 3 levels was listed",
                 (seen["walk"].get("levels_whole") or 0) >= 3),
                ("both installs are found",
                 status_of(seen, SITE) == "fixed" and status_of(seen, UAT) == "vulnerable"),
                ("the host reads vulnerable", seen["exposure"]["status"] == "vulnerable"),
            ], seen)  # fmt: skip

            await shell(tree("version", UAT, "17.3.10", 600))
            seen = await look("busy, UAT fixed")
            expect(result, "busy, UAT fixed", [
                ("both installs read fixed",
                 status_of(seen, SITE) == "fixed" and status_of(seen, UAT) == "fixed"),
                ("the installs found decide: fixed", seen["exposure"]["status"] == "fixed"),
                ("no install is said to be missing", seen["exposure"].get("partial") is None),
                ("the deeper-install note is said",
                 any("every folder down to 3 levels" in g for g in seen["gaps"])),
            ], seen)  # fmt: skip
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            await asyncio.to_thread(api.delete, node["id"])
            print(f"{scenario.name}: deleted {label}")
        except Exception as exc:  # the end-of-run sweep tries again
            print(f"{scenario.name}: could not delete {label}: {exc}")
    return result


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--scenario", nargs="+", default=list(SCENARIOS), choices=list(SCENARIOS))
    parser.add_argument("--region", default="us-sea")
    args = parser.parse_args()
    pack = read(args.pack.read_bytes())
    if pack.id != PACK_ID or not pack.exposure.applications:
        print(f"not the REDCap pack: {pack.id}", file=sys.stderr)
        return 2
    # The patterns the controller sends for the packs in force: here, the pack under test.
    collecting._web_first = lambda home, config: patterns([pack])
    proof._cancel_on_sigterm()
    api = proof.Linode(proof.linode_token())
    await asyncio.to_thread(proof.sweep, api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-redcap-") as work:
            results = await asyncio.gather(
                *(prove(api, SCENARIOS[n], pack, args.region, Path(work))
                  for n in args.scenario)
            )  # fmt: skip
    finally:
        await asyncio.to_thread(proof.sweep_run, api)
    left = [n["label"] for n in await asyncio.to_thread(api.tagged)
            if n["label"].startswith(f"{proof.LABEL_PREFIX}{proof.RUN}-")]  # fmt: skip
    if left:
        print(f"SERVERS LEFT RUNNING, delete them by hand: {', '.join(left)}")
    ok = True
    print()
    for r in results:
        good = not r.failed and not r.error and r.passed
        ok = ok and good
        print(f"=== {r.scenario}: {'PASS' if good else 'FAIL'}")
        if r.error:
            print(f"  error: {r.error}")
        for line in r.timings:
            print(f"  time    {line}")
        for line in r.passed:
            print(f"  ok      {line}")
        for line in r.failed:
            print(f"  FAILED  {line}")
    return 0 if ok and not left else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(asyncio.run(main()))
