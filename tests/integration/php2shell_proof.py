"""The PHP2Shell pack on real servers (plan 4.8, decision D7): each stage of a
throwaway Linode must be judged as the stage says. No exploit is run: the
vulnerable PHP is an older vendor build, pinned, and the log lines the
detections read are written in the shapes the advisories and the servers use.

The pack is read as a file, unsigned: this proves what it judges, before it
is signed. The servers are deleted afterwards.

    python tests/integration/php2shell_proof.py --pack PATH/PACK.yaml
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
from checker.packs.format import read

PPA = "https://launchpad.net/~ondrej/+archive/ubuntu/php/+files"
ARCHIVE = "https://launchpad.net/ubuntu/+archive/primary/+files"
QUIET_APT = r"""
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_SUSPEND=1  # Ubuntu's needrestart would restart the workers we mean to leave
APT='apt-get -y -q -o DPkg::Lock::Timeout=300'
systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer || true
"""


def debs(base: str, branch: str, version: str) -> str:
    names = ("fpm", "cli", "common", "opcache", "readline")
    files = " ".join(f"php{branch}-{n}_{version}_amd64.deb" for n in names)
    return (
        "mkdir -p /root/old && cd /root/old\n"
        f'for f in {files}; do curl -fsSL -o "$f" "{base}/$f"; done\n'
        "$APT install --allow-downgrades ./*.deb\n"
    )


@dataclass(frozen=True)
class Scenario:
    name: str
    distro: str
    install: str  # the vulnerable PHP, running
    fix: str  # the fixed PHP, its workers left running
    restart: str  # after the setting: every PHP on the host
    restart_fixed: str  # after the fix: only the one fixed
    ini: str  # where a setting of our own goes (one or more files)
    log: str  # the PHP-FPM log the crash lines go in
    memory_log: str  # where memory errors go
    memory_line: str  # one, with {when}


def ubuntu_fix(branch: str) -> str:
    pkgs = " ".join(f"php{branch}-{n}" for n in ("fpm", "cli", "common", "opcache", "readline"))
    return (
        "printf '#!/bin/sh\\nexit 101\\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d\n"
        f"$APT install {pkgs}\n"
        "rm -f /usr/sbin/policy-rc.d\n"
    )


FPM_MEMORY = (
    '[{when}] WARNING: [pool www] child 900 said into stderr: "NOTICE: PHP message: PHP Fatal'
    " error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes)"
    ' in /var/www/html/index.php on line 3"'
)
SCENARIOS = {
    "ubuntu-own": Scenario(
        "ubuntu-own",
        "ubuntu24.04",
        QUIET_APT
        + "$APT update -q\n$APT install curl\n"
        + debs(ARCHIVE, "8.3", "8.3.6-0ubuntu0.24.04.12")
        + "systemctl enable --now php8.3-fpm\n",
        QUIET_APT + ubuntu_fix("8.3"),
        "systemctl restart php8.3-fpm",
        "systemctl restart php8.3-fpm",
        "/etc/php/8.3/fpm/conf.d/99-proof.ini",
        "/var/log/php8.3-fpm.log",
        "/var/log/php8.3-fpm.log",
        FPM_MEMORY,
    ),
    "ubuntu-sury": Scenario(
        "ubuntu-sury",
        "ubuntu24.04",
        QUIET_APT + "$APT update -q\n$APT install software-properties-common curl\n"
        "add-apt-repository -y ppa:ondrej/php\n$APT update -q\n"
        + debs(PPA, "8.4", "8.4.26-1+ubuntu24.04.1+deb.sury.org+1")
        + "systemctl enable --now php8.4-fpm\n",
        QUIET_APT + ubuntu_fix("8.4"),
        # The scanner's setup left Ubuntu's PHP 8.3 running too, as on a host in
        # the middle of a move: its workers must not read as 8.4's old code.
        "systemctl restart php8.3-fpm php8.4-fpm",
        "systemctl restart php8.4-fpm",
        "/etc/php/8.3/fpm/conf.d/99-proof.ini /etc/php/8.4/fpm/conf.d/99-proof.ini",
        "/var/log/php8.4-fpm.log",
        "/var/log/php8.4-fpm.log",
        FPM_MEMORY,
    ),
    "rocky-own": Scenario(
        "rocky-own",
        "rocky9",
        "dnf -y -q install php-fpm-8.0.30-8.el9_8 php-cli-8.0.30-8.el9_8"
        " php-common-8.0.30-8.el9_8\n"
        "systemctl enable --now php-fpm\n",
        "dnf -y -q --setopt=tsflags=noscripts upgrade php-fpm php-cli php-common\n",
        "systemctl restart php-fpm",
        "systemctl restart php-fpm",
        "/etc/php.d/99-proof.ini",
        "/var/log/php-fpm/error.log",
        "/var/log/php-fpm/www-error.log",
        # PHP's own error log, which RHEL's pools default to.
        "[{when} UTC] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted"
        " (tried to allocate 20480 bytes) in /var/www/html/index.php on line 3",
    ),
}


def planted(s: Scenario) -> str:
    """Six crash lines and thirty memory errors, seconds apart, just now."""
    return f"""
stamp() {{ TZ=UTC date -d "-$1 seconds" '+%d-%b-%Y %H:%M:%S'; }}
for i in 1 2 3 4 5 6; do
  echo "[$(stamp $((i * 10)))] WARNING: [pool www] child $((900 + i)) exited on signal 11 (SIGSEGV) after 1.5 seconds from start" >> {s.log}
done
for i in $(seq 1 30); do
  line='{s.memory_line}'
  echo "${{line/\\{{when\\}}/$(stamp $i)}}" >> {s.memory_log}
done
"""  # noqa: E501


@dataclass
class Result:
    scenario: str
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    error: str | None = None


def facts(assessment: dict) -> dict:
    exposure = next(e for e in assessment["exposures"] if e["pack"] == "php2shell-2026-10")
    variants = {f.get("variant") for f in assessment["findings"] if f["check"] == "pack.exposure"}
    detections = {
        f["variant"].partition("/")[2]
        for f in assessment["findings"]
        if f["check"] == "pack.detection"
    }
    return {
        "exposure": exposure,
        "variants": variants,
        "detections": detections,
        "gaps": assessment["coverage"]["gaps"],
        "score": assessment["score"],
        "said": [f["summary"] for f in assessment["findings"] if f["check"] == "pack.exposure"],
    }


def expect(result: Result, stage: str, claims: list[tuple[str, bool]], seen: dict) -> None:
    summary = (
        f"status {seen['exposure']['status']}, share {seen['exposure']['share']},"
        f" findings {sorted(v for v in seen['variants'] if v)},"
        f" detections {sorted(seen['detections'])},"
        f" prior {seen['score'].get('raised_prior')}, {seen['score']['band']}"
    )
    print(f"{result.scenario}: {stage}: {summary}")
    for line in seen["said"]:
        print(f"{result.scenario}:   {line[:300]}")
    for claim, held in claims:
        (result.passed if held else result.failed).append(f"{stage}: {claim}")
    if not all(held for _, held in claims):
        result.failed.append(f"{stage}: saw {summary}")


async def prove(api, scenario: Scenario, pack, region: str, keep: bool, work: Path) -> Result:
    result = Result(scenario.name)
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
    key_file = work / f"{scenario.name}-scanner"
    scanner_key.write_private_key(key_file)
    label = proof.run_label(scenario.name)
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
            await conn.run(setup, check=True, timeout=600)
            home = work / f"{scenario.name}-home"
            config, _ = initialise(home)
            scanner = Host(
                name=scenario.name, address=address, user="scanner", auth="key",
                key_path=str(key_file), sudo="nopasswd",
            )  # fmt: skip

            async def shell(script: str) -> None:
                done = await conn.run("bash -seu", input=script, timeout=900)
                if done.exit_status != 0:
                    raise RuntimeError(f"on the server: {done.stderr[-600:]}")

            async def look() -> dict:
                state = await conn.run(
                    "dpkg-query -W -f='${Package} ${Version}\\n' 'php*' 2>/dev/null"
                    " || rpm -qa 'php*'; ps -eo pid,lstart,comm | grep -i php;"
                    " systemctl list-units --no-legend '*php*'; true",
                    timeout=60,
                )
                for line in state.stdout.splitlines():
                    print(f"{scenario.name}: host: {line[:150]}")
                await detection.collect(home, config, scanner, known)
                store = Store(database_file(home))
                try:
                    return facts(
                        analyze(
                            store, scenario.name, load_identity(Path(config.identity_file)),
                            load_config(home).recipients, packs=[pack],
                            whitelist=proof.proof_whitelist(home, scenario.name),
                        )
                    )  # fmt: skip
                finally:
                    store.close()

            await shell(scenario.install)
            seen = await look()
            raised = seen["score"].get("raised_prior") or 0
            expect(result, "vulnerable", [
                ("reads vulnerable", seen["exposure"]["status"] == "vulnerable"),
                ("the package is a finding", "vulnerable" in seen["variants"]),
                ("the prior is raised", raised > seen["score"]["prior"]),
                ("upload progress on is a finding", "mitigation_missing" in seen["variants"]),
                ("no detection fires", not seen["detections"]),
            ], seen)  # fmt: skip

            await shell(
                f"echo 'session.upload_progress.enabled = Off' | tee {scenario.ini} >/dev/null\n"
                + scenario.restart
                + "\n"
            )
            seen = await look()
            in_place = any("upload-progress-off is in place" in g for g in seen["gaps"])
            expect(result, "mitigation on", [
                ("still vulnerable", seen["exposure"]["status"] == "vulnerable"),
                ("no finding for the setting", "mitigation_missing" not in seen["variants"]),
                ("it is said to be in place", in_place),
            ], seen)  # fmt: skip

            await shell(planted(scenario))
            seen = await look()
            expect(result, "log lines", [
                ("worker crashes fire", "php-crash" in seen["detections"]),
                ("memory errors fire", "memory-limit-burst" in seen["detections"]),
            ], seen)  # fmt: skip

            await shell(scenario.fix)
            seen = await look()
            expect(result, "fixed, not restarted", [
                ("reads fixed", seen["exposure"]["status"] == "fixed"),
                ("no longer vulnerable", "vulnerable" not in seen["variants"]),
                ("the old workers are a finding", "stale_code" in seen["variants"]),
                ("still counted as exposed", seen["exposure"]["exposed_until"] is None),
            ], seen)  # fmt: skip

            await shell(scenario.restart_fixed + "\n")
            seen = await look()
            expect(result, "fixed, restarted", [
                ("reads fixed", seen["exposure"]["status"] == "fixed"),
                ("the old workers are gone", "stale_code" not in seen["variants"]),
                ("the exposure has an end", seen["exposure"]["exposed_until"] is not None),
                ("was exposed is said", "was_exposed" in seen["variants"]),
            ], seen)  # fmt: skip
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        if keep:
            print(f"{scenario.name}: --keep: leaving {label} running (id {node['id']})")
        else:
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
    parser.add_argument("--keep", action="store_true", help="don't delete the servers")
    args = parser.parse_args()
    pack = read(args.pack.read_bytes())
    proof._cancel_on_sigterm()
    api = proof.Linode(proof.linode_token())
    await asyncio.to_thread(proof.sweep, api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-php2shell-") as work:
            results = await asyncio.gather(
                *(prove(api, SCENARIOS[n], pack, args.region, args.keep, Path(work))
                  for n in args.scenario)
            )  # fmt: skip
    finally:
        if not args.keep:
            await asyncio.to_thread(proof.sweep_run, api)
    ok = True
    print()
    for r in results:
        good = not r.failed and not r.error and r.passed
        ok = ok and good
        print(f"=== {r.scenario}: {'PASS' if good else 'FAIL'}")
        if r.error:
            print(f"  error: {r.error}")
        for line in r.passed:
            print(f"  ok      {line}")
        for line in r.failed:
            print(f"  FAILED  {line}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(asyncio.run(main()))
