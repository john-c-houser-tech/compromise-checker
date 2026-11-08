"""Any pack's package entries on real servers (decision D5): on one throwaway
Linode per release the pack names, the newest build the vendor's archive
still offers that the pack calls vulnerable is installed and must read
vulnerable; then the oldest build it calls fixed is installed and must read
fixed. Every other build the archive offers for the pack's packages is
judged too: one the pack doesn't cover (it would read not affected) is a
failure, and one it can't judge is listed for a look (an old stream the
vendor's data left out, say).

No exploit is run and nothing else is planted: this proves the versions and
patterns, not the detections (a pack's own proof does those, like
php2shell_proof.py). The pack is read as a file, unsigned, so it is proved
before it is signed. The servers are deleted afterwards.

    python tests/integration/pack_proof.py --pack PATH/PACK.yaml          # the plan, no servers
    python tests/integration/pack_proof.py --pack PATH/PACK.yaml --go     # the run

Exit status: 0 everything proved, 1 a failure, 2 nothing failed but something
needs a look: a part that couldn't be proved (no image for a release, no
vulnerable build left in the archive, a fix not published yet) or an offered
build the pack can't judge. Each run needs its own OK (D5: about a
cent a server, under the plan's $10 cap).
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import shlex
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import asyncssh
import detection_proof as detection
import readonly_proof as proof

from checker.analysis import snapshot_of
from checker.assess import analyze
from checker.evidence import Store, database_file, initialise, load_config, load_identity
from checker.inventory import Host
from checker.packs.exposure import FIXED, VULNERABLE, _state, judge
from checker.packs.format import read
from checker.packs.versions import VersionError, compare

# The image each release is proved on: Rocky Linux for RHEL, unless --alma.
IMAGES = {
    "ubuntu:22.04": "ubuntu22.04",
    "ubuntu:24.04": "ubuntu24.04",
    "ubuntu:26.04": "ubuntu26.04",
    "rhel:9": "rocky9",
    "rhel:10": "rocky10",
}
ALMA = {"rhel:9": "alma9", "rhel:10": "alma10"}
CENTS_PER_SERVER = 1  # a Nanode's hour, rounded up
QUIET_APT = r"""
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_SUSPEND=1
APT='apt-get -y -q -o DPkg::Lock::Timeout=300'
systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer || true
"""
QUIET_DNF = r"""
DNF='dnf -y -q --setopt=install_weak_deps=False'
systemctl disable --now dnf-makecache.timer dnf-automatic.timer || true
"""


def manager_of(release: str) -> str:
    return "dpkg" if release.startswith("ubuntu:") else "rpm"


@dataclass(frozen=True)
class Group:
    """Packages a release's entries name together: proved together, since
    they are one source's binaries and install at one version."""

    release: str
    names: tuple[str, ...]
    has_fix: bool


def groups(pack, release: str) -> list[Group]:
    """The release's package groups, in the pack's order."""
    found: dict[tuple[str, ...], bool] = {}
    for entry in pack.exposure.packages:
        if entry.release != release:
            continue
        key = tuple(entry.binary_names)
        found[key] = found.get(key, False) or entry.fixed is not None
    return [Group(release, names, fix) for names, fix in found.items()]


def releases(pack) -> list[str]:
    return list(dict.fromkeys(e.release for e in pack.exposure.packages))


def plan(pack, alma: bool = False) -> tuple[dict[str, str], list[str]]:
    """(release → image) for the releases that have one, and those that don't."""
    images = IMAGES | (ALMA if alma else {})
    have = {r: images[r] for r in releases(pack) if r in images}
    return have, [r for r in releases(pack) if r not in images]


def parse_madison(text: str) -> dict[str, list[str]]:
    """`apt-cache madison` lines (" name | version | source"), binaries only."""
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3 or not parts[0] or not parts[1] or parts[2].endswith("Sources"):
            continue
        versions = found.setdefault(parts[0], [])
        if parts[1] not in versions:
            versions.append(parts[1])
    return found


def parse_repoquery(text: str) -> dict[str, list[str]]:
    """`dnf repoquery --qf '%{name} %{epoch}:%{version}-%{release}'` lines,
    the epoch dropped when it is 0 (as the collector writes versions)."""
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2 or ":" not in parts[1]:
            continue
        name, evr = parts
        if evr.startswith("0:") or evr.startswith("(none):"):
            evr = evr.partition(":")[2]
        versions = found.setdefault(name, [])
        if evr not in versions:
            versions.append(evr)
    return found


@dataclass
class Choice:
    vulnerable: str | None = None  # the newest build the pack calls vulnerable
    fixed: str | None = None  # the oldest build it calls fixed
    uncovered: list[str] = field(default_factory=list)  # offered builds that read not affected
    unjudged: list[str] = field(default_factory=list)  # offered builds that read can't judge


def _sorted(manager: str, versions: list[str]) -> list[str]:
    """Oldest first, by the checker's own ordering; one it can't read is
    left out (and is a gap: `choose` judges it as can't judge)."""

    readable = []
    for v in versions:
        try:
            compare(manager, v, v)
        except VersionError:
            continue
        readable.append(v)
    return sorted(readable, key=functools.cmp_to_key(lambda a, b: compare(manager, a, b)))


def choose(pack, group: Group, offered: dict[str, list[str]]) -> Choice:
    """Which builds to install, from what the archive offers. The group's
    first name the archive has decides the version; every name it offers is
    judged, and one no entry covers, or that reads can't judge, is listed."""
    manager = manager_of(group.release)
    entries = [e for e in pack.exposure.packages if e.release == group.release]
    other = pack.exposure.other_builds
    choice = Choice()
    for name in group.names:
        for version in offered.get(name, []):
            state = _state(name, version, entries, manager, other)
            if state == "absent":
                choice.uncovered.append(f"{name} {version} is offered but no entry covers it")
            elif state not in (VULNERABLE, FIXED):
                choice.unjudged.append(f"{name} {version} is offered and reads {state}")
    lead = next((n for n in group.names if offered.get(n)), None)
    if lead is None:
        return choice
    states = {v: _state(lead, v, entries, manager, other) for v in offered[lead]}
    ordered = _sorted(manager, offered[lead])
    vulnerable = [v for v in ordered if states[v] == VULNERABLE]
    fixed = [v for v in ordered if states[v] == FIXED]
    choice.vulnerable = vulnerable[-1] if vulnerable else None
    choice.fixed = fixed[0] if fixed else None
    return choice


def install(release: str, names: list[str], version: str) -> str:
    """The shell that installs these packages at this version (a downgrade
    when something newer is in)."""
    if manager_of(release) == "dpkg":
        wanted = " ".join(shlex.quote(f"{n}={version}") for n in names)
        return QUIET_APT + f"$APT install --allow-downgrades {wanted}\n"
    wanted = " ".join(shlex.quote(f"{n}-{version}") for n in names)
    return QUIET_DNF + f"$DNF install --allowerasing {wanted}\n"


def listing(release: str, names: tuple[str, ...]) -> str:
    quoted = " ".join(shlex.quote(n) for n in names)
    if manager_of(release) == "dpkg":
        return (
            QUIET_APT
            + f'$APT update -q >/dev/null\nfor n in {quoted}; do apt-cache madison "$n"; done\n'
        )
    qf = "%{name} %{epoch}:%{version}-%{release}\\n"
    return (
        QUIET_DNF
        + "dnf -q makecache >/dev/null\n"
        + f"dnf -q repoquery --showduplicates --arch x86_64,noarch --qf '{qf}' {quoted}\n"
    )


def offered_from(release: str, text: str) -> dict[str, list[str]]:
    return parse_madison(text) if manager_of(release) == "dpkg" else parse_repoquery(text)


@dataclass
class Result:
    scenario: str  # the release
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    unproved: list[str] = field(default_factory=list)  # and offered builds it can't judge
    error: str | None = None


def facts(assessment: dict, snapshot, pack, names: tuple[str, ...]) -> dict:
    """The pack's exposure as the assessment has it, and each of the group's
    installed packages as the pack judges it on its own."""
    exposure = next(e for e in assessment["exposures"] if e["pack"] == pack.id)
    packages = snapshot.sections["packages"].items
    found = judge(pack, snapshot.sections["host"].items, packages, [], datetime.now(UTC))
    judged = {p.name: (p.version, p.status) for p in found.packages if p.name in names}
    return {"exposure": exposure, "judged": judged}


def expect_stage(result: Result, stage: str, seen: dict, version: str, wanted: str) -> None:
    """Every package installed at the version, each judged `wanted`, and
    the host's exposure `wanted` too."""
    judged = seen["judged"]
    print(f"{result.scenario}: {stage}: status {seen['exposure']['status']}, packages {judged}")
    claims = [
        (f"installed at {version}", bool(judged) and all(v == version for v, _ in judged.values()))
    ]
    claims += [(f"{n} reads {wanted}", s == wanted) for n, (_, s) in sorted(judged.items())]
    claims.append((f"the host reads {wanted}", seen["exposure"]["status"] == wanted))
    for claim, held in claims:
        (result.passed if held else result.failed).append(f"{stage}: {claim}")


async def prove(api, release: str, image: str, pack, region: str, work: Path) -> Result:
    result = Result(release)
    tag = release.replace(":", "")
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    scanner_key = asyncssh.generate_private_key("ssh-ed25519")
    key_file = work / f"{tag}-scanner"
    scanner_key.write_private_key(key_file)
    label = proof.run_label(image)
    try:
        node = await proof._create_server(
            api, label, proof.IMAGES[image], region,
            root_key.export_public_key().decode().strip(),
        )  # fmt: skip
    except Exception as exc:
        result.error = f"could not create the server: {type(exc).__name__}: {exc}"
        return result
    print(f"{release}: created {label} (id {node['id']}, {image})")
    try:
        deadline = time.monotonic() + 600
        while node["status"] != "running":
            if time.monotonic() > deadline:
                raise TimeoutError("server did not start within 10 minutes")
            await asyncio.sleep(5)
            node = await asyncio.to_thread(api.get, node["id"])
        address = node["ipv4"][0]
        known = work / f"{tag}-known_hosts"
        root = Host(name=f"{tag}-root", address=address, user="root", sudo="root")
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
            home = work / f"{tag}-home"
            config, _ = initialise(home)
            scanner = Host(
                name=tag, address=address, user="scanner", auth="key",
                key_path=str(key_file), sudo="nopasswd",
            )  # fmt: skip

            async def shell(script: str) -> str:
                done = await conn.run(f"bash -eu -c {shlex.quote(script)}", timeout=1800)
                if done.exit_status != 0:
                    raise RuntimeError(f"on the server: {done.stderr[-600:]}")
                return done.stdout

            async def look(names: tuple[str, ...]) -> dict:
                await detection.collect(home, config, scanner, known)
                store = Store(database_file(home))
                try:
                    identity = load_identity(Path(config.identity_file))
                    recipients = load_config(home).recipients
                    assessment = analyze(
                        store, tag, identity, recipients, packs=[pack],
                        whitelist=proof.proof_whitelist(home, tag),
                    )  # fmt: skip
                    row = store.bundle(assessment["bundle_id"])
                    snapshot = snapshot_of(store, row, identity, recipients)
                    return facts(assessment, snapshot, pack, names)
                finally:
                    store.close()

            for group in groups(pack, release):
                what = "/".join(group.names)
                offered = offered_from(release, await shell(listing(release, group.names)))
                for name in group.names:
                    print(
                        f"{release}: offered {name}: {', '.join(offered.get(name, [])) or 'none'}"
                    )
                choice = choose(pack, group, offered)
                result.failed += [f"{what}: {line}" for line in choice.uncovered]
                result.unproved += [f"{what}: {line}" for line in choice.unjudged]
                if not any(offered.get(n) for n in group.names):
                    result.unproved.append(f"{what}: the archive offers none of them")
                    continue
                if choice.vulnerable is None:
                    result.unproved.append(f"{what}: no build the pack calls vulnerable is offered")
                else:
                    names = [n for n in group.names if choice.vulnerable in offered.get(n, [])]
                    await shell(install(release, names, choice.vulnerable))
                    expect_stage(result, f"{what} {choice.vulnerable}", await look(tuple(names)),
                                 choice.vulnerable, VULNERABLE)  # fmt: skip
                if choice.fixed is None:
                    why = (
                        "a fix the archive doesn't offer yet"
                        if group.has_fix
                        else "no fix in the pack"
                    )
                    result.unproved.append(f"{what}: fixed not proved ({why})")
                else:
                    names = [n for n in group.names if choice.fixed in offered.get(n, [])]
                    await shell(install(release, names, choice.fixed))
                    expect_stage(result, f"{what} {choice.fixed}", await look(tuple(names)),
                                 choice.fixed, FIXED)  # fmt: skip
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            await asyncio.to_thread(api.delete, node["id"])
            print(f"{release}: deleted {label}")
        except Exception as exc:  # the end-of-run sweep tries again
            print(f"{release}: could not delete {label}: {exc}")
    return result


def verdict(r: Result) -> str:
    if r.error or r.failed:
        return "FAIL"
    return "NEEDS A LOOK" if r.unproved or not r.passed else "PASS"


def report(results: list[Result]) -> int:
    print()
    for r in results:
        print(f"=== {r.scenario}: {verdict(r)}")
        if r.error:
            print(f"  error: {r.error}")
        for line in r.passed:
            print(f"  ok        {line}")
        for line in r.failed:
            print(f"  FAILED    {line}")
        for line in r.unproved:
            print(f"  look      {line}")
    verdicts = {verdict(r) for r in results}
    return 1 if "FAIL" in verdicts else 2 if verdicts - {"PASS"} else 0


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument(
        "--release", nargs="+", help="only these releases (as the pack writes them)"
    )
    parser.add_argument("--alma", action="store_true", help="prove RHEL on AlmaLinux, not Rocky")
    parser.add_argument("--region", default="us-sea")
    parser.add_argument(
        "--go", action="store_true", help="create the servers (each run needs an OK)"
    )
    args = parser.parse_args()
    pack = read(args.pack.read_bytes())
    have, missing = plan(pack, args.alma)
    if args.release:
        unknown = set(args.release) - set(have) - set(missing)
        if unknown:
            parser.error(f"not releases the pack names: {', '.join(sorted(unknown))}")
        have = {r: i for r, i in have.items() if r in args.release}
        missing = [r for r in missing if r in args.release]
    print(f"{pack.id} version {pack.version}:")
    for release, image in have.items():
        names = "; ".join("/".join(g.names) for g in groups(pack, release))
        print(f"  {release} on {image}: {names}")
    for release in missing:
        print(f"  {release}: no image, can't be proved here")
    print(f"{len(have)} servers, about {len(have) * CENTS_PER_SERVER}¢")
    if not args.go:
        print("Nothing created: add --go to run it.")
        return 0
    if not have:
        return 2
    proof._cancel_on_sigterm()
    api = proof.Linode(proof.linode_token())
    await asyncio.to_thread(proof.sweep, api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-pack-proof-") as work:
            results = await asyncio.gather(
                *(prove(api, r, i, pack, args.region, Path(work)) for r, i in have.items())
            )
    finally:
        await asyncio.to_thread(proof.sweep_run, api)
    left = [n["label"] for n in await asyncio.to_thread(api.tagged)
            if n["label"].startswith(f"{proof.LABEL_PREFIX}{proof.RUN}-")]  # fmt: skip
    if left:
        print(f"SERVERS LEFT RUNNING, delete them by hand: {', '.join(left)}")
    results += [Result(r, unproved=["no image for this release"]) for r in missing]
    status = report(results)
    return 1 if left else status


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(asyncio.run(main()))
