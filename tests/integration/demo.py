"""The demo fleet that can be shown and kept running (plans/demo-fleet-plan-2026-11-10.md).

Unlike demo_fleet.py, the checker itself runs on a throwaway server too, installed by the install
page's own line, and every step on a fleet server is taken through that server. So no address in
anything the checker stores is the laptop's: what it holds can be shown as it is.

    LINODE_TOKEN=… python tests/integration/demo.py up       # the checker's server and the fleet
    LINODE_TOKEN=… python tests/integration/demo.py status   # what is up, its cost, when it ends
    LINODE_TOKEN=… python tests/integration/demo.py down     # delete every server

This is step D.2: the fleet and behaviours of demo_fleet.py, two checks each, run from the
checker's own server. The story (D.3), keeping it up for days (D.4) and saving its data (D.5) come
after. Its servers carry their own tag, so the proofs' sweep of servers older than two hours leaves
them alone; `up` deletes any demo server past the end date in its tags.

Costs Linode time (six Nanodes, about 5 cents an hour): run only with John's approval. What `up`
makes stays up until `down`.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import detection_proof as detection  # noqa: E402
import install_proof as install  # noqa: E402
import php2shell_proof as php  # noqa: E402
import readonly_proof as proof  # noqa: E402

TAG = "compromise-checker-demo"
LABEL_PREFIX = "cc-demo-"
UNTIL = "cc-demo-until-"  # a tag: the last day a server may be up, as YYYYMMDD
STATE = Path.home() / ".local" / "share" / "compromise-checker-demo"
# The published release, and its installer's SHA-256 as the install page gives it
# (https://nouriloop.com/work/compromise-checker/install/). Both change with a release.
RELEASE = "0.1.2"
INSTALLER_SHA256 = "8bc8989552356ef0aff29e0bcc291e5e53b53b7fbe919ff422857bccef022a5e"
NANODE_AN_HOUR = 0.0075
CHECKER = f"{install.PROGRAM}/current/bin/checker"
MACHINE_KEY = f"{install.DATA}/keys/scanner_ed25519"  # where first setup makes it
UNREACHABLE = ("old-box", "192.0.2.10")  # a documentation address: nothing answers there
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")

# demo_fleet.py's names for the proofs' scaffolding, and its smaller behaviour.
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


class DemoError(Exception):
    pass


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
CONTROLLER = Member("checker", "", "ubuntu24.04", "checker")


# --- what is up, kept between commands ---------------------------------------------------


@dataclass
class Server:
    name: str
    role: str
    distro: str
    group: str
    id: int
    label: str
    address: str


@dataclass
class State:
    run: str
    created: str  # UTC, ISO
    until: str  # YYYY-MM-DD: the last day it may be up
    servers: list[Server]
    web_name: str = ""

    def checker(self) -> Server:
        return next(s for s in self.servers if s.role == "checker")

    def fleet(self) -> list[Server]:
        return [s for s in self.servers if s.role != "checker"]


def save_state(folder: Path, state: State) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    target = folder / "state.json"
    part = folder / "state.json.part"
    part.write_text(json.dumps(asdict(state), indent=2) + "\n", encoding="utf-8")
    part.chmod(0o600)
    part.replace(target)


def load_state(folder: Path) -> State | None:
    try:
        data = json.loads((folder / "state.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    data["servers"] = [Server(**s) for s in data["servers"]]
    return State(**data)


# --- labels, tags and the end date ---------------------------------------------------------


def until_tag(day: date) -> str:
    return f"{UNTIL}{day:%Y%m%d}"


def until_of(tags: list[str]) -> date | None:
    """The end date a demo server's tags give, or None if they give none that reads as one."""
    for tag in tags:
        if tag.startswith(UNTIL):
            try:
                return datetime.strptime(tag[len(UNTIL) :], "%Y%m%d").date()  # noqa: DTZ007
            except ValueError:
                return None
    return None


def demo_nodes(nodes: list[dict]) -> list[dict]:
    return [n for n in nodes if TAG in n["tags"] and n["label"].startswith(LABEL_PREFIX)]


def past_their_date(nodes: list[dict], today: date) -> list[dict]:
    """Demo servers to delete: past their end date, or with no date that can be read (so one
    whose tags were damaged doesn't stay up for good)."""
    out = []
    for node in demo_nodes(nodes):
        until = until_of(node["tags"])
        if until is None or until < today:
            out.append(node)
    return out


def cost(servers: int, hours: float) -> float:
    return servers * hours * NANODE_AN_HOUR


# --- commands, as text ---------------------------------------------------------------------


def web_name(address: str) -> str:
    return f"{address.replace('.', '-')}.sslip.io"


def install_line(version: str, sha256: str, name: str) -> str:
    """The install page's line, with the flags that stop the installer asking questions. The
    certificate is Let's Encrypt's test one (D.2): a browser warns about it."""
    return (
        f"(d=$(mktemp -d) && trap 'rm -rf \"$d\"' EXIT && curl -fsSL"
        f' {install.RELEASES}/v{version}/install.py -o "$d/install.py"'
        f' && echo "{sha256}  $d/install.py" | sha256sum -c -'
        f' && umask 077 && sudo python3 -I "$d/install.py"'
        f" --web-address {shlex.quote(name)} --test-certificates)"
    )


def as_checker(*words: str) -> str:
    """A checker command on its own server, run as the tool's account (docs/install.md)."""
    said = " ".join(shlex.quote(w) for w in words)
    return (
        f"runuser -u {install.ACCOUNT} -- env CHECKER_HOME={install.DATA}"
        f" HOME={install.HOME} {CHECKER} {said}"
    )


def hosts_add(member: Member | Server, address: str) -> str:
    words = ["hosts", "add", member.name, "--address", address, "--user", "scanner"]
    words += ["--auth", "key", "--key", MACHINE_KEY, "--sudo", "nopasswd"]
    if member.group:
        words += ["--group", member.group]
    return as_checker(*words)


def offered(output: str) -> str | None:
    """The fingerprint `checker trust` says a server offers: the first in what it prints."""
    found = _FINGERPRINT.search(output)
    return found.group(0) if found else None


def demo_names(script: str) -> str:
    for old, new in DEMO_NAMES:
        script = script.replace(old, new)
    return script


def behaviour(role: str, root_key: str, admin_key: str) -> str | None:
    """What happens on a server between its two checks, as a script for root, or None."""
    if role == "attacked":
        script = demo_names(detection.ATTACKS)
    elif role == "small":
        script = SMALL_ATTACK
    else:
        return None
    return script.replace("{root_key}", root_key).replace("{admin_key}", admin_key)


# --- reaching the servers --------------------------------------------------------------------


class Through(install.Node):
    """A fleet server, reached through the checker's server and never from here, so its login
    records name the checker's server alone."""

    def __init__(self, address: str, key: Path, known: Path, via: install.Node, user="root"):
        super().__init__(address, key, known, user)
        self.via = via
        hop = ["ssh", *via.options, "-W", "%h:%p", f"{via.user}@{via.address}"]
        self.options += ["-o", "ProxyCommand=" + " ".join(shlex.quote(w) for w in hop)]


def must(node: install.Node, command: str, what: str, timeout: int = 900) -> str:
    done = node.run(command, timeout=timeout)
    if done.returncode != 0:
        raise DemoError(f"{what} failed on {node.address}:\n{(done.stdout + done.stderr)[-2000:]}")
    return done.stdout


def keypair(folder: Path, name: str) -> tuple[Path, str]:
    path = folder / name
    if not path.exists():
        subprocess.run(  # noqa: S603
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(path)],  # noqa: S607
            check=True,
        )
    public = path.with_suffix(".pub").read_text(encoding="utf-8").split()
    return path, " ".join(public[:2])


# --- up --------------------------------------------------------------------------------------


def make_servers(api, folder: Path, state: State, public_key: str, region: str) -> None:
    """The checker's server and the fleet's, each written to the state as soon as it exists, so
    `down` deletes whatever a failed `up` left."""
    tags = [TAG, until_tag(date.fromisoformat(state.until))]

    def make(member: Member) -> Server:
        label = f"{LABEL_PREFIX}{state.run}-{member.name}"
        try:
            made = api.create(label, proof.IMAGES[member.distro], region, public_key, tags=tags)
        except Exception:  # an answer lost on the way may still have made it
            time.sleep(15)
            made = api.find_demo(label) or api.create(
                label, proof.IMAGES[member.distro], region, public_key, tags=tags
            )
        return Server(
            member.name, member.role, member.distro, member.group, made["id"], label,
            made["ipv4"][0],
        )  # fmt: skip

    with ThreadPoolExecutor(max_workers=8) as pool:
        for server in pool.map(make, (CONTROLLER, *FLEET)):
            state.servers.append(server)
            save_state(folder, state)
            print(f"{server.name}: created (id {server.id})")


def install_checker(node: install.Node, state: State, folder: Path) -> str:
    """The published release, by the install page's line. Returns the one-time setup link."""
    state.web_name = web_name(node.address)
    save_state(folder, state)
    started = time.monotonic()
    said = must(
        node,
        install_line(RELEASE, INSTALLER_SHA256, state.web_name),
        "the install",
        timeout=1800,
    )
    print(f"checker: version {RELEASE} installed in {round(time.monotonic() - started)}s")
    links = re.findall(rf"https://{re.escape(state.web_name)}/s/\S+", said)
    if len(links) != 1:
        raise DemoError(f"the installer handed over no setup link:\n{said[-1500:]}")
    key_folder = shlex.quote(str(Path(MACHINE_KEY).parent))
    must(
        node,
        f"runuser -u {install.ACCOUNT} -- sh -c 'umask 077 && mkdir -p {key_folder}"
        f' && ssh-keygen -q -t ed25519 -N "" -C compromise-checker -f {MACHINE_KEY}\'',
        "making the checker's key for its servers",
    )
    print(must(node, as_checker("packs", "pull"), "getting the threat updates").strip())
    return links[0]


def prepare_member(checker: install.Node, node: Through, server: Server, scanner_key: str) -> None:
    """A fleet server as the proofs set one up, with the scanner account open to the checker's
    server only; then added to the checker and its identity confirmed against its own word."""
    node.wait(600)
    setup = proof.SETUP.replace("{controller}", checker.address).replace(
        "{scanner_key}", scanner_key
    )
    done = node.run(proof.strict(setup))
    if done.returncode != 0:
        raise DemoError(
            f"setting the server up failed on {node.address}:\n"
            f"{(done.stdout + done.stderr)[-2000:]}"
        )
    for line in done.stderr.splitlines():
        if line.startswith("proof setup:"):  # a part it goes on without, e.g. no container
            print(f"{server.name}: {line}")
    must(node, proof.strict(detection.WEB_SETUP), "its web server", timeout=300)
    if server.role == "vulnerable":
        must(node, proof.strict(php.SCENARIOS["ubuntu-own"].install), "the older PHP")
    must(checker, hosts_add(server, server.address), f"adding {server.name}")
    its_own = set(
        _FINGERPRINT.findall(
            must(node, "for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done", "keys")
        )
    )
    # "n": only what it offers is wanted here; it is trusted below, by fingerprint.
    asked = checker.run("echo n | " + as_checker("trust", server.name))
    fingerprint = offered(asked.stdout)
    if fingerprint is None or fingerprint not in its_own:
        raise DemoError(f"{server.name} offered {fingerprint}, which isn't one of its own keys")
    must(checker, as_checker("trust", server.name, "--expect", fingerprint), "confirming it")
    whitelist = f"{install.DATA}/whitelist/hosts/{server.name}.yaml"
    node_text = shlex.quote(proof.PROOF_WHITELIST.read_text(encoding="utf-8"))
    must(
        checker,
        f"runuser -u {install.ACCOUNT} -- sh -c 'umask 077 && mkdir -p"
        f" {install.DATA}/whitelist/hosts && cat > {whitelist}' <<< {node_text}",
        f"{server.name}'s whitelist",
    )
    print(f"{server.name}: set up, added and confirmed")


def check_all(checker: install.Node, which: str) -> None:
    """One pass over every server, as the daily check does it. A server that can't be reached
    makes the command end non-zero: that is `old-box`'s part, so only its output is shown."""
    done = checker.run(as_checker("run", "--all", "--unattended"), timeout=3600)
    print(f"{which} check: ended {done.returncode}")
    for line in (done.stdout + done.stderr).strip().splitlines()[-12:]:
        print(f"    {line}")


def behave(node: Through, server: Server, folder: Path) -> None:
    _, root_key = keypair(folder, "planted-root")
    admin_file, admin_key = keypair(folder, "planted-admin")
    script = behaviour(server.role, root_key, admin_key)
    if script is None:
        return
    # On standard input, not as `bash -c <script>`: the script's own shell would carry every
    # pattern its pgrep checks look for, and they would find it instead of what they staged.
    done = node.run("bash -s", timeout=900, input=script)
    for line in done.stderr.splitlines():
        if line.startswith("ATTACK FAILED"):
            print(f"{server.name}: {line}")
    used = Through(server.address, admin_file, node.known, node.via, user="deploy2")
    try:
        used.run("true", timeout=60)  # the new account is used, as an intruder would
    finally:
        used.close()
    print(f"{server.name}: behaviours done")


def never_seen_from_here(checker: install.Node, nodes: dict[str, Through]) -> list[str]:
    """D.2's proof: the names of the fleet servers whose logs hold this machine's address (none,
    if every step went through the checker's server), and of the checker's files that do."""
    here = checker.out("echo $SSH_CLIENT").split()[0]
    pattern = shlex.quote(here)
    found = []
    for name, node in nodes.items():
        seen = node.out(
            f"(journalctl --no-pager 2>/dev/null; cat /var/log/auth.log /var/log/secure"
            f" /var/log/audit/audit.log 2>/dev/null) | grep -cF -- {pattern}"
        )
        if seen.strip() not in ("0", ""):
            found.append(f"{name}: its logs name this machine {seen.strip()} times")
    kept = checker.out(f"grep -rlF -- {pattern} {install.DATA} 2>/dev/null | head -5")
    found += [f"the checker's own files: {line}" for line in kept.splitlines()]
    return found


def up(api, folder: Path, region: str, today: date) -> int:
    if load_state(folder) is not None:
        raise DemoError(f"a demo is up already ({folder}/state.json): `down` first")
    for node in past_their_date(api.demo_tagged(), today):
        print(f"sweep: deleting {node['label']}, past its end date")
        api.delete(node["id"])
    folder.mkdir(parents=True, exist_ok=True)
    key, public = keypair(folder, "key")
    run = proof.RUN
    state = State(run, datetime.now(UTC).isoformat(), (today + timedelta(days=1)).isoformat(), [])
    save_state(folder, state)
    known = folder / "known_hosts"
    nodes: dict[str, Through] = {}
    checker = None
    try:
        make_servers(api, folder, state, public, region)
        checker = install.Node(state.checker().address, key, known)
        checker.wait(600)
        link = install_checker(checker, state, folder)
        scanner_key = must(checker, f"cat {MACHINE_KEY}.pub", "reading the checker's key").strip()
        for server in state.fleet():
            nodes[server.name] = Through(server.address, key, known, checker)
        with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
            list(
                pool.map(
                    lambda s: prepare_member(checker, nodes[s.name], s, scanner_key), state.fleet()
                )
            )
        name, address = UNREACHABLE
        must(checker, hosts_add(Member(name, "", "", "clean"), address), f"adding {name}")
        check_all(checker, "first")
        for server in state.fleet():
            behave(nodes[server.name], server, folder)
        check_all(checker, "second")
        print(must(checker, as_checker("fleet"), "the fleet's results"))
        leaks = never_seen_from_here(checker, nodes)
        for leak in leaks:
            print(f"FAIL {leak}")
        if not leaks:
            print("PASS nothing on the fleet, or in what the checker keeps, names this machine")
        print(f"\nThe checker: https://{state.web_name}/ (a test certificate: the browser warns)")
        print(f"Make the first account, within the hour: {link}")
        print(f"Up until `demo.py down`; its tags end on {state.until}.")
        return 1 if leaks else 0
    except BaseException:
        print("up failed: deleting what it made", file=sys.stderr)
        down(api, folder)
        raise
    finally:
        for node in [*nodes.values(), checker]:
            if node is not None:
                node.close()


# --- status and down ---------------------------------------------------------------------


def status(api, folder: Path, now: datetime) -> int:
    state = load_state(folder)
    if state is None:
        print("No demo is up.")
        stray = demo_nodes(api.demo_tagged())
        for node in stray:
            print(f"But {node['label']} exists (id {node['id']}): `down` deletes it.")
        return 1 if stray else 0
    alive = {n["id"]: n for n in api.demo_tagged()}
    hours = (now - datetime.fromisoformat(state.created)).total_seconds() / 3600
    print(f"Up for {hours:.1f} hours, about ${cost(len(state.servers), hours):.2f} so far.")
    print(f"Ends {state.until}. The checker: https://{state.web_name}/")
    for server in state.servers:
        node = alive.get(server.id)
        print(f"  {server.name:<12} {server.address:<16} {node['status'] if node else 'GONE'}")
    return 0


def down(api, folder: Path) -> int:
    """Delete every server the state names, and any other carrying this run's label; then the
    state and its keys. A delete that fails is said, and the state kept so it can be tried again."""
    state = load_state(folder)
    wanted = {s.id: s.label for s in state.servers} if state else {}
    for node in demo_nodes(api.demo_tagged()):
        if state is None or node["label"].startswith(f"{LABEL_PREFIX}{state.run}-"):
            wanted.setdefault(node["id"], node["label"])
    failed = 0
    for linode_id, label in wanted.items():
        try:
            api.delete(linode_id)
            print(f"deleted {label}")
        except Exception as exc:  # noqa: BLE001 - one failure mustn't stop the others
            if " 404 " in str(exc):
                print(f"{label} was gone already")
            else:
                failed += 1
                print(f"could not delete {label}: {exc}", file=sys.stderr)
    if failed:
        print("The state is kept: run `down` again.", file=sys.stderr)
        return 1
    if folder.exists():
        shutil.rmtree(folder)
    return 0


class Api(proof.Linode):
    """Linode's API, for servers with the demo's tag."""

    def demo_tagged(self) -> list[dict]:
        return demo_nodes(self.call("GET", "/linode/instances?page_size=500")["data"])

    def find_demo(self, label: str) -> dict | None:
        return next((n for n in self.demo_tagged() if n["label"] == label), None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["up", "status", "down"])
    parser.add_argument("--state", type=Path, default=STATE, help="where what is up is kept")
    parser.add_argument("--region", default="us-sea")
    args = parser.parse_args(argv)
    api = Api(proof.linode_token())
    try:
        if args.command == "up":
            return up(api, args.state, args.region, datetime.now(UTC).date())
        if args.command == "status":
            return status(api, args.state, datetime.now(UTC))
        return down(api, args.state)
    except DemoError as exc:
        print(f"demo: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(main())
