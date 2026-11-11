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
them alone. The end date in its tags is acted on only when no state is kept here: then `up`
deletes any demo server past it. While a state is kept, `status` says when it is overdue (D.4
brings the sweep that needs no one to look).

Costs Linode time (six Nanodes, about 5 cents an hour): run only with John's approval. What `up`
makes stays up until `down`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, fields
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


class Unreadable(DemoError):
    """A state file that is there but can't be read: empty, damaged, or another version's."""


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
    except (OSError, ValueError) as exc:
        raise Unreadable(f"{folder}/state.json can't be read ({exc})") from exc
    try:  # a field another version added is left out, not a reason to refuse
        servers = [Server(**{f.name: s[f.name] for f in fields(Server)}) for s in data["servers"]]
        known = {f.name for f in fields(State)} - {"servers"}
        return State(servers=servers, **{k: v for k, v in data.items() if k in known})
    except (KeyError, TypeError) as exc:
        raise Unreadable(f"{folder}/state.json isn't a demo's state ({exc!r})") from exc


# What the demo itself puts in its folder: `down` removes these and nothing else.
OWN_FILES = ("state.json", "state.json.part", "key", "key.pub", "known_hosts")


def claim(folder: Path) -> None:
    """Take the folder for one run of `up`, or refuse: only a new or empty folder, and only one
    `up` at a time (the state file is made here, empty, and whoever makes it has the folder)."""
    folder.mkdir(parents=True, exist_ok=True)
    if any(folder.iterdir()):
        raise DemoError(f"{folder} isn't empty: the demo keeps its state in a folder of its own")
    try:
        os.close(os.open(folder / "state.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError:
        raise DemoError(f"another `up` has just taken {folder}") from None


def forget(folder: Path) -> None:
    """Remove the demo's own files from its folder, then the folder if nothing else is in it."""
    if not folder.is_dir():
        return
    for path in folder.iterdir():
        # m-*: the ssh connections' sockets (install.Node), if one was left behind.
        if path.name in OWN_FILES or path.name.startswith("m-"):
            path.unlink(missing_ok=True)
    try:
        folder.rmdir()
    except OSError:
        print(f"{folder} holds files that aren't the demo's: left as it is", file=sys.stderr)


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

    def fresh_login(self, user: str, *more: str):
        raise NotImplementedError("it would connect from here, not through the checker's server")


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


BANDS = ("Low", "Elevated", "High", "Critical")


def unjudged(output: str, names: list[str]) -> list[str]:
    """The servers a check run's output gives no result for. It prints a line a server:
    its name, how the collection went, and the band it was judged at if it was."""
    judged = set()
    for line in output.splitlines():
        words = line.split()
        if len(words) >= 3 and words[2] in BANDS:
            judged.add(words[0])
    return [name for name in names if name not in judged]


def check_all(checker: install.Node, which: str, names: list[str]) -> None:
    """One pass over every server, as the daily check does it. A server that can't be reached
    makes the command end 1: that is `old-box`'s part, so the status alone says nothing, and
    what counts is that every one of the fleet's servers was collected from and judged."""
    done = checker.run(as_checker("run", "--all", "--unattended"), timeout=3600)
    print(f"{which} check: ended {done.returncode}")
    for line in (done.stdout + done.stderr).strip().splitlines()[-12:]:
        print(f"    {line}")
    missing = unjudged(done.stdout, names)
    if missing:
        raise DemoError(
            f"the {which} check gave no result for {', '.join(missing)}:\n"
            f"{(done.stdout + done.stderr)[-3000:]}"
        )


def behave(node: Through, server: Server) -> None:
    """What happens on a server between its two checks. The keys it plants are made in a
    folder that is gone when this returns: no one keeps a way in to a weakened server."""
    with tempfile.TemporaryDirectory(prefix="cc-demo-planted-") as made:
        _, root_key = keypair(Path(made), "planted-root")
        admin_file, admin_key = keypair(Path(made), "planted-admin")
        script = behaviour(server.role, root_key, admin_key)
        if script is None:
            return
        # On standard input, not as `bash -c <script>`: the script's own shell would carry every
        # pattern its pgrep checks look for, and they would find it instead of what they staged.
        done = node.run("bash -s", timeout=900, input=script)
        if done.returncode == 255:
            raise DemoError(f"{server.name}: the behaviours didn't run:\n{done.stderr[-1000:]}")
        for line in done.stderr.splitlines():
            if line.startswith("ATTACK FAILED"):
                print(f"{server.name}: {line}")
        if done.returncode != 0:
            print(f"{server.name}: the behaviours' script ended {done.returncode}")
        used = Through(server.address, admin_file, node.known, node.via, user="deploy2")
        try:
            login = used.run("true", timeout=60)  # the new account is used, as an intruder would
        finally:
            used.close()
        if login.returncode != 0:
            raise DemoError(
                f"{server.name}: the new account's login failed:\n{login.stderr[-500:]}"
            )
    print(f"{server.name}: behaviours done")


# The address goes in on standard input and is kept in a file for root alone while grep runs: on
# a command line it would be in the process list, which a check at that moment would collect.
_COUNT_IN_LOGS = (
    'f=$(mktemp) && cat > "$f" || exit 3; '
    "(journalctl --no-pager 2>/dev/null; cat /var/log/auth.log /var/log/secure"
    " /var/log/audit/audit.log /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null)"
    ' | grep -acF -f "$f"; s=$?; rm -f "$f"; exit $s'
)
_FILES_NAMING = (
    'f=$(mktemp) && cat > "$f" || exit 3; '
    f'grep -rlaF --devices=skip -f "$f" {install.DATA}; s=$?; rm -f "$f"; exit $s'
)

# The evidence itself: each stored collection, opened with the evidence key on the checker's
# server by the checker's own Python, and read the way the checker reads it (age, then gzip, then
# a record a line, a file's bytes in base64 where they aren't text). Nothing opened is written
# anywhere. It goes in on standard input, the address inside it, for the reason above.
_IN_EVIDENCE = r"""
import base64, json, sys, zlib
from pathlib import Path
import pyrage, yaml
from pyrage import x25519

home, needle = Path(sys.argv[1]), b"{needle}"
named = (yaml.safe_load((home / "config.yaml").read_text()) or {}).get("identity_file")
if not named:
    sys.exit("no evidence key is kept here")
identity = next(
    x25519.Identity.from_str(line.strip())
    for line in Path(named).read_text().splitlines()
    if line.startswith("AGE-SECRET-KEY-")
)


class Look:
    def __init__(self):
        self.inflate, self.partial = zlib.decompressobj(wbits=31), b""
        self.tails, self.hit = {}, False

    def write(self, data):
        *lines, self.partial = (self.partial + self.inflate.decompress(data)).split(b"\n")
        for line in lines:
            self.line(line)
        return len(data)

    def flush(self):
        pass

    def line(self, raw):
        if needle in raw:
            self.hit = True
        try:
            record = json.loads(raw)
        except ValueError:
            return
        if not isinstance(record, dict) or record.get("type") != "chunk":
            return
        data = record.get("data")
        if not isinstance(data, str):
            return
        try:
            piece = base64.b64decode(data) if record.get("encoding") == "base64" else data.encode()
        except ValueError:
            return
        source = record.get("source_id")
        whole = self.tails.get(source, b"") + piece  # an address split across two chunks
        if needle in whole:
            self.hit = True
        self.tails[source] = whole[-len(needle) :]


looked = 0
for path in sorted((home / "evidence").glob("*/*.age")):
    look = Look()
    with open(path, "rb") as source:
        pyrage.decrypt_io(source, look, [identity])
    look.line(look.partial)
    looked += 1
    if look.hit:
        print("HIT", path)
print("LOOKED", looked)
"""


def in_evidence(checker: install.Node, here: str, at_least: int) -> list[str]:
    """What the stored evidence says of this machine's address: a line for each collection that
    names it, or one saying the evidence couldn't be looked at (or not all of it was there)."""
    done = checker.run(
        f"runuser -u {install.ACCOUNT} -- {install.PROGRAM}/current/bin/python -I -"
        f" {shlex.quote(install.DATA)}",
        input=_IN_EVIDENCE.replace("{needle}", here),
        timeout=1800,
    )
    lines = done.stdout.splitlines()
    looked = [line for line in lines if line.startswith("LOOKED ")]
    if done.returncode != 0 or len(looked) != 1:
        return [f"the evidence couldn't be looked at ({done.stderr.strip()[-300:]})"]
    found = [f"the evidence names this machine: {line[4:]}" for line in lines if line[:4] == "HIT "]
    if int(looked[0].split()[1]) < at_least:
        found.append(f"only {looked[0].split()[1]} collections were there, of {at_least} or more")
    return found


def never_seen_from_here(checker: install.Node, nodes: dict[str, Through]) -> list[str]:
    """D.2's proof: what names this machine's address. The fleet's login records and logs; the
    files the checker keeps unencrypted; and the evidence it collected, which is encrypted as it
    arrives and so is opened to be read (two collections a server by now). A place that couldn't
    be looked at is a failure too, never a pass."""
    said = checker.out("echo $SSH_CLIENT").split()
    if not said or not re.fullmatch(r"[0-9a-fA-F.:]+", said[0]):
        return ["this machine's address, as the checker's server sees it, couldn't be read"]
    address = said[0]
    here = address + "\n"
    found = []
    for name, node in nodes.items():
        done = node.run(_COUNT_IN_LOGS, input=here)
        seen = done.stdout.strip()
        if done.returncode not in (0, 1) or not seen.isdigit():
            found.append(f"{name}: its logs couldn't be looked at ({done.stderr.strip()[-200:]})")
        elif seen != "0":
            found.append(f"{name}: its logs name this machine {seen} times")
    done = checker.run(_FILES_NAMING, input=here)
    if done.returncode not in (0, 1):
        found.append(f"the checker's files couldn't be looked at ({done.stderr.strip()[-200:]})")
    found += [f"the checker's own files: {line}" for line in done.stdout.splitlines()[:5]]
    return found + in_evidence(checker, address, 2 * len(nodes))


def up(api, folder: Path, region: str, today: date) -> int:
    try:
        if load_state(folder) is not None:
            raise DemoError(f"a demo is up already ({folder}/state.json): `down` first")
    except Unreadable as exc:
        raise DemoError(f"{exc}: `down` first") from exc
    claim(folder)
    count = len(FLEET) + 1
    print(f"{count} servers, about {cost(count, 1) * 100:.1f} cents an hour, until `demo.py down`.")
    run = proof.RUN
    state = State(run, datetime.now(UTC).isoformat(), (today + timedelta(days=1)).isoformat(), [])
    save_state(folder, state)
    known = folder / "known_hosts"
    nodes: dict[str, Through] = {}
    checker = None
    try:
        key, public = keypair(folder, "key")
        for node in past_their_date(api.demo_tagged(), today):
            print(f"sweep: deleting {node['label']}, past its end date")
            api.delete(node["id"])
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
        check_all(checker, "first", list(nodes))
        for server in state.fleet():
            behave(nodes[server.name], server)
        check_all(checker, "second", list(nodes))
        print(must(checker, as_checker("fleet"), "the fleet's results"))
        leaks = never_seen_from_here(checker, nodes)
        for leak in leaks:
            print(f"FAIL {leak}")
        if not leaks:
            print(
                "PASS nothing names this machine: not the fleet's logs, not the checker's"
                " files, not the evidence it collected"
            )
        print(f"\nThe checker: https://{state.web_name}/ (a test certificate: the browser warns)")
        print(f"Make the first account, within the hour: {link}")
        print(f"Up until `demo.py down`; its tags end on {state.until}.")
        return 1 if leaks else 0
    except BaseException:
        print("up failed: deleting what it made", file=sys.stderr)
        try:
            cleared = down(api, folder) == 0
        except BaseException as exc:  # noqa: BLE001 - it must be said, whatever stopped it
            print(f"deleting failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            cleared = False
        if not cleared:
            print("SERVERS MAY STILL BE UP AND BILLING: run `demo.py down`.", file=sys.stderr)
        raise
    finally:
        for node in [*nodes.values(), checker]:
            if node is not None:
                node.close()


# --- status and down ---------------------------------------------------------------------


def status(api, folder: Path, now: datetime) -> int:
    """What is up. Ends 1 for anything that wants a `down`: a demo past its end date, a demo
    server the state doesn't name, or a state that can't be read."""
    listed = demo_nodes(api.demo_tagged())
    try:
        state = load_state(folder)
    except Unreadable as exc:
        print(f"{exc}. Every demo server there is:")
        state = None
    else:
        if state is None:
            print("No demo is up.")
    if state is None:
        for node in listed:
            print(f"But {node['label']} exists (id {node['id']}): `down` deletes it.")
        return 1 if listed or (folder / "state.json").exists() else 0
    alive = {n["id"]: n for n in listed}
    hours = (now - datetime.fromisoformat(state.created)).total_seconds() / 3600
    print(f"Up for {hours:.1f} hours, about ${cost(len(state.servers), hours):.2f} so far.")
    print(f"Ends {state.until}. The checker: https://{state.web_name}/")
    for server in state.servers:
        node = alive.get(server.id)
        print(f"  {server.name:<12} {server.address:<16} {node['status'] if node else 'GONE'}")
    wants_down = False
    if date.fromisoformat(state.until) < now.date():
        print(f"OVERDUE: its end date was {state.until}. Run `down`.")
        wants_down = True
    ours = {s.id for s in state.servers}
    for node in listed:
        if node["id"] not in ours:
            print(f"Not in the state: {node['label']} (id {node['id']}), also up and billing.")
            wants_down = True
    return 1 if wants_down else 0


def listing(api, tries: int = 3, pause: float = 5) -> list[dict]:
    """Every demo server on the account; tried again, since it is asked for when things failed."""
    for attempt in range(tries):
        try:
            return demo_nodes(api.demo_tagged())
        except Exception as exc:  # noqa: BLE001 - a lost connection, whatever it raised
            if attempt == tries - 1:
                raise DemoError(f"the servers couldn't be listed ({exc})") from exc
            time.sleep(pause)
    return []


def down(api, folder: Path) -> int:
    """Delete this run's servers: those the state names, and any other carrying the run's
    label. With no state that can be read, every demo server. Only a server Linode lists with the
    demo's tag and label is ever deleted, whatever the state file says. Then the demo's own files
    go; a delete or listing that fails is said, and the state kept so it can be tried again."""
    try:
        state = load_state(folder)
    except Unreadable as exc:
        print(f"{exc}: deleting every demo server instead", file=sys.stderr)
        state = None
    try:
        listed = {n["id"]: n["label"] for n in listing(api)}
    except DemoError as exc:
        print(f"{exc}. Nothing was deleted: run `down` again.", file=sys.stderr)
        return 1
    named = {s.id: s.label for s in state.servers} if state else {}
    for linode_id, label in named.items():
        if linode_id not in listed:
            print(f"{label} was gone already")
    prefix = f"{LABEL_PREFIX}{state.run}-" if state else LABEL_PREFIX
    wanted = {i: label for i, label in listed.items() if i in named or label.startswith(prefix)}
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
    forget(folder)
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

    def stop(number, _frame):  # so a killed `up` still deletes what it made
        raise SystemExit(128 + number)

    try:
        if args.command == "up":
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGHUP, stop)
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
