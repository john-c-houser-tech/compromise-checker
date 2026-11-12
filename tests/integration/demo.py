"""The demo fleet that can be shown and kept running (plans/demo-fleet-plan-2026-11-10.md).

Unlike demo_fleet.py, the checker itself runs on a throwaway server too, installed by the install
page's own line, and every step on a fleet server is taken through that server. So no address in
anything the checker stores is the laptop's: what it holds can be shown as it is.

    LINODE_TOKEN=… python tests/integration/demo.py up       # the checker's server and the fleet
    LINODE_TOKEN=… python tests/integration/demo.py status   # what is up, its cost, when it ends
    python tests/integration/demo.py save DIR                # copy the checker's data down
    LINODE_TOKEN=… python tests/integration/demo.py down     # delete every server

`up` plays the story in demo_story.py in one sitting: each of its days is a few minutes, and
ends with a check of every server, run from the checker's own server.

`up --days N` keeps it up N days (1 to 14) and plays the story on its real days. Day 0 is played
from here; each later day is a timer on the checker's server, which plays that day's steps the way
this script does, a little before the checker's own daily check. So this machine can be off, and
the history has real dates. `status` says how each day went.

`save DIR` copies what the checker keeps to a new folder outside the repository: the demo dataset,
which `CHECKER_HOME=DIR checker web` shows on this machine with no servers. The web accounts stay
behind, and so does every key but the one the evidence is read with. The record of who did what
at the pages comes down with each address in it replaced (they are this machine's). It needs no
Linode token and changes nothing on the servers. `down` asks for it first: `down --unsaved`
deletes without.

Its servers carry their own tag, so the proofs' sweep of servers older than two hours leaves them
alone. Each also carries the last day it may be up: `status` says when that has passed, the next
`up` deletes any demo server past it that no state here names, and so does any proof's sweep.
Nothing else deletes a demo for its owner.

Costs Linode time (seven Nanodes, about 5 cents an hour): run only with John's approval. What `up`
makes stays up until `down`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import demo_story as story  # noqa: E402
import detection_proof as detection  # noqa: E402
import install_proof as install  # noqa: E402
import readonly_proof as proof  # noqa: E402

TAG = proof.DEMO_TAG
LABEL_PREFIX = proof.DEMO_LABEL
UNTIL = proof.DEMO_UNTIL  # a tag: the last day a server may be up, as YYYYMMDD
STATE = Path.home() / ".local" / "share" / "compromise-checker-demo"
# The published release, and its installer's SHA-256 as the install page gives it
# (https://nouriloop.com/work/compromise-checker/install/). Both change with a release.
RELEASE = "0.1.2"
INSTALLER_SHA256 = "8bc8989552356ef0aff29e0bcc291e5e53b53b7fbe919ff422857bccef022a5e"
NANODE_AN_HOUR = 0.0075
CHECKER = f"{install.PROGRAM}/current/bin/checker"
MACHINE_KEY = f"{install.DATA}/keys/scanner_ed25519"  # where first setup makes it
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


class DemoError(Exception):
    pass


class Unreadable(DemoError):
    """A state file that is there but can't be read: empty, damaged, or another version's."""


Member = story.Member
FLEET = story.FLEET
CONTROLLER = Member("checker", "", "ubuntu24.04")


# --- what is up, kept between commands ---------------------------------------------------


@dataclass
class Server:
    name: str
    role: str  # checker or fleet
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
    days: int = 0  # kept up this many days, the story's later days played by timers (0: no)
    last_check: str = ""  # then: when the last of those days is checked, by the checker's clock
    plan: list[dict] = field(default_factory=list)  # those days' steps, and when each runs
    saved: str = ""  # where `save` last put its data
    saved_at: str = ""  # and when (UTC, ISO)
    saved_whole: bool = False  # and whether the last day of a stay was in it

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


MOST_DAYS = 14


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
    # XDG_RUNTIME_DIR: `schedule install` talks to the account's own systemd, which the installer
    # keeps running. runuser gives no login session, so without it there is no way to find it.
    return (
        f"runuser -u {install.ACCOUNT} -- env CHECKER_HOME={install.DATA}"
        f" HOME={install.HOME} XDG_RUNTIME_DIR=/run/user/$(id -u {install.ACCOUNT})"
        f" {CHECKER} {said}"
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


def must(
    node: install.Node, command: str, what: str, timeout: int = 900, input: str | None = None
) -> str:
    done = node.run(command, timeout=timeout, input=input)
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
        role = "checker" if member is CONTROLLER else "fleet"
        return Server(
            member.name, role, member.distro, member.group, made["id"], label, made["ipv4"][0]
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


def prepare_member(
    checker: install.Node, node: Through, server: Server, member: Member, scanner_key: str
) -> None:
    """A fleet server as the proofs set one up, under the demo's names, with the scanner account
    and then all of SSH open to the checker's server only; then added to the checker and its
    identity confirmed against its own word."""
    node.wait(600)
    setup = story.renamed(proof.SETUP, story.SETUP_NAMES)
    setup = setup.replace("{controller}", checker.address).replace("{scanner_key}", scanner_key)
    done = node.run(proof.strict(setup))
    if done.returncode != 0:
        raise DemoError(
            f"setting the server up failed on {node.address}:\n"
            f"{(done.stdout + done.stderr)[-2000:]}"
        )
    for line in done.stderr.splitlines():
        if line.startswith("proof setup:"):  # a part it goes on without, e.g. no container
            print(f"{server.name}: {line}")
    if "Docker not started" in done.stderr:
        # The break-in's container step needs it. Once more, this time saying why.
        again = node.run("bash --norc --noprofile -s", timeout=600, input=story.CONTAINER)
        if again.returncode == 0:
            print(f"{server.name}: Docker started at the second try")
        else:
            said = (again.stdout + again.stderr).strip()[-1500:]
            print(f"{server.name}: Docker still not started:\n{said}")
    firewall = story.FIREWALL.replace("{checker}", checker.address)
    must(
        node,
        "bash --norc --noprofile -s",
        "closing SSH to all but the checker's server",
        input=firewall,
    )
    must(node, proof.strict(detection.WEB_SETUP), "its web server", timeout=300)
    if member.old_php:
        must(node, proof.strict(story.PHP.install), "the older PHP")
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
    must(
        checker,
        whitelist_command(server.name, 'mkdir -p "$(dirname "$0")" && cat > "$0"'),
        f"{server.name}'s whitelist",
        input=story.WHITELIST.replace("{checker}", checker.address),
    )
    print(f"{server.name}: set up, closed to all but the checker, added and confirmed")


def whitelist_command(name: str, shell: str) -> str:
    """A shell line run as the checker's account, with a server's whitelist file as its $0."""
    path = f"{install.DATA}/whitelist/hosts/{name}.yaml"
    return (
        f"runuser -u {install.ACCOUNT} -- sh -c {shlex.quote('umask 077 && ' + shell)}"
        f" {shlex.quote(path)}"
    )


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


def filled(step: story.Step, keys: dict[str, str]) -> str:
    """A step's script as it is run: strict where the story says, its keys and addresses in."""
    script = ("set -eu\n" if step.strict else "") + step.script
    for name, value in keys.items():
        script = script.replace("{" + name + "}", value)
    return script


def on_server(node: Through, step: story.Step, keys: dict[str, str], admin_file: Path) -> list[str]:
    """One of the story's steps on a fleet server: its script as root, then a login as the
    account it made, if the story has one. Returns what the script said had failed: the story
    goes on, and `up` says so at the end."""
    script = filled(step, keys)
    # On standard input, not as `bash -c <script>`: the script's own shell would carry every
    # pattern its pgrep checks look for, and they would find it instead of what they staged.
    done = node.run("bash --norc --noprofile -s", timeout=1800, input=script)
    if done.returncode == 255:
        raise DemoError(f"{step.where}: the step didn't run:\n{done.stderr[-1000:]}")
    if step.strict and done.returncode != 0:
        raise DemoError(f"{step.where}: {step.says}: it failed:\n{done.stderr[-1000:]}")
    failed = [
        f"{step.where}: {line}"
        for line in done.stderr.splitlines()
        if line.startswith(("ATTACK FAILED", "STEP FAILED"))
    ]
    if done.returncode != 0:
        failed.append(
            f"{step.where}: its script ended {done.returncode}: {done.stderr.strip()[-300:]}"
        )
    for line in failed:
        print(f"    {line}")
    if step.login:
        used = Through(node.address, admin_file, node.known, node.via, user=step.login)
        try:
            login = used.run("true", timeout=60)  # the new account is used
        finally:
            used.close()
        if login.returncode != 0:
            raise DemoError(
                f"{step.where}: the login as {step.login} failed:\n{login.stderr[-500:]}"
            )
    return failed


def by_admin(checker: install.Node, step: story.Step, world: World) -> None:
    """One of the story's steps by the person running the checker, through its own commands.
    Where the story wants to see what the checker answers (an acceptance it may refuse), the
    answer is printed and the story goes on."""
    verb, *words = step.admin

    def said(done) -> None:
        for line in (done.stdout + done.stderr).strip().splitlines()[-6:]:
            print(f"    {line}")

    if verb == "schedule":
        at = must(checker, "date -d '1 hour ago' +%H:00", "reading its clock").strip()
        done = checker.run(as_checker("schedule", "install", "--at", at))
        said(done)
        world.at = at if done.returncode == 0 else ""
        if done.returncode != 0:  # the pages still work without it: said at the end
            world.failed.append(
                f"the daily check wasn't set (`schedule install` ended {done.returncode})"
            )
    elif verb == "accept":
        host, reason = words
        said(checker.run(as_checker("baseline", "accept", host, "--reason", reason)))
    elif verb == "remove":
        (host,) = words
        must(checker, as_checker("hosts", "remove", host), f"taking {host} off the list")
        world.unlisted.add(host)
    elif verb == "rule":
        (host,) = words
        rule = story.BACKUP_RULE.format(expires=world.expires.isoformat())
        must(checker, whitelist_command(host, 'cat >> "$0"'), f"{host}'s rule", input=rule)
        print("    " + must(checker, as_checker("whitelist", "check"), "the rules").strip())
    elif verb == "retire":
        pack, reason = words
        told = must(
            checker, as_checker("packs", "retire", pack, "--reason", reason), f"stopping {pack}"
        )
        if "Retired:" not in told:  # it ends 0 for an update that wasn't in use
            raise DemoError(f"{pack} wasn't stopped: {told.strip()[-300:]}")
    else:
        raise DemoError(f"the story asks for {verb!r}, which isn't a thing the admin does here")


@dataclass
class World:
    """What the story changes as it plays."""

    nodes: dict[str, Through]  # every fleet server, for as long as the demo is up
    today: date
    lost: set[str] = field(default_factory=set)  # still listed, no longer answering
    unlisted: set[str] = field(default_factory=set)  # taken off the checker's list, still up
    found: list[str] = field(default_factory=list)  # the proof's findings on a server since lost
    failed: list[str] = field(default_factory=list)  # steps that didn't do what the story says
    collected: int = 0  # how many collections the story's checks made
    at: str = ""  # the daily check's time, once it is set (HH:MM, the checker's server's clock)
    expires_on: date | None = None  # kept up for days: the admin's rule lasts to a day of the story

    @property
    def expires(self) -> date:
        """The last day of the rule the admin writes: in one sitting, the day after it."""
        return self.expires_on or self.today + timedelta(days=1)

    def checked(self) -> list[str]:
        return [name for name in self.nodes if name not in self.lost | self.unlisted]


def shut_out(checker: install.Node, address: str, tries: int = 8, pause: float = 5) -> bool:
    """Whether a server has stopped letting the checker's server in."""
    for _ in range(tries):
        time.sleep(pause)
        if checker.run(f"timeout 5 bash -c '</dev/tcp/{address}/22'").returncode != 0:
            return True
    return False


def play(
    checker: install.Node, world: World, steps=story.STORY, checked=story.CHECKED_DAYS
) -> None:
    """The story, a day at a time: what happens on the servers, what the admin does, then the
    day's check. The keys it plants are made in a folder that is gone when this returns: no one
    keeps a way in to a weakened server."""
    with tempfile.TemporaryDirectory(prefix="cc-demo-planted-") as made:
        _, root_key = keypair(Path(made), "planted-root")
        keys = {"root_key": root_key, "checker": checker.address}
        for day in sorted({step.day for step in steps} | set(checked)):
            print(f"--- day {day}")
            for step in (s for s in steps if s.day == day):
                print(f"  {step.where}: {step.says}")
                if step.admin:
                    by_admin(checker, step, world)
                else:
                    if step.lost:  # the proof looks at its logs now: it can't afterwards
                        here = this_machine(checker)
                        one = {step.where: world.nodes[step.where]}
                        world.found += (
                            in_logs(here, one) if here else [f"{step.where}: not looked at"]
                        )
                    # Each account the story makes has a key of its own.
                    admin_file, admin_key = keypair(Path(made), f"planted-{step.login or 'none'}")
                    node = world.nodes[step.where]
                    world.failed += on_server(
                        node, step, {**keys, "admin_key": admin_key}, admin_file
                    )
                    if step.lost:
                        if not shut_out(checker, node.address):
                            raise DemoError(f"{step.where} still lets the checker's server in")
                        world.lost.add(step.where)
            if day in checked:
                check_all(checker, f"day {day}'s", world.checked())
                world.collected += len(world.checked())


# --- kept up for days: the later days, played from the checker's server ---------------------

# The story's later days happen with this machine off. They are played from the checker's server,
# by a timer a day, the way `play` does it from here: a root login to the fleet server from the
# checker's address, the step's script on standard input. (A timer on the fleet server itself
# would be a new timer there: a finding of its own, in a story that isn't about it.) So the
# checker's server holds, for root alone, a key that root on every fleet server accepts from that
# address only, and the keys of the accounts the story logs in as. Each is deleted when it has been
# used for the last time.
STORY_HOME = "/root/cc-story"
_SSH = (
    "-o UserKnownHostsFile=known_hosts -o BatchMode=yes -o IdentitiesOnly=yes"
    " -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"
)
RUNNER = r"""#!/bin/bash
# The demo story's day {day} (tests/integration/demo.py), run once by cc-story-day{day}.timer.
cd {home} || exit 1
note() { echo "$(date -u +%FT%TZ) $*" >> results; }
on_server() {  # a step's id, the server's address: its script, as root
    timeout 1500 ssh -i key {ssh} "root@$2" 'bash --norc --noprofile -s' \
        < "$1.sh" > "$1.out" 2> "$1.err"
    code=$?
    note "$1 ended $code $(grep -E '^(ATTACK|STEP) FAILED' "$1.err" | tr '\n' ';')"
    rm -f "$1.sh"
}
login() {  # a step's id, the account, the address: the new account is used, once
    timeout 60 ssh -i "account-$2" {ssh} "$2@$3" true > /dev/null 2>> "$1.err"
    note "$1-login ended $?"
    rm -f "account-$2"
}
shut() {  # a step's id, the address: the server has stopped letting this one in
    for _ in 1 2 3 4 5 6 7 8; do
        sleep 5
        if ! timeout 5 bash -c "</dev/tcp/$2/22" 2> /dev/null; then
            note "$1-shut ended 0"
            return
        fi
    done
    note "$1-shut ended 1 it still lets the checker's server in"
}
"""
_UNIT = """\
[Unit]
Description=The demo story, day {day}

[Service]
Type=oneshot
TimeoutStartSec=40min
ExecStart=/bin/bash {home}/day{day}.sh
"""
_TIMER = """\
[Unit]
Description=The demo story, day {day}

[Timer]
OnCalendar={when}:00
AccuracySec=1s
Persistent=true

[Install]
WantedBy=timers.target
"""
# A day's steps, ahead of that day's check. Long enough for the slowest day (the break-in, a few
# minutes; 25 if it waits on a package lock), and inside the unit's 40-minute limit.
BEFORE_THE_CHECK = timedelta(minutes=45)
AFTER_THE_CHECK = timedelta(minutes=60)  # a day the story doesn't check: after the daily one


def story_key(checker: install.Node, nodes: dict[str, Through]) -> None:
    """The key the later days are played with. Made on the checker's server and put on each
    fleet server before its first check, so it is part of what the server starts with."""
    public = must(
        checker,
        f"umask 077 && mkdir -p {STORY_HOME} && cd {STORY_HOME}"
        " && ssh-keygen -q -t ed25519 -N '' -C ops@checker -f key && cat key.pub",
        "making the story's key",
    ).strip()
    line = shlex.quote(f'from="{checker.address}" {public}')
    for name, node in nodes.items():
        must(node, f"echo {line} >> /root/.ssh/authorized_keys", f"{name}: the story's key")
        must(
            checker,
            f"cd {STORY_HOME} && ssh -i key {_SSH} -o StrictHostKeyChecking=accept-new"
            f" root@{node.address} true",
            f"reaching {name} with the story's key",
        )


def first_check(now: datetime, at: str) -> datetime:
    """Day 1's check: the daily check's next time that leaves room for day 1's steps before it."""
    hour, minute = (int(part) for part in at.split(":"))
    first = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if first <= now + BEFORE_THE_CHECK:
        first += timedelta(days=1)
    return first


def step_times(now: datetime, at: str, days: list[int], checked=story.CHECKED_DAYS) -> dict:
    """When each later day's steps run, on the checker's server's clock: before that day's
    check, or after it for a day the story doesn't check (its point is what the pages say until
    the next one). Day 1's check is the first the daily timer makes."""
    first = first_check(now, at)
    return {
        day: first
        + timedelta(days=day - 1)
        + (AFTER_THE_CHECK if day not in checked else -BEFORE_THE_CHECK)
        for day in days
    }


def admin_lines(step: story.Step, expires: date) -> str:
    """One of the admin's steps as shell lines for the checker's server: what `by_admin` runs."""
    verb, *words = step.admin
    if verb == "accept":
        host, reason = words
        return as_checker("baseline", "accept", host, "--reason", reason)
    if verb == "remove":
        return as_checker("hosts", "remove", words[0])
    if verb == "rule":
        rule = story.BACKUP_RULE.format(expires=expires.isoformat())
        return (
            whitelist_command(words[0], 'cat >> "$0"')
            + f" <<'RULE'\n{rule}RULE\n"
            + as_checker("whitelist", "check")
        )
    if verb == "retire":
        pack, reason = words
        return as_checker("packs", "retire", pack, "--reason", reason) + " | grep -q Retired:"
    raise DemoError(f"the story asks for {verb!r}, which can't be left to a timer")


def stage(
    checker: install.Node, world: World, days: int, steps=story.STORY
) -> tuple[list[dict], list[str], datetime]:
    """Put the story's days 1 to `days` on the checker's server, a timer each. Returns the plan
    (each step, and when it runs), the steps left out for being after the last day, and when the
    last day is checked (the checker's server's clock)."""
    if not world.at:
        raise DemoError("the daily check wasn't set, so there is nothing for the days to wait for")
    later = [s for s in steps if s.day >= 1]
    left_out = [f"day {s.day}: {s.where}: {s.says}" for s in later if s.day > days]
    later = [s for s in later if s.day <= days]
    now = datetime.fromisoformat(must(checker, "date +%Y-%m-%dT%H:%M", "its clock").strip())
    times = step_times(now, world.at, sorted({s.day for s in later}))
    first = first_check(now, world.at)
    # The admin's rule lasts through day 5's check, so day 6's shows it run out.
    world.expires_on = (first + timedelta(days=4)).date()
    plan = []

    def put(name: str, text: str) -> None:
        must(checker, f"umask 077 && cat > {STORY_HOME}/{name}", f"staging {name}", input=text)

    with tempfile.TemporaryDirectory(prefix="cc-demo-planted-") as made:
        _, root_key = keypair(Path(made), "planted-root")
        keys = {"root_key": root_key, "checker": checker.address}
        for day, when in times.items():
            runner = RUNNER.replace("{day}", str(day)).replace("{home}", STORY_HOME)
            runner = runner.replace("{ssh}", _SSH)
            for number, step in enumerate((s for s in later if s.day == day), 1):
                name = f"d{day}-{number}"
                plan.append(
                    {"id": name, "day": day, "where": step.where, "says": step.says}
                    | {"when": when.isoformat(timespec="minutes")}
                )
                runner += f"\n# {step.where}: {step.says}\n"
                if step.admin:
                    lines = admin_lines(step, world.expires)
                    runner += (
                        f"(\nset -e\n{lines}\n) > {name}.out 2> {name}.err\n"
                        f'note "{name} ended $?"\n'
                    )
                    continue
                address = world.nodes[step.where].address
                if step.login:
                    private, public = keypair(Path(made), f"planted-{step.login}")
                    put(f"account-{step.login}", private.read_text(encoding="utf-8"))
                    keys["admin_key"] = public
                put(f"{name}.sh", story.renamed(filled(step, keys), story.DAYS_APART))
                runner += f"on_server {name} {address}\n"
                if step.login:
                    runner += f"login {name} {step.login} {address}\n"
                if step.lost:
                    runner += f"shut {name} {address}\n"
            if day == max(times):  # nothing is left to do with them: no way in is kept
                runner = runner.replace(
                    "note() {", "trap 'rm -f key key.pub account-*' EXIT\nnote() {", 1
                )
            put(f"day{day}.sh", runner)
            unit = f"/etc/systemd/system/cc-story-day{day}"
            must(
                checker,
                f"cat > {unit}.service",
                "its unit",
                input=_UNIT.format(day=day, home=STORY_HOME),
            )
            must(
                checker,
                f"cat > {unit}.timer && systemctl daemon-reload"
                f" && systemctl enable -q --now cc-story-day{day}.timer",
                f"day {day}'s timer",
                input=_TIMER.format(day=day, when=when.strftime("%Y-%m-%d %H:%M")),
            )
    return plan, left_out, first + timedelta(days=days - 1)


def story_so_far(checker: install.Node, plan: list[dict]) -> tuple[list[str], bool]:
    """Each of the later days' steps, and how it went, from what its day's timer wrote down; and
    whether all is as it should be (nothing failed, nothing is late)."""
    done = checker.run(f"date +%Y-%m-%dT%H:%M; cat {STORY_HOME}/results 2>/dev/null")
    clock, _, results = done.stdout.partition("\n")
    try:
        now = datetime.fromisoformat(clock.strip())
    except ValueError:
        said = done.stderr.strip()[-200:]
        return [f"  The checker's server couldn't be asked ({said})"], False
    ended: dict[str, list[str]] = {}
    for line in results.splitlines():
        words = line.split(" ", 4)
        if len(words) < 4:
            continue
        name, code, more = words[1], words[3], " ".join(words[4:]).strip()
        ended.setdefault(name.split("-login")[0].split("-shut")[0], []).append(
            "" if code == "0" and not more else f"{name} ended {code} {more}".strip()
        )
    lines, good = [], True
    for step in plan:
        went = ended.get(step["id"])
        if went is None:  # the slowest day is done well inside the hour
            late = now > datetime.fromisoformat(step["when"]) + timedelta(hours=1)
            how = "LATE: it should have run by now, and hasn't said so" if late else "not yet"
        else:
            how = "; ".join(w for w in went if w) or "done"
        good = good and how in ("not yet", "done")
        lines.append(
            f"  day {step['day']}, {step['when'].replace('T', ' ')}  {step['where']}:"
            f" {step['says']}: {how}"
        )
    return lines, good


# The address goes in on standard input and is kept in a file for root alone while grep runs: on
# a command line it would be in the process list, which a check at that moment would collect.
_COUNT_IN_LOGS = (
    'f=$(mktemp) && cat > "$f" || exit 3; '
    '[ -n "$(journalctl -a --no-pager -n 1 2>/dev/null)" ] || [ -s /var/log/auth.log ]'
    ' || [ -s /var/log/secure ] || { rm -f "$f"; echo "no log could be read" >&2; exit 4; }; '
    "(journalctl -a --no-pager 2>/dev/null; cat /var/log/auth.log /var/log/secure"
    " /var/log/audit/audit.log /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null)"
    ' | grep -acF -f "$f"; s=$?; rm -f "$f"; exit $s'
)
_FILES_NAMING = (
    'f=$(mktemp) && cat > "$f" || exit 3; '
    f'grep -rlaF --devices=skip -f "$f" {install.HOME}; s=$?; rm -f "$f"; exit $s'
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
    # What the checker works out from a collection is kept beside it and read too; only the
    # collections themselves are counted.
    looked += not any(kind in path.name for kind in (".events-", ".snapshot-", ".assessment-"))
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


def this_machine(checker: install.Node) -> str | None:
    """This machine's address, as the checker's server sees it."""
    said = checker.out("echo $SSH_CLIENT").split()
    return said[0] if said and re.fullmatch(r"[0-9a-fA-F.:]+", said[0]) else None


def in_logs(here: str, nodes: dict[str, Through]) -> list[str]:
    """The fleet servers whose login records and logs name this address, or couldn't be read."""
    found = []
    for name, node in nodes.items():
        done = node.run(_COUNT_IN_LOGS, input=here + "\n")
        seen = done.stdout.strip()
        if done.returncode not in (0, 1) or not seen.isdigit():
            found.append(f"{name}: its logs couldn't be looked at ({done.stderr.strip()[-200:]})")
        elif seen != "0":
            found.append(f"{name}: its logs name this machine {seen} times")
    return found


def never_seen_from_here(
    checker: install.Node,
    nodes: dict[str, Through],
    earlier: tuple[str, ...] = (),
    collected: int = 1,
) -> list[str]:
    """The proof that the demo can be shown as it is: what names this machine's address. The
    fleet's login records and logs; the files the checker keeps unencrypted; and the evidence it
    collected, which is encrypted as it arrives and so is opened to be read. A place that
    couldn't be looked at is a failure too, never a pass. `earlier`: what was found on a server
    looked at before the story shut it off. `collected`: how many collections must be there."""
    address = this_machine(checker)
    if address is None:
        return ["this machine's address, as the checker's server sees it, couldn't be read"]
    found = [*earlier, *in_logs(address, nodes)]
    done = checker.run(_FILES_NAMING, input=address + "\n")
    if done.returncode not in (0, 1):
        found.append(f"the checker's files couldn't be looked at ({done.stderr.strip()[-200:]})")
    found += [f"the checker's own files: {line}" for line in done.stdout.splitlines()[:5]]
    return found + in_evidence(checker, address, collected)


class Said:
    """Somewhere to print that can't fail: when the terminal is gone (which is what a hang-up
    means) every print raises, and that would end the deleting. What is said then goes to a file."""

    def __init__(self, stream, instead: Path):
        self.stream, self.instead = stream, instead

    def write(self, text: str) -> int:
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):
            self.stream = open(self.instead, "a", encoding="utf-8")  # noqa: SIM115
            self.stream.write(text)
            self.stream.flush()
        return len(text)

    def flush(self) -> None:
        pass


@contextmanager
def nothing_stops_it(folder: Path):
    """While a failed `up` deletes what it made: a second signal is ignored, and a terminal that
    has gone doesn't stop it (what is said goes to a file beside the state folder instead)."""
    held = {}
    for number in (signal.SIGTERM, signal.SIGHUP):
        try:
            held[number] = signal.signal(number, signal.SIG_IGN)
        except ValueError:  # not the main thread: there is no handler of ours to hold off
            pass
    out, err = sys.stdout, sys.stderr
    log = folder.with_name(folder.name + "-up-failed.log")
    sys.stdout, sys.stderr = Said(out, log), Said(err, log)
    try:
        yield
    finally:
        sys.stdout, sys.stderr = out, err
        for number, handler in held.items():
            signal.signal(number, handler)


def play_days(checker: install.Node, world: World, state: State, folder: Path, days: int) -> None:
    """Kept up for days: day 0 from here, then each later day put on the checker's server."""
    story_key(checker, world.nodes)  # before the first check: part of what a server starts with
    play(checker, world, [s for s in story.STORY if s.day == 0], (0,))
    state.plan, left_out, last = stage(checker, world, days)
    state.last_check = last.isoformat(timespec="minutes")
    save_state(folder, state)
    print("\nThe days to come, by the checker's server's clock:")
    for line in story_so_far(checker, state.plan)[0]:
        print(line)
    for line in left_out:
        print(f"  left out, after day {days}: {line}")


def up(api, folder: Path, region: str, today: date, days: int = 0) -> int:
    """`days`: keep it up that many days, the story's later days on their own days (0: the whole
    story now, minutes apart)."""
    if not 0 <= days <= MOST_DAYS:
        raise DemoError(f"--days is 1 to {MOST_DAYS}")
    try:
        if load_state(folder) is not None:
            raise DemoError(f"a demo is up already ({folder}/state.json): `down` first")
    except Unreadable as exc:
        raise DemoError(f"{exc}: `down` first") from exc
    claim(folder)
    count = len(FLEET) + 1
    print(f"{count} servers, about {cost(count, 1) * 100:.1f} cents an hour, until `demo.py down`.")
    # Kept up for days, the last of them is checked up to a day after `days` days have passed
    # (and day 5's step comes after its check): its tags end the day after that.
    until = today + timedelta(days=days + 1 if days else 1)
    if days:
        print(
            f"Kept up {days} days: about ${cost(count, 24 * days):.2f}, and nothing deletes it"
            " for you. `up` says when the last day is done, once the daily check is set."
        )
    run = proof.RUN
    state = State(run, datetime.now(UTC).isoformat(), until.isoformat(), [], days=days)
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
        members = {m.name: m for m in FLEET}
        with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
            list(
                pool.map(
                    lambda s: prepare_member(
                        checker, nodes[s.name], s, members[s.name], scanner_key
                    ),
                    state.fleet(),
                )
            )
        name, address = story.UNREACHABLE
        must(checker, hosts_add(Member(name, "", ""), address), f"adding {name}")
        world = World(nodes, today)
        if days:
            play_days(checker, world, state, folder, days)
        else:
            play(checker, world)
        print(must(checker, as_checker("fleet"), "the fleet's results"))
        answering = {name: node for name, node in nodes.items() if name not in world.lost}
        leaks = never_seen_from_here(checker, answering, tuple(world.found), world.collected)
        for leak in leaks:
            print(f"FAIL {leak}")
        if not leaks:
            print(
                "PASS nothing names this machine so far: not the fleet's logs, not the checker's"
                " files, not the evidence it collected. (Signing in to the pages from here puts"
                " this address in the web interface's own records.)"
            )
        if world.failed:
            print("\nNOT AS THE STORY SAYS:")
            for line in world.failed:
                print(f"  {line}")
        print(f"\nThe checker: https://{state.web_name}/ (a test certificate: the browser warns)")
        print(f"Make the first account, within the hour: {link}")
        print(f"Up until `demo.py down`; its tags end on {state.until}.")
        if days:
            print(
                "`demo.py status` says how the days went. Run `demo.py down` after"
                f" {state.last_check.replace('T', ' ')} (the checker's server's clock, UTC),"
                f" when day {days} has been checked, and by the end of {state.until}."
            )
        hands_on()
        return 1 if leaks or world.failed else 0
    except BaseException:
        with nothing_stops_it(folder):
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


# --- save ----------------------------------------------------------------------------------

# What of the checker's home is the demo's data: enough for `CHECKER_HOME=DIR checker web` to show
# every page on a machine with no servers. Named here, so a file the checker starts keeping later
# isn't copied until someone has said it should be. Left out on purpose: every key but the one the
# evidence is read with (the key that logs in to the fleet, the web interface's secrets, the mail
# key), and web.db, which holds the accounts, their sessions and failed sign-ins. Two of its
# tables do come down, since two pages show nothing without them: the record of who did what at
# the pages, and the checks started from one. Each row holds the address it came from, which is
# the one place this machine's address is kept: the server puts NOT_KEPT there before it sends.
STORE = "checker.db"
EVIDENCE_KEY = "keys/evidence-identity.txt"
KEPT_FILES = ("config.yaml", "hosts.yaml", "known_hosts", "run-state.age", EVIDENCE_KEY)
KEPT_FOLDERS = ("evidence", "packs", "whitelist", "proposals", "reports")
ABOUT = "demo.json"  # what `save` writes beside them: which run this was, and its servers
ACCOUNTS = "web.db"
RECORD = "web-record.db"  # the two tables, as they come down; put into a new web.db here
RECORD_TABLES = ("web_actionrecord", "web_checkrun")
NOT_KEPT = "(not kept)"
MOST_ROWS = 200_000
# The most `save` takes from a server, and the longest it waits: a week's stay is a few megabytes.
MOST_BYTES = 2 * 1024**3
MOST_SECONDS = 3600
MOST_IN_A_VALUE = 64 * 1024**2  # of the saved store, or of a sealed file, read to be searched
AFTER_THE_LAST_CHECK = timedelta(minutes=5)  # a timer may fire up to a minute late

# On the checker's server, as the tool's account, by the checker's own Python: the home as a tar
# on standard output, and nothing written there. No check or purge runs meanwhile (their lock is
# held, and a check under way is a reason to stop, not to wait), and no threat update changes.
# The store is read through SQLite's own backup, so the copy is whole whatever was being written.
_SEND = r"""
import fcntl, io, json, os, sqlite3, sys, tarfile, time
from pathlib import Path

home = Path(sys.argv[1])
files, folders, store, accounts, record, tables, not_kept = json.loads(sys.argv[2])
lock = os.open(home / "run.lock", os.O_RDWR | os.O_CREAT, 0o600)
try:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(3)
if not (home / store).is_file():
    sys.exit(4)
if (home / "packs").is_dir():  # a threat update moves files between folders: wait for it
    packs = os.open(home / "packs" / "state.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(packs, fcntl.LOCK_EX)
source = sqlite3.connect(f"file:{home / store}?mode=ro", uri=True)
whole = sqlite3.connect(":memory:")
source.backup(whole)
source.close()
whole_files = {store: whole.serialize()}
if (home / accounts).is_file() and (home / accounts).stat().st_size:
    # The record of the pages' use, and no other table: made anew here, each row's address
    # replaced as it is copied, so what is sent never held one.
    source = sqlite3.connect(f"file:{home / accounts}?mode=ro", uri=True)
    kept = sqlite3.connect(":memory:")
    for table in tables:
        made = source.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        if made is None:
            continue
        kept.execute(made[0])
        columns = [row[1] for row in source.execute(f'PRAGMA table_info("{table}")')]
        if "address" not in columns:
            sys.exit(f"{table} has no address column: is this a newer checker?")
        marks = ", ".join("?" for _ in columns)
        for row in source.execute(f'SELECT * FROM "{table}"'):
            row = [not_kept if c == "address" else v for c, v in zip(columns, row)]
            kept.execute(f'INSERT INTO "{table}" VALUES ({marks})', row)
    kept.commit()
    source.close()
    whole_files[record] = kept.serialize()
sent, collections, newest = 0, 0, 0
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as out:
    for name, data in whole_files.items():
        entry = tarfile.TarInfo(name)
        entry.size, entry.mode, entry.mtime = len(data), 0o600, int(time.time())
        out.addfile(entry, io.BytesIO(data))
        sent += 1
    paths = [home / name for name in files]
    for name in folders:
        paths += sorted((home / name).rglob("*"))
    for path in paths:
        name = path.relative_to(home)
        # A lock, or anything half made under a temporary name, is no part of the data.
        if path.is_symlink() or not path.is_file() or any(p.startswith(".") for p in name.parts):
            continue
        if path.name.endswith((".lock", ".tmp")):
            continue
        try:
            with open(path, "rb") as content:
                entry = out.gettarinfo(arcname=str(name), fileobj=content)
                # A second name for a file already sent goes as a file too, not as a link to it.
                entry.type, entry.linkname = tarfile.REGTYPE, ""
                entry.size = os.fstat(content.fileno()).st_size
                out.addfile(entry, content)
        except FileNotFoundError:
            continue
        sent += 1
        if name.parts[0] == "evidence" and len(name.parts) == 3 and path.suffix == ".age":
            collections += 1
            derived = any(k in path.name for k in (".events-", ".snapshot-", ".assessment-"))
            if not derived:
                newest = max(newest, int(entry.mtime))
print("SENT", sent, collections, newest, file=sys.stderr)
"""


def shown(text: str) -> str:
    """Text a server wrote, fit to print: nothing in it can move the cursor or clear the screen."""
    return "".join(c if c.isprintable() or c == "\n" else "?" for c in text)


def wanted(name: str) -> bool:
    """Whether a path in what the checker's server sent is one `save` asked for."""
    parts = Path(name).parts
    if not parts or Path(name).is_absolute() or ".." in parts or not name.isprintable():
        return False
    if any(part.startswith(".") for part in parts):
        return False
    if parts[0] == "evidence":  # a server's folder, and its files in it: where they are read
        return len(parts) == 3
    return name in (STORE, RECORD, *KEPT_FILES) or (len(parts) > 1 and parts[0] in KEPT_FOLDERS)


def fetch(checker: install.Node, work: Path) -> tuple[Path, int, int, int]:
    """The checker's data, as a tar in `work` (a folder for this account alone). Returns the tar,
    how many files the server says it sent, how many of them are stored evidence, and when the
    newest collection was written. A server that sends too much, or for too long, is cut off."""
    sent_for = [KEPT_FILES, KEPT_FOLDERS, STORE, ACCOUNTS, RECORD, RECORD_TABLES, NOT_KEPT]
    command = (
        f"runuser -u {install.ACCOUNT} -- {install.PROGRAM}/current/bin/python -I -"
        f" {shlex.quote(install.DATA)}"
        f" {shlex.quote(json.dumps(sent_for))}"
    )
    archive, errors = work / "data.tar", work / "said"
    with open(archive, "wb") as out, open(errors, "wb") as err:
        sending = subprocess.Popen(  # noqa: S603
            ["ssh", *checker.options, f"{checker.user}@{checker.address}", command],  # noqa: S607
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=err,
        )
        stop = threading.Timer(MOST_SECONDS, sending.kill)
        stop.start()
        try:
            sending.stdin.write(_SEND.encode())
            sending.stdin.close()
            taken = 0
            while block := sending.stdout.read(1 << 20):
                taken += len(block)
                if taken > MOST_BYTES:
                    raise DemoError(
                        f"the checker's server sent more than {MOST_BYTES >> 30} GB: stopped"
                    )
                out.write(block)
            code = sending.wait()
        finally:
            late = not stop.is_alive()
            stop.cancel()
            sending.kill()
            sending.wait()
    with open(errors, "rb") as err:
        err.seek(max(0, errors.stat().st_size - 4000))
        said = shown(err.read().decode(errors="replace"))
    if late:
        raise DemoError(
            f"the checker's server was still sending after {MOST_SECONDS // 60} minutes"
        )
    if code == 3:
        raise DemoError("a check or a purge is running on the checker's server: save when it ends")
    if code == 4:
        raise DemoError(f"the checker's server keeps no store in {install.DATA}/{STORE}")
    counts = [line.split() for line in said.splitlines() if line.startswith("SENT ")]
    if code != 0 or len(counts) != 1 or not all(n.isdigit() for n in counts[0][1:]):
        raise DemoError(f"the checker's data couldn't be read:\n{said.strip()[-1500:]}")
    sent, collections, newest = (int(n) for n in counts[0][1:4])
    return archive, sent, collections, newest


def unpack(archive: Path, into: Path) -> int:
    """Take the tar apart into `into`: only ordinary files, only the ones asked for, each once,
    readable by this account alone. Returns how many. Anything else in it stops the save, since
    what comes from a server is never taken on trust."""
    try:
        with tarfile.open(archive, "r:") as tar:
            members = tar.getmembers()
            seen = set()
            for member in members:
                ordinary = member.type == tarfile.REGTYPE and member.sparse is None
                if not ordinary or not wanted(member.name) or member.name in seen:
                    raise DemoError(
                        f"the checker's server sent {member.name!r}, which wasn't asked for"
                    )
                seen.add(member.name)
            tar.extractall(into, members=members, filter="data")  # noqa: S202 - each checked
    except (tarfile.TarError, OSError) as exc:
        raise DemoError(f"what the checker's server sent couldn't be taken apart ({exc})") from exc
    for path in [into, *into.rglob("*")]:
        path.chmod(0o700 if path.is_dir() else 0o600)
    return len(members)


def settings_here(folder: Path, where: Path) -> None:
    """The saved settings, made safe to use on this machine. They name the evidence key by its
    whole path, which was the server's: it becomes the saved key's, as it will be in `where`. And
    whatever in them could run a command here or send anything anywhere is put back to what a new
    checker starts with, since a settings file is taken from the server like any other: the
    command for notifications, the advisor, where threat updates come from and whose signature
    they need, and asking for new releases. The servers' list may only name key logins, so a check
    started here by mistake offers nothing of this machine's."""
    import yaml

    if not (folder / EVIDENCE_KEY).is_file():
        raise DemoError("no evidence key came with the data, so what was collected can't be read")
    path = folder / "config.yaml"
    try:
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        hosts = (folder / "hosts.yaml").read_text(encoding="utf-8")
        listed = (yaml.safe_load(hosts) or {}).get("hosts") or []
    except FileNotFoundError:
        listed = []
    except (OSError, yaml.YAMLError, AttributeError) as exc:
        raise DemoError(f"the saved settings can't be read ({exc})") from exc
    if not isinstance(config, dict):
        raise DemoError("the saved settings aren't the checker's")
    if config.get("database"):
        raise DemoError("the store is in a database of its own, which `save` doesn't copy")
    if not all(isinstance(h, dict) and h.get("auth") == "key" for h in listed):
        raise DemoError("the saved list of servers has one that doesn't log in with the demo's key")
    for name in ("notify_command", "advisor"):
        config.pop(name, None)
    if isinstance(config.get("packs"), dict):
        for name in ("source", "trusted_keys"):
            config["packs"].pop(name, None)
    else:
        config.pop("packs", None)
    config["updates"] = {"check": False}
    config["identity_file"] = str(where / EVIDENCE_KEY)
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)


def paths_here(folder: Path, was: str, where: Path) -> int:
    """The store says where each collection and what was worked out from it is kept, by its whole
    path, which was the server's (`was`). Each becomes the saved file's, as it will be in `where`:
    without that no page here could open one. Those rows can't otherwise be changed, so their
    guards are lifted for this and put back. A path that isn't a saved file's stops the save: the
    checker opens, writes beside and deletes what these name. Returns how many were changed."""
    changed = 0
    store = sqlite3.connect(folder / STORE)
    try:
        store.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MOST_IN_A_VALUE)
        guards = store.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
        tables = [t for (t,) in store.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in store.execute(f"PRAGMA table_info({quoted})")]
            if "path" not in columns:
                continue
            mine = [(name, sql) for name, on, sql in guards if on == table]
            for name, _ in mine:
                store.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
            rows = store.execute(f"SELECT rowid, path FROM {quoted}").fetchall()  # noqa: S608
            for rowid, path in rows:
                if not isinstance(path, str) or not path.startswith(was + "/"):
                    raise DemoError(f"the saved store's {table} names a file outside {was}")
                inside = path[len(was) + 1 :]
                if not wanted(inside) or not (folder / inside).is_file():
                    raise DemoError(f"the saved store's {table} names a file that wasn't saved")
                store.execute(
                    f"UPDATE {quoted} SET path = ? WHERE rowid = ?",  # noqa: S608
                    (str(where / inside), rowid),
                )
                changed += 1
            for _, sql in mine:
                store.execute(sql)
        store.commit()
    except sqlite3.Error as exc:
        raise DemoError(f"the saved store's paths couldn't be changed ({exc})") from exc
    finally:
        store.close()
    return changed


_NEW_ACCOUNTS = """
import sys
from pathlib import Path
from checker.web import app
app.configure(Path(sys.argv[1]))
"""


def record_here(folder: Path) -> dict[str, int]:
    """The record of the pages' use, put where the pages read it: a new accounts database, made
    by the checker's own code as it makes one at its first start (so with no account in it), and
    the rows that came down added to it. Only the two tables, only columns this checker has, and
    only rows whose address the server did replace. Returns how many rows of each."""
    came = folder / RECORD
    if not came.is_file():
        return {}
    made = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _NEW_ACCOUNTS, str(folder)],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "CHECKER_HOME": str(folder)},
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if made.returncode != 0:
        raise DemoError(f"a new accounts database couldn't be made:\n{made.stderr.strip()[-800:]}")
    counts = {}
    source = sqlite3.connect(f"file:{came}?mode=ro&immutable=1", uri=True)
    target = sqlite3.connect(folder / ACCOUNTS)
    try:
        source.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MOST_IN_A_VALUE)
        for table in RECORD_TABLES:
            sent = [row[1] for row in source.execute(f'PRAGMA table_info("{table}")')]
            here = [row[1] for row in target.execute(f'PRAGMA table_info("{table}")')]
            columns = [name for name in sent if name in here]
            if not sent:
                continue
            if "address" not in columns:
                raise DemoError(f"the record's table {table} isn't one this checker keeps")
            names = ", ".join(f'"{name}"' for name in columns)
            marks = ", ".join("?" for _ in columns)
            place = columns.index("address")
            counts[table] = 0
            for row in source.execute(f'SELECT {names} FROM "{table}"'):  # noqa: S608
                if row[place] != NOT_KEPT:
                    raise DemoError(f"the server sent a row of {table} with its address still in")
                if counts[table] >= MOST_ROWS:
                    raise DemoError(f"the server sent more than {MOST_ROWS} rows of {table}")
                target.execute(f'INSERT INTO "{table}" ({names}) VALUES ({marks})', row)  # noqa: S608
                counts[table] += 1
        target.commit()
    except sqlite3.Error as exc:
        raise DemoError(f"the record of the pages' use couldn't be put in place ({exc})") from exc
    finally:
        source.close()
        target.close()
    came.unlink()
    for path in folder.rglob("*"):  # what making the database left: this account's alone
        path.chmod(0o700 if path.is_dir() else 0o600)
    return counts


def forms_of(here: str) -> list[str]:
    """The ways an address is written that are looked for: as it is, and as it appears in a name
    made from it, in a reverse lookup, or (IPv6) written out in full or as its network."""
    import ipaddress

    forms = [here]
    try:
        address = ipaddress.ip_address(here.split("%")[0])
    except ValueError:
        return forms
    if address.version == 4:
        forms += [here.replace(".", "-"), address.reverse_pointer]
    else:
        network = ipaddress.ip_network(f"{address}/64", strict=False)
        forms += [str(address), address.exploded, str(network.network_address), str(network)]
    forms += [form.upper() for form in forms if form.upper() != form]
    return list(dict.fromkeys(forms))


SEALED = b"age-encryption.org/v1"


def opened(blob: bytes, identity) -> bytes:
    """A sealed value or file, opened with the saved key, and unpacked if it was packed."""
    import pyrage

    plain = pyrage.decrypt(blob, [identity])
    if plain[:2] == b"\x1f\x8b":
        unpacker = zlib.decompressobj(wbits=31)
        plain = unpacker.decompress(plain, MOST_IN_A_VALUE)
        if unpacker.unconsumed_tail:
            raise ValueError("more is packed in it than is read to search it")
    return plain


def in_store(path: Path, needles: list[str], identity, what: str = "the store") -> list[str]:
    """Where a saved database holds any of the texts, or couldn't be read: each table, row by row,
    through SQLite (a value can lie across pages in the file, where a search of its bytes would
    miss it), with every value the checker sealed opened first."""
    found = []
    wanted_bytes = [needle.encode() for needle in needles]
    # immutable: nothing else has it open, and no file is made beside it for reading it.
    store = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        store.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MOST_IN_A_VALUE)
        said = store.execute("PRAGMA integrity_check").fetchall()
        if said != [("ok",)]:
            raise DemoError(f"the saved copy of {what} is damaged: {shown(str(said[:3]))}")
        tables = store.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        for (table,) in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            said = set()
            for row in store.execute(f"SELECT * FROM {quoted}"):  # noqa: S608 - its own table
                for value in row:
                    if isinstance(value, str):
                        value = value.encode()
                    if not isinstance(value, bytes):
                        continue
                    if value.startswith(SEALED):
                        try:
                            value = opened(value, identity)
                        except Exception as exc:  # noqa: BLE001 - whatever stopped it, it's said
                            said.add(f"a sealed value couldn't be opened ({type(exc).__name__})")
                            continue
                    if any(needle in value for needle in wanted_bytes):
                        said.add("names this machine")
            found += [f"{what}'s table {shown(table)}: {why}" for why in sorted(said)]
    except sqlite3.Error as exc:
        raise DemoError(f"the saved copy of {what} can't be read ({exc})") from exc
    finally:
        store.close()
    return found


def _no_more_memory_than() -> None:
    """For the evidence's reader, which unpacks what a server packed: a bound on what it may use."""
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))


def names_this_machine(folder: Path, here: str, collections: int) -> list[str]:
    """What in the saved data names this machine's address, or couldn't be looked at. The files
    as they are and the store row by row, for the address in each way it is written; every sealed
    file and value, opened with the saved key; and the evidence, opened and read the way the proof
    reads it on the checker's server. So it also proves every collection can be read."""
    from checker.evidence import load_identity

    try:
        identity = load_identity(folder / EVIDENCE_KEY)
    except Exception as exc:  # noqa: BLE001 - a key that isn't one, however it fails
        return [f"the saved evidence key can't be read ({type(exc).__name__})"]
    needles = forms_of(here)
    found = in_store(folder / STORE, needles, identity)
    if (folder / ACCOUNTS).is_file():
        found += in_store(folder / ACCOUNTS, needles, identity, "the pages' record")
    evidence = {p for p in (folder / "evidence").glob("*/*.age")}
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path in evidence:
            continue
        name = shown(str(path.relative_to(folder)))
        if path.stat().st_size > MOST_IN_A_VALUE and path.name != STORE:
            found.append(f"{name}: too big to be looked through")
            continue
        content = path.read_bytes()
        if path.suffix == ".age" or content.startswith(SEALED):
            try:
                content = opened(content, identity)
            except Exception as exc:  # noqa: BLE001 - whatever stopped it, it's said
                found.append(
                    f"{name}: couldn't be opened with the saved key ({type(exc).__name__})"
                )
                continue
        if any(needle.encode() in content for needle in needles):
            found.append(f"{name}: names this machine")
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-", str(folder)],
        input=_IN_EVIDENCE.replace("{needle}", here),
        capture_output=True,
        text=True,
        timeout=MOST_SECONDS,
        check=False,
        preexec_fn=_no_more_memory_than,  # noqa: PLW1509 - one thread here, and it only sets a limit
    )
    lines = done.stdout.splitlines()
    looked = [line for line in lines if line.startswith("LOOKED ")]
    if done.returncode != 0 or len(looked) != 1:
        said = shown(done.stderr.strip()[-300:])
        return [*found, f"the saved evidence couldn't be opened ({said})"]
    found += [f"the evidence: {shown(line[4:])}" for line in lines if line[:4] == "HIT "]
    if len(evidence) != collections:
        found.append(f"{len(evidence)} evidence files were saved, of the {collections} sent")
    return found


def too_near_a_check(state: State, now: datetime) -> str | None:
    """While a stay still has days to play: why not to save now, if the story's steps or the
    daily check are about to run or running. `save` holds off checks while it copies, and a day's
    check that found it doing so would be lost. The last day's too: its timer may fire a little
    after its time, so a save holds off for the first minutes after it."""
    if not state.last_check:
        return None
    last = datetime.fromisoformat(state.last_check)
    clock = now.astimezone(UTC).replace(tzinfo=None)
    if clock > last + AFTER_THE_LAST_CHECK:
        return None  # the last day's check has started: if it is still going, the lock says so
    if clock > last:
        return (
            f"the last day's check is starting ({last:%H:%M} UTC): save in"
            f" {AFTER_THE_LAST_CHECK.seconds // 60} minutes, when it is under way or done"
        )
    check = clock.replace(hour=last.hour, minute=last.minute, second=0, microsecond=0)
    for day in (-1, 0, 1):
        start = check + timedelta(days=day) - BEFORE_THE_CHECK - timedelta(minutes=15)
        # A day the story doesn't check plays its steps an hour after, for up to 40 minutes.
        end = check + timedelta(days=day) + AFTER_THE_CHECK + timedelta(minutes=45)
        if start <= clock <= end:
            return (
                f"the story's steps and the daily check run between {start:%H:%M} and"
                f" {end:%H:%M} UTC, and it is {clock:%H:%M}: save after that"
            )
    return None


def in_a_repository(target: Path) -> Path | None:
    """The git repository `target` would be inside, whichever checkout of whichever it is."""
    return next((p for p in (target, *target.parents) if (p / ".git").exists()), None)


def save(folder: Path, target: Path, now: datetime) -> int:
    """Copy the checker's data down as the demo dataset, to a new folder outside any repository.
    It is put together beside `target` and takes that name only when nothing in it names this
    machine and all of its evidence opens; otherwise it stays under its working name, and says
    why. The servers aren't changed, and `save` can be run again."""
    state = load_state(folder)
    if state is None or not state.web_name:
        raise DemoError("no demo with a checker installed is up: there is nothing to save")
    target = target.expanduser().resolve()
    if inside := in_a_repository(target):
        raise DemoError(f"the dataset goes outside any repository ({inside} is one): it is data")
    if target.exists():
        raise DemoError(f"{target} exists: `save` makes a new folder")
    if reason := too_near_a_check(state, now):
        raise DemoError(reason)
    part = target.with_name(target.name + ".part")
    if part.exists() or part.is_symlink():
        raise DemoError(f"{part} is left from a save that didn't finish: look at it, or delete it")
    target.parent.mkdir(parents=True, exist_ok=True)
    checker = install.Node(state.checker().address, folder / "key", folder / "known_hosts")
    # The tar holds the evidence and its key: in a folder of this account's own while it exists.
    work = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=target.parent))
    try:
        here = this_machine(checker)
        if here is None:
            raise DemoError("this machine's address, as the checker's server sees it, wasn't read")
        part.mkdir(mode=0o700)
        try:
            archive, sent, collections, newest = fetch(checker, work)
            got = unpack(archive, part)
            if got != sent:
                raise DemoError(f"{got} files arrived, of the {sent} the checker's server sent")
            settings_here(part, part)
            moved = paths_here(part, install.DATA, part)
            record = record_here(part)
        except BaseException:  # nothing whole came down: no working folder is left in the way
            shutil.rmtree(part, ignore_errors=True)
            raise
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise DemoError(f"the save stopped ({type(exc).__name__}: {exc})") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
        checker.close()
    # A stay's data is whole when its last day's check has left a collection.
    last = (
        datetime.fromisoformat(state.last_check).replace(tzinfo=UTC) if state.last_check else None
    )
    whole = last is None or newest >= last.timestamp()
    about = {
        "run": state.run,
        "created": state.created,
        "saved": now.astimezone(UTC).isoformat(timespec="seconds"),
        "release": RELEASE,
        "days": state.days,
        "last_day_in_it": whole,
        "web_name": state.web_name,
        "servers": [
            {"name": s.name, "role": s.role, "distro": s.distro, "address": s.address}
            for s in state.servers
        ],
        "plan": state.plan,
        "changed_here": (
            f"{moved} paths in the store, from {install.DATA} to this folder; the settings'"
            " evidence key path; notifications, the advisor, the threat updates' source and"
            " release checks put back to off or as new"
        ),
        "pages_record": (
            f"{record.get('web_actionrecord', 0)} lines of who did what at the pages and"
            f" {record.get('web_checkrun', 0)} checks started from one, each with the address it"
            f" came from replaced by {NOT_KEPT!r}; no account, session or sign-in came down"
        ),
    }
    (part / ABOUT).write_text(json.dumps(about, indent=2) + "\n", encoding="utf-8")
    (part / ABOUT).chmod(0o600)
    leaks = names_this_machine(part, here, collections)
    if leaks:
        for leak in leaks:
            print(f"FAIL {leak}")
        print(f"Not fit to show as it is. Kept for a look, under its working name: {part}")
        return 1
    settings_here(part, target)
    paths_here(part, str(part), target)
    part.rename(target)
    state.saved, state.saved_at, state.saved_whole = str(target), about["saved"], whole
    save_state(folder, state)
    print(
        f"PASS {got} files, {collections} of them stored evidence. Every collection, sealed file"
        f" and sealed value opened with the saved key, and none of them holds {here}, this"
        " machine's address as the checker's server sees it now. The web accounts, their sessions"
        " and sign-ins stayed on the server, and so did every key but the evidence's. The record"
        f" of who did what at the pages came down ({sum(record.values())} rows), each address in"
        f" it replaced by {NOT_KEPT!r} before it was sent."
    )
    if not whole:
        print(
            "NOTE the last day's check has left no collection yet"
            f" ({state.last_check.replace('T', ' ')} UTC): `down` will ask for a save after it."
        )
    print(f"Saved to {target}. It names its own place, so it can't be moved: save again instead.")
    print(f"To look through it here, with no servers: CHECKER_HOME={target} checker web")
    return 0


def unsaved(folder: Path) -> str | None:
    """Why `down` should wait: a checker is up whose data was never saved, was saved before the
    last day of its stay left a collection, or isn't where it was saved to. Deleting the servers
    deletes the only copy."""
    try:
        state = load_state(folder)
    except Unreadable:
        return None  # nothing says where its checker is: there is nothing `save` could do
    if state is None or not state.web_name:
        return None
    how = "`demo.py save DIR` first, or `down --unsaved` to delete it as it is"
    if not state.saved:
        return f"the checker's data hasn't been saved, and `down` deletes the only copy: {how}"
    if not (Path(state.saved) / STORE).is_file():
        return f"the data was saved to {state.saved}, which isn't there now: {how}"
    if not state.saved_whole:
        return (
            f"the data was saved ({state.saved}) before the last day's check, at"
            f" {state.last_check.replace('T', ' ')} UTC, had left a collection: {how}"
        )
    return None


# --- status and down ---------------------------------------------------------------------


def hands_on() -> None:
    print("\nYours to do while it is up (what only a person at the pages can produce):")
    for line in story.HANDS_ON:
        print(f"  - {line}")


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
    wants_look = False
    if state.plan and state.checker().id in alive:  # a server that is gone isn't asked
        print(f"Kept up {state.days} days. The story's days, by the checker's server's clock:")
        checker = install.Node(state.checker().address, folder / "key", folder / "known_hosts")
        try:
            lines, good = story_so_far(checker, state.plan)
        finally:
            checker.close()
        for line in lines:
            print(line)
        print(f"Day {state.days} is checked at {state.last_check.replace('T', ' ')}.")
        wants_look = not good
    wants_down = False
    if date.fromisoformat(state.until) < now.date():
        print(f"OVERDUE: its end date was {state.until}. Run `down`.")
        wants_down = True
    ours = {s.id for s in state.servers}
    for node in listed:
        if node["id"] not in ours:
            print(f"Not in the state: {node['label']} (id {node['id']}), also up and billing.")
            wants_down = True
    hands_on()
    return 1 if wants_down or wants_look else 0


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
    parser.add_argument("command", choices=["up", "status", "save", "down"])
    parser.add_argument("folder", nargs="?", type=Path, help="save: the new folder for the data")
    parser.add_argument("--state", type=Path, default=STATE, help="where what is up is kept")
    parser.add_argument("--region", default="us-sea")
    parser.add_argument(
        "--days",
        type=int,
        help=f"up: keep it up this many days (1 to {MOST_DAYS}), the story a day at a time",
    )
    parser.add_argument(
        "--unsaved", action="store_true", help="down: delete though the data was never saved"
    )
    args = parser.parse_args(argv)
    if args.days is not None and (args.command != "up" or not 1 <= args.days <= MOST_DAYS):
        parser.error(f"--days goes with `up`, and is 1 to {MOST_DAYS}")
    if (args.folder is not None) != (args.command == "save"):
        parser.error("`save` takes the new folder to save to, and nothing else does")
    if args.unsaved and args.command != "down":
        parser.error("--unsaved goes with `down`")
    try:
        if args.command == "save":  # the servers are asked, not Linode: no token
            return save(args.state, args.folder, datetime.now(UTC))
        if args.command == "down" and not args.unsaved and (reason := unsaved(args.state)):
            raise DemoError(reason)
    except DemoError as exc:
        print(f"demo: {exc}", file=sys.stderr)
        return 1
    api = Api(proof.linode_token())

    def stop(number, _frame):  # so a killed `up` still deletes what it made
        raise SystemExit(128 + number)

    try:
        if args.command == "up":
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGHUP, stop)
            return up(api, args.state, args.region, datetime.now(UTC).date(), args.days or 0)
        if args.command == "status":
            return status(api, args.state, datetime.now(UTC))
        return down(api, args.state)
    except DemoError as exc:
        print(f"demo: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(main())
