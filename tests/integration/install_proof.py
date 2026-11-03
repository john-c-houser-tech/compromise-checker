"""Proof of the install script on real, new servers (installation plan, I.2).

Builds a release of this commit as version 9.9.9, signed by a throwaway key that a copy of the
installer is told to trust, and installs it from a folder on a new Linode per system. It proves the
refusals first, then the install, then that what it set up survives a reboot. Every server is
deleted, and leftovers are swept up next time.

Run by hand, not in CI: it spends money (a Nanode is $0.0075 an hour) and needs a Linode API token.
It works from what's committed, so commit first.

    LINODE_TOKEN=... python tests/integration/install_proof.py [--distro ubuntu24.04 rocky9 | all]
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parent))
import readonly_proof as proof  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
VERSION = "9.9.9"
SYSTEMS = ["ubuntu24.04", "ubuntu26.04", "rocky9", "rocky10"]
ACCOUNT = "compromise-checker"
UNIT = "compromise-checker-web.service"
PROGRAM = "/opt/compromise-checker"
HOME = "/var/lib/compromise-checker"
DATA = f"{HOME}/data"
LINK = "/usr/local/sbin/compromise-checker-link"
_LINK_LINE = re.compile(r"http://127\.0\.0\.1:8088/setup/\S+")


def build_release(work: Path) -> Path:
    """A release as `scripts/release.py` builds one, of a copy of this commit at a final version."""
    clone = work / "clone"
    subprocess.run(["git", "clone", "-q", str(ROOT), str(clone)], check=True)  # noqa: S603, S607
    head = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "checkout", "-q", head], cwd=clone, check=True)  # noqa: S603, S607
    for name in ("checker/__init__.py", "checker/collector/collector.py"):
        path = clone / name
        path.write_text(path.read_text(encoding="utf-8").replace("0.1.0.dev0", VERSION), "utf-8")
    subprocess.run(  # noqa: S603
        ["git", "-c", "user.name=proof", "-c", "user.email=proof@example.test"]  # noqa: S607
        + ["commit", "-qam", "proof version"],
        cwd=clone,
        check=True,
    )
    subprocess.run(  # noqa: S603
        [sys.executable, "scripts/release.py", "build", "--prerelease", "--trial"],
        cwd=clone,
        check=True,
    )
    return clone / "dist" / f"trial-{VERSION}"


def sign_release(directory: Path) -> None:
    """Trust a throwaway key instead, and sign with it, as minisign signs."""
    secret = Ed25519PrivateKey.generate()
    key_id = os.urandom(8)
    public = secret.public_key().public_bytes_raw()
    line = base64.b64encode(b"Ed" + key_id + public).decode()
    installer = directory / "install.py"
    text = installer.read_text(encoding="utf-8")
    text, changed = re.subn(r'RELEASE_KEY = "[^"]+"', f'RELEASE_KEY = "{line}"', text)
    assert changed == 1
    installer.write_text(text, encoding="utf-8")
    manifest = json.loads((directory / "release.json").read_text(encoding="utf-8"))
    manifest["schema"] = 1
    for name in manifest["files"]:
        data = (directory / name).read_bytes()
        manifest["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    data = (json.dumps(manifest, indent=2) + "\n").encode()
    (directory / "release.json").write_bytes(data)
    comment = b"Compromise Checker proof"
    signature = secret.sign(hashlib.blake2b(data, digest_size=64).digest())
    whole = secret.sign(signature + comment)
    (directory / "release.json.minisig").write_bytes(
        b"untrusted comment: proof\n"
        + base64.b64encode(b"ED" + key_id + signature)
        + b"\ntrusted comment: "
        + comment
        + b"\n"
        + base64.b64encode(whole)
        + b"\n"
    )


class Node:
    def __init__(self, address: str, key: Path, known: Path) -> None:
        self.address = address
        self.options = [
            "-F",
            "/dev/null",
            "-i",
            str(key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={known}",
            "-o",
            "ConnectTimeout=10",
        ]

    def run(self, command: str, timeout: int = 900) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603
            ["ssh", *self.options, f"root@{self.address}", command],  # noqa: S607
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )

    def out(self, command: str) -> str:
        return self.run(command).stdout.strip()

    def copy(self, source: Path, target: str) -> None:
        subprocess.run(  # noqa: S603
            ["scp", *self.options, "-q", "-r", str(source), f"root@{self.address}:{target}"],  # noqa: S607
            check=True,
            timeout=300,
        )

    def wait(self, seconds: int = 300) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if self.run("true", timeout=20).returncode == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
            time.sleep(5)
        raise RuntimeError(f"{self.address} never answered")


def status_of(node: Node, url: str) -> str:
    return node.out(f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'")


def untouched(node: Node) -> bool:
    return node.out(f"id {ACCOUNT} 2>/dev/null; ls -d {PROGRAM} {HOME} 2>/dev/null") == ""


def user_systemctl(uid: str, words: str) -> str:
    return f"runuser -u {ACCOUNT} -- env XDG_RUNTIME_DIR=/run/user/{uid} systemctl --user {words}"


def denials(node: Node) -> str:
    """What SELinux refused the tool, if it's enforcing."""
    if node.out("getenforce 2>/dev/null") != "Enforcing":
        return ""
    return node.out(
        "grep -E 'avc: +denied' /var/log/audit/audit.log 2>/dev/null"
        " | grep -E 'compromise|gunicorn|checker|python|systemd-user|user@' | tail -5"
    )


def prove(api, distro: str, region: str, release: Path, work: Path) -> list:
    results = []

    def checks(what: str, good: bool, detail: object = "") -> None:
        results.append((what, good, detail))
        shown = f" ({str(detail)[:600]})" if detail and not good else ""
        print(f"[{distro}] {'PASS' if good else 'FAIL'} {what}{shown}")

    place = work / distro
    place.mkdir()
    key = place / "key"
    subprocess.run(  # noqa: S603
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],  # noqa: S607
        check=True,
    )
    label = proof.run_label(distro)
    made = api.create(
        label, proof.IMAGES[distro], region, key.with_suffix(".pub").read_text().strip()
    )
    try:
        node = Node(made["ipv4"][0], key, place / "known")
        node.wait()
        node.copy(release, "/root/release")

        # --- Refusals, each leaving the machine as it was ---------------------------------------
        node.run("cp -r /root/release /root/bad && sed -i '1s/^./X/' /root/bad/requirements.lock")
        done = node.run("python3 /root/bad/install.py --from /root/bad --new-machine")
        checks(
            "a changed file is refused, with nothing changed",
            done.returncode == 1
            and "isn't the file that was signed" in done.stderr
            and untouched(node),
            done.stdout + done.stderr,
        )
        node.run("rm -rf /root/bad; cp -r /root/release /root/bad")
        node.run(
            "python3 - <<'EOF'\n"
            "from pathlib import Path\n"
            "p = Path('/root/bad/release.json')\n"
            "p.write_text(p.read_text().replace('9.9.9', '1.0.0'))\n"
            "EOF"
        )
        done = node.run("python3 /root/bad/install.py --from /root/bad --new-machine")
        checks(
            "a changed list of files is refused, with nothing changed",
            done.returncode == 1 and "doesn't match" in done.stderr and untouched(node),
            done.stdout + done.stderr,
        )
        node.run(
            "nohup python3 -m http.server 8123 >/dev/null 2>&1 & echo $! > /root/other; sleep 2"
        )
        done = node.run("python3 /root/release/install.py --from /root/release")
        checks(
            "signs of other use stop it when nobody can be asked, with nothing changed",
            done.returncode == 1 and "nobody here to ask" in done.stderr and untouched(node),
            done.stdout + done.stderr,
        )
        node.run("kill $(cat /root/other); while ss -Hltn | grep -q ':8123 '; do sleep 1; done")

        # --- The install ------------------------------------------------------------------------
        started = time.monotonic()
        done = node.run("python3 /root/release/install.py --from /root/release")
        took = round(time.monotonic() - started)
        print(f"[{distro}] install took {took}s")
        checks("it installs", done.returncode == 0, done.stdout + done.stderr)
        links = _LINK_LINE.findall(done.stdout)
        checks("it hands over a link", len(links) == 1, done.stdout)
        if done.returncode or not links:
            print(node.out(f"journalctl -u {UNIT} -n 40 --no-pager"))
            return results
        checks("the link opens", status_of(node, links[0]) == "200", links[0])
        checks(
            "the service is running",
            node.out(f"systemctl is-active {UNIT}") == "active",
            node.out(f"systemctl status {UNIT} --no-pager"),
        )
        pid = node.out(f"systemctl show -p MainPID --value {UNIT}")
        checks(
            "as the tool's own account",
            node.out(f"ps -o user= -p {pid}") == ACCOUNT,
            pid,
        )
        listening = node.out("ss -Hltn | grep ':8088 '")
        bound = [line.split()[3] for line in listening.splitlines()]
        checks("only on this machine", bound == ["127.0.0.1:8088"], listening)
        checks("the sign-in page answers", status_of(node, "http://127.0.0.1:8088/login") == "200")
        checks(
            "its folder is private",
            node.out(f"stat -c '%a %U' {HOME} {DATA}").split("\n") == [f"700 {ACCOUNT}"] * 2,
        )
        checks(
            "the evidence key is there, readable only by the tool",
            node.out(f"stat -c '%a %U' {DATA}/keys/evidence-identity.txt") == f"600 {ACCOUNT}",
        )
        code = node.run(f"runuser -u {ACCOUNT} -- test -w {PROGRAM}/current/bin/checker").returncode
        checks("the tool can't change its own program", code != 0)
        checks("sleep is off", node.out("systemctl is-enabled suspend.target") == "masked")

        # --- A new link -------------------------------------------------------------------------
        again = _LINK_LINE.findall(node.out(LINK))
        checks("the link can be shown again", len(again) == 1)
        checks("the new one opens", status_of(node, again[0]) == "200")
        checks("the old one stops working", status_of(node, links[0]) != "200")
        refused = node.run(f"su -s /bin/sh nobody -c {LINK}")
        checks("the command needs an administrator", refused.returncode != 0)

        # --- The daily timer, under the same limits as the web interface ------------------------
        uid = node.out(f"id -u {ACCOUNT}")
        unit = node.out(f"systemctl cat {UNIT}")
        service = unit.split("[Service]")[1].split("[Install]")[0]
        limits = " ".join(
            f"-p '{line}'"
            for line in service.splitlines()
            if line.strip() and not line.startswith(("ExecStart=", "Restart"))
        )
        done = node.run(
            f"systemd-run --wait --pipe {limits} {PROGRAM}/current/bin/checker"
            " schedule install --at 03:00"
        )
        checks(
            "the daily check can be set from inside the limits",
            done.returncode == 0,
            done.stdout + done.stderr,
        )
        timer = user_systemctl(uid, "list-timers --all --no-pager")
        checks("its timer is running", "compromise-checker" in node.out(timer), node.out(timer))

        # --- Running it again, and a reboot -----------------------------------------------------
        done = node.run("python3 /root/release/install.py --from /root/release")
        checks(
            "running it again changes nothing",
            done.returncode == 0 and "already installed" in done.stdout,
            done.stdout + done.stderr,
        )
        node.run("systemctl reboot")
        time.sleep(15)
        node.wait()
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if status_of(node, "http://127.0.0.1:8088/login") == "200":
                break
            time.sleep(3)
        checks(
            "after a reboot the page is back",
            status_of(node, "http://127.0.0.1:8088/login") == "200",
        )
        checks(
            "the service came back as itself", node.out(f"systemctl is-enabled {UNIT}") == "enabled"
        )
        checks("the timer came back", "compromise-checker" in node.out(timer), node.out(timer))
        after = _LINK_LINE.findall(node.out(LINK))
        checks("a link can still be made", len(after) == 1 and status_of(node, after[0]) == "200")
        print(f"[{distro}] SELinux: {node.out('getenforce 2>/dev/null') or 'not on this system'}")
        found = denials(node)
        checks("SELinux refused nothing", not found, found)
    finally:
        api.delete(made["id"])
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--distro", nargs="+", default=SYSTEMS, choices=[*SYSTEMS, "all"])
    parser.add_argument("--region", default="us-sea")
    arguments = parser.parse_args()
    systems = SYSTEMS if "all" in arguments.distro else arguments.distro
    api = proof.Linode(proof.linode_token())
    proof.sweep(api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-install-") as work:
            release = build_release(Path(work))
            sign_release(release)
            with ThreadPoolExecutor(len(systems)) as pool:
                futures = {
                    system: pool.submit(prove, api, system, arguments.region, release, Path(work))
                    for system in systems
                }
            failed = 0
            for system, future in futures.items():
                try:
                    results = future.result()
                except Exception as exc:  # one system's trouble doesn't hide the others'
                    print(f"[{system}] FAIL: {exc}")
                    failed += 1
                    continue
                bad = [what for what, good, _ in results if not good]
                word = "FAIL" if bad else "PASS"
                print(f"{system}: {word} ({len(results) - len(bad)} of {len(results)})")
                failed += bool(bad)
    finally:
        proof.sweep_run(api)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(main())
