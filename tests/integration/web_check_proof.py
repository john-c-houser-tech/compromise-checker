"""A check started from a page, for real (plan 5.11): one throwaway server that logs in and uses
sudo with a typed password, driven through the real pages in a real browser. A wrong password, a
right one, working it out again, and stopping one; and the password found nowhere afterwards.

Costs Linode time (about a cent): run only with John's approval. The server is deleted afterwards.
The home holds its address and the controller's, so it stays out of the repository.

    LINODE_TOKEN=… python tests/integration/web_check_proof.py --home NEW-FOLDER
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import asyncssh
import readonly_proof as proof
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from checker.inventory import Host

DISTRO = "ubuntu24.04"
USER = "webcheck"
PORT = "18349"
SETUP = """set -eu
useradd -m -s /bin/bash {user}
echo '{user}:{password}' | chpasswd
usermod -aG sudo {user}
printf 'PasswordAuthentication yes\\nKbdInteractiveAuthentication yes\\n' \\
    > /etc/ssh/sshd_config.d/00-web-check-proof.conf
systemctl restart ssh
"""
ACCOUNT_PASSWORD = secrets.token_urlsafe(18)


def checks(done: list, name: str, passed: bool, detail: str = "") -> None:
    print(("ok   " if passed else "FAIL ") + name + (f": {detail}" if detail else ""), flush=True)
    done.append(passed)


def wait_until_finished(page, seconds: int = 900) -> str:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        page.wait_for_timeout(3500)
        try:
            if not page.query_selector('meta[http-equiv="refresh"]'):
                return page.inner_text("[role=status]")
        except PlaywrightError:  # the page refreshed itself just then
            continue
    raise TimeoutError("still running")


def child_holds(password: str, pid_pattern: str) -> bool:
    """Whether a running check shows the password in its arguments or environment."""
    listing = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True).stdout  # noqa: S607
    found = False
    for line in listing.splitlines():
        if pid_pattern in line and "ps -eo" not in line:
            pid = line.split()[0]
            for part in ("cmdline", "environ"):
                try:
                    found |= password.encode() in Path(f"/proc/{pid}/{part}").read_bytes()
                except OSError:
                    pass
    return found


def anywhere_in(base: Path, password: str) -> list[str]:
    needle = password.encode()
    return [str(p) for p in base.rglob("*") if p.is_file() and needle in p.read_bytes()]


def drive(home: Path, password: str, env: dict, done: list) -> None:
    base = f"http://127.0.0.1:{PORT}"
    log = open(home / "server-output.txt", "wb")  # noqa: SIM115
    server = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "checker", "web", "--bind", f"127.0.0.1:{PORT}"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=log,
        text=True,
    )
    try:
        link = None
        for _ in range(40):
            line = server.stdout.readline()
            if "/setup/" in line:
                link = line.strip()
            if "is at" in line:
                break
        time.sleep(1)
        with sync_playwright() as play:
            browser = play.chromium.launch(
                executable_path=os.environ.get("CHROMIUM", "/usr/bin/chromium"),
                args=["--no-sandbox"],
            )
            page = browser.new_context().new_page()
            page.goto(link)
            page.fill("[name=username]", "owner")
            page.fill("[name=password]", ACCOUNT_PASSWORD)
            page.fill("[name=password2]", ACCOUNT_PASSWORD)
            page.click("main form button")
            page.wait_for_load_state()

            def start(typed: str) -> None:
                page.goto(f"{base}/checks/new")
                page.fill("[name=password-web-proof]", typed)
                page.click("main form button")
                page.wait_for_load_state()

            start("not the password")
            state = wait_until_finished(page)
            checks(done, "a wrong password says it had problems", "problems" in state, state)
            words = page.inner_text(".from-server")
            checks(done, "and what it reported says not collected", "not collected" in words)

            start(password)
            checks(done, "the check runs in its own process", True)
            checks(
                done,
                "the password isn't in its arguments or environment",
                not child_holds(password, "checker run --unattended"),
            )
            state = wait_until_finished(page)
            checks(done, "the right password finishes", state.startswith("Finished."), state)
            page.goto(f"{base}/")
            checks(done, "the server shows results", "web-proof" in page.inner_text("main"))
            page.goto(f"{base}/hosts/web-proof")
            checks(done, "its page opens", "Check this server now" in page.inner_text("main"))

            page.click("text=Work it out again")
            page.wait_for_load_state()
            state = wait_until_finished(page)
            checks(done, "working it out again finishes", state.startswith("Finished"), state)

            start(password)
            page.wait_for_timeout(1500)
            page.click("text=Stop this check")
            page.wait_for_load_state()
            state = wait_until_finished(page, 60)
            checks(done, "stopping one stops it", state.startswith("Stopped"), state)

            start(password)
            state = wait_until_finished(page)
            checks(done, "and the next one runs", state.startswith("Finished."), state)

            page.goto(f"{base}/activity")
            rows = page.inner_text("tbody")
            checks(done, "the record has it all", "stopped a check" in rows, "")
            browser.close()
    finally:
        server.terminate()
        server.wait()
        log.close()
    where = anywhere_in(home, password)
    checks(done, "the password is nowhere in the home", not where, ", ".join(where))
    purge = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "checker", "purge", "web-proof", "--yes"],
        env=env,
        capture_output=True,
        text=True,
    )
    left = [p.name for p in home.rglob("*.age") if "web-proof" in p.name and "report" not in p.name]
    checks(done, "a purge finds all of it, stopped check too", purge.returncode == 0 and not left)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--region", default="us-sea")
    args = parser.parse_args()
    if args.home.exists() and any(args.home.iterdir()):
        sys.exit(f"{args.home} isn't empty: give a new folder")
    home = args.home.resolve()
    env = {**os.environ, "CHECKER_HOME": str(home), "PYTHONUNBUFFERED": "1"}
    env.pop("LINODE_TOKEN", None)
    env.pop("SSH_AUTH_SOCK", None)
    subprocess.run([sys.executable, "-m", "checker", "init"], env=env, check=True)  # noqa: S603
    proof._cancel_on_sigterm()
    api = proof.Linode(proof.linode_token())
    await asyncio.to_thread(proof.sweep, api)
    password = secrets.token_urlsafe(24)
    done: list = []
    root_key = asyncssh.generate_private_key("ssh-ed25519")
    try:
        node = await proof._create_server(
            api, proof.run_label(DISTRO), proof.IMAGES[DISTRO], args.region,
            root_key.export_public_key().decode().strip(),
        )  # fmt: skip
        print(f"created (id {node['id']})", flush=True)
        deadline = time.monotonic() + 600
        while node["status"] != "running":
            if time.monotonic() > deadline:
                raise TimeoutError("server did not start within 10 minutes")
            await asyncio.sleep(5)
            node = await asyncio.to_thread(api.get, node["id"])
        address = node["ipv4"][0]
        with tempfile.TemporaryDirectory(prefix="cc-web-") as work:
            known = Path(work) / "known_hosts"
            root = Host(name="root", address=address, user="root", sudo="root")
            await proof.wait_for_ssh(root, known, deadline)
            async with asyncssh.connect(
                address, username="root", client_keys=[root_key], known_hosts=str(known),
                agent_path=None, gss_host=None, config=None,
            ) as conn:  # fmt: skip
                await conn.run(SETUP.format(user=USER, password=password), check=True, timeout=120)
        (home / "hosts.yaml").write_text(
            f"hosts:\n- name: web-proof\n  address: {address}\n  user: {USER}\n"
            "  auth: password\n  sudo: password\n"
        )
        trust = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "checker", "trust", "web-proof"],
            env=env,
            input="yes\n",
            capture_output=True,
            text=True,
        )
        if trust.returncode:
            sys.exit(f"trust failed: {re.sub(r'[0-9.]{7,}', 'ADDRESS', trust.stderr)}")
        await asyncio.to_thread(drive, home, password, env, done)
    finally:
        await asyncio.to_thread(proof.sweep_run, api)
    left = ["not checked"]
    for _ in range(24):  # a delete takes a little while to show
        nodes = await asyncio.to_thread(api.tagged)
        left = [n for n in nodes if n["label"].startswith(f"cc-test-{proof.RUN}")]
        if not left:
            break
        await asyncio.sleep(5)
    print(f"servers left from this run: {len(left)}")
    print(f"{sum(done)} of {len(done)} passed")
    return 0 if done and all(done) and not left else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
