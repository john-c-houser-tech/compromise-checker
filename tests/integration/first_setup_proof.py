"""First setup's whole journey, for real (plan 5.13b): an empty home, a real browser, the page's own
commands run on a real sshd in a throwaway container, a real identity check and a real collection.
Nothing here touches a Linode, this machine's timers or its real home.

    python tests/integration/first_setup_proof.py     # needs Docker, Chromium and Playwright

The container has no init system or login records, so the check's results say so: this proves the
path, not what it finds."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[2]
ACCOUNT = "correct horse battery 9"
WEB_PORT, SSH_PORT = 8100, 2298
CONTAINER = "cc-first-setup-proof"
PREPARE = (
    "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq"
    " && apt-get install -y -qq openssh-server sudo python3 > /dev/null"
    " && mkdir -p /run/sshd && /usr/sbin/sshd"
)
results: list[bool] = []


def checks(what: str, good: bool, detail: object = "") -> None:
    results.append(bool(good))
    print(("PASS " if good else "FAIL ") + what, detail if not good else "", flush=True)


def run(*words: str, check: bool = True, given: str | None = None):
    return subprocess.run(  # noqa: S603
        words, capture_output=True, text=True, check=check, input=given, timeout=400
    )


def start_server(home: Path, env: dict) -> tuple[subprocess.Popen, str, list[str]]:
    server = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "checker", "web", "--bind", f"127.0.0.1:{WEB_PORT}"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        cwd=REPO,
    )
    link, said = "", []
    for _ in range(40):
        line = server.stdout.readline()
        said.append(line)
        if "/setup/" in line:
            link = line.strip()
        if "is at" in line:
            break
    time.sleep(1)
    return server, link, said


def wait_for_check(page) -> str:
    for _ in range(120):
        text = page.inner_text("main")
        if re.search(r"Finished|had problems|didn.t finish|stopped", text):
            return text
        time.sleep(2)
        page.reload()
    return page.inner_text("main")


def journey(page, base: str, link: str, home: Path, gateway: str) -> None:
    page.goto(link)
    page.fill("[name=username]", "owner")
    page.fill("[name=password]", ACCOUNT)
    page.fill("[name=password2]", ACCOUNT)
    page.click("main form button")
    page.wait_for_load_state()
    checks(
        "the first page points at first setup", "Start with first setup" in page.inner_text("main")
    )
    page.click("text=Start with first setup")
    page.wait_for_load_state()
    page.click("text=I've backed it up")
    page.wait_for_load_state()
    page.fill("form[action$='choices'] [name=confirm_password]", ACCOUNT)
    page.click("text=Save these choices")
    page.wait_for_load_state()
    page.fill("form[action$='make-key'] [name=confirm_password]", ACCOUNT)
    page.click('button:has-text("Make this machine\'s key")')
    page.wait_for_load_state()
    key = home / "keys" / "scanner_ed25519"
    checks("the key is made, for its owner only", key.stat().st_mode & 0o777 == 0o600)
    page.click("text=Add a server")
    page.wait_for_load_state()
    page.fill("[name=name]", "web-1")
    page.fill("[name=address]", "127.0.0.1")
    page.fill("[name=port]", str(SSH_PORT))
    page.fill("[name=confirm_password]", ACCOUNT)
    page.click("text=Add this server")
    page.wait_for_load_state()
    page.goto(f"{base}/first-setup")
    page.click("text=What to set up on web-1")
    page.wait_for_load_state()
    page.fill("[name=from]", gateway)
    page.click("text=Put it in the commands")
    page.wait_for_load_state()
    commands = page.locator("pre.command").first.inner_text()
    checks("the commands limit the key to this machine", f'from="{gateway}"' in commands, commands)
    done = run("docker", "exec", "-i", CONTAINER, "bash", "-e", check=False, given=commands)
    said = done.stdout + done.stderr
    checks(
        "the page's commands run on a server", done.returncode == 0 and "parsed OK" in said, said
    )
    page.goto(f"{base}/manage/server?host=web-1")
    page.click("text=Ask the server for its key")
    page.wait_for_load_state()
    command = re.search(r"ssh-keygen -lf \S+", page.inner_text("main"))
    checks("the page names the key file", bool(command), page.inner_text("main"))
    printed = run("docker", "exec", CONTAINER, "bash", "-c", command.group(0)).stdout.strip()
    page.fill("[name=pasted]", printed)
    page.fill("form[action$='trust-key'] [name=confirm_password]", ACCOUNT)
    page.click("text=Compare and confirm")
    page.wait_for_load_state()
    checks("its identity is confirmed", "identity is confirmed" in page.inner_text("main"))
    page.goto(f"{base}/first-setup")
    page.click("text=Check your servers")
    page.wait_for_load_state()
    checks("it's ready to check", "Ready to check: web-1" in page.inner_text("main"))
    page.click("text=Start checking")
    page.wait_for_load_state()
    text = wait_for_check(page)
    checks("the real check finishes", "Finished" in text, text)
    checks("evidence is stored", bool(list((home / "evidence").rglob("*.age"))))
    page.goto(f"{base}/first-setup")
    checks("first setup says it's done", "Your first server is checked" in page.inner_text("main"))
    page.goto(f"{base}/")
    checks("the server has a result", "web-1" in page.inner_text("main"))


def main() -> int:
    top = Path(tempfile.mkdtemp())
    home = top / "fresh"
    env = {**os.environ, "CHECKER_HOME": str(home), "HOME": str(top), "PYTHONPATH": str(REPO)}
    env.pop("SSH_AUTH_SOCK", None)
    run("docker", "rm", "-f", CONTAINER, check=False)
    run("docker", "run", "-d", "--name", CONTAINER, "-p", f"127.0.0.1:{SSH_PORT}:22",
        "ubuntu:24.04", "sleep", "1800")  # fmt: skip
    server = None
    try:
        run("docker", "exec", CONTAINER, "bash", "-c", PREPARE)
        gateway = run(
            "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}",
            CONTAINER,
        ).stdout.strip()  # fmt: skip
        server, link, said = start_server(home, env)
        made = (home / "keys" / "evidence-identity.txt").exists()
        checks("an empty home sets itself up", made and any("BACK IT UP" in s for s in said), said)
        with sync_playwright() as play:
            browser = play.chromium.launch(
                executable_path=os.environ.get("CHROMIUM", "/usr/bin/chromium"),
                args=["--no-sandbox"],
            )
            page = browser.new_context().new_page()
            journey(page, f"http://127.0.0.1:{WEB_PORT}", link, home, gateway)
    finally:
        if server:
            server.terminate()
            server.wait(timeout=30)
        run("docker", "rm", "-f", CONTAINER, check=False)
    print("PASS" if all(results) else "FAIL", f"{sum(results)}/{len(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
