"""A real Caddy in front of the web interface, set up as docs/web.md says: a request gets in only
through it, a false address gets nowhere, and it can be reloaded with its admin port on a socket.
Needs caddy and curl. Run by hand. Its Caddy has its own folders and spare ports, doesn't touch the
machine's certificates or any other Caddy, and is stopped afterwards.

    python tests/integration/proxy_proof.py
"""

import contextlib
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

URL = "https://checker.localhost:18443"
DIRECT = "http://127.0.0.1:18767/login"
HOST = ("-H", "Host: checker.localhost")


def stop(process) -> None:
    if process is None:
        return
    process.terminate()
    try:
        process.wait(5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def this_machines_other_address() -> str | None:
    """One a client here can come from that isn't loopback, which counts as one for everyone."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("192.0.2.1", 9))  # sends nothing: only picks a way out
        except OSError:
            return None
        address = probe.getsockname()[0]
    return None if address.startswith("127.") else address


class Proof:
    def __init__(self, work: Path):
        self.work = work
        self.home = work / "home"
        self.home.mkdir(mode=0o700)
        self.config = work / "Caddyfile"
        self.caddy_env = {
            **os.environ,
            "XDG_DATA_HOME": str(work / "d"),
            "XDG_CONFIG_HOME": str(work / "c"),
            "HOME": str(work),
        }

    def write_config(self, secret: str | None) -> None:
        extra = f'header_up X-Checker-Proxy-Secret "{secret}"' if secret else ""
        self.config.write_text(
            f"{{\n admin unix/{self.work}/admin.sock\n skip_install_trust\n"
            " auto_https disable_redirects\n http_port 18080\n https_port 18443\n}\n"
            "checker.localhost:18443 {\n tls internal\n"
            f" reverse_proxy 127.0.0.1:18767 {{\n  {extra}\n }}\n}}\n"
        )

    def caddy(self, *args):
        return ["caddy", *args, "--config", str(self.config), "--adapter", "caddyfile"]

    def curl(self, url, *args, reach="127.0.0.1"):
        jar, body = str(self.work / "jar"), str(self.work / "body")
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "curl",
                "-sk",
                "--max-time",
                "8",
                "--resolve",
                f"checker.localhost:18443:{reach}",
                "-o",
                body,
                "-w",
                "%{http_code}",
                "-c",
                jar,
                "-b",
                jar,
                *args,
                url,
            ],
            capture_output=True,
            text=True,
        )
        return result.stdout

    def wait_until(self, code: str) -> None:
        for _ in range(40):
            if self.curl(URL + "/login") == code:
                return
            time.sleep(0.25)
        raise SystemExit(f"never answered {code}")

    def attempts(self) -> list:
        database = sqlite3.connect(self.home / "web.db")
        try:
            return database.execute("select username, address from web_loginattempt").fetchall()
        finally:
            database.close()


def run(proof: Proof) -> None:
    server = caddy = None
    try:
        server = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "checker",
                "web",
                "--bind",
                "127.0.0.1:18767",
                "--public-url",
                URL,
            ],
            env={**os.environ, "CHECKER_HOME": str(proof.home)},
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        said = []
        for line in server.stdout:
            said.append(line.rstrip())
            if " is at " in line:
                break
        secret_file = proof.home / "keys/web-proxy-secret.txt"
        secret = secret_file.read_text().strip()
        assert secret not in "\n".join(said)
        assert secret_file.stat().st_mode & 0o777 == 0o600

        proof.write_config(None)
        caddy = subprocess.Popen(  # noqa: S603
            proof.caddy("run"),
            env=proof.caddy_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proof.wait_until("403")
        print("A proxy without the secret is refused.")

        proof.write_config(secret)
        subprocess.run(proof.caddy("reload"), env=proof.caddy_env, check=True, capture_output=True)  # noqa: S603
        proof.wait_until("200")
        print("Reloaded through its admin socket, a proxy with the secret gets in.")

        address = this_machines_other_address()
        reach = address or "127.0.0.1"
        assert proof.curl(URL + "/login", reach=reach) == "200"
        token = re.search(
            r'name="csrfmiddlewaretoken" value="([^"]+)"', (proof.work / "body").read_text()
        ).group(1)
        fields = {"username": "jo", "password": "wrong", "csrfmiddlewaretoken": token}
        code = proof.curl(
            URL + "/login",
            "-H",
            "X-Forwarded-For: 198.51.100.66",
            "-H",
            "X-Checker-Proxy-Secret: forged",
            "-H",
            f"Referer: {URL}/login",
            "-d",
            urllib.parse.urlencode(fields),
            reach=reach,
        )
        assert code == "403", code
        time.sleep(0.2)
        assert proof.attempts() == [("jo", reach)], proof.attempts()
        print(f"A client's forged address and secret count for nothing: recorded as {reach}.")

        forged = ("-H", "X-Forwarded-For: 198.51.100.77")
        assert proof.curl(DIRECT, *HOST) == "403"
        assert proof.curl(DIRECT, *HOST, *forged) == "403"
        assert proof.curl(DIRECT, *HOST, "-H", "X-Checker-Proxy-Secret: nope") == "403"
        assert proof.curl(DIRECT, *HOST, *forged, "-d", "username=jo&password=x") == "403"
        assert len(proof.attempts()) == 1, proof.attempts()
        print("Connecting directly to the port is refused, and leaves no trace.")
    finally:
        with contextlib.suppress(Exception):
            stop(caddy)
        with contextlib.suppress(Exception):
            stop(server)


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="cc"))  # short: a socket path has a limit
    try:
        run(Proof(work))
    finally:
        shutil.rmtree(work, ignore_errors=True)  # it holds the secret


if __name__ == "__main__":
    main()
