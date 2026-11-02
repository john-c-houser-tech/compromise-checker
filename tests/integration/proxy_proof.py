"""A real Caddy in front of the web interface: a request gets in only through it, and a false
address gets nowhere. Needs caddy and curl. Run by hand. Its Caddy has its own folders and spare
ports, turns off its admin port, and doesn't touch the machine's certificates or any other Caddy.

    python tests/integration/proxy_proof.py
"""

import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

work = Path(tempfile.mkdtemp(prefix="cc"))  # short: a socket path has a limit
home = work / "home"
home.mkdir(mode=0o700)
env = {**os.environ, "CHECKER_HOME": str(home)}
URL = "https://checker.localhost:18443"
server = subprocess.Popen(
    [sys.executable, "-m", "checker", "web", "--bind", "127.0.0.1:18767", "--public-url", URL],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
)
said = []
for line in server.stdout:
    said.append(line.rstrip())
    if " is at " in line:
        break
print("\n".join(line for line in said if "/setup/" not in line))
secret = (home / "keys/web-proxy-secret.txt").read_text().strip()
assert secret not in "\n".join(said)


def caddy(with_secret):
    extra = f'header_up X-Checker-Proxy-Secret "{secret}"' if with_secret else ""
    cfg = work / "Caddyfile"
    cfg.write_text(
        "{\n admin off\n skip_install_trust\n auto_https disable_redirects\n"
        " http_port 18080\n https_port 18443\n}\n"
        "checker.localhost:18443 {\n tls internal\n"
        f" reverse_proxy 127.0.0.1:18767 {{\n  {extra}\n }}\n}}\n"
    )
    return subprocess.Popen(  # noqa: S603
        [  # noqa: S607
            "caddy",
            "run",
            "--config",
            str(cfg),
            "--adapter",
            "caddyfile",
        ],
        env={
            **os.environ,
            "XDG_DATA_HOME": str(work / "d"),
            "XDG_CONFIG_HOME": str(work / "c"),
            "HOME": str(work),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def curl(url, *args):
    r = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "curl",
            "-sk",
            "--max-time",
            "8",
            "--resolve",
            "checker.localhost:18443:127.0.0.1",
            "-o",
            str(work / "body"),
            "-w",
            "%{http_code}",
            "-c",
            str(work / "jar"),
            "-b",
            str(work / "jar"),
            *args,
            url,
        ],
        capture_output=True,
        text=True,
    )
    return r.stdout


def csrf():
    body = (work / "body").read_text()
    return re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', body).group(1)


def wait(p):
    for _ in range(40):
        if curl(URL + "/login") != "000":
            return
        time.sleep(0.25)
    raise SystemExit("caddy didn't answer")


DIRECT = "http://127.0.0.1:18767/login"
try:
    p = caddy(False)
    wait(p)
    assert curl(URL + "/login") == "403", "a proxy without the secret must be refused"
    print("A proxy without the secret is refused.")
    p.terminate()
    p.wait(5)
    p = caddy(True)
    wait(p)
    assert curl(URL + "/login") == "200"
    print("A proxy with the secret gets in.")
    token = csrf()
    # A client tries to claim both a forwarded address and a secret; it comes from 127.0.0.2.
    code = curl(
        URL + "/login",
        "--interface",
        "127.0.0.2",
        "-H",
        "X-Forwarded-For: 198.51.100.66",
        "-H",
        "X-Checker-Proxy-Secret: forged",
        "-H",
        f"Referer: {URL}/login",
        "-d",
        urllib.parse.urlencode(
            {"username": "jo", "password": "wrong", "csrfmiddlewaretoken": token}
        ),
    )
    assert code == "403", code
    time.sleep(0.2)
    rows = (
        sqlite3.connect(home / "web.db")
        .execute("select username, address from web_loginattempt")
        .fetchall()
    )
    assert rows == [("jo", "127.0.0.2")], rows
    print("A forged address and secret from a client count for nothing: recorded", rows)
    assert curl(DIRECT, "-H", "Host: checker.localhost") == "403"
    assert (
        curl(DIRECT, "-H", "Host: checker.localhost", "-H", "X-Forwarded-For: 198.51.100.77")
        == "403"
    )
    assert (
        curl(DIRECT, "-H", "Host: checker.localhost", "-H", "X-Checker-Proxy-Secret: nope") == "403"
    )
    assert (
        curl(
            DIRECT,
            "-H",
            "Host: checker.localhost",
            "-H",
            "X-Forwarded-For: 198.51.100.77",
            "-d",
            "username=jo&password=x",
        )
        == "403"
    )
    rows = (
        sqlite3.connect(home / "web.db").execute("select count(*) from web_loginattempt").fetchone()
    )
    assert rows == (1,), rows
    print("Connecting directly to the port is refused, and leaves no trace.")
    assert (home / "keys/web-proxy-secret.txt").stat().st_mode & 0o777 == 0o600
    p.terminate()
    p.wait(5)
finally:
    server.terminate()
    server.wait(10)
