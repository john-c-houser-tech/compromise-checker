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
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography import x509
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


PLANTED = "/root/planted-code-ran"
PLANT = (
    f"mkdir -p /root/plant; for name in venv ensurepip json base64 re subprocess; do"
    f" echo \"open('{PLANTED}', 'w').close()\" | tee /root/plant/$name.py"
    f" > /root/release/$name.py; done"
)


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


def local(*words: str) -> subprocess.CompletedProcess:
    """A command from this machine, which plays someone elsewhere on the internet."""
    return subprocess.run(  # noqa: S603
        list(words), capture_output=True, text=True, timeout=120, check=False
    )


def served_certificate_issuer(name: str) -> str:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((name, 443), timeout=20) as raw:
        with context.wrap_socket(raw, server_hostname=name) as tls:
            der = tls.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der).issuer.rfc4514_string()


def prove_web(node: "Node", checks, distro: str) -> None:
    """The web address route, from a name that leads to the new server, with Let's Encrypt's
    test certificates. This machine plays someone using it from elsewhere."""
    address = node.address
    name = f"{address.replace('.', '-')}.sslip.io"
    laptop = node.out("echo ${SSH_CLIENT%% *}")
    install = "cd /root/release && umask 077 && sudo python3 -I install.py --from /root/release"

    done = node.run(f"{install} --web-address 203-0-113-9.sslip.io --test-certificates")
    checks(
        "a name pointing elsewhere is refused, with nothing changed",
        done.returncode == 1 and "points to 203.0.113.9" in done.stderr and untouched(node),
        done.stdout + done.stderr,
    )
    done = node.run(
        f"{install} --web-address nowhere-{os.urandom(4).hex()}.invalid --test-certificates"
        " --dns-wait-minutes 0.2"
    )
    checks(
        "a name that doesn't exist yet is waited for, then refused, with nothing changed",
        done.returncode == 1
        and "A record: nowhere-" in done.stdout
        and "still doesn't point anywhere" in done.stderr
        and untouched(node),
        done.stdout + done.stderr,
    )

    started = time.monotonic()
    done = node.run(
        f"{install} --web-address {name} --test-certificates --allow '{laptop}'", timeout=1500
    )
    print(f"[{distro}] install took {round(time.monotonic() - started)}s")
    checks("it installs with a web address", done.returncode == 0, done.stdout + done.stderr)
    checks(
        "and gets its certificate",
        f"installed at https://{name}" in done.stdout and "hasn't given it" not in done.stdout,
        done.stdout,
    )
    links = re.findall(rf"https://{re.escape(name)}/setup/\S+", done.stdout)
    checks("it hands over a link to the web address", len(links) == 1, done.stdout)
    if done.returncode or not links:
        print(node.out("journalctl -u compromise-checker-web -u apache2 -u httpd -n 80 --no-pager"))
        print(
            node.out("tail -n 60 /var/log/apache2/error.log /var/log/httpd/error_log 2>/dev/null")
        )
        return
    try:
        issuer = served_certificate_issuer(name)
    except OSError as exc:
        issuer = str(exc)
    checks("the certificate is Let's Encrypt's test one", "STAGING" in issuer, issuer)
    status = local(
        "curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"https://{name}/login"
    )
    checks("the sign-in page answers from elsewhere", status.stdout == "200", status.stdout)
    version = local(
        "curl",
        "-k",
        "--http2",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_version}",
        f"https://{name}/login",
    )
    checks("HTTP/2 is off", version.stdout == "1.1", version.stdout)
    plain = local(
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{redirect_url}",
        f"http://{name}/login",
    )
    checks(
        "plain http only redirects to https",
        plain.stdout == f"301 https://{name}/login",
        plain.stdout,
    )
    direct = local(
        "curl",
        "-s",
        "-m",
        "10",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        f"http://{address}:8088/login",
    )
    checks(
        "the tool itself can't be reached from elsewhere",
        direct.stdout in ("000", ""),
        direct.stdout,
    )
    secretless = status_of_with(node, "http://127.0.0.1:8088/login", f"-H 'Host: {name}'")
    checks(
        "on the machine, nothing gets past without Apache's secret", secretless == "403", secretless
    )
    outside = node.out(f"curl -k -s -o /dev/null -w '%{{http_code}}' https://{name}/login")
    checks("an address outside the limit is turned away", outside == "403", outside)
    checks(
        "Apache's settings, which hold the secret, are private",
        node.out(
            "stat -c '%a %U' /etc/apache2/sites-available/compromise-checker.conf"
            " /etc/httpd/conf.d/compromise-checker.conf 2>/dev/null"
        )
        == "600 root",
    )
    checks(
        "the daily reload is set",
        node.out("systemctl is-enabled compromise-checker-certificate-reload.timer") == "enabled",
    )
    if distro.startswith("rocky"):
        labelled = node.out("semanage port -l | grep -E '^http_port_t'")
        checks(
            "SELinux lets Apache reach the tool's port, and no more", "8088" in labelled, labelled
        )

    # --- Someone elsewhere makes the first account and signs in, through Apache -----------------
    jar = Path(tempfile.mkdtemp()) / "jar"
    password = "proof-password-" + os.urandom(8).hex()

    def token(url: str) -> str:
        page = local("curl", "-k", "-s", "-c", str(jar), "-b", str(jar), url).stdout
        found = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page)
        return found.group(1) if found else ""

    def post(url: str, *fields: str) -> str:
        words = [
            "curl",
            "-k",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-c",
            str(jar),
            "-b",
            str(jar),
        ]
        words += ["-H", f"Referer: https://{name}/"]
        for field in fields:
            words += ["--data-urlencode", field]
        return local(*words, url).stdout

    made = post(
        links[0],
        f"csrfmiddlewaretoken={token(links[0])}",
        "username=proofadmin",
        f"password={password}",
        f"password2={password}",
    )
    checks("the first account can be made from elsewhere", made == "302", made)
    jar.unlink(missing_ok=True)
    login = f"https://{name}/login"
    signed = post(
        login, f"csrfmiddlewaretoken={token(login)}", "username=proofadmin", f"password={password}"
    )
    checks("and that account can sign in", signed == "302", signed)

    done = node.run(f"{install} --web-address {name} --test-certificates --allow '{laptop}'")
    checks(
        "running it again changes nothing",
        done.returncode == 0 and "already installed" in done.stdout,
        done.stdout + done.stderr,
    )
    node.run("systemctl reboot")
    time.sleep(15)
    node.wait()
    deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < deadline:
        status = local("curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}", login).stdout
        if status == "200":
            break
        time.sleep(3)
    checks("after a reboot the web address is back", status == "200", status)
    selinux = node.out("getenforce 2>/dev/null") or "not on this system"
    print(f"[{distro}] SELinux: {selinux}")
    if distro.startswith("rocky"):
        checks("SELinux is enforcing, so this means something", selinux == "Enforcing", selinux)
    found = denials(node)
    checks("SELinux refused nothing", not found, found)


def status_of_with(node: "Node", url: str, extra: str) -> str:
    return node.out(f"curl -s -o /dev/null -w '%{{http_code}}' {extra} '{url}'")


def prove(
    api,
    distro: str,
    region: str,
    release: Path,
    work: Path,
    route: str = "local",
    keep_minutes: float = 0,
) -> list:
    results = []

    def checks(what: str, good: bool, detail: object = "") -> None:
        results.append((what, good, detail))
        shown = f" (...{str(detail)[-1500:]})" if detail and not good else ""
        print(f"[{distro} {route}] {'PASS' if good else 'FAIL'} {what}{shown}")

    place = work / f"{distro}-{route}"
    place.mkdir()
    key = place / "key"
    subprocess.run(  # noqa: S603
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],  # noqa: S607
        check=True,
    )
    label = proof.run_label(distro)
    public = key.with_suffix(".pub").read_text().strip()
    try:
        made = api.create(label, proof.IMAGES[distro], region, public)
    except Exception:  # an answer lost on the way may still have made it: look before trying again
        time.sleep(15)
        made = api.find(label) or api.create(label, proof.IMAGES[distro], region, public)
    try:
        node = Node(made["ipv4"][0], key, place / "known")
        node.wait()
        node.copy(release, "/root/release")
        if route == "web":
            prove_web(node, checks, distro)
            return results

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

        # --- Planted code, run without -I, stops there as the missing folder says -----------------
        node.run(PLANT)
        done = node.run(
            "cd /root/plant && python3 /root/release/install.py --from /root/nowhere --new-machine"
        )
        checks(
            "planted code beside it doesn't run, even without -I",
            done.returncode == 1
            and "Couldn't read" in done.stderr
            and node.out(f"ls {PLANTED} 2>/dev/null") == "",
            done.stdout + done.stderr,
        )

        # --- The install, as the documented line runs it, under a strict umask --------------------
        started = time.monotonic()
        done = node.run(
            "cd /root/release && umask 077 && sudo python3 -I install.py --from /root/release"
        )
        took = round(time.monotonic() - started)
        print(f"[{distro}] install took {took}s")
        checks("it installs", done.returncode == 0, done.stdout + done.stderr)
        checks("no planted code ran", node.out(f"ls {PLANTED} 2>/dev/null") == "")
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
        found = node.run(
            f"cd / && runuser -u {ACCOUNT} -- find {PROGRAM}/ -writable -not -type l -print -quit"
        )
        checks(
            "the tool can't change its own program",
            found.returncode == 0 and found.stdout.strip() == "",
            found.stdout + found.stderr,
        )
        checks("sleep is off", node.out("systemctl is-enabled suspend.target") == "masked")

        # --- A new link -------------------------------------------------------------------------
        again = _LINK_LINE.findall(node.out(LINK))
        checks("the link can be shown again", len(again) == 1)
        checks("the new one opens", status_of(node, again[0]) == "200")
        checks("the old one stops working", status_of(node, links[0]) != "200")
        refused = node.run(f"su -s /bin/sh nobody -c {LINK}")
        checks(
            "the command needs an administrator",
            refused.returncode == 1 and "Run this with sudo" in refused.stderr,
            refused.stderr,
        )

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
        selinux = node.out("getenforce 2>/dev/null") or "not on this system"
        print(f"[{distro}] SELinux: {selinux}")
        if distro.startswith("rocky"):
            checks("SELinux is enforcing, so this means something", selinux == "Enforcing", selinux)

        # --- What the page has to be able to do -------------------------------------------------
        pdf = node.run(
            f"systemd-run --wait --pipe {limits} {PROGRAM}/current/bin/python -c"
            " \"from weasyprint import HTML; print(len(HTML(string='<p>x</p>').write_pdf()))\""
        )
        checks(
            "a PDF can be made inside the limits",
            pdf.returncode == 0 and pdf.stdout.strip().isdigit(),
            pdf.stdout + pdf.stderr,
        )
        password = "proof-password-" + os.urandom(8).hex()
        form = (
            "curl -s -c /root/jar -b /root/jar {url} | "
            'sed -n \'s/.*name="csrfmiddlewaretoken" value="\\([^"]*\\)".*/\\1/p\' | head -1'
        )
        token = node.out(form.format(url=f"'{after[0]}'"))
        checks("the setup page has its form", bool(token), token)
        created = node.out(
            f"curl -s -o /dev/null -w '%{{http_code}}' -c /root/jar -b /root/jar"
            f" --data-urlencode csrfmiddlewaretoken={token} -d username=proofadmin"
            f" -d password={password} -d password2={password} '{after[0]}'"
        )
        checks("the first account can be made", created == "302", created)
        node.run("rm -f /root/jar")
        token = node.out(form.format(url="http://127.0.0.1:8088/login"))
        signed_in = node.out(
            f"curl -s -o /dev/null -w '%{{http_code}}' -c /root/jar -b /root/jar"
            f" --data-urlencode csrfmiddlewaretoken={token} -d username=proofadmin"
            f" -d password={password} http://127.0.0.1:8088/login"
        )
        checks("that account can sign in", signed_in == "302", signed_in)
        done = node.run(LINK)
        checks(
            "no link is made once there's an account",
            done.returncode == 1 and "already an account" in done.stdout,
            done.stdout + done.stderr,
        )
        checks("the spent link stops working", status_of(node, after[0]) != "200")
        found = denials(node)  # last, to cover all of the above
        checks("SELinux refused nothing", not found, found)
    finally:
        if keep_minutes:
            where = f"ssh -i {key} root@{made['ipv4'][0]}"
            print(f"[{distro} {route}] kept for {keep_minutes} minutes: {where}")
            time.sleep(keep_minutes * 60)
        api.delete(made["id"])
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--distro", nargs="+", default=SYSTEMS, choices=[*SYSTEMS, "all"])
    parser.add_argument("--region", default="us-sea")
    parser.add_argument(
        "--route",
        nargs="+",
        default=["local", "web"],
        choices=["local", "web"],
        help="from this machine only, or with a web address",
    )
    parser.add_argument(
        "--keep-minutes", type=float, default=0, help="keep each server this long, to look at it"
    )
    parser.add_argument("--work", type=Path, help="a folder to keep the servers' keys in")
    arguments = parser.parse_args()

    def stop(number, _frame):  # so the servers are still deleted when this is killed
        raise SystemExit(128 + number)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    systems = SYSTEMS if "all" in arguments.distro else arguments.distro
    api = proof.Linode(proof.linode_token())
    proof.sweep(api)
    try:
        with tempfile.TemporaryDirectory(prefix="cc-install-", dir=arguments.work) as work:
            release = build_release(Path(work))
            sign_release(release)
            runs = [(system, route) for system in systems for route in arguments.route]
            with ThreadPoolExecutor(len(runs)) as pool:
                futures = {
                    f"{system} {route}": pool.submit(
                        prove,
                        api,
                        system,
                        arguments.region,
                        release,
                        Path(work),
                        route,
                        arguments.keep_minutes,
                    )
                    for system, route in runs
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
