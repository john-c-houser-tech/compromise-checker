#!/usr/bin/env python3
"""Install Compromise Checker on a machine of its own (installation plan, I.2).

    sudo python3 -I install.py

This one file is all that's needed, and it only uses what comes with Python, because nothing from
the release may run until the release's signature has been checked. Its version and key are fixed
when a release is built, so it can't be given another release, or one signed by anyone else. That
protects what it installs, not this file: it's the published hash of this file that does that.

It works with Python 3.9, the oldest a supported system starts with. The tool itself runs on a newer
Python that this script installs from the system's own packages."""

import sys

# Python looks for code beside a script first, and this runs as root: a json.py planted in the
# folder would run before anything could be checked. So nothing else is imported until that's shut.
if __name__ == "__main__" and not (sys.flags.isolated or getattr(sys.flags, "safe_path", False)):
    del sys.path[0]

import argparse  # noqa: E402
import base64  # noqa: E402
import contextlib  # noqa: E402
import hashlib  # noqa: E402
import http.client  # noqa: E402
import http.server  # noqa: E402
import ipaddress  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import pwd  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402
import subprocess  # noqa: E402, S404
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402
from collections.abc import Callable  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import NamedTuple, Optional  # noqa: E402

VERSION = "@VERSION@"  # fixed when a release is built
RELEASE_KEY = "RWSrQekC3RodNJBjEJsAevGCUsudzjSUpTcGCiIyE/Cj1ISXhnqZOx95"
DOWNLOADS = "https://github.com/john-c-houser-tech/compromise-checker/releases/download"

MANIFEST = "release.json"
SIGNATURE = "release.json.minisig"
REQUIREMENTS = "requirements.lock"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 4096
MAX_COMMENT = 1024
MAX_FILE_BYTES = 256 * 1024 * 1024

ACCOUNT = "compromise-checker"
PROGRAM = Path("/opt/compromise-checker")
ACCOUNT_HOME = Path("/var/lib/compromise-checker")
DATA = ACCOUNT_HOME / "data"
UNIT = "compromise-checker-web.service"
UNIT_FILE = Path("/etc/systemd/system") / UNIT
LINK_COMMAND = Path("/usr/local/sbin/compromise-checker-link")
FINISHED = (
    PROGRAM / "installed"
)  # written last, so an install that stopped part way can be run again
PORT = 8088
ADDRESS = f"http://127.0.0.1:{PORT}"
GO_AHEAD = "I know this machine is in use"
SLEEP_UNITS = ("sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target")
PAGE_SECONDS = 180
_CHUNK = 1024 * 1024
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PLAIN_ACCOUNTS = {"nobody", "root", "ubuntu", "rocky", "cloud-user", "linode"}
_NO_LOGIN = ("nologin", "false", "sync", "shutdown", "halt")
# What a new system already has open: rpcbind, and systemd holding Cockpit's port until it's used.
# These say nothing about the machine being in use. The firewall step is what closes them.
# systemd also holds port 22 where SSH starts on demand.
_ON_A_NEW_SYSTEM = {("rpcbind", "111"), ("systemd", "9090"), ("systemd", "22")}


class Stop(Exception):
    """Why the install can't go on, in words for the person running it."""


# --- Signatures: Ed25519 (RFC 8032) as minisign uses it ------------------------------------------
# Python's standard library has no Ed25519, and minisign isn't in every system's package sources.
# Only checking is done here, of public data with a public key, so there's nothing secret to protect
# from timing.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a: tuple, b: tuple) -> tuple:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e = (y1 - x1) * (y2 - x2) % _P
    f = (y1 + x1) * (y2 + x2) % _P
    g = 2 * t1 * t2 * _D % _P
    h = 2 * z1 * z2 % _P
    i, j, k, m = f - e, h - g, h + g, f + e
    return (i * j % _P, k * m % _P, j * k % _P, i * m % _P)


def _times(n: int, point: tuple) -> tuple:
    total = (0, 1, 1, 0)
    while n:
        if n & 1:
            total = _add(total, point)
        point = _add(point, point)
        n >>= 1
    return total


def _same(a: tuple, b: tuple) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _decode_point(raw: bytes) -> Optional[tuple]:
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    square = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(square, (_P + 3) // 8, _P)
    if (x * x - square) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - square) % _P:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_B_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE = _decode_point(_B_Y.to_bytes(32, "little"))


def ed25519_good(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    r_raw, s_raw = signature[:32], signature[32:]
    s = int.from_bytes(s_raw, "little")
    r_point, a_point = _decode_point(r_raw), _decode_point(public)
    if s >= _L or r_point is None or a_point is None or _BASE is None:
        return False
    digest = hashlib.sha512(r_raw + public + message).digest()
    h = int.from_bytes(digest, "little") % _L
    return _same(_times(s, _BASE), _add(r_point, _times(h, a_point)))


def _b64(text: bytes, what: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except ValueError:
        raise Stop(f"The release's {what} is damaged.") from None


def check_signature(data: bytes, signature: bytes, key_line: str) -> None:
    """A minisign signature of `data` by `key_line`, or Stop. As checker/packs/signing.py checks
    one, trusted comment included, without its dependency on the release being checked."""
    key = base64.b64decode(key_line, validate=True)
    if len(key) != 42 or key[:2] != b"Ed":
        raise Stop("This installer's key is damaged. Download it again.")
    if len(signature) > MAX_SIGNATURE_BYTES:
        raise Stop("The release's signature file is too large.")
    lines = [line.rstrip(b"\r") for line in signature.split(b"\n")]
    if lines and lines[-1] == b"":
        lines = lines[:-1]
    if (
        len(lines) != 4
        or not lines[0].startswith(b"untrusted comment:")
        or not lines[2].startswith(b"trusted comment: ")
    ):
        raise Stop("The release's signature file isn't in the right form.")
    blob = _b64(lines[1], "signature")
    whole = _b64(lines[3], "signature")
    comment = lines[2][len(b"trusted comment: ") :]
    if len(blob) != 74 or blob[:2] != b"ED" or len(whole) != 64 or len(comment) > MAX_COMMENT:
        raise Stop("The release's signature file isn't in the right form.")
    if blob[2:10] != key[2:10]:
        raise Stop("This release wasn't signed with the release key. It wasn't installed.")
    prehashed = hashlib.blake2b(data, digest_size=64).digest()
    if not ed25519_good(key[10:], prehashed, blob[10:]):
        raise Stop("The release's signature doesn't match. It wasn't installed.")
    if not ed25519_good(key[10:], blob[10:] + comment, whole):
        raise Stop("The release's signature has been altered. It wasn't installed.")


class Listed(NamedTuple):
    sha256: str
    size: int


def read_manifest(data: bytes, version: str) -> dict:
    """What the signed list says, once its signature has been checked. Only what this needs is
    looked at closely: the signature already says who wrote it."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise Stop("The release's list of files is too large.")
    try:
        manifest = json.loads(data)
    except ValueError:
        raise Stop("The release's list of files can't be read.") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise Stop("This release's format is one this installer can't read. Get a newer installer.")
    if manifest.get("version") != version:
        raise Stop(
            f"This is an installer for version {version}, and it was offered version"
            f" {manifest.get('version')}. It wasn't installed."
        )
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise Stop("The release's list of files can't be read.")
    listed = {}
    for name, entry in files.items():
        if not _FILE_NAME.fullmatch(name) or not isinstance(entry, dict):
            raise Stop("The release's list of files can't be read.")
        sha256, size = entry.get("sha256"), entry.get("size")
        size_good = isinstance(size, int) and not isinstance(size, bool)
        if not (isinstance(sha256, str) and _SHA256.fullmatch(sha256) and size_good):
            raise Stop("The release's list of files can't be read.")
        if not 0 <= size <= MAX_FILE_BYTES:
            raise Stop(f"The release says {name} is an impossible size.")
        listed[name] = Listed(sha256, size)
    for needed in (wheel_name(version), REQUIREMENTS):
        if needed not in listed:
            raise Stop(f"The release doesn't list {needed}.")
    return listed


def wheel_name(version: str) -> str:
    return f"checker-{version}-py3-none-any.whl"


# --- Getting the release -------------------------------------------------------------------------


def _read_url(url: str, limit: int) -> bytes:
    if not url.startswith("https://"):
        raise Stop(f"Refusing to download over an unprotected connection: {url}")
    try:
        with urllib.request.urlopen(url, timeout=60) as answer:  # noqa: S310
            data = answer.read(limit + 1)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        raise Stop(f"Couldn't download {url}: {exc}. Check this machine's internet.") from None
    if len(data) > limit:
        raise Stop(f"{url} is larger than it should be.")
    return data


def _read_local(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError as exc:
        raise Stop(f"Couldn't read {path}: {exc}") from None
    if len(data) > limit:
        raise Stop(f"{path} is larger than it should be.")
    return data


def fetcher(source: Optional[Path], version: str) -> Callable[[str, int], bytes]:
    if source is not None:
        return lambda name, limit: _read_local(source / name, limit)
    return lambda name, limit: _read_url(f"{DOWNLOADS}/v{version}/{name}", limit)


def get_release(
    fetch: Callable[[str, int], bytes], version: str, key_line: str, into: Path
) -> dict:
    """Into a private folder, nothing kept that hasn't been checked: first the signature, then each
    file against the hash in what was signed."""
    data = fetch(MANIFEST, MAX_MANIFEST_BYTES)
    check_signature(data, fetch(SIGNATURE, MAX_SIGNATURE_BYTES), key_line)
    listed = read_manifest(data, version)
    for name, entry in listed.items():
        content = fetch(name, entry.size)
        if len(content) != entry.size or hashlib.sha256(content).hexdigest() != entry.sha256:
            raise Stop(f"{name} isn't the file that was signed. It wasn't installed.")
        (into / name).write_bytes(content)
    return listed


# --- This machine --------------------------------------------------------------------------------


class System(NamedTuple):
    name: str
    python: str  # the command for a Python this tool can run on
    packages: tuple
    install: tuple  # the command that installs packages


_PANGO_APT = ("libpango-1.0-0", "libpangoft2-1.0-0", "libharfbuzz-subset0")
_APT = ("apt-get", "install", "-y", "-qq")
APT_WAIT_SECONDS = 300
_DNF = ("dnf", "install", "-y", "-q")
SYSTEMS = {
    ("ubuntu", "24.04"): System(
        "Ubuntu 24.04",
        "python3",
        ("python3-venv", "iproute2", "ufw", "unattended-upgrades", *_PANGO_APT),
        _APT,
    ),
    ("ubuntu", "26.04"): System(
        "Ubuntu 26.04",
        "python3",
        ("python3-venv", "iproute2", "ufw", "unattended-upgrades", *_PANGO_APT),
        _APT,
    ),
    ("rocky", "9"): System(
        "Rocky Linux 9",
        "python3.12",
        ("python3.12", "iproute", "firewalld", "dnf-automatic", "pango", "harfbuzz"),
        _DNF,
    ),
    ("rocky", "10"): System(
        "Rocky Linux 10",
        "python3",
        ("iproute", "firewalld", "dnf-automatic", "pango", "harfbuzz"),
        _DNF,
    ),
}


def os_release(text: str) -> dict:
    found = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z_]+)=\"?([^\"]*)\"?", line.strip())
        if match:
            found[match.group(1)] = match.group(2)
    return found


def which_system(text: str) -> System:
    release = os_release(text)
    distribution = release.get("ID", "")
    version = release.get("VERSION_ID", "")
    if distribution == "rocky":
        version = version.split(".")[0]
    system = SYSTEMS.get((distribution, version))
    if system is None:
        shown = release.get("PRETTY_NAME") or "this system"
        raise Stop(
            f"Compromise Checker can only be installed on Ubuntu 24.04 or 26.04, or Rocky Linux 9"
            f" or 10, and this is {shown}. Close relatives of those aren't supported yet. Nothing"
            " has been changed."
        )
    return system


class Sign(NamedTuple):
    what: str
    matters: str


def _listeners(ss_output: str) -> list:
    """(address, port, program) for each listening TCP socket in `ss -Hltnp`."""
    found = []
    for line in ss_output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        address, _, port = parts[3].rpartition(":")
        program = re.search(r'users:\(\("([^"]+)"', line)
        found.append((address.strip("[]"), port, program.group(1) if program else "unknown"))
    return found


def _loopback(address: str) -> bool:
    return address.startswith("127.") or address == "::1"


def holders(ss_output: str, port: int) -> set:
    """The process numbers listening on `port`."""
    found = set()
    for line in ss_output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3].rpartition(":")[2] == str(port):
            found.update(int(number) for number in re.findall(r"pid=(\d+)", line))
    return found


def port_in_use(ss_output: str, port: int) -> Optional[str]:
    """Which program holds `port`, on any address this tool would need."""
    for address, held, program in _listeners(ss_output):
        if held == str(port) and (_loopback(address) or address in ("0.0.0.0", "*", "::")):  # noqa: S104
            return program
    return None


def signs_of_use(
    ss_output: str, passwd: str, invoker: Optional[str], ours: frozenset = frozenset()
) -> list:
    """What suggests this machine does something else. Things only reachable from the machine
    itself, and the SSH that's probably how the person got here, aren't counted. Nor is the person,
    or an account a cloud provider makes. It's a nudge and not a guarantee: only TCP is looked at,
    since a normal desktop has UDP open anyway, and only accounts in /etc/passwd."""
    signs = []
    seen = set()
    for address, port, program in _listeners(ss_output):
        if _loopback(address) or program == "sshd" or (program, port) in _ON_A_NEW_SYSTEM:
            continue
        if (program, port) in ours:  # left by an earlier run of this installer
            continue
        if (program, port) in seen:  # the same thing on IPv4 and IPv6
            continue
        seen.add((program, port))
        signs.append(
            Sign(
                f"{program} is accepting connections on port {port}",
                "If other people use it, they could be cut off once this machine is locked down,"
                " and a problem in it could expose this tool's keys.",
            )
        )
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, uid, shell = parts[0], parts[2], parts[6]
        if not uid.isdigit() or int(uid) < 1000 or name == invoker or name in _PLAIN_ACCOUNTS:
            continue
        if shell.rsplit("/", 1)[-1] in _NO_LOGIN:
            continue
        signs.append(
            Sign(
                f"{name} has an account that can log in",
                "Anyone else who can log in here may be able to reach the keys this tool holds.",
            )
        )
    return signs


def _run(*command: str, check: bool = True, **more) -> subprocess.CompletedProcess:
    """From a folder of no consequence: Python looks for code in the current one too."""
    more.setdefault("cwd", "/")
    done = subprocess.run(  # noqa: S603
        command, check=False, text=True, errors="replace", capture_output=True, **more
    )
    if check and done.returncode:
        raise Stop(
            f"This step failed: {' '.join(command)}\n{done.stdout}{done.stderr}\n"
            "The machine may be part way through the install. Run this installer again to continue."
        )
    return done


def web_unit(uid: int, public_address: Optional[str] = None) -> str:
    """The web interface, as the tool's own account, able to write only to the tool's own folder.
    The running user manager is what its Check every day page sets the daily timer with. That's
    why people's homes are closed off by name: ProtectHome would hide /run/user too. With a public
    address it still listens only on this machine, and Apache stands in front of it."""
    command = f"{PROGRAM}/current/bin/checker web"
    if public_address:
        command += f" --public-url {public_address}"
    return f"""[Unit]
Description=Compromise Checker web interface
After=network.target user@{uid}.service
Wants=user@{uid}.service

[Service]
User={ACCOUNT}
Group={ACCOUNT}
Environment=CHECKER_HOME={DATA}
Environment=XDG_RUNTIME_DIR=/run/user/{uid}
UMask=0077
ExecStart={command}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={ACCOUNT_HOME}
InaccessiblePaths=-/home -/root
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
"""


def link_command(address: str = ADDRESS) -> str:
    """Shows a new first-setup link. Any before it stops working, so only the newest one is live."""
    return f"""#!/bin/sh
if [ "$(id -u)" != 0 ]; then
    echo "Run this with sudo: sudo {LINK_COMMAND}" >&2
    exit 1
fi
cd / || exit 1
# In a session of its own, without this terminal, so what runs as the tool's account can't type
# into it or read from it. What it printed is shown afterwards, as plain text and nothing else.
out=$(setsid --wait runuser -u {ACCOUNT} -- env CHECKER_HOME={DATA} \\
    {PROGRAM}/current/bin/checker web-setup-link --address {address} < /dev/null 2>&1)
code=$?
printf '%s\\n' "$out" | tr -cd '[:print:]\\n'
exit $code
"""


def say(text: str) -> None:
    print(text, flush=True)


def installed() -> bool:
    return FINISHED.exists()


def ask_about_use(signs: list, answer: Callable[[], str]) -> None:
    say("\nThis machine looks like it's already being used for something else:\n")
    for sign in signs:
        say(f"  - {sign.what}.\n    {sign.matters}")
    say(
        "\nCompromise Checker holds keys that act as an administrator on every server it checks,"
        "\nso it should have a machine to itself. This run hasn't changed anything."
        f"\n\nTo go ahead anyway, type exactly: {GO_AHEAD}\nTo stop, press Enter.\n"
    )
    try:
        typed = answer()
    except (EOFError, KeyboardInterrupt):
        typed = ""
    if typed.strip() != GO_AHEAD:
        raise Stop("Stopped. This run changed nothing.")


def run_apt(command: tuple, env: dict, seconds: float = APT_WAIT_SECONDS) -> None:
    """A new machine's own updates often hold apt's locks for its first minutes. apt's own option
    for waiting only covers one of them, so this waits for all of them."""
    deadline = time.monotonic() + seconds
    while True:
        done = _run(*command, check=False, env={**env, "LC_ALL": "C"})  # so it's in English here
        if done.returncode == 0:
            return
        if "Could not get lock" not in done.stderr or time.monotonic() > deadline:
            _run(*command, env={**env, "LC_ALL": "C"})  # says what went wrong, if it still does
            return
        time.sleep(10)


def _install_packages(system: System, more: tuple = ()) -> None:
    say(f"Installing what the tool needs from {system.name}'s own packages.")
    if system.install is _APT:
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        run_apt(("apt-get", "update", "-qq"), env)
        run_apt((*system.install, *system.packages, *more), env)
    else:
        _run(*system.install, *system.packages, *more)


def account_problem(uid: int, home: str, shell: str) -> Optional[str]:
    """An account by this name that this installer didn't make would be handed the tool's keys, so
    it has to look just like one it did."""
    if uid == 0:
        return "it's an administrator"
    if home != str(ACCOUNT_HOME):
        return f"its home is {home}, not {ACCOUNT_HOME}"
    if shell.rsplit("/", 1)[-1] not in _NO_LOGIN:
        return f"it can log in, with {shell}"
    return None


def _make_account() -> int:
    try:
        found = pwd.getpwnam(ACCOUNT)
    except KeyError:
        found = None
    if found is not None:
        problem = account_problem(found.pw_uid, found.pw_dir, found.pw_shell)
        if problem:
            raise Stop(
                f"There's already an account called {ACCOUNT}, and {problem}. This tool's keys"
                " shouldn't be handed to it, so the install has stopped. Please look at it."
            )
        return found.pw_uid
    say(f"Making an account for the tool, {ACCOUNT}, that nobody can log in to.")
    _run(
        "useradd",
        "--system",
        "--user-group",
        "--home-dir",
        str(ACCOUNT_HOME),
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        "--comment",
        "Compromise Checker",
        ACCOUNT,
    )
    return pwd.getpwnam(ACCOUNT).pw_uid


def _own_folder(folder: Path, uid: int, gid: int) -> None:
    """The tool's account could have changed what's here if an earlier install got that far, and
    this runs as root: a link would hand over whatever it points to."""
    try:
        folder.mkdir(mode=0o700, exist_ok=True)
        opened = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (OSError, FileExistsError):
        raise Stop(
            f"{folder} isn't a plain folder, so it's been left alone. Please look at it."
        ) from None
    try:
        os.fchown(opened, uid, gid)
        os.fchmod(opened, 0o700)
    finally:
        os.close(opened)


def _make_folders() -> None:
    account = pwd.getpwnam(ACCOUNT)
    for folder in (ACCOUNT_HOME, DATA):
        _own_folder(folder, account.pw_uid, account.pw_gid)


def _install_program(system: System, version: str, staged: Path) -> None:
    say("Installing the tool and exactly the dependency versions the release lists.")
    target = PROGRAM / "versions" / version
    if target.exists():  # left by an install that didn't finish
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    python = Path("/usr/bin") / system.python  # the system's own, not one found first on the path
    if not python.exists():
        raise Stop(f"{python} isn't there after installing it. Run this installer again.")
    _run(str(python), "-I", "-m", "venv", str(target))
    pip = (str(target / "bin" / "python"), "-I", "-m", "pip", "--isolated", "--no-input")
    quiet = ("--quiet", "--no-cache-dir", "--disable-pip-version-check")
    _run(
        *pip,
        "install",
        *quiet,
        "--require-hashes",
        "--only-binary",
        ":all:",
        "-r",
        str(staged / REQUIREMENTS),
    )
    _run(*pip, "install", *quiet, "--no-deps", "--no-index", str(staged / wheel_name(version)))
    link = PROGRAM / "current"
    fresh = PROGRAM / ".current.new"
    if fresh.is_symlink():
        fresh.unlink()
    fresh.symlink_to(target)
    fresh.replace(link)


def _write_file(path: Path, text: str, mode: int) -> None:
    """Made with its final mode from the start: some hold secrets, and a moment of being readable
    would be enough for someone watching the folder."""
    fresh = path.with_name(f".{path.name}.new")
    if fresh.exists() or fresh.is_symlink():
        fresh.unlink()
    descriptor = os.open(fresh, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as out:
        out.write(text)
    os.chmod(fresh, mode)
    fresh.replace(path)


def _start_user_manager(uid: int) -> None:
    """The Check every day page sets a timer in the account's own systemd, which has to keep running
    with nobody logged in."""
    _run("loginctl", "enable-linger", ACCOUNT)
    _run("systemctl", "start", f"user@{uid}.service")


def _turn_sleep_off() -> None:
    say("Turning sleep off, so a daily check isn't missed. This machine now stays on.")
    _run("systemctl", "mask", *SLEEP_UNITS)


def port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Whether something could listen here: the only way to be sure is to try."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as trial:
        trial.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            trial.bind((host, port))
        except OSError:
            return False
    return True


def _service_running(unit: str = UNIT) -> bool:
    return _run("systemctl", "is-active", unit, check=False).stdout.strip() == "active"


def _service_holds_port(port: int, unit: str = UNIT) -> bool:
    """Answering isn't enough, nor is the service looking active: it flickers between that and
    restarting when another program has the port. So it has to be its process that's listening."""
    main_pid = _run("systemctl", "show", "-p", "MainPID", "--value", unit, check=False).stdout
    if not main_pid.strip().isdigit() or int(main_pid) == 0:
        return False
    return int(main_pid) in holders(_run("ss", "-Hltnp", check=False).stdout, port)


def page_answers(address: str, headers: Optional[dict] = None) -> bool:
    """Directly, whatever proxy the environment names."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(f"{address}/login", headers=headers or {})  # noqa: S310
    try:
        with opener.open(request, timeout=5):
            return True
    except (urllib.error.URLError, http.client.HTTPException, OSError):
        return False


def _wait_for_page(
    address: str, headers: Optional[dict] = None, seconds: float = PAGE_SECONDS
) -> None:
    say("Starting the web interface.")
    deadline = time.monotonic() + seconds
    while not (page_answers(address, headers) and _service_holds_port(PORT)):
        if time.monotonic() > deadline:
            log = _run("journalctl", "-u", UNIT, "-n", "30", "--no-pager", check=False).stdout
            raise Stop(
                f"The web interface didn't start. What it said:\n{plain_text(log)}\n"
                "Run this installer again once that's dealt with."
            )
        time.sleep(2)


def plain_text(text: str) -> str:
    """What the tool's account or its log said, without anything that could steer a terminal."""
    return "".join(c for c in text if c == "\n" or (c.isprintable() and c.isascii()))


def new_link(address: str = ADDRESS) -> Optional[str]:
    """A new link, or None if there's already an account and so nothing to set up. Only something
    that's exactly a link to the tool's own address is passed on."""
    done = _run(str(LINK_COMMAND), check=False)
    said = done.stdout + done.stderr
    if done.returncode == 0:
        lines = done.stdout.strip().splitlines()
        if lines and re.fullmatch(re.escape(address) + r"/setup/[A-Za-z0-9_-]+", lines[-1]):
            return lines[-1]
    elif "already an account" in said:
        return None
    raise Stop(
        f"The web interface is running, but a setup link couldn't be made:\n{plain_text(said)}\n"
        "Run this installer again once that's dealt with."
    )


def _set_labels() -> None:
    """Where SELinux is on, files keep the label of where they were made."""
    if shutil.which("restorecon"):
        _run("restorecon", "-R", str(PROGRAM), check=False)
        # Not all the way down the account's folder, which it can change as this runs. What it
        # makes there takes its label from these.
        paths = (ACCOUNT_HOME, DATA, LINK_COMMAND, UNIT_FILE)
        _run("restorecon", *(str(path) for path in paths), check=False)


# --- The web address route ------------------------------------------------------------------------
# Apache with its own certificate module, mod_md, all from each system's base packages, so their
# security fixes arrive with the system's own updates. HTTP/2 stays off: most of Apache's serious
# bugs lately have been there.

STAGING_CA = "https://acme-staging-v02.api.letsencrypt.org/directory"
CERTIFICATE_SECONDS = 300
DNS_WAIT_MINUTES = 30
DNS_POLL_SECONDS = 15
PROXY_SECRET = DATA / "keys" / "web-proxy-secret.txt"
PROXY_HEADER = "X-Checker-Proxy-Secret"
RELOAD = "compromise-checker-certificate-reload"
WEB_MARKER = PROGRAM / "web-address.json"  # what this installer set up for a web address
SELINUX_SWITCH = "httpd_graceful_shutdown"
_NAME = re.compile(
    r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_SECRET = re.compile(r"[A-Za-z0-9_-]{32,}")
SHORTEST_V4, SHORTEST_V6 = 16, 48  # a range wider than this hardly limits anything


class Web(NamedTuple):
    name: str
    allowed: tuple  # address ranges as text; none means anyone
    test_certificates: bool = False

    @property
    def address(self) -> str:
        return f"https://{self.name}"


class Apache(NamedTuple):
    service: str
    packages: tuple
    config: Path
    stores: tuple  # where mod_md may keep certificates
    check: tuple  # the command that checks the settings
    store: Optional[Path] = None  # where it's told to keep them, if its default won't do
    real_store: Path = Path("/var/lib/httpd/md")  # the store's own path, links followed


APACHE_APT = Apache(
    "apache2",
    ("apache2",),
    Path("/etc/apache2/sites-available/compromise-checker.conf"),
    (Path("/var/lib/apache2/md"),),
    ("apache2ctl", "-t"),
    # Ubuntu 26.04's Apache can't write under /etc, mod_md's default.
    Path("/var/lib/apache2/md"),
    Path("/var/lib/apache2/md"),
)
APACHE_DNF = Apache(
    "httpd",
    ("httpd", "mod_ssl", "mod_md", "policycoreutils-python-utils"),
    Path("/etc/httpd/conf.d/compromise-checker.conf"),
    (Path("/etc/httpd/state/md"), Path("/etc/httpd/md")),
    ("apachectl", "-t"),
)


def apache_for(system: System) -> Apache:
    return APACHE_APT if system.install is _APT else APACHE_DNF


def web_name(text: str) -> str:
    """The name people will type, such as checker.example.org, or why it can't be one."""
    name = text.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise Stop(
            "That's an address, and a certificate needs a name, such as checker.example.org."
        )
    if not _NAME.fullmatch(name):
        raise Stop(f"{text.strip()!r} isn't a web address such as checker.example.org.")
    return name


def allowed_ranges(text: str) -> tuple:
    """Addresses or ranges such as 203.0.113.10 or 203.0.113.0/24, apart by spaces or commas."""
    ranges = []
    for part in re.split(r"[\s,]+", text.strip()):
        if not part:
            continue
        try:
            network = ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise Stop(f"{part!r} isn't an address or a range such as 203.0.113.0/24.") from None
        shortest = SHORTEST_V4 if network.version == 4 else SHORTEST_V6
        if network.prefixlen < shortest:
            raise Stop(f"{part} is so wide it hardly limits anything. Name a narrower range.")
        ranges.append(str(network))
    return tuple(ranges)


def global_addresses(ip_json: str) -> list:
    """This machine's own addresses that the internet can reach, from `ip -j address`."""
    try:
        interfaces = json.loads(ip_json or "[]")
    except ValueError:
        return []
    found = []
    for interface in interfaces if isinstance(interfaces, list) else []:
        for entry in interface.get("addr_info", []) if isinstance(interface, dict) else []:
            try:
                address = ipaddress.ip_address(entry.get("local", ""))
            except ValueError:
                continue
            if address.is_global and str(address) not in found:
                found.append(str(address))
    return found


def resolve(name: str) -> set:
    try:
        answers = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return set()
    found = {ipaddress.ip_address(answer[4][0]) for answer in answers}
    # A hosts file often names the machine's own name as a loopback address: that's not DNS.
    return {str(address) for address in found if not address.is_loopback}


def hosts_file_names(text: str, name: str, loopback: bool = False) -> list:
    """Addresses this machine's own /etc/hosts gives the name, which the check above sees first:
    those elsewhere, or, with `loopback`, those on this machine itself."""
    found = []
    for line in text.splitlines():
        words = line.split("#", 1)[0].split()
        if len(words) >= 2 and name in (word.lower() for word in words[1:]):
            try:
                address = ipaddress.ip_address(words[0])
            except ValueError:
                continue
            if address.is_loopback == loopback:
                found.append(str(address))
    return found


def name_problem(name: str, found: set, ours: list) -> Optional[str]:
    """Every address the name gives has to be this machine's: Let's Encrypt may use any of them."""
    private = sorted(a for a in found if not ipaddress.ip_address(a).is_global)
    if private:
        return (
            f"{name} points to {', '.join(private)}, which can't be reached from the internet."
            " Change the DNS record to the machine's public address, then run this installer again."
        )
    elsewhere = sorted(found - set(ours))
    if elsewhere:
        return (
            f"{name} points to {', '.join(elsewhere)}, but this machine is {', '.join(ours)}."
            " Change the DNS record so it points here, then run this installer again."
        )
    return None


def wait_for_name(
    name: str,
    ours: list,
    minutes: float,
    lookup: Callable[[str], set] = resolve,
    pause: Callable[[float], None] = time.sleep,
    leads_here: Optional[Callable[[str], bool]] = None,
) -> None:
    """Some clouds give a machine only a private address and pass a public one on to it, so a name
    that leads elsewhere is tried: if a request to it arrives here, it leads here."""
    found = lookup(name)
    if not found:
        records = [
            f"  {'A' if ipaddress.ip_address(address).version == 4 else 'AAAA'} record:"
            f" {name} -> {address}"
            for address in ours
        ] or [f"  A record: {name} -> this machine's public address, as your provider shows it"]
        say(
            f"\n{name} doesn't point anywhere yet. Add this at whoever looks after your domain's"
            " DNS:\n" + "\n".join(records) + "\nWaiting for it to appear. That can take a few"
            " minutes. Press Ctrl-C to stop, and run this installer again later."
        )
        deadline = time.monotonic() + minutes * 60
        while not found:
            if time.monotonic() > deadline:
                raise Stop(
                    f"{name} still doesn't point anywhere. Once the DNS record is there, run this"
                    " installer again. This run changed nothing."
                )
            pause(DNS_POLL_SECONDS)
            found = lookup(name)
    problem = name_problem(name, found, ours)
    private = any(not ipaddress.ip_address(a).is_global for a in found)
    if problem and not private and leads_here is not None:
        if leads_here(name, set(found) - set(ours)):
            problem = None
    if problem and not ours and not private:
        problem = (
            f"{name} points to {', '.join(sorted(found))}, but nothing sent there arrives at this"
            " machine. It may be behind a router, the provider's firewall may block port 80, or an"
            " old DNS record may still be there."
        )
    if problem:
        raise Stop(f"{problem} This run changed nothing.")
    say(f"{name} leads to this machine.")


def leads_here(name: str, addresses: set, seconds: float = 10) -> bool:
    """Ask each address for a one-time page by the name, from a server on port 80 here for the
    moment. Every one has to lead here, since Let's Encrypt may use any of them. A connection that
    never says anything can't hold it up: each is handled apart, and given up on after a while."""
    asked = base64.urlsafe_b64encode(os.urandom(18)).decode()
    token = base64.urlsafe_b64encode(
        os.urandom(18)
    ).decode()  # never sent: only this machine knows it
    path = f"/.well-known/compromise-checker/{asked}"

    class Answer(http.server.BaseHTTPRequestHandler):
        timeout = 3

        def do_GET(self):  # noqa: N802
            body = token.encode() if self.path == path else b""
            self.send_response(200 if body else 404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class BothKinds(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6
        daemon_threads = True

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()

    class FourOnly(http.server.ThreadingHTTPServer):
        daemon_threads = True

    try:
        server = BothKinds(("::", 80), Answer)
    except OSError:
        try:
            server = FourOnly(("0.0.0.0", 80), Answer)  # noqa: S104
        except OSError:
            return False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with _port_80_open_for_a_moment():
            return all(_page_from(address, name, path, seconds) == token for address in addresses)
    finally:
        server.shutdown()
        server.server_close()


def _page_from(address: str, name: str, path: str, seconds: float) -> str:
    connection = http.client.HTTPConnection(address, 80, timeout=seconds)
    try:
        connection.request("GET", path, headers={"Host": name})
        answer = connection.getresponse()
        return answer.read(64).decode(errors="replace") if answer.status == 200 else ""
    except (OSError, http.client.HTTPException):
        return ""
    finally:
        connection.close()


@contextlib.contextmanager
def _port_80_open_for_a_moment():
    """A firewall here would turn the request away. Opened for this check only, and closed again
    unless it was already open."""
    closing = None
    if (
        shutil.which("firewall-cmd")
        and _run("firewall-cmd", "--state", check=False).returncode == 0
    ):
        if _run("firewall-cmd", "--query-port=80/tcp", check=False).returncode != 0 and (
            _run("firewall-cmd", "--query-service=http", check=False).returncode != 0
        ):
            _run("firewall-cmd", "--add-port=80/tcp", check=False)  # not --permanent
            closing = ("firewall-cmd", "--remove-port=80/tcp")
    elif shutil.which("ufw") and "Status: active" in _ufw_status():
        if not ufw_allows_anyone(_ufw_status(), "80/tcp"):
            _run("ufw", "allow", "80/tcp", check=False)
            closing = ("ufw", "delete", "allow", "80/tcp")
    try:
        yield
    finally:
        if closing:
            _run(*closing, check=False)


def ask_route(answer: Callable[[], str]) -> Optional[Web]:
    say(
        "\nWill people use Compromise Checker from other computers? It then needs a web address"
        " of its own, such as checker.example.org, and this machine has to be reachable from the"
        " internet. Type yes or no. No keeps it to a browser on this machine."
    )
    try:
        said = answer()
    except (EOFError, KeyboardInterrupt):
        raise Stop("Stopped. This run changed nothing.") from None
    if said.strip().lower() not in ("y", "yes"):
        return None
    name = web_name(answer_with_prompt(answer, "\nThe web address, such as checker.example.org:"))
    allowed = allowed_ranges(
        answer_with_prompt(
            answer,
            "\nShould only some addresses be able to reach the page, such as your office's? Type"
            " them, apart by spaces, or press Enter for anyone. Let's Encrypt can still reach"
            " this machine, so the certificate keeps renewing.",
        )
    )
    return Web(name, allowed)


def answer_with_prompt(answer: Callable[[], str], prompt: str) -> str:
    say(prompt)
    try:
        return answer()
    except (EOFError, KeyboardInterrupt):
        raise Stop("Stopped. This run changed nothing.") from None


def apache_config(web: Web, secret: str, store: Optional[Path] = None) -> str:
    """Port 80 only redirects, apart from Let's Encrypt's checks, which mod_md answers before the
    redirect. Only Apache knows the secret it sends to the tool, so nothing else on this machine can
    pass for it."""
    if not _SECRET.fullmatch(secret):
        raise Stop("The tool's proxy secret isn't what it should be. Run this installer again.")
    who = " ".join(web.allowed) if web.allowed else ""
    access = f"Require ip {who}" if who else "Require all granted"
    host = re.escape(web.name)
    staging = f"MDCertificateAuthority {STAGING_CA}\n" if web.test_certificates else ""
    if store is not None:
        staging += f"MDStoreDir {store}\n"
    return f"""# Written by the Compromise Checker installer, and replaced when it runs again.
Protocols http/1.1
# Apache would otherwise answer TRACE itself, echoing the request's headers, the secret included.
TraceEnable Off
MDCertificateAgreement accepted
# mod_md won't go on without one. It needn't be read, and nothing personal is sent.
MDContactEmail webmaster@{web.name}
{staging}MDomain {web.name}

<VirtualHost *:80>
    ServerName {web.name}
    Protocols http/1.1
    # No access log: a setup link's path would be in it. The tool keeps none either.
    CustomLog /dev/null common
    Redirect permanent / https://{web.name}/
</VirtualHost>

<VirtualHost *:443>
    ServerName {web.name}
    Protocols http/1.1
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    CustomLog /dev/null common
    # Refusals would otherwise name the path, and a setup link's is a secret.
    LogLevel authz_core:crit
    ProxyRequests Off
    ProxyPreserveHost On
    ProxyTimeout 300
    RequestHeader set {PROXY_HEADER} "{secret}"
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass / http://127.0.0.1:{PORT}/ disablereuse=On
    ProxyPassReverse / http://127.0.0.1:{PORT}/
    <Location />
        <RequireAll>
            # Only requests for the name: the tool would turn others away, but not if it were ever
            # started without its public address.
            Require expr "%{{HTTP_HOST}} =~ /^{host}(:443)?$/i"
            {access}
        </RequireAll>
    </Location>
</VirtualHost>
"""


def reload_units(apache: Apache, web: Optional[Web] = None) -> dict:
    """mod_md renews certificates by itself, but Apache only uses a new one once it reloads. Hourly,
    so one that arrives late is in use within the hour: until then the page doesn't work at all.
    A reload with nothing new costs next to nothing. (Watching for the file instead would need
    systemd to read Apache's files, which SELinux on Rocky 9 doesn't allow.)"""
    service = f"""[Unit]
Description=Compromise Checker: let Apache use a new certificate

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reload {apache.service}
"""
    timer = """[Unit]
Description=Compromise Checker: let Apache use a new certificate, hourly

[Timer]
OnCalendar=hourly
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
"""
    folder = Path("/etc/systemd/system")
    return {folder / f"{RELOAD}.service": service, folder / f"{RELOAD}.timer": timer}


def port_free_everywhere(port: int) -> bool:
    """Free on every address, IPv6 ones included: something could be listening on those alone."""
    if not port_free(port, "0.0.0.0"):  # noqa: S104
        return False
    try:
        trial = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return True  # no IPv6 here
    with trial:
        trial.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        trial.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            trial.bind(("::", port))
        except OSError:
            return False
    return True


def _web_ports_problem(apache: Apache) -> Optional[str]:
    """Apache on these ports is only let by if an earlier run of this installer started it: one that
    was there before belongs to someone else, and isn't taken over."""
    ours = WEB_MARKER.exists() and not read_marker().get("apache_before")
    for port in (80, 443):
        if port_free_everywhere(port):
            continue
        if not (ours and _service_holds_port(port, apache.service)):
            return f"Something else is using port {port}, which the web address needs."
    return None


def _reachable(web: Web, dns_minutes: float) -> None:
    """Before anything changes: this machine has to be on the internet, and the name has to lead
    here. Whether a firewall outside lets Let's Encrypt in only shows when it tries."""
    ours = global_addresses(_run("ip", "-j", "address", check=False).stdout)
    try:
        hosts_text = Path("/etc/hosts").read_text(encoding="utf-8")
    except OSError:
        hosts_text = ""
    given = hosts_file_names(hosts_text, web.name, loopback=True) + hosts_file_names(
        hosts_text, web.name
    )
    if given:
        raise Stop(
            f"This machine's own /etc/hosts gives {web.name} as {', '.join(given)}, so it can't"
            " see what everyone else sees for that name. Take the name off that line, then run"
            " this installer again. (A line like that often names the machine itself, and its"
            " short name can stay.) This run changed nothing."
        )
    try:
        wait_for_name(web.name, ours, dns_minutes, leads_here=leads_here)
    except Stop as exc:
        if ours:
            raise
        raise Stop(
            f"{exc} If this machine is behind a router, run this installer again and answer no,"
            " to use it from this machine only, or use a cloud server for a web address."
        ) from None


def _allow_proxy_under_selinux() -> None:
    """Apache is confined. httpd_graceful_shutdown, despite its name, is the narrowest switch that
    lets it connect out at all: only to web ports, Let's Encrypt's 443 included, and the tool's port
    becomes one of them. httpd_can_network_relay and httpd_can_network_connect allow far more."""
    if not (shutil.which("selinuxenabled") and shutil.which("semanage")):
        return
    if _run("selinuxenabled", check=False).returncode != 0:
        return
    say(f"Letting Apache, under SELinux, connect to web ports, and to the tool's port, {PORT}.")
    if "--> on" not in _run("getsebool", SELINUX_SWITCH, check=False).stdout:
        write_marker({**read_marker(), "selinux_switch": True})  # noted first, in case it stops
        _run("setsebool", "-P", SELINUX_SWITCH, "1")
    listed = _run("semanage", "port", "-l", check=False).stdout
    if re.search(rf"^http_port_t\s+tcp\s+.*\b{PORT}\b", listed, re.MULTILINE):
        return
    before = port_label(listed, PORT)
    write_marker({**read_marker(), "port_label": before or "added"})
    if before is None:
        _run("semanage", "port", "-a", "-t", "http_port_t", "-p", "tcp", str(PORT))
    else:
        _run("semanage", "port", "-m", "-t", "http_port_t", "-p", "tcp", str(PORT))


def port_label(listing: str, port: int) -> Optional[str]:
    """The type SELinux gives a TCP port by name, from `semanage port -l`, if any does."""
    for line in listing.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[1] == "tcp":
            if str(port) in [part.strip() for part in parts[2].split(",")]:
                return parts[0]
    return None


def _ufw_status() -> str:
    return _run("ufw", "status", check=False, env={**os.environ, "LC_ALL": "C"}).stdout


def read_marker() -> dict:
    try:
        found = json.loads(WEB_MARKER.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def write_marker(marker: dict) -> None:
    WEB_MARKER.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_file(WEB_MARKER, json.dumps(marker) + "\n", 0o644)


def ufw_allows_anyone(status: str, port: str) -> bool:
    """A rule that lets everyone in: one limited to some addresses wouldn't let Let's Encrypt in."""
    return bool(re.search(rf"^{re.escape(port)}\s+ALLOW(?: IN)?\s+Anywhere\s*$", status, re.M))


def _note(key: str, value: str) -> None:
    """Noted before it's done, so an install that stops part way can still undo it."""
    marker = read_marker()
    marker[key] = sorted(set(marker.get(key, [])) | {value})
    write_marker(marker)


def _open_firewall() -> None:
    """Only a firewall that's running: one that's off, or not there, isn't turned on here. What it
    opens is noted, so taking the web address down closes only that. firewalld isn't reloaded:
    that would drop rules someone added for the running session only, SSH perhaps among them."""
    if (
        shutil.which("firewall-cmd")
        and _run("firewall-cmd", "--state", check=False).returncode == 0
    ):
        say("Opening ports 80 and 443 in the firewall.")
        for service in ("http", "https"):
            if _run("firewall-cmd", f"--query-service={service}", check=False).returncode != 0:
                _note("firewalld_runtime", service)
                _run("firewall-cmd", f"--add-service={service}")
            permanent = _run(
                "firewall-cmd", "--permanent", f"--query-service={service}", check=False
            )
            if permanent.returncode != 0:
                _note("firewalld_permanent", service)
                _run("firewall-cmd", "--permanent", f"--add-service={service}")
    elif shutil.which("ufw") and "Status: active" in _ufw_status():
        say("Opening ports 80 and 443 in the firewall.")
        status = _ufw_status()
        for port in ("80/tcp", "443/tcp"):
            if not ufw_allows_anyone(status, port):
                _note("ufw", port)
                _run("ufw", "allow", port)


# Locking the machine down (installation plan, I.4). Every change is said as it's made.

# What a new system's own firewall lets in that this machine has no use for. Anything else
# someone allowed is listed, not removed.
_FIREWALLD_DROPPED = ("cockpit",)
# Kept: some networks give the machine its IPv6 address through it.
_FIREWALLD_KEPT = ("ssh", "dhcpv6-client")
# The web address's openings: _open_firewall makes and notes them, so they aren't listed as extras.
_WEB_OPENINGS = ("http", "https", "80/tcp", "443/tcp")
LOCKDOWN_MARKER = PROGRAM / "lockdown.json"  # what this installer changed to lock the machine down


def read_lockdown() -> dict:
    try:
        found = json.loads(LOCKDOWN_MARKER.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def note_lockdown(key: str, value) -> None:
    """Noted before it's done, so a later run knows it was this installer's doing."""
    marker = read_lockdown()
    marker[key] = value
    LOCKDOWN_MARKER.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_file(LOCKDOWN_MARKER, json.dumps(marker, sort_keys=True) + "\n", 0o644)


def ssh_ports(ss_output: str, socket_listen: str = "") -> list:
    """The ports SSH takes connections on from other machines. On Ubuntu systemd may hold the port
    for SSH until someone connects, which `socket_listen` (ssh.socket's Listen=) shows."""
    held_for_ssh = set(re.findall(r":(\d+) \(Stream\)", socket_listen))
    ports = set()
    for address, port, program in _listeners(ss_output):
        if _loopback(address):
            continue
        if program == "sshd" or (program == "systemd" and port in held_for_ssh):
            ports.add(port)
    return sorted(ports, key=int)


def running_firewall() -> Optional[str]:
    if (
        shutil.which("firewall-cmd")
        and _run("firewall-cmd", "--state", check=False).returncode == 0
    ):
        return "firewalld"
    if shutil.which("ufw") and "Status: active" in _ufw_status():
        return "ufw"
    return None


def ufw_extras(status: str, ours: set) -> list:
    """What an active ufw lets in besides `ours`: each rule's "To" part, once."""
    ours = set(ours) | set(_WEB_OPENINGS)
    found = []
    for line in status.splitlines():
        match = re.match(r"^(\S+(?: \(v6\))?)\s+(?:ALLOW|LIMIT)(?: IN)?\s", line)
        if not match:
            continue
        to = match.group(1).replace(" (v6)", "")
        if to not in ours and to not in found:
            found.append(to)
    return found


def firewalld_extras(listing: str, ports: list) -> list:
    """What a firewalld zone lets in besides SSH's ports, from `--list-all`."""
    found = []
    for line in listing.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "services":
            found += [
                name
                for name in value.split()
                if name not in _FIREWALLD_KEPT and name not in _WEB_OPENINGS
            ]
        elif key == "ports":
            ours = {f"{p}/tcp" for p in ports} | set(_WEB_OPENINGS)
            found += [port for port in value.split() if port not in ours]
        elif key == "rich rules" and value.strip():
            found.append("rules of its own")
    return found


def _ssh_listen() -> str:
    return _run("systemctl", "show", "-p", "Listen", "--value", "ssh.socket", check=False).stdout


def _set_up_ufw(ports: list, limit: bool) -> list:
    say("Setting up the firewall, ufw, to let nothing in but SSH.")
    _run("ufw", "default", "deny", "incoming")
    _run("ufw", "default", "allow", "outgoing")
    for port in ports:
        _run("ufw", "limit" if limit else "allow", f"{port}/tcp")
    _run("ufw", "--force", "enable")
    return ufw_extras(_ufw_status(), {f"{port}/tcp" for port in ports})


def _set_up_firewalld(ports: list) -> list:
    """Its saved settings are changed before it starts, so nothing it starts with can cut off SSH
    on a port other than 22."""
    say("Setting up the firewall, firewalld, to let nothing in but SSH.")
    if _run("firewall-cmd", "--state", check=False).returncode == 0:
        # an earlier run's, already started: its saved settings can't be changed offline now
        _run("systemctl", "stop", "firewalld")
    zone = _run("firewall-offline-cmd", "--get-default-zone").stdout.strip() or "public"
    offline = ("firewall-offline-cmd", f"--zone={zone}")
    for service in _FIREWALLD_DROPPED:
        if _run(*offline, f"--query-service={service}", check=False).returncode == 0:
            say(f"Closing {service}, which this system lets in at first.")
            _run(*offline, f"--remove-service={service}")
    for port in ports:
        if port == "22":
            if _run(*offline, "--query-service=ssh", check=False).returncode != 0:
                _run(*offline, "--add-service=ssh")
        elif _run(*offline, f"--query-port={port}/tcp", check=False).returncode != 0:
            _run(*offline, f"--add-port={port}/tcp")
    _run("systemctl", "enable", "--now", "firewalld")
    return firewalld_extras(_run("firewall-cmd", f"--zone={zone}", "--list-all").stdout, ports)


def set_up_firewall(system: System, limit: bool = False) -> None:
    """A firewall letting in only SSH (and, later, the web address's two ports). One that's already
    running is someone's, unless an earlier run of this installer set it up: its rules are kept,
    and what else it lets in is listed. `limit` makes ufw hold off an address that keeps opening
    SSH connections."""
    ports = ssh_ports(_run("ss", "-Hltnp", check=False).stdout, _ssh_listen())
    found = running_firewall()
    mine = "ufw" if system.install is _APT else "firewalld"
    if found and read_lockdown().get("firewall") == found:
        found = None  # this installer's own, from a run that didn't finish: set up the same again
    if found:
        say(f"A firewall, {found}, is already running here. Its rules are kept as they are.")
        if found == "ufw":
            if limit:
                for port in ports:
                    _run("ufw", "limit", f"{port}/tcp")
            extras = ufw_extras(_ufw_status(), {f"{port}/tcp" for port in ports})
        else:
            zone = _run("firewall-cmd", "--get-default-zone").stdout.strip()
            listing = _run("firewall-cmd", f"--zone={zone}", "--list-all").stdout
            extras = firewalld_extras(listing, ports)
    elif mine == "ufw":
        note_lockdown("firewall", "ufw")
        extras = _set_up_ufw(ports, limit)
    else:
        note_lockdown("firewall", "firewalld")
        extras = _set_up_firewalld(ports)
    if ports:
        say(f"SSH can still be reached, on port {', '.join(ports)}.")
    else:
        say(
            "SSH isn't running here, so the firewall lets nothing in for it. If you turn SSH on"
            " later, let its port in through the firewall as well."
        )
    if extras:
        say(
            f"The firewall also lets in: {', '.join(extras)}. Close what this machine doesn't need."
        )


APT_UPDATES = Path("/etc/apt/apt.conf.d/52compromise-checker-updates")
DNF_UPDATES = Path("/etc/dnf/automatic-compromise-checker.conf")
DNF_TIMER = "dnf-automatic-install.timer"
DNF_DROP_IN = Path("/etc/systemd/system/dnf-automatic-install.service.d/compromise-checker.conf")

# apt reads its files in order and the last one wins, so this comes after Ubuntu's 20auto-upgrades.
# Which updates are installed stays Ubuntu's own choice: the security ones.
APT_UPDATES_TEXT = """\
// Compromise Checker's installer: install security updates every day (installation plan, I.4).
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
"""

# Its own file, so Rocky's automatic.conf stays as the package left it.
DNF_UPDATES_TEXT = """\
# Compromise Checker's installer: install security updates every day (installation plan, I.4).
# The machine isn't restarted: the web page says when an update needs that.
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio
"""

DNF_DROP_IN_TEXT = f"""\
# Compromise Checker's installer: the security updates only, from its own settings.
[Service]
ExecStart=
ExecStart=/usr/bin/dnf-automatic {DNF_UPDATES} --timer --installupdates
"""


def apt_value(dump: str, name: str) -> Optional[str]:
    """One setting from `apt-config dump`."""
    match = re.search(rf'^{re.escape(name)} "([^"]*)";$', dump, re.M)
    return match.group(1) if match else None


def apt_updates_on(dump: str) -> bool:
    return all(
        apt_value(dump, f"APT::Periodic::{name}") not in (None, "0", "")
        for name in ("Update-Package-Lists", "Unattended-Upgrade")
    )


def _apt_dump() -> str:
    return _run("apt-config", "dump", check=False, env={**os.environ, "LC_ALL": "C"}).stdout


def _turn_updates_on_apt() -> None:
    if apt_updates_on(_apt_dump()):
        say("Security updates already install by themselves here.")
    else:
        say("Turning on automatic security updates, which Ubuntu installs every day.")
        _write_file(APT_UPDATES, APT_UPDATES_TEXT, 0o644)
        if not apt_updates_on(_apt_dump()):
            raise Stop(
                "Automatic security updates didn't turn on, so something else here turns them"
                " off. Look in /etc/apt/apt.conf.d, then run this installer again."
            )
    _run("systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer")
    reboot = apt_value(_apt_dump(), "Unattended-Upgrade::Automatic-Reboot")
    if reboot == "true":
        say("They're set to restart the machine when one needs it, which was already the case.")


def _turn_updates_on_dnf() -> None:
    enabled = _run("systemctl", "is-enabled", DNF_TIMER, check=False).stdout.strip()
    if enabled == "enabled" and not DNF_DROP_IN.exists():
        say("Updates already install by themselves here, with this machine's own settings.")
        return
    say("Turning on automatic security updates, which Rocky installs every day.")
    _write_file(DNF_UPDATES, DNF_UPDATES_TEXT, 0o644)
    DNF_DROP_IN.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_file(DNF_DROP_IN, DNF_DROP_IN_TEXT, 0o644)
    if shutil.which("restorecon"):
        _run("restorecon", str(DNF_UPDATES), str(DNF_DROP_IN.parent), str(DNF_DROP_IN), check=False)
    _run("systemctl", "daemon-reload")
    _run("systemctl", "enable", "--now", DNF_TIMER)


def turn_updates_on(system: System) -> None:
    """The system's own security updates, every day. The machine is never restarted for one."""
    if system.install is _APT:
        _turn_updates_on_apt()
    else:
        _turn_updates_on_dnf()


# The three changes made only with the person's permission, each behind a safety check, so nobody
# is locked out of their own machine.

SSHD_DROP_IN = Path("/etc/ssh/sshd_config.d/01-compromise-checker.conf")  # first, so it wins
SSH_LIMIT = "compromise-checker-ssh-limit"
SSH_LIMIT_UNIT = Path("/etc/systemd/system") / f"{SSH_LIMIT}.service"
SSH_LIMIT_RULES = Path("/etc/nftables") / f"{SSH_LIMIT}.nft"
SSH_LIMIT_TABLE = "compromise_checker_ssh"
_ADMIN_GROUPS = ("sudo", "admin", "wheel")
_ACCEPTED = re.compile(r"^Accepted (publickey|password|keyboard-interactive/pam) for (\S+) from ")
# What sshd's own processes are called: sshd, and from OpenSSH 9.8 sshd-session too.
_SSHD_PROCESSES = ("sshd", "sshd-session")
LIMITED = (
    "The firewall now makes an address that opens more than 6 SSH connections in 30 seconds wait."
)


class Choices(NamedTuple):
    passwords_off: bool = False
    root_off: bool = False
    block: bool = False


class SshState(NamedTuple):
    running: bool
    settings: dict  # sshd -T, as SSH really runs
    admins: tuple  # accounts that can act as an administrator
    key_logins: frozenset  # admins seen logging in with a key, that still have one
    logins: frozenset  # admins seen logging in at all
    ports: tuple


def sshd_settings(text: str) -> dict:
    """`sshd -T`: one setting a line, the first of each being the one in force. OpenSSH 10 writes
    the names as they're written in its settings, and older versions in lower case."""
    found: dict = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        key = key.lower()
        if key and key not in found:
            found[key] = value.strip()
    return found


def admin_accounts(group: str, passwd: str) -> tuple:
    """root, and each account in an administrators' group that can log in."""
    shells = {}
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            shells[parts[0]] = parts[6]
    found = ["root"]
    for line in group.splitlines():
        parts = line.split(":")
        if len(parts) < 4 or parts[0] not in _ADMIN_GROUPS:
            continue
        for name in parts[3].split(","):
            name = name.strip()
            shell = shells.get(name)
            if shell is None or name in found:
                continue  # a member with no account here
            if shell.rsplit("/", 1)[-1] not in _NO_LOGIN:
                found.append(name)
    return tuple(found)


def accepted_logins(journal: str) -> dict:
    """Who sshd says logged in, and how, from `journalctl -o json`. Only what sshd's own processes
    wrote, as root, counts: anyone on the machine can write a line that looks like sshd's."""
    found: dict = {}
    for line in journal.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        if entry.get("_COMM") not in _SSHD_PROCESSES or entry.get("_UID") != "0":
            continue
        message = entry.get("MESSAGE")
        match = _ACCEPTED.match(message) if isinstance(message, str) else None
        if match:
            found.setdefault(match.group(2), set()).add(match.group(1))
    return found


def key_files(settings: dict, name: str, home: str) -> list:
    """Where sshd looks for this account's keys."""
    files = []
    for pattern in settings.get("authorizedkeysfile", ".ssh/authorized_keys").split():
        if pattern.lower() == "none":
            continue
        path = pattern.replace("%%", "\0").replace("%h", home).replace("%u", name)
        path = path.replace("\0", "%")
        files.append(Path(path) if path.startswith("/") else Path(home) / path)
    return files


def has_a_key(paths: list) -> bool:
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(line.strip() and not line.lstrip().startswith("#") for line in text.splitlines()):
            return True
    return False


def ssh_state(ss_output: str) -> SshState:
    ports = tuple(ssh_ports(ss_output, _ssh_listen()))
    active = any(
        _run("systemctl", "is-active", unit, check=False).stdout.strip() == "active"
        for unit in ("ssh.service", "sshd.service", "ssh.socket")
    )
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    shown = _run(sshd, "-T", check=False) if Path(sshd).exists() else None
    if not (ports or active) or shown is None or shown.returncode != 0:
        return SshState(False, {}, (), frozenset(), frozenset(), ports)
    settings = sshd_settings(shown.stdout)
    admins = admin_accounts(
        Path("/etc/group").read_text(encoding="utf-8"),
        Path("/etc/passwd").read_text(encoding="utf-8"),
    )
    journal = _run(
        "journalctl",
        "-q",
        "--no-pager",
        "-o",
        "json",
        "--output-fields=MESSAGE,_COMM,_UID",
        *(f"_COMM={name}" for name in _SSHD_PROCESSES),
        check=False,
    ).stdout
    seen = accepted_logins(journal)
    keyed = set()
    for name in admins:
        try:
            home = pwd.getpwnam(name).pw_dir
        except KeyError:
            continue
        if "publickey" in seen.get(name, ()) and has_a_key(key_files(settings, name, home)):
            keyed.add(name)
    logins = frozenset(name for name in admins if name in seen)
    return SshState(True, settings, admins, frozenset(keyed), logins, ports)


def passwords_on(settings: dict) -> bool:
    return (
        settings.get("passwordauthentication", "yes") != "no"
        or settings.get("kbdinteractiveauthentication", "no") != "no"
    )


def passwords_problem(state: SshState) -> Optional[str]:
    """Why SSH passwords have to stay on, if they do."""
    if not state.key_logins:
        return (
            "no administrator account has logged in here with a key yet, so turning passwords off"
            " could lock everyone out"
        )
    return None


def root_problem(state: SshState, passwords_off: bool) -> Optional[str]:
    """Why root login has to stay on, if it does."""
    others = (state.key_logins if passwords_off else state.logins) - {"root"}
    if not others:
        how = " with a key" if passwords_off else ""
        return (
            f"no other administrator account has logged in here{how}, so root may be the only way"
            " in"
        )
    return None


def blocking_kind(state: SshState, firewall: str) -> str:
    """What blocks repeated login failures here. "on": SSH's own blocking, on already. "ssh": SSH
    has it, turned off. Otherwise the firewall limits new connections: "ufw", or "nft" for a table
    of our own."""
    penalties = state.settings.get("persourcepenalties")
    if penalties is not None:
        return "ssh" if penalties == "no" else "on"
    return "ufw" if firewall == "ufw" else "nft"


def _yes(answer: Callable[[], str], prompt: str) -> bool:
    while True:
        typed = answer_with_prompt(answer, prompt).strip().lower()
        if typed in ("", "n", "no"):
            return False
        if typed in ("y", "yes"):
            return True
        say("Type yes or no.")


def choose_lockdown(
    state: SshState,
    firewall: str,
    answer: Optional[Callable[[], str]] = None,
    wanted: Optional[Choices] = None,
) -> Choices:
    """Each change, asked separately when there's someone to ask, or taken from `wanted` when not.
    A safety check that fails leaves that setting alone, and says why."""
    if not state.running:
        say(
            "\nSSH isn't running here, so its settings are left as they are. Turning it on isn't"
            " needed for this tool."
        )
        return Choices()
    say("\nThree changes to how people log in to this machine over SSH are up to you.")
    wanted = wanted or Choices()
    passwords_off = root_off = block = False
    if not passwords_on(state.settings):
        say("SSH already refuses passwords here.")
    else:
        problem = passwords_problem(state)
        if problem:
            say(f"SSH passwords stay on: {problem}. The web page reminds you while they're on.")
        elif answer is not None:
            names = ", ".join(sorted(state.key_logins))
            passwords_off = _yes(
                answer,
                "\nTurn off logging in to SSH with a password? Then only someone holding a key can"
                f" log in, and a key can't be guessed. A key login has worked here for: {names}."
                "\nType yes or no. Enter keeps passwords on.",
            )
        else:
            passwords_off = wanted.passwords_off
    if state.settings.get("permitrootlogin", "yes") == "no":
        say("SSH already refuses root logins here.")
    else:
        problem = root_problem(state, passwords_off)
        if problem:
            if answer is not None or wanted.root_off:
                say(f"Root login over SSH stays on: {problem}.")
        elif answer is not None:
            names = ", ".join(
                sorted((state.key_logins if passwords_off else state.logins) - {"root"})
            )
            root_off = _yes(
                answer,
                "\nTurn off logging in to SSH as root? Administrators then log in as themselves and"
                " use sudo, which leaves a record of who did what. Another administrator account"
                f" has logged in here: {names}.\nType yes or no. Enter keeps root login on.",
            )
        else:
            root_off = wanted.root_off
    kind = blocking_kind(state, firewall)
    if kind == "on":
        say("SSH already holds off an address that keeps failing to log in, for longer each time.")
    elif answer is not None:
        how = (
            "SSH then holds off an address that keeps failing to log in, for longer each time."
            if kind == "ssh"
            else "This system's SSH can't do that itself, so the firewall makes an address that"
            " opens more than 6 SSH connections in 30 seconds wait. That could slow a tool that"
            " logs in to this machine many times in a row."
        )
        block = _yes(
            answer,
            f"\nBlock addresses that keep trying to log in? {how}"
            "\nType yes or no. Enter leaves it off.",
        )
    else:
        block = wanted.block
    return Choices(passwords_off, root_off, block and kind != "on")


def wanted_ssh_settings(choices: Choices, kind: str) -> dict:
    """What `sshd -T` should say once SSH has taken the changes."""
    wanted = {}
    if choices.passwords_off:
        wanted["passwordauthentication"] = "no"
        wanted["kbdinteractiveauthentication"] = "no"
    if choices.root_off:
        wanted["permitrootlogin"] = "no"
    if choices.block and kind == "ssh":
        wanted["persourcepenalties"] = None  # anything but "no"
    return wanted


def sshd_drop_in(choices: Choices, kind: str) -> Optional[str]:
    wanted = wanted_ssh_settings(choices, kind)
    if not wanted:
        return None
    names = {
        "passwordauthentication": "PasswordAuthentication no",
        "kbdinteractiveauthentication": "KbdInteractiveAuthentication no",
        "permitrootlogin": "PermitRootLogin no",
        "persourcepenalties": "PerSourcePenalties yes",
    }
    lines = [
        "# Compromise Checker's installer, with the permission of the person installing it",
        "# (installation plan, I.4). SSH takes the first value it reads, so this file comes first.",
        *(names[key] for key in wanted),
    ]
    return "\n".join(lines) + "\n"


def ssh_settings_took(shown: dict, wanted: dict) -> list:
    """The settings SSH didn't take."""
    return [
        key
        for key, value in wanted.items()
        if (shown.get(key, "no") == "no" if value is None else shown.get(key) != value)
    ]


def _change_ssh(choices: Choices, kind: str) -> None:
    text = sshd_drop_in(choices, kind)
    if text is None:
        return
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    SSHD_DROP_IN.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_file(SSHD_DROP_IN, text, 0o600)
    if shutil.which("restorecon"):
        _run("restorecon", str(SSHD_DROP_IN), check=False)
    checked = _run(sshd, "-t", check=False)
    shown = sshd_settings(_run(sshd, "-T", check=False).stdout) if checked.returncode == 0 else {}
    missed = ssh_settings_took(shown, wanted_ssh_settings(choices, kind))
    if checked.returncode != 0 or missed:
        SSHD_DROP_IN.unlink()
        why = plain_text(checked.stderr).strip() or f"SSH didn't take: {', '.join(missed)}"
        say(
            "SSH's settings were left as they were, because the change didn't work:"
            f" {why}. The rest of the install went ahead."
        )
        return
    for unit in ("ssh.service", "sshd.service"):  # Ubuntu's name, then Rocky's
        _run("systemctl", "try-reload-or-restart", unit, check=False)
    if choices.passwords_off:
        say("SSH no longer accepts passwords. Logins already open stay open.")
    if choices.root_off:
        say("SSH no longer lets anyone log in as root.")
    if choices.block and kind == "ssh":
        say("SSH now holds off an address that keeps failing to log in.")


def ssh_limit_rules(ports: tuple) -> str:
    """An address opening more than 6 new SSH connections in 30 seconds has the rest dropped until
    it slows down, the same as `ufw limit`. In a table of its own, before the firewall's own rules,
    so firewalld can't remove it and dropping here is final."""
    listed = ", ".join(ports)
    rule = "limit rate over 12/minute burst 6 packets"
    return f"""\
#!/usr/sbin/nft -f
# Compromise Checker's installer, with the permission of the person installing it (installation
# plan, I.4): this system's SSH can't hold off an address that keeps failing to log in by itself.
table inet {SSH_LIMIT_TABLE}
delete table inet {SSH_LIMIT_TABLE}
table inet {SSH_LIMIT_TABLE} {{
    set recent4 {{ type ipv4_addr; flags dynamic, timeout; timeout 1m; }}
    set recent6 {{ type ipv6_addr; flags dynamic, timeout; timeout 1m; }}
    chain input {{
        type filter hook input priority filter - 10; policy accept;
        iif "lo" accept
        tcp dport {{ {listed} }} ct state new update @recent4 {{ ip saddr {rule} }} drop
        tcp dport {{ {listed} }} ct state new update @recent6 {{ ip6 saddr {rule} }} drop
    }}
}}
"""


def ssh_limit_unit(nft: str) -> str:
    return f"""\
[Unit]
Description=Compromise Checker: a limit on new SSH connections from each address
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft} -f {SSH_LIMIT_RULES}
ExecStop={nft} delete table inet {SSH_LIMIT_TABLE}

[Install]
WantedBy=multi-user.target
"""


def _limit_ssh_in_nftables(ports: tuple) -> None:
    nft = shutil.which("nft")
    if nft is None:
        say("Addresses aren't limited: this system has no nft command.")
        return
    SSH_LIMIT_RULES.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_file(SSH_LIMIT_RULES, ssh_limit_rules(ports), 0o644)
    checked = _run(nft, "-c", "-f", str(SSH_LIMIT_RULES), check=False)
    if checked.returncode != 0:
        SSH_LIMIT_RULES.unlink()
        say(
            "Addresses aren't limited: the rules didn't pass nft's check:"
            f" {plain_text(checked.stderr)}"
        )
        return
    _write_file(SSH_LIMIT_UNIT, ssh_limit_unit(nft), 0o644)
    if shutil.which("restorecon"):
        _run("restorecon", str(SSH_LIMIT_RULES), str(SSH_LIMIT_UNIT), check=False)
    _run("systemctl", "daemon-reload")
    _run("systemctl", "enable", "--now", f"{SSH_LIMIT}.service")
    say(LIMITED)


def apply_lockdown(choices: Choices, kind: str) -> None:
    """At the end, once everything else has worked. ufw's limit is set with the firewall."""
    _change_ssh(choices, kind)
    ports = tuple(ssh_ports(_run("ss", "-Hltnp", check=False).stdout, _ssh_listen()))
    if choices.block and kind == "nft" and ports:
        _limit_ssh_in_nftables(ports)
    elif choices.block and kind == "ufw":
        say(LIMITED)


def _set_up_apache(web: Web, apache: Apache, secret: str) -> None:
    say(f"Setting up Apache to give {web.name} a certificate and pass requests to the tool.")
    _allow_proxy_under_selinux()
    if apache is APACHE_APT:
        _run("a2enmod", "-q", "md", "ssl", "proxy", "proxy_http", "headers")
        _run("a2dismod", "-q", "-f", "http2", check=False)
        _run("a2dissite", "-q", "000-default", check=False)
    if apache.store is not None:
        apache.store.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_file(apache.config, apache_config(web, secret, apache.store), 0o600)
    if apache is APACHE_APT:
        _run("a2ensite", "-q", "compromise-checker")
    if shutil.which("restorecon"):
        _run("restorecon", str(apache.config), check=False)
    if apache is APACHE_DNF:  # makes the certificate Rocky's own default settings point to
        _run("systemctl", "start", "httpd-init.service", check=False)
    checked = _run(*apache.check, check=False)
    if checked.returncode != 0:
        raise Stop(
            f"Apache's settings didn't pass its own check:\n{plain_text(checked.stderr)}\n"
            "Run this installer again once that's dealt with."
        )
    for path, text in reload_units(apache, web).items():
        _write_file(path, text, 0o644)
    _run("systemctl", "daemon-reload")
    _run("systemctl", "enable", "--now", f"{RELOAD}.timer")
    _open_firewall()  # first, so Let's Encrypt's check can get in as soon as Apache asks
    _run("systemctl", "enable", apache.service)
    _run("systemctl", "restart", apache.service)


def _undo_web_address(apache: Apache) -> None:
    """An earlier run that didn't finish may have set up a web address. Without one, the tool trusts
    whatever reaches it, so nothing may still be passing it requests from outside."""
    marker = read_marker()
    if not (WEB_MARKER.exists() or apache.config.exists()):
        return
    say("Taking down the web address an earlier run of this installer began to set up.")
    if apache.config.exists():
        if apache is APACHE_APT:
            _run("a2dissite", "-q", "compromise-checker", check=False)
        apache.config.unlink()
    _run("systemctl", "disable", "--now", f"{RELOAD}.timer", check=False)
    # Apache must really stop passing requests on before this goes on: the tool is about to start
    # trusting whatever reaches it. If it can't, the marker stays, so a later run tries again.
    exists = _run("systemctl", "cat", apache.service, check=False).returncode == 0
    if not exists:
        pass  # an earlier run stopped before Apache was installed
    elif not marker.get("apache_before"):  # Apache came with this installer, and goes with it
        _run("systemctl", "disable", "--now", apache.service)
    elif _service_running(apache.service):
        _run("systemctl", "reload", apache.service)
    left = _undo_openings(marker)
    if left:
        write_marker(left)
        say(
            "These couldn't be undone, and are noted so a later run of this installer tries again:"
            f" {', '.join(sorted(left))}."
        )
    else:
        WEB_MARKER.unlink(missing_ok=True)


def _undo_openings(marker: dict) -> dict:
    """The firewall openings and SELinux changes this installer made, each undone. What couldn't
    be is returned, to stay on record."""
    left: dict = {}

    def keep(key: str, value) -> None:
        if isinstance(value, str) and key not in ("port_label",):
            left[key] = sorted(set(left.get(key, [])) | {value})
        else:
            left[key] = value

    running = (
        shutil.which("firewall-cmd") is not None
        and _run("firewall-cmd", "--state", check=False).returncode == 0
    )
    for service in marker.get("firewalld_runtime", []):
        if running and _run("firewall-cmd", f"--remove-service={service}", check=False).returncode:
            keep("firewalld_runtime", service)
    for service in marker.get("firewalld_permanent", []):
        # With firewalld stopped, its permanent rules can still be changed, offline.
        command = ("firewall-cmd", "--permanent") if running else ("firewall-offline-cmd",)
        if (
            not shutil.which(command[0])
            or _run(*command, f"--remove-service={service}", check=False).returncode
        ):
            keep("firewalld_permanent", service)
    for port in marker.get("ufw", []):
        if not shutil.which("ufw") or _run("ufw", "delete", "allow", port, check=False).returncode:
            keep("ufw", port)
    if marker.get("selinux_switch"):
        if (
            not shutil.which("setsebool")
            or _run("setsebool", "-P", SELINUX_SWITCH, "0", check=False).returncode
        ):
            keep("selinux_switch", True)
    label = marker.get("port_label")
    if label:
        command = (
            ("semanage", "port", "-d", "-p", "tcp", str(PORT))
            if label == "added"
            else ("semanage", "port", "-m", "-t", label, "-p", "tcp", str(PORT))
        )
        if not shutil.which("semanage") or _run(*command, check=False).returncode:
            keep("port_label", label)
    return left


def stored_certificate(web: Web, apache: Apache, where: str = "domains") -> Optional[Path]:
    """mod_md keeps a new certificate in "staging" until Apache reloads, then in "domains"."""
    for store in apache.stores:
        path = store / where / web.name / "pubcert.pem"
        if path.is_file():
            return path
    return None


def served_certificate(name: str) -> Optional[bytes]:
    """What Apache hands someone asking for `name`, read without judging it: a test certificate
    isn't trusted, and the comparison with what mod_md stored is what counts here."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=name) as tls:
                return tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None


def first_certificate(pem: str) -> Optional[bytes]:
    match = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", pem, re.DOTALL)
    return ssl.PEM_cert_to_DER_cert(match.group(0)) if match else None


def wait_for_certificate(web: Web, apache: Apache, seconds: float = CERTIFICATE_SECONDS) -> bool:
    say("Getting a certificate from Let's Encrypt. This usually takes under a minute.")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        stored = stored_certificate(web, apache)
        if stored is not None:
            wanted = first_certificate(stored.read_text(encoding="utf-8", errors="replace"))
            if wanted is not None and served_certificate(web.name) == wanted:
                return True
        if stored_certificate(web, apache, "staging") is not None:
            _run("systemctl", "reload", apache.service)  # takes it from staging into use
            time.sleep(3)
            continue
        time.sleep(5)
    return False


def _proxy_secret(seconds: float = PAGE_SECONDS) -> str:
    """The tool makes it when it first starts with a public address."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if PROXY_SECRET.is_file() and not PROXY_SECRET.is_symlink():
            text = PROXY_SECRET.read_text(encoding="utf-8", errors="replace").strip()
            if _SECRET.fullmatch(text):
                return text
        time.sleep(2)
    raise Stop("The web interface didn't make its proxy secret. Run this installer again.")


def install(
    version: str,
    source: Optional[Path],
    new_machine: bool,
    web: Optional[Web] = None,
    ask: bool = False,
    dns_minutes: float = DNS_WAIT_MINUTES,
    lockdown: Optional[Choices] = None,
) -> int:
    """`lockdown` holds the answers to the three questions about SSH, when they aren't to be asked.
    With neither those nor a terminal, nothing about SSH is changed."""
    os.umask(0o022)  # what's installed has to be readable by the tool's account, and no more
    if os.geteuid() != 0:
        raise Stop("This has to be run as an administrator: sudo python3 -I install.py")
    if os.uname().machine != "x86_64":
        raise Stop(f"Only x86 machines are supported so far, and this is {os.uname().machine}.")
    if not Path("/run/systemd/system").is_dir():
        raise Stop("This needs a machine running systemd. This run changed nothing.")
    system = which_system(Path("/etc/os-release").read_text(encoding="utf-8"))
    if installed():
        say(f"Compromise Checker is already installed here. For a setup link: sudo {LINK_COMMAND}")
        if web is not None:
            say(
                "The web address wasn't applied: an installed machine can't be switched yet. To use"
                " one, install on a new machine."
            )
        return 0
    say(f"Installing Compromise Checker {version} on {system.name}.")
    with tempfile.TemporaryDirectory(prefix="compromise-checker-") as work:
        staged = Path(work)
        say("Checking the release's signature.")
        get_release(fetcher(source, version), version, RELEASE_KEY, staged)
        say("The signature is good.")
        can_look = shutil.which("ss") is not None
        ss_output = _run("ss", "-Hltnp", check=False).stdout if can_look else ""
        if not port_free(PORT) and not _service_running():
            holder = port_in_use(ss_output, PORT) or "Something else"
            raise Stop(
                f"{holder} is using port {PORT}, which this tool needs. This run changed nothing."
            )
        if not new_machine:
            passwd = Path("/etc/passwd").read_text(encoding="utf-8")
            mine = apache_for(system)
            ours = WEB_MARKER.exists() and not read_marker().get("apache_before")
            left = frozenset(
                (program, port)
                for program in (mine.service, "httpd")
                for port in ("80", "443")
                if ours
            )
            signs = signs_of_use(ss_output, passwd, os.environ.get("SUDO_USER"), left)
            if not can_look:
                signs.append(
                    Sign(
                        "the programs accepting connections couldn't be listed",
                        "The ss command isn't here, so something else could be running unseen.",
                    )
                )
            if signs:
                if not sys.stdin.isatty():
                    listed = "".join(f"\n  - {sign.what}" for sign in signs)
                    raise Stop(
                        "This machine looks like it's being used for something else, and there's"
                        f" nobody here to ask:{listed}\nRun this in a terminal. This run"
                        " changed nothing."
                    )
                ask_about_use(signs, input)
        if ask and web is None:
            web = ask_route(input)
        apache = apache_for(system) if web else None
        firewall = running_firewall() or ("ufw" if system.install is _APT else "firewalld")
        state = ssh_state(ss_output)
        kind = blocking_kind(state, firewall)
        asking = lockdown is None and sys.stdin.isatty()
        choices = choose_lockdown(state, firewall, input if asking else None, lockdown)
        if web is not None and apache is not None:
            problem = _web_ports_problem(apache)
            if problem:
                raise Stop(f"{problem} This run changed nothing.")
            stopped = False
            if WEB_MARKER.exists() and _service_running(apache.service):
                _run(
                    "systemctl", "stop", apache.service
                )  # an earlier run's, so the check can listen
                stopped = True
            try:
                _reachable(web, dns_minutes)
            except Stop:
                if stopped:
                    _run("systemctl", "start", apache.service, check=False)
                raise
            if not WEB_MARKER.exists():
                before = any(shutil.which(command) for command in ("apache2", "httpd"))
                write_marker({"name": web.name, "apache_before": bool(before)})
        _install_packages(system, apache.packages if apache else ())
        if apache is APACHE_APT and not read_marker().get("apache_before"):
            # Ubuntu starts Apache, with its welcome page, as soon as it's installed.
            _run("a2dissite", "-q", "000-default", check=False)
            _run("systemctl", "stop", apache.service, check=False)
        if web is None:
            _undo_web_address(apache_for(system))
        set_up_firewall(system, limit=choices.block and kind == "ufw")
        turn_updates_on(system)
        _run("systemctl", "stop", UNIT, check=False)  # one left by an install that didn't finish
        if not port_free(PORT):  # with that stopped, whatever's left isn't this tool
            raise Stop(f"Something else is using port {PORT}, which this tool needs.")
        uid = _make_account()
        _make_folders()
        _install_program(system, version, staged)
    address = web.address if web else ADDRESS
    _write_file(LINK_COMMAND, link_command(address), 0o755)
    _start_user_manager(uid)
    _write_file(UNIT_FILE, web_unit(uid, web.address if web else None), 0o644)
    _set_labels()
    _run("systemctl", "daemon-reload")
    _turn_sleep_off()
    _run("systemctl", "enable", "--now", UNIT)
    headers = None
    certified = True
    if web is not None and apache is not None:
        secret = _proxy_secret()
        headers = {"Host": web.name, PROXY_HEADER: secret, "X-Forwarded-For": "127.0.0.1"}
        _wait_for_page(ADDRESS, headers)
        _set_up_apache(web, apache, secret)
        certified = wait_for_certificate(web, apache)
    else:
        _wait_for_page(ADDRESS)
    link = new_link(address)
    apply_lockdown(choices, kind)
    _write_file(FINISHED, f"{version}\n", 0o644)
    if web is None:
        say("\nCompromise Checker is installed, and it only answers on this machine for now.")
        where = "in a browser on this machine"
    else:
        say(f"\nCompromise Checker is installed at {web.address}")
        where = "in a browser"
        if web.allowed:
            say(f"Only these addresses can reach it: {', '.join(web.allowed)}")
        if not certified:
            say(
                "\nLet's Encrypt hasn't given it a certificate yet, so the page won't work until it"
                " does. Apache keeps trying by itself, and starts using the certificate within the"
                " hour after it arrives. The usual cause is a firewall at the hosting provider that"
                " blocks port 80 or 443: let both in."
            )
    if link is None:
        say(f"\nThere's already an account, so sign in at {address}/login")
    else:
        say(
            f"\nOpen this link {where} to create the first account. It works once, within an"
            f" hour:\n\n  {link}\n"
            f"\nIf you lose it, or it runs out, this makes a new one: sudo {LINK_COMMAND}"
        )
    say("\nThe machine is meant to stay on and be used only for this.")
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Install Compromise Checker on this machine.")
    parser.add_argument(
        "--from",
        dest="source",
        type=Path,
        help="a folder holding the release, instead of downloading it; its files are checked just"
        " the same",
    )
    parser.add_argument(
        "--new-machine",
        action="store_true",
        help="skip the check for other use, on a machine just created for this",
    )
    parser.add_argument(
        "--web-address",
        metavar="NAME",
        help="the web address people will use, such as checker.example.org, instead of asking",
    )
    parser.add_argument(
        "--allow",
        metavar="ADDRESSES",
        default="",
        help="only these addresses or ranges can reach the page, apart by spaces",
    )
    parser.add_argument(
        "--ssh-passwords-off",
        action="store_true",
        help="turn off SSH logins with a password, instead of asking; only done if a key login has"
        " worked for an administrator account",
    )
    parser.add_argument(
        "--root-login-off",
        action="store_true",
        help="turn off SSH logins as root, instead of asking; only done if another administrator"
        " account has logged in",
    )
    parser.add_argument(
        "--block-login-failures",
        action="store_true",
        help="hold off addresses that keep trying to log in over SSH, instead of asking",
    )
    parser.add_argument("--test-certificates", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--dns-wait-minutes", type=float, default=DNS_WAIT_MINUTES, help=argparse.SUPPRESS
    )
    arguments = parser.parse_args(argv)
    if "@" in VERSION:
        print("This is the installer's source. Use the one from a release.", file=sys.stderr)
        return 2
    try:
        web = None
        if arguments.web_address:
            web = Web(
                web_name(arguments.web_address),
                allowed_ranges(arguments.allow),
                arguments.test_certificates,
            )
        elif arguments.allow:
            raise Stop("--allow only means something with --web-address.")
        ask = web is None and sys.stdin.isatty()
        wanted = Choices(
            arguments.ssh_passwords_off, arguments.root_login_off, arguments.block_login_failures
        )
        return install(
            VERSION,
            arguments.source,
            arguments.new_machine,
            web,
            ask,
            arguments.dns_wait_minutes,
            wanted if any(wanted) else None,
        )
    except Stop as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped. Run this installer again to continue.", file=sys.stderr)
        return 1
    except OSError as exc:  # a full disk, or a command that isn't here
        print(f"\nThis couldn't go on: {exc}\nRun this installer again.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
