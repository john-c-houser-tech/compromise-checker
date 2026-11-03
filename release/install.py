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
import hashlib  # noqa: E402
import http.client  # noqa: E402
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
        "Ubuntu 24.04", "python3", ("python3-venv", "iproute2", *_PANGO_APT), _APT
    ),
    ("ubuntu", "26.04"): System(
        "Ubuntu 26.04", "python3", ("python3-venv", "iproute2", *_PANGO_APT), _APT
    ),
    ("rocky", "9"): System(
        "Rocky Linux 9", "python3.12", ("python3.12", "iproute", "pango", "harfbuzz"), _DNF
    ),
    ("rocky", "10"): System("Rocky Linux 10", "python3", ("iproute", "pango", "harfbuzz"), _DNF),
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


def signs_of_use(ss_output: str, passwd: str, invoker: Optional[str]) -> list:
    """What suggests this machine does something else. Things only reachable from the machine
    itself, and the SSH that's probably how the person got here, aren't counted. Nor is the person,
    or an account a cloud provider makes. It's a nudge and not a guarantee: only TCP is looked at,
    since a normal desktop has UDP open anyway, and only accounts in /etc/passwd."""
    signs = []
    seen = set()
    for address, port, program in _listeners(ss_output):
        if _loopback(address) or program == "sshd" or (program, port) in _ON_A_NEW_SYSTEM:
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
    fresh = path.with_name(f".{path.name}.new")
    fresh.write_text(text, encoding="utf-8")
    fresh.chmod(mode)
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
    stores: tuple  # where mod_md may keep certificates, by its default for this system
    check: tuple  # the command that checks the settings


APACHE_APT = Apache(
    "apache2",
    ("apache2",),
    Path("/etc/apache2/sites-available/compromise-checker.conf"),
    (Path("/etc/apache2/md"),),
    ("apache2ctl", "-t"),
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
    return {str(ipaddress.ip_address(answer[4][0])) for answer in answers}


def name_problem(name: str, found: set, ours: list) -> Optional[str]:
    """Every address the name gives has to be this machine's: Let's Encrypt may use any of them."""
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
) -> None:
    found = lookup(name)
    if not found:
        records = [
            f"  {'A' if ipaddress.ip_address(address).version == 4 else 'AAAA'} record:"
            f" {name} -> {address}"
            for address in ours
        ]
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
    if problem:
        raise Stop(f"{problem} This run changed nothing.")
    say(f"{name} points to this machine.")


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


def apache_config(web: Web, secret: str) -> str:
    """Port 80 only redirects, apart from Let's Encrypt's checks, which mod_md answers before the
    redirect. Only Apache knows the secret it sends to the tool, so nothing else on this machine can
    pass for it."""
    if not _SECRET.fullmatch(secret):
        raise Stop("The tool's proxy secret isn't what it should be. Run this installer again.")
    who = " ".join(web.allowed) if web.allowed else ""
    access = f"Require ip {who}" if who else "Require all granted"
    staging = f"MDCertificateAuthority {STAGING_CA}\n" if web.test_certificates else ""
    return f"""# Written by the Compromise Checker installer, and replaced when it runs again.
Protocols http/1.1
MDCertificateAgreement accepted
{staging}MDomain {web.name}

<VirtualHost *:80>
    ServerName {web.name}
    Protocols http/1.1
    Redirect permanent / https://{web.name}/
</VirtualHost>

<VirtualHost *:443>
    ServerName {web.name}
    Protocols http/1.1
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    ProxyRequests Off
    ProxyPreserveHost On
    ProxyTimeout 300
    RequestHeader set {PROXY_HEADER} "{secret}"
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass / http://127.0.0.1:{PORT}/
    ProxyPassReverse / http://127.0.0.1:{PORT}/
    <Location />
        {access}
    </Location>
</VirtualHost>
"""


def reload_units(apache: Apache) -> dict:
    """mod_md renews certificates by itself, but Apache only uses a renewed one once it reloads."""
    service = f"""[Unit]
Description=Compromise Checker: let Apache use a renewed certificate

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reload {apache.service}
"""
    timer = """[Unit]
Description=Compromise Checker: let Apache use a renewed certificate, daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
"""
    folder = Path("/etc/systemd/system")
    return {folder / f"{RELOAD}.service": service, folder / f"{RELOAD}.timer": timer}


def _web_ports_problem(apache: Apache) -> Optional[str]:
    for port in (80, 443):
        if not port_free(port, "0.0.0.0") and not _service_holds_port(port, apache.service):  # noqa: S104
            return f"Something else is using port {port}, which the web address needs."
    return None


def _reachable(web: Web, dns_minutes: float) -> None:
    """Before anything changes: this machine has to be on the internet, and the name has to lead
    here. Whether a firewall outside lets Let's Encrypt in only shows when it tries."""
    ours = global_addresses(_run("ip", "-j", "address", check=False).stdout)
    if not ours:
        raise Stop(
            "This machine has no address on the internet: it's probably behind a router. People"
            " elsewhere couldn't reach it, and it couldn't get a certificate. Run this installer"
            " again and answer no, to use it from this machine only, or use a cloud server for a"
            " web address. This run changed nothing."
        )
    wait_for_name(web.name, ours, dns_minutes)


def _allow_proxy_under_selinux() -> None:
    """Apache is confined, and may only connect to web ports: the tool's port becomes one."""
    if _run("selinuxenabled", check=False).returncode != 0 or not shutil.which("semanage"):
        return
    listed = _run("semanage", "port", "-l", check=False).stdout
    if re.search(rf"^http_port_t\s+tcp\s+.*\b{PORT}\b", listed, re.MULTILINE):
        return
    say(f"Letting Apache reach the tool's port, {PORT}, under SELinux.")
    added = _run("semanage", "port", "-a", "-t", "http_port_t", "-p", "tcp", str(PORT), check=False)
    if added.returncode != 0:
        _run("semanage", "port", "-m", "-t", "http_port_t", "-p", "tcp", str(PORT))


def _open_firewall() -> None:
    if _run("firewall-cmd", "--state", check=False).returncode == 0:
        say("Opening ports 80 and 443 in the firewall.")
        _run("firewall-cmd", "--permanent", "--add-service=http", "--add-service=https")
        _run("firewall-cmd", "--reload")
    elif "Status: active" in _run("ufw", "status", check=False).stdout:
        say("Opening ports 80 and 443 in the firewall.")
        _run("ufw", "allow", "80/tcp")
        _run("ufw", "allow", "443/tcp")


def _set_up_apache(web: Web, apache: Apache, secret: str) -> None:
    say(f"Setting up Apache to give {web.name} a certificate and pass requests to the tool.")
    _allow_proxy_under_selinux()
    if apache is APACHE_APT:
        _run("a2enmod", "-q", "md", "ssl", "proxy", "proxy_http", "headers")
        _run("a2dismod", "-q", "-f", "http2", check=False)
        _run("a2dissite", "-q", "000-default", check=False)
    _write_file(apache.config, apache_config(web, secret), 0o600)
    if apache is APACHE_APT:
        _run("a2ensite", "-q", "compromise-checker")
    if shutil.which("restorecon"):
        _run("restorecon", str(apache.config), check=False)
    checked = _run(*apache.check, check=False)
    if checked.returncode != 0:
        raise Stop(
            f"Apache's settings didn't pass its own check:\n{plain_text(checked.stderr)}\n"
            "Run this installer again once that's dealt with."
        )
    for path, text in reload_units(apache).items():
        _write_file(path, text, 0o644)
    _run("systemctl", "daemon-reload")
    _run("systemctl", "enable", "--now", f"{RELOAD}.timer")
    _run("systemctl", "enable", apache.service)
    _run("systemctl", "restart", apache.service)
    _open_firewall()


def stored_certificate(web: Web, apache: Apache) -> Optional[Path]:
    for store in apache.stores:
        path = store / "domains" / web.name / "pubcert.pem"
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
    reloaded = False
    while time.monotonic() < deadline:
        stored = stored_certificate(web, apache)
        if stored is not None:
            if not reloaded:
                _run("systemctl", "reload", apache.service)
                reloaded = True
                time.sleep(2)
            wanted = first_certificate(stored.read_text(encoding="utf-8", errors="replace"))
            if wanted is not None and served_certificate(web.name) == wanted:
                return True
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
) -> int:
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
            signs = signs_of_use(ss_output, passwd, os.environ.get("SUDO_USER"))
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
        if web is not None and apache is not None:
            problem = _web_ports_problem(apache)
            if problem:
                raise Stop(f"{problem} This run changed nothing.")
            _reachable(web, dns_minutes)
        _install_packages(system, apache.packages if apache else ())
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
                "\nLet's Encrypt hasn't given it a certificate yet, so browsers will warn about it."
                " Don't use it until they stop. Apache keeps trying by itself. The usual cause is"
                " a firewall at the hosting provider that blocks port 80 or 443: let both in."
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
        return install(
            VERSION, arguments.source, arguments.new_machine, web, ask, arguments.dns_wait_minutes
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
