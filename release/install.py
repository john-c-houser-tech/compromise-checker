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
import json  # noqa: E402
import os  # noqa: E402
import pwd  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import socket  # noqa: E402
import stat  # noqa: E402
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
    """Why the install can't go on, in words for the person running it. Nothing has been changed
    unless the message says so."""


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
        raise Stop("This release wasn't signed with the release key. Nothing has been installed.")
    prehashed = hashlib.blake2b(data, digest_size=64).digest()
    if not ed25519_good(key[10:], prehashed, blob[10:]):
        raise Stop("The release's signature doesn't match. Nothing has been installed.")
    if not ed25519_good(key[10:], blob[10:] + comment, whole):
        raise Stop("The release's signature has been altered. Nothing has been installed.")


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
            f" {manifest.get('version')}. Nothing has been installed."
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
    except (urllib.error.URLError, OSError) as exc:
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
            raise Stop(f"{name} isn't the file that was signed. Nothing has been installed.")
        (into / name).write_bytes(content)
    return listed


# --- This machine --------------------------------------------------------------------------------


class System(NamedTuple):
    name: str
    python: str  # the command for a Python this tool can run on
    packages: tuple
    install: tuple  # the command that installs packages


_PANGO_APT = ("libpango-1.0-0", "libpangoft2-1.0-0", "libharfbuzz-subset0")
# A new machine's own updates often hold the lock for its first minutes.
_APT_WAIT = ("-o", "DPkg::Lock::Timeout=300")
_APT = ("apt-get", *_APT_WAIT, "install", "-y", "-qq")
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


def web_unit(uid: int) -> str:
    """The web interface, as the tool's own account, able to write only to the tool's own folder.
    The running user manager is what its Check every day page sets the daily timer with. That's
    why people's homes are closed off by name: ProtectHome would hide /run/user too."""
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
ExecStart={PROGRAM}/current/bin/checker web
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


def link_command() -> str:
    """Shows a new first-setup link. Any before it stops working, so only the newest one is live."""
    return f"""#!/bin/sh
if [ "$(id -u)" != 0 ]; then
    echo "Run this with sudo: sudo {LINK_COMMAND}" >&2
    exit 1
fi
cd / || exit 1
# In a session of its own, so what runs as the tool's account can't type into this administrator's
# terminal.
exec setsid --wait runuser -u {ACCOUNT} -- env CHECKER_HOME={DATA} \\
    {PROGRAM}/current/bin/checker web-setup-link --address {ADDRESS} < /dev/null
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
        "\nso it should have a machine to itself. Nothing has been changed yet."
        f"\n\nTo go ahead anyway, type exactly: {GO_AHEAD}\nTo stop, press Enter.\n"
    )
    try:
        typed = answer()
    except (EOFError, KeyboardInterrupt):
        typed = ""
    if typed.strip() != GO_AHEAD:
        raise Stop("Stopped. Nothing has been changed.")


def _install_packages(system: System) -> None:
    say(f"Installing what the tool needs from {system.name}'s own packages.")
    if system.install is _APT:
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        _run("apt-get", *_APT_WAIT, "update", "-qq", env=env)
        _run(*system.install, *system.packages, env=env)
    else:
        _run(*system.install, *system.packages)


def _make_account() -> int:
    try:
        return pwd.getpwnam(ACCOUNT).pw_uid
    except KeyError:
        pass
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
    folder.mkdir(mode=0o700, exist_ok=True)
    if not stat.S_ISDIR(os.lstat(folder).st_mode):
        raise Stop(f"{folder} isn't a plain folder, so it's been left alone. Please look at it.")
    os.chown(folder, uid, gid, follow_symlinks=False)
    os.chmod(folder, 0o700)  # noqa: S103


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


def port_free(port: int) -> bool:
    """Whether the tool could listen here: the only way to be sure is to try."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as trial:
        trial.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            trial.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _service_running() -> bool:
    return _run("systemctl", "is-active", UNIT, check=False).stdout.strip() == "active"


def page_answers(address: str) -> bool:
    """Directly, whatever proxy the environment names."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"{address}/login", timeout=5):
            return True
    except (urllib.error.URLError, OSError):
        return False


def _wait_for_page(address: str, seconds: float = PAGE_SECONDS) -> None:
    """The service has to be running too: another program could be answering on the port."""
    say("Starting the web interface.")
    deadline = time.monotonic() + seconds
    while not (page_answers(address) and _service_running()):
        if time.monotonic() > deadline:
            log = _run("journalctl", "-u", UNIT, "-n", "30", "--no-pager", check=False).stdout
            raise Stop(
                f"The web interface didn't start. What it said:\n{log}\n"
                "Run this installer again once that's dealt with."
            )
        time.sleep(2)


def new_link() -> Optional[str]:
    """A new link, or None if there's already an account and so nothing to set up."""
    done = _run(str(LINK_COMMAND), check=False)
    if done.returncode == 0:
        lines = done.stdout.strip().splitlines()
        if lines and "/setup/" in lines[-1]:
            return lines[-1]
    elif "already an account" in done.stderr:
        return None
    raise Stop(
        f"The web interface is running, but a setup link couldn't be made:\n{done.stdout}"
        f"{done.stderr}\nRun this installer again once that's dealt with."
    )


def _set_labels() -> None:
    """Where SELinux is on, files keep the label of where they were made."""
    if shutil.which("restorecon"):
        paths = (PROGRAM, ACCOUNT_HOME, LINK_COMMAND, UNIT_FILE)
        _run("restorecon", "-R", *(str(path) for path in paths), check=False)


def install(version: str, source: Optional[Path], new_machine: bool) -> int:
    os.umask(0o022)  # what's installed has to be readable by the tool's account, and no more
    if os.geteuid() != 0:
        raise Stop("This has to be run as an administrator: sudo python3 -I install.py")
    if os.uname().machine != "x86_64":
        raise Stop(f"Only x86 machines are supported so far, and this is {os.uname().machine}.")
    if not Path("/run/systemd/system").is_dir():
        raise Stop("This needs a machine running systemd. Nothing has been changed.")
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
                f"{holder} is using port {PORT}, which this tool needs. Nothing has been changed."
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
                        f" nobody here to ask:{listed}\nRun this in a terminal. Nothing has been"
                        " changed."
                    )
                ask_about_use(signs, input)
        _install_packages(system)
        _run("systemctl", "stop", UNIT, check=False)  # one left by an install that didn't finish
        uid = _make_account()
        _make_folders()
        _install_program(system, version, staged)
    _write_file(LINK_COMMAND, link_command(), 0o755)
    _start_user_manager(uid)
    _write_file(UNIT_FILE, web_unit(uid), 0o644)
    _set_labels()
    _run("systemctl", "daemon-reload")
    _turn_sleep_off()
    _run("systemctl", "enable", "--now", UNIT)
    _wait_for_page(ADDRESS)
    link = new_link()
    _write_file(FINISHED, f"{version}\n", 0o644)
    say("\nCompromise Checker is installed, and it only answers on this machine for now.")
    if link is None:
        say(f"\nThere's already an account, so sign in at {ADDRESS}/login")
    else:
        say(
            "\nOpen this link in a browser on this machine to create the first account."
            " It works once, within an hour:"
            f"\n\n  {link}\n"
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
    arguments = parser.parse_args(argv)
    if "@" in VERSION:
        print("This is the installer's source. Use the one from a release.", file=sys.stderr)
        return 2
    try:
        return install(VERSION, arguments.source, arguments.new_machine)
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
