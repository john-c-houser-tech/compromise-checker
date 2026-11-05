"""The installer's signature check against files signed as minisign signs them, and against the
tool's own check of the same thing: the two must agree. Keys here are throwaway ones."""

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from test_pack_trust import Key

from checker import releases
from checker.packs.signing import SignatureError, public_key, verify

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("installer", ROOT / "release" / "install.py")
installer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(installer)


def _tool_agrees(data: bytes, signature: bytes, key: Key) -> bool:
    try:
        verify(data, signature, [public_key(key.line)])
    except SignatureError:
        return False
    return True


def _installer_agrees(data: bytes, signature: bytes, key: Key) -> bool:
    try:
        installer.check_signature(data, signature, key.line)
    except installer.Stop:
        return False
    return True


def test_the_shipped_key_is_the_tools():
    assert installer.RELEASE_KEY in releases.RELEASE_KEYS


def test_the_installer_knows_the_same_file_names():
    assert installer.MANIFEST == releases.MANIFEST
    assert installer.SIGNATURE == releases.SIGNATURE
    assert installer.REQUIREMENTS == releases.REQUIREMENTS
    assert installer.wheel_name("1.2.3") == releases.wheel_name("1.2.3")


def test_a_good_signature_is_good_to_both():
    key = Key()
    data = b"some bytes"
    signature = key.sign(data)
    assert _installer_agrees(data, signature, key)
    assert _tool_agrees(data, signature, key)


def test_the_two_agree_on_what_is_wrong():
    key, other = Key(), Key()
    data = b"some bytes"
    good = key.sign(data).decode()
    lines = good.split("\n")
    cases = [
        (b"other bytes", good.encode()),
        (data, other.sign(data)),
        (data, key.sign(data, algorithm=b"Ed")),
        (data, "\n".join([*lines[:2], "trusted comment: changed", *lines[3:]]).encode()),
        (data, "\n".join(lines[:3]).encode()),
        (data, b"not a signature"),
        (data, b""),
        (data, good.encode() + b"x" * 5000),
    ]
    for content, signature in cases:
        assert not _installer_agrees(content, signature, key)
        assert not _tool_agrees(content, signature, key)


def test_many_keys_and_messages_agree():
    """A hand-written Ed25519 has to give the library's answer."""
    for size in range(0, 40, 3):
        key = Key()
        data = bytes(range(size))
        assert _installer_agrees(data, key.sign(data), key)
        assert not _installer_agrees(data + b"x", key.sign(data), key)


def _library_says(public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def test_every_single_bit_changed_in_a_signature_is_refused_as_the_library_refuses_it():
    secret = Ed25519PrivateKey.generate()
    public = secret.public_key().public_bytes_raw()
    message = b"the release's hash"
    signature = secret.sign(message)
    assert installer.ed25519_good(public, message, signature)
    for bit in range(len(signature) * 8):
        forged = bytearray(signature)
        forged[bit // 8] ^= 1 << (bit % 8)
        assert not installer.ed25519_good(public, message, bytes(forged)), bit
        assert not _library_says(public, message, bytes(forged)), bit


def test_every_single_bit_changed_in_the_message_or_key_is_refused():
    secret = Ed25519PrivateKey.generate()
    public = secret.public_key().public_bytes_raw()
    message = b"the release's hash"
    signature = secret.sign(message)
    for bit in range(len(message) * 8):
        forged = bytearray(message)
        forged[bit // 8] ^= 1 << (bit % 8)
        assert not installer.ed25519_good(public, bytes(forged), signature), bit
    for bit in range(len(public) * 8):
        forged = bytearray(public)
        forged[bit // 8] ^= 1 << (bit % 8)
        assert not installer.ed25519_good(bytes(forged), message, signature), bit


def test_crafted_forgeries_are_refused():
    secret = Ed25519PrivateKey.generate()
    public = secret.public_key().public_bytes_raw()
    message = b"the release's hash"
    signature = secret.sign(message)
    r, s = signature[:32], int.from_bytes(signature[32:], "little")
    identity = (1).to_bytes(32, "little")  # the point that adds nothing
    p = 2**255 - 19
    forgeries = {
        "s plus the group order": r + (s + installer._L).to_bytes(32, "little"),
        "s of the group order": r + installer._L.to_bytes(32, "little"),
        "all zeros": bytes(64),
        "all ones": b"\xff" * 64,
        "identity R, zero s": identity + bytes(32),
        "R out of range": (p + 1).to_bytes(32, "little") + signature[32:],
        "s all ones": r + b"\xff" * 32,
    }
    for name, forged in forgeries.items():
        assert not installer.ed25519_good(public, message, forged), name
        assert not _library_says(public, message, forged), name


def test_the_shipped_key_is_a_proper_one():
    """A key of low order could vouch for anything, in the library as well as here, which is why it
    matters that the one key this ever checks against is fixed, and sound."""
    raw = base64.b64decode(installer.RELEASE_KEY)[10:]
    point = installer._decode_point(raw)
    assert point is not None
    identity = (0, 1, 1, 0)
    assert installer._same(installer._times(installer._L, point), identity)
    assert not installer._same(installer._times(8, point), identity)


def test_random_keys_and_messages_give_the_librarys_answer():
    for size in (0, 1, 31, 32, 33, 64, 65, 1000):
        secret = Ed25519PrivateKey.generate()
        public = secret.public_key().public_bytes_raw()
        message = os.urandom(size)
        signature = secret.sign(message)
        assert installer.ed25519_good(public, message, signature)
        assert _library_says(public, message, signature)
        other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        assert not installer.ed25519_good(other, message, signature)


@pytest.mark.skipif(shutil.which("minisign") is None, reason="needs minisign")
def test_a_signature_from_real_minisign(tmp_path):
    public, secret = tmp_path / "t.pub", tmp_path / "t.key"
    subprocess.run(
        ["minisign", "-G", "-W", "-f", "-p", public, "-s", secret],  # noqa: S607
        check=True,
        capture_output=True,
    )
    data = tmp_path / "release.json"
    data.write_bytes(b"the list")
    subprocess.run(
        ["minisign", "-S", "-s", secret, "-m", data, "-t", "Compromise Checker 1.2.3"],  # noqa: S607
        check=True,
        capture_output=True,
    )
    signature = (tmp_path / "release.json.minisig").read_bytes()
    line = public.read_text().splitlines()[1]
    installer.check_signature(b"the list", signature, line)
    with pytest.raises(installer.Stop):
        installer.check_signature(b"the list!", signature, line)


def _release(tmp_path: Path, key: Key, version: str = "1.2.3") -> Path:
    source = tmp_path / "source"
    source.mkdir()
    files = {installer.wheel_name(version): b"wheel", installer.REQUIREMENTS: b"list"}
    listed = {}
    for name, content in files.items():
        (source / name).write_bytes(content)
        listed[name] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
    manifest = json.dumps({"schema": 1, "version": version, "files": listed}).encode()
    (source / installer.MANIFEST).write_bytes(manifest)
    (source / installer.SIGNATURE).write_bytes(key.sign(manifest))
    return source


def _get(source: Path, key: Key, into: Path, version: str = "1.2.3"):
    into.mkdir()
    return installer.get_release(installer.fetcher(source, version), version, key.line, into)


def test_a_good_release_is_fetched(tmp_path):
    key = Key()
    source = _release(tmp_path, key)
    listed = _get(source, key, tmp_path / "into")
    assert set(listed) == {installer.wheel_name("1.2.3"), installer.REQUIREMENTS}
    assert (tmp_path / "into" / installer.REQUIREMENTS).read_bytes() == b"list"
    # The checked manifest and its signature too: the installer keeps them beside the version.
    assert (tmp_path / "into" / installer.MANIFEST).read_bytes() == (
        source / installer.MANIFEST
    ).read_bytes()
    assert (tmp_path / "into" / installer.SIGNATURE).exists()


def test_a_changed_file_is_refused_and_not_kept(tmp_path):
    key = Key()
    source = _release(tmp_path, key)
    (source / installer.REQUIREMENTS).write_bytes(b"LIST")
    with pytest.raises(installer.Stop, match="isn't the file that was signed"):
        _get(source, key, tmp_path / "into")
    assert not (tmp_path / "into" / installer.REQUIREMENTS).exists()


def test_a_release_signed_by_someone_else_is_refused_before_any_file_is_kept(tmp_path):
    key, other = Key(), Key()
    source = _release(tmp_path, other)
    with pytest.raises(installer.Stop, match="wasn't signed with the release key"):
        _get(source, key, tmp_path / "into")
    assert list((tmp_path / "into").iterdir()) == []


def test_an_older_signed_release_is_refused(tmp_path):
    key = Key()
    source = _release(tmp_path, key, version="1.0.0")
    with pytest.raises(installer.Stop, match="offered version 1.0.0"):
        _get(source, key, tmp_path / "into", version="1.2.3")


def test_the_source_form_refuses_to_run():
    if "@" in installer.VERSION:
        assert installer.main([]) == 2


def test_the_setup_link_command(tmp_path):
    env = {
        "CHECKER_HOME": str(tmp_path / "home"),
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "PATH": "/usr/bin:/bin",
    }

    def python(*words: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-P", *words],
            env=env,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    (tmp_path / "home").mkdir()
    done = python("-m", "checker", "web-setup-link")
    assert done.returncode == 1
    assert "no web interface has been run" in done.stderr
    assert not (tmp_path / "home" / "web.db").exists()

    (tmp_path / "home" / "web.db").touch()
    address = ("--address", "https://example.test")
    first = python("-m", "checker", "web-setup-link", *address)
    second = python("-m", "checker", "web-setup-link", *address)
    assert first.returncode == 0, first.stderr
    assert "https://example.test/setup/" in first.stdout
    assert first.stdout != second.stdout

    make_account = (
        "from pathlib import Path; import os\n"
        "from checker.web.app import configure\n"
        "configure(Path(os.environ['CHECKER_HOME']))\n"
        "from django.contrib.auth import get_user_model\n"
        "get_user_model().objects.create_user(username='sam', password='x')\n"
    )
    made = python("-c", make_account)
    assert made.returncode == 0, made.stderr
    done = python("-m", "checker", "web-setup-link", *address)
    assert done.returncode == 1
    assert "already an account" in done.stderr
    assert "/setup/" not in done.stdout


def test_the_web_service_runs_through_the_link_s_own_python():
    """So what the running tool starts, such as the daily timer, follows the link after an
    update."""
    unit = installer.web_unit(1001)
    assert "ExecStart=/opt/compromise-checker/current/bin/python -P -m checker web" in unit
    assert "current/bin/checker" not in unit


def test_the_update_units_watch_the_account_s_request_and_run_the_installed_code():
    units = installer.update_units()
    path = units[Path("/etc/systemd/system/compromise-checker-update.path")]
    service = units[Path("/etc/systemd/system/compromise-checker-update.service")]
    assert "PathExists=/var/lib/compromise-checker/data/updates/request" in path
    assert "Unit=compromise-checker-update.service" in path
    assert (
        "ExecStart=/opt/compromise-checker/current/bin/python -I -P -m checker.update_service"
        in service
    )
    assert "IPAddressDeny=any" in service and "IPAddressAllow=localhost" in service
    assert "ProtectSystem=full" in service and "StateDirectoryMode=0755" in service
    assert "CapabilityBoundingSet=CAP_DAC_OVERRIDE" in service
    assert "NoNewPrivileges=yes" in service and "ProtectHome=yes" in service
    assert "User=" not in service, "root: it writes /opt and restarts the web service"


def test_the_status_units_name_root_s_own_copy_of_the_script():
    units = installer.status_units()
    service = units[Path("/etc/systemd/system/compromise-checker-status.service")]
    assert "-I -S /opt/compromise-checker/machine_status.py" in service
    # It takes the console note off, so it may write that one file under a read-only /etc, and a
    # query made to spin can't hold it forever.
    assert "ProtectSystem=full" in service and "ReadWritePaths=-/etc/issue" in service
    assert "TimeoutStartSec=5min" in service


def test_the_console_note_carries_the_link_and_is_replaced_not_repeated(tmp_path):
    from checker import machine_status

    issue = tmp_path / "issue"
    issue.write_text("Rocky Linux 9\nKernel \\r on an \\m\n")
    installer.write_console_notice("https://checker.example.org/setup/first", issue)
    text = issue.read_text()
    assert text.startswith(installer.NOTICE_START) and "setup/first" in text
    assert text.endswith("Rocky Linux 9\nKernel \\r on an \\m\n")
    assert issue.stat().st_mode & 0o777 == 0o644
    installer.write_console_notice("https://checker.example.org/setup/second", issue)
    text = issue.read_text()
    assert text.count(installer.NOTICE_START) == 1 and "setup/first" not in text
    assert "setup/second" in text
    # The status service's marks are the same ones, so it can take the note off again.
    assert (installer.NOTICE_START, installer.NOTICE_END) == (
        machine_status.NOTICE_START,
        machine_status.NOTICE_END,
    )
    assert machine_status.without_notice(text) == "Rocky Linux 9\nKernel \\r on an \\m\n"
