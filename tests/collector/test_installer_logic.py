"""The installer's own logic (release/install.py), standard library only and Python 3.9 compatible:
CI runs this with each system's own python3, which is what the installer first runs on. What signs
files with a real key is in tests/test_installer.py."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
_spec = importlib.util.spec_from_file_location("installer", ROOT / "release" / "install.py")
installer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(installer)

# RFC 8032, section 7.1: tests 1 and 2.
VECTORS = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]

UBUNTU = 'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n'
ROCKY = 'ID="rocky"\nVERSION_ID="9.8"\nPRETTY_NAME="Rocky Linux 9.8 (Blue Onyx)"\n'
MINT = 'PRETTY_NAME="Linux Mint 22"\nID=linuxmint\nVERSION_ID="22"\nID_LIKE="ubuntu debian"\n'


class Signatures(unittest.TestCase):
    def test_the_published_vectors_check_out(self):
        for public, message, signature in VECTORS:
            self.assertTrue(
                installer.ed25519_good(
                    bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
                )
            )

    def test_anything_changed_fails(self):
        public, message, signature = [bytes.fromhex(part) for part in VECTORS[1]]
        self.assertFalse(installer.ed25519_good(public, message + b"x", signature))
        self.assertFalse(installer.ed25519_good(public, b"\x73", signature))
        changed = bytes([signature[0] ^ 1]) + signature[1:]
        self.assertFalse(installer.ed25519_good(public, message, changed))
        changed = signature[:32] + bytes([signature[32] ^ 1]) + signature[33:]
        self.assertFalse(installer.ed25519_good(public, message, changed))
        other = bytes.fromhex(VECTORS[0][0])
        self.assertFalse(installer.ed25519_good(other, message, signature))

    def test_bad_lengths_and_points_fail_quietly(self):
        public, message, signature = [bytes.fromhex(part) for part in VECTORS[1]]
        self.assertFalse(installer.ed25519_good(public, message, signature[:-1]))
        self.assertFalse(installer.ed25519_good(public[:-1], message, signature))
        self.assertFalse(installer.ed25519_good(b"\xff" * 32, message, signature))

    def test_a_too_large_s_fails(self):
        public, message, signature = [bytes.fromhex(part) for part in VECTORS[1]]
        s = int.from_bytes(signature[32:], "little") + installer._L
        self.assertFalse(
            installer.ed25519_good(public, message, signature[:32] + s.to_bytes(32, "little"))
        )


def manifest(**changes):
    whole = {
        "schema": 1,
        "version": "1.2.3",
        "files": {
            "checker-1.2.3-py3-none-any.whl": {"sha256": "0" * 64, "size": 1},
            "requirements.lock": {"sha256": "1" * 64, "size": 2},
        },
    }
    whole.update(changes)
    return json.dumps(whole).encode()


class Manifest(unittest.TestCase):
    def test_a_good_one(self):
        listed = installer.read_manifest(manifest(), "1.2.3")
        self.assertEqual(listed["requirements.lock"].size, 2)

    def test_a_different_version_is_refused(self):
        with self.assertRaisesRegex(installer.Stop, "offered version 1.0.0"):
            installer.read_manifest(manifest(version="1.0.0"), "1.2.3")

    def test_what_is_wrong_is_refused(self):
        whl = "checker-1.2.3-py3-none-any.whl"
        lock = {"sha256": "1" * 64, "size": 2}
        for bad in (
            {"schema": 0},
            {"schema": 2},
            {"files": []},
            {"files": {whl: lock}},
            {"files": {"requirements.lock": lock}},
            {"files": {whl: lock, "requirements.lock": lock, "../evil": lock}},
            {"files": {whl: lock, "requirements.lock": {"sha256": "x", "size": 2}}},
            {"files": {whl: lock, "requirements.lock": {"sha256": "1" * 64, "size": True}}},
            {"files": {whl: lock, "requirements.lock": {"sha256": "1" * 64, "size": -1}}},
            {"files": {whl: lock, "requirements.lock": {"sha256": "1" * 64, "size": 2**40}}},
        ):
            with self.assertRaises(installer.Stop):
                installer.read_manifest(manifest(**bad), "1.2.3")
        with self.assertRaises(installer.Stop):
            installer.read_manifest(b"not json", "1.2.3")
        with self.assertRaises(installer.Stop):
            installer.read_manifest(b" " * 70000, "1.2.3")


class Systems(unittest.TestCase):
    def test_the_supported_ones(self):
        self.assertEqual(installer.which_system(UBUNTU).python, "python3")
        self.assertEqual(installer.which_system(ROCKY).python, "python3.12")

    def test_a_close_relative_is_refused_and_named(self):
        with self.assertRaisesRegex(installer.Stop, "Linux Mint 22"):
            installer.which_system(MINT)

    def test_an_older_version_is_refused(self):
        with self.assertRaises(installer.Stop):
            installer.which_system(UBUNTU.replace("24.04", "22.04"))


SS = """LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=1,fd=1))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=2,fd=3))
LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=2,fd=4))
LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=3,fd=7))
LISTEN 0 128 [::1]:631 [::]:* users:(("cupsd",pid=3,fd=8))
"""
WEB = 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=4,fd=6))\n'
PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sam:x:1000:1000:Sam:/home/sam:/bin/bash
"""


class SignsOfUse(unittest.TestCase):
    def test_a_new_machine_shows_nothing(self):
        self.assertEqual(installer.signs_of_use(SS, PASSWD, "sam"), [])

    def test_what_a_new_system_already_has_open_is_not_a_sign_of_use(self):
        new = (
            'LISTEN 0 4096 0.0.0.0:111 0.0.0.0:* users:(("rpcbind",pid=5,fd=4))\n'
            'LISTEN 0 4096 [::]:111 [::]:* users:(("rpcbind",pid=5,fd=6))\n'
            'LISTEN 0 4096 *:9090 *:* users:(("systemd",pid=1,fd=50))\n'
        )
        self.assertEqual(installer.signs_of_use(SS + new, PASSWD, "sam"), [])

    def test_the_same_program_on_another_port_still_is(self):
        other = 'LISTEN 0 4096 0.0.0.0:8000 0.0.0.0:* users:(("rpcbind",pid=5,fd=4))\n'
        self.assertEqual(len(installer.signs_of_use(SS + other, PASSWD, "sam")), 1)
        other = 'LISTEN 0 4096 *:8000 *:* users:(("systemd",pid=1,fd=50))\n'
        self.assertEqual(len(installer.signs_of_use(SS + other, PASSWD, "sam")), 1)

    def test_one_program_on_ipv4_and_ipv6_is_listed_once(self):
        both = WEB + 'LISTEN 0 511 [::]:443 [::]:* users:(("nginx",pid=4,fd=7))\n'
        self.assertEqual(len(installer.signs_of_use(SS + both, PASSWD, "sam")), 1)

    def test_a_program_others_can_reach_is_listed(self):
        signs = installer.signs_of_use(SS + WEB, PASSWD, "sam")
        self.assertEqual(len(signs), 1)
        self.assertIn("nginx", signs[0].what)
        self.assertIn("443", signs[0].what)

    def test_someone_else_with_a_login_is_listed(self):
        signs = installer.signs_of_use(SS, PASSWD, "alex")
        self.assertEqual([sign.what for sign in signs], ["sam has an account that can log in"])

    def test_an_account_with_no_login_is_not(self):
        passwd = PASSWD + "svc:x:1001:1001::/srv:/usr/sbin/nologin\n"
        self.assertEqual(installer.signs_of_use(SS, passwd, "sam"), [])

    def test_the_tools_port_being_taken_is_noticed(self):
        taken = 'LISTEN 0 128 127.0.0.1:8088 0.0.0.0:* users:(("other",pid=9,fd=3))\n'
        self.assertEqual(installer.port_in_use(SS + taken, 8088), "other")
        self.assertIsNone(installer.port_in_use(SS, 8088))

    def test_only_the_exact_sentence_goes_ahead(self):
        sign = [installer.Sign("x", "y")]
        installer.ask_about_use(sign, lambda: installer.GO_AHEAD)
        for typed in ("", "yes", installer.GO_AHEAD.lower()):
            with self.assertRaisesRegex(installer.Stop, "Nothing has been changed"):
                installer.ask_about_use(sign, lambda typed=typed: typed)

    def test_no_answer_stops(self):
        def nothing():
            raise EOFError

        with self.assertRaises(installer.Stop):
            installer.ask_about_use([installer.Sign("x", "y")], nothing)


class Units(unittest.TestCase):
    def test_the_web_interface_is_kept_to_its_own_folder_and_account(self):
        unit = installer.web_unit(990)
        self.assertIn(f"User={installer.ACCOUNT}", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn(f"ReadWritePaths={installer.ACCOUNT_HOME}", unit)
        self.assertIn("XDG_RUNTIME_DIR=/run/user/990", unit)
        self.assertIn("InaccessiblePaths=-/home -/root", unit)
        self.assertNotIn("ProtectHome", unit)  # would hide /run/user, and so the daily timer
        self.assertIn("/current/bin/checker web\n", unit)
        self.assertNotIn("--bind", unit)  # stays on this machine, the tool's own default

    def test_the_link_command_needs_an_administrator_and_uses_the_tools_account(self):
        command = installer.link_command()
        self.assertIn('"$(id -u)" != 0', command)
        self.assertIn(f"runuser -u {installer.ACCOUNT} --", command)
        self.assertIn("web-setup-link", command)


class Fetching(unittest.TestCase):
    def test_only_https_is_downloaded(self):
        with self.assertRaisesRegex(installer.Stop, "unprotected"):
            installer._read_url("http://example.com/x", 10)

    def test_a_local_file_larger_than_it_should_be_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "f"
            path.write_bytes(b"x" * 11)
            with self.assertRaisesRegex(installer.Stop, "larger"):
                installer._read_local(path, 10)
            self.assertEqual(installer._read_local(path, 11), b"x" * 11)


if __name__ == "__main__":
    unittest.main()
