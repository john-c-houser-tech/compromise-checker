"""The installer's own logic (release/install.py), standard library only and Python 3.9 compatible:
CI runs this with each system's own python3, which is what the installer first runs on. What signs
files with a real key is in tests/test_installer.py."""

import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
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

    def test_ssh_started_on_demand_is_not_a_sign_of_use(self):
        ssh = 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("systemd",pid=1,fd=40))\n'
        self.assertEqual(installer.signs_of_use(ssh, PASSWD, "sam"), [])

    def test_a_port_in_use_is_noticed_by_trying_it(self):
        with socket.socket() as other:
            other.bind(("127.0.0.1", 0))
            other.listen()
            self.assertFalse(installer.port_free(other.getsockname()[1]))
        with socket.socket() as other:
            other.bind(("127.0.0.1", 0))
            port = other.getsockname()[1]
        self.assertTrue(installer.port_free(port))

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
            with self.assertRaisesRegex(installer.Stop, "changed nothing"):
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


class Steps(unittest.TestCase):
    def _with_run(self, returncode, stdout="", stderr=""):
        done = subprocess.CompletedProcess([], returncode, stdout, stderr)
        real = installer._run
        installer._run = lambda *_, **__: done
        self.addCleanup(setattr, installer, "_run", real)

    def test_a_link_is_handed_over(self):
        self._with_run(0, "Open this\nhttp://127.0.0.1:8088/setup/abc\n")
        self.assertEqual(installer.new_link(), "http://127.0.0.1:8088/setup/abc")

    def test_an_existing_account_finishes_the_install(self):
        self._with_run(1, "checker: there's already an account, so\n")
        self.assertIsNone(installer.new_link())

    def test_no_link_is_never_taken_for_success(self):
        for result in (
            (0, "", ""),
            (0, "something else\n", ""),
            (1, "database is broken\n", ""),
            (0, "http://example.test/setup/abc\n", ""),
            (0, "http://127.0.0.1:8088/setup/abc\x1b[2J\n", ""),
        ):
            self._with_run(*result)
            with self.assertRaisesRegex(installer.Stop, "couldn't be made"):
                installer.new_link()

    def test_commands_run_from_a_folder_of_no_consequence(self):
        done = installer._run("pwd")
        self.assertEqual(done.stdout.strip(), "/")

    def test_a_linked_folder_is_left_alone(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "target"
            target.mkdir()
            target.chmod(0o755)
            link = Path(folder) / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(installer.Stop, "isn't a plain folder"):
                installer._own_folder(link, os.getuid(), os.getgid())
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_the_link_command_keeps_the_account_off_the_terminal(self):
        command = installer.link_command()
        self.assertIn("out=$(setsid --wait runuser", command)
        self.assertIn("< /dev/null 2>&1)", command)
        self.assertIn("tr -cd", command)
        self.assertIn("exit $code", command)

    def test_the_link_command_shows_only_plain_text_and_keeps_the_exit_status(self):
        with tempfile.TemporaryDirectory() as folder:
            fake = Path(folder) / "setsid"
            fake.write_text(
                "#!/bin/sh\nprintf 'good\\033[2Jtext\\n'\necho second >&2\nexit 7\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            text = installer.link_command().replace('"$(id -u)" != 0', "1 = 0")
            done = subprocess.run(
                ["/bin/sh", "-c", text],
                env={"PATH": f"{folder}:/usr/bin:/bin"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 7)
            self.assertEqual(done.stdout, "good[2Jtext\nsecond\n")

    def test_plain_text_takes_out_what_could_steer_a_terminal(self):
        self.assertEqual(installer.plain_text("a\x1b[2Jb\nc\x07"), "a[2Jb\nc")

    def test_apt_waits_for_a_lock_and_for_nothing_else(self):
        results = [
            subprocess.CompletedProcess(
                [], 100, "", "E: Could not get lock /var/lib/apt/lists/lock"
            ),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        real_run, real_sleep = installer._run, installer.time.sleep
        calls = []

        def run(*command, **more):
            calls.append(command)
            return results.pop(0)

        installer._run = run
        installer.time.sleep = lambda _: None
        self.addCleanup(setattr, installer, "_run", real_run)
        self.addCleanup(setattr, installer.time, "sleep", real_sleep)
        installer.run_apt(("apt-get", "update"), {})
        self.assertEqual(len(calls), 2)

        def broken(*command, check=True, **more):
            calls.append(command)
            if check:
                raise installer.Stop("broken")
            return subprocess.CompletedProcess([], 100, "", "E: no such package")

        calls.clear()
        installer._run = broken
        with self.assertRaisesRegex(installer.Stop, "broken"):
            installer.run_apt(("apt-get", "install", "x"), {})
        self.assertEqual(len(calls), 2)  # no waiting, and the second is what reports it

    def test_apt_is_asked_to_answer_in_english(self):
        seen = []

        def run(*command, env=None, **more):
            seen.append(env)
            return subprocess.CompletedProcess([], 0, "", "")

        real = installer._run
        installer._run = run
        self.addCleanup(setattr, installer, "_run", real)
        installer.run_apt(("apt-get", "update"), {"LANG": "de_DE.UTF-8", "LC_ALL": "de_DE.UTF-8"})
        self.assertEqual(seen[0]["LC_ALL"], "C")

    def test_an_account_this_installer_would_not_have_made_is_refused(self):
        home = str(installer.ACCOUNT_HOME)
        self.assertIsNone(installer.account_problem(990, home, "/usr/sbin/nologin"))
        self.assertIsNone(installer.account_problem(990, home, "/sbin/nologin"))
        self.assertIn("administrator", installer.account_problem(0, home, "/usr/sbin/nologin"))
        self.assertIn("/home/sam", installer.account_problem(990, "/home/sam", "/usr/sbin/nologin"))
        self.assertIn("can log in", installer.account_problem(990, home, "/bin/bash"))

    def test_who_holds_a_port(self):
        line = (
            "LISTEN 0 2048 127.0.0.1:8088 0.0.0.0:*"
            ' users:(("checker",pid=41,fd=5),("gunicorn",pid=42,fd=5))\n'
        )
        self.assertEqual(installer.holders(SS + line, 8088), {41, 42})
        self.assertEqual(installer.holders(SS, 8088), set())
        self.assertEqual(installer.holders(SS + line, 80), set())

    def test_the_port_counts_as_ours_only_if_our_process_holds_it(self):
        other = 'LISTEN 0 128 127.0.0.1:8088 0.0.0.0:* users:(("other",pid=99,fd=3))\n'
        for main_pid, listening, expected in (
            ("41\n", 'LISTEN 0 1 127.0.0.1:8088 0.0.0.0:* users:(("checker",pid=41,fd=5))\n', True),
            ("41\n", other, False),
            ("0\n", other, False),
            ("\n", other, False),
        ):

            def run(*command, main_pid=main_pid, listening=listening, **more):
                out = main_pid if command[0] == "systemctl" else listening
                return subprocess.CompletedProcess([], 0, out, "")

            real = installer._run
            installer._run = run
            try:
                self.assertEqual(installer._service_holds_port(8088), expected)
            finally:
                installer._run = real

    def test_a_server_that_does_not_speak_http_is_not_an_answer(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]

            def speak():
                connection, _ = server.accept()
                connection.sendall(b"SSH-2.0-OpenSSH\r\n")
                connection.close()

            thread = threading.Thread(target=speak)
            thread.start()
            self.assertFalse(installer.page_answers(f"http://127.0.0.1:{port}"))
            thread.join()


class BesideTheScript(unittest.TestCase):
    def test_a_file_planted_beside_it_never_runs(self):
        for flags in ([], ["-I"]):
            with tempfile.TemporaryDirectory() as folder:
                folder = Path(folder)
                source = (ROOT / "release" / "install.py").read_text(encoding="utf-8")
                (folder / "install.py").write_text(source, encoding="utf-8")
                marker = folder / "it-ran"
                for name in ("base64", "hashlib", "json", "re", "argparse", "typing", "socket"):
                    (folder / f"{name}.py").write_text(
                        f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8"
                    )
                done = subprocess.run(
                    [sys.executable, *flags, str(folder / "install.py")],
                    cwd="/",
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertFalse(marker.exists(), done.stderr)
                self.assertEqual(done.returncode, 2, done.stderr)  # the source form says so


IP_JSON = json.dumps(
    [
        {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}, {"local": "::1"}]},
        {
            "ifname": "eth0",
            "addr_info": [
                {"local": "172.232.170.46"},
                {"local": "10.0.0.5"},
                {"local": "2600:3c01::f03c:95ff:fe00:1"},
                {"local": "fe80::1"},
            ],
        },
    ]
)
HOME_JSON = json.dumps([{"ifname": "eth0", "addr_info": [{"local": "192.168.1.20"}]}])


class WebAddress(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        real = installer.WEB_MARKER
        installer.WEB_MARKER = Path(folder.name) / "web-address.json"
        self.addCleanup(setattr, installer, "WEB_MARKER", real)

    def test_a_name_is_tidied_and_checked(self):
        self.assertEqual(installer.web_name(" Checker.Example.ORG. "), "checker.example.org")
        for bad in (
            "",
            "checker",
            "203.0.113.10",
            "::1",
            "a..b.org",
            "-a.b.org",
            "a_b.example.org",
            "checker.example.org/x",
            "https://checker.example.org",
        ):
            with self.assertRaises(installer.Stop):
                installer.web_name(bad)

    def test_allowed_ranges(self):
        self.assertEqual(
            installer.allowed_ranges("203.0.113.10, 198.51.100.0/24 2001:db8::/56"),
            ("203.0.113.10/32", "198.51.100.0/24", "2001:db8::/56"),
        )
        self.assertEqual(installer.allowed_ranges("  "), ())
        for bad in ("not-an-address", "10.0.0.0/8", "2001:db8::/32", "0.0.0.0/0"):
            with self.assertRaises(installer.Stop):
                installer.allowed_ranges(bad)

    def test_only_addresses_the_internet_can_reach_count(self):
        self.assertEqual(
            installer.global_addresses(IP_JSON),
            ["172.232.170.46", "2600:3c01::f03c:95ff:fe00:1"],
        )
        self.assertEqual(installer.global_addresses(HOME_JSON), [])
        self.assertEqual(installer.global_addresses("not json"), [])

    def test_every_address_of_the_name_has_to_be_this_machine(self):
        ours = ["172.232.170.46", "2600:3c01::f03c:95ff:fe00:1"]
        self.assertIsNone(installer.name_problem("c.example.org", {"172.232.170.46"}, ours))
        problem = installer.name_problem("c.example.org", {"172.232.170.46", "203.0.113.9"}, ours)
        self.assertIn("203.0.113.9", problem)

    def test_waiting_for_the_name_to_appear(self):
        answers = [set(), set(), {"172.232.170.46"}]
        installer.wait_for_name(
            "c.example.org", ["172.232.170.46"], 1, lambda _: answers.pop(0), lambda _: None
        )
        self.assertEqual(answers, [])

    def test_a_name_that_never_appears_stops_in_time(self):
        clock = [0.0]
        real = installer.time.monotonic
        installer.time.monotonic = lambda: clock[0]
        self.addCleanup(setattr, installer.time, "monotonic", real)

        def pause(seconds):
            clock[0] += seconds

        with self.assertRaisesRegex(installer.Stop, "still doesn't point anywhere"):
            installer.wait_for_name("c.example.org", ["172.232.170.46"], 1, lambda _: set(), pause)

    def test_a_name_pointing_elsewhere_stops_at_once(self):
        with self.assertRaisesRegex(installer.Stop, "changed nothing"):
            installer.wait_for_name(
                "c.example.org", ["172.232.170.46"], 1, lambda _: {"203.0.113.9"}, lambda _: None
            )

    def test_the_route_question(self):
        answers = ["yes", "checker.example.org", "203.0.113.10"]
        web = installer.ask_route(lambda: answers.pop(0))
        self.assertEqual(web, installer.Web("checker.example.org", ("203.0.113.10/32",)))
        self.assertIsNone(installer.ask_route(lambda: "no"))
        self.assertIsNone(installer.ask_route(lambda: ""))

    def test_apache_is_told_exactly_what_it_needs(self):
        secret = "a" * 43
        web = installer.Web("checker.example.org", ())
        config = installer.apache_config(web, secret)
        self.assertIn("Protocols http/1.1", config)
        self.assertNotIn("h2", config)
        self.assertIn("MDomain checker.example.org", config)
        self.assertIn(f'RequestHeader set X-Checker-Proxy-Secret "{secret}"', config)
        self.assertIn("ProxyPass / http://127.0.0.1:8088/", config)
        self.assertIn("Require all granted", config)
        self.assertNotIn("MDCertificateAuthority", config)
        self.assertIn("Redirect permanent / https://checker.example.org/", config)
        self.assertIn("TraceEnable Off", config)
        self.assertEqual(config.count("CustomLog /dev/null common"), 2)
        self.assertIn("LogLevel authz_core:crit", config)
        self.assertIn("disablereuse=On", config)
        self.assertIn('Require expr "%{HTTP_HOST} =~ /^checker\\.example\\.org(:443)?$/i"', config)
        self.assertIn("<RequireAll>", config)
        self.assertIn("MDContactEmail webmaster@checker.example.org", config)
        self.assertNotIn("MDStoreDir", config)
        stored = installer.apache_config(web, secret, installer.APACHE_APT.store)
        self.assertIn("MDStoreDir /var/lib/apache2/md", stored)
        self.assertEqual(installer.APACHE_APT.stores, (installer.APACHE_APT.store,))

    def test_a_limit_and_test_certificates(self):
        web = installer.Web("checker.example.org", ("203.0.113.0/24",), True)
        config = installer.apache_config(web, "a" * 43)
        self.assertIn("Require ip 203.0.113.0/24", config)
        self.assertNotIn("Require all granted", config)
        self.assertIn(f"MDCertificateAuthority {installer.STAGING_CA}", config)

    def test_a_strange_secret_never_reaches_apaches_settings(self):
        web = installer.Web("checker.example.org", ())
        for bad in ("short", 'a" ' * 20, "a" * 40 + "\n"):
            with self.assertRaises(installer.Stop):
                installer.apache_config(web, bad)

    def test_files_are_never_readable_by_others_even_for_a_moment(self):
        seen = []
        real_open = installer.os.open

        def watching(path, flags, mode=0o777, **more):
            if str(path).endswith(".secret.conf.new"):
                seen.append(mode)
            return real_open(path, flags, mode, **more)

        installer.os.open = watching
        self.addCleanup(setattr, installer.os, "open", real_open)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "secret.conf"
            installer._write_file(target, "x", 0o600)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(seen, [0o600])

    def test_an_earlier_runs_apache_is_not_a_sign_of_use(self):
        apache = 'LISTEN 0 511 *:80 *:* users:(("apache2",pid=7,fd=4))\n'
        self.assertEqual(len(installer.signs_of_use(SS + apache, PASSWD, "sam")), 1)
        ours = frozenset({("apache2", "80"), ("apache2", "443")})
        self.assertEqual(installer.signs_of_use(SS + apache, PASSWD, "sam", ours), [])

    def test_names_in_the_hosts_file_are_noticed(self):
        hosts = (
            "127.0.0.1 localhost\n127.0.1.1 checker.example.org checker\n"
            "203.0.113.5 Checker.Example.Org # here\n"
        )
        self.assertEqual(installer.hosts_file_names(hosts, "checker.example.org"), ["203.0.113.5"])

    def test_a_name_leading_here_through_the_providers_network_is_accepted(self):
        installer.wait_for_name(
            "c.example.org", [], 1, lambda _: {"93.184.215.14"}, lambda _: None, lambda *_: True
        )
        with self.assertRaisesRegex(installer.Stop, "nothing sent there arrives"):
            installer.wait_for_name(
                "c.example.org",
                [],
                1,
                lambda _: {"93.184.215.14"},
                lambda _: None,
                lambda *_: False,
            )

    def test_every_address_of_the_name_is_tried(self):
        asked = []

        def leads(name, addresses):
            asked.append(set(addresses))
            return True

        installer.wait_for_name(
            "c.example.org",
            ["172.232.170.46"],
            1,
            lambda _: {"172.232.170.46", "93.184.215.14", "2606:4700::1111"},
            lambda _: None,
            leads,
        )
        self.assertEqual(asked, [{"93.184.215.14", "2606:4700::1111"}])

    def test_a_server_elsewhere_cannot_forge_the_answer_by_echoing(self):
        if os.geteuid() != 0:
            self.skipTest("port 80 needs root")
        real = installer._page_from
        installer._page_from = lambda address, name, path, seconds: path.rsplit("/", 1)[-1]
        self.addCleanup(setattr, installer, "_page_from", real)
        self.assertFalse(installer.leads_here("c.example.org", {"198.51.100.7"}, seconds=2))

    def test_the_real_answer_is_recognised(self):
        if os.geteuid() != 0:
            self.skipTest("port 80 needs root")
        self.assertTrue(installer.leads_here("c.example.org", {"127.0.0.1"}, seconds=5))

    def test_a_name_pointing_to_a_private_address_is_refused_without_trying(self):
        tried = []
        with self.assertRaisesRegex(installer.Stop, "can't be reached from the internet"):
            installer.wait_for_name(
                "c.example.org",
                [],
                1,
                lambda _: {"10.0.0.5"},
                lambda _: None,
                lambda *args: tried.append(args) or True,
            )
        self.assertEqual(tried, [])

    def test_cleanup_that_fails_stays_on_record(self):
        def run(*command, **more):
            failed = command[:2] == ("ufw", "delete") or command[0] == "semanage"
            return subprocess.CompletedProcess([], 1 if failed else 0, "", "")

        real = (installer._run, installer.shutil.which)
        installer._run = run
        installer.shutil.which = lambda name: "/usr/sbin/" + name
        try:
            left = installer._undo_openings(
                {"ufw": ["80/tcp"], "selinux_switch": True, "port_label": "added"}
            )
        finally:
            installer._run, installer.shutil.which = real
        self.assertEqual(left, {"ufw": ["80/tcp"], "port_label": "added"})

    def test_an_apache_that_was_never_installed_is_not_stopped(self):
        called = []

        def run(*command, check=True, **more):
            called.append(command)
            missing = command[:2] == ("systemctl", "cat")
            return subprocess.CompletedProcess([], 1 if missing else 0, "", "")

        real = (installer._run, installer.shutil.which)
        installer._run = run
        installer.shutil.which = lambda name: None
        try:
            installer.write_marker({"apache_before": False})
            installer._undo_web_address(installer.APACHE_APT)
        finally:
            installer._run, installer.shutil.which = real
        self.assertNotIn(("systemctl", "disable", "--now", "apache2"), called)
        self.assertFalse(installer.WEB_MARKER.exists())

    def test_a_silent_connection_cannot_hold_the_check_up(self):
        if os.geteuid() != 0:
            self.skipTest("port 80 needs root")
        result = []
        thread = threading.Thread(
            target=lambda: result.append(
                installer.leads_here("c.example.org", {"127.0.0.1"}, seconds=2)
            )
        )
        started = installer.time.monotonic()
        thread.start()
        installer.time.sleep(0.5)
        idle = socket.create_connection(("127.0.0.1", 80))  # says nothing, ever
        thread.join(15)
        stuck = thread.is_alive()
        idle.close()
        thread.join(30)
        self.assertFalse(stuck)
        self.assertLess(installer.time.monotonic() - started, 20)

    def test_a_loopback_hosts_entry_for_the_name_is_found(self):
        hosts = "127.0.1.1 checker.example.org checker\n"
        self.assertEqual(
            installer.hosts_file_names(hosts, "checker.example.org", loopback=True), ["127.0.1.1"]
        )
        self.assertEqual(installer.hosts_file_names(hosts, "checker.example.org"), [])

    def test_taking_the_web_address_down_undoes_only_what_this_installer_did(self):
        called = []
        real = (installer._run, installer.shutil.which, installer.WEB_MARKER)
        with tempfile.TemporaryDirectory() as folder:
            installer.WEB_MARKER = Path(folder) / "web-address.json"

            def run(*command, **more):
                called.append(command)
                return subprocess.CompletedProcess([], 0, "active\n", "")

            installer._run = run
            installer.shutil.which = lambda name: "/usr/sbin/" + name
            fake = installer.APACHE_DNF._replace(config=Path(folder) / "cc.conf")
            try:
                installer.write_marker(
                    {
                        "apache_before": True,
                        "firewalld_permanent": ["https"],
                        "firewalld_runtime": ["https"],
                        "selinux_switch": False,
                        "port_label": "added",
                    }
                )
                (Path(folder) / "cc.conf").write_text("x")
                installer._undo_web_address(fake)
                self.assertFalse((Path(folder) / "cc.conf").exists())
                self.assertFalse(installer.WEB_MARKER.exists())
            finally:
                installer._run, installer.shutil.which, installer.WEB_MARKER = real
        text = str(called)
        self.assertNotIn("'disable', '--now', 'httpd'", text)  # it was there before
        self.assertIn("'--permanent', '--remove-service=https'", text)
        self.assertIn("'firewall-cmd', '--remove-service=https'", text)
        self.assertNotIn("--remove-service=http'", text)  # not opened by this installer
        self.assertNotIn("--reload", text)  # would drop rules made for the running session
        self.assertNotIn("setsebool", text)
        self.assertIn("'semanage', 'port', '-d', '-p', 'tcp', '8088'", text)

    def test_a_failed_stop_keeps_the_record_for_another_try(self):
        def run(*command, check=True, **more):
            if command[:3] == ("systemctl", "disable", "--now") and "httpd" in command and check:
                raise installer.Stop("couldn't stop it")
            return subprocess.CompletedProcess([], 0, "", "")

        real = (installer._run, installer.shutil.which)
        installer._run = run
        installer.shutil.which = lambda name: None
        try:
            with tempfile.TemporaryDirectory() as folder:
                fake = installer.APACHE_DNF._replace(config=Path(folder) / "cc.conf")
                installer.write_marker({"apache_before": False})
                with self.assertRaises(installer.Stop):
                    installer._undo_web_address(fake)
                self.assertTrue(installer.WEB_MARKER.exists())
        finally:
            installer._run, installer.shutil.which = real

    def test_the_firewall_note_is_made_before_the_change(self):
        order = []

        def run(*command, **more):
            if command[:2] == ("firewall-cmd", "--state"):
                return subprocess.CompletedProcess([], 0, "running", "")
            if "--query-service=http" in command[-1] or "--query-service=https" in command[-1]:
                return subprocess.CompletedProcess([], 1, "no", "")
            if "--add-service=https" in command[-1]:
                order.append(("change", installer.read_marker()))
                raise installer.Stop("firewall broke")
            return subprocess.CompletedProcess([], 0, "", "")

        real = (installer._run, installer.shutil.which)
        installer._run = run
        installer.shutil.which = lambda name: "/usr/bin/" + name
        try:
            with self.assertRaises(installer.Stop):
                installer._open_firewall()
        finally:
            installer._run, installer.shutil.which = real
        self.assertIn("https", order[0][1]["firewalld_runtime"])

    def test_someone_elses_apache_is_not_taken_over(self):
        real = (installer.port_free_everywhere, installer._service_holds_port)
        installer.port_free_everywhere = lambda port: False
        installer._service_holds_port = lambda port, unit=None: True
        try:
            self.assertIn("Something else", installer._web_ports_problem(installer.APACHE_APT))
            installer.write_marker({"apache_before": False})
            self.assertIsNone(installer._web_ports_problem(installer.APACHE_APT))
        finally:
            installer.port_free_everywhere, installer._service_holds_port = real

    def test_a_listener_on_ipv6_alone_is_noticed(self):
        try:
            other = socket.socket(socket.AF_INET6)
        except OSError:
            self.skipTest("no IPv6 here")
        with other:
            other.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                other.bind(("::", 0))
            except OSError:
                self.skipTest("no IPv6 here")
            other.listen()
            port = other.getsockname()[1]
            self.assertTrue(installer.port_free(port, "0.0.0.0"))
            self.assertFalse(installer.port_free_everywhere(port))

    def test_selinux_port_types(self):
        listing = "http_port_t tcp 80, 81, 443\nsome_port_t tcp 8088, 9000\nother_t udp 8088\n"
        self.assertEqual(installer.port_label(listing, 8088), "some_port_t")
        self.assertIsNone(installer.port_label("http_port_t tcp 80\n", 8088))

    def test_only_a_rule_letting_everyone_in_counts(self):
        status = (
            "Status: active\n\nTo Action From\n-- ------ ----\n"
            "80/tcp ALLOW 203.0.113.10\n443/tcp ALLOW Anywhere\n"
        )
        self.assertFalse(installer.ufw_allows_anyone(status, "80/tcp"))
        self.assertTrue(installer.ufw_allows_anyone(status, "443/tcp"))

    def test_the_daily_reload(self):
        units = installer.reload_units(installer.APACHE_APT)
        texts = "".join(units.values())
        self.assertIn("ExecStart=/usr/bin/systemctl reload apache2", texts)
        self.assertIn("OnCalendar=hourly", texts)
        self.assertNotIn("[Path]", texts)  # SELinux on Rocky 9 won't let systemd watch the file

    def test_the_tool_is_told_its_public_address(self):
        unit = installer.web_unit(990, "https://checker.example.org")
        self.assertIn("checker web --public-url https://checker.example.org\n", unit)

    def test_the_link_is_for_the_web_address(self):
        self.assertIn(
            "--address https://checker.example.org",
            installer.link_command("https://checker.example.org"),
        )

    def test_only_a_link_to_the_web_address_is_passed_on(self):
        good = "https://checker.example.org/setup/abc"
        done = subprocess.CompletedProcess([], 0, f"Open this\n{good}\n", "")
        real = installer._run
        installer._run = lambda *_, **__: done
        self.addCleanup(setattr, installer, "_run", real)
        self.assertEqual(installer.new_link("https://checker.example.org"), good)
        with self.assertRaises(installer.Stop):
            installer.new_link("https://other.example.org")

    def test_selinux_lets_apache_relay_and_reach_the_port(self):
        called = []

        def run(*command, **more):
            called.append(command)
            out = {
                "getsebool": "httpd_graceful_shutdown --> off\n",
                "semanage": "http_port_t tcp 80, 443\n",
            }
            return subprocess.CompletedProcess([], 0, out.get(command[0], ""), "")

        real_run, real_which = installer._run, installer.shutil.which
        installer._run = run
        installer.shutil.which = lambda name: "/usr/sbin/" + name
        self.addCleanup(setattr, installer, "_run", real_run)
        self.addCleanup(setattr, installer.shutil, "which", real_which)
        installer._allow_proxy_under_selinux()
        self.assertIn(("setsebool", "-P", "httpd_graceful_shutdown", "1"), called)
        self.assertIn(("semanage", "port", "-a", "-t", "http_port_t", "-p", "tcp", "8088"), called)
        self.assertNotIn("httpd_can_network_connect", str(called))
        self.assertNotIn("httpd_can_network_relay", str(called))

    def test_commands_a_system_lacks_are_not_called(self):
        called = []
        real_run, real_which = installer._run, installer.shutil.which
        installer._run = lambda *command, **more: called.append(command)
        installer.shutil.which = lambda _: None
        self.addCleanup(setattr, installer, "_run", real_run)
        self.addCleanup(setattr, installer.shutil, "which", real_which)
        installer._allow_proxy_under_selinux()
        installer._open_firewall()
        self.assertEqual(called, [])

    def test_the_first_certificate_in_a_chain(self):
        self.assertIsNone(installer.first_certificate("nothing here"))


SS_SSH = (
    'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=700,fd=3))\n'
    'LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=700,fd=4))\n'
    'LISTEN 0 128 127.0.0.1:2222 0.0.0.0:* users:(("sshd",pid=701,fd=3))\n'
    'LISTEN 0 4096 0.0.0.0:111 0.0.0.0:* users:(("rpcbind",pid=600,fd=4))\n'
    'LISTEN 0 4096 *:9090 *:* users:(("systemd",pid=1,fd=60))\n'
)

UFW_ACTIVE = (
    "Status: active\n\nTo                         Action      From\n"
    "--                         ------      ----\n"
    "22/tcp                     ALLOW       Anywhere\n"
    "80/tcp                     ALLOW       Anywhere\n"
    "5432                       ALLOW       10.0.0.0/8\n"
    "22/tcp (v6)                ALLOW       Anywhere (v6)\n"
    "5432 (v6)                  ALLOW       Anywhere (v6)\n"
)

FIREWALLD_LISTING = (
    "public (active)\n  target: default\n  interfaces: eth0\n"
    "  services: cockpit dhcpv6-client https ssh\n  ports: 2200/tcp 8080/tcp\n"
    "  forward: yes\n  rich rules: \n"
)

ROCKY_9 = installer.SYSTEMS[("rocky", "9")]
UBUNTU_24 = installer.SYSTEMS[("ubuntu", "24.04")]


class FakeMachine:
    """Answers the commands the lockdown steps run, and keeps them in order."""

    def __init__(self, ss=SS_SSH, ufw="Status: inactive\n", firewalld=False, listen=""):
        self.ss, self.ufw, self.firewalld, self.listen = ss, ufw, firewalld, listen
        self.offline = {"cockpit", "ssh", "dhcpv6-client"}
        self.called = []

    def __call__(self, *command, **more):
        self.called.append(command)
        out, code = "", 0
        if command[0] == "ss":
            out = self.ss
        elif command[:2] == ("ufw", "status"):
            out = self.ufw
        elif command[:2] == ("ufw", "--force"):
            self.ufw = "Status: active\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW Anywhere\n"
        elif command[:2] == ("firewall-cmd", "--state"):
            code = 0 if self.firewalld else 252
        elif command[:2] == ("systemctl", "show"):
            out = self.listen
        elif command[:3] == ("systemctl", "enable", "--now") and command[3] == "firewalld":
            self.firewalld = True
        elif command[:2] == ("systemctl", "stop") and command[2] == "firewalld":
            self.firewalld = False
        elif command[0] == "firewall-offline-cmd":
            if command[1] == "--get-default-zone":
                out = "public\n"
            else:
                word, _, value = command[-1].partition("=")
                if word in ("--query-service", "--query-port"):
                    code = 0 if value in self.offline else 1
                elif word in ("--add-service", "--add-port"):
                    self.offline.add(value)
                elif word == "--remove-service":
                    self.offline.discard(value)
        elif command[0] == "firewall-cmd" and command[-1] == "--list-all":
            services = " ".join(sorted(s for s in self.offline if "/" not in s))
            ports = " ".join(sorted(p for p in self.offline if "/" in p))
            out = f"public (active)\n  services: {services}\n  ports: {ports}\n"
        elif command[:2] == ("firewall-cmd", "--get-default-zone"):
            out = "public\n"
        return subprocess.CompletedProcess(list(command), code, out, "")

    def index(self, *command):
        return self.called.index(command)


class Lockdown(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        real = (installer.LOCKDOWN_MARKER, installer._run, installer.shutil.which, installer.say)
        installer.LOCKDOWN_MARKER = Path(folder.name) / "lockdown.json"
        installer.shutil.which = lambda name: "/usr/sbin/" + name
        self.said = []
        installer.say = self.said.append

        def restore():
            (
                installer.LOCKDOWN_MARKER,
                installer._run,
                installer.shutil.which,
                installer.say,
            ) = real

        self.addCleanup(restore)

    def machine(self, **more):
        fake = FakeMachine(**more)
        installer._run = fake
        return fake

    def test_ssh_ports_are_those_other_machines_can_reach(self):
        self.assertEqual(installer.ssh_ports(SS_SSH), ["22"])
        held = 'LISTEN 0 4096 *:22 *:* users:(("systemd",pid=1,fd=200))\n'
        self.assertEqual(installer.ssh_ports(held), [])
        self.assertEqual(installer.ssh_ports(held, "[::]:22 (Stream)\n"), ["22"])
        self.assertEqual(installer.ssh_ports(SS_SSH, "[::]:9091 (Stream)\n"), ["22"])

    def test_what_else_an_active_ufw_lets_in(self):
        self.assertEqual(installer.ufw_extras(UFW_ACTIVE, ["22"]), ["5432"])
        limited = "Status: active\n\n22/tcp                     LIMIT IN    Anywhere\n"
        self.assertEqual(installer.ufw_extras(limited, ["22"]), [])
        self.assertEqual(installer.ufw_extras(limited, []), ["22/tcp"])
        named = (
            "Status: active\n\nTo Action From\n-- ------ ----\n"
            "OpenSSH                    ALLOW       Anywhere\n"
            "22                         ALLOW       Anywhere\n"
            "5432/tcp on eth1           ALLOW       10.0.0.0/8\n"
        )
        self.assertEqual(installer.ufw_extras(named, ["22"]), ["5432/tcp on eth1"])

    def test_what_else_a_firewalld_zone_lets_in(self):
        self.assertEqual(
            installer.firewalld_extras(FIREWALLD_LISTING, ["22", "2200"]), ["cockpit", "8080/tcp"]
        )
        ruled = (
            '  services: ssh\n  rich rules: rule family="ipv4" source address="10.0.0.0/8" accept\n'
        )
        self.assertEqual(installer.firewalld_extras(ruled, ["22"]), ["rules of its own"])

    def test_ufw_lets_ssh_in_before_it_is_turned_on(self):
        fake = self.machine()
        installer.set_up_firewall(UBUNTU_24)
        self.assertLess(
            fake.index("ufw", "prepend", "allow", "22/tcp"), fake.index("ufw", "--force", "enable")
        )
        self.assertLess(
            fake.index("ufw", "default", "deny", "incoming"), fake.index("ufw", "--force", "enable")
        )
        self.assertEqual(installer.read_lockdown(), {"firewall": "ufw"})
        self.assertIn("SSH can still be reached, on port 22.", self.said)

    def test_ufw_can_limit_ssh_connections_instead(self):
        fake = self.machine()
        installer.set_up_firewall(UBUNTU_24, limit=True)
        self.assertIn(("ufw", "prepend", "limit", "22/tcp"), fake.called)
        self.assertNotIn(("ufw", "prepend", "allow", "22/tcp"), fake.called)

    def test_firewalld_is_set_up_before_it_starts(self):
        two = SS_SSH + 'LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=700,fd=5))\n'
        fake = self.machine(ss=two)
        installer.set_up_firewall(ROCKY_9)
        start = fake.index("systemctl", "enable", "--now", "firewalld")
        self.assertLess(
            fake.index("firewall-offline-cmd", "--zone=public", "--remove-service=cockpit"), start
        )
        self.assertLess(
            fake.index("firewall-offline-cmd", "--zone=public", "--add-port=2200/tcp"), start
        )
        self.assertNotIn("cockpit", fake.offline)
        self.assertIn("dhcpv6-client", fake.offline)
        self.assertEqual(installer.read_lockdown(), {"firewall": "firewalld"})
        self.assertFalse(any("also lets in" in line for line in self.said))

    def test_someone_elses_firewall_keeps_its_rules(self):
        fake = self.machine(ufw=UFW_ACTIVE)
        installer.set_up_firewall(UBUNTU_24)
        self.assertFalse(any(command[:2] == ("ufw", "default") for command in fake.called))
        self.assertFalse(any(command[:2] == ("ufw", "--force") for command in fake.called))
        self.assertEqual(installer.read_lockdown(), {})
        self.assertTrue(any("5432" in line and "also lets in" in line for line in self.said))
        self.assertTrue(any("already running" in line for line in self.said))

    def test_someone_elses_firewalld_is_not_stopped(self):
        fake = self.machine(firewalld=True)
        installer.set_up_firewall(ROCKY_9)
        self.assertNotIn(("systemctl", "stop", "firewalld"), fake.called)
        self.assertFalse(any(command[0] == "firewall-offline-cmd" for command in fake.called))
        self.assertTrue(any("cockpit" in line and "also lets in" in line for line in self.said))

    def test_an_earlier_runs_firewall_is_set_up_again(self):
        installer.note_lockdown("firewall", "firewalld")
        fake = self.machine(firewalld=True)
        installer.set_up_firewall(ROCKY_9)
        stop = fake.index("systemctl", "stop", "firewalld")
        self.assertLess(stop, fake.index("firewall-offline-cmd", "--get-default-zone"))
        self.assertNotIn("cockpit", fake.offline)
        self.assertFalse(any("already running" in line for line in self.said))

    def test_the_firewall_note_comes_before_the_firewall(self):
        noted = []
        fake = self.machine()

        def run(*command, **more):
            if command[:2] == ("ufw", "default"):
                noted.append(installer.read_lockdown())
            return fake(*command, **more)

        installer._run = run
        installer.set_up_firewall(UBUNTU_24)
        self.assertEqual(noted[0], {"firewall": "ufw"})

    def test_without_ssh_nothing_is_let_in_for_it(self):
        fake = self.machine(ss="")
        installer.set_up_firewall(UBUNTU_24)
        self.assertFalse(any(command[:2] == ("ufw", "allow") for command in fake.called))
        self.assertIn(("ufw", "--force", "enable"), fake.called)
        self.assertTrue(any("SSH isn't running here" in line for line in self.said))


APT_ON = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'


class Updates(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        names = ("APT_UPDATES", "DNF_UPDATES", "DNF_DROP_IN", "_run", "say")
        real = {name: getattr(installer, name) for name in names}
        real_which = installer.shutil.which
        installer.APT_UPDATES = self.folder / "52compromise-checker-updates"
        installer.DNF_UPDATES = self.folder / "automatic-compromise-checker.conf"
        installer.DNF_DROP_IN = self.folder / "drop-in" / "compromise-checker.conf"
        installer.shutil.which = lambda name: None
        self.said = []
        installer.say = self.said.append
        self.called = []

        def restore():
            for name, value in real.items():
                setattr(installer, name, value)
            installer.shutil.which = real_which

        self.addCleanup(restore)

    def apt(self, before: str, after: str = APT_ON, reboot: str = ""):
        def run(*command, **more):
            self.called.append(command)
            out = ""
            if command[0] == "apt-config":
                out = after if installer.APT_UPDATES.exists() else before
                out += reboot
            return subprocess.CompletedProcess(list(command), 0, out, "")

        installer._run = run

    def test_apt_settings_are_read(self):
        self.assertTrue(installer.apt_updates_on(APT_ON))
        self.assertFalse(installer.apt_updates_on(APT_ON.replace('Upgrade "1"', 'Upgrade "0"')))
        self.assertFalse(installer.apt_updates_on('APT::Periodic::Update-Package-Lists "1";\n'))
        self.assertEqual(
            installer.apt_value(
                'Unattended-Upgrade::Automatic-Reboot "false";\n',
                "Unattended-Upgrade::Automatic-Reboot",
            ),
            "false",
        )

    def test_ubuntu_updates_are_turned_on(self):
        self.apt("")
        installer.turn_updates_on(UBUNTU_24)
        self.assertEqual(installer.APT_UPDATES.read_text(), installer.APT_UPDATES_TEXT)
        self.assertIn(
            ("systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer"),
            self.called,
        )
        self.assertTrue(any("Turning on automatic security updates" in line for line in self.said))

    def test_ubuntu_updates_already_on_are_left(self):
        self.apt(APT_ON)
        installer.turn_updates_on(UBUNTU_24)
        self.assertFalse(installer.APT_UPDATES.exists())
        self.assertTrue(any("already install by themselves" in line for line in self.said))

    def test_a_later_file_turning_them_off_stops_the_install(self):
        self.apt("", after="")
        with self.assertRaisesRegex(installer.Stop, "didn't turn on"):
            installer.turn_updates_on(UBUNTU_24)

    def test_a_restart_the_owner_set_is_mentioned(self):
        self.apt(APT_ON, reboot='Unattended-Upgrade::Automatic-Reboot "true";\n')
        installer.turn_updates_on(UBUNTU_24)
        self.assertTrue(any("restart the machine" in line for line in self.said))

    def dnf(self, enabled: str):
        def run(*command, **more):
            self.called.append(command)
            out = enabled if command[:2] == ("systemctl", "is-enabled") else ""
            return subprocess.CompletedProcess(list(command), 0, out, "")

        installer._run = run

    def test_rocky_gets_security_updates_from_its_own_settings(self):
        self.dnf("disabled\n")
        installer.turn_updates_on(ROCKY_9)
        settings = installer.DNF_UPDATES.read_text()
        self.assertIn("upgrade_type = security\n", settings)
        self.assertIn("apply_updates = yes\n", settings)
        self.assertIn(
            "ExecStart=\nExecStart=/usr/bin/dnf-automatic"
            " /etc/dnf/automatic-compromise-checker.conf --timer --installupdates\n",
            installer.DNF_DROP_IN.read_text(),
        )
        self.assertLess(
            self.called.index(("systemctl", "daemon-reload")),
            self.called.index(("systemctl", "enable", "--now", installer.DNF_TIMER)),
        )

    def test_rockys_own_automatic_updates_are_left(self):
        self.dnf("enabled\n")
        installer.turn_updates_on(ROCKY_9)
        self.assertFalse(installer.DNF_UPDATES.exists())
        self.assertFalse(installer.DNF_DROP_IN.exists())

    def test_an_earlier_runs_rocky_updates_are_set_again(self):
        installer.DNF_DROP_IN.parent.mkdir()
        installer.DNF_DROP_IN.write_text("old\n")
        self.dnf("enabled\n")
        installer.turn_updates_on(ROCKY_9)
        self.assertIn("--installupdates", installer.DNF_DROP_IN.read_text())

    def test_the_settings_never_restart_the_machine(self):
        for text in (installer.APT_UPDATES_TEXT, installer.DNF_UPDATES_TEXT):
            self.assertNotIn("Automatic-Reboot", text)
            self.assertNotIn("reboot =", text)


shutil_which = shutil.which

SSHD_T = (
    "port 22\npasswordauthentication yes\nkbdinteractiveauthentication no\n"
    "permitrootlogin yes\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n"
)
ADMIN_GROUP = "root:x:0:\nsudo:x:27:sam,gone,daemonish\nwheel:x:10:pat\nusers:x:100:lee\n"
ADMIN_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\nsam:x:1000:1000::/home/sam:/bin/bash\n"
    "pat:x:1001:1001::/home/pat:/bin/zsh\nlee:x:1002:1002::/home/lee:/bin/bash\n"
    "daemonish:x:998:998::/var/lib/d:/usr/sbin/nologin\n"
)


def journal_line(message, comm="sshd", uid="0"):
    return json.dumps({"MESSAGE": message, "_COMM": comm, "_UID": uid})


def state(key_logins=(), logins=(), settings=None, running=True):
    return installer.SshState(
        running,
        installer.sshd_settings(SSHD_T) if settings is None else settings,
        ("root", "sam"),
        frozenset(key_logins),
        frozenset(set(logins) | set(key_logins)),
        ("22",),
    )


class Answers:
    def __init__(self, *typed):
        self.typed = list(typed)
        self.asked = 0

    def __call__(self):
        self.asked += 1
        return self.typed.pop(0)


class Questions(unittest.TestCase):
    def setUp(self):
        real = installer.say
        self.said = []
        installer.say = self.said.append
        self.addCleanup(setattr, installer, "say", real)

    def saw(self, text):
        return any(text in line for line in self.said)

    def test_sshds_settings_are_read_first_value_first(self):
        found = installer.sshd_settings("port 22\nport 2200\nPasswordAuthentication no\n")
        self.assertEqual(installer.sshd_settings("Port 2200\n")["port"], "2200")
        self.assertEqual(found["port"], "22")
        self.assertEqual(found["passwordauthentication"], "no")

    def test_administrators_are_root_and_the_groups_members_who_can_log_in(self):
        self.assertEqual(
            installer.admin_accounts(ADMIN_GROUP, ADMIN_PASSWD), ("root", "sam", "pat")
        )

    def test_only_sshds_own_lines_count_as_logins(self):
        journal = "\n".join(
            [
                journal_line("Accepted publickey for sam from 192.0.2.9 port 5000 ssh2: ED25519 x"),
                journal_line("Accepted password for root from 192.0.2.9 port 5001 ssh2"),
                journal_line("Accepted publickey for pat from 192.0.2.9 port 5002 ssh2", "logger"),
                journal_line(
                    "Accepted publickey for lee from 192.0.2.9 port 5003 ssh2", uid="1000"
                ),
                journal_line(
                    "Accepted publickey for root from 192.0.2.9 port 5004 ssh2", "sshd-session"
                ),
                journal_line("Failed password for pat from 192.0.2.9 port 5005 ssh2"),
                "not json",
                "[1]",
            ]
        )
        self.assertEqual(
            installer.accepted_logins(journal),
            {
                "sam": {("publickey", "192.0.2.9")},
                "root": {("password", "192.0.2.9"), ("publickey", "192.0.2.9")},
            },
        )

    def test_where_sshd_looks_for_keys(self):
        settings = {"authorizedkeysfile": ".ssh/authorized_keys /etc/keys/%u %h/k%%"}
        self.assertEqual(
            installer.key_files(settings, "sam", "/home/sam"),
            [Path("/home/sam/.ssh/authorized_keys"), Path("/etc/keys/sam"), Path("/home/sam/k%")],
        )
        self.assertEqual(installer.key_files({"authorizedkeysfile": "none"}, "sam", "/h"), [])

    def test_a_key_file_of_comments_holds_no_key(self):
        with tempfile.TemporaryDirectory() as folder:
            empty, keyed = Path(folder) / "empty", Path(folder) / "keyed"
            empty.write_text("# nothing\n\n")
            keyed.write_text("# a key\nssh-ed25519 AAAA sam\n")
            self.assertFalse(installer.has_a_key([empty, Path(folder) / "missing"]))
            self.assertTrue(installer.has_a_key([empty, keyed]))

    def test_passwords_stay_on_without_a_key_login(self):
        self.assertIsNotNone(installer.passwords_problem(state(logins=["root", "sam"])))
        self.assertIsNone(installer.passwords_problem(state(key_logins=["root"])))

    def test_root_login_stays_on_without_another_way_in(self):
        self.assertIsNotNone(installer.root_problem(state(key_logins=["root"]), False))
        self.assertIsNone(installer.root_problem(state(logins=["sam"]), False))
        # With passwords going off, sam's password login no longer counts.
        self.assertIsNotNone(
            installer.root_problem(state(key_logins=["root"], logins=["sam"]), True)
        )
        self.assertIsNone(installer.root_problem(state(key_logins=["sam"]), True))

    def test_what_does_the_blocking(self):
        on = state(settings={"persourcepenalties": "crash:90s authfail:5s"})
        off = state(settings={"persourcepenalties": "no"})
        self.assertEqual(installer.blocking_kind(on, "ufw"), "on")
        self.assertEqual(installer.blocking_kind(off, "ufw"), "ssh")
        self.assertEqual(installer.blocking_kind(state(), "ufw"), "ufw")
        self.assertEqual(installer.blocking_kind(state(), "firewalld"), "nft")

    def test_without_ssh_nothing_is_asked(self):
        answers = Answers()
        found = installer.choose_lockdown(state(running=False), "ufw", answers)
        self.assertEqual(found, installer.Choices())
        self.assertEqual(answers.asked, 0)
        self.assertTrue(self.saw("SSH isn't running here"))

    def test_each_change_is_asked_separately(self):
        answers = Answers("yes", "no", "y")
        found = installer.choose_lockdown(state(key_logins=["sam"]), "ufw", answers)
        self.assertEqual(found, installer.Choices(True, False, True))
        self.assertEqual(answers.asked, 3)

    def test_enter_is_no(self):
        answers = Answers("", "", "")
        found = installer.choose_lockdown(state(key_logins=["sam"]), "ufw", answers)
        self.assertEqual(found, installer.Choices())

    def test_an_unclear_answer_is_asked_again(self):
        answers = Answers("maybe", "yes", "", "")
        found = installer.choose_lockdown(state(key_logins=["sam"]), "ufw", answers)
        self.assertTrue(found.passwords_off)
        self.assertTrue(self.saw("Type yes or no."))

    def test_ctrl_d_stops_before_anything_changes(self):
        def gone():
            raise EOFError

        with self.assertRaisesRegex(installer.Stop, "changed nothing"):
            installer.choose_lockdown(state(key_logins=["sam"]), "ufw", gone)

    def test_a_question_that_could_lock_someone_out_isnt_asked(self):
        # Only root has a key login: passwords can go, but then root is the only way in.
        answers = Answers("yes", "yes")
        found = installer.choose_lockdown(state(key_logins=["root"]), "ufw", answers)
        self.assertEqual(found, installer.Choices(True, False, True))
        self.assertEqual(answers.asked, 2)
        self.assertTrue(self.saw("Root login over SSH stays on"))

    def test_no_key_login_keeps_passwords_on_and_says_why(self):
        answers = Answers("yes", "no")
        found = installer.choose_lockdown(state(logins=["sam"]), "ufw", answers)
        self.assertFalse(found.passwords_off)
        self.assertTrue(found.root_off)
        self.assertTrue(self.saw("SSH passwords stay on: no administrator account has a key login"))

    def test_settings_already_made_arent_asked(self):
        settings = {
            "passwordauthentication": "no",
            "kbdinteractiveauthentication": "no",
            "permitrootlogin": "no",
            "persourcepenalties": "authfail:5s",
        }
        answers = Answers()
        found = installer.choose_lockdown(state(settings=settings), "ufw", answers)
        self.assertEqual(found, installer.Choices())
        self.assertEqual(answers.asked, 0)
        self.assertTrue(self.saw("already refuses passwords"))
        self.assertTrue(self.saw("already refuses root logins"))
        self.assertTrue(self.saw("already holds off"))

    def test_keyboard_interactive_counts_as_a_password(self):
        settings = {"passwordauthentication": "no", "kbdinteractiveauthentication": "yes"}
        self.assertTrue(installer.passwords_on(settings))

    def test_answers_given_ahead_still_pass_the_safety_checks(self):
        wanted = installer.Choices(True, True, True)
        found = installer.choose_lockdown(state(key_logins=["root"]), "ufw", None, wanted)
        self.assertEqual(found, installer.Choices(True, False, True))
        self.assertEqual(installer.choose_lockdown(state(), "ufw", None), installer.Choices())
        nothing = installer.choose_lockdown(state(key_logins=["sam"]), "ufw", None)
        self.assertEqual(nothing, installer.Choices())
        some = installer.Choices(False, True, False)
        found = installer.choose_lockdown(state(key_logins=["sam"]), "ufw", None, some)
        self.assertEqual(found, some)

    def test_the_ssh_file_holds_only_what_was_agreed(self):
        text = installer.sshd_drop_in(installer.Choices(True, False, True), "ssh")
        self.assertIn("PasswordAuthentication no\nKbdInteractiveAuthentication no\n", text)
        self.assertIn("PerSourcePenalties yes\n", text)
        self.assertNotIn("PermitRootLogin", text)
        self.assertIsNone(installer.sshd_drop_in(installer.Choices(False, False, True), "ufw"))
        self.assertTrue(installer.SSHD_DROP_IN.name.startswith("01-"))

    def test_what_ssh_didnt_take(self):
        wanted = installer.wanted_ssh_settings(installer.Choices(True, True, True), "ssh")
        shown = {
            "passwordauthentication": "no",
            "kbdinteractiveauthentication": "no",
            "permitrootlogin": "yes",
            "persourcepenalties": "authfail:5s",
        }
        self.assertEqual(installer.ssh_settings_took(shown, wanted), ["permitrootlogin"])
        self.assertEqual(
            installer.ssh_settings_took({}, wanted),
            list(wanted),
        )

    def test_the_limit_rules(self):
        rules = installer.ssh_limit_rules(("22", "2200"))
        self.assertIn("tcp dport { 22, 2200 } ct state new update @recent4", rules)
        self.assertIn(
            "ip6 saddr and ffff:ffff:ffff:ffff:: limit rate over 12/minute burst 6 packets", rules
        )
        self.assertIn("priority filter - 10", rules)
        self.assertIn(f"delete table inet {installer.SSH_LIMIT_TABLE}\n", rules)
        unit = installer.ssh_limit_unit("/usr/sbin/nft")
        self.assertIn(f"ExecStart=/usr/sbin/nft -f {installer.SSH_LIMIT_RULES}\n", unit)
        self.assertIn(
            f"ExecStop=-/usr/sbin/nft delete table inet {installer.SSH_LIMIT_TABLE}\n", unit
        )


class ChangingSsh(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        real = (installer.SSHD_DROP_IN, installer._run, installer.say, installer.shutil.which)
        installer.SSHD_DROP_IN = Path(folder.name) / "sshd_config.d" / "01-compromise-checker.conf"
        installer.shutil.which = lambda name: None
        self.said = []
        installer.say = self.said.append
        self.called = []

        def restore():
            installer.SSHD_DROP_IN, installer._run, installer.say, installer.shutil.which = real

        self.addCleanup(restore)

    def sshd(self, check=0, shown="passwordauthentication no\nkbdinteractiveauthentication no\n"):
        def run(*command, **more):
            self.called.append(command)
            if command[-1] == "-t":
                return subprocess.CompletedProcess(
                    list(command), check, "", "bad line 3\n" if check else ""
                )
            if command[-1] == "-T":
                return subprocess.CompletedProcess(list(command), 0, shown, "")
            return subprocess.CompletedProcess(list(command), 0, "", "")

        installer._run = run

    def test_ssh_takes_the_change_and_reloads(self):
        self.sshd()
        installer._change_ssh(installer.Choices(True, False, False), "ufw")
        self.assertEqual(installer.SSHD_DROP_IN.stat().st_mode & 0o777, 0o600)
        self.assertIn(("systemctl", "try-reload-or-restart", "ssh.service"), self.called)
        self.assertIn(("systemctl", "try-reload-or-restart", "sshd.service"), self.called)
        self.assertTrue(any("no longer accepts passwords" in line for line in self.said))

    def test_a_change_ssh_refuses_is_taken_back(self):
        self.sshd(check=255)
        installer._change_ssh(installer.Choices(True, False, False), "ufw")
        self.assertFalse(installer.SSHD_DROP_IN.exists())
        self.assertFalse(any(command[0] == "systemctl" for command in self.called))
        self.assertTrue(any("bad line 3" in line for line in self.said))

    def test_a_change_that_doesnt_take_is_taken_back(self):
        self.sshd(shown="passwordauthentication yes\n")
        installer._change_ssh(installer.Choices(True, False, False), "ufw")
        self.assertFalse(installer.SSHD_DROP_IN.exists())
        self.assertFalse(any(command[0] == "systemctl" for command in self.called))

    def test_an_earlier_runs_settings_are_kept(self):
        installer.SSHD_DROP_IN.parent.mkdir()
        earlier = installer.sshd_drop_in(installer.Choices(True, False, False), "ufw")
        installer.SSHD_DROP_IN.write_text(earlier)
        self.sshd(
            shown="passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin no\n"
        )
        installer._change_ssh(installer.Choices(False, True, False), "ufw")
        text = installer.SSHD_DROP_IN.read_text()
        self.assertIn("PasswordAuthentication no\nKbdInteractiveAuthentication no\n", text)
        self.assertEqual(text.count("PermitRootLogin no"), 1)

    def test_a_failed_change_puts_an_earlier_runs_file_back(self):
        installer.SSHD_DROP_IN.parent.mkdir()
        earlier = installer.sshd_drop_in(installer.Choices(True, False, False), "ufw")
        installer.SSHD_DROP_IN.write_text(earlier)
        self.sshd(check=255)
        installer._change_ssh(installer.Choices(False, True, False), "ufw")
        self.assertEqual(installer.SSHD_DROP_IN.read_text(), earlier)

    def test_nothing_agreed_changes_nothing(self):
        self.sshd()
        installer._change_ssh(installer.Choices(), "ufw")
        self.assertFalse(installer.SSHD_DROP_IN.exists())
        self.assertEqual(self.called, [])

    @unittest.skipUnless(
        Path("/usr/sbin/sshd").exists() or shutil_which("sshd"), "no sshd here to check against"
    )
    def test_real_sshd_takes_the_file_first(self):
        """The drop-in, read before a later file turning passwords on, as a cloud image has."""
        sshd = shutil_which("sshd") or "/usr/sbin/sshd"
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / "d").mkdir()
            key = base / "host_key"
            keygen = shutil_which("ssh-keygen")
            if keygen is None:
                self.skipTest("no ssh-keygen here")
            subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            text = installer.sshd_drop_in(installer.Choices(True, True, False), "ufw")
            (base / "d" / installer.SSHD_DROP_IN.name).write_text(text)
            (base / "d" / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n")
            config = base / "sshd_config"
            config.write_text(f"Include {base}/d/*.conf\nHostKey {key}\nPermitRootLogin yes\n")
            done = subprocess.run(
                [sshd, "-T", "-f", str(config)], capture_output=True, text=True, check=False
            )
            if done.returncode != 0:
                self.skipTest(f"sshd -T can't run here: {done.stderr.strip()}")
            shown = installer.sshd_settings(done.stdout)
            wanted = installer.wanted_ssh_settings(installer.Choices(True, True, False), "ufw")
            self.assertEqual(installer.ssh_settings_took(shown, wanted), [])


class MachineNotes(unittest.TestCase):
    def test_the_status_service_runs_the_tools_own_module_as_root(self):
        script = "/opt/compromise-checker/current/lib/python3.12/site-packages/checker/x.py"
        units = installer.status_units(script)
        service = units[Path("/etc/systemd/system/compromise-checker-status.service")]
        timer = units[Path("/etc/systemd/system/compromise-checker-status.timer")]
        self.assertIn(
            f"ExecStart=/opt/compromise-checker/current/bin/python -I -S {script}"
            " /var/lib/compromise-checker-status/machine.json\n",
            service,
        )
        self.assertNotIn("User=", service)  # SSH's settings are root's to read
        self.assertIn("PrivateNetwork=yes\n", service)
        self.assertIn("StateDirectoryMode=0755\n", service)
        self.assertIn("OnUnitActiveSec=1h\n", timer)

    def test_the_status_file_is_where_the_tool_reads_it(self):
        text = (ROOT / "checker" / "machine_status.py").read_text(encoding="utf-8")
        self.assertIn(f'STATUS = Path("{installer.STATUS_FILE}")', text)


SSHD_OPEN = {
    "permitrootlogin": "yes",
    "pubkeyauthentication": "yes",
    "passwordauthentication": "yes",
    "kbdinteractiveauthentication": "no",
}


class LoginsThatStillWork(unittest.TestCase):
    """A login seen in SSH's log only counts if SSH, as it's set today, would let it in again."""

    def works(self, settings, name="root", method="publickey", keyed=True, lists=None, groups=()):
        merged = {**SSHD_OPEN, **settings}
        return installer.login_still_works(
            merged, lists or {}, name, groups, method, "192.0.2.9", keyed
        )

    def test_a_root_key_login_from_before_root_was_shut_out(self):
        self.assertTrue(self.works({}))
        self.assertTrue(self.works({"permitrootlogin": "prohibit-password"}))
        self.assertFalse(self.works({"permitrootlogin": "no"}))
        self.assertFalse(self.works({"permitrootlogin": "forced-commands-only"}))

    def test_a_root_password_login_needs_root_passwords(self):
        self.assertTrue(self.works({}, method="password"))
        self.assertFalse(self.works({"permitrootlogin": "prohibit-password"}, method="password"))

    def test_keys_turned_off_or_gone(self):
        self.assertFalse(self.works({"pubkeyauthentication": "no"}, name="sam"))
        self.assertFalse(self.works({}, name="sam", keyed=False))

    def test_passwords_and_keyboard_interactive(self):
        self.assertFalse(self.works({"passwordauthentication": "no"}, "sam", "password"))
        method = "keyboard-interactive/pam"
        self.assertFalse(self.works({}, "sam", method))
        self.assertTrue(self.works({"kbdinteractiveauthentication": "yes"}, "sam", method))

    def test_allow_and_deny_lists(self):
        allowed = installer.user_allowed
        self.assertTrue(allowed({}, "sam", ("sam",), "192.0.2.9"))
        self.assertFalse(allowed({"denyusers": ["s*"]}, "sam", (), "192.0.2.9"))
        self.assertFalse(allowed({"allowusers": ["pat"]}, "sam", (), "192.0.2.9"))
        self.assertTrue(
            allowed({"allowusers": ["pat", "sam@192.0.2.0/24"]}, "sam", (), "192.0.2.9")
        )
        self.assertFalse(allowed({"allowusers": ["sam@10.0.0.0/8"]}, "sam", (), "192.0.2.9"))
        self.assertFalse(allowed({"denygroups": ["users"]}, "sam", ("sam", "users"), "192.0.2.9"))
        self.assertFalse(allowed({"allowgroups": ["wheel"]}, "sam", ("sam",), "192.0.2.9"))
        self.assertTrue(allowed({"allowgroups": ["wheel"]}, "sam", ("wheel",), "192.0.2.9"))

    def test_sshd_lists_keep_every_value(self):
        text = "allowusers sam\nallowusers pat@10.0.0.0/8\nport 22\n"
        self.assertEqual(installer.sshd_lists(text), {"allowusers": ["sam", "pat@10.0.0.0/8"]})

    def test_who_can_use_sudo(self):
        self.assertTrue(installer.sudo_rule("User sam may run:\n    (ALL) NOPASSWD: ALL\n"))
        self.assertIs(installer.sudo_rule("User sam may run:\n    (ALL : ALL) ALL\n"), False)
        self.assertIsNone(installer.sudo_rule("User sam may run:\n    (ALL) /usr/bin/systemctl\n"))
        self.assertIsNone(installer.sudo_rule("User sam is not allowed to run sudo on x.\n"))
        shadow = "sam:$6$abc:1::\npat:!$6$abc:1::\nlee:*:1::\nkim::1::\n"
        self.assertTrue(installer.usable_password(shadow, "sam"))
        for name in ("pat", "lee", "kim", "nobody"):
            self.assertFalse(installer.usable_password(shadow, name))

    def test_a_key_held_to_one_command_gives_no_login(self):
        with tempfile.TemporaryDirectory() as folder:
            backup, plain = Path(folder) / "backup", Path(folder) / "plain"
            backup.write_text('command="/usr/bin/rsync --server",no-pty ssh-ed25519 AAAA backup\n')
            plain.write_text('restrict,from="10.0.0.0/8" ssh-ed25519 AAAA sam\n')
            self.assertFalse(installer.has_a_key([backup]))
            self.assertTrue(installer.has_a_key([plain]))

    def test_a_key_file_that_isnt_a_plain_file_isnt_read(self):
        with tempfile.TemporaryDirectory() as folder:
            real = Path(folder) / "real"
            real.write_text("ssh-ed25519 AAAA sam\n")
            link = Path(folder) / "link"
            link.symlink_to(real)
            fifo = Path(folder) / "fifo"
            os.mkfifo(fifo)
            self.assertFalse(installer.has_a_key([link]))
            self.assertFalse(installer.has_a_key([fifo]))  # and doesn't hang
            self.assertTrue(installer.has_a_key([real]))


class FakeSsh:
    """sshd, journalctl and sudo for ssh_state, from what a machine is set to."""

    def __init__(self, folder, settings, per_login=None, sudo="", journal=()):
        self.folder, self.settings = folder, settings
        self.per_login = per_login or {}
        self.sudo, self.journal = sudo, journal

    def __call__(self, *command, **more):
        out, code = "", 0
        if command[0] == "ss":
            out = SS_SSH
        elif command[:2] == ("systemctl", "is-active"):
            out = "active\n"
        elif command[:2] == ("systemctl", "show"):
            out = ""
        elif command[0].endswith("sshd") and command[1:] == ("-T",):
            out = self.settings
        elif command[0].endswith("sshd") and command[1:3] == ("-T", "-C"):
            user = command[3].split(",")[0].split("=")[1]
            out = self.per_login.get(user, self.settings)
        elif command[0] == "journalctl":
            out = "\n".join(journal_line(line) for line in self.journal)
        elif command[0].endswith("sudo"):
            out = self.sudo
        return subprocess.CompletedProcess(list(command), code, out, "")


class SshStateFromTheMachine(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        sshd = self.folder / "sshd"
        sshd.write_text("")
        for name in ("root", "sam"):
            (self.folder / name / ".ssh").mkdir(parents=True)
            (self.folder / name / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAA x\n")
        names = ("_run", "_sshd_command", "admin_accounts", "_groups_of", "_can_sudo")
        real = {name: getattr(installer, name) for name in names}
        real_getpwnam = installer.pwd.getpwnam
        installer._sshd_command = lambda: str(sshd)
        installer.admin_accounts = lambda group, passwd: ("root", "sam")
        installer._groups_of = lambda name: (name,)
        folder_path = self.folder

        class Account:
            def __init__(self, name):
                self.pw_dir = str(folder_path / name)
                self.pw_gid = 0

        installer.pwd.getpwnam = Account

        def restore():
            for name, value in real.items():
                setattr(installer, name, value)
            installer.pwd.getpwnam = real_getpwnam

        self.addCleanup(restore)

    def state(self, settings, journal, sudo=True, per_login=None):
        installer._run = FakeSsh(self.folder, settings, per_login, journal=journal)
        installer._can_sudo = lambda name, shadow: sudo or name == "root"
        return installer.ssh_state(SS_SSH)

    def test_an_old_root_key_login_doesnt_count_once_root_is_shut_out(self):
        settings = "permitrootlogin no\npasswordauthentication yes\npubkeyauthentication yes\n"
        journal = [
            "Accepted publickey for root from 192.0.2.9 port 5000 ssh2: ED25519 x",
            "Accepted password for sam from 192.0.2.9 port 5001 ssh2",
        ]
        found = self.state(settings, journal)
        self.assertEqual(found.key_logins, frozenset())
        self.assertEqual(found.logins, frozenset({"sam"}))
        self.assertIsNotNone(installer.passwords_problem(found))

    def test_a_key_login_counts_while_ssh_would_still_take_it(self):
        settings = "permitrootlogin prohibit-password\npasswordauthentication yes\n"
        journal = ["Accepted publickey for root from 192.0.2.9 port 5000 ssh2: ED25519 x"]
        found = self.state(settings, journal)
        self.assertEqual(found.key_logins, frozenset({"root"}))
        self.assertEqual(found.sources, (("root", "192.0.2.9"),))

    def test_a_match_section_shutting_an_account_out_is_seen(self):
        settings = "permitrootlogin yes\npasswordauthentication yes\n"
        journal = ["Accepted publickey for sam from 192.0.2.9 port 5000 ssh2: ED25519 x"]
        found = self.state(settings, journal, per_login={"sam": settings + "denyusers sam\n"})
        self.assertEqual(found.key_logins, frozenset())

    def test_a_key_login_that_also_needs_a_code_doesnt_let_passwords_go(self):
        settings = "permitrootlogin yes\npasswordauthentication yes\n"
        journal = ["Accepted publickey for sam from 192.0.2.9 port 5000 ssh2: ED25519 x"]
        both = settings + "authenticationmethods publickey,keyboard-interactive\n"
        found = self.state(settings, journal, per_login={"sam": both})
        self.assertEqual(found.key_logins, frozenset())
        self.assertEqual(found.logins, frozenset({"sam"}))  # it still works while passwords do

    def test_an_administrator_who_cant_use_sudo_isnt_another_way_in(self):
        settings = "permitrootlogin yes\npasswordauthentication yes\n"
        journal = [
            "Accepted publickey for root from 192.0.2.9 port 5000 ssh2: ED25519 x",
            "Accepted publickey for sam from 192.0.2.9 port 5001 ssh2: ED25519 x",
        ]
        found = self.state(settings, journal, sudo=False)
        self.assertEqual(found.logins, frozenset({"root"}))
        self.assertIsNotNone(installer.root_problem(found, False))
        found = self.state(settings, journal, sudo=True)
        self.assertIsNone(installer.root_problem(found, True))

    def test_the_person_running_this_through_sudo_can_use_it(self):
        real = os.environ.get("SUDO_USER")
        os.environ["SUDO_USER"] = "sam"
        try:
            self.assertTrue(installer._can_sudo("sam", ""))
        finally:
            if real is None:
                del os.environ["SUDO_USER"]
            else:
                os.environ["SUDO_USER"] = real


class FirewallsReviewed(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        real = (installer.LOCKDOWN_MARKER, installer._run, installer.shutil.which, installer.say)
        installer.LOCKDOWN_MARKER = Path(folder.name) / "lockdown.json"
        installer.shutil.which = lambda name: "/usr/sbin/" + name
        self.said = []
        installer.say = self.said.append

        def restore():
            (
                installer.LOCKDOWN_MARKER,
                installer._run,
                installer.shutil.which,
                installer.say,
            ) = real

        self.addCleanup(restore)

    def test_saved_ufw_rules_are_seen(self):
        self.assertFalse(
            installer.ufw_saved_rules("Added user rules (see 'ufw status'):\n(None)\n")
        )
        self.assertTrue(installer.ufw_saved_rules("Added user rules:\nufw deny 22/tcp\n"))

    def test_ssh_goes_in_front_of_saved_ufw_rules(self):
        fake = FakeMachine()

        def run(*command, **more):
            if command[:3] == ("ufw", "show", "added"):
                fake.called.append(command)
                return subprocess.CompletedProcess(list(command), 0, "Added:\nufw deny 22\n", "")
            return fake(*command, **more)

        installer._run = run
        installer.set_up_firewall(UBUNTU_24)
        self.assertIn(("ufw", "--force", "delete", "deny", "22/tcp"), fake.called)
        self.assertLess(
            fake.index("ufw", "--force", "delete", "deny", "22/tcp"),
            fake.index("ufw", "prepend", "allow", "22/tcp"),
        )
        self.assertNotIn(("ufw", "--force", "delete", "allow", "22/tcp"), fake.called)
        self.assertLess(
            fake.index("ufw", "prepend", "allow", "22/tcp"),
            fake.index("ufw", "--force", "enable"),
        )

    def test_someone_elses_ufw_is_never_limited(self):
        fake = FakeMachine(ufw=UFW_ACTIVE)
        installer._run = fake
        installer.set_up_firewall(UBUNTU_24, limit=True)
        self.assertFalse(any(command[:2] == ("ufw", "limit") for command in fake.called))
        self.assertEqual(installer.blocking_kind(state(), "someone else's"), "nft")

    def test_ssh_running_on_a_port_that_cant_be_found_leaves_the_firewall_off(self):
        fake = FakeMachine(ss="")

        def run(*command, **more):
            if command[:2] == ("systemctl", "is-active") and command[2] in installer.SSH_UNITS:
                fake.called.append(command)
                return subprocess.CompletedProcess(list(command), 0, "active\n", "")
            return fake(*command, **more)

        installer._run = run
        installer.set_up_firewall(UBUNTU_24)
        self.assertFalse(any(command[:2] == ("ufw", "--force") for command in fake.called))
        self.assertTrue(any("no firewall was turned on" in line for line in self.said))

    def test_a_firewall_of_another_kind_is_kept(self):
        fake = FakeMachine()

        def run(*command, **more):
            if command == ("systemctl", "is-active", "nftables.service"):
                return subprocess.CompletedProcess(list(command), 0, "active\n", "")
            return fake(*command, **more)

        installer._run = run
        self.assertEqual(installer.running_firewall(), "nftables")
        installer.set_up_firewall(UBUNTU_24)
        self.assertFalse(any(command[:2] == ("ufw", "--force") for command in fake.called))
        self.assertTrue(any("nftables, is already running" in line for line in self.said))

    def test_every_zone_ssh_could_come_through_lets_it_in(self):
        fake = FakeMachine()

        def run(*command, **more):
            if command[0] == "firewall-offline-cmd" and command[-1].startswith(
                "--get-zone-of-interface="
            ):
                zone = "internal\n" if command[-1].endswith("=eth1") else ""
                return subprocess.CompletedProcess(list(command), 0 if zone else 2, zone, "")
            if command[0] == "nmcli":
                return subprocess.CompletedProcess(list(command), 0, "", "")
            return fake(*command, **more)

        installer._run = run
        real_iterdir = installer.Path.iterdir

        def iterdir(self):
            if str(self) == "/sys/class/net":
                return iter(
                    [
                        Path("/sys/class/net/lo"),
                        Path("/sys/class/net/eth0"),
                        Path("/sys/class/net/eth1"),
                    ]
                )
            return real_iterdir(self)

        installer.Path.iterdir = iterdir
        try:
            installer.set_up_firewall(ROCKY_9)
        finally:
            installer.Path.iterdir = real_iterdir
        zones = {
            command[1]
            for command in fake.called
            if command[0] == "firewall-offline-cmd" and command[1].startswith("--zone=")
        }
        self.assertEqual(zones, {"--zone=public", "--zone=internal"})


class LimitAndNotesReviewed(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        names = ("SSH_LIMIT_UNIT", "SSH_LIMIT_RULES", "_run", "say")
        real = {name: getattr(installer, name) for name in names}
        installer.SSH_LIMIT_UNIT = self.folder / "limit.service"
        installer.SSH_LIMIT_RULES = self.folder / "limit.nft"
        self.called, self.said = [], []
        installer.say = self.said.append
        installer._run = lambda *command, **more: (
            self.called.append(command) or subprocess.CompletedProcess(list(command), 0, "", "")
        )

        def restore():
            for name, value in real.items():
                setattr(installer, name, value)

        self.addCleanup(restore)

    def test_an_earlier_runs_limit_goes_when_the_answer_is_now_no(self):
        installer.SSH_LIMIT_UNIT.write_text("x")
        installer.SSH_LIMIT_RULES.write_text("x")
        installer._remove_nftables_limit()
        self.assertFalse(installer.SSH_LIMIT_UNIT.exists())
        self.assertFalse(installer.SSH_LIMIT_RULES.exists())
        self.assertIn(
            ("systemctl", "disable", "--now", f"{installer.SSH_LIMIT}.service"), self.called
        )

    def test_the_limit_comes_back_with_nftables(self):
        unit = installer.ssh_limit_unit("/usr/sbin/nft")
        self.assertIn("PartOf=nftables.service\n", unit)
        self.assertIn("After=network-pre.target nftables.service firewalld.service\n", unit)

    def test_the_status_service_is_kept_to_what_it_needs(self):
        service = list(installer.status_units("/x/machine_status.py").values())[0]
        for line in ("RestrictAddressFamilies=AF_UNIX", "PrivateNetwork=yes", "ProtectHome=yes"):
            self.assertIn(line + "\n", service)
        self.assertIn(" -I -S /x/machine_status.py ", service)


class UdpSigns(unittest.TestCase):
    def test_a_vpn_or_other_udp_service_is_a_sign_of_use(self):
        udp = (
            'UNCONN 0 0 0.0.0.0%eth0:68 0.0.0.0:* users:(("systemd-network",pid=500,fd=20))\n'
            'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=501,fd=13))\n'
            'UNCONN 0 0 127.0.0.1:323 0.0.0.0:* users:(("chronyd",pid=502,fd=5))\n'
            'UNCONN 0 0 0.0.0.0:111 0.0.0.0:* users:(("rpcbind",pid=503,fd=5))\n'
            "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n"
            "UNCONN 0 0 [::]:51820 [::]:*\n"
            'UNCONN 0 0 0.0.0.0:1194 0.0.0.0:* users:(("openvpn",pid=600,fd=6))\n'
        )
        signs = installer.udp_signs(udp)
        self.assertEqual(
            [sign.what for sign in signs],
            [
                "something in the kernel, such as a WireGuard VPN, is taking UDP on port 51820",
                "openvpn is taking UDP on port 1194",
            ],
        )
        self.assertIn("cut off", signs[0].matters)


class SecondReview(unittest.TestCase):
    def setUp(self):
        real = installer.say
        self.said = []
        installer.say = self.said.append
        self.addCleanup(setattr, installer, "say", real)

    def test_a_key_then_a_one_time_code_isnt_a_key_alone(self):
        self.assertTrue(installer.keys_alone_suffice({}))
        self.assertTrue(installer.keys_alone_suffice({"authenticationmethods": "any"}))
        self.assertTrue(installer.keys_alone_suffice({"authenticationmethods": "publickey"}))
        self.assertTrue(
            installer.keys_alone_suffice(
                {"authenticationmethods": "publickey,keyboard-interactive publickey"}
            )
        )
        self.assertFalse(
            installer.keys_alone_suffice(
                {"authenticationmethods": "publickey,keyboard-interactive:pam"}
            )
        )
        self.assertFalse(installer.keys_alone_suffice({"authenticationmethods": "password"}))

    def test_host_lists_in_allow_and_deny_patterns(self):
        allowed = installer.user_allowed
        deny = {"denyusers": ["alice@10.0.0.0/8,192.168.0.0/16"]}
        self.assertFalse(allowed(deny, "alice", (), "192.168.1.1"))
        self.assertTrue(allowed(deny, "alice", (), "203.0.113.5"))
        allow = {"allowusers": ["alice@192.168.0.0/16,!192.168.1.1"]}
        self.assertFalse(allowed(allow, "alice", (), "192.168.1.1"))
        self.assertTrue(allowed(allow, "alice", (), "192.168.2.1"))
        self.assertTrue(allowed({"allowusers": ["a@b@10.0.0.1"]}, "a@b", (), "10.0.0.1"))

    def test_unreadable_ssh_settings_ask_and_change_nothing(self):
        state = installer.SshState(
            True, {}, (), frozenset(), frozenset(), ("22",), (), "Match LocalPort"
        )
        found = installer.choose_lockdown(
            state, "ufw", Answers(), installer.Choices(True, True, True)
        )
        self.assertEqual(found, installer.Choices())
        self.assertTrue(any("couldn't be read (Match LocalPort)" in line for line in self.said))

    def test_the_limit_follows_nftables_reloads(self):
        unit = installer.ssh_limit_unit("/usr/sbin/nft")
        self.assertIn("ReloadPropagatedFrom=nftables.service\n", unit)
        self.assertIn(f"ExecReload=/usr/sbin/nft -f {installer.SSH_LIMIT_RULES}\n", unit)

    def test_a_limit_that_wasnt_set_isnt_claimed(self):
        real = (installer._change_ssh, installer._remove_nftables_limit)
        removed = []
        installer._change_ssh = lambda *a, **k: None
        installer._remove_nftables_limit = lambda: removed.append(True)
        try:
            installer.apply_lockdown(installer.Choices(False, False, True), "ufw", (), False)
            self.assertNotIn(installer.LIMITED, self.said)
            self.assertTrue(any("aren't limited" in line for line in self.said))
            installer.apply_lockdown(installer.Choices(False, False, True), "ufw", (), True)
            self.assertIn(installer.LIMITED, self.said)
            removed.clear()
            installer.apply_lockdown(installer.Choices(), "nft", (), False, answered=False)
            self.assertEqual(removed, [])
            installer.apply_lockdown(installer.Choices(), "nft", (), False, answered=True)
            self.assertEqual(removed, [True])
        finally:
            installer._change_ssh, installer._remove_nftables_limit = real


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
