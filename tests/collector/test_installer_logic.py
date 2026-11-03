"""The installer's own logic (release/install.py), standard library only and Python 3.9 compatible:
CI runs this with each system's own python3, which is what the installer first runs on. What signs
files with a real key is in tests/test_installer.py."""

import importlib.util
import json
import os
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
        self.assertIn("LimitRequestBody 131072", config)
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

    def test_a_new_certificate_is_used_as_soon_as_it_arrives(self):
        web = installer.Web("checker.example.org", ())
        for apache, store in (
            (installer.APACHE_APT, "/var/lib/apache2/md"),
            (installer.APACHE_DNF, "/var/lib/httpd/md"),
        ):
            units = installer.reload_units(apache, web)
            path = [text for name, text in units.items() if name.suffix == ".path"][0]
            self.assertIn(f"PathExists={store}/staging/checker.example.org/pubcert.pem", path)

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
            "c.example.org", [], 1, lambda _: {"198.51.100.7"}, lambda _: None, lambda _: True
        )
        with self.assertRaisesRegex(installer.Stop, "nothing sent there arrives"):
            installer.wait_for_name(
                "c.example.org", [], 1, lambda _: {"198.51.100.7"}, lambda _: None, lambda _: False
            )

    def test_the_daily_reload(self):
        units = installer.reload_units(installer.APACHE_APT)
        texts = "".join(units.values())
        self.assertIn("ExecStart=/usr/bin/systemctl reload apache2", texts)
        self.assertIn("OnCalendar=daily", texts)

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
