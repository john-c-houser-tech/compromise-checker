"""Collector module, masking and limit tests against fixture directories.

Standard library `unittest` only, Python 3.9 compatible, like
test_collector.py. The collector is loaded from its file and pointed at a
temporary directory laid out like a server (its ROOT), which only tests can do.
"""

import base64
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
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


def settings(modules, days=30, source_bytes=1 << 20, module_seconds=60):
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    return json.dumps(
        {
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
    )


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

    def mask(self, text):
        return self.collector.mask_text(text)

    def test_ordinary_log_lines_are_untouched(self):
        for line in (
            b"sshd[1]: Failed password for invalid user admin from 192.0.2.9 port 22 ssh2\n",
            b"sudo: pam_unix(sudo:auth): auth could not identify password for [jch]\n",
            b"sudo: jch : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl\n",
            b"sshd[2]: Accepted publickey for jch from 192.0.2.9 port 5 ssh2: ED25519 SHA256:x\n",
            b"passwd[3]: pam_unix(passwd:chauthtok): password changed for jch\n",
            b"sshd[4]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=x\n",
            b"sshd[5]: Postponed keyboard-interactive/pam for jch from 192.0.2.9 port 5\n",
        ):
            self.assertEqual(self.mask(line), (line, {}), line)

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
        self.assertEqual(manifest["masking_version"], 2)


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
            manifest["commands_allowed"], {"journalctl": ["/usr/bin/journalctl", "/bin/journalctl"]}
        )


if __name__ == "__main__":
    unittest.main()
