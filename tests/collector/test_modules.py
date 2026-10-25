"""Collector module, masking and limit tests against fixture directories.

Standard library `unittest` only, Python 3.9 compatible, like
test_collector.py. The collector is loaded from its file and pointed at a
temporary directory laid out like a server (its ROOT), which only tests can do.
"""

import base64
import datetime
import gzip
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

    def test_masked_values_are_not_masked_twice(self):
        masked, counts = self.mask(b"token=ghp_" + b"d" * 36 + b"\n")
        self.assertEqual(masked, b"token=[MASKED:github_token]\n")
        self.assertEqual(counts, {"github_token": 1})


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
        self.assertEqual(manifest["masking_version"], 1)


if __name__ == "__main__":
    unittest.main()
