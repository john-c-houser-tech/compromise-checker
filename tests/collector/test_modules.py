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
        kept = b"jch ALL = (root) NOPASSWD:SETENV: /bin/a, PASSWD: /bin/b\n"
        self.assertEqual(self.mask(kept), (kept, {}))
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
        self.assertEqual(manifest["masking_version"], 3)


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
            manifest["commands_allowed"], {"journalctl": ["/usr/bin/journalctl", "/bin/journalctl"]}
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
        records = collect(self.root, ["ssh"])
        self.assertIn("/usr/share/crypto-policies/DEFAULT/opensshserver.txt", sources(records))

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

    def test_too_many_pam_files_is_a_recorded_gap(self):
        for name in ("a", "b", "c"):
            self.write("etc/pam.d/" + name, b"auth required pam_unix.so\n")
        collector = load_collector(self.root)
        collector.MAX_DIR_FILES = 2
        out = io.BytesIO()
        collector.main(settings(["pam"]), out=out)
        records = [json.loads(line) for line in gzip.decompress(out.getvalue()).splitlines()]
        (listing,) = records_named(records, "config_dir")
        self.assertEqual((listing["entries"], listing["truncated"]), (3, True))
        self.assertEqual(sorted(sources(records)), ["/etc/pam.d/a", "/etc/pam.d/b"])


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

    def test_glob_expansion_is_bounded(self):
        for index in range(30):
            self.write(f"etc/ssh/sshd_config.d/{index:02}.conf", b"\n")
        collector = load_collector(self.root)
        collector.MAX_GLOB_ENTRIES = 10
        skipped = []
        found = collector.glob_absolute("/etc/ssh/sshd_config.d/*.conf", skipped)
        self.assertLessEqual(len(found), 10)
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
}


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
        for directory in ("etc/pam.d", "etc/sudoers.d", "etc/ssh/sshd_config.d"):
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
        os.makedirs(Path(self.root, "var/log"))
        self.write("var/log/secure", f"Oct 26 sshd[1]: password={c['log']} x\n".encode())
        self.write(
            "var/log/auth.log",
            f"Oct 26 sudo: -----BEGIN RSA PRIVATE KEY-----\n{c['private']}\n".encode(),
        )

    def test_no_canary_leaves_through_any_module(self):
        self.plant()
        collector = load_collector(self.root)
        collector.COMMANDS = {"journalctl": ()}  # no real journal in a fixture
        out = io.BytesIO()
        collector.main(settings(None), out=out)
        raw = gzip.decompress(out.getvalue())
        text = raw.decode("utf-8", "replace")
        leaks = {}
        for name, canary in CANARIES.items():
            for form in {canary, canary[:16], base64.b64encode(canary.encode()).decode()[:16]}:
                if form in text:
                    leaks[name] = form
        self.assertEqual(leaks, {})
        trailer = json.loads(raw.splitlines()[-1])
        self.assertEqual(trailer["status"], "complete", trailer["modules"])


if __name__ == "__main__":
    unittest.main()
