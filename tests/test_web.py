"""Web applications, collection and parsing (PR 2.8a, DESIGN.md §8.12)."""

from zoneinfo import ZoneInfo

import pytest

from checker.cli import main
from checker.events import EventBuilder
from checker.evidence import load_config
from checker.protocol import Limits, Record, Settings, SourceStart


def web_source(source_id, name):
    return SourceStart(
        type="source_start", source_id=source_id, module="web_logs", kind="file", name=name, meta={}
    )


ACCESS = [
    # Ordinary: counted, not kept.
    '203.0.113.9 - - [28/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "x"',
    '203.0.113.10 - - [28/Oct/2026:10:00:01 +0000] "GET /nope HTTP/1.1" 404 0 "-" "x"',
    # A script, a server error, an attack marker: kept.
    '203.0.113.9 - - [28/Oct/2026:10:00:02 +0000] "POST /up/shell.php?c=[MASKED:value] HTTP/1.1"'
    ' 200 12 "-" "curl/8"',
    '198.51.100.7 - bob [28/Oct/2026:10:00:03 +0000] "GET /api HTTP/1.1" 502 0 "-" "x"',
    '198.51.100.7 - - [28/Oct/2026:10:00:04 +0000] "GET /x?f=[MASKED:exploit:traversal] HTTP/1.1"'
    ' 404 0 "-" "x"',
    "not a log line at all",
]


def test_access_lines_kept_or_counted():
    builder = EventBuilder()
    for line in ACCESS:
        builder.line(web_source(1, "/var/log/nginx/access.log"), line.encode() + b"\n")
    kept = [(e.fields["path"], e.fields["status"]) for e in builder.events]
    assert kept == [
        ("/up/shell.php?c=[MASKED:value]", 200),
        ("/api", 502),
        ("/x?f=[MASKED:exploit:traversal]", 404),
    ]
    shell, _, attack = builder.events
    assert shell.type == "web.request" and shell.fields["method"] == "POST"
    assert shell.fields["network"] == "203.0.113.0/24" and shell.time == "2026-10-28T10:00:02+00:00"
    assert attack.fields["attacks"] == ["traversal"]
    summary = builder.web.summary()
    assert summary["requests_by_network"] == {"203.0.113.0/24": {"2xx": 1, "4xx": 1}}
    assert summary["unparsed"] == {"/var/log/nginx/access.log": 1}
    assert summary["lines"] == {"/var/log/nginx/access.log": 6}


@pytest.mark.parametrize(
    ("line", "level", "client", "time"),
    [
        (
            "2026/10/28 10:00:03 [error] 77#77: *5 open() failed, client: 198.51.100.4,"
            ' server: x, request: "GET /a.php?id=[MASKED:value] HTTP/1.1"',
            "error",
            "198.51.100.4",
            "2026-10-28T09:00:03+00:00",
        ),
        (
            "[Wed Oct 28 10:00:03.123456 2026] [php:error] [pid 812] [client 198.51.100.4:5123]"
            " PHP Fatal error: x",
            "error",
            "198.51.100.4",
            "2026-10-28T09:00:03.123456+00:00",
        ),
        (
            "[28-Oct-2026 10:00:03] WARNING: [pool www] child 9 said into stderr: x",
            "warning",
            None,
            "2026-10-28T09:00:03+00:00",
        ),
    ],
)
def test_error_lines_in_the_host_s_zone(line, level, client, time):
    builder = EventBuilder()
    builder.zone = ZoneInfo("Europe/Berlin")
    builder.line(web_source(1, "/var/log/nginx/error.log"), line.encode() + b"\n")
    [event] = builder.events
    assert (event.type, event.fields["level"], event.fields.get("client"), event.time) == (
        "web.error",
        level,
        client,
        time,
    )
    if "request:" in line:
        assert event.fields["request"].startswith("GET /a.php")


def test_configuration_files_aren_t_log_lines():
    builder = EventBuilder()
    builder.line(web_source(1, "/etc/nginx/nginx.conf"), ACCESS[0].encode() + b"\n")
    assert builder.events == [] and builder.web.lines == {}


def test_program_starts_become_events():
    builder = EventBuilder()
    data = {
        "time": "2026-10-28T10:00:05+00:00",
        "pid": 901,
        "ppid": 900,
        "uid": 33,
        "euid": 33,
        "comm": "sh",
        "exe": "/usr/bin/dash",
        "cwd": "/var/www/html",
        "argv": "sh -c id",
        "success": "yes",
    }
    builder.record(Record(type="record", module="web_logs", name="exec_record", data=data))
    [event] = builder.events
    assert event.type == "process.exec" and event.source == "web_logs:audit"
    assert event.fields["argv"] == "sh -c id" and event.fields["success"] is True


def test_settings_and_init_choices(checker_home, capsys):
    from test_mail import T0

    limits = Limits(overall_seconds=1, module_seconds=1, source_bytes=1)
    settings = Settings(run_id="r", since=T0, limits=limits)
    assert (settings.web_access_logs, settings.exec_records, settings.web_users) == (
        False,
        "web",
        [],
    )
    with pytest.raises(ValueError):
        Settings(run_id="r", since=T0, limits=limits, web_users=["-bad"])
    assert main(["init", "--web-access-logs", "--exec-records", "privileged"]) == 0
    out = capsys.readouterr().out
    assert "Web access logs: collected, masked" in out
    assert "root, service and administrator accounts" in out
    config = load_config(checker_home)
    assert config.web_access_logs is True and config.exec_records == "privileged"


@pytest.fixture
def checker_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def test_coverage_says_what_web_data_is_missing():
    from test_checks_live import snap

    from checker.assess import web_gaps

    live = {
        "web_logs_summary": {"access_logs_opted_in": False, "access_found": 2},
        "exec_records_unavailable": {"reason": "no audit log"},
        "web_requests": {
            "lines": {"/var/log/x.log": 10, "/var/log/y.log": 10},
            "unparsed": {"/var/log/x.log": 9, "/var/log/y.log": 2},
        },
    }
    gaps = web_gaps(snap(live))
    assert any("not chosen at setup" in g for g in gaps)
    assert any("docs/auditd-web.rules" in g for g in gaps)
    assert [g for g in gaps if "not recognised" in g] == [
        "web log format not recognised: /var/log/x.log (9 lines)"
    ]
    opted = {"web_logs_summary": {"access_logs_opted_in": True, "access_found": 2}}
    assert web_gaps(snap(opted)) == []
