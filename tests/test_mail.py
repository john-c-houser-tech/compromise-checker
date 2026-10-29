"""Outgoing mail (PR 2.7, DESIGN.md §8.9): events, settings, checks, and
the mail key."""

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from test_checks import T0, ev, of
from test_checks_live import snap

from checker.checks import Context, run_checks
from checker.cli import main
from checker.events import EventBuilder, classify_exim, classify_mail, merge_duplicates
from checker.evidence import mail_fingerprint, mail_key, mail_key_file
from checker.protocol import Limits, Settings, SourceStart
from checker.snapshot import compare, exim_settings, postfix_services, postfix_settings

KEY = "ab" * 32


# --- The mail key -------------------------------------------------------------------------


def test_the_controller_and_collector_fingerprint_alike():
    spec = importlib.util.spec_from_file_location(
        "collector_for_mail", Path(__file__).parents[1] / "checker/collector/collector.py"
    )
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    for address in ("Alice@Example.org", "www-data", '"j doe"@ex.org', "jörg@example.org"):
        local, _, domain = address.rpartition("@") if "@" in address else (address, "", "")
        line = (f"to=<{address}>" if "@" in address else f"from=<{address}>").encode()
        masked = collector.mask_mail(line, bytes.fromhex(KEY), {}).decode()
        assert mail_fingerprint(KEY, address) in masked, address


def test_the_mail_key_is_made_once_and_kept_private(tmp_path):
    first = mail_key(tmp_path)
    assert len(first) == 64 and mail_key(tmp_path) == first
    assert mail_key_file(tmp_path).stat().st_mode & 0o077 == 0
    assert mail_fingerprint(first, "Bob@Example.ORG").endswith("@example.org")
    assert mail_fingerprint(first, "bob") == mail_fingerprint(first, "BOB")
    with pytest.raises(ValueError):
        mail_fingerprint(first, "@example.org")


def test_settings_never_show_the_key():
    settings = Settings(
        run_id="r",
        since=T0,
        limits=Limits(overall_seconds=1, module_seconds=1, source_bytes=1),
        mail_key=KEY,
    )
    assert KEY not in repr(settings)
    assert settings.model_dump(mode="json")["mail_key"] == KEY  # it does reach the collector
    with pytest.raises(ValueError):
        Settings(
            run_id="r",
            since=T0,
            limits=Limits(overall_seconds=1, module_seconds=1, source_bytes=1),
            mail_key="secret",
        )


@pytest.fixture
def checker_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def test_mail_hash_command(checker_home, capsys):
    assert main(["init"]) == 0
    capsys.readouterr()
    assert main(["mail-hash", "Alice@Example.org", "root"]) == 0
    out = capsys.readouterr().out.splitlines()
    key = mail_key(checker_home)
    assert out == [
        f"Alice@Example.org\t{mail_fingerprint(key, 'Alice@Example.org')}",
        f"root\t{mail_fingerprint(key, 'root')}",
    ]


# --- Events ----------------------------------------------------------------------------------


def start(source_id, name, kind="file"):
    return SourceStart(
        type="source_start", source_id=source_id, module="mail", kind=kind, name=name, meta={}
    )


PICKUP = "4F1A: uid=33 from=<h:66e509c79779>"
SENT = (
    "4F1A: to=<h:aaaa@example.org>, relay=mx.example.org[192.0.2.25]:25, delay=1, status=sent (ok)"
)


def test_postfix_messages():
    assert classify_mail("postfix/pickup", PICKUP) == (
        "mail.submitted",
        {"queue_id": "4F1A", "uid": 33, "sender": "h:66e509c79779"},
    )
    kind, fields = classify_mail("postfix-out/smtp", SENT)
    assert kind == "mail.sent"
    assert fields == {
        "queue_id": "4F1A",
        "recipient": "h:aaaa@example.org",
        "relay": "mx.example.org[192.0.2.25]:25",
        "domain": "example.org",
    }
    deferred = SENT.replace("status=sent", "status=deferred")
    assert classify_mail("postfix/smtp", deferred)[0] == "mail.deferred"
    expired = SENT.replace("status=sent", "status=expired")
    assert classify_mail("postfix/error", expired)[0] == "mail.bounced"
    assert classify_mail("smtp", SENT) is None  # not Postfix
    assert classify_mail("postfix/qmgr", "4F1A: removed") is None


def test_exim_lines():
    kind, fields, when = classify_exim(
        "2026-10-28 10:00:01 1tA-0-DE <= h:1@web01 U=www-data P=local S=500"
    )
    assert (kind, fields["user"], when["date"]) == ("mail.submitted", "www-data", "2026-10-28")
    assert (
        classify_exim("2026-10-28 10:00:01 1tA-0-DE <= h:1@x.org H=mx [192.0.2.4] P=esmtp") is None
    )
    kind, fields, _ = classify_exim(
        "2026-10-28 10:00:02 1tA-0-DE => h:2@example.com R=dnslookup T=remote_smtp"
        " H=mx.example.com [192.0.2.30]"
    )
    assert (kind, fields["relay"], fields["domain"]) == (
        "mail.sent",
        "mx.example.com [192.0.2.30]",
        "example.com",
    )
    assert classify_exim("2026-10-28 10:00:03 1tA-0-DG ** h:3@x.net R=d: 550")[0] == "mail.bounced"


def test_mail_events_from_files_and_the_journal_are_one_record():
    builder = EventBuilder()
    log = start(1, "/var/log/mail.log")
    builder.source_start(log)
    stamp = "2026-10-28T10:00:02.000000+00:00"
    builder.line(log, f"{stamp} web01 postfix/smtp[901]: {SENT}\n".encode())
    journal = start(2, "/usr/bin/journalctl --output=json", kind="command")
    builder.source_start(journal)
    micro = int(datetime.fromisoformat(stamp).timestamp() * 1e6)
    entry = (
        f'{{"MESSAGE":"{SENT}","SYSLOG_IDENTIFIER":"postfix/smtp","SYSLOG_PID":"901",'
        f'"_SOURCE_REALTIME_TIMESTAMP":"{micro}","_COMM":"smtp","_UID":"89"}}'
    )
    builder.line(journal, entry.encode())
    exim = start(3, "/var/log/exim4/mainlog")
    builder.source_start(exim)
    builder.line(exim, b"2026-10-28 10:00:01 1tA-0-DE <= h:1@web01 U=www-data P=local S=500\n")
    events = merge_duplicates(builder.events)
    sent = [e for e in events if e.type == "mail.sent"]
    assert len(sent) == 1 and sent[0].source == "mail_journal"
    assert sent[0].also_in == ["mail_log:/var/log/mail.log"]
    [submitted] = [e for e in events if e.type == "mail.submitted"]
    assert submitted.source == "mail_log:/var/log/exim4/mainlog"
    assert submitted.time == "2026-10-28T10:00:01+00:00"  # UTC assumed: no zone known


def test_exim_times_are_the_host_s_local_time():
    builder = EventBuilder()
    builder.zone = ZoneInfo("Europe/Berlin")
    exim = start(1, "/var/log/exim/main.log")
    builder.source_start(exim)
    builder.line(exim, b"2026-10-28 10:00:01 1tA-0-DE <= h:1@web01 U=apache P=local S=500\n")
    builder.line(exim, b"2026-10-28 10:00:02 -0500 1tA-0-DF ** h:2@x.org R=d: 550\n")
    assert [e.time for e in builder.events] == [
        "2026-10-28T09:00:01+00:00",
        "2026-10-28T15:00:02+00:00",
    ]


# --- Settings ----------------------------------------------------------------------------


def test_postfix_and_exim_settings():
    main_cf = [
        "# comment",
        "relayhost = [smtp.example.net]:587",
        "smtpd_relay_restrictions = permit_mynetworks,",
        "    permit_sasl_authenticated, defer_unauth_destination",
        "mynetworks = 127.0.0.0/8 [::1]/128",
    ]
    assert postfix_settings(main_cf) == [
        ("relayhost", "[smtp.example.net]:587"),
        (
            "smtpd_relay_restrictions",
            "permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination",
        ),
        ("mynetworks", "127.0.0.0/8 [::1]/128"),
    ]
    master = ["smtp      inet  n       -       y       -       -       smtpd", "  -o x=y"]
    assert postfix_services(master) == [("smtp inet", "n - y - - smtpd -o x=y")]
    debian = ["dc_smarthost='relay.example.net::587'", "dc_relay_nets=''"]
    assert exim_settings("/etc/exim4/update-exim4.conf.conf", debian) == [
        ("dc_smarthost", "relay.example.net::587"),
        ("dc_relay_nets", ""),
    ]
    conf = ["hostlist relay_from_hosts = <; 127.0.0.1 ; ::1", "  route_list = * relay.example"]
    assert exim_settings("/etc/exim/exim.conf", conf) == [
        ("hostlist relay_from_hosts", "<; 127.0.0.1 ; ::1"),
        ("route_list", "* relay.example"),
    ]


# --- Checks ------------------------------------------------------------------------------


def run(events=(), snapshot=None, baseline=None, earlier=(), previous=None, baseline_time=None):
    snapshot = snapshot or snap()
    context = Context(
        host="web01",
        bundle_id="b2",
        events=list(events),
        snapshot=snapshot,
        baseline_id="b0" if baseline else None,
        since_baseline=compare(baseline, snapshot) if baseline else None,
        since_previous=None,
        earlier_events=lambda: [list(e) for e in earlier],
        previous_snapshot=previous,
        baseline_time=(baseline_time or T0).isoformat() if baseline else None,
        baseline_snapshot=baseline,
    )
    findings, ran = run_checks(context)
    assert not [r for r in ran if r["status"].startswith("failed")], ran
    return findings


def config(**settings):
    return {
        f"postfix: {name}": {"value": value, "path": "/etc/postfix/main.cf"}
        for name, value in settings.items()
    }


def test_mail_from_a_web_server_account():
    accounts = {"www-data": {"uid": 33}, "jch": {"uid": 1000}}
    events = [
        ev("mail.submitted", 1, source="mail_journal", queue_id="A", uid=33),
        ev("mail.submitted", 2, source="mail_journal", queue_id="B", uid=33),
        ev("mail.submitted", 3, source="mail_journal", queue_id="C", uid=1000),
        ev("mail.submitted", 4, source="mail_log:/var/log/exim4/mainlog", user="apache"),
    ]
    found = of(run(events, snap(accounts=accounts)), "mail.web_user")
    assert [(f.summary, f.band) for f in found] == [
        ("apache: 1 message", "medium"),
        ("www-data: 2 messages", "medium"),
    ]


def test_a_relay_change_and_an_open_relay():
    before = snap(mail_config=config(relayhost="[smtp.example.net]:587"))
    after = snap(
        mail_config=config(
            relayhost="[evil.example]:25",
            mynetworks="127.0.0.0/8 0.0.0.0/0",
            smtpd_relay_restrictions="permit",
        )
    )
    found = {f.variant: f for f in of(run([], after, baseline=before), "mail.relay")}
    assert found["relay"].band == "medium" and "evil.example" in found["relay"].summary
    assert found["open_relay"].category == "exposure"
    assert "0.0.0.0/0" in found["open_relay"].summary
    assert "neither" in found["open_relay"].summary


def test_a_permit_before_the_refusal_relays_for_anyone():
    after = snap(mail_config=config(smtpd_relay_restrictions="permit, reject_unauth_destination"))
    [found] = of(run([], after), "mail.relay")
    assert found.variant == "open_relay"


@pytest.mark.parametrize(
    "settings",
    [
        {},  # Postfix's defaults refuse relaying
        {"mynetworks": "127.0.0.0/8 10.0.0.0/8 192.168.1.0/24 203.0.113.0/24"},
        {"smtpd_relay_restrictions": "permit_mynetworks, reject_unauth_destination"},
        {"smtpd_relay_restrictions": "permit", "smtpd_recipient_restrictions": "reject"},
        {"mynetworks": "0.0.0.0/0", "inet_interfaces": "loopback-only"},
        {"smtpd_relay_restrictions": "$my_restrictions"},
        {"mynetworks": "hash:/etc/postfix/network_table"},
    ],
)
def test_ordinary_postfix_settings_arent_an_open_relay(settings):
    found = of(run([], snap(mail_config=config(main="x", **settings))), "mail.relay")
    assert found == []


def test_exim_open_relay():
    items = {
        "exim: dc_relay_nets": {"value": "0.0.0.0/0", "path": "/etc/exim4/update-exim4.conf.conf"},
        "exim: domainlist relay_to_domains": {"value": "*", "path": "/etc/exim/exim.conf"},
    }
    [found] = of(run([], snap(mail_config=items)), "mail.relay")
    assert "0.0.0.0/0" in found.summary and "every domain" in found.summary
    items["exim: dc_local_interfaces"] = {"value": "127.0.0.1 ; ::1", "path": "x"}
    assert of(run([], snap(mail_config=items)), "mail.relay") == []


def sent(minutes, queue_id, domain="example.org", kind="mail.sent", local="h:1"):
    return ev(
        kind,
        minutes,
        source="mail_journal",
        queue_id=queue_id,
        recipient=f"{local}@{domain}",
        domain=domain,
    )


def test_a_jump_in_volume_after_the_baseline():
    # Before the baseline: 20 deliveries over ten days, 2 a day.
    earlier = [[sent(-60 * 24 * d, f"E{d}{n}") for d in range(10) for n in range(2)]]
    burst = [sent(10 + n, f"B{n}") for n in range(150)]
    found = of(run(burst, snap(), baseline=snap(), earlier=earlier), "mail.volume")
    assert [(f.variant, f.band) for f in found] == [("deliveries", "medium")]
    assert found[0].summary.startswith(f"{T0.date()}: 150 deliveries")


def test_retries_and_repeats_arent_new_mail():
    # 150 attempts of the same 15 messages, logged in two places.
    retries = [sent(10 + n, f"Q{n % 15}", kind="mail.deferred") for n in range(150)]
    assert of(run(retries, snap(), baseline=snap()), "mail.volume") == []
    # A busy server's ordinary day is no jump: 120 against 100 a day before.
    earlier = [[sent(-60 * 24 * d - n, f"E{d}-{n}") for d in range(1, 11) for n in range(100)]]
    day = [sent(10 + n, f"D{n}") for n in range(120)]
    assert of(run(day, snap(), baseline=snap(), earlier=earlier), "mail.volume") == []


def test_mail_before_the_baseline_isnt_judged():
    # 2 a day for 100 days, then 300 just before the baseline: an average of
    # 5 a day, but none of it after the baseline.
    earlier = [[sent(-60 * 24 * d, f"E{d}{n}") for d in range(1, 101) for n in range(2)]]
    early = [sent(-30 - n / 10, f"B{n}") for n in range(300)]
    assert of(run(early, snap(), baseline=snap(), earlier=earlier), "mail.volume") == []


def test_a_retry_after_the_baseline_isnt_new_mail():
    # Deferred before the baseline, retried after it: counted at the first try.
    first = [sent(-10, f"Q{n}", kind="mail.deferred") for n in range(150)]
    retry = [sent(30, f"Q{n}", kind="mail.sent") for n in range(150)]
    assert of(run(first + retry, snap(), baseline=snap()), "mail.volume") == []


def queues(deferred):
    return {"mail_queues": [{"server": "postfix", "queues": {"deferred": deferred}}]}


def test_a_growing_queue():
    found = of(run([], snap(queues(600)), baseline=snap(queues(0))), "mail.volume")
    assert [(f.variant, f.summary) for f in found] == [
        ("queue", "600 messages waiting; 0 at the baseline")
    ]
    assert of(run([], snap(queues(60)), baseline=snap(queues(10))), "mail.volume") == []
    assert of(run([], snap(queues(60)), baseline=snap(queues(5))), "mail.volume")


def test_many_new_recipient_domains_in_a_day():
    known = [[sent(-60 * 24, f"K{n}", domain=f"old{n}.example") for n in range(80)]]
    burst = [sent(10 + n, f"N{n}", domain=f"new{n}.example") for n in range(60)]
    burst += [sent(70 + n, f"O{n}", domain=f"old{n}.example") for n in range(80)]
    [found] = of(run(burst, snap(), baseline=snap(), earlier=known), "mail.domains")
    assert found.summary.startswith(f"{T0.date()}: 60 new domains: new0.example")
    # Domains seen before the baseline, or earlier that day, aren't new.
    again = [sent(200 + n, f"R{n}", domain=f"new{n}.example") for n in range(60)]
    assert of(run(again, snap(), baseline=snap(), earlier=[burst]), "mail.domains") == []


def test_no_baseline_no_volume_or_domain_checks():
    burst = [sent(10 + n, f"B{n}", domain=f"d{n}.example") for n in range(150)]
    findings = run(burst, snap())
    assert of(findings, "mail.volume") == [] and of(findings, "mail.domains") == []


def test_days_are_utc():
    late = datetime(2027, 1, 2, 23, 30, tzinfo=UTC)
    burst = [sent(10 + n, f"B{n}") for n in range(150)]
    found = of(
        run(burst, snap(), baseline=snap(), baseline_time=late - timedelta(hours=13)), "mail.volume"
    )
    assert found and found[0].summary.startswith("2027-01-02")


def test_deliveries_into_mailboxes_here_arent_outgoing():
    kind, fields = classify_mail(
        "postfix/local", SENT.replace("mx.example.org[192.0.2.25]:25", "local")
    )
    assert fields["local"] is True
    lmtp = SENT.replace("mx.example.org[192.0.2.25]:25", "mail.example.org[private/dovecot-lmtp]")
    assert classify_mail("postfix/lmtp", lmtp)[1]["local"] is True
    assert "local" not in classify_mail("postfix/smtp", SENT)[1]
    _, fields, _ = classify_exim("2026-10-28 10:00:02 1tA-0-DF => h:1 <h:1@web01> R=u T=mail_spool")
    assert fields["local"] is True
    inbound = [
        ev(
            "mail.sent",
            10 + n,
            source="mail_journal",
            queue_id=f"I{n}",
            recipient="h:1@here",
            domain=f"d{n}.example",
            local=True,
        )
        for n in range(150)
    ]
    findings = run(inbound, snap(), baseline=snap())
    assert of(findings, "mail.volume") == [] and of(findings, "mail.domains") == []


def test_installing_a_mail_server_isnt_a_relay_change():
    after = snap(
        mail_config=config(relayhost="", default_transport="error", relay_transport="error")
    )
    assert of(run([], after, baseline=snap(mail_config={})), "mail.relay") == []
    # Setting one where there was none is.
    before = snap(mail_config=config(relayhost=""))
    after = snap(mail_config=config(relayhost="[evil.example]:25"))
    [found] = of(run([], after, baseline=before), "mail.relay")
    assert found.summary == "postfix: relayhost: (empty) → [evil.example]:25"


def test_a_baseline_without_queue_counts_uses_only_the_limit():
    assert of(run([], snap(queues(60)), baseline=snap()), "mail.volume") == []
    [found] = of(run([], snap(queues(600)), baseline=snap()), "mail.volume")
    assert found.summary == "600 messages waiting; no count at the baseline"


def test_defer_all_refuses_relaying():
    items = snap(mail_config=config(smtpd_relay_restrictions="permit_mynetworks, defer_all"))
    assert of(run([], items), "mail.relay") == []


def test_mail_hash_lowercases_domains_as_the_collector_does():
    assert mail_fingerprint(KEY, "a@ÉXAMPLE.org").endswith("@Éxample.org")


def test_coverage_only_names_modules_the_collector_has():
    # A name that isn't a module would show as "not collected" on every bundle.
    from checker.assess import LOG_SOURCES
    from checker.snapshot import FULL

    spec = importlib.util.spec_from_file_location(
        "collector_for_modules", Path(__file__).parents[1] / "checker/collector/collector.py"
    )
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    assert (FULL | set(LOG_SOURCES) | {"boots"}) <= set(collector.MODULES)
