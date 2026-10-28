"""Whitelists (PR 2.2a, DESIGN.md §9): layered rule files, strict
validation, matching on typed fields only, suppression kept and shown."""

from datetime import date, datetime

import pytest
from test_snapshot import add_bundle, host_records

from checker import cli
from checker.assess import analyze, load_assessment
from checker.report import write_report
from checker.whitelist import (
    Layer,
    WhitelistError,
    Window,
    build,
    load,
    matches,
    path_matches,
    read_layer,
    reapply,
)

UID0 = (("root", 0), ("jch", 1000), ("toor", 0))

RULE = """
rules:
  - id: {id}
    match: {match}
    reason: "Explained."
    owner: john
    expires: {expires}
"""


def write(base, where, text):
    path = base / "whitelist" / where
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def rule(id="r1", match="{check: account.uid0, account: toor}", expires="never"):
    return RULE.format(id=id, match=match, expires=expires)


def finding(check="account.uid0", entities=("account:toor",), variant=None, **extra):
    return {"check": check, "variant": variant, "entities": list(entities), **extra}


# --- validation --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (rule(match="{check: no.such, account: x}"), "no check 'no.such'"),
        (rule(match="{check: ssh.login, variant: nope, account: x}"), "no variant 'nope'"),
        (rule(match="{check: account.uid0, variant: x, account: x}"), "its variants: none"),
        (rule(match="{check: account.uid0, colour: red}"), "Extra inputs"),
        (rule(match="{check: account.uid0}"), "broad: true"),
        (rule(match="{check: ssh.login, address: 300.1.1.1}"), "does not appear to be"),
        (rule(match="{check: files.web, path: var/www/*}"), "must start with /"),
        (rule(id="Bad Id"), "lower-case"),
        (rule().replace('reason: "Explained."', 'reason: "  "'), "reason"),
        (rule().replace("    owner: john\n", ""), "owner"),
        (rule().replace("    expires: never\n", ""), "expires"),
        (rule(expires="someday"), "expires"),
        ("rules:\n  - id: x\n   bad indent", "not valid YAML"),
        ("colour: red\n", "colour"),
    ],
)
def test_invalid_files_are_refused_with_their_name(tmp_path, text, message):
    path = tmp_path / "w.yaml"
    path.write_text(text)
    with pytest.raises(WhitelistError) as caught:
        read_layer(path)
    assert str(path) in str(caught.value) and message in str(caught.value)


def test_an_error_names_its_line(tmp_path):
    path = tmp_path / "w.yaml"
    path.write_text(rule() + rule(id="r2", match="{check: no.such, account: x}")[8:])
    with pytest.raises(WhitelistError, match=r"rules\.1\.match \(line 9\)"):
        read_layer(path)


def test_a_broad_rule_must_say_so(tmp_path):
    path = tmp_path / "w.yaml"
    path.write_text(rule(match="{check: account.uid0}") + "    broad: true\n")
    assert read_layer(path).rules[0].broad


# --- layers ------------------------------------------------------------------------------


def test_layers_merge_widest_first_and_name_the_narrowest_match(tmp_path):
    write(tmp_path, "global.yaml", rule(id="everywhere"))
    write(tmp_path, "groups/web.yaml", rule(id="web-only", match="{check: ssh.login, account: x}"))
    write(tmp_path, "hosts/web01.yaml", rule(id="mine"))
    merged = load(tmp_path, "web01", "web")
    assert [(p.layer, p.rule.id) for p in merged.rules] == [
        ("host web01", "mine"),
        ("group web", "web-only"),
        ("global", "everywhere"),
    ]
    findings = [finding()]
    merged.apply(findings)
    assert findings[0]["suppressed_by"]["rule"] == "mine"
    assert [p.rule.id for p in load(tmp_path, "db01", "db").rules] == ["everywhere"]


def test_a_host_can_switch_off_a_wider_rule_with_a_reason(tmp_path):
    write(tmp_path, "global.yaml", rule(id="everywhere"))
    write(
        tmp_path,
        "hosts/web01.yaml",
        "disable:\n  - {id: everywhere, reason: 'Not here.', owner: john}\n",
    )
    merged = load(tmp_path, "web01", None)
    assert merged.rules == [] and merged.disabled[0]["by"] == "host web01"
    findings = [finding()]
    merged.apply(findings)
    assert "suppressed_by" not in findings[0]


def test_switching_off_an_unknown_rule_or_reusing_an_id_is_an_error(tmp_path):
    write(tmp_path, "hosts/web01.yaml", "disable:\n  - {id: nope, reason: x, owner: y}\n")
    with pytest.raises(WhitelistError, match="no such rule"):
        load(tmp_path, "web01", None)
    write(tmp_path, "global.yaml", rule(id="same"))
    write(tmp_path, "hosts/web01.yaml", rule(id="same"))
    with pytest.raises(WhitelistError, match="already used"):
        load(tmp_path, "web01", None)


def test_an_unknown_profile_is_an_error(tmp_path):
    write(tmp_path, "global.yaml", "profiles: [nonesuch]\n")
    with pytest.raises(WhitelistError, match="no profile 'nonesuch'"):
        load(tmp_path, "web01", None)


# --- matching ----------------------------------------------------------------------------


def m(**fields):
    return (
        Layer.model_validate(
            {
                "rules": [
                    {"id": "x", "match": fields, "reason": "r", "owner": "o", "expires": "never"}
                ]
            }
        )
        .rules[0]
        .match
    )


def test_every_given_field_must_match():
    rule_match = m(check="ssh.login", variant="root_login", account="root")
    assert matches(rule_match, finding("ssh.login", ["account:root"], "root_login"))
    assert not matches(rule_match, finding("ssh.login", ["account:root"], "new_address"))
    assert not matches(rule_match, finding("ssh.login", ["account:rooted"], "root_login"))
    assert not matches(rule_match, finding("account.uid0", ["account:root"], "root_login"))


def test_addresses_match_by_network():
    rule_match = m(check="ssh.login", address="203.0.113.0/24")
    assert matches(rule_match, finding("ssh.login", ["address:203.0.113.9"]))
    assert not matches(rule_match, finding("ssh.login", ["address:198.51.100.9"]))
    assert not matches(rule_match, finding("ssh.login", ["address:not-an-address"]))


def test_path_patterns_are_anchored_and_dont_cross_directories():
    one = m(check="files.web", path="/var/www/*")
    deep = m(check="files.web", path="/var/www/**")
    assert matches(one, finding("files.web", ["path:/var/www/x.php"]))
    assert not matches(one, finding("files.web", ["path:/var/www/up/x.php"]))
    assert not matches(one, finding("files.web", ["path:/srv/var/www/x.php"]))
    assert matches(deep, finding("files.web", ["path:/var/www/up/x.php"]))
    # A name the intruder chose can't widen the rule.
    for sneaky in (
        "/var/www/../../etc/shadow",
        "/var/www/./x",
        "/var/www//x",
        "/var/www/x\n/etc/shadow",
    ):
        assert not matches(deep, finding("files.web", [f"path:{sneaky}"]))
    assert path_matches("/a/[b].txt", "/a/[b].txt")  # brackets are literal
    assert not path_matches("/a/[b].txt", "/a/b.txt")
    assert path_matches("/a/**/z", "/a/z") and path_matches("/a/**/z", "/a/b/c/z")
    assert path_matches("/a/x?.log", "/a/x1.log") and not path_matches("/a/x?.log", "/a/x/.log")


def test_expired_rules_stop_applying_and_are_listed(tmp_path):
    write(tmp_path, "hosts/web01.yaml", rule(expires="2026-01-31"))
    merged = load(tmp_path, "web01", None)
    findings = [finding()]
    applied = merged.apply(findings, today=date(2026, 2, 1))
    assert "suppressed_by" not in findings[0] and applied["expired"] == ["host web01/r1"]
    applied = merged.apply(findings, today=date(2026, 1, 31))
    assert findings[0]["suppressed_by"]["rule"] == "r1" and applied["expired"] == []


def test_the_record_holds_the_rules_and_their_hash():
    merged = build([("host h", "f.yaml", read_layer_text(rule()))])
    applied = merged.apply([finding()])
    assert applied["hash"] == merged.digest() and applied["suppressed"] == 1
    assert applied["rules"][0]["id"] == "r1" and applied["matched"] == {"host h/r1": 1}


def read_layer_text(text):
    import yaml

    return Layer.model_validate(yaml.safe_load(text))


# --- analysis, the command and the report --------------------------------------------------


def test_a_suppressed_finding_is_kept_and_counts_for_nothing(home):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records(accounts=UID0))
    write(base, "hosts/web01.yaml", rule())
    merged = load(base, "web01", None)
    assessment = analyze(store, "web01", identity, config.recipients, whitelist=merged)
    [uid0] = [f for f in assessment["findings"] if f["check"] == "account.uid0"]
    assert uid0["suppressed_by"]["reason"] == "Explained." and uid0["contribution"] == 0
    assert all(c["check"] != "account.uid0" for c in assessment["score"]["contributors"])
    assert "compromise indicator/critical" not in assessment["counts"]
    assert assessment["whitelist"]["suppressed"] == 1


def test_cli_analyze_refuses_an_invalid_whitelist(home, capsys):
    base = home[0]
    add_bundle(home, "b1", 0, host_records())
    path = write(base, "hosts/web01.yaml", rule(match="{check: no.such, account: x}"))
    assert cli.main(["analyze", "web01"]) == 1
    err = capsys.readouterr().err
    assert str(path) in err and "no check" in err


def test_cli_analyze_counts_and_lists_suppressed_findings(home, capsys):
    base = home[0]
    add_bundle(home, "b1", 0, host_records(accounts=UID0))
    write(base, "hosts/web01.yaml", rule())
    assert cli.main(["analyze", "web01"]) == 0
    out = capsys.readouterr().out
    assert "1 finding(s) suppressed" in out and "UID 0" not in out.split("Whitelist")[1]
    assert cli.main(["analyze", "web01", "--suppressed"]) == 0
    assert "by host web01 / r1: Explained." in capsys.readouterr().out


def test_the_report_shows_suppressed_findings_and_follows_a_changed_whitelist(home, monkeypatch):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records(accounts=UID0))
    analyze(store, "web01", identity, config.recipients)
    write(base, "hosts/web01.yaml", rule())
    merged = load(base, "web01", None)

    def no_analysis(*args, **kwargs):
        raise AssertionError("the checks ran again")

    monkeypatch.setattr("checker.report.analyze", no_analysis)
    path = write_report(
        store,
        ["web01"],
        identity,
        config.recipients,
        base / "reports",
        whitelists=lambda _: merged,
    )
    html = path.read_text()
    appendix = html.split("<h2>Appendix</h2>")[1]
    assert "host web01 / r1" in appendix and "Explained." in appendix
    assert (
        "An account other than root has UID 0"
        not in html.split("<h2>Appendix</h2>")[0]
        .split("<h2>Summary</h2>")[1]
        .split("<h3>Exposure")[0]
        .split("Probability of compromise")[1]
    )
    assert load_assessment(store, "b1", identity)["whitelist"]["hash"] == merged.digest()


def test_cli_whitelist_check(home, capsys):
    base = home[0]
    assert cli.main(["whitelist", "check"]) == 0
    write(base, "global.yaml", rule(id="everywhere"))
    write(base, "hosts/web01.yaml", rule(id="mine", expires="2020-01-01"))
    assert cli.main(["whitelist", "check", "web01"]) == 0
    out = capsys.readouterr().out
    assert "host web01" in out and "EXPIRED 2020-01-01" in out and "global" in out
    write(base, "groups/web.yaml", "rules: nope\n")
    assert cli.main(["whitelist", "check"]) == 1
    assert "groups/web.yaml" in capsys.readouterr().err


# --- from the review of 2.2a ---------------------------------------------------------------


def test_a_rule_must_cover_every_entity_of_the_kinds_it_names():
    rule_match = m(check="ssh.login", variant="new_address", account="deploy")
    both = finding("ssh.login", ["address:203.0.113.9", "account:admin", "account:deploy"])
    both["variant"] = "new_address"
    assert not matches(rule_match, both)
    only = finding("ssh.login", ["address:203.0.113.9", "account:deploy"], "new_address")
    assert matches(rule_match, only)
    files = m(check="files.scratch", path="/tmp/build/known-tool")
    group = finding("files.scratch", ["path:/tmp/build/known-tool", "path:/tmp/build/evil"])
    assert not matches(files, group)


def test_a_finding_listing_only_some_of_its_entities_matches_no_named_rule():
    partial = finding("files.scratch", ["path:/tmp/a"], entities_complete=False)
    assert not matches(m(check="files.scratch", path="/tmp/**"), partial)
    broad = (
        Layer.model_validate(
            {
                "rules": [
                    {
                        "id": "x",
                        "match": {"check": "files.scratch"},
                        "broad": True,
                        "reason": "r",
                        "owner": "o",
                        "expires": "never",
                    }
                ]
            }
        )
        .rules[0]
        .match
    )
    assert matches(broad, partial)


def test_a_process_name_alone_narrows_nothing(tmp_path):
    path = tmp_path / "w.yaml"
    path.write_text(rule(match="{check: process.injected, program: datadog-agent}"))
    with pytest.raises(WhitelistError, match="program name"):
        read_layer(path)
    path.write_text(
        rule(match="{check: process.injected, program: datadog-agent, exe: /opt/datadog/**}")
    )
    rule_match = read_layer(path).rules[0].match
    real = finding(
        "process.injected",
        ["program:datadog-agent", "pid:7", "exe:/opt/datadog/bin/agent"],
    )
    fake = finding("process.injected", ["program:datadog-agent", "pid:8", "exe:/tmp/x"])
    assert matches(rule_match, real) and not matches(rule_match, fake)


@pytest.mark.parametrize(
    "match",
    [
        "{check: ssh.login, address: 0.0.0.0/0}",
        "{check: ssh.login, address: '::/0'}",
        "{check: files.web, path: /**}",
        "{check: files.web, path: /**/**}",
    ],
)
def test_everything_patterns_need_broad(tmp_path, match):
    path = tmp_path / "w.yaml"
    path.write_text(rule(match=match))
    with pytest.raises(WhitelistError, match="broad: true"):
        read_layer(path)


@pytest.mark.parametrize(
    ("match", "message"),
    [
        ("{check: ssh.login, address: 203.0.113.10/24}", "host bits"),
        ("{check: files.web, path: /var/www/x**}", "whole directories"),
        ("{check: files.web, path: '/a/**/**/**/**/**/b'}", "at most four"),
    ],
)
def test_ambiguous_patterns_are_refused(tmp_path, match, message):
    path = tmp_path / "w.yaml"
    path.write_text(rule(match=match))
    with pytest.raises(WhitelistError, match=message):
        read_layer(path)


def test_matching_a_crafted_name_takes_no_time():
    import time

    start = time.monotonic()
    assert not path_matches("/srv/**/x/**/x/**/y", "/srv/" + "x/" * 2000 + "z")
    assert not path_matches("/tmp/*-*-*-*-*.log", "/tmp/" + "-" * 255)
    assert time.monotonic() - start < 1


def test_hidden_characters_in_a_path_never_match():
    for name in ("/var/www/a\u2028b", "/var/www/a\u202eb", "/var/www/a\x85b"):
        assert not matches(
            m(check="files.web", path="/var/www/*"), finding("files.web", [f"path:{name}"])
        )


def test_ipv4_mapped_addresses_match_their_network():
    rule_match = m(check="ssh.login", address="203.0.113.0/24")
    assert matches(rule_match, finding("ssh.login", ["address:::ffff:203.0.113.5"]))


def test_a_key_given_twice_is_refused(tmp_path):
    path = tmp_path / "w.yaml"
    path.write_text(rule(match="{check: files.web, path: /var/www/app/x, path: /tmp/*}"))
    with pytest.raises(WhitelistError, match="given twice"):
        read_layer(path)


def test_unreadable_odd_and_misnamed_files_are_errors(tmp_path):
    hosts = tmp_path / "whitelist" / "hosts"
    hosts.mkdir(parents=True)
    (hosts / "web01.yml").write_text(rule())
    with pytest.raises(WhitelistError, match="named .yaml"):
        load(tmp_path, "web01", None)
    (hosts / "web01.yml").unlink()
    (hosts / "web01.yaml").symlink_to(tmp_path / "nowhere")
    with pytest.raises(WhitelistError, match="link to nothing"):
        load(tmp_path, "web01", None)
    (hosts / "web01.yaml").unlink()
    (hosts / "web01.yaml").mkdir()
    with pytest.raises(WhitelistError, match="not a regular file"):
        load(tmp_path, "web01", None)
    (hosts / "web01.yaml").rmdir()
    (hosts / "web01.yaml").write_text(rule(expires="2027-13-45"))
    with pytest.raises(WhitelistError, match="not valid YAML|expires"):
        load(tmp_path, "web01", None)


def test_a_switched_off_rule_stays_off(tmp_path, monkeypatch):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "base.yaml").write_text(rule(id="from-profile"))
    monkeypatch.setattr("checker.whitelist.PROFILES", profiles)
    write(tmp_path, "global.yaml", rule(id="everywhere"))
    write(tmp_path, "groups/web.yaml", "disable:\n  - {id: everywhere, reason: x, owner: y}\n")
    write(tmp_path, "hosts/web01.yaml", "profiles: [base]\n" + rule(id="everywhere").lstrip("\n"))
    with pytest.raises(WhitelistError, match="switched off by group web"):
        load(tmp_path, "web01", "web")
    write(tmp_path, "hosts/web01.yaml", "profiles: [base]\n" + rule(id="from-profile").lstrip("\n"))
    with pytest.raises(WhitelistError, match="already used"):
        load(tmp_path, "web01", "web")


def test_whitelist_check_builds_every_set(home, capsys):
    base = home[0]
    write(base, "global.yaml", rule(id="same"))
    write(base, "hosts/web01.yaml", rule(id="same"))
    assert cli.main(["whitelist", "check"]) == 1
    assert "already used" in capsys.readouterr().err


def test_no_whitelist_file_means_no_whitelist(tmp_path):
    assert load(tmp_path, "web01", None) is None


def test_the_report_stops_suppressing_once_a_rule_expires(home, monkeypatch):
    import checker.whitelist as wl

    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records(accounts=UID0))
    write(base, "hosts/web01.yaml", rule(expires="2026-11-15"))
    merged = load(base, "web01", None)
    first = analyze(store, "web01", identity, config.recipients, whitelist=merged)
    assert first["whitelist"]["suppressed"] == 1  # live when analysed

    class Later(wl.datetime):
        @classmethod
        def now(cls, tz=None):
            return wl.datetime(2026, 11, 20, tzinfo=tz)

    monkeypatch.setattr(wl, "datetime", Later)
    write_report(
        store, ["web01"], identity, config.recipients, base / "reports", whitelists=lambda _: merged
    )
    latest = load_assessment(store, "b1", identity)
    assert latest["whitelist"]["expired"] == ["host web01/r1"]
    assert not any(f.get("suppressed_by") for f in latest["findings"])


# --- 2.2b: maintenance windows, test and stale ----------------------------------------------

WEEKLY = """
maintenance:
  - id: patch-night
    every: [sun]
    from: "{start}"
    to: "{end}"
    tz: {tz}
    reason: "Weekly patching."
    owner: ops
    expires: never
"""


def window(**fields):
    base = {"id": "w", "reason": "r", "owner": "o", "expires": "never"}
    return Window.model_validate(base | fields)


def at(text):
    return datetime.fromisoformat(text)


def test_a_weekly_window_in_its_time_zone():
    w = window(every=["sun"], **{"from": "02:00", "to": "04:00"}, tz="America/Los_Angeles")
    assert w.covers(at("2026-11-01T10:30:00+00:00"))  # Sun 02:30 PST
    assert not w.covers(at("2026-11-01T12:00:00+00:00"))  # Sun 04:00 PST: the end is out
    assert not w.covers(at("2026-11-02T10:30:00+00:00"))  # Mon


def test_a_window_across_midnight():
    w = window(every=["sat"], **{"from": "23:00", "to": "01:00"})
    assert w.covers(at("2026-10-31T23:30:00+00:00"))  # Sat night
    assert w.covers(at("2026-11-01T00:30:00+00:00"))  # the Sunday morning after
    assert not w.covers(at("2026-11-01T23:30:00+00:00"))  # Sun night


def test_a_one_off_window():
    w = window(start="2026-11-05T01:00:00-07:00", end="2026-11-05T03:00:00-07:00")
    assert w.covers(at("2026-11-05T08:30:00+00:00"))
    assert not w.covers(at("2026-11-05T10:00:00+00:00"))


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"every": ["sun"], "from": 120, "to": "04:00"}, "quote clock times"),
        ({"every": ["sun"], "from": "2:00", "to": "04:00"}, "HH:MM"),
        ({"every": ["sun"], "from": "02:00", "to": "02:00"}, "same time"),
        ({"every": ["sun"], "from": "02:00"}, "every, from and to"),
        ({"every": ["sunday"], "from": "02:00", "to": "04:00"}, "Input should be"),
        ({"every": ["sun"], "from": "02:00", "to": "04:00", "tz": "Mars/Base"}, "time zone"),
        ({"start": "2026-11-05T01:00:00", "end": "2026-11-05T03:00:00"}, "UTC offset"),
        ({"start": "2026-11-05T03:00:00Z", "end": "2026-11-05T01:00:00Z"}, "not after"),
        (
            {"every": ["sun"], "from": "02:00", "to": "04:00", "start": "2026-11-05T01:00:00Z"},
            "either",
        ),
        ({}, "either"),
    ],
)
def test_invalid_windows_are_refused(fields, message):
    with pytest.raises(ValueError, match=message):
        window(**fields)


def reboot(variant, band, when):
    return {
        "check": "system.reboot",
        "variant": variant,
        "band": band,
        "entities": ["boot:x"],
        "first_seen": when,
        "last_seen": when,
    }


def test_reboots_in_a_window_become_informational_and_undo_cleanly(tmp_path):
    write(tmp_path, "hosts/web01.yaml", WEEKLY.format(start="02:00", end="04:00", tz="UTC"))
    merged = load(tmp_path, "web01", None)
    inside = reboot("unexplained", "low", "2026-11-01T02:30:00+00:00")
    unclean = reboot("unclean", "medium", "2026-11-01T03:00:00+00:00")
    outside = reboot("unexplained", "low", "2026-11-01T05:00:00+00:00")
    operator = reboot("operator", "info", "2026-11-01T02:30:00+00:00")
    findings = [inside, unclean, outside, operator]
    applied = merged.apply(findings, today=date(2026, 11, 2))
    assert applied["maintenance"] == 2
    assert inside["band"] == "info" and inside["maintenance"]["band"] == "low"
    # Unclean: one step down, still visible (John, 2026-10-28).
    assert unclean["band"] == "low" and unclean["maintenance"]["window"] == "patch-night"
    assert outside["band"] == "low" and "maintenance" not in outside
    assert "maintenance" not in operator
    merged.apply(findings, today=date(2026, 11, 2))  # again: the same, not doubled
    assert inside["band"] == "info" and inside["maintenance"]["band"] == "low"
    reapply(findings, None)
    assert inside["band"] == "low" and unclean["band"] == "medium"


def test_an_expired_window_stops_applying(tmp_path):
    write(
        tmp_path,
        "hosts/web01.yaml",
        WEEKLY.format(start="02:00", end="04:00", tz="UTC").replace("never", "2026-10-01"),
    )
    merged = load(tmp_path, "web01", None)
    findings = [reboot("unexplained", "low", "2026-11-01T02:30:00+00:00")]
    applied = merged.apply(findings, today=date(2026, 11, 2))
    assert findings[0]["band"] == "low" and applied["expired"] == ["host web01/patch-night"]


def test_windows_share_ids_with_rules_and_can_be_switched_off(tmp_path):
    write(tmp_path, "global.yaml", WEEKLY.format(start="02:00", end="04:00", tz="UTC"))
    write(tmp_path, "hosts/web01.yaml", "disable:\n  - {id: patch-night, reason: x, owner: y}\n")
    assert load(tmp_path, "web01", None).windows == []
    write(tmp_path, "hosts/web01.yaml", rule(id="patch-night"))
    with pytest.raises(WhitelistError, match="already used"):
        load(tmp_path, "web01", None)


def test_cli_whitelist_test_shows_what_a_change_would_do_and_saves_nothing(home, capsys):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records(accounts=UID0))
    analyze(store, "web01", identity, config.recipients)
    proposed = base / "proposed.yaml"
    proposed.write_text(rule())
    before = len(store.assessments("b1"))
    assert cli.main(["whitelist", "test", "web01", "--file", str(proposed)]) == 0
    out = capsys.readouterr().out
    assert "would hide     critical account.uid0" in out and "(by r1)" in out
    assert "1 of 1 analyses would change. Nothing was saved." in out
    assert len(store.assessments("b1")) == before
    assert not (base / "whitelist" / "hosts" / "web01.yaml").exists()
    # The reverse: the rule in place, a proposal without it.
    write(base, "hosts/web01.yaml", rule())
    analyze(store, "web01", identity, config.recipients, whitelist=load(base, "web01", None))
    proposed.write_text("rules: []\n")
    assert cli.main(["whitelist", "test", "web01", "--file", str(proposed)]) == 0
    assert "would reveal   critical account.uid0" in capsys.readouterr().out


def test_cli_whitelist_test_refuses_an_invalid_proposal(home, capsys):
    base = home[0]
    add_bundle(home, "b1", 0, host_records())
    proposed = base / "proposed.yaml"
    proposed.write_text(rule(match="{check: no.such, account: x}"))
    assert cli.main(["whitelist", "test", "web01", "--file", str(proposed)]) == 1
    assert "the proposed file" in capsys.readouterr().err


def test_cli_whitelist_stale(home, capsys):
    from checker.inventory import Host, inventory_transaction

    base, store, identity, config = home
    with inventory_transaction() as hosts:
        hosts.add(Host(name="web01", address="192.0.2.1", user="u"))
    add_bundle(home, "b1", 0, host_records(accounts=UID0))
    write(
        base,
        "hosts/web01.yaml",
        rule(id="used")
        + rule(id="unused", match="{check: ssh.login, account: nobody}")[8:]
        + rule(id="soon", match="{check: ssh.login, account: x}", expires="2099-01-01")[8:]
        + rule(id="gone", match="{check: ssh.login, account: y}", expires="2020-01-01")[8:],
    )
    analyze(store, "web01", identity, config.recipients, whitelist=load(base, "web01", None))
    assert cli.main(["whitelist", "stale", "--days", "36500"]) == 0
    out = capsys.readouterr().out
    stale_part = out.split("Expired")[0]
    assert "unused" in stale_part and "used (" not in stale_part.replace("unused", "")
    assert "gone (host web01" in out.split("Expired")[1]
    assert "Expiring within 30 days:\n  none" in out


# --- from the review of 2.2b -----------------------------------------------------------------


def outage(variant, start, end, band="low"):
    return {
        "check": "system.reboot",
        "variant": variant,
        "band": band,
        "entities": ["boot:x"],
        "first_seen": start,
        "last_seen": end,
    }


def weekly_set(tmp_path, expires="never"):
    write(
        tmp_path,
        "hosts/web01.yaml",
        WEEKLY.format(start="02:00", end="04:00", tz="UTC").replace("never", expires),
    )
    return load(tmp_path, "web01", None)


def test_the_whole_outage_must_be_inside_the_window(tmp_path):
    merged = weekly_set(tmp_path)
    inside = outage("unexplained", "2026-11-01T02:00:00+00:00", "2026-11-01T02:10:00+00:00")
    started_before = outage("unexplained", "2026-10-31T18:00:00+00:00", "2026-11-01T02:10:00+00:00")
    merged.apply([inside, started_before], today=date(2026, 11, 2))
    assert inside["band"] == "info"  # the window's first minute counts
    assert started_before["band"] == "low"


def test_an_expired_window_still_explains_what_it_covered(tmp_path):
    merged = weekly_set(tmp_path, expires="2026-11-15")
    then = outage("unexplained", "2026-11-01T02:10:00+00:00", "2026-11-01T02:20:00+00:00")
    later = outage("unexplained", "2026-11-22T02:10:00+00:00", "2026-11-22T02:20:00+00:00")
    merged.apply([then, later], today=date(2026, 12, 1))
    assert then["band"] == "info" and later["band"] == "low"


def test_a_maintained_reboot_scores_as_information_whatever_the_override(monkeypatch):
    from checker import scoring

    monkeypatch.setitem(scoring.OVERRIDES, ("system.reboot", None), 9.0)
    found = outage("unexplained", "x", "x", band="info")
    found["maintenance"] = {"window": "w", "band": "low"}
    assert scoring.ratio(found) == 1.0
    stepped = outage("unclean", "x", "x", band="low")
    stepped["maintenance"] = {"window": "w", "band": "medium"}
    assert scoring.ratio(stepped) == scoring.BAND_RATIOS["low"]


def test_daylight_saving_days_follow_the_wall_clock():
    w = window(every=["sun"], **{"from": "02:00", "to": "03:00"}, tz="America/Los_Angeles")
    # 2026-03-08: 02:00-03:00 doesn't exist; nothing in it.
    assert not w.covers(at("2026-03-08T10:30:00+00:00"))  # 03:30 PDT
    late = window(every=["sun"], **{"from": "01:00", "to": "02:00"}, tz="America/Los_Angeles")
    # 2026-11-01: 01:00-02:00 happens twice; both are covered.
    assert late.covers(at("2026-11-01T08:30:00+00:00"))  # 01:30 PDT
    assert late.covers(at("2026-11-01T09:30:00+00:00"))  # 01:30 PST


def test_a_one_off_window_takes_no_time_zone():
    with pytest.raises(ValueError, match="no tz"):
        window(start="2026-11-05T01:00:00Z", end="2026-11-05T03:00:00Z", tz="UTC")


def test_whitelist_check_lists_windows(home, capsys):
    base = home[0]
    write(base, "hosts/web01.yaml", WEEKLY.format(start="02:00", end="04:00", tz="UTC"))
    assert cli.main(["whitelist", "check", "web01"]) == 0
    assert "patch-night" in capsys.readouterr().out


def test_whitelist_test_works_while_the_current_file_is_broken(home, capsys):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records(accounts=UID0))
    analyze(store, "web01", identity, config.recipients)
    write(base, "hosts/web01.yaml", rule(match="{check: no.such, account: x}"))
    fixed = base / "fixed.yaml"
    fixed.write_text(rule())
    assert cli.main(["whitelist", "test", "web01", "--file", str(fixed)]) == 0
    out = capsys.readouterr().out
    assert "the current set is invalid" in out and "would hide" in out


def test_whitelist_test_replaces_the_named_layer(home, capsys):
    from checker.inventory import Host, inventory_transaction

    base, store, identity, config = home
    with inventory_transaction() as hosts:
        hosts.add(Host(name="web01", address="192.0.2.1", user="u", group="web"))
    add_bundle(home, "b1", 0, host_records(accounts=UID0))
    write(base, "groups/web.yaml", rule(id="group-rule"))
    analyze(store, "web01", identity, config.recipients, whitelist=load(base, "web01", "web"))
    empty = base / "empty.yaml"
    empty.write_text("rules: []\n")
    assert cli.main(["whitelist", "test", "web01", "--file", str(empty), "--as", "group"]) == 0
    assert "would reveal" in capsys.readouterr().out
    assert cli.main(["whitelist", "test", "web01", "--file", str(empty), "--as", "global"]) == 0
    assert "0 of 1 analyses would change" in capsys.readouterr().out


def test_whitelist_test_shows_rebanding(home, capsys):
    base, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    analyze(store, "web01", identity, config.recipients)
    stored = load_assessment(store, "b1", identity)
    stored["findings"].append(
        outage("unexplained", "2026-11-01T02:10:00+00:00", "2026-11-01T02:20:00+00:00")
        | {"title": "An unexplained reboot", "category": "compromise indicator", "summary": "s"}
    )
    from checker.assess import store_assessment

    store_assessment(store, store.bundle("b1"), config.recipients, stored)
    windows = base / "windows.yaml"
    windows.write_text(WEEKLY.format(start="02:00", end="04:00", tz="UTC"))
    assert cli.main(["whitelist", "test", "web01", "--file", str(windows)]) == 0
    assert "would reband   info system.reboot: s (low -> info)" in capsys.readouterr().out


def test_whitelist_commands_report_a_wrong_key_without_a_traceback(home, capsys, tmp_path):
    from pyrage import x25519

    add_bundle(home, "b1", 0, host_records())
    analyze(home[1], "web01", home[2], home[3].recipients)
    other = tmp_path / "other.key"
    other.write_text(str(x25519.Identity.generate()) + "\n")
    proposed = tmp_path / "p.yaml"
    proposed.write_text("rules: []\n")
    args = ["whitelist", "test", "web01", "--file", str(proposed), "--identity", str(other)]
    assert cli.main(args) == 1
    assert "can't read the stored analyses" in capsys.readouterr().err


def test_stale_days_are_bounded(home):
    with pytest.raises(SystemExit):
        cli.main(["whitelist", "stale", "--days", "0"])
    with pytest.raises(SystemExit):
        cli.main(["whitelist", "stale", "--days", "99999999999"])


def test_stale_counts_shared_rules_once_skips_expired_and_windows_and_sees_orphans(home):
    from datetime import UTC as _UTC

    from checker.inventory import Host, inventory_transaction
    from checker.whitelist import other_sets
    from checker.whitelist_review import stale

    base, store, identity, config = home
    with inventory_transaction() as hosts:
        for name in ("web01", "web02"):
            hosts.add(Host(name=name, address="192.0.2.1", user="u"))
    add_bundle(home, "b1", 0, host_records(accounts=UID0))  # web01 only
    write(
        base,
        "global.yaml",
        rule(id="shared")
        + rule(id="soon", match="{check: ssh.login, account: x}", expires="2027-01-20")[8:]
        + rule(id="gone", match="{check: ssh.login, account: y}", expires="2020-01-01")[8:]
        + WEEKLY.format(start="02:00", end="04:00", tz="UTC"),
    )
    write(base, "groups/db.yaml", rule(id="nobody-uses", match="{check: ssh.login, account: z}"))
    analyze(store, "web01", identity, config.recipients)  # no whitelist then: a new rule
    from checker.inventory import load_inventory

    sets = {h: load(base, h, None) for h in ("web01", "web02")} | other_sets(base, load_inventory())
    found = stale(store, identity, sets, 36500, now=datetime(2027, 1, 2, 13, 0, tzinfo=_UTC))
    ids = {line.split(" ")[0] for line in found["stale"]}
    assert "shared" not in ids  # used on web01; web02's lack of use doesn't count
    assert "gone" not in ids and "patch-night" not in ids
    assert ids == {"soon", "nobody-uses"}
    assert any(e.startswith("gone") for e in found["expired"])
    assert any(e.startswith("soon") for e in found["expiring"])
