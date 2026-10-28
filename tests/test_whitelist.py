"""Whitelists (PR 2.2a, DESIGN.md §9): layered rule files, strict
validation, matching on typed fields only, suppression kept and shown."""

from datetime import date

import pytest
from test_snapshot import add_bundle, host_records

from checker import cli
from checker.assess import analyze, load_assessment
from checker.report import write_report
from checker.whitelist import (
    Layer,
    WhitelistError,
    build,
    load,
    matches,
    path_pattern,
    read_layer,
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
    assert path_pattern("/a/[b].txt").fullmatch("/a/[b].txt")  # brackets are literal
    assert not path_pattern("/a/[b].txt").fullmatch("/a/b.txt")


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
