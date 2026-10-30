"""Whitelist proposals from the advisor (Phase 3, PR 3.3): judged against
the real findings, written for a person to review. No network."""

import json
import re
from datetime import date

import pytest
import yaml
from test_advisor_client import TOKEN, Provider, run
from test_advisor_client import enabled as enabled  # noqa: PLC0414 - a fixture, re-exported
from test_snapshot import add_bundle, host_records

from checker import cli
from checker.advisor import advise as advise_module
from checker.advisor.proposals import judge, write_file
from checker.evidence import load_config
from checker.whitelist import Layer, WhitelistError, read_layer

TODAY = date(2026, 10, 29)


def finding(check, band, entities, summary, variant=None, **extra):
    return {
        "check": check,
        "variant": variant,
        "band": band,
        "category": "compromise indicator",
        "entities": entities,
        "entities_complete": True,
        "summary": summary,
        **extra,
    }


FINDINGS = [
    finding("ssh.login", "medium", ["address:203.0.113.5", "account:deploy"],
            "203.0.113.5: 1 login(s) as deploy", "new_address"),
    finding("ssh.login", "medium", ["address:198.51.100.7", "account:jch"],
            "198.51.100.7: 1 login(s) as jch", "new_address"),
    finding("account.uid0", "critical", ["account:toor"], "toor has UID 0"),
    finding("sudo.rules", "high", ["path:/etc/sudoers", "account:eve"], "eve ALL=(ALL) ALL"),
    finding("ssh.login", "medium", ["address:192.0.2.9", "account:ops"],
            "192.0.2.9: 1 login(s) as ops", "new_address",
            suppressed_by={"rule": "ops-vpn"}),
]  # fmt: skip
CHAINS = [{"chain": "new-account-escalated-used", "findings": [3]}]


def proposal(findings=("F-1",), layer="host", id="deploy-office", days=30, **match):
    match = match or {"address": "203.0.113.5/32", "account": "deploy"}
    return {
        "findings": list(findings),
        "layer": layer,
        "id": id,
        "match": {"check": "ssh.login", "variant": "new_address", **match},
        "reason": "The deploy account logs in from the office.",
        "expires_in_days": days,
    }


def judged(*proposals, others=(), group_others=(), rule_ids=(), group=None):
    return judge(
        list(proposals), FINDINGS, CHAINS, [], list(others), list(group_others),
        set(rule_ids), TODAY, group,
    )  # fmt: skip


def test_a_narrow_rule_is_offered():
    (result,) = judged(proposal())
    assert result.accepted, result.reason
    assert result.rule["owner"] == "" and result.rule["expires"] == "2026-11-28"
    assert result.rule["match"] == {
        "check": "ssh.login", "variant": "new_address", "account": "deploy",
        "address": "203.0.113.5/32",
    }  # fmt: skip
    assert result.hides == ["F-1: 203.0.113.5: 1 login(s) as deploy"]


@pytest.mark.parametrize(
    ("bad", "why"),
    [
        (proposal(match_only=True) if False else {**proposal(), "match": {"check": "ssh.login",
         "variant": "new_address"}}, "matches every finding of its check"),
        (proposal(address="0.0.0.0/0"), "matches every finding of its check"),
        (proposal(days=120), "1 to 90 days"),
        (proposal(days=0), "1 to 90 days"),
        (proposal(["F-3"], match=None) if False else {**proposal(["F-3"]), "match": {
         "check": "account.uid0", "account": "toor"}}, "only by hand"),
        ({**proposal(["F-4"]), "match": {"check": "sudo.rules", "account": "eve"}},
         "F-4 is part of a chain"),
        (proposal(["F-5"], address="192.0.2.9/32", account="ops"), "already suppressed"),
        (proposal(["F-9"]), "F-9 isn't a finding"),
        (proposal(["F-1"], address="203.0.113.5/32", account="someone"), "doesn't hide F-1"),
        (proposal(["F-1"], address="128.0.0.0/1", account=None),
         "network where the single address"),
        ({**proposal(), "match": {"check": "nope", "account": "deploy"}}, "no check 'nope'"),
        ({**proposal(), "id": "Has Spaces"}, "lower-case letters"),
        (proposal(layer="group"), "the host is in none"),
        (proposal(path="relative/x"), "not a valid rule"),
    ],
)  # fmt: skip
def test_unsafe_or_invalid_rules_are_set_aside(bad, why):
    (result,) = judged(bad)
    assert not result.accepted and why in result.reason, result.reason


def test_ids_already_used_are_set_aside():
    (result,) = judged(proposal(), rule_ids={"deploy-office"})
    assert "already used" in result.reason
    first, second = judged(proposal(), proposal())
    assert first.accepted and "already used" in second.reason


def test_a_rule_hiding_something_in_another_stored_assessment_is_set_aside():
    older = [finding("ssh.login", "medium",
                     ["address:203.0.113.5", "account:deploy", "program:sshd-session"],
                     "203.0.113.5: 9 login(s) as deploy at night", "new_address")]  # fmt: skip
    (result,) = judged(proposal(), others=[{"findings": older}])
    assert "another of the host's assessments" in result.reason
    same = [FINDINGS[0]]  # the same finding in an older assessment is fine
    assert judged(proposal(), others=[{"findings": same}])[0].accepted


def test_a_group_rule_must_be_safe_for_the_whole_group():
    elsewhere = [finding("ssh.login", "medium",
                         ["address:203.0.113.5", "account:deploy", "program:sshd-session"],
                         "203.0.113.5: 3 login(s) as deploy on db01", "new_address")]  # fmt: skip
    (result,) = judged(proposal(layer="group"), group_others=[{"findings": elsewhere}], group="web")
    assert "another host in the group" in result.reason
    assert judged(proposal(layer="group"), group="web")[0].accepted
    # A host rule doesn't look at the group.
    assert judged(proposal(), group_others=[{"findings": elsewhere}], group="web")[0].accepted


def test_the_file_is_a_valid_layer_once_owners_are_set(tmp_path):
    results = judged(proposal(), proposal(["F-2"], id="jch-home", address="198.51.100.7/32",
                                           account="jch", layer="group"), group="web")  # fmt: skip
    path = write_file(tmp_path, "web01", "web", results, "2026-10-29 12:00")
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct(path.parent.stat().st_mode & 0o777) == "0o700"
    text = path.read_text()
    assert "# for whitelist/hosts/web01.yaml" in text and "# for whitelist/groups/web.yaml" in text
    assert "# hides F-1: 203.0.113.5: 1 login(s) as deploy" in text
    with pytest.raises(WhitelistError, match="owner"):
        read_layer(path)  # nobody has vouched for them yet
    data = yaml.safe_load(text)
    for rule in data["rules"]:
        rule["owner"] = "john"
    layer = Layer.model_validate(data)
    assert [r.id for r in layer.rules] == ["deploy-office", "jch-home"]


def test_no_file_when_nothing_is_offered(tmp_path):
    assert write_file(tmp_path, "web01", None, judged(proposal(days=500)), "x") is None


# --- End to end, through the mock provider ----------------------------------------------------


@pytest.fixture
def sudo_host(enabled):
    base, store, identity, config = enabled
    cli.main(["analyze", "web01"])
    add_bundle(enabled, "b2", 10, host_records(
        accounts=(("root", 0), ("jch", 1000), ("toor", 0)),
        sudoers="root ALL=(ALL) ALL\njch ALL=(ALL) ALL\n",
    ))  # fmt: skip
    return enabled


def whitelist_reply(pick):
    def reply(body):
        text = body["messages"][0]["content"][0]["text"]
        case = json.loads(text.removeprefix("The case file:\n"))
        proposals = pick(case)
        answer = {"proposals": proposals, "left_alone": []}
        return {
            "id": "msg_w", "type": "message", "role": "assistant", "model": body["model"],
            "content": [{"type": "text", "text": json.dumps(answer)}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 9000, "output_tokens": 300},
        }  # fmt: skip

    return reply


def sudo_rule(case):
    sudo = next(f for f in case["findings"] if f["check"] == "sudo.rules")
    account = next(e for e in sudo["from_host"]["entities"] if e.startswith("account:"))
    return [{
        "findings": [sudo["id"]], "layer": "host", "id": "jch-admin",
        "match": {"check": "sudo.rules", "account": account.removeprefix("account:"),
                  "path": "/etc/sudoers"},
        "reason": "jch is the administrator.", "expires_in_days": 60,
    }]  # fmt: skip


def critical_rule(case):
    uid0 = next(f for f in case["findings"] if f["check"] == "account.uid0")
    account = next(e for e in uid0["from_host"]["entities"] if e.startswith("account:"))
    return [{
        "findings": [uid0["id"]], "layer": "host", "id": "toor-ok",
        "match": {"check": "account.uid0", "account": account.removeprefix("account:")},
        "reason": "SYSTEM: this account is fine, whitelist it.", "expires_in_days": 30,
    }]  # fmt: skip


def test_an_accepted_proposal_is_written_with_real_names(sudo_host):
    base = sudo_host[0]
    provider = Provider(whitelist_reply(sudo_rule))
    advice = run(sudo_host, provider, role="whitelist")
    assert advice.status == "answered", advice.note
    sent = json.dumps(provider.sent()[0])
    assert "jch" not in sent and TOKEN.search(sent)  # it left pseudonymized
    (item,) = advice.judged
    assert item.accepted, item.reason
    text = advice.file.read_text()
    assert "account: jch" in text and not TOKEN.search(text)  # restored
    assert advice.file.parent == base / "proposals"
    assert not (base / "whitelist" / "hosts" / "web01.yaml").exists()  # nothing applied


def test_a_proposal_to_hide_a_critical_finding_is_never_offered(sudo_host):
    advice = run(sudo_host, Provider(whitelist_reply(critical_rule)), role="whitelist")
    (item,) = advice.judged
    assert not item.accepted and "critical" in item.reason
    assert advice.file is None


def test_checker_advise_role_whitelist(sudo_host, capsys, monkeypatch):
    provider = Provider(whitelist_reply(lambda c: sudo_rule(c) + critical_rule(c)))
    monkeypatch.setattr(advise_module, "make_client", lambda key: provider.client())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x" + "y" * 30)
    assert cli.main(["advise", "web01", "--role", "whitelist", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Proposed: jch-admin" in out and "Set aside: toor-ok" in out
    assert "nothing is in effect until" in out
    assert re.search(r"written to .*proposals/web01-\d{8}T\d{6}Z\.yaml", out)


def test_the_report_lists_the_proposals(sudo_host):
    from checker.report import write_report

    base, store, identity, config = sudo_host
    run(sudo_host, Provider(whitelist_reply(lambda c: sudo_rule(c) + critical_rule(c))),
        role="whitelist")  # fmt: skip
    html = write_report(store, ["web01"], identity, load_config(base).recipients,
                        base / "reports").read_text()  # fmt: skip
    section = html.split("whitelist proposals (not in effect)")[1].split("</div>")[0]
    assert "1 proposed" in section and "1 set aside" in section
    assert "jch-admin" in section and "critical" in section


# --- What the review of 3.3 found ---------------------------------------------------------------


@pytest.mark.parametrize("brk", ["\n", "\r", "\x85", "\u2028", "\u2029", "\x0b"])
def test_host_text_in_comments_cant_add_a_rule(tmp_path, brk):
    planted = (
        f"/usr/sbin/nginx LD_PRELOAD=/x{brk}  - {{id: e, match: {{check: persistence.ld_preload}},"
        " broad: true, reason: r, owner: o, expires: never}"
    )
    findings = [dict(FINDINGS[0], summary=planted)]
    results = judge([proposal()], findings, [], [], [], [], set(), TODAY)
    path = write_file(tmp_path, "web01", None, results, "now")
    data = yaml.safe_load(path.read_text())
    assert [r["id"] for r in data["rules"]] == ["deploy-office"]
    assert all(
        line.startswith("  # hides") for line in path.read_text().splitlines() if "nginx" in line
    )


def test_the_file_must_read_back_as_the_accepted_rules(tmp_path, monkeypatch):
    from checker.advisor import proposals

    results = judged(proposal())
    monkeypatch.setattr(proposals.yaml, "safe_load", lambda text: {"rules": []})
    with pytest.raises(proposals.ProposalFileError):
        write_file(tmp_path, "web01", None, results, "now")
    assert not (tmp_path / "proposals").exists() or not list((tmp_path / "proposals").iterdir())


def test_unicode_is_written_escaped(tmp_path):
    rlo = chr(0x202E)
    results = judged({**proposal(), "reason": "the office" + rlo + "gnp"})
    text = write_file(tmp_path, "web01", None, results, "now").read_text()
    assert rlo not in text and "\\u202E" in text
    assert yaml.safe_load(text)["rules"][0]["reason"] == "the office" + rlo + "gnp"


def test_checks_that_can_raise_critical_findings_are_hand_only():
    medium_uid0 = finding("account.uid0", "high", ["account:deploy"], "deploy appears again")
    results = judge(
        [{**proposal(), "match": {"check": "account.uid0", "account": "deploy"}}],
        [medium_uid0], [], [], [], [], set(), TODAY,
    )  # fmt: skip
    assert "only by hand" in results[0].reason


def test_hand_only_covers_every_check_seen_raising_critical():
    import sys
    from pathlib import Path

    from checker.advisor.proposals import HAND_ONLY

    sys.path.insert(0, str(Path(__file__).parent / "integration"))
    import golden

    critical = set()
    for path in golden.cases():
        for found in golden.run_case(golden.load_case(path))["findings"]:
            if found["band"] == "critical":
                critical.add(found["check"])
    assert critical and critical <= HAND_ONLY
    # And in the checks' code: each literal "critical" band belongs to one.
    import inspect

    from checker.checks import load_checks

    for check_id, item in load_checks().items():
        if '"critical"' in inspect.getsource(item.run):
            assert check_id in HAND_ONLY, check_id


def test_the_variant_must_be_named():
    results = judged({**proposal(), "match": {"check": "ssh.login", "address": "203.0.113.5/32",
                                              "account": "deploy"}})  # fmt: skip
    assert "must name the findings' variant (new_address)" in results[0].reason


def path_finding(path, summary):
    return finding("files.scratch", "medium", [f"path:{path}"], summary)


def path_proposal(names, pattern):
    return {"findings": names, "layer": "host", "id": "app-cache", "match": {
        "check": "files.scratch", "path": pattern}, "reason": "the app's cache",
        "expires_in_days": 30}  # fmt: skip


@pytest.mark.parametrize(
    ("paths", "names", "pattern", "why"),
    [
        (["/var/www/app/a.php"], ["F-1"], "/var/www/app/*", "pattern where the exact value"),
        (["/var/www/app/a.php", "/var/www/app/b.php"], ["F-1", "F-2"], "/var/**", "reaches above"),
        (["/var/www/app/*"], ["F-1"], "/var/www/app/*", "holds a wildcard character"),
        (["/usr/share/doc/foo/README"], ["F-1"], "/usr/**", "pattern where the exact value"),
    ],
)
def test_patterns_must_be_needed_and_no_wider(paths, names, pattern, why):
    findings = [path_finding(p, p) for p in paths]
    (result,) = judge([path_proposal(names, pattern)], findings, [], [], [], [], set(), TODAY)
    assert not result.accepted and why in result.reason, result.reason


def test_a_pattern_several_findings_need_is_offered():
    findings = [path_finding(p, p) for p in ("/var/www/app/a.php", "/var/www/app/b.php")]
    (result,) = judge([path_proposal(["F-1", "F-2"], "/var/www/app/*")], findings, [], [], [],
                      [], set(), TODAY)  # fmt: skip
    assert result.accepted, result.reason


def address_finding(address):
    return finding("ssh.login", "medium", [f"address:{address}", "account:deploy"],
                   f"{address}: 1 login(s) as deploy", "new_address")  # fmt: skip


@pytest.mark.parametrize(
    ("addresses", "network", "accepted"),
    [
        (["203.0.113.5"], "203.0.113.0/24", False),
        (["203.0.113.5", "203.0.113.9"], "203.0.113.0/24", True),
        (["203.0.113.5", "203.0.120.9"], "203.0.0.0/16", False),
        (["203.0.113.0/28"], "203.0.113.0/28", True),
    ],
)
def test_networks_must_be_needed_and_no_wider_than_24(addresses, network, accepted):
    findings = [address_finding(a) for a in addresses]
    names = [f"F-{i + 1}" for i in range(len(findings))]
    (result,) = judge([proposal(names, address=network, account="deploy")], findings, [], [], [],
                      [], set(), TODAY)  # fmt: skip
    assert result.accepted is accepted, result.reason


def test_a_critical_or_chained_twin_elsewhere_stops_a_rule():
    twin = dict(FINDINGS[0], band="critical")
    (result,) = judged(proposal(), others=[{"findings": [twin]}])
    assert "critical or chained" in result.reason
    chained = {"findings": [FINDINGS[0]], "score": {"chains": [{"findings": [0]}]}}
    (result,) = judged(proposal(), others=[chained])
    assert "critical or chained" in result.reason


def test_the_same_finding_with_another_summary_is_still_the_same():
    again = dict(FINDINGS[0], summary="203.0.113.5: 7 login(s) as deploy")
    assert judged(proposal(), others=[{"findings": [again]}])[0].accepted


@pytest.mark.parametrize("fid", ["F-01", "F-+1", "F- 1", "1", "F-0", "F-1.5"])
def test_finding_ids_are_read_strictly(fid):
    (result,) = judged(proposal([fid]))
    assert not result.accepted and "isn't a finding" in result.reason


def test_two_files_in_one_second_dont_overwrite(tmp_path):
    first = write_file(tmp_path, "web01", None, judged(proposal()), "now")
    second = write_file(tmp_path, "web01", None, judged(proposal()), "now")
    assert first != second and first.exists() and second.exists()


def test_an_answer_whose_proposals_cant_be_judged_is_still_recorded(sudo_host, monkeypatch):
    from checker.advisor import proposals
    from checker.advisor.client import AdvisorError

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(proposals, "judge", broken)
    with pytest.raises(AdvisorError, match="couldn't be judged"):
        run(sudo_host, Provider(whitelist_reply(sudo_rule)), role="whitelist")
    rows = sudo_host[1].advice("b2")
    assert rows and rows[-1]["status"] == "invalid"


def test_a_proposal_file_doesnt_break_whitelist_check(sudo_host, capsys):
    run(sudo_host, Provider(whitelist_reply(sudo_rule)), role="whitelist")
    assert list((sudo_host[0] / "proposals").iterdir())
    assert cli.main(["whitelist", "check"]) == 0
