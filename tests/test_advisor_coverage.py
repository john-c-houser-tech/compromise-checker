"""Coverage suggestions from the advisor (Phase 3, PR 3.4, role 3): only
settings and host configuration the tool knows; nothing changes. No
network."""

import json

import pytest
from test_advisor_client import Provider, run
from test_advisor_client import enabled as enabled  # noqa: PLC0414 - a fixture, re-exported

from checker import cli
from checker.advisor import advise as advise_module
from checker.advisor.coverage import CATALOGUE, judge
from checker.evidence import Config, load_config

GAPS = [
    "no audit log: earlier program starts by web accounts can't be checked",
    "web access logs not collected (not chosen at setup)",
]


def config(**settings):
    return Config(recipients=["age1x"], **settings)


def setting(key, value, helps=("G-1",)):
    return {"kind": "setting", "setting": key, "value": value, "helps_with": list(helps),
            "why": "see more", "trade_off": "privacy"}  # fmt: skip


def host(item, helps=("G-1",)):
    return {"kind": "host", "item": item, "helps_with": list(helps), "why": "see more",
            "trade_off": "disk"}  # fmt: skip


def test_a_known_setting_is_offered_as_a_command():
    (result,) = judge([setting("web_access_logs", "on")], GAPS, set(), config())
    assert result.accepted and result.action == "checker config set web_access_logs on"


def test_a_catalogue_entry_is_offered_as_text():
    (result,) = judge([host("journald-persistent", ["F-2"])], [], {"F-2"}, config())
    assert result.accepted and result.action == CATALOGUE["journald-persistent"]["how"]


@pytest.mark.parametrize(
    ("suggestion", "why"),
    [
        (setting("advisor.enabled", "on"), "isn't a collection setting"),
        (setting("retention_days", "9999"), "isn't a collection setting"),
        (setting("exec_records", "none"), "can't be suggested as 'none'"),
        (setting("web_access_logs", "off"), "already off"),
        (host("curl-pipe-bash"), "isn't in the host configuration catalogue"),
        (setting("web_access_logs", "on", ["G-9"]), "isn't one of the case's 2 coverage gaps"),
        (setting("web_access_logs", "on", ["F-9"]), "isn't a finding of the case"),
        (setting("web_access_logs", "on", ["X-1"]), "neither a coverage gap"),
        (setting("web_access_logs", "on", ["G-01"]), "neither a coverage gap"),
        (setting("web_access_logs", "on", []), "cites no coverage gap"),
        ({**setting("web_access_logs", "on"), "kind": "module"}, "kind must be"),
    ],
)
def test_anything_else_is_set_aside(suggestion, why):
    (result,) = judge([suggestion], GAPS, {"F-1"}, config())
    assert not result.accepted and why in result.reason, result.reason


def test_a_setting_already_so_is_set_aside():
    (result,) = judge(
        [setting("home_text", "privileged")], GAPS, set(), config(home_text="privileged")
    )
    assert "already privileged" in result.reason
    (result,) = judge([setting("web_access_logs", "on")], GAPS, set(), config(web_access_logs=True))
    assert "already on" in result.reason


def test_a_repeat_is_set_aside():
    first, second = judge([host("auditd-running"), host("auditd-running")], GAPS, set(), config())
    assert first.accepted and "repeats" in second.reason


# --- End to end, through the mock provider ----------------------------------------------------


def coverage_reply(suggestions):
    def reply(body):
        return {
            "id": "msg_c", "type": "message", "role": "assistant", "model": body["model"],
            "content": [{"type": "text", "text": json.dumps({"suggestions": suggestions})}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 9000, "output_tokens": 200},
        }  # fmt: skip

    return reply


SUGGESTIONS = [
    setting("web_access_logs", "on", ["F-1"]),
    host("sshd-log-verbose", ["F-1"]),
    {"kind": "host", "item": "rm -rf /", "helps_with": ["F-1"], "why": "x", "trade_off": "y"},
]


def test_suggestions_are_judged_and_nothing_changes(enabled):
    base = enabled[0]
    provider = Provider(coverage_reply(SUGGESTIONS))
    advice = run(enabled, provider, role="coverage")
    assert advice.status == "answered", advice.note
    assert [j.accepted for j in advice.judged] == [True, True, False]
    assert load_config(base).web_access_logs is False  # suggested, not set
    question = provider.sent()[0]["messages"][0]["content"][1]["text"]
    assert "only from this list" in question and "sshd-log-verbose" in question


def test_checker_advise_role_coverage(enabled, capsys, monkeypatch):
    provider = Provider(coverage_reply(SUGGESTIONS))
    monkeypatch.setattr(advise_module, "make_client", lambda key: provider.client())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x" + "y" * 30)
    assert cli.main(["advise", "web01", "--role", "coverage", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "checker config set web_access_logs on" in out
    assert "LogLevel VERBOSE" in out
    assert "Set aside: rm -rf /: 'rm -rf /' isn't in the host configuration catalogue" in out
    assert "nothing was changed" in out


def test_the_report_lists_the_suggestions(enabled):
    from checker.report import write_report

    base, store, identity, config_ = enabled
    run(enabled, Provider(coverage_reply(SUGGESTIONS)), role="coverage")
    html = write_report(store, ["web01"], identity, config_.recipients,
                        base / "reports").read_text()  # fmt: skip
    section = html.split("coverage suggestions (nothing changed)")[1].split("<h")[0]
    assert "checker config set web_access_logs on" in section and "1 set aside" in section
    assert "security and privacy policy §7" in section and "As judged against" in section


# --- What the review of 3.4 found ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("current", "suggested"),
    [({"exec_records": "all"}, ("exec_records", "privileged")),
     ({"home_text": "all"}, ("home_text", "off")),
     ({"exec_records": "privileged"}, ("exec_records", "web"))],
)  # fmt: skip
def test_only_wider_settings_are_offered(current, suggested):
    (result,) = judge([setting(*suggested)], GAPS, set(), config(**current))
    assert not result.accepted and "collects no more" in result.reason


def test_a_setting_carries_the_tools_own_privacy_note():
    (result,) = judge([setting("exec_records", "all")], GAPS, set(), config())
    assert result.note.startswith("Program starts by every account, ordinary users' included.")
    assert "security and privacy policy §7" in result.note


def test_a_cited_gap_carries_its_text():
    (result,) = judge([setting("web_access_logs", "on", ["G-2"])], GAPS, set(), config())
    assert result.cited == ["G-2: web access logs not collected (not chosen at setup)"]


def test_the_catalogue_survives_being_shown():
    from checker.report import visible

    for name, item in CATALOGUE.items():
        assert "\\" not in item["how"], name
        assert str(visible(item["how"], 1000)) == item["how"], name
        assert "checker config set" not in item["how"], name


def test_repeats_are_caught_by_the_name_checked():
    junk = {**host("auditd-running"), "setting": "junk"}
    first, second = judge([host("auditd-running"), junk], GAPS, set(), config())
    assert first.accepted and "repeats" in second.reason


def test_under_strict_g_n_counts_the_kinds_the_advisor_saw(enabled):
    from checker.settings import change

    base = enabled[0]
    change(base, "advisor.redaction", "strict")
    seen = {}

    def reply(body):
        text = body["messages"][0]["content"][0]["text"]
        case = json.loads(text.removeprefix("The case file:\n"))
        seen["gaps"] = case["coverage_gaps"]
        cite = f"G-{len(case['coverage_gaps'])}" if case["coverage_gaps"] else "F-1"
        return coverage_reply([setting("web_access_logs", "on", [cite])])(body)

    advice = run(enabled, Provider(reply), role="coverage")
    (item,) = advice.judged
    assert item.accepted, item.reason
    if seen["gaps"]:
        assert item.cited == [f"G-{len(seen['gaps'])}: {seen['gaps'][-1]}"]
