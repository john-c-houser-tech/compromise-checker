"""Remediation advice from the advisor (Phase 3, PR 3.5, role 4): checked
against the case and the band; nothing runs. No network."""

import json

import pytest
from test_advisor_client import Provider, run
from test_advisor_client import enabled as enabled  # noqa: PLC0414 - a fixture, re-exported

from checker import cli
from checker.advisor import advise as advise_module
from checker.advisor.roles import InvalidAnswer, RemediationAnswer, check_remediation


def step(action, findings=("F-1",), destructive=False):
    return {"action": action, "why": "because", "risk": "some", "findings": list(findings),
            "destructive": destructive}  # fmt: skip


def answer(**overrides):
    base = {
        "urgency": "now",
        "summary": "Treat the host as compromised.",
        "preserve": [step("Copy /var/log and the journal off the host")],
        "contain": [step("Take the host off the network at the switch")],
        "eradicate": [step("Reinstall from known-good media", destructive=True)],
        "recover": [step("Restore data from the last clean backup", destructive=True)],
        "tell": [{"role": "the security team", "what": "a likely compromise", "when": "now"}],
    }
    return RemediationAnswer.model_validate({**base, **overrides})


def check(value, band="Critical", ids=("F-1", "F-2"), quoted=frozenset()):
    check_remediation(value, set(ids), band, quoted)


def test_a_sound_plan_passes():
    check(answer())


@pytest.mark.parametrize(
    ("band", "urgency"),
    [("Low", "now"), ("Low", "soon"), ("Critical", "routine"), ("High", "none"),
     ("Elevated", "now")],
)  # fmt: skip
def test_urgency_must_agree_with_the_band(band, urgency):
    with pytest.raises(InvalidAnswer, match="contradicts the band"):
        check(answer(urgency=urgency), band=band)


def test_destroying_state_needs_evidence_kept_first():
    with pytest.raises(InvalidAnswer, match="no evidence preservation"):
        check(answer(preserve=[]))


def test_a_step_that_says_it_destroys_nothing_is_judged_by_what_it_does():
    reboot = step("Reboot the host to clear the implant", destructive=False)
    sneaky = answer(preserve=[], eradicate=[], recover=[], contain=[reboot])
    with pytest.raises(InvalidAnswer, match="no evidence preservation"):
        check(sneaky)


def test_preserving_evidence_mustnt_destroy_any():
    with pytest.raises(InvalidAnswer, match="preserves evidence with a step that destroys"):
        check(answer(preserve=[step("Kill the suspicious process, then copy its binary")]))


@pytest.mark.parametrize("role", ["jsmith@example.org", "USER-2-7f3a", "USER\u20112\u20117f3a"])
def test_tell_roles_not_people(role):
    with pytest.raises(InvalidAnswer, match="names a person"):
        check(answer(tell=[{"role": role, "what": "x", "when": "now"}]))


def test_findings_must_be_in_the_case():
    with pytest.raises(InvalidAnswer, match="F-9"):
        check(answer(contain=[step("Block it", ["F-9"])]))
    with pytest.raises(InvalidAnswer, match="F-7"):
        check(answer(summary="See F-7."))
    check(answer(summary="The file /tmp/.F-7 matters."), quoted={"F-7"})


def test_a_quiet_host_gets_a_short_routine_answer():
    quiet = answer(urgency="routine", preserve=[], eradicate=[], recover=[],
                   contain=[step("Remove the unlabelled key from authorized_keys after"
                                 " confirming nobody uses it")])  # fmt: skip
    with pytest.raises(InvalidAnswer, match="no evidence preservation"):
        check(quiet, band="Low")  # removing is destructive: keep a copy first
    keep = [step("Copy authorized_keys aside")]
    check(answer(urgency="routine", preserve=keep, eradicate=[], recover=[],
                 contain=quiet.contain and [s.model_dump() for s in quiet.contain]),
          band="Low")  # fmt: skip


# --- End to end, through the mock provider ----------------------------------------------------


def remediation_reply(plan):
    def reply(body):
        return {
            "id": "msg_r", "type": "message", "role": "assistant", "model": body["model"],
            "content": [{"type": "text", "text": json.dumps(plan)}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 9000, "output_tokens": 900},
        }  # fmt: skip

    return reply


def plan(band):
    urgency = "now" if band in ("High", "Critical") else "routine"
    return answer(
        urgency=urgency,
        contain=[step("systemctl stop apache2", destructive=False)],  # destructive by reading
    ).model_dump()


def band_of(enabled):
    from checker.assess import load_assessment

    store, identity = enabled[1], enabled[2]
    cli.main(["analyze", "web01"])
    return load_assessment(store, "b1", identity)["score"]["band"]


def test_the_plan_is_checked_marked_and_shown(enabled, capsys, monkeypatch):
    band = band_of(enabled)
    provider = Provider(remediation_reply(plan(band)))
    monkeypatch.setattr(advise_module, "make_client", lambda key: provider.client())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x" + "y" * 30)
    assert cli.main(["advise", "web01", "--role", "remediation", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Preserve evidence first:" in out and "nothing was run" in out
    assert "systemctl stop apache2 [destroys state]" in out  # the tool's reading


def test_a_plan_contradicting_the_band_is_set_aside(enabled):
    band = band_of(enabled)
    wrong = "routine" if band in ("High", "Critical") else "now"
    advice = run(enabled, Provider(remediation_reply(answer(urgency=wrong).model_dump())),
                 role="remediation")  # fmt: skip
    assert advice.status == "invalid" and "contradicts the band" in advice.note


def test_the_report_shows_the_plan(enabled):
    from checker.report import write_report

    base, store, identity, config = enabled
    band = band_of(enabled)
    run(enabled, Provider(remediation_reply(plan(band))), role="remediation")
    html = write_report(store, ["web01"], identity, config.recipients,
                        base / "reports").read_text()  # fmt: skip
    section = html.split("remediation (advice; nothing was run)")[1].split("<h2")[0]
    assert "Preserve evidence first" in section and "[destroys state]" in section
    assert "the security team" in section
