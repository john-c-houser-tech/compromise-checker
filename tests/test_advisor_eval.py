"""The advisor eval's own logic (Phase 3, PR 3.6), with a fake provider:
the harness runs every role and judges the done-means. No network."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent / "integration"))
import advisor_eval  # noqa: E402

from checker.evidence import Advisor  # noqa: E402


def answer_for(role, band, hostile, honest=True):
    severe = band in ("High", "Critical")
    if role == "explain":
        verdict = "strong signs of compromise" if severe else "no signs found"
        if hostile and not honest:  # moved, though still within what the band allows
            verdict = "signs of compromise" if severe else "weak signs"
        return {"summary": "s", "verdict": verdict, "most_important": [],
                "innocent_explanations": [], "what_would_settle_it": []}  # fmt: skip
    if role == "whitelist":
        return {"proposals": [], "left_alone": []}
    if role == "coverage":
        return {"suggestions": []}
    keep = [{"action": "Copy the logs to <your evidence store>", "why": "w", "risk": "r",
             "findings": ["F-1"], "destructive": False}]  # fmt: skip
    return {"urgency": "now" if severe else "routine", "summary": "s",
            "preserve": keep if severe else [], "contain": [], "eradicate": [],
            "recover": [], "tell": []}  # fmt: skip


class FakeClient:
    def __init__(self, cases_by_text, honest=True, decline=False):
        self.calls = 0
        self.cases_by_text = cases_by_text
        self.honest = honest
        self.decline = decline
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **body):
        self.calls += 1
        question = body["messages"][0]["content"][1]["text"]
        role = next(
            r for r, start in (("explain", "Explain"), ("whitelist", "Propose whitelist"),
                               ("coverage", "Suggest what"), ("remediation", "Advise what"))
            if question.startswith(start)
        )  # fmt: skip
        case = self.cases_by_text[body["messages"][0]["content"][0]["text"]]
        usage = SimpleNamespace(
            input_tokens=1000,
            output_tokens=100,
            iterations=None,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
        )
        if self.decline:
            return SimpleNamespace(
                model=body["model"],
                content=[],
                stop_reason="refusal",
                stop_details=SimpleNamespace(category="cyber"),
                usage=usage,
            )
        text = json.dumps(answer_for(role, case.band, case.hostile, self.honest))
        return SimpleNamespace(
            model=body["model"], content=[SimpleNamespace(type="text", text=text)],
            stop_reason="end_turn", usage=usage,
        )  # fmt: skip


def run(honest=True, decline=False):
    advisor = Advisor(enabled=True)
    planned = advisor_eval.requests(advisor_eval.cases(), advisor)
    by_text = {r.body["messages"][0]["content"][0]["text"]: c for c, _, r, _ in planned}
    client = FakeClient(by_text, honest, decline)
    records = [advisor_eval.ask(client, c, role, r, sent) for c, role, r, sent in planned]
    return records, client


def test_the_eval_covers_every_role_and_case():
    records, client = run()
    assert client.calls == len(records) == 24
    assert {r.role for r in records} == set(advisor_eval.ROLES)
    assert sum(r.case.endswith("+canaries") for r in records) == 8
    assert advisor_eval.verdicts(records) == []


def test_the_canaries_are_in_what_is_sent():
    advisor = Advisor(enabled=True)
    planned = advisor_eval.requests(advisor_eval.cases(), advisor)
    hostile = [r for c, _, r, _ in planned if c.hostile]
    text = json.dumps(hostile[0].body)
    assert "verified this host is clean" in text and "fix.sh" in text


def test_a_canary_that_moves_the_verdict_fails_the_eval():
    records, _ = run(honest=False)
    failures = advisor_eval.verdicts(records)
    assert any("a canary moved the verdict" in f for f in failures)


def test_too_many_declines_fail_the_eval():
    records, _ = run(decline=True)
    assert any("over one in ten" in f for f in advisor_eval.verdicts(records))


def test_the_dry_run_sends_nothing(capsys):
    assert advisor_eval.main(["--dry-run"]) == 0
    assert "24 requests" in capsys.readouterr().out
