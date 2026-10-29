"""The advisor's client and `checker advise` (Phase 3, PR 3.2), through the
real SDK with a mock transport: nothing here reaches a network."""

import json
import re

import anthropic
import httpx2
import pytest
from test_snapshot import add_bundle, host_records

from checker import cli
from checker.advisor import advise as advise_module
from checker.advisor.advise import advise, latest_advice
from checker.advisor.client import FALLBACK_BETA, AdvisorError, build_request
from checker.evidence import load_config, open_text
from checker.inventory import Inventory
from checker.settings import change

KEY = "sk-ant-api03-" + "k" * 40
TOKEN = re.compile(r"\b(?:USER|HOST)-\d+-[0-9a-f]{4}\b")


class Provider:
    """A fake Messages API: records each request; answers from `reply`."""

    def __init__(self, reply=None, status=200):
        self.requests = []
        self.reply = reply or (lambda request: answer_message(request))
        self.status = status

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content or b"{}")
        self.requests.append((request.url.path, dict(request.headers), body))
        if self.status != 200:
            return httpx2.Response(
                self.status, json={"type": "error", "error": {"type": "x", "message": "no"}}
            )
        if request.url.path.endswith("/count_tokens"):
            return httpx2.Response(200, json={"input_tokens": 12_000})
        return httpx2.Response(200, json=self.reply(body))

    def client(self):
        return anthropic.Anthropic(
            api_key=KEY,
            max_retries=0,
            http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(self.handler)),
        )

    def sent(self):
        return [body for path, _, body in self.requests if path.endswith("/messages")]


def case_text(body):
    return body["messages"][0]["content"][0]["text"]


def answer_message(body, verdict="strong signs of compromise", finding="F-1", model=None, **extra):
    names = TOKEN.findall(case_text(body))
    person = next((n for n in names if n.startswith("USER")), "someone")
    answer = {
        "summary": f"{person} has UID 0 and logged in.",
        "verdict": verdict,
        "most_important": [{"finding": finding, "why": f"{person} is root under another name"}],
        "innocent_explanations": [],
        "what_would_settle_it": [f"Did anyone create {person} on purpose?"],
    }
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": model or body["model"],
        "content": [*extra.pop("before", []), {"type": "text", "text": json.dumps(answer)}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 12_000, "output_tokens": 400, "cache_read_input_tokens": 0},
        **extra,
    }


@pytest.fixture
def enabled(home):
    base, store, identity, config = home
    change(base, "advisor.enabled", "on")
    add_bundle(home, "b1", 0, host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0))))
    return home


def run(home, provider, confirm=lambda q: True, **kwargs):
    base, store, identity, _ = home
    config = load_config(base)
    return advise(
        store, "web01", identity, config, Inventory(), (0.02, "default"), None,
        client=provider.client(), confirm=confirm, say=lambda line: None, **kwargs,
    )  # fmt: skip


# --- The request ----------------------------------------------------------------------------


def test_the_request_as_sent(enabled):
    provider = Provider()
    advice = run(enabled, provider)
    assert advice.status == "answered"
    ((path, headers, body),) = [r for r in provider.requests if r[0].endswith("/messages")]
    assert body["model"] == "claude-opus-5-5"
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "from_host" in body["system"][0]["text"]
    case_block, question = body["messages"][0]["content"]
    assert case_block["cache_control"] == {"type": "ephemeral"}
    assert question["text"].startswith("Explain this assessment")
    assert body["output_config"]["effort"] == "high"
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["fallbacks"] == "default"
    assert FALLBACK_BETA in headers.get("anthropic-beta", "")
    for field in ("temperature", "top_p", "top_k", "thinking"):
        assert field not in body
    assert "jch" not in json.dumps(body) and "toor" not in json.dumps(body)
    counted = [b for p, _, b in provider.requests if p.endswith("/count_tokens")]
    assert counted and counted[0]["messages"] == body["messages"]


def test_without_the_fallback_nothing_extra_is_asked(enabled):
    base = enabled[0]
    change(base, "advisor.fallback", "off")
    change(base, "advisor.inference_geo", "us")
    provider = Provider()
    run(enabled, provider)
    ((_, headers, body),) = [r for r in provider.requests if r[0].endswith("/messages")]
    assert "fallbacks" not in body and FALLBACK_BETA not in headers.get("anthropic-beta", "")
    assert body["inference_geo"] == "us"


# --- What came of it ----------------------------------------------------------------------------


def test_an_answer_is_restored_and_stored_with_what_was_sent(enabled):
    base, store, identity, _ = enabled
    provider = Provider()
    advice = run(enabled, provider)
    assert advice.answer["verdict"] == "strong signs of compromise"
    text = json.dumps(advice.answer)
    assert ("jch" in text or "toor" in text) and not TOKEN.search(text)
    (row,) = store.advice("b1")
    assert row["status"] == "answered" and row["model_answered"] == "claude-opus-5-5"
    assert row["redaction"] == "pseudonymize" and row["role"] == "explain"
    request = json.loads(open_text(row["request"], identity))
    assert request["messages"] == provider.sent()[0]["messages"]  # exactly what left
    assert "jch" not in json.dumps(request)
    assert row["estimated_cost"] == pytest.approx((12_000 * 4 + 400 * 20) / 1e6)
    record = latest_advice(store, "b1", identity)["explain"]
    assert record["answer"] == advice.answer


def test_an_answer_naming_a_finding_not_in_the_case_is_set_aside(enabled):
    store = enabled[1]
    provider = Provider(lambda body: answer_message(body, finding="F-999"))
    advice = run(enabled, provider)
    assert advice.status == "invalid" and advice.answer is None
    assert "F-999" in advice.note
    assert store.advice("b1")[0]["status"] == "invalid"


def test_a_verdict_contradicting_the_band_is_set_aside(enabled):
    provider = Provider(lambda body: answer_message(body, verdict="no signs found"))
    advice = run(enabled, provider)
    assert advice.status == "invalid" and "contradicts the band" in advice.note


def test_a_decline_answered_by_the_fallback_names_both(enabled):
    store = enabled[1]
    fallback = {
        "type": "fallback",
        "from": {"model": "claude-opus-5-5"},
        "to": {"model": "claude-opus-4-8"},
        "trigger": {"type": "refusal"},
    }
    provider = Provider(
        lambda body: answer_message(body, model="claude-opus-4-8", before=[fallback])
    )
    advice = run(enabled, provider)
    assert advice.status == "answered"
    assert advice.outcome.declined_by == ["claude-opus-5-5"]
    assert advice.outcome.model_answered == "claude-opus-4-8"
    row = store.advice("b1")[0]
    assert json.loads(row["declined_by"]) == ["claude-opus-5-5"]
    assert row["model_answered"] == "claude-opus-4-8"
    assert row["estimated_cost"] == pytest.approx((12_000 * 5 + 400 * 25) / 1e6)


def test_a_decline_with_no_answer(enabled):
    store = enabled[1]

    def declined(body):
        return {
            "id": "msg_2", "type": "message", "role": "assistant", "model": body["model"],
            "content": [], "stop_reason": "refusal", "stop_sequence": None,
            "stop_details": {"type": "refusal", "category": "cyber", "explanation": None},
            "usage": {"input_tokens": 12_000, "output_tokens": 0},
        }  # fmt: skip

    advice = run(enabled, Provider(declined))
    assert advice.status == "declined" and advice.answer is None
    assert advice.outcome.refusal_category == "cyber"
    assert "declined by the model's safety checks (cyber)" in advice.note
    row = store.advice("b1")[0]
    assert row["status"] == "declined" and row["model_answered"] is None


def test_an_answer_cut_off(enabled):
    provider = Provider(lambda body: dict(answer_message(body), stop_reason="max_tokens"))
    advice = run(enabled, provider)
    assert advice.status == "cut off" and advice.answer is None


def test_above_the_cost_limit_it_asks_and_sends_nothing_without_a_yes(enabled):
    base, store, _, _ = enabled
    change(base, "advisor.max_cost_per_run", "0.01")
    asked = []
    provider = Provider()
    advice = run(enabled, provider, confirm=lambda q: asked.append(q) or False)
    assert advice.status == "not sent" and asked and "Send it?" in asked[0]
    assert provider.sent() == [] and store.advice("b1") == []


def test_provider_errors_are_plain_and_never_show_the_key(enabled):
    provider = Provider(status=401)
    with pytest.raises(AdvisorError) as raised:
        run(enabled, provider)
    assert "API key was refused" in str(raised.value) and KEY not in str(raised.value)
    with pytest.raises(AdvisorError, match="rate limited"):
        run(enabled, Provider(status=429))


def test_strict_redaction_sends_no_excerpts(enabled):
    base = enabled[0]
    change(base, "advisor.redaction", "strict")
    provider = Provider()
    run(enabled, provider)
    case = json.loads(case_text(provider.sent()[0]).removeprefix("The case file:\n"))
    assert case["redaction"] == "strict" and "from_host" not in case


# --- Through the command, the report and purge -----------------------------------------------


def test_checker_advise_prints_the_advice(enabled, capsys, monkeypatch):
    provider = Provider()
    monkeypatch.setattr(advise_module, "make_client", lambda key: provider.client())
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    assert cli.main(["advise", "web01", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Asked claude-opus-5-5; answered by claude-opus-5-5." in out
    assert "Verdict: strong signs of compromise" in out and "score is the tool's own" in out
    assert cli.main(["advise", "web01", "--redaction", "none"]) == 1
    assert "only previews" in capsys.readouterr().err


def test_checker_advise_without_a_key(enabled, capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert cli.main(["advise", "web01", "--yes"]) == 1
    assert "no API key: ANTHROPIC_API_KEY is not set" in capsys.readouterr().err


def test_the_report_shows_the_advice_labelled(enabled):
    from checker.report import write_report

    base, store, identity, config = enabled
    fallback = {
        "type": "fallback",
        "from": {"model": "claude-opus-5-5"},
        "to": {"model": "claude-opus-4-8"},
    }
    run(
        enabled,
        Provider(lambda body: answer_message(body, model="claude-opus-4-8", before=[fallback])),
    )
    html = write_report(store, ["web01"], identity, config.recipients, base / "reports").read_text()
    assert "AI advisor (advice, not findings)" in html
    assert "declined by claude-opus-5-5; answered by claude-opus-4-8" in html
    assert "redaction pseudonymize" in html and "Verdict: strong signs of compromise." in html
    assert "F-1</span>" in html  # findings are numbered as the advice names them
    assert "stale" not in html.split("AI advisor (advice")[1].split("</div>")[0]


def test_purge_takes_the_advice_with_its_bundle(enabled):
    from checker.purge import execute, plan

    base, store, identity, _ = enabled
    run(enabled, Provider())
    assert store.advice("b1")
    execute(store, base, plan(store, base, {"web01"}, 90, host="web01"))
    assert store.advice("b1") == []


def test_show_prints_the_whole_request(enabled, capsys):
    assert cli.main(["advise", "web01", "--show"]) == 0
    request = json.loads(capsys.readouterr().out)
    assert request == build_request(
        json.loads(case_text(request).removeprefix("The case file:\n")),
        "explain",
        load_config(enabled[0]).advisor,
    )
