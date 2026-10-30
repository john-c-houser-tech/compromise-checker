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
    assert [p for p, _, _ in provider.requests] == ["/v1/messages"]  # nothing else left


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
    assert request["body"] == provider.sent()[0]  # exactly what left
    assert request["anthropic-beta"] == [FALLBACK_BETA]
    assert "jch" not in json.dumps(request)
    assert row["estimated_cost"] == pytest.approx((12_000 * 4 + 400 * 20) / 1e6)
    assessed = row["assessed_at"]
    record = latest_advice(store, "web01", identity, "b1", assessed)["explain"]["answered"]
    assert record["answer"] == advice.answer and record["stale"] is False


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
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
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
    from checker.report import read_report, write_report

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
    html = read_report(
        write_report(store, ["web01"], identity, config.recipients, base / "reports"), identity
    )
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
    shown = json.loads(capsys.readouterr().out)
    case = json.loads(case_text(shown["body"]).removeprefix("The case file:\n"))
    assert shown == build_request(case, "explain", load_config(enabled[0]).advisor).shown()
    assert shown["body"]["output_config"]["format"]["type"] == "json_schema"


# --- Responses with partial text, and what the review of 3.2 found -----------------------------


def message(body, content, stop_reason="end_turn", model=None, **extra):
    return {
        "id": "msg_9", "type": "message", "role": "assistant", "model": model or body["model"],
        "content": content, "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": 12_000, "output_tokens": 300}, **extra,
    }  # fmt: skip


def test_a_decline_after_partial_text(enabled):
    def declined(body):
        return message(
            body, [{"type": "text", "text": '{"summary": "The host'}], "refusal",
            stop_details={"type": "refusal", "category": "cyber"},
        )  # fmt: skip

    advice = run(enabled, Provider(declined))
    assert advice.status == "declined" and advice.outcome.refusal_category == "cyber"
    assert enabled[1].advice("b1")[0]["status"] == "declined"


def test_a_fallback_answer_after_the_declined_models_partial_text(enabled):
    def served(body):
        good = answer_message(body)["content"][-1]
        return message(
            body,
            [
                {"type": "text", "text": '{"summary": "The ho'},
                {"type": "fallback", "from": {"model": "claude-opus-5-5"},
                 "to": {"model": "claude-opus-4-8"}},
                good,
            ],
            model="claude-opus-4-8",
            usage={
                "input_tokens": 24_000, "output_tokens": 700,
                "iterations": [
                    {"type": "message", "model": "claude-opus-5-5",
                     "input_tokens": 12_000, "output_tokens": 300},
                    {"type": "fallback_message", "model": "claude-opus-4-8",
                     "input_tokens": 12_000, "output_tokens": 400},
                ],
            },
        )  # fmt: skip

    advice = run(enabled, Provider(served))
    assert advice.status == "answered", advice.note
    assert advice.outcome.declined_by == ["claude-opus-5-5"]
    assert advice.outcome.model_answered == "claude-opus-4-8"
    row = enabled[1].advice("b1")[0]
    each_at_its_own_rate = (12_000 * 4 + 300 * 20 + 12_000 * 5 + 400 * 25) / 1e6
    assert row["estimated_cost"] == pytest.approx(each_at_its_own_rate)


def test_a_fallback_shown_only_in_the_usage(enabled):
    def served(body):
        reply = answer_message(body, model="claude-opus-4-8")
        reply["usage"]["iterations"] = [
            {"type": "message", "model": "claude-opus-5-5", "input_tokens": 1, "output_tokens": 1},
            {"type": "fallback_message", "model": "claude-opus-4-8", "input_tokens": 1,
             "output_tokens": 1},
        ]  # fmt: skip
        return reply

    advice = run(enabled, Provider(served))
    assert advice.outcome.declined_by == ["claude-opus-5-5"]


@pytest.mark.parametrize(
    ("content", "stop", "status"),
    [
        ([{"type": "text", "text": '{"summary": "cut'}], "max_tokens", "cut off"),
        ([{"type": "text", "text": ""}], "end_turn", "unreadable"),
        ([], "end_turn", "unreadable"),
        ([{"type": "text", "text": '{"summary": 1}'}], "end_turn", "unreadable"),
    ],
)
def test_answers_that_cant_be_read_are_recorded(enabled, content, stop, status):
    advice = run(enabled, Provider(lambda body: message(body, content, stop)))
    assert advice.status == status and advice.answer is None
    assert enabled[1].advice("b1")[0]["status"] == status


def test_a_request_that_failed_is_recorded(enabled):
    store, identity = enabled[1], enabled[2]
    with pytest.raises(AdvisorError):
        run(enabled, Provider(status=500))
    (row,) = store.advice("b1")
    assert row["status"] == "failed"
    assert json.loads(open_text(row["request"], identity))["body"]["model"] == "claude-opus-5-5"
    assert "error (500)" in json.loads(open_text(row["answer"], identity))["note"]


def test_rate_limited_then_answered(enabled):
    base, store, identity, _ = enabled
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx2.Response(429, headers={"retry-after": "0"}, json={"type": "error"})
        return httpx2.Response(200, json=answer_message(json.loads(request.content)))

    client = anthropic.Anthropic(
        api_key=KEY,
        max_retries=1,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
    )
    config = load_config(base)
    advice = advise(
        store, "web01", identity, config, Inventory(), (0.02, "default"), None,
        client=client, confirm=lambda q: True, say=lambda line: None,
    )  # fmt: skip
    assert advice.status == "answered" and len(calls) == 2


def test_the_most_counts_a_fallback_and_a_no_sends_nothing_at_all(enabled):
    base = enabled[0]
    change(base, "advisor.max_cost_per_run", "0.01")
    said = []
    provider = Provider()
    base_, store, identity, _ = enabled
    advice = advise(
        store, "web01", identity, load_config(base), Inventory(), (0.02, "default"), None,
        client=provider.client(), confirm=lambda q: False, say=said.append,
    )  # fmt: skip
    assert advice.status == "not sent" and provider.requests == []
    assert "estimated here; nothing sent yet" in said[0]
    assert "and a re-run on a fallback model if declined" in said[0]
    assert "likely cost is above advisor.max_cost_per_run" in advice.note


def test_between_the_likely_cost_and_the_most_it_sends_without_asking(enabled, monkeypatch):
    from checker.advisor.prices import Estimate

    monkeypatch.setattr(advise_module, "estimate", lambda *a, **k: Estimate(0.30, 1.20))
    advice = run(enabled, Provider(), confirm=None)  # nobody to ask
    assert advice.status == "answered"
    monkeypatch.setattr(advise_module, "estimate", lambda *a, **k: Estimate(1.05, 1.20))
    assert run(enabled, Provider(), confirm=None).status == "not sent"


def test_a_model_without_a_price_says_so(enabled):
    base = enabled[0]
    change(base, "advisor.model", "claude-something-new")
    advice = run(enabled, Provider(), confirm=lambda q: False)
    assert advice.status == "not sent" and "no price is known" in advice.note


def test_a_finding_cited_in_free_text_must_be_in_the_case(enabled):
    def citing(body):
        reply = answer_message(body)
        answer = json.loads(reply["content"][-1]["text"])
        answer["summary"] += " See also F-999."
        reply["content"][-1]["text"] = json.dumps(answer)
        return reply

    advice = run(enabled, Provider(citing))
    assert advice.status == "invalid" and "F-999" in advice.note


def test_the_terminal_gets_the_models_words_escaped(enabled, capsys, monkeypatch):
    def ansi(body):
        reply = answer_message(body)
        answer = json.loads(reply["content"][-1]["text"])
        answer["summary"] = "fine\x1b[2Jcleared"
        reply["content"][-1]["text"] = json.dumps(answer)
        return reply

    provider = Provider(ansi)
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    assert cli.main(["advise", "web01", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "fine\\u001b[2Jcleared" in out


def test_the_report_keeps_the_last_good_answer_and_marks_old_ones_stale(enabled):
    from checker.report import read_report, write_report

    base, store, identity, config = enabled
    run(enabled, Provider())
    declined = Provider(
        lambda body: message(
            body, [], "refusal", stop_details={"type": "refusal", "category": "cyber"}
        )
    )
    run(enabled, declined)
    html = read_report(
        write_report(store, ["web01"], identity, config.recipients, base / "reports"), identity
    )
    section = html.split("AI advisor (advice")[1].split("</div>")[0]
    assert "Verdict: strong signs of compromise." in section
    assert "A later request" in section and "(cyber)" in section
    add_bundle(enabled, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0))))
    html = read_report(
        write_report(store, ["web01"], identity, config.recipients, base / "reports"), identity
    )
    assert "stale: it read another collection or assessment" in html


def test_the_estimate_errs_high_for_a_real_case():
    from checker.advisor.prices import estimate, tokens_in

    # The first real request (2026-10-29): 86 000 characters were 35 831
    # tokens, all written to the cache, and 2 618 out; it cost $0.23.
    tokens = tokens_in("x" * 86_000)
    assert tokens >= 35_831
    priced = estimate("claude-opus-5-5", tokens, 16_000)
    assert priced.likely >= 0.23  # what it cost
    assert priced.likely < 1.00  # sent at the default limit without asking


def test_the_limit_is_checked_against_the_likely_cost():
    from checker.advisor.prices import estimate, tokens_in

    real = estimate("claude-opus-5-5", tokens_in("x" * 86_000), 16_000, fallback=True)
    assert real.likely == pytest.approx(43_001 * 5 / 1e6 + 4_000 * 20 / 1e6)
    assert real.most > 1.00 > real.likely  # the worst case shown, not the check
    huge = estimate("claude-opus-5-5", tokens_in("x" * 400_000), 16_000, fallback=True)
    assert huge.likely > 1.00  # a huge case still asks


# --- What the second review of 3.2 found ---------------------------------------------------------


def test_an_interrupted_request_is_recorded(enabled):
    def handler(request):
        if request.url.path.endswith("/messages"):
            raise KeyboardInterrupt
        return httpx2.Response(404)

    client = anthropic.Anthropic(
        api_key=KEY, max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
    )  # fmt: skip
    base, store, identity, _ = enabled
    with pytest.raises(KeyboardInterrupt):
        advise(
            store, "web01", identity, load_config(base), Inventory(), (0.02, "default"), None,
            client=client, confirm=lambda q: True, say=lambda line: None,
        )  # fmt: skip
    assert store.advice("b1")[0]["status"] == "interrupted"


def test_an_error_before_sending_records_nothing(enabled):
    class Broken:
        class beta:  # noqa: N801
            class messages:  # noqa: N801
                @staticmethod
                def create(**kwargs):
                    raise ValueError("max_tokens too large for a non-streaming request")

    base, store, identity, _ = enabled
    with pytest.raises(AdvisorError, match="couldn't be made .ValueError: max_tokens"):
        advise(
            store, "web01", identity, load_config(base), Inventory(), (0.02, "default"), None,
            client=Broken(), confirm=lambda q: True, say=lambda line: None,
        )  # fmt: skip
    assert store.advice("b1") == []


def test_a_provider_error_keeps_its_request_id(enabled):
    store = enabled[1]

    def handler(request):
        return httpx2.Response(500, headers={"request-id": "req_abc"}, json={"type": "error"})

    client = anthropic.Anthropic(
        api_key=KEY, max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
    )  # fmt: skip
    base, _, identity, _ = enabled
    with pytest.raises(AdvisorError):
        advise(
            store, "web01", identity, load_config(base), Inventory(), (0.02, "default"), None,
            client=client, confirm=lambda q: True, say=lambda line: None,
        )  # fmt: skip
    assert store.advice("b1")[0]["request_id"] == "req_abc"


def test_both_models_declining(enabled):
    def declined(body):
        return message(
            body,
            [{"type": "fallback", "from": {"model": "claude-opus-5-5"},
              "to": {"model": "claude-opus-4-8"}}],
            "refusal",
            stop_details={"type": "refusal", "category": "cyber"},
            usage={"input_tokens": 2, "output_tokens": 0, "iterations": [
                {"type": "message", "input_tokens": 1, "output_tokens": 0},
                {"type": "fallback_message", "input_tokens": 1, "output_tokens": 0},
            ]},
        )  # fmt: skip

    advice = run(enabled, Provider(declined))
    assert advice.outcome.declined_by == ["claude-opus-5-5", "claude-opus-4-8"]
    assert "and by the fallback too" in advice.note
    hops = advice.outcome.iterations
    assert [h["model"] for h in hops] == ["claude-opus-5-5", "claude-opus-4-8"]


def test_a_window_too_small_is_cut_off(enabled):
    advice = run(enabled, Provider(lambda b: message(b, [], "model_context_window_exceeded")))
    assert advice.status == "cut off"


def test_finding_numbers_the_host_wrote_may_be_quoted(enabled):
    from checker.advisor.roles import Explanation, InvalidAnswer, check_explanation

    answer = Explanation(
        summary="A file /tmp/.F-31337 appeared.", verdict="strong signs of compromise",
        most_important=[{"finding": "F-1", "why": "see backup-F-2024.tar"}],
        innocent_explanations=[], what_would_settle_it=[],
    )  # fmt: skip
    check_explanation(answer, {"F-1"}, "Critical", {"F-31337", "F-2024"})
    with pytest.raises(InvalidAnswer, match="F-31337"):
        check_explanation(answer, {"F-1"}, "Critical")


def test_advisor_requests_are_never_retried_automatically():
    from checker.advisor.client import make_client

    assert make_client(KEY).max_retries == 0


# --- Text in the case that addresses an AI ---------------------------------------------------


def test_an_answer_to_a_case_whose_text_addresses_an_ai_carries_a_warning(
    enabled, capsys, monkeypatch
):
    """The answer is still shown, in the terminal and the report, with a
    warning naming where the text was; here the uid-0 finding's own words
    are set as what counts as addressing an AI."""
    import checker.advisor.proposals as proposals
    from checker.report import read_report, write_report

    base, store, identity, config = enabled
    monkeypatch.setattr(proposals, "ADDRESSED", re.compile(r"root under another name"))
    advice = run(enabled, Provider())
    assert advice.status == "answered" and advice.answer["verdict"]
    assert advice.warning.startswith("text in the case (F-") and "addresses an AI" in advice.warning
    (row,) = store.advice("b1")
    record = latest_advice(store, "web01", identity, "b1", row["assessed_at"])["explain"]
    assert record["answered"]["warning"] == advice.warning
    html = read_report(
        write_report(store, ["web01"], identity, config.recipients, base / "reports"), identity
    )
    assert "<strong>Warning: text in the case (F-" in html
    cli._print_advice(advice, "explain")
    assert "Warning: text in the case (F-" in capsys.readouterr().out


def test_an_ordinary_case_carries_no_warning(enabled, capsys):
    base, store, identity, config = enabled
    advice = run(enabled, Provider())
    assert advice.warning == ""
    cli._print_advice(advice, "explain")
    assert "Warning" not in capsys.readouterr().out
    from checker.report import read_report, write_report

    html = read_report(
        write_report(store, ["web01"], identity, config.recipients, base / "reports"), identity
    )
    assert "Warning:" not in html


def test_a_steering_check_that_fails_keeps_the_answer_with_a_warning(enabled, monkeypatch):
    import checker.advisor.proposals as proposals

    def broken(payload):
        raise ValueError("odd")

    monkeypatch.setattr(proposals, "steering", broken)
    advice = run(enabled, Provider())
    assert advice.status == "answered" and advice.answer["verdict"]
    assert advice.warning.startswith("the case's text couldn't be checked")


def test_the_warning_names_the_place_with_its_real_name(monkeypatch):
    import checker.advisor.proposals as proposals

    class Names:
        def restore(self, text):
            return text.replace("HOST-1-7f3a", "web01")

    monkeypatch.setattr(proposals, "steering", lambda payload: "whitelist rule HOST-1-7f3a-db")
    where, warning = advise_module._steered({}, Names())
    assert where == "whitelist rule web01-db"
    # A rule's reason is usually the organization's own: not put down to an intruder.
    assert warning.startswith("the reason or match of whitelist rule web01-db reads like words")
    assert "intruder steering" not in warning


def test_an_answer_set_aside_carries_no_warning(enabled, monkeypatch):
    import checker.advisor.proposals as proposals

    monkeypatch.setattr(proposals, "ADDRESSED", re.compile(r"root under another name"))
    advice = run(enabled, Provider(lambda body: answer_message(body, finding="F-999")))
    assert advice.status == "invalid" and advice.warning == ""
