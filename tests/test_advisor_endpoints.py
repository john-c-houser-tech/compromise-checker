"""Local models, OpenAI-compatible servers and the fallback model (Phase 3,
PR 3.7; decision 3's `model`): what is sent where, what it costs, how a
cut-short request is caught, and what the report says. A mock transport
stands in for every server; nothing here reaches a network."""

import json
import re
import sqlite3

import httpx2
import pytest
from test_advisor_client import KEY, Provider, run
from test_advisor_client import enabled as enabled  # noqa: PLC0414 - a fixture, re-exported

from checker import cli
from checker.advisor import advise as advise_module
from checker.advisor.advise import Estimate, cost_line, merged, spent
from checker.advisor.client import (
    AdvisorError,
    Outcome,
    build_request,
    fallback_request,
    make_client,
    send,
)
from checker.advisor.keys import read_api_key
from checker.advisor.prices import tokens_in
from checker.advisor.roles import SYSTEM_PROMPT
from checker.evidence import Advisor, EvidenceError, Store, is_local, load_config, open_text
from checker.settings import change, describe

LOCAL = "http://localhost:11434/v1"
ELSEWHERE = "https://models.example.org/v1"


def explain_answer(verdict="strong signs of compromise"):
    return {
        "summary": "An account other than root has UID 0.",
        "verdict": verdict,
        "most_important": [{"finding": "F-1", "why": "root under another name"}],
        "innocent_explanations": [],
        "what_would_settle_it": ["Did anyone create it on purpose?"],
    }


class Server:
    """A fake OpenAI-compatible server: records each request; answers
    from `reply` (body -> (status, json))."""

    def __init__(self, reply=None, base_url=LOCAL):
        self.requests = []
        self.reply = reply or (lambda body: (200, chat(body, explain_answer())))
        self.base_url = base_url

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content or b"{}")
        self.requests.append((str(request.url), dict(request.headers), body))
        status, data = self.reply(body)
        return httpx2.Response(status, json=data)

    def client(self):
        return httpx2.Client(base_url=self.base_url, transport=httpx2.MockTransport(self.handler))


def chat(body, answer, finish="stop", read=None, **message):
    """A chat answer; `read` is the prompt tokens the server says it read
    (default: what a real tokenizer would make of the request)."""
    if read is None:
        read = int(tokens_in(json.dumps(body, ensure_ascii=False)) * 0.8)
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": body["model"],
        "choices": [
            {
                "index": 0,
                "finish_reason": finish,
                "message": {"role": "assistant", "content": json.dumps(answer), **message},
            }
        ],
        "usage": {"prompt_tokens": read, "completion_tokens": 300},
    }


def local(base, model="qwen2.5:7b", url=LOCAL):
    change(base, "advisor.fallback", "off")
    change(base, "advisor.base_url", url)
    change(base, "advisor.api", "openai")
    change(base, "advisor.api_key_source", "none")
    change(base, "advisor.model", model)


# --- What is sent, and where -----------------------------------------------------------------


def test_a_local_model_gets_the_same_case_in_its_own_form(enabled):
    base, store, identity, _ = enabled
    local(base)
    server = Server()
    advice = run(enabled, server)
    assert advice.status == "answered", advice.note
    ((url, headers, body),) = server.requests
    assert url == f"{LOCAL}/chat/completions"
    assert "authorization" not in headers  # no key for this server
    assert body["model"] == "qwen2.5:7b"
    system, user = body["messages"]
    assert system == {"role": "system", "content": SYSTEM_PROMPT}
    assert user["content"].startswith("The case file:\n")
    assert "Explain this assessment" in user["content"]
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    for anthropic_only in ("output_config", "fallbacks", "system", "inference_geo"):
        assert anthropic_only not in body
    assert "cache_control" not in json.dumps(body)
    assert "jch" not in json.dumps(body) and "toor" not in json.dumps(body)  # redaction holds
    row = store.advice("b1")[0]
    assert row["endpoint"] == LOCAL and row["estimated_cost"] == 0.0
    assert row["model_answered"] == "qwen2.5:7b"
    stored = json.loads(open_text(row["request"], identity))
    assert stored["endpoint"] == f"{LOCAL}/chat/completions" and stored["body"] == body


def test_show_prints_where_it_would_go(enabled, capsys):
    base = enabled[0]
    local(base)
    assert cli.main(["advise", "web01", "--show"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["endpoint"] == f"{LOCAL}/chat/completions"
    payload = json.loads(
        shown["body"]["messages"][1]["content"].removeprefix("The case file:\n").split("\n\n")[0]
    )
    assert shown == build_request(payload, "explain", load_config(base).advisor).shown()


def test_an_anthropic_compatible_server_is_named_too(enabled):
    base = enabled[0]
    change(base, "advisor.base_url", "https://gateway.example.org")
    request = build_request({"findings": []}, "explain", load_config(base).advisor)
    assert request.shown()["endpoint"] == "https://gateway.example.org/v1/messages"
    assert "endpoint" not in build_request({"findings": []}, "explain", Advisor()).shown()


def test_the_key_goes_as_a_bearer_token(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-" + "x" * 40)
    key = read_api_key("env", "openai")
    client = make_client(key, "openai", ELSEWHERE)
    assert client.headers["authorization"] == f"Bearer {key}"
    assert str(client.base_url).rstrip("/") == ELSEWHERE
    assert read_api_key("none", "openai") is None
    assert "authorization" not in make_client(None, "openai", LOCAL).headers


# --- What it costs -------------------------------------------------------------------------------


def test_a_model_on_this_machine_costs_nothing_and_asks_nothing(enabled):
    base = enabled[0]
    local(base)
    change(base, "advisor.max_cost_per_run", "0.01")
    asked = []
    advice = run(enabled, Server(), confirm=lambda q: asked.append(q) or False)
    assert advice.status == "answered" and not asked
    line, priced = cost_line(load_config(base).advisor, 5000)
    assert priced == Estimate(0.0, 0.0) and "on this machine" in line and "no charge" in line


def test_a_server_elsewhere_has_no_price_so_it_asks(enabled):
    base = enabled[0]
    local(base, model="some-hosted-model", url=ELSEWHERE)
    server = Server(base_url=ELSEWHERE)
    asked = []
    advice = run(enabled, server, confirm=lambda q: asked.append(q) or False)
    assert advice.status == "not sent" and "no price is known" in advice.note
    assert asked and f"at {ELSEWHERE}" in asked[0]
    assert server.requests == []  # nothing left


def test_the_fallback_models_cost_is_part_of_the_most():
    advisor = Advisor(
        fallback="model", fallback_model={"model": "claude-sonnet-5-5"}, model="claude-opus-5-5"
    )
    line, priced = cost_line(advisor, 10_000)
    alone, _ = cost_line(Advisor(fallback="off"), 10_000)
    assert "If declined, claude-sonnet-5-5 too: at most about $" in line
    assert priced.most > cost_line(Advisor(fallback="off"), 10_000)[1].most
    advisor = Advisor(
        fallback="model",
        fallback_model={
            "model": "qwen",
            "api": "openai",
            "base_url": LOCAL,
            "api_key_source": "none",
        },
    )
    assert "If declined, qwen on this machine: no charge." in cost_line(advisor, 10_000)[0]
    advisor.fallback_model.base_url = ELSEWHERE
    assert "at a cost not known here" in cost_line(advisor, 10_000)[0]


def test_spent_prices_each_model_and_nothing_on_this_machine():
    first = Outcome("declined", "claude-opus-5-5", declined_by=["claude-opus-5-5"],
                    usage={"input_tokens": 10_000, "output_tokens": 0})  # fmt: skip
    second = Outcome("answered", "qwen", "qwen", usage={"input_tokens": 9000,
                     "output_tokens": 500}, endpoint=LOCAL)  # fmt: skip
    both = merged(first, second)
    assert both.model_asked == "claude-opus-5-5" and both.declined_by == ["claude-opus-5-5"]
    assert both.usage == {"input_tokens": 19_000, "output_tokens": 500}
    assert spent(both) == pytest.approx(10_000 * 4.00 / 1e6)  # the local hop is free
    second = Outcome("answered", "hosted", "hosted", usage={"input_tokens": 1}, endpoint=ELSEWHERE)
    assert spent(merged(first, second)) is None  # a model without a price ran


# --- Read in part, cut off, declined, errors ---------------------------------------------------


def test_a_request_the_server_read_only_in_part_is_cut_off(enabled):
    base, store, _, _ = enabled
    local(base)
    advice = run(enabled, Server(lambda body: (200, chat(body, explain_answer(), read=900))))
    assert advice.status == "cut off" and advice.answer is None
    assert "read only 900 tokens" in advice.note and "num_ctx" in advice.note
    assert store.advice("b1")[0]["status"] == "cut off"


def test_a_request_read_whole_is_not_mistaken_for_one_cut_short(enabled):
    base = enabled[0]
    local(base)

    def english(body):  # four characters a token, as prose: still read whole
        read = len(json.dumps(body, ensure_ascii=False)) // 4
        return 200, chat(body, explain_answer(), read=read)

    assert run(enabled, Server(english)).status == "answered"


def test_an_answer_at_its_length_limit_is_cut_off(enabled):
    local(enabled[0])
    advice = run(enabled, Server(lambda body: (200, chat(body, explain_answer(), "length"))))
    assert advice.status == "cut off" and "length limit" in advice.note


@pytest.mark.parametrize(
    "declined",
    [
        lambda body: chat(body, explain_answer(), refusal="I can't help with that."),
        lambda body: chat(body, explain_answer(), "content_filter"),
    ],
)
def test_a_decline_is_a_decline(enabled, declined):
    local(enabled[0])
    advice = run(enabled, Server(lambda body: (200, declined(body))))
    assert advice.status == "declined" and advice.answer is None
    assert advice.outcome.declined_by == ["qwen2.5:7b"]


def test_an_answer_that_doesnt_fit_the_schema_is_unreadable(enabled):
    local(enabled[0])
    advice = run(enabled, Server(lambda body: (200, chat(body, {"colour": "blue"}))))
    assert advice.status == "unreadable"


@pytest.mark.parametrize(
    ("status", "data", "words"),
    [
        (404, {"error": "model 'qwen2.5:7b' not found"}, "doesn't know the model"),
        (401, {"error": {"message": "bad key"}}, "refused the API key"),
        (400, {"error": {"message": "context too long"}}, "(400): context too long"),
        (503, {}, "answered with an error (503)"),
        (200, ["not", "a", "chat"], "isn't a chat answer"),
        (200, {"choices": ["x"]}, "isn't a chat answer"),
    ],
)
def test_server_errors_in_words(enabled, status, data, words):
    base, store, _, _ = enabled
    local(base)
    with pytest.raises(AdvisorError, match=re.escape(words)) as raised:
        run(enabled, Server(lambda body: (status, data)))
    assert raised.value.sent
    assert store.advice("b1")[0]["status"] == "failed"  # it reached the server: recorded


def test_a_server_that_isnt_running_is_said_plainly(enabled):
    base, store, _, _ = enabled
    local(base)

    def refuse(request):
        raise httpx2.ConnectError("connection refused", request=request)

    class Down(Server):
        def client(self):
            return httpx2.Client(base_url=LOCAL, transport=httpx2.MockTransport(refuse))

    with pytest.raises(AdvisorError, match="could not reach http://localhost:11434/v1") as raised:
        run(enabled, Down())
    assert not raised.value.sent and store.advice("b1") == []


# --- The fallback model (decision 3, `model`) ---------------------------------------------------


def declined_by_claude(body):
    return {
        "id": "msg_2", "type": "message", "role": "assistant", "model": body["model"],
        "content": [], "stop_reason": "refusal", "stop_sequence": None,
        "stop_details": {"type": "refusal", "category": "cyber", "explanation": None},
        "usage": {"input_tokens": 12_000, "output_tokens": 0},
    }  # fmt: skip


def fallback_to_local(base):
    change(base, "advisor.fallback_model.api", "openai")
    change(base, "advisor.fallback_model.base_url", LOCAL)
    change(base, "advisor.fallback_model.api_key_source", "none")
    change(base, "advisor.fallback_model.model", "qwen2.5:7b")
    change(base, "advisor.fallback", "model")


def test_a_declined_request_goes_to_the_fallback_model(enabled, monkeypatch):
    base, store, identity, _ = enabled
    fallback_to_local(base)
    server = Server()
    monkeypatch.setattr(advise_module, "make_client", lambda key, api, url: server.client())
    provider = Provider(declined_by_claude)
    advice = run(enabled, provider)
    assert advice.status == "answered", advice.note
    assert advice.outcome.declined_by == ["claude-opus-5-5"]
    assert advice.outcome.model_answered == "qwen2.5:7b"
    assert "fallbacks" not in provider.sent()[0]  # Anthropic's own fallback isn't asked for
    ((_, _, body),) = server.requests
    first_case = provider.sent()[0]["messages"][0]["content"][0]["text"]
    assert body["messages"][1]["content"].startswith(first_case)  # same case, same placeholders
    row = store.advice("b1")[0]
    assert row["endpoint"] == LOCAL and json.loads(row["declined_by"]) == ["claude-opus-5-5"]
    assert row["estimated_cost"] == pytest.approx(12_000 * 4.00 / 1e6)
    stored = json.loads(open_text(row["request"], identity))
    assert stored["fallback"]["endpoint"] == f"{LOCAL}/chat/completions"


def test_the_fallback_model_declining_too(enabled, monkeypatch):
    fallback_to_local(enabled[0])
    server = Server(lambda body: (200, chat(body, explain_answer(), "content_filter")))
    monkeypatch.setattr(advise_module, "make_client", lambda key, api, url: server.client())
    advice = run(enabled, Provider(declined_by_claude))
    assert advice.status == "declined"
    assert advice.outcome.declined_by == ["claude-opus-5-5", "qwen2.5:7b"]
    assert "and by the fallback too" in advice.note


def test_a_fallback_model_that_cant_be_asked_leaves_the_decline(enabled, monkeypatch):
    base, store, identity, _ = enabled
    fallback_to_local(base)
    change(base, "advisor.fallback_model.api_key_source", "env")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    advice = run(enabled, Provider(declined_by_claude))
    assert advice.status == "declined"
    assert "the fallback model couldn't be asked: no API key: OPENAI_API_KEY is not set" in (
        advice.note
    )
    row = store.advice("b1")[0]
    assert "fallback" not in json.loads(open_text(row["request"], identity))  # nothing went


def test_the_fallback_request_on_the_anthropic_api():
    advisor = Advisor(fallback="model", fallback_model={"model": "claude-opus-4-8"})
    request = fallback_request({"findings": []}, "explain", advisor)
    assert request.api == "anthropic" and request.body["model"] == "claude-opus-4-8"
    assert "fallbacks" not in request.body


# --- Settings -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("steps", "words"),
    [
        ([("advisor.api", "openai")], "needs advisor.base_url"),
        ([("advisor.api_key_source", "none")], "only for a server at advisor.base_url"),
        ([("advisor.base_url", LOCAL), ("advisor.api", "openai")], "anthropic fallback is"),
        ([("advisor.fallback", "model")], "needs advisor.fallback_model.model"),
        ([("advisor.base_url", "ftp://x")], "http or https"),
        ([("advisor.base_url", "https://user:pw@x.example")], "no user name, password"),
        ([("advisor.base_url", "https://x.example/?key=1")], "no user name, password, query"),
        (
            [("advisor.fallback_model.api", "openai"), ("advisor.fallback_model.model", "m")],
            "needs its base_url",
        ),
        ([("advisor.inference_geo", "us"), ("advisor.fallback", "off"),
          ("advisor.base_url", LOCAL), ("advisor.api", "openai")], "inference_geo is Anthropic"),
    ],
)  # fmt: skip
def test_settings_that_dont_fit_together_are_refused(base_with_config, steps, words):
    *before, (key, value) = steps
    for k, v in before:
        change(base_with_config, k, v)
    with pytest.raises(EvidenceError, match=words):
        change(base_with_config, key, value)


@pytest.fixture
def base_with_config(home):
    return home[0]


def test_describe_says_who_receives_it(base_with_config):
    base = base_with_config
    change(base, "advisor.enabled", "on")
    local(base)
    lines = "\n".join(describe(load_config(base)))
    assert "to the model running on this machine, at http://localhost:11434/v1;" in lines
    assert "nothing leaves it" in lines and "effort" not in lines
    assert "API key from nowhere (the server takes no key)" in lines
    change(base, "advisor.base_url", "http://10.0.0.5:11434/v1")
    lines = "\n".join(describe(load_config(base)))
    assert "to the server at http://10.0.0.5:11434/v1 (OpenAI-compatible API, not encrypted" in (
        lines
    )
    fallback_to_local_from_openai(base)
    lines = "\n".join(describe(load_config(base)))
    assert "re-run on qwen-fallback, sent to the model running on this machine" in lines


def fallback_to_local_from_openai(base):
    change(base, "advisor.fallback_model.api", "openai")
    change(base, "advisor.fallback_model.base_url", LOCAL)
    change(base, "advisor.fallback_model.api_key_source", "none")
    change(base, "advisor.fallback_model.model", "qwen-fallback")
    change(base, "advisor.fallback", "model")


def test_the_default_wording_is_unchanged(base_with_config):
    base = base_with_config
    change(base, "advisor.enabled", "on")
    lines = describe(load_config(base))
    assert "  Sent only when you run `checker advise`: " in lines[4]
    assert lines[4].endswith(", to Anthropic with your own account.")
    assert lines[3].startswith("AI advisor: on, model claude-opus-5-5, effort high, API key from")


def test_check_key_with_no_key(base_with_config, capsys):
    base = base_with_config
    local(base)
    assert cli.main(["config", "check-key"]) == 0
    assert "No key is used (api_key_source none). Nothing was sent." in capsys.readouterr().out


def test_check_key_reads_the_fallback_models_key_too(base_with_config, capsys, monkeypatch):
    base = base_with_config
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    change(base, "advisor.fallback_model.api", "openai")
    change(base, "advisor.fallback_model.base_url", ELSEWHERE)
    change(base, "advisor.fallback_model.model", "hosted")
    change(base, "advisor.fallback", "model")
    assert cli.main(["config", "check-key"]) == 1
    captured = capsys.readouterr()
    assert "The fallback model's key: Reading the key from the OPENAI_API_KEY" in captured.out
    assert "OPENAI_API_KEY is not set" in captured.err


@pytest.mark.parametrize(
    ("url", "local_"),
    [
        ("http://localhost:11434/v1", True),
        ("http://ollama.localhost:8443/v1", True),
        ("http://127.0.0.1:8080", True),
        ("http://[::1]:8080", True),
        ("http://10.0.0.5:11434/v1", False),
        ("https://localhost.example.org/v1", False),
        (None, False),
    ],
)
def test_what_counts_as_this_machine(url, local_):
    assert is_local(url) is local_


# --- Storage and the report ---------------------------------------------------------------------


def test_an_older_advice_table_gains_the_endpoint_column(tmp_path):
    path = tmp_path / "evidence.db"
    store = Store(path)
    store.close()
    db = sqlite3.connect(path)
    db.execute("DROP TRIGGER advice_no_update")
    db.execute("DROP TRIGGER advice_no_delete")
    db.execute("ALTER TABLE advice DROP COLUMN endpoint")
    db.commit()
    db.close()
    store = Store(path)
    columns = {row[1] for row in store._db.execute("PRAGMA table_info(advice)")}
    assert "endpoint" in columns
    triggers = {row[0] for row in store._db.execute("SELECT name FROM sqlite_master"
                                                    " WHERE type = 'trigger'")}  # fmt: skip
    assert {"advice_no_update", "advice_no_delete"} <= triggers  # still append-only
    store.close()


def test_the_report_names_the_server_and_the_lower_quality(enabled):
    from checker.report import write_report

    base, store, identity, config = enabled
    local(base)
    run(enabled, Server())
    html = write_report(store, ["web01"], identity, config.recipients, base / "reports").read_text()
    assert "answered by qwen2.5:7b at http://localhost:11434/v1" in html
    assert "Answered by a model running on this machine: expect lower quality" in html


def test_the_report_is_unchanged_for_anthropic(enabled):
    from checker.report import write_report

    base, store, identity, config = enabled
    run(enabled, Provider())
    html = write_report(store, ["web01"], identity, config.recipients, base / "reports").read_text()
    assert "answered by claude-opus-5-5 ·" in html
    assert "running on this machine" not in html


def test_send_dispatches_by_api():
    request = build_request({"findings": []}, "explain", Advisor(fallback="off"))
    assert request.api == "anthropic"
    server = Server()
    openai = build_request(
        {"findings": []},
        "explain",
        Advisor(api="openai", base_url=LOCAL, fallback="off", api_key_source="none", model="m"),
    )
    outcome = send(server.client(), openai, "explain")
    assert outcome.status == "answered" and outcome.endpoint == LOCAL
