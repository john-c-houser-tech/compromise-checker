"""The triage model and `checker advise --all` (Phase 3, PR 3.7b;
DESIGN.md §12.4, decision 5): quiet hosts' explanations may go to a
faster, cheaper model the organization chose; everything else to the main
model; one question for the whole run. Nothing here reaches a network."""

import json

import pytest
from test_advisor_client import KEY, Provider, answer_message
from test_snapshot import add_bundle, host_records

from checker import cli
from checker.advisor import advise as advise_module
from checker.advisor.advise import model_for, quiet
from checker.evidence import Advisor, load_config
from checker.settings import change, describe


def finding(band, suppressed=False):
    return {"band": band, **({"suppressed_by": "rule-1"} if suppressed else {})}


@pytest.mark.parametrize(
    ("band", "findings", "expected"),
    [
        ("Low", [], True),
        ("Low", [finding("low"), finding("info")], True),
        ("Low", [finding("medium")], False),
        ("Low", [finding("medium", suppressed=True)], True),  # whitelisted: not in effect
        ("Low", [finding("critical", suppressed=True), finding("high")], False),
        ("Elevated", [], False),
        ("Critical", [], False),
        (None, [], False),
    ],
)
def test_what_counts_as_a_quiet_host(band, findings, expected):
    assert quiet(band, {"findings": findings, "score": {"chains": []}}) is expected


@pytest.mark.parametrize("odd", ["Medium", "", None, "severe"])
def test_an_unexpected_finding_band_isnt_quiet(odd):
    assert not quiet("Low", {"findings": [finding(odd)]})


def test_a_chain_isnt_quiet():
    chained = {"findings": [finding("low")], "score": {"chains": [{"name": "x"}]}}
    assert not quiet("Low", chained)


def test_the_triage_model_only_explains_quiet_hosts():
    advisor = Advisor(triage_model="claude-haiku-5-5")
    calm = {"findings": []}
    assert model_for(advisor, "explain", "Low", calm) == ("claude-haiku-5-5", True)
    assert model_for(advisor, "explain", "Elevated", calm) == ("claude-opus-5-5", False)
    for role in ("whitelist", "coverage", "remediation"):
        assert model_for(advisor, role, "Low", calm) == ("claude-opus-5-5", False)
    assert model_for(Advisor(), "explain", "Low", calm) == ("claude-opus-5-5", False)  # empty


def test_haiku_is_asked_without_a_server_side_fallback():
    from checker.advisor.advise import cost_line
    from checker.advisor.client import FALLBACK_BETA, build_request

    request = build_request({"findings": []}, "explain", Advisor(model="claude-haiku-5-5"))
    assert "fallbacks" not in request.body and FALLBACK_BETA not in request.betas
    line, _ = cost_line(Advisor(model="claude-haiku-5-5"), 10_000)
    assert "re-run on a fallback model" not in line
    lines = describe_for(Advisor(enabled=True, model="claude-haiku-5-5"))
    assert "nothing more is sent: claude-haiku-5-5 has no server-side fallback." in lines


def describe_for(advisor):
    from checker.evidence import Config

    return "\n".join(describe(Config(recipients=["age1x"], advisor=advisor)))


@pytest.mark.parametrize(
    ("settings", "words"),
    [
        ({"triage_model": "claude-haiku-5-5"}, "the triage model, claude-haiku-5-5."),
        ({"triage_model": "qwen3:8b"}, "no price is known for it"),
        ({"triage_model": "claude-haiku-5-5", "api": "openai", "base_url": "http://localhost:1/v1",
          "fallback": "off", "api_key_source": "none"}, "a Claude name, sent to"),
    ],
)  # fmt: skip
def test_the_triage_model_is_named_with_any_doubt(settings, words):
    assert words in describe_for(Advisor(enabled=True, **settings))


def test_it_ships_empty_and_says_so_when_set(home):
    base = home[0]
    assert load_config(base).advisor.triage_model is None  # decision 5
    change(base, "advisor.enabled", "on")
    assert not any("quiet hosts" in line for line in describe(load_config(base)))
    change(base, "advisor.triage_model", "claude-haiku-5-5")
    assert any("Explaining quiet hosts" in line and "claude-haiku-5-5" in line
               for line in describe(load_config(base)))  # fmt: skip
    change(base, "advisor.triage_model", "none")
    assert load_config(base).advisor.triage_model is None


# --- checker advise --all ----------------------------------------------------------------------


@pytest.fixture
def two_hosts(home, monkeypatch):
    """web01 with a second UID 0 account (not quiet); web02 ordinary."""
    base = home[0]
    change(base, "advisor.enabled", "on")
    add_bundle(home, "b1", 0, host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0))))
    add_bundle(home, "b2", 0, host_records(), host="web02")
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    return home


def verdict_for(body):
    """An answer that agrees with the case: its band's verdict, and the
    first finding as the most important, when there is one."""
    case = json.loads(body["messages"][0]["content"][0]["text"].removeprefix("The case file:\n"))
    ids = [f["id"] for f in case.get("findings") or []]
    message = answer_message(
        body, verdict="strong signs of compromise" if ids else "no signs found"
    )
    answer = json.loads(message["content"][-1]["text"])
    answer["most_important"] = answer["most_important"] if ids else []
    message["content"][-1]["text"] = json.dumps(answer)
    return message


def run_all(monkeypatch, provider, *extra):
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    return cli.main(["advise", "--all", "--yes", *extra])


def test_all_hosts_with_the_triage_model_for_the_quiet_one(two_hosts, monkeypatch, capsys):
    base, store, _, _ = two_hosts
    change(base, "advisor.triage_model", "claude-haiku-5-5")
    provider = Provider(verdict_for)
    assert run_all(monkeypatch, provider) == 0
    out = capsys.readouterr().out
    assert sorted(b["model"] for b in provider.sent()) == ["claude-haiku-5-5", "claude-opus-5-5"]
    assert store.advice("b1")[0]["model_asked"] == "claude-opus-5-5"  # High: the main model
    assert store.advice("b2")[0]["model_asked"] == "claude-haiku-5-5"  # Low, nothing found
    assert "web02: About" in out and "(the triage model: a quiet host)" in out
    assert "web01: About" in out and out.count("(the triage model") == 1
    assert "== web01 ==" in out and "== web02 ==" in out
    assert "2 requests: likely about $" in out


def test_without_a_triage_model_every_host_gets_the_main_model(two_hosts, monkeypatch):
    provider = Provider(verdict_for)
    run_all(monkeypatch, provider)
    assert [b["model"] for b in provider.sent()] == ["claude-opus-5-5"] * 2


def test_other_roles_never_use_the_triage_model(two_hosts, monkeypatch, capsys):
    base = two_hosts[0]
    change(base, "advisor.triage_model", "claude-haiku-5-5")
    provider = Provider()
    run_all(monkeypatch, provider, "--role", "coverage")
    assert {body["model"] for body in provider.sent()} == {"claude-opus-5-5"}


def test_one_question_for_the_whole_run(two_hosts, monkeypatch, capsys):
    base = two_hosts[0]
    change(base, "advisor.max_cost_per_run", "0.01")
    provider = Provider(verdict_for)
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    questions = []
    monkeypatch.setattr("builtins.input", lambda q: questions.append(q) or "n")
    assert cli.main(["advise", "--all"]) == 1
    assert len(questions) == 1 and "2 requests: likely about $" in capsys.readouterr().out
    assert provider.sent() == []
    questions.clear()
    monkeypatch.setattr("builtins.input", lambda q: questions.append(q) or "y")
    assert cli.main(["advise", "--all"]) == 0
    assert len(questions) == 1 and len(provider.sent()) == 2  # asked once, not per host


def test_without_a_terminal_it_needs_yes(two_hosts, monkeypatch, capsys):
    change(two_hosts[0], "advisor.max_cost_per_run", "0.01")
    provider = Provider()
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["advise", "--all"]) == 1
    assert "confirm with --yes" in capsys.readouterr().err and provider.sent() == []


def test_a_host_that_cant_be_asked_is_skipped(two_hosts, monkeypatch, capsys):
    from checker.advisor import advise as module

    real = module.case_for_host

    def broken(store, host, *args, **kwargs):
        if host == "web02":
            from checker.evidence import EvidenceError

            raise EvidenceError("its bundle can't be read")
        return real(store, host, *args, **kwargs)

    monkeypatch.setattr(module, "case_for_host", broken)
    provider = Provider(verdict_for)
    assert run_all(monkeypatch, provider) == 1
    err = capsys.readouterr().err
    assert "web02: its bundle can't be read; skipped" in err
    assert len(provider.sent()) == 1


@pytest.mark.parametrize(
    "argv",
    [["advise"], ["advise", "web01", "--all"], ["advise", "--all", "--show"],
     ["advise", "--all", "--bundle", "b1"], ["advise", "--all", "--redaction", "strict"]],
)  # fmt: skip
def test_all_and_one_host_dont_mix(two_hosts, argv, capsys):
    assert cli.main(argv) == 2


def test_all_with_the_advisor_off(home, capsys):
    add_bundle(home, "b1", 0, host_records())
    assert cli.main(["advise", "--all"]) == 1
    assert "the advisor is off" in capsys.readouterr().err


def test_the_limit_is_for_the_whole_run_not_each_host(two_hosts, monkeypatch, capsys):
    change(two_hosts[0], "advisor.max_cost_per_run", "0.15")  # each about $0.10, both $0.20
    provider = Provider(verdict_for)
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    questions = []
    monkeypatch.setattr("builtins.input", lambda q: questions.append(q) or "n")
    assert cli.main(["advise", "--all"]) == 1
    assert len(questions) == 1 and provider.sent() == []


# --- What the review of 3.7b found ------------------------------------------------------------


def test_a_collection_between_estimate_and_send_isnt_sent(two_hosts, monkeypatch, capsys):
    """A newer bundle (web02 now has a second UID 0 account) arrives after
    the estimate: the bundle estimated is the one sent."""
    home = two_hosts
    change(home[0], "advisor.triage_model", "claude-haiku-5-5")
    provider = Provider(verdict_for)
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    from checker.advisor import advise as module

    real_plan = module.plan

    def plan_then_collect(store, host, *args):
        planned = real_plan(store, host, *args)
        if host == "web02":
            add_bundle(home, "b3", 5,
                       host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0))),
                       host="web02")  # fmt: skip
        return planned

    monkeypatch.setattr(module, "plan", plan_then_collect)
    assert cli.main(["advise", "--all", "--yes"]) == 0
    store = home[1]
    assert store.advice("b3") == []  # the newer bundle wasn't sent
    assert store.advice("b2")[0]["model_asked"] == "claude-haiku-5-5"


def test_a_changed_analysis_or_a_larger_estimate_isnt_sent(two_hosts, monkeypatch):
    from dataclasses import replace

    from checker.advisor.advise import Estimate, advise, plan
    from checker.inventory import Inventory

    base, store, identity, _ = two_hosts
    change(base, "advisor.triage_model", "claude-haiku-5-5")
    config = load_config(base)
    provider = Provider(verdict_for)
    args = (store, "web02", identity, config, Inventory(), (0.02, "default"), None)
    planned = plan(*args, "explain")
    wrong_model = replace(planned, model="claude-opus-5-5")  # as if web02 had been loud
    advice = advise(*args, client=provider.client(), planned=wrong_model, say=lambda line: None)
    assert advice.status == "not sent" and "analysis changed" in advice.note
    smaller = replace(planned, priced=Estimate(planned.priced.likely / 10, planned.priced.most))
    advice = advise(*args, client=provider.client(), planned=smaller, say=lambda line: None)
    assert advice.status == "not sent" and "estimate grew" in advice.note
    assert provider.sent() == []
    advice = advise(*args, client=provider.client(), planned=planned, say=lambda line: None)
    assert advice.status == "answered"


@pytest.mark.parametrize("stop", [KeyboardInterrupt, EOFError])
def test_stopping_at_the_question_sends_nothing(two_hosts, monkeypatch, capsys, stop):
    change(two_hosts[0], "advisor.max_cost_per_run", "0.01")
    provider = Provider()
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def interrupted(question):
        raise stop

    monkeypatch.setattr("builtins.input", interrupted)
    assert cli.main(["advise", "--all"]) == 130
    captured = capsys.readouterr()
    assert "Nothing was sent." in captured.out and "had been sent" not in captured.err
    assert provider.sent() == []


@pytest.mark.parametrize("stop", [KeyboardInterrupt, EOFError])
def test_stopping_at_one_hosts_question_sends_nothing(two_hosts, monkeypatch, capsys, stop):
    change(two_hosts[0], "advisor.max_cost_per_run", "0.01")
    provider = Provider()
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def interrupted(question):
        raise stop

    monkeypatch.setattr("builtins.input", interrupted)
    assert cli.main(["advise", "web01"]) == 1
    assert "had been sent" not in capsys.readouterr().err and provider.sent() == []


def test_an_interrupt_partway_says_where(two_hosts, monkeypatch, capsys):
    calls = []

    def reply(body):
        calls.append(body)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return verdict_for(body)

    provider = Provider(reply)
    assert run_all(monkeypatch, provider) == 130
    err = capsys.readouterr().err
    assert "interrupted at web02: 1 host(s) asked before it;" in err
    assert "its request may have been sent, and is recorded; 0 not sent" in err
    assert two_hosts[1].advice("b2")[0]["status"] == "interrupted"


def test_the_key_is_read_once_after_the_yes(two_hosts, monkeypatch):
    reads = []
    provider = Provider(verdict_for)

    def counted(key, *where):
        reads.append(key)
        return provider.client()

    monkeypatch.setattr(advise_module, "make_client", counted)
    assert cli.main(["advise", "--all", "--yes"]) == 0
    assert len(reads) == 1 and len(provider.sent()) == 2


def test_a_send_failure_on_one_host_doesnt_stop_the_others(two_hosts, monkeypatch, capsys):
    real = advise_module.CHECKS["explain"]
    calls = []

    def check(*args):
        calls.append(args)
        if len(calls) == 1:
            raise ValueError("something unexpected")
        return real(*args)

    monkeypatch.setitem(advise_module.CHECKS, "explain", check)
    provider = Provider(verdict_for)
    assert run_all(monkeypatch, provider) == 1
    assert "web01: something unexpected" in capsys.readouterr().err
    assert len(provider.sent()) == 2
    assert two_hosts[1].advice("b2")[0]["status"] == "answered"


def test_yes_sends_a_run_over_the_limit_without_asking(two_hosts, monkeypatch):
    change(two_hosts[0], "advisor.max_cost_per_run", "0.01")
    monkeypatch.setattr("builtins.input", lambda q: pytest.fail("asked"))
    provider = Provider(verdict_for)
    assert run_all(monkeypatch, provider) == 0 and len(provider.sent()) == 2


def test_an_unpriced_triage_model_makes_the_run_ask(two_hosts, monkeypatch, capsys):
    change(two_hosts[0], "advisor.triage_model", "claude-unknown-9")
    provider = Provider(verdict_for)
    monkeypatch.setattr(advise_module, "make_client", lambda key, *where: provider.client())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda q: "n")
    assert cli.main(["advise", "--all"]) == 1
    assert "some at a cost not known here" in capsys.readouterr().out and provider.sent() == []
