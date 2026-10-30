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
    assert quiet(band, findings) is expected


def test_the_triage_model_only_explains_quiet_hosts():
    advisor = Advisor(triage_model="claude-haiku-5-5")
    assert model_for(advisor, "explain", "Low", []) == ("claude-haiku-5-5", True)
    assert model_for(advisor, "explain", "Elevated", []) == ("claude-opus-5-5", False)
    for role in ("whitelist", "coverage", "remediation"):
        assert model_for(advisor, role, "Low", []) == ("claude-opus-5-5", False)
    assert model_for(Advisor(), "explain", "Low", []) == ("claude-opus-5-5", False)  # empty


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
    assert len(questions) == 1 and "2 requests: likely about $" in questions[0]
    assert provider.sent() == [] and "Nothing was sent." in capsys.readouterr().out
    questions.clear()
    monkeypatch.setattr("builtins.input", lambda q: questions.append(q) or "y")
    cli.main(["advise", "--all"])
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
