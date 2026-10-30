"""`checker config` and the advisor settings (Phase 3, PR 3.0)."""

import json
import sqlite3
import sys
import types

import pytest
import yaml

from checker.advisor.keys import (
    COMMAND_TIMEOUT,
    KEYRING_USERNAME,
    KeySourceError,
    read_api_key,
)
from checker.cli import main
from checker.credentials import KEYRING_SERVICE
from checker.evidence import Advisor, Store, config_file, database_file, load_config
from checker.settings import SETTABLE, change


@pytest.fixture
def base(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    assert main(["init", "--advisor", "off"]) == 0
    return tmp_path


def changes(base):
    store = Store(database_file(base))
    try:
        return [dict(row) for row in store.config_changes()]
    finally:
        store.close()


# --- init -----------------------------------------------------------------------


def test_init_leaves_the_advisor_off_without_a_terminal(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert main(["init"]) == 0
    assert load_config(tmp_path).advisor.enabled is False
    out = capsys.readouterr().out
    assert "AI advisor: off" in out
    assert "Turn the AI advisor on?" not in out


@pytest.mark.parametrize(("answer", "enabled"), [("y", True), ("", False), ("no", False)])
def test_init_asks_in_a_terminal(tmp_path, monkeypatch, capsys, answer, enabled):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt: asked.append(prompt) or answer)
    assert main(["init"]) == 0
    assert asked == ["Turn the AI advisor on? [y/N] "]
    assert load_config(tmp_path).advisor.enabled is enabled
    out = capsys.readouterr().out
    assert "with your organization's own API key" in out  # explained before asking
    assert ("AI advisor: on" in out) is enabled


def test_init_advisor_flags(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    source = "command:op read 'op://Vault/Anthropic key/credential'"
    assert (
        main(
            [
                "init",
                "--advisor",
                "on",
                "--advisor-key-source",
                source,
                "--advisor-redaction",
                "strict",
            ]
        )
        == 0
    )
    advisor = load_config(tmp_path).advisor
    assert (advisor.enabled, advisor.api_key_source, advisor.redaction) == (True, source, "strict")
    out = capsys.readouterr().out
    assert "op read 'op://Vault/Anthropic key/credential'" in out
    assert "only the kinds of finding, counts, scores and kinds of coverage gap are sent" in out


def test_init_refuses_a_bad_key_source(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    assert main(["init", "--advisor", "on", "--advisor-key-source", "the-key-itself"]) == 2
    assert capsys.readouterr().err == (
        "checker: --advisor-key-source: must be env, keyring, none or command:<command>\n"
    )
    assert not config_file(tmp_path).exists()


def test_init_when_already_set_up_asks_nothing(base, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked"))
    assert main(["init"]) == 1
    assert "already set up" in capsys.readouterr().err


def test_init_end_of_input_at_the_question_means_off(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def eof(prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert main(["init"]) == 0
    assert load_config(tmp_path).advisor.enabled is False


@pytest.mark.parametrize(
    ("redaction", "says", "never"),
    [
        ("pseudonymize", "replaced with placeholders first", "sent as collected"),
        ("none", "sent as collected, after secret masking", "placeholders"),
        ("strict", "only the kinds of finding, their counts", "excerpts of the evidence"),
    ],
)
def test_the_question_says_what_this_redaction_sends(
    tmp_path, monkeypatch, capsys, redaction, says, never
):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert main(["init", "--advisor-redaction", redaction]) == 0
    question = capsys.readouterr().out.split("Set up in")[0]
    assert " ".join(says.split()) in " ".join(question.split())
    assert never not in question


@pytest.mark.parametrize(
    "source",
    [
        "command:echo sk-ant-api03-abc",
        "command:printf %s AbCdEf0123456789AbCdEf0123456789xyz",
    ],
)
def test_a_key_pasted_into_the_command_is_refused(base, capsys, source):
    assert main(["config", "set", "advisor.api_key_source", source]) == 2
    assert "looks like a key itself" in capsys.readouterr().err
    assert "sk-ant" not in config_file(base).read_text()
    assert changes(base) == []


def test_ordinary_key_commands_are_accepted(base):
    for source in (
        "command:op read 'op://Vault/Anthropic key/credential'",
        "command:/usr/local/bin/print-anthropic-api-key-for-checker",
        "command:op read op://Private/3f2a1c9e1b2c4d5e8f90abcdef012345/credential",
    ):
        change(base, "advisor.api_key_source", source)
        assert load_config(base).advisor.api_key_source == source


def test_older_configuration_files_get_the_advisor_off(base):
    data = yaml.safe_load(config_file(base).read_text())
    del data["advisor"]
    config_file(base).write_text(yaml.safe_dump(data))
    assert load_config(base).advisor == Advisor()
    assert load_config(base).advisor.enabled is False


# --- config set / show / history ------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "text", "value"),
    [
        ("home_text", "privileged", "privileged"),
        ("web_access_logs", "on", True),
        ("exec_records", "all", "all"),
        ("retention_days", "30", 30),
        ("notify_command", "/usr/local/bin/tell-ops", "/usr/local/bin/tell-ops"),
        ("prior", "0.05", 0.05),
        ("advisor.enabled", "on", True),
        ("advisor.model", "claude-sonnet-5-5", "claude-sonnet-5-5"),
        ("advisor.triage_model", "claude-haiku-5-5", "claude-haiku-5-5"),
        ("advisor.effort", "max", "max"),
        ("advisor.redaction", "none", "none"),
        ("advisor.api_key_source", "keyring", "keyring"),
        ("advisor.inference_geo", "us", "us"),
        ("advisor.max_cost_per_run", "2.5", 2.5),
        ("advisor.fallback", "off", "off"),
        ("advisor.base_url", "http://localhost:11434/v1", "http://localhost:11434/v1"),
        ("advisor.fallback_model.model", "qwen2.5:7b", "qwen2.5:7b"),
        ("advisor.fallback_model.api", "openai", "openai"),
        (
            "advisor.fallback_model.base_url",
            "https://models.example.org/v1/",
            "https://models.example.org/v1",
        ),
        ("advisor.fallback_model.api_key_source", "keyring", "keyring"),
    ],
)
def test_every_setting_round_trips(base, key, text, value):
    old, new, _ = change(base, key, text)
    assert new == value and old != value
    data = load_config(base).model_dump()
    for name in key.split("."):
        data = data[name]
    assert data == value
    (row,) = changes(base)
    assert row["setting"] == key
    assert json.loads(row["old"]) == old and json.loads(row["new"]) == value
    assert row["operator"] and row["controller"] and row["at"]


def test_the_table_lists_every_setting_tested():
    # advisor.api is tested with base_url, which it needs (test_advisor_endpoints).
    assert len(SETTABLE) == 21


@pytest.mark.parametrize(
    ("key", "text", "words"),
    [
        ("home_text", "some", "'off', 'privileged' or 'all'"),
        ("web_access_logs", "maybe", "must be on or off"),
        ("retention_days", "0", "greater than or equal to 1"),
        ("prior", "1.5", "less than 1"),
        ("advisor.effort", "extreme", "'low', 'medium', 'high', 'xhigh' or 'max'"),
        ("advisor.api_key_source", "sk-ant-abc", "must be env, keyring, none or command:<command>"),
        ("advisor.api_key_source", "command:", "needs a command after it"),
        ("advisor.api_key_source", "command:op read 'unclosed", "doesn't parse"),
        ("advisor.model", "bad model; rm", "should match pattern"),
        ("advisor.max_cost_per_run", "-1", "greater than 0"),
    ],
)
def test_invalid_values_are_refused_and_change_nothing(base, capsys, key, text, words):
    before = config_file(base).read_text()
    assert main(["config", "set", key, text]) == 2
    err = capsys.readouterr().err
    assert words in err and err.startswith(f"checker: {key}: ")
    assert config_file(base).read_text() == before
    assert changes(base) == []


def test_unknown_setting(base, capsys):
    with pytest.raises(SystemExit):
        main(["config", "set", "recipients", "age1…"])
    assert "invalid choice" in capsys.readouterr().err


def test_same_value_records_nothing(base, capsys):
    assert main(["config", "set", "advisor.enabled", "off"]) == 0
    assert "Nothing changed" in capsys.readouterr().out
    assert changes(base) == []


def test_an_optional_setting_can_be_cleared(base):
    change(base, "advisor.inference_geo", "us")
    _, new, _ = change(base, "advisor.inference_geo", "none")
    assert new is None and load_config(base).advisor.inference_geo is None


def test_turning_the_advisor_on_explains_what_is_sent(base, capsys):
    assert main(["config", "set", "advisor.enabled", "on"]) == 0
    out = capsys.readouterr().out
    assert "advisor.enabled: false -> true (recorded)" in out
    assert "with your organization's own API key" in out
    assert "Redaction: pseudonymize" in out


def test_a_failed_write_records_no_change(base, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("checker.settings.atomic_write", fail)
    with pytest.raises(OSError):
        change(base, "advisor.enabled", "on")
    assert changes(base) == []
    assert load_config(base).advisor.enabled is False


def test_a_failed_commit_puts_the_old_configuration_back(base, monkeypatch):
    import checker.settings

    before = config_file(base).read_text()

    class FailingCommit:
        def __init__(self, db):
            self._db = db

        def commit(self):
            raise sqlite3.OperationalError("database is locked")

        def __getattr__(self, name):
            return getattr(self._db, name)

    class Flaky(Store):
        def __init__(self, path):
            super().__init__(path)
            self._db = FailingCommit(self._db)

    monkeypatch.setattr(checker.settings, "Store", Flaky)
    with pytest.raises(sqlite3.OperationalError):
        change(base, "advisor.enabled", "on")
    assert config_file(base).read_text() == before
    assert changes(base) == []


def test_config_set_reports_a_write_failure(base, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("checker.settings.atomic_write", fail)
    assert main(["config", "set", "advisor.enabled", "on"]) == 1
    assert "advisor.enabled not changed: disk full" in capsys.readouterr().err


def test_turning_the_advisor_on_says_what_its_redaction_sends(base, capsys):
    change(base, "advisor.redaction", "none")
    assert main(["config", "set", "advisor.enabled", "on"]) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "Excerpts are sent as collected" in out and "placeholders first" not in out


def test_changes_are_append_only(base):
    change(base, "advisor.enabled", "on")
    db = sqlite3.connect(database_file(base))
    try:
        for sql in ("UPDATE config_changes SET new = 'false'", "DELETE FROM config_changes"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                db.execute(sql)
    finally:
        db.close()


def test_history_and_show(base, capsys):
    assert main(["config", "history"]) == 0
    assert "No settings changed" in capsys.readouterr().out
    change(base, "web_access_logs", "on")
    assert main(["config", "history"]) == 0
    assert "web_access_logs: false -> true" in capsys.readouterr().out
    assert main(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert "Web access logs: collected, masked" in out
    assert 'advisor.api_key_source = "env"' in out


def test_config_before_init(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    assert main(["config", "show"]) == 2
    assert main(["config", "set", "web_access_logs", "on"]) == 2
    assert "checker init" in capsys.readouterr().err


# --- the API key -------------------------------------------------------------------------

KEY = "sk-ant-api03-" + "x" * 40


def test_key_from_the_environment(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY + "\n")
    assert read_api_key("env") == KEY
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    with pytest.raises(KeySourceError, match="ANTHROPIC_API_KEY is not set"):
        read_api_key("env")


def test_key_from_the_keyring(monkeypatch):
    stored = {}
    fake = types.ModuleType("keyring")
    fake.get_password = lambda service, username: stored.get((service, username))
    monkeypatch.setitem(sys.modules, "keyring", fake)
    with pytest.raises(KeySourceError, match="keyring set compromise-checker advisor-api-key"):
        read_api_key("keyring")
    stored[(KEYRING_SERVICE, KEYRING_USERNAME)] = KEY
    assert read_api_key("keyring") == KEY

    def locked(service, username):
        raise RuntimeError("the collection is locked")

    fake.get_password = locked
    with pytest.raises(KeySourceError, match="could not be read .RuntimeError"):
        read_api_key("keyring")


def test_key_command_that_cannot_run_or_prints_bytes(tmp_path):
    not_executable = tmp_path / "plain"
    not_executable.write_text("echo hi\n")
    with pytest.raises(KeySourceError, match="could not be run"):
        read_api_key(f"command:{not_executable}")
    binary = tmp_path / "binary"
    binary.write_text("#!/bin/sh\nprintf '\\377\\376'\n")
    binary.chmod(0o700)
    with pytest.raises(KeySourceError, match="isn't text"):
        read_api_key(f"command:{binary}")


def test_key_command_errors_hide_tokens(tmp_path):
    token = "AbCdEf0123456789AbCdEf0123456789xyz"
    script = tmp_path / "fail"
    script.write_text(f"#!/bin/sh\necho 'bad token {token} given' >&2\nexit 1\n")
    script.chmod(0o700)
    with pytest.raises(KeySourceError) as raised:
        read_api_key(f"command:{script}")
    assert str(raised.value).endswith(": bad token [hidden] given")


def test_key_from_a_command(tmp_path):
    script = tmp_path / "print-key"
    script.write_text(f"#!/bin/sh\nprintf '%s\\n' '{KEY}'\n")
    script.chmod(0o700)
    assert read_api_key(f"command:{script}") == KEY


def test_key_command_failures_never_show_its_output(tmp_path):
    script = tmp_path / "fail"
    script.write_text(f"#!/bin/sh\necho '{KEY}'\necho 'not signed in' >&2\nexit 3\n")
    script.chmod(0o700)
    with pytest.raises(KeySourceError) as raised:
        read_api_key(f"command:{script}")
    assert "status 3: not signed in" in str(raised.value) and KEY not in str(raised.value)
    leaky = tmp_path / "leaky"
    leaky.write_text(f"#!/bin/sh\necho '{KEY}' >&2\nexit 1\n")
    leaky.chmod(0o700)
    with pytest.raises(KeySourceError) as raised:
        read_api_key(f"command:{leaky}")
    assert KEY not in str(raised.value)
    with pytest.raises(KeySourceError, match="was not found"):
        read_api_key(f"command:{tmp_path / 'missing'}")
    with pytest.raises(KeySourceError, match="gave no key"):
        read_api_key("command:true")
    with pytest.raises(KeySourceError, match="isn't a single key"):
        read_api_key("command:echo two words")


def test_key_command_timeout(monkeypatch):
    import subprocess

    def slow(*args, **kwargs):
        assert kwargs["timeout"] == COMMAND_TIMEOUT
        assert kwargs["stdin"] is subprocess.DEVNULL
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(KeySourceError, match="prompt not answered"):
        read_api_key("command:op read x")


def test_check_key_reports_without_showing_the_key(base, monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    assert main(["config", "check-key"]) == 0
    out = capsys.readouterr().out
    assert f"A key was read ({len(KEY)} characters). Nothing was sent." in out
    assert "advisor is off" in out and KEY not in out
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-key")
    assert main(["config", "check-key"]) == 0
    assert "doesn't look like an Anthropic API key" in capsys.readouterr().out
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert main(["config", "check-key"]) == 1
    assert "ANTHROPIC_API_KEY is not set" in capsys.readouterr().err
