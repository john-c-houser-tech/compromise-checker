"""Scheduled checks: `checker run` and `checker schedule` (checker.schedule).
Collection is faked (a bundle added as a collection would add it), and no
timer is really installed: systemctl and launchctl are recorded, not run."""

import plistlib
import shlex
import sys
import time
from pathlib import Path

import asyncssh
import pytest
from test_snapshot import add_bundle, host_records

from checker import cli, schedule
from checker.collect import Outcome
from checker.evidence import EvidenceError, load_config
from checker.inventory import Host, inventory_transaction, load_inventory
from checker.purge import Plan
from checker.settings import change, describe

ROOTED = host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0)))  # a second UID 0
CLEAN = host_records()


def key_file(tmp_path, passphrase=None) -> Path:
    path = tmp_path / ("locked_key" if passphrase else "key")
    key = asyncssh.generate_private_key("ssh-ed25519")
    path.write_bytes(key.export_private_key("pkcs8-pem", passphrase=passphrase))
    path.chmod(0o600)
    return path


def keyed_host(tmp_path, name="web01", **extra) -> Host:
    return Host(
        name=name, address="192.0.2.1", user="scanner", auth="key",
        key_path=str(key_file(tmp_path)), **extra,
    )  # fmt: skip


@pytest.fixture
def fleet(home, tmp_path):
    with inventory_transaction() as hosts:
        hosts.add(keyed_host(tmp_path))
    return home


def collector(home, records, status="complete", error=None):
    """A stand-in for collect_hosts: each call stores one more bundle per host."""
    calls = []

    async def collect(base, config, hosts, **kwargs):
        calls.append((hosts, kwargs))
        outcomes = []
        for host in hosts:
            count = len(home[1].bundles(host.name))
            name = f"{host.name}-b{count + 1}"
            if status in ("complete", "partial", "incomplete"):
                add_bundle(home, name, (count + 1) * 10, records, status=status, host=host.name)
            outcomes.append(Outcome(host.name, name, status, error, 1))
        return outcomes

    collect.calls = calls
    return collect


def one_run(home, collect, unattended=True, environ=None):
    base, _, identity, _ = home
    inventory = load_inventory()
    return schedule.run(
        base, load_config(base), list(inventory.hosts), identity, inventory,
        unattended=unattended, collect=collect, say=lambda line: None, environ=environ or {},
    )  # fmt: skip


def recorder(tmp_path, name="told") -> tuple[str, Path]:
    """A notify command that keeps what it was given."""
    out = tmp_path / f"{name}.txt"
    script = tmp_path / f"{name}.py"
    script.write_text("import sys\nopen(sys.argv[1], 'a').write(sys.stdin.read())\n")
    return shlex.join([sys.executable, str(script), str(out)]), out


def failing(code=4) -> str:
    return f"{shlex.quote(sys.executable)} -c 'import sys; sys.exit({code})'"


# --- A run ---------------------------------------------------------------------------------


def test_a_first_run_on_a_rooted_host_alerts_reports_and_tells(fleet, tmp_path):
    base = fleet[0]
    command, told = recorder(tmp_path)
    change(base, "notify_command", command)
    result = one_run(fleet, collector(fleet, ROOTED))
    (host,) = result.hosts
    assert host.band == "High" and host.problem is None
    assert result.alerting[0].startswith("web01: Low to High (")
    assert any(line.startswith("web01: new critical: An account") for line in result.alerting)
    assert result.report is not None and result.report.exists()
    assert result.exit_status() == schedule.EXIT_BAND["High"] == 11
    text = told.read_text()
    assert text.startswith("Compromise Checker: 2 thing(s) need a look\n")
    assert f"Report: {result.report}" in text
    assert f"To read it: checker report --open {result.report}" in text
    assert "toor" not in text  # titles and bands only: no evidence


def test_nothing_new_tells_no_one(fleet, tmp_path):
    base = fleet[0]
    collect = collector(fleet, ROOTED)
    one_run(fleet, collect)
    command, told = recorder(tmp_path)
    change(base, "notify_command", command)
    result = one_run(fleet, collect)
    assert result.alerting == [] and not told.exists()
    assert result.exit_status() == 11  # still High: the timer's log shows it


def test_a_new_serious_finding_on_a_host_already_known_is_told(fleet):
    one_run(fleet, collector(fleet, CLEAN))
    result = one_run(fleet, collector(fleet, ROOTED))
    assert any("new critical" in line for line in result.alerting)


def test_an_analysis_between_runs_doesnt_swallow_the_alert(fleet):
    """Runs compare with the last run, not with whatever was analysed since."""
    one_run(fleet, collector(fleet, CLEAN))
    add_bundle(fleet, "web01-manual", 15, ROOTED)
    assert cli.main(["analyze", "web01"]) in (0, 1)
    result = one_run(fleet, collector(fleet, ROOTED))
    assert any("new critical" in line for line in result.alerting)


def test_what_a_run_keeps_between_runs_is_encrypted(fleet):
    one_run(fleet, collector(fleet, ROOTED))
    kept = (fleet[0] / schedule.STATE_FILE).read_bytes()
    assert kept.startswith(b"age-encryption.org/") and b"account.uid0" not in kept
    assert schedule.load_state(fleet[0], fleet[2])["hosts"]["web01"]["band"] == "High"


def test_a_host_that_couldnt_be_collected_is_told_in_the_tools_words(fleet):
    """The host's own error text (sudo's, say) stays out of the summary."""
    forged = "sudo: x\n\nweb01: Low to Low\nReport: https://evil.example/r"
    result = one_run(fleet, collector(fleet, ROOTED, status="refused", error=forged))
    assert result.alerting == ["web01: not collected (refused)"]
    (host,) = result.hosts
    assert "\n" not in host.problem and "\\u000a" in host.problem  # shown safely, in the log
    assert result.report is None and result.exit_status() == schedule.EXIT_FAILED


def test_a_partial_collection_needs_a_look(fleet):
    result = one_run(fleet, collector(fleet, CLEAN, status="partial", error="module timed out"))
    assert "web01: collected in part (partial)" in result.alerting
    assert result.exit_status() == schedule.EXIT_FAILED


def test_a_host_that_would_need_a_prompt_is_left_out_and_the_rest_are_collected(fleet):
    with inventory_transaction() as hosts:
        hosts.add(Host(name="typed", address="192.0.2.2", user="u", auth="password"))
    collect = collector(fleet, CLEAN)
    result = one_run(fleet, collect)
    ((collected, _),) = collect.calls
    assert [h.name for h in collected] == ["web01"]
    assert "typed: not collected (it would need a prompt)" in result.alerting
    assert result.exit_status() == schedule.EXIT_FAILED


def test_an_analysis_that_breaks_doesnt_stop_the_purge_or_the_notice(fleet, tmp_path, monkeypatch):
    base = fleet[0]
    command, told = recorder(tmp_path)
    change(base, "notify_command", command)
    purged = []
    monkeypatch.setattr(schedule, "_purge_expired", lambda *args: purged.append(True))

    def broken(*args, **kwargs):
        raise KeyError("odd")

    monkeypatch.setattr("checker.assess.analyze", broken)
    result = one_run(fleet, collector(fleet, CLEAN))
    assert result.alerting == ["web01: not analysed (KeyError)"]
    assert purged and "web01: not analysed (KeyError)" in told.read_text()


def test_an_undelivered_alert_is_sent_with_the_next_run(fleet, tmp_path):
    base = fleet[0]
    change(base, "notify_command", failing())
    first = one_run(fleet, collector(fleet, ROOTED))
    assert first.notified and first.alerting
    command, told = recorder(tmp_path)
    change(base, "notify_command", command)
    one_run(fleet, collector(fleet, ROOTED))
    text = told.read_text()
    assert "(from an earlier run) web01: Low to High" in text
    told.unlink()
    third = one_run(fleet, collector(fleet, ROOTED))
    assert third.alerting == [] and not told.exists()  # delivered: not sent again


def test_a_run_that_stops_unforeseen_still_tells(fleet, tmp_path, monkeypatch):
    base = fleet[0]
    command, told = recorder(tmp_path)
    change(base, "notify_command", command)

    def crash(*args, **kwargs):
        raise RuntimeError("odd")

    monkeypatch.setattr(schedule, "run", crash)
    assert cli.main(["run", "--all", "--unattended"]) == schedule.EXIT_FAILED
    assert "the scheduled run stopped: RuntimeError" in told.read_text()


def test_an_unattended_run_never_prompts(fleet):
    collect = collector(fleet, CLEAN)
    one_run(fleet, collect)
    assert collect.calls[0][1]["password_provider"] is schedule.unattended_password
    with pytest.raises(RuntimeError, match="doesn't ask"):
        schedule.unattended_password(Host(name="a", address="192.0.2.1", user="u", sudo="password"))


def test_a_password_given_for_this_run_is_used_and_nothing_is_refused(fleet):
    base, *_ = fleet
    inventory = load_inventory()
    host = inventory.hosts[0].model_copy(update={"auth": "password"})
    collect = collector(fleet, CLEAN)
    config = load_config(base)
    identity = fleet[2]
    schedule.run(
        base, config, [host], identity, inventory, unattended=True, collect=collect,
        say=lambda line: None, environ={}, typed_passwords={host.name: "given"},
    )  # fmt: skip
    assert collect.calls and collect.calls[0][1]["password_provider"](host) == "given"
    other = host.model_copy(update={"name": "other"})
    with pytest.raises(RuntimeError, match="doesn't ask"):
        collect.calls[0][1]["password_provider"](other)


def test_a_keyring_that_doesnt_answer_isnt_waited_for(monkeypatch):
    monkeypatch.setattr("checker.credentials.password_for", lambda host: time.sleep(5))
    host = Host(name="a", address="192.0.2.1", user="u", auth="password", password_source="keyring")
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="didn't answer within"):
        schedule.unattended_password(host, timeout=0.2)
    assert time.monotonic() - started < 2


def test_a_failing_notify_command_fails_the_run(fleet):
    change(fleet[0], "notify_command", failing())
    result = one_run(fleet, collector(fleet, CLEAN, status="refused", error="down"))
    assert result.notified == "it exited with status 4"
    assert result.exit_status() == schedule.EXIT_FAILED


def test_the_notify_command_doesnt_wait_for_what_it_leaves_running():
    started = time.monotonic()
    assert schedule.notify("/bin/sh -c 'sleep 3 & exit 0'", "hi", timeout=2) is None
    assert time.monotonic() - started < 2


def test_the_notify_command_isnt_given_the_advisors_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    out = tmp_path / "env.txt"
    script = tmp_path / "env.py"
    script.write_text(
        "import os, sys\nopen(sys.argv[1], 'w').write(os.environ.get('ANTHROPIC_API_KEY', '-'))\n"
    )
    assert schedule.notify(shlex.join([sys.executable, str(script), str(out)]), "hi") is None
    assert out.read_text() == "-"


def test_runs_take_turns(fleet):
    with schedule.run_lock(fleet[0]), pytest.raises(schedule.Busy):
        one_run(fleet, collector(fleet, CLEAN))


def test_an_empty_inventory_purges_nothing(home):
    base, store, _, config = home
    result = schedule.RunResult([])
    schedule._purge_expired(store, base, config, load_inventory(), print, result)
    assert result.problems == [
        "nothing purged: the inventory is empty, and expiry keeps inventoried baselines"
    ]


def test_a_purged_baseline_needs_a_look(fleet, monkeypatch):
    base, store, _, config = fleet
    chosen = Plan(scope={}, bundles=[object()], baselines={"web01": "moved", "db1": "emptied"})
    monkeypatch.setattr("checker.purge.plan", lambda *args, **kwargs: chosen)

    class Purged:
        counts, failed = {"bundles": 1}, []

    monkeypatch.setattr("checker.purge.execute", lambda *args: Purged())
    result = schedule.RunResult([])
    schedule._purge_expired(store, base, config, load_inventory(), lambda line: None, result)
    assert result.run_alerts == [
        "db1: all its evidence had expired and was purged",
        "web01: its expired baseline was purged; a newer bundle becomes its baseline",
    ]


# --- What counts as worse --------------------------------------------------------------------


def finding(check, band, entities=("account:x",), suppressed=None, **extra):
    return {"check": check, "band": band, "title": f"{check} title", "variant": None,
            "entities": list(entities), "suppressed_by": suppressed, **extra}  # fmt: skip


def analysis(band, *findings, failed=()):
    return {
        "score": {"band": band, "probability": 0.5},
        "findings": list(findings),
        "checks": [{"check": c, "status": "failed: KeyError: x"} for c in failed],
    }


def worse(before, after):
    return schedule.alerts("h", schedule.remembered(before), after)


def test_what_counts_as_worse():
    root = finding("account.uid0", "critical")
    before = analysis("High", root)
    assert worse(before, analysis("High", root)) == []
    assert worse(before, analysis("Critical", root)) == ["h: High to Critical (50.0%)"]
    assert worse(analysis("High"), analysis("Elevated")) == []  # better isn't news
    other = finding("account.uid0", "critical", entities=("account:y",))
    assert worse(before, analysis("High", root, other)) == ["h: new critical: account.uid0 title"]
    # Suppressed, or below high: not news.
    quiet = [finding("net.listener", "medium"), finding("x.y", "high", suppressed="rule")]
    assert worse(before, analysis("High", root, *quiet)) == []
    # A finding a rule hid last time, in effect now (its rule expired): news.
    hidden = analysis("High", root, finding("x.y", "high", suppressed="rule"))
    assert worse(hidden, analysis("High", root, finding("x.y", "high"))) == [
        "h: new high: x.y title"
    ]


def test_a_finding_that_grew_serious_is_news():
    before = analysis("Elevated", finding("net.listener", "medium"))
    assert worse(before, analysis("Elevated", finding("net.listener", "high"))) == [
        "h: now high (was medium): net.listener title"
    ]


def test_a_restarted_process_is_the_same_finding():
    before = analysis("High", finding("process.x", "high", entities=("program:sh", "pid:10")))
    after = analysis("High", finding("process.x", "high", entities=("program:sh", "pid:99")))
    assert worse(before, after) == []


def test_a_group_listed_in_part_shows_a_new_member():
    group = ("file:/tmp/a",)
    before = analysis("High", finding("files.tmp", "high", group, entities_complete=False,
                                      summary="21 files in /tmp"))  # fmt: skip
    after = analysis("High", finding("files.tmp", "high", group, entities_complete=False,
                                     summary="22 files in /tmp"))  # fmt: skip
    assert worse(before, after) == ["h: new high: files.tmp title"]


def test_a_check_that_newly_fails_is_news_once():
    assert worse(analysis("Low"), analysis("Low", failed=["mail.burst"])) == [
        "h: check mail.burst failed"
    ]
    assert (
        worse(analysis("Low", failed=["mail.burst"]), analysis("Low", failed=["mail.burst"])) == []
    )


def test_host_text_in_a_title_is_shown_safely():
    odd = finding("web.shell", "high")
    odd["title"] = "evil" + chr(0x202E) + "txt"
    (line,) = schedule.alerts("h", None, analysis("Low", odd))
    assert chr(0x202E) not in line and "\\u202e" in line


def test_the_exit_status_is_failure_else_the_worst_band():
    low = schedule.HostResult("a", "complete", band="Low")
    high = schedule.HostResult("b", "complete", band="High")
    broken = schedule.HostResult("c", "refused", problem="not collected (x)")
    assert schedule.RunResult([low]).exit_status() == 0
    assert schedule.RunResult([low, high]).exit_status() == 11
    assert schedule.RunResult([low, broken]).exit_status() == 1
    assert schedule.RunResult([high, broken]).exit_status() == 1  # a failure isn't hidden
    assert schedule.RunResult([high], notified="down").exit_status() == 1
    assert schedule.RunResult([low], problems=["report"]).exit_status() == 1


# --- Unattended ------------------------------------------------------------------------------


def test_what_would_stop_an_unattended_run_at_a_prompt(tmp_path):
    hosts = [
        Host(name="typed", address="192.0.2.1", user="u", auth="password", sudo="nopasswd"),
        Host(name="sudo", address="192.0.2.1", user="u", sudo="password"),
        Host(
            name="kept", address="192.0.2.1", user="u", auth="password", password_source="keyring"
        ),  # fmt: skip
        Host(name="agent", address="192.0.2.1", user="u", auth="agent"),
        Host(
            name="locked",
            address="192.0.2.1",
            user="u",
            auth="key",
            key_path=str(key_file(tmp_path, passphrase="secret")),
        ),  # fmt: skip
        Host(
            name="gone",
            address="192.0.2.1",
            user="u",
            auth="key",
            key_path=str(tmp_path / "missing"),
        ),  # fmt: skip
        keyed_host(tmp_path, name="fine"),
    ]
    problems = schedule.unattended_problems(hosts, environ={})
    named = [p.split(" ", 1)[0].split("'", 1)[0] for p in problems]
    assert named == ["typed", "sudo", "sudo", "agent", "locked", "gone"]
    assert "password typed at a prompt" in problems[0]
    assert "passphrase" in problems[4]
    assert schedule.unattended_problems(hosts[3:4], environ={"SSH_AUTH_SOCK": "/s"}) == []


def test_the_command_prints_and_exits_with_the_band(fleet, monkeypatch, capsys):
    monkeypatch.setattr("checker.collect.collect_hosts", collector(fleet, ROOTED))
    assert cli.main(["run", "--all", "--unattended"]) == 11
    out = capsys.readouterr().out
    assert "web01" in out and "High (67%)" in out and "Needs a look:" in out
    assert "No notify_command is set" in out


def test_unreadable_settings_are_a_setup_problem(fleet):
    (fleet[0] / "config.yaml").write_text("retention_days: [", encoding="utf-8")
    assert cli.main(["run", "--all"]) == schedule.EXIT_SETUP


# --- The setting -----------------------------------------------------------------------------


def test_the_notify_command_setting(home):
    base = home[0]
    with pytest.raises(EvidenceError, match="can't be split"):
        change(base, "notify_command", "/bin/mail -s 'oops")
    with pytest.raises(EvidenceError, match="full path"):
        change(base, "notify_command", "tell-ops")
    change(base, "notify_command", "/usr/local/bin/tell-ops")
    lines = describe(load_config(base))
    assert any("`/usr/local/bin/tell-ops`" in line for line in lines)
    assert any("and what your notify command sends" in line for line in lines)
    change(base, "notify_command", "none")
    assert load_config(base).notify_command is None


# --- The timer --------------------------------------------------------------------------------


def test_the_systemd_units(tmp_path):
    env = {"CHECKER_HOME": "/home/a b/checker", "SSH_AUTH_SOCK": "/run/x%y"}
    where = schedule.placement("linux", (3, 5), env, tmp_path, tmp_path / "home")
    service, timer = (where.files[p].decode() for p in sorted(where.files))
    assert 'Environment="CHECKER_HOME=/home/a b/checker"' in service
    assert 'Environment="SSH_AUTH_SOCK=/run/x%%y"' in service  # % is systemd's own
    assert (
        f'ExecStart="{sys.executable}" "-P" "-m" "checker" "run" "--all" "--unattended"' in service
    )
    assert "SuccessExitStatus=10 11 12" in service and "TimeoutStartSec=4h" in service
    assert "OnCalendar=*-*-* 03:05:00" in timer and "Persistent=true" in timer


@pytest.mark.parametrize("path", ["/home/a$b", '/home/a"b', "/home/a\\b", "/home/a'b", "/a\nb"])
def test_paths_a_systemd_unit_cant_hold_are_refused(path):
    assert schedule.systemd_unsafe({"CHECKER_HOME": path}) == [path]
    assert schedule.systemd_unsafe({"CHECKER_HOME": "/home/a b/c%d"}) == []


def test_install_refuses_a_home_systemd_cant_hold(fleet, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(schedule, "timer_environment", lambda base, hosts: {"CHECKER_HOME": "/a$b"})
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    assert cli.main(["schedule", "install"]) == 2
    assert "can't hold these paths" in capsys.readouterr().err
    assert not (tmp_path / "user").exists()


def test_the_launchd_agent(tmp_path):
    where = schedule.placement("darwin", (22, 30), {"CHECKER_HOME": "/c"}, tmp_path, tmp_path)
    ((path, content),) = where.files.items()
    assert path.name == "com.nouriloop.compromise-checker.plist"
    agent = plistlib.loads(content)
    assert agent["StartCalendarInterval"] == {"Hour": 22, "Minute": 30}
    assert agent["ProgramArguments"][-3:] == ["run", "--all", "--unattended"]
    assert agent["EnvironmentVariables"] == {"CHECKER_HOME": "/c"}


@pytest.mark.parametrize("text", ["3", "24:00", "12:60", "noon", "1:2:3"])
def test_a_time_must_be_a_time_of_day(text):
    with pytest.raises(ValueError, match="HH:MM"):
        schedule.parse_time(text)


class Done:
    def __init__(self, code=0, stdout="Linger=no\n"):
        self.returncode, self.stdout, self.stderr = code, stdout, "busy" if code else ""


def test_install_and_remove(fleet, tmp_path, monkeypatch, capsys):
    ran = []
    monkeypatch.setattr("subprocess.run", lambda command, **kw: ran.append(command) or Done())
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user" / ".config"))
    assert cli.main(["schedule", "install", "--at", "02:15"]) == 0
    folder = tmp_path / "user" / ".config" / "systemd" / "user"
    timer = (folder / "compromise-checker.timer").read_text()
    assert "OnCalendar=*-*-* 02:15:00" in timer
    assert ["systemctl", "--user", "enable", "--now", "compromise-checker.timer"] in ran
    out = capsys.readouterr().out
    assert "every day at 02:15" in out and "enable-linger" in out
    assert cli.main(["schedule", "show"]) == 0
    assert "Installed:" in capsys.readouterr().out
    ran.clear()
    assert cli.main(["schedule", "remove"]) == 0
    assert not (folder / "compromise-checker.timer").exists()
    assert ran[0] == ["systemctl", "--user", "disable", "--now", "compromise-checker.timer"]
    assert ran[-1] == ["systemctl", "--user", "daemon-reload"]


def test_install_on_a_mac_waits_for_the_old_agent_to_go(fleet, tmp_path, monkeypatch):
    answers = iter([Done(), Done(5), Done(5), Done()])  # bootout, then two busy bootstraps
    ran, waited = [], []
    monkeypatch.setattr(
        "subprocess.run", lambda command, **kw: ran.append(command) or next(answers)
    )
    monkeypatch.setattr("time.sleep", waited.append)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    assert cli.main(["schedule", "install"]) == 0
    assert [c[1] for c in ran] == ["bootout", "bootstrap", "bootstrap", "bootstrap"]
    assert waited == [1.0, 1.0]
    agents = tmp_path / "user" / "Library" / "LaunchAgents"
    assert (agents / "com.nouriloop.compromise-checker.plist").exists()


def test_a_run_purges_only_hosts_in_the_inventory(fleet):
    """A host taken out of the inventory (perhaps only paused) keeps its
    evidence and baseline until a person runs the purge."""
    from test_purge import add

    base, store, _, config = fleet
    add(fleet, "old-web", 400)
    add(fleet, "old-paused", 400, host="paused")
    said = []
    result = schedule.RunResult([])
    schedule._purge_expired(store, base, config, load_inventory(), said.append, result)
    assert store.bundles("web01") == [] and len(store.bundles("paused")) == 1
    assert result.run_alerts == ["web01: all its evidence had expired and was purged"]
    assert any("1 expired bundle(s) of hosts not in the inventory are kept" in s for s in said)


def test_the_bands_are_the_ones_scoring_gives():
    from checker.scoring import PROBABILITY_BANDS

    assert set(schedule.BANDS) == {name for _, name in PROBABILITY_BANDS} == set(schedule.EXIT_BAND)


def test_rising_to_elevated_is_news():
    (line,) = schedule.alerts("web01", {"band": "Low"}, {"score": {"band": "Elevated"}})
    assert line == "web01: Low to Elevated"


def test_a_stopped_collection_ends_the_run_cleanly(fleet, monkeypatch):
    import asyncio

    async def stopped(*args, **kwargs):
        raise asyncio.CancelledError

    with pytest.raises(schedule.Stopped):
        one_run(fleet, stopped)
    with schedule.run_lock(fleet[0]):  # the lock went with it
        pass
