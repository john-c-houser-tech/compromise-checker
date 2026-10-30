"""Scheduled checks: `checker run` and `checker schedule` (checker.schedule).
Collection is faked (a bundle added as a collection would add it), and no
timer is really installed: systemctl and launchctl are recorded, not run."""

import plistlib
import shlex
import sys
from pathlib import Path

import asyncssh
import pytest
from test_snapshot import add_bundle, host_records

from checker import cli, schedule
from checker.collect import Outcome
from checker.evidence import EvidenceError, load_config
from checker.inventory import Host, inventory_transaction, load_inventory
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
    """A stand-in for collect_hosts: each call stores one more bundle."""
    calls = []

    async def collect(base, config, hosts, **kwargs):
        calls.append(kwargs)
        count = len(home[1].bundles("web01"))
        name = f"b{count + 1}"
        if status in ("complete", "partial"):
            add_bundle(home, name, (count + 1) * 10, records, status=status)
        return [Outcome(h.name, name, status, error, 1) for h in hosts]

    collect.calls = calls
    return collect


def one_run(home, collect, unattended=True):
    base, _, identity, _ = home
    inventory = load_inventory()
    return schedule.run(
        base, load_config(base), list(inventory.hosts), identity, inventory,
        unattended=unattended, collect=collect, say=lambda line: None,
    )  # fmt: skip


def recorder(tmp_path) -> tuple[str, Path]:
    """A notify command that keeps what it was given."""
    out = tmp_path / "told.txt"
    script = tmp_path / "tell.py"
    script.write_text("import sys\nopen(sys.argv[1], 'w').write(sys.stdin.read())\n")
    return shlex.join([sys.executable, str(script), str(out)]), out


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
    assert text.startswith("Compromise Checker: 1 host(s) need a look\n")
    assert f"Report: {result.report}" in text
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


def test_a_host_that_couldnt_be_collected_is_told(fleet):
    result = one_run(fleet, collector(fleet, ROOTED, status="refused", error="no route"))
    assert result.alerting == ["web01: not collected (no route)"]
    assert result.report is None and result.exit_status() == schedule.EXIT_FAILED


def test_an_unattended_run_never_prompts(fleet):
    collect = collector(fleet, CLEAN)
    one_run(fleet, collect)
    assert collect.calls[0]["password_provider"] is schedule.unattended_password
    with pytest.raises(RuntimeError, match="doesn't ask"):
        schedule.unattended_password(Host(name="a", address="192.0.2.1", user="u", sudo="password"))


def test_a_failing_notify_command_fails_the_run(fleet, tmp_path):
    base = fleet[0]
    change(base, "notify_command", f"{shlex.quote(sys.executable)} -c 'import sys; sys.exit(4)'")
    result = one_run(fleet, collector(fleet, CLEAN, status="refused", error="down"))
    assert result.notified == "it exited with status 4"
    assert result.exit_status() == schedule.EXIT_FAILED


def test_runs_take_turns(fleet):
    with schedule.run_lock(fleet[0]), pytest.raises(schedule.Busy):
        one_run(fleet, collector(fleet, CLEAN))


def test_an_empty_inventory_purges_nothing(home):
    base, store, _, config = home
    inventory = load_inventory()
    assert schedule._purge_expired(store, base, config, inventory, print) == [
        "nothing purged: the inventory is empty, and expiry keeps inventoried baselines"
    ]


# --- What counts as worse --------------------------------------------------------------------


def finding(check, band, entities=("account:x",), suppressed=None):
    return {"check": check, "band": band, "title": f"{check} title", "variant": None,
            "entities": list(entities), "suppressed_by": suppressed}  # fmt: skip


def analysis(band, *findings):
    return {"score": {"band": band, "probability": 0.5}, "findings": list(findings)}


def test_what_counts_as_worse():
    root = finding("account.uid0", "critical")
    before = analysis("High", root)
    assert schedule.alerts("h", before, analysis("High", root)) == []
    assert schedule.alerts("h", before, analysis("Critical", root)) == [
        "h: High to Critical (50.0%)"
    ]
    assert schedule.alerts("h", analysis("High"), analysis("Medium")) == []  # better isn't news
    other = finding("account.uid0", "critical", entities=("account:y",))
    assert schedule.alerts("h", before, analysis("High", root, other)) == [
        "h: new critical: account.uid0 title"
    ]
    # Suppressed, or below high: not news.
    quiet = [finding("net.listener", "medium"), finding("x.y", "high", suppressed="rule")]
    assert schedule.alerts("h", before, analysis("High", root, *quiet)) == []
    # A finding a rule hid last time, in effect now (its rule expired): news.
    hidden = analysis("High", root, finding("x.y", "high", suppressed="rule"))
    assert schedule.alerts("h", hidden, analysis("High", root, finding("x.y", "high"))) == [
        "h: new high: x.y title"
    ]


def test_host_text_in_a_title_is_shown_safely():
    odd = finding("web.shell", "high")
    odd["title"] = "evil" + chr(0x202E) + "txt"
    (line,) = schedule.alerts("h", None, analysis("Low", odd))
    assert chr(0x202E) not in line and "\\u202e" in line


def test_the_exit_status_is_the_worst_band_else_failure():
    low = schedule.HostResult("a", "complete", band="Low")
    high = schedule.HostResult("b", "complete", band="High")
    broken = schedule.HostResult("c", "refused", problem="not collected (x)")
    assert schedule.RunResult([low]).exit_status() == 0
    assert schedule.RunResult([low, high]).exit_status() == 11
    assert schedule.RunResult([low, broken]).exit_status() == 1
    assert schedule.RunResult([high, broken]).exit_status() == 11
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


def test_the_command_refuses_before_collecting(home, monkeypatch, capsys):
    with inventory_transaction() as hosts:
        hosts.add(Host(name="web01", address="192.0.2.1", user="u", auth="password"))

    def never(*args, **kwargs):
        raise AssertionError("collected")

    monkeypatch.setattr(schedule, "run", never)
    assert cli.main(["run", "--all", "--unattended"]) == schedule.EXIT_SETUP
    assert "an unattended run would stop at a prompt" in capsys.readouterr().err


def test_the_command_prints_and_exits_with_the_band(fleet, monkeypatch, capsys):
    monkeypatch.setattr("checker.collect.collect_hosts", collector(fleet, ROOTED))
    assert cli.main(["run", "--all", "--unattended"]) == 11
    out = capsys.readouterr().out
    assert "web01" in out and "High (67%)" in out and "Needs a look:" in out
    assert "No notify_command is set" in out


# --- The setting -----------------------------------------------------------------------------


def test_the_notify_command_setting(home):
    base = home[0]
    with pytest.raises(EvidenceError, match="can't be split"):
        change(base, "notify_command", "mail -s 'oops")
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
    assert f'ExecStart="{sys.executable}" "-m" "checker" "run" "--all" "--unattended"' in service
    assert "SuccessExitStatus=10 11 12" in service
    assert "OnCalendar=*-*-* 03:05:00" in timer and "Persistent=true" in timer


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


def test_install_and_remove(fleet, tmp_path, monkeypatch, capsys):
    ran = []

    class Done:
        returncode, stdout, stderr = 0, "Linger=no\n", ""

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
