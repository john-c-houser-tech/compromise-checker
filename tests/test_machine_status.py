"""What the page says about the machine the tool runs on (installation plan, I.4)."""

import json
import subprocess
from datetime import UTC, datetime

from checker import machine_status


def test_sshd_settings_are_read_the_way_sshd_writes_them():
    assert machine_status.passwords_from(
        "passwordauthentication yes\nkbdinteractiveauthentication no\n"
    )
    assert machine_status.passwords_from(
        "PasswordAuthentication no\nKbdInteractiveAuthentication yes\n"
    )
    assert not machine_status.passwords_from(
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPasswordAuthentication yes\n"
    )
    assert machine_status.passwords_from("port 22\n")  # nothing said is SSH's own default, yes


def _commands(monkeypatch, answers):
    def run(*command):
        for start, (code, out) in answers.items():
            if command[: len(start)] == start:
                return subprocess.CompletedProcess(list(command), code, out, "")
        return subprocess.CompletedProcess(list(command), 3, "inactive\n", "")

    monkeypatch.setattr(machine_status, "_run", run)


def test_no_ssh_running_means_no_notice(monkeypatch, tmp_path):
    _commands(monkeypatch, {})
    sshd = tmp_path / "sshd"
    sshd.write_text("")
    monkeypatch.setattr(machine_status.shutil, "which", lambda name, path=None: str(sshd))
    assert machine_status.ssh_passwords() is None


def test_ssh_running_with_passwords(monkeypatch, tmp_path):
    sshd = tmp_path / "sshd"
    sshd.write_text("")
    monkeypatch.setattr(machine_status.shutil, "which", lambda name, path=None: str(sshd))
    _commands(
        monkeypatch,
        {
            ("systemctl", "is-active", "ssh.socket"): (0, "active\n"),
            (str(sshd), "-T"): (0, "passwordauthentication yes\n"),
        },
    )
    assert machine_status.ssh_passwords() is True
    _commands(
        monkeypatch,
        {
            ("systemctl", "is-active", "sshd.service"): (0, "active\n"),
            (str(sshd), "-T"): (255, ""),
        },
    )
    assert machine_status.ssh_passwords() is None


def test_a_restart_is_needed(monkeypatch, tmp_path):
    note = tmp_path / "reboot-required"
    monkeypatch.setattr(machine_status, "REBOOT_REQUIRED", note)
    monkeypatch.setattr(machine_status.shutil, "which", lambda name, path=None: None)
    assert machine_status.restart_needed() is False
    note.write_text("*** System restart required ***\n")
    assert machine_status.restart_needed() is True
    note.unlink()
    monkeypatch.setattr(machine_status.shutil, "which", lambda name, path=None: "/usr/bin/dnf")
    required = (
        "Core libraries or services have been updated since boot-up:\n  * kernel\n\n"
        "Reboot is required to fully utilize these updates.\n"
    )
    fine = (
        "No core libraries or services have been updated since boot-up.\n"
        "Reboot should not be necessary.\n"
    )
    for code, said, meaning in (
        (0, fine, False),
        (1, required, True),
        (1, "Error: rpmdb open failed\n", None),
        (0, "", None),
        (2, "", None),
    ):
        _commands(
            monkeypatch, {("/usr/bin/dnf", "-C", "-q", "needs-restarting", "-r"): (code, said)}
        )
        assert machine_status.restart_needed() is meaning


def test_what_is_written_is_read_back(tmp_path):
    path = tmp_path / "status" / "machine.json"
    now = "2026-11-03T12:00:00+00:00"
    machine_status.write(path, {"checked": now, "ssh_passwords": True, "restart_needed": None})
    assert path.stat().st_mode & 0o777 == 0o644
    assert machine_status.read(path, datetime.fromisoformat(now)) == {"ssh_passwords": True}
    later = datetime.fromisoformat("2026-11-03T16:00:00+00:00")
    assert machine_status.read(path, later) == {"ssh_passwords": True, "stale": True}
    assert machine_status.notices(path)[0] == "ssh_passwords"
    assert list(path.parent.iterdir()) == [path]


def test_anything_odd_is_as_good_as_not_known(tmp_path):
    path = tmp_path / "machine.json"
    assert machine_status.notices(path) == []
    for text in ("not json", "[true]"):
        path.write_text(text)
        assert machine_status.notices(path) == []
    path.write_text(json.dumps({"ssh_passwords": "yes", "restart_needed": 1}))
    assert machine_status.notices(path) == ["stale"]  # nor does it say when it was written


def test_the_service_writes_where_it_is_told(monkeypatch, tmp_path):
    monkeypatch.setattr(
        machine_status,
        "collect",
        lambda: {
            "checked": datetime.now(UTC).isoformat(),
            "ssh_passwords": False,
            "restart_needed": True,
        },
    )
    path = tmp_path / "machine.json"
    assert machine_status.main([str(path)]) == 0
    assert machine_status.notices(path) == ["restart_needed"]


def test_the_install_route_is_read_from_what_the_installer_left(tmp_path):
    installed, web = tmp_path / "installed", tmp_path / "web-address.json"
    assert machine_status.install_route(installed, web) is None
    installed.write_text("0.1.0\n")
    assert machine_status.install_route(installed, web) == "local"
    web.write_text('{"name": "checker.example.org", "apache_before": false}\n')
    assert machine_status.install_route(installed, web) == "web"
    # The installer leaves a nameless marker when a web address was taken down and a firewall
    # opening couldn't be undone: that machine is used from itself.
    web.write_text('{"port_label": "added"}\n')
    assert machine_status.install_route(installed, web) == "local"
    for odd in ("not json", "[1]", '{"name": ""}', '{"name": 3}'):
        web.write_text(odd)
        assert machine_status.install_route(installed, web) in ("local", None)
    web.write_text('{"name": "checker.example.org"}\n')
    installed.unlink()  # a web address set up, but the installer never finished
    assert machine_status.install_route(installed, web) is None


def _web_db(path, accounts: int):
    import sqlite3

    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE auth_user (id INTEGER PRIMARY KEY, username TEXT)")
    for n in range(accounts):
        connection.execute("INSERT INTO auth_user (username) VALUES (?)", (f"person{n}",))
    connection.commit()
    connection.close()


def test_the_console_note_comes_off_once_the_first_account_exists(tmp_path, monkeypatch):
    issue = tmp_path / "issue"
    original = "Ubuntu 24.04 LTS \\n \\l\n\n"
    note = (
        f"{machine_status.NOTICE_START}\nOpen https://checker.example.org/s/abc to make the"
        f" first account.\n{machine_status.NOTICE_END}\n"
    )
    issue.write_text(note + original)
    refreshed = []
    monkeypatch.setattr(machine_status, "refresh_console_prompts", lambda: refreshed.append(True))
    issue.chmod(0o600)  # as the installer leaves it while the link is in it
    web_db = tmp_path / "web.db"
    assert machine_status.has_an_account(web_db) is None, "no file yet"
    assert not machine_status.clear_console_notice(issue, web_db)
    _web_db(web_db, 0)
    assert machine_status.has_an_account(web_db) is False
    assert not machine_status.clear_console_notice(issue, web_db)
    assert issue.read_text() == note + original
    _web_db(tmp_path / "with.db", 1)
    assert machine_status.has_an_account(tmp_path / "with.db") is True
    before = issue.stat().st_ino
    assert machine_status.clear_console_notice(issue, tmp_path / "with.db")
    assert issue.read_text() == original, "only the note goes"
    assert issue.stat().st_ino == before, "written in place: the unit opens that file alone"
    assert issue.stat().st_mode & 0o777 == 0o644, "ordinary again with the link gone"
    assert refreshed == [True]
    assert not machine_status.clear_console_notice(issue, tmp_path / "with.db"), "nothing left"
    (tmp_path / "odd.db").write_text("not a database")
    assert machine_status.has_an_account(tmp_path / "odd.db") is None


def test_without_notice_leaves_other_text_alone():
    assert machine_status.without_notice("plain\n") == "plain\n"
    text = f"a\n{machine_status.NOTICE_START}\nx\n{machine_status.NOTICE_END}\nb\n"
    assert machine_status.without_notice(text) == "a\nb\n"
    assert machine_status.without_notice(
        f"{machine_status.NOTICE_END}\n{machine_status.NOTICE_START}"
    ) == (f"{machine_status.NOTICE_END}\n{machine_status.NOTICE_START}")


def test_the_service_clears_the_note_when_run_as_the_unit_runs_it(monkeypatch, tmp_path):
    """The unit names the status file: that path, not an empty argument list, means the real
    machine."""
    cleared = []
    monkeypatch.setattr(machine_status, "collect", lambda: {"checked": "2026-11-05T00:00:00Z"})
    monkeypatch.setattr(machine_status, "clear_console_notice", lambda: cleared.append(True))
    monkeypatch.setattr(machine_status, "STATUS", tmp_path / "status" / "machine.json")
    assert machine_status.main([str(tmp_path / "status" / "machine.json")]) == 0
    assert cleared == [True]
    assert machine_status.main([str(tmp_path / "elsewhere.json")]) == 0
    assert cleared == [True], "a test's path: left alone"


def test_the_status_service_draws_an_idle_prompt_again_but_not_a_session(monkeypatch):
    calls = []

    def run(*command):
        calls.append(command)
        if command[:2] == ("systemctl", "show"):
            pid = {"serial-getty@ttyS0.service": "601", "getty@tty1.service": "602"}[command[-1]]
            return subprocess.CompletedProcess(list(command), 0, f"{pid}\n", "")
        return subprocess.CompletedProcess(list(command), 0, "", "")

    monkeypatch.setattr(machine_status, "_run", run)
    comm = {"/proc/601/comm": "agetty\n", "/proc/602/comm": "login\n"}
    monkeypatch.setattr(
        machine_status.Path, "read_text", lambda self, encoding=None: comm[str(self)]
    )
    assert machine_status.refresh_console_prompts() == ["serial-getty@ttyS0.service"]
    assert ("systemctl", "restart", "serial-getty@ttyS0.service") in calls
    assert all(c != ("systemctl", "restart", "getty@tty1.service") for c in calls)
