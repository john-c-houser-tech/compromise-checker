"""What the page says about the machine the tool runs on (installation plan, I.4)."""

import json
import subprocess

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
    for code, meaning in ((0, False), (1, True), (2, None)):
        _commands(monkeypatch, {("/usr/bin/dnf", "-C", "-q", "needs-restarting", "-r"): (code, "")})
        assert machine_status.restart_needed() is meaning


def test_what_is_written_is_read_back(tmp_path):
    path = tmp_path / "status" / "machine.json"
    machine_status.write(path, {"checked": "now", "ssh_passwords": True, "restart_needed": None})
    assert path.stat().st_mode & 0o777 == 0o644
    assert machine_status.read(path) == {"ssh_passwords": True}
    assert machine_status.notices(path) == ["ssh_passwords"]
    assert list(path.parent.iterdir()) == [path]


def test_anything_odd_is_as_good_as_not_known(tmp_path):
    path = tmp_path / "machine.json"
    assert machine_status.notices(path) == []
    for text in ("not json", "[true]", json.dumps({"ssh_passwords": "yes", "restart_needed": 1})):
        path.write_text(text)
        assert machine_status.notices(path) == []


def test_the_service_writes_where_it_is_told(monkeypatch, tmp_path):
    monkeypatch.setattr(
        machine_status, "collect", lambda: {"ssh_passwords": False, "restart_needed": True}
    )
    path = tmp_path / "machine.json"
    assert machine_status.main([str(path)]) == 0
    assert machine_status.notices(path) == ["restart_needed"]
