"""The root service that installs a release (installation plan I.6): what it does with a folder
the tool's account left, with venv, pip and systemctl stood in for, since it can't run as root
here."""

import json
import os
import subprocess
from pathlib import Path

import pytest
from test_pack_trust import Key
from test_updates import KEY, _release

from checker import releases, update_service


@pytest.fixture
def trusted(monkeypatch):
    monkeypatch.setattr(releases, "RELEASE_KEYS", (KEY.line,))


class Machine:
    """A pretend /opt and the account's updates folder, and a record of every command run."""

    def __init__(self, tmp_path: Path, monkeypatch, answers_after: int = 0, fail=()):
        self.program = tmp_path / "opt"
        self.updates = tmp_path / "data" / "updates"
        self.updates.mkdir(parents=True)
        self.commands: list[list[str]] = []
        self.restarts = 0
        self.fail = set(fail)
        self.answers_after = answers_after
        current = self.program / "versions" / "0.1.0"
        _release(current, "0.1.0")
        for name in (releases.MANIFEST, releases.SIGNATURE):
            (current / name).write_bytes((current / name).read_bytes())
        (current / "bin").mkdir()
        (self.program / "current").symlink_to(current)
        self.status_script = self.program / "machine_status.py"
        self.status_script.write_text("# old status script\n")
        monkeypatch.setattr(update_service, "STATUS_SCRIPT", self.status_script)
        monkeypatch.setattr(update_service, "PROGRAM", self.program)
        monkeypatch.setattr(update_service, "ANSWER_SECONDS", 0.2)
        monkeypatch.setattr(subprocess, "run", self.run)
        monkeypatch.setattr(update_service, "answers", self.answers)
        monkeypatch.setattr(update_service.time, "sleep", lambda seconds: None)

    def run(self, command, **kwargs):
        self.commands.append(list(command))
        words = " ".join(command)
        if "-m venv" in words:
            target = Path(command[-1])
            (target / "bin").mkdir(parents=True)
            (target / "bin" / "python").write_text("#!python\n")
            purelib = target / "lib" / "python3.12" / "site-packages"
            (purelib / "checker").mkdir(parents=True)
            (purelib / "checker" / "machine_status.py").write_text(f"# status of {target.name}\n")
            return subprocess.CompletedProcess(command, 1 if "venv" in self.fail else 0, "", "")
        if "pip" in words and "--find-links" in words:
            code = 1 if "deps" in self.fail else 0
            return subprocess.CompletedProcess(command, code, "", "hashes don't match" * code)
        if "pip" in words:
            return subprocess.CompletedProcess(command, 1 if "wheel" in self.fail else 0, "", "")
        if "sysconfig" in words:
            python = Path(command[0])
            purelib = python.parent.parent / "lib" / "python3.12" / "site-packages"
            return subprocess.CompletedProcess(command, 0, f"{purelib}\n", "")
        if list(command[:2]) == ["systemctl", "restart"]:
            self.restarts += 1
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected command {command}")

    def answers(self, port=8088, seconds=0):
        return self.restarts >= self.answers_after

    def offer(self, version: str, wheels=(("dep-1.0-py3-none-any.whl", b"dep"),), **flags):
        source = self.updates / "incoming" / version
        _release(source, version, **flags)
        (source / "wheels").mkdir()
        for name, content in wheels:
            (source / "wheels" / name).write_bytes(content)
        (self.updates / "request").write_text(f"{version}\n")
        return source

    def current(self) -> str:
        return Path(os.readlink(self.program / "current")).name

    def outcome(self) -> dict:
        return json.loads((self.updates / "outcome.json").read_text())


def test_a_newer_signed_release_is_installed_beside_the_old_and_switched_to(
    tmp_path, monkeypatch, trusted
):
    machine = Machine(tmp_path, monkeypatch, answers_after=1)
    machine.offer("0.2.0")
    assert update_service.main([str(machine.updates)]) == 0
    assert machine.current() == "0.2.0"
    assert machine.outcome()["outcome"] == "installed"
    assert machine.outcome()["from"] == "0.1.0"
    assert (machine.program / "versions" / "0.1.0").is_dir(), "the previous version is kept"
    new = machine.program / "versions" / "0.2.0"
    assert (new / releases.MANIFEST).exists() and (new / releases.SIGNATURE).exists()
    assert machine.status_script.read_text() == "# status of 0.2.0\n"
    assert not (machine.updates / "request").exists()
    assert not (machine.updates / "incoming" / "0.2.0").exists()
    assert not any((machine.program / "staged").iterdir()), "root's copy is cleared away"
    pip_installs = [c for c in machine.commands if "pip" in c and "install" in c]
    assert all("--no-index" in c for c in pip_installs), "root never fetches"
    assert any("--require-hashes" in c and "--find-links" in c for c in pip_installs)
    assert machine.restarts == 1
    assert (machine.updates / "outcome.json").stat().st_mode & 0o777 == 0o644


def test_a_version_that_does_not_answer_is_rolled_back(tmp_path, monkeypatch, trusted):
    machine = Machine(tmp_path, monkeypatch, answers_after=99)
    machine.offer("0.2.0")
    assert update_service.main([str(machine.updates)]) == 1
    assert machine.current() == "0.1.0"
    outcome = machine.outcome()
    assert outcome["outcome"] == "rolled back" and "didn't answer" in outcome["words"]
    assert not (machine.program / "versions" / "0.2.0").exists()
    assert machine.status_script.read_text() == "# old status script\n"
    assert machine.restarts == 2, "the new one, then the old one again"


def test_a_build_that_fails_leaves_the_old_version_running(tmp_path, monkeypatch, trusted):
    machine = Machine(tmp_path, monkeypatch, answers_after=1, fail={"deps"})
    machine.offer("0.2.0")
    assert update_service.main([str(machine.updates)]) == 1
    assert machine.current() == "0.1.0"
    assert machine.outcome()["outcome"] == "rolled back"
    assert "hashes don't match" in machine.outcome()["words"]
    assert not (machine.program / "versions" / "0.2.0").exists()


@pytest.mark.parametrize("version", ["0.1.0", "0.0.9"])
def test_nothing_not_newer_is_installed(tmp_path, monkeypatch, trusted, version):
    machine = Machine(tmp_path, monkeypatch, answers_after=1)
    machine.offer(version)
    assert update_service.main([str(machine.updates)]) == 1
    assert machine.current() == "0.1.0"
    assert machine.outcome()["outcome"] == "refused"
    assert "isn't newer" in machine.outcome()["words"]
    assert machine.restarts == 0
    assert (machine.program / "versions" / version).exists() == (version == "0.1.0")


def test_a_release_signed_by_someone_else_or_changed_is_refused(tmp_path, monkeypatch, trusted):
    machine = Machine(tmp_path, monkeypatch, answers_after=1)
    source = machine.offer("0.2.0")
    (source / releases.REQUIREMENTS).write_bytes(b"evil==1 --hash=sha256:0\n")
    assert update_service.main([str(machine.updates)]) == 1
    assert machine.outcome()["outcome"] == "refused"
    assert machine.current() == "0.1.0" and machine.restarts == 0
    assert not (machine.updates / "incoming").exists(), "what was refused is gone"
    source = machine.offer("0.2.0")
    data = (source / releases.MANIFEST).read_bytes()
    (source / releases.SIGNATURE).write_bytes(Key().sign(data))
    assert update_service.main([str(machine.updates)]) == 1
    assert machine.outcome()["outcome"] == "refused" and machine.current() == "0.1.0"


def test_the_request_file_is_never_read_and_nothing_waiting_is_said(tmp_path, monkeypatch, trusted):
    machine = Machine(tmp_path, monkeypatch, answers_after=1)
    (machine.updates / "request").write_text("/etc/shadow\n")
    assert update_service.main([str(machine.updates)]) == 1
    assert machine.outcome()["outcome"] == "failed"
    assert "nothing is waiting" in machine.outcome()["words"]
    assert machine.restarts == 0 and not machine.commands
    # Two folders: the service won't choose.
    machine.offer("0.2.0")
    machine.offer("0.3.0")
    assert update_service.main([str(machine.updates)]) == 1
    assert "more than one" in machine.outcome()["words"]
    # No request at all: nothing happens, and the outcome says so without touching the folder.
    assert update_service.main([str(machine.updates)]) == 0
    assert machine.outcome()["outcome"] == "nothing"


def test_only_plain_wheel_files_are_taken_from_the_account_s_folder(tmp_path, monkeypatch, trusted):
    machine = Machine(tmp_path, monkeypatch, answers_after=1)
    source = machine.offer("0.2.0")
    (source / "wheels" / "planted.txt").write_text("not a wheel")
    (source / "wheels" / "link-1.0-py3-none-any.whl").symlink_to("/etc/hostname")
    staged = machine.program / "staged" / "0.2.0"
    copied = []
    real_build = update_service.build

    def build(staged_folder, version, program):
        copied.extend(sorted(p.name for p in (staged_folder / "wheels").iterdir()))
        return real_build(staged_folder, version, program)

    monkeypatch.setattr(update_service, "build", build)
    assert update_service.main([str(machine.updates)]) == 0
    assert copied == ["dep-1.0-py3-none-any.whl"]
    assert not staged.exists()


def test_older_versions_are_removed_but_the_previous_kept(tmp_path, monkeypatch, trusted):
    machine = Machine(tmp_path, monkeypatch, answers_after=1)
    (machine.program / "versions" / "0.0.1").mkdir()
    machine.offer("0.2.0")
    assert update_service.main([str(machine.updates)]) == 0
    kept = sorted(p.name for p in (machine.program / "versions").iterdir())
    assert kept == ["0.1.0", "0.2.0"]


def test_the_running_version_comes_from_the_kept_manifest_or_the_link(tmp_path, trusted):
    program = tmp_path / "opt"
    with pytest.raises(update_service.Failed):
        update_service.running_version(program)
    (program / "versions" / "0.3.0").mkdir(parents=True)
    (program / "current").symlink_to(program / "versions" / "0.3.0")
    assert update_service.running_version(program) == "0.3.0"
    _release(program / "versions" / "0.3.0", "0.4.0")  # the manifest wins over the name
    assert update_service.running_version(program) == "0.4.0"
