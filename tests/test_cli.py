import re
import subprocess
import sys
from importlib.resources import files

import asyncssh
import pytest

from checker import __version__, cli
from checker.cli import main
from checker.inventory import known_hosts_file, load_inventory
from checker.transport import HostKeyCheck


def test_no_arguments_prints_version(capsys):
    assert main([]) == 0
    assert capsys.readouterr().out.startswith(f"checker {__version__}")


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"checker {__version__}"


def test_runs_as_module():
    result = subprocess.run(
        [sys.executable, "-m", "checker", "--version"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"checker {__version__}"


def test_collector_ships_with_package_and_matches_version():
    source = (files("checker") / "collector" / "collector.py").read_text()
    match = re.search(r'^COLLECTOR_VERSION = "([^"]+)"$', source, re.MULTILINE)
    assert match, "collector.py must define COLLECTOR_VERSION"
    assert match.group(1) == __version__


# --- hosts and trust ------------------------------------------------------------------


@pytest.fixture
def checker_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    return tmp_path


def add_web01(*extra):
    return main(["hosts", "add", "web01", "--address", "192.0.2.10", "--user", "scanner", *extra])


def test_hosts_add_list_remove(checker_home, capsys):
    assert add_web01("--group", "web") == 0
    assert (checker_home / "hosts.yaml").stat().st_mode & 0o777 == 0o600
    assert load_inventory().get("web01").group == "web"
    assert add_web01() == 2  # duplicate name
    assert main(["hosts", "list"]) == 0
    assert "scanner@192.0.2.10:22" in capsys.readouterr().out
    assert main(["hosts", "remove", "web01"]) == 0
    assert load_inventory().hosts == []
    assert main(["hosts", "remove", "web01"]) == 2


def test_hosts_add_rejects_bad_values(checker_home):
    assert main(["hosts", "add", "bad name", "--address", "a", "--user", "u"]) == 2
    assert add_web01("--python", "python3;id") == 2


def fake_fetch(key, known=()):
    async def fetch(host):
        return HostKeyCheck(
            key=key,
            fingerprint=key.get_fingerprint("sha256"),
            key_type=key.get_algorithm(),
            known_fingerprints=list(known),
        )

    return fetch


def trust(monkeypatch, check_key, answer="y", known=(), *flags):
    monkeypatch.setattr(cli, "fetch_host_key", fake_fetch(check_key, known))
    args = cli.build_parser().parse_args(["trust", "web01", *flags])
    return cli.cmd_trust(args, ask=lambda prompt: answer)


def test_trust_asks_then_records_the_key(checker_home, monkeypatch, capsys):
    add_web01()
    key = asyncssh.generate_private_key("ssh-ed25519")
    assert trust(monkeypatch, key, answer="n") == 1
    assert not known_hosts_file().exists()
    assert trust(monkeypatch, key, answer="y") == 0
    assert known_hosts_file().read_text().startswith("192.0.2.10 ssh-ed25519 ")
    assert key.get_fingerprint("sha256") in capsys.readouterr().out


def test_trust_with_expect(checker_home, monkeypatch):
    add_web01()
    key = asyncssh.generate_private_key("ssh-ed25519")
    assert trust(monkeypatch, key, "", (), "--expect", "SHA256:wrong") == 1
    assert trust(monkeypatch, key, "", (), "--expect", key.get_fingerprint("sha256")) == 0


def test_changed_key_needs_replace(checker_home, monkeypatch, capsys):
    add_web01()
    key = asyncssh.generate_private_key("ssh-ed25519")
    known = ["SHA256:previous"]
    assert trust(monkeypatch, key, "y", known) == 1
    assert "NOT the key trusted before" in capsys.readouterr().err
    assert trust(monkeypatch, key, "y", known, "--replace") == 0


def test_expect_is_checked_even_for_an_already_trusted_key(checker_home, monkeypatch):
    add_web01()
    key = asyncssh.generate_private_key("ssh-ed25519")
    known = [key.get_fingerprint("sha256")]
    assert trust(monkeypatch, key, "", known, "--expect", "SHA256:wrong") == 1
    assert trust(monkeypatch, key, "", known, "--expect", known[0]) == 0


def test_same_key_is_a_no_op(checker_home, monkeypatch, capsys):
    add_web01()
    key = asyncssh.generate_private_key("ssh-ed25519")
    assert trust(monkeypatch, key, "n", [key.get_fingerprint("sha256")]) == 0
    assert "already trusted" in capsys.readouterr().out
