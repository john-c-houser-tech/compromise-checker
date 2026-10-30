"""The test suite's own guards (conftest.py): no test can start a password
manager or read the OS keyring, which would put a real prompt in front of
whoever is at the machine. Probed with harmless commands only."""

import pytest

import checker.advisor.keys as keys


@pytest.mark.parametrize(
    "args",
    [
        ["op", "--version"],
        ["/usr/bin/env", "op", "--version"],
        ["sh", "-c", "op --version"],
        ["sh", "-c", "true; rbw --version"],
        "op --version",
    ],
)
def test_a_password_manager_is_refused_however_it_is_wrapped(args):
    with pytest.raises(RuntimeError, match="key command"):
        keys.subprocess.run(args)


def test_other_commands_still_run():
    assert keys.subprocess.run(["true"]).returncode == 0


def test_the_keyring_is_refused():
    keyring = pytest.importorskip("keyring")
    with pytest.raises(RuntimeError, match="keyring"):
        keyring.get_password("compromise-checker", "advisor-api-key")
