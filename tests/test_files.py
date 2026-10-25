"""Concurrent `checker` commands must not lose each other's changes."""

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from checker.inventory import load_inventory

ADD = [sys.executable, "-m", "checker", "hosts", "add"]


def test_concurrent_host_adds_all_survive(tmp_path):
    env = dict(os.environ, CHECKER_HOME=str(tmp_path))

    def add(n):
        return subprocess.run(
            [*ADD, f"h{n}", "--address", f"192.0.2.{n}", "--user", "u"],
            env=env,
            capture_output=True,
            timeout=60,
        ).returncode

    with ThreadPoolExecutor(max_workers=12) as pool:
        assert list(pool.map(add, range(12))) == [0] * 12
    names = {host.name for host in load_inventory(tmp_path / "hosts.yaml").hosts}
    assert names == {f"h{n}" for n in range(12)}
    assert not list(tmp_path.glob("*.tmp")) and not list(tmp_path.glob(".*.tmp"))


TRUST = """
import sys, asyncssh
from pathlib import Path
from checker.inventory import Host
from checker.transport import HostKeyCheck, trust_host_key
key = asyncssh.generate_private_key("ssh-ed25519")
host = Host(name="h" + sys.argv[2], address="192.0.2." + sys.argv[2], user="u")
check = HostKeyCheck(key=key, fingerprint=key.get_fingerprint("sha256"), key_type="ssh-ed25519")
trust_host_key(host, check, Path(sys.argv[1]))
"""


def test_concurrent_trusts_all_survive(tmp_path):
    known = tmp_path / "known_hosts"

    def trust(n):
        return subprocess.run(
            [sys.executable, "-c", TRUST, str(known), str(n)], capture_output=True, timeout=60
        ).returncode

    with ThreadPoolExecutor(max_workers=12) as pool:
        assert list(pool.map(trust, range(12))) == [0] * 12
    entries = {line.split()[0] for line in known.read_text().splitlines()}
    assert entries == {f"192.0.2.{n}" for n in range(12)}


def test_duplicate_names_in_a_hand_edited_inventory_are_rejected(tmp_path):
    path = Path(tmp_path, "hosts.yaml")
    path.write_text(
        "hosts:\n- {name: web01, address: a, user: u}\n- {name: web01, address: b, user: u}\n"
    )
    with pytest.raises(ValidationError, match="more than once"):
        load_inventory(path)
