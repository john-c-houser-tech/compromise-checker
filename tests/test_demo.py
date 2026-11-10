"""The demo fleet's planning: its tags and end date, the commands it sends, and what `down`
deletes (the servers are only in the real run)."""

import importlib.util
import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

HERE = Path(__file__).parent / "integration"
sys.path.insert(0, str(HERE))  # it imports the proofs beside it
_spec = importlib.util.spec_from_file_location("demo", HERE / "demo.py")
demo = importlib.util.module_from_spec(_spec)
sys.modules["demo"] = demo
_spec.loader.exec_module(demo)

TODAY = date(2026, 11, 10)


def node(label, tags, linode_id=1, status="running"):
    return {"id": linode_id, "label": label, "tags": tags, "status": status}


class FakeApi:
    def __init__(self, nodes=(), refuse=()):
        self.nodes, self.refuse, self.deleted = list(nodes), set(refuse), []

    def demo_tagged(self):
        return demo.demo_nodes(self.nodes)

    def delete(self, linode_id):
        if linode_id in self.refuse:
            raise RuntimeError(f"Linode API DELETE /linode/instances/{linode_id}: 500 no")
        if not any(n["id"] == linode_id for n in self.nodes):
            raise RuntimeError(f"Linode API DELETE /linode/instances/{linode_id}: 404 gone")
        self.nodes = [n for n in self.nodes if n["id"] != linode_id]
        self.deleted.append(linode_id)


def state(*ids, run="abc123"):
    servers = [
        demo.Server(
            f"s{i}",
            "checker" if n == 0 else "clean",
            "ubuntu24.04",
            "",
            i,
            f"cc-demo-{run}-s{i}",
            f"192.0.2.{i}",
        )
        for n, i in enumerate(ids)
    ]
    return demo.State(run, "2026-11-10T12:00:00+00:00", "2026-11-11", servers, "192-0-2-1.sslip.io")


def test_the_end_date_is_a_tag_and_reads_back():
    tag = demo.until_tag(date(2026, 11, 17))
    assert tag == "cc-demo-until-20261117"
    assert demo.until_of([demo.TAG, tag]) == date(2026, 11, 17)
    assert demo.until_of([demo.TAG]) is None
    assert demo.until_of(["cc-demo-until-soon"]) is None


def test_the_proofs_sweep_cant_see_a_demo_server_and_the_demo_cant_see_a_proofs():
    import readonly_proof as proof

    assert demo.TAG != proof.TAG and not demo.LABEL_PREFIX.startswith(proof.LABEL_PREFIX)
    proofs = node("cc-test-abc-ubuntu2404-1f2e", [proof.TAG])
    ours = node("cc-demo-abc123-db-1", [demo.TAG, demo.until_tag(TODAY)], 2)
    someone = node("cc-demo-lookalike", ["web"], 3)  # the label alone isn't enough
    assert demo.demo_nodes([proofs, ours, someone]) == [ours]


def test_only_demo_servers_past_their_date_or_without_one_are_swept():
    today = demo.until_tag(TODAY)
    kept = node("cc-demo-a-x", [demo.TAG, today], 1)  # its last day: still up
    past = node("cc-demo-b-x", [demo.TAG, demo.until_tag(date(2026, 11, 9))], 2)
    undated = node("cc-demo-c-x", [demo.TAG], 3)
    other = node("prod-web", ["cc-demo-until-20200101"], 4)
    assert demo.past_their_date([kept, past, undated, other], TODAY) == [past, undated]


def test_the_install_line_is_the_pages_with_the_hash_checked_first():
    line = demo.install_line("0.1.2", "ab" * 32, "192-0-2-1.sslip.io")
    assert "/releases/download/v0.1.2/install.py" in line
    assert line.index("sha256sum -c -") < line.index("sudo python3 -I")
    assert f'echo "{"ab" * 32}  $d/install.py"' in line
    assert line.endswith("--web-address 192-0-2-1.sslip.io --test-certificates)")
    assert len(demo.INSTALLER_SHA256) == 64 and int(demo.INSTALLER_SHA256, 16)


def test_checker_commands_run_as_its_account_with_every_word_quoted():
    said = demo.as_checker("hosts", "add", "a b; rm -rf /")
    assert said.startswith("runuser -u compromise-checker -- env CHECKER_HOME=")
    assert said.endswith("/current/bin/checker hosts add 'a b; rm -rf /'")
    added = demo.hosts_add(demo.FLEET[0], "192.0.2.7")
    assert "--address 192.0.2.7 --user scanner --auth key --key" in added
    assert added.endswith("--sudo nopasswd --group web")
    assert "--group" not in demo.hosts_add(demo.Member("old-box", "", "", "clean"), "192.0.2.10")


def test_the_offered_fingerprint_is_read_from_what_trust_prints():
    printed = (
        "db-1 (192.0.2.9:22) offers a ssh-ed25519 host key:\n"
        "  SHA256:" + "A" * 43 + "\nCompare it with the server's own fingerprint\n"
    )
    assert demo.offered(printed) == "SHA256:" + "A" * 43
    assert demo.offered("checker: cannot connect") is None


def test_behaviours_carry_the_demo_names_and_the_planted_keys():
    attacked = demo.behaviour("attacked", "ssh-ed25519 ROOT", "ssh-ed25519 ADMIN")
    assert "ssh-ed25519 ROOT" in attacked and "ssh-ed25519 ADMIN" in attacked
    assert "{root_key}" not in attacked and "{admin_key}" not in attacked
    assert "ccadmin" not in attacked and "cc-proof" not in attacked and "deploy2" in attacked
    small = demo.behaviour("small", "r", "ssh-ed25519 ADMIN")
    assert "useradd -m -s /bin/bash deploy2" in small and "ssh-ed25519 ADMIN" in small
    assert demo.behaviour("clean", "r", "a") is None
    assert demo.behaviour("vulnerable", "r", "a") is None


def test_a_fleet_server_is_only_ever_reached_through_the_checkers(tmp_path):
    import install_proof as install

    key, known = tmp_path / "key", tmp_path / "known"
    checker = install.Node("192.0.2.1", key, known)
    through = demo.Through("192.0.2.7", key, known, checker)
    proxy = next(o for o in through.options if o.startswith("ProxyCommand="))
    assert proxy.endswith("-W %h:%p root@192.0.2.1")
    assert str(checker.master) in proxy  # over the connection already open to it
    assert through.master != checker.master and through.via is checker


def test_state_is_private_and_reads_back(tmp_path):
    folder = tmp_path / "demo"
    assert demo.load_state(folder) is None
    demo.save_state(folder, state(1, 2))
    assert (folder / "state.json").stat().st_mode & 0o777 == 0o600
    assert folder.stat().st_mode & 0o777 == 0o700
    back = demo.load_state(folder)
    assert back == state(1, 2)
    assert back.checker().id == 1 and [s.id for s in back.fleet()] == [2]


def test_up_refuses_while_a_demo_is_up(tmp_path):
    demo.save_state(tmp_path, state(1))
    api = FakeApi()
    with pytest.raises(demo.DemoError, match="up already"):
        demo.up(api, tmp_path, "us-sea", TODAY)
    assert api.deleted == []


def test_down_deletes_what_the_state_names_and_its_runs_strays(tmp_path, capsys):
    tags = [demo.TAG, demo.until_tag(TODAY)]
    api = FakeApi(
        [
            node("cc-demo-abc123-s1", tags, 1),
            node("cc-demo-abc123-lost", tags, 7),  # made, but its answer never arrived
            node("cc-demo-zzz999-s1", tags, 8),  # another run's
            node("cc-test-abc123-x", ["compromise-checker-test"], 9),  # a proof's
        ]
    )
    demo.save_state(tmp_path, state(1, 2))  # 2 is gone already
    assert demo.down(api, tmp_path) == 0
    assert sorted(api.deleted) == [1, 7]
    assert "was gone already" in capsys.readouterr().out
    assert not tmp_path.exists()


def test_down_keeps_the_state_when_a_delete_fails(tmp_path, capsys):
    tags = [demo.TAG, demo.until_tag(TODAY)]
    api = FakeApi([node("cc-demo-abc123-s1", tags, 1), node("cc-demo-abc123-s2", tags, 2)], [1])
    demo.save_state(tmp_path, state(1, 2))
    assert demo.down(api, tmp_path) == 1
    assert api.deleted == [2]  # the other still went
    assert demo.load_state(tmp_path) is not None
    assert "run `down` again" in capsys.readouterr().err


def test_down_with_no_state_deletes_every_demo_server(tmp_path):
    tags = [demo.TAG, demo.until_tag(TODAY)]
    api = FakeApi([node("cc-demo-old111-s1", tags, 5), node("web-1", ["prod"], 6)])
    assert demo.down(api, tmp_path / "none") == 0
    assert api.deleted == [5]


def test_status_says_cost_end_date_and_what_is_gone(tmp_path, capsys):
    api = FakeApi([node("cc-demo-abc123-s1", [demo.TAG], 1)])
    assert demo.status(api, tmp_path, datetime(2026, 11, 10, 14, tzinfo=UTC)) == 1
    assert "No demo is up." in capsys.readouterr().out
    demo.save_state(tmp_path, state(1, 2))
    assert demo.status(api, tmp_path, datetime(2026, 11, 10, 14, tzinfo=UTC)) == 0
    out = capsys.readouterr().out
    assert "Up for 2.0 hours, about $0.03 so far." in out and "Ends 2026-11-11" in out
    assert "running" in out and "GONE" in out
    assert json.loads((tmp_path / "state.json").read_text())["run"] == "abc123"
