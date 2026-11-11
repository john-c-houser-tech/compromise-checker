"""The demo fleet's planning: its tags and end date, the commands it sends, and what `down`
deletes (the servers are only in the real run)."""

import importlib.util
import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace

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

    nodes = [
        node("cc-demo-abc123-checker", [demo.TAG, demo.until_tag(TODAY)], 1),
        node("cc-test-abc123-ubuntu2404-1a2b", [proof.TAG], 2),
    ]
    api = proof.Linode("token")
    api.call = lambda method, path, body=None: {"data": nodes}
    assert [n["id"] for n in api.tagged()] == [2]  # what the proofs' sweeps delete from
    demo_api = demo.Api("token")
    demo_api.call = api.call
    assert [n["id"] for n in demo_api.demo_tagged()] == [1]
    assert demo_api.find_demo("cc-demo-abc123-checker")["id"] == 1
    assert demo_api.find_demo("cc-test-abc123-ubuntu2404-1a2b") is None


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


def test_the_behaviours_go_in_on_standard_input(monkeypatch, tmp_path):
    """Not as `bash -c <script>`: the script's pgrep checks would find its own shell."""
    calls = []

    class Fake:
        known = tmp_path / "known"
        via = None

        def run(self, command, timeout=900, input=None):
            calls.append((command, input))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    class Used:
        def __init__(self, *a, **k):
            pass

        def run(self, command, timeout=900, input=None):
            calls.append((command, input))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        def close(self):
            pass

    monkeypatch.setattr(
        demo, "keypair", lambda folder, name: (tmp_path / name, f"ssh-ed25519 {name}")
    )
    monkeypatch.setattr(demo, "Through", Used)
    server = demo.Server("shop-web-1", "attacked", "ubuntu24.04", "web", 1, "l", "192.0.2.5")
    demo.behave(Fake(), server)
    command, script = calls[0]
    assert command == "bash -s"
    assert "dev/tcp/127.0.0.1/4444" in script


class Ran:
    """A server that answers each command from a list of (returncode, stdout, stderr)."""

    address = "192.0.2.1"

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def run(self, command, timeout=900, input=None):
        self.calls.append((command, input))
        code, out, err = self.answers.pop(0)
        return SimpleNamespace(returncode=code, stdout=out, stderr=err)

    def out(self, command):
        return self.run(command).stdout.strip()


def test_a_failed_login_as_the_new_account_stops_the_run(monkeypatch, tmp_path):
    class Refused:
        def __init__(self, *a, **k):
            pass

        def run(self, command, timeout=900, input=None):
            return SimpleNamespace(returncode=255, stdout="", stderr="Permission denied")

        def close(self):
            pass

    monkeypatch.setattr(demo, "keypair", lambda folder, name: (tmp_path / name, "ssh-ed25519 K"))
    monkeypatch.setattr(demo, "Through", Refused)
    server = demo.Server("db-1", "small", "rocky9", "database", 1, "l", "192.0.2.5")
    fake = Ran((0, "", ""))
    fake.known, fake.via = tmp_path / "known", None
    with pytest.raises(demo.DemoError, match="login failed"):
        demo.behave(fake, server)
    lost = Ran((255, "", "connection closed"))
    with pytest.raises(demo.DemoError, match="didn't run"):
        demo.behave(lost, server)


def test_the_planted_keys_are_not_kept(monkeypatch, tmp_path):
    made = []

    def keypair(folder, name):
        made.append(folder)
        return folder / name, "ssh-ed25519 K"

    monkeypatch.setattr(demo, "keypair", keypair)
    server = demo.Server("mail-1", "clean", "ubuntu24.04", "mail", 1, "l", "192.0.2.5")
    demo.behave(Ran(), server)
    assert made and not any(folder.exists() for folder in made)


RUN_OUTPUT = """\
shop-web-1           complete     Critical (100.0%)
db-1                 complete     Low (5.8%)
mail-1               failed       -
old-box              empty        -
"""


def test_a_check_counts_only_if_every_fleet_server_was_judged(capsys):
    assert demo.unjudged(RUN_OUTPUT, ["shop-web-1", "db-1"]) == []
    assert demo.unjudged(RUN_OUTPUT, ["shop-web-1", "mail-1", "app-1"]) == ["mail-1", "app-1"]
    demo.check_all(Ran((1, RUN_OUTPUT, "checker: old-box: not collected")), "first", ["db-1"])
    with pytest.raises(demo.DemoError, match="no result for mail-1"):
        demo.check_all(Ran((1, RUN_OUTPUT, "")), "first", ["db-1", "mail-1"])
    with pytest.raises(demo.DemoError, match="no result for db-1"):  # busy, set-up, crashed
        demo.check_all(Ran((3, "", "checker: another run holds the lock")), "second", ["db-1"])


def test_the_proof_fails_for_what_it_couldnt_look_at():
    def proof_of(checker_files, evidence=(0, "LOOKED 9\n", ""), **fleet):
        checker = Ran((0, "203.0.113.9 51234 22\n", ""), checker_files, evidence)
        return demo.never_seen_from_here(checker, fleet), checker, fleet

    found, checker, fleet = proof_of((1, "", ""), a=Ran((1, "0\n", "")))
    assert found == []
    command, sent = fleet["a"].calls[0]
    assert sent == "203.0.113.9\n" and "203.0.113.9" not in command  # never on a command line
    assert "203.0.113.9" not in checker.calls[1][0]
    assert "wtmp" in command and "lastlog" in command

    found, _, _ = proof_of((1, "", ""), a=Ran((0, "3\n", "")), b=Ran((255, "", "no route")))
    assert found == [
        "a: its logs name this machine 3 times",
        "b: its logs couldn't be looked at (no route)",
    ]
    found, _, _ = proof_of((0, "/var/lib/x/log\n", ""), a=Ran((1, "0\n", "")))
    assert found == ["the checker's own files: /var/lib/x/log"]
    found, _, _ = proof_of((2, "", "grep: denied"), a=Ran((1, "0\n", "")))
    assert found == ["the checker's files couldn't be looked at (grep: denied)"]
    assert "couldn't be read" in demo.never_seen_from_here(Ran((0, "\n", "")), {})[0]

    one = {"a": Ran((1, "0\n", ""))}
    found, checker, _ = proof_of((1, "", ""), (0, "HIT /e/a/b.age\nLOOKED 2\n", ""), **one)
    assert found == ["the evidence names this machine: /e/a/b.age"]
    command, script = checker.calls[2]
    assert "203.0.113.9" not in command and 'b"203.0.113.9"' in script
    assert command.startswith("runuser -u compromise-checker -- /opt/compromise-checker/current")
    for answer in ((1, "", "no evidence key is kept here"), (0, "", ""), (0, "LOOKED 1\n", "")):
        one = {"a": Ran((1, "0\n", ""))}
        found, _, _ = proof_of((1, "", ""), answer, **one)
        assert len(found) == 1 and ("couldn't be looked at" in found[0] or "only 1" in found[0])


def test_the_evidence_is_opened_and_read_as_the_checker_reads_it(tmp_path):
    """The script itself, on a real encrypted collection: text, bytes in base64, and an address
    split across two chunks are all found; a clean collection isn't."""
    import base64
    import gzip
    import subprocess

    import pyrage
    from pyrage import x25519

    identity = x25519.Identity.generate()
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "id.txt").write_text(f"# made now\n{identity}\n")
    (tmp_path / "config.yaml").write_text(f"identity_file: {tmp_path}/keys/id.txt\n")

    def chunk(data, seq=0, encoding="utf-8"):
        return {"type": "chunk", "source_id": 1, "seq": seq, "encoding": encoding, "data": data}

    def stored(host, *records):
        lines = b"".join(json.dumps(r).encode() + b"\n" for r in records)
        (tmp_path / "evidence" / host).mkdir(parents=True)
        (tmp_path / "evidence" / host / "b.age").write_bytes(
            pyrage.encrypt(gzip.compress(lines), [identity.to_public()])
        )

    stored("clean", chunk("Accepted publickey for scanner from 198.51.100.7 port 4"))
    stored("text", chunk("Accepted publickey for root from 203.0.113.9 port 51234"))
    stored("bytes", chunk(base64.b64encode(b"\x00\x01 203.0.113.9 \xff").decode(), 0, "base64"))
    stored("split", chunk("from 203.0."), chunk("113.9 port", 1))
    stored("named", {"type": "source_start", "source_id": 1, "name": "/home/203.0.113.9"})
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-", str(tmp_path)],
        input=demo._IN_EVIDENCE.replace("{needle}", "203.0.113.9"),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    hit = sorted(Path(line[4:]).parent.name for line in done.stdout.splitlines()[:-1])
    assert hit == ["bytes", "named", "split", "text"]
    assert done.stdout.splitlines()[-1] == "LOOKED 5"


def test_a_fleet_server_cant_be_logged_in_to_from_here(tmp_path):
    import install_proof as install

    checker = install.Node("192.0.2.1", tmp_path / "key", tmp_path / "known")
    through = demo.Through("192.0.2.7", tmp_path / "key", tmp_path / "known", checker)
    with pytest.raises(NotImplementedError):
        through.fresh_login("scanner")


class Making(FakeApi):
    """An API that makes servers too; `lose` names one whose first answer never arrives."""

    def __init__(self, lose=None, fail=None):
        super().__init__()
        self.lose, self.fail, self.asked = lose, fail, []

    def find_demo(self, label):
        return next((n for n in self.demo_tagged() if n["label"] == label), None)

    def create(self, label, image, region, public_key, tags=None):
        self.asked.append(label)
        if self.fail and label.endswith(self.fail):
            raise RuntimeError("Linode API POST /linode/instances: 500 no")
        made = node(label, tags, 100 + len(self.nodes)) | {"ipv4": [f"192.0.2.{len(self.nodes)}"]}
        self.nodes.append(made)
        if self.lose and label.endswith(self.lose):
            self.lose = None
            raise TimeoutError("the answer was lost")
        return made


def test_servers_are_made_with_the_demos_tags_and_a_lost_answer_isnt_made_twice(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    api = Making(lose="db-1")
    st = demo.State("abc123", "2026-11-10T12:00:00+00:00", "2026-11-11", [])
    demo.make_servers(api, tmp_path, st, "ssh-ed25519 K", "us-sea")
    assert len(api.nodes) == 6 == len(st.servers)
    assert all(n["tags"] == [demo.TAG, "cc-demo-until-20261111"] for n in api.nodes)
    assert api.asked.count("cc-demo-abc123-db-1") == 1  # found by its label, not made again
    assert len(demo.load_state(tmp_path).servers) == 6


def test_a_failed_up_deletes_what_it_made_and_its_own_files(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    monkeypatch.setattr(demo, "keypair", lambda folder, name: (folder / name, "ssh-ed25519 K"))
    folder = tmp_path / "demo"
    api = Making(fail="app-1")
    with pytest.raises(RuntimeError):
        demo.up(api, folder, "us-sea", TODAY)
    assert api.nodes == [] and len(api.deleted) == 5  # the five that were made
    assert not folder.exists()
    assert "6 servers, about 4.5 cents an hour" in capsys.readouterr().out


def test_a_failed_up_says_so_when_it_couldnt_delete(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    monkeypatch.setattr(demo, "keypair", lambda folder, name: (folder / name, "ssh-ed25519 K"))
    api = Making(fail="app-1")
    api.refuse = set(range(100, 110))
    with pytest.raises(RuntimeError):
        demo.up(api, tmp_path / "demo", "us-sea", TODAY)
    assert "SERVERS MAY STILL BE UP" in capsys.readouterr().err
    assert demo.load_state(tmp_path / "demo") is not None  # kept, so `down` can try again


def test_up_takes_only_a_new_or_empty_folder_and_one_up_at_a_time(tmp_path):
    (tmp_path / "notes.txt").write_text("mine")
    api = FakeApi()
    with pytest.raises(demo.DemoError, match="isn't empty"):
        demo.up(api, tmp_path, "us-sea", TODAY)
    assert (tmp_path / "notes.txt").exists()
    fresh = tmp_path / "fresh"
    demo.claim(fresh)
    with pytest.raises(demo.DemoError, match="isn't empty"):
        demo.claim(fresh)
    with pytest.raises(demo.DemoError, match="`down` first"):  # the claim reads as a state
        demo.up(api, fresh, "us-sea", TODAY)


def test_down_removes_only_the_demos_own_files(tmp_path, capsys):
    demo.save_state(tmp_path, state(1))
    for name in ("key", "key.pub", "known_hosts", "m-abc", "notes.txt"):
        (tmp_path / name).write_text("x")
    assert demo.down(FakeApi(), tmp_path) == 0
    assert [p.name for p in tmp_path.iterdir()] == ["notes.txt"]
    assert "aren't the demo's" in capsys.readouterr().err
    other = tmp_path / "other"
    other.mkdir()
    (other / "thesis.txt").write_text("x")
    assert demo.down(FakeApi(), other) == 0  # a folder that was never the demo's
    assert (other / "thesis.txt").exists()


def test_down_deletes_only_what_linode_lists_as_the_demos(tmp_path):
    tags = [demo.TAG, demo.until_tag(TODAY)]
    api = FakeApi([node("cc-demo-abc123-s1", tags, 1), node("web-1", ["prod"], 2)])
    demo.save_state(tmp_path, state(1, 2))  # a damaged state naming someone else's server
    assert demo.down(api, tmp_path) == 0
    assert api.deleted == [1] and [n["id"] for n in api.nodes] == [2]


def test_down_says_so_and_keeps_the_state_when_the_servers_cant_be_listed(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    api = FakeApi([node("cc-demo-abc123-s1", [demo.TAG], 1)])
    api.demo_tagged = lambda: (_ for _ in ()).throw(TimeoutError("timed out"))
    demo.save_state(tmp_path, state(1))
    assert demo.down(api, tmp_path) == 1
    assert api.deleted == [] and demo.load_state(tmp_path) is not None
    assert "Nothing was deleted: run `down` again" in capsys.readouterr().err


def test_a_state_that_cant_be_read_doesnt_stop_down_or_status(tmp_path, capsys):
    tags = [demo.TAG, demo.until_tag(TODAY)]
    api = FakeApi([node("cc-demo-abc123-s1", tags, 1)])
    (tmp_path / "state.json").write_text("{ not json")
    with pytest.raises(demo.Unreadable):
        demo.load_state(tmp_path)
    assert demo.status(api, tmp_path, datetime(2026, 11, 10, 14, tzinfo=UTC)) == 1
    assert "cc-demo-abc123-s1 exists" in capsys.readouterr().out
    assert demo.down(api, tmp_path) == 0
    assert api.deleted == [1] and not tmp_path.exists()


def test_a_state_with_a_field_from_another_version_still_reads(tmp_path):
    demo.save_state(tmp_path, state(1, 2))
    data = json.loads((tmp_path / "state.json").read_text())
    data["days"] = 7
    data["servers"][0]["timer"] = "daily"
    (tmp_path / "state.json").write_text(json.dumps(data))
    assert demo.load_state(tmp_path) == state(1, 2)


def test_status_says_overdue_and_names_servers_the_state_doesnt(tmp_path, capsys):
    tags = [demo.TAG, demo.until_tag(TODAY)]
    api = FakeApi([node("cc-demo-abc123-s1", tags, 1), node("cc-demo-zzz999-s1", tags, 8)])
    demo.save_state(tmp_path, state(1))
    assert demo.status(api, tmp_path, datetime(2026, 11, 11, 23, tzinfo=UTC)) == 1  # last day
    out = capsys.readouterr().out
    assert "Not in the state: cc-demo-zzz999-s1" in out and "OVERDUE" not in out
    api.nodes.pop()
    assert demo.status(api, tmp_path, datetime(2026, 11, 11, 23, tzinfo=UTC)) == 0
    assert demo.status(api, tmp_path, datetime(2026, 11, 12, 0, 5, tzinfo=UTC)) == 1
    assert "OVERDUE: its end date was 2026-11-11" in capsys.readouterr().out
