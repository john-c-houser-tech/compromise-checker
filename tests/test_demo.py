"""The demo fleet's planning: its tags and end date, the commands it sends, and what `down`
deletes (the servers are only in the real run)."""

import importlib.util
import json
import os
import re
import signal
import subprocess
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
    # `schedule install` finds the account's own systemd by this.
    assert " XDG_RUNTIME_DIR=/run/user/$(id -u compromise-checker) " in said
    added = demo.hosts_add(demo.FLEET[0], "192.0.2.7")
    assert "--address 192.0.2.7 --user scanner --auth key --key" in added
    assert added.endswith("--sudo nopasswd --group web")
    assert "--group" not in demo.hosts_add(demo.Member("old-box", "", ""), "192.0.2.10")


def test_the_offered_fingerprint_is_read_from_what_trust_prints():
    printed = (
        "db-1 (192.0.2.9:22) offers a ssh-ed25519 host key:\n"
        "  SHA256:" + "A" * 43 + "\nCompare it with the server's own fingerprint\n"
    )
    assert demo.offered(printed) == "SHA256:" + "A" * 43
    assert demo.offered("checker: cannot connect") is None


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
        return demo.never_seen_from_here(checker, fleet, collected=2), checker, fleet

    found, checker, fleet = proof_of((1, "", ""), a=Ran((1, "0\n", "")))
    assert found == []
    command, sent = fleet["a"].calls[0]
    assert sent == "203.0.113.9\n" and "203.0.113.9" not in command  # never on a command line
    assert "203.0.113.9" not in checker.calls[1][0]
    assert "wtmp" in command and "lastlog" in command
    assert "journalctl -a " in command and "exit 4" in command  # nothing readable isn't clean
    assert '-f "$f" /var/lib/compromise-checker;' in checker.calls[1][0]  # its whole home

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
    assert len(api.nodes) == 7 == len(st.servers)
    assert all(n["tags"] == [demo.TAG, "cc-demo-until-20261111"] for n in api.nodes)
    assert api.asked.count("cc-demo-abc123-db-1") == 1  # found by its label, not made again
    assert len(demo.load_state(tmp_path).servers) == 7


def test_a_failed_up_deletes_what_it_made_and_its_own_files(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    monkeypatch.setattr(demo, "keypair", lambda folder, name: (folder / name, "ssh-ed25519 K"))
    folder = tmp_path / "demo"
    api = Making(fail="staging-1")
    with pytest.raises(RuntimeError):
        demo.up(api, folder, "us-sea", TODAY)
    assert api.nodes == [] and len(api.deleted) == 6  # the six that were made
    assert not folder.exists()
    assert "7 servers, about 5.2 cents an hour" in capsys.readouterr().out


def test_a_failed_up_says_so_when_it_couldnt_delete(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    monkeypatch.setattr(demo, "keypair", lambda folder, name: (folder / name, "ssh-ed25519 K"))
    api = Making(fail="staging-1")
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
    data["weeks"] = 7
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


# --- the story (D.3) -----------------------------------------------------------------------

story = demo.story


def test_the_story_names_only_its_own_servers_and_shows_no_scaffolding():
    import readonly_proof as proof

    names = {m.name for m in story.FLEET}
    for step in story.STORY:
        assert step.where in names | {"admin"}, step
        assert bool(step.script) != bool(step.admin), step  # one or the other
        if step.admin and step.admin[0] in ("accept", "remove", "rule"):
            assert step.admin[1] in names
    assert max(story.CHECKED_DAYS) < max(s.day for s in story.STORY)  # day 5's note stays
    setup = story.renamed(proof.SETUP, story.SETUP_NAMES)
    whitelist = story.WHITELIST
    attack = next(s.script for s in story.STORY if s.says == "the break-in")
    for old, _ in story.SETUP_NAMES:
        assert old in proof.SETUP, old  # no entry left over from a setup that has changed
    for text in (setup, attack):
        lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        shown = "\n".join(lines).replace("proof setup:", "").replace("-k cc-w", "")
        assert not re.search(r"proof|cc[-_ ](?!web-exec)|ccadmin", shown, re.IGNORECASE), (
            re.findall(r".*(?:proof|cc[-_ ]|ccadmin).*", shown)
        )
    # the whitelist goes to the checker's server whole, comments and all
    assert not re.search(r"proof|cc[-_ ]|persistence modules", whitelist, re.IGNORECASE)
    assert (
        "account: webdev" in whitelist and "useradd --create-home --shell /bin/bash webdev" in setup
    )
    # what the container retry waits for is still what the renamed setup says
    assert 'echo "proof setup: Docker not started"' in setup
    assert "--name web-cache " in setup and "--name web-cache " in story.CONTAINER
    # the intruder's account isn't db-1's admin's
    assert "{root_key}" in attack and "{admin_key}" in attack
    assert f"useradd -m -s /bin/bash {story.INTRUDER}" in attack and "deploy2" not in attack
    assert "useradd -m -s /bin/bash deploy2" in story.ROUTINE_WORK
    # the rule the admin writes is for the job the story adds, on the server it adds it to
    job = next(s for s in story.STORY if s.script == story.BACKUP_JOB)
    rule = next(s for s in story.STORY if s.admin[:1] == ("rule",))
    assert rule.admin[1] == job.where and rule.day > job.day
    assert "path: /etc/cron.d/mail-backup}" in story.BACKUP_RULE
    assert "> /etc/cron.d/mail-backup" in story.BACKUP_JOB
    # a script that says nothing of its own failures is stopped by them
    for step in story.STORY:
        if step.script and "FAILED" not in step.script and "nohup" not in step.script:
            assert step.strict or step.script == story.BACKUP_JOB, step.says
    tidy = next(s.script for s in story.STORY if "removes the web shell" in s.says)
    assert "sys-shell.php" in attack and "sys-shell.php" in tidy
    assert "/etc/cron.d/sysupdate" in attack and "/etc/cron.d/sysupdate" in tidy


def test_the_demos_whitelist_and_the_admins_rule_are_ones_the_checker_takes(tmp_path):
    import readonly_proof as proof

    from checker import whitelist

    folder = tmp_path / "whitelist" / "hosts"
    folder.mkdir(parents=True)
    text = story.WHITELIST.replace("{checker}", "192.0.2.1")
    text += story.BACKUP_RULE.format(expires="2026-11-12")
    (folder / "mail-1.yaml").write_text(text)
    loaded = whitelist.load(tmp_path, "mail-1", "mail")
    ours = {
        placed.rule.id: placed.rule.match.model_dump(exclude_none=True) for placed in loaded.rules
    }
    assert "mail-backup-job" in ours
    # It explains what the proofs' own whitelist does, under the demo's names, and one thing
    # less: a root login from anywhere but the checker's server (the break-in's tunnel is one).
    (folder / "x.yaml").write_text(
        story.renamed(proof.PROOF_WHITELIST.read_text(), story.SETUP_NAMES)
    )
    theirs = {
        placed.rule.id.replace("proof-", "setup-").replace("proofuser", "webdev"): (
            placed.rule.match.model_dump(exclude_none=True)
        )
        for placed in whitelist.load(tmp_path, "x", "").rules
    }
    assert ours.pop("setup-root-login") == {
        **theirs.pop("setup-root-login"),
        "address": "192.0.2.1",
    }
    for rule_id, match in theirs.items():
        assert ours[rule_id] == match, rule_id


def test_ssh_is_closed_to_all_but_the_checker_before_a_server_is_added_or_weakened(tmp_path):
    checker = Ran(*[(0, "SHA256:" + "a" * 43 + "\n", "")] * 4)
    server = Ran(*[(0, "256 SHA256:" + "a" * 43 + " root@x (ED25519)\n", "")] * 5)
    server.wait = lambda seconds: None
    member = story.Member("shop-web-1", "web", "ubuntu24.04", old_php=True)
    made = demo.Server("shop-web-1", "fleet", "ubuntu24.04", "web", 1, "l", "192.0.2.5")
    demo.prepare_member(checker, server, made, member, "ssh-ed25519 SCANNER")
    setup, firewall, web, old_php, keys = server.calls
    assert 'from="192.0.2.1"' in setup[0] and "ssh-ed25519 SCANNER" in setup[0]
    assert "ufw allow from 192.0.2.1 to any port 22" in firewall[1]
    assert "ufw delete allow 22/tcp" in firewall[1] and 'address="192.0.2.1"' in firewall[1]
    # ...and it is what is on that is checked, not only that one open rule is gone
    for proved in ("Status: active", "Default: deny (incoming)", '$NF != "192.0.2.1"', "--state"):
        assert proved in firewall[1], proved
    assert "nginx" in web[0] and "php8.3" in old_php[0]
    added, asked, trusted, listed = checker.calls
    assert "hosts add shop-web-1" in added[0] and "--expect SHA256:" in trusted[0]
    assert "whitelist/hosts/shop-web-1.yaml" in listed[0] and "account: webdev" in listed[1]
    assert "account: root, address: 192.0.2.1}" in listed[1]


def test_a_container_that_did_not_start_is_tried_again_before_the_firewall(capsys):
    key = (0, "256 SHA256:" + "a" * 43 + " root@x (ED25519)\n", "")
    for second, expected in ((0, "started at the second try"), (1, "still not started:\nno space")):
        checker = Ran((0, "", ""), (0, "SHA256:" + "a" * 43 + "\n", ""), (0, "", ""), (0, "", ""))
        server = Ran(
            (0, "", "proof setup: Docker not started\n"), (second, "no space", ""), *[key] * 4
        )
        server.wait = lambda seconds: None
        member = story.Member("staging-1", "", "ubuntu24.04")
        made = demo.Server("staging-1", "fleet", "ubuntu24.04", "", 1, "l", "192.0.2.5")
        demo.prepare_member(checker, server, made, member, "ssh-ed25519 SCANNER")
        _, again, firewall = server.calls[:3]
        assert "docker run -d --name web-cache" in again[1] and "ufw delete" in firewall[1]
        assert expected in capsys.readouterr().out


class Node(Ran):
    """A fleet server in the story: answers yes to everything, and remembers it."""

    known, via, closed = Path("known"), None, False

    def __init__(self, address="192.0.2.5"):
        super().__init__()
        self.address = address

    def run(self, command, timeout=900, input=None):
        self.calls.append((command, input))
        out = "0\n" if "lastlog" in command else ""  # the proof's count of its log lines
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    def close(self):
        self.closed = True


class Checker(Node):
    """The checker's server: every check it runs judges whoever the test says still answers."""

    def __init__(self, answering):
        super().__init__("192.0.2.1")
        self.answering = answering
        self.fails: dict[str, int] = {}  # a part of a command, and how it ends
        self.retired, self.still_open = "Retired: dotnet-2026-10 (kept).\n", False
        self.results, self.clock = "", "2026-11-10T15:25"

    def run(self, command, timeout=900, input=None):
        self.calls.append((command, input))
        out, code = "", self.fails.get(next((k for k in self.fails if k in command), ""), 0)
        if "SSH_CLIENT" in command:
            out = "203.0.113.9 51234 22\n"
        if " run --all --unattended" in command:
            out = "".join(f"{name:20} complete     Low (5.0%)\n" for name in self.answering())
        if "date -d" in command:
            out = "14:00\n"
        if "date +%Y" in command:
            out = "2026-11-10T15:20\n"
        if "ssh-keygen" in command:
            out = "ssh-ed25519 STORY ops@checker\n"
        if "/results" in command:
            out = f"{self.clock}\n{self.results}"
        if " packs retire " in command:
            out = self.retired
        if "/dev/tcp/" in command:  # a server that has shut the checker out refuses it
            code = 0 if self.still_open else 1
        return SimpleNamespace(returncode=code, stdout=out, stderr="said why")


def world_of(tmp_path, monkeypatch, names=None):
    logins = []

    class Login(Node):
        def __init__(self, address, key, known, via, user="root"):
            super().__init__(address)
            logins.append((address, user, key.name))

    monkeypatch.setattr(demo, "Through", Login)

    def keypair(folder, name):
        (folder / name).write_text(f"PRIVATE {name}\n")
        return folder / name, f"ssh-ed25519 {name}"

    monkeypatch.setattr(demo, "keypair", keypair)
    monkeypatch.setattr(demo.time, "sleep", lambda seconds: None)
    names = names or [m.name for m in story.FLEET]
    servers = [
        demo.Server(
            n, "fleet", "ubuntu24.04", "", 10 + i, f"cc-demo-abc123-{n}", f"192.0.2.{10 + i}"
        )
        for i, n in enumerate(names)
    ]
    world = demo.World({s.name: Node(s.address) for s in servers}, TODAY)
    return world, logins


def test_the_story_plays_a_day_at_a_time_and_each_check_expects_who_still_answers(
    tmp_path, monkeypatch, capsys
):
    world, logins = world_of(tmp_path, monkeypatch)
    all_nodes = dict(world.nodes)
    checker = Checker(world.checked)
    demo.play(checker, world)
    said = [c for c, _ in checker.calls]
    checks = [i for i, c in enumerate(said) if " run --all --unattended" in c]
    assert len(checks) == len(story.CHECKED_DAYS)

    def at(text):
        return next(i for i, c in enumerate(said) if text in c)

    assert at("schedule install --at 14:00") < checks[0]  # the hour before its clock's
    assert world.at == "14:00"  # which the later days are timed by, when it is kept up
    assert checks[1] < at("baseline accept db-1 --reason") < checks[2]
    assert checks[3] < at("hosts remove staging-1") < checks[4]
    assert checks[4] < at("packs retire dotnet-2026-10 --reason")  # and no check after it
    # staging-1: off the list and no longer expected in a check; its server stays, for the proof
    # to look at and for the person to add back
    assert world.unlisted == {"staging-1"} and "staging-1" not in world.checked()
    assert "staging-1" in world.nodes and not all_nodes["staging-1"].closed
    # every collection the checks made is one the proof will want to find
    assert world.collected == 6 + 6 + 6 + 5 + 4 and world.failed == []
    # app-1 no longer answers, and the checks after stop expecting it
    assert world.lost == {"app-1"} and "app-1" not in world.checked()
    # ...and its logs were looked at for this machine's address just before it shut the door
    looked = [i for i, (c, _) in enumerate(all_nodes["app-1"].calls) if "lastlog" in c]
    shut = next(
        i
        for i, (_, text) in enumerate(all_nodes["app-1"].calls)
        if text and "remove-rich-rule" in text
    )
    assert looked and looked[0] < shut and world.found == []
    # the scripts went in on standard input, the keys and the checker's address filled in
    command, attack = next(c for c in all_nodes["shop-web-1"].calls if "useradd -o -u 0" in c[1])
    assert command == "bash --norc --noprofile -s"
    assert "ssh-ed25519 planted-root" in attack and "{" + "root_key}" not in attack
    assert any('address="192.0.2.1"' in (text or "") for _, text in all_nodes["app-1"].calls)
    assert "ssh-ed25519 planted-deploy2" in all_nodes["db-1"].calls[0][1]
    assert "ssh-ed25519 planted-svc-backup" in attack
    # each new account is used on the server that got it, with a key of its own
    assert logins == [
        ("192.0.2.12", "deploy2", "planted-deploy2"),
        ("192.0.2.10", "svc-backup", "planted-svc-backup"),
    ]
    # the scripts that say nothing of their own failures are stopped by them
    php = [text for _, text in all_nodes["shop-web-2"].calls if text]
    assert len(php) == 2 and all(text.startswith("set -eu\n") for text in php)
    # the rule went onto mail-1's whitelist, to expire tomorrow
    rule = next(i for c, i in checker.calls if "whitelist/hosts/mail-1.yaml" in c)
    assert "id: mail-backup-job" in rule and "expires: 2026-11-11" in rule
    assert "--- day 5" in capsys.readouterr().out


def test_what_didnt_go_as_the_story_says_is_kept_or_stops_it(tmp_path, monkeypatch):
    # A break-in step that failed, a tidy-up with nothing to remove, a daily check that wasn't
    # set: the story goes on, and `up` says so at its end and ends 1.
    world, _ = world_of(tmp_path, monkeypatch)
    step = story.Step(3, "shop-web-1", "x", script="true")
    said = demo.on_server(Ran((0, "", "noise\nATTACK FAILED: container\n")), step, {}, tmp_path)
    assert said == ["shop-web-1: ATTACK FAILED: container"]
    assert "ended 2" in demo.on_server(Ran((2, "", "oops")), step, {}, tmp_path)[0]
    checker = Checker(world.checked)
    checker.fails = {" schedule install ": 1}
    demo.by_admin(checker, story.STORY[0], world)
    assert world.failed == ["the daily check wasn't set (`schedule install` ended 1)"]
    # A PHP step that failed, rules the checker won't take, a threat update that wasn't in use,
    # a server that still lets the checker in: each would make the pages tell another story.
    strict = story.Step(2, "shop-web-2", "PHP is updated", script="true", strict=True)
    with pytest.raises(demo.DemoError, match="PHP is updated: it failed"):
        demo.on_server(Ran((100, "", "E: no package")), strict, {}, tmp_path)
    checker.fails = {" whitelist check": 1}
    with pytest.raises(demo.DemoError, match="the rules failed"):
        demo.by_admin(checker, story.Step(4, "admin", "x", admin=("rule", "mail-1")), world)
    checker.fails, checker.retired = {}, "Nothing to retire.\n"
    retire = next(s for s in story.STORY if s.admin[:1] == ("retire",))
    with pytest.raises(demo.DemoError, match="dotnet-2026-10 wasn't stopped"):
        demo.by_admin(checker, retire, world)
    checker.still_open = True
    with pytest.raises(demo.DemoError, match="app-1 still lets the checker's server in"):
        demo.play(checker, world)


def test_a_failed_up_goes_on_deleting_when_the_terminal_is_gone(tmp_path):
    """A hang-up: every print raises. The deleting must not stop for it."""

    class Gone:
        def write(self, text):
            raise OSError(5, "Input/output error")

        def flush(self):
            pass

    folder, done = tmp_path / "demo", []
    was = sys.stdout, sys.stderr, signal.getsignal(signal.SIGHUP)
    sys.stdout = sys.stderr = Gone()
    try:
        with demo.nothing_stops_it(folder):
            assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN  # nor a second signal
            for label in ("a", "b"):
                print(f"deleted {label}")
                done.append(label)
            print("could not delete c", file=sys.stderr)
    finally:
        sys.stdout, sys.stderr = was[:2]
    assert done == ["a", "b"] and signal.getsignal(signal.SIGHUP) is was[2]
    log = (tmp_path / "demo-up-failed.log").read_text()
    assert log == "deleted a\ndeleted b\ncould not delete c\n"


def test_a_check_that_misses_a_server_stops_the_story(tmp_path, monkeypatch):
    world, _ = world_of(tmp_path, monkeypatch)
    checker = Checker(lambda: [n for n in world.checked() if n != "mail-1"])
    with pytest.raises(demo.DemoError, match="day 0's check gave no result for mail-1"):
        demo.play(checker, world)


def test_a_step_that_didnt_run_or_a_login_that_failed_stops_the_story(tmp_path, monkeypatch):
    world, _ = world_of(tmp_path, monkeypatch)
    step = story.Step(1, "db-1", "x", script="true", login="deploy2")
    lost = Ran((255, "", "connection closed"))
    with pytest.raises(demo.DemoError, match="didn't run"):
        demo.on_server(lost, step, {}, tmp_path / "k")

    class Refused(Node):
        def __init__(self, *a, **k):
            super().__init__()

        def run(self, command, timeout=900, input=None):
            return SimpleNamespace(returncode=255, stdout="", stderr="Permission denied")

    monkeypatch.setattr(demo, "Through", Refused)
    with pytest.raises(demo.DemoError, match="login as deploy2 failed"):
        demo.on_server(Node(), step, {}, tmp_path / "k")
    with pytest.raises(demo.DemoError, match="isn't a thing the admin does"):
        demo.by_admin(Node(), story.Step(1, "admin", "x", admin=("reboot",)), world)


def test_the_planted_keys_are_not_kept(tmp_path, monkeypatch):
    world, _ = world_of(tmp_path, monkeypatch)
    made = []
    monkeypatch.setattr(
        demo,
        "keypair",
        lambda folder, name: (made.append(folder), (folder / name, "ssh-ed25519 K"))[1],
    )
    demo.play(Checker(world.checked), world)
    assert made and not any(folder.exists() for folder in made)


def test_status_prints_what_is_left_to_the_person(tmp_path, capsys):
    demo.save_state(tmp_path, state(1))
    demo.status(
        FakeApi([node("cc-demo-abc123-s1", [demo.TAG], 1)]),
        tmp_path,
        datetime(2026, 11, 10, 14, tzinfo=UTC),
    )
    out = capsys.readouterr().out
    assert "Yours to do while it is up" in out and "put the stopped threat update back" in out


# --- kept up for days ----------------------------------------------------------------------


def test_each_days_steps_run_before_its_check_or_after_it_for_a_day_not_checked():
    now = datetime(2026, 11, 10, 15, 20)
    times = demo.step_times(now, "14:00", [1, 3, 5])
    assert times[1] == datetime(2026, 11, 11, 13, 15)  # day 1's check is tomorrow's, at 14:00
    assert times[3] == datetime(2026, 11, 13, 13, 15)
    assert times[5] == datetime(2026, 11, 15, 15, 0)  # after day 5's: its note is the point
    # A check later today is day 1's, unless its steps would already be late.
    assert demo.step_times(now, "20:00", [1])[1] == datetime(2026, 11, 10, 19, 15)
    assert demo.step_times(now, "16:00", [1])[1] == datetime(2026, 11, 11, 15, 15)


def staged(tmp_path, monkeypatch, days):
    world, _ = world_of(tmp_path, monkeypatch)
    checker = Checker(world.checked)
    world.at = "14:00"
    plan, left_out, last = demo.stage(checker, world, days)
    # day 1's check is tomorrow at 14:00, and the last day's a day later each
    assert last == datetime(2026, 11, 10 + days, 14, 0)
    assert world.expires_on == date(2026, 11, 15)  # through day 5's check, gone at day 6's
    put = {c.rsplit("/", 1)[-1]: text for c, text in checker.calls if "cat > /" in c}
    return world, checker, plan, left_out, put


def test_the_later_days_are_put_on_the_checkers_server_a_timer_each(tmp_path, monkeypatch):
    world, checker, plan, left_out, put = staged(tmp_path, monkeypatch, 5)
    later = [s for s in story.STORY if s.day >= 1]
    assert [(p["day"], p["where"], p["says"]) for p in plan] == [
        (s.day, s.where, s.says) for s in later
    ]
    assert left_out == [] and plan[0] == {
        "id": "d1-1",
        "day": 1,
        "where": "db-1",
        "says": later[0].says,
        "when": "2026-11-11T13:15",
    }
    # Each day's runner is a script bash takes, run by a timer for its day that survives a restart.
    for day in (1, 2, 3, 4, 5):
        runner = put[f"day{day}.sh"]
        (tmp_path / "r.sh").write_text(runner)
        assert subprocess.run(["bash", "-n", tmp_path / "r.sh"], check=False).returncode == 0  # noqa: S603, S607
        assert (
            f"ExecStart=/bin/bash /root/cc-story/day{day}.sh" in put[f"cc-story-day{day}.service"]
        )
    timer = next(text for c, text in checker.calls if "cc-story-day3.timer &&" in c)
    assert "OnCalendar=2026-11-13 13:15:00" in timer and "Persistent=true" in timer
    assert any("enable -q --now cc-story-day3.timer" in c for c, _ in checker.calls)
    # A step on a server: its script as `play` would send it, a root login from the checker's.
    day3 = put["day3.sh"]
    assert "on_server d3-1 192.0.2.10\nlogin d3-1 svc-backup 192.0.2.10\n" in day3
    assert "ssh-ed25519 planted-root" in put["d3-1.sh"]
    assert (
        "ssh-ed25519 planted-svc-backup" in put["d3-1.sh"]
        and "{" + "admin_key}" not in put["d3-1.sh"]
    )
    assert put["account-svc-backup"] == "PRIVATE planted-svc-backup\n"
    assert "ssh-ed25519 planted-deploy2" in put["d1-1.sh"]
    assert put["d2-1.sh"].startswith("set -eu\n")  # the PHP step, strict as it is from here
    # app-1's shut-out is confirmed, as it is from here
    assert "on_server d3-4 192.0.2.14\nshut d3-4 192.0.2.14\n" in day3
    assert all("umask 077" in c for c, _ in checker.calls if "cat > /root/cc-story/" in c)
    # The admin's steps are the commands `by_admin` runs.
    accept = next(s for s in story.STORY if s.admin[:1] == ("accept",))
    host, reason = accept.admin[1:]
    assert demo.as_checker("baseline", "accept", host, "--reason", reason) in put["day2.sh"]
    assert "|| true" not in put["day2.sh"]  # a refusal is noted, not passed over
    day4 = put["day4.sh"]
    assert demo.as_checker("hosts", "remove", "staging-1") in day4
    assert "whitelist/hosts/mail-1.yaml <<'RULE'" in day4 and "expires: 2026-11-15\nRULE\n" in day4
    assert demo.as_checker("whitelist", "check") in day4
    assert "packs retire dotnet-2026-10" in put["day5.sh"] and "grep -q Retired:" in put["day5.sh"]
    # The keys go when the last day ends, however it ends, and not before.
    assert "trap 'rm -f key key.pub account-*' EXIT" in put["day5.sh"]
    assert not any("rm -f key" in put[f"day{day}.sh"] for day in (1, 2, 3, 4))
    # Nothing waits for ever on a server that has stopped answering.
    assert "timeout 1500 ssh -i key" in day3 and "ServerAliveInterval=15" in day3
    assert "TimeoutStartSec=40min" in put["cc-story-day3.service"]
    # A day off, what the break-in leaves running outlives the next check, and nothing else of
    # the story's is changed by that but the PHP update, which fetches the lists first.
    assert "/root/kworkerd 2000000" in put["d3-1.sh"] and "7200" not in put["d3-1.sh"]
    assert "sleep 2000000 >/dev/null || fail container" in put["d3-1.sh"]
    assert "$APT update >/dev/null\n$APT install" in put["d2-1.sh"]
    changed = [
        s.says
        for s in story.STORY
        if s.script and story.renamed(s.script, story.DAYS_APART) != s.script
    ]
    assert changed == ["PHP is updated; its service isn't restarted", "the break-in"]


def test_a_shorter_stay_plays_the_days_it_has_and_says_what_it_left_out(tmp_path, monkeypatch):
    _, _, plan, left_out, put = staged(tmp_path, monkeypatch, 2)
    assert {p["day"] for p in plan} == {1, 2} and "trap 'rm -f key key.pub" in put["day2.sh"]
    assert "day3.sh" not in put and "account-svc-backup" not in put
    assert len(left_out) == len([s for s in story.STORY if s.day > 2])
    assert left_out[0] == "day 3: shop-web-1: the break-in"
    world, _ = world_of(tmp_path, monkeypatch)
    with pytest.raises(demo.DemoError, match="daily check wasn't set"):
        demo.stage(Checker(world.checked), world, 2)


def test_the_storys_key_is_on_each_server_before_its_first_check(tmp_path, monkeypatch):
    world, _ = world_of(tmp_path, monkeypatch)
    checker = Checker(world.checked)
    demo.story_key(checker, world.nodes)
    made, *reached = [c for c, _ in checker.calls]
    assert "umask 077" in made and "ssh-keygen" in made and "/root/cc-story" in made
    for node in world.nodes.values():
        (line,) = [c for c, _ in node.calls]
        assert 'from="192.0.2.1" ssh-ed25519 STORY ops@checker' in line  # the checker's only
        assert line.endswith(">> /root/.ssh/authorized_keys")
    assert len(reached) == len(world.nodes) and all("accept-new" in c for c in reached)


def test_status_says_how_each_of_the_days_went(tmp_path, monkeypatch, capsys):
    _, checker, plan, _, _ = staged(tmp_path, monkeypatch, 3)
    checker.results = (
        "2026-11-11T13:15:40Z d1-1 ended 0 \n"
        "2026-11-11T13:15:41Z d1-1-login ended 0\n"
        "2026-11-13T13:16:02Z d3-1 ended 0 ATTACK FAILED: container;\n"
        "2026-11-13T13:16:03Z d3-1-login ended 255\n"
        "2026-11-13T13:16:30Z d3-4 ended 0 \n"
        "2026-11-13T13:16:55Z d3-4-shut ended 1 it still lets the checker's server in\n"
    )
    checker.clock = "2026-11-13T14:20"  # an hour and five minutes after day 3's steps were due
    lines, good = demo.story_so_far(checker, plan)
    assert not good
    assert lines[0].endswith("and a package: done") and "day 1, 2026-11-11 13:15" in lines[0]
    assert lines[1].endswith("isn't restarted: LATE: it should have run by now, and hasn't said so")
    assert lines[5].endswith(
        "a backup job is added: LATE: it should have run by now, and hasn't said so"
    )
    checker.clock = "2026-11-12T12:00"  # the morning of day 2
    early, _ = demo.story_so_far(checker, plan)
    assert early[1].endswith("isn't restarted: not yet")
    quiet = Checker(lambda: [])
    quiet.results = "2026-11-11T13:15:40Z d1-1 ended 0 \n2026-11-11T13:15:41Z d1-1-login ended 0\n"
    assert demo.story_so_far(quiet, plan[:1]) == ([lines[0]], True)
    gone = Ran((255, "", "ssh: no route"))
    assert demo.story_so_far(gone, plan) == (
        ["  The checker's server couldn't be asked (ssh: no route)"],
        False,
    )
    assert lines[3].endswith(
        "the break-in: d3-1 ended 0 ATTACK FAILED: container;; d3-1-login ended 255"
    )
    assert lines[6].endswith("d3-4-shut ended 1 it still lets the checker's server in")
    # `status` asks the checker's server, with the demo's own key
    asked = []

    class Asked(Checker):
        def __init__(self, address, key, known):
            super().__init__(lambda: [])
            self.results = checker.results
            asked.append((address, key.name, self))

    monkeypatch.setattr(demo.install, "Node", Asked)
    kept = state(0, 1)
    kept.days, kept.plan, kept.last_check = 3, plan, "2026-11-13T14:00"
    demo.save_state(tmp_path, kept)
    api = FakeApi([node(s.label, [demo.TAG], s.id) for s in kept.servers])
    # a step that failed or is late wants a look: `status` ends 1
    assert demo.status(api, tmp_path, datetime(2026, 11, 10, 14, tzinfo=UTC)) == 1
    out = capsys.readouterr().out
    assert "Kept up 3 days." in out and "and a package: done" in out
    assert "Day 3 is checked at 2026-11-13 14:00." in out
    # a checker's server Linode no longer lists isn't asked (whatever has its address now)
    asked.clear()
    demo.status(FakeApi(), tmp_path, datetime(2026, 11, 10, 14, tzinfo=UTC))
    assert asked == [] and "GONE" in capsys.readouterr().out
    asked.append(("192.0.2.0", "key", Asked("192.0.2.0", Path("key"), None)))
    asked[0][2].closed = True
    assert asked[0][:2] == ("192.0.2.0", "key") and asked[0][2].closed
    assert demo.load_state(tmp_path).plan == plan  # and the plan reads back


def test_up_takes_one_to_fourteen_days(tmp_path):
    for days in (-1, 15):
        with pytest.raises(demo.DemoError, match="--days is 1 to 14"):
            demo.up(FakeApi(), tmp_path / "demo", "us-sea", TODAY, days)
    assert not (tmp_path / "demo").exists()


def test_any_proofs_sweep_takes_a_demo_server_past_its_date_and_no_other():
    import readonly_proof as proof

    now = datetime(2026, 11, 12, 9, tzinfo=UTC)
    tag = demo.until_tag
    nodes = [
        node("cc-demo-a-s1", [demo.TAG, tag(date(2026, 11, 11))], 1),  # yesterday: past
        node("cc-demo-a-s2", [demo.TAG, tag(date(2026, 11, 12))], 2),  # today is its last day
        node("cc-demo-a-s3", [demo.TAG], 3),  # no date it can read: `demo.py`'s to deal with
        node("cc-demo-a-s4", [demo.TAG, "cc-demo-until-soon"], 4),
        node("cc-test-a-s5", [proof.TAG, tag(date(2026, 11, 1))], 5),  # not a demo's
        node("web-1", [tag(date(2026, 11, 1))], 6),  # nor this
        node("web-2", [demo.TAG, tag(date(2026, 11, 1))], 7),  # the tag without the label
    ]
    assert [n["id"] for n in proof.demo_past_its_date(nodes, now)] == [1]
    assert (demo.TAG, demo.LABEL_PREFIX, demo.UNTIL) == (
        proof.DEMO_TAG,
        proof.DEMO_LABEL,
        proof.DEMO_UNTIL,
    )


def test_kept_up_day_0_is_played_from_here_and_the_rest_is_staged(tmp_path, monkeypatch, capsys):
    world, _ = world_of(tmp_path, monkeypatch)
    checker = Checker(world.checked)
    kept = state(0, 1)
    demo.play_days(checker, world, kept, tmp_path, 2)
    said = [c for c, _ in checker.calls]

    def at(text):
        return next(i for i, c in enumerate(said) if text in c)

    # the story's key is on every server before the first check, so it is never a change
    assert at("ssh-keygen") < at(" run --all --unattended") < at("cat > /root/cc-story/")
    # only day 0 is played from here: one check, and none of the later days' steps
    assert len([c for c in said if " run --all --unattended" in c]) == 1
    assert world.collected == 6 and not any(
        "baseline accept" in c for c in said if "cat >" not in c
    )
    assert all(
        not text or "useradd" not in text for n in world.nodes.values() for _, text in n.calls
    )
    # what is to come is kept, for `status`, and said
    saved = demo.load_state(tmp_path)
    assert saved.plan == kept.plan and {p["day"] for p in saved.plan} == {1, 2}
    assert saved.last_check == "2026-11-12T14:00"
    out = capsys.readouterr().out
    assert "The days to come" in out and "db-1: an admin adds" in out and ": not yet" in out
    assert "left out, after day 2: day 3: shop-web-1: the break-in" in out


def test_a_days_runner_writes_down_what_status_reads(tmp_path, monkeypatch):
    """The runner itself, with an `ssh` that stands in for the servers: what it notes is what
    `story_so_far` takes."""
    _, checker, plan, _, put = staged(tmp_path, monkeypatch, 3)
    home, tools = tmp_path / "cc-story", tmp_path / "bin"
    home.mkdir()
    tools.mkdir()
    for name, text in put.items():
        if name.endswith(".sh") or name.startswith("account-"):
            (home / name).write_text(text)
    (home / "key").write_text("K")
    # The break-in "fails" one part; the login as the new account is refused.
    (tools / "ssh").write_text(
        '#!/bin/bash\ncat > /dev/null\ncase "$*" in\n'
        "  *svc-backup@*) exit 255 ;;\n"
        "  *192.0.2.10*) echo 'ATTACK FAILED: container' >&2 ;;\nesac\n"
    )
    (tools / "sleep").write_text("#!/bin/bash\n")
    (tools / "timeout").write_text('#!/bin/bash\nshift\n[ "$1" = bash ] && exit 1\nexec "$@"\n')
    for tool in tools.iterdir():
        tool.chmod(0o755)
    runner = put["day3.sh"].replace("/root/cc-story", str(home))
    done = subprocess.run(  # noqa: S603
        ["bash", "-c", runner],  # noqa: S607
        env={"PATH": f"{tools}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    checker.results, checker.clock = (home / "results").read_text(), "2026-11-13T13:30"
    lines, good = demo.story_so_far(checker, [p for p in plan if p["day"] == 3])
    assert not good
    assert lines[0].endswith("d3-1 ended 0 ATTACK FAILED: container;; d3-1-login ended 255")
    assert [line.rsplit(": ", 1)[1] for line in lines[1:]] == ["done", "done", "done"]
    # the scripts and the account's key are gone once used; the last day takes the story's key
    assert sorted(p.name for p in home.iterdir() if p.suffix == ".sh") == [
        "d1-1.sh", "d2-1.sh", "day1.sh", "day2.sh", "day3.sh"
    ]  # fmt: skip
    assert not (home / "account-svc-backup").exists() and not (home / "key").exists()


def test_days_goes_with_up_only(monkeypatch, capsys):
    monkeypatch.setattr(demo.proof, "linode_token", lambda: pytest.fail("asked for the token"))
    for words in (["status", "--days", "2"], ["up", "--days", "0"], ["up", "--days", "15"]):
        with pytest.raises(SystemExit):
            demo.main(words)
    assert "--days goes with `up`, and is 1 to 14" in capsys.readouterr().err


# --- save (D.5) ------------------------------------------------------------------------------


def a_home(base, address="198.51.100.7"):
    """A checker's home as the installer leaves it, with one collection that names `address`."""
    import gzip
    import sqlite3

    import pyrage
    from pyrage import x25519

    identity = x25519.Identity.generate()
    (base / "keys").mkdir(parents=True)
    (base / "keys" / "evidence-identity.txt").write_text(f"# made now\n{identity}\n")
    for secret in ("scanner_ed25519", "web-secret.txt", "web-proxy-secret.txt", "mail-key.txt"):
        (base / "keys" / secret).write_text("SECRET\n")
    (base / "config.yaml").write_text(
        f"recipients: [{identity.to_public()}]\n"
        "identity_file: /var/lib/compromise-checker/data/keys/evidence-identity.txt\n"
        "database: null\n"
    )
    (base / "hosts.yaml").write_text("hosts: []\n")
    (base / "hosts.yaml.lock").write_text("")
    (base / "known_hosts").write_text("192.0.2.5 ssh-ed25519 AAAA\n")
    (base / "run.lock").write_text("")
    (base / "logs").mkdir()
    (base / "logs" / "run.log").write_text("not asked for\n")
    (base / "packs" / "active").mkdir(parents=True)
    (base / "packs" / "active" / "brotli-2026-10.toml").write_text("pack\n")
    (base / "packs" / "state.lock").write_text("")
    (base / "whitelist" / "hosts").mkdir(parents=True)
    (base / "whitelist" / "hosts" / "mail-1.yaml").write_text("rules: []\n")
    (base / "whitelist" / ".global.yaml.x.tmp").write_text("half written\n")
    (base / "evidence" / "db-1").mkdir(parents=True)
    line = json.dumps(
        {"type": "chunk", "source_id": 1, "encoding": "utf-8", "data": f"login from {address}"}
    )
    (base / "evidence" / "db-1" / "db-1-20261110T030000Z-abcd1234.age").write_bytes(
        pyrage.encrypt(gzip.compress(line.encode() + b"\n"), [identity.to_public()])
    )
    (base / "evidence" / "db-1" / "link.age").symlink_to("/etc/passwd")
    store = sqlite3.connect(base / "checker.db")
    store.execute("PRAGMA journal_mode = WAL")
    store.execute("CREATE TABLE custody (who TEXT, note BLOB)")
    store.execute("INSERT INTO custody VALUES ('ops (web interface)', x'00ff')")
    store.commit()
    return store  # left open, as the checker's own would be


def as_ssh(monkeypatch, base, instead=None):
    """ssh to the checker's server, replaced by the same script run here on `base` (or by
    `instead`, a command that stands for a server gone wrong)."""
    import shlex

    real = subprocess.Popen

    def ssh(argv, **kwargs):
        if argv[0] != "ssh":
            return real(argv, **kwargs)
        assert "runuser -u compromise-checker -- " in argv[-1]
        assert "/opt/compromise-checker/current/bin/python -I - " in argv[-1]
        # The last word is the list of what to send, as the server's shell would read it.
        here = [sys.executable, "-I", "-", str(base), shlex.split(argv[-1])[-1]]
        return real(instead or here, **kwargs)

    monkeypatch.setattr(demo.subprocess, "Popen", ssh)


def pages_used(base, here="203.0.113.9"):
    """The web interface's own database on the server, as the checker makes it, after someone
    signed in from `here`, started a check and looked at a server."""
    made = subprocess.run(
        [sys.executable, "-c", demo._NEW_ACCOUNTS, str(base)],
        cwd=Path(demo.__file__).resolve().parents[2],
        env={**os.environ, "CHECKER_HOME": str(base)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert made.returncode == 0, made.stderr
    import sqlite3

    web = sqlite3.connect(base / "web.db")
    web.execute(
        "INSERT INTO auth_user (password, is_superuser, username, first_name, last_name, email,"
        " is_staff, is_active, date_joined)"
        " VALUES ('hash', 0, 'ops', '', '', '', 0, 1, '2026-11-11')"
    )
    web.execute("INSERT INTO django_session VALUES ('key', 'session data', '2026-12-01 00:00:00')")
    web.execute(
        "INSERT INTO web_loginattempt (username, address, at) VALUES ('ops', ?, '2026-11-11')",
        (here,),
    )
    web.execute(
        "INSERT INTO web_actionrecord (at, who, address, action, target, outcome, detail)"
        " VALUES ('2026-11-11 05:00:00', 'ops', ?, 'viewed a server''s results', 'db-1',"
        " 'done', '')",
        (here,),
    )
    web.execute(
        "INSERT INTO web_checkrun (kind, hosts, who, address, started_at, finished_at, ended)"
        " VALUES ('check', '[\"db-1\"]', 'ops', ?, '2026-11-11 05:01:00', '2026-11-11 05:03:00',"
        " 'finished')",
        (here,),
    )
    web.commit()
    return web


class Home:
    """The checker's server for `save`: the real script, run here on a folder."""

    address, user, options = "192.0.2.1", "root", []

    def __init__(self, base, here="203.0.113.9"):
        self.base, self.here, self.closed = base, here, False

    def run(self, command, timeout=900, input=None):
        return SimpleNamespace(returncode=0, stdout=f"{self.here} 51234 22\n", stderr="")

    def out(self, command):
        return self.run(command).stdout.strip()

    def close(self):
        self.closed = True


def saving(tmp_path, monkeypatch, here="203.0.113.9", **more):
    """A demo that is up, its checker's home in a folder, and ssh replaced by this machine."""
    base = tmp_path / "server"
    store = a_home(base, **more)
    folder = tmp_path / "state"
    up = state(1, 2)
    demo.save_state(folder, up)
    home = Home(base, here)
    monkeypatch.setattr(demo.install, "Node", lambda *a, **k: home)
    as_ssh(monkeypatch, base)
    return folder, base, store


NOON = datetime(2026, 11, 12, 20, 0, tzinfo=UTC)


def test_save_brings_down_the_data_and_leaves_the_accounts_and_the_keys(
    tmp_path, monkeypatch, capsys
):
    folder, base, store = saving(tmp_path, monkeypatch)
    target = tmp_path / "out" / "dataset"
    assert demo.save(folder, target, NOON) == 0
    store.close()
    got = sorted(str(p.relative_to(target)) for p in target.rglob("*") if p.is_file())
    assert got == [
        "checker.db",
        "config.yaml",
        "demo.json",
        "evidence/db-1/db-1-20261110T030000Z-abcd1234.age",
        "hosts.yaml",
        "keys/evidence-identity.txt",
        "known_hosts",
        "packs/active/brotli-2026-10.toml",
        "whitelist/hosts/mail-1.yaml",
    ]
    assert all(p.stat().st_mode & 0o077 == 0 for p in [target, *target.rglob("*")])
    # The settings name the saved key, so the checker here can open the evidence.
    import yaml

    config = yaml.safe_load((target / "config.yaml").read_text())
    assert config["identity_file"] == str(target / "keys" / "evidence-identity.txt")
    about = json.loads((target / "demo.json").read_text())
    assert about["run"] == "abc123" and about["servers"][0]["address"] == "192.0.2.1"
    assert not (tmp_path / "out" / "dataset.part").exists()
    assert not list((tmp_path / "out").glob("*.tar"))
    said = capsys.readouterr().out
    assert "PASS 8 files, 1 of them stored evidence" in said
    assert "none of them holds 203.0.113.9" in said and "NOTE" not in said
    assert not list((tmp_path / "out").glob(".dataset.*"))  # the tar's own folder is gone
    assert f"CHECKER_HOME={target} checker web" in said
    kept = demo.load_state(folder)
    assert kept.saved == str(target) and kept.saved_at == "2026-11-12T20:00:00+00:00"
    assert kept.saved_whole  # one sitting: there is no last day to wait for


def test_the_saved_store_is_whole_though_the_checker_had_it_open(tmp_path, monkeypatch):
    """Rows still in the write-ahead log, not yet in the file, are in the copy."""
    import sqlite3

    folder, base, store = saving(tmp_path, monkeypatch)
    store.execute("INSERT INTO custody VALUES ('written just now', NULL)")
    store.commit()
    assert (base / "checker.db-wal").stat().st_size > 0
    assert demo.save(folder, tmp_path / "dataset", NOON) == 0
    saved = sqlite3.connect(tmp_path / "dataset" / "checker.db")
    assert saved.execute("SELECT count(*) FROM custody").fetchone() == (2,)
    saved.close()
    store.close()


@pytest.mark.parametrize(
    "where",
    ["evidence", "store", "store-bytes", "file"],
)
def test_data_that_names_this_machine_is_kept_aside_and_not_called_the_dataset(
    tmp_path, monkeypatch, capsys, where
):
    here = "203.0.113.9"
    folder, base, store = saving(
        tmp_path, monkeypatch, **({"address": here} if where == "evidence" else {})
    )
    if where == "store":
        store.execute("INSERT INTO custody VALUES (?, NULL)", (f"from {here}",))
    if where == "store-bytes":
        store.execute("INSERT INTO custody VALUES ('x', ?)", (f"from {here}".encode(),))
    if where == "file":
        (base / "known_hosts").write_text(f"{here} ssh-ed25519 AAAA\n")
    store.commit()
    target = tmp_path / "dataset"
    assert demo.save(folder, target, NOON) == 1
    store.close()
    assert not target.exists() and (tmp_path / "dataset.part" / "checker.db").exists()
    said = capsys.readouterr().out
    assert "FAIL " in said and "Not fit to show as it is" in said
    assert demo.load_state(folder).saved == ""
    # And the next try says that one is in the way, not a second copy beside it.
    with pytest.raises(demo.DemoError, match="left from a save that didn't finish"):
        demo.save(folder, target, NOON)


def test_evidence_the_saved_key_cant_open_fails_the_save(tmp_path, monkeypatch, capsys):
    import pyrage
    from pyrage import x25519

    folder, base, store = saving(tmp_path, monkeypatch)
    other = x25519.Identity.generate().to_public()
    (base / "evidence" / "db-1" / "another.age").write_bytes(pyrage.encrypt(b"x", [other]))
    assert demo.save(folder, tmp_path / "dataset", NOON) == 1
    store.close()
    assert "the saved evidence couldn't be opened" in capsys.readouterr().out


def test_save_stops_for_a_check_under_way_and_changes_nothing_here(tmp_path, monkeypatch):
    import fcntl

    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    held = os.open(base / "run.lock", os.O_RDWR)
    fcntl.flock(held, fcntl.LOCK_EX)
    try:
        with pytest.raises(demo.DemoError, match="a check or a purge is running"):
            demo.save(folder, tmp_path / "dataset", NOON)
    finally:
        os.close(held)
    assert not (tmp_path / "dataset").exists() and not (tmp_path / "dataset.part").exists()


def test_save_takes_only_a_new_folder_outside_the_repository(tmp_path, monkeypatch):
    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    (tmp_path / "there").mkdir()
    with pytest.raises(demo.DemoError, match="exists"):
        demo.save(folder, tmp_path / "there", NOON)
    inside = Path(demo.__file__).resolve().parents[2] / "demo-data"
    with pytest.raises(demo.DemoError, match="outside any repository"):
        demo.save(folder, inside, NOON)
    assert not inside.exists()
    # Another checkout, or another repository altogether, is one too.
    (tmp_path / "other" / ".git").mkdir(parents=True)
    with pytest.raises(demo.DemoError, match="outside any repository"):
        demo.save(folder, tmp_path / "other" / "deep" / "data", NOON)
    (tmp_path / "worktree").mkdir()
    (tmp_path / "worktree" / ".git").write_text("gitdir: elsewhere\n")
    with pytest.raises(demo.DemoError, match="outside any repository"):
        demo.save(folder, tmp_path / "worktree" / "data", NOON)
    with pytest.raises(demo.DemoError, match="nothing to save"):
        demo.save(tmp_path / "no-state", tmp_path / "dataset", NOON)


def test_only_what_was_asked_for_is_taken_from_what_the_server_sends(tmp_path):
    import io
    import tarfile

    def archive(*entries):
        path = tmp_path / "sent.tar"
        with tarfile.open(path, "w") as tar:
            for entry in entries:
                tar.addfile(entry, io.BytesIO(b"x" * entry.size))
        return path

    def a_file(name, size=1):
        entry = tarfile.TarInfo(name)
        entry.size = size
        return entry

    link = tarfile.TarInfo("evidence/db-1/a.age")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    for bad in (
        a_file("web.db"),
        a_file("keys/scanner_ed25519"),
        a_file("../outside"),
        a_file("/etc/cron.d/x"),
        a_file("evidence/../../outside"),
        a_file("evidence"),
        link,
    ):
        (tmp_path / "into").mkdir(exist_ok=True)
        with pytest.raises(demo.DemoError, match="wasn't asked for"):
            demo.unpack(archive(bad), tmp_path / "into")
        assert not list((tmp_path / "into").iterdir())
    assert demo.unpack(archive(a_file("checker.db"), a_file("packs/state.json")), tmp_path / "into")


def stay(last_check="2026-11-15T03:00"):
    up = state(1, 2)
    up.days, up.last_check = 4, last_check
    return up


def test_save_keeps_clear_of_the_days_steps_and_the_daily_check():
    def at(text):
        return demo.too_near_a_check(stay(), datetime.fromisoformat(text).replace(tzinfo=UTC))

    assert at("2026-11-12T20:00") is None
    assert at("2026-11-13T01:55") is None
    assert "between 02:00 and 04:45 UTC" in at("2026-11-13T02:00")
    assert at("2026-11-13T03:00") and at("2026-11-13T04:30")
    assert at("2026-11-13T04:45") and at("2026-11-13T04:46") is None
    # The last day's timer may fire a little late: a save in its first minutes would take the
    # lock ahead of it, and that day's check would be lost. After that, only the lock holds it.
    assert "the last day's check is starting" in at("2026-11-15T03:00:10")
    assert at("2026-11-15T03:05") and at("2026-11-15T03:06") is None
    assert demo.too_near_a_check(state(1), NOON) is None  # one sitting: no days to come
    # A daily check a little after midnight: its window starts the evening before.
    late = stay("2026-11-15T00:10")
    assert demo.too_near_a_check(late, datetime(2026, 11, 12, 23, 30, tzinfo=UTC))


def test_down_waits_for_a_save_and_for_one_made_after_the_last_check(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(demo.proof, "linode_token", lambda: pytest.fail("Linode was asked"))
    folder = tmp_path / "state"
    up = stay()
    demo.save_state(folder, up)
    assert "hasn't been saved" in demo.unsaved(folder)
    assert demo.main(["down", "--state", str(folder)]) == 1
    assert "`demo.py save DIR` first, or `down --unsaved`" in capsys.readouterr().err
    up.saved, up.saved_at = str(tmp_path / "dataset"), "2026-11-15T03:40:00+00:00"
    demo.save_state(folder, up)
    assert "which isn't there now" in demo.unsaved(folder)
    (tmp_path / "dataset").mkdir()
    (tmp_path / "dataset" / "checker.db").write_text("")
    assert "before the last day's check" in demo.unsaved(folder)  # whenever it was made
    up.saved_whole = True
    demo.save_state(folder, up)
    assert demo.unsaved(folder) is None
    # Nothing to save: no demo, a state that can't be read, or no checker installed yet.
    assert demo.unsaved(tmp_path / "none") is None
    (folder / "state.json").write_text("{")
    assert demo.unsaved(folder) is None
    bare = state(1)
    bare.web_name = ""
    demo.save_state(folder, bare)
    assert demo.unsaved(folder) is None


def test_down_unsaved_deletes_and_a_failed_up_never_waits(tmp_path, monkeypatch):
    folder = tmp_path / "state"
    demo.save_state(folder, stay())
    api = FakeApi([node("cc-demo-abc123-s1", [demo.TAG], 1)])
    monkeypatch.setattr(demo.proof, "linode_token", lambda: "token")
    monkeypatch.setattr(demo, "Api", lambda token: api)
    assert demo.main(["down", "--unsaved", "--state", str(folder)]) == 0
    assert api.deleted == [1]


def test_save_takes_a_folder_and_nothing_else_does(monkeypatch, capsys):
    monkeypatch.setattr(demo.proof, "linode_token", lambda: pytest.fail("Linode was asked"))
    for words in (
        ["save"],
        ["status", "somewhere"],
        ["up", "--unsaved"],
        ["save", "x", "--days", "2"],
    ):
        with pytest.raises(SystemExit):
            demo.main(words)
    capsys.readouterr()


def test_a_saved_home_shows_its_servers_with_the_server_gone(home, tmp_path_factory, monkeypatch):
    """A home the checker made, with a collection it analysed, saved, and then read by the
    checker's own code with the original out of reach: the store names the saved files."""
    from test_schedule import CLEAN
    from test_snapshot import add_bundle

    from checker.assess import analyze
    from checker.evidence import Store, database_file, load_config
    from checker.fleet import read_host

    base, store, identity, config = home
    (base / "evidence" / "web01").mkdir(parents=True)
    add_bundle(home, "evidence/web01/b1", 10, CLEAN)
    analyze(store, "web01", identity, config.recipients, "evidence/web01/b1")
    assert read_host(base, "web01")[1] is not None
    out = tmp_path_factory.mktemp("laptop")
    folder = out / "state"
    demo.save_state(folder, state(1, 2))
    monkeypatch.setattr(demo.install, "Node", lambda *a, **k: Home(base))
    monkeypatch.setattr(demo.install, "DATA", str(base))
    as_ssh(monkeypatch, base)
    target = out / "dataset"
    assert demo.save(folder, target, NOON) == 0
    (base / "evidence").rename(base / "gone")
    assert read_host(base, "web01")[1] is None  # the original can't be read any more
    monkeypatch.setenv("CHECKER_HOME", str(target))
    item, assessment, _, advisor_on = read_host(target, "web01")
    assert item.state == "analysed" and assessment is not None and not advisor_on
    saved = Store(database_file(target), read_only=True)
    paths = [row["path"] for row in saved.bundles("web01")]
    saved.close()
    assert paths == [str(target / "evidence" / "web01" / "b1.age")]
    # Its guards are back: what a row says of a collection still can't be changed.
    import sqlite3

    direct = sqlite3.connect(target / "checker.db")
    with pytest.raises(sqlite3.DatabaseError):
        direct.execute("UPDATE bundles SET path = 'x'")
    direct.close()
    assert load_config(target).identity_file == str(target / "keys" / "evidence-identity.txt")
    about = json.loads((target / "demo.json").read_text())
    assert about["changed_here"].startswith(f"4 paths in the store, from {base} to this folder")
    assert not (target / "keys" / "mail-key.txt").exists()


def test_settings_that_could_run_or_send_anything_here_are_put_back(tmp_path, monkeypatch):
    """A settings file comes from the server like any other file. The checker runs the commands
    one names, and sends where it says."""
    import yaml

    from checker.evidence import load_config

    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    config = yaml.safe_load((base / "config.yaml").read_text())
    config |= {
        "notify_command": "/usr/bin/touch /tmp/ran",
        "advisor": {"enabled": True, "api_key_source": "command:/usr/bin/touch /tmp/ran"},
        "packs": {"source": "https://elsewhere.example/", "apply": "all"},
        "retention_days": 30,
    }
    (base / "config.yaml").write_text(yaml.safe_dump(config))
    target = tmp_path / "dataset"
    assert demo.save(folder, target, NOON) == 0
    kept = load_config(target)
    assert kept.notify_command is None and not kept.advisor.enabled
    assert kept.advisor == type(kept.advisor)()  # as a new checker has it: off
    assert "elsewhere" not in kept.packs.source and not kept.updates.check
    assert kept.retention_days == 30 and kept.packs.apply == "all"  # what is harmless stays


@pytest.mark.parametrize(
    "hosts",
    [
        "hosts:\n- {name: a, address: 198.51.100.9, user: root, auth: agent}\n",
        "hosts:\n- {name: a, address: 198.51.100.9, user: root}\n",
        "hosts: [oops]\n",
        "- not a list of servers\n",
    ],
)
def test_a_list_of_servers_that_would_offer_this_machines_keys_stops_the_save(
    tmp_path, monkeypatch, hosts
):
    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    (base / "hosts.yaml").write_text(hosts)
    with pytest.raises(demo.DemoError, match="list of servers|settings can't be read"):
        demo.save(folder, tmp_path / "dataset", NOON)
    assert not (tmp_path / "dataset.part").exists()


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "{data}/../../etc/passwd", "{data}/web.db", "{data}/evidence/db-1/gone.age"],
)
def test_a_store_that_names_a_file_that_isnt_a_saved_one_stops_the_save(
    tmp_path, monkeypatch, path
):
    """The checker opens, writes beside and deletes the files its store names."""
    folder, base, store = saving(tmp_path, monkeypatch)
    monkeypatch.setattr(demo.install, "DATA", str(base))
    store.execute("CREATE TABLE derived (path TEXT)")
    store.execute("INSERT INTO derived VALUES (?)", (path.replace("{data}", str(base)),))
    store.commit()
    store.close()
    with pytest.raises(demo.DemoError, match="names a file"):
        demo.save(folder, tmp_path / "dataset", NOON)


def test_a_second_name_for_a_file_comes_down_as_a_file(tmp_path, monkeypatch):
    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    (base / "reports").mkdir()
    (base / "reports" / "report-a.html").write_text("a report\n")
    os.link(base / "reports" / "report-a.html", base / "reports" / "report-b.html")
    (base / "packs" / "keylists" / ".new-1").mkdir(parents=True)
    (base / "packs" / "keylists" / ".new-1" / "half-made.pub").write_text("not yet\n")
    target = tmp_path / "dataset"
    assert demo.save(folder, target, NOON) == 0
    assert (target / "reports" / "report-b.html").read_text() == "a report\n"
    assert not (target / "packs" / "keylists").exists()


@pytest.mark.parametrize(
    ("instead", "says"),
    [
        (["sh", "-c", "echo 'not a tar'; echo SENT 1 0 0 >&2"], "couldn't be taken apart"),
        (["sh", "-c", "printf '\\033[2Jgone wrong' >&2; exit 1"], r"couldn't be read:\n\?\[2Jgone"),
        (["sh", "-c", "head -c 3000000 /dev/zero; echo SENT 1 0 0 >&2"], "sent more than"),
        (["sh", "-c", "sleep 30"], "still sending after"),
    ],
)
def test_a_server_gone_wrong_stops_the_save_and_leaves_nothing(
    tmp_path, monkeypatch, instead, says
):
    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    as_ssh(monkeypatch, base, instead)
    monkeypatch.setattr(demo, "MOST_BYTES", 2_000_000)
    if "sleep" in instead[-1]:
        real = demo.threading.Timer
        monkeypatch.setattr(demo.threading, "Timer", lambda seconds, then: real(0.3, then))
    with pytest.raises(demo.DemoError, match=says):
        demo.save(folder, tmp_path / "dataset", NOON)
    assert [p.name for p in tmp_path.iterdir() if "dataset" in p.name] == []


def test_a_sealed_value_or_file_is_opened_to_be_searched(tmp_path, monkeypatch, capsys):
    """What the checker seals with the evidence key (a collection's session, the last run's
    state, a report) is read too, and one that won't open isn't passed over."""
    import gzip

    import pyrage
    from pyrage import x25519

    from checker.evidence import load_identity

    here = "203.0.113.9"
    folder, base, store = saving(tmp_path, monkeypatch)
    to = [load_identity(base / "keys" / "evidence-identity.txt").to_public()]
    store.execute(
        "INSERT INTO custody VALUES ('x', ?)", (pyrage.encrypt(f"from {here}".encode(), to),)
    )
    store.commit()
    (base / "run-state.age").write_bytes(pyrage.encrypt(b'{"seen": "203-0-113-9.sslip.io"}', to))
    (base / "reports").mkdir()
    (base / "reports" / "report-x.html.age").write_bytes(
        pyrage.encrypt(gzip.compress(b"<p>9.113.0.203.in-addr.arpa</p>"), to)
    )
    other = [x25519.Identity.generate().to_public()]
    (base / "reports" / "report-y.html.age").write_bytes(pyrage.encrypt(b"x", other))
    assert demo.save(folder, tmp_path / "dataset", NOON) == 1
    store.close()
    said = capsys.readouterr().out
    assert "FAIL the store's table custody: names this machine" in said
    assert "FAIL run-state.age: names this machine" in said
    assert "FAIL reports/report-x.html.age: names this machine" in said
    assert "FAIL reports/report-y.html.age: couldn't be opened with the saved key" in said


def test_an_address_is_looked_for_in_each_way_it_is_written():
    assert demo.forms_of("203.0.113.9") == [
        "203.0.113.9",
        "203-0-113-9",
        "9.113.0.203.in-addr.arpa",
        "9.113.0.203.IN-ADDR.ARPA",
    ]
    six = demo.forms_of("2001:db8:0:1::abcd")
    assert "2001:0db8:0000:0001:0000:0000:0000:abcd" in six and "2001:db8:0:1::/64" in six
    assert "2001:DB8:0:1::ABCD" in six
    assert demo.forms_of("not an address") == ["not an address"]


def test_a_save_before_the_last_days_collection_says_so_and_down_still_waits(
    tmp_path, monkeypatch, capsys
):
    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    up = stay("2026-11-15T03:00")
    demo.save_state(folder, up)
    collection = base / "evidence" / "db-1" / "db-1-20261110T030000Z-abcd1234.age"
    before = datetime(2026, 11, 14, 3, 4, tzinfo=UTC).timestamp()
    os.utime(collection, (before, before))
    assert demo.save(folder, tmp_path / "early", datetime(2026, 11, 14, 20, 0, tzinfo=UTC)) == 0
    assert "NOTE the last day's check has left no collection yet" in capsys.readouterr().out
    assert "before the last day's check" in demo.unsaved(folder)
    # After it, with that day's collection there, the save is whole and `down` goes ahead.
    after = datetime(2026, 11, 15, 3, 4, tzinfo=UTC).timestamp()
    os.utime(collection, (after, after))
    assert demo.save(folder, tmp_path / "whole", datetime(2026, 11, 15, 3, 30, tzinfo=UTC)) == 0
    assert "NOTE" not in capsys.readouterr().out and demo.unsaved(folder) is None
    assert json.loads((tmp_path / "whole" / "demo.json").read_text())["last_day_in_it"] is True


READ_THE_RECORD = """
from django.contrib.auth import get_user_model
from checker.web.models import ActionRecord, CheckRun
line, run = ActionRecord.objects.get(), CheckRun.objects.get()
print(line.who, line.address, run.who, run.ended, get_user_model().objects.count())
"""


def test_the_pages_record_comes_down_with_no_address_and_no_account(tmp_path, monkeypatch, capsys):
    """Who did what at the pages, and the checks started from one, are in the saved copy for the
    Activity and Checks pages to show. The address in each row is replaced on the server, and
    the accounts, sessions and sign-ins never leave it."""
    import sqlite3

    here = "203.0.113.9"
    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    pages_used(base, here).close()
    target = tmp_path / "dataset"
    assert demo.save(folder, target, NOON) == 0
    said = capsys.readouterr().out
    assert "came down (2 rows), each address in it replaced by '(not kept)'" in said
    assert not (target / "web-record.db").exists()
    assert here.encode() not in (target / "web.db").read_bytes()
    web = sqlite3.connect(target / "web.db")
    assert web.execute("SELECT who, address, action, target FROM web_actionrecord").fetchall() == [
        ("ops", "(not kept)", "viewed a server's results", "db-1")
    ]
    assert web.execute("SELECT who, address, hosts, ended FROM web_checkrun").fetchall() == [
        ("ops", "(not kept)", '["db-1"]', "finished")
    ]
    for table in ("auth_user", "django_session", "web_loginattempt"):
        assert web.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), table  # noqa: S608
    # The record is still one that can only be added to.
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        web.execute("DELETE FROM web_actionrecord")
    web.close()
    about = json.loads((target / "demo.json").read_text())
    assert about["pages_record"].startswith("1 lines of who did what at the pages and 1 checks")
    # And the checker's own code reads them, as its Activity and Checks pages do.
    read = subprocess.run(
        [sys.executable, "-c", demo._NEW_ACCOUNTS + READ_THE_RECORD, str(target)],
        cwd=Path(demo.__file__).resolve().parents[2],
        env={**os.environ, "CHECKER_HOME": str(target)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert read.returncode == 0, read.stderr
    assert read.stdout.split() == ["ops", "(not", "kept)", "ops", "finished", "0"]
    assert all(p.stat().st_mode & 0o077 == 0 for p in target.rglob("*"))


def test_what_is_sent_of_the_pages_record_never_held_the_address(tmp_path, monkeypatch):
    """Looked for in the tar itself, as it leaves the server."""
    here = "203.0.113.9"
    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    pages_used(base, here).close()
    work = tmp_path / "work"
    work.mkdir()
    archive, sent, _, _ = demo.fetch(Home(base), work)
    assert here.encode() not in archive.read_bytes() and b"session data" not in archive.read_bytes()
    assert b"(not kept)" in archive.read_bytes() and sent == 9


def test_a_pages_record_with_an_address_left_in_or_a_line_naming_it_stops_the_save(
    tmp_path, monkeypatch, capsys
):
    import sqlite3

    here = "203.0.113.9"
    folder, base, store = saving(tmp_path, monkeypatch)
    store.close()
    web = pages_used(base, here)
    # A line whose own words hold the address: the server replaces the address column only.
    web.execute(
        "INSERT INTO web_actionrecord (at, who, address, action, target, outcome, detail)"
        " VALUES ('2026-11-11 06:00:00', 'ops', 'x', 'signed in', '', 'done', ?)",
        (f"from {here}",),
    )
    web.commit()
    web.close()
    assert demo.save(folder, tmp_path / "dataset", NOON) == 1
    assert "FAIL the pages' record's table web_actionrecord: names this machine" in (
        capsys.readouterr().out
    )
    # And a server that didn't replace one isn't believed.
    came = tmp_path / "came"
    came.mkdir()
    (came / "keys").mkdir()
    record = sqlite3.connect(came / "web-record.db")
    record.execute("CREATE TABLE web_checkrun (id INTEGER PRIMARY KEY, kind TEXT, address TEXT)")
    record.execute("INSERT INTO web_checkrun VALUES (1, 'check', ?)", (here,))
    record.commit()
    record.close()
    with pytest.raises(demo.DemoError, match="with its address still in"):
        demo.record_here(came)


def test_the_screenshot_script_wont_delete_a_saved_datasets_record(tmp_path):
    """It deletes web.db for its own throwaway account; in a saved dataset that file is the only
    copy of the record of the pages' use."""
    pytest.importorskip("playwright")
    (tmp_path / "demo.json").write_text("{}")
    (tmp_path / "demo-protect.json").write_text("[]")
    (tmp_path / "web.db").write_text("the record")
    done = subprocess.run(
        [sys.executable, str(HERE / "screenshots.py"), "--home", str(tmp_path), "--out", "x"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 1 and "is a saved demo dataset" in done.stderr
    assert (tmp_path / "web.db").read_text() == "the record" and not (tmp_path / "x").exists()
