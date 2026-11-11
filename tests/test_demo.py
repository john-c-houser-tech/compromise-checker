"""The demo fleet's planning: its tags and end date, the commands it sends, and what `down`
deletes (the servers are only in the real run)."""

import importlib.util
import json
import re
import signal
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

    def run(self, command, timeout=900, input=None):
        self.calls.append((command, input))
        out, code = "", self.fails.get(next((k for k in self.fails if k in command), ""), 0)
        if "SSH_CLIENT" in command:
            out = "203.0.113.9 51234 22\n"
        if " run --all --unattended" in command:
            out = "".join(f"{name:20} complete     Low (5.0%)\n" for name in self.answering())
        if "date -d" in command:
            out = "14:00\n"
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
    monkeypatch.setattr(
        demo, "keypair", lambda folder, name: (folder / name, f"ssh-ed25519 {name}")
    )
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
