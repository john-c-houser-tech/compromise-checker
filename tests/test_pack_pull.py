"""`checker packs pull` and `checker packs index` (plan 4.7). The packs
repository is made here, in memory, signed with throwaway keys standing in
for NouriLoop's root and pack keys; nothing is downloaded."""

import hashlib
import io
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

import pytest
from test_pack_format import GOOD
from test_pack_trust import Key, key_list
from test_pack_trust import nouriloop as nouriloop_fixture

from checker import cli
from checker.checks import load_checks
from checker.evidence import load_config
from checker.packs import pull as pulling
from checker.packs.pull import DEFAULT_SOURCE, PullError, fetch, pull, read_index, staleness
from checker.packs.release import ReleaseError, write_index
from checker.packs.state import read_state
from checker.packs.store import active, retired

SOURCE = "https://packs.example.org/"
NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)
NEWER = GOOD.replace("version: 2", "version: 3")
ZEROS = '"' + "0" * 64 + '"'  # a hash of digits only, quoted as an index writes it


class Repository:
    """A packs repository: files by URL, signed as a release is."""

    def __init__(self, root, signer, serial=1):
        self.files = {}
        self.signer = signer
        self.keys(root, serial, [signer])

    def put(self, name, data, signer=None):
        self.files[SOURCE + name] = data
        self.files[SOURCE + name + ".minisig"] = (signer or self.signer).sign(data)

    def keys(self, root, serial, trusted, revoked=()):
        data, signature = key_list(root, serial, trusted, revoked)
        self.files[SOURCE + "keys.yaml"], self.files[SOURCE + "keys.yaml.minisig"] = data, signature

    def index(self, serial, packs, withdrawn=(), issued=NOW, signer=None):
        lines = [f"format: 1\nserial: {serial}\nissued: {issued:%Y-%m-%dT%H:%M:%SZ}\npacks:"]
        for text in packs:
            pack_id, version = _id_version(text)
            sha = hashlib.sha256(text.encode()).hexdigest()
            lines.append(f'  - {{id: {pack_id}, version: {version}, sha256: "{sha}"}}')
            self.put(f"packs/{pack_id}/PACK.yaml", text.encode())
        lines.append("withdrawn:")
        lines += [f"  - {{id: {i}, reason: no longer needed}}" for i in withdrawn]
        text = "\n".join(lines).replace("packs:\nwithdrawn:", "packs: []\nwithdrawn:") + "\n"
        text = text.replace("withdrawn:\n", "withdrawn: []\n") if not withdrawn else text
        self.put("index.yaml", text.encode(), signer)

    def get(self, url, limit):
        data = self.files.get(url)
        assert data is None or len(data) <= limit
        return data


def _id_version(text):
    fields = dict(line.split(": ", 1) for line in text.splitlines()[:3] if ": " in line)
    return fields["id"].strip('"'), int(fields["version"])


nouriloop = pytest.fixture(nouriloop_fixture.__wrapped__)


@pytest.fixture
def repo(nouriloop, home):
    return Repository(nouriloop, Key())


def run(home, repo, now=NOW):
    base = home[0]
    return pull(base, load_config(base).packs.trusted_keys, load_checks(), SOURCE, repo.get, now)


def in_force(home):
    keys = load_config(home[0]).packs.trusted_keys
    return [(s.pack.id, s.pack.version) for s in active(home[0], keys)[0]]


def test_a_pull_takes_the_key_list_then_the_packs_it_signs(home, repo):
    repo.index(1, [GOOD])
    done = run(home, repo)
    assert done.key_list == (1, None)
    assert done.added == [("example-2026-10", 2, "added")]
    assert in_force(home) == [("example-2026-10", 2)]
    assert read_state(home[0])["index_serial"] == 1
    again = run(home, repo)
    assert (again.key_list, again.added, again.problems) == (None, [], [])


def test_a_newer_version_replaces_the_older(home, repo):
    repo.index(1, [GOOD])
    run(home, repo)
    repo.index(2, [NEWER])
    assert run(home, repo).added == [("example-2026-10", 3, "added, replacing version 2")]


def test_an_index_signed_by_any_other_key_is_refused(home, repo):
    repo.index(1, [GOOD], signer=Key())
    with pytest.raises(PullError, match="the index's signature"):
        run(home, repo)
    assert in_force(home) == []


def test_an_older_index_is_refused_and_the_same_one_is_nothing_new(home, repo):
    repo.index(5, [GOOD])
    run(home, repo)
    repo.index(4, [NEWER])
    with pytest.raises(PullError, match="lower than one accepted before"):
        run(home, repo)
    assert in_force(home) == [("example-2026-10", 2)]


def test_a_file_without_the_index_hash_isnt_added(home, repo):
    repo.index(1, [GOOD])
    repo.put("packs/example-2026-10/PACK.yaml", GOOD.replace("Example", "Changed").encode())
    done = run(home, repo)
    assert done.added == [] and "doesn't have the hash the index gives" in done.problems[0]
    assert in_force(home) == []


def test_a_pack_a_person_retired_isnt_brought_back(home, repo, capsys):
    repo.index(1, [GOOD])
    run(home, repo)
    assert cli.main(["packs", "retire", "example-2026-10", "--reason", "noisy here"]) == 0
    repo.index(2, [GOOD])
    assert run(home, repo).added == []
    assert in_force(home) == []


def test_a_withdrawn_pack_is_retired(home, repo):
    repo.index(1, [GOOD])
    run(home, repo)
    repo.index(2, [], withdrawn=["example-2026-10"])
    assert run(home, repo).withdrawn == ["example-2026-10-v2.yaml"]
    assert in_force(home) == []
    assert any("withdrawn by the packs source: no longer needed" in why
               for _, _, why in retired(home[0]))  # fmt: skip


def test_a_revoked_pack_key_takes_its_packs_and_its_index_with_it(nouriloop, home, repo):
    repo.index(1, [GOOD])
    run(home, repo)
    leaked = repo.signer
    fresh = Key()
    repo.keys(nouriloop, 2, [fresh], revoked=[leaked])
    repo.index(2, [GOOD])  # still signed by the leaked key
    with pytest.raises(PullError, match="the index's signature"):
        run(home, repo)
    assert in_force(home) == []  # retired as the new key list came in
    repo.signer = fresh
    repo.index(3, [NEWER])
    assert run(home, repo).added == [("example-2026-10", 3, "added")]


def test_an_older_key_list_at_the_source_is_a_problem(nouriloop, home, repo):
    repo.keys(nouriloop, 3, [repo.signer])
    repo.index(1, [GOOD])
    run(home, repo)
    repo.keys(nouriloop, 2, [repo.signer])
    assert "older than the one in force (3)" in run(home, repo).problems[0]


def test_an_old_index_is_pointed_out_on_the_pull_and_in_the_list(home, repo, capsys):
    repo.index(1, [GOOD], issued=NOW - timedelta(days=40))
    assert "issued 40 days ago" in run(home, repo).notes[0]
    said = staleness(read_state(home[0]), NOW)
    assert said.startswith("Last pull 2026-11-02T12:00: index issued 2026-09-23 (40 days ago);")
    assert "the source may have stopped updating" in said
    assert "older than expected" not in staleness(read_state(home[0]), NOW - timedelta(days=20))


def test_without_a_root_key_nothing_can_be_trusted(home, monkeypatch):
    monkeypatch.setattr("checker.packs.trust.ROOT_KEYS", ())
    repo = Repository(Key(), Key())
    repo.index(1, [GOOD])
    with pytest.raises(PullError, match="no NouriLoop root key yet"):
        run(home, repo)


def test_a_source_without_a_key_list_isnt_the_repository(home, repo):
    repo.index(1, [GOOD])
    run(home, repo)
    del repo.files[SOURCE + "keys.yaml"]
    with pytest.raises(PullError, match="has no keys.yaml"):
        run(home, repo)


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ("format: 1\nserial: 1\nissued: 2026-11-02T10:00:00\npacks: []\nwithdrawn: []\n",
         "needs its time zone"),
        ("format: 1\nserial: 0\nissued: 2026-11-02T10:00:00Z\npacks: []\nwithdrawn: []\n",
         "greater than or equal to 1"),
        ("format: 1\nserial: 1\nissued: 2026-11-02T10:00:00Z\npacks:\n"
         f"  - {{id: a-1, version: 1, sha256: {ZEROS}}}\n"
         f"  - {{id: a-1, version: 2, sha256: {ZEROS}}}\nwithdrawn: []\n", "lists a pack twice"),
        ("format: 1\nserial: 1\nissued: 2026-11-02T10:00:00Z\npacks:\n"
         f"  - {{id: a-1, version: 1, sha256: {ZEROS}}}\n"
         "withdrawn:\n  - {id: a-1, reason: x}\n", "both lists and withdraws"),
        ("format: 1\nserial: 1\nissued: 2026-11-02T10:00:00Z\npacks:\n"
         "  - {id: ../x, version: 1, sha256: ab}\nwithdrawn: []\n", "should match pattern"),
    ],
)  # fmt: skip
def test_what_an_index_cant_say(text, said):
    with pytest.raises(PullError, match=said):
        read_index(text.encode())


# --- The command ----------------------------------------------------------------------------


def test_the_command_says_what_changed(home, repo, monkeypatch, capsys):
    from checker.settings import change

    repo.index(1, [GOOD])
    monkeypatch.setattr(pulling, "fetch", repo.get)
    change(home[0], "packs.source", SOURCE)
    assert cli.main(["packs", "pull"]) == 0
    out = capsys.readouterr().out
    assert f"Pulling from {SOURCE}" in out
    assert "Key list serial 1 is in force." in out
    assert "example-2026-10 version 2: added." in out
    assert "`checker analyze --all`" in out
    assert cli.main(["packs", "pull"]) == 0
    assert "Nothing new." in capsys.readouterr().out
    assert cli.main(["packs", "list"]) == 0
    assert "Last pull " in capsys.readouterr().out


def test_the_command_refuses_a_source_that_isnt_https(home, capsys):
    assert cli.main(["packs", "pull", "--source", "http://packs.example.org/"]) == 2
    assert "must be an https:// address" in capsys.readouterr().err


def test_the_default_source_is_the_repository():
    from checker.evidence import Packs  # the setting's default and the module's agree

    assert Packs().source == DEFAULT_SOURCE


# --- Downloading -----------------------------------------------------------------------------


class Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_giving(result):
    class Opener:
        def open(self, request, timeout):
            assert request.full_url.startswith("https://") and timeout == pulling.TIMEOUT
            if isinstance(result, Exception):
                raise result
            return Answer(result)

    return lambda *handlers: Opener()


def test_fetch_only_over_https_and_within_its_limit(monkeypatch):
    with pytest.raises(PullError, match="only HTTPS"):
        fetch("http://packs.example.org/index.yaml", 10)
    monkeypatch.setattr(urllib.request, "build_opener", opener_giving(b"12345"))
    assert fetch(SOURCE + "x", 5) == b"12345"
    with pytest.raises(PullError, match="larger than 4 bytes"):
        fetch(SOURCE + "x", 4)
    missing = urllib.error.HTTPError(SOURCE, 404, "Not Found", {}, None)
    monkeypatch.setattr(urllib.request, "build_opener", opener_giving(missing))
    assert fetch(SOURCE + "x", 5) is None
    broken = urllib.error.HTTPError(SOURCE, 500, "Oops", {}, None)
    monkeypatch.setattr(urllib.request, "build_opener", opener_giving(broken))
    with pytest.raises(PullError, match="answered 500"):
        fetch(SOURCE + "x", 5)
    monkeypatch.setattr(urllib.request, "build_opener", opener_giving(OSError("no route")))
    with pytest.raises(PullError, match="no route"):
        fetch(SOURCE + "x", 5)


def test_a_redirect_away_from_https_is_refused():
    handler = pulling._HttpsOnly()
    request = urllib.request.Request(SOURCE + "index.yaml")  # noqa: S310 - never opened
    with pytest.raises(urllib.error.URLError, match="away from HTTPS"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://evil.example/")
    moved = handler.redirect_request(request, None, 302, "Found", {}, "https://cdn.example/x")
    assert moved.full_url == "https://cdn.example/x"


# --- Writing an index -------------------------------------------------------------------------


@pytest.fixture
def signer(nouriloop, tmp_path):
    """A pack key, trusted by the repository's keys.yaml (root-signed)."""
    key = Key()
    data, signature = key_list(nouriloop, 1, [key])
    (tmp_path / "keys.yaml").write_bytes(data)
    (tmp_path / "keys.yaml.minisig").write_bytes(signature)
    return key


def release(tmp_path, *texts, signer):
    for text in texts:
        pack_id, _ = _id_version(text)
        folder = tmp_path / "packs" / pack_id
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "PACK.yaml").write_text(text)
        (folder / "PACK.yaml.minisig").write_bytes(signer.sign(text.encode()))
    return tmp_path


def test_an_index_is_written_from_the_packs_and_reads_back(tmp_path, signer):
    path, index, _ = write_index(release(tmp_path, GOOD, signer=signer), None, {}, NOW)
    assert (index.serial, [(e.id, e.version) for e in index.packs]) == (
        1, [("example-2026-10", 2)])  # fmt: skip
    assert read_index(path.read_bytes()) == index
    assert index.packs[0].sha256 == hashlib.sha256(GOOD.encode()).hexdigest()
    _, again, _ = write_index(tmp_path, None, {"old-2026-01": 'too noisy: "x"'}, NOW)
    assert again.serial == 2 and again.withdrawn[0].reason == 'too noisy: "x"'
    _, third, _ = write_index(tmp_path, None, {}, NOW)
    assert third.serial == 3 and [w.id for w in third.withdrawn] == ["old-2026-01"]


@pytest.mark.parametrize(
    ("change", "said"),
    [
        (lambda d: (d / "packs" / "example-2026-10" / "PACK.yaml.minisig").unlink(),
         "needs PACK.yaml and PACK.yaml.minisig"),
        (lambda d: (d / "packs" / "example-2026-10").rename(d / "packs" / "other"),
         "holds example-2026-10: the folder is its id"),
        (lambda d: (d / "packs" / "example-2026-10" / "PACK.yaml").write_text("format: 9\n"),
         "PACK.yaml:"),
    ],
)  # fmt: skip
def test_what_stops_an_index_being_written(tmp_path, signer, change, said):
    release(tmp_path, GOOD, signer=signer)
    change(tmp_path)
    with pytest.raises(ReleaseError, match=said):
        write_index(tmp_path, None, {}, NOW)


def test_an_index_never_goes_backwards(tmp_path, signer):
    release(tmp_path, NEWER, signer=signer)
    write_index(tmp_path, 4, {}, NOW)
    with pytest.raises(ReleaseError, match="must go above the last index's"):
        write_index(tmp_path, 4, {}, NOW)
    release(tmp_path, GOOD, signer=signer)
    with pytest.raises(ReleaseError, match="older than the last index's"):
        write_index(tmp_path, None, {}, NOW)
    release(tmp_path, NEWER, signer=signer)
    with pytest.raises(ReleaseError, match="withdrawn but still in packs/"):
        write_index(tmp_path, None, {"example-2026-10": "gone"}, NOW)


def test_the_index_command(tmp_path, signer, capsys):
    release(tmp_path, GOOD, signer=signer)
    assert cli.main(["packs", "index", str(tmp_path), "--withdraw", "old-1=noisy"]) == 0
    out = capsys.readouterr().out
    assert "serial 1, 1 pack(s), 1 withdrawn" in out and "minisign -S -s" in out
    assert cli.main(["packs", "index", str(tmp_path), "--withdraw", "nothing"]) == 1
    assert "give ID=REASON" in capsys.readouterr().err


def test_an_organizations_own_key_cant_sign_nouriloops_index(home, repo, tmp_path, capsys):
    ours = Key()
    assert cli.main(["packs", "trust", "add", "team", str(ours.pub_file(tmp_path / "k.pub"))]) == 0
    repo.index(1, [GOOD], signer=ours)
    with pytest.raises(PullError, match="the index's signature"):
        run(home, repo)


# --- After review ----------------------------------------------------------------------------


def test_a_broken_connection_is_a_pull_error_not_a_crash(monkeypatch):
    import http.client

    for broken in (http.client.IncompleteRead(b"ab", 10), http.client.BadStatusLine("x")):
        monkeypatch.setattr(urllib.request, "build_opener", opener_giving(broken))
        with pytest.raises(PullError, match=type(broken).__name__):
            fetch(SOURCE + "x", 5)


def test_the_real_opener_follows_https_redirects_only():
    built = pulling.opener()
    redirects = [h for h in built.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert len(redirects) == 1 and isinstance(redirects[0], pulling._HttpsOnly)


def test_a_file_that_trickles_in_is_cut_off(monkeypatch):
    clock = iter(range(0, 10_000, 100))
    monkeypatch.setattr(pulling.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(urllib.request, "build_opener", opener_giving(b"x" * 300_000))
    with pytest.raises(PullError, match="took longer than 120 seconds"):
        fetch(SOURCE + "x", 400_000)


def test_an_organizations_own_pack_id_is_left_alone(home, repo, tmp_path, capsys):
    from test_pack_trust import pack

    ours = Key()
    assert cli.main(["packs", "trust", "add", "team", str(ours.pub_file(tmp_path / "k.pub"))]) == 0
    assert cli.main(["packs", "add", str(pack(tmp_path, ours))]) == 0
    repo.index(1, [NEWER])  # NouriLoop's index offers the same id
    done = run(home, repo)
    assert done.added == [] and done.problems == []
    assert "your organization's key signs this pack id here" in done.notes[0]
    repo.index(2, [], withdrawn=["example-2026-10"])
    assert run(home, repo).withdrawn == []
    assert in_force(home) == [("example-2026-10", 2)]


def test_a_mirror_cant_resign_a_pack_with_an_organization_key(home, repo, tmp_path, capsys):
    ours = Key()
    assert cli.main(["packs", "trust", "add", "team", str(ours.pub_file(tmp_path / "k.pub"))]) == 0
    repo.index(1, [GOOD])
    repo.files[SOURCE + "packs/example-2026-10/PACK.yaml.minisig"] = ours.sign(GOOD.encode())
    done = run(home, repo)
    assert done.added == [] and "not by one of NouriLoop's keys" in done.problems[0]
    assert read_state(home[0])["packs"] == {}  # nothing recorded for the id


def test_an_index_entry_naming_another_pack_writes_nothing(home, repo):
    other = GOOD.replace("id: example-2026-10", "id: other-2026-10")
    repo.index(1, [other])
    index = repo.files[SOURCE + "index.yaml"].replace(b"other-2026-10", b"example-2026-10")
    repo.put("index.yaml", index)
    repo.put("packs/example-2026-10/PACK.yaml", other.encode())
    done = run(home, repo)
    assert done.added == [] and "holds other-2026-10 version 2" in done.problems[0]
    assert in_force(home) == [] and read_state(home[0])["packs"] == {}


def test_what_a_pull_did_before_it_stopped_is_said(nouriloop, home, repo, monkeypatch, capsys):
    from checker.settings import change

    repo.index(1, [GOOD])
    run(home, repo)
    leaked = repo.signer
    repo.keys(nouriloop, 2, [Key()], revoked=[leaked])
    repo.index(2, [GOOD])  # still signed by the leaked key
    monkeypatch.setattr(pulling, "fetch", repo.get)
    change(home[0], "packs.source", SOURCE)
    capsys.readouterr()
    assert cli.main(["packs", "pull"]) == 1
    said = capsys.readouterr()
    assert "Key list serial 2 is in force (was 1)." in said.out
    assert "Retired example-2026-10-v2.yaml: its signing key is no longer trusted." in said.out
    assert "nothing more was pulled: the index's signature" in said.err


def test_problems_make_the_command_exit_1_and_aren_t_nothing_new(home, repo, monkeypatch, capsys):
    from checker.settings import change

    repo.index(1, [GOOD])
    repo.put("packs/example-2026-10/PACK.yaml", b"format: 1\n")
    monkeypatch.setattr(pulling, "fetch", repo.get)
    change(home[0], "packs.source", SOURCE)
    capsys.readouterr()
    assert cli.main(["packs", "pull"]) == 1
    said = capsys.readouterr()
    assert "Nothing new." not in said.out and "doesn't have the hash" in said.err


def test_a_pull_that_fails_late_still_raises_the_floor(home, repo, monkeypatch):
    repo.index(5, [GOOD])

    def failing(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("checker.packs.store.add", failing)
    with pytest.raises(OSError):
        run(home, repo)
    assert read_state(home[0])["index_serial"] == 5


def test_two_indexes_under_one_serial_are_refused(home, repo):
    repo.index(3, [GOOD])
    run(home, repo)
    repo.index(3, [NEWER])
    with pytest.raises(PullError, match="differs from the one accepted before under the same"):
        run(home, repo)


def test_an_index_from_the_future_is_pointed_out(home, repo):
    repo.index(1, [GOOD], issued=NOW + timedelta(days=3))
    assert "ahead of this machine's clock" in run(home, repo).notes[0]


def test_a_pack_retired_by_hand_stays_retired_whatever_version_comes(home, repo, capsys):
    repo.index(1, [GOOD])
    run(home, repo)
    assert cli.main(["packs", "retire", "example-2026-10", "--reason", "noisy here"]) == 0
    repo.index(2, [NEWER])
    done = run(home, repo)
    assert done.added == [] and "retired here by hand" in done.notes[0]
    assert in_force(home) == []


def test_a_changed_pack_under_an_accepted_version_is_a_problem(home, repo):
    repo.index(1, [GOOD])
    run(home, repo)
    changed = GOOD.replace("Example: a made-up", "Example: a changed")
    repo.index(2, [changed])
    assert "isn't the one accepted here under that version" in run(home, repo).problems[0]


@pytest.mark.parametrize(
    "text",
    ['source: "https://evil\\u001b[2J.example/"', "source: https://user:pw@mirror.example/"],
)
def test_a_source_with_control_characters_or_credentials_is_refused(text):
    import yaml
    from pydantic import ValidationError

    from checker.evidence import Packs

    with pytest.raises(ValidationError, match="user name"):
        Packs.model_validate(yaml.safe_load(text))


def test_a_damaged_last_pull_record_doesnt_break_the_list():
    assert staleness({"last_pull": {"index_issued": "2026-10-01T00:00:00"}}, NOW) is None
    assert staleness({"last_pull": {"index_issued": 7}}, NOW) is None


def test_ids_that_look_like_other_things_and_any_reason_round_trip(tmp_path, signer):
    for pack_id in ("2026-10-30", "1e5", "null", "true"):
        text = GOOD.replace("id: example-2026-10", f'id: "{pack_id}"')
        release(tmp_path, text, signer=signer)
    path, index, _ = write_index(tmp_path, None, {"gone-1": 'noisy 🦝 "quoted" \\ back'}, NOW)
    assert read_index(path.read_bytes()) == index
    assert {e.id for e in index.packs} >= {"2026-10-30", "1e5", "null", "true"}


def test_a_release_needs_every_pack_signed_by_a_pack_key(tmp_path, signer):
    release(tmp_path, GOOD, signer=Key())
    with pytest.raises(ReleaseError, match="isn't a pack key's from keys.yaml"):
        write_index(tmp_path, None, {}, NOW)
    (tmp_path / "keys.yaml").unlink()
    with pytest.raises(ReleaseError, match="needs keys.yaml"):
        write_index(tmp_path, None, {}, NOW)


def test_a_release_refuses_a_changed_pack_under_the_same_version(tmp_path, signer):
    release(tmp_path, GOOD, signer=signer)
    write_index(tmp_path, None, {}, NOW)
    release(tmp_path, GOOD.replace("Example: a made-up", "Example: a changed"), signer=signer)
    with pytest.raises(ReleaseError, match="changed under the same version"):
        write_index(tmp_path, None, {}, NOW)


def test_a_withdrawal_can_be_forgotten(tmp_path, signer):
    write_index(tmp_path, None, {"old-1": "noisy"}, NOW)
    _, index, _ = write_index(tmp_path, None, {}, NOW, forget=("old-1",))
    assert index.withdrawn == []
    with pytest.raises(ReleaseError, match="isn't withdrawn"):
        write_index(tmp_path, None, {}, NOW, forget=("old-1",))


# --- After the second review ---------------------------------------------------------------


def test_a_server_sending_a_byte_at_a_time_is_cut_off_at_the_deadline(monkeypatch):
    import http.client
    import socket
    import threading
    import time

    ours, theirs = socket.socketpair()
    ours.settimeout(1.0)
    stop = threading.Event()

    def trickle():
        theirs.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        while not stop.is_set():
            try:
                theirs.sendall(b"x")
            except OSError:
                return
            time.sleep(0.05)

    threading.Thread(target=trickle, daemon=True).start()
    response = http.client.HTTPResponse(ours)
    response.begin()

    class Opener:
        def open(self, request, timeout):
            return response

    monkeypatch.setattr(pulling, "opener", lambda: Opener())
    monkeypatch.setattr(pulling, "DEADLINE", 0.3)
    started = time.monotonic()
    try:
        with pytest.raises(PullError, match="took longer than"):
            fetch(SOURCE + "x", 2000)
        assert time.monotonic() - started < 1.5
    finally:
        stop.set()
        theirs.close()


def test_what_a_pull_did_is_said_whatever_stops_it(nouriloop, home, repo, monkeypatch, capsys):
    from checker.settings import change

    repo.keys(nouriloop, 2, [repo.signer])
    repo.index(1, [GOOD])

    def full(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("checker.packs.store.add", full)
    monkeypatch.setattr(pulling, "fetch", repo.get)
    change(home[0], "packs.source", SOURCE)
    capsys.readouterr()
    assert cli.main(["packs", "pull"]) == 1
    said = capsys.readouterr()
    assert "Key list serial 2 is in force." in said.out and "disk full" in said.err


def test_a_pack_out_of_use_can_still_be_held_back_from_pulls(home, repo, capsys):
    repo.index(1, [GOOD])
    run(home, repo)
    repo.index(2, [], withdrawn=["example-2026-10"])
    run(home, repo)
    assert cli.main(["packs", "retire", "example-2026-10", "--reason", "keep it out"]) == 0
    assert "pulls leave it out until it is added again" in capsys.readouterr().out
    repo.index(3, [NEWER])
    assert run(home, repo).added == []
    assert cli.main(["packs", "retire", "never-seen", "--reason", "x"]) == 1


def test_an_index_ahead_of_the_clock_is_said_in_the_list_too(home, repo):
    repo.index(1, [GOOD], issued=NOW + timedelta(days=400))
    run(home, repo)
    assert "ahead of this machine's clock" in staleness(read_state(home[0]), NOW)


def test_a_pack_in_force_with_no_record_isnt_replaced_on_a_guess(home, repo):
    from checker.packs.state import write_state

    repo.index(1, [GOOD])
    run(home, repo)
    state = read_state(home[0])
    state["packs"] = {}  # lost: an older backup restored
    write_state(home[0], state)
    repo.index(2, [GOOD.replace("Example: a made-up", "Example: a changed")])
    done = run(home, repo)
    assert done.added == [] and "has no record of" in done.problems[0]


def test_a_source_in_anything_but_ascii_is_refused():
    from pydantic import ValidationError

    from checker.evidence import Packs

    with pytest.raises(ValidationError, match="plain ASCII"):
        Packs(source="https://mirror" + chr(0x202E) + ".example/")


def test_a_relisted_pack_must_go_above_the_version_withdrawn(tmp_path, signer):
    release(tmp_path, GOOD, signer=signer)
    write_index(tmp_path, None, {}, NOW)
    import shutil

    shutil.rmtree(tmp_path / "packs" / "example-2026-10")
    _, index, _ = write_index(tmp_path, None, {"example-2026-10": "wrong"}, NOW)
    assert index.withdrawn[0].version == 2
    release(tmp_path, GOOD, signer=signer)
    with pytest.raises(ReleaseError, match="version 2 was withdrawn"):
        write_index(tmp_path, None, {}, NOW, forget=("example-2026-10",))
    release(tmp_path, NEWER, signer=signer)
    _, index, _ = write_index(tmp_path, None, {}, NOW, forget=("example-2026-10",))
    assert [e.version for e in index.packs] == [3] and index.withdrawn == []


def test_a_pack_dropped_without_a_withdrawal_is_pointed_out(tmp_path, signer):
    import shutil

    release(tmp_path, GOOD, signer=signer)
    write_index(tmp_path, None, {}, NOW)
    shutil.rmtree(tmp_path / "packs" / "example-2026-10")
    _, _, warnings = write_index(tmp_path, None, {}, NOW)
    assert "neither in packs/ nor withdrawn" in warnings[0]
