"""Evidence bundles: encryption as data streams in, hashes, custody, verification."""

import asyncio
import gzip
import json
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import asyncssh
import pytest

from checker import cli
from checker import collect as collect_module
from checker.collect import collect_hosts
from checker.evidence import (
    BUNDLE_COLUMNS,
    BundleWriter,
    EvidenceError,
    Store,
    Summary,
    database_file,
    initialise,
    judge,
    load_config,
    load_identity,
    open_bundle,
    open_text,
)
from checker.inventory import Host
from checker.protocol import MAX_RECORD, Limits, Settings, StreamReader, build_program

LIMITS = Limits(overall_seconds=60, module_seconds=30, source_bytes=1 << 20)
# One light module: the fake target runs the collector on the machine hosting
# the tests, where the heavy modules (package verification) take minutes.
MODULES = ["host_facts"]


def real_stream(run_id: str = "evidence-run") -> bytes:
    settings = Settings(
        run_id=run_id, since=datetime(2026, 9, 25, tzinfo=UTC), modules=MODULES, limits=LIMITS
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-"],
        input=build_program(settings).encode(),
        capture_output=True,
        timeout=60,
    )
    return result.stdout


@pytest.fixture
def checker_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKER_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def seal(home, data: bytes, pieces: int = 7):
    config, _ = initialise(home)
    writer = BundleWriter(home / "evidence" / "h" / "b.age", config.recipients)

    async def feed():
        step = max(1, len(data) // pieces)
        for start in range(0, len(data), step):
            await writer.write(data[start : start + step])

    asyncio.run(feed())
    return writer.seal(), config


# --- init -------------------------------------------------------------------------


def test_init_creates_key_config_and_database(checker_home):
    config, identity_path = initialise(checker_home)
    assert identity_path.stat().st_mode & 0o777 == 0o600
    assert (checker_home / "config.yaml").stat().st_mode & 0o777 == 0o600
    assert database_file(checker_home).stat().st_mode & 0o777 == 0o600
    assert str(load_identity(identity_path).to_public()) == config.recipients[0]
    assert load_config(checker_home) == config
    with pytest.raises(EvidenceError, match="already set up"):
        initialise(checker_home)


def test_init_with_an_outside_recipient_keeps_no_private_key(checker_home, tmp_path):
    from pyrage import x25519

    public = str(x25519.Identity.generate().to_public())
    config, identity_path = initialise(checker_home, public)
    assert identity_path is None and config.recipients == [public]
    # Only the mail key, which collection needs: no evidence identity.
    kept = {p.name for p in (checker_home / "keys").iterdir()} - {"mail-key.txt.lock"}
    assert kept == {"mail-key.txt"}
    with pytest.raises(EvidenceError, match="not an age public key"):
        initialise(tmp_path / "other", "age1notakey")


# --- writing bundles ---------------------------------------------------------------


def test_bundle_is_encrypted_hashed_and_checked(checker_home):
    data = real_stream()
    sealed, config = seal(checker_home, data)
    assert sealed.status == "complete"
    assert sealed.plaintext_bytes == len(data)
    assert sealed.path.read_bytes().startswith(b"age-encryption.org/v1")
    assert sealed.path.stat().st_mode & 0o777 == 0o600
    opened = open_bundle(sealed.path, load_identity(checker_home / "keys/evidence-identity.txt"))
    assert opened.sha256.hexdigest() == sealed.plaintext_sha256
    assert opened.status() == "complete"
    assert sealed.summary.manifest["run_id"] == "evidence-run"


def test_no_plaintext_reaches_the_controllers_disk(checker_home):
    data = real_stream(run_id="needle-4f1c9a52")
    seal(checker_home, data)
    plain = gzip.decompress(data)
    for path in checker_home.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert b"needle-4f1c9a52" not in content, path
            assert plain[:200] not in content, path


@pytest.mark.parametrize(
    ("data", "status"),
    [
        (b"", "empty"),
        (b"not gzip at all", "broken"),
    ],
)
def test_status_of_bad_streams(checker_home, data, status):
    sealed, _ = seal(checker_home, data)
    assert sealed.status == status


def test_cut_off_stream_is_incomplete(checker_home):
    data = real_stream()
    sealed, _ = seal(checker_home, data[: len(data) // 2])
    assert sealed.status == "incomplete"


def test_store_is_append_only(checker_home):
    initialise(checker_home)
    store = Store(database_file(checker_home))
    row = dict.fromkeys(
        (
            "id host run_id path started_at ended_at status collector_version collector_sha256"
            " plaintext_sha256 plaintext_bytes ciphertext_sha256 ciphertext_bytes recipients"
            " session summary problem"
        ).split(),
        "x",
    )
    store.record_bundle(row)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("UPDATE bundles SET status = 'complete'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("DELETE FROM custody")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute("DELETE FROM bundles")
    assert [r["action"] for r in store.custody_of("x")] == ["collected"]


# --- end to end over SSH --------------------------------------------------------------


def target_host(server, **overrides):
    values = dict(
        name="web01",
        address="127.0.0.1",
        port=server.port,
        user="scanner",
        auth="key",
        key_path=str(server.key_file),
        sudo="nopasswd",
    )
    values.update(overrides)
    return Host(**values)


async def test_collect_store_show_verify_and_detect_tampering(server, checker_home, capsys):
    config, _ = initialise(checker_home)
    outcomes = await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    [outcome] = outcomes
    assert outcome.status == "complete" and outcome.error is None

    store = Store(database_file(checker_home))
    row = store.bundle(outcome.bundle_id)
    identity = load_identity(checker_home / "keys/evidence-identity.txt")
    session = json.loads(open_text(row["session"], identity))
    assert session["client_key_fingerprint"] == server.client_key.get_fingerprint("sha256")
    sidecar = json.loads((checker_home / "evidence/web01" / f"{row['id']}.json").read_text())
    assert sidecar["ciphertext_sha256"] == row["ciphertext_sha256"]
    assert set(sidecar) == {
        "id",
        "host",
        "run_id",
        "started_at",
        "ended_at",
        "collector_sha256",
        "plaintext_sha256",
        "ciphertext_sha256",
    }
    store.close()

    args = cli.build_parser().parse_args(["bundle", "verify", outcome.bundle_id])
    assert cli.cmd_bundle_verify(args) == 0
    args = cli.build_parser().parse_args(["bundle", "show", outcome.bundle_id])
    assert cli.cmd_bundle_show(args) == 0
    shown = capsys.readouterr().out
    assert "Status     complete" in shown

    # Flip one byte of the encrypted file: verification must fail, and say so.
    path = checker_home / "evidence/web01" / f"{outcome.bundle_id}.age"
    damaged = bytearray(path.read_bytes())
    damaged[-10] ^= 0xFF
    path.write_bytes(bytes(damaged))
    args = cli.build_parser().parse_args(["bundle", "verify", outcome.bundle_id])
    assert cli.cmd_bundle_verify(args) == 1
    assert "FAIL  encrypted file matches its recorded hash" in capsys.readouterr().out

    store = Store(database_file(checker_home))
    actions = [r["action"] for r in store.custody_of(outcome.bundle_id)]
    assert actions == ["collected", "verified", "viewed", "verified"]
    verdicts = [
        json.loads(r["detail"])["passed"] for r in store.custody_of(outcome.bundle_id)[1::2]
    ]
    assert verdicts == [True, False]


async def test_failed_runs_are_recorded_with_their_session(server, checker_home):
    config, _ = initialise(checker_home)
    server.target.sudo_n_refuses = True
    [outcome] = await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    assert outcome.status == "empty"
    assert "a password is required" in outcome.error
    store = Store(database_file(checker_home))
    row = store.bundle(outcome.bundle_id)
    identity = load_identity(checker_home / "keys/evidence-identity.txt")
    session = json.loads(open_text(row["session"], identity))
    assert session["exit_status"] == 1  # traces were left: keep the record
    assert "a password is required" in open_text(row["problem"], identity)


async def test_the_index_holds_no_readable_details(server, checker_home):
    config, _ = initialise(checker_home)
    await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    database = database_file(checker_home).read_bytes()
    # (The custody log names the controller's own host, as the policy says; the
    # fake target is this machine, so its hostname can't be used as a probe here.)
    machine_id = Path("/etc/machine-id").read_bytes().strip()
    for detail in (
        machine_id,  # collected by host_facts from the target
        b"127.0.0.1",  # the target's address
        b"scanner",  # the login account
        server.client_key.get_fingerprint("sha256").encode(),
        b"host_facts",  # what was collected
    ):
        assert detail not in database, detail


async def test_one_unreachable_host_does_not_stop_the_others(server, checker_home):
    config, _ = initialise(checker_home)
    unreachable = target_host(server, name="stranger", address="127.0.0.2")  # nothing listens
    outcomes = await collect_hosts(
        checker_home,
        config,
        [target_host(server), unreachable],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    by_host = {o.host: o for o in outcomes}
    assert by_host["web01"].status == "complete"
    assert by_host["stranger"].status == "empty"
    assert by_host["stranger"].error.startswith("stranger: ")


# --- Review fixes (Copilot on PR #8) ------------------------------------------------


def stream_of(*records) -> bytes:
    return gzip.compress(b"".join(json.dumps(r).encode() + b"\n" for r in records))


def test_errors_never_quote_the_evidence(checker_home):
    manifest = json.loads(gzip.decompress(real_stream()).splitlines()[0])
    secret = "SECRET-PAYLOAD-7f3a"
    bad_chunk = {
        "type": "chunk",
        "source_id": 1,
        "seq": secret,
        "encoding": "utf-8",
        "data": secret,
    }
    start = {"type": "source_start", "source_id": 1, "module": "m", "kind": "file", "name": "/x"}
    sealed, _ = seal(checker_home, stream_of(manifest, start, bad_chunk))
    assert sealed.status == "broken"
    assert "seq" in sealed.problem
    assert secret not in sealed.problem
    not_json = gzip.compress(json.dumps(manifest).encode() + b"\n{" + secret.encode() + b"\n")
    sealed, _ = seal(checker_home / "again", not_json)
    assert secret not in sealed.problem


def test_a_decompression_bomb_is_refused_not_buffered(checker_home):
    bomb = gzip.compress(b"A" * (MAX_RECORD + 1024 * 1024))  # no newline, tiny when compressed
    assert len(bomb) < 100_000
    sealed, _ = seal(checker_home, bomb, pieces=1)
    assert sealed.status == "broken"
    assert "longer than" in sealed.problem


@pytest.mark.parametrize("pieces", [1, 50])
def test_data_after_the_gzip_stream_is_rejected_however_it_arrives(checker_home, pieces):
    sealed, _ = seal(checker_home, real_stream() + b"appended junk", pieces=pieces)
    assert sealed.status == "broken"
    assert "after the end of the gzip stream" in sealed.problem


def test_concurrent_inits_leave_a_readable_setup(tmp_path):
    home = tmp_path / "home"
    code = (
        "import sys; from pathlib import Path; from checker.evidence import initialise;"
        " initialise(Path(sys.argv[1]))"
    )

    def init(_):
        return subprocess.run(
            [sys.executable, "-c", code, str(home)], capture_output=True, timeout=60
        ).returncode

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(init, range(8)))
    assert codes.count(0) == 1
    config = load_config(home)
    identity = load_identity(Path(config.identity_file))
    assert str(identity.to_public()) == config.recipients[0]


async def test_verify_checks_every_sidecar_field_and_survives_a_damaged_one(
    server, checker_home, capsys
):
    config, _ = initialise(checker_home)
    [outcome] = await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    sidecar = checker_home / "evidence/web01" / f"{outcome.bundle_id}.json"
    original = json.loads(sidecar.read_text())

    def verify():
        args = cli.build_parser().parse_args(["bundle", "verify", outcome.bundle_id])
        return cli.cmd_bundle_verify(args)

    sidecar.write_text(json.dumps(dict(original, run_id="someone-else")))
    assert verify() == 1
    assert "FAIL  sidecar run_id agrees with the database" in capsys.readouterr().out
    for damaged in ("{not json", "[1, 2]"):
        sidecar.write_text(damaged)
        assert verify() == 1
    store = Store(database_file(checker_home))
    verdicts = [r["action"] for r in store.custody_of(outcome.bundle_id)]
    assert verdicts.count("verified") == 3  # every attempt logged, none crashed


async def test_hosts_whose_bundle_cannot_be_recorded_are_reported(
    server, checker_home, monkeypatch
):
    config, _ = initialise(checker_home)

    def broken_writer(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(collect_module, "BundleWriter", broken_writer)
    [outcome] = await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    assert outcome.status == "not_recorded"
    assert "disk full" in outcome.error


# --- Copilot's second review of PR #8 -------------------------------------------------


def test_judge_uses_the_run_id_echo_and_the_exit_status():
    manifest = {"run_id": "mine"}
    assert judge("complete", manifest, "mine", 0) == ("complete", None)
    assert judge("complete", {"run_id": "other"}, "mine", 0)[0] == "broken"
    assert judge("complete", manifest, "mine", 1)[0] == "incomplete"
    assert judge("complete", manifest, "mine", None)[0] == "incomplete"
    assert judge("refused", {"run_id": None}, "mine", 0) == ("refused", None)
    assert judge("broken", None, "mine", 0) == ("broken", None)


def test_insert_or_replace_cannot_bypass_append_only(checker_home):
    initialise(checker_home)
    store = Store(database_file(checker_home))
    row = dict.fromkeys(BUNDLE_COLUMNS, "x")
    store.record_bundle(row)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        columns = ", ".join(BUNDLE_COLUMNS)
        marks = ", ".join("?" for _ in BUNDLE_COLUMNS)
        store._db.execute(
            f"INSERT OR REPLACE INTO bundles ({columns}) VALUES ({marks})",  # noqa: S608
            ["x"] + ["forged"] * (len(BUNDLE_COLUMNS) - 1),
        )
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._db.execute(
            "INSERT OR REPLACE INTO custody (seq, bundle_id, at, action, operator, controller)"
            " VALUES (1, 'x', 'now', 'forged', 'me', 'here')"
        )


def test_errors_quote_neither_type_tags_nor_dictionary_keys(checker_home):
    manifest = json.loads(gzip.decompress(real_stream()).splitlines()[0])
    secret = "SECRET-TAG-91b2"
    bad_type = {"type": secret}
    sealed, _ = seal(checker_home, stream_of(manifest, bad_type))
    assert sealed.status == "broken" and secret not in sealed.problem
    trailer_with_bad_key = {
        "type": "trailer",
        "finished_at": "2026-10-25T00:00:00+00:00",
        "duration_seconds": 1,
        "status": "complete",
        "counts": {"records": 0, "sources": 0, "chunks": 0, "errors": 0},
        "modules": {secret: {"status": "nonsense", "seconds": 1}},
    }
    sealed, _ = seal(checker_home / "again", stream_of(manifest, trailer_with_bad_key))
    assert sealed.status == "broken"
    assert secret not in sealed.problem
    assert "modules.?.status" in sealed.problem


def test_records_are_streamed_not_accumulated():
    data = real_stream()
    reader = StreamReader()
    stream = reader.feed(data)
    first = next(stream)  # available before the rest of the input is decoded
    assert first.type == "manifest"
    assert list(stream)[-1].type == "trailer"


async def test_refused_login_keeps_what_was_tried(server, checker_home):
    config, _ = initialise(checker_home)
    stranger_key = checker_home.parent / "stranger_key"
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(stranger_key)
    [outcome] = await collect_hosts(
        checker_home,
        config,
        [target_host(server, key_path=str(stranger_key))],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    assert "login refused" in outcome.error
    store = Store(database_file(checker_home))
    identity = load_identity(checker_home / "keys/evidence-identity.txt")
    session = json.loads(open_text(store.bundle(outcome.bundle_id)["session"], identity))
    assert session["offered_key_fingerprints"]  # sshd logged this attempt; so do we
    assert session["error"].endswith("login refused for scanner")


async def test_verify_reports_an_unreadable_bundle_instead_of_crashing(
    server, checker_home, capsys
):
    config, _ = initialise(checker_home)
    [outcome] = await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    path = checker_home / "evidence/web01" / f"{outcome.bundle_id}.age"
    path.unlink()
    path.mkdir()  # now a directory: reading it raises IsADirectoryError
    args = cli.build_parser().parse_args(["bundle", "verify", outcome.bundle_id])
    assert cli.cmd_bundle_verify(args) == 1
    assert "FAIL  encrypted file readable (IsADirectoryError)" in capsys.readouterr().out


# --- Copilot's third review of PR #8 (requested by John) ----------------------------


def test_summary_is_bounded_however_many_errors_a_target_sends(checker_home):
    manifest = json.loads(gzip.decompress(real_stream()).splitlines()[0])
    flood = Summary.MAX_ERRORS + 500
    errors = [{"type": "error", "module": "m", "message": "x" * 2000}] * flood
    trailer = {
        "type": "trailer",
        "finished_at": "2026-10-25T00:00:00+00:00",
        "duration_seconds": 1,
        "status": "complete",
        "counts": {"records": 0, "sources": 0, "chunks": 0, "errors": flood},
        "modules": {},
    }
    sealed, _ = seal(checker_home, stream_of(manifest, *errors, trailer), pieces=3)
    summary = sealed.summary.as_dict()
    assert len(summary["errors"]) == Summary.MAX_ERRORS
    assert summary["dropped"] == {"errors": 500}
    assert all(len(e["message"]) == Summary.MAX_MESSAGE for e in summary["errors"])
    assert sealed.status == "complete"  # the bundle itself still holds everything


def test_a_source_cut_off_midway_stays_in_the_summary(checker_home):
    manifest = json.loads(gzip.decompress(real_stream()).splitlines()[0])
    start = {
        "type": "source_start",
        "source_id": 1,
        "module": "auth_log",
        "kind": "file",
        "name": "/var/log/secure",
        "meta": {"size": 10},
    }
    chunk = {"type": "chunk", "source_id": 1, "seq": 0, "encoding": "utf-8", "data": "abc"}
    sealed, _ = seal(checker_home, stream_of(manifest, start, chunk))  # no end, no trailer
    [source] = sealed.summary.as_dict()["sources"]
    assert source["name"] == "/var/log/secure"
    assert source["truncated_reason"] == "unfinished" and source["bytes"] is None


async def test_show_displays_why_a_run_failed(server, checker_home, capsys):
    config, _ = initialise(checker_home)
    server.target.sudo_n_refuses = True
    [outcome] = await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    args = cli.build_parser().parse_args(["bundle", "show", outcome.bundle_id])
    assert cli.cmd_bundle_show(args) == 0
    assert "Problem    web01: sudo refused" in capsys.readouterr().out


async def test_verify_fails_when_the_named_key_cannot_be_loaded(server, checker_home, capsys):
    config, _ = initialise(checker_home)
    [outcome] = await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    missing = checker_home / "no-such-key.txt"
    args = cli.build_parser().parse_args(
        ["bundle", "verify", outcome.bundle_id, "--identity", str(missing)]
    )
    assert cli.cmd_bundle_verify(args) == 1
    out = capsys.readouterr().out
    assert "FAIL  evidence key loaded" in out and "Verified." not in out


async def test_refused_login_records_both_endpoints(server, checker_home):
    config, _ = initialise(checker_home)
    stranger_key = checker_home.parent / "stranger_key2"
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(stranger_key)
    [outcome] = await collect_hosts(
        checker_home,
        config,
        [target_host(server, key_path=str(stranger_key))],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    store = Store(database_file(checker_home))
    identity = load_identity(checker_home / "keys/evidence-identity.txt")
    session = json.loads(open_text(store.bundle(outcome.bundle_id)["session"], identity))
    assert session["remote_address"] == "127.0.0.1" and session["remote_port"] == server.port
    assert session["local_address"] == "127.0.0.1" and session["local_port"]


async def test_sealing_does_not_block_other_hosts(server, checker_home, monkeypatch):
    config, _ = initialise(checker_home)
    real_seal = collect_module.BundleWriter.seal
    gaps = []

    def slow_seal(self):
        time.sleep(0.5)  # a slow evidence disk
        return real_seal(self)

    async def ticker():
        last = time.monotonic()
        for _ in range(40):
            await asyncio.sleep(0.03)
            now = time.monotonic()
            gaps.append(now - last)
            last = now

    monkeypatch.setattr(collect_module.BundleWriter, "seal", slow_seal)
    await asyncio.gather(
        collect_hosts(
            checker_home,
            config,
            [target_host(server)],
            known_hosts=server.known,
            limits=LIMITS,
            modules=MODULES,
        ),
        ticker(),
    )
    assert max(gaps) < 0.3  # the loop kept turning while the bundle was sealed


async def test_collect_sends_the_configured_home_text(server, checker_home, monkeypatch):
    sent = []
    real = collect_module.build_program

    def capture(settings):
        sent.append(settings)
        return real(settings)

    monkeypatch.setattr(collect_module, "build_program", capture)
    config, _ = initialise(checker_home, home_text="privileged")
    await collect_hosts(
        checker_home,
        config,
        [target_host(server)],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    assert [s.home_text for s in sent] == ["privileged"]


async def test_each_host_gets_its_own_web_roots(server, checker_home, monkeypatch):
    sent = []
    real = collect_module.build_program

    def capture(settings):
        sent.append(settings)
        return real(settings)

    monkeypatch.setattr(collect_module, "build_program", capture)
    config, _ = initialise(checker_home)
    await collect_hosts(
        checker_home,
        config,
        [target_host(server, web_roots=["/srv/app"])],
        known_hosts=server.known,
        limits=LIMITS,
        modules=MODULES,
    )
    assert [s.web_roots for s in sent] == [["/srv/app"]]
