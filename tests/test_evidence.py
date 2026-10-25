"""Evidence bundles: encryption as data streams in, hashes, custody, verification."""

import asyncio
import gzip
import json
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime

import pytest

from checker import cli
from checker.collect import collect_hosts
from checker.evidence import (
    BundleWriter,
    EvidenceError,
    Store,
    database_file,
    initialise,
    load_config,
    load_identity,
    open_bundle,
)
from checker.inventory import Host
from checker.protocol import Limits, Settings, build_program

LIMITS = Limits(overall_seconds=60, module_seconds=30, source_bytes=1 << 20)


def real_stream(run_id: str = "evidence-run") -> bytes:
    settings = Settings(
        run_id=run_id, since=datetime(2026, 9, 25, tzinfo=UTC), modules=None, limits=LIMITS
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
    assert not (checker_home / "keys").exists()
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
        checker_home, config, [target_host(server)], known_hosts=server.known, limits=LIMITS
    )
    [outcome] = outcomes
    assert outcome.status == "complete" and outcome.error is None

    store = Store(database_file(checker_home))
    row = store.bundle(outcome.bundle_id)
    session = json.loads(row["session"])
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
        checker_home, config, [target_host(server)], known_hosts=server.known, limits=LIMITS
    )
    assert outcome.status == "empty"
    assert "a password is required" in outcome.error
    store = Store(database_file(checker_home))
    row = store.bundle(outcome.bundle_id)
    assert json.loads(row["session"])["exit_status"] == 1  # traces were left: keep the record


async def test_one_unreachable_host_does_not_stop_the_others(server, checker_home):
    config, _ = initialise(checker_home)
    unreachable = target_host(server, name="stranger", address="127.0.0.2")  # nothing listens
    outcomes = await collect_hosts(
        checker_home,
        config,
        [target_host(server), unreachable],
        known_hosts=server.known,
        limits=LIMITS,
    )
    by_host = {o.host: o for o in outcomes}
    assert by_host["web01"].status == "complete"
    assert by_host["stranger"].status == "empty"
    assert by_host["stranger"].error.startswith("stranger: ")
