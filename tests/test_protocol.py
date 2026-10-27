"""Contract tests: the real collector's output against the controller's models."""

import gzip
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime

import pytest

from checker.protocol import (
    Chunk,
    Error,
    IncompleteStream,
    Limits,
    Manifest,
    ProtocolError,
    Settings,
    Trailer,
    build_program,
    collector_sha256,
    collector_source,
    parse_lines,
    read_stream,
)


def make_settings(**overrides):
    values = {
        "run_id": "run-1",
        "since": datetime(2026, 9, 25, tzinfo=UTC),
        "limits": Limits(overall_seconds=60, module_seconds=30, source_bytes=1 << 20),
    }
    values.update(overrides)
    return Settings(**values)


def run_program(program: str) -> bytes:
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-"],
        input=program.encode("utf-8"),
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


# --- Contract: real collector, real models ------------------------------------


def test_collector_output_matches_the_models():
    records = read_stream(run_program(build_program(make_settings())))
    manifest, trailer = records[0], records[-1]
    assert isinstance(manifest, Manifest)
    assert isinstance(trailer, Trailer)
    assert manifest.run_id == "run-1"
    assert manifest.settings["run_id"] == "run-1"
    assert trailer.status == "complete"


def test_settings_cannot_break_out_of_the_call():
    hostile = 'x")\nimport os; os.system("touch /tmp/pwned")  #   \\ "'
    records = read_stream(run_program(build_program(make_settings(run_id=hostile))))
    assert records[0].run_id == hostile
    assert records[-1].status == "complete"


def test_non_ascii_settings_survive_the_trip():
    run_id = "réseau-😀-运行"
    records = read_stream(run_program(build_program(make_settings(run_id=run_id))))
    assert records[0].run_id == run_id
    assert records[-1].status == "complete"


def raw_program(settings_json: str) -> str:
    """A program carrying settings the Settings model would never produce."""
    return collector_source() + "\nmain(" + json.dumps(settings_json) + ")\n"


@pytest.mark.parametrize(
    "settings_json",
    ["[]", '{"protocol": 1, "run_id": 5}', '"just a string"', "{not json"],
)
def test_refusals_of_malformed_settings_are_valid_streams(settings_json):
    records = read_stream(run_program(raw_program(settings_json)))
    assert records[-1].status == "refused"
    assert any(isinstance(r, Error) for r in records)


def test_refusal_is_a_valid_stream():
    settings = make_settings().model_dump(mode="json") | {"protocol": 2}
    records = read_stream(run_program(raw_program(json.dumps(settings))))
    assert records[-1].status == "refused"
    assert any(isinstance(r, Error) and "protocol" in r.message for r in records)


def test_fingerprint_is_sha256_of_the_shipped_text():
    expected = hashlib.sha256(collector_source().encode("utf-8")).hexdigest()
    assert collector_sha256() == expected
    assert build_program(make_settings()).startswith(collector_source().rstrip("\n"))


def test_settings_reject_naive_times_and_unknown_fields():
    with pytest.raises(ValueError):
        make_settings(since=datetime(2026, 9, 25))
    with pytest.raises(ValueError):
        Settings(**make_settings().model_dump(), extra_field=1)


# --- Stream checks on hand-built records --------------------------------------

MANIFEST = {
    "type": "manifest",
    "protocol": 1,
    "collector_version": "0.1.0.dev0",
    "run_id": "r",
    "started_at": "2026-10-25T00:00:00+00:00",
    "host": {
        "hostname": "h",
        "os_id": "ubuntu",
        "os_version_id": "24.04",
        "os_pretty_name": "Ubuntu 24.04",
        "kernel": "6.8.0",
        "machine": "x86_64",
        "boot_id": "b",
    },
    "python": {"version": "3.12.3", "executable": "/usr/bin/python3"},
    "effective_uid": 0,
    "settings": {},
    "modules_planned": ["auth_log"],
}
START = {
    "type": "source_start",
    "source_id": 1,
    "module": "auth_log",
    "kind": "file",
    "name": "/var/log/auth.log",
}


def chunk(seq, source_id=1):
    return {"type": "chunk", "source_id": source_id, "seq": seq, "encoding": "utf-8", "data": "x"}


def end(chunks, source_id=1):
    return {
        "type": "source_end",
        "source_id": source_id,
        "chunks": chunks,
        "bytes": chunks,
        "truncated": False,
    }


def trailer(sources=1, chunks=2, records=0, errors=0):
    return {
        "type": "trailer",
        "finished_at": "2026-10-25T00:00:01+00:00",
        "duration_seconds": 1.0,
        "status": "complete",
        "counts": {"records": records, "sources": sources, "chunks": chunks, "errors": errors},
        "modules": {"auth_log": {"status": "ok", "seconds": 0.5}},
    }


def lines(*records):
    return [json.dumps(r).encode() for r in records]


def test_valid_source_sequence():
    records = list(parse_lines(lines(MANIFEST, START, chunk(0), chunk(1), end(2), trailer())))
    assert [type(r).__name__ for r in records] == [
        "Manifest",
        "SourceStart",
        "Chunk",
        "Chunk",
        "SourceEnd",
        "Trailer",
    ]
    assert isinstance(records[2], Chunk)


@pytest.mark.parametrize(
    ("stream", "message"),
    [
        ((START, chunk(0), end(1), trailer(chunks=1)), "first record must be the manifest"),
        ((MANIFEST, START, chunk(1), end(1), trailer(chunks=1)), "expected 0"),
        ((MANIFEST, START, chunk(0), end(2), trailer(chunks=1)), "says 2 chunks"),
        ((MANIFEST, START, {"type": "error", "module": None, "message": "m"}), "not ended"),
        ((MANIFEST, chunk(0), trailer(sources=0, chunks=1)), "not open"),
        ((MANIFEST, START, chunk(0), end(1), trailer(chunks=5)), "trailer counts"),
        ((MANIFEST, trailer(sources=0, chunks=0), MANIFEST), "after the trailer"),
        ((MANIFEST, MANIFEST), "second manifest"),
        ((MANIFEST, {"type": "mystery"}), "line 2"),
        ((dict(MANIFEST, protocol=9),), "unsupported protocol"),
    ],
)
def test_broken_streams_are_rejected(stream, message):
    with pytest.raises(ProtocolError, match=message):
        list(parse_lines(lines(*stream)))


def test_invalid_base64_chunk_is_rejected():
    bad = dict(chunk(0), encoding="base64", data="!!!")
    with pytest.raises(ProtocolError, match="base64"):
        list(parse_lines(lines(MANIFEST, START, bad, end(1), trailer(chunks=1))))


def test_valid_base64_chunk_is_accepted():
    good = dict(chunk(0), encoding="base64", data="AAEC/w==")
    assert len(list(parse_lines(lines(MANIFEST, START, good, end(1), trailer(chunks=1))))) == 5


def test_newer_trailer_counters_are_ignored():
    newer = trailer(chunks=1)
    newer["counts"]["future_counter"] = 7
    records = list(parse_lines(lines(MANIFEST, START, chunk(0), end(1), newer)))
    assert records[-1].status == "complete"


def test_missing_trailer_is_incomplete():
    with pytest.raises(IncompleteStream):
        list(parse_lines(lines(MANIFEST, START, chunk(0), end(1))))


def test_cut_off_gzip_is_incomplete():
    data = gzip.compress(b"\n".join(lines(MANIFEST, trailer(sources=0, chunks=0))))
    with pytest.raises(IncompleteStream):
        read_stream(data[: len(data) // 2])


def test_not_gzip_is_a_protocol_error():
    with pytest.raises(ProtocolError, match="not a valid gzip stream"):
        read_stream(b"plain text")


def test_corrupt_deflate_data_is_a_protocol_error():
    data = bytearray(gzip.compress(b"x" * 1000))
    data[10:14] = b"\xff\xff\xff\xff"  # first bytes after the 10-byte gzip header
    with pytest.raises(ProtocolError, match="not a valid gzip stream") as info:
        read_stream(bytes(data))
    assert not isinstance(info.value, IncompleteStream)


# --- Contract with real modules, against a fixture server ---------------------


def test_modules_output_matches_the_models(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID="ubuntu"\nVERSION_ID="24.04"\n')
    log = tmp_path / "var/log"
    log.mkdir(parents=True)
    (log / "auth.log").write_bytes(
        b"2026-10-25T09:00:00+00:00 h sudo[1]: jch : COMMAND=/usr/bin/mysql -pSecret1\n"
    )
    (log / "auth.log.2.gz").write_bytes(gzip.compress(b"\xff\xfe not utf-8\n"))
    program = build_program(make_settings(modules=["host_facts", "auth_log"]))
    # Test-only: point the collector at the fixture directory (protocol.py never does).
    program = program.replace("\n\nmain(", f"\nROOT = {str(tmp_path)!r}\n\nmain(", 1)
    records = read_stream(run_program(program))

    assert records[0].host.os_id == "ubuntu"
    assert records[0].masking_version == 4
    assert records[-1].status == "complete"
    assert set(records[-1].modules) == {"host_facts", "auth_log"}
    chunks = [r for r in records if isinstance(r, Chunk)]
    assert {c.encoding for c in chunks} == {"utf-8", "base64"}
    assert all("Secret1" not in c.data for c in chunks)


def test_home_text_setting_reaches_the_collector():
    for value in ("off", "privileged", "all"):
        records = read_stream(run_program(build_program(make_settings(home_text=value))))
        assert records[0].settings["home_text"] == value
        assert records[-1].status == "complete"
    with pytest.raises(ValueError):
        make_settings(home_text="everyone")
