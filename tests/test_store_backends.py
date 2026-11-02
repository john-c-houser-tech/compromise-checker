"""The store's promises, on each database it can use (plan 5.14): append-only held by the database
itself, custody, purges that are all or nothing, one writer at a time. SQLite always; PostgreSQL
when CHECKER_TEST_POSTGRES names one to use up (a throwaway: each test gets a schema of its own)."""

import json
import os
import secrets
import threading
import time

import pytest

from checker.database import DATABASE_ERRORS, check_database_url
from checker.evidence import EvidenceError, Store, database_file

SERVER = os.environ.get("CHECKER_TEST_POSTGRES")
BACKENDS = ["sqlite", "postgres"] if SERVER else ["sqlite"]
APPEND_ONLY_TABLES = ["bundles", "custody", "baselines", "assessments", "advice", "purges",
                      "config_changes"]  # fmt: skip


def bundle_row(name, host="web01", started="2026-11-01T00:00:00+00:00"):
    return {
        "id": name,
        "host": host,
        "run_id": name,
        "path": f"/x/{name}.age",
        "started_at": started,
        "ended_at": started,
        "status": "complete",
        "collector_version": "t",
        "collector_sha256": "x",
        "plaintext_sha256": "x",
        "plaintext_bytes": 1,
        "ciphertext_sha256": "x",
        "ciphertext_bytes": 1,
        "recipients": "[]",
        "session": b"sealed\x00bytes",
        "summary": None,
        "problem": None,
    }


@pytest.fixture(params=BACKENDS)
def opened(request, tmp_path):
    """A way to open the store, as often as a test wants."""
    url = None
    schema = None
    if request.param == "postgres":
        import psycopg

        schema = f"t{secrets.token_hex(6)}"
        with psycopg.connect(SERVER, autocommit=True) as admin:
            admin.execute(f"CREATE SCHEMA {schema}")
        separator = "&" if "?" in SERVER else "?"
        url = f"{SERVER}{separator}options=-csearch_path%3D{schema}"
    stores = []

    def make(read_only=False):
        store = Store(database_file(tmp_path), read_only=read_only, url=url)
        stores.append(store)
        return store

    make.dialect = request.param
    make.path, make.url = database_file(tmp_path), url
    yield make
    for store in stores:
        store.close()
    if schema:
        with psycopg.connect(SERVER, autocommit=True) as admin:
            admin.execute(f"DROP SCHEMA {schema} CASCADE")


def filled(store):
    store.record_bundle(bundle_row("b1"))
    store.record_baseline("web01", "b1", "first", b"why")
    store.record_assessment(
        {
            "bundle_id": "b1",
            "host": "web01",
            "at": "2026-11-01T00:00:00+00:00",
            "checks_version": 1,
            "baseline_id": "b1",
            "path": "/x/a",
            "ciphertext_sha256": "x",
            "summary": b"s",
        }
    )
    store.record_advice(
        {
            "bundle_id": "b1",
            "host": "web01",
            "assessed_at": "t",
            "role": "explain",
            "at": "t",
            "status": "answered",
            "redaction": "strict",
            "model_asked": "m",
            "request": b"r",
        }
    )
    store.record_config_change("retention_days", 90, 30, lambda: None, lambda: None)
    store.purge(["b1"], {"host": "web01"}, {"web01": "emptied"})
    store.record_bundle(bundle_row("b1"))
    store.record_baseline("web01", "b1", "first", b"why")
    store.record_assessment(
        {
            "bundle_id": "b1",
            "host": "web01",
            "at": "2026-11-01T00:00:00+00:00",
            "checks_version": 1,
            "baseline_id": "b1",
            "path": "/x/a",
            "ciphertext_sha256": "x",
            "summary": b"s",
        }
    )
    store.record_advice(
        {
            "bundle_id": "b1",
            "host": "web01",
            "assessed_at": "t",
            "role": "explain",
            "at": "t",
            "status": "answered",
            "redaction": "strict",
            "model_asked": "m",
            "request": b"r",
        }
    )
    return store


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.parametrize("statement", ["UPDATE {} SET at = 'x'", "DELETE FROM {}"])
def test_the_database_itself_refuses_to_change_history(opened, table, statement):
    store = filled(opened())
    if table == "bundles":
        statement = statement.replace("at = 'x'", "status = 'x'")
    with pytest.raises(DATABASE_ERRORS, match="append-only"):
        with store._db:
            store._db.execute(statement.format(table))
    assert store._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] > 0  # noqa: S608


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
def test_truncate_is_refused_too(opened, table):
    if opened.dialect != "postgres":
        pytest.skip("SQLite has no TRUNCATE")
    store = filled(opened())
    with pytest.raises(DATABASE_ERRORS, match="append-only"):
        with store._db:
            store._db.execute(f"TRUNCATE {table} CASCADE")


def test_replacing_a_row_can_t_get_round_it(opened):
    store = filled(opened())
    with pytest.raises(DATABASE_ERRORS):
        store.record_bundle(bundle_row("b1"))
    assert len(store.bundles()) == 1


def test_a_purge_takes_everything_and_leaves_a_record_and_the_guards(opened):
    store = filled(opened())
    assert store.purge(["b1"], {"host": "web01"}, {"web01": "emptied"})["bundles"] == 1
    for table in ("bundles", "custody", "baselines", "assessments", "advice"):
        assert store._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0  # noqa: S608
    assert len(store.purges()) == 2
    record = store.purges()[-1]
    assert json.loads(record["bundles"]) == [["b1", "web01"]]
    store.record_bundle(bundle_row("b2"))
    with pytest.raises(DATABASE_ERRORS, match="append-only"):
        with store._db:
            store._db.execute("DELETE FROM bundles")


def test_a_purge_that_fails_changes_nothing_and_keeps_the_guards(opened, monkeypatch):
    store = filled(opened())
    real = store._db.restore_append_only

    class Boom(Exception):
        pass

    def fails():
        real()
        raise Boom

    monkeypatch.setattr(type(store._db), "restore_append_only", lambda self: fails())
    with pytest.raises(Boom):
        store.purge(["b1"], {"host": "web01"}, {"web01": "emptied"})
    monkeypatch.setattr(type(store._db), "restore_append_only", lambda self: real())
    assert len(store.bundles()) == 1 and len(store.custody_of("b1")) >= 1
    with pytest.raises(DATABASE_ERRORS, match="append-only"):
        with store._db:
            store._db.execute("DELETE FROM custody")


def test_a_purge_planned_on_old_facts_deletes_nothing(opened):
    store = filled(opened())
    state = store.purge_state("web01")
    store.record_bundle(bundle_row("b2"))
    with pytest.raises(EvidenceError, match="changed while"):
        store.purge(["b1"], {"host": "web01"}, {}, {"web01": state})
    assert len(store.bundles()) == 2


def test_rows_read_the_same(opened):
    store = opened()
    store.record_bundle(bundle_row("b1"))
    row = store.bundle("b1")
    assert row["id"] == "b1" and row[0] == "b1" and "id" in row.keys()
    assert dict(row)["host"] == "web01"
    assert bytes(row["session"]) == b"sealed\x00bytes" and row["summary"] is None
    assert row["plaintext_bytes"] == 1
    assert store.hosts() == ["web01"]


def test_a_derived_row_is_replaced(opened):
    store = opened()
    store.record_bundle(bundle_row("b1"))
    row = {"bundle_id": "b1", "kind": "events", "parser_version": 1, "path": "/a",
           "created_at": "t", "items": 1, "ciphertext_sha256": "x", "summary": None}  # fmt: skip
    store.record_derived(row)
    store.record_derived({**row, "parser_version": 2})
    assert store.derived("b1", "events")["parser_version"] == 2


def test_times_and_names_sort_by_bytes_as_they_do_in_sqlite(opened):
    store = opened()
    for name, host, at in (
        ("b1", "web-1", "2026-11-01T10:00:00+00:00"),
        ("b2", "WEB", "2026-11-01T09:00:00.5+00:00"),
        ("b3", "web_2", "2026-11-01T09:00:00+00:00"),
    ):
        store.record_bundle(bundle_row(name, host, at))
    assert store.hosts() == ["WEB", "web-1", "web_2"]
    assert [r["id"] for r in store.bundles()] == ["b3", "b2", "b1"]


def test_a_config_change_and_what_it_guards_happen_together(opened):
    store = opened()
    wrote = []
    store.record_config_change("x", 1, 2, lambda: wrote.append(1), lambda: None)
    assert wrote == [1] and len(store.config_changes()) == 1

    def fails():
        raise OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        store.record_config_change("y", 1, 2, fails, lambda: None)
    assert [r["setting"] for r in store.config_changes()] == ["x"]


def test_a_store_opened_for_looking_can_t_write(opened):
    opened().record_bundle(bundle_row("b1"))
    looking = opened(read_only=True)
    assert len(looking.bundles()) == 1
    with pytest.raises(DATABASE_ERRORS):
        looking.record_bundle(bundle_row("b2"))


def test_one_writer_at_a_time(opened):
    first_path, first_url = opened.path, opened.url
    first = opened()
    order = []
    first._db.begin_write()

    def other():
        # Its own connection, in its own thread, as another command would be.
        second = Store(first_path, url=first_url)
        second.record_config_change("y", 1, 2, lambda: order.append("second"), lambda: None)
        second.close()

    thread = threading.Thread(target=other)
    thread.start()
    time.sleep(0.5)
    order.append("first")
    first._db.commit()
    thread.join(timeout=30)
    assert order == ["first", "second"]


def test_a_guard_that_was_dropped_comes_back_on_opening(opened):
    store = opened()
    if opened.dialect == "postgres":
        store._db.execute("DROP TRIGGER custody_no_delete ON custody")
    else:
        store._db.execute("DROP TRIGGER custody_no_delete")
    store.record_bundle(bundle_row("b1"))
    again = opened()
    with pytest.raises(DATABASE_ERRORS, match="append-only"):
        with again._db:
            again._db.execute("DELETE FROM custody")


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://user:secret@localhost/checker",
        "postgresql://localhost/checker?password=secret",
        "postgresql://db.example.org/checker",
        "postgresql://db.example.org/checker?sslmode=prefer",
        "postgresql://db.example.org/checker?sslmode=disable",
        "postgresql:///checker?host=db.example.org",
        "mysql://localhost/checker",
        "/some/file",
    ],
)
def test_an_address_with_a_password_or_no_encryption_is_refused(url):
    with pytest.raises(ValueError, match="password|sslmode|postgresql://"):
        check_database_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "postgresql:///checker",
        "postgresql://localhost/checker",
        "postgresql://user@127.0.0.1:5433/checker",
        "postgresql:///checker?host=/run/postgresql",
        "postgresql://db.example.org/checker?sslmode=verify-full",
    ],
)
def test_a_good_address_is_kept(url):
    assert check_database_url(url) == url


def test_a_settings_file_that_can_t_be_read_never_reads_as_use_sqlite(tmp_path):
    (tmp_path / "config.yaml").write_text("database: [not: right\n")
    with pytest.raises(EvidenceError, match="settings file"):
        Store(database_file(tmp_path))
    assert not database_file(tmp_path).exists()


@pytest.fixture
def server_address():
    if not SERVER:
        pytest.skip("needs CHECKER_TEST_POSTGRES")
    import psycopg

    schema = f"t{secrets.token_hex(6)}"
    with psycopg.connect(SERVER, autocommit=True) as admin:
        admin.execute(f"CREATE SCHEMA {schema}")
    separator = "&" if "?" in SERVER else "?"
    yield f"{SERVER}{separator}options=-csearch_path%3D{schema}"
    with psycopg.connect(SERVER, autocommit=True) as admin:
        admin.execute(f"DROP SCHEMA {schema} CASCADE")


def test_moving_a_store_copies_everything_and_changes_the_settings(
    tmp_path, monkeypatch, server_address, capsys
):
    from checker import cli
    from checker.evidence import COPIED_TABLES, _fingerprint_of, initialise, load_config

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    initialise(tmp_path)
    old = Store(database_file(tmp_path))
    filled(old)
    before = {table: _fingerprint_of(old, table) for table in COPIED_TABLES}
    seq = old._db.execute("SELECT max(seq) FROM custody").fetchone()[0]
    old.close()
    assert cli.main(["store", "move", "--to", server_address, "--yes"]) == 0
    assert load_config(tmp_path).database == server_address
    assert not database_file(tmp_path).exists(), "a purge couldn't reach what's left in it"
    new = Store(database_file(tmp_path))
    assert new._db.dialect == "postgres"
    for table in COPIED_TABLES:
        if table == "config_changes":
            continue
        assert _fingerprint_of(new, table) == before[table], table
    assert new.config_changes()[-1]["setting"] == "database"
    new.record_bundle(bundle_row("b9"))
    assert new.custody_of("b9")[-1]["seq"] > seq, "numbering carries on"
    with pytest.raises(DATABASE_ERRORS, match="append-only"):
        with new._db:
            new._db.execute("DELETE FROM custody")
    new.close()
    assert cli.main(["store", "move", "--to", server_address, "--yes"]) == 1
    assert "already in a database" in capsys.readouterr().err


def test_moving_keeps_the_old_file_unless_told(tmp_path, monkeypatch, server_address):
    from checker import cli
    from checker.evidence import initialise

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    initialise(tmp_path)
    args = type("Args", (), {"to": server_address, "yes": False})
    assert cli.cmd_store_move(args, ask=lambda words: "no") == 0
    assert database_file(tmp_path).exists()


def test_moving_into_a_database_with_something_in_it_changes_nothing(
    tmp_path, monkeypatch, server_address, capsys
):
    from checker import cli
    from checker.evidence import initialise, load_config

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    initialise(tmp_path)
    used = Store(database_file(tmp_path), url=server_address)
    used.record_bundle(bundle_row("theirs"))
    used.close()
    assert cli.main(["store", "move", "--to", server_address, "--yes"]) == 1
    assert "already has bundles" in capsys.readouterr().err
    assert load_config(tmp_path).database is None and database_file(tmp_path).exists()


def test_a_move_that_doesn_t_read_back_the_same_changes_nothing(
    tmp_path, monkeypatch, server_address, capsys
):
    from checker import cli, evidence
    from checker.evidence import initialise, load_config

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    initialise(tmp_path)
    old = Store(database_file(tmp_path))
    filled(old)
    old.close()
    real = evidence._fingerprint_of
    calls = []

    def differs(store, table):
        calls.append(table)
        return (0, "different") if len(calls) == 2 else real(store, table)

    monkeypatch.setattr(evidence, "_fingerprint_of", differs)
    assert cli.main(["store", "move", "--to", server_address, "--yes"]) == 1
    assert "read back" in capsys.readouterr().err
    assert load_config(tmp_path).database is None and database_file(tmp_path).exists()
    monkeypatch.setattr(evidence, "_fingerprint_of", real)
    empty = Store(database_file(tmp_path), url=server_address)
    assert empty.bundles() == []
    empty.close()


def test_a_password_can_t_get_into_the_settings(tmp_path, monkeypatch, capsys):
    from checker import cli

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    address = "postgresql://user:secret@localhost/checker"
    assert cli.main(["init", "--advisor", "off", "--database", address]) == 1
    assert "password" in capsys.readouterr().err
    assert (
        not (tmp_path / "config.yaml").exists()
        or "secret" not in (tmp_path / "config.yaml").read_text()
    )
    assert cli.main(["init", "--advisor", "off"]) == 0
    assert cli.main(["store", "move", "--to", address, "--yes"]) == 2
    assert (
        "secret" not in (tmp_path / "config.yaml").read_text() and database_file(tmp_path).exists()
    )


def test_the_settings_page_says_where_the_store_is_but_not_the_address(tmp_path):
    from checker.evidence import Config
    from checker.web.setting_forms import _command_line_only

    address = "postgresql://user@db.example.org/checker?sslmode=verify-full"
    config = Config(recipients=["x"], database=address)
    said = dict(_command_line_only(config))
    assert said["Where the store is kept"] == "a database server"
    assert "example" not in str(_command_line_only(config))
