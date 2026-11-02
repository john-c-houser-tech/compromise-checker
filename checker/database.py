"""The two databases the store can use (plan 5.14): SQLite, a file beside the evidence, by default;
PostgreSQL, for a team, as an optional extra. `checker.evidence.Store` holds the SQL, which is
written for SQLite and translated here. What differs is here too: how a writer gets the database to
itself, and how append-only is enforced and lifted, so that it holds the same way on either, by the
database itself.

A database address never holds a password (policy §6): libpq finds that itself, through a Unix
socket's peer authentication or a `.pgpass` file. Evidence stays in files on disk either way: what a
database holds is the index, with whatever's sensitive encrypted to the evidence key, as it always
was."""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Any

try:
    import psycopg
    import psycopg.conninfo
except ImportError:
    psycopg = None

# Everything a database can raise, for those who catch it. Which exist depends on what's installed.
DATABASE_ERRORS: tuple[type[Exception], ...] = (
    (sqlite3.Error, psycopg.Error) if psycopg else (sqlite3.Error,)
)

# Append-only, enforced by the database itself (DESIGN.md §3.4). Only `purge` lifts it, inside its
# own transaction (Store.purge).
APPEND_ONLY = (
    ("bundles", "bundles are"),
    ("custody", "custody is"),
    ("baselines", "baselines are"),
    ("assessments", "assessments are"),
    ("advice", "advice is"),
)
# Never lifted, by anything.
ALWAYS_APPEND_ONLY = (
    ("purges", "purges are"),
    ("config_changes", "config changes are"),
)
_LOCAL_HOSTS = {"", "localhost", "127.0.0.1", "::1"}
# All an address may say, as libpq reads it. Nothing that holds a secret, or that sends the decision
# of where to connect somewhere this can't see (service, hostaddr).
_ADDRESS_KEYS = {
    "host",
    "port",
    "dbname",
    "user",
    "sslmode",
    "sslrootcert",
    "sslcert",
    "sslkey",
    "options",
    "application_name",
    "connect_timeout",
}
# libpq falls back on these for what an address leaves out, so they could send it elsewhere unseen.
_STEERING_VARIABLES = ("PGHOST", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGSSLMODE")
LOCK_TIMEOUT_SECONDS = 20
CONNECT_TIMEOUT_SECONDS = 15
STATEMENT_TIMEOUT_SECONDS = 300
_KEEPALIVE = {
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 3,
    "tcp_user_timeout": 60000,  # a server gone silent: a page or a check mustn't wait for ever
}


def check_database_url(url: str) -> str:
    """A PostgreSQL address fit to keep in the settings, or ValueError saying why not. Read as libpq
    reads it, since that's what will use it: a parser of URLs disagrees about what's in one."""
    if psycopg is None:
        raise ValueError("needs PostgreSQL support: pip install -e '.[postgres]'")
    if not isinstance(url, str) or not url.startswith(("postgresql://", "postgres://")):
        raise ValueError("has to be a postgresql:// address")
    try:
        parts = psycopg.conninfo.conninfo_to_dict(url)
    except psycopg.Error:
        raise ValueError("can't be read as a postgresql:// address") from None
    if "password" in parts or "passfile" in parts or "sslpassword" in parts:
        raise ValueError(
            "can't hold a password: use peer authentication or a .pgpass file, which keep it out of"
            " the settings"
        )
    extra = sorted(set(parts) - _ADDRESS_KEYS)
    if extra:
        raise ValueError(f"can't say {extra[0]}: name the server in the address itself")
    hosts = str(parts.get("host", "")).split(",")
    remote = [host for host in hosts if host not in _LOCAL_HOSTS and not host.startswith("/")]
    if remote and parts.get("sslmode") != "verify-full":
        raise ValueError(
            "reaches another machine, so it needs sslmode=verify-full, which checks it's really"
            " that server: what's sent includes which servers you have and how they were judged"
        )
    return url


def append_only_triggers_sqlite() -> list[str]:
    return [
        f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action} BEFORE {action.upper()}"
        f" ON {table} BEGIN SELECT RAISE(ABORT, '{label} append-only'); END"
        for table, label in APPEND_ONLY
        for action in ("update", "delete")
    ]


class SQLiteDatabase(sqlite3.Connection):
    """The connection itself, with what Store asks of either database."""

    dialect = "sqlite"

    def begin_write(self) -> None:
        self.execute("BEGIN IMMEDIATE")

    def lift_append_only(self) -> None:
        for table, _ in APPEND_ONLY:
            for action in ("update", "delete"):
                self.execute(f"DROP TRIGGER {table}_no_{action}")

    def restore_append_only(self) -> None:
        for sql in append_only_triggers_sqlite():
            self.execute(sql)


class Row(dict):
    """A row as sqlite3.Row reads: by name, or by position."""

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


def _row_factory(cursor: Any) -> Any:
    names = [column.name for column in cursor.description or []]
    return lambda values: Row(zip(names, values, strict=True))


_NAMED = re.compile(r"(?<!:):([a-z_][a-z0-9_]*)")


def _translated(sql: str) -> str:
    return _NAMED.sub(r"%(\1)s", sql.replace("?", "%s"))


def _schema_for_postgres(schema: str) -> str:
    """The tables as SQLite's schema has them. Text sorts by bytes, as in SQLite: times and names
    are compared and ordered, and a locale's order would change what's "latest"."""
    tables = re.sub(r"CREATE TRIGGER.*?END;", "", schema, flags=re.S)
    tables = tables.replace(
        "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY"
    )
    tables = re.sub(r"\bTEXT\b", 'TEXT COLLATE "C"', tables)
    tables = re.sub(r"\bINTEGER\b", "BIGINT", tables)
    tables = re.sub(r"\bREAL\b", "DOUBLE PRECISION", tables)
    return re.sub(r"\bBLOB\b", "BYTEA", tables)


def _postgres_trigger_statements(table: str, label: str) -> list[str]:
    message = f"{label} append-only".replace("'", "''")
    return [
        f"CREATE OR REPLACE TRIGGER {table}_no_{action} BEFORE {action.upper()} ON {table}"
        f" FOR EACH ROW EXECUTE FUNCTION checker_append_only('{message}')"
        for action in ("update", "delete")
    ] + [
        # SQLite has no TRUNCATE. Here it would empty a table without a row trigger noticing.
        f"CREATE OR REPLACE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table}"
        f" FOR EACH STATEMENT EXECUTE FUNCTION checker_append_only('{message}')"
    ]


_GUARD_BODY = " BEGIN RAISE EXCEPTION '%', TG_ARGV[0]; END "
_TABLES = (
    "bundles",
    "custody",
    "derived",
    "baselines",
    "assessments",
    "purges",
    "advice",
    "config_changes",
)


def _no_nul(value: Any) -> Any:
    """PostgreSQL's text can't hold a NUL, and a hostile server can send one in what's recorded
    about it. Refusing would let it keep its own collection out of the record, so it's shown."""
    return value.replace("\x00", "\\u0000") if isinstance(value, str) else value


class PostgresDatabase:
    """What Store asks of a database, on PostgreSQL. Autocommit, with transactions begun by hand, so
    that looking never leaves one open and each write says where it starts. A store can sit idle for
    the length of a collection, so a connection lost by then is made again, wherever nothing is at
    stake: between transactions, not in one."""

    dialect = "postgres"

    def __init__(self, url: str, read_only: bool = False) -> None:
        if psycopg is None:
            raise RuntimeError("PostgreSQL needs: pip install -e '.[postgres]'")
        check_database_url(url)
        steering = [name for name in _STEERING_VARIABLES if os.environ.get(name)]
        if steering:
            raise RuntimeError(
                f"{steering[0]} is set, and would change which database this reaches: unset it"
            )
        self._url, self._read_only = url, read_only
        self._connect()

    def _connect(self) -> None:
        self._connection = psycopg.connect(
            self._url,
            autocommit=True,
            row_factory=_row_factory,
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
            **_KEEPALIVE,
        )
        self._connection.execute(f"SET lock_timeout = '{LOCK_TIMEOUT_SECONDS}s'")
        self._connection.execute(f"SET statement_timeout = '{STATEMENT_TIMEOUT_SECONDS}s'")
        self._connection.execute(
            f"SET idle_in_transaction_session_timeout = '{STATEMENT_TIMEOUT_SECONDS}s'"
        )
        if self._read_only:
            self._connection.execute("SET default_transaction_read_only = on")

    def _in_transaction(self) -> bool:
        return self._connection.info.transaction_status != psycopg.pq.TransactionStatus.IDLE

    def _again_if_lost(self, work: Any) -> Any:
        """`work`, and once more on a new connection if the old one has gone. Only outside a
        transaction, where nothing was begun that a new connection would lose."""
        if self._writing:
            return work()
        try:
            return work()
        except psycopg.OperationalError:
            if not (self._connection.closed or self._connection.broken):
                raise
            self._connect()
            return work()

    _writing = False

    def execute(self, sql: str, parameters: Any = ()) -> Any:
        if isinstance(parameters, dict):
            cleaned: Any = {key: _no_nul(value) for key, value in parameters.items()}
        else:
            cleaned = [_no_nul(value) for value in parameters]
        return self._again_if_lost(
            lambda: self._connection.execute(_translated(sql), cleaned or None)
        )

    def begin_write(self) -> None:
        self._again_if_lost(lambda: self._connection.execute("BEGIN"))
        self._writing = True
        try:
            # One writer per store, as SQLite has: per schema, since a server holds many.
            self._connection.execute("SELECT pg_advisory_xact_lock(hashtext(current_schema()))")
        except BaseException:
            self.rollback()
            raise

    def commit(self) -> None:
        self._writing = False
        self._connection.execute("COMMIT")

    def rollback(self) -> None:
        self._writing = False
        if self._connection.closed or self._connection.broken:
            return
        if self._in_transaction():
            self._connection.execute("ROLLBACK")

    def __enter__(self) -> PostgresDatabase:
        self.begin_write()
        return self

    def __exit__(self, kind: Any, value: Any, traceback: Any) -> None:
        if kind is None:
            self.commit()
        else:
            self.rollback()

    def close(self) -> None:
        self._connection.close()

    def _guards_as_they_should_be(self) -> bool:
        """Every table, and every guard: there, switched on, unconditional and calling the function,
        which says what it should. Not a count: a guard disabled or replaced still counts."""
        wanted = {
            f"{table}_no_{action}"
            for table, _ in (*APPEND_ONLY, *ALWAYS_APPEND_ONLY)
            for action in ("update", "delete", "truncate")
        }
        tables = self.execute(
            "SELECT count(*) FROM pg_class WHERE relkind = 'r' AND relname = ANY(?)"
            " AND relnamespace = current_schema()::regnamespace",
            [list(_TABLES)],
        ).fetchone()[0]
        if tables != len(_TABLES):
            return False
        found = self.execute(
            "SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
            " JOIN pg_proc p ON p.oid = t.tgfoid"
            " WHERE NOT t.tgisinternal AND t.tgenabled = 'O' AND t.tgqual IS NULL"
            " AND c.relnamespace = current_schema()::regnamespace"
            " AND p.proname = 'checker_append_only' AND p.prosrc = ?"
            " AND t.tgname LIKE c.relname || '\\_no\\_%%'",
            [_GUARD_BODY],
        ).fetchall()
        return wanted <= {row["tgname"] for row in found}

    def ensure_schema(self, schema: str) -> None:
        """Tables, function and guards, if any aren't as they should be, as SQLite's schema is on
        each opening: a guard someone dropped, disabled or changed goes back. Looked at first, since
        making them takes locks."""
        if self._guards_as_they_should_be():
            return
        with self:
            self._connection.execute(_schema_for_postgres(schema))
            self._connection.execute(
                "CREATE OR REPLACE FUNCTION checker_append_only() RETURNS trigger"
                f" LANGUAGE plpgsql AS $${_GUARD_BODY}$$"
            )
            for table, label in (*APPEND_ONLY, *ALWAYS_APPEND_ONLY):
                for statement in _postgres_trigger_statements(table, label):
                    self._connection.execute(statement)

    def lift_append_only(self) -> None:
        for table, _ in APPEND_ONLY:
            for action in ("update", "delete", "truncate"):
                self._connection.execute(f"DROP TRIGGER {table}_no_{action} ON {table}")

    def restore_append_only(self) -> None:
        for table, label in APPEND_ONLY:
            for statement in _postgres_trigger_statements(table, label):
                self._connection.execute(statement)


def configured_url(home: Path) -> str | None:
    """The settings' database address, read without the rest of them, since the store is opened on
    its own. Settings that can't be read must not read as "use SQLite", which would silently be an
    empty store, and one naming a bad address must not be connected to: so ValueError."""
    import yaml

    try:
        text = (home / "config.yaml").read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as exc:
        raise ValueError("the settings file can't be read") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError("the settings file can't be read") from exc
    if not isinstance(data, dict):
        raise ValueError("the settings file can't be read")
    url = data.get("database")
    if url is None:
        return None
    try:
        return check_database_url(url)
    except ValueError as exc:
        raise ValueError(f"the settings' database address {exc}") from None
