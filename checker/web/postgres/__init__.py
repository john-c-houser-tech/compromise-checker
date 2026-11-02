"""The web interface's own tables in PostgreSQL (plan 5.15): beside the store's."""

from __future__ import annotations

from contextlib import contextmanager

from checker import database

_MARK = "compromise-checker web interface"
_MIGRATIONS = "django_migrations"
# Two starts at once, such as the server and `checker web-password`, mustn't both make the tables.
_ONE_MIGRATION = "(hashtext('checker web migration'), hashtext(current_schema()))"


def settings_for(url: str) -> dict:
    """What Django needs to reach this address, from the address as libpq reads it. A name it leaves
    out is asked for, since libpq's default and Django's differ: Django would go to "postgres". The
    same refusals as the store's, as it's opened first."""
    import psycopg.conninfo

    db = database.PostgresDatabase(url)
    try:
        row = db.execute("SELECT current_database() AS name, session_user AS who").fetchone()
    finally:
        db.close()
    named = psycopg.conninfo.conninfo_to_dict(url)
    host, port = named.pop("host", ""), named.pop("port", "")
    named.pop("dbname", None)
    named.pop("user", None)
    return {
        "ENGINE": "checker.web.postgres",
        "NAME": row["name"],
        "USER": row["who"],
        "HOST": host,
        "PORT": port,
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {
            **named,
            "connect_timeout": database.CONNECT_TIMEOUT_SECONDS,
            **database.KEEPALIVE,
        },
    }


def _table_marks(connection, names: list[str]) -> dict[str, str | None]:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT relname, obj_description(oid, 'pg_class') FROM pg_class WHERE relname = ANY(%s)"
            " AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema())",
            [names],
        )
        return dict(cursor.fetchall())


def _found_elsewhere(connection, names: list[str]) -> list[str]:
    """In another schema this session's path reaches: Django's and PostgreSQL's own look-ups by name
    would take them for these."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE c.relname = ANY(%s) AND n.nspname = ANY(current_schemas(false))"
            " AND n.nspname <> current_schema()",
            [names],
        )
        return [row[0] for row in cursor.fetchall()]


def is_ours(connection) -> bool:
    return _table_marks(connection, [_MIGRATIONS]).get(_MIGRATIONS) == _MARK


def refuse_tables_of_others(connection) -> None:
    """Another Django application's tables would be taken for these, and its accounts could then
    sign in here. So whether this tool made them is written on the table that says what's been
    made, as the first thing done."""
    names = connection.introspection.django_table_names(only_existing=False, include_views=False)
    if is_ours(connection):
        # Its own shadow any of the same name further along the path, unless one has gone missing,
        # as from a partial restore: the name would then quietly reach the other.
        here = _table_marks(connection, names)
        strays = _found_elsewhere(connection, [name for name in names if name not in here])
        if strays:
            raise RuntimeError(
                f"this database has no {sorted(strays)[0]} table of this tool's, but another schema"
                " on its search path has one: restore the database, or take it off the path"
            )
        return
    names = [*names, _MIGRATIONS]
    found = [*_table_marks(connection, names), *_found_elsewhere(connection, names)]
    if found:
        raise RuntimeError(
            f"this database already has a {sorted(found)[0]} table this tool didn't make: use a"
            " database of its own"
        )


def claim(connection) -> None:
    from django.db import transaction
    from django.db.migrations.recorder import MigrationRecorder

    # Together: stopped between them, its own empty table would be refused as someone else's.
    with transaction.atomic(using=connection.alias):
        MigrationRecorder(connection).ensure_schema()
        with connection.cursor() as cursor:
            cursor.execute(f"COMMENT ON TABLE {_MIGRATIONS} IS '{_MARK}'")


def drop_ours(connection) -> None:
    """Only what this tool marked, and only in its own schema: never by a name the path resolves."""
    if not is_ours(connection):
        return
    names = connection.introspection.django_table_names(only_existing=False, include_views=False)
    quote = connection.ops.quote_name
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema = quote(cursor.fetchone()[0])
        for table in [*names, _MIGRATIONS]:
            cursor.execute(f"DROP TABLE IF EXISTS {schema}.{quote(table)} CASCADE")


@contextmanager
def one_migration_at_a_time(connection):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT pg_advisory_lock{_ONE_MIGRATION}")
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT pg_advisory_unlock{_ONE_MIGRATION}")
