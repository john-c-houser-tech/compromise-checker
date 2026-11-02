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
        row = db.execute("SELECT current_database() AS name, current_user AS who").fetchone()
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


def is_ours(connection) -> bool:
    return _table_marks(connection, [_MIGRATIONS]).get(_MIGRATIONS) == _MARK


def refuse_tables_of_others(connection) -> None:
    """Another Django application's tables would be taken for these, and its accounts could then
    sign in here. So whether this tool made them is written on the table that says what's been
    made, as the first thing done."""
    if is_ours(connection):
        return
    names = connection.introspection.django_table_names(only_existing=False, include_views=False)
    found = _table_marks(connection, [*names, _MIGRATIONS])
    if found:
        raise RuntimeError(
            f"this database already has a {sorted(found)[0]} table this tool didn't make: use a"
            " database of its own"
        )


def claim(connection) -> None:
    from django.db.migrations.recorder import MigrationRecorder

    MigrationRecorder(connection).ensure_schema()
    with connection.cursor() as cursor:
        cursor.execute(f"COMMENT ON TABLE {_MIGRATIONS} IS '{_MARK}'")


@contextmanager
def one_migration_at_a_time(connection):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT pg_advisory_lock{_ONE_MIGRATION}")
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT pg_advisory_unlock{_ONE_MIGRATION}")
