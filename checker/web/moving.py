"""Moving the web interface's accounts and record from `web.db` to PostgreSQL, for `checker store
move`. In a process of its own making: Django is set up here with both databases, and the web
interface must be stopped, as for the store."""

from __future__ import annotations

from pathlib import Path

from checker import database
from checker.evidence import EvidenceError
from checker.web import app, postgres


def _set_up(home: Path, url: str) -> None:
    import django
    from django.conf import settings

    databases = {
        "default": postgres.settings_for(url),
        "source": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": str(home / "web.db"),
            "OPTIONS": {"transaction_mode": "IMMEDIATE", "timeout": 20},
        },
    }
    settings.configure(**app.django_settings(home, databases=databases))
    django.setup()


def _models() -> list:
    from django.apps import apps

    return [
        model
        for model in apps.get_models(include_auto_created=True)
        if model._meta.managed or model._meta.auto_created
    ]


def _rows(model, alias: str) -> list[tuple]:
    names = [field.attname for field in model._meta.local_concrete_fields]
    return list(model._base_manager.using(alias).order_by("pk").values_list(*names))


def _as_stored(rows: list[tuple]) -> list[tuple]:
    return [tuple(database.no_nul(value) for value in row) for row in rows]


def _same(model) -> bool:
    return _as_stored(_rows(model, "source")) == _rows(model, "default")


def _copy(model, cursor, connection) -> int:
    fields = model._meta.local_concrete_fields
    columns = ", ".join(connection.ops.quote_name(field.column) for field in fields)
    places = ", ".join(["%s"] * len(fields))
    rows = _rows(model, "source")
    if rows:
        table = connection.ops.quote_name(model._meta.db_table)
        cursor.executemany(
            f"INSERT INTO {table} ({columns}) VALUES ({places})",  # noqa: S608 - its own names
            rows,
        )
    return len(rows)


def _copy_everything(connection) -> int:
    from django.contrib.auth.models import Permission
    from django.contrib.contenttypes.models import ContentType
    from django.core.management.color import no_style
    from django.db import transaction

    models = _models()
    with transaction.atomic(using="default"), connection.cursor() as cursor:
        # A new database's own, numbered as it made them. The old one's numbers are in its rows.
        tables = (Permission._meta.db_table, ContentType._meta.db_table)
        cursor.execute(f"TRUNCATE {', '.join(tables)} CASCADE")
        total = sum(_copy(model, cursor, connection) for model in models)
        for statement in connection.ops.sequence_reset_sql(no_style(), models):
            cursor.execute(statement)
        for model in models:
            if not _same(model):
                raise EvidenceError(
                    f"{model._meta.db_table} didn't read back the same, so the accounts weren't"
                    " moved"
                )
    return total


def _drop(connection) -> None:
    names = connection.introspection.django_table_names(only_existing=True, include_views=False)
    with connection.cursor() as cursor:
        for table in [*names, "django_migrations"]:
            cursor.execute(f"DROP TABLE IF EXISTS {connection.ops.quote_name(table)} CASCADE")


def move_accounts(home: Path, url: str) -> int:
    """How many rows. All of them are there and read back the same, or nothing is left behind. An
    earlier move that got this far is only checked, so that one stopped before its last step can be
    finished by running it again."""
    from django.core.management import call_command
    from django.db import Error, connections

    try:
        _set_up(home, url)
        # What the next start would have done, so the two are alike.
        call_command("migrate", database="source", verbosity=0, interactive=False)
        target = connections["default"]
        with postgres.one_migration_at_a_time(target):
            if postgres.is_ours(target):
                call_command("migrate", verbosity=0, interactive=False)
                if not all(_same(model) for model in _models()):
                    raise EvidenceError(
                        "the new database already has other accounts in it: use an empty one. If an"
                        " earlier move stopped part way, empty that database first"
                    )
                return sum(len(_rows(model, "default")) for model in _models())
            postgres.refuse_tables_of_others(target)
            try:
                postgres.claim(target)
                call_command("migrate", verbosity=0, interactive=False)
                total = _copy_everything(target)
                app._protect_the_record()
            except BaseException:
                _drop(target)
                raise
            return total
    except (Error, ValueError, RuntimeError, *database.DATABASE_ERRORS) as exc:
        raise EvidenceError(f"the accounts: {exc}") from exc


def take_accounts_back() -> None:
    """After `move_accounts` when the rest of the move failed, so it can be tried again."""
    from django.db import connections

    _drop(connections["default"])
