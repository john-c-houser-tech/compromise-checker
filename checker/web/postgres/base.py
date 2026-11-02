"""Django's PostgreSQL backend, made to keep the promises SQLite's keeps for the accounts' code.

That code relies on `transaction.atomic()` meaning one writer at a time, from its first line: on
SQLite, BEGIN IMMEDIATE. "Count the failures, then add one" and "is someone else still left with
full access?" are only safe because of it, so each transaction here takes a lock as it begins, in
one place rather than at each of those. Looking takes no lock, as on SQLite."""

from __future__ import annotations

from django.db.backends.postgresql import base
from psycopg.types.string import StrDumperUnknown

from checker import database

# Its own number space, apart from the store's lock: a long purge mustn't hold up signing in.
_ONE_WRITER = "SELECT pg_advisory_xact_lock(hashtext('checker web'), hashtext(current_schema()))"


class _NoNul(StrDumperUnknown):
    """PostgreSQL's text can't hold a NUL, and anyone can send one in a login's name. It would then
    be an error page rather than a name that doesn't exist. Shown the way the store shows one."""

    def dump(self, obj):
        return super().dump(database.no_nul(obj))


class DatabaseWrapper(base.DatabaseWrapper):
    def get_new_connection(self, conn_params):
        connection = super().get_new_connection(conn_params)
        connection.adapters.register_dumper(str, _NoNul)
        return connection

    def init_connection_state(self):
        super().init_connection_state()
        with self.connection.cursor() as cursor:
            for statement in database.session_limits():
                cursor.execute(statement)
            cursor.execute("SHOW session_replication_role")
            allowed = cursor.fetchone()[0] == "origin"
        if not allowed:
            # Not left open: Django would take it as a good connection the next time it's needed.
            self.connection.close()
            self.connection = None
            raise RuntimeError(database.TRIGGERS_OFF)

    def set_autocommit(self, autocommit, force_begin_transaction_with_broken_autocommit=False):
        super().set_autocommit(autocommit, force_begin_transaction_with_broken_autocommit)
        if autocommit:
            return
        try:
            with self.wrap_database_errors:
                self.connection.execute(_ONE_WRITER)
        except BaseException:
            # `atomic` hasn't started yet, so nothing else would put this back.
            if not self.is_usable():
                self.close()
                raise
            self.connection.rollback()
            super().set_autocommit(True)
            raise
