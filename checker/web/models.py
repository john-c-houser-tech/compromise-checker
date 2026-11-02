"""What the web interface keeps of its own, with django-otp's tables. Never evidence."""

from django.conf import settings
from django.db import models


class Access(models.Model):
    """What an account may do. Without a row an account can only view, so a way of making accounts
    that forgets this gives away nothing."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="access"
    )
    full = models.BooleanField(default=False)


class Invitation(models.Model):
    """The one-time link someone uses to choose their password: only its hash is kept."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="invitation"
    )
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()


class SetupToken(models.Model):
    """The one-time link that creates the first account: only its hash is kept."""

    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()


class LoginAttempt(models.Model):
    """A failed login, for throttling. Old rows are removed as new ones arrive."""

    username = models.CharField(max_length=150, db_index=True)
    address = models.CharField(max_length=64, db_index=True)
    at = models.DateTimeField(db_index=True)


class WrongConfirmation(models.Model):
    """A wrong password at a confirmation, per session: enough of them end that session. Apart
    from logins, so nobody can use bad logins from a shared address to block a confirmation."""

    session_key = models.CharField(max_length=40, db_index=True)
    at = models.DateTimeField(db_index=True)


class CheckRun(models.Model):
    """A check started from a page, for showing it and how it ended. Only the latest are kept; the
    activity record is what lasts."""

    kind = models.CharField(max_length=16)  # "check", "analysis" or "advice"
    hosts = models.TextField()  # JSON
    who = models.CharField(max_length=150)
    address = models.CharField(max_length=64)
    started_at = models.DateTimeField(db_index=True)
    finished_at = models.DateTimeField(null=True)
    ended = models.CharField(max_length=200, default="")


class ActionRecord(models.Model):
    """Who did what from these pages, and who viewed which results: permanent, and in the tool's
    own words, never evidence. The triggers keep it append-only."""

    at = models.DateTimeField(db_index=True)
    who = models.CharField(max_length=150)
    address = models.CharField(max_length=64)
    action = models.CharField(max_length=64)
    target = models.TextField()  # bounded where it's written; a limit here would refuse a line
    outcome = models.CharField(max_length=32)
    detail = models.TextField()


# Rebuilding the table for a migration drops these, so they are put back at every start too.
ACTION_RECORD_TRIGGERS = [
    "CREATE TRIGGER IF NOT EXISTS web_actionrecord_no_update BEFORE UPDATE ON web_actionrecord"
    " BEGIN SELECT RAISE(ABORT, 'the record is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS web_actionrecord_no_delete BEFORE DELETE ON web_actionrecord"
    " BEGIN SELECT RAISE(ABORT, 'the record is append-only'); END",
]


def action_record_guards(vendor: str) -> list[str]:
    """Each start puts them back, on either database. On PostgreSQL, the same guards as the store's
    history, which also stop TRUNCATE."""
    if vendor != "postgresql":
        return ACTION_RECORD_TRIGGERS
    from checker import database

    return [
        database.guard_function(),
        *database.postgres_trigger_statements("web_actionrecord", "the record is"),
    ]
