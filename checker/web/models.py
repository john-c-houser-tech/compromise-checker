"""What the web interface keeps of its own, with django-otp's tables. Never evidence."""

from django.db import models


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


class ActionRecord(models.Model):
    """Who did what from these pages, and who viewed which results: permanent, and in the tool's
    own words, never evidence. The triggers keep it append-only."""

    at = models.DateTimeField(db_index=True)
    who = models.CharField(max_length=150)
    address = models.CharField(max_length=64)
    action = models.CharField(max_length=64)
    target = models.CharField(max_length=200)
    outcome = models.CharField(max_length=32)
    detail = models.TextField()


# Rebuilding the table for a migration drops these, so they are put back at every start too.
ACTION_RECORD_TRIGGERS = [
    "CREATE TRIGGER IF NOT EXISTS web_actionrecord_no_update BEFORE UPDATE ON web_actionrecord"
    " BEGIN SELECT RAISE(ABORT, 'the record is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS web_actionrecord_no_delete BEFORE DELETE ON web_actionrecord"
    " BEGIN SELECT RAISE(ABORT, 'the record is append-only'); END",
]
