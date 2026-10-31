"""What the web interface keeps of its own. Never evidence."""

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
