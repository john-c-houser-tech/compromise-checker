"""The first account's one-time link, and login throttling."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from checker.web.models import LoginAttempt, SetupToken

SETUP_LIFETIME = timedelta(hours=1)
THROTTLE_WINDOW = timedelta(minutes=15)
MAX_FAILURES_FOR_NAME = 5  # from one address: guessing one account's password
MAX_FAILURES_FROM_ADDRESS = 20  # guessing across accounts


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def no_accounts() -> bool:
    return not get_user_model().objects.exists()


def setup_link(address: str) -> str | None:
    """A fresh link if there is no account yet, replacing any before it."""
    if not no_accounts():
        SetupToken.objects.all().delete()
        return None
    token = secrets.token_urlsafe(32)
    with transaction.atomic():
        SetupToken.objects.all().delete()
        SetupToken.objects.create(
            token_hash=_hash(token), expires_at=timezone.now() + SETUP_LIFETIME
        )
    return f"{address.rstrip('/')}/setup/{token}"


def setup_token_valid(token: str) -> bool:
    if not no_accounts():
        return False
    wanted = _hash(token)
    return any(
        hmac.compare_digest(row.token_hash, wanted) and row.expires_at > timezone.now()
        for row in SetupToken.objects.all()
    )


def create_first_account(token: str, username: str, password: str):
    """The token is spent in the same transaction, so two tabs can't make two accounts."""
    with transaction.atomic():
        if not setup_token_valid(token):
            return None
        SetupToken.objects.all().delete()
        return get_user_model().objects.create_user(username=username, password=password)


def _recent():
    return LoginAttempt.objects.filter(at__gt=timezone.now() - THROTTLE_WINDOW)


def throttled(username: str, address: str) -> bool:
    return (
        _recent().filter(username=username.lower(), address=address).count()
        >= MAX_FAILURES_FOR_NAME
        or _recent().filter(address=address).count() >= MAX_FAILURES_FROM_ADDRESS
    )


def record_failure(username: str, address: str) -> None:
    LoginAttempt.objects.filter(at__lte=timezone.now() - THROTTLE_WINDOW).delete()
    LoginAttempt.objects.create(
        username=username.lower()[:150], address=address[:64], at=timezone.now()
    )


def clear_failures(username: str, address: str) -> None:
    LoginAttempt.objects.filter(username=username.lower(), address=address).delete()
