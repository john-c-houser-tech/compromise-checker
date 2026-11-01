"""The first account's one-time link, and the limits on guessing a login or a confirmation."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.sessions.models import Session
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from checker.web.app import is_local
from checker.web.models import ActionRecord, LoginAttempt, SetupToken, WrongConfirmation

SETUP_LIFETIME = timedelta(hours=1)
THROTTLE_WINDOW = timedelta(minutes=15)
MAX_FAILURES_FOR_NAME = 5  # from one address: guessing one account's password
MAX_FAILURES_FROM_ADDRESS = 20  # guessing across accounts
MAX_WRONG_CONFIRMATIONS = 5  # then the session ends: it's the only way a thief can keep trying


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


def normal_name(username: str) -> str:
    """As an account name is stored, so what was typed at setup works at login."""
    return get_user_model().normalize_username(username.strip())


def client_address(request) -> str:
    """Whose this request is, for throttling and the record. Behind the proxy on this machine
    every peer is the proxy, so one person could lock everyone out: there it is the last
    forwarded address, the one the proxy added itself (earlier ones are whatever the
    client sent). IPv6 counts by network, since one client can hold a whole /64."""
    address = request.META.get("REMOTE_ADDR", "")
    if settings.CHECKER_BEHIND_PROXY and is_local(address):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "").rpartition(",")[2].strip()
        address = forwarded if _is_address(forwarded) else address
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    if parsed.version == 4:
        return str(parsed)
    if parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return str(ipaddress.ip_network(f"{parsed}/64", strict=False))


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


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


def begin_login(username: str, address: str) -> bool:
    """False if throttled. Counted as failed before the password is checked, under the write
    lock, so guesses sent at once can't all pass the count; a success then clears it."""
    with transaction.atomic():
        if throttled(username, address):
            return False
        record_failure(username, address)
    return True


def clear_failures(username: str, address: str) -> None:
    LoginAttempt.objects.filter(username=username.lower(), address=address).delete()


def begin_confirmation(session_key: str) -> bool:
    """False if this session has used up its tries; counted first, as in `begin_login`."""
    with transaction.atomic():
        old = timezone.now() - timedelta(seconds=settings.SESSION_COOKIE_AGE)
        WrongConfirmation.objects.filter(at__lte=old).delete()
        if confirmations_used_up(session_key):
            return False
        WrongConfirmation.objects.create(session_key=session_key, at=timezone.now())
    return True


def confirmations_used_up(session_key: str) -> bool:
    return (
        WrongConfirmation.objects.filter(session_key=session_key).count() >= MAX_WRONG_CONFIRMATIONS
    )


def clear_confirmations(session_key: str) -> None:
    WrongConfirmation.objects.filter(session_key=session_key).delete()


def no_such_account(username: str) -> str | None:
    if get_user_model().objects.filter(username=username).exists():
        return None
    names = ", ".join(get_user_model().objects.values_list("username", flat=True))
    return f"There's no account called {username}. The accounts are: {names or 'none yet'}"


def turn_off_two_factor(username: str) -> str | None:
    """For the command line, when a phone and its recovery codes are both gone."""
    from checker.web import two_factor  # it needs Django set up further than this module does

    problem = no_such_account(username)
    if problem:
        return problem
    user = get_user_model().objects.get(username=username)
    if not two_factor.is_on(user):
        return f"Two-factor sign-in is already off for {username}."
    with transaction.atomic():
        two_factor.turn_off(user)
        _end_sessions(user)  # or a thief's half-finished sign-in could set it up as theirs
        _record_from_command_line("turned off two-factor from the command line", username)
    return None


def _end_sessions(user) -> None:
    for session in Session.objects.all():
        if session.get_decoded().get("_auth_user_id") == str(user.pk):
            session.delete()


def _record_from_command_line(action: str, username: str) -> None:
    ActionRecord.objects.create(
        at=timezone.now(),
        who="",
        address="this machine",
        action=action,
        target=username,
        outcome="done",
        detail="",
    )


def reset_password(username: str, password: str) -> list[str]:
    """For the command line, when a password is lost. Why it can't be done, or nothing: the
    account's sessions end with its old password, and the record says it happened."""
    from checker.web import two_factor  # it needs Django set up further than this module does

    problem = no_such_account(username)
    if problem:
        return [problem]
    user = get_user_model().objects.get(username=username)
    try:
        validate_password(password, user)
    except ValidationError as exc:
        return list(exc.messages)
    with transaction.atomic():
        user.set_password(password)
        user.save()
        two_factor.forget_pending(user)  # a thief may have started one with the old password
        two_factor.forgive_wrong_codes(user)
        LoginAttempt.objects.filter(username=username.lower()).delete()
        _record_from_command_line("reset a password from the command line", username)
    return []
