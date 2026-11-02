"""The first account's one-time link, and the limits on guessing a login or a confirmation."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import unicodedata
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from checker.web.app import is_local
from checker.web.models import (
    Access,
    ActionRecord,
    Invitation,
    LoginAttempt,
    SetupToken,
    WrongConfirmation,
)

SETUP_LIFETIME = timedelta(hours=1)
INVITATION_LIFETIME = timedelta(hours=24)  # it crosses to someone else, who may be asleep
THROTTLE_WINDOW = timedelta(minutes=15)
START_WINDOW = timedelta(hours=1)
MAX_STARTS = 30  # per person: one run is already the most at a time, and "all servers" is one run
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
        user = get_user_model().objects.create_user(username=username, password=password)
        Access.objects.create(user=user, full=True)
        return user


def normal_name(username: str) -> str:
    """As an account name is stored, so what was typed at setup works at login."""
    return get_user_model().normalize_username(username.strip())


def has_full_access(user) -> bool:
    """Read afresh for each request, so a change applies to whoever is already signed in."""
    return user.is_authenticated and Access.objects.filter(user=user, full=True).exists()


class PersonProblem(ValueError):
    """Why that can't be done to that person, in words for the page."""


def people() -> list[dict]:
    """Everyone who has or had an account: the record still names those removed."""
    from checker.web import two_factor  # it needs Django set up further than this module does

    rows = []
    users = get_user_model().objects.select_related("access", "invitation").order_by("username")
    for user in users:
        invitation = getattr(user, "invitation", None)
        rows.append(
            {
                "name": user.get_username(),
                "full": hasattr(user, "access") and user.access.full,
                "removed": not user.is_active,
                "invited": invitation is not None,
                "expired": invitation is not None and invitation.expires_at <= timezone.now(),
                "two_factor": two_factor.is_on(user),
            }
        )
    return rows


def _new_invitation(user) -> str:
    token = secrets.token_urlsafe(32)
    Invitation.objects.filter(user=user).delete()
    Invitation.objects.create(
        user=user, token_hash=_hash(token), expires_at=timezone.now() + INVITATION_LIFETIME
    )
    return token


def _still_full(actor) -> None:
    """Checked again inside the write, so two people can't take each other's access at once and
    leave nobody who can give it back. The password too: a new link leaves access as it was, but
    what was confirmed before it no longer counts."""
    if not Access.objects.filter(
        user=actor, full=True, user__is_active=True, user__password=actor.password
    ).exists():
        raise PersonProblem("Your own access has changed, so this wasn't done.")


def _someone_else(actor, name: str):
    """Nobody does this to themselves: with that rule, whoever does it still has full access
    afterwards, so there's always someone who does."""
    _still_full(actor)
    user = get_user_model().objects.filter(username=name).first()
    if user is None:
        raise PersonProblem(f"There's no account called {name}.")
    if user.pk == actor.pk:
        raise PersonProblem(
            "You can't do this to your own account. Ask someone else with full access."
        )
    if not user.is_active:
        raise PersonProblem(f"{name} has been removed.")
    return user


def name_shape_problem(name: str) -> str | None:
    """Names reach the record, a terminal and hidden form fields: plain ones survive all of them."""
    if not name:
        return "Choose a name."
    # By category, since a letter in many languages is written with marks that join it.
    if not all(c in "@.+-_" or unicodedata.category(c)[0] in "LMN" for c in name):
        return "A name can have only letters, numbers and the characters @ . + - _"
    return "That name is too long." if len(name) > 150 else None


def new_name_problem(name: str) -> str | None:
    """A name can't be used twice, even after someone is removed: the record would then seem to
    mean the new person. Compared here, since SQLite's own comparison knows only English letters."""
    if problem := name_shape_problem(name):
        return problem
    wanted = name.casefold()
    for username, active in get_user_model().objects.values_list("username", "is_active"):
        if username.casefold() != wanted:
            continue
        if active:
            return f"There's already an account called {username}."
        return (
            f"{username} was removed, and the activity record still names them."
            " Choose a different name."
        )
    return None


def invite(actor, name: str, full: bool) -> str:
    """A new account with no password yet, and the token for its link."""
    with transaction.atomic():
        _still_full(actor)
        if problem := new_name_problem(name):
            raise PersonProblem(problem)
        user = get_user_model().objects.create_user(username=name, password=None)
        Access.objects.create(user=user, full=full)
        return _new_invitation(user)


def set_access(actor, name: str, full: bool) -> None:
    with transaction.atomic():
        user = _someone_else(actor, name)
        Access.objects.update_or_create(user=user, defaults={"full": full})


def _lock_out(user) -> None:
    """No way in that was there before: password, second step, sessions or link."""
    from checker.web import two_factor  # it needs Django set up further than this module does

    user.set_unusable_password()
    user.save()
    two_factor.turn_off(user)
    two_factor.forget_pending(user)
    two_factor.forgive_wrong_codes(user)
    _end_sessions(user)
    LoginAttempt.objects.filter(username=user.get_username().lower()).delete()
    Invitation.objects.filter(user=user).delete()


def new_link(actor, name: str) -> str:
    """For a lost password or phone, or to invite them again. It ends what they had."""
    with transaction.atomic():
        user = _someone_else(actor, name)
        _lock_out(user)
        return _new_invitation(user)


def remove(actor, name: str) -> None:
    """Kept, unable to sign in, for the record's sake: its lines name them by this name."""
    with transaction.atomic():
        user = _someone_else(actor, name)
        _lock_out(user)
        user.is_active = False
        user.save()
        Access.objects.filter(user=user).update(full=False)


def invited(token: str):
    """Whose link this is, or None if it isn't one that works."""
    found = (
        Invitation.objects.select_related("user")
        .filter(token_hash=_hash(token), expires_at__gt=timezone.now(), user__is_active=True)
        .first()
    )
    return found.user if found else None


def accept(token: str, password: str):
    """The link is spent with the password set, so two tabs can't both use it. Anything set up
    for this account by a request that was still running when it was locked out goes too."""
    from checker.web import two_factor  # it needs Django set up further than this module does

    with transaction.atomic():
        user = invited(token)
        if user is None:
            return None
        Invitation.objects.filter(user=user).delete()
        two_factor.turn_off(user)
        user.set_password(password)
        user.save()
        return user


def upgrade_password_hash(user, password: str) -> None:
    """After a right password, if Django now makes stronger hashes. Only over the one checked."""
    from checker.web.hashing import out_of_date  # needs Django set up

    if out_of_date(user.password):
        hashed = make_password(password)
        same = get_user_model().objects.filter(pk=user.pk, password=user.password)
        if same.update(password=hashed):
            user.password = hashed


def change_own_password(user, password: str) -> bool:
    """False if the account was locked out or its password changed since this request began: what
    was confirmed no longer holds, and writing it back would undo that. The new hash is made first,
    since that's slow and everything else waits for a write."""
    hashed = make_password(password)
    changed = (
        get_user_model()
        .objects.filter(pk=user.pk, is_active=True, password=user.password)
        .update(password=hashed)
    )
    if changed:
        user.password = hashed
    return bool(changed)


def client_address(request) -> str:
    """Whose this request is, for throttling and the record. Behind the proxy on this machine
    every peer is the proxy, so one person could lock everyone out: there it is the last
    forwarded address, the one the proxy added itself (earlier ones are whatever the
    client sent). Only the proxy's requests get this far: see middleware.only_through_the_proxy.
    IPv6 counts by network, since one client can hold a whole /64."""
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


def forgive_one_confirmation(session_key: str) -> None:
    """For a try the wait stopped: it was never checked, so it isn't a wrong one."""
    latest = WrongConfirmation.objects.filter(session_key=session_key).order_by("-id").first()
    if latest is not None:
        latest.delete()


def confirmations_used_up(session_key: str) -> bool:
    return (
        WrongConfirmation.objects.filter(session_key=session_key).count() >= MAX_WRONG_CONFIRMATIONS
    )


def clear_confirmations(session_key: str) -> None:
    WrongConfirmation.objects.filter(session_key=session_key).delete()


def too_many_starts(who: str, names: tuple[str, ...]) -> bool:
    """Whether this person has started enough lately: each start reaches every server it names,
    and may cost money. The record already says, and no one can make it forget."""
    since = timezone.now() - START_WINDOW
    started = ActionRecord.objects.filter(
        who=who, action__in=names, outcome="started", at__gt=since
    )
    return started.count() >= MAX_STARTS


def no_such_account(username: str) -> str | None:
    found = get_user_model().objects.filter(username=username).first()
    if found is not None and found.is_active:
        return None
    if found is not None:
        return f"{username} has been removed, so can't sign in again."
    active = get_user_model().objects.filter(is_active=True)
    names = ", ".join(active.values_list("username", flat=True))
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
    Session.objects.filter(expire_date__lt=timezone.now()).delete()
    rows = Session.objects.values_list("session_key", "session_data")
    store = SessionStore()  # its decode treats a damaged row as empty
    keys = [
        key
        for key, data in rows.iterator()
        if store.decode(data).get("_auth_user_id") == str(user.pk)
    ]
    Session.objects.filter(session_key__in=keys).delete()


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
        user = get_user_model().objects.get(pk=user.pk)  # it may have changed during the checks
        if not user.is_active:
            return [no_such_account(username)]
        user.set_password(password)
        user.save()
        two_factor.forget_pending(user)  # a thief may have started one with the old password
        two_factor.forgive_wrong_codes(user)
        LoginAttempt.objects.filter(username=username.lower()).delete()
        Invitation.objects.filter(user=user).delete()  # the password is now the way in
        _record_from_command_line("reset a password from the command line", username)
    return []
