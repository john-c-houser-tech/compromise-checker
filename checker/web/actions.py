"""The one way a page changes anything, and the record of it (plan 5.10).

Viewing pages read. Anything else goes through `action`: signed in, POST, CSRF-checked by the
middleware, and recorded from start to finish. If it can't be recorded as started, it doesn't
happen. A consequential action, one that changes what later findings mean or removes data, also
needs the password again, and a code if two-factor is on, however recently its user signed in:
someone with a stolen session or at a browser left open has to know them, unless a password manager
fills them in. Actions call
what the command line calls; no logic of their own lives here. They should keep their
transactions short, since every page that records something waits for them."""

from __future__ import annotations

import sys
from functools import wraps

from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.db import connection, transaction
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_POST

from checker.report import visible
from checker.web import accounts, two_factor
from checker.web.models import ActionRecord

GATED = set()  # every view `action` made: no attribute a view could set by hand gets in here


class ActionFailed(Exception):
    """An action's way to say it didn't work, in the tool's own words, for the page and the
    record. Returning normally is what the record calls "done". `page` shows something better than
    the words alone, and `sign_out` ends the session once the record has said who it was."""

    def __init__(self, words: str, page=None, sign_out: bool = False):
        super().__init__(words)
        self.page, self.sign_out = page, sign_out


def record(request, action: str, target: str = "", outcome: str = "done", detail: str = "") -> None:
    """One line in the permanent record. The tool's own words only, and never evidence."""
    user = getattr(request, "user", None)
    who = user.get_username() if user is not None and user.is_authenticated else ""
    ActionRecord.objects.create(
        at=timezone.now(),
        who=who[:150],
        address=accounts.client_address(request)[:64],
        action=action[:64],
        target=str(visible(target, 200)),
        outcome=outcome[:32],
        detail=str(visible(detail, 1000)),
    )


def record_if_possible(
    request, action: str, target: str = "", outcome: str = "done", detail: str = ""
) -> None:
    """For what must go ahead anyway: reading evidence on a full disk, or signing out."""
    try:
        with transaction.atomic():  # a failure here can't undo a transaction around it
            record(request, action, target, outcome, detail)
    except Exception as exc:  # noqa: BLE001 - whatever it is, the page still has to work
        print(f"checker web: not recorded: {action}: {type(exc).__name__}", file=sys.stderr)


def confirmation_refused(request, action: str, target: str) -> str | None:
    """Why a consequential action can't go ahead, in words for the page; None if it can. Too many
    wrong passwords end the session, so whoever is guessing has to sign in to go on."""
    session = request.session.session_key
    if not accounts.begin_confirmation(session):
        return _signed_out(request, action, target)
    user = request.user
    right_password = user.check_password(request.POST.get("confirm_password", ""))
    code_needed = two_factor.is_on(user)
    # The password first: a code isn't used up on someone who doesn't know it.
    if right_password and (
        not code_needed or two_factor.check_code(user, request.POST.get("confirm_code", ""))
    ):
        accounts.clear_confirmations(session)
        return None
    if accounts.confirmations_used_up(session):
        return _signed_out(request, action, target)
    wrong = "wrong code" if right_password else "wrong password"
    record_if_possible(request, action, target, "refused", wrong)
    if code_needed:  # not "nothing was changed": a double-click's other request may have worked
        return (
            "That password or code didn't work. A code works only once, so if you just used one,"
            " wait for the next. If you clicked twice, the first click may have gone through: the"
            " Activity page shows what ran."
        )
    return "That password didn't work, so nothing was changed."


def _signed_out(request, action: str, target: str) -> str:
    record_if_possible(request, action, target, "refused", "too many wrong tries: signed out")
    logout(request)
    # Not "nothing was changed": a double-click's other request may have gone through.
    return "Too many wrong tries, so you've been signed out. The Activity page shows what ran."


def action(name: str, consequential: bool = False, target=lambda request, **kwargs: ""):
    """Make a view an action. `target` says what it acts on, for the record."""

    def decorate(view):
        if getattr(view, "csrf_exempt", False):
            raise TypeError(f"{name}: an action can't be exempt from the CSRF check")

        @login_required
        @require_POST
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if connection.in_atomic_block:
                raise RuntimeError(f"{name}: in a transaction, its record would be undone with it")
            try:
                on = str(target(request, **kwargs))
            except Exception as exc:
                record(request, name, "(couldn't be named)", "failed", type(exc).__name__)
                raise
            if consequential:
                refused = confirmation_refused(request, name, on)
                if refused:
                    return render(request, "problem.html.j2", {"title": refused}, status=403)
            record(request, name, on, "started")  # if this fails, nothing has happened
            try:
                response = view(request, *args, **kwargs)
            except ActionFailed as exc:
                record_if_possible(request, name, on, "failed", str(exc))
                if exc.sign_out:
                    logout(request)
                if exc.page is not None:
                    return exc.page
                return render(request, "problem.html.j2", {"title": str(exc)}, status=400)
            except Exception as exc:
                record_if_possible(request, name, on, "failed", type(exc).__name__)
                raise
            done = "done" if response.status_code < 400 else f"failed: {response.status_code}"
            record_if_possible(request, name, on, done)  # it has happened: say what it did
            return response

        GATED.add(wrapped)
        return wrapped

    return decorate
