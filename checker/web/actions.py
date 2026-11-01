"""The one way a page changes anything, and the record of it (plan 5.10).

Viewing pages read. Anything else goes through `action`: signed in, POST, CSRF-checked by the
middleware, and recorded whatever happens. If it can't be recorded, it doesn't happen. A
consequential action, one that changes what later findings mean or removes data, also needs the
password again, however recently its user signed in: a stolen session or an unattended browser
mustn't be able to hide a break-in. Actions call what the command line calls; no logic of their
own lives here."""

from __future__ import annotations

from functools import wraps

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_POST

from checker.report import visible
from checker.web import accounts
from checker.web.models import ActionRecord


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


def confirmation_refused(request, action: str, target: str) -> str | None:
    """Why a consequential action can't go ahead, in words for the page; None if it can."""
    name = accounts.normal_name(request.user.get_username())
    address = accounts.client_address(request)
    if accounts.throttled(name, address):
        record(request, action, target, "refused", "too many failed confirmations")
        return "Too many failed attempts. Wait 15 minutes and try again."
    if not request.user.check_password(request.POST.get("confirm_password", "")):
        accounts.record_failure(name, address)
        record(request, action, target, "refused", "wrong password")
        return "That password didn't work, so nothing was changed."
    accounts.clear_failures(name, address)
    return None


def action(name: str, consequential: bool = False, target=lambda request, **kwargs: ""):
    """Make a view an action. `target` says what it acts on, for the record."""

    def decorate(view):
        @login_required
        @require_POST
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            on = str(target(request, **kwargs))
            if consequential:
                refused = confirmation_refused(request, name, on)
                if refused:
                    return render(request, "problem.html.j2", {"title": refused}, status=403)
            record(request, name, on, "started")  # if this fails, nothing has happened
            try:
                response = view(request, *args, **kwargs)
            except Exception as exc:
                record(request, name, on, "failed", type(exc).__name__)
                raise
            done = "done" if response.status_code < 400 else f"failed: {response.status_code}"
            record(request, name, on, done)
            return response

        wrapped.checker_action = name
        wrapped.checker_consequential = consequential
        return wrapped

    return decorate
