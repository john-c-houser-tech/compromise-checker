"""Pages. Viewing pages read the results; the only writes here are to accounts, sessions and the
record of who looked."""

from __future__ import annotations

import sys
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import Resolver404, resolve, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from django_otp import login as otp_login

from checker.evidence import EvidenceError
from checker.fleet import read_evidence, read_fleet, read_host, read_threats
from checker.inventory import home
from checker.report import visible
from checker.web import accounts, two_factor, wording
from checker.web.actions import ActionFailed, action, record, record_if_possible
from checker.web.app import HERE
from checker.web.middleware import before_second_step, setting_it_up
from checker.web.models import ActionRecord

# Where a login may go on to: not a form's address, which would land on an error.
VIEWABLE = {"fleet", "host", "evidence", "threats", "activity", "two_factor_manage"}


def _safe_next(request) -> str:
    wanted = request.POST.get("next") or request.GET.get("next") or ""
    if url_has_allowed_host_and_scheme(
        wanted, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        try:
            if resolve(urlsplit(wanted).path).url_name in VIEWABLE:
                return wanted
        except Resolver404:
            pass
    return reverse("fleet")


FONTS = (
    "atkinson-hyperlegible-latin-400-normal.woff2",
    "atkinson-hyperlegible-latin-700-normal.woff2",
)


@before_second_step
@require_GET
def font(request, name: str) -> HttpResponse:
    """Only these files, by exact name: nothing typed in a URL reaches the file system."""
    if name not in FONTS:
        return not_found(request)
    data = (HERE / "static" / "fonts" / name).read_bytes()
    response = HttpResponse(data, content_type="font/woff2")
    response["Cache-Control"] = "max-age=86400"
    return response


@before_second_step
@require_GET
def stylesheet(request) -> HttpResponse:
    response = HttpResponse((HERE / "static" / "style.css").read_bytes(), content_type="text/css")
    response["Cache-Control"] = "max-age=3600"
    return response


@before_second_step
@require_http_methods(["GET", "POST"])
def setup_page(request, token: str) -> HttpResponse:
    """Creates the first account, once. An invalid link says nothing about why."""
    if not accounts.setup_token_valid(token):
        return render(request, "problem.html.j2", {"title": "This link isn't valid"}, status=404)
    errors: list[str] = []
    username = ""
    if request.method == "POST":
        username = accounts.normal_name(request.POST.get("username", ""))[:150]
        password = request.POST.get("password", "")
        if not username:
            errors.append("Choose a username.")
        if password != request.POST.get("password2", ""):
            errors.append("The two passwords don't match.")
        try:
            validate_password(password, get_user_model()(username=username))
        except ValidationError as exc:
            errors.extend(exc.messages)
        if not errors:
            try:
                with transaction.atomic():  # no account without its line in the record
                    user = accounts.create_first_account(token, username, password)
                    if user is not None:
                        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
                        record(request, "created the first account")
            except Exception:
                request.user = AnonymousUser()  # the error page mustn't look signed in
                raise
            if user is None:
                return render(
                    request, "problem.html.j2", {"title": "This link isn't valid"}, status=404
                )
            return HttpResponseRedirect(reverse("fleet"))
    return render(request, "setup.html.j2", {"errors": errors, "username": username})


@before_second_step
@require_http_methods(["GET", "POST"])
def login_page(request) -> HttpResponse:
    error = None
    if request.method == "POST":
        username = accounts.normal_name(request.POST.get("username", ""))[:150]
        password = request.POST.get("password", "")
        address = accounts.client_address(request)
        # One message for all of it: a page mustn't say which usernames exist.
        error = "That username and password didn't work."
        if not accounts.begin_login(username, address):
            error = "Too many failed attempts. Wait 15 minutes and try again."
        else:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                try:
                    with transaction.atomic():  # no sign-in without its line in the record
                        accounts.clear_failures(username, address)
                        login(request, user)
                        # With a second step to come, this isn't signing in yet.
                        to_come = two_factor.is_on(user) or settings.CHECKER_TWO_FACTOR_REQUIRED
                        words = "password accepted" if to_come else "signed in"
                        record(request, words)
                except Exception:
                    request.user = AnonymousUser()  # the error page mustn't look signed in
                    raise
                return HttpResponseRedirect(_safe_next(request))
    return render(
        request,
        "login.html.j2",
        {"error": error, "next": request.GET.get("next", "")},
        status=200 if error is None else 403,
    )


@before_second_step
@require_POST
def logout_page(request) -> HttpResponse:
    if request.user.is_authenticated:  # anyone can post here: only a real sign-out is kept
        record_if_possible(request, "signed out")
    try:
        logout(request)
    except DatabaseError as exc:
        # On a full disk the session's row can't be removed: forget it in this browser, and say so.
        print(f"checker web: session not ended: {type(exc).__name__}", file=sys.stderr)
        request.user = AnonymousUser()
        response = render(
            request,
            "problem.html.j2",
            {
                "title": "You're signed out of this browser only",
                "detail": "The server couldn't save the change, usually because its disk is full,"
                " so anyone holding a copy of this session could still use it for up to 8 hours."
                " Free up space, then change the password with checker web-password to end it.",
            },
            status=503,
        )
        response.delete_cookie(
            settings.SESSION_COOKIE_NAME, samesite=settings.SESSION_COOKIE_SAMESITE
        )
        return response
    return HttpResponseRedirect(reverse("login"))


@before_second_step
@require_http_methods(["GET", "POST"])
@login_required
def two_factor_page(request) -> HttpResponse:
    """The second step, with only a password so far. A form and not an action, like signing in."""
    user = request.user
    if user.is_verified():
        return HttpResponseRedirect(_safe_next(request))
    if not two_factor.is_on(user):
        return HttpResponseRedirect(reverse("two_factor_setup"))
    error = None
    code = request.POST.get("code", "")
    wait = two_factor.minutes_to_wait(user, code) if request.method == "POST" else 0
    if wait:
        error = two_factor.wait_words(wait)
    elif request.method == "POST":
        session = request.session.session_key
        allowed = accounts.begin_confirmation(session)
        device = allowed and two_factor.check_code(user, code)
        if device:
            try:
                with transaction.atomic():  # no sign-in without its line in the record
                    accounts.clear_confirmations(session)
                    otp_login(request, device)
                    request.session.cycle_key()
                    how = "with a recovery code" if two_factor.used_recovery_code(device) else ""
                    record(request, "signed in", detail=how)
            except Exception:
                request.user = AnonymousUser()  # the error page mustn't look signed in
                raise
            return HttpResponseRedirect(_safe_next(request))
        if not allowed or accounts.confirmations_used_up(session):
            record_if_possible(
                request, "wrong code at sign-in", outcome="refused", detail="signed out"
            )
            logout(request)
            return render(
                request,
                "problem.html.j2",
                {"title": TOO_MANY_WRONG_CODES, "sign_in_again": True},
                status=403,
            )
        record_if_possible(request, "wrong code at sign-in", outcome="refused")
        error = (
            "That code didn't work. A code works only once, so wait for the next. If you never set"
            " this up or the code won't work, someone may have your password: on the server, run"
            " checker web-password and then checker web-two-factor-off."
        )
    return render(
        request,
        "two_factor.html.j2",
        {"error": error, "next": request.POST.get("next") or request.GET.get("next", "")},
        status=200 if error is None else 403,
    )


TOO_MANY_WRONG_CODES = "Too many wrong codes, so you've been signed out"


def _setup_page(request, device=None, error=None, status=200, retry=False) -> HttpResponse:
    """The secret goes out only in answer to the password, never from a page a stolen session can
    just open or get by sending a wrong code."""
    return render(
        request,
        "two_factor_setup.html.j2",
        {
            "required": settings.CHECKER_TWO_FACTOR_REQUIRED,
            "error": error,
            "retry": retry,
            "qr": two_factor.qr_code(device) if device else None,
            "secret": two_factor.secret_text(device) if device else None,
        },
        status=status,
    )


@setting_it_up
@login_required
@require_GET
def two_factor_setup(request) -> HttpResponse:
    if two_factor.is_on(request.user):
        return HttpResponseRedirect(reverse("two_factor_manage"))
    return _setup_page(request)


@setting_it_up
@action("started setting up two-factor", consequential=True)
def two_factor_start(request) -> HttpResponse:
    if two_factor.is_on(request.user):
        raise ActionFailed("Two-factor sign-in is already on.")
    return _setup_page(request, two_factor.start(request))


@setting_it_up
@action("turned on two-factor")
def two_factor_turn_on(request) -> HttpResponse:
    """Only the session that gave the password holds a secret to confirm, so no password here."""
    user = request.user
    if two_factor.is_on(user):  # a double-click's other request: the first one did it
        return HttpResponseRedirect(reverse("two_factor_manage"))
    session = request.session.session_key
    allowed = accounts.begin_confirmation(session)
    done = allowed and two_factor.turn_on(request, request.POST.get("code", ""))
    if done:
        accounts.clear_confirmations(session)
        device, codes = done
        otp_login(request, device)
        request.session.cycle_key()
        return render(request, "two_factor_codes.html.j2", {"codes": codes})
    if two_factor.is_on(user):  # the same, when the two requests crossed
        return HttpResponseRedirect(reverse("two_factor_manage"))
    if not allowed or accounts.confirmations_used_up(session):
        raise ActionFailed(TOO_MANY_WRONG_CODES, sign_out=True)
    if two_factor.pending(request) is None:
        raise ActionFailed(
            "That setup has ended. Go to Sign-in security and start again. If you didn't start"
            " again somewhere else, someone may have your password: on the server, change it with"
            " checker web-password."
        )
    words = (
        "That code didn't work. Check that your phone's clock is right, and try the next one. If"
        " you pressed Get started more than once, only the newest code works: start again and"
        " scan it."
    )
    raise ActionFailed(words, page=_setup_page(request, error=words, status=400, retry=True))


@login_required
@require_GET
def two_factor_manage(request) -> HttpResponse:
    user = request.user
    return render(
        request,
        "two_factor_manage.html.j2",
        {
            "on": two_factor.is_on(user),
            "left": two_factor.recovery_codes_left(user),
            "unsaved": two_factor.codes_unsaved(user),
            "code_needed": two_factor.code_needed(request),
            "required": settings.CHECKER_TWO_FACTOR_REQUIRED,
        },
    )


@action("made new recovery codes", consequential=True)
def two_factor_new_codes(request) -> HttpResponse:
    if not two_factor.is_on(request.user):
        raise ActionFailed("Two-factor sign-in is off, so there are no recovery codes to replace.")
    codes = two_factor.new_recovery_codes(request.user)
    return render(request, "two_factor_codes.html.j2", {"codes": codes})


@action("said the recovery codes are saved")
def two_factor_codes_saved(request) -> HttpResponse:
    two_factor.mark_codes_saved(request.user)
    return HttpResponseRedirect(reverse("two_factor_manage"))


@action("turned off two-factor", consequential=True)
def two_factor_turn_off(request) -> HttpResponse:
    two_factor.turn_off(request.user)
    return HttpResponseRedirect(reverse("two_factor_manage"))


@login_required
@require_GET
def fleet_page(request) -> HttpResponse:
    group = request.GET.get("group") or None
    tone = request.GET.get("show") or None
    try:
        hosts, problems = read_fleet(home())
    except EvidenceError as exc:  # the tool's own words, and what to do
        return _unavailable(request, str(exc))
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        # Details may quote a settings file, secrets included: only the kind goes to the log.
        print(f"checker web: can't read the results: {type(exc).__name__}", file=sys.stderr)
        return _unavailable(request, "A settings file or the evidence key can't be read.")
    for problem in problems:
        print(f"checker web: threat pack not applied: {visible(problem, 300)}", file=sys.stderr)
    rows = wording.rows_for(hosts)
    groups = sorted({h.group for h in hosts if h.group})
    tones = [t for t in wording.TONE_NAMES if any(r.tone == t for r in rows)]
    # The filters narrow the list, never the answer at the top: it's about every server.
    shown = [
        r
        for r in rows
        # A removed host has no group: its bad result shouldn't be filtered out of sight.
        if (group is None or r.host.group == group or r.host.removed)
        and (tone is None or r.tone == tone)
    ]
    title, title_tone = wording.headline(rows)
    return render(
        request,
        "fleet.html.j2",
        {
            "headline": title,
            "headline_tone": title_tone,
            "rows": shown,
            "total": len(rows),
            "threat_problem": bool(problems),
            "group": group,
            "groups": groups,
            "tone": tone,
            "tones": [(t, wording.TONE_NAMES[t]) for t in tones],
        },
    )


@login_required
@require_GET
def host_page(request, name: str) -> HttpResponse:
    try:
        found = read_host(home(), name)
    except EvidenceError as exc:
        return _unavailable(request, str(exc))
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        print(f"checker web: can't read the results: {type(exc).__name__}", file=sys.stderr)
        return _unavailable(request, "A settings file or the evidence key can't be read.")
    if found is None:
        return not_found(request)
    record_if_possible(request, "viewed a server's results", name)
    host, assessment, advice, enabled = found
    return render(
        request,
        "host.html.j2",
        {
            "row": wording.row(host),
            **wording.host_details(assessment),
            **wording.advice_details(advice, enabled),
        },
    )


@login_required
@require_GET
def evidence_page(request, name: str) -> HttpResponse:
    try:
        stored = read_evidence(home(), name)
    except EvidenceError as exc:
        return _unavailable(request, str(exc))
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        print(f"checker web: can't read the results: {type(exc).__name__}", file=sys.stderr)
        return _unavailable(request, "A settings file or the evidence key can't be read.")
    if stored is None:
        return not_found(request)
    record_if_possible(request, "viewed a server's evidence", name)
    return render(request, "evidence.html.j2", {"host": name, **wording.evidence_details(stored)})


@login_required
@require_GET
def threats_page(request) -> HttpResponse:
    try:
        stored = read_threats(home())
    except EvidenceError as exc:
        return _unavailable(request, str(exc))
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        print(f"checker web: can't read the results: {type(exc).__name__}", file=sys.stderr)
        return _unavailable(request, "A settings file or the evidence key can't be read.")
    return render(request, "threats.html.j2", wording.threat_details(stored))


ACTIVITY_PAGE = 200


@login_required
@require_GET
def activity_page(request) -> HttpResponse:
    rows = ActionRecord.objects.order_by("-id")
    try:
        before = int(request.GET.get("before", ""))
    except ValueError:
        before = 0
    if 0 < before < 2**63:  # by id, so new lines arriving don't shift the pages
        rows = rows.filter(id__lt=before)
    rows = list(rows[: ACTIVITY_PAGE + 1])
    return render(
        request,
        "activity.html.j2",
        {
            "rows": rows[:ACTIVITY_PAGE],
            "older": rows[ACTIVITY_PAGE - 1].id if len(rows) > ACTIVITY_PAGE else None,
        },
    )


def _unavailable(request, detail: str) -> HttpResponse:
    return render(
        request,
        "problem.html.j2",
        {"title": "The results can't be read right now", "detail": detail},
        status=503,
    )


def _error(request, title: str, status: int) -> HttpResponse:
    return render(request, "problem.html.j2", {"title": title}, status=status)


def bad_request(request, exception=None) -> HttpResponse:
    return _error(request, "That request wasn't understood", 400)


def forbidden(request, exception=None) -> HttpResponse:
    return _error(request, "That isn't allowed", 403)


def csrf_failed(request, reason="") -> HttpResponse:
    return _error(request, "That form has expired: go back, reload it and try again", 403)


def not_found(request, exception=None) -> HttpResponse:
    return _error(request, "There's nothing here", 404)


def server_error(request) -> HttpResponse:
    return _error(request, "Something went wrong in the tool", 500)
