"""Pages. Viewing pages read the results; the only writes here are to accounts, sessions and the
record of who looked."""

from __future__ import annotations

import sys
from urllib.parse import urlsplit

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import Resolver404, resolve, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from checker.evidence import EvidenceError
from checker.fleet import read_evidence, read_fleet, read_host, read_threats
from checker.inventory import home
from checker.report import visible
from checker.web import accounts, wording
from checker.web.actions import record, record_if_possible
from checker.web.app import HERE
from checker.web.models import ActionRecord

# Where a login may go on to: not a form's address, which would land on an error.
VIEWABLE = {"fleet", "host", "evidence", "threats", "activity"}


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


@require_GET
def font(request, name: str) -> HttpResponse:
    """Only these files, by exact name: nothing typed in a URL reaches the file system."""
    if name not in FONTS:
        return not_found(request)
    data = (HERE / "static" / "fonts" / name).read_bytes()
    response = HttpResponse(data, content_type="font/woff2")
    response["Cache-Control"] = "max-age=86400"
    return response


@require_GET
def stylesheet(request) -> HttpResponse:
    response = HttpResponse((HERE / "static" / "style.css").read_bytes(), content_type="text/css")
    response["Cache-Control"] = "max-age=3600"
    return response


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
            with transaction.atomic():  # no account without its line in the record
                user = accounts.create_first_account(token, username, password)
                if user is not None:
                    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
                    record(request, "created the first account")
            if user is None:
                return render(
                    request, "problem.html.j2", {"title": "This link isn't valid"}, status=404
                )
            return HttpResponseRedirect(reverse("fleet"))
    return render(request, "setup.html.j2", {"errors": errors, "username": username})


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
                accounts.clear_failures(username, address)
                login(request, user)
                record(request, "signed in")
                return HttpResponseRedirect(_safe_next(request))
    return render(
        request,
        "login.html.j2",
        {"error": error, "next": request.GET.get("next", "")},
        status=200 if error is None else 403,
    )


@require_POST
def logout_page(request) -> HttpResponse:
    if request.user.is_authenticated:  # anyone can post here: only a real sign-out is kept
        record_if_possible(request, "signed out")  # nothing may stop someone signing out
    logout(request)
    return HttpResponseRedirect(reverse("login"))


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
