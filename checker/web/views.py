"""Pages. Viewing pages only read; the only writes here are to accounts and sessions."""

from __future__ import annotations

import ipaddress
import sys
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import Resolver404, resolve, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from checker.evidence import EvidenceError
from checker.fleet import read_fleet
from checker.inventory import home
from checker.report import visible
from checker.web import accounts, wording
from checker.web.app import HERE, is_local

# Where a login may go on to: not a form's address, which would land on an error.
VIEWABLE = {"fleet"}


def client_address(request) -> str:
    """Whose failed logins these are, for throttling. Behind the proxy on this machine
    every peer is the proxy, so one person could lock everyone out: there it is the last
    forwarded address, the one the proxy added itself (earlier ones are whatever the
    client sent). IPv6 counts by network, since one client can hold a whole /64."""
    address = request.META.get("REMOTE_ADDR", "")
    if settings.CHECKER_BEHIND_PROXY and is_local(address):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "").rpartition(",")[2].strip()
        address = forwarded or address
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    if parsed.version == 4:
        return str(parsed)
    if parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return str(ipaddress.ip_network(f"{parsed}/64", strict=False))


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
            user = accounts.create_first_account(token, username, password)
            if user is None:
                return render(
                    request, "problem.html.j2", {"title": "This link isn't valid"}, status=404
                )
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            return HttpResponseRedirect(reverse("fleet"))
    return render(request, "setup.html.j2", {"errors": errors, "username": username})


@require_http_methods(["GET", "POST"])
def login_page(request) -> HttpResponse:
    error = None
    if request.method == "POST":
        username = accounts.normal_name(request.POST.get("username", ""))[:150]
        password = request.POST.get("password", "")
        address = client_address(request)
        # One message for all of it: a page mustn't say which usernames exist.
        error = "That username and password didn't work."
        if accounts.throttled(username, address):
            error = "Too many failed attempts. Wait 15 minutes and try again."
        else:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                accounts.clear_failures(username, address)
                login(request, user)
                return HttpResponseRedirect(_safe_next(request))
            accounts.record_failure(username, address)
    return render(
        request,
        "login.html.j2",
        {"error": error, "next": request.GET.get("next", "")},
        status=200 if error is None else 403,
    )


@require_POST
def logout_page(request) -> HttpResponse:
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
