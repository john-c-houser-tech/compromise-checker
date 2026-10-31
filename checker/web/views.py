"""Pages. Viewing pages only read; the only writes here are to accounts and sessions."""

from __future__ import annotations

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from pydantic import ValidationError as SettingsError
from yaml import YAMLError

from checker.evidence import EvidenceError
from checker.fleet import UNREADABLE, read_fleet, serious
from checker.inventory import home
from checker.web import accounts
from checker.web.app import HERE


def _address(request) -> str:
    return request.META.get("REMOTE_ADDR", "")


def _safe_next(request) -> str:
    wanted = request.POST.get("next") or request.GET.get("next") or ""
    if url_has_allowed_host_and_scheme(
        wanted, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return wanted
    return reverse("fleet")


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
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        if not username:
            errors.append("Choose a username.")
        if password != request.POST.get("password2", ""):
            errors.append("The two passwords don't match.")
        try:
            validate_password(password)
        except ValidationError as exc:
            errors.extend(exc.messages)
        if not errors:
            user = accounts.create_first_account(token, username[:150], password)
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
        username = request.POST.get("username", "")[:150]
        password = request.POST.get("password", "")
        address = _address(request)
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
    try:
        hosts, problems = read_fleet(home(), group=group)
    except (EvidenceError, OSError, SettingsError, YAMLError) as exc:
        return render(
            request,
            "problem.html.j2",
            {"title": "The results can't be read right now", "detail": str(exc)},
            status=503,
        )
    return render(
        request,
        "fleet.html.j2",
        {
            "hosts": hosts,
            "problems": problems,
            "group": group,
            "unreadable_words": UNREADABLE,
            "serious": serious,
        },
    )


def _error(request, title: str, status: int) -> HttpResponse:
    return render(request, "problem.html.j2", {"title": title}, status=status)


def bad_request(request, exception=None) -> HttpResponse:
    return _error(request, "That request wasn't understood", 400)


def forbidden(request, exception=None) -> HttpResponse:
    return _error(request, "That isn't allowed", 403)


def not_found(request, exception=None) -> HttpResponse:
    return _error(request, "There's nothing here", 404)


def server_error(request) -> HttpResponse:
    return _error(request, "Something went wrong in the tool", 500)
