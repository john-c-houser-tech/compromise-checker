"""What applies to every request, before anything else reads it."""

import hmac
from urllib.parse import urlencode

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django_otp import user_has_device

from checker.evidence import acting_for
from checker.web import accounts
from checker.web.actions import record_if_possible
from checker.web.app import PROXY_SECRET_HEADER

CSP = (
    "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


def security_headers(get_response):
    def middleware(request):
        response = get_response(request)
        if response.status_code == 405 and request.method == "GET":  # an address typed or reloaded
            title = "That page only opens from its form"
            response = render(request, "problem.html.j2", {"title": title}, status=405)
        response["Content-Security-Policy"] = CSP
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        # Other sites never see an address here. Not no-referrer: browsers would then send
        # "Origin: null" with forms, and the CSRF check would rightly refuse every one.
        response["Referrer-Policy"] = "same-origin"
        response["Cross-Origin-Opener-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.is_secure():
            response["Strict-Transport-Security"] = "max-age=31536000"
        # Evidence must not stay in a browser's or a proxy's cache.
        if not request.path.startswith(("/style", "/fonts/")):
            response["Cache-Control"] = "no-store"
        return response

    return middleware


_PROXY_SECRET_META = "HTTP_" + PROXY_SECRET_HEADER.upper().replace("-", "_")


def only_through_the_proxy(get_response):
    """Behind a proxy, the port is still open to everyone with an account on this machine. Without
    this, they could connect to it directly and claim any forwarded address, which would get round
    the limits on guessing a login and put a false address in the record. The proxy holds a secret
    they don't, and replaces whatever a client sends in its place."""

    def middleware(request):
        wanted = settings.CHECKER_PROXY_SECRET
        if wanted is not None:
            sent = request.META.get(_PROXY_SECRET_META, "")
            if not wanted or not hmac.compare_digest(sent.encode(), wanted.encode()):
                words = (
                    "This has to be reached through its proxy, and that request didn't come"
                    f" through it. The proxy must send the header {PROXY_SECRET_HEADER}: see the"
                    " guide to the web interface.\n"
                )
                return HttpResponse(words, status=403, content_type="text/plain")
        return get_response(request)

    return middleware


FORM = "application/x-www-form-urlencoded"
MAX_FORM_BYTES = 64 * 1024


def small_forms_only(get_response):
    """Every form here is a few short fields. Refused before the CSRF check parses a
    body: a file part would otherwise be written to disk, however large, for anyone."""

    def middleware(request):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            try:
                length = int(request.META.get("CONTENT_LENGTH") or -1)
            except ValueError:
                length = -1
            if length < 0:
                return HttpResponse("A length is needed.\n", status=411, content_type="text/plain")
            if length > MAX_FORM_BYTES:
                return HttpResponse("Too large.\n", status=413, content_type="text/plain")
            if length and request.content_type != FORM:
                return HttpResponse("Only plain forms.\n", status=415, content_type="text/plain")
        return get_response(request)

    return middleware


def name_the_person(get_response):
    """Whatever this request writes to the evidence store says who is signed in, not which account
    on this machine runs the server."""

    def middleware(request):
        if not request.user.is_authenticated:
            return get_response(request)
        with acting_for(request.user.get_username()):
            return get_response(request)

    return middleware


BEFORE_SECOND_STEP = set()  # what can be used with only a password so far, kept by identity
SETTING_IT_UP = set()  # and these too, with no second step set up yet


FOR_VIEWERS = set()  # what an account that can only view may use, kept by identity


def for_viewers(view):
    FOR_VIEWERS.add(view)
    return view


def before_second_step(view):
    BEFORE_SECOND_STEP.add(view)
    return view


def setting_it_up(view):
    SETTING_IT_UP.add(view)
    return view


class TwoFactorGate:
    """Here and not on each page, so a new page can't forget it. With only a password so far,
    nothing but the second step and signing out is reachable."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view, args, kwargs):
        user = request.user
        if not user.is_authenticated or user.is_verified() or view in BEFORE_SECOND_STEP:
            return None
        if user_has_device(user):
            wanted = request.get_full_path() if request.method == "GET" else ""
            query = f"?{urlencode({'next': wanted})}" if wanted else ""
            return HttpResponseRedirect(reverse("two_factor") + query)
        if settings.CHECKER_TWO_FACTOR_REQUIRED and view not in SETTING_IT_UP:
            return HttpResponseRedirect(reverse("two_factor_setup"))
        return None


class AccessGate:
    """Here and not on each page, so a new page is closed to those who can only view until someone
    decides otherwise."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view, args, kwargs):
        user = request.user
        if (
            not user.is_authenticated
            or view in FOR_VIEWERS
            or view in BEFORE_SECOND_STEP
            or view in SETTING_IT_UP
            or accounts.has_full_access(user)
        ):
            return None
        if request.method not in ("GET", "HEAD"):
            record_if_possible(request, "tried what needs full access", request.path, "refused")
        context = {
            "title": "Your account can view results, but not do this",
            "detail": "Ask someone with full access if it needs doing.",
        }
        return render(request, "problem.html.j2", context, status=403)
