"""What applies to every request, before anything else reads it."""

from urllib.parse import urlencode

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django_otp import user_has_device

CSP = (
    "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


def security_headers(get_response):
    def middleware(request):
        response = get_response(request)
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


BEFORE_SECOND_STEP = set()  # what can be used with only a password so far, kept by identity
SETTING_IT_UP = set()  # and these too, with no second step set up yet


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
