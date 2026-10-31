"""What applies to every request, before anything else reads it."""

from django.http import HttpResponse

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
