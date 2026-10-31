"""Headers on every response, error pages included."""

CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


def security_headers(get_response):
    def middleware(request):
        response = get_response(request)
        response["Content-Security-Policy"] = CSP
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["Referrer-Policy"] = "no-referrer"
        response["Cross-Origin-Opener-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        # Evidence must not stay in a browser's or a proxy's cache.
        if not request.path.startswith("/style"):
            response["Cache-Control"] = "no-store"
        return response

    return middleware
