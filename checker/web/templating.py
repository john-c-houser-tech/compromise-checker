"""Pages use Jinja2, with the report's rule: every printed value is escaped and has its
invisible characters shown, whether or not the template asked. Host text can't opt out."""

from django.db import DatabaseError
from django.urls import NoReverseMatch, reverse
from jinja2 import Environment, Undefined

from checker.product import product_name
from checker.report import _finalize, visible
from checker.scoring import percent
from checker.web.wording import when


def host_url(name: str) -> str | None:
    """A host's page, or None for a name no URL can hold: it mustn't take down the list."""
    try:
        return reverse("host", kwargs={"name": name})
    except NoReverseMatch:
        return None


def _finalize_page(value):
    """The report's rule, plus Django's own safe markup (the CSRF field). Text from a
    host is a plain string, which has no __html__, so it can't pass as markup."""
    if isinstance(value, Undefined):
        return ""
    return value if hasattr(value, "__html__") else _finalize(value)


def fully_signed_in(request) -> bool:
    """As the gate sees it, for pages it doesn't reach, like a missing address. An error page
    mustn't fail for want of it."""
    from django.conf import settings
    from django_otp import user_has_device

    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return False
    try:
        is_verified = getattr(user, "is_verified", None)
        if is_verified is not None and is_verified():
            return True
        return not user_has_device(user) and not settings.CHECKER_TWO_FACTOR_REQUIRED
    except DatabaseError:
        return False


def full_access(request) -> bool:
    """For hiding what the gate would refuse. An error page mustn't fail for want of it."""
    from checker.web.accounts import has_full_access  # needs Django set up

    user = getattr(request, "user", None)
    if user is None:
        return False
    try:
        return has_full_access(user)
    except DatabaseError:
        return False


def two_factor_nudge(request) -> str | None:
    """What the reminder on every page should say, if anything: "off" or "unsaved"."""
    from checker.web import two_factor  # it needs Django set up further than this module does

    if not fully_signed_in(request):
        return None
    try:
        if not two_factor.is_on(request.user):
            return "off"
        return "unsaved" if two_factor.codes_unsaved(request.user) else None
    except DatabaseError:
        return None


def machine_notices(request) -> list[str]:
    """What the page should say about this machine, from what its root service wrote down: for
    people with full access, who look after it, and only once they're fully signed in."""
    from checker import machine_status

    if not fully_signed_in(request) or not full_access(request):
        return []
    return machine_status.notices()


def theme(request) -> str:
    """ "light" or "dark" when chosen in the top bar; empty to follow the browser."""
    from django.conf import settings

    chosen = getattr(request, "COOKIES", {}).get(settings.CHECKER_THEME_COOKIE, "")
    return chosen if chosen in ("light", "dark") else ""


def page_back(request) -> str:
    """Where choosing a theme returns to: this page, unless it came from a form."""
    if getattr(request, "method", "") == "GET":
        return request.get_full_path()
    return reverse("fleet")


def initial(request) -> str:
    """The first letter of the signed-in name, for the round badge in the top bar."""
    user = getattr(request, "user", None)
    name = user.get_username() if user is not None and user.is_authenticated else ""
    return name[:1].upper()


SECTIONS = (  # which part of the top bar each page belongs to, by its URL name's start
    ("two_factor", "security"),
    ("password_change", "security"),
    ("check", "checks"),
    ("analyze", "checks"),
    ("threats", "threats"),
    ("activity", "activity"),
    ("fleet", "servers"),
    ("host", "servers"),
    ("evidence", "servers"),
    ("decide", "servers"),
    ("baseline", "servers"),
    ("rule", "servers"),
)


def section(request) -> str:
    """The top bar's entry for this page: everything not named above is under Manage."""
    match = getattr(request, "resolver_match", None)
    name = getattr(match, "url_name", "") or ""
    for start, part in SECTIONS:
        if name.startswith(start):
            return part
    return "manage" if name else ""


def environment(**options) -> Environment:
    options.update(autoescape=True, finalize=_finalize_page, trim_blocks=True, lstrip_blocks=True)
    env = Environment(**options)  # noqa: S701 - autoescape is set just above
    env.filters["visible"] = visible
    env.filters["percent"] = percent
    env.filters["when"] = when
    env.globals["url"] = lambda view, **kwargs: reverse(view, kwargs=kwargs or None)
    env.globals["product_name"] = product_name
    env.globals["two_factor_nudge"] = two_factor_nudge
    env.globals["machine_notices"] = machine_notices
    env.globals["theme"] = theme
    env.globals["page_back"] = page_back
    env.globals["initial"] = initial
    env.globals["section"] = section
    env.globals["fully_signed_in"] = fully_signed_in
    env.globals["full_access"] = full_access
    env.globals["host_url"] = host_url
    return env
