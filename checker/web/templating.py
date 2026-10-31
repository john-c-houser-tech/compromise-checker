"""Pages use Jinja2, with the report's rule: every printed value is escaped and has its
invisible characters shown, whether or not the template asked. Host text can't opt out."""

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


def environment(**options) -> Environment:
    options.update(autoescape=True, finalize=_finalize_page, trim_blocks=True, lstrip_blocks=True)
    env = Environment(**options)  # noqa: S701 - autoescape is set just above
    env.filters["visible"] = visible
    env.filters["percent"] = percent
    env.filters["when"] = when
    env.globals["url"] = lambda view, **kwargs: reverse(view, kwargs=kwargs or None)
    env.globals["product_name"] = product_name
    env.globals["host_url"] = host_url
    return env
