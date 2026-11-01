"""Pages. Viewing pages read the results; the only writes here are to accounts, sessions and the
record of who looked."""

from __future__ import annotations

import json
import sqlite3
import sys
from urllib.parse import urlencode, urlsplit

import yaml
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
from pydantic import ValidationError as InvalidSettings

from checker import schedule
from checker.evidence import EvidenceError
from checker.fleet import read_evidence, read_fleet, read_host, read_threats
from checker.inventory import home, load_inventory
from checker.report import visible
from checker.settings import remove_host
from checker.web import accounts, decide, manage, runs, two_factor, wording
from checker.web.actions import ActionFailed, action, record, record_if_possible
from checker.web.app import HERE
from checker.web.middleware import before_second_step, setting_it_up
from checker.web.models import ActionRecord, CheckRun
from checker.whitelist import WhitelistError

# Where a login may go on to: not a form's address, which would land on an error.
VIEWABLE = {
    "fleet",
    "host",
    "evidence",
    "threats",
    "activity",
    "checks",
    "check",
    "decide",
    "manage",
    "manage_add",
    "manage_server",
    "two_factor_manage",
}


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
    try:
        can_check = any(h.name == name for h in load_inventory().hosts)
    except Exception:  # noqa: BLE001 - a broken inventory only loses the button here
        can_check = False
    return render(
        request,
        "host.html.j2",
        {
            "row": wording.row(host),
            "can_check": can_check,
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


def _inventory_hosts(request, names: list[str]) -> list:
    """Those of the inventory's hosts named, or all of them if none are. Anything else in `names` is
    dropped: only the inventory decides what a check connects to."""
    hosts = load_inventory().hosts
    return [host for host in hosts if not names or host.name in names]


def _check_plan(request, names: list[str]) -> tuple[list, list, list]:
    """What can go ahead as it is, what needs a password typed, and what can't, and why."""
    ready, asking, blocked = [], [], []
    for host in _inventory_hosts(request, names):
        typed = schedule.needs_typed_password(host)
        problems = manage.check_blockers(host)
        if problems:
            blocked.append((host.name, str(visible(" ".join(problems), 600))))
        elif typed:
            asking.append(host)
        else:
            ready.append(host)
    return ready, asking, blocked


def _unreadable_inventory(request, exc) -> HttpResponse:
    print(f"checker web: can't read the servers: {type(exc).__name__}", file=sys.stderr)
    return _unavailable(request, "The list of servers can't be read.")


def _known_host(name: str) -> bool:
    return bool(name) and any(host.name == name for host in load_inventory().hosts)


def _posted_host(request, **kwargs) -> str:
    return request.POST.get("host", "")


@login_required
@require_GET
def manage_page(request) -> HttpResponse:
    """Read from this machine's files alone: no server is contacted to show this."""
    try:
        rows, groups = manage.rows(home())
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        return _unreadable_inventory(request, exc)
    return render(request, "manage.html.j2", {"rows": rows, "groups": groups})


def _add_form(request, values=None, problem: str = "", status: int = 200, ask_same: bool = False):
    try:
        groups = manage.group_names(home())
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        return _unreadable_inventory(request, exc)
    context = {
        "values": values if values is not None else manage.blank_form(),
        "problem": problem,
        "ask_same": ask_same,
        "groups": groups,
        "code_needed": two_factor.code_needed(request),
    }
    return render(request, "manage_add.html.j2", context, status=status)


@login_required
@require_GET
def manage_add(request) -> HttpResponse:
    return _add_form(request)


def _server_page(
    request,
    name: str,
    values=None,
    version=None,
    problem="",
    key_problem="",
    offer=None,
    status=200,
):
    host = load_inventory().get(name)
    try:
        earlier = manage.has_results(home(), name)
    except Exception as exc:  # noqa: BLE001 - only a link depends on it
        print(f"checker web: can't read the results: {type(exc).__name__}", file=sys.stderr)
        earlier = False
    context = {
        "host": host,
        "values": values if values is not None else manage.form_of(host),
        "version": version or host.version(),
        "problem": problem,
        "key_problem": key_problem,
        "offer": offer,
        "trusted": manage.trust_of(host),
        "stops": schedule.host_problems_in_plain_words(host),
        "earlier": earlier,
        "groups": manage.group_names(home()),
        "code_needed": two_factor.code_needed(request),
    }
    return render(request, "manage_server.html.j2", context, status=status)


@login_required
@require_GET
def manage_server(request) -> HttpResponse:
    name = request.GET.get("host", "")
    try:
        if not _known_host(name):
            return not_found(request)
        return _server_page(request, name)
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        return _unreadable_inventory(request, exc)


def _back_to_server(name: str) -> HttpResponse:
    return HttpResponseRedirect(f"{reverse('manage_server')}?{urlencode({'host': name})}")


CANT_MANAGE = "That couldn't be done: the list of servers or the evidence store can't be written."
GONE = "That server isn't in the list of servers any more."
MANAGE_FAILURES = (
    OSError,
    sqlite3.Error,
    yaml.YAMLError,
    InvalidSettings,
    EvidenceError,
    UnicodeError,
)


def _posted_name(request, **kwargs) -> str:
    return request.POST.get("name", "")


@action("added a server", consequential=True, target=_posted_name)
def server_add(request) -> HttpResponse:
    """Password again: every later check connects to what this names, as root."""
    values = manage.form_values(request.POST)
    try:
        host = manage.host_from_form(request.POST)
        manage.add(home(), host, same_server=request.POST.get("same_server") == "on")
        request.action_detail = manage.settings_in_words(host)
    except manage.FormProblem as exc:
        words = str(visible(str(exc), 600))
        same = isinstance(exc, manage.EarlierResults)
        page = _add_form(request, values, words, 400, ask_same=same)
        raise ActionFailed(words, page=page) from None
    except MANAGE_FAILURES as exc:
        print(f"checker web: adding a server failed: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed(CANT_MANAGE) from None
    return _back_to_server(host.name)


def _listed(request) -> str:
    name = request.POST.get("host", "")
    try:
        known = _known_host(name)
    except Exception as exc:  # noqa: BLE001 - whatever it is, words and not a stack trace
        print(f"checker web: can't read the servers: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed("The list of servers can't be read.") from None
    if not known:
        raise ActionFailed("That server isn't in the list of servers.")
    return name


@action("changed a server's settings", consequential=True, target=_posted_host)
def server_change(request) -> HttpResponse:
    """Password again: its group, for one, decides which rules hide its findings."""
    name = _listed(request)
    values = manage.form_values(request.POST)
    try:
        version = request.POST.get("version", "")
        changed = manage.change(home(), name, request.POST, version)
    except manage.ChangedMeanwhile as exc:
        # The settings as they are now, so saving again can't undo what someone else did unseen.
        words = str(exc)
        page = _server_page(request, name, problem=words, status=400)
        raise ActionFailed(words, page=page) from None
    except manage.FormProblem as exc:
        # What they typed, against what they started from: if that's old, saving again is refused.
        words = str(visible(str(exc), 600))
        page = _server_page(
            request, name, values=values, version=version, problem=words, status=400
        )
        raise ActionFailed(words, page=page) from None
    except KeyError:
        raise ActionFailed(GONE) from None
    except MANAGE_FAILURES as exc:
        print(f"checker web: changing a server failed: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed(CANT_MANAGE) from None
    request.action_detail = manage.changes_in_words(changed)
    return _back_to_server(name)


@action("removed a server", consequential=True, target=_posted_host)
def server_remove(request) -> HttpResponse:
    name = _listed(request)
    try:
        request.action_detail = manage.settings_in_words(load_inventory().get(name))
        remove_host(home(), name)
    except KeyError:
        raise ActionFailed(GONE) from None
    except MANAGE_FAILURES as exc:
        print(f"checker web: removing a server failed: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed(CANT_MANAGE) from None
    return HttpResponseRedirect(reverse("manage"))


def _key_offered(request, name: str):
    """(host, what it offers), or the server's page saying why it couldn't be asked."""
    try:
        host = load_inventory().get(name)
    except KeyError:
        raise ActionFailed(GONE) from None
    try:
        return host, manage.ask_for_key(host)
    except manage.KeyUnavailable as exc:
        words = str(visible(str(exc), 600))
        page = _server_page(request, name, key_problem=words, status=400)
        raise ActionFailed(words, page=page) from None


@action("asked a server for its host key", target=_posted_host)
def server_key_ask(request) -> HttpResponse:
    """A POST, though it changes nothing here: it makes this machine contact a server, which a link
    on someone else's page mustn't be able to do."""
    name = _listed(request)
    _, check = _key_offered(request, name)
    return _server_page(request, name, offer=manage.offer_of(check))


@action("trusted a server's host key", consequential=True, target=_posted_host)
def server_key_trust(request) -> HttpResponse:
    """The key is fetched again, and has to be the one the person pasted from the server itself:
    what a page showed them proves nothing, since whoever is in the middle would have sent that."""
    name = _listed(request)
    host, check = _key_offered(request, name)
    try:
        wrote = manage.trust(
            host, check, request.POST.get("pasted", ""), request.POST.get("replace") == "on"
        )
    except manage.FormProblem as exc:
        words = str(visible(str(exc), 600))
        offer = manage.offer_of(check)
        page = _server_page(request, name, key_problem=words, offer=offer, status=400)
        # Only its start: the Activity page shows this, and the whole of it could be pasted.
        said = f"{words} It offered a key starting {check.fingerprint[:15]}."
        raise ActionFailed(said, page=page) from None
    except OSError as exc:
        print(f"checker web: trusting a key failed: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed(CANT_MANAGE) from None
    request.action_detail = check.fingerprint + ("" if wrote else ": already trusted")
    return _back_to_server(name)


@login_required
@require_GET
def checks_page(request) -> HttpResponse:
    rows = list(CheckRun.objects.order_by("-id")[: runs.KEEP])
    return render(
        request,
        "checks.html.j2",
        {"rows": [_run_row(run) for run in rows]},
    )


def _run_row(run) -> dict:
    return {
        "id": run.id,
        "kind": {"analysis": "Analysis", "advice": "AI advice"}.get(run.kind, "Check"),
        "hosts": ", ".join(json.loads(run.hosts)),
        "who": run.who,
        "started": run.started_at,
        "state": runs.state_of(run),
        "running": runs.is_running(run.id),
    }


@login_required
@require_GET
def check_new(request) -> HttpResponse:
    names = request.GET.getlist("host")
    try:
        ready, asking, blocked = _check_plan(request, names)
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        return _unreadable_inventory(request, exc)
    return render(
        request,
        "check_new.html.j2",
        {
            "ready": ready,
            "asking": asking,
            "blocked": blocked,
            "unknown": bool(names) and not (ready or asking or blocked),
        },
    )


def _names_of(request, **kwargs) -> str:
    return ", ".join(request.POST.getlist("host")) or "every server"


@action("started a check", target=_names_of)
def check_start(request) -> HttpResponse:
    try:
        ready, asking, _ = _check_plan(request, request.POST.getlist("host"))
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        print(f"checker web: can't read the servers: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed("The list of servers can't be read.") from None
    passwords = {host.name: request.POST.get(f"password-{host.name}", "") for host in asking}
    missing = [name for name, password in passwords.items() if not password]
    if missing:
        raise ActionFailed(f"Type the password for {', '.join(missing)} and try again.")
    hosts = [host.name for host in [*ready, *asking]]
    if not hosts:
        raise ActionFailed("None of those servers can be checked from here yet.")
    return _start_run(request, "check", hosts, passwords)


def _start_run(request, kind: str, hosts: list[str], passwords=None) -> HttpResponse:
    try:
        run_id = runs.start(
            kind,
            hosts,
            request.user.get_username(),
            accounts.client_address(request),
            passwords,
        )
    except runs.AlreadyRunning as exc:  # a double-click's other half, or someone else's
        where = reverse("check", kwargs={"run_id": exc.run_id}) + "?busy=1"
        raise ActionFailed(
            "another check was already running", page=HttpResponseRedirect(where)
        ) from None
    except OSError as exc:
        print(f"checker web: a check didn't start: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed("The check couldn't be started.") from None
    return HttpResponseRedirect(reverse("check", kwargs={"run_id": run_id}))


@action("started an analysis", target=lambda request, **kwargs: request.POST.get("host", ""))
def analyze_start(request) -> HttpResponse:
    """Runs the checks again on what was last collected, connecting to nothing: after a new threat
    pack or a changed rule, say."""
    name = request.POST.get("host", "")
    try:
        known = any(host.name == name for host in _inventory_hosts(request, [name]))
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        print(f"checker web: can't read the servers: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed("The list of servers can't be read.") from None
    if not name or not known:
        raise ActionFailed("That server isn't in the list of servers.")
    return _start_run(request, "analysis", [name])


@login_required
@require_GET
def check_page(request, run_id: int) -> HttpResponse:
    if run_id >= 2**63:
        return not_found(request)
    run = CheckRun.objects.filter(pk=run_id).first()
    if run is None:
        return not_found(request)
    return render(
        request,
        "check.html.j2",
        {
            "run": _run_row(run),
            "lines": runs.output_lines(run.id),
            "busy": "busy" in request.GET,
            "from_decide": run.kind == "advice",
        },
    )


@action("stopped a check", target=lambda request, run_id, **kwargs: str(run_id))
def check_stop(request, run_id: int) -> HttpResponse:
    if run_id >= 2**63 or not runs.stop(run_id):
        raise ActionFailed("That check isn't running any more.")
    return HttpResponseRedirect(reverse("check", kwargs={"run_id": run_id}))


def _posted_rule(request, **kwargs) -> str:
    what = request.POST.get("rule") or request.POST.get("file", "")
    return f"{request.POST.get('host', '')}: {what}"


@login_required
@require_GET
def decide_page(request) -> HttpResponse:
    """Everything shown here is what a decision would do, worked out without changing anything."""
    name = request.GET.get("host", "")
    try:
        if not _known_host(name):
            return not_found(request)
        found = read_host(home(), name)
        choice = decide.baseline_choice(home(), name)
        owner = request.user.get_username()
        rules, more_rules = decide.previews(home(), name, owner)
        enabled = found[3] if found else False
    except EvidenceError as exc:
        return _unavailable(request, str(exc))
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        print(f"checker web: can't read the results: {type(exc).__name__}", file=sys.stderr)
        return _unavailable(request, "A settings file or the evidence key can't be read.")
    record_if_possible(request, "viewed what could be decided about a server", name)
    return render(
        request,
        "decide.html.j2",
        {
            "name": name,
            "row": wording.row(found[0]) if found else None,
            "choice": choice,
            "rules": rules,
            "more_rules": more_rules,
            "advisor_on": enabled,
            "code_needed": two_factor.code_needed(request),
            "worried": bool(found) and found[0].band in decide.TOO_WORRYING,
        },
    )


def _back_to_decide(name: str) -> HttpResponse:
    return HttpResponseRedirect(f"{reverse('decide')}?{urlencode({'host': name})}")


def _rule_from_form(request) -> tuple[str, str, str]:
    post = request.POST
    return post.get("host", ""), post.get("file", ""), post.get("digest", "")


CANT_DECIDE = "That couldn't be done: a file or the evidence store can't be read or written."


def _deciding(request, work) -> HttpResponse:
    """Whatever stands in its way, in words, and the record says it failed."""
    name = request.POST.get("host", "")
    try:
        if not _known_host(name):
            raise ActionFailed("That server isn't in the list of servers.")
        work(name)
    except ActionFailed:
        raise
    except (ValueError, EvidenceError) as exc:
        raise ActionFailed(str(visible(str(exc), 600))) from None
    except (OSError, sqlite3.Error, yaml.YAMLError, WhitelistError) as exc:
        print(f"checker web: a decision failed: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed(CANT_DECIDE) from None
    return _back_to_decide(name)


@action("accepted a baseline", consequential=True, target=_posted_host)
def baseline_accept(request) -> HttpResponse:
    return _deciding(
        request,
        lambda name: decide.accept_baseline(
            home(),
            name,
            request.POST.get("bundle", ""),
            request.POST.get("sight", ""),
            request.POST.get("reason", ""),
            request.user.get_username(),
        ),
    )


@action("approved a whitelist rule", consequential=True, target=_posted_rule)
def rule_approve(request) -> HttpResponse:
    _, file, digest = _rule_from_form(request)
    sight = request.POST.get("sight", "")
    who = request.user.get_username()
    return _deciding(request, lambda name: decide.approve(home(), name, file, digest, sight, who))


@action("refused a whitelist rule", target=_posted_rule)
def rule_refuse(request) -> HttpResponse:
    _, file, digest = _rule_from_form(request)
    return _deciding(request, lambda name: decide.refuse(home(), name, file, digest))


@action("discarded a proposal file", target=_posted_rule)
def rule_discard(request) -> HttpResponse:
    _, file, _ = _rule_from_form(request)
    return _deciding(request, lambda name: decide.discard(home(), name, file))


@action("asked the AI advisor for rules", consequential=True, target=_posted_host)
def rules_ask(request) -> HttpResponse:
    """The password, since this spends the organization's money."""
    name = _posted_host(request)
    try:
        known = _known_host(name)
    except Exception as exc:  # noqa: BLE001 - whatever it is, a plain page and not a stack trace
        print(f"checker web: can't read the servers: {type(exc).__name__}", file=sys.stderr)
        raise ActionFailed("The list of servers can't be read.") from None
    if not known:
        raise ActionFailed("That server isn't in the list of servers.")
    return _start_run(request, "advice", [name])


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
