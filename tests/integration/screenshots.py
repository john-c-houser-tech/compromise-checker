"""Screenshots for the README and marketing (plan 5.7), from a demo dataset that `demo.py save`
made, through the real pages in a real browser.

The pages are served from a throwaway copy of the dataset, with an account made for this run in
the copy: the dataset itself, whose record of the pages' use is the only one, is only read. Every
page passes through the golden tests' scrubber on its way to the browser, and the run stops if any
public address, or any address the demo's servers had, survives. Each page says it's a demo
fleet. Needs the `shots` extra and a Chromium.

    python tests/integration/screenshots.py --dataset ~/demo-saves/RUN --out docs/screenshots
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

import demo
import golden
from playwright.sync_api import sync_playwright

PAGES = (
    # name, path, width, colours, and whether to take the whole page or the top of a long one
    ("fleet", "/", 1280, "light", True),
    ("fleet-dark", "/", 1280, "dark", True),
    ("fleet-phone", "/", 390, "light", False),
    ("host", "/hosts/shop-web-1", 1280, "light", False),
    ("evidence", "/hosts/shop-web-1/evidence", 1280, "light", False),
    ("threats", "/threats", 1280, "light", True),
)
# Who and where this ran, and what the proofs call things: none belongs in a picture.
NAMES = {
    getpass.getuser(): "operator",
    socket.gethostname(): "controller",
    "proofuser": "appuser",
    "/var/www/proof": "/var/www/shop",
}
FORBIDDEN = re.compile(r"linode|\bli\d+-\d+\b", re.IGNORECASE)
BANNER = (
    '<p class="note">Demo fleet: throwaway servers, attacked on purpose. Real results from'
    " this tool. Addresses replaced.</p>"
)


def named(text: str, names: dict[str, str]) -> str:
    """The scrubber knows addresses. This machine's user and name, and the proofs' scaffolding,
    are replaced here, and the run stops if anything that points at a real machine is left."""
    for old, new in names.items():
        text = re.sub(rf"\b{re.escape(old)}\b", new, text)
    left = [old for old in names if re.search(rf"\b{re.escape(old)}\b", text)]
    if left or FORBIDDEN.search(text):
        raise ValueError("a real name survived scrubbing")
    return text


def scrubbing(wsgi, protect: list[str], pages: list[str], names: dict[str, str] = NAMES):
    """The pages as the browser gets them: scrubbed and checked, or not at all."""

    def application(environ, start_response):
        held = {}

        def start(status, headers, exc_info=None):
            held.update(status=status, headers=headers)
            return lambda data: None

        body = b"".join(wsgi(environ, start))
        headers = held["headers"]
        if any(k.lower() == "content-type" and "text/html" in v for k, v in headers):
            text = body.decode()
            text = named(golden.scrub(text, protect), names)
            golden.check_scrubbed(text, protect)
            # In the page's padded column, under its band if it has one.
            column = '<div class="main-in">'
            if text and column not in text:  # a redirect has no body to label
                raise ValueError("no place for the demo fleet's label")
            text = text.replace(column, f"{column}\n{BANNER}", 1)
            pages.append(environ["PATH_INFO"])
            body = text.encode()
            headers = [(k, v) for k, v in headers if k.lower() != "content-length"]
            headers.append(("Content-Length", str(len(body))))
        start_response(held["status"], headers)
        return [body]

    return application


class Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dataset", type=Path, required=True, help="a folder `demo.py save` made")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", default="Compromise Checker")
    parser.add_argument("--chromium", default=os.environ.get("CHROMIUM", "/usr/bin/chromium"))
    parser.add_argument(
        "--scoring-changed",
        action="store_true",
        help="the checker's scoring changed since the save: take its new results (each is"
        " printed), unless a whitelist rule has expired since the last check",
    )
    args = parser.parse_args()
    dataset = args.dataset.resolve()
    args.out = args.out.resolve()
    if refused := refusal(dataset, args.out):
        sys.exit(f"screenshots: {refused}")
    # The copy holds the evidence key: a stop by signal (a closed terminal, kill) still deletes it.
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, lambda n, frame: sys.exit(128 + n))
    scratch = Path(tempfile.mkdtemp(prefix=".shots-data-", dir=dataset.parent))
    try:
        home = demo.working_copy(dataset, scratch)
        # From here on, the checker's code reads this copy and never the laptop's own home.
        os.environ["CHECKER_HOME"] = str(home)
        score_again(home, scoring_changed=args.scoring_changed)
        names = NAMES | {name: "admin" for name in demo.names_of(dataset)}
        return photograph(home, demo.addresses_of(dataset), names, args)
    except demo.DemoError as exc:
        sys.exit(f"screenshots: {exc}")
    finally:
        try:
            shutil.rmtree(scratch)
        except OSError as exc:
            print(
                f"screenshots: the copy at {scratch} wasn't deleted ({exc}). Delete it: it holds"
                " the evidence key.",
                file=sys.stderr,
            )


def score_again(home: Path, scoring_changed: bool = False) -> None:
    """Each server's latest result worked out again in the copy, with the same evidence and the
    same rules. A stored result names its whitelist by a digest that holds each rule file's full
    path, and the copy's files are in another folder from the server's: without this, every
    server would read "Settings have changed since this result". A rule's expiry counts from the
    day this runs, not the day of the last check, so the run stops if any server's result moves:
    the pictures must show what the checks said.

    When the checker's scoring changed since the save (`scoring_changed`), a result that moves is
    the new code's and is taken, and printed; one that moves because a rule expired still stops
    the run. Each check since each server's baseline is then worked out again too, oldest first,
    and the latest last: the pages compare a result with the check before it and with the one
    before it for the same collection, and would otherwise say "The check before showed" or
    "This same check first showed" the old code's band, a note about the upgrade, not about the
    fleet. A check from before a server's baseline is left as it was: worked out again, it would
    compare with a baseline accepted after it ran."""
    before = results(home)
    _analyze_all(home)
    after = results(home)
    moved = sorted(h for h in before.keys() | after.keys() if before.get(h) != after.get(h))
    if not moved:
        return
    said = ", ".join(f"{h} ({before.get(h)} -> {after.get(h)})" for h in moved)
    if not scoring_changed:
        sys.exit(
            f"screenshots: scoring the copy again changed {said}. A whitelist rule may have"
            " expired since the last check: take the pictures the day the data was saved. If"
            " the checker's scoring changed since the save, --scoring-changed takes the new"
            " results."
        )
    if expired := expired_rules(home):
        sys.exit(
            "screenshots: scoring the copy again changed "
            + said
            + ", and whitelist rules have expired since the last check ("
            + "; ".join(f"{h}: {', '.join(rules)}" for h, rules in sorted(expired.items()))
            + "): the pictures would show results the checks never gave. Take them from a"
            " fresh save."
        )
    for host in moved:
        print(
            f"screenshots: scored by the newer code: {host} {before.get(host)} -> {after.get(host)}"
        )
    for host, bundle in checks_since_baselines(home):
        _analyze(home, [host, "--bundle", bundle])
    if (again := results(home)) != after:
        sys.exit(f"screenshots: scoring the copy a second time moved it again: {after} -> {again}")


def checks_since_baselines(home: Path) -> list[tuple[str, str]]:
    """(server, check) for each check collected since its server's current baseline, oldest
    first, so each server's latest comes last."""
    from checker.baseline import current_baseline, usable_bundles
    from checker.evidence import Store, database_file

    store = Store(database_file(home), read_only=True)
    try:
        found = []
        for host in store.hosts():
            baseline = current_baseline(store, host)
            if baseline is None:
                continue
            since = store.bundle(baseline["bundle_id"])["started_at"]
            rows = [r for r in usable_bundles(store, host) if r["started_at"] >= since]
            found += [(r["started_at"], host, r["id"]) for r in rows]
    finally:
        store.close()
    return [(host, bundle) for _, host, bundle in sorted(found)]


def _analyze_all(home: Path) -> None:
    _analyze(home, ["--all"])


def _analyze(home: Path, words: list[str]) -> None:
    try:
        done = subprocess.run(
            [sys.executable, "-I", "-m", "checker", "analyze", *words],
            env={**os.environ, "CHECKER_HOME": str(home)},
            capture_output=True,
            text=True,
            check=False,
            timeout=1800,  # a hung run would keep the copy, and its evidence key, until killed
        )
    except subprocess.TimeoutExpired:
        sys.exit("screenshots: scoring the copy again took over 30 minutes; stopped")
    if done.returncode:
        sys.exit(f"screenshots: scoring the copy again failed:\n{done.stderr.strip()[-2000:]}")


def expired_rules(home: Path) -> dict[str, list[str]]:
    """The whitelist rules each server's result now finds expired, from the report the copy's
    checker writes (into the copy, which is deleted)."""
    out = home / "screenshots-expired.json"
    done = subprocess.run(
        [sys.executable, "-I", "-m", "checker", "report", "--all", "--format", "json"]
        + ["--plain", "--output", str(out)],
        env={**os.environ, "CHECKER_HOME": str(home)},
        capture_output=True,
        text=True,
        check=False,
        timeout=1800,
    )
    if done.returncode:
        sys.exit(f"screenshots: reading the copy's rules failed:\n{done.stderr.strip()[-2000:]}")
    hosts = json.loads(out.read_text()).get("hosts") or []
    return {
        h["host"]: [str(r) for r in h["whitelist_rules_expired"]]
        for h in hosts
        if h.get("whitelist_rules_expired")
    }


def results(home: Path) -> dict[str, tuple[str | None, float | None]]:
    """Each server's band and chance as the pages show them."""
    from checker.fleet import read_fleet

    hosts, _ = read_fleet(home)
    return {
        h.host: (h.band, None if h.probability is None else round(h.probability, 4)) for h in hosts
    }


def refusal(dataset: Path, out: Path) -> str | None:
    """Why a run mustn't start: the pictures' folder is replaced whole, so it can't be the
    dataset, inside it, or hold it, nor anything but pictures; and an earlier run's copy, with the
    evidence key in it, is dealt with first."""
    if out == dataset or dataset in out.parents or out in dataset.parents:
        return f"--out {out} is the dataset, is inside it or holds it, and it is replaced whole"
    if out.exists() and (
        not out.is_dir() or any(not p.is_file() or p.suffix != ".png" for p in out.iterdir())
    ):
        return f"--out {out} holds more than pictures, and it is replaced whole"
    left = sorted(dataset.parent.glob(".shots-data-*"))
    if left:
        return (
            "an earlier run's copy, with the evidence key in it, is still there: "
            + ", ".join(map(str, left))
            + ". Delete it, then run again."
        )
    return None


def photograph(home: Path, protect: list[str], names: dict[str, str], args) -> int:
    """The pages of the copy at `home`, signed in as an account made in the copy's web.db."""
    os.environ["CHECKER_HOME"] = str(home)
    os.environ["CHECKER_PRODUCT_NAME"] = args.name

    from checker.web.app import configure

    configure(home)

    from django.contrib.auth import get_user_model
    from django.core.wsgi import get_wsgi_application
    from django.utils import timezone
    from django_otp.oath import totp
    from django_otp.plugins.otp_totp.models import TOTPDevice

    from checker.web import first_setup
    from checker.web.models import Access, ActionRecord

    password = secrets.token_urlsafe(24)
    user = get_user_model().objects.create_user("demo", password=password)
    Access.objects.create(user=user, full=True)
    # The pictures show the pages in use, not the first-day reminder to back up the evidence key:
    # in the copy, the account says it's backed up, the line a click on the reminder would add.
    ActionRecord.objects.create(
        at=timezone.now(),
        who="demo",
        address="",
        action=first_setup.KEY_SAVED,
        target=first_setup.this_key(home),
        outcome="done",
        detail="",
    )
    device = TOTPDevice.objects.create(user=user, name="demo", confirmed=True)
    seen: list[str] = []
    server = make_server(
        "127.0.0.1", 0, scrubbing(get_wsgi_application(), protect, seen, names), handler_class=Quiet
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    # Into a new folder first: the pictures there now are replaced only by a run that finishes.
    out = Path(tempfile.mkdtemp(prefix=".shots-", dir=args.out.parent))
    try:
        with sync_playwright() as play:
            browser = play.chromium.launch(executable_path=args.chromium, args=["--no-sandbox"])
            for name, path, width, scheme, whole in PAGES:
                context = browser.new_context(
                    viewport={"width": width, "height": 1400 if width > 500 else 844},
                    color_scheme=scheme,
                    device_scale_factor=2,
                )
                page = context.new_page()
                problems: list[str] = []
                page.on("pageerror", lambda e, out=problems: out.append(str(e)))
                page.goto(f"{base}/login")
                page.fill("input[name=username]", "demo")
                page.fill("input[name=password]", password)
                page.click("main button")
                page.wait_for_load_state()
                # The next code still counts. On its own thread: Playwright's loop runs on
                # this one, and Django won't touch the database from a thread with a loop.
                with ThreadPoolExecutor(1) as one:
                    one.submit(TOTPDevice.objects.filter(pk=device.pk).update, last_t=-1).result()
                page.fill("input[name=code]", f"{totp(device.bin_key):06d}")
                page.click("main button")
                page.wait_for_load_state()
                response = page.goto(base + path)
                if response.status != 200:
                    sys.exit(f"{path}: {response.status}")
                page.wait_for_timeout(400)
                page.screenshot(path=str(out / f"{name}.png"), full_page=whole)
                print(
                    name,
                    "overflow"
                    if page.evaluate("document.documentElement.scrollWidth > innerWidth")
                    else "ok",
                    problems,
                )
                context.close()
            browser.close()
    except BaseException:  # a run that stops leaves the pictures as they were
        shutil.rmtree(out, ignore_errors=True)
        raise
    finally:
        server.shutdown()  # nothing writes into the copy while it is deleted
    shutil.rmtree(args.out, ignore_errors=True)
    out.rename(args.out)
    print(f"{len(seen)} pages scrubbed and checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
