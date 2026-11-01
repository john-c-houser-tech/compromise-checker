"""Screenshots for the README and marketing (plan 5.7), from a demo fleet's home
(demo_fleet.py), through the real pages in a real browser.

Every page passes through the golden tests' scrubber on its way to the browser, and the run
stops if any public address, or any address the demo run noted (the controller's, the servers'),
survives. Each page says it's a demo fleet. Needs the `shots` extra and a Chromium.

    python tests/integration/screenshots.py --home DIR --out docs/screenshots
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import shutil
import socket
import sys
import threading
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

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


def scrubbing(wsgi, protect: list[str], pages: list[str]):
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
            text = named(golden.scrub(text, protect), NAMES)
            golden.check_scrubbed(text, protect)
            if text and "<main>" not in text:  # a redirect has no body to label
                raise ValueError("no place for the demo fleet's label")
            text = text.replace("<main>", f"<main>\n{BANNER}", 1)
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
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", default="Compromise Checker by NouriLoop")
    parser.add_argument("--chromium", default=os.environ.get("CHROMIUM", "/usr/bin/chromium"))
    args = parser.parse_args()
    home = args.home.resolve()
    os.environ["CHECKER_HOME"] = str(home)
    os.environ["CHECKER_PRODUCT_NAME"] = args.name
    protect = json.loads((home / "demo-protect.json").read_text())
    (home / "web.db").unlink(missing_ok=True)  # a throwaway account for this run

    from checker.web.app import configure

    configure(home)

    from django.contrib.auth import get_user_model
    from django.core.wsgi import get_wsgi_application
    from django_otp.oath import totp
    from django_otp.plugins.otp_totp.models import TOTPDevice

    password = secrets.token_urlsafe(24)
    user = get_user_model().objects.create_user("demo", password=password)
    device = TOTPDevice.objects.create(user=user, name="demo", confirmed=True)
    seen: list[str] = []
    server = make_server(
        "127.0.0.1", 0, scrubbing(get_wsgi_application(), protect, seen), handler_class=Quiet
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    shutil.rmtree(args.out, ignore_errors=True)  # nothing left from a run that stopped
    args.out.mkdir(parents=True)
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
            TOTPDevice.objects.filter(pk=device.pk).update(last_t=-1)  # the next code still counts
            page.fill("input[name=code]", f"{totp(device.bin_key):06d}")
            page.click("main button")
            page.wait_for_load_state()
            response = page.goto(base + path)
            if response.status != 200:
                sys.exit(f"{path}: {response.status}")
            page.wait_for_timeout(400)
            page.screenshot(path=str(args.out / f"{name}.png"), full_page=whole)
            print(
                name,
                "overflow"
                if page.evaluate("document.documentElement.scrollWidth > innerWidth")
                else "ok",
                problems,
            )
            context.close()
        browser.close()
    server.shutdown()
    (home / "web.db").unlink(missing_ok=True)
    print(f"{len(seen)} pages scrubbed and checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
