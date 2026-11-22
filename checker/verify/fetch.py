"""Downloads for verification: public package files, size- and time-capped.

The signatures carry the trust, so a plain-HTTP mirror would do, but the
default addresses are HTTPS; redirects stay on the same host. What is sent: the file's address and
a User-Agent naming the checker and its version, nothing about the user or
their servers. Ubuntu's archive answers 403 to Python's default User-Agent
for package files (V.1), which is one more reason to send our own.
"""

from __future__ import annotations

import http.client
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Protocol

from checker import __version__

TIMEOUT = 20  # seconds for one socket read
USER_AGENT = f"compromise-checker/{__version__}"


class FetchError(Exception):
    """A download failed (other than "not there")."""


class Fetcher(Protocol):
    def get(self, url: str, limit: int, first: int | None = None) -> bytes | None:
        """The file's bytes (only its first `first` bytes, if given), None if
        it isn't there (404 or 410); FetchError past `limit` or on failure."""


class _SameHost(urllib.request.HTTPRedirectHandler):
    """Redirects only within the same host, only to http or https, and
    never from https down to http; at most a few."""

    max_redirections = 4

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if new.scheme not in ("http", "https") or (old.scheme == "https" and new.scheme != "https"):
            raise urllib.error.URLError(f"refused a redirect to {newurl[:200]}")
        if (new.hostname or "").lower() != (old.hostname or "").lower():
            raise urllib.error.URLError(f"refused a redirect to another host: {newurl[:200]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RunClock:
    """The time a whole run's servers may spend waiting on downloads, all
    together (`verify.seconds_per_run`, #217). Only time inside requests
    counts: collecting and analysing don't, so a large fleet doesn't use it
    up by being large."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.used = 0.0

    def left(self) -> float:
        return self.seconds - self.used


class HttpFetcher:
    """Fetcher over HTTP and HTTPS, with one overall deadline for the
    server it checks, and the run's clock (if any) shared with the others.

    Each request runs in a worker thread that is given up on at the
    deadline, so a server that is slow to connect or to send its headers
    can't hold the run past it (the thread itself ends at its socket
    timeout)."""

    def __init__(self, deadline: float = 60.0, run: RunClock | None = None):
        self.deadline = deadline
        self.run = run
        self.ends: float | None = None  # set at the first download, not before
        self.started: float | None = None  # the request under way, if one is
        self.opener = urllib.request.build_opener(_SameHost())

    def left(self) -> float:
        now = time.monotonic()
        if self.ends is None:
            self.ends = now + self.deadline
        left = self.ends - now
        if self.run is not None:
            under_way = now - self.started if self.started is not None else 0.0
            left = min(left, self.run.left() - under_way)
        return left

    def get(self, url: str, limit: int, first: int | None = None) -> bytes | None:
        if not url.lower().startswith(("http://", "https://")):
            raise FetchError(f"not a web address: {url[:200]}")
        if self.left() <= 0:
            raise FetchError("out of time for verification")
        self.started = time.monotonic()
        try:
            return self._timed(url, limit, first)
        finally:
            if self.run is not None:
                self.run.used += time.monotonic() - self.started
            self.started = None

    def _timed(self, url: str, limit: int, first: int | None) -> bytes | None:
        outcome: dict = {}

        def work():
            try:
                outcome["data"] = self._get(url, limit, first)
            except BaseException as exc:  # noqa: BLE001 - handed to the caller
                outcome["error"] = exc

        worker = threading.Thread(target=work, name="checker-verify-fetch", daemon=True)
        worker.start()
        worker.join(max(self.left(), 0))
        if worker.is_alive():
            raise FetchError(f"{url[:200]}: out of time for verification")
        if "error" in outcome:
            raise outcome["error"]
        return outcome["data"]

    def _get(self, url: str, limit: int, first: int | None) -> bytes | None:
        headers = {"User-Agent": USER_AGENT}
        if first is not None:
            headers["Range"] = f"bytes=0-{first - 1}"
            limit = min(limit, first)
        request = urllib.request.Request(url, headers=headers)  # noqa: S310 - http(s), checked
        timeout = max(min(TIMEOUT, self.left()), 1)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                chunks, size = [], 0
                while size <= limit:
                    if self.left() <= 0:
                        raise FetchError(f"{url[:200]}: out of time for verification")
                    chunk = response.read1(min(65536, limit + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if first is not None and size >= first:
                        break  # a server that ignored Range: keep only what was asked
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                return None
            raise FetchError(f"{url[:200]}: the server answered {exc.code}") from None
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", None) or f"{type(exc).__name__}: {exc}"
            raise FetchError(f"{url[:200]}: {reason}") from None
        data = b"".join(chunks)
        if first is not None:
            return data[:first]
        if size > limit:
            raise FetchError(f"{url[:200]}: larger than {limit} bytes")
        return data
