"""Downloads for verification: public package files, size- and time-capped.

The signatures carry the trust, so plain HTTP mirrors are fine and any
redirect is followed (at most a few). What is sent: the file's address and
a User-Agent naming the checker and its version, nothing about the user or
their servers. Ubuntu's archive answers 403 to Python's default User-Agent
for package files (V.1), which is one more reason to send our own.
"""

from __future__ import annotations

import http.client
import time
import urllib.error
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


class _FewRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 4


class HttpFetcher:
    """Fetcher over HTTP and HTTPS, with one overall deadline."""

    def __init__(self, deadline: float = 60.0):
        self.ends = time.monotonic() + deadline
        self.opener = urllib.request.build_opener(_FewRedirects())

    def left(self) -> float:
        return self.ends - time.monotonic()

    def get(self, url: str, limit: int, first: int | None = None) -> bytes | None:
        if not url.lower().startswith(("http://", "https://")):
            raise FetchError(f"not a web address: {url[:200]}")
        if self.left() <= 0:
            raise FetchError("out of time for verification")
        headers = {"User-Agent": USER_AGENT}
        if first is not None:
            headers["Range"] = f"bytes=0-{first - 1}"
            limit = min(limit, first)
        request = urllib.request.Request(url, headers=headers)  # noqa: S310 - http(s), checked
        try:
            with self.opener.open(request, timeout=TIMEOUT) as response:
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
