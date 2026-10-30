"""The advisor's API key, read from where the organization keeps it
(decision 1, 2026-10-29): an environment variable, the OS keyring, or a
command that prints it; or none, for a server that takes no key (a local
model). The key is read only when a request is about to be
sent, kept in memory for that run, and never written, logged or shown.
"""

import os
import shlex
import subprocess

from checker.credentials import KEYRING_SERVICE
from checker.evidence import looks_like_a_key

ENVIRONMENT_VARIABLE = "ANTHROPIC_API_KEY"
KEYRING_USERNAME = "advisor-api-key"
# A vendor's own variable is read only for that vendor's own API; any
# other server's key, and the fallback model's, have places of their own,
# so one vendor's key is never sent to another.
OPENAI_VARIABLE = "OPENAI_API_KEY"
OPENAI_API = "https://api.openai.com"
SERVER_VARIABLE = "CHECKER_ADVISOR_API_KEY"
FALLBACK_VARIABLE = "CHECKER_FALLBACK_API_KEY"
FALLBACK_USERNAME = "advisor-fallback-api-key"
# Long enough to answer a password manager's prompt; a missed prompt then
# fails with a message instead of waiting for ever.
COMMAND_TIMEOUT = 120
MAX_KEY = 4096


class KeySourceError(Exception):
    """The key could not be read; the message says why, never the key."""


def _usable(text: str, where: str) -> str:
    key = text.strip()
    if not key:
        raise KeySourceError(f"{where} gave no key")
    if len(key) > MAX_KEY or any(c.isspace() for c in key) or not key.isprintable():
        raise KeySourceError(f"{where} gave something that isn't a single key")
    return key


def key_places(
    api: str = "anthropic", base_url: str | None = None, fallback: bool = False
) -> tuple[str, str]:
    """Where `env` and `keyring` look: the environment variable and the
    keyring username, for the main model or the fallback model."""
    if api == "anthropic" and not base_url:
        variable = ENVIRONMENT_VARIABLE
    elif api == "openai" and (base_url or "").startswith(OPENAI_API + "/"):
        variable = OPENAI_VARIABLE
    else:
        variable = FALLBACK_VARIABLE if fallback else SERVER_VARIABLE
    return variable, (FALLBACK_USERNAME if fallback else KEYRING_USERNAME)


def read_api_key(
    source: str, places: tuple[str, str] = (ENVIRONMENT_VARIABLE, KEYRING_USERNAME)
) -> str | None:
    """The key, or None when the source is none."""
    variable, username = places
    if source == "none":
        return None
    if source == "env":
        value = os.environ.get(variable)
        if value is None:
            raise KeySourceError(f"{variable} is not set")
        return _usable(value, variable)
    if source == "keyring":
        try:
            import keyring
        except ImportError as exc:
            raise KeySourceError(
                "api_key_source is 'keyring' but the keyring package is not installed"
                " (pip install 'checker[keyring]')"
            ) from exc
        try:
            value = keyring.get_password(KEYRING_SERVICE, username)
        except Exception as exc:  # noqa: BLE001 - backends raise their own kinds
            raise KeySourceError(
                f"the keyring could not be read ({type(exc).__name__}: locked, or no backend?)"
            ) from None
        if value is None:
            raise KeySourceError(
                f"no key in the keyring for service {KEYRING_SERVICE!r}, username"
                f" {username!r} (store one with `keyring set {KEYRING_SERVICE}"
                f" {username}`)"
            )
        return _usable(value, "the keyring")
    if source.startswith("command:"):
        words = shlex.split(source.removeprefix("command:"))
        try:
            done = subprocess.run(  # noqa: S603 - the organization's own command, no shell
                words,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=COMMAND_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            raise KeySourceError(f"the key command {words[0]!r} was not found") from None
        except OSError as exc:
            raise KeySourceError(
                f"the key command {words[0]!r} could not be run: {exc.strerror}"
            ) from None
        except subprocess.TimeoutExpired:
            raise KeySourceError(
                f"the key command didn't finish within {COMMAND_TIMEOUT} s"
                " (a password manager prompt not answered?)"
            ) from None
        if done.returncode != 0:
            # The last line of its error output, never its standard output
            # (which may hold a key), with anything shaped like a key hidden.
            text = done.stderr.decode("utf-8", "replace")
            last = (text.strip().splitlines() or [""])[-1][:200]
            last = " ".join("[hidden]" if looks_like_a_key(w) else w for w in last.split())
            raise KeySourceError(
                f"the key command exited with status {done.returncode}"
                + (f": {last}" if last else "")
            )
        try:
            output = done.stdout.decode("utf-8")
        except UnicodeDecodeError:
            raise KeySourceError("the key command printed something that isn't text") from None
        return _usable(output, "the key command")
    raise KeySourceError(f"unknown key source {source!r}")


def looks_like_anthropic_key(key: str) -> bool:
    return key.startswith("sk-ant-")
