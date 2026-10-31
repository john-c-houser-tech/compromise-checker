"""`checker packs pull` (plan 4.7, DESIGN.md §10.4): new threat packs, and
a newer key list, from the packs repository, verified before anything is
kept. Nothing else in the tool downloads, and this only when asked.

The repository (`compromise-checker-packs`, or a mirror of it) holds:

    keys.yaml, keys.yaml.minisig      the key list, signed by the root key
    index.yaml, index.yaml.minisig    the release index, signed by a pack key
    packs/<id>/PACK.yaml, .minisig    each pack's current version

    format: 1                         # the index
    serial: 7                         # only goes up, like the key list's
    issued: 2026-11-02T10:00:00Z
    packs:
      - {id: php2shell-2026-10, version: 2, sha256: 3f2a...}
    withdrawn:
      - {id: example-2026-09, reason: false positives on Debian builds}

A pull takes a newer key list first (a revocation comes before any pack
signed by the revoked key could be added), then the index, checked
against NouriLoop's pack keys and refused if its serial is lower than one
accepted before (an old index replayed, or a mirror gone stale, can't
hide a newer pack or bring back a withdrawn one). A pack newer than any
version accepted here is downloaded, must have the index's hash, and is
added as `checker packs add` adds one (its own signature and content
checked again); one a person retired, or an older version, isn't brought
back. A withdrawn pack in force is retired. Only HTTPS, redirects
included, with each file's size capped.

A serial stops an older index being swapped in, not the current one
being served for ever: so the index is signed again at least monthly,
and one older than STALE_DAYS is pointed out by the pull and by
`checker packs list`, with when the last pull was.

Limits: revocations reach a site only through the source. Someone who
holds a leaked pack key and controls the source (a mirror, or someone in
between) can keep serving the old key list with fresh indexes, and the
staleness check can't tell; only looking at the repository itself, by
another route, shows a newer list. Signatures carry no context: a pack's
signature passes as an index's only if the file reads as both, and the
strict, disjoint formats (extra fields refused) keep that from
happening."""

from __future__ import annotations

import hashlib
import http.client
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from checker.packs.format import MAX_BYTES, PackError, load, problems
from checker.packs.signing import MAX_SIGNATURE_BYTES, SignatureError, verify

DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/john-c-houser-tech/compromise-checker-packs/main/"
)
INDEX = "index.yaml"
MAX_INDEX_BYTES = MAX_BYTES  # what the YAML reader reads at most
MAX_KEY_LIST_BYTES = 64 * 1024
TIMEOUT = 30.0  # seconds a socket may wait for each read
DEADLINE = 120.0  # seconds a whole file may take, however it trickles in
SKEW_DAYS = 1  # an index issued further ahead of this clock is pointed out
# An index older than this is pointed out (pull, `packs list`): the index is
# signed again at least monthly, even with nothing new, so a source that
# keeps serving the same one (a stale mirror, or someone in between) shows.
STALE_DAYS = 30


class PullError(Exception):
    """A pull that can't go on; the message says why, and `pulled` what it
    did before it stopped."""

    pulled: Any = None


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


_ID = r"^[a-z0-9][a-z0-9-]{0,62}$"


class Entry(_Strict):
    id: str = Field(pattern=_ID)
    version: int = Field(ge=1, le=99999)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Withdrawn(_Strict):
    id: str = Field(pattern=_ID)
    reason: str = Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")
    version: int | None = Field(default=None, ge=1, le=99999)  # the last one listed, if any


class Index(_Strict):
    format: Literal[1]
    serial: int = Field(ge=1, le=2**31 - 1)
    issued: datetime
    packs: list[Entry] = Field(default=[], max_length=500)
    withdrawn: list[Withdrawn] = Field(default=[], max_length=500)

    @field_validator("issued")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("needs its time zone (Z for UTC)")
        return value


def read_index(data: bytes) -> Index:
    try:
        index = Index.model_validate(load(data))
    except PackError as exc:
        raise PullError(f"the index: {exc}") from None
    except ValidationError as exc:
        raise PullError(f"the index: {problems(exc)}") from None
    ids = [e.id for e in index.packs]
    if len(set(ids)) != len(ids):
        raise PullError("the index lists a pack twice")
    if set(ids) & {w.id for w in index.withdrawn}:
        raise PullError("the index both lists and withdraws a pack")
    return index


def pack_path(pack_id: str) -> str:
    """Where a pack is in the repository: from its id, never from the index."""
    return f"packs/{pack_id}/PACK.yaml"


# --- Downloading --------------------------------------------------------------------------


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    """The opener's redirect handler, in place of urllib's: HTTPS only."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError(f"refused a redirect away from HTTPS, to {newurl[:200]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def opener() -> urllib.request.OpenerDirector:
    """HTTPS with the system's certificates, and redirects only to HTTPS."""
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _HttpsOnly()
    )


def fetch(url: str, limit: int) -> bytes | None:
    """A file's bytes over HTTPS (the certificate checked), None if it isn't
    there (404); at most `limit` bytes within DEADLINE seconds, or PullError."""
    if not url.lower().startswith("https://"):
        raise PullError(f"only HTTPS is used: {url[:200]}")
    request = urllib.request.Request(  # noqa: S310 - https only, checked above
        url, headers={"User-Agent": "compromise-checker"}
    )
    started = time.monotonic()
    try:
        with opener().open(request, timeout=TIMEOUT) as response:
            chunks, size = [], 0
            while size <= limit:
                if time.monotonic() - started > DEADLINE:
                    raise PullError(f"{url[:200]}: took longer than {DEADLINE:.0f} seconds")
                # read1: what one read of the socket gives, so a server
                # sending a byte at a time can't hold the loop past the
                # deadline by more than one socket timeout.
                chunk = response.read1(min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise PullError(f"{url[:200]}: the server answered {exc.code}") from None
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", None) or f"{type(exc).__name__}: {exc}"
        raise PullError(f"{url[:200]}: {reason}") from None
    if size > limit:
        raise PullError(f"{url[:200]}: larger than {limit} bytes")
    return b"".join(chunks)


# --- A pull --------------------------------------------------------------------------------


@dataclass
class Pulled:
    key_list: tuple[int, int | None] | None = None  # (new serial, old) if a newer one came
    retired_by_keys: list[str] = field(default_factory=list)
    index_serial: int | None = None
    index_issued: str | None = None
    added: list[tuple[str, int, str]] = field(default_factory=list)  # (id, version, outcome)
    withdrawn: list[str] = field(default_factory=list)  # files retired
    notes: list[str] = field(default_factory=list)  # worth knowing; the pull still did its part
    problems: list[str] = field(default_factory=list)  # what went wrong; the pull exits 1

    def changed(self) -> bool:
        return bool(self.added or self.withdrawn or self.key_list or self.retired_by_keys)


def _signed_pair(get, source: str, name: str, limit: int) -> tuple[bytes, bytes] | None:
    data = get(source + name, limit)
    if data is None:
        return None
    signature = get(source + name + ".minisig", MAX_SIGNATURE_BYTES)
    if signature is None:
        raise PullError(f"{name} has no signature ({name}.minisig) at the source")
    return data, signature


def pull(
    home: Path,
    organization: list[Any],
    checks: dict[str, Any],
    source: str,
    get: Callable[[str, int], bytes | None] | None = None,
    now: datetime | None = None,
) -> Pulled:
    """Pull from `source` (a URL ending in "/"). The caller holds the packs
    lock. Raises PullError when the pull can't go on; what it did by then
    (a key list taken, packs retired or added) is the error's `pulled`,
    whatever the error."""
    get = get or fetch  # looked up now, so a test's stand-in is the one used
    done = Pulled()
    try:
        _pull(home, organization, checks, source, get, now or datetime.now(UTC), done)
    except Exception as exc:  # whatever stopped it, what it did is said
        exc.pulled = done
        raise
    return done


def _pull(home, organization, checks, source, get, now, done: Pulled) -> None:
    from checker.packs.state import StateError, read_state, write_state
    from checker.packs.store import StoreError, add, adopt, retire, sweep
    from checker.packs.trust import (
        NOURILOOP,
        TrustError,
        accept_key_list,
        key_list,
        read_key_list,
        trusted_keys,
    )

    # 1. The key list: a revocation first, whichever way it came. The
    # repository always has one.
    done.retired_by_keys += adopt(home, organization)
    pair = _signed_pair(get, source, "keys.yaml", MAX_KEY_LIST_BYTES)
    if pair is None:
        raise PullError("the source has no keys.yaml: it isn't the packs repository, or is broken")
    try:
        current = key_list(home)
    except TrustError:
        current = None
    try:
        offered = read_key_list(*pair)
    except TrustError as exc:
        raise PullError(str(exc)) from None
    floor = max(read_state(home)["key_list_serial"], current.serial if current else 0)
    if offered.serial > floor:
        new, old = accept_key_list(home, *pair)
        done.key_list = (new.serial, old.serial if old else None)
        done.retired_by_keys += sweep(home, organization)
    elif offered.serial < floor:
        done.problems.append(
            f"the source's key list (serial {offered.serial}) is older than the one in force"
            f" ({floor}): it is out of date, or not the real repository's, and a revocation"
            " it should carry may be missing"
        )
    # 2. The index, signed by a NouriLoop pack key.
    pair = _signed_pair(get, source, INDEX, MAX_INDEX_BYTES)
    if pair is None:
        raise PullError("the source has no index.yaml")
    keys, problem = trusted_keys(home, organization)
    ours = [k.key for k in keys if k.domain == NOURILOOP]
    if not ours:
        raise PullError(
            "no NouriLoop pack key is trusted, so the index can't be checked"
            + (f" ({problem})" if problem else "")
        )
    try:
        verify(pair[0], pair[1], ours)
    except SignatureError as exc:
        raise PullError(f"the index's signature: {exc}") from None
    index = read_index(pair[0])
    digest = hashlib.sha256(pair[0]).hexdigest()
    state = read_state(home)
    accepted = state.get("index_serial", 0)
    if not isinstance(accepted, int) or not isinstance(state.get("index_sha256", ""), str):
        raise StateError("packs/state.json isn't the tool's: restore it from a backup")
    if index.serial < accepted:
        raise PullError(
            f"the index's serial {index.serial} is lower than one accepted before ({accepted}):"
            " it is out of date, or replayed; nothing was taken from it"
        )
    if index.serial == accepted and state.get("index_sha256") not in (None, digest):
        raise PullError(
            f"this index differs from the one accepted before under the same serial"
            f" ({accepted}): a new index needs a new serial; nothing was taken from it"
        )
    # Recorded at once: whatever fails below, an older index can't come next.
    state["index_serial"], state["index_sha256"] = index.serial, digest
    state["last_pull"] = {
        "at": now.isoformat(timespec="seconds"),
        "source": source,
        "index_issued": index.issued.isoformat(),
    }
    write_state(home, state)
    done.index_serial, done.index_issued = index.serial, index.issued.isoformat()
    age = (now - index.issued).days
    if age > STALE_DAYS:
        done.notes.append(
            f"the index was issued {age} days ago: if a newer one was expected, the source"
            " may have stopped updating"
        )
    elif index.issued - now > timedelta(days=SKEW_DAYS):
        done.notes.append(
            f"the index says it was issued {index.issued.isoformat()[:16]}, ahead of this"
            " machine's clock: one of them is wrong"
        )
    # 3. Packs newer than any version accepted here, NouriLoop's to give.
    for entry in index.packs:
        record = state["packs"].get(entry.id)
        if record is not None:
            if record.get("domain") != NOURILOOP:
                done.notes.append(
                    f"{entry.id}: your organization's key signs this pack id here, so"
                    " NouriLoop's is left alone"
                )
                continue
            if record.get("held"):
                if entry.version > record["highest"]:
                    done.notes.append(
                        f"{entry.id} version {entry.version} is offered, but the pack was"
                        " retired here by hand: `checker packs add` brings it back"
                    )
                continue
            seen = record.get("seen", {}).get(str(entry.version))
            if seen is not None and seen != entry.sha256:
                done.problems.append(
                    f"{entry.id} version {entry.version}: the index's file isn't the one"
                    " accepted here under that version (a changed pack needs a new version)"
                )
                continue
            if entry.version <= record["highest"]:
                continue  # in force already, or older
        try:
            pack = _signed_pair(get, source, pack_path(entry.id), MAX_BYTES)
            if pack is None:
                raise PullError(f"the index lists {pack_path(entry.id)}, which isn't there")
            if hashlib.sha256(pack[0]).hexdigest() != entry.sha256:
                raise PullError("its file doesn't have the hash the index gives")
            stored, outcome = add(
                home, organization, pack[0], pack[1], checks,
                domain=NOURILOOP, expect=(entry.id, entry.version),
            )  # fmt: skip
        except (PullError, StoreError) as exc:
            done.problems.append(f"{entry.id} version {entry.version}: {exc}")
            continue
        done.added.append((stored.pack.id, stored.pack.version, outcome))
    # 4. Withdrawn packs in force, if they are NouriLoop's.
    state = read_state(home)
    for gone in index.withdrawn:
        record = state["packs"].get(gone.id)
        if record is None or record.get("domain") != NOURILOOP:
            continue  # not here, or your organization's own
        try:
            done.withdrawn += retire(home, gone.id, f"withdrawn by the packs source: {gone.reason}")
        except StoreError:
            continue  # not in force here


def staleness(state: dict[str, Any], now: datetime | None = None) -> str | None:
    """What `checker packs list` says of the last pull: when it was, and
    whether the index it found is old."""
    last = state.get("last_pull")
    if not isinstance(last, dict):
        return None
    try:
        issued = datetime.fromisoformat(str(last.get("index_issued")))
        age = ((now or datetime.now(UTC)) - issued).days
    except (ValueError, TypeError):
        return None
    at = str(last.get("at"))[:16]
    said = f"Last pull {at}: index issued {issued.isoformat()[:10]} ({age} days ago)"
    if age > STALE_DAYS:
        said += "; older than expected: the source may have stopped updating"
    elif age < -SKEW_DAYS:
        said = (
            f"Last pull {at}: the index says it was issued {issued.isoformat()[:10]}, ahead of"
            " this machine's clock: one of them is wrong, and its age can't be judged"
        )
    return said
