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
`checker packs list`, with when the last pull was."""

from __future__ import annotations

import hashlib
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from checker.packs.format import MAX_BYTES, PackError, load, problems
from checker.packs.signing import MAX_SIGNATURE_BYTES, SignatureError, verify

DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/john-c-houser-tech/compromise-checker-packs/main/"
)
INDEX = "index.yaml"
MAX_INDEX_BYTES = 1024 * 1024
MAX_KEY_LIST_BYTES = 64 * 1024
TIMEOUT = 30.0  # seconds, for each file
# An index older than this is pointed out (pull, `packs list`): the index is
# signed again at least monthly, even with nothing new, so a source that
# keeps serving the same one (a stale mirror, or someone in between) shows.
STALE_DAYS = 30


class PullError(Exception):
    """A pull that can't go on; the message says why."""


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
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError(f"refused a redirect away from HTTPS, to {newurl[:200]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, limit: int) -> bytes | None:
    """A file's bytes over HTTPS (the certificate checked), None if it isn't
    there (404); at most `limit` bytes, or PullError."""
    if not url.lower().startswith("https://"):
        raise PullError(f"only HTTPS is used: {url[:200]}")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _HttpsOnly()
    )
    request = urllib.request.Request(  # noqa: S310 - https only, checked above
        url, headers={"User-Agent": "compromise-checker"}
    )
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise PullError(f"{url[:200]}: the server answered {exc.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise PullError(f"{url[:200]}: {reason}") from None
    if len(data) > limit:
        raise PullError(f"{url[:200]}: larger than {limit} bytes")
    return data


# --- A pull --------------------------------------------------------------------------------


@dataclass
class Pulled:
    key_list: tuple[int, int | None] | None = None  # (new serial, old) if a newer one came
    retired_by_keys: list[str] = field(default_factory=list)
    index_serial: int | None = None
    index_issued: str | None = None
    added: list[tuple[str, int, str]] = field(default_factory=list)  # (id, version, outcome)
    withdrawn: list[str] = field(default_factory=list)  # files retired
    notes: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # a pack that wasn't added, and why


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
    lock. Raises PullError when nothing can be trusted from the source."""
    from checker.packs.state import read_state, write_state
    from checker.packs.store import StoreError, add, retire, sweep
    from checker.packs.trust import NOURILOOP, TrustError, accept_key_list, key_list, trusted_keys

    get = get or fetch  # looked up now, so a test's stand-in is the one used
    done = Pulled()
    # 1. The key list: a revocation first.
    pair = _signed_pair(get, source, "keys.yaml", MAX_KEY_LIST_BYTES)
    if pair is None:
        done.notes.append("the source has no key list: the one in force is kept")
    else:
        try:
            current = key_list(home)
        except TrustError:
            current = None
        try:
            from checker.packs.trust import read_key_list

            offered = read_key_list(*pair)
        except TrustError as exc:
            raise PullError(str(exc)) from None
        floor = max(read_state(home)["key_list_serial"], current.serial if current else 0)
        if offered.serial > floor:
            new, old = accept_key_list(home, *pair)
            done.key_list = (new.serial, old.serial if old else None)
            done.retired_by_keys = sweep(home, organization)
        elif offered.serial < floor:
            done.notes.append(
                f"the source's key list (serial {offered.serial}) is older than the one in"
                f" force ({floor}): it is out of date, or not the real repository's"
            )
    # 2. The index, signed by a NouriLoop pack key.
    pair = _signed_pair(get, source, INDEX, MAX_INDEX_BYTES)
    if pair is None:
        raise PullError("the source has no index.yaml")
    keys, problem = trusted_keys(home, organization)
    ours = [k.key for k in keys if k.domain == NOURILOOP]
    if not ours:
        raise PullError(
            "no NouriLoop pack key is trusted yet, so the index can't be checked"
            + (f" ({problem})" if problem else "")
        )
    try:
        verify(pair[0], pair[1], ours)
    except SignatureError as exc:
        raise PullError(f"the index's signature: {exc}") from None
    index = read_index(pair[0])
    state = read_state(home)
    accepted = state.get("index_serial", 0)
    if index.serial < accepted:
        raise PullError(
            f"the index's serial {index.serial} is lower than one accepted before ({accepted}):"
            " it is out of date, or replayed; nothing was taken from it"
        )
    done.index_serial, done.index_issued = index.serial, index.issued.isoformat()
    age = ((now or datetime.now(UTC)) - index.issued).days
    if age > STALE_DAYS:
        done.notes.append(
            f"the index was issued {age} days ago: if a newer one was expected, the source"
            " may have stopped updating"
        )
    # 3. Packs newer than any version accepted here.
    for entry in index.packs:
        record = state["packs"].get(entry.id)
        if record is not None and entry.version <= record["highest"]:
            continue  # in force already, or retired by a person, or older
        try:
            pack = _signed_pair(get, source, pack_path(entry.id), MAX_BYTES)
            if pack is None:
                raise PullError(f"the index lists {pack_path(entry.id)}, which isn't there")
            if hashlib.sha256(pack[0]).hexdigest() != entry.sha256:
                raise PullError("its file doesn't have the hash the index gives")
            stored, outcome = add(home, organization, pack[0], pack[1], checks)
        except (PullError, StoreError) as exc:
            done.problems.append(f"{entry.id} version {entry.version}: {exc}")
            continue
        if (stored.pack.id, stored.pack.version) != (entry.id, entry.version):
            done.problems.append(
                f"{entry.id} version {entry.version}: the file holds {stored.pack.id} version"
                f" {stored.pack.version}"
            )
        done.added.append((stored.pack.id, stored.pack.version, outcome))
    # 4. Withdrawn packs in force.
    for gone in index.withdrawn:
        try:
            done.withdrawn += retire(home, gone.id, f"withdrawn by the packs source: {gone.reason}")
        except StoreError:
            continue  # not in force here
    state = read_state(home)
    state["index_serial"] = max(accepted, index.serial)
    state["last_pull"] = {
        "at": (now or datetime.now(UTC)).isoformat(timespec="seconds"),
        "source": source,
        "index_issued": index.issued.isoformat(),
    }
    write_state(home, state)
    return done


def staleness(state: dict[str, Any], now: datetime | None = None) -> str | None:
    """What `checker packs list` says of the last pull: when it was, and
    whether the index it found is old."""
    last = state.get("last_pull")
    if not isinstance(last, dict):
        return None
    try:
        issued = datetime.fromisoformat(str(last.get("index_issued")))
        at = str(last.get("at"))[:16]
    except ValueError:
        return None
    age = ((now or datetime.now(UTC)) - issued).days
    said = f"Last pull {at}: index issued {issued.isoformat()[:10]} ({age} days ago)"
    if age > STALE_DAYS:
        said += "; older than expected: the source may have stopped updating"
    return said
