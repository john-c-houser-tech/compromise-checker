"""Which keys may sign threat packs (plan 4.2, DESIGN.md §10.4).

NouriLoop LLC has two keys. The root key, kept offline and used rarely,
signs nothing but the key list; its public half is in this file (and on
nouriloop.com). The pack key signs pack releases, and is trusted only
because the key list in force names it. A pack key that leaks or is lost
is revoked by a new key list, without a release of the tool.

The key list carries a serial that only goes up: the tool records the
highest it has accepted (in `packs/state.json`), keeps each accepted list
whole in `packs/keylists/<serial>/`, and refuses a lower or equal one, so
an old list can't be replayed to bring a revoked key back. A kept list
that is damaged or missing makes no NouriLoop key trusted, rather than
falling back to an older one.
A copy of the current list ships in the tool; a newer one comes from
`checker packs pull`, or `checker packs keys add` for air-gapped sites.

An organization's own keys (config `packs.trusted_keys`) sign its private
packs; the key list doesn't touch them.

    format: 1
    serial: 2
    issued: 2026-12-01
    pack_keys:
      - {name: pack key 2026-12, public_key: RWQ...}
    revoked:
      - {key_id: 0123456789ABCDEF, since: 2026-12-01, reason: lost}
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, model_validator

from checker.packs.format import PackError, load, problems
from checker.packs.signing import PublicKey, SignatureError, public_key, verify

# NouriLoop LLC's root key: none until John makes it (plan 4.8, D5). Until
# then no NouriLoop pack is trusted, only an organization's own.
ROOT_KEYS: tuple[str, ...] = ()
SHIPPED = Path(__file__).parent / "keys"  # keys.yaml and keys.yaml.minisig, from 4.8
KEY_LIST = "keys.yaml"


class TrustError(Exception):
    """A key list or key that can't be trusted; the message says why."""


def _key(text: str) -> str:
    try:
        public_key(text)
    except SignatureError as exc:
        raise ValueError(str(exc)) from None
    return text


KeyText = Annotated[str, AfterValidator(_key)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PackKey(_Strict):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 ._()-]+$")
    public_key: KeyText


class Revoked(_Strict):
    key_id: str = Field(pattern=r"^[0-9A-F]{16}$")
    since: date
    reason: str = Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")


class KeyList(_Strict):
    format: Literal[1]
    serial: int = Field(ge=1, le=2**31 - 1)
    issued: date
    pack_keys: list[PackKey] = Field(default=[], max_length=20)
    revoked: list[Revoked] = Field(default=[], max_length=200)

    @model_validator(mode="after")
    def _consistent(self) -> KeyList:
        roots = {k.raw for k in root_keys()}
        if any(public_key(k.public_key).raw in roots for k in self.pack_keys):
            raise ValueError("a root key can't be a pack key")
        ids = [public_key(k.public_key).key_id for k in self.pack_keys]
        if len(set(ids)) != len(ids):
            raise ValueError("a pack key is listed twice")
        if set(ids) & {r.key_id for r in self.revoked}:
            raise ValueError("a key is both trusted and revoked")
        return self

    def trusted(self) -> list[PublicKey]:
        return [public_key(k.public_key) for k in self.pack_keys]


def root_keys() -> list[PublicKey]:
    return [public_key(text) for text in ROOT_KEYS]


def read_key_list(data: bytes, signature: bytes) -> KeyList:
    """A key list, its signature checked against the root keys first."""
    roots = root_keys()
    if not roots:
        raise TrustError("this version of the tool has no NouriLoop root key yet")
    try:
        verify(data, signature, roots)
    except SignatureError as exc:
        raise TrustError(f"the key list's signature: {exc}") from None
    try:
        loaded = load(data)
        return KeyList.model_validate(loaded)
    except PackError as exc:
        raise TrustError(f"the key list: {exc}") from None
    except ValidationError as exc:
        raise TrustError(f"the key list: {problems(exc)}") from None


def _pair(directory: Path) -> tuple[bytes, bytes] | None:
    data, sig = directory / KEY_LIST, directory / f"{KEY_LIST}.minisig"
    if not data.is_file() and not sig.is_file():
        return None
    if not (data.is_file() and sig.is_file()):
        raise TrustError(f"{directory}: a key list without its signature, or the reverse")
    return data.read_bytes()[:65537], sig.read_bytes()[:4097]


def _kept(home: Path) -> tuple[int, Path] | None:
    """The highest-serial key list kept here, by its folder."""
    folder = home / "packs" / "keylists"
    serials = (
        [
            int(p.name)
            for p in folder.glob("*")
            if p.is_dir() and re.fullmatch(r"[1-9][0-9]{0,9}", p.name)
        ]
        if folder.is_dir()
        else []
    )
    return (max(serials), folder / str(max(serials))) if serials else None


def key_list(home: Path) -> KeyList | None:
    """The key list in force: the kept one or the shipped one, whichever
    has the higher serial. A kept list that fails its checks, or one that
    is missing below the serial recorded as accepted, is an error: no
    NouriLoop key is trusted then, rather than an older list."""
    from checker.packs.state import read_state

    recorded = read_state(home)["key_list_serial"]
    kept = None
    found = _kept(home)
    if found is not None:
        serial, directory = found
        pair = _pair(directory)
        if pair is None:
            raise TrustError(f"the kept key list {serial} is empty")
        kept = read_key_list(*pair)
        if kept.serial != serial:
            raise TrustError(f"the kept key list in folder {serial} says serial {kept.serial}")
    if recorded and (kept is None or kept.serial < recorded):
        raise TrustError(
            f"key list {recorded} was accepted here but isn't kept any more: add it again"
            " (`checker packs keys add`)"
        )
    shipped = None
    pair = _pair(SHIPPED) if SHIPPED.is_dir() else None
    if pair is not None:
        shipped = read_key_list(*pair)
    candidates = [k for k in (kept, shipped) if k is not None]
    return max(candidates, key=lambda k: k.serial) if candidates else None


def accept_key_list(home: Path, data: bytes, signature: bytes) -> tuple[KeyList, KeyList | None]:
    """Make a newer key list the one in force: (new, old). The caller holds
    the packs lock."""
    from checker.packs.state import read_state, write_state

    new = read_key_list(data, signature)
    state = read_state(home)
    try:
        old = key_list(home)
    except TrustError:
        old = None  # a damaged one is replaced by a newer list
    floor = max(state["key_list_serial"], old.serial if old else 0)
    if new.serial <= floor:
        raise TrustError(
            f"the key list's serial {new.serial} isn't newer than the one accepted ({floor}):"
            " an older list can't bring a revoked key back"
        )
    folder = home / "packs" / "keylists"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(dir=folder, prefix=".new-"))
    try:
        _write(staging / f"{KEY_LIST}.minisig", signature)
        _write(staging / KEY_LIST, data)
        os.replace(staging, folder / str(new.serial))  # both files appear at once
    except BaseException:
        for leftover in staging.glob("*") if staging.exists() else []:
            leftover.unlink(missing_ok=True)
        staging.rmdir() if staging.exists() else None
        raise
    state["key_list_serial"] = new.serial
    write_state(home, state)
    return new, old


def _write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


NOURILOOP = "NouriLoop"
ORGANIZATION = "your organization"


@dataclass(frozen=True)
class Trusted:
    key: PublicKey
    who: str  # "NouriLoop pack key <name>" or "organization key <name>"
    domain: str  # NOURILOOP or ORGANIZATION: a pack id stays with one


def trusted_keys(home: Path, organization: list[Any]) -> tuple[list[Trusted], str | None]:
    """Every key a pack may be signed with now, and why NouriLoop's keys
    aren't among them if they aren't: the key list's pack keys, and the
    organization's own (`packs.trusted_keys`) unless the key list revokes
    one, or it is a root key."""
    found, problem = [], None
    try:
        listed = key_list(home)
    except TrustError as exc:
        listed, problem = None, str(exc)
    revoked = {r.key_id for r in listed.revoked} if listed else set()
    if listed is not None:
        for entry in listed.pack_keys:
            found.append(
                Trusted(public_key(entry.public_key), f"NouriLoop pack key {entry.name}", NOURILOOP)
            )
    roots = {k.raw for k in root_keys()}
    for entry in organization:
        key = public_key(entry.public_key)
        if key.key_id in revoked or key.raw in roots:
            continue
        found.append(Trusted(key, f"organization key {entry.name}", ORGANIZATION))
    return found, problem


def check_organization_key(home: Path, key: PublicKey, others: list[Any]) -> None:
    """Refuse an organization key that is revoked, a root key, or shares a
    key id with a key already trusted."""
    if key.raw in {k.raw for k in root_keys()}:
        raise TrustError("that is NouriLoop's root key, which signs only key lists")
    try:
        listed = key_list(home)
    except TrustError:
        listed = None
    if listed is not None and key.key_id in {r.key_id for r in listed.revoked}:
        raise TrustError(f"key {key.key_id} is revoked by NouriLoop's key list")
    ids = [public_key(o.public_key).key_id for o in others]
    if listed is not None:
        ids += [k.key_id for k in listed.trusted()]
    if key.key_id in ids:
        raise TrustError(f"a key with the id {key.key_id} is already trusted")
