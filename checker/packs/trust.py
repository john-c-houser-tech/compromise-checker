"""Which keys may sign threat packs (plan 4.2, DESIGN.md §10.4).

NouriLoop LLC has two keys. The root key, kept offline and used rarely,
signs nothing but the key list; its public half is in this file (and on
nouriloop.com). The pack key signs pack releases, and is trusted only
because the key list in force names it. A pack key that leaks or is lost
is revoked by a new key list, without a release of the tool.

The key list carries a serial that only goes up: the tool keeps the
highest it has accepted (in `packs/keys.yaml`) and refuses a lower or
equal one, so an old list can't be replayed to bring a revoked key back.
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


def _stored(directory: Path) -> tuple[bytes, bytes] | None:
    data, sig = directory / KEY_LIST, directory / f"{KEY_LIST}.minisig"
    if not data.is_file() or not sig.is_file():
        return None
    return data.read_bytes(), sig.read_bytes()


def key_list(home: Path) -> KeyList | None:
    """The key list in force: the stored one or the shipped one, whichever
    has the higher serial (each checked against the root keys)."""
    found = []
    for directory in (home / "packs", SHIPPED):
        pair = _stored(directory)
        if pair is not None:
            try:
                found.append(read_key_list(*pair))
            except TrustError:
                continue  # a damaged copy doesn't stop the other
    return max(found, key=lambda k: k.serial) if found else None


def accept_key_list(home: Path, data: bytes, signature: bytes) -> tuple[KeyList, KeyList | None]:
    """Make a newer key list the one in force: (new, old)."""
    new = read_key_list(data, signature)
    old = key_list(home)
    if old is not None and new.serial <= old.serial:
        raise TrustError(
            f"the key list's serial {new.serial} isn't newer than the one in force"
            f" ({old.serial}): an older list can't bring a revoked key back"
        )
    folder = home / "packs"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write(folder / f"{KEY_LIST}.minisig", signature)
    _write(folder / KEY_LIST, data)
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


@dataclass(frozen=True)
class Trusted:
    key: PublicKey
    who: str  # "NouriLoop pack key <name>" or "organization key <name>"


def trusted_keys(home: Path, organization: list[Any]) -> list[Trusted]:
    """Every key a pack may be signed with now: the key list's pack keys,
    and the organization's own (`packs.trusted_keys`)."""
    found = []
    listed = key_list(home)
    if listed is not None:
        for entry in listed.pack_keys:
            found.append(Trusted(public_key(entry.public_key), f"NouriLoop pack key {entry.name}"))
    for entry in organization:
        found.append(Trusted(public_key(entry.public_key), f"organization key {entry.name}"))
    return found
