"""Threat packs kept in the checker's home (plan 4.2): `packs/active/`
holds each pack in force, `packs/retired/` the ones taken out of use
(replaced by a newer version, retired by a person, or signed by a key no
longer trusted), kept so an old analysis can be reproduced; each retired
file is named by its content's hash, so nothing retired is overwritten.
Each pack is kept with its signature and checked again whenever it is
read. `packs/state.json` (checker.packs.state) remembers, per pack id,
which trust domain signs it, the highest version accepted and every
version's hash: no rollback, no changed content under an old version
number, no taking over another domain's pack, even after a retire."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from checker.packs.format import MAX_BYTES, Pack, PackError, read
from checker.packs.signing import MAX_SIGNATURE_BYTES, SignatureError, verify
from checker.packs.state import read_state, write_state
from checker.packs.trust import Trusted, trusted_keys

_ACTIVE = re.compile(r"(?P<id>[a-z0-9][a-z0-9-]{0,62})-v(?P<version>[1-9][0-9]{0,4})\.yaml")
_RETIRED = re.compile(
    r"(?P<id>[a-z0-9][a-z0-9-]{0,62})-v(?P<version>[1-9][0-9]{0,4})-(?P<sha>[0-9a-f]{16})\.yaml"
)


class StoreError(Exception):
    """A pack that can't be added or found; the message says why."""


@dataclass(frozen=True)
class Stored:
    pack: Pack
    path: Path
    signed_by: Trusted
    sha256: str  # of the pack file as signed


def folder(home: Path, which: str) -> Path:
    path = home / "packs" / which
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _files(directory: Path, pattern: re.Pattern) -> Iterable[tuple[re.Match, Path]]:
    if not directory.is_dir():
        return []
    found = []
    for path in directory.iterdir():
        named = pattern.fullmatch(path.name)
        if named and path.is_file() and not path.is_symlink():
            found.append((named, path))
    return sorted(found, key=lambda f: (f[0]["id"], int(f[0]["version"])))


def _capped(path: Path, limit: int) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise PackError(f"{path.name} is larger than a pack may be")
    return data


def _signed(data: bytes, signature: bytes, keys: list[Trusted]) -> Trusted:
    signed = verify(data, signature, [k.key for k in keys])
    return next(k for k in keys if k.key == signed.key)


def _load(path: Path, keys: list[Trusted]) -> Stored:
    """A kept pack, its signature checked against the keys trusted now."""
    data = _capped(path, MAX_BYTES)
    signature = _capped(path.with_name(path.name + ".minisig"), MAX_SIGNATURE_BYTES)
    signer = _signed(data, signature, keys)
    return Stored(read(data), path, signer, hashlib.sha256(data).hexdigest())


def active(home: Path, organization: list[Any]) -> tuple[list[Stored], list[str]]:
    """The packs in force (the highest version of each id), and why any
    kept one can't be used now."""
    keys, problem = trusted_keys(home, organization)
    usable: dict[str, Stored] = {}
    problems = [f"NouriLoop's keys aren't trusted now: {problem}"] if problem else []
    for named, path in _files(home / "packs" / "active", _ACTIVE):
        try:
            stored = _load(path, keys)
        except (OSError, SignatureError, PackError) as exc:
            problems.append(f"{named['id']} version {named['version']}: {exc}")
            continue
        if (stored.pack.id, stored.pack.version) != (named["id"], int(named["version"])):
            problems.append(f"{path.name}: holds {stored.pack.id} version {stored.pack.version}")
            continue
        earlier = usable.get(stored.pack.id)
        if earlier is not None:
            problems.append(
                f"{stored.pack.id}: version {earlier.pack.version} is also in force; only"
                f" {stored.pack.version} is used"
            )
        usable[stored.pack.id] = stored
    return list(usable.values()), problems


def retired(home: Path) -> list[tuple[str, int, str]]:
    """(id, version, why) for each retired pack."""
    found = []
    for named, path in _files(home / "packs" / "retired", _RETIRED):
        why = path.with_name(path.name + ".why")
        text = why.read_text(errors="replace").strip() if why.is_file() else ""
        found.append((named["id"], int(named["version"]), text))
    return found


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


def _retire(home: Path, path: Path, why: str) -> None:
    """Move a pack and its signature to retired/, named by the content's
    hash (the same content retired twice is the same file), and add why
    and when to its notes."""
    target = folder(home, "retired")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    name = f"{path.name.removesuffix('.yaml')}-{digest}.yaml"
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    notes = target / f"{name}.why"
    before = notes.read_bytes() if notes.is_file() else b""
    _write(notes, before + f"{stamp}: {why}\n".encode())
    signature = path.with_name(path.name + ".minisig")
    if signature.exists():
        os.replace(signature, target / f"{name}.minisig")
    os.replace(path, target / name)


def add(
    home: Path, organization: list[Any], data: bytes, signature: bytes, checks: dict[str, Any]
) -> tuple[Stored, str]:
    """Check a pack's signature, then its content, then that it is newer
    than any version of it accepted before (and in the same trust domain),
    then keep it in force; an older version is retired. The caller holds
    the packs lock. Returns it and what happened."""
    keys, problem = trusted_keys(home, organization)
    if not keys:
        raise StoreError(
            "no key is trusted to sign packs yet: NouriLoop's arrive with the first key"
            " list; an organization adds its own with `checker packs trust add`"
            + (f" ({problem})" if problem else "")
        )
    try:
        signer = _signed(data, signature, keys)  # before the content is read at all
    except SignatureError as exc:
        raise StoreError(f"its signature: {exc}") from None
    try:
        pack = read(data)
    except PackError as exc:
        raise StoreError(f"its content:\n{exc}") from None
    from checker.packs.detect import reference_problems

    unknown = reference_problems(pack, checks)
    if unknown:
        raise StoreError(
            "its detections name what this version doesn't have: " + "; ".join(unknown)
        )
    digest = hashlib.sha256(data).hexdigest()
    state = read_state(home)
    record = state["packs"].get(pack.id)
    if record is not None:
        if record["domain"] != signer.domain:
            raise StoreError(
                f"{pack.id} is signed by {record['domain']}'s keys: a pack signed by"
                f" {signer.domain}'s can't replace it (use another id)"
            )
        seen = record["seen"].get(str(pack.version))
        if seen is not None and seen != digest:
            raise StoreError(
                f"{pack.id} version {pack.version} was accepted before with different content:"
                " a changed pack needs a new version"
            )
        if pack.version < record["highest"]:
            raise StoreError(
                f"{pack.id} version {record['highest']}, newer, was accepted before: an older"
                " version can't come back"
            )
    target = folder(home, "active")
    name = f"{pack.id}-v{pack.version}.yaml"
    path = target / name
    if path.is_file() and path.read_bytes() == data:
        return Stored(pack, path, signer, digest), "already in force"
    older = [p for named, p in _files(target, _ACTIVE) if named["id"] == pack.id and p != path]
    _write(path.with_name(name + ".minisig"), signature)
    _write(path, data)
    state["packs"][pack.id] = {
        "domain": signer.domain,
        "highest": pack.version,
        "seen": {**(record or {}).get("seen", {}), str(pack.version): digest},
    }
    write_state(home, state)
    for old in older:
        _retire(home, old, f"replaced by version {pack.version}")
    outcome = "added"
    if older:
        outcome += f", replacing version {_ACTIVE.fullmatch(older[-1].name)['version']}"
    elif seen_before := (record or {}).get("seen", {}).get(str(pack.version)):
        outcome = "back in force" if seen_before == digest else outcome
    return Stored(pack, path, signer, digest), outcome


def retire(home: Path, pack_id: str, why: str) -> list[str]:
    """Take a pack out of use, every version in force; returns their names."""
    done = []
    for named, path in _files(home / "packs" / "active", _ACTIVE):
        if named["id"] == pack_id:
            _retire(home, path, why)
            done.append(path.name)
    if not done:
        raise StoreError(f"no pack {pack_id!r} is in force")
    return done


def sweep(home: Path, organization: list[Any]) -> list[str]:
    """Retire every pack in force whose signature no key trusted now
    checks out (its key revoked, or an organization key removed)."""
    keys, problem = trusted_keys(home, organization)
    if problem:
        return []  # a damaged key list isn't a revocation: nothing is retired for it
    done = []
    for _, path in _files(home / "packs" / "active", _ACTIVE):
        try:
            _load(path, keys)
        except SignatureError as exc:
            _retire(home, path, f"its signature is no longer trusted: {exc}")
            done.append(path.name)
        except (OSError, PackError):
            continue  # reported by active(); a damaged file isn't a revocation
    return done
