"""Making a release of the packs repository (plan 4.7): `checker packs
index` writes its `index.yaml` from the packs in `packs/<id>/`, each
checked as the tool reads it, for the maintainer to sign by hand with the
pack key (`minisign -S`). Nothing here signs, and nothing is downloaded or
sent: the repository is pushed by hand too."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from checker.packs.format import MAX_BYTES, PackError, read
from checker.packs.pull import INDEX, Entry, Index, PullError, Withdrawn, read_index


class ReleaseError(Exception):
    """An index that can't be written; the message says why."""


def _pack_keys(directory: Path) -> list:
    """The pack keys the repository's own key list (keys.yaml, checked
    against the root key) trusts: every pack must be signed by one."""
    from checker.packs.trust import TrustError, read_key_list

    data, signature = directory / "keys.yaml", directory / "keys.yaml.minisig"
    if not data.is_file() or not signature.is_file():
        raise ReleaseError("needs keys.yaml and keys.yaml.minisig: the packs' keys come from it")
    try:
        return read_key_list(data.read_bytes(), signature.read_bytes()).trusted()
    except TrustError as exc:
        raise ReleaseError(f"keys.yaml: {exc}") from None


def write_index(
    directory: Path,
    serial: int | None,
    withdraw: dict[str, str],
    now: datetime | None = None,
    forget: tuple[str, ...] = (),
) -> tuple[Path, Index, list[str]]:
    """Write `directory`/index.yaml; returns it, what it says, and what to
    look at (a pack the last index listed that is now gone). The last
    index there gives the serial to go above and the withdrawals to keep
    (`forget` drops one: a site that never pulled while it was withdrawn
    keeps the pack). Each pack's signature is checked against the pack
    keys the repository's keys.yaml trusts."""
    from checker.packs.signing import SignatureError, verify

    target = directory / INDEX
    keys = _pack_keys(directory)
    previous = None
    if target.is_file():
        try:
            previous = read_index(target.read_bytes()[: MAX_BYTES + 1])
        except PullError as exc:
            raise ReleaseError(f"the index there now: {exc}") from None
    entries = []
    folder = directory / "packs"
    for place in sorted(folder.iterdir()) if folder.is_dir() else []:
        if not place.is_dir():
            continue
        path = place / "PACK.yaml"
        if not path.is_file() or not path.with_name("PACK.yaml.minisig").is_file():
            raise ReleaseError(f"{place.name}: needs PACK.yaml and PACK.yaml.minisig")
        data = path.read_bytes()
        if len(data) > MAX_BYTES:
            raise ReleaseError(f"{place.name}: PACK.yaml is larger than a pack may be")
        try:
            pack = read(data)
        except PackError as exc:
            raise ReleaseError(f"{place.name}/PACK.yaml:\n{exc}") from None
        if pack.id != place.name:
            raise ReleaseError(f"{place.name}/PACK.yaml holds {pack.id}: the folder is its id")
        try:
            verify(data, path.with_name("PACK.yaml.minisig").read_bytes(), keys)
        except SignatureError as exc:
            raise ReleaseError(
                f"{place.name}: its signature isn't a pack key's from keys.yaml ({exc})"
            ) from None
        entries.append(Entry(id=pack.id, version=pack.version,
                             sha256=hashlib.sha256(data).hexdigest()))  # fmt: skip
    if previous is not None:
        before = {e.id: e for e in previous.packs}
        for entry in entries:
            last = before.get(entry.id)
            if last is not None and entry.version < last.version:
                raise ReleaseError(
                    f"{entry.id}: version {entry.version} is older than the last index's"
                    f" ({last.version}): pulls would never take it"
                )
            if last is not None and entry.version == last.version and entry.sha256 != last.sha256:
                raise ReleaseError(
                    f"{entry.id}: changed under the same version ({entry.version}): sites that"
                    " have it would keep the old content; give it a new version"
                )
    was_listed = {e.id: e.version for e in previous.packs} if previous else {}
    withdrawn = {w.id: w for w in previous.withdrawn} if previous else {}
    forgotten = {}
    for pack_id in forget:
        if pack_id not in withdrawn:
            raise ReleaseError(f"{pack_id} isn't withdrawn")
        forgotten[pack_id] = withdrawn.pop(pack_id)
    for entry in entries:
        gone = forgotten.get(entry.id)
        if gone is not None and gone.version is not None and entry.version <= gone.version:
            raise ReleaseError(
                f"{entry.id}: listed again at version {entry.version}, but version"
                f" {gone.version} was withdrawn: sites that had it would never take this one;"
                " give it a newer version"
            )
    for pack_id, reason in withdraw.items():
        withdrawn[pack_id] = Withdrawn(id=pack_id, reason=reason, version=was_listed.get(pack_id))
    listed = {e.id for e in entries}
    warnings = [
        f"{pack_id}: the last index listed it, and it is neither in packs/ nor withdrawn:"
        " sites keep it as it is; withdraw it if it should go"
        for pack_id in sorted(set(was_listed) - listed - set(withdrawn))
    ]
    if listed & set(withdrawn):
        raise ReleaseError(
            f"withdrawn but still in packs/: {', '.join(sorted(listed & set(withdrawn)))}"
        )
    last = previous.serial if previous else 0
    serial = last + 1 if serial is None else serial
    if serial <= last:
        raise ReleaseError(f"the serial must go above the last index's ({last})")
    issued = (now or datetime.now(UTC)).replace(microsecond=0)
    try:
        index = Index(
            format=1,
            serial=serial,
            issued=issued,
            packs=entries,
            withdrawn=[withdrawn[k] for k in sorted(withdrawn)],
        )
    except ValueError as exc:
        raise ReleaseError(str(exc)) from None
    lines = [
        "# The packs repository's release index (checker packs index). Signed by",
        "# hand with the pack key: index.yaml.minisig.",
        "format: 1",
        f"serial: {index.serial}",
        f"issued: {issued.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "packs:" if index.packs else "packs: []",
        # Ids and hashes quoted: one like 2026-10-30, 1e5 or null would read as
        # a date, a number or nothing.
        *(f'  - {{id: "{e.id}", version: {e.version}, sha256: "{e.sha256}"}}' for e in index.packs),
        "withdrawn:" if index.withdrawn else "withdrawn: []",
        *(
            f'  - {{id: "{w.id}", reason: {json.dumps(w.reason, ensure_ascii=False)}'
            + (f", version: {w.version}" if w.version is not None else "")
            + "}"
            for w in index.withdrawn
        ),
    ]
    text = "\n".join(lines) + "\n"
    try:
        same = read_index(text.encode()) == index  # what a pull will read is what was meant
    except PullError as exc:
        raise ReleaseError(f"the index wouldn't read back as written: {exc}") from None
    if not same:
        raise ReleaseError("the index wouldn't read back as written (a reason's quoting?)")
    target.write_text(text, encoding="utf-8")
    return target, index, warnings
