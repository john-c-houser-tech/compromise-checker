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


def write_index(
    directory: Path, serial: int | None, withdraw: dict[str, str], now: datetime | None = None
) -> tuple[Path, Index]:
    """Write `directory`/index.yaml; returns it and what it says. The last
    index there gives the serial to go above and the withdrawals to keep."""
    target = directory / INDEX
    previous = None
    if target.is_file():
        try:
            previous = read_index(target.read_bytes()[: 1024 * 1024 + 1])
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
        entries.append(Entry(id=pack.id, version=pack.version,
                             sha256=hashlib.sha256(data).hexdigest()))  # fmt: skip
    if previous is not None:
        before = {e.id: e.version for e in previous.packs}
        for entry in entries:
            if entry.version < before.get(entry.id, 0):
                raise ReleaseError(
                    f"{entry.id}: version {entry.version} is older than the last index's"
                    f" ({before[entry.id]}): pulls would never take it"
                )
    withdrawn = {w.id: w.reason for w in previous.withdrawn} if previous else {}
    withdrawn |= withdraw
    listed = {e.id for e in entries}
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
            withdrawn=[Withdrawn(id=k, reason=v) for k, v in sorted(withdrawn.items())],
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
        # Quoted: a hash of digits only (or digits and one e) would read as a number.
        *(f'  - {{id: {e.id}, version: {e.version}, sha256: "{e.sha256}"}}' for e in index.packs),
        "withdrawn:" if index.withdrawn else "withdrawn: []",
        *(f"  - {{id: {w.id}, reason: {json.dumps(w.reason)}}}" for w in index.withdrawn),
    ]
    text = "\n".join(lines) + "\n"
    if read_index(text.encode()) != index:  # what a pull will read is what was meant
        raise ReleaseError("the index wouldn't read back as written (a reason's quoting?)")
    target.write_text(text, encoding="utf-8")
    return target, index
