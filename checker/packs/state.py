"""What the tool remembers about packs between runs (`packs/state.json`,
written whole under the packs lock): the highest key list serial it has
accepted, and for each pack id the trust domain that signs it, the
highest version accepted and the hash of every version it has seen. So a
pack can't be rolled back to an older version, a version can't change
content, and one domain's key can't take over another's pack id, even
after the newer one is retired."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

STATE = "state.json"


class StateError(Exception):
    """The state file is unreadable; nothing is added until it is mended."""


def _empty() -> dict[str, Any]:
    return {"key_list_serial": 0, "packs": {}}


def read_state(home: Path) -> dict[str, Any]:
    path = home / "packs" / STATE
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _empty()
    except (OSError, ValueError) as exc:
        raise StateError(f"{path} can't be read ({exc}): restore it from a backup") from None
    if (
        not isinstance(state, dict)
        or not isinstance(state.get("key_list_serial"), int)
        or not isinstance(state.get("packs"), dict)
    ):
        raise StateError(f"{path} isn't the tool's: restore it from a backup")
    return state


def write_state(home: Path, state: dict[str, Any]) -> None:
    folder = home / "packs"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=f".{STATE}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(state, out, indent=1, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, folder / STATE)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
