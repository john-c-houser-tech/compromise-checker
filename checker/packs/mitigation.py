"""Whether a pack's mitigations are in place on a host (plan 4.4b), from
PHP's settings as collected (checker/snapshot.py php_settings) and the
files the collector read (web_config, with its links).

Each PHP set-up is judged as PHP reads it: its php.ini, then its conf.d
files in name order (a link read as the file it points to); the last
occurrence of a setting outside [PATH=…] and [HOST=…] sections wins;
a setting no file sets is PHP's built-in default, the pack's `default`
(session.upload_progress.enabled's is On). PHP-FPM pools can override it
(php_value, php_admin_value), each pool apart. A mitigation is in place
only if every set-up and pool has the expected value; "not seen" when
PHP's settings weren't collected whole, or no PHP set-up was found.
Settings an application changes as it runs (ini_set) aren't seen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

IN_PLACE, MISSING, NOT_SEEN = "in place", "missing", "not seen"

# php.ini of each set-up, and where its conf.d files and pools are.
_SETUPS = (
    (re.compile(r"^/etc/php/([^/]+)/(fpm|apache2|cgi)/php\.ini$"),
     lambda m: f"/etc/php/{m[1]}/{m[2]}/conf.d/",
     lambda m: f"/etc/php/{m[1]}/fpm/pool.d/" if m[2] == "fpm" else None),
    (re.compile(r"^/etc/php\.ini$"), lambda m: "/etc/php.d/", lambda m: "/etc/php-fpm.d/"),
    (re.compile(r"^/etc/opt/remi/(php[0-9]+)/php\.ini$"),
     lambda m: f"/etc/opt/remi/{m[1]}/php.d/", lambda m: f"/etc/opt/remi/{m[1]}/php-fpm.d/"),
)  # fmt: skip
_ON = {"1", "on", "true", "yes"}
_OFF = {"0", "off", "false", "no", "none", ""}


def normal(value: str | None) -> str | None:
    """A value as PHP reads a flag: on/1/true/yes and off/0/false/no/none are each one."""
    if value is None:
        return None
    text = value.strip().lower()
    return "on" if text in _ON else "off" if text in _OFF else text


@dataclass
class Place:
    where: str  # "/etc/php/8.3/fpm/php.ini", or "… pool www"
    value: str | None  # as set, or the default; None: set nowhere and no default
    source: str  # the file that set it, or "PHP's default"


@dataclass
class Judged:
    id: str
    setting: str
    expect: str
    status: str
    places: list[Place] = field(default_factory=list)
    why: str = ""


def judge(
    mitigations: list[Any],
    settings: dict[str, dict[str, Any]],
    files: dict[str, dict[str, Any]],
    complete: bool,
) -> list[Judged]:
    """Each php_ini mitigation against the host's PHP set-ups. `settings`:
    the snapshot's php_settings items; `files`: its web_config items (the
    files read, and links with what they resolve to); `complete`: PHP's
    settings were collected whole."""
    found = []
    for mitigation in mitigations:
        if mitigation.setting.kind != "php_ini":
            continue
        result = Judged(mitigation.id, mitigation.setting.name, mitigation.expect, NOT_SEEN)
        found.append(result)
        if not complete:
            result.why = "PHP's settings weren't collected whole"
            continue
        places = _places(mitigation.setting.name, mitigation.default, settings, files)
        if not places:
            result.why = "no PHP set-up was found among the files read"
            continue
        result.places = places
        if any(p.value is None for p in places):
            result.why = "set nowhere, and the pack doesn't say PHP's default"
            continue
        expect = normal(mitigation.expect)
        result.status = IN_PLACE if all(normal(p.value) == expect for p in places) else MISSING
    return found


def _places(name: str, default: str | None, settings: dict, files: dict) -> list[Place]:
    by_file: dict[str, list[dict[str, Any]]] = {}
    for item in settings.values():
        by_file.setdefault(item.get("path"), []).append(item)
    places = []
    for path in sorted(files):
        for pattern, conf_dir, pool_dir in _SETUPS:
            matched = pattern.match(path)
            if not matched:
                continue
            chain = [path] + _conf_d(conf_dir(matched), files)
            value, source = default, "PHP's default"
            for file in chain:
                for item in sorted(by_file.get(file, []), key=lambda i: i.get("position", 0)):
                    section = str(item.get("section") or "").upper()
                    if item.get("kind") != "ini" or section.startswith(("PATH=", "HOST=")):
                        continue
                    if item.get("name") == name:
                        value, source = item.get("value"), file
            places.append(Place(path, value, source))
            pools = pool_dir(matched)
            if pools:
                places += _pools(name, pools, by_file)
    return places


def _conf_d(folder: str, files: dict) -> list[str]:
    """A conf.d folder's .ini files in the order PHP reads them, each as
    the file a link points to."""
    found = []
    for path, item in files.items():
        if path.startswith(folder) and "/" not in path[len(folder) :] and path.endswith(".ini"):
            found.append((path.rsplit("/", 1)[-1], item.get("resolved") or path))
    return [target for _, target in sorted(found)]


def _pools(name: str, folder: str, by_file: dict) -> list[Place]:
    """Pools that set the setting themselves; the others have the set-up's."""
    places = []
    for path, items in sorted(by_file.items()):
        if not str(path).startswith(folder):
            continue
        last: dict[str, dict[str, Any]] = {}
        for item in items:
            if item.get("kind") == "pool" and item.get("name") == name:
                pool = str(item.get("section"))
                # php_admin_value can't be overridden by php_value.
                if pool not in last or item.get("admin") or not last[pool].get("admin"):
                    last[pool] = item
        for pool, item in sorted(last.items()):
            places.append(Place(f"{path} pool {pool}", item.get("value"), path))
    return places
