"""Whether a pack's mitigations are in place on a host (plan 4.4b), from
PHP's settings as collected (checker/snapshot.py php_settings) and the
files the collector read (web_config, with its links).

Each PHP set-up (Debian's /etc/php/X/{fpm,apache2,cgi}, RHEL's /etc/php.ini
and php.d, Remi's /etc/opt/remi/phpNN) is judged as PHP reads it: its
php.ini (a link read as what it points to; none: no settings), then its
conf.d files in name order; the last occurrence of a setting outside
[PATH=…] and [HOST=…] sections wins; a setting no file sets is PHP's
built-in default, the pack's `default` (session.upload_progress.enabled's
is On). Each place a site can get another value is a place of its own: a
[PATH=]/[HOST=] section, each PHP-FPM pool (its php_admin_* first, which
nothing in PHP's files overrides, else its php_value/php_flag, else the
set-up's), the web server's own PHP settings (Apache's php_value, a
FastCGI PHP_VALUE), and each site's .user.ini or .htaccess in the web
roots walked (plan 4.4c), where something reads it:
- .user.ini: PHP-FPM and CGI, under the name user_ini.filename gives (set
  empty: none read; another name: those files weren't read, "not seen");
  not where every pool reading it sets the setting with php_admin_* as
  expected, which a .user.ini can't override;
- .htaccess: only under Apache — php_value/php_flag through Apache's PHP
  module; SetEnv PHP_VALUE / PHP_ADMIN_VALUE through PHP-FPM, which applies
  them over any php_admin_* (php-src fpm_php_zend_ini_alter_master); one
  set some other way (SetEnvIf, a rewrite's E= flag) was only named, "not
  seen". Which sites a pool serves, AllowOverride, <IfModule> and Apache's
  own php_admin_* aren't modelled: those only make a site count where it
  might not.
Several values for one place: the one that isn't the expected, if any. A
mitigation is in place only if every place has the expected value; missing
if any has another; otherwise "not seen": PHP's settings not collected
whole (a site's file not read among them), no set-up found, a file in the
chain not read (a link out of /etc), a pool file included from elsewhere,
or PHP_INI_SCAN_DIR adding folders. Sites outside the web roots walked, and
ini_set at run time, aren't seen (the report says so).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

IN_PLACE, MISSING, NOT_SEEN = "in place", "missing", "not seen"
DEFAULT = "PHP's default"

_ON = {"on", "true", "yes"}
_OFF = {"off", "false", "no", "none", ""}
_DEBIAN = re.compile(r"^/etc/php/([^/]+)/(fpm|apache2|cgi)/")
_REMI = re.compile(r"^/etc/opt/remi/(php[0-9]+)/")


def normal(value: str | None) -> str | None:
    """A value as PHP reads a flag: on/true/yes and any non-zero integer
    are on; off/false/no/none, an empty value and 0 are off."""
    if value is None:
        return None
    text = value.strip().lower()
    if re.fullmatch(r"[-+]?\d+", text):
        return "off" if int(text) == 0 else "on"
    return "on" if text in _ON else "off" if text in _OFF else text


@dataclass
class Place:
    where: str  # "/etc/php/8.3/fpm/php.ini", "… pool www", "… [PATH=/x]"
    value: str | None  # as set, or the default; None: set nowhere and no default
    source: str  # the file that set it, or DEFAULT
    admin: bool = False  # a PHP-FPM pool's php_admin_* value: nothing overrides it


@dataclass
class Judged:
    id: str
    setting: str
    expect: str
    status: str
    places: list[Place] = field(default_factory=list)
    why: str = ""


@dataclass
class _Setup:
    name: str  # where it is reported: its php.ini's path
    conf_d: str
    fpm: tuple[str, ...]  # path prefixes of its PHP-FPM configuration, if it has any


def _setups(paths: set[str]) -> list[_Setup]:
    """Every set-up any file read belongs to (a php.ini need not exist)."""
    found: dict[str, _Setup] = {}
    for path in paths:
        if debian := _DEBIAN.match(path):
            folder = f"/etc/php/{debian[1]}/{debian[2]}/"
            fpm = (folder,) if debian[2] == "fpm" else ()
            found.setdefault(folder, _Setup(folder + "php.ini", folder + "conf.d/", fpm))
        elif path == "/etc/php.ini" or path.startswith(("/etc/php.d/", "/etc/php-fpm")):
            fpm = ("/etc/php-fpm.conf", "/etc/php-fpm.d/")
            found.setdefault("rhel", _Setup("/etc/php.ini", "/etc/php.d/", fpm))
        elif remi := _REMI.match(path):
            folder = f"/etc/opt/remi/{remi[1]}/"
            fpm = (folder + "php-fpm.conf", folder + "php-fpm.d/")
            found.setdefault(folder, _Setup(folder + "php.ini", folder + "php.d/", fpm))
    return [found[k] for k in sorted(found)]


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
    by_path: dict[str, list[dict[str, Any]]] = {}
    for item in sorted(settings.values(), key=lambda i: i.get("position", 0)):
        by_path.setdefault(str(item.get("path")), []).append(item)
    setups = _setups(set(files) | set(by_path))
    found = []
    for mitigation in mitigations:
        if mitigation.setting.kind != "php_ini":
            continue
        result = Judged(mitigation.id, mitigation.setting.name, mitigation.expect, NOT_SEEN)
        found.append(result)
        if not setups:
            result.why = "no PHP set-up was found among the files read"
            continue
        places, doubts = _places(mitigation, setups, by_path, files)
        if not complete:
            doubts.append("PHP's settings weren't collected whole")
        result.places = places
        expect = normal(mitigation.expect)
        if any(p.value is not None and normal(p.value) != expect for p in places):
            result.status = MISSING  # wrong somewhere, whatever else isn't known
        elif doubts or any(p.value is None for p in places):
            result.why = "; ".join(doubts) or "set nowhere, and the pack doesn't say PHP's default"
        else:
            result.status = IN_PLACE
    return found


def _worst(values: list[tuple[str, str | None]], expect: str) -> tuple[str, str | None]:
    """Of several values for one place, one that isn't the expected, if
    any: which one PHP uses can depend on more than the files show."""
    wrong = [v for v in values if normal(v[1]) != normal(expect)]
    return (wrong or values)[-1]


def _setup_value(name: str, default: str | None, setup: _Setup, by_path: dict, files: dict):
    """A setting in one set-up as PHP loads it: (its value, the file that set
    it, its [PATH=]/[HOST=] places, doubts about files in the chain)."""
    ini = (files.get(setup.name) or {}).get("resolved") or setup.name
    chain = ([ini] if setup.name in files or ini in by_path else []) + _conf_d(setup.conf_d, files)
    doubts = [
        f"{path} is in {setup.name}'s settings but wasn't read"
        for path in chain
        if "content_sha256" not in (files.get(path) or {}) and path not in by_path
    ]
    value, source, scoped = default, DEFAULT, []
    for path in chain:
        for item in by_path.get(path, []):
            if item.get("kind") != "ini" or item.get("name") != name:
                continue
            section = str(item.get("section") or "")
            if section.upper().startswith(("PATH=", "HOST=")):
                scoped.append(Place(f"{path} [{section}]", item.get("value"), path))
            else:
                value, source = item.get("value"), path
    return value, source, scoped, doubts


def _places(mitigation: Any, setups: list[_Setup], by_path: dict, files: dict):
    name, expect = mitigation.setting.name, mitigation.expect
    places, doubts = [], []
    paths = set(by_path) | set(files)
    # What reads a site's .user.ini: PHP-FPM (each pool) and CGI, as
    # (where, locked: the pool's php_admin_* sets it as expected, which a
    # .user.ini can't override, user_ini.filename there).
    user_ini: list[tuple[str, bool, str]] = []
    fpm = False
    for setup in setups:
        value, source, scoped, chain_doubts = _setup_value(
            name, mitigation.default, setup, by_path, files
        )
        places += scoped
        doubts += chain_doubts
        pools, pool_doubts = _pools(name, expect, setup, by_path, value, source)
        doubts += pool_doubts
        # A set-up with pools runs its requests in them; without, as set.
        places += pools if pools else [Place(setup.name, value, source)]
        cgi = setup.name.endswith("/cgi/php.ini")
        runs_fpm = bool(setup.fpm) and any(p.startswith(setup.fpm) for p in paths)
        if not (cgi or runs_fpm):
            continue  # Apache's own PHP module: it reads .htaccess, not .user.ini
        fpm = fpm or runs_fpm
        filename = _setup_value("user_ini.filename", ".user.ini", setup, by_path, files)[0]
        named = {
            p.where: p.value
            for p in _pools("user_ini.filename", ".user.ini", setup, by_path, filename, "")[0]
        }
        for pool in pools if runs_fpm and pools else []:
            locked = pool.admin and normal(pool.value) == normal(expect)
            user_ini.append((pool.where, locked, str(named.get(pool.where, filename) or "")))
        if cgi or not pools:
            user_ini.append((setup.name, False, str(filename or "")))
    for where, _, filename in user_ini:
        if filename.strip() not in ("", ".user.ini"):
            doubts.append(f"{where} reads sites' {filename.strip()}, which wasn't read")
    # A site's .user.ini counts where something reads it under that name
    # and no pool's php_admin_* locks the setting; its .htaccess only under
    # Apache: php_value / php_flag (kept lowercase) through Apache's PHP
    # module, SetEnv PHP_VALUE (uppercase) passed on to PHP-FPM, which
    # applies it whatever php_admin_* says.
    apache = any(p.startswith(("/etc/apache2/", "/etc/httpd/")) for p in paths)
    mod_php = apache and any(not s.name.startswith("/etc/php/") or "/apache2/" in s.name
                             for s in setups)  # fmt: skip
    reads_user_ini = any(not locked and f.strip() == ".user.ini" for _, locked, f in user_ini)
    for path, items in sorted(by_path.items()):
        for item in items:
            kind, how = item.get("kind"), str(item.get("how"))
            if kind == "site_unread" and apache and fpm:
                doubts.append(f"{path} sets PHP_VALUE with {how}, whose value wasn't read")
            if kind not in ("server", "site") or item.get("name") != name:
                continue
            if kind == "site" and not (
                reads_user_ini
                if how == ".user.ini"
                else mod_php
                if how.startswith("php_")
                else apache and fpm
            ):
                continue
            places.append(Place(f"{path} ({how})", item.get("value"), path))
    for path, items in sorted(by_path.items()):
        for item in items:
            if item.get("kind") == "scan_dir" and item.get("value"):
                doubts.append(f"{path} sets PHP_INI_SCAN_DIR: its folders' ini files weren't read")
    return places, doubts


def _conf_d(folder: str, files: dict) -> list[str]:
    """A conf.d folder's .ini files in the order PHP reads them, each as
    the file a link points to."""
    found = []
    for path, item in files.items():
        if path.startswith(folder) and "/" not in path[len(folder) :] and path.endswith(".ini"):
            found.append((path.rsplit("/", 1)[-1], item.get("resolved") or path))
    return [target for _, target in sorted(found)]


def _pools(name: str, expect: str, setup: _Setup, by_path: dict, value: str | None, source: str):
    """Each PHP-FPM pool of a set-up, with the value its requests run with:
    its php_admin_* (nothing overrides them), else its php_value/php_flag,
    else the set-up's."""
    if not setup.fpm:
        return [], []
    pools: dict[str, dict[str, list[tuple[str, str | None]]]] = {}
    doubts = []
    for path, items in sorted(by_path.items()):
        if not path.startswith(setup.fpm):
            continue
        for item in items:
            kind, section = item.get("kind"), str(item.get("section"))
            if kind == "pool_header":
                pools.setdefault(section, {"admin": [], "user": []})
            elif kind == "pool" and item.get("name") == name:
                which = "admin" if item.get("admin") else "user"
                pools.setdefault(section, {"admin": [], "user": []})[which].append(
                    (path, item.get("value"))
                )
            elif kind == "include" and not any(
                str(item.get("value") or "").startswith(prefix) for prefix in setup.fpm
            ):
                doubts.append(f"{path} includes {item.get('value')}, which wasn't read")
    places = []
    for pool, sets in sorted(pools.items()):
        where = f"{setup.name} pool {pool}"
        chosen = sets["admin"] or sets["user"]
        if chosen:
            path, set_value = _worst(chosen, expect)
            places.append(Place(where, set_value, path, admin=bool(sets["admin"])))
        else:
            places.append(Place(where, value, source))
    return places, doubts
