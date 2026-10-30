"""Package version ordering, as each distribution's own tools order them:
dpkg's (Debian, Ubuntu) and rpm's (RHEL, Rocky Linux, AlmaLinux). A threat
pack's fixed versions are in the vendor's own numbering, and a backported
fix changes only the vendor's part of a version, so comparing upstream
version strings would get it wrong (DESIGN.md §8.14).

Written from dpkg's `verrevcmp` (lib/dpkg/version.c) and rpm's
`rpmvercmp` (rpmio/rpmvercmp.c); no new dependency. Like the pack format,
this module imports nothing else from the tool.
"""

from __future__ import annotations

from typing import Literal

Family = Literal["dpkg", "rpm"]


class VersionError(ValueError):
    """Not a version this family's tools would accept. An installed
    version comes from the server's own package database, which an
    intruder can write: a caller judging exposure treats this as "can't
    judge" (reported), never as fixed and never by skipping the package."""


# dpkg's own limit on an epoch (INT_MAX), and the characters it accepts.
MAX_EPOCH = 2**31 - 1
_DPKG_UPSTREAM = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+~-:")
_DPKG_REVISION = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+~")


def compare(family: Family, a: str, b: str) -> int:
    """-1, 0 or 1 as `a` sorts before, with or after `b`."""
    if family == "dpkg":
        return dpkg_compare(a, b)
    if family == "rpm":
        return rpm_compare(a, b)
    raise ValueError(f"no version ordering for {family!r}")


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


def _text(version: object, family: str) -> str:
    if not isinstance(version, str):
        raise VersionError(f"not a {family} version: {version!r}")
    text = version.strip()
    if not text or any(c.isspace() for c in text):
        raise VersionError(f"not a {family} version: {version[:100]!r}")
    return text


def _epoch(head: str, version: str, family: str) -> str:
    """An epoch as digits without leading zeros ("" for 0): compared by
    length, then text, so no number is ever built from it."""
    if not head or not all(_digit(c) for c in head):
        raise VersionError(f"a {family} epoch is a number: {version[:100]!r}")
    digits = head.lstrip("0")
    if len(digits) > 10 or (digits and int(digits) > MAX_EPOCH):
        raise VersionError(f"a {family} epoch too big: {version[:100]!r}")
    return digits


def _epoch_compare(a: str, b: str) -> int:
    if len(a) != len(b):
        return 1 if len(a) > len(b) else -1
    return (a > b) - (a < b)


def _digit(c: str) -> bool:
    return "0" <= c <= "9"  # ASCII only, as the C code's isdigit in the C locale


# --- dpkg ---------------------------------------------------------------------------------------


def _dpkg_parts(version: object) -> tuple[str, str, str]:
    """(epoch, upstream, revision): `[epoch:]upstream[-revision]`, split as
    dpkg's parseversion splits it (the first colon, the last hyphen) and
    refused where dpkg refuses it."""
    text = _text(version, "dpkg")
    epoch = ""
    if ":" in text:
        head, text = text.split(":", 1)
        epoch = _epoch(head, text, "dpkg")
    upstream, hyphen, revision = text.rpartition("-")
    if not hyphen:  # no hyphen: all of it is the upstream version
        upstream, revision = text, ""
    if not upstream:
        raise VersionError(f"a dpkg version number is empty: {text[:100]!r}")
    if hyphen and not revision:
        raise VersionError(f"a dpkg revision number is empty: {text[:100]!r}")
    if set(upstream) - _DPKG_UPSTREAM or set(revision) - _DPKG_REVISION:
        raise VersionError(f"a character dpkg doesn't allow in a version: {text[:100]!r}")
    return epoch, upstream, revision


def _dpkg_order(c: str) -> int:
    if _digit(c):
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not _digit(a[i])) or (j < len(b) and not _digit(b[j])):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and _digit(a[i]) and j < len(b) and _digit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and _digit(a[i]):
            return 1
        if j < len(b) and _digit(b[j]):
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_parts(a)
    eb, ub, rb = _dpkg_parts(b)
    return _epoch_compare(ea, eb) or _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# --- rpm ----------------------------------------------------------------------------------------


def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def rpmvercmp(a: str, b: str) -> int:
    """rpm's comparison of one version (or release) string with another."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        at, bt = a[i] if i < len(a) else "", b[j] if j < len(b) else ""
        if at == "~" or bt == "~":  # sorts before anything, even the end
            if at != "~":
                return 1
            if bt != "~":
                return -1
            i += 1
            j += 1
            continue
        if at == "^" or bt == "^":  # sorts after the end, before anything else
            if not at:
                return -1
            if not bt:
                return 1
            if at != "^":
                return 1
            if bt != "^":
                return -1
            i += 1
            j += 1
            continue
        if not at or not bt:
            break
        si, sj = i, j
        numeric = _digit(at)
        same = _digit if numeric else (lambda c: c.isascii() and c.isalpha())
        while i < len(a) and same(a[i]):
            i += 1
        while j < len(b) and same(b[j]):
            j += 1
        one, two = a[si:i], b[sj:j]
        if not two:  # different kinds of segment: a number is newer
            return 1 if numeric else -1
        if numeric:
            one, two = one.lstrip("0"), two.lstrip("0")
            if len(one) != len(two):
                return 1 if len(one) > len(two) else -1
        if one != two:
            return 1 if one > two else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _rpm_parts(version: object) -> tuple[str, str, str | None]:
    """(epoch, version, release): `[epoch:]version[-release]`, split as
    rpm's parseEVR splits it (the first colon, the last hyphen)."""
    text = _text(version, "rpm")
    epoch = ""
    if ":" in text:
        head, text = text.split(":", 1)
        epoch = _epoch(head, text, "rpm")
    upstream, hyphen, release = text.rpartition("-")
    if not hyphen:
        upstream, release = text, ""
    if not upstream:
        raise VersionError(f"not an rpm version: {text[:100]!r}")
    return epoch, upstream, release or None


def rpm_compare(a: str, b: str) -> int:
    """`[epoch:]version[-release]`, as rpm orders them; a release is
    compared only when both have one (as rpm does for a dependency). An
    installed version always has one (the collector sends
    epoch:version-release), and a pack's fixed version must have one, so
    the two are always compared whole."""
    ea, va, ra = _rpm_parts(a)
    eb, vb, rb = _rpm_parts(b)
    return (
        _epoch_compare(ea, eb)
        or rpmvercmp(va, vb)
        or (rpmvercmp(ra, rb) if ra is not None and rb is not None else 0)
    )
