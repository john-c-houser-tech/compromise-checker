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
    """Not a version this family's tools would accept."""


def compare(family: Family, a: str, b: str) -> int:
    """-1, 0 or 1 as `a` sorts before, with or after `b`."""
    if family == "dpkg":
        return dpkg_compare(a, b)
    if family == "rpm":
        return rpm_compare(a, b)
    raise ValueError(f"no version ordering for {family!r}")


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


def _digit(c: str) -> bool:
    return "0" <= c <= "9"  # ASCII only, as the C code's isdigit in the C locale


# --- dpkg ---------------------------------------------------------------------------------------


def _dpkg_parts(version: str) -> tuple[int, str, str]:
    """(epoch, upstream, revision): `[epoch:]upstream[-revision]`."""
    text = version.strip()
    if not text or any(c.isspace() for c in text):
        raise VersionError(f"not a dpkg version: {version!r}")
    epoch = 0
    if ":" in text:
        head, text = text.split(":", 1)
        if not head or not all(_digit(c) for c in head):
            raise VersionError(f"a dpkg epoch is a number: {version!r}")
        epoch = int(head)
    upstream, _, revision = text.rpartition("-")
    if not upstream:  # no hyphen: all of it is the upstream version
        upstream, revision = revision, ""
    if not upstream:
        raise VersionError(f"not a dpkg version: {version!r}")
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
    if ea != eb:
        return _sign(ea - eb)
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


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


def _rpm_parts(version: str) -> tuple[int, str, str | None]:
    """(epoch, version, release): `[epoch:]version[-release]`."""
    text = version.strip()
    if not text or any(c.isspace() for c in text):
        raise VersionError(f"not an rpm version: {version!r}")
    epoch = 0
    if ":" in text:
        head, text = text.split(":", 1)
        if not head or not all(_digit(c) for c in head):
            raise VersionError(f"an rpm epoch is a number: {version!r}")
        epoch = int(head)
    if text.count("-") > 1:
        raise VersionError(f"an rpm version and release hold no hyphen: {version!r}")
    upstream, _, release = text.partition("-")
    if not upstream:
        raise VersionError(f"not an rpm version: {version!r}")
    return epoch, upstream, release or None


def rpm_compare(a: str, b: str) -> int:
    """`[epoch:]version[-release]`, as rpm orders them; a release is
    compared only when both have one (as rpm does for a dependency)."""
    ea, va, ra = _rpm_parts(a)
    eb, vb, rb = _rpm_parts(b)
    if ea != eb:
        return _sign(ea - eb)
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra is not None and rb is not None else 0)
