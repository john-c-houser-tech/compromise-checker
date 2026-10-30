"""Package version ordering (checker/packs/versions.py, plan 4.1). The rpm
table is rpm's own (tests/rpmvercmp.at); the dpkg one is written by hand
from dpkg's rules (lib/dpkg/version.c) and Debian policy §5.6.12, and
checked against dpkg itself where it is installed."""

import random
import subprocess
import sys

import pytest

from checker.packs.versions import VersionError, compare, dpkg_compare, rpm_compare, rpmvercmp

RPMVERCMP = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0), ("2.0", "2.0.1", -1), ("2.0.1", "2.0", 1),
    ("2.0.1a", "2.0.1a", 0), ("2.0.1a", "2.0.1", 1), ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p1", 0), ("5.5p1", "5.5p2", -1), ("5.5p2", "5.5p1", 1),
    ("5.5p10", "5.5p10", 0), ("5.5p1", "5.5p10", -1), ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1), ("10.1xyz", "10xyz", 1),
    ("xyz10", "xyz10", 0), ("xyz10", "xyz10.1", -1), ("xyz10.1", "xyz10", 1),
    ("xyz.4", "xyz.4", 0), ("xyz.4", "8", -1), ("8", "xyz.4", 1),
    ("xyz.4", "2", -1), ("2", "xyz.4", 1),
    ("5.5p2", "5.6p1", -1), ("5.6p1", "5.5p2", 1), ("5.6p1", "6.5p1", -1), ("6.5p1", "5.6p1", 1),
    ("6.0.rc1", "6.0", 1), ("6.0", "6.0.rc1", -1),
    ("10b2", "10a1", 1), ("10a2", "10b2", -1),
    ("1.0aa", "1.0aa", 0), ("1.0a", "1.0aa", -1), ("1.0aa", "1.0a", 1),
    ("10.0001", "10.0001", 0), ("10.0001", "10.1", 0), ("10.1", "10.0001", 0),
    ("10.0001", "10.0039", -1), ("10.0039", "10.0001", 1),
    ("4.999.9", "5.0", -1), ("5.0", "4.999.9", 1),
    ("20101121", "20101121", 0), ("20101121", "20101122", -1), ("20101122", "20101121", 1),
    ("2_0", "2_0", 0), ("2.0", "2_0", 0), ("2_0", "2.0", 0),
    ("a", "a", 0), ("a+", "a+", 0), ("a+", "a_", 0), ("a_", "a+", 0),
    ("+a", "+a", 0), ("+a", "_a", 0), ("_a", "+a", 0),
    ("+_", "+_", 0), ("_+", "+_", 0), ("_+", "_+", 0), ("+", "_", 0), ("_", "+", 0),
    ("1.0~rc1", "1.0~rc1", 0), ("1.0~rc1", "1.0", -1), ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1), ("1.0~rc2", "1.0~rc1", 1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0), ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0~rc1", "1.0~rc1~git123", 1),
    ("1.0^", "1.0^", 0), ("1.0^", "1.0", 1), ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0), ("1.0^git1", "1.0", 1), ("1.0", "1.0^git1", -1),
    ("1.0^git1", "1.0^git2", -1), ("1.0^git2", "1.0^git1", 1),
    ("1.0^git1", "1.01", -1), ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0^20160101", 0), ("1.0^20160101", "1.0.1", -1),
    ("1.0.1", "1.0^20160101", 1),
    ("1.0^20160101^git1", "1.0^20160101^git1", 0),
    ("1.0^20160102", "1.0^20160101^git1", 1), ("1.0^20160101^git1", "1.0^20160102", -1),
    ("1.0~rc1^git1", "1.0~rc1^git1", 0), ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc1^git1", -1),
    ("1.0^git1~pre", "1.0^git1~pre", 0), ("1.0^git1", "1.0^git1~pre", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
]  # fmt: skip


@pytest.mark.parametrize(("a", "b", "expected"), RPMVERCMP)
def test_rpmvercmp(a, b, expected):
    assert rpmvercmp(a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("8.3.15-1.el9_6", "8.3.15-2.el9_6", -1),
        ("8.3.15-1.el9_6", "8.3.15-1.el9_6.1", -1),
        ("1:1.54.3-5.el9_8", "1.99-1.el9", 1),  # the epoch wins
        ("0:8.3.15-1.el9", "8.3.15-1.el9", 0),
        ("8.3.15", "8.3.15-9.el9", 0),  # no release on one side: not compared
        ("8.0.30-1.module+el8.4.0+1", "8.0.30-1.module+el8.10.0+1", -1),
    ],
)
def test_rpm_epoch_version_release(a, b, expected):
    assert rpm_compare(a, b) == expected
    assert compare("rpm", a, b) == expected


DPKG = [
    ("1.0", "1.0", 0), ("1.0-1", "1.0-2", -1), ("1:1.0", "2.0", 1), ("0:1.0", "1.0", 0),
    ("1.2.3", "1.2.3-0", 0),  # no revision equals revision 0
    ("1.0~rc1", "1.0", -1), ("1.0", "1.0+b1", -1), ("1.0+b1", "1.0.1", -1),
    ("1.0a", "1.0", 1), ("2.30", "2.4", 1), ("1.0-1ubuntu1", "1.0-1", 1),
    ("8.3.6-0ubuntu0.24.04.5", "8.3.6-0ubuntu0.24.04.6", -1),
    ("7.4.3-4ubuntu2.24", "7.4.3-4ubuntu2.3", 1),
    ("2:8.3+93ubuntu2", "1:9.0", 1),
    ("1.0-1~bpo12+1", "1.0-1", -1),  # a backport sorts before the release it came from
    ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.10", -1),
    ("1.001", "1.1", 0), ("1.0.0", "1.0", 1),
    ("1.0a", "1.0+", -1), ("1.0z", "1.0.", -1),  # letters before other symbols
]  # fmt: skip


@pytest.mark.parametrize(("a", "b", "expected"), DPKG)
def test_dpkg(a, b, expected):
    assert dpkg_compare(a, b) == expected
    assert dpkg_compare(b, a) == -expected
    assert compare("dpkg", a, b) == expected


def test_dpkg_tilde_chain():
    """Debian policy §5.6.12: ~~ < ~~a < ~ < (nothing) < a."""
    chain = ["1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a"]
    for low, high in zip(chain, chain[1:], strict=False):
        assert dpkg_compare(low, high) == -1, (low, high)


@pytest.mark.parametrize(
    ("family", "text"),
    [
        ("dpkg", ""), ("dpkg", "1.0 2"), ("dpkg", "x:1.0"), ("dpkg", ":1.0"), ("dpkg", "1:"),
        ("rpm", ""), ("rpm", "a:1"), ("rpm", "-1"), ("rpm", "1²:1"),
        ("dpkg", "-1"), ("dpkg", "0:-0"), ("dpkg", "1.0-"),
        ("dpkg", "999999999999999999999999:0-1"), ("dpkg", "9" * 5000 + ":1"),
        ("dpkg", "1.0_1"), ("dpkg", "1.0-1:2"),
        ("rpm", "9" * 5000 + ":1"), ("dpkg", None), ("rpm", 3),
    ],
)  # fmt: skip
def test_what_isnt_a_version(family, text):
    with pytest.raises(VersionError):
        compare(family, text, "1.0")


def test_only_ascii_digits_count():
    # A digit from another script isn't one to rpm, and dpkg refuses it.
    arabic_three = "1." + chr(0x663)
    assert rpmvercmp(arabic_three, "1.3") != 0
    with pytest.raises(VersionError):
        dpkg_compare(arabic_three, "1.3")


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0-beta-1", "1.0-beta-2", -1),  # an upstream version holding hyphens
        ("1:2:3-1", "1:2:3-1", 0), ("1:2:3-1", "1:2:4-1", -1),  # and colons, after an epoch
        ("01:1.0", "1:1.0", 0), ("1:1.0", "2:0.1", -1), ("9:1.0", "10:1.0", -1),
        ("1." + "9" * 40, "1." + "9" * 39, 1),
    ],
)  # fmt: skip
def test_dpkg_splits_as_dpkg_does(a, b, expected):
    assert dpkg_compare(a, b) == expected


def test_rpm_splits_as_rpm_does():
    """rpm's parseEVR splits on the last hyphen; leading zeros in an epoch
    don't count; long numbers compare as numbers."""
    assert rpm_compare("1.0-1-1", "1.0-1-2") == -1
    assert rpm_compare("1.0-1-9", "1.0.1-1") == 1  # version 1.0-1 equals 1.0.1; release 9 > 1
    assert rpm_compare("01:1.0-1", "1:1.0-1") == 0
    assert rpm_compare("1." + "9" * 40 + "-1", "1." + "9" * 39 + "-1") == 1


def test_an_unknown_family():
    with pytest.raises(ValueError, match="no version ordering"):
        compare("pacman", "1", "2")


def golden_versions():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent / "integration"))
    import golden

    found = {"dpkg": set(), "rpm": set()}
    for path in golden.cases():
        case = golden.load_case(path)
        items = case["snapshots"][case["target"]]["sections"]["packages"]["items"]
        for item in items.values():
            found[item["manager"]].add(item["version"])
    return found


def test_every_golden_version_orders_consistently():
    """Every package version on the golden servers is read, and the order
    is a proper one: each equals itself, swapping flips the sign, and a
    sorted sample stays sorted pairwise."""
    import functools

    found = golden_versions()
    assert len(found["dpkg"]) > 100 and len(found["rpm"]) > 100
    for family, versions in found.items():
        versions = sorted(versions)
        for version in versions:  # every one parses
            assert compare(family, version, version) == 0
        sample = random.Random(1).sample(versions, 60)  # noqa: S311 - a fixed sample
        for a in sample:
            assert compare(family, a, a) == 0
            for b in sample[:15]:
                assert compare(family, a, b) == -compare(family, b, a)
        ordered = sorted(sample, key=functools.cmp_to_key(functools.partial(compare, family)))
        for i, low in enumerate(ordered):
            for high in ordered[i + 1 :]:
                assert compare(family, low, high) <= 0, (low, high)


def test_the_ordering_stands_alone():
    code = (
        "import sys, checker.packs.versions\n"
        "print(sorted(m for m in sys.modules if m.startswith('checker')"
        " and m not in ('checker', 'checker.packs', 'checker.packs.versions')))\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "[]"


def test_matches_dpkg_itself_where_it_is_installed():
    """Where this machine has dpkg, its own answers agree with ours."""
    import shutil

    dpkg = shutil.which("dpkg")
    if dpkg is None:
        pytest.skip("no dpkg on this machine")
    for a, b, expected in DPKG:
        for op, want in (("lt", expected < 0), ("eq", expected == 0), ("gt", expected > 0)):
            done = subprocess.run([dpkg, "--compare-versions", a, op, b], check=False)
            assert (done.returncode == 0) == want, (a, op, b)
