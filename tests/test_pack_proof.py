"""The general pack proof's planning and judging (the servers are only in the real run)."""

import importlib.util
import sys
from pathlib import Path

import pytest

from checker.packs.format import read

HERE = Path(__file__).parent / "integration"
sys.path.insert(0, str(HERE))  # it imports readonly_proof beside it
_spec = importlib.util.spec_from_file_location("pack_proof", HERE / "pack_proof.py")
pp = importlib.util.module_from_spec(_spec)
sys.modules["pack_proof"] = pp
_spec.loader.exec_module(pp)

PACK = """
format: 1
id: demo-2026-10
version: 1
title: A demo
published: 2026-11-01
cves: [CVE-2026-0001]
exposure:
  window_start: 2026-10-22T00:00:00Z
  likelihood_ratio: 3
  other_builds: {other}
  packages:
    - release: "ubuntu:24.04"
      binary_names: ["demo", "libdemo1"]
      versions: "1.1.0-2build*"
      fixed: "1.1.0-2ubuntu0.1"
      source: "https://ubuntu.com/security/notices/USN-0001-1"
    - release: "ubuntu:24.04"
      binary_names: ["demo", "libdemo1"]
      versions: "1.1.0-2ubuntu*"
      fixed: "1.1.0-2ubuntu0.1"
      source: "https://ubuntu.com/security/notices/USN-0001-1"
    - release: "ubuntu:26.10"
      binary_names: ["demo"]
      versions: "1.2.0-4"
      fixed: "1.2.0-4ubuntu0.1"
      source: "https://ubuntu.com/security/notices/USN-0001-1"
    - release: "rhel:9"
      binary_names: ["demo", "libdemo"]
      versions: "*.el9*"
      fixed: "1.0.9-10.el9_8.1"
      source: "https://access.redhat.com/errata/RHSA-2026:0001"
    - release: "rhel:9"
      binary_names: ["nodejs"]
      versions: "26.*"
      fixed: null
      source: "https://access.redhat.com/security/cve/CVE-2026-0001"
remediation: [Update demo.]
references: ["https://ubuntu.com/security/CVE-2026-0001"]
"""


def pack(other="cant_judge"):
    try:
        return read(PACK.replace("{other}", other).encode())
    except Exception as exc:  # the demo must stay a valid pack
        pytest.fail(f"the demo pack doesn't read: {exc}")


MADISON = """\
      demo | 1.1.0-2ubuntu0.1 | http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
      demo | 1.1.0-2ubuntu0.1 | http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
      demo | 1.1.0-2build2 | http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
      demo | 1.1.0-2build2 | http://archive.ubuntu.com/ubuntu noble/main Sources
  libdemo1 | 1.1.0-2ubuntu0.1 | http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
  libdemo1 | 1.1.0-2build2 | http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
"""


def test_releases_get_one_image_each_and_the_rest_are_named():
    have, missing = pp.plan(pack())
    assert have == {"ubuntu:24.04": "ubuntu24.04", "rhel:9": "rocky9"}
    assert missing == ["ubuntu:26.10"]
    assert pp.plan(pack(), alma=True)[0]["rhel:9"] == "alma9"


def test_groups_are_the_names_entries_share():
    found = pp.groups(pack(), "rhel:9")
    assert [g.names for g in found] == [("demo", "libdemo"), ("nodejs",)]
    assert [g.has_fix for g in found] == [True, False]


def test_madison_keeps_binaries_once():
    assert pp.parse_madison(MADISON) == {
        "demo": ["1.1.0-2ubuntu0.1", "1.1.0-2build2"],
        "libdemo1": ["1.1.0-2ubuntu0.1", "1.1.0-2build2"],
    }


def test_repoquery_drops_a_zero_epoch_and_keeps_a_real_one():
    text = "demo 0:1.0.9-10.el9_8.1\n\ndemo 0:1.0.9-7.el9_5\nnodejs 1:26.1.0-1.el9\n"
    assert pp.parse_repoquery(text) == {
        "demo": ["1.0.9-10.el9_8.1", "1.0.9-7.el9_5"],
        "nodejs": ["1:26.1.0-1.el9"],
    }


def test_the_last_vulnerable_and_the_first_fixed_are_chosen():
    group = pp.groups(pack(), "rhel:9")[0]
    offered = {"demo": ["1.0.9-10.el9_8.1", "1.0.9-7.el9_5", "1.0.9-11.el9_8", "1.0.9-6.el9"]}
    choice = pp.choose(pack(), group, offered)
    assert (choice.vulnerable, choice.fixed) == ("1.0.9-7.el9_5", "1.0.9-10.el9_8.1")
    assert (choice.uncovered, choice.unjudged) == ([], [])


def test_offered_builds_the_pack_cant_judge_or_doesnt_cover_are_listed():
    group = pp.groups(pack(), "ubuntu:24.04")[0]
    offered = pp.parse_madison(MADISON) | {"libdemo1": ["1.1.0-1", "1.1.0-2build2"]}
    choice = pp.choose(pack(), group, offered)
    assert (choice.vulnerable, choice.fixed) == ("1.1.0-2build2", "1.1.0-2ubuntu0.1")
    assert choice.unjudged == ["libdemo1 1.1.0-1 is offered and reads can't judge"]
    assert choice.uncovered == []
    quiet = pp.choose(pack("not_affected"), group, offered)
    assert quiet.uncovered == ["libdemo1 1.1.0-1 is offered but no entry covers it"]
    assert quiet.unjudged == []


def test_no_fix_offered_and_nothing_offered():
    group = pp.groups(pack(), "rhel:9")[1]
    choice = pp.choose(pack(), group, {"nodejs": ["1:26.1.0-1.el9"]})
    assert (choice.vulnerable, choice.fixed) == ("1:26.1.0-1.el9", None)
    assert pp.choose(pack(), group, {}) == pp.Choice()


def test_install_downgrades_with_each_managers_syntax():
    apt = pp.install("ubuntu:24.04", ["demo", "libdemo1"], "1.1.0-2build2")
    assert "install --allow-downgrades demo=1.1.0-2build2 libdemo1=1.1.0-2build2" in apt
    dnf = pp.install("rhel:9", ["nodejs"], "1:26.1.0-1.el9")
    assert "install --allowerasing nodejs-1:26.1.0-1.el9" in dnf


def test_the_report_says_what_wasnt_proved():
    good = pp.Result("ubuntu:24.04", passed=["x"])
    partial = pp.Result("rhel:9", passed=["x"], unproved=["nodejs: fixed not proved"])
    none = pp.Result("ubuntu:26.10", unproved=["no image for this release"])
    bad = pp.Result("rhel:10", passed=["x"], failed=["y"])
    assert [pp.verdict(r) for r in (good, partial, none, bad)] == [
        "PASS", "NEEDS A LOOK", "NEEDS A LOOK", "FAIL",
    ]  # fmt: skip
    assert pp.report([good]) == 0
    assert pp.report([good, partial]) == 2
    assert pp.report([good, partial, bad]) == 1
