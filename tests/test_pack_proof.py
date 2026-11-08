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
    - release: "rhel:9"
      binary_names: ["nodejs", "npm"]
      versions: "27.*"
      fixed: "1:27.1.0-2.el9"
      source: "https://access.redhat.com/security/cve/CVE-2026-0001"
    - release: "rhel:9"
      binary_names: ["ruby"]
      versions: "3.3.*module?el9*"
      fixed: "3.3.9-1.module+el9.8.0"
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
    assert [g.names for g in found] == [("demo", "libdemo"), ("nodejs", "npm"), ("ruby",)]
    assert [g.has_fix for g in found] == [True, True, True]
    assert [g.module for g in found] == [False, False, True]


def test_a_group_is_judged_on_its_own_entries():
    whole = pack()
    group = pp.groups(whole, "rhel:9")[1]
    alone = pp.only(whole, group)
    assert [e.versions for e in alone.exposure.packages] == ["26.*", "27.*"]
    assert alone.id == whole.id and alone.exposure.other_builds == "cant_judge"
    assert len(whole.exposure.packages) == 7  # the pack itself is untouched


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
    assert quiet.uncovered == [
        "libdemo1 1.1.0-1 is offered, no pattern matches it, and the pack reads that as"
        " not affected (other_builds): check it isn't affected"
    ]
    assert quiet.unjudged == []


def test_no_fix_offered_and_nothing_offered():
    group = pp.groups(pack(), "rhel:9")[1]
    choice = pp.choose(pack(), group, {"nodejs": ["1:26.1.0-1.el9"]})
    assert (choice.vulnerable, choice.fixed) == ("1:26.1.0-1.el9", None)
    assert choice.looks == ["the pack's fix 1:27.1.0-2.el9 for nodejs isn't offered by the archive"]
    assert pp.choose(pack(), group, {}) == pp.Choice()


def test_the_fix_boundary_is_listed_when_it_cant_be_seen_whole():
    group = pp.groups(pack(), "rhel:9")[0]
    offered = {"demo": ["1.0.9-7.el9_5", "1.0.9-12.el9_8"]}  # the fix itself is gone
    choice = pp.choose(pack(), group, offered)
    assert (choice.vulnerable, choice.fixed) == ("1.0.9-7.el9_5", "1.0.9-12.el9_8")
    assert choice.looks == ["the pack's fix 1.0.9-10.el9_8.1 for demo isn't offered by the archive"]
    between = {"demo": ["1.0.9-7.el9_5", "1.0.9-8", "1.0.9-10.el9_8.1"]}  # an unjudged build
    looks = pp.choose(pack(), group, between).looks
    assert looks == ["demo builds between 1.0.9-7.el9_5 and 1.0.9-10.el9_8.1 read neither"]


def test_versions_that_cant_be_read_are_left_out_of_the_order():
    assert pp._sorted("rpm", ["1.0-2.el9", "1.0-10.el9", "1.0-1.el9"]) == [
        "1.0-1.el9", "1.0-2.el9", "1.0-10.el9",
    ]  # fmt: skip
    assert pp._sorted("dpkg", ["1.0-1", "bad version", "0.9-1"]) == ["0.9-1", "1.0-1"]


def test_listing_lists_every_build_without_dnf4_only_flags():
    apt = pp.listing("ubuntu:24.04", ("demo", "lib demo"))
    assert 'apt-cache madison "$n"' in apt and "'lib demo'" in apt
    dnf = pp.listing("rhel:10", ("demo",))
    assert (
        "repoquery --arch x86_64,noarch --qf '%{name} %{epoch}:%{version}-%{release}\\n' demo"
        in dnf
    )
    assert "--showduplicates" not in dnf


def seen(status, judged):
    return {"exposure": {"status": status}, "judged": judged}


def test_a_stage_needs_every_package_at_the_version_and_the_verdict():
    good = pp.Result("rhel:9")
    judged = {
        "demo x86_64": ("1.0-1.el9", "vulnerable"),
        "libdemo x86_64": ("1.0-1.el9", "vulnerable"),
    }
    pp.expect_stage(good, "s", seen("vulnerable", judged), "1.0-1.el9", "vulnerable")
    assert not good.failed and len(good.passed) == 4
    bad = pp.Result("rhel:9")
    judged = {"demo x86_64": ("1.0-1.el9", "vulnerable"), "demo i686": ("1.0-2.el9", "fixed")}
    pp.expect_stage(bad, "s", seen("vulnerable", judged), "1.0-1.el9", "vulnerable")
    assert "s: installed at 1.0-1.el9" in bad.failed
    assert "s: demo i686 reads vulnerable" in bad.failed
    assert any(line.startswith("s: saw status vulnerable") for line in bad.failed)
    nothing = pp.Result("rhel:9")
    pp.expect_stage(nothing, "s", seen("fixed", {}), "1.0-1.el9", "fixed")
    assert nothing.failed[0] == "s: installed at 1.0-1.el9"


def test_install_downgrades_with_each_managers_syntax():
    apt = pp.install("ubuntu:24.04", ["demo", "libdemo1"], "1.1.0-2build2")
    assert "install --no-remove --allow-downgrades demo=1.1.0-2build2 libdemo1=1.1.0-2build2" in apt
    dnf = pp.install("rhel:9", ["nodejs"], "1:26.1.0-1.el9")
    assert "$DNF install nodejs-1:26.1.0-1.el9" in dnf and "allowerasing" not in dnf


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


def test_another_groups_vulnerable_package_doesnt_reach_this_groups_verdict():
    from datetime import UTC, datetime

    from checker.packs.exposure import judge

    whole = pack()
    rocky = {"os": {"id": "rocky", "version_id": "9.6"}}
    installed = {
        "demo x86_64": {"manager": "rpm", "version": "1.0.9-10.el9_8.1"},  # fixed
        "nodejs x86_64": {"manager": "rpm", "version": "1:26.1.0-1.el9"},  # no fix: vulnerable
    }
    now = datetime(2026, 11, 8, tzinfo=UTC)
    assert judge(whole, rocky, installed, [], now).status == "vulnerable"
    alone = pp.only(whole, pp.groups(whole, "rhel:9")[0])
    assert judge(alone, rocky, installed, [], now).status == "fixed"


def test_prove_creates_one_server_and_deletes_it_in_finally():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(pp.prove))
    source = inspect.getsource(pp.prove)
    assert source.count("_create_server(") == 1
    assert source.count("for group in groups(") == 1
    tries = [n for n in ast.walk(tree) if isinstance(n, ast.Try) and n.finalbody]
    assert any("api.delete" in ast.unparse(t.finalbody) for t in tries)


def test_the_groups_others_left_as_they_were_are_in_the_summary():
    result = pp.Result("ubuntu:24.04")
    state = seen("vulnerable", {"demo amd64": ("1.1.0-2ubuntu0.1", "fixed")})
    state["rest"] = {"libdemo1 amd64": ("1.1.0-2build2", "vulnerable")}
    pp.expect_stage(result, "s", state, "1.1.0-2ubuntu0.1", "fixed")
    assert "s: the host reads fixed" in result.failed
    saw = next(line for line in result.failed if line.startswith("s: saw"))
    assert "left as they were {'libdemo1 amd64': ('1.1.0-2build2', 'vulnerable')}" in saw
