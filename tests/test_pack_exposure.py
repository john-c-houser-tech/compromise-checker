"""Exposure to a pack's threat (checker/packs/exposure.py, checks/packs.py,
the prior's raise; plan 4.3). The pack is the format tests' made-up one."""

import math
from datetime import UTC, datetime

import pytest
from test_pack_format import GOOD
from test_snapshot import add_bundle, host_records, rec

from checker.packs.exposure import (
    CANT_JUDGE,
    FIXED,
    NOT_AFFECTED,
    NOT_COVERED,
    UNKNOWN_RELEASE,
    VULNERABLE,
    judge,
    prior_raise,
    release_of,
)
from checker.packs.format import read
from checker.scoring import score

PACK = read(GOOD.encode())  # window from 2026-10-20 00:00 UTC; ubuntu:24.04 and rhel:9
UBUNTU = {"os": {"id": "ubuntu", "version_id": "24.04"}}
ROCKY = {"os": {"id": "rocky", "version_id": "9.4"}}
NOW = datetime(2026, 10, 30, tzinfo=UTC)  # ten days into the window
FIXED_AT = datetime(2026, 10, 25, tzinfo=UTC).timestamp()  # half way


def dpkg(version, installed=FIXED_AT, name="php8.3-fpm amd64"):
    return {name: {"manager": "dpkg", "version": version, "installed": installed}}


def with_pack(text):
    return read(text.encode())


def test_releases():
    assert release_of(UBUNTU) == ("ubuntu:24.04", "dpkg")
    assert release_of(ROCKY) == ("rhel:9", "rpm")
    assert release_of({"os": {"id": "almalinux", "version_id": "10.0"}}) == ("rhel:10", "rpm")
    assert release_of({"os": {"id": "debian", "version_id": "12"}}) == (None, None)


def test_a_vulnerable_package_exposes_the_whole_window():
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.5"), [], NOW)
    assert found.status == VULNERABLE and found.share == 1.0
    (package,) = found.packages
    assert (package.name, package.status, package.fixed) == (
        "php8.3-fpm",
        VULNERABLE,
        "8.3.6-0ubuntu0.24.04.6",
    )


def test_a_fix_half_way_through_exposes_half_and_says_by_when():
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [], NOW)
    assert found.status == FIXED and found.share == pytest.approx(0.5)
    assert found.exposed_until.startswith("2026-10-25")


def test_a_fix_before_the_window_exposes_nothing():
    early = datetime(2026, 10, 1, tzinfo=UTC).timestamp()
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.7", early), [], NOW)
    assert found.status == FIXED and found.share == 0.0 and found.exposed_from is None


def test_a_version_that_cant_be_read_cant_be_judged_and_counts_as_exposed():
    found = judge(PACK, UBUNTU, dpkg("8.3_6"), [], NOW)
    assert found.status == CANT_JUDGE and found.share == 1.0
    assert "doesn't allow" in found.packages[0].why


def test_not_installed_not_covered_unknown():
    assert judge(PACK, UBUNTU, dpkg("1.0-1", name="nginx amd64"), [], NOW).status == NOT_AFFECTED
    noble = {"os": {"id": "ubuntu", "version_id": "26.04"}}
    assert judge(PACK, noble, dpkg("8.3.0-1"), [], NOW).status == NOT_COVERED
    assert judge(PACK, {}, dpkg("8.3.0-1"), [], NOW).status == UNKNOWN_RELEASE
    rpm_named_like_dpkg = {
        "php8.3-fpm x86_64": {"manager": "rpm", "version": "1-1", "installed": 0}
    }
    assert judge(PACK, UBUNTU, rpm_named_like_dpkg, [], NOW).status == NOT_AFFECTED


SURY = GOOD.replace(
    "  stale_code:",
    '    - release: "ubuntu:24.04"\n'
    "      binary_names: [php8.3-fpm]\n"
    '      versions: "*+deb.sury.org*"\n'
    '      fixed: "8.3.27-1+ubuntu24.04.1+deb.sury.org+1"\n'
    "      source: https://launchpad.net/~ondrej/+archive/ubuntu/php\n"
    "  stale_code:",
)


def test_a_package_matching_two_entries_is_vulnerable_if_either_says_so():
    """A Sury build sorts above the Ubuntu archive's fix, but the Sury
    entry's fix is later still: vulnerable."""
    pack = with_pack(SURY)
    sury = judge(pack, UBUNTU, dpkg("8.3.20-1+ubuntu24.04.1+deb.sury.org+1"), [], NOW)
    assert sury.status == VULNERABLE
    assert sury.packages[0].fixed == "8.3.27-1+ubuntu24.04.1+deb.sury.org+1"
    fixed_sury = judge(pack, UBUNTU, dpkg("8.3.27-1+ubuntu24.04.1+deb.sury.org+1"), [], NOW)
    assert fixed_sury.status == FIXED
    archive = judge(pack, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [], NOW)
    assert archive.status == FIXED  # the Sury pattern doesn't match it


def test_no_fix_yet_is_vulnerable_whatever_the_version():
    pack = with_pack(GOOD.replace('fixed: "8.3.6-0ubuntu0.24.04.6"', "fixed: null"))
    assert judge(pack, UBUNTU, dpkg("99.0-1"), [], NOW).status == VULNERABLE


def test_a_service_started_before_the_last_update_may_run_old_code():
    old = {"pid": 7, "comm": "php-fpm8.3", "start_time": "2026-10-22T00:00:00+00:00"}
    new = {"pid": 8, "comm": "php-fpm8.3", "start_time": "2026-10-26T00:00:00+00:00"}
    other = {"pid": 9, "comm": "nginx", "start_time": "2026-10-01T00:00:00+00:00"}
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [old, new, other], NOW)
    assert [p["pid"] for p in found.stale] == [7]


def test_before_the_window_opens_nothing_counts():
    found = judge(
        PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.5"), [], datetime(2026, 10, 1, tzinfo=UTC)
    )
    assert found.status == VULNERABLE and found.share == 0.0


def test_the_raise_follows_decision_d3_and_is_capped():
    full = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.5"), [], NOW)
    half = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [], NOW)
    assert prior_raise([full], 10) == pytest.approx(math.log(5))
    assert prior_raise([half], 10) == pytest.approx(math.log(5) / 2)
    assert prior_raise([full, full], 10) == pytest.approx(
        math.log(10)
    )  # threats don't stack past 10
    raised = score([], 0.02, [], prior_raise([full], 10), [{"pack": "x"}])
    assert raised["raised_prior"] == pytest.approx(0.0926, abs=1e-4)  # 2% -> about 9%
    assert raised["probability"] == pytest.approx(0.0926, abs=1e-4)
    halfway = score([], 0.02, [], prior_raise([half], 10), [{"pack": "x"}])
    assert halfway["raised_prior"] == pytest.approx(0.0436, abs=1e-4)
    assert "raised_prior" not in score([], 0.02, [])


# --- Through an analysis ---------------------------------------------------------------------


def records(version, installed=FIXED_AT, extra=()):
    return host_records(
        extra=(
            rec(
                "software",
                "package",
                manager="dpkg",
                name="php8.3-fpm",
                arch="amd64",
                version=version,
                installed=installed,
            ),  # fmt: skip
            *extra,
        )
    )


def analysed(home, version, **kwargs):
    from checker.assess import analyze

    base, store, identity, config = home
    add_bundle(home, "b1", 0, records(version, **kwargs))
    return analyze(store, "web01", identity, config.recipients, packs=[PACK])


def test_an_analysis_applies_the_pack(home):
    assessment = analysed(home, "8.3.6-0ubuntu0.24.04.5")
    (finding,) = [f for f in assessment["findings"] if f["check"] == "pack.exposure"]
    assert finding["variant"] == "vulnerable" and finding["category"] == "exposure"
    assert "php8.3-fpm 8.3.6-0ubuntu0.24.04.5 is before the fix" in finding["summary"]
    assert assessment["packs"] == [{"id": "example-2026-10", "version": 2}]
    s = assessment["score"]
    assert s["raised_by"][0]["pack"] == "example-2026-10" and s["raised_prior"] > s["prior"]
    assert finding["contribution"] == 0.0  # exposure isn't a sign of compromise


def test_the_report_says_the_prior_was_raised_and_keeps_it_when_reassessed(home):
    from checker.report import read_report, write_report

    base, store, identity, config = home
    analysed(home, "8.3.6-0ubuntu0.24.04.5")

    def report(prior):
        path = write_report(store, ["web01"], identity, config.recipients, base / "reports",
                            priors=lambda host: prior)  # fmt: skip
        return read_report(path, identity)

    html = report((0.02, "default"))
    assert "raised to 9% by exposure to example-2026-10 v2 (100% of its window, at most)" in html
    # Another prior (only the score is redone): the raise stays.
    again = report((0.05, "host"))
    assert "from a prior of 5% (host), raised to 20%" in again  # 5% at odds x5: 20.8%
    assert "the probability is the prior, as raised" in again


def test_a_host_on_a_release_the_pack_doesnt_cover_is_a_coverage_gap(home):
    from checker.assess import analyze

    base, store, identity, config = home
    other = [r for r in records("8.3.0-1") if not (r.get("name") == "os_release")]
    other.insert(1, rec("host_facts", "os_release", ID="ubuntu", VERSION_ID="22.04"))
    add_bundle(home, "b1", 0, other)
    assessment = analyze(store, "web01", identity, config.recipients, packs=[PACK])
    assert any("has no entry for this host's release (ubuntu:22.04)" in g
               for g in assessment["coverage"]["gaps"])  # fmt: skip
    assert "raised_prior" not in assessment["score"]
