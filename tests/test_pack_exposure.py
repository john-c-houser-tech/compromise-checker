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
                            priors=lambda host: prior, packs=lambda host: ([PACK], []))  # fmt: skip
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


# --- After review ------------------------------------------------------------------------------


def test_an_epoch_the_fix_doesnt_write_cant_be_judged():
    """1:8.3.6…5 sorts above 8.3.6…6 as written: that mustn't read as fixed."""
    found = judge(PACK, UBUNTU, dpkg("1:8.3.6-0ubuntu0.24.04.5"), [], NOW)
    assert found.status == CANT_JUDGE and "has an epoch" in found.packages[0].why
    assert found.share == 1.0


RHEL_STREAM = GOOD.replace(
    '      fixed: "8.3.15-1.el9_6"', '      versions: "8.1.*"\n      fixed: "8.1.30-1.el9_6"'
)


def test_a_versions_pattern_matches_with_or_without_the_epoch():
    pack = with_pack(RHEL_STREAM)
    rpm = {"php-fpm x86_64": {"manager": "rpm", "version": "1:8.1.14-1.el9", "installed": FIXED_AT}}
    assert judge(pack, ROCKY, rpm, [], NOW).status == CANT_JUDGE  # matched, not "not affected"
    rpm["php-fpm x86_64"]["version"] = "8.1.14-1.el9"
    assert judge(pack, ROCKY, rpm, [], NOW).status == VULNERABLE


def test_a_build_from_another_repository_above_the_fix_cant_be_judged():
    remi = {"php-fpm x86_64": {"manager": "rpm", "version": "8.3.20-1.remi", "installed": FIXED_AT}}
    found = judge(PACK, ROCKY, remi, [], NOW)
    assert found.status == CANT_JUDGE and "isn't the vendor's own build" in found.packages[0].why
    # The vendor's own build above the fix is fixed.
    own = {"php-fpm x86_64": {"manager": "rpm", "version": "8.3.16-1.el9_6", "installed": FIXED_AT}}
    assert judge(PACK, ROCKY, own, [], NOW).status == FIXED


def test_a_service_on_old_code_keeps_the_host_exposed_even_when_the_fix_came_first():
    early = datetime(2026, 10, 2, tzinfo=UTC).timestamp()  # before the window opened
    old = {"pid": 7, "comm": "php-fpm8.3", "start_time": "2026-09-01T00:00:00+00:00"}
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6", early), [old], NOW)
    assert found.status == FIXED and found.share == 1.0 and found.exposed_until is None
    assert [p["pid"] for p in found.stale] == [7]


def test_a_program_replaced_under_a_service_is_stale_whatever_its_start():
    later = {"pid": 9, "comm": "php-fpm8.3", "start_time": "2026-10-28T00:00:00+00:00",
             "exe_deleted": True, "exe": "/usr/sbin/php-fpm8.3 (deleted)"}  # fmt: skip
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [later], NOW)
    assert [p["pid"] for p in found.stale] == [9]


def test_one_unknown_install_time_makes_the_fix_time_unknown():
    both = {
        **dpkg("8.3.6-0ubuntu0.24.04.6", None),
        **dpkg("8.3.6-0ubuntu0.24.04.6", datetime(2026, 10, 21, tzinfo=UTC).timestamp(),
               name="libapache2-mod-php8.3 amd64"),
    }  # fmt: skip
    found = judge(PACK, UBUNTU, both, [], NOW)
    assert found.status == FIXED and found.share == 1.0 and found.fixed_at is None


@pytest.mark.parametrize("installed", [1e20, float("nan"), "year 30000", -1e18])
def test_an_impossible_install_time_doesnt_break_the_analysis(installed):
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6", installed), [], NOW)
    assert found.status == FIXED and found.share == 1.0


def test_a_listing_collected_in_part_proves_nothing():
    found = judge(PACK, UBUNTU, dpkg("1.0-1", name="nginx amd64"), [], NOW, complete=False)
    assert found.status == CANT_JUDGE and found.share == 1.0


def test_no_fix_yet_wins_over_a_version_that_cant_be_read():
    sury = 'versions: "*+deb.sury.org*"\n      fixed: "8.3.27-1+ubuntu24.04.1+deb.sury.org+1"'
    text = SURY.replace(sury, 'versions: "*"\n      fixed: null')
    found = judge(with_pack(text), UBUNTU, dpkg("8.3_6"), [], NOW)
    assert found.status == VULNERABLE


def test_a_naive_collection_time_is_taken_as_utc():
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.5"), [], datetime(2026, 10, 30))
    assert found.share == 1.0


def test_the_raise_is_kept_exactly_for_a_rescore():
    from checker.scoring import prior_raise_of

    assert prior_raise_of([{"log_raise": 1.2345678, "share": 0.5, "ratio": 5}]) == 1.2345678
    assert prior_raise_of([]) == 0.0


def findings_for(home, version, extra_records=(), **kwargs):
    assessment = analysed_with(home, version, extra_records, **kwargs)
    return [f for f in assessment["findings"] if f["check"] == "pack.exposure"], assessment


def analysed_with(home, version, extra_records=(), installed=FIXED_AT, pack=PACK):
    from checker.assess import analyze

    base, store, identity, config = home
    add_bundle(home, "b1", 0, records(version, installed, extra_records))
    return analyze(store, "web01", identity, config.recipients, packs=[pack])


def test_the_findings_say_what_is_known(home):
    pack = with_pack(
        GOOD.replace(
            "  likelihood_ratio: 5", "  window_end: 2026-10-23T00:00:00Z\n  likelihood_ratio: 5"
        )
    )
    found, _ = findings_for(home, "8.3.6-0ubuntu0.24.04.6", pack=pack)
    (exposed,) = [f for f in found if f["variant"] == "was_exposed"]
    assert "until the window closed at 2026-10-23" in exposed["summary"]


def test_a_rule_for_pack_findings_must_name_the_pack():
    from checker.whitelist import Match

    with pytest.raises(ValueError, match="must name the pack"):
        Match(check="pack.exposure", package="php8.3-fpm")
    assert Match(check="pack.exposure", package="php8.3-fpm", pack="example-2026-10")


def test_a_release_not_covered_names_the_os(home):
    found = judge(PACK, {"os": {"id": "centos", "version_id": "9"}}, {}, [], NOW)
    assert found.status == UNKNOWN_RELEASE and found.release == "centos"


def test_a_build_no_entry_matches_is_safe_only_if_the_pack_says_so():
    text = GOOD.replace(
        "binary_names: [php8.3-fpm, libapache2-mod-php8.3]\n",
        'binary_names: [php8.3-fpm, libapache2-mod-php8.3]\n      versions: "8.3.6-*"\n',
    )
    listed = {"php8.3-fpm amd64": {"manager": "dpkg", "version": "8.3.99-custom"}}
    plain = judge(read(text.encode()), UBUNTU, listed, [], NOW)
    assert plain.status == "not affected"
    strict = read(
        text.replace("  stale_code:", "  other_builds: cant_judge\n  stale_code:").encode()
    )
    found = judge(strict, UBUNTU, listed, [], NOW)
    assert found.status == "can't judge" and "doesn't cover" in found.packages[0].why
    # A package no entry names is still not this pack's.
    other = {"nginx amd64": {"manager": "dpkg", "version": "1.0-1"}}
    assert judge(strict, UBUNTU, other, [], NOW).status == "not affected"


STRICT = read(
    GOOD.replace(
        "binary_names: [php-fpm]\n", 'binary_names: [php-fpm]\n      versions: "8.3.*.el9_*"\n'
    )
    .replace("  stale_code:", "  other_builds: cant_judge\n  stale_code:")
    .encode()
)
ROCKY = {"os": {"id": "rocky", "version_id": "9.8"}}
UNCOVERED, COVERED = "8.3.30-1.foo.el9", "8.3.15-1.el9_6"


def removal(name, previous, when):
    return {"time": when, "type": "package.remove",
            "fields": {"name": name, "previous": previous, "version": None}}  # fmt: skip


def test_an_uncovered_build_removed_in_the_window_was_exposed_until_then():
    history = [removal("php-fpm", UNCOVERED, "2026-10-25T00:00:00+00:00")]
    found = judge(STRICT, ROCKY, {}, [], NOW, True, history, [], True)
    assert found.status == "fixed" and found.removed_at and found.share > 0


def test_an_uncovered_build_earlier_means_a_fixed_install_isnt_fresh():
    listing = {"php-fpm x86_64": {"manager": "rpm", "version": COVERED, "installed": FIXED_AT}}
    earlier = [(datetime(2026, 10, 22, tzinfo=UTC),
                {"php-fpm x86_64": {"manager": "rpm", "version": UNCOVERED}})]  # fmt: skip
    installed = {"time": "2026-10-25T00:00:00+00:00", "type": "package.install",
                 "fields": {"name": "php-fpm", "version": COVERED, "previous": None}}  # fmt: skip
    found = judge(STRICT, ROCKY, listing, [], NOW, True, [installed], earlier, True)
    assert found.packages[0].fresh is False and found.share > 0


def test_a_stale_service_is_said_when_another_package_cant_be_judged():
    listing = {
        "php-fpm x86_64": {"manager": "rpm", "version": COVERED, "installed": FIXED_AT},
        "php-fpm i686": {"manager": "rpm", "version": UNCOVERED},
    }
    old = {"pid": 7, "comm": "php-fpm", "start_time": "2026-10-21T00:00:00+00:00"}
    found = judge(STRICT, ROCKY, listing, [old], NOW)
    assert found.status == "can't judge" and [p["pid"] for p in found.stale] == [7]


def test_a_versioned_worker_is_judged_by_its_own_versions_fix():
    text = GOOD.replace(
        "binary_names: [php8.3-fpm, libapache2-mod-php8.3]",
        "binary_names: [php8.3-fpm, php8.4-fpm, libapache2-mod-php8.3]",
    ).replace('fixed: "8.3.6-0ubuntu0.24.04.6"', 'fixed: "8.3.6-0ubuntu0.24.04.6"', 1)
    pack = read(text.encode())
    early, late = datetime(2026, 10, 22, tzinfo=UTC).timestamp(), FIXED_AT
    listed = {
        "php8.3-fpm amd64": {"manager": "dpkg", "version": "8.3.6-0ubuntu0.24.04.6",
                             "installed": early},
        "php8.4-fpm amd64": {"manager": "dpkg", "version": "8.3.6-0ubuntu0.24.04.7",
                             "installed": late},
    }  # fmt: skip
    between = "2026-10-23T00:00:00+00:00"
    workers = [{"pid": 1, "comm": "php-fpm8.3", "start_time": between},
               {"pid": 2, "comm": "php-fpm8.4", "start_time": between},
               {"pid": 3, "comm": "php-fpm", "start_time": between}]  # fmt: skip
    found = judge(pack, UBUNTU, listed, workers, NOW)
    # 8.3's fix came first: its workers are on it. 8.4's aren't. One naming no
    # version can't be told apart, so the newest fix counts.
    assert sorted(p["pid"] for p in found.stale) == [2, 3]
