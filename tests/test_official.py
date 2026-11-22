"""checker.official: changed PAM modules checked against the distribution's packages (#189, V.4).

The verifier is a fake here (checker.verify has its own tests); what is
tested is which files are checked, how each lookup is held to the
baseline, and how the results are stored with the collection and used.
"""

from __future__ import annotations

import pytest
from test_snapshot import add_bundle, host_records, rec

from checker import official
from checker.analysis import load_official
from checker.assess import analyze
from checker.snapshot import Section, Snapshot, compare
from checker.verify import Lookup, Official

UNIX = "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"
GOOD, BAD = "a" * 64, "b" * 64


def snap(
    *,
    os=("ubuntu", "24.04"),
    pam=None,
    owners=None,
    packages=None,
    packages_complete=True,
    merged=None,
    owners_complete=True,
):
    sections = {
        "host": Section({"os": {"id": os[0], "version_id": os[1]}} if os else {}),
        "pam": Section(dict(pam or {})),
        "packages": Section(dict(packages or {}), complete=packages_complete),
    }
    live = {"system_files_summary": {"merged_dirs": merged or {}}}
    if owners is not None:
        live["pam_owners"] = {"complete": owners_complete, "owners": owners}
    return Snapshot({"masking_version": 6, "full": True}, sections, live=live)


def owner(package="libpam-modules", arch="amd64", several=False):
    return {"package": package, "arch": arch, "several": several}


BEFORE = dict(
    pam={UNIX: {"sha256": GOOD, "size": 1}},
    owners={UNIX: owner()},
    packages={"libpam-modules amd64": {"version": "1.5.3-5ubuntu5.6", "manager": "dpkg"}},
)
AFTER = dict(
    pam={UNIX: {"sha256": BAD, "size": 2}},
    owners={UNIX: owner()},
    packages={"libpam-modules amd64": {"version": "1.5.3-5ubuntu5.7", "manager": "dpkg"}},
)


class FakeVerifier:
    """Answers with `files` for every lookup, and keeps what it was asked."""

    def __init__(self, files=None, reason="not there"):
        self.files, self.reason, self.asked = files, reason, []

    def package(self, lookup: Lookup) -> Official:
        self.asked.append(lookup)
        if self.files is None:
            return Official(lookup, reason=self.reason)
        return Official(lookup, dict(self.files), "https://archive.test/x.deb", "FPR")


def check(before, after, verifier):
    baseline, current = snap(**before), snap(**after)
    return official.verify_pam(current, baseline, compare(baseline, current), verifier, "b0")


def test_a_changed_module_matched_against_its_package_held_to_the_baseline():
    verifier = FakeVerifier({UNIX: {"sha256": BAD}})
    result = check(BEFORE, AFTER, verifier)["files"][UNIX]
    assert result["outcome"] == "matched"
    assert result["version"] == "1.5.3-5ubuntu5.7" and result["baseline_version"] == (
        "1.5.3-5ubuntu5.6"
    )
    assert result["older_than_baseline"] is False
    # Asked with the baseline's system and release, the package's own architecture.
    assert verifier.asked == [
        Lookup("ubuntu", "24.04", "libpam-modules", "1.5.3-5ubuntu5.7", "amd64")
    ]


def test_differs_and_not_found():
    assert (
        check(BEFORE, AFTER, FakeVerifier({UNIX: {"sha256": GOOD}}))["files"][UNIX]["outcome"]
        == "differs"
    )
    result = check(BEFORE, AFTER, FakeVerifier(None, "isn't in Ubuntu's archive"))["files"][UNIX]
    assert result["outcome"] == "not_checked" and "archive" in result["reason"]


def test_a_downgrade_is_marked():
    after = dict(AFTER, packages={"libpam-modules amd64": {"version": "1.5.3-5ubuntu5.1"}})
    result = check(BEFORE, after, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert result["older_than_baseline"] is True


@pytest.mark.parametrize(
    ("after", "before", "reason"),
    [
        # A 24.04 server claiming 22.04, to use 22.04's genuine module (#210's review).
        (dict(AFTER, os=("ubuntu", "22.04")), BEFORE, "isn't the baseline's"),
        (dict(AFTER, os=None), BEFORE, "doesn't say which system"),
        (dict(AFTER, owners={}), BEFORE, "no owning package"),
        (dict(AFTER, owners={UNIX: owner(several=True)}), BEFORE, "more than one package"),
        # An owner swap: another package that ships a genuine file at that path.
        (dict(AFTER, owners={UNIX: owner("evil-pam")}), BEFORE, "isn't the baseline's"),
        (dict(AFTER, owners={UNIX: owner(arch="i386")}), BEFORE, "isn't the baseline's"),
        (dict(AFTER, packages_complete=False), BEFORE, "collected whole"),
        (dict(AFTER, packages={}), BEFORE, "exactly one installed version"),
        (dict(AFTER, os=("debian", "12")), dict(BEFORE, os=("debian", "12")), "isn't covered"),
    ],
)
def test_lookups_not_held_to_the_baseline_are_not_checked(after, before, reason):
    verifier = FakeVerifier({UNIX: {"sha256": BAD}})
    result = check(before, after, verifier)["files"][UNIX]
    assert result["outcome"] == "not_checked" and reason in result["reason"], result
    assert verifier.asked == []  # nothing downloaded for a claim that isn't held


def test_an_owner_without_an_architecture_is_the_one_package_of_that_name():
    owners = {UNIX: owner("libpam-tmpdir", arch=None)}
    before = dict(BEFORE, owners=owners, packages={"libpam-tmpdir amd64": {"version": "1"}})
    after = dict(AFTER, owners=owners, packages={"libpam-tmpdir amd64": {"version": "2"}})
    verifier = FakeVerifier({UNIX: {"sha256": BAD}})
    assert check(before, after, verifier)["files"][UNIX]["outcome"] == "matched"
    assert verifier.asked[0].arch == "amd64" and verifier.asked[0].version == "2"
    two = dict(after, packages={"libpam-tmpdir amd64": {"version": "2"}, "libpam-tmpdir i386": {}})
    assert check(before, two, FakeVerifier())["files"][UNIX]["outcome"] == "not_checked"


def test_a_baseline_without_owners_doesnt_block_the_check():
    # Baselines from before owners were recorded (0.1.3): the owner can't be compared, but
    # the version is still held to the baseline's package list, and the result says so.
    before = dict(BEFORE, owners=None)
    result = check(before, AFTER, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert result["outcome"] == "matched" and result["baseline_owner_unknown"] is True
    assert result["baseline_version"] == "1.5.3-5ubuntu5.6"
    assert result["older_than_baseline"] is False
    older = dict(AFTER, packages={"libpam-modules amd64": {"version": "1.5.3-5ubuntu5.1"}})
    assert (
        check(before, older, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX][
            "older_than_baseline"
        ]
        is True
    )
    # A module that was there, now claimed by a package that wasn't installed then.
    swapped = dict(
        AFTER, owners={UNIX: owner("evil-pam")}, packages={"evil-pam amd64": {"version": "1"}}
    )
    result = check(before, swapped, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert (
        result["outcome"] == "not_checked"
        and "wasn't installed at the baseline" in (result["reason"])
    )
    counted = official.summary(check(before, AFTER, FakeVerifier({UNIX: {"sha256": BAD}})))
    assert counted["baseline_owner_unknown"] == 1


def test_only_changed_or_new_regular_files_in_pam_module_directories():
    baseline = snap(**BEFORE)
    current = snap(
        **dict(
            AFTER,
            pam={
                UNIX: {"sha256": BAD, "size": 2},
                "/usr/lib/x86_64-linux-gnu/security/pam_new.so": {"sha256": GOOD},
                "/usr/lib/x86_64-linux-gnu/security/dir": {"type": "d"},
                "/etc/security/limits.conf": {"sha256": GOOD},
            },
        )
    )
    found = official.targets(current, compare(baseline, current))
    assert [(t.path, t.how) for t in found] == [
        ("/usr/lib/x86_64-linux-gnu/security/pam_new.so", "added"),
        (UNIX, "changed"),
    ]  # /etc/security/ isn't a module directory; the directory entry has no hash
    assert official.targets(current, None) == []
    same = snap(**dict(BEFORE, pam={UNIX: {"sha256": GOOD, "size": 1, "mtime": 9}}))
    assert official.targets(same, compare(baseline, same)) == []  # only the time changed


def test_merged_usr_paths_are_passed_on():
    after = dict(AFTER, merged={"/lib": "/usr/lib"})
    jammy = {"/lib/x86_64-linux-gnu/security/pam_unix.so": {"sha256": BAD}}
    assert check(BEFORE, after, FakeVerifier(jammy))["files"][UNIX]["outcome"] == "matched"


def test_stored_results_count_only_for_the_same_baseline_and_version():
    results = {"version": official.OFFICIAL_VERSION, "baseline_id": "b0", "files": {}}
    assert official.stored_is_current(results, "b0")
    assert not official.stored_is_current(results, "b1")
    assert not official.stored_is_current(dict(results, version=0), "b0")
    assert not official.stored_is_current(None, "b0")


def test_settings_build_the_verifier(tmp_path):
    from checker.evidence import Verify

    assert official.verifier_for(Verify(enabled=False), tmp_path) is None
    verifier = official.verifier_for(
        Verify(seconds_per_server=30, rocky="https://m.test/rocky/"), tmp_path
    )
    assert verifier.cache_dir == tmp_path / "cache" / "official-files"
    assert verifier.ubuntu.lists_dir == tmp_path / "cache" / "signed-lists"
    assert verifier.rpm.systems["rocky"]["current"] == "https://m.test/rocky/{major}"
    assert verifier.rpm.systems["rocky"]["keys"]["9"] == ("rocky-9",)


# --- With analyze: stored with the collection, used again ------------------------------------


def pam_records(sha256, version):
    return host_records(
        extra=[
            rec("pam", "module_file", path=UNIX, sha256=sha256, size=len(version), type="f"),
            rec("software", "package", manager="dpkg", name="libpam-modules", version=version,
                arch="amd64"),
            rec("system_files", "pam_module_owner", path=UNIX, package="libpam-modules",
                arch="amd64"),
            rec("system_files", "pam_owners_summary", complete=True, count=1),
        ]
    )  # fmt: skip


def test_analyze_checks_once_stores_the_results_and_a_rebuild_uses_them(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, pam_records(GOOD, "1.5.3-5ubuntu5.6"))
    analyze(store, "web01", identity, config.recipients)
    add_bundle(home, "b2", 10, pam_records(BAD, "1.5.3-5ubuntu5.7"))
    verifier = FakeVerifier({UNIX: {"sha256": BAD}})
    second = analyze(store, "web01", identity, config.recipients, verifier=verifier)
    assert second["official_files"]["counts"] == {"matched": 1}
    assert len(verifier.asked) == 1
    stored = load_official(store, store.bundle("b2"), identity)
    assert stored["files"][UNIX]["outcome"] == "matched" and stored["baseline_id"] == "b1"
    # Again, with no verifier at all (a report rebuilt): the stored results, nothing fetched.
    again = analyze(store, "web01", identity, config.recipients, "b2")
    assert again["official_files"]["counts"] == {"matched": 1}
    # With a verifier: still the stored results, not asked again.
    analyze(store, "web01", identity, config.recipients, "b2", verifier=verifier)
    assert len(verifier.asked) == 1


def test_analyze_says_when_changed_modules_werent_checked(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, pam_records(GOOD, "1.5.3-5ubuntu5.6"))
    analyze(store, "web01", identity, config.recipients)
    add_bundle(home, "b2", 10, pam_records(BAD, "1.5.3-5ubuntu5.7"))
    off = analyze(store, "web01", identity, config.recipients)
    assert off["official_files"] is None
    assert any("weren't checked" in n and "verify is off" in n for n in off["notes"])
    failed = analyze(
        store, "web01", identity, config.recipients, "b2",
        verifier=FakeVerifier(None, "couldn't download: no network"),
    )  # fmt: skip
    assert failed["official_files"]["counts"] == {"not_checked": 1}
    assert any("couldn't be checked" in n and "no network" in n for n in failed["notes"])


# --- From #213's reviews ---------------------------------------------------------------------


def test_a_changed_module_the_baseline_recorded_no_owner_for_is_not_checked():
    # The baseline listed its owners in full but not this one (unowned, or hand-installed).
    before = dict(BEFORE, owners={"/other": owner()})
    result = check(before, AFTER, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert "at the baseline" in result["reason"]
    # A baseline owner list cut short can't vouch: treated like a 0.1.3 baseline.
    cut = dict(BEFORE, owners={"/other": owner()}, owners_complete=False)
    result = check(cut, AFTER, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert result["outcome"] == "matched" and result["baseline_owner_unknown"] is True


def test_versions_unknown_at_the_baseline_are_said_to_be_unknown():
    incomplete = dict(BEFORE, packages_complete=False)
    result = check(incomplete, AFTER, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert result["baseline_version"] is None and result["older_than_baseline"] is None
    same = check(
        BEFORE, dict(AFTER, packages=BEFORE["packages"]), FakeVerifier({UNIX: {"sha256": BAD}})
    )
    assert same["files"][UNIX]["older_than_baseline"] is False  # the same version: not older


def test_an_added_module_from_a_package_new_since_the_baseline_says_so():
    new = "/usr/lib/x86_64-linux-gnu/security/pam_sss.so"
    after = dict(
        AFTER,
        pam={**AFTER["pam"], new: {"sha256": GOOD}},
        owners={**AFTER["owners"], new: owner("libpam-sss")},
        packages={**AFTER["packages"], "libpam-sss amd64": {"version": "2.9"}},
    )
    result = check(BEFORE, after, FakeVerifier({new: {"sha256": GOOD}}))["files"][new]
    assert result["outcome"] == "matched" and result["new_package"] is True
    assert result["older_than_baseline"] is None


def test_rocky_minor_releases_are_the_same_release_ubuntu_s_are_not():
    def rocky(release, version):
        return dict(
            os=("rocky", release),
            pam={"/usr/lib64/security/pam_unix.so": {"sha256": GOOD if version == "1" else BAD}},
            owners={"/usr/lib64/security/pam_unix.so": owner("pam", "x86_64")},
            packages={"pam x86_64": {"version": f"1.5.1-{version}.el9"}},
        )

    verifier = FakeVerifier({"/usr/lib64/security/pam_unix.so": {"sha256": BAD}})
    result = check(rocky("9.5", "1"), rocky("9.6", "2"), verifier)["files"]
    assert result["/usr/lib64/security/pam_unix.so"]["outcome"] == "matched"
    assert verifier.asked[0].release == "9.6"
    other = check(rocky("9.5", "1"), rocky("10.0", "2"), FakeVerifier())["files"]
    assert "isn't the baseline's" in other["/usr/lib64/security/pam_unix.so"]["reason"]


def test_the_package_s_architecture_and_duplicates_are_held():
    owners = {UNIX: owner("libpam-tmpdir", arch=None)}
    before = dict(BEFORE, owners=owners, packages={"libpam-tmpdir amd64": {"version": "1"}})
    after = dict(AFTER, owners=owners, packages={"libpam-tmpdir all": {"version": "2"}})
    result = check(before, after, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert "architecture isn't the baseline's" in result["reason"]
    twice = dict(AFTER, packages={"libpam-modules amd64": {"version": "2", "duplicate": True}})
    result = check(BEFORE, twice, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert "exactly one installed version" in result["reason"]


def test_odd_values_from_the_server_never_stop_the_step():
    result = check(BEFORE, dict(AFTER, merged=["/lib"]), FakeVerifier({UNIX: {"sha256": BAD}}))
    assert result["files"][UNIX]["outcome"] == "matched"

    class Broken:
        def package(self, lookup):
            raise RuntimeError("boom")

    result = check(BEFORE, AFTER, Broken())["files"][UNIX]
    assert result["outcome"] == "not_checked" and "RuntimeError" in result["reason"]
    assert result["sha256"] == BAD


def test_one_package_update_is_asked_about_once():
    paths = [f"/usr/lib/x86_64-linux-gnu/security/pam_{i}.so" for i in range(40)]
    before = dict(
        BEFORE, pam={p: {"sha256": GOOD} for p in paths}, owners={p: owner() for p in paths}
    )
    after = dict(AFTER, pam={p: {"sha256": BAD} for p in paths}, owners={p: owner() for p in paths})
    verifier = FakeVerifier({p: {"sha256": BAD} for p in paths})
    found = check(before, after, verifier)["files"]
    assert len(found) == 40 and len(verifier.asked) == 1


def test_failures_on_this_machine_s_side_are_marked_and_asked_again():
    class Offline(FakeVerifier):
        def package(self, lookup):
            self.asked.append(lookup)
            return Official(lookup, reason="couldn't download: no network", transient=True)

    results = check(BEFORE, AFTER, Offline())
    assert results["files"][UNIX]["transient"] is True
    assert official.stored_is_current(results, "b0")
    assert not official.stored_is_current(results, "b0", retrying=True)
    assert official.summary(results)["transient"] == 1
    assert official.unreachable({"official_files": official.summary(results)})
    matched = check(BEFORE, AFTER, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert not official.unreachable({"official_files": official.summary(matched)})
    assert not official.unreachable({"official_files": None}) and not official.unreachable(None)


def test_older_versions_can_be_turned_off(tmp_path):
    from checker.evidence import Verify

    verifier = official.verifier_for(Verify(older_versions=False), tmp_path)
    assert verifier.ubuntu.snapshot is None and verifier.ubuntu.launchpad is None
    assert verifier.rpm.vaults is False


def test_analyze_asks_again_after_a_failure_on_this_machine_s_side(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, pam_records(GOOD, "1.5.3-5ubuntu5.6"))
    analyze(store, "web01", identity, config.recipients)
    add_bundle(home, "b2", 10, pam_records(BAD, "1.5.3-5ubuntu5.7"))

    class Offline(FakeVerifier):
        def package(self, lookup):
            self.asked.append(lookup)
            return Official(lookup, reason="couldn't download: no network", transient=True)

    analyze(store, "web01", identity, config.recipients, verifier=Offline())
    good = FakeVerifier({UNIX: {"sha256": BAD}})
    again = analyze(store, "web01", identity, config.recipients, "b2", verifier=good)
    assert again["official_files"]["counts"] == {"matched": 1} and len(good.asked) == 1


def test_config_show_says_what_is_downloaded_and_from_where():
    from checker.evidence import Config, Verify
    from checker.settings import describe

    def line(**verify):
        config = Config(recipients=["age1x"], verify=Verify(**verify))
        return next(s for s in describe(config) if s.startswith("PAM modules"))

    assert "the distributions' own servers" in line() and "snapshot.ubuntu.com" in line()
    assert "your mirrors (https://m.test/u)" in line(ubuntu_archive="https://m.test/u")
    assert "aren't looked for" in line(older_versions=False)
    assert "not checked" in line(enabled=False)


# === V.5: pam.changes judged by the results ==================================================


def pam_findings(before, after, verifier=None, official_override=None, previous=None, raw=False):
    from checker.checks import Context, run_checks

    baseline, current = snap(**before), snap(**after)
    diff = compare(baseline, current)
    earlier = snap(**previous) if previous else None
    results = (
        official_override
        if official_override is not None
        else (
            official.verify_pam(current, baseline, diff, verifier, "b0", earlier)
            if verifier
            else None
        )
    )
    context = Context(
        host="web01", bundle_id="b2", events=[], snapshot=current, baseline_id="b0",
        since_baseline=diff, baseline_snapshot=baseline, official=results,
    )  # fmt: skip
    found, ran = run_checks(context)
    assert not [r for r in ran if r["status"].startswith("failed")], ran
    pam = [f for f in found if f.check == "pam.changes"]
    return (pam, results) if raw else pam


def titles(found):
    return sorted((f.band, f.title) for f in found)


def test_an_ordinary_update_is_one_low_finding():
    paths = [f"/usr/lib/x86_64-linux-gnu/security/pam_{i}.so" for i in range(46)]
    before = dict(
        BEFORE, pam={p: {"sha256": GOOD} for p in paths}, owners={p: owner() for p in paths}
    )
    after = dict(AFTER, pam={p: {"sha256": BAD} for p in paths}, owners={p: owner() for p in paths})
    found = pam_findings(before, after, FakeVerifier({p: {"sha256": BAD} for p in paths}))
    assert titles(found) == [("low", "PAM modules updated by Ubuntu's own packages")]
    assert found[0].variant == "official_update" and len(found[0].evidence) == 46
    assert "libpam-modules 1.5.3-5ubuntu5.6 -> 1.5.3-5ubuntu5.7" in found[0].summary
    # Without the results (verify off): 46 high findings, as before.
    unchecked = pam_findings(before, after)
    assert {f.band for f in unchecked} == {"high"} and len(unchecked) == 46


def test_genuine_files_that_aren_t_an_ordinary_update_are_medium():
    older = dict(AFTER, packages={"libpam-modules amd64": {"version": "1.5.3-5ubuntu5.1"}})
    found = pam_findings(BEFORE, older, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert titles(found) == [("medium", "PAM was moved back to an older Ubuntu package")]
    assert "older than the baseline's 1.5.3-5ubuntu5.6" in found[0].summary
    unknown = dict(BEFORE, packages_complete=False)
    found = pam_findings(unknown, AFTER, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert [f.variant for f in found] == ["version_unknown"] and found[0].band == "medium"
    new = "/usr/lib/x86_64-linux-gnu/security/pam_sss.so"
    added = dict(
        BEFORE,
        pam={**BEFORE["pam"], new: {"sha256": GOOD}},
        owners={**BEFORE["owners"], new: owner("libpam-sss")},
        packages={**BEFORE["packages"], "libpam-sss amd64": {"version": "2.9"}},
    )
    found = pam_findings(
        BEFORE, added, FakeVerifier({new: {"sha256": GOOD}, UNIX: {"sha256": GOOD}})
    )
    assert [(f.band, f.variant) for f in found] == [("medium", "new_package")]


def test_a_module_that_isn_t_the_package_s_file_is_high():
    found = pam_findings(BEFORE, AFTER, FakeVerifier({UNIX: {"sha256": GOOD}}))
    assert titles(found) == [
        ("high", "A PAM module differs from Ubuntu's package for the installed version")
    ]
    assert found[0].variant == "differs"


def test_what_couldn_t_be_checked_stays_high_and_says_why():
    found = pam_findings(BEFORE, AFTER, FakeVerifier(None, "isn't in Ubuntu's archive"))
    assert titles(found) == [("high", "A PAM module file changed")]
    assert "not checked against Ubuntu's package: isn't in Ubuntu's archive" in found[0].summary
    swapped = dict(AFTER, owners={UNIX: owner("evil-pam")})
    found = pam_findings(BEFORE, swapped, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert "owning package isn't the baseline's" in found[0].summary and found[0].band == "high"


def test_a_result_for_another_file_counts_for_nothing():
    results = check(BEFORE, AFTER, FakeVerifier({UNIX: {"sha256": BAD}}))
    results["files"][UNIX]["sha256"] = GOOD  # made for a file other than the one collected now
    found = pam_findings(BEFORE, AFTER, official_override=results)
    assert titles(found) == [("high", "A PAM module file changed")]


def test_the_assessment_of_a_routine_update_is_no_longer_a_break_in(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, pam_records(GOOD, "1.5.3-5ubuntu5.6"))
    analyze(store, "web01", identity, config.recipients)
    add_bundle(home, "b2", 10, pam_records(BAD, "1.5.3-5ubuntu5.7"))
    off = analyze(store, "web01", identity, config.recipients)
    assert [f["band"] for f in off["findings"] if f["check"] == "pam.changes"] == ["high"]
    on = analyze(
        store, "web01", identity, config.recipients, "b2",
        verifier=FakeVerifier({UNIX: {"sha256": BAD}}),
    )  # fmt: skip
    pam = [f for f in on["findings"] if f["check"] == "pam.changes"]
    assert [(f["band"], f["variant"]) for f in pam] == [("low", "official_update")]
    assert on["score"]["probability"] < off["score"]["probability"]


# --- From #214's reviews ----------------------------------------------------------------------


def test_going_back_below_a_version_seen_since_the_baseline_is_a_downgrade():
    # Baseline 5.6, last collection 5.9 (a fix), now the genuine 5.7 files: newer than the
    # baseline's, older than what was seen since.
    seen = dict(AFTER, packages={"libpam-modules amd64": {"version": "1.5.3-5ubuntu5.9"}})
    back = dict(AFTER, packages={"libpam-modules amd64": {"version": "1.5.3-5ubuntu5.7"}})
    found, results = pam_findings(
        BEFORE, back, FakeVerifier({UNIX: {"sha256": BAD}}), previous=seen, raw=True
    )
    assert [(f.band, f.variant) for f in found] == [("medium", "downgrade")]
    assert "older than 1.5.3-5ubuntu5.9, seen since the baseline" in found[0].summary
    # Carried on: the next collection's previous one is this one; its results remember 5.9.
    baseline, current = snap(**BEFORE), snap(**back)
    again = official.verify_pam(
        current, baseline, compare(baseline, current), FakeVerifier({UNIX: {"sha256": BAD}}),
        "b0", snap(**back), results,
    )  # fmt: skip
    assert again["files"][UNIX]["older_than_seen"] is True


def test_an_os_id_that_isn_t_text_can_t_stop_the_check():
    odd = dict(AFTER, os=None)
    for verifier in (None, FakeVerifier({UNIX: {"sha256": BAD}})):
        current = snap(**odd)
        current.sections["host"].items["os"] = {"id": ["ubuntu"], "version_id": "24.04"}
        from checker.checks import Context, run_checks

        baseline = snap(**BEFORE)
        context = Context(
            host="h", bundle_id="b2", events=[], snapshot=current, baseline_id="b0",
            since_baseline=compare(baseline, current), baseline_snapshot=baseline,
            official=None if verifier is None else {"files": {}},
        )  # fmt: skip
        found, ran = run_checks(context)
        assert not [r for r in ran if r["status"].startswith("failed")]
        assert any(f.check == "pam.changes" and f.band == "high" for f in found)


def test_the_update_s_finding_joins_no_group_in_scoring():
    from checker.scoring import score

    def finding(check, band, entities, variant=None):
        return {"check": check, "band": band, "category": "compromise indicator",
                "entities": entities, "variant": variant, "title": check}  # fmt: skip

    two = [
        finding("package.changed", "high", ["path:/a"]),
        finding("files.privileged", "high", ["path:/b"]),
    ]
    joined = [*two, finding("pam.changes", "low", ["path:/a", "path:/b"], "official_update")]
    assert score(joined)["probability"] >= score(two)["probability"]


def test_a_whitelist_rule_must_name_differs_to_cover_it():
    from checker.whitelist import Match, matches

    differs = {"check": "pam.changes", "variant": "differs", "entities": [f"path:{UNIX}"]}
    assert not matches(Match(check="pam.changes", path=UNIX), differs)
    assert matches(Match(check="pam.changes", variant="differs", path=UNIX), differs)
    changed = dict(differs, variant="changed")
    assert matches(Match(check="pam.changes", path=UNIX), changed)
    moved = dict(differs, variant="owner_changed")  # #217: how a swap would be hidden
    assert not matches(Match(check="pam.changes", path=UNIX), moved)


def test_a_genuine_file_whose_mode_or_owner_changed_stays_high():
    after = dict(AFTER, pam={UNIX: {"sha256": BAD, "size": 2, "mode": "0666", "uid": 33}})
    found = pam_findings(BEFORE, after, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert [(f.band, f.variant) for f in found] == [("high", "changed")]
    assert "its content is Ubuntu's, but it is writable by others than root, uid 33" in (
        found[0].summary
    )


def test_new_package_only_when_the_baseline_s_list_shows_it_wasn_t_there():
    new = "/usr/lib/x86_64-linux-gnu/security/pam_extra.so"
    added = dict(
        AFTER, pam={**AFTER["pam"], new: {"sha256": GOOD}},
        owners={**AFTER["owners"], new: owner("libpam-extra")},
        packages={**AFTER["packages"], "libpam-extra amd64": {"version": "1"}},
    )  # fmt: skip
    incomplete = dict(BEFORE, packages_complete=False)
    found = pam_findings(
        incomplete, added, FakeVerifier({new: {"sha256": GOOD}, UNIX: {"sha256": BAD}})
    )
    assert {f.variant for f in found} == {"version_unknown"}


def test_a_mix_is_reported_as_a_mix():
    other = "/usr/lib/x86_64-linux-gnu/security/pam_permit.so"
    before = dict(BEFORE, pam={UNIX: {"sha256": GOOD}, other: {"sha256": GOOD}},
                  owners={UNIX: owner(), other: owner()})  # fmt: skip
    after = dict(AFTER, pam={UNIX: {"sha256": BAD}, other: {"sha256": BAD}},
                 owners={UNIX: owner(), other: owner()})  # fmt: skip
    found = pam_findings(
        before, after, FakeVerifier({UNIX: {"sha256": BAD}, other: {"sha256": GOOD}})
    )
    assert titles(found) == [
        ("high", "A PAM module differs from Ubuntu's package for the installed version"),
        ("low", "PAM modules updated by Ubuntu's own packages"),
    ]


def test_an_added_file_from_a_package_that_was_there_is_part_of_the_update():
    new = "/usr/lib/x86_64-linux-gnu/security/pam_new.so"
    after = dict(AFTER, pam={**AFTER["pam"], new: {"sha256": GOOD}},
                 owners={**AFTER["owners"], new: owner()})  # fmt: skip
    found = pam_findings(
        BEFORE, after, FakeVerifier({UNIX: {"sha256": BAD}, new: {"sha256": GOOD}})
    )
    assert titles(found) == [("low", "PAM modules updated by Ubuntu's own packages")]
    assert len(found[0].evidence) == 2


def test_the_same_version_with_its_files_replaced_says_so():
    same = dict(AFTER, packages=BEFORE["packages"])
    found = pam_findings(BEFORE, same, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert "1.5.3-5ubuntu5.6 (the same version, its files replaced)" in found[0].summary


def test_reasons_say_why_a_module_wasn_t_checked():
    found = pam_findings(BEFORE, AFTER, FakeVerifier({UNIX: {"link": "pam_x.so"}}))
    assert "its package has a link there, not a file" in found[0].summary
    found = pam_findings(BEFORE, AFTER, FakeVerifier({"/elsewhere": {"sha256": BAD}}))
    assert "its package has no such file" in found[0].summary
    results = check(BEFORE, AFTER, FakeVerifier({UNIX: {"sha256": BAD}}))
    results["files"][UNIX]["sha256"] = GOOD
    found = pam_findings(BEFORE, AFTER, official_override=results)
    assert "the result was for another copy of the file" in found[0].summary
    new = "/usr/lib/x86_64-linux-gnu/security/pam_new.so"
    added = dict(AFTER, pam={**AFTER["pam"], new: {"sha256": GOOD}},
                 owners={**AFTER["owners"], new: owner("evil")})  # fmt: skip
    found = pam_findings(BEFORE, added, FakeVerifier({UNIX: {"sha256": BAD}}))
    new_one = next(f for f in found if new in f.summary)
    assert new_one.variant == "added" and "exactly one installed version" in new_one.summary


def test_rocky_and_alma_name_themselves():
    def rocky(system, version, digest):
        return dict(
            os=(system, "9.6"),
            pam={"/usr/lib64/security/pam_unix.so": {"sha256": digest}},
            owners={"/usr/lib64/security/pam_unix.so": owner("pam", "x86_64")},
            packages={"pam x86_64": {"version": version}},
        )

    for system, name in (("rocky", "Rocky Linux"), ("almalinux", "AlmaLinux")):
        found = pam_findings(
            rocky(system, "1.5.1-1.el9", GOOD), rocky(system, "1.5.1-2.el9", BAD),
            FakeVerifier({"/usr/lib64/security/pam_unix.so": {"sha256": BAD}}),
        )  # fmt: skip
        assert titles(found) == [("low", f"PAM modules updated by {name}'s own packages")]


def test_a_run_past_an_unreachable_host_still_answers_from_the_cache(tmp_path):
    from checker.evidence import Verify

    cached = official.verifier_for(Verify(), tmp_path, cached_only=True)
    result = cached.package(Lookup("rocky", "9", "pam", "1.5.1-1.el9", "x86_64"))
    assert result.transient and "out of reach this run" in result.reason


# --- From V.6's proof on real servers ---------------------------------------------------------


def test_a_re_created_link_is_checked_by_its_target():
    # Rocky: pam_unix_acct.so -> pam_unix.so, re-created by every pam update.
    link = "/usr/lib/x86_64-linux-gnu/security/pam_unix_acct.so"
    before = dict(BEFORE, pam={**BEFORE["pam"], link: {"type": "l", "link_target": "pam_unix.so",
                  "inode": 1}}, owners={**BEFORE["owners"], link: owner()})  # fmt: skip
    after = dict(AFTER, pam={**AFTER["pam"], link: {"type": "l", "link_target": "pam_unix.so",
                 "inode": 2}}, owners={**AFTER["owners"], link: owner()})  # fmt: skip
    package = {UNIX: {"sha256": BAD}, link: {"link": "pam_unix.so"}}
    found = pam_findings(before, after, FakeVerifier(package))
    assert titles(found) == [("low", "PAM modules updated by Ubuntu's own packages")]
    assert len(found[0].evidence) == 2
    # Pointed elsewhere (at pam_permit.so): not the package's link.
    moved = dict(after, pam={**after["pam"], link: {"type": "l", "link_target": "pam_permit.so",
                 "inode": 2}})  # fmt: skip
    found = pam_findings(before, moved, FakeVerifier(package))
    assert ("high", "A PAM module differs from Ubuntu's package for the installed version") in (
        titles(found)
    )


def test_an_added_file_s_own_mode_and_owner_aren_t_changes():
    # Ubuntu: pam_userdb.so arrives with an update; its record has mode and owner fields.
    new = "/usr/lib/x86_64-linux-gnu/security/pam_userdb.so"
    after = dict(
        AFTER,
        pam={**AFTER["pam"], new: {"sha256": GOOD, "mode": "0644", "uid": 0, "gid": 0}},
        owners={**AFTER["owners"], new: owner()},
    )
    found = pam_findings(
        BEFORE, after, FakeVerifier({UNIX: {"sha256": BAD}, new: {"sha256": GOOD}})
    )
    assert titles(found) == [("low", "PAM modules updated by Ubuntu's own packages")]


# --- From #215's reviews: dangerous modes and owners -----------------------------------------


def test_an_added_module_anyone_can_write_or_not_root_s_is_high():
    new = "/usr/lib/x86_64-linux-gnu/security/pam_userdb.so"
    for bad in ({"mode": "0666"}, {"mode": "4755"}, {"uid": 1000}, {"gid": 1000}):
        item = {"sha256": GOOD, "mode": "0644", "uid": 0, "gid": 0, **bad}
        after = dict(
            AFTER, pam={**AFTER["pam"], new: item}, owners={**AFTER["owners"], new: owner()}
        )
        found = pam_findings(
            BEFORE, after, FakeVerifier({UNIX: {"sha256": BAD}, new: {"sha256": GOOD}})
        )
        flagged = [f for f in found if new in f.summary]
        assert [(f.band, f.variant) for f in flagged] == [("high", "added")], bad


def test_a_mode_or_owner_change_alone_is_high_when_it_leaves_the_module_dangerous():
    same = {"sha256": GOOD, "size": 1}
    before = dict(BEFORE, pam={UNIX: dict(same, mode="0644", uid=0)})
    opened = dict(AFTER, pam={UNIX: dict(same, mode="0666", uid=0)}, packages=BEFORE["packages"])
    found = pam_findings(before, opened, FakeVerifier({UNIX: {"sha256": GOOD}}))
    assert [(f.band, f.variant) for f in found] == [("high", "changed")]
    assert "writable by others than root" in found[0].summary
    harmless = dict(opened, pam={UNIX: dict(same, mode="0755", uid=0)})
    assert pam_findings(before, harmless, FakeVerifier({UNIX: {"sha256": GOOD}})) == []


def test_a_harmless_mode_change_with_an_update_is_still_the_update():
    before = dict(BEFORE, pam={UNIX: {"sha256": GOOD, "size": 1, "mode": "0644", "uid": 0}})
    after = dict(AFTER, pam={UNIX: {"sha256": BAD, "size": 2, "mode": "0755", "uid": 0}})
    found = pam_findings(before, after, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert titles(found) == [("low", "PAM modules updated by Ubuntu's own packages")]


# === V.7: every module, not only changed ones ================================================


OTHER = "/usr/lib/x86_64-linux-gnu/security/pam_permit.so"


def test_unchanged_modules_are_checked_and_the_genuine_ones_say_nothing():
    before = dict(BEFORE, pam={**BEFORE["pam"], OTHER: {"sha256": GOOD}},
                  owners={**BEFORE["owners"], OTHER: owner()})  # fmt: skip
    after = dict(AFTER, pam={**AFTER["pam"], OTHER: {"sha256": GOOD}},
                 owners={**AFTER["owners"], OTHER: owner()})  # fmt: skip
    verifier = FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}})
    found, results = pam_findings(before, after, verifier, raw=True)
    assert results["files"][OTHER]["how"] == "unchanged"
    assert results["files"][OTHER]["outcome"] == "matched"
    assert titles(found) == [("low", "PAM modules updated by Ubuntu's own packages")]
    assert len(verifier.asked) == 1  # one package version, however many modules
    counted = official.summary(results)
    assert counted["counts"] == {"matched": 1} and counted["unchanged"] == {"matched": 1}


def test_a_module_swapped_before_the_baseline_is_high():
    # pam_permit.so's genuine content is GOOD; the server has had BAD there since before the
    # baseline, so nothing changed and only the package can show it.
    trojan = {"sha256": BAD}
    before = dict(BEFORE, pam={**BEFORE["pam"], OTHER: trojan},
                  owners={**BEFORE["owners"], OTHER: owner()})  # fmt: skip
    after = dict(AFTER, pam={**AFTER["pam"], OTHER: trojan},
                 owners={**AFTER["owners"], OTHER: owner()})  # fmt: skip
    found = pam_findings(
        before, after, FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}})
    )
    swapped = [f for f in found if OTHER in f.summary]
    assert [(f.band, f.variant) for f in swapped] == [("high", "differs")]
    assert "unchanged since the baseline" in swapped[0].summary
    assert swapped[0].evidence == [{"item": ["pam", OTHER]}]


def test_the_first_collection_is_checked_against_itself():
    from checker.checks import Context, run_checks

    current = snap(**dict(BEFORE, pam={UNIX: {"sha256": BAD}}))
    results = official.verify_pam(current, None, None, FakeVerifier({UNIX: {"sha256": GOOD}}), "b1")
    assert results["files"][UNIX]["how"] == "unchanged"
    context = Context(host="h", bundle_id="b1", events=[], snapshot=current, baseline_id="b1",
                      official=results)  # fmt: skip
    found, _ = run_checks(context)
    pam = [f for f in found if f.check == "pam.changes"]
    assert [(f.band, f.variant) for f in pam] == [("high", "differs")]
    assert "found at the first check, before any baseline" in pam[0].summary
    genuine = official.verify_pam(current, None, None, FakeVerifier({UNIX: {"sha256": BAD}}), "b1")
    context = Context(host="h", bundle_id="b1", events=[], snapshot=current, baseline_id="b1",
                      official=genuine)  # fmt: skip
    assert [f for f in run_checks(context)[0] if f.check == "pam.changes"] == []


def test_an_unchanged_module_that_can_t_be_checked_says_nothing():
    before = dict(BEFORE, pam={**BEFORE["pam"], OTHER: {"sha256": BAD}},
                  owners={**BEFORE["owners"], OTHER: owner()})  # fmt: skip
    after = dict(AFTER, pam={**AFTER["pam"], OTHER: {"sha256": BAD}},
                 owners={**AFTER["owners"], OTHER: owner()})  # fmt: skip
    found = pam_findings(before, after, FakeVerifier(None, "isn't in Ubuntu's archive"))
    assert not [f for f in found if OTHER in f.summary]


def test_analyze_catches_a_swapped_module_at_the_first_collection(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, pam_records(BAD, "1.5.3-5ubuntu5.6"))
    first = analyze(store, "web01", identity, config.recipients,
                    verifier=FakeVerifier({UNIX: {"sha256": GOOD}}))  # fmt: skip
    pam = [f for f in first["findings"] if f["check"] == "pam.changes"]
    assert [(f["band"], f["variant"]) for f in pam] == [("high", "differs")]
    assert first["official_files"]["unchanged"] == {"differs": 1}
    assert not any("weren't checked" in n or "couldn't be checked" in n for n in first["notes"])


# --- From #216's reviews ----------------------------------------------------------------------


def test_cache_hits_don_t_hide_servers_out_of_reach():
    summary = {"counts": {"not_checked": 46}, "unchanged": {"matched": 5}, "transient": 46,
               "downloaded": 0}  # fmt: skip
    assert official.unreachable({"official_files": summary})
    assert not official.unreachable({"official_files": dict(summary, downloaded=1)})

    class Cached(FakeVerifier):
        def package(self, lookup):
            found = super().package(lookup)
            found.cached = True
            return found

    results = check(BEFORE, AFTER, Cached({UNIX: {"sha256": BAD}}))
    assert results["files"][UNIX]["cached"] is True
    assert official.summary(results)["downloaded"] == 0


def test_a_swapped_module_whose_mode_changed_is_reported_once():
    trojan = {"sha256": BAD, "mode": "0644", "uid": 0}
    before = dict(BEFORE, pam={**BEFORE["pam"], OTHER: trojan},
                  owners={**BEFORE["owners"], OTHER: owner()})  # fmt: skip
    after = dict(AFTER, pam={**AFTER["pam"], OTHER: dict(trojan, mode="0666")},
                 owners={**AFTER["owners"], OTHER: owner()})  # fmt: skip
    found = pam_findings(
        before, after, FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}})
    )
    assert len([f for f in found if OTHER in f.summary]) == 1


def test_a_rebuilt_report_keeps_results_from_an_earlier_version():
    older = {"version": 2, "baseline_id": "b0", "files": {}}
    assert official.stored_is_current(older, "b0")  # no verifier: kept
    assert not official.stored_is_current(older, "b0", retrying=True)  # with one: checked again
    assert not official.stored_is_current(dict(older, version=1), "b0")


def test_the_baseline_itself_isn_t_called_a_first_check():
    from checker.checks import Context, run_checks

    current = snap(**dict(BEFORE, pam={UNIX: {"sha256": BAD}}))
    results = official.verify_pam(current, None, None, FakeVerifier({UNIX: {"sha256": GOOD}}), "b1")
    context = Context(host="h", bundle_id="b1", events=[], snapshot=current, baseline_id="b1",
                      official=results, no_baseline="this bundle is the baseline")  # fmt: skip
    pam = [f for f in run_checks(context)[0] if f.check == "pam.changes"]
    assert "found without a comparison with the baseline" in pam[0].summary


# --- #216, John's decision: what the package says against the server, and coverage ----------


def test_an_unchanged_module_its_package_doesn_t_ship_or_ships_as_a_link_is_high():
    # The trojan's dpkg list entry moved to a package that doesn't ship it; or a regular file
    # where the package (Rocky) has its link.
    for package_files, says in (
        ({UNIX: {"sha256": BAD}}, "has no such file"),
        ({UNIX: {"sha256": BAD}, OTHER: {"link": "pam_unix.so"}}, "has a link there, not a file"),
    ):
        before = dict(BEFORE, pam={**BEFORE["pam"], OTHER: {"sha256": BAD}},
                      owners={**BEFORE["owners"], OTHER: owner()})  # fmt: skip
        after = dict(AFTER, pam={**AFTER["pam"], OTHER: {"sha256": BAD}},
                     owners={**AFTER["owners"], OTHER: owner()})  # fmt: skip
        found = [
            f
            for f in pam_findings(before, after, FakeVerifier(package_files))
            if OTHER in f.summary
        ]
        assert [(f.band, f.variant) for f in found] == [("high", "differs")], says
        assert says in found[0].summary


def test_a_ghost_file_isn_t_a_file_the_package_lacks():
    before = dict(BEFORE, pam={**BEFORE["pam"], OTHER: {"sha256": BAD}},
                  owners={**BEFORE["owners"], OTHER: owner()})  # fmt: skip
    after = dict(AFTER, pam={**AFTER["pam"], OTHER: {"sha256": BAD}},
                 owners={**AFTER["owners"], OTHER: owner()})  # fmt: skip
    found = pam_findings(
        before, after, FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"ghost": True}})
    )
    assert not [f for f in found if OTHER in f.summary]


def test_unchanged_modules_that_can_t_be_checked_are_a_coverage_note(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, pam_records(GOOD, "1.5.3-5ubuntu5.6"))
    first = analyze(store, "web01", identity, config.recipients,
                    verifier=FakeVerifier(None, "isn't in Ubuntu's archive"))  # fmt: skip
    assert not [f for f in first["findings"] if f["check"] == "pam.changes"]
    assert any(
        "1 PAM module file(s) couldn't be checked" in n and "swapped before the first check" in n
        and "isn't in Ubuntu's archive" in n
        for n in first["notes"]
    )  # fmt: skip


# --- #217: an owner change on an unchanged module ---------------------------------------------


def owner_swap(content, now, packages=None):
    """pam_permit.so unchanged since the baseline (`content`), its owner by the
    package records `now` (None: no owner recorded)."""
    before = dict(BEFORE, pam={**BEFORE["pam"], OTHER: {"sha256": content}},
                  owners={**BEFORE["owners"], OTHER: owner()})  # fmt: skip
    owners = {**AFTER["owners"]}
    if now is not None:
        owners[OTHER] = now
    after = dict(AFTER, pam={**AFTER["pam"], OTHER: {"sha256": content}}, owners=owners)
    if packages is not None:
        after["packages"] = packages
    return before, after


def test_an_owner_swap_doesn_t_hide_a_module_swapped_before_the_baseline():
    # The trojan (BAD) was there at the baseline; its dpkg list entry then moved to another
    # package, so it isn't held to libpam-modules' file. It is, as the baseline's.
    before, after = owner_swap(BAD, owner("evil-pam"))
    verifier = FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}})
    found, results = pam_findings(before, after, verifier, raw=True)
    result = results["files"][OTHER]
    assert result["outcome"] == "differs" and result["package"] == "libpam-modules"
    assert result["owner_changed"] == {
        "baseline": {"package": "libpam-modules", "arch": "amd64"},
        "now": {"package": "evil-pam", "arch": "amd64"},
    }
    assert all(lookup.package == "libpam-modules" for lookup in verifier.asked)
    mine = [f for f in found if OTHER in f.summary]
    assert [(f.band, f.variant) for f in mine] == [("high", "differs")]  # one finding, not two
    assert "name evil-pam:amd64 as its owner, not libpam-modules:amd64" in mine[0].summary


@pytest.mark.parametrize(
    ("now", "words"),
    [
        (owner("evil-pam"), "evil-pam:amd64"),
        (owner("libpam-modules", arch="i386"), "libpam-modules:i386"),
        (owner(several=True), "more than one package"),
        (None, "no package"),
    ],
)
def test_an_owner_change_on_a_genuine_module_is_medium(now, words):
    before, after = owner_swap(GOOD, now)
    found = pam_findings(
        before, after, FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}})
    )
    mine = [f for f in found if OTHER in f.summary]
    if now is None:  # no package lists it, in a complete list: that is high on its own
        assert ("high", "A PAM module that no package installed") in titles(mine)
        mine = [f for f in mine if f.variant == "owner_changed"]
    assert [(f.band, f.variant) for f in mine] == [("medium", "owner_changed")]
    assert mine[0].title == "A PAM module's owning package changed, its content didn't"
    assert f"name {words} as its owner" in mine[0].summary
    assert "it is the file in the baseline's owner libpam-modules" in mine[0].summary
    assert mine[0].new  # no earlier check had seen the owner change


def test_an_owner_change_that_can_t_be_checked_is_medium_and_says_why():
    # The baseline's owner was removed from the package list along with the swap.
    before, after = owner_swap(
        BAD, owner("evil-pam"), packages={"evil-pam amd64": {"version": "1.0"}}
    )
    found = pam_findings(before, after, FakeVerifier({OTHER: {"sha256": GOOD}}))
    mine = [f for f in found if OTHER in f.summary]
    assert [(f.band, f.variant) for f in mine] == [("medium", "owner_changed")]
    assert "exactly one installed version of the baseline's owning package" in mine[0].summary


def test_an_owner_change_after_the_module_was_reported_is_high():
    before, after = owner_swap(
        BAD, owner("evil-pam"), packages={"evil-pam amd64": {"version": "1.0"}}
    )
    baseline, current = snap(**before), snap(**after)
    diff = compare(baseline, current)
    verifier = FakeVerifier({OTHER: {"sha256": GOOD}})
    for earlier, high in (
        ({"outcome": "differs", "sha256": BAD}, True),
        ({"outcome": "absent", "sha256": BAD}, True),
        ({"outcome": "differs", "sha256": GOOD}, False),  # another file was reported
        ({"outcome": "matched", "sha256": BAD}, False),
    ):
        results = official.verify_pam(current, baseline, diff, verifier, "b0",
                                      reported={"files": {OTHER: earlier}})  # fmt: skip
        assert results["files"][OTHER].get("reported_before", False) is high
        mine = [f for f in pam_findings(before, after, official_override=results)
                if OTHER in f.summary]  # fmt: skip
        assert [(f.band, f.variant) for f in mine] == [
            ("high" if high else "medium", "owner_changed")
        ]
        assert ("an earlier check found it wasn't the file" in mine[0].summary) is high


def test_no_owner_change_no_mark_and_a_changed_module_stays_as_it_was():
    before, after = owner_swap(GOOD, owner())
    results = pam_findings(
        before, after, FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}}), raw=True
    )[1]
    assert "owner_changed" not in results["files"][OTHER]
    # Changed content with another owner: not held to the baseline's owner, the high change.
    swapped = dict(AFTER, owners={UNIX: owner("evil-pam")})
    results = check(BEFORE, swapped, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]
    assert "owner_changed" not in results and "isn't the baseline's" in results["reason"]


def test_analyze_reports_an_owner_swap_after_the_baseline_s_own_report(home):
    # b1 (the baseline) shows the trojan; by b2 its owner record moved and the baseline's
    # package left the list, so nothing can be checked, but b1 had reported it.
    _, store, identity, config = home
    add_bundle(home, "b1", 0, pam_records(BAD, "1.5.3-5ubuntu5.6"))
    analyze(store, "web01", identity, config.recipients,
            verifier=FakeVerifier({UNIX: {"sha256": GOOD}}))  # fmt: skip
    swapped = host_records(
        extra=[
            rec("pam", "module_file", path=UNIX, sha256=BAD, size=len("1.5.3-5ubuntu5.6"),
                type="f"),
            rec("software", "package", manager="dpkg", name="evil-pam", version="1.0",
                arch="amd64"),
            rec("system_files", "pam_module_owner", path=UNIX, package="evil-pam", arch="amd64"),
            rec("system_files", "pam_owners_summary", complete=True, count=1),
        ]
    )  # fmt: skip
    add_bundle(home, "b2", 10, swapped)
    second = analyze(store, "web01", identity, config.recipients,
                     verifier=FakeVerifier({UNIX: {"sha256": GOOD}}))  # fmt: skip
    pam = [f for f in second["findings"] if f["check"] == "pam.changes"]
    assert [(f["band"], f["variant"]) for f in pam] == [("high", "owner_changed")]


# --- #217's reviews ---------------------------------------------------------------------------


@pytest.mark.parametrize("owners_complete", [False, None])
def test_an_owner_list_cut_short_or_not_collected_isn_t_an_owner_change(owners_complete):
    before, after = owner_swap(GOOD, None)
    current = snap(**after, owners_complete=bool(owners_complete))
    if owners_complete is None:
        current.live.pop("pam_owners")
    baseline = snap(**before)
    results = official.verify_pam(current, baseline, compare(baseline, current),
                                  FakeVerifier({OTHER: {"sha256": GOOD}}), "b0")  # fmt: skip
    result = results["files"][OTHER]
    assert "owner_changed" not in result and result["outcome"] == "not_checked"


def test_a_multi_arch_list_move_isn_t_an_owner_change():
    # dpkg's pkg.list became pkg:amd64.list: the owner gains an architecture, same package.
    before, after = owner_swap(GOOD, owner(arch=None))
    found, results = pam_findings(
        before, after, FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}}), raw=True
    )
    assert "owner_changed" not in results["files"][OTHER]
    assert results["files"][OTHER]["outcome"] == "matched"
    assert not [f for f in found if OTHER in f.summary]
    # A changed module too: the same installed package, so held as the baseline's.
    after = dict(AFTER, owners={UNIX: owner(arch=None)})
    assert (
        check(BEFORE, after, FakeVerifier({UNIX: {"sha256": BAD}}))["files"][UNIX]["outcome"]
        == "matched"
    )


REPORTED = {"outcome": "differs", "sha256": BAD}


@pytest.mark.parametrize(
    "edit",
    [
        # The owner record left alone; the package list made unusable instead, or the
        # release forged: each makes the module "not checked".
        lambda a: a.update(packages={}),
        lambda a: a.update(packages={"libpam-modules amd64": {"version": "9:not-in-archive"}}),
        lambda a: a.update(os=("ubuntu", "22.04")),
        lambda a: a.update(packages_complete=False),
    ],
)
def test_a_reported_module_made_unchecked_stays_high(edit):
    before, after = owner_swap(BAD, owner())
    edit(after)
    baseline, current = snap(**before), snap(**after)
    diff = compare(baseline, current)
    verifier = FakeVerifier(None, "isn't in Ubuntu's archive")
    results = official.verify_pam(current, baseline, diff, verifier, "b0",
                                  reported={"files": {OTHER: REPORTED}})  # fmt: skip
    result = results["files"][OTHER]
    assert result["outcome"] == "not_checked" and result["reported_before"] is True
    mine = [f for f in pam_findings(before, after, official_override=results)
            if OTHER in f.summary]  # fmt: skip
    assert [(f.band, f.variant, f.new) for f in mine] == [("high", "differs", True)]
    assert "an earlier check found it wasn't the file in Ubuntu's package" in mine[0].summary
    # Nor is it counted as an unchecked module in the coverage notes: it is a finding.
    assert not official.summary(results)["unchanged_not_checked"]
    # The next check keeps it high (no longer new), until the file itself changes.
    again = official.verify_pam(current, baseline, diff, verifier, "b0", reported=results)
    assert again["files"][OTHER]["reported_before"] is True
    mine = [f for f in pam_findings(before, after, official_override=again)
            if OTHER in f.summary]  # fmt: skip
    assert [(f.band, f.new) for f in mine] == [("high", False)]
    replaced = {"files": {OTHER: dict(again["files"][OTHER], sha256=GOOD)}}
    fresh = official.verify_pam(current, baseline, diff, verifier, "b0", reported=replaced)
    assert "reported_before" not in fresh["files"][OTHER]


def test_an_owner_change_stays_high_and_is_new_only_once():
    before, after = owner_swap(
        BAD, owner("evil-pam"), packages={"evil-pam amd64": {"version": "1.0"}}
    )
    baseline, current = snap(**before), snap(**after)
    diff = compare(baseline, current)
    verifier = FakeVerifier({OTHER: {"sha256": GOOD}})
    first = official.verify_pam(current, baseline, diff, verifier, "b0",
                                reported={"files": {OTHER: REPORTED}})  # fmt: skip
    second = official.verify_pam(current, baseline, diff, verifier, "b0", reported=first)
    for results, new in ((first, True), (second, False)):
        mine = [f for f in pam_findings(before, after, official_override=results)
                if OTHER in f.summary]  # fmt: skip
        assert [(f.band, f.variant, f.new) for f in mine] == [("high", "owner_changed", new)]


# --- #223's third review: the mark can't be shed --------------------------------------------


def run(before, after, reported, verifier=None):
    baseline, current = snap(**before), snap(**after)
    verifier = verifier or FakeVerifier(None, "isn't in Ubuntu's archive")
    return official.verify_pam(current, baseline, compare(baseline, current), verifier, "b0",
                               reported=reported)  # fmt: skip


def test_a_check_without_the_module_doesn_t_shed_the_mark():
    before, after = owner_swap(BAD, owner())
    hidden = dict(after, pam=AFTER["pam"])  # the module left out of one collection
    between = run(before, hidden, {"files": {OTHER: REPORTED}})
    assert OTHER not in between["files"] and between["mismatched"][OTHER] == [BAD]
    back = run(before, after, between)
    assert back["files"][OTHER]["reported_before"] is True


def test_a_check_between_where_it_changed_doesn_t_shed_the_mark():
    # One check with only its inode changed (a "changed" module, same hash), then back.
    before, after = owner_swap(BAD, owner())
    moved = dict(after, pam={**after["pam"], OTHER: {"sha256": BAD, "inode": 9}})
    between = run(before, moved, {"files": {OTHER: REPORTED}})
    result = between["files"][OTHER]
    assert result["how"] == "changed" and result["reported_before"] is True
    mine = [f for f in pam_findings(before, moved, official_override=between)
            if OTHER in f.summary]  # fmt: skip
    assert [(f.band, f.variant) for f in mine] == [("high", "differs")]
    assert run(before, after, between)["files"][OTHER]["reported_before"] is True


def test_a_match_for_that_very_file_clears_the_mark():
    before, after = owner_swap(BAD, owner())
    found = run(before, after, {"files": {OTHER: REPORTED}},
                FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": BAD}}))  # fmt: skip
    assert "reported_before" not in found["files"][OTHER] and OTHER not in found["mismatched"]
    # Another file at the path (GOOD) never clears the trojan's mark.
    genuine = run(before, owner_swap(GOOD, owner())[1], {"files": {OTHER: REPORTED}},
                  FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}}))  # fmt: skip
    assert genuine["mismatched"][OTHER] == [BAD]


def test_a_dangerous_mode_doesn_t_turn_an_owner_change_into_a_plain_change():
    before, after = owner_swap(GOOD, owner("evil-pam"))
    after["pam"] = {**after["pam"], OTHER: {"sha256": GOOD, "mode": "0666"}}
    found = pam_findings(
        before, after, FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}})
    )
    mine = [f for f in found if OTHER in f.summary]
    assert [(f.band, f.variant) for f in mine] == [("high", "owner_changed")]
    assert "writable by others than root" in mine[0].summary


def test_the_marks_stay_bounded():
    keys = [f"{i:064x}" for i in range(official.MAX_MISMATCHED_PER_PATH)]
    before, after = owner_swap(BAD, owner())
    found = run(before, after, {"files": {}, "mismatched": {OTHER: keys}},
                FakeVerifier({UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}}))  # fmt: skip
    assert len(found["mismatched"][OTHER]) == official.MAX_MISMATCHED_PER_PATH
    assert BAD in found["mismatched"][OTHER]


def test_analyze_looks_back_past_a_check_that_stored_no_results(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, pam_records(BAD, "1.5.3-5ubuntu5.6"))
    analyze(store, "web01", identity, config.recipients,
            verifier=FakeVerifier({UNIX: {"sha256": GOOD}}))  # fmt: skip
    add_bundle(home, "b2", 10, pam_records(BAD, "1.5.3-5ubuntu5.6"))
    analyze(store, "web01", identity, config.recipients)  # verify off: nothing stored
    assert load_official(store, store.bundle("b2"), identity) is None
    add_bundle(home, "b3", 20, pam_records(BAD, "9:forged"))
    third = analyze(store, "web01", identity, config.recipients,
                    verifier=FakeVerifier(None, "isn't in Ubuntu's archive"))  # fmt: skip
    pam = [f for f in third["findings"] if f["check"] == "pam.changes"]
    assert [(f["band"], f["variant"]) for f in pam] == [("high", "differs")]


# --- Owner records forged before the baseline ---------------------------------------------


def claims_owner(*claims):
    first = claims[0]
    return dict(owner(*first), several=True,
                claims=[{"package": p, "arch": a} for p, a in claims])  # fmt: skip


class ByPackage(FakeVerifier):
    """Each package's own files."""

    def __init__(self, by_package):
        super().__init__()
        self.by_package = by_package

    def package(self, lookup):
        self.asked.append(lookup)
        files = self.by_package.get(lookup.package)
        if files is None:
            return Official(lookup, reason="not in the archive")
        return Official(lookup, dict(files), "https://archive.test/x.deb", "FPR")


TWO = {"libpam-modules amd64": {"version": "1.5.3-5ubuntu5.6"}, "other amd64": {"version": "2"}}


def first_check(owners, verifier, packages=TWO, content=BAD):
    current = snap(pam={UNIX: {"sha256": content}}, owners=owners, packages=packages)
    return official.verify_pam(current, None, None, verifier, "b1")["files"][UNIX]


def test_a_module_several_packages_list_is_checked_against_each():
    owners = {UNIX: claims_owner(("other", "amd64"), ("libpam-modules", "amd64"))}
    genuine = ByPackage({"libpam-modules": {UNIX: {"sha256": BAD}}, "other": {}})
    result = first_check(owners, genuine)
    assert result["outcome"] == "matched" and result["package"] == "libpam-modules"
    # A trojan: the real owner ships another file, the made-up one none.
    trojan = ByPackage({"libpam-modules": {UNIX: {"sha256": GOOD}}, "other": {}})
    assert first_check(owners, trojan)["outcome"] == "differs"
    # The real owner ships another file, the other can't be looked up: still differs.
    local = ByPackage({"libpam-modules": {UNIX: {"sha256": GOOD}}})
    assert first_check(owners, local)["outcome"] == "differs"
    # No package ships it, as every one says: absent; one not answering: not checked.
    assert (
        first_check(owners, ByPackage({"libpam-modules": {}, "other": {}}))["outcome"] == "absent"
    )
    result = first_check(owners, ByPackage({"libpam-modules": {}}))
    assert (
        result["outcome"] == "not_checked" and "none of them could be checked" in result["reason"]
    )
    # An older collector sent one name only: not checked, as before.
    assert first_check({UNIX: owner(several=True)}, genuine)["outcome"] == "not_checked"


def test_several_owners_are_held_to_those_the_baseline_listed():
    # At the baseline libpam-modules alone; later a second package that "ships" the trojan.
    before = dict(BEFORE, pam={UNIX: {"sha256": BAD}})
    after = dict(BEFORE, pam={UNIX: {"sha256": BAD, "size": 9}},
                 owners={UNIX: claims_owner(("libpam-modules", "amd64"), ("other", "amd64"))},
                 packages=TWO)  # fmt: skip
    verifier = ByPackage(
        {"libpam-modules": {UNIX: {"sha256": GOOD}}, "other": {UNIX: {"sha256": BAD}}}
    )
    result = check(before, after, verifier)["files"][UNIX]
    assert result["outcome"] == "differs"
    assert [lookup.package for lookup in verifier.asked] == ["libpam-modules"]


def test_snapshot_keeps_the_claims_and_the_cut(tmp_path):
    records = host_records(
        extra=[
            rec("system_files", "pam_module_owner", path=UNIX, package="a", several=True,
                claims=[{"package": "a"}, {"package": "b", "arch": "amd64"}, "junk", {"x": 1}]
                + [{"package": f"p{i}"} for i in range(20)]),
            rec("system_files", "pam_owners_summary", complete=False, count=1, cut="limit"),
        ]
    )  # fmt: skip
    from test_snapshot import snapshot_of_records

    found = snapshot_of_records(records, tmp_path).live["pam_owners"]
    assert found["owners"][UNIX]["claims"][:2] == [
        {"package": "a", "arch": None}, {"package": "b", "arch": "amd64"}
    ]  # fmt: skip
    assert len(found["owners"][UNIX]["claims"]) <= 8 and found["cut"] == "limit"


def owner_findings(pam, owners, complete=True, unowned=None, cut=None):
    from checker.checks import Context, run_checks
    from checker.snapshot import Section

    current = snap(pam=pam, owners=owners, owners_complete=complete)
    if cut:
        current.live["pam_owners"]["cut"] = cut
    current.sections["unowned_executables"] = Section(dict(unowned or {}))
    context = Context(host="h", bundle_id="b1", events=[], snapshot=current, baseline_id="b1")
    return [f for f in run_checks(context)[0] if f.check == "pam.changes"]


def test_a_module_no_package_lists_is_high_whatever_the_unowned_scan_sent():
    pam = {UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}}
    found = owner_findings(pam, {UNIX: owner()})
    assert [(f.band, f.title, f.summary) for f in found] == [
        ("high", "A PAM module that no package installed", f"{OTHER}: no package lists it")
    ]
    # Can't say which modules no package lists; the incomplete list is said instead.
    assert [f.variant for f in owner_findings(pam, {UNIX: owner()}, complete=False)] == [
        "owners_unread"
    ]
    # Reported by the unowned scan: once, as before.
    found = owner_findings(pam, {UNIX: owner()}, unowned={OTHER: {}})
    assert len(found) == 1 and found[0].evidence == [{"item": ["unowned_executables", OTHER]}]


def test_an_owner_list_cut_at_its_limit_is_high():
    found = owner_findings({UNIX: {"sha256": BAD}}, {UNIX: owner()}, complete=False, cut="limit")
    assert [(f.band, f.variant) for f in found] == [("high", "owners_cut")]


def test_several_a_mismatch_is_asked_again_when_another_lookup_failed_here():
    owners = {UNIX: claims_owner(("libpam-modules", "amd64"), ("other", "amd64"))}

    class Down(ByPackage):
        def package(self, lookup):
            found = super().package(lookup)
            if lookup.package == "other":
                found.transient = True
            return found

    result = first_check(owners, Down({"libpam-modules": {UNIX: {"sha256": GOOD}}}))
    assert result["outcome"] == "differs" and result["transient"] is True


def test_an_unlisted_link_isn_t_reported_as_a_module_no_package_installed():
    pam = {UNIX: {"sha256": BAD}, OTHER: {"type": "l", "link_target": "/opt/agent/pam.so"}}
    assert owner_findings(pam, {UNIX: owner()}) == []


def test_owners_cut_needs_a_rule_that_names_it():
    from checker.whitelist import Match, matches

    cut = {"check": "pam.changes", "variant": "owners_cut", "entities": []}
    assert not matches(Match(check="pam.changes"), cut)


# --- #224's second round: what the records can't vouch for ---------------------------------


def unverified_findings(after_owner, verifier, packages=None):
    before, after = owner_swap(BAD, owner())
    after["owners"] = {**after["owners"], OTHER: after_owner}
    if packages is not None:
        after["packages"] = packages
    before["owners"] = {**before["owners"], OTHER: after_owner}
    found = pam_findings(before, after, verifier)
    return [f for f in found if OTHER in f.summary]


def test_a_module_credited_to_a_package_not_installed_is_medium():
    mine = unverified_findings(owner("ghost-pkg"), FakeVerifier({UNIX: {"sha256": BAD}}))
    assert [(f.band, f.variant) for f in mine] == [("medium", "owner_unverified")]
    assert "exactly one installed version" in mine[0].summary


def test_a_module_credited_to_a_package_not_in_the_distribution_is_medium():
    class Vendor(FakeVerifier):
        def package(self, lookup):
            if lookup.package == "duo-unix":
                return Official(lookup, reason="'duo-unix' isn't one of Ubuntu's packages",
                                unlisted="package")  # fmt: skip
            return super().package(lookup)

    packages = {**AFTER["packages"], "duo-unix amd64": {"version": "2.0.3"}}
    mine = unverified_findings(owner("duo-unix"), Vendor({UNIX: {"sha256": BAD}}), packages)
    assert [(f.band, f.variant) for f in mine] == [("medium", "owner_unverified")]
    # A lookup that failed on this side (no network) isn't one.
    mine = unverified_findings(owner(), FakeVerifier(None, "no network"))
    assert mine == []


def test_more_claimants_than_sent_is_high():
    claimed = dict(claims_owner(("a", "amd64"), ("b", "amd64")), claims_cut=True)
    mine = unverified_findings(claimed, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert [(f.band, f.variant) for f in mine] == [("high", "owner_unverified")]


def test_an_odd_owner_record_is_a_module_no_package_installed_even_when_incomplete():
    pam = {UNIX: {"sha256": BAD}, OTHER: {"sha256": GOOD}}
    owners = {UNIX: owner(), OTHER: {"package": None, "arch": None, "several": False, "odd": True}}
    found = [f for f in owner_findings(pam, owners, complete=False) if f.variant is None]
    assert [(f.band, f.summary) for f in found] == [
        ("high", f"{OTHER}: its package records name it only with names dpkg and rpm never make")
    ]


def test_records_that_couldn_t_be_read_are_medium():
    from checker.checks import Context, run_checks

    current = snap(pam={UNIX: {"sha256": BAD}}, owners={UNIX: owner()}, owners_complete=False)
    current.live["pam_owners"]["problems"] = ["a package header couldn't be read"]
    context = Context(host="h", bundle_id="b1", events=[], snapshot=current, baseline_id="b1")
    found = [f for f in run_checks(context)[0] if f.check == "pam.changes"]
    assert [(f.band, f.variant) for f in found] == [("medium", "owners_unread")]


def test_snapshot_keeps_odd_owners_and_problems(tmp_path):
    from test_snapshot import snapshot_of_records

    records = host_records(
        extra=[
            rec("system_files", "pam_module_owner", path=UNIX, odd_owner=True),
            rec("system_files", "pam_owners_summary", complete=False, count=1,
                problems=["a package list couldn't be read whole: x.list"]),
        ]
    )  # fmt: skip
    found = snapshot_of_records(records, tmp_path).live["pam_owners"]
    assert found["owners"][UNIX]["odd"] is True and found["problems"]


# --- #224's third round -----------------------------------------------------------------------


def test_one_real_name_left_of_several_is_the_owner():
    owners = {UNIX: dict(owner(), several=True, claims=[{"package": "libpam-modules",
                                                         "arch": "amd64"}])}  # fmt: skip
    assert first_check(owners, FakeVerifier({UNIX: {"sha256": GOOD}}))["outcome"] == "differs"


def test_leaving_a_baseline_s_several_owners_for_another_is_an_owner_change():
    several = claims_owner(("libpam-modules", "amd64"), ("other", "amd64"))
    before = dict(BEFORE, pam={UNIX: {"sha256": BAD}}, owners={UNIX: several}, packages=TWO)
    after = dict(before, owners={UNIX: owner("third")})
    verifier = ByPackage({"libpam-modules": {UNIX: {"sha256": GOOD}}, "other": {}})
    result = check(before, after, verifier)["files"][UNIX]
    assert result["owner_changed"]["now"] == {"package": "third", "arch": "amd64"}
    assert result["outcome"] == "differs"  # held to the baseline's packages
    # Still one of the baseline's: no change.
    kept = dict(before, owners={UNIX: owner("other")})
    assert "owner_changed" not in check(before, kept, verifier)["files"][UNIX]


def test_unverified_modules_are_one_finding_per_package_banded_by_kind():
    paths = [f"/usr/lib/x86_64-linux-gnu/security/pam_{i}.so" for i in range(7)]
    before = dict(BEFORE, pam={p: {"sha256": BAD} for p in paths},
                  owners={p: owner("vendor") for p in paths})  # fmt: skip
    after = dict(before)

    class Answers(FakeVerifier):
        def __init__(self, kind):
            super().__init__()
            self.kind = kind

        def package(self, lookup):
            return Official(lookup, reason="not there", unlisted=self.kind)

    with_vendor = dict(after, packages={"vendor amd64": {"version": "1"}})
    with_vendor_before = dict(before, packages=with_vendor["packages"])
    found = pam_findings(with_vendor_before, with_vendor, Answers("package"))
    assert [(f.band, f.variant, len(f.entities)) for f in found] == [
        ("medium", "owner_unverified", 7)
    ]
    assert "and 2 more" in found[0].summary
    found = pam_findings(with_vendor_before, with_vendor, Answers("version"))
    assert [(f.band, f.variant) for f in found] == [("low", "version_unverified")]
    # The system as a whole not covered (a subscription, say): nothing new.
    assert pam_findings(with_vendor_before, with_vendor, Answers("")) == []
    # Nor are they counted again in the coverage note.
    baseline, current = snap(**with_vendor_before), snap(**with_vendor)
    results = official.verify_pam(current, baseline, compare(baseline, current),
                                  Answers("package"), "b0")  # fmt: skip
    assert not official.summary(results)["unchanged_not_checked"]


def test_owners_unread_says_why_or_that_it_wasn_t_said():
    found = owner_findings({UNIX: {"sha256": BAD}}, {UNIX: owner()}, complete=False)
    assert "didn't say why" in found[0].summary


# --- #224's fourth round ----------------------------------------------------------------------


def test_several_owners_swapped_for_others_are_an_owner_change():
    several = claims_owner(("libpam-modules", "amd64"), ("other", "amd64"))
    before = dict(BEFORE, pam={UNIX: {"sha256": BAD}}, owners={UNIX: several}, packages=TWO)
    after = dict(before, owners={UNIX: claims_owner(("x", "amd64"), ("y", "amd64"))})
    verifier = ByPackage({"libpam-modules": {UNIX: {"sha256": GOOD}}, "other": {}})
    result = check(before, after, verifier)["files"][UNIX]
    assert result["owner_changed"]["now"] == "several" and result["outcome"] == "differs"
    # A baseline from a collector that sent one name for several: held to that name.
    old = dict(before, owners={UNIX: owner(several=True)})
    result = check(old, after, verifier)["files"][UNIX]
    assert result["owner_changed"] and result["outcome"] == "differs"


@pytest.mark.parametrize("version", ["x" * 300, "1.0 OR 1=1", "1.0/../.."])
def test_an_odd_version_is_never_asked_about_and_is_low(version):
    after = dict(AFTER, packages={"libpam-modules amd64": {"version": version}})
    before, current = snap(**BEFORE), snap(**dict(after, pam=BEFORE["pam"]))
    verifier = FakeVerifier({UNIX: {"sha256": GOOD}})
    result = official.verify_pam(current, before, compare(before, current), verifier, "b0")[
        "files"
    ][UNIX]
    assert result["unverified"] == "version" and verifier.asked == []


@pytest.mark.parametrize(
    ("machine", "arch", "path", "marked"),
    [
        ("aarch64", "arm64", UNIX, False),  # the server's own: the whole server isn't covered
        ("x86_64", "i386", "/usr/lib/i386-linux-gnu/security/pam_unix.so", False),  # multilib
        ("x86_64", "i686", "/usr/lib/security/pam_unix.so", False),
        ("x86_64", "arm64", UNIX, True),  # not this server's: a sign
        ("x86_64", "i686", "/usr/lib64/security/pam_unix.so", True),
    ],
)
def test_an_architecture_not_covered_counts_only_when_it_isn_t_the_server_s(
    machine, arch, path, marked
):
    current = snap()
    current.sections["host"].items["kernel"] = {"machine": machine}
    assert bool(official._unverified(current, path, arch, "arch")) is marked


def test_a_package_list_not_collected_whole_is_a_finding():
    from checker.checks import Context, run_checks

    cases = (
        (["software: timeout"], ["software: timeout"], "low"),  # as at the baseline: slow
        (["software: timeout"], [], "medium"),  # new: could be brought on
        (["dpkg status past the limit"], ["dpkg status past the limit"], "medium"),
    )
    for gaps, earlier, band in cases:
        current = snap(pam={UNIX: {"sha256": BAD}}, owners={UNIX: owner()},
                       packages_complete=False)  # fmt: skip
        current.sections["packages"].gaps[:] = gaps
        baseline = snap(pam={UNIX: {"sha256": BAD}}, owners={UNIX: owner()},
                        packages_complete=not earlier)  # fmt: skip
        baseline.sections["packages"].gaps[:] = earlier
        results = official.verify_pam(current, None, None, FakeVerifier(None), "b1")
        assert results["files"][UNIX]["reason"] == "the package list wasn't collected whole"
        context = Context(host="h", bundle_id="b2", events=[], snapshot=current,
                          baseline_id="b1", baseline_snapshot=baseline,
                          official=results)  # fmt: skip
        found = [f for f in run_checks(context)[0] if f.variant == "packages_unread"]
        assert [f.band for f in found] == [band]


def test_owners_unread_is_low_for_honest_gaps():
    found = owner_findings({UNIX: {"sha256": BAD}}, {UNIX: owner()}, complete=False)
    assert found[0].band == "medium"
    from checker.checks import Context, run_checks

    current = snap(pam={UNIX: {"sha256": BAD}}, owners={UNIX: owner()}, owners_complete=False)
    current.live["pam_owners"]["problems"] = [
        "the package records couldn't be read in the time allowed"
    ]
    for earlier, band in (([], "medium"), (list(current.live["pam_owners"]["problems"]), "low")):
        baseline = snap(pam={UNIX: {"sha256": BAD}}, owners={UNIX: owner()},
                        owners_complete=False)  # fmt: skip
        baseline.live["pam_owners"]["problems"] = earlier
        context = Context(host="h", bundle_id="b2", events=[], snapshot=current,
                          baseline_id="b1", baseline_snapshot=baseline)  # fmt: skip
        found = [f for f in run_checks(context)[0] if f.variant == "owners_unread"]
        assert [f.band for f in found] == [band]


# --- Unhashed files and names without .so ---------------------------------------------------


def test_a_file_in_a_pam_directory_without_a_hash_is_reported():
    big = "/usr/lib/x86_64-linux-gnu/security/pam_big.so"
    pam = {
        UNIX: {"sha256": BAD, "type": "-"},
        big: {"type": "-", "size": 9_000_000, "hash_skipped": "larger than 8388608 bytes"},
        OTHER: {"type": "-", "hash_skipped": "time limit"},
        "/usr/lib/x86_64-linux-gnu/security/pam_filter": {"type": "d"},
        "/usr/lib/x86_64-linux-gnu/security/pam_link.so": {"type": "l", "link_target": "x"},
    }
    owners = {UNIX: owner(), big: owner(), OTHER: owner()}
    found = [f for f in owner_findings(pam, owners) if f.variant == "unhashed"]
    assert [(f.band, f.summary) for f in found] == [
        ("high", f"{big}: larger than 8388608 bytes (9000000 bytes)"),
        ("medium", f"{OTHER}: time limit"),
    ]


def test_a_changed_module_without_a_hash_is_reported_once():
    before = dict(BEFORE, pam={UNIX: {"type": "-", "size": 1, "hash_skipped": "refused"}})
    after = dict(AFTER, pam={UNIX: {"type": "-", "size": 2, "hash_skipped": "refused"}})
    found = pam_findings(before, after, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert len([f for f in found if UNIX in f.summary]) == 1


def test_a_module_of_any_name_no_package_lists_is_high():
    planted = "/usr/lib/x86_64-linux-gnu/security/pam_x"
    filter_ = "/usr/lib/x86_64-linux-gnu/security/pam_filter/upperLOWER"
    pam = {UNIX: {"sha256": BAD}, planted: {"sha256": GOOD}, filter_: {"sha256": GOOD}}
    found = owner_findings(pam, {UNIX: owner(), filter_: owner()})
    assert [(f.band, f.summary) for f in found] == [("high", f"{planted}: no package lists it")]


def test_devices_and_cut_listings_in_pam_directories_are_reported():
    dev = "/usr/lib/x86_64-linux-gnu/security/pam_dev.so"
    pam = {UNIX: {"sha256": BAD, "type": "-"}, dev: {"type": "b", "device": [8, 1]}}
    from checker.checks import Context, run_checks

    current = snap(pam=pam, owners={UNIX: owner()})
    current.sections["pam"].gaps.append(
        "walk of /usr/lib/x86_64-linux-gnu/security: 3 directories not entered"
    )
    context = Context(host="h", bundle_id="b1", events=[], snapshot=current, baseline_id="b1")
    found = [f for f in run_checks(context)[0] if f.variant == "unhashed"]
    assert sorted((f.band, f.title) for f in found) == [
        ("high", "A device file in a PAM module directory"),
        ("medium", "A PAM module directory wasn't listed whole"),
    ]


def test_an_update_s_temporary_file_is_medium_and_a_plain_name_high():
    temp = "/usr/lib/x86_64-linux-gnu/security/pam_unix.so.dpkg-new"
    rpm_temp = "/usr/lib64/security/pam_unix.so;6a1f0c2b"
    pam = {UNIX: {"sha256": BAD}, temp: {"sha256": GOOD}, rpm_temp: {"sha256": GOOD}}
    found = owner_findings(pam, {UNIX: owner()})
    assert sorted((f.band, f.title) for f in found) == [
        ("medium", "A package manager's temporary file in a PAM module directory"),
        ("medium", "A package manager's temporary file in a PAM module directory"),
    ]
    # An executable without .so, reported by the unowned-files scan: high, as a .so is.
    plain = "/usr/lib/x86_64-linux-gnu/security/pam_x"
    found = owner_findings({UNIX: {"sha256": BAD}, plain: {"sha256": GOOD}}, {UNIX: owner()},
                           unowned={plain: {}})  # fmt: skip
    assert [(f.band, f.title) for f in found] == [
        ("high", "A PAM module that no package installed")
    ]
