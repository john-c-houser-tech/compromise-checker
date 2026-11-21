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
        return next(s for s in describe(config) if s.startswith("Changed PAM modules"))

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
    found = pam_findings(BEFORE, added, FakeVerifier({new: {"sha256": GOOD}}))
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


def test_a_genuine_file_whose_mode_or_owner_changed_stays_high():
    after = dict(AFTER, pam={UNIX: {"sha256": BAD, "size": 2, "mode": "0666", "uid": 33}})
    found = pam_findings(BEFORE, after, FakeVerifier({UNIX: {"sha256": BAD}}))
    assert [(f.band, f.variant) for f in found] == [("high", "changed")]
    assert "its content is Ubuntu's, but its mode, uid changed" in found[0].summary


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
