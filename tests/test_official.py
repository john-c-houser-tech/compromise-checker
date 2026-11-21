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
