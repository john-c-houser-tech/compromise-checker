"""Applications judged by a version folder in the web roots (plan A.2,
plans/application-exposure-plan-2026-11-26.md): the format, the judging,
a walk cut short, and an analysis through a bundle."""

import textwrap
from datetime import UTC, datetime

import pytest
from test_pack_format import GOOD
from test_snapshot import add_bundle, host_records, rec

from checker.packs.applications import WebEvidence, patterns
from checker.packs.exposure import (
    CANT_JUDGE,
    FIXED,
    NOT_AFFECTED,
    NOT_COVERED,
    VULNERABLE,
    judge,
)
from checker.packs.format import PackError, globs_overlap, read

REDCAP = textwrap.dedent(
    """\
    format: 1
    id: redcap-2026-09
    version: 1
    title: "REDCap survey passthrough remote code execution (CVE-2026-90817)"
    published: 2026-11-26
    cves: [CVE-2026-90817]
    exposure:
      window_start: 2026-09-20T00:00:00Z
      first_seen_in_wild: 2026-10-07T00:00:00Z
      likelihood_ratio: 5
      applications:
        - name: REDCap
          folder: "redcap_v*"
          versions: "16.0.*"
          fixed: "16.0.49"
          source: https://www.cve.org/CVERecord?id=CVE-2026-90817
        - name: REDCap
          folder: "redcap_v*"
          versions: "17.3.*"
          fixed: "17.3.10"
          source: https://www.cve.org/CVERecord?id=CVE-2026-90817
        - name: REDCap
          folder: "redcap_v*"
          versions: "*"
          affected_from: "13.3.0"
          fixed: "17.4.4"
          source: https://www.cve.org/CVERecord?id=CVE-2026-90817
    detections:
      - id: worker-child
        check: web.worker_child
        likelihood_ratio: 20
    remediation:
      - Upgrade REDCap to 16.0.49 LTS, 17.3.10 LTS or 17.4.4 Standard, or later on its line.
    references:
      - https://www.cve.org/CVERecord?id=CVE-2026-90817
    """
)
PACK = read(REDCAP.encode())
HOST = {"os": {"id": "ubuntu", "version_id": "24.04"}}
NOW = datetime(2026, 10, 20, tzinfo=UTC)  # 30 days into the window
ROOT = "/var/www"
SITE = "/var/www/html/redcap"


def tree(*versions, site=SITE, ctime="2026-09-01T00:00:00+00:00", place=ROOT, files=2):
    """web_files items for version folders: (version, ctime) or version."""
    items = {f"{site}/index.php": {"type": "-", "place": place, "ctime": ctime}}
    for v in versions:
        version, when = v if isinstance(v, tuple) else (v, ctime)
        for n in range(files):
            items[f"{site}/redcap_v{version}/Classes/F{n}.php"] = {
                "type": "-", "place": place, "ctime": when,
            }  # fmt: skip
    return items


def web(files, whole=True, first_whole=None, complete=True, earlier=(), walks=True,
        patterns=("redcap_v*",), extra=None, levels=None):  # fmt: skip
    found = {ROOT: {"whole": whole, "first_whole": first_whole, "first_patterns": list(patterns),
                    "levels_whole": levels}}  # fmt: skip
    found |= extra or {}
    return WebEvidence(
        files=files,
        complete=complete,
        walks=found if walks else None,
        roots=[ROOT, *(extra or {})],
        earlier=list(earlier),
    )


def judged(files, **kwargs):
    return judge(PACK, HOST, {}, [], NOW, True, web=web(files, **kwargs))


# --- The format ------------------------------------------------------------------------------


def test_an_applications_only_pack_reads():
    first, second, third = PACK.exposure.applications
    assert (first.name, first.folder, first.versions, first.fixed) == (
        "REDCap", "redcap_v*", "16.0.*", "16.0.49",
    )  # fmt: skip
    assert third.affected_from == "13.3.0" and PACK.exposure.packages == []
    assert patterns([PACK]) == ["redcap_v*"]


@pytest.mark.parametrize(
    ("old", "new", "said"),
    [
        (
            'folder: "redcap_v*"\n      versions: "16.0.*"',
            'folder: "redcap_v"\n      versions: "16.0.*"',
            "a fixed prefix and then *",
        ),
        (
            'folder: "redcap_v*"\n      versions: "16.0.*"',
            'folder: "../x*"\n      versions: "16.0.*"',
            "a fixed prefix and then *",
        ),
        ('versions: "16.0.*"', 'versions: "16.0.x"', "not a version pattern"),
        ('fixed: "16.0.49"', 'fixed: "16.0.49-lts"', "not a dotted version"),
        ('affected_from: "13.3.0"', 'affected_from: "18.0.0"', "is below affected_from"),
        ('versions: "16.0.*"', 'versions: "17.?.1"', "equally specific"),
        (
            'name: REDCap\n      folder: "redcap_v*"\n      versions: "16.0.*"',
            'name: Redcap\n      folder: "redcap_v*"\n      versions: "16.0.*"',
            "under two names",
        ),
        (
            'folder: "redcap_v*"\n      versions: "16.0.*"',
            'folder: "redcap_*"\n      versions: "16.0.*"',
            "one prefix starts the other",
        ),
    ],
)
def test_a_bad_application_entry_is_refused(old, new, said):
    assert old in REDCAP, old
    with pytest.raises(PackError, match=said):
        read(REDCAP.replace(old, new, 1).encode())


def test_an_exposure_needs_packages_or_applications():
    bare = REDCAP.split("  applications:")[0] + "detections:" + REDCAP.split("detections:")[1]
    with pytest.raises(PackError, match="needs packages, applications or both"):
        read(bare.encode())


def test_equally_specific_globs_that_cant_meet_are_allowed():
    assert not globs_overlap("16.0.*", "17.3.*")
    assert globs_overlap("17.3.*", "17.?.1") and globs_overlap("*", "17.3.*")


# --- Judging ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("newest", "status", "why"),
    [
        ("17.3.9", VULNERABLE, "before the fix 17.3.10"),
        ("17.3.10", FIXED, ""),
        ("17.3.32", FIXED, ""),
        ("16.0.48", VULNERABLE, "before the fix 16.0.49"),
        ("16.0.49", FIXED, ""),
        ("17.4.3", VULNERABLE, "before the fix 17.4.4"),
        ("17.4.4", FIXED, ""),
        ("17.6.6", FIXED, ""),
        # A line with no fix of its own (decision 5).
        (
            "17.1.8",
            VULNERABLE,
            "no fix on the 17.1 line; the fixes are 16.0.49, 17.3.10 and 17.4.4",
        ),  # noqa: E501
        ("14.5.2", VULNERABLE, "no fix on the 14.5 line"),
        ("13.2.9", NOT_AFFECTED, ""),
        ("13.3.0", VULNERABLE, "no fix on the 13.3 line"),
    ],
)
def test_each_line_before_and_after_its_fix(newest, status, why):
    found = judged(tree("13.0.1", newest))
    (install,) = found.applications
    assert (install.name, install.path, install.version, install.status) == (
        "REDCap", SITE, newest, status,
    )  # fmt: skip
    assert why in install.why
    assert install.evidence.startswith(f"{SITE}/redcap_v{newest}/")
    assert found.status == status


def test_the_newest_folder_is_the_running_version():
    # An upgrade unpacked but not finished reads as the new version (decision 2).
    (install,) = judged(tree("17.3.9", "17.3.10")).applications
    assert install.status == FIXED and install.folders == ["17.3.9", "17.3.10"]


def test_a_folder_with_the_prefix_but_no_version_isnt_a_version_folder():
    files = tree("17.3.10")
    files[f"{SITE}/redcap_vendor/lib.php"] = {"type": "-", "place": ROOT}
    (install,) = judged(files).applications
    assert install.status == FIXED and install.folders == ["17.3.10"]


def test_a_folder_with_a_leading_zero_isnt_read_as_a_version():
    (install,) = judged(tree("17.3.10", "017.3.11")).applications
    assert install.status == CANT_JUDGE and "isn't a version" in install.why


def test_a_two_part_version_compares_as_its_three_part_form():
    (install,) = judged(tree("13.3")).applications
    assert install.status == VULNERABLE  # 13.3 is 13.3.0, affected


def test_versions_sort_as_numbers():
    (install,) = judged(tree("17.3.9", "17.3.10", "17.3.2")).applications
    assert install.version == "17.3.10"


def test_a_folder_name_that_isnt_a_version_is_never_fixed():
    found = judged(tree("17.3.10", "17.3.11-test"))
    (install,) = found.applications
    assert install.status == CANT_JUDGE and "isn't a version" in install.why
    assert found.status == CANT_JUDGE and found.share == 1.0


def test_a_vulnerable_install_exposes_the_whole_window():
    found = judged(tree("17.3.9"))
    assert found.status == VULNERABLE and found.share == 1.0 and found.exposed_until is None


def test_a_fix_dates_from_its_folder_and_gives_the_share():
    found = judged(tree("17.3.9", ("17.3.10", "2026-10-05T00:00:00+00:00")))
    (install,) = found.applications
    assert install.fixed_since == "2026-10-05T00:00:00+00:00"
    assert found.status == FIXED and found.share == pytest.approx(0.5)
    assert found.exposed_until == "2026-10-05T00:00:00+00:00" and not found.fix_time_exact
    assert found.fix_source == "applications"


def test_the_first_fixed_folder_dates_the_fix_not_the_newest():
    found = judged(
        tree("17.3.9", ("17.3.10", "2026-10-05T00:00:00+00:00"),
             ("17.3.12", "2026-10-15T00:00:00+00:00"))
    )  # fmt: skip
    assert found.applications[0].fixed_since == "2026-10-05T00:00:00+00:00"


def test_the_fix_dates_from_the_last_move_to_a_fixed_version():
    # 16.0.49 (fixed), then 17.3.9 (vulnerable, in the window), then 17.3.10.
    found = judged(
        tree(("16.0.49", "2026-09-10T00:00:00+00:00"), ("17.3.9", "2026-10-01T00:00:00+00:00"),
             ("17.3.10", "2026-10-15T00:00:00+00:00"))
    )  # fmt: skip
    assert found.applications[0].fixed_since == "2026-10-15T00:00:00+00:00"
    assert found.status == FIXED and found.share == pytest.approx(25 / 30)


def test_an_earlier_collection_that_listed_the_fix_dates_it_sooner():
    late = tree("17.3.9", ("17.3.10", "2026-10-15T00:00:00+00:00"))
    seen = datetime(2026, 10, 1, tzinfo=UTC)
    found = judge(PACK, HOST, {}, [], NOW, True, web=web(late, earlier=[(seen, late)]))
    assert found.applications[0].fixed_since == seen.isoformat()


def test_a_fix_before_the_window_exposes_nothing():
    found = judged(tree("17.3.10", ctime="2026-09-10T00:00:00+00:00"))
    assert found.status == FIXED and found.share == 0.0 and found.exposed_from is None


def test_two_installs_are_judged_each_and_the_worse_decides():
    files = tree("17.3.10") | tree("17.3.9", site="/var/www/html/redcap2")
    found = judged(files)
    statuses = {i.path: i.status for i in found.applications}
    assert statuses == {SITE: FIXED, "/var/www/html/redcap2": VULNERABLE}
    assert found.status == VULNERABLE


def test_no_install_is_not_affected():
    found = judged({"/var/www/html/index.php": {"type": "-", "place": ROOT}})
    assert found.status == NOT_AFFECTED and found.share == 0.0 and found.applications == []


# --- A walk cut short (A.1, decision 7) ------------------------------------------------------


def test_a_cut_short_walk_with_every_version_folder_walked_first_judges_the_install():
    found = judged(tree("17.3.10"), whole=False, first_whole=True)
    (install,) = found.applications
    assert install.status == FIXED
    # Another install may be in what wasn't walked: never fixed from a partial list.
    assert found.applications_partial and found.status == CANT_JUDGE and found.share == 1.0


def test_a_cut_short_walk_that_listed_every_folder_near_the_top_trusts_the_installs():
    # Decision 8: every install down to INSTALL_DEPTH was found, so none is missing there.
    found = judged(tree("17.3.10"), whole=False, first_whole=True, levels=3)
    assert not found.applications_partial and found.status == FIXED
    assert found.applications_shallow == [ROOT]
    shallower = judged(tree("17.3.10"), whole=False, first_whole=True, levels=2)
    assert shallower.applications_partial and shallower.status == CANT_JUDGE


@pytest.mark.parametrize(
    "kwargs",
    [
        {"first_whole": False, "levels": 3},  # the version folders weren't all walked
        {"first_whole": True, "levels": 3, "patterns": ["other_v*"]},  # not this pack's pattern
        {"first_whole": True, "levels": None},  # an older collector
    ],
)
def test_levels_alone_never_trust_the_installs(kwargs):
    found = judged(tree("17.3.10"), whole=False, **kwargs)
    assert found.applications_partial and found.status == CANT_JUDGE


def test_running_out_of_time_never_trusts_the_installs():
    evidence = web(tree("17.3.10"), whole=False, first_whole=True, levels=3)
    evidence.time_limit = True
    found = judge(PACK, HOST, {}, [], NOW, True, web=evidence)
    assert found.applications_partial and found.status == CANT_JUDGE


def test_a_cut_short_walk_still_says_a_vulnerable_install_is_vulnerable():
    found = judged(tree("17.3.9"), whole=False, first_whole=True)
    assert found.status == VULNERABLE


def test_a_cut_short_walk_before_the_version_folders_cant_judge_the_install():
    found = judged(tree("17.3.10"), whole=False, first_whole=False)
    (install,) = found.applications
    assert install.status == CANT_JUDGE and "cut short" in install.why


def test_version_folders_walked_first_count_only_for_the_patterns_sent():
    # A pack added after the collection: its folders weren't walked first.
    found = judged(tree("17.3.10"), whole=False, first_whole=True, patterns=["other_v*"])
    assert found.applications[0].status == CANT_JUDGE


def test_a_web_root_that_wasnt_walked_may_hide_an_install():
    unwalked = {"/srv/www": {"whole": False, "first_whole": False, "first_patterns": []}}
    found = judge(PACK, HOST, {}, [], NOW, True, web=web(tree("17.3.10"), extra=unwalked))
    assert found.applications[0].status == FIXED
    assert found.applications_partial and found.status == CANT_JUDGE


def test_an_install_without_a_web_root_says_so():
    files = {k: {**v, "place": None} for k, v in tree("17.3.10").items()}
    (install,) = judged(files).applications
    assert install.status == CANT_JUDGE and "its web root" in install.why


def test_a_collection_from_an_older_collector_uses_the_section():
    assert judged(tree("17.3.10"), walks=False, complete=True).status == FIXED
    found = judged(tree("17.3.10"), walks=False, complete=False)
    assert found.status == CANT_JUDGE


def test_a_pack_with_packages_and_applications_takes_the_worse():
    assert "  stale_code:" in GOOD
    both = GOOD.replace(
        "  stale_code:",
        "  applications:\n"
        "    - name: REDCap\n"
        '      folder: "redcap_v*"\n'
        '      fixed: "17.4.4"\n'
        "      source: https://www.cve.org/CVERecord?id=CVE-2026-90817\n"
        "  stale_code:",
        1,
    )
    pack = read(both.encode())
    php = {"php8.3-fpm amd64": {"manager": "dpkg", "version": "8.3.6-0ubuntu0.24.04.5"}}
    found = judge(pack, HOST, php, [], datetime(2026, 10, 30, tzinfo=UTC), True,
                  web=web(tree("17.4.4")))  # fmt: skip
    assert found.status == VULNERABLE  # the package
    assert found.applications[0].status == FIXED
    rocky = {"os": {"id": "rocky", "version_id": "9.4"}}
    found = judge(pack, rocky, {}, [], datetime(2026, 10, 30, tzinfo=UTC), True,
                  web=web(tree("17.4.3")))  # fmt: skip
    assert found.status == VULNERABLE  # the install, on a release with no package of the pack's
    debian = {"os": {"id": "ubuntu", "version_id": "22.04"}}
    found = judge(pack, debian, {}, [], datetime(2026, 10, 30, tzinfo=UTC), True, web=web({}))
    assert found.status == NOT_COVERED  # no install found: the release gap still stands


# --- Through an analysis ---------------------------------------------------------------------


def redcap_records(version, whole=True, levels=None):
    web_files = [
        rec(
            "unusual_files",
            "web_file",
            path=path,
            place=ROOT,
            type="-",
            mode="0644",
            uid=33,
            gid=33,
            size=10,
            nlink=1,
            inode=100 + n,
            mtime=item["ctime"],
            ctime=item["ctime"],
            sha256="0" * 64,
        )  # fmt: skip
        for n, (path, item) in enumerate(tree(version).items())
    ]
    summary = rec(
        "unusual_files", "walk_summary", top=ROOT, place=ROOT, resolved=ROOT, entries=10,
        errors=0, not_descended={"depth": 0, "other_filesystem": 0, "pruned": 0},
        truncated=not whole, truncated_reason=None if whole else "entries", sent=len(web_files),
        not_listed=0, whole=whole,
        first={"patterns": ["redcap_v*"], "found": 1, "whole": True, "levels_whole": levels},
        phase="web_roots", seen_whole=whole,
    )  # fmt: skip
    # The privileged search's later walk of the same folder isn't the web roots' own.
    later = rec("unusual_files", "walk_summary", top=ROOT, place=ROOT, resolved=ROOT, entries=1,
                errors=0, not_descended={}, truncated=False, truncated_reason=None, sent=0,
                not_listed=0, whole=True)  # fmt: skip
    roots = rec("unusual_files", "web_roots", roots=[ROOT], source="default", walks="tagged")
    return host_records(extra=(roots, *web_files, summary, later))


def test_an_analysis_reports_a_vulnerable_install(home):
    from checker.assess import analyze

    base, store, identity, config = home
    add_bundle(home, "b1", 0, redcap_records("17.3.9"))
    assessment = analyze(store, "web01", identity, config.recipients, packs=[PACK])
    (finding,) = [f for f in assessment["findings"] if f["check"] == "pack.exposure"]
    assert finding["variant"] == "vulnerable" and finding["band"] == "high"
    assert f"REDCap 17.3.9 at {SITE}: before the fix 17.3.10" in finding["summary"]
    assert any("running version is read from the newest version folder" in g
               for g in assessment["coverage"]["gaps"])  # fmt: skip
    (record,) = [e for e in assessment["exposures"] if e["pack"] == "redcap-2026-09"]
    (install,) = record["applications"]
    assert install == {
        "name": "REDCap", "path": SITE, "version": "17.3.9", "status": VULNERABLE,
        "fixed": "17.3.10", "why": "before the fix 17.3.10", "versions_seen": ["17.3.9"],
        "fixed_since": None,
    }  # fmt: skip
    assert "partial" not in record and record["judged"] is True


def _record_for(found):
    from checker.assess import exposure_records

    (record,) = exposure_records([found])
    return record


def test_a_record_for_an_install_cut_off_by_its_walk_is_a_gap_not_a_judgement():
    # The pack's pattern wasn't sent (added after the collection): the install can't be judged.
    found = judged(tree("17.3.10"), whole=False, first_whole=True, patterns=["other_v*"])
    record = _record_for(found)
    assert record["status"] == CANT_JUDGE and record["judged"] is False
    assert record["partial"] == "web_roots"


def test_a_record_lists_installs_worst_first_with_the_fix_time_and_caps():
    files = tree(("17.3.10", "2026-10-05T00:00:00+00:00")) | tree("17.3.9", site="/var/www/b")
    record = _record_for(judged(files))
    assert [a["path"] for a in record["applications"]] == ["/var/www/b", SITE]
    assert record["applications"][1]["fixed_since"] == "2026-10-05T00:00:00+00:00"
    many = {}
    for n in range(25):
        many |= tree("17.3.10", site=f"/var/www/s{n:02d}")
    record = _record_for(judged(many))
    assert len(record["applications"]) == 20 and record["applications_more"] == 5


def test_an_analysis_of_a_cut_short_walk_says_an_install_may_be_missing(home):
    from checker.assess import analyze

    base, store, identity, config = home
    add_bundle(home, "b1", 0, redcap_records("17.4.4", whole=False))
    assessment = analyze(store, "web01", identity, config.recipients, packs=[PACK])
    (finding,) = [f for f in assessment["findings"] if f["check"] == "pack.exposure"]
    assert finding["variant"] == "cant_judge" and "may be missing" in finding["summary"]
    assert not any("package listing" in g for g in assessment["coverage"]["gaps"])
    (record,) = [e for e in assessment["exposures"] if e["pack"] == "redcap-2026-09"]
    assert record["status"] == CANT_JUDGE and record["partial"] == "web_roots"
    assert record["judged"] is False  # the install is fixed: the gap is the walk


def test_an_analysis_with_no_install_and_a_cut_short_walk_is_a_gap(home):
    from checker.assess import analyze

    base, store, identity, config = home
    records = [r for r in redcap_records("17.4.4", whole=False)
               if r.get("name") != "web_file"]  # fmt: skip
    add_bundle(home, "b1", 0, records)
    assessment = analyze(store, "web01", identity, config.recipients, packs=[PACK])
    (record,) = [e for e in assessment["exposures"] if e["pack"] == "redcap-2026-09"]
    assert record["status"] == CANT_JUDGE and record["judged"] is False
    assert record["partial"] == "web_roots" and "applications" not in record


def test_an_analysis_of_a_cut_short_walk_that_found_every_install_near_the_top(home):
    from checker.assess import analyze

    base, store, identity, config = home
    add_bundle(home, "b1", 0, redcap_records("17.4.4", whole=False, levels=3))
    assessment = analyze(store, "web01", identity, config.recipients, packs=[PACK])
    (record,) = [e for e in assessment["exposures"] if e["pack"] == "redcap-2026-09"]
    assert record["status"] == FIXED and "partial" not in record
    assert any("every folder down to 3 levels below it was listed" in g
               for g in assessment["coverage"]["gaps"])  # fmt: skip


def test_the_snapshot_keeps_only_the_web_roots_own_walks():
    from checker.snapshot import SnapshotBuilder

    snap = SnapshotBuilder()
    for r in redcap_records("17.4.4", whole=False):
        if r.get("type") == "record" and r["module"] == "unusual_files":
            snap._web_walk(r["name"], r["data"])
    snap._web_walk("not_examined", {"path": "/srv/www", "reason": "nfs"})  # not a web root here
    # A walk that came out whole but hit an error on the way isn't whole for this.
    errored = {"top": "/x", "place": "/x", "whole": True, "seen_whole": False, "errors": 1,
               "phase": "web_roots"}  # fmt: skip
    snap._web_walk("walk_summary", errored)
    assert snap.live["web_walks"].pop("/x")["whole"] is False
    walks = snap.live["web_walks"]
    assert walks == {ROOT: {"whole": False, "first_whole": True, "first_patterns": ["redcap_v*"],
                            "levels_whole": None}}  # fmt: skip
    snap.live["web_roots"].append("/srv/www")
    snap._web_walk("not_examined", {"path": "/srv/www", "reason": "nfs"})
    assert walks["/srv/www"] == {
        "whole": False, "first_whole": False, "first_patterns": [], "levels_whole": None,
    }  # fmt: skip
