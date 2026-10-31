"""Applying the packs in force (plan 4.6): `checker analyze`, `checker
report` and `checker run` all apply them; a pack that can't be used is a
gap, not silence; a run says when a pack newly finds a host exposed or a
detection firing. The pack is the format tests' made-up one."""

import pytest
import yaml
from test_pack_exposure import records
from test_pack_format import GOOD
from test_pack_trust import Key, pack
from test_schedule import collector, keyed_host, one_run
from test_snapshot import add_bundle

from checker import cli, schedule
from checker.assess import load_assessment
from checker.evidence import load_config
from checker.inventory import inventory_transaction
from checker.packs.store import in_force

VULNERABLE = records("8.3.6-0ubuntu0.24.04.5")  # before the pack's fix


@pytest.fixture
def ours(home, tmp_path, capsys):
    """An organization key, trusted, and a way to add a pack it signs."""
    key = Key()
    assert cli.main(["packs", "trust", "add", "team", str(key.pub_file(tmp_path / "k.pub"))]) == 0

    def add(text=GOOD):
        assert cli.main(["packs", "add", str(pack(tmp_path, key, text))]) == 0
        capsys.readouterr()

    capsys.readouterr()
    return add


@pytest.fixture
def fleet(home, tmp_path):
    with inventory_transaction() as hosts:
        hosts.add(keyed_host(tmp_path))
    return home


def latest(home):
    _, store, identity, _ = home
    return load_assessment(store, store.bundles("web01")[-1]["id"], identity)


def test_analyze_applies_the_packs_in_force_and_says_so(home, ours, capsys):
    add_bundle(home, "b1", 0, VULNERABLE)
    ours()
    assert cli.main(["analyze", "web01"]) == 0
    out = capsys.readouterr().out
    assert "Packs      example-2026-10 v2" in out
    assert "prior raised to 9%: exposed to example-2026-10 v2 (100% of its window)" in out
    assert latest(home)["packs"] == [{"id": "example-2026-10", "version": 2}]


def test_a_pack_that_cant_be_used_is_said_and_is_a_gap(home, ours, capsys):
    add_bundle(home, "b1", 0, VULNERABLE)
    ours()
    kept = home[0] / "packs" / "active" / "example-2026-10-v2.yaml"
    kept.write_text(GOOD.replace("likelihood_ratio: 5", "likelihood_ratio: 2"))
    assert cli.main(["analyze", "web01"]) == 0
    err = capsys.readouterr().err
    assert "checker: threat pack not applied: example-2026-10 version 2:" in err
    assessment = latest(home)
    assert assessment["packs"] == []
    assert any(g.startswith("threat pack not applied: example-2026-10") for g in
               assessment["coverage"]["gaps"])  # fmt: skip


def test_trouble_reading_the_packs_is_a_reason_not_a_crash(home, monkeypatch):
    def broken(*args):
        raise PermissionError("no")

    monkeypatch.setattr("checker.packs.store.active", broken)
    assert in_force(home[0], []) == ([], ["the packs couldn't be read: PermissionError: no"])


def test_a_report_analyses_again_when_the_packs_changed(home, ours, capsys):
    add_bundle(home, "b1", 0, VULNERABLE)
    assert cli.main(["analyze", "web01"]) == 0
    assert latest(home)["packs"] == []
    ours()
    assert cli.main(["report", "web01"]) == 0
    assert latest(home)["packs"] == [{"id": "example-2026-10", "version": 2}]
    # And again without it, once it is retired.
    assert cli.main(["packs", "retire", "example-2026-10", "--reason", "test"]) == 0
    assert "`checker analyze --all`" in capsys.readouterr().out
    assert cli.main(["report", "web01"]) == 0
    assert latest(home)["packs"] == []


def test_analyze_all_applies_a_pack_added_since_to_every_host(home, ours):
    add_bundle(home, "b1", 0, VULNERABLE)
    add_bundle(home, "c1", 0, VULNERABLE, host="web02")
    assert cli.main(["analyze", "--all"]) == 0
    ours()
    assert cli.main(["analyze", "--all"]) == 0
    _, store, identity, _ = home
    for host in ("web01", "web02"):
        row = store.bundles(host)[-1]
        assert load_assessment(store, row["id"], identity)["packs"][0]["id"] == "example-2026-10"


# --- A run -----------------------------------------------------------------------------------


def test_a_pack_added_between_runs_that_finds_a_host_exposed_needs_a_look(fleet, ours):
    collect = collector(fleet, VULNERABLE)
    first = one_run(fleet, collect)
    assert not any("threat pack" in line for line in first.alerting)
    ours()
    second = one_run(fleet, collect)
    assert "web01: exposed to threat pack example-2026-10 v2 (vulnerable now)" in second.alerting
    assert latest(fleet)["packs"] == [{"id": "example-2026-10", "version": 2}]
    # Said once: the next run, still exposed, is quiet about it.
    third = one_run(fleet, collect)
    assert not any("threat pack" in line for line in third.alerting)


def test_a_pack_that_cant_be_used_fails_the_run_and_is_told(fleet, ours):
    ours()
    kept = fleet[0] / "packs" / "active" / "example-2026-10-v2.yaml"
    kept.write_text(GOOD.replace("likelihood_ratio: 5", "likelihood_ratio: 2"))
    result = one_run(fleet, collector(fleet, VULNERABLE))
    assert any(p.startswith("threat pack not applied: example-2026-10") for p in result.problems)
    assert "1 threat pack(s) not applied (`checker packs list`)" in result.alerting
    assert result.exit_status() == schedule.EXIT_FAILED
    assert any(g.startswith("threat pack not applied") for g in
               latest(fleet)["coverage"]["gaps"])  # fmt: skip


def test_with_no_pack_a_run_says_nothing_of_packs(fleet):
    result = one_run(fleet, collector(fleet, VULNERABLE))
    assert result.problems == [] and not any("pack" in line for line in result.alerting)
    assert load_config(fleet[0]).packs.trusted_keys == []


# --- What counts as news ---------------------------------------------------------------------


def scored(*exposures, findings=()):
    return {"score": {"band": "Low", "probability": 0.05}, "exposures": list(exposures),
            "findings": list(findings), "checks": []}  # fmt: skip


def exposed(status="vulnerable", pack="p-2026", version=1, share=1.0, judged=True):
    return {"pack": pack, "version": version, "status": status, "share": share,
            "judged": judged}  # fmt: skip


def detection(band="medium", suppressed=None, summary="3 matching events (p-2026 v1, since)"):
    return {"check": "pack.detection", "band": band, "title": "Workers crashing",
            "variant": "p-2026/fpm-crash", "entities": ["pack:p-2026", "uid:48"],
            "summary": summary, "suppressed_by": suppressed}  # fmt: skip


def runs(*assessments):
    """What each of a sequence of runs says, remembering as a run does."""
    said, before = [], None
    for after in assessments:
        said.append(schedule.alerts("h", before, after))
        before = schedule.remembered(after, before)
    return said


def test_exposure_is_news_once_per_pack_and_again_when_it_worsens():
    assert runs(scored(), scored(exposed())) == [
        [], ["h: exposed to threat pack p-2026 v1 (vulnerable now)"]]  # fmt: skip
    # A new version of the same pack, still vulnerable: not news.
    assert runs(scored(exposed()), scored(exposed(version=2)))[1] == []
    assert runs(scored(exposed()), scored(exposed(), exposed(pack="q-2026")))[1] == [
        "h: exposed to threat pack q-2026 v1 (vulnerable now)"
    ]
    assert runs(scored(exposed("fixed")))[0] == [
        "h: exposed to threat pack p-2026 v1 (exposed while the threat was active, fixed since)"
    ]
    # Fixed, then vulnerable again (a downgrade, or a version that widens it): news.
    assert runs(scored(exposed("fixed")), scored(exposed()))[1] == [
        "h: exposed to threat pack p-2026 v1 (vulnerable now)"
    ]
    assert runs(scored(exposed()), scored(exposed("fixed")))[1] == []  # better isn't news
    # Not exposed at all (share 0), then exposed: news again.
    assert runs(scored(exposed()), scored(exposed(share=0)), scored(exposed()))[2] != []


def test_a_listing_collected_in_part_neither_tells_nor_forgets():
    unjudged = exposed("can't judge", judged=False)
    assert runs(scored(unjudged)) == [[]]  # a gap, not news
    # Vulnerable, then a run that couldn't judge, then vulnerable again: told once.
    assert runs(scored(exposed()), scored(unjudged), scored(exposed()))[1:] == [[], []]
    assert schedule.remembered(scored(unjudged), schedule.remembered(scored(exposed())))[
        "exposed"
    ] == {"p-2026": "vulnerable"}


def test_a_packs_detection_is_news_whatever_its_band_and_its_counts():
    assert runs(scored(), scored(findings=[detection()]))[1] == [
        "h: new medium: Workers crashing (threat pack p-2026)"
    ]
    # The same group, more events, a new pack version: the same detection.
    again = detection(summary="9 matching events (p-2026 v2, since)")
    assert runs(scored(findings=[detection()]), scored(findings=[again]))[1] == []
    assert runs(scored(), scored(findings=[detection(suppressed="rule")]))[1] == []
    assert runs(scored(findings=[detection("low")]), scored(findings=[detection("high")]))[1] == [
        "h: now high (was low): Workers crashing (threat pack p-2026)"
    ]


def test_a_core_finding_a_pack_newly_weighs_is_news_once():
    core = {"check": "web.worker_child", "band": "medium", "title": "A web worker ran a shell",
            "variant": "history", "entities": ["account:x"], "suppressed_by": None}  # fmt: skip
    weighed = dict(core, raised_by_pack="p-2026 v1 (worker-child)")
    said = runs(scored(findings=[core]), scored(findings=[weighed]), scored(findings=[weighed]))
    assert said == [[], ["h: newly weighed by a threat pack: A web worker ran a shell (weighed"
                         " by threat pack p-2026 v1 (worker-child))"], []]  # fmt: skip


def test_an_older_runs_memory_counts_as_far_as_it_goes():
    before = schedule.remembered(scored())
    del before["exposed"], before["weighed"]
    assert schedule.alerts("h", before, scored(exposed())) == [
        "h: exposed to threat pack p-2026 v1 (vulnerable now)"
    ]
    before["exposed"] = ["p-2026"]  # an earlier form: ids only
    assert schedule.alerts("h", before, scored(exposed())) == []


def test_a_real_by_group_detection_keeps_its_identity_across_runs():
    from test_pack_detect import context, event, pack_with

    from checker.packs.detect import own_detections

    rule = """\
        - id: shell-probe
          title: A web account probing the host
          events:
            any_of:
              - type: process.exec
                fields: {argv: {equals: id}}
            count: {at_least: 2}
            by: uid
          likelihood_ratio: 8
    """
    pack = pack_with(rule)

    def probes(n):
        return [event(f"2026-10-22T10:{m:02d}:00+00:00", "process.exec", argv="id", uid=48)
                for m in range(n)]  # fmt: skip

    first, later = (own_detections(context(pack, probes(n)))[0].as_dict() for n in (3, 7))
    assert first["summary"] != later["summary"]
    assert "uid:48" in first["entities"] and first["entities_complete"]
    assert runs(scored(findings=[first]), scored(findings=[later]))[1] == []


# --- Which packs apply to a host ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        ("all", "all"),
        (" none ", "none"),
        ("only:a-1,b-2", "only: a-1, b-2"),
        ("except: a-1 , a-1", "except: a-1"),
    ],
)
def test_a_pack_rule_is_kept_one_way(text, kept):
    from checker.packs.choice import normal

    assert normal(text) == kept


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ("some", "not a pack rule"),
        ("only:", "names no pack"),
        ("except: Bad_Id", "not a pack id"),
        ("only: " + ",".join(f"p{n}" for n in range(51)), "at most 50"),
    ],
)
def test_a_bad_pack_rule_is_refused(text, said):
    from checker.packs.choice import parse

    with pytest.raises(ValueError, match=said):
        parse(text)


def test_the_hosts_rule_wins_then_its_groups_then_the_configurations():
    from types import SimpleNamespace as N

    from checker.packs.choice import choose, rule_for

    config = N(packs=N(apply="except: a", group_apply={"web": "only: b"}))
    inventory = N(hosts=[N(name="h1", group="web", packs=None), N(name="h2", group="web",
                         packs="none"), N(name="h3", group=None, packs=None)])  # fmt: skip
    assert rule_for("h1", config, inventory) == ("only: b", "group web's")
    assert rule_for("h2", config, inventory) == ("none", "the host's")
    assert rule_for("h3", config, inventory) == ("except: a", "the configuration's")
    assert rule_for("gone", config, inventory) == ("except: a", "the configuration's")
    a, b = N(id="a", version=1), N(id="b", version=3)
    assert choose([a, b], "only: b", "group web's") == (
        [b], ["a version 1: held back by group web's setting (packs: only: b)"])  # fmt: skip
    assert choose([a, b], "all", "x") == ([a, b], [])
    assert choose([a, b], "except: a", "x")[0] == [b]
    assert choose([a, b], "none", "x")[0] == []


def test_a_host_set_to_none_is_analysed_without_them_and_says_so(fleet, ours, capsys):
    ours()
    assert cli.main(["hosts", "packs", "web01", "none"]) == 0
    out = capsys.readouterr().out
    assert "web01: packs: all -> none (recorded)." not in out  # it had no rule of its own
    assert "web01: packs: default -> none (recorded)." in out
    assert "web01: packs: none (the host's setting)" in out
    assert "  held back: example-2026-10 v2" in out
    result = one_run(fleet, collector(fleet, VULNERABLE))
    assert not any("threat pack" in line for line in result.alerting)
    assert result.problems == []  # held back by choice: not a problem
    assessment = latest(fleet)
    assert assessment["packs"] == [] and assessment["exposures"] == []
    assert any("example-2026-10 version 2: held back by the host's setting (packs: none)" in g
               for g in assessment["coverage"]["gaps"])  # fmt: skip
    # Back to the default: the next run applies it, and says what it finds.
    assert cli.main(["hosts", "packs", "web01", "default"]) == 0
    result = one_run(fleet, collector(fleet, VULNERABLE))
    assert "web01: exposed to threat pack example-2026-10 v2 (vulnerable now)" in result.alerting


def test_who_changed_a_hosts_rule_and_when_is_recorded(fleet, ours, capsys):
    from checker.settings import change

    assert cli.main(["hosts", "packs", "web01", "except: example-2026-10"]) == 0
    assert cli.main(["hosts", "packs", "web01", "except:example-2026-10"]) == 0  # the same
    change(fleet[0], "packs.apply", "none")
    capsys.readouterr()
    assert cli.main(["config", "history"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [line.split("  ", 2)[2] for line in lines[-2:]] == [
        'hosts.web01.packs: null -> "except: example-2026-10"',
        'packs.apply: "all" -> "none"',
    ]
    assert cli.main(["hosts", "packs", "web01", "only"]) == 2
    assert "not a pack rule" in capsys.readouterr().err
    assert cli.main(["hosts", "packs", "nobody", "none"]) == 2


def test_a_groups_rule_from_the_configuration(fleet, ours, capsys):
    from checker.evidence import config_file
    from checker.inventory import inventory_transaction as hosts_transaction

    with hosts_transaction() as inventory:
        inventory.get("web01").group = "web"
    path = config_file(fleet[0])
    data = yaml.safe_load(path.read_text())
    data["packs"]["group_apply"] = {"web": "none"}
    path.write_text(yaml.safe_dump(data))
    assert load_config(fleet[0]).packs.group_apply == {"web": "none"}
    assert cli.main(["hosts", "packs", "web01"]) == 0
    assert "web01: packs: none (group web's setting)" in capsys.readouterr().out
    assert cli.main(["config", "show"]) == 0
    assert "groups' own: web: none" in capsys.readouterr().out


# --- The advisor, and what a report shows --------------------------------------------------------


def test_the_advisor_sees_the_same_analysis_as_the_report(home, ours):
    from checker.advisor.case import case_for_host
    from checker.inventory import load_inventory

    _, store, identity, config = home
    add_bundle(home, "b1", 0, VULNERABLE)
    ours()
    assert cli.main(["analyze", "web01"]) == 0
    stored = len(store.assessments(store.bundles("web01")[-1]["id"]))
    packs = cli._packs_in_force(home[0], load_config(home[0]), load_inventory())[0]("web01")
    _, _, which = case_for_host(store, "web01", identity, config.recipients, load_inventory(),
                                (0.02, "configuration"), None, packs=packs)  # fmt: skip
    assert which["report"].assessment["packs"] == [{"id": "example-2026-10", "version": 2}]
    assert len(store.assessments(store.bundles("web01")[-1]["id"])) == stored  # not analysed again
    assert cli.main(["advise", "web01", "--show"]) in (0, 1)
    assert latest(home)["packs"] == [{"id": "example-2026-10", "version": 2}]


def test_a_change_in_why_a_pack_isnt_applied_alone_analyses_again(home, ours):
    from checker.report import host_report

    _, store, identity, config = home
    add_bundle(home, "b1", 0, VULNERABLE)
    host_report(store, "web01", identity, config.recipients, None, (0.02, "c"), None, [], ["x: y"])
    assert latest(home)["packs_not_applied"] == ["x: y"]
    host_report(store, "web01", identity, config.recipients, None, (0.02, "c"), None, [], [])
    assert latest(home)["packs_not_applied"] == []


def test_the_timeline_marks_the_window_and_the_exposure():
    from checker.report import exposure_marks

    marks = exposure_marks({"exposures": [
        exposed("fixed") | {"window_start": "2026-10-20T00:00:00+00:00",
                            "exposed_from": "2026-10-21T00:00:00+00:00",
                            "exposed_until": "2026-10-24T00:00:00+00:00"},
        exposed(pack="never", share=0) | {"window_start": "2026-10-20T00:00:00+00:00"},
    ]})  # fmt: skip
    assert [(m["when"][:10], m["text"]) for m in marks] == [
        ("2026-10-20", "p-2026 v1: the threat's window opens"),
        ("2026-10-21", "p-2026 v1: the host is exposed from here"),
        ("2026-10-24", "p-2026 v1: exposed until here at the latest"),
    ]


def test_a_pack_problem_is_told_once_while_it_lasts(fleet, ours):
    ours()
    kept = fleet[0] / "packs" / "active" / "example-2026-10-v2.yaml"
    kept.write_text(GOOD.replace("likelihood_ratio: 5", "likelihood_ratio: 2"))
    collect = collector(fleet, VULNERABLE)
    first, second = one_run(fleet, collect), one_run(fleet, collect)
    told = "1 threat pack(s) not applied (`checker packs list`)"
    assert told in first.alerting and told not in second.alerting
    assert second.problems and second.exit_status() == schedule.EXIT_FAILED


def test_an_exposure_resting_only_on_a_listing_in_part_is_kept_as_unjudged():
    from checker.assess import exposure_records
    from checker.packs.exposure import Exposure, Judged

    unsure = Exposure("p-2026", 1, 5, "ubuntu:24.04", "can't judge", share=1.0)
    odd = Judged("php8.3-fpm amd64", "php8.3-fpm", "8.3.6-x", None, "can't judge", None)
    seen = Exposure("p-2026", 1, 5, "ubuntu:24.04", "can't judge", packages=[odd], share=1.0)
    gone = Exposure("p-2026", 1, 5, "ubuntu:24.04", "can't judge", removed_at="t", share=1.0)
    plain = Exposure("p-2026", 1, 5, "ubuntu:24.04", "vulnerable", share=1.0)
    judged = [r["judged"] for r in exposure_records([unsure, seen, gone, plain])]
    assert judged == [False, True, True, True]


def test_a_snapshot_detections_identity_leaves_out_the_packs_version():
    found = {"check": "pack.detection", "variant": "p-2026/odd-user",
             "entities": ["pack:p-2026"], "entities_complete": False,
             "summary": "accounts present: eve (p-2026 v1, since)"}  # fmt: skip
    newer = dict(found, summary="accounts present: eve (p-2026 v2, since)")
    other = dict(found, summary="accounts present: mallory (p-2026 v2, since)")
    identity = schedule._identity_of
    assert identity(found) == identity(newer) != identity(other)


# --- After the second review -------------------------------------------------------------------


def test_a_value_too_long_to_name_isnt_cut_short_for_a_whitelist():
    from test_pack_detect import context, event, pack_with

    from checker.packs.detect import MAX_GROUP, own_detections

    pack = pack_with("""\
        - id: odd-path
          title: Odd paths
          events:
            any_of:
              - type: web.request
                fields: {path: {prefix: /var/www/}}
            by: path
          likelihood_ratio: 4
    """)  # fmt: skip
    long = "/var/www/" + "a/" * 96 + "../../../../../etc/cron.d/x"
    assert len(long) > MAX_GROUP
    found = [f.as_dict() for f in own_detections(context(pack, [
        event("2026-10-22T10:00:00+00:00", "web.request", path=long),
        event("2026-10-22T10:00:00+00:00", "web.request", path="/var/www/ok"),
    ]))]  # fmt: skip
    by_path = {f["entities_complete"]: f["entities"] for f in found}
    assert by_path[False] == ["pack:example-2026-10"]  # not named: listed in part
    assert by_path[True] == ["pack:example-2026-10", "path:/var/www/ok"]


def test_a_listing_in_part_with_only_fixed_packages_seen_doesnt_flap():
    from checker.assess import exposure_records
    from checker.packs.exposure import Exposure, Judged

    def judged(status):
        return Judged("php8.3-fpm amd64", "php8.3-fpm", "8.3.6-1", None, status, "8.3.6-0")

    fixed_only = Exposure("p-2026", 1, 5, "ubuntu:24.04", "can't judge",
                          packages=[judged("fixed")], share=1.0)  # fmt: skip
    vulnerable = Exposure("p-2026", 1, 5, "ubuntu:24.04", "can't judge",
                          packages=[judged("vulnerable")], share=1.0)  # fmt: skip
    assert [r["judged"] for r in exposure_records([fixed_only, vulnerable])] == [False, True]
    partial = scored(exposed("can't judge", judged=False))
    said = runs(scored(exposed("fixed")), partial, scored(exposed("fixed")), partial)
    assert said[1:] == [[], [], []]


def test_the_first_run_after_weighing_was_kept_isnt_a_burst_of_news():
    weighed = {"check": "web.worker_child", "band": "medium", "title": "t", "variant": None,
               "entities": ["account:x"], "suppressed_by": None,
               "raised_by_pack": "p v1 (w)"}  # fmt: skip
    before = schedule.remembered(scored(findings=[weighed]))
    del before["weighed"]
    assert schedule.alerts("h", before, scored(findings=[weighed])) == []


def test_the_window_opening_and_the_exposure_starting_together_are_one_mark():
    from checker.report import MAX_MARKED, exposure_marks

    start = "2026-10-20T00:00:00+00:00"
    item = exposed() | {"window_start": start, "exposed_from": start}
    assert [m["text"] for m in exposure_marks({"exposures": [item]})] == [
        "p-2026 v1: the threat's window opens"
    ]
    many = [item | {"pack": f"p{n}"} for n in range(MAX_MARKED + 5)]
    assert len(exposure_marks({"exposures": many})) == MAX_MARKED


def test_removing_a_host_with_its_own_rule_is_recorded(fleet, capsys):
    assert cli.main(["hosts", "packs", "web01", "none"]) == 0
    assert cli.main(["hosts", "remove", "web01"]) == 0
    capsys.readouterr()
    assert cli.main(["config", "history"]) == 0
    assert capsys.readouterr().out.splitlines()[-1].endswith('hosts.web01.packs: "none" -> null')


def test_a_groups_rule_is_set_and_cleared_on_the_record(fleet, capsys):
    assert cli.main(["config", "set", "packs.group_apply.web", "except:x-1"]) == 0
    assert load_config(fleet[0]).packs.group_apply == {"web": "except: x-1"}
    assert cli.main(["config", "set", "packs.group_apply.web", "default"]) == 0
    assert load_config(fleet[0]).packs.group_apply == {}
    assert cli.main(["config", "set", "packs.group_apply.we b", "none"]) == 2
    assert "not a group name: 'we b'" in capsys.readouterr().err
    assert cli.main(["config", "set", "packs.group_apply.web", "some"]) == 2
    capsys.readouterr()
    assert cli.main(["config", "history"]) == 0
    assert [line.split("  ", 2)[2] for line in capsys.readouterr().out.splitlines()] == [
        'packs.group_apply.web: null -> "except: x-1"',
        'packs.group_apply.web: "except: x-1" -> null',
    ]


def test_typos_are_pointed_out(fleet, ours, capsys):
    assert cli.main(["hosts", "packs", "web01", "only: exampel-2026-10"]) == 0
    assert "note: no pack exampel-2026-10 is in force (yet)" in capsys.readouterr().out
    assert cli.main(["config", "set", "packs.group_apply.wbe", "none"]) == 0
    capsys.readouterr()
    assert cli.main(["config", "show"]) == 0
    assert "note: no host is in group wbe, whose pack rule is set" in capsys.readouterr().out
