"""A pack's detections (checker/packs/detect.py, plan 4.5): the language's
format, its matching, and how they count only while the host was exposed.
The pack is the format tests' made-up one; its window opens 2026-10-20."""

import textwrap

import pytest
from test_pack_exposure import FIXED_AT, records
from test_pack_format import GOOD, changed
from test_snapshot import add_bundle, rec

from checker.checks import Context
from checker.events import Event
from checker.packs.detect import _band, glob_match, own_detections, raise_referenced
from checker.packs.exposure import Exposure
from checker.packs.format import PackError, read
from checker.scoring import ratio
from checker.snapshot import Section, Snapshot

WORKER = "  - id: worker-child\n    check: web.worker_child\n    likelihood_ratio: 20\n"


def pack_with(detections: str):
    return read(changed(WORKER, textwrap.indent(textwrap.dedent(detections), "  ")))


CRASH = """\
    - id: fpm-crash
      title: PHP-FPM workers crashing
      events:
        any_of:
          - type: web.error
            fields: {message: {glob: "*child * exited on signal 11*"}}
          - type: kernel.segfault
            fields: {comm: {prefix: php-fpm}}
        count: {at_least: 3, within: 10m}
      likelihood_ratio: 8
"""


def event(time, kind, program=None, **fields):
    return Event(time, time, "web_logs:/var/log/php-fpm.log", kind, fields, program)


def exposure(pack, exposed_from="2026-10-20T00:00:00+00:00", until=None):
    return Exposure(pack.id, pack.version, 5, "ubuntu:24.04", "vulnerable",
                    exposed_from=exposed_from, exposed_until=until)  # fmt: skip


def context(pack, events=(), sections=None, live=None, exposed=True, **kwargs):
    snapshot = Snapshot({}, sections or {}, live or {})
    found = Context("web01", "b1", list(events), snapshot, packs=[pack], **kwargs)
    found.exposures = [exposure(pack) if exposed is True else exposed] if exposed else []
    return found


def crash(minute, pid=1):
    message = f"WARNING: [pool www] child {pid} exited on signal 11 (SIGSEGV)"
    return event(f"2026-10-22T10:{minute:02d}:00+00:00", "web.error", message=message)


# --- The format ------------------------------------------------------------------------------


def test_the_documented_example_reads():
    pack = pack_with(CRASH)
    (detection,) = pack.detections
    assert detection.events.count.at_least == 3 and detection.events.count.within == "10m"
    assert detection.events.any_of[1].fields["comm"].prefix == "php-fpm"


@pytest.mark.parametrize(
    ("detections", "problem"),
    [
        ("- {id: a, likelihood_ratio: 2}", "one of: check, events, snapshot"),
        ("- {id: a, check: web.errors, title: x, snapshot: {section: s, state: present},"
         " likelihood_ratio: 2}", "one of: check, events, snapshot"),
        ("- {id: a, snapshot: {section: s, state: present}, likelihood_ratio: 2}", "has a title"),
        ("- {id: a, title: t, snapshot: {section: s, state: present}, likelihood_ratio: 21}",
         "at most 20"),
        ("- {id: a, check: web.errors, likelihood_ratio: 101}", "less than or equal to 100"),
        ("- {id: a, title: t, variant: x, snapshot: {section: s, state: present},"
         " likelihood_ratio: 2}", "variant goes with check"),
        ("- {id: a, title: t, snapshot: {section: s, state: here}, likelihood_ratio: 2}",
         "present"),
        ("- {id: a, title: t, snapshot: {section: s, key: {equals: x, glob: y}, state: present},"
         " likelihood_ratio: 2}", "one of equals, prefix or glob"),
        ("- {id: a, title: t, snapshot: {section: s, key: {glob: '*********** *'},"
         " state: present}, likelihood_ratio: 2}", "at most 10"),
        ("- {id: a, title: t, snapshot: {section: s, key: {regex: x}, state: present},"
         " likelihood_ratio: 2}", "regex"),
        ("- {id: a, title: t, events: {any_of: [{type: 'Web'}]}, likelihood_ratio: 2}",
         "not an event type"),
        ("- {id: a, title: t, events: {any_of: [{type: web.x, fields: {Bad: {equals: x}}}]},"
         " likelihood_ratio: 2}", "not a field name"),
        ("- {id: a, title: t, events: {any_of: [{type: web.x}], count: {at_least: 2,"
         " within: 8d}}, likelihood_ratio: 2}", "at most 7 days"),
        ("- {id: a, title: t, events: {any_of: []}, likelihood_ratio: 2}", "at least 1"),
        ("- {id: a, check: web.errors, needs: [telepathy], likelihood_ratio: 2}", "web_access_log"),
        ("- {id: a, check: web.errors, needs: [web_error_log, web_error_log],"
         " likelihood_ratio: 2}", "listed twice"),
    ],
)  # fmt: skip
def test_what_a_detection_cant_say(detections, problem):
    with pytest.raises(PackError, match=problem):
        pack_with(detections + "\n")


# --- Matching --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("*", "", True),
        ("a*c", "abbbc", True),
        ("a*c", "abbbd", False),
        ("a?c", "abc", True),
        ("a?c", "ac", False),
        ("*child * exited*", "WARNING: child 12 exited on signal 11", True),
        ("[x]", "[x]", True),  # no character classes: brackets are themselves
        ("a.c", "abc", False),  # nor a dot
        ("*a*a*a*a*a*a*a*a*b", "a" * 3000, False),  # no runaway
    ],
)
def test_glob(pattern, text, expected):
    assert glob_match(pattern, text) is expected


@pytest.mark.parametrize(
    ("ratio", "band"),
    [(1.5, "low"), (4, "medium"), (19.9, "medium"), (20, "high"), (100, "critical")],
)
def test_a_detections_band_follows_its_ratio(ratio, band):
    assert _band(ratio) == band


# --- Events ----------------------------------------------------------------------------------


def test_a_burst_fires_once_with_its_events():
    pack = pack_with(CRASH)
    events = [crash(0), crash(4), crash(9), crash(30)]
    events.append(event("2026-10-22T10:05:00+00:00", "kernel.segfault", comm="php-fpm8.3"))
    # A prefix is the start: another program with it inside isn't one.
    events.append(event("2026-10-22T10:06:00+00:00", "kernel.segfault", comm="not-php-fpm"))
    (finding,) = own_detections(context(pack, events))
    assert finding.check == "pack.detection" and finding.variant == "example-2026-10/fpm-crash"
    assert finding.likelihood_ratio == 8 and finding.band == "medium"
    assert finding.summary.startswith("4 matching events within 10m (5 in all)")
    assert [e["event"] for e in finding.evidence] == [0, 1, 4, 2]  # in time order
    assert finding.first_seen.startswith("2026-10-22T10:00")


def test_too_few_or_spread_out_doesnt_fire():
    pack = pack_with(CRASH)
    assert own_detections(context(pack, [crash(0), crash(20), crash(40)])) == []


def test_only_while_the_host_was_exposed():
    pack = pack_with(CRASH)
    events = [crash(0), crash(1), crash(2)]
    assert own_detections(context(pack, events, exposed=False)) == []
    # Fixed before the crashes: they can't have exploited it.
    early = exposure(pack, until="2026-10-21T00:00:00+00:00")
    assert own_detections(context(pack, events, exposed=early)) == []
    # Before the window: not counted either.
    before = [event(f"2026-10-19T10:0{m}:00+00:00", "web.error", message="child 1 exited on"
                    " signal 11") for m in range(3)]  # fmt: skip
    assert own_detections(context(pack, before)) == []


def test_counted_apart_by_a_field_and_named_by_address():
    pack = pack_with(
        """\
        - id: errors
          title: 5xx bursts
          events:
            any_of: [{type: web.request, fields: {status: {glob: "5??"}}}]
            count: {at_least: 2, within: 1m}
            by: network
          likelihood_ratio: 4
        """
    )
    events = [
        event("2026-10-22T10:00:00+00:00", "web.request", status=502, network="203.0.113.0/24"),
        event("2026-10-22T10:00:10+00:00", "web.request", status=500, network="203.0.113.0/24"),
        event("2026-10-22T10:00:20+00:00", "web.request", status=500, network="198.51.100.0/24"),
        event("2026-10-22T10:00:30+00:00", "web.request", status=404, network="198.51.100.0/24"),
    ]
    (finding,) = own_detections(context(pack, events))
    assert "address:203.0.113.0/24" in finding.entities and finding.entities_complete


def test_list_values_match_any_element_and_missing_fields_never():
    pack = pack_with(
        """\
        - id: traversal
          title: Traversal
          events:
            any_of: [{type: web., fields: {attacks: {equals: traversal}}}]
          likelihood_ratio: 3
        """
    )
    events = [
        event("2026-10-22T10:00:00+00:00", "web.request", attacks=["sqli", "traversal"]),
        event("2026-10-22T10:00:01+00:00", "web.request"),
        event("2026-10-22T10:00:02+00:00", "web.error", attacks={"traversal": 1}),
    ]
    (finding,) = own_detections(context(pack, events))
    assert finding.evidence == [{"event": 0}]


# --- The snapshot ----------------------------------------------------------------------------

INI = """\
    - id: ini
      title: A .user.ini added to a web root
      snapshot:
        section: web_files
        key: {glob: "*/.user.ini"}
        state: {state}
      likelihood_ratio: 4
"""


def web_files(*paths, complete=True):
    return {"web_files": Section({p: {"size": 1} for p in paths}, complete)}


def test_present_and_absent():
    present = pack_with(INI.replace("{state}", "present"))
    (finding,) = own_detections(context(present, sections=web_files("/var/www/a/.user.ini")))
    assert finding.evidence == [{"item": ["web_files", "/var/www/a/.user.ini"]}]
    assert "path:/var/www/a/.user.ini" in finding.entities
    absent = pack_with(INI.replace("{state}", "absent"))
    assert own_detections(context(absent, sections=web_files("/var/www/a/.user.ini"))) == []
    assert len(own_detections(context(absent, sections=web_files("/var/www/a/x.php")))) == 1
    found = context(absent, sections=web_files(complete=False))
    assert own_detections(found) == [] and "absence can't be told" in found.gaps[0]


def test_added_since_the_baseline_needs_one():
    added = pack_with(INI.replace("{state}", "added"))
    sections = web_files("/var/www/a/.user.ini", "/var/www/b/.user.ini")
    diff = {"web_files": {"added": {"/var/www/b/.user.ini": {}}, "removed": {}, "changed": {},
                          "comparable": True, "notes": []}}  # fmt: skip
    (finding,) = own_detections(context(added, sections=sections, since_baseline=diff,
                                        baseline_id="b0"))  # fmt: skip
    assert finding.evidence == [{"change": ["b0", "web_files", "/var/www/b/.user.ini", "added"]}]
    none = context(added, sections=sections)
    assert own_detections(none) == [] and "needs a baseline" in none.gaps[0]


def test_a_section_not_collected_is_a_gap():
    found = context(pack_with(INI.replace("{state}", "present")))
    assert own_detections(found) == [] and "web_files not collected" in found.gaps[0]


# --- Needs -----------------------------------------------------------------------------------


def test_what_the_collection_lacks_is_a_gap_not_silence():
    pack = pack_with(
        """\
        - id: multipart
          title: Multipart POSTs to the site root
          needs: [web_access_log, request_content_type]
          events:
            any_of: [{type: web.request, fields: {method: {equals: POST}, path: {equals: /}}}]
          likelihood_ratio: 4
        """
    )
    found = context(pack, [event("2026-10-22T10:00:00+00:00", "web.request", method="POST",
                                 path="/")])  # fmt: skip
    assert own_detections(found) == []
    assert "web access logs (not chosen at setup)" in found.gaps[0]
    assert "content types" in found.gaps[0]


# --- References to core checks ---------------------------------------------------------------


def core(check="web.worker_child", first="2026-10-22T10:00:00+00:00", variant="history"):
    return {"check": check, "category": "compromise indicator", "band": "high",
            "variant": variant, "first_seen": first, "last_seen": first}  # fmt: skip


def test_a_core_finding_while_exposed_weighs_as_the_pack_says():
    pack = read(changed("likelihood_ratio: 20\n", "likelihood_ratio: 60\n"))
    found = [core(), core(first="2026-10-01T00:00:00+00:00"), core("web.errors")]
    raise_referenced(context(pack), found, [{"check": "web.worker_child", "status": "ran"}])
    assert ratio(found[0]) == 60 and found[0]["raised_by"] == "example-2026-10 v2 (worker-child)"
    assert ratio(found[1]) == 20 and "raised_by" not in found[1]  # before the window
    assert "raised_by" not in found[2]
    # Never lowered: the pack's 20 is the band's own.
    found = [core()]
    raise_referenced(context(read(GOOD.encode())), found, [{"check": "web.worker_child",
                                                           "status": "ran"}])  # fmt: skip
    assert "raised_by" not in found[0]


def test_a_finding_with_no_time_counts_while_still_exposed():
    pack = read(changed("likelihood_ratio: 20\n", "likelihood_ratio: 60\n"))
    found = [core(first=None)]
    raise_referenced(context(pack), found, [{"check": "web.worker_child", "status": "ran"}])
    assert ratio(found[0]) == 60
    found = [core(first=None)]
    fixed = exposure(pack, until="2026-10-25T00:00:00+00:00")
    raise_referenced(context(pack, exposed=fixed), found, [{"check": "web.worker_child",
                                                            "status": "ran"}])  # fmt: skip
    assert "raised_by" not in found[0]


def test_a_variant_narrows_and_a_check_that_didnt_run_is_a_gap():
    pack = read(changed("    check: web.worker_child\n    likelihood_ratio: 20\n",
                        "    check: web.worker_child\n    variant: live\n"
                        "    likelihood_ratio: 60\n"))  # fmt: skip
    found = [core(), core(variant="live")]
    raise_referenced(context(pack), found, [{"check": "web.worker_child", "status": "ran"}])
    assert "raised_by" not in found[0] and ratio(found[1]) == 60
    skipped = context(pack)
    raise_referenced(skipped, [], [{"check": "web.worker_child", "status": "no baseline yet"}])
    assert "web.worker_child no baseline yet" in skipped.gaps[0]


# --- An analysis -----------------------------------------------------------------------------


def test_an_analysis_scores_a_packs_own_detection(home):
    from checker.assess import analyze

    _, store, identity, config = home
    pack = pack_with(CRASH)
    lines = [
        rec("host_facts", "clock", localtime_link="/usr/share/zoneinfo/Etc/UTC"),
        rec("web_logs", "web_logs_summary", access_logs_opted_in=False, error_sent=1),
    ]
    from test_snapshot import text_source

    log = "".join(
        f"22-Oct-2026 10:0{m}:00] WARNING: [pool www] child {m} exited on signal 11 (SIGSEGV)\n"
        for m in range(3)
    )
    extra = (*lines, *text_source(9, "web_logs", "/var/log/php8.3-fpm.log", "[" + log.replace(
        "\n22", "\n[22")))  # fmt: skip
    add_bundle(home, "b1", 0, records("8.3.6-0ubuntu0.24.04.5", FIXED_AT, extra))
    assessment = analyze(store, "web01", identity, config.recipients, packs=[pack])
    (finding,) = [f for f in assessment["findings"] if f["check"] == "pack.detection"]
    assert finding["likelihood_ratio"] == 8 and finding["contribution"] > 0
    assert any(c["check"] == "pack.detection" for c in assessment["score"]["contributors"])
