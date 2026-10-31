"""A pack's detections (decision D1, plan 4.5), for a host its threat
reached (checker/packs/exposure.py). Each counts either while the host ran
a vulnerable version, from its exposure in the window to the fix or the
window's end (`counts: while_exposed`: an attack attempt, harmless once
fixed), or from that exposure on to the collection, fix or not
(`since_exposed`, the default: someone already inside stays). A host the
pack doesn't affect, or one whose exposure is only a package listing
collected in part, gets nothing from its detections.

- A detection naming a check built into the tool raises that check's
  compromise findings to the pack's ratio when they fall in that time
  (a finding with no time of its own: when the time runs to the
  collection). Never lowered; never a pack's own check.
- The pack's own rules: over events (the matchers' events in that time;
  at least so many within a span, counted apart for each value of `by`),
  and over the snapshot (items present or absent now, when the time runs
  to the collection; or added, changed or removed since a baseline taken
  before it ended).

Values are matched as text, never by a regular expression: exactly, by
prefix, or by a glob, matched segment by segment between its `*`s, each
at its leftmost place (str.find); the work is counted against a budget
for the whole analysis, and past it the detections stop, with a coverage
gap saying so. A detection whose data the collection lacks (what it says
it needs, and the logs its event types come from), or that needs a
baseline there isn't, is a coverage gap, not a silent miss."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from checker.checks import COMPROMISE, Context, Finding, parse_time, span
from checker.packs.format import Detection, EventRule, Match, Pack, SnapshotRule, span_seconds

MAX_TEXT = 65536  # a value longer than this is matched on its start only
MAX_LIST = 100  # of a list value's elements, the first this many are matched
MAX_FINDINGS = 20  # per detection; more groups are a coverage gap
MAX_EVIDENCE = 50
MAX_KEYS = 10  # items named in one snapshot finding
# Matching work for one analysis, in characters looked at (str.find's
# counted at a sixteenth: it runs in C).
BUDGET = 20_000_000
# Event types a rule can only see through one log: needed whether or not
# the pack says so.
IMPLIED_NEEDS = {
    "web.request": "web_access_log",
    "web.error": "web_error_log",
    "process.exec": "process_starts",
}


class _OverBudget(Exception):
    pass


class Budget:
    def __init__(self, steps: int | None = None) -> None:
        self.left = BUDGET if steps is None else steps

    def spend(self, steps: int) -> None:
        self.left -= steps
        if self.left < 0:
            raise _OverBudget()


def _at(segment: str, text: str, i: int) -> bool:
    """`segment` (with `?` for any one character) at text[i:]."""
    if i < 0 or i + len(segment) > len(text):
        return False
    if "?" not in segment:
        return text.startswith(segment, i)
    return all(c == "?" or text[i + k] == c for k, c in enumerate(segment))


def _find(segment: str, text: str, start: int, end: int, budget: Budget | None) -> int:
    """The leftmost place at or after `start` where `segment` fits whole
    before `end`, or -1."""
    if "?" not in segment:
        return text.find(segment, start, end)
    pieces = [p for p in segment.split("?") if p]
    if not pieces:
        return start if end - start >= len(segment) else -1
    anchor = max(pieces, key=len)
    offset = segment.index(anchor)
    j = text.find(anchor, start + offset, end - (len(segment) - offset - len(anchor)))
    while j >= 0:
        if budget is not None:
            budget.spend(len(segment))
        if _at(segment, text, j - offset):
            return j - offset
        j = text.find(anchor, j + 1, end - (len(segment) - offset - len(anchor)))
    return -1


def glob_match(pattern: str, text: str, budget: Budget | None = None) -> bool:
    """`*` any run of characters (none too), `?` exactly one; all else as
    itself. Between the `*`s, each segment has a fixed length, so placing
    each at its leftmost fit is right: a later one only needs room after."""
    if budget is not None:
        budget.spend(len(text) // 16 + 1)
    parts = pattern.split("*")
    if len(parts) == 1:
        return len(text) == len(pattern) and _at(pattern, text, 0)
    first, middle, last = parts[0], parts[1:-1], parts[-1]
    if len(first) + len(last) > len(text):
        return False
    if not _at(first, text, 0) or not _at(last, text, len(text) - len(last)):
        return False
    position, end = len(first), len(text) - len(last)
    for segment in middle:
        if not segment:
            continue
        found = _find(segment, text, position, end, budget)
        if found < 0:
            return False
        position = found + len(segment)
    return True


def _as_text(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)[:MAX_TEXT]
    return None


def matches(match: Match, value: Any, budget: Budget | None = None) -> bool:
    """A value against a matcher; a list matches if any element does; a
    missing value, or one that isn't text or a number, never matches."""
    if isinstance(value, (list, tuple)):
        return any(matches(match, v, budget) for v in value[:MAX_LIST])
    text = _as_text(value)
    if text is None:
        return False
    if match.equals is not None:
        return text == match.equals
    if match.prefix is not None:
        return text.startswith(match.prefix)
    return glob_match(match.glob or "", text, budget)


def _event_value(event: Any, name: str) -> Any:
    return event.program if name == "program" else event.fields.get(name)


Interval = tuple[datetime, datetime | None]


def _interval(exposure: Any, start: datetime, detection: Detection) -> Interval:
    """When a detection counts: (from, until); until None: to the
    collection."""
    if detection.counts == "since_exposed":
        return start, None
    end = parse_time(exposure.exposed_until)
    closed = parse_time(exposure.window_end)
    if closed is not None and (end is None or closed < end):
        end = closed
    return start, end


def _inside(when: datetime, interval: Interval) -> bool:
    start, end = interval
    return when >= start and (end is None or when <= end)


def needs_missing(context: Context, need: str) -> str | None:
    """Why the collection lacks what a detection needs, or None."""
    live = context.snapshot.live
    web = live.get("web_logs_summary") or {}
    requests = live.get("web_requests") or {}
    lines = sum((requests.get("lines") or {}).values())
    unparsed = sum((requests.get("unparsed") or {}).values())
    if need in ("web_access_log", "web_error_log") and lines and unparsed * 2 > lines:
        return "web logs (most lines in a format not recognised)"
    if need == "web_access_log":
        if not web.get("access_logs_opted_in"):
            return "web access logs (not chosen at setup)"
        if not web.get("access_sent"):
            return "web access logs (none found)"
    elif need == "web_error_log":
        if not web.get("error_sent"):
            return "web error logs (none found)"
    elif need == "process_starts":
        starts = (live.get("exec_records_summary") or {}).get("starts")
        if live.get("exec_records_unavailable") or not starts:
            return "program starts from the audit log"
    elif need == "request_content_type":
        return "requests' content types (in no log format the tool reads)"
    elif need == "every_web_request":
        return "every web request (only 5xx, attacks, scripts and sensitive paths become events)"
    return None


def _named(pack: Pack, detection: Detection) -> str:
    return f"pack {pack.id} v{pack.version}: detection {detection.id}"


def _gap(context: Context, text: str) -> None:
    if text not in context.gaps:
        context.gaps.append(text)


def _band(ratio: float) -> str:
    return (
        "critical" if ratio >= 100 else "high" if ratio >= 20 else "medium" if ratio >= 4 else "low"
    )


def _exposed(context: Context) -> list[tuple[Pack, Any, datetime]]:
    """Packs whose threat reached the host. A "can't judge" with no package
    of the pack's found (only the listing collected in part) isn't
    enough: nothing says the host has what the threat needs."""
    from checker.packs.exposure import CANT_JUDGE

    packs = {p.id: p for p in context.packs}
    found = []
    for exposure in context.exposures:
        pack = packs.get(exposure.pack_id)
        start = parse_time(exposure.exposed_from)
        if pack is None or start is None:
            continue
        if exposure.status == CANT_JUDGE and not exposure.packages and not exposure.removed_at:
            continue
        found.append((pack, exposure, start))
    return found


def _blind(context: Context, pack: Pack, detection: Detection) -> bool:
    """Says what the collection lacks for a detection; True if that leaves
    it nothing to see (it isn't judged)."""
    declared = [m for m in (needs_missing(context, n) for n in detection.needs) if m]
    if declared:
        _gap(context, f"{_named(pack, detection)} needs {', '.join(declared)}: not judged")
        return True
    if detection.events is None:
        return False
    blind, lacking = 0, []
    for matcher in detection.events.any_of:
        kind = matcher.type
        covered = [
            need
            for event_type, need in IMPLIED_NEEDS.items()
            if event_type == kind or (kind.endswith(".") and event_type.startswith(kind))
        ]
        missing = [m for m in (needs_missing(context, n) for n in covered) if m]
        if covered and len(missing) == len(covered):
            blind += 1
            lacking += [m for m in missing if m not in lacking]
    if not blind:
        return False
    if blind == len(detection.events.any_of):
        _gap(context, f"{_named(pack, detection)} needs {', '.join(lacking)}: not judged")
        return True
    _gap(context, f"{_named(pack, detection)} judged in part: no {', '.join(lacking)}")
    return False


def own_detections(context: Context) -> list[Finding]:
    """The packs' own rules over events and the snapshot."""
    findings: list[Finding] = []
    budget = Budget()
    index: dict[str, list[tuple[int, Any]]] = {}
    for position, event in enumerate(context.events):
        if not event.own_session:
            index.setdefault(event.type, []).append((position, event))
    try:
        for pack, exposure, start in _exposed(context):
            for detection in pack.detections:
                if detection.check is not None or _blind(context, pack, detection):
                    continue
                interval = _interval(exposure, start, detection)
                if detection.events is not None:
                    findings += _events(context, pack, detection, detection.events, interval,
                                        index, budget)  # fmt: skip
                elif detection.snapshot is not None:
                    findings += _snapshot(context, pack, detection, detection.snapshot,
                                          interval, budget)  # fmt: skip
    except _OverBudget:
        _gap(context, "threat packs' detections stopped: matching them cost more than an"
                      " analysis allows (a pack's patterns against long values)")  # fmt: skip
    return findings


def _finding(pack: Pack, detection: Detection, summary: str, **more: Any) -> Finding:
    ratio = detection.likelihood_ratio
    when = "while the host was exposed" if detection.counts == "while_exposed" else (
        "since the host was exposed"
    )  # fmt: skip
    return Finding(
        "pack.detection",
        detection.title or detection.id,
        COMPROMISE,
        _band(ratio),
        f"{summary} ({pack.id} v{pack.version}, {when})",
        variant=f"{pack.id}/{detection.id}",
        likelihood_ratio=ratio,
        **more,
    )


def _of(index: dict[str, list[tuple[int, Any]]], kinds: list[str]) -> list[tuple[int, Any]]:
    found: dict[int, Any] = {}
    for kind in kinds:
        for event_type, events in index.items():
            if event_type == kind or (kind.endswith(".") and event_type.startswith(kind)):
                found.update(events)
    return sorted(found.items(), key=lambda x: x[0])


def _events(context: Context, pack: Pack, detection: Detection, rule: EventRule,
            interval: Interval, index: dict, budget: Budget) -> list[Finding]:  # fmt: skip
    groups: dict[str, list[tuple[datetime, int, Any]]] = {}
    untimed = 0
    for position, event in _of(index, [m.type for m in rule.any_of]):
        if not any(_event_matches(m, event, budget) for m in rule.any_of):
            continue
        when = parse_time(event.corrected)
        if when is None:
            untimed += 1
            continue
        if not _inside(when, interval):
            continue
        group = "" if rule.by is None else (_as_text(_event_value(event, rule.by)) or "unknown")
        groups.setdefault(group, []).append((when, position, event))
    if untimed:
        _gap(context, f"{_named(pack, detection)}: {untimed} matching events had no usable"
                      " time and weren't counted")  # fmt: skip
    within = span_seconds(rule.count.within) if rule.count.within else None
    findings = []
    for group in sorted(groups):
        found = sorted(groups[group], key=lambda x: (x[0], x[1]))
        best = _densest(found, within)
        if len(best) < rule.count.at_least:
            continue
        if len(findings) == MAX_FINDINGS:
            _gap(context, f"{_named(pack, detection)}: more than {MAX_FINDINGS} groups fired;"
                          " the rest aren't listed")  # fmt: skip
            break
        events = [e for _, _, e in best]
        first, last = span(events)
        where = f" from {group}" if rule.by is not None else ""
        how = f" within {rule.count.within}" if rule.count.within else ""
        address = rule.by in ("network", "client", "address") and group != "unknown"
        # The group is what the finding is about: named, so the same
        # group's finding is the same one in the next analysis, whatever
        # its counts (checker.schedule).
        named = [f"address:{group}" if address else f"{rule.by}:{group[:200]}"] if rule.by else []
        findings.append(
            _finding(
                pack,
                detection,
                f"{len(best)} matching events{how}{where} ({len(found)} in all)",
                entities=[f"pack:{pack.id}", *named],
                evidence=[{"event": i} for _, i, _ in best[:MAX_EVIDENCE]],
                first_seen=first,
                last_seen=last,
            )
        )
    return findings


def _event_matches(matcher: Any, event: Any, budget: Budget) -> bool:
    kind = matcher.type
    if not (event.type == kind or (kind.endswith(".") and event.type.startswith(kind))):
        return False
    return all(matches(m, _event_value(event, name), budget) for name, m in matcher.fields.items())


def _densest(found: list, within: int | None) -> list:
    """The most events inside any span of `within` seconds (all of them
    with no span), as the run of them."""
    if within is None:
        return found
    best_start = best_end = start = 0
    for end in range(len(found)):
        while (found[end][0] - found[start][0]).total_seconds() > within:
            start += 1
        if end - start > best_end - best_start:
            best_start, best_end = start, end
    return found[best_start : best_end + 1] if found else []


def _item_matches(rule: SnapshotRule, key: str, item: Any, budget: Budget) -> bool:
    if rule.key is not None and not matches(rule.key, key, budget):
        return False
    item = item if isinstance(item, dict) else {}
    return all(matches(m, item.get(name), budget) for name, m in rule.fields.items())


def _snapshot(context: Context, pack: Pack, detection: Detection, rule: SnapshotRule,
              interval: Interval, budget: Budget) -> list[Finding]:  # fmt: skip
    end = interval[1]
    if rule.state in ("present", "absent"):
        if end is not None:
            return []  # what the host shows now, after the time this counts in
    else:
        # A change since the baseline happened after it was taken.
        taken = parse_time(context.baseline_time)
        if end is not None and taken is not None and taken > end:
            return []
    section = context.snapshot.sections.get(rule.section)
    if section is None:
        _gap(context, f"{_named(pack, detection)}: {rule.section} not collected")
        return []
    if rule.state in ("present", "absent"):
        keys = [
            k for k, item in sorted(section.items.items()) if _item_matches(rule, k, item, budget)
        ]
        if rule.state == "absent":
            if keys:
                return []
            if not section.complete:
                _gap(context, f"{_named(pack, detection)}: {rule.section} not fully collected,"
                              " so an absence can't be told")  # fmt: skip
                return []
            return [_finding(pack, detection, f"nothing like it in {rule.section}",
                             entities=[f"pack:{pack.id}"])]  # fmt: skip
        evidence = [{"item": [rule.section, k]} for k in keys]
    else:
        diff = context.changes(rule.section)
        if diff is None:
            _gap(context, f"{_named(pack, detection)} needs a baseline: {context.no_baseline}")
            return []
        current = section.items
        keys = []
        for key in sorted(diff.get(rule.state) or {}):
            item = diff["removed"][key] if rule.state == "removed" else current.get(key)
            if _item_matches(rule, key, item, budget):
                keys.append(key)
        evidence = [context.change_ref(rule.section, k, rule.state) for k in keys]
    if not keys:
        return []
    more = f" and {len(keys) - MAX_KEYS} more" if len(keys) > MAX_KEYS else ""
    # Paths name what the finding is about, for whitelists; scoring never
    # groups a pack's findings by them (checker/scoring.py).
    paths = [f"path:{k}" for k in keys[:MAX_KEYS] if k.startswith("/")]
    return [
        _finding(
            pack,
            detection,
            f"{rule.section} {rule.state}: {', '.join(keys[:MAX_KEYS])}{more}",
            entities=[f"pack:{pack.id}", *paths],
            evidence=evidence[:MAX_EVIDENCE],
            uncertain=context.uncertain(rule.section),
            entities_complete=len(paths) == len(keys),
        )
    ]


def raise_referenced(
    context: Context, found: list[dict[str, Any]], ran: list[dict[str, Any]]
) -> None:
    """Findings of a check a pack names, in the time its detection counts,
    weigh as the pack says if more than they would, but at most one band
    up (low to medium's ratio, medium to high's, high to critical's: a
    pack can't make a check's everyday noise critical); the finding records
    which pack raised it. A check that didn't run, or whose needs the
    collection lacks, is a coverage gap."""
    from checker.scoring import BAND_RATIOS, ratio

    status = {r["check"]: r.get("status") for r in ran}
    for pack, exposure, start in _exposed(context):
        for detection in pack.detections:
            check = detection.check
            if check is None or check.startswith("pack.") or _blind(context, pack, detection):
                continue
            if status.get(check) != "ran":
                why = status.get(check) or "not a check this version has"
                _gap(context, f"{_named(pack, detection)}: {check} {why}")
                continue
            interval = _interval(exposure, start, detection)
            for finding in found:
                if finding["check"] != check or finding["category"] != COMPROMISE:
                    continue
                if detection.variant is not None and finding.get("variant") != detection.variant:
                    continue
                if not _overlaps(finding, interval):
                    continue
                own = ratio(finding)
                above = [r for r in BAND_RATIOS.values() if r > own]
                raised = min(detection.likelihood_ratio, min(above, default=own))
                if raised > own:
                    finding["likelihood_ratio"] = raised
                    finding["raised_by_pack"] = f"{pack.id} v{pack.version} ({detection.id})"


def _overlaps(finding: dict[str, Any], interval: Interval) -> bool:
    """A finding's time against when a detection counts; one with no time
    (what the host shows now) counts when that runs to the collection."""
    first = parse_time(finding.get("first_seen")) or parse_time(finding.get("last_seen"))
    last = parse_time(finding.get("last_seen")) or first
    start, end = interval
    if first is None or last is None:
        return end is None
    return last >= start and (end is None or first <= end)


def reference_problems(pack: Pack, checks: dict[str, Any]) -> list[str]:
    """What a pack's detections name that this version of the tool doesn't
    have: checks, their variants, snapshot sections (typos never match)."""
    from checker.snapshot import SECTIONS

    problems = []
    for detection in pack.detections:
        if detection.check is not None:
            known = checks.get(detection.check)
            if known is None:
                problems.append(f"detection {detection.id}: no check {detection.check}")
            elif detection.variant is not None and detection.variant not in known.variants:
                problems.append(
                    f"detection {detection.id}: {detection.check} has no variant"
                    f" {detection.variant}"
                )
        elif detection.snapshot is not None and detection.snapshot.section not in SECTIONS:
            problems.append(
                f"detection {detection.id}: no snapshot section {detection.snapshot.section}"
            )
    return problems
