"""A pack's detections (decision D1, plan 4.5), judged while the host was
exposed to the pack's threat (checker/packs/exposure.py): from when it
became exposed in the window until the fix (or the collection, if still
exposed). A host the pack doesn't affect gets nothing from its detections.

- A detection naming a check built into the tool raises that check's
  findings to the pack's ratio when they fall in that time (a finding
  with no time of its own counts if the host is exposed still).
- The pack's own rules: over events (the matchers' events in that time;
  at least so many within a span, counted apart for each value of `by`),
  and over the snapshot (items present or absent now, or added, changed or
  removed since the baseline, while the host was exposed).

Values are matched as text, never by a regular expression: exactly, by
prefix, or by a glob, whose matching is linear in the text for each `*`
(no backtracking beyond the last one). A detection whose `needs` the
collection lacks, or that needs a baseline there isn't, is a coverage
gap, not a silent miss."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from checker.checks import COMPROMISE, Context, Finding, parse_time, span
from checker.packs.format import Detection, EventRule, Match, Pack, SnapshotRule, span_seconds

MAX_TEXT = 4096  # a value longer than this is matched on its start only
MAX_LIST = 100  # of a list value's elements, the first this many are matched
MAX_FINDINGS = 20  # per detection: the rest are counted in the last one's gap
MAX_EVIDENCE = 50
MAX_KEYS = 10  # items named in one snapshot finding


def glob_match(pattern: str, text: str) -> bool:
    """`*` any run of characters (none too), `?` exactly one; all else as
    itself. Greedy with one remembered star: at most len(text) steps per
    star."""
    p = t = 0
    star = -1
    resume = 0
    while t < len(text):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p, t = p + 1, t + 1
        elif p < len(pattern) and pattern[p] == "*":
            star, resume = p, t
            p += 1
        elif star >= 0:
            p = star + 1
            resume += 1
            t = resume
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _as_text(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)[:MAX_TEXT]
    return None


def matches(match: Match, value: Any) -> bool:
    """A value against a matcher; a list matches if any element does; a
    missing value, or one that isn't text or a number, never matches."""
    if isinstance(value, (list, tuple)):
        return any(matches(match, v) for v in value[:MAX_LIST])
    text = _as_text(value)
    if text is None:
        return False
    if match.equals is not None:
        return text == match.equals
    if match.prefix is not None:
        return text.startswith(match.prefix)
    return glob_match(match.glob or "", text)


def _event_value(event: Any, name: str) -> Any:
    return event.program if name == "program" else event.fields.get(name)


def _interval(exposure: Any) -> tuple[datetime, datetime | None] | None:
    """When the host was exposed: (from, until); until None while it still
    is. None if it never was."""
    start = parse_time(exposure.exposed_from)
    if start is None:
        return None
    return start, parse_time(exposure.exposed_until)


def _inside(when: datetime | None, interval: tuple[datetime, datetime | None]) -> bool:
    start, end = interval
    return when is not None and when >= start and (end is None or when <= end)


def needs_missing(context: Context, need: str) -> str | None:
    """Why the collection lacks what a detection needs, or None."""
    live = context.snapshot.live
    web = live.get("web_logs_summary") or {}
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
    return None


def _named(pack: Pack, detection: Detection) -> str:
    return f"pack {pack.id} v{pack.version}: detection {detection.id}"


def _band(ratio: float) -> str:
    return (
        "critical" if ratio >= 100 else "high" if ratio >= 20 else "medium" if ratio >= 4 else "low"
    )


def _exposed(context: Context) -> list[tuple[Pack, Any, tuple[datetime, datetime | None]]]:
    packs = {p.id: p for p in context.packs}
    found = []
    for exposure in context.exposures:
        pack = packs.get(exposure.pack_id)
        interval = _interval(exposure)
        if pack is not None and interval is not None:
            found.append((pack, exposure, interval))
    return found


def own_detections(context: Context) -> list[Finding]:
    """The packs' own rules over events and the snapshot, while exposed."""
    findings: list[Finding] = []
    for pack, _, interval in _exposed(context):
        for detection in pack.detections:
            if detection.check is not None:
                continue
            missing = [m for m in (needs_missing(context, n) for n in detection.needs) if m]
            if missing:
                context.gaps.append(
                    f"{_named(pack, detection)} needs {', '.join(missing)}: not judged"
                )
                continue
            if detection.events is not None:
                findings += _events(context, pack, detection, detection.events, interval)
            elif detection.snapshot is not None:
                findings += _snapshot(context, pack, detection, detection.snapshot)
    return findings


def _finding(pack: Pack, detection: Detection, summary: str, **more: Any) -> Finding:
    ratio = detection.likelihood_ratio
    return Finding(
        "pack.detection",
        detection.title or detection.id,
        COMPROMISE,
        _band(ratio),
        f"{summary} ({pack.id} v{pack.version}, while the host was exposed)",
        variant=f"{pack.id}/{detection.id}",
        likelihood_ratio=ratio,
        **more,
    )


def _events(
    context: Context, pack: Pack, detection: Detection, rule: EventRule, interval
) -> list[Finding]:
    types = tuple(dict.fromkeys(m.type for m in rule.any_of))
    groups: dict[str, list[tuple[datetime, int, Any]]] = {}
    for index, event in context.of(*types):
        when = parse_time(event.corrected)
        if not _inside(when, interval):
            continue
        if not any(_event_matches(m, event) for m in rule.any_of):
            continue
        group = "" if rule.by is None else (_as_text(_event_value(event, rule.by)) or "unknown")
        groups.setdefault(group, []).append((when, index, event))
    within = span_seconds(rule.count.within) if rule.count.within else None
    findings = []
    for group in sorted(groups):
        found = sorted(groups[group], key=lambda x: (x[0], x[1]))
        best = _densest(found, within)
        if len(best) < rule.count.at_least:
            continue
        if len(findings) == MAX_FINDINGS:
            context.gaps.append(
                f"{_named(pack, detection)}: more than {MAX_FINDINGS} groups fired; the rest"
                " aren't listed"
            )
            break
        events = [e for _, _, e in best]
        first, last = span(events)
        where = f" from {group}" if rule.by is not None else ""
        how = f" within {rule.count.within}" if rule.count.within else ""
        address = rule.by in ("network", "client", "address") and group != "unknown"
        findings.append(
            _finding(
                pack,
                detection,
                f"{len(best)} matching events{how}{where} ({len(found)} in all)",
                entities=[f"pack:{pack.id}", *([f"address:{group}"] if address else [])],
                evidence=[{"event": i} for _, i, _ in best[:MAX_EVIDENCE]],
                first_seen=first,
                last_seen=last,
                entities_complete=rule.by is None or address,
            )
        )
    return findings


def _event_matches(matcher: Any, event: Any) -> bool:
    kind = matcher.type
    if not (event.type == kind or (kind.endswith(".") and event.type.startswith(kind))):
        return False
    return all(matches(m, _event_value(event, name)) for name, m in matcher.fields.items())


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


def _item_matches(rule: Any, key: str, item: Any) -> bool:
    if rule.key is not None and not matches(rule.key, key):
        return False
    item = item if isinstance(item, dict) else {}
    return all(matches(m, item.get(name)) for name, m in rule.fields.items())


def _snapshot(
    context: Context, pack: Pack, detection: Detection, rule: SnapshotRule
) -> list[Finding]:
    section = context.snapshot.sections.get(rule.section)
    if section is None:
        context.gaps.append(f"{_named(pack, detection)}: {rule.section} not collected")
        return []
    if rule.state in ("present", "absent"):
        keys = [k for k, item in sorted(section.items.items()) if _item_matches(rule, k, item)]
        if rule.state == "absent":
            if keys:
                return []
            if not section.complete:
                context.gaps.append(
                    f"{_named(pack, detection)}: {rule.section} not fully collected, so an"
                    " absence can't be told"
                )
                return []
            return [_finding(pack, detection, f"nothing like it in {rule.section}",
                             entities=[f"pack:{pack.id}"])]  # fmt: skip
        evidence = [{"item": [rule.section, k]} for k in keys]
    else:
        diff = context.changes(rule.section)
        if diff is None:
            context.gaps.append(
                f"{_named(pack, detection)} needs a baseline: {context.no_baseline}"
            )
            return []
        current = section.items
        keys = []
        for key in sorted(diff.get(rule.state) or {}):
            item = diff["removed"][key] if rule.state == "removed" else current.get(key)
            if _item_matches(rule, key, item):
                keys.append(key)
        evidence = [context.change_ref(rule.section, k, rule.state) for k in keys]
    if not keys:
        return []
    shown = ", ".join(keys[:MAX_KEYS]) + (
        f" and {len(keys) - MAX_KEYS} more" if len(keys) > MAX_KEYS else ""
    )
    paths = [f"path:{k}" for k in keys[:MAX_KEYS] if k.startswith("/")]
    return [
        _finding(
            pack,
            detection,
            f"{rule.section} {rule.state}: {shown}",
            entities=[f"pack:{pack.id}", *paths],
            evidence=evidence[:MAX_EVIDENCE],
            uncertain=context.uncertain(rule.section),
            entities_complete=len(paths) == len(keys),
        )
    ]


def raise_referenced(
    context: Context, found: list[dict[str, Any]], ran: list[dict[str, Any]]
) -> None:
    """Findings of a check a pack names, in the time the host was exposed,
    weigh as the pack says (if more than they would); the finding records
    which pack raised it. A check that didn't run, or whose needs the
    collection lacks, is a coverage gap."""
    from checker.scoring import ratio

    status = {r["check"]: r.get("status") for r in ran}
    for pack, _, interval in _exposed(context):
        for detection in pack.detections:
            if detection.check is None:
                continue
            missing = [m for m in (needs_missing(context, n) for n in detection.needs) if m]
            if missing:
                context.gaps.append(
                    f"{_named(pack, detection)} needs {', '.join(missing)}: not judged"
                )
                continue
            if status.get(detection.check) != "ran":
                why = status.get(detection.check) or "not a check this version has"
                context.gaps.append(f"{_named(pack, detection)}: {detection.check} {why}")
                continue
            for finding in found:
                if finding["check"] != detection.check or finding["category"] != COMPROMISE:
                    continue
                if detection.variant is not None and finding.get("variant") != detection.variant:
                    continue
                if not _overlaps(finding, interval):
                    continue
                if detection.likelihood_ratio > ratio(finding):
                    finding["likelihood_ratio"] = detection.likelihood_ratio
                    finding["raised_by"] = f"{pack.id} v{pack.version} ({detection.id})"


def _overlaps(finding: dict[str, Any], interval: tuple[datetime, datetime | None]) -> bool:
    """A finding's time against the exposed time; one with no time (what
    the host shows now) counts while the host is exposed still."""
    first = parse_time(finding.get("first_seen")) or parse_time(finding.get("last_seen"))
    last = parse_time(finding.get("last_seen")) or first
    start, end = interval
    if first is None or last is None:
        return end is None
    return last >= start and (end is None or first <= end)
