"""Exposure to the threats the packs in force describe (DESIGN.md §8.14,
plan 4.3): findings in the exposure category, rated apart from the
compromise probability; the exposure itself raises the prior instead
(checker/scoring.py). The judging is checker/packs/exposure.py."""

from __future__ import annotations

from datetime import datetime

from checker.checks import EXPOSURE, Context, Finding, check
from checker.packs.exposure import CANT_JUDGE, FIXED, NOT_COVERED, UNKNOWN_RELEASE, VULNERABLE
from checker.packs.mitigation import IN_PLACE, MISSING, NOT_SEEN, normal

MAX_PIDS = 10  # processes named in one stale-code finding


def _days(start: str, until: str | None, now: str | None) -> str:
    try:
        end = datetime.fromisoformat(until or now or start)
        seconds = (end - datetime.fromisoformat(start)).total_seconds()
    except (ValueError, TypeError):
        return "an unknown time"
    return f"{seconds / 86400:.1f} days"


@check("pack.detection", "A threat pack's own detection, while the host was exposed")
def detection(context: Context) -> list[Finding]:
    """The packs' own rules over events and the snapshot
    (checker/packs/detect.py); their references to core checks are applied
    after every check has run (checker/assess.py)."""
    from checker.packs.detect import own_detections

    return own_detections(context)


@check(
    "pack.exposure",
    "Exposure to a threat a pack describes",
    variants=("vulnerable", "cant_judge", "was_exposed", "stale_code", "mitigation_missing"),
)
def exposure(context: Context) -> list[Finding]:
    found = []
    for item in context.exposures:
        named = f"{item.pack_id} v{item.pack_version}"
        pack = f"pack:{item.pack_id}"
        if item.status in (NOT_COVERED, UNKNOWN_RELEASE):
            context.gaps.append(
                f"pack {named} has no entry for this host's release ({item.release})"
            )
            continue
        for judged in item.packages:
            entities = [f"package:{judged.name}", pack]
            if judged.status == VULNERABLE:
                against = f"the fix {judged.fixed}" if judged.fixed else "a fix (none released yet)"
                found.append(
                    Finding(
                        "pack.exposure",
                        "A package is vulnerable to a threat a pack describes",
                        EXPOSURE,
                        "high",
                        f"{judged.name} {judged.version} is before {against} ({named})",
                        entities,
                        [{"item": ["packages", judged.key]}],
                        variant="vulnerable",
                    )
                )
            elif judged.status == CANT_JUDGE:
                found.append(
                    Finding(
                        "pack.exposure",
                        "A package's version can't be judged against a threat pack",
                        EXPOSURE,
                        "medium",
                        f"{judged.name} {judged.version}: {judged.why} ({named}); counted as"
                        " exposed",
                        entities,
                        [{"item": ["packages", judged.key]}],
                        variant="cant_judge",
                    )
                )
        if item.status == CANT_JUDGE and not any(p.status == CANT_JUDGE for p in item.packages):
            context.gaps.append(
                f"pack {named}: the package listing wasn't collected whole, so a vulnerable"
                " package may be missing from it; counted as exposed"
            )
            found.append(
                Finding(
                    "pack.exposure",
                    "A package's version can't be judged against a threat pack",
                    EXPOSURE,
                    "medium",
                    f"the package listing wasn't collected whole ({named}): counted as exposed",
                    [pack],
                    [],
                    variant="cant_judge",
                )
            )
        if item.status == FIXED and item.exposed_from:
            found.append(_was_exposed(item, named, pack, context.collected_at))
        if item.stale:
            found.append(_stale(item, named, pack))
        found += _mitigations(item, named, pack, context)
    return found


def _mitigations(item, named: str, pack: str, context: Context) -> list[Finding]:
    """A pack's mitigation not in place: high while the host is vulnerable
    or can't be judged (the fix isn't known to be there), medium once
    fixed (a mitigation can also cover a flaw not yet fixed)."""
    found = []
    for mitigation in item.mitigations:
        if mitigation.status == NOT_SEEN:
            context.gaps.append(
                f"pack {named}: mitigation {mitigation.id} not seen ({mitigation.why})"
            )
            continue
        if mitigation.status == IN_PLACE:
            # The sites' .user.ini and .htaccess in the web roots walked are
            # among the settings read (plan 4.4c); others, and ini_set, aren't.
            context.gaps.append(
                f"pack {named}: mitigation {mitigation.id} is in place in the settings read;"
                " a site outside the web roots examined (its .user.ini or .htaccess), or an"
                " application changing it as it runs (ini_set), could set it back, and those"
                " aren't seen"
            )
            continue
        if mitigation.status != MISSING:
            continue
        wrong = [p for p in mitigation.places if normal(p.value) != normal(mitigation.expect)]
        shown = "; ".join(
            f"{p.where}: {p.value}"
            + (" (PHP's default: set in no file)" if p.source == "PHP's default" else "")
            for p in wrong[:5]
        )
        found.append(
            Finding(
                "pack.exposure",
                "A threat pack's mitigation isn't in place",
                EXPOSURE,
                "high" if item.status in (VULNERABLE, CANT_JUDGE) else "medium",
                f"{mitigation.setting} should be {mitigation.expect} ({mitigation.id}, {named}):"
                f" {shown}",
                [f"setting:{mitigation.setting}", pack],
                [],
                variant="mitigation_missing",
            )
        )
    return found


def _was_exposed(item, named: str, pack: str, collected_at: str | None) -> Finding:
    if item.exposed_until is None:
        why = (
            "a service still runs code from before the fix"
            if item.stale
            else "when the fix was installed isn't known"
        )
        summary = f"exposed from {item.exposed_from[:16]}, and still taken to be: {why} ({named})"
    elif item.fix_time_exact:
        what = (
            f"the vulnerable package was removed at {item.removed_at[:16]}"
            if item.removed_at
            else f"the fix was installed at {(item.fixed_at or '')[:16]}"
        )
        closed = (
            item.window_end
            and item.exposed_until
            and item.exposed_until < (item.removed_at or item.fixed_at or "")
        )
        until = (
            f"until the window closed at {item.exposed_until[:16]} ({what}, after it)"
            if closed
            else f"until {what}"
        )
        summary = (
            f"exposed from {item.exposed_from[:16]} {until} (the package history):"
            f" {_days(item.exposed_from, item.exposed_until, collected_at)},"
            f" {round(item.share * 100)}% of the window so far ({named})"
        )
    else:
        closed = bool(item.window_end and item.fixed_at and item.fixed_at > item.window_end)
        ending = (
            f"until the window closed at {item.exposed_until[:16]} (the fix was installed after"
            " it, at the latest at its last install or update)"
            if closed
            else f"until the fix was installed, by {item.exposed_until[:16]} at the latest (its"
            " last install or update; it may have come earlier)"
        )
        summary = (
            f"exposed from {item.exposed_from[:16]} {ending}: at most"
            f" {_days(item.exposed_from, item.exposed_until, collected_at)},"
            f" {round(item.share * 100)}% of the window so far ({named})"
        )
    return Finding(
        "pack.exposure",
        "The host was exposed to a threat while it was active",
        EXPOSURE,
        "low",
        summary,
        [pack],
        [{"item": ["packages", p.key]} for p in item.packages],
        variant="was_exposed",
    )


def _stale(item, named: str, pack: str) -> Finding:
    """One finding for every process of the pack's services still on old
    code (a pool of PHP workers is one service)."""
    pids = [p.get("pid") for p in item.stale]
    programs = sorted({str(p.get("comm")) for p in item.stale})
    starts = sorted(str(p.get("start_time")) for p in item.stale if p.get("start_time"))
    replaced = any(p.get("exe_deleted") for p in item.stale)
    shown = ", ".join(str(pid) for pid in pids[:MAX_PIDS])
    more = f" and {len(pids) - MAX_PIDS} more" if len(pids) > MAX_PIDS else ""
    how = (
        ": its program file was replaced under it"
        if replaced
        else " started before the fixed package's current version was installed: it runs older code"
        " than installed, from before the fix unless the fix came earlier"
    )
    return Finding(
        "pack.exposure",
        "A service may still run code from before a threat's fix",
        EXPOSURE,
        "high" if replaced else "medium",
        f"{', '.join(programs)} (pid {shown}{more}){how}; restart it ({named})",
        [*(f"program:{p}" for p in programs), *(f"pid:{pid}" for pid in pids), pack],
        [{"live": ["processes", pid]} for pid in pids[:MAX_PIDS]],
        starts[0] if starts else None,
        starts[-1] if starts else None,
        variant="stale_code",
    )
