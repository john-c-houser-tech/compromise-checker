"""Exposure to the threats the packs in force describe (DESIGN.md §8.14,
plan 4.3): findings in the exposure category, rated apart from the
compromise probability; the exposure itself raises the prior instead
(checker/scoring.py). The judging is checker/packs/exposure.py."""

from __future__ import annotations

from checker.checks import EXPOSURE, Context, Finding, check
from checker.packs.exposure import CANT_JUDGE, FIXED, NOT_COVERED, UNKNOWN_RELEASE, VULNERABLE


def _days(start: str, until: str | None, now: str | None) -> str:
    from datetime import datetime

    try:
        end = datetime.fromisoformat(until or now or start)
        seconds = (end - datetime.fromisoformat(start)).total_seconds()
    except ValueError:
        return ""
    return f"{seconds / 86400:.1f} days"


@check(
    "pack.exposure",
    "Exposure to a threat a pack describes",
    variants=("vulnerable", "cant_judge", "was_exposed", "stale_code"),
)
def exposure(context: Context) -> list[Finding]:
    found = []
    for item in context.exposures:
        named = f"{item.pack_id} v{item.pack_version}"
        if item.status in (NOT_COVERED, UNKNOWN_RELEASE):
            context.gaps.append(
                f"pack {named} has no entry for this host's release ({item.release or 'unknown'})"
            )
            continue
        for judged in item.packages:
            entities = [f"package:{judged.name}", f"pack:{item.pack_id}"]
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
                        f"{judged.name}'s installed version can't be read as its package manager"
                        f" reads versions ({named}): {judged.why}",
                        entities,
                        [{"item": ["packages", judged.key]}],
                        variant="cant_judge",
                        uncertain="the version in the package database isn't one the package"
                        " manager would accept",
                    )
                )
        if item.status == FIXED and item.exposed_from:
            found.append(
                Finding(
                    "pack.exposure",
                    "The host was exposed to a threat while it was active",
                    EXPOSURE,
                    "low",
                    f"exposed from {item.exposed_from[:16]} until the fix was installed, by"
                    f" {(item.exposed_until or '')[:16]} at the latest (its last install or"
                    f" update; it may have come earlier): at most"
                    f" {_days(item.exposed_from, item.exposed_until, context.collected_at)},"
                    f" {round(item.share * 100)}% of the window so far ({named})",
                    [f"pack:{item.pack_id}"],
                    [{"item": ["packages", p.key]} for p in item.packages],
                    variant="was_exposed",
                )
            )
        for process in item.stale:
            pid = process.get("pid")
            found.append(
                Finding(
                    "pack.exposure",
                    "A service may still run code from before a threat's fix",
                    EXPOSURE,
                    "medium",
                    f"{process.get('comm')} (pid {pid}) started"
                    f" {str(process.get('start_time'))[:16]}, before its package was last"
                    f" installed or updated ({(item.fixed_at or '')[:16]}): it runs older code"
                    f" than installed, from before the fix unless the fix came earlier; restart"
                    f" it ({named})",
                    [f"program:{process.get('comm')}", f"pid:{pid}", f"pack:{item.pack_id}"],
                    [{"live": ["processes", pid]}],
                    process.get("start_time"),
                    process.get("start_time"),
                    variant="stale_code",
                )
            )
    return found
