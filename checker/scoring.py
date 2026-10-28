"""Scoring (DESIGN.md §11): how likely it is that a host is compromised,
from its findings' likelihood ratios.

    log-odds = log-odds(prior) + Σ contributions
    probability = 1 / (1 + e^-log-odds)

Each compromise-indicator finding contributes the log of its likelihood
ratio: how much more likely it is on a compromised host than on a clean
one. Hygiene and exposure findings are rated separately and never move the
probability (DESIGN.md §2 principle 9).

The ratios live here and only here, so calibration changes one table and
the golden reports show the effect."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

SCORING_VERSION = 1

DEFAULT_PRIOR = 0.02  # DESIGN.md §11.2

# Default likelihood ratio by band (DESIGN.md §11.1).
BAND_RATIOS = {"critical": 100.0, "high": 20.0, "medium": 4.0, "low": 1.5, "info": 1.0}

# Per-check overrides, (check, variant) -> ratio, where calibration shows a
# check's band misjudges it (2.10). A variant of None covers the whole check.
OVERRIDES: dict[tuple[str, str | None], float] = {}

# The most that the rest of a group, or of a family, can add to its
# strongest finding: one behaviour seen by several checks, or one check
# firing many times, is still about one thing (DESIGN.md §11.3).
EXTRA = math.log(2)

# A finding that may be wrong (its section wasn't fully collected) counts
# half its log ratio.
UNCERTAIN_WEIGHT = 0.5

# Entities that name one concrete thing on the host: findings sharing one
# are one behaviour seen by several checks (a set-user-ID shell in /tmp is
# both a scratch-place program and a privileged file). Accounts and program
# names are left out: a new key for root and a direct root login are two
# signals, not one.
GROUPING_ENTITIES = ("path:", "pid:")

# Probability bands (DESIGN.md §11.4), highest first.
PROBABILITY_BANDS = ((0.90, "Critical"), (0.50, "High"), (0.10, "Elevated"), (0.0, "Low"))

COMPROMISE = "compromise indicator"


def ratio(finding: dict[str, Any]) -> float:
    if finding.get("maintenance"):
        # Planned work explains it, whatever its check's override says.
        return BAND_RATIOS["info"]
    for key in ((finding["check"], finding.get("variant")), (finding["check"], None)):
        if key in OVERRIDES:
            return OVERRIDES[key]
    return BAND_RATIOS[finding["band"]]


def logit(p: float) -> float:
    return math.log(p / (1 - p))


def probability_band(probability: float) -> str:
    return next(name for floor, name in PROBABILITY_BANDS if probability >= floor)


def score(findings: list[dict[str, Any]], prior: float = DEFAULT_PRIOR) -> dict[str, Any]:
    """The score of one assessment's findings (dicts, as stored). Sets
    `ratio` and `contribution` on each finding and returns the score:
    prior, log-odds, probability, band, contributors (largest first) and
    the separate hygiene and exposure rating."""
    if not 0 < prior < 1:
        raise ValueError(f"a prior must be between 0 and 1, not {prior}")
    counted = []
    for index, finding in enumerate(findings):
        finding["ratio"] = ratio(finding)
        finding["contribution"] = 0.0
        if finding["category"] != COMPROMISE or finding.get("suppressed_by"):
            continue
        weight = math.log(finding["ratio"])
        if weight <= 0:
            continue
        if finding.get("uncertain"):
            weight *= UNCERTAIN_WEIGHT
        counted.append(index)
        finding["contribution"] = weight
    capped = _apply_caps(findings, counted)
    log_odds = logit(prior) + sum(findings[i]["contribution"] for i in counted)
    probability = 1 / (1 + math.exp(-log_odds))
    total = sum(findings[i]["contribution"] for i in counted)
    contributors = sorted(
        (
            {
                "finding": i,
                "check": findings[i]["check"],
                "title": findings[i]["title"],
                "ratio": findings[i]["ratio"],
                "contribution": round(findings[i]["contribution"], 4),
                "share": round(findings[i]["contribution"] / total, 4) if total else 0.0,
                "capped": capped.get(i),
            }
            for i in counted
            if findings[i]["contribution"] > 0
        ),
        key=lambda c: (-c["contribution"], c["finding"]),
    )
    for finding in findings:
        finding["contribution"] = round(finding["contribution"], 4)
    return {
        "version": SCORING_VERSION,
        "prior": prior,
        "log_odds": round(log_odds, 4),
        "probability": round(probability, 4),
        "band": probability_band(probability),
        "contributors": contributors,
        "hygiene_and_exposure": _rating(findings),
    }


def _key(finding: dict[str, Any]) -> tuple:
    """Content, never list position: the score mustn't depend on the order
    findings come in."""
    return (
        -finding["contribution"],
        finding["check"],
        finding.get("summary") or "",
        finding["title"],
        tuple(finding.get("entities") or ()),
    )


def _apply_caps(findings: list[dict[str, Any]], counted: list[int]) -> dict[int, str]:
    """Groups first: each group (findings about one file or process) is one
    behaviour, led by its strongest finding, the rest adding at most EXTRA.
    Then families, over the leads only: one check's leads add at most EXTRA
    beyond its strongest. A lead is chosen, among equally strong members,
    from the check with the fewest other leads, so a second, separate
    behaviour of that check isn't cut because the first was also seen by
    another check. Returns which findings a cap cut, and which cap."""
    by_check: dict[str, int] = defaultdict(int)
    for i in counted:
        by_check[findings[i]["check"]] += 1
    capped: dict[int, str] = {}
    leads = []
    for members in _groups(findings, counted):
        outside = {
            i: by_check[findings[i]["check"]]
            - sum(findings[m]["check"] == findings[i]["check"] for m in members)
            for i in members
        }
        ordered = sorted(
            members,
            key=lambda i: (-findings[i]["contribution"], outside[i], *_key(findings[i])[1:]),
        )
        leads.append(ordered[0])
        capped.update(dict.fromkeys(_cap(findings, ordered), "group"))
    families = defaultdict(list)
    for i in leads:
        families[findings[i]["check"]].append(i)
    for members in families.values():
        ordered = sorted(members, key=lambda i: _key(findings[i]))
        capped.update(dict.fromkeys(_cap(findings, ordered), "family"))
    return capped


def _groups(findings: list[dict[str, Any]], counted: list[int]) -> list[list[int]]:
    """Counted findings joined by a shared path or process (transitively);
    a finding sharing neither is a group of its own."""
    parent = {i: i for i in counted}

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    holder: dict[str, int] = {}
    for i in counted:
        for entity in findings[i].get("entities") or []:
            if entity.startswith(GROUPING_ENTITIES):
                if entity in holder:
                    parent[root(i)] = root(holder[entity])
                else:
                    holder[entity] = i
    groups = defaultdict(list)
    for i in counted:
        groups[root(i)].append(i)
    return list(groups.values())


def _cap(findings: list[dict[str, Any]], ordered: list[int]) -> list[int]:
    """Let the rest of `ordered` (strongest first) add at most EXTRA beyond
    the first, scaled down evenly. Returns the ones it cut."""
    rest = ordered[1:]
    extra = sum(findings[i]["contribution"] for i in rest)
    if extra <= EXTRA:
        return []
    scale = EXTRA / extra
    for i in rest:
        findings[i]["contribution"] *= scale
    return rest


def percent(probability: float) -> str:
    """A probability as people read it, never rounded up across a band's
    edge (0.4999 is 49%, Elevated, not 50%), and small priors not shown as
    0%."""
    if probability >= 0.01:
        return f"{math.floor(probability * 100)}%"
    if probability >= 0.001:
        return f"{math.floor(probability * 1000) / 10:g}%"
    return "<0.1%"


def _rating(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Hygiene and exposure, rated apart from the probability: the highest
    band among them, and how many of each."""
    order = list(BAND_RATIOS)
    counts: dict[str, dict[str, int]] = {}
    worst = None
    for finding in findings:
        category = finding["category"]
        if category == COMPROMISE or finding.get("suppressed_by"):
            continue
        band = finding["band"]
        counts.setdefault(category, {}).setdefault(band, 0)
        counts[category][band] += 1
        if band != "info" and (worst is None or order.index(band) < order.index(worst)):
            worst = band
    return {"band": worst or "none", "counts": counts}
