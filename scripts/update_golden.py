"""Rewrite the golden expectations (tests/golden/*.expected.json) from the
current checks and scoring, and show what moved: each case's log-odds and
probability before and after, findings added or gone, and ratios that
changed. Expectations whose case was deleted are removed. Run after a
deliberate change; commit the new expectations with it."""

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests" / "integration"))

import golden  # noqa: E402


def key(finding: dict) -> tuple:
    return (finding["check"], finding["band"], finding["summary"])


def main() -> int:
    for path in golden.orphans():
        path.unlink()
        print(f"{path.name}: removed (its case is gone)")
    for path in golden.cases():
        before_path = golden.expected_path(path)
        before = json.loads(before_path.read_text()) if before_path.exists() else None
        after = golden.write_expected(path)
        name = path.name.removesuffix(".json.gz")
        now = after["score"]
        if before is None:
            print(f"{name}: new, {now['probability']:.4f} {now['band']}")
            continue
        was = before["score"]
        print(
            f"{name}: log-odds {was['log_odds']:+.3f} -> {now['log_odds']:+.3f},"
            f" {was['probability']:.4f} {was['band']} -> {now['probability']:.4f} {now['band']}"
        )
        old = Counter(key(f) for f in before["findings"])
        new = Counter(key(f) for f in after["findings"])
        for f, n in sorted((new - old).items()):
            print(f"  + {n}x {f[1]:8} {f[0]}: {f[2][:100]}")
        for f, n in sorted((old - new).items()):
            print(f"  - {n}x {f[1]:8} {f[0]}: {f[2][:100]}")
        ratios_before = {
            (f["check"], f.get("variant"), f["band"]): f["ratio"] for f in before["findings"]
        }
        for f in after["findings"]:
            k = (f["check"], f.get("variant"), f["band"])
            if k in ratios_before and ratios_before[k] != f["ratio"]:
                print(f"  ratio {k[0]} {k[2]}: {ratios_before[k]:g} -> {f['ratio']:g}")
                ratios_before.pop(k)
    return 0


if __name__ == "__main__":
    sys.exit(main())
