"""Rewrite the golden expectations (tests/golden/*.expected.json) from the
current checks and scoring, and show what moved: each case's probability
before and after, and findings added or gone. Run after a deliberate
change; commit the new expectations with it."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests" / "integration"))

import golden  # noqa: E402


def key(finding: dict) -> tuple:
    return (finding["check"], finding["band"], finding["summary"])


def main() -> int:
    for path in golden.cases():
        before_path = golden.expected_path(path)
        before = json.loads(before_path.read_text()) if before_path.exists() else None
        after = golden.write_expected(path)
        name = path.name.removesuffix(".json.gz")
        if before is None:
            print(f"{name}: new, {after['score']['probability']:.4f} {after['score']['band']}")
            continue
        was, now = before["score"], after["score"]
        print(
            f"{name}: {was['probability']:.4f} {was['band']}"
            f" -> {now['probability']:.4f} {now['band']}"
        )
        old = {key(f) for f in before["findings"]}
        new = {key(f) for f in after["findings"]}
        for f in sorted(new - old):
            print(f"  + {f[1]:8} {f[0]}: {f[2][:100]}")
        for f in sorted(old - new):
            print(f"  - {f[1]:8} {f[0]}: {f[2][:100]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
