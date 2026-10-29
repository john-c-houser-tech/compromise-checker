"""Calibration (plan 2.10): run the read-only proof on all seven images and
the detection proof on Ubuntu 24.04 and Rocky 9, gather each run's
assessment, and write the results table into docs/scoring.md.

Asserts done-means 2 and 3: every clean image scores Low (with the proof's
whitelist and the base profile), and every detection behaviour and chain
reaches its band. Costs Linode time: run only with John's approval.

    python tests/integration/calibrate.py [--write-docs]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import readonly_proof as proof  # noqa: E402  (the token, as the proofs read it)

SCORING = HERE.parents[1] / "docs" / "scoring.md"
START, END = "<!-- calibration:start -->", "<!-- calibration:end -->"


def run(script: str, out: Path, *extra: str) -> tuple[list[dict], int]:
    """One proof, its results as JSON (it prints its own report too), and
    its exit status. The token is read once, by the caller, and passed on."""
    done = subprocess.run(
        [sys.executable, str(HERE / script), "--json", str(out), *extra], cwd=HERE, check=False
    )
    return (json.loads(out.read_text()) if out.exists() else []), done.returncode


def table(clean: list[dict], detection: list[dict]) -> tuple[str, list[str]]:
    """The results as Markdown, and what breaks done-means 2 or 3."""
    problems = []
    lines = [
        f"Calibration run of {date.today().isoformat()} (tests/integration/calibrate.py).",
        "",
        "| Clean image | Probability | Band | Compromise findings by band |",
        "|---|---|---|---|",
    ]
    for r in sorted(clean, key=lambda r: r["distro"]):
        bands = ", ".join(f"{n} {b}" for b, n in sorted(r.get("findings_by_band", {}).items()))
        probability = r.get("probability")
        shown = f"{probability:.1%}" if isinstance(probability, (int, float)) else "?"
        lines.append(f"| {r['distro']} | {shown} | {r.get('band') or '?'} | {bands or 'none'} |")
        if r.get("band") != "Low":
            problems.append(f"{r['distro']} (clean) scored {r.get('band')} ({shown})")
        if not r.get("passed"):
            problems.append(f"{r['distro']}: the read-only proof failed")
    lines += [
        "",
        "| Compromised image | Probability | Band | Behaviours and chains |",
        "|---|---|---|---|",
    ]
    for r in sorted(detection, key=lambda r: r["distro"]):
        probability = r.get("probability")
        shown = f"{probability:.1%}" if isinstance(probability, (int, float)) else "?"
        found, missed = len(r.get("found") or []), len(r.get("missing") or [])
        lines.append(
            f"| {r['distro']} | {shown} | {r.get('band') or '?'} | {found} found, {missed} missed |"
        )
        problems += [f"{r['distro']}: {m}" for m in r.get("missing") or []]
        if r.get("error"):
            problems.append(f"{r['distro']}: {r['error']}")
        if r.get("band") not in ("High", "Critical"):
            problems.append(f"{r['distro']} (compromised) scored {r.get('band')} ({shown})")
    return "\n".join(lines), problems


def write_docs(text: str) -> None:
    doc = SCORING.read_text(encoding="utf-8")
    if START in doc and END in doc:
        head, rest = doc.split(START, 1)
        doc = head + START + "\n" + text + "\n" + END + rest.split(END, 1)[1]
    else:
        doc = doc.rstrip("\n") + f"\n\n## Calibration\n\n{START}\n{text}\n{END}\n"
    SCORING.write_text(doc, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write-docs", action="store_true", help="update docs/scoring.md")
    parser.add_argument("--golden", help="also re-export the golden cases into this directory")
    args = parser.parse_args()
    if not os.environ.get("LINODE_TOKEN"):
        os.environ["LINODE_TOKEN"] = proof.linode_token()  # one 1Password prompt
    with tempfile.TemporaryDirectory(prefix="cc-calibrate-") as work:
        clean, clean_status = run("readonly_proof.py", Path(work) / "clean.json", "--distro", "all")
        detection, detection_status = run(
            "detection_proof.py",
            Path(work) / "detection.json",
            *(("--golden", args.golden) if args.golden else ()),
        )
    text, problems = table(clean, detection)
    for name, results, status in (
        ("read-only proof", clean, clean_status),
        ("detection proof", detection, detection_status),
    ):
        if not results:
            problems.append(f"the {name} wrote no results (exit status {status})")
    print("\n" + text)
    if args.write_docs:
        # Written either way, so a failing run is on record too; its
        # failures are listed with it.
        write_docs(text + "".join(f"\n\nFAIL: {p}" for p in problems))
    for problem in problems:
        print(f"FAIL: {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
