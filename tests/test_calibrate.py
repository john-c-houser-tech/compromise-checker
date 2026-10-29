"""The calibration harness's judging and table (no servers)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "integration"))
import calibrate  # noqa: E402


def test_done_means_2_and_3_are_judged():
    clean = [
        {
            "distro": "rocky9",
            "probability": 0.084,
            "band": "Low",
            "passed": True,
            "findings_by_band": {"low": 3},
        },
        {
            "distro": "ubuntu24.04",
            "probability": 0.14,
            "band": "Elevated",
            "passed": True,
            "findings_by_band": {"medium": 1},
        },
    ]
    detection = [
        {
            "distro": "rocky9",
            "probability": 1.0,
            "band": "Critical",
            "found": ["a", "b"],
            "missing": [],
        },
        {
            "distro": "ubuntu24.04",
            "probability": 1.0,
            "band": "Critical",
            "found": ["a"],
            "missing": ["chain web-shell-used: not found"],
        },
    ]
    text, problems = calibrate.table(clean, detection)
    assert "| rocky9 | 8.4% | Low | 3 low |" in text
    assert "| ubuntu24.04 | 100.0% | Critical | 1 found, 1 missed |" in text
    assert problems == [
        "ubuntu24.04 (clean) scored Elevated (14.0%)",
        "ubuntu24.04: chain web-shell-used: not found",
    ]
    _, problems = calibrate.table([], [{"distro": "x", "probability": 0.3, "band": "Elevated"}])
    assert problems == ["x (compromised) scored Elevated (30.0%)"]


def test_the_table_goes_between_its_markers(tmp_path, monkeypatch):
    doc = tmp_path / "scoring.md"
    doc.write_text("# Scoring\n\nintro\n")
    monkeypatch.setattr(calibrate, "SCORING", doc)
    calibrate.write_docs("first")
    calibrate.write_docs("second")
    text = doc.read_text()
    assert text.count(calibrate.START) == 1 and "second" in text and "first" not in text
