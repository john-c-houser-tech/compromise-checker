"""Golden reports (plan 2.1b): each stored case, analysed now, must give
exactly its stored expectation. A deliberate change to the checks, the
ratios or the whitelists is committed with the expectations
`scripts/update_golden.py` rewrites, so the diff shows what moved."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent / "integration"
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("golden", HERE / "golden.py")
golden = importlib.util.module_from_spec(_spec)
sys.modules["golden"] = golden
_spec.loader.exec_module(golden)


@pytest.mark.parametrize("path", golden.cases(), ids=lambda p: p.name.removesuffix(".json.gz"))
def test_each_case_still_gives_its_expected_assessment(path):
    expected = json.loads(golden.expected_path(path).read_text())
    actual = json.loads(json.dumps(golden.run_case(golden.load_case(path)), sort_keys=True))
    assert actual["score"] == expected["score"], "the score moved: run scripts/update_golden.py"
    assert actual == expected, "findings moved: run scripts/update_golden.py and review the diff"


def test_there_are_cases_from_both_families_fresh_and_compromised():
    names = {p.name for p in golden.cases()}
    for distro in ("ubuntu24.04", "rocky9"):
        assert f"fresh-{distro}.json.gz" in names
        assert f"detection-{distro}.json.gz" in names


# --- scrubbing ---------------------------------------------------------------------------


def test_public_addresses_are_replaced_consistently_and_private_ones_kept():
    case = {
        "events": [
            {"fields": {"address": "8.8.8.8"}, "line": "Accepted publickey from 8.8.8.8 port 2"},
            {"fields": {"address": "10.0.0.5"}, "line": "from 10.0.0.5"},
        ],
        "snapshot": {"remote": ["2606:4700::1111", 443], "host": "li-8-8-8-8.example"},
        "version": "kernel 5.15.0.105 and 1.2.3.4-ubuntu",
    }
    text = golden.scrub(json.dumps(case), protect=["1.1.1.1"])
    assert "8.8.8.8" not in text and "8-8-8-8" not in text and "2606:4700::1111" not in text
    assert text.count("203.0.113.") == 2  # the same address, both times
    assert "203-0-113-" in text  # the reverse-DNS form too
    assert "2001:db8::" in text
    assert "10.0.0.5" in text  # private: kept
    assert "5.15.0.105" in text  # a version, not after an address word: kept


def test_a_protected_address_anywhere_is_replaced():
    text = golden.scrub(json.dumps({"x": "x9.9.9.9", "y": "ok 9.9.9.9"}), protect=["9.9.9.9"])
    assert "9.9.9.9" not in text.replace("x9.9.9.9", "")


def test_leftovers_are_listed_for_review():
    assert golden.leftover_addresses('{"v": "5.15.0.105"}') == ["5.15.0.105"]


# --- the harness is analyze ------------------------------------------------------------------


def test_an_exported_case_gives_what_analyze_gave(home, tmp_path):
    from test_snapshot import add_bundle, host_records

    from checker.assess import analyze

    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    accounts = (("root", 0), ("jch", 1000), ("toor", 0))
    add_bundle(home, "b2", 10, host_records(accounts=accounts))
    add_bundle(home, "b3", 20, host_records(accounts=accounts))
    analysed = analyze(store, "web01", identity, config.recipients, "b3")
    path, _ = golden.export_case(
        store, "web01", identity, config.recipients, "b3", "t", [], tmp_path
    )
    result = golden.run_case(golden.load_case(path))
    assert result["findings"] == analysed["findings"]
    assert result["score"]["probability"] == analysed["score"]["probability"]
    assert json.loads(golden.expected_path(path).read_text())["score"] == json.loads(
        json.dumps(result["score"], sort_keys=True)
    )
