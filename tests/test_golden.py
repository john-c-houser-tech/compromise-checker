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


def scrubbed(case, protect=()):
    text = golden.scrub(json.dumps(case), list(protect))
    golden.check_scrubbed(text, list(protect))
    return text


def test_public_addresses_are_replaced_consistently_and_private_ones_kept():
    case = {
        "events": [
            {"fields": {"address": "8.8.8.8"}, "line": "Accepted publickey from 8.8.8.8 port 2"},
            {"fields": {"address": "10.0.0.5"}, "line": "from 10.0.0.5"},
        ],
        "snapshot": {"remote": ["2606:4700::1111", 443], "host": "li-8-8-8-8.example"},
    }
    text = scrubbed(case)
    assert "8.8.8.8" not in text and "8-8-8-8" not in text and "2606:4700::1111" not in text
    assert text.count("203.0.113.1") == 2 and "203-0-113-1." in text
    assert "2001:db8::1" in text
    assert "10.0.0.5" in text  # private: kept


@pytest.mark.parametrize(
    "line",
    [
        "stdin is tcp to 8.8.8.8:4444",
        "Connection closed by 8.8.8.8 port 22",
        "authenticating user root 8.8.8.8 port 5",
        "listening on 8.8.8.8",
        "peer=::ffff:8.8.8.8",
        "kernel 8.8.8.8 then from 8.8.8.8",
        "v18.8.8.8 from 8.8.8.8",
        "client [2606:4700::1111]:443 and 2606:4700:0:0:0:0:0:1111 and 2606:4700::1111 upper",
        "upper 2606:4700::ABCD",
    ],
)
def test_addresses_in_free_text_are_replaced_however_they_are_written(line):
    text = scrubbed({"line": line})
    assert "8.8.8.8" not in text and "4700" not in text


def test_a_loopback_address_with_a_port_is_left_alone():
    assert "::1:323" in scrubbed({"listen": "::1:323"})


def test_dashed_forms_are_replaced_only_whole():
    text = scrubbed({"a": "1.2.3.4", "pkg": "11-2-3-45", "host": "x-1-2-3-4.example"})
    assert "11-2-3-45" in text and "1-2-3-4." not in text


def test_a_protected_address_in_any_known_form_fails_the_export():
    for leaked in ("9-9-9-9", "09090909"):
        with pytest.raises(ValueError, match="protected"):
            golden.check_scrubbed(json.dumps({"x": leaked}), ["9.9.9.9"])
    with pytest.raises(ValueError, match="survived"):
        golden.check_scrubbed(json.dumps({"x": "from 8.8.8.8"}), [])


# --- the harness is analyze ------------------------------------------------------------------


@pytest.mark.parametrize("bundles", [1, 2, 3])
def test_an_exported_case_gives_what_analyze_gave(home, tmp_path, bundles):
    # 1: the host's first bundle, its own baseline; 2: against the previous
    # bundle, which is the baseline; 3: against a previous bundle that
    # isn't the baseline.
    from test_snapshot import add_bundle, host_records

    from checker.assess import analyze

    _, store, identity, config = home
    accounts = (("root", 0), ("jch", 1000), ("toor", 0))
    add_bundle(home, "b1", 0, host_records())
    for n in range(2, bundles + 1):
        add_bundle(home, f"b{n}", 10 * n, host_records(accounts=accounts))
    target = f"b{bundles}"
    # Analysed once first, as the proof does: a host's very first analysis
    # says "no baseline yet", every later one "this bundle is the baseline".
    analyze(store, "web01", identity, config.recipients, target)
    path = golden.export_case(
        store, "web01", identity, config.recipients, target, "t", [], tmp_path
    )
    analysed = analyze(store, "web01", identity, config.recipients, target)
    result = json.loads(json.dumps(golden.run_case(golden.load_case(path)), sort_keys=True))
    analysed = json.loads(json.dumps(analysed, sort_keys=True))
    assert result["findings"] == analysed["findings"]
    assert result["checks"] == analysed["checks"]
    assert {k: v for k, v in result["score"].items() if k != "prior_source"} == {
        k: v for k, v in analysed["score"].items() if k != "prior_source"
    }


def test_an_export_that_would_change_the_findings_fails(home, tmp_path, monkeypatch):
    from test_snapshot import add_bundle, host_records

    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records(accounts=(("root", 0), ("toor", 0))))
    monkeypatch.setattr(golden, "scrub", lambda text, protect: text.replace('"uid": 0', '"uid": 7'))
    with pytest.raises(ValueError, match="changed what the checks find"):
        golden.export_case(store, "web01", identity, config.recipients, "b1", "t", [], tmp_path)


def test_an_export_whose_scrubbing_missed_an_address_fails(home, tmp_path, monkeypatch):
    from test_snapshot import add_bundle, host_records

    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    monkeypatch.setattr(golden, "scrub", lambda text, protect: text + " from 8.8.8.8")
    with pytest.raises(ValueError, match="survived"):
        golden.export_case(store, "web01", identity, config.recipients, "b1", "t", [], tmp_path)
    assert not (tmp_path / "t.json.gz").exists()
