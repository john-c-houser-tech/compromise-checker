"""Collector tests.

Standard library `unittest` only, Python 3.9 compatible: CI runs this file
with the targets' own interpreters (RHEL/Rocky 9 and 10, Ubuntu 22.04 and
24.04), where nothing else is installed. pytest also collects it locally.
The full contract check against the controller's models is in
tests/test_protocol.py.
"""

import ast
import gzip
import json
import subprocess
import sys
import unittest
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parents[2] / "checker" / "collector" / "collector.py"

GOOD_SETTINGS = {
    "protocol": 1,
    "run_id": "test-run",
    "since": "2026-09-25T00:00:00+00:00",
    "modules": None,
    "limits": {"overall_seconds": 60, "module_seconds": 30, "source_bytes": 1048576},
}


def run_collector(settings):
    """Run the collector as on a target: program on stdin, isolated, no bytecode."""
    settings_json = settings if isinstance(settings, str) else json.dumps(settings)
    program = COLLECTOR.read_text() + "\nmain(" + json.dumps(settings_json) + ")\n"
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-"],
        input=program.encode("utf-8"),
        capture_output=True,
        timeout=60,
    )
    records = [json.loads(line) for line in gzip.decompress(result.stdout).splitlines()]
    return result, records


class StreamTests(unittest.TestCase):
    def test_manifest_first_and_trailer_last(self):
        result, records = run_collector(GOOD_SETTINGS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(records[0]["type"], "manifest")
        self.assertEqual(records[-1]["type"], "trailer")
        self.assertEqual(records[0]["run_id"], "test-run")
        self.assertEqual(records[0]["protocol"], 1)
        self.assertEqual(records[-1]["status"], "complete")

    def test_manifest_describes_this_host(self):
        _, records = run_collector(GOOD_SETTINGS)
        host = records[0]["host"]
        self.assertTrue(host["hostname"])
        self.assertTrue(host["kernel"])
        self.assertEqual(records[0]["python"]["version"].split(".")[0], "3")

    def test_accepts_z_suffix_times(self):
        # Python 3.9's fromisoformat() rejects "Z"; the controller may send it.
        settings = dict(GOOD_SETTINGS, since="2026-09-25T00:00:00Z")
        _, records = run_collector(settings)
        self.assertEqual(records[-1]["status"], "complete")

    def test_refuses_other_protocol_versions(self):
        _, records = run_collector(dict(GOOD_SETTINGS, protocol=2))
        self.assertEqual(records[-1]["status"], "refused")
        errors = [r for r in records if r["type"] == "error"]
        self.assertTrue(any("protocol" in e["message"] for e in errors))

    def test_refuses_unknown_modules(self):
        _, records = run_collector(dict(GOOD_SETTINGS, modules=["no_such_module"]))
        self.assertEqual(records[-1]["status"], "refused")

    def test_refuses_invalid_json(self):
        _, records = run_collector("{not json")
        self.assertEqual(records[0]["type"], "manifest")
        self.assertEqual(records[-1]["status"], "refused")

    def test_writes_only_to_stdout(self):
        result, _ = run_collector(GOOD_SETTINGS)
        self.assertEqual(result.stderr, b"")


class SourceTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(sys, "stdlib_module_names"), "needs Python 3.10+")
    def test_imports_standard_library_only(self):
        tree = ast.parse(COLLECTOR.read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        self.assertEqual(sorted(names - set(sys.stdlib_module_names)), [])


if __name__ == "__main__":
    unittest.main()
