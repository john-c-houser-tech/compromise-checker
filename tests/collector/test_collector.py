"""Collector tests.

Standard library `unittest` only, Python 3.9 compatible: CI runs this file
with the targets' own interpreters (RHEL/Rocky 9 and 10, Ubuntu 22.04 and
24.04), where nothing else is installed. pytest also collects it locally.
"""

import ast
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parents[2] / "checker" / "collector" / "collector.py"


def load_collector():
    spec = importlib.util.spec_from_file_location("collector", COLLECTOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CollectorTests(unittest.TestCase):
    def test_main_returns_zero(self):
        self.assertEqual(load_collector().main({}), 0)

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

    def test_runs_as_a_program_on_stdin(self):
        # The way it runs on a target: program text on stdin, isolated mode,
        # no bytecode, with the controller's one-line call appended.
        program = COLLECTOR.read_text() + "\nmain({})\n"
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-"],
            input=program,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
