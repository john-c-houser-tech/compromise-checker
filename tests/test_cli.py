import re
import subprocess
import sys
from importlib.resources import files

import pytest

from checker import __version__
from checker.cli import main


def test_no_arguments_prints_version(capsys):
    assert main([]) == 0
    assert capsys.readouterr().out.startswith(f"checker {__version__}")


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"checker {__version__}"


def test_runs_as_module():
    result = subprocess.run(
        [sys.executable, "-m", "checker", "--version"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"checker {__version__}"


def test_collector_ships_with_package_and_matches_version():
    source = (files("checker") / "collector" / "collector.py").read_text()
    match = re.search(r'^COLLECTOR_VERSION = "([^"]+)"$', source, re.MULTILINE)
    assert match, "collector.py must define COLLECTOR_VERSION"
    assert match.group(1) == __version__
