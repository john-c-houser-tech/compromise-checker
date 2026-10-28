"""The repository's own text holds no invisible or direction-changing
characters: in a doc or source file they can make text read differently
from what it is (the report defends against the same trick in host text).
Tests and docs write them as escapes such as \\u202e."""

import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUFFIXES = {".py", ".md", ".j2", ".toml", ".yml", ".yaml", ".txt", ".cfg"}
SKIP = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache"}


def hidden(char: str) -> bool:
    return char not in "\n\t" and unicodedata.category(char) in ("Cc", "Cf", "Co", "Cs", "Zl", "Zp")


def test_no_invisible_characters_in_the_repository():
    found = []
    for path in ROOT.rglob("*"):
        if path.suffix not in SUFFIXES or SKIP & set(path.relative_to(ROOT).parts):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for char in line:
                if hidden(char):
                    found.append(f"{path.relative_to(ROOT)}:{number}: U+{ord(char):04X}")
    assert not found, "\n".join(found)
