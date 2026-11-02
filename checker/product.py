"""The product's name, from one place: it stays configurable (DESIGN.md §19)."""

import os


def product_name() -> str:
    return os.environ.get("CHECKER_PRODUCT_NAME") or "Compromise Checker"
