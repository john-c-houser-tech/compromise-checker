"""Compromise Checker collector.

This file is streamed over SSH to `python3 -I -B -` on the target and runs
there. It is never imported by the controller. Rules for this file
(DESIGN.md §2, §3.2, §5):

- Python 3.9 compatible (RHEL 9's python3) and standard library only.
- Read-only: it never writes, renames, deletes or changes anything on the
  target, and it writes nothing to disk.
- Output goes to stdout only; diagnostics to stderr.

The controller appends one line, `main(<settings as JSON>)`, to the text it
streams, so the collector takes no arguments, files or environment variables.
"""

COLLECTOR_VERSION = "0.1.0.dev0"


def main(settings):
    """Entry point. Modules arrive in PR 0.4."""
    return 0
