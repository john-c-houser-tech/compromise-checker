# Compromise Checker

*Working title. A NouriLoop LLC project.*

An agentless, read-only tool that checks Red Hat Enterprise Linux (and Rocky
Linux and AlmaLinux) 9+ and Ubuntu 22.04+ servers for signs of compromise.
It logs in over SSH, streams a small collector to the server's own Python,
brings the evidence back, and analyses it on the operator's machine. Nothing
is written to the server.

**Status:** Phase 0 is being built — nothing is usable yet.

- [DESIGN.md](DESIGN.md) — architecture, security and privacy policy, checks,
  scoring, and the decisions made so far.
- [plans/](plans/) — build plans for each phase.

## Development

```
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest
```

The collector (`checker/collector/collector.py`) must stay Python 3.9
compatible and standard-library only; CI runs its tests with the system
`python3` of each supported distribution.

## Licence

AGPL-3.0 (see [LICENSE](LICENSE)). Threat packs, when they exist, are
published separately under CC BY 4.0.
