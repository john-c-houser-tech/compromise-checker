# Compromise Checker

*Working title. A NouriLoop LLC project.*

An agentless, read-only tool that checks Red Hat Enterprise Linux (and Rocky
Linux and AlmaLinux) 9+ and Ubuntu 22.04+ servers for signs of compromise.
It logs in over SSH, streams a small collector to the server's own Python,
brings the evidence back, and analyses it on the operator's machine. Nothing
is written to the server.

**Status: Phase 0 complete (2026-10-26).** The tool collects and stores
evidence; it does not analyse it yet. Checks, baselines, scoring and reports
come in Phase 1, the AI advisor in Phase 3 (see [DESIGN.md §18](DESIGN.md)).

What works today:

- `checker init` — sets up the evidence key, database and configuration;
  `--home-text privileged|all` opts in to collecting the masked text of
  start-up files and user units in home directories (policy §7).
- `checker hosts add|list|remove` and `checker trust` — the inventory
  (`--web-root DIR`, repeatable, sets a host's own web roots), and
  verified SSH host keys (no way to switch verification off).
- `checker collect` — logs in (key, agent or password; sudo with or without a
  password, or root), runs the collector read-only, and stores the result as
  an `age`-encrypted, hashed bundle with a chain of custody. Collects host
  facts and the authentication log, with secrets masked before they leave
  the server.
- `checker bundle list|show|verify` — inspect and re-check stored evidence.
- `checker events BUNDLE` — parse a bundle into events (logins, sudo, account
  changes, kernel and systemd messages, login records), with the tool's own
  session recognised and left out ([how](docs/events.md)).
- `checker changes HOST` — what changed on a host since its previous bundle
  and since its baseline: accounts, sudo rules, authorized keys, sshd
  settings, persistence files, listening sockets, kernel modules and more.
  The host's first analysis is its baseline; `checker baseline accept HOST
  --reason …` moves it after a reviewed change ([how](docs/snapshots.md)).
- `checker analyze HOST|--all` — runs the checks (kernel and system health,
  reboots, accounts and authentication so far) and lists the findings by
  category and band, with what the collection couldn't see; each analysis
  is stored encrypted ([checks](docs/checks.md)).

**Read-only, proven:** on throwaway Ubuntu 24.04 and Rocky Linux 9 servers,
with auditd recording every write by the scanner's session, the collector
wrote nothing at all, and every write by the system's own login machinery
matched the traces disclosed in the policy
([proof script](tests/integration/readonly_proof.py),
[results](plans/phase0-build-plan-2026-10-25.md#results)).

Set up a server for it with [docs/scanner-account.md](docs/scanner-account.md).

- [DESIGN.md](DESIGN.md) — architecture, security and privacy policy, checks,
  scoring, and the decisions made so far.
- [plans/](plans/) — build plans for each phase.
- [Security and privacy policy](docs/security-and-privacy-policy.md) — what the
  tool does on your servers and with your data. [SECURITY.md](SECURITY.md) —
  reporting a vulnerability.

## Development

Runs on Python 3.12 or later on the controller.

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

Provided as is, without warranty. Findings are estimates, and a clean report
is not proof that a server is clean; see section 14 of the
[security and privacy policy](docs/security-and-privacy-policy.md).
