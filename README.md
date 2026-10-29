# Compromise Checker

*Working title. A NouriLoop LLC project.*

An agentless, read-only tool that checks Red Hat Enterprise Linux (and Rocky
Linux and AlmaLinux) 9+ and Ubuntu 22.04+ servers for signs of compromise.
It logs in over SSH, streams a small collector to the server's own Python,
brings the evidence back, and analyses it on the operator's machine. Nothing
is written to the server.

**Status: Phase 2 complete (2026-10-29).** The tool collects evidence,
compares each host with its baseline, runs the checks, scores the host and
writes the report. The AI advisor comes in Phase 3 and threat packs in
Phase 4 (see [DESIGN.md §18](DESIGN.md)).

What works today:

- `checker init` — sets up the evidence key, database and configuration;
  `--home-text privileged|all` opts in to collecting the masked text of
  start-up files and user units in home directories (policy §7);
  `--web-access-logs` opts in to web servers' access logs, masked;
  `--exec-records` chooses whose program starts are read from the audit
  log (the web server's accounts by default). It also asks whether to turn
  on the optional AI advisor (`--advisor on|off` for unattended setups,
  which leave it off), and where its API key comes from
  (`--advisor-key-source env|keyring|command:<command>`; never stored in
  the configuration).
- `checker advise HOST --show [--redaction MODE]` — prints exactly what the
  optional AI advisor would be sent about a host's latest analysis, after
  redaction, and sends nothing. Under *pseudonymize* (the default) people's
  account names, host names, email addresses, IP addresses and SSH key
  fingerprints become placeholders (USER-2-7f3a) made fresh for each run;
  *strict* sends only the kinds of finding, counts, scores and kinds of
  coverage gap. Sending
  arrives later in Phase 3.
- `checker config show|set|history|check-key` — the settings in words;
  change one after `init` (validated, and recorded with who, when, old and
  new value; the file is written back whole, so hand-added comments go);
  every change so far; read the advisor's API key from its source to check
  it works, without sending anything. A key pasted into a `command:`
  source is refused.
- `checker hosts add|list|remove` and `checker trust` — the inventory
  (`--web-root DIR`, repeatable, sets a host's own web roots), and
  verified SSH host keys (no way to switch verification off).
- `checker collect` — logs in (key, agent or password; sudo with or without a
  password, or root), runs the collector read-only, and stores the result as
  an `age`-encrypted, hashed bundle with a chain of custody. Collects host
  facts, logs, persistence, the network, software, mail, web servers and
  containers, with secrets masked before they leave the server (email
  addresses' local parts are fingerprinted, the domain kept).
- `checker mail-hash ADDRESS…` — shows how known email addresses appear in
  the collected mail logs, so they can be looked for.
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
  reboots, accounts and authentication, persistence, system binary
  integrity, files in unusual places, live processes, the network, logging
  stopped or wiped, software changes, mail, web applications, containers),
  links findings that tell an attack's story into chains, and lists the findings by
  category and band, with what the collection couldn't see, and scores the
  host: a probability of compromise with its band and what drove it, from
  a prior set per host, group or configuration; each analysis is stored
  encrypted ([checks](docs/checks.md), [scoring](docs/scoring.md)).
- `checker report HOST|--all` — writes one self-contained, confidential HTML
  report: findings with their evidence, a timeline, coverage, and the
  collection's hashes and chain of custody ([report](docs/report.md)).
- `checker whitelist check [HOST]`, `test HOST --file F`, `stale` —
  validate the whitelist files (global, per group, per host) and show a
  host's merged rules; show what a proposed file would hide or reveal on
  stored analyses before it is saved; list rules that matched nothing
  lately or are expiring. Maintenance windows make planned reboots
  informational. Shipped profiles (`base`, `web`, `database`, `mail`,
  `build`) cover what such servers ordinarily do. A rule suppresses
  a finding an operator has explained, with a reason, an owner and an
  expiry; suppressed findings are kept and listed in the report's appendix,
  and count for nothing in the score ([whitelists](docs/whitelists.md)).
- `checker purge HOST | --before DATE | --expired` — deletes stored evidence,
  reports included, and records what went by identifiers and counts only.
  `--expired` keeps each host's current baseline until a newer one is
  accepted ([retention](docs/retention.md)).

**Read-only, proven:** on throwaway Ubuntu 22.04, 24.04 and 26.04, Rocky
Linux 9 and 10, and AlmaLinux 9 and 10 servers, with auditd recording every
write by the scanner's session, the collector wrote nothing at all, and
every write by the system's own login machinery matched the traces
disclosed in the policy
([proof script](tests/integration/readonly_proof.py),
results in the [Phase 1](plans/phase1-build-plan-2026-10-26.md) and
[Phase 2](plans/phase2-build-plan-2026-10-28.md) plans).

**Detection, proven:** on throwaway Ubuntu 24.04 and Rocky Linux 9 servers,
30 scripted compromise behaviours each produced their finding at its band
or above: among them a second UID 0 account, a backdoor key for root,
cron and systemd persistence, `/etc/ld.so.preload`, a reverse shell, an SSH
tunnel, auditd stopped and login records emptied, an attack tool and a
package repository added, a burst of mail from the web server's account, a
web shell answering requests and running programs, and a privileged
container mounting `/`. Both attack chains applied (a new account given
sudo and used; a web shell answering, then starting a shell)
([detection proof](tests/integration/detection_proof.py)).

**Calibrated:** fresh servers on all seven images score Low (5.8%), with
the proof's own setup whitelisted and the `base` profile; the compromised
servers score Critical ([calibration](docs/scoring.md#calibration)).

**RHEL itself hasn't been tested:** Rocky Linux and AlmaLinux, built from
the same sources, stand in for it. Red Hat's own subscription and Insights
services, which they lack, may raise findings no run has seen yet.

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

Golden reports (`tests/golden/`) pin the findings and score of real
analyses of throwaway servers; after a deliberate change to checks or scoring,
`python scripts/update_golden.py` rewrites them and shows what moved
([scoring](docs/scoring.md#golden-reports)).

## Licence

AGPL-3.0 (see [LICENSE](LICENSE)). Threat packs, when they exist, are
published separately under CC BY 4.0.

Provided as is, without warranty. Findings are estimates, and a clean report
is not proof that a server is clean; see section 14 of the
[security and privacy policy](docs/security-and-privacy-policy.md).
