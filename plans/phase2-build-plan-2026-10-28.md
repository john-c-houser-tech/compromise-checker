# Phase 2 build plan — 2026-10-28

> **Status: PROPOSED (outline)** — waiting for John's review. Nothing built
> yet. Once the outline is agreed, each PR gets its detail here before it
> starts, as in Phase 1.

**Goal (DESIGN.md §18, Phase 2):** the tool says how likely it is that a
host is compromised, and an operator can make a real server's report quiet
without hiding anything. Phase 1's findings get likelihood ratios and a
score (§11); whitelists suppress known behaviour with a recorded reason
(§9); checks 8.8–8.13 cover the network, mail, anti-forensics, software
changes, web applications and containers. The AI advisor stays Phase 3 and
threat packs Phase 4.

**Done means:**
1. Every assessment has a probability of compromise, its band
   (*Low / Elevated / High / Critical*), the contributors largest first, and
   a separate hygiene and exposure rating; the report shows all of it.
2. **Clean hosts score Low.** A fresh server on each of the seven images
   scores in the Low band with the default profile, apart from the proof's
   own setup (which the proof whitelists, so it shows in the appendix).
3. **Compromised hosts score High or above.** Each detection-proof
   behaviour, Phase 1's ten and the new ones for 8.8–8.13, reaches at least
   its stated band on Ubuntu 24.04 and Rocky Linux 9. The detection proof
   also covers chains, where the correlation bonus must apply.
4. Whitelists work end to end: layered files, every rule with a reason,
   owner and expiry; suppressed findings kept in the report's appendix;
   `checker whitelist test` shows what a change would hide before it is
   saved; stale and expired rules are reported.
5. The read-only proof still passes on all seven images with the new
   collector modules.
6. Golden reports: stored evidence plus the expected assessment, so any
   change to checks, ratios or whitelists shows up as a diff in CI.
7. Calibration results, the false-positive and detection counts per image,
   are written into this plan and `docs/scoring.md`.

## Ground rules

Phase 0 and 1's rules carry over: a feature branch per PR into `dev`; John
merges `dev` → `main`; the collector stays Python 3.9 and standard library
only, read-only, and fails closed; evidence stays encrypted; collect less,
not more; bounded on the target; the collector judges nothing. Every code
PR gets an independent agent review with its fixes first, then Copilot
review (from 2026-11-01), before it is called ready. Also:

- **Vertical slices.** Phase 1 built the collector first and the checks
  later. Phase 2 builds each check area as one PR: its collector module,
  parser, snapshot section, checks, tests and detection behaviours
  together, so each PR's proof shows the whole thing working.
- **The score never hides evidence.** Whitelisting a finding removes its
  contribution to the score but keeps the finding, with the rule that
  suppressed it. Nothing is deleted or rewritten.
- **Ratios live in one table.** Each check states its default likelihood
  ratio in one place (`checker/scoring.py` or a data file beside it), not
  scattered through check code, so calibration changes one file and the
  golden reports show the effect.
- **Low coverage never lowers the score**, and is shown beside it
  (DESIGN.md §11.4).

## Pull requests

**2.0 — `purge` and retention** (needs decision 1 first).
Policy §8 promises 90-day retention and a `purge` command, but bundles,
custody, baselines and assessments are append-only, enforced by triggers.
Settled before Phase 2 adds whitelist history, which would be one more
append-only table.

**2.1 — Scoring core.**
- `checker/scoring.py`: a likelihood ratio per check (and per variant,
  where a check's band depends on what it saw), the prior (2% default,
  settable per host and group), log-odds sums, family caps, the
  probability and its band.
- Hygiene and exposure scored separately, as a risk rating, never in the
  probability.
- Assessments v2 store the prior, each finding's ratio and contribution,
  the probability and the band. Earlier assessments stay as they are; an
  analysis adds a new one.
- `checker analyze` and the report show the score and the contributors.
- Golden-report harness: stored evidence from the 1.9 proofs (fresh and
  compromised servers) with the expected assessments, checked in CI.

**2.2 — Whitelists.**
- The YAML format of DESIGN.md §9.2, validated strictly (unknown keys are
  errors), layered `global` → `group` → `host`; a host file can switch off a
  group rule with a reason.
- Matching on the check id, entities and finding fields; every rule needs a
  `reason`, an `owner` and `expires` (`never` written out).
- Suppression in `analyze`; the report's appendix lists suppressed findings
  with their rule. The assessment records a hash of the whitelist set it
  used, so a later reader knows which rules applied.
- `checker whitelist check` (validate), `test` (re-score stored evidence
  with a proposed change and show what it would hide), `stale` (no match in
  90 days, or expired).
- Maintenance windows (deferred from 1.7): reboots and package changes
  inside a declared window drop to informational.

**2.3 — Correlation.**
- A small engine for "A then B within T, same user/host/process": used by
  whitelist rules (`correlated_with`, as in §9.2's deploy-after-login) and by
  scoring's chain bonuses (§11.3: new account → sudo grant → outbound
  transfer; web worker child → scratch file → new outbound connection).
- Chains are defined as data, like the ratios, and each one names the
  findings it joins.

**2.4 — Network and data transfer (8.8).**
- Collector: `/etc/hosts`, `resolv.conf`, `nsswitch.conf`; interface flags
  (promiscuous) and counters from `/sys/class/net`; firewall rules (needs
  decision 2: `nft list ruleset` / `iptables-save` would be the first new
  allow-listed commands since `journalctl`).
- Checks: new listening ports (from the snapshot's sockets); outbound
  connections to new destinations, unusual ports and Tor; ★ a web-tier host
  connecting to directory services (445, 389/636, 88, 5985/5986); processes
  other than the cloud agent reaching 169.254.169.254; SSH forwards and
  tunnels (from sshd logs and live sockets); firewall and resolver changes.
- Weak transfer signals combined: large archives in scratch places,
  download tools in live processes, counter jumps. The report says when no
  strong source exists.

**2.5 — Anti-forensics (8.10, ★ all).**
- Collector: log file manifests (sizes and times for `/var/log`, so a
  truncated or missing file shows), unit states for auditd, rsyslog,
  journald and named security agents, audit rules files, SELinux mode from
  `/sys/fs/selinux`, AppArmor profiles from `/sys/kernel/security`.
- Checks: journal gaps; truncated or missing logs that should exist;
  cleared `wtmp`/`btmp`; history files linked to `/dev/null` or emptied
  (from Phase 1's history metadata); logging or audit stopped, audit rules
  changed; SELinux permissive or disabled; AppArmor profiles unloaded;
  security agents stopped; clock jumps from the journal.

**2.6 — Software changes (8.11).**
- Collector: package logs (`dpkg.log`, apt `history.log`, `dnf.rpm.log`),
  repository files and signing keys, global `pip` and `npm` locations.
- Checks: packages installed or removed (outside maintenance windows once
  2.2 is in); new repositories or keys; compilers and attack tools on a
  production host (`nmap`, `masscan`, `socat`, `ncat`, `proxychains`…);
  global `pip`/`npm` installs.

**2.7 — Outgoing mail (8.9)** (needs decision 3: mail logs hold
recipient addresses).
- Collector: Postfix and Exim configuration, mail log lines from the
  journal or `/var/log/mail.log`/`maillog`, queue size by counting the
  spool, not by running `mailq`.
- Checks: new relays; mail sent by web-server users; volume and queue
  jumps; new recipient domains in bulk; configuration changes (relayhost,
  open-relay settings). Baseline of domains, relays and sending users.

**2.8 — Web applications (8.12)** (needs decision 3: access logs hold
client addresses and URLs).
- Collector: nginx and Apache access and error logs for the look-back
  window (bounded, masked), and the web server configuration to find them.
- Checks: ★ children of web workers (live, from Phase 1's processes; and
  from auditd execve records where auditd is running, with the gap flagged
  otherwise); 5xx bursts from one source; exploit strings; requests that
  succeed against newly appeared scripts; the "internet background noise"
  classifier from DESIGN.md §17, so scanner traffic is informational.

**2.9 — Containers (8.13).**
- Collector: Docker and Podman container state read from their files under
  `/var/lib/docker` and `/var/lib/containers` (needs decision 4: files, not
  the runtime's socket).
- Checks: new containers; privileged containers; containers mounting the
  host's root or the runtime's socket.

**2.10 — Default profiles and calibration.**
- Default whitelist profiles: *base* (what every fresh image showed in
  1.9: Ubuntu's replaced `libaudit`, firewalld's libffi, AlmaLinux 10's
  `/boot/efi` mode), *web server*, *database server*, *mail relay*, each
  rule with its reason.
- Calibration harness: run the proofs, collect each run's assessment, and
  write the table (false positives by band per image, detection per
  behaviour, scores) into this plan and `docs/scoring.md`.
- Detection proof extended with behaviours for 8.8–8.13 (a process reaching
  the metadata address, mail sent as `www-data`, auditd stopped, history
  linked to `/dev/null`, SELinux set permissive, `nmap` installed, a new
  repository, a web shell spawning a shell, a privileged container) and with
  two chains.
- Ratios tuned from the results; the tuning recorded with its reasons.
- With John's go-ahead: nouriloop-prod as the first real-world clean run.

## Explicitly gated on John

- Any change to the security and privacy policy's wording. 2.7 and 2.8
  collect personal data the policy doesn't yet name (decision 3).
- New allow-listed commands on targets (decision 2).
- Spending on throwaway servers: each PR's proof, and 2.10's calibration
  runs (budget, decision 5).
- Running the tool against nouriloop-prod.

## Decisions to confirm with John (one at a time, before the PR that needs it)

1. **Before 2.0 — purge vs append-only.** Proposed in the Phase 1 plan:
   `purge` is the one sanctioned way to delete; it drops the triggers inside
   its transaction, deletes, restores them, and records what it removed (by
   identifiers and counts only) in a purge log.
2. **Before 2.4 — firewall rules.** Allow-list `nft list ruleset` and
   `iptables-save` (read-only, fixed arguments), or skip firewall rules and
   say so in coverage.
3. **Before 2.7 and 2.8 — mail and web logs.** What to keep from them and
   how to mask it: recipient domains rather than full addresses; client
   addresses kept (they are the evidence) but query strings masked. Needs
   policy wording.
4. **Before 2.9 — containers.** Read the runtimes' state files (proposed),
   or ask the runtime over its socket (more complete, but talks to a
   daemon).
5. **Before the first proof run — budget.** A cap for Phase 2's server
   time, as in 1.9 ($10 then; about 10 cents spent).

The probability band thresholds are proposed here for review with the
outline, not as a separate decision: Low below 10%, Elevated 10–50%, High
50–90%, Critical 90% and above.

## After Phase 2

Carried over from Phase 1:

- **A RHEL proof run, only if there is interest in the software.**
- **Package verification against vendor packages:** compare with checksums
  from the vendor's signed packages or repository metadata, since root can
  rewrite rpm's database and dpkg's lists.
- **Encrypting reports at rest:** John's decision (2026-10-27) to revisit
  after the currently planned development phases.
