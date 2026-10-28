# Phase 1 build plan — 2026-10-26

> **Status: PROPOSED** — waiting for John's review. Nothing built yet.

**Goal (DESIGN.md §18, Phase 1):** the tool turns collections into findings.
The collector gathers what checks 8.1–8.7 need; the controller parses it
into events and snapshots, keeps per-host baselines, runs the checks, and
writes an HTML report a person can act on. Whitelists and the probability
score are Phase 2; the AI advisor is Phase 3.

**Done means:**
1. `checker collect` followed by `checker analyze` and `checker report` on a
   fresh server produces a report with no findings except ones that are
   genuinely there (a clean host is quiet).
2. On throwaway servers with scripted, reversible compromise behaviours, each
   behaviour produces its expected finding (section "Detection proof").
3. The read-only proof still passes, now on the full distribution matrix:
   RHEL, Rocky Linux and AlmaLinux 9 and 10; Ubuntu 22.04, 24.04 and 26.04.

## Ground rules

Phase 0's rules carry over: a feature branch per PR into `dev`; John merges
`dev` → `main`; the collector stays Python 3.9 and standard library only,
read-only, and fails closed; every PR has Copilot review (two rounds unless
John asks for more) and its tests green before the next starts. Also:

- **Evidence stays encrypted.** Snapshots and events are evidence: they are
  stored `age`-encrypted like bundles, so `analyze` and `report` need the
  evidence key. The index keeps only identifiers, times, status and hashes
  (policy §8).
- **Collect less, not more.** Each new collector module states in
  `docs/collector-modules.md` what it reads and why. Where a check needs only
  a fact, the collector sends the fact, not the file: for example the
  *status* of each password (set, locked, empty, hash type) — never the
  hash — and the *fingerprint* of each SSH key, not the key.
- **Bounded on the target.** Every walk, scan and command has a size and
  time limit; anything cut short is recorded as a coverage gap, never as
  "nothing found".
- **The collector judges nothing.** It reports what is there; deciding what
  is suspicious happens on the controller, so rules can change without
  touching servers.

## Pull requests

**1.1 — Collector groundwork.**
- Peak memory in the trailer (`resource.getrusage`), closing the gap the
  Phase 0 proof found.
- Shared helpers for the new modules: a bounded directory walk (file type,
  owner, mode, size, times, link target; SHA-256 for small executables and
  config files), and running an allow-listed read-only command as a source
  (`kind: command`) with a time limit and its exit status.
- `journalctl` as the first allow-listed command, in JSON, limited to the
  look-back window.

**1.2 — Collector: accounts and access** (feeds 8.3).
- `/etc/passwd` and `/etc/group` as structured records.
- `/etc/shadow` reduced on the server to *status only* per account: password
  set / locked / empty / hash algorithm, and the dates. Never the hash.
- sudoers and `sudoers.d` (masked text), `authorized_keys` for every account
  as fingerprint + options + comment, `sshd_config` and its includes, PAM
  configuration, and the PAM module directory listing with hashes.
- Shell history *metadata* only (decision 4: contents stay opt-in, later).

**1.3 — Collector: persistence** (feeds 8.4).
Cron (system and every user), `at` spool, systemd units and timers (system
and user directories), `rc.local`, `/etc/profile.d`, shell start-up files,
Ubuntu `update-motd.d`, apt and dnf hook configuration, udev rules,
`/etc/ld.so.preload` — as file manifests plus masked contents of small text
files.
As built (#18, agreed with John 2026-10-27): crontab and `at` text from the
spools (`at` environments reduced to names); files in homes as hashes only.

**1.3b — Collector: opt-in text of home start-up files and user units**
(agreed with John 2026-10-27). Hashes alone can't show what a backdoor
already present at the first check runs. Modelled on the shell-history
opt-in: chosen in `checker init`, root, service and administrator accounts
by default (ordinary users only if also enabled), masked as usual. Needs its
own policy §7 wording, approved by John before the PR. After 1.3 merges.

**1.4 — Collector: logs, boots and integrity** (feeds 8.1, 8.2, 8.5).
- Kernel messages and sshd/sudo/su units from the journal (JSON); `wtmp` and
  `btmp` sent raw for the controller to parse; the journal's boot list;
  core-dump and apport directory listings.
- Kernel taint and loaded modules (`/proc/modules`, signature state).
- Package verification: `rpm -Va` on the RHEL family; on Ubuntu, the
  `dpkg` md5sums checked directly by the collector (no `debsums` needed).
- A bounded filesystem pass over system directories for SUID/SGID files,
  file capabilities (read from extended attributes), and executables no
  package owns.

**1.5 — Collector: files in unusual places and live processes** (feeds 8.6,
8.7).
- `/tmp`, `/var/tmp`, `/dev/shm` and `/dev`, plus configurable web roots:
  manifests, hidden and deceptive names, change time versus modification
  time.
- Every process from `/proc`: executable (and whether it is deleted or
  `memfd`), working directory, parent, user, start time, CPU time, masked
  command line, and only the `LD_PRELOAD`/`LD_LIBRARY_PATH` entries of its
  environment. Sockets per process from `/proc/net` and file descriptors.
- Hidden-process check: the `/proc` listing compared with `ps`, and a
  bounded probe of process IDs that `/proc` doesn't list.
  *As built (1.5b):* `ps` isn't on the command allow-list and would be fooled
  by the same `readdir` hook, so the check is the probe of every PID up to
  `pid_max` (thread IDs skipped, re-checked against a fresh listing) and the
  kernel's own task count from `/proc/loadavg`.
- Set-user-ID and set-group-ID files and file capabilities outside the
  system directories 1.4c walks (`/var`, `/tmp`, `/dev/shm`, `/home`,
  `/root`, `/srv`): noted in the 1.4c review.

**1.6 — Controller: parsers, events, snapshots, baselines.**
- Parsers per source: authentication logs (traditional syslog dates with
  year inference, and RFC 3339), journal JSON, `wtmp`/`btmp` binary records,
  `rpm -Va` output, and every structured record from 1.2–1.5.
- Normalized events and a per-host snapshot (DESIGN.md §6), stored
  encrypted.
- Baselines: a host's first analysis becomes its baseline (and says so);
  later analyses compare with the previous and the oldest retained snapshot;
  `checker baseline accept HOST --reason …` records an accepted change, with
  custody.
- The self-session filter: the tool's own logins, sudo calls and session
  writes are recognised from the stored session records and left out of
  findings.
  *As built:* split into 1.6a (#25: the bundle reader, events, the
  self-session filter) and 1.6b (snapshots, comparisons, baselines; see
  docs/snapshots.md). There is no `rpm -Va` output to parse: since 1.4b the
  collector checks rpm's database itself. The "oldest retained snapshot" is
  the baseline: the host's oldest analysed bundle until an operator accepts
  a later one. Comparisons go section by section, and a section the
  collection left incomplete is marked not comparable rather than read as
  removals.

**1.7 — Controller: checks 8.1–8.7 and `checker analyze`.**
- Each check is a small rule over events and snapshots that produces
  findings: id, title, category (compromise indicator / hygiene / exposure),
  a severity band (the likelihood ratios themselves are Phase 2), the
  entities involved, and links to the evidence behind it.
- Coverage: which sources were missing, truncated or unreadable, reported
  beside the findings (DESIGN.md §2 principle 8).
- `checker analyze HOST|--all [--bundle ID]`, storing an encrypted
  assessment.
  *As built:* split into 1.7a (the findings framework, coverage, `checker
  analyze`, assessments, and checks 8.1–8.3; docs/checks.md) and 1.7b
  (checks 8.4–8.7, with the snapshot's uncompared `live` part for
  processes and sockets). Not yet: configured maintenance windows for 8.2 (with
  the whitelists), logins at unusual hours for 8.3 (needs a per-host
  profile).
- **Decision needed before `purge` is built:** the policy (§8) promises
  90-day retention and a `purge` command, but the bundles, custody,
  baselines and assessments tables are append-only, enforced by triggers.
  For example, `purge` could be the one sanctioned way to delete: it drops
  the triggers inside its transaction, deletes, restores them, and records
  what it removed (by identifiers and counts only) in a purge log. Noted in
  the 1.6b and 1.7a reviews.

**1.8 — HTML report and `checker report`.**
- One self-contained HTML file per run: summary (hosts, findings by band,
  coverage), per-host findings with evidence excerpts, a timeline, hygiene
  separated from compromise indicators (principle 9), and an appendix with
  the collection manifest, hashes and chain of custody.
- Marked confidential (policy §8). Jinja2 templates, no external resources.
- The report shows findings and bands only; it says plainly that a scored
  probability arrives in Phase 2.
  *As built:* docs/report.md. Host text is escaped and its invisible
  characters shown; the page loads nothing (CSP `default-src 'none'`).
  The report file is owner-only but not encrypted. John's decision
  (2026-10-27): keep it so for now, and revisit encrypting reports at rest
  after the currently planned development phases are done.

**1.9 — Distribution matrix and detection proof.**
- The read-only proof extended to all seven distribution images.
- A detection proof on throwaway servers: for each scripted, reversible
  behaviour, run the tool and assert the expected finding — a second UID 0
  account; a new `authorized_keys` entry for root; a cron job and a systemd
  timer added; `/etc/ld.so.preload` set; a SUID copy of a shell in `/tmp`; a
  process running from a deleted binary; a shell with its input on a socket;
  `sshd_config` changed to allow root login; a `pam_exec` line added.
- A clean-host run on each image to count false positives, reported in the
  plan's results.

  *Results (1.9a, 2026-10-27, PR #30):* the read-only proof passes on all
  seven images Linode offers. The collector wrote nothing on any of them,
  and the snapshot and `checker analyze` passes held. Linode has no RHEL
  images.

  | Image | Collector | Peak memory | Medium+ findings on a fresh server | Low / hygiene |
  |---|---|---|---|---|
  | Ubuntu 22.04 | 61 s | 47 MB | 4 (the proof's own setup) | 13 services on a replaced `libaudit` |
  | Ubuntu 24.04 | 73 s | 53 MB | 4 (the proof's own setup) | 5 services on a replaced `libaudit` |
  | Ubuntu 26.04 | 64 s | 60 MB | 4 (the proof's own setup) | none |
  | Rocky Linux 9 | 52 s | 68 MB | 4 (the proof's own setup) | firewalld's libffi code |
  | Rocky Linux 10 | 73 s | 63 MB | 4 (the proof's own setup) | none |
  | AlmaLinux 9 | 56 s | 67 MB | 4 (the proof's own setup) | firewalld's libffi code |
  | AlmaLinux 10 | 41 s | 59 MB | 4 (the proof's own setup) | `/boot/efi` 755 where the package says 700 |

  The proof's own setup is a direct root login, the `scanner` and
  `proofuser` accounts it creates, and the `at` job it queues: correct
  findings, not false alarms. So every image is clean of false alarms at
  medium and above.

  The matrix runs turned up these fixes:
  - systemd 256+ login placeholders added to the proof's disclosed writes;
  - processes forked without a new program, like `(sd-pam)`, judged by
    their ancestors' start;
  - mode changes rated by what they allow;
  - Python caches and libffi tuned down (in #28);
  - the proof survives Linode API timeouts, and deletes any server they
    leave.

  Spend so far: about 5.5 server-hours, roughly 4 cents of the $10 cap.

## Explicitly gated on John

- Any change to the security and privacy policy's wording. None is expected:
  the policy already covers "only what the checks need", masking, and
  encrypted evidence. If a module needs more than that, it stops for a
  decision first.
- Spending on throwaway servers for 1.9 (the matrix and scenarios: roughly
  ten Nanodes for under an hour per run, a few cents to tens of cents).
- Running the tool against nouriloop-prod as the first real-world clean
  baseline, after 1.8 — only with his go-ahead.

## Decisions to confirm with John (one at a time, before the PR that needs it)

1. **Before 1.2 — `/etc/shadow`:** send per-account password *status* only
   (recommended), never hashes.
2. ~~Before 1.5 — process command lines.~~ **Decided 2026-10-27:** sent
   masked (they are the main evidence for reverse shells and miners).
3. ~~Before 1.5 — web roots.~~ **Decided 2026-10-27:** common paths by
   default (`/var/www`, `/srv/www`, `/srv/http`, `/usr/share/nginx/html`),
   replaced by a per-host list where one is set.
4. ~~Before 1.9 — budget.~~ **Decided 2026-10-27:** a $10 cap for all of
   1.9; each run still needs John's OK, with its server count reported.

**As built:** 1.4 was split into 1.4a (logs and boots, #20), 1.4b (package
verification) and 1.4c (SUID/SGID files, file capabilities, unowned
executables), to keep each review small.

## After Phase 1

- **Package verification against vendor packages** (noted during 1.4b): rpm's
  database and dpkg's lists live on the server, so root can rewrite them with
  the file they describe. Compare instead with checksums from the vendor's
  signed packages or repository metadata, fetched by the controller.


Phase 2 (whitelists, scoring and calibration, checks 8.8–8.13) gets its own
plan once Phase 1's clean-host false-positive counts are in: they decide
what the default whitelist profiles must cover.
