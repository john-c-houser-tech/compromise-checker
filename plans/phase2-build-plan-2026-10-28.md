# Phase 2 build plan — 2026-10-28

> **Status: AGREED 2026-10-28** — outline and details reviewed by John;
> decisions 1–5 settled. Nothing built yet.

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
  together, so each PR's proof shows the whole thing working. A slice that
  grows too big for one review splits into *a* (collector and parser) and
  *b* (checks), as 1.4–1.7 did.
- **The score never hides evidence.** Whitelisting a finding removes its
  contribution to the score but keeps the finding, with the rule that
  suppressed it. Nothing is deleted or rewritten.
- **Ratios live in one table.** Each check states its default likelihood
  ratio in one place (`checker/scoring.py`), not scattered through check
  code, so calibration changes one file and the golden reports show the
  effect.
- **Low coverage never lowers the score**, and is shown beside it
  (DESIGN.md §11.4).
- **Host text never steers a rule.** Whitelist rules and chains match typed
  fields (account, address, path, program, port), never free text from the
  host, and path patterns are anchored, so a file name an intruder chose
  can't make a narrow rule match more than it says.
- **Each slice states its limits.** Several Phase 2 checks see only what is
  there at collection time (open connections, running containers). The
  docs and the report say so rather than imply continuous watching.

## Pull requests

### 2.0 — `purge` and retention (decision 1: decided)

Policy §8 promises: evidence, snapshots and reports kept 90 days by default,
the period configurable, a `purge` command for a server or a date range, and
data for a server removed from the inventory deleted when its retention
ends. None of that is built, and the bundles, custody, baselines and
assessments tables are append-only, enforced by triggers.

- `checker purge HOST | --before DATE | --expired [--dry-run]`.
  `--expired` uses `retention_days` from the configuration (90 by default)
  and covers hosts removed from the inventory. `--dry-run` lists what would
  go, by identifiers and counts.
- One transaction: drop the append-only triggers, delete the rows, recreate
  the triggers, and add a row to a new append-only `purges` table (time, who,
  scope, bundle identifiers, counts, never content). SQLite's schema changes
  are transactional, so a failure leaves the triggers in place.
- Files removed after the commit: the bundle, its events, snapshot and
  assessments, and that host's reports. A crash between the commit and the
  deletes is finished by the next `purge` (it removes files no row refers
  to, inside the evidence directory only).
- Custody: a purged bundle's custody rows go with it; the `purges` row is
  the record that it existed.
- Baselines: if a host's baseline is purged, its oldest remaining usable
  bundle becomes the baseline, the `purges` row says so, and the next
  analysis states it, as for a first analysis.
- `collect` and `analyze` print one line when expired data exists, so it
  isn't silently kept past the policy's period.
- `docs/retention.md`: what purge deletes, and its limit (an unlink, not a
  wipe; on SSDs and copy-on-write file systems the blocks may survive
  until reused — encryption is what protects them).
- Tests: purge by host, by date, expired; the triggers are back after
  success and after a forced failure; a purged baseline moves; a dry run
  changes nothing.

### 2.1 — Scoring core

- **`checker/scoring.py`** holds:
  - default ratios by band: info 1, low 1.5, medium 4, high 20;
  - per-check overrides for DESIGN.md §11.1's critical examples, with a new
    `critical` band (ratio 100): `persistence.ld_preload`, `process.hidden`,
    `kernel.taint` by an unexplained module, `package.changed` on the
    programs intruders replace, `account.uid0` (a second UID 0 account);
  - a `variant` on findings whose check reports several things at
    different bands (for example `ssh.authorized_keys`: new key, changed
    options), so the table can give each its own ratio.
- **The model** (DESIGN.md §11):
  `log-odds = log-odds(prior) + Σ contributions (+ chain bonuses, 2.3)`.
  - Only *compromise indicator* findings count. Hygiene and exposure get a
    separate rating: the highest band among them and their counts.
  - **Same thing, several checks.** Phase 1's proofs showed one behaviour
    caught by two checks (a set-user-ID shell in `/tmp` is both
    `files.scratch` and `files.privileged`). Findings that share an entity
    (the same path, process or account) form a group; the group counts its
    strongest finding in full and adds at most log 2 for the rest.
  - **Family caps.** Findings of one check count at most its strongest
    ratio plus log 2 in all, so fifty failed logins are not fifty findings'
    worth.
  - **Uncertain** findings (a section not fully collected on one side)
    count half their log ratio.
  - Findings count on every analysis while the state they describe is
    there (a change stays a finding until a new baseline is accepted); the
    report marks which are new since the previous bundle.
  - Prior: 2% by default; settable per group and per host in the
    configuration (`prior:`), shown in the report beside the score.
  - Bands: Low below 10%, Elevated 10–50%, High 50–90%, Critical 90% and
    above.
- **Assessments v2:** scoring version, prior, each finding's ratio,
  contribution and group, the probability and band, the hygiene and
  exposure rating. Older assessments stay as they are; analysing again adds
  a v2 one. The index's encrypted summary gains the band.
- `checker analyze` prints the probability, band and top contributors;
  `checker report` puts them at the top of each host, with coverage beside
  the score and the contributors' table (each finding's share of the
  log-odds, largest first). The report stops saying the score is Phase 2.
- **Golden reports** (`tests/golden/`): the derived inputs of each case
  (events, snapshot, the baseline's snapshot, as JSON, from throwaway
  servers only, so nothing personal) and the expected assessment. CI runs
  the checks and scoring over them and fails on any difference;
  `scripts/update-golden` rewrites the expectations and shows the diff for
  review. Cases: a fresh Ubuntu 24.04 and Rocky 9 server, and the detection
  proof's compromised state on both. They come from the 1.9 proof runs if
  their data is still on disk; otherwise from one run of each proof (a few
  cents, under decision 5).
- `docs/scoring.md`: the model, the ratio table, worked numbers, and the
  calibration results (filled in by 2.10).
- Tests: the worked numbers of DESIGN.md §11.3 (2% and one LR 20 → 29%; plus
  an LR 5 → 67%); group and family caps; uncertain halving; hygiene never in
  the probability; band edges.

*As built:* split into 2.1a (scoring, priors, assessments v2, the CLI and
the report, `docs/scoring.md`) and 2.1b (golden reports). The 1.9 proof
data no longer exists (the proofs ran in temporary folders), so 2.1b needs
one run of each proof on Ubuntu 24.04 and Rocky 9 under decision 5, with
the proofs saving their derived data, public addresses replaced by
documentation addresses (the repository is public). The `critical` band is
set by the checks themselves (five cases), so the table maps bands to
ratios and `OVERRIDES` starts empty; `variant` is set where a check's
kinds weigh differently (`kernel.taint` so far) and grows with 2.2.

*2.1b results (2026-10-28):* one detection-proof run with `--golden` on
Ubuntu 24.04 and Rocky 9 (2 Nanodes, about 1 cent; both deleted): all ten
behaviours detected on both. Golden cases and expectations are in
`tests/golden/` (0.9 MB). Scores: compromised servers 100% Critical; fresh
servers High (Ubuntu 72%, Rocky 80%), entirely from the proof's own setup
(the `scanner` and `proofuser` accounts it creates, its root login, its
`at` job: four mediums). 2.2's whitelist for that setup should bring them
to Low (done-means 2). A calibration note for 2.10: four mediums from
different checks take a 2% prior to about 72%.

### 2.2 — Whitelists

- **Files**, in the configuration directory:
  `whitelist/global.yaml`, `whitelist/groups/<group>.yaml`,
  `whitelist/hosts/<host>.yaml` (hosts already have a group in the
  inventory). Each file holds:
  ```yaml
  profiles: [base, web]          # shipped profiles to apply (2.10)
  rules:
    - id: home-office
      match:
        check: ssh.login
        variant: new_address
        address: 203.0.113.10/32
      reason: "Home office."
      owner: john
      expires: 2027-10-25
  disable:                       # switch off a rule from a wider layer
    - id: web-mail-from-www-data
      reason: "This host never sends mail."
      owner: john
  maintenance:                   # windows (deferred from 1.7)
    - every: [sun]
      from: "02:00"
      to: "04:00"
      tz: UTC
      reason: "Weekly patching."
      owner: john
      expires: never
  ```
  This replaces DESIGN.md §9.2's bare list; the design is updated to match.
- **Validation is strict:** unknown keys, unknown check ids or variants,
  a missing `reason`, `owner` or `expires`, an id used twice in one merged
  set, and a malformed address or date are errors, and `analyze` refuses to
  run with an invalid set (it says which file and line). A rule matching on
  `check` alone, with no entity, is allowed only with `broad: true`.
- **Matching fields:** `check`, `variant`, `account`, `group`, `address`
  (address or network), `path` (glob, anchored, `*` doesn't cross `/`,
  `**` does), `program`, `module`, `port`, `unit`, and from 2.3
  `correlated_with`. All given fields must match.
- **Effect:** a matched finding is kept with `suppressed_by` (rule id,
  layer, file) and contributes nothing to the score. An expired rule stops
  matching and is reported. The assessment stores the merged rules it used
  and their hash, so a later reader knows exactly what applied.
- **Maintenance windows:** reboots classified *unexplained* or *unclean*,
  and package changes (2.6), inside a window become informational, with
  the window named.
  **Decided 2026-10-28 (John, after the 2.2b review):** an *unclean*
  reboot inside a window drops one band (medium to low), never to
  informational: its crash time is unknown, and a forced reset timed for
  the patch night must stay visible. Unexplained reboots become
  informational.
- **Commands:**
  - `checker whitelist check [HOST]` validates, and prints the merged set
    for a host with each rule's origin;
  - `checker whitelist test HOST [--file F]` re-applies the rules (with a
    proposed file in place of the current one) to the host's stored
    assessments in the retention period and shows, per assessment, which
    findings would be hidden or revealed and the score before and after;
  - `checker whitelist stale` lists rules with no match in 90 days of
    assessments, and rules expired or expiring within 30 days.
- The read-only and detection proofs get a host file whitelisting their own
  setup (the `scanner` and `proofuser` accounts, the proof's root login,
  its `at` job), so their reports show those in the appendix.
- `docs/whitelists.md`; the report's appendix lists suppressed findings with
  their rule and reason.
- Tests: layers and `disable`; every validation error; anchored globs (a
  file named `x/../y` or with `*` in it doesn't widen a match); expiry;
  `test` output; a window boundary.

*As built:* split into 2.2a (files, validation with file and line, layers
and `disable`, matching, suppression in `analyze` and the report, `checker
whitelist check`, the proofs' own whitelist) and 2.2b (`whitelist test`,
`whitelist stale`, maintenance windows). Checks now declare their variants
(`ssh.login`, `system.reboot`, `kernel.taint` so far), so a rule naming an
unknown variant is an error. The proofs' setup is whitelisted by
`tests/integration/proof-whitelist.yaml`, also carried by the golden cases:
the fresh servers now score Low (Ubuntu 2.0%, Rocky 3.0%, the remaining
point from firewalld's libffi code), the compromised ones still 100%
Critical, and the detection proof ignores suppressed findings, so the
whitelist can't hide a behaviour.

*2.2b as built:* maintenance windows (weekly in a time zone, or once with
offsets; ids shared with rules, so `disable` and expiry work the same);
`checker whitelist test` reads stored assessments only and adds nothing;
`checker whitelist stale` counts a rule once by file and id across hosts.
A window must hold the whole outage (shutdown and boot); an expired window
still explains what it covered. The whitelist record now leaves out unset
fields, so every 2.2a assessment's whitelist hash differs and the next
report reassesses it once (no checks run).

### 2.3 — Correlation

- **Engine** (`checker/correlate.py`): a time-ordered view of a bundle's
  events and findings, and matchers of the form "A, then B within T, sharing
  K" (K: account, address, process ancestry, or path prefix). Times are the
  corrected times from 1.6a; findings without a time (state found in the
  snapshot) match only steps marked `state: true`.
- **Whitelist `correlated_with`:** a finding is suppressed only when the
  other step is there too. The design's deploy example (a login followed by
  `git pull`) needs a record of the pull: in Phase 2 that is a `sudo.command`
  event (`sudo -u deploy git pull`) or, from 2.8, an audit `execve` record;
  without either the login stays a finding, and the docs say so.
- **Chains** in `checker/scoring.py`, as data. Each names its steps, window
  and bonus ratio, added once per chain found and shown in the contributors
  as its own line. Ones that land with 2.3 (the rest arrive with the checks
  they need):
  1. a new account or key → a privilege for it (`sudo.rules`,
     `group.privileged`) → a login by it, within 7 days: ×5;
  2. a guessed login (`ssh.guessed`) → a new key, persistence change or
     privilege for that account, within 24 hours: ×5.
  Later: web worker child → scratch file → outbound connection (2.4, 2.8):
  ×10; anything high → logging stopped or history wiped (2.5): ×3; a new
  web script → successful requests to it (2.8): ×5.
- Tests: each chain present, absent, outside its window, and with a
  different account; a whitelisted step doesn't count towards a chain.

*As built:* `checker/correlate.py`. Whitelist conditions require a partner
for every event the finding cites (never itself), with `same` account
and/or address and an optional command pattern (matched without
backtracking). Chains count once each; state steps (no time) must be new
since the previous bundle. `sudo.rules` findings now name the account or
group a rule grants to, so the first chain can follow it. No chain fires
on the golden cases (fresh or detection); the proofs stage chains in 2.10.
After the 2.3 review (2 High): a condition's partner must be trusted (the
journal's own `_COMM` and root `_UID`, not a `logger -t sudo` line), and
`sudo.rules` entities cover the whole user list. John's side note
(2026-10-28): a stolen deploy key can still log in and run the same
command, so a rule with `correlated_with` must name the account, a command
must start with the program's full path, and docs/whitelists.md states the
limit and recommends an address range. Chains use variants (new accounts
and keys only), distinct findings and log lines per step, a login after
the previous bundle when no step is timed, and never the tool's own
account. SCORING_VERSION 2, CHECKS_VERSION 6.

### 2.4 — Network and data transfer (8.8)

- **Collector, new module `network`** (files, plus the two firewall
  commands of decision 2): `/etc/hosts`, `/etc/resolv.conf`, `nsswitch.conf`,
  `/etc/hosts.allow` and `hosts.deny`; per interface from `/sys/class/net`:
  flags (promiscuous), state and byte counters; routes from `/proc/net`.
  Firewall rules per decision 2: the configuration files, and the loaded
  rules only where the firewall is already loaded; loaded rules that differ
  from the configuration are a `net.config` finding. Existing: listeners,
  and each process's sockets, from 1.5b.
- **Snapshot:** `network_files`, `interfaces` (compared), and a compared
  `peers` summary from the live sockets: program, remote port and remote
  network (/24 or /48), so "new destination" means new for that program,
  not a new ephemeral address.
- **Checks** (proposed ratios):
  - `net.listener` new listening port: low;
  - `net.directory` ★ a host in a group whose profile marks it web-facing
    with a connection to directory services (445, 389, 636, 88, 3268,
    5985, 5986): high;
  - `net.metadata` a connection to 169.254.169.254 from a program other
    than the known cloud agents: medium;
  - `net.peer` a new destination for a program: low; on an unusual port
    or a Tor port (9001, 9030, 9050, 9150), or from a `tor` process: medium;
  - `net.tunnel` an `ssh` client with forwarding options, or an sshd
    session holding a listening socket (a remote forward): medium;
  - `net.config` changes to hosts, resolver, NSS, TCP wrappers or firewall
    rules: medium (low inside a maintenance window);
  - `net.promiscuous` an interface in promiscuous mode not from a known
    capture tool or bridge: medium;
  - `net.transfer` weak signals, each low and mainly chain material: large
    archives (zip, tar, 7z, over 50 MB) in scratch places; `curl`, `wget`,
    `scp`, `rsync` or `rclone` running at collection time with a public
    peer; an interface's transmit counter far above its receive counter
    since boot on a host that serves little.
- **Limits stated:** connections are a sample at collection time; with no
  firewall or proxy logging, transfer evidence is weak, and the report says
  so and names the source that would help (egress firewall logging,
  auditd `connect` rules).
- **Detection behaviours:** `curl` to the metadata address in a loop; a
  connection to port 445 on a documentation address (blocked, so the socket
  sits in `SYN_SENT`); an `ssh -R` forward to localhost; `/etc/hosts`
  rewritten.

*As built:* split into 2.4a (the collector's `network` module, the
`network_files`, `interfaces`, `firewall_rules` and `peers` snapshot
sections, and the read-only proof's module-list check; proof: read-only on
all seven images) and 2.4b (the checks, with their detection behaviours).
Peers leave out connections accepted on the host's own listening ports
(found while testing: an incoming SSH session looked like an outgoing
connection to the client's port).
After the 2.4a review, `nft` isn't run while nft_compat is loaded
(iptables-nft rules: ufw, Docker), so those servers' live rules are a
coverage gap. **Decided 2026-10-28 (John): the first step of 2.4b is an
experiment** on Ubuntu 22.04, 24.04 and 26.04 with ufw enabled and Docker
running (3 Nanodes, about 2 cents, approved): `nft list ruleset` and
`iptables-nft-save`, several times each, with the kernel's module list
compared around every run. If nothing ever loads, the collector reads
those rules too and the proof keeps ufw and Docker on the Ubuntu images;
if anything loads, the gap stays and the docs name it.

*Experiment result (2026-10-28, 3 Nanodes, about 2 cents, all deleted):*
CLEAN on Ubuntu 22.04, 24.04 and 26.04 with ufw enabled and Docker
running a container (nft_compat loaded on each): 5 rounds each of `nft
list ruleset`, `iptables-nft-save` and `ip6tables-nft-save`, 45 listings,
and the kernel's module list never changed around one. So 2.4b lists
those rules (`nft`), and the read-only proof runs ufw and Docker on the
Ubuntu images. Script: `tests/integration/nft_compat_experiment.py`.

*2.4b as built:* `checker/checks/network.py`: `net.listener`, `net.peer`,
`net.metadata`, `net.directory` (judged by the process's account, not a
host role, which waits for 2.10's profiles), `net.tunnel`, `net.config`,
`net.promiscuous`, `net.transfer`; documentation ranges count as public
there (they stand in for real addresses in tests and golden cases). The
detection proof gains the four network behaviours.
After the 2.4b review (2 High): LDAP and Kerberos from web accounts are
medium (SMB and WinRM stay high); the metadata check knows agents by the
file they run (and AWS's IPv6 address); managed chains (Docker, Kubernetes,
fail2ban…) are summarised; ssh options parsed as ssh does; X11 forwards
left out; container restarts aren't new listeners; entities for whitelist
rules; Open vSwitch ports; container bridges out of the counters. John's
side note: a chain named like a managed one is only summarised, so a new
check, `net.managed_chain`, flags such a chain whose owner isn't running,
and `DOCKER-USER` is compared rule by rule.

*2.4b proofs (2026-10-28, approved by John; about 3 cents, every server
deleted):* read-only PASS on Ubuntu 22.04, 24.04 and 26.04 with ufw and
Docker running: nft_compat loaded, the rules listed with `nft`, no firewall
module changed, the collector wrote nothing. Detection PASS on Ubuntu 24.04
and Rocky 9 after two reruns, all fifteen behaviours at their bands. The
first run found every behaviour but failed on the proof's own metadata
check (bash had replaced itself with `sleep`; now checked by socket) and
showed root's connections named after the proof's second UID 0 account
(a shared UID is now named after its first account). The second showed
the metadata connection at low: a root `sleep` in a system directory read
as SDK-like, so shells, interpreters without a script and generic tools
now stay medium. Golden cases re-exported from the first run (they now
hold the network behaviours); the proof whitelist covers its Docker
install (`dnsmasq` account, `docker` group). Phase 2 spend so far: about
11 cents.

*2.4a proof (2026-10-28, read-only, all seven images, 7 Nanodes, about 5
cents, all deleted):* PASS on every image: the collector wrote nothing and
no firewall module was loaded or unloaded during any collection.

| Image | Firewall | Rules listed | Collector | Peak memory |
|---|---|---|---|---|
| Ubuntu 22.04 | ufw (nft_compat) | no: gap, as designed | 57 s | 47 MB |
| Ubuntu 24.04 | ufw (nft_compat) | no: gap, as designed | 71 s | 53 MB |
| Ubuntu 26.04 | ufw (nft_compat) | no: gap, as designed | 66 s | 60 MB |
| Rocky Linux 9 | firewalld (native nftables) | yes, `nft` | 54 s | 68 MB |
| Rocky Linux 10 | none loaded | nothing to list | 54 s | 63 MB |
| AlmaLinux 9 | firewalld (native nftables) | yes, `nft` | 56 s | 69 MB |
| AlmaLinux 10 | none loaded | nothing to list | 45 s | 65 MB |

For 2.10's calibration: on Ubuntu 22.04 one `(sd-pam)` process was a
*high* "code mapped from a deleted file" (libaudit, replaced when the
proof installs auditd), beside the known low hygiene findings for the same
library; the 1.9 ancestor rule for forks without a new program didn't
cover it this time.

### 2.5 — Anti-forensics (8.10, ★ all)

- **Collector, new module `logging_state`:** a manifest of `/var/log` and
  `/var/log/journal` (names, sizes, times, inode numbers; no contents);
  journald, rsyslog and auditd configuration files; audit rules files
  (`/etc/audit/rules.d`, `audit.rules`); from `/var/log/audit/audit.log`,
  only records of the types `CONFIG_CHANGE`, `DAEMON_START`, `DAEMON_END`,
  `DAEMON_ABORT`, `MAC_STATUS` and `MAC_POLICY_LOAD` within the look-back;
  SELinux mode from `/sys/fs/selinux/enforce` and `/etc/selinux/config`;
  AppArmor profile names and modes from `/sys/kernel/security/apparmor`.
- **Checks** (all high unless noted):
  - `logs.cleared` `wtmp` or `btmp` emptied or shrunk since the previous
    bundle without a rotation (the rotated file is there and newer); a log
    file that existed in the baseline missing, or smaller with the same
    inode;
  - `logs.journal_gap` a gap of six hours or more inside one boot's journal
    on a host whose journal is otherwise busy (median gap under ten
    minutes): medium, tuned in 2.10;
  - `logs.stopped` auditd, rsyslog or journald stopped or failed outside a
    shutdown (journal `unit.stopped` events, and auditd's own
    `DAEMON_END`), or disabled since the baseline; audit rules changed
    (files, or a `CONFIG_CHANGE` record not from the rules loading at
    boot);
  - `logs.journald_config` `Storage=none` or `volatile` set since the
    baseline;
  - `history.disabled` a history file linked to `/dev/null`; a history
    file emptied that wasn't before (medium); `unset HISTFILE`,
    `HISTSIZE=0` or `HISTFILE=/dev/null` in system start-up files;
  - `mac.disabled` SELinux permissive or disabled where the baseline had it
    enforcing (or `setenforce 0` in the logs); AppArmor profiles unloaded or
    set to complain;
  - `agent.stopped` a known security agent (fail2ban, wazuh, osquery,
    falcon-sensor, and the like, kept as a list) running in the baseline
    and not now;
  - `clock.jump` the clock set by more than a minute other than by
    time synchronisation (journal "Time has been changed" without
    `systemd-timesyncd` or `chronyd` around it): medium.
- **Detection behaviours:** `history -c` plus the root history linked to
  `/dev/null`; `systemctl stop auditd` (installed first on Ubuntu);
  `setenforce 0` on Rocky; `wtmp` truncated.

*As built:* one PR (collector, snapshot v6 and checks together).
`checker/checks/antiforensics.py`; the checks see the previous bundle's
snapshot (`Context.previous_snapshot`) for the log manifest. The journal
gap inside one boot isn't checked (it needs the whole journal); a
`system.clock_changed` event (parser version 3) feeds `clock.jump`. John's
side note: a file merely named like a rotated copy doesn't excuse a shrunk
log; the copy must carry the old inode or be an uncompressed copy at least
as large. On Ubuntu the detection proof unloads AppArmor's profiles
(`aa-teardown`) in place of `setenforce 0`.
After the 2.5 review (4 High): logging restarts and augenrules reloads are
routine, and removed rules are one finding; AppArmor's transient profiles
are left out and a few changes are medium; replaced key logs and a
removed journal are reported; a cut-short listing never reads as
deletion; `node=`-prefixed audit records count and the newest are kept;
agents and services are keyed by the file they run; no service findings
without a full process listing; journald precedence as systemd's.

*2.5 proofs (2026-10-28, approved by John; 11 Nanodes, about 6 cents,
every server deleted):* read-only PASS on all seven images (the collector
reads /var/log and the audit log and wrote nothing; no firewall module
changed). Detection PASS on Ubuntu 24.04 and Rocky 9, all nineteen
behaviours, after one rerun: the first run's Rocky server timed out at
Linode's API, and on Ubuntu `aa-teardown` unloaded 28 of its profiles,
under half, which the most-of-them rule rated medium; ten or more is now
high, and the proof checks the profile count fell rather than
aa-teardown's exit code. Golden cases re-exported from the passing run.
Phase 2 spend so far: about 17 cents.

### 2.6 — Software changes (8.11)

- **Collector, new module `software`:** package logs within the look-back
  (`/var/log/dpkg.log*`, `/var/log/apt/history.log*`,
  `/var/log/dnf.rpm.log*`, rotated and compressed ones included);
  repository files (`/etc/apt/sources.list`, `sources.list.d`,
  `/etc/yum.repos.d`) as masked text; signing keys as fingerprints
  (`/etc/apt/trusted.gpg*`, `/etc/apt/keyrings`, `/usr/share/keyrings`,
  `/etc/pki/rpm-gpg`); names and versions of global Python and Node
  packages (`dist-info` and `node_modules` directory names under
  `/usr/local/lib` and `/usr/lib/node_modules`); and the installed-package
  list (names, versions, architectures, install times), read from the same
  rpm database and dpkg status file `package_verify` (1.4b) already reads,
  which sends only file results today.
- **Snapshot:** `packages`, `repositories`, `signing_keys`,
  `global_packages`, all compared.
- **Checks:**
  - `software.packages` installed or removed: low; info inside a
    maintenance window or when an automatic updater ran it;
  - `software.repository` a new repository or signing key: medium;
  - `software.tools` attack and tunnelling tools appearing (`nmap`,
    `masscan`, `socat`, `ncat`, `proxychains`, `chisel`, `hydra`…, by
    package or by program name in the system walk): medium; compilers
    appearing (`gcc`, `cc`, `clang`, `go`, `rustc`) on a host whose profile
    doesn't allow them: low;
  - `software.global` new global `pip` or `npm` packages: low.
- **Detection behaviours:** `nmap` installed; a repository file added with
  a new key.

*As built:* the collector's `software` module reads the installed
packages itself (rpm's database immutable, dpkg's status file; the
install time from rpm, or from dpkg's file lists), not the package logs:
the checks need what is installed, and install times date it. Signing
keys are hashed, not parsed (a new or changed key file is the finding).
Package changes are grouped, one finding per kind; a maintenance window
makes installs and removals informational.

### 2.7 — Outgoing mail (8.9) (decision 3: decided)

- **Collector, new module `mail`:** Postfix (`main.cf`, `master.cf`) and
  Exim configuration as masked text, never `sasl_passwd` or other secret
  maps; mail log lines from the journal (Postfix and Exim units) or
  `/var/log/mail.log`/`maillog` within the look-back, with recipient and
  sender addresses masked on the server per decision 3 (the domain kept,
  the local part replaced by a keyed hash, so the same address can be
  counted without being shown); queue size by counting files
  in the spool directories, never by running `mailq`.
- **Events:** `mail.sent`, `mail.deferred`, `mail.bounced`,
  `mail.submitted` (with the submitting UID from Postfix's `pickup`).
- **Snapshot:** `mail_config` (settings), and a compared summary of
  relays, recipient domains and sending users per day.
- **Checks:**
  - `mail.web_user` mail submitted by a web-server user: medium (the web
    profile whitelists it for hosts whose apps send mail);
  - `mail.relay` a new relay host, or open-relay settings (`mynetworks`
    wider than the host's own networks, permissive relay restrictions):
    medium; open relay is also an exposure finding;
  - `mail.volume` a day's sent count over ten times the baseline's daily
    average and over 100; deferred queue over 500 or ten times its
    baseline: medium;
  - `mail.domains` more than 50 recipient domains not seen before in one
    day: medium.
- **Detection behaviour:** a burst of local mail submitted as `www-data`
  (`apache` on Rocky) to documentation domains, which Postfix defers.

### 2.8 — Web applications (8.12) (decision 3: decided)

- **Collector, new module `web_logs`:** web server configuration (nginx,
  Apache) to find access and error logs, defaulting to `/var/log/nginx`,
  `/var/log/apache2`, `/var/log/httpd`; access and error log lines within the
  look-back, bounded by bytes, only when the organization opted in, masked
  per decision 3; PHP-FPM logs and error logs always. From `audit.log`,
  where auditd runs: `SYSCALL` (execve), `EXECVE` and `PROCTITLE` records
  within the look-back for web-server accounts (more with decision 3's
  opt-ins), masked like command lines (masking v6).
- **Parsers:** combined and common formats, and nginx's default; any other
  format is a coverage gap ("access log format not recognised"), not a
  silent skip. Audit records are joined by their serial into one
  `process.exec` event (user, parent, program, masked arguments).
- **Checks:**
  - `web.worker_child` ★ a shell, interpreter, download tool or recon
    command (`id`, `whoami`, `uname`, `cat /etc/passwd`…) whose parent is a
    web worker (`php-fpm`, `httpd`, `apache2`, `nginx`, `lsphp`) or that
    runs as a web-server user outside a login session: high; live from
    1.5b's processes and historical from audit records. With no auditd, the
    coverage says historical process data is missing and points to a rule
    file shipped as `docs/auditd-web.rules`;
  - `web.new_script_hit` successful (2xx) requests to a script `files.web`
    found new since the baseline: high, and a chain with it;
  - `web.exploit` exploit strings (path traversal, `php://`, `<?php` in a
    request, `${jndi:`, shell metacharacters with `sh`, `%00`) answered 2xx
    or 5xx: medium; answered 3xx or 4xx: info;
  - `web.errors` a burst of 5xx or upstream errors from one source (20 or
    more in five minutes): low;
  - **background noise** (DESIGN.md §17): requests for paths the site
    doesn't have, answered 3xx or 4xx, without errors, are summarised as
    one informational line per source network, not one finding each.
- **Detection behaviours:** nginx and PHP-FPM installed on the throwaway
  server; a PHP file dropped in the web root that runs `id` and starts a
  shell, requested a few times with `curl`; auditd installed with the
  shipped rules so the historical path is proved too.

### 2.9 — Containers (8.13) (decision 4: decided)

- **Collector, new module `containers`**, reading files only (decision 4),
  locations from Docker's `daemon.json` and Podman's `storage.conf`:
  Docker's `/var/lib/docker/containers/<id>/config.v2.json` and
  `hostconfig.json`; Podman's
  `/var/lib/containers/storage/overlay-containers/containers.json` and each
  container's OCI `config.json`. The collector keeps only: id, name, image,
  created, running, privileged, added capabilities, host PID/network/IPC
  namespaces, devices, and mounts (source and destination). Never the
  environment (it holds secrets) or labels. Rootless Podman in homes, and
  Kubernetes (a `kubelet` present), are coverage notes, not inventoried.
- **Snapshot:** `containers`, compared.
- **Checks:**
  - `container.privileged` privileged, or mounting `/`, `/etc`, `/root`,
    `/var/run/docker.sock` or Podman's socket, or with `SYS_ADMIN`: high if
    new since the baseline, else medium hygiene;
  - `container.host_namespace` host PID or network namespace: medium if
    new;
  - `container.new` new containers: low (deploys make them).
- **Detection behaviour:** a privileged container mounting `/` started with
  Docker on Ubuntu and Podman on Rocky.

### 2.10 — Default profiles and calibration

- **Profiles** shipped as `checker/profiles/*.yaml`, applied by a layer's
  `profiles:` list, every rule with a reason and owner "Compromise Checker
  defaults":
  - *base*: what the 1.9 fresh servers showed (Ubuntu's services on a
    replaced `libaudit`, firewalld's libffi code on Rocky and Alma,
    AlmaLinux 10's `/boot/efi` mode), and what 2.4–2.9 show on them;
  - *web*: marks a host web-facing (for `net.directory`), web users sending
    mail through the local sendmail, PHP-FPM's own workers;
  - *database*: database listeners, large files in database directories;
  - *mail*: relay traffic and queue sizes of a mail relay;
  - *build*: compilers allowed.
- **Calibration harness** (`tests/integration/calibrate.py`): runs the
  read-only proof on all seven images and the detection proof on Ubuntu
  24.04 and Rocky 9, gathers each run's assessment, and writes the results
  table (probability and band per clean image; band reached per behaviour
  and chain; false positives by band) into this plan and
  `docs/scoring.md`. Assertions: done-means 2 and 3.
- **Detection proof** gains each slice's behaviours (listed above) and two
  chains: a new account given sudo then logging in; the web shell writing a
  file to `/tmp` and opening an outbound connection.
- **Tuning:** ratios and thresholds adjusted from the results, each change
  recorded with its reason in `docs/scoring.md`, and the golden reports
  regenerated in the same PR so the diff shows the effect.
- **Real-world clean run:** with John's go-ahead, nouriloop-prod with the
  *web* profile. Only counts go into the plan (findings by band, score),
  never their content.

## Explicitly gated on John

- Any change to the security and privacy policy's wording. 2.0 may tighten
  §8's retention lines to match what is built; 2.7 and 2.8 collect personal
  data the policy doesn't yet name (decision 3).
- New allow-listed commands on targets beyond decision 2's two.
- Spending on throwaway servers: each slice's proof and 2.10's calibration
  runs, one approval per PR within the $10 cap (decision 5).
- Running the tool against nouriloop-prod.

## Decisions to confirm with John (one at a time, before the PR that needs it)

1. ~~Before 2.0 — purge vs append-only.~~ **Decided 2026-10-28:** `purge`
   is the one sanctioned way to delete; it drops the triggers inside its
   transaction, deletes, restores them, and records what it removed (by
   identifiers and counts only) in an append-only `purges` table. A purged
   baseline moves to the host's oldest remaining usable bundle.
2. ~~Before 2.4 — firewall rules.~~ **Decided 2026-10-28:** configuration
   files always (`/etc/nftables.conf`, `/etc/sysconfig/nftables.conf`,
   `/etc/firewalld/`, `/etc/ufw/*.rules`, `/etc/iptables/rules.v4`);
   `nft -j list ruleset` only when `/sys/module/nf_tables` exists, and
   `iptables-legacy-save` only when `/proc/net/ip_tables_names` lists
   tables, so running them never loads a kernel module; otherwise coverage
   says no firewall is loaded. Both through 1.1's command runner with fixed
   arguments. Large sets (fail2ban, CrowdSec blocklists) sent as counts and
   a hash. The read-only proof also checks the module list is unchanged.
3. ~~Before 2.7 and 2.8 — mail and web logs.~~ **Decided 2026-10-28:**
   - *Web access logs* are opt-in in `checker init`, as policy §7 already
     promises; off, the web checks use live processes, audit records and
     error logs, and coverage says which checks didn't run. On: client
     addresses kept; query-string and referrer values masked, keys kept,
     except that a value matching an exploit pattern is replaced by a
     marker naming the pattern; user agents cut to 256 characters.
   - *Mail logs* always collected (8.9 needs them): every address's local
     part replaced on the server by an HMAC with a per-organization key
     made at `checker init` (`h:3f9a1c2e@example.org`), domain kept; a
     `checker` helper hashes a known address for an investigator.
   - *Audit exec records* by default only for web-server accounts
     (`www-data`, `apache`, `nginx`, and any configured). John asked for an
     option to collect more, shaped like the shell-history opt-in: also
     root, service and administrator accounts; and, only with that, also
     ordinary users. Arguments always masked (masking v6).
   - Policy §7 gets matching bullets, worded in the 2.7 and 2.8 PRs for
     John's approval.
4. ~~Before 2.9 — containers.~~ **Decided 2026-10-28:** the runtimes'
   state files only, never their sockets (Podman's is usually
   socket-activated, so connecting would start `podman.service`). Docker's
   directory from `data-root` in `/etc/docker/daemon.json` (and its
   userns-remap subdirectory), Podman's from `/etc/containers/storage.conf`.
   Only the listed fields leave the server; the environment never does.
   Running state cross-checked with live processes; an unrecognised file
   layout is a coverage gap, never "no containers".
5. ~~Before the first proof run — budget.~~ **Decided 2026-10-28:** a $10
   cap for all of Phase 2 (estimate: 90–100 server-hours, about $1); at $5
   spent, stop and tell John before going on. One approval per PR: asked
   once when its proof is ready (servers, images, expected cost), covering
   that PR's reruns after review fixes within the cap. After each run:
   servers used, cost, and a check that no tagged Linode is left. Runs
   outside a PR's stated scope, and any run against a real server, still
   need their own OK.

## After Phase 2

Carried over from Phase 1:

- **A RHEL proof run, only if there is interest in the software.**
- **Package verification against vendor packages:** compare with checksums
  from the vendor's signed packages or repository metadata, since root can
  rewrite rpm's database and dpkg's lists.
- **Encrypting reports at rest:** John's decision (2026-10-27) to revisit
  after the currently planned development phases.

Noted while planning Phase 2:

- **Logins at unusual hours** (DESIGN.md §8.3) need a per-host profile of
  normal hours; a candidate for Phase 3, where the advisor can propose it.
- **Outbound connections over time:** Phase 2 sees connections only at
  collection time. Continuous evidence needs firewall or proxy logs, or
  auditd `connect` rules; a collector for those logs is a later slice.
