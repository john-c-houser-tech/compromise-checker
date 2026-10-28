# Phase 2 build plan — 2026-10-28

> **Status: PROPOSED** — outline agreed with John 2026-10-28; details
> waiting for his review. Nothing built yet.

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

### 2.0 — `purge` and retention (needs decision 1 first)

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

### 2.4 — Network and data transfer (8.8)

- **Collector, new module `network`** (all files, no commands unless
  decision 2 allows): `/etc/hosts`, `/etc/resolv.conf`, `nsswitch.conf`,
  `/etc/hosts.allow` and `hosts.deny`; per interface from `/sys/class/net`:
  flags (promiscuous), state and byte counters; routes from `/proc/net`.
  Firewall rules per decision 2. Existing: listeners, and each process's
  sockets, from 1.5b.
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

### 2.7 — Outgoing mail (8.9) (needs decision 3)

- **Collector, new module `mail`:** Postfix (`main.cf`, `master.cf`) and
  Exim configuration as masked text, never `sasl_passwd` or other secret
  maps; mail log lines from the journal (Postfix and Exim units) or
  `/var/log/mail.log`/`maillog` within the look-back, with recipient and
  sender addresses masked on the server per decision 3 (proposed: the
  domain kept, the local part replaced by a short keyed hash so the same
  address can be counted without being shown); queue size by counting files
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

### 2.8 — Web applications (8.12) (needs decision 3)

- **Collector, new module `web_logs`:** web server configuration (nginx,
  Apache) to find access and error logs, defaulting to `/var/log/nginx`,
  `/var/log/apache2`, `/var/log/httpd`; access and error log lines within the
  look-back, bounded by bytes, with query-string values masked (keys kept)
  per decision 3; PHP-FPM logs. From `audit.log`, where auditd runs:
  `SYSCALL` (execve), `EXECVE` and `PROCTITLE` records within the look-back,
  masked like command lines (masking v6).
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

### 2.9 — Containers (8.13) (needs decision 4)

- **Collector, new module `containers`**, reading files only (proposed):
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
- New allow-listed commands on targets (decision 2).
- Spending on throwaway servers: each slice's proof and 2.10's calibration
  runs (decision 5). Each run still needs his OK, with its server count.
- Running the tool against nouriloop-prod.

## Decisions to confirm with John (one at a time, before the PR that needs it)

1. **Before 2.0 — purge vs append-only.** Proposed: `purge` is the one
   sanctioned way to delete; it drops the triggers inside its transaction,
   deletes, restores them, and records what it removed (by identifiers and
   counts only) in an append-only `purges` table.
2. **Before 2.4 — firewall rules.** Allow-list `nft list ruleset` and
   `iptables-save` (read-only, fixed arguments, through 1.1's command
   runner), or skip firewall rules and say so in coverage.
3. **Before 2.7 and 2.8 — mail and web logs.** Proposed: mail addresses
   kept as domain plus a keyed hash of the local part; client addresses
   kept (they are the evidence); query-string values masked, keys kept;
   user agents kept, bounded. Needs new policy §7 wording.
4. **Before 2.9 — containers.** Read the runtimes' state files, keeping only
   the listed fields (proposed), or ask the runtime over its socket (more
   complete, but talks to a daemon and its API).
5. **Before the first proof run — budget.** Proposed: a $10 cap for all of
   Phase 2, as for 1.9 (which spent about 10 cents). Slices with a web
   stack or containers take a few minutes longer to set up, so expect
   under $1 in all.

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
