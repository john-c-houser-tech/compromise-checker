# Checks

`checker analyze HOST` (or `--all`) runs every check (DESIGN.md §8.1–8.7) on a host's latest
bundle (or `--bundle ID`) and lists the findings, most serious first, with
what the collection couldn't see. Each analysis is stored as an encrypted
**assessment**. Checks read the bundle's [events](events.md) and
[snapshot](snapshots.md), and the snapshot's changes since the host's
baseline; the tool's own session is never a finding.

## Findings

Each finding has:

- **check**: the check's id, such as `account.uid0`.
- **title** and a one-line **summary**: what was seen, who, where.
- **category**: a *compromise indicator*, *exposure* or *hygiene*. Hygiene
  is not compromise (DESIGN.md §2 principle 9): an unattributed key is a
  risk, not evidence that someone got in.
- **band**: `high`, `medium`, `low` or `info`. `high` is for DESIGN.md
  §8's ★ checks. The likelihood ratios behind the bands, and the score, are
  Phase 2.
- **entities**: what it involves (`account:eve`, `address:203.0.113.9`,
  `path:…`, `module:…`, `program:…`, `boot:…`).
- **evidence**: the events (by their index in the stored events), snapshot
  items (`[section, key]`), changes (`[baseline, section, key, how]`) and
  processes (`{"live": ["processes", pid]}`) that show it.
- **first_seen**, **last_seen**: from its events, on the corrected clock.
- **new**: for a change, it changed since the previous bundle, not only
  since the baseline (a change stays a finding on every analysis until an
  operator accepts a new baseline; if the previous bundle didn't collect
  that section, it counts as new). For a finding from the logs, its latest
  event came after the previous bundle was collected: older log lines,
  still within the logs' reach, were in an earlier analysis already.
- **uncertain**: why it may be wrong. Usually its snapshot section wasn't
  fully collected on one side.

Informational findings (reboots by an operator, `su` use, password
changes) are left out of the listing unless `--info` is given; they are
kept in the assessment for the timeline.

## Change-based checks and the first analysis

Checks marked *baseline* compare with the host's baseline. On a host's first
analysis, the bundle *is* the baseline, so they don't run, and the output
says so and why (no baseline yet; this bundle is the baseline; the baseline
is newer than this bundle). Every other check runs on every bundle
(DESIGN.md §7).

## The checks

### 8.1 Kernel and system health

| Check | What | Band |
|---|---|---|
| `kernel.oom_kill` | out-of-memory kills, per program | medium for security and logging services (sshd, auditd, rsyslogd, journald, fail2ban…), else low hygiene |
| `kernel.segfault` | segfaults in a program holding a listening socket, or of any program 3 times or more | medium if network-facing and repeated, else low |
| `kernel.errors` | kernel oops/BUG (low, compromise), hung tasks and machine checks (low, hygiene) | low |
| `kernel.taint` | taint by a module that no listed module explains (a module hiding itself) | high; medium when the logs show a tainting module loaded and since unloaded |
| | the kernel tainted since the baseline | high if by a module (P, F, R, O, E), else low |
| | an out-of-tree, unsigned, proprietary or force-loaded module | high if loaded since the baseline; otherwise medium, on every analysis (the baseline's own bundle may never have been analysed) |
| | a tainting module load in the kernel log | medium |
| `kernel.core_dump` | core dumps (medium for network-facing services, else info hygiene); new crash dump files since the baseline (low) | |

### 8.2 Reboots

`system.reboot` takes each boot from the journal's boot list (or from
`wtmp`, when the journal lists fewer than two boots, as a volatile journal
does) whose preceding time is within the logs' reach, and classifies it:

- **unclean** (medium): no shutdown recorded since the boot before (no
  systemd shutdown target, no `wtmp` shutdown record, no logind
  power-off): a crash, a power loss or a forced reset;
- **operator** (info): a reboot, shutdown, poweroff, halt or `systemctl
  reboot` through `sudo` within 15 minutes before the shutdown;
- **power button** (info): logind saw the power button (a cloud provider's
  console power-off sends one too);
- **planned** (info): an automatic updater (unattended-upgrades,
  dnf-automatic) ran within the hour before;
- **unexplained** (low): a clean shutdown that neither explains.

Configured maintenance windows (DESIGN.md §8.2) come with the whitelist
work.

### 8.3 Accounts and authentication

| Check | What | Band | Baseline |
|---|---|---|---|
| `account.uid0` | an account other than root with UID 0; a name listed twice in `/etc/passwd` | high | no |
| | accounts sharing a UID | medium | no |
| `account.changes` | new accounts | medium | yes |
| | removed accounts (only when both sides were fully collected) | low | yes |
| | a service account (UID 1–999, and `nobody`) that gained a login shell (an empty shell field is `/bin/sh`), a password, or an empty password — in `/etc/shadow` or written into `/etc/passwd` | medium | yes |
| | a new account, or an account's primary group changed, to a root-equivalent group (by GID; GID 0 always) | high (medium for log-reading groups) | yes |
| `account.log_changes` | account and group changes in the logs (useradd, usermod, gpasswd…): seen even when undone before the scan | high for adding to a root-equivalent group, medium for new accounts and members, else low | no |
| `sudo.rules` | new sudo rules (the title says when `NOPASSWD`) | high | yes |
| `group.privileged` | new members of root-equivalent groups (`root`, `wheel`, `sudo`, `admin`, `docker`, `lxd`, `disk`, `shadow`) | high | yes |
| | new members of log-reading groups (`adm`, `systemd-journal`) | medium | yes |
| `ssh.authorized_keys` | new keys | high | yes |
| | changed options | medium | yes |
| | a key that belongs to no local account (hygiene) | medium | no |
| `ssh.guessed` | a login after 5 or more failed attempts from the same address in the 24 hours before. One attempt is logged several times (sshd's line, an invalid-user line, PAM's), so attempts are counted once per connection port and second; PAM failures (with that `rhost`) count only for addresses sshd logged none for | high | no |
| `ssh.login` | a direct root login | medium | no |
| | logins from an address no earlier bundle of the host saw a login from (only once earlier bundles hold some login) | medium | earlier bundles |
| `account.password` | `su` use and password changes (info); failed `su`, wrong sudo passwords and refused sudo (low) | | no |
| `sshd.config` | sshd settings added or removed | high for settings that change who can log in and how (PermitRootLogin, ports, key and principal files and commands, PasswordAuthentication, Match, Include…), else medium | yes |
| `pam.changes` | a `pam_exec` line (PAM running a program) | medium | no |
| | PAM lines added or removed | high | yes |
| | new or changed files in a PAM module directory | high | yes |
| | a PAM module no package installed | high | no |

Logins at unusual hours (DESIGN.md §8.3) need a per-host profile and come
later.

**Expected noise on a new server**, until whitelists and profiles (later
phases): the provisioner's account creation (cloud-init's `useradd` and
`sudo` membership) while those log lines are within reach, though they are
not `new` after the first analysis; direct root logins where admins log in
as root.

### 8.4 Persistence

| Check | What | Band | Baseline |
|---|---|---|---|
| `persistence.ld_preload` | a non-empty `/etc/ld.so.preload`; a process running with `LD_PRELOAD` or `LD_AUDIT` | high | no |
| `persistence.changes` | new cron, systemd, start-up and hook files, and changes to what they run or who owns them (content, size, link, mode, owner — not times alone). Run-time systemd units only when they are services, timers, sockets or paths (every login makes a scope) | high for the loader's configuration; low for files packages install (`/usr/lib`, `/lib`, `/usr/share`: updates change them); else medium | yes |
| `persistence.at_jobs` | queued `at` jobs | medium | no |
| `persistence.homes` | users' own systemd units and autostart entries, by name (their contents are hashes only by default, policy §7; changes show in `persistence.changes`); lingering users, whose units start at boot (low) | info | no |

### 8.5 System binary integrity

| Check | What | Band | Baseline |
|---|---|---|---|
| `package.changed` | package files that differ from their package: programs intruders replace (`ps`, `ls`, `ss`, `sshd`, `sudo`, `su`, `login`, shells, `systemd`…), the loader, libc, libpam, PAM modules | high | no |
| | other programs and libraries | medium | no |
| | other package files | low | no |
| | edited configuration files (hygiene) | info | no |
| | the package managers' checksum lists changed (expected after updates; a rewrite to hide a replaced file shows here too) | low | yes |
| `files.privileged` | a set-user-ID, set-group-ID or capability file new since the baseline | high | yes |
| | outside the system directories (or a device node there), or one no package installed with set-user-ID, set-group-ID or root-equivalent capabilities (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`…) — only when package ownership was loaded completely | high | no |
| | a capability attribute that can't be read | medium | no |
| `files.unowned` | executables in system directories no package installed (only when package ownership was loaded completely): new ones high (medium in `/usr/local`, `/opt`); others medium (info in `/usr/local`, `/opt`), on every analysis | | no |

A package's own set-user-ID programs are ordinary and not reported; walk
errors are coverage gaps, not findings; systemd's own masking device nodes
(`/run/systemd/inaccessible`) are left out.

### 8.6 Files in unusual places

| Check | What | Band |
|---|---|---|
| `files.scratch` | programs (ELF) and scripts (`#!`) in `/tmp`, `/var/tmp` and `/dev/shm`, recognised by their first bytes — an execute bit alone isn't enough (unpacked files carry them) — and grouped by the directory directly under the scratch place | high for programs, medium for scripts |
| `files.deceptive` | names of only dots or spaces, with leading or trailing spaces, posing as kernel threads or system programs (high), or with control characters (medium); a hidden name alone (`.X11-unix`) is not reported | |
| `files.dev` | regular files under `/dev` (high); hidden or misplaced entries there (medium) | |
| `files.web` | a new script in a web root since the baseline; a program; a script in an upload directory; a script behind a second extension (`shell.php.jpg`) | high |
| | a link out of the web root | medium |
| | `.env`, `.htpasswd`, `.git` and the like inside a web root (exposure) | medium |
| `files.backdated` | programs and scripts changed long after their stated modification time (archives keep old times too, so weak alone; grouped by directory); impossible times | low |

### 8.7 Live process state

The tool's own processes — its sshd process and everything it started —
are left out, found from the process its own SSH login was logged with.

| Check | What | Band |
|---|---|---|
| `process.hidden` | a process that answers a direct `/proc/<pid>` lookup but isn't in the listing (what `ps` sees) | high |
| `process.executable` | running from memory only, from a scratch directory, from a deleted file in a home; posing as a kernel thread (`[kworker/0:1]` with a real executable) | high |
| | from another deleted file | medium |
| | a program a package update replaced under a running service (hygiene: restart it) | low |
| `process.reverse_shell` | a shell or interpreter (sh, bash, python, perl, nc, socat…) whose standard input, output or error is a TCP or UDP socket | high |
| `process.miner` | a known miner by name; or at least half a core on average over ten minutes or more, with a connection to a common mining-pool port | high |
| `process.injected` | code mapped from a scratch or home file, or a deleted file outside the system directories (high); from memory only (medium: JITs do this too); replaced system libraries still in use (low hygiene) | |

## Coverage

Beside the findings, each assessment says what the collection couldn't see
(DESIGN.md §2 principle 8):

- the bundle's status, if not complete;
- modules not collected;
- modules that failed or ran out of time;
- sources cut short;
- the collector's errors;
- snapshot sections not fully collected, and why;
- no authentication log events, no system journal events, or no boot
  list or records (so logins, kernel messages or reboots can't be checked);
- a host clock more than two minutes off the controller's;
- a time zone assumed;
- the tool's own login not recognised (NAT).

It also gives each log's reach: the first and last times of the events the
checks use, from the authentication log, the authentication journal, the
system journal and the login records. Lines no check uses aren't counted,
so a quiet log can reach further back than this says.

## Assessments

Each analysis is stored encrypted beside the bundle
(`<bundle>.assessment-<hash>.age`): the findings, which checks ran (or
waited for a baseline, or failed — a broken check never stops the others),
the coverage, and the counts. An append-only `assessments` table indexes
each one with its bundle, host, time, checks version, baseline, file hash
and an encrypted summary of counts, and the bundle's chain of custody gets
an `analysed` entry. Analysing again (with newer checks, or after a new
baseline) adds an assessment; earlier ones are kept.
