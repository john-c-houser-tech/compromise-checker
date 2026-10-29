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
- **band**: `critical`, `high`, `medium`, `low` or `info`. `critical` is
  for the strongest signs (DESIGN.md §11.1's critical examples), `high` for
  DESIGN.md §8's ★ checks. Each band has a likelihood ratio, and the
  findings' ratios make the host's score ([scoring](scoring.md)).
- **variant**: which of a check's kinds of finding this is, where they
  weigh differently, declared by the check; used by scoring's per-check
  overrides and by whitelist rules. So far: `ssh.login` (`root_login`,
  `new_address`), `system.reboot` (`unclean`, `operator`, `power_button`,
  `planned`, `unexplained`), `kernel.taint` (`unexplained`, `unloaded`).
- **suppressed_by**: set when a whitelist rule matched: the rule, its
  layer and file, its reason and owner ([whitelists](whitelists.md)).
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
| `kernel.taint` | taint by a module that no listed module explains (a module hiding itself) | critical; medium when the logs show a tainting module loaded and since unloaded |
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

Maintenance windows in the whitelist files make unclean and unexplained
reboots inside them informational ([whitelists](whitelists.md#maintenance-windows)).

### 8.3 Accounts and authentication

| Check | What | Band | Baseline |
|---|---|---|---|
| `account.uid0` | an account other than root with UID 0 (critical); a name listed twice in `/etc/passwd` (high) | | no |
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
| `persistence.ld_preload` | a non-empty `/etc/ld.so.preload` (critical); a process running with `LD_PRELOAD` or `LD_AUDIT` (high: jemalloc and test tools use it too) | | no |
| `persistence.changes` | new cron, systemd, start-up and hook files, and changes to what they run or who owns them (content, size, link, mode, owner — not times alone). Run-time systemd units only when they are services, timers, sockets or paths (every login makes a scope) | high for `/etc/ld.so.preload` and `/etc/ld.so.conf`; low for files packages install (`/usr/lib`, `/lib`, `/usr/share`) when the package lists changed too (an update); else medium | yes |
| `persistence.at_jobs` | queued `at` jobs | medium | no |
| `persistence.homes` | users' own systemd units and autostart entries, by name, in any home directory (wherever it is) (their contents are hashes only by default, policy §7; changes show in `persistence.changes`); lingering users, whose units start at boot (low) | info | no |

### 8.5 System binary integrity

| Check | What | Band | Baseline |
|---|---|---|---|
| `package.changed` | package files whose content differs from their package: programs intruders replace (`ps`, `ls`, `ss`, `sshd`, `sudo`, `su`, `login`, shells, `systemd`…), the loader, libc, libpam, PAM modules | critical | no |
| | other programs and libraries | medium | no |
| | other package files | low | no |
| | edited configuration files (hygiene) | info | no |
| | on RHEL, rpm's other differences: a set-user-ID or set-group-ID bit gained, capabilities changed, a link pointing elsewhere (high); another mode change, owner or group (high for critical programs, else medium) | | no |
| | the package managers' checksum lists changed (expected after updates; a rewrite to hide a replaced file shows here too) | low | yes |
| `files.privileged` | a set-user-ID, set-group-ID or capability file new since the baseline | high | yes |
| | outside the system directories (or a device node there), or one no package installed with set-user-ID, set-group-ID or root-equivalent capabilities (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`…) — only when package ownership was loaded completely | high | no |
| | a file already listed that gained capabilities or set-user-ID or set-group-ID since the baseline (dpkg doesn't record capabilities) | high | yes |
| | outside the system directories includes files right in `/` | | |
| | a capability attribute that can't be read | medium | no |
| `files.unowned` | executables in system directories no package installed (only when package ownership was loaded completely): new ones high (medium in `/usr/local`, `/opt`, and for files packages generate after installing, such as Python caches); others medium (info for those), on every analysis | | no |

A package's own set-user-ID programs are ordinary and not reported; walk
errors are coverage gaps, not findings; systemd's own masking device nodes
(`/run/systemd/inaccessible`) are left out.

### 8.6 Files in unusual places

| Check | What | Band |
|---|---|---|
| `files.scratch` | programs (ELF) and scripts (`#!`) in `/tmp`, `/var/tmp` and `/dev/shm`, recognised by their first bytes — an execute bit alone isn't enough (unpacked files carry them) — and grouped by the directory directly under the scratch place | high for programs, medium for scripts |
| `files.deceptive` | names of only dots or spaces, with leading or trailing spaces, posing as kernel threads or system programs (high), or with control characters (medium); a hidden name alone (`.X11-unix`) is not reported, nor a system program's name on a link or in a `bin/` directory (a virtualenv's `python`) | |
| `files.dev` | regular files under `/dev` (high); hidden or misplaced entries there (medium); a device node anywhere else (`mknod /dev/shm/.k c 1 1`, a copy of `/dev/mem`) (high) | |
| `files.web` | a new script in a web root since the baseline; a program; a script in an upload directory; a script behind a second extension (`shell.php.jpg`) | high |
| | a link out of the web root (relative targets resolved), except to system programs and libraries | medium |
| | `.env`, `.htpasswd`, `.git` and the like inside a web root (exposure) | medium |
| `files.backdated` | programs and scripts changed long after their stated modification time (archives keep old times too, so weak alone; grouped by directory); impossible times | low |

### 8.7 Live process state

The tool's own processes — its sshd session process and everything under
it — are left out. They are found from the running collector itself (root,
its exact command line), up its parents to the sshd session process, which
must be one whose login the logs show as the tool's own and a child of the
sshd listener. A forged log line alone can't make anything the tool's own.

| Check | What | Band |
|---|---|---|
| `process.hidden` | a process that answers a direct `/proc/<pid>` lookup but isn't in the listing (what `ps` sees) | critical |
| `process.executable` | running from memory only, from a scratch directory (`/tmp`, `/var/tmp`, `/dev/shm`, `/dev/mqueue`, `/run/lock`, `/var/lock`, `/var/crash`, `/run/user`), from a deleted file in a home; posing as a kernel thread (`[kworker/0:1]` with a real executable) | high |
| | from another deleted file | medium |
| | a deleted system program, when the package lists changed after the process started: an update replaced it under a running service (hygiene: restart it) | low |
| `process.reverse_shell` | a shell or interpreter (sh, bash, python, perl, nc, socat…, by its name, its program's name or its argv[0], so a renamed copy still counts) whose standard input, output or error is a TCP or UDP socket; any process whose input and output are one TCP or UDP socket. Not seen: a shell joined to a socket through pipes (`mkfifo … \| sh \| nc`), where only `nc` holds the socket | high |
| `process.miner` | a known miner by name; or at least half a core on average over ten minutes or more, with a connection to a common mining-pool port on a public address | high |
| `process.injected` | code mapped from a scratch or home file, or a deleted file outside the system directories, or a deleted system library no update explains (high); from memory only (medium: JITs do this too; low when it is libffi's, as firewalld's on RHEL); system libraries an update replaced, still in use (low hygiene) | |

### 8.8 Network and data transfer

Connections are a sample: only those open (or closing) when the collector
looked; a socket whose process isn't visible still counts, under its
owner's account. Without firewall or proxy logs, transfer evidence is
weak. Rules inside the chains Docker, Kubernetes and fail2ban manage aren't
compared: on a host where that software really runs, a rule slipped into
one of its own chains doesn't show (a new jump into such a chain from an
ordinary chain does; `DOCKER-USER`, where administrators add rules, is
compared).

| Check | What | Band | Baseline |
|---|---|---|---|
| `net.listener` | a new listening port | low | yes |
| `net.peer` | a new outgoing destination for a program (`new_destination`) | low | yes |
| | over a Tor port (9001, 9030, 9050, 9051, 9150) or from `tor` (`tor`) | medium | yes |
| `net.metadata` | a program other than a known cloud agent connected to the metadata address (169.254.169.254, or AWS's `fd00:ec2::254`). Agents are known by the file they run (or, run by an interpreter, their script), in a system directory, never by their self-chosen name; another root program in a system directory (an SDK using the instance's role) is low, unless it is a shell, an interpreter given no script, or a generic tool (`curl`, `nc`, `sleep`…). On AWS, EC2 Instance Connect runs `curl` as root at each login, so expect a medium finding there | medium | no |
| `net.directory` | ★ a process running as a web-server account (`www-data`, `apache`, `nginx`…, by its effective UID) connected to SMB or WinRM (high, `smb_winrm`), or LDAP, LDAPS or Kerberos (medium, `ldap_kerberos`: web apps that log users in against a directory use these). Judged by the account, not a host role, so a domain-joined server's own lookups don't count | | no |
| `net.tunnel` | an `ssh` client forwarding: its options read as ssh reads them, up to the destination (`-L`, `-R`, `-D`, `-W`, `-J`, combined like `-fNR`, or `-o LocalForward=`/`RemoteForward=`/`DynamicForward=`/`ProxyJump=`/`Tunnel=`; `ssh host ls -lR` forwards nothing); an sshd session process (not the listener) holding a listening socket, a remote forward into this host (X11's loopback ports 6000–6099 left out) | medium | no |
| `net.config` | `/etc/hosts`, resolver, NSS, TCP-wrapper or firewall configuration files added, removed or changed (`file`); loaded firewall rules added or removed, one finding per direction (`firewall`) | medium | yes |
| `net.managed_chain` | a firewall chain named like one Docker, Kubernetes, Calico, Cilium, fail2ban, Flannel, libvirt or Tailscale writes (whose rules aren't compared: they change all the time), while that program isn't running (known by the file it runs) | medium | no |
| `net.promiscuous` | an interface in promiscuous mode that isn't a bridge, a bridge port, or enslaved to something (a bond, Open vSwitch); low when a known capture tool (by the file it runs) holds a packet socket | medium | no |
| `net.transfer` | weak signs, mostly material for chains: an archive of 50 MB or more in a scratch place (`archive`); `curl`, `wget`, `scp`, `rsync`, `rclone`, `nc`… connected to a public address (`tool`); an interface that sent over 1 GB and ten times what it received (`counters`) | low | no |

### 8.9 Outgoing mail

Addresses arrive fingerprinted (policy §7: the local part replaced by a
keyed hash, the domain kept), so recipients are counted and domains
compared without any address being shown; `checker mail-hash` shows how a
known address appears. Only outgoing deliveries count: those into mailboxes on
the host (Postfix's `local`, `virtual` and `lmtp`, Dovecot's LMTP socket,
Exim deliveries with no remote host) don't. Deliveries are counted once
each (a message to a recipient, at its first attempt): retries of deferred mail, and the same
line in the mail log and the journal or in several bundles, are not new
mail. Days are UTC days.

| Check | What | Band | Baseline |
|---|---|---|---|
| `mail.web_user` | mail submitted by a web-server account (`www-data`, `apache`, `nginx`, `http`, `wwwrun`, `lighttpd`): Postfix's `pickup` names the UID, Exim's `<=` line (`P=local`) the user. One finding per account, counting messages. Hosts whose web apps send mail whitelist it | medium | no |
| `mail.relay` | a setting that routes mail elsewhere added, changed or removed since the baseline: Postfix's `relayhost`, `smtp_fallback_relay`, `default_transport`, `relay_transport`, `transport_maps`, `sender_dependent_relayhost_maps`; Exim's `dc_smarthost`, `route_list`, `route_data` (`relay`, a compromise sign); one added or
removed with no value, `error` or `local` is a mail server installed or
removed, which `software.packages` reports, and isn't one. Relaying open to anyone, while the server listens beyond loopback (`open_relay`, exposure): trusted networks (`mynetworks`, `dc_relay_nets`, `relay_from_hosts`) wider than any one host's own — a /0 to /7 of any kind (IPv6 /0 to /15), or a public network wider than a /24 (/48) — or `mynetworks_style = class`; Postfix restrictions that never refuse mail for other domains (neither `smtpd_relay_restrictions`, which refuses by default, nor `smtpd_recipient_restrictions` has `reject_unauth_destination`, `defer_unauth_destination`, `reject`, `defer`, `defer_all` or `defer_if_permit` before a `permit`; a list with `$variables` isn't judged); Exim relaying to every domain (`*`) | medium | partly |
| `mail.volume` | a day with more deliveries attempted after the baseline was collected than both 100 and ten times the daily average before it (from every bundle's mail logs, over the days they reach back) (`deliveries`); messages waiting (Postfix's deferred queue, Exim's spool) over 500, or 50 or more and ten times the baseline's (`queue`; a baseline without queue counts gets only the 500 limit) | medium | yes |
| `mail.domains` | more than 50 recipient domains, in one day after the baseline, that no delivery in any bundle went to before | medium | yes |

Observed relays (each recipient domain's mail server, for a host that
delivers directly) aren't compared: they change with every new recipient
domain, which `mail.domains` covers.

### 8.13 Containers

From the runtimes' state files (decision 4: never their sockets), compared
by runtime and name: a redeploy replaces a container's ID, not what it is.
Kubernetes, containerd, LXD, LXC and rootless Podman aren't inventoried;
the coverage names them when present.

| Check | What | Band | Baseline |
|---|---|---|---|
| `container.privileged` | privileged (Docker's flag; Podman's every capability), mounting `/`, `/etc`, `/root`, `/boot` or a runtime's socket (Docker's, Podman's, containerd's), or holding `CAP_SYS_ADMIN`: new since the baseline (added, or given it since) high (`new`); there before, or with no baseline yet, medium hygiene (`standing`). Says whether it runs (its process alive at collection) | high / medium | partly |
| `container.host_namespace` | sharing the host's process or network namespace, new since the baseline | medium | yes |
| `container.new` | a container new since the baseline: deploys make them; what it can do is judged above | low | yes |

### 8.12 Web applications

Web accounts are `www-data`, `apache`, `nginx`, `http`, `wwwrun`,
`lighttpd` and any named at setup (`web_users`, recorded by the collector
as `web_accounts`). Access logs are read only where the organization chose
them (policy §7); without them, `web.new_script_hit`, `web.exploit` and
`web.noise` have nothing to read, and the coverage says so. Network
findings name `address:<network>` entities, which a whitelist rule's
`address` covers when the network lies inside it.

| Check | What | Band | Baseline |
|---|---|---|---|
| `web.worker_child` | ★ live: a process whose parent is a web worker (`php-fpm`, `php-cgi`, `lsphp`, `httpd`, `apache2`, `nginx`; a root master's own root helpers aside), or run by a web account inside a web server's own systemd service (its cgroup: a child `setsid` moved away is still there) with no `sshd`, `sudo`, `su`, `cron` above it (`live`); from the audit log's program starts by web accounts whose login UID is unset — an administrator's `sudo -u www-data …` or a cron job has one — or is that of a running web worker (a web server an administrator started by hand runs under their login), that didn't fail, one finding per account, program and command (`history`). Judged: a shell by what it was asked (`sh -c` with recon, a download, a pipe into a shell, `/dev/tcp`, `base64 -d`, a scratch place…; with no command, interactive), since PHP runs every `exec()` through `sh -c` and each program it starts is judged by its own start; PHP's `sh -c /usr/sbin/sendmail …` (or `msmtp`, `ssmtp`; options and addresses only) left out; download and network tools (`curl`, `wget`, `nc`, `socat`, `openssl`…), schedulers (`crontab`, `at`), recon (`id`, `whoami`, `uname`, `ps`, `netstat`…, `cat /etc/passwd`), and anything run from `/tmp`, `/dev/shm`, a web root or a home (high); an interpreter (Python, Perl, Ruby, PHP's CLI, Node: sites run their own jobs so; medium). The first and newest 25 starts are cited | high | no |
| `web.new_script_hit` | a script added to a web root since the baseline (what `files.web` reports) that answered requests 2xx, its path below some web root matched to the request's (decoded, normalised, cut after the script's name for `PATH_INFO`); uncertain when a file there before also ends in that path (two sites); its account is the web account that owns the file | high | yes |
| `web.exploit` | per source network and attack: answered (medium) when a script took it in its request and answered 2xx, or the server failed (5xx), or a CGI program answered a Shellshock user agent; refused (info) otherwise — static pages, front controllers ignoring a parameter, attacks in user agents | medium; refused info | no |
| `web.errors` | 20 or more 5xx answers from one network within five minutes; upstream error lines count only for a network with no 5xx in the access log (nginx logs one failure in both) | low | no |
| `web.noise` | DESIGN.md §17: refused requests (counted ones, and refused script requests with no attack) as one informational line naming the busiest networks, from 10 | info | no |

### 8.10 Anti-forensics (★ all)

| Check | What | Band | Baseline |
|---|---|---|---|
| `logs.cleared` | against the previous bundle's `/var/log` manifest: a log with the same inode but smaller (`truncated`); a key log gone (`deleted`) or a new file in its place, as `sed -i` or `rm` and `touch` leave (`replaced`); the persistent journal's folder or active `system.journal` gone (`journal_removed`). Key logs: `wtmp`, `btmp`, `lastlog`, `auth.log`, `secure`, `syslog`, `messages`, `kern.log`, `audit.log`. Rotation explains it only when a rotated copy really holds the old log: it carries the old inode (renamed), or is an uncompressed copy at least as large (copytruncate); a file merely named like a rotated copy proves nothing. With only a compressed copy as new as the old log (which can't be checked by size), the log is still reported, at medium, naming it. Nothing is read as deleted when either listing was cut short | high for key logs, else medium | previous bundle |
| `logs.stopped` | auditd, rsyslog, journald or syslog-ng stopped or failed, not within 15 minutes of a shutdown or boot and not started again within two minutes (an update's restart) (`unit`); the audit daemon ending outside a shutdown and not starting again (`audit_daemon`); auditing switched off, or audit rules removed and not loaded again within 30 seconds (augenrules deletes all rules before reloading them), as one finding however many rules (`audit_rules`); a logging service that ran at the baseline not running (`not_running`), or running from a different file (`moved`). Nothing about services when the process listing didn't complete | high | partly |
| `logs.journald_config` | journald's effective `Storage=` (main file, then drop-ins in `/etc`, `/run`, `/usr/lib` as systemd orders them) changed since the baseline to `none` or `volatile` | high | yes |
| `history.disabled` | a shell history file linked to `/dev/null` (high, `link`); emptied (medium, `emptied`) or deleted (medium, `deleted`) since the baseline; a system shell start-up file (`/etc/profile`, `profile.d`, `bash.bashrc`, `bashrc`, zsh's) with `unset HISTFILE`, `HISTFILE=/dev/null`, `HISTSIZE=0`, `HISTFILESIZE=0` or `set +o history`, quoted or not (high, `startup`). Users' own start-up files are hashed only (policy §7), so a change there shows in `persistence.changes`, not here | | partly |
| `mac.disabled` | SELinux switched to permissive (`setenforce 0` in the audit log, `selinux_audit`), or turned down since the baseline, running or configured (`selinux`); AppArmor profiles unloaded or no longer enforcing since the baseline (`apparmor`): high when ten or more, or most of them; medium for a few (an upgrade, a removed package). Profiles that come and go with VMs, containers and snaps (`libvirt-`, `lxd-`, `docker-`, `snap…`) are left out | high | partly |
| `agent.stopped` | a security agent (fail2ban, Wazuh, osquery, CrowdStrike, auditbeat, CrowdSec, ClamAV, Defender, SentinelOne, Elastic…) that ran at the baseline, known by the file it runs, isn't running, or runs from a different file (`moved`) | high | yes |
| `clock.jump` | the system clock set ("Time has been changed" from the system's manager, not a user's), not in the ten minutes after a boot; low when a time synchronisation daemon runs (chrony, timesyncd, ntpd, or a hypervisor's: VMware tools, Hyper-V, QEMU agent, PTP) | medium | no |

A journal gap inside one boot isn't checked: it needs the whole journal,
which the collector doesn't read (plan 2.5).

### 8.11 Software changes

| Check | What | Band | Baseline |
|---|---|---|---|
| `software.packages` | packages installed since the baseline, grouped by when they were installed (six hours apart is another group) and named (`installed`); informational when every one is dated inside a run of the automatic updater's service (`apt-daily-upgrade.service`, `dnf-automatic*`: from its Starting… to its Finished… in the journal, not its timer, PackageKit or unattended-upgrades' shutdown helper) (`automatic`), or when a maintenance window covers the group. Packages removed (`removed`, low; removals carry no time, so no window covers them). Upgrades (`upgraded`, informational) | low | yes |
| `software.repository` | a repository or signing-key file added, or changed in content or ownership (`repository`, `key`), medium; a file the package manager doesn't read (`.rpmnew`, `.save`, `.dpkg-dist`…) low; a key imported into rpm's own database (a new `gpg-pubkey`), medium (`key`) | | yes |
| `software.tools` | an attack or tunnelling tool installed as a package (nmap, masscan, ncat, proxychains, chisel, hydra, sqlmap, impacket…: `attack_tool`, medium); a compiler (gcc, clang, Go, Rust: `compiler`, low). A tool unpacked from an archive or installed with pip isn't a package and isn't seen here (`files.unowned`, `software.global` may) | | yes |
| `software.global` | Python packages installed system-wide by hand (in `/usr/local/lib*/python3*`) or Node packages installed with `npm -g` (not the `npm` and `corepack` Node.js ships) | low | yes |

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
