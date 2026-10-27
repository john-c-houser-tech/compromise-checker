# Collector modules

What each collector module reads, why, and what it sends back. The security
and privacy policy (§7) promises this list; keep it in step with
`checker/collector/collector.py`.

Every file is opened read-only, without following a final symbolic link,
without blocking on pipes or devices, and without updating its access time
where the kernel allows. Anything that is not a regular file is described
(type, owner, link target) instead of read. Text is masked for secrets before
it leaves the server (masking rules version 5, listed in the policy §7).
Masking works on whole lines, so a secret can never be split across two
reads. Password hashes in the standard crypt formats (`$1$`, `$2b$`, `$5$`,
`$6$`, `$7$`, `$y$`, `$gy$`…) are masked wherever they appear, salt
included, for example in a copied shadow line pasted into a config file or
`usermod -p<hash>` in a sudo log. This rule runs last, so a `password=`
value is still masked whole; each format's fields are bounded, so it runs
in linear time even on hostile input.
The old 13-character DES format can't be told apart from ordinary text and
is not masked. A name given at a login prompt that isn't an account can be a
password typed in the wrong box, so in failed-login messages — sshd's
`Invalid user X` and `… for invalid user X` (or `illegal user`), login's
`FAILED LOGIN … FOR 'X'`, su's `user X does not exist`, pam_sss's
`received for user X: … (User not known …)` — the name is masked as
`unknown_user` unless it is an `/etc/passwd` account name. This rule runs
first, so it judges the name as written. Two fixed vocabularies are never masked, because they look like
`key=value` settings but can't hold a secret and are exactly what the checks
compare: sudo's `NOPASSWD:` and `PASSWD:` tags in a line that is a sudo rule
(`user host = (runas) TAG: command`), and only where a command spec starts —
after the rule's `=` or an unescaped `,`, before the command — never in a
command's arguments or a comment; anywhere else, such as a log line,
`PASSWD: x` is masked like any password label),
and PAM control flags and `pam_debug` arguments where both the key and the
value are PAM's own words (`auth_err=die`, `new_authtok_reqd=ok`,
`auth=authinfo_unavail`). A private key block runs only as long as its lines look like key
material — a base64 token alone on the line (`=` only as end padding), a
PEM header or a blank line, or, for a key logged line by line, one base64
token straight after the same program tag as its `BEGIN` line (the log
prefix is kept and masked like any text) — and for at most 256 lines. The
first other line ends it and is masked normally, so a fake `BEGIN … PRIVATE
KEY` line can't hide the log lines after it; such a block is counted as
`private_key_unterminated`. An unfinished last line cut off by a time limit
is never sent, since masking might not recognise a secret's missing end. Two cases fail closed — nothing is sent rather than risk an unmasked
secret: a line longer than 1 MiB is replaced by a marker giving its length,
and a compressed file in a format the server's Python cannot open (for
example `.zst`) is described as unreadable instead of being sent raw.

## `host_facts`

**Why:** identifies the host across runs, records the clock for timeline
correction, and captures security settings whose change is itself a finding.

| Record | Read from | Contents |
|---|---|---|
| `os_release` | `/etc/os-release` (or `/usr/lib/os-release`) | All fields |
| `uname` | kernel | System, node name, kernel release and build, machine |
| `machine_id` | `/etc/machine-id` | Stable host identifier (survives IP and name changes) |
| `uptime` | `/proc/uptime`, `/proc/stat`, boot id | Seconds up, boot time, boot id |
| `clock` | system clock, `/etc/localtime` link | UTC time, time-zone names |
| `kernel_taint` | `/proc/sys/kernel/tainted` | Taint flags (DESIGN.md §8.1) |
| `mandatory_access_control` | `/sys/fs/selinux/enforce`, `/sys/module/apparmor/parameters/enabled` | SELinux mode; AppArmor on or off |
| `hardware` | `/proc/meminfo`, CPU count | CPUs, memory |

## `auth_log`

**Why:** the authentication log records logins, failed logins, sudo use,
`su`, account changes and SSH configuration problems — the raw material for
DESIGN.md §8.3.

**Reads:** in `/var/log`, `secure` and its date-suffixed rotations (RHEL
family) or `auth.log` and its numbered rotations (Ubuntu), decompressing
`.gz`, `.xz` and `.bz2`. Files last written before the look-back window are
skipped, since nothing in them is new. Each file is sent whole, up to the
per-source size limit.

**Sends:** one source per file (name, size, times, mode, owner, inode,
compression), its masked content in chunks, and a `summary` record (files
found, sent, and skipped as older than the window). Unreadable entries — for
example the log replaced by a link to `/dev/null`, however old — become
`unreadable_file` records, which are themselves evidence. The look-back
window only ever skips regular files. If `/var/log` itself cannot be listed,
the module ends with status `error`.

Systems that log authentication only to the systemd journal (no `secure`
or `auth.log`) send an empty summary here; `auth_journal` covers them.

## `auth_journal`

**Why:** the same authentication messages as `auth_log`, from the systemd
journal. On hosts without a syslog daemon the journal is the only copy, and
where both exist, comparing the two shows a log edited in one place only
(DESIGN.md §8.2).

**Runs:** `journalctl --output=json --no-pager --quiet --all
--since=@<window start> --output-fields=<list> SYSLOG_FACILITY=4
SYSLOG_FACILITY=10` — only the auth and authpriv facilities, which are what
`secure` and `auth.log` hold. `--all` stops journalctl from silently
replacing fields over 4 KiB with `null`; the collector's own line limit
applies instead, and is recorded.

**Sends:** one `command` source of journal entries, one JSON object per
line, with only these fields: `MESSAGE`, `PRIORITY`, `SYSLOG_FACILITY`,
`SYSLOG_IDENTIFIER`, `SYSLOG_PID`, `_SOURCE_REALTIME_TIMESTAMP`,
`_HOSTNAME`, `_TRANSPORT`, `_PID`, `_UID`, `_GID`, `_COMM`, `_EXE`,
`_SYSTEMD_UNIT`, `_AUDIT_SESSION`, `_AUDIT_LOGINUID`, `_BOOT_ID`, plus the cursor,
times, sequence numbers and boot id journalctl always adds. The process
command line (`_CMDLINE`) is never requested. Each entry is decoded and
every field value masked on its own — never the JSON text, where escaped
quotes would hide a quoted secret's end from the rules. Masking state is
kept per field across the whole source, so a private key logged over several
entries is masked to its end. journalctl writes a
field that is not valid UTF-8 as an array of byte values, and those bytes
are masked too. A line that can't be parsed is not sent (fail closed) and is
counted as `unparsed_line`.

## `accounts`

**Why:** new accounts, extra UID 0 accounts, service accounts gaining a
login shell or a password, new members of powerful groups, and history files
switched off (DESIGN.md §8.3).

| Record | Read from | Contents |
|---|---|---|
| `account_file` | `/etc/passwd`, `/etc/group`, `/etc/shadow` | Type, owner, mode, size, inode, times |
| `account` | `/etc/passwd` | Name, UID, GID, home, shell, line number, and the password field's *status* (`shadowed`, or as below). The comment (GECOS) field, usually a full name, is not sent. |
| `group` | `/etc/group` | Name, GID, members, line number |
| `password_status` | `/etc/shadow` | Per account: `empty`, `no_password` (`*`, `!!`…), `locked` or `set`; the hash *algorithm* (yescrypt, sha512, md5, des…); last change, minimum, maximum, warning, inactivity and expiry, in days and as dates |
| `shell_history` | each home directory | Type, owner, mode, size, times and link target of known history files (`.bash_history`, `.zsh_history`, fish, MySQL, PostgreSQL, Python, SQLite…) |
| `malformed_lines` | any of the three | Line numbers only |
| `incomplete_file` | any of the three | Read only to its last whole line within 8 MiB: later entries are missing |

If `/etc/group` or `/etc/shadow` can't be read, an `unreadable_file` record
says so. **Never sent:** password hashes — `/etc/shadow` is reduced to status on the
server (Phase 1 plan, decision 1), and so is a hash found in `/etc/passwd` —
and the contents of history files (policy §7). A malformed line is reported
by number only, since it could hold anything.

### Home directories, including domain users

Accounts that log in through NSS — SSSD, LDAP, Active Directory, winbind —
are not in `/etc/passwd`, but their keys and shell history count just the
same. So homes are also found on disk: a directory one or two levels below
a home root (`/home`, the parent directories of regular users' homes, and
the fixed part of SSSD's `override_homedir`, `fallback_homedir` and
`homedir_substring` settings) that holds `.ssh` or a history file and
belongs to no `/etc/passwd` account is an *unlisted home*. A home that is a
symbolic link (`/home/alice` → `/srv/alice`) is followed to its target, as
sshd follows it, but never descended through. A home root that is itself a
link (`/home` → `/srv/homes`) is searched at its target. If a root can't be
searched, or the search is cut short, the `homes` record says so
(`complete: false`): some keys may not have been looked at. (Protection
doesn't depend on the search; see "Protected files".) A
home-like directory is still searched one level below (`/home/CORP/.ssh` and
`/home/CORP/alice`). Only those three
SSSD settings are read from `sssd.conf`; nothing from it is sent. NSS itself
is not asked: with SSSD's defaults it lists no domain users, and a lookup
can reach the directory server and write SSSD's cache on the target.

A `homes` record — from `accounts` and from `ssh` — gives the roots
searched, how many directory entries were examined, whether the search was
cut short (at 20,000 entries or the module's time limit, checked while each
directory is read), the unlisted homes, and the homes not examined because
of their mounts (see "Network drives and automounted folders"). Their history files are
described (with `home_source: directory` and the owner's UID), protected
like any other, and their keys listed by the `ssh` module.

## `sudoers`

**Why:** new sudo rights, especially `NOPASSWD` (DESIGN.md §8.3).

**Sends:** `/etc/sudoers` and every file it includes (`@include`,
`#include`, `@includedir`, `#includedir`; quotes, backslash escapes,
relative paths and `%h` resolved as sudo does; up to 8 levels), masked. Each included directory also
gets an `include_dir` record listing its files and whether sudo reads each
one (sudo skips names ending in `~` or containing a `.`); every file is sent
either way, since a skipped one is still evidence.

## `ssh`

**Why:** `sshd_config` changes (root login, ports, key file locations,
`AuthorizedKeysCommand`) and new or changed authorized keys for any account,
root and service accounts included (DESIGN.md §8.3).

**Sends:** `/etc/ssh/sshd_config` and every file its `Include` lines name
(globs resolved relative to `/etc/ssh`, up to 8 levels), masked. The
configuration is read as sshd reads it — includes expanded in place, the
first global `AuthorizedKeysFile` winning, `none` meaning no key files —
to find the key file locations: that global value (or sshd's defaults
`.ssh/authorized_keys` and `.ssh/authorized_keys2` if it isn't set), plus
every location set inside a `Match` block, since those apply to some logins.
`authorized_keys_locations` records which is which. Each location is
expanded for every account (`%h`, `%u`, `%U`, `~`). For each key file found:

- `authorized_key`, one per key: account, file, line, key type, the
  SHA-256 fingerprint exactly as `ssh-keygen -l` and sshd's logs show it
  (for a certificate, the fingerprint of the key inside it, as OpenSSH
  gives it, with `certificate: true`), the key's size in bytes, its options
  as a list of names and values — each value decoded as sshd decodes it and
  then masked; for `environment`, the variable's name (masked), and its value only
  for the loader and interpreter variables a check needs (`LD_PRELOAD`,
  `LD_LIBRARY_PATH`, `LD_AUDIT`, `PATH`, `PYTHONPATH`, `PYTHONSTARTUP`,
  `PERL5LIB`, `PERL5OPT`, `RUBYOPT`, `RUBYLIB`, `NODE_OPTIONS`, `BASH_ENV`,
  `ENV`, `PROMPT_COMMAND`) and a few harmless ones (`HOME`, `SHELL`, `LANG`,
  `LC_ALL`, `TZ`) — any other value could be a secret no pattern recognises,
  so only its length is sent; an option sshd doesn't know, which makes it
  ignore the line, is replaced by its length and `known: false` — and its comment (masked). If the type
  on the line and the type inside the key differ, both are given.
- `authorized_keys_file`: the file's owner, mode, size, times and inode, the
  number of keys, and the line numbers of lines that are not keys. Only the
  first 1 MiB is read, whole lines only (`truncated` says if more was left).
- `ssh_dir`: facts about each home's `.ssh` directory.

Unlisted homes (see `accounts`) are checked too, at every location that
doesn't need the account name; their keys carry `account: null`,
`home_source: directory`, the home and its owner's UID. For an absolute
per-user location such as `/etc/ssh/keys/%u`, every file there is read, and
one that matches no local account is marked `unattributed`.

**Not collected:** keys that sshd gets from an `AuthorizedKeysCommand` (for
example SSSD's `sss_ssh_authorizedkeys`, from LDAP or Active Directory)
exist only in the directory service; running the command would query it.
The command itself is in the collected configuration.

**Never sent:** the keys themselves, and any line that isn't a public key,
including one whose key data holds no recognised key type (only its number —
someone may have pasted a private key).

**Links are followed, as sshd follows them.** A key file reached through a
symbolic link — the file itself, or a linked `.ssh` directory — still grants
access, so its keys are listed: each `authorized_key` and
`authorized_keys_file` record gives the configured path and the `resolved`
one, and an `authorized_keys_link` record lists every link on the way. This
is safe because nothing but public keys' fingerprints, options and comments
is ever taken from the file: a link to `/etc/shadow` yields only "line 1 is
not a key". The resolved file must still be a regular file.

## `pam`

**Why:** `pam_exec` and other added lines, and unknown or replaced modules
in the PAM module directory (DESIGN.md §8.3).

**Sends:** `/etc/pam.conf` if present and every file in `/etc/pam.d` (up to
1024; a `config_dir` record gives the count and says if any were left out),
masked; and a directory walk (see "Directory walks") of each PAM module
directory found (`/usr/lib64/security`, `/usr/lib/<architecture>/security`
and their `/lib` equivalents, each walked once at its real location), with
the SHA-256 of every file up to 8 MiB.

## Persistence: `cron`, `systemd`, `startup`, `hooks`

**Why:** the places an intruder leaves something to run again — on a
schedule, at boot, at login, or when packages or devices change
(DESIGN.md §8.4).

All four work the same way. Single files are sent as text through links
(see "Configuration files that are links"). Directories get a walk (see
"Directory walks") with the SHA-256 of every file up to 8 MiB, recorded as
`file` records with a `walk_summary`, and then the text of each file in them
up to 256 KiB. A file with a NUL byte in its first 8 KiB (a compiled
generator, for example) or a longer file gets a `content_skipped` record
instead; its hash is still in the walk. A directory reached through a link
is recorded as a `config_link` and walked once at its real location
(`/lib/systemd/system` is usually `/usr/lib/systemd/system`); every further
link to it still gets its own `config_link` (with `already_walked`, and the
home and accounts for a home's directory), so one user's unit directory
linked to another's still shows. Likewise every link to a single file
already sent (`/etc/profile` → `/etc/rc.d/rc.local`) gets a `config_link`
marked `already_sent`. All text is
masked, and the protection rules below decide what may be read at all.

| Module | Sends as text | Walked without text |
|---|---|---|
| `cron` | `/etc/crontab`, `/etc/anacrontab`, `cron.allow`/`deny`, `at.allow`/`deny`; `/etc/cron.d` and `/etc/cron.{hourly,daily,weekly,monthly,yearly}`; every user's crontab (`/var/spool/cron/<user>` on RHEL, `/var/spool/cron/crontabs/<user>` on Ubuntu); queued `at` jobs (`/var/spool/at`, `/var/spool/cron/atjobs`), without their environment (below) | Running `at` jobs' output (`/var/spool/at/spool`, `/var/spool/cron/atspool`): anything a job printed |
| `systemd` | `/etc/systemd/system.conf`, `user.conf` and their `.d` directories; system and user unit directories in `/etc`, `/run` (including `transient` and the generators' output) and `/usr/local/lib`, `/usr/lib`, `/lib`; the `system.control` drop-in directories in `/etc` and `/run`; generator directories in `/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, `/lib` (scripts as text, programs by hash) | `/var/lib/systemd/linger` (users whose own units start at boot); `~/.config/systemd/user`, `~/.config/systemd/user.control` and `~/.local/share/systemd/user` in every home |
| `startup` | `rc.local`, `/etc/init.d`, `/etc/rc.d`; `/etc/environment`, `/etc/security/pam_env.conf`; the system shell start-up files (`/etc/profile`, `profile.d`, `bashrc`/`bash.bashrc`, zsh, fish, csh) and `/etc/skel`; `/etc/update-motd.d`; `/etc/xdg/autostart`; `/etc/ld.so.preload`, `/etc/ld.so.conf` and `ld.so.conf.d` | `.config/fish/conf.d` and `.config/autostart` in every home; plus a `home_startup_file` record with the SHA-256 of each of `.profile`, `.bash_profile`, `.bash_login`, `.bashrc`, `.bash_logout`, zsh's, csh's and fish's start-up files, `.pam_environment`, `.xprofile`, `.xsession`, `.ssh/rc` and `.ssh/environment` — for one that is a link, the SHA-256 of the file it leads to (`resolved`, `target_sha256`), under the same checks |
| `hooks` | `/etc/apt/apt.conf` and `apt.conf.d` (`DPkg::Pre-Invoke` and the like); `/etc/dpkg/dpkg.cfg` and `dpkg.cfg.d`; `/etc/dnf/dnf.conf`, `/etc/yum.conf`, `/etc/dnf/plugins` (including `post-transaction-actions.d`), `/etc/yum/pluginconf.d`, libdnf5's plugin directories, and the Python dnf plugins; udev rules in `/etc`, `/run`, `/usr/local/lib`, `/usr/lib` and `/lib` | — |

Homes are found as in `accounts` (including domain users' homes), and each
of `systemd` and `startup` records the search's `homes` summary. Nothing in
a home is sent as text: files there are listed and hashed only, so a changed
`.bashrc` or a new user unit shows against the baseline without anything a
user wrote leaving the server.

**Limit: the first check.** A hash shows change, not content. On a server's
first check there is no baseline, so a backdoor already in a home start-up
file or a user unit before that check is not recognised from its text. What
the first check still has: a home start-up file whose hash differs from the
`/etc/skel` file of the same name is reported as customised (one that
matches is known to be unchanged), and any user unit or user autostart entry
is reported by name, owner and times, since servers rarely have one. Their
contents are left for a person on the server to read, unless the opt-in
below collects them.

**Opt-in: home text** (`checker init --home-text`, policy §7). With
`privileged` or `all`, `startup` also sends the masked text of each home
start-up file listed above, and `systemd` and `startup` the text of the
files in the home unit and autostart directories, for the homes it covers;
each module records which in a `home_text` record. The default, `off`, sends
none.

- **`privileged`** covers the homes of: UID 0; service accounts (UIDs
  outside `/etc/login.defs`' `UID_MIN`–`UID_MAX`, 1000–60000 by default);
  members of the `sudo`, `wheel` and `admin` groups (by membership or
  primary group); and every user and local group that sudoers grants rights
  to, read the way sudo reads it (includes followed, `User_Alias` expanded,
  numeric `#uid` and `%#gid` entries and quoted names (`"bob"`) included;
  negated entries ignored; a
  rule for `ALL` covers everyone). A local account must be named exactly. A
  home with no local account (a domain user's) is covered when sudoers names
  a user — or a local admin group lists a member (`sudo:x:27:alice@corp`) —
  whose name, without `@domain` or `DOMAIN\`, is the home's directory name;
  that short form never covers a local account of the same name. A
  domain group's members (`%domain\ admins`) can't be seen without asking
  the directory server, which the collector never does, so their homes are
  covered only by `all`.
- **`all`** covers every home found.

Only files already hashed are read, under the same protection rules, plus
three of their own, judged on the path with every link resolved, parent
directories included (an `~/.ssh` linked to another user's): the file must
lie inside that home (a link leading out of it, to `/opt/shared/profile`
say, is described as unreadable, not sent); never inside another home the
setting doesn't cover, even one inside it or at the same path through a
covered account's link (`/srv/svc` → `/home/amy`) — the most specific home
decides, and a tie closes
(service accounts' homes can be broad: `/srv` holding `/srv/erin`, `/var`,
`/var/www`); and nothing hard-linked is read, even under `/usr` (a service
account's home can be `/usr/sbin`). `/` as a home (several service accounts
have it on systemd hosts) is never covered and never closes anything.
`.ssh/environment` and `.pam_environment` — every home's resolved before
any text is read (`~/.ssh` may itself link to `~/.config/env/ssh`), and
recognised by the path reached, so a `.bashrc` linked to one, or a unit
directory linked to `~/.ssh`, gets the same treatment — are sent with each
value replaced by
`[collector: value withheld]`, except the variables whose value is the
evidence (`LD_PRELOAD`, `PATH`, `BASH_ENV` and the others listed for
`authorized_keys` `environment=` options); a line that doesn't start with a
variable name is withheld whole.

**`at` jobs.** `at` stores a copy of the submitting user's whole environment
in each job, as `NAME=value; export NAME` lines between the `umask` line and
`cd <directory> || {`. Those lines are replaced, before masking, by one
comment giving their count and the variables' names; the header comments,
`umask`, working directory and commands are sent. `at` escapes the spaces in
a value, so no value can put a `cd … || {` line of its own into the file and
end the environment early. A file not laid out this way keeps only its
leading comment lines, and a note says the rest was withheld. A spool
directory reached through a link (`/var/spool/cron` → `/var/spool/at`) is
listed and hashed without text, since its files can't be told apart by
where they lie; its target still gets its own walk.

## `system_journal`

**Why:** kernel and system health (DESIGN.md §8.1): out-of-memory kills,
segfaults, oopses, hung tasks, machine checks, module loads and taint; and
reboots (§8.2): unit starts and stops, shutdown and reboot requests, and
core-dump reports.

**Runs:** `journalctl` with the same options and fields as `auth_journal`,
for `_TRANSPORT=kernel` + `_PID=1` (systemd itself) +
`SYSLOG_IDENTIFIER=systemd-logind`, `systemd-coredump` or `systemd-shutdown`.

**Sends:** one `command` source, masked exactly as `auth_journal`'s.

## `boots`

**Why:** which boots the journal holds, with their first and last entries:
the frame for classifying reboots (§8.2) and for spotting gaps (§8.10).

**Runs:** `journalctl --list-boots --no-pager`. **Sends:** its text as a
`command` source, masked. (JSON output needs systemd 251, newer than Ubuntu
22.04's, so the controller parses the text.)

## `login_records`

**Why:** logins, logouts, boots and shutdowns (`wtmp`) and failed logins
(`btmp`): reboot classification (§8.2), login history (§8.3), and cleared or
edited records (§8.10).

**Reads:** every `/var/log/wtmp*` and `/var/log/btmp*` file (rotations
included, decompressed where the server's Python can), under the protection
rules (a hard-linked one is refused). These files are binary, so masking
can't run on them as they are: the collector parses each 384-byte record on
the server and sends only fields. **Sends:** a `login_record` for each record
in the window — type, PID, terminal, id, user, host, exit status, session,
time and address — with the four text fields masked like any log text; then
a `login_file` summary per file: file metadata, counts of records, records
before the window, blank (zeroed) records, as log cleaners leave them, and
of bytes left over at the end, the first and last record times, and what
masking replaced. At most 200,000 records per file are sent; past that, or
past the time limit, the summary says so. Nothing else of the files is sent.
`btmp`'s user field is where a password typed at the login prompt by mistake
ends up, so it is sent only when it names an `/etc/passwd` account, and is
otherwise replaced by `[MASKED:unknown_user]` (counted in the summary) — the
same rule masking applies to failed-login names in the authentication logs.
`wtmp` records successful logins, whose names are kept. The SQLite login databases of newer systems
(`/var/lib/wtmpdb/wtmp.db`, `/var/lib/lastlog/lastlog2.db`) are described
(`login_database`), not yet read.

## `crash_dumps`

**Why:** core dumps of network-facing services (§8.1).

**Sends:** a directory walk (see "Directory walks") of
`/var/lib/systemd/coredump`, `/var/crash` and `/var/lib/apport/coredump`:
names, owners, sizes and times only. Nothing is read or hashed: a core dump
or an apport report holds the crashed program's memory.

## `kernel_modules`

**Why:** out-of-tree, unsigned or proprietary modules, and the
module-loading policy (§8.1); a rootkit's module shows here unless it hides
itself, which the kernel's taint flags may still reveal.

**Reads:** `/proc/modules`, each module's `/sys/module/<name>/taint`, and
`/sys/module/module/parameters/sig_enforce`,
`/proc/sys/kernel/modules_disabled`, `/sys/kernel/security/lockdown` and
`/proc/sys/kernel/tainted`. **Sends:** a `kernel_module` record per module
(name, size, reference count, the modules using it, state, taint flags) and
a `module_policy` record. Load addresses are left out: they would reveal the
kernel's memory layout. A line that doesn't parse is counted
(`unparsed_line`), not sent. If `/proc/modules` can't be read, the module
ends with an error.

## Protected files

Some files are collected only as structured records, status or metadata,
never as text: `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` and
their `-` backups, `/etc/security/opasswd` (old password hashes), and every
account's shell history. These rules keep their contents in, checked on the
file actually opened, after any links:

- **Configuration and log text is read only from system locations** —
  `/etc`, `/usr`, `/lib`, `/lib64`, `/var/log`, `/run`. Cron's and `at`'s
  spools (`/var/spool/cron`, `/var/spool/at`) are read only by `cron`'s own
  walk of them, which tells crontabs, `at` jobs and job output apart; no
  configuration link can reach them. A link that leads
  anywhere else, a home directory included, is not followed for its text.
  History files live in home directories, so no configuration link can
  carry one out, whether or not the home search found it.
- **Nothing hard-linked is read as text**, since a hard link could be any
  file — except root-owned distribution content under `/usr` that a
  program's own configuration names, where packages ship hard links (RHEL's
  crypto policies, for example). Files found by walking a directory (the
  persistence modules) get no exception: ownership can't vouch for them,
  since root's shell can write a history file into a user's home (`su`
  without `-` keeps `HOME`).
- **Nothing protected is hashed either**: a short file's hash can be
  guessed, so directory walks and home start-up files skip the hash of any
  file these rules refuse.
- **The account files above, and the history files in every `/etc/passwd`
  account's home, are refused by device and inode**, however they're
  reached and whatever the name; anything named like a history file is
  refused too.
- **Nothing inside an account's home is read as configuration** where shell
  history can exist there — the account has a login shell, or a history
  file is already present — even where the home lies inside a system
  location. Service accounts' runtime homes without either (Ubuntu 22.04's
  `systemd-network` at `/run/systemd`, `sshd` at `/run/sshd`) stay
  readable, since `/run/systemd/system` is itself evidence. A custom-named
  history file in a no-login account's home, with no default history beside
  it, is not recognised.

Key files, whose place is the home directory, are read wherever sshd reads
them, but never if hard-linked or named like a history file — and only
public keys' fingerprints, options and comments are taken from them. A file
refused by any rule is described (`unreadable_file`, with the reason)
instead. An include pointing outside the system locations (for example
`/opt/app/sudoers`) is therefore recorded but not sent.

## Network drives and automounted folders

On a server joined to a domain, home folders are often network drives that
the automounter connects the first time anything looks inside them. That
would be a change to the server, and a lookup on a slow or unreachable file
server can block in the kernel, past any time limit. So before looking
inside any path — a home, a configuration link's target, a key file — the
collector checks the mount table (`/proc/self/mountinfo`, kernel memory).
Anything under an `autofs` mount point (except listing an indirect map's
directory itself, which mounts nothing; a direct map's mount point is never
touched, since any access mounts it) or on a network file system (NFS, CIFS/SMB,
Ceph, GlusterFS, Lustre, GPFS, AFS, 9p, sshfs, WebDAV and similar) is left
alone and recorded as `not_examined` with the reason (`automount` or
`network_filesystem`). The check sits where every file-system access goes —
the function that turns a path on the server into one the operating system
opens — so no lookup can bypass it: parent directories are resolved one step
at a time, checking the mount table before each, and a final symbolic link's
destination is checked too, so a link can't lead the collector onto such a
mount either; glob patterns are expanded one directory
at a time behind the same check, and stop at 10,000 entries or the module's
time limit — returning no matches at all rather than partial ones (recorded
as `not_examined` with reason `limit`). Directory listings (`sudoers.d`,
`/etc/pam.d`) are read incrementally and stop at 1024 entries, saying so. Directory walks
check each entry the same way before reading its metadata. On a server with no automounted or network
mounts at all, the check costs nothing.

Directives (includes, `AuthorizedKeysFile`) are looked for in the first
1 MiB of each sudo and sshd configuration file; a longer file gets a
`directives_incomplete` record, since what lies beyond could change what is
collected.

## Configuration files that are links

`sudoers`, `ssh` and `pam` read configuration the way sudo, sshd and PAM
do: through symbolic links, which RHEL's `authselect` and crypto policies
use by design (`/etc/pam.d/system-auth` → `/etc/authselect/system-auth`). A
`config_link` record gives the link, its target and the resolved path; the
resolved file is then sent, still only if it is a regular file. Key files
follow links too (see `ssh`); logs never do.

## Commands

Where a file can't practically be read directly, a module runs a command
from the collector's fixed allow-list (DESIGN.md §5.4). The settings can't
add to the list or change a command's arguments. Today the list is
`journalctl`; the manifest carries the list as `commands_allowed`.

A command runs only from its absolute path (`/usr/bin/…` or `/bin/…`, never
a search of `PATH`), and only if that file is owned by root and writable by
no one else; otherwise a `command_unavailable` record says why. It gets no
input (`/dev/null`), a fixed environment (`PATH` and `LC_ALL=C.UTF-8`
only), `/` as its working directory, and the collector's lowered priority.
It runs in its own process group, which is killed when the module's time
runs out or its output reaches the size cap (the source says which), and
again when the command ends, so nothing it started outlives it. Its output is masked line by line exactly
like a file. The source records the command line, the executable's owner,
mode, times and SHA-256, the exit status, and the first 4 KiB of its error
output, masked; if that output was longer, or the command was stopped
part-way through a line, that unfinished line is left out
(`stderr_truncated`). A command that fails on its own (non-zero exit
status) ends its module with status `error`.

## Directory walks

Modules that list directories (from Phase 1's accounts, persistence and
file-system modules on) share one bounded walk. It never follows a symbolic
link (it records the link's target instead), never descends into another
file system, and opens directories without updating their access times.
Each directory it opens must still be the one it listed (same device and
inode); one replaced meanwhile — say a parent swapped for a link — is
recorded as replaced, not followed. A top path that is itself a link is
recorded with its target and not followed.
For each entry it sends the path, type, mode (including set-user-ID and
set-group-ID bits), owner, group, size, link count, inode and change and
modification times; regular files under a size limit — executables, or
every file where the module says so — also get a SHA-256. Each walk has a
depth limit, an entry limit and the module's time limit, and its summary
says whether any of them cut it short, so a gap is never read as "nothing
there".
