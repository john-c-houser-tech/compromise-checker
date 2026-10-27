# Collector modules

What each collector module reads, why, and what it sends back. The security
and privacy policy (§7) promises this list; keep it in step with
`checker/collector/collector.py`.

Every file is opened read-only, without following a final symbolic link,
without blocking on pipes or devices, and without updating its access time
where the kernel allows. Anything that is not a regular file is described
(type, owner, link target) instead of read. Text is masked for secrets before
it leaves the server (masking rules version 3, listed in the policy §7).
Masking works on whole lines, so a secret can never be split across two
reads. Two fixed vocabularies are never masked, because they look like
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
`_SYSTEMD_UNIT`, `_AUDIT_SESSION`, `_AUDIT_LOGINUID`, plus the cursor,
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

## Protected files

Some files are collected only as structured records, status or metadata,
never as text: `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` and
their `-` backups, `/etc/security/opasswd` (old password hashes), and every
account's shell history. Three rules keep their contents in, checked on the
file actually opened, after any links:

- **Configuration and log text is read only from system locations** —
  `/etc`, `/usr`, `/lib`, `/lib64`, `/var/log`, `/run`. A link that leads
  anywhere else, a home directory included, is not followed for its text.
  History files live in home directories, so no configuration link can
  carry one out, whether or not the home search found it.
- **Nothing hard-linked is read as text**, since a hard link could be any
  file — except distribution content under `/usr`, where packages ship hard
  links (RHEL's crypto policies, for example).
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
