# Collector modules

What each collector module reads, why, and what it sends back. The security
and privacy policy (§7) promises this list; keep it in step with
`checker/collector/collector.py`.

Every file is opened read-only, without following a final symbolic link,
without blocking on pipes or devices, and without updating its access time
where the kernel allows. Anything that is not a regular file is described
(type, owner, link target) instead of read. Text is masked for secrets before
it leaves the server (masking rules version 2, listed in the policy §7).
Masking works on whole lines, so a secret can never be split across two
reads. A private key block runs only as long as its lines look like key
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
belongs to no `/etc/passwd` account is an *unlisted home*. Only those three
SSSD settings are read from `sssd.conf`; nothing from it is sent. NSS itself
is not asked: with SSSD's defaults it lists no domain users, and a lookup
can reach the directory server and write SSSD's cache on the target.

A `homes` record gives the roots searched, how many directories were
examined, whether the search was cut short (at 20,000 directories or the
module's time limit), and the unlisted homes. Their history files are
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
  then masked; for `environment`, the whole value is masked when the
  variable's name looks like a secret (including any `…_PWD`, but not the
  directories `PWD` and `OLDPWD`); an option sshd doesn't know, which makes
  it ignore the line, is replaced by its length and `known: false` — and its comment (masked). If the type
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

`/etc/passwd`, `/etc/shadow`, `/etc/gshadow` and their `-` backups,
`/etc/security/opasswd` (old password hashes) and every account's shell
history files are collected only as structured records, status or metadata.
Any file the collector would send — and any authorized_keys file it reads —
is checked against them *after* it is opened, by device and inode, so no
configuration link or hard link can carry their contents out: such a file
is described (`unreadable_file`, "is (or links to) a protected file")
instead.

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
