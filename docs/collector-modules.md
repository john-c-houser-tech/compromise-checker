# Collector modules

What each collector module reads, why, and what it sends back. The security
and privacy policy (§7) promises this list; keep it in step with
`checker/collector/collector.py`.

Every file is opened read-only, without following a final symbolic link,
without blocking on pipes or devices, and without updating its access time
where the kernel allows. Anything that is not a regular file is described
(type, owner, link target) instead of read. Text is masked for secrets before
it leaves the server (masking rules version 1, listed in the policy §7).
Masking works on whole lines, so a secret can never be split across two
reads. Two cases fail closed — nothing is sent rather than risk an unmasked
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
