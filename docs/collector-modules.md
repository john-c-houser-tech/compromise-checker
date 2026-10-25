# Collector modules

What each collector module reads, why, and what it sends back. The security
and privacy policy (§7) promises this list; keep it in step with
`checker/collector/collector.py`.

Every file is opened read-only, without following a final symbolic link,
without blocking on pipes or devices, and without updating its access time
where the kernel allows. Anything that is not a regular file is described
(type, owner, link target) instead of read. Text is masked for secrets before
it leaves the server (masking rules version 1, listed in the policy §7).

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
example the log replaced by a link to `/dev/null` — become `unreadable_file`
records, which are themselves evidence.

**Not yet:** systems that log authentication only to the systemd journal
(no `secure` or `auth.log`) send an empty summary here; reading the journal
comes in Phase 1.
