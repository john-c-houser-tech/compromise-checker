# Snapshots and baselines

Besides its [events](events.md), each bundle gives a **snapshot**: the
host's state when it was collected (DESIGN.md §6). Two snapshots of the same
host can be compared, and every change-based check (DESIGN.md §2 principle
4) is a check on such a comparison against the host's **baseline**
(DESIGN.md §7).

`checker changes HOST` shows what changed in the host's latest bundle (or
`--bundle ID`) since the bundle before it and since the baseline, the first
20 items per kind and section (`--all` lists every one).

## What a snapshot holds

A snapshot is a set of sections, each mapping a stable key (a name, a path)
to that item's facts:

| Section | Key | From |
|---|---|---|
| `host` | os, kernel, machine_id, kernel_taint, mandatory_access_control, module_policy | `host_facts`, `kernel_modules` |
| `accounts` | account name: UID, GID, home, shell, password field, and the password status from `/etc/shadow` (`shadow_…`) | `accounts` |
| `groups` | group name: GID and members | `accounts` |
| `shell_history` | path: size, owner, mode, times | `accounts` |
| `sudo_rules` | file and line: each line sudo acts on (comments dropped, `#include` kept, continuations joined, spaces collapsed) | `sudoers` |
| `sudo_files` | path: owner, mode, size, times and the SHA-256 of its (masked) text | `sudoers` |
| `authorized_keys` | account, fingerprint and file: key type, options, comment | `ssh` |
| `sshd_config` | file, Match block, keyword and value: each sshd setting | `ssh` |
| `ssh_files` | path: sshd configuration files, key files and `.ssh` directories | `ssh` |
| `pam`, `cron`, `systemd`, `startup`, `hooks`, `crash_dumps` | path: file facts, and the SHA-256 of any text sent | those modules |
| `kernel_modules` | module name: size and taint flags | `kernel_modules` |
| `package_changes` | path: package files that differ from their package | `package_verify` |
| `checksum_store` | path: the package managers' own checksum lists | `package_verify` |
| `privileged_files` | path: set-user-ID, set-group-ID and capability files | `system_files` |
| `unusual_files` | path: unusual files in writable and web directories | `unusual_files` |
| `listeners` | protocol, address and port, network namespace: listening TCP, unconnected UDP, raw and packet sockets, with the owning UID and the programs holding them | `processes` |

Running processes, logins and anything else that changes by itself between
two runs are not in a snapshot; checks read them from the bundle as they
were.

Text is hashed and parsed as it was sent — already masked. A newer masking
version can change a hash or a line with nothing changed on the host, so a
comparison across masking versions says so for the sections built from
text.

## Complete or not

Each section says whether it is complete, and if not, why (`gaps`): its
module failed, ran out of time or wasn't collected; the bundle ended before
its trailer; a file in it couldn't be read, was cut short, or a walk or
listing was cut off; not every home directory was examined. A gap counts
only against the sections it touches: an unreadable `/etc/shadow` leaves
`accounts` incomplete, not `groups`.

A section a bundle didn't collect at all (a run with `--module`) is absent.

## Comparing

For each section: the items **added**, **removed** and **changed** (field by
field, old and new). A section that is incomplete on either side, present
on only one, or built from text under a different masking version is still
compared, but marked **not comparable**, with the reasons: what is missing
from an incomplete collection is not evidence it was removed from the host.
Sections with no change and nothing to note are left out.

## Baselines

- **The first.** The first time a host is analysed (`checker changes`), its
  oldest usable bundle (complete, partial or cut off — not broken, empty or
  refused) becomes its baseline, and the output says so: change-based checks
  start from there. A baseline taken from an already-compromised host would
  hide the compromise; the checks that need no baseline (1.7) still run on
  every bundle.
- **Later ones.** Each analysis compares the bundle with the one before it
  and with the baseline. Until an operator accepts a newer one, the baseline
  is the host's oldest analysed snapshot, so a slow change, a little each
  run, still shows in full.
- **Accepting a change.** After reviewing a change (a planned upgrade, say),
  `checker baseline accept HOST --reason "…"` makes the host's latest bundle
  (or `--bundle ID`) the baseline. A reason is required.
- **Recorded.** Baselines are kept in an append-only table, enforced by the
  database: host, bundle, time, how (`first` or `accepted`), the operator
  and the controller; the reason is encrypted to the evidence key, like
  everything else that could describe the host. Each new baseline also adds
  a `baseline` entry to its bundle's chain of custody. `checker baseline
  show HOST` lists them, with reasons when the key is at hand.

## Storage

The snapshot is stored like the events: gzip JSON, encrypted to the
evidence key, beside the bundle (`<bundle>.snapshot-<hash>.age`), indexed
with its SHA-256, item count, version and an encrypted per-section summary.
It is made in the same walk of the bundle as the events, so the bundle's
hashes are checked once for both, and it can always be made again from the
bundle.
