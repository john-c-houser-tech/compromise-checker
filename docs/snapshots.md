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

A name listed twice keeps its plain key for the first entry — the one the
system uses — and `name #2` and so on for the others, so a second `jch`
with UID 0 inserted above the real one shows as `jch` changed and `jch #2`
added.

| Section | Key | From |
|---|---|---|
| `shell_history` | path: size, owner, mode, times | `accounts` |
| `sudo_rules` | file and line: each line sudo acts on, read as sudo reads it — comments dropped, including at a line's end, but not `#include`/`#includedir` or a `#1000` user ID, nor an escaped `\#`; a comment ends at its line's end even after a backslash; other continuations joined; spaces collapsed | `sudoers` |
| `sudo_files` | path: owner, mode, size, times and the SHA-256 of its (masked) text | `sudoers` |
| `authorized_keys` | account, fingerprint and file: key type, options, comment | `ssh` |
| `sshd_config` | file, Match block, keyword and value: each sshd setting | `ssh` |
| `ssh_files` | path: sshd configuration files, key files and `.ssh` directories | `ssh` |
| `pam`, `cron`, `systemd`, `startup`, `hooks`, `crash_dumps` | path: file facts, and the SHA-256 of any text sent | those modules |
| `kernel_modules` | module name: size and taint flags | `kernel_modules` |
| `package_changes` | path: package files that differ from their package | `package_verify` |
| `checksum_store` | path: the package managers' own checksum lists | `package_verify` |
| `privileged_files` | path: set-user-ID, set-group-ID, capability and device files, in system directories and elsewhere (`/home`, `/var`, `/tmp`…) | `system_files`, `unusual_files` |
| `unowned_executables` | path: executables in system directories that no package installed | `system_files` |
| `unusual_files` | path: unusual files in writable and web directories | `unusual_files` |
| `web_files` | path: executable and script files in web roots | `unusual_files` |
| `network_files` | path: resolver, hosts, TCP-wrapper and firewall configuration files, and the SHA-256 of their (masked) text | `network` |
| `interfaces` | interface name: promiscuous, state, type, bridge, bridge port (byte counters, and containers' `veth` interfaces, which are renamed at every restart, are in the uncompared `live` part) | `network` |
| `firewall_rules` | program, table and chain (or set), and line: the loaded rules from `nft` or `iptables-legacy-save`, with what changes by itself left out (counters, quotas used, expiry timers, last-used times, a large set's elements, and the rules of chains Docker, Kubernetes, CNI plugins, fail2ban, libvirt and Tailscale rewrite, which become one line per chain, except `DOCKER-USER`), comments dropped, spaces collapsed, a line repeated in one place numbered | `network` |
| `log_config` | path: journald, rsyslog, audit and SELinux configuration files, and the SHA-256 of their (masked) text | `logging_state` |
| `logging` | `selinux` (running and configured mode), `journald` (its effective `Storage=`, as systemd orders the main file and drop-ins), `apparmor` (loaded, how many profiles) and `apparmor: <profile>` (its mode), `service: <name>` for logging services running and `agent: <name>` for security agents running, each known by the file it runs (or its script) and recording that file's path; `services: {known: false}` instead when the process listing didn't complete. The `/var/log` manifest and the audit records are in the uncompared `live` part; a start-up file that switches history off carries `disables_history` | `logging_state`, `processes` |
| `packages` | name and architecture (and version, for packages installed side by side: rpm's imported keys, `gpg-pubkey`, and kernels): the package manager, version and install time | `software` |
| `software_files` | path: repository files (and the SHA-256 of their masked text) and signing keys (their SHA-256; `record: signing_key`) | `software` |
| `global_packages` | `python: <name>` or `node: <name>`: version and folder | `software` |
| `containers` | runtime and name (`docker: web`): image, privileged, capabilities, host PID/network/IPC namespaces, devices, mounts (`source:destination:rw`), security options; the ID, process and running state are in the uncompared `live` part, with the summary | `containers` |
| `web_config` | path: nginx, Apache and PHP-FPM configuration files, and the SHA-256 of their (masked) text; the logs' summary, the program starts' summary and the counted requests (`web_requests`) are in the uncompared `live` part | `web_logs` |
| `web_served` | `<file>: <directive> <folder>`: each folder an nginx (`root`, `alias`) or Apache (`DocumentRoot`, `Alias`, `ScriptAlias`, `AliasMatch`, `ScriptAliasMatch`) configuration file serves, and each file it includes (`include`, `Include`, `IncludeOptional`), as written | `web_logs` |
| `mail_files` | path: Postfix and Exim configuration files, and the SHA-256 of their (masked) text | `mail` |
| `mail_config` | `postfix: <setting>` (each `main.cf` setting, continuation lines joined), `postfix service: <service> <type>` (each `master.cf` service), `exim: <dc_ setting>` (Debian's `update-exim4.conf.conf`), `exim: <hostlist\|domainlist…> <name>`, `exim: route_list`, `route_data`, `local_interfaces`, `daemon_smtp_ports`: the value and its file. The queue sizes are in the uncompared `live` part | `mail` |
| `peers` | program, remote network (/24 or /48) and port: outgoing TCP connections open at collection, established or connecting, held by a process (not loopback or link-local; connections accepted on one of the host's listening ports, in the same network namespace, are incoming and left out). How many is in the uncompared `live` part | `processes` |
| `listeners` | protocol, address and port (for a packet socket: its type, ethertype and interface), network namespace: listening TCP, unconnected UDP, raw and packet sockets, with the owning UIDs, the programs holding them (hidden processes included) and how many sockets share the key | `processes` |

Running processes, sockets and anything else that changes by itself
between two runs are kept apart, in the snapshot's **live** part: the
processes (hidden ones marked), the sockets, and the `processes` and
`system_files` summaries (whether package ownership was loaded). The
checks read it (DESIGN.md §8.5, §8.7); it is never compared. Logins are
events.

Files under `/run` (transient units, generators' output) are remade at
every boot, so their inode and times are left out; their content hash,
owner, mode and size stay.

Text is hashed and parsed as it was sent — already masked, like key
comments, file names and program names. A newer masking version can change
these with nothing changed on the host, so a comparison across masking
versions says so for every section that holds them.

## Complete or not

Each section says whether it is complete, and if not, why (`gaps`): its
module failed, ran out of time or wasn't collected; the bundle ended before
its trailer; a file in it couldn't be read, was cut short or wasn't
examined (a link that could lead somewhere unsafe, a network drive, a
search past its limit); a configuration file too large to search for
includes; a key file, an include directory or `/etc/pam.d` cut short; a
walk or listing cut off, or a directory not entered (too deep, or another
filesystem mounted on it — except in the walks of writable places, which
leave other filesystems by design); not every home directory examined.

A gap counts only against the sections it touches, judged by what reported
it: an unreadable `/etc/shadow` leaves `accounts` incomplete, not `groups`;
an unreadable key file (reported with its account) leaves
`authorized_keys` incomplete even under `/etc/ssh`, and an unreadable
`sshd_config` include leaves `sshd_config` incomplete; home directories not
all examined affect only what comes from them. An error in a module affects
all of its sections.

A file in a persistence directory whose content wasn't read — refused
because it is hard-linked, say, as RHEL does with identical `.pyc` files —
but which its directory walk still listed is marked on its own item
(`content_unread`, with the reason): its inode, size and times still show a
change. Only an unreadable file the walk didn't list leaves its section
incomplete.

A section a bundle didn't collect at all (a run with `--module`) is absent.
A snapshot also says whether its bundle was a **full** collection (every
module planned).

## Comparing

For each section: the items **added**, **removed** and **changed** (field by
field, old and new). A section that is incomplete on either side, or holds
masked text under a different masking version, is still compared, but
marked **not comparable**, with the reasons: what is missing from an
incomplete collection is not evidence it was removed from the host. A
section present on only one side is not compared at all (and says so).
Sections with no change and nothing to note are left out. Comparisons
always run from the older bundle to the newer.

## Baselines

- **The first.** The first time a host is analysed (`checker changes`), its
  oldest usable bundle (complete, partial or cut off — not broken, empty or
  refused) from a full collection becomes its baseline, and the output says
  the baseline was set just now: change-based checks start from there. If
  none was a full collection, the oldest usable bundle is used, with a note. A baseline taken from an already-compromised host would
  hide the compromise; the checks that need no baseline (1.7) still run on
  every bundle.
- **Later ones.** Each analysis compares the bundle with the one before it
  and with the baseline. Until an operator accepts a newer one, the baseline
  is the host's oldest analysed snapshot, so a slow change, a little each
  run, still shows in full.
- **Accepting a change.** After reviewing a change (a planned upgrade, say),
  `checker baseline accept HOST --reason "…"` makes the host's latest bundle
  (or `--bundle ID`) the baseline. A reason is required, and the bundle must
  be a full collection. Accepting one older than the current baseline, or
  not complete, is allowed but noted.
- **Asking about an older bundle.** `checker changes HOST --bundle ID` with
  a bundle older than the baseline compares it forwards, to the baseline,
  and says the baseline is the newer one.
- **After a purge.** Automatic expiry (`checker purge --expired`) never
  takes a host's current baseline. An explicit purge can, and then the
  host's next analysis takes its oldest remaining usable bundle as the
  baseline (how: `after purge`); every analysis against that baseline says
  so, because changes made before it no longer show
  ([retention](retention.md)).
- **Recorded.** Baselines are kept in an append-only table, enforced by the
  database: host, bundle, time, how (`first`, `accepted` or `after purge`), the operator
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
