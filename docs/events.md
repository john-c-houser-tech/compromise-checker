# Events

The controller turns a stored bundle into **events** (DESIGN.md §6): one per
log record a check can use. Events are derived, never evidence themselves:
they can always be regenerated from the bundle, and a newer parser replaces
an older parse.

`checker events BUNDLE` parses a bundle (or loads its stored parse) and
lists the events; `--type ssh.` narrows them, `--own` shows the tool's own
session too, `--reparse` parses again. Parsing is recorded in the bundle's
chain of custody (`parsed`, then `viewed` when a stored parse is read).

## How a bundle is read

The bundle is decrypted straight into the reader — the plaintext never
touches the disk — and walked once: records in order, and each source's
chunks joined into whole lines. Both the encrypted file and its content are
hashed as they are read and must match the hashes recorded when the bundle
was stored, or the parse is refused: anyone with the public key could make a
valid bundle, so only the hashes show it is the one on record.

A bundle cut off part-way (the connection dropped, the collector was
killed) still yields what arrived: a log file the stream ended inside gives
its events like any other, marked `source_cut`, and the parse summary says
what stopped the walk.

## Times

Every event carries `time`, on the host's clock, and `corrected`, the same
moment on the controller's clock: the host's clock offset is measured from
the collector's start time (host clock, in the manifest, which the
collector sends first) against the moment its first bytes reached the
controller, and taken off — after any password prompt, so typing a password
doesn't shift every time. Both are UTC. The summary gives the offset and
its basis (`first data`; `run start` for sessions stored before that was
recorded, which includes connecting and any prompt).

- **Traditional syslog dates** (`Oct 25 09:01:02`) have no year or zone.
  The zone is the host's (`/etc/localtime`'s link, reported by `host_facts`;
  UTC, and the summary says it was assumed, when it can't be known). The
  year: a log file's lines are in time order and the last is no later than
  the file's modification time, so walking back from the end the year steps
  back whenever the month goes up (December before January), and a last
  line dated after the file's time belongs to the year before. These events
  carry `year_inferred`. Only December before January is a sure year
  boundary: any other step back (a log quiet across New Year, or a clock
  that jumped, as on a VM that boots on a wrong date until NTP corrects it),
  a line dated after the next one within a month, and a last line more than
  31 days before the file's time mark the times from there back
  `time_uncertain`. A date that can't exist (29 February in the wrong year)
  gives an event without a time.
- **RFC 3339 dates** (`2026-10-25T09:01:02.123456+00:00`) are taken as they
  are.
- **The journal** gives each entry's time in microseconds (the source's own,
  else the journal's).
- **Login records** carry their own times.

## Event types

| Type | From | Fields |
|---|---|---|
| `ssh.login.accepted` | sshd | method, user, address, port, key type and fingerprint |
| `ssh.login.failed` | sshd | method, user, address, port, invalid_user |
| `ssh.invalid_user` | sshd | user, address, port |
| `ssh.login.too_many_failures`, `ssh.login.abandoned` | sshd | user, address, port, invalid_user |
| `session.opened`, `session.closed` | PAM (any service) | service, user, by (for sudo, who ran it) |
| `auth.failure` | pam_unix, pam_sss | module, service, the rest of the line |
| `sudo.command` | sudo | user (who ran sudo), runas, tty, pwd, command |
| `sudo.failed`, `sudo.denied` | sudo | user, reason (wrong password; not allowed), and the command details when logged |
| `su.switch`, `su.failed` | su | user, target, tty |
| `account.created`, `account.deleted`, `account.modified`, `account.renamed`, `account.locked`, `account.unlocked`, `account.password_changed` | useradd, userdel, usermod, passwd | user (uid; old_user for a rename) |
| `group.created`, `group.member_added`, `group.member_removed`, `group.members_set` | groupadd, usermod, gpasswd | group, user, by, members |
| `logind.session_new`, `logind.session_end` | systemd-logind (both message formats: systemd 256 and later quote the values) | session, user |
| `system.shutdown_requested`, `system.shutdown` | logind, systemd | what, target |
| `kernel.oom_kill`, `kernel.segfault`, `kernel.oops`, `kernel.hung_task`, `kernel.machine_check`, `kernel.module_taint` | kernel | pid, comm, module |
| `process.core_dump` | systemd-coredump | pid, comm, uid |
| `unit.started`, `unit.stopped`, `unit.failed` | systemd | what, unit |
| `system.boot_journal` | the journal's boot list | index, boot id, first and last entry |
| `login.session`, `login.ended`, `system.boot`, `system.shutdown_record` | wtmp | user, line, host, address |
| `login.failed` | btmp | user (masked unless a local account), host, address |
| `mail.submitted` | Postfix's `pickup`, Exim's `<=` with `P=local` | queue_id, sender (fingerprinted), uid (Postfix) or user (Exim) |
| `mail.sent`, `mail.deferred`, `mail.bounced` | Postfix's delivery agents (`status=sent`, `deferred`, `bounced` or `expired`); Exim's `=>`/`->`, `==`, `**` | queue_id, recipient (fingerprinted), domain, relay; `local` for a delivery into a mailbox on the host |

Mail events come from the mail logs (`mail_log:<path>`) and the journal's
mail facility (`mail_journal`); Exim's main log uses the host's time zone
unless its lines carry an offset.

Journal events also carry the journal's `audit_session`, `boot_id`,
`systemd_unit`, `journal_comm` and `journal_uid` where present — fields the
journal sets itself, so they say who really logged a message whatever name
it gives itself, kept apart from a message's own fields (a core dump's
`comm`) — and a `pid`. Each event keeps the line it came
from (up to 2,048 characters) — already masked on the server like all
collected text.

## One record, several sources

The same record often reaches a bundle more than once: sshd and sudo lines
are both in `/var/log/secure` (or `auth.log`) and in the journal, and
logind's in both journal reads; Postfix's are in `mail.log` (or `maillog`)
and the journal. Events alike to the second, in type,
process and fields are one record: the source with the most of them is kept
(the journal on a tie, for its trusted fields), and the others are named in
the event's `also_in`. Counting per source keeps real repeats — two failed
passwords in one second stay two.

## The tool's own session

The tool's own visit leaves traces on the host: its SSH login, PAM and
logind sessions, the `sudo` of the collector. These are recognised from the
session record stored with the bundle and marked `own_session` — kept, so
the record is complete, but left out of findings and of `checker events`
unless `--own` is given.

Each is tied to the tool's own connection, never to the account or the
time alone — anyone can log in as the scanner account, or write a log line
claiming to be logind. Within five minutes of the session (on the corrected
clock), an event is the tool's own when it is:

- **its SSH login:** the session's user, from the source port the
  controller used (and from its address too, when that is public, so no NAT
  can have changed it), with the key that logged in;
- **that sshd process's** PAM session and any login record (same process
  ID);
- **logind's session** whose number is the audit session the journal itself
  gave that PAM session — never a number read from a message — logged by
  logind itself (the journal's `journal_comm` and `journal_uid`), and that session's scope
  starting and stopping;
- **its `sudo` of exactly the collector's command** as the session recorded
  it (python's path as sudo resolved it, then exactly the arguments), as
  root, with no terminal, in that audit session when the journal says; and
  that sudo process's PAM session;
- the systemd user manager for the session's user starting within 30
  seconds of that login.

Anything else is not marked: another login to the scanner account (with its
password or its stolen key), its sessions, and every command run through
its `sudo`. In `sudo: root` mode only the tool's own root connection is
marked, not other root logins.

**Behind NAT** the host sees another source port, so the tool's own login
isn't recognised; it, and what follows from it, then stay findings — a
false alarm rather than hidden evidence. The parse summary says when the
tool's own login wasn't found (`own_login_found`), and `checker events`
prints a note saying why.

## Storage

The events are stored as gzip JSON Lines, encrypted to the evidence key
like the bundle, beside it (`<bundle>.events-<hash>.age`, named by its
content), and indexed with their SHA-256, item count, parser version and an
encrypted summary. A new parse is written whole, owner-only and to disk
before it is recorded, and the one it replaces is removed only after, so a
crash never leaves the record pointing at the wrong file. A stored parse
whose file no longer matches its hash is refused (`--reparse` parses the
bundle again).
