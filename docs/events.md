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
chunks joined into whole lines. A bundle cut off part-way still yields what
arrived; the parse summary says what stopped it.

## Times

Every event carries `time`, on the host's clock, and `corrected`, the same
moment on the controller's clock: the host's clock offset is measured from
the collector's start time (host clock, in the manifest) against the
controller's start of the run, and taken off. Both are UTC.

- **Traditional syslog dates** (`Oct 25 09:01:02`) have no year or zone.
  The zone is the host's (`/etc/localtime`'s link, reported by `host_facts`;
  UTC, and the summary says it was assumed, when it can't be known). The
  year: a log file's lines are in time order and the last is no later than
  the file's modification time, so walking back from the end the year steps
  back whenever the month goes up (December before January), and a last
  line dated after the file's time belongs to the year before. A date that
  can't exist (29 February in the wrong year) gives an event without a time.
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
| `session.opened`, `session.closed` | PAM (any service) | service, user |
| `auth.failure` | PAM | service, the rest of the line |
| `sudo.command` | sudo | user (who ran sudo), runas, tty, pwd, command |
| `sudo.denied` | sudo | user |
| `su.switch`, `su.failed` | su | user, target, tty |
| `account.created`, `account.deleted`, `account.modified`, `account.password_changed` | useradd, userdel, usermod, passwd | user (uid) |
| `group.created`, `group.member_added` | groupadd, usermod | group, user |
| `logind.session_new`, `logind.session_end` | systemd-logind | session, user |
| `system.shutdown_requested`, `system.shutdown` | logind, systemd | what, target |
| `kernel.oom_kill`, `kernel.segfault`, `kernel.oops`, `kernel.hung_task`, `kernel.machine_check`, `kernel.module_taint` | kernel | pid, comm, module |
| `process.core_dump` | systemd-coredump | pid, comm, uid |
| `unit.started`, `unit.stopped`, `unit.failed` | systemd | what, unit |
| `system.boot_journal` | the journal's boot list | index, boot id, first and last entry |
| `login.session`, `login.ended`, `system.boot`, `system.shutdown_record` | wtmp | user, line, host, address |
| `login.failed` | btmp | user (masked unless a local account), host, address |

Journal events also carry the journal's `audit_session`, `boot_id` and
`systemd_unit` where present, and a `pid`. Each event keeps the line it came
from (up to 2,048 characters) — already masked on the server like all
collected text.

## The tool's own session

The tool's own visit leaves traces on the host: its SSH login, PAM and
logind sessions, the `sudo` of the collector, login records. These are
recognised from the session record stored with the bundle and marked
`own_session` — kept, so the record is complete, but left out of findings
and of `checker events` unless `--own` is given. An event is the tool's own
when, within five minutes of the session (on the corrected clock):

- it is an SSH login of the session's user with the session's key
  fingerprint (or one of the keys it offered) or from its source port;
- it is a PAM session (`sshd`, `sudo`, `systemd-user`) or a login record of
  the session's user;
- it is a `sudo` by the session's user of the collector itself
  (`python3 -I -B -`);
- it is logind's new session for the session's user — and then every
  journal entry carrying that audit session number is the tool's too.

Anything else by the same account (a person logging in as the scanner
account, another command through its `sudo`) is not marked.

## Storage

The events are stored as gzip JSON Lines, encrypted to the evidence key
like the bundle, beside it (`<bundle>.events.age`), and indexed with their
SHA-256, item count, parser version and an encrypted summary; a stored parse
whose file no longer matches its hash is refused.
