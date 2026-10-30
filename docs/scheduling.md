# Scheduled checks

`checker run` does a whole pass in one command; `checker schedule install`
starts it every day on a timer. Run them on a machine that stays on (a
small server or a desktop that doesn't sleep), not a laptop.

## One pass

```
checker run --all [--unattended]          # or host names, or --group GROUP
```

In order:

1. collects from each host (as `checker collect`);
2. analyses each host collected (as `checker analyze`) and compares it with
   what the host looked like at the last run (or, for a host no run has
   seen, its latest analysis);
3. writes one report for the hosts analysed (as `checker report`);
4. deletes what is past its retention period (as `checker purge --expired
   --yes`; each host's current baseline is kept);
5. says what needs a look, and tells your notify command (below).

A host that couldn't be collected isn't analysed again from an older
bundle: it is listed as needing a look. Trouble with one host or one step
is reported and the rest of the run goes on, so the purge and the
notification always happen. The AI advisor is never asked.

Only one run goes at a time: a second one started while the first is
still going (a slow host, a timer firing twice) stops at once.

### What needs a look

- a host's band rose since the last run (a host's first analysis counts
  from Low);
- a high or critical finding is in effect that wasn't at the last run, or
  was less serious then (a rule that expired counts);
- a check failed that didn't at the last run;
- a host wasn't collected (it would have needed a prompt, or the
  collection failed), was collected only in part, or couldn't be analysed;
- a step of the run failed (the report, the purge);
- the purge took a host's baseline (changes made before the next one no
  longer show) or all of a host's evidence.

A finding is the same one in two analyses when its check, its kind and
what it is about (accounts, files, addresses; a process's id left out, as
it changes on a restart) are the same; for a group of many files listed
only in part, its summary must match too, so a new member shows.

What each host looked like at the last run, and anything the notify
command couldn't deliver, is kept encrypted to the evidence key in
`run-state.age` in the checker's home. An analysis made by hand between
runs doesn't change what the next run compares with.

### Exit status

| Status | Meaning |
|---|---|
| 0 | every step worked, and every host analysed is Low |
| 1 | something failed: a host not collected (or only in part) or not analysed, the report, the purge, the notify command, or the run itself; the bands are in the log |
| 2 | nothing was collected: no evidence key, or unreadable settings or inventory |
| 3 | another run is in progress |
| 10, 11, 12 | every step worked, and the worst host is Medium, High or Critical |

The systemd timer counts 10 to 12 as success, so a failed unit means
something in the run went wrong.

## Unattended

`--unattended` asks nothing. A host that would need a prompt isn't
collected, and needs a look (the log says why); the others are collected
as usual:

- a password typed at a prompt, for the login or for sudo: keep it in the
  OS keyring (`password_source: keyring` in `hosts.yaml`), or better, use
  a key and `NOPASSWD` sudo ([scanner account](scanner-account.md));
- a key file with a passphrase;
- the SSH agent, when there is none (`SSH_AUTH_SOCK` unset).

A password kept in the OS keyring is read without a prompt, but a keyring
that has to be unlocked first shows a dialog no one answers: a run waits
a minute for it, then leaves the host out.

For scheduled runs, a dedicated key file for the scanner account, without
a passphrase and readable only by the account that runs the timer
(`--auth key --key PATH`), is the simplest. An SSH agent works if its key
is already unlocked when the run starts; one that asks for a passphrase
(gpg-agent's pop-up) leaves the run waiting for someone to type it, and
the run can't tell beforehand.

## Notifications

```
checker config set notify_command '/usr/local/bin/tell-ops'
checker config set notify_command none
```

When something needs a look, the run starts this command (split into
words, never through a shell; it must start with the command's full path,
as a timer's `PATH` is short) and gives it a short summary on its input:
a subject line, then one line per item, then the report's path. The
advisor's API keys are kept out of its environment. What it couldn't
deliver is sent again with the next run's summary, marked "(from an
earlier run)".

```
Compromise Checker: 2 thing(s) need a look

web01: Low to High (67.1%)
web01: new critical: An account other than root has UID 0

Report: /home/ops/.config/checker/reports/report-web01-20261030T030012Z.html
```

It is in the tool's own words: host names (as in your inventory), bands,
check ids, the tool's titles for the findings and the report's path. No
evidence, and no text from a host (a host's own error message stays in the
log and the report). Where it goes is up to your command: mail, a chat
webhook, a pager. A command that fails or takes more than two minutes
fails the run (exit status 1) and is printed. Keep secrets, such as a
webhook's URL, in the script rather than in the setting: `checker config
show` prints the command.

An example for mail, `/usr/local/bin/tell-ops`:

```sh
#!/bin/sh
{ read -r subject; cat; } | mail -s "$subject" ops@example.org
```

## The timer

```
checker schedule install [--at 03:00]      # every day at this time (the machine's)
checker schedule show
checker schedule remove
```

`install` warns about hosts an unattended run would leave out, writes the
timer and starts it:

- **Linux**: a systemd user timer, `~/.config/systemd/user/compromise-checker.{service,timer}`.
  It runs only while you are logged in unless lingering is on (`sudo
  loginctl enable-linger USER`); `install` says so. Output: `journalctl
  --user -u compromise-checker.service`. A run missed while the machine
  was off runs when it next starts.
- **macOS**: a launchd agent, `~/Library/LaunchAgents/com.nouriloop.compromise-checker.plist`,
  which runs while you are logged in at the Mac. Output: `logs/run.log` in
  the checker's home.

The timer runs `checker run --all --unattended` with this installation's
Python, and with `CHECKER_HOME` set to this home. On Linux, a run still
going after four hours is stopped, so a hung run can't keep the next one
from starting; `install` refuses paths a systemd unit can't hold (quotes,
backslashes, `$`). For hosts that log in
with the SSH agent it also passes this session's `SSH_AUTH_SOCK`; that
path changes with each login for some agents, so a key file is steadier.
Run `install` again after moving the checker or its home.
