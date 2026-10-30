# Whitelists

A whitelist rule suppresses a finding an operator has looked at and
explained: the home office's address, a deploy account, a monitoring
agent's odd process. A suppressed finding is **kept**, with the rule that
suppressed it, listed in the report's appendix, and counts for nothing in
the probability of compromise ([scoring](scoring.md)). Nothing is deleted.

## Files

In the tool's directory (`$CHECKER_HOME`, else `~/.config/checker`):

```
whitelist/global.yaml            every host
whitelist/groups/<group>.yaml    hosts in that inventory group
whitelist/hosts/<host>.yaml      one host
```

They are merged widest first: global, then the host's group, then the
host. Keep them in version control: they are the record of what was
explained, and by whom.

```yaml
profiles: [web]          # shipped rule sets in checker/profiles/ (plan 2.10)
rules:
  - id: home-office
    match:
      check: ssh.login
      variant: new_address
      address: 203.0.113.0/28
    reason: "Home office."
    owner: john
    expires: 2027-10-25
  - id: monitoring-agent
    match:
      check: process.injected
      exe: /opt/datadog-agent/**
    reason: "The monitoring agent maps JIT code."
    owner: ops
    expires: never
disable:
  - id: some-group-rule
    reason: "This host doesn't do that."
    owner: john
```

## Shipped profiles

`profiles:` in any layer applies rule sets shipped with the tool
(`checker/profiles/`), owned by "Compromise Checker defaults", each rule
with its reason:

- `base`, for every host: firewalld's libffi closures (the RHEL family),
  PHP-FPM's opcache in shared memory, AlmaLinux 10's `/boot/efi` modes;
- `web`, only for hosts whose web applications send their own mail:
  `mail.web_user` for `www-data`, `apache`, `nginx`. With it, mail a web
  shell sends shows only in bulk (`mail.volume`, `mail.domains`, which
  need a baseline), not message by message;
- `database`: database servers' own listeners (`mysql`, `postgres`,
  `redis`, `mongodb`, `mongod`);
- `mail`, for relays: daily volume and new recipient domains (broad, on
  purpose; relay changes and web accounts' mail still show);
- `build`, for build servers: compilers (attack tools still show).

Monitoring agents that hold the host (cadvisor, node-exporter) aren't in a
profile: their container names differ per site, and a rule needs the
container and its image together. Write one per agent, for example
`{check: container.privileged, variant: standing, container: "docker: cadvisor", image: gcr.io/cadvisor/cadvisor}`.

## A rule

- `id`: lower-case letters, digits, `.`, `_` and `-`; unique across the
  merged set (a narrower file can't quietly redefine a wider rule: it must
  `disable` it and add its own).
- `reason`, `owner`: required, and must say something.
- `expires`: required. A date (the rule applies up to and including it), or
  `never`, written out. An expired rule stops suppressing, and the
  assessment, `checker analyze` and the report say so.
- `match`: what it suppresses. Every field given must match:
  - `check` (required): the check's id, which must exist;
  - `variant`: one of the check's declared kinds of finding
    (docs/checks.md);
  - `account`, `group`, `key`, `module`, `package`, `program`: an exact
    entity of the finding;
  - `container` (its runtime and name: `docker: cadvisor`) and `image` (its
    repository, without tag or digest: `gcr.io/cadvisor/cadvisor`, so a
    rule survives version bumps): exact entities of a container finding.
    Whoever runs containers chooses both, so they narrow a rule only
    together;
  - `address`: an address or network with its host bits zero
    (`203.0.113.0/24`; `203.0.113.10/24` is refused as a likely typo); an
    IPv4-mapped IPv6 address matches its IPv4 network, and a finding about
    a network (`web.exploit`) matches when that network lies inside it;
  - `path`, `exe` (a process's executable): an anchored pattern. `*` and
    `?` stay within one directory, `**` stands for any number of whole
    directories (`/a/**/b`, not `/a/x**`; at most four), anything else is
    literal (`[` included).
- `broad: true`: required when `match` names nothing that narrows it: only
  the check (and variant), a process's own name (`program`), every address
  (`0.0.0.0/0`, `::/0`) or every path (`/**`). Such a rule suppresses every
  finding of that check, and should look like it does.

A rule matches a finding only if, for each kind it names, it covers
**every** entity of that kind the finding lists: a rule for the account
`deploy` doesn't hide "3 logins as admin, deploy", and a rule for one file
doesn't hide a group of files that also holds an unknown one. A finding
that lists only some of its entities (a group of more than 20 files) is
matched only by a broad rule.

## Conditions: `correlated_with`

A rule can require a partner event: a login from a new address is
explained only when the same account runs the deploy command right after.

```yaml
  - id: deploy-after-login
    match:
      check: ssh.login
      variant: new_address
      account: deploy            # required with correlated_with
      # address: 198.51.100.0/24 # recommended where deploys come from a known network
      correlated_with:
        event: sudo.command      # any type in docs/events.md
        within: 30s              # 1s … 1d
        direction: after         # after (default), before, either
        same: [account]          # account (default), address, or both
        command: "/usr/bin/git -C /srv/app pull"   # full program path; * and ? after it
    reason: "Deploys log in from wherever John is, then pull at once."
    owner: john
    expires: never
```

**Every** event the finding cites (each login, for a finding about
several) needs its own partner: of that type, recorded by the journal from
the program that writes it, running as root (a line written with `logger
-t sudo`, or found only in a log file, is not a partner), not the tool's
own session, within the time on the given side, by the same account (and
from the same address, when asked), running a matching command when one
is named. An event is never its own partner, and a finding's own events
don't vouch for each other. A rule with a condition must name the
`account`; a `command` must start with the program's full path.

**The limit, plainly:** a condition reads what the server logged, so it
explains, it doesn't prove. Whoever holds the deploy account's key can log
in from anywhere and run the same `git pull`, and that login is hidden
like a real deploy. Add an `address` range wherever the deploys come from
a known network, keep `within` short and the command exact, and treat a
stolen deploy key as the risk this rule accepts.

## Maintenance windows

Planned work explains reboots. Inside a window in any layer, an
*unexplained* reboot (a clean shutdown no command explains) becomes
informational, and an *unclean* one (no shutdown recorded: a crash, a
power loss, a forced reset) drops one band, from medium to low, but stays
a finding. The tool knows when an unclean reboot came back, not when the
host went down, and a forced reset timed for the patch night must stay
visible. Each is marked with the window and the band it would have had
(package changes join with plan 2.6):

```yaml
maintenance:
  - id: patch-night            # ids are shared with rules
    every: [sun]               # mon … sun
    from: "02:00"              # quoted: YAML reads 02:00 as a number
    to: "04:00"                # the end is outside; to < from crosses midnight
    tz: America/Los_Angeles    # default UTC
    reason: "Weekly patching."
    owner: ops
    expires: never
  - id: kernel-upgrade
    start: 2026-11-05T01:00:00-08:00   # once; both times with their offset
    end: 2026-11-05T03:00:00-08:00
    reason: "Kernel upgrade, change 1234."
    owner: john
    expires: 2026-12-31
```

The whole outage must be inside one window: the shutdown (the first thing
the finding records) and the boot (for an unclean reboot, only the boot is
known). A host that went down on Saturday
evening and came back during Sunday's window is not maintenance. An
expired window still explains the reboots it covered before its expiry, so
scores don't jump on the day it expires; it stops covering new ones.
Windows can be switched off with `disable`. Operator reboots, power-button
and planned (automatic updater) reboots are already informational and are
left alone.

Times are the window's wall clock in its `tz`. On the day clocks go
forward, a window inside the skipped hour covers nothing; on the day they
go back, the repeated hour is covered twice. One-off windows carry their
offsets and take no `tz`.

## What a rule can't be tricked into

Rules read typed fields the checks set, never text from the host, so a log
line can't make a finding look like another. Path patterns are anchored and
match only plain absolute paths: `/var/www/**` doesn't match
`/var/www/../../etc/shadow`, `/var/www/./x`, `/var/www//x`, or a name with
a control, bidi or line-separator character in it. They are matched without
backtracking, so a crafted file name can't stall the analysis. A process's
name (`comm`) is whatever the process says it is (`prctl` sets it), so
`program` never narrows a rule by itself; match the executable (`exe`)
instead, which is the file it runs.

## Invalid files stop the analysis

Unknown keys, a key given twice, an unknown check or variant, a missing
reason, owner or expiry, a bad address, a relative path, a duplicate id, a
`disable` naming no wider rule, a rule a narrower layer or profile brings
back after a wider one switched it off, an unknown profile, a file that
exists but can't be read, isn't a regular file, is a link to nothing, or
is named `.yml`: `checker analyze` and `checker report` refuse to run,
naming the file and, where it can, the line. Analysing with
a half-read whitelist would hide or show findings no one decided on.

## Commands

- `checker whitelist check` validates every file and builds every set the
  files make (each inventory host, each group, each host file of a host no
  longer in the inventory), so it catches what `analyze` would refuse;
  `checker whitelist check HOST` also shows the host's merged rules, narrowest first, with where each
  comes from, its expiry, and the rules switched off.
- `checker analyze HOST` counts suppressed findings; `--suppressed` lists
  them with their rule and reason.
- `checker whitelist test HOST --file F [--as host|group|global]`: the
  proposed file read in place of the host's (or its group's, or the global)
  file, applied to the host's stored analyses in the retention period. For
  each it prints the probability before and after and the findings the
  change would hide, reveal or move into or out of a maintenance window.
  It reads stored assessments and changes nothing: no file is written and
  no assessment or custody entry is added. If the host's current file is
  broken, it still runs (comparing with no whitelist), so a fix can be
  tested. `--as global` or `--as group` shows the effect on this host only;
  the change reaches every host that uses that file.
- `checker whitelist stale [--days 90]` (1 to 36500): live rules that
  match no stored finding of any inventory host in that time, with the
  current files applied to the stored findings (so a rule added since the
  last analysis is judged fairly). A rule counts once, by its file and id,
  however many hosts share it. Group files no host belongs to, and host
  files of hosts no longer in the inventory, are included: their rules
  match nothing. Expired rules and windows are listed apart, as are those
  expiring within 30 days. Stale rules are candidates for
  removal: a rule that matches nothing still hides what it would match.

## What is recorded

Each assessment records the merged rules it used, the rules switched off,
the expired ones, how many findings each rule matched, and the set's
SHA-256, and the day it judged expiry on. When the whitelist changes, or a
rule has expired since, the next report applies the current one to the
stored findings and scores them again (the checks don't run again), as a
new assessment; the earlier one is kept.

A path or exe pattern made of wildcards alone (`/**`, `/*/**`, `/**/*`)
matches every path: a rule with one needs `broad: true`, as one naming
nothing does.

## Proposals from the AI advisor

`checker advise HOST --role whitelist` asks the optional advisor
(security and privacy policy §9) for rules for findings that are routine on
the host. Its answer is advice: nothing is applied. Each proposed rule is
checked against the host's real findings, after its placeholders are
turned back into names, and offered only when:

- it is a valid rule (the same model as these files) that narrows its
  check, expires within 90 days, and has an id no whitelist it could join
  uses;
- the host isn't assessed High or Critical and has no chain: tidying
  noise is for a host that looks clean;
- no text from the host in the case addresses an AI (asks for rules,
  states a verdict, tells the assistant to ignore its instructions…),
  however it is encoded: that is an intruder steering the advisor, so
  none of its proposals is offered until a person has looked;
- its check is not written only by hand: the checks that can raise a
  critical finding (`account.uid0`, `kernel.taint`, `package.changed`,
  `persistence.ld_preload`, `process.hidden`), every check a chain is made
  of (a suppressed finding takes no part in a chain, so a rule could stop
  one forming), and `web.exploit` (what an attack was isn't one of its
  entities);
- it hides every finding it names, none already suppressed, critical or
  part of a chain (Phase 3 decision 7), all of one variant, which the rule
  names;
- it names every kind of entity its findings carry (account, address,
  path, exe…), with the findings' exact values; a pattern only when several
  named findings in one directory need it, `*` or `?` in its last part
  only, never `**` and never a last part of wildcards alone; a network only
  when several named addresses need it, no wider than /24 (/64); an
  interpreter (`python3`, `bash`, `node`…) as exe only with an account;
- it hides nothing else in any stored analysis of the host, and, for a
  group rule, of any host in the group, and nothing critical or chained
  there either.

The accepted rules are written to `proposals/HOST-TIME.yaml` (beside `whitelist/`, not in it)
(owner-only), each with the layer file it belongs in and the findings it
hides. The file is read back before it is kept and must hold exactly the
accepted rules, so text from a host quoted in its comments can't add one. Its `owner` is left empty, so `checker whitelist check` refuses it
until a person writes in who vouches for it. Review, set the owner, try it
with `checker whitelist test`, then copy it into the layer file. The
report lists what was proposed and what was set aside, and why.

The checks bound what a rule can hide, not why it was proposed. Text an
intruder wrote on a quiet host can ask the advisor for rules, and a rule
for a low finding can pass every other check (a small local model did
this in the [eval](advisor.md#how-well-it-works)). The tool sets aside
every proposal for a host whose text addresses an AI, but such text can
be worded in ways no check foresees. Ask of each proposal whether you
would have written it yourself from the findings it hides.
