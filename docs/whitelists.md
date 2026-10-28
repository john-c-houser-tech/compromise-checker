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
      program: datadog-agent
    reason: "The monitoring agent maps JIT code."
    owner: ops
    expires: never
disable:
  - id: some-group-rule
    reason: "This host doesn't do that."
    owner: john
```

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
  - `address`: an address or network (`203.0.113.0/24`);
  - `path`: an anchored pattern: `*` and `?` stay within one directory,
    `**` crosses directories, and anything else is literal (`[` included).
- `broad: true`: required when `match` names nothing but the check (and
  variant): such a rule suppresses every finding of that check, and should
  look like it does.

## What a rule can't be tricked into

Rules read typed fields the checks set, never text from the host, so a log
line can't make a finding look like another. Path patterns are anchored and
match only plain absolute paths: `/var/www/**` doesn't match
`/var/www/../../etc/shadow`, `/var/www/./x`, `/var/www//x`, or a name with
a newline or control character in it.

## Invalid files stop the analysis

Unknown keys, an unknown check or variant, a missing reason, owner or
expiry, a bad address, a relative path, a duplicate id, a `disable` naming
no wider rule, an unknown profile: `checker analyze` and `checker report`
refuse to run, naming the file and, where it can, the line. Analysing with
a half-read whitelist would hide or show findings no one decided on.

## Commands

- `checker whitelist check` validates every file; `checker whitelist check
  HOST` also shows the host's merged rules, narrowest first, with where each
  comes from, its expiry, and the rules switched off.
- `checker analyze HOST` counts suppressed findings; `--suppressed` lists
  them with their rule and reason.
- Coming in plan 2.2b: `checker whitelist test` (what a change would hide,
  on stored assessments, before it is saved), `checker whitelist stale`
  (rules that matched nothing in 90 days, or are about to expire), and
  maintenance windows.

## What is recorded

Each assessment records the merged rules it used, the rules switched off,
the expired ones, how many findings each rule matched, and the set's
SHA-256. When the whitelist changes, the next report applies the new one to
the stored findings and scores them again (the checks don't run again), as
a new assessment; the earlier one is kept.
