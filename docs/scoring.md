# Scoring

Each analysis turns its findings into a **probability that the host is
compromised**, with a band: *Low*, *Elevated*, *High* or *Critical*
(DESIGN.md §11). The number is an estimate, not a measurement: read it
with the coverage beside it, since a host with no logs can't produce the
findings that would raise it. The code is `checker/scoring.py`; its tables
are the only place the weights live.

## The model

Every compromise-indicator finding has a **likelihood ratio**: how much
more likely it is on a compromised host than on a clean one. They combine
in log-odds, starting from a prior:

```
log-odds = log-odds(prior) + Σ contributions
probability = 1 / (1 + e^-log-odds)
```

A finding's contribution is the logarithm of its ratio, adjusted by the
rules below.

| Band | Likelihood ratio | Examples |
|---|---|---|
| critical | 100 | a second UID 0 account; `/etc/ld.so.preload` set; a hidden process; a module hiding from the module list; `ps`, `sshd` or libpam differing from its package |
| high | 20 | a new key for root; a web shell; a shell on a network socket; a new sudo rule |
| medium | 4 | a direct root login; a login from a new address; a new cron job |
| low | 1.5 | an unexplained reboot; a backdated file |
| info | 1 | an operator's reboot; `su` use (they don't count) |

`OVERRIDES` in `checker/scoring.py` can give one check, or one variant of
it, its own ratio where calibration shows its band misjudges it. There are
none yet; Phase 2's calibration (plan 2.10) sets them, each with its
reason recorded here.

## Rules

- **Only compromise indicators count.** Hygiene and exposure findings get
  their own rating, the highest band among them with their counts, and
  never move the probability (DESIGN.md §2 principle 9).
- **One thing seen by several checks counts once, plus a little.**
  Findings that name the same file (`path:`) or process (`pid:`), directly
  or through each other, form a group. The group counts its strongest
  finding in full and adds at most a doubling (log 2) for the rest. A
  set-user-ID shell in `/tmp` is both `files.scratch` and
  `files.privileged`, and is one behaviour. Shared accounts and program
  names don't group: a new key for root and a direct root login are two
  pieces of evidence. Among equally strong members, the group is led by
  the one whose check has the fewest other findings, so a second,
  separate file that check caught still counts in full.
- **Volume isn't evidence.** All of one check's findings together add at
  most a doubling beyond its strongest, so fifty logins from new addresses
  weigh twice one, not fifty times. This applies to each group's lead;
  the rest of a group is capped by the group alone.
- **Order never matters.** Ties are broken by what findings say, never by
  where they are in the list, so the same findings always give the same
  score. The contributors' table marks a finding "capped" only when a cap
  cut it.
- **Uncertain findings count half** their log ratio: the section they
  come from wasn't fully collected on one side.
- **Suppressed findings don't count** (whitelists, plan 2.2), and are
  kept with the rule that suppressed them.
- **Every analysis counts the state it finds.** A change stays a finding
  until a new baseline is accepted, and counts each time; the report marks
  which findings are new.

## Chains

Findings that together tell an attack's story earn a bonus on top of what
each counts alone (DESIGN.md §11.3; `CHAINS` in `checker/correlate.py`,
data like the ratios):

| Chain | Steps, for one account | Within | Bonus |
|---|---|---|---|
| `new-account-escalated-used` | a *new* account or key → a sudo rule, privileged group or group membership for it → a login by it | 7 days | ×5 |
| `guessed-then-entrenched` | a login after repeated failures → a new key, sudo rule or privileged group for it | 24 hours | ×5 |

- Each chain counts **once**, however many accounts complete it.
- Only findings the score counts are steps: compromise indicators, not
  suppressed (a whitelisted step is explained), not informational (a
  maintenance window may have made them so).
- Each step is a different finding, citing different log lines: one
  `usermod -aG sudo alice` is not both "a new account" and "privilege".
  Adding an existing user to a privileged group isn't a new account, so
  ordinary onboarding of an existing user doesn't complete the first chain.
- A step from the logs must fall within the chain's time of its first
  step (before or after it), and the login must come after the first
  timed step; when every earlier step is about state (a snapshot change,
  which has no time, and counts only if new since the previous bundle),
  the login must come after the previous bundle. With no previous bundle,
  such a chain can't be told and isn't counted.
- The tool's own account (the one its current session logged in as)
  never completes a chain: its earlier visits' logins are in the logs.
- A new administrator account that is created, given sudo and used is
  exactly what the first chain describes. Where that is routine (a
  provisioner), whitelist one of its steps for that account.
- The bonus shows in the contributors as its own line (`chain:<id>`),
  with the findings that made it listed under it in the report; the
  assessment records each chain's findings and events.

More chains arrive with the checks they need: a web worker's child, a file
in a scratch place and an outbound connection (2.4, 2.8); anything high,
then logging stopped or history wiped (2.5); a new web script, then
successful requests to it (2.8).

## The prior

The prior is the probability of compromise before any evidence: 2% by
default (DESIGN.md §11.2). Set it in `config.yaml` as `prior:`, per host
group in `group_priors:` (`{web: 0.05}`), or per host with
`checker hosts add --prior`. A host's own wins over its group's, which
wins over the configuration's. The assessment records the prior and where
it came from. Threat packs (Phase 4) will raise it for hosts exposed during
an exploitation window.

## Bands

| Probability | Band |
|---|---|
| below 10% | Low |
| 10% to 50% | Elevated |
| 50% to 90% | High |
| 90% and above | Critical |

From the default 2% prior: one high finding gives 29% (Elevated); one
critical, 67% (High); two highs from different checks, about different
things, 89% (High); a high and a critical, 98% (Critical). Two highs from
one check give 45% (Elevated): the family cap counts the second as a
doubling. Percentages are shown rounded down, so the number shown is never
across a band's edge from its band (0.4999 is 49%, Elevated), and priors
under 1% keep a decimal. DESIGN.md §11.3's worked example: one ratio-20 finding gives
29%, and adding a ratio-5 finding gives 67%.

## What is stored

Assessments from 2.1 on (format 2) hold the prior and its source, the
log-odds, the probability and band, each finding's ratio and contribution,
the contributors (largest first, with their share and any cap), and the
hygiene and exposure rating. The scoring version is among the assessment's
versions; an older assessment is analysed again when the report needs it,
or when the host's prior has changed since. The index's encrypted summary
gains the probability and band.

## Golden reports

`tests/golden/` holds real analyses from throwaway servers: for each of
Ubuntu 24.04 and Rocky Linux 9, a fresh server (`fresh-*`, its own
baseline) and the same server after the detection proof's ten behaviours
(`detection-*`). Each case is what `analyze` reads for one bundle (its
events and snapshot, the previous bundle's and the baseline's snapshots,
earlier bundles' events), gzipped JSON, beside its expected assessment
(`*.expected.json`: findings, which checks ran, the score).

CI analyses every case through the same `evaluate` that `analyze` uses and
fails on any difference. After a deliberate change to the checks, the
ratios or the whitelists, run `python scripts/update_golden.py`: it
rewrites the expectations and prints each case's probability before and
after, and the findings added or gone. Commit those with the change, so
the review shows what moved.

New cases come from `tests/integration/detection_proof.py --golden
tests/golden`, which picks the bundles and their baseline the way
`analyze` does. The repository is public, so before a case is written
every public IPv4 and IPv6 address in it, wherever and however it is
written (log text, `address:port`, IPv4-mapped, any case, reverse-DNS
dashes), is replaced by a documentation address (203.0.113.x,
2001:db8::x), consistently; a version number that happens to parse as a
public address is replaced too. The export then fails if any public
address survives, or if the controller's or the server's address survives
in any form it knows (also `/proc/net` hex), and fails if the replacement
changed what the checks find (a check that tells public addresses from
others), so a case stays faithful to the real analysis.

Cases hold parsed events and snapshots: they pin the checks and the
scoring, not the parsers or the collector.

## Calibration

The ratios are expert estimates. Plan 2.10 tunes them against fresh
servers on all seven images (false alarms) and the detection proof's
compromised servers (detections), and records the results here.
