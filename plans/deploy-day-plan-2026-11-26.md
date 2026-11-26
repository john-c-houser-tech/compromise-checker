# A deploy day on a clean server (2026-11-26)

Draft 1; all three decisions settled by John on 2026-11-26. From the outside technical evaluation of 0.1.6 (risk 3: "calibration on a thin corpus").

## The problem

Calibration (plan 2.10, `docs/scoring.md`) proves two things: a fresh server of each of the seven
images scores Low, and the detection proof's 30 behaviours are all found. Neither one covers the
day a real server is most likely to raise a false alarm: a deploy, when many ordinary changes land
together.

A deploy on one server can add packages, a vendor repository and its key, service accounts, a deploy
user with a narrow sudo rule and an SSH key, a systemd service and a timer, a new listening port, a
firewall rule, and a reboot for a new kernel. Each of these is a finding the tool is right to show.
The risk is how they add up. They come from different checks and name different things, so neither
the groups nor the per-check caps shrink them, and a deploy user who is created, given sudo and then logs in completes the
`new-account-escalated-used` chain (×5). That chain matches what both an attacker and a deploy tool
do.

This has happened once already, in a narrower form: Ubuntu's automatic updates replaced 46 PAM
modules on the demo's `staging-1`, and it read 99.96% (#185, fixed by #189's off-server
verification). A deploy is the same failure on a larger scale.

## What this plan does

It measures before it changes anything. A new proof does a scripted deploy on a clean server, the
way an administrator would, and records what the tool says about it three ways:

1. **Without notice** (no maintenance window, no rules for the deploy).
2. **With notice** (a maintenance window over the deploy, plus a few narrow whitelist rules naming
   what it added), on the same stored evidence. Re-scoring needs no new collection.
3. **After the new baseline is accepted** (`checker baseline accept`), on a fresh collection.

A safety test then makes sure the notice can't hide an attack: the detection proof's golden cases,
analysed with the same window and rules, must still find every behaviour and chain at its band.

Any fix comes after the numbers, each in its own PR, with its reason recorded under "Tuning" in
`docs/scoring.md`, as plan 2.10 did.

## The deploy

On Ubuntu 24.04 and Rocky 9 (the detection proof's two images), on a fresh Nanode set up by
`readonly_proof.set_up` as the other proofs do. Before the baseline, setup also creates `ops`: an
existing administrator with a login shell, a key and sudo, as most servers have. The deploy runs as
`ops` through sudo, not as root over SSH, so the root logins the harness needs for setup all come
before the baseline.

After the baseline, as `ops`, in this order:

| Step | Ubuntu 24.04 | Rocky 9 |
|---|---|---|
| Patch | `apt-get update && apt-get -y full-upgrade` | `dnf -y upgrade` |
| Vendor repository | PostgreSQL's PGDG apt repository and key | PGDG's dnf repository and key |
| Stack | nginx, PHP-FPM, PostgreSQL from PGDG | the same |
| Service account | `useradd --system --no-create-home --shell /usr/sbin/nologin appsvc` | `--shell /sbin/nologin` |
| App | a small program in `/opt/app`, a systemd unit for it listening on 8080, a backup timer | the same |
| Firewall | `ufw allow 443/tcp` | `firewall-cmd --permanent --add-service=https` and reload |
| Deploy user | `useradd -m deploy`, its key, `/etc/sudoers.d/deploy` allowing only `systemctl restart app` | the same |
| Config | an nginx site, a PHP-FPM pool, `pg_hba.conf` | the same |
| Reboot | `systemctl reboot` (the new kernel) | the same |
| Deploy tool | after the reboot, `deploy` logs in and runs `sudo systemctl restart app` | the same |

The patch step must move at least 10 packages, or the run reports "too few updates to count" and
fails as inconclusive, since a current image has nothing to upgrade. The proof records how many
moved.

## What the tool is predicted to say

From `docs/checks.md` and `docs/scoring.md`, before any run. The run confirms or corrects this
table, and the plan records the real one.

| Finding | Predicted band | Note |
|---|---|---|
| `software.packages` installed, upgraded | low, info | low groups become info inside a window |
| `software.repository` repo and key | medium | not covered by windows today |
| `account.log_changes` / `account.changes` for package accounts | low | the "install nearby" rule |
| the same for `appsvc` | low or medium | no terminal and an install nearby should make it low |
| the same for `deploy` | medium | it has a login shell |
| `ssh.authorized_keys` for `deploy` | high | any new key |
| `sudo.rules` for `deploy` | high | |
| `persistence.changes` for the unit and timer | medium | in `/etc`, written by hand |
| `net.listener` 8080, 80, 5432 | low | |
| `net.config` firewall | medium | |
| reboot | info | an operator's reboot |
| chain `new-account-escalated-used` for `deploy` | ×5 | new account → sudo rule → login |

With a 2% prior, two highs, four mediums and the chain go past 99%: Critical, without notice.

## What counts as passing

- **Without notice:** any score, High and Critical included, as long as the report's top
  contributors are the deploy's own steps, so a person can tell within a minute that it was the
  deploy (decision 1).
- **With notice:** Low, using one maintenance window and at most five whitelist rules. Each rule
  names its subject (an account, a path, a port, a repository file), and none uses a glob wider than
  one directory. The rules are kept as `tests/integration/deploy-whitelist.yaml`, so they also serve
  as the example of how an operator gives notice.
- **After the new baseline:** Low with no deploy rules, and no finding about the deploy shown as new.
  This is the expected way to live with a deploy, and it is untested today. It tests whether
  log-based findings from before the new baseline count again.
- **Safety:** the detection proof's golden cases (`tests/golden/detection-*.json.gz`), analysed with
  the deploy window (a one-off window over the cases' attack times) and the deploy rules, still find
  all their behaviours and both chains, and stay High or Critical. This test is offline and runs in
  CI from then on.

## Steps

### DD.1 The proof

`tests/integration/deploy_day_proof.py`, built from `detection_proof.py`'s pieces (server, setup,
`collect`, `judge`, `report`, `--json`, `--golden`, sweep). It runs the deploy script on standard
input (as the detection proof does with its attacks), checks the patch count, collects, analyses
the three ways above, and prints a findings table for each. It adds the `ops` setup and the deploy
fixture `deploy-whitelist.yaml`. Unit tests cover the parts that run without a server: the
three-way judging and the table.

Cost: two Nanodes for under an hour, a few cents. John runs it, since I can't start Linodes.

### DD.2 The run

John runs the proof on both images with `--golden`. The results go into this plan: the real
findings table, the three scores, and every finding that went against the prediction. The golden
cases `deploy-ubuntu24.04` and `deploy-rocky9` join `tests/golden`, so CI pins the deploy day's
scores from then on.

### DD.3 The safety test

An offline test: the detection golden cases under the deploy notice, as in "What counts as
passing". It runs in CI. It goes in the same PR as DD.2's golden cases.

### DD.4 Fixes

Only what DD.2's numbers call for, one PR each, each with its reason under "Tuning" in
`docs/scoring.md` and a proof re-run before merge. Possible directions, to be chosen once the
numbers are in, not before:

- **Windows covering more than reboots and packages**, such as repository files, units and
  listeners added inside the window. This needs care: a window is the time an attacker would pick
  if they knew it.
- **The chain inside a window.** It could stay as it is, or need its login step outside the window.
  The safety test has to hold either way.
- **A finding band that calibration shows is wrong**, through an `OVERRIDES` entry, the first one.
- **Report wording**, if the deploy's findings are right but hard to read as a deploy.

### DD.5 Calibration

`calibrate.py` runs the deploy proof as well and writes a third table into `docs/scoring.md`
(image, the three scores, findings by band), so every later calibration covers a deploy day.

## Decisions

1. **What may a deploy without notice score?** DECIDED (John, 2026-11-26), as recommended: anything, High and Critical included,
   as long as the report's top contributors are the deploy's own steps, so a person can tell within
   a minute that it was the deploy. A new user given sudo who then logs in, with nobody saying it
   was planned, is what a break-in looks like, and a tool that reads it as Low would miss the real
   one. The alternative is to require Elevated or lower, which would mean weakening the chain or
   the sudo rule finding.
2. **How much notice is reasonable?** DECIDED (John, 2026-11-26), as recommended: one window and at most five narrow rules (see
   "What counts as passing"). If DD.2 needs more, that is a finding about the tool, to fix in DD.4,
   and a reason not to raise the limit.
3. **A second deploy shape.** DECIDED (John, 2026-11-26), as recommended: not now. A container deploy (Docker, new images, a
   published port) is the other common shape, and `container.new` already treats a new tag as a
   deploy. Add it after DD.5 if the first shape turns up problems.
