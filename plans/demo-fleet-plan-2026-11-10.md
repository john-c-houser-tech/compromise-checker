# A demo fleet that can be shown, and kept running (2026-11-10)

John: the checker needs demonstrating to people who might use it, Multnomah County among them,
without showing them anything from his own server. And he can't test the whole web interface
himself: one real server only goes so far.

`tests/integration/demo_fleet.py` (plan 5.7) already makes five throwaway servers, checks each,
really attacks two, checks again and deletes them, for the README's pictures. It falls short three
ways:

- **Two checks a server, minutes apart.** No week of quiet checks, no change that was looked at and
  accepted, no rule approved earlier.
- **Its data can't be shown as it is.** The checker runs on John's laptop, so the servers' login
  records hold his network address. Only the screenshot script's scrubber makes a picture fit to
  show.
- **It is over before anyone looks.** The servers are deleted, so a check can't be started, watched,
  stopped or scheduled: the parts of the interface John can't reach today.

## Decided (John, 2026-11-10)

- **Staged throwaway servers, never his own data, scrubbed or not.**
- **The checker itself runs on a throwaway server too,** installed the way the install page says.
  Every address in what it stores then belongs to a server made for the demo.
- **A keep-alive option:** the fleet can stay up, so the live parts of the interface can be used.
- **History:** the saved demo data holds checks from earlier runs, not one before and one after.

## How it works

One script, `tests/integration/demo.py`, with four commands:

    # Built so far: up [--days N], status, save DIR (D.5), down. --build when it is needed.
    demo.py up [--days N] [--build]   # make the checker's server and the fleet, play the story
    demo.py status                    # what is up, since when, what it has cost, when it ends
    demo.py save DIR                  # copy the checker's data down, as the demo dataset
    demo.py down                      # delete every server (it asks for a save first)

- **The checker's server** is a new Linode with the published release installed by the install
  page's own line (the `public-web` route of the install proof already does this, with a name and
  a real certificate). `--build` installs this commit instead, for testing work not yet released.
  The script then adds the fleet through the checker's own commands on that server, as an admin
  would.
- **The story** is a list of dated steps in one file: what happens on a server (a package update, a
  new admin account, the attack), and what the person running the checker does about it (accepts a
  change, approves a rule, leaves one undecided). Without `--days` it plays in one sitting, about
  half an hour, and the history's dates are minutes apart. With `--days N` the servers stay up, the
  checker's own daily schedule does the checking, and each step happens on its day, so the history
  has real dates. (As built, the later days are timers on the checker's server: see the last
  section.) The steps that happen on a fleet server were to be put there as timers when it is made,
  so the laptop needn't be on.
- **Shown as it is.** Nothing in the data comes from John's laptop or network except his sign-in to
  the web interface, which the script filters out of what it saves. Every page still says it is a
  demo fleet, attacked on purpose.
- **The dataset.** `save` copies the checker's home (store, evidence key, web accounts left out)
  to a folder outside the repository. `CHECKER_HOME=DIR checker web` browses it on the laptop, with
  no servers and no network. The screenshot script reads the same folder.

## Safety and cost

- **A staged server is really weakened** (a root login key, a new sudo account, `PermitRootLogin
  yes`), and with keep-alive it stays that way for days. So each fleet server's firewall lets SSH in
  from the checker's server only, set before any attack step, and the keys the attacks plant have
  their private halves thrown away at once, as now.
- **The checker's server** is public, as any install with a web address is: sign-in with two-factor,
  the installer's own lockdown.
- **Cost:** seven Nanodes (the story needed one more) are about $1.30 a day. One sitting is a few
  cents; a week is about $9.
  `up` says the cost before it starts and needs John's OK each time, as the proofs do. `--days` has
  a ceiling of 14.
- **Nothing deletes the fleet by itself** (a server can't delete itself without holding the Linode
  token, which it must not). `up --days` prints the end date, `status` shows it, the next run of any
  proof sweeps up what is past its date, and the session that starts a fleet puts a reminder in
  John's calendar for the day it ends.

## Open decisions

1. **The AI advisor.** It is the part people most want to see, and it needs an Anthropic API key on
   a public throwaway server. Proposed: leave it off in the first build; then a key made only for
   the demo, with a low spend limit, put there by `up` and revoked by `down`.
2. **Who signs in.** Proposed: John only at first. Later, invited accounts that can view and not
   act (the interface has these already), for a prospective user to look around by themselves.
3. **The story's content:** which servers, what happens when, what is decided. Settled in D.1.

## Steps (one pull request each)

- **D.1 The story and what it covers.** No servers. A table of every page and state of the
  interface, and which step of the story produces it; what no story can produce is named, with why.
  The story file itself. John approves the story.
- **D.2 The checker on its own server.** `up` and `down` with today's two checks, run from the
  throwaway. Proved by a run: the saved data holds no address but the demo's own.
- **D.3 The story, in one sitting.** The player, the admin's decisions made through the checker's
  commands, the firewall rule. Proved by a run and a look through the pages against D.1's table.
- **D.4 Keep-alive.** `--days`, timers (on the checker's server, as built), `status`, the end date and the sweep. Proved
  by a two-day run.
- **D.5 The dataset.** `save`, browsing it on the laptop, the screenshot script moved onto it, and
  `demo_fleet.py` retired (done 2026-11-14: `screenshots.py --dataset` works on a throwaway
  copy of a saved dataset). The README's pictures taken again.
- **D.6 The advisor and viewers,** as decided in 1 and 2.

## Found in the pages while the demo was up (to fix later)

- **After setting up two-factor, the first account lands on the Sign-in security form**
  (John, 2026-11-10). It reads as one more step of making the account, but the account is done
  and the rest of the interface is open. Fix: send the person on to the Servers page with a line
  saying the account is ready, or say so plainly at the top of the form.
  **Fixed 2026-11-12:** when two-factor is required, saving the recovery codes goes on to the
  Servers page, which says "Two-factor sign-in is on, and your account is ready." Turned on by
  choice from Sign-in security, it goes back there as before.
- **The log command `schedule install` prints doesn't work for the installed checker's account**
  (seen on the demo's third run, 2026-11-10). `journalctl --user -u compromise-checker.service`,
  run as the service account, answers "No journal files were opened due to insufficient
  permissions": a system account has no journal of its own, so its timer's output is in the
  system journal. Fix: print a command that works there (to be tried on a server:
  `sudo journalctl _SYSTEMD_USER_UNIT=compromise-checker.service`), in `checker/schedule.py`
  and `docs/scheduling.md`.
  **Fixed 2026-11-12:** a system account is told that command, with `+ USER_UNIT=` for what
  systemd says of the unit; an ordinary one the old one. The
  match was tried on a laptop's own units; on an installed checker it is still to be tried.
- **Docker needs a second try on every fresh Ubuntu server** (all three runs). The proofs' setup
  hides why the first fails; the demo's retry works and says nothing either. Harmless here, but
  the read-only proof's own container step may be quietly skipped the same way.
  **Why, seen on the four-day run (2026-11-10):** fetching from `mirrors.linode.com` over IPv6
  timed out ("containerd ... Connection timed out [IP: 2600:..."), and that time the retry failed
  too, on all three. The demo's retry now asks over IPv4 with three tries; the proofs' setup
  should do the same.
- **Proven at the four-day run's end (2026-11-14):** the journal command #182 prints,
  `sudo journalctl _SYSTEMD_USER_UNIT=compromise-checker.service + USER_UNIT=compromise-checker.service`,
  showed the daily check's output on the checker's server.
- **`status` offers a hands-on item the run never reached** (four-day run, 2026-11-14). Its list
  says "Known threats, Manage: put the stopped threat update back (the story's day 6)", but a
  stay shorter than the story never plays day 5, so nothing is stopped and there is no "Stopped by
  hand" section. Fix: print each hands-on item only when the days it needs were played (or say
  which day it needs). **Fixed (D.5, #184):** each item carries the day it needs. The list holds
  what the days played so far allow, then "from day N" for later days of this stay, then what this
  stay never reaches.
- **The demo checker's pages carry two red notes** (four-day run, 2026-11-14): "This machine still
  lets people log in over SSH with a password" and "An update to this machine is waiting for a
  restart". Both are true of a fresh Linode and both are on every page a demo shows. Fix in `up`:
  turn password logins off on the checker's server and restart it after the install, before the
  first check. **Fixed (D.5, #184):** the install line adds `--ssh-passwords-off` (the
  installer's own flag; root's key login counts). `settle` waits for Ubuntu's update runs,
  restarts the server if an update asks (at most twice, the restart known by a new boot id), runs
  the status service, and prints a WARN for whatever the pages will still say. It never stops
  `up`: a note on a page isn't worth the servers. `up` then makes a fresh first-account link, since
  the restart eats into the install's hour. During a stay of days, Ubuntu's updates go on and the
  restart note can come back: `status` says so. Unproven on a server until the next `up`.
- **`status` exits non-zero while a demo is up and fine** (2026-11-14). Not a fault: it ends 1
  when a story step failed (day 3's container step had). **Fixed (D.5):** it now says which reason
  it ends 1 for.

- **Setup leftovers made two servers read worse than the story says** (browsing the saved four-day
  dataset, 2026-11-14). (1) The proofs' audit rules are loaded with `auditctl` alone: Ubuntu's
  automatic update restarted auditd on staging-1 and dropped them, so every later check reported
  "audit rules were removed and not loaded again" (high). (2) On Rocky, the setup's Podman
  container sleeps two hours and exits, taking its firewall rules with it: mail-1 read "firewall
  rules removed" from day 1. (3) The setup puts nginx, PHP-FPM and a site with planted PHP settings
  on every server, so mail-1 read as a web server open to PHP2Shell. **Fixed (D.5):** right after
  the setup, before the first check, `story.KEEP` saves the rules in `/etc/audit/rules.d/` and
  replaces the container with one that runs for good and comes back at boot; `story.NOT_WEB` takes
  the web stack and the planted site off every server not in the web group. Unproven on a server
  until the next `up`.
- **staging-1 still reads high after an ordinary PAM update, and honestly** (#185): the checker
  can't tell Ubuntu's update of PAM's modules from a swapped module using the server's own records
  (#186 reverted, #188 closed; the fix is #189, off the server). Until then a demo's "clean" server
  is mail-1 or db-1, not an Ubuntu server that took a PAM update.

## Keep-alive as built (D.4, 2026-11-10)

`up --days N` (1 to 14). Day 0 is played from the laptop, as in one sitting. Each later day is one
timer on the **checker's** server, 45 minutes before the checker's own daily check, which plays
that day's steps as the laptop would: a root login to the fleet server from the checker's address
and the step's script, or the admin's own commands. A day the story doesn't check (day 5, whose
point is the note the next check clears) runs an hour after the daily check instead. Story day
*d* is real day *d*; with fewer days than the story, `up` says which steps it left out.

- **Not timers on the fleet servers, which the plan above proposed.** The checker reports a new
  timer as a finding, so each server would have shown one that is no part of the story. Driven from
  the checker's server, a fleet server's data is the same as in one sitting.
- **What that costs:** for the length of the stay the checker's server holds, readable by root
  only, a key that root on every fleet server accepts (from the checker's address only), and the
  keys of the two accounts the story logs in as. Each account's key is deleted when used; the
  root key when the last day has run. The fleet is throwaway, weakened on purpose, and closed to
  everything but the checker's server, which already holds a key with sudo on each.
- **The root key is put on each fleet server before its first check,** so it is part of what the
  server starts with and never shows as a change.
- `status` asks the checker's server how each day's steps went.
- The admin's rule for `mail-1` lasts through the date of day 5's check, so day 6's shows it run
  out (in one sitting: the day after `up`).
- **Played a day apart, two scripts differ from one sitting's:** what the break-in leaves running
  lasts weeks, not the proofs' hour or two, so it is still there at the next day's check and only
  what the intruder removes goes; and the PHP update fetches the package lists first.
- **Nothing waits for ever:** each step has a 25-minute limit and each day 40; the keys go when
  the last day ends, however it ends.
- `status` says of each step "done", what failed, "not yet", or LATE (its time passed an hour ago
  and it has said nothing), and ends 1 for a failure or a late step.
- **The end:** `up` says the cost first and, once the daily check is set, when the last day is
  checked: `down` is for after that. The servers' tags end the day after `--days` days (dates in
  UTC), since the last check can fall on it. `status` says OVERDUE; any proof's sweep and the next
  `up` delete demo servers past their date. The session that starts a stay puts a reminder in
  John's calendar for after the last check.
- **The privacy proof** runs at the end of day 0. After John signs in from the laptop the web
  interface holds his address by design; D.5's `save` leaves that out.

## Save as built (D.5, first part, 2026-11-12)

`demo.py save DIR` copies the checker's data to a new folder outside any repository. It needs no
Linode token and changes nothing on the servers, so it can be run during a stay and again at the
end.

- **What comes down:** the store, the stored evidence and the key it is read with, the settings,
  the servers' list and their host keys, the threat updates, the whitelists, proposals and
  reports. They are named in `demo.py`; a file the checker starts keeping later isn't copied until
  it is added there.
- **What stays on the server:** the accounts, their sessions and failed sign-ins, and every key
  but the evidence's: the one that logs in to the fleet, the web interface's secrets, the mail
  key.
- **The Activity page and the Checks page's list are kept, with the address replaced** (John,
  2026-11-12). Both live in `web.db` with the address each row came from, which is the laptop's.
  The server copies those two tables and no other, putting "(not kept)" where each address was,
  before anything is sent. On the laptop the rows go into a new accounts database, made by the
  checker's own code with no account in it. A row that still held an address would stop the
  save, and the record is searched for the laptop's address like everything else.
- **The account's name is in the data.** The store's own record of each collection says who
  started it, so a check or a decision made at the pages carries the name of the account that
  made it.
- **A whole copy.** The checker's lock is held while it copies, so no check or purge runs
  meanwhile, and one under way stops the save instead. The store is read through SQLite's own
  backup. During a stay, `save` refuses from an hour before the daily check to an hour and
  three quarters after it, and for the first five minutes after the last day's (its timer may
  fire a little late), so a day's check never finds the lock taken.
- **Three things are changed in the copy, and `DIR/demo.json` says so.** The store names each
  collection by its whole path, which was the server's: each becomes the saved file's, or no page
  on the laptop could open one. The settings' path to the evidence key, likewise. And whatever in
  the settings could run a command or send anything from the laptop is put back to what a new
  checker starts with: the notification command, the advisor, where threat updates come from,
  the check for new releases. So a saved folder names its own place and can't be moved.
- **Nothing is taken on trust from the server:** only ordinary files, only the names asked for,
  each once, no more than 2 GB and no longer than an hour; a store that names a file outside the
  saved ones, or a list of servers with a login that isn't the demo's key, stops the save.
- **The proof.** The folder is put together as `DIR.part` and becomes `DIR` only when every
  collection, sealed file and sealed value in it opens with the saved key and none holds this
  machine's address: the files, the store row by row, the evidence. Otherwise it stays as
  `DIR.part` and says what was found. The address is the one the checker's server sees the
  laptop come from at that moment, in the ways it can be written; one the laptop had on another
  day or network isn't looked for.
- **`down` waits for it:** with a checker up whose data was never saved, was saved before the
  last day's check left a collection, or is no longer where it was saved, `down` says so and
  stops. `down --unsaved` deletes anyway. A failed `up` still deletes what it made without asking.

Done since: the saved dataset browsed on the laptop (2026-11-14), `screenshots.py --dataset`
working on a throwaway copy of it, and `demo_fleet.py` retired (#191). Left in D.5: the README's
pictures, below.

## The README's pictures (D.5, last part)

Taken from the five-day run that started 2026-11-14, the first with the setup leftovers fixed
(#190), so mail-1 and staging-1 read only what the story did to them. Its last check is Thursday
2026-11-19 at 9 PM PST (2026-11-20 05:00 UTC).

| Picture | Page | Used in | What it should show |
|---|---|---|---|
| `fleet.png` | `/`, whole page | README, top | the end of the story: shop-web-1 broken into, shop-web-2 fixed, db-1's routine work accepted, mail-1 clean, app-1 stale, old-box never answered |
| `fleet-dark.png` | `/`, whole page, dark | nowhere yet | the same, for the site and talks |
| `fleet-phone.png` | `/`, top, 390 wide | nowhere yet | the same at phone width, no sideways scroll |
| `host.png` | `/hosts/shop-web-1`, top | docs/web.md | the break-in, in plain words |
| `evidence.png` | `/hosts/shop-web-1/evidence`, top | docs/web.md | the excerpts behind it |
| `threats.png` | `/threats`, whole page | docs/web.md | dotnet-2026-10 retired: day 5, which no earlier run reached |

Whatever is done on the pages before the save shows in the pictures, so a hands-on item that
changes the end (adding staging-1 back, putting the threat update back) goes before Thursday's
last check or after the save, not in between.

Thursday, from 9:05 PM PST (save holds off five minutes after the last check), in the usual
folder on dev:

1. `demo.py status`: every day played, no warnings on the pages.
2. `demo.py save ~/demo-saves/run-<id>` and again to `~/demo-saves/run-<id>-backup`.
3. `screenshots.py --dataset ~/demo-saves/run-<id>-backup --out docs/screenshots`: every page
   `ok` with no overflow and no page errors.
4. Look at all six before they go in: the demo banner on each; no evidence-key reminder (the
   script says the key is backed up, in its copy only); no red banner for password logins or a
   pending restart (#184); no "Settings have changed since this result" line (see below).
5. `demo.py down`, then `status` clean; the pictures go in as one PR.

**Found 2026-11-15, on the four-day dataset:** every server read "Settings have changed since
this result". The whitelist's digest (`checker/whitelist.py`, `Placed.as_dict`) held each rule
file's full path, and the copy's files are in another folder from the server's, so every stored
result looked scored against another whitelist. `screenshots.py` now runs `checker analyze --all`
in its copy first: the same evidence and rules, worked out again, scores unchanged. The digest
itself is fixed in its own PR, since a restored or moved checker home showed the same; the five-day
run's server still stores the old form, so the script's step stays needed for its data.
