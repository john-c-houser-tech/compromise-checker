# The demo's story, and what it reaches (D.1, 2026-11-10)

Step D.1 of [the demo fleet plan](demo-fleet-plan-2026-11-10.md): the story the fleet plays, and
which pages and states of the web interface it produces. Made from a reading of every page,
template and message in `checker/web/` against the staged behaviours the proofs already have.
Nothing here has been run: where a result depends on something not yet checked on a real server,
it says so, and D.2 and D.3 settle those first.

## The fleet

| Server | Group | System | Its part |
|---|---|---|---|
| `shop-web-1` | web | Ubuntu 24.04 | broken into on day 3; the attacker tidies up a little on day 4 |
| `shop-web-2` | web | Ubuntu 24.04 | open to PHP2Shell from the start; fixed in two stages |
| `db-1` | database | Rocky 9 | routine admin work that looks alarming until it is accepted |
| `mail-1` | mail | Ubuntu 24.04 | nothing happens: the server that earns "No strong signs" |
| `app-1` | web | Rocky 9 | clean, then can't be reached from day 3, and goes stale |
| `staging-1` | none | Ubuntu 24.04 | clean; taken off the list on day 4, and its Linode deleted |
| `old-box` | none | none | never a real server: an address nothing answers at |

Seven Linodes with the checker's own (the plan said six): about $1.30 a day, less after day 4.

## The story

Each day's check is the checker's own daily schedule. "Admin" is what the script does through the
checker's commands on its server, as a person would through the pages.

| Day | On the servers | Admin | What the pages then show |
|---|---|---|---|
| 0 | all made; `shop-web-2` gets the vulnerable PHP | adds the servers, confirms their keys, pulls the threat updates, runs the first check, sets the daily check | first checks ("changes will show from the next one"); `shop-web-2` open to a known threat now; `old-box` "every check has failed so far"; four threat updates in use |
| 1 | `db-1`: an admin adds a deploy account with sudo rights and a nightly job, and updates packages | none | `db-1` with warning signs, new since the last check |
| 2 | `shop-web-2`: PHP updated, its service not restarted | accepts `db-1`'s changes as its baseline, with a reason | `db-1` calm again, the acceptance on its evidence page and in Activity; `shop-web-2` "fix installed, but old code may still be running" |
| 3 | `shop-web-1`: the break-in (the detection proof's behaviours: second root account, root key, web shell used, cron and timer, preload, reverse shell, tunnel, logging and audit turned down). `shop-web-2`: service restarted. `app-1`: its firewall starts refusing the checker | none | `shop-web-1` "Strong signs of a break-in", its findings, evidence and timeline; `shop-web-2` "was open while it was active, fixed now"; `app-1` "the last check didn't finish" |
| 4 | `shop-web-1`: the web shell and the cron job are removed | takes `staging-1` off the list; writes a rule for `mail-1`'s backup job that expires on day 6 | `shop-web-1` "serious warnings from before no longer found: someone removing what they left behind looks the same"; `staging-1` "no longer being checked"; a finding hidden by the list of accepted activity |
| 5 | none | stops using one threat update by hand, with a reason | every server "the threat updates have changed since this result"; the update under "Stopped by hand", with "Put it back" |
| 6 | none | puts the threat update back | `app-1` "hasn't been checked recently"; `mail-1` "settings have changed since this result" (its rule expired) |
| 7 | none | `down`: the data is saved and every server deleted | |

Played in one sitting (no `--days`), the same steps run minutes apart. What that can't show is
listed under "Needs real days" below.

## What it reaches

**Servers page.** All four headlines but one at a time, as the story moves ("needs attention now"
from day 3). Every count: Strong signs, Need a closer look, Warning signs, No strong signs, No
longer checked. Filters by group and by result. "New since the last check" lines. The meter and
"No estimate". The evidence-key banner (until John says it's backed up).

**One server.** Each severity; new-since-last-check; the four sections; "for information" folds;
hidden findings; "what the check couldn't see"; a known threat making a finding more serious
(`shop-web-1` is in PHP2Shell's window only if it too runs the old PHP: see "To settle").

**Evidence.** Excerpts per finding, the order of events with the threat's marks, hidden findings
with their rule, the custody list with accepted-from-the-web entries.

**Known threats.** Four updates; servers under "open now", "fix installed, old code may still be
running", "were open, fixed now", "no sign of exposure", "can't be relied on right now", "no longer
on your list", "not checked for this threat yet" (between a pull and the next check); a retired
update and its return.

**Decide.** The baseline half in full: what accepting would hide, the refusal on a worrying server
(`shop-web-1`), "the latest check already is the baseline". The rules half shows "None waiting"
until the advisor is on (D.6).

**Activity, Checks, Manage.** Filled by the story's own actions. The check list has the daily runs
only if they are started from the pages; the schedule's runs don't appear there. So `up` starts
day 0's check from the page's own command, and the rest is John's to add while it is up.

## Needs real days

Only `--days` shows these: "checked N days ago"; "hasn't been checked recently" (3 days); logs that
"go back N days" instead of "less than a day, which can mean they were cleared", a note every
freshly made server carries on its first day; a rule expiring; an invitation link that "ran out"
(24 hours). In one sitting, days 5 and 6 lose their effect and the rest holds.

## Yours to do while it is up

The states that come from using the interface, not from a server. A list to work through, which
`status` prints:

- Start a check; start a second while it runs ("another check was already running"); stop one.
- A check of a server whose key is refused or whose sudo rule is missing (`app-1` after day 3):
  the "what to look at" list and "what to set up" link.
- Ask a server for its key again; paste a wrong fingerprint.
- Invite a view-only person, sign in as them in a private window, try what needs full access.
- Settings, each field's refusals. The daily check's page. Delete stored evidence: one server's,
  and before a date. Add `staging-1` back under its old name ("the same server as the earlier
  results").
- Sign-in security: change password, recovery codes, wrong codes.
- Light, dark, and a phone's width, on each page.

## What no story reaches

- **First setup's six steps**, since the script sets the checker up. `up --bare` makes the
  checker's server and one fresh server and stops, for walking first setup by hand.
- **The AI advisor's explanation, steps and proposed rules:** D.6.
- **A newer version to update to**, and the update's outcomes: only when a release newer than the
  installed one is published. `up --release 0.1.1` would show "0.1.2 is available" and a real
  update.
- **Damage:** a result that can't be read, a threat update that fails its signature, a lost
  evidence key, a full disk. Each needs something broken on purpose on the checker's server; left
  out, and proposable later one at a time.
- **A threat update withdrawn by its publisher,** or one whose signing key is retired.
- **Checks no staged behaviour triggers** (about half of them: guessed passwords, logins at odd
  hours, miners, hidden processes, kernel faults, clock jumps and others). The story uses what the
  detection proof already proves. New behaviours are a separate piece of work each.

## To settle on real servers first (D.2, D.3)

- Whether the installed checker's web service can set the daily check from its page, or only its
  command can.
- Whether a server that is only open to a threat, and otherwise clean, reads "Open to a known
  threat" or rises to "Some warning signs".
- Whether `mail-1` earns the green "No strong signs" on day 0 or only once its logs span a day.
- Whether `db-1`'s routine work lands at "Some warning signs" and not higher; if higher, the story
  says so honestly (a new sudo account is alarming) and the acceptance is refused until looked at.
- Whether `shop-web-1` should also start on the old PHP, so the break-in falls inside PHP2Shell's
  window and the pack raises its findings.
- What a check stopped part-way leaves behind.
