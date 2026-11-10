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

    demo.py up [--days N] [--build]   # make the checker's server and the fleet, play the story
    demo.py status                    # what is up, since when, what it has cost, when it ends
    demo.py save DIR                  # copy the checker's data down, as the demo dataset
    demo.py down                      # save, then delete every server

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
  has real dates. The steps that happen on a fleet server are put there as timers when it is made,
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
- **Cost:** six Nanodes are about $1.10 a day. One sitting is a few cents; a week is about $8.
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
- **D.4 Keep-alive.** `--days`, timers on the servers, `status`, the end date and the sweep. Proved
  by a two-day run.
- **D.5 The dataset.** `save`, browsing it on the laptop, the screenshot script moved onto it, and
  `demo_fleet.py` retired. The README's pictures taken again.
- **D.6 The advisor and viewers,** as decided in 1 and 2.
