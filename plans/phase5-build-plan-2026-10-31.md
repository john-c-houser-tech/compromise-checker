# Phase 5 build plan — 2026-10-31

> **Status: DRAFT 1, 2026-10-31.** Order set by John: the web interface and fleet
> view first, then PDF and JSON, then actions and PostgreSQL. All of it is in this
> phase: John plans to finish the application within days (2026-10-31). All decisions (W1 to
> W5) settled. Nothing built yet.

**Goal (DESIGN.md §13, §14, §18):** a person can see a whole fleet in a browser,
most worrying first, with what changed since the last run, and go from any host
down to the evidence behind a finding. It also has to give real screenshots for
marketing, taken from what the tool really produced, so the page is built to be
looked at, not only to be correct.

**Who it is for (John, 2026-10-31):** small organizations and businesses that can't
afford commercial security products, and mostly won't work on a command line. So the
browser is the product for them, not a view on top of the real tool: everything they
need is reachable there, and the pages explain themselves in plain words, including
what to do next. Comprehensive, easy installation follows later (see the end).

**Done means:**
1. **Fleet page.** Every host, sorted by probability of compromise, with its band,
   coverage, exposure to packs in force, and changes since the previous run.
2. **Host page.** What the report holds: score and contributors, findings, exposure
   and hygiene apart, timeline with each pack's window, coverage. The notes every
   reader needs stay on every page: an estimate, not proof; no findings isn't a
   clean server.
3. **Evidence.** From a finding to its excerpts, decrypted for that request only.
4. **Hostile text is harmless.** Log lines come from possibly compromised servers,
   and now reach a logged-in browser. A planted string in every field a host can
   influence does nothing, shown by a test that fails if escaping is removed.
5. **Looking changes nothing.** Viewing pages open the store read-only. Only the
   action routes of stage 3 can write, each one recorded with who did it (W1).
6. **Screenshots.** A script takes them from a demo fleet, so they can be taken
   again after any change, and no real server's data can appear in them (W4).
7. **PDF and JSON** reports (DESIGN.md §13).
8. **Actions:** every job a small organization needs can be done from a page, from
   first setup through adding a server to acting on a finding, with no command line.
9. **PostgreSQL**, with accounts and roles for a team sharing one store.

## Ground rules

- **The same numbers as the report.** Pages read through the code the report uses,
  so a page and a report can't disagree. The report's `host_report` and `visible`
  are the starting point, moved out of the report where pages need them.
- **Nothing leaves the machine.** No CDN, font service or analytics. A strict
  content security policy is sent on every page and tested. Charts are drawn on the
  server as inline SVG.
- **`checker report --open` already sets the standard:** 127.0.0.1, Host checked,
  `no-store`, its CSP as a header, nothing decrypted to disk. The web interface
  keeps all of it.
- **Policy first:** wording for the web interface goes to John before its PR is
  ready (§8 how evidence is stored, §12 security of the tool).
- **The usual reviews:** agent review, then Copilot, on every code PR. Pages get
  looked at in a real browser, at phone width as well, in light and dark.

## Pull requests

### Stage 1: the web interface and screenshots

**5.1 The fleet's numbers.** `checker/fleet.py`: each host's latest assessment,
the one before it, and what changed between them, with no web code. Also
`checker fleet` on the command line, which is useful alone and tests the logic.

**5.2 The server.** `checker web`: read-only, with accounts (passwords hashed, login
throttled, first account made through a one-time setup link), headers and hostile-text tests in place before any page shows evidence (W2, W3).

**5.3 Fleet page.** Sorted list, filters by group and band in the URL, changes since
the last run, and a clear view of the states that matter: never collected, a failed
last run, an old collection, coverage gaps.

**5.4 Host page.** Score, contributors, findings, exposure and hygiene, coverage.

**5.5 Evidence and timeline.** Excerpts per finding, the timeline with pack windows,
the appendix (suppressed findings and their rules, manifest, hashes, custody).
Measure page times on a large bundle here: if a parse takes seconds, keep the parsed
result in memory only, for a short time, and say so in the policy wording.

**5.6 Packs and advisor.** Packs in force and which hosts each one touches; stored
advisor output, labelled as AI's, as in the report.

**5.7 Demo fleet and screenshots.** The fleet (W4), the screenshot script, and images
in the README and `docs/`. Getting them onto the NouriLoop site is a separate PR
there, after John picks them.

Before the shots are taken: John reads `checker/web/finding_words.py`, the advice owners
will act on and the images will show (only checked against the code so far), and the USPTO
search on the name is done.

### Stage 2: other formats

**5.8 PDF.** From the report's HTML with WeasyPrint, as an optional extra because of
its native libraries. Hostile text again: no remote fetches while rendering.

**5.9 JSON.** A versioned, documented schema for SIEMs and tickets, with the same
findings and the same masking as the report.

### Stage 3: actions

Added once the read-only pages and their tests are in, so each action is reviewed
on top of something already proved safe.

**5.10 Action groundwork.** A separate write path: POST only, CSRF tokens, a fresh
confirmation for anything that changes what later findings mean, and each action in
an append-only record. Who viewed which evidence pages goes in it too, since the command
line records views in the chain of custody and pages, being read-only, can't.

**5.10a Two-factor login (John, 2026-10-31).** Authenticator-app codes through `django-otp`, as in
Auditor, with one-time recovery codes, since a small business has no help desk when a phone is lost.
Required whenever the server can be reached from another machine; optional but strongly prompted on
one only this machine can reach. It comes before any page that can act.

**5.11 Run.** Start a collection or analysis, and watch it. The server needs SSH
credentials for this, which the viewing pages never touch: agent and password prompts
have to work without a terminal.

**5.12 Decide.** Accept a baseline with its reason, and approve or refuse the advisor's
whitelist proposals. These can hide a real change, so each shows what it would
suppress, as `checker whitelist test` does, before it can be confirmed.

**5.13 Manage.** Hosts, groups, trust of a new host key (shown for checking, never
accepted blind), packs, settings, scheduled checks, purge.

**5.13b First setup and adding a server.** A guided path for someone who has never
done this: create the keys and settings the policy's choices depend on (`checker
init`'s questions in plain words, including the AI advisor), then for each server what
to set up there (the scanner account and its one sudo rule) and a check that it worked.
Reminds them to back up the evidence key, without which stored evidence can't be read.

### Stage 4: a shared store

**5.14 PostgreSQL.** The store behind one interface, with its append-only triggers,
custody and purges proved to hold there as they do on SQLite.

**5.15 Accounts and roles.** Login, roles (who may view, who may act), and the action
record naming a person, not a machine. Reaching it from another machine comes with this.

## Decisions to settle (one at a time)

- **W1. Read-only, or can it act? DECIDED (John, 2026-10-31): both, in this phase.**
  Read-only pages first, since the actions build on them; actions in stage 3.
- **W2. Who can log in, and from where? DECIDED (John, 2026-10-31): real accounts from
  the first page**, so there is one login to build and review, not a token replaced by
  accounts days later. The first account is made through a one-time setup link, and a single operator
  simply has one. It listens on 127.0.0.1 by default (loopback is open to every local
  user on a shared management host, so login still matters); at John's desk it sits
  behind Caddy at `https://checker.localhost:8443`. Reaching it from another machine
  is a setting that refuses to start without TLS. Roles are added at 5.15.
- **W3. What is it built with? DECIDED (John, 2026-10-31): Django and Jinja2 templates
  or Django's own (settled at 5.2), as an optional `web` extra,** with little or no
  JavaScript. It brings tested login, password hashing, sessions, CSRF protection and
  roles, and `django-otp` for two-factor login, as in Auditor. Its database layer manages
  accounts and sessions only: the evidence store keeps its own code, triggers and custody.
  Login throttling is added either way.
- **W4. Where does the demo fleet's data come from? DECIDED (John, 2026-10-31): a real
  run, under the $10 cap.**
  About eight throwaway Linodes for a few cents, near the end of stage 1: some clean, some
  taken through the detection proof's behaviours, some on a pinned vulnerable PHP.
  Then scrub it with the golden tests' scrubber (its hard check that no public address
  survives also keeps John's home address out) and rename the hosts. Screenshots then
  show what the tool really found, and are labelled as a demo fleet. Golden cases hold
  parsed results, so they can't show everything the pages do, and a hand-made fleet
  would be a mock-up.
- **W5. What name goes in the screenshots? DECIDED (John, 2026-10-31): Compromise
  Checker**, and it stays configurable in every page. A USPTO search runs before 5.7
  (not done yet). Pages carry a plain tagline, since a small business owner may not
  read "compromise" as "hacked". Whether it gets its own domain is for later: the aim
  now is building the NouriLoop business.

## Not known yet

- How long a page takes on a large bundle (5.5).
- Whether the golden scrubber handles whole bundles or needs extending, since it was
  written for parsed cases (5.7). The check that no public address survives stays
  either way.

## After Phase 5: installation

John (2026-10-31): really comprehensive and easy installation options, for people who
won't use a command line. Its own plan, after Phase 5. The web interface shouldn't assume
a person typed anything: 5.2's first account must be possible from a page, using a
one-time setup link, so an installer can hand over to it.
