# The report

`checker report HOST` (or `--all`) writes one self-contained HTML file for
the hosts' latest bundles (or `--bundle ID`, which must be that host's and
usable), from each one's latest assessment. If a bundle has no assessment,
or one made by older checks, an older event parser or an older snapshot
version (its evidence points into one parse of the bundle), it is analysed
first.

## What it holds

- **A confidential banner** on every page, and the notes every reader needs:
  - the probability of compromise is an estimate, shown with a band, and is
    read beside the coverage ([scoring](scoring.md));
  - no findings is not proof of a clean server;
  - a high band is a reason to investigate, not proof of an intrusion.
- **Summary:** each host's probability of compromise and band, its
  critical, high, medium and low compromise indicators, hygiene and
  exposure counts, and coverage gaps.
- **Each host:**
  - its probability of compromise, band and prior (and where the prior
    came from), the hygiene and exposure rating, and the contributors:
    each finding's likelihood ratio and share of the score, largest first,
    and whether a cap cut it. A stored assessment scored from another
    prior than the host's current one is scored again from its stored
    findings (the checks don't run again) and kept as a new assessment;
  - its compromise indicators, most serious first (informational ones
    folded away);
  - its exposure and hygiene findings, in a section of their own (DESIGN.md
    §2 principle 9);
  - a timeline of the logged events behind the findings (past 300, the
    first 100 and the last 200, with a note of how many are left out:
    the earliest are often the first signs), with each threat pack's
    window and the host's exposure in it marked (from, and until, "at the
    latest" where only the fix's last install time is known);
  - its coverage: each log's reach, the gaps, and the checks that didn't run.
  
  Each finding shows up to five excerpts of its evidence: the log line, the
  snapshot item, the change since the baseline (added, removed, or field by
  field before → after), or the running process.
- **Appendix:**
  - each bundle's collection details: times, status, the collector's
    version and hash, the content's and the encrypted file's sizes and
    SHA-256, the host facts, the modules, the masking version;
  - the analysis's time and checks version;
  - the full chain of custody;
  - each host's suppressed findings, with the rule, layer, reason and
    owner that suppressed them, the whitelist's hash, and any expired rules
    ([whitelists](whitelists.md)).

## Host text is untrusted

File names, log lines and command lines came from the hosts, and an intruder
may have chosen them. The report:

- **HTML-escapes everything.** Jinja2's autoescaping covers the whole
  template.
- **Passes every value through one filter.** Jinja's `finalize` runs the
  visible-character filter on every value the template prints, whether or
  not the template asks for it.
- **Shows invisible characters as escapes.** These include controls,
  formats (bidirectional overrides, zero-width characters), private use,
  surrogates, unassigned characters, combining and enclosing marks, line and
  paragraph separators, every space but the plain one, and the letters that
  display as blanks (Hangul fillers, the braille blank). Characters past
  U+FFFF become `\U000e0080`.

  So a right-to-left override (written here as its escape, `\u202e`) can't
  make a file name display as another, an overlay can't strike a name
  through, and nothing can hide in a name.
- **Doubles the host's own backslash.** A host can't fake an escape.
- **Cuts long text** by what is shown, never inside an escape.
- **Doesn't catch look-alike letters.** A Cyrillic "о" in "rооt" isn't
  escaped. The collector flags non-ASCII file names (`name_flags`).
- **Has no scripts and loads nothing.** A Content-Security-Policy of
  `default-src 'none'` forbids all loading, so even an escaping mistake
  couldn't load a script, an image or a font. The file opens the same
  offline.

## Where it goes

- **Encrypted.** The report is encrypted to the evidence key, as the
  evidence is (`report-HOST-TIME.html.age`). `checker report --open [FILE]`
  (the newest by default) shows it without writing it anywhere in plain:
  it decrypts it in memory and serves it to your browser from this
  machine only (127.0.0.1), at an address no one can guess, never to be
  cached, until you press Enter. Sandboxed browsers (snap, Flatpak) can
  show it too. With no screen (over SSH), it prints the address and the
  `ssh -L` line that shows it on your own machine; with no terminal, it is
  shown for ten minutes. A plain report opens without the evidence key.
  The browser's history keeps the address, not the report.
- **Plain, on purpose.** `--plain` writes plain HTML, to hand a report to
  someone; it says so, and the file is yours to protect and delete.
- **Location.** By default the report goes to `reports/` in the checker's
  home (a directory only its owner can open). `--output` writes it anywhere
  else (its name must end in `.html.age`, or, with `--plain`, must not end
  in `.age`).
- **Written whole, then moved into place.** The report is written to an
  owner-only temporary file beside its destination and then moved there,
  so:
  - a crash leaves any earlier file intact;
  - a symbolic link at the path is replaced, not followed;
  - no one holding the old file open can read the new report.
  
  The `reports/` directory is made owner-only, also when it already
  existed.
- **Custody.** Each bundle in the report gets a `reported` entry in its
  chain of custody, with the SHA-256 of the file as written and whether it
  is encrypted.

Reports are confidential (policy §8): they describe weaknesses an attacker
could use, and they repeat much of the evidence: file names, log lines,
command lines (already masked). Encryption keeps a copy of the reports
folder (a backup, a synced folder, a disk image) from being read without
the evidence key; it doesn't keep them from someone who can log in as you
where that key is. Reports written before encryption, and plain ones, are
not encrypted: keep them out of backups and synced folders, and delete
them when they have been read. `checker purge` deletes the reports in the
reports folder that show a purged bundle; a report written elsewhere with
`--output` is yours to delete ([retention](retention.md)).

## The fleet at a glance

`checker fleet [--group GROUP]` lists every host, most worrying first:

1. hosts whose stored analysis can't be read: it says why (doesn't match its recorded hash,
   file missing, damaged), and what the last readable analysis said, never as the current
   result. A store that can't answer, or a key that opens nothing, is one error for the whole
   fleet, not a claim about each host;
2. Critical, then High;
3. hosts with no result to go on, and Elevated or Low results that can't be relied on: the
   last collection failed or was partial, a newer one isn't analysed yet, a check couldn't
   run, it can see less than before, the whitelist or threat packs have changed (so a report
   might now say something worse), or it is old. Old means over 3 days:
   `checker config set stale_after_days N` if you check less often than daily, or every host
   will say so;
4. Elevated, then Low, those with high or critical findings first. Hygiene and exposure
   findings don't move the band, so this keeps them from hiding under a low score.

A newer version of the tool's checks is said, but doesn't move hosts up: an upgrade shouldn't
alarm the whole fleet. High and Critical never move down, and a doubt under one says "may
have changed since", not that it can be ignored.

For each host it shows the band and probability, threat packs it was exposed to, coverage
gaps, and what changed since the analysis before. High and critical findings that went away
are told apart: no longer found, now suppressed by a whitelist, or not seen. "No longer found"
is said only between two whole collections, by the same checks, with nothing failed and no
new gap: wiped logs make findings disappear too. An exposure known before stays listed when
later listings can't judge it, looking back up to 30 analyses.

It reads what is stored, and collects, analyses and writes nothing: the database is opened
read-only, and it doesn't adopt a newer key list or retire packs, which is left to runs. For
the same reason it can't repair a store: after an interrupted run it says which command does.

A host's whole evidence being purged is said only while it is in the inventory. A host
removed from the inventory stays listed while it has bundles, under any group filter, and
says how to purge it.
