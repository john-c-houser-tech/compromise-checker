# The report

`checker report HOST` (or `--all`) writes one self-contained HTML file for
the hosts' latest bundles (or `--bundle ID`, which must be that host's and
usable), from each one's latest assessment. If a bundle has no assessment,
or one made by older checks, an older event parser or an older snapshot
version (its evidence points into one parse of the bundle), it is analysed
first.

## What it holds

- **A confidential banner** on every page, and the notes every reader needs:
  - it shows findings and bands only (a scored probability comes in Phase 2);
  - no findings is not proof of a clean server;
  - a high band is a reason to investigate, not proof of an intrusion.
- **Summary:** each host's high, medium and low compromise indicators,
  hygiene and exposure counts, and coverage gaps.
- **Each host:**
  - its compromise indicators, most serious first (informational ones
    folded away);
  - its exposure and hygiene findings, in a section of their own (DESIGN.md
    §2 principle 9);
  - a timeline of the logged events behind the findings (past 300, the
    first 100 and the last 200, with a note of how many are left out:
    the earliest are often the first signs);
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
  - suppressed findings (none until whitelists exist).

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

- **Location.** By default the report goes to `reports/` in the checker's
  home (a directory only its owner can open). `--output` writes it anywhere
  else.
- **Written whole, then moved into place.** The report is written to an
  owner-only temporary file beside its destination and then moved there,
  so:
  - a crash leaves any earlier file intact;
  - a symbolic link at the path is replaced, not followed;
  - no one holding the old file open can read the new report.
  
  The `reports/` directory is made owner-only, also when it already
  existed.
- **Custody.** Each bundle in the report gets a `reported` entry in its
  chain of custody, with the report's SHA-256.

Reports are confidential (policy §8): they describe weaknesses an attacker
could use, and they repeat much of the evidence: file names, log lines,
command lines (already masked). The report file itself is not encrypted, so
keep the reports folder out of backups and synced folders, and delete
reports you no longer need. `checker purge` deletes the reports in the
reports folder that show a purged bundle; a report written elsewhere with
`--output` is yours to delete ([retention](retention.md)).
