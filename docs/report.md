# The report

`checker report HOST` (or `--all`) writes one self-contained HTML file for
the hosts' latest bundles (or `--bundle ID`), from each one's latest
assessment. If a bundle has no assessment, or one made by older checks,
it is analysed first.

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
  - a timeline of the logged events behind the findings;
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
- **Shows invisible characters.** Control, format and other invisible
  characters become visible escapes, such as `‮`. A right-to-left
  override can't make `evil‮gnp.exe` display as `evilexe.png`, and a
  zero-width space can't hide in a name.
- **Cuts long text.**
- **Has no scripts and loads nothing.** A Content-Security-Policy of
  `default-src 'none'` forbids all loading, so even an escaping mistake
  couldn't load a script, an image or a font. The file opens the same
  offline.

## Where it goes

- **Location.** By default the report goes to `reports/` in the checker's
  home (a directory only its owner can open). `--output` writes it anywhere
  else.
- **Owner-only.** The file is created that way, and an existing file it
  replaces is made so.
- **Custody.** Each bundle in the report gets a `reported` entry in its
  chain of custody, with the report's SHA-256.

Reports are confidential (policy §8): they describe weaknesses an attacker
could use, and they repeat much of the evidence: file names, log lines,
command lines (already masked). The report file itself is not encrypted, so
keep the reports folder out of backups and synced folders, and delete
reports you no longer need. Deleting them after the retention period is
part of `purge`, still to come.
