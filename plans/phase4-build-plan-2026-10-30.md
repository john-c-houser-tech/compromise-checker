# Phase 4 build plan — 2026-10-30

> **Status: DRAFT 2, 2026-10-30** — every decision settled (D1–D7).
> Restructured the same day (John): pack drafting moved out of the tool
> into a separate pack application in its own repository, with its own
> plan after Phase 4 (see "After Phase 4"). Nothing built yet.

**Goal (DESIGN.md §18, Phase 4):** when a new threat is published, an
organization can check its whole fleet against it within a day, from the
evidence it already holds where that evidence is enough. A threat pack, a
small signed file published apart from the tool, says which package
versions are vulnerable and fixed on each distribution, when the threat
was active in the wild, what settings reduce exposure, what to look for on
a host, and what to do. The tool verifies the pack's signature, applies it
to stored evidence at once, reports exposure separately from signs of
compromise, raises the host's prior when it was exposed during the window,
and focuses the timeline there. The first real pack is PHP2Shell
(DESIGN.md §10.2), written by hand from the advisories. Drafting packs is
not the tool's job: a separate pack application, in its own repository,
will watch for threats and draft packs for approval (after Phase 4).

**Done means:**
1. **Format.** A pack is YAML with a fixed, versioned schema (DESIGN.md
   §10.1): id, title, version, dates, exposure window, affected packages
   with fixed versions per distribution release, mitigations, detections,
   remediation, references. `checker packs check FILE` validates one, and
   says exactly what is wrong.
2. **Trust.** The tool refuses an unsigned pack, or one signed by a key it
   doesn't trust. NouriLoop LLC's minisign public key ships inside the tool
   and is published on nouriloop.com; an organization may add its own keys
   for private packs (DESIGN.md §10.4). Verification works offline.
3. **Exposure, judged correctly.** Vulnerable or fixed is decided by each
   distribution's own version ordering (dpkg's and rpm's, epochs and
   backports included), never by comparing upstream version strings. For a
   fixed host, the report says when the fix arrived (from the package's
   install time) and how long the host was exposed during the window.
4. **Stale code.** A service still running code from before the fix was
   installed (process started before the fixed package's install time) is
   an exposure finding, even though the package is fixed.
5. **Mitigations.** Each setting a pack names is reported as in place,
   missing, or not seen (the evidence doesn't cover it).
6. **Detections.** A pack's detections run over stored events and
   snapshots, weighted higher inside the exposure window, and appear as
   ordinary findings with the pack named.
7. **Scoring.** Exposure findings sit in the report's hygiene and exposure
   section and don't count towards the compromise probability (DESIGN.md
   §11.4). A host exposed during the window gets a raised prior, by a
   stated formula, shown with its reason in the report.
8. **Stored evidence.** Adding a pack and running `checker analyze --all`
   applies it to every host's latest bundle with no new collection; the
   report says which packs, at which versions, were applied. Retired packs
   are kept, so an old analysis can be reproduced.
9. **PHP2Shell.** The first pack, written from the real advisories, signed
   with the NouriLoop LLC key and published in the packs repository. On
   throwaway servers: a vulnerable PHP is reported exposed, a fixed one
   fixed, a fixed one whose PHP-FPM wasn't restarted stale, and the
   mitigation setting found on or off.
10. **The format as a library.** The pack format and its checks can be
    used on their own, without the rest of the tool, so the pack
    application validates its drafts exactly as the tool will read them.

## Ground rules

Phase 0–3 rules carry over: a feature branch per PR into `dev`; John
merges `dev` → `main`; evidence stays encrypted; collect less, not more;
every code PR gets an independent agent review with its fixes first, then
Copilot review (from 2026-11-01), before it is called ready; policy wording
is John's to approve before it is committed. Also:

- **A pack is data, never code.** Nothing in a pack is executed or
  evaluated: no Python, no shell, no regular expressions that could run
  away (detections use a small, bounded matching language, D1). A pack can
  only describe; the engine decides.
- **Signatures before parsing.** A pack's signature is checked over the
  file's bytes before its YAML is read. The YAML loader is the safe one,
  with size and depth limits.
- **The signing keys never touch a server or CI.** John makes them on his
  own machine and keeps them in 1Password plus an offline backup
  (DESIGN.md §10.4). Releases are signed by hand.
- **Two keys, so one can be replaced.** A root key, used rarely and kept
  offline, signs only the list of trusted pack keys; a pack key signs
  pack releases. A leaked or lost pack key is revoked and replaced by a
  new list, without a tool release (4.2; a side note John relayed,
  2026-10-30).
- **Vendor data, not upstream strings.** Fixed versions come from each
  vendor's advisory for each release (Ubuntu USN/OVAL, Red Hat errata,
  the Sury PPA's changelog), recorded in the pack with their source.
- **Exposure isn't compromise.** Being vulnerable raises the prior; it is
  never itself a sign of compromise.
- **No network by default.** Only `checker packs pull` downloads, and only
  when asked (policy §10, §11). The tool fetches no advisory and asks no
  AI about packs: the advisor's roles stay the four of Phase 3.

## Pull requests

### 4.0 — The pack format

- `checker/packs/format.py`: the schema (pydantic, strict, `extra=forbid`),
  a `format` number, and validation messages a pack author can act on.
  Pack ids are `[a-z0-9-]`, versions are integers, dates are UTC.
- Package rules per distribution release: `ubuntu:24.04`, `rhel:9` (also
  matching Rocky Linux and AlmaLinux 9, which the tool maps to their RHEL
  release),
  each with the source package or binary package names and the first fixed
  version in that vendor's own numbering, plus where it came from.
- `checker packs check FILE`: validates without trusting or installing.
- `checker.packs.format` depends on nothing but pydantic and PyYAML and
  imports nothing else from the tool, so the pack application can use it
  as a library (done means 10); a test holds it to that.
- Where packs live: `packs/` in the checker's home (active and retired),
  owner-only.
- *As built (4.0):* `checker/packs/format.py`, strict schema (no type
  coercion), YAML read with aliases, deep nesting and repeated keys
  refused, 256 KiB at most; https references and sources only; detections
  name a built-in check (the matching language widens this in 4.5, before
  the format is first published); `checker packs check FILE` also checks
  those checks exist. The `packs/` folder comes with `packs add` (4.2).
- **After review (4.0; 2 high, 7 medium):** malformed files crashed the
  reader (impossible dates, odd tags, huge numbers, unhashable keys): all
  are pack errors now. One fixed version per release couldn't tell the
  Ubuntu archive from the Sury PPA, nor RHEL's PHP module streams: a
  release may now hold several entries, each picking installed versions
  by a glob (`versions`), and `fixed: null` says no fix yet. `names`
  became `binary_names` (the collector knows no source names). A fixed
  version must carry the vendor's revision or release. Hidden and control
  characters are refused in every text field and escaped in messages;
  YAML is read with 1.2's plain types (`off` stays text, no octal or
  sixty-based numbers); times and dates say how to write them; at most 20
  problems are listed; `packs check` reads only a regular file, no more
  than a pack may hold. Addresses must be public https host names. Still
  to do once 4.1 is in: check each fixed version's structure with the
  family's own parser.

### 4.1 — Version ordering

- dpkg's and rpm's version comparison (epoch, upstream version, revision;
  `~` sorting before everything, `^` for rpm), written from their
  documented algorithms, no new dependency. Tested against tables taken
  from dpkg's and rpm's own test suites, and against every PHP package
  version on the golden cases.

### 4.2 — Signing and trust

- minisign signatures verified in Python (Ed25519 over the file's
  BLAKE2b-512 hash, minisign's default; the trusted comment checked too),
  with the `cryptography` library the tool already depends on through
  asyncssh. No minisign binary needed to verify.
- **Two NouriLoop LLC keys** (D5): a **root key**, whose public half is
  in the tool's source and on nouriloop.com, and which signs nothing but
  the **key list**; and a **pack key**, which signs pack releases and is
  trusted only because the current key list names it. The root key is
  never trusted for a pack, nor a pack key for a key list.
- **The key list** (`keys.yaml` and its `.minisig`, signed by the root
  key): a format number, a **serial** that only goes up, the date, the
  pack keys to trust (minisign key id, public key, name) and the revoked
  ones (key id, since when, why). A copy of the current list ships in the
  tool; a newer one is taken from `checker packs pull` (4.7) or added by
  hand (`checker packs keys add FILE`, for air-gapped sites). The tool
  remembers the highest serial it has accepted and refuses a lower one,
  so an old list can't be replayed to bring a revoked key back.
- **Revocation:** a pack signed by a revoked key is refused when added or
  pulled, and one already added is retired at once when the new list
  arrives; the next analysis says it was retired and why. Reports made
  with it stay readable.
- **Losing or leaking the root key** needs a tool release with a new root
  key; it is used perhaps once in years and never online, so that should
  be rare. `checker packs keys` shows the list in force: its serial, the
  trusted and revoked keys.
- Organization keys in `config.yaml` (`packs.trusted_keys`, each with a
  name), changed with `checker config` and recorded like other settings:
  the organization replaces its own keys there; the key list doesn't
  touch them.
- `checker packs add FILE [--signature FILE.minisig]`: verifies, then
  copies into `packs/`. A pack whose id and version are already present
  with different content is refused. `checker packs list`, `show ID`,
  `retire ID`.
- Built and tested with throwaway test keys; the real ones (D5) go in at
  4.8. Needs from John then: both key pairs, made with `minisign -G` on
  his machine, and the first key list signed with the root key (I'll give
  the exact commands).

- *As built (4.2, #80):* `checker/packs/signing.py` (minisign, prehashed
  only, trusted comment under its global signature, UTF-8 comments),
  `trust.py` (root key, key list kept whole per serial in
  `packs/keylists/<serial>/`, highest serial recorded; a damaged or
  missing kept list trusts no NouriLoop key), `state.py`
  (`packs/state.json`: per pack id its signing domain, highest version
  and every version's hash, so no rollback, changed content or takeover
  even after a retire), `store.py` (active and retired packs, retired
  files named by content hash). Organization keys can't be revoked or
  root keys; two trusted keys sharing an id are both refused.
  `ROOT_KEYS` is empty until 4.8. Not yet: interoperability with the real
  minisign (at 4.8, with John's).

### 4.3 — Exposure

- An installed package that matches several entries (one with no
  `versions` pattern matches every version) is vulnerable if any of them
  says so, so the Ubuntu archive's fix can't vouch for a Sury build that
  sorts above it (a side note John relayed, 2026-10-30). An installed
  version the family's parser refuses is "can't judge", reported, never
  fixed and never skipped.
- For each active pack and host: which affected packages are installed,
  their versions, vulnerable or fixed by the vendor's ordering, and for a
  fixed host when the fixed version was installed (the package's install
  time; the package history where it says more).
- The exposure window from the pack: exposed during the window, from when
  to when, and for how long.
- Stale code: a process whose executable belongs to an affected package
  (or matches the pack's service glob) and started before the fixed
  package's install time.
- Findings in a new `exposure` category, scored apart from the compromise
  probability, with the pack's id and version on each.
- The prior raised for a host exposed during the window (D3), shown in the
  report with the pack, the exposure and the formula's result.
- The report's timeline marks the window.
- *As built (4.3):* `checker/packs/exposure.py` judges each pack once per
  analysis (host release from os-release: Ubuntu by version, RHEL,
  Rocky and AlmaLinux by major version; packages by manager, binary name
  and `versions` pattern; vulnerable if any matching entry says so; an
  unreadable version is "can't judge", counted as exposed). The check
  `pack.exposure` (variants vulnerable, cant_judge, was_exposed,
  stale_code) reports in the exposure category; a release a pack doesn't
  cover is a coverage gap. The prior's log-odds rise by each exposure's
  share of log(ratio), all of them together at most log(10); the score
  keeps `raised_prior` and `raised_by`, a re-score keeps the raise, and
  the report says "raised to … by exposure to …". The analysis records
  the packs applied. **The fix time is an upper limit** (a side note John
  relayed, 2026-10-30): the collector has no package history (apt's,
  dpkg's, dnf's logs), only each package's last install time, so a
  routine update after the fix stretches the exposure; findings and the
  report say "at the latest", and stale code is "may still run" (medium).
  Not done: the timeline marking the window (with 4.6's report changes).
  Package history: John said yes (2026-10-30), collected alongside 4.4.
  Policy §7 bullet for it approved by John the same day (in #82).
- **After review (4.3; 2 high, 6 medium, 7 low):** an installed epoch the
  pack's fix doesn't write (1:8.3.6…5 against 8.3.6…6) read as fixed: now
  "can't judge", and `versions` patterns match with or without the epoch.
  A service still on pre-fix code didn't extend the exposure: now the host
  stays exposed (share 1) while one runs, and a program file replaced
  under a service counts whatever its start. One fixed package with an
  unknown install time now makes the fix time unknown (exposed); an
  impossible install time can't break the analysis; a package listing
  collected only in part is "can't judge" (exposed), not "not affected";
  a build from another repository that sorts above the vendor's fix
  (Remi, Sury with no entry of its own) is "can't judge" unless it
  carries the fix's vendor mark (`ubuntu`, `.elN`). Whitelist rules for
  `pack.exposure` must name the pack (new `pack` field), so one pack's
  rule can't hide a later pack's findings. Smaller: an entry with no fix
  wins over an unreadable version; the raise is stored exactly
  (`log_raise`) for re-scores; a naive collection time is UTC; stale
  services are one finding per pack, not per worker; the wording when the
  window closed before the fix, or the time is unknown; a release not
  covered names the OS. Still to do, with package history (4.4b): earlier
  collections' package listings as history (a package removed during the
  window; a fix seen in an earlier bundle bounds the fix time), and
  kernels judged by the running kernel (a design note for kernel packs).

### 4.4 — Mitigations

- What a pack can name as a mitigation: settings the collector already
  reads (sshd, sysctl, systemd units, web server configuration) and, for
  PHP2Shell, PHP's ini settings, which it doesn't read yet (D4).
- Each mitigation reported as in place, missing, or not seen.
- **A setting written nowhere is PHP's built-in default** (a side note
  John relayed, 2026-10-30): `session.upload_progress.enabled` defaults to
  On, and Ubuntu's php.ini leaves the line commented out, so it is often
  in no file at all. The pack format gains the setting's default (`default:
  "on"`), and "set nowhere" counts as that default: unprotected, never
  "in place" or "not seen". Only a settings section collected in part is
  "not seen". The last occurrence wins, as PHP reads them (each setting
  carries its position; `[PATH=…]` and `[HOST=…]` sections apart; a pool's
  php_admin_value over the ini file).
- *As built (4.4, #82): the collection.* PHP's ini files and the package
  history are collected (see the 4.4 PR and docs/collector-modules.md);
  4.4b judges with them.
- **After review (4.4; 1 high, 5 medium, 11 low):** dnf's history query
  could spill a sort to a temporary file in /tmp on a busy server (a
  write): every SQLite read of a server's database (dnf's, and rpm's
  three) now keeps sorts in memory, runs no schema functions, refuses
  views in place of dnf's tables, and checks the deadline inside SQLite (a
  crafted view looped forever). PHP settings not read whole leave
  `php_settings` incomplete. Secret directives (`*_pw`, `license`,
  `auth`, `save_path`…) are masked whole. Quoted values followed by a
  comment parse as PHP reads them. The 20,000 cap keeps the newest
  changes; old lines in a recent dpkg log are skipped; logrotate's
  dateext names and .xz/.bz2 are read; the horizon reaches back as far as
  the look-back window if that is longer; obsoleting/obsoleted dnf
  changes are recorded; dnf's write-ahead log is reported when not empty;
  a host whose dpkg log is only old isn't "no history"; repeated
  directives and [PATH=]/[HOST=] sections are kept apart; dpkg times in
  the hour that happens twice are marked uncertain. php.ini's own
  error_log no longer leads the collector to PHP's application error log
  (collecting it would widen collection without a decision). Not done:
  dnf5's database (Fedora 41+, not RHEL 9/10).
- **Read-only proof (4.4, 2026-10-30, John's OK):** throwaway Ubuntu 24.04
  and Rocky Linux 9 Linodes with nginx and PHP-FPM installed by the setup:
  both PASS, bundle complete, the collector wrote nothing; package history
  (`package_change`) and php.ini collected on both (one secret directive
  masked on each: `session.save_path`'s whole value). About 60 seconds of
  collection each; both servers deleted. Spend: about $0.01 (Phase 4 so
  far: about $0.01 of the $10 cap).

### 4.4b — Mitigations and dated fixes (as built)

- The pack format's mitigation gains `default` (PHP's built-in value
  when no file sets it). `checker/packs/mitigation.py` judges each PHP
  set-up as PHP loads it (php.ini, then conf.d in name order through its
  links; the last occurrence outside [PATH=]/[HOST=] wins; set nowhere =
  the default) and each PHP-FPM pool's override: in place only if every
  set-up and pool has the expected value; "not seen" when PHP's settings
  weren't collected whole, no set-up was found, or the pack gives no
  default for a setting set nowhere. A missing mitigation is a
  `pack.exposure` finding (`mitigation_missing`): high while the host is
  vulnerable or can't be judged, medium once fixed. Mitigations don't move
  the prior (D3 didn't say they should).
- **What an in-place mitigation can't see** (a side note John relayed,
  2026-10-30): a site's `.user.ini` (PHP-FPM) or `.htaccess` (Apache's
  PHP) can set `session.upload_progress.enabled` again for that site; the
  collector reads neither, and the coverage section says so whenever a
  mitigation reads as in place. Reading them is a collection change:
  **John said yes (2026-10-30): read them after 4.4b, as 4.4c** (the web
  roots the tool already walks; PHP settings lines only, masked; policy
  §7 wording to John; the read-only proof again).
- Fix times from the package history: the change into a fixed version
  after which the package stayed fixed dates the fix exactly (a later
  routine update no longer stretches the exposure); a first install of an
  already-fixed version extends no exposure; a downgrade back restarts
  the clock; without history, an earlier collection that already had the
  fix bounds it; a vulnerable package removed during the window was
  exposed until its removal. Findings say "at" for an exact time and "by
  … at the latest" otherwise.
- **After review (4.4b; 3 high, 7 medium, 6 low):** the worst two
  outcomes both happened. An exposure cut to nothing: a vulnerable
  version purged and reinstalled fixed, or removed while another affected
  package stayed, counted as no exposure; now a removal always counts,
  and a first install counts as fresh only with the history whole and
  nothing vulnerable still installed just before it (any name). "Exact"
  on partial history: now exact only if the last change found is to the
  version installed and its time is certain; a retried upgrade dates from
  the retry; dnf's pending write-ahead log leaves the history incomplete;
  an earlier collection bounds the time only for the very same version.
  "In place" with PHP on: a pool's php_admin_* line was overwritten by a
  later php_flag in the snapshot; now every override is kept with its
  kind and order, and a pool's admin values come first. Also now places
  of their own: [PATH=]/[HOST=] sections, a set-up with no php.ini (its
  defaults), pools in php-fpm.conf and pool subfolders, the web server's
  own php_value / php_admin_* / FastCGI PHP_VALUE. "Not seen" when a
  conf.d link points to a file not read, a pool file is included from
  elsewhere, or PHP_INI_SCAN_DIR adds folders; but a value definitely
  wrong anywhere is "missing" first. Any non-zero integer is on. A
  php_ini mitigation must say its default. Clearer wording for an exact
  fix after the window closed, a removal, and stale code.
- Running kernels: no kernel pack exists yet; when one does, the running
  kernel (uname, in the host facts) is what to judge, since an installed
  but unbooted fix protects nothing. A design note for that pack, not
  built.

### 4.4c — Sites' own PHP settings (as built)

- The web-root walk notes each `.user.ini` and `.htaccess` (a link too)
  and then reads them, up to 500 per root: PHP lines only (`.user.ini`:
  directives, as php.ini; `.htaccess`: `php_value`/`php_flag` and admin
  forms, and `SetEnv PHP_VALUE`), masked, secret-named values whole. The
  refusal rules gain one exception: with `site_root`, a file may lie
  outside the system locations only if it has one of those two names and
  lies inside the root being walked (checked on the file opened); the
  hard-link, home and history rules still apply. A file whose path
  masking would change isn't read (its source name would carry the
  secret). Anything not read, or a walk not whole: `site_php_partial`.
- The snapshot parses them into `php_settings` as kind `site` (`how`:
  `.user.ini`, `php_value`…, `PHP_VALUE`); `php_settings` now also
  depends on `unusual_files`; a site file not read leaves `php_settings`
  incomplete, not the web-file sections. SNAPSHOT_VERSION 13.
- The mitigation judge counts each site value as a place of its own.
  A `.user.ini` or `PHP_VALUE` value doesn't count where every PHP-FPM
  pool sets the setting with `php_admin_*` to the expected value and no
  CGI set-up exists (nothing overrides `php_admin_*`); an `.htaccess`
  `php_value` (Apache's module) always counts. The in-place note now
  names what's still unseen: sites outside the web roots examined, and
  `ini_set`.
- **After review (4.4c; 4 high, 5 medium, 6 low), all fixed:**
  - a folder swapped for a link between the walk and the read could reach
    a kept-out home: the file opened must now be the walked inode;
  - secret settings inside `SetEnv PHP_VALUE` went out unmasked: each
    pair is masked whole now, and any other directive naming `PHP_VALUE`
    is sent only as a marker naming the directive ("not seen");
  - time running out, or a root not examined, left `php_settings`
    complete: `site_php_partial` is now recorded however reading ends,
    a web-roots time limit maps to `php_settings`, and a `site_php`
    record marks a collection that went through every root (without it,
    an older collector: a gap);
  - PHP-FPM applies a FastCGI `PHP_VALUE` over `php_admin_*` (php-src
    `fpm_php_zend_ini_alter_master`): only `.user.ini` is locked out now;
  - `user_ini.filename` is resolved per set-up and pool (empty: none
    read; another name: "not seen");
  - site values count only where something reads them: `.user.ini` under
    PHP-FPM or CGI, `.htaccess` `php_*` under Apache's PHP module,
    `SetEnv PHP_VALUE` under Apache with PHP-FPM;
  - a linked site file is counted, never opened (its target was sent
    unmasked); `.user.ini` sections aren't sent.
  - Not modelled (they only make a site count where it might not):
    which pools serve which site, AllowOverride, `<IfModule>`, Apache's
    own `php_admin_*`, a `.user.ini` above the document root. One goes
    the other way: RHEL's php-cgi (mod_fcgid) isn't recognised as CGI,
    so with every pool locked a site's `.user.ini` there is wrongly left
    out; the judge sees settings and files, not which packages provide
    php-cgi.
- **Read-only proof (2026-10-30, after the review fixes): PASSED** on
  ubuntu24.04 and rocky9. The collector wrote nothing; the planted
  `/var/www/proof/.user.ini` and `.htaccess` were collected on both
  (`.user.ini` with its secret-named setting masked, `.htaccess` down to
  its `php_flag` line), the planted secret appeared nowhere in the
  bundles, and `php_settings` was complete on both. Both servers deleted.
  Spend: about $0.01 (Phase 4 so far: about $0.02 of the $10 cap).

### 4.5 — Detections

- The detection language (D1): over events (type, fields matched by
  literal, prefix or bounded glob; counts within a time span; grouped by
  source), over snapshot items (present, absent, changed), and references
  to core checks whose weight rises inside the window. Bounded in size and
  cost; no regular expressions.
- Each detection has a band and a likelihood ratio, capped by the pack
  format so a pack can't outweigh the core checks.
- Detections that need data the host's collection doesn't have (web access
  logs off, a log format without request sizes) are listed as coverage
  gaps, not silently skipped.

### 4.5 — Detections (as built)

- **The language** (`checker/packs/format.py`): a detection is one of
  - `check` (+ optional `variant`): a core check, its compromise findings
    raised to the pack's ratio (at most 100, the critical band's) while
    the host was exposed, never lowered, marked `raised_by`;
  - `events`: up to five matchers (an event type, exact or a prefix
    ending in "."; up to eight fields), `count: {at_least, within}` (a
    span up to 7 days, or the whole time exposed), optional `by` (a
    field counted apart per value);
  - `snapshot`: a section, optional `key` and field matchers, `state`
    present / absent / added / changed / removed.
  Values are matched as text: `equals`, `prefix`, or `glob` (`*`, `?`,
  at most ten stars; a linear matcher, no regular expressions). A list
  value matches if any element does. A pack's own detection needs a
  title and weighs at most 20 (the high band's ratio): a pack can't
  outweigh the core checks. `needs` names data from a fixed list
  (`web_access_log`, `web_error_log`, `process_starts`,
  `request_content_type`), judged from the collection.
- **When they count** (`checker/packs/detect.py`): only while the host
  was exposed — from `exposed_from` to `exposed_until` (or still), as
  4.3/4.4b judge it. A host the pack doesn't affect, or fixed before the
  window, gets nothing from its detections. A raised core finding with
  no time of its own (what the host shows now) counts while the host is
  still exposed.
- **Findings**: `pack.detection`, variant `pack-id/detection-id`, band
  from the ratio, the ratio on the finding (`likelihood_ratio`), which
  scoring uses before the band's. One check, so the family cap holds all
  the packs' own detections to a doubling beyond the strongest.
  CHECKS_VERSION 14, SCORING_VERSION 3 (no golden score moved).
- **Gaps, not silence**: a need the collection lacks, a referenced check
  that didn't run, a section not collected, an absence in a section not
  collected whole, a change with no baseline. `request_content_type` is
  in no log format the tool reads: DESIGN.md §10.2's multipart-POST
  detection is always a gap until a log format carries it.
- **Ratio caps: 100 for a core check's findings, 20 for a pack's own
  rule.** John confirmed them (2026-10-30), within D1's "capped so a pack
  can't outweigh the core checks".
- **When a detection counts** (a side note John relayed, 2026-10-30; John
  said build it): first built as only while the host ran a vulnerable
  version, which on a patched host like prod (fixed after about 2.5
  days) covers only those days, though an intruder who got in may stay.
  Now each detection says: `counts: while_exposed` (to the fix or the
  window's end: an attack attempt, harmless once fixed) or
  `since_exposed` (from its exposure to the collection, fix or not;
  the default, so leaving it out can't hide an intruder). PHP2Shell's
  crash and memory-limit bursts are `while_exposed`; worker children and
  new scripts `since_exposed`.
- **After review (4.5; 3 high, 9 medium, 8 low), fixed:**
  - a pack could name `pack.detection` and lift every pack's own
    detections past their cap: a pack can't name a pack check;
  - a pack's snapshot finding naming several paths joined unrelated
    core findings into one group, cutting them (a score went down):
    `pack.detection` findings never group;
  - a careless glob on long values cost minutes (one star is the worst
    case): segments are now matched with str.find, each leftmost, the
    work counted against a budget per analysis (past it: a gap); events
    are indexed by type once;
  - rules over web requests, web errors and program starts need those
    logs whether they say so or not (judged in part when only some
    matchers are blind); `every_web_request` names what's never there
    (only some requests become events); logs mostly in a format not
    recognised count as missing;
  - snapshot rules follow when they count; `while_exposed` ends at the
    window's end; a can't-judge with no package found (a listing in
    part) turns nothing on; a pack can't read the sections exposure is
    judged from (`packages`, `package_history`, `php_settings`,
    `web_config`, `host`);
  - whitelist rules for `pack.detection` name the pack and may name one
    detection (`pack-id/detection-id`); store and `packs check` refuse
    variants and sections this version doesn't have; a raised finding
    never weighs less than its check says now; the report says which pack
    raised a finding; untimed matches and too many groups are gaps; gaps
    are said once; a failing reference is a gap, not a failed analysis;
    a check detection can't carry a title.
  - M7, decided by John (2026-10-30): a raise is at most one band up
    (low to 4, medium to 20, high to 100), so a pack can't turn a check's
    everyday noise (a login from a new address) into a critical score;
    PHP2Shell's `web.worker_child` (high) can still reach 100.

### 4.6 — Applying packs to stored evidence

- `checker analyze` applies every active pack; an analysis records which
  packs and versions it applied, so reports are reproducible. Adding a
  pack and running `checker analyze --all` re-analyses each host's latest
  bundle; scheduled runs (`checker run`) apply packs as they are.
- A newly added pack that finds a host exposed or a detection firing is a
  "needs a look" item in `checker run`.
- Golden tests: the golden cases analysed with and without a test pack.
- As built (2026-10-30): `checker.packs.store.in_force` reads the packs in
  force for `analyze`, `report`, `run` and `advise` (once per command or
  run, so every host is analysed with the same ones); one that can't be
  used is said (stderr, or a run problem, which fails the run, told when
  it starts or changes) and is a coverage gap in each analysis. A report
  (and the advisor's case) analyses a host again when the packs, or why
  any isn't applied, differ from its stored analysis's. Each analysis
  keeps its packs' exposures (`exposures`): the report's timeline marks
  each pack's window and the host's exposure in it (the timeline item
  deferred from 4.3). `checker analyze` prints the packs applied and the
  prior's raise. A run's "needs a look" gains a host newly or more
  exposed to a pack's threat (per pack id and status; an exposure that
  couldn't be judged at all is neither news nor forgotten) and any pack
  detection new or more serious, whatever its band (a pack's own, whose
  group is now in its entities so its identity survives new counts and
  pack versions, or a core finding a pack newly weighs). Golden: each
  case also against `tests/golden/test-pack.yaml` (never signed or added
  to a home), `*.pack.expected.json`; the fresh cases go from 6% to 23%
  on exposure alone. The harness now passes the baseline's time and
  snapshot as `analyze` does, which moved both detection cases' plain
  expectations by the same two mail findings (mail.domains, mail.volume)
  and their advisor requests; it still passes no scanner account and
  doesn't model a baseline newer than the bundle.
- **Per-host switch, decided by John (2026-10-30):** large organizations
  will want control over where a pack applies, so a rule (`all`, `none`,
  `only: IDs`, `except: IDs`) per host (inventory, `checker hosts packs`),
  per group (`packs.group_apply`) and for all (`packs.apply`, default
  `all`), host first, as with the prior (`checker/packs/choice.py`). A
  held-back pack is a coverage gap, not a problem. Changes made with the
  commands are recorded in `checker config history` (a side note relayed
  the same day: who turned a pack off for a host must stay known); hand
  edits aren't. Test packs stay in test homes; the first pack in the real
  home is 4.8's, added with John's OK.
- **After review (4.6; 2 high, 3 medium, 5 low), all fixed:** the advisor
  re-analysed without the packs (assessments flip-flopped); a by-field
  detection's identity changed with its counts (a new alert most runs);
  a partial listing's can't-judge re-alerted each time it recurred; a
  core finding a pack weighs never alerted; a worsening exposure was
  silent; a change in why a pack isn't applied didn't re-analyse; gaps
  printed unescaped and the run's pack alert repeated daily; the plan's
  golden note was wrong (both detection cases moved); tests asserted
  loosely.
- **Second review (the switch and the fixes; 2 medium, 4 low), all
  fixed:** a by-field value cut to 200 characters could let a whitelist
  rule judge part of it (now never cut: too long, not named); a listing
  collected in part with only fixed packages seen flapped between fixed
  and can't judge (now unjudged); a run state from before weighing was
  kept would have told every weighed finding once; the timeline's
  exposure mark duplicated the window's opening and wasn't capped;
  removing a host with its own rule, and a group's rule, went
  unrecorded (now `checker config set packs.group_apply.GROUP`); typos in
  pack ids and group names went unnoticed. Behaviour change to note: a
  by-field pack detection now names its group, so its identity in a run's
  memory changes once (one "new" alert each, the first run after), and a
  broad whitelist rule for the pack now hides it.

### 4.7 — Distribution

- The public packs repository, `compromise-checker-packs` (D6): one
  directory per pack, `PACK.yaml` and `PACK.yaml.minisig`, a README on how
  to verify, CC BY 4.0. Releases are signed by hand.
- `checker packs pull`: downloads the repository's release index and new
  packs over HTTPS, verifies each before anything is kept, and says what
  changed. Air-gapped sites copy the files across and use `packs add`.
- The public key published on nouriloop.com (the site is GitHub Pages), so
  it can be checked against the copy in the tool.

- As built (2026-10-30): `checker/packs/pull.py`. The repository holds
  `keys.yaml` (root-signed), `index.yaml` (signed by a NouriLoop pack
  key: an organization's own key can't sign it) and `packs/<id>/PACK.yaml`,
  each with its `.minisig`. A pull takes a newer key list first (and
  retires packs whose key it revokes), then the index: its serial only
  goes up (`index_serial` in `packs/state.json`), and a pack newer than
  any version accepted here is downloaded, must have the index's SHA-256,
  and goes through `packs add`'s checks; one a person retired isn't
  brought back; a withdrawn one is retired. A pack's path comes from its
  id, never from the index. HTTPS only, redirects included (urllib, the
  system's certificates), each file's size capped, 30 seconds a file.
  `packs.source` (default the repository's raw files on GitHub) can point
  at a mirror. `checker packs index DIR` writes the index for signing by
  hand (hashes quoted: a hash of digits alone would read as a number).
- **A stale source** (a side note relayed 2026-10-30): a serial stops an
  older index, not the current one served for ever, which would hide a
  new pack or a revoking key list. So the index is signed again at least
  monthly, even with nothing new, and the pull and `checker packs list`
  point out one older than 30 days, with when the last pull was.
- Waits for 4.8's keys: the repository's first `keys.yaml` and index, and
  the root public key on nouriloop.com.
- **After review (4.7; 1 high, 7 medium, 12 low), all fixed:** an HTTP
  protocol error (a body cut short) crashed the pull; a NouriLoop
  withdrawal, or index entry, could touch an organization's own pack of
  the same id (now left alone); a mirror could re-sign NouriLoop's bytes
  with an organization key and take the id into that domain (a pulled
  pack must be signed by a NouriLoop key); an index entry naming another
  pack wrote before it was refused (`add` now checks the expected id and
  version first); the release writer's ids (`2026-10-30`, `1e5`, `null`)
  and non-BMP reasons didn't round-trip (all quoted); a missing key list
  passed quietly (now refused; an older one is a problem, exit 1); what
  a pull did before failing went unsaid; a changed pack under the same
  version could be released (refused, and a pull says so); the index
  serial is recorded as soon as it is checked, with its hash (one serial,
  one index); a future-dated index is pointed out; a file gets two
  minutes in all; the source refuses control characters and user
  names; a damaged last-pull record doesn't break `packs list`; the
  index cap matches the reader's; withdrawals can be forgotten; a
  release checks every pack's signature against the repository's
  keys.yaml; a pack retired by hand stays out of pulls, whatever version
  is offered, until a person adds it again. Revocations still depend on
  the source (pull.py's docstring says so; nouriloop.com is the second
  place to check the key list).
- **Second review (the fixes; 2 medium, 6 low), all fixed:** the per-file
  deadline didn't hold against a server sending a byte at a time (now
  read1, tested with a real socket); what a pull did went unsaid when it
  stopped on anything but a PullError; a person couldn't hold back a pack
  already out of use, and the hold was written after the move; `packs
  list` didn't flag a future-dated index; a pack in force with no record
  (state lost) could be overwritten; the source took non-ASCII; the
  release writer dropped a pack without a word, and let one withdrawn be
  relisted at a version sites already had (a withdrawal now keeps the
  version it covered).

### 4.8 — The PHP2Shell pack

- Written from the advisories: CISA's alert, the vendors' errata for
  Ubuntu 22.04, 24.04 and 26.04, RHEL (and its rebuilds) 9 and 10, and the
  Sury PPA, with the fixed version for each release and its source. Every
  version and date checked against the vendor's own page before signing.
- **A Sury entry for each release** (a side note John relayed,
  2026-10-30): an Ubuntu entry with no `versions` pattern vouches only
  for Ubuntu's own builds (4.3's review), so a Sury build is "can't
  judge", exposed for the whole window. nouriloop-prod runs PHP 8.4 on
  Ubuntu 24.04, whose own PHP is 8.3, so most likely from Sury: the pack
  needs `versions: "*+deb.sury.org*"` entries with Sury's own fixed
  versions, checked against the PPA's changelog, or prod looks exposed
  after it is fixed.
- Mitigation: `session.upload_progress.enabled` off (it also covers
  CVE-2026-115560, unpatched when the pack was first published).
- Detections from DESIGN.md §10.2: web worker child processes, memory-limit
  bursts, PHP-FPM worker crashes, 5xx bursts from one source, multipart
  POSTs to the site root.
- Proof on throwaway Linodes (D7), with a vulnerable PHP pinned, a fixed
  one, a fixed one not restarted, and the mitigation on and off: each
  reported as expected. No exploit is run; the detections are shown with
  log lines written in the shapes the advisories describe.
- Applied to nouriloop-prod's stored evidence only with John's OK.
- As built so far (2026-10-30): a vendor check of the first draft found
  real vulnerable builds read as "not affected" (AlmaLinux's module form,
  RHEL 9's php:8.1, Remi's older branches and Collections, Sury 5.6 to
  7.3), because a version no pattern matched was treated as safe. So a
  pack can now say `other_builds: cant_judge`; the entries were corrected
  too. The tool also reads PHP's own error log, RHEL's PHP-FPM default,
  which it silently couldn't parse. Dropped from the plan's detections:
  multipart POSTs (no log format gives content types, so it could only
  be a permanent gap), and a 5xx rule of the pack's own (it doubled
  `web.errors`, now named by the pack instead). Known limits: patched
  RHEL EUS and SAP-minor builds read vulnerable, since one pattern can't
  exclude them; mod_php's Apache isn't in stale code, since it would flag
  every Apache in front of PHP-FPM; cPanel's and Plesk's own packages read
  not affected (the remediation says so), as do Ubuntu ESM releases and
  RHEL 8 only as "not covered". Second check (2 high, 7 medium, low): one
  log line dated year 1 or 9999 stopped a whole analysis (now no time);
  `other_builds` didn't reach the package-history path, so an uncovered
  build removed in the window looked never exposed; a PHP stack trace's
  lines counted as an unknown format and could blind the log rules; the
  pack missed php8.5-litespeed and let third-party Ubuntu builds read
  fixed. Left as a limit, not changed: Remi collections' logs under
  `/var/opt/remi` and a pool's `php_admin_value[error_log]` elsewhere aren't
  read, because the collector refuses files outside its system locations
  and widening that boundary is John's to decide. A tool older than this rejects a pack using
  `other_builds`: the pack ships after the tool.
- **Proof PASS (2026-10-30), `tests/integration/php2shell_proof.py`, 63 of 63
  checks:** Ubuntu 24.04's own PHP 8.3, Sury's PHP 8.4 on Ubuntu 24.04 beside
  Ubuntu's 8.3, and Rocky 9's 8.0, each taken through vulnerable (a pinned
  older vendor build), the setting off, log lines in the shapes described
  (no exploit run), fixed with workers left running, then restarted. It
  found one tool bug: on a host with two PHP versions, one version's workers
  read as old code after the other's fix, for as long as they ran; a
  program is no longer judged by a package naming another version. Ubuntu
  24.04's needrestart would restart workers during an upgrade by itself, so
  the proof suspends it. Not proved on servers: the core `web.worker_child`,
  `web.new_script_hit` and `web.errors` raises (unit and golden tests
  only), Remi, AlmaLinux, RHEL itself, PHP's real crash lines, and the
  nginx-shaped memory line a default Ubuntu pool writes (parser test only).
  Remi's Collections side by side keep the two-version flaw, erring toward
  old code: their program names no version. A mod_php Apache left running
  isn't detected, and the pack's remediation says so.
  Four runs, eleven Nanodes: at most about 8 cents if each is billed a whole
  hour; Phase 4 about $0.10 of $10.

- Firewall parsing (found by reviews of a fail2ban fix, 2026-10-31): nft prints
  comments raw, so its text can't be read back reliably. A line with an
  unbalanced quote now stops all summarising for that output. Still open: a
  comment with balanced quotes (settable through `nft -j -f`) can forge a block,
  and a comment line starting `elements = {` can trigger the collector's
  large-set reduction. The real fix is collecting `nft -j list ruleset`, a
  collector change for John to schedule. An accept inside a chain named like a
  running program's isn't compared, by design.

### 4.9 — Policy, docs and README

- Policy §11 (threat packs and trust) brought up to date with what was
  built; §10 (`checker packs pull` downloads). Wording to John first.
- `docs/packs.md`: writing, checking, signing, adding, pulling, retiring a
  pack; the detection language; how exposure and the prior are computed.
- DESIGN.md §10 and §11.2 as built; §10.3, §12.1 (role 5) and §18 say
  drafting moved to the pack application; README "Status: Phase 4
  complete".
- As built (2026-10-30): §10 and §11 in John's approved wording ("kept off
  any server" rather than "offline": the pack key is on his laptop for
  signing). `docs/packs.md` written. Phase 4 complete; on nouriloop-prod the
  pack is in force, and John chose not to rotate secrets for now.

## Decisions to settle (one at a time)

- **D1. What a pack's detections can say. Decided 2026-10-30 (John): the
  small language.** A small declarative language
  (events, snapshot items and core checks, with bounded matching and
  counts), so a pack can teach the tool about a new threat without a new
  release of the tool; or detections only as references to checks built
  into the tool, so anything new waits for a tool release.
  *Recommendation:* the small language, with no code and no regular
  expressions; a pack whose detections need more waits for a release.
- **D2. Where vulnerable versions come from. Decided 2026-10-30 (John): in
  the pack.** Fixed versions written into
  the pack when it is made (offline, reproducible, works air-gapped); or
  the tool downloads the vendors' OVAL data at run time.
  *Recommendation:* in the pack.
- **D3. How much exposure raises the prior. Decided 2026-10-30 (John):
  proportional, PHP2Shell at 5.** DESIGN.md §11.2 says "in
  proportion to the pack's stated confidence and the length of exposure".
  *Recommendation:* the pack states a likelihood ratio for a host exposed
  through the whole window (PHP2Shell: 5, capped at 10 by the format);
  a host exposed for part of it gets that ratio scaled by the share of the
  window it was exposed (in log-odds), and a host never exposed gets none.
  At 2% and a full window, the prior becomes 9%.
- **D4. Reading PHP's settings. Decided 2026-10-30 (John): read the ini
  files, as recommended.** PHP2Shell's mitigation is an ini setting
  the collector doesn't read. *Recommendation:* the collector reads the
  ini files of each installed PHP (`php.ini` and `conf.d/*.ini`, by file,
  never by running `php`), keeps only directive names and values, and
  masks them like any other text; a new module part, read-only like the
  rest, proven by the read-only proof.
- **D5. The signing keys. Decided 2026-10-30 (John): he makes them at
  4.8; test keys until then. Two keys (decided the same day, after a side
  note on replacing a key): a root key and a pack key, as in 4.2.** John
  makes both minisign key pairs on his machine (`minisign -G`), keeps each
  secret key and its password in 1Password with an offline backup (the
  root key's backup apart from the pack key's), signs the first key list
  with the root key, and gives me the public keys to put in the tool and
  on nouriloop.com.
- **D6. The packs repository. Decided 2026-10-30 (John): create it at
  4.7.** A new public repository,
  `john-c-houser-tech/compromise-checker-packs`, under CC BY 4.0.
  Creating it is outward-facing, so it waits for John's word.
- **D7. Spend on throwaway servers. Decided 2026-10-30 (John): Phase 2's
  rules: one OK per PR, $10 cap, stop and tell at $5.** The PHP2Shell
  proof needs a few short-lived Linodes, as in Phase 2.
- ~~D8. What drafting sends.~~ **Dropped 2026-10-30 (John):** drafting
  moved out of the tool, into the pack application.

## Order

4.0 → 4.1 → 4.2 can go first, in that order, without any decision but D5
(4.2 can be built and tested with a test key; the real key goes in when
John has made it). 4.3 needs D2 and D3; 4.4 needs D4; 4.5 needs D1; 4.7
needs D6; 4.8 needs D5 and D7. 4.9 last.

## After Phase 4: reading nftables as JSON

Decided by John (2026-10-31, option B after review). nft prints comments raw, so
text can't be read back reliably: a comment can forge a block or set off the
large-set reduction. But JSON alone was worse: a review on real nft showed it drops
iptables-nft rules' arguments (ufw, Docker: a changed DNAT target compares equal;
on 22.04 even the name is gone), and parsing took 12 to 20 times its size in memory.

So both are collected and each is compared with itself: what one misses the other
shows. The text keeps comparing with existing baselines, so nothing pauses; the JSON
side says so as a gap until a new baseline. JSON is read up to 8 MB; past that, or on
any trouble, only text counts, and losing JSON a baseline had is a finding, since an
attacker could grow the ruleset to cause it (a real blocklist of about 130,000
elements can too: the finding says why). The second review showed a comment in a
managed chain could recreate a changed iptables-nft rule's old lines, seen by
neither, and the third that scanning the JSON's strings doesn't stop it: a word
_VOLATILE removes defeats a duplicate check, and a comment in an object too big to
send, a big set's element, an xt argument or invalid UTF-8 never reaches the scan.
So the text's structure is checked against the JSON's: any table, chain, set or map
the text has that JSON doesn't list raises `net.firewall_comment` and compares the
text literally. A comment can't forge JSON's list, and without a forged header it
can't give a line another chain's place. Text with no JSON to check against only
has its own checks (a quote out of balance, a header twice), with `json_lost` saying
so. A fixed list over 50 elements a compared rule uses is compared by its hash, so
refreshing one (a cron job) shows as a change, as it would at 50 or fewer.

Limits: rule order isn't in either key; a chain removed between the two listings
raises the finding once; a big list no compared rule uses, or one filled as it runs,
isn't compared; a set of 50 or fewer filled as it runs churns, as text always did.

## After Phase 4: the pack application

John's idea (2026-10-30): a separate application, in its own repository (John, 2026-10-31; at first
the packs repository) and entirely apart from Compromise Checker, that watches public sources for
new threats, proposes packs, gets a person's approval through a web
interface, and then uses AI to write them. It gets its own build plan,
started after Phase 4. What that plan starts from (agreed in outline):

- **Feeds, not scraping:** CISA's Known Exploited Vulnerabilities list,
  OSV, Ubuntu's and Red Hat's security data (OVAL/CSAF), the NVD API.
- **Versions from vendor data, never from the AI.** Fixed versions are
  filled in mechanically from the vendors' structured data; the AI writes
  the prose and proposes detections, and every draft is checked with the
  tool's own pack format (done means 10). Fetched advisories are
  untrusted text, as host text is to the advisor.
- **Approval before spending:** the AI drafts only threats a person has
  approved in the web interface.
- **Signing stays by hand.** The web interface approves drafts; it can't
  sign them. John signs each release on his own machine after seeing what
  changed, so a compromised web interface can't publish a pack.
- **No customer evidence**, ever: it reads only public data.
- **Its relation to the CVE response orchestrator** (a separate product
  idea with the same core: watching advisories, triage, human approval)
  to be settled in that plan.
