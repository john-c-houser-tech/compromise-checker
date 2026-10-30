# Phase 4 build plan — 2026-10-30

> **Status: DRAFT 1, 2026-10-30** — for John's review. Nothing built yet.
> Decisions D1–D8 below are open; each is asked on its own, with a
> recommendation.

**Goal (DESIGN.md §18, Phase 4):** when a new threat is published, an
organization can check its whole fleet against it within a day, from the
evidence it already holds where that evidence is enough. A threat pack, a
small signed file published apart from the tool, says which package
versions are vulnerable and fixed on each distribution, when the threat
was active in the wild, what settings reduce exposure, what to look for on
a host, and what to do. The tool verifies the pack's signature, applies it
to stored evidence at once, reports exposure separately from signs of
compromise, raises the host's prior when it was exposed during the window,
and focuses the timeline there. The AI advisor can draft a pack from
advisories the operator supplies, for a person to review. The first real
pack is PHP2Shell (DESIGN.md §10.2).

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
10. **Drafting.** `checker packs draft --from FILE…` asks the advisor (role
    5) for a pack from advisory text the operator saved; the draft is
    checked against the schema and against the text it was given (every
    version, date, CVE id and reference in the draft must appear in the
    supplied text), written unsigned to `packs/drafts/` for review, and
    never trusted until a person signs it.

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
- **The signing key never touches a server or CI.** John makes the key on
  his own machine and keeps it in 1Password plus an offline backup
  (DESIGN.md §10.4). Releases are signed by hand.
- **Vendor data, not upstream strings.** Fixed versions come from each
  vendor's advisory for each release (Ubuntu USN/OVAL, Red Hat errata,
  the Sury PPA's changelog), recorded in the pack with their source.
- **Exposure isn't compromise.** Being vulnerable raises the prior; it is
  never itself a sign of compromise.
- **No network by default.** Only `checker packs pull` downloads, and only
  when asked (policy §10, §11). Drafting reads files the operator saved;
  the tool fetches no advisory itself.
- **Spend is asked.** Drafting is an advisor request: estimated, shown and
  confirmed like the other roles. Eval runs need John's OK per run.

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
- Where packs live: `packs/` in the checker's home (active, retired,
  drafts), owner-only.

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
- The NouriLoop LLC public key in the tool's source; organization keys in
  `config.yaml` (`packs.trusted_keys`, each with a name), changed with
  `checker config` and recorded like other settings.
- `checker packs add FILE [--signature FILE.minisig]`: verifies, then
  copies into `packs/`. A pack whose id and version are already present
  with different content is refused. `checker packs list`, `show ID`,
  `retire ID`.
- Needs from John (D5): the key pair, made with `minisign -G` on his
  machine.

### 4.3 — Exposure

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

### 4.4 — Mitigations

- What a pack can name as a mitigation: settings the collector already
  reads (sshd, sysctl, systemd units, web server configuration) and, for
  PHP2Shell, PHP's ini settings, which it doesn't read yet (D4).
- Each mitigation reported as in place, missing, or not seen.

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

### 4.6 — Applying packs to stored evidence

- `checker analyze` applies every active pack; an analysis records which
  packs and versions it applied, so reports are reproducible. Adding a
  pack and running `checker analyze --all` re-analyses each host's latest
  bundle; scheduled runs (`checker run`) apply packs as they are.
- A newly added pack that finds a host exposed or a detection firing is a
  "needs a look" item in `checker run`.
- Golden tests: the golden cases analysed with and without a test pack.

### 4.7 — Distribution

- The public packs repository, `compromise-checker-packs` (D6): one
  directory per pack, `PACK.yaml` and `PACK.yaml.minisig`, a README on how
  to verify, CC BY 4.0. Releases are signed by hand.
- `checker packs pull`: downloads the repository's release index and new
  packs over HTTPS, verifies each before anything is kept, and says what
  changed. Air-gapped sites copy the files across and use `packs add`.
- The public key published on nouriloop.com (the site is GitHub Pages), so
  it can be checked against the copy in the tool.

### 4.8 — The PHP2Shell pack

- Written from the advisories: CISA's alert, the vendors' errata for
  Ubuntu 22.04, 24.04 and 26.04, RHEL (and its rebuilds) 9 and 10, and the
  Sury PPA, with the fixed version for each release and its source. Every
  version and date checked against the vendor's own page before signing.
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

### 4.9 — Drafting (advisor role 5)

- `checker packs draft --from FILE… [--show]`: the operator's saved
  advisories (text, HTML or Markdown files; the tool fetches nothing)
  are the case; the answer is a pack in the schema.
- Checked before anyone sees it: the schema; every CVE id, version, date
  and URL in the draft appears in the supplied text; package names exist
  for that distribution (from the packages in stored evidence, where
  there are any); detections use only the language's terms.
- Written unsigned to `packs/drafts/ID-vN.yaml` with what was checked and
  what wasn't; the report of the run names the model, like every advisor
  answer. A draft is never applied until a person signs and adds it.
- The eval: drafts from the PHP2Shell advisories compared with the
  reviewed pack (API spend with John's OK per run).

### 4.10 — Policy, docs and README

- Policy §11 (threat packs and trust) brought up to date with what was
  built; §10 (`checker packs pull` downloads); §9 (role 5: advisory text
  the operator supplies is sent). Wording to John first.
- `docs/packs.md`: writing, checking, signing, adding, pulling, retiring a
  pack; the detection language; how exposure and the prior are computed.
- DESIGN.md §10 and §11.2 as built; README "Status: Phase 4 complete".

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
- **D5. The signing key. Decided 2026-10-30 (John): he makes it at 4.8;
  a test key until then.** John makes a minisign key pair on his machine
  (`minisign -G`), keeps the secret key and its password in 1Password with
  an offline backup, and gives me the public key to put in the tool and on
  nouriloop.com.
- **D6. The packs repository. Decided 2026-10-30 (John): create it at
  4.7.** A new public repository,
  `john-c-houser-tech/compromise-checker-packs`, under CC BY 4.0.
  Creating it is outward-facing, so it waits for John's word.
- **D7. Spend on throwaway servers. Decided 2026-10-30 (John): Phase 2's
  rules: one OK per PR, $10 cap, stop and tell at $5.** The PHP2Shell proof needs a few
  short-lived Linodes, as in Phase 2. *Recommendation:* the same rules: one
  OK per PR, a $10 cap, stop and tell at $5.
- **D8. What drafting sends.** The advisory text the operator supplies
  goes to the model, and, to check package names, nothing from the
  evidence (names are checked locally afterwards). *Recommendation:* that,
  with `--show` printing the request first, like the other roles.

## Order

4.0 → 4.1 → 4.2 can go first, in that order, without any decision but D5
(4.2 can be built and tested with a test key; the real key goes in when
John has made it). 4.3 needs D2 and D3; 4.4 needs D4; 4.5 needs D1; 4.7
needs D6; 4.8 needs D7; 4.9 needs D8. 4.10 last.
