# Checking changed PAM modules against the distribution's own packages (2026-11-21)

Issue #189, for #185. Draft 1; all four open decisions settled by John on 2026-11-21.

## The problem

`pam.changes` raises **"A PAM module file changed" (high)** for every changed module. A routine
update of PAM therefore reads as a break-in: on the demo's `staging-1`, Ubuntu's automatic updates
replaced 46 modules and the server read 99.96%, "Strong signs of a break-in".

Two attempts to explain such changes from records on the server failed security review (#186,
reverted in #187; #188, closed). With root, an intruder can forge every one of those records: the
package database, dpkg's checksum lists and file ownership (through `dpkg-divert`), the journal's
"systemd" lines, and change times (by setting the clock back). So nothing on the server may lower
this finding.

## The idea

When a PAM module has changed, **the checker's own machine** fetches the distribution's official
package for the version the server says it has installed, checks that package's signature with
keys shipped inside the checker, and compares the module's SHA-256 with the file at the same path
in that package.

- **A match explains the change.** It proves the file on the server is the distribution's own file
  for that path, whatever else on the server was forged.
- **Anything else leaves the finding high.** A forged version number finds no package. A rebuilt
  package isn't in the signed index. A trojaned module doesn't match.

The server's claims (which package owns the file, its version, its architecture) are only used to
**find** the package. They are never trusted as evidence. A false claim can only make the lookup
fail, and then the finding stays high.

## What is trusted, for each system

### Ubuntu (22.04, 24.04, 26.04)

1. `dists/<suite>/InRelease` for the release, `-updates` and `-security` suites, checked with
   `gpgv` against Ubuntu's archive signing key, shipped in the checker
   (`checker/verify/keys/`).
2. The `main/binary-<arch>/Packages.xz` hash from that signed file, then the package's own
   `SHA256` line from `Packages`.
3. The `.deb`'s SHA-256 against that line, then the module's SHA-256 read from the `.deb`'s data
   archive, in memory. Nothing is unpacked to disk.

**Older versions.** The `-updates` and `-security` lists hold only the newest version of each
package. Once Ubuntu releases the next PAM update, the previous one drops off. A server that
updated and then missed the next update before its check would find no package, and stay high:
the same false alarm as today. So when the server's version isn't in the current lists, the
checker looks in **Ubuntu's dated archive copies** (`snapshot.ubuntu.com/ubuntu/<time>/`), which
carry their own signed `InRelease` and go through the same three steps.

- **Which date to ask for:** Launchpad's publishing history says when that version was published.
  That is only a hint for choosing the copy. The trust still comes from the copy's own signature.
  Without Launchpad, the checker tries a few dates between the baseline and the collection, taken
  from the checker's own records.
- **The copies only reach back to 2023.** An older version stays high, with a note saying so.

Ubuntu's PAM packages ship their modules under `/lib/<triplet>/security/` on 22.04 and under
`/usr/lib/...` later. With merged `/usr` the server reports either one. The comparison accepts only
that one known alias (the collector already reports it, `merged_dirs`), never any other path.

### Rocky Linux and AlmaLinux (9, 10)

1. The repository metadata (`repomd.xml` → `primary.xml`) is used only to **locate** the rpm and
   its checksum.
2. The trust comes from the rpm's own **header signature**, checked with `gpgv` against the
   vendor's key shipped in the checker. The header holds every file's SHA-256
   (`FILEDIGESTS`), so only the header is needed. It can be fetched with an HTTP range request
   instead of the whole package.
3. The header's name, version, release and architecture must equal the server's claim, and the
   module's path must appear in it with the matching digest.

**Older versions** (V.1): the main repositories list only the newest pam. Each vault keeps a
repository for every minor release (Rocky 9.0–9.8, Alma 9.0–9.9 and 10.0–10.3), with every pam
version released in it, signed with the same key. A release such as `el9_8.1` names its minor
(9.8). A plain `el9` doesn't, so the checker tries the minors from the newest down.

### Red Hat Enterprise Linux itself

Red Hat's packages need a subscription to download, so the checker can't fetch them by default.
Changed modules stay high, with a note saying why. Pointing the checker at the organization's own
Red Hat mirror (Satellite) could come later.

## Where it runs

Checks don't use the network. They are pure functions of what was collected, which keeps reports
reproducible and tests offline. So verification is **its own step**, after a collection and before
the checks:

- For each changed (or new) file in a PAM module directory, it looks up the package and records
  the outcome in a new section of the collection, `official_files`:
  `matched`, `differs`, or `not_checked` with a reason (no network, package not in the archive,
  signature failed, older collector, Red Hat without a mirror, too large, timed out).
- The section is saved with the collection, so a report rebuilt later gives the same answer
  without fetching again.
- `pam.changes` reads that section. A collection without it (older checker, step turned off)
  behaves exactly as today.

## What the check reports

| Outcome | Finding |
|---|---|
| Every changed module `matched` | **One low finding**, "PAM modules updated by Ubuntu's own packages", listing the packages and versions |
| A module `differs` from the official file | **High, per file**, "A PAM module differs from Ubuntu's package for the installed version". This is the strongest version of the finding: the real file was available and didn't match |
| `matched`, but an older version than at the baseline | **Medium**, "PAM was moved back to an older Ubuntu package", naming both versions (decision 2) |
| `not_checked` | **High, per file**, as today, with the reason shown |

A mix of results is reported as a mix: the matched modules get one low finding, and the rest stay
high, each on its own.

## How the attacks from the reviews fail

These become the tests (step V.5), each played through the real collector on a test root, then the
snapshot, verification against recorded package data, and the checks:

1. **dpkg diversion** (`dpkg-divert --package vim … pam_unix.so`, path added to `vim.list`): the
   owner hint says `vim`, and vim's package has no such file. Stays high.
2. **Made-up upgrade** (`Version:` edited in `/var/lib/dpkg/status`, `.md5sums` rewritten): that
   version isn't in the signed index, or its file doesn't match. Stays high.
3. **Rebuilt package with a bumped version:** not in the signed index. Stays high.
4. **Fake "systemd" journal lines:** no longer used for anything.
5. **Clock set back:** no times are used.
6. **A signed module copied over another**, e.g. `pam_permit.so` (always says yes) over
   `pam_unix.so`. Both are in the same signed package, so the comparison is **by path**.
   `pam_unix.so` must match the package's `pam_unix.so`. Stays high.
7. **A module from another release or architecture**, e.g. 22.04's `pam_unix.so` on 24.04: the
   claimed version must match too. Stays high.
8. **Tampered or replayed download** (someone between the checker and the mirror): the signature
   fails, or an old index only offers older real packages (see the downgrade decision below).
9. **Lying hints** (owner, version, architecture): the lookup fails. Stays high.
10. **Hostile package contents** (paths with `..`, links, huge or endlessly compressed data): parsed
    in memory with size caps, links never followed. Not checked, so it stays high.

## Network, privacy and cost

- **Hosts the checker machine needs to reach:** `archive.ubuntu.com`, `security.ubuntu.com` and
  `ports.ubuntu.com` (arm64), `snapshot.ubuntu.com` and `api.launchpad.net` (older versions);
  `dl.rockylinux.org` (its `/vault/` too) and `repo.almalinux.org` plus `vault.almalinux.org`
  (older versions, V.1). One setting replaces them with the
  organization's own mirror.
- **Without network access** everything stays high, with the note saying so. Nothing fails.
- **What leaves the machine:** requests for public package files by name and version. No server
  names, addresses or findings. The mirror's operator can see that someone fetched, say,
  `libpam-modules 1.5.3-5ubuntu5.4`. This goes in the security and privacy policy and on the
  install page.
- **Caching:** the verified per-file hashes are kept by system, package, version and architecture
  under `CHECKER_HOME`, so each package is fetched once for the whole fleet. Only verified data is
  cached. Signed indexes are kept for a few hours.
- **Limits:** a size cap per download, a time cap for the whole step (about a minute), and HTTPS
  where the host offers it (the signatures carry the trust either way).
- **One new Python dependency, for Ubuntu's packages only** (V.1): Ubuntu's `.deb` data is zstd,
  and the checker machine runs Python 3.12 on Ubuntu 24.04 and Rocky 9 and 10, which can't read
  it. Python 3.14 can (`compression.zstd`). So: `backports.zstd; python_version < "3.14"`, the
  same interface, dropped once every checker machine has 3.14. `gpgv` comes with apt on Ubuntu.
  On Rocky the installer adds `gnupg2` to be sure, checked in V.6's install proof.

## Open decisions

1. **On by default: DECIDED yes (John, 2026-11-21).** It only fetches public files, and without it
   every PAM update reads as a break-in. An organization that allows no outbound access turns it
   off or names its mirror.
2. **A downgrade to an older official version.** The module matches a real signed package, but an
   older one than at the baseline (an intruder could put back a version with a known flaw).
   **DECIDED medium (John, 2026-11-21):** "PAM was moved back to an older Ubuntu package", naming
   both versions.
3. **Verify every module at each collection, or only the changed ones?** Checking all of them at
   the first collection would also catch a module trojaned **before** the baseline, which today
   nothing catches. With the cache the cost is one fetch per package version. **DECIDED (John,
   2026-11-21): all of them, as step V.7, after the changed-only version is proven.**
4. **Later, `package.changed`:** the same check could cover every critical path it watches (sshd,
   sudo, the loader, and so on). **DECIDED (John, 2026-11-21): this plan stays PAM-only.** After
   V.7 works, `package.changed` gets its own issue, decided then from how the PAM version holds up
   in use.

5. **Ubuntu Pro (ESM) packages: OPEN, for later.** Servers attached to Ubuntu Pro also get
   updates from ESM, Ubuntu's extended support: separate servers (`esm.ubuntu.com`) that need
   the organization's Pro token, with packages signed by another key. Today such a version is
   reported "an Ubuntu Pro (ESM) version: can't be checked yet" and stays high (V.2 names it
   from the `+esm` in the version, without searching). This matters most for **Ubuntu 22.04
   from April 2027**, when its free updates end and fixes come only through ESM, and for 24.04
   in 2029. Many organizations, government ones among them, run Pro. Supporting it means a
   setting for the Pro token on the checker's machine (kept like the advisor's key), the ESM
   signing keys pinned, and the ESM lists' own `InRelease` chain. To decide before April 2027.

## Steps (one pull request each)

- **V.1 Prove the chains by hand. DONE 2026-11-21** (results below). On one Ubuntu 24.04 and one Rocky 9 package: `gpgv` on
  `InRelease`, `gpgv` on an rpm's header signature, a range request for the header, zstd, and
  where older versions live **on both systems**. For Ubuntu that means a `libpam-modules` version
  that has dropped off `-updates`: whether a dated copy has it, which key signs that copy's
  `InRelease`, how far back the copies reach, and whether Launchpad's publishing date picks the
  right copy. For Rocky and AlmaLinux, it means the main repositories against the vault. Output: a
  short note in this file. No product code.
- **V.2 The verifier** (`checker/verify/`): fetch, check signatures, read file hashes, cache.
  Tested offline with packages built and signed by a test key, plus recorded real signed indexes.
- **V.3 Collector: owner hints. DONE 2026-11-21** (below). The owner and architecture of each file in a PAM module
  directory (reusing #188's `record_pam_owners`), kept out of the comparison. Collector version
  bump.
- **V.4 The step and its settings: DONE 2026-11-21** (below). run after collection, save `official_files`, the on/off and
  mirror settings, notes in the report and web pages.
- **Time for the step (V.4, from a side note on #210):** V.2 gives the whole run one deadline
  (about a minute). A server on the newest version takes 2-5 seconds; one an update behind,
  needing a dated copy, took 15-18 seconds live. Several servers behind on different versions
  in one run would use the minute up and stay high ("out of time"). V.4 settles it: a share of
  time per server as well as a cap for the run, signed lists kept on disk for a few hours (as
  "Caching" above says; V.2 keeps them only for the run), and the verified results already
  cached by version, so a version is fetched once for the whole fleet.
- **Finding the version (V.4, from #211's reviews, checked on five real systems):** an owner
  with an architecture is looked up as `packages["<name> <arch>"]`. dpkg names the architecture
  only for Multi-Arch: same packages, so an owner without one (Architecture: all, or Multi-Arch:
  no, such as libpam-tmpdir) is the **single** `packages` entry with that name; none or several
  is "not checked". Also "not checked", with the reason: an owner marked `several` (more than
  one package lists the path), an owner with no `packages` entry (dpkg's half-installed states,
  which the package list leaves out), two rpm entries for one name and architecture (an
  interrupted dnf), a `packages_pending` collection (rpm's log not yet written back), and
  directories (the owner list names them too; only files have a digest).
- **V.5 The check: DONE 2026-11-21** (below). `pam.changes` uses the results. The tests are the ten attacks above, end to
  end, plus the ones below.
- **Held to the baseline (V.4/V.5, from the #210 security review).** Every field the verifier
  is given is the server's claim, so a match only proves "a genuine file for the system,
  release, package and version the server named". A 24.04 server could copy 22.04's genuine
  `pam_unix.so` into place and claim 22.04, or claim an old version with a known flaw for one
  module only. So the step asks only with the **system, release and architecture an earlier
  collection recorded**, and doesn't explain the change (stays high, with the reason) when the
  current collection says otherwise. A module whose **owner package differs** from the
  baseline's, or whose version is lower than the baseline's (by real dpkg/rpm ordering), isn't
  explained either: the version case is decision 2's medium. Tests: the release switch, mixed
  versions inside one package, and an owner swap.
- **V.6 Docs and proof: DONE 2026-11-21** (below). `docs/checks.md`, the security and privacy policy, the install page's
  outbound hosts, and a scoring calibration rerun. Then a Linode proof on Ubuntu 24.04 and Rocky 9
  (a real PAM update should read low, a swapped module high). Cents, with one OK from John.

- **V.7 Every module, not only the changed ones** (decision 3): check all PAM modules at the
  first collection and now and again after, so a module swapped before the baseline shows as
  "differs from the package". Starts after V.6's proof passes.

Each PR gets two independent agent reviews, and V.2 and V.5 also get a security review, before
John merges. V.2–V.5 can't help anyone until all of them are in, so they ride to main together.

## V.1 results (2026-11-21, by hand from the laptop, no product code)

Spike scripts walked each chain against the real servers, for `libpam-modules` (Ubuntu) and `pam`
(Rocky, Alma), reading `pam_unix.so` and `pam_permit.so`.

**Ubuntu: works.**
- `InRelease` for 22.04, 24.04 and 26.04 (release, `-updates`, `-security`) all verify with `gpgv`
  against one key: *Ubuntu Archive Automatic Signing Key (2018)*, `F6EC B376 2474 EDA9 D21B 7022
  8719 20D1 991B C93C`.
- `InRelease` → `Packages.xz` → `.deb` → the module's SHA-256: every hash matched, read in memory.
- Paths: 22.04 ships modules in `/lib/x86_64-linux-gnu/security/`, 24.04 in `/usr/lib/...`. The
  merged-`/usr` alias is needed.
- **Older versions:** `-updates` lists only `1.5.3-5ubuntu5.7`. Launchpad's publishing history
  (`getPublishedBinaries`, no sign-in) lists every version with when it was published and
  superseded. The dated copy from inside that window (`snapshot.ubuntu.com/ubuntu/20260801T000000Z/`
  for 5ubuntu5.6, `20240701T000000Z` for 5ubuntu5.1) has a signed `InRelease` with the same key,
  and the whole chain passed. Copies start in early 2023: a 2023-03-01 copy exists, a 2023-01-01
  one is 404. Only the Release, Updates and Security pockets count. Launchpad also lists Proposed
  and Deleted entries.
- Ubuntu's `InRelease` has no `Valid-Until`, so an old list can be replayed. That can only offer
  older real packages, which decision 2 already makes medium.

**Rocky Linux and AlmaLinux, 9 and 10: works, two ways.**
- `repomd.xml.asc` exists and verifies for all four (Rocky 9 `21CB 256A … 350D 275D`, Rocky 10
  `FC22 6859 … 6FED FC85`, Alma 9 `BF18 AC28 … B86B 3716`, Alma 10 `EE6D B7B9 … C2A1 E572`).
  `repomd` → `primary` → the rpm's SHA-256 matched in every case.
- The rpm's own RSA header signature (tag 268) verifies with `gpgv` as a detached signature over
  the header. A **range request** (HTTP 206, using `primary`'s `header-range`) fetches 72–124 KB
  instead of the whole 520–580 KB package.
- `FILEDIGESTS` is SHA-256 (algorithm 8) on all four. For both modules it equals the real file in
  the package's payload (checked with `bsdtar`).
- Older versions: see "Older versions" under Rocky and AlmaLinux above. Vault repositories verify
  with the same keys.

**Findings for V.2:**
- **User-Agent:** `archive.ubuntu.com` answers **403** to Python's default User-Agent for package
  files (lists are fine). Send `compromise-checker/<version>`, nothing that names the user.
- **Parse only what was signed:** `gpgv --output` gives the signed text of `InRelease`. Parse that,
  never the file as downloaded. Require `VALIDSIG` with the pinned fingerprint, with `GNUPGHOME`
  set to an empty private folder, so no other keyring counts.
- **Decompression caps:** use the streaming decompressor with a maximum output size, never
  one-shot `decompress()`.
- **Keys:** ship five keys (one Ubuntu key serves all three releases, plus one each for
  Rocky 9 and 10 and Alma 9 and 10) in `checker/verify/keys/`, fingerprints checked against two sources when added.
- **Untested:** arm64 (`ports.ubuntu.com`, `aarch64` repositories) and Red Hat itself.

## V.6: the proof on real servers (2026-11-21)

`tests/integration/pam_update_proof.py`, on new Linodes (Ubuntu 24.04, Rocky Linux 9): PAM moved
back to an older official version and a baseline taken; PAM updated the ordinary way, collected
and analysed with verification on, as `checker run` does; then `pam_permit.so` copied over
`pam_unix.so`, collected and analysed again.

| | After the update | After the swap |
|---|---|---|
| Ubuntu 24.04, libpam-modules 1.5.3-5ubuntu5 to 5ubuntu5.7 | one low `official_update`, 44 files matched, Low (0.0297), 10.4 s verifying | high `differs`, High (0.8596) |
| Rocky Linux 9, pam 1.5.1-28.el9_8.1 to 29.el9 | one low `official_update`, 53 files and links matched, Low (0.0439), 0.5 s | high `differs`, Critical (0.9018) |

The first real run found two things the built tests hadn't, both fixed before the passing run:
Rocky's `pam_unix_acct.so` and its siblings are links to `pam_unix.so` that every update
re-creates, so links are now checked by their target against the package's own link (results
version 2); and an added file's own mode and owner were read as changes (now only for a file that
was there before). Three runs, six Nanodes for minutes each: about two cents.

Also in V.6: the installer adds `gpgv` (Ubuntu) and `gnupg2` (Rocky), and the install guide says
what the machine reaches out to. The scoring calibration (fresh servers) isn't rerun: a fresh
server has no baseline to differ from, so nothing here changes its score; the golden cases
moved only in the scoring version's number.

## V.5 as built (2026-11-21)

- `pam.changes` reads `Context.official`, and a result counts only if the hash it compared is the
  file's hash in this collection. For each new or changed file in a PAM module directory:
  - matched, `older_than_baseline is False`, not `new_package`: counted into **one low finding**,
    "PAM modules updated by Ubuntu's own packages" (variant `official_update`), with the
    packages and their versions;
  - matched but older (`downgrade`, decision 2), from a package new since the baseline
    (`new_package`), or the baseline's version unknown (`version_unknown`): **medium**, one per
    file. The file is genuine, so the worst it can be is a downgrade, which is medium;
  - `differs`: **high**, "A PAM module differs from Ubuntu's package for the installed version";
  - anything else: **high**, as before, with "not checked against Ubuntu's package: <reason>"
    in the summary.
- Checks version 18. Plain words for each variant in the web interface; `docs/checks.md`.
- The attack list: 1 (diversion) and 9 (lying hints) are "owner isn't the baseline's" or no
  package to match; 2 and 3 (made-up, rebuilt versions) aren't in the signed lists; 4 and 5
  (journal, clock) are no longer used; 6 (pam_permit over pam_unix) is `differs`; 7 (another
  release) is "the release isn't the baseline's"; 8 and 10 (tampering, hostile packages) fail in
  the verifier. Each has a test in `tests/test_verify.py` or `tests/test_official.py`, on built
  snapshots and a fake verifier; the real collector on real servers is V.6's proof.
- **From #214's two reviews:**
  - A version older than the newest seen since the baseline (the previous collection's, or
    what its results had seen, carried on from one to the next) is a `downgrade` too, though
    newer than the baseline's: going back from a fix to a still-vulnerable version.
  - The package's own file whose mode, uid or gid changed stays high (the verifier compares
    content only).
  - The update's one finding joins no group in scoring (scoring version 5), so it can't tie
    other findings about its paths together and cut them.
  - A whitelist rule must name `differs` to cover it; the high findings that couldn't be
    checked now have variants (`added`, `changed`), so rules for them pin them.
  - A host's OS id that isn't text can't stop the check; reasons say what kept a file from
    being checked; `new_package` only when the baseline's complete list lacked the package; the
    same version with its files replaced says so.
  - Once a run finds the servers out of reach, its later hosts still get answers from what is
    cached (no downloads), instead of none.
- End to end: the same update that read as one high finding per module without the results now
  reads as one low finding, and the host's probability drops.

## V.4 as built (2026-11-21)

- `checker/official.py` is the step. `analyze()` takes the collection's stored results when they
  were made against the same baseline; otherwise, given a verifier, it checks now and stores them
  encrypted beside the bundle (derived kind `official`). Scheduled runs and `checker analyze`
  give it one (each server its own `verify.seconds_per_server`, default 60, and the shared caches);
  a report rebuilt gives none, so it never downloads. The results reach the checks as
  `Context.official`; V.5 uses them.
- Checked: files added or changed in content since the baseline in the PAM module directories
  themselves (`/etc/security/` isn't one). Each result: matched, differs, absent, link or
  not_checked with its reason, plus the package, version and architecture asked about, the
  baseline's version and whether this one is older (by dpkg's or rpm's ordering).
- "Not checked" before anything is fetched: no baseline; the system or release isn't the
  baseline's; no owner recorded; `several`; an owner that isn't the baseline's; the package list
  not collected whole; not exactly one installed version of the owner.
- **Baselines from 0.1.3 have no owners** (side note on V.4): the owner can't be compared, so a
  file that was there at the baseline is checked only if its owning package was installed then
  too, the version is still compared with the baseline's package list, and the assessment's notes
  say an owner swap can't be ruled out until a new baseline is taken. **DECIDED (John,
  2026-11-21): the note is enough;** the checker doesn't prompt for a new baseline after an
  upgrade (that would also accept whatever changed since the last one).
- Ubuntu's signed lists are kept on disk (`CHECKER_HOME/cache/signed-lists`) and checked again
  every time they are used: an InRelease for six hours (a dated copy's for good), an index by
  its hash. Live: the first lookup of an older version took 22 s, the next server's 0.9 s.
- Settings: `verify.enabled` (on), `verify.seconds_per_server`, `verify.ubuntu_archive`,
  `verify.rocky`, `verify.almalinux`. `checker config show` and the security and privacy policy
  (sections 2 and 10) say what is downloaded and that no server's name, finding or evidence is
  sent.
- The assessment carries `official_files` (counts by outcome, reasons) and a note for every
  reason a changed module wasn't checked. Tests never download (an autouse guard).
- **From #213's two reviews:**
  - A changed module the baseline recorded no owner for (its owner list otherwise complete) is
    not checked; a baseline owner list that wasn't complete counts as unknown, like 0.1.3's.
  - Every result says the baseline's version and whether this one is older, `None` when not
    known (an incomplete baseline package list, say). **For V.5: only `older_than_baseline is
    False` may let a change count as an update**, and a module added by a package that wasn't
    installed at the baseline (`new_package`) is never "updated by the distribution".
  - The package's architecture is held to the baseline's; a package listed twice for one name
    and architecture (snapshot version 18 marks it) isn't checked.
  - Rocky Linux and AlmaLinux are held to the baseline's major release only (9.5 to 9.6 is an
    ordinary update); Ubuntu to its whole release.
  - Each result records the hash it compared (V.5 should require it to be the current file's).
  - Failures on this machine's side (network, time, gpgv, an error) are marked `transient`,
    stored, and asked again whenever a verifier is given. In one run, once a host finds the
    distributions' servers out of reach, its later hosts aren't asked (checked next run).
  - One lookup per package version, however many modules it changed. Nothing the server sends
    can stop the step: each file's check fails alone, as "not checked".
  - The lists cache keeps a list only once it has checked out, drops a kept copy that no longer
    does (fetching once more), reads at most the size limit and never through a link.
  - The clock for a server starts at its first download, not before its bundle is parsed.
  - `verify.older_versions` (on) turns off the dated copies, Launchpad and the vaults; the
    policy and `config show` say a mirror replaces only the current lists, and what a request
    reveals (release, version, architecture, the User-Agent, and by its timing that some
    server's PAM changed).

## V.3 as built (2026-11-21)

- The collector sends `pam_module_owner` (path under the walk's merged-`/usr` form, package, and
  architecture when dpkg's `<name>:<arch>.list` or rpm's header names it) and always a
  `pam_owners_summary`. A diverted module is owned by the diverting package, with no
  architecture. The snapshot keeps them in `live["pam_owners"]`, never compared (snapshot
  version 17). The version comes from the package list (`packages`, keyed by name and
  architecture), so the collector sends no versions of its own.
- From the reviews: only the paths the PAM listing walks count (the directory, then one or two
  levels, `*` never crossing `/`), since `/usr/lib/jvm/.../security/` and Python's `security`
  packages would otherwise fill the limit first. Paths over 4,096 bytes, and package or
  architecture names that don't look like dpkg's or rpm's, are left out and the owners called
  incomplete. (A path that isn't UTF-8 is kept since #212: it is written the way the walk
  writes the same path.) A path more than one package lists is marked `several`. The
  snapshot believes "complete" only when the summary's count matches the records it kept.

## V.2 as built (PR #210, 2026-11-21)

- **Where to look, for rpm:** the standard file name, without downloading the repository list:
  `<repo>/BaseOS|AppStream/x86_64/os/Packages/<name>-<version>-<release>.<arch>.rpm`. Rocky puts
  packages in a folder per first letter (`Packages/p/`), AlmaLinux in one flat folder. The
  current repositories first, then the vault, starting with the minor that a release such as
  `el9_8.1` names.
- **`%ghost` files** (listed in a package, never shipped, so no digest) are skipped. sssd-client,
  which ships `pam_sss.so`, has one.
- **Ubuntu:** the archive over HTTPS. `main` in every suite before `universe`, index files by
  their hash name first (a mirror part-way through an update still has them), and a list that
  fails is skipped and named in the reason.
- **Downloads:** one deadline for the run, held even while a server is slow to send its headers,
  and redirects only within the same host, never away from HTTPS.
- **Not covered, all left high:** Ubuntu Pro/ESM versions (decision 5), AlmaLinux 10's `x86_64_v2` builds, and
  arm64. If Ubuntu ever signs with a second, new key, every Ubuntu check fails until that key is
  pinned.
