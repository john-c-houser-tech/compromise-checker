# Checking changed PAM modules against the distribution's own packages (2026-11-21)

Issue #189, for #185. Draft 1, for John to read before any code.

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
  `dl.rockylinux.org` and `repo.almalinux.org`, plus their vault hosts
  if old versions live there (step V.1 finds out). One setting replaces them with the
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
- **No new Python dependency** if V.1 confirms it: `gpgv` is already on Ubuntu and Rocky (apt and
  dnf rely on it). Reading Ubuntu's `.deb` data needs zstd, which Python 3.12 lacks. The options
  are the `zstandard` package or the system `zstd` program, decided in V.1.

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
   nothing catches. With the cache the cost is one fetch per package version. I'd say all of them,
   but as a second step after the changed-only version works.
4. **Later, `package.changed`:** the same check could cover every critical path it watches (sshd,
   sudo, the loader, and so on). This plan stops at PAM.

## Steps (one pull request each)

- **V.1 Prove the chains by hand.** On one Ubuntu 24.04 and one Rocky 9 package: `gpgv` on
  `InRelease`, `gpgv` on an rpm's header signature, a range request for the header, zstd, and
  where older versions live **on both systems**. For Ubuntu that means a `libpam-modules` version
  that has dropped off `-updates`: whether a dated copy has it, which key signs that copy's
  `InRelease`, how far back the copies reach, and whether Launchpad's publishing date picks the
  right copy. For Rocky and AlmaLinux, it means the main repositories against the vault. Output: a
  short note in this file. No product code.
- **V.2 The verifier** (`checker/verify/`): fetch, check signatures, read file hashes, cache.
  Tested offline with packages built and signed by a test key, plus recorded real signed indexes.
- **V.3 Collector: owner hints.** The owner and architecture of each file in a PAM module
  directory (reusing #188's `record_pam_owners`), kept out of the comparison. Collector version
  bump.
- **V.4 The step and its settings:** run after collection, save `official_files`, the on/off and
  mirror settings, notes in the report and web pages.
- **V.5 The check:** `pam.changes` uses the results. The tests are the ten attacks above, end to
  end.
- **V.6 Docs and proof:** `docs/checks.md`, the security and privacy policy, the install page's
  outbound hosts, and a scoring calibration rerun. Then a Linode proof on Ubuntu 24.04 and Rocky 9
  (a real PAM update should read low, a swapped module high). Cents, with one OK from John.

Each PR gets two independent agent reviews, and V.2 and V.5 also get a security review, before
John merges. V.2–V.5 can't help anyone until all of them are in, so they ride to main together.
