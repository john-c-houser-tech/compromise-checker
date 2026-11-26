# Judging exposure by an application's version, for REDCap (2026-11-26)

Draft 1. The open decisions are near the end of this plan; nothing is built until John has
settled them.

## The problem

CVE-2026-90817 lets anyone who knows one public survey's hash run code on a REDCap server, with a
single unauthenticated request. CISA added it to KEV on 2026-11-18, and Unit 42 reported
attacks installing Monero miners on 2026-10-07. REDCap is widely used by universities, hospitals
and public-health departments, so it meets the scope rule: exploited, with signs on the server.

A pack can't describe it today. Every pack judges exposure from installed packages
(`exposure.packages`, at least one entry), and REDCap isn't installed as a package. Institutions
download it from Vanderbilt under a licence and unpack it into a web root.

The built-in checks already catch most of the known attack: `web.worker_child` (bash started from
php-fpm), `process.miner`, `files.scratch` and `process.executable` (the miner in `/var/tmp`),
`ssh.authorized_keys`, `persistence.changes` (cron) and `history.disabled`. What's missing is the
pack's part: when a server was open to the attack, which raises the weight of everything found
in that window, and detections written for this campaign.

## What the bundle already has

REDCap keeps each version's code in its own folder, beside the shared entry points:

```
/var/www/html/redcap/index.php, surveys/, api/, temp/, edocs/ …
/var/www/html/redcap/redcap_v17.3.9/…     the version that was running
/var/www/html/redcap/redcap_v17.3.10/…    unpacked for the upgrade
```

Old version folders stay behind after an upgrade. The collector already sends every script file
in the web roots with its path, times and SHA-256 (`web_file`, "Directory walks" in
`docs/collector-modules.md`), so a bundle from a REDCap server lists every `redcap_vX.Y.Z` folder
on disk and when its files were written. **No collector change is needed.** The walk takes up to
500,000 files; how long several version folders take within the web roots' time share is for
step A.1 to measure.

## The design

### An `applications` list in a pack's exposure

Beside `packages`, an exposure can list applications found by a version folder:

```yaml
exposure:
  applications:
    - name: REDCap
      folder: "redcap_v*"                 # the folder whose name carries the version
      versions: "16.0.*"                  # the release line this entry judges
      fixed: "16.0.49"
      source: https://www.cve.org/CVERecord?id=CVE-2026-90817
    - name: REDCap
      folder: "redcap_v*"
      versions: "17.3.*"
      fixed: "17.3.10"
      source: https://www.cve.org/CVERecord?id=CVE-2026-90817
    - name: REDCap
      folder: "redcap_v*"
      versions: "*"
      affected_from: "13.3.0"             # older versions aren't affected
      fixed: "17.4.4"                     # every other line: the Standard fix
      source: https://www.cve.org/CVERecord?id=CVE-2026-90817
```

- `packages` may then be empty, as long as `applications` isn't.
- **Versions compare as dotted numbers** (`17.3.10` above `17.3.9`), with no epoch or revision.
- **An entry's `versions` glob** picks the release line, like a package entry's. A version that
  several entries match is judged by the most specific glob, the one with more literal
  characters, so `17.3.*` decides 17.3.x before `*` does. Two entries for the same application
  that are equally specific and can both match a version make the pack invalid: `checker packs
  check` refuses it. This is where application entries differ from package entries, where any
  vulnerable match wins (decision 4).
- **`affected_from`** is the lowest affected version. Below it, the install is "not affected".
- **Older checkers refuse a pack with `applications`,** as checker 0.1.1 refused `native`. So the
  REDCap pack goes out only after a checker release that reads it (step A.4).

### Finding an install and its running version

- **An install** is a folder in a collected web root holding at least one folder that matches
  `folder`, with a script inside it. Each install is judged on its own, so two REDCap sites on one
  server get two results.
- **The running version** is the newest matching folder in that install (decision 2).
- **When a fix arrived:** the earliest `ctime` among the files of the first fixed folder, or,
  where the bundles go back far enough, the first collection that listed it, whichever is
  earlier. That ends the install's exposure, as a package's history does now.
- **Coverage notes:**
  - "REDCap's running version is read from the newest version folder on disk; an upgrade unpacked
    but not finished in the browser reads as the new version."
  - "Only installs in the collected web roots are seen." That's the default roots, or a host's own
    `--web-root` list.

### Reports

An install reads like a package: vulnerable, fixed, can't judge, or not affected. It's named by
its folder (`/var/www/html/redcap`) and its version (`REDCap 17.3.9`), with the fix that applies
(`17.3.10 LTS`). A version folder whose name doesn't parse (`redcap_v17.3.9-test`) gives "can't
judge", never "fixed".

## The REDCap pack (step A.5)

- **Window:** opens 2026-09-20, when the CVE was published. First seen in the wild by
  2026-10-07, Unit 42's note; Securifera's write-up came out on 2026-09-27, so the first attacks
  may be earlier.
- **Exposure:** the three entries above. Lines from 13.3.0 with no fix of their own (for example
  16.1 to 17.2) count as vulnerable until they reach a fixed version (decision 5).
- **Detections,** from Unit 42's chain, written in the event and snapshot types the format has.
  A.5 checks each one against real bundle fields:
  - the exploit request, `route=DataImportController` with `__passthru`, on `/surveys/` (only
    where access logs are collected)
  - a process named `syslog-ng-<hash>`
  - a folder `/var/tmp/.syslog-*`
  - a connection to `auto.c3pool.org`, if the collected network data holds names; otherwise
    left out
  - a cron entry fetching `*.jpg` into `bash`
- **Mitigation:** turning off public surveys blocks the known route. A pack can't read REDCap's
  settings, so this goes in the remediation text rather than as a checked mitigation.
- **Remediation:** upgrade to 16.0.49 LTS, 17.3.10 LTS or 17.4.4 Standard. Where the install was
  exposed, treat whatever the web account could read as disclosed: REDCap's database password and
  salt in `database.php`, and the project data.

## Open decisions

1. **The format change.** An optional `applications` list beside `packages`, keeping `format: 1`,
   as `native` did. **DECIDED 2026-11-26 (John): yes.** It needs a checker release before the pack
   can go out.
2. **The running version.** The newest version folder in each install. **DECIDED 2026-11-26
   (John): yes,** with the coverage note about unfinished upgrades. A later refinement could read the version from
   collected access logs, where REDCap's URLs carry `redcap_vX.Y.Z`.
3. **Only version-in-a-folder-name, for now.** Other web applications keep their version in a
   file's contents (WordPress in `wp-includes/version.php`), which the collector doesn't send.
   **DECIDED 2026-11-26 (John):** build only the folder-name form now, and decide on others when
   a threat needs one.
4. **Which entry decides.** The most specific glob, so a release line's own fix decides before the
   catch-all entry. **DECIDED 2026-11-26 (John): yes,** for application entries only; package
   entries keep "any vulnerable match wins". The alternative would call 17.3.10 LTS vulnerable
   because it's below 17.4.4.
5. **Lines with no fix.** Versions from 13.3.0 on a line with no fix of its own (16.1 to 17.2)
   count as vulnerable, with a reason saying to move to a fixed LTS or Standard release ("no fix
   on the 17.1 line; upgrade to 17.3.10 LTS or 17.4.4 Standard"). **DECIDED 2026-11-26 (John):
   yes,** as the CVE record lists only three fixed versions.
6. **Where the fixed versions come from.** REDCap's release notes need a community login, so the
   pack cites the CVE record, which Securifera (the CNA) wrote. The packs README says each
   version is checked against the vendor's own page, so the pack should say why it can't be here.
   **Recommended:** cite the CVE record and Unit 42. If a REDCap administrator can read the
   release notes for you, confirm the three versions there before signing.

## Steps (one pull request each, after the decisions)

- **A.1 Measure, no product code.** Build a fake REDCap tree (three version folders, each with as
  many PHP files as a real release; REDCap is licensed, so the count comes from Securifera's
  write-up or from a REDCap administrator, never from an unlicensed copy). Collect it on the
  laptop, then time the web-root walk. Results go in this plan.
- **A.2 Format and judging:** `applications` in `format.py` (validation, dotted versions,
  `affected_from`, the most-specific rule), the install finder and judging in `exposure.py`, and
  the arrival time. Tests on synthetic bundles: every line before and after its fix, an unfinished
  upgrade, two installs on one server, an unparsable folder name, a pack with only applications.
- **A.3 Report and docs:** installs in the report, JSON and web UI beside packages, the coverage
  notes, and `docs/packs.md` (the format, with the REDCap example).
- **A.4 Checker release 0.1.7** (John), so pulls can read the new field.
- **A.5 The REDCap pack:** drafted, checked with `checker packs check` and the synthetic bundles,
  then signed by John, with the index and a PR into the packs repo. It merges only after 0.1.7 is
  out.
- **A.6 The proof on a real server** (John runs it): a Linode with nginx, PHP-FPM and the fake
  REDCap tree. Collect it with a vulnerable version folder newest, then with a fixed one, and
  check both read as expected end to end. It runs no exploit.

## Sources

- CVE record, CVE-2026-90817 (affected from 13.3.0; fixed in 16.0.49 LTS, 17.3.10 LTS, 17.4.4
  Standard): https://www.cve.org/CVERecord?id=CVE-2026-90817
- Unit 42, "Exploitation of CVE-2026-90817 for evasive cryptocurrency mining campaign",
  2026-10-07 (request, web shell path, miner paths and names, pool, persistence):
  https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-07-XMRig-campaign-through-CVE-2026-90817.txt
- Securifera's write-up, 2026-09-27:
  https://www.securifera.com/blog/2026/09/27/survey-says-remote-code-execution-cve-2026-90817/
- CISA, KEV addition of 2026-11-18:
  https://www.cisa.gov/news-events/alerts/2026/11/18/cisa-adds-four-known-exploited-vulnerabilities-catalog
- Rescana, REDCap CVE-2026-90817 (secondary; dates and Unit 42's indicators):
  https://www.rescana.com/post/redcap-cve-2026-90817-public-survey-rce-patch-now
