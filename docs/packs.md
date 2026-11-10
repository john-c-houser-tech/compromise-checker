# Threat packs

A threat pack teaches the tool about one attack seen in the wild, without a
new release of the tool, so it can judge whether a server was broken into that
way: which signs of the attack to look for, when the server was open to it
(which package versions were vulnerable on each Linux release, from the
vendors' own advisories), and which settings help. The tool answers one
question, whether a server has been broken into; it isn't a vulnerability
scanner or a patching tool, so a pack is made only for a threat that is being
exploited and leaves signs on a server ([which threats get a
pack](#which-threats-get-a-pack)). A pack is data, never code. It runs nothing on your servers and doesn't change what
the collector reads; it is applied on your own machine, to evidence already
collected. The policy is [§11](security-and-privacy-policy.md#11-threat-packs-and-trust).
The format is documented in full at the top of `checker/packs/format.py`.

## Using packs

    checker packs pull            # download new packs and a newer key list, verified
    checker analyze --all         # apply them to each host's latest bundle
    checker packs list            # what is in force, and when the last pull was
    checker packs show ID         # what a pack says
    checker packs retire ID --reason "..."

- **`pull`** is the only part of the tool that fetches packs, and only when
  asked. It uses HTTPS, from NouriLoop's public repository or the mirror in
  `packs.source`. It takes a newer key list first, then the signed index,
  then each pack newer than any version accepted here. It warns about an
  index more than 30 days old.
- **Air-gapped sites** copy the files across and use `checker packs keys add
  keys.yaml` and `checker packs add packs/ID/PACK.yaml`.
- **Retiring** keeps the file, so old reports can be reproduced, and holds the
  pack back from pulls until a person adds it again.
- **`checker run` and `checker report`** apply the packs in force as they are.
  A run's "needs a look" says when a host is newly or more exposed, or a
  detection is new or more serious ([scheduling](scheduling.md)).

### Which servers

Every pack in force applies to every server unless a rule says otherwise:
`all`, `none`, `only: ID, ...` or `except: ID, ...`. A host's rule wins, then
its group's, then the configuration's:

    checker hosts packs HOST [RULE|default]
    checker config set packs.group_apply.GROUP RULE
    checker config set packs.apply RULE

Changes made with these commands are in `checker config history`, with who
made them and when; hand edits to the files are not. A pack held back is a
coverage gap in that host's analysis.

## What a pack changes

- **Exposure.** Each host gets a status: vulnerable, fixed, can't judge, not
  affected, or not covered (no entry for its release, which is a coverage gap).
  Being exposed is never itself a sign of compromise: it shows under exposure
  and raises the prior instead.
- **The prior.** A pack states a likelihood ratio for a host exposed through
  its whole window, at most 10. A host exposed for part of it gets that ratio
  scaled by its share of the window, in log-odds, and all packs together add
  at most a ratio of 10 ([scoring](scoring.md)).
- **Exposure's end.** The fix's time comes from the package history when it can
  be read; otherwise the last install time is the latest it can have been, and
  the report says "at the latest". A service still running code from before
  the fix keeps the host counted as exposed.
- **Mitigations.** A setting not in place is a finding. Being in place is a
  coverage note, because what an application changes as it runs isn't seen.
- **Detections.** See below. Findings a whitelist suppresses stay suppressed.

## Which threats get a pack

Since 2026-11-10, a threat gets a pack only if both hold:

- **It is being exploited:** on CISA's list of known exploited
  vulnerabilities, rated active by CISA, or credibly reported as attacked.
- **It leaves signs on a server that the tool can see:** something in the logs,
  processes, files, accounts or network connections the collector reads, so the
  pack carries detections.

A flaw that fails either, however serious, gets no pack. A pack for it could
only say "update", which is the vendor's updates' job and a vulnerability
scanner's, not this tool's.

## Writing a pack

    checker packs check PACK.yaml     # validates; trusts and adds nothing

- **Versions** come from each vendor's own advisory, with the source in the
  entry. A fixed version carries the vendor's revision or release: `8.3.6` alone
  would count every build of 8.3.6 as fixed, backport or not. A native Ubuntu
  package (`ca-certificates`, `base-files`) has no revision: its whole version is
  Ubuntu's (`20260816ubuntu0.24.04.1`), so its entry says `native: true`, which
  waives the rule for that entry alone. An installed build with a revision can't be
  judged against it (so `native` can't make `8.3.6` fix every 8.3.6 backport), and
  any later build without one is Ubuntu's own. Checker 0.1.1 and earlier refuse such a
  pack: a pull there reports it as a problem every time (keeping the pack's earlier
  version, and pulling the others) until the checker is upgraded. So one goes out
  only after a checker release that reads it.
- **Several repositories on one release** are told apart by a `versions` glob on
  the installed version. A package matching several entries is vulnerable if
  any says so.
- **A version no entry matches** is not affected, unless the pack says
  `other_builds: cant_judge`: use that for a threat in every build of a package,
  so a build from an unlisted repository isn't called safe. Without it, check
  real version strings from each repository, not just the ones you expect.
- **`stale_code`** names programs that must be restarted after a fix. A program
  with a version in its name (`php-fpm8.3`) isn't judged by a package naming
  another version.

### Detections

Each detection counts only for a host the threat reached: `counts:
while_exposed` for an attack attempt, harmless once fixed; `since_exposed`, the
default, because someone already inside stays. There are no regular expressions
and no code: matching is `equals`, `prefix` or `glob` (`*` and `?`, at most ten
stars).

| Kind | Says | Weight |
|---|---|---|
| A check built into the tool | `check: web.worker_child` | Its findings in that time weigh as the pack says: at most 100, and at most one band up |
| Events | `any_of` matchers on `web.request`, `web.error`, `kernel.segfault`...; `count: {at_least, within}`; `by` a field | At most 20 |
| Snapshot items | a section, key and `state`: present, absent, added, changed, removed | At most 20 |

A detection whose data the collection lacks is a coverage gap, not silence. Only
some web requests become events (5xx, attack markers, scripts, sensitive paths),
and no log format the tool reads gives a request's content type. Give thresholds
some room: an ordinary busy site can log a burst of memory errors, and one crash
can log two lines.

## Releasing a pack (maintainers)

Releases are signed by hand; no key is held by CI or any server.

1. Validate it, and check every version and date against the vendor's own page.
2. Prove it on throwaway servers. `tests/integration/pack_proof.py --pack PACK.yaml`
   checks a pack's package entries against the vendor's real builds: on one
   server per release it installs the newest offered build the pack calls
   vulnerable, then the oldest it calls fixed, and checks each reads so through
   a real collection; every other offered build is judged too. Without `--go`
   it only prints the plan; each run costs about a cent a server. Exit status 2
   means nothing failed but something needs a look (listed). It can't tell
   whether the fix version is the vendor's (step 1 does), and doesn't prove
   RHEL module streams yet. A pack's detections need a proof of their own:
   `tests/integration/php2shell_proof.py` is the model (it runs no exploit).
3. Sign the pack: `minisign -S -s pack.key -m PACK.yaml -t "ID version N"`.
4. Write the index, in a clone of the packs repository: `checker packs index .`
   (it checks every pack's signature against `keys.yaml`, and refuses a changed
   pack under an old version). Then `minisign -S -s pack.key -m index.yaml`.
5. Open a pull request. Don't touch a file after signing it.

Sign the index again at least monthly, even with nothing new: a serial stops an
older index being swapped in, not the current one being served for ever. To
withdraw a pack: `checker packs index . --withdraw ID=REASON`, and the next pull
retires it.

**A pack key leaks or is lost:** write a new `keys.yaml` with a higher serial,
naming the new key and revoking the old one, and sign it with the root key. It
reaches sites through a pull or a new release of the tool; packs signed by the
revoked key are retired. Someone who holds a leaked key and controls a site's
source could withhold that list, and the staleness warning wouldn't show it.

## Limits

- A pack judges only the packages it lists. Software bundling its own PHP, or a
  hosting panel's own packages, reads as not affected unless the pack names them.
- A clean result isn't proof: attackers can avoid or remove evidence, and an
  old program start can only be seen where the audit log recorded it.
