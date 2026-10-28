# Retention and purge

Stored evidence is kept for 90 days by default (`retention_days` in
`config.yaml`), then deleted with `checker purge` (policy §8). Purge is the
only way anything stored is deleted: the bundles, custody, baselines and
assessments tables are otherwise append-only, enforced by the database.

## What to purge

```
checker purge web01                      # everything stored for web01
checker purge web01 --before 2026-07-01  # web01's bundles collected before then
checker purge --before 2026-07-01        # every host's bundles before then
checker purge --expired                  # everything past the retention period
checker purge --expired --dry-run        # what that would delete
```

A date without a time is midnight UTC. Purge lists what it will delete and
asks you to type `purge`; `--yes` skips the question (for a scheduled
`--expired` run), `--dry-run` deletes nothing.

For each purged bundle it deletes:

- its database rows: the bundle, its chain of custody, its events and
  snapshot records, its assessments, and any baseline that named it;
- its files: the encrypted bundle, its sidecar, and the encrypted events,
  snapshots and assessments derived from it (older versions included);
- every report in the `reports/` folder that shows it, found by the hash
  the report left in the bundle's chain of custody. A report saved
  elsewhere with `report --output` is yours to delete.

`collect` and `analyze` print a one-line reminder when stored evidence is
past the retention period.

## Baselines

Later analyses compare each bundle with the host's baseline (see
[snapshots](snapshots.md)), usually its oldest bundle. If expiry took it, the
next-oldest bundle would become the baseline, and a change nobody accepted —
a backdoor added after the baseline — would stop showing just because time
passed. So:

- **`--expired` keeps each host's current baseline**, however old, and says
  so. It expires normally once a newer baseline is accepted
  (`checker baseline accept`). A host removed from the inventory loses this:
  its baseline expires with the rest.
- **An explicit purge** (a host, or `--before`) deletes what it names,
  baselines included, and warns first. The host's next analysis takes its
  oldest remaining usable bundle as the baseline (how: `after purge`), and
  every analysis against that baseline says changes made before it don't
  show.

## The record

Each purge adds a row to the append-only `purges` table: when, who, from
which controller, the scope (host, date, or expiry and its period), the
purged bundles' identifiers and hosts, the number of rows and files
deleted, and what happened to each affected host's baseline. Never any
content: the row shows that a bundle existed and when it was purged, not
what it held.

## Safe to interrupt

The rows go in one database transaction. To delete them it lifts the
append-only triggers and puts them back in that same transaction, so a
failure leaves every row and every trigger in place. The files are deleted
after the transaction commits; if purge stops in between, the files no row
refers to any more are deleted by the next purge, whatever its scope.
Purge refuses to run if a bundle's recorded path is outside this home's
`evidence/` folder (the home was moved), and lists those paths.

## Limits

Purge unlinks files; it doesn't overwrite them. On SSDs and copy-on-write
file systems the old blocks may survive until they are reused. What
protects them is the encryption: without the evidence key they can't be
read. Backups and synced copies of the tool's folder are outside its reach;
keep it out of both.
