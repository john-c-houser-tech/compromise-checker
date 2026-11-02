# Keeping the store in PostgreSQL

By default the store is a SQLite file, `checker.db`, beside the evidence. For a team, it can be a
PostgreSQL database instead (14 or later):

```
pip install -e '.[postgres]'
checker init --database postgresql:///checker         # a new install
checker store move --to postgresql:///checker         # an existing one
```

## What it holds

The same index SQLite holds: which bundles exist, their hashes, the chain of custody, baselines,
assessments, advice requests, purges and settings changes. Hosts' names and times are in plain text.
What's sensitive in it (a collection's connection details and errors, findings' summaries, reasons,
what was sent to the AI advisor) is encrypted to the evidence key before it gets there, as it is in
SQLite, so the database server can't read it.

**Evidence files stay on disk**, under the tool's home. They're encrypted and can be large. Anyone
running the tool from another machine needs that folder too, as well as the database and the evidence key.
The web interface's accounts and activity record are still in their own file, `web.db`.

## The address

It can't hold a password, and the tool refuses one that does, since settings are kept in plain text.
Use a Unix socket with peer authentication (`postgresql:///checker`), or a `.pgpass` file.

An address on another machine has to use TLS: `postgresql://db.example.org/checker?sslmode=verify-full`.
Otherwise anyone on the way could read which servers you have and how they were judged.

## Append-only

History is protected the same way as in SQLite, by triggers in the database: updates and deletes of
bundles, custody, baselines, assessments, advice, purges and settings changes are refused, and so is
`TRUNCATE`. Only a purge lifts them, inside its own transaction, and a failed purge leaves them in place.

As with SQLite, this stops mistakes and casual tampering, not whoever controls the database. The account
the tool uses owns these tables, so it could drop the triggers, as could a database administrator. The tool
puts them back the next time it opens the store for writing.

## Moving an existing store

`checker store move` needs an empty database, and doesn't run during a `checker run`. It copies every
row, checks that each table reads back the same, changes the settings, and only then offers to delete the
old file. Delete it: a purge can't reach what's left in it. There's no command for moving back.

## Backups

Back up the database as you would any other, with the evidence folder and the evidence key. Each is useless
without the others, and a restored database needs the evidence files it lists.

## Testing

`tests/test_store_backends.py` runs the store's promises on both databases, given a throwaway server:

```
PGPASSWORD=… CHECKER_TEST_POSTGRES=postgresql://postgres@127.0.0.1:55432/postgres pytest tests/test_store_backends.py
PGPASSWORD=… CHECKER_TEST_POSTGRES_EVERYWHERE=postgresql://postgres@127.0.0.1:55432/postgres pytest
```

The second runs the whole suite with its store on PostgreSQL. Each test gets a schema of its own.
