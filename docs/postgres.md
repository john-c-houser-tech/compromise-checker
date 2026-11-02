# Keeping the store in PostgreSQL

By default the store is a SQLite file, `checker.db`, beside the evidence. It can be a PostgreSQL
database instead (14 or later), which your organization backs up and looks after like its others.
One machine still runs the tool: a team signs in to its web interface.
The tool's account has to own the database, since it makes the tables and their guards:

```
createdb --owner=checker checker                      # as a PostgreSQL administrator
pip install -e '.[postgres]'
checker init --database postgresql:///checker         # a new install
checker store move --to postgresql:///checker         # an existing one
```

## What it holds

The same index SQLite holds: which bundles exist, their hashes, the chain of custody, baselines,
assessments, advice requests, purges and settings changes.

Whoever runs the database server can read what's in plain text: hosts' names, times, file paths, hashes
and sizes, statuses, the accounts and machine that ran each command, what purges took, the AI models
used and their cost, and every settings change with its old and new values. What's most sensitive (a
collection's connection details and errors, findings' summaries, reasons for accepting a baseline, what
was sent to the AI advisor) is encrypted to the evidence key before it gets there, so that part they
can't read.

**Evidence files stay on disk**, under the tool's home. They're encrypted and can be large.

**One machine runs the tool.** A database server doesn't make this safe to run from several at once:
evidence is found by its full path, and "only one check at a time" and "no purge during a check" are locks
on that machine. The web interface's accounts and activity record are still in their own file, `web.db`.

## The address

It can't hold a password, and the tool refuses one that does, since settings are kept in plain text and
every change to them is kept for good. Use a Unix socket with peer authentication
(`postgresql:///checker`), or a `.pgpass` file. It's read as PostgreSQL's own library reads it, and can
only name a server, port, database and account, their TLS settings, and `requirepeer` or `require_auth`.
Its options can only choose a schema. Its socket should be one only PostgreSQL can create, not `/tmp` on a
shared machine: anyone able to listen there could collect a password from `.pgpass`, unless `requirepeer`
names the account the server runs as.

An address on another machine has to use `sslmode=verify-full`, which checks it's really that server:
`postgresql://db.example.org/checker?sslmode=verify-full`. Otherwise someone on the way could read
which servers you have and how they were judged.

Environment variables could send it elsewhere unseen. The tool refuses to connect while `PGHOST`, `PGPORT`,
`PGDATABASE`, `PGUSER`, `PGSSLMODE` or `PGSSLROOTCERT` is set unless the address says the same thing itself,
which then wins. It refuses while `PGSERVICE`, `PGHOSTADDR`, `PGOPTIONS` and others that an address can't
overrule are set. The message names the one in the way.

It refuses a session with triggers switched off (`session_replication_role`), and tables with these names
that it didn't make, so give it a database of its own.

## Append-only

History is protected the same way as in SQLite, by triggers in the database: updates and deletes of
bundles, custody, baselines, assessments, advice, purges and settings changes are refused, and so is
`TRUNCATE`. Only a purge lifts them, inside its own transaction, and a failed purge leaves them in place.

As with SQLite, this stops mistakes and casual tampering, not whoever controls the database. The account
the tool uses owns these tables, so it could drop or disable the triggers, as could a database
administrator. The tool checks them each time it opens the store for writing, and puts back any that are
missing, disabled or changed.

## Moving an existing store

Stop the web interface and anything else using the tool first. `checker store move` needs an empty
database, and doesn't run during a `checker run`. It holds the old store while it copies every row, checks
that each table reads back the same and changes the settings, and only then renames the old file to
`checker.db.moved`, so it can't be taken for the store, and offers to delete it.
If the settings can't be written, what it made is taken away. If it's stopped between the two, the old
store stays in charge, nothing is lost, and the new database needs emptying before trying again. Delete it: a purge can't reach what's left in it. There's no command for moving back.

If `config.yaml` is lost while the store is in a database, the tool won't start an empty store beside
your evidence: restore the file. If the store really is lost, `checker init --new-store` starts an empty one,
which won't list the evidence already there.

## Backups

Back up the database as you would any other, with the evidence folder and the evidence key. Each is useless
without the others, and a restored database needs the evidence files it lists.

**A purge doesn't reach your backups**, or a replica or archived log that has already copied what it
deleted. Keep those for no longer than your retention period if that matters to you. Deleted rows also stay
in the database's own files until it next vacuums them.

## Testing

`tests/test_store_backends.py` runs the store's promises on both databases, given a throwaway server:

```
PGPASSWORD=… CHECKER_TEST_POSTGRES=postgresql://postgres@127.0.0.1:55432/postgres pytest tests/test_store_backends.py
PGPASSWORD=… CHECKER_TEST_POSTGRES_EVERYWHERE=postgresql://postgres@127.0.0.1:55432/postgres pytest
```

The second runs the whole suite with its store on PostgreSQL. Each test gets a schema of its own.
