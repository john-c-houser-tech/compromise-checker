# Collector protocol

How the controller and the collector talk during one collection (DESIGN.md
§5). Protocol version **1**.

The collector side is `checker/collector/collector.py` (Python 3.9, standard
library only). The controller side is `checker/protocol.py`, whose Pydantic
models are the authoritative definition of every record below; a contract
test runs the real collector and validates its output against them.

## 1. Session

The controller runs `python3 -I -B -` on the target (under `sudo` unless it
logs in as root) and writes to its stdin, in order:

1. the sudo password and a newline, only after sudo's prompt appears (in
   sudo-password mode Python then starts with a one-line bootstrap that
   prints a ready marker to stderr; the program is sent only after it);
2. the collector program text;
3. one final line, `main(<settings>)`, where `<settings>` is the settings
   object (section 2) encoded as JSON and then encoded again as a JSON string
   (`json.dumps(json.dumps(settings))`). An ASCII-only JSON string is also a
   valid Python string literal, so nothing in the settings can break out of
   the call;
4. end of file.

Python reads the whole program, then runs it. The collector takes no command
line arguments, reads no files of its own and uses no environment variables.

The collector writes the result stream (section 3) to stdout and human-readable
diagnostics to stderr. The exit status is 0 when it produced a trailer,
whatever the collection status; anything else means the stream must be
treated as incomplete.

**The collector's fingerprint** is the SHA-256 of the program text the
controller sent (item 2, without the `main(...)` line). The collector cannot
see its own source when run from stdin, so the controller computes it and
stores it with the evidence; the manifest carries the version string only.

## 2. Settings

```json
{
  "protocol": 1,
  "run_id": "6f1c9a52-6c0e-4c55-9a7b-2a3c3a7f0e11",
  "since": "2026-09-25T00:00:00+00:00",
  "modules": ["host_facts", "auth_log"],
  "limits": {
    "overall_seconds": 600,
    "module_seconds": 120,
    "source_bytes": 268435456
  }
}
```

- `protocol` — must equal the collector's protocol version, or the collector
  refuses (section 3.6).
- `run_id` — chosen by the controller; echoed in the manifest so a stream
  can't be attached to the wrong run.
- `since` — start of the look-back window, UTC.
- `modules` — which modules to run, in order; `null` or omitted means all,
  and an empty list means none.
- `limits` — time limits and the per-source byte cap. A source that reaches
  its cap is cut off and marked truncated.

## 3. Result stream

stdout carries a single **gzip** stream. Decompressed, it is **UTF-8 JSON
Lines**: one JSON object per line, each with a `type` field.

```
manifest                       exactly once, first
( record
| source_start chunk* source_end
| error )*                     any number, in any order between modules
trailer                        exactly once, last
```

A stream without a trailer is incomplete (the session died, or the collector
was killed). The controller keeps it, marks the collection incomplete, and
says so in the report.

### 3.1 `manifest`

```json
{"type": "manifest", "protocol": 1, "collector_version": "0.1.0.dev0",
 "run_id": "6f1c…", "started_at": "2026-10-25T21:04:05.123456+00:00",
 "host": {"hostname": "web01", "os_id": "rocky", "os_version_id": "9.6",
          "os_pretty_name": "Rocky Linux 9.6 (Blue Onyx)", "kernel": "5.14.0-570.el9.x86_64",
          "machine": "x86_64", "boot_id": "4b1f…"},
 "python": {"version": "3.9.25", "executable": "/usr/bin/python3"},
 "effective_uid": 0,
 "settings": { … as received … },
 "modules_planned": ["host_facts", "auth_log"],
 "masking_version": 2,
 "priority": {"nice": 19, "io": "idle"},
 "commands_allowed": {"journalctl": ["/usr/bin/journalctl", "/bin/journalctl"]}}
```

- `masking_version` — version of the secret-masking rules applied to every
  text chunk (DESIGN.md §3.4); reports cite it.
- `priority` — what the collector achieved when lowering its own priority:
  the resulting nice value, and `idle` or `unchanged` for disk I/O.
- `commands_allowed` — the collector's fixed command allow-list: each
  command and the absolute paths it may be run from
  (docs/collector-modules.md, "Commands").

The collector flushes the stream right after the manifest, so it reaches the
controller before any module runs. `started_at` is the **target's** clock. The controller records its own clock
when the manifest arrives; the difference (less half the connection's round
trip) is the clock offset used to correct timelines (DESIGN.md §5.3).

### 3.2 `record` — structured facts

```json
{"type": "record", "module": "host_facts", "name": "uptime",
 "data": {"seconds": 86400.5}}
```

For facts that are naturally structured (host facts, and later the snapshot
items of DESIGN.md §6). `data` is any JSON object; each module documents its
records.

### 3.3 `source_start`, `chunk`, `source_end` — raw content

Raw content (log files, command output) is sent as a **source** split into
chunks.

```json
{"type": "source_start", "source_id": 3, "module": "auth_log", "kind": "file",
 "name": "/var/log/secure-20261019.gz",
 "meta": {"size": 18234, "mtime": "…", "mode": "0600", "uid": 0, "gid": 0,
          "inode": 131, "compressed": "gzip"}}
{"type": "chunk", "source_id": 3, "seq": 0, "encoding": "utf-8", "data": "Oct 18 …"}
{"type": "source_end", "source_id": 3, "chunks": 1, "bytes": 52011,
 "truncated": false, "masked": {"password": 2}}
```

- `source_id` — unique within the stream, starting at 1. Sources do not
  interleave: a source's chunks all come between its start and end.
- `kind` — `file`, `command` (`name` is the command line), or `proc` (a file
  under `/proc`, read as it was at that moment).
- `meta` — for files: size, modification time, mode, owner, inode, and the
  compression the collector undid, if any. For commands: `argv`, and the
  executable's size, times, mode, owner, inode and `executable_sha256`.
- `chunk.seq` — 0, 1, 2… with no gaps. `encoding` is `utf-8` when the bytes
  are valid UTF-8, otherwise `base64`. Chunks hold whole lines, masked whole,
  up to 64 KiB of original bytes; a single longer line (up to 1 MiB) travels
  alone in its own chunk. A line longer than 1 MiB is not sent: it is
  replaced by `[MASKED:oversized_line N bytes]` and counted under `masked`.
- `source_end.bytes` — total original bytes sent (after decompression, before
  masking). `truncated` is true when the source hit the byte cap (the last
  line that would not fit whole is left out) or a time limit;
  `truncated_reason` then says which. `masked` counts masked secrets by kind
  (DESIGN.md §3.4). `error` is set if reading failed part-way. For
  commands, `exit_code` is the exit status (negative: killed by that signal,
  as when the collector stops it at a limit) and `stderr` the first 4 KiB of
  its error output, masked, with `stderr_truncated: true` when there was
  more (the line the limit cut is left out).

### 3.4 `error`

```json
{"type": "error", "module": "auth_log", "message": "Permission denied: /var/log/secure"}
```

A problem that stopped part of a module. The collector carries on with the
next source or module. `module` is `null` for problems outside any module,
such as a refusal.

### 3.5 `trailer`

```json
{"type": "trailer", "finished_at": "2026-10-25T21:04:09.871+00:00",
 "duration_seconds": 4.75, "status": "complete",
 "counts": {"records": 6, "sources": 4, "chunks": 31, "errors": 0},
 "modules": {"host_facts": {"status": "ok", "seconds": 0.02},
             "auth_log": {"status": "ok", "seconds": 4.6}},
 "resources": {"peak_rss_kb": 21116, "cpu_seconds": 0.19,
               "commands_peak_rss_kb": 22116, "commands_cpu_seconds": 0.05}}
```

- `status` — `complete` (every planned module finished), `partial` (some
  module failed, timed out or was skipped), or `refused` (section 3.6).
- `counts` — totals of each record type in the stream, so the controller can
  check nothing was lost.
- `modules` — per module: `ok`, `error`, `timeout` or `skipped`, and seconds.
- `resources` — the collector's own peak memory (KiB) and CPU time, and
  separately the largest peak and total CPU time of the commands it ran;
  `null` where the server's Python lacks the `resource` module.

### 3.6 Refusal

If the settings are invalid or the protocol version differs, the collector
writes a manifest, one `error` per problem, and a trailer with status
`refused`, and exits 0. It never guesses. In a refused manifest, `run_id` and
`settings` are `null` when what was received had the wrong type.

## 4. Versioning

The protocol version changes only when a record's meaning changes or a field
is removed. Adding an optional field does not change it. The controller
refuses streams with a protocol version it does not know.
