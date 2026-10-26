# Phase 0 build plan — 2026-10-25

> **Status: COMPLETE (2026-10-26).** All seven pull requests merged (#2–#9;
> #7 was a follow-up to #5), with Copilot review on every code PR. Results of
> the read-only proof are [at the end](#results).

**Goal (DESIGN.md §18, Phase 0):** the tool can log into a real server,
collect a first small set of evidence read-only, bring it back, and store it
encrypted and verifiable. A test on throwaway VMs proves that nothing was
written to the target beyond the traces disclosed in DESIGN.md §3.2. No
analysis, scoring, reports or AI yet; those are Phases 1–3.

**Done means:** `checker collect` against fresh Ubuntu 24.04 and Rocky Linux 9
VMs produces an encrypted bundle that `checker bundle verify` accepts,
containing host facts and the authentication log; the read-only test passes
on both; CI is green.

## Ground rules

- Feature branch per PR, into `dev`. John merges `dev` → `main`.
- No product name in code. The command is `checker`, the Python package is
  `checker`, and "Compromise Checker" appears only in configuration and docs.
- The collector is one file, Python 3.9-compatible, standard library only.
  CI runs its tests under 3.9 as well as the controller's 3.12+.
- Every external effect (SSH, cloud API) sits behind an interface with a fake
  for unit tests. Real servers appear only in the integration tests of 0.7.
- Each PR lands with its tests green before the next starts.

## Pull requests

**0.1 — Skeleton.** `pyproject.toml` (package `checker`, Python ≥ 3.12),
`LICENSE` (AGPL-3.0), short `README.md` (working title, status, link to the
design), pytest and ruff, GitHub Actions running lint and tests on 3.12 and
the collector tests on 3.9. Empty `checker` command that prints its version.

**0.2 — Policy text.** `SECURITY.md` (how to report a vulnerability to
security@nouriloop.com, what to expect back) and
`docs/security-and-privacy-policy.md`: DESIGN.md §3 rewritten for the people
who will rely on it (operators, their security and legal reviewers), not for
us. Includes the list of unavoidable traces and the secret-masking rules.
**John reviews the wording before merge**: this is a public promise.

**0.3 — The collection contract.** `docs/collector-protocol.md` and Pydantic
models for the stream: manifest (collector version and SHA-256, host facts,
both clocks, modules run, limits applied), source-chunk records, trailer
(counts, errors, truncations). The collector cannot import Pydantic, so it
emits plain dictionaries and a contract test checks that its output
validates against the models. How the controller passes settings to the
collector: it appends one line to the program text it streams,
`main(<settings as JSON>)`, so the collector needs no arguments, files or
environment variables.

**0.4 — Collector skeleton.** `collector/collector.py`:
- module registry with per-module time limits and per-source size caps,
  and an overall time limit;
- lowers its own CPU and I/O priority first thing (`os.nice`, and
  `ioprio_set` through `ctypes`) — so the sudo rule can stay
  `python3 -I -B -` with nothing in front of it (a small change from
  DESIGN.md §5.1, recorded there in this PR);
- gzip JSON-lines output on stdout, diagnostics on stderr;
- secret masking applied to every text chunk, with its own tests;
- two modules only: `host_facts` (os-release, kernel, hostname, boot id,
  uptime, clock) and `auth_log` (`/var/log/secure` or `/var/log/auth.log`
  plus rotated and compressed copies, within the look-back window);
- unit tests against a fake root directory with fixture files from both
  families (the test harness alone can point the collector at that root).

**0.5 — SSH transport.** AsyncSSH client:
- host keys kept in the tool's own known-hosts file; `checker trust <host>`
  shows the fingerprint and asks; unknown or changed keys stop the run;
- authentication by agent, key file or password (password from a prompt or
  the OS keyring, never stored by the tool);
- sudo modes: `password` (sent first on stdin), `nopasswd`, `root`;
- streams the program in and the output out, with time limits and a
  parallel limit across hosts;
- records the session (start, end, both addresses, key fingerprint) for the
  self-session filter later;
- minimal inventory (`hosts.yaml`) and `checker hosts add`;
- tests against AsyncSSH's own in-process server, so no real host is needed.
- `docs/scanner-account.md`: how to create the recommended key-only scanner
  account and its one-line sudoers rule, and why that rule is root-equivalent.

**0.6 — Evidence bundles.** Writes the stream to disk encrypted with age as
it arrives (to the organization's key, created by `checker init`), with
SHA-256 over both the plaintext and the encrypted file. A small unencrypted
sidecar holds only bundle id, host id, times and hashes. Chain-of-custody
rows in SQLite. Commands: `checker init` (config directory, age key,
database), `checker collect <host>`, `checker bundle verify`, `checker
bundle show` (decrypts and summarises). The `init` questions about the AI
advisor and shell-history contents are added in the phases that build those
features.

**0.7 — Read-only proof on real VMs.** A script that, for each of Ubuntu
24.04 and Rocky Linux 9:
1. creates a throwaway Linode (smallest plan, tagged, deleted at the end,
   and swept by a max-age cleanup if a run dies);
2. creates the scanner account and installs auditd rules that record every
   file write, rename, delete and permission change by any process in the
   scanner's login session;
3. runs `checker collect` against it;
4. fails if the audit log shows any write that is not on the disclosed list
   (sshd login records, sudo's timestamp under `/run`, sudo's lecture marker);
5. records run time and peak memory on the target;
6. deletes the VM.

The full distribution matrix (RHEL, Rocky, Alma 9 and 10; Ubuntu 22.04,
24.04, 26.04) comes in Phase 1, once there are enough modules to make it
worth the time.

## Explicitly gated on John

- Merging 0.2 (the policy wording).
- A Linode API token for 0.7, limited to creating and deleting Linodes, and
  any spending it implies (cents per run at hourly billing).
- Running the collector against nouriloop-prod after 0.7 passes — a good
  first real-world run, but only with his go-ahead.
- Making the repository public (after Phase 0, by decision of 2026-10-25).

## After Phase 0

Phase 1 (parsers, snapshots, baselines, core checks 8.1–8.7, HTML report)
gets its own plan once Phase 0 is merged and we have seen real collector
output from both families.

## Results

The read-only proof (`tests/integration/readonly_proof.py`, PR #9) on
2026-10-26, final run after all review fixes:

| | Ubuntu 24.04 | Rocky Linux 9 |
|---|---|---|
| Writes by the collector | **none** | **none** |
| Bundle | complete; `/var/log/auth.log` 3,127 bytes | complete; `/var/log/secure` 1,873 bytes |
| Writes by login machinery, all disclosed | 106 — control groups 51, `/run/user` 40, devices 5, process settings 4, login message 3, first-login marker on disk 2, session-manager permissions 1 | 77 — control groups 43, `/run/user` 23, process settings 7, SELinux 4 |

What the proof changed along the way:

- The first run showed that the operating system's own login machinery
  (systemd's per-user session, Ubuntu's login messages and a first-login
  marker file in the scanner's home, SELinux and control-group bookkeeping)
  writes things the policy's list of traces didn't name. Policy §5 and
  DESIGN.md §3.2 now disclose them.
- The proof itself was made to fail closed: it reads raw audit records, so
  names with spaces can't hide, treats `..` in a path as undisclosed, fails
  if the audit query errors or returns nothing, and always deletes its
  servers, including on Ctrl-C, SIGTERM and mid-creation cancellation.

Not measured reliably: the collector's peak memory (it finishes in about
3 ms, faster than the 0.2 s sampler). Phase 1 has the collector report its
own peak memory instead.

Cost of all proof runs on 2026-10-25/26: a few cents (Linode Nanodes, hourly).

