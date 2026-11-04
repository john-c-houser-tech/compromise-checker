# Commands

Every `checker` command, with what it does and its options. The [README](../README.md) gives
the picture; this page gives the detail. `checker COMMAND --help` prints the same options at
the terminal.

## `checker init`

Sets up the evidence key, database and configuration; `--home-text privileged|all` opts in to
collecting the masked text of start-up files and user units in home directories (policy §7);
`--web-access-logs` opts in to web servers' access logs, masked; `--exec-records` chooses whose
program starts are read from the audit log (the web server's accounts by default). It also asks
whether to turn on the optional AI advisor (`--advisor on|off` for unattended setups, which leave
it off), and where its API key comes from (`--advisor-key-source env|keyring|command:<command>`;
never stored in the configuration).

## `checker advise HOST [--yes]`

Asks the optional AI advisor to explain a host's latest analysis (verdict, what matters most,
innocent explanations, what would settle it), after showing the likely cost and the most it can
cost, and asking when the likely cost is above `advisor.max_cost_per_run`. The answer is checked
against the case (it must name only real findings and agree with the band), its placeholders
turned back into names, and it is stored encrypted with exactly what was sent; the report shows
it, labelled with the models and redaction, separately from the findings. `--role whitelist`
asks instead for whitelist rules for findings that are routine on the host: each is checked
against the real findings (it must hide exactly the findings it names, none critical or part
of a chain, on the host's stored analyses and, for a group rule, the group's) and the accepted
ones written to `proposals/` with the owner left empty, for a person to review and copy in;
nothing is applied. `--role coverage` asks what would let the next collection see more, picked
only from the tool's collection settings (printed as the `checker config set` line to run) and
a fixed catalogue of host configuration (auditd for web accounts, running the audit daemon,
a persistent journal, sshd `LogLevel VERBOSE`, a readable web log format, log retention),
each citing the coverage gap or finding it helps with; nothing is changed. `--role remediation`
asks what to do, scaled to the band: evidence to preserve first, then containment, eradication,
recovery, and who to tell (by role); it must agree with the band (no "now" for a Low host), keep
evidence before any step that destroys state (judged by what a step does, not only by what it says),
and cite only real findings. Commands are shown as text; nothing runs. The model's safety checks
may decline security content now and then (the report says so, and a fallback model answers when
`advisor.fallback` is `anthropic`); organizations doing this work regularly can apply to Anthropic's
Cyber Verification Program, or set `advisor.fallback` to `model` to send declined requests to a
model of their choosing (`advisor.fallback_model`). `advisor.api openai` with `advisor.base_url`
asks a local model (Ollama, llama.cpp, vLLM) or another OpenAI-compatible server instead of
Anthropic. A model on the same machine (loopback) costs nothing and is reached directly, never
through a proxy, but its answers are weaker (the report says so), and its context must hold
the whole case (for Ollama, a model with `num_ctx` of 32768 or more). A request the server
read only in part is reported as cut off, not answered (Ollama keeps about half its context
when it cuts); give the model more context than the case needs. With `api_key_source env`,
the key comes from `ANTHROPIC_API_KEY` for Anthropic's own API, `OPENAI_API_KEY` for OpenAI's,
and otherwise `CHECKER_ADVISOR_API_KEY` (`CHECKER_FALLBACK_API_KEY` for the fallback model), so
one vendor's key never goes to another; `none` sends no key. `checker advise --all [--role ROLE]`
asks about every host with a usable bundle: each host's estimate first, then one question for the
whole run. When `advisor.triage_model` is set (it ships empty; for example `claude-haiku-5-5`),
explanations of quiet hosts (Low, with no chain and no finding at medium or worse in effect)
go to that model, through the same API and key, and everything else to `advisor.model`; the
output and the report name the model per host. Each host is sent the bundle it was estimated on,
and a host whose analysis, model or estimate changed in between isn't sent. Haiku models have
no server-side fallback, so with `advisor.fallback anthropic` a declined request to one isn't
re-run (with `model`, it goes to the fallback model as usual). `--show [--redaction MODE]`
prints exactly what would be sent, after redaction, and sends nothing. Under *pseudonymize*
(the default) people's account names, host names, email addresses, IP addresses and SSH key
fingerprints become placeholders (USER-2-7f3a) made fresh for each run; *strict* sends only
the kinds of finding, counts, scores and kinds of coverage gap.

## `checker config show|set|history|check-key`

The settings in words; change one after `init` (validated, and recorded with who, when, old
and new value; the file is written back whole, so hand-added comments go); every change so far;
read the advisor's API key from its source to check it works, without sending anything. A key
pasted into a `command:` source is refused.

## `checker packs pull|list|show|add|retire|check|keys|trust|index`

Signed threat packs ([packs](packs.md)); nothing is downloaded unless you pull.

## `checker hosts add|list|remove|packs`

And `checker trust` — the inventory (`--web-root DIR`, repeatable, sets a host's own web roots;
`hosts packs HOST [RULE]` shows or sets which threat packs apply to it), and verified SSH host
keys (no way to switch verification off).

## `checker collect`

Logs in (key, agent or password; sudo with or without a password, or root), runs the
collector read-only, and stores the result as an `age`-encrypted, hashed bundle with a chain
of custody. Collects host facts, logs, persistence, the network, software, mail, web servers
and containers, with secrets masked before they leave the server (email addresses' local parts
are fingerprinted, the domain kept).

## `checker mail-hash ADDRESS…`

Shows how known email addresses appear in the collected mail logs, so they can be looked for.

## `checker bundle list|show|verify`

Inspect and re-check stored evidence.

## `checker events BUNDLE`

Parse a bundle into events (logins, sudo, account changes, kernel and systemd messages, login
records), with the tool's own session recognised and left out ([how](events.md)).

## `checker changes HOST`

What changed on a host since its previous bundle and since its baseline: accounts, sudo rules,
authorized keys, sshd settings, persistence files, listening sockets, kernel modules and
more. The host's first analysis is its baseline; `checker baseline accept HOST --reason …`
moves it after a reviewed change ([how](snapshots.md)).

## `checker analyze HOST|--all`

Runs the checks (kernel and system health, reboots, accounts and authentication, persistence,
system binary integrity, files in unusual places, live processes, the network, logging stopped
or wiped, software changes, mail, web applications, containers), links findings that tell
an attack's story into chains, and lists the findings by category and band, with what the
collection couldn't see, and scores the host: a probability of compromise with its band and what
drove it, from a prior set per host, group or configuration; each analysis is stored encrypted
([checks](checks.md), [scoring](scoring.md)).

## `checker report HOST|--all`

Writes one self-contained, confidential HTML report: findings with their evidence, a timeline,
coverage, and the collection's hashes and chain of custody, encrypted to the evidence key
(`--plain` for plain HTML to hand on); `checker report --open [FILE]` shows one in the browser,
served from memory on this machine, never written in plain ([report](report.md)).

## `checker whitelist check [HOST]`

, `test HOST --file F`, `stale` — validate the whitelist files (global, per group, per host)
and show a host's merged rules; show what a proposed file would hide or reveal on stored analyses
before it is saved; list rules that matched nothing lately or are expiring. Maintenance windows
make planned reboots informational. Shipped profiles (`base`, `web`, `database`, `mail`, `build`)
cover what such servers ordinarily do. A rule suppresses a finding an operator has explained,
with a reason, an owner and an expiry; suppressed findings are kept and listed in the report's
appendix, and count for nothing in the score ([whitelists](whitelists.md)).

## `checker run --all [--unattended]`

Collects, analyses, writes the report and purges what has expired, in one pass, and says which hosts
need a look (band risen, a new high or critical finding, not collected); `notify_command` hands
that short summary to a command of yours (mail, a webhook). `--unattended` asks nothing and leaves
out, with a warning, hosts that would need a prompt. `checker schedule install --at HH:MM` runs
it every day (a systemd user timer, or a launchd agent on macOS) ([scheduling](scheduling.md)).

## `checker purge HOST | --before DATE | --expired`

Deletes stored evidence, reports included, and records what went by identifiers and
counts only. `--expired` keeps each host's current baseline until a newer one is accepted
([retention](retention.md)).
