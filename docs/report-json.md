# The JSON report

`checker report HOST --format json` (or `--all`), for SIEMs and tickets. It holds the same findings as
the HTML report, with the same masking. It's encrypted to the evidence key like any report, or written
plain with `--plain` to hand to another system, and that copy is confidential too: it describes
weaknesses an attacker could use. Purging takes it as it takes other reports.

**Treat text in it as untrusted.** Much of it comes from servers that may be compromised. Invisible
characters and control codes are shown as escapes like `\u202e`, but anything else a server wrote is
there as written, so don't feed it to a shell, a template or a query without escaping it.

`format` is 1. It goes up only when a field changes meaning or goes away; new fields can appear without
it. Text is cut at 4,000 characters.

| Field | What it is |
|---|---|
| `format` | this schema's version |
| `generated_at`, `generated_by` | when, who, on which machine, which version of the tool |
| `hosts[]` | one per server |

Each host:

| Field | What it is | From the server? |
|---|---|---|
| `host` | the name in your inventory | no |
| `bundle` | the collection: id, status, times, SHA-256s, collector version | no |
| `analysed_at`, `versions` | when it was analysed, and by which checks | no |
| `score` | `probability`, `band`, `prior`, `contributors` and more: see [scoring](scoring.md) | no |
| `findings[]` | in effect, as below | partly |
| `suppressed[]` | hidden by a whitelist, with `suppressed_by` | partly |
| `exposures[]`, `packs[]` | how it stands towards each threat pack, and which it applied | no |
| `coverage` | `gaps` (what couldn't be seen) and `log_reach` | partly |
| `timeline[]` | `when`, `type`, `text`, `findings`, in order, with threat windows | `text`: yes |
| `advisor` | an AI model's words by role, with `at`, `model_answered`, `stale`, `warning`. Never findings | shaped by it |

Each finding:

| Field | What it is | From the server? |
|---|---|---|
| `number` | its number in the analysis, the "F-3" the advisor uses | no |
| `check`, `variant` | which check, and which kind of finding: stable, for rules | no |
| `title` | what it is, in the tool's words | no |
| `category` | `compromise indicator`, `exposure` or `hygiene` | no |
| `band` | `critical`, `high`, `medium`, `low` or `info` | no |
| `summary` | what, who, where | yes |
| `entities`, `entities_complete` | what it's about (`account:eve`), and whether that's all of them | yes |
| `first_seen`, `last_seen`, `new` | when, and whether it changed since the last collection | no |
| `uncertain` | why it may be wrong | partly |
| `ratio`, `contribution`, `raised_by_pack` | its weight in the score | no |
| `maintenance`, `suppressed_by` | a maintenance window or whitelist rule that applied | no |
| `excerpts[]` | `when`, `where`, `text`: the evidence, briefly | yes |

The estimate is an estimate, not a measurement, and no findings isn't proof of a clean server: see
[the report](report.md).
