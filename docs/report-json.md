# The JSON report

`checker report HOST --format json` (or `--all`), for SIEMs and tickets. It holds the same findings as
the HTML report, with the same masking. It's encrypted to the evidence key like any report, or written
plain with `--plain` to hand to another system, and that copy is confidential too: it describes
weaknesses an attacker could use. Purging takes it as it takes other reports.

Purging removes only reports in `reports/`, not copies written with `--output` or already handed on.

**Treat text in it as untrusted.** Much of it comes from servers that may be compromised. As in the HTML
report, characters that display as nothing or disguise what's around them, control codes, tabs and line
breaks are shown as escapes like `\u202e`, and a backslash is doubled, so an exact match on a path or
indicator can fail for such strings. Anything else a server wrote is there as written: a summary can begin
with `=` or `@`, or hold ticket markup. Don't put it into a spreadsheet, a shell, a template or a query
without escaping it.

It's one document with every host, in lines of text, and grows with the findings: a SIEM with a limit per
event has to split it.

`format` is 1. It goes up only when a field changes meaning or goes away; new fields can appear without it.
A string cut short ends in `…`, which a server can also write. Summaries and gaps stop at 4,000 characters,
excerpts and timeline text sooner. Findings can hold more than the HTML shows: `entities` isn't in it, and
can list up to 200 names or networks.

| Field | What it is |
|---|---|
| `format` | this schema's version |
| `generated_at`, `generated_by` | when, who, on which machine, which version of the tool |
| `hosts[]` | one per server |

Each host:

| Field | What it is | From the server? |
|---|---|---|
| `host` | the name in your inventory | no |
| `bundle` | the collection: id, status, times, SHA-256s | `collector_version` only |
| `analysed_at`, `versions` | when it was analysed, and by which checks | no |
| `notes` | what to know about this analysis, such as it being the first | no |
| `checks_not_run[]` | `check`, `status`: **these found nothing because they didn't look** | no |
| `baseline_id`, `baseline_set_now`, `whitelist_rules_expired` | what it compares with, and rules that have lapsed | no |
| `score` | `probability`, `band`, `prior`, `contributors` and more: see [scoring](scoring.md). `finding` and `findings` in it are finding `number`s | `contributors[].title` and a chain's `account` can be |
| `findings[]` | in effect, worst first, as below | partly |
| `suppressed[]` | hidden by a whitelist, with `suppressed_by` | partly |
| `exposures[]`, `packs[]` | how it stands towards each threat pack, and which it applied. Its dates can come from the server's package history | dates only |
| `coverage` | `gaps` (what couldn't be seen) and `log_reach` | partly |
| `timeline[]` | `when`, `type`, `text`, `findings`, in order, with threat windows. A row with an empty `when` says how many events aren't shown, and `after` places it | `text`: yes |
| `advisor` | an AI model's words by role, as `answered` and `came_to_nothing`. Never findings. Its "F-3" numbers mean the analysis it read: check `stale` | shaped by it |

Each finding:

| Field | What it is | From the server? |
|---|---|---|
| `number` | its number in the analysis, with gaps where others are suppressed: the "F-3" the advisor uses | no |
| `check`, `variant` | which check, and which kind of finding: stable, for rules | no |
| `title` | what it is, in the tool's words or a threat pack's | no |
| `category` | `compromise indicator`, `exposure` or `hygiene` | no |
| `band` | `critical`, `high`, `medium`, `low` or `info` | no |
| `summary` | what, who, where | yes |
| `entities`, `entities_complete` | what it's about (`account:eve`), and whether that's all of them | yes |
| `first_seen`, `last_seen` | the earliest and latest event behind it **in this collection**, from the server's logs. Null for a finding about a state, not an event | times only |
| `new` | changed since the last collection. On a first analysis every logged finding counts, and a state finding doesn't, so don't alert on it alone | no |
| `uncertain` | why it may be wrong | partly |
| `ratio`, `contribution`, `raised_by_pack` | its weight: only `contribution` counts towards the score | no |
| `maintenance`, `suppressed_by` | a maintenance window or whitelist rule that applied | no |
| `excerpts[]` | `when` (no zone, or marked "host clock"), `where`, `text`: the evidence, briefly | yes |

The estimate is an estimate, not a measurement, and no findings isn't proof of a clean server: see
[the report](report.md).
