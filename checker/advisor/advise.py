"""`checker advise`: one role's request for a host's current assessment,
from the case file to the stored, restored answer (Phase 3 plan, PR 3.2).

The steps, each visible to the operator: build the case and redact it;
estimate its size here (nothing is sent to estimate it) and show the
estimated cost, asking first above the configured limit; send; check the
answer against the case; turn the placeholders back into names; store the
request and what came of it encrypted, append-only, for every request
that was sent, whatever came of it. Nothing here changes a score, a
whitelist or a setting.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from checker.advisor.case import case_for_host, redact
from checker.advisor.client import (
    MAX_TOKENS,
    AdvisorError,
    Outcome,
    build_request,
    fallback_request,
    make_client,
    send,
)
from checker.advisor.keys import KeySourceError, key_places, read_api_key
from checker.advisor.prices import Estimate, cost, estimate, tokens_in
from checker.advisor.roles import CHECKS, FINDING_ID, InvalidAnswer
from checker.evidence import Advisor, Config, is_local, open_text, seal_text


@dataclass
class Advice:
    status: str  # answered, declined, invalid, cut off, not sent
    outcome: Outcome | None
    answer: dict[str, Any] | None  # restored, for the operator
    note: str = ""
    judged: list | None = None  # whitelist proposals, each accepted or why not
    file: Path | None = None  # where the accepted ones were written


def _restore(value: Any, restore: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return restore(value)
    if isinstance(value, list):
        return [_restore(v, restore) for v in value]
    if isinstance(value, dict):
        return {k: _restore(v, restore) for k, v in value.items()}
    return value


def advise(
    store,
    host: str,
    identity,
    config: Config,
    inventory,
    prior,
    whitelist,
    *,
    role: str = "explain",
    bundle_id: str | None = None,
    client=None,
    confirm: Callable[[str], bool] | None = None,
    say: Callable[[str], None] = print,
    home: Path | None = None,
) -> Advice:
    """Ask the advisor about a host's current assessment. `confirm` is
    asked (with the estimate) when a run would cost more than the limit or
    its cost is unknown; without it, such a run isn't sent."""
    advisor = config.advisor
    if not advisor.enabled:
        raise AdvisorError(
            "the advisor is off: `checker config set advisor.enabled on` turns it on"
            " (`checker advise HOST --show` shows what it would send)"
        )
    built, known, which = case_for_host(
        store, host, identity, config.recipients, inventory, prior, whitelist, bundle_id
    )
    payload, pseudonyms = redact(built, advisor.redaction, known)
    request = build_request(payload, role, advisor)
    tokens = tokens_in(json.dumps(request.body, ensure_ascii=False))
    line, priced = cost_line(advisor, tokens)
    say(line)
    if priced is None or priced.likely > advisor.max_cost_per_run:
        reason = (
            "not sent: no price is known for a model it may use, and it wasn't confirmed"
            if priced is None
            else "not sent: the likely cost is above advisor.max_cost_per_run, and it wasn't"
            " confirmed"
        )
        if confirm is None or not confirm(f"{line} Send it? [y/N] "):
            return Advice("not sent", None, None, reason)
    if client is None:
        client = _client(advisor.api_key_source, advisor.api, advisor.base_url)
    sent_fallback = None

    def record(
        outcome: Outcome | None, status: str, raw, answer, note: str, request_id=None
    ) -> None:
        asked = outcome.model_asked if outcome else advisor.model
        store.record_advice(
            {
                "bundle_id": which["bundle_id"],
                "host": host,
                "assessed_at": which["assessed_at"] or "",
                "role": role,
                "at": datetime.now(UTC).isoformat(timespec="seconds"),
                "status": status,
                "redaction": advisor.redaction,
                "model_asked": asked,
                "model_answered": outcome.model_answered if outcome else None,
                "declined_by": json.dumps(outcome.declined_by)
                if outcome and outcome.declined_by
                else None,
                "refusal_category": outcome.refusal_category if outcome else None,
                # Effort is sent only in Anthropic's form of the request.
                "effort": advisor.effort
                if "output_config" in request.body
                or (sent_fallback and "output_config" in sent_fallback.body)
                else None,
                "request_id": outcome.request_id if outcome else request_id,
                "usage": json.dumps(
                    {"total": outcome.usage, "per_model": outcome.iterations} if outcome else {}
                ),
                "estimated_cost": spent(outcome) if outcome else None,
                "endpoint": outcome.endpoint if outcome else advisor.base_url,
                "request": seal_text(
                    json.dumps(
                        {**request.shown(), "fallback": sent_fallback.shown()}
                        if sent_fallback
                        else request.shown(),
                        ensure_ascii=False,
                    ),
                    config.recipients,
                ),
                "answer": seal_text(
                    json.dumps({"raw": raw, "restored": answer, "note": note}, ensure_ascii=False),
                    config.recipients,
                ),
            }
        )

    try:
        outcome = send(client, request, role)
    except AdvisorError as exc:
        if exc.sent:  # it may have reached the provider: recorded all the same
            record(None, "failed", None, None, str(exc), exc.request_id)
        raise
    except BaseException:  # Ctrl-C: it has left and may be billed
        record(None, "interrupted", None, None, "interrupted before the answer came")
        raise
    fallback_note, fallback_declined = "", False
    if outcome.status == "declined" and advisor.fallback == "model":
        # Decision 3: the same case, to the organization's fallback model.
        fallback = advisor.fallback_model
        try:
            fallback_client = _client(
                fallback.api_key_source, fallback.api, fallback.base_url, fallback=True
            )
        except AdvisorError as exc:
            fallback_note = f"; the fallback model couldn't be asked: {exc}"
        except BaseException:
            record(outcome, "declined", None, None,
                   "declined; interrupted before the fallback model was asked")  # fmt: skip
            raise
        else:
            try:
                sent_fallback = fallback_request(payload, role, advisor)
            except BaseException:
                record(outcome, "declined", None, None,
                       "declined; the fallback request couldn't be built")  # fmt: skip
                raise
            try:
                second = send(fallback_client, sent_fallback, role)
            except AdvisorError as exc:
                fallback_note = f"; the fallback model couldn't be asked: {exc}"
                if exc.sent:  # it may have reached the fallback's server, and billed
                    outcome = _fallback_failed(outcome, sent_fallback, exc.request_id)
                else:
                    sent_fallback = None
            except BaseException as exc:
                outcome = _fallback_failed(outcome, sent_fallback, None)
                interrupted = isinstance(exc, KeyboardInterrupt)
                record(outcome, "interrupted" if interrupted else "failed", None, None,
                       "declined; interrupted waiting for the fallback model" if interrupted
                       else f"declined; the fallback model's answer couldn't be read"
                       f" ({type(exc).__name__})")  # fmt: skip
                raise
            else:
                fallback_declined = second.status == "declined"
                outcome = merged(outcome, second)
    status, answer, note = outcome.status, None, ""
    raw = outcome.answer.model_dump() if outcome.answer is not None else None
    if outcome.status == "answered":
        ids = {f["id"] for f in payload.get("findings") or []}
        try:
            own = (payload.get("host") or {}).get("name")
            quoted = _quoted(payload) | ({own} if isinstance(own, str) and own else set())
            CHECKS[role](outcome.answer, ids, which["band"], quoted)
        except InvalidAnswer as exc:
            status, note = "invalid", f"the answer was set aside: it {exc}"
        else:
            answer = _restore(raw, pseudonyms.restore) if pseudonyms is not None else raw
    judged, written = None, None
    if status == "answered" and role == "remediation":
        from checker.advisor.roles import DESTRUCTIVE, _plain

        # Marked by the tool's own reading too, whatever the step says; on a
        # copy, so the stored raw answer stays the model's.
        answer = copy.deepcopy(answer)
        for key in ("preserve", "contain", "eradicate", "recover"):
            for step in answer.get(key) or []:
                step["destructive"] = bool(step.get("destructive")) or bool(
                    DESTRUCTIVE.search(_plain(step.get("action") or ""))
                )
    if status == "answered" and role == "coverage":
        from checker.advisor.coverage import judge as judge_coverage

        host_text = payload.get("from_host") or {}
        gaps = host_text.get("coverage_gaps", payload.get("coverage_gaps")) or []
        ids = {f["id"] for f in payload.get("findings") or []}
        # The gaps as the advisor saw them, names restored: what each G-n means.
        shown = [pseudonyms.restore(g) if pseudonyms else g for g in gaps]
        judged = judge_coverage(answer.get("suggestions") or [], shown, ids, config)
        answer = dict(
            answer,
            judged=[
                {"accepted": j.accepted, "reason": j.reason, "action": j.action,
                 "note": j.note, "cited": j.cited, "suggestion": j.suggestion}
                for j in judged
            ],
        )  # fmt: skip
    if status == "answered" and role == "whitelist":
        try:
            judged, written = _proposals(
                store, host, identity, inventory, whitelist, which, answer, home
            )
        except Exception as exc:  # the answer was paid for: kept, whatever happens next
            note = f"the proposals couldn't be judged: {type(exc).__name__}: {exc}"
            record(outcome, "invalid", raw, answer, note)
            raise AdvisorError(note) from exc
        answer = dict(
            answer,
            judged=[
                {"id": j.proposal.get("id"), "accepted": j.accepted, "reason": j.reason,
                 "hides": j.hides}
                for j in judged
            ],
            file=str(written) if written else None,
        )  # fmt: skip
    elif outcome.status == "declined":
        note = (
            "the request was declined by the model's safety checks"
            + (f" ({outcome.refusal_category})" if outcome.refusal_category else "")
            + (
                ", and by the fallback too"
                if fallback_declined or len(outcome.declined_by) > 1
                else ""
            )
            + fallback_note
        )
    elif outcome.status == "cut off":
        note = outcome.note or "the answer was cut off at its length limit"
    elif outcome.status == "unreadable":
        note = "the answer didn't fit the requested form"
    record(outcome, status, raw, answer, note)
    return Advice(status, outcome, answer, note, judged, written)


def _client(source: str, api: str, base_url: str | None, fallback: bool = False):
    try:
        key = read_api_key(source, key_places(api, base_url, fallback))
    except KeySourceError as exc:
        raise AdvisorError(f"no API key: {exc}") from None
    return make_client(key, api, base_url)


def _fallback_failed(first: Outcome, request, request_id: str | None) -> Outcome:
    """A declined request whose fallback may have reached its server but
    brought nothing back: still declined, with the fallback's server and
    request id kept, and its cost unknown unless it is on this machine."""
    hop = Outcome("failed", request.body["model"], request_id=request_id,
                  endpoint=request.base_url)  # fmt: skip
    both = merged(first, hop)
    both.status, both.model_answered = "declined", None
    both.refusal_category = first.refusal_category
    both.iterations[-1]["unknown"] = True
    return both


def cost_line(advisor: Advisor, tokens: int) -> tuple[str, Estimate | None]:
    """What a run will likely cost and the most it can, in words, and the
    estimate (None: unknown, so the run asks). A model on this machine
    costs nothing; a server without a price list is unknown."""
    where = f" at {advisor.base_url}" if advisor.base_url else ""
    if is_local(advisor.base_url):
        priced: Estimate | None = Estimate(0.0, 0.0)
        line = f"About {tokens} input tokens to {advisor.model} on this machine{where}: no charge."
    else:
        priced = (
            None
            if advisor.api == "openai"
            else estimate(advisor.model, tokens, MAX_TOKENS, advisor.fallback == "anthropic")
        )
        if priced is None:
            line = (
                f"About {tokens} input tokens to {advisor.model}{where};"
                " no price is known for that model."
            )
        else:
            rerun = (
                ", and a re-run on a fallback model if declined"
                if advisor.fallback == "anthropic"
                else ""
            )
            line = (
                f"About {tokens} input tokens to {advisor.model}{where} (estimated here;"
                f" nothing sent yet): likely about ${priced.likely:.2f}, at most about"
                f" ${priced.most:.2f} (a {MAX_TOKENS}-token answer{rerun})."
            )
    if advisor.fallback == "model" and priced is not None:
        fallback = advisor.fallback_model
        if is_local(fallback.base_url):
            line += f" If declined, {fallback.model} on this machine: no charge."
        elif fallback.api == "anthropic" and (
            again := estimate(fallback.model or "", tokens, MAX_TOKENS)
        ):
            priced = Estimate(priced.likely, priced.most + again.most)
            line += f" If declined, {fallback.model} too: at most about ${again.most:.2f} more."
        else:
            # Unknown: the run asks, as for any unknown cost.
            priced = None
            line += f" If declined, {fallback.model} too, at a cost not known here."
    return line, priced


def merged(first: Outcome, second: Outcome) -> Outcome:
    """A declined request and the fallback model's outcome, as one: who
    declined, who answered and where, and the usage of each."""
    hops = first.iterations or [
        {"model": first.model_asked, "type": "message", **first.usage,
         "endpoint": first.endpoint}
    ]  # fmt: skip
    hops[-1].setdefault("request_id", first.request_id)
    hops.append(
        {"model": second.model_answered or second.model_asked, "type": "fallback_model",
         **second.usage, "endpoint": second.endpoint, "request_id": second.request_id}
    )  # fmt: skip
    declined = first.declined_by + [m for m in second.declined_by if m not in first.declined_by]
    total = {
        key: (first.usage.get(key) or 0) + (second.usage.get(key) or 0)
        for key in ("input_tokens", "output_tokens")
    }
    second.model_asked = first.model_asked
    second.declined_by = declined
    second.iterations = hops
    second.usage = total
    if second.status == "declined" and not second.refusal_category:
        second.refusal_category = first.refusal_category
    return second


def spent(outcome: Outcome) -> float | None:
    """What a request cost: each model that ran at its own rate, nothing
    for a model on this machine; None when a model that ran has no price."""
    if outcome.iterations:
        total = 0.0
        for hop in outcome.iterations:
            if is_local(hop.get("endpoint")):
                continue
            if hop.get("unknown"):  # it may have run, with no usage to show for it
                return None
            part = cost(hop.get("model") or outcome.model_asked, hop)
            if part is None:
                return None
            total += part
        return total
    if is_local(outcome.endpoint):
        return 0.0
    return cost(outcome.model_answered or outcome.model_asked, outcome.usage)


def _proposals(store, host, identity, inventory, whitelist, which, answer, home):
    """Role 2's rules judged against the real findings (checker.advisor.
    proposals), and the file the accepted ones go to."""
    from checker.advisor.proposals import judge, write_file
    from checker.assess import load_assessment
    from checker.baseline import usable_bundles
    from checker.inventory import home as default_home
    from checker.whitelist import WhitelistError
    from checker.whitelist import for_host as whitelist_for_host

    base = home or default_home()
    report = which["report"]
    group = which["group"]

    def assessments(name: str, skip: str | None = None) -> list[dict]:
        found = []
        for row in usable_bundles(store, name):
            if row["id"] != skip and (assessment := load_assessment(store, row["id"], identity)):
                found.append(assessment)
        return found

    others = assessments(host, skip=which["bundle_id"])
    group_others: list[dict] = []

    def ids(whitelist) -> set[str]:
        """Every id a rule could clash with when copied in: rules, windows,
        and the ones a layer disables."""
        if whitelist is None:
            return set()
        found = {placed.rule.id for placed in [*whitelist.rules, *whitelist.windows]}
        return found | {str(d.get("id")) for d in whitelist.disabled}

    rule_ids = ids(whitelist)
    if group:
        for entry in inventory.hosts:
            if entry.group == group and entry.name != host:
                group_others += assessments(entry.name)
                try:
                    theirs = whitelist_for_host(base, entry.name, inventory)
                except WhitelistError:
                    theirs = None
                rule_ids |= ids(theirs)
    judged = judge(
        answer.get("proposals") or [],
        report.assessment["findings"],
        (report.assessment.get("score") or {}).get("chains") or [],
        report.events,
        others,
        group_others,
        rule_ids,
        group=group,
        band=which["band"],
    )
    written = write_file(base, host, group, judged, datetime.now(UTC).strftime("%Y-%m-%d %H:%M"))
    return judged, written


def _quoted(payload: dict[str, Any]) -> set[str]:
    """F-n strings in the case's host text, which an answer may quote."""
    found: set[str] = set()

    def walk(value: Any, host: bool) -> None:
        if isinstance(value, str):
            if host:
                found.update(FINDING_ID.findall(value))
        elif isinstance(value, list):
            for item in value:
                walk(item, host)
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, host or key in ("from_host", "os", "kernel", "account"))

    walk(payload, False)
    return found


def latest_advice(
    store, host: str, identity, bundle_id: str, assessed_at: str | None
) -> dict[str, dict[str, Any]]:
    """For the report, per role: the latest answer about this bundle, else
    the host's latest answer about another (either marked stale when it
    read another collection or assessment than the report shows), and,
    when a later request about this bundle came to nothing, that too."""
    shown: dict[str, dict[str, Any]] = {}
    rows = store.advice_for_host(host)
    # Other bundles' rows first, this bundle's last: this bundle's win.
    rows = [r for r in rows if r["bundle_id"] != bundle_id] + [
        r for r in rows if r["bundle_id"] == bundle_id
    ]
    for row in rows:
        record = dict(row)
        record.pop("request", None)
        saved = json.loads(open_text(row["answer"], identity) or "{}")
        record["answer"] = saved.get("restored")
        record["note"] = saved.get("note") or ""
        record["declined_by"] = json.loads(row["declined_by"]) if row["declined_by"] else []
        record["stale"] = row["bundle_id"] != bundle_id or row["assessed_at"] != assessed_at
        record["local"] = is_local(row["endpoint"])
        entry = shown.setdefault(row["role"], {})
        if record["answer"] is not None:
            entry["answered"] = record
            entry.pop("later", None)
        elif row["bundle_id"] == bundle_id:
            entry["later"] = record
    return shown
