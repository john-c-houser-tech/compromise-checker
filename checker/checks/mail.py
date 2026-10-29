"""Outgoing mail (DESIGN.md §8.9): mail submitted by web-server accounts,
relay changes and open-relay settings, sudden volume and queue growth, and
new recipient domains in bulk.

Addresses arrive fingerprinted (`h:3f9a1c2e5b7d@example.org`, policy §7):
recipients are counted and domains compared without any being shown."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from checker.checks import COMPROMISE, EXPOSURE, Context, Finding, check, parse_time, span
from checker.events import Event

WEB_USERS = {"www-data", "apache", "nginx", "http", "wwwrun", "lighttpd"}
DELIVERIES = ("mail.sent", "mail.deferred", "mail.bounced")
VOLUME_FLOOR = 100  # deliveries in a day, at the least, to be a jump
VOLUME_FACTOR = 10  # times the baseline's daily average
NEW_DOMAINS = 50  # recipient domains never seen before, in one day
QUEUE_LIMIT = 500  # messages waiting, whatever the baseline
QUEUE_FLOOR = 50  # messages waiting, at the least, to be ten times the baseline
SHOWN = 8
MAX_EVIDENCE = 50
# Settings that send mail somewhere else: a change is how an intruder
# routes a server's mail through their own relay.
RELAY_SETTINGS = {
    "postfix: relayhost",
    "postfix: smtp_fallback_relay",
    "postfix: default_transport",
    "postfix: relay_transport",
    "postfix: transport_maps",
    "postfix: sender_dependent_relayhost_maps",
    "exim: dc_smarthost",
    "exim: route_list",
    "exim: route_data",
}
LOOPBACK = {"loopback-only", "localhost", "127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1"}
BLOCKS_RELAY = {
    "reject_unauth_destination",
    "defer_unauth_destination",
    "reject",
    "defer",
    "defer_all",
    "defer_if_permit",
}
# A relay setting added or removed with one of these values routes nothing
# elsewhere: a mail server installed or removed (its package shows that).
NO_RELAY = {"", "error", "local"}


def _account(event: Event, names: dict[Any, str]) -> str | None:
    """Who submitted it: Exim names the user, Postfix's pickup the UID."""
    if event.fields.get("user"):
        return str(event.fields["user"])
    return names.get(event.fields.get("uid"))


@check("mail.web_user", "Mail submitted by a web-server account")
def web_user(context: Context) -> list[Finding]:
    names = {
        item.get("uid"): name
        for name, item in context.items("accounts").items()
        if item.get("uid") is not None
    }
    by_user: dict[str, list[tuple[int, Event]]] = {}
    for index, event in context.of("mail.submitted"):
        user = _account(event, names)
        if user in WEB_USERS:
            by_user.setdefault(user, []).append((index, event))
    findings = []
    for user, found in sorted(by_user.items()):
        messages = len({e.fields.get("queue_id") or i for i, e in found})
        first, last = span([e for _, e in found])
        findings.append(
            Finding(
                "mail.web_user",
                "Mail submitted by a web-server account",
                COMPROMISE,
                "medium",
                f"{user}: {messages} message{'s' if messages != 1 else ''}",
                [f"account:{user}"],
                [{"event": i} for i, _ in found[:MAX_EVIDENCE]],
                first,
                last,
            )
        )
    return findings


# --- Settings ------------------------------------------------------------------------------


def _value(items: dict[str, dict[str, Any]], key: str) -> str | None:
    item = items.get(key)
    return str(item.get("value") or "") if item is not None else None


def _network(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """A network from a list entry; None for lookup tables, files,
    variables and host names, which can't be judged from the text."""
    if any(c in entry for c in "$/{}") and not _looks_like_cidr(entry):
        return None
    try:
        return ipaddress.ip_network(entry.strip("[]").replace("]/", "/"), strict=False)
    except ValueError:
        return None


def _looks_like_cidr(entry: str) -> bool:
    address, _, prefix = entry.partition("/")
    return prefix.isdigit() and "$" not in address and "{" not in address


def _wide(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Wider than any one host's own networks: a /0 to /7 (IPv4; /15 for
    IPv6) of any kind, or a public network wider than a /24 (/48)."""
    if network.version == 4:
        return network.prefixlen < 8 or (network.is_global and network.prefixlen < 24)
    return network.prefixlen < 16 or (network.is_global and network.prefixlen < 48)


def _wide_entries(entries: Iterable[str]) -> list[str]:
    return [e for e in entries if (net := _network(e.strip())) is not None and _wide(net)]


def _blocks(restrictions: str) -> bool:
    """Whether a Postfix restriction list refuses mail for other domains
    before anything permits it; a list with variables counts as refusing
    (it can't be judged from the text)."""
    if "$" in restrictions:
        return True
    for word in restrictions.replace(",", " ").split():
        if word in BLOCKS_RELAY:
            return True
        if word == "permit":
            return False
    return False


def postfix_open(items: dict[str, dict[str, Any]]) -> list[tuple[str, str]]:
    """Why Postfix relays for anyone, as (setting, reason): trusted networks
    wider than a host's own, or restrictions that never refuse other
    domains. Nothing when it listens on loopback only."""
    if not any(key.startswith("postfix: ") for key in items):
        return []
    interfaces = (_value(items, "postfix: inet_interfaces") or "all").replace(",", " ").split()
    if interfaces and all(i in LOOPBACK for i in interfaces):
        return []
    reasons = []
    networks = _value(items, "postfix: mynetworks")
    if networks is not None:
        for entry in _wide_entries(networks.replace(",", " ").split()):
            reasons.append(("postfix: mynetworks", f"mynetworks trusts {entry}"))
    elif _value(items, "postfix: mynetworks_style") == "class":
        reasons.append(
            ("postfix: mynetworks_style", "mynetworks_style = class trusts a whole address class")
        )
    relay = _value(items, "postfix: smtpd_relay_restrictions")
    recipient = _value(items, "postfix: smtpd_recipient_restrictions")
    # Postfix 2.10 and later refuse relaying by default (relay restrictions
    # unset); recipient restrictions are empty by default.
    if not (relay is None or _blocks(relay)) and not (recipient and _blocks(recipient)):
        reasons.append(
            (
                "postfix: smtpd_relay_restrictions",
                "neither smtpd_relay_restrictions nor smtpd_recipient_restrictions refuses"
                " mail for other domains",
            )
        )
    return reasons


def _exim_list(value: str) -> list[str]:
    """An Exim list: colon-separated, or another separator after `<`."""
    value = value.strip()
    if value.startswith("<") and len(value) > 1:
        separator, value = value[1], value[2:]
    else:
        separator = ";" if ";" in value else ":"
    return [e.strip() for e in value.split(separator) if e.strip()]


def exim_open(items: dict[str, dict[str, Any]]) -> list[tuple[str, str]]:
    """Why Exim relays for anyone: relay networks wider than a host's own,
    or relaying to every domain. Nothing when it listens on loopback only."""
    listening = _value(items, "exim: dc_local_interfaces") or _value(
        items, "exim: local_interfaces"
    )
    if listening and all(e in LOOPBACK for e in _exim_list(listening.replace(" ", ""))):
        return []
    reasons = []
    for key in ("exim: dc_relay_nets", "exim: hostlist relay_from_hosts"):
        value = _value(items, key)
        for entry in _wide_entries(_exim_list(value or "")):
            reasons.append((key, f"{key.split(' ')[-1]} trusts {entry}"))
    for key in ("exim: dc_relay_domains", "exim: domainlist relay_to_domains"):
        if "*" in _exim_list(_value(items, key) or ""):
            reasons.append((key, f"{key.split(' ')[-1]} allows every domain"))
    return reasons


@check(
    "mail.relay",
    "Mail relay changed, or relaying open to anyone",
    variants=("relay", "open_relay"),
)
def relay(context: Context) -> list[Finding]:
    findings = []
    diff = context.changes("mail_config")
    for how in ("added", "changed", "removed") if diff is not None else ():
        for key, item in diff[how].items():
            if key.split(" (", 1)[0] not in RELAY_SETTINGS:
                continue
            if how == "changed":
                if "value" not in item:
                    continue
                before, after = item["value"]
                what = f"{key}: {before or '(empty)'} → {after or '(empty)'}"
            elif str(item.get("value") or "").strip() in NO_RELAY:
                continue
            else:
                what = f"{key} {how}: {item.get('value')}"
            findings.append(
                Finding(
                    "mail.relay",
                    "The mail relay setting changed",
                    COMPROMISE,
                    "medium",
                    what,
                    [f"path:{(context.items('mail_config').get(key) or item).get('path')}"],
                    [context.change_ref("mail_config", key, how)],
                    new=context.new_since_previous("mail_config", key),
                    uncertain=context.uncertain("mail_config"),
                    variant="relay",
                )
            )
    items = context.items("mail_config")
    reasons = postfix_open(items) + exim_open(items)
    if reasons:
        findings.append(
            Finding(
                "mail.relay",
                "The mail server relays for addresses outside the host's networks",
                EXPOSURE,
                "medium",
                "; ".join(reason for _, reason in reasons),
                sorted({f"path:{items[key].get('path')}" for key, _ in reasons if key in items}),
                [{"item": ["mail_config", key]} for key in dict.fromkeys(k for k, _ in reasons)],
                uncertain=context.uncertain("mail_config"),
                variant="open_relay",
            )
        )
    return findings


# --- Volume and domains --------------------------------------------------------------------


def _time(event: Event) -> datetime | None:
    moment = parse_time(event.corrected)
    if moment is not None and moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment


def _deliveries(events: Iterable[Event]) -> dict[tuple, tuple[datetime, Event]]:
    """Each message's outgoing delivery to each recipient (not one into a
    mailbox on the host), once, at its first
    attempt: retries of deferred mail, and the same line in several logs
    or several bundles (whose look-backs overlap), aren't new mail."""
    first: dict[tuple, tuple[datetime, Event]] = {}
    for event in events:
        if event.own_session or event.type not in DELIVERIES or event.fields.get("local"):
            continue
        moment = _time(event)
        if moment is None:
            continue
        queue_id = event.fields.get("queue_id")
        key = (queue_id, event.fields.get("recipient")) if queue_id else (moment, id(event))
        if key not in first or moment < first[key][0]:
            first[key] = (moment, event)
    return first


def _history(context: Context) -> tuple[dict[tuple, tuple[datetime, Event]], set[tuple]]:
    """Every delivery known, from earlier bundles and this one, and which
    of them this bundle holds."""
    current = _deliveries(context.events)
    earlier = _deliveries(e for events in context.earlier_events() for e in events)
    for key, found in current.items():
        if key not in earlier or found[0] < earlier[key][0]:
            earlier[key] = found
    return earlier, set(current)


def _days_after(
    deliveries: dict[tuple, tuple[datetime, Event]], current: set[tuple], since: datetime
) -> dict[str, list[tuple[datetime, Event]]]:
    """This bundle's deliveries after `since`, by day (UTC)."""
    days: dict[str, list[tuple[datetime, Event]]] = {}
    for key in current:
        moment, event = deliveries[key]
        if moment >= since:
            days.setdefault(moment.date().isoformat(), []).append((moment, event))
    return days


def _indexes(context: Context, events: list[Event]) -> list[dict[str, int]]:
    position = {id(e): i for i, e in enumerate(context.events)}
    return [{"event": position[id(e)]} for e in events if id(e) in position][:MAX_EVIDENCE]


def _queued(snapshot) -> int | None:
    """Messages waiting: Postfix's deferred queue and Exim's spool."""
    if snapshot is None or "mail_queues" not in snapshot.live:
        return None
    total = 0
    for queue in snapshot.live["mail_queues"]:
        counts = queue.get("queues") or {}
        total += counts.get("deferred", 0) + counts.get("input", 0)
    return total


@check(
    "mail.volume",
    "A sudden jump in outgoing mail, or a growing queue",
    needs_baseline=True,
    variants=("deliveries", "queue"),
)
def volume(context: Context) -> list[Finding]:
    findings = []
    since = parse_time(context.baseline_time)
    if since is not None:
        if since.tzinfo is None:
            since = since.replace(tzinfo=UTC)
        deliveries, current = _history(context)
        before = [moment for moment, _ in deliveries.values() if moment < since]
        days = max(1.0, (since - min(before)).total_seconds() / 86400) if before else 1.0
        average = len(before) / days
        limit = max(VOLUME_FLOOR, VOLUME_FACTOR * average)
        for day, found in sorted(_days_after(deliveries, current, since).items()):
            if len(found) <= limit:
                continue
            events = [e for _, e in sorted(found, key=lambda f: f[0])]
            first, last = span(events)
            findings.append(
                Finding(
                    "mail.volume",
                    "A sudden jump in outgoing mail",
                    COMPROMISE,
                    "medium",
                    f"{day}: {len(found)} deliveries attempted; the baseline averaged"
                    f" {average:.1f} a day",
                    [f"host:{context.host}"],
                    _indexes(context, events),
                    first,
                    last,
                    variant="deliveries",
                )
            )
    waiting = _queued(context.snapshot)
    # A baseline without queue counts (collected before they were) is
    # compared with nothing: only the absolute limit applies.
    before_queue = _queued(context.baseline_snapshot)
    grown = (
        before_queue is not None
        and waiting is not None
        and waiting >= QUEUE_FLOOR
        and waiting > VOLUME_FACTOR * before_queue
    )
    if waiting is not None and (waiting > QUEUE_LIMIT or grown):
        findings.append(
            Finding(
                "mail.volume",
                "The mail queue has grown",
                COMPROMISE,
                "medium",
                f"{waiting} messages waiting; "
                + (
                    f"{before_queue} at the baseline"
                    if before_queue is not None
                    else "no count at the baseline"
                ),
                [f"host:{context.host}"],
                [{"live": ["mail_queues", 0]}],
                uncertain=(
                    "the queue count was cut short"
                    if context.snapshot.live.get("mail_queue_incomplete")
                    else None
                ),
                new=(_queued(context.previous_snapshot) or 0) < waiting,
                variant="queue",
            )
        )
    return findings


@check(
    "mail.domains",
    "Many recipient domains never written to before, in one day",
    needs_baseline=True,
)
def domains(context: Context) -> list[Finding]:
    since = parse_time(context.baseline_time)
    if since is None:
        return []
    if since.tzinfo is None:
        since = since.replace(tzinfo=UTC)
    deliveries, current = _history(context)
    # Each domain's first delivery ever known; a domain is new on the day of
    # it, if that delivery is this bundle's and came after the baseline.
    first_seen: dict[str, tuple[datetime, tuple]] = {}
    for key, (moment, event) in deliveries.items():
        domain = event.fields.get("domain") or ""
        if domain and (domain not in first_seen or moment < first_seen[domain][0]):
            first_seen[domain] = (moment, key)
    by_day: dict[str, dict[str, list[Event]]] = {}
    for domain, (moment, key) in first_seen.items():
        if key in current and moment >= since:
            day = moment.date().isoformat()
            by_day.setdefault(day, {})[domain] = [deliveries[key][1]]
    findings = []
    for day, new in sorted(by_day.items()):
        if len(new) <= NEW_DOMAINS:
            continue
        names = sorted(new)
        events = sorted((e for found in new.values() for e in found[:1]), key=lambda e: e.corrected)
        first, last = span(events)
        findings.append(
            Finding(
                "mail.domains",
                "Mail to many recipient domains never written to before",
                COMPROMISE,
                "medium",
                f"{day}: {len(names)} new domains: {', '.join(names[:SHOWN])}"
                + (f" and {len(names) - SHOWN} more" if len(names) > SHOWN else ""),
                [f"domain:{name}" for name in names[:200]],
                _indexes(context, events),
                first,
                last,
                entities_complete=len(names) <= 200,
            )
        )
    return findings
