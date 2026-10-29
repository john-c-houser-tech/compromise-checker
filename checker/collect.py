"""One collection run across hosts: transport → encrypted bundle → store."""

import asyncio
import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from checker.analysis import snapshot_of
from checker.baseline import usable_bundles
from checker.evidence import (
    BundleWriter,
    Config,
    EvidenceError,
    Store,
    bundle_id,
    bundle_path,
    database_file,
    judge,
    load_identity,
    mail_key,
    seal_text,
    write_sidecar,
)
from checker.inventory import Host
from checker.protocol import Limits, Settings, build_program, collector_sha256
from checker.transport import PasswordProvider, Session, TransportError, collect, collect_many

DEFAULT_LIMITS = Limits(overall_seconds=600, module_seconds=120, source_bytes=256 * 1024 * 1024)
# sudo's input logging: an un-negated log_input or log_stdin in a Defaults
# line, or a LOG_INPUT: tag on a rule (NOLOG_INPUT: turns it off).
_SUDO_LOGS_INPUT = re.compile(r"(?<![!\w])(?:log_input|log_stdin)\b|(?<!NO)LOG_INPUT:")


def mail_key_for(
    store: Store, config: Config, host: str, key: str
) -> tuple[str | None, str | None]:
    """The mail key to send to a host, or why not (policy §7: the key is
    never written on a server). The program, key included, reaches the
    collector on sudo's input, which sudo writes to disk where its input
    logging is on; the collector can't tell before sudo has logged it. So
    the key goes only to a host whose latest stored collection shows
    sudo's rules, read whole, without input logging."""
    rows = usable_bundles(store, host)
    if not rows:
        return None, "first collection: sudo's settings not seen yet, so the mail key wasn't sent"
    if not config.identity_file:
        return None, "the evidence key isn't on this machine, so sudo's settings can't be read"
    try:
        identity = load_identity(Path(config.identity_file))
        snapshot = snapshot_of(store, rows[-1], identity, config.recipients)
    except EvidenceError as exc:
        return None, f"sudo's settings can't be read ({exc})"
    rules = snapshot.sections.get("sudo_rules")
    if rules is None or not rules.complete:
        return None, "sudo's settings weren't fully collected last time"
    if any(_SUDO_LOGS_INPUT.search(line) for line in rules.items):
        return None, "sudo logs its input on this host, so the mail key would be written there"
    return key, None


@dataclass
class Outcome:
    host: str
    bundle_id: str
    status: str  # complete / partial / refused / incomplete / broken / empty / not_recorded
    error: str | None
    bytes: int


async def collect_hosts(
    home: Path,
    config: Config,
    hosts: list[Host],
    *,
    days: int = 30,
    parallel: int = 5,
    password_provider: PasswordProvider | None = None,
    known_hosts: Path | None = None,
    limits: Limits = DEFAULT_LIMITS,
    modules: list[str] | None = None,
) -> list[Outcome]:
    """Collect from every host and store each result, failures included: a
    failed run still left traces on its host, so its session is kept too."""
    started = datetime.now(UTC)
    settings = Settings(
        run_id=str(uuid.uuid4()),
        since=started - timedelta(days=days),
        modules=modules,  # None: every module
        limits=limits,
        home_text=config.home_text,
    )
    key = mail_key(home)
    fingerprint = collector_sha256()
    store = Store(database_file(home))
    outcomes: list[Outcome] = []

    async def one(host: Host) -> Session:
        run_started = datetime.now(UTC)
        identifier = bundle_id(host.name, run_started, settings.run_id)
        writer = BundleWriter(bundle_path(home, host.name, identifier), config.recipients)
        host_key, withheld = mail_key_for(store, config, host.name, key)
        # The host's own web roots, if it has any, replace the defaults.
        program = build_program(
            settings.model_copy(
                update={
                    "web_roots": host.web_roots,
                    "mail_key": host_key,
                    "mail_key_withheld": withheld,
                }
            )
        )
        session: Session | None = None
        error: TransportError | None = None
        try:
            session = await collect(
                host,
                program,
                writer.write,
                timeout=limits.overall_seconds + 120,
                password_provider=password_provider,
                known_hosts=known_hosts,
            )
        except TransportError as exc:
            error, session = exc, exc.session
        finally:
            # Joining the encryptor and fsync can be slow: keep other hosts moving.
            sealed = await asyncio.to_thread(writer.seal)
        manifest = sealed.summary.manifest or {}
        status, verdict = judge(
            sealed.status,
            sealed.summary.manifest,
            settings.run_id,
            session.exit_status if session else None,
        )
        problem = str(error) if error else (sealed.problem or verdict)
        row = {
            "id": identifier,
            "host": host.name,
            "run_id": settings.run_id,
            "path": str(sealed.path),
            "started_at": run_started.isoformat(),
            "ended_at": datetime.now(UTC).isoformat(),
            "status": status,
            "collector_version": manifest.get("collector_version"),
            "collector_sha256": fingerprint,
            "plaintext_sha256": sealed.plaintext_sha256,
            "plaintext_bytes": sealed.plaintext_bytes,
            "ciphertext_sha256": sealed.ciphertext_sha256,
            "ciphertext_bytes": sealed.ciphertext_bytes,
            "recipients": json.dumps(config.recipients),
            # Only identifiers, times, status, sizes and hashes stay readable
            # without the key (security and privacy policy §8).
            "session": seal_text(
                json.dumps(asdict(session), default=str) if session else None, config.recipients
            ),
            "summary": seal_text(json.dumps(sealed.summary.as_dict()), config.recipients),
            "problem": seal_text(problem, config.recipients),
        }
        store.record_bundle(row)
        write_sidecar(sealed, row)
        outcomes.append(Outcome(host.name, identifier, status, problem, sealed.plaintext_bytes))
        if error is not None:
            raise error
        return session

    try:
        results = await collect_many(hosts, one, parallel=parallel)
    finally:
        store.close()
    # A host whose bundle couldn't even be created or recorded must still be
    # reported, never silently dropped.
    recorded = {outcome.host for outcome in outcomes}
    for name, result in results.items():
        if name not in recorded:
            outcomes.append(Outcome(name, "", "not_recorded", str(result), 0))
    return sorted(outcomes, key=lambda outcome: outcome.host)
