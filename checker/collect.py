"""One collection run across hosts: transport → encrypted bundle → store."""

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from checker.evidence import (
    BundleWriter,
    Config,
    Store,
    bundle_id,
    bundle_path,
    database_file,
    write_sidecar,
)
from checker.inventory import Host
from checker.protocol import Limits, Settings, build_program, collector_sha256
from checker.transport import PasswordProvider, Session, TransportError, collect, collect_many

DEFAULT_LIMITS = Limits(overall_seconds=600, module_seconds=120, source_bytes=256 * 1024 * 1024)


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
) -> list[Outcome]:
    """Collect from every host and store each result, failures included: a
    failed run still left traces on its host, so its session is kept too."""
    started = datetime.now(UTC)
    settings = Settings(
        run_id=str(uuid.uuid4()),
        since=started - timedelta(days=days),
        modules=None,
        limits=limits,
    )
    program = build_program(settings)
    fingerprint = collector_sha256()
    store = Store(database_file(home))
    outcomes: list[Outcome] = []

    async def one(host: Host) -> Session:
        run_started = datetime.now(UTC)
        identifier = bundle_id(host.name, run_started, settings.run_id)
        writer = BundleWriter(bundle_path(home, host.name, identifier), config.recipients)
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
            sealed = writer.seal()
        manifest = sealed.summary.manifest or {}
        row = {
            "id": identifier,
            "host": host.name,
            "run_id": settings.run_id,
            "path": str(sealed.path),
            "started_at": run_started.isoformat(),
            "ended_at": datetime.now(UTC).isoformat(),
            "status": sealed.status,
            "collector_version": manifest.get("collector_version"),
            "collector_sha256": fingerprint,
            "plaintext_sha256": sealed.plaintext_sha256,
            "plaintext_bytes": sealed.plaintext_bytes,
            "ciphertext_sha256": sealed.ciphertext_sha256,
            "ciphertext_bytes": sealed.ciphertext_bytes,
            "recipients": json.dumps(config.recipients),
            "session": json.dumps(asdict(session), default=str) if session else None,
            "summary": json.dumps(sealed.summary.as_dict()),
            "problem": str(error) if error else sealed.problem,
        }
        store.record_bundle(row)
        write_sidecar(sealed, row)
        outcomes.append(
            Outcome(host.name, identifier, sealed.status, row["problem"], sealed.plaintext_bytes)
        )
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
