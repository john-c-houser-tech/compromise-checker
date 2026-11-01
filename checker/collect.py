"""One collection run across hosts: transport → encrypted bundle → store."""

import asyncio
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
    judge,
    mail_gate_open,
    mail_key,
    record_mail_gate,
    seal_text,
    write_sidecar,
)
from checker.inventory import Host
from checker.protocol import Limits, Settings, build_program, collector_sha256
from checker.transport import PasswordProvider, Session, TransportError, collect, collect_many

DEFAULT_LIMITS = Limits(overall_seconds=600, module_seconds=120, source_bytes=256 * 1024 * 1024)


def mail_key_for(
    home: Path, host: Host, key: str, reads_sudo: bool = True
) -> tuple[str | None, str | None]:
    """The mail key to send to a host, or why not (policy §7: the key is
    never written on a server). The program, key included, reaches the
    collector on sudo's input, which sudo writes to disk where its input
    logging is on, and the collector can't tell before sudo has logged it.
    So the key goes only to a host whose latest collection, at the same
    address, showed sudo, read whole, not logging its input. The host's
    gate is then closed until this collection's own answer is recorded, so
    a run whose answer can't be recorded leaves it closed (`reads_sudo`: the
    run collects sudo's settings; one that doesn't leaves the gate as it was)."""
    address = f"{host.address}:{host.port}"
    sent = key if mail_gate_open(home, key, host.name, address) else None
    try:
        if reads_sudo:
            record_mail_gate(home, key, host.name, address, None)
    except OSError as exc:
        return None, f"the mail gate couldn't be updated ({exc}), so the mail key wasn't sent"
    if sent is None:
        return None, (
            "sudo's input logging wasn't shown to be off at the last collection (or this is"
            " the first), so the mail key wasn't sent"
        )
    return sent, None


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
        web_access_logs=config.web_access_logs,
        exec_records=config.exec_records,
        web_users=config.web_users,
    )
    key = mail_key(home)
    fingerprint = collector_sha256()
    store = Store(database_file(home))
    outcomes: list[Outcome] = []

    async def one(host: Host) -> Session:
        run_started = datetime.now(UTC)
        identifier = bundle_id(host.name, run_started, settings.run_id)
        writer = BundleWriter(bundle_path(home, host.name, identifier), config.recipients)
        host_key, withheld = mail_key_for(
            home, host, key, reads_sudo=modules is None or "sudoers" in modules
        )
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
        stopped = False
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
        except asyncio.CancelledError:  # stopped: what it has so far is still kept, and recorded
            stopped = True
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
        if stopped:
            problem = "stopped before it finished"
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
        # What this collection showed about sudo's input logging decides
        # whether the next one gets the mail key; a run that didn't read
        # sudo's settings leaves that as it was. After the bundle is
        # recorded: a problem here must never cost the evidence.
        if modules is None or "sudoers" in modules:
            try:
                record_mail_gate(
                    home,
                    key,
                    host.name,
                    f"{host.address}:{host.port}",
                    sealed.summary.sudo_input_logging,
                )
            except OSError as exc:
                problem = f"{problem + '; ' if problem else ''}mail gate not recorded: {exc}"
        outcomes.append(Outcome(host.name, identifier, status, problem, sealed.plaintext_bytes))
        if stopped:
            raise asyncio.CancelledError
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
