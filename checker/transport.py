"""SSH transport: run the collector on a host and stream its output back.

DESIGN.md §5.1 and docs/collector-protocol.md §1. Host keys are always
verified against the tool's own known-hosts file; there is no way to turn
that off. Passwords are kept in memory only for the run and are never put on
a command line.
"""

import asyncio
import json
import secrets
import shlex
import threading
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import asyncssh
from asyncssh.public_key import decode_ssh_public_key

from checker.files import atomic_write, locked
from checker.inventory import Host, known_hosts_file

STDERR_LIMIT = 64 * 1024
READ_SIZE = 64 * 1024

# Called with each piece of the collector's stdout as it arrives.
Sink = Callable[[bytes], Awaitable[None] | None]
# Asked for a password when a host needs one (SSH or sudo). Never stored.
PasswordProvider = Callable[[Host], str]


class TransportError(Exception):
    """A collection could not be carried out; the message says why.

    `session` is set when the failure came after login: the run still left
    traces on the host (sshd, sudo), and the self-session filter needs the
    record of it."""

    def __init__(self, message: str, session: "Session | None" = None):
        super().__init__(message)
        self.session = session


class UnknownHostKey(TransportError):
    pass


class SudoError(TransportError):
    pass


@dataclass
class Session:
    """What the controller records about one SSH session (DESIGN.md §5.1 step 5).
    The analyzer uses it to recognise the tool's own traces on the host."""

    host: str
    address: str
    port: int
    user: str
    sudo: str
    started_at: datetime
    ended_at: datetime | None = None
    auth_method: str | None = None
    client_key_fingerprint: str | None = None
    server_key_fingerprint: str | None = None
    local_address: str | None = None
    local_port: int | None = None
    remote_address: str | None = None
    remote_port: int | None = None
    # Every key offered, in order: sshd logs refused ones too.
    offered_key_fingerprints: list[str] = field(default_factory=list)
    # The exact command run on the host (sudo logs it), and when the
    # collector's first bytes arrived: the collector writes its manifest,
    # with its start on the host's clock, first, so this is the controller's
    # side of the clock-offset measurement (after any password prompt).
    command: str | None = None
    first_data_at: datetime | None = None
    exit_status: int | None = None
    bytes_received: int = 0
    stderr: str = ""
    error: str | None = None


# In sudo-password mode Python starts with this tiny program instead of `-`:
# it announces itself on stderr, then reads and runs the collector from stdin.
# The announcement can only appear once sudo has accepted the password, so it
# is the positive signal that it is safe to send the program (Python 3.9 safe).
_BOOTSTRAP = (
    'import sys;sys.stderr.write({ready}+"\\n");sys.stderr.flush();'
    'exec(compile(sys.stdin.read(),"<collector>","exec"))'
)


def remote_command(host: Host, prompt: str | None = None, ready: str | None = None) -> str:
    """The command run on the target. Nothing secret is ever part of it."""
    python = [host.python, "-I", "-B", "-"]
    if host.sudo == "root":
        argv = python
    elif host.sudo == "nopasswd":
        # -n: fail rather than ask, so no password can be expected. This is
        # exactly the command the scanner account's sudo rule allows.
        argv = ["sudo", "-n", "--", *python]
    else:
        # -k: always ask, so the prompt we wait for really comes; -S: read
        # the password from stdin; -p: a prompt unique to this run.
        if prompt is None or ready is None:
            raise ValueError("sudo mode 'password' needs prompt and ready markers")
        bootstrap = _BOOTSTRAP.format(ready=json.dumps(ready))
        argv = ["sudo", "-k", "-S", "-p", prompt, "--", host.python, "-I", "-B", "-c", bootstrap]
    return " ".join(shlex.quote(part) for part in argv)


# Credential prompts run off the event loop, so other hosts' SSH traffic and
# time limits keep going while someone types, and one at a time, so prompts
# on a shared terminal never interleave. The lock is taken inside the worker
# thread: if the waiting coroutine is cancelled, the prompt already on screen
# still holds it until it really finishes.
_prompt_lock = threading.Lock()


def _prompt_serially(provider: PasswordProvider, host: Host) -> str:
    with _prompt_lock:
        return provider(host)


async def _ask_password(provider: PasswordProvider, host: Host) -> str:
    return await asyncio.to_thread(_prompt_serially, provider, host)


class _Client(asyncssh.SSHClient):
    """Offers credentials one at a time and remembers which one worked."""

    def __init__(self, keys: list, password: str | None):
        self._keys = list(keys)
        self._password = password
        self._offered_key = None
        self.method: str | None = None
        self.key_fingerprint: str | None = None
        self.offered: list[str] = []
        self.sockname: tuple | None = None
        self.peername: tuple | None = None

    def connection_made(self, conn):
        # Before authentication, so even a refused login records its endpoints.
        self.sockname = conn.get_extra_info("sockname")
        self.peername = conn.get_extra_info("peername")

    def public_key_auth_requested(self):
        if not self._keys:
            return None
        self._offered_key = self._keys.pop(0)
        self.offered.append(_fingerprint(self._offered_key))
        self.method = "publickey"
        return self._offered_key

    def password_auth_requested(self):
        if self._password is None:
            return None
        password, self._password = self._password, None  # offer once
        self.method = "password"
        return password

    def auth_completed(self):
        if self.method == "publickey" and self._offered_key is not None:
            self.key_fingerprint = _fingerprint(self._offered_key)


def _fingerprint(key) -> str:
    """SHA256 fingerprint of a private key or agent key pair, as sshd logs it."""
    return decode_ssh_public_key(key.public_data).get_fingerprint("sha256")


async def _client_keys(host: Host, agent_path: str | None) -> tuple[list, object | None]:
    if host.auth == "key":
        if not host.key_path:
            raise TransportError(f"{host.name}: auth is 'key' but no key_path is set")
        try:
            return [asyncssh.read_private_key(Path(host.key_path).expanduser())], None
        except (OSError, asyncssh.KeyImportError) as exc:
            raise TransportError(f"{host.name}: cannot read key {host.key_path}: {exc}") from exc
    if host.auth == "agent":
        try:
            agent = await asyncssh.connect_agent(agent_path or ())
        except (OSError, asyncssh.Error) as exc:
            raise TransportError(f"{host.name}: no SSH agent available: {exc}") from exc
        if agent is None:
            raise TransportError(f"{host.name}: no SSH agent available (SSH_AUTH_SOCK unset)")
        keys = await agent.get_keys()
        if not keys:
            agent.close()
            raise TransportError(f"{host.name}: the SSH agent holds no keys")
        return list(keys), agent
    return [], None


async def collect(
    host: Host,
    program: str,
    sink: Sink,
    *,
    timeout: float,
    password_provider: PasswordProvider | None = None,
    known_hosts: Path | None = None,
    connect_timeout: float = 15.0,
    prompt_timeout: float = 15.0,
    agent_path: str | None = None,
) -> Session:
    """Run `program` (collector text plus its main(...) line) on `host`,
    passing its stdout to `sink` as it arrives. Raises TransportError with a
    plain explanation if the run cannot be carried out."""
    session = Session(
        host=host.name,
        address=host.address,
        port=host.port,
        user=host.user,
        sudo=host.sudo,
        started_at=datetime.now(UTC),
    )
    known = known_hosts or known_hosts_file()
    if not known.exists():
        raise UnknownHostKey(
            f"{host.name}: no known host keys yet; run `checker trust {host.name}`"
        )

    password = None
    if host.needs_password():
        if password_provider is None:
            raise TransportError(f"{host.name}: a password is needed but none can be asked for")
        try:
            password = await _ask_password(password_provider, host)
        except Exception as exc:
            raise TransportError(f"{host.name}: cannot get a password: {exc}") from exc
    try:
        return await _connect_and_run(
            host, program, sink, session, known, password, timeout, connect_timeout,
            prompt_timeout, agent_path,
        )  # fmt: skip
    except TransportError as exc:
        _take_out_password(exc, session, password)
        raise


def _take_out_password(exc: TransportError, session: Session, password: str | None) -> None:
    """A hostile server can repeat it in anything it sends: a disconnect's reason, sudo's errors.
    Here, before anything cuts the text short or stores it."""
    if not password:
        return
    exc.args = tuple(
        arg.replace(password, "[password]") if isinstance(arg, str) else arg for arg in exc.args
    )
    if session.error:
        session.error = session.error.replace(password, "[password]")
    if session.stderr:
        session.stderr = session.stderr.replace(password, "[password]")


async def _connect_and_run(
    host, program, sink, session, known, password, timeout, connect_timeout, prompt_timeout,
    agent_path,
) -> Session:  # fmt: skip
    keys, agent = await _client_keys(host, agent_path)
    client = _Client(keys, password if host.auth == "password" else None)
    # The agent may ask its user for a passphrase before it signs the
    # login (gpg-agent's pop-up), inside this wait.
    wait = connect_timeout + (AGENT_PROMPT_SECONDS if host.auth == "agent" else 0)
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host.address,
                port=host.port,
                username=host.user,
                known_hosts=str(known),
                client_factory=lambda: client,
                client_keys=[],
                agent_path=None,
                kbdint_auth=False,
                gss_host=None,  # no Kerberos logins; also avoids a slow hostname lookup
                config=None,  # the operator's ~/.ssh/config must not change behaviour
            ),
            wait,
        )
    except asyncssh.HostKeyNotVerifiable as exc:
        raise UnknownHostKey(
            f"{host.name}: host key not trusted ({exc.reason}). If you expected this, check the"
            f" new key and run `checker trust {host.name} --replace`."
        ) from exc
    except asyncssh.PermissionDenied as exc:
        # A refused login still leaves sshd records: keep what was tried.
        raise _failed(session, client, f"{host.name}: login refused for {host.user}") from exc
    except TimeoutError as exc:
        if exc.errno is not None:  # the system's own (no answer to the TCP connect)
            raise _failed(session, client, f"{host.name}: cannot connect: {exc}") from exc
        why = f"{host.name}: cannot connect: timed out after {wait:g} seconds"
        if host.auth == "agent":
            why += " (was the SSH agent waiting for a passphrase?)"
        raise _failed(session, client, why) from exc
    except (OSError, asyncssh.Error) as exc:
        raise _failed(session, client, f"{host.name}: cannot connect: {exc}") from exc
    finally:
        if agent is not None:  # only needed to sign during authentication
            agent.close()

    try:
        async with conn:
            session.auth_method = client.method
            session.client_key_fingerprint = client.key_fingerprint
            session.offered_key_fingerprints = list(client.offered)
            session.server_key_fingerprint = conn.get_server_host_key().get_fingerprint("sha256")
            session.local_address, session.local_port = conn.get_extra_info("sockname")[:2]
            session.remote_address, session.remote_port = conn.get_extra_info("peername")[:2]
            await asyncio.wait_for(
                _run(conn, host, program, sink, session, password, prompt_timeout),
                timeout,
            )
    except TimeoutError as exc:
        session.error = f"timed out after {timeout:g} seconds"
        raise TransportError(f"{host.name}: {session.error}", session) from exc
    except TransportError as exc:
        session.error = str(exc)
        exc.session = session
        raise
    except (OSError, asyncssh.Error) as exc:
        session.error = f"{type(exc).__name__}: {exc}"
        raise TransportError(f"{host.name}: {session.error}", session) from exc
    finally:
        session.ended_at = datetime.now(UTC)
    return session


def _failed(session: Session, client: _Client, message: str) -> TransportError:
    session.auth_method = client.method
    session.offered_key_fingerprints = list(client.offered)
    if client.sockname:
        session.local_address, session.local_port = client.sockname[:2]
    if client.peername:
        session.remote_address, session.remote_port = client.peername[:2]
    session.error = message
    session.ended_at = datetime.now(UTC)
    return TransportError(message, session)


async def _run(conn, host, program, sink, session, password, prompt_timeout) -> None:
    prompt = ready = None
    if host.sudo == "password":
        token = secrets.token_hex(8)
        prompt, ready = f"[checker-sudo-{token}]", f"[checker-ready-{token}]"
    session.command = remote_command(host, prompt, ready)
    process = await conn.create_process(session.command, encoding=None)
    stderr = bytearray()
    prompt_seen = asyncio.Event()
    password_rejected = asyncio.Event()
    ready_seen = asyncio.Event()

    async def read_stderr():
        while data := await process.stderr.read(READ_SIZE):
            if len(stderr) < STDERR_LIMIT:
                stderr.extend(data[: STDERR_LIMIT - len(stderr)])
            if prompt:
                prompts = stderr.count(prompt.encode())
                if prompts >= 1:
                    prompt_seen.set()
                if prompts >= 2 or b"Sorry, try again" in stderr:
                    password_rejected.set()
                if ready.encode() in stderr:
                    ready_seen.set()

    async def read_stdout():
        while data := await process.stdout.read(READ_SIZE):
            if session.first_data_at is None:
                session.first_data_at = datetime.now(UTC)
            session.bytes_received += len(data)
            result = sink(data)
            if result is not None:  # any awaitable: keep backpressure, surface errors
                await result

    stderr_task = asyncio.create_task(read_stderr())
    stdout_task = asyncio.create_task(read_stdout())
    try:
        if prompt:
            try:
                await asyncio.wait_for(prompt_seen.wait(), prompt_timeout)
            except TimeoutError as exc:
                # Never send a password that sudo didn't ask for: it would be
                # read by Python as program text.
                process.close()
                raise SudoError(
                    f"{host.name}: sudo did not ask for a password; if this account has a"
                    " NOPASSWD rule, set its sudo mode to 'nopasswd'"
                ) from exc
            process.stdin.write(password.encode("utf-8") + b"\n")
            # Send the program only on a positive signal that sudo accepted the
            # password: otherwise sudo, asking again, would read program lines
            # as further password attempts.
            accepted = asyncio.ensure_future(ready_seen.wait())
            rejected = asyncio.ensure_future(password_rejected.wait())
            try:
                done, _ = await asyncio.wait(
                    {accepted, rejected},
                    timeout=prompt_timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:  # also when this run is cancelled (e.g. its time limit)
                for waiter in (accepted, rejected):
                    waiter.cancel()
            if rejected in done:
                process.close()
                raise SudoError(f"{host.name}: sudo rejected the password")
            if accepted not in done:
                process.close()
                raise SudoError(
                    f"{host.name}: no sign that sudo accepted the password within"
                    f" {prompt_timeout:g} seconds; the collector was not sent"
                )
        try:
            process.stdin.write(program.encode("utf-8"))
            process.stdin.write_eof()
        except (BrokenPipeError, ConnectionError):
            pass  # the remote side already ended (e.g. sudo -n refused); its stderr says why
        await asyncio.gather(stdout_task, stderr_task)
        completed = await process.wait()
        session.exit_status = completed.exit_status
    finally:
        for task in (stdout_task, stderr_task):
            task.cancel()
        text = bytes(stderr)
        for marker in (prompt, ready):
            if marker:
                text = text.replace(marker.encode() + b"\n", b"").replace(marker.encode(), b"")
        if password:  # a hostile sudo can repeat it, and this text is shown and stored
            text = text.replace(password.encode("utf-8"), b"[password]")
        session.stderr = text.decode("utf-8", errors="replace")

    if host.sudo != "root" and session.exit_status == 1 and "sudo" in session.stderr.lower():
        raise SudoError(f"{host.name}: sudo refused: {session.stderr.strip()[:300]}")


async def collect_many(
    hosts: Iterable[Host],
    run: Callable[[Host], Awaitable[Session]],
    *,
    parallel: int,
) -> dict[str, Session | TransportError]:
    """Run `run(host)` for each host, at most `parallel` at a time. A failure
    on one host is recorded for it and never stops the others."""
    limit = asyncio.Semaphore(max(1, parallel))
    results: dict[str, Session | TransportError] = {}

    async def one(host: Host):
        async with limit:
            try:
                results[host.name] = await run(host)
            except TransportError as exc:
                results[host.name] = exc
            except Exception as exc:  # anything else is still this host's failure only
                error = TransportError(f"{host.name}: {type(exc).__name__}: {exc}")
                error.__cause__ = exc
                results[host.name] = error

    # Every host's to the end, even when cancelled: each is sealing and recording what it has, and
    # without return_exceptions the first to stop would take the others' records with it.
    for ended in await asyncio.gather(*(one(host) for host in hosts), return_exceptions=True):
        if isinstance(ended, BaseException):
            raise ended
    return results


# --- Trusting host keys ---------------------------------------------------------


@dataclass
class HostKeyCheck:
    key: object
    fingerprint: str
    key_type: str
    known_fingerprints: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.known_fingerprints:
            return "new"
        return "same" if self.fingerprint in self.known_fingerprints else "changed"


# Time for an SSH agent's passphrase prompt, on top of the connection's own.
AGENT_PROMPT_SECONDS = 120

# The host key to trust when a server has several: the strongest first.
# asyncssh's own order puts RSA first, so a server with an ED25519 key too
# was trusted by its RSA one. Later connections use the trusted key's kind.
HOST_KEY_ALGS = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp256",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
)
# A known key's type and the algorithms that fetch it.
_KEY_ALGS = {"ssh-rsa": ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")}


def _known_hosts_name(host: Host) -> str:
    return host.address if host.port == 22 else f"[{host.address}]:{host.port}"


def _read_known(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


async def fetch_host_key(host: Host, known_hosts: Path | None = None) -> HostKeyCheck:
    """Ask the server for its host key, and compare it with what we know:
    a known key's kind first, so a host trusted by its RSA key isn't
    reported changed for offering its ED25519 one."""
    known_types, known = [], []
    name = _known_hosts_name(host)
    for line in _read_known(known_hosts or known_hosts_file()):
        parts = line.split()
        if len(parts) >= 3 and parts[0] == name:
            known.append(asyncssh.import_public_key(" ".join(parts[1:3])).get_fingerprint("sha256"))
            known_types.extend(_KEY_ALGS.get(parts[1], (parts[1],)))
    algs = list(dict.fromkeys([*known_types, *HOST_KEY_ALGS]))
    try:
        key = await asyncio.wait_for(
            # Same connection behaviour as collect(): the operator's
            # ~/.ssh/config must not redirect us to a different endpoint.
            asyncssh.get_server_host_key(
                host.address, host.port, config=None, server_host_key_algs=algs
            ),
            timeout=15,
        )
    except (OSError, TimeoutError, asyncssh.Error) as exc:
        raise TransportError(f"{host.name}: cannot fetch the host key: {exc}") from exc
    if key is None:
        raise TransportError(f"{host.name}: the server offered no host key")
    return HostKeyCheck(
        key=key,
        fingerprint=key.get_fingerprint("sha256"),
        key_type=key.get_algorithm(),
        known_fingerprints=known,
    )


def trust_host_key(host: Host, check: HostKeyCheck, known_hosts: Path | None = None) -> None:
    """Record `check.key` as the only trusted key for this host. The whole
    read-modify-write holds a lock, so concurrent `trust` commands can't
    lose each other's entries."""
    path = known_hosts or known_hosts_file()
    name = _known_hosts_name(host)
    entry = check.key.export_public_key("openssh").decode("ascii").split()
    with locked(path):
        kept = [line for line in _read_known(path) if line.split()[:1] != [name]]
        kept.append(f"{name} {entry[0]} {entry[1]}")
        atomic_write(path, "\n".join(kept) + "\n")
