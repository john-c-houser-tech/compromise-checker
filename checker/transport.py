"""SSH transport: run the collector on a host and stream its output back.

DESIGN.md §5.1 and docs/collector-protocol.md §1. Host keys are always
verified against the tool's own known-hosts file; there is no way to turn
that off. Passwords are kept in memory only for the run and are never put on
a command line.
"""

import asyncio
import secrets
import shlex
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import asyncssh
from asyncssh.public_key import decode_ssh_public_key

from checker.inventory import Host, known_hosts_file

STDERR_LIMIT = 64 * 1024
READ_SIZE = 64 * 1024

# Called with each piece of the collector's stdout as it arrives.
Sink = Callable[[bytes], Awaitable[None] | None]
# Asked for a password when a host needs one (SSH or sudo). Never stored.
PasswordProvider = Callable[[Host], str]


class TransportError(Exception):
    """A collection could not be carried out; the message says why."""


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
    exit_status: int | None = None
    bytes_received: int = 0
    stderr: str = ""
    error: str | None = None


def remote_command(host: Host, prompt: str | None = None) -> str:
    """The command run on the target. Nothing secret is ever part of it."""
    python = [host.python, "-I", "-B", "-"]
    if host.sudo == "root":
        argv = python
    elif host.sudo == "nopasswd":
        # -n: fail rather than ask, so no password can be expected.
        argv = ["sudo", "-n", "--", *python]
    else:
        # -k: always ask, so the prompt we wait for really comes; -S: read
        # the password from stdin; -p: a prompt unique to this run.
        if prompt is None:
            raise ValueError("sudo mode 'password' needs a prompt marker")
        argv = ["sudo", "-k", "-S", "-p", prompt, "--", *python]
    return " ".join(shlex.quote(part) for part in argv)


class _Client(asyncssh.SSHClient):
    """Offers credentials one at a time and remembers which one worked."""

    def __init__(self, keys: list, password: str | None):
        self._keys = list(keys)
        self._password = password
        self._offered_key = None
        self.method: str | None = None
        self.key_fingerprint: str | None = None

    def public_key_auth_requested(self):
        if not self._keys:
            return None
        self._offered_key = self._keys.pop(0)
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
    sudo_check_seconds: float = 5.0,
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
        password = password_provider(host)

    keys, agent = await _client_keys(host, agent_path)
    client = _Client(keys, password if host.auth == "password" else None)
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
            connect_timeout,
        )
    except asyncssh.HostKeyNotVerifiable as exc:
        raise UnknownHostKey(
            f"{host.name}: host key not trusted ({exc.reason}). If you expected this, check the"
            f" new key and run `checker trust {host.name} --replace`."
        ) from exc
    except asyncssh.PermissionDenied as exc:
        raise TransportError(f"{host.name}: login refused for {host.user}") from exc
    except (OSError, TimeoutError, asyncssh.Error) as exc:
        raise TransportError(f"{host.name}: cannot connect: {exc}") from exc
    finally:
        if agent is not None:  # only needed to sign during authentication
            agent.close()

    try:
        async with conn:
            session.auth_method = client.method
            session.client_key_fingerprint = client.key_fingerprint
            session.server_key_fingerprint = conn.get_server_host_key().get_fingerprint("sha256")
            session.local_address, session.local_port = conn.get_extra_info("sockname")[:2]
            session.remote_address, session.remote_port = conn.get_extra_info("peername")[:2]
            await asyncio.wait_for(
                _run(
                    conn, host, program, sink, session, password, prompt_timeout, sudo_check_seconds
                ),
                timeout,
            )
    except TimeoutError as exc:
        session.error = f"timed out after {timeout:g} seconds"
        raise TransportError(f"{host.name}: {session.error}") from exc
    finally:
        session.ended_at = datetime.now(UTC)
    return session


async def _run(
    conn, host, program, sink, session, password, prompt_timeout, sudo_check_seconds
) -> None:
    prompt = f"[checker-sudo-{secrets.token_hex(8)}]" if host.sudo == "password" else None
    process = await conn.create_process(remote_command(host, prompt), encoding=None)
    stderr = bytearray()
    prompt_seen = asyncio.Event()
    password_rejected = asyncio.Event()

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

    async def read_stdout():
        while data := await process.stdout.read(READ_SIZE):
            session.bytes_received += len(data)
            result = sink(data)
            if asyncio.iscoroutine(result):
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
            # A wrong password makes sudo ask again, and it would then read the
            # program's first lines as further attempts. Wait long enough for
            # PAM's failure delay before sending the program.
            try:
                await asyncio.wait_for(password_rejected.wait(), sudo_check_seconds)
            except TimeoutError:
                pass
            else:
                process.close()
                raise SudoError(f"{host.name}: sudo rejected the password")
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
        if prompt:
            text = text.replace(prompt.encode(), b"")
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

    await asyncio.gather(*(one(host) for host in hosts))
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


def _known_hosts_name(host: Host) -> str:
    return host.address if host.port == 22 else f"[{host.address}]:{host.port}"


def _read_known(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


async def fetch_host_key(host: Host, known_hosts: Path | None = None) -> HostKeyCheck:
    """Ask the server for its host key, and compare it with what we know."""
    try:
        key = await asyncio.wait_for(
            asyncssh.get_server_host_key(host.address, host.port), timeout=15
        )
    except (OSError, TimeoutError, asyncssh.Error) as exc:
        raise TransportError(f"{host.name}: cannot fetch the host key: {exc}") from exc
    if key is None:
        raise TransportError(f"{host.name}: the server offered no host key")
    known = []
    name = _known_hosts_name(host)
    for line in _read_known(known_hosts or known_hosts_file()):
        parts = line.split()
        if len(parts) >= 3 and parts[0] == name:
            known.append(asyncssh.import_public_key(" ".join(parts[1:3])).get_fingerprint("sha256"))
    return HostKeyCheck(
        key=key,
        fingerprint=key.get_fingerprint("sha256"),
        key_type=key.get_algorithm(),
        known_fingerprints=known,
    )


def trust_host_key(host: Host, check: HostKeyCheck, known_hosts: Path | None = None) -> None:
    """Record `check.key` as the only trusted key for this host."""
    path = known_hosts or known_hosts_file()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = _known_hosts_name(host)
    kept = [line for line in _read_known(path) if line.split()[:1] != [name]]
    entry = check.key.export_public_key("openssh").decode("ascii").split()
    kept.append(f"{name} {entry[0]} {entry[1]}")
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(kept) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)
