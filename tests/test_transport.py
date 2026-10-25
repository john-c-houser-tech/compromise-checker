"""Transport tests against an in-process SSH server that acts like a target.

The server runs real `python3 -I -B -` for the collector, and plays sudo's
part (prompting, not prompting, rejecting) so every sudo mode is exercised.
"""

import asyncio
import shlex
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import asyncssh
import pytest

from checker import transport
from checker.inventory import Host
from checker.protocol import Limits, Settings, build_program, read_stream
from checker.transport import (
    Session,
    SudoError,
    TransportError,
    UnknownHostKey,
    collect,
    collect_many,
    fetch_host_key,
    remote_command,
    trust_host_key,
)

PASSWORD = "correct horse"


@dataclass
class Target:
    """What the fake target does, and what it saw."""

    sudo_prompts: bool = True
    sudo_stalls_after_password: bool = False
    sudo_accepts: bool = True
    sudo_n_refuses: bool = False
    hang: bool = False
    commands: list[str] = field(default_factory=list)
    stdin_seen: bytes = b""


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == PASSWORD


async def _run_command(process, argv: list[str], first_input: bytes = b""):
    """Run argv locally (python3 → this interpreter), passing the SSH channel's
    streams through live, as a real target would."""
    argv = [sys.executable if part == "python3" else part for part in argv]
    child = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def feed():
        child.stdin.write(first_input)
        while data := await process.stdin.read(65536):
            child.stdin.write(data)
            await child.stdin.drain()
        child.stdin.close()

    async def pump(source, write):
        while data := await source.read(65536):
            write(data)

    await asyncio.gather(
        feed(), pump(child.stdout, process.stdout.write), pump(child.stderr, process.stderr.write)
    )
    process.exit(await child.wait())


def _handler(target: Target):
    async def handle(process):
        target.commands.append(process.command)
        argv = shlex.split(process.command)
        if target.hang:
            await asyncio.sleep(30)
        if argv[0] == "sudo" and "-n" in argv and target.sudo_n_refuses:
            process.stderr.write(b"sudo: a password is required\n")
            process.exit(1)
            return
        if argv[0] == "sudo" and "-S" in argv:
            prompt = argv[argv.index("-p") + 1].encode()
            if not target.sudo_prompts:
                # Like a NOPASSWD rule: python starts at once and reads stdin.
                await asyncio.sleep(1.0)
                target.stdin_seen = await process.stdin.read(1 << 20)
                process.exit(0)
                return
            process.stderr.write(prompt)
            line = await process.stdin.readline()
            target.stdin_seen = line
            if not target.sudo_accepts or line.rstrip(b"\n") != PASSWORD.encode():
                process.stderr.write(b"\nSorry, try again.\n" + prompt)
                await asyncio.sleep(0.5)
                process.exit(1)
                return
            if target.sudo_stalls_after_password:
                # Accepted or not, sudo says nothing for longer than we wait.
                target.stdin_seen += await process.stdin.read(1 << 20)
                process.exit(1)
                return
        command = argv[argv.index("--") + 1 :] if argv[0] == "sudo" else argv
        await _run_command(process, command)

    return handle


@pytest.fixture
async def server(tmp_path):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    target = Target()
    listener = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_factory=_Server,
        server_host_keys=[host_key],
        authorized_client_keys=asyncssh.import_authorized_keys(
            client_key.export_public_key().decode()
        ),
        process_factory=_handler(target),
        encoding=None,
        gss_host=None,
    )
    port = listener.sockets[0].getsockname()[1]
    key_file = tmp_path / "id_ed25519"
    client_key.write_private_key(key_file)
    known = tmp_path / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} " + host_key.export_public_key().decode())

    class Env:
        pass

    env = Env()
    env.target, env.port, env.known = target, port, known
    env.host_key, env.client_key, env.key_file = host_key, client_key, key_file
    yield env
    listener.close()
    await listener.wait_closed()


def host(env, **overrides):
    values = dict(
        name="web01",
        address="127.0.0.1",
        port=env.port,
        user="scanner",
        auth="key",
        key_path=str(env.key_file),
        sudo="nopasswd",
    )
    values.update(overrides)
    return Host(**values)


def program():
    settings = Settings(
        run_id="r1",
        since=datetime(2026, 9, 25, tzinfo=UTC),
        modules=None,  # all the collector has
        limits=Limits(overall_seconds=60, module_seconds=30, source_bytes=1 << 20),
    )
    return build_program(settings)


async def run(env, h, **kwargs):
    received = bytearray()
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("known_hosts", env.known)
    session = await collect(h, program(), received.extend, **kwargs)
    return session, bytes(received)


# --- Collecting -------------------------------------------------------------------


async def test_key_login_runs_the_collector_and_records_the_session(server):
    session, data = await run(server, host(server))
    records = read_stream(data)
    assert records[0].run_id == "r1"
    assert records[-1].status == "complete"
    assert server.target.commands == ["sudo -n -- python3 -I -B -"]
    assert session.auth_method == "publickey"
    assert session.client_key_fingerprint == server.client_key.get_fingerprint("sha256")
    assert session.server_key_fingerprint == server.host_key.get_fingerprint("sha256")
    assert session.exit_status == 0
    assert session.bytes_received == len(data)
    assert session.remote_port == server.port
    assert session.ended_at >= session.started_at


async def test_password_login_as_root(server):
    h = host(server, auth="password", key_path=None, sudo="root")
    session, data = await run(server, h, password_provider=lambda _: PASSWORD)
    assert read_stream(data)[-1].status == "complete"
    assert server.target.commands == ["python3 -I -B -"]
    assert session.auth_method == "password"
    assert session.client_key_fingerprint is None


async def test_agent_keys_are_offered_and_the_agent_closed(server, monkeypatch):
    class FakeAgent:
        closed = False

        async def get_keys(self):
            return [server.client_key]

        def close(self):
            FakeAgent.closed = True

    async def connect_agent(path=()):
        return FakeAgent()

    monkeypatch.setattr(transport.asyncssh, "connect_agent", connect_agent)
    session, data = await run(server, host(server, auth="agent", key_path=None))
    assert read_stream(data)[-1].status == "complete"
    assert session.client_key_fingerprint == server.client_key.get_fingerprint("sha256")
    assert FakeAgent.closed


# --- Host keys ----------------------------------------------------------------------


async def test_unknown_host_key_stops_the_run(server, tmp_path):
    empty = tmp_path / "empty_known_hosts"
    empty.write_text("")
    with pytest.raises(UnknownHostKey, match="checker trust web01"):
        await run(server, host(server), known_hosts=empty)
    assert server.target.commands == []


async def test_changed_host_key_stops_the_run(server, tmp_path):
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
    changed = tmp_path / "changed_known_hosts"
    changed.write_text(f"[127.0.0.1]:{server.port} {other}")
    with pytest.raises(UnknownHostKey, match="--replace"):
        await run(server, host(server), known_hosts=changed)
    assert server.target.commands == []


async def test_missing_known_hosts_file(server, tmp_path):
    with pytest.raises(UnknownHostKey, match="checker trust"):
        await run(server, host(server), known_hosts=tmp_path / "nope")


async def test_trust_ignores_the_operators_ssh_config(server, monkeypatch, tmp_path):
    seen = {}
    real = transport.asyncssh.get_server_host_key

    async def spy(*args, **kwargs):
        seen.update(kwargs)
        return await real(*args, **kwargs)

    monkeypatch.setattr(transport.asyncssh, "get_server_host_key", spy)
    await fetch_host_key(host(server), tmp_path / "k")
    assert seen.get("config", ()) is None


async def test_trust_new_then_same_then_changed(server, tmp_path):
    known = tmp_path / "trusted"
    h = host(server)
    check = await fetch_host_key(h, known)
    assert check.status == "new"
    assert check.fingerprint == server.host_key.get_fingerprint("sha256")
    trust_host_key(h, check, known)
    assert (await fetch_host_key(h, known)).status == "same"
    assert known.stat().st_mode & 0o777 == 0o600
    _, data = await run(server, h, known_hosts=known)
    assert read_stream(data)[-1].status == "complete"

    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
    known.write_text(f"[127.0.0.1]:{server.port} {other}")
    changed = await fetch_host_key(h, known)
    assert changed.status == "changed"
    trust_host_key(h, changed, known)  # what --replace does
    assert known.read_text().count(f"[127.0.0.1]:{server.port}") == 1


# --- sudo -----------------------------------------------------------------------------


async def test_sudo_password_is_sent_only_after_the_prompt(server):
    h = host(server, sudo="password")
    session, data = await run(server, h, password_provider=lambda _: PASSWORD)
    assert read_stream(data)[-1].status == "complete"
    command = server.target.commands[0]
    assert command.startswith("sudo -k -S -p '[checker-sudo-")
    assert PASSWORD not in command
    assert server.target.stdin_seen.startswith(PASSWORD.encode() + b"\n")
    assert "[checker-sudo-" not in session.stderr
    assert "[checker-ready-" not in session.stderr
    assert " -c " in command  # the bootstrap that signals readiness


async def test_password_is_never_sent_if_sudo_does_not_ask(server):
    server.target.sudo_prompts = False
    with pytest.raises(SudoError, match="did not ask for a password"):
        await run(
            server,
            host(server, sudo="password"),
            password_provider=lambda _: PASSWORD,
            prompt_timeout=0.3,
        )
    await asyncio.sleep(1.2)
    assert PASSWORD.encode() not in server.target.stdin_seen


async def test_rejected_sudo_password_sends_no_program(server):
    server.target.sudo_accepts = False
    with pytest.raises(SudoError, match="rejected the password"):
        await run(
            server,
            host(server, sudo="password"),
            password_provider=lambda _: "wrong",
        )
    assert server.target.stdin_seen == b"wrong\n"


async def test_no_ready_signal_means_no_program(server):
    server.target.sudo_stalls_after_password = True
    with pytest.raises(SudoError, match="no sign that sudo accepted"):
        await run(
            server,
            host(server, sudo="password"),
            password_provider=lambda _: PASSWORD,
            prompt_timeout=0.5,
        )
    assert server.target.stdin_seen == PASSWORD.encode() + b"\n"


async def test_sink_may_return_any_awaitable(server):
    loop = asyncio.get_running_loop()
    written = bytearray()

    def sink(data: bytes):
        future = loop.create_future()
        loop.call_soon(lambda: (written.extend(data), future.set_result(None)))
        return future

    session = await collect(host(server), program(), sink, timeout=30, known_hosts=server.known)
    assert len(written) == session.bytes_received > 0
    assert read_stream(bytes(written))[-1].status == "complete"


async def test_sudo_n_refusal_is_reported(server):
    server.target.sudo_n_refuses = True
    with pytest.raises(SudoError, match="a password is required") as info:
        await run(server, host(server))
    # The failed run still left traces on the host: its record is kept.
    session = info.value.session
    assert session.exit_status == 1
    assert session.client_key_fingerprint == server.client_key.get_fingerprint("sha256")
    assert "password is required" in session.stderr
    assert session.ended_at is not None


async def test_timeout(server):
    server.target.hang = True
    with pytest.raises(TransportError, match="timed out") as info:
        await run(server, host(server), timeout=0.5)
    assert info.value.session.error == "timed out after 0.5 seconds"
    assert info.value.session.ended_at is not None


async def test_password_prompts_run_off_the_loop_one_at_a_time():
    loop_thread = threading.get_ident()
    active, peak, threads = 0, 0, set()

    def provider(h: Host) -> str:
        nonlocal active, peak
        threads.add(threading.get_ident())
        active += 1
        peak = max(peak, active)
        time.sleep(0.2)  # someone typing
        active -= 1
        return PASSWORD

    ticks = 0

    async def ticker():
        nonlocal ticks
        for _ in range(10):
            await asyncio.sleep(0.03)
            ticks += 1

    h = Host(name="h", address="a", user="u", sudo="password")
    await asyncio.gather(
        transport._ask_password(provider, h), transport._ask_password(provider, h), ticker()
    )
    assert peak == 1  # prompts never interleave
    assert loop_thread not in threads  # and never block the event loop
    assert ticks == 10  # other work kept running meanwhile


def test_remote_command_for_sudo_password_mode():
    h = Host(name="h", address="a", user="u", sudo="password")
    command = remote_command(h, "[checker-sudo-ab12]", "[checker-ready-ab12]")
    argv = shlex.split(command)
    assert argv[:6] == ["sudo", "-k", "-S", "-p", "[checker-sudo-ab12]", "--"]
    assert argv[6:10] == ["python3", "-I", "-B", "-c"]
    assert '"[checker-ready-ab12]"' in argv[10]
    assert remote_command(Host(name="h", address="a", user="u", sudo="root")) == ("python3 -I -B -")


def test_python_setting_rejects_shell_syntax():
    with pytest.raises(ValueError):
        Host(name="h", address="a", user="u", python="python3; rm -rf /")


# --- Many hosts -----------------------------------------------------------------------


async def test_collect_many_limits_parallelism_and_isolates_failures():
    running = 0
    peak = 0

    async def fake_run(h: Host) -> Session:
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.05)
        running -= 1
        if h.name == "bad":
            raise TransportError("bad: cannot connect")
        if h.name == "odd":
            raise RuntimeError("no password in the keyring")
        return Session(h.name, h.address, h.port, h.user, h.sudo, datetime.now(UTC))

    hosts = [Host(name=n, address="a", user="u") for n in ("a", "b", "bad", "odd", "c", "d")]
    results = await collect_many(hosts, fake_run, parallel=2)
    assert peak == 2
    assert isinstance(results["bad"], TransportError)
    assert isinstance(results["odd"], TransportError)
    assert "no password in the keyring" in str(results["odd"])
    assert all(isinstance(results[n], Session) for n in ("a", "b", "c", "d"))
