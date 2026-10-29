"""Transport tests against an in-process SSH server that acts like a target.

The server runs real `python3 -I -B -` for the collector, and plays sudo's
part (prompting, not prompting, rejecting) so every sudo mode is exercised.
"""

import asyncio
import shlex
import threading
import time
from datetime import UTC, datetime

import asyncssh
import pytest
from conftest import PASSWORD

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
        # One light module: the fake target runs the collector on the machine
        # hosting the tests, where heavy modules (package verification) take minutes.
        modules=["host_facts"],
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
    # What the own-session filter needs: the exact command, and when the
    # first bytes came (the controller's side of the clock offset).
    assert session.command == server.target.commands[0]
    assert session.started_at <= session.first_data_at <= session.ended_at


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


async def test_a_silent_server_times_out_with_a_reason(server, monkeypatch):
    # Accepts the connection and never speaks: the wait runs out. With an
    # agent, its passphrase prompt gets time too, and the message says so.
    async def silent(reader, writer):
        await reader.read()  # until the client gives up and hangs up
        writer.close()

    quiet = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = quiet.sockets[0].getsockname()[1]
    try:
        with pytest.raises(TransportError, match=r"cannot connect: timed out after 0\.2 seconds$"):
            await run(server, host(server, port=port), connect_timeout=0.2)

        class FakeAgent:
            async def get_keys(self):
                return [server.client_key]

            def close(self):
                pass

        async def connect_agent(path=()):
            return FakeAgent()

        monkeypatch.setattr(transport.asyncssh, "connect_agent", connect_agent)
        monkeypatch.setattr(transport, "AGENT_PROMPT_SECONDS", 0.2)
        with pytest.raises(TransportError, match=r"0\.4 seconds \(was the SSH agent waiting"):
            await run(
                server, host(server, port=port, auth="agent", key_path=None), connect_timeout=0.2
            )
    finally:
        quiet.close()
        await quiet.wait_closed()


async def test_the_systems_own_timeout_is_reported_as_it_is(server, monkeypatch):
    # No answer to the TCP connect: the kernel gives up (ETIMEDOUT) before
    # our wait does, and that has nothing to do with an agent.
    import errno

    async def unanswered(*args, **kwargs):
        raise TimeoutError(errno.ETIMEDOUT, "Connection timed out")

    monkeypatch.setattr(transport.asyncssh, "connect", unanswered)
    with pytest.raises(
        TransportError, match=r"cannot connect: \[Errno 110\] Connection timed out$"
    ):
        await run(server, host(server))


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


async def test_trust_takes_the_ed25519_key_when_the_server_offers_rsa_too(tmp_path):
    ed25519 = asyncssh.generate_private_key("ssh-ed25519")
    listener = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_host_keys=[asyncssh.generate_private_key("ssh-rsa"), ed25519],
        gss_host=None,
    )
    try:
        h = Host(
            name="both", address="127.0.0.1", port=listener.sockets[0].getsockname()[1], user="u"
        )
        check = await fetch_host_key(h, tmp_path / "k")
    finally:
        listener.close()
        await listener.wait_closed()
    assert check.key_type == "ssh-ed25519"
    assert check.fingerprint == ed25519.get_fingerprint("sha256")


async def test_a_host_trusted_by_its_rsa_key_stays_the_same_when_it_has_ed25519_too(tmp_path):
    rsa = asyncssh.generate_private_key("ssh-rsa")
    listener = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_host_keys=[rsa, asyncssh.generate_private_key("ssh-ed25519")],
        gss_host=None,
    )
    port = listener.sockets[0].getsockname()[1]
    known = tmp_path / "k"
    known.write_text(f"[127.0.0.1]:{port} " + rsa.export_public_key().decode())
    try:
        h = Host(name="both", address="127.0.0.1", port=port, user="u")
        check = await fetch_host_key(h, known)
    finally:
        listener.close()
        await listener.wait_closed()
    assert check.status == "same"


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


async def test_a_cancelled_run_leaves_no_waiters_behind(server):
    server.target.sudo_stalls_after_password = True
    with pytest.raises(TransportError, match="timed out"):
        await run(
            server,
            host(server, sudo="password"),
            password_provider=lambda _: PASSWORD,
            prompt_timeout=10,
            timeout=0.5,
        )
    await asyncio.sleep(0)
    leftovers = [t for t in asyncio.all_tasks() if "Event.wait" in repr(t.get_coro())]
    assert leftovers == []


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


async def test_cancelling_a_waiting_run_keeps_the_prompt_lock_until_the_prompt_ends():
    first_on_screen, release_first = threading.Event(), threading.Event()
    active, peak = 0, 0

    def provider(h: Host) -> str:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if h.name == "first":
            first_on_screen.set()
            release_first.wait(5)  # the person is still typing
        active -= 1
        return PASSWORD

    first = asyncio.create_task(
        transport._ask_password(provider, Host(name="first", address="a", user="u"))
    )
    await asyncio.to_thread(first_on_screen.wait, 5)
    first.cancel()  # e.g. its run hit a time limit
    second = asyncio.create_task(
        transport._ask_password(provider, Host(name="second", address="a", user="u"))
    )
    await asyncio.sleep(0.2)
    assert not second.done()  # still waiting: the first prompt holds the terminal
    release_first.set()
    assert await second == PASSWORD
    assert peak == 1


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
