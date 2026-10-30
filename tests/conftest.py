"""Shared fixtures: an in-process SSH server that acts like a target.

The server runs the real collector with this interpreter, and plays sudo's
part (prompting, not prompting, rejecting) so every sudo mode is exercised.
"""

import asyncio
import shlex
import sys
from dataclasses import dataclass, field

import asyncssh
import pytest

PASSWORD = "correct horse"


@pytest.fixture(autouse=True)
def _no_real_http(monkeypatch):
    """No test reaches a real server over HTTP (the advisor's tests use mock
    transports): a request that would is an error, at once, instead of a
    call to a model server that may be running on this machine."""
    try:
        import httpx2
    except ImportError:
        return

    def refuse(self, request):
        raise RuntimeError(f"a test tried to reach {request.url.host}: use a mock transport")

    monkeypatch.setattr(httpx2.HTTPTransport, "handle_request", refuse)


# Password managers and keychains a key command might name: a test that
# reaches one would put a real prompt in front of whoever is at the machine.
SECRET_STORES = {"op", "bw", "pass", "gopass", "security", "secret-tool", "gpg", "keepassxc-cli"}


@pytest.fixture(autouse=True)
def _no_real_key_command(monkeypatch):
    """No test runs a password manager as a key command (the eval's default
    source is one): it is an error, at once, before any prompt appears."""
    import os
    import subprocess

    import checker.advisor.keys as keys

    real = subprocess.run

    def guarded(args, *rest, **kwargs):
        first = args[0] if isinstance(args, list | tuple) and args else str(args).split()[0]
        if os.path.basename(str(first)) in SECRET_STORES:
            raise RuntimeError(f"a test tried to run {first!r} as a key command: use env")
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(keys.subprocess, "run", guarded)


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


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A checker home with its evidence key and database: (path, store,
    identity, config)."""
    from checker.evidence import Store, database_file, initialise, load_identity

    monkeypatch.setenv("CHECKER_HOME", str(tmp_path))
    config, identity_path = initialise(tmp_path)
    store = Store(database_file(tmp_path))
    yield tmp_path, store, load_identity(identity_path), config
    store.close()
