"""Signature checks with `gpgv`, against keys shipped inside the checker only.

`gpgv` runs with an empty private GNUPGHOME and one keyring made from the
keys named for that system, so nothing else on the machine can count as
trusted. A signature counts only when gpgv's status lines report it valid
(VALIDSIG) and the signing key's primary fingerprint is one of the pinned
ones; any bad, unknown, expired or revoked signature fails the whole check.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from importlib import resources

# The pinned keys: name -> (primary fingerprint, file in keys/). Each
# fingerprint was checked against two sources when it was added
# (plans/pam-offserver-verify-plan-2026-11-21.md, V.1 and V.2).
KEYS = {
    "ubuntu-2018": ("F6ECB3762474EDA9D21B7022871920D1991BC93C", "ubuntu-archive-2018.asc"),
    "rocky-9": ("21CB256AE16FC54C6E652949702D426D350D275D", "rocky-9.asc"),
    "rocky-10": ("FC226859C0860BF0DDB95B085B106C736FEDFC85", "rocky-10.asc"),
    "almalinux-9": ("BF18AC2876178908D6E71267D36CB86CB86B3716", "almalinux-9.asc"),
    "almalinux-10": ("EE6DB7B98F5BF5EDD9DA0DE5DEE5C11CC2A1E572", "almalinux-10.asc"),
}

TIMEOUT = 30  # seconds for one gpgv run
MAX_SIGNED = 64 * 1024 * 1024  # what a clear-signed file may hold


class SignatureError(Exception):
    """The signature didn't check out, or couldn't be checked."""


def dearmor(text: str) -> bytes:
    """The binary key data inside ASCII armor (the checksum line dropped)."""
    lines = text.strip().splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith("-----BEGIN PGP"))
        end = next(i for i, line in enumerate(lines) if line.startswith("-----END PGP"))
    except StopIteration:
        raise SignatureError("not an armored key") from None
    body, i = [], start + 1
    while i < end and lines[i].strip():  # armor headers, up to the blank line
        i += 1
    for line in lines[i + 1 : end]:
        if line.startswith("="):
            break
        body.append(line.strip())
    return base64.b64decode("".join(body), validate=True)


def _keyring(names) -> bytes:
    folder = resources.files("checker.verify") / "keys"
    return b"".join(dearmor((folder / KEYS[name][1]).read_text()) for name in names)


def gpgv_path() -> str | None:
    return shutil.which("gpgv")


def _run(names, args: list[str], files: dict[str, bytes]) -> tuple[str, bytes | None]:
    """gpgv's status lines (and --output's bytes, if asked) for `files`
    written into a private folder; `args` name those files."""
    gpgv = gpgv_path()
    if gpgv is None:
        raise SignatureError("gpgv isn't installed on this machine")
    with tempfile.TemporaryDirectory(prefix="checker-gpgv-") as home:
        os.chmod(home, 0o700)
        keyring = os.path.join(home, "pinned.gpg")
        with open(keyring, "wb") as handle:
            handle.write(_keyring(names))
        for name, data in files.items():
            with open(os.path.join(home, name), "wb") as handle:
                handle.write(data)
        output = os.path.join(home, "signed.out")
        argv = [gpgv, "--status-fd", "1", "--keyring", keyring]
        argv += [a.replace("{out}", output) for a in args]
        try:
            done = subprocess.run(  # noqa: S603 - fixed program and arguments
                argv,
                cwd=home,
                capture_output=True,
                timeout=TIMEOUT,
                env={"GNUPGHOME": home, "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
            )
        except subprocess.TimeoutExpired:
            raise SignatureError("gpgv took too long") from None
        signed = None
        if os.path.exists(output):
            with open(output, "rb") as handle:
                signed = handle.read(MAX_SIGNED + 1)
        return done.stdout.decode("utf-8", "replace"), signed if done.returncode == 0 else None


def _signer(status: str, names) -> str:
    """The pinned fingerprint that made the one valid signature, or SignatureError."""
    allowed = {KEYS[name][0] for name in names}
    valid, problems = [], []
    for line in status.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "[GNUPG:]":
            continue
        word = parts[1]
        if word == "VALIDSIG" and len(parts) >= 3:
            valid.append(parts[-1].upper())  # the primary key's fingerprint is the last field
        elif word in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"):
            problems.append(word)
    if problems:
        raise SignatureError(f"the signature failed ({', '.join(sorted(set(problems)))})")
    if len(valid) != 1:
        raise SignatureError(f"expected one valid signature, found {len(valid)}")
    if valid[0] not in allowed:
        raise SignatureError(f"signed by a key that isn't pinned for this system: {valid[0]}")
    return valid[0]


def verify_clearsigned(data: bytes, names) -> tuple[bytes, str]:
    """(the signed text only, the signer's fingerprint) of a clear-signed
    file such as Ubuntu's InRelease. Anything outside the one signed block
    is never returned: only gpgv's --output, which is what it checked."""
    if len(data) > MAX_SIGNED:
        raise SignatureError("too large")
    if not data.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\n"):
        raise SignatureError("doesn't start with a clear-signed block")
    if data.count(b"-----BEGIN PGP SIGNED MESSAGE-----") != 1 or (
        data.count(b"-----BEGIN PGP SIGNATURE-----") != 1
    ):
        raise SignatureError("more than one signed block")
    status, signed = _run(names, ["--output", "{out}", "in.txt"], {"in.txt": data})
    signer = _signer(status, names)
    if signed is None or len(signed) > MAX_SIGNED:
        raise SignatureError("gpgv gave no signed text")
    return signed, signer


def verify_detached(signature: bytes, data: bytes, names) -> str:
    """The signer's fingerprint, if `signature` is a valid detached
    signature of `data` by one of the pinned keys `names`."""
    status, _ = _run(names, ["sig.bin", "data.bin"], {"sig.bin": signature, "data.bin": data})
    return _signer(status, names)
