"""minisign signatures, checked in Python (DESIGN.md §10.4): no minisign
binary is needed to verify, only the `cryptography` library the tool
already has through asyncssh.

A public key file holds, after its comment line, base64 of "Ed", an
8-byte key id and a 32-byte Ed25519 key. A signature file holds base64
of "ED" (the file's BLAKE2b-512 hash is what was signed, minisign's
default), the key id and a 64-byte signature; then a trusted comment and
a global signature over that signature and the comment, so the comment
can't be changed either. The legacy form ("Ed", the whole file signed)
is refused: minisign hasn't made it by default since 0.10.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_SIGNATURE_BYTES = 4096
MAX_COMMENT = 1024


class SignatureError(Exception):
    """A signature or key that doesn't check out; the message says why."""


@dataclass(frozen=True)
class PublicKey:
    key_id: str  # as minisign shows it: 16 hex digits
    raw: bytes  # the 32-byte Ed25519 key
    text: str  # the base64 line, as written in key files and the key list

    def __str__(self) -> str:
        return self.key_id


def _id(raw: bytes) -> str:
    """minisign shows the 8 little-endian key id bytes as one hex number."""
    return raw[::-1].hex().upper()


def _b64(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise SignatureError(f"the {what} isn't base64") from None


def public_key(text: str) -> PublicKey:
    """A public key from its base64 line, or a whole .pub file."""
    lines = [line for line in text.strip().splitlines() if line.strip()]
    if lines and lines[0].startswith("untrusted comment:"):
        lines = lines[1:]
    if len(lines) != 1:
        raise SignatureError("not a minisign public key")
    blob = _b64(lines[0], "public key")
    if len(blob) != 42 or blob[:2] != b"Ed":
        raise SignatureError("not a minisign Ed25519 public key")
    return PublicKey(_id(blob[2:10]), blob[10:], lines[0].strip())


@dataclass(frozen=True)
class Signed:
    key: PublicKey  # the key that signed it
    trusted_comment: str


def verify(data: bytes, signature: bytes, keys: list[PublicKey]) -> Signed:
    """Check `signature` (a .minisig file's bytes) over `data` against
    whichever of `keys` has its key id; raises SignatureError otherwise.
    The trusted comment may be any UTF-8 (minisign puts the signed file's
    name in it); what it signs is its bytes as written."""
    if len(signature) > MAX_SIGNATURE_BYTES:
        raise SignatureError("the signature file is too large")
    lines = [line.rstrip(b"\r") for line in signature.split(b"\n")]
    if lines and lines[-1] == b"":
        lines = lines[:-1]
    if (
        len(lines) != 4
        or not lines[0].startswith(b"untrusted comment:")
        or not lines[2].startswith(b"trusted comment: ")
    ):
        raise SignatureError("the signature file isn't minisign's (four lines)")
    try:
        sig_line, global_line = lines[1].decode("ascii"), lines[3].decode("ascii")
        comment = lines[2].removeprefix(b"trusted comment: ")
        shown = comment.decode("utf-8")
    except UnicodeDecodeError:
        raise SignatureError("the signature file isn't minisign's") from None
    blob = _b64(sig_line, "signature")
    if len(blob) != 74:
        raise SignatureError("the signature isn't minisign's")
    algorithm, key_id, sig = blob[:2], _id(blob[2:10]), blob[10:]
    if algorithm == b"Ed":
        raise SignatureError("a legacy signature (not prehashed): sign with a current minisign")
    if algorithm != b"ED":
        raise SignatureError("the signature isn't minisign's")
    if len(comment) > MAX_COMMENT:
        raise SignatureError("the trusted comment is too long")
    global_sig = _b64(global_line, "global signature")
    if len(global_sig) != 64:
        raise SignatureError("the global signature isn't minisign's")
    matching = [k for k in keys if k.key_id == key_id]
    if not matching:
        raise SignatureError(f"signed by key {key_id}, which isn't trusted")
    if len({k.raw for k in matching}) > 1:
        raise SignatureError(f"two trusted keys share the key id {key_id}: neither is used")
    key = matching[0]
    checker = Ed25519PublicKey.from_public_bytes(key.raw)
    try:
        checker.verify(sig, hashlib.blake2b(data, digest_size=64).digest())
    except InvalidSignature:
        raise SignatureError(f"the signature doesn't match the file (key {key_id})") from None
    try:
        checker.verify(global_sig, sig + comment)
    except InvalidSignature:
        raise SignatureError("the trusted comment has been changed") from None
    return Signed(key, shown)
