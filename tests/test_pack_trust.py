"""Pack signatures, the key list and kept packs (plan 4.2). Keys here are
throwaway ones made for the tests; files are signed as minisign signs
them (prehashed Ed25519, a trusted comment under a global signature)."""

import base64
import hashlib
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_pack_format import GOOD

from checker import cli
from checker.packs import trust
from checker.packs.signing import SignatureError, public_key, verify


class Key:
    """A minisign key pair made for a test."""

    def __init__(self):
        self.secret = Ed25519PrivateKey.generate()
        self.id = os.urandom(8)
        raw = self.secret.public_key().public_bytes_raw()
        self.line = base64.b64encode(b"Ed" + self.id + raw).decode()

    @property
    def key_id(self) -> str:
        return self.id[::-1].hex().upper()

    def pub_file(self, path: Path) -> Path:
        path.write_text(f"untrusted comment: minisign public key {self.key_id}\n{self.line}\n")
        return path

    def sign(self, data: bytes, comment: str = "timestamp:1793000000", algorithm=b"ED") -> bytes:
        message = hashlib.blake2b(data, digest_size=64).digest() if algorithm == b"ED" else data
        sig = self.secret.sign(message)
        whole = self.secret.sign(sig + comment.encode())
        line = base64.b64encode(algorithm + self.id + sig).decode()
        return (
            f"untrusted comment: signature from minisign secret key\n{line}\n"
            f"trusted comment: {comment}\n{base64.b64encode(whole).decode()}\n"
        ).encode()


# --- Signatures --------------------------------------------------------------------------------


def test_a_good_signature_and_what_breaks_one():
    key, other = Key(), Key()
    data = b"some file\n"
    signed = verify(
        data, key.sign(data), [other_key := public_key(other.line), public_key(key.line)]
    )
    assert signed.key.key_id == key.key_id and signed.trusted_comment == "timestamp:1793000000"
    with pytest.raises(SignatureError, match="isn't trusted"):
        verify(data, key.sign(data), [other_key])
    with pytest.raises(SignatureError, match="doesn't match the file"):
        verify(data + b"x", key.sign(data), [public_key(key.line)])
    forged = key.sign(data).replace(b"timestamp:1793000000", b"timestamp:1893000000")
    with pytest.raises(SignatureError, match="trusted comment has been changed"):
        verify(data, forged, [public_key(key.line)])
    with pytest.raises(SignatureError, match="legacy"):
        verify(data, key.sign(data, algorithm=b"Ed"), [public_key(key.line)])


@pytest.mark.parametrize(
    "broken",
    [
        b"",
        b"untrusted comment: x\nAAAA\ntrusted comment: y\n",
        b"untrusted comment: x\n!!!\ntrusted comment: y\nAAAA\n",
        b"untrusted comment: x\nAAAA\ntrusted comment: y\nAAAA\n",
        b"comment: x\nAAAA\ntrusted comment: y\nAAAA\n",
        b"\xff" * 10,
        b"x" * 5000,
    ],
)
def test_a_malformed_signature_is_refused(broken):
    with pytest.raises(SignatureError):
        verify(b"data", broken, [public_key(Key().line)])


def test_a_public_key_with_or_without_its_comment_line(tmp_path):
    key = Key()
    assert public_key(key.pub_file(tmp_path / "k.pub").read_text()).key_id == key.key_id
    assert public_key(key.line).raw == key.secret.public_key().public_bytes_raw()
    for bad in ("", "RWQ", base64.b64encode(b"Xx" + b"0" * 40).decode(), "a\nb\nc"):
        with pytest.raises(SignatureError):
            public_key(bad)


# --- The key list ------------------------------------------------------------------------------


@pytest.fixture
def nouriloop(monkeypatch, tmp_path):
    """A test root key in place of NouriLoop's, no key list shipped."""
    root = Key()
    monkeypatch.setattr(trust, "ROOT_KEYS", (root.line,))
    monkeypatch.setattr(trust, "SHIPPED", tmp_path / "shipped")
    return root


def key_list(root, serial, trusted=(), revoked=()):
    lines = [f"format: 1\nserial: {serial}\nissued: 2026-11-0{min(serial, 9)}\npack_keys:"]
    lines += [f"  - {{name: pack key {i}, public_key: {k.line}}}" for i, k in enumerate(trusted)]
    lines += ["revoked:"] + [
        f"  - {{key_id: {k.key_id}, since: 2026-11-01, reason: leaked}}" for k in revoked
    ]
    data = ("\n".join(lines) + "\n").replace("pack_keys:\nrevoked:", "pack_keys: []\nrevoked:")
    if not revoked:
        data = data.replace("revoked:\n", "revoked: []\n")
    data = data.encode()
    return data, root.sign(data)


def test_a_key_list_only_from_the_root_key(nouriloop, home):
    base = home[0]
    pack_key = Key()
    data, sig = key_list(nouriloop, 1, [pack_key])
    new, old = trust.accept_key_list(base, data, sig)
    assert new.serial == 1 and old is None
    assert [k.key_id for k in trust.key_list(base).trusted()] == [pack_key.key_id]
    with pytest.raises(trust.TrustError, match="isn't trusted"):
        trust.accept_key_list(base, data, pack_key.sign(data))  # a pack key can't sign one


def test_an_older_key_list_cant_come_back(nouriloop, home):
    base = home[0]
    leaked, fresh = Key(), Key()
    trust.accept_key_list(base, *key_list(nouriloop, 1, [leaked]))
    trust.accept_key_list(base, *key_list(nouriloop, 2, [fresh], revoked=[leaked]))
    for serial in (1, 2):
        with pytest.raises(trust.TrustError, match="isn't newer"):
            trust.accept_key_list(base, *key_list(nouriloop, serial, [leaked]))
    assert [k.key_id for k in trust.key_list(base).trusted()] == [fresh.key_id]


def test_the_shipped_list_counts_until_a_newer_one_arrives(nouriloop, home):
    base = home[0]
    first, second = Key(), Key()
    trust.SHIPPED.mkdir()
    data, sig = key_list(nouriloop, 3, [first])
    (trust.SHIPPED / "keys.yaml").write_bytes(data)
    (trust.SHIPPED / "keys.yaml.minisig").write_bytes(sig)
    assert trust.key_list(base).serial == 3
    with pytest.raises(trust.TrustError, match="isn't newer"):
        trust.accept_key_list(base, *key_list(nouriloop, 2, [second]))
    trust.accept_key_list(base, *key_list(nouriloop, 4, [second]))
    assert trust.key_list(base).serial == 4
    # A tool update shipping a newer list than the one kept wins too.
    data, sig = key_list(nouriloop, 6, [first])
    (trust.SHIPPED / "keys.yaml").write_bytes(data)
    (trust.SHIPPED / "keys.yaml.minisig").write_bytes(sig)
    assert trust.key_list(base).serial == 6


def test_a_key_list_that_contradicts_itself_is_refused(nouriloop, home):
    key = Key()
    with pytest.raises(trust.TrustError, match="both trusted and revoked"):
        trust.accept_key_list(home[0], *key_list(nouriloop, 1, [key], revoked=[key]))


def test_without_a_root_key_no_key_list_is_trusted(home, monkeypatch):
    monkeypatch.setattr(trust, "ROOT_KEYS", ())
    with pytest.raises(trust.TrustError, match="no NouriLoop root key"):
        trust.accept_key_list(home[0], b"format: 1\n", b"")


# --- Adding and keeping packs ----------------------------------------------------------------


def pack(tmp_path, signer, text=GOOD, name="pack.yaml"):
    path = tmp_path / name
    path.write_text(text)
    (tmp_path / f"{name}.minisig").write_bytes(signer.sign(text.encode()))
    return path


@pytest.fixture
def ours(home, tmp_path, capsys):
    """An organization key, trusted with `checker packs trust add`."""
    key = Key()
    assert (
        cli.main(["packs", "trust", "add", "security team", str(key.pub_file(tmp_path / "k.pub"))])
        == 0
    )
    capsys.readouterr()
    return key


def test_add_list_show_and_retire(ours, home, tmp_path, capsys):
    path = pack(tmp_path, ours)
    assert cli.main(["packs", "add", str(path)]) == 0
    out = capsys.readouterr().out
    assert "example-2026-10 version 2" in out and "added" in out
    assert f"organization key security team ({ours.key_id})" in out
    assert cli.main(["packs", "add", str(path)]) == 0
    assert "already in force" in capsys.readouterr().out
    assert cli.main(["packs", "list"]) == 0
    assert "example-2026-10" in capsys.readouterr().out
    assert cli.main(["packs", "show", "example-2026-10"]) == 0
    shown = capsys.readouterr().out
    assert (
        "ubuntu:24.04: php8.3-fpm, libapache2-mod-php8.3: fixed in 8.3.6-0ubuntu0.24.04.6" in shown
    )
    assert "times 5" in shown
    assert cli.main(["packs", "retire", "example-2026-10", "--reason", "not ours"]) == 0
    capsys.readouterr()
    assert cli.main(["packs", "list", "--retired"]) == 0
    out = capsys.readouterr().out
    assert "No pack is in force" in out and "retired by hand: not ours" in out
    kept = home[0] / "packs" / "retired"
    (retired_pack,) = kept.glob("example-2026-10-v2-*.yaml")
    assert retired_pack.with_name(retired_pack.name + ".minisig").exists()


def test_a_newer_version_retires_the_older_and_an_older_one_is_refused(
    ours, tmp_path, capsys, home
):
    assert cli.main(["packs", "add", str(pack(tmp_path, ours))]) == 0
    v3 = pack(tmp_path, ours, GOOD.replace("version: 2", "version: 3"), "v3.yaml")
    assert cli.main(["packs", "add", str(v3)]) == 0
    assert "added, replacing version 2" in capsys.readouterr().out
    v1 = pack(tmp_path, ours, GOOD.replace("version: 2", "version: 1"), "v1.yaml")
    assert cli.main(["packs", "add", str(v1)]) == 1
    assert "version 3, newer, was accepted before" in capsys.readouterr().err
    (why,) = (p.read_text() for p in (home[0] / "packs" / "retired").glob("*-v2-*.yaml.why"))
    assert "replaced by version 3" in why


def test_changed_content_needs_a_new_version(ours, tmp_path, capsys):
    assert cli.main(["packs", "add", str(pack(tmp_path, ours))]) == 0
    changed = pack(tmp_path, ours, GOOD.replace("Turn off upload", "Switch off upload"), "c.yaml")
    assert cli.main(["packs", "add", str(changed)]) == 1
    assert "a changed pack needs a new version" in capsys.readouterr().err


def test_the_signature_is_checked_before_the_content_is_read(ours, tmp_path, capsys, monkeypatch):
    import checker.packs.store as store

    stranger = Key()
    path = pack(tmp_path, stranger, "!!python/object/apply:os.system ['true']\n")

    def must_not_read(data):
        raise AssertionError("the content was read before the signature was checked")

    monkeypatch.setattr(store, "read", must_not_read)
    assert cli.main(["packs", "add", str(path)]) == 1
    assert "isn't trusted" in capsys.readouterr().err


def test_no_signature_no_pack(ours, tmp_path, capsys):
    path = tmp_path / "unsigned.yaml"
    path.write_text(GOOD)
    assert cli.main(["packs", "add", str(path)]) == 1
    assert "No such file" in capsys.readouterr().err


def test_with_no_trusted_key_nothing_is_added(home, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(trust, "ROOT_KEYS", ())
    monkeypatch.setattr(trust, "SHIPPED", tmp_path / "none")
    assert cli.main(["packs", "add", str(pack(tmp_path, Key()))]) == 1
    assert "no key is trusted to sign packs:" in capsys.readouterr().err


def test_a_pack_naming_an_unknown_check_is_refused(ours, tmp_path, capsys):
    text = GOOD.replace("check: web.worker_child", "check: web.not_a_check")
    assert cli.main(["packs", "add", str(pack(tmp_path, ours, text))]) == 1
    assert (
        "doesn't have: detection worker-child: no check web.not_a_check" in capsys.readouterr().err
    )


def test_a_kept_pack_changed_on_disk_isnt_used(ours, home, tmp_path, capsys):
    from checker.evidence import load_config
    from checker.packs.store import active

    assert cli.main(["packs", "add", str(pack(tmp_path, ours))]) == 0
    kept = home[0] / "packs" / "active" / "example-2026-10-v2.yaml"
    kept.write_text(GOOD.replace("likelihood_ratio: 5", "likelihood_ratio: 2"))
    usable, problems = active(home[0], load_config(home[0]).packs.trusted_keys)
    assert usable == [] and "doesn't match the file" in problems[0]


def test_a_revoked_pack_key_retires_its_packs(nouriloop, home, tmp_path, capsys):
    leaked, fresh = Key(), Key()
    keys = tmp_path / "keys.yaml"
    data, sig = key_list(nouriloop, 1, [leaked])
    keys.write_bytes(data)
    (tmp_path / "keys.yaml.minisig").write_bytes(sig)
    assert cli.main(["packs", "keys", "add", str(keys)]) == 0
    assert cli.main(["packs", "add", str(pack(tmp_path, leaked))]) == 0
    assert "NouriLoop pack key 0" in capsys.readouterr().out
    data, sig = key_list(nouriloop, 2, [fresh], revoked=[leaked])
    keys.write_bytes(data)
    (tmp_path / "keys.yaml.minisig").write_bytes(sig)
    assert cli.main(["packs", "keys", "add", str(keys)]) == 0
    out = capsys.readouterr().out
    assert "serial 2 is in force (was 1)" in out
    assert "Retired example-2026-10-v2.yaml: its signing key is no longer trusted" in out
    assert not (home[0] / "packs" / "active" / "example-2026-10-v2.yaml").exists()
    assert list((home[0] / "packs" / "retired").glob("example-2026-10-v2-*.yaml"))
    assert cli.main(["packs", "add", str(pack(tmp_path, leaked))]) == 1  # refused from now on
    assert cli.main(["packs", "keys"]) == 0
    shown = capsys.readouterr().out
    assert f"revoked: {leaked.key_id} since 2026-11-01: leaked" in shown


def test_removing_an_organization_key_retires_its_packs_and_is_recorded(
    ours, home, tmp_path, capsys
):
    from test_settings import changes

    assert cli.main(["packs", "add", str(pack(tmp_path, ours))]) == 0
    assert cli.main(["packs", "trust", "remove", "security team"]) == 0
    assert "Retired example-2026-10-v2.yaml" in capsys.readouterr().out
    assert [row["setting"] for row in changes(home[0])] == ["packs.trusted_keys"] * 2
    assert cli.main(["packs", "trust", "remove", "security team"]) == 1


def test_a_key_is_trusted_once(ours, tmp_path, capsys):
    path = ours.pub_file(tmp_path / "again.pub")
    assert cli.main(["packs", "trust", "add", "same key", str(path)]) == 1
    assert "is already trusted" in capsys.readouterr().err


# --- After review ------------------------------------------------------------------------------


def test_no_older_version_and_no_changed_content_even_after_a_retire(ours, tmp_path, capsys):
    v1 = pack(tmp_path, ours, GOOD.replace("version: 2", "version: 1"), "v1.yaml")
    v2 = pack(tmp_path, ours)
    assert cli.main(["packs", "add", str(v1)]) == 0
    assert cli.main(["packs", "add", str(v2)]) == 0
    assert cli.main(["packs", "retire", "example-2026-10", "--reason", "done"]) == 0
    capsys.readouterr()
    assert cli.main(["packs", "add", str(v1)]) == 1
    assert "an older version can't come back" in capsys.readouterr().err
    changed = pack(tmp_path, ours, GOOD.replace("Turn off", "Switch off"), "c.yaml")
    assert cli.main(["packs", "add", str(changed)]) == 1
    assert "accepted before with different content" in capsys.readouterr().err
    assert cli.main(["packs", "add", str(v2)]) == 0  # the same one, back in force
    assert "back in force" in capsys.readouterr().out


def test_retiring_the_same_pack_twice_keeps_both_notes(ours, home, tmp_path):
    path = pack(tmp_path, ours)
    for why in ("first", "second"):
        assert cli.main(["packs", "add", str(path)]) == 0
        assert cli.main(["packs", "retire", "example-2026-10", "--reason", why]) == 0
    (notes,) = (home[0] / "packs" / "retired").glob("*.why")
    text = notes.read_text()
    assert "retired by hand: first" in text and "retired by hand: second" in text


def test_a_pack_id_stays_with_the_domain_that_signs_it(nouriloop, home, tmp_path, capsys):
    pack_key, ours_key = Key(), Key()
    keys = tmp_path / "keys.yaml"
    data, sig = key_list(nouriloop, 1, [pack_key])
    keys.write_bytes(data)
    (tmp_path / "keys.yaml.minisig").write_bytes(sig)
    assert cli.main(["packs", "keys", "add", str(keys)]) == 0
    assert (
        cli.main(["packs", "trust", "add", "ours", str(ours_key.pub_file(tmp_path / "o.pub"))]) == 0
    )
    assert cli.main(["packs", "add", str(pack(tmp_path, pack_key))]) == 0
    capsys.readouterr()
    takeover = pack(tmp_path, ours_key, GOOD.replace("version: 2", "version: 10000"), "t.yaml")
    assert cli.main(["packs", "add", str(takeover)]) == 1
    assert "signed by NouriLoop's keys" in capsys.readouterr().err


def test_a_revoked_key_is_no_organization_key_either(nouriloop, home, tmp_path, capsys):
    from checker.settings import change_trusted_keys

    leaked = Key()
    keys = tmp_path / "keys.yaml"
    data, sig = key_list(nouriloop, 1, [Key()], revoked=[leaked])
    keys.write_bytes(data)
    (tmp_path / "keys.yaml.minisig").write_bytes(sig)
    assert cli.main(["packs", "keys", "add", str(keys)]) == 0
    assert cli.main(["packs", "trust", "add", "x", str(leaked.pub_file(tmp_path / "l.pub"))]) == 1
    assert "is revoked" in capsys.readouterr().err
    # Put in by hand all the same: still not trusted.
    change_trusted_keys(home[0], lambda old: [*old, {"name": "x", "public_key": leaked.line}])
    assert cli.main(["packs", "add", str(pack(tmp_path, leaked))]) == 1
    assert "isn't trusted" in capsys.readouterr().err


def test_a_root_key_signs_no_pack(nouriloop, home, tmp_path, capsys):
    with pytest.raises(trust.TrustError, match="a root key can't be a pack key"):
        trust.accept_key_list(home[0], *key_list(nouriloop, 1, [nouriloop]))
    assert (
        cli.main(["packs", "trust", "add", "r", str(nouriloop.pub_file(tmp_path / "r.pub"))]) == 1
    )
    assert "root key" in capsys.readouterr().err


def test_a_damaged_kept_key_list_trusts_nothing_rather_than_an_older_one(
    nouriloop, home, tmp_path, capsys
):
    base = home[0]
    leaked, fresh = Key(), Key()
    trust.SHIPPED.mkdir()
    data, sig = key_list(nouriloop, 1, [leaked])
    (trust.SHIPPED / "keys.yaml").write_bytes(data)
    (trust.SHIPPED / "keys.yaml.minisig").write_bytes(sig)
    trust.accept_key_list(base, *key_list(nouriloop, 2, [fresh], revoked=[leaked]))
    assert cli.main(["packs", "add", str(pack(tmp_path, fresh))]) == 0
    kept = base / "packs" / "keylists" / "2" / "keys.yaml.minisig"
    kept.write_bytes(leaked.sign(b"x"))
    with pytest.raises(trust.TrustError):
        trust.key_list(base)
    keys, problem = trust.trusted_keys(base, [])
    assert keys == [] and problem
    from checker.packs.store import sweep

    assert sweep(base, []) == []  # a damaged list isn't a revocation
    capsys.readouterr()
    assert cli.main(["packs", "add", str(pack(tmp_path, leaked, name="l.yaml"))]) == 1
    # Removed altogether: the recorded serial still stands.
    import shutil

    shutil.rmtree(base / "packs" / "keylists" / "2")
    with pytest.raises(trust.TrustError, match="accepted here but isn't kept"):
        trust.key_list(base)


def test_two_trusted_keys_sharing_an_id_are_both_refused():
    first, second = Key(), Key()
    second.id = first.id  # an id chosen to collide
    data = b"pack"
    keys = [public_key(first.line), public_key(Key().line)]
    keys.append(
        public_key(
            base64.b64encode(
                b"Ed" + first.id + second.secret.public_key().public_bytes_raw()
            ).decode()
        )
    )
    with pytest.raises(SignatureError, match="share the key id"):
        verify(data, first.sign(data), keys)


def test_only_the_newest_version_of_a_pack_is_in_force(ours, home, tmp_path):
    from checker.evidence import load_config
    from checker.packs.store import active

    active_dir = home[0] / "packs" / "active"
    for version in (9, 10):
        text = GOOD.replace("version: 2", f"version: {version}")
        path = pack(tmp_path, ours, text, f"v{version}.yaml")
        active_dir.mkdir(parents=True, exist_ok=True)
        (active_dir / f"example-2026-10-v{version}.yaml").write_text(text)
        (active_dir / f"example-2026-10-v{version}.yaml.minisig").write_bytes(
            path.with_name(path.name + ".minisig").read_bytes()
        )
    usable, problems = active(home[0], load_config(home[0]).packs.trusted_keys)
    assert [s.pack.version for s in usable] == [10]
    assert "version 9 is also in force; only 10 is used" in problems[0]


def test_a_trusted_comment_may_be_any_utf8():
    key = Key()
    signed = verify(
        b"x", key.sign(b"x", comment="timestamp:1 file:paquet-été.yaml"), [public_key(key.line)]
    )
    assert signed.trusted_comment.endswith("été.yaml")


def test_an_oversized_kept_pack_isnt_read(ours, home, tmp_path):
    from checker.evidence import load_config
    from checker.packs.format import MAX_BYTES
    from checker.packs.store import active

    assert cli.main(["packs", "add", str(pack(tmp_path, ours))]) == 0
    (home[0] / "packs" / "active" / "example-2026-10-v2.yaml").write_bytes(b"#" * (MAX_BYTES + 10))
    usable, problems = active(home[0], load_config(home[0]).packs.trusted_keys)
    assert usable == [] and "larger than a pack may be" in problems[0]


# --- The keys shipped ------------------------------------------------------------------------


def test_the_shipped_key_list_is_signed_by_the_shipped_root_key():
    """NouriLoop's own: changing either key is a deliberate, visible change."""
    assert [k.key_id for k in trust.root_keys()] == ["93AB05572B87296E"]
    data = (trust.SHIPPED / "keys.yaml").read_bytes()
    listed = trust.read_key_list(data, (trust.SHIPPED / "keys.yaml.minisig").read_bytes())
    assert listed.serial == 1 and listed.revoked == []
    assert [k.key_id for k in listed.trusted()] == ["97CF7C2D514024F0"]


def test_a_fresh_home_trusts_the_shipped_pack_key_and_nothing_else(home):
    keys, problem = trust.trusted_keys(home[0], [])
    assert problem is None
    assert [(k.key.key_id, k.domain) for k in keys] == [("97CF7C2D514024F0", trust.NOURILOOP)]


# --- A list that ships with the tool ------------------------------------------------------------


def ship(serial_list):
    trust.SHIPPED.mkdir(exist_ok=True)
    (trust.SHIPPED / "keys.yaml").write_bytes(serial_list[0])
    (trust.SHIPPED / "keys.yaml.minisig").write_bytes(serial_list[1])


def test_going_back_to_an_older_tool_cant_bring_a_revoked_key_back(nouriloop, home, tmp_path):
    from checker.packs.state import read_state
    from checker.packs.store import in_force

    base = home[0]
    leaked, fresh = Key(), Key()
    ship(key_list(nouriloop, 1, [leaked]))
    assert cli.main(["packs", "add", str(pack(tmp_path, leaked))]) == 0
    assert read_state(base)["key_list_serial"] == 1
    # The tool is updated: its list revokes the key. The next analysis takes it in.
    ship(key_list(nouriloop, 2, [fresh], revoked=[leaked]))
    packs, problems = in_force(base, [])
    assert packs == []
    assert problems == ["example-2026-10-v2.yaml: retired, its signing key is no longer trusted"]
    assert read_state(base)["key_list_serial"] == 2
    assert in_force(base, []) == ([], [])  # said once
    # The older tool again: serial 2 is kept, and stands.
    ship(key_list(nouriloop, 1, [leaked]))
    assert trust.key_list(base).serial == 2
    assert [k.key.key_id for k in trust.trusted_keys(base, [])[0]] == [fresh.key_id]


def test_a_shipped_list_no_newer_is_left_alone_and_a_damaged_one_named(nouriloop, home):
    base = home[0]
    ship(key_list(nouriloop, 1, [Key()]))
    assert trust.adopt_shipped(base).serial == 1
    assert trust.adopt_shipped(base) is None
    (trust.SHIPPED / "keys.yaml.minisig").write_bytes(Key().sign(b"x"))
    assert trust.key_list(base).serial == 1  # the kept copy stands
    assert not trust.shipped_newer(base)
    import shutil

    shutil.rmtree(base / "packs" / "keylists")
    state = base / "packs" / "state.json"
    state.unlink()
    with pytest.raises(trust.TrustError, match="the key list shipped with the tool"):
        trust.key_list(base)


def test_the_same_list_again_is_already_in_force(nouriloop, home, tmp_path, capsys):
    files = key_list(nouriloop, 1, [Key()])
    ship(files)
    path = tmp_path / "keys.yaml"
    path.write_bytes(files[0])
    (tmp_path / "keys.yaml.minisig").write_bytes(files[1])
    assert cli.main(["packs", "keys", "add", str(path)]) == 0
    assert "serial 1 is already in force" in capsys.readouterr().out
    other = key_list(nouriloop, 1, [Key()])
    path.write_bytes(other[0])
    (tmp_path / "keys.yaml.minisig").write_bytes(other[1])
    assert cli.main(["packs", "keys", "add", str(path)]) == 1
    assert "isn't newer" in capsys.readouterr().err
