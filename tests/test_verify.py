"""checker/verify: files checked against the distribution's own signed packages (#189).

Packages, signed lists and rpm headers are built here and signed with
throwaway keys made for the run (gpg is needed for that; gpgv for every
check). Two real files, saved from the distributions (tests/verify_fixtures),
check the parsers and the pinned keys against the real formats.

The attack tests follow the plan's list
(plans/pam-offserver-verify-plan-2026-11-21.md, "How the attacks fail").
"""

from __future__ import annotations

import hashlib
import io
import json
import lzma
import os
import shutil
import struct
import subprocess
import tarfile
import tempfile
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from checker.verify import Lookup, Official, Verifier, compare, deb, gpg, package_paths, rpm
from checker.verify.fetch import FetchError, HttpFetcher

try:
    from compression import zstd
except ImportError:
    from backports import zstd

FIXTURES = Path(__file__).parent / "verify_fixtures"
UNIX = "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"
PERMIT = "/usr/lib/x86_64-linux-gnu/security/pam_permit.so"
JAMMY_UNIX = "/lib/x86_64-linux-gnu/security/pam_unix.so"
RPM_UNIX = "/usr/lib64/security/pam_unix.so"
UNIX_BYTES = b"\x7fELF the real pam_unix"
PERMIT_BYTES = b"\x7fELF pam_permit: always yes"
TROJAN = b"\x7fELF pam_unix with a backdoor"
ARCHIVE = "http://archive.test/ubuntu"
SNAP = "https://snapshot.test/ubuntu"
LP = "https://launchpad.test/1.0"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# conftest's guard refuses any `gpg` run, so no test can use a password
# manager's key command. These are the test's own throwaway keys, in a
# private --homedir made here: never a key command, so the unguarded run,
# taken when this module loads (before the guard is put in place).
_run = subprocess.run

needs_gpgv = pytest.mark.skipif(shutil.which("gpgv") is None, reason="gpgv isn't installed")


# --- Throwaway keys -----------------------------------------------------------------------


class Keys:
    def __init__(self):
        if shutil.which("gpg") is None:
            if os.environ.get("CI"):
                raise RuntimeError("gpg is needed to sign the test data")
            pytest.skip("gpg isn't installed")
        # A short path: gpg-agent's socket lives in it.
        self.home = tempfile.mkdtemp(prefix="cvk", dir="/tmp")
        self.fpr = {}
        for name in ("good", "other"):
            self._gpg(
                "--quick-gen-key",
                f"{name} test key <{name}@test.invalid>",
                "ed25519",
                "sign",
                "never",
            )
            listing = self._gpg("--with-colons", "--list-keys", f"{name}@test.invalid").decode()
            self.fpr[name] = next(
                line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr")
            )
        self.public = {n: self._gpg("--export", f) for n, f in self.fpr.items()}

    def _gpg(self, *args, data: bytes | None = None) -> bytes:
        return _run(
            [
                "gpg",
                "--homedir",
                self.home,
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                *args,
            ],
            input=data,
            capture_output=True,
            check=True,
        ).stdout

    def clearsign(self, text: bytes, key: str = "good") -> bytes:
        return self._gpg("--local-user", self.fpr[key], "--clearsign", data=text)

    def detach(self, data: bytes, key: str = "good") -> bytes:
        return self._gpg("--local-user", self.fpr[key], "--detach-sign", data=data)

    def close(self):
        _run(["gpgconf", "--homedir", self.home, "--kill", "all"], capture_output=True)
        shutil.rmtree(self.home, ignore_errors=True)


@pytest.fixture(scope="session")
def keys():
    made = Keys()
    yield made
    made.close()


@pytest.fixture
def pinned(keys, monkeypatch):
    """Every pinned name stands for the throwaway "good" key."""
    monkeypatch.setattr(gpg, "KEYS", {n: (keys.fpr["good"], "-") for n in gpg.KEYS})
    monkeypatch.setattr(gpg, "_keyring", lambda names: keys.public["good"])
    return keys


# --- Building the distributions' formats --------------------------------------------------


def make_deb(files: dict[str, bytes], links: dict[str, str] | None = None) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for path, data in files.items():
            info = tarfile.TarInfo("." + path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for path, target in (links or {}).items():
            info = tarfile.TarInfo("." + path)
            info.type, info.linkname = tarfile.SYMTYPE, target
            tar.addfile(info)
    return make_ar({"debian-binary": b"2.0\n", "data.tar.zst": zstd.compress(raw.getvalue())})


def make_ar(members: dict[str, bytes]) -> bytes:
    out = b"!<arch>\n"
    for name, body in members.items():
        head = f"{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(body):<10}".encode() + b"`\n"
        out += head + body + (b"\n" if len(body) % 2 else b"")
    return out


def packages_text(entries) -> bytes:
    stanzas = []
    for package, version, filename, data, arch in entries:
        stanzas.append(
            f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n"
            f"Filename: {filename}\nSize: {len(data)}\nSHA256: {sha(data)}\n"
        )
    return "\n".join(stanzas).encode()


def inrelease_text(suite: str, indexes: dict[str, bytes]) -> bytes:
    lines = [f"Origin: Ubuntu\nSuite: {suite}\nCodename: {suite.split('-')[0]}\nSHA256:"]
    lines += [f" {sha(d)} {len(d):>16} {n}" for n, d in indexes.items()]
    return ("\n".join(lines) + "\n").encode()


class Site:
    """A fake web: {url: bytes}, with the first-bytes form of a range request."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.asked: list[str] = []
        self.down = False

    def get(self, url, limit, first=None):
        self.asked.append(url)
        if self.down:
            raise FetchError("no network")
        data = self.files.get(url)
        if data is None:
            return None
        return data[:first] if first is not None else data

    def ubuntu(self, keys, base, suite, debs, key="good", inrelease=None, component="main"):
        """Publish `debs` [(package, version, {path: bytes}[, arch])] in a signed suite."""
        entries = []
        for package, version, files, *rest in debs:
            arch = rest[0] if rest else "amd64"
            data = make_deb(files)
            filename = f"pool/{component}/{package[0]}/{package}/{package}_{version}_{arch}.deb"
            self.files[f"{base}/{filename}"] = data
            entries.append((package, version, filename, data, arch))
        index = lzma.compress(packages_text(entries))
        name = f"{component}/binary-amd64/Packages.xz"
        self.files[f"{base}/dists/{suite}/{name}"] = index
        text = inrelease if inrelease is not None else inrelease_text(suite, {name: index})
        self.files[f"{base}/dists/{suite}/InRelease"] = keys.clearsign(text, key)


PAM = {UNIX: UNIX_BYTES, PERMIT: PERMIT_BYTES}


def ubuntu_verifier(site, **kw):
    kw.setdefault("ubuntu_snapshot", None)
    kw.setdefault("launchpad", None)
    return Verifier(None, fetcher=site, ubuntu_archive=ARCHIVE, **kw)


NOBLE = Lookup("ubuntu", "24.04", "libpam-modules", "1.5.3-5ubuntu5.7", "amd64")


# --- rpm headers --------------------------------------------------------------------------


def header(tags: list[tuple[int, int, bytes, int]]) -> bytes:
    index, store = b"", b""
    for tag, kind, data, count in tags:
        index += struct.pack(">IIII", tag, kind, len(store), count)
        store += data
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", len(tags), len(store)) + index + store


def strs(*values: str) -> bytes:
    return b"".join(v.encode() + b"\0" for v in values)


def make_rpm(
    keys,
    name="pam",
    version="1.5.1",
    release="29.el9",
    arch="x86_64",
    files=None,
    algo=8,
    key="good",
    pad=0,
    epoch=None,
    ghosts=(),
) -> bytes:
    """`files` {path: bytes}; `ghosts` paths listed with no digest (%ghost)."""
    files = dict(files if files is not None else {RPM_UNIX: UNIX_BYTES})
    files.update({g: None for g in ghosts})
    paths = sorted(files)
    dirs = sorted({p.rsplit("/", 1)[0] + "/" for p in paths})
    main = header(
        [
            (rpm.NAME, 6, strs(name), 1),
            (rpm.VERSION, 6, strs(version), 1),
            (rpm.RELEASE, 6, strs(release), 1),
            (rpm.ARCH, 6, strs(arch), 1),
            (
                rpm.FILEMODES,
                3,
                struct.pack(f">{len(paths)}H", *[0o100755] * len(paths)),
                len(paths),
            ),
            (
                rpm.FILEDIGESTS,
                8,
                strs(*[sha(files[p]) if files[p] is not None else "" for p in paths]),
                len(paths),
            ),
            (
                rpm.FILEFLAGS,
                4,
                struct.pack(f">{len(paths)}I", *[rpm.GHOST if p in ghosts else 0 for p in paths]),
                len(paths),
            ),
            (rpm.FILELINKTOS, 8, strs(*[""] * len(paths)), len(paths)),
            (
                rpm.DIRINDEXES,
                4,
                struct.pack(
                    f">{len(paths)}I", *[dirs.index(p.rsplit("/", 1)[0] + "/") for p in paths]
                ),
                len(paths),
            ),
            (rpm.BASENAMES, 8, strs(*[p.rsplit("/", 1)[1] for p in paths]), len(paths)),
            (rpm.DIRNAMES, 8, strs(*dirs), len(dirs)),
            (rpm.FILEDIGESTALGO, 4, struct.pack(">I", algo), 1),
            (99999, 7, b"\0" * pad, pad),
        ]
        + ([(rpm.EPOCH, 4, struct.pack(">I", epoch), 1)] if epoch is not None else [])
    )
    signed = keys.detach(main, key)
    signature = header([(rpm.SIG_RSA, 7, signed, len(signed))])
    lead = b"\xed\xab\xee\xdb" + b"\0" * 92
    body = lead + signature
    body += b"\0" * ((8 - len(body) % 8) % 8)
    return body + main + b"payload that is never fetched"


ROCKY_URL = "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/p/"
ROCKY = Lookup("rocky", "9", "pam", "1.5.1-29.el9", "x86_64")


# === The real formats, with the real pinned keys =========================================


@needs_gpgv
def test_real_ubuntu_inrelease_verifies_with_the_pinned_key():
    signed, signer = gpg.verify_clearsigned(
        (FIXTURES / "ubuntu-noble-updates.InRelease").read_bytes(), deb.KEYS
    )
    assert signer == gpg.KEYS["ubuntu-2018"][0]
    hashes = deb.release_hashes(signed, "noble-updates")
    assert len(hashes["main/binary-amd64/Packages.xz"][0]) == 64
    with pytest.raises(deb.PackageError, match="not noble-security"):
        deb.release_hashes(signed, "noble-security")


@needs_gpgv
def test_real_rocky_header_verifies_and_lists_pam_unix():
    data = (FIXTURES / "rocky-9-pam-1.5.1-29.el9.x86_64.rpm-header").read_bytes()
    files, signer = rpm.check_header(data, ("rocky-9",), "pam", "1.5.1-29.el9", "x86_64")
    assert signer == gpg.KEYS["rocky-9"][0]
    assert files[RPM_UNIX] == {
        "sha256": "d040eed6a5a3fd16e4cd2fa021bd56edc574dcc6d9eace71b14f2323fad3f30c"
    }
    with pytest.raises(rpm.PackageError, match="header is for"):
        rpm.check_header(data, ("rocky-9",), "pam", "1.5.1-28.el9", "x86_64")
    with pytest.raises(rpm.PackageError, match="isn't pinned|failed"):
        rpm.check_header(data, ("almalinux-9",), "pam", "1.5.1-29.el9", "x86_64")


def test_every_pinned_key_file_holds_its_fingerprint(tmp_path):
    if shutil.which("gpg") is None:
        pytest.skip("gpg isn't installed")
    for name, (fingerprint, _) in gpg.KEYS.items():
        ring = tmp_path / f"{name}.gpg"
        ring.write_bytes(gpg._keyring([name]))
        listing = _run(
            ["gpg", "--homedir", str(tmp_path), "--with-colons", "--show-keys", str(ring)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        primary = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr")]
        assert primary[0] == fingerprint, name


# === Ubuntu =============================================================================


@needs_gpgv
def test_ubuntu_package_found_and_matched(pinned):
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-security", [("libpam-modules", NOBLE.version, PAM)])
    official = ubuntu_verifier(site).package(NOBLE)
    assert official.found, official.reason
    assert official.files[UNIX] == {"sha256": sha(UNIX_BYTES)}
    assert official.signer == pinned.fpr["good"]
    assert compare(official, UNIX, sha(UNIX_BYTES), {}) == "matched"
    assert compare(official, UNIX, sha(TROJAN), {}) == "differs"


@needs_gpgv
def test_the_suites_are_tried_in_turn(pinned):
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-security", [("other", "1", {"/x": b"x"})])
    site.ubuntu(pinned, ARCHIVE, "noble", [("libpam-modules", NOBLE.version, PAM)])
    assert ubuntu_verifier(site).package(NOBLE).found


@needs_gpgv
def test_jammy_paths_under_lib_match_only_where_the_server_reports_merged_usr(pinned):
    site = Site()
    lookup = Lookup("ubuntu", "22.04", "libpam-modules", "1.4.0-11ubuntu2.8", "amd64")
    site.ubuntu(
        pinned,
        ARCHIVE,
        "jammy-updates",
        [("libpam-modules", lookup.version, {JAMMY_UNIX: UNIX_BYTES})],
    )
    official = ubuntu_verifier(site).package(lookup)
    assert compare(official, UNIX, sha(UNIX_BYTES), {"/lib": "/usr/lib"}) == "matched"
    assert compare(official, UNIX, sha(UNIX_BYTES), {}) == "absent"
    # Only the fixed pairs: a made-up "merge" maps nothing.
    assert package_paths(UNIX, {"/usr/lib": "/opt"}) == [UNIX]


# --- The attacks -------------------------------------------------------------------------


@needs_gpgv
def test_attack_dpkg_diversion_owner_claims_vim(pinned):
    """1: the server says vim owns the module; vim's package has no such file."""
    site = Site()
    site.ubuntu(
        pinned, ARCHIVE, "noble-updates", [("vim", "2:9.1", {"/usr/bin/vim.basic": b"vim"})]
    )
    official = ubuntu_verifier(site).package(Lookup("ubuntu", "24.04", "vim", "2:9.1", "amd64"))
    assert compare(official, UNIX, sha(TROJAN), {}) == "absent"


@needs_gpgv
def test_attack_made_up_or_rebuilt_version_isnt_in_the_signed_lists(pinned):
    """2 and 3: a forged Version: line, or a rebuilt package with a bumped version."""
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-updates", [("libpam-modules", NOBLE.version, PAM)])
    forged = Lookup("ubuntu", "24.04", "libpam-modules", "1.5.3-5ubuntu5.8", "amd64")
    official = ubuntu_verifier(site).package(forged)
    assert not official.found
    assert "isn't in Ubuntu's archive" in official.reason


@needs_gpgv
def test_attack_list_signed_by_another_key(pinned):
    """3: a rebuilt archive signed by a key that isn't Ubuntu's."""
    site = Site()
    site.ubuntu(
        pinned, ARCHIVE, "noble-security", [("libpam-modules", NOBLE.version, PAM)], key="other"
    )
    official = ubuntu_verifier(site).package(NOBLE)
    assert not official.found
    assert "InRelease" in official.reason and "signature" in official.reason


@needs_gpgv
def test_attack_pam_permit_copied_over_pam_unix(pinned):
    """6: both files are in the same signed package; only the path's own file counts."""
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-security", [("libpam-modules", NOBLE.version, PAM)])
    official = ubuntu_verifier(site).package(NOBLE)
    assert compare(official, UNIX, sha(PERMIT_BYTES), {}) == "differs"


@needs_gpgv
def test_attack_module_from_another_release(pinned):
    """7: 22.04's pam_unix on a 24.04 server claiming 24.04's version."""
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-security", [("libpam-modules", NOBLE.version, PAM)])
    official = ubuntu_verifier(site).package(NOBLE)
    assert compare(official, UNIX, sha(b"\x7fELF jammy's pam_unix"), {}) == "differs"


@needs_gpgv
def test_attack_tampered_list_index_or_package(pinned):
    """8: someone between the checker and the mirror."""
    for target in ("InRelease", "Packages.xz", ".deb"):
        site = Site()
        site.ubuntu(pinned, ARCHIVE, "noble-security", [("libpam-modules", NOBLE.version, PAM)])
        url = next(u for u in site.files if u.endswith(target))
        data = bytearray(site.files[url])
        if target == "InRelease":
            at = data.index(b"Suite: noble-security") + len("Suite: ")
            data[at : at + 5] = b"NOBLE"
        else:
            data[len(data) // 2] ^= 0xFF
        site.files[url] = bytes(data)
        official = ubuntu_verifier(site).package(NOBLE)
        assert not official.found, target
        expected = "signature failed" if target == "InRelease" else "doesn't match the signed list"
        assert expected in official.reason, (target, official.reason)


@needs_gpgv
def test_attack_another_suites_signed_list_served_in_its_place(pinned):
    """8: a genuine signed list, but for another suite (mix and match)."""
    site = Site()
    site.ubuntu(
        pinned,
        ARCHIVE,
        "noble-security",
        [("libpam-modules", NOBLE.version, PAM)],
        inrelease=inrelease_text("noble-proposed", {}),
    )
    official = ubuntu_verifier(site).package(NOBLE)
    assert "not noble-security" in official.reason


@needs_gpgv
def test_attack_text_around_the_signed_block_is_never_used(pinned):
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-security", [("libpam-modules", NOBLE.version, PAM)])
    url = f"{ARCHIVE}/dists/noble-security/InRelease"
    genuine = site.files[url]
    site.files[url] = genuine + b"SHA256:\n " + b"0" * 64 + b" 1 main/binary-amd64/Packages.xz\n"
    signed, _ = gpg.verify_clearsigned(site.files[url], deb.KEYS)
    assert b"0" * 64 not in signed
    with pytest.raises(gpg.SignatureError, match="doesn't start"):
        gpg.verify_clearsigned(b"Suite: x\n" + genuine, deb.KEYS)
    with pytest.raises(gpg.SignatureError, match="more than one"):
        gpg.verify_clearsigned(genuine + genuine, deb.KEYS)


@needs_gpgv
def test_attack_a_second_signature_by_an_unknown_key_fails_it(pinned):
    text = inrelease_text("noble-security", {})
    both = pinned._gpg(
        "--local-user",
        pinned.fpr["good"],
        "--local-user",
        pinned.fpr["other"],
        "--clearsign",
        data=text,
    )
    with pytest.raises(gpg.SignatureError):
        gpg.verify_clearsigned(both, deb.KEYS)


def test_attack_hostile_package_contents(monkeypatch):
    """10: paths that climb out, links, and endless data."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        info = tarfile.TarInfo("./../../etc/shadow")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    evil = make_ar({"debian-binary": b"2.0\n", "data.tar.zst": zstd.compress(raw.getvalue())})
    with pytest.raises(deb.PackageError, match="climbs out"):
        deb.deb_files(evil)
    linked = deb.deb_files(make_deb({}, links={UNIX: "/etc/shadow"}))
    assert linked[UNIX] == {"link": "/etc/shadow"}
    official = Official(NOBLE, linked)
    assert compare(official, UNIX, sha(b"anything"), {}) == "link"
    monkeypatch.setattr(deb, "MAX_DATA", 1000)
    with pytest.raises(deb.PackageError, match="more than the limit"):
        deb.deb_files(make_deb({UNIX: b"\0" * 100_000}))
    with pytest.raises(deb.PackageError):
        deb.ar_members(b"!<arch>\nshort")


# --- Older versions: dated copies, chosen with Launchpad's dates --------------------------


def launchpad_answer(version, pocket, published, superseded=None):
    return json.dumps(
        {
            "entries": [
                {
                    "binary_package_version": version,
                    "pocket": pocket,
                    "status": "Superseded",
                    "date_published": published,
                    "date_superseded": superseded,
                }
            ]
        }
    ).encode()


@needs_gpgv
def test_a_version_that_dropped_off_is_found_in_a_dated_copy(pinned):
    site = Site()
    old = Lookup("ubuntu", "24.04", "libpam-modules", "1.5.3-5ubuntu5.6", "amd64")
    site.ubuntu(pinned, ARCHIVE, "noble-updates", [("libpam-modules", NOBLE.version, PAM)])
    copy = f"{SNAP}/20260827T200300Z"
    site.ubuntu(pinned, copy, "noble-updates", [("libpam-modules", old.version, PAM)])
    answer = launchpad_answer(
        old.version, "Updates", "2026-07-23T18:36:44+00:00", "2026-08-27T20:04:00+00:00"
    )
    site.files[next_launchpad_url(old)] = answer
    verifier = ubuntu_verifier(site, ubuntu_snapshot=SNAP, launchpad=LP)
    official = verifier.package(old)
    assert official.found, official.reason
    assert official.source.startswith(copy)


def next_launchpad_url(lookup):
    import urllib.parse

    query = urllib.parse.urlencode(
        {
            "ws.op": "getPublishedBinaries",
            "binary_name": lookup.package,
            "exact_match": "true",
            "version": lookup.version,
            "distro_arch_series": f"{LP}/ubuntu/noble/{lookup.arch}",
            "ws.size": "50",
        }
    )
    return f"{LP}/ubuntu/+archive/primary?{query}"


def test_which_dated_copy():
    now = datetime(2026, 11, 21, tzinfo=UTC)
    item = {
        "binary_package_version": "1",
        "pocket": "Updates",
        "date_published": "2026-07-23T18:36:44+00:00",
        "date_superseded": "2026-08-27T20:05:00+00:00",
    }
    assert deb.copy_time(item, "1", now) == datetime(2026, 8, 27, 20, 4, tzinfo=UTC)
    assert deb.copy_time(dict(item, date_superseded=None), "1", now) == datetime(
        2026, 11, 20, 23, 59, tzinfo=UTC
    )
    assert deb.copy_time(dict(item, pocket="Proposed"), "1", now) is None
    assert deb.copy_time(item, "2", now) is None
    old = dict(item, date_published="2022-01-01T00:00:00", date_superseded="2022-06-01T00:00:00")
    assert deb.copy_time(old, "1", now) is None  # before the copies start
    brief = dict(item, date_superseded="2026-07-23T18:37:00+00:00")
    assert deb.copy_time(brief, "1", now) is None


@needs_gpgv
def test_launchpad_lying_only_leads_nowhere(pinned):
    """Launchpad's answer only picks a date: a copy without the version finds nothing."""
    site = Site()
    old = Lookup("ubuntu", "24.04", "libpam-modules", "1.5.3-5ubuntu5.6", "amd64")
    site.ubuntu(
        pinned,
        f"{SNAP}/20260827T200300Z",
        "noble-updates",
        [("libpam-modules", NOBLE.version, PAM)],
    )
    site.files[next_launchpad_url(old)] = launchpad_answer(
        old.version, "Updates", "2026-07-23T18:36:44+00:00", "2026-08-27T20:04:00+00:00"
    )
    official = ubuntu_verifier(site, ubuntu_snapshot=SNAP, launchpad=LP).package(old)
    assert not official.found
    site.files[next_launchpad_url(old)] = b"<html>not json"
    assert not ubuntu_verifier(site, ubuntu_snapshot=SNAP, launchpad=LP).package(old).found


# === Rocky Linux and AlmaLinux ==========================================================


@needs_gpgv
def test_rocky_header_by_range_request(pinned):
    site = Site()
    site.files[ROCKY_URL + "pam-1.5.1-29.el9.x86_64.rpm"] = make_rpm(pinned)
    official = Verifier(None, fetcher=site).package(ROCKY)
    assert official.found, official.reason
    assert compare(official, RPM_UNIX, sha(UNIX_BYTES), {}) == "matched"
    assert compare(official, RPM_UNIX, sha(TROJAN), {}) == "differs"


@needs_gpgv
def test_a_header_longer_than_the_first_fetch_is_fetched_again(pinned):
    site = Site()
    site.files[ROCKY_URL + "pam-1.5.1-29.el9.x86_64.rpm"] = make_rpm(pinned, pad=300_000)
    official = Verifier(None, fetcher=site).package(ROCKY)
    assert official.found, official.reason
    assert site.asked.count(ROCKY_URL + "pam-1.5.1-29.el9.x86_64.rpm") == 2


@needs_gpgv
def test_vault_minor_named_by_the_release_is_tried_first(pinned):
    site = Site()
    lookup = Lookup("almalinux", "9", "pam", "1.5.1-28.el9_8.1", "x86_64")
    site.files["https://vault.almalinux.org/"] = b'<a href="9.7/"> <a href="9.8/"> <a href="9.9/">'
    url = (
        "https://vault.almalinux.org/9.8/BaseOS/x86_64/os/Packages/pam-1.5.1-28.el9_8.1.x86_64.rpm"
    )
    site.files[url] = make_rpm(pinned, release="28.el9_8.1")
    official = Verifier(None, fetcher=site).package(lookup)
    assert official.found, official.reason
    assert not any("/9.9/" in u for u in site.asked)


@needs_gpgv
def test_rpm_attacks(pinned):
    def check(lookup, data):
        site = Site()
        url = ROCKY_URL + "pam-1.5.1-29.el9.x86_64.rpm"
        site.files[url] = data
        return Verifier(None, fetcher=site).package(lookup)

    # Another version's genuine header served under this name.
    assert "header is for" in check(ROCKY, make_rpm(pinned, release="28.el9")).reason
    # Signed by a key that isn't the vendor's.
    assert "signature" in check(ROCKY, make_rpm(pinned, key="other")).reason
    # A header changed after signing.
    data = bytearray(make_rpm(pinned))
    at = data.index(sha(UNIX_BYTES).encode())
    data[at : at + 4] = b"0000"
    assert "signature" in check(ROCKY, bytes(data)).reason
    # MD5 file digests aren't accepted.
    assert "SHA-256" in check(ROCKY, make_rpm(pinned, algo=1)).reason
    # Truncated, and not an rpm.
    assert not check(ROCKY, make_rpm(pinned)[:200]).found
    assert not check(ROCKY, b"<html>").found
    # A name that would make an odd address.
    odd = Lookup("rocky", "9", "pam/../../x", "1-1", "x86_64")
    assert "odd" in Verifier(None, fetcher=Site()).package(odd).reason


def test_header_parser_refuses_out_of_range_tags():
    bad = (
        b"\x8e\xad\xe8\x01\0\0\0\0"
        + struct.pack(">II", 1, 4)
        + struct.pack(">IIII", rpm.NAME, 6, 100, 1)
        + b"pam\0"
    )
    with pytest.raises(rpm.PackageError):
        rpm.Header(bad, 0).one(rpm.NAME)
    unterminated = (
        b"\x8e\xad\xe8\x01\0\0\0\0"
        + struct.pack(">II", 1, 3)
        + struct.pack(">IIII", rpm.NAME, 6, 0, 1)
        + b"pam"
    )
    with pytest.raises(rpm.PackageError, match="runs past"):
        rpm.Header(unterminated, 0).one(rpm.NAME)


# === The Verifier's own behaviour =======================================================


@needs_gpgv
def test_results_are_cached_and_a_damaged_cache_is_ignored(pinned, tmp_path):
    site = Site()
    site.files[ROCKY_URL + "pam-1.5.1-29.el9.x86_64.rpm"] = make_rpm(pinned)
    first = Verifier(tmp_path, fetcher=site).package(ROCKY)
    assert first.found and not first.cached
    site.files.clear()
    again = Verifier(tmp_path, fetcher=site).package(ROCKY)
    assert again.cached and again.files == first.files
    (entry,) = tmp_path.glob("*.json")
    good = json.loads(entry.read_text())
    entry.write_text(json.dumps(dict(good, files="x")))
    assert not Verifier(tmp_path, fetcher=site).package(ROCKY).found
    entry.write_text(json.dumps(dict(good, signer=pinned.fpr["other"])))
    assert not Verifier(tmp_path, fetcher=site).package(ROCKY).found  # not pinned for Rocky 9
    entry.write_text(json.dumps(good))
    tmp_path.chmod(0o770)  # others could write it: not believed
    try:
        assert not Verifier(tmp_path, fetcher=site).package(ROCKY).found
    finally:
        tmp_path.chmod(0o700)


@needs_gpgv
def test_nothing_is_cached_when_nothing_was_found(pinned, tmp_path):
    Verifier(tmp_path, fetcher=Site()).package(ROCKY)
    assert list(tmp_path.iterdir()) == []


def test_reasons_when_it_cant_check(monkeypatch):
    monkeypatch.setattr(gpg, "gpgv_path", lambda: "/usr/bin/gpgv")
    site = Site()
    site.down = True
    assert "couldn't download" in Verifier(None, fetcher=site).package(ROCKY).reason
    rhel = Lookup("rhel", "9", "pam", "1.5.1-29.el9", "x86_64")
    assert "subscription" in Verifier(None, fetcher=site).package(rhel).reason
    arm = Lookup("ubuntu", "24.04", "libpam-modules", "1", "arm64")
    assert "isn't covered yet" in Verifier(None, fetcher=site).package(arm).reason
    assert (
        "isn't covered"
        in Verifier(None, fetcher=site).package(Lookup("debian", "12", "x", "1", "amd64")).reason
    )
    monkeypatch.setattr(gpg, "gpgv_path", lambda: None)
    assert "gpgv isn't installed" in Verifier(None, fetcher=site).package(ROCKY).reason


def test_compare_needs_a_found_package():
    with pytest.raises(ValueError):
        compare(Official(ROCKY, reason="x"), RPM_UNIX, "", {})


# === Downloads ==========================================================================


class _Handler(BaseHTTPRequestHandler):
    body = b"0123456789" * 1000
    seen: list[dict] = []

    def do_GET(self):  # noqa: N802 - the http.server interface
        type(self).seen.append(dict(self.headers))
        if self.path == "/missing":
            self.send_error(404)
            return
        if self.path == "/broken":
            self.send_error(500)
            return
        self.send_response(200)  # Range is ignored on purpose
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        pass


@pytest.fixture
def web():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_fetcher(web):
    fetcher = HttpFetcher(deadline=10)
    assert fetcher.get(f"{web}/file", 100_000) == _Handler.body
    assert _Handler.seen[-1]["User-Agent"].startswith("compromise-checker/")
    assert fetcher.get(f"{web}/file", 100_000, first=25) == _Handler.body[:25]
    assert _Handler.seen[-1]["Range"] == "bytes=0-24"
    assert fetcher.get(f"{web}/missing", 100) is None
    with pytest.raises(FetchError, match="larger than"):
        fetcher.get(f"{web}/file", 100)
    with pytest.raises(FetchError, match="500"):
        fetcher.get(f"{web}/broken", 100)
    with pytest.raises(FetchError, match="not a web address"):
        fetcher.get("file:///etc/passwd", 100)
    with pytest.raises(FetchError, match="out of time"):
        HttpFetcher(deadline=0).get(f"{web}/file", 100)


# === From the PR #210 reviews ===========================================================


@needs_gpgv
def test_rpm_ghost_files_are_skipped_not_refused(pinned):
    """%ghost files (sssd-client's, say) have no digest: listed, not shipped."""
    site = Site()
    url = ROCKY_URL.replace("/p/", "/s/") + "sssd-client-2.9.9-3.el9.x86_64.rpm"
    pam_sss = "/usr/lib64/security/pam_sss.so"
    site.files[url] = make_rpm(
        pinned,
        name="sssd-client",
        version="2.9.9",
        release="3.el9",
        files={pam_sss: b"sss"},
        ghosts=("/etc/cifs-utils/idmap-plugin",),
    )
    official = Verifier(None, fetcher=site).package(
        Lookup("rocky", "9", "sssd-client", "2.9.9-3.el9", "x86_64")
    )
    assert official.found, official.reason
    assert "/etc/cifs-utils/idmap-plugin" not in official.files
    assert compare(official, pam_sss, sha(b"sss"), {}) == "matched"


@needs_gpgv
def test_rpm_epoch_noarch_and_appstream(pinned):
    site = Site()
    appstream = "https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/s/"
    site.files[appstream + "shadow-utils-4.9-17.el9.noarch.rpm"] = make_rpm(
        pinned, name="shadow-utils", version="4.9", release="17.el9", arch="noarch", epoch=2
    )
    verifier = Verifier(None, fetcher=site)
    good = Lookup("rocky", "9", "shadow-utils", "2:4.9-17.el9", "noarch")
    assert verifier.package(good).found
    wrong_epoch = Lookup("rocky", "9", "shadow-utils", "1:4.9-17.el9", "noarch")
    assert "header is for" in verifier.package(wrong_epoch).reason
    no_epoch = Lookup("rocky", "9", "shadow-utils", "4.9-17.el9", "noarch")
    assert "header is for" in verifier.package(no_epoch).reason


def test_rpm_with_no_files_needs_no_digest_algorithm():
    empty = header([(rpm.NAME, 6, strs("filesystem-meta"), 1)])
    assert rpm.header_files(rpm.Header(empty, 0)) == {}


def test_a_mirror_setting_changes_addresses_never_keys():
    chosen = rpm.Rpm(Site(), {"rocky": {"keys": {"9": ("almalinux-9",)}, "current": "https://m/"}})
    assert chosen.systems["rocky"]["keys"] == rpm.SYSTEMS["rocky"]["keys"]
    assert chosen.systems["rocky"]["current"] == "https://m/"


@needs_gpgv
def test_ubuntu_all_arch_universe_and_by_hash(pinned):
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-updates", [("other", "1", {"/x": b"x"})])
    site.ubuntu(
        pinned, ARCHIVE, "noble", [("libpam-runtime", "1.5.3-5ubuntu5", {"/usr/x": b"r"}, "all")]
    )
    lookup = Lookup("ubuntu", "24.04", "libpam-runtime", "1.5.3-5ubuntu5", "all")
    official = ubuntu_verifier(site).package(lookup)
    assert official.found, official.reason
    # universe, only after main everywhere
    site2 = Site()
    site2.ubuntu(
        pinned,
        ARCHIVE,
        "noble-security",
        [("libpam-yubico", "2.27", {"/y": b"y"})],
        component="universe",
    )
    official = ubuntu_verifier(site2).package(
        Lookup("ubuntu", "24.04", "libpam-yubico", "2.27", "amd64")
    )
    assert official.found, official.reason
    asked = [u for u in site2.asked if u.endswith("InRelease")]
    assert len(asked) == 3  # each suite's list fetched once, for both components
    # the by-hash name is tried first
    digest = sha(site.files[f"{ARCHIVE}/dists/noble/main/binary-amd64/Packages.xz"])
    by_hash = f"{ARCHIVE}/dists/noble/main/binary-amd64/by-hash/SHA256/{digest}"
    assert by_hash in site.asked


@needs_gpgv
def test_a_list_that_fails_is_skipped_and_named_in_the_reason(pinned):
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-security", [("other", "1", {"/x": b"x"})], key="other")
    site.ubuntu(pinned, ARCHIVE, "noble-updates", [("libpam-modules", NOBLE.version, PAM)])
    assert ubuntu_verifier(site).package(NOBLE).found
    del site.files[f"{ARCHIVE}/dists/noble-updates/InRelease"]
    official = ubuntu_verifier(site).package(NOBLE)
    assert not official.found and "noble-security/InRelease" in official.reason


def test_deb_hardlinks_gzip_and_trailing_data():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        info = tarfile.TarInfo("./usr/a")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"a"))
        link = tarfile.TarInfo("./usr/b")
        link.type, link.linkname = tarfile.LNKTYPE, "./usr/a"
        tar.addfile(link)
    import gzip

    files = deb.deb_files(
        make_ar({"debian-binary": b"2.0\n", "data.tar.gz": gzip.compress(raw.getvalue())})
    )
    assert files["/usr/b"] == files["/usr/a"] == {"sha256": sha(b"a")}
    twice = zstd.compress(raw.getvalue()) + zstd.compress(b"more")
    with pytest.raises(deb.PackageError, match="more after its end"):
        deb.decompress(twice, "data.tar.zst", 10**6)


@needs_gpgv
def test_an_oversized_deb_is_refused_before_download(pinned, monkeypatch):
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-security", [("libpam-modules", NOBLE.version, PAM)])
    monkeypatch.setattr(deb, "MAX_DEB", 10)
    official = ubuntu_verifier(site).package(NOBLE)
    assert "larger than the limit" in official.reason
    assert not any(u.endswith(".deb") for u in site.asked)


def test_package_never_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(gpg, "gpgv_path", lambda: "/usr/bin/gpgv")
    verifier = Verifier(None, fetcher=Site())

    def boom(*args):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(verifier.rpm, "files", boom)
    assert "couldn't check it: RuntimeError" in verifier.package(ROCKY).reason
    # Launchpad's odd answers are only hints that lead nowhere
    item = {
        "binary_package_version": "1",
        "pocket": "Updates",
        "date_published": "0001-01-01T00:00:00",
        "date_superseded": "0001-01-01T00:00:00",
    }
    assert deb.copy_time(item, "1", datetime(2026, 1, 1, tzinfo=UTC)) is None
    site = Site()
    site.files[next_launchpad_url(Lookup("ubuntu", "24.04", "p", "1", "amd64"))] = (
        b"[" * 100_000 + b"]" * 100_000
    )
    found = Ubuntu_copies(site)
    assert found == []
    # gpgv that can't be run
    monkeypatch.setattr(gpg, "gpgv_path", lambda: str(tmp_path / "no-gpgv"))
    with pytest.raises(gpg.SignatureError, match="couldn't be run"):
        gpg.verify_detached(b"x", b"y", ("rocky-9",))
    # a cache folder that can't be read
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o700)
    (locked / "x").write_text("x")
    locked.chmod(0)
    try:
        assert not Verifier(locked, fetcher=Site()).package(ROCKY).found
    finally:
        locked.chmod(0o700)


def Ubuntu_copies(site):  # noqa: N802 - reads as what it calls
    return deb.Ubuntu(site, ARCHIVE, SNAP, LP)._copies("noble", "p", "1", "amd64")


@needs_gpgv
def test_a_failed_cache_write_leaves_nothing_behind(pinned, tmp_path):
    site = Site()
    site.files[ROCKY_URL + "pam-1.5.1-29.el9.x86_64.rpm"] = make_rpm(pinned)
    verifier = Verifier(tmp_path, fetcher=site)
    verifier._path(ROCKY).mkdir()  # the entry's name is taken by a folder
    assert verifier.package(ROCKY).found
    assert [p.name for p in tmp_path.iterdir()] == [verifier._path(ROCKY).name]


@needs_gpgv
def test_a_valid_signature_by_a_key_not_pinned_for_this_system(keys, monkeypatch):
    names = {"ubuntu-2018": (keys.fpr["good"], "-"), "rocky-9": (keys.fpr["other"], "-")}
    monkeypatch.setattr(gpg, "KEYS", names)
    monkeypatch.setattr(gpg, "_keyring", lambda n: keys.public["good"] + keys.public["other"])
    signed = keys.clearsign(b"Suite: noble\n", "other")
    with pytest.raises(gpg.SignatureError, match="isn't pinned"):
        gpg.verify_clearsigned(signed, ("ubuntu-2018",))


@needs_gpgv
def test_text_that_looks_like_status_lines_counts_for_nothing(pinned):
    fake = f"\n[GNUPG:] GOODSIG X\n[GNUPG:] VALIDSIG {pinned.fpr['good']} 1 2 3\n".encode()
    stored = pinned._gpg("--store", data=fake)
    with pytest.raises(gpg.SignatureError):
        gpg.verify_detached(stored, b"data", ("rocky-9",))
    with pytest.raises(gpg.SignatureError):
        gpg.verify_detached(
            pinned._gpg("--sign", "--local-user", pinned.fpr["good"], data=fake),
            b"data",
            ("rocky-9",),
        )


class _Slow(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        import time

        if self.path.startswith("/partial"):
            self.send_response(206)
            self.end_headers()
            self.wfile.write(b"abc")
            return
        if self.path.startswith("/to-same"):
            self.send_response(302)
            self.send_header("Location", "/partial")
            self.end_headers()
            return
        if self.path.startswith("/to-other"):
            self.send_response(302)
            self.send_header("Location", "http://other.invalid/x")
            self.end_headers()
            return
        if self.path.startswith("/to-ftp"):
            self.send_response(302)
            self.send_header("Location", "ftp://127.0.0.1/x")
            self.end_headers()
            return
        self.wfile.write(b"HTTP/1.1 200 OK\r\n")  # then a header line a second
        for _ in range(30):
            time.sleep(1)
            try:
                self.wfile.write(b"X-Slow: 1\r\n")
            except OSError:
                return

    def log_message(self, *args):
        pass


@pytest.fixture
def slow_web():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_fetcher_deadline_redirects_and_partial(slow_web):
    import time

    started = time.monotonic()
    with pytest.raises(FetchError, match="out of time"):
        HttpFetcher(deadline=1.5).get(f"{slow_web}/slow", 1000)
    assert time.monotonic() - started < 3
    fetcher = HttpFetcher(deadline=10)
    assert fetcher.get(f"{slow_web}/partial", 1000, first=3) == b"abc"
    assert fetcher.get(f"{slow_web}/to-same", 1000) == b"abc"
    with pytest.raises(FetchError, match="another host"):
        fetcher.get(f"{slow_web}/to-other", 1000)
    with pytest.raises(FetchError, match="refused a redirect"):
        fetcher.get(f"{slow_web}/to-ftp", 1000)


@needs_gpgv
def test_an_ubuntu_pro_esm_version_says_so_without_searching():
    site = Site()
    esm = Lookup("ubuntu", "22.04", "libpam-modules", "1.4.0-11ubuntu2.8+esm1", "amd64")
    official = ubuntu_verifier(site).package(esm)
    assert "Ubuntu Pro (ESM)" in official.reason
    assert site.asked == []


# === From PR #213's reviews: the signed lists kept on disk, the clock, the vaults ==========


@needs_gpgv
def test_signed_lists_are_kept_only_once_they_check_out(pinned, tmp_path):
    site = Site()
    site.ubuntu(pinned, ARCHIVE, "noble-security", [("libpam-modules", NOBLE.version, PAM)])
    url = f"{ARCHIVE}/dists/noble-security/InRelease"
    genuine = site.files[url]
    site.files[url] = b"<html>captive portal</html>"
    lists = tmp_path / "lists"
    first = Verifier(None, fetcher=site, ubuntu_archive=ARCHIVE, ubuntu_snapshot=None,
                     launchpad=None, lists_dir=lists).package(NOBLE)  # fmt: skip
    assert not first.found
    assert not any(p.name.startswith("inrelease-") for p in lists.glob("*"))  # not kept
    site.files[url] = genuine
    second = Verifier(None, fetcher=site, ubuntu_archive=ARCHIVE, ubuntu_snapshot=None,
                      launchpad=None, lists_dir=lists).package(NOBLE)  # fmt: skip
    assert second.found
    kept = [p for p in lists.glob("inrelease-*")]
    assert len(kept) == 1 and kept[0].read_bytes() == genuine
    # Kept: the next run reads the list (and its index) from disk, checked again.
    site.asked.clear()
    third = Verifier(None, fetcher=site, ubuntu_archive=ARCHIVE, ubuntu_snapshot=None,
                     launchpad=None, lists_dir=lists).package(NOBLE)  # fmt: skip
    assert third.found
    assert not any(u.endswith(("InRelease", "Packages.xz")) or "by-hash" in u for u in site.asked)
    # A kept copy that no longer checks out is dropped and fetched again, once.
    kept[0].write_bytes(b"damaged")
    site.asked.clear()
    fourth = Verifier(None, fetcher=site, ubuntu_archive=ARCHIVE, ubuntu_snapshot=None,
                      launchpad=None, lists_dir=lists).package(NOBLE)  # fmt: skip
    assert fourth.found and site.asked.count(url) == 1
    assert kept[0].read_bytes() == genuine


def test_a_kept_list_is_never_read_through_a_link(tmp_path):
    lists = tmp_path / "lists"
    lists.mkdir()
    (tmp_path / "elsewhere").write_bytes(b"x")
    (lists / "inrelease-x").symlink_to(tmp_path / "elsewhere")
    ubuntu = deb.Ubuntu(Site(), ARCHIVE, SNAP, None, lists_dir=lists)
    assert ubuntu._kept("inrelease-x", None, 100) is None
    (lists / "big").write_bytes(b"x" * 200)
    assert ubuntu._kept("big", None, 100) is None


def test_the_clock_starts_at_the_first_download(web):
    import time

    fetcher = HttpFetcher(deadline=1.0)
    time.sleep(1.2)  # parsing a big bundle, say
    assert fetcher.get(f"{web}/file", 100_000) == _Handler.body


@needs_gpgv
def test_vaults_can_be_left_out(pinned):
    site = Site()
    lookup = Lookup("almalinux", "9", "pam", "1.5.1-28.el9_8.1", "x86_64")
    site.files["https://vault.almalinux.org/"] = b'<a href="9.8/">'
    url = (
        "https://vault.almalinux.org/9.8/BaseOS/x86_64/os/Packages/pam-1.5.1-28.el9_8.1.x86_64.rpm"
    )
    site.files[url] = make_rpm(pinned, release="28.el9_8.1")
    assert not Verifier(None, fetcher=site, vaults=False).package(lookup).found
    assert not any("vault" in u for u in site.asked)
