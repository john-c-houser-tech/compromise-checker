"""Snapshots and baselines (PR 1.6b): a host's state from a bundle, what
changed between two, and the baseline later ones are compared with."""

import base64
import gzip
import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pyrage
import pytest
from pyrage import x25519

from checker import cli
from checker.analysis import load_snapshot, parse_bundle, store_parsed
from checker.baseline import accept, changes, current_baseline
from checker.bundle import walk_bundle
from checker.evidence import (
    EvidenceError,
    open_text,
)
from checker.snapshot import (
    FULL,
    SnapshotBuilder,
    compare,
    firewall_json_lines,
    firewall_lines,
    firewall_text_is_odd,
    nft_json_odd_strings,
    sshd_lines,
    sudoers_lines,
)

START = datetime(2027, 1, 2, 12, 0, tzinfo=UTC)
ALL_MODULES = sorted(FULL)  # a full collection


def stream(records):
    return gzip.compress(b"".join(json.dumps(r, default=str).encode() + b"\n" for r in records))


def text_source(source_id, module, name, text, cut=False):
    data = text.encode()
    out = [
        {
            "type": "source_start",
            "source_id": source_id,
            "module": module,
            "kind": "file",
            "name": name,
            "meta": {"size": len(data), "mode": "0440", "uid": 0, "gid": 0, "mtime": "x"},
        },
        {
            "type": "chunk",
            "source_id": source_id,
            "seq": 0,
            "encoding": "base64",
            "data": base64.b64encode(data).decode(),
        },
    ]
    if not cut:
        out.append(
            {
                "type": "source_end",
                "source_id": source_id,
                "chunks": 1,
                "bytes": len(data),
                "truncated": False,
            }
        )
    return out


def rec(module, name, /, **data):
    return {"type": "record", "module": module, "name": name, "data": data}


def host_records(
    *,
    accounts=(("root", 0), ("jch", 1000)),
    sudoers="root ALL=(ALL) ALL\n",
    keys=(("jch", "SHA256:jchkey"),),
    listening=(("tcp", ["0.0.0.0", 22], "listen", 700),),
    extra=(),
    statuses=None,
    planned=ALL_MODULES,
    trailer=True,
    masking=6,
    site_php=True,
):
    records = [
        {
            "type": "manifest",
            "protocol": 1,
            "collector_version": "t",
            "run_id": "r",
            "started_at": START.isoformat(),
            "host": {
                "hostname": "web01",
                "os_id": "ubuntu",
                "os_version_id": "24.04",
                "os_pretty_name": "Ubuntu",
                "kernel": "6.8",
                "machine": "x86_64",
                "boot_id": None,
            },
            "python": {"version": "3.12", "executable": "/usr/bin/python3"},
            "effective_uid": 0,
            "settings": {},
            "modules_planned": list(planned),
            "masking_version": masking,
        },
        rec("host_facts", "os_release", ID="ubuntu", VERSION_ID="24.04"),
        rec("host_facts", "uname", release="6.8.0", machine="x86_64"),
        rec("host_facts", "kernel_taint", value=0),
    ]
    for name, uid in accounts:
        records.append(
            rec(
                "accounts",
                "account",
                name=name,
                uid=uid,
                gid=uid,
                home=f"/home/{name}",
                shell="/bin/bash",
                password="shadowed",
                line=1,
            )
        )
        records.append(rec("accounts", "password_status", name=name, line=1, status="set"))
    records.append(rec("accounts", "group", name="sudo", gid=27, members=["jch"], line=1))
    records += text_source(1, "sudoers", "/etc/sudoers", sudoers)
    records += text_source(
        2,
        "ssh",
        "/etc/ssh/sshd_config",
        "# comment\nPermitRootLogin no\nMatch User backup\n  PasswordAuthentication yes\n",
    )
    for account, fingerprint in keys:
        records.append(
            rec(
                "ssh",
                "authorized_key",
                account=account,
                path=f"/home/{account}/.ssh/authorized_keys",
                line=1,
                type="ssh-ed25519",
                fingerprint=fingerprint,
            )
        )
    records.append(
        rec("kernel_modules", "kernel_module", name="ext4", size=1, taint="", used_by=[])
    )
    records.append(rec("processes", "process", pid=700, comm="sshd"))
    records.append(rec("processes", "process", pid=800, comm="nc"))
    for protocol, local, state, pid in listening:
        records.append(
            rec(
                "processes",
                "socket",
                protocol=protocol,
                netns="host",
                local=local,
                remote=["0.0.0.0", 0],
                state=state,
                uid=0,
                inode="1",
                pids=[pid],
            )
        )
    records.append(
        rec(
            "processes",
            "socket",
            protocol="tcp",
            netns="host",
            local=["10.0.0.5", 22],
            remote=["198.51.100.1", 5000],
            state="ESTABLISHED",
            uid=0,
            inode="2",
            pids=[700],
        )
    )
    records += list(extra)
    if "unusual_files" in planned and site_php:
        # Every web root's .user.ini and .htaccess read (plan 4.4c).
        records.append(rec("unusual_files", "site_php", roots=4))
    if trailer:
        records.append(
            {
                "type": "trailer",
                "finished_at": START.isoformat(),
                "duration_seconds": 1,
                "status": "complete",
                "counts": {
                    "records": sum(r["type"] == "record" for r in records),
                    "sources": sum(r["type"] == "source_start" for r in records),
                    "chunks": sum(r["type"] == "chunk" for r in records),
                    "errors": sum(r["type"] == "error" for r in records),
                },
                "modules": {
                    m: {"status": (statuses or {}).get(m, "ok"), "seconds": 0} for m in planned
                },
            }
        )
    return records


def snapshot_of_records(records, tmp_path):
    identity = x25519.Identity.generate()
    path = tmp_path / "b.age"
    path.write_bytes(pyrage.encrypt(stream(records), [identity.to_public()]))
    builder = SnapshotBuilder()
    walk_bundle(path, identity, builder)
    return builder.finish()


# --- Reading text -----------------------------------------------------------------------


def test_sudoers_lines():
    text = [
        "# a comment",
        "",
        "Defaults   env_reset",
        "#includedir /etc/sudoers.d",
        "jch ALL=(ALL) \\",
        "    NOPASSWD: ALL",
    ]
    assert sudoers_lines(text) == [
        "Defaults env_reset",
        "#includedir /etc/sudoers.d",
        "jch ALL=(ALL) NOPASSWD: ALL",
    ]


def test_sshd_lines_keep_their_match_block():
    lines = ["Port 22", "Match User backup", " PasswordAuthentication=yes", "Match all", "X11 no"]
    assert sshd_lines(lines) == [
        ("", "port", "22"),
        ("User backup", "match", "User backup"),
        ("User backup", "passwordauthentication", "yes"),
        ("", "match", "all"),
        ("", "x11", "no"),
    ]


# --- One snapshot -----------------------------------------------------------------------------


def test_a_snapshot_holds_the_host_state(tmp_path):
    snap = snapshot_of_records(host_records(), tmp_path)
    s = snap.sections
    assert s["accounts"].items["jch"]["uid"] == 1000
    assert s["accounts"].items["jch"]["shadow_status"] == "set"
    assert s["groups"].items["sudo"] == {"gid": 27, "members": ["jch"]}
    assert "/etc/sudoers: root ALL=(ALL) ALL" in s["sudo_rules"].items
    assert len(s["sudo_files"].items["/etc/sudoers"]["content_sha256"]) == 64
    assert "/etc/ssh/sshd_config [Match User backup]: passwordauthentication yes" in (
        s["sshd_config"].items
    )
    [key] = s["authorized_keys"].items.values()
    assert key["fingerprint"] == "SHA256:jchkey" and "line" not in key
    # Listening sockets only, with their programs.
    assert s["listeners"].items == {
        "tcp 0.0.0.0:22 netns=host": {"uids": [0], "programs": ["sshd"], "sockets": 1}
    }
    assert s["host"].items["os"] == {"id": "ubuntu", "version_id": "24.04"}
    assert all(section.complete for section in s.values())
    assert snap.meta["masking_version"] == 6


def test_password_status_before_its_account_still_merges(tmp_path):
    records = host_records(accounts=())
    records.insert(-1, rec("accounts", "password_status", name="late", line=1, status="locked"))
    records.insert(
        -1, rec("accounts", "account", name="late", uid=5, gid=5, home="/", shell="/x", line=1)
    )
    snap = snapshot_of_records(records, tmp_path)
    assert snap.sections["accounts"].items["late"]["shadow_status"] == "locked"


def test_gaps_mark_only_the_sections_they_touch(tmp_path):
    shadow = rec("accounts", "unreadable_file", path="/etc/shadow", reason="denied")
    snap = snapshot_of_records(host_records(extra=[shadow]), tmp_path)
    assert not snap.sections["accounts"].complete
    assert snap.sections["accounts"].gaps == ["unreadable_file: /etc/shadow"]
    assert snap.sections["groups"].complete


def test_a_failed_or_missing_module_leaves_its_sections_incomplete(tmp_path):
    snap = snapshot_of_records(host_records(statuses={"ssh": "timeout"}), tmp_path)
    assert not snap.sections["authorized_keys"].complete
    assert snap.sections["authorized_keys"].gaps == ["ssh: timeout"]
    assert snap.sections["accounts"].complete
    # Not collected at all: no section, so nothing to compare.
    snap = snapshot_of_records(host_records(planned=["host_facts", "accounts"]), tmp_path)
    assert "authorized_keys" not in snap.sections
    # No trailer: every section is in doubt.
    snap = snapshot_of_records(host_records(trailer=False), tmp_path)
    assert not any(s.complete for s in snap.sections.values())


def test_a_file_cut_off_is_a_gap(tmp_path):
    records = host_records()[:-1] + text_source(9, "sudoers", "/etc/sudoers.d/x", "a b\n", cut=True)
    snap = snapshot_of_records(records, tmp_path)
    assert snap.sections["sudo_files"].items["/etc/sudoers.d/x"]["content_cut"]
    assert not snap.sections["sudo_rules"].complete


# --- Comparing ------------------------------------------------------------------------------


def test_compare_reports_added_removed_and_changed(tmp_path):
    old = snapshot_of_records(host_records(), tmp_path)
    new = snapshot_of_records(
        host_records(
            accounts=(("root", 0), ("jch", 1000), ("backdoor", 0)),
            sudoers="root ALL=(ALL) ALL\nbackdoor ALL=(ALL) NOPASSWD: ALL\n",
            keys=(("jch", "SHA256:jchkey"), ("root", "SHA256:newkey")),
            listening=(
                ("tcp", ["0.0.0.0", 22], "listen", 700),
                ("tcp", ["0.0.0.0", 4444], "listen", 800),
            ),
        ),
        tmp_path,
    )
    diff = compare(old, new)
    assert list(diff["accounts"]["added"]) == ["backdoor"]
    assert list(diff["sudo_rules"]["added"]) == ["/etc/sudoers: backdoor ALL=(ALL) NOPASSWD: ALL"]
    assert "content_sha256" in diff["sudo_files"]["changed"]["/etc/sudoers"]
    assert [k.split()[1] for k in diff["authorized_keys"]["added"]] == ["SHA256:newkey"]
    assert list(diff["listeners"]["added"]) == ["tcp 0.0.0.0:4444 netns=host"]
    assert all(d["comparable"] for d in diff.values())
    assert "host" not in diff  # unchanged sections are left out
    assert compare(new, old)["accounts"]["removed"] == {
        "backdoor": diff["accounts"]["added"]["backdoor"]
    }


def test_an_incomplete_side_is_not_comparable(tmp_path):
    old = snapshot_of_records(host_records(), tmp_path)
    new = snapshot_of_records(host_records(keys=(), statuses={"ssh": "error"}), tmp_path)
    diff = compare(old, new)["authorized_keys"]
    assert list(diff["removed"]) and not diff["comparable"]
    assert diff["notes"] == ["later incomplete: ssh: error"]


def test_a_new_masking_version_is_noted(tmp_path):
    old = snapshot_of_records(host_records(masking=5), tmp_path)
    new = snapshot_of_records(host_records(masking=6, sudoers="root ALL=(ALL) ALL\n#x\n"), tmp_path)
    notes = compare(old, new)["sudo_files"]["notes"]
    assert notes == ["masking changed between the two; text may differ without a change"]


# --- Stored, and baselines ---------------------------------------------------------------------


def add_bundle(home, name, minutes, records, status="complete", host="web01", summary=None):
    base, store, _, config = home
    keys = [x25519.Recipient.from_str(r) for r in config.recipients]
    plain = stream(records)
    cipher = pyrage.encrypt(plain, keys)
    path = base / f"{name}.age"
    path.write_bytes(cipher)
    store.record_bundle(
        {
            "id": name,
            "host": host,
            "run_id": name,
            "path": str(path),
            "started_at": (START + timedelta(minutes=minutes)).isoformat(),
            "ended_at": (START + timedelta(minutes=minutes)).isoformat(),
            "status": status,
            "collector_version": "t",
            "collector_sha256": "x",
            "plaintext_sha256": hashlib.sha256(plain).hexdigest(),
            "plaintext_bytes": len(plain),
            "ciphertext_sha256": hashlib.sha256(cipher).hexdigest(),
            "ciphertext_bytes": len(cipher),
            "recipients": json.dumps(config.recipients),
            "session": None,
            "summary": summary,
            "problem": None,
        }
    )


def test_the_snapshot_is_stored_encrypted(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    row = store.bundle("b1")
    store_parsed(store, row, config.recipients, parse_bundle(row, identity))
    derived = store.derived("b1", "snapshot")
    assert b"jchkey" not in open(derived["path"], "rb").read()
    assert load_snapshot(store, row, identity).sections["accounts"].items["jch"]["uid"] == 1000
    detail = json.loads(store.custody_of("b1")[-1]["detail"])
    assert detail["snapshot_items"] == derived["items"] > 0


def test_the_first_analysis_becomes_the_baseline(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    found = changes(store, "web01", identity, config.recipients)
    assert found.first and found.baseline_id == "b1" and found.comparisons == []
    assert found.baseline_set_now
    assert current_baseline(store, "web01")["how"] == "first"
    assert [r["action"] for r in store.custody_of("b1")][-1] == "baseline"


def test_later_bundles_compare_with_the_previous_and_the_baseline(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("tmp", 2000))))
    add_bundle(home, "b3", 20, host_records(accounts=(("root", 0), ("jch", 1000), ("tmp", 2000))))
    add_bundle(home, "broken", 25, [], status="broken")  # never compared with
    found = changes(store, "web01", identity, config.recipients)
    assert found.bundle_id == "b3" and not found.first
    assert [(c.label, c.bundle_id) for c in found.comparisons] == [
        ("previous", "b2"),
        ("baseline", "b1"),
    ]
    assert found.comparisons[0].differences == {}  # nothing changed since b2
    assert list(found.comparisons[1].differences["accounts"]["added"]) == ["tmp"]


def test_accepting_moves_the_baseline_with_who_and_why(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("tmp", 2000))))
    changes(store, "web01", identity, config.recipients)
    _, notes = accept(
        store, "web01", "Planned: tmp account for the migration", identity, config.recipients
    )
    assert notes == []
    rows = store.baselines("web01")
    assert [(r["how"], r["bundle_id"]) for r in rows] == [("first", "b1"), ("accepted", "b2")]
    assert b"migration" not in rows[-1]["reason"]  # encrypted
    assert open_text(rows[-1]["reason"], identity) == "Planned: tmp account for the migration"
    add_bundle(home, "b3", 20, host_records(accounts=(("root", 0), ("jch", 1000), ("tmp", 2000))))
    found = changes(store, "web01", identity, config.recipients)
    # The baseline is now the previous bundle too: one comparison, no change.
    assert [(c.label, c.bundle_id, c.differences) for c in found.comparisons] == [
        ("previous", "b2", {})
    ]


def test_accepting_needs_a_reason_and_the_hosts_own_usable_bundle(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "other", 0, host_records(), host="db01")
    add_bundle(home, "bad", 5, [], status="broken")
    with pytest.raises(EvidenceError, match="reason"):
        accept(store, "web01", "  ", identity, config.recipients)
    with pytest.raises(EvidenceError, match="from db01"):
        accept(store, "web01", "x", identity, config.recipients, bundle_id="other")
    with pytest.raises(EvidenceError, match="broken"):
        accept(store, "web01", "x", identity, config.recipients, bundle_id="bad")
    with pytest.raises(EvidenceError, match="no usable bundle"):
        changes(store, "nowhere", identity, config.recipients)


def test_baselines_are_append_only(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    changes(store, "web01", identity, config.recipients)
    for statement in ("UPDATE baselines SET how = 'x'", "DELETE FROM baselines"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"), store._db:
            store._db.execute(statement)


def test_cli_changes_and_baseline(home, capsys):
    add_bundle(home, "b1", 0, host_records())
    assert cli.main(["changes", "web01"]) == 0
    assert "set just now" in capsys.readouterr().out
    add_bundle(home, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("evil", 0))))
    assert cli.main(["changes", "web01"]) == 0
    out = capsys.readouterr().out
    assert "Since the previous bundle, b1:" in out and "+ evil  uid=0" in out
    assert cli.main(["baseline", "accept", "web01", "--reason", "known"]) == 0
    assert "baseline is now b2" in capsys.readouterr().out
    assert cli.main(["baseline", "show", "web01"]) == 0
    out = capsys.readouterr().out
    assert "first" in out and "accepted" in out and "— known" in out


# --- Review findings ----------------------------------------------------------------------


def test_the_collectors_own_socket_states_and_packet_sockets(tmp_path):
    packet = [
        rec("processes", "process", pid=900, comm="implant"),
        rec("processes", "process", pid=901, comm="dhclient"),
    ]
    for pid, ethertype in ((900, "0800"), (901, "0003")):
        packet.append(
            rec(
                "processes",
                "socket",
                protocol="packet",
                netns="host",
                type="3",
                ethertype=ethertype,
                interface="2",
                uid=0,
                inode=str(pid),
                pids=[pid],
            )
        )
    # Two listeners on one port (SO_REUSEPORT): one item with both programs.
    listening = (("tcp", ["0.0.0.0", 22], "listen", 700), ("tcp", ["0.0.0.0", 22], "listen", 800))
    snap = snapshot_of_records(host_records(listening=listening, extra=packet), tmp_path)
    items = snap.sections["listeners"].items
    assert items["tcp 0.0.0.0:22 netns=host"]["programs"] == ["nc", "sshd"]
    assert items["tcp 0.0.0.0:22 netns=host"]["sockets"] == 2
    assert items["packet type=3 ethertype=0800 interface=2 netns=host"]["programs"] == ["implant"]
    assert len(items) == 3


def test_privileged_files_elsewhere_web_files_and_unowned_executables(tmp_path):
    extra = [
        rec("unusual_files", "privileged_file", path="/home/eve/.x/sh", setuid=True, mode="4755"),
        rec("unusual_files", "web_file", path="/var/www/html/up.php", size=10),
        rec("system_files", "unowned_executable", path="/usr/lib/libz.so.9", size=10),
    ]
    snap = snapshot_of_records(host_records(extra=extra), tmp_path)
    assert "/home/eve/.x/sh" in snap.sections["privileged_files"].items
    assert "/var/www/html/up.php" in snap.sections["web_files"].items
    assert "/usr/lib/libz.so.9" in snap.sections["unowned_executables"].items


def test_a_duplicate_name_above_the_real_one_shows(tmp_path):
    old = snapshot_of_records(host_records(), tmp_path)
    # A second jch, UID 0, inserted above the real one: the system uses it.
    records = host_records(accounts=(("root", 0), ("jch", 0), ("jch", 1000)))
    new = snapshot_of_records(records, tmp_path)
    diff = compare(old, new)["accounts"]
    assert diff["changed"]["jch"]["uid"] == [1000, 0]
    assert list(diff["added"]) == ["jch #2"]


def test_sudoers_uid_users_and_comments_ending_in_a_backslash():
    lines = ["# a comment \\", "eve ALL=(ALL) NOPASSWD: ALL", "#1000 ALL=(ALL) ALL # why"]
    assert sudoers_lines(lines) == ["eve ALL=(ALL) NOPASSWD: ALL", "#1000 ALL=(ALL) ALL"]
    assert sudoers_lines(["a ALL=\\", "  /bin/x", "esc \\#kept"]) == [
        "a ALL= /bin/x",
        "esc \\#kept",
    ]


@pytest.mark.parametrize(
    ("record", "section"),
    [
        (
            rec(
                "ssh", "authorized_keys_file", path="/home/jch/.ssh/authorized_keys", truncated=True
            ),
            "authorized_keys",
        ),
        (rec("ssh", "directives_incomplete", path="/etc/ssh/sshd_config", size=2), "sshd_config"),
        (rec("sudoers", "include_dir", path="/etc/sudoers.d", truncated=True), "sudo_rules"),
        (rec("pam", "config_dir", path="/etc/pam.d", entries=2000, truncated=True), "pam"),
        (
            rec(
                "systemd",
                "walk_summary",
                top="/etc/systemd/system",
                truncated=False,
                not_descended={"depth": 0, "other_filesystem": 1, "pruned": 0},
            ),
            "systemd",
        ),
        (
            rec("ssh", "not_examined", account="jch", path="/etc/ssh/keys/jch", reason="hard link"),
            "authorized_keys",
        ),
        (
            rec(
                "system_files",
                "system_files_summary",
                truncated=True,
                truncated_reason="findings",
                dropped={"privileged_file": 3},
            ),
            "privileged_files",
        ),
    ],
)
def test_every_kind_of_gap_marks_its_section(tmp_path, record, section):
    snap = snapshot_of_records(host_records(extra=[record]), tmp_path)
    assert not snap.sections[section].complete, snap.sections[section].gaps


def test_gaps_go_to_the_right_sections(tmp_path):
    homes = rec("ssh", "homes", complete=False)
    key_gap = rec("ssh", "not_examined", account="jch", path="/etc/ssh/keys/jch", reason="x")
    snap = snapshot_of_records(host_records(extra=[homes, key_gap]), tmp_path)
    assert not snap.sections["authorized_keys"].complete
    assert snap.sections["sshd_config"].complete  # a key file under /etc/ssh is still a key file
    snap = snapshot_of_records(
        host_records(extra=[rec("accounts", "homes", complete=False)]), tmp_path
    )
    assert snap.sections["accounts"].complete and snap.sections["groups"].complete
    # Writable places cross into other filesystems by design.
    walk = rec(
        "unusual_files",
        "walk_summary",
        top="/var",
        truncated=False,
        not_descended={"depth": 0, "other_filesystem": 4, "pruned": 3},
    )
    snap = snapshot_of_records(host_records(extra=[walk]), tmp_path)
    assert snap.sections["unusual_files"].complete


def test_a_partial_run_is_not_compared_and_cannot_be_a_baseline(home):
    _, store, identity, config = home
    partial = host_records(planned=["host_facts", "accounts"])
    add_bundle(home, "p0", 0, partial)
    add_bundle(home, "b1", 10, host_records())
    add_bundle(home, "p2", 20, partial)
    found = changes(store, "web01", identity, config.recipients)
    assert found.baseline_id == "b1" and found.baseline_set_now and not found.first
    previous = found.comparisons[0].differences
    assert previous["sudo_rules"]["removed"] == {} and not previous["sudo_rules"]["comparable"]
    with pytest.raises(EvidenceError, match="only some modules"):
        accept(store, "web01", "x", identity, config.recipients, bundle_id="p2")


def test_an_older_bundle_compares_forwards_and_an_older_accept_is_noted(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("new", 5))))
    changes(store, "web01", identity, config.recipients)
    accept(store, "web01", "reviewed", identity, config.recipients, bundle_id="b2")
    found = changes(store, "web01", identity, config.recipients, bundle_id="b1")
    [comparison] = found.comparisons
    assert comparison.newer and list(comparison.differences["accounts"]["added"]) == ["new"]
    _, notes = accept(store, "web01", "back", identity, config.recipients, bundle_id="b1")
    assert notes == ["it is older than the baseline it replaces (b2)"]


def test_masking_note_covers_masked_names_too(tmp_path):
    old = snapshot_of_records(host_records(masking=5), tmp_path)
    new = snapshot_of_records(host_records(masking=6, keys=(("jch", "SHA256:other"),)), tmp_path)
    assert "masking changed" in compare(old, new)["authorized_keys"]["notes"][0]


def test_run_files_ignore_their_boot_time_facts(tmp_path):
    def unit(inode):
        return rec(
            "systemd",
            "file",
            path="/run/systemd/transient/x.service",
            inode=inode,
            mtime=str(inode),
            ctime=str(inode),
            mode="0644",
            uid=0,
            size=5,
        )

    old = snapshot_of_records(host_records(extra=[unit(1)]), tmp_path)
    new = snapshot_of_records(host_records(extra=[unit(2)]), tmp_path)
    assert "systemd" not in compare(old, new)


def test_an_error_in_a_module_marks_all_its_sections(tmp_path):
    error = {"type": "error", "module": "accounts", "message": "boom"}
    snap = snapshot_of_records(host_records(extra=[error]), tmp_path)
    for section in ("accounts", "groups", "shell_history"):
        assert snap.sections[section].gaps == ["error: boom"]


def test_a_listed_file_whose_content_was_refused_is_marked_on_its_item(tmp_path):
    listed = rec("hooks", "file", path="/usr/lib/dnf/x.pyc", inode=5, size=9, mtime="t", uid=0)
    refused = rec("hooks", "unreadable_file", path="/usr/lib/dnf/x.pyc", reason="hard link")
    unlisted = rec("hooks", "unreadable_file", path="/etc/dnf/plugins/y.conf", reason="denied")
    snap = snapshot_of_records(host_records(planned=ALL_MODULES, extra=[refused, listed]), tmp_path)
    hooks = snap.sections["hooks"]
    assert hooks.complete and hooks.items["/usr/lib/dnf/x.pyc"]["content_unread"] == "hard link"
    snap = snapshot_of_records(host_records(extra=[unlisted]), tmp_path)
    assert snap.sections["hooks"].gaps == ["unreadable_file: /etc/dnf/plugins/y.conf"]


# --- PR 2.4a: network --------------------------------------------------------------------


def command_source(source_id, module, argv, text):
    out = text_source(source_id, module, " ".join(argv), text)
    out[0]["kind"] = "command"
    out[0]["meta"] = {"argv": argv}
    return out


def test_network_sections(tmp_path):
    from checker.snapshot import remote_network

    records = host_records(
        extra=[
            rec(
                "network",
                "interface",
                name="eth0",
                flags=0x1103,
                promiscuous=True,
                state="up",
                type=1,
                bridge=False,
                bridge_port=False,
                rx_bytes=1,
                tx_bytes=2,
            ),
            rec("network", "firewall_loaded", nf_tables=True, ip_tables=False, ip6_tables=False),
            *command_source(
                40,
                "network",
                ["/usr/sbin/nft", "list", "ruleset"],
                "table inet filter {\n\tchain input {\n\t\ttcp dport 22 counter packets 9"
                " bytes 99 accept\n\t}\n}\n",
            ),
            *text_source(41, "network", "/etc/hosts", "127.0.0.1 localhost\n"),
        ]
    )
    snapshot = snapshot_of_records(records, tmp_path)
    assert snapshot.sections["interfaces"].items["eth0"]["promiscuous"] is True
    assert "rx_bytes" not in snapshot.sections["interfaces"].items["eth0"]
    assert snapshot.live["interfaces"][0]["tx_bytes"] == 2
    assert (
        "nft: [inet filter / chain input] tcp dport 22 counter accept"
        in snapshot.sections["firewall_rules"].items
    )
    assert "/etc/hosts" in snapshot.sections["network_files"].items
    assert snapshot.live["firewall_loaded"]["nf_tables"] is True
    assert firewall_lines(["# Generated by iptables-save", ":INPUT ACCEPT [12:345]", ""]) == [
        ":INPUT ACCEPT"
    ]
    assert remote_network("203.0.113.77") == "203.0.113.0/24"
    assert remote_network("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert remote_network("::ffff:198.51.100.9") == "198.51.100.0/24"
    assert remote_network("127.0.0.1") is None and remote_network("fe80::1") is None


def test_peers_group_connections_by_program_network_and_port(tmp_path):
    records = host_records(
        extra=[
            rec("processes", "process", pid=10, comm="curl"),
            rec(
                "processes",
                "socket",
                protocol="tcp",
                local=["10.0.0.5", 40001],
                remote=["203.0.113.7", 443],
                state="established",
                pids=[10],
            ),
            rec(
                "processes",
                "socket",
                protocol="tcp",
                local=["10.0.0.5", 40002],
                remote=["203.0.113.9", 443],
                state="established",
                pids=[10],
            ),
            rec(
                "processes",
                "socket",
                protocol="tcp",
                local=["127.0.0.1", 40003],
                remote=["127.0.0.1", 5432],
                state="established",
                pids=[10],
            ),
        ]
    )
    snapshot = snapshot_of_records(records, tmp_path)
    assert snapshot.sections["peers"].items == {"curl 203.0.113.0/24 port 443": {"program": "curl"}}
    assert snapshot.live["peer_connections"] == {"curl 203.0.113.0/24 port 443": 2}


def test_a_firewall_command_that_couldnt_run_is_a_gap(tmp_path):
    records = host_records(
        extra=[rec("network", "command_unavailable", command="nft", reason="not installed")]
    )
    section = snapshot_of_records(records, tmp_path).sections["firewall_rules"]
    assert not section.complete and "nft" in " ".join(section.gaps)


def test_incoming_connections_are_not_peers(tmp_path):
    records = host_records(
        extra=[
            rec("processes", "process", pid=20, comm="nginx"),
            rec(
                "processes",
                "socket",
                protocol="tcp",
                local=["0.0.0.0", 443],
                remote=["0.0.0.0", 0],
                state="listen",
                pids=[20],
            ),
            rec(
                "processes",
                "socket",
                protocol="tcp",
                local=["10.0.0.5", 443],
                remote=["203.0.113.7", 51515],
                state="established",
                pids=[20],
            ),
        ]
    )
    peers = snapshot_of_records(records, tmp_path).sections["peers"].items
    assert not any(k.startswith("nginx") for k in peers)


def test_firewall_lines_keep_their_place_and_drop_what_changes_by_itself():
    from checker.snapshot import firewall_lines

    nft = [
        "table inet filter {",
        "\tset f2b {",
        "\t\telements = { [999 elements, sha256 abcd] }",
        "\t}",
        "\tchain input {",
        '\t\tiifname "eth0" accept',
        "\t\tip saddr 192.0.2.1 accept expires 9m58s",
        "\t\tquota over 10 mbytes used 3 mbytes drop",
        "\t}",
        "\tchain forward {",
        '\t\tiifname "eth0" accept',
        '\t\tiifname "eth0" accept',
        "\t}",
        "}",
    ]
    out = firewall_lines(nft)
    assert '[inet filter / chain input] iifname "eth0" accept' in out
    assert '[inet filter / chain forward] iifname "eth0" accept #2' in out
    assert "[inet filter / set f2b] elements = { [a large set: elements not compared] }" in out
    assert "[inet filter / chain input] ip saddr 192.0.2.1 accept" in out
    assert "[inet filter / chain input] quota over 10 mbytes drop" in out
    ipt = [
        "*filter",
        ":INPUT ACCEPT [1:2]",
        "-A INPUT -j ACCEPT",
        "COMMIT",
        "*nat",
        "-A INPUT -j ACCEPT",
    ]
    out = firewall_lines(ipt)
    assert "[filter / chain INPUT] -A INPUT -j ACCEPT" in out
    assert "[nat / chain INPUT] -A INPUT -j ACCEPT" in out


def test_peers_are_open_owned_tcp_connections_v4_and_v6(tmp_path):
    records = host_records(
        extra=[
            rec("processes", "process", pid=10, comm="curl"),
            rec(
                "processes",
                "socket",
                protocol="udp",
                local=["10.0.0.5", 5353],
                remote=["203.0.113.7", 53],
                state="established",
                pids=[10],
            ),
            rec(
                "processes",
                "socket",
                protocol="tcp",
                local=["10.0.0.5", 40001],
                remote=["203.0.113.8", 443],
                state="time_wait",
                pids=[],
            ),
            rec(
                "processes",
                "socket",
                protocol="tcp6",
                local=["2001:db8::5", 40002],
                remote=["2001:db8:aa:1::9", 443],
                state="established",
                pids=[10],
            ),
            rec(
                "processes",
                "socket",
                protocol="tcp6",
                local=["::", 8443],
                remote=["::", 0],
                state="listen",
                pids=[10],
            ),
            rec(
                "processes",
                "socket",
                protocol="tcp6",
                local=["2001:db8::5", 8443],
                remote=["2001:db8:bb::1", 50000],
                state="established",
                pids=[10],
            ),
        ]
    )
    peers = snapshot_of_records(records, tmp_path).sections["peers"].items
    assert set(peers) == {"curl 2001:db8:aa::/48 port 443"}


def test_veth_interfaces_are_seen_not_compared(tmp_path):
    records = host_records(
        extra=[rec("network", "interface", name="veth1a2b3c", flags=0x1003, promiscuous=False)]
    )
    snapshot = snapshot_of_records(records, tmp_path)
    assert "veth1a2b3c" not in snapshot.sections["interfaces"].items
    assert snapshot.live["interfaces"][0]["name"] == "veth1a2b3c"


def test_a_firewall_failure_leaves_only_the_rules_incomplete(tmp_path):
    records = host_records(
        extra=[
            rec("network", "command_failed", command="nft", reason="exited 1"),
            rec("network", "interface", name="eth0", flags=1, promiscuous=False),
            *text_source(41, "network", "/etc/hosts", "127.0.0.1 localhost\n"),
        ]
    )
    sections = snapshot_of_records(records, tmp_path).sections
    assert not sections["firewall_rules"].complete
    assert sections["interfaces"].complete and sections["network_files"].complete


def test_an_open_connection_no_process_holds_is_not_a_peer(tmp_path):
    records = host_records(
        extra=[
            rec(
                "processes",
                "socket",
                protocol="tcp",
                local=["10.0.0.5", 40001],
                remote=["203.0.113.8", 443],
                state="established",
                pids=[],
            ),
        ]
    )
    assert snapshot_of_records(records, tmp_path).sections["peers"].items == {}


def test_chains_other_software_manages_are_summarised():
    from checker.snapshot import firewall_lines

    nft = [
        "table ip filter {",
        "\tchain DOCKER {",
        "\t\tip daddr 172.17.0.2 tcp dport 80 accept",
        "\t\tip daddr 172.17.0.3 tcp dport 443 accept",
        "\t}",
        "\tchain f2b-sshd {",
        "\t\tip saddr 192.0.2.9 reject",
        "\t}",
        "\tchain INPUT {",
        "\t\ttcp dport 22 accept",
        "\t}",
        "}",
    ]
    out = firewall_lines(nft)
    assert "[ip filter / chain DOCKER] (managed by other software: rules not compared)" in out
    assert not any("172.17.0" in line or "192.0.2.9" in line for line in out)
    assert "[ip filter / chain INPUT] tcp dport 22 accept" in out
    ipt = ["*nat", "-A KUBE-SEP-ABC -s 10.244.1.5/32 -j KUBE-MARK-MASQ", "-A OUTPUT -j ACCEPT"]
    out = firewall_lines(ipt)
    assert "[nat / chain KUBE-SEP-ABC] (managed by other software: rules not compared)" in out


# --- Web servers' folders (PR 2.11) -------------------------------------------------------


def test_web_served_reads_nginx_and_apache_folders():
    from checker.snapshot import web_served

    nginx = [
        "server {",
        "    root /var/www/app/public;  # the front controller",
        "    location /.well-known/ { root /var/www/letsencrypt; }",
        '    location /static/ { alias "/srv/static/"; }',
        "    # root /var/www/old;",
        "    location / { root $site_root; }",
        "    fastcgi_param DOCUMENT_ROOT /nowhere;",
        "}",
    ]
    assert web_served("/etc/nginx/sites-available/app", nginx) == [
        ("root", "/var/www/app/public"),
        ("root", "/var/www/letsencrypt"),
        ("alias", "/srv/static/"),
        ("root", "$site_root"),
    ]
    apache = [
        '    DocumentRoot "/var/www/html"',
        "    Alias /icons/ /usr/share/apache2/icons/",
        '    ScriptAlias /cgi-bin/ "/usr/lib/cgi-bin/"',
        '    Alias /docs "/srv/my docs"',
        "#   DocumentRoot /var/www/old",
    ]
    assert web_served("/etc/apache2/sites-enabled/000-default.conf", apache) == [
        ("documentroot", "/var/www/html"),
        ("alias", "/usr/share/apache2/icons/"),
        ("scriptalias", "/usr/lib/cgi-bin/"),
        ("alias", "/srv/my docs"),
    ]
    # A # inside quotes is part of the path; includes are kept for the check.
    assert web_served(
        "/etc/nginx/sites-available/b", ['root "/srv/a#b"; # old', "include snippets/x.conf;"]
    ) == [("root", "/srv/a#b"), ("include", "snippets/x.conf")]
    assert web_served("/etc/apache2/apache2.conf", ["IncludeOptional sites-enabled/*.conf"]) == [
        ("includeoptional", "sites-enabled/*.conf")
    ]
    # PHP-FPM serves nothing itself.
    assert web_served("/etc/php/8.4/fpm/pool.d/www.conf", ["chdir = /var/www"]) == []


def test_web_served_folders_reach_the_snapshot_and_a_cut_file_leaves_them_incomplete(tmp_path):
    site = "/etc/nginx/sites-available/app"
    records = host_records(
        extra=text_source(90, "web_logs", site, "server { root /var/www/app/public; }\n")
    )
    served = snapshot_of_records(records, tmp_path).sections["web_served"]
    assert served.complete
    assert served.items == {
        f"{site}: root /var/www/app/public": {
            "path": site,
            "directive": "root",
            "folder": "/var/www/app/public",
        }
    }
    # Read only up to the byte limit: the source ends, marked truncated.
    cut = text_source(90, "web_logs", site, "root /x;\n")
    cut[-1]["truncated"] = True
    taken = snapshot_of_records(host_records(extra=cut), tmp_path)
    assert not taken.sections["web_served"].complete
    assert not taken.sections["web_config"].complete


def nft_rules(banned):
    return firewall_lines(
        [
            "table inet f2b-table {",
            "\tset addr-set-sshd {",
            "\t\ttype ipv4_addr",
            f"\t\telements = {{ {banned} }}",
            "\t}",
            "\tset addr6-set-sshd {",
            f"\t\telements = {{ {banned}:: }}",
            "\t}",
            "\tchain f2b-chain {",
            "\t\tip saddr @addr-set-sshd reject",
            "\t}",
            "\tchain hidden {",
            "\t\tip saddr 203.0.113.9 accept",
            "\t}",
            "}",
            "table inet filter {",
            "\tset mine {",
            f"\t\telements = {{ {banned} }}",
            "\t}",
            "}",
        ]
    )


def test_fail2bans_banned_addresses_in_its_own_table_arent_compared():
    first, second = nft_rules("192.0.2.1"), nft_rules("192.0.2.2")
    managed = "(managed by other software: rules not compared)"
    assert f"[inet f2b-table / set addr-set-sshd] {managed}" in first
    assert f"[inet f2b-table / set addr6-set-sshd] {managed}" in first
    # A rule hidden in that table under another name, and a set of one's own, still show.
    assert "[inet f2b-table / chain hidden] ip saddr 203.0.113.9 accept" in first
    assert set(first) - set(second) == {"[inet filter / set mine] elements = { 192.0.2.1 }"}


def test_a_set_a_compared_rule_lets_traffic_in_by_is_compared():
    def rules(address, table="f2b-table", name="addr-set-ok"):
        return firewall_lines(
            [
                f"table inet {table} {{",
                f"\tset {name} {{",
                f"\t\telements = {{ {address} }}",
                "\t}",
                "\tchain in {",
                f"\t\tip saddr @{name} accept",
                "\t}",
                "}",
            ]
        )

    assert "[inet f2b-table / set addr-set-ok] elements = { 192.0.2.1 }" in rules("192.0.2.1")
    # A table merely named like Docker's or Tailscale's: its sets are compared.
    for table in ("docker-allow", "ts-x", "dockerhosts"):
        assert rules("192.0.2.1", table, "ok") != rules("203.0.113.6", table, "ok")


def test_a_block_the_parser_doesnt_know_doesnt_end_the_table():
    out = firewall_lines(
        [
            "table inet t {",
            '\tct helper h { type "ftp" protocol tcp; l3proto ip; }',
            "\tct helper g {",
            '\t\ttype "ftp" protocol tcp',
            "\t}",
            "\tchain f2b-x {",
            "\t\ttcp dport 4444 accept",
            "\t}",
            "}",
        ]
    )
    assert "[inet t / chain f2b-x] (managed by other software: rules not compared)" in out
    assert not any(line.startswith("[chain") for line in out)


@pytest.mark.parametrize("forged", ["set z {", "chain f2b-z {"])
def test_a_newline_in_a_comment_cant_forge_a_block(forged):
    out = firewall_lines(
        [
            "table inet f2b-table {",
            "\tchain input {",
            '\t\ttcp dport 22 accept comment "a',
            forged,
            '";',
            "\t\tip saddr 198.51.100.7 accept;",
            "\t\ttcp dport 4444 accept;",
            "\t}",
            "}",
        ]
    )
    assert any(line.endswith("ip saddr 198.51.100.7 accept;") for line in out)
    assert any(line.endswith("tcp dport 4444 accept;") for line in out)
    assert not any("managed by other software" in line for line in out)


def test_a_comment_ending_in_a_backslash_swallows_nothing():
    fail2ban = [
        "table inet f2b-table {",
        "\tchain f2b-chain {",
        '\t\ttcp dport 2222 accept comment "a\\"',
        "\t}",
        "}",
    ]
    out = firewall_lines([*fail2ban, "table inet zz {", "\tchain input {",
                          "\t\ttcp dport 4444 accept", "\t}", "}"])  # fmt: skip
    assert "[inet zz / chain input] tcp dport 4444 accept" in out


def test_a_line_starting_with_a_hash_after_an_open_quote_hides_nothing():
    out = firewall_lines(
        [
            "table inet t {",
            "\tchain input {",
            '\t\tiifname != "x\\" tcp dport 4444 accept comment "a',
            '#"',
            "\t\ttcp dport 5555 accept",
            "\t}",
            "}",
            "table inet later {",
            "\tchain f2b-c {",
            "\t\ttcp dport 6666 accept",
            "\t}",
            "}",
        ]
    )
    text = "\n".join(out)
    assert '#"' in text and "5555" in text and "6666" in text  # nothing dropped or summarised


def test_only_a_plain_set_name_can_be_summarised():
    out = firewall_lines(["table inet f2b-x {", "\tset addr-set-a/b {",
                          "\t\telements = { 192.0.2.1 }", "\t}", "}"])  # fmt: skip
    assert any("192.0.2.1" in line for line in out)


def test_a_maps_catch_all_isnt_read_as_a_table():
    out = firewall_lines(
        [
            "table inet f2b-x {",
            "\tset addr-set-q {",
            "\t\telements = { 192.0.2.1 }",
            "\t}",
            "\tmap m {",
            "\t\telements = { 1.1.1.1 : accept,",
            "\t\t* : continue }",
            "\t}",
            "\tchain c {",
            "\t\tip saddr @addr-set-q accept",
            "\t}",
            "}",
        ]
    )
    assert "[inet f2b-x / chain c] ip saddr @addr-set-q accept" in out
    assert any("192.0.2.1" in line and "addr-set-q" in line for line in out)


def test_iptables_lines_ending_in_a_brace_open_no_block():
    out = firewall_lines(
        ["*filter", "-A INPUT -i {", "-A INPUT -i {", "-A INPUT -j DROP", "COMMIT"]
    )
    assert "[filter / chain INPUT] -A INPUT -j DROP" in out


def test_multi_line_elements_stay_in_their_set():
    out = firewall_lines(
        [
            "table inet filter {",
            "\tset mine {",
            "\t\telements = { 192.0.2.1,",
            "\t\t192.0.2.2 }",
            "\t}",
            "\tchain c {",
            "\t\taccept",
            "\t}",
            "}",
        ]
    )
    assert "[inet filter / set mine] 192.0.2.2 }" in out
    assert "[inet filter / chain c] accept" in out


def test_only_fail2bans_own_sets_in_its_own_table_are_summarised():
    def out(table, name):
        return firewall_lines([f"table inet {table} {{", f"\tset {name} {{",
                               "\t\telements = { 192.0.2.1 }", "\t}", "}"])  # fmt: skip

    assert not any("192.0.2.1" in line for line in out("f2b-table", "addr-set-sshd"))
    assert any("192.0.2.1" in line for line in out("f2b-table", "other"))
    assert any("192.0.2.1" in line for line in out("filter", "addr-set-sshd"))


def test_a_newline_in_a_table_level_comment_cant_forge_a_block():
    out = firewall_lines(
        [
            "table inet t {",
            '\tcomment "a',
            "chain f2b-z {",
            '";',
            "\tchain input {",
            "\t\ttcp dport 4444 accept;",
            "\t}",
            "}",
        ]
    )
    assert any(line.endswith("tcp dport 4444 accept;") for line in out)
    assert not any("managed by other software" in line for line in out)


# --- nftables as JSON -----------------------------------------------------------------------


def nft_objects(*items):
    return [json.dumps(item, sort_keys=True) for item in items]


F2B_SET = {"set": {"family": "inet", "table": "f2b-table", "name": "addr-set-sshd", "handle": 2,
                   "type": "ipv4_addr", "elem": ["192.0.2.1"]}}  # fmt: skip
F2B_RULE = {"rule": {"family": "inet", "table": "f2b-table", "chain": "f2b-chain",
                     "expr": [{"match": {"right": "@addr-set-sshd"}}]}}  # fmt: skip


def test_json_rules_read_in_the_same_form_as_text():
    out = firewall_json_lines(nft_objects(
        {"metainfo": {"version": "1.1.7"}},
        {"table": {"family": "inet", "name": "filter", "handle": 1}},
        {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1,
                   "hook": "input", "policy": "drop"}},
        {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4,
                  "comment": "web", "expr": [{"accept": None}]}},
    ))  # fmt: skip
    assert out[0] == "[inet filter] {}"
    assert out[1].startswith('[inet filter / chain input] {"hook": "input"')
    assert out[2] == '[inet filter / chain input] {"comment": "web", "expr": [{"accept": null}]}'
    assert not any("1.1.7" in line or "handle" in line for line in out)


def test_counters_and_timers_dont_read_as_changes():
    def rule(packets):
        return firewall_json_lines(nft_objects({"rule": {
            "family": "inet", "table": "t", "chain": "c", "handle": packets,
            "expr": [{"counter": {"packets": packets, "bytes": packets}}, {"accept": None}],
        }}))  # fmt: skip

    assert rule(1) == rule(2)
    big = {"set": {"family": "inet", "table": "t", "name": "b",
                   "elem": {"count": 120, "sha256": "ab"}}}  # fmt: skip
    assert "[a large set: elements not compared]" in firewall_json_lines(nft_objects(big))[0]


def test_a_comment_in_json_cant_forge_anything():
    comment = "a\n}\nchain f2b-x {\ncomment"
    out = firewall_json_lines(nft_objects({"rule": {
        "family": "inet", "table": "v", "chain": "input", "comment": comment,
        "expr": [{"match": {"right": 4444}}, {"accept": None}],
    }}))  # fmt: skip
    assert len(out) == 1 and out[0].startswith("[inet v / chain input] ")
    assert "4444" in out[0] and "managed by other software" not in out[0]


def test_json_fail2bans_set_is_summarised_unless_a_compared_rule_uses_it():
    managed = "(managed by other software: rules not compared)"
    out = firewall_json_lines(nft_objects(F2B_SET, F2B_RULE))
    assert f"[inet f2b-table / set addr-set-sshd] {managed}" in out
    assert f"[inet f2b-table / chain f2b-chain] {managed}" in out
    assert not any("192.0.2.1" in line for line in out)
    uses = [{"match": {"right": "@addr-set-sshd"}}, {"accept": None}]
    accept = {"rule": {"family": "inet", "table": "f2b-table", "chain": "hidden", "expr": uses}}
    out = firewall_json_lines(nft_objects(F2B_SET, accept))
    assert any("192.0.2.1" in line for line in out)
    other = {"set": {"family": "inet", "table": "filter", "name": "addr-set-sshd", "elem": ["x"]}}
    assert '"elem": ["x"]' in firewall_json_lines(nft_objects(other))[0]


def test_a_line_not_json_is_kept_and_compared():
    assert firewall_json_lines(["[MASKED:oversized_line 9 bytes]"]) == [
        "[not read] [MASKED:oversized_line 9 bytes]"
    ]


def test_text_and_json_are_each_compared_with_themselves():
    from checker.snapshot import NFT_JSON_LOST, NFT_JSON_STARTED, Section, Snapshot

    def snap(*keys):
        return Snapshot({}, {"firewall_rules": Section({k: {} for k in keys})}, {})

    # An old baseline, text only: the text is still compared, the JSON waits.
    diff = compare(snap("nft: a"), snap("nft: b", "nft-json: x"))["firewall_rules"]
    assert list(diff["added"]) == ["nft: b"] and list(diff["removed"]) == ["nft: a"]
    assert diff["comparable"] and diff["nft_json"] == NFT_JSON_STARTED
    # JSON lost: said, and not every rule as removed.
    diff = compare(snap("nft: a", "nft-json: x"), snap("nft: a"))["firewall_rules"]
    assert not diff["removed"] and diff["nft_json"] == NFT_JSON_LOST
    # Both on both sides: a change shows on the side that sees it.
    diff = compare(snap("nft: a", "nft-json: x"), snap("nft: a", "nft-json: y"))["firewall_rules"]
    assert list(diff["added"]) == ["nft-json: y"] and "nft_json" not in diff


def test_what_json_drops_the_text_still_shows():
    # iptables-nft's arguments: gone from JSON, in the text as nft translates them.
    def both(target):
        expr = [{"xt": None}]
        rule = {"rule": {"family": "ip", "table": "nat", "chain": "PREROUTING", "expr": expr}}
        text = ["table ip nat {", "\tchain PREROUTING {", f"\t\tdnat to {target}", "\t}", "}"]
        return firewall_json_lines(nft_objects(rule)), firewall_lines(text)

    (json_a, text_a), (json_b, text_b) = both("192.0.2.77:4444"), both("203.0.113.66:22")
    assert json_a == json_b and text_a != text_b


def test_a_dormant_table_shows():
    def table(**more):
        body = {"family": "inet", "name": "filter", "handle": 1, **more}
        return firewall_json_lines(nft_objects({"table": body}))

    assert table() != table(flags=["dormant"])


def test_steady_keeps_a_quotas_limit_and_drops_what_runs_on_its_own():
    def named(kind, **more):
        body = {"family": "inet", "table": "t", "name": "q", **more}
        return firewall_json_lines(nft_objects({kind: body}))

    assert named("quota", bytes=1048576, used=1) != named("quota", bytes=2097152, used=1)
    assert named("quota", bytes=1, used=1) == named("quota", bytes=1, used=9, used_unit="bytes")
    assert named("set", size=5, count=1) == named("set", size=5, count=2)


def test_an_odd_name_is_never_managed():
    expr = [{"accept": None}]
    rule = {"rule": {"family": "inet", "table": "a]b", "chain": "f2b-q", "expr": expr}}
    assert "managed by other software" not in firewall_json_lines(nft_objects(rule))[0]


def test_json_said_to_be_unread_leaves_only_the_text():
    builder = SnapshotBuilder()
    rules = builder.section("firewall_rules").items
    rules["nft: a"], rules["nft-json: b"] = {}, {}
    builder._on_network("nft_json_unread", {"reason": "not JSON"})
    assert list(rules) == ["nft: a"] and builder.live["nft_json_unread"] == "not JSON"


def test_an_odd_chain_name_is_never_managed_either():
    rule = {"rule": {"family": "inet", "table": "t", "chain": "f2b q", "expr": [{"accept": None}]}}
    assert "managed by other software" not in firewall_json_lines(nft_objects(rule))[0]


def test_the_same_chain_twice_in_a_table_is_read_literally():
    forged = [
        "table ip nat {",
        "\tchain DOCKER {",
        '\t\tcounter comment "a"',
        "\t}",
        "\tchain PREROUTING {",
        "\t\ttcp dport 8080 dnat to 10.0.0.5",
        "\t}",
        "\tchain DOCKER {",
        "\tq {",
        '"b"',
        "\t}",
        "\tchain PREROUTING {",
        "\t\ttcp dport 8080 dnat to 6.6.6.6",
        "\t}",
        "\t}",
        "}",
    ]
    assert firewall_text_is_odd(forged)
    out = firewall_lines(forged)
    assert any("6.6.6.6" in line for line in out)
    assert not any("managed by other software" in line for line in out)
    assert not firewall_text_is_odd(["table a b {", "\tchain c {", "\t}", "}",
                                     "table a d {", "\tchain c {", "\t}", "}"])  # fmt: skip


def test_json_shows_an_odd_comment_whatever_the_text_looks_like():
    def rule(comment):
        return nft_objects({"rule": {"family": "ip", "table": "nat", "chain": "DOCKER",
                                     "comment": comment, "expr": []}})  # fmt: skip

    assert nft_json_odd_strings(rule("web")) == 0
    assert nft_json_odd_strings(rule("a\nb")) == 1
    assert nft_json_odd_strings(rule('a"b')) == 1
    assert nft_json_odd_strings(["[MASKED:oversized_line 9 bytes]"]) == 0
    assert nft_json_odd_strings(rule("[MASKED:private_key]")) == 1


def _firewall_sources(builder, text, as_json):
    for source_id, name, lines in (
        (1, "/usr/sbin/nft list ruleset", text),
        (2, "/usr/sbin/nft -j list ruleset", as_json),
    ):
        builder._text[source_id] = (("", hashlib.sha256()), lines)
        start = SimpleNamespace(source_id=source_id, kind="command", name=name, module="network")
        builder.source_end(start, SimpleNamespace(truncated=False))


def test_an_odd_comment_seen_in_json_makes_the_text_literal_and_says_so():
    text = ["table ip nat {", "\tchain DOCKER {", "\t\ttcp dport 8080 return", "\t}", "}"]
    rule = {"family": "ip", "table": "nat", "chain": "x", "comment": "a\nb", "expr": []}
    odd = SnapshotBuilder()
    _firewall_sources(odd, text, nft_objects({"rule": rule}))
    assert odd.live["nft_odd_comments"] == 1
    keys = odd.section("firewall_rules").items
    assert "nft: [ip nat / chain DOCKER] tcp dport 8080 return" in keys
    assert not any("managed" in key for key in keys if key.startswith("nft: "))

    plain = SnapshotBuilder()
    _firewall_sources(plain, text, nft_objects({"rule": {**rule, "comment": "web"}}))
    assert "nft_odd_comments" not in plain.live
    assert any("managed" in key for key in plain.section("firewall_rules").items)


def test_odd_text_alone_is_said_and_nft_json_that_breaks_reading_leaves_the_text():
    builder = SnapshotBuilder()
    _firewall_sources(builder, ["table a b {", '\tchain c { # "', "\t}", "}"], ["{not json"])
    assert builder.live["nft_odd_comments"] == 1
    assert builder.live["nft_json_unread"] == "not what nft gives"
    assert not any(k.startswith("nft-json") for k in builder.section("firewall_rules").items)


def test_an_empty_ruleset_is_neither_json_started_nor_lost():
    from checker.snapshot import Section, Snapshot

    def snap(*keys):
        return Snapshot({}, {"firewall_rules": Section({k: {} for k in keys})}, {})

    flushed = compare(snap("nft-json: x", "nft: y"), snap())["firewall_rules"]
    assert "nft_json" not in flushed and len(flushed["removed"]) == 2
    grown = compare(snap(), snap("nft-json: x", "nft: y"))["firewall_rules"]
    assert "nft_json" not in grown and len(grown["added"]) == 2


def test_a_fixed_big_list_a_compared_rule_uses_is_compared():
    def rules(sha, flags=(), use=True):
        body = {"family": "inet", "table": "t", "name": "ok", "flags": list(flags),
                "elem": {"count": 60, "sha256": sha}}  # fmt: skip
        rule = {"family": "inet", "table": "t", "chain": "c",
                "expr": [{"match": {"right": "@ok"}}, {"accept": None}]}  # fmt: skip
        return firewall_json_lines(nft_objects({"set": body}, *([{"rule": rule}] if use else [])))

    assert rules("aa") != rules("bb")
    assert rules("aa", ["timeout"]) == rules("bb", ["timeout"])
    assert rules("aa", use=False) == rules("bb", use=False)


def test_a_count_in_the_text_isnt_a_change():
    assert firewall_lines(["table a b {", "\tset s {", "\t\tsize 1000 # count 3", "\t}", "}"]) == (
        firewall_lines(["table a b {", "\tset s {", "\t\tsize 1000 # count 9", "\t}", "}"])
    )
