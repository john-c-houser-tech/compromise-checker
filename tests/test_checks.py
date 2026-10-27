"""Checks 8.1–8.3 and `checker analyze` (PR 1.7a)."""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from test_snapshot import add_bundle, host_records

from checker import cli
from checker.assess import analyze, load_assessment
from checker.checks import Context, run_checks
from checker.checks.accounts import pam_module
from checker.checks.kernel import taint_flags
from checker.events import Event
from checker.snapshot import Section, Snapshot, compare

T0 = datetime(2027, 1, 2, 12, 0, tzinfo=UTC)


def ev(kind, minutes=0, source="auth_journal", own=False, line="", **fields):
    moment = (T0 + timedelta(minutes=minutes)).isoformat()
    return Event(moment, moment, source, kind, fields, line=line, own_session=own)


def snap(**sections):
    return Snapshot(
        {"masking_version": 6, "full": True},
        {name: Section(dict(items)) for name, items in sections.items()},
    )


def run(events=(), snapshot=None, baseline=None, previous=None, earlier=()):
    snapshot = snapshot or snap()
    context = Context(
        host="web01",
        bundle_id="b2",
        events=list(events),
        snapshot=snapshot,
        baseline_id="b0" if baseline else None,
        since_baseline=compare(baseline, snapshot) if baseline else None,
        since_previous=compare(previous, snapshot) if previous else None,
        earlier_events=lambda: [list(e) for e in earlier],
    )
    findings, ran = run_checks(context)
    assert not [r for r in ran if r["status"].startswith("failed")], ran
    return findings


def of(findings, check):
    return [f for f in findings if f.check == check]


# --- 8.1 -----------------------------------------------------------------------------------


def test_oom_of_a_security_service_matters_more():
    found = of(
        run([ev("kernel.oom_kill", comm="auditd"), ev("kernel.oom_kill", comm="php-fpm")]),
        "kernel.oom_kill",
    )
    assert [(f.summary.split(":")[0], f.band, f.category) for f in found] == [
        ("auditd", "medium", "compromise indicator"),
        ("php-fpm", "low", "hygiene"),
    ]


def test_segfaults_in_network_facing_services():
    listeners = {"tcp 0.0.0.0:443 netns=host": {"programs": ["nginx"], "uids": [0], "sockets": 1}}
    events = [ev("kernel.segfault", i, comm="nginx") for i in range(3)]
    events += [ev("kernel.segfault", comm="vim")]  # once, not network-facing: nothing
    found = of(run(events, snap(listeners=listeners)), "kernel.segfault")
    assert [(f.title, f.band) for f in found] == [
        ("A network-facing service crashed repeatedly", "medium")
    ]
    assert len(found[0].evidence) == 3


def test_taint_flags():
    assert taint_flags(512) == {"W"}
    assert taint_flags(4096 + 8192) == {"O", "E"}
    assert taint_flags("junk") == set()


def test_taint_no_module_explains_is_high():
    hidden = snap(host={"kernel_taint": {"value": 4096}}, kernel_modules={"ext4": {"taint": ""}})
    [finding] = of(run([], hidden), "kernel.taint")
    assert finding.band == "high" and "hiding" in finding.summary
    # A tainting module loaded and since unloaded explains it, more mildly.
    unloaded = [ev("kernel.module_taint", source="system_journal", module="vboxdrv")]
    found = of(run(unloaded, hidden), "kernel.taint")
    assert found[0].band == "medium" and "vboxdrv" in found[0].summary


def test_taint_and_out_of_tree_modules_against_the_baseline():
    before = snap(host={"kernel_taint": {"value": 0}}, kernel_modules={"ext4": {"taint": ""}})
    after = snap(
        host={"kernel_taint": {"value": 4096}},
        kernel_modules={"ext4": {"taint": ""}, "rootkit": {"taint": "OE"}},
    )
    found = of(run([], after, baseline=before), "kernel.taint")
    titles = {f.title: f.band for f in found}
    assert titles["The kernel became tainted since the baseline"] == "high"
    assert (
        titles[
            "An out-of-tree, unsigned or proprietary kernel module was loaded since the baseline"
        ]
        == "high"
    )
    # Without a baseline: such a module is reported as present, medium.
    found = of(run([], after), "kernel.taint")
    assert [f.band for f in found if "rootkit" in f.summary] == ["medium"]


def test_core_dumps():
    listeners = {"tcp :::22 netns=host": {"programs": ["sshd"], "uids": [0], "sockets": 1}}
    events = [ev("process.core_dump", comm="sshd", pid="5"), ev("process.core_dump", comm="x")]
    found = of(run(events, snap(listeners=listeners)), "kernel.core_dump")
    assert [(f.band, f.category) for f in found] == [
        ("medium", "compromise indicator"),
        ("info", "hygiene"),
    ]


# --- 8.2 -----------------------------------------------------------------------------------


def boot(minutes, boot_id):
    return ev("system.boot_journal", minutes, source="boots", boot_id=boot_id)


def test_reboots_are_classified():
    events = [
        ev("unit.started", -1, source="system_journal", what="x"),  # the logs' reach
        boot(0, "a"),
        # Unclean: nothing between boot a and boot b.
        boot(100, "b"),
        # Operator: sudo reboot, then a shutdown, then boot c.
        ev("sudo.command", 150, user="jch", command="/usr/sbin/reboot"),
        ev("system.shutdown", 151, source="system_journal", target="Reboot"),
        boot(155, "c"),
        # Planned: an automatic update, then a shutdown.
        ev("unit.started", 200, source="system_journal", what="Unattended Upgrades Shutdown"),
        ev("system.shutdown", 210, source="system_journal", target="Reboot"),
        boot(215, "d"),
        # Unexplained: a clean shutdown and nothing to say why.
        ev("system.shutdown_record", 300, source="login_records:/var/log/wtmp"),
        boot(305, "e"),
    ]
    found = sorted(of(run(events), "system.reboot"), key=lambda f: f.last_seen)
    assert [(f.title, f.band) for f in found] == [
        ("An unclean reboot: no shutdown was recorded before it", "medium"),
        ("A reboot by an operator", "info"),
        ("A planned reboot (automatic updates)", "info"),
        ("An unexplained reboot", "low"),
    ]
    assert "account:jch" in found[1].entities


def test_boots_before_the_logs_reach_are_not_classified():
    events = [
        boot(0, "a"),
        boot(100, "b"),
        ev("unit.started", 50, source="system_journal", what="x"),
    ]
    assert of(run(events), "system.reboot") == []


# --- 8.3 -----------------------------------------------------------------------------------


def accounts(**extra):
    base = {
        "root": {"uid": 0, "shell": "/bin/bash", "shadow_status": "set"},
        "jch": {"uid": 1000, "shell": "/bin/bash", "shadow_status": "set"},
        "www-data": {"uid": 33, "shell": "/usr/sbin/nologin", "shadow_status": "locked"},
    }
    base.update(extra)
    return base


def test_uid0_duplicates_and_shared_uids():
    found = of(
        run(
            [],
            snap(
                accounts=accounts(
                    toor={"uid": 0},
                    **{"jch #2": {"uid": 0}},
                    alias={"uid": 1000},
                )
            ),
        ),
        "account.uid0",
    )
    titles = sorted(f.title for f in found)
    assert titles == [
        "Accounts sharing a UID",
        "An account name listed twice",
        "An account other than root has UID 0",
    ]


def test_account_changes_need_a_baseline():
    before = snap(accounts=accounts(), groups={})
    after = snap(
        accounts=accounts(
            eve={"uid": 1001, "shell": "/bin/bash"},
            **{"www-data": {"uid": 33, "shell": "/bin/bash", "shadow_status": "set"}},
        ),
        groups={},
    )
    assert of(run([], after), "account.changes") == []  # no baseline: not run
    found = of(run([], after, baseline=before), "account.changes")
    assert [f.title for f in found] == ["A new account", "A service account can now log in"]
    assert "a login shell (/bin/bash) and a password" in found[1].summary


def test_removed_accounts_only_when_comparable():
    before = snap(accounts=accounts())
    after = Snapshot({"masking_version": 6}, {"accounts": Section({"root": {"uid": 0}})})
    assert len(of(run([], after, baseline=before), "account.changes")) == 2
    after.sections["accounts"].complete = False
    after.sections["accounts"].gaps = ["unreadable_file: /etc/passwd"]
    assert of(run([], after, baseline=before), "account.changes") == []


def test_account_changes_in_the_logs():
    events = [
        ev("account.created", user="eve", uid="0"),
        ev("group.member_added", user="eve", group="sudo"),
        ev("group.member_added", user="bob", group="users"),
        ev("account.created", user="tool", uid="1", own=True),  # the tool's own: never
    ]
    found = of(run(events), "account.log_changes")
    assert [f.band for f in found] == ["high", "medium", "medium"]


def test_new_sudo_rules():
    before = snap(sudo_rules={"/etc/sudoers: root ALL=(ALL) ALL": {"path": "/etc/sudoers"}})
    after = snap(
        sudo_rules={
            "/etc/sudoers: root ALL=(ALL) ALL": {"path": "/etc/sudoers"},
            "/etc/sudoers.d/x: eve ALL=(ALL) NOPASSWD: ALL": {"path": "/etc/sudoers.d/x"},
        }
    )
    [finding] = of(run([], after, baseline=before, previous=before), "sudo.rules")
    assert finding.band == "high" and "NOPASSWD" in finding.title and finding.new


def test_new_members_of_root_groups():
    before = snap(groups={"sudo": {"gid": 27, "members": ["jch"]}, "adm": {"members": []}})
    after = snap(
        groups={"sudo": {"gid": 27, "members": ["eve", "jch"]}, "adm": {"members": ["bob"]}},
    )
    found = of(run([], after, baseline=before), "group.privileged")
    assert [(f.summary, f.band) for f in found] == [("sudo: eve", "high"), ("adm: bob", "medium")]


def test_authorized_keys():
    key = {"account": "jch", "fingerprint": "SHA256:a", "type": "ssh-ed25519", "path": "/p"}
    stray = {
        "account": None,
        "fingerprint": "SHA256:z",
        "path": "/etc/ssh/keys/x",
        "unattributed": True,
    }
    before = snap(authorized_keys={"jch SHA256:a /p": key})
    after = snap(
        authorized_keys={
            "jch SHA256:a /p": dict(key, options=[["command", "x"]]),
            "root SHA256:b /root": dict(key, account="root", fingerprint="SHA256:b"),
            "? SHA256:z /etc/ssh/keys/x": stray,
        }
    )
    found = of(run([], after, baseline=before), "ssh.authorized_keys")
    assert sorted((f.title, f.band) for f in found) == [
        ("A new authorized SSH key", "high"),
        ("A new authorized SSH key", "high"),  # the stray one is new too
        ("An authorized SSH key's options changed", "medium"),
        ("An authorized key that belongs to no local account", "medium"),
    ]


def test_success_after_guessing():
    events = [ev("ssh.login.failed", i, address="198.51.100.9", user="root") for i in range(4)]
    events.append(ev("auth.failure", 4, rest=" logname= uid=0 rhost=198.51.100.9 user=root"))
    events.append(
        ev("ssh.login.accepted", 5, address="198.51.100.9", user="root", method="password")
    )
    events.append(
        ev("ssh.login.accepted", 6, address="203.0.113.1", user="jch", method="publickey")
    )
    [finding] = of(run(events), "ssh.guessed")
    assert finding.band == "high" and "5 failures" in finding.summary
    assert of(run(events[1:]), "ssh.guessed") == []  # four failures: under the threshold


def test_root_logins_and_new_sources():
    earlier = [[ev("ssh.login.accepted", -900, address="203.0.113.1", user="jch")]]
    events = [
        ev("ssh.login.accepted", 0, address="203.0.113.1", user="jch"),
        ev("ssh.login.accepted", 1, address="198.51.100.7", user="root", method="password"),
        ev("ssh.login.accepted", 2, address="192.0.2.50", user="scanner", own=True),
    ]
    found = of(run(events, earlier=earlier), "ssh.login")
    assert sorted(f.title for f in found) == [
        "A direct root login over SSH",
        "Logins from an address never seen before",
    ]
    # No earlier bundle: "never seen before" can't be said yet.
    assert [f.title for f in of(run(events), "ssh.login")] == ["A direct root login over SSH"]


def test_su_passwords_and_refused_sudo():
    events = [
        ev("su.switch", user="jch", target="root"),
        ev("su.switch", 1, user="jch", target="root"),
        ev("sudo.failed", user="eve", reason="3 incorrect password attempts"),
    ]
    found = of(run(events), "account.password")
    assert [(f.title, f.summary) for f in found] == [
        ("sudo failed (wrong password)", "eve: 1 time(s)"),
        ("su was used", "jch → root: 2 time(s)"),
    ]


def test_sshd_changes():
    line = {"path": "/etc/ssh/sshd_config", "match": None}
    before = snap(
        sshd_config={
            "/etc/ssh/sshd_config: permitrootlogin no": dict(
                line, keyword="permitrootlogin", value="no"
            )
        }
    )
    after = snap(
        sshd_config={
            "/etc/ssh/sshd_config: permitrootlogin yes": dict(
                line, keyword="permitrootlogin", value="yes"
            ),
            "/etc/ssh/sshd_config: banner /x": dict(line, keyword="banner", value="/x"),
        }
    )
    found = of(run([], after, baseline=before), "sshd.config")
    assert sorted((f.title, f.band) for f in found) == [
        ("An sshd setting was added", "high"),
        ("An sshd setting was added", "medium"),
        ("An sshd setting was removed", "high"),
    ]


def test_pam_module_parsing():
    assert pam_module("/etc/pam.d/sshd: auth required pam_unix.so") == "pam_unix.so"
    assert pam_module("f: -session optional /lib/security/pam_exec.so /x") == "pam_exec.so"
    assert pam_module("f: auth [success=1 default=ignore] pam_exec.so quiet /x") == "pam_exec.so"
    assert pam_module("f: auth include common-auth") is None
    assert pam_module("f: @include common-auth") is None


def test_pam_changes():
    before = snap(
        pam_rules={"/etc/pam.d/sshd: auth required pam_unix.so": {"path": "/etc/pam.d/sshd"}},
        pam={"/usr/lib/security/pam_unix.so": {"sha256": "a", "size": 1}},
        unowned_executables={},
    )
    after = snap(
        pam_rules={
            "/etc/pam.d/sshd: auth required pam_unix.so": {"path": "/etc/pam.d/sshd"},
            "/etc/pam.d/sshd: auth optional pam_exec.so /tmp/x": {"path": "/etc/pam.d/sshd"},
        },
        pam={
            "/usr/lib/security/pam_unix.so": {"sha256": "b", "size": 1},
            "/usr/lib/security/pam_evil.so": {"sha256": "c"},
        },
        unowned_executables={"/usr/lib/security/pam_evil.so": {}},
    )
    found = of(run([], after, baseline=before), "pam.changes")
    assert sorted(f.title for f in found) == [
        "A PAM line was added that runs a program (pam_exec)",
        "A PAM module file changed",
        "A PAM module that no package installed",
        "A new file in a PAM module directory",
    ]
    # Without a baseline: the pam_exec line and the unowned module still show.
    found = of(run([], after), "pam.changes")
    assert sorted(f.title for f in found) == [
        "A PAM module that no package installed",
        "PAM runs a program (pam_exec)",
    ]


def test_a_broken_check_is_reported_not_fatal(monkeypatch):
    from checker import checks

    def broken(context):
        raise RuntimeError("bug")

    monkeypatch.setattr(checks, "REGISTRY", [checks.Check("x.broken", "x", False, broken)])
    findings, ran = run_checks(Context("h", "b", [], snap()))
    assert findings == [] and ran == [{"check": "x.broken", "status": "failed: RuntimeError: bug"}]


# --- Analyze ----------------------------------------------------------------------------------


def test_analyze_stores_an_assessment_with_coverage(home):
    _, store, identity, config = home
    add_bundle(home, "b1", 0, host_records())
    first = analyze(store, "web01", identity, config.recipients)
    assert first["baseline_set_now"] and "first analysis" in first["notes"][0]
    waiting = {c["check"] for c in first["checks"] if c["status"] == "no baseline yet"}
    assert "sudo.rules" in waiting
    assert any("no authentication log events" in g for g in first["coverage"]["gaps"])
    add_bundle(
        home,
        "b2",
        10,
        host_records(
            accounts=(("root", 0), ("jch", 1000), ("evil", 0)),
            sudoers="root ALL=(ALL) ALL\nevil ALL=(ALL) NOPASSWD: ALL\n",
        ),
    )
    second = analyze(store, "web01", identity, config.recipients)
    checks = {f["check"] for f in second["findings"]}
    assert {"account.uid0", "account.changes", "sudo.rules"} <= checks
    assert second["counts"]["compromise indicator/high"] >= 2
    stored = load_assessment(store, "b2", identity)
    assert stored["findings"] == second["findings"]
    row = store.assessments("b2")[-1]
    assert b"evil" not in open(row["path"], "rb").read()  # encrypted
    assert [c["action"] for c in store.custody_of("b2")][-1] == "analysed"
    with pytest.raises(sqlite3.DatabaseError, match="append-only"), store._db:
        store._db.execute("DELETE FROM assessments")


def test_cli_analyze(home, capsys):
    add_bundle(home, "b1", 0, host_records())
    add_bundle(home, "b2", 10, host_records(accounts=(("root", 0), ("jch", 1000), ("toor", 0))))
    add_bundle(home, "d1", 0, host_records(), host="db01")
    assert cli.main(["analyze", "web01"]) == 0
    out = capsys.readouterr().out
    assert "Compromise indicators:" in out and "HIGH   An account other than root has UID 0" in out
    assert "Coverage:" in out
    assert cli.main(["analyze", "--all"]) == 0
    out = capsys.readouterr().out
    assert "Host       db01" in out and "Host       web01" in out


def test_changes_that_are_not_findings():
    # An out-of-tree module already there at the baseline: reported then, not again.
    modules = {"zfs": {"taint": "PO"}}
    same = snap(host={"kernel_taint": {"value": 4097}}, kernel_modules=modules)
    assert of(run([], same, baseline=same), "kernel.taint") == []
    # A person's account (UID 1000+) getting a shell is not a service account.
    before = snap(accounts=accounts(ann={"uid": 1002, "shell": "/usr/sbin/nologin"}))
    after = snap(accounts=accounts(ann={"uid": 1002, "shell": "/bin/bash"}))
    assert of(run([], after, baseline=before), "account.changes") == []
    # New members of an ordinary group.
    before = snap(groups={"users": {"members": []}})
    after = snap(groups={"users": {"members": ["bob"]}})
    assert of(run([], after, baseline=before), "group.privileged") == []
