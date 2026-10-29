"""Anti-forensics checks (PR 2.5, DESIGN.md §8.10)."""

from datetime import timedelta

from test_checks import T0, ev, of
from test_checks_live import proc, snap

from checker.checks import Context, run_checks
from checker.snapshot import compare

PREVIOUS = (T0 - timedelta(days=1)).isoformat()


def run(events=(), snapshot=None, baseline=None, previous=None):
    snapshot = snapshot or snap()
    context = Context(
        host="web01",
        bundle_id="b2",
        events=list(events),
        snapshot=snapshot,
        baseline_id="b0" if baseline else None,
        since_baseline=compare(baseline, snapshot) if baseline else None,
        since_previous=compare(previous, snapshot) if previous else None,
        previous_time=PREVIOUS if previous else None,
        previous_snapshot=previous,
    )
    findings, ran = run_checks(context)
    assert not [r for r in ran if r["status"].startswith("failed")], ran
    return findings


def logs(*files):
    return {"log_files": [{"type": "f", **f} for f in files], "processes": [], "sockets": []}


def test_a_key_log_truncated_or_deleted():
    before = snap(
        logs(
            {"path": "/var/log/wtmp", "size": 9000, "inode": 1},
            {"path": "/var/log/auth.log", "size": 5000, "inode": 2},
            {"path": "/var/log/app.log", "size": 800, "inode": 3},
        )
    )
    after = snap(
        logs(
            {"path": "/var/log/wtmp", "size": 384, "inode": 1},
            {"path": "/var/log/app.log", "size": 100, "inode": 3},
        )
    )
    found = {
        f.summary.split(":")[0]: f for f in of(run([], after, previous=before), "logs.cleared")
    }
    assert found["/var/log/wtmp"].band == "high" and found["/var/log/wtmp"].variant == "truncated"
    assert found["/var/log/auth.log"].variant == "deleted"
    assert found["/var/log/app.log"].band == "medium"


def test_rotation_is_not_clearing():
    later = (T0 + timedelta(hours=1)).timestamp()
    before = snap(
        logs(
            {"path": "/var/log/auth.log", "size": 5000, "inode": 2},
            {"path": "/var/log/app.log", "size": 800, "inode": 3},
        )
    )
    after = snap(
        logs(
            {"path": "/var/log/auth.log", "size": 10, "inode": 9},  # new file
            {"path": "/var/log/auth.log.1", "size": 5000, "inode": 2, "mtime": later},
            {"path": "/var/log/app.log", "size": 0, "inode": 3},  # copytruncate
            {"path": "/var/log/app.log.1", "size": 800, "inode": 7, "mtime": later},
        )
    )
    assert of(run([], after, previous=before), "logs.cleared") == []


def test_logging_stopped_outside_a_shutdown():
    events = [
        ev("unit.stopped", 0, what="Security Auditing Service"),
        ev("unit.stopped", 60, what="System Logging Service"),
        ev("system.shutdown", 65, target="Shutdown"),
        ev("unit.stopped", 5, what="nginx"),
    ]
    found = of(run(events), "logs.stopped")
    assert [f.summary.split(" (")[0] for f in found] == ["Security Auditing Service"]


def test_audit_switched_off_and_its_daemon_ended():
    at = int(T0.timestamp())
    records = [
        f"type=CONFIG_CHANGE msg=audit({at}.100:5): auid=0 ses=3 op=remove_rule key=x res=1",
        f"type=CONFIG_CHANGE msg=audit({at}.200:6): op=set audit_enabled=0 old=1 auid=0 res=1",
        f"type=CONFIG_CHANGE msg=audit({at}.300:7): auid=0 op=add_rule key=y res=1",
        f"type=DAEMON_END msg=audit({at}.400:8): op=terminate auid=0 res=success",
    ]
    found = of(run([], snap({"audit_records": records, "processes": []})), "logs.stopped")
    assert sorted(f.variant for f in found) == ["audit_daemon", "audit_rules", "audit_rules"]


def test_journald_storage_and_services_and_agents():
    before = snap(
        logging={
            "journald": {"storage": "persistent"},
            "service: auditd": {"running": True},
            "agent: fail2ban-server": {"running": True},
        }
    )
    after = snap(logging={"journald": {"storage": "none"}})
    found = run([], after, baseline=before)
    assert of(found, "logs.journald_config")[0].band == "high"
    assert [f.variant for f in of(found, "logs.stopped")] == ["not_running"]
    assert of(found, "agent.stopped")[0].summary == "fail2ban-server"


def test_history_switched_off():
    before = snap(shell_history={"/root/.bash_history": {"type": "-", "size": 4000}})
    after = snap(
        shell_history={
            "/root/.bash_history": {"type": "-", "size": 0},
            "/home/eve/.bash_history": {"type": "l", "link_target": "/dev/null"},
        },
        startup={"/etc/profile.d/x.sh": {"disables_history": True}},
    )
    found = {f.variant: f for f in of(run([], after, baseline=before), "history.disabled")}
    assert found["link"].band == "high" and found["startup"].band == "high"
    assert found["emptied"].band == "medium"


def test_selinux_and_apparmor_turned_down():
    at = int(T0.timestamp())
    record = f"type=MAC_STATUS msg=audit({at}.1:9): enforcing=0 old_enforcing=1 auid=0 ses=2"
    before = snap(
        logging={
            "selinux": {"mode": "enforcing", "configured": "enforcing"},
            "apparmor: /usr/sbin/cupsd": {"mode": "enforce"},
            "apparmor: nginx": {"mode": "enforce"},
        }
    )
    after = snap(
        {"audit_records": [record], "processes": []},
        logging={
            "selinux": {"mode": "permissive", "configured": "enforcing"},
            "apparmor: nginx": {"mode": "complain"},
        },
    )
    found = {f.variant: f for f in of(run([], after, baseline=before), "mac.disabled")}
    assert set(found) == {"selinux", "selinux_audit", "apparmor"}
    assert "1 unloaded, 1 no longer enforcing" in found["apparmor"].summary


def test_clock_changes_after_boot_with_and_without_time_sync():
    events = [
        ev("system.boot", 0),
        ev("system.clock_changed", 5),  # minutes after boot: normal
        ev("system.clock_changed", 180),
    ]
    found = of(run(events), "clock.jump")
    assert len(found) == 1 and found[0].band == "medium"
    synced = snap({"processes": [proc(9, "chronyd", exe="/usr/sbin/chronyd")]})
    assert of(run(events, synced), "clock.jump")[0].band == "low"


def test_the_snapshot_flags_history_off_and_reads_logging_state(tmp_path):
    from test_snapshot import host_records, rec, snapshot_of_records, text_source

    records = host_records(
        extra=[
            *text_source(50, "startup", "/etc/profile.d/quiet.sh", "export HISTSIZE=0\n"),
            *text_source(
                51, "logging_state", "/etc/systemd/journald.conf", "[Journal]\nStorage=volatile\n"
            ),
            *text_source(52, "logging_state", "/etc/selinux/config", "SELINUX=permissive\n"),
            rec(
                "logging_state",
                "mac_state",
                selinux="enforcing",
                apparmor={"profiles": {"/usr/sbin/cupsd": "enforce"}},
            ),
            rec("logging_state", "log_file", path="/var/log/wtmp", type="f", size=10, inode=4),
            rec("processes", "process", pid=30, comm="auditd", exe="/usr/sbin/auditd"),
        ]
    )
    snapshot = snapshot_of_records(records, tmp_path)
    assert snapshot.sections["startup"].items["/etc/profile.d/quiet.sh"]["disables_history"]
    logging = snapshot.sections["logging"].items
    assert logging["journald"] == {"storage": "volatile"}
    assert logging["selinux"] == {"mode": "enforcing", "configured": "permissive"}
    assert logging["apparmor: /usr/sbin/cupsd"] == {"mode": "enforce"}
    assert logging["service: auditd"] == {"running": True}
    assert snapshot.live["log_files"][0]["path"] == "/var/log/wtmp"


def test_a_file_merely_named_like_a_rotated_copy_hides_nothing():
    later = (T0 + timedelta(hours=1)).timestamp()
    before = snap(logs({"path": "/var/log/auth.log", "size": 5000, "inode": 2}))
    faked = snap(
        logs(
            {"path": "/var/log/auth.log", "size": 0, "inode": 2},
            {"path": "/var/log/auth.log.1", "size": 0, "inode": 8, "mtime": later},  # touch
        )
    )
    [found] = of(run([], faked, previous=before), "logs.cleared")
    assert found.band == "high" and found.variant == "truncated"
    compressed = snap(
        logs(
            {"path": "/var/log/auth.log", "size": 0, "inode": 2},
            {"path": "/var/log/auth.log.1.gz", "size": 700, "inode": 8, "mtime": later},
        )
    )
    [found] = of(run([], compressed, previous=before), "logs.cleared")
    assert found.band == "medium" and "auth.log.1.gz" in found.summary
