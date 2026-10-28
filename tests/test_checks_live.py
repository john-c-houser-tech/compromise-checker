"""Checks 8.4–8.7 (PR 1.7b): persistence, binary integrity, files in
unusual places, live processes."""

from datetime import timedelta

from test_checks import T0, accounts, ev, of, run  # noqa: F401 - accounts unused here
from test_snapshot import host_records, snapshot_of_records

from checker.snapshot import Section, Snapshot


def snap(live=None, **sections):
    return Snapshot(
        {"masking_version": 6, "full": True, "host_time": (T0 + timedelta(hours=2)).isoformat()},
        {name: Section(dict(items)) for name, items in sections.items()},
        live or {},
    )


def proc(pid, comm, **fields):
    return {"pid": pid, "ppid": 1, "comm": comm, "start_time": T0.isoformat(), **fields}


# --- The snapshot's live part -------------------------------------------------------------


def test_the_snapshot_keeps_processes_and_summaries_uncompared(tmp_path):
    extra = [
        {
            "type": "record",
            "module": "processes",
            "name": "hidden_process",
            "data": {"pid": 66, "comm": "x", "hidden_from_listing": True},
        },
        {
            "type": "record",
            "module": "system_files",
            "name": "system_files_summary",
            "data": {"owners": "dpkg", "owners_complete": True, "truncated": False},
        },
    ]
    taken = snapshot_of_records(host_records(extra=extra), tmp_path)
    pids = {p["pid"]: p["hidden"] for p in taken.live["processes"]}
    assert pids[66] is True and pids[700] is False
    assert taken.live["system_files_summary"]["owners"] == "dpkg"
    assert len(taken.live["sockets"]) == 2
    from checker.snapshot import compare

    other = snapshot_of_records(host_records(), tmp_path)
    assert compare(other, taken) == {}  # live data never shows as a change


# --- 8.4 ---------------------------------------------------------------------------------


def test_ld_preload_file_and_process_variables():
    live = {
        "processes": [
            proc(5, "nginx", loader_environment={"LD_PRELOAD": "/lib/x.so"}),
            proc(6, "app", loader_environment={"LD_LIBRARY_PATH": "/opt/lib"}),
        ]
    }
    found = of(
        run([], snap(live, startup={"/etc/ld.so.preload": {"type": "-", "size": 12}})),
        "persistence.ld_preload",
    )
    assert sorted(f.summary for f in found) == [
        "/etc/ld.so.preload (12 bytes)",
        "nginx (pid 5): LD_PRELOAD=/lib/x.so",
    ]
    empty = snap(startup={"/etc/ld.so.preload": {"type": "-", "size": 0}})
    assert of(run([], empty), "persistence.ld_preload") == []


def test_persistence_changes():
    before = snap(
        cron={"/etc/cron.d/x": {"type": "-", "content_sha256": "a"}},
        systemd={"/usr/lib/systemd/system/a.service": {"type": "-", "content_sha256": "a"}},
        startup={},
        hooks={},
    )
    after = snap(
        cron={
            "/etc/cron.d/x": {"type": "-", "content_sha256": "b"},
            "/etc/cron.d/new": {"type": "-", "content_sha256": "c"},
            "/etc/cron.d/dir": {"type": "d"},
        },
        systemd={
            "/usr/lib/systemd/system/a.service": {"type": "-", "content_sha256": "z"},
            "/run/systemd/transient/session-5.scope": {"type": "-"},
            "/run/systemd/transient/run-x.service": {"type": "-"},
        },
        startup={"/etc/ld.so.preload": {"type": "-", "size": 9}},
        hooks={},
    )
    found = of(run([], after, baseline=before), "persistence.changes")
    assert sorted((f.summary, f.band) for f in found) == [
        ("/etc/cron.d/new", "medium"),
        ("/etc/cron.d/x: content_sha256", "medium"),
        ("/etc/ld.so.preload", "high"),
        ("/run/systemd/transient/run-x.service", "medium"),
        ("/usr/lib/systemd/system/a.service: content_sha256", "low"),
    ]
    touched = snap(
        cron={"/etc/cron.d/x": {"type": "-", "content_sha256": "a", "mtime": "t2"}},
        systemd={},
        startup={},
        hooks={},
    )
    assert (
        of(
            run(
                [],
                touched,
                baseline=snap(
                    cron={"/etc/cron.d/x": {"type": "-", "content_sha256": "a", "mtime": "t1"}},
                    systemd={},
                    startup={},
                    hooks={},
                ),
            ),
            "persistence.changes",
        )
        == []
    )


def test_at_jobs_and_home_persistence():
    found = run(
        [],
        snap(
            cron={
                "/var/spool/cron/atjobs/a0001": {"type": "-", "uid": 1000},
                "/var/spool/cron/atjobs/.SEQ": {"type": "-"},
            },
            systemd={
                "/home/eve/.config/systemd/user/x.service": {"type": "-"},
                "/var/lib/systemd/linger/eve": {"type": "-"},
            },
            startup={"/home/eve/.config/autostart/x.desktop": {"type": "-"}},
        ),
    )
    assert [f.summary for f in of(found, "persistence.at_jobs")] == [
        "/var/spool/cron/atjobs/a0001 (owner UID 1000)"
    ]
    assert sorted(f.band for f in of(found, "persistence.homes")) == ["info", "info", "low"]


# --- 8.5 ---------------------------------------------------------------------------------


OWNERS = {"system_files_summary": {"owners": "dpkg", "owners_complete": True}}


def test_package_changes_by_importance():
    changes = {
        "/usr/bin/ps": {"package": "procps", "result": "changed"},
        "/usr/lib/x86_64-linux-gnu/libfoo.so.1": {"package": "foo", "result": "changed"},
        "/usr/share/doc/x/README": {"package": "x", "result": "missing"},
        "/etc/ssh/sshd_config": {
            "package": "openssh-server",
            "result": "changed",
            "configuration": True,
        },
        "/usr/bin/protected": {"package": "y", "result": "refused"},
        "/usr/lib/x86_64-linux-gnu/security/pam_unix.so": {
            "package": "libpam",
            "result": "changed",
        },
    }
    found = of(run([], snap(package_changes=changes)), "package.changed")
    bands = {f.summary.split(" ")[0]: (f.band, f.category) for f in found}
    assert bands == {
        "/usr/bin/ps": ("high", "compromise indicator"),
        "/usr/lib/x86_64-linux-gnu/security/pam_unix.so": ("high", "compromise indicator"),
        "/usr/lib/x86_64-linux-gnu/libfoo.so.1": ("medium", "compromise indicator"),
        "/usr/share/doc/x/README": ("low", "compromise indicator"),
        "/etc/ssh/sshd_config": ("info", "hygiene"),
    }


def test_privileged_files():
    files = {
        "/usr/bin/passwd": {"setuid": True, "package": "passwd", "uid": 0},
        "/usr/bin/evil": {"setuid": True, "package": None, "uid": 0},
        "/usr/bin/ping": {"capabilities": "cap_net_raw=ep", "package": "iputils"},
        "/usr/local/bin/x": {"capabilities": "cap_setuid=ep", "package": None},
        "/home/eve/.x": {"setuid": True, "place": "/home", "uid": 0},
        "/var/tmp/disk": {"type": "b", "place": "/var"},
        "/run/systemd/inaccessible/chr": {"type": "c", "place": "/run"},
        "/root": {"error": "permission denied", "place": "/root"},
    }
    found = of(run([], snap(OWNERS, privileged_files=files)), "files.privileged")
    assert sorted(f.summary.split(":")[0] for f in found) == [
        "/home/eve/.x",
        "/usr/bin/evil",
        "/usr/local/bin/x",
        "/var/tmp/disk",
    ]
    # Without package ownership, nothing is called unowned.
    found = of(run([], snap({}, privileged_files=files)), "files.privileged")
    assert sorted(f.summary.split(":")[0] for f in found) == ["/home/eve/.x", "/var/tmp/disk"]
    # A new one since the baseline, even a package's.
    before = snap(OWNERS, privileged_files={})
    after = snap(OWNERS, privileged_files={"/usr/bin/newuid": {"setuid": True, "package": "x"}})
    [finding] = of(run([], after, baseline=before), "files.privileged")
    assert finding.band == "high" and finding.title.startswith("A new privileged file")


def test_unowned_executables():
    items = {"/usr/bin/implant": {"sha256": "ab" * 32}, "/usr/local/bin/tool": {"local": True}}
    found = of(run([], snap(OWNERS, unowned_executables=items)), "files.unowned")
    assert sorted((f.summary.split(" ")[0], f.band) for f in found) == [
        ("/usr/bin/implant", "medium"),
        ("/usr/local/bin/tool", "info"),
    ]
    before = snap(OWNERS, unowned_executables={})
    found = of(run([], snap(OWNERS, unowned_executables=items), baseline=before), "files.unowned")
    assert sorted(f.band for f in found) == ["high", "medium"]
    assert of(run([], snap({}, unowned_executables=items)), "files.unowned") == []


# --- 8.6 ---------------------------------------------------------------------------------


def test_scratch_programs_are_grouped_by_directory():
    items = {
        "/tmp/.x/miner": {"place": "/tmp", "type": "-", "kind": "elf", "uid": 33},
        "/tmp/build/a.so": {"place": "/tmp", "type": "-", "kind": "elf"},
        "/tmp/build/b.so": {"place": "/tmp", "type": "-", "kind": "elf"},
        "/dev/shm/run.sh": {"place": "/dev/shm", "type": "-", "kind": "script"},
        "/tmp/data.bin": {"place": "/tmp", "type": "-", "mode": "0755"},  # an execute bit only
    }
    found = of(run([], snap(unusual_files=items)), "files.scratch")
    assert sorted((f.title, f.band) for f in found) == [
        ("A program in a scratch directory", "high"),
        ("A program in a scratch directory (2 in /tmp/build)", "high"),
        ("A script in a scratch directory", "medium"),
    ]


def test_deceptive_names_and_dev():
    items = {
        "/tmp/...": {"place": "/tmp", "type": "d", "name_flags": ["hidden", "dots_or_spaces_only"]},
        "/tmp/.X11-unix": {"place": "/tmp", "type": "d", "name_flags": ["hidden"]},
        "/var/tmp/[kworker]": {
            "place": "/var/tmp",
            "type": "-",
            "name_flags": ["kernel_thread_name"],
        },
        "/dev/.lib": {"place": "/dev", "type": "-", "size": 9},
        "/dev/.udev": {"place": "/dev", "type": "d"},
    }
    found = run([], snap(unusual_files=items))
    assert sorted(f.summary.split(":")[0] for f in of(found, "files.deceptive")) == [
        "'/tmp/...'",
        "'/var/tmp/[kworker]'",
    ]
    assert [(f.title, f.band) for f in of(found, "files.dev")] == [
        ("A regular file under /dev", "high"),
        ("A hidden or misplaced entry under /dev", "medium"),
    ]


def test_web_shells():
    items = {
        "/var/www/html/index.php": {"place": "/var/www", "type": "-"},
        "/var/www/html/wp-content/uploads/2026/x.php": {"place": "/var/www", "type": "-"},
        "/var/www/html/img/cat.php.jpg": {"place": "/var/www", "type": "-"},
        "/var/www/html/bin": {"place": "/var/www", "type": "-", "kind": "elf"},
        "/var/www/html/.env": {"place": "/var/www", "type": "-"},
        "/var/www/html/root.txt": {"place": "/var/www", "type": "l", "link_target": "/"},
    }
    found = of(run([], snap(web_files=items)), "files.web")
    assert sorted((f.title, f.band) for f in found) == [
        ("A link out of the web root", "medium"),
        ("A program in a web root", "high"),
        ("A script hidden behind a second extension", "high"),
        ("A script in an upload directory", "high"),
        ("A secrets or repository file inside a web root", "medium"),
    ]
    before = snap(web_files={"/var/www/html/index.php": items["/var/www/html/index.php"]})
    after = snap(
        web_files={
            **before.sections["web_files"].items,
            "/var/www/html/shell.php": {"place": "/var/www", "type": "-"},
        }
    )
    [finding] = of(run([], after, baseline=before), "files.web")
    assert finding.title == "A new script in a web root" and finding.band == "high"


def test_backdated_programs_only():
    items = {
        "/tmp/a/x": {
            "place": "/tmp",
            "type": "-",
            "kind": "elf",
            "changed_after_modified_seconds": 864000,
        },
        "/tmp/a/y.pb": {
            "place": "/tmp",
            "type": "-",
            "mode": "0755",
            "changed_after_modified_seconds": 864000,
        },
        "/tmp/z": {"place": "/tmp", "type": "-", "time_out_of_range": {"mtime": -1}},
    }
    found = of(run([], snap(unusual_files=items)), "files.backdated")
    assert sorted(f.title for f in found) == [
        "A file with an impossible time",
        "A program or script whose modification time is long before its change time",
    ]


# --- 8.7 ---------------------------------------------------------------------------------


def test_process_executables():
    live = {
        "processes": [
            proc(10, "x", exe="/memfd:payload (deleted)", exe_memfd=True, exe_deleted=True),
            proc(11, "y", exe="/tmp/.y/y"),
            proc(12, "z", exe="/home/eve/z (deleted)", exe_deleted=True),
            proc(13, "nginx", exe="/usr/sbin/nginx (deleted)", exe_deleted=True),
            proc(14, "kworker/0:1", exe="/usr/bin/python3", cmdline="[kworker/0:1]"),
            proc(15, "kworker/0:2", kernel_thread=True),
        ]
    }
    found = of(run([], snap(live)), "process.executable")
    assert sorted((f.summary.split(" ")[2].rstrip("):"), f.band) for f in found) == [
        ("10", "high"),
        ("11", "high"),
        ("12", "high"),
        ("13", "low"),
        ("14", "high"),
    ]


def test_hidden_processes():
    live = {"processes": [proc(66, "x", hidden=True, exe="/x"), proc(67, "y", hidden=False)]}
    [finding] = of(run([], snap(live)), "process.hidden")
    assert finding.band == "high" and "pid 66" in finding.summary


def test_reverse_shells_but_not_the_tools_own_session():
    sockets = [
        {"protocol": "raw", "inode": "555", "remote": ["0.0.0.0", 0], "pids": [21]},
        {
            "protocol": "tcp",
            "inode": "900",
            "remote": ["198.51.100.9", 4444],
            "state": "established",
            "pids": [20],
        },
        {
            "protocol": "tcp",
            "inode": "901",
            "remote": ["192.0.2.1", 50000],
            "state": "established",
            "pids": [32],
        },
    ]
    live = {
        "sockets": sockets,
        "processes": [
            proc(20, "bash", std_streams={"0": {"kind": "socket", "inode": "900"}}),
            proc(
                21, "bash", std_streams={"0": {"kind": "socket", "inode": "555"}}
            ),  # a unix socket
            proc(22, "nginx", std_streams={"0": {"kind": "socket", "inode": "900"}}),  # not a shell
            # The tool's own: sshd (pid 30) → sudo (31) → python3 (32).
            {**proc(30, "sshd-session"), "ppid": 1},
            {**proc(31, "sudo"), "ppid": 30},
            {
                **proc(32, "python3"),
                "ppid": 31,
                "std_streams": {"0": {"kind": "socket", "inode": "901"}},
            },
        ],
    }
    own_login = ev("ssh.login.accepted", own=True, user="scanner", pid=30)
    found = of(run([own_login], snap(live)), "process.reverse_shell")
    assert [f.summary for f in found] == ["bash (pid 20): stdin is tcp to 198.51.100.9:4444"]


def test_miners():
    start = T0.isoformat()
    sockets = [
        {
            "protocol": "tcp",
            "inode": "1",
            "remote": ["203.0.113.5", 3333],
            "state": "established",
            "pids": [40],
        }
    ]
    live = {
        "sockets": sockets,
        "processes": [
            proc(40, "systemd-helper", cpu_seconds=6000, start_time=start),  # 2 h, 0.8 cores
            proc(41, "xmrig", cpu_seconds=1),
            proc(42, "postgres", cpu_seconds=6000, start_time=start),  # busy, no pool port
        ],
    }
    found = of(run([], snap(live)), "process.miner")
    assert sorted(f.title for f in found) == [
        "A known miner is running",
        "Sustained high CPU with a connection to a mining-pool port",
    ]


def test_injected_code_by_where_it_came_from():
    live = {
        "processes": [
            proc(50, "a", suspicious_mappings=["/tmp/.l/libx.so"]),
            proc(51, "b", suspicious_mappings=["/srv/app/lib.so (deleted)"]),
            proc(52, "c", suspicious_mappings=["/memfd:JITCode (deleted)"]),
            proc(53, "d", suspicious_mappings=["/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)"]),
        ]
    }
    found = of(run([], snap(live)), "process.injected")
    assert sorted((f.summary.split(" ")[0], f.band, f.category) for f in found) == [
        ("a", "high", "compromise indicator"),
        ("b", "high", "compromise indicator"),
        ("c", "medium", "compromise indicator"),
        ("d", "low", "hygiene"),
    ]
