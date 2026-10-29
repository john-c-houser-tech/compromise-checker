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
        checksum_store={"/var/lib/dpkg/info/x.md5sums": {"sha256": "1"}},
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
        checksum_store={"/var/lib/dpkg/info/x.md5sums": {"sha256": "2"}},  # an update ran
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
        "/usr/bin/ps": ("critical", "compromise indicator"),
        "/usr/lib/x86_64-linux-gnu/security/pam_unix.so": ("critical", "compromise indicator"),
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


def test_a_translation_is_not_a_script_behind_a_second_extension():
    # Symfony ships Polish translations as validators.pl.xlf: .pl there is
    # a language, and .pl runs only as a CGI script, never by AddHandler.
    w = {"place": "/var/www", "type": "-"}
    items = {
        "/var/www/app/vendor/symfony/validator/Resources/translations/validators.pl.xlf": w,
        "/var/www/app/public/uploads/messages.pl.yml": w,
        "/var/www/app/public/img/cat.php5.png": w,
        "/var/www/app/public/uploads/run.pl": w,
    }
    found = of(run([], snap(web_files=items)), "files.web")
    assert sorted((f.title, f.summary) for f in found) == [
        ("A script hidden behind a second extension", "/var/www/app/public/img/cat.php5.png"),
        ("A script in an upload directory", "/var/www/app/public/uploads/run.pl"),
    ]


APP = "/var/www/app"
SERVED = {"/etc/nginx/sites-available/app: root /var/www/app/public": {"folder": f"{APP}/public"}}
NGINX = {"tcp 0.0.0.0:443 netns=net:[1]": {"programs": ["nginx"]}}


def web(items, served=None, listeners=None):
    return snap(
        web_files={p: {"place": "/var/www", "type": "-", **i} for p, i in items.items()},
        web_config={"/etc/nginx/nginx.conf": {}},
        web_served=SERVED if served is None else served,
        listeners=NGINX if listeners is None else listeners,
    )


def test_what_the_web_server_does_not_serve_is_no_web_shell():
    # A Symfony application: nginx serves public/; the libraries, the
    # compiled cache and the repository sit beside it.
    items = {
        f"{APP}/public/index.php": {"sha256": "aa"},
        f"{APP}/public/uploads/x.php": {"sha256": "bb"},
        f"{APP}/public/.env": {},
        f"{APP}/vendor/symfony/cache/Adapter/AbstractAdapter.php": {"sha256": "cc"},
        f"{APP}/var/cache/prod/ContainerRgxCWWf/getRouterService.php": {"sha256": "dd"},
        f"{APP}/.env": {},
        f"{APP}/.git": {"type": "d"},
        f"{APP}/bin/helper": {"kind": "elf"},
    }
    found = of(run([], web(items)), "files.web")
    assert sorted((f.title, f.summary.split(" (")[0]) for f in found) == [
        ("A program in a web root", f"{APP}/bin/helper"),
        ("A script in an upload directory", f"{APP}/public/uploads/x.php"),
        (
            "A secrets or repository file inside a web root",
            f"{APP}/public/.env: a web server may serve it",
        ),
    ]
    # Without knowing what is served, all of it counts, as before.
    for unsure in (
        web(items, served={}),
        web(items, served={"x: root /var/www/$host": {"folder": "/var/www/$host"}}),
        web(items, served={"x: root html": {"folder": "html"}}),
        web(items, listeners={"tcp 0.0.0.0:8080 netns=net:[1]": {"programs": ["node"]}}),
        web(items, listeners={"tcp :::80 netns=net:[1]": {"programs": []}}),
    ):
        titles = [f.title for f in of(run([], unsure), "files.web")]
        assert titles.count("A script in an upload directory") == 3, titles
    incomplete = web(items)
    incomplete.sections["web_served"].complete = False
    assert len(of(run([], incomplete), "files.web")) > 3


def test_a_deploy_is_one_low_finding_per_folder_and_an_edited_front_controller_is_high():
    before = {
        f"{APP}/public/index.php": {"sha256": "aa", "mtime": "1"},
        f"{APP}/var/cache/prod/ContainerAAAA/a.php": {"sha256": "c1"},
        f"{APP}/vendor/twig/twig/src/Environment.php": {"sha256": "t1", "mtime": "1"},
        f"{APP}/src/Kernel.php": {"sha256": "k1"},
    }
    after = {
        # The deploy: a checkout rewrote index.php's times, not its text;
        # a new compiled cache; one library updated; Kernel.php unchanged.
        f"{APP}/public/index.php": {"sha256": "aa", "mtime": "2"},
        **{f"{APP}/var/cache/prod/ContainerBBBB/s{n}.php": {"sha256": f"n{n}"} for n in range(5)},
        f"{APP}/vendor/twig/twig/src/Environment.php": {"sha256": "t2", "mtime": "2"},
        f"{APP}/src/Kernel.php": {"sha256": "k1"},
    }
    found = of(run([], web(after), baseline=web(before)), "files.web")
    assert sorted((f.title, f.band, f.summary.split(":")[0]) for f in found) == [
        (
            "New or changed scripts outside what the web servers serve",
            "low",
            f"1 in {APP}/vendor (a deploy or an update does this)",
        ),
        (
            "New or changed scripts outside what the web servers serve",
            "low",
            f"5 in {APP}/var (a deploy or an update does this)",
        ),
    ]
    # A few lines added to the front controller: a web shell.
    after[f"{APP}/public/index.php"] = {"sha256": "ee", "mtime": "2"}
    found = of(run([], web(after), baseline=web(before)), "files.web")
    [edited] = [f for f in found if f.band == "high"]
    assert edited.title == "A changed script in a web root"
    assert edited.evidence == [
        {"change": ["b0", "web_files", f"{APP}/public/index.php", "changed"]}
    ]


def test_web_shells():
    items = {
        "/var/www/html/index.php": {"place": "/var/www", "type": "-"},
        "/var/www/html/wp-content/uploads/2026/x.php": {"place": "/var/www", "type": "-"},
        "/var/www/html/img/cat.php.jpg": {"place": "/var/www", "type": "-"},
        "/var/www/html/bin": {"place": "/var/www", "type": "-", "kind": "elf"},
        "/var/www/html/.env": {"place": "/var/www", "type": "-"},
        "/var/www/html/root.txt": {"place": "/var/www", "type": "l", "link_target": "/"},
        # RHEL's nginx stock page: links into the distribution's shared data.
        "/var/www/html/index.html": {
            "place": "/var/www",
            "type": "l",
            "link_target": "../../../usr/share/testpage/index.html",
        },
        "/var/www/html/logo.png": {
            "place": "/var/www",
            "type": "l",
            "link_target": "/usr/share/pixmaps/system-noindex-logo.png",
        },
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


UPDATED = {"/var/lib/dpkg/status": {"mtime": (T0 + timedelta(minutes=30)).isoformat()}}


def test_process_executables():
    live = {
        "processes": [
            proc(10, "x", exe="/memfd:payload (deleted)", exe_memfd=True, exe_deleted=True),
            proc(11, "y", exe="/tmp/.y/y"),
            proc(12, "z", exe="/home/eve/z (deleted)", exe_deleted=True),
            proc(13, "nginx", exe="/usr/sbin/nginx (deleted)", exe_deleted=True),
            proc(14, "kworker/0:1", exe="/usr/bin/python3", cmdline="[kworker/0:1]"),
            proc(15, "kworker/0:2", kernel_thread=True),
            proc(16, "q", exe="/dev/mqueue/q"),
            proc(17, "r", exe="/run/lock/.r"),
        ]
    }
    # An update after nginx started: its deleted program was replaced.
    found = of(run([], snap(live, checksum_store=UPDATED)), "process.executable")
    assert sorted((f.summary.split(" ")[2].rstrip("):"), f.band) for f in found) == [
        ("10", "high"),
        ("11", "high"),
        ("12", "high"),
        ("13", "low"),
        ("14", "high"),
        ("16", "high"),
        ("17", "high"),
    ]
    # No update since it started: a program deleted under it is suspicious.
    found = of(run([], snap(live)), "process.executable")
    assert [f.band for f in found if "pid 13" in f.summary] == ["medium"]


def test_hidden_processes():
    live = {"processes": [proc(66, "x", hidden=True, exe="/x"), proc(67, "y", hidden=False)]}
    [finding] = of(run([], snap(live)), "process.hidden")
    assert finding.band == "critical" and "pid 66" in finding.summary


def _tool_tree(collector_stdin=None):
    """sshd listener (29) → session (30) → sudo (31) → the collector (32)."""
    collector = {
        **proc(32, "python3"),
        "ppid": 31,
        "cmdline": "/usr/bin/python3 -I -B -",
        "uids": [0, 0, 0, 0],
    }
    if collector_stdin:
        collector["std_streams"] = {"0": {"kind": "socket", "inode": collector_stdin}}
    return [
        {**proc(29, "sshd"), "ppid": 1},
        {**proc(30, "sshd-session"), "ppid": 29},
        {**proc(31, "sudo"), "ppid": 30},
        collector,
    ]


TCP = {"protocol": "tcp", "state": "established"}


def test_reverse_shells_but_not_the_tools_own_session():
    sockets = [
        {"protocol": "raw", "inode": "555", "remote": ["0.0.0.0", 0], "pids": [21]},
        {**TCP, "inode": "900", "remote": ["198.51.100.9", 4444], "pids": [20]},
        {**TCP, "inode": "901", "remote": ["192.0.2.1", 50000], "pids": [32]},
        {**TCP, "protocol": "tcp6", "inode": "902", "remote": ["2001:db8::9", 443], "pids": [23]},
    ]
    live = {
        "sockets": sockets,
        "processes": [
            proc(20, "bash", std_streams={"0": {"kind": "socket", "inode": "900"}}),
            proc(21, "bash", std_streams={"0": {"kind": "socket", "inode": "555"}}),  # not TCP/UDP
            proc(22, "nginx", std_streams={"0": {"kind": "socket", "inode": "900"}}),  # not a shell
            # A copied bash called httpd, talking over IPv6.
            proc(
                23,
                "httpd",
                exe="/usr/local/sbin/httpd",
                cmdline="bash -i",
                std_streams={"0": {"kind": "socket", "inode": "902"}},
            ),
            # Something unknown whose stdin and stdout are one TCP socket.
            proc(
                24,
                "updater",
                std_streams={
                    "0": {"kind": "socket", "inode": "900"},
                    "1": {"kind": "socket", "inode": "900"},
                },
            ),
            *_tool_tree(collector_stdin="901"),
        ],
    }
    own_login = ev("ssh.login.accepted", own=True, user="scanner", pid=30)
    found = of(run([own_login], snap(live)), "process.reverse_shell")
    assert sorted(f.summary.split(":")[0] for f in found) == [
        "bash (pid 20)",
        "httpd (pid 23)",
        "updater (pid 24)",
    ]


def test_a_forged_login_line_cannot_make_processes_the_tools_own():
    sockets = [{**TCP, "inode": "900", "remote": ["198.51.100.9", 4444], "pids": [20]}]
    shell = proc(20, "bash", std_streams={"0": {"kind": "socket", "inode": "900"}})
    # logger -t sshd --id=1 "Accepted … for scanner …": pid 1, or the listener.
    for forged_pid in (1, 29):
        forged = ev("ssh.login.accepted", own=True, user="scanner", pid=forged_pid)
        live = {"sockets": sockets, "processes": [{**shell, "ppid": 29}, *_tool_tree()]}
        assert len(of(run([forged], snap(live)), "process.reverse_shell")) == 1
    # A fake collector under an attacker's own sshd session the logs don't
    # show as the tool's: still a finding.
    fake = {**proc(40, "python3"), "ppid": 39, "cmdline": "python3 -I -B -", "uids": [0, 0, 0, 0]}
    live = {
        "sockets": sockets,
        "processes": [
            {**proc(29, "sshd"), "ppid": 1},
            {**proc(39, "sshd-session"), "ppid": 29},
            fake,
            {**shell, "ppid": 40},
        ],
    }
    real = ev("ssh.login.accepted", own=True, user="scanner", pid=30)
    assert len(of(run([real], snap(live)), "process.reverse_shell")) == 1
    # A forged line naming the attacker's own sshd session, with no
    # collector in it: nothing there is the tool's.
    live = {
        "sockets": sockets,
        "processes": [
            {**proc(29, "sshd"), "ppid": 1},
            {**proc(39, "sshd-session"), "ppid": 29},
            {**shell, "ppid": 39},
        ],
    }
    forged = ev("ssh.login.accepted", own=True, user="scanner", pid=39)
    assert len(of(run([forged], snap(live)), "process.reverse_shell")) == 1


def test_miners():
    start = T0.isoformat()
    sockets = [
        {**TCP, "inode": "1", "remote": ["100.25.0.9", 3333], "pids": [40]},
        {**TCP, "inode": "2", "remote": ["127.0.0.1", 8888], "pids": [43]},  # a local backend
    ]
    live = {
        "sockets": sockets,
        "processes": [
            proc(40, "systemd-helper", cpu_seconds=6000, start_time=start),  # 2 h, 0.8 cores
            proc(41, "xmrig", cpu_seconds=1),
            proc(42, "postgres", cpu_seconds=6000, start_time=start),  # busy, no pool port
            proc(43, "nginx", cpu_seconds=6000, start_time=start),  # busy, proxying locally
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
    found = of(run([], snap(live, checksum_store=UPDATED)), "process.injected")
    assert sorted((f.summary.split(" ")[0], f.band, f.category) for f in found) == [
        ("a", "high", "compromise indicator"),
        ("b", "high", "compromise indicator"),
        ("c", "medium", "compromise indicator"),
        ("d", "low", "hygiene"),
    ]
    # A deleted system library with no update to explain it.
    found = of(run([], snap(live)), "process.injected")
    assert [f.band for f in found if f.summary.startswith("d ")] == ["high"]


def test_rpm_differences_and_gained_privilege():
    changes = {
        "/usr/bin/find": {
            "package": "findutils",
            "results": ["mode"],
            "expected_mode": "100755",
            "mode": "104755",
        },
        "/usr/bin/ping": {
            "package": "iputils",
            "results": ["capabilities"],
            "expected_capabilities": "cap_net_raw=ep",
            "capabilities": "cap_setuid=ep",
        },
        "/usr/bin/ps": {"package": "procps", "results": ["link"]},
        "/usr/sbin/sshd": {
            "package": "openssh",
            "results": ["group", "owner"],
            "expected_owner": "root",
            "owner": "eve",
        },
        "/usr/share/x": {"package": "x", "results": ["unreadable"]},
    }
    found = of(run([], snap(package_changes=changes)), "package.changed")
    assert sorted((f.summary.split(" ")[0], f.title, f.band) for f in found) == [
        ("/usr/bin/find", "A package file gained set-user-ID or set-group-ID", "high"),
        ("/usr/bin/ping", "A package file's capabilities changed", "high"),
        ("/usr/bin/ps", "A package's link points elsewhere", "high"),
        ("/usr/sbin/sshd", "A package file's owner or group changed", "high"),
    ]
    # dpkg doesn't record capabilities: a capability added to a listed file.
    before = snap(
        OWNERS,
        privileged_files={
            "/usr/bin/ping": {"capabilities": "cap_net_raw=ep", "package": "iputils"}
        },
    )
    after = snap(
        OWNERS,
        privileged_files={
            "/usr/bin/ping": {"capabilities": "cap_net_raw,cap_setuid=ep", "package": "iputils"}
        },
    )
    [finding] = of(run([], after, baseline=before), "files.privileged")
    assert (
        finding.title == "A file gained capabilities since the baseline" and finding.band == "high"
    )


def test_device_nodes_anywhere_and_files_right_in_root(tmp_path):
    items = {"/dev/shm/.k": {"place": "/dev/shm", "type": "c", "uid": 0}}
    [finding] = of(run([], snap(unusual_files=items)), "files.dev")
    assert finding.title == "A device node outside /dev" and finding.band == "high"
    record = {
        "type": "record",
        "module": "unusual_files",
        "name": "privileged_file",
        "data": {"path": "/.s", "setuid": True, "uid": 0, "type": "-"},
    }
    taken = snapshot_of_records(host_records(extra=[record]), tmp_path)
    assert taken.sections["privileged_files"].items["/.s"]["place"] == "/"
    [finding] = of(
        run([], snap(privileged_files=taken.sections["privileged_files"].items)), "files.privileged"
    )
    assert finding.title == "A privileged file outside the system directories"


def test_venvs_and_relative_links_in_web_roots():
    items = {
        "/var/www/app/venv/bin/python3": {
            "place": "/var/www",
            "type": "l",
            "link_target": "/usr/bin/python3",
            "name_flags": ["system_name"],
        },
        "/var/www/html/config.php": {
            "place": "/var/www",
            "type": "l",
            "link_target": "config.prod.php",
        },
        "/var/www/html/root.txt": {"place": "/var/www", "type": "l", "link_target": "/"},
        "/var/www/html/up": {"place": "/var/www", "type": "l", "link_target": "/var/www2/x"},
    }
    found = run([], snap(web_files=items))
    assert of(found, "files.deceptive") == []
    assert sorted(f.summary for f in of(found, "files.web")) == [
        "/var/www/html/root.txt",
        "/var/www/html/up",
    ]


def test_persistence_bands_and_homes_anywhere():
    before = snap(systemd={}, cron={}, startup={}, hooks={}, checksum_store={})
    after = snap(
        systemd={
            "/usr/lib/systemd/system/evil.service": {"type": "-"},
            "/var/lib/postgresql/.config/systemd/user/x.service": {
                "type": "-",
                "home": "/var/lib/postgresql",
            },
        },
        cron={},
        startup={"/etc/ld.so.conf.d/kernel-6.conf": {"type": "-"}},
        hooks={},
        checksum_store={},
    )
    found = of(run([], after, baseline=before), "persistence.changes")
    bands = {f.summary: f.band for f in found}
    assert (
        bands["/usr/lib/systemd/system/evil.service"] == "medium"
    )  # no package install to explain it
    assert bands["/etc/ld.so.conf.d/kernel-6.conf"] == "medium"
    homes = of(run([], after), "persistence.homes")
    assert [f.summary for f in homes] == ["/var/lib/postgresql/.config/systemd/user/x.service"]


def test_one_file_with_several_rpm_differences(tmp_path):
    records = [
        {
            "type": "record",
            "module": "package_verify",
            "name": "package_file_changed",
            "data": {
                "package": "openssh",
                "path": "/usr/sbin/sshd",
                "result": "owner",
                "owner": "eve",
            },
        },
        {
            "type": "record",
            "module": "package_verify",
            "name": "package_file_changed",
            "data": {
                "package": "openssh",
                "path": "/usr/sbin/sshd",
                "result": "mode",
                "expected_mode": "100755",
                "mode": "104755",
            },
        },
    ]
    taken = snapshot_of_records(host_records(extra=records), tmp_path)
    item = taken.sections["package_changes"].items["/usr/sbin/sshd"]
    assert item["results"] == ["mode", "owner"] and item["owner"] == "eve"


def test_fresh_server_false_alarms_are_tuned_down():
    items = {"/usr/lib/python3/dist-packages/twisted/plugins/dropin.cache": {"sha256": "c2" * 32}}
    [finding] = of(run([], snap(OWNERS, unowned_executables=items)), "files.unowned")
    assert finding.band == "info"
    assert finding.title == "An executable no package installed (made by a package after install)"
    live = {"processes": [proc(635, "firewalld", suspicious_mappings=["/memfd:libffi (deleted)"])]}
    [finding] = of(run([], snap(live)), "process.injected")
    assert finding.band == "low"


def test_shared_memory_is_not_a_deleted_file():
    # Shared anonymous memory (PHP's opcache JIT) and System V shared memory
    # show as deleted files in /proc's maps; nothing was on disk.
    for mapping in ("/dev/zero (deleted)", "/SYSV0000a3f1 (deleted)"):
        live = {"processes": [proc(124397, "php-fpm8.4", suspicious_mappings=[mapping])]}
        [finding] = of(run([], snap(live)), "process.injected")
        assert (finding.band, finding.variant) == ("medium", "shared")
    # Alongside a memory-only file, the file is what's reported; alongside a
    # deleted file outside the system directories, that is.
    both = ["/dev/zero (deleted)", "/memfd:payload (deleted)"]
    live = {"processes": [proc(124397, "php-fpm8.4", suspicious_mappings=both)]}
    [finding] = of(run([], snap(live)), "process.injected")
    assert finding.variant == "memory"
    both = ["/dev/zero (deleted)", "/var/www/x.so (deleted)"]
    live = {"processes": [proc(124397, "php-fpm8.4", suspicious_mappings=both)]}
    [finding] = of(run([], snap(live)), "process.injected")
    assert (finding.band, finding.variant) == ("high", "deleted")
    # libffi's closures stay low, but not when shared memory is mapped too.
    both = ["/dev/zero (deleted)", "/memfd:libffi (deleted)"]
    live = {"processes": [proc(635, "firewalld", suspicious_mappings=both)]}
    [finding] = of(run([], snap(live)), "process.injected")
    assert finding.variant == "shared"


def test_a_forked_process_inherits_its_parents_code():
    # (sd-pam) is systemd forked without a new program: it maps what PID 1
    # loaded before the update, though it started after.
    late = (T0 + timedelta(hours=1)).isoformat()
    live = {
        "processes": [
            {
                **proc(
                    1,
                    "systemd",
                    exe="/usr/lib/systemd/systemd",
                    suspicious_mappings=["/usr/lib/x86_64-linux-gnu/libaudit.so.1 (deleted)"],
                ),
                "ppid": 0,
            },
            {
                **proc(
                    1935,
                    "(sd-pam)",
                    exe="/usr/lib/systemd/systemd",
                    start_time=late,
                    suspicious_mappings=["/usr/lib/x86_64-linux-gnu/libaudit.so.1 (deleted)"],
                ),
                "ppid": 1,
            },
        ]
    }
    found = of(run([], snap(live, checksum_store=UPDATED)), "process.injected")
    assert [(f.band, f.category) for f in found] == [("low", "hygiene")] * 2


def test_mode_changes_by_what_they_allow():
    changes = {
        "/boot/efi": {
            "package": "efi-filesystem",
            "results": ["mode"],
            "expected_mode": "40700",
            "mode": "40755",
        },
        "/usr/share/x/data": {
            "package": "x",
            "results": ["mode"],
            "expected_mode": "100644",
            "mode": "100666",
        },
        "/usr/bin/sudo": {
            "package": "sudo",
            "results": ["mode"],
            "expected_mode": "100755",
            "mode": "100775",
        },
    }
    found = of(run([], snap(package_changes=changes)), "package.changed")
    assert sorted((f.summary.split(" ")[0], f.band) for f in found) == [
        ("/boot/efi", "low"),
        ("/usr/bin/sudo", "high"),
        ("/usr/share/x/data", "medium"),
    ]


def test_a_process_that_ran_its_program_afresh_inherits_nothing():
    # sshd re-executes itself per connection: the listener predates the
    # update, but a child started after it can't hold a replaced library
    # by inheritance unless the listener holds it too.
    late = (T0 + timedelta(hours=1)).isoformat()
    lib = "/usr/lib/x86_64-linux-gnu/libaudit.so.1 (deleted)"
    live = {
        "processes": [
            {**proc(600, "sshd", exe="/usr/sbin/sshd"), "ppid": 1},
            {
                **proc(
                    700, "sshd", exe="/usr/sbin/sshd", start_time=late, suspicious_mappings=[lib]
                ),
                "ppid": 600,
            },
        ]
    }
    [finding] = of(run([], snap(live, checksum_store=UPDATED)), "process.injected")
    assert finding.band == "high"


def test_mode_changes_that_open_things_up():
    def mode(path, expected, now):
        return {path: {"package": "p", "results": ["mode"], "expected_mode": expected, "mode": now}}

    cases = {
        **mode("/etc/shadow", "100000", "100644"),
        **mode("/tmp", "41777", "40777"),
        **mode("/root", "40550", "40555"),
        **mode("/usr/lib/x/f", "100644", "10644"),  # a regular file became a FIFO
        **mode("/usr/share/x/g", "100644", "?"),
    }
    found = of(run([], snap(package_changes=cases)), "package.changed")
    assert sorted((f.summary.split(" ")[0], f.band) for f in found) == [
        ("/etc/shadow", "high"),
        ("/root", "medium"),
        ("/tmp", "high"),
        ("/usr/lib/x/f", "medium"),
        ("/usr/share/x/g", "medium"),
    ]


def test_a_set_user_id_shell_in_a_scratch_place_is_a_privileged_file():
    # /tmp is listed whole as unusual files, so the privileged search skips it.
    items = {
        "/tmp/.cc-sh": {"place": "/tmp", "type": "-", "kind": "elf", "setuid": True, "uid": 0},
        "/tmp/plain": {"place": "/tmp", "type": "-", "kind": "elf"},
    }
    web = {
        "/var/www/html/x.cgi": {"place": "/var/www", "type": "-", "capabilities": "cap_setuid=ep"}
    }
    found = of(run([], snap(OWNERS, unusual_files=items, web_files=web)), "files.privileged")
    assert sorted((f.summary.split(":")[0], f.band) for f in found) == [
        ("/tmp/.cc-sh", "high"),
        ("/var/www/html/x.cgi", "high"),
    ]
    # And as new since the baseline, from its own section's changes.
    before = snap(OWNERS, unusual_files={}, web_files={}, privileged_files={})
    after = snap(OWNERS, unusual_files=items, web_files={}, privileged_files={})
    [finding] = of(run([], after, baseline=before), "files.privileged")
    assert finding.title == "A new privileged file since the baseline"
    assert finding.evidence == [{"change": ["b0", "unusual_files", "/tmp/.cc-sh", "added"]}]


def test_a_different_program_cannot_inherit_a_deleted_library():
    # cron started after the update maps the old library: it can't have
    # inherited it from PID 1 (it loaded its own) — someone swapped it back.
    late = (T0 + timedelta(hours=1)).isoformat()
    lib = "/usr/lib/systemd/libsystemd-shared.so (deleted)"
    systemd = proc(1, "systemd", exe="/usr/lib/systemd/systemd", suspicious_mappings=[lib])
    cron = proc(700, "cron", exe="/usr/sbin/cron", start_time=late, suspicious_mappings=[lib])
    live = {"processes": [{**systemd, "ppid": 0}, {**cron, "ppid": 1}]}
    found = of(run([], snap(live, checksum_store=UPDATED)), "process.injected")
    assert {f.summary.split(" ")[0]: f.band for f in found} == {"systemd": "low", "cron": "high"}


def test_a_privileged_file_moving_between_sections_is_not_new():
    item = {"place": "/tmp", "type": "-", "kind": "elf", "setuid": True, "uid": 0}
    before = snap(OWNERS, privileged_files={"/tmp/.x": item}, unusual_files={}, web_files={})
    after = snap(OWNERS, privileged_files={}, unusual_files={"/tmp/.x": item}, web_files={})
    [finding] = of(run([], after, baseline=before), "files.privileged")
    assert finding.title == "A privileged file outside the system directories" and not finding.new
