"""Shipped profiles and the calibration fixes (PR 2.10)."""

from datetime import timedelta

import pytest
from test_checks import T0, ev, of, run
from test_checks_live import proc, snap

from checker.events import classify
from checker.whitelist import PROFILES, Layer, build, matches, profile_file, read_layer

SHIPPED = sorted(p.stem for p in PROFILES.glob("*.yaml"))


def test_the_shipped_profiles():
    assert SHIPPED == ["base", "build", "database", "mail", "web"]


@pytest.mark.parametrize("name", SHIPPED)
def test_every_profile_rule_names_its_reason_and_owner(name):
    layer = read_layer(profile_file(name))  # validates checks and variants too
    assert layer.rules
    for rule in layer.rules:
        assert rule.owner == "Compromise Checker defaults"
        assert rule.reason and rule.expires == "never"
        assert rule.id.startswith(name + "-")
        assert rule.match.narrow() or rule.broad


def rules(name):
    return {r.id: r for r in read_layer(profile_file(name)).rules}


def test_base_lets_firewalld_s_libffi_through_but_no_other_injection():
    def injected(comm, exe, mapping):
        p = proc(635, comm, exe=exe, suspicious_mappings=[mapping])
        found = of(run([], snap({"processes": [p], "sockets": []})), "process.injected")
        return found[0].as_dict()

    rule = rules("base")["base-firewalld-libffi"]
    assert matches(
        rule.match, injected("firewalld", "/usr/bin/python3.9", "/memfd:libffi (deleted)")
    )
    # Another Python program, a scratch file, a Python outside the system: not.
    assert not matches(
        rule.match, injected("loader", "/usr/bin/python3.9", "/memfd:libffi (deleted)")
    )
    assert not matches(
        rule.match, injected("firewalld", "/usr/bin/python3.9", "/tmp/.x.so (deleted)")
    )
    assert not matches(rule.match, injected("firewalld", "/tmp/python3", "/memfd:libffi (deleted)"))


def test_base_lets_php_fpm_s_opcache_through_but_no_other_injection():
    def injected(comm, exe, *mappings):
        p = proc(124397, comm, exe=exe, suspicious_mappings=list(mappings))
        found = of(run([], snap({"processes": [p], "sockets": []})), "process.injected")
        return found[0].as_dict()

    rule = rules("base")["base-php-fpm-opcache"]
    assert matches(
        rule.match, injected("php-fpm8.4", "/usr/sbin/php-fpm8.4", "/dev/zero (deleted)")
    )
    # A memory-only file, a PHP-FPM outside the system: not.
    assert not matches(
        rule.match,
        injected("php-fpm8.4", "/usr/sbin/php-fpm8.4", "/dev/zero (deleted)", "/memfd:x (deleted)"),
    )
    assert not matches(rule.match, injected("php-fpm8.4", "/tmp/php-fpm8.4", "/dev/zero (deleted)"))


def test_a_profile_named_in_two_layers_applies_once(tmp_path, monkeypatch):
    from checker.whitelist import Layer, build

    layers = [
        ("global", "global.yaml", Layer(profiles=["base"])),
        ("host web01", "hosts/web01.yaml", Layer(profiles=["base", "web", "base"])),
    ]
    whitelist = build(layers)
    ids = [placed.rule.id for placed in whitelist.rules]
    assert len(ids) == len(set(ids)) and "base-firewalld-libffi" in ids


def test_web_lets_its_application_s_mail_through_not_volume():
    rule = rules("web")["web-app-mail-www-data"]
    accounts = {"www-data": {"uid": 33}}
    events = [ev("mail.submitted", 1, source="mail_journal", queue_id="A", uid=33)]
    [found] = of(run(events, snap(accounts=accounts)), "mail.web_user")
    assert matches(rule.match, found.as_dict())
    assert all(r.match.check != "mail.volume" for r in rules("web").values())


# --- Accounts a package creates ------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "fields"),
    [
        (
            "new user: name=postfix, UID=110, GID=117, home=/var/spool/postfix,"
            " shell=/usr/sbin/nologin, from=none",
            {"user": "postfix", "uid": "110", "shell": "/usr/sbin/nologin", "origin": "none"},
        ),
        (
            "new user: name=eve, UID=1001, GID=1001, home=/home/eve, shell=/bin/bash,"
            " from=/dev/pts/0",
            {"user": "eve", "uid": "1001", "shell": "/bin/bash", "origin": "/dev/pts/0"},
        ),
        ("new user: name=old, UID=5", {"user": "old", "uid": "5"}),
    ],
)
def test_useradd_lines(line, fields):
    kind, found = classify("useradd", line)
    assert kind == "account.created"
    assert found == fields


def created(user, uid, shell, origin, minutes=1):
    fields = {"user": user, "uid": uid, "shell": shell}
    if origin is not None:
        fields["origin"] = origin
    return ev("account.created", minutes, **fields)


INSTALLED = {
    "postfix amd64": {"version": "3.8", "installed": (T0 + timedelta(minutes=2)).timestamp()}
}


def bands_of(events, **sections):
    sections.setdefault("packages", INSTALLED)
    return {
        f.summary.split(": ")[1].split(" ")[0]
        if "group" not in f.summary
        else f.summary.split(": ")[1]: f.band
        for f in of(run(events, snap(**sections)), "account.log_changes")
    }


def test_an_account_a_package_install_made_is_low_any_other_medium():
    bands = bands_of(
        [
            created("postfix", "110", "/usr/sbin/nologin", "none"),
            # A login shell, a terminal, a person's UID, UID 0, no origin
            # logged, a web account (a web shell's), long after any install.
            created("svc", "998", "/bin/bash", "none"),
            created("svc2", "997", "/usr/sbin/nologin", "/dev/pts/0"),
            created("eve", "1001", "/usr/sbin/nologin", "none"),
            created("toor", "0", "/usr/sbin/nologin", "none"),
            created("old", "996", "/usr/sbin/nologin", None),
            created("nginx", "995", "/sbin/nologin", "none"),  # RHEL's nginx package makes it
            created("late", "995", "/usr/sbin/nologin", "none", minutes=120),
        ]
    )
    assert bands == {
        "postfix": "low",
        "svc": "medium",
        "svc2": "medium",
        "eve": "medium",
        "toor": "medium",
        "old": "medium",
        "nginx": "low",
        "late": "medium",
    }


def test_a_scripted_account_with_no_install_nearby_stays_medium():
    events = [created("backdoor", "990", "/usr/sbin/nologin", "none")]
    assert bands_of(events, packages={}) == {"backdoor": "medium"}


def test_an_account_given_a_login_shell_since_isn_t_a_package_s():
    events = [created("postfix", "110", "/usr/sbin/nologin", "none")]
    accounts = {"postfix": {"uid": 110, "shell": "/bin/bash"}}
    assert bands_of(events, accounts=accounts) == {"postfix": "medium"}


def test_a_package_account_joining_a_group_is_low():
    accounts = {
        "postfix": {"uid": 89, "shell": "/sbin/nologin"},
        "eve": {"uid": 1001, "shell": "/bin/bash"},
        "www-data": {"uid": 33, "shell": "/usr/sbin/nologin"},
    }
    events = [
        ev("group.member_added", 1, user="postfix", group="mail"),
        ev("group.member_added", 2, user="eve", group="mail"),
        ev("group.member_added", 3, user="postfix", group="wheel"),  # a root group: high
        ev("group.member_added", 3, user="postfix", group="libvirt"),  # root-equivalent too
        ev("group.member_added", 4, user="www-data", group="adm"),  # a web account: never
    ]
    assert bands_of(events, accounts=accounts) == {
        "postfix group mail": "low",
        "eve group mail": "medium",
        "postfix group wheel": "high",
        "postfix group libvirt": "high",
        "www-data group adm": "medium",
    }


# --- (sd-pam) and what it inherits from PID 1 -------------------------------------------


def test_sd_pam_holds_what_pid_1_loaded():
    boot, update, login = T0, T0 + timedelta(hours=1), T0 + timedelta(hours=2)
    lib = "/usr/lib/x86_64-linux-gnu/libaudit.so.1.0.0 (deleted)"
    processes = [
        proc(
            1,
            "systemd",
            exe="/usr/lib/systemd/systemd",
            start_time=boot.isoformat(),
            suspicious_mappings=[lib],
            ppid=0,
        ),
        # The user manager: a fresh program, the new library.
        proc(900, "systemd", exe="/usr/lib/systemd/systemd", start_time=login.isoformat(), ppid=1),
        proc(
            901,
            "(sd-pam)",
            exe="/usr/lib/systemd/systemd",
            start_time=login.isoformat(),
            suspicious_mappings=[lib],
            ppid=900,
        ),
    ]
    checksum = {"/var/lib/dpkg/info/libaudit1.md5sums": {"mtime": update.isoformat()}}
    found = of(
        run([], snap({"processes": processes, "sockets": []}, checksum_store=checksum)),
        "process.injected",
    )
    by_pid = {f.summary.split("(pid ")[1].split(")")[0]: f for f in found}
    assert by_pid["901"].variant == "replaced" and by_pid["901"].band == "low"
    # Another program holding PID 1's library isn't let off that way.
    processes[2] = proc(
        901,
        "evil",
        exe="/tmp/evil",
        start_time=login.isoformat(),
        suspicious_mappings=[lib],
        ppid=900,
    )
    found = of(
        run([], snap({"processes": processes, "sockets": []}, checksum_store=checksum)),
        "process.injected",
    )
    [evil] = [f for f in found if "pid 901" in f.summary]
    assert (evil.variant, evil.band) == ("deleted", "high")
    # PID 1's own program run by hand, holding its library: not (sd-pam).
    processes[2] = proc(
        901,
        "systemd",
        exe="/usr/lib/systemd/systemd",
        start_time=login.isoformat(),
        suspicious_mappings=[lib],
        ppid=900,
    )
    found = of(
        run([], snap({"processes": processes, "sockets": []}, checksum_store=checksum)),
        "process.injected",
    )
    [other] = [f for f in found if "pid 901" in f.summary]
    assert (other.variant, other.band) == ("deleted", "high")


def test_a_profile_is_recorded_by_its_place_in_the_package_not_where_it_is_installed():
    """The set's hash (recorded in every assessment, pinned by the golden
    cases) must not depend on the machine."""
    wl = build([("site", "site.yaml", Layer(profiles=["base"]))])
    files = {p.file for p in wl.rules}
    assert files == {"checker/profiles/base.yaml"}
