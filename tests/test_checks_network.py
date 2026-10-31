"""Network and data transfer checks (PR 2.4b, DESIGN.md §8.8)."""

import pytest
from test_checks import accounts, of, run
from test_checks_live import proc, snap

from checker.checks.network import ssh_forwarding

ROOT = [0, 0, 0, 0]


def sock(remote, pids, state="established", protocol="tcp", local=("10.0.0.5", 40000), uid=0):
    return {
        "protocol": protocol,
        "local": list(local),
        "remote": list(remote),
        "state": state,
        "pids": list(pids),
        "netns": "net:[1]",
        "uid": uid,
    }


def live(processes, sockets, **more):
    return {"processes": processes, "sockets": sockets, **more}


def found(check, processes=(), sockets=(), **sections):
    return of(
        run([], snap(live(list(processes), list(sockets)), accounts=accounts(), **sections)),
        check,
    )


# --- the metadata address ---------------------------------------------------------------------


def test_metadata_by_the_file_a_process_runs_not_its_name():
    processes = [
        proc(5, "bash", exe="/usr/bin/bash", uids=ROOT),
        proc(
            6,
            "cloud-init",
            exe="/usr/bin/python3",
            cmdline="/usr/bin/python3 /usr/bin/cloud-init",
            uids=ROOT,
        ),
        proc(
            7,
            "python3",
            exe="/usr/bin/python3",
            cmdline="python3 -u /usr/sbin/waagent -run-exthandlers",
            uids=ROOT,
        ),
        # A copy of curl renamed to look like the agent, outside the system dirs.
        proc(8, "cloud-init", exe="/tmp/cloud-init", uids=ROOT),
        proc(9, "aws", exe="/usr/local/bin/aws", uids=ROOT),
    ]
    sockets = [sock(["169.254.169.254", 80], [p["pid"]]) for p in processes]
    bands = {
        f.summary.split(" (")[0] + f" {f.summary.split('pid ')[1].split(',')[0]}": f.band
        for f in found("net.metadata", processes, sockets)
    }
    # A root shell is medium even from /usr/bin; an SDK-like program, low.
    assert bands == {"bash 5": "medium", "cloud-init 8": "medium", "aws 9": "low"}


def test_the_ipv6_metadata_address_and_mapped_forms():
    processes = [proc(5, "x", exe="/home/eve/x", uids=[1000] * 4)]
    for remote in ("fd00:ec2::254", "::ffff:169.254.169.254"):
        assert found("net.metadata", processes, [sock([remote, 80], [5])])[0].band == "medium"


def test_a_closing_connection_counts_but_a_listener_doesnt():
    processes = [proc(5, "x", exe="/home/eve/x", uids=[1000] * 4)]
    assert found("net.metadata", processes, [sock(["169.254.169.254", 80], [5], "close_wait")])
    assert not found("net.metadata", processes, [sock(["169.254.169.254", 80], [5], "time_wait")])


def test_a_socket_whose_process_isnt_visible_still_counts():
    [finding] = found("net.metadata", [], [sock(["169.254.169.254", 80], [], uid=33)])
    assert "an unseen process" in finding.summary and "account:www-data" in finding.entities


# --- directory services -------------------------------------------------------------------------


def test_smb_and_winrm_from_a_web_account_are_high_ldap_and_kerberos_medium():
    processes = [
        proc(7, "php-fpm", exe="/usr/sbin/php-fpm8.3", uids=[33] * 4),
        proc(8, "sssd_be", exe="/usr/libexec/sssd/sssd_be", uids=ROOT),
    ]
    sockets = [
        sock(["192.0.2.10", 445], [7], state="syn_sent"),
        sock(["192.0.2.10", 389], [7]),
        sock(["192.0.2.10", 389], [8]),  # a domain-joined host's own lookup
    ]
    bands = sorted((f.variant, f.band) for f in found("net.directory", processes, sockets))
    assert bands == [("ldap_kerberos", "medium"), ("smb_winrm", "high")]


def test_the_effective_uid_decides_the_account():
    # Judged by the effective uid: a setuid helper run by www-data acts as root.
    processes = [proc(7, "x", exe="/usr/bin/x", uids=[33, 0, 0, 0])]
    assert not found("net.directory", processes, [sock(["192.0.2.10", 445], [7])])


# --- tunnels ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cmdline", "forwards"),
    [
        ("ssh -N -R 2222:localhost:22 root@203.0.113.9", "-R 2222:localhost:22"),
        ("ssh -fNR 2222:localhost:22 h", "-R 2222:localhost:22"),
        ("ssh -Llocalhost:80:intranet:80 h", "-L localhost:80:intranet:80"),
        ("ssh -D 1080 h", "-D 1080"),
        ("ssh -J jump h", "-J jump"),
        ("ssh -W intranet:22 h", "-W intranet:22"),
        ("ssh -o RemoteForward=2222:localhost:22 h", "-o RemoteForward=2222:localhost:22"),
        ("ssh -p 2222 -i /root/k -o LocalForward=8080:x:80 h", "-o LocalForward=8080:x:80"),
        ("ssh admin@h ls -lR", None),
        ("ssh h cp -R a b", None),
        ("ssh -p 2222 h grep -RD x", None),
        ("ssh -o ServerAliveInterval=30 h", None),
        ("ssh h", None),
    ],
)
def test_ssh_forwarding_is_read_as_ssh_reads_its_options(cmdline, forwards):
    assert ssh_forwarding(cmdline) == forwards


def test_tunnels_client_and_remote_forward_but_not_x11():
    processes = [
        proc(9, "ssh", exe="/usr/bin/ssh", cmdline="ssh -N -R 2222:localhost:22 root@h", uids=ROOT),
        proc(10, "ssh", exe="/usr/bin/ssh", cmdline="ssh admin@h uptime", uids=ROOT),
        proc(11, "sshd", ppid=1),
        {**proc(12, "sshd-session"), "ppid": 11},
    ]
    sockets = [
        sock(["0.0.0.0", 0], [11], state="listen", local=("0.0.0.0", 22)),
        sock(["0.0.0.0", 0], [12], state="listen", local=("127.0.0.1", 2222)),
        sock(["0.0.0.0", 0], [12], state="listen", local=("127.0.0.1", 6010)),  # X11
    ]
    titles = sorted(f.title for f in found("net.tunnel", processes, sockets))
    assert titles == [
        "An SSH client forwarding ports (a tunnel)",
        "An SSH session listening on a port (a remote forward)",
    ]


# --- baseline-based ------------------------------------------------------------------------------


def test_new_listeners_peers_and_tor():
    before = snap(
        listeners={"tcp 0.0.0.0:8080 netns=net:[1]": {"programs": ["docker-proxy"]}},
        peers={"curl 203.0.113.0/24 port 443": {"program": "curl"}},
    )
    after = snap(
        listeners={
            "tcp 0.0.0.0:8080 netns=net:[2]": {"programs": ["docker-proxy"]},  # restarted
            "tcp 0.0.0.0:31337 netns=net:[1]": {"programs": ["nc"], "uids": [0], "sockets": 1},
        },
        peers={
            "curl 203.0.113.0/24 port 443": {"program": "curl"},
            "python3 198.51.100.0/24 port 8443": {"program": "python3"},
            "minio 198.51.100.0/24 port 9001": {"program": "minio"},
            "tor 198.51.100.0/24 port 9001": {"program": "tor"},
        },
        accounts=accounts(),
    )
    results = run([], after, baseline=before)
    listeners = of(results, "net.listener")
    assert [f.summary.split(":")[0] + ":" + f.summary.split(":")[1] for f in listeners] == [
        "tcp 0.0.0.0:31337 netns=net"
    ]
    assert "address:0.0.0.0" in listeners[0].entities and "account:root" in listeners[0].entities
    peers = {f.summary.split(" ")[0]: f for f in of(results, "net.peer")}
    assert peers["tor"].band == "medium" and peers["tor"].variant == "tor"
    assert peers["minio"].band == "low" and "Tor relay port" in peers["minio"].summary
    assert "address:198.51.100.0" in peers["python3"].entities


def test_resolver_and_firewall_changes_both_directions():
    before = snap(
        network_files={"/etc/hosts": {"content_sha256": "a"}},
        firewall_rules={
            "nft: [inet filter / chain input] tcp dport 22 accept": {},
            "nft: [inet filter / chain input] tcp dport 23 accept": {},
        },
    )
    after = snap(
        network_files={"/etc/hosts": {"content_sha256": "b"}},
        firewall_rules={
            "nft: [inet filter / chain input] tcp dport 22 accept": {},
            "nft: [inet filter / chain input] tcp dport 31337 accept": {},
        },
    )
    results = of(run([], after, baseline=before), "net.config")
    assert sorted(f.title for f in results) == [
        "A network configuration file was changed",
        "Firewall rules added since the baseline",
        "Firewall rules removed since the baseline",
    ]


# --- interfaces and transfer ---------------------------------------------------------------------


def test_promiscuous_interfaces():
    processes = [proc(3, "tcpdump", exe="/usr/bin/tcpdump")]
    sockets = [sock([], [3], state="", protocol="packet")]
    interfaces = {
        "eth0": {"promiscuous": True},
        "docker0": {"promiscuous": True, "bridge": True},
        "vethx": {"promiscuous": True, "bridge_port": True},
        "ovs-port": {"promiscuous": True, "master": True},
        "eth1": {"promiscuous": False},
    }
    results = found("net.promiscuous", processes, sockets, interfaces=interfaces)
    assert [(f.summary.split(" ")[0], f.band) for f in results] == [("eth0", "low")]
    # A sniffer merely named tcpdump doesn't lower anything.
    fake = [proc(3, "tcpdump", exe="/tmp/x")]
    assert found("net.promiscuous", fake, sockets, interfaces=interfaces)[0].band == "medium"


def test_weak_transfer_signs():
    processes = [proc(4, "rclone", exe="/usr/bin/rclone", uids=[1000] * 4)]
    sockets = [sock(["203.0.113.5", 443], [4]), sock(["10.0.0.9", 443], [4])]
    interfaces = [
        {"name": "eth0", "rx_bytes": 10 * 1024**2, "tx_bytes": 5 * 1024**3},
        {"name": "docker0", "rx_bytes": 1, "tx_bytes": 5 * 1024**3},
        {"name": "lo", "rx_bytes": 1, "tx_bytes": 5 * 1024**3},
        {"name": "eth1", "rx_bytes": 1, "tx_bytes": 900 * 1024**2},  # under 1 GB
    ]
    results = of(
        run(
            [],
            snap(
                live(processes, sockets, interfaces=interfaces),
                accounts=accounts(),
                unusual_files={
                    "/tmp/dump.tar.zst": {"size": 200 * 1024**2},
                    "/tmp/small.zip": {"size": 1024},
                },
            ),
        ),
        "net.transfer",
    )
    assert sorted((f.variant, f.summary.split(":")[0].split(" ")[0]) for f in results) == [
        ("archive", "/tmp/dump.tar.zst"),
        ("counters", "eth0"),
        ("tool", "rclone"),
    ]


def test_a_set_in_a_table_named_like_fail2bans_needs_it_running():
    rules = {
        "nft: [inet f2b-table / set addr-set-sshd] (managed by other software: rules not"
        " compared)": {},
    }
    rules[
        "nft: [inet f2b-table / set addr6-set-sshd] (managed by other software: rules not compared)"
    ] = {}  # a table's several sets: said once
    results = found("net.managed_chain", [], [], firewall_rules=rules)
    assert [f.summary.split(":")[0] for f in results] == ["f2b-table"]


def test_a_rules_comment_cant_read_as_a_managed_chain():
    rules = {'nft: [inet filter / chain c] accept comment "[a f2b-x / set c] (managed by other'
             ' software: rules not compared)"': {}}  # fmt: skip
    assert found("net.managed_chain", [], [], firewall_rules=rules) == []
    ending = {"nft: accept [a f2b-x / set c] (managed by other software: rules not compared)": {}}
    assert found("net.managed_chain", [], [], firewall_rules=ending) == []


def test_a_managed_looking_chain_whose_owner_isnt_running():
    rules = {
        "nft: [ip filter / chain DOCKER] (managed by other software: rules not compared)": {},
        "nft: [ip filter / chain f2b-x] (managed by other software: rules not compared)": {},
    }
    dockerd = proc(2, "dockerd", exe="/usr/bin/dockerd", uids=ROOT)
    results = found("net.managed_chain", [dockerd], [], firewall_rules=rules)
    assert [f.summary.split(":")[0] for f in results] == ["f2b-x"]
    # A process merely named fail2ban-server doesn't vouch for the chain.
    fake = proc(3, "fail2ban-server", exe="/tmp/x", uids=ROOT)
    assert len(found("net.managed_chain", [dockerd, fake], [], firewall_rules=rules)) == 1
    real = proc(
        4,
        "fail2ban-server",
        exe="/usr/bin/python3",
        cmdline="/usr/bin/python3 /usr/bin/fail2ban-server -xf start",
        uids=ROOT,
    )
    assert not found("net.managed_chain", [dockerd, real], [], firewall_rules=rules)


def test_docker_user_is_compared_rule_by_rule():
    from checker.snapshot import firewall_lines

    out = firewall_lines(["*filter", "-A DOCKER-USER -p tcp --dport 31337 -j ACCEPT"])
    assert out == [
        "[filter] *filter",
        "[filter / chain DOCKER-USER] -A DOCKER-USER -p tcp --dport 31337 -j ACCEPT",
    ]


def test_a_shared_uid_is_named_after_its_first_account():
    from test_checks import Context  # noqa: F401 - the run helper builds one

    from checker.checks.network import _accounts_by_uid

    snapshot = snap(
        accounts={
            "cc-toor": {"uid": 0, "line": 30},
            "root": {"uid": 0, "line": 1},
            "a": {"uid": 1001, "line": 5},
            "b": {"uid": 1001, "line": 4},
        }
    )

    class Ctx:
        def items(self, section):
            return snapshot.sections[section].items

    names = _accounts_by_uid(Ctx())
    assert names[0] == "root" and names[1001] == "b"


@pytest.mark.parametrize(
    "exe", ["/usr/bin/sleep", "/usr/bin/curl", "/usr/bin/nc", "/usr/bin/python3"]
)
def test_generic_tools_reaching_the_metadata_address_stay_medium(exe):
    processes = [proc(5, exe.rsplit("/", 1)[-1], exe=exe, cmdline=exe, uids=ROOT)]
    [finding] = found("net.metadata", processes, [sock(["169.254.169.254", 80], [5])])
    assert finding.band == "medium"


def rule_check(items, diff=None, live=None):
    from checker.checks import Context
    from checker.checks.network import config, managed_chains
    from checker.snapshot import Section, Snapshot

    snapshot = Snapshot({}, {"firewall_rules": Section(items)}, live or {})
    context = Context("h", "b", [], snapshot, since_baseline={}, baseline_id="a")
    context.since_baseline = {"firewall_rules": diff} if diff else {}
    managed_chains(context)
    return config(context), context.gaps


def test_rules_read_only_as_text_are_said():
    assert any("only as text" in g for g in rule_check({"nft: [inet t] x": {}})[1])
    both = {"nft: [inet t] x": {}, "nft-json: [inet t] {}": {}}
    assert rule_check(both)[1] == []


def json_change(how):
    return {"added": {}, "removed": {}, "changed": {}, "comparable": True, "notes": [],
            "nft_json": how}  # fmt: skip


def test_json_starting_is_a_gap_and_json_lost_a_finding():
    from checker.snapshot import NFT_JSON_LOST, NFT_JSON_STARTED

    found_now, gaps = rule_check({"nft-json: x": {}, "nft: y": {}}, json_change(NFT_JSON_STARTED))
    assert not found_now and any("a new baseline compares both" in g for g in gaps)
    live = {"nft_json_unread": "too long"}
    found_now, _ = rule_check({"nft: y": {}}, json_change(NFT_JSON_LOST), live)
    assert [f.variant for f in found_now] == ["json_lost"] and "too long" in found_now[0].summary
