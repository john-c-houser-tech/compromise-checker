"""Network and data transfer checks (PR 2.4b, DESIGN.md §8.8)."""

from test_checks import accounts, of, run
from test_checks_live import proc, snap


def sock(remote, pids, state="established", protocol="tcp", local=("10.0.0.5", 40000)):
    return {
        "protocol": protocol,
        "local": list(local),
        "remote": list(remote),
        "state": state,
        "pids": list(pids),
        "netns": "net:[1]",
    }


def live(processes, sockets, **more):
    return {"processes": processes, "sockets": sockets, **more}


def test_the_metadata_address_from_anything_but_the_cloud_agent():
    found = of(
        run(
            [],
            snap(
                live(
                    [proc(5, "bash", uids=[0, 0, 0, 0]), proc(6, "cloud-init", uids=[0, 0, 0, 0])],
                    [sock(["169.254.169.254", 80], [5]), sock(["169.254.169.254", 80], [6])],
                ),
                accounts=accounts(),
            ),
        ),
        "net.metadata",
    )
    assert [f.summary.split(" ")[0] for f in found] == ["bash"] and found[0].band == "medium"


def test_a_web_server_account_reaching_directory_services_is_high():
    processes = [
        proc(7, "php-fpm", uids=[33, 33, 33, 33]),
        proc(8, "sssd_be", uids=[0, 0, 0, 0]),
    ]
    sockets = [
        sock(["192.0.2.10", 445], [7], state="syn_sent"),
        sock(["192.0.2.10", 389], [8]),  # a domain-joined host's own lookup
    ]
    found = of(run([], snap(live(processes, sockets), accounts=accounts())), "net.directory")
    assert len(found) == 1 and found[0].band == "high" and "SMB" in found[0].title
    assert "account:www-data" in found[0].entities


def test_ssh_tunnels():
    processes = [
        proc(9, "ssh", cmdline="ssh -N -R 2222:localhost:22 root@203.0.113.9", uids=[0] * 4),
        proc(10, "ssh", cmdline="ssh admin@203.0.113.9 uptime", uids=[0] * 4),
        proc(11, "sshd", ppid=1),
        {**proc(12, "sshd"), "ppid": 11},
    ]
    sockets = [
        sock(["0.0.0.0", 0], [11], state="listen", local=("0.0.0.0", 22)),
        sock(["0.0.0.0", 0], [12], state="listen", local=("127.0.0.1", 2222)),
    ]
    found = of(run([], snap(live(processes, sockets), accounts=accounts())), "net.tunnel")
    titles = sorted(f.title for f in found)
    assert titles == [
        "An SSH client forwarding ports (a tunnel)",
        "An SSH session listening on a port (a remote forward)",
    ]


def test_new_listeners_peers_and_tor():
    before = snap(listeners={}, peers={"curl 203.0.113.0/24 port 443": {"program": "curl"}})
    after = snap(
        listeners={"tcp 0.0.0.0:31337 netns=x": {"programs": ["nc"], "uids": [0], "sockets": 1}},
        peers={
            "curl 203.0.113.0/24 port 443": {"program": "curl"},
            "python3 198.51.100.0/24 port 8443": {"program": "python3"},
            "tor 198.51.100.0/24 port 9001": {"program": "tor"},
        },
    )
    found = run([], after, baseline=before)
    assert [(f.band, f.summary.split(":")[0]) for f in of(found, "net.listener")] == [
        ("low", "tcp 0.0.0.0")
    ]
    peers = {f.variant: f for f in of(found, "net.peer")}
    assert peers["new_destination"].band == "low" and peers["tor"].band == "medium"


def test_resolver_and_firewall_changes():
    before = snap(
        network_files={"/etc/hosts": {"content_sha256": "a"}},
        firewall_rules={"nft: [inet filter / chain input] tcp dport 22 accept": {}},
    )
    after = snap(
        network_files={"/etc/hosts": {"content_sha256": "b"}},
        firewall_rules={
            "nft: [inet filter / chain input] tcp dport 22 accept": {},
            "nft: [inet filter / chain input] tcp dport 31337 accept": {},
        },
    )
    found = of(run([], after, baseline=before), "net.config")
    assert sorted(f.variant for f in found) == ["file", "firewall"]
    firewall = [f for f in found if f.variant == "firewall"][0]
    assert "31337" in firewall.summary and not firewall.entities_complete


def test_promiscuous_interfaces():
    found = of(
        run(
            [],
            snap(
                live([proc(3, "tcpdump")], [sock([], [3], state="", protocol="packet")]),
                interfaces={
                    "eth0": {"promiscuous": True},
                    "docker0": {"promiscuous": True, "bridge": True},
                    "veth": {"promiscuous": True, "bridge_port": True},
                    "eth1": {"promiscuous": False},
                },
            ),
        ),
        "net.promiscuous",
    )
    assert [(f.summary.split(" ")[0], f.band) for f in found] == [("eth0", "low")]
    found = of(run([], snap(interfaces={"eth0": {"promiscuous": True}})), "net.promiscuous")
    assert found[0].band == "medium"


def test_weak_transfer_signs():
    processes = [proc(4, "rclone", uids=[1000] * 4)]
    sockets = [sock(["203.0.113.5", 443], [4]), sock(["10.0.0.9", 443], [4])]
    found = of(
        run(
            [],
            snap(
                live(
                    processes,
                    sockets,
                    interfaces=[
                        {"name": "eth0", "rx_bytes": 10 * 1024**2, "tx_bytes": 5 * 1024**3}
                    ],
                ),
                accounts=accounts(),
                unusual_files={
                    "/tmp/dump.tar.gz": {"size": 200 * 1024**2},
                    "/tmp/small.zip": {"size": 1024},
                },
            ),
        ),
        "net.transfer",
    )
    assert sorted(f.variant for f in found) == ["archive", "counters", "tool"]
    assert all(f.band == "low" for f in found)
