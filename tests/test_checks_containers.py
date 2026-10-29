"""Container checks (PR 2.9, DESIGN.md §8.13)."""

import pytest
from test_checks import of, run
from test_checks_live import snap

from checker.checks.containers import dangers, repository, uninventoried
from checker.protocol import Record
from checker.snapshot import SnapshotBuilder
from checker.whitelist import Match, matches

ID = "a" * 64


def item(**fields):
    base = {
        "image": "docker.io/library/nginx:1.25",
        "mounts": [],
        "mount_sources": [],
        "privileged": False,
        "capabilities": [],
        "host_pid": False,
        "host_network": False,
        "host_ipc": False,
        "devices": [],
        "security_opt": [],
    }
    return base | fields


def by_container(findings):
    return {f.entities[0]: f for f in findings}


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"privileged": True}, {"privileged"}),
        ({"mount_sources": ["/"]}, {"mounts /"}),
        ({"mount_sources": ["/etc/cron.d"]}, {"mounts /etc/cron.d"}),
        ({"mount_sources": ["/var/run"]}, {"mounts /var/run (holds /var/run/docker.sock)"}),
        ({"mount_sources": ["/var/lib/docker"]}, {"mounts /var/lib/docker"}),
        ({"capabilities": ["SYS_MODULE"]}, {"has CAP_SYS_MODULE"}),
        (
            {"capabilities": ["SYS_PTRACE"], "host_pid": True},
            {"has CAP_SYS_PTRACE with the host's processes"},
        ),
        ({"devices": ["/dev/sda"]}, {"has device /dev/sda"}),
        # Ordinary: data folders, ordinary devices, ptrace inside its own processes.
        ({"mount_sources": ["/srv/data", "/var/lib/app"]}, set()),
        ({"devices": ["/dev/fuse", "/dev/net/tun"]}, set()),
        ({"capabilities": ["SYS_PTRACE", "NET_ADMIN"]}, set()),
    ],
)
def test_what_holds_the_host(fields, expected):
    assert dangers(item(**fields)) == expected


def test_a_new_container_holding_the_host_is_high_an_old_one_hygiene():
    before = snap(containers={"docker: web": item(), "docker: agent": item(privileged=True)})
    after = snap(
        containers={
            "docker: web": item(),
            "docker: agent": item(privileged=True),
            "docker: cc-priv": item(image="alpine", mount_sources=["/"]),
        }
    )
    found = by_container(of(run([], after, baseline=before), "container.privileged"))
    assert (
        found["container:docker: cc-priv"].band,
        found["container:docker: cc-priv"].category,
    ) == (
        "high",
        "compromise indicator",
    )
    assert "mounts /" in found["container:docker: cc-priv"].summary
    assert (found["container:docker: agent"].band, found["container:docker: agent"].category) == (
        "medium",
        "hygiene",
    )
    assert "container:docker: web" not in found


def test_a_recreated_container_holding_the_host_as_before_isn_t_new():
    """Podman's own mounts carry the container's ID; a privileged agent
    recreated at every boot holds the host just as at the baseline."""
    before = snap(
        containers={"podman: agent": item(privileged=True, mounts=["/:/host (ro)", "x -> 1"])}
    )
    after = snap(
        containers={"podman: agent": item(privileged=True, mounts=["/:/host (ro)", "x -> 2"])}
    )
    [found] = of(run([], after, baseline=before), "container.privileged")
    assert found.variant == "standing" and found.band == "medium"


def test_gaining_a_danger_since_the_baseline_is_new():
    before = snap(containers={"docker: web": item(privileged=True)})
    after = snap(containers={"docker: web": item(privileged=True, mount_sources=["/"])})
    [found] = of(run([], after, baseline=before), "container.privileged")
    assert found.band == "high" and found.variant == "new" and "mounts /" in found.summary
    # No baseline yet: risky, but nothing says it is new.
    [found] = of(run([], after), "container.privileged")
    assert found.band == "medium" and found.variant == "standing"


def test_host_namespaces_since_the_baseline():
    before = snap(containers={"docker: old": item(host_network=True), "docker: changed": item()})
    after = snap(
        containers={
            "docker: old": item(host_network=True),
            "docker: new": item(host_pid=True),
            "docker: changed": item(host_network=True),
        }
    )
    found = sorted(
        f.summary.split(";")[0]
        for f in of(run([], after, baseline=before), "container.host_namespace")
    )
    assert found == [
        "docker: changed: the host's network namespace",
        "docker: new: the host's pid namespace",
    ]


def live(processes, containers, summary=True):
    data = {"processes": processes, "sockets": [], "containers": containers}
    if summary:
        data["process_summary"] = {}
    return data


def test_new_containers_say_whether_they_run_by_cgroup():
    before = snap(containers={"docker: web": item()})
    processes = [{"pid": 4242, "comm": "sleep", "cgroup": f"0::/system.slice/docker-{ID}.scope"}]
    containers = [
        {"runtime": "docker", "name": "cc-priv", "id": ID},
        {"runtime": "podman", "name": "stopped", "id": "b" * 64},
    ]
    after = snap(
        live(processes, containers),
        containers={"docker: web": item(), "docker: cc-priv": item(), "podman: stopped": item()},
    )
    found = by_container(of(run([], after, baseline=before), "container.new"))
    assert "(running)" in found["container:docker: cc-priv"].summary
    assert "(not running)" in found["container:podman: stopped"].summary
    unknown = snap(live([], containers, summary=False), containers={"docker: cc-priv": item()})
    [found] = of(run([], unknown, baseline=before), "container.new")
    assert "(running state unknown)" in found.summary
    assert of(run([], after), "container.new") == []  # no baseline yet


def test_running_containers_no_state_file_described_are_a_gap():
    processes = [
        {"pid": 1, "cgroup": f"0::/system.slice/docker-{ID}.scope"},
        {"pid": 2, "cgroup": "0::/kubepods.slice/cri-containerd-" + "c" * 64 + ".scope"},
    ]
    assert uninventoried(snap(live(processes, [{"id": ID}]))) == 1
    assert uninventoried(snap(live(processes[:1], [{"id": ID}]))) == 0


def test_another_image_under_a_trusted_name_but_not_another_version():
    assert repository("nginx:1.25") == repository("docker.io/library/nginx@sha256:abc")
    assert repository("docker.io/nginx") == repository("index.docker.io/library/nginx:1")
    assert repository("registry.example:5000/app:2") == "registry.example:5000/app"
    assert repository("localhost/app:1") == "localhost/app"
    assert repository("sha256:" + "a" * 64) != repository("sha256:" + "b" * 64)
    before = snap(
        containers={
            "docker: web": item(image="nginx:1.25"),
            "docker: db": item(image="postgres:16"),
        }
    )
    after = snap(
        containers={
            "docker: web": item(image="docker.io/library/nginx:1.27"),
            "docker: db": item(image="docker.io/evil/postgres:16"),
        }
    )
    [found] = of(run([], after, baseline=before), "container.new")
    assert found.variant == "image_changed" and found.band == "low"
    assert found.summary.startswith("docker: db: postgres:16 → docker.io/evil/postgres:16")


def test_a_monitoring_agent_is_whitelisted_by_container_and_image_together():
    after = snap(
        containers={
            "docker: cadvisor": item(image="gcr.io/cadvisor/cadvisor:v0.49.1", mount_sources=["/"])
        }
    )
    [finding] = of(run([], after), "container.privileged")
    assert "image:gcr.io/cadvisor/cadvisor" in finding.entities  # no tag: survives version bumps
    rule = Match(
        check="container.privileged", container="docker: cadvisor", image="gcr.io/cadvisor/cadvisor"
    )
    assert matches(rule, finding.as_dict()) and rule.narrow()
    other = Match(check="container.privileged", container="docker: cadvisor", image="evil/x")
    assert not matches(other, finding.as_dict())
    # Either alone is chosen by whoever runs containers: it narrows nothing.
    assert not Match(check="container.privileged", container="docker: cadvisor").narrow()
    assert not Match(check="container.privileged", image="gcr.io/cadvisor/cadvisor").narrow()


def test_the_snapshot_keeps_what_a_container_is_not_its_id():
    builder = SnapshotBuilder()
    data = {
        "runtime": "docker",
        "id": ID,
        "name": "web",
        "image": "nginx",
        "privileged": False,
        "capabilities": ["NET_ADMIN"],
        "host_pid": True,
        "host_network": False,
        "host_ipc": False,
        "devices": [],
        "security_opt": [],
        "mounts": [
            {"type": "bind", "source": "/", "destination": "/a:b", "rw": False},
            {"type": "volume", "source": None, "destination": "/data", "rw": True},
        ],
        "running_state": True,
    }
    builder.record(Record(type="record", module="containers", name="container", data=data))
    stored = builder.sections["containers"].items["docker: web"]
    assert stored["host_pid"] is True and stored["capabilities"] == ["NET_ADMIN"]
    # A ":" in a destination can't hide the host's root.
    assert stored["mount_sources"] == ["/"]
    assert stored["mounts"] == ["/ -> /a:b (ro)", "volume -> /data"]
    assert "id" not in stored and "running_state" not in stored
    assert builder.live["containers"][0]["id"] == ID
    # Its host configuration unread: no privilege fields, rather than "no".
    unread = dict(data, name="x")
    for field in ("privileged", "capabilities", "host_pid", "host_network", "host_ipc", "devices"):
        unread.pop(field)
    builder.record(Record(type="record", module="containers", name="container", data=unread))
    assert "privileged" not in builder.sections["containers"].items["docker: x"]
