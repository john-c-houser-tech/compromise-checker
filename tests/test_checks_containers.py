"""Container checks (PR 2.9, DESIGN.md §8.13)."""

from test_checks import of, run
from test_checks_live import snap

from checker.snapshot import SnapshotBuilder
from checker.whitelist import Match, matches


def item(**fields):
    base = {
        "image": "docker.io/library/nginx",
        "privileged": False,
        "capabilities": [],
        "host_pid": False,
        "host_network": False,
        "host_ipc": False,
        "devices": [],
        "mounts": [],
        "security_opt": [],
    }
    return base | fields


def test_a_new_privileged_container_is_high_an_old_one_hygiene():
    before = snap(containers={"docker: web": item(), "docker: agent": item(privileged=True)})
    after = snap(
        containers={
            "docker: web": item(),
            "docker: agent": item(privileged=True),
            "docker: cc-priv": item(image="alpine", mounts=["/:/host:rw"]),
            "podman: admin": item(capabilities=["CAP_CHOWN", "CAP_SYS_ADMIN"]),
            "docker: socket": item(mounts=["/var/run/docker.sock:/var/run/docker.sock:rw"]),
        }
    )
    by_key = {f.entities[0]: f for f in of(run([], after, baseline=before), "container.privileged")}
    assert (
        by_key["container:docker: cc-priv"].band,
        by_key["container:docker: cc-priv"].category,
    ) == (
        "high",
        "compromise indicator",
    )
    assert "mounts /" in by_key["container:docker: cc-priv"].summary
    assert by_key["container:docker: agent"].band == "medium"
    assert by_key["container:docker: agent"].category == "hygiene"
    assert "has CAP_SYS_ADMIN" in by_key["container:podman: admin"].summary
    assert "mounts /var/run/docker.sock" in by_key["container:docker: socket"].summary
    assert "container:docker: web" not in by_key


def test_gaining_privilege_since_the_baseline_is_new():
    before = snap(containers={"docker: web": item()})
    after = snap(containers={"docker: web": item(privileged=True)})
    [found] = of(run([], after, baseline=before), "container.privileged")
    assert found.band == "high" and found.variant == "new"
    # No baseline yet: risky, but nothing says it is new.
    [found] = of(run([], after), "container.privileged")
    assert found.band == "medium" and found.variant == "standing"


def test_host_namespaces_since_the_baseline():
    before = snap(containers={"docker: old": item(host_network=True)})
    after = snap(
        containers={
            "docker: old": item(host_network=True),
            "docker: new": item(host_pid=True),
            "docker: changed": item(host_network=True),
        }
    )
    before.sections["containers"].items["docker: changed"] = item()
    found = sorted(
        f.summary.split(";")[0]
        for f in of(run([], after, baseline=before), "container.host_namespace")
    )
    assert found == [
        "docker: changed: the host's network namespace",
        "docker: new: the host's pid namespace",
    ]


def test_new_containers_are_low_and_say_whether_they_run():
    before = snap(containers={"docker: web": item()})
    live = {
        "processes": [{"pid": 4242, "comm": "sleep"}],
        "sockets": [],
        "containers": [
            {"runtime": "docker", "name": "cc-priv", "pid": 4242, "running": True},
            {"runtime": "podman", "name": "stopped", "pid": 999, "running": None},
        ],
    }
    after = snap(
        live,
        containers={"docker: web": item(), "docker: cc-priv": item(), "podman: stopped": item()},
    )
    found = {f.entities[0]: f for f in of(run([], after, baseline=before), "container.new")}
    assert found["container:docker: cc-priv"].band == "low"
    assert "(running)" in found["container:docker: cc-priv"].summary
    assert "(not running)" in found["container:podman: stopped"].summary
    assert of(run([], after), "container.new") == []  # no baseline yet


def test_a_monitoring_agent_can_be_whitelisted_by_container_and_image():
    after = snap(
        containers={
            "docker: cadvisor": item(image="gcr.io/cadvisor/cadvisor", mounts=["/:/rootfs:ro"])
        }
    )
    [finding] = of(run([], after), "container.privileged")
    rule = Match(
        check="container.privileged", container="docker: cadvisor", image="gcr.io/cadvisor/cadvisor"
    )
    assert matches(rule, finding.as_dict())
    assert not matches(
        Match(check="container.privileged", container="docker: cadvisor", image="evil"),
        finding.as_dict(),
    )


def test_the_snapshot_keeps_what_a_container_is_not_its_id():
    from checker.protocol import Record

    builder = SnapshotBuilder()
    data = {
        "runtime": "docker",
        "id": "a" * 64,
        "name": "web",
        "image": "nginx",
        "privileged": False,
        "cap_add": ["NET_ADMIN"],
        "pid_mode": "host",
        "network_mode": "bridge",
        "ipc_mode": None,
        "devices": [],
        "security_opt": [],
        "mounts": [{"source": "/srv", "destination": "/srv", "rw": False}],
        "running": True,
        "pid": 1,
    }
    builder.record(Record(type="record", module="containers", name="container", data=data))
    stored = builder.sections["containers"].items["docker: web"]
    assert stored["host_pid"] is True and stored["capabilities"] == ["NET_ADMIN"]
    assert stored["mounts"] == ["/srv:/srv:ro"]
    assert "id" not in stored and "running" not in stored
    assert builder.live["containers"][0]["id"] == "a" * 64


def test_another_image_under_a_trusted_name_but_not_another_version():
    from checker.checks.containers import repository

    assert repository("nginx:1.25") == repository("docker.io/library/nginx@sha256:abc")
    assert repository("registry.example:5000/app:2") == "registry.example:5000/app"
    assert repository("org/app:1") == "docker.io/org/app"
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
