"""Containers (DESIGN.md §8.13): privileged containers and those mounting
the host's root or a container runtime's socket, containers sharing the
host's process or network namespace, and new containers.

From the runtimes' state files (decision 4), compared by name: a redeploy
replaces a container's ID, not what it is."""

from __future__ import annotations

from typing import Any

from checker.checks import COMPROMISE, HYGIENE, Context, Finding, check

# Mount sources that give a container the host: its root, its
# configuration, root's home, the runtimes' sockets (a container that can
# talk to dockerd can start a privileged one).
HOST_MOUNTS = {
    "/",
    "/etc",
    "/root",
    "/boot",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
}
ADMIN_CAPABILITIES = {"SYS_ADMIN", "CAP_SYS_ADMIN", "ALL"}


def _dangers(item: dict[str, Any]) -> list[str]:
    """What gives the container the host, if anything."""
    found = []
    if item.get("privileged"):
        found.append("privileged")
    for mount in item.get("mounts") or []:
        source = str(mount).rsplit(":", 2)[0].rstrip("/") or "/"
        if source in HOST_MOUNTS:
            found.append(f"mounts {source}")
    if ADMIN_CAPABILITIES & set(item.get("capabilities") or []):
        found.append("has CAP_SYS_ADMIN")
    return found


def _running(context: Context) -> dict[str, bool]:
    """Each container's running state: its process alive at collection."""
    pids = {p.get("pid") for p in context.snapshot.live.get("processes", [])}
    state = {}
    for container in context.snapshot.live.get("containers", []):
        key = f"{container.get('runtime')}: {container.get('name')}"
        pid = container.get("pid")
        state[key] = bool(pid) and pid in pids and container.get("running") is not False
    return state


def _entities(key: str, item: dict[str, Any]) -> list[str]:
    return [f"container:{key}"] + ([f"image:{item['image']}"] if item.get("image") else [])


def _is_new(context: Context, key: str, fields: tuple[str, ...]) -> bool:
    """Added since the baseline, or changed in one of these fields."""
    diff = context.changes("containers")
    if diff is None:
        return False
    if key in diff["added"]:
        return True
    return any(f in (diff["changed"].get(key) or {}) for f in fields)


def _ref(context: Context, key: str) -> dict[str, Any]:
    diff = context.changes("containers") or {"added": {}, "changed": {}}
    if key in diff["added"]:
        return context.change_ref("containers", key, "added")
    if key in diff["changed"]:
        return context.change_ref("containers", key, "changed")
    return {"item": ["containers", key]}


@check(
    "container.privileged",
    "A privileged container, or one mounting the host's root or a runtime's socket",
    variants=("new", "standing"),
)
def privileged(context: Context) -> list[Finding]:
    """High if new since the baseline (added, or given it since): a way
    onto the host. Otherwise medium hygiene: risky, but there before."""
    findings = []
    running = _running(context)
    for key, item in sorted(context.items("containers").items()):
        dangers = _dangers(item)
        if not dangers:
            continue
        new = _is_new(context, key, ("privileged", "mounts", "capabilities"))
        findings.append(
            Finding(
                "container.privileged",
                "A container with the host's privileges" + (" since the baseline" if new else ""),
                COMPROMISE if new else HYGIENE,
                "high" if new else "medium",
                f"{key}: {', '.join(dangers)}; image {item.get('image') or '?'}"
                f" ({'running' if running.get(key) else 'not running'})",
                _entities(key, item),
                [_ref(context, key)],
                new=new and context.new_since_previous("containers", key),
                uncertain=context.uncertain("containers"),
                variant="new" if new else "standing",
            )
        )
    return findings


@check(
    "container.host_namespace",
    "A container sharing the host's process or network namespace since the baseline",
    needs_baseline=True,
)
def host_namespace(context: Context) -> list[Finding]:
    """Medium when new: a container that sees the host's processes or its
    network interfaces. Monitoring agents do; a deploy rarely adds one."""
    findings = []
    for key, item in sorted(context.items("containers").items()):
        shared = [n for n in ("pid", "network") if item.get(f"host_{n}")]
        if not shared or not _is_new(context, key, ("host_pid", "host_network")):
            continue
        findings.append(
            Finding(
                "container.host_namespace",
                "A container sharing the host's namespaces since the baseline",
                COMPROMISE,
                "medium",
                f"{key}: the host's {' and '.join(shared)} namespace;"
                f" image {item.get('image') or '?'}",
                _entities(key, item),
                [_ref(context, key)],
                new=context.new_since_previous("containers", key),
                uncertain=context.uncertain("containers"),
            )
        )
    return findings


@check("container.new", "Containers new since the baseline", needs_baseline=True)
def new(context: Context) -> list[Finding]:
    """Low: deploys make containers; what a new one can do is judged above."""
    diff = context.changes("containers") or {"added": {}}
    running = _running(context)
    return [
        Finding(
            "container.new",
            "A container new since the baseline",
            COMPROMISE,
            "low",
            f"{key}: image {item.get('image') or '?'}"
            f" ({'running' if running.get(key) else 'not running'})",
            _entities(key, item),
            [context.change_ref("containers", key, "added")],
            new=context.new_since_previous("containers", key),
            uncertain=context.uncertain("containers"),
        )
        for key, item in sorted(diff["added"].items())
    ]
