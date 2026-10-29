"""Containers (DESIGN.md §8.13): containers that hold the host
(privileged, mounting its root, configuration or a runtime's socket,
holding a device or a capability that reaches it), containers sharing the
host's process or network namespace, and new containers or images.

From the runtimes' state files (decision 4), compared by name: a redeploy
replaces a container's ID, not what it is. Running state comes from the
processes' cgroups, which name the container's ID."""

from __future__ import annotations

import re
from typing import Any

from checker.checks import COMPROMISE, HYGIENE, Context, Finding, check

# Host paths that give a container the host: its root, configuration,
# root's home, kernel interfaces, and the runtimes' state and sockets (a
# container that can talk to dockerd can start a privileged one). A mount
# of one of these, of anything inside one, or of a folder holding one
# (/var/run holds docker.sock) counts.
HOST_PATHS = (
    "/etc",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/var/lib/docker",
    "/var/lib/containers",
    "/var/lib/containerd",
    "/var/lib/kubelet",
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
)
# Capabilities with a known route to the host; SYS_PTRACE only with the
# host's processes in view.
HOST_CAPABILITIES = {"SYS_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF", "ALL"}
# Devices containers ordinarily get.
ORDINARY_DEVICES = re.compile(
    r"^/dev/(?:fuse|net/tun|kvm|null|zero|full|random|urandom|tty|console|ptmx|dri/.*|nvidia.*)$"
)
CONTAINER_ID = re.compile(
    r"(?:docker-|libpod-|crio-|cri-containerd-|/docker/|/libpod/)([0-9a-f]{64})(?:\.scope)?\b"
)


def _covers(source: str, sensitive: str) -> bool:
    """A mount of `source` reaches `sensitive`: it is it, inside it, or holds it."""
    source = source.rstrip("/") or "/"
    return (
        source == "/"
        or source == sensitive
        or source.startswith(sensitive + "/")
        or sensitive.startswith(source + "/")
    )


def dangers(item: dict[str, Any] | None) -> set[str]:
    """What gives the container the host, if anything."""
    if not item:
        return set()
    found = set()
    if item.get("privileged"):
        found.add("privileged")
    for source in item.get("mount_sources") or []:
        if not str(source).startswith("/"):
            continue
        if (str(source).rstrip("/") or "/") == "/":
            found.add("mounts /")
            continue
        reached = [p for p in HOST_PATHS if _covers(str(source), p)]
        held = [p for p in reached if p.startswith(str(source).rstrip("/") + "/")]
        if reached:
            found.add(f"mounts {source}" + (f" (holds {held[0]})" if held else ""))
    capabilities = set(item.get("capabilities") or [])
    for name in sorted(capabilities & HOST_CAPABILITIES):
        found.add(f"has CAP_{name}")
    if "SYS_PTRACE" in capabilities and item.get("host_pid"):
        found.add("has CAP_SYS_PTRACE with the host's processes")
    for device in item.get("devices") or []:
        if not ORDINARY_DEVICES.match(str(device)) and not item.get("privileged"):
            found.add(f"has device {device}")
    return found


def running_ids(context_snapshot) -> set[str] | None:
    """IDs of the containers running at collection, from the processes'
    cgroups; None when the processes weren't collected."""
    live = context_snapshot.live
    if "process_summary" not in live and not live.get("processes"):
        return None
    ids = set()
    for process in live.get("processes", []):
        match = CONTAINER_ID.search(str(process.get("cgroup") or ""))
        if match:
            ids.add(match.group(1))
    return ids


def uninventoried(snapshot) -> int:
    """Containers running (by cgroup) that no state file described."""
    ids = running_ids(snapshot)
    if not ids:
        return 0
    known = {c.get("id") for c in snapshot.live.get("containers", [])}
    return len(ids - known)


def _states(context: Context) -> dict[str, str]:
    ids = running_ids(context.snapshot)
    state = {}
    for container in context.snapshot.live.get("containers", []):
        key = f"{container.get('runtime')}: {container.get('name')}"
        if ids is None:
            state[key] = "running state unknown"
        else:
            state[key] = "running" if container.get("id") in ids else "not running"
    return state


def repository(image: str | None) -> str:
    """An image's repository, without its tag or digest, with Docker Hub's
    implied parts added: nginx:1.25, docker.io/nginx and
    index.docker.io/library/nginx@sha256:… are one repository. An image
    ID (sha256:…, or 64 hex digits) stands for itself."""
    image = (image or "").strip()
    if image.startswith("sha256:") or re.fullmatch(r"[0-9a-f]{64}", image):
        return image
    name = image.split("@", 1)[0]
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name = name[: len(name) - len(last)] + last.split(":", 1)[0]
    parts = name.split("/")
    if parts[0] == "index.docker.io":
        parts[0] = "docker.io"
    if len(parts) == 1:
        parts = ["docker.io", "library", *parts]
    elif "." not in parts[0] and ":" not in parts[0] and parts[0] != "localhost":
        parts = ["docker.io", *parts]
    if parts[0] == "docker.io" and len(parts) == 2:
        parts = ["docker.io", "library", parts[1]]
    return "/".join(parts).lower()


def _entities(key: str, item: dict[str, Any]) -> list[str]:
    return [f"container:{key}"] + (
        [f"image:{repository(item['image'])}"] if item.get("image") else []
    )


def _baseline(context: Context, key: str) -> dict[str, Any] | None:
    """The container as it was at the baseline: today's item with each
    changed field put back (None if it wasn't there)."""
    diff = context.changes("containers")
    item = context.items("containers").get(key)
    if diff is None or item is None or key in diff["added"]:
        return None
    before = dict(item)
    for field, (old, _) in (diff["changed"].get(key) or {}).items():
        before[field] = old
    return before


def _ref(context: Context, key: str) -> dict[str, Any]:
    diff = context.changes("containers") or {"added": {}, "changed": {}}
    if key in diff["added"]:
        return context.change_ref("containers", key, "added")
    if key in diff["changed"]:
        return context.change_ref("containers", key, "changed")
    return {"item": ["containers", key]}


@check(
    "container.privileged",
    "A container that holds the host: privileged, mounting its root or a runtime's socket,"
    " or with a device or capability that reaches it",
    variants=("new", "standing"),
)
def privileged(context: Context) -> list[Finding]:
    """High when it holds the host in a way it didn't at the baseline (a
    new container, or a danger it gained): a way onto the host. Otherwise
    medium hygiene: risky, but there before (a monitoring agent)."""
    findings = []
    states = _states(context)
    diff = context.changes("containers")
    for key, item in sorted(context.items("containers").items()):
        now = dangers(item)
        if not now:
            continue
        gained = sorted(now - dangers(_baseline(context, key))) if diff is not None else []
        new = bool(gained) or (diff is not None and key in diff["added"])
        findings.append(
            Finding(
                "container.privileged",
                "A container that holds the host" + (" since the baseline" if new else ""),
                COMPROMISE if new else HYGIENE,
                "high" if new else "medium",
                f"{key}: {', '.join(gained or sorted(now))}; image {item.get('image') or '?'}"
                f" ({states.get(key, 'running state unknown')})",
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
        before = _baseline(context, key) or {}
        shared = [
            n for n in ("pid", "network") if item.get(f"host_{n}") and not before.get(f"host_{n}")
        ]
        if not shared:
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


@check(
    "container.new",
    "Containers new since the baseline, or running another image",
    needs_baseline=True,
    variants=("new", "image_changed"),
)
def new(context: Context) -> list[Finding]:
    """Low: deploys make containers, and change their images' versions;
    what a container can do is judged above. A container whose image is
    another repository (not another tag or digest of the same) under the
    same name is reported too: a trusted name running something else."""
    diff = context.changes("containers") or {"added": {}, "changed": {}}
    states = _states(context)
    findings = [
        Finding(
            "container.new",
            "A container new since the baseline",
            COMPROMISE,
            "low",
            f"{key}: image {item.get('image') or '?'} ({states.get(key, 'running state unknown')})",
            _entities(key, item),
            [context.change_ref("containers", key, "added")],
            new=context.new_since_previous("containers", key),
            uncertain=context.uncertain("containers"),
            variant="new",
        )
        for key, item in sorted(diff["added"].items())
    ]
    items = context.items("containers")
    for key, fields in sorted((diff.get("changed") or {}).items()):
        if "image" not in fields:
            continue
        before, after = fields["image"]
        if repository(before) == repository(after):
            continue  # another version of the same image: a deploy
        findings.append(
            Finding(
                "container.new",
                "A container running another image since the baseline",
                COMPROMISE,
                "low",
                f"{key}: {before or '?'} → {after or '?'}"
                f" ({states.get(key, 'running state unknown')})",
                _entities(key, items.get(key) or {"image": after}),
                [context.change_ref("containers", key, "changed")],
                new=context.new_since_previous("containers", key),
                uncertain=context.uncertain("containers"),
                variant="image_changed",
            )
        )
    return findings
