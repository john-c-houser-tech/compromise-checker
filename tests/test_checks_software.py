"""Software change checks (PR 2.6, DESIGN.md §8.11)."""

from datetime import timedelta

from test_checks import T0, ev, of, run
from test_checks_live import snap

AT = (T0 + timedelta(minutes=30)).timestamp()


def packages(**items):
    return {
        f"{name} amd64": {"manager": "dpkg", "version": "1.0", "installed": AT, **fields}
        for name, fields in items.items()
    }


def test_installs_removals_and_upgrades_are_grouped():
    before = snap(packages=packages(bash={}, curl={}, oldpkg={}))
    after = snap(
        packages=packages(
            bash={"version": "2.0"},
            curl={},
            **{f"new{n}": {} for n in range(12)},
        )
    )
    found = {f.variant: f for f in of(run([], after, baseline=before), "software.packages")}
    assert found["installed"].band == "low" and found["installed"].summary.startswith("12:")
    assert "and 4 more" in found["installed"].summary
    assert found["removed"].band == "low" and "oldpkg" in found["removed"].summary
    assert found["upgraded"].band == "info" and "bash" in found["upgraded"].summary


def test_the_automatic_updater_makes_installs_informational():
    before = snap(packages=packages(bash={}))
    after = snap(packages=packages(bash={}, libfoo={}))
    events = [ev("unit.started", 10, what="Daily apt upgrade and clean activities")]
    [found] = of(run(events, after, baseline=before), "software.packages")
    assert found.variant == "automatic" and found.band == "info"
    late = [ev("unit.started", -300, what="Daily apt upgrade and clean activities")]
    [found] = of(run(late, after, baseline=before), "software.packages")
    assert found.band == "low"


def test_attack_tools_and_compilers():
    before = snap(packages=packages(bash={}))
    after = snap(packages=packages(bash={}, nmap={}, gcc={}, htop={}))
    found = {f.variant: f for f in of(run([], after, baseline=before), "software.tools")}
    assert found["attack_tool"].band == "medium" and found["attack_tool"].summary.startswith("nmap")
    assert found["compiler"].band == "low"
    assert set(found) == {"attack_tool", "compiler"}


def test_repositories_and_keys():
    before = snap(software_files={"/etc/apt/sources.list": {"content_sha256": "a"}})
    after = snap(
        software_files={
            "/etc/apt/sources.list": {"content_sha256": "b"},
            "/etc/apt/sources.list.d/x.list": {"content_sha256": "c"},
            "/etc/apt/keyrings/x.gpg": {"sha256": "d", "record": "signing_key"},
        }
    )
    found = sorted(
        (f.variant, f.summary) for f in of(run([], after, baseline=before), "software.repository")
    )
    assert found == [
        ("key", "/etc/apt/keyrings/x.gpg"),
        ("repository", "/etc/apt/sources.list"),
        ("repository", "/etc/apt/sources.list.d/x.list"),
    ]


def test_global_pip_and_npm():
    before = snap(global_packages={"python: requests": {"version": "2.0"}})
    after = snap(
        global_packages={
            "python: requests": {"version": "2.0"},
            "python: impacket": {"version": "0.11"},
            "node: @evil/pkg": {"version": None},
        }
    )
    [found] = of(run([], after, baseline=before), "software.global")
    assert found.summary.startswith("2:") and "package:impacket" in found.entities


def test_a_maintenance_window_covers_package_installs(tmp_path):
    from checker.whitelist import build, read_layer

    path = tmp_path / "w.yaml"
    path.write_text(
        "maintenance:\n  - id: patch\n    start: 2027-01-02T00:00:00Z\n"
        "    end: 2027-01-03T00:00:00Z\n    reason: r\n    owner: o\n    expires: never\n"
    )
    whitelist = build([("host h", str(path), read_layer(path))])
    finding = {
        "check": "software.packages",
        "variant": "installed",
        "band": "low",
        "entities": [],
        "first_seen": (T0 + timedelta(minutes=30)).isoformat(),
        "last_seen": (T0 + timedelta(minutes=40)).isoformat(),
    }
    whitelist.apply([finding], today=T0.date())
    assert finding["band"] == "info" and finding["maintenance"]["window"] == "patch"
