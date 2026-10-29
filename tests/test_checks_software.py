"""Software change checks (PR 2.6, DESIGN.md §8.11)."""

from datetime import timedelta

import pytest
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


RUN = "apt-daily-upgrade.service - Daily apt upgrade and clean activities"


def test_the_automatic_updater_makes_installs_informational():
    before = snap(packages=packages(bash={}))
    after = snap(packages=packages(bash={}, libfoo={}))
    events = [ev("unit.starting", 25, what=RUN), ev("unit.finished", 40, what=RUN)]
    [found] = of(run(events, after, baseline=before), "software.packages")
    assert found.variant == "automatic" and found.band == "info"


@pytest.mark.parametrize(
    "events",
    [
        # The timer starting at boot, not the service running.
        [
            ev(
                "unit.started",
                25,
                what="apt-daily-upgrade.timer - Daily apt upgrade and clean activities",
            )
        ],
        # PackageKit, which apt starts after any install.
        [
            ev("unit.starting", 25, what="packagekit.service - PackageKit Daemon"),
            ev("unit.finished", 40, what="packagekit.service - PackageKit Daemon"),
        ],
        # A run that finished before the install.
        [ev("unit.starting", 0, what=RUN), ev("unit.finished", 10, what=RUN)],
    ],
)
def test_other_things_arent_the_automatic_updater(events):
    before = snap(packages=packages(bash={}))
    after = snap(packages=packages(bash={}, libfoo={}))
    [found] = of(run(events, after, baseline=before), "software.packages")
    assert found.band == "low"


def test_an_undated_install_isnt_automatic_and_installs_are_grouped_by_time():
    before = snap(packages=packages(bash={}))
    later = (T0 + timedelta(days=2)).timestamp()
    after = snap(
        packages=packages(
            bash={}, libfoo={}, undated={"installed": None}, later={"installed": later}
        )
    )
    events = [ev("unit.starting", 25, what=RUN), ev("unit.finished", 40, what=RUN)]
    found = sorted(
        (f.summary, f.band) for f in of(run(events, after, baseline=before), "software.packages")
    )
    assert found == [("1: later", "low"), ("1: libfoo", "info"), ("1: undated", "low")]


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


def test_an_imported_rpm_key_is_a_new_signing_key_not_a_package():
    before = snap(packages={"gpg-pubkey 0:abcd-1": {"manager": "rpm", "version": "abcd-1"}})
    after = snap(
        packages={
            "gpg-pubkey 0:abcd-1": {"manager": "rpm", "version": "abcd-1"},
            "gpg-pubkey ffff-2": {"manager": "rpm", "version": "ffff-2", "installed": AT},
        }
    )
    results = run([], after, baseline=before)
    assert of(results, "software.packages") == []
    [key] = of(results, "software.repository")
    assert key.variant == "key" and "ffff-2" in key.summary


def test_only_real_changes_to_repository_files_count():
    before = snap(
        software_files={
            "/etc/yum.repos.d/rocky.repo": {"content_sha256": "a", "mtime": 1, "inode": 5},
        }
    )
    after = snap(
        software_files={
            "/etc/yum.repos.d/rocky.repo": {"content_sha256": "a", "mtime": 2, "inode": 9},
            "/etc/yum.repos.d/rocky.repo.rpmnew": {"content_sha256": "b"},
        }
    )
    [found] = of(run([], after, baseline=before), "software.repository")
    assert found.summary.endswith(".rpmnew") and found.band == "low"


def test_nodes_own_npm_isnt_installed_by_hand():
    before = snap(global_packages={})
    after = snap(global_packages={"node: npm": {}, "node: corepack": {}})
    assert of(run([], after, baseline=before), "software.global") == []


def test_package_keys_for_side_by_side_installs(tmp_path):
    from test_snapshot import host_records, rec, snapshot_of_records

    records = host_records(
        extra=[
            rec(
                "software",
                "package",
                manager="rpm",
                name="kernel-core",
                arch="x86_64",
                version="5.14-1",
            ),
            rec(
                "software",
                "package",
                manager="rpm",
                name="kernel-core",
                arch="x86_64",
                version="5.14-2",
            ),
            rec("software", "package", manager="rpm", name="gpg-pubkey", arch=None, version="a-1"),
            rec("software", "package", manager="rpm", name="gpg-pubkey", arch=None, version="b-2"),
            rec("software", "package", manager="dpkg", name="libc6", arch="amd64", version="2.39"),
            rec("software", "package", manager="dpkg", name="libc6", arch="i386", version="2.39"),
        ]
    )
    items = snapshot_of_records(records, tmp_path).sections["packages"].items
    assert len(items) == 6


def test_the_updaters_journal_lines_are_parsed():
    from checker.events import classify

    assert classify(
        "systemd", "Starting apt-daily-upgrade.service - Daily apt upgrade and clean activities..."
    ) == (
        "unit.starting",
        {"what": "apt-daily-upgrade.service - Daily apt upgrade and clean activities"},
    )
    assert classify(
        "systemd", "Finished dnf-automatic-install.service - dnf automatic install updates."
    )[0] == ("unit.finished")


def test_removals_arent_read_from_an_incomplete_listing():
    from checker.snapshot import Section, Snapshot

    before = snap(packages=packages(bash={}, curl={}))
    after = Snapshot(
        {"masking_version": 6, "full": True},
        {"packages": Section(packages(bash={}), complete=False, gaps=["cut short"])},
    )
    assert [f.variant for f in of(run([], after, baseline=before), "software.packages")] == []


def test_a_directory_in_a_repository_folder_isnt_a_repository():
    before = snap(software_files={})
    after = snap(software_files={"/etc/apt/sources.list.d/sub": {"type": "d"}})
    assert of(run([], after, baseline=before), "software.repository") == []
