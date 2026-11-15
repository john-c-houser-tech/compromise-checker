"""A changed PAM module that its own package's upgrade explains (#185), and every way the reviews
of #186 found to fake that explanation, which must leave each module high."""

from datetime import timedelta

import pytest
from test_checks import T0, ev, of, run
from test_checks_live import snap

from checker.events import Event

DIR = "/usr/lib/x86_64-linux-gnu/security"
MODULES = [f"{DIR}/pam_{n}.so" for n in ("access", "deny", "unix")]
INFO = "/var/lib/dpkg/info/"
LIST = INFO + "libpam-modules:amd64.md5sums"
VIM_LIST = INFO + "vim.md5sums"
RUN = "apt-daily-upgrade.service - Daily apt upgrade and clean activities"
LONG_AGO = T0 - timedelta(days=30)


def at(minutes):
    return T0 + timedelta(minutes=minutes)


def systemd(kind, minutes, comm="systemd", uid="0"):
    fields = {"what": RUN}
    if comm is not None:
        fields |= {"journal_comm": comm, "journal_uid": uid}
    return ev(kind, minutes, source="journal", **fields)


TRUSTED_RUN = [systemd("unit.starting", 25), systemd("unit.finished", 40)]


def upgrade(
    module_at=31,
    list_at=31,
    installed_at=30,
    upgraded=("libpam-modules",),
    manager="dpkg",
    owners=None,
    owners_complete=True,
    package_changes=None,
    vim_list_at=None,
    remove_owner_list=False,
    links=None,
    modules=MODULES,
):
    """Before and after an upgrade of PAM's modules; each argument moves one piece of evidence."""

    def packages(changed):
        return {
            f"{name} amd64": {
                "manager": manager,
                "version": "2" if name in changed else "1",
                "installed": (at(installed_at) if name in changed else LONG_AGO).timestamp(),
            }
            for name in ("libpam-modules", "vim")
        }

    def lists(owner_at, vim_at):
        if manager != "dpkg":
            return {}
        found = {
            LIST: {
                "sha256": "new" if owner_at else "old",
                "ctime": (owner_at or LONG_AGO).isoformat(),
            },
            VIM_LIST: {
                "sha256": "new" if vim_at else "old",
                "ctime": (vim_at or LONG_AGO).isoformat(),
            },
        }
        if remove_owner_list and owner_at:
            del found[LIST]
        return found

    before = snap(
        pam={m: {"sha256": "a", "size": 1, "ctime": LONG_AGO.isoformat()} for m in modules},
        packages=packages(()),
        package_changes={},
        unowned_executables={},
        checksum_store=lists(None, None),
    )
    live = {
        "pam_owners": {
            "complete": owners_complete,
            "owners": owners if owners is not None else {m: "libpam-modules" for m in modules},
        },
        "system_files_summary": {"merged_dirs": links or {}},
    }
    after = snap(
        live,
        pam={m: {"sha256": "b", "size": 1, "ctime": at(module_at).isoformat()} for m in modules},
        packages=packages(upgraded),
        package_changes=package_changes or {},
        unowned_executables={},  # #186's test needed it: every case here meets that test
        checksum_store=lists(
            at(list_at) if list_at is not None else None, at(vim_list_at) if vim_list_at else None
        ),
    )
    return before, after


def outcome(events, before, after):
    found = of(run(events, after, baseline=before), "pam.changes")
    return sorted((f.band, f.variant, len(f.evidence)) for f in found)


ALL_HIGH = [("high", None, 1)] * 3


def test_an_automatic_update_of_pams_own_package_is_one_low_finding():
    """The demo's staging-1: Ubuntu's updates replaced 46 modules, and read as a break-in."""
    before, after = upgrade()
    [found] = of(run(TRUSTED_RUN, after, baseline=before), "pam.changes")
    assert (found.band, found.variant) == ("low", "automatic_update")
    assert found.title == "PAM module files changed with an automatic update of their package"
    assert found.summary.startswith("3: pam_access.so, pam_deny.so, pam_unix.so. Each still")
    assert "an intruder acting during a real update could hide here" in found.summary
    assert found.entities_complete and len(found.entities) == 3


def test_an_upgrade_by_hand_is_medium():
    before, after = upgrade()
    assert outcome([], before, after) == [("medium", "hand_upgrade", 3)]


@pytest.mark.parametrize(
    "events",
    [
        # `logger -t systemd 'Starting apt-daily-upgrade.service…'`: any account can write it.
        [
            systemd("unit.starting", 25, "logger", "1000"),
            systemd("unit.finished", 40, "logger", "1000"),
        ],
        [systemd("unit.starting", 25, None), systemd("unit.finished", 40, None)],  # a text log
        [systemd("unit.starting", 25)],  # a start with no finish isn't a run
        [systemd("unit.starting", 33), systemd("unit.finished", 40)],  # began after the change
    ],
    ids=["logger", "text log", "no finish", "outside the run"],
)
def test_only_a_run_systemd_logged_as_root_start_and_finish_makes_it_low(events):
    before, after = upgrade()
    assert outcome(events, before, after) == [("medium", "hand_upgrade", 3)]


@pytest.mark.parametrize(
    "evidence",
    [
        {"upgraded": ("vim",), "vim_list_at": 31},  # any other package's upgrade explains nothing
        {"list_at": None},  # `touch` on the package's files: its checksum list never changed
        {"remove_owner_list": True},  # the checksum list deleted, so verification is silent
        {"vim_list_at": 31},  # another package's list rewritten with no version change
        {"owners_complete": False},  # ownership not fully known
        {"owners": {}},  # no owner recorded for these modules
        {"list_at": 31 + 16},  # rewritten 16 minutes from the module
        {"module_at": 31 - 16},
        {"manager": "rpm", "installed_at": 31 + 16},  # rpm: the install time, inside its database
    ],
    ids=[
        "unrelated package",
        "list unchanged",
        "list deleted",
        "another list rewritten",
        "owners incomplete",
        "no owner",
        "16 minutes after",
        "16 minutes before",
        "rpm 16 minutes",
    ],
)
def test_evidence_an_intruder_can_fake_or_that_is_missing_leaves_each_module_high(evidence):
    before, after = upgrade(**evidence)
    assert outcome(TRUSTED_RUN, before, after) == ALL_HIGH


def test_an_older_collector_explains_nothing():
    before, after = upgrade()
    del after.live["pam_owners"]
    assert outcome(TRUSTED_RUN, before, after) == ALL_HIGH


def test_fourteen_minutes_is_near_enough():
    before, after = upgrade(module_at=26, list_at=26 + 14)
    assert outcome(TRUSTED_RUN, before, after) == [("low", "automatic_update", 3)]


def test_rpm_uses_the_install_time_in_its_database():
    before, after = upgrade(manager="rpm", installed_at=31)
    assert outcome(TRUSTED_RUN, before, after) == [("low", "automatic_update", 3)]


def test_a_module_that_differs_from_its_package_stays_high_under_either_path():
    """dpkg on Ubuntu 22.04 lists /lib/…; the PAM walk records /usr/lib/… on a merged system."""
    swapped = {"/lib/x86_64-linux-gnu/security/pam_unix.so": {"package": "libpam-modules"}}
    before, after = upgrade(package_changes=swapped, links={"/lib": "/usr/lib"})
    assert outcome(TRUSTED_RUN, before, after) == [
        ("high", None, 1),
        ("low", "automatic_update", 2),
    ]


def test_the_servers_own_clock_is_used_on_both_sides():
    """A server whose clock is two hours off: the run's corrected time would miss the change."""
    before, after = upgrade()

    def skewed(kind, minutes):
        event = systemd(kind, minutes)
        later = (at(minutes) + timedelta(hours=2)).isoformat()
        return Event(event.time, later, event.source, event.type, event.fields)

    events = [skewed("unit.starting", 25), skewed("unit.finished", 40)]
    assert outcome(events, before, after) == [("low", "automatic_update", 3)]


def test_a_large_group_names_fifty_and_says_it_names_only_some():
    many = [f"{DIR}/pam_m{n:02}.so" for n in range(60)]
    before, after = upgrade(modules=many)
    [found] = of(run(TRUSTED_RUN, after, baseline=before), "pam.changes")
    assert found.summary.startswith("60: ") and len(found.entities) == 50
    assert not found.entities_complete and len(found.evidence) == 50
