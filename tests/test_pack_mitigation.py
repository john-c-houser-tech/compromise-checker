"""Mitigations judged from PHP's settings, and fix times from the package
history (plan 4.4b). The pack is the format tests' made-up one: its
mitigation wants session.upload_progress.enabled off, PHP's default on."""

from datetime import UTC, datetime

import pytest
from test_pack_exposure import NOW, PACK, ROCKY, UBUNTU, dpkg, records
from test_snapshot import add_bundle, rec, text_source

from checker.packs.exposure import FIXED, NOT_AFFECTED, judge
from checker.packs.mitigation import IN_PLACE, MISSING, NOT_SEEN
from checker.packs.mitigation import judge as mitigations
from checker.snapshot import php_settings

FPM = "/etc/php/8.3/fpm/php.ini"
NAME = "session.upload_progress.enabled"


def setting_items(files):
    """{path: [lines]} -> (php_settings items, web_config items)."""
    items, read = {}, {}
    for path, lines in files.items():
        read[path] = {}
        items.update(dict(php_settings(path, lines)))
    return items, read


def judged(files, links=None, complete=True, default="on"):
    items, read = setting_items(files)
    for link, target in (links or {}).items():
        read[link] = {"resolved": target}
    mitigation = PACK.mitigations[0].model_copy(update={"default": default})
    (result,) = mitigations([mitigation], items, read, complete)
    return result


def test_set_nowhere_is_phps_default_and_so_missing():
    result = judged({FPM: ["[PHP]", "engine = On"]})
    assert result.status == MISSING
    (place,) = result.places
    assert (place.value, place.source) == ("on", "PHP's default")


def test_off_in_php_ini_is_in_place_and_zero_counts_as_off():
    assert judged({FPM: [f"{NAME} = Off"]}).status == IN_PLACE
    assert judged({FPM: [f"{NAME} = 0"]}).status == IN_PLACE


def test_conf_d_is_read_after_php_ini_in_name_order_through_links():
    files = {
        FPM: [f"{NAME} = On"],
        "/etc/php/8.3/mods-available/zz-safety.ini": [f"{NAME} = Off"],
        "/etc/php/8.3/fpm/conf.d/10-opcache.ini": ["opcache.enable = 1"],
    }
    links = {"/etc/php/8.3/fpm/conf.d/99-safety.ini": "/etc/php/8.3/mods-available/zz-safety.ini"}
    assert judged(files, links).status == IN_PLACE
    # A later conf.d file turning it back on wins.
    files["/etc/php/8.3/fpm/conf.d/99-zz-again.ini"] = [f"{NAME} = On"]
    assert judged(files, links).status == MISSING


def test_a_path_or_host_section_is_not_the_global_setting():
    assert judged({FPM: ["[PATH=/var/www/legacy]", f"{NAME} = Off"]}).status == MISSING


def test_each_fpm_pool_can_turn_it_back_on():
    files = {
        FPM: [f"{NAME} = Off"],
        "/etc/php/8.3/fpm/pool.d/www.conf": ["[www]", f"php_value[{NAME}] = On"],
    }
    result = judged(files)
    assert result.status == MISSING
    assert [p.where for p in result.places if p.value == "On"] == [
        "/etc/php/8.3/fpm/pool.d/www.conf pool www"
    ]


def test_every_web_facing_setup_must_have_it():
    files = {FPM: [f"{NAME} = Off"], "/etc/php/8.3/apache2/php.ini": ["engine = On"]}
    result = judged(files)
    assert result.status == MISSING and len(result.places) == 2


def test_rhel_layout():
    files = {"/etc/php.ini": ["engine = On"], "/etc/php.d/20-off.ini": [f"{NAME} = off"]}
    assert judged(files).status == IN_PLACE


@pytest.mark.parametrize(
    ("files", "complete", "default", "why"),
    [
        ({FPM: [f"{NAME} = Off"]}, False, "on", "weren't collected whole"),
        ({"/etc/nginx/nginx.conf": []}, True, "on", "no PHP set-up"),
        ({FPM: ["engine = On"]}, True, None, "doesn't say PHP's default"),
    ],
)
def test_what_cant_be_seen(files, complete, default, why):
    result = judged(files, complete=complete, default=default)
    assert result.status == NOT_SEEN and why in result.why


# --- Fix times from the package history ---------------------------------------------------------


def event(kind, version, when, previous=None, name="php8.3-fpm"):
    fields = {"name": name, "arch": "amd64", "version": version, "previous": previous}
    return {
        "type": f"package.{kind}",
        "time": when,
        "fields": {k: v for k, v in fields.items() if v},
    }


LATER = datetime(2026, 10, 28, tzinfo=UTC).timestamp()  # a routine update after the fix


def test_the_history_dates_the_fix_not_the_last_update():
    history = [
        event(
            "upgrade",
            "8.3.6-0ubuntu0.24.04.6",
            "2026-10-22T00:00:00+00:00",
            "8.3.6-0ubuntu0.24.04.5",
        ),
        event(
            "upgrade",
            "8.3.6-0ubuntu0.24.04.7",
            "2026-10-28T00:00:00+00:00",
            "8.3.6-0ubuntu0.24.04.6",
        ),
    ]
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.7", LATER), [], NOW, True, history)
    assert found.status == FIXED and found.fix_time_exact
    assert found.exposed_until.startswith("2026-10-22") and found.share == pytest.approx(0.2)


def test_a_first_install_already_fixed_exposed_nothing():
    history = [event("install", "8.3.6-0ubuntu0.24.04.6", "2026-10-25T00:00:00+00:00")]
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [], NOW, True, history)
    assert found.status == FIXED and found.share == 0.0 and found.exposed_from is None


def test_a_downgrade_back_restarts_the_clock():
    history = [
        event(
            "upgrade",
            "8.3.6-0ubuntu0.24.04.6",
            "2026-10-21T00:00:00+00:00",
            "8.3.6-0ubuntu0.24.04.5",
        ),
        event(
            "downgrade",
            "8.3.6-0ubuntu0.24.04.5",
            "2026-10-23T00:00:00+00:00",
            "8.3.6-0ubuntu0.24.04.6",
        ),
        event(
            "upgrade",
            "8.3.6-0ubuntu0.24.04.6",
            "2026-10-26T00:00:00+00:00",
            "8.3.6-0ubuntu0.24.04.5",
        ),
    ]
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [], NOW, True, history)
    assert found.exposed_until.startswith("2026-10-26")


def test_an_earlier_collection_that_had_the_fix_bounds_it():
    earlier = [(datetime(2026, 10, 22, tzinfo=UTC), dpkg("8.3.6-0ubuntu0.24.04.6"))]
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.7", LATER), [], NOW, True, [], earlier)
    assert found.exposed_until.startswith("2026-10-22") and not found.fix_time_exact


def test_a_vulnerable_package_removed_in_the_window_was_exposed_until_then():
    history = [event("remove", None, "2026-10-25T00:00:00+00:00", "8.3.6-0ubuntu0.24.04.5")]
    found = judge(PACK, UBUNTU, dpkg("1.0-1", name="nginx amd64"), [], NOW, True, history)
    assert found.status == FIXED and found.removed_at.startswith("2026-10-25")
    assert found.share == pytest.approx(0.5)
    assert judge(PACK, UBUNTU, dpkg("1.0-1", name="nginx amd64"), [], NOW).status == NOT_AFFECTED


def test_rpm_history_by_name():
    rocky = {"php-fpm x86_64": {"manager": "rpm", "version": "8.3.15-1.el9_6", "installed": LATER}}
    fields = {"name": "php-fpm", "arch": "x86_64", "version": "8.3.15-1.el9_6"}
    history = [{"type": "package.upgrade", "time": "2026-10-21T00:00:00+00:00", "fields": fields}]
    found = judge(PACK, ROCKY, rocky, [], NOW, True, history)
    assert found.fix_time_exact and found.exposed_until.startswith("2026-10-21")


# --- Through an analysis ---------------------------------------------------------------------


def test_an_analysis_reports_the_missing_mitigation_and_the_dated_fix(home):
    from checker.assess import analyze

    base, store, identity, config = home
    extra = (
        rec(
            "software",
            "package_change",
            manager="dpkg",
            action="upgrade",
            name="php8.3-fpm",
            arch="amd64",
            previous="8.3.6-0ubuntu0.24.04.5",
            version="8.3.6-0ubuntu0.24.04.6",
            local_time="2026-10-22 00:00:00",
            source="/var/log/dpkg.log",
        ),  # fmt: skip
        *text_source(9, "web_logs", FPM, "[Session]\nsession.save_path = /var/lib/php\n"),
    )
    bundle = records("8.3.6-0ubuntu0.24.04.6", LATER, extra)
    add_bundle(home, "b1", 0, bundle)
    assessment = analyze(store, "web01", identity, config.recipients, packs=[PACK])
    found = {f["variant"]: f for f in assessment["findings"] if f["check"] == "pack.exposure"}
    missing = found["mitigation_missing"]
    assert missing["band"] == "medium"  # fixed host: the mitigation also covers another flaw
    assert (
        "should be off" in missing["summary"]
        and "PHP's default: set in no file" in missing["summary"]
    )
    assert "until the fix was installed at 2026-10-22" in found["was_exposed"]["summary"]


def test_in_place_says_what_wasnt_read(home):
    from checker.assess import analyze

    base, store, identity, config = home
    extra = tuple(text_source(9, "web_logs", FPM, f"{NAME} = Off\n"))
    add_bundle(home, "b1", 0, records("8.3.6-0ubuntu0.24.04.5", extra=extra))
    assessment = analyze(store, "web01", identity, config.recipients, packs=[PACK])
    assert not [f for f in assessment["findings"] if f.get("variant") == "mitigation_missing"]
    assert any(
        ".user.ini" in g and "upload-progress-off" in g for g in assessment["coverage"]["gaps"]
    )


def test_a_missing_mitigation_on_a_vulnerable_host_is_high(home):
    from checker.assess import analyze

    base, store, identity, config = home
    extra = tuple(text_source(9, "web_logs", FPM, "engine = On\n"))
    add_bundle(home, "b1", 0, records("8.3.6-0ubuntu0.24.04.5", extra=extra))
    assessment = analyze(store, "web01", identity, config.recipients, packs=[PACK])
    (missing,) = [f for f in assessment["findings"] if f.get("variant") == "mitigation_missing"]
    assert missing["band"] == "high"
