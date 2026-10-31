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
        read[path] = {"content_sha256": "read"}
        # Under a web root: a site's .user.ini or .htaccess (plan 4.4c).
        items.update(dict(php_settings(path, lines, site=path.startswith("/var/www/"))))
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
        "/etc/php/8.3/fpm/php.ini pool www"
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
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [], NOW, True, history, [], True)
    assert found.status == FIXED and found.share == 0.0 and found.exposed_from is None
    # With part of the history missing, it may have replaced a vulnerable one.
    partial = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.6"), [], NOW, True, history)
    assert partial.share == pytest.approx(0.5)


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
    earlier = [(datetime(2026, 10, 22, tzinfo=UTC), dpkg("8.3.6-0ubuntu0.24.04.7"))]
    found = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.7", LATER), [], NOW, True, [], earlier)
    assert found.exposed_until.startswith("2026-10-22") and not found.fix_time_exact
    # A different version then: it may have changed in between, so no bound.
    changed = [(datetime(2026, 10, 22, tzinfo=UTC), dpkg("8.3.6-0ubuntu0.24.04.6"))]
    later = judge(PACK, UBUNTU, dpkg("8.3.6-0ubuntu0.24.04.7", LATER), [], NOW, True, [], changed)
    assert later.exposed_until.startswith("2026-10-28")


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
        rec("host_facts", "clock", localtime_link="/usr/share/zoneinfo/Etc/UTC"),
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


# --- After review -------------------------------------------------------------------------------


def judged_with(files, links=None, default="on", complete=True):
    return judged(files, links, complete, default)


def test_a_pools_admin_setting_isnt_overwritten_by_a_later_ordinary_one():
    files = {
        FPM: [f"{NAME} = Off"],
        "/etc/php/8.3/fpm/pool.d/www.conf": [
            "[www]", f"php_admin_flag[{NAME}] = on", f"php_flag[{NAME}] = off"
        ],
    }  # fmt: skip
    assert judged(files).status == MISSING


def test_a_path_section_turning_it_on_is_a_place_of_its_own():
    result = judged({FPM: [f"{NAME} = Off", "[PATH=/var/www/a]", f"{NAME} = On"]})
    assert result.status == MISSING
    assert any(p.where.endswith("[PATH=/var/www/a]") for p in result.places)


def test_a_setup_without_its_php_ini_runs_on_defaults():
    files = {FPM: [f"{NAME} = Off"], "/etc/php/8.3/apache2/conf.d/10-opcache.ini": ["x = 1"]}
    result = judged(files)
    assert result.status == MISSING
    assert any(p.where == "/etc/php/8.3/apache2/php.ini" and p.source == "PHP's default"
               for p in result.places)  # fmt: skip


def test_a_conf_d_link_to_a_file_not_read_isnt_seen():
    items, read = setting_items({FPM: [f"{NAME} = Off"]})
    read["/etc/php/8.3/fpm/conf.d/99-x.ini"] = {"resolved": "/opt/vendor/x.ini"}
    (result,) = mitigations([PACK.mitigations[0]], items, read, True)
    assert result.status == NOT_SEEN and "/opt/vendor/x.ini" in result.why


@pytest.mark.parametrize(
    "pools",
    [
        {"/etc/php/8.3/fpm/php-fpm.conf": ["[global]", "[www]", f"php_admin_value[{NAME}] = 1"]},
        {"/etc/php/8.3/fpm/pool.d/sites/a.conf": ["[a]", f"php_value[{NAME}] = 1"]},
    ],
)
def test_pools_in_php_fpm_conf_and_subfolders(pools):
    assert judged({FPM: [f"{NAME} = Off"], **pools}).status == MISSING


def test_a_pool_file_included_from_elsewhere_isnt_seen():
    files = {
        FPM: [f"{NAME} = Off"],
        "/etc/php/8.3/fpm/php-fpm.conf": ["[global]", "include=/srv/pools/*.conf"],
    }
    result = judged(files)
    assert result.status == NOT_SEEN and "/srv/pools/*.conf" in result.why


def test_every_pool_overriding_it_makes_php_ini_moot():
    files = {
        FPM: [f"{NAME} = On"],
        "/etc/php/8.3/fpm/pool.d/www.conf": ["[www]", f"php_admin_flag[{NAME}] = off"],
    }
    assert judged(files).status == IN_PLACE


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("/etc/apache2/sites-enabled/a.conf", f"php_admin_flag {NAME} on"),
        ("/etc/nginx/sites-enabled/b", f'fastcgi_param PHP_VALUE "{NAME}=1";'),
    ],
)
def test_a_web_servers_own_setting_counts(path, line):
    assert judged({FPM: [f"{NAME} = Off"], path: [line]}).status == MISSING


def test_php_ini_scan_dir_adds_what_wasnt_read():
    files = {FPM: [f"{NAME} = Off"], "/etc/apache2/envvars": ["export PHP_INI_SCAN_DIR=/srv/ini"]}
    result = judged(files)
    assert result.status == NOT_SEEN and "PHP_INI_SCAN_DIR" in result.why


def test_wrong_somewhere_is_missing_even_without_a_default():
    files = {FPM: [f"{NAME} = On"], "/etc/php/8.3/apache2/php.ini": ["engine = On"]}
    assert judged_with(files, default=None).status == MISSING


def test_any_non_zero_integer_is_on():
    assert judged({FPM: [f"{NAME} = 2"]}).status == MISSING
    assert judged({FPM: [f"{NAME} = -1"]}).status == MISSING


def test_the_pack_must_say_the_default():
    from test_pack_format import GOOD, changed

    from checker.packs.format import PackError, read

    with pytest.raises(PackError, match="says the setting's default"):
        read(changed('    default: "on"\n', ""))
    assert GOOD


V5, V6, V7 = "8.3.6-0ubuntu0.24.04.5", "8.3.6-0ubuntu0.24.04.6", "8.3.6-0ubuntu0.24.04.7"


def test_a_purge_then_a_fresh_install_still_exposed_until_the_purge():
    history = [
        event("install", V5, "2026-09-01T00:00:00+00:00"),
        event("purge", None, "2026-10-24T00:00:00+00:00", V5),
        event("install", V6, "2026-10-25T00:00:00+00:00"),
    ]
    found = judge(PACK, UBUNTU, dpkg(V6), [], NOW, True, history, [], True)
    assert found.share == pytest.approx(0.4) and found.removed_at.startswith("2026-10-24")


def test_a_removal_counts_while_another_affected_package_stays():
    history = [
        event("install", V6, "2026-10-21T00:00:00+00:00", name="libapache2-mod-php8.3"),
        event("remove", None, "2026-10-26T00:00:00+00:00", V5),
    ]
    installed = dpkg(V6, name="libapache2-mod-php8.3 amd64")
    found = judge(PACK, UBUNTU, installed, [], NOW, True, history, [], True)
    assert found.share == pytest.approx(0.6)


def test_a_retried_upgrade_dates_from_the_retry():
    history = [
        event("upgrade", V6, "2026-10-21T00:00:00+00:00", V5),  # failed, rolled back
        event("upgrade", V6, "2026-10-25T00:00:00+00:00", V5),
    ]
    found = judge(PACK, UBUNTU, dpkg(V6), [], NOW, True, history, [], True)
    assert found.exposed_until.startswith("2026-10-25")


def test_history_that_doesnt_reach_the_installed_version_isnt_exact():
    history = [event("upgrade", V6, "2026-10-21T00:00:00+00:00", V5)]
    found = judge(PACK, UBUNTU, dpkg(V7, LATER), [], NOW, True, history, [], True)
    assert not found.fix_time_exact and found.exposed_until.startswith("2026-10-28")


def test_an_uncertain_history_time_isnt_exact():
    uncertain = event("upgrade", V6, "2026-10-21T00:00:00+00:00", V5)
    uncertain["fields"]["zone_assumed"] = True
    found = judge(PACK, UBUNTU, dpkg(V6), [], NOW, True, [uncertain], [], True)
    assert not found.fix_time_exact


def test_an_earlier_vulnerable_listing_means_a_later_install_isnt_fresh():
    earlier = [(datetime(2026, 10, 21, tzinfo=UTC), dpkg(V5))]
    history = [event("install", V6, "2026-10-25T00:00:00+00:00")]
    found = judge(PACK, UBUNTU, dpkg(V6), [], NOW, True, history, earlier, True)
    assert found.share == pytest.approx(0.5)


def test_pending_history_leaves_it_incomplete(tmp_path):
    from test_snapshot import host_records, snapshot_of_records

    pending = rec("software", "package_history_pending", path="/var/lib/dnf/history.sqlite-wal")
    records = host_records(planned=["host_facts", "software"], extra=[pending])
    assert not snapshot_of_records(records, tmp_path).sections["package_history"].complete


def test_wrong_somewhere_is_missing_even_when_something_else_isnt_seen():
    files = {FPM: [f"{NAME} = On"], "/etc/apache2/envvars": ["export PHP_INI_SCAN_DIR=/srv/ini"]}
    assert judged(files).status == MISSING


def test_a_pool_given_it_twice_counts_the_wrong_one():
    files = {
        FPM: [f"{NAME} = Off"],
        "/etc/php/8.3/fpm/pool.d/www.conf": [
            "[www]", f"php_admin_flag[{NAME}] = on", f"php_admin_flag[{NAME}] = off"
        ],
    }  # fmt: skip
    assert judged(files).status == MISSING


# --- Sites' own settings (plan 4.4c) ----------------------------------------------------------

POOL = "/etc/php/8.3/fpm/pool.d/www.conf"
USER_INI = "/var/www/shop/.user.ini"
HTACCESS = "/var/www/blog/.htaccess"
APACHE = "/etc/apache2/apache2.conf"
MOD_PHP = "/etc/php/8.3/apache2/php.ini"
LOCKED = ["[www]", f"php_admin_flag[{NAME}] = off", "[api]", f"php_admin_value[{NAME}] = 0"]


def test_a_sites_user_ini_turning_it_back_on_is_missing():
    result = judged({FPM: [f"{NAME} = Off"], USER_INI: [f"{NAME} = 1"]})
    assert result.status == MISSING
    assert [p.where for p in result.places if p.value == "1"] == [f"{USER_INI} (.user.ini)"]
    assert judged({FPM: [f"{NAME} = Off"], USER_INI: [f"{NAME} = Off"]}).status == IN_PLACE


def test_every_pools_admin_setting_locks_out_a_user_ini():
    files = {FPM: [f"{NAME} = Off"], USER_INI: [f"{NAME} = On"], POOL: list(LOCKED)}
    assert judged(files).status == IN_PLACE
    # One pool without it: the site may run there.
    files[POOL] += ["[legacy]", f"php_flag[{NAME}] = off"]
    assert judged(files).status == MISSING
    # CGI reads .user.ini too, and has no php_admin_*.
    files[POOL] = list(LOCKED)
    files["/etc/php/8.3/cgi/php.ini"] = [f"{NAME} = Off"]
    assert judged(files).status == MISSING


def test_a_php_value_passed_to_php_fpm_overrides_even_php_admin():
    # PHP-FPM applies a FastCGI PHP_VALUE over php_admin_* (fpm_php.c).
    for how in ("PHP_VALUE", "PHP_ADMIN_VALUE"):
        files = {FPM: [f"{NAME} = Off"], POOL: list(LOCKED), APACHE: [],
                 HTACCESS: [f'SetEnv {how} "{NAME}=1"']}  # fmt: skip
        assert judged(files).status == MISSING, how
    # Without Apache nothing reads an .htaccess.
    del files[APACHE]
    assert judged(files).status == IN_PLACE


def test_an_htaccess_php_flag_counts_only_with_apaches_php_module():
    files = {FPM: [f"{NAME} = Off"], MOD_PHP: [f"{NAME} = Off"], APACHE: [],
             HTACCESS: [f"php_flag {NAME} on"], POOL: list(LOCKED)}  # fmt: skip
    assert judged(files).status == MISSING  # pools' php_admin_* don't reach Apache's module
    del files[MOD_PHP]
    assert judged(files).status == IN_PLACE  # Apache passes PHP to PHP-FPM only


def test_a_user_ini_counts_only_where_php_fpm_or_cgi_reads_it():
    files = {MOD_PHP: [f"{NAME} = Off"], APACHE: [], USER_INI: [f"{NAME} = On"]}
    assert judged(files).status == IN_PLACE


@pytest.mark.parametrize(
    ("where", "line", "status"),
    [
        (FPM, "user_ini.filename =", IN_PLACE),  # none read
        (FPM, 'user_ini.filename = ""', IN_PLACE),
        (POOL, "php_admin_value[user_ini.filename] = none", NOT_SEEN),
        (FPM, "user_ini.filename = .phprc", NOT_SEEN),
    ],
)
def test_user_ini_filename(where, line, status):
    files = {FPM: [f"{NAME} = Off"], USER_INI: [f"{NAME} = On"]}
    if where == POOL:
        files[POOL] = ["[www]", line]
        line = 'user_ini.filename = ""'
    files[FPM].append(line)
    result = judged(files)
    assert result.status == status
    if status == NOT_SEEN:
        assert "which wasn't read" in result.why


def test_php_value_set_some_other_way_isnt_seen():
    files = {FPM: [f"{NAME} = Off"], APACHE: [],
             HTACCESS: ["[PHP_VALUE set by SetEnvIf: not read]"]}  # fmt: skip
    result = judged(files)
    assert result.status == NOT_SEEN and "SetEnvIf" in result.why
    files[USER_INI] = [f"{NAME} = On"]
    assert judged(files).status == MISSING  # wrong somewhere wins


def test_a_locking_admin_value_that_turns_it_on_locks_nothing():
    files = {FPM: [f"{NAME} = Off"], USER_INI: [f"{NAME} = Off"],
             POOL: ["[www]", f"php_admin_flag[{NAME}] = on"]}  # fmt: skip
    result = judged(files)
    assert result.status == MISSING
    assert [p.where for p in result.places] == [f"{FPM} pool www", f"{USER_INI} (.user.ini)"]
