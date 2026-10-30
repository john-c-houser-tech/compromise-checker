"""What packs read from the evidence, as the controller reads it (plan
4.4): PHP's settings into the snapshot, package history into events."""

from test_snapshot import host_records, rec, snapshot_of_records, text_source

from checker.events import EventBuilder
from checker.protocol import Record
from checker.snapshot import php_settings


def record(module, kind, /, **data):
    return Record(type="record", module=module, name=kind, data=data)


# --- PHP's settings ----------------------------------------------------------------------------


def test_ini_directives_with_their_sections():
    lines = ["[PHP]", "engine = On", "[Session]", 'session.save_path = "/var/lib/php/sessions"',
             "session.upload_progress.enabled = Off ; trailing comment"]  # fmt: skip
    found = dict(php_settings("/etc/php/8.3/fpm/php.ini", lines))
    upload = found["/etc/php/8.3/fpm/php.ini: session.upload_progress.enabled"]
    assert upload == {"path": "/etc/php/8.3/fpm/php.ini", "kind": "ini",
                      "name": "session.upload_progress.enabled", "value": "Off",
                      "section": "Session", "position": 2}  # fmt: skip
    assert found["/etc/php/8.3/fpm/php.ini: session.save_path"]["value"] == "/var/lib/php/sessions"


def test_pool_settings_per_pool():
    lines = ["[www]", "user = www-data", "php_admin_flag[session.upload_progress.enabled] = off",
             "[api]", "php_value[memory_limit] = 256M"]  # fmt: skip
    found = dict(php_settings("/etc/php/8.3/fpm/pool.d/www.conf", lines))
    assert found["/etc/php/8.3/fpm/pool.d/www.conf [www]: session.upload_progress.enabled"] == {
        "path": "/etc/php/8.3/fpm/pool.d/www.conf", "kind": "pool",
        "name": "session.upload_progress.enabled", "value": "off", "section": "www",
        "admin": True,
    }  # fmt: skip
    assert found["/etc/php/8.3/fpm/pool.d/www.conf [api]: memory_limit"]["admin"] is False
    assert php_settings("/etc/nginx/nginx.conf", ["user = x"]) == []


def test_the_snapshot_holds_php_settings(tmp_path):
    ini = "[Session]\nsession.upload_progress.enabled = On\n"
    records = host_records(
        planned=["host_facts", "web_logs"],
        extra=text_source(9, "web_logs", "/etc/php/8.3/fpm/php.ini", ini),
    )
    snap = snapshot_of_records(records, tmp_path)
    settings = snap.sections["php_settings"].items
    assert settings["/etc/php/8.3/fpm/php.ini: session.upload_progress.enabled"]["value"] == "On"


def test_no_package_history_leaves_it_incomplete(tmp_path):
    records = host_records(
        planned=["host_facts", "software"],
        extra=[rec("software", "package_history_absent")],
    )
    snap = snapshot_of_records(records, tmp_path)
    assert not snap.sections["package_history"].complete
    assert snap.sections["packages"].complete  # the listing itself is whole


# --- Package history ---------------------------------------------------------------------------


def test_package_changes_become_events_in_the_hosts_zone():
    builder = EventBuilder()
    builder.record(
        record("host_facts", "clock", localtime_link="/usr/share/zoneinfo/America/Los_Angeles")
    )
    builder.record(record("software", "package_change", manager="dpkg", action="upgrade",
                          name="php8.3-fpm", arch="amd64", previous="8.3.6-0ubuntu0.24.04.5",
                          version="8.3.6-0ubuntu0.24.04.6", local_time="2026-10-23 18:20:02",
                          source="/var/log/dpkg.log"))  # fmt: skip
    builder.record(record("software", "package_change", manager="rpm", action="install",
                          name="bind", version="32:9.16-2.el9", time="2026-10-24T01:00:00+00:00",
                          source="/var/lib/dnf/history.sqlite"))  # fmt: skip
    builder.record(record("software", "package_change", action="explode", name="x"))
    first, second = builder.events
    assert (
        first.type == "package.upgrade" and first.time == "2026-10-24T01:20:02+00:00"
    )  # 18:20 Pacific
    assert first.fields == {"manager": "dpkg", "name": "php8.3-fpm", "arch": "amd64",
                            "version": "8.3.6-0ubuntu0.24.04.6",
                            "previous": "8.3.6-0ubuntu0.24.04.5"}  # fmt: skip
    assert first.source == "software:/var/log/dpkg.log"
    assert second.type == "package.install" and second.fields["version"] == "32:9.16-2.el9"


def test_a_local_time_without_a_known_zone_says_so():
    builder = EventBuilder()
    change = {"manager": "dpkg", "action": "install", "name": "nginx", "version": "1.24-1",
              "local_time": "2026-10-24 09:00:00"}  # fmt: skip
    builder.record(record("software", "package_change", **change))
    (event,) = builder.events
    assert event.fields.get("zone_assumed") is True


def test_quoted_values_scoped_sections_and_repeats():
    lines = ['session.upload_progress.enabled = "0" ; off for CVE-2026-115560',
             "x = 'raw ; value'", "extension=a.so", "extension=b.so",
             "[PATH=/var/www/legacy]", "session.upload_progress.enabled = 1"]  # fmt: skip
    found = dict(php_settings("/etc/php.ini", lines))
    assert found["/etc/php.ini: session.upload_progress.enabled"]["value"] == "0"
    assert found["/etc/php.ini: x"]["value"] == "raw ; value"
    assert found["/etc/php.ini: extension"]["value"] == "a.so"
    assert found["/etc/php.ini: extension #2"]["value"] == "b.so"
    scoped = found["/etc/php.ini [PATH=/var/www/legacy]: session.upload_progress.enabled"]
    assert (
        scoped["value"] == "1"
        and scoped["position"] > found["/etc/php.ini: extension #2"]["position"]
    )


def test_an_ini_file_not_read_leaves_php_settings_incomplete(tmp_path):
    records = host_records(
        planned=["host_facts", "web_logs"],
        extra=[rec("web_logs", "not_examined", path="/etc/php/8.3/fpm/php.ini", reason="x")],
    )
    snap = snapshot_of_records(records, tmp_path)
    assert not snap.sections["php_settings"].complete
    nginx = host_records(
        planned=["host_facts", "web_logs"],
        extra=[rec("web_logs", "not_examined", path="/etc/nginx/nginx.conf", reason="x")],
    )
    assert snapshot_of_records(nginx, tmp_path).sections["php_settings"].complete


def test_the_hour_that_happens_twice_is_uncertain():
    builder = EventBuilder()
    zone = "/usr/share/zoneinfo/America/Los_Angeles"
    builder.record(record("host_facts", "clock", localtime_link=zone))
    change = {"manager": "dpkg", "action": "install", "name": "nginx", "version": "1.24-1"}
    builder.record(record("software", "package_change", **change, local_time="2026-11-01 01:30:00"))
    builder.record(record("software", "package_change", **change, local_time="2026-11-02 01:30:00"))
    twice, once = builder.events
    assert twice.fields.get("time_uncertain") is True and "time_uncertain" not in once.fields
