"""The threat-pack format (checker/packs/format.py, plan 4.0). The pack here
is made up for the tests: its versions, dates and addresses are examples."""

import subprocess
import sys
import textwrap

import pytest

from checker import cli
from checker.packs.format import MAX_BYTES, PackError, read

GOOD = textwrap.dedent(
    """\
    format: 1
    id: example-2026-10
    version: 2
    title: "Example: a made-up threat for the tests"
    published: 2026-10-25
    cves: [CVE-2026-109618, CVE-2026-109619]
    exposure:
      window_start: 2026-10-20T00:00:00Z
      first_seen_in_wild: 2026-10-21T07:43:00Z
      likelihood_ratio: 5
      packages:
        - release: "ubuntu:24.04"
          binary_names: [php8.3-fpm, libapache2-mod-php8.3]
          fixed: "8.3.6-0ubuntu0.24.04.6"
          source: https://ubuntu.com/security/notices/USN-0000-1
        - release: "rhel:9"
          binary_names: [php-fpm]
          fixed: "8.3.15-1.el9_6"
          source: https://access.redhat.com/errata/RHSA-2026:0000
      stale_code: {programs: ["php-fpm*"]}
    mitigations:
      - id: upload-progress-off
        setting: {kind: php_ini, name: session.upload_progress.enabled}
        expect: "off"
        default: "on"
        covers: [CVE-2026-115560]
        text: Turn off upload progress tracking until PHP is fixed.
    detections:
      - id: worker-child
        check: web.worker_child
        likelihood_ratio: 20
    remediation:
      - Upgrade PHP to a fixed package and restart every PHP worker.
    references:
      - https://www.cisa.gov/news-events/alerts/2026/10/21/example
    """
)


def changed(old: str, new: str) -> bytes:
    assert old in GOOD, old
    return GOOD.replace(old, new, 1).encode()


def test_a_good_pack_reads_whole():
    pack = read(GOOD.encode())
    assert (pack.id, pack.version, pack.format) == ("example-2026-10", 2, 1)
    ubuntu, rhel = pack.exposure.packages
    assert ubuntu.release == "ubuntu:24.04" and ubuntu.fixed == "8.3.6-0ubuntu0.24.04.6"
    assert rhel.binary_names == ["php-fpm"] and rhel.versions is None
    assert pack.exposure.window_start.isoformat() == "2026-10-20T00:00:00+00:00"
    assert pack.exposure.likelihood_ratio == 5
    assert pack.mitigations[0].setting.name == "session.upload_progress.enabled"
    assert pack.exposure.stale_code.programs == ["php-fpm*"]


@pytest.mark.parametrize(
    ("old", "new", "said"),
    [
        ("format: 1", "format: 2", "this version of the tool reads format 1"),
        ("id: example-2026-10", "id: Example_2026", "id: String should match pattern"),
        ("version: 2", "version: '2'", "version: Input should be a valid integer"),
        ("likelihood_ratio: 5", "likelihood_ratio: 11", "less than or equal to 10"),
        ("likelihood_ratio: 5", "likelihood_ratio: 1", "greater than 1"),
        ('release: "ubuntu:24.04"', 'release: "debian:12"', "ubuntu:YY.MM or rhel:N"),
        ('release: "rhel:9"\n      binary_names: [php-fpm]\n      fixed: "8.3.15-1.el9_6"',
         'release: "ubuntu:24.04"\n      binary_names: [php8.3-fpm]\n      fixed: "8.3.6-1"',
         "same versions pattern"),
        ('fixed: "8.3.15-1.el9_6"', 'fixed: "8.3 15"', "not a package version"),
        ("binary_names: [php-fpm]", "binary_names: [php-fpm, php-fpm]", "a package is named twice"),
        ("binary_names: [php-fpm]", "binary_names: ['php fpm']", "not a package name"),
        ("binary_names: [php-fpm]", "binary_names: []", "at least 1 item"),
        ("https://ubuntu.com/security/notices/USN-0000-1", "http://ubuntu.com/x", "not an https"),
        ("window_start: 2026-10-20T00:00:00Z", "window_start: 2026-10-20T00:00:00",
         "must be a UTC time"),
        ("window_start: 2026-10-20T00:00:00Z", "window_start: 2026-10-20T00:00:00+02:00",
         "must be a UTC time"),
        ("first_seen_in_wild: 2026-10-21T07:43:00Z", "first_seen_in_wild: 2026-10-19T00:00:00Z",
         "before window_start"),
        ('programs: ["php-fpm*"]', 'programs: ["php-fpm[0-9]"]', "not a program pattern"),
        ('programs: ["php-fpm*"]', 'programs: ["*a*b*c*d"]', "not a program pattern"),
        ("kind: php_ini", "kind: registry", "setting.kind"),
        ("covers: [CVE-2026-115560]", "covers: [CVE-26-1]", "not a CVE id"),
        ("check: web.worker_child", "check: 'web; rm'", "not a check id"),
        ("likelihood_ratio: 20", "likelihood_ratio: 500", "less than or equal to 200"),
        ("  - Upgrade PHP", "  - ''\n  - Upgrade PHP", "at least 1 character"),
        ("title:", "colour: red\ntitle:", "Extra inputs are not permitted"),
    ],
)  # fmt: skip
def test_what_is_wrong_is_said(old, new, said):
    with pytest.raises(PackError) as caught:
        read(changed(old, new))
    assert said in str(caught.value)


def test_ids_are_unique_within_a_pack():
    twice = changed(
        "detections:\n",
        "detections:\n  - {id: worker-child, check: web.errors, likelihood_ratio: 2}\n",
    )
    with pytest.raises(PackError, match="a detection id is used twice"):
        read(twice)


def test_a_window_may_end_and_must_end_after_it_starts():
    ended = read(
        changed(
            "  likelihood_ratio: 5", "  window_end: 2026-11-30T00:00:00Z\n  likelihood_ratio: 5"
        )
    )
    assert ended.exposure.window_end.month == 11
    with pytest.raises(PackError, match="window_end must be after window_start"):
        read(
            changed(
                "  likelihood_ratio: 5", "  window_end: 2026-10-01T00:00:00Z\n  likelihood_ratio: 5"
            )
        )


def test_every_problem_is_listed_with_where_it_is():
    both = GOOD.replace("version: 2", "version: 0").replace(
        "likelihood_ratio: 5", "likelihood_ratio: 50"
    )
    with pytest.raises(PackError) as caught:
        read(both.encode())
    lines = str(caught.value).splitlines()
    assert any(line.startswith("version:") for line in lines)
    assert any(line.startswith("exposure.likelihood_ratio:") for line in lines)


# --- Reading safely ----------------------------------------------------------------------------


def test_aliases_are_refused_before_anything_is_built():
    bomb = "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a]\n"
    with pytest.raises(PackError, match="line 2: aliases"):
        read(bomb.encode())


def test_deep_nesting_is_refused():
    deep = "a: " + "[" * 40 + "]" * 40 + "\n"
    with pytest.raises(PackError, match="nested too deeply"):
        read(deep.encode())


def test_a_key_given_twice_is_refused():
    with pytest.raises(PackError, match="the key 'version' is given twice"):
        read(changed("version: 2", "version: 2\nversion: 3"))


def test_no_python_objects_or_huge_files():
    with pytest.raises(PackError, match="not valid YAML"):
        read(b"!!python/object/apply:os.system ['true']\n")
    with pytest.raises(PackError, match="larger than"):
        read(b"#" * (MAX_BYTES + 1))
    with pytest.raises(PackError, match="not UTF-8"):
        read(b"id: \xff\n")
    with pytest.raises(PackError, match="a mapping of fields"):
        read(b"- format\n")


def test_the_format_stands_alone():
    """The pack application uses the format as a library: reading a pack
    must import nothing else from the tool, and nothing outside the
    standard library but PyYAML and pydantic (with pydantic's own)."""
    code = (
        "import sys\n"
        "before = set(sys.modules)\n"
        "import checker.packs.format as f\n"
        f"f.read({GOOD.encode()!r})\n"
        "loaded = {m.split('.')[0] for m in set(sys.modules) - before}\n"
        "print(sorted(m for m in sys.modules if m.startswith('checker')"
        " and m not in ('checker', 'checker.packs', 'checker.packs.format',"
        " 'checker.packs.versions')))\n"
        "print(sorted(m for m in loaded"
        " if m not in sys.stdlib_module_names and not m.startswith('_')))\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    tool, third_party = done.stdout.strip().splitlines()
    assert tool == "[]"
    allowed = {"checker", "yaml", "pydantic", "pydantic_core", "annotated_types",
               "typing_extensions", "typing_inspection", "cython_runtime"}  # fmt: skip
    assert set(eval(third_party)) <= allowed, third_party  # noqa: S307 - our own subprocess's list


# --- The command ---------------------------------------------------------------------------------


def test_check_from_the_command_line(tmp_path, capsys):
    good = tmp_path / "pack.yaml"
    good.write_text(GOOD)
    assert cli.main(["packs", "check", str(good)]) == 0
    out = capsys.readouterr().out
    assert "Valid: example-2026-10 version 2" in out and "ubuntu:24.04, rhel:9" in out
    assert "nothing was trusted or added" in out

    unknown = tmp_path / "unknown.yaml"
    unknown.write_bytes(changed("check: web.worker_child", "check: web.not_a_check"))
    assert cli.main(["packs", "check", str(unknown)]) == 1
    assert "checks this version doesn't have: web.not_a_check" in capsys.readouterr().err

    bad = tmp_path / "bad.yaml"
    bad.write_bytes(changed("version: 2", "version: 0"))
    assert cli.main(["packs", "check", str(bad)]) == 1
    assert "  version: Input should be greater than or equal to 1" in capsys.readouterr().err
    assert cli.main(["packs", "check", str(tmp_path / "missing.yaml")]) == 1


# --- After review: what a file can hold ------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "published: 2026-02-30",
        "published: !!timestamp nope",
        "version: !!int abc",
        "version: !!float abc",
        "version: !!bool maybe",
        "version: " + "9" * 5000,
        "version: 1:59:59:59:59.5",
        "? [a, b]\n: c",
        "<<: {version: 3}",
        "1: one",
    ],
)
def test_a_malformed_file_is_a_pack_error_not_a_crash(bad):
    with pytest.raises(PackError):
        read((GOOD + bad + "\n").encode())


def test_a_window_time_that_doesnt_exist_is_a_pack_error():
    with pytest.raises(PackError):
        read(changed("window_start: 2026-10-20T00:00:00Z", "window_start: 2026-02-30T00:00:00Z"))
    with pytest.raises(PackError):
        read(
            changed("window_start: 2026-10-20T00:00:00Z", "window_start: 2026-10-20T00:00:00+99:00")
        )


def test_yaml_is_read_as_yaml_1_2():
    """off/no/yes stay text; no octal, hex or sixty-based numbers; 1e1 is a number."""
    pack = read(changed('expect: "off"', "expect: off"))
    assert pack.mitigations[0].expect == "off"
    for new in ("version: 0x10", "version: 1:30", "version: 0o10"):
        with pytest.raises(PackError):
            read(changed("version: 2", new))
    assert read(changed("version: 2", "version: 010")).version == 10  # decimal, not octal
    assert (
        read(changed("likelihood_ratio: 5", "likelihood_ratio: 5e0")).exposure.likelihood_ratio == 5
    )


@pytest.mark.parametrize(
    ("old", "new", "said"),
    [
        ("window_start: 2026-10-20T00:00:00Z", "window_start: 2026-10-20T00:00Z", "with seconds"),
        ("window_start: 2026-10-20T00:00:00Z", "window_start: 2026-10-20", "with seconds"),
        ("window_start: 2026-10-20T00:00:00Z", "window_start: '2026-10-20T00:00:00Z'", "unquoted"),
        ("published: 2026-10-25", "published: 2026-10-25T00:00:00Z", "a date alone"),
        ("published: 2026-10-25", "published: '2026-10-25'", "a date alone"),
    ],
)
def test_times_and_dates_say_how_to_write_them(old, new, said):
    with pytest.raises(PackError, match=said):
        read(changed(old, new))


def test_one_release_can_hold_several_repositories_and_streams():
    """Ubuntu's archive and the Sury PPA on one release, and RHEL's PHP
    module streams, each told apart by a pattern on the installed version."""
    more = changed(
        "  stale_code:",
        '    - release: "ubuntu:24.04"\n'
        "      binary_names: [php8.3-fpm]\n"
        '      versions: "*+deb.sury.org*"\n'
        '      fixed: "8.3.27-1+ubuntu24.04.1+deb.sury.org+1"\n'
        "      source: https://launchpad.net/~ondrej/+archive/ubuntu/php\n"
        '    - release: "rhel:9"\n'
        "      binary_names: [php-fpm]\n"
        '      versions: "8.1.*"\n'
        "      fixed: null\n"
        "      source: https://access.redhat.com/security/cve/CVE-2026-109618\n"
        "  stale_code:",
    )
    pack = read(more)
    sury, stream = pack.exposure.packages[2:]
    assert sury.versions == "*+deb.sury.org*" and stream.fixed is None
    with pytest.raises(PackError, match="not a version pattern"):
        read(more.replace(b'"8.1.*"', b'"8.1.[0-9]"'))


def test_no_fix_yet_must_be_said_not_left_out():
    with pytest.raises(PackError, match="fixed"):
        read(changed('      fixed: "8.3.15-1.el9_6"\n', ""))
    assert (
        read(changed('fixed: "8.3.15-1.el9_6"', "fixed: null")).exposure.packages[1].fixed is None
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('title: "Example: a made-up threat for the tests"', 'title: "\\e[31mRED\\e[0m"'),
        ('title: "Example: a made-up threat for the tests"', 'title: "evil\\u202etxt"'),
        ("  - Upgrade PHP", '  - "Upgrade\\u00a0PHP'),
        ("text: Turn off", 'text: "Turn\\x00 off'),
        ("https://www.cisa.gov/news-events/alerts/2026/10/21/example", '"https://x.org/\\u202e"'),
    ],
)
def test_hidden_characters_are_refused(old, new):
    data = changed(old, new)
    if new.count('"') % 2:  # close a quote the replacement opened
        data = data.replace(b"PHP worker.", b'PHP worker."').replace(
            b"PHP is fixed.", b'PHP is fixed."'
        )
    with pytest.raises(PackError, match="hidden or control character"):
        read(data)


def test_errors_show_hidden_characters_escaped_and_stop_at_twenty():
    many = "".join(f"x{n}\u202e: 1\n" for n in range(30))
    with pytest.raises(PackError) as caught:
        read((GOOD + many).encode())
    text = str(caught.value)
    assert "\u202e" not in text and "\\u202e" in text
    assert text.splitlines()[-1] == "…and 10 more" and len(text.splitlines()) == 21


@pytest.mark.parametrize(
    "url",
    ["https://-.:99999", "https://127.0.0.1/", "https://localhost/x", "https://a.org:0/",
     "https://user@a.org/", "https://a.org:70000/", "https://a/", "https://" + "a" * 600 + ".org"],
)  # fmt: skip
def test_addresses_are_public_https_hosts(url):
    with pytest.raises(PackError, match="address"):
        read(changed("https://www.cisa.gov/news-events/alerts/2026/10/21/example", url))


def test_window_end_after_first_seen_and_no_duplicate_covers():
    with pytest.raises(PackError, match="before first_seen_in_wild"):
        read(
            changed(
                "  likelihood_ratio: 5", "  window_end: 2026-10-21T00:00:00Z\n  likelihood_ratio: 5"
            )
        )
    with pytest.raises(PackError, match="a CVE is listed twice"):
        read(changed("covers: [CVE-2026-115560]", "covers: [CVE-2026-115560, CVE-2026-115560]"))


@pytest.mark.parametrize(("value", "said"), [("true", "format True"), ("1.0", "format 1.0")])
def test_format_must_be_the_integer_1(value, said):
    with pytest.raises(PackError, match=said):
        read(changed("format: 1", f"format: {value}"))
    with pytest.raises(PackError, match="no format field"):
        read(changed("format: 1\n", ""))


def test_check_reads_only_a_regular_file(tmp_path, capsys):
    import os

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert cli.main(["packs", "check", str(fifo)]) == 1
    assert "not a regular file" in capsys.readouterr().err
    assert cli.main(["packs", "check", str(tmp_path)]) == 1


def test_check_shows_a_title_safely(tmp_path, capsys, monkeypatch):
    from checker.packs import format as pack_format

    good = tmp_path / "pack.yaml"
    good.write_text(GOOD)
    real = pack_format.read

    def odd_title(data):
        return real(data).model_copy(update={"title": "a\x1b[2Jb"})

    monkeypatch.setattr(pack_format, "read", odd_title)
    assert cli.main(["packs", "check", str(good)]) == 0
    assert "\x1b" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("bad", "said"),
    [
        ("<<: {version: 3}", "merge keys"),
        ("1: one", "a key must be text"),
        ("? [a, b]\n: c", "a key must be text"),
    ],
)
def test_keys_are_plain_text(bad, said):
    with pytest.raises(PackError, match=said):
        read((GOOD + bad + "\n").encode())


def test_integers_are_decimal_and_bounded():
    with pytest.raises(PackError, match="not a decimal integer"):
        read(changed("version: 2", "version: " + "9" * 19))


def test_a_local_host_name_is_refused():
    with pytest.raises(PackError, match="public host name"):
        read(changed("https://www.cisa.gov/", "https://localhost.localdomain/"))


@pytest.mark.parametrize("fixed", ["8.3.6", "1:8.3.6", "8.3.6-", "-1"])
def test_a_fixed_version_carries_the_vendors_part(fixed):
    with pytest.raises(PackError, match="revision or release"):
        read(changed('fixed: "8.3.15-1.el9_6"', f'fixed: "{fixed}"'))
    assert read(changed('fixed: "8.3.15-1.el9_6"', 'fixed: "1:8.3.15-1.el9_6"'))


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('fixed: "8.3.6-0ubuntu0.24.04.6"', 'fixed: "8.3.6-0ubuntu_0"'),  # _ isn't dpkg's
        ('fixed: "8.3.15-1.el9_6"', 'fixed: "99999999999:8.3.15-1.el9_6"'),  # epoch too big
    ],
)
def test_a_fixed_version_is_read_as_its_family_reads_it(old, new):
    with pytest.raises(PackError, match="dpkg|rpm"):
        read(changed(old, new))
