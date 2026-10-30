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
          names: [php8.3-fpm, libapache2-mod-php8.3]
          fixed: "8.3.6-0ubuntu0.24.04.6"
          source: https://ubuntu.com/security/notices/USN-0000-1
        - release: "rhel:9"
          names: [php-fpm]
          fixed: "8.3.15-1.el9_6"
          source: https://access.redhat.com/errata/RHSA-2026:0000
      stale_code: {programs: ["php-fpm*"]}
    mitigations:
      - id: upload-progress-off
        setting: {kind: php_ini, name: session.upload_progress.enabled}
        expect: "off"
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
    assert rhel.names == ["php-fpm"]
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
        ('release: "rhel:9"', 'release: "ubuntu:24.04"', "a release is listed twice"),
        ('fixed: "8.3.15-1.el9_6"', 'fixed: "8.3 15"', "not a package version"),
        ("names: [php-fpm]", "names: [php-fpm, php-fpm]", "a package is named twice"),
        ("names: [php-fpm]", "names: ['php fpm']", "not a package name"),
        ("names: [php-fpm]", "names: []", "at least 1 item"),
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
    with pytest.raises(PackError, match=None) as caught:
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
    """The pack application uses the format as a library: it must import
    nothing else from the tool."""
    code = (
        "import sys, checker.packs.format\n"
        "extra = sorted(m for m in sys.modules if m.startswith('checker')"
        " and m not in ('checker', 'checker.packs', 'checker.packs.format'))\n"
        "print(extra)\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "[]"


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
