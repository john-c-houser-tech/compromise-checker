"""The web interface's accounts and record on PostgreSQL. Each case runs in a process of its own,
since Django is set up once per process, against a schema of its own on a throwaway server."""

import json
import os
import secrets
import sqlite3
import subprocess
import sys
import textwrap

import pytest

server = os.environ.get("CHECKER_TEST_POSTGRES")
pytestmark = pytest.mark.skipif(
    not server, reason="needs CHECKER_TEST_POSTGRES: a throwaway server"
)

START = """
import json, sys, threading
from pathlib import Path
from checker.web.app import configure
configure(Path(sys.argv[1]))
from django.contrib.auth import get_user_model
from django.db import connection, connections, transaction, DatabaseError
from django.utils import timezone
from checker.web import accounts
from checker.web.models import Access, ActionRecord, LoginAttempt
"""


@pytest.fixture
def address():
    import psycopg

    schema = f"w{secrets.token_hex(6)}"
    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"CREATE SCHEMA {schema}")
    separator = "&" if "?" in server else "?"
    yield f"{server}{separator}options=-csearch_path%3D{schema}", schema
    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"DROP SCHEMA {schema} CASCADE")


@pytest.fixture
def home(tmp_path, address):
    (tmp_path / "keys").mkdir()
    (tmp_path / "config.yaml").write_text(f"database: {address[0]}\n")
    return tmp_path


def run(home, body, *arguments, check=True):
    done = subprocess.run(
        [sys.executable, "-c", START + textwrap.dedent(body), str(home), *arguments],
        capture_output=True,
        text=True,
        timeout=120,
        env=os.environ | {"CHECKER_HOME": str(home)},
    )
    if check:
        assert done.returncode == 0, done.stderr
        return json.loads(done.stdout.strip().splitlines()[-1])
    return done


def test_it_starts_empty_there_and_makes_no_file(home, address):
    result = run(home, "print(json.dumps([connection.vendor, accounts.no_accounts()]))")
    assert result == ["postgresql", True]
    assert not (home / "web.db").exists()
    import psycopg

    with psycopg.connect(address[0]) as db:
        assert db.execute("SELECT to_regclass('auth_user')").fetchone()[0] == "auth_user"


def test_guesses_sent_at_once_cant_all_pass_the_count(home):
    """Without one writer at a time, every one of these reads the count before any adds to it."""
    allowed, limit = run(
        home,
        """
        gate = threading.Barrier(16)
        results = []
        def guess():
            gate.wait()
            results.append(accounts.begin_login("jo", "198.51.100.1"))
            connection.close()
        threads = [threading.Thread(target=guess) for _ in range(16)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        print(json.dumps([sum(results), accounts.MAX_FAILURES_FOR_NAME]))
        """,
    )
    assert allowed == limit


def test_two_people_cant_take_each_others_access_at_once(home):
    result = run(
        home,
        """
        users = get_user_model().objects
        a = users.create_user("a", password="x" * 14)
        b = users.create_user("b", password="y" * 14)
        Access.objects.create(user=a, full=True)
        Access.objects.create(user=b, full=True)
        gate = threading.Barrier(2)
        def take(actor, name):
            gate.wait()
            try:
                accounts.set_access(actor, name, False)
            except accounts.PersonProblem:
                pass
            connection.close()
        for _ in range(10):
            threads = [threading.Thread(target=take, args=pair) for pair in ((a, "b"), (b, "a"))]
            [t.start() for t in threads]
            [t.join() for t in threads]
            left = Access.objects.filter(full=True).count()
            if left != 1:
                print(json.dumps(left)); break
            Access.objects.update(full=True)
        else:
            print(json.dumps(1))
        """,
    )
    assert result == 1


def test_two_tabs_cant_make_two_first_accounts(home):
    result = run(
        home,
        """
        link = accounts.setup_link("http://x")
        token = link.rpartition("/")[2]
        gate = threading.Barrier(6)
        made = []
        def go(n):
            gate.wait()
            try:
                made.append(accounts.create_first_account(token, f"u{n}", "a long password here"))
            finally:
                connection.close()
        threads = [threading.Thread(target=go, args=(n,)) for n in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        print(json.dumps([sum(m is not None for m in made), get_user_model().objects.count()]))
        """,
    )
    assert result == [1, 1]


def test_the_record_refuses_change_including_truncate(home):
    result = run(
        home,
        """
        ActionRecord.objects.create(at=timezone.now(), who="", address="", action="x", target="",
                                    outcome="", detail="")
        held = []
        for sql in ("UPDATE web_actionrecord SET who='y'", "DELETE FROM web_actionrecord",
                    "TRUNCATE web_actionrecord"):
            try:
                with transaction.atomic(), connection.cursor() as cursor:
                    cursor.execute(sql)
                held.append(False)
            except DatabaseError as exc:
                held.append("append-only" in str(exc))
        print(json.dumps(held))
        """,
    )
    assert result == [True, True, True]


def test_a_disabled_guard_goes_back_at_the_next_start(home, address):
    import psycopg

    run(
        home,
        """
        ActionRecord.objects.create(at=timezone.now(), who="", address="", action="x", target="",
                                    outcome="", detail="")
        print(1)
        """,
    )
    with psycopg.connect(address[0], autocommit=True) as db:
        db.execute("ALTER TABLE web_actionrecord DISABLE TRIGGER web_actionrecord_no_delete")
    result = run(
        home,
        """
        try:
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute("DELETE FROM web_actionrecord")
            print(json.dumps("deleted"))
        except DatabaseError:
            print(json.dumps("held"))
        """,
    )
    assert result == "held"


def test_a_nul_in_a_name_is_a_name_that_doesnt_exist(home):
    result = run(
        home,
        """
        name = "jo\\x00hn"
        print(json.dumps([accounts.begin_login(name, "198.51.100.1"),
                          accounts.no_such_account(name) is not None,
                          LoginAttempt.objects.get().username]))
        """,
    )
    assert result == [True, True, "jo\\u0000hn"]


def test_another_applications_tables_are_refused_not_taken_for_ours(home, address):
    import psycopg

    with psycopg.connect(address[0], autocommit=True) as db:
        db.execute("CREATE TABLE auth_user (id int)")
    done = run(home, "print(1)", check=False)
    assert done.returncode != 0 and "didn't make" in done.stderr


def test_another_django_applications_migrations_are_refused(home, address):
    import psycopg

    with psycopg.connect(address[0], autocommit=True) as db:
        db.execute("CREATE TABLE django_migrations (id int)")
    done = run(home, "print(1)", check=False)
    assert done.returncode != 0 and "didn't make" in done.stderr


def test_a_session_with_triggers_off_is_refused(home, address):
    import psycopg

    role = f"r{secrets.token_hex(4)}"
    # Set for the database's account in general, and the store refuses that too: tested there.
    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"CREATE ROLE {role} SUPERUSER LOGIN PASSWORD 'test'")
        admin.execute(f"ALTER ROLE {role} SET session_replication_role = replica")
    try:
        separator = "&" if "?" in address[0] else "?"
        as_role = f"{address[0]}{separator}user={role}"
        (home / "config.yaml").write_text(f"database: {as_role}\n")
        done = run(home, "print(1)", check=False)
        assert done.returncode != 0 and "session_replication_role" in done.stderr
    finally:
        with psycopg.connect(server, autocommit=True) as admin:
            admin.execute(f"DROP ROLE {role}")


def test_settings_naming_a_database_with_accounts_still_in_the_file_are_refused(home):
    (home / "web.db").write_bytes(b"something")
    done = run(home, "print(1)", check=False)
    assert done.returncode != 0 and "checker store move" in done.stderr


def test_a_lost_settings_file_doesnt_start_empty_accounts(tmp_path):
    (tmp_path / "web.db.moved").write_bytes(b"something")
    done = run(tmp_path, "print(1)", check=False)
    assert done.returncode != 0 and "restore config.yaml" in done.stderr
    assert not (tmp_path / "web.db").exists()


def test_two_starts_at_once_both_succeed(home):
    runs = [
        subprocess.Popen(
            [sys.executable, "-c", START, str(home)],
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    for each in runs:
        _, err = each.communicate(timeout=120)
        assert each.returncode == 0, err


MAKE_ACCOUNTS = """
import sys
from pathlib import Path
from checker.web.app import configure
configure(Path(sys.argv[1]))
from django.contrib.auth import authenticate, get_user_model
from django.utils import timezone
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from checker.web import two_factor
from checker.web.models import Access, ActionRecord, Invitation
users = get_user_model().objects
jo = users.create_user("jo", password="the first long password")
Access.objects.create(user=jo, full=True)
sam = users.create_user("sam", password="a second long password")
TOTPDevice.objects.create(user=jo, name="authenticator", confirmed=True)
two_factor.new_recovery_codes(jo)
when = timezone.now().replace(microsecond=123456)
for n in range(3):
    ActionRecord.objects.create(at=when, who="jo", address="a", action=f"did {n}", target="t" * 201,
                                outcome="done", detail="d")
"""

READ_ACCOUNTS = """
from django.contrib.auth import authenticate
from django_otp.plugins.otp_static.models import StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice
records = list(ActionRecord.objects.order_by("id").values_list("id", "action", "target"))
new = ActionRecord.objects.create(at=timezone.now(), who="", address="", action="new", target="",
                                  outcome="", detail="")
print(json.dumps({
    "vendor": connection.vendor,
    "jo": authenticate(username="jo", password="the first long password") is not None,
    "full": list(Access.objects.values_list("user__username", "full")),
    "totp": TOTPDevice.objects.filter(user__username="jo", confirmed=True).count(),
    "codes": StaticToken.objects.filter(device__user__username="jo").count(),
    "records": [r[1] for r in records],
    "long": len(records[0][2]),
    "numbered_after": new.id > records[-1][0],
    "at": ActionRecord.objects.order_by("id").first().at.microsecond,
}))
"""


def made_store_and_accounts(home):
    (home / "config.yaml").unlink()
    env = os.environ | {"CHECKER_HOME": str(home)}
    subprocess.run(
        [sys.executable, "-m", "checker", "init", "--advisor", "off"],
        check=True,
        env=env,
        capture_output=True,
        input="",
        text=True,
    )
    subprocess.run(
        [sys.executable, "-c", MAKE_ACCOUNTS, str(home)], check=True, env=env, capture_output=True
    )


def move(home, to, *more, check=True):
    done = subprocess.run(
        [sys.executable, "-m", "checker", "store", "move", "--to", to, *more],
        capture_output=True,
        text=True,
        input="no\n",
        timeout=120,
        env=os.environ | {"CHECKER_HOME": str(home)},
    )
    if check:
        assert done.returncode == 0, done.stderr
    return done


def test_moving_keeps_accounts_two_factor_the_record_and_its_numbers(home, address):
    made_store_and_accounts(home)
    done = move(home, address[0])
    assert "accounts and record" in done.stdout
    assert not (home / "web.db").exists()
    assert (home / "web.db.moved").exists()
    result = run(home, READ_ACCOUNTS)
    assert result["vendor"] == "postgresql" and result["jo"]
    assert result["full"] == [["jo", True]]
    assert result["totp"] == 1 and result["codes"] > 0
    assert result["records"] == ["did 0", "did 1", "did 2"]
    assert result["long"] == 201  # a line longer than the old column allowed for is kept whole
    assert result["numbered_after"]
    assert result["at"] == 123456
    # The old file really has what was moved: the rename didn't lose anything to look back on.
    with sqlite3.connect(home / "web.db.moved") as old:
        assert old.execute("SELECT count(*) FROM web_actionrecord").fetchone()[0] == 3


def test_a_move_that_cant_finish_leaves_nothing_there_and_the_old_ones_in_charge(home, address):
    made_store_and_accounts(home)
    with sqlite3.connect(home / "web.db") as old:
        old.execute("UPDATE auth_user SET first_name = ? WHERE username = 'jo'", ("x" * 151,))
    done = move(home, address[0], check=False)
    assert done.returncode == 1 and "not moved" in done.stderr
    assert (home / "web.db").exists() and not (home / "web.db.moved").exists()
    assert "database" not in (home / "config.yaml").read_text().replace("database: null", "")
    import psycopg

    with psycopg.connect(address[0]) as db:
        assert db.execute("SELECT to_regclass('auth_user')").fetchone()[0] is None
        assert db.execute("SELECT to_regclass('django_migrations')").fetchone()[0] is None
    with sqlite3.connect(home / "web.db") as old:
        old.execute("UPDATE auth_user SET first_name = '' WHERE username = 'jo'")
    move(home, address[0])  # so it can be tried again
    assert run(home, READ_ACCOUNTS)["jo"]


def test_a_store_copy_that_fails_takes_the_accounts_back_too(home, address):
    import psycopg

    made_store_and_accounts(home)
    with psycopg.connect(address[0], autocommit=True) as db:
        db.execute("CREATE TABLE bundles (id int)")  # the store will refuse this
    done = move(home, address[0], check=False)
    assert done.returncode == 1
    with psycopg.connect(address[0]) as db:
        assert db.execute("SELECT to_regclass('auth_user')").fetchone()[0] is None
    assert (home / "web.db").exists()


def test_a_store_already_there_can_have_its_accounts_join_it(home, address):
    made_store_and_accounts(home)
    accounts_file = home / "web.db"
    held = home / "held"
    accounts_file.rename(held)
    move(home, address[0])
    held.rename(accounts_file)
    assert run(home, "print(1)", check=False).returncode != 0
    assert move(home, f"{address[0]}&x=1", check=False).returncode == 1
    done = move(home, address[0])
    assert "bundle" not in done.stdout and "accounts and record" in done.stdout
    assert run(home, READ_ACCOUNTS)["jo"]


def test_a_move_stopped_before_its_last_step_can_be_finished(home, address):
    made_store_and_accounts(home)
    move(home, address[0])
    (home / "web.db.moved").rename(home / "web.db")  # as if stopped before the rename
    done = move(home, address[0])
    assert "accounts and record" in done.stdout
    assert run(home, READ_ACCOUNTS)["jo"]


def test_a_move_refuses_a_database_holding_other_accounts(home, address):
    made_store_and_accounts(home)
    move(home, address[0])
    run(home, 'get_user_model().objects.create_user("another", password="z" * 14); print(1)')
    (home / "web.db.moved").rename(home / "web.db")
    done = move(home, address[0], check=False)
    assert done.returncode == 1 and "other accounts" in done.stderr
