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


def a_role(*settings):
    import psycopg

    role = f"r{secrets.token_hex(4)}"
    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"CREATE ROLE {role} SUPERUSER LOGIN PASSWORD 'test'")
        for setting in settings:
            admin.execute(f"ALTER ROLE {role} SET {setting}")
    return role


def drop_role(role):
    import psycopg

    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"DROP ROLE {role}")


GUESSES_AT_ONCE = """
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
"""


def test_the_lock_means_the_same_when_a_stricter_level_is_the_default(home, address):
    """At REPEATABLE READ a waiter reads from before it waited, so all of these would pass."""
    role = a_role("default_transaction_isolation = 'repeatable read'")
    try:
        (home / "config.yaml").write_text(f"database: {address[0]}&user={role}\n")
        allowed, limit = run(home, GUESSES_AT_ONCE)
        assert allowed == limit
    finally:
        import psycopg

        with psycopg.connect(address[0], autocommit=True) as db:
            db.execute(f"DROP OWNED BY {role} CASCADE")
        drop_role(role)


def test_the_stores_writers_read_what_the_last_one_wrote_at_a_stricter_default(address):
    from checker.database import PostgresDatabase

    role = a_role("default_transaction_isolation = 'repeatable read'")
    try:
        db = PostgresDatabase(f"{address[0]}&user={role}")
        level = db.execute("SHOW transaction_isolation").fetchone()[0]
        db.close()
        assert level == "read committed"
    finally:
        drop_role(role)


def test_another_schema_on_the_path_isnt_taken_for_ours_and_a_failed_move_leaves_it(home, address):
    import psycopg

    role = a_role()
    schema = address[1]
    other = f"o{secrets.token_hex(4)}"
    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"CREATE SCHEMA {other}")
        admin.execute(f"CREATE TABLE {other}.django_migrations (id int)")
        admin.execute(f"CREATE TABLE {other}.auth_user (id int)")
        admin.execute(f"ALTER ROLE {role} SET search_path = {schema}, {other}")
    plain = f"{server}{'&' if '?' in server else '?'}user={role}"
    try:
        (home / "config.yaml").write_text(f"database: {plain}\n")
        done = run(home, "print(1)", check=False)
        assert done.returncode != 0 and "didn't make" in done.stderr
        with psycopg.connect(server, autocommit=True) as admin:
            found = admin.execute(
                "SELECT obj_description(oid, 'pg_class') FROM pg_class WHERE relnamespace ="
                " %s::regnamespace AND relname = 'django_migrations'",
                (other,),
            ).fetchone()
        assert found == (None,), "its table wasn't marked as ours"
        made_store_and_accounts(home)
        assert move(home, plain, check=False).returncode == 1
        with psycopg.connect(server, autocommit=True) as admin:
            for table in ("django_migrations", "auth_user"):
                assert admin.execute(f"SELECT to_regclass('{other}.{table}')").fetchone()[0]
    finally:
        with psycopg.connect(server, autocommit=True) as admin:
            admin.execute(f"DROP SCHEMA {other} CASCADE")
        drop_role(role)


def test_a_refused_session_isnt_kept_for_the_next_use(home, address):
    import psycopg

    role = a_role()
    try:
        (home / "config.yaml").write_text(f"database: {address[0]}&user={role}\n")
        result = run(
            home,
            f"""
            import psycopg
            connection.close()
            with psycopg.connect(sys.argv[2], autocommit=True) as admin:
                admin.execute("ALTER ROLE {role} SET session_replication_role = replica")
            refused = []
            for _ in range(2):
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT 1")
                    refused.append(False)
                except RuntimeError:
                    refused.append(True)
            print(json.dumps(refused))
            """,
            server,
        )
        assert result == [True, True]
    finally:
        with psycopg.connect(address[0], autocommit=True) as db:
            db.execute(f"DROP OWNED BY {role} CASCADE")
        drop_role(role)


def test_a_database_not_in_utf8_is_refused(tmp_path):
    import psycopg

    name = f"d{secrets.token_hex(4)}"
    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"CREATE DATABASE {name} ENCODING 'LATIN1' LOCALE 'C' TEMPLATE template0")
    try:
        base = server.rpartition("/")[0]
        (tmp_path / "keys").mkdir()
        (tmp_path / "config.yaml").write_text(f"database: {base}/{name}\n")
        done = run(tmp_path, "print(1)", check=False)
        assert done.returncode != 0 and "UTF8" in done.stderr
    finally:
        with psycopg.connect(server, autocommit=True) as admin:
            admin.execute(f"DROP DATABASE {name}")


def test_names_that_grow_once_stored_are_still_only_wrong_logins(home):
    result = run(
        home,
        """
        results = [accounts.begin_login(name, "198.51.100.1")
                   for name in ("\\x00" * 26, "a" * 149 + "\\x00", "x" * 5000)]
        lengths = sorted(len(n) for n in LoginAttempt.objects.values_list("username", flat=True))
        print(json.dumps([results, lengths[-1]]))
        """,
    )
    assert result == [[True, True, True], 150]


def test_a_throttle_still_counts_a_name_too_long_to_keep_whole(home):
    result = run(
        home,
        """
        name = "x" * 5000
        answers = [accounts.begin_login(name, "198.51.100.1") for _ in range(7)]
        print(json.dumps(sum(answers)))
        """,
    )
    assert result == 5


def test_old_failed_logins_dont_stop_a_move(home, address):
    made_store_and_accounts(home)
    with sqlite3.connect(home / "web.db") as old:
        old.execute(
            "INSERT INTO web_loginattempt (username, address, at) VALUES (?, 'a', '2026-01-01')",
            ("\x00" * 150,),
        )
    move(home, address[0])
    assert run(home, READ_ACCOUNTS)["jo"]


def test_the_move_leaves_the_old_file_owner_only(home, address):
    made_store_and_accounts(home)
    (home / "web.db").chmod(0o644)
    move(home, address[0])
    assert (home / "web.db.moved").stat().st_mode & 0o077 == 0


def test_a_stale_file_beside_a_database_in_use_doesnt_advise_emptying_it(home, address):
    made_store_and_accounts(home)
    move(home, address[0])
    run(home, 'get_user_model().objects.create_user("another", password="z" * 14); print(1)')
    (home / "web.db.moved").rename(home / "web.db")
    done = move(home, address[0], check=False)
    assert done.returncode == 1 and "don't empty" in done.stderr


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
    assert done.returncode == 1 and "different accounts" in done.stderr


def test_a_move_into_a_database_holding_another_installs_accounts_says_use_an_empty_one(
    home, address, tmp_path_factory
):
    made_store_and_accounts(home)
    other = tmp_path_factory.mktemp("other")
    (other / "keys").mkdir()
    (other / "config.yaml").write_text(f"database: {address[0]}\n")
    run(other, 'get_user_model().objects.create_user("another", password="z" * 14); print(1)')
    done = move(home, address[0], check=False)
    assert done.returncode == 1 and "use an empty one" in done.stderr


def test_a_move_stopped_before_it_copied_starts_again_and_loses_nobody(home, address):
    """The store's already there, and the tables were made but nothing came across."""
    made_store_and_accounts(home)
    (home / "web.db").rename(home / "held")
    move(home, address[0])
    run(home, "print(1)")  # empty tables, marked as ours, as a move stopped there would leave
    (home / "held").rename(home / "web.db")
    done = move(home, address[0])
    assert "accounts and record" in done.stdout
    result = run(home, READ_ACCOUNTS)
    assert result["jo"] and result["records"] == ["did 0", "did 1", "did 2"]


def test_a_nul_in_the_record_moves_as_the_database_shows_it(home, address):
    made_store_and_accounts(home)
    with sqlite3.connect(home / "web.db") as old:
        old.execute("DROP TRIGGER web_actionrecord_no_update")
        old.execute("UPDATE web_actionrecord SET detail = ?", ("a\x00b",))
    move(home, address[0])
    assert run(home, "print(json.dumps(ActionRecord.objects.first().detail))") == "a\\u0000b"


def test_a_move_doesnt_depend_on_how_the_database_orders_text(tmp_path):
    """In Czech, ch sorts after h, so the two databases' own orders of these keys differ."""
    import psycopg

    name = f"d{secrets.token_hex(4)}"
    with psycopg.connect(server, autocommit=True) as admin:
        if admin.info.server_version < 150000:
            pytest.skip("ICU as a database's locale needs PostgreSQL 15")
        admin.execute(
            f"CREATE DATABASE {name} TEMPLATE template0 LOCALE_PROVIDER icu ICU_LOCALE 'cs'"
        )
    try:
        (tmp_path / "keys").mkdir()
        (tmp_path / "config.yaml").write_text("")
        made_store_and_accounts(tmp_path)
        with sqlite3.connect(tmp_path / "web.db") as old:
            for key in ("ch1", "ci1", "cz1", "h1"):
                old.execute(
                    "INSERT INTO django_session (session_key, session_data, expire_date)"
                    " VALUES (?, 'x', '2099-01-01 00:00:00')",
                    (key,),
                )
        move(tmp_path, f"{server.rpartition('/')[0]}/{name}")
    finally:
        with psycopg.connect(server, autocommit=True) as admin:
            admin.execute(f"DROP DATABASE {name} WITH (FORCE)")


def test_taking_away_only_touches_whats_ours_in_our_schema(home, address):
    import psycopg

    role = a_role()
    schema = address[1]
    other = f"o{secrets.token_hex(4)}"
    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"CREATE SCHEMA {other}")
        admin.execute(f"ALTER ROLE {role} SET search_path = {schema}, {other}")
    plain = f"{server}{'&' if '?' in server else '?'}user={role}"
    try:
        (home / "config.yaml").write_text(f"database: {plain}\n")
        # Set up after its start, which would rightly refuse this layout.
        result = run(
            home,
            f"""
            from checker.web import postgres
            with connection.cursor() as cursor:
                cursor.execute("DROP TABLE {schema}.web_checkrun")
                cursor.execute("CREATE TABLE {other}.web_checkrun (id int)")
                cursor.execute("COMMENT ON TABLE django_migrations IS NULL")
            postgres.drop_ours(connection)  # without the mark it isn't ours, so it stays
            with connection.cursor() as cursor:
                cursor.execute("SELECT to_regclass('{schema}.django_migrations')")
                kept = cursor.fetchone()[0] is not None
                cursor.execute(
                    "COMMENT ON TABLE django_migrations IS 'compromise-checker web interface'"
                )
            postgres.drop_ours(connection)
            print(json.dumps(kept))
            """,
        )
        assert result is True
        with psycopg.connect(server, autocommit=True) as admin:
            assert admin.execute(f"SELECT to_regclass('{other}.web_checkrun')").fetchone()[0]
            assert admin.execute(f"SELECT to_regclass('{schema}.auth_user')").fetchone()[0] is None
    finally:
        with psycopg.connect(server, autocommit=True) as admin:
            admin.execute(f"DROP SCHEMA {other} CASCADE")
            admin.execute(f"DROP OWNED BY {role} CASCADE")
        drop_role(role)


def test_a_role_with_another_client_encoding_can_still_store_any_text(address):
    from checker.database import PostgresDatabase

    role = a_role("client_encoding = 'LATIN1'")
    try:
        db = PostgresDatabase(f"{address[0]}&user={role}")
        assert (
            db.execute("SELECT %s AS t".replace("%s", "?"), ["日本語"]).fetchone()["t"] == "日本語"
        )
        db.close()
    finally:
        drop_role(role)


def test_a_table_gone_missing_doesnt_reach_one_further_along_the_path(home, address):
    """A partial restore: its accounts would otherwise be able to sign in."""
    import psycopg

    role = a_role()
    schema = address[1]
    other = f"o{secrets.token_hex(4)}"
    with psycopg.connect(server, autocommit=True) as admin:
        admin.execute(f"CREATE SCHEMA {other}")
        admin.execute(f"ALTER ROLE {role} SET search_path = {schema}, {other}")
    plain = f"{server}{'&' if '?' in server else '?'}user={role}"
    try:
        (home / "config.yaml").write_text(f"database: {plain}\n")
        run(home, "print(1)")
        with psycopg.connect(server, autocommit=True) as admin:
            admin.execute(f"CREATE TABLE {other}.web_access (id int)")
        run(home, "print(1)")  # shadowed by its own, so nothing is wrong yet
        with psycopg.connect(server, autocommit=True) as admin:
            admin.execute(f"DROP TABLE {schema}.web_access")
        done = run(home, "print(1)", check=False)
        assert done.returncode != 0 and "restore the database" in done.stderr
    finally:
        with psycopg.connect(server, autocommit=True) as admin:
            admin.execute(f"DROP SCHEMA {other} CASCADE")
            admin.execute(f"DROP OWNED BY {role} CASCADE")
        drop_role(role)


def test_a_file_in_wal_mode_is_whole_after_the_move(home, address):
    made_store_and_accounts(home)
    with sqlite3.connect(home / "web.db") as old:
        assert old.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    old.close()
    move(home, address[0])
    assert not (home / "web.db-wal.moved").exists()
    with sqlite3.connect(home / "web.db.moved") as kept:
        assert kept.execute("SELECT count(*) FROM web_actionrecord").fetchone()[0] == 3
    kept.close()


def test_a_file_from_before_view_only_accounts_moves_with_their_access(home, address):
    """Migrating it reads and writes the file, not the database it's moving to."""
    made_store_and_accounts(home)
    (home / "web.db").unlink()
    env = os.environ | {"CHECKER_HOME": str(home)}
    old_version = """
import sys
from pathlib import Path
from checker.web.app import django_settings
import django
from django.conf import settings
from django.contrib.auth.hashers import make_password
settings.configure(**django_settings(Path(sys.argv[1])))
django.setup()
from django.core.management import call_command
from django.contrib.auth import get_user_model
call_command("migrate", "web", "0004", verbosity=0)
call_command("migrate", "auth", verbosity=0)
get_user_model().objects.create_user("jo", password="the first long password")
"""
    subprocess.run(
        [sys.executable, "-c", old_version, str(home)], check=True, env=env, capture_output=True
    )
    move(home, address[0])
    assert run(home, "print(json.dumps(list(Access.objects.values_list('full', flat=True))))") == [
        True
    ]


def test_a_moved_database_never_gives_a_deleted_devices_number_again(home, address):
    """A session can still name that device, and would count as verified with the new one."""
    made_store_and_accounts(home)
    env = os.environ | {"CHECKER_HOME": str(home)}
    delete = """
import sys
from pathlib import Path
from checker.web.app import configure
configure(Path(sys.argv[1]))
from django_otp.plugins.otp_totp.models import TOTPDevice
print(TOTPDevice.objects.get().pk)
TOTPDevice.objects.all().delete()
"""
    done = subprocess.run(
        [sys.executable, "-c", delete, str(home)],
        check=True, env=env, capture_output=True, text=True,
    )  # fmt: skip
    old = int(done.stdout.strip())
    move(home, address[0])
    new = run(
        home,
        """
        from django_otp.plugins.otp_totp.models import TOTPDevice
        user = get_user_model().objects.get(username="jo")
        print(json.dumps(TOTPDevice.objects.create(user=user, name="n", confirmed=True).pk))
        """,
    )
    assert new > old


def test_a_store_file_left_by_a_stopped_move_is_retired_when_it_finishes(home, address):
    made_store_and_accounts(home)
    move(home, address[0])
    (home / "web.db.moved").rename(
        home / "web.db"
    )  # stopped after the settings, before the renames
    (home / "checker.db.moved").rename(home / "checker.db")
    move(home, address[0])
    assert not (home / "checker.db").exists() and (home / "checker.db.moved").exists()
    assert not (home / "web.db").exists() and (home / "web.db.moved").exists()


def test_a_database_that_cant_be_reached_stops_a_move_with_words(home):
    made_store_and_accounts(home)
    done = move(home, "postgresql://postgres@127.0.0.1:1/nothing", check=False)
    assert done.returncode == 1 and "not moved" in done.stderr
    assert "Traceback" not in done.stderr
    assert (home / "web.db").exists()


def test_a_move_with_accounts_but_no_web_extra_says_so(tmp_path, address):
    (tmp_path / "web.db").write_bytes(b"x")
    made = """
import sys
sys.modules["django"] = None
from checker import cli
raise SystemExit(cli.main(["store", "move", "--to", sys.argv[1], "--yes"]))
"""
    env = os.environ | {"CHECKER_HOME": str(tmp_path)}
    subprocess.run(
        [sys.executable, "-m", "checker", "init", "--advisor", "off"],
        check=True, env=env, capture_output=True, text=True, input="",
    )  # fmt: skip
    done = subprocess.run(
        [sys.executable, "-c", made, address[0]], capture_output=True, text=True, env=env
    )
    assert done.returncode == 2 and "pip install" in done.stderr and "Traceback" not in done.stderr


def test_a_move_into_a_database_with_someone_elses_accounts_is_refused(home, address):
    import psycopg

    made_store_and_accounts(home)
    other = f"{address[0]}"
    with psycopg.connect(other, autocommit=True) as db:
        db.execute("CREATE TABLE auth_user (id int)")
    done = move(home, other, check=False)
    assert done.returncode == 1 and "didn't make" in done.stderr
    with psycopg.connect(other) as db:
        assert db.execute("SELECT to_regclass('auth_user')").fetchone()[0] == "auth_user"
