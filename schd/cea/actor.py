"""cea.actor — who the runner is to the database (IAM plan 2.4).

The runner writes regulated records (cycles, the run's end, Q-table states) through
migration 008b's functions, each in one transaction with its actor, because the
actor lasts one transaction:

    with acting(conn, run_id) as cur:
        cur.execute("SELECT medcea.record_cycle(%s, %s::jsonb)", ...)
    # committed here; rolled back if the block raised

acting() sets system:scheduler for the run's creator (set_system_actor 'run', which
falls back to the run's schedule). A run whose creator is no person is refused
(42501); only while IAM_DB_ROLES is false and only as a superuser (postgres, before
IAM plan 2.5) does the runner then act as the internal system:scheduler actor.

enforcing() reads the database setting medcea.iam_db_roles: it picks this client's
code path and grants nothing (the database decides through medcea.platform_setting,
and _set_internal_actor is executable by superusers only).
"""
import contextlib

import psycopg2


class RunStopped(BaseException):
    """The run was stopped (SIGTERM from the scheduler's stop route, which has already
    marked it F): the runner exits without writing anything more. A BaseException,
    like SystemExit, so no `except Exception` on the way swallows it."""


def _one(conn, sql, args=None):
    with conn.cursor() as cur:
        cur.execute(sql, args)
        row = cur.fetchone()
    return row[0] if row else None


def has_008b(conn):
    """True when migration 008b's run functions exist (record_cycle, finish_run)."""
    return bool(_one(conn, "SELECT to_regprocedure('medcea.record_cycle(integer, jsonb)') IS NOT NULL"))


def enforcing(conn):
    return bool(_one(conn, "SELECT coalesce(current_setting('medcea.iam_db_roles', true), '') = 'true'"))


def is_superuser(conn):
    return bool(_one(conn, "SELECT coalesce((SELECT rolsuper FROM pg_catalog.pg_roles "
                           "WHERE rolname = session_user), false)"))


@contextlib.contextmanager
def acting(conn, run_id):
    """One transaction acting as system:scheduler for run `run_id`; yields a cursor,
    commits on success, rolls back on any exception (re-raised)."""
    cur = conn.cursor()
    try:
        cur.execute("SAVEPOINT medcea_actor")
        try:
            cur.execute("SELECT medcea_auth.set_system_actor('system:scheduler', 'run', %s)", (run_id,))
            cur.execute("RELEASE SAVEPOINT medcea_actor")
        except psycopg2.Error as e:
            cur.execute("ROLLBACK TO SAVEPOINT medcea_actor")
            if e.pgcode != '42501' or enforcing(conn) or not is_superuser(conn):
                raise
            # IAM_DB_ROLES=false, postgres: a run nobody person-attributed created
            cur.execute("SELECT medcea_auth._set_internal_actor('system:scheduler')")
        yield cur
        conn.commit()
    except BaseException:
        try:
            conn.rollback()
        except psycopg2.Error:
            pass
        raise
    finally:
        cur.close()
