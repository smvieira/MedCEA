"""cea.runs — a run started by the scheduler API (RECIPE_RUN_ID), recorded through
migration 008b's functions (IAM plan 2.4).

    run_context(conn, run_id)   the run with its unit, recipe and parameter set
    run_status(conn, run_id)    its status now ('S', 'R', 'C', 'F' or None)
    record_cycle(conn, run_id, recipe_id, seq_id, cycle_num, status, run_params=None, end=None)
                                medcea.record_cycle: inserts or updates one cycle; a
                                completed cycle is never reopened (22023)
    finish(conn, run_id, status)
                                medcea.finish_run(C|F); False when the run is no
                                longer R (stopped meanwhile), True when ended

Each write is its own transaction acting for the run (cea.actor.acting); every read
ends its transaction, so the runner never sits idle in one during a cycle.
"""
import json

import psycopg2

from .actor import acting


def run_context(conn, run_id):
    """dict of the run, or None. set_algorithm/set_params come from its parameter set
    (params_id; NULL while IAM_DB_ROLES=false)."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT rr.recipe_run_id, rr.recipe_run_status, rr.unit_id, rr.recipe_id, rr.params_id,
                       rr.recipe_run_start, u.unit_code, r.recipe_name,
                       a.algorithm_code AS set_algorithm, s.params AS set_params
                FROM medcea.recipe_run rr
                JOIN medcea.cea_unit u ON u.unit_id = rr.unit_id
                JOIN medcea.recipe   r ON r.recipe_id = rr.recipe_id
                LEFT JOIN medcea.unit_algorithm_params s ON s.params_id = rr.params_id
                LEFT JOIN medcea.control_algorithm     a ON a.algorithm_id = s.algorithm_id
                WHERE rr.recipe_run_id = %s
            """, (run_id,))
            row = cur.fetchone()
            cols = [c[0] for c in cur.description]
        return dict(zip(cols, row)) if row else None
    finally:
        conn.rollback()


def run_status(conn, run_id):
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT recipe_run_status FROM medcea.recipe_run WHERE recipe_run_id = %s", (run_id,))
            row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.rollback()


def record_cycle(conn, run_id, recipe_id, seq_id, cycle_num, status, run_params=None, end=None):
    """The cycle's id. run_params is stored as JSON: a list (or its JSON text, which
    is parsed first — a string inside the jsonb would be stored as a JSON string)."""
    cycle = {"recipe_id": int(recipe_id), "recipe_item_seq_id": int(seq_id),
             "recipe_item_seq_cycle_num": int(cycle_num), "status": status}
    if run_params is not None:
        cycle["run_params"] = json.loads(run_params) if isinstance(run_params, str) else run_params
    if end is not None:
        cycle["end"] = end
    with acting(conn, run_id) as cur:
        cur.execute("SELECT medcea.record_cycle(%s, %s::jsonb)", (run_id, json.dumps(cycle)))
        return cur.fetchone()[0]


def finish(conn, run_id, status):
    try:
        with acting(conn, run_id) as cur:
            cur.execute("SELECT medcea.finish_run(%s, %s)", (run_id, status))
        return True
    except psycopg2.Error as e:
        primary = getattr(getattr(e, "diag", None), "message_primary", "") or ""
        if e.pgcode == "22023" and "not R" in primary:
            return False
        raise
