#!/usr/bin/env python3
"""
monitor-api.py — Run Monitor REST API
Read-only Flask API for active recipe runs, step progress, and live measurements.

Endpoints:
  GET /api/runs                    — units with non-completed recipe runs
  GET /api/run/<run_id>            — steps + cycle progress for a run
  GET /api/measurements/<unit_code> — latest measurement per tag for a unit
  GET /api/actions/<unit_code>     — latest actuator action per tag for a unit

own_unit (IAM 2.6): an operator sees only the runs of their units (iam_policy.user_unit)
and the telemetry of those units' zones, the rule of medcea_auth.my_units()/my_zones().
It applies while IAM_ENFORCE or IAM_DB_ROLES is true; otherwise it is logged as
"own_unit: would limit ..." (once an hour per person and route).
"""

import os, sys, time, logging, importlib.util
from datetime import datetime, timezone
import psycopg2, psycopg2.extras
from flask import Flask, jsonify, request, g

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── Access policy check (IAM plan 1.2) ──────────────────────────────────────
# medcea_iam.py and the route table come from ConfigMap medcea-iam-lib at /iam/.
# Loaded from the mount and reloaded when it changes, so a ConfigMap that appears
# later heals and a new library needs no restart. While IAM_ENFORCE is false the
# check only logs "would refuse ..." (stderr); nothing is refused.
_IAM = {'mtime': None, 'mod': None, 'warned': False}


def _medcea_iam():
    path = '/iam/medcea_iam.py'
    try:
        mtime = os.stat(path).st_mtime
        if mtime != _IAM['mtime']:
            spec = importlib.util.spec_from_file_location('medcea_iam', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _IAM.update(mtime=mtime, mod=mod)
    except Exception as e:  # noqa: BLE001 — a missing mount must not stop the service
        if not _IAM['warned']:
            print('medcea_iam: not loaded (%s); requests are not checked' % e, file=sys.stderr, flush=True)
            _IAM['warned'] = True
    return _IAM['mod']


@app.before_request
def _access_check():
    iam = _medcea_iam()
    if iam:
        return iam.flask_check('monitor')
    # No library: fail closed under enforcement (IAM_ENFORCE is also in the pod's
    # environment for this case), report-only otherwise.
    if os.environ.get('IAM_ENFORCE') == 'true' and request.path != '/healthz':
        return jsonify(error='access policy not loaded'), 503
    return None

DB = {
    'host':     os.getenv('PG_HOST',     'rdbms-postgresql'),
    'dbname':   os.getenv('PG_DATABASE', 'medcea_db'),
    'user':     os.getenv('PG_USER',     'postgres'),
    'password': os.getenv('PG_PASSWORD', ''),
}


def get_db():
    return psycopg2.connect(**DB)


def _serial(val):
    if isinstance(val, datetime):
        return val.isoformat()
    return val


def rows_to_dicts(cur):
    cols = [d[0] for d in cur.description]
    return [
        {c: _serial(v) for c, v in zip(cols, row)}
        for row in cur.fetchall()
    ]


# ── own_unit (IAM 2.6) ──────────────────────────────────────────────────────
# The service logs in as svc_monitor, whose RLS policies are permissive, so an
# operator's reads are limited here. The rule is medcea_auth.my_units()/my_zones()
# (medcea_db_migrations.sql): the person's units in iam_policy.user_unit, and a
# reading by its zone's *current* unit (a zone moved to another unit takes its
# history along: the deferred zone-move gap). Written as a subquery with the sub
# as a parameter, because svc_monitor may not execute those functions.
_NIL_SUB = '00000000-0000-0000-0000-000000000000'
_MY_UNITS = "(SELECT uu.unit_id FROM iam_policy.user_unit uu WHERE uu.person_sub = %s::uuid)"
_MY_ZONES = ("(SELECT cz.zone_id FROM medcea.cea_zone cz JOIN iam_policy.user_unit uu ON uu.unit_id = cz.unit_id"
             " WHERE uu.person_sub = %s::uuid)")
_REPORTED = {}  # (username, route) -> time of the last "would limit" line


def _db_roles(cur):
    cur.execute("SELECT coalesce(current_setting('medcea.iam_db_roles', true), '') = 'true' AS v")
    return bool(cur.fetchone()['v'])


def _unit_scope(cur):
    """None (not limited) or the uuid whose units bound this read. Applied while
    IAM_ENFORCE or IAM_DB_ROLES is true; otherwise only logged."""
    iam = _medcea_iam()
    d = getattr(g, 'medcea_iam', None)
    if iam is None or d is None:
        return None
    if hasattr(iam, 'own_unit_sub'):
        sub = iam.own_unit_sub(d)
    else:   # a library from before own_unit_sub: fail closed
        sub = _NIL_SUB if getattr(d, 'allow', False) and 'own_unit' in (getattr(d, 'constraints', None) or []) else None
    if sub is None:
        return None
    if iam.enforcing() or _db_roles(cur):
        return sub
    user = (getattr(d, 'who', None) or {}).get('username') or '-'
    key, now = (user, getattr(d, 'route', None) or request.path), time.time()
    if now - _REPORTED.get(key, 0) > 3600:
        _REPORTED[key] = now
        log.info('own_unit: would limit %s %s to the units of %s (IAM_ENFORCE and IAM_DB_ROLES are false)',
                 request.method, request.path, user)
    return None


# ---------------------------------------------------------------------------
# GET /api/runs
# ---------------------------------------------------------------------------
@app.route('/api/runs')
def get_runs():
    try:
        con = get_db()
        cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        sub = _unit_scope(cur)
        sql = """
            SELECT
              u.unit_id, u.unit_code, u.unit_type,
              rr.recipe_run_id, rr.recipe_run_status, rr.recipe_run_start,
              rc.recipe_name
            FROM medcea.recipe_run rr
            JOIN medcea.cea_unit u ON u.unit_id = rr.unit_id
            JOIN medcea.recipe rc ON rc.recipe_id = rr.recipe_id
            WHERE rr.recipe_run_status <> 'C'
            """ + ("AND rr.unit_id IN " + _MY_UNITS + "\n            " if sub else "") + """ORDER BY u.unit_code
        """
        if sub:
            cur.execute(sql, (sub,))
        else:
            cur.execute(sql)
        rows = cur.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        con.close()
        return jsonify(result)
    except Exception as e:
        log.exception('get_runs failed')
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# GET /api/run/<run_id>
# ---------------------------------------------------------------------------
@app.route('/api/run/<int:run_id>')
def get_run(run_id):
    try:
        con = get_db()
        cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        sub = _unit_scope(cur)   # another unit's run is [] like a missing one
        cur.execute("""
            SELECT
              rl.recipe_item_seq_id,
              rl.recipe_item_seq_name,
              rl.cycle_number                        AS total_cycles,
              rl.air_temperature_lower_limit,
              rl.air_temperature_upper_limit,
              rl.light_type, rl.light_on_minutes, rl.light_off_minutes,
              rl.co2_lower_limit, rl.co2_upper_limit,
              rl.hr_lower_limit, rl.hr_upper_limit,
              rl.substrate_temperature_lower_limit,
              rl.substrate_temperature_upper_limit,
              rl.notes,
              COALESCE(
                MAX(rlcr.recipe_item_seq_cycle_num)
                  FILTER (WHERE rlcr.recipe_line_cycle_run_status <> 'C'),
                0
              ) AS current_cycle,
              COALESCE(
                MAX(rlcr.recipe_item_seq_cycle_num)
                  FILTER (WHERE rlcr.recipe_line_cycle_run_status = 'C'),
                0
              ) AS completed_cycles,
              MAX(rlcr.recipe_line_cycle_run_status)
                FILTER (WHERE rlcr.recipe_item_seq_cycle_num = (
                  SELECT MAX(r2.recipe_item_seq_cycle_num)
                  FROM medcea.recipe_line_cycle_run r2
                  WHERE r2.recipe_run_id = rlcr.recipe_run_id
                    AND r2.recipe_item_seq_id = rl.recipe_item_seq_id
                )) AS step_status
            FROM medcea.recipe_line rl
            JOIN medcea.recipe_run rr ON rr.recipe_id = rl.recipe_id
            LEFT JOIN medcea.recipe_line_cycle_run rlcr
              ON rlcr.recipe_id = rl.recipe_id
             AND rlcr.recipe_item_seq_id = rl.recipe_item_seq_id
             AND rlcr.recipe_run_id = rr.recipe_run_id
            WHERE rr.recipe_run_id = %s
            """ + ("AND rr.unit_id IN " + _MY_UNITS + "\n            " if sub else "") + """GROUP BY
              rl.recipe_item_seq_id, rl.recipe_item_seq_name, rl.cycle_number,
              rl.air_temperature_lower_limit, rl.air_temperature_upper_limit,
              rl.light_type, rl.light_on_minutes, rl.light_off_minutes,
              rl.co2_lower_limit, rl.co2_upper_limit,
              rl.hr_lower_limit, rl.hr_upper_limit,
              rl.substrate_temperature_lower_limit, rl.substrate_temperature_upper_limit,
              rl.notes, rlcr.recipe_run_id
            ORDER BY rl.recipe_item_seq_id
        """, (run_id, sub) if sub else (run_id,))
        rows = cur.fetchall()
        result = [dict(r) for r in rows]
        con.close()
        return jsonify(result)
    except Exception as e:
        log.exception('get_run failed')
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# GET /api/measurements/<unit_code>
# ---------------------------------------------------------------------------
@app.route('/api/measurements/<unit_code>')
def get_measurements(unit_code):
    try:
        con = get_db()
        cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        sub = _unit_scope(cur)
        if sub is None:
            cur.execute("""
            SELECT DISTINCT ON (tag) tag, value, unit_of_measurement, measure_timestamp
            FROM medcea.v_ap_measurements
            WHERE unit_code = %s
            ORDER BY tag, measure_timestamp DESC
        """, (unit_code,))
        else:
            # v_ap_measurements' expressions (it has no zone_id) plus the RLS rule
            # zone_id = ANY(my_zones()): a reading without a zone (an unregistered
            # board) is never shown to an operator
            cur.execute("""
            SELECT DISTINCT ON (tag) tag, value, unit_of_measurement, measure_timestamp
            FROM (SELECT m.msg ->> 'tag' AS tag, (m.msg ->> 'value')::numeric AS value,
                         m.msg ->> 'UoM' AS unit_of_measurement, m.measure_timestamp
                    FROM medcea.measurement m
                   WHERE m.msg_type::text = 'AP' AND m.msg ->> 'unit_code' = %s
                     AND m.zone_id IN """ + _MY_ZONES + """) v
            ORDER BY tag, measure_timestamp DESC
        """, (unit_code, sub))
        rows = cur.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            result.append(d)
        con.close()
        return jsonify(result)
    except Exception as e:
        log.exception('get_measurements failed')
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# GET /api/actions/<unit_code>
# ---------------------------------------------------------------------------
@app.route('/api/actions/<unit_code>')
def get_actions(unit_code):
    try:
        con = get_db()
        cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        sub = _unit_scope(cur)
        if sub is None:
            cur.execute("""
            SELECT DISTINCT ON (tag) tag, command, msg, measure_timestamp
            FROM medcea.v_ct_measurements
            WHERE unit_code = %s
            ORDER BY tag, measure_timestamp DESC
        """, (unit_code,))
        else:   # v_ct_measurements' expressions plus zone_id = ANY(my_zones())
            cur.execute("""
            SELECT DISTINCT ON (tag) tag, command, msg, measure_timestamp
            FROM (SELECT m.msg ->> 'tag' AS tag, m.msg ->> 'command' AS command, m.msg,
                         m.measure_timestamp
                    FROM medcea.measurement m
                   WHERE m.msg_type::text = 'CT' AND m.msg ->> 'unit_code' = %s
                     AND m.zone_id IN """ + _MY_ZONES + """) v
            ORDER BY tag, measure_timestamp DESC
        """, (unit_code, sub))
        rows = cur.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            for k, v in d.items():
                if isinstance(v, datetime):
                    d[k] = v.isoformat()
            # msg is already a dict (psycopg2 parses jsonb); ensure it's JSON-safe
            result.append(d)
        con.close()
        return jsonify(result)
    except Exception as e:
        log.exception('get_actions failed')
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082, debug=False)
