#!/usr/bin/env python3
"""
monitor-api.py — Run Monitor REST API
Read-only Flask API for active recipe runs, step progress, and live measurements.

Endpoints:
  GET /api/runs                    — units with non-completed recipe runs
  GET /api/run/<run_id>            — steps + cycle progress for a run
  GET /api/measurements/<unit_code> — latest measurement per tag for a unit
  GET /api/actions/<unit_code>     — latest actuator action per tag for a unit
"""

import os, sys, logging, importlib.util
from datetime import datetime, timezone
import psycopg2, psycopg2.extras
from flask import Flask, jsonify, request

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


# ---------------------------------------------------------------------------
# GET /api/runs
# ---------------------------------------------------------------------------
@app.route('/api/runs')
def get_runs():
    try:
        con = get_db()
        cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT
              u.unit_id, u.unit_code, u.unit_type,
              rr.recipe_run_id, rr.recipe_run_status, rr.recipe_run_start,
              rc.recipe_name
            FROM medcea.recipe_run rr
            JOIN medcea.cea_unit u ON u.unit_id = rr.unit_id
            JOIN medcea.recipe rc ON rc.recipe_id = rr.recipe_id
            WHERE rr.recipe_run_status <> 'C'
            ORDER BY u.unit_code
        """)
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
            GROUP BY
              rl.recipe_item_seq_id, rl.recipe_item_seq_name, rl.cycle_number,
              rl.air_temperature_lower_limit, rl.air_temperature_upper_limit,
              rl.light_type, rl.light_on_minutes, rl.light_off_minutes,
              rl.co2_lower_limit, rl.co2_upper_limit,
              rl.hr_lower_limit, rl.hr_upper_limit,
              rl.substrate_temperature_lower_limit, rl.substrate_temperature_upper_limit,
              rl.notes, rlcr.recipe_run_id
            ORDER BY rl.recipe_item_seq_id
        """, (run_id,))
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
        cur.execute("""
            SELECT DISTINCT ON (tag) tag, value, unit_of_measurement, measure_timestamp
            FROM medcea.v_ap_measurements
            WHERE unit_code = %s
            ORDER BY tag, measure_timestamp DESC
        """, (unit_code,))
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
        cur.execute("""
            SELECT DISTINCT ON (tag) tag, command, msg, measure_timestamp
            FROM medcea.v_ct_measurements
            WHERE unit_code = %s
            ORDER BY tag, measure_timestamp DESC
        """, (unit_code,))
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
