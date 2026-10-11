#!/usr/bin/env python3
"""
scheduler-api.py — Recipe Schedule Manager REST API
Flask + APScheduler. Runs as a container sidecar alongside the scheduler-ui nginx.

Endpoints:
  GET  /api/units                      — active units with allowed recipe count
  GET  /api/recipes?unit_id=X          — recipes allowed for a unit
  GET  /api/schedules                  — all schedules + APScheduler next_run
  POST /api/schedules                  — create schedule
  PUT  /api/schedules/<id>             — update schedule
  DEL  /api/schedules/<id>             — delete schedule
  POST /api/schedules/<id>/trigger     — run immediately (background thread)
  GET  /api/runs?limit=N               — recent completed recipe_run rows
  GET  /api/runs/active                — runs with status != C
  GET  /api/runs/<id>                  — single run + full log content
  GET  /api/runs/<id>/log?offset=N     — incremental log tail (live polling)
  POST /api/runs/<id>/execute          — start execution of a queued run
  PATCH /api/runs/<id>/status          — reset run to S (retry)
  GET  /api/config/logs                — log management thresholds + stats
  PUT  /api/config/logs                — save log management thresholds
  POST /api/logs/compress?days=N       — gzip .log files older than N days
  POST /api/logs/delete?days=N         — delete .log/.log.gz files older than N days
"""

import os, sys, signal, logging, subprocess, threading, gzip, shutil, json
from datetime import timezone, timedelta
import psycopg2, psycopg2.extras
from flask import Flask, jsonify, request
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Config from env vars (injected by deploy.sh)
# ---------------------------------------------------------------------------
DB = {
    'host':     os.getenv('PG_HOST',     'rdbms-postgresql'),
    'dbname':   os.getenv('PG_DATABASE', 'medcea_db'),
    'user':     os.getenv('PG_USER',     'postgres'),
    'password': os.getenv('PG_PASSWORD', ''),
}
SCHD_DIR  = os.getenv('SCHD_DIR',  '/schd')
LOG_DIR   = os.getenv('LOG_DIR',   '/logs')
MQTT_URL  = os.getenv('MQTT_URL',  'localhost')
MQTT_PORT = os.getenv('MQTT_PORT', '1883')
PROJECT   = os.getenv('PROJECT_NAME', 'medcea')

# In-memory PID registry: run_id -> pid of the active run_recipe.py subprocess
_active_pids = {}
_active_pids_lock = threading.Lock()

# ---------------------------------------------------------------------------
# PID file helpers — persist PIDs across API restarts
# ---------------------------------------------------------------------------
def _pid_file(run_id):
    return os.path.join(SCHD_DIR, f'run_{run_id}.pid')

def _write_pid_file(run_id, pid):
    try:
        with open(_pid_file(run_id), 'w') as f:
            f.write(str(pid))
    except Exception as e:
        log.warning(f'Could not write PID file for run_id={run_id}: {e}')

def _delete_pid_file(run_id):
    try:
        os.unlink(_pid_file(run_id))
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning(f'Could not delete PID file for run_id={run_id}: {e}')

def _pid_alive(pid):
    """Return True if a process with this PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False

# ---------------------------------------------------------------------------
# Write /installer/.env so run_recipe.py's load_dotenv('../installer/.env')
# resolves correctly when CWD is /schd
# ---------------------------------------------------------------------------
def _write_dotenv():
    os.makedirs('/installer', exist_ok=True)
    with open('/installer/.env', 'w') as f:
        f.write(f"DB_HOST={DB['host']}\n")
        f.write(f"DB_NAME={DB['dbname']}\n")
        f.write(f"DB_USER={DB['user']}\n")
        f.write(f"DB_PASS={DB['password']}\n")
        f.write(f"MQTT_URL={MQTT_URL}\n")
        f.write(f"MQTT_PORT={MQTT_PORT}\n")
        f.write(f"PROJECT_NAME={PROJECT}\n")
    log.info('Wrote /installer/.env')

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db():
    return psycopg2.connect(**DB)

def query(sql, params=None, *, fetchall=True):
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        result = cur.fetchall() if fetchall else cur.fetchone()
        conn.commit()
        return [dict(r) for r in result] if fetchall else (dict(result) if result else None)
    finally:
        conn.close()

def execute(sql, params=None, *, returning=False):
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        row = dict(cur.fetchone()) if returning and cur.rowcount else None
        conn.commit()
        return row
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Run recipe as subprocess
# ---------------------------------------------------------------------------
def _log_path(unit_code, recipe_name, run_id=None):
    su = unit_code.replace('/', '_')
    sr = recipe_name.replace(' ', '_').replace('/', '_')
    suffix = f'_{run_id}' if run_id is not None else ''
    return os.path.join(LOG_DIR, f'run_recipe_{su}_{sr}{suffix}.log')

def _find_log_path(unit_code, recipe_name, run_id):
    """Return the log file path: new run_id-based name first, then legacy fallback."""
    path = _log_path(unit_code, recipe_name, run_id)
    if os.path.exists(path):
        return path
    legacy = _log_path(unit_code, recipe_name)
    if os.path.exists(legacy):
        return legacy
    return path  # return new-style path even if missing (for error messages)

def _run_recipe(unit_code, recipe_name, run_id=None, schedule_id=None,
                control_algorithm=None, control_algorithm_params=None):
    log_file = _log_path(unit_code, recipe_name, run_id)
    os.makedirs(LOG_DIR, exist_ok=True)
    algo = (control_algorithm or 'IF_THEN_ELSE').upper()
    log.info(f'Triggering run_recipe.py unit={unit_code} recipe="{recipe_name}" run_id={run_id} algo={algo} log={log_file}')
    env = os.environ.copy()
    env['CONTROL_ALGORITHM']        = algo
    env['CONTROL_ALGORITHM_PARAMS'] = json.dumps(control_algorithm_params or {})
    with open(log_file, 'a') as lf:
        proc = subprocess.Popen(
            [sys.executable, '-u', os.path.join(SCHD_DIR, 'run_recipe.py'), unit_code, recipe_name],
            stdout=lf, stderr=subprocess.STDOUT,
            cwd=SCHD_DIR, env=env,
        )
        if run_id is not None:
            with _active_pids_lock:
                _active_pids[run_id] = {'pid': proc.pid, 'algo': algo}
            _write_pid_file(run_id, proc.pid)
        proc.wait()
    if run_id is not None:
        with _active_pids_lock:
            _active_pids.pop(run_id, None)
        _delete_pid_file(run_id)
    log.info(f'run_recipe.py finished (rc={proc.returncode}) unit={unit_code} run_id={run_id}')
    # Auto-delete run-once schedules after they fire
    if schedule_id is not None:
        try:
            execute("DELETE FROM medcea.schedule WHERE schedule_id=%s", (schedule_id,))
            log.info(f'Run-once schedule {schedule_id} deleted after execution')
        except Exception as e:
            log.error(f'Failed to delete run-once schedule {schedule_id}: {e}')

def trigger_in_thread(unit_code, recipe_name, run_id=None, schedule_id=None,
                      control_algorithm=None, control_algorithm_params=None):
    t = threading.Thread(
        target=_run_recipe,
        args=(unit_code, recipe_name, run_id, schedule_id,
              control_algorithm, control_algorithm_params),
        daemon=True,
    )
    t.start()

# ---------------------------------------------------------------------------
# APScheduler
# ---------------------------------------------------------------------------
scheduler = BackgroundScheduler(timezone='UTC')

def _schedule_trigger_job(schedule_id, unit_id, recipe_id, unit_code, recipe_name,
                           once_schedule_id=None,
                           control_algorithm=None, control_algorithm_params=None):
    """Called by APScheduler. Pre-creates a recipe_run record then fires the subprocess."""
    conflict = query(
        "SELECT recipe_run_id FROM medcea.recipe_run WHERE unit_id=%s AND recipe_run_status IN ('S','R') AND is_active='Y'",
        (unit_id,))
    if conflict:
        log.warning(f'Skipping scheduled trigger for {unit_code}/{recipe_name}: unit has active run {conflict[0]["recipe_run_id"]}')
        return
    row = execute("""
        INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
        VALUES (%s, %s, CURRENT_TIMESTAMP, 'S', 'Y')
        RETURNING recipe_run_id
    """, (recipe_id, unit_id), returning=True)
    if not row:
        log.error(f'Failed to create recipe_run for scheduled trigger {schedule_id}')
        return
    trigger_in_thread(unit_code, recipe_name, run_id=row['recipe_run_id'],
                      schedule_id=once_schedule_id,
                      control_algorithm=control_algorithm,
                      control_algorithm_params=control_algorithm_params)

def _resolve_algorithm(row):
    """Resolve effective algorithm code + params from schedule → permission → default chain."""
    algo_code = row.get('sched_algo_code') or row.get('perm_algo_code') or 'IF_THEN_ELSE'
    defaults  = row.get('sched_defaults') or row.get('perm_defaults') or {}
    params    = {
        **defaults,
        **(row.get('perm_algo_params') or {}),
        **(row.get('sched_algo_params') or {}),
    }
    return algo_code, params


def _reload_schedules():
    rows = query("""
        SELECT s.schedule_id, s.unit_id, s.recipe_id, s.cron_expression, s.enabled,
               s.algorithm_id     AS sched_algo_id,
               s.algorithm_params AS sched_algo_params,
               p.algorithm_id     AS perm_algo_id,
               p.algorithm_params AS perm_algo_params,
               ca_s.algorithm_code AS sched_algo_code, ca_s.default_params AS sched_defaults,
               ca_p.algorithm_code AS perm_algo_code,  ca_p.default_params AS perm_defaults,
               u.unit_code, r.recipe_name
        FROM medcea.schedule s
        JOIN medcea.cea_unit u  ON s.unit_id   = u.unit_id
        JOIN medcea.recipe   r  ON s.recipe_id = r.recipe_id
        LEFT JOIN medcea.recipe_unit_permission p
               ON p.unit_id=s.unit_id AND p.recipe_id=s.recipe_id
        LEFT JOIN medcea.control_algorithm ca_s ON s.algorithm_id = ca_s.algorithm_id
        LEFT JOIN medcea.control_algorithm ca_p ON p.algorithm_id = ca_p.algorithm_id
    """)
    # Remove jobs that are no longer in DB
    db_ids = {f"sched_{r['schedule_id']}" for r in rows}
    for job in scheduler.get_jobs():
        if job.id not in db_ids:
            scheduler.remove_job(job.id)
    # Add/replace
    for r in rows:
        jid = f"sched_{r['schedule_id']}"
        if r['enabled']:
            try:
                expr = r['cron_expression']
                algo_code, algo_params = _resolve_algorithm(r)
                if expr.startswith('once '):
                    dt = datetime.fromisoformat(expr[5:]).replace(tzinfo=timezone.utc)
                    if dt <= datetime.now(timezone.utc):
                        continue
                    trigger = DateTrigger(run_date=dt, timezone='UTC')
                else:
                    trigger = CronTrigger.from_crontab(expr, timezone='UTC')
                scheduler.add_job(
                    _schedule_trigger_job,
                    trigger,
                    id=jid, replace_existing=True,
                    args=[r['schedule_id'], r['unit_id'], r['recipe_id'],
                          r['unit_code'], r['recipe_name'],
                          r['schedule_id'] if expr.startswith('once ') else None,
                          algo_code, algo_params],
                )
            except Exception as e:
                log.error(f'Bad expression for schedule {r["schedule_id"]}: {e}')
        else:
            if scheduler.get_job(jid):
                scheduler.remove_job(jid)

def _next_run(schedule_id):
    job = scheduler.get_job(f"sched_{schedule_id}")
    if job and job.next_run_time:
        return job.next_run_time.astimezone(timezone.utc).isoformat()
    return None

# ---------------------------------------------------------------------------
# Routes — units / recipes
# ---------------------------------------------------------------------------
@app.route('/api/units')
def get_units():
    rows = query("""
        SELECT u.unit_id, u.unit_code,
               COUNT(p.recipe_id) FILTER (WHERE p.allowed) AS recipe_count,
               COALESCE(
                   (SELECT jsonb_object_agg(algorithm, cnt)
                    FROM (SELECT algorithm, COUNT(*) AS cnt
                          FROM medcea.algorithm_state
                          WHERE unit_id = u.unit_id
                          GROUP BY algorithm) t),
                   '{}'::jsonb
               ) AS algorithm_states
        FROM medcea.cea_unit u
        LEFT JOIN medcea.recipe_unit_permission p ON u.unit_id = p.unit_id
        WHERE u.is_active = 'Y'
        GROUP BY u.unit_id, u.unit_code
        ORDER BY u.unit_code
    """)
    return jsonify(rows)


@app.route('/api/units/<int:uid>/algorithm-state', methods=['DELETE'])
def delete_unit_algorithm_state(uid):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM medcea.algorithm_state WHERE unit_id=%s", (uid,))
        purged = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return jsonify({'purged': purged, 'unit_id': uid})


@app.route('/api/units/<int:uid>/algorithm-state/<algorithm>', methods=['GET'])
def get_unit_algorithm_state(uid, algorithm):
    rows = query("""
        SELECT channel, state, updated_at
        FROM medcea.algorithm_state
        WHERE unit_id = %s AND algorithm = %s
        ORDER BY channel
    """, (uid, algorithm.upper()))
    return jsonify(rows)


@app.route('/api/units/<int:uid>/algorithm-state/<algorithm>', methods=['DELETE'])
def delete_unit_algorithm_state_by_algo(uid, algorithm):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM medcea.algorithm_state WHERE unit_id=%s AND algorithm=%s",
                    (uid, algorithm.upper()))
        purged = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return jsonify({'purged': purged, 'unit_id': uid, 'algorithm': algorithm.upper()})

@app.route('/api/algorithms')
def get_algorithms():
    rows = query("""
        SELECT algorithm_id, algorithm_code, algorithm_name, description,
               default_params, is_active
        FROM medcea.control_algorithm
        WHERE is_active = 'Y'
        ORDER BY algorithm_id
    """)
    return jsonify(rows)


@app.route('/api/algorithms/<int:aid>', methods=['PUT'])
def update_algorithm(aid):
    d = request.json
    if 'default_params' in d:
        try:
            # Validate it's a JSON object
            if not isinstance(d['default_params'], dict):
                return jsonify({'error': 'default_params must be a JSON object'}), 400
        except Exception:
            return jsonify({'error': 'invalid default_params'}), 400
    row = execute("""
        UPDATE medcea.control_algorithm
        SET algorithm_name  = COALESCE(%s, algorithm_name),
            description     = COALESCE(%s, description),
            default_params  = COALESCE(%s::jsonb, default_params)
        WHERE algorithm_id = %s
        RETURNING algorithm_id, algorithm_code, algorithm_name, description, default_params, is_active
    """, (d.get('algorithm_name'), d.get('description'),
          json.dumps(d['default_params']) if 'default_params' in d else None,
          aid), returning=True)
    if not row:
        return jsonify({'error': 'not found'}), 404
    return jsonify(row)


@app.route('/api/recipes')
def get_recipes():
    unit_id = request.args.get('unit_id', type=int)
    if unit_id:
        rows = query("""
            SELECT r.recipe_id, r.recipe_name
            FROM medcea.recipe r
            JOIN medcea.recipe_unit_permission p ON r.recipe_id = p.recipe_id
            WHERE p.unit_id = %s AND p.allowed = true AND r.is_active = 'Y'
            ORDER BY r.recipe_name
        """, (unit_id,))
    else:
        rows = query("""
            SELECT recipe_id, recipe_name FROM medcea.recipe
            WHERE is_active = 'Y' ORDER BY recipe_name
        """)
    return jsonify(rows)

# ---------------------------------------------------------------------------
# Routes — schedules
# ---------------------------------------------------------------------------
@app.route('/api/schedules', methods=['GET'])
def list_schedules():
    rows = query("""
        SELECT s.schedule_id, s.unit_id, s.recipe_id,
               s.cron_expression, s.enabled, s.description,
               s.algorithm_id, s.algorithm_params,
               u.unit_code, r.recipe_name,
               ca.algorithm_code AS algorithm_code
        FROM medcea.schedule s
        JOIN medcea.cea_unit  u  ON s.unit_id   = u.unit_id
        JOIN medcea.recipe    r  ON s.recipe_id = r.recipe_id
        LEFT JOIN medcea.control_algorithm ca ON s.algorithm_id = ca.algorithm_id
        ORDER BY s.schedule_id DESC
    """)
    for r in rows:
        r['next_run'] = _next_run(r['schedule_id'])
    return jsonify(rows)

@app.route('/api/schedules', methods=['POST'])
def create_schedule():
    d = request.json
    algo_params = d.get('algorithm_params')
    row = execute("""
        INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, enabled, description,
                                   algorithm_id, algorithm_params)
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
        RETURNING schedule_id, unit_id, recipe_id, cron_expression, enabled, description,
                  algorithm_id, algorithm_params
    """, (d['unit_id'], d['recipe_id'], d['cron_expression'],
          d.get('enabled', True), d.get('description', ''),
          d.get('algorithm_id'), json.dumps(algo_params) if algo_params is not None else None),
         returning=True)
    _reload_schedules()
    row['next_run'] = _next_run(row['schedule_id'])
    return jsonify(row), 201

@app.route('/api/schedules/<int:sid>', methods=['PUT'])
def update_schedule(sid):
    d = request.json
    algo_params = d.get('algorithm_params')
    row = execute("""
        UPDATE medcea.schedule
        SET unit_id=%s, recipe_id=%s, cron_expression=%s, enabled=%s, description=%s,
            algorithm_id=%s, algorithm_params=%s::jsonb,
            timestamp_upd=CURRENT_TIMESTAMP
        WHERE schedule_id=%s
        RETURNING schedule_id, unit_id, recipe_id, cron_expression, enabled, description,
                  algorithm_id, algorithm_params
    """, (d['unit_id'], d['recipe_id'], d['cron_expression'],
          d.get('enabled', True), d.get('description', ''),
          d.get('algorithm_id'), json.dumps(algo_params) if algo_params is not None else None,
          sid), returning=True)
    if not row:
        return jsonify({'error': 'not found'}), 404
    _reload_schedules()
    row['next_run'] = _next_run(sid)
    return jsonify(row)

@app.route('/api/schedules/<int:sid>', methods=['DELETE'])
def delete_schedule(sid):
    execute("DELETE FROM medcea.schedule WHERE schedule_id=%s", (sid,))
    _reload_schedules()
    return jsonify({'deleted': sid})

@app.route('/api/schedules/<int:sid>/trigger', methods=['POST'])
def trigger_schedule(sid):
    row = query("""
        SELECT s.unit_id, s.recipe_id,
               s.algorithm_id     AS sched_algo_id,
               s.algorithm_params AS sched_algo_params,
               p.algorithm_id     AS perm_algo_id,
               p.algorithm_params AS perm_algo_params,
               ca_s.algorithm_code AS sched_algo_code, ca_s.default_params AS sched_defaults,
               ca_p.algorithm_code AS perm_algo_code,  ca_p.default_params AS perm_defaults,
               u.unit_code, r.recipe_name
        FROM medcea.schedule s
        JOIN medcea.cea_unit u  ON s.unit_id   = u.unit_id
        JOIN medcea.recipe   r  ON s.recipe_id = r.recipe_id
        LEFT JOIN medcea.recipe_unit_permission p
               ON p.unit_id=s.unit_id AND p.recipe_id=s.recipe_id
        LEFT JOIN medcea.control_algorithm ca_s ON s.algorithm_id = ca_s.algorithm_id
        LEFT JOIN medcea.control_algorithm ca_p ON p.algorithm_id = ca_p.algorithm_id
        WHERE s.schedule_id = %s
    """, (sid,), fetchall=False)
    if not row:
        return jsonify({'error': 'not found'}), 404
    unit_id, recipe_id = row['unit_id'], row['recipe_id']
    conflict = query(
        "SELECT recipe_run_id FROM medcea.recipe_run WHERE unit_id=%s AND recipe_run_status IN ('S','R') AND is_active='Y'",
        (unit_id,))
    if conflict:
        return jsonify({'error': 'Unit already has an active run', 'run_id': conflict[0]['recipe_run_id']}), 409
    algo_code, algo_params = _resolve_algorithm(row)
    run_row = execute("""
        INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
        VALUES (%s, %s, CURRENT_TIMESTAMP, 'S', 'Y')
        RETURNING recipe_run_id
    """, (recipe_id, unit_id), returning=True)
    run_id = run_row['recipe_run_id']
    trigger_in_thread(row['unit_code'], row['recipe_name'], run_id=run_id,
                      control_algorithm=algo_code, control_algorithm_params=algo_params)
    return jsonify({'triggered': True, 'run_id': run_id, 'algorithm': algo_code,
                    'log': _log_path(row['unit_code'], row['recipe_name'], run_id)})

# ---------------------------------------------------------------------------
# Routes — runs
# ---------------------------------------------------------------------------
def _fmt_runs(rows):
    for r in rows:
        r['recipe_run_start'] = r['recipe_run_start'].isoformat() if r['recipe_run_start'] else None
        r['recipe_run_end']   = r['recipe_run_end'].isoformat()   if r['recipe_run_end']   else None
    return rows

@app.route('/api/runs/active')
def list_active_runs():
    rows = query("""
        SELECT rr.recipe_run_id, rr.recipe_run_status,
               rr.recipe_run_start, rr.recipe_run_end,
               u.unit_id, u.unit_code, r.recipe_id, r.recipe_name
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_status != 'C'
        ORDER BY rr.recipe_run_id DESC
    """)
    _fmt_runs(rows)
    with _active_pids_lock:
        for r in rows:
            entry = _active_pids.get(r['recipe_run_id'])
            r['pid']               = entry['pid']  if entry else None
            r['control_algorithm'] = entry['algo'] if entry else None
    return jsonify(rows)

@app.route('/api/runs')
def list_runs():
    limit = request.args.get('limit', 50, type=int)
    rows = query("""
        SELECT rr.recipe_run_id, rr.recipe_run_status,
               rr.recipe_run_start, rr.recipe_run_end,
               u.unit_code, r.recipe_name
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_status = 'C'
        ORDER BY rr.recipe_run_id DESC
        LIMIT %s
    """, (limit,))
    return jsonify(_fmt_runs(rows))

@app.route('/api/runs', methods=['POST'])
def create_run():
    d = request.json
    unit_id, recipe_id = d['unit_id'], d['recipe_id']
    conflict = query(
        "SELECT recipe_run_id FROM medcea.recipe_run WHERE unit_id=%s AND recipe_run_status IN ('S','R') AND is_active='Y'",
        (unit_id,))
    if conflict:
        return jsonify({'error': 'Unit already has an active run', 'run_id': conflict[0]['recipe_run_id']}), 409
    row = execute("""
        INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
        VALUES (%s, %s, CURRENT_TIMESTAMP, 'S', 'Y')
        RETURNING recipe_run_id
    """, (recipe_id, unit_id), returning=True)
    return jsonify(row), 201

@app.route('/api/runs/<int:run_id>/status', methods=['PATCH'])
def set_run_status(run_id):
    d = request.json
    new_status = d.get('status')
    if new_status != 'S':
        return jsonify({'error': 'Only reset to S is supported'}), 400
    current = query("SELECT recipe_run_status FROM medcea.recipe_run WHERE recipe_run_id=%s", (run_id,), fetchall=False)
    if not current:
        return jsonify({'error': 'not found'}), 404
    if current['recipe_run_status'] == 'R':
        return jsonify({'error': 'Cannot modify a currently running recipe'}), 409
    execute("UPDATE medcea.recipe_run SET recipe_run_status='S', recipe_run_end=NULL, timestamp_upd=CURRENT_TIMESTAMP WHERE recipe_run_id=%s", (run_id,))
    return jsonify({'updated': run_id, 'status': 'S'})

@app.route('/api/runs/<int:run_id>/execute', methods=['POST'])
def execute_run(run_id):
    row = query("""
        SELECT u.unit_code, r.recipe_name, rr.recipe_run_status
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_id = %s
    """, (run_id,), fetchall=False)
    if not row:
        return jsonify({'error': 'not found'}), 404
    if row['recipe_run_status'] != 'S':
        return jsonify({'error': 'Run must be in Started (S) status to execute'}), 409
    # Guard: reject if a live process is already running for this unit
    with _active_pids_lock:
        unit_pids = {
            rid: e for rid, e in _active_pids.items()
            if rid != run_id and _pid_alive(e['pid'])
        }
    # Cross-check unit ownership via DB
    if unit_pids:
        busy = query(
            "SELECT recipe_run_id FROM medcea.recipe_run "
            "WHERE recipe_run_id = ANY(%s) AND unit_id = "
            "(SELECT unit_id FROM medcea.recipe_run WHERE recipe_run_id=%s)",
            (list(unit_pids.keys()), run_id)
        )
        if busy:
            return jsonify({
                'error': f'Unit {row["unit_code"]} already has a running recipe',
                'run_id': busy[0]['recipe_run_id']
            }), 409
    d = request.json or {}
    algo   = (d.get('control_algorithm') or 'IF_THEN_ELSE').upper()
    params = d.get('control_algorithm_params') or {}
    trigger_in_thread(row['unit_code'], row['recipe_name'], run_id=run_id,
                      control_algorithm=algo, control_algorithm_params=params)
    return jsonify({'executing': True, 'unit': row['unit_code'], 'recipe': row['recipe_name'],
                    'algorithm': algo})

@app.route('/api/runs/<int:run_id>/stop', methods=['POST'])
def stop_run(run_id):
    with _active_pids_lock:
        entry = _active_pids.get(run_id)
        pid = entry['pid'] if entry else None
    # Send SIGTERM if we have a tracked PID; otherwise just update DB (e.g. after pod restart)
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            log.info(f'Sent SIGTERM to pid={pid} for run_id={run_id}')
        except ProcessLookupError:
            log.warning(f'Process pid={pid} for run_id={run_id} already gone')
        except PermissionError as e:
            return jsonify({'error': f'Cannot kill process: {e}'}), 500
        with _active_pids_lock:
            _active_pids.pop(run_id, None)
    else:
        log.info(f'No tracked pid for run_id={run_id} — marking stopped in DB only')
    # Update DB
    conn = get_db()
    try:
        sys.path.insert(0, SCHD_DIR)
        from cea.update_recipe_run import update_recipe_run
        update_recipe_run(run_id, 'F', conn)  # commits internally
        execute(
            "UPDATE medcea.recipe_run SET recipe_run_end = CURRENT_TIMESTAMP WHERE recipe_run_id = %s",
            (run_id,)
        )
        log.info(f'run_id={run_id} marked F (stopped) in DB')
    except Exception as e:
        log.error(f'DB update after stop failed for run_id={run_id}: {e}')
        return jsonify({'error': f'DB update failed: {e}'}), 500
    finally:
        conn.close()
    return jsonify({'stopped': True, 'run_id': run_id, 'pid': pid})

@app.route('/api/runs/<int:run_id>')
def get_run(run_id):
    row = query("""
        SELECT rr.recipe_run_id, rr.recipe_run_status,
               rr.recipe_run_start, rr.recipe_run_end,
               u.unit_code, r.recipe_name
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_id = %s
    """, (run_id,), fetchall=False)
    if not row:
        return jsonify({'error': 'not found'}), 404
    row['recipe_run_start'] = row['recipe_run_start'].isoformat() if row['recipe_run_start'] else None
    row['recipe_run_end']   = row['recipe_run_end'].isoformat()   if row['recipe_run_end']   else None
    log_path = _find_log_path(row['unit_code'], row['recipe_name'], run_id)
    if os.path.exists(log_path):
        with open(log_path) as f:
            row['log'] = f.read()
    else:
        row['log'] = f'(no log file at {log_path})'
    return jsonify(row)

@app.route('/api/runs/<int:run_id>/cycles')
def get_run_cycles(run_id):
    rows = query("""
        SELECT rlcr.recipe_item_seq_cycle_num,
               rl.recipe_item_seq_name,
               rlcr.recipe_line_seq_cycle_run_start,
               rlcr.recipe_line_seq_cycle_run_end,
               rlcr.recipe_line_cycle_run_status,
               rlcr.run_params
        FROM medcea.recipe_line_cycle_run rlcr
        JOIN medcea.recipe_line rl
          ON rlcr.recipe_id = rl.recipe_id
         AND rlcr.recipe_item_seq_id = rl.recipe_item_seq_id
        WHERE rlcr.recipe_run_id = %s
        ORDER BY rlcr.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num
    """, (run_id,))
    for r in rows:
        r['recipe_line_seq_cycle_run_start'] = r['recipe_line_seq_cycle_run_start'].isoformat() if r['recipe_line_seq_cycle_run_start'] else None
        r['recipe_line_seq_cycle_run_end']   = r['recipe_line_seq_cycle_run_end'].isoformat()   if r['recipe_line_seq_cycle_run_end']   else None
    return jsonify(rows)

@app.route('/api/runs/<int:run_id>/log')
def get_run_log(run_id):
    """Incremental log tail for live polling.

    Query params:
      offset (int) — byte offset to read from (default 0); used for incremental polling
      tail   (int) — if > 0, return only the last N lines (ignores offset); used for initial open
    """
    offset = request.args.get('offset', 0, type=int)
    tail   = request.args.get('tail',   0, type=int)
    row = query("""
        SELECT rr.recipe_run_status, u.unit_code, r.recipe_name
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_id = %s
    """, (run_id,), fetchall=False)
    if not row:
        return jsonify({'error': 'not found'}), 404
    log_path = _find_log_path(row['unit_code'], row['recipe_name'], run_id)
    content = ''
    next_offset = offset
    if os.path.exists(log_path):
        if tail > 0:
            with open(log_path, 'rb') as f:
                raw = f.read()
            next_offset = len(raw)
            text  = raw.decode('utf-8', errors='replace')
            lines = text.splitlines(keepends=True)
            content = ''.join(lines[-tail:]) if len(lines) > tail else text
        else:
            with open(log_path, 'rb') as f:
                f.seek(offset)
                chunk = f.read()
                next_offset = offset + len(chunk)
                content = chunk.decode('utf-8', errors='replace')
    return jsonify({
        'content':     content,
        'next_offset': next_offset,
        'status':      row['recipe_run_status'],
        'unit_code':   row['unit_code'],
        'recipe_name': row['recipe_name'],
    })

# ---------------------------------------------------------------------------
# Routes — log management config
# ---------------------------------------------------------------------------
def _get_config(key, default):
    row = query("SELECT value FROM medcea.scheduler_config WHERE key=%s", (key,), fetchall=False)
    return row['value'] if row else default

def _log_stats():
    files = []
    if os.path.isdir(LOG_DIR):
        for fname in os.listdir(LOG_DIR):
            if fname.endswith('.log') or fname.endswith('.log.gz'):
                fpath = os.path.join(LOG_DIR, fname)
                try:
                    st = os.stat(fpath)
                    files.append({'size': st.st_size, 'mtime': st.st_mtime})
                except OSError:
                    pass
    total_size = sum(f['size'] for f in files)
    oldest = min((f['mtime'] for f in files), default=None)
    return {
        'log_count': len(files),
        'log_size_bytes': total_size,
        'oldest_mtime': datetime.fromtimestamp(oldest, tz=timezone.utc).isoformat() if oldest else None,
    }

@app.route('/api/config/logs', methods=['GET'])
def get_log_config():
    result = {
        'compress_days': int(_get_config('log_compress_days', '7')),
        'delete_days':   int(_get_config('log_delete_days',   '30')),
    }
    result.update(_log_stats())
    return jsonify(result)

@app.route('/api/config/logs', methods=['PUT'])
def put_log_config():
    d = request.json
    for key, val in [('log_compress_days', d.get('compress_days')),
                     ('log_delete_days',   d.get('delete_days'))]:
        if val is not None:
            execute("""
                INSERT INTO medcea.scheduler_config (key, value)
                VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """, (key, str(int(val))))
    return jsonify({'saved': True})

@app.route('/api/logs/compress', methods=['POST'])
def compress_logs():
    days = request.args.get('days', type=int) or int(_get_config('log_compress_days', '7'))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    compressed = 0
    skipped = 0
    if os.path.isdir(LOG_DIR):
        for fname in os.listdir(LOG_DIR):
            if not fname.endswith('.log'):
                continue
            fpath = os.path.join(LOG_DIR, fname)
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc)
                if mtime >= cutoff:
                    skipped += 1
                    continue
                gz_path = fpath + '.gz'
                with open(fpath, 'rb') as f_in, gzip.open(gz_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(fpath)
                compressed += 1
                log.info(f'Compressed {fname}')
            except Exception as e:
                log.error(f'Failed to compress {fname}: {e}')
                skipped += 1
    return jsonify({'compressed': compressed, 'skipped': skipped})

@app.route('/api/logs/delete', methods=['POST'])
def delete_logs():
    days = request.args.get('days', type=int) or int(_get_config('log_delete_days', '30'))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = 0
    skipped = 0
    if os.path.isdir(LOG_DIR):
        for fname in os.listdir(LOG_DIR):
            if not (fname.endswith('.log') or fname.endswith('.log.gz')):
                continue
            fpath = os.path.join(LOG_DIR, fname)
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc)
                if mtime >= cutoff:
                    skipped += 1
                    continue
                os.remove(fpath)
                deleted += 1
                log.info(f'Deleted {fname}')
            except Exception as e:
                log.error(f'Failed to delete {fname}: {e}')
                skipped += 1
    return jsonify({'deleted': deleted, 'skipped': skipped})

# ---------------------------------------------------------------------------
# Startup recovery — re-register or reap orphaned run_recipe.py processes
# ---------------------------------------------------------------------------
def _startup_recovery():
    import glob
    pid_files = glob.glob(os.path.join(SCHD_DIR, 'run_*.pid'))
    if not pid_files:
        return
    log.info(f'Startup recovery: found {len(pid_files)} PID file(s)')
    for pf in pid_files:
        try:
            run_id = int(os.path.basename(pf).replace('run_', '').replace('.pid', ''))
            pid    = int(open(pf).read().strip())
        except Exception:
            continue
        if _pid_alive(pid):
            log.info(f'Startup recovery: run_id={run_id} pid={pid} alive — re-registering')
            with _active_pids_lock:
                _active_pids[run_id] = {'pid': pid, 'algo': 'UNKNOWN'}
        else:
            log.info(f'Startup recovery: run_id={run_id} pid={pid} dead — marking Failed')
            _delete_pid_file(run_id)
            try:
                execute(
                    "UPDATE medcea.recipe_run SET recipe_run_status='F', "
                    "recipe_run_end=CURRENT_TIMESTAMP, timestamp_upd=CURRENT_TIMESTAMP "
                    "WHERE recipe_run_id=%s AND recipe_run_status IN ('R','S')",
                    (run_id,)
                )
            except Exception as e:
                log.error(f'Startup recovery: failed to mark run_id={run_id} as Failed: {e}')

# ---------------------------------------------------------------------------
# Schema migration — runs at startup
# ---------------------------------------------------------------------------
def _ensure_schema():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS medcea.schedule (
                schedule_id      serial       PRIMARY KEY,
                unit_id          integer      NOT NULL REFERENCES medcea.cea_unit(unit_id)  ON DELETE CASCADE,
                recipe_id        integer      NOT NULL REFERENCES medcea.recipe(recipe_id)  ON DELETE CASCADE,
                cron_expression  varchar(100) NOT NULL,
                enabled          boolean      NOT NULL DEFAULT true,
                description      text,
                timestamp_cre    timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
                timestamp_upd    timestamptz
            )
        """)
        # Add algorithm selection columns to medcea.schedule (idempotent)
        cur.execute("""
            ALTER TABLE medcea.schedule
                ADD COLUMN IF NOT EXISTS algorithm_id     INTEGER REFERENCES medcea.control_algorithm(algorithm_id),
                ADD COLUMN IF NOT EXISTS algorithm_params JSONB DEFAULT NULL
        """)
        cur.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON medcea.schedule TO authenticator")
        cur.execute("GRANT USAGE, SELECT ON SEQUENCE medcea.schedule_schedule_id_seq TO authenticator")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS medcea.scheduler_config (
                key   varchar(100) PRIMARY KEY,
                value text NOT NULL
            )
        """)
        cur.execute("""
            INSERT INTO medcea.scheduler_config (key, value)
            VALUES ('log_compress_days', '7'), ('log_delete_days', '30')
            ON CONFLICT (key) DO NOTHING
        """)
        conn.commit()
        log.info('Schema ready (medcea.schedule, medcea.scheduler_config)')
    except Exception as e:
        log.error(f'Schema migration failed: {e}')
        conn.rollback()
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    _write_dotenv()
    sys.path.insert(0, SCHD_DIR)
    _ensure_schema()
    _startup_recovery()
    scheduler.start()
    _reload_schedules()
    log.info('Scheduler API ready on :8082')
    app.run(host='0.0.0.0', port=8082, threaded=True)
