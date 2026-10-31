#!/usr/bin/env python3
"""
scheduler-api.py — Recipe Schedule Manager REST API
Flask + APScheduler. Runs as a container sidecar alongside the scheduler-ui nginx.

Endpoints:
  GET  /api/units                      — active units with allowed recipe count
  GET  /api/recipes?unit_id=X          — recipes allowed for a unit (+ status, params_id)
  GET  /api/algorithms                 — control algorithms (+ status)
  PUT  /api/algorithms/<id>            — edit an algorithm (an approved one becomes a draft)
  GET  /api/param-sets?unit_id=&algorithm_id=
                                       — parameter sets a schedule or run may point to
  GET  /api/schedules                  — live (not retired) schedules + APScheduler next_run
  POST /api/schedules                  — create schedule
  PUT  /api/schedules/<id>             — update schedule (a retired one: 409)
  DEL  /api/schedules/<id>             — RETIRE schedule (medcea.retire_schedule; kept, never deleted)
  POST /api/schedules/<id>/trigger     — run immediately (background thread)
  GET  /api/runs?limit=N               — recent completed recipe_run rows
  GET  /api/runs/active                — runs with status != C
  GET  /api/runs/<id>                  — single run + full log content (log null and
                                         log_withheld for a role without R on run_logs)
  GET  /api/runs/<id>/log?offset=N     — incremental log tail (live polling)
  POST /api/runs/<id>/execute          — start execution of a queued run (medcea.start_run)
  POST /api/runs/<id>/stop             — stop a run (medcea.set_run_status F, then SIGTERM)
  PATCH /api/runs/<id>/status          — reset run to S (retry)
  GET  /api/config/logs                — log management thresholds + stats
  PUT  /api/config/logs                — save thresholds (IAM_DB_ROLES=true: a proposal for qa, 202)
Run logs are compressed by the scheduler's own job sys_log_retention (daily 03:15 UTC,
log_retention.py; only run_recipe_*.log of finished runs) and never deleted; no person
compresses or deletes a log (IAM 2.6). Q-tables are retired through PostgREST
/rpc/retire_algorithm_state by qa (Config UI); the scheduler never deletes or retires one.

Who is recorded (IAM plan 2.4). Every regulated write runs in one transaction with
its actor (the actor lasts one transaction):
  person    the person whose token medcea_iam verified (g.medcea_iam.who), through
            medcea_auth.set_actor(sub, person_id or sub, username, own role);
  system    a schedule firing, a runner that died, the run-once retire: through
            medcea_auth.set_system_actor('system:scheduler', 'schedule'|'run', id),
            i.e. the schedule's or run's creator;
  neither   only while IAM_DB_ROLES=false and as a superuser (postgres; on svc_scheduler,
            IAM_DB_SERVICE_ROLES=true, a creator that is no person is refused as under true):
            plain DML gets no actor (stamp_actor writes the honest db:postgres); a
            function that needs an actor gets system:scheduler-unverified (a request
            without a verified person) or system:scheduler (a background job). Each
            such fallback is logged with method, path and reason. Under true a request
            without a person is refused (401) and a system actor without a person
            creator is refused.
own_unit (IAM 2.6): for an operator, the run reads (GET /api/runs, /runs/active,
/runs/<id>, /runs/<id>/cycles, /runs/<id>/log) are limited to their units in
iam_policy.user_unit, the rule of my_units(); another unit's run is 404 (cycles: [])
like a missing one. Applied while IAM_ENFORCE or IAM_DB_ROLES is true, otherwise
logged as "own_unit: would limit". GET /api/runs/<id> leaves the log out for a role
without R on run_logs (maintenance, qc, qp) while IAM_ENFORCE is true.
IAM_DB_ROLES is read from the database setting medcea.iam_db_roles; it only picks the
code path, the database stays authoritative (medcea.platform_setting, the triggers).
While false, runs carry no params_id and the algorithm is chosen exactly as before
(the execute body, else IF_THEN_ELSE; a schedule's inline settings); while true a run
uses its approved parameter set (params_id) and inline parameters are refused.
Database WARNINGs (e.g. "IAM_DB_ROLES=false, would refuse: …", a demoted approval) are
returned in the response as `warnings` — advisory, not errors.
"""

import os, sys, re, signal, logging, subprocess, threading, gzip, json, time, importlib.util, contextlib
import psycopg2, psycopg2.extras
from flask import Flask, jsonify, request, g, has_request_context
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from datetime import datetime, timezone

# next to this file: /scripts in the pod (same ConfigMap), the checkout for iam_runner_flow
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import log_retention

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
        return iam.flask_check('scheduler')
    # No library: fail closed under enforcement (IAM_ENFORCE is also in the pod's
    # environment for this case), report-only otherwise.
    if os.environ.get('IAM_ENFORCE') == 'true' and request.path != '/healthz':
        return jsonify(error='access policy not loaded'), 503
    return None

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
MQTT_USER = os.getenv('MQTT_USER', '')      # the broker's "scheduler" service account
MQTT_PASS = os.getenv('MQTT_PASS', '')
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
        f.write(f"MQTT_USER={MQTT_USER}\n")
        f.write(f"MQTT_PASS={MQTT_PASS}\n")
        f.write(f"PROJECT_NAME={PROJECT}\n")
    log.info('Wrote /installer/.env')

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db():
    # rdbms sets client_min_messages=error for every session: ask for the WARNINGs,
    # which become the answers' advisory `warnings` (tx())
    return psycopg2.connect(options='-c client_min_messages=warning', **DB)

def query(sql, params=None, *, fetchall=True):
    """A read in its own connection (no actor: reads are not stamped)."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        result = cur.fetchall() if fetchall else cur.fetchone()
        conn.commit()
        return [dict(r) for r in result] if fetchall else (dict(result) if result else None)
    finally:
        conn.close()


def _note(msg):
    """An advisory line for the response's `warnings` (logged outside a request)."""
    if has_request_context():
        if not hasattr(g, 'db_warnings'):
            g.db_warnings = []
        if msg not in g.db_warnings:
            g.db_warnings.append(msg)
    else:
        log.warning('advisory: %s', msg)


@contextlib.contextmanager
def tx():
    """One connection, one transaction: commit on success, rollback on any error.
    The database's WARNINGs of a committed transaction become `warnings`."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        yield cur
        conn.commit()
        for n in conn.notices:
            if n.startswith('WARNING:'):
                _note(n.split(':', 1)[1].strip())
    except BaseException:
        try:
            conn.rollback()
        except psycopg2.Error:
            pass
        raise
    finally:
        conn.close()


@app.after_request
def _attach_warnings(resp):
    w = getattr(g, 'db_warnings', None)
    if w and resp.is_json:
        body = resp.get_json(silent=True)
        if isinstance(body, dict) and 'warnings' not in body:
            body['warnings'] = w
            resp.set_data(json.dumps(body))
    return resp


class Refused(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


@app.errorhandler(Refused)
def _refused(e):
    return jsonify(error=e.message), e.status


@app.errorhandler(psycopg2.Error)
def _db_error(e):
    """The database's refusals keep their primary message (42501: 403, or 409 for an
    approval state; 22023 and 23505: 409); anything else is 'database error', with the
    SQLSTATE logged (never the statement's parameters or the DSN)."""
    code = getattr(e, 'pgcode', None)
    diag = getattr(e, 'diag', None)
    primary = getattr(diag, 'message_primary', None) if diag else None
    if code == '42501':
        status = 409 if primary and ('draft_only' in primary or 'approved' in primary) else 403
    elif code in ('22023', '23505'):
        status = 409
    else:
        log.error('database error on %s %s: %s %s', request.method, request.path, code or '-', type(e).__name__)
        return jsonify(error='database error'), 500
    return jsonify(error=primary or 'refused by the database'), status


def _body():
    return request.get_json(silent=True) or {}


# ── IAM_DB_ROLES and the actor ──────────────────────────────────────────────
# coalesce(current_setting(...)) only picks this client's code path; it grants
# nothing (a session could SET it). The database decides through
# medcea.platform_setting, and _set_internal_actor is executable by superusers only.
def _enforcing(cur):
    cur.execute("SELECT coalesce(current_setting('medcea.iam_db_roles', true), '') = 'true' AS v")
    return bool(cur.fetchone()['v'])


def _superuser(cur):
    cur.execute("SELECT coalesce((SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = session_user), false) AS v")
    return bool(cur.fetchone()['v'])


def _functions_only(cur):
    """True when a write must take the IAM_DB_ROLES=true path even while the database
    is false: on its own role (svc_scheduler, IAM 2.5) the scheduler holds no UPDATE on
    recipe_run and only SELECT on scheduler_config, so the direct DML of the false
    path would be "permission denied"."""
    return _enforcing(cur) or not _superuser(cur)


_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)


def _decision():
    return getattr(g, 'medcea_iam', None) if has_request_context() else None


def _person():
    """(sub, person, name, role) of the verified person behind this request, or None.
    Only g.medcea_iam.who counts (set after the token's signature, issuer, audience
    and azp were verified); never an X-Forwarded-* header."""
    d = _decision()
    who = getattr(d, 'who', None) or {}
    sub = who.get('sub')
    if not sub or not _UUID.match(str(sub)):
        return None
    iam = _medcea_iam()
    if iam is not None and hasattr(iam, 'actor_role'):
        role = iam.actor_role(d)
    else:                               # a library from before actor_role
        roles = who.get('roles') or []
        role = roles[0] if len(roles) == 1 else None
    if not role:
        return None
    return (sub, who.get('person_id') or sub, who.get('username'), role)


def _why_no_person():
    d = _decision()
    if d is None:
        return 'access library not loaded'
    who = getattr(d, 'who', None)
    if not who:
        return getattr(d, 'reason', None) or 'no verified token'
    if not who.get('sub') or not _UUID.match(str(who.get('sub'))):
        return 'the token has no account uuid'
    return 'no single own platform role in %s' % (who.get('roles') or '[]')


# ── own_unit (IAM 2.6) ──────────────────────────────────────────────────────
# svc_scheduler's RLS policies are permissive, so an operator's run reads are
# limited here, by the rule of medcea_auth.my_units() (medcea_db_migrations.sql):
# the person's units in iam_policy.user_unit. A subquery with the sub as a
# parameter, because svc_scheduler may not execute my_units(). Another unit's
# run answers as a missing one. Applied while IAM_ENFORCE or IAM_DB_ROLES is
# true, otherwise logged ("own_unit: would limit", once an hour per person and
# route: the page polls).
_NIL_SUB = '00000000-0000-0000-0000-000000000000'
_MY_UNITS = "(SELECT uu.unit_id FROM iam_policy.user_unit uu WHERE uu.person_sub = %s::uuid)"
_DB_ROLES = {'at': 0.0, 'v': False}
_REPORTED = {}  # (what, username, route) -> time of the last report-only line


def _db_roles():
    """_enforcing() for the read routes, which have no cursor: cached for 30 s, so a
    polling page in report-only mode costs one connection per 30 s, not per request."""
    now = time.time()
    if now - _DB_ROLES['at'] > 30:
        conn = get_db()
        try:
            _DB_ROLES.update(v=_enforcing(conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)), at=now)
        finally:
            conn.close()
    return _DB_ROLES['v']


def _report(what, fmt, *args):
    d = _decision()
    key = (what, (getattr(d, 'who', None) or {}).get('username'), getattr(d, 'route', None) or request.path)
    now = time.time()
    if now - _REPORTED.get(key, 0) > 3600:
        _REPORTED[key] = now
        log.info(fmt, *args)


def _unit_scope():
    """None (not limited) or the uuid whose units bound this run read."""
    iam, d = _medcea_iam(), _decision()
    if iam is None or d is None:
        return None
    if hasattr(iam, 'own_unit_sub'):
        sub = iam.own_unit_sub(d)
    else:   # a library from before own_unit_sub: fail closed
        sub = _NIL_SUB if getattr(d, 'allow', False) and 'own_unit' in (getattr(d, 'constraints', None) or []) else None
    if sub is None:
        return None
    if iam.enforcing() or _db_roles():
        return sub
    user = (getattr(d, 'who', None) or {}).get('username') or '-'
    _report('own_unit', 'own_unit: would limit %s %s to the units of %s (IAM_ENFORCE and IAM_DB_ROLES are false)',
            request.method, request.path, user)
    return None


def _withhold_log(run_id):
    """True when GET /api/runs/<id> must leave out the log: the verified person holds R
    on runs but not on run_logs (maintenance, qc, qp). A route-level check, so it
    follows IAM_ENFORCE alone; while false it is only logged."""
    d, iam = _decision(), _medcea_iam()
    who = getattr(d, 'who', None) or {}
    if not who or iam is None or not hasattr(iam, 'allows'):
        return False
    if iam.allows(who.get('roles'), 'scheduler', 'GET', f'/api/runs/{run_id}/log'):
        return False
    if iam.enforcing():
        return True
    _report('run_logs', 'run_logs: would withhold the log of run %s from %s (no R on run_logs; IAM_ENFORCE is false)',
            run_id, who.get('username') or '-')
    return False


def _act_person(cur, need_fn=False):
    """Set this transaction's actor to the verified person. Without one: 401 under
    IAM_DB_ROLES=true; under false, no actor (plain DML is stamped db:<login>), or
    system:scheduler-unverified when a function needs an actor (superuser only).

    A person the route table refused (d.allow false: an auditor on POST /api/runs)
    is never made the actor under IAM_DB_ROLES=true, even while IAM_ENFORCE=false
    only logs the refusal: svc_scheduler holds the table grants for every
    scheduler write, and the database checks the person's role only inside some
    functions, so the route decision is the check for plain DML. Under false the
    write goes on as today (report-only), attributed to that person."""
    p = _person()
    d = _decision()
    if p and d is not None and not getattr(d, 'allow', False):
        if _enforcing(cur):
            raise Refused(getattr(d, 'status', None) or 403,
                          f"refused (IAM_DB_ROLES=true): {getattr(d, 'reason', None) or 'the route check refused this request'}")
        log.warning('actor: %s %s by %s, whom the route check refused (%s): allowed while IAM_DB_ROLES=false',
                    request.method, request.path, p[2] or p[0], getattr(d, 'reason', None) or '-')
    if p:
        cur.execute("SELECT medcea_auth.set_actor(%s, %s, %s, %s)", p)
        return p
    why = _why_no_person()
    if _enforcing(cur):
        raise Refused(401, f'a verified person is required (IAM_DB_ROLES=true): {why}')
    if need_fn:
        if not _superuser(cur):
            raise Refused(401, f'a verified person is required: {why}')
        cur.execute("SELECT medcea_auth._set_internal_actor('system:scheduler-unverified')")
    log.warning('actor: %s %s without a verified person (%s): %s', request.method, request.path, why,
                'system:scheduler-unverified' if need_fn else 'no actor, stamped db:%s' % DB['user'])
    return None


def _act_system(cur, kind, ident, need_fn=False):
    """Set the actor to system:scheduler acting for the creator of schedule/run
    `ident`. A creator that is no person is refused (42501): re-raised under true or
    for a non-superuser; under false, no actor, or the internal system:scheduler
    actor when a function needs one. True when the creator's actor was set."""
    cur.execute("SAVEPOINT medcea_actor")
    try:
        cur.execute("SELECT medcea_auth.set_system_actor('system:scheduler', %s, %s)", (kind, ident))
        cur.execute("RELEASE SAVEPOINT medcea_actor")
        return True
    except psycopg2.Error as e:
        cur.execute("ROLLBACK TO SAVEPOINT medcea_actor")
        if e.pgcode != '42501' or _enforcing(cur) or not _superuser(cur):
            raise
        log.warning('actor: %s %s has no person-attributed creator (IAM_DB_ROLES=false): %s', kind, ident,
                    'system:scheduler' if need_fn else 'no actor, stamped db:%s' % DB['user'])
        if need_fn:
            cur.execute("SELECT medcea_auth._set_internal_actor('system:scheduler')")
        return False


def _algo_of_set(cur, params_id):
    if params_id is None:
        return None
    cur.execute("SELECT a.algorithm_code FROM medcea.unit_algorithm_params s "
                "JOIN medcea.control_algorithm a ON a.algorithm_id = s.algorithm_id WHERE s.params_id = %s",
                (params_id,))
    row = cur.fetchone()
    return row['algorithm_code'] if row else None


def _insert_run(cur, unit_id, recipe_id, schedule_id=None, params_id=None):
    cur.execute("""
        INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active,
                                       schedule_id, params_id)
        VALUES (%s, %s, CURRENT_TIMESTAMP, 'S', 'Y', %s, %s)
        RETURNING recipe_run_id
    """, (recipe_id, unit_id, schedule_id, params_id))
    return cur.fetchone()['recipe_run_id']


def _active_run(cur, unit_id):
    cur.execute("SELECT recipe_run_id FROM medcea.recipe_run "
                "WHERE unit_id=%s AND recipe_run_status IN ('S','R') AND is_active='Y'", (unit_id,))
    row = cur.fetchone()
    return row['recipe_run_id'] if row else None


def _fail_run(run_id, why):
    """A background job ends a run the runner left R or S (system actor)."""
    try:
        with tx() as cur:
            cur.execute("SELECT recipe_run_status AS s FROM medcea.recipe_run WHERE recipe_run_id=%s", (run_id,))
            row = cur.fetchone()
            if not row or row['s'] not in ('R', 'S'):
                return
            _act_system(cur, 'run', run_id, need_fn=True)
            cur.execute("SELECT medcea.set_run_status(%s, 'F')", (run_id,))
        log.warning(f'run_id={run_id} was still {row["s"]} ({why}): marked F')
    except Exception as e:  # noqa: BLE001 — logged, the next recovery tries again
        log.error(f'run_id={run_id}: could not mark F ({why}): {type(e).__name__} {getattr(e, "pgcode", "")}')

# ---------------------------------------------------------------------------
# Run recipe as subprocess
# ---------------------------------------------------------------------------
def _log_path(unit_code, recipe_name, run_id=None):
    su = unit_code.replace('/', '_')
    sr = recipe_name.replace(' ', '_').replace('/', '_')
    suffix = f'_{run_id}' if run_id is not None else ''
    return os.path.join(LOG_DIR, f'run_recipe_{su}_{sr}{suffix}.log')

def _find_log_parts(unit_code, recipe_name, run_id):
    """The run's log as existing files in reading order: the new run_id-based name,
    else the legacy one; its .log.gz (compressed by sys_log_retention) before its .log
    (a retried run appends to a fresh .log). Empty when there is none."""
    for path in (_log_path(unit_code, recipe_name, run_id), _log_path(unit_code, recipe_name)):
        parts = [p for p in (path + '.gz', path) if os.path.exists(p)]
        if parts:
            return parts
    return []


def _read_log_bytes(parts):
    """The decompressed content of _find_log_parts, concatenated (offsets for live
    polling count in it)."""
    out = b''
    for p in parts:
        with (gzip.open(p, 'rb') if p.endswith('.gz') else open(p, 'rb')) as f:
            out += f.read()
    return out


def _spawn(run_id, unit_code, recipe_name, legacy=None, once_sid=None, label=None):
    """Start run_recipe.py for a run already in R (medcea.start_run). The runner reads
    RECIPE_RUN_ID; `legacy` = (algorithm, params) only while IAM_DB_ROLES=false (the
    runner then takes them from CONTROL_ALGORITHM(_PARAMS)); under true it reads the
    run's parameter set. Popen errors reach the caller; the wait is a thread."""
    log_file = _log_path(unit_code, recipe_name, run_id)
    os.makedirs(LOG_DIR, exist_ok=True)
    env = os.environ.copy()
    env['RECIPE_RUN_ID'] = str(run_id)
    env.pop('CONTROL_ALGORITHM', None)
    env.pop('CONTROL_ALGORITHM_PARAMS', None)
    algo = label or 'PARAMETER_SET'
    if legacy is not None:
        algo = (legacy[0] or 'IF_THEN_ELSE').upper()
        env['CONTROL_ALGORITHM'] = algo
        env['CONTROL_ALGORITHM_PARAMS'] = json.dumps(legacy[1] or {})
    log.info(f'Triggering run_recipe.py unit={unit_code} recipe="{recipe_name}" run_id={run_id} algo={algo} log={log_file}')
    with open(log_file, 'a') as lf:
        # the pid file in the same lock as Popen: a recovery or a stop never sees a
        # running child without it
        with _active_pids_lock:
            proc = subprocess.Popen(
                [sys.executable, '-u', os.path.join(SCHD_DIR, 'run_recipe.py'), unit_code, recipe_name],
                stdout=lf, stderr=subprocess.STDOUT,
                cwd=SCHD_DIR, env=env,
            )
            _active_pids[run_id] = {'pid': proc.pid, 'algo': algo}
            _write_pid_file(run_id, proc.pid)
    threading.Thread(target=_reap, args=(proc, run_id, unit_code, once_sid), daemon=True).start()
    return proc.pid


def _reap(proc, run_id, unit_code, once_sid):
    rc = proc.wait()
    with _active_pids_lock:
        _active_pids.pop(run_id, None)
    _delete_pid_file(run_id)
    log.info(f'run_recipe.py finished (rc={rc}) unit={unit_code} run_id={run_id}')
    # a runner that died (kill -9, a crash before its own error handling) leaves its
    # run R: end it here, so the unit is not blocked
    _fail_run(run_id, f'run_recipe.py exited with rc={rc}')
    # run-once schedules are retired (never deleted) after they fire
    if once_sid is not None:
        try:
            with tx() as cur:
                _act_system(cur, 'schedule', once_sid, need_fn=True)
                cur.execute("SELECT medcea.retire_schedule(%s)", (once_sid,))
            log.info(f'Run-once schedule {once_sid} retired after execution')
        except Exception as e:  # noqa: BLE001
            log.error(f'Failed to retire run-once schedule {once_sid}: {type(e).__name__} {getattr(e, "pgcode", "")}')

# ---------------------------------------------------------------------------
# APScheduler
# ---------------------------------------------------------------------------
scheduler = BackgroundScheduler(timezone='UTC')

# A schedule with what a run needs: its unit, recipe, inline algorithm settings
# (IAM_DB_ROLES=false), its parameter set and the assignment's (true).
_SCHEDULE_SQL = """
    SELECT s.schedule_id, s.unit_id, s.recipe_id, s.cron_expression, s.enabled, s.retired_at,
           s.params_id,
           s.algorithm_id     AS sched_algo_id,
           s.algorithm_params AS sched_algo_params,
           p.algorithm_id     AS perm_algo_id,
           p.algorithm_params AS perm_algo_params,
           p.params_id        AS perm_params_id,
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
"""


def _resolve_algorithm(row):
    """IAM_DB_ROLES=false only: effective algorithm code + params from the schedule →
    permission → default chain (what migration 008b copies into parameter sets)."""
    algo_code = row.get('sched_algo_code') or row.get('perm_algo_code') or 'IF_THEN_ELSE'
    defaults  = row.get('sched_defaults') or row.get('perm_defaults') or {}
    params    = {
        **defaults,
        **(row.get('perm_algo_params') or {}),
        **(row.get('sched_algo_params') or {}),
    }
    return algo_code, params


def _schedule_trigger_job(schedule_id):
    """Called by APScheduler. Everything is read when the schedule fires: a run is
    created and started (S -> R) as system:scheduler for the schedule's creator, in
    one transaction, then the runner is spawned. A refusal makes no run."""
    try:
        with tx() as cur:
            cur.execute(_SCHEDULE_SQL + " WHERE s.schedule_id = %s", (schedule_id,))
            row = cur.fetchone()
            if not row or row['retired_at'] is not None or not row['enabled']:
                log.info(f'Schedule {schedule_id} fired but is gone, retired or disabled: skipped')
                return
            busy = _active_run(cur, row['unit_id'])
            if busy:
                log.warning(f'Skipping scheduled trigger for {row["unit_code"]}/{row["recipe_name"]}: unit has active run {busy}')
                return
            enforce = _enforcing(cur)
            _act_system(cur, 'schedule', schedule_id, need_fn=True)
            params_id = (row['params_id'] or row['perm_params_id']) if enforce else None
            run_id = _insert_run(cur, row['unit_id'], row['recipe_id'], schedule_id, params_id)
            cur.execute("SELECT medcea.start_run(%s)", (run_id,))
            label = _algo_of_set(cur, params_id) if enforce else None
    except psycopg2.Error as e:
        primary = getattr(getattr(e, 'diag', None), 'message_primary', None)
        log.error(f'Schedule {schedule_id}: no run ({e.pgcode} {primary})')
        return
    except Exception as e:  # noqa: BLE001
        log.error(f'Schedule {schedule_id}: no run ({type(e).__name__})')
        return
    once = row['cron_expression'].startswith('once ')
    try:
        _spawn(run_id, row['unit_code'], row['recipe_name'],
               legacy=None if enforce else _resolve_algorithm(row),
               once_sid=schedule_id if once else None, label=label)
    except OSError as e:
        log.error(f'Schedule {schedule_id}: run_recipe.py did not start ({e})')
        _fail_run(run_id, 'run_recipe.py did not start')


def _reload_schedules():
    rows = query("""
        SELECT s.schedule_id, s.cron_expression, s.enabled
        FROM medcea.schedule s
        WHERE s.retired_at IS NULL
    """)
    # Remove jobs that are no longer in DB (or were retired)
    db_ids = {f"sched_{r['schedule_id']}" for r in rows}
    for job in scheduler.get_jobs():   # sched_ only: sys_log_retention stays
        if job.id.startswith('sched_') and job.id not in db_ids:
            scheduler.remove_job(job.id)
    # Add/replace
    for r in rows:
        jid = f"sched_{r['schedule_id']}"
        if r['enabled']:
            try:
                expr = r['cron_expression']
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
                    args=[r['schedule_id']],
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
# Routes — units / recipes / algorithms / parameter sets
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
                          WHERE unit_id = u.unit_id AND retired_at IS NULL
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


@app.route('/api/units/<int:uid>/algorithm-state/<algorithm>', methods=['GET'])
def get_unit_algorithm_state(uid, algorithm):
    rows = query("""
        SELECT channel, state, updated_at
        FROM medcea.algorithm_state
        WHERE unit_id = %s AND algorithm = %s AND retired_at IS NULL
        ORDER BY channel
    """, (uid, algorithm.upper()))
    return jsonify(rows)


@app.route('/api/algorithms')
def get_algorithms():
    rows = query("""
        SELECT algorithm_id, algorithm_code, algorithm_name, description,
               default_params, is_active, status
        FROM medcea.control_algorithm
        WHERE is_active = 'Y'
        ORDER BY algorithm_id
    """)
    return jsonify(rows)


@app.route('/api/algorithms/<int:aid>', methods=['PUT'])
def update_algorithm(aid):
    d = _body()
    if 'default_params' in d and not isinstance(d['default_params'], dict):
        return jsonify({'error': 'default_params must be a JSON object'}), 400
    with tx() as cur:
        _act_person(cur)
        # an approved algorithm becomes a draft (a WARNING) while IAM_DB_ROLES=false;
        # under true draft_only refuses the edit (409)
        cur.execute("""
            UPDATE medcea.control_algorithm
            SET algorithm_name  = COALESCE(%s, algorithm_name),
                description     = COALESCE(%s, description),
                default_params  = COALESCE(%s::jsonb, default_params)
            WHERE algorithm_id = %s
            RETURNING algorithm_id, algorithm_code, algorithm_name, description, default_params, is_active, status
        """, (d.get('algorithm_name'), d.get('description'),
              json.dumps(d['default_params']) if 'default_params' in d else None,
              aid))
        row = cur.fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404
    return jsonify(dict(row))


@app.route('/api/recipes')
def get_recipes():
    unit_id = request.args.get('unit_id', type=int)
    if unit_id:
        rows = query("""
            SELECT r.recipe_id, r.recipe_name, r.status, p.params_id
            FROM medcea.recipe r
            JOIN medcea.recipe_unit_permission p ON r.recipe_id = p.recipe_id
            WHERE p.unit_id = %s AND p.allowed = true AND r.is_active = 'Y'
            ORDER BY r.recipe_name
        """, (unit_id,))
    else:
        rows = query("""
            SELECT recipe_id, recipe_name, status FROM medcea.recipe
            WHERE is_active = 'Y' ORDER BY recipe_name
        """)
    return jsonify(rows)


@app.route('/api/param-sets')
def get_param_sets():
    """Parameter sets a schedule or a run may point to (not retired): for one unit
    (its own and the any-unit sets) and/or one algorithm. Header
    X-Medcea-Iam-Db-Roles says whether a schedule must name one."""
    where, args = ["s.status <> 'retired'"], []
    unit_id = request.args.get('unit_id', type=int)
    algorithm_id = request.args.get('algorithm_id', type=int)
    if unit_id:
        where.append("(s.unit_id IS NULL OR s.unit_id = %s)")
        args.append(unit_id)
    if algorithm_id:
        where.append("s.algorithm_id = %s")
        args.append(algorithm_id)
    with tx() as cur:
        enforce = _enforcing(cur)
        cur.execute("""
            SELECT s.params_id, s.name, s.algorithm_id, a.algorithm_code, s.unit_id, s.params, s.status
            FROM medcea.unit_algorithm_params s
            JOIN medcea.control_algorithm a ON a.algorithm_id = s.algorithm_id
            WHERE """ + " AND ".join(where) + """
            ORDER BY a.algorithm_code, s.name
        """, tuple(args))
        rows = [dict(r) for r in cur.fetchall()]
    resp = jsonify(rows)
    # the UI's schedule form: the set is required under IAM_DB_ROLES=true, shown for
    # information while false (no route of its own for one flag)
    resp.headers['X-Medcea-Iam-Db-Roles'] = 'true' if enforce else 'false'
    return resp

# ---------------------------------------------------------------------------
# Routes — schedules
# ---------------------------------------------------------------------------
_SCHEDULE_COLS = """schedule_id, unit_id, recipe_id, cron_expression, enabled, description,
                    algorithm_id, algorithm_params, params_id"""


@app.route('/api/schedules', methods=['GET'])
def list_schedules():
    rows = query("""
        SELECT s.schedule_id, s.unit_id, s.recipe_id,
               s.cron_expression, s.enabled, s.description,
               s.algorithm_id, s.algorithm_params, s.params_id,
               s.created_by_name, s.updated_by_name,
               u.unit_code, r.recipe_name,
               ca.algorithm_code AS algorithm_code
        FROM medcea.schedule s
        JOIN medcea.cea_unit  u  ON s.unit_id   = u.unit_id
        JOIN medcea.recipe    r  ON s.recipe_id = r.recipe_id
        LEFT JOIN medcea.control_algorithm ca ON s.algorithm_id = ca.algorithm_id
        WHERE s.retired_at IS NULL
        ORDER BY s.schedule_id DESC
    """)
    for r in rows:
        r['next_run'] = _next_run(r['schedule_id'])
    return jsonify(rows)


def _schedule_algorithm(cur, d, enforce):
    """(algorithm_id, algorithm_params json, params_id) a schedule is saved with.
    true: an approved parameter set is required (params_id) and decides the
    algorithm; inline parameters are refused. The inline columns get the set's copy,
    so a rollback to false runs what the set says. false: the inline settings as
    before; params_id is never written (the guard reserves it to migration 008b)."""
    if enforce:
        if d.get('algorithm_params') not in (None, {}):
            raise Refused(400, 'inline algorithm_params are not accepted (IAM_DB_ROLES=true): choose a parameter set (params_id)')
        pid = d.get('params_id')
        if not pid:
            raise Refused(400, 'params_id is required (IAM_DB_ROLES=true): a schedule runs an approved parameter set')
        cur.execute("SELECT algorithm_id, params FROM medcea.unit_algorithm_params WHERE params_id = %s", (pid,))
        s = cur.fetchone()
        if not s:
            raise Refused(400, f'no parameter set {pid}')
        if d.get('algorithm_id') not in (None, s['algorithm_id']):
            _note('algorithm_id ignored: the parameter set decides the algorithm')
        return s['algorithm_id'], json.dumps(s['params']), pid
    if d.get('params_id') is not None:
        _note('params_id is not stored while IAM_DB_ROLES=false: the schedule runs its inline algorithm settings')
    ap = d.get('algorithm_params')
    return d.get('algorithm_id'), (json.dumps(ap) if ap is not None else None), None


def _schedule_fields(d):
    try:
        return d['unit_id'], d['recipe_id'], d['cron_expression']
    except KeyError as e:
        raise Refused(400, f'{e.args[0]} is required')


@app.route('/api/schedules', methods=['POST'])
def create_schedule():
    d = _body()
    unit_id, recipe_id, cron = _schedule_fields(d)
    with tx() as cur:
        enforce = _enforcing(cur)
        _act_person(cur)
        algo_id, algo_params, params_id = _schedule_algorithm(cur, d, enforce)
        if enforce:
            cur.execute(f"""
                INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, enabled, description,
                                             algorithm_id, algorithm_params, params_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                RETURNING {_SCHEDULE_COLS}
            """, (unit_id, recipe_id, cron, d.get('enabled', True), d.get('description', ''),
                  algo_id, algo_params, params_id))
        else:
            cur.execute(f"""
                INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, enabled, description,
                                             algorithm_id, algorithm_params)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                RETURNING {_SCHEDULE_COLS}
            """, (unit_id, recipe_id, cron, d.get('enabled', True), d.get('description', ''),
                  algo_id, algo_params))
        row = dict(cur.fetchone())
    _reload_schedules()
    row['next_run'] = _next_run(row['schedule_id'])
    return jsonify(row), 201

@app.route('/api/schedules/<int:sid>', methods=['PUT'])
def update_schedule(sid):
    d = _body()
    unit_id, recipe_id, cron = _schedule_fields(d)
    with tx() as cur:
        cur.execute("SELECT retired_at FROM medcea.schedule WHERE schedule_id=%s", (sid,))
        cur_row = cur.fetchone()
        if not cur_row:
            return jsonify({'error': 'not found'}), 404
        if cur_row['retired_at'] is not None:
            return jsonify({'error': f'schedule {sid} is retired; create a new one'}), 409
        enforce = _enforcing(cur)
        _act_person(cur)
        algo_id, algo_params, params_id = _schedule_algorithm(cur, d, enforce)
        set_pid = ", params_id=%s" if enforce else ""
        args = [unit_id, recipe_id, cron, d.get('enabled', True), d.get('description', ''), algo_id, algo_params]
        if enforce:
            args.append(params_id)
        cur.execute(f"""
            UPDATE medcea.schedule
            SET unit_id=%s, recipe_id=%s, cron_expression=%s, enabled=%s, description=%s,
                algorithm_id=%s, algorithm_params=%s::jsonb{set_pid},
                timestamp_upd=CURRENT_TIMESTAMP
            WHERE schedule_id=%s
            RETURNING {_SCHEDULE_COLS}
        """, args + [sid])
        row = dict(cur.fetchone())
    _reload_schedules()
    row['next_run'] = _next_run(sid)
    return jsonify(row)

@app.route('/api/schedules/<int:sid>', methods=['DELETE'])
def delete_schedule(sid):
    """Retires the schedule (medcea.retire_schedule): it stops firing and is kept.
    Already retired: 200 and nothing written."""
    with tx() as cur:
        cur.execute("SELECT retired_at FROM medcea.schedule WHERE schedule_id=%s", (sid,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'not found'}), 404
        if row['retired_at'] is None:
            _act_person(cur, need_fn=True)
            cur.execute("SELECT medcea.retire_schedule(%s)", (sid,))
    _reload_schedules()
    return jsonify({'retired': sid})

@app.route('/api/schedules/<int:sid>/trigger', methods=['POST'])
def trigger_schedule(sid):
    """Run a schedule now: the run is created as the schedule's (system:scheduler for
    its creator) and started (S -> R) by the person who pressed the button."""
    with tx() as cur:
        cur.execute(_SCHEDULE_SQL + " WHERE s.schedule_id = %s", (sid,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'not found'}), 404
        if row['retired_at'] is not None:
            return jsonify({'error': f'schedule {sid} is retired'}), 409
        busy = _active_run(cur, row['unit_id'])
        if busy:
            return jsonify({'error': 'Unit already has an active run', 'run_id': busy}), 409
        enforce = _enforcing(cur)
        _act_system(cur, 'schedule', sid)
        params_id = (row['params_id'] or row['perm_params_id']) if enforce else None
        run_id = _insert_run(cur, row['unit_id'], row['recipe_id'], sid, params_id)
        _act_person(cur, need_fn=True)
        cur.execute("SELECT medcea.start_run(%s)", (run_id,))
        label = _algo_of_set(cur, params_id) if enforce else None
    legacy = None if enforce else _resolve_algorithm(row)
    algo_code = legacy[0] if legacy else (label or 'PARAMETER_SET')
    try:
        _spawn(run_id, row['unit_code'], row['recipe_name'], legacy=legacy, label=label)
    except OSError as e:
        _fail_run(run_id, 'run_recipe.py did not start')
        return jsonify({'error': f'run_recipe.py did not start: {e}', 'run_id': run_id}), 500
    return jsonify({'triggered': True, 'run_id': run_id, 'algorithm': algo_code,
                    'log': _log_path(row['unit_code'], row['recipe_name'], run_id)})

# ---------------------------------------------------------------------------
# Routes — runs
# ---------------------------------------------------------------------------
_RUN_COLS = """rr.recipe_run_id, rr.recipe_run_status,
               rr.recipe_run_start, rr.recipe_run_end,
               rr.params_id, rr.schedule_id,
               rr.created_by_name, rr.executed_by_name"""


def _fmt_runs(rows):
    for r in rows:
        r['recipe_run_start'] = r['recipe_run_start'].isoformat() if r['recipe_run_start'] else None
        r['recipe_run_end']   = r['recipe_run_end'].isoformat()   if r['recipe_run_end']   else None
    return rows

@app.route('/api/runs/active')
def list_active_runs():
    sub = _unit_scope()
    rows = query(f"""
        SELECT {_RUN_COLS},
               u.unit_id, u.unit_code, r.recipe_id, r.recipe_name
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_status != 'C'
        """ + ("AND rr.unit_id IN " + _MY_UNITS + "\n        " if sub else "") + """ORDER BY rr.recipe_run_id DESC
    """, (sub,) if sub else None)
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
    sub = _unit_scope()
    rows = query(f"""
        SELECT {_RUN_COLS},
               u.unit_code, r.recipe_name
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_status = 'C'
        """ + ("AND rr.unit_id IN " + _MY_UNITS + "\n        " if sub else "") + """ORDER BY rr.recipe_run_id DESC
        LIMIT %s
    """, (sub, limit) if sub else (limit,))
    return jsonify(_fmt_runs(rows))

@app.route('/api/runs', methods=['POST'])
def create_run():
    d = _body()
    try:
        unit_id, recipe_id = d['unit_id'], d['recipe_id']
    except KeyError as e:
        return jsonify({'error': f'{e.args[0]} is required'}), 400
    with tx() as cur:
        busy = _active_run(cur, unit_id)
        if busy:
            return jsonify({'error': 'Unit already has an active run', 'run_id': busy}), 409
        enforce = _enforcing(cur)
        _act_person(cur)
        params_id = None
        if enforce:
            # the body's set, else the assignment's; start_run refuses a run without one
            params_id = d.get('params_id')
            if params_id is None:
                cur.execute("SELECT params_id FROM medcea.recipe_unit_permission WHERE unit_id=%s AND recipe_id=%s",
                            (unit_id, recipe_id))
                p = cur.fetchone()
                params_id = p['params_id'] if p else None
        elif d.get('params_id') is not None:
            _note('params_id is not stored while IAM_DB_ROLES=false: the run is executed with the algorithm chosen at execute')
        run_id = _insert_run(cur, unit_id, recipe_id, None, params_id)
    return jsonify({'recipe_run_id': run_id}), 201

@app.route('/api/runs/<int:run_id>/status', methods=['PATCH'])
def set_run_status(run_id):
    """Reset a run to S (retry). S: nothing to do. R: 409. F: medcea.set_run_status.
    C: reopening a completed run is refused once it is released or under
    IAM_DB_ROLES=true; before that it is a direct update, reported as a warning."""
    d = _body()
    if d.get('status') != 'S':
        return jsonify({'error': 'Only reset to S is supported'}), 400
    with tx() as cur:
        cur.execute("SELECT recipe_run_status AS s FROM medcea.recipe_run WHERE recipe_run_id=%s", (run_id,))
        current = cur.fetchone()
        if not current:
            return jsonify({'error': 'not found'}), 404
        st = current['s']
        if st == 'S':
            return jsonify({'updated': run_id, 'status': 'S'})
        if st == 'R':
            return jsonify({'error': 'Cannot modify a currently running recipe'}), 409
        if st == 'F':
            _act_person(cur, need_fn=True)
            cur.execute("SELECT medcea.set_run_status(%s, 'S')", (run_id,))
            return jsonify({'updated': run_id, 'status': 'S'})
        # C
        cur.execute("SELECT 1 AS x FROM medcea.run_release WHERE recipe_run_id=%s", (run_id,))
        if cur.fetchone():
            return jsonify({'error': f'run {run_id} is released; a released run is never reopened'}), 409
        if _functions_only(cur):
            return jsonify({'error': f'run {run_id} is completed; a completed run is not reopened '
                                     '(IAM_DB_ROLES=true, or the scheduler on its own database role)'}), 409
        _act_person(cur)
        cur.execute("UPDATE medcea.recipe_run SET recipe_run_status='S', recipe_run_end=NULL, "
                    "timestamp_upd=CURRENT_TIMESTAMP WHERE recipe_run_id=%s", (run_id,))
        _note(f'IAM_DB_ROLES=false, would refuse: reopening completed run {run_id}')
    return jsonify({'updated': run_id, 'status': 'S'})

@app.route('/api/runs/<int:run_id>/execute', methods=['POST'])
def execute_run(run_id):
    row = query("""
        SELECT u.unit_code, r.recipe_name, rr.recipe_run_status, rr.params_id
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
    d = _body()
    with tx() as cur:
        enforce = _enforcing(cur)
        _act_person(cur, need_fn=True)
        cur.execute("SELECT medcea.start_run(%s)", (run_id,))
        label = _algo_of_set(cur, row['params_id']) if enforce else None
    if enforce:
        legacy = None
        if d.get('control_algorithm') or d.get('control_algorithm_params'):
            _note('control_algorithm(_params) ignored (IAM_DB_ROLES=true): the run uses its parameter set')
        algo = label or 'PARAMETER_SET'
    else:
        legacy = ((d.get('control_algorithm') or 'IF_THEN_ELSE').upper(), d.get('control_algorithm_params') or {})
        algo = legacy[0]
    try:
        _spawn(run_id, row['unit_code'], row['recipe_name'], legacy=legacy, label=label)
    except OSError as e:
        with tx() as cur:
            _act_person(cur, need_fn=True)
            cur.execute("SELECT medcea.set_run_status(%s, 'F')", (run_id,))
        return jsonify({'error': f'run_recipe.py did not start: {e}'}), 500
    return jsonify({'executing': True, 'unit': row['unit_code'], 'recipe': row['recipe_name'],
                    'algorithm': algo})

@app.route('/api/runs/<int:run_id>/stop', methods=['POST'])
def stop_run(run_id):
    """R or S: medcea.set_run_status(F) as the person, then SIGTERM (a refusal kills
    nothing). F: already stopped; SIGTERM if a process is still tracked. C: 409."""
    with tx() as cur:
        cur.execute("SELECT recipe_run_status AS s FROM medcea.recipe_run WHERE recipe_run_id=%s", (run_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'not found'}), 404
        if row['s'] == 'C':
            return jsonify({'error': f'run {run_id} is completed'}), 409
        if row['s'] in ('R', 'S'):
            _act_person(cur, need_fn=True)
            cur.execute("SELECT medcea.set_run_status(%s, 'F')", (run_id,))
    with _active_pids_lock:
        entry = _active_pids.get(run_id)
        pid = entry['pid'] if entry else None
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
        log.info(f'No tracked pid for run_id={run_id} — marked stopped in DB only')
    log.info(f'run_id={run_id} marked F (stopped) in DB')
    return jsonify({'stopped': True, 'run_id': run_id, 'pid': pid})

@app.route('/api/runs/<int:run_id>')
def get_run(run_id):
    sub = _unit_scope()
    row = query(f"""
        SELECT {_RUN_COLS},
               u.unit_code, r.recipe_name
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_id = %s
    """ + ("    AND rr.unit_id IN " + _MY_UNITS + "\n" if sub else ""), (run_id, sub) if sub else (run_id,), fetchall=False)
    if not row:
        return jsonify({'error': 'not found'}), 404
    row['recipe_run_start'] = row['recipe_run_start'].isoformat() if row['recipe_run_start'] else None
    row['recipe_run_end']   = row['recipe_run_end'].isoformat()   if row['recipe_run_end']   else None
    if _withhold_log(run_id):
        row['log'], row['log_withheld'] = None, 'run_logs'
        return jsonify(row)
    parts = _find_log_parts(row['unit_code'], row['recipe_name'], run_id)
    if parts:
        row['log'] = _read_log_bytes(parts).decode('utf-8', errors='replace')
    else:
        row['log'] = f"(no log file at {_log_path(row['unit_code'], row['recipe_name'], run_id)})"
    return jsonify(row)

@app.route('/api/runs/<int:run_id>/cycles')
def get_run_cycles(run_id):
    sub = _unit_scope()   # another unit's run: [] as for a missing one (rr_operator's RLS)
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
        """ + ("AND rlcr.recipe_run_id IN (SELECT x.recipe_run_id FROM medcea.recipe_run x WHERE x.unit_id IN "
               + _MY_UNITS + ")\n        " if sub else "") + """ORDER BY rlcr.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num
    """, (run_id, sub) if sub else (run_id,))
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
    sub    = _unit_scope()   # another unit's run: 404 before any log path is built
    row = query("""
        SELECT rr.recipe_run_status, u.unit_code, r.recipe_name
        FROM medcea.recipe_run rr
        JOIN medcea.cea_unit  u ON rr.unit_id   = u.unit_id
        JOIN medcea.recipe    r ON rr.recipe_id = r.recipe_id
        WHERE rr.recipe_run_id = %s
    """ + ("    AND rr.unit_id IN " + _MY_UNITS + "\n" if sub else ""), (run_id, sub) if sub else (run_id,), fetchall=False)
    if not row:
        return jsonify({'error': 'not found'}), 404
    parts = _find_log_parts(row['unit_code'], row['recipe_name'], run_id)
    content = ''
    next_offset = offset
    if parts:
        raw = _read_log_bytes(parts)
        if tail > 0:
            next_offset = len(raw)
            text  = raw.decode('utf-8', errors='replace')
            lines = text.splitlines(keepends=True)
            content = ''.join(lines[-tail:]) if len(lines) > tail else text
        else:
            chunk = raw[offset:]
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
        for fname in os.listdir(LOG_DIR):   # run logs only: /logs also holds the deploy logs
            if log_retention.RUN_LOG.match(fname):
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
    dd = _get_config('log_delete_days', None)
    result = {
        'compress_days': int(_get_config('log_compress_days', '7')),
        'delete_days':   int(dd) if dd is not None else None,   # kept, unused: nothing deletes a run log
        'minimums': {'compress_days': log_retention.MIN_COMPRESS_DAYS,
                     'delete_days':   log_retention.MIN_DELETE_DAYS},
        'job': {'schedule': RETENTION_SCHEDULE, 'last_run': _RETENTION['at'],
                'last_result': _RETENTION['result'], 'last_error': _RETENTION['error']},
    }
    result.update(_log_stats())
    return jsonify(result)

@app.route('/api/config/logs', methods=['PUT'])
def put_log_config():
    """false: saved at once, as the person. true: retention changes wait for qa —
    one medcea.propose_setting per changed key, answered 202 with the change ids."""
    d = _body()
    wanted = []
    for key, val in [('log_compress_days', d.get('compress_days')),
                     ('log_delete_days',   d.get('delete_days'))]:
        if val is not None:
            try:
                wanted.append((key, int(val)))
            except (TypeError, ValueError):
                return jsonify({'error': f'{key} must be a whole number of days'}), 400
    with tx() as cur:
        # a key sent back unchanged is skipped, so a legacy value below the minimum
        # (the page sends both fields; 008b's CHECK is NOT VALID) never blocks the other
        changed = []
        for key, val in wanted:
            cur.execute("SELECT value FROM medcea.scheduler_config WHERE key=%s", (key,))
            now = cur.fetchone()
            if not (now and str(now['value']) == str(val)):
                changed.append((key, val))
        # the database's minimums (approve_change, scheduler_config_retention_chk), in both
        # modes: under IAM_DB_ROLES=false there is no CHECK
        for key, val in changed:
            low = log_retention.MIN_COMPRESS_DAYS if key == 'log_compress_days' else log_retention.MIN_DELETE_DAYS
            if val < low:
                return jsonify({'error': f'{key} must be at least {low}'}), 400
        if _functions_only(cur):   # a proposal, applied once approved (A on scheduler_settings)
            _act_person(cur, need_fn=True)
            ids = []
            for key, val in changed:
                cur.execute("SELECT medcea.propose_setting(%s, %s::jsonb) AS id", (key, json.dumps(val)))
                ids.append(cur.fetchone()['id'])
            return jsonify({'pending': bool(ids), 'change_ids': ids}), 202
        _act_person(cur)
        for key, val in changed:
            cur.execute("""
                INSERT INTO medcea.scheduler_config (key, value)
                VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """, (key, str(val)))
    return jsonify({'saved': True})

# ---------------------------------------------------------------------------
# System job — run-log compression (IAM 2.6)
# ---------------------------------------------------------------------------
_RETENTION = {'at': None, 'result': None, 'error': None}
RETENTION_SCHEDULE = 'daily 03:15 UTC'


def _still_idle(run_id):
    with _active_pids_lock:
        return run_id not in _active_pids


def _log_retention_job():
    """System job sys_log_retention: no person compresses or deletes a run log, and
    this job only compresses (log_retention.plan). Writes no database row, so it needs
    no actor. A database it cannot read means no run this time, never the defaults."""
    try:
        cd = _get_config('log_compress_days', '7')
        entries, stats = [], {}
        if os.path.isdir(LOG_DIR):
            for fname in os.listdir(LOG_DIR):
                if log_retention.RUN_LOG.match(fname):
                    try:
                        st = os.stat(os.path.join(LOG_DIR, fname))
                    except OSError:
                        continue
                    entries.append((fname, st.st_mtime))
                    stats[fname] = (st.st_mtime, st.st_size)
        ids = sorted({i for i in (log_retention.run_id_of(f) for f, _ in entries) if i is not None})
        runs = {}
        if ids:
            for r in query("""
                SELECT rr.recipe_run_id, rr.recipe_run_status, u.unit_code, r.recipe_name
                FROM medcea.recipe_run rr
                JOIN medcea.cea_unit u ON u.unit_id   = rr.unit_id
                JOIN medcea.recipe   r ON r.recipe_id = rr.recipe_id
                WHERE rr.recipe_run_id = ANY(%s)
            """, (ids,)):
                runs[r['recipe_run_id']] = {
                    'status': r['recipe_run_status'],
                    'basename': os.path.basename(_log_path(r['unit_code'], r['recipe_name'], r['recipe_run_id']))}
        with _active_pids_lock:
            active = set(_active_pids)
        actions = log_retention.plan(entries, time.time(), cd, runs, active)
        res = log_retention.apply(LOG_DIR, actions, log, still_idle=_still_idle, stats=stats)
        _RETENTION.update(at=datetime.now(timezone.utc).isoformat(), result=res, error=None)
        log.info(f"log retention: compressed {res['compressed']}, kept {res['kept']}, errors {res['errors']}")
    except Exception as e:  # noqa: BLE001
        _RETENTION.update(at=datetime.now(timezone.utc).isoformat(), error=f'{type(e).__name__}: {e}')
        log.error(f'log retention: not run: {type(e).__name__}: {e}')

# ---------------------------------------------------------------------------
# Startup recovery — re-register or reap orphaned run_recipe.py processes
# ---------------------------------------------------------------------------
def _startup_recovery():
    """A pid file whose process is gone: its run is ended (F). So is a run in R that
    this API started (executed_by_sub is set by medcea.start_run only) with no pid
    file left. Runs started from the command line (legacy path, no executed_by) are
    not touched."""
    import glob
    pid_files = glob.glob(os.path.join(SCHD_DIR, 'run_*.pid'))
    if pid_files:
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
            _fail_run(run_id, 'startup recovery: its process is gone')
    try:
        orphans = query("SELECT recipe_run_id FROM medcea.recipe_run "
                        "WHERE recipe_run_status = 'R' AND executed_by_sub IS NOT NULL")
    except Exception as e:  # noqa: BLE001
        log.error(f'Startup recovery: cannot list running runs: {type(e).__name__}')
        return
    for o in orphans:
        rid = o['recipe_run_id']
        with _active_pids_lock:
            tracked = rid in _active_pids
        if not tracked and not os.path.exists(_pid_file(rid)):
            _fail_run(rid, 'startup recovery: started by the API, no runner left')

# ---------------------------------------------------------------------------
# Schema presence — checked at startup (read-only)
# ---------------------------------------------------------------------------
def _check_schema():
    """medcea.schedule, medcea.scheduler_config and the run functions are created by
    migration 008b (apps/database/deploy.sh); the scheduler runs no DDL and grants
    nothing, so its database role needs no ownership and cannot re-grant what the
    access policy revoked. Anything missing is logged, not created."""
    try:
        row = query("SELECT to_regclass('medcea.schedule') IS NOT NULL AS schedule, "
                    "to_regclass('medcea.scheduler_config') IS NOT NULL AS scheduler_config, "
                    "to_regprocedure('medcea.start_run(integer)') IS NOT NULL AS start_run, "
                    "to_regprocedure('medcea.retire_schedule(integer)') IS NOT NULL AS retire_schedule",
                    fetchall=False)
        missing = [k for k, v in (row or {}).items() if not v]
        if missing:
            log.error('Schema check: missing medcea.%s — run ./apps/database/deploy.sh' % ', medcea.'.join(missing))
        else:
            log.info('Schema ready (medcea.schedule, medcea.scheduler_config, start_run, retire_schedule)')
    except Exception as e:
        log.error(f'Schema check failed: {e}')

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    _write_dotenv()
    sys.path.insert(0, SCHD_DIR)
    _check_schema()
    _startup_recovery()
    scheduler.start()
    scheduler.add_job(_log_retention_job, CronTrigger(hour=3, minute=15, timezone='UTC'),
                      id='sys_log_retention', replace_existing=True, max_instances=1,
                      coalesce=True, misfire_grace_time=3600)
    _reload_schedules()
    log.info('Scheduler API ready on :8082')
    app.run(host='0.0.0.0', port=8082, threaded=True)
