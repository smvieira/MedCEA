#!/usr/bin/env python3
"""tests/runner/iam_runner_flow.py — the scheduler API and the runner of IAM plan 2.4
against the throwaway database of tests/iam-db-fixture.sh.

Runs INSIDE the iam-runner pod that tests/iam-runner.sh starts (never on the host, never
against production):

    python3 /work/cur/tests/runner/iam_runner_flow.py --mode false|false-svc|true|legacy

The real apps/scheduler/scheduler-api.py is loaded as a module and driven through
Flask's test client, as postgres (IAM_DB_ROLES=false) or svc_scheduler (true). Its
access check is the real medcea_iam.py with this checkout's compiled routes.json and a
JWKS made here from a throwaway RSA key that never leaves the pod; requests carry tokens
signed with it as X-Forwarded-Access-Token, as the scheduler's oauth2-proxy sends them.
run_recipe.py runs as the API spawns it (paho is a stub: no broker). Assertions read the
database as postgres. Exit 1 on any FAIL.

  legacy  (before migration 008b) the new run_recipe.py's command-line path
  R1   schedules are stamped with the person; true: a parameter set is required and
       inline parameters are refused
  R2   a schedule triggered by an operator: created as the schedule's creator, started
       by the operator, completed by the runner; params_id only under true; a schedule
       whose set's algorithm differs from the assignment's runs (B1)
  R3   a run created by a production manager, executed by an operator, completed
  R4   execute's algorithm: false from the body, true from the set (body ignored)
  R5   stop: F at once, SIGTERM, the runner writes nothing more
  R6   PATCH status: S is a no-op, F -> S, C refused once released (and under true)
  R7   DELETE retires; a retired schedule cannot be edited (API 409, old SQL 42501)
  R8   (false) the runner of the previous commit and this one leave the same run
  R9   a migration:008 schedule: no person-less re-save makes it fire under true
  R10  the cron path (_schedule_trigger_job): fires as the schedule's creator
  R11  log retention: saved (false), proposed for qa, 202 (true)
  R12  a request without a person: stamped db:postgres (false), 401 (true)
  R13  editing an approved algorithm: demoted with an advisory (false), 409 (true)
  R14  a runner killed with SIGKILL: its run ends F
  R15  a medcea_iam.py from before actor_role
  R16  PUT /api/algorithms through the Config UI's nginx: the nginx half (the token
       reaches the scheduler) is tests/iam-postgrest.sh R16; the scheduler half (that
       header makes the person the actor) is R13 here
  R17  a verified person the route table refuses (an auditor's POST /api/runs, an
       operator's DELETE /api/schedules/<id>): 403 and nothing written under true,
       even with IAM_ENFORCE=false; written and attributed under false (report-only)
"""
import argparse
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid

import psycopg2
import psycopg2.extras

PG = dict(host=os.environ.get("PG_HOST", "rdbms-postgresql"), dbname=os.environ.get("PG_DATABASE", "medcea_db"))
ISSUER = "https://keycloak.iamtest.invalid/realms/medcea"
UNIT, UNIT2, R0, R1 = "IAMT01", "IAMT02", "IAMTEST-R0", "IAMTEST-R1"
UUID_PM = "22222222-2222-4222-8222-222222222222"
UUID_OP = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"   # assigned unit IAMT01 in main() (IAM 2.8)
FAILS = 0
PASSES = 0


def ok(case, name, cond, detail=""):
    global FAILS, PASSES
    if cond:
        PASSES += 1
        print(f"  PASS  {case:<6} {name}", flush=True)
    else:
        FAILS += 1
        print(f"  FAIL  {case:<6} {name}{': ' + str(detail) if detail else ''}", flush=True)
    return cond


def note(case, msg):
    print(f"  NOTE  {case:<6} {msg}", flush=True)


# ── the database, as postgres ───────────────────────────────────────────────────────
def su():
    return psycopg2.connect(user="postgres", password=os.environ["PG_SU_PASSWORD"],
                            options="-c client_min_messages=warning", **PG)


def q(sql, args=(), one=False):
    conn = su()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()] if cur.description else []
        conn.commit()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()


def owner(sql, args=()):
    """A test-only setup or cleanup write as medcea_owner (the guards exempt it);
    before migration 008b (mode legacy) a plain write as postgres."""
    conn = su()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT to_regprocedure('medcea_auth._set_internal_actor(text)') IS NOT NULL AS v")
        if cur.fetchone()["v"]:
            cur.execute("SELECT medcea_auth._set_internal_actor('migration:008')")
            cur.execute("SET LOCAL ROLE medcea_owner")
        cur.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()] if cur.description else []
        conn.commit()
        return rows
    finally:
        conn.close()


def has_008b():
    return q("SELECT to_regprocedure('medcea.record_cycle(integer, jsonb)') IS NOT NULL AS v", one=True)["v"]


def ids():
    r = q("""SELECT (SELECT unit_id FROM medcea.cea_unit WHERE unit_code = %s) AS u1,
                    (SELECT unit_id FROM medcea.cea_unit WHERE unit_code = %s) AS u2,
                    (SELECT recipe_id FROM medcea.recipe WHERE recipe_name = %s) AS r0,
                    (SELECT recipe_id FROM medcea.recipe WHERE recipe_name = %s) AS r1""",
          (UNIT, UNIT2, R0, R1), one=True)
    if None in r.values():
        raise SystemExit(f"the seed is missing (tests/sql/iam-db-seed.sql): {r}")
    return r


def end_open_runs():
    """Leave no S/R run on the IAMT units for the next case or the next fixture step."""
    owner("""UPDATE medcea.recipe_run SET recipe_run_status = 'F', recipe_run_end = now()
              WHERE recipe_run_status IN ('S', 'R')
                AND unit_id IN (SELECT unit_id FROM medcea.cea_unit WHERE unit_code IN (%s, %s))""", (UNIT, UNIT2))


def cycles(run_id):
    return q("""SELECT recipe_item_seq_id, recipe_item_seq_cycle_num, recipe_line_cycle_run_status AS st,
                       run_params::jsonb AS rp
                  FROM medcea.recipe_line_cycle_run WHERE recipe_run_id = %s
                 ORDER BY recipe_item_seq_id, recipe_item_seq_cycle_num""", (run_id,))


def run_row(run_id):
    return q("SELECT * FROM medcea.recipe_run WHERE recipe_run_id = %s", (run_id,), one=True)


# ── tokens ──────────────────────────────────────────────────────────────────────────
class Tokens:
    def __init__(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.jwt = jwt
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid="iam-runner", alg="RS256", use="sig")
        with open("/jwks/jwks.json", "w") as f:
            json.dump({"keys": [jwk]}, f)

    def __call__(self, roles, sub, person, user):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": ["medcea-api", "account"], "sub": sub, "typ": "Bearer",
                  "azp": "scheduler", "iat": now, "exp": now + 3600, "preferred_username": user,
                  "person_id": person, "groups": roles + ["default-roles-medcea"]}
        return self.jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "iam-runner"})


def setup_iam(cur_dir):
    os.makedirs("/iam", exist_ok=True)
    shutil.copy(os.path.join(cur_dir, "apps/iam/lib/medcea_iam.py"), "/iam/medcea_iam.py")
    shutil.copy("/src/routes.json", "/iam/routes.json")
    with open("/iam/settings.json", "w") as f:
        json.dump({"issuer": ISSUER, "audience": "medcea-api", "enforce": False}, f)
    with open("/iam/routes.json") as f:
        return json.load(f)


def role_for(routes, route, prefer):
    """A role that may call `route` (scheduler), preferring `prefer`."""
    roles = routes["services"]["scheduler"]["routes"][route]["roles"]
    for r in prefer:
        if r in roles:
            return r
    return sorted(roles, key=lambda r: (roles[r] is not None, r))[0]


# ── the API under test ──────────────────────────────────────────────────────────────
def load_api(svc, cur_dir):
    if os.path.isdir("/schd"):
        for name in os.listdir("/schd"):
            p = os.path.join("/schd", name)
            shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
    shutil.copytree(os.path.join(cur_dir, "schd"), "/schd", dirs_exist_ok=True)
    if svc:
        os.environ["PG_USER"], os.environ["PG_PASSWORD"] = "svc_scheduler", os.environ.get("PG_SVC_PASSWORD", "")
    else:
        os.environ["PG_USER"], os.environ["PG_PASSWORD"] = "postgres", os.environ["PG_SU_PASSWORD"]
    os.environ["PG_HOST"], os.environ["PG_DATABASE"] = PG["host"], PG["dbname"]
    spec = importlib.util.spec_from_file_location("scheduler_api", os.path.join(cur_dir, "apps/scheduler/scheduler-api.py"))
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    api._write_dotenv()
    sys.path.insert(0, "/schd")
    return api


def wait_run(api, run_id, timeout=240):
    """Until the run is C or F and the API has reaped its runner."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = run_row(run_id)["recipe_run_status"]
        with api._active_pids_lock:
            alive = run_id in api._active_pids
        if st in ("C", "F") and not alive:
            return st
        time.sleep(1)
    return run_row(run_id)["recipe_run_status"]


def wait_for(cond, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            return True
        time.sleep(1)
    return False


def log_of(api, run_id):
    r = q("""SELECT u.unit_code, r.recipe_name FROM medcea.recipe_run rr JOIN medcea.cea_unit u USING (unit_id)
              JOIN medcea.recipe r USING (recipe_id) WHERE rr.recipe_run_id = %s""", (run_id,), one=True)
    p = api._log_path(r["unit_code"], r["recipe_name"], run_id)
    try:
        with open(p) as f:
            return f.read()
    except OSError:
        return ""


def changes(target, key):
    return q("SELECT op, actor_sub, actor_person, actor_name, actor_source, new_values FROM medcea.row_change "
             "WHERE target = %s AND row_key = %s::jsonb ORDER BY change_id", (target, json.dumps(key)))


def approved_set(alg_code, unit_id, name):
    """A test-only approved parameter set (owner write + grandfather approval)."""
    old = q("SELECT params_id FROM medcea.unit_algorithm_params WHERE name = %s", (name,), one=True)
    if old:
        return old["params_id"]
    pid = owner("""INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params, status, source)
                   SELECT algorithm_id, %s, %s, '{}', 'approved', 'tests/iam-runner.sh'
                     FROM medcea.control_algorithm WHERE algorithm_code = %s RETURNING params_id""",
                (unit_id, name, alg_code))[0]["params_id"]
    owner("""INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note,
                                          approved_by_sub, approved_by_name, approved_by_source, last_change_id)
             SELECT 'medcea.unit_algorithm_params', jsonb_build_array(%s),
                    medcea_auth.row_digest('medcea.unit_algorithm_params', jsonb_build_array(%s)), 'controllers',
                    'grandfather', 'tests/iam-runner.sh', 'migration:008', 'migration:008', 'migration',
                    (SELECT x.last_change FROM medcea_auth._authors('medcea.unit_algorithm_params', jsonb_build_array(%s)) x)""",
          (pid, pid, pid))
    return pid


# ── legacy: before 008b, the new runner's command-line path ─────────────────────────
def run_legacy_cli(schd_dir, i, env_extra=None, svc=False):
    """The old API's run row, then run_recipe.py without RECIPE_RUN_ID (exit code, run id).
    The command-line path refuses a unit with a failed run that is still active
    (check_unit_availability), so earlier cases' F runs are deactivated first. svc: as
    svc_scheduler, the login the scheduler pod hands its runner (false-svc, true)."""
    owner("UPDATE medcea.recipe_run SET is_active = 'N' WHERE unit_id = %s AND recipe_run_status = 'F' AND is_active = 'Y'",
          (i["u1"],))
    run_id = q("""INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
                  VALUES (%s, %s, CURRENT_TIMESTAMP, 'S', 'Y') RETURNING recipe_run_id""", (i["r0"], i["u1"]), one=True)["recipe_run_id"]
    os.makedirs(os.path.join(schd_dir, "..", "installer"), exist_ok=True)
    dotenv = os.path.join(schd_dir, "..", "installer", ".env")
    with open(dotenv, "w") as f:
        os.chmod(dotenv, 0o600)
        user, pw = ("svc_scheduler", os.environ.get("PG_SVC_PASSWORD", "")) if svc else ("postgres", os.environ["PG_SU_PASSWORD"])
        f.write(f"DB_HOST={PG['host']}\nDB_NAME={PG['dbname']}\nDB_USER={user}\nDB_PASS={pw}\n"
                f"MQTT_URL=127.0.0.1\nMQTT_PORT=1883\nPROJECT_NAME=medcea\n")
    env = {k: v for k, v in os.environ.items() if k != "RECIPE_RUN_ID"}
    env.update({"CONTROL_ALGORITHM": "IF_THEN_ELSE", "CONTROL_ALGORITHM_PARAMS": json.dumps({"iamt_runner": 0})})
    env.update(env_extra or {})
    try:
        p = subprocess.run([sys.executable, "-u", "run_recipe.py", UNIT, R0], cwd=schd_dir, env=env,
                           capture_output=True, text=True, timeout=300)
    finally:
        os.unlink(dotenv)
    return p, run_id


def case_legacy(i):
    if has_008b():
        note("legacy", "migration 008b is already loaded: the pre-008b runner check is skipped")
        return
    shutil.copytree("/work/cur/schd", "/schd", dirs_exist_ok=True)
    end_open_runs()
    p, run_id = run_legacy_cli("/schd", i)
    ok("legacy", "new run_recipe.py, command-line path, before 008b: exit 0", p.returncode == 0, p.stderr[-400:])
    ok("legacy", "the run completed with both cycles", run_row(run_id)["recipe_run_status"] == "C"
       and [c["st"] for c in cycles(run_id)] == ["C", "C"], cycles(run_id))
    end_open_runs()


# ── the cases ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["false", "false-svc", "true", "legacy"])
    a = ap.parse_args()
    mode = a.mode
    i = ids()
    print(f"iam-runner: mode {mode}, units {UNIT}={i['u1']} {UNIT2}={i['u2']}, recipes {R0}={i['r0']} {R1}={i['r1']}")
    if mode == "legacy":
        case_legacy(i)
        return
    if not has_008b():
        ok("setup", "migration 008b is loaded", False)
        return
    db_mode = q("SELECT coalesce((SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'), '') AS v", one=True)["v"]
    want_db = "false" if mode == "false-svc" else mode
    if not ok("setup", f"the database is in mode {want_db}", db_mode == want_db, db_mode):
        return
    # the operator's unit (own_unit, assigned_run); the trigger logs unit_assigned
    owner("INSERT INTO iam_policy.user_unit (person_sub, unit_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
          (UUID_OP, i["u1"]))
    # enforce: IAM_DB_ROLES=true. svc: the scheduler on svc_scheduler (true, or
    # false-svc = IAM_DB_SERVICE_ROLES, IAM 2.5). strict: writes go through the
    # functions only — the scheduler holds no direct DML for them off superuser.
    enforce = mode == "true"
    svc = mode in ("true", "false-svc")
    strict = enforce or svc
    routes = setup_iam("/work/cur")
    tok = Tokens()
    api = load_api(svc, "/work/cur")
    # paused: next_run is computed, but no schedule fires by itself during the test
    api.scheduler.start(paused=True)
    c = api.app.test_client()

    def H(t):
        return {"X-Forwarded-Access-Token": t} if t else {}

    T_PM = tok(["production_manager", "operator"], UUID_PM, "p-pm", "test-pm")   # a composite, as Keycloak sends it
    T_PM1 = tok(["production_manager"], UUID_PM, "p-pm", "test-pm")
    T_OP = tok(["operator"], UUID_OP, "p-op", "test-op")
    alg_role = role_for(routes, "PUT /api/algorithms/<id>", ["engineer", "control_scientist"])
    T_ALG = tok([alg_role], "55555555-5555-4555-8555-555555555555", "p-alg", "test-alg")
    log_role = role_for(routes, "PUT /api/config/logs", ["admin", "production_manager"])
    T_LOG = tok([log_role], "77777777-7777-4777-8777-777777777777", "p-log", "test-log")
    who = "svc_scheduler" if svc else "postgres"
    set_r0 = q("SELECT params_id FROM medcea.recipe_unit_permission WHERE recipe_id = %s AND unit_id = %s",
               (i["r0"], i["u1"]), one=True)["params_id"]
    end_open_runs()

    def new_schedule(token, extra=None, recipe="r0", unit="u1"):
        body = {"unit_id": i[unit], "recipe_id": i[recipe], "cron_expression": "0 3 1 1 *",
                "description": f"iamtest runner {uuid.uuid4().hex[:6]}", "enabled": True}
        if enforce:
            body["params_id"] = set_r0
        body.update(extra or {})
        return c.post("/api/schedules", json=body, headers=H(token))

    # R1 ───────────────────────────────────────────────────────────────────────────
    r = new_schedule(T_PM)
    ok("R1", "a production manager creates a schedule (201)", r.status_code == 201, r.get_json())
    sid = (r.get_json() or {}).get("schedule_id")
    s = q("SELECT * FROM medcea.schedule WHERE schedule_id = %s", (sid,), one=True) or {}
    ok("R1", f"stamped with the person, via {who}", s.get("created_by_name") == "test-pm"
       and s.get("created_by_person") == "p-pm" and s.get("created_by_role") == "production_manager"
       and s.get("created_by_source") == f"person via {who}", {k: s.get(k) for k in ("created_by_name", "created_by_source")})
    if enforce:
        ok("R1", "params_id is stored and decides the algorithm", s.get("params_id") == set_r0, s.get("params_id"))
        r2 = new_schedule(T_PM, {"params_id": None})
        ok("R1", "without a parameter set: 400", r2.status_code == 400, r2.get_json())
        r2 = new_schedule(T_PM, {"algorithm_params": {"x": 9}})
        ok("R1", "inline algorithm_params: 400", r2.status_code == 400, r2.get_json())
    else:
        ok("R1", "params_id is never written while false", s.get("params_id") is None, s.get("params_id"))

    # R2 ───────────────────────────────────────────────────────────────────────────
    r = c.post(f"/api/schedules/{sid}/trigger", headers=H(T_OP))
    ok("R2", "an operator triggers the schedule (200)", r.status_code == 200, r.get_json())
    rid = (r.get_json() or {}).get("run_id")
    if rid:
        st = wait_run(api, rid)
        rr = run_row(rid)
        ok("R2", "the runner completed the run (C, two cycles C)", st == "C" and [x["st"] for x in cycles(rid)] == ["C", "C"],
           (st, cycles(rid), log_of(api, rid)[-600:]))
        ok("R2", "created as the schedule's creator, executed by the operator",
           rr["created_by_person"] == "p-pm" and rr["created_by_source"] == "system"
           and rr["executed_by_person"] == "p-op" and rr["executed_by_name"] == "test-op",
           {k: rr[k] for k in ("created_by_person", "created_by_source", "executed_by_person")})
        ok("R2", "the run names its schedule", rr["schedule_id"] == sid, rr["schedule_id"])
        ok("R2", "params_id: the schedule's set under true, NULL under false",
           rr["params_id"] == (set_r0 if enforce else None), rr["params_id"])
        rp = (cycles(rid) or [{}])[0].get("rp") or [{}]
        ok("R2", "the cycle's run_params is a list naming the algorithm",
           isinstance(rp, list) and rp[0].get("control_algorithm") == "IF_THEN_ELSE"
           and rp[0].get("control_algorithm_params", {}).get("iamt_runner") == 0, rp)
        ch = changes("medcea.recipe_line_cycle_run", [q("SELECT min(recipe_line_cycle_run_id) AS v FROM medcea.recipe_line_cycle_run "
                                                        "WHERE recipe_run_id = %s", (rid,), one=True)["v"]])
        ok("R2", "cycles are written as system:scheduler for the run's creator",
           ch and all(x["actor_sub"] == "system:scheduler" and x["actor_person"] == "p-pm" for x in ch), ch)
    # B1: the schedule's own algorithm (FLC) on a unit whose assignment says IF_THEN_ELSE
    if enforce:
        flc = approved_set("FLC", i["u1"], "iamt-runner-flc")
        r = new_schedule(T_PM, {"params_id": flc})
    else:
        flc_id = q("SELECT algorithm_id FROM medcea.control_algorithm WHERE algorithm_code = 'FLC'", one=True)["algorithm_id"]
        r = new_schedule(T_PM, {"algorithm_id": flc_id, "algorithm_params": {}})
    sid_flc = (r.get_json() or {}).get("schedule_id")
    r = c.post(f"/api/schedules/{sid_flc}/trigger", headers=H(T_OP))
    ok("R2", "B1: a schedule whose algorithm differs from the assignment's starts", r.status_code == 200, r.get_json())
    rid_flc = (r.get_json() or {}).get("run_id")
    if rid_flc:
        st = wait_run(api, rid_flc)
        rp = (cycles(rid_flc) or [{}])[0].get("rp") or [{}]
        ok("R2", "B1: completed with the schedule's algorithm (FLC)", st == "C" and rp[0].get("control_algorithm") == "FLC",
           (st, rp, log_of(api, rid_flc)[-400:]))
    end_open_runs()

    # R3, R4 ───────────────────────────────────────────────────────────────────────
    r = c.post("/api/runs", json={"unit_id": i["u1"], "recipe_id": i["r0"]}, headers=H(T_PM))
    ok("R3", "a production manager creates a run (201)", r.status_code == 201, r.get_json())
    rid3 = (r.get_json() or {}).get("recipe_run_id")
    body = {"control_algorithm": "PID", "control_algorithm_params": {}}
    r = c.post(f"/api/runs/{rid3}/execute", json=body, headers=H(T_OP))
    ok("R3", "an operator executes it (200)", r.status_code == 200, r.get_json())
    if enforce:
        ok("R4", "true: the body's algorithm is ignored, with an advisory",
           any("ignored" in w for w in (r.get_json() or {}).get("warnings", [])), r.get_json())
    st = wait_run(api, rid3)
    rr = run_row(rid3)
    ok("R3", "completed; created by the production manager, executed by the operator",
       st == "C" and rr["created_by_name"] == "test-pm" and rr["executed_by_name"] == "test-op", (st, log_of(api, rid3)[-600:]))
    rp = (cycles(rid3) or [{}])[0].get("rp") or [{}]
    want_algo = "IF_THEN_ELSE" if enforce else "PID"
    ok("R4", f"{mode}: the cycles ran {want_algo}", rp[0].get("control_algorithm") == want_algo, rp)
    end_open_runs()

    # R5 stop, R14 kill ─────────────────────────────────────────────────────────────
    def long_run():
        rj = c.post("/api/runs", json={"unit_id": i["u1"], "recipe_id": i["r1"]}, headers=H(T_PM)).get_json() or {}
        rlong = rj.get("recipe_run_id")
        rx = c.post(f"/api/runs/{rlong}/execute", json={}, headers=H(T_PM))
        started = wait_for(lambda: any(x["st"] == "R" for x in cycles(rlong)), 120)
        return rlong, rx, started

    rid5, rx, started = long_run()
    ok("R5", "a 2-hour run is executing (its first cycle R)", rx.status_code == 200 and started, (rx.get_json(), log_of(api, rid5)[-400:]))
    with api._active_pids_lock:
        pid5 = (api._active_pids.get(rid5) or {}).get("pid")
    r = c.post(f"/api/runs/{rid5}/stop", headers=H(T_PM))
    ok("R5", "stop answers 200 and marks it F at once", r.status_code == 200 and run_row(rid5)["recipe_run_status"] == "F", r.get_json())
    gone = wait_for(lambda: pid5 is None or not api._pid_alive(pid5), 60)
    time.sleep(2)
    ok("R5", "the runner exited and wrote nothing after the stop (cycle still R, run F)",
       gone and run_row(rid5)["recipe_run_status"] == "F" and [x["st"] for x in cycles(rid5)] == ["R"],
       (cycles(rid5), log_of(api, rid5)[-500:]))
    r = c.post(f"/api/runs/{rid5}/stop", headers=H(T_PM))
    ok("R5", "stop on F: 200, nothing to do", r.status_code == 200, r.get_json())
    end_open_runs()

    rid14, rx, started = long_run()
    with api._active_pids_lock:
        pid14 = (api._active_pids.get(rid14) or {}).get("pid")
    if started and pid14:
        os.kill(pid14, signal.SIGKILL)
        st = wait_run(api, rid14, 90)
        ch = changes("medcea.recipe_run", [rid14])
        ok("R14", "a runner killed with SIGKILL: the run ends F, as system:scheduler", st == "F"
           and ch and ch[-1]["actor_sub"] == "system:scheduler", (st, ch[-1:] if ch else ch))
    else:
        ok("R14", "the long run started", False, log_of(api, rid14)[-400:])
    end_open_runs()

    # R6 ───────────────────────────────────────────────────────────────────────────
    rid6 = (c.post("/api/runs", json={"unit_id": i["u1"], "recipe_id": i["r0"]}, headers=H(T_PM)).get_json() or {}).get("recipe_run_id")
    n0 = len(changes("medcea.recipe_run", [rid6]))
    r = c.patch(f"/api/runs/{rid6}/status", json={"status": "S"}, headers=H(T_PM))
    ok("R6", "PATCH S on a run in S: 200, nothing written", r.status_code == 200 and len(changes("medcea.recipe_run", [rid6])) == n0, r.get_json())
    c.post(f"/api/runs/{rid6}/stop", headers=H(T_PM))
    r = c.patch(f"/api/runs/{rid6}/status", json={"status": "S"}, headers=H(T_PM))
    ok("R6", "F -> S through set_run_status", r.status_code == 200 and run_row(rid6)["recipe_run_status"] == "S", r.get_json())
    end_open_runs()
    r = c.patch(f"/api/runs/{rid_flc}/status", json={"status": "S"}, headers=H(T_PM))   # completed in R2 (B1)
    if strict:
        ok("R6", f"{mode}: reopening a completed run is 409", r.status_code == 409, r.get_json())
    else:
        ok("R6", "false: reopening a completed run works, with an advisory",
           r.status_code == 200 and any("reopening" in w for w in (r.get_json() or {}).get("warnings", [])), r.get_json())
        end_open_runs()
    if rid:
        owner("""INSERT INTO medcea.run_release (recipe_run_id, row_hash, released_by_sub, released_by_person,
                                                  released_by_name, released_by_role, released_by_source)
                 SELECT %s, 'iam-runner', '44444444-4444-4444-8444-444444444444', 'p-qp', 'test-qp', 'qp', 'token'
                  WHERE NOT EXISTS (SELECT 1 FROM medcea.run_release WHERE recipe_run_id = %s)""", (rid, rid))
        r = c.patch(f"/api/runs/{rid}/status", json={"status": "S"}, headers=H(T_PM))
        ok("R6", "a released run is never reopened: 409", r.status_code == 409, r.get_json())

    # R7 ───────────────────────────────────────────────────────────────────────────
    r = c.delete(f"/api/schedules/{sid}", headers=H(T_PM))
    s = q("SELECT retired_at, enabled FROM medcea.schedule WHERE schedule_id = %s", (sid,), one=True)
    ok("R7", "DELETE retires: kept, retired, disabled", r.status_code == 200 and (r.get_json() or {}).get("retired") == sid
       and s and s["retired_at"] is not None and not s["enabled"], (r.get_json(), s))
    listed = {x["schedule_id"] for x in (c.get("/api/schedules", headers=H(T_PM)).get_json() or [])}
    ok("R7", "a retired schedule is not listed", sid not in listed)
    r = c.put(f"/api/schedules/{sid}", json={"unit_id": i["u1"], "recipe_id": i["r0"], "cron_expression": "0 4 * * *",
                                             "params_id": set_r0} if enforce else
              {"unit_id": i["u1"], "recipe_id": i["r0"], "cron_expression": "0 4 * * *"}, headers=H(T_PM))
    ok("R7", "PUT on a retired schedule: 409", r.status_code == 409, r.get_json())
    try:
        q("UPDATE medcea.schedule SET enabled = true, timestamp_upd = CURRENT_TIMESTAMP WHERE schedule_id = %s", (sid,))
        ok("R7", "the previous scheduler's PUT (direct UPDATE) on a retired schedule is refused", False, "accepted")
    except psycopg2.Error as e:
        ok("R7", "the previous scheduler's PUT (direct UPDATE) on a retired schedule is refused (42501)",
           e.pgcode == "42501" and "is retired" in str(e), str(e).splitlines()[0])
    r = c.delete(f"/api/schedules/{sid}", headers=H(T_PM))
    ok("R7", "DELETE again: 200, nothing written", r.status_code == 200, r.get_json())
    r = c.post(f"/api/schedules/{sid}/trigger", headers=H(T_OP))
    ok("R7", "a retired schedule is not triggered: 409", r.status_code == 409, r.get_json())

    # R8 ───────────────────────────────────────────────────────────────────────────
    if not strict and os.path.isfile("/work/prev/schd/run_recipe.py") and rid3:
        end_open_runs()
        prev_root = "/work/prev-run"
        shutil.rmtree(prev_root, ignore_errors=True)
        shutil.copytree("/work/prev/schd", os.path.join(prev_root, "schd"))
        env = {"PYTHONPATH": "/work/cur/tests/runner/stub",
               "CONTROL_ALGORITHM": "PID", "CONTROL_ALGORITHM_PARAMS": json.dumps({})}
        p, rid_old = run_legacy_cli(os.path.join(prev_root, "schd"), i, env)
        new_c = [(x["recipe_item_seq_id"], x["recipe_item_seq_cycle_num"], x["st"], json.dumps(x["rp"], sort_keys=True)) for x in cycles(rid3)]
        old_c = [(x["recipe_item_seq_id"], x["recipe_item_seq_cycle_num"], x["st"], json.dumps(x["rp"], sort_keys=True)) for x in cycles(rid_old)]
        ok("R8", "the previous commit's runner and this one: the same run (status, cycles, run_params)",
           p.returncode == 0 and run_row(rid_old)["recipe_run_status"] == run_row(rid3)["recipe_run_status"] == "C"
           and old_c == new_c, {"rc": p.returncode, "old": old_c, "new": new_c, "stderr": p.stderr[-300:]})
        old_actors = {x["actor_sub"] for x in changes("medcea.recipe_run", [rid_old])}
        new_actors = {x["actor_sub"] for x in changes("medcea.recipe_run", [rid3])}
        note("R8", f"expected differences — run actors: previous {sorted(old_actors)}, now {sorted(new_actors)}; "
                   "executed_by is set only by start_run")
        end_open_runs()
    elif svc and not enforce:
        note("R8", "false-svc: the previous commit's runner writes recipe_run directly, which svc_scheduler may not: skipped")
    elif not enforce:
        note("R8", "no previous schd/ (--prev-schd) or no R3 run: skipped")

    # R9 ───────────────────────────────────────────────────────────────────────────
    r = new_schedule(T_PM)
    sid9 = (r.get_json() or {}).get("schedule_id")
    conn = su()
    try:
        cur = conn.cursor()
        cur.execute("SET LOCAL session_replication_role = replica")
        cur.execute("""UPDATE medcea.schedule SET created_by_sub = 'migration:008', created_by_person = NULL,
                         created_by_name = 'migration:008', created_by_role = NULL, created_by_source = 'migration',
                         updated_by_sub = 'migration:008', updated_by_person = NULL, updated_by_name = 'migration:008',
                         updated_by_role = NULL, updated_by_source = 'migration' WHERE schedule_id = %s""", (sid9,))
        conn.commit()
    finally:
        conn.close()

    def fires(s_id):
        conn2 = su()
        try:
            conn2.cursor().execute("SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', %s)", (s_id,))
            return True
        except psycopg2.Error:
            return False
        finally:
            conn2.rollback()
            conn2.close()

    ok("R9", "a migration:008 schedule has no person to fire as", not fires(sid9))
    r = c.post(f"/api/schedules/{sid9}/trigger", headers=H(T_OP))
    if svc:
        # only a superuser had the internal-actor fallback (_set_internal_actor)
        ok("R9", f"{mode}: triggering it is refused (403)", r.status_code == 403, r.get_json())
    else:
        ok("R9", "false: it is triggered (the run is stamped db:postgres)", r.status_code == 200, r.get_json())
        rid9 = (r.get_json() or {}).get("run_id")
        if rid9:
            wait_run(api, rid9)
            ok("R9", "false: the run's creator is db:postgres", run_row(rid9)["created_by_sub"] == "db:postgres", run_row(rid9)["created_by_sub"])
        end_open_runs()
        body = {"unit_id": i["u1"], "recipe_id": i["r0"], "cron_expression": "0 3 1 1 *", "description": "iamtest r9 re-saved"}
        r = c.put(f"/api/schedules/{sid9}", json=body)            # no token
        ok("R9", "false: a re-save without a person (db:postgres) still leaves no one to fire as",
           r.status_code == 200 and not fires(sid9), r.get_json())
    body = {"unit_id": i["u1"], "recipe_id": i["r0"], "cron_expression": "0 3 1 1 *", "description": "iamtest r9 pm"}
    if enforce:
        body["params_id"] = set_r0
    r = c.put(f"/api/schedules/{sid9}", json=body, headers=H(T_PM))
    ok("R9", "a production manager re-saves it: it fires as that person", r.status_code == 200 and fires(sid9), r.get_json())

    # R10 ──────────────────────────────────────────────────────────────────────────
    end_open_runs()
    n_before = q("SELECT count(*) AS n FROM medcea.recipe_run WHERE schedule_id = %s", (sid9,), one=True)["n"]
    api._schedule_trigger_job(sid9)
    rid10 = q("SELECT max(recipe_run_id) AS v FROM medcea.recipe_run WHERE schedule_id = %s", (sid9,), one=True)["v"]
    made = q("SELECT count(*) AS n FROM medcea.recipe_run WHERE schedule_id = %s", (sid9,), one=True)["n"] == n_before + 1
    ok("R10", "the cron path creates a run", made)
    if made:
        st = wait_run(api, rid10)
        rr = run_row(rid10)
        ok("R10", "completed, created and executed as system:scheduler for the re-saving production manager",
           st == "C" and rr["created_by_person"] == "p-pm" and rr["executed_by_source"] == "system", (st, rr["executed_by_source"]))
    owner("UPDATE medcea.schedule SET enabled = false WHERE schedule_id = %s", (sid9,))
    api._schedule_trigger_job(sid9)
    ok("R10", "a disabled schedule fires nothing",
       q("SELECT count(*) AS n FROM medcea.recipe_run WHERE schedule_id = %s", (sid9,), one=True)["n"] == n_before + (1 if made else 0))
    api._schedule_trigger_job(sid)      # retired in R7
    ok("R10", "a retired schedule fires nothing",
       q("SELECT count(*) AS n FROM medcea.recipe_run WHERE schedule_id = %s AND recipe_run_id > %s", (sid, rid or 0), one=True)["n"] == 0)
    end_open_runs()

    # R11 ──────────────────────────────────────────────────────────────────────────
    before = {x["key"]: x["value"] for x in q("SELECT key, value FROM medcea.scheduler_config")}
    want = {"compress_days": 6, "delete_days": int(before.get("log_delete_days", 30)) + 1}
    r = c.put("/api/config/logs", json=want, headers=H(T_LOG))
    after = {x["key"]: x["value"] for x in q("SELECT key, value FROM medcea.scheduler_config")}
    if strict:
        d = r.get_json() or {}
        ok("R11", f"{mode}: a proposal for qa, 202 with its change ids", r.status_code == 202 and d.get("pending") and d.get("change_ids"), d)
        ok("R11", f"{mode}: nothing applied yet", after == before, (before, after))
    else:
        ok("R11", "false: saved at once", r.status_code == 200 and after.get("log_compress_days") == "6", (r.get_json(), after))
        s = q("SELECT updated_by_name FROM medcea.scheduler_config WHERE key = 'log_compress_days'", one=True)
        ok("R11", "false: stamped with the person", s and s["updated_by_name"] == "test-log", s)

    # R12 ──────────────────────────────────────────────────────────────────────────
    r = c.post("/api/runs", json={"unit_id": i["u1"], "recipe_id": i["r0"]})
    if enforce:
        ok("R12", "true: a request without a person is 401", r.status_code == 401, r.get_json())
    else:
        rid12 = (r.get_json() or {}).get("recipe_run_id")
        ok("R12", f"{mode}: accepted and stamped db:{who}", r.status_code == 201 and rid12
           and run_row(rid12)["created_by_sub"] == f"db:{who}", r.get_json())
    end_open_runs()

    # R17 ──────────────────────────────────────────────────────────────────────────
    # The route check runs report-only here (settings.json enforce false), as before
    # 2.6; under IAM_DB_ROLES=true the scheduler still never acts for a refused person.
    platform = set(routes.get("roles", []))
    runs_roles = set(routes["services"]["scheduler"]["routes"]["POST /api/runs"]["roles"])
    no_run = sorted(platform - runs_roles, key=lambda r: (r != "auditor", r))
    del_roles = set(routes["services"]["scheduler"]["routes"]["DELETE /api/schedules/<id>"]["roles"])
    if not no_run or "operator" in del_roles:
        ok("R17", "the policy has a role without C on runs and operator lacks U on schedules", False, (no_run, del_roles))
    else:
        T_NO = tok([no_run[0]], "88888888-8888-4888-8888-888888888888", "p-no", "test-no")
        n0 = q("SELECT count(*) AS n FROM medcea.recipe_run", one=True)["n"]
        r = c.post("/api/runs", json={"unit_id": i["u1"], "recipe_id": i["r0"]}, headers=H(T_NO))
        n1 = q("SELECT count(*) AS n FROM medcea.recipe_run", one=True)["n"]
        if enforce:
            ok("R17", f"true: {no_run[0]} on POST /api/runs is 403 and writes no run", r.status_code == 403 and n1 == n0,
               (r.status_code, r.get_json(), n1 - n0))
        else:
            rid17 = (r.get_json() or {}).get("recipe_run_id")
            ok("R17", f"false: {no_run[0]} on POST /api/runs goes on (report-only), attributed to that person",
               r.status_code == 201 and rid17 and run_row(rid17)["created_by_name"] == "test-no", r.get_json())
        end_open_runs()
        r = new_schedule(T_PM)
        sid17 = (r.get_json() or {}).get("schedule_id")
        r = c.delete(f"/api/schedules/{sid17}", headers=H(T_OP))
        ret = (q("SELECT retired_at FROM medcea.schedule WHERE schedule_id = %s", (sid17,), one=True) or {}).get("retired_at")
        if enforce:
            ok("R17", "true: an operator's DELETE /api/schedules is 403 and the schedule stays", r.status_code == 403 and ret is None,
               (r.status_code, r.get_json(), ret))
            owner("UPDATE medcea.schedule SET enabled = false WHERE schedule_id = %s", (sid17,))
        else:
            ok("R17", "false: an operator's DELETE retires it (report-only, the database's refusal an advisory)",
               r.status_code == 200 and ret is not None, (r.status_code, r.get_json()))

    # R13 ──────────────────────────────────────────────────────────────────────────
    aid = q("SELECT algorithm_id FROM medcea.control_algorithm WHERE algorithm_code = 'IAMT_ALGO'", one=True)
    if not aid:
        aid = owner("""INSERT INTO medcea.control_algorithm (algorithm_code, algorithm_name, description, default_params, is_active, status)
                       VALUES ('IAMT_ALGO', 'iam-runner algorithm', 'tests/iam-runner.sh', '{"k": 1}', 'N', 'approved')
                       RETURNING algorithm_id""")[0]
    owner("UPDATE medcea.control_algorithm SET status = 'approved' WHERE algorithm_id = %s AND status = 'draft'", (aid["algorithm_id"],))
    r = c.put(f"/api/algorithms/{aid['algorithm_id']}", json={"default_params": {"k": int(time.time()) % 1000}}, headers=H(T_ALG))
    d = r.get_json() or {}
    if enforce:
        ok("R13", "true: editing an approved algorithm is 409 (draft_only)", r.status_code == 409 and "draft_only" in d.get("error", ""), d)
    else:
        ok("R13", "false: saved, demoted to draft, with an advisory (not an error)",
           r.status_code == 200 and d.get("status") == "draft" and any("draft" in w for w in d.get("warnings", [])), d)
        a13 = q("SELECT updated_by_name, updated_by_source FROM medcea.control_algorithm WHERE algorithm_id = %s",
                (aid["algorithm_id"],), one=True) or {}
        ok("R13", "false: the token in X-Forwarded-Access-Token made the person the actor (R16's scheduler half)",
           a13.get("updated_by_name") == "test-alg" and a13.get("updated_by_source") == f"person via {who}", a13)

    # R15 ──────────────────────────────────────────────────────────────────────────
    lib = api._medcea_iam()
    saved = getattr(lib, "actor_role", None)
    try:
        if saved is not None:
            delattr(lib, "actor_role")
        r = c.post("/api/runs", json={"unit_id": i["u1"], "recipe_id": i["r0"]}, headers=H(T_PM))
        if enforce:
            ok("R15", "old library, composite token (two roles): no person, 401", r.status_code == 401, r.get_json())
        else:
            rid15 = (r.get_json() or {}).get("recipe_run_id")
            ok("R15", f"old library, composite token (two roles): no person, stamped db:{who}",
               r.status_code == 201 and run_row(rid15)["created_by_sub"] == f"db:{who}", r.get_json())
        end_open_runs()
        r = c.post("/api/runs", json={"unit_id": i["u1"], "recipe_id": i["r0"]}, headers=H(T_PM1))
        rid15 = (r.get_json() or {}).get("recipe_run_id")
        ok("R15", "old library, one role: the person", r.status_code == 201 and run_row(rid15)["created_by_name"] == "test-pm", r.get_json())
    finally:
        if saved is not None:
            lib.actor_role = saved
    end_open_runs()

    # the new runner's command-line path with 008b: works while false, refused while true
    p, rid_cli = run_legacy_cli("/schd", i, svc=svc)
    if strict:
        ok("legacy", f"{mode}: run_recipe.py without RECIPE_RUN_ID refuses", p.returncode == 1 and "Refused" in p.stderr, p.stderr[-300:])
    else:
        ok("legacy", "false: run_recipe.py without RECIPE_RUN_ID still completes a run", p.returncode == 0
           and run_row(rid_cli)["recipe_run_status"] == "C", p.stderr[-300:])
    end_open_runs()

    note("R16", "the nginx half runs in tests/iam-postgrest.sh (R16); the scheduler half is R13 above")


if __name__ == "__main__":
    try:
        main()
    finally:
        try:
            end_open_runs()
        except Exception as e:  # noqa: BLE001
            print(f"  NOTE  cleanup  {type(e).__name__}", flush=True)
    print(f"\niam-runner: {PASSES} passed, {FAILS} failed")
    sys.exit(1 if FAILS else 0)
