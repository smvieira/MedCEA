#!/usr/bin/env python3
"""Offline tests of own_unit on the Monitor's and the scheduler's reads (IAM 2.6):
an operator's run, cycle, log and telemetry reads carry the iam_policy.user_unit
subquery with their sub as a parameter while IAM_ENFORCE or IAM_DB_ROLES is true;
everyone else, and an operator in report-only mode, runs the unscoped SQL unchanged.
GET /api/runs/<id> leaves out the log for a role without R on run_logs while
IAM_ENFORCE is true.

No cluster, no database, no Flask: flask, psycopg2 and apscheduler are stubs, every
statement goes to a fake connection that records it, and the real medcea_iam library
runs against the compiled route table with verify() replaced (the token is its claims).

    python3 tests/test_unit_scope.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='test-unit-scope-')
sys.path.insert(0, os.path.join(REPO, 'apps', 'iam'))
from compiler import model, routes                                  # noqa: E402

with open(os.path.join(TMP, 'routes.json'), 'w') as fh:
    fh.write(routes.dumps(routes.compile(model.load())))
with open(os.path.join(TMP, 'settings.json'), 'w') as fh:
    json.dump({'issuer': 'https://kc.test/realms/medcea', 'audience': 'medcea-api', 'enforce': False}, fh)
os.environ.update(MEDCEA_IAM_ROUTES=os.path.join(TMP, 'routes.json'), MEDCEA_IAM_SETTINGS=os.path.join(TMP, 'settings.json'),
                  MEDCEA_IAM_JWKS=os.path.join(TMP, 'jwks.json'), LOG_DIR=TMP)


# ── stubs ───────────────────────────────────────────────────────────────────────────
class _Args(dict):
    def get(self, key, default=None, type=None):
        return type(self[key]) if key in self and type else super().get(key, default)


REQ = types.SimpleNamespace(method='GET', path='/', args=_Args(), headers={})
G = types.SimpleNamespace()


class _Flask:
    def __init__(self, *a, **k):
        pass

    def route(self, *a, **k):
        return lambda f: f
    before_request = after_request = staticmethod(lambda f: f)

    def errorhandler(self, *a):
        return lambda f: f


def _jsonify(*a, **k):
    return a[0] if a else k


def _module(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


_module('flask', Flask=_Flask, jsonify=_jsonify, request=REQ, g=G, has_request_context=lambda: True)
_module('psycopg2', connect=None, Error=type('Error', (Exception,), {}))
sys.modules['psycopg2'].extras = _module('psycopg2.extras', RealDictCursor=object)
_module('apscheduler')
_module('apscheduler.schedulers')
_module('apscheduler.schedulers.background', BackgroundScheduler=lambda **k: None)
_module('apscheduler.triggers')
_module('apscheduler.triggers.cron', CronTrigger=object)
_module('apscheduler.triggers.date', DateTrigger=object)


class DB:
    """Every statement (sql, params); medcea.iam_db_roles is DB.db_roles; a run lookup
    finds one run."""
    log, db_roles, connects = [], False, 0

    class Cursor:
        def execute(self, sql, params=None):
            DB.log.append((sql, params))
            self._sql = sql

        def fetchone(self):
            if 'medcea.iam_db_roles' in self._sql:
                return {'v': DB.db_roles}
            if 'recipe_run_start' in self._sql:
                return {'recipe_run_id': 7, 'recipe_run_start': None, 'recipe_run_end': None,
                        'unit_code': 'U1', 'recipe_name': 'R'}
            return None

        def fetchall(self):
            return []

    class Conn:
        notices = []

        def cursor(self, **k):
            return DB.Cursor()

        def commit(self):
            pass

        def close(self):
            pass

    @staticmethod
    def connect(*a, **k):
        DB.connects += 1
        return DB.Conn()


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LIB = _load('medcea_iam', os.path.join(REPO, 'apps', 'iam', 'lib', 'medcea_iam.py'))
LIB.verify = lambda token, clients: (json.loads(token), None)
ENFORCE = {'v': False}
LIB.enforcing = lambda: ENFORCE['v']
sys.path.insert(0, os.path.join(REPO, 'apps', 'scheduler'))
MON = _load('monitor_api', os.path.join(REPO, 'apps', 'monitor', 'monitor-api.py'))
SCH = _load('scheduler_api', os.path.join(REPO, 'apps', 'scheduler', 'scheduler-api.py'))
for api in (MON, SCH):
    api._medcea_iam = lambda: LIB
    api.get_db = DB.connect

UID = '11111111-1111-4111-8111-111111111111'
MON_CALLS = [('/api/runs', lambda: MON.get_runs()), ('/api/run/7', lambda: MON.get_run(7)),
             ('/api/measurements/U1', lambda: MON.get_measurements('U1')),
             ('/api/actions/U1', lambda: MON.get_actions('U1'))]
SCH_CALLS = [('/api/runs/active', lambda: SCH.list_active_runs()), ('/api/runs', lambda: SCH.list_runs()),
             ('/api/runs/7', lambda: SCH.get_run(7)), ('/api/runs/7/cycles', lambda: SCH.get_run_cycles(7)),
             ('/api/runs/7/log', lambda: SCH.get_run_log(7))]


def call(service, path, fn, roles, sub=UID, user='tester'):
    """The route's statements (the iam_db_roles reading left out) and its answer."""
    REQ.method, REQ.path, REQ.args = 'GET', path, _Args()
    claims = {'sub': sub, 'preferred_username': user, 'person_id': 'p', 'groups': roles, 'azp': service}
    G.medcea_iam = LIB.check(service, 'GET', path, {'X-Forwarded-Access-Token': json.dumps(claims)})
    DB.log = []
    out = fn()
    return [s for s in DB.log if 'medcea.iam_db_roles' not in s[0]], out


class UnitScopeTest(unittest.TestCase):
    def setUp(self):
        ENFORCE['v'], DB.db_roles = False, False
        MON._REPORTED.clear()
        SCH._REPORTED.clear()
        SCH._DB_ROLES.update(at=0.0, v=False)

    def stmts(self, roles, sub=UID):
        return {p: call(svc, p, fn, roles, sub)[0][-1]
                for svc, calls in (('monitor', MON_CALLS), ('scheduler', SCH_CALLS)) for p, fn in calls}

    def assertScoped(self, got, sub):
        for path, (sql, params) in got.items():
            self.assertIn('WHERE uu.person_sub = %s::uuid)', sql, path)
            self.assertIn(sub, params, path)

    def assertUnscoped(self, got):
        for path, (sql, params) in got.items():
            self.assertNotIn('user_unit', sql, path)
            self.assertNotIn(UID, params or (), path)

    def test_operator_scoped_under_either_switch(self):
        ENFORCE['v'] = True
        self.assertScoped(self.stmts(['operator']), UID)
        ENFORCE['v'], DB.db_roles = False, True
        self.assertScoped(self.stmts(['operator']), UID)

    def test_scope_only_adds_the_clause(self):
        # the unscoped statement is the scoped one without the subquery: nothing else moves
        plain = self.stmts(['operator'])
        ENFORCE['v'] = True
        scoped = self.stmts(['operator'])
        for path in ('/api/runs', '/api/run/7', '/api/runs/active', '/api/runs/7', '/api/runs/7/cycles', '/api/runs/7/log'):
            sql, params = scoped[path]
            end = sql.index(MON._MY_UNITS)
            start = sql.rindex('AND ', 0, end)
            end += len(MON._MY_UNITS)
            end += sql[end:].index(')') + 1 if path.endswith('/cycles') else 0
            cut = sql[:start].rstrip(' ') + sql[end:].lstrip('\n')
            self.assertEqual(' '.join(cut.split()), ' '.join(plain[path][0].split()), path)
            self.assertEqual([p for p in params if p != UID], list(plain[path][1] or ()), path)
        for path, view in (('/api/measurements/U1', 'v_ap_measurements'), ('/api/actions/U1', 'v_ct_measurements')):
            self.assertIn(view, plain[path][0])
            self.assertIn('m.zone_id IN ' + MON._MY_ZONES, scoped[path][0])
            self.assertEqual(scoped[path][1], ('U1', UID))
        self.assertEqual(scoped['/api/runs'][1], (UID, 50))       # the scope comes before LIMIT

    def test_report_only_logs_once(self):
        with self.assertLogs(MON.log, 'INFO') as cm:
            self.assertUnscoped({'/api/runs': call('monitor', '/api/runs', MON.get_runs, ['operator'])[0][-1]})
            call('monitor', '/api/runs', MON.get_runs, ['operator'])
        self.assertEqual(sum('own_unit: would limit' in m for m in cm.output), 1, cm.output)
        self.assertFalse([m for m in cm.output if 'would refuse' in m])
        with self.assertLogs(SCH.log, 'INFO') as cm:
            self.assertUnscoped({p: call('scheduler', p, fn, ['operator'])[0][-1] for p, fn in SCH_CALLS})
        self.assertEqual(sum('own_unit: would limit' in m for m in cm.output), 5, cm.output)

    def test_scheduler_reads_iam_db_roles_once_per_30s(self):
        DB.connects = 0
        for p, fn in SCH_CALLS:
            call('scheduler', p, fn, ['operator'])
        self.assertEqual(DB.connects, len(SCH_CALLS) + 1)

    def test_not_limited(self):
        ENFORCE['v'], DB.db_roles = True, True
        for roles in (['production_manager', 'operator'], ['qa'], ['engineer'], ['admin']):  # admin: refused
            self.assertUnscoped(self.stmts(roles))

    def test_fail_closed(self):
        ENFORCE['v'] = True
        self.assertScoped(self.stmts(['operator'], sub='u-1'), LIB.NIL_SUB)   # no account uuid
        saved = LIB.own_unit_sub
        try:
            del LIB.own_unit_sub                                                # a library from before 2.6
            self.assertScoped(self.stmts(['operator']), LIB.NIL_SUB)
        finally:
            LIB.own_unit_sub = saved

    def test_log_withheld_without_run_logs(self):
        def run(roles):
            return call('scheduler', '/api/runs/7', lambda: SCH.get_run(7), roles)[1]
        ENFORCE['v'] = True
        for role in ('qc', 'qp', 'maintenance'):
            r = run([role])
            self.assertEqual((r['log'], r['log_withheld']), (None, 'run_logs'), role)
        for roles in (['operator'], ['qa'], ['production_manager', 'operator']):
            self.assertIsNotNone(run(roles)['log'], roles)
            self.assertNotIn('log_withheld', run(roles))
        ENFORCE['v'] = False
        with self.assertLogs(SCH.log, 'INFO') as cm:
            r = run(['qc'])
        self.assertIsNotNone(r['log'])
        self.assertTrue(any('run_logs: would withhold' in m for m in cm.output), cm.output)


if __name__ == '__main__':
    unittest.main()
