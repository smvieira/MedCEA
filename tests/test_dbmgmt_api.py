#!/usr/bin/env python3
"""Offline tests of apps/frontend/html/dbmgmt-api.py (IAM 2.6): Database Management lists
and exports exactly the medcea members of the person's X groups, refuses whatever
IAM_ENFORCE says, and logs every export to iam_policy.export_log before it commits.

No cluster, no database: connect() is a fake connection that records every statement,
commit and rollback, and the real medcea_iam library runs against the compiled route
table with its _check() replaced by a scripted Decision (no PyJWT). Requests go to the
real Handler on a loopback HTTPServer.

    python3 tests/test_dbmgmt_api.py
"""
import datetime
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import HTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='test-dbmgmt-api-')
sys.path.insert(0, os.path.join(REPO, 'apps', 'iam'))
from compiler import model, routes                                  # noqa: E402

DOC = routes.compile(model.load())
with open(os.path.join(TMP, 'routes.json'), 'w') as fh:
    fh.write(routes.dumps(DOC))
OLD = dict(DOC)
OLD.pop('exports')
with open(os.path.join(TMP, 'routes-pre-2.6.json'), 'w') as fh:
    json.dump(OLD, fh)
with open(os.path.join(TMP, 'settings.json'), 'w') as fh:
    json.dump({'issuer': 'https://kc.test/realms/medcea', 'audience': 'medcea-api', 'enforce': False}, fh)
os.environ.update(MEDCEA_IAM_ROUTES=os.path.join(TMP, 'routes.json'), MEDCEA_IAM_SETTINGS=os.path.join(TMP, 'settings.json'),
                  MEDCEA_IAM_JWKS=os.path.join(TMP, 'jwks.json'), IAM_ENFORCE='false')


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LIB = _load('medcea_iam', os.path.join(REPO, 'apps', 'iam', 'lib', 'medcea_iam.py'))
API = _load('dbmgmt_api', os.path.join(REPO, 'apps', 'frontend', 'html', 'dbmgmt-api.py'))

SUB = 'bbbbbbbb-0000-4000-8000-000000000001'
QP = {'sub': SUB, 'person_id': 'pQ', 'username': 'quentin', 'roles': ['qp'], 'azp': 'dbmgmt'}
AUDITOR = dict(QP, username='audrey', roles=['auditor'])
SEQ = 'recipe_run_recipe_run_id_seq'

# the catalog the fake database shows svc_dbexport (schema, name, type)
CATALOG = [('medcea', 'measurement', 'table'), ('medcea', 'recipe', 'table'), ('iam', 'access_request', 'table'),
           ('iam_policy', 'export_log', 'table'), ('medcea', 'v_ap_measurements', 'view'),
           ('medcea', SEQ, 'sequence'), ('medcea', 'unit_state', 'enum')]
ROWS = [(1, {'a': "it's"}, ['R', 'X'], uuid.UUID(SUB)), (2, None, None, None)]
DESCRIPTION = [('id', 23), ('msg', 3802), ('levels', 1009), ('who', 2950)]


# ── fakes ────────────────────────────────────────────────────────────────────
class World:
    def __init__(self):
        self.events, self.log_error, self.on_commit = [], None, None

    def connect(self):
        return FakeConn(self)

    def sql(self):
        return [e[1] for e in self.events if e[0] == 'sql']


class FakeConn:
    def __init__(self, w):
        self.w = w

    def cursor(self):
        return FakeCur(self.w)

    def commit(self):
        if self.w.on_commit:
            self.w.on_commit()
        self.w.events.append(('commit',))

    def rollback(self):
        self.w.events.append(('rollback',))

    def close(self):
        self.w.events.append(('close',))


class FakeCur:
    def __init__(self, w):
        self.w, self.rows, self.description = w, [], None

    def execute(self, sql, params=None):
        self.w.events.append(('sql', sql, params))
        self.rows, self.description = [], None
        if 'information_schema.tables' in sql:
            schemas = params[0]
            self.rows = [r for r in CATALOG if r[0] in schemas]
        elif sql.startswith('SELECT * FROM'):
            self.rows, self.description = list(ROWS), [d + (None,) * 5 for d in DESCRIPTION]
        elif 'iam_policy.log_export' in sql:
            if self.w.log_error:
                raise self.w.log_error
            self.rows = [(41,)]
        elif 'medcea_auth.set_actor' in sql:
            self.rows = [('',)]

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None


class DbmgmtTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), API.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = 'http://127.0.0.1:%d' % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.w = World()
        self.decision = LIB.Decision(True, 200, 'allowed', dict(QP))
        self.orig = dict(_check=LIB._check, routes=LIB.ROUTES_FILE, connect=API.connect,
                         iam=API._medcea_iam, export_dir=API.EXPORT_DIR)
        LIB._check = lambda service, method, path, headers: self.decision
        API.connect = self.w.connect
        API._medcea_iam = lambda: LIB
        API.EXPORT_DIR = tempfile.mkdtemp(dir=TMP)

    def tearDown(self):
        LIB._check, LIB.ROUTES_FILE = self.orig['_check'], self.orig['routes']
        API.connect, API._medcea_iam, API.EXPORT_DIR = self.orig['connect'], self.orig['iam'], self.orig['export_dir']

    def req(self, method, path, body=None, ctype='application/json', raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        r = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            r.add_header('Content-Type', ctype)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.headers, e.read()

    def export(self, selections, target='local', **kw):
        return self.req('POST', '/export', dict({'selections': selections, 'filename': 'x.sql', 'target': target}, **kw))

    def objects(self):
        code, _, body = self.req('GET', '/objects')
        self.assertEqual(code, 200, body)
        return json.loads(body)

    # ── listing ──────────────────────────────────────────────────────────────
    def test_e1_qp_lists_only_its_x_groups(self):
        j = self.objects()
        self.assertEqual(j['groups'], ['audit_histories', 'measurements', 'runs'])
        got = {(o['schema'], o['name']): o['group'] for o in j['objects']}
        self.assertEqual(got, {('medcea', 'measurement'): 'measurements', ('medcea', 'v_ap_measurements'): 'measurements',
                               ('medcea', SEQ): None, ('medcea', 'unit_state'): None})
        self.assertIn(('close',), self.w.events)

    def test_e2_auditor_lists_every_medcea_object(self):
        self.decision = LIB.Decision(True, 200, 'allowed', dict(AUDITOR))
        j = self.objects()
        self.assertEqual({(o['schema'], o['name']) for o in j['objects']},
                         {(s, n) for s, n, _ in CATALOG if s == 'medcea'})
        # medcea only (SCHEMAS): the catalog is never asked for iam or iam_policy
        self.assertEqual(self.w.events[0][2][0], ['medcea'])
        self.assertNotIn('iam_users', j['groups'])

    # ── export ───────────────────────────────────────────────────────────────
    def test_e3_out_of_group_object_refuses_the_whole_export(self):
        code, _, body = self.export([{'schema': 'medcea', 'name': 'measurement', 'type': 'table', 'ddl': True},
                                     {'schema': 'medcea', 'name': 'recipe', 'type': 'table', 'ddl': True}])
        self.assertEqual(code, 403)
        self.assertIn('not in your export groups: table medcea.recipe', json.loads(body)['error'])
        self.assertFalse([s for s in self.w.sql() if 'log_export' in s])
        self.assertNotIn(('commit',), self.w.events)
        self.assertIn(('rollback',), self.w.events)
        self.assertEqual(os.listdir(API.EXPORT_DIR), [])

    def test_e4_logged_then_committed_then_sent(self):
        code, hdr, body = self.export([{'schema': 'medcea', 'name': 'measurement', 'type': 'table', 'ddl': True, 'data': True},
                                       {'schema': 'medcea', 'name': SEQ, 'type': 'sequence', 'ddl': True, 'data': True}])
        self.assertEqual(code, 200, body)
        sql = self.w.sql()
        self.assertEqual(sql[0], 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        self.assertIn('medcea_auth.set_actor', sql[1])
        self.assertEqual(self.w.events[1][2], (SUB, 'pQ', 'quentin', 'qp'))
        log = [e for e in self.w.events if e[0] == 'sql' and 'log_export' in e[1]]
        self.assertEqual(len(log), 1)
        self.assertIn('%s::text[]', log[0][1])
        self.assertEqual(log[0][2], (['measurements'], ['medcea.measurement:table:ddl,data=2', f'medcea.{SEQ}:sequence:ddl']))
        i_log, i_commit = self.w.events.index(log[0]), self.w.events.index(('commit',))
        self.assertLess(self.w.events.index(next(e for e in self.w.events if e[0] == 'sql' and e[1].startswith('SELECT * FROM'))), i_log)
        self.assertLess(i_log, i_commit)
        self.assertTrue(body.startswith(b'-- medcea_db export #41 (iam_policy.export_log)\n'))
        self.assertIn(b'-- Exported by: quentin (qp)\n-- Groups: measurements\n', body)
        self.assertEqual(hdr['X-Medcea-Export-Id'], '41')
        self.assertEqual(hdr['X-Medcea-Export-Sha256'], hashlib.sha256(body).hexdigest())
        # json, arrays and uuid serialise as SQL, not Python repr
        self.assertIn(b"""VALUES (1, '{"a": "it''s"}', '{"R","X"}', '""" + SUB.encode() + b"');", body)
        self.assertIn(b'VALUES (2, NULL, NULL, NULL);', body)
        self.assertIn(b'SELECT * FROM "medcea"."measurement"', ''.join(sql).encode())

    def test_e4b_sequence_only_logs_no_group(self):
        code, _, body = self.export([{'schema': 'medcea', 'name': SEQ, 'type': 'sequence', 'ddl': True}])
        self.assertEqual(code, 200, body)
        log = [e for e in self.w.events if e[0] == 'sql' and 'log_export' in e[1]]
        self.assertEqual(log[0][2], ([], [f'medcea.{SEQ}:sequence:ddl']))
        self.assertIn(b'-- Groups: none\n', body)

    def test_e5_failed_log_rolls_back_and_sends_nothing(self):
        self.w.log_error = RuntimeError('log_export: no actor')
        code, _, body = self.export([{'schema': 'medcea', 'name': 'measurement', 'type': 'table', 'data': True}], target='platform')
        self.assertEqual(code, 500)
        self.assertEqual(json.loads(body), {'error': 'export failed: database error'})
        self.assertIn(('rollback',), self.w.events)
        self.assertNotIn(('commit',), self.w.events)
        self.assertEqual(os.listdir(API.EXPORT_DIR), [])

    def test_e6_no_person_no_sql(self):
        self.decision = LIB.Decision(True, 200, 'allowed', dict(QP, sub='not-a-uuid'))
        code, _, body = self.req('GET', '/objects')
        self.assertEqual(code, 401, body)
        self.decision = LIB.Decision(True, 200, 'allowed', dict(QP, roles=['qa', 'qp']))
        code, _, body = self.export([{'name': 'measurement', 'type': 'table', 'ddl': True}])
        self.assertEqual(code, 403)
        self.assertIn('no single own platform role', json.loads(body)['error'])
        self.assertEqual(self.w.events, [])

    def test_e7_refused_whatever_iam_enforce_says(self):
        self.assertFalse(LIB.enforcing())
        self.decision = LIB.Decision(False, 403, "roles ['operator'] do not hold X on db_export",
                                     dict(QP, roles=['operator']))
        for method, path, body in (('GET', '/objects', None), ('POST', '/export', {'selections': []})):
            code, _, out = self.req(method, path, body)
            self.assertEqual(code, 403, path)
            self.assertIn('do not hold X', json.loads(out)['error'])
        self.assertEqual(self.w.events, [])

    def test_e7b_no_library_is_503(self):
        API._medcea_iam = lambda: None
        code, _, _ = self.req('GET', '/objects')
        self.assertEqual(code, 503)
        self.assertEqual(self.w.events, [])

    def test_e8_input_checks(self):
        sel = [{'name': 'measurement', 'type': 'table', 'ddl': True}]
        self.assertEqual(self.req('POST', '/export', {'selections': sel}, ctype='text/plain')[0], 415)
        self.assertEqual(self.req('POST', '/export', raw=b'{not json')[0], 400)
        self.assertEqual(self.export([])[0], 400)
        self.assertEqual(self.export([{'name': 'measurement', 'type': 'table'}])[0], 400)   # selects nothing
        self.assertEqual(self.export([{'name': 7, 'type': 'table', 'ddl': True}])[0], 400)
        self.assertEqual(self.export(sel, target='x')[0], 400)
        self.assertEqual(self.req('POST', '/export', ['a'])[0], 400)
        self.assertFalse([s for s in self.w.sql() if 'log_export' in s])

    def test_e9_route_table_before_2_6_is_503(self):
        LIB.ROUTES_FILE = os.path.join(TMP, 'routes-pre-2.6.json')
        for method, path, body in (('GET', '/objects', None),
                                   ('POST', '/export', {'selections': [{'name': 'measurement', 'type': 'table', 'ddl': True}]})):
            code, _, out = self.req(method, path, body)
            self.assertEqual(code, 503, path)
            self.assertIn('run ./deploy-infra.sh', json.loads(out)['error'])
        self.assertEqual(self.w.events, [])

    def test_e10_injection_shaped_name_is_refused(self):
        bad = 'measurement" ; DROP'
        code, _, body = self.export([{'schema': 'medcea', 'name': bad, 'type': 'table', 'ddl': True, 'data': True}])
        self.assertEqual(code, 403)
        self.assertIn('medcea.measurement? ? DROP', json.loads(body)['error'])
        self.assertFalse([s for s in self.w.sql() if 'DROP' in s])
        for e in self.w.events:
            self.assertNotIn(bad, repr(e[2:]))

    def test_e11_selection_without_schema_means_medcea(self):
        code, _, body = self.export([{'name': 'measurement', 'type': 'table', 'ddl': True}])
        self.assertEqual(code, 200, body)
        log = [e for e in self.w.events if e[0] == 'sql' and 'log_export' in e[1]]
        self.assertEqual(log[0][2][1], ['medcea.measurement:table:ddl'])

    def test_e12_platform_file_written_after_commit(self):
        path = os.path.join(API.EXPORT_DIR, 'x.sql')
        self.w.on_commit = lambda: self.assertFalse(os.path.exists(path))
        code, _, body = self.export([{'name': 'measurement', 'type': 'table', 'data': True}], target='platform')
        self.assertEqual(code, 200, body)
        j = json.loads(body)
        with open(path, 'rb') as f:
            data = f.read()
        self.assertEqual((j['path'], j['size'], j['export_id'], j['sha256']),
                         ('apps/database/exports/x.sql', len(data), 41, hashlib.sha256(data).hexdigest()))

    def test_e13_platform_never_overwrites(self):
        path = os.path.join(API.EXPORT_DIR, 'x.sql')
        with open(path, 'wb') as f:
            f.write(b'keep')
        code, _, body = self.export([{'name': 'measurement', 'type': 'table', 'data': True}], target='platform')
        self.assertEqual(code, 409, body)
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), b'keep')
        self.assertFalse([e for e in self.w.events if e[0] == 'sql' and 'log_export' in e[1]])


class ValToSqlTest(unittest.TestCase):
    def test_literals(self):
        v = API.val_to_sql
        self.assertEqual(v(None), 'NULL')
        self.assertEqual(v({'k': "o'k"}, 3802), """'{"k": "o''k"}'""")
        self.assertEqual(v(['a', 'b'], 3802), """'["a", "b"]'""")          # a jsonb array stays JSON
        self.assertEqual(v('plain', 114), """'"plain"'""")
        self.assertEqual(v(['R', None, 'q"\\', "it's"], 1009), """'{"R",NULL,"q\\"\\\\","it''s"}'""")
        self.assertEqual(v([[1, 2], [3, None]], 1007), """'{{"1","2"},{"3",NULL}}'""")
        self.assertEqual(v([True, False], 1000), """'{t,f}'""")
        self.assertEqual(v(uuid.UUID(SUB)), "'" + SUB + "'")
        self.assertEqual(v(float('nan')), "'NaN'")
        self.assertEqual(v(float('-inf')), "'-Infinity'")
        self.assertEqual(v(True), 'TRUE')
        self.assertEqual(v(datetime.date(2026, 10, 30)), "'2026-10-30'")
        self.assertEqual(v(b'\x01\xff'), "E'\\\\x01ff'")


if __name__ == '__main__':
    unittest.main()
