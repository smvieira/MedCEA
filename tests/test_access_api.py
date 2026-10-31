#!/usr/bin/env python3
"""Offline tests of apps/access/access-api.py (IAM 2.7, spec §8.1): the admin port's
enforcement, identity from the verified token, the account-decision flows, Keycloak
compensation, I17, CSRF and the SQLSTATE mapping.

No cluster, no database, no Keycloak: db() is a fake connection that records every
statement and answers from scripted rules, kc() is an in-memory realm that records
every call, and the real medcea_iam library runs against a fixture route table with its
_check() replaced by a scripted Decision. Requests go through the handler classes'
own parse_request/do_* (BaseHTTPRequestHandler.handle_one_request on in-memory files).

    python3 tests/test_access_api.py
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='test-access-api-')
ORIGIN = 'https://access.test'
sys.path.insert(0, os.path.join(REPO, 'apps', 'iam'))
from compiler import model as POLICY_MODEL                          # noqa: E402

# ── fixture route table (what deploy-infra writes to ConfigMap medcea-iam-lib) ──
# Deliberately not the policy's role list (superqa is a made-up composite, maintenance,
# qc and the scientists are left out); RoleCatalogue checks the offered list against it.
ROLES = ['admin', 'auditor', 'engineer', 'operator', 'production_manager', 'qa', 'qp', 'superqa']
INCLUDES = {'admin': [], 'auditor': [], 'engineer': [], 'operator': [], 'production_manager': ['operator'],
            'qa': ['auditor'], 'qp': [], 'superqa': ['auditor', 'qa']}
WIDENING = {
    '-': {r: [['portal', 'R']] + ([['runs', 'R']] if r != 'auditor' else []) for r in ROLES},
    'operator': {'production_manager': [['runs', 'O'], ['runs', 'R']], 'engineer': [['devices', 'C']],
                 'admin': [['iam_users', 'K']]},
    'auditor': {'qa': [['iam_users', 'A']], 'admin': [['iam_users', 'K']], 'operator': [['runs', 'R']]},
}
_ALL4 = {r: None for r in ('admin', 'auditor', 'qa', 'qp', 'superqa')}
TABLE = {
    'schema': 1, 'policy_version': 'test-1', 'digest': 'd' * 64, 'roles': ROLES, 'role_includes': INCLUDES,
    'widening': WIDENING, 'waivers': [{'id': 'W1', 'invariant': 'I11', 'subject': 'engineer', 'target': 'measurements',
                                       'levels': ['C'], 'review': '2027-10-27'}],
    'public': {'*': ['GET /healthz'], 'access-public': ['POST /api/register', 'GET /register']},
    'services': {'access': {'clients': ['access'], 'routes': {
        'GET /': {'group': 'user_manager', 'levels': ['R'], 'roles': _ALL4},
        'GET /api/me': {'group': 'user_manager', 'levels': ['R'], 'roles': _ALL4},
        'GET /api/decisions': {'group': 'iam_users', 'levels': ['R', 'K'],
                               'roles': {'admin': None, 'auditor': None, 'qa': None, 'superqa': None}},
        'GET /api/users': {'group': 'iam_users', 'levels': ['K'], 'roles': {'admin': None}},
        'POST /api/decisions/<id>/confirm': {'group': 'iam_users', 'levels': ['A'], 'roles': {'qa': None, 'superqa': None}},
        'POST /api/decisions/<id>/withdraw': {'group': 'iam_users', 'levels': ['K'], 'roles': {'admin': None}},
        'GET /api/config-history': {'group': 'audit_histories', 'levels': ['R'],
                                    'roles': {'auditor': None, 'qa': None, 'qp': None, 'superqa': None}},
    }}},
}
with open(os.path.join(TMP, 'routes.json'), 'w') as fh:
    json.dump(TABLE, fh)
with open(os.path.join(TMP, 'settings.json'), 'w') as fh:
    json.dump({'issuer': 'https://kc.test/realms/medcea', 'audience': 'medcea-api', 'enforce': False,
               'switches': {'IAM_GATES': True, 'written_at': '2026-10-30T00:00:00Z'}}, fh)
os.environ.update(MEDCEA_IAM_ROUTES=os.path.join(TMP, 'routes.json'), MEDCEA_IAM_SETTINGS=os.path.join(TMP, 'settings.json'),
                  MEDCEA_IAM_JWKS=os.path.join(TMP, 'jwks.json'), IAM_ENFORCE='false', ACCESS_URL=ORIGIN,
                  HTML_DIR=os.path.join(REPO, 'apps', 'access', 'html'),
                  TEMPLATE_DIR=os.path.join(REPO, 'apps', 'access', 'templates'))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LIB = _load('medcea_iam', os.path.join(REPO, 'apps', 'iam', 'lib', 'medcea_iam.py'))
API = _load('access_api', os.path.join(REPO, 'apps', 'access', 'access-api.py'))

A, Q, Q2, S, T, X = ('aaaaaaaa-0000-4000-8000-00000000000%d' % i for i in range(1, 7))
ADMIN = {'sub': A, 'person_id': 'pA', 'username': 'alice', 'roles': ['admin'], 'azp': 'access'}
QA = {'sub': Q, 'person_id': 'pQ', 'username': 'quinn', 'roles': ['auditor', 'qa'], 'azp': 'access'}
AUDITOR = {'sub': X, 'person_id': 'pX', 'username': 'audrey', 'roles': ['auditor'], 'azp': 'access'}


# ── fakes ────────────────────────────────────────────────────────────────────
class PgErr(Exception):
    """What pg8000 raises: args[0] is the server's error fields (C = SQLSTATE, M = message)."""
    def __init__(self, code, msg):
        super().__init__({'C': code, 'M': msg, 'S': 'ERROR'})


class World:
    """One test's database, Keycloak and outbox, with a shared event log so the order
    of SQL statements, Keycloak calls, commits and mail can be asserted."""
    def __init__(self):
        self.events, self.rules, self.mail = [], [], []
        self.users, self.maps, self.realm, self.fail = {}, {}, None, []
        self.commit_error = None

    # database
    def on(self, needle, rows=(), error=None, rowcount=None, once=False):
        self.rules.insert(0, dict(needle=needle, rows=rows, error=error, rowcount=rowcount, once=once))

    def connect(self):
        return FakeConn(self)

    def sql(self):
        return [e[1] for e in self.events if e[0] == 'sql']

    # Keycloak
    def user(self, uid, username, enabled=True, roles=(), person=None, email=None, **attrs):
        a = {k: [v] for k, v in attrs.items()}
        if person:
            a['person_id'] = [person]
        self.users[uid] = {'id': uid, 'username': username, 'enabled': enabled, 'email': email or username + '@x.org',
                           'firstName': username.title(), 'lastName': 'Test', 'attributes': a}
        self.maps[uid] = list(roles)

    def kc(self, method, path, body=None):
        self.events.append(('kc', method, path, json.loads(json.dumps(body)) if body is not None else None))
        for i, (m, rx, err, once) in enumerate(self.fail):
            if m == method and re.fullmatch(rx, path.split('?')[0]):
                if once:
                    self.fail.pop(i)
                raise err
        p, _, qs = path.partition('?')
        q = urllib.parse.parse_qs(qs)
        seg = p.strip('/').split('/') if p else []
        nf = API.KCError(404, 'not found')
        if p == '' and method == 'PUT':
            self.realm = body
            return 204, None, {}
        if seg == ['users'] and method == 'GET':
            us = [dict(u) for u in self.users.values()]
            if 'username' in q:
                us = [u for u in us if u['username'] == q['username'][0]]
            return 200, us, {}
        if seg[:1] == ['users'] and len(seg) >= 2:
            uid = seg[1]
            if uid not in self.users:
                raise nf
            if len(seg) == 2:
                if method == 'GET':
                    return 200, json.loads(json.dumps(self.users[uid])), {}
                if method == 'PUT':
                    self.users[uid] = dict(body)
                    return 204, None, {}
                if method == 'DELETE':
                    del self.users[uid]
                    return 204, None, {}
            if seg[2:] == ['logout']:
                return 204, None, {}
            if seg[2:4] == ['role-mappings', 'realm']:
                if seg[4:] == ['composite']:
                    eff = {x for r in self.maps[uid] for x in [r] + INCLUDES.get(r, [])}
                    return 200, [{'name': r, 'id': r} for r in sorted(eff)], {}
                if method == 'GET':
                    return 200, [{'name': r, 'id': r} for r in self.maps[uid]], {}
                if method == 'POST':
                    self.maps[uid] += [r['name'] for r in body if r['name'] not in self.maps[uid]]
                    return 204, None, {}
                if method == 'DELETE':
                    gone = {r['name'] for r in body}
                    self.maps[uid] = [r for r in self.maps[uid] if r not in gone]
                    return 204, None, {}
        if seg[:1] == ['roles'] and len(seg) == 2:
            return 200, {'name': seg[1], 'id': seg[1]}, {}
        if seg[:1] == ['roles'] and seg[2:] == ['users']:
            return 200, [dict(self.users[u]) for u, rs in self.maps.items() if seg[1] in rs and u in self.users], {}
        if seg == ['events']:
            return 200, [], {}
        raise AssertionError('fake Keycloak: unhandled %s %s' % (method, path))

    def kc_writes(self):
        return [e for e in self.events if e[0] == 'kc' and e[1] != 'GET']

    def send_mail(self, to, subject, body, st=None):
        self.events.append(('mail', tuple(to), subject))
        self.mail.append((to, subject, body))
        return True, 'sent to %s' % ', '.join(to)


class FakeConn:
    def __init__(self, w):
        self.w = w

    def cursor(self):
        return FakeCursor(self.w)

    def commit(self):
        if self.w.commit_error is not None:
            e, self.w.commit_error = self.w.commit_error, None
            raise e
        self.w.events.append(('commit',))

    def rollback(self):
        self.w.events.append(('rollback',))

    def close(self):
        pass


class FakeCursor:
    def __init__(self, w):
        self.w, self._rows, self.rowcount = w, [], -1

    def execute(self, sql, params=()):
        self.w.events.append(('sql', sql, params))
        for r in self.w.rules:
            if r['needle'] in sql:
                if r['once']:
                    self.w.rules.remove(r)
                if r['error'] is not None:
                    raise r['error']
                rows = r['rows'](sql, params) if callable(r['rows']) else r['rows']
                self._rows = [tuple(x) for x in rows]
                self.rowcount = r['rowcount'] if r['rowcount'] is not None else len(self._rows)
                return
        self._rows, self.rowcount = [], 0

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows


def response(raw):
    head, _, body = raw.partition(b'\r\n\r\n')
    status = int(head.split(b' ', 2)[1])
    try:
        return status, json.loads(body or b'null')
    except ValueError:
        return status, body


class Base(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.decision = LIB.Decision(True, 200, 'allowed', dict(ADMIN))
        self.check_error = None
        self._orig = dict(_check=LIB._check)
        test = self

        def fake_check(service, method, path, headers):
            if test.check_error:
                raise test.check_error
            return test.decision
        LIB._check = fake_check
        self._api = {k: getattr(API, k) for k in ('db', 'kc', 'send_mail', '_medcea_iam', 'register', 'kc_token')}
        API.db = self.w.connect
        API.kc = self.w.kc
        API.send_mail = self.w.send_mail
        API._medcea_iam = lambda: LIB
        API._COMP_FAILED[:] = []
        LIB._cache.clear()
        self.stderr = io.StringIO()

    def tearDown(self):
        LIB._check = self._orig['_check']
        for k, v in self._api.items():
            setattr(API, k, v)

    def as_(self, who):
        self.decision = LIB.Decision(True, 200, 'allowed', dict(who))

    def call(self, method, path, body=None, cls=None, headers=None, raw_body=None):
        cls = cls or API.Admin
        h = {'Host': 'access.test'}
        if method == 'POST' and cls is API.Admin:
            h.update({'Content-Type': 'application/json', 'Origin': ORIGIN})
        h.update(headers or {})
        data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else b'')
        if data:
            h['Content-Length'] = str(len(data))
        req = ('%s %s HTTP/1.1\r\n' % (method, path) + ''.join('%s: %s\r\n' % kv for kv in h.items()) + '\r\n').encode() + data
        handler = object.__new__(cls)
        handler.rfile, handler.wfile = io.BytesIO(req), io.BytesIO()
        handler.client_address, handler.server, handler.request = ('127.0.0.1', 1), None, None
        handler.close_connection = True
        with contextlib.redirect_stderr(self.stderr), contextlib.redirect_stdout(io.StringIO()):
            handler.handle_one_request()
        return response(handler.wfile.getvalue())

    def order(self, *needles):
        """Positions in the event log of each needle (a SQL fragment, ('kc', METHOD, path
        regex), 'commit', 'rollback' or 'mail'); asserts all are present and in order."""
        pos = []
        for n in needles:
            for i, e in enumerate(self.w.events):
                if i <= (pos[-1] if pos else -1):
                    continue
                hit = (e[0] == n if isinstance(n, str) and n in ('commit', 'rollback', 'mail') else
                       e[0] == 'sql' and n in e[1] if isinstance(n, str) else
                       e[0] == 'kc' and e[1] == n[1] and re.fullmatch(n[2], e[2].split('?')[0]))
                if hit:
                    pos.append(i)
                    break
            else:
                self.fail('%r not found after %r in %s' % (n, needles[:len(pos)], self.w.events))
        return pos

    # common realm: admin alice, qa quinn, a second qa, an auditor
    def staff(self):
        self.w.user(A, 'alice', roles=['admin'], person='pA')
        self.w.user(Q, 'quinn', roles=['qa'], person='pQ')
        self.w.user(Q2, 'quentin', roles=['qa'], person='pQ2')
        self.w.user(X, 'audrey', roles=['auditor'], person='pX')

    def request_row(self, status='pending', uid=S, granted=None):
        r = dict(request_id=5, keycloak_user_id=uid, username='newbie', email='newbie@x.org', first_name='New',
                 last_name='Bie', organisation=None, requested_role='operator', justification='j' * 30, status=status,
                 granted_role=granted, decided_by=None, decided_at=None, admin_notes=None, created_at=None,
                 email_subject=None, email_body=None)
        return tuple(r[c] for c in API.REQ_COLS)


# ── 1. the admin port enforces always ─────────────────────────────────────────
class Enforcement(Base):
    def test_refusal_under_report_only(self):
        self.decision = LIB.Decision(False, 403, "roles ['qp'] do not hold K on iam_users", dict(ADMIN, roles=['qp']))
        status, body = self.call('GET', '/api/users')
        self.assertEqual(status, 403)
        self.assertEqual(self.w.events, [], 'the handler must not run')
        lines = [l for l in self.stderr.getvalue().splitlines() if 'medcea_iam' in l]
        self.assertEqual(len(lines), 1, lines)
        self.assertIn('refused', lines[0])
        self.assertNotIn('would refuse', lines[0])

    def test_missing_library(self):
        API._medcea_iam = lambda: None
        self.assertEqual(self.call('GET', '/api/me')[0], 503)
        self.assertEqual(self.call('POST', '/api/users/%s/role' % S, {'role': 'qa'})[0], 503)
        status, body = self.call('GET', '/healthz')
        self.assertEqual((status, body), (200, {'ok': True, 'access_version': '2.7', 'enforce_always': True}))

    def test_check_exception_and_missing_table_keep_healthz(self):
        self.check_error = RuntimeError('boom')
        self.assertEqual(self.call('GET', '/healthz')[0], 200)
        self.assertEqual(self.call('GET', '/api/me')[0], 503)
        LIB._check = self._orig['_check']        # the real check, with no route table
        LIB.ROUTES_FILE, old = os.path.join(TMP, 'absent.json'), LIB.ROUTES_FILE
        try:
            self.assertEqual(self.call('GET', '/healthz')[0], 200)
            self.assertEqual(self.call('GET', '/api/me')[0], 503)
        finally:
            LIB.ROUTES_FILE = old

    def test_public_route_decision_is_not_a_person(self):
        self.decision = LIB.Decision(True, 200, 'public route')
        for m, p in (('GET', '/api/me'), ('GET', '/'), ('GET', '/healthz?x=1'), ('POST', '/api/review')):
            self.assertEqual(self.call(m, p, {} if m == 'POST' else None)[0], 401, p)
        self.assertEqual(self.w.events, [])


# ── 2. identity comes from the token ──────────────────────────────────────────
class Identity(Base):
    def test_forged_headers_ignored(self):
        self.staff()
        self.w.user(S, 'newbie', enabled=False)
        self.w.on('FOR UPDATE', [self.request_row()])
        self.w.on('iam.record_decision', [(7, 'pending_qa', WIDENING['-']['operator'], [])])
        self.w.on('UPDATE iam.access_request', [self.request_row('approved', granted='operator')])
        status, _ = self.call('POST', '/api/requests/5/decision',
                              {'decision': 'approve', 'role': 'operator', 'send_email': False},
                              headers={'X-Forwarded-Preferred-Username': 'mallory', 'X-Forwarded-User': 'mallory',
                                       'X-Forwarded-Email': 'm@evil'})
        self.assertEqual(status, 202)
        actor = next(e for e in self.w.events if e[0] == 'sql' and 'set_actor' in e[1])
        self.assertEqual(actor[2], (A, 'pA', 'alice', 'admin'))
        upd = next(e for e in self.w.events if e[0] == 'sql' and 'UPDATE iam.access_request' in e[1])
        self.assertEqual(upd[2][1], 'alice')
        self.assertNotIn('mallory', json.dumps([e[2] for e in self.w.events if e[0] == 'sql'], default=str))

    def test_two_own_roles_cannot_write(self):
        self.as_(dict(ADMIN, roles=['admin', 'operator']))
        status, body = self.call('POST', '/api/users/%s/person' % S, {'person_id': 'p9', 'reason': 'r'})
        self.assertEqual(status, 403)
        self.assertIn('more than one platform role', body['error'])


# ── 3-5. proposals ────────────────────────────────────────────────────────────
class Proposals(Base):
    def test_approve_is_a_waiting_grant(self):
        self.staff()
        self.w.user(S, 'newbie', enabled=False)
        self.w.on('FOR UPDATE', [self.request_row()])
        self.w.on('iam.record_decision', [(7, 'pending_qa', WIDENING['-']['operator'], [])])
        self.w.on('UPDATE iam.access_request', [self.request_row('approved', granted='operator')])
        status, body = self.call('POST', '/api/requests/5/decision',
                                 {'decision': 'approve', 'role': 'operator', 'email_subject': 'Hi', 'email_body': 'Welcome'})
        self.assertEqual(status, 202, body)
        self.assertEqual(body['decision']['decision_id'], 7)
        self.assertFalse(body['email']['sent'])
        self.order('set_actor', 'iam.record_decision', 'UPDATE iam.access_request', 'commit')
        rec = next(e for e in self.w.events if e[0] == 'sql' and 'record_decision' in e[1])
        self.assertEqual(rec[2], ('grant', S, 'newbie', S, None, 'operator', S, rec[2][7], 5))
        self.assertEqual([e for e in self.w.events if e[0] == 'kc'], [], 'no Keycloak call')
        self.assertEqual(self.w.mail, [])

    def test_narrowing_applies_at_once(self):
        self.staff()
        self.w.user(S, 'sam', roles=['production_manager'], person='pS')
        self.w.on('iam.record_decision', [(8, 'applied', [], [])])
        self.w.on('revoke_person_mqtt', [(0,)])
        status, body = self.call('POST', '/api/users/%s/role' % S, {'role': 'operator', 'reason': 'moved'})
        self.assertEqual(status, 200, body)
        self.order('iam.record_decision', 'revoke_person_mqtt', ('kc', 'POST', r'/users/%s/role-mappings/realm' % S),
                   ('kc', 'DELETE', r'/users/%s/role-mappings/realm' % S), 'commit')
        rec = next(e for e in self.w.events if e[0] == 'sql' and 'record_decision' in e[1])
        self.assertEqual(rec[2][4:6], ('production_manager', 'operator'))
        self.assertEqual(self.w.maps[S], ['operator'])

    def test_widening_waits_without_keycloak(self):
        self.staff()
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        self.w.on('iam.record_decision', [(9, 'pending_qa', WIDENING['operator']['engineer'], [])])
        status, body = self.call('POST', '/api/users/%s/role' % S, {'role': 'engineer', 'reason': 'promoted'})
        self.assertEqual(status, 202, body)
        self.assertEqual(body['status'], 'pending_qa')
        self.assertEqual(self.w.kc_writes(), [])
        self.assertFalse(any('revoke_person_mqtt' in s for s in self.w.sql()))
        self.order('commit')

    def test_deactivate_order_and_logout(self):
        self.staff()
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        self.w.on('iam.record_decision', [(10, 'applied', [], [])])
        self.w.on('revoke_person_mqtt', [(1,)])
        status, body = self.call('POST', '/api/users/%s/status' % S, {'active': False, 'reason': 'left'})
        self.assertEqual(status, 200, body)
        self.assertNotIn('warning', body)
        self.order('iam.record_decision', 'revoke_person_mqtt', ('kc', 'PUT', r'/users/%s' % S), 'commit',
                   ('kc', 'POST', r'/users/%s/logout' % S))
        self.assertFalse(self.w.users[S]['enabled'])

    def test_deactivate_logout_failure_is_a_warning(self):
        self.staff()
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        self.w.on('iam.record_decision', [(10, 'applied', [], [])])
        self.w.on('revoke_person_mqtt', [(0,)])
        self.w.fail.append(('POST', r'/users/.*/logout', API.KCError(500, 'down'), False))
        status, body = self.call('POST', '/api/users/%s/status' % S, {'active': False, 'reason': 'left'})
        self.assertEqual(status, 200)
        self.assertIn('sessions not ended', body['warning'])

    def test_last_qa_and_own_account(self):
        self.w.user(A, 'alice', roles=['admin'], person='pA')
        self.w.user(Q, 'quinn', roles=['qa'], person='pQ')
        status, body = self.call('POST', '/api/users/%s/status' % Q, {'active': False, 'reason': 'left'})
        self.assertEqual(status, 409)
        self.assertIn('last enabled qa', body['error'])
        status, body = self.call('POST', '/api/users/%s/status' % A, {'active': False, 'reason': 'x'})
        self.assertEqual(status, 400)
        self.assertIn('own account', body['error'])


# ── 6, 7, 15. confirm ─────────────────────────────────────────────────────────
class Confirm(Base):
    def setUp(self):
        super().setUp()
        self.staff()
        self.as_(QA)
        self.w.user(S, 'newbie', enabled=False, organisation='Lab')
        self.w.on('SELECT request_id, subject_person FROM iam.account_decision', [(5, S)])
        self.w.on('iam.confirm_decision', [(12, 'grant', S, 'newbie', None, 'operator', S, None)])
        self.w.on('SELECT email, email_subject, email_body FROM iam.access_request', [('newbie@x.org', 'Welcome', 'Hello')])

    def test_grant(self):
        status, body = self.call('POST', '/api/decisions/12/confirm', {'note': 'ok'})
        self.assertEqual(status, 200, body)
        actor = next(e for e in self.w.events if e[0] == 'sql' and 'set_actor' in e[1])
        self.assertEqual(actor[2], (Q, 'pQ', 'quinn', 'qa'))
        p = self.order('set_actor', 'iam.confirm_decision', ('kc', 'GET', r'/users/%s' % Q),
                       ('kc', 'POST', r'/users/%s/role-mappings/realm' % S), ('kc', 'PUT', r'/users/%s' % S), 'commit', 'mail')
        put = self.w.events[p[4]][3]
        self.assertTrue(put['enabled'])
        self.assertEqual(put['attributes'], {'organisation': ['Lab'], 'person_id': [S]})
        self.assertEqual(self.w.maps[S], ['operator'])
        self.assertTrue(body['email']['sent'])

    def test_keycloak_error_compensates(self):
        self.w.fail.append(('PUT', r'/users/%s' % S, API.KCError(500, 'boom'), False))
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 502, body)
        self.assertNotIn('drift', body)
        self.order(('kc', 'POST', r'/users/%s/role-mappings/realm' % S), ('kc', 'PUT', r'/users/%s' % S),
                   ('kc', 'DELETE', r'/users/%s/role-mappings/realm' % S), 'rollback')
        self.assertNotIn(('commit',), self.w.events)
        self.assertEqual(self.w.maps[S], [])
        self.assertEqual(self.w.mail, [])

    def test_failed_compensation_is_drift(self):
        self.w.fail.append(('PUT', r'/users/%s' % S, API.KCError(500, 'boom'), False))
        self.w.fail.append(('DELETE', r'/users/%s/role-mappings/realm' % S, API.KCError(500, 'boom'), False))
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 502)
        self.assertTrue(body['drift'])
        self.assertNotIn(('commit',), self.w.events)
        self.assertEqual(API._COMP_FAILED[0]['role'], 'operator')

    def test_i17_before_any_write(self):
        self.w.user(T, 'twin', roles=['auditor'], person='pA')        # alice's person
        self.w.rules.clear()
        self.w.on('SELECT request_id, subject_person FROM iam.account_decision', [(None, 'pA')])
        self.w.on('iam.confirm_decision', [(13, 'role_change', T, 'twin', 'auditor', 'qa', None, None)])
        status, body = self.call('POST', '/api/decisions/13/confirm', {})
        self.assertEqual(status, 409, body)
        self.assertIn('I17', body['error'])
        self.assertEqual(self.w.kc_writes(), [])
        self.assertIn(('rollback',), self.w.events)

    def test_approver_changed(self):
        self.w.users[Q]['attributes']['person_id'] = ['someone-else']
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 409)
        self.assertIn('sign in again', body['error'])
        self.assertEqual(self.w.kc_writes(), [])

    def test_subject_same_person(self):
        self.w.users[S]['attributes']['person_id'] = ['pQ']
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 403)
        self.assertIn('not_own_author', body['error'])

    def test_account_changed_since(self):
        self.w.users[S]['enabled'] = True
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 409)
        self.assertIn('changed since', body['error'])
        self.assertEqual(self.w.kc_writes(), [])


# ── 8. refuse ─────────────────────────────────────────────────────────────────
class Refuse(Base):
    def setUp(self):
        super().setUp()
        self.staff()
        self.as_(QA)

    def test_note_required(self):
        self.assertEqual(self.call('POST', '/api/decisions/20/refuse', {'note': ' '})[0], 400)
        self.assertEqual(self.w.events, [])

    def test_unit_returns_removed(self):
        self.w.on('SELECT from_role, to_role FROM iam.account_decision', [(None, None)])
        self.w.on('iam.refuse_decision', [(20, 'unit_assign', S, 3, True)])
        status, body = self.call('POST', '/api/decisions/20/refuse', {'note': 'wrong unit'})
        self.assertEqual(status, 200, body)
        self.assertTrue(body['removed_unit'])
        self.assertEqual(self.w.kc_writes(), [])

    def test_refused_grant_deletes_the_account(self):
        self.w.user(S, 'newbie', enabled=False)
        self.w.on('SELECT from_role, to_role FROM iam.account_decision', [(None, 'operator')])
        self.w.on('iam.refuse_decision', [(21, 'grant', S, None, False)])
        status, body = self.call('POST', '/api/decisions/21/refuse', {'note': 'unknown person'})
        self.assertEqual(status, 200, body)
        self.order('iam.refuse_decision', ('kc', 'DELETE', r'/users/%s' % S), 'commit')
        self.assertNotIn(S, self.w.users)
        self.assertEqual(self.w.mail, [])


# ── 9. template reset ─────────────────────────────────────────────────────────
class Templates(Base):
    def test_reset_is_an_update(self):
        self.w.on('UPDATE iam.mail_template', rowcount=1)
        status, body = self.call('POST', '/api/templates/approved/reset', {})
        self.assertEqual(status, 200, body)
        upd = [s for s in self.w.sql() if 'UPDATE iam.mail_template' in s]
        self.assertEqual(len(upd), 1)
        self.assertIn('is_default = true', upd[0])
        self.assertFalse(any('DELETE' in s for s in self.w.sql()))

    def test_reset_of_a_default(self):
        self.w.on('UPDATE iam.mail_template', rowcount=0)
        status, body = self.call('POST', '/api/templates/approved/reset', {})
        self.assertEqual((status, body['unchanged']), (200, True))


# ── 10. SQLSTATE mapping ──────────────────────────────────────────────────────
class SqlState(Base):
    def person(self, err):
        self.staff()
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        self.w.on('iam.record_decision', error=err)
        return self.call('POST', '/api/users/%s/person' % S, {'person_id': 'p9', 'reason': 'merge'})

    def test_grant_missing(self):
        status, body = self.person(PgErr('42501', 'permission denied for schema medcea'))
        self.assertEqual(status, 503)
        self.assertIn('./apps/database/deploy.sh', body['error'])

    def test_function_missing(self):
        self.assertEqual(self.person(PgErr('42883', 'function iam.record_decision does not exist'))[0], 503)

    def test_refusal(self):
        status, body = self.person(PgErr('42501', 'role admin holds no K on iam_users'))
        self.assertEqual((status, body['error']), (403, 'role admin holds no K on iam_users'))

    def test_conflict(self):
        self.assertEqual(self.person(PgErr('22023', 'decision #4 is waiting for qa'))[0], 409)
        self.assertIn(('rollback',), self.w.events)


# ── 11. I17 ───────────────────────────────────────────────────────────────────
class I17(Base):
    def test_shared_person(self):
        self.w.user(A, 'alice', roles=['admin'], person='p1')
        self.w.user(Q, 'quinn', roles=['qa'], person='p1')
        self.assertIn('I17', API.i17_violation(Q))
        self.w.users[Q]['attributes']['person_id'] = ['p2']
        self.assertIsNone(API.i17_violation(Q))
        self.assertIn('I17', API.i17_violation(Q, new_person='p1'))
        self.assertIsNone(API.i17_violation(A, new_role='operator', subject=self.w.users[A]) or
                          API.i17_violation(Q))

    def test_composite(self):
        self.w.user(A, 'alice', roles=['admin'], person='p1')
        self.w.user(T, 'tom', roles=['superqa'], person='p1')    # includes qa
        self.assertIn('I17', API.i17_violation(T))
        self.w.maps[T] = ['auditor']
        self.w.user(S, 'sam', roles=['operator'], person='p1')
        self.assertIsNone(API.i17_violation(S, new_role='auditor'))
        self.assertIn('I17', API.i17_violation(S, new_role='superqa'))   # a composite that includes qa


# ── 12. roles outside ROLES, two-role accounts ────────────────────────────────
class Roles(Base):
    def test_activate_qp(self):
        self.staff()
        self.w.user(S, 'pat', enabled=False, roles=['qp'], person='pS')
        self.w.on('iam.record_decision', [(31, 'pending_qa', WIDENING['-']['qp'], [])])
        status, body = self.call('POST', '/api/users/%s/status' % S, {'active': True})
        self.assertEqual(status, 202, body)
        rec = next(e for e in self.w.events if e[0] == 'sql' and 'record_decision' in e[1])
        self.assertEqual(rec[2][0], 'activate')
        self.assertEqual(rec[2][4], 'qp')
        self.assertEqual(self.w.kc_writes(), [])

    def test_two_role_change_is_from_none(self):
        self.staff()
        self.w.user(S, 'dual', roles=['auditor', 'operator'], person='pS')
        self.w.on('iam.record_decision', [(32, 'pending_qa', WIDENING['-']['admin'], [])])
        status, body = self.call('POST', '/api/users/%s/role' % S, {'role': 'admin', 'reason': 'ops'})
        self.assertEqual(status, 202, body)
        rec = next(e for e in self.w.events if e[0] == 'sql' and 'record_decision' in e[1])
        self.assertIsNone(rec[2][4])
        self.assertEqual(self.w.kc_writes(), [])

    def test_two_role_activation_refused(self):
        self.staff()
        self.w.user(S, 'dual', enabled=False, roles=['auditor', 'operator'], person='pS')
        status, body = self.call('POST', '/api/users/%s/status' % S, {'active': True})
        self.assertEqual(status, 409)
        self.assertIn('one role first', body['error'])
        self.assertFalse(any('record_decision' in s for s in self.w.sql()))


# ── IAM 2.6: every policy role is offered ─────────────────────────────────────
class RoleCatalogue(Base):
    FORM = {'username': 'newbie', 'email': 'n@x.org', 'first_name': 'N', 'last_name': 'B',
            'justification': 'j' * 30, 'password': 'p' * 12}

    def test_roles_match_policy(self):
        p = POLICY_MODEL.load()
        self.assertEqual(list(API.ROLES), list(p.roles))
        for r, v in API.ROLES.items():
            for k in ('label', 'description', 'availability'):
                self.assertEqual(v[k], p.roles[r][k], '%s.%s differs from defaults.yaml' % (r, k))
            self.assertIn(v['availability'], ('prototype', 'later'))

    def test_db_check_accepts_every_role(self):
        with open(os.path.join(REPO, 'apps', 'access', 'access_db.sql')) as fh:
            sql = fh.read()
        for c in ('access_request_requested_role_check', 'access_request_granted_role_check'):
            m = re.search(r'ADD CONSTRAINT %s\s+CHECK \(\w+ IN \(([^)]*)\)' % c, sql)
            self.assertIsNotNone(m, c)
            self.assertEqual(set(re.findall(r"'(\w+)'", m.group(1))), set(API.ROLES), c)

    def test_register_roles_public(self):
        self.decision = LIB.Decision(True, 200, 'public route')
        status, body = self.call('GET', '/api/register/roles', cls=API.Public)
        self.assertEqual(status, 200)
        self.assertEqual([x['id'] for x in body], list(API.ROLES))
        for x in body:
            self.assertEqual(set(x), {'id', 'label', 'description', 'availability'})
            self.assertEqual(x['availability'], 'later' if x['id'] in ('qc', 'qp') else 'prototype')

    def test_me_roles(self):
        self.as_(ADMIN)
        status, body = self.call('GET', '/api/me')
        self.assertEqual(status, 200, body)
        self.assertEqual(body['roles'], API.role_list())
        self.assertLessEqual({'maintenance', 'bio_scientist', 'control_scientist', 'qc'}, {x['id'] for x in body['roles']})

    def test_validate_every_role(self):
        for r in API.ROLES:
            clean, err = API.validate(dict(self.FORM, requested_role=r))
            self.assertIsNone(err, r)
            self.assertEqual(clean['requested_role'], r)
        for r in ('superqa', ''):
            self.assertEqual(API.validate(dict(self.FORM, requested_role=r)), (None, 'Choose a role.'))

    def test_approve_new_role(self):
        self.staff()
        self.w.user(S, 'newbie', enabled=False)
        self.w.on('FOR UPDATE', [self.request_row()])
        self.w.on('iam.record_decision', [(7, 'pending_qa', WIDENING['-']['production_manager'], [])])
        self.w.on('UPDATE iam.access_request', [self.request_row('approved', granted='production_manager')])
        status, body = self.call('POST', '/api/requests/5/decision', {'decision': 'approve', 'role': 'production_manager', 'email_subject': 'Hi', 'email_body': 'Welcome'})
        self.assertEqual(status, 202, body)
        rec = next(e for e in self.w.events if e[0] == 'sql' and 'record_decision' in e[1])
        self.assertEqual(rec[2][5], 'production_manager')
        self.assertEqual(self.w.kc_writes(), [])

    def test_approve_unknown_role(self):
        self.staff()
        self.w.user(S, 'newbie', enabled=False)
        self.w.on('FOR UPDATE', [self.request_row()])
        status, body = self.call('POST', '/api/requests/5/decision', {'decision': 'approve', 'role': 'superqa', 'email_subject': 'Hi', 'email_body': 'Welcome'})
        self.assertEqual(status, 400, body)
        self.assertIn('choose the role to grant', body['error'])
        self.assertFalse(any('record_decision' in s for s in self.w.sql()))

    def test_role_change_to_maintenance(self):
        # The fixture table has no maintenance (above): both widening sides are [].
        self.staff()
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        self.w.on('iam.record_decision', [(33, 'pending_qa', [], [])])
        status, body = self.call('POST', '/api/users/%s/role' % S, {'role': 'maintenance', 'reason': 'r'})
        self.assertEqual(status, 202, body)
        rec = next(e for e in self.w.events if e[0] == 'sql' and 'record_decision' in e[1])
        self.assertEqual(rec[2][4:6], ('operator', 'maintenance'))
        status, body = self.call('POST', '/api/users/%s/role' % S, {'role': 'superqa', 'reason': 'r'})
        self.assertEqual(status, 400, body)
        self.assertIn('choose one of', body['error'])

    def test_template_labels(self):
        row = dict(zip(API.REQ_COLS, self.request_row(granted='qp')), requested_role='qc')
        v = API.template_values(row)
        self.assertEqual((v['requested_role_label'], v['granted_role_label']),
                         ('Quality Control Analyst', 'Qualified / Responsible Person'))


# ── 13. public and profile ports unchanged ────────────────────────────────────
class OtherPorts(Base):
    def test_register_without_token(self):
        self.decision = LIB.Decision(True, 200, 'public route')
        seen = []
        API.register = lambda f, ip: seen.append(f) or (201, {'ok': True})
        status, _ = self.call('POST', '/api/register', {'username': 'x'}, cls=API.Public,
                              headers={'Content-Type': 'text/plain'})
        self.assertEqual(status, 201)
        self.assertEqual(seen, [{'username': 'x'}])

    def test_public_report_only(self):
        self.decision = LIB.Decision(False, 401, 'no access token')
        API.register = lambda f, ip: (201, {'ok': True})
        self.assertEqual(self.call('POST', '/api/register', {}, cls=API.Public)[0], 201)
        self.assertIn('would refuse', self.stderr.getvalue())

    def test_profile(self):
        self.w.user(S, 'sam')
        status, body = self.call('GET', '/_account/api/me', cls=API.Profile,
                                 headers={'X-Forwarded-Preferred-Username': 'sam'})
        self.assertEqual((status, body['username']), (200, 'sam'))
        self.assertEqual(self.call('GET', '/_account/api/me', cls=API.Profile)[0], 401)
        self.assertEqual(self.call('GET', '/_account/healthz', cls=API.Profile)[0], 200)


# ── 14. CSRF ──────────────────────────────────────────────────────────────────
class Csrf(Base):
    def test_form_post(self):
        status, _ = self.call('POST', '/api/decisions/1/confirm', raw_body=b'note=x',
                              headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(status, 415)
        status, _ = self.call('POST', '/api/decisions/1/confirm', {}, headers={'Content-Type': 'text/plain'})
        self.assertEqual(status, 415)
        self.assertEqual(self.w.events, [])

    def test_foreign_origin(self):
        self.assertEqual(self.call('POST', '/api/decisions/1/confirm', {}, headers={'Origin': 'https://evil.test'})[0], 403)
        self.assertEqual(self.call('POST', '/api/decisions/1/confirm', {}, headers={'Origin': ''})[0], 403)
        self.assertEqual(self.w.events, [])


# ── 16. deactivation withdraws ────────────────────────────────────────────────
class Withdraw(Base):
    def test_deactivate_disabled_with_pending_grant(self):
        self.staff()
        self.w.user(S, 'newbie', enabled=False)
        self.w.on('iam.record_decision', [(40, 'applied', [], [12])])
        self.w.on('revoke_person_mqtt', [(0,)])
        status, body = self.call('POST', '/api/users/%s/status' % S, {'active': False, 'reason': 'left before start'})
        self.assertEqual(status, 200, body)
        self.assertEqual(body['decision']['withdrawn'], [12])
        self.assertFalse(any(e[1] == 'PUT' for e in self.w.kc_writes()), 'already disabled: no PUT')
        # the withdrawn grant cannot be confirmed afterwards
        self.as_(QA)
        self.w.on('iam.confirm_decision', error=PgErr('22023', 'decision #12 is already withdrawn'))
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 409)
        self.assertIn('withdrawn', body['error'])

    def test_withdraw_needs_reason(self):
        self.assertEqual(self.call('POST', '/api/decisions/12/withdraw', {})[0], 400)
        self.w.on('iam.withdraw_decision', [(12,)])
        self.assertEqual(self.call('POST', '/api/decisions/12/withdraw', {'reason': 'dup'})[0], 200)


# ── 17. mail settings wait for qa ─────────────────────────────────────────────
class MailSettings(Base):
    def test_save_confirm_refuse(self):
        self.staff()
        self.w.on('iam.record_decision', [(50, 'pending_qa', [], [])])
        status, body = self.call('POST', '/api/settings', {'smtp_user': '', 'from_name': 'MedCEA'})
        self.assertEqual(status, 202, body)
        self.order('iam.record_decision', 'INSERT INTO iam.mail_settings_pending', 'commit')
        self.assertIsNone(self.w.realm)
        self.assertFalse(any('UPDATE iam.mail_settings' in s for s in self.w.sql()))
        self.as_(QA)
        self.w.on('iam.confirm_decision', [(50, 'mail_settings', 'realm', 'realm mail settings', None, None, None, None)])
        self.w.on('FROM iam.mail_settings WHERE id = 1',
                  [('smtp.gmail.com', 587, 'm@x.org', 'secret', 'MedCEA', '', 'alice', None)])
        status, body = self.call('POST', '/api/decisions/50/confirm', {})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.w.realm['smtpServer']['user'], 'm@x.org')
        self.w.realm = None
        self.w.on('iam.refuse_decision', [(51, 'mail_settings', 'realm', None, False)])
        self.assertEqual(self.call('POST', '/api/decisions/51/refuse', {'note': 'not ours'})[0], 200)
        self.assertIsNone(self.w.realm)


# ── 18. widening cross-check ──────────────────────────────────────────────────
class WideningCheck(Base):
    def test_mismatch_is_503(self):
        self.staff()
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        self.w.on('iam.record_decision', [(60, 'pending_qa', [['devices', 'C'], ['flows', 'C']], [])])
        status, body = self.call('POST', '/api/users/%s/role' % S, {'role': 'engineer', 'reason': 'x'})
        self.assertEqual(status, 503)
        self.assertIn('differ', body['error'])
        self.assertNotIn(('commit',), self.w.events)
        self.assertIn(('rollback',), self.w.events)


# ── /api/me and the decisions list ────────────────────────────────────────────
class Reads(Base):
    def test_me_capabilities(self):
        self.as_(QA)
        status, body = self.call('GET', '/api/me')
        self.assertEqual(status, 200)
        self.assertTrue(body['can']['decisions_check'])
        self.assertTrue(body['can']['histories'])
        self.assertFalse(body['can']['users'])
        self.assertEqual(body['role'], 'qa')
        self.assertNotIn('widening', body)
        self.as_(ADMIN)
        body = self.call('GET', '/api/me')[1]
        self.assertTrue(body['can']['users'])
        self.assertFalse(body['can']['histories'])
        self.assertIn('-', body['widening'])

    def test_decisions_can_check(self):
        self.staff()
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        row = {c: None for c in API.DEC_COLS}
        row.update(decision_id=70, kind='role_change', keycloak_user_id=S, username='sam', subject_person='pS',
                   from_role='operator', to_role='engineer', widens=True, widening=[['devices', 'C']], status='pending_qa',
                   reason='r', made_by_sub=A, made_by_person='pA', made_by_name='alice')
        mine = dict(row, decision_id=71, made_by_sub=Q, made_by_person='pQ', made_by_name='quinn')
        self.w.on('FROM iam.account_decision d LEFT JOIN',
                  [tuple(r[c] for c in API.DEC_COLS) + (None, None, False) for r in (row, mine)])
        self.as_(QA)
        status, body = self.call('GET', '/api/decisions?status=pending_qa')
        self.assertEqual(status, 200, body)
        a, b = body['decisions']
        self.assertIs(a['in_effect'], False)
        sql = next(q for q in self.w.sql() if 'FROM iam.account_decision d LEFT JOIN' in q)
        self.assertIn('FROM iam_policy.user_unit uu', sql)                   # in effect before the check
        self.assertTrue(a['can_check'])
        self.assertEqual(a['subject'], {'enabled': True, 'role': 'operator', 'person_id': 'pS'})
        self.assertFalse(b['can_check'])
        self.assertIn('you made', b['why_not'])
        self.as_(AUDITOR)
        a = self.call('GET', '/api/decisions')[1]['decisions'][0]
        self.assertFalse(a['can_check'])


# ── review fixes: Keycloak read under the account lock (security 1, 2) ─────────
def under_lock(world, change, row):
    """A record_decision answer that first applies `change` to the fake realm: what a
    concurrent confirm committed while this request waited for the account lock."""
    def rows(sql, params):
        change()
        return [row]
    return rows


class LockedReads(Base):
    def setUp(self):
        super().setUp()
        self.staff()

    def test_deactivate_disables_an_account_enabled_meanwhile(self):
        self.w.user(S, 'newbie', enabled=False, roles=['operator'], person='pS')
        self.w.on('iam.record_decision', under_lock(self.w, lambda: self.w.users[S].update(enabled=True),
                                                    (40, 'applied', [], [])))
        self.w.on('revoke_person_mqtt', [(0,)])
        status, body = self.call('POST', '/api/users/%s/status' % S, {'active': False, 'reason': 'left'})
        self.assertEqual(status, 200, body)
        self.assertFalse(self.w.users[S]['enabled'], 'the account a confirm enabled meanwhile is disabled')
        self.order('iam.record_decision', ('kc', 'GET', r'/users/%s' % S), ('kc', 'PUT', r'/users/%s' % S), 'commit')

    def test_role_change_classified_on_stale_roles(self):
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        self.w.on('iam.record_decision', under_lock(self.w, lambda: self.w.maps.update({S: ['production_manager']}),
                                                    (41, 'applied', [], [])))
        self.w.on('revoke_person_mqtt', [(0,)])
        status, body = self.call('POST', '/api/users/%s/role' % S, {'role': 'auditor', 'reason': 'moved'})
        self.assertEqual(status, 409, body)
        self.assertIn('changed while', body['error'])
        self.assertEqual(self.w.kc_writes(), [])
        self.assertIn(('rollback',), self.w.events)
        self.assertNotIn(('commit',), self.w.events)

    def test_activation_after_a_grant_was_confirmed_meanwhile(self):
        self.w.user(S, 'newbie', enabled=False, person='pS')
        def granted():
            self.w.users[S]['enabled'] = True
            self.w.maps[S] = ['operator']
        self.w.on('iam.record_decision', under_lock(self.w, granted, (42, 'pending_qa', [], [])))
        status, body = self.call('POST', '/api/users/%s/status' % S, {'active': True})
        self.assertEqual(status, 409, body)
        self.assertNotIn(('commit',), self.w.events)

    def test_person_changed_meanwhile(self):
        self.w.user(S, 'sam', roles=['operator'], person='pS')
        self.w.on('iam.record_decision', under_lock(
            self.w, lambda: self.w.users[S]['attributes'].update(person_id=['pZ']), (43, 'pending_qa', [], [])))
        status, body = self.call('POST', '/api/users/%s/person' % S, {'person_id': 'p9', 'reason': 'merge'})
        self.assertEqual(status, 409, body)
        self.assertNotIn(('commit',), self.w.events)


# ── review fixes: compensation (security 3, 10; correctness 2) ─────────────────
class Compensation(Base):
    def setUp(self):
        super().setUp()
        self.staff()

    def test_failed_narrowing_removes_the_added_role(self):
        self.w.user(S, 'sam', roles=['production_manager'], person='pS')
        self.w.on('iam.record_decision', [(8, 'applied', [], [])])
        self.w.on('revoke_person_mqtt', [(0,)])
        self.w.fail.append(('DELETE', r'/users/%s/role-mappings/realm' % S, API.KCError(500, 'boom'), True))
        status, body = self.call('POST', '/api/users/%s/role' % S, {'role': 'operator', 'reason': 'moved'})
        self.assertEqual(status, 502, body)
        self.assertNotIn('drift', body)
        self.assertEqual(self.w.maps[S], ['production_manager'], 'the role added first is removed again')
        self.assertNotIn(('commit',), self.w.events)

    def confirm_setup(self, decision):
        self.as_(QA)
        self.w.on('SELECT request_id, subject_person FROM iam.account_decision', [(5 if decision[1] == 'grant' else None, S)])
        self.w.on('iam.confirm_decision', [decision])
        self.w.on('SELECT email, email_subject, email_body FROM iam.access_request', [('newbie@x.org', 'W', 'Hi')])

    def test_timeout_mid_confirm_is_compensated(self):
        self.w.user(S, 'newbie', enabled=False)
        self.confirm_setup((12, 'grant', S, 'newbie', None, 'operator', S, None))
        self.w.fail.append(('PUT', r'/users/%s' % S, TimeoutError('timed out'), False))
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 502, body)
        self.assertEqual(self.w.maps[S], [])

    def test_failed_commit_undoes_the_grant(self):
        self.w.user(S, 'newbie', enabled=False)
        self.confirm_setup((12, 'grant', S, 'newbie', None, 'operator', S, None))
        self.w.commit_error = PgErr('08006', 'connection lost')
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 503, body)
        self.assertNotIn('drift', body)
        self.assertEqual(self.w.maps[S], [])
        self.assertFalse(self.w.users[S]['enabled'])
        self.assertEqual(self.w.mail, [])

    def test_failed_commit_restores_a_role_change(self):
        self.w.user(S, 'sam', roles=['auditor'], person='pS')
        self.confirm_setup((13, 'role_change', S, 'sam', 'auditor', 'operator', None, None))
        self.w.commit_error = PgErr('08006', 'connection lost')
        status, body = self.call('POST', '/api/decisions/13/confirm', {})
        self.assertEqual(status, 503, body)
        self.assertEqual(self.w.maps[S], ['auditor'])

    def test_role_already_held_is_not_compensated(self):
        # from several roles (from_role NULL) to one of them: nothing is added, so a
        # failure must not take that role away
        self.w.user(S, 'dual', roles=['operator', 'auditor'], person='pS')
        self.confirm_setup((14, 'role_change', S, 'dual', None, 'operator', None, None))
        self.w.fail.append(('DELETE', r'/users/%s/role-mappings/realm' % S, API.KCError(500, 'boom'), True))
        status, body = self.call('POST', '/api/decisions/14/confirm', {})
        self.assertEqual(status, 502, body)
        self.assertEqual(sorted(self.w.maps[S]), ['auditor', 'operator'])

    def test_failed_commit_with_failed_undo_is_drift(self):
        self.w.user(S, 'newbie', enabled=False)
        self.confirm_setup((12, 'grant', S, 'newbie', None, 'operator', S, None))
        self.w.commit_error = PgErr('08006', 'connection lost')
        self.w.fail.append(('PUT', r'/users/%s' % S, API.KCError(500, 'boom'), False))
        # the enable PUT must succeed once: fail only after it
        self.w.fail.pop()
        orig = self.w.kc
        calls = {'n': 0}
        def kc(method, path, body=None):
            if method == 'PUT' and path == '/users/%s' % S:
                calls['n'] += 1
                if calls['n'] > 1:
                    raise API.KCError(500, 'boom')
            return orig(method, path, body)
        API.kc = kc
        status, body = self.call('POST', '/api/decisions/12/confirm', {})
        self.assertEqual(status, 503, body)
        self.assertTrue(body['drift'])
        kinds = {(c['role'], c.get('enabled')) for c in API._COMP_FAILED}
        self.assertIn((None, True), kinds)


# ── review fixes: live checks on every kind and verb (security 6, correctness 1) ─
class LiveChecks(Base):
    def setUp(self):
        super().setUp()
        self.staff()
        self.as_(QA)

    def unit_row(self, subject_person=None):
        self.w.on('SELECT request_id, subject_person FROM iam.account_decision', [(None, subject_person)])
        self.w.on('iam.confirm_decision', [(30, 'unit_assign', S, 'op2', None, None, None, 3)])

    def test_unit_confirm_subject_is_the_approver(self):
        self.w.user(S, 'op2', roles=['operator'], person='pQ')       # declares quinn's person now
        self.unit_row()
        status, body = self.call('POST', '/api/decisions/30/confirm', {'note': API.ATTEST})
        self.assertEqual(status, 403, body)
        self.assertIn('same person as the subject', body['error'])
        self.assertNotIn(('commit',), self.w.events)

    def test_unit_confirm_approver_lost_qa(self):
        self.w.user(S, 'op2', roles=['operator'], person='pS')
        self.w.maps[Q] = ['auditor']
        self.unit_row()
        status, body = self.call('POST', '/api/decisions/30/confirm', {'note': API.ATTEST})
        self.assertEqual(status, 409, body)
        self.assertNotIn(('commit',), self.w.events)

    def test_unit_confirm_deleted_subject(self):
        # confirm_decision inserts the user_unit row now: an account Keycloak no longer
        # has (kc_user 404) gets none — 409, and the insert is rolled back
        self.unit_row()
        status, body = self.call('POST', '/api/decisions/30/confirm', {'note': API.ATTEST})
        self.assertEqual(status, 409, body)
        self.assertIn('no longer exists', body['error'])
        self.assertNotIn(('commit',), self.w.events)
        self.assertIn(('rollback',), self.w.events)

    def test_unit_refuse_deleted_subject(self):
        # refusing stays possible for an account Keycloak no longer has
        self.w.on('SELECT from_role, to_role FROM iam.account_decision', [(None, None)])
        self.w.on('iam.refuse_decision', [(30, 'unit_assign', S, 3, False)])
        status, body = self.call('POST', '/api/decisions/30/refuse', {'note': 'gone'})
        self.assertEqual(status, 200, body)
        self.assertIn(('commit',), self.w.events)

    def test_unit_confirm_assigns_the_unit(self):
        # IAM 2.8: confirm_decision inserts the user_unit row; the answer names the unit
        self.w.user(S, 'op2', roles=['operator'], person='pS')
        self.unit_row('pS')
        self.w.on('FROM medcea.cea_unit WHERE unit_id', [('UNIT03',)])
        status, body = self.call('POST', '/api/decisions/30/confirm', {'note': API.ATTEST})
        self.assertEqual(status, 200, body)
        self.assertEqual(body['message'], 'UNIT03 assigned to op2')
        self.assertEqual(body['applied'], ['UNIT03 assigned to op2'])
        self.order('medcea_auth.set_actor', 'iam.confirm_decision', 'FROM medcea.cea_unit WHERE unit_id', 'commit')
        self.assertEqual(self.w.kc_writes(), [])

    def test_unit_confirm_a_deleted_unit_is_refused(self):
        # iam.confirm_decision raises 22023 when the unit is gone (FK 23503 on the insert)
        self.w.user(S, 'op2', roles=['operator'], person='pS')
        self.w.on('SELECT request_id, subject_person FROM iam.account_decision', [(None, 'pS')])
        self.w.on('iam.confirm_decision', error=PgErr('22023', 'unit 3 no longer exists: refuse decision #30'))
        status, body = self.call('POST', '/api/decisions/30/confirm', {'note': API.ATTEST})
        self.assertEqual(status, 409, body)
        self.assertIn('no longer exists: refuse decision #30', body['error'])
        self.assertNotIn(('commit',), self.w.events)
        self.assertEqual(self.w.kc_writes(), [])

    def test_refuse_and_review_check_the_approver(self):
        self.w.user(S, 'op2', roles=['operator'], person='pS')
        self.w.users[Q]['enabled'] = False
        self.w.on('SELECT from_role, to_role FROM iam.account_decision', [(None, None)])
        self.w.on('iam.refuse_decision', [(30, 'unit_assign', S, 3, True)])
        status, body = self.call('POST', '/api/decisions/30/refuse', {'note': 'no'})
        self.assertEqual(status, 409, body)
        self.assertNotIn(('commit',), self.w.events)
        self.w.on('iam.review_decision', [(31,)])
        self.w.on('SELECT kind, keycloak_user_id FROM iam.account_decision', [('deactivate', S)])
        status, body = self.call('POST', '/api/decisions/31/review', {})
        self.assertEqual(status, 409, body)
        self.assertNotIn(('commit',), self.w.events)

    def test_review_subject_is_the_approver(self):
        self.w.user(S, 'op2', roles=['operator'], person='pQ')
        self.w.on('iam.review_decision', [(31,)])
        self.w.on('SELECT kind, keycloak_user_id FROM iam.account_decision', [('role_change', S)])
        status, body = self.call('POST', '/api/decisions/31/review', {})
        self.assertEqual(status, 403, body)

    def test_activation_without_a_role_confirms(self):
        self.w.user(S, 'sam', enabled=False, person='pS')
        self.w.on('SELECT request_id, subject_person FROM iam.account_decision', [(None, 'pS')])
        self.w.on('iam.confirm_decision', [(32, 'activate', S, 'sam', None, None, None, None)])
        status, body = self.call('POST', '/api/decisions/32/confirm', {})
        self.assertEqual(status, 200, body)
        self.assertTrue(self.w.users[S]['enabled'])


# ── review fixes: refuse reconcile, mail settings, attestation, drift ─────────
class ReviewFixes(Base):
    def setUp(self):
        super().setUp()
        self.staff()

    def test_refused_change_to_a_held_role_keeps_it(self):
        self.as_(QA)
        self.w.user(S, 'dual', roles=['operator', 'engineer'], person='pS')
        self.w.on('SELECT from_role, to_role FROM iam.account_decision', [(None, 'operator')])
        self.w.on('iam.refuse_decision', [(33, 'role_change', S, None, False)])
        status, body = self.call('POST', '/api/decisions/33/refuse', {'note': 'keep both for now'})
        self.assertEqual(status, 200, body)
        self.assertEqual(sorted(self.w.maps[S]), ['engineer', 'operator'])
        self.assertEqual(body['reconciled'], [])

    def test_mail_reason_names_the_account(self):
        self.w.on('iam.record_decision', [(50, 'pending_qa', [], [])])
        status, body = self.call('POST', '/api/settings', {'smtp_user': '', 'from_name': 'MedCEA',
                                                            'reason': 'routine app-password rotation'})
        self.assertEqual(status, 202, body)
        rec = next(e for e in self.w.events if e[0] == 'sql' and 'record_decision' in e[1])
        self.assertTrue(rec[2][7].startswith('mail settings: send as no account through smtp.gmail.com:587'), rec[2][7])
        self.assertTrue(rec[2][7].endswith('Note: routine app-password rotation'))

    def test_decisions_show_the_staged_settings(self):
        row = {c: None for c in API.DEC_COLS}
        row.update(decision_id=50, kind='mail_settings', keycloak_user_id='realm', username='realm mail settings',
                   subject_person='realm', widens=True, widening=[], status='pending_qa', reason='r',
                   made_by_sub=A, made_by_person='pA', made_by_name='alice')
        self.w.on('FROM iam.account_decision d LEFT JOIN', [tuple(row[c] for c in API.DEC_COLS) + (None, None, False)])
        self.w.on('FROM iam.mail_settings WHERE id = 1',
                  [('smtp.gmail.com', 587, 'old@x.org', 'oldpw', 'MedCEA', '', 'alice', None)])
        self.w.on('FROM iam.mail_settings_pending',
                  [(50, 'smtp.gmail.com', 587, 'mine@gmail.com', 'newpw', 'MedCEA', '')])
        self.as_(QA)
        status, body = self.call('GET', '/api/decisions')
        self.assertEqual(status, 200, body)
        m = body['decisions'][0]['mail_settings']
        self.assertEqual((m['smtp_user'], m['current_user'], m['password']), ('mine@gmail.com', 'old@x.org', 'new app password'))
        self.assertNotIn('newpw', json.dumps(body))

    def test_by_rows_need_the_attestation(self):
        self.assertTrue(API.needs_attestation({'kind': 'unit_assign', 'made_by_sub': None, 'made_by_name': 'system:deploy'}))
        self.assertTrue(API.needs_attestation({'kind': 'unit_assign', 'made_by_sub': A,
                                               'made_by_name': 'system:deploy (by alice)'}))
        self.assertFalse(API.needs_attestation({'kind': 'role_change', 'made_by_sub': A, 'made_by_name': 'alice'}))

    def drift(self, history=(), review=None):
        import datetime as dt
        t = lambda d: dt.datetime(2026, 10, d, tzinfo=dt.timezone.utc)
        self.w.on('FROM iam.user_status_history', [(u, r, t(d), i) for i, (u, r, d) in enumerate(history, 1)])
        self.w.on('FROM iam.access_request r', [])
        self.w.on('FROM iam.access_review', [] if review is None else [(json.dumps(review[0]), t(review[1]))])
        con = self.w.connect()
        users = [self.w.users[u] for u in self.w.users]
        held = {u: list(rs) for u, rs in self.w.maps.items()}
        return [(x['username'], x.get('role')) for x in API.compute_drift(con.cursor(), users, held)
                if x['kind'] == 'unexplained_role']

    def test_drift_narrowed_then_readded(self):
        self.w.maps = {}
        self.w.user(S, 'sam', roles=['engineer'])
        self.assertEqual(self.drift([(S, 'engineer', 1), (S, 'operator', 2)]), [('sam', 'engineer')])
        self.assertEqual(self.drift([(S, 'operator', 1), (S, 'engineer', 2)]), [])

    def test_drift_review_explains_only_what_it_flagged(self):
        self.w.maps = {}
        self.w.user(S, 'sam', roles=['operator', 'engineer'])
        snap = {'drift': [{'kind': 'unexplained_role', 'user_id': S, 'role': 'engineer'}],
                'accounts': [{'id': S, 'role': 'operator, engineer'}]}
        self.assertEqual(self.drift([(S, 'operator', 1)], (snap, 5)), [])
        # a role only the accounts list names is not explained
        snap2 = {'drift': [], 'accounts': [{'id': S, 'role': 'operator, engineer'}]}
        self.assertEqual(self.drift([(S, 'operator', 1)], (snap2, 5)), [('sam', 'engineer')])
        # a record after the sign-off replaces what the review accepted
        self.assertEqual(self.drift([(S, 'operator', 1), (S, 'operator', 9)], (snap, 5)), [('sam', 'engineer')])



class ReviewSwitches(unittest.TestCase):
    """The access review records every IAM switch deploy-infra writes (IAM 3.5: IAM_MQTT_PERSON)."""

    def test_switches_in_snapshot(self):
        from unittest import mock

        class Con:
            def cursor(self):
                return None

            def close(self):
                pass
        with mock.patch.object(API, 'kc', return_value=(200, [], None)), \
                mock.patch.object(API, 'role_members', return_value={}), \
                mock.patch.object(API, 'db', return_value=Con()), \
                mock.patch.object(API, 'compute_drift', return_value=[]):
            snap = API.review_snapshot()
        self.assertEqual(set(snap['switches']),
                         {'IAM_ENFORCE', 'IAM_GATES', 'IAM_NETPOL', 'IAM_POSTGREST_JWT', 'IAM_MQTT_PERSON'})
        self.assertIn('as of deploy-infra', snap['switches']['IAM_MQTT_PERSON']['source'])

if __name__ == '__main__':
    unittest.main()
