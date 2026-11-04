"""policy_api: the Policy UI's port of iam-api (IAM Phase 4, slice 4.3; design §5, §14.6).

  :8083  iam  reached only as the upstream of iam-oauth2-proxy (POLICY_DOMAIN; network:
              admits that proxy and the node). Read-only, apart from a qa person's
              confirmation or dispute of a bootstrap or rollback version.

The port enforces the route table whatever IAM_ENFORCE says (copied from access-api's admin
port): /healthz is answered before any check; every other request needs a verified token
with a uuid sub, a person_id claim (never the sub instead) and exactly one own platform
role, and iam._changed_since(sub, person, iat) false. POSTs are JSON (415) from the Policy
UI's own Origin (403).

Reads run as iam_svc (SELECT on iam_policy): the version list, a version's matrix composed
with the skeleton this pod ships (ConfigMap iam-compiler: apps/iam/compiler and
policy/defaults.yaml, so a version is shown with the skeleton the platform accepted),
explain.cell, the policy events, audit_versions() and verify_chain(). Confirm and dispute
are forwarded to config-api's /rpc/confirm_policy and /rpc/dispute_policy with the person's
own token (design §1.1): iam_svc cannot execute them, and the database's _qa() checks the
token's azp, the person and the attestation itself. Nothing here calls Keycloak.

Served in 4.3: GET /, /healthz, /api/me, /api/policy, /api/policy/<v>, /api/policy/<v>/explain,
/api/policy/history, /api/policy/chain; POST /api/policy/<v>/confirm, /dispute. The route
table's other iam routes (draft, entry, submit, withdraw, approve, return, diff, who-can,
service-identities, break-glass) arrive with 4.4 and answer 404 until then.
"""
import json, os, re, sys, time, urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler

E = os.environ
POLICY_ORIGIN = 'https://' + E['POLICY_DOMAIN'] if E.get('POLICY_DOMAIN') else ''
ACCESS_URL = 'https://%s/' % E['ACCESS_DOMAIN'] if E.get('ACCESS_DOMAIN') else ''   # the User Manager's links
CONFIG_API_URL = E.get('CONFIG_API_URL', 'http://config-api:3000').rstrip('/')
COMPILER_DIR = E.get('MEDCEA_COMPILER_DIR', '/opt/iam')   # holds compiler/ and policy/defaults.yaml
HTML_FILE = E.get('POLICY_HTML', '/app/policy.html')
ATTEST = 'I did not run apply.sh for this version.'      # iam_policy.confirm_applied's p_attest
HISTORY_LIMIT = 500
_VERSION = re.compile(r'^(?:[1-9][0-9]{0,8}|applied)$')
_KEY = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
# The policy events (infra/lib-policy-source.sh _PS_POLICY_EVENTS): a version's own events and
# the deploys' policy records; never the account or MQTT events of the same chain.
POLICY_EVENTS = """(h.version IS NOT NULL OR h.event IN ('account_seeded', 'break_glass_seen', 'break_glass_ended')
                    OR h.event LIKE 'skeleton\\_%%' OR h.event LIKE 'apply\\_%%' OR h.event LIKE 'bootstrap\\_%%'
                    OR h.event LIKE 'waiver\\_%%' OR h.event LIKE 'policy\\_%%')"""
VERSION_COLS = ('version', 'kind', 'status', 'reason', 'based_on', 'rollback_of', 'created_at', 'created_by_name',
                'submitted_at', 'submitted_by_name', 'approved_at', 'approved_by_name', 'applied_at',
                'confirmed_at', 'confirm_note', 'disputed_at', 'dispute_note', 'withdrawn_at', 'superseded_at',
                'claimed_by_person', 'entries_digest', 'skeleton_digest')

# set by iam-api.py, which owns the connection, the library loader and the log
db = None
medcea_iam = None
log = print


class Refused(Exception):
    def __init__(self, status, error):
        super().__init__(status, error)
        self.status, self.error = status, error


def sqlstate(e):
    a = e.args[0] if getattr(e, 'args', None) else None
    if isinstance(a, dict):
        return a.get('C'), a.get('M') or ''
    return None, None


def db_refusal(e):
    """access-api's mapping: a missing privilege or function is deploy order (503); any other
    42501 is the database refusing the person (403); 22023/23505 are a conflict (409)."""
    code, msg = sqlstate(e)
    if code in ('42883', '42P01', '3F000') or (code == '42501' and msg.startswith('permission denied for')):
        log('database: %s %s — run ./apps/database/deploy.sh' % (code, msg))
        return 503, {'error': 'the Policy UI lacks a database grant, table or function (%s): '
                              'run ./apps/database/deploy.sh' % msg}
    if code == '42501':
        return 403, {'error': msg}
    if code in ('22023', '23505'):
        return 409, {'error': msg}
    return None


# ── the compiler this pod ships (ConfigMap iam-compiler) ──────────────────────────────
_COMPILER = {}


def compiler():
    """(source, model, invariants, explain) from COMPILER_DIR; None while it is not mounted."""
    if 'mods' not in _COMPILER:
        try:
            if COMPILER_DIR not in sys.path:
                sys.path.insert(0, COMPILER_DIR)
            from compiler import explain, invariants, model, source
            _COMPILER['mods'] = (source, model, invariants, explain)
            _COMPILER['skel'] = source.skeleton(source.factory())
            _COMPILER['skeleton_digest'] = source.skeleton_digest(_COMPILER['skel'])
            _COMPILER['compiler_digest'] = source.compiler_digest() if hasattr(source, 'compiler_digest') else None
        except Exception as e:                     # noqa: BLE001 — a missing mount must not stop the pod
            log('compiler: not loaded from %s (%s: %s)' % (COMPILER_DIR, type(e).__name__, e))
            return None
    return _COMPILER['mods']


def rows(cur, sql, args=()):
    cur.execute(sql, args)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def iso(x):
    return x.isoformat() if hasattr(x, 'isoformat') else x


def jsonable(d):
    return {k: iso(v) for k, v in d.items()}


def applied_version(cur):
    cur.execute("SELECT version FROM iam_policy.version WHERE status = 'applied'")
    r = cur.fetchone()
    return r[0] if r else None


def resolve_version(cur, v):
    if v == 'applied':
        n = applied_version(cur)
        if n is None:
            raise Refused(404, 'no version of the access policy is applied yet')
        return n
    return int(v)


_COMPOSED = {}


def composed(cur, version):
    """(Policy, dropped) of a version's rows with the shipped skeleton; cached per version
    while its entries digest is unchanged (a draft's rows change; an applied version's never)."""
    source, model, _inv, _ex = compiler()
    cur.execute('SELECT entries_digest FROM iam_policy.version WHERE version = %s', (version,))
    r = cur.fetchone()
    if r is None:
        raise Refused(404, 'no version %s' % version)
    key = (version, r[0])
    if key in _COMPOSED and r[0]:
        return _COMPOSED[key]
    entries = rows(cur, 'SELECT role, group_code, level::text AS level, constraint_name FROM iam_policy.entry '
                        'WHERE version = %s ORDER BY role, group_code, level', (version,))
    waivers = rows(cur, 'SELECT id, invariant, subject, group_code, target, levels::text[] AS levels, review_by, '
                        'rationale, controls, objects FROM iam_policy.waiver WHERE version = %s ORDER BY id', (version,))
    for e in entries:
        e['level'] = (e['level'] or '').strip()
    ew = {'entries': entries, 'waivers': [source.waiver_from_row(w) for w in waivers]}
    data, dropped = source.compose_counted(_COMPILER['skel'], ew, drop_unknown=True)
    out = (model.Policy(data), dropped)
    _COMPOSED[key] = out
    return out


def policy_doc(p, dropped, invariants):
    """The Matrix tab's document: every name with its help, the cells, the waivers, the
    checker's verdicts."""
    errors, notes = invariants.check(p)
    cells = {}
    for g in p.groups:
        for r in p.roles:
            c = p.cell(g, r)
            if c:
                cells.setdefault(g, {})[r] = {'levels': sorted(c[0], key=list(p.levels).index),
                                              'constraints': dict(sorted(c[1].items()))}
    return {
        'levels': [{'key': k, 'name': v.get('name'), 'summary': v.get('summary'), 'help': v.get('help'),
                    'implies': v.get('implies') or []} for k, v in p.levels.items()],
        'roles': [{'key': k, 'label': v.get('label'), 'includes': v.get('includes') or [],
                   'availability': v.get('availability'), 'help': v.get('description')
                   or '; '.join(v.get('responsibilities') or [])} for k, v in p.roles.items()],
        'groups': [{'key': k, 'label': v.get('label'), 'class': v.get('class'), 'risk': v.get('risk'),
                    'help': v.get('description'), 'members': len(v.get('members') or [])} for k, v in p.groups.items()],
        'constraints': {k: v.get('help') or v.get('description') for k, v in p.constraints.items()},
        'cells': cells,
        'not_granted': [g for g in p.groups if g not in cells],
        'waivers': [{k: iso(v) for k, v in w.items()} for w in p.waivers],
        'checker': {'errors': errors, 'notes': notes},
        'dropped': dropped,
    }


# ── config-api forwarding (confirm, dispute) ──────────────────────────────────────────
def switches_ok(cur):
    iam = medcea_iam_mod()
    s = iam.settings() if iam is not None and hasattr(iam, 'settings') else {}
    jwt = (s.get('switches') or {}).get('IAM_POSTGREST_JWT') is True
    cur.execute("SELECT pg_catalog.current_setting('medcea.iam_db_roles', true)")
    r = cur.fetchone()
    return jwt and (r[0] if r else None) == 'true'


def forward(rpc, args, token):
    """POST config-api /rpc/<rpc> with the person's own token; (status, payload)."""
    req = urllib.request.Request(CONFIG_API_URL + '/rpc/' + rpc, data=json.dumps(args).encode(), method='POST',
                                 headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200, {'ok': True}
    except urllib.error.HTTPError as e:
        with e:
            try:
                body = json.loads(e.read() or b'{}')
            except ValueError:
                body = {}
        code, msg = body.get('code'), body.get('message') or ''
        if e.code == 401 and code != '42501':
            return 401, {'error': 'sign in again', 'reauth': True}
        if code == '42501' and msg.startswith('permission denied for'):
            return 503, {'error': 'confirmation needs IAM_DB_ROLES=true (the database refused: %s)' % msg}
        if code == '42501':
            return 403, {'error': msg}
        if code in ('22023', '23505', 'P0001'):
            return 409, {'error': msg}
        log('config-api answered %s %s on %s' % (e.code, code, rpc))
        return 502, {'error': 'config-api refused the request (%s %s)' % (e.code, code or '')}
    except (urllib.error.URLError, OSError) as e:
        log('config-api unreachable on %s: %s' % (rpc, e))
        return 503, {'error': 'config-api cannot be reached'}


# ── HTTP ──────────────────────────────────────────────────────────────────────────────
class PolicyAdmin(BaseHTTPRequestHandler):
    server_version = 'medcea-iam'
    IAM_SERVICE = 'iam'

    def parse_request(self):
        if not super().parse_request():
            return False
        if self.path == '/healthz':
            return True                          # liveness: answered before any check
        iam = medcea_iam_mod()
        if iam is None:
            self.send(503, {'error': 'access policy not loaded'})
            return False
        if not iam.http_check(self, self.IAM_SERVICE, enforce=True):
            return False
        w = self.who()
        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', str(w.get('sub') or '')):
            self.send(401, {'error': 'sign in'})
            return False
        if not w.get('person_id'):
            self.send(403, {'error': 'your account has no person_id: ask an administrator (./deploy-infra.sh sets one)'})
            return False
        return True

    def log_message(self, fmt, *args):
        if not self.path.startswith('/healthz'):
            log('%s %s' % (self.address_string(), fmt % args))

    def send(self, status, payload, ctype='application/json'):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def who(self):
        return getattr(getattr(self, 'medcea_iam', None), 'who', None) or {}

    def role(self):
        iam = medcea_iam_mod()
        r = iam.actor_role(self.medcea_iam) if iam is not None and hasattr(iam, 'actor_role') else None
        if not r:
            raise Refused(403, 'your account holds more than one platform role; ask an administrator')
        return r

    def can(self, method, path):
        iam = medcea_iam_mod()
        return bool(iam is not None and hasattr(iam, 'allows')
                    and iam.allows(list(self.who().get('roles') or []), self.IAM_SERVICE, method, path))

    def guarded(self, fn):
        con = None
        try:
            con = db()
            cur = con.cursor()
            w = self.who()
            self.role()
            cur.execute('SELECT iam._changed_since(%s, %s, %s)', (w['sub'], w.get('person_id'), w.get('iat')))
            if cur.fetchone()[0]:
                raise Refused(403, 'your access changed since you signed in: reload the page')
            self.send(*fn(cur))
        except Refused as e:
            self.send(e.status, {'error': e.error})
        except (ValueError, KeyError) as e:
            self.send(400, {'error': str(e)})
        except Exception as e:                   # noqa: BLE001
            mapped = db_refusal(e)
            if mapped:
                return self.send(*mapped)
            log('error on %s %s: %s' % (self.command, self.path.split('?', 1)[0], type(e).__name__))
            self.send(500, {'error': 'Something went wrong on our side. Please try again later.'})
        finally:
            if con is not None:
                try:
                    con.rollback()                   # reads only: nothing to keep
                    con.close()
                except Exception:                    # noqa: BLE001
                    pass

    # ── GET ──────────────────────────────────────────────────────────────────────
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p, q = u.path, urllib.parse.parse_qs(u.query)
        if p == '/healthz':
            return self.send(200, healthz())
        if p == '/':
            try:
                with open(HTML_FILE, 'rb') as fh:
                    return self.send(200, fh.read(), 'text/html')
            except OSError:
                return self.send(503, {'error': 'policy.html is missing: run ./apps/iam/deploy.sh'})
        if p == '/api/me':
            return self.guarded(lambda cur: (200, self.me()))
        if p == '/api/policy':
            return self.guarded(versions)
        if p == '/api/policy/history':
            return self.guarded(lambda cur: history(cur, (q.get('version') or [''])[0]))
        if p == '/api/policy/chain':
            return self.guarded(chain)
        m = re.fullmatch(r'/api/policy/([^/]+)(/explain)?', p)
        if m and _VERSION.match(m.group(1)):
            if compiler() is None:
                return self.send(503, {'error': 'the compiler is not mounted (ConfigMap iam-compiler): run ./apps/iam/deploy.sh'})
            if m.group(2):
                role, group = (q.get('role') or [''])[0], (q.get('group') or [''])[0]
                if not (_KEY.match(role) and _KEY.match(group)):
                    return self.send(400, {'error': 'role and group are required'})
                return self.guarded(lambda cur: explain_cell(cur, m.group(1), role, group))
            return self.guarded(lambda cur: version_doc(cur, m.group(1)))
        self.send(404, {'error': 'not found'})

    def me(self):
        w = self.who()
        return {'user': w.get('username'), 'person': w.get('person_id'), 'role': self.role(),
                'can': {'matrix': self.can('GET', '/api/policy/1'), 'history': self.can('GET', '/api/policy/history'),
                        'confirm': self.can('POST', '/api/policy/1/confirm')},
                'attest': ATTEST, 'policy_origin': POLICY_ORIGIN, 'access_url': ACCESS_URL}

    # ── POST ─────────────────────────────────────────────────────────────────────
    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        m = re.fullmatch(r'/api/policy/([1-9][0-9]{0,8})/(confirm|dispute)', p)
        if not m:
            return self.send(404, {'error': 'not found'})
        ctype = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if ctype != 'application/json':
            return self.send(415, {'error': 'send JSON (Content-Type: application/json)'})
        if not POLICY_ORIGIN or self.headers.get('Origin') != POLICY_ORIGIN:
            log('refused a POST to %s from origin %r' % (p, self.headers.get('Origin')))
            return self.send(403, {'error': 'cross-origin request refused'})
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if n > 64 * 1024:
                raise ValueError('request too large')
            body = json.loads(self.rfile.read(n) or b'{}')
            if not isinstance(body, dict):
                raise ValueError('send a JSON object')
        except ValueError as e:
            return self.send(400, {'error': str(e)})
        version, verb = int(m.group(1)), m.group(2)
        note = str(body.get('note') or '').strip()
        token = self.headers.get('X-Forwarded-Access-Token') or ''
        if token.lower().startswith('bearer '):
            token = token[7:]
        if not token:
            auth = self.headers.get('Authorization') or ''
            token = auth[7:] if auth.lower().startswith('bearer ') else ''

        def act(cur):
            if not note:
                raise Refused(400, 'a note is required')
            if not switches_ok(cur):
                raise Refused(503, 'confirmation needs IAM_POSTGREST_JWT and IAM_DB_ROLES to be true')
            if verb == 'confirm':
                args = {'p_version': version, 'p_note': note, 'p_attest': str(body.get('attest') or '')}
            else:
                args = {'p_version': version, 'p_note': note}
            status, payload = forward(verb + '_policy', args, token)
            log('%s of version %d by %s: %s' % (verb, version, self.who().get('username'), status))
            return status, payload
        self.guarded(act)


def medcea_iam_mod():
    return medcea_iam() if callable(medcea_iam) else medcea_iam


def versions(cur):
    vs = rows(cur, 'SELECT %s FROM iam_policy.version ORDER BY version DESC' % ', '.join(VERSION_COLS))
    out = []
    for v in vs:
        d = jsonable(v)
        if v['status'] in ('draft', 'submitted', 'approved'):
            w = rows(cur, 'SELECT may_approve, why_not_code, needs_token_path FROM iam_policy.why_not(%s)', (v['version'],))
            d['why_not'] = w[0] if w else None
        d['needs_confirmation'] = (v['kind'] in ('bootstrap', 'rollback') and v['status'] in ('applied', 'superseded')
                                   and v['confirmed_at'] is None and v['disputed_at'] is None)
        out.append(d)
    return 200, {'versions': out, 'applied': applied_version(cur),
                 'skeleton_digest': _COMPILER.get('skeleton_digest')}


def version_doc(cur, v):
    source, model, invariants, _ex = compiler()
    n = resolve_version(cur, v)
    p, dropped = composed(cur, n)
    doc = policy_doc(p, dropped, invariants)
    doc.update(version=n, skeleton_digest=_COMPILER['skeleton_digest'])
    return 200, doc


def explain_cell(cur, v, role, group):
    _s, _m, _i, explain = compiler()
    n = resolve_version(cur, v)
    p, _ = composed(cur, n)
    a = applied_version(cur)
    pa = composed(cur, a)[0] if a is not None and a != n else (p if a == n else None)
    try:
        return 200, explain.cell(p, pa, role, group)
    except KeyError as e:
        raise Refused(404, str(e.args[0]))


def history(cur, version):
    args, where = (), POLICY_EVENTS
    if version:
        if not re.match(r'^[1-9][0-9]{0,8}$', version):
            raise ValueError('version must be a number')
        where, args = 'h.version = %s', (int(version),)
    ev = rows(cur, 'SELECT h.event_id, h.at, h.event, h.version, h.actor_name, h.reason, h.payload::text AS payload '
                   'FROM iam_policy.history h WHERE %s ORDER BY h.event_id DESC LIMIT %d' % (where, HISTORY_LIMIT), args)
    for e in ev:
        try:
            e['payload'] = json.loads(e['payload'] or '{}')
        except ValueError:
            pass
    findings = rows(cur, 'SELECT version, finding, detail::text AS detail FROM iam_policy.audit_versions()')
    return 200, {'events': [jsonable(e) for e in ev], 'findings': findings, 'limit': HISTORY_LIMIT}


def chain(cur):
    try:
        r = rows(cur, 'SELECT ok, events, first_bad_event, detail, head FROM iam_policy.verify_chain()')
    except Exception as e:                     # noqa: BLE001 — "cannot verify" is an answer
        code, msg = sqlstate(e)
        return 200, {'ok': None, 'detail': 'cannot verify: %s' % (msg or type(e).__name__)}
    return 200, jsonable(r[0]) if r else {'ok': None, 'detail': 'cannot verify: no answer'}


_HEALTH = {}


def healthz():
    """{policy_port, enforce_always, applied_version, skeleton_digest, compiler_digest}; the
    applied version is read at most every 30 s (probes come every 10 s)."""
    now = time.time()
    if now - _HEALTH.get('at', 0) > 30:
        av = None
        try:
            con = db()
            try:
                cur = con.cursor()
                av = applied_version(cur)
            finally:
                con.close()
        except Exception:                        # noqa: BLE001 — health answers without the database
            av = None
        _HEALTH.update(at=now, applied_version=av)
    compiler()
    return {'service': 'iam', 'policy_port': True, 'enforce_always': True,
            'applied_version': _HEALTH.get('applied_version'),
            'skeleton_digest': _COMPILER.get('skeleton_digest'), 'compiler_digest': _COMPILER.get('compiler_digest')}
