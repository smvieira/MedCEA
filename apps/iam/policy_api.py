"""policy_api: the Policy UI's port of iam-api (IAM Phase 4, slices 4.3–4.5; design §5, §14.6–§14.8).

  :8083  iam  reached only as the upstream of iam-oauth2-proxy (POLICY_DOMAIN; network:
              admits that proxy and the node).

The port enforces the route table whatever IAM_ENFORCE says (copied from access-api's admin
port): /healthz is answered before any check; every other request needs a verified token
with a uuid sub, a person_id claim (never the sub instead) and exactly one own platform
role, and iam._changed_since(sub, person, iat) false. POSTs and PUTs are JSON (415) from
the Policy UI's own Origin (403).

Reads run as iam_svc (SELECT on iam_policy): the version list (why_not after set_actor, so
it answers for the viewer; since 4.5 each version's apply state, from the latest of its apply
events: rollout incomplete, or reverted), a version's matrix composed with the skeleton this pod ships
(ConfigMap iam-compiler: apps/iam/compiler and policy/defaults.yaml, so a version is shown
with the skeleton the platform accepted), explain.cell, a version's approval diff
(explain.diff_document, served as its canonical bytes), who can reach an object, the
service identities and break-glass identities, the policy events, audit_versions() and
verify_chain().

Writes (4.4) run as iam_svc in one transaction (written()): the version advisory lock the
author functions take, before any row iam-api checks is read, then set_actor from the
token (person_id, never the sub) and the author function: new_draft (with one unchanged
save_entry that records the checker's verdict at creation), save_entry (the whole cell),
submit (the checker run again on the stored rows) and withdraw.

Approve, return, confirm and dispute are forwarded to config-api's /rpc/<verb>_policy with
the person's own token (design §1.1): iam_svc cannot execute them, and the database's _qa()
checks the token's azp, the person and the attestation itself. Before an approval is
forwarded iam-api checks what qa saw: the diff digest (recomputed for a change, the host's
stored one for a skeleton version), the skeleton it was computed on, and that the version
widens no role the approver holds. Nothing here calls Keycloak.
"""
import hashlib, json, os, re, sys, time, urllib.error, urllib.parse, urllib.request, weakref
from http.server import BaseHTTPRequestHandler

E = os.environ
POLICY_ORIGIN = 'https://' + E['POLICY_DOMAIN'] if E.get('POLICY_DOMAIN') else ''
ACCESS_URL = 'https://%s/' % E['ACCESS_DOMAIN'] if E.get('ACCESS_DOMAIN') else ''   # the User Manager's links
CONFIG_API_URL = E.get('CONFIG_API_URL', 'http://config-api:3000').rstrip('/')
COMPILER_DIR = E.get('MEDCEA_COMPILER_DIR', '/opt/iam')   # holds compiler/ and policy/defaults.yaml
HTML_FILE = E.get('POLICY_HTML', '/app/policy.html')
ATTEST = 'I did not run apply.sh for this version.'      # iam_policy.confirm_applied's p_attest
# iam_policy.approve's skeleton-version attestation (design §14.7.1 item 2): p_note begins with it
SKELETON_ATTEST = 'I did not run apply.sh --propose-skeleton for this version.'
HISTORY_LIMIT = 500
_VERSION = re.compile(r'^(?:[1-9][0-9]{0,8}|applied)$')
_KEY = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_FROM = re.compile(r'^(?:applied|defaults|[1-9][0-9]{0,8})$')
_DIGEST = re.compile(r'^[0-9a-f]{64}$')
# The version lock the author functions take inside (008c new_draft, save_entry, submit,
# withdraw); written() takes it first, so the rows iam-api checks are the rows it saves.
VERSION_LOCK = "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'))"
# iam_policy._authors' event list (008c): a version's makers
AUTHOR_EVENTS = ('draft_created', 'entry_saved', 'waiver_saved', 'waiver_dropped', 'submitted')
OPEN = ('draft', 'submitted', 'approved')
# The write capabilities that are not tabs (/api/me `acts`), each as the route that grants it
ACTS = {'draft': ('POST', '/api/policy/draft'), 'edit': ('PUT', '/api/policy/1/entry'),
        'submit': ('POST', '/api/policy/1/submit'), 'withdraw': ('POST', '/api/policy/1/withdraw'),
        'approve': ('POST', '/api/policy/1/approve'), 'return': ('POST', '/api/policy/1/return')}
# The open policy break-glass overrides: infra/lib-policy-source.sh's break_glass_open predicate
BREAK_GLASS_OPEN = """
SELECT b.event_id, b.at, b.open AS components
  FROM (SELECT h.event_id, h.at,
               (SELECT coalesce(pg_catalog.jsonb_agg(c.value ORDER BY c.value), '[]')
                  FROM pg_catalog.jsonb_array_elements_text(CASE WHEN pg_catalog.jsonb_typeof(h.payload -> 'components') = 'array'
                                                                THEN h.payload -> 'components' ELSE '[]' END) AS c(value)
                 WHERE NOT EXISTS (SELECT 1 FROM iam_policy.history e
                                    WHERE e.event = 'break_glass_ended'
                                      AND e.payload ->> 'since_event' = h.event_id::text
                                      AND e.payload ->> 'component' = c.value))::text AS open
          FROM iam_policy.history h
         WHERE h.event = 'break_glass_seen' AND h.payload ->> 'source' = 'file') b
 WHERE b.open <> '[]'
 ORDER BY b.event_id"""
# The policy events (infra/lib-policy-source.sh _PS_POLICY_EVENTS): a version's own events and
# the deploys' policy records; never the account or MQTT events of the same chain.
POLICY_EVENTS = """(h.version IS NOT NULL OR h.event IN ('account_seeded', 'break_glass_seen', 'break_glass_ended')
                    OR h.event LIKE 'skeleton\\_%%' OR h.event LIKE 'apply\\_%%' OR h.event LIKE 'bootstrap\\_%%'
                    OR h.event LIKE 'waiver\\_%%' OR h.event LIKE 'policy\\_%%')"""
# A version's apply state (IAM 4.5, design §14.8.12): the latest of these events filed under it
APPLY_EVENTS = ('apply_started', 'applied', 'bootstrap_applied', 'partial_apply', 'apply_reverted')
APPLY_LATEST = """
SELECT DISTINCT ON (h.version) h.version, h.event, h.payload ->> 'outcome' AS outcome
  FROM iam_policy.history h
 WHERE h.version IS NOT NULL AND h.event IN (%s)
 ORDER BY h.version, h.event_id DESC""" % ', '.join("'%s'" % e for e in APPLY_EVENTS)
VERSION_COLS = ('version', 'kind', 'status', 'reason', 'based_on', 'rollback_of', 'created_at', 'created_by_name',
                'submitted_at', 'submitted_by_name', 'approved_at', 'approved_by_name', 'applied_at',
                'confirmed_at', 'confirm_note', 'disputed_at', 'dispute_note', 'withdrawn_at', 'superseded_at',
                'claimed_by_person', 'entries_digest', 'skeleton_digest', 'checker_verdict', 'returned_at',
                'return_note', 'approval_note', 'diff_digest', 'approved_skeleton_digest', 'withdrawn_by',
                'created_by_person')

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
    42501 is the database refusing the person (403); 22023/23505 are a conflict (409); 55000
    is iam_policy._changed_since without the access component (503)."""
    code, msg = sqlstate(e)
    if code == '55000':
        log('database: %s %s' % (code, msg))
        return 503, {'error': 'the Policy UI needs the access component: run ./apps/access/deploy.sh'}
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


def version_rows(cur, version):
    """(entries, waivers) of a version as the tables store them."""
    entries = rows(cur, 'SELECT role, group_code, level::text AS level, constraint_name FROM iam_policy.entry '
                        'WHERE version = %s ORDER BY role, group_code, level', (version,))
    waivers = rows(cur, 'SELECT id, invariant, subject, group_code, target, levels::text[] AS levels, review_by, '
                        'rationale, controls, objects FROM iam_policy.waiver WHERE version = %s ORDER BY id', (version,))
    for e in entries:
        e['level'] = (e['level'] or '').strip()
    return entries, waivers


def compose_rows(entries, waivers):
    """(Policy, dropped) of entry and waiver rows with the shipped skeleton."""
    source, model, _inv, _ex = compiler()
    ew = {'entries': entries, 'waivers': [source.waiver_from_row(w) for w in waivers]}
    data, dropped = source.compose_counted(_COMPILER['skel'], ew, drop_unknown=True)
    return model.Policy(data), dropped


def composed(cur, version):
    """(Policy, dropped) of a version's rows with the shipped skeleton; cached per version
    while its entries digest is unchanged, never for a draft (its rows change, and a returned
    draft keeps the digest of its submission)."""
    compiler()
    cur.execute('SELECT entries_digest, status FROM iam_policy.version WHERE version = %s', (version,))
    r = cur.fetchone()
    if r is None:
        raise Refused(404, 'no version %s' % version)
    key = (version, r[0])
    cache = bool(r[0]) and r[1] != 'draft'
    if cache and key in _COMPOSED:
        return _COMPOSED[key]
    out = compose_rows(*version_rows(cur, version))
    if cache:
        _COMPOSED[key] = out
    return out


def verdict_of(p):
    """The checker's verdict on a composed Policy: (verdict for save_entry, answer for the page)."""
    _s, _m, invariants, _ex = compiler()
    errors, notes = invariants.check(p)
    return ({'ok': not errors, 'errors': errors[:100], 'checker_digest': _COMPILER.get('compiler_digest')},
            {'ok': not errors, 'errors': errors, 'notes': notes})


def role_closure(role):
    """The roles `role` includes (Keycloak composites), transitively, from the pod's skeleton;
    the role itself left out."""
    compiler()
    roles = _COMPILER.get('skel', {}).get('roles') or {}
    seen, todo = set(), [role]
    while todo:
        for inc in (roles.get(todo.pop()) or {}).get('includes') or []:
            if inc not in seen:
                seen.add(inc)
                todo.append(inc)
    seen.discard(role)
    return sorted(seen, key=lambda r: r.encode())


def bytewise(xs):
    return sorted(xs, key=lambda x: x.encode())


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


# ── config-api forwarding (approve, return, confirm, dispute) ─────────────────────────
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
        if code == '28000':                    # pre_request (only_rpc, a read-only client), PostgREST's 403
            return 403, {'error': msg}
        if code in ('42883', 'PGRST202'):      # the function is missing: deploy order
            log('config-api answered %s %s on %s: run ./apps/database/deploy.sh' % (e.code, code, rpc))
            return 503, {'error': 'config-api has no %s yet: run ./apps/database/deploy.sh' % rpc}
        if e.code == 401 and code != '42501':
            return 401, {'error': 'sign in again', 'reauth': True}
        if code == '42501' and msg.startswith('permission denied for'):
            return 503, {'error': 'approvals need IAM_POSTGREST_JWT=true and IAM_DB_ROLES=true (the database refused: %s)' % msg}
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

    def send(self, status, payload, ctype='application/json', headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
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

    def actor(self):
        """set_actor's (sub, person, username, role): the person_id claim, never the sub
        (parse_request refused a token without one)."""
        w = self.who()
        return w['sub'], w['person_id'], w.get('username'), self.role()

    def can(self, method, path):
        iam = medcea_iam_mod()
        return bool(iam is not None and hasattr(iam, 'allows')
                    and iam.allows(list(self.who().get('roles') or []), self.IAM_SERVICE, method, path))

    def guarded(self, fn):
        """fn(cur) in a read transaction as iam_svc, rolled back whatever happens."""
        self._run(fn, write=False)

    def written(self, fn):
        """fn(cur) in one write transaction as iam_svc: the version lock (before any row
        iam-api checks is read), set_actor from the token, the changed_since check, fn,
        commit when fn answered below 400; anything else is rolled back."""
        self._run(fn, write=True)

    def _run(self, fn, write):
        con = None
        try:
            con = db()
            cur = con.cursor()
            w = self.who()
            actor = self.actor()
            if write:
                cur.execute(VERSION_LOCK)
                cur.execute('SELECT medcea_auth.set_actor(%s, %s, %s, %s)', actor)
            cur.execute('SELECT iam._changed_since(%s, %s, %s)', (w['sub'], w.get('person_id'), w.get('iat')))
            if cur.fetchone()[0]:
                raise Refused(403, 'your access changed since you signed in: reload the page')
            answer = fn(cur)
            if write and answer[0] < 400:
                con.commit()
            self.send(*answer)
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
                    con.rollback()                   # reads, a refusal, or after the commit: nothing left
                    con.close()
                except Exception:                    # noqa: BLE001
                    pass

    # ── GET ──────────────────────────────────────────────────────────────────────
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p, q = u.path, urllib.parse.parse_qs(u.query)
        arg = lambda k: (q.get(k) or [''])[0]       # noqa: E731
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
            return self.guarded(lambda cur: versions(cur, self.actor()))
        if p == '/api/policy/history':
            return self.guarded(lambda cur: history(cur, arg('version')))
        if p == '/api/policy/chain':
            return self.guarded(chain)
        if compiler() is None and p.startswith('/api/policy/'):
            return self.send(503, {'error': 'the compiler is not mounted (ConfigMap iam-compiler): run ./apps/iam/deploy.sh'})
        # literal paths first: the generic /api/policy/<v> below would read them as versions
        if p == '/api/policy/who-can':
            return self.guarded(lambda cur: who_can(cur, arg('version') or 'applied', arg('object'), arg('level')))
        if p == '/api/policy/service-identities':
            return self.guarded(lambda cur: (200, service_identities()))
        if p == '/api/policy/break-glass':
            return self.guarded(break_glass)
        m = re.fullmatch(r'/api/policy/([^/]+)/diff', p)
        if m and _VERSION.match(m.group(1)):
            if (arg('against') or 'applied') != 'applied':
                return self.send(400, {'error': 'a diff is against the applied version only (against=applied)'})
            return self.guarded(lambda cur: diff_response(cur, m.group(1)))
        m = re.fullmatch(r'/api/policy/([^/]+)(/explain)?', p)
        if m and _VERSION.match(m.group(1)):
            if m.group(2):
                role, group = arg('role'), arg('group')
                if not (_KEY.match(role) and _KEY.match(group)):
                    return self.send(400, {'error': 'role and group are required'})
                return self.guarded(lambda cur: explain_cell(cur, m.group(1), role, group))
            return self.guarded(lambda cur: version_doc(cur, m.group(1)))
        self.send(404, {'error': 'not found'})

    def me(self):
        w = self.who()
        role = self.role()
        return {'user': w.get('username'), 'person': w.get('person_id'), 'role': role,
                'includes': role_closure(role) if compiler() is not None else [],
                'can': {'matrix': self.can('GET', '/api/policy/1'), 'changes': self.can('GET', '/api/policy'),
                        'approval': self.can('POST', '/api/policy/1/approve'),
                        'whocan': self.can('GET', '/api/policy/who-can'),
                        'identities': self.can('GET', '/api/policy/service-identities'),
                        'breakglass': self.can('GET', '/api/policy/break-glass'),
                        'history': self.can('GET', '/api/policy/history'),
                        'confirm': self.can('POST', '/api/policy/1/confirm')},
                'acts': {k: self.can(*mp) for k, mp in ACTS.items()},
                'attest': ATTEST, 'skeleton_attest': SKELETON_ATTEST,
                'policy_origin': POLICY_ORIGIN, 'access_url': ACCESS_URL}

    # ── POST, PUT ────────────────────────────────────────────────────────────────
    def _body(self, p):
        """The request's JSON object; None after answering 415, 403 or 400."""
        ctype = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if ctype != 'application/json':
            self.send(415, {'error': 'send JSON (Content-Type: application/json)'})
            return None
        if not POLICY_ORIGIN or self.headers.get('Origin') != POLICY_ORIGIN:
            log('refused a %s to %s from origin %r' % (self.command, p, self.headers.get('Origin')))
            self.send(403, {'error': 'cross-origin request refused'})
            return None
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if n > 64 * 1024:
                raise ValueError('request too large')
            body = json.loads(self.rfile.read(n) or b'{}')
            if not isinstance(body, dict):
                raise ValueError('send a JSON object')
        except ValueError as e:
            self.send(400, {'error': str(e)})
            return None
        return body

    def _token(self):
        """The person's own token, as the proxy forwarded it; never logged."""
        token = self.headers.get('X-Forwarded-Access-Token') or ''
        if token.lower().startswith('bearer '):
            token = token[7:]
        if not token:
            auth = self.headers.get('Authorization') or ''
            token = auth[7:] if auth.lower().startswith('bearer ') else ''
        return token

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        if p == '/api/policy/draft':
            body = self._body(p)
            if body is not None:
                self.written(lambda cur: new_draft(cur, body, self.who().get('iat')))
            return
        m = re.fullmatch(r'/api/policy/([1-9][0-9]{0,8})/(submit|withdraw)', p)
        if m:
            body = self._body(p)
            if body is not None:
                fn = submit if m.group(2) == 'submit' else withdraw
                self.written(lambda cur: fn(cur, int(m.group(1)), body, self.who().get('iat')))
            return
        m = re.fullmatch(r'/api/policy/([1-9][0-9]{0,8})/(confirm|dispute|approve|return)', p)
        if not m:
            return self.send(404, {'error': 'not found'})
        body = self._body(p)
        if body is None:
            return
        version, verb = int(m.group(1)), m.group(2)
        note = str(body.get('note') or '').strip()
        token = self._token()

        def act(cur):
            if not note:
                raise Refused(400, 'a note is required')
            if verb == 'approve':
                for k in ('entries_digest', 'diff_digest', 'skeleton_digest'):
                    if not _DIGEST.match(str(body.get(k) or '')):
                        raise Refused(400, '%s must be 64 lower-case hex characters' % k)
            if not switches_ok(cur):
                raise Refused(503, ('confirmation' if verb in ('confirm', 'dispute') else 'approvals')
                              + ' need IAM_POSTGREST_JWT=true and IAM_DB_ROLES=true')
            if verb == 'confirm':
                args = {'p_version': version, 'p_note': note, 'p_attest': str(body.get('attest') or '')}
            elif verb == 'approve':
                args = approve_args(cur, version, body, note, self.role())
            else:
                args = {'p_version': version, 'p_note': note}
            status, payload = forward(verb + '_policy', args, token)
            log('%s of version %d by %s: %s' % (verb, version, self.who().get('username'), status))
            return status, payload
        self.guarded(act)

    def do_PUT(self):
        p = urllib.parse.urlparse(self.path).path
        m = re.fullmatch(r'/api/policy/([1-9][0-9]{0,8})/entry', p)
        if not m:
            return self.send(404, {'error': 'not found'})
        body = self._body(p)
        if body is None:
            return
        if compiler() is None:
            return self.send(503, {'error': 'the compiler is not mounted (ConfigMap iam-compiler): run ./apps/iam/deploy.sh'})
        self.written(lambda cur: save_entry(cur, int(m.group(1)), body, self.who().get('iat')))


def medcea_iam_mod():
    return medcea_iam() if callable(medcea_iam) else medcea_iam


def apply_state(event, outcome, status):
    """A version's apply state from the latest of its APPLY_EVENTS (design §14.8.12):
    'rollout incomplete' (apply_started with no later end, or partial_apply mixed or
    reverting: apply.sh --resume finishes it), 'reverted' (the latest is the revert of a
    failed apply and the version is approved again), else None."""
    if event == 'apply_started' or (event == 'partial_apply' and outcome in ('mixed', 'reverting')):
        return 'rollout incomplete'
    if status == 'approved' and (event == 'apply_reverted' or (event == 'partial_apply' and outcome == 'reverted')):
        return 'reverted'
    return None


def versions(cur, actor=None):
    cols = ', '.join('v.' + c for c in VERSION_COLS)
    vs = rows(cur, 'SELECT %s, s.git_commit AS skeleton_commit FROM iam_policy.version v '
                   'LEFT JOIN iam_policy.skeleton s ON s.digest = v.skeleton_digest ORDER BY v.version DESC' % cols)
    latest = {r['version']: r for r in rows(cur, APPLY_LATEST)}
    if actor is not None and any(v['status'] in OPEN for v in vs):
        # why_not answers for the viewer only with an actor (request_actor()); rolled back with the read
        cur.execute('SELECT medcea_auth.set_actor(%s, %s, %s, %s)', actor)
    out, open_v = [], None
    for v in vs:
        d = jsonable(v)
        if v['status'] in OPEN:
            w = rows(cur, 'SELECT may_approve, why_not_code, needs_token_path FROM iam_policy.why_not(%s)', (v['version'],))
            d['why_not'] = w[0] if w else None
            d['authors'] = authors(cur, v)
            if v['kind'] in ('change', 'skeleton') and open_v is None:
                open_v = v['version']
        d['needs_confirmation'] = (v['kind'] in ('bootstrap', 'rollback') and v['status'] in ('applied', 'superseded')
                                   and v['confirmed_at'] is None and v['disputed_at'] is None)
        a = latest.get(v['version']) or {}
        d['apply_state'] = apply_state(a.get('event'), a.get('outcome'), v['status'])
        out.append(d)
    return 200, {'versions': out, 'applied': applied_version(cur), 'open': open_v,
                 'accepted_skeleton_digest': accepted_skeleton(cur),
                 'skeleton_digest': _COMPILER.get('skeleton_digest')}


def authors(cur, v):
    """[{name, person}] of a version's makers: the actors of iam_policy._authors' events; for a
    skeleton version also the claimed apply.sh --by person (created_by_name is fixed text)."""
    ev = ', '.join("'%s'" % e for e in AUTHOR_EVENTS)
    out = rows(cur, 'SELECT DISTINCT h.actor_name AS name, h.actor_person AS person FROM iam_policy.history h '
                    'WHERE h.version = %%s AND h.event IN (%s) AND (h.actor_sub IS NOT NULL OR h.actor_person IS NOT NULL) '
                    'ORDER BY 2, 1' % ev, (v['version'],))
    if v['kind'] == 'skeleton':
        out.append({'name': None, 'person': v.get('created_by_person'), 'claimed': True})
    return out


def accepted_skeleton(cur):
    """iam_policy._accepted(), inlined: iam_svc does not execute it."""
    cur.execute('SELECT s.digest FROM iam_policy.skeleton s WHERE s.accepted_at IS NOT NULL '
                'ORDER BY s.accepted_at DESC, s.accepted_event DESC NULLS LAST LIMIT 1')
    r = cur.fetchone()
    return r[0] if r else None


def need_compiler():
    mods = compiler()
    if mods is None:
        raise Refused(503, 'the compiler is not mounted (ConfigMap iam-compiler): run ./apps/iam/deploy.sh')
    return mods


def reason_of(body):
    reason = str(body.get('reason') or '').strip()
    if not reason:
        raise Refused(400, 'a reason is required')
    return reason


def version_row(cur, version):
    r = rows(cur, 'SELECT version, kind, status, groups, roles, entries_digest, skeleton_digest '
                  'FROM iam_policy.version WHERE version = %s', (version,))
    if not r:
        raise Refused(404, 'no policy version %s' % version)
    return r[0]


def entries_digest_now(cur, version):
    cur.execute('SELECT iam_policy.entries_digest(%s)', (version,))
    return cur.fetchone()[0]


def levels_json(entries):
    """save_entry's p_levels of one cell's entry rows: {level: constraint or null}."""
    return json.dumps({e['level']: e['constraint_name'] for e in entries}, sort_keys=True)


# ── the write side (IAM 4.4, design §14.7.2; each called by written(), under the lock) ─
def new_draft(cur, body, iat):
    """A change draft, and the checker's verdict recorded at creation (owner decision 1):
    one save_entry of the draft's first cell of the accepted skeleton (the version's groups and
    roles), unchanged and whole, in the same transaction."""
    source, _m, _inv, _ex = need_compiler()
    frm = str(body.get('from') or '')
    if not _FROM.match(frm):
        raise Refused(400, 'from is applied, defaults or a version number')
    reason = reason_of(body)
    factory = source.entries_and_waivers(source.factory())
    cur.execute('SELECT iam_policy.new_draft(%s, %s, %s, %s::jsonb, %s::jsonb)',
                (frm, reason, iat, json.dumps(factory['entries']),
                 json.dumps([source.waiver_row(w) for w in factory['waivers']])))
    v = cur.fetchone()[0]
    entries, waivers = version_rows(cur, v)
    p, _dropped = compose_rows(entries, waivers)
    verdict, answer = verdict_of(p)
    # only a cell save_entry admits: a base row of a group or role a narrowing skeleton retired
    # since is copied but cannot be saved (22023), and would roll the whole draft back
    vr = version_row(cur, v)
    live = {(e['group_code'], e['role']) for e in entries
            if e['group_code'] in (vr.get('groups') or []) and e['role'] in (vr.get('roles') or [])}
    if entries and not live:
        log('draft %d: no cell of the accepted skeleton to record the checker verdict on; left unset' % v)
    if live:
        first = min(live, key=lambda k: (k[0].encode(), k[1].encode()))
        cell = [e for e in entries if (e['group_code'], e['role']) == first]
        before = entries_digest_now(cur, v)
        cur.execute('SELECT iam_policy.save_entry(%s, %s, %s, %s::jsonb, %s, %s::jsonb, %s)',
                    (v, first[1], first[0], levels_json(cell), reason + ' (checker run when the draft was created)',
                     json.dumps(verdict), iat))
        if entries_digest_now(cur, v) != before:
            log('draft %d: the verdict save changed its entries; rolled back' % v)
            raise Refused(500, 'the new draft changed while its checker verdict was recorded: nothing was kept')
    log('draft %d from %s: checker %s' % (v, frm, 'ok' if verdict['ok'] else '%d errors' % len(answer['errors'])))
    return 201, {'version': v, 'verdict': answer}


def save_entry(cur, version, body, iat):
    """PUT /api/policy/<v>/entry: the whole cell {level: constraint or null}; the checker runs
    on the draft's rows with that cell replaced, and a red verdict still saves (design §5)."""
    _s, _m, _inv, _ex = need_compiler()
    skel = _COMPILER['skel']
    role, group, levels = body.get('role'), body.get('group'), body.get('levels')
    if not (isinstance(role, str) and _KEY.match(role) and role in (skel.get('roles') or {})):
        raise Refused(400, 'no role %r in the platform skeleton' % role)
    if not (isinstance(group, str) and _KEY.match(group) and group in (skel.get('resource_groups') or {})):
        raise Refused(400, 'no resource group %r in the platform skeleton' % group)
    if not isinstance(levels, dict):
        raise Refused(400, 'levels must be an object {level: constraint or null}')
    for l, c in levels.items():
        if l not in (skel.get('levels') or {}):
            raise Refused(400, 'no level %r' % l)
        if c is not None and not (isinstance(c, str) and c in (skel.get('constraints') or {})):
            raise Refused(400, 'no constraint %r' % c)
    reason = reason_of(body)
    v = version_row(cur, version)
    if v['status'] != 'draft' or v['kind'] != 'change':
        raise Refused(409, 'version %d is not a draft' % version)
    entries, waivers = version_rows(cur, version)
    entries = [e for e in entries if (e['role'], e['group_code']) != (role, group)] + \
        [{'role': role, 'group_code': group, 'level': l, 'constraint_name': c} for l, c in levels.items()]
    p, _dropped = compose_rows(entries, waivers)
    verdict, answer = verdict_of(p)
    cur.execute('SELECT iam_policy.save_entry(%s, %s, %s, %s::jsonb, %s, %s::jsonb, %s)',
                (version, role, group, json.dumps(levels, sort_keys=True), reason, json.dumps(verdict), iat))
    c = p.cell(group, role)
    cell = {'levels': sorted(c[0], key=list(p.levels).index), 'constraints': dict(sorted(c[1].items()))} if c \
        else {'levels': [], 'constraints': {}}
    return 200, {'verdict': answer, 'cell': cell}


def submit(cur, version, body, iat):
    """The checker runs again on the stored rows (a verdict saved under an older pod is not
    trusted); submit's entries digest must be the digest of the rows checked."""
    source, _m, _inv, _ex = need_compiler()
    reason = reason_of(body)
    v = version_row(cur, version)
    if v['status'] != 'draft' or v['kind'] != 'change':
        raise Refused(409, 'version %d is not a draft' % version)
    entries, waivers = version_rows(cur, version)
    p, _dropped = compose_rows(entries, waivers)
    _verdict, answer = verdict_of(p)
    if not answer['ok']:
        return 409, {'error': 'version %d fails the checker now: fix the errors it lists first' % version,
                     'errors': answer['errors']}
    checked = source.entries_digest('change', v['groups'], v['roles'], entries, waivers)
    cur.execute('SELECT iam_policy.submit(%s, %s, %s)', (version, reason, iat))
    d = cur.fetchone()[0]
    if d != checked:
        log('submit %d: the stored digest %s is not the checked rows\' %s; rolled back' % (version, d[:12] if d else d, checked[:12]))
        raise Refused(409, 'version %d changed while it was checked: reload the page' % version)
    return 200, {'entries_digest': d}


def withdraw(cur, version, body, iat):
    cur.execute('SELECT iam_policy.withdraw(%s, %s, %s)', (version, reason_of(body), iat))
    return 200, {'ok': True}


# ── the approval diff (design §14.7.3) ────────────────────────────────────────────────
_DIFFS = {}


def change_diff(cur, v):
    """(canonical bytes, sha256, skeleton digest, document) of a change version's diff against
    the applied version, both composed with the pod's skeleton; cached per (version, entries
    digest, applied, skeleton) except for a draft. The approve forwarder uses the same."""
    source, _m, _inv, explain = need_compiler()
    applied = applied_version(cur)
    if applied is None:
        raise Refused(409, 'no policy version is applied yet')
    d = v['entries_digest'] if v['status'] != 'draft' and v['entries_digest'] else entries_digest_now(cur, v['version'])
    key = (v['version'], d, applied, _COMPILER['skeleton_digest'])
    if v['status'] != 'draft' and key in _DIFFS:
        return _DIFFS[key]
    doc = explain.diff_document('change', v['version'], applied, d, composed(cur, applied)[0], composed(cur, v['version'])[0])
    b = source.canonical(doc)
    out = (b, hashlib.sha256(b).hexdigest(), _COMPILER['skeleton_digest'], doc)
    if v['status'] != 'draft':
        if len(_DIFFS) > 32:
            _DIFFS.clear()
        _DIFFS[key] = out
    return out


def skeleton_diff(cur, v):
    """The host's stored diff of a skeleton version, re-serialised canonically; refused when it
    does not hash to the stored digest (nothing is served that qa could approve by mistake)."""
    source, _m, _inv, _ex = need_compiler()
    r = rows(cur, 'SELECT diff::text AS diff, diff_digest FROM iam_policy.version_diff WHERE version = %s', (v['version'],))
    if not r:
        raise Refused(500, 'skeleton version %d has no stored diff' % v['version'])
    doc = json.loads(r[0]['diff'])
    b = source.canonical(doc)
    if hashlib.sha256(b).hexdigest() != r[0]['diff_digest']:
        log('version %d: the stored diff does not hash to its digest %s' % (v['version'], str(r[0]['diff_digest'])[:12]))
        raise Refused(500, 'the stored diff of version %d does not hash to its digest' % v['version'])
    return b, r[0]['diff_digest'], v['skeleton_digest'], doc


def approval_diff(cur, v):
    if v['kind'] == 'change':
        return change_diff(cur, v)
    if v['kind'] == 'skeleton':
        return skeleton_diff(cur, v)
    raise Refused(409, 'only a change or skeleton version has an approval diff')


def diff_response(cur, version):
    v = version_row(cur, resolve_version(cur, version))
    b, digest, skel, _doc = approval_diff(cur, v)
    return 200, b, 'application/json', {'X-Medcea-Skeleton-Digest': skel or '', 'X-Medcea-Diff-Digest': digest}


def approve_args(cur, version, body, note, role):
    """approve_policy's arguments, after checking what qa saw (design §14.7.2): the diff digest
    and the skeleton against iam-api's recomputation (a change) or the host's stored diff (a
    skeleton version), the attestation of a skeleton version, and no own-role widening."""
    v = version_row(cur, version)
    b, digest, skel, doc = approval_diff(cur, v)
    if v['kind'] == 'skeleton':
        if body.get('attest') != SKELETON_ATTEST:
            raise Refused(400, 'approving a skeleton version needs the attestation "%s"' % SKELETON_ATTEST)
        note = SKELETON_ATTEST + ' ' + note
    if body['diff_digest'] != digest or body['skeleton_digest'] != skel:
        raise Refused(409, 'the diff you approved is not the one the Policy service computes now: reload the page')
    for r in bytewise({role} | set(role_closure(role))):
        if ((doc.get('roles') or {}).get(r) or {}).get('added'):
            raise Refused(403, 'version %d widens role %s, which you hold: you may not approve it' % (version, r))
    return {'p_version': version, 'p_note': note, 'p_entries_digest': body['entries_digest'],
            'p_diff_digest': body['diff_digest'], 'p_skeleton_digest': body['skeleton_digest']}


# ── Who can…, Service identities, Break-glass (design §14.7.5) ────────────────────────
_WHO = weakref.WeakKeyDictionary()   # explain.who_can's reach sets per composed Policy


def who_can(cur, version, obj, level):
    _s, _m, _inv, explain = need_compiler()
    if not _VERSION.match(version):
        raise Refused(400, 'version is applied or a number')
    p, _ = composed(cur, resolve_version(cur, version))
    if level and level not in p.levels:
        raise Refused(400, 'no level %r' % level)
    if not obj:
        return 200, explain.who_can_index(p)
    if len(obj) > 512:
        raise Refused(400, 'object name too long')
    try:
        return 200, explain.who_can(p, obj, level or None, cache=_WHO.setdefault(p, {}))
    except KeyError as e:
        raise Refused(404, 'no object %s' % (e.args[0] if e.args else obj))


def service_identities():
    skel = _COMPILER['skel']
    groups = skel.get('resource_groups') or {}
    out = []
    for k, s in (skel.get('service_identities') or {}).items():
        ceiling = s.get('ceiling') or {}
        out.append({'key': k, 'label': s.get('label'), 'description': s.get('description'),
                    'db_role': s.get('db_role'), 'mqtt_user': s.get('mqtt_user'), 'ceiling': ceiling,
                    'groups': {g: {'label': (groups.get(g) or {}).get('label'), 'help': (groups.get(g) or {}).get('description')}
                               for g in ceiling},
                    'managed_by': s.get('managed_by'),
                    # the NAME of a config.env key, never a secret
                    'password_key': s.get('db_password')})
    return {'identities': out}


def break_glass(cur):
    skel = _COMPILER['skel']
    opened = rows(cur, BREAK_GLASS_OPEN)
    for o in opened:
        o['components'] = json.loads(o['components'] or '[]')
    return 200, {'identities': [{'identity': b.get('identity'), 'used_by': b.get('used_by'), 'logged_by': b.get('logged_by')}
                                for b in skel.get('break_glass') or []],
                 'open_overrides': [jsonable(o) for o in opened]}


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
