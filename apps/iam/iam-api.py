"""iam-api: the access policy's own service (IAM plan Phase 3.5; 4.1 adds the Policy UI's port).

One listener per route-table service, so the trust boundary is a port:
  :8085  iam-mqttx  POST /_mqtt-credential, reached only as an upstream of the MQTT
                    Explorer's oauth2-proxy (mqttx-oauth2-proxy; network: admits that proxy
                    and the node). GET /healthz answers before any check.

POST /_mqtt-credential issues the signed-in person a short-lived MQTT credential for the
broker's WebSocket listener (IAM_MQTT_PERSON=true; 1883 refuses it). Its rows come from
/iam/mqtt.json (compiler/mqtt.py, ConfigMap medcea-iam-lib) for the person's one own role:
reads as compiled, writes with unit '+', which the broker's auth sidecar narrows on every
sync to units flagged for commissioning without a running run. The port refuses whatever
medcea_iam.check() refuses, whatever IAM_ENFORCE says; then JSON only (415), the
Explorer's own Origin (403), 409 while IAM_MQTT_PERSON is false (read live from
/iam/settings.json `switches`; without it, false), 503 without a valid mqtt.json or when
not logged in as iam_svc, 403 for a role with no rows and when the account was
deactivated or changed role after the token was issued (the proxy may still forward a
token up to 300 s old). One transaction as iam_svc: set_actor -> retire the person's
credentials beyond max_active - 1 and the expired ones -> the credential and its rows ->
iam_policy.append_history('mqtt_credential_issued') -> commit. The password is made here
(secrets), hashed with infra/mqtt-passwd.py (mounted as mqtt_passwd.py), returned once
with Cache-Control no-store and never logged; log lines carry the username only.
"""
import datetime, hashlib, importlib.util, json, os, re, secrets, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

E = os.environ
PG = dict(host=E.get('PG_HOST', 'rdbms-postgresql'), port=int(E.get('PG_PORT', '5432')),
          database=E.get('PG_DATABASE', 'medcea_db'), user=E.get('PG_USER', 'iam_svc'),
          password=E.get('PG_PASSWORD', ''))
ROOT = E.get('PROJECT_NAME', 'medcea')
MQTTX_ORIGIN = 'https://' + E.get('MQTTX_DOMAIN', '') if E.get('MQTTX_DOMAIN') else ''
IAM_LIB = E.get('MEDCEA_IAM_LIB', '/iam/medcea_iam.py')
MQTT_FILE = E.get('MEDCEA_IAM_MQTT', '/iam/mqtt.json')
MQTT_PASSWD = E.get('MQTT_PASSWD_PY', '/app/mqtt_passwd.py')
SERVICE_ROLE = 'iam_svc'
PERSON_PREFIX = 'explorer-'
SYNC_S = 15                  # the broker sidecar's POLL_SECONDS
_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
_NAME = re.compile(r'[^A-Za-z0-9._-]')


def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, flush=True)


def db():
    import pg8000.dbapi
    return pg8000.dbapi.connect(**PG)


def _load_module(name, path, cache):
    try:
        mtime = os.stat(path).st_mtime
        if mtime != cache.get('mtime'):
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            cache.update(mtime=mtime, mod=mod)
    except Exception as e:  # noqa: BLE001 — a missing mount must not stop the service
        if not cache.get('warned'):
            print('%s: not loaded from %s (%s)' % (name, path, e), file=sys.stderr, flush=True)
            cache['warned'] = True
    return cache.get('mod')


# ── Access policy library (/iam/, ConfigMap medcea-iam-lib) ──────────────────
# medcea_iam.py is loaded from the mount and reloaded when it changes, so a late
# ConfigMap heals without a restart. Without it every request but /healthz is 503.
_IAM = {}
_PASSWD = {}


def _medcea_iam():
    return _load_module('medcea_iam', IAM_LIB, _IAM)


def hash_password(password):
    """infra/mqtt-passwd.py's mosquitto_hash: one implementation of the $7$ hash."""
    mod = _load_module('mqtt_passwd', MQTT_PASSWD, _PASSWD)
    if mod is None:
        raise RuntimeError('mqtt_passwd.py is missing')
    return mod.mosquitto_hash(password)


def person_mode():
    """IAM_MQTT_PERSON, live from /iam/settings.json `switches`; false without it."""
    iam = _medcea_iam()
    s = iam.settings() if iam is not None and hasattr(iam, 'settings') else {}
    return (s.get('switches') or {}).get('IAM_MQTT_PERSON') is True


def mqtt_doc():
    """mqtt.json when present and its digest matches its own body; else None."""
    try:
        with open(MQTT_FILE, encoding='utf-8') as fh:
            doc = json.load(fh)
        body = {k: v for k, v in doc.items() if k != 'digest'}
        canon = json.dumps(body, sort_keys=True, separators=(',', ':'))
        if hashlib.sha256(canon.encode()).hexdigest() != doc.get('digest'):
            return None
        if not isinstance(doc.get('roles'), dict) or not isinstance(doc.get('ttl_hours'), int):
            return None
        return doc
    except (OSError, ValueError, AttributeError):
        return None


class Refused(Exception):
    def __init__(self, status, error):
        super().__init__(status, error)
        self.status, self.error = status, error


def username_for(who):
    u = _NAME.sub('_', who.get('username') or 'person')[:40]
    return '%s%s-%s' % (PERSON_PREFIX, u, secrets.token_hex(3))


# The re-issue guard: a deactivation, an applied narrowing or a confirmed role change after
# the token was issued means the token's role is no longer the account's.
CHANGED_SINCE = """
    SELECT EXISTS (SELECT 1 FROM iam.user_status_history h
                    WHERE h.keycloak_user_id = %s AND h.occurred_at >= to_timestamp(%s))
        OR EXISTS (SELECT 1 FROM iam.account_decision d
                    WHERE d.keycloak_user_id = %s AND d.kind IN ('deactivate', 'role_change')
                      AND ((d.status IN ('applied', 'reviewed') AND d.made_at >= to_timestamp(%s))
                           OR (d.status = 'confirmed' AND d.checked_at >= to_timestamp(%s))))"""
RETIRE = """
    UPDATE medcea.mqtt_service_credential c SET active = false
     WHERE c.person_sub = %s::uuid AND c.active
       AND (c.expires_at <= now()
            OR c.username IN (SELECT k.username FROM medcea.mqtt_service_credential k
                               WHERE k.person_sub = %s::uuid AND k.active AND k.expires_at > now()
                               ORDER BY k.created_at DESC, k.username OFFSET %s))"""


def issue(who, role, doc):
    """(status, payload). One transaction as iam_svc; nothing is kept on a refusal."""
    rows = doc['roles'].get(role) or []
    iat = who.get('iat')
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        raise Refused(503, 'the access library predates IAM 3.5 (no token iat): run ./deploy-infra.sh')
    sub = who['sub']
    name = username_for(who)
    password = secrets.token_hex(24)
    pw_hash = hash_password(password)
    reads = ['%s/%s' % (ROOT, r['topic']) for r in rows if r['access'] == 'read']
    writes = ['%s/%s' % (ROOT, r['topic']) for r in rows if r['access'] == 'write']
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT medcea_auth.set_actor(%s, %s, %s, %s)',
                    (sub, who.get('person_id') or sub, who.get('username'), role))
        cur.execute(CHANGED_SINCE, (sub, iat, sub, iat, iat))
        if cur.fetchone()[0]:
            raise Refused(403, 'your access changed since you signed in: reload the page')
        cur.execute(RETIRE, (sub, sub, max(int(doc.get('max_active') or 1) - 1, 0)))
        cur.execute('INSERT INTO medcea.mqtt_service_credential (username, password_hash, person_sub, expires_at) '
                    "VALUES (%s, %s, %s::uuid, now() + make_interval(hours => %s)) RETURNING expires_at",
                    (name, pw_hash, sub, int(doc['ttl_hours'])))
        expires = cur.fetchone()[0]
        for access, topics in (('read', reads), ('write', writes)):
            for t in topics:
                cur.execute('INSERT INTO medcea.mqtt_service_acl (username, access, topic) VALUES (%s, %s, %s)',
                            (name, access, t))
        exp = expires.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') \
            if hasattr(expires, 'astimezone') else str(expires)
        cur.execute('SELECT iam_policy.append_history(%s, %s::jsonb, %s)',
                    ('mqtt_credential_issued',
                     json.dumps({'username': name, 'person_sub': sub, 'role': role, 'expires_at': exp,
                                 'read': reads, 'write': writes, 'mqtt_digest': doc.get('digest')}),
                     'MQTT Explorer sign-in'))
        con.commit()
    except BaseException:
        try:
            con.rollback()
        except Exception:                        # noqa: BLE001 — the connection may be gone
            pass
        raise
    finally:
        con.close()
    log('issued %s to %s (%s), expires %s: %d read, %d write row(s)'
        % (name, who.get('username') or sub, role, exp, len(reads), len(writes)))
    return 200, {'username': name, 'password': password, 'expires_at': exp, 'broker': '/mqtt',
                 'read': reads, 'write': writes,
                 'write_rule': 'only units flagged for commissioning without a running run; '
                               're-checked by the broker every %d s' % SYNC_S,
                 'ready_after_s': SYNC_S}


def db_refusal(e):
    a = e.args[0] if getattr(e, 'args', None) else None
    code, msg = (a.get('C'), a.get('M') or '') if isinstance(a, dict) else (None, '')
    if code in ('42501', '42883', '42P01', '3F000'):
        log('database: %s %s — run ./apps/database/deploy.sh (and ./apps/access/deploy.sh)' % (code, msg))
        return 503, {'error': 'iam-api lacks a database grant, table or function (%s): '
                              'run ./apps/database/deploy.sh' % msg}
    return None


# ── HTTP ──────────────────────────────────────────────────────────────────────
class MqttCredential(BaseHTTPRequestHandler):
    server_version = 'medcea-iam'
    IAM_SERVICE = 'iam-mqttx'

    def parse_request(self):
        if not super().parse_request():
            return False
        if self.path.split('?', 1)[0] == '/healthz':
            return True                          # liveness: answered before any check
        iam = _medcea_iam()
        if iam is None:
            self.send(503, {'error': 'access policy not loaded'})
            return False
        if not iam.http_check(self, self.IAM_SERVICE, enforce=True):
            return False
        w = getattr(getattr(self, 'medcea_iam', None), 'who', None) or {}
        if not _UUID.match(str(w.get('sub') or '')):
            self.send(401, {'error': 'sign in'})
            return False
        return True

    def log_message(self, fmt, *args):
        if not self.path.startswith('/healthz'):
            log('%s %s' % (self.address_string(), fmt % args))

    def send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split('?', 1)[0] == '/healthz':
            doc = mqtt_doc()
            return self.send(200, {'service': self.IAM_SERVICE, 'mode': person_mode(),
                                   'mqtt_digest': doc.get('digest') if doc else None,
                                   'db_user': PG['user'], 'enforce_always': True})
        self.send(404, {'error': 'not found'})

    def do_POST(self):
        if self.path.split('?', 1)[0] != '/_mqtt-credential':
            return self.send(404, {'error': 'not found'})
        ctype = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if ctype != 'application/json':
            return self.send(415, {'error': 'send JSON (Content-Type: application/json)'})
        if not MQTTX_ORIGIN or self.headers.get('Origin') != MQTTX_ORIGIN:
            log('refused a POST from origin %r' % self.headers.get('Origin'))
            return self.send(403, {'error': 'cross-origin request refused'})
        if not person_mode():
            return self.send(409, {'error': 'person credentials are off (IAM_MQTT_PERSON=false)'})
        if PG['user'] != SERVICE_ROLE:
            return self.send(503, {'error': 'iam-api is not logged in as %s: run ./apps/iam/deploy.sh' % SERVICE_ROLE})
        doc = mqtt_doc()
        if doc is None:
            return self.send(503, {'error': 'mqtt.json is missing or damaged: run ./deploy-infra.sh'})
        iam = _medcea_iam()
        role = iam.actor_role(self.medcea_iam) if hasattr(iam, 'actor_role') else None
        if not role or not doc['roles'].get(role):
            return self.send(403, {'error': 'your role has no MQTT rights'})
        try:
            self.send(*issue(self.medcea_iam.who, role, doc))
        except Refused as e:
            self.send(e.status, {'error': e.error})
        except Exception as e:                   # noqa: BLE001
            mapped = db_refusal(e)
            if mapped:
                return self.send(*mapped)
            log('error on POST /_mqtt-credential: %s' % type(e).__name__)
            self.send(500, {'error': 'Something went wrong on our side. Please try again later.'})


def serve(handler, port):
    srv = ThreadingHTTPServer(('0.0.0.0', port), handler)
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == '__main__':
    if PG['user'] != SERVICE_ROLE:
        log('warning: PG_USER is %s, not %s — POST /_mqtt-credential answers 503' % (PG['user'], SERVICE_ROLE))
    log('listening: iam-mqttx :8085')
    serve(MqttCredential, 8085)
