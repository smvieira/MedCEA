"""Self-service access requests: the registration form and the User Manager.

Two listeners, so the trust boundary is a port rather than a path check:
  :8080  public  GET /register, POST /api/register             (Ingress, no auth)
  :8081  admin   the User Manager (only behind the access oauth2-proxy, which admits
                 the roles compiled for ACCESS_DOMAIN: admin, qa, qp, auditor). This
                 port refuses whatever medcea_iam.check() refuses, whatever
                 IAM_ENFORCE says (IAM 2.7), and takes the person from the verified
                 token, never from X-Forwarded-* headers.
  :8082  profile /_account/ on every signed-in host (portal, config, access):
                 each host's oauth2-proxy routes that path here, so the user
                 menu, the profile page and its API act for whoever that proxy
                 signed in — any role, and only their own account.

A registration creates the Keycloak user *disabled* and stores the request in
iam.access_request; nobody can sign in until it is approved and confirmed.

Account decisions (IAM 2.7, qa_dual_control): every change an administrator makes to
an account is a row in iam.account_decision, written by iam.record_decision() after
medcea_auth.set_actor() named the signed-in person. A widening — a grant, an
activation of an account that holds a role, a role change that adds a (group, level)
pair, a person_id change, new mail settings — waits as pending_qa and Keycloak is not
touched until a qa person who is neither the maker nor the subject confirms it
(iam.confirm_decision, then the Keycloak change inside the open transaction). A
deactivation or a pure narrowing acts at once (applied) and revokes the person's MQTT
credentials in the same transaction; qa reviews it afterwards. Rejecting a request
still deletes the Keycloak account (the request row keeps who asked, for what, and
why it was refused), so the person may apply again; a grant qa refuses does the same.

Mail is configured in the User Manager, not in config.env: the Gmail account
(iam.mail_settings, changed only through a qa-confirmed decision) and the four
templates (iam.mail_template; a reset is an UPDATE back to the file in templates/).
E-mail goes out after the database commit; without SMTP settings the message is
written to the log instead.
"""
import contextlib, datetime, importlib.util, inspect, json, os, re, smtplib, ssl, string, sys, threading, time, urllib.error, urllib.parse, urllib.request
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

E = os.environ
PG = dict(host=E.get('PG_HOST', 'rdbms-postgresql'), port=int(E.get('PG_PORT', '5432')),
          database=E.get('PG_DATABASE', 'medcea_db'), user=E.get('PG_USER', 'access_svc'),
          password=E.get('PG_PASSWORD', ''))
KC_URL = E.get('KC_URL', 'http://keycloak').rstrip('/')
KC_REALM = E.get('KC_REALM', 'medcea')
KC_CLIENT_ID = E.get('KC_CLIENT_ID', 'access')
KC_CLIENT_SECRET = E.get('KC_CLIENT_SECRET', '')
ACCESS_URL = E.get('ACCESS_URL', '').rstrip('/')
PORTAL_URL = E.get('PORTAL_URL', '').rstrip('/')
# The Keycloak login page (theme medcea) posts its Request access tab here.
LOGIN_ORIGIN = E.get('LOGIN_ORIGIN', '').rstrip('/')
HTML_DIR = E.get('HTML_DIR', '/app/html')
TEMPLATE_DIR = E.get('TEMPLATE_DIR', '/app/templates')
PLATFORM = 'MedCEA Platform'
KC_PUBLIC = E.get('KC_PUBLIC_URL', '').rstrip('/')       # https://keycloak.<domain>, for the browser
# host=client pairs: which Keycloak client a signed-in host belongs to, for its
# sign-out and change-password links (portal.medcea=portal,config.medcea=config).
HOST_CLIENTS = dict(p.split('=', 1) for p in E.get('HOST_CLIENTS', '').split(',') if '=' in p)
# What /healthz on the admin port reports; apps/access/deploy.sh widens the proxy only
# after every Ready pod answers with it (invariant W, never fail open).
ACCESS_VERSION = '2.7'

# The platform roles this service offers as a *target*, in the form's order. The
# access policy (apps/iam/policy/defaults.yaml) has eleven, and every one of them is
# read from Keycloak (routes.json roles); offering the rest is task 2.6. engineer is
# offered from Phase 0 because the policy admits only engineers to Node-RED, MQTT
# Explorer and device onboarding.
ROLES = {
    'operator': 'Operator — runs recipes and day-to-day cultivation',
    'engineer': 'Automation Engineer — devices, recipes, controllers, flows and dashboards (drafts that QA approves)',
    'qa':       'Quality Assurance — reviews data and releases batches',
    'auditor':  'Auditor — read-only access to records and audit trails',
    'admin':    'Administrator — manages the platform and its users',
}

USERNAME_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{2,31}$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
PERSON_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$')
_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
UNIT_KINDS = ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove')
# Rule 6 of the who-may rules: a units.sh row — without a maker (bootstrap), or with
# the maker --by names, which the script cannot prove its runner holds — is confirmed
# only with this attestation, which iam.confirm_decision checks.
ATTEST = 'attest: I did not run units.sh for this assignment.'


def needs_attestation(r):
    return r['kind'] in UNIT_KINDS and (r.get('made_by_sub') is None
                                        or (r.get('made_by_name') or '').startswith('system:deploy'))


def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, flush=True)


def _is_uuid(s):
    return isinstance(s, str) and bool(_UUID.match(s))


# ── Database ──────────────────────────────────────────────────────────────────
def db():
    import pg8000.dbapi
    return pg8000.dbapi.connect(**PG)


class Refused(Exception):
    """An answer decided inside a handler: (status, payload). Raised inside tx(), it
    rolls the transaction back."""
    def __init__(self, status, payload):
        super().__init__(status, payload)
        self.status = status
        self.payload = payload if isinstance(payload, dict) else {'error': payload}


def sqlstate(e):
    """(SQLSTATE, primary message) of a pg8000 error, else (None, None)."""
    a = e.args[0] if getattr(e, 'args', None) else None
    if isinstance(a, dict):
        return a.get('C'), a.get('M') or ''
    return None, None


def db_refusal(e):
    """The HTTP answer for a database refusal, or None for anything else.
    A missing privilege or function is deploy order or grant drift (503); every other
    42501 is the account functions refusing the person (403)."""
    code, msg = sqlstate(e)
    if code == '42883' or (code == '42501' and msg.startswith('permission denied for')):
        log('database: %s %s — run ./apps/database/deploy.sh' % (code, msg))
        return 503, {'error': 'the User Manager lacks a database grant or function (%s): '
                              'run ./apps/database/deploy.sh' % msg}
    if code == '42501':
        return 403, {'error': msg}
    if code in ('22023', '23505'):
        return 409, {'error': msg}
    return None


@contextlib.contextmanager
def tx(who, role):
    """One transaction whose actor is the verified person (medcea_auth.set_actor, source
    'person via access_svc'). Commit is the caller's; leaving the block without it, or
    with an exception, rolls back."""
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT medcea_auth.set_actor(%s, %s, %s, %s)',
                    (who['sub'], who.get('person_id'), who.get('username'), role))
        yield con, cur
    except BaseException:
        try:
            con.rollback()
        except Exception:                        # noqa: BLE001 — the connection may be gone
            pass
        raise
    finally:
        con.close()


REQ_COLS = ('request_id', 'keycloak_user_id', 'username', 'email', 'first_name', 'last_name',
            'organisation', 'requested_role', 'justification', 'status', 'granted_role',
            'decided_by', 'decided_at', 'admin_notes', 'created_at', 'email_subject', 'email_body')


def row_dict(cols, row):
    d = dict(zip(cols, row))
    for k, v in d.items():
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d


# ── Access policy library (/iam/, ConfigMap medcea-iam-lib) ──────────────────
# medcea_iam.py and the route table are loaded from the mount and reloaded when it
# changes, so a ConfigMap that appears later heals and a new library needs no restart.
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
            print('medcea_iam: not loaded (%s); the admin port refuses, the others are not checked' % e,
                  file=sys.stderr, flush=True)
            _IAM['warned'] = True
    return _IAM['mod']


def _table():
    """routes.json, as the library reads it; {} without one."""
    iam = _medcea_iam()
    loader = getattr(iam, '_load', None)
    return (loader(iam.ROUTES_FILE) if loader else None) or {}


def platform_roles():
    """All eleven platform roles (routes.json roles); ROLES without a table."""
    return list(_table().get('roles') or ROLES)


def role_includes():
    return _table().get('role_includes') or {}


def roles_including(role):
    """The roles that include `role` (Keycloak composites): the inverse of role_includes."""
    iam = _medcea_iam()
    if iam is not None and hasattr(iam, 'roles_including'):
        return sorted(iam.roles_including(role))
    return sorted(r for r, inc in role_includes().items() if role in (inc or []))


def effective(role):
    return {role} | set(role_includes().get(role) or [])


def own_roles(held):
    """The held platform roles minus every role another held one includes — the rule of
    medcea_iam.actor_role() and the database's _own_role()."""
    inc = role_includes()
    covered = {i for r in held for i in (inc.get(r) or [])}
    return sorted(set(held) - covered)


def widening(old, new):
    """Sorted [[group, level]] that `new` adds over `old` (None = no role), from
    routes.json — what the UI shows; the database (role_widening) decides."""
    if not new:
        return []
    iam = _medcea_iam()
    if iam is not None and hasattr(iam, 'widening'):
        w = iam.widening(old, new)
    else:
        w = ((_table().get('widening') or {}).get(old or '-') or {}).get(new)
    return sorted([list(p) for p in (w or [])])


def allows(roles, method, path, service='access'):
    """Whether one of `roles` may call the route: the route match and role test of
    check(), without a token (for /api/me's capabilities)."""
    iam = _medcea_iam()
    if iam is None:
        return False
    if hasattr(iam, 'allows'):
        return bool(iam.allows(list(roles or []), service, method, path))
    routes = ((_table().get('services') or {}).get(service) or {}).get('routes') or {}
    key = iam.match(routes, method, path)
    return bool(key) and any(r in (routes[key].get('roles') or {}) for r in roles or [])


# ── Keycloak admin API (service account of client KC_CLIENT_ID) ───────────────
class KCError(Exception):
    def __init__(self, status, body):
        super().__init__('Keycloak HTTP %s: %s' % (status, body[:300]))
        self.status = status


_tok = {'value': '', 'exp': 0.0}
_tok_lock = threading.Lock()


def kc_token():
    with _tok_lock:
        if time.time() < _tok['exp'] - 20:
            return _tok['value']
        data = urllib.parse.urlencode({'grant_type': 'client_credentials', 'client_id': KC_CLIENT_ID,
                                       'client_secret': KC_CLIENT_SECRET}).encode()
        req = urllib.request.Request('%s/realms/%s/protocol/openid-connect/token' % (KC_URL, KC_REALM), data=data)
        with urllib.request.urlopen(req, timeout=10) as r:
            t = json.load(r)
        _tok.update(value=t['access_token'], exp=time.time() + t.get('expires_in', 60))
        return _tok['value']


def kc(method, path, body=None):
    """Call /admin/realms/<realm><path>. Returns (status, parsed body or None, headers)."""
    url = '%s/admin/realms/%s%s' % (KC_URL, KC_REALM, path)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Authorization', 'Bearer ' + kc_token())
    if data is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None), r.headers
    except urllib.error.HTTPError as e:
        raise KCError(e.code, e.read().decode('utf-8', 'replace')) from None


def kc_user_exists(username, email):
    for q in ('username=%s&exact=true' % urllib.parse.quote(username),
              'email=%s&exact=true' % urllib.parse.quote(email)):
        _, users, _ = kc('GET', '/users?' + q)
        if users:
            return True
    return False


def kc_create_disabled_user(f):
    _, _, headers = kc('POST', '/users', {
        'username': f['username'], 'email': f['email'],
        'firstName': f['first_name'], 'lastName': f['last_name'],
        'attributes': {'organisation': [f['organisation']]} if f.get('organisation') else {},
        'enabled': False, 'emailVerified': False,
        'credentials': [{'type': 'password', 'value': f['password'], 'temporary': False}],
    })
    return headers.get('Location', '').rstrip('/').rsplit('/', 1)[-1]


def kc_delete_user(user_id):
    try:
        kc('DELETE', '/users/%s' % user_id)
    except KCError as e:
        if e.status != 404:
            raise


def kc_user(user_id):
    return kc('GET', '/users/%s' % user_id)[1]


def kc_update_user(user_id, attributes=None, attributes_default=None, **fields):
    """Read-modify-write the whole user: a partial PUT is how Keycloak loses things (see
    the service-account pitfall in CLAUDE.md). `attributes` merges per key;
    `attributes_default` sets only keys the user does not have yet. The GET is right
    before the PUT, so a change made since the caller last read the user is kept."""
    u = kc_user(user_id)
    attrs = dict(u.get('attributes') or {})
    if attributes:
        attrs.update(attributes)
    for k, v in (attributes_default or {}).items():
        if not attrs.get(k):
            attrs[k] = v
    if attributes or attributes_default:
        u['attributes'] = attrs
    u.update(fields)
    kc('PUT', '/users/%s' % user_id, u)
    return u


def kc_set_enabled(user_id, enabled, **extra):
    return kc_update_user(user_id, enabled=enabled, **extra)


def attr_person(u):
    return (((u or {}).get('attributes') or {}).get('person_id') or [None])[0] or None


def person_of(u):
    """The person an account declares (attribute person_id), else the account itself."""
    return attr_person(u) or u['id']


def role_users(role):
    """Accounts holding `role` directly (full representations); [] for a role the realm
    does not have."""
    try:
        _, users, _ = kc('GET', '/roles/%s/users?briefRepresentation=false&max=2000' % urllib.parse.quote(role))
    except KCError as e:
        if e.status == 404:
            return []
        raise
    return users or []


def role_members():
    """user id -> platform roles held directly (one call per role, not per user)."""
    held = {}
    for role in platform_roles():
        for u in role_users(role):
            held.setdefault(u['id'], []).append(role)
    return held


def mapped_platform(user_id):
    """The user's direct realm-role mappings that are platform roles (representations)."""
    _, mapped, _ = kc('GET', '/users/%s/role-mappings/realm' % user_id)
    plat = set(platform_roles())
    return [r for r in mapped or [] if r.get('name') in plat]


def holders(role):
    """{id: user} of every account whose effective roles include `role`."""
    out = {}
    for r in sorted({role, *roles_including(role)}):
        for u in role_users(r):
            out[u['id']] = u
    return out


def last_enabled(user_id, role):
    """True when user_id is the only enabled account holding `role`."""
    hs = holders(role)
    return user_id in hs and not any(u.get('enabled') and i != user_id for i, u in hs.items())


def guard_last(user_id, new_role=None):
    """409 when a deactivation (new_role None) or a change to new_role would leave no
    enabled admin, or no enabled qa (break-glass: CLAUDE.md, deploy-infra QA_USER)."""
    after = effective(new_role) if new_role else set()
    for role, what in (('admin', 'administrator'), ('qa', 'qa person')):
        if role not in after and last_enabled(user_id, role):
            raise Refused(409, 'this is the last enabled %s' % what)


_KEEP = object()


def i17_violation(subject_uid, new_role=_KEEP, new_person=None, subject=None):
    """I17: no person holds both an admin-side and a qa-side account. Applies the
    proposed change (role and/or person) to the subject and checks the subject's person,
    accounts enabled or not. Returns the refusal text, or None."""
    sides = {'admin': {'admin', *roles_including('admin')}, 'qa': {'qa', *roles_including('qa')}}
    acc = {}
    for side, roles in sides.items():
        for r in sorted(roles):
            for u in role_users(r):
                a = acc.setdefault(u['id'], {'person': person_of(u), 'username': u['username'],
                                             'admin': False, 'qa': False})
                a[side] = True
    s = acc.get(subject_uid)
    if s is None:
        u = subject or kc_user(subject_uid)
        s = acc[subject_uid] = {'person': person_of(u), 'username': u['username'], 'admin': False, 'qa': False}
    if new_role is not _KEEP:
        s['admin'] = new_role in sides['admin']
        s['qa'] = new_role in sides['qa']
    if new_person:
        s['person'] = new_person
    mine = [a for a in acc.values() if a['person'] == s['person']]
    adm = sorted(a['username'] for a in mine if a['admin'])
    qa = sorted(a['username'] for a in mine if a['qa'])
    if adm and qa:
        return ('person %s would hold both an admin account (%s) and a qa account (%s) (I17)'
                % (s['person'], ', '.join(adm), ', '.join(qa)))
    return None


def admin_emails():
    try:
        users = role_users('admin')
    except Exception as e:                       # noqa: BLE001 — notification must not fail a request
        log('could not list admins:', e)
        users = []
    found = [u['email'] for u in users or [] if u.get('enabled') and u.get('email')]
    extra = [a.strip() for a in mail_settings()['notify_emails'].split(',') if a.strip()]
    return sorted(set(found + extra))


# ── E-mail ────────────────────────────────────────────────────────────────────
TEMPLATES = ('new-request', 'approved', 'reassigned', 'rejected')
SETTINGS_COLS = ('smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'from_name', 'notify_emails',
                 'updated_by', 'updated_at')


def mail_settings(cur=None):
    def read(c):
        c.execute('SELECT ' + ', '.join(SETTINGS_COLS) + ' FROM iam.mail_settings WHERE id = 1')
        return c.fetchone()
    if cur is not None:
        row = read(cur)
    else:
        con = db()
        try:
            row = read(con.cursor())
        finally:
            con.close()
    return row_dict(SETTINGS_COLS, row) if row else dict(
        smtp_host='smtp.gmail.com', smtp_port=587, smtp_user='', smtp_pass='', from_name=PLATFORM,
        notify_emails='', updated_by=None, updated_at=None)


def pending_settings():
    """The staged mail settings waiting for qa (never the password), or None."""
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT p.decision_id, p.smtp_user, p.smtp_host, p.smtp_port, p.updated_by, p.updated_at"
                    " FROM iam.mail_settings_pending p JOIN iam.account_decision d USING (decision_id)"
                    " WHERE d.status = 'pending_qa' ORDER BY p.decision_id DESC LIMIT 1")
        row = cur.fetchone()
    finally:
        con.close()
    return row_dict(('decision_id', 'smtp_user', 'smtp_host', 'smtp_port', 'updated_by', 'updated_at'), row) if row else None


def smtp_ready(st):
    return bool(st['smtp_host'] and st['smtp_user'] and st['smtp_pass'])


def default_template(name):
    """templates/<name>.txt: first line 'Subject: ...', a blank line, the body."""
    with open(os.path.join(TEMPLATE_DIR, name + '.txt'), encoding='utf-8') as fh:
        head, _, body = fh.read().partition('\n\n')
    subject = head[len('Subject:'):].strip() if head.startswith('Subject:') else PLATFORM
    return subject, body.strip() + '\n'


def all_templates():
    """A row marked is_default (a reset) means the file, so a changed default file
    still applies after a reset."""
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT name, subject, body, updated_by, updated_at, is_default FROM iam.mail_template')
        saved = {r[0]: row_dict(('name', 'subject', 'body', 'updated_by', 'updated_at', 'is_default'), r)
                 for r in cur.fetchall()}
    finally:
        con.close()
    out = []
    for name in TEMPLATES:
        d_subject, d_body = default_template(name)
        t = saved.get(name)
        custom = bool(t) and not t['is_default']
        out.append({'name': name, 'subject': t['subject'] if custom else d_subject, 'body': t['body'] if custom else d_body,
                    'default_subject': d_subject, 'default_body': d_body, 'customised': custom,
                    'updated_by': t['updated_by'] if t else None, 'updated_at': t['updated_at'] if t else None})
    return out


def render_template(name, values):
    t = next(t for t in all_templates() if t['name'] == name)
    sub = lambda text: string.Template(text).safe_substitute(values)
    return sub(t['subject']).strip(), sub(t['body']).strip() + '\n'


def smtp_connect(st):
    ctx = ssl.create_default_context()
    if int(st['smtp_port']) == 465:
        s = smtplib.SMTP_SSL(st['smtp_host'], 465, timeout=20, context=ctx)
    else:
        s = smtplib.SMTP(st['smtp_host'], int(st['smtp_port']), timeout=20)
        s.starttls(context=ctx)
    # PLAIN only, not s.login(): login() falls back to AUTH LOGIN after Gmail's
    # 535 "Username and Password not accepted", Gmail hangs up, and the 535 is
    # lost behind SMTPServerDisconnected ("Connection unexpectedly closed").
    s.user, s.password = st['smtp_user'], st['smtp_pass']
    s.ehlo_or_helo_if_needed()
    s.auth('PLAIN', s.auth_plain)
    return s


def send_mail(to, subject, body, st=None):
    """Returns (sent, detail). Never raises: a mail failure must not undo a decision."""
    if not to:
        return False, 'no recipient'
    st = st or mail_settings()
    if not smtp_ready(st):
        log('SMTP not configured; message not sent:\n  To: %s\n  Subject: %s\n%s' % (', '.join(to), subject, body))
        return False, 'e-mail is not configured (User Manager → E-mail settings); message written to the service log'
    msg = EmailMessage()
    msg['From'] = formataddr((st['from_name'] or PLATFORM, st['smtp_user']))
    msg['To'] = ', '.join(to)
    msg['Subject'] = subject
    msg['Message-ID'] = make_msgid(domain=st['smtp_user'].split('@')[-1])
    msg.set_content(body)
    try:
        with smtp_connect(st) as s:
            s.send_message(msg)
        log('mail sent to %s: %s' % (', '.join(to), subject))
        return True, 'sent to %s' % ', '.join(to)
    except Exception as e:                       # noqa: BLE001
        log('mail to %s failed: %s' % (', '.join(to), e))
        return False, 'send failed: %s' % e


def kc_mail_rep(st):
    """The realm fields Keycloak's own mail (Forgot password?) uses: the same account.
    Pushed only when qa confirms a mail_settings decision (needs realm-management
    manage-realm on the access service account)."""
    rep = {'resetPasswordAllowed': smtp_ready(st)}
    if smtp_ready(st):
        port = str(st['smtp_port'])
        rep['smtpServer'] = {'host': st['smtp_host'], 'port': port, 'auth': 'true', 'user': st['smtp_user'],
                             'password': st['smtp_pass'], 'from': st['smtp_user'],
                             'fromDisplayName': st['from_name'] or PLATFORM,
                             'starttls': 'false' if port == '465' else 'true', 'ssl': 'true' if port == '465' else 'false'}
    else:
        rep['smtpServer'] = {}
    return rep


def public_settings(st):
    d = {k: v for k, v in st.items() if k != 'smtp_pass'}
    d['pass_set'] = bool(st['smtp_pass'])
    d['ready'] = smtp_ready(st)
    return d


def mail_change_text(old, new):
    """What a mail settings change does, for the decision's reason (never the password)."""
    pw = ('unchanged' if new['smtp_pass'] == old['smtp_pass'] else 'removed' if not new['smtp_pass']
          else 'new app password')
    return ('mail settings: send as %s through %s:%s, from name "%s", notify %s, %s (was %s)'
            % (new['smtp_user'] or 'no account', new['smtp_host'], new['smtp_port'], new['from_name'],
               new['notify_emails'] or 'nobody extra', pw, old['smtp_user'] or 'no account'))


def save_settings(body, who, role):
    """Stages the new account in iam.mail_settings_pending as a mail_settings decision
    (Q8): neither iam.mail_settings nor the realm changes until a qa person confirms,
    so an administrator cannot point password-reset mail at a mailbox they read."""
    st = mail_settings()
    new = dict(st)
    new['smtp_host'] = (body.get('smtp_host') or 'smtp.gmail.com').strip()
    try:
        new['smtp_port'] = int(body.get('smtp_port') or 587)
    except ValueError:
        return 400, {'error': 'port must be a number'}
    new['smtp_user'] = (body.get('smtp_user') or '').strip()
    if body.get('smtp_pass'):                    # empty = keep the stored one
        new['smtp_pass'] = str(body['smtp_pass']).replace(' ', '')   # Google shows it in groups of four
    if body.get('clear_pass'):
        new['smtp_pass'] = ''
    new['from_name'] = (body.get('from_name') or PLATFORM).strip()[:255]
    notify = [a.strip() for a in str(body.get('notify_emails') or '').split(',') if a.strip()]
    bad = [a for a in notify if not EMAIL_RE.match(a)]
    if bad:
        return 400, {'error': 'not an e-mail address: %s' % ', '.join(bad)}
    new['notify_emails'] = ', '.join(notify)
    if new['smtp_user'] and not EMAIL_RE.match(new['smtp_user']):
        return 400, {'error': 'the sending account must be an e-mail address'}
    waiting = pending_settings()
    if waiting:
        return 409, {'error': 'decision #%s (mail settings) is waiting for qa — withdraw it or ask qa to '
                              'confirm or refuse it first' % waiting['decision_id']}
    if smtp_ready(new):                          # prove the login before keeping it
        try:
            smtp_connect(new).quit()
        except smtplib.SMTPAuthenticationError:
            return 400, {'error': 'Gmail rejected this address / app password. Use an app password '
                                  '(myaccount.google.com/apppasswords), not your normal password.'}
        except Exception as e:                   # noqa: BLE001
            return 400, {'error': 'could not log in to %s:%s — %s' % (new['smtp_host'], new['smtp_port'], e)}
    # The reason starts with what changes, written here, so the record qa confirms
    # names the account whatever the administrator adds after it.
    note = (body.get('reason') or '').strip()
    reason = (mail_change_text(st, new) + ('. Note: ' + note if note else ''))[:2000]
    with tx(who, role) as (con, cur):
        dec = record_decision(cur, 'mail_settings', 'realm', 'realm mail settings', 'realm', None, None, None, reason)
        cur.execute('INSERT INTO iam.mail_settings_pending (id, smtp_host, smtp_port, smtp_user, smtp_pass, from_name,'
                    ' notify_emails, updated_by, updated_at, decision_id) VALUES (1,%s,%s,%s,%s,%s,%s,%s,now(),%s)',
                    (new['smtp_host'], new['smtp_port'], new['smtp_user'], new['smtp_pass'], new['from_name'],
                     new['notify_emails'], who.get('username'), dec['decision_id']))
        con.commit()
    log('mail settings staged by %s as decision #%s (account %s)' % (who.get('username'), dec['decision_id'],
                                                                     new['smtp_user'] or 'none'))
    return 202, {'decision': dec, 'settings': public_settings(st), 'pending': pending_settings()}


def save_template(name, body, who, role):
    if name not in TEMPLATES:
        return 404, {'error': 'no such template'}
    subject, text = (body.get('subject') or '').strip(), (body.get('body') or '').strip()
    if not subject or not text:
        return 400, {'error': 'subject and body are both required'}
    if len(subject) > 300 or len(text) > 20000:
        return 400, {'error': 'template too long'}
    with tx(who, role) as (con, cur):
        cur.execute('INSERT INTO iam.mail_template (name, subject, body, updated_by, is_default) VALUES (%s,%s,%s,%s,false)'
                    ' ON CONFLICT (name) DO UPDATE SET subject = EXCLUDED.subject, body = EXCLUDED.body,'
                    ' updated_by = EXCLUDED.updated_by, updated_at = now(), is_default = false',
                    (name, subject, text + '\n', who.get('username')))
        con.commit()
    return 200, {'templates': all_templates()}


def reset_template(name, who, role):
    """Back to the default file as an UPDATE (is_default), never a DELETE: the row and
    its history stay, and iam.log_mail_config logs a 'reset'."""
    if name not in TEMPLATES:
        return 404, {'error': 'no such template'}
    subject, text = default_template(name)
    with tx(who, role) as (con, cur):
        cur.execute('UPDATE iam.mail_template SET subject = %s, body = %s, is_default = true, updated_by = %s,'
                    ' updated_at = now() WHERE name = %s AND NOT is_default', (subject, text, who.get('username'), name))
        changed = cur.rowcount
        con.commit()
    if not changed:
        return 200, {'unchanged': True, 'detail': 'already the default', 'templates': all_templates()}
    return 200, {'templates': all_templates()}


def config_history():
    cols = ('event_id', 'item', 'action', 'detail', 'actor', 'occurred_at')
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT ' + ', '.join(cols) + ' FROM iam.config_history ORDER BY occurred_at DESC, event_id DESC LIMIT 100')
        return [row_dict(cols, r) for r in cur.fetchall()]
    finally:
        con.close()


def template_values(r):
    notes = (r.get('admin_notes') or '').strip()
    return {
        'platform': PLATFORM, 'request_id': r['request_id'],
        'first_name': r['first_name'], 'last_name': r['last_name'], 'username': r['username'],
        'email': r['email'], 'organisation': r.get('organisation') or '—',
        'requested_role': r['requested_role'], 'requested_role_label': ROLES.get(r['requested_role'], ''),
        'granted_role': r.get('granted_role') or '', 'granted_role_label': ROLES.get(r.get('granted_role') or '', ''),
        'justification': r['justification'], 'decided_by': r.get('decided_by') or '',
        'notes': notes or '—',
        'notes_block': ('Notes from the administrator:\n%s\n' % notes) if notes else '',
        'portal_url': PORTAL_URL, 'admin_url': ACCESS_URL + '/',
    }


def notify_admins(r):
    subject, body = render_template('new-request', template_values(r))
    send_mail(admin_emails(), subject, body)


# ── Registration (public) ─────────────────────────────────────────────────────
_hits, _hits_lock = {}, threading.Lock()


def rate_limited(ip, limit=10, window=3600):
    now = time.time()
    with _hits_lock:
        recent = [t for t in _hits.get(ip, []) if now - t < window]
        if len(recent) >= limit:
            _hits[ip] = recent
            return True
        _hits[ip] = recent + [now]
        return False


def validate(f):
    clean = {k: str(f.get(k) or '').strip() for k in
             ('username', 'email', 'first_name', 'last_name', 'organisation', 'requested_role', 'justification')}
    clean['username'] = clean['username'].lower()
    clean['email'] = clean['email'].lower()
    clean['password'] = str(f.get('password') or '')
    if not USERNAME_RE.match(clean['username']):
        return None, 'Username: 3–32 characters, lowercase letters, digits, dot, dash or underscore.'
    if not EMAIL_RE.match(clean['email']) or len(clean['email']) > 254:
        return None, 'Enter a valid e-mail address.'
    if not (clean['first_name'] and clean['last_name']) or max(len(clean['first_name']), len(clean['last_name'])) > 100:
        return None, 'Enter your first and last name.'
    if len(clean['organisation']) > 200:
        return None, 'Organisation is too long.'
    if clean['requested_role'] not in ROLES:
        return None, 'Choose a role.'
    if not 20 <= len(clean['justification']) <= 2000:
        return None, 'Business justification: 20 to 2000 characters.'
    if not 10 <= len(clean['password']) <= 128:
        return None, 'Password: at least 10 characters.'
    return clean, None


def register(f, ip):
    if f.get('website'):                         # honeypot: a field people never see
        return 200, {'ok': True, 'message': 'Request received.'}
    clean, err = validate(f)
    if err:
        return 400, {'ok': False, 'error': err}
    # Counted after validation, so someone fixing typos in the form is not locked
    # out; what is limited is the work a request causes (Keycloak, DB, mail).
    if rate_limited(ip):
        return 429, {'ok': False, 'error': 'Too many requests from this address. Try again in an hour.'}
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT 1 FROM iam.access_request WHERE lower(email) = %s AND status = 'pending'", (clean['email'],))
        if cur.fetchone():
            return 409, {'ok': False, 'error': 'A request for this e-mail address is already waiting for review.'}
        if kc_user_exists(clean['username'], clean['email']):
            return 409, {'ok': False, 'error': 'That username or e-mail address already has an account.'}
        user_id = kc_create_disabled_user(clean)
        try:
            cur.execute(
                "INSERT INTO iam.access_request (keycloak_user_id, username, email, first_name, last_name,"
                " organisation, requested_role, justification) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
                " RETURNING " + ', '.join(REQ_COLS),
                (user_id, clean['username'], clean['email'], clean['first_name'], clean['last_name'],
                 clean['organisation'] or None, clean['requested_role'], clean['justification']))
            row = row_dict(REQ_COLS, cur.fetchone())
            con.commit()
        except Exception:
            con.rollback()
            kc_delete_user(user_id)              # no orphan disabled account without a request
            raise
    finally:
        con.close()
    log('request %s submitted by %s for role %s' % (row['request_id'], row['username'], row['requested_role']))
    threading.Thread(target=notify_admins, args=(row,), daemon=True).start()
    return 201, {'ok': True, 'message': 'Request received. You will get an e-mail once an administrator has reviewed it.'}


# ── Account decisions (IAM 2.7) ───────────────────────────────────────────────
def record_decision(cur, kind, user_id, username, subject_person, from_role, to_role, new_person, reason,
                    request_id=None):
    """iam.record_decision, then the widening cross-check: the database computes the
    widening from its compiled role_widening(); a different answer from routes.json means
    one of the two deploys is missing (the caller's transaction is rolled back)."""
    cur.execute('SELECT decision_id, status, widening, withdrawn FROM iam.record_decision'
                '(%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                (kind, user_id, username, subject_person, from_role, to_role, new_person, reason, request_id))
    did, status, w, withdrawn = cur.fetchone()
    if isinstance(w, str):
        w = json.loads(w)
    got = sorted([list(p) for p in (w or [])])
    pair = {'grant': (None, to_role), 'role_change': (from_role, to_role), 'activate': (None, from_role)}.get(kind)
    want = widening(*pair) if pair else []
    if got != want:
        log('decision %s (%s %s -> %s): database widening %s, routes.json %s' % (did, kind, pair and pair[0],
                                                                                 pair and pair[1], got, want))
        raise Refused(503, 'the policy in the database and in routes.json differ: run ./deploy-infra.sh and '
                           './apps/database/deploy.sh')
    return {'decision_id': did, 'status': status, 'widening': got, 'withdrawn': list(withdrawn or [])}


DEC_COLS = ('decision_id', 'kind', 'keycloak_user_id', 'username', 'subject_person', 'from_role', 'to_role',
            'zone_id', 'unit_id', 'new_person_id', 'widens', 'widening', 'status', 'reason', 'made_by_sub',
            'made_by_person', 'made_by_name', 'made_at', 'checked_by_sub', 'checked_by_person', 'checked_by_name',
            'checked_at', 'check_note', 'request_id', 'withdrawn_by_sub', 'withdrawn_by_person', 'withdrawn_by_name',
            'withdrawn_at', 'withdraw_reason')
CONFIRM_COLS = ('decision_id', 'kind', 'keycloak_user_id', 'username', 'from_role', 'to_role', 'new_person_id', 'unit_id')

# Compensation that failed (a Keycloak change left wider than the database says). Kept
# in this process and shown in the drift list until Keycloak no longer shows it.
_COMP_FAILED, _comp_lock = [], threading.Lock()


def _live_approver(who):
    """The approver, live: enabled, effectively qa, and declaring the person the token
    names. The token can be up to 300 s old."""
    try:
        u = kc_user(who['sub'])
        _, eff, _ = kc('GET', '/users/%s/role-mappings/realm/composite' % who['sub'])
    except KCError as e:
        log('approver check for %s failed: %s' % (who.get('username'), e))
        raise Refused(409, 'sign in again: your account changed')
    if not u.get('enabled') or 'qa' not in {r.get('name') for r in eff or []} \
            or attr_person(u) != who.get('person_id'):
        raise Refused(409, 'sign in again: your account changed')


CHANGED = 'the account changed since: withdraw or refuse this decision'


def _precheck(d, u):
    """The per-kind live state the decision was made against (§2.2)."""
    kind, uid = d['kind'], d['keycloak_user_id']
    held = [r['name'] for r in mapped_platform(uid)]
    own = own_roles(held)
    if kind == 'grant':
        ok = not u.get('enabled') and not held
    elif kind == 'role_change':
        # A NULL from_role was recorded for an account with no role or several own roles;
        # the set itself is not stored, so "still in that state" is the test.
        ok = own == [d['from_role']] if d['from_role'] else len(own) != 1
        if ok:
            guard_last(uid, d['to_role'])
    elif kind == 'activate':
        ok = not u.get('enabled') and own == ([d['from_role']] if d['from_role'] else [])
    elif kind == 'person_id':
        ok = person_of(u) == d.get('subject_person')
    else:
        ok = True
    if not ok:
        raise Refused(409, CHANGED)


def _role_rep(role):
    return kc('GET', '/roles/%s' % urllib.parse.quote(role))[1]


def _apply(d, steps):
    """The Keycloak effect of a confirmed decision (or an applied narrowing); `steps`
    records what was done, for compensation. A role the account already held is not
    a step: undoing it would take away a role the decision never gave."""
    kind, uid = d['kind'], d['keycloak_user_id']
    if kind == 'grant':
        rep = _role_rep(d['to_role'])
        kc('POST', '/users/%s/role-mappings/realm' % uid, [rep])
        steps.append(('role_added', d['to_role'], rep))
        kc_update_user(uid, enabled=True, emailVerified=True, attributes_default={'person_id': [uid]})
        steps.append(('enabled', None, None))
    elif kind == 'role_change':
        # Add first, remove second: a failure in between leaves the account with both
        # roles (compensated, or reported as drift), never with none.
        mapped = mapped_platform(uid)
        old = [r for r in mapped if r['name'] != d['to_role']]
        if d['to_role'] not in {r['name'] for r in mapped}:
            rep = _role_rep(d['to_role'])
            kc('POST', '/users/%s/role-mappings/realm' % uid, [rep])
            steps.append(('role_added', d['to_role'], rep))
        if old:
            kc('DELETE', '/users/%s/role-mappings/realm' % uid, old)
            steps.append(('roles_removed', ','.join(r['name'] for r in old), old))
    elif kind == 'activate':
        kc_update_user(uid, enabled=True)
        steps.append(('enabled', None, None))
    elif kind == 'person_id':
        before = attr_person(kc_user(uid))
        kc_update_user(uid, attributes={'person_id': [d['new_person_id']]})
        steps.append(('person_id', d['new_person_id'], before))


def _comp_failed(d, step, name, e, detail, **check):
    log('DRIFT: decision %s: undoing %s %s on %s failed (%s)' % (d['decision_id'], step, name or '', d['username'], e))
    with _comp_lock:
        _COMP_FAILED.append(dict({'user_id': d['keycloak_user_id'], 'username': d['username'], 'role': name,
                                  'decision_id': d['decision_id'], 'kind': 'compensation_failed', 'detail': detail,
                                  'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}, **check))


def _compensate(d, steps):
    """Undo, newest first, what a failed confirm (or narrowing) did in Keycloak. True
    when an undo failed too: that is drift, reported until Keycloak no longer shows it."""
    drift = False
    uid, did = d['keycloak_user_id'], d['decision_id']
    for step, name, rep in reversed(steps):
        try:
            if step == 'role_added':
                kc('DELETE', '/users/%s/role-mappings/realm' % uid, [rep])
            elif step == 'roles_removed':
                kc('POST', '/users/%s/role-mappings/realm' % uid, rep)
            elif step == 'enabled':
                kc_update_user(uid, enabled=False)
            elif step == 'person_id':
                kc_update_user(uid, attributes={'person_id': [rep] if rep else []})
            log('decision %s: compensated, %s %s undone' % (did, step, name or ''))
        except Exception as e:                   # noqa: BLE001
            drift = True
            if step == 'role_added':
                _comp_failed(d, step, name, e, 'a failed change (#%s) left %s on the account' % (did, name), held=True)
            elif step == 'roles_removed':
                for r in rep:
                    _comp_failed(d, step, r['name'], e, 'a failed change (#%s) took %s from the account'
                                 % (did, r['name']), held=False)
            elif step == 'enabled':
                _comp_failed(d, step, None, e, 'a failed change (#%s) left the account enabled' % did, enabled=True)
            else:
                _comp_failed(d, step, None, e, 'a failed change (#%s) left person_id %s on the account'
                             % (did, name), person=name)
    return drift


def _keycloak_then_commit(con, d, steps, waiting):
    """_apply, then commit; anything that fails after the first Keycloak change is
    compensated (§2.2): a KCError, a network error or timeout (OSError), or a commit
    that does not go through. `waiting` says what stays of the record ('decision #n
    stays waiting', 'nothing was recorded')."""
    try:
        _apply(d, steps)
    except Exception as e:                       # noqa: BLE001
        drift = _compensate(d, steps)
        if not isinstance(e, (KCError, OSError)):
            raise
        log('decision %s: Keycloak step failed: %s' % (d['decision_id'], e))
        out = {'error': 'Keycloak refused the change: %s; %s' % (e, waiting)}
        if drift:
            out['drift'] = True
        raise Refused(502, out)
    try:
        con.commit()
    except Exception as e:                       # noqa: BLE001
        drift = _compensate(d, steps)
        log('decision %s: commit failed after the Keycloak change: %r' % (d['decision_id'], e))
        out = {'error': 'the record could not be saved, and the Keycloak change was %s; %s'
                        % ('NOT undone (drift)' if drift else 'undone', waiting)}
        if drift:
            out['drift'] = True
        raise Refused(503, out)


def _live_checks(who, d):
    """The live part of the who-may rules (§2.5), for every kind and every verb: the
    approver as Keycloak has them now, and — for an account decision — the subject's
    person as its account declares it now, which also covers rows recorded without a
    subject person (bootstrap units). Returns the subject (None: mail settings, or an
    account Keycloak no longer has)."""
    _live_approver(who)
    if d['kind'] == 'mail_settings':
        return None
    try:
        u = kc_user(d['keycloak_user_id'])
    except KCError as e:
        if e.status == 404:
            return None
        raise
    if who.get('person_id') and person_of(u) == who['person_id']:
        raise Refused(403, 'not_own_author: same person as the subject')
    return u


def confirm_decision(did, body, who, role):
    note = (body.get('note') or '').strip()[:4000] or None
    steps = []
    with tx(who, role) as (con, cur):
        cur.execute('SELECT request_id, subject_person FROM iam.account_decision WHERE decision_id = %s', (did,))
        extra = cur.fetchone()
        cur.execute('SELECT ' + ', '.join(CONFIRM_COLS) + ' FROM iam.confirm_decision(%s, %s)', (did, note))
        d = dict(zip(CONFIRM_COLS, cur.fetchone()))
        d['request_id'], d['subject_person'] = (extra or (None, None))[:2]
        # The decision's locks are held from here: Keycloak is read after them.
        u = _live_checks(who, d)
        if d['kind'] in UNIT_KINDS:              # bootstrap: already in effect
            con.commit()
            log('decision %s (%s) confirmed by %s' % (did, d['kind'], who.get('username')))
            return 200, {'decision': d, 'applied': []}
        if d['kind'] == 'mail_settings':
            # confirm_decision moved the staged row into iam.mail_settings; the realm
            # follows, last, so a refusal there rolls the move back.
            before = mail_settings()             # committed state: what the realm has now
            try:
                kc('PUT', '', kc_mail_rep(mail_settings(cur)))
            except (KCError, OSError) as e:
                raise Refused(502, 'Keycloak refused the mail settings: %s' % e)
            try:
                con.commit()
            except Exception as e:               # noqa: BLE001
                try:
                    kc('PUT', '', kc_mail_rep(before))
                    undone = 'undone'
                except Exception as e2:          # noqa: BLE001
                    log('DRIFT: decision %s: the realm keeps the new mail settings (%s)' % (did, e2))
                    undone = 'NOT undone: the realm sends with the new account (drift)'
                log('decision %s: commit failed after the realm change: %r' % (did, e))
                raise Refused(503, 'the record could not be saved, and the realm change was %s; decision #%s '
                                   'stays waiting' % (undone, did))
            log('decision %s (mail settings) confirmed by %s' % (did, who.get('username')))
            return 200, {'decision': d, 'applied': ['realm mail settings']}
        if u is None:
            raise Refused(409, 'the account no longer exists: refuse this decision')
        if d['kind'] in ('grant', 'role_change', 'activate', 'person_id'):
            v = i17_violation(d['keycloak_user_id'],
                              new_role=d['to_role'] if d['kind'] in ('grant', 'role_change') else _KEEP,
                              new_person=d['new_person_id'] if d['kind'] == 'person_id' else None, subject=u)
            if v:
                raise Refused(409, v)
        _precheck(d, u)
        _keycloak_then_commit(con, d, steps, 'decision #%s stays waiting' % did)
    log('decision %s (%s %s) confirmed by %s; applied: %s' % (did, d['kind'], d['username'], who.get('username'),
                                                              ', '.join(s[0] for s in steps)))
    out = {'decision': d, 'applied': [s[0] if not s[1] else '%s %s' % s[:2] for s in steps]}
    if d['kind'] == 'grant' and d.get('request_id'):
        out['email'] = _send_approval(d['request_id'])
    return 200, out


def _send_approval(request_id):
    """The e-mail the approving admin wrote, sent when the account is enabled."""
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT email, email_subject, email_body FROM iam.access_request WHERE request_id = %s', (request_id,))
        row = cur.fetchone()
    finally:
        con.close()
    if not row or not row[2]:
        return {'sent': False, 'detail': 'no e-mail with this approval'}
    sent, detail = send_mail([row[0]], row[1], row[2] + '\n')
    log('request %s: approval e-mail: %s' % (request_id, detail))
    return {'sent': sent, 'detail': detail}


def refuse_decision(did, body, who, role):
    note = (body.get('note') or '').strip()[:4000]
    if not note:
        return 400, {'error': 'a refusal needs a note explaining why'}
    steps = []
    with tx(who, role) as (con, cur):
        cur.execute('SELECT from_role, to_role FROM iam.account_decision WHERE decision_id = %s', (did,))
        roles = cur.fetchone() or (None, None)
        cur.execute('SELECT decision_id, kind, keycloak_user_id, unit_id, removed FROM iam.refuse_decision(%s, %s)',
                    (did, note))
        d = dict(zip(('decision_id', 'kind', 'keycloak_user_id', 'unit_id', 'removed'), cur.fetchone()))
        d['from_role'], d['to_role'] = roles[:2]
        _live_checks(who, d)
        if d['kind'] in ('grant', 'role_change'):
            try:
                _reconcile(d, steps)
            except (KCError, OSError) as e:
                raise Refused(502, 'Keycloak refused the change: %s; decision #%s stays waiting' % (e, did))
        con.commit()
    log('decision %s (%s) refused by %s%s' % (did, d['kind'], who.get('username'),
                                              '; ' + ', '.join(steps) if steps else ''))
    return 200, {'decision': d, 'removed_unit': bool(d.get('removed')), 'reconciled': steps}


def _reconcile(d, steps):
    """Make Keycloak match a refusal. Nothing should have been applied, but a failed
    confirm whose compensation failed may have left a trace. A refused grant deletes
    the account, as a rejected request does, so the person can apply again."""
    uid = d['keycloak_user_id']
    try:
        u = kc_user(uid)
    except KCError as e:
        if e.status == 404:
            return
        raise
    mapped = mapped_platform(uid)
    if d['kind'] == 'role_change':
        names = {r['name'] for r in mapped}
        if d['from_role']:
            # from one role: holding both is the trace of a failed confirm
            stale = d['to_role'] in names and d['from_role'] in names
        else:
            # from none or several (the set is not recorded): the new role may be one
            # the account already held, so only a failure this process saw is undone
            with _comp_lock:
                stale = d['to_role'] in names and any(
                    c['decision_id'] == d['decision_id'] and c['role'] == d['to_role'] and c.get('held')
                    for c in _COMP_FAILED)
        if stale:
            kc('DELETE', '/users/%s/role-mappings/realm' % uid, [r for r in mapped if r['name'] == d['to_role']])
            steps.append('removed %s again' % d['to_role'])
        return
    if u.get('enabled'):
        kc_update_user(uid, enabled=False)
        steps.append('disabled')
    if mapped:
        kc('DELETE', '/users/%s/role-mappings/realm' % uid, mapped)
        steps.append('roles removed')
    kc_delete_user(uid)
    steps.append('account deleted')


def review_decision(did, body, who, role):
    note = (body.get('note') or '').strip()[:4000] or None
    with tx(who, role) as (con, cur):
        cur.execute('SELECT iam.review_decision(%s, %s)', (did, note))
        cur.fetchone()
        cur.execute('SELECT kind, keycloak_user_id FROM iam.account_decision WHERE decision_id = %s', (did,))
        row = cur.fetchone()
        if row:
            _live_checks(who, {'kind': row[0], 'keycloak_user_id': row[1]})
        con.commit()
    log('decision %s reviewed by %s' % (did, who.get('username')))
    return 200, {'decision': did}


def withdraw_decision(did, body, who, role):
    reason = (body.get('reason') or '').strip()[:2000]
    if not reason:
        return 400, {'error': 'give a reason for withdrawing; it is recorded'}
    with tx(who, role) as (con, cur):
        cur.execute('SELECT iam.withdraw_decision(%s, %s)', (did, reason))
        cur.fetchone()
        con.commit()
    log('decision %s withdrawn by %s' % (did, who.get('username')))
    return 200, {'decision': did}


def _why_not(r, who, can_a, live_person):
    """Why the caller cannot confirm, refuse or review this row — the database's rules
    (§2.5), mirrored for the screen; the database decides. None when they can."""
    if not can_a:
        return 'your role holds no A on account decisions'
    if r['status'] not in ('pending_qa', 'applied'):
        return 'already %s' % r['status']
    p, sub = who.get('person_id'), who.get('sub')
    if not p:
        return 'your token carries no person_id'
    if sub == r['made_by_sub']:
        return 'not_own_author: you made this decision'
    if sub == r['keycloak_user_id']:
        return 'not_own_author: you are its subject'
    if p == r['made_by_person']:
        return 'not_own_author: same person as the maker'
    if p in (r['subject_person'], live_person):
        return 'not_own_author: same person as the subject'
    if p == r['new_person_id']:
        return 'not_own_author: same person as the new person_id'
    if r['made_by_person'] is None and not (r['made_by_name'] or '').startswith('system:'):
        return 'unattributed maker'
    if r['subject_person'] is None and not (r['kind'] in UNIT_KINDS and (r['made_by_name'] or '').startswith('system:deploy')):
        return 'the subject has no person_id'
    return None


def list_decisions(q, who):
    status = q.get('status', ['pending_qa'])[0]
    user = q.get('user', [None])[0]
    try:
        limit = max(1, min(int(q.get('limit', ['200'])[0]), 500))
    except ValueError:
        return 400, {'error': 'limit must be a number'}
    where, args = [], []
    if status == 'open':
        where.append("d.status IN ('pending_qa', 'applied')")
    elif status in ('pending_qa', 'applied', 'confirmed', 'refused', 'reviewed', 'withdrawn'):
        where.append('d.status = %s')
        args.append(status)
    elif status != 'all':
        return 400, {'error': 'status: pending_qa, applied, open or all'}
    if user:
        if not _is_uuid(user):
            return 400, {'error': 'user must be an account id'}
        where.append('d.keycloak_user_id = %s')
        args.append(user)
    units = "('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove')"
    sql = ('SELECT ' + ', '.join('d.' + c for c in DEC_COLS) + ', u.unit_code,'
           ' (SELECT max(l.decision_id) FROM iam.account_decision l WHERE l.keycloak_user_id = d.keycloak_user_id'
           '   AND l.decision_id > d.decision_id AND ((d.kind IN %s AND l.kind IN %s AND l.unit_id = d.unit_id)'
           '   OR (d.kind NOT IN %s AND l.kind NOT IN %s))) AS superseded_by'
           ' FROM iam.account_decision d LEFT JOIN medcea.cea_unit u ON u.unit_id = d.unit_id' % (units, units, units, units))
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    sql += " ORDER BY (d.status = 'pending_qa') DESC, d.made_at DESC, d.decision_id DESC LIMIT %s"
    con = db()
    try:
        cur = con.cursor()
        cur.execute(sql, tuple(args) + (limit,))
        rows = [row_dict(DEC_COLS + ('unit_code', 'superseded_by'), r) for r in cur.fetchall()]
        staged = {}
        if any(r['kind'] == 'mail_settings' for r in rows):
            now = mail_settings(cur)
            cur.execute('SELECT decision_id, smtp_host, smtp_port, smtp_user, smtp_pass, from_name, notify_emails'
                        ' FROM iam.mail_settings_pending')
            for did, host, port, user, pw, name, notify in cur.fetchall():
                staged[did] = {'smtp_host': host, 'smtp_port': port, 'smtp_user': user, 'from_name': name,
                               'notify_emails': notify, 'current_user': now['smtp_user'],
                               'password': ('unchanged' if pw == now['smtp_pass'] else 'removed' if not pw
                                            else 'new app password')}
        reqs = sorted({r['request_id'] for r in rows if r['request_id']})
        applicants = {}
        if reqs:
            cur.execute('SELECT request_id, email, first_name, last_name, organisation, created_at, requested_role'
                        ' FROM iam.access_request WHERE request_id = ANY(%s)', (reqs,))
            applicants = {r[0]: row_dict(('request_id', 'email', 'first_name', 'last_name', 'organisation',
                                          'registered_at', 'requested_role'), r) for r in cur.fetchall()}
        try:
            users = [u for u in (kc('GET', '/users?max=2000&briefRepresentation=false')[1] or [])
                     if not u['username'].startswith('service-account-')]
            held = role_members()
            drift, live_error = compute_drift(cur, users, held), None
        except (KCError, OSError) as e:
            users, held, drift, live_error = [], {}, None, 'Keycloak unreachable: %s' % e
    finally:
        con.close()
    by_id = {u['id']: u for u in users}
    inc = role_includes()
    eff = lambda roles: {x for r in roles for x in ({r} | set(inc.get(r) or []))}
    staff = [u for u in users if eff(held.get(u['id'], [])) & {'admin', 'qa'}]
    can_a = allows((who or {}).get('roles'), 'POST', '/api/decisions/1/confirm')
    for r in rows:
        if isinstance(r['widening'], str):
            r['widening'] = json.loads(r['widening'])
        u = by_id.get(r['keycloak_user_id'])
        r['subject'] = None if u is None else {
            'enabled': bool(u.get('enabled')), 'role': ', '.join(own_roles(held.get(u['id'], []))) or None,
            'person_id': attr_person(u)}
        r['superseded'] = r['superseded_by'] is not None
        r['why_not'] = _why_not(r, who or {}, can_a, person_of(u) if u else None)
        r['can_check'] = r['why_not'] is None
        r['needs_attestation'] = r['status'] == 'pending_qa' and needs_attestation(r)
        if r['kind'] == 'mail_settings':
            r['mail_settings'] = staged.get(r['decision_id'])
        if r['kind'] == 'grant' and r['request_id'] in applicants:
            a = r['applicant'] = applicants[r['request_id']]
            r['lookalikes'] = _lookalikes(a, staff, held)
    return 200, {'decisions': rows, 'drift': drift, 'live_error': live_error, 'attestation': ATTEST}


def _lookalikes(a, staff, held):
    """Existing admin and qa accounts beside an applicant (R10): a matching e-mail domain
    or name is flagged, so qa can ask whether this is a second identity."""
    dom = (a.get('email') or '').rpartition('@')[2].lower()
    name = ('%s %s' % (a.get('first_name') or '', a.get('last_name') or '')).strip().lower()
    out = []
    for u in staff:
        udom = (u.get('email') or '').rpartition('@')[2].lower()
        uname = ('%s %s' % (u.get('firstName') or '', u.get('lastName') or '')).strip().lower()
        flags = (['same e-mail domain'] if dom and dom == udom else []) + (['same name'] if name and name == uname else [])
        out.append({'username': u['username'], 'email': u.get('email') or '', 'name': uname,
                    'roles': ', '.join(own_roles(held.get(u['id'], []))), 'flags': flags})
    return out


_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _when(ts):
    if ts is None:
        return _EPOCH
    return ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)


def expected_roles(cur):
    """account -> the platform roles the record says it holds now (§5.8). Records, in
    time order: a status history row that ends with a role (every applied or
    confirmed grant, role change and activation writes one, and so did the role
    changes before 2.7) sets the expected role; an access request approved before 2.7
    (no decision) sets its granted role; the latest signed-off access review adds the
    roles it listed as unexplained — the qa person signing it off accepted them — and
    nothing else. A later record replaces what an earlier one said, so a role
    narrowed away and re-added outside the decisions is unexplained again."""
    ev = []
    cur.execute('SELECT keycloak_user_id, to_role, occurred_at, event_id FROM iam.user_status_history'
                ' WHERE to_role IS NOT NULL')
    ev += [(uid, _when(at), 0, eid or 0, 'set', {to}) for uid, to, at, eid in cur.fetchall()]
    cur.execute("SELECT r.keycloak_user_id, r.granted_role, r.decided_at FROM iam.access_request r"
                " WHERE r.status = 'approved' AND r.keycloak_user_id IS NOT NULL AND r.granted_role IS NOT NULL"
                " AND NOT EXISTS (SELECT 1 FROM iam.account_decision d WHERE d.request_id = r.request_id)")
    ev += [(uid, _when(at), 0, 0, 'set', {g}) for uid, g, at in cur.fetchall()]
    cur.execute('SELECT snapshot, signed_off_at FROM iam.access_review WHERE signed_off_at IS NOT NULL'
                ' ORDER BY signed_off_at DESC LIMIT 1')
    row = cur.fetchone()
    if row:
        snap = json.loads(row[0]) if isinstance(row[0], str) else (row[0] or {})
        acks = {}
        for x in snap.get('drift') or []:
            if x.get('kind') == 'unexplained_role' and x.get('user_id') and x.get('role'):
                acks.setdefault(x['user_id'], set()).add(x['role'])
        ev += [(uid, _when(row[1]), 1, 0, 'ack', roles) for uid, roles in acks.items()]
    out = {}
    for uid, _, _, _, what, roles in sorted(ev, key=lambda e: e[1:4]):
        out[uid] = (out.get(uid, set()) | roles) if what == 'ack' else set(roles)
    return out


def compute_drift(cur, users, held):
    """Accounts whose Keycloak state the record does not explain (§5.8): a platform role
    that is not the one the latest record gives the account (expected_roles); an
    enabled account whose latest decision is a waiting grant or activation; a failed
    compensation, until Keycloak no longer shows it."""
    expected = expected_roles(cur)
    cur.execute("SELECT DISTINCT ON (keycloak_user_id) keycloak_user_id, decision_id, kind, status"
                " FROM iam.account_decision WHERE kind NOT IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove')"
                " ORDER BY keycloak_user_id, decision_id DESC")
    latest = {r[0]: r[1:] for r in cur.fetchall()}
    out = []
    for u in users:
        for role in held.get(u['id'], []):
            if role not in expected.get(u['id'], set()):
                out.append({'user_id': u['id'], 'username': u['username'], 'kind': 'unexplained_role', 'role': role,
                            'detail': '%s holds %s, which no confirmed decision or signed-off review explains'
                                      % (u['username'], role)})
        last = latest.get(u['id'])
        if u.get('enabled') and last and last[2] == 'pending_qa' and last[1] in ('grant', 'activate'):
            out.append({'user_id': u['id'], 'username': u['username'], 'kind': 'enabled_while_pending',
                        'decision_id': last[0],
                        'detail': '%s is enabled while %s #%s waits for qa' % (u['username'], last[1], last[0])})
    by_id = {u['id']: u for u in users}

    def still(c):
        u = by_id.get(c['user_id'])
        if u is None:
            return False
        if 'held' in c:
            return (c['role'] in held.get(c['user_id'], [])) == c['held']
        if 'enabled' in c:
            return bool(u.get('enabled')) == c['enabled']
        return attr_person(u) == c.get('person')
    with _comp_lock:
        _COMP_FAILED[:] = [c for c in _COMP_FAILED if still(c)]
        out += [{k: v for k, v in c.items() if k not in ('held', 'enabled', 'person')} for c in _COMP_FAILED]
    return out


# ── User Manager (admin) ──────────────────────────────────────────────────────
def list_requests(status):
    con = db()
    try:
        cur = con.cursor()
        sql = ('SELECT ' + ', '.join('r.' + c for c in REQ_COLS) +
               ', (SELECT d.decision_id FROM iam.account_decision d WHERE d.request_id = r.request_id'
               '   ORDER BY d.decision_id DESC LIMIT 1),'
               ' (SELECT d.status FROM iam.account_decision d WHERE d.request_id = r.request_id'
               '   ORDER BY d.decision_id DESC LIMIT 1)'
               ' FROM iam.access_request r')
        args = ()
        if status in ('pending', 'approved', 'rejected'):
            sql += ' WHERE r.status = %s'
            args = (status,)
        cur.execute(sql + " ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT 500", args)
        return [row_dict(REQ_COLS + ('grant_decision_id', 'grant_status'), r) for r in cur.fetchall()]
    finally:
        con.close()


def request_history(rid):
    cols = ('event_id', 'event', 'username', 'requested_role', 'granted_role', 'actor', 'notes', 'occurred_at')
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT ' + ', '.join(cols) + ' FROM iam.access_request_history'
                    ' WHERE request_id = %s ORDER BY occurred_at, event_id', (rid,))
        return [row_dict(cols, r) for r in cur.fetchall()]
    finally:
        con.close()


def decide(rid, body, who, role):
    """Approve: a grant decision waiting for qa — no Keycloak call and no e-mail until
    it is confirmed. Reject: as before, the Keycloak account is deleted and the
    applicant is told."""
    decision = body.get('decision')
    grant = (body.get('role') or '').strip()
    notes = (body.get('notes') or '').strip()[:4000] or None
    send = body.get('send_email', True) is not False
    mail_subject = (body.get('email_subject') or '').strip()[:300]
    mail_body = (body.get('email_body') or '').strip()[:20000]
    if send and not (mail_subject and mail_body):
        return 400, {'error': 'the e-mail to the applicant needs a subject and a body (or untick "Send e-mail")'}
    if decision not in ('approve', 'reject'):
        return 400, {'error': 'decision must be approve or reject'}
    if decision == 'approve' and grant not in ROLES:
        return 400, {'error': 'choose the role to grant'}
    if decision == 'reject' and not notes:
        return 400, {'error': 'a rejection needs a note explaining why'}
    actor = who.get('username')
    dec = None
    try:
        with tx(who, role) as (con, cur):
            # Row lock: two admins deciding the same request at once get one winner.
            cur.execute('SELECT ' + ', '.join(REQ_COLS) + ' FROM iam.access_request WHERE request_id = %s FOR UPDATE', (rid,))
            row = cur.fetchone()
            if not row:
                return 404, {'error': 'no such request'}
            r = row_dict(REQ_COLS, row)
            if r['status'] != 'pending':
                return 409, {'error': 'already %s by %s' % (r['status'], r['decided_by'])}
            if decision == 'approve':
                if not r['keycloak_user_id']:
                    return 409, {'error': 'the request has no Keycloak account'}
                uid = r['keycloak_user_id']
                reason = 'access request #%s approved as %s%s' % (rid, grant, (': ' + notes) if notes else '')
                dec = record_decision(cur, 'grant', uid, r['username'], uid, None, grant, uid, reason, rid)
                cur.execute("UPDATE iam.access_request SET status = 'approved', granted_role = %s, decided_by = %s,"
                            " decided_at = now(), admin_notes = %s, email_subject = %s, email_body = %s"
                            " WHERE request_id = %s RETURNING " + ', '.join(REQ_COLS),
                            (grant, actor, notes, mail_subject if send else None, mail_body if send else None, rid))
            else:
                # Keycloak inside the open transaction: if it fails, the request stays pending.
                if r['keycloak_user_id']:
                    kc_delete_user(r['keycloak_user_id'])
                cur.execute("UPDATE iam.access_request SET status = 'rejected', decided_by = %s,"
                            " decided_at = now(), admin_notes = %s, email_subject = %s, email_body = %s"
                            " WHERE request_id = %s RETURNING " + ', '.join(REQ_COLS),
                            (actor, notes, mail_subject if send else None, mail_body if send else None, rid))
            r = row_dict(REQ_COLS, cur.fetchone())
            con.commit()
    except KCError as e:
        log('decision on %s failed in Keycloak: %s' % (rid, e))
        return 502, {'error': 'Keycloak refused the change: %s' % e}
    if r['status'] == 'rejected':
        tpl = 'rejected'
    elif r['granted_role'] != r['requested_role']:
        tpl = 'reassigned'
    else:
        tpl = 'approved'
    if dec:
        log('request %s approved by %s as %s: decision #%s waits for qa' % (rid, actor, grant, dec['decision_id']))
        return 202, {'request': r, 'decision': dec,
                     'email': {'sent': False, 'template': tpl,
                               'detail': ('sent when qa confirms decision #%s' % dec['decision_id']) if send
                               else 'not sent (unticked by the approver)'}}
    if send:
        sent, detail = send_mail([r['email']], mail_subject, mail_body + '\n')
    else:
        sent, detail = False, 'not sent (unticked by the approver)'
    log('request %s %s by %s; mail: %s' % (rid, r['status'], actor, detail))
    return 200, {'request': r, 'email': {'sent': sent, 'detail': detail, 'template': tpl}}


# ── Users: activate / deactivate / role / person (admins) ───────────────────
UUID_RE = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
STATUS_COLS = ('event_id', 'keycloak_user_id', 'username', 'action', 'reason', 'actor', 'occurred_at', 'from_role',
               'to_role', 'actor_sub', 'actor_person', 'decision_id')


def list_users():
    _, users, _ = kc('GET', '/users?max=2000&briefRepresentation=false')
    users = [u for u in users or [] if not u['username'].startswith('service-account-')]
    held = role_members()
    order = platform_roles()
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT keycloak_user_id, request_id FROM iam.access_request WHERE status = 'pending'")
        pending = dict(cur.fetchall())
        cur.execute('SELECT DISTINCT ON (keycloak_user_id) ' + ', '.join(STATUS_COLS) +
                    ' FROM iam.user_status_history ORDER BY keycloak_user_id, occurred_at DESC, event_id DESC')
        last = {r[1]: row_dict(STATUS_COLS, r) for r in cur.fetchall()}
        cur.execute("SELECT DISTINCT ON (keycloak_user_id) keycloak_user_id, decision_id, kind FROM iam.account_decision"
                    " WHERE status = 'pending_qa' AND kind NOT IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove')"
                    " ORDER BY keycloak_user_id, decision_id DESC")
        waiting = {r[0]: {'id': r[1], 'kind': r[2]} for r in cur.fetchall()}
    finally:
        con.close()
    out = []
    for u in users:
        d = profile_of(u)
        d.update(id=u['id'], enabled=bool(u.get('enabled')),
                 roles=[r for r in order if r in held.get(u['id'], [])], person_id=attr_person(u),
                 created=u.get('createdTimestamp'), pending_request_id=pending.get(u['id']),
                 pending_decision=waiting.get(u['id']), last_event=last.get(u['id']))
        out.append(d)
    out.sort(key=lambda d: (d['pending_request_id'] is not None, not d['enabled'], d['display_name'].lower()))
    return out


def user_status_history(user_id):
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT ' + ', '.join(STATUS_COLS) + ' FROM iam.user_status_history'
                    ' WHERE keycloak_user_id = %s ORDER BY occurred_at DESC, event_id DESC', (user_id,))
        return [row_dict(STATUS_COLS, r) for r in cur.fetchall()]
    finally:
        con.close()


def _managed_user(user_id, who, verb):
    """The account, if this admin may change it: not a service account, not their own."""
    try:
        u = kc_user(user_id)
    except KCError as e:
        raise Refused(*((404, 'no such user') if e.status == 404 else (502, str(e))))
    if u['username'].startswith('service-account-'):
        raise Refused(400, 'service accounts are not managed here')
    if user_id == who.get('sub'):
        raise Refused(400, 'you cannot %s your own account — ask another administrator' % verb)
    return u


def _pending_request(user_id):
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT request_id FROM iam.access_request WHERE keycloak_user_id = %s AND status = 'pending'", (user_id,))
        row = cur.fetchone()
    finally:
        con.close()
    return row[0] if row else None


def _logout(user_id, username):
    """End every SSO and offline session now, after commit; best effort."""
    try:
        kc('POST', '/users/%s/logout' % user_id)
        return None
    except Exception as e:                       # noqa: BLE001
        log('logout of %s failed: %s' % (username, e))
        return 'sessions not ended: %s' % e


CHANGED_NOW = 'the account changed while you were deciding: reload and try again'


def _names(mapped):
    return sorted(r['name'] for r in mapped)


def set_user_status(user_id, body, who, role):
    active = body.get('active')
    reason = (body.get('reason') or '').strip()[:2000] or None
    if not isinstance(active, bool):
        return 400, {'error': 'active must be true or false'}
    u = _managed_user(user_id, who, 'deactivate' if not active else 'activate')
    if not active:
        return _deactivate(u, reason, who, role)
    if u.get('enabled'):
        return 409, {'error': 'the account is already active'}
    pending = _pending_request(user_id)
    if pending:
        return 409, {'error': 'this account is waiting for its access request (#%s) — approve or reject that instead' % pending}
    mapped = mapped_platform(user_id)
    own = own_roles([r['name'] for r in mapped])
    if len(own) > 1:
        return 409, {'error': 'the account holds roles %s; change it to one role first' % ' and '.join(own)}
    from_role = own[0] if own else None
    if from_role:
        v = i17_violation(user_id, subject=u)
        if v:
            return 409, {'error': v}
    reason = reason or 'activated'
    # Every activation waits for qa (record_decision): an enabled account reaches the
    # hosts not gated by role yet (Grafana, until IAM 3.1) even with no platform role.
    with tx(who, role) as (con, cur):
        dec = record_decision(cur, 'activate', user_id, u['username'], person_of(u), from_role, None, None, reason)
        # The account lock is held from here: what was classified must still be so.
        if kc_user(user_id).get('enabled') or _names(mapped_platform(user_id)) != _names(mapped):
            raise Refused(409, CHANGED_NOW)
        if dec['status'] == 'applied':
            d = {'kind': 'activate', 'keycloak_user_id': user_id, 'username': u['username'],
                 'decision_id': dec['decision_id']}
            _keycloak_then_commit(con, d, [], 'nothing was recorded')
        else:
            con.commit()
    if dec['status'] != 'applied':
        log('activation of %s (%s) proposed by %s: decision #%s waits for qa' % (u['username'], from_role or 'no role',
                                                                                  who.get('username'), dec['decision_id']))
        return 202, {'status': 'pending_qa', 'decision': dec}
    log('account %s activated by %s' % (u['username'], who.get('username')))
    return 200, {'ok': True, 'status': 'applied', 'enabled': True, 'decision': dec}


def _deactivate(u, reason, who, role):
    """Applied at once, on an enabled or a disabled account: the record (which withdraws
    every waiting decision for the account and takes its lock), the MQTT person
    credentials, Keycloak re-read under that lock and disabled, commit — then the
    logout. The account is read again under the lock because a qa person may have just
    confirmed a grant or activation that enabled it."""
    user_id = u['id']
    if not reason:
        return 400, {'error': 'give a reason for the deactivation; it is recorded'}
    if u.get('enabled'):
        guard_last(user_id)                      # early answer; checked again under the lock
    try:
        with tx(who, role) as (con, cur):
            dec = record_decision(cur, 'deactivate', user_id, u['username'], person_of(u), None, None, None, reason)
            cur.execute('SELECT medcea.revoke_person_mqtt(%s::uuid, %s)', (user_id, 'deactivated'))
            revoked = (cur.fetchone() or [0])[0]
            if kc_user(user_id).get('enabled'):
                guard_last(user_id)
                kc_update_user(user_id, enabled=False)
            con.commit()
    except (KCError, OSError) as e:
        return 502, {'error': 'Keycloak refused the change: %s' % e}
    warning = _logout(user_id, u['username'])
    log('account %s deactivated by %s (decision #%s; withdrew %s; MQTT credentials revoked: %s)'
        % (u['username'], who.get('username'), dec['decision_id'], dec['withdrawn'] or 'none', revoked))
    out = {'ok': True, 'status': 'applied', 'enabled': False, 'decision': dec, 'mqtt_revoked': revoked}
    if warning:
        out['warning'] = warning
    return 200, out


def set_user_role(user_id, body, who, role):
    """One platform role per account. A widening waits for qa; a pure narrowing is
    applied at once: the record, the MQTT revocation, then Keycloak (add first, remove
    second, compensated on failure), commit last. The classification is made from
    Keycloak read before the account lock, so it is checked again under it."""
    new = (body.get('role') or '').strip()
    reason = (body.get('reason') or '').strip()[:2000]
    if new not in ROLES:
        return 400, {'error': 'choose one of: %s' % ', '.join(ROLES)}
    if not reason:
        return 400, {'error': 'give a reason for the role change; it is recorded'}
    u = _managed_user(user_id, who, 'change the role of')
    current = mapped_platform(user_id)
    own = own_roles([r['name'] for r in current])
    if own == [new] and len(current) == 1:
        return 409, {'error': 'the account already has the role %s' % new}
    pending = _pending_request(user_id)
    if pending:
        return 409, {'error': 'this account is waiting for its access request (#%s) — choose the role there' % pending}
    if u.get('enabled'):
        guard_last(user_id, new)
    # Two or more own roles: recorded as from none, so the change always waits.
    from_role = own[0] if len(own) == 1 else None
    v = i17_violation(user_id, new_role=new, subject=u)
    if v:
        return 409, {'error': v}
    with tx(who, role) as (con, cur):
        dec = record_decision(cur, 'role_change', user_id, u['username'], person_of(u), from_role, new, None, reason)
        if _names(mapped_platform(user_id)) != _names(current):
            raise Refused(409, CHANGED_NOW)
        if dec['status'] == 'applied':
            if kc_user(user_id).get('enabled'):
                guard_last(user_id, new)
            cur.execute('SELECT medcea.revoke_person_mqtt(%s::uuid, %s)', (user_id, 'role narrowed'))
            cur.fetchone()
            d = {'kind': 'role_change', 'keycloak_user_id': user_id, 'username': u['username'], 'to_role': new,
                 'decision_id': dec['decision_id']}
            _keycloak_then_commit(con, d, [], 'nothing was recorded')
        else:
            con.commit()
    if dec['status'] != 'applied':
        log('role change of %s %s -> %s proposed by %s: decision #%s waits for qa'
            % (u['username'], from_role or 'none', new, who.get('username'), dec['decision_id']))
        return 202, {'status': 'pending_qa', 'decision': dec, 'role': new, 'from': from_role}
    log('role of %s narrowed %s -> %s by %s' % (u['username'], from_role or 'none', new, who.get('username')))
    return 200, {'ok': True, 'status': 'applied', 'role': new, 'from': from_role, 'decision': dec}


def set_user_person(user_id, body, who, role):
    """A person_id change always waits for qa: the person is what not_own_author and
    I17 compare."""
    new = (body.get('person_id') or '').strip()
    reason = (body.get('reason') or '').strip()[:2000]
    if not PERSON_RE.match(new):
        return 400, {'error': 'person_id: 1–64 letters, digits or . _ : @ -, starting with a letter or digit'}
    if not reason:
        return 400, {'error': 'give a reason for the person_id change; it is recorded'}
    u = _managed_user(user_id, who, 'change the person of')
    if person_of(u) == new:
        return 409, {'error': 'the account already declares person %s' % new}
    v = i17_violation(user_id, new_person=new, subject=u)
    if v:
        return 409, {'error': v}
    with tx(who, role) as (con, cur):
        dec = record_decision(cur, 'person_id', user_id, u['username'], person_of(u), None, None, new, reason)
        if person_of(kc_user(user_id)) != person_of(u):
            raise Refused(409, CHANGED_NOW)
        con.commit()
    log('person_id of %s -> %s proposed by %s: decision #%s waits for qa' % (u['username'], new, who.get('username'),
                                                                             dec['decision_id']))
    return 202, {'status': dec['status'], 'decision': dec}


# ── Quarterly access review (audit_histories) ────────────────────────────────
REVIEW_COLS = ('review_id', 'period', 'created_by', 'created_at', 'signed_off_by_name', 'signed_off_at')


def list_reviews():
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT ' + ', '.join(REVIEW_COLS) + ' FROM iam.access_review ORDER BY created_at DESC')
        rows = [row_dict(REVIEW_COLS, r) for r in cur.fetchall()]
        cur.execute("SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-\"Q\"Q')")
        period = cur.fetchone()[0]
    finally:
        con.close()
    return {'reviews': rows, 'period': period}


def get_review(rid):
    cols = REVIEW_COLS + ('created_by_sub', 'created_by_person', 'sign_off_note', 'snapshot')
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT ' + ', '.join(cols) + ' FROM iam.access_review WHERE review_id = %s', (rid,))
        row = cur.fetchone()
    finally:
        con.close()
    if not row:
        return 404, {'error': 'no such review'}
    r = row_dict(cols, row)
    if isinstance(r['snapshot'], str):
        r['snapshot'] = json.loads(r['snapshot'])
    return 200, r


def _last_login(user_id):
    """The latest retained LOGIN event (needs realm-management view-events), or None."""
    try:
        _, ev, _ = kc('GET', '/events?type=LOGIN&user=%s&max=1' % user_id)
    except KCError:
        return None
    return (ev or [{}])[0].get('time')


def review_snapshot():
    """The service's part of the snapshot; iam.create_review adds the database's (units,
    pending decisions, decisions since, iam_db_roles, service_logins, the chain verdict)
    over any key of the same name, so the service cannot misreport them."""
    _, users, _ = kc('GET', '/users?max=2000&briefRepresentation=false')
    held = role_members()
    accounts = []
    for u in sorted(users or [], key=lambda u: u['username']):
        if u['username'].startswith('service-account-'):
            continue
        accounts.append({'id': u['id'], 'username': u['username'], 'enabled': bool(u.get('enabled')),
                         'created': u.get('createdTimestamp'), 'role': ', '.join(own_roles(held.get(u['id'], []))) or None,
                         'person_id': attr_person(u), 'last_login': _last_login(u['id'])})
    table = _table()
    iam = _medcea_iam()
    s = iam.settings() if iam is not None and hasattr(iam, 'settings') else {}
    sw = s.get('switches') or {}
    switches = {'IAM_ENFORCE': {'value': s.get('enforce'), 'source': '/iam/settings.json (live)'}}
    for k in ('IAM_GATES', 'IAM_NETPOL', 'IAM_POSTGREST_JWT'):
        switches[k] = {'value': sw.get(k), 'source': 'as of deploy-infra %s' % (sw.get('written_at') or '(time unknown)')}
    # The drift at this moment, so the qa person signing off sees what they accept:
    # a signed-off review explains the roles it lists here, and nothing it does not.
    con = db()
    try:
        drift = compute_drift(con.cursor(), [u for u in users or [] if not u['username'].startswith('service-account-')],
                              held)
    finally:
        con.close()
    return {'accounts': accounts, 'policy': {'version': table.get('policy_version'), 'digest': table.get('digest')},
            'waivers': table.get('waivers') or [], 'switches': switches, 'drift': drift}


def create_review(who, role):
    """A second review in the same quarter is the function's 23505 (409, naming it)."""
    snap = review_snapshot()                     # Keycloak first, outside the transaction
    with tx(who, role) as (con, cur):
        cur.execute('SELECT iam.create_review(%s::jsonb)', (json.dumps(snap),))
        rid = cur.fetchone()[0]
        con.commit()
    log('access review #%s created by %s' % (rid, who.get('username')))
    return 201, {'review': rid}


def sign_off_review(rid, body, who, role):
    note = (body.get('note') or '').strip()[:4000] or None
    with tx(who, role) as (con, cur):
        cur.execute('SELECT iam.sign_off_review(%s, %s)', (rid, note))
        cur.fetchone()
        con.commit()
    log('access review #%s signed off by %s' % (rid, who.get('username')))
    return 200, {'review': rid}


# ── Profile (any signed-in user, own account only) ──────────────────────────
def kc_user_by_username(username):
    _, users, _ = kc('GET', '/users?username=%s&exact=true' % urllib.parse.quote(username))
    return users[0] if users else None


def profile_of(u):
    first, last = (u.get('firstName') or '').strip(), (u.get('lastName') or '').strip()
    org = ((u.get('attributes') or {}).get('organisation') or [''])[0]
    return {'username': u['username'], 'email': u.get('email') or '', 'first_name': first, 'last_name': last,
            'organisation': org, 'display_name': (first + ' ' + last).strip() or u['username']}


def account_links(host):
    """Sign-out and change-password URLs for the client this host signs in with."""
    client = HOST_CLIENTS.get(host, '')
    if not (client and KC_PUBLIC):
        return {'sign_out': '/oauth2/sign_out', 'change_password': ''}
    q = urllib.parse.quote
    logout = '%s/realms/%s/protocol/openid-connect/logout?client_id=%s&post_logout_redirect_uri=%s' % (
        KC_PUBLIC, KC_REALM, client, q('https://%s/' % host, safe=''))
    # Application-initiated action: Keycloak shows its (medcea-themed) update
    # password page, asking to sign in again if the login is old, then returns
    # here. The password never passes through this service.
    pw = '%s/realms/%s/protocol/openid-connect/auth?client_id=%s&response_type=code&scope=openid' \
         '&kc_action=UPDATE_PASSWORD&redirect_uri=%s' % (
             KC_PUBLIC, KC_REALM, client, q('https://%s/_account/?password=updated' % host, safe=''))
    return {'sign_out': '/oauth2/sign_out?rd=' + q(logout, safe=''), 'change_password': pw}


def update_profile(username, body):
    first = (body.get('first_name') or '').strip()
    last = (body.get('last_name') or '').strip()
    org = (body.get('organisation') or '').strip()
    if not first or not last or max(len(first), len(last)) > 100:
        return 400, {'error': 'Enter your first and last name.'}
    if len(org) > 200:
        return 400, {'error': 'Organisation is too long.'}
    u = kc_user_by_username(username)
    if not u:
        return 404, {'error': 'account not found'}
    attrs = dict(u.get('attributes') or {})
    attrs['organisation'] = [org] if org else []
    # A full representation: Keycloak's PUT replaces the attribute map, and an
    # email left out would trip the realm's user profile validation.
    kc('PUT', '/users/%s' % u['id'], {'firstName': first, 'lastName': last, 'email': u.get('email'),
                                      'attributes': attrs})
    log('profile updated by %s' % username)
    return 200, profile_of(kc_user_by_username(username))


# ── Access policy check (IAM plan 1.2; the admin port enforces from 2.7) ─────
def _http_check(handler, iam, service, enforce):
    """medcea_iam.http_check; enforce=True refuses whatever check() refuses, whatever
    IAM_ENFORCE says, with one 'refused' log line. A library from before IAM 2.7 has no
    `enforce`: the same check is then enforced here."""
    fn = iam.http_check
    try:
        takes = 'enforce' in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        takes = False
    if takes:
        return fn(handler, service, enforce=True) if enforce else fn(handler, service)
    if not enforce:
        return fn(handler, service)
    d = iam.check(service, handler.command, handler.path, handler.headers)
    handler.medcea_iam = d
    if d.allow:
        return True
    print('medcea_iam: refused %s %s on %s for %s: %s %s' % (
        handler.command, handler.path.split('?', 1)[0], service, (d.who or {}).get('username') or '-',
        d.status, d.reason), file=sys.stderr, flush=True)
    handler.send(d.status, {'error': d.reason})
    return False


# ── HTTP ──────────────────────────────────────────────────────────────────────
class Base(BaseHTTPRequestHandler):
    server_version = 'medcea-access'
    IAM_SERVICE = None      # the route-table service of each port, set below
    ENFORCE_ALWAYS = False  # True on the admin port only; there is no switch to turn it off

    def parse_request(self):
        # Before any do_*: the raw path, /_account/ prefix and all, is what the
        # route table keys on (Profile.route() strips it later).
        if not super().parse_request():
            return False
        if self.ENFORCE_ALWAYS and self.path == '/healthz':
            return True                          # liveness: answered before any check
        iam = _medcea_iam()
        if iam is None:
            # No library: the admin port refuses everything but /healthz; the others
            # fail closed under enforcement (IAM_ENFORCE is also in the pod's
            # environment for this case), report-only otherwise.
            if self.ENFORCE_ALWAYS or (os.environ.get('IAM_ENFORCE') == 'true' and self.path.split('?')[0] != '/healthz'):
                self.send(503, {'error': 'access policy not loaded'})
                return False
            return True
        if not _http_check(self, iam, self.IAM_SERVICE, self.ENFORCE_ALWAYS):
            return False
        if self.ENFORCE_ALWAYS:
            w = getattr(getattr(self, 'medcea_iam', None), 'who', None) or {}
            if not _is_uuid(w.get('sub')):       # a public route (allowed, who None) has no person
                self.send(401, {'error': 'sign in'})
                return False
        return True

    def log_message(self, fmt, *args):
        if not self.path.startswith('/healthz'):
            log('%s %s' % (self.address_string(), fmt % args))

    def send(self, status, payload, ctype='application/json'):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype + ('; charset=utf-8' if 'charset' not in ctype else ''))
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def page(self, name):
        with open(os.path.join(HTML_DIR, name), 'rb') as fh:
            self.send(200, fh.read(), 'text/html')

    def body_json(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > 64 * 1024:
            raise ValueError('request too large')
        return json.loads(self.rfile.read(n) or b'{}')

    def guarded(self, fn):
        try:
            self.send(*fn())
        except Refused as e:
            self.send(e.status, e.payload)
        except (ValueError, json.JSONDecodeError) as e:
            self.send(400, {'ok': False, 'error': str(e)})
        except KCError as e:
            log('Keycloak error on %s %s: %s' % (self.command, self.path, e))
            self.send(502, {'ok': False, 'error': 'Keycloak refused the request: %s' % e})
        except Exception as e:                   # noqa: BLE001
            mapped = db_refusal(e)
            if mapped:
                return self.send(*mapped)
            log('error on %s %s: %r' % (self.command, self.path, e))
            self.send(500, {'ok': False, 'error': 'Something went wrong on our side. Please try again later.'})


class Public(Base):
    IAM_SERVICE = 'access-public'
    # CORS for the login page only. Not credentialed: registration needs no
    # cookie, and nothing on this port answers for a signed-in user.
    def end_headers(self):
        if LOGIN_ORIGIN and self.headers.get('Origin') == LOGIN_ORIGIN:
            self.send_header('Access-Control-Allow-Origin', LOGIN_ORIGIN)
            self.send_header('Vary', 'Origin')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Methods', 'GET, POST')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Max-Age', '3600')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p in ('/register', '/register/'):
            return self.page('register.html')
        if p == '/healthz':
            return self.send(200, {'ok': True})
        if p == '/api/register/roles':
            return self.send(200, [{'id': k, 'label': v} for k, v in ROLES.items()])
        self.send(404, {'error': 'not found'})

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != '/api/register':
            return self.send(404, {'error': 'not found'})
        ip = (self.headers.get('X-Forwarded-For') or self.client_address[0]).split(',')[0].strip()
        self.guarded(lambda: register(self.body_json(), ip))


class Admin(Base):
    IAM_SERVICE = 'access'
    ENFORCE_ALWAYS = True

    def who(self):
        """The verified person (sub, person_id, username, roles): parse_request let the
        request through only with a uuid sub. Never an X-Forwarded-* header."""
        return self.medcea_iam.who

    def role(self):
        """The person's one own platform role for set_actor; 403 without exactly one."""
        iam = _medcea_iam()
        r = iam.actor_role(self.medcea_iam) if iam is not None and hasattr(iam, 'actor_role') else None
        if not r:
            raise Refused(403, 'your account holds more than one platform role; ask an administrator')
        return r

    def me(self):
        w = self.who()
        roles = w.get('roles') or []
        iam = _medcea_iam()
        role = iam.actor_role(self.medcea_iam) if iam is not None and hasattr(iam, 'actor_role') else None
        can = {k: allows(roles, m, p) for k, (m, p) in {
            'requests': ('GET', '/api/requests'), 'users': ('GET', '/api/users'),
            'settings': ('GET', '/api/settings'), 'templates': ('GET', '/api/templates'),
            'decisions_read': ('GET', '/api/decisions'), 'decisions_check': ('POST', '/api/decisions/1/confirm'),
            'decisions_withdraw': ('POST', '/api/decisions/1/withdraw'),
            'review_read': ('GET', '/api/review'), 'review_write': ('POST', '/api/review'),
            'histories': ('GET', '/api/config-history')}.items()}
        out = {'user': w.get('username'), 'sub': w.get('sub'), 'has_person': bool(w.get('person_id')), 'role': role,
               'roles': [{'id': k, 'label': v} for k, v in ROLES.items()], 'smtp': smtp_ready(mail_settings()),
               'platform': PLATFORM, 'portal_url': PORTAL_URL, 'admin_url': ACCESS_URL + '/', 'can': can}
        if can['users']:
            out['widening'] = _table().get('widening') or {}
        return 200, out

    def same_origin_json(self):
        """CSRF: an admin-port POST is JSON (a cross-site form cannot send it without a
        preflight, which this port never answers) from the User Manager's own origin."""
        ctype = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if ctype != 'application/json':
            self.send(415, {'error': 'send JSON (Content-Type: application/json)'})
            return False
        if not ACCESS_URL or self.headers.get('Origin') != ACCESS_URL:
            log('refused a POST to %s from origin %r' % (self.path, self.headers.get('Origin')))
            self.send(403, {'error': 'cross-origin request refused'})
            return False
        return True

    def test_mail(self, body, who):
        to = (body.get('to') or '').strip()
        if not to:
            to = (kc_user(who['sub']).get('email') or '').strip()
        if not EMAIL_RE.match(to):
            return 400, {'error': 'no address to send the test to'}
        sent, detail = send_mail([to], '[MedCEA] Test e-mail',
                                 'This is a test from the MedCEA User Manager, sent by %s.\n'
                                 'If you can read it, access-request e-mail works.\n' % who.get('username'))
        return (200 if sent else 502), {'sent': sent, 'detail': detail}

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == '/healthz':
            return self.send(200, {'ok': True, 'access_version': ACCESS_VERSION, 'enforce_always': True})
        if p.path == '/':
            return self.page('admin.html')
        if p.path == '/api/me':
            return self.guarded(self.me)
        q = urllib.parse.parse_qs(p.query)
        if p.path == '/api/decisions':
            return self.guarded(lambda: list_decisions(q, self.who()))
        if p.path == '/api/settings':
            return self.guarded(lambda: (200, dict(public_settings(mail_settings()), pending=pending_settings())))
        if p.path == '/api/templates':
            return self.guarded(lambda: (200, all_templates()))
        if p.path == '/api/config-history':
            return self.guarded(lambda: (200, config_history()))
        if p.path == '/api/users':
            return self.guarded(lambda: (200, list_users()))
        m = re.fullmatch(r'/api/users/(%s)/history' % UUID_RE, p.path)
        if m:
            return self.guarded(lambda: (200, user_status_history(m.group(1))))
        if p.path == '/api/requests':
            status = q.get('status', ['pending'])[0]
            return self.guarded(lambda: (200, list_requests(status)))
        m = re.fullmatch(r'/api/requests/(\d+)/history', p.path)
        if m:
            return self.guarded(lambda: (200, request_history(int(m.group(1)))))
        if p.path == '/api/review':
            return self.guarded(lambda: (200, list_reviews()))
        m = re.fullmatch(r'/api/review/(\d+)', p.path)
        if m:
            return self.guarded(lambda: get_review(int(m.group(1))))
        self.send(404, {'error': 'not found'})

    def do_POST(self):
        if not self.same_origin_json():
            return
        path = urllib.parse.urlparse(self.path).path
        who = self.who()
        m = re.fullmatch(r'/api/requests/(\d+)/decision', path)
        if m:
            return self.guarded(lambda: decide(int(m.group(1)), self.body_json(), who, self.role()))
        m = re.fullmatch(r'/api/decisions/(\d+)/(confirm|refuse|review|withdraw)', path)
        if m:
            fn = {'confirm': confirm_decision, 'refuse': refuse_decision, 'review': review_decision,
                  'withdraw': withdraw_decision}[m.group(2)]
            return self.guarded(lambda: fn(int(m.group(1)), self.body_json(), who, self.role()))
        if path == '/api/settings':
            return self.guarded(lambda: save_settings(self.body_json(), who, self.role()))
        if path == '/api/settings/test':
            return self.guarded(lambda: self.test_mail(self.body_json(), who))
        m = re.fullmatch(r'/api/users/(%s)/(status|role|person)' % UUID_RE, path)
        if m:
            fn = {'status': set_user_status, 'role': set_user_role, 'person': set_user_person}[m.group(2)]
            return self.guarded(lambda: fn(m.group(1), self.body_json(), who, self.role()))
        m = re.fullmatch(r'/api/templates/([a-z-]+)(/reset)?', path)
        if m:
            if m.group(2):
                return self.guarded(lambda: reset_template(m.group(1), who, self.role()))
            return self.guarded(lambda: save_template(m.group(1), self.body_json(), who, self.role()))
        if path == '/api/review':
            return self.guarded(lambda: create_review(who, self.role()))
        m = re.fullmatch(r'/api/review/(\d+)/sign-off', path)
        if m:
            return self.guarded(lambda: sign_off_review(int(m.group(1)), self.body_json(), who, self.role()))
        self.send(404, {'error': 'not found'})


class Profile(Base):
    IAM_SERVICE = 'access-profile'
    """Mounted at /_account/ on every signed-in host by that host's oauth2-proxy."""
    def username(self):
        return (self.headers.get('X-Forwarded-Preferred-Username') or '').strip()

    def route(self):
        # oauth2-proxy routes /_account/ here; strip the mount prefix (as many
        # times as it appears, so either way of forwarding the path works).
        p = urllib.parse.urlparse(self.path).path
        while p.startswith('/_account'):
            p = p[len('/_account'):]
        return p

    def do_GET(self):
        p = self.route()
        if p == '/healthz':
            return self.send(200, {'ok': True})
        if p == '/user-menu.js':
            with open(os.path.join(HTML_DIR, 'user-menu.js'), 'rb') as fh:
                return self.send(200, fh.read(), 'application/javascript')
        user = self.username()
        if not user:
            return self.send(401, {'error': 'not signed in'})
        if p in ('', '/'):
            return self.page('profile.html')
        if p == '/api/me':
            def me():
                u = kc_user_by_username(user)
                if not u:
                    return 404, {'error': 'account not found'}
                return 200, dict(profile_of(u), **account_links(self.headers.get('Host', '').split(':')[0]))
            return self.guarded(me)
        self.send(404, {'error': 'not found'})

    def do_POST(self):
        user = self.username()
        if not user:
            return self.send(401, {'error': 'not signed in'})
        if self.route() != '/api/me':
            return self.send(404, {'error': 'not found'})
        self.guarded(lambda: update_profile(user, self.body_json()))


def serve(handler, port):
    srv = ThreadingHTTPServer(('0.0.0.0', port), handler)
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == '__main__':
    if not KC_CLIENT_SECRET:
        sys.exit('KC_CLIENT_SECRET is empty — run ./deploy-infra.sh to create the access client')
    threading.Thread(target=serve, args=(Admin, 8081), daemon=True).start()
    threading.Thread(target=serve, args=(Profile, 8082), daemon=True).start()
    log('listening: public :8080, admin :8081, profile :8082')
    serve(Public, 8080)
