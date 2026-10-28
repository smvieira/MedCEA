"""Self-service access requests: the registration form and the User Manager.

Two listeners, so the trust boundary is a port rather than a path check:
  :8080  public  GET /register, POST /api/register             (Ingress, no auth)
  :8081  admin   GET /, /api/requests, POST .../decision          (only behind the
                 access oauth2-proxy, which admits realm role 'admin' and sets
                 X-Forwarded-Preferred-Username / -Email for the audit trail)
  :8082  profile /_account/ on every signed-in host (portal, config, access):
                 each host's oauth2-proxy routes that path here, so the user
                 menu, the profile page and its API act for whoever that proxy
                 signed in — any role, and only their own account.

A registration creates the Keycloak user *disabled* and stores the request in
iam.access_request; nobody can sign in until an admin approves. Approval maps
the granted realm role and enables the user; rejection deletes the Keycloak
account (the request row keeps who asked, for what, and why it was refused), so
the person may apply again. Every step lands in iam.access_request_history by
trigger. E-mail goes out after the database commit; without SMTP settings the
message is written to the log instead.

Mail is configured in the User Manager, not in config.env: the Gmail account
(iam.mail_settings) and the four templates (iam.mail_template, falling back to
the files in templates/). The approver sees the applicant's e-mail pre-filled
from its template and may edit it; what was sent is stored with the decision.
Changes to either are logged in the append-only iam.config_history.
"""
import json, os, re, smtplib, ssl, string, sys, threading, time, urllib.error, urllib.parse, urllib.request
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

# The platform roles this service offers, in the form's order. The access policy
# (apps/iam/policy/defaults.yaml) has eleven; the rest are offered once the
# services enforce it (IAM plan, Phase 2.6). engineer is offered from Phase 0
# because the policy admits only engineers to Node-RED, MQTT Explorer and
# device onboarding.
ROLES = {
    'operator': 'Operator — runs recipes and day-to-day cultivation',
    'engineer': 'Automation Engineer — devices, recipes, controllers, flows and dashboards (drafts that QA approves)',
    'qa':       'Quality Assurance — reviews data and releases batches',
    'auditor':  'Auditor — read-only access to records and audit trails',
    'admin':    'Administrator — manages the platform and its users',
}

USERNAME_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{2,31}$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, flush=True)


# ── Database ──────────────────────────────────────────────────────────────────
def db():
    import pg8000.dbapi
    return pg8000.dbapi.connect(**PG)


REQ_COLS = ('request_id', 'keycloak_user_id', 'username', 'email', 'first_name', 'last_name',
            'organisation', 'requested_role', 'justification', 'status', 'granted_role',
            'decided_by', 'decided_at', 'admin_notes', 'created_at', 'email_subject', 'email_body')


def row_dict(cols, row):
    d = dict(zip(cols, row))
    for k, v in d.items():
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d


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


def kc_set_enabled(user_id, enabled, **extra):
    """Read-modify-write the whole user: a partial PUT is how Keycloak loses
    things (see the service-account pitfall in CLAUDE.md)."""
    _, u, _ = kc('GET', '/users/%s' % user_id)
    u['enabled'] = enabled
    u.update(extra)
    kc('PUT', '/users/%s' % user_id, u)


def kc_grant_and_enable(user_id, role):
    _, role_rep, _ = kc('GET', '/roles/%s' % urllib.parse.quote(role))
    kc('POST', '/users/%s/role-mappings/realm' % user_id, [role_rep])
    kc_set_enabled(user_id, True, emailVerified=True)


def admin_emails():
    try:
        _, users, _ = kc('GET', '/roles/admin/users?max=200')
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


def mail_settings():
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT ' + ', '.join(SETTINGS_COLS) + ' FROM iam.mail_settings WHERE id = 1')
        row = cur.fetchone()
    finally:
        con.close()
    return row_dict(SETTINGS_COLS, row) if row else dict(
        smtp_host='smtp.gmail.com', smtp_port=587, smtp_user='', smtp_pass='', from_name=PLATFORM,
        notify_emails='', updated_by=None, updated_at=None)


def smtp_ready(st):
    return bool(st['smtp_host'] and st['smtp_user'] and st['smtp_pass'])


def default_template(name):
    """templates/<name>.txt: first line 'Subject: ...', a blank line, the body."""
    with open(os.path.join(TEMPLATE_DIR, name + '.txt'), encoding='utf-8') as fh:
        head, _, body = fh.read().partition('\n\n')
    subject = head[len('Subject:'):].strip() if head.startswith('Subject:') else PLATFORM
    return subject, body.strip() + '\n'


def all_templates():
    con = db()
    try:
        cur = con.cursor()
        cur.execute('SELECT name, subject, body, updated_by, updated_at FROM iam.mail_template')
        saved = {r[0]: row_dict(('name', 'subject', 'body', 'updated_by', 'updated_at'), r) for r in cur.fetchall()}
    finally:
        con.close()
    out = []
    for name in TEMPLATES:
        d_subject, d_body = default_template(name)
        t = saved.get(name)
        out.append({'name': name, 'subject': t['subject'] if t else d_subject, 'body': t['body'] if t else d_body,
                    'default_subject': d_subject, 'default_body': d_body, 'customised': bool(t),
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


def kc_sync_mail(st):
    """Keycloak's own mail (Forgot password?) uses the same account. Needs
    realm-management manage-realm on the access service account."""
    rep = {'resetPasswordAllowed': smtp_ready(st)}
    if smtp_ready(st):
        port = str(st['smtp_port'])
        rep['smtpServer'] = {'host': st['smtp_host'], 'port': port, 'auth': 'true', 'user': st['smtp_user'],
                             'password': st['smtp_pass'], 'from': st['smtp_user'],
                             'fromDisplayName': st['from_name'] or PLATFORM,
                             'starttls': 'false' if port == '465' else 'true', 'ssl': 'true' if port == '465' else 'false'}
    else:
        rep['smtpServer'] = {}
    try:
        kc('PUT', '', rep)
        return 'Keycloak updated (Forgot password? %s)' % ('on' if smtp_ready(st) else 'off')
    except Exception as e:                       # noqa: BLE001
        log('Keycloak mail sync failed:', e)
        return 'Keycloak not updated (%s) — Forgot password? keeps its previous mail settings' % e


def public_settings(st):
    d = {k: v for k, v in st.items() if k != 'smtp_pass'}
    d['pass_set'] = bool(st['smtp_pass'])
    d['ready'] = smtp_ready(st)
    return d


def save_settings(body, actor):
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
    if smtp_ready(new):                          # prove the login before keeping it
        try:
            smtp_connect(new).quit()
        except smtplib.SMTPAuthenticationError:
            return 400, {'error': 'Gmail rejected this address / app password. Use an app password '
                                  '(myaccount.google.com/apppasswords), not your normal password.'}
        except Exception as e:                   # noqa: BLE001
            return 400, {'error': 'could not log in to %s:%s — %s' % (new['smtp_host'], new['smtp_port'], e)}
    con = db()
    try:
        cur = con.cursor()
        cur.execute('UPDATE iam.mail_settings SET smtp_host=%s, smtp_port=%s, smtp_user=%s, smtp_pass=%s,'
                    ' from_name=%s, notify_emails=%s, updated_by=%s, updated_at=now() WHERE id = 1',
                    (new['smtp_host'], new['smtp_port'], new['smtp_user'], new['smtp_pass'],
                     new['from_name'], new['notify_emails'], actor))
        con.commit()
    finally:
        con.close()
    log('mail settings saved by %s (account %s)' % (actor, new['smtp_user'] or 'none'))
    return 200, {'settings': public_settings(mail_settings()), 'keycloak': kc_sync_mail(new)}


def save_template(name, body, actor):
    if name not in TEMPLATES:
        return 404, {'error': 'no such template'}
    subject, text = (body.get('subject') or '').strip(), (body.get('body') or '').strip()
    if not subject or not text:
        return 400, {'error': 'subject and body are both required'}
    if len(subject) > 300 or len(text) > 20000:
        return 400, {'error': 'template too long'}
    con = db()
    try:
        cur = con.cursor()
        cur.execute('INSERT INTO iam.mail_template (name, subject, body, updated_by) VALUES (%s,%s,%s,%s)'
                    ' ON CONFLICT (name) DO UPDATE SET subject = EXCLUDED.subject, body = EXCLUDED.body,'
                    ' updated_by = EXCLUDED.updated_by, updated_at = now()', (name, subject, text + '\n', actor))
        con.commit()
    finally:
        con.close()
    return 200, {'templates': all_templates()}


def reset_template(name, actor):
    if name not in TEMPLATES:
        return 404, {'error': 'no such template'}
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT set_config('iam.actor', %s, true)", (actor,))   # for the history trigger
        cur.execute('DELETE FROM iam.mail_template WHERE name = %s', (name,))
        con.commit()
    finally:
        con.close()
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


# ── User Manager (admin) ──────────────────────────────────────────────────────
def list_requests(status):
    con = db()
    try:
        cur = con.cursor()
        sql = 'SELECT ' + ', '.join(REQ_COLS) + ' FROM iam.access_request'
        args = ()
        if status in ('pending', 'approved', 'rejected'):
            sql += ' WHERE status = %s'
            args = (status,)
        cur.execute(sql + " ORDER BY (status = 'pending') DESC, created_at DESC LIMIT 500", args)
        return [row_dict(REQ_COLS, r) for r in cur.fetchall()]
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


def decide(rid, body, actor):
    decision = body.get('decision')
    role = (body.get('role') or '').strip()
    notes = (body.get('notes') or '').strip()[:4000] or None
    send = body.get('send_email', True) is not False
    mail_subject = (body.get('email_subject') or '').strip()[:300]
    mail_body = (body.get('email_body') or '').strip()[:20000]
    if send and not (mail_subject and mail_body):
        return 400, {'error': 'the e-mail to the applicant needs a subject and a body (or untick "Send e-mail")'}
    if decision not in ('approve', 'reject'):
        return 400, {'error': 'decision must be approve or reject'}
    if decision == 'approve' and role not in ROLES:
        return 400, {'error': 'choose the role to grant'}
    if decision == 'reject' and not notes:
        return 400, {'error': 'a rejection needs a note explaining why'}
    con = db()
    try:
        cur = con.cursor()
        # Row lock: two admins deciding the same request at once get one winner.
        cur.execute('SELECT ' + ', '.join(REQ_COLS) + ' FROM iam.access_request WHERE request_id = %s FOR UPDATE', (rid,))
        row = cur.fetchone()
        if not row:
            return 404, {'error': 'no such request'}
        r = row_dict(REQ_COLS, row)
        if r['status'] != 'pending':
            con.rollback()
            return 409, {'error': 'already %s by %s' % (r['status'], r['decided_by'])}
        # Keycloak first, inside the open transaction: if it fails, the request
        # stays pending and nothing is recorded as decided.
        if decision == 'approve':
            if not r['keycloak_user_id']:
                con.rollback()
                return 409, {'error': 'the request has no Keycloak account'}
            kc_grant_and_enable(r['keycloak_user_id'], role)
            cur.execute("UPDATE iam.access_request SET status = 'approved', granted_role = %s, decided_by = %s,"
                        " decided_at = now(), admin_notes = %s, email_subject = %s, email_body = %s"
                        " WHERE request_id = %s RETURNING " + ', '.join(REQ_COLS),
                        (role, actor, notes, mail_subject if send else None, mail_body if send else None, rid))
        else:
            if r['keycloak_user_id']:
                kc_delete_user(r['keycloak_user_id'])
            cur.execute("UPDATE iam.access_request SET status = 'rejected', decided_by = %s,"
                        " decided_at = now(), admin_notes = %s, email_subject = %s, email_body = %s"
                        " WHERE request_id = %s RETURNING " + ', '.join(REQ_COLS),
                        (actor, notes, mail_subject if send else None, mail_body if send else None, rid))
        r = row_dict(REQ_COLS, cur.fetchone())
        con.commit()
    except KCError as e:
        con.rollback()
        log('decision on %s failed in Keycloak: %s' % (rid, e))
        return 502, {'error': 'Keycloak refused the change: %s' % e}
    finally:
        con.close()
    if r['status'] == 'rejected':
        tpl = 'rejected'
    elif r['granted_role'] != r['requested_role']:
        tpl = 'reassigned'
    else:
        tpl = 'approved'
    if send:
        sent, detail = send_mail([r['email']], mail_subject, mail_body + '\n')
    else:
        sent, detail = False, 'not sent (unticked by the approver)'
    log('request %s %s by %s (%s); mail: %s' % (rid, r['status'], actor, r['granted_role'] or '-', detail))
    return 200, {'request': r, 'email': {'sent': sent, 'detail': detail, 'template': tpl}}


# ── Users: activate / deactivate (admins) ───────────────────────────────────
UUID_RE = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
STATUS_COLS = ('event_id', 'keycloak_user_id', 'username', 'action', 'reason', 'actor', 'occurred_at', 'from_role', 'to_role')


def role_members():
    """user id -> platform roles held (one call per role, not per user)."""
    held = {}
    for role in ROLES:
        _, users, _ = kc('GET', '/roles/%s/users?max=2000' % role)
        for u in users or []:
            held.setdefault(u['id'], []).append(role)
    return held


def list_users():
    _, users, _ = kc('GET', '/users?max=2000&briefRepresentation=false')
    users = [u for u in users or [] if not u['username'].startswith('service-account-')]
    held = role_members()
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT keycloak_user_id, request_id FROM iam.access_request WHERE status = 'pending'")
        pending = dict(cur.fetchall())
        cur.execute('SELECT DISTINCT ON (keycloak_user_id) ' + ', '.join(STATUS_COLS) +
                    ' FROM iam.user_status_history ORDER BY keycloak_user_id, occurred_at DESC, event_id DESC')
        last = {r[1]: row_dict(STATUS_COLS, r) for r in cur.fetchall()}
    finally:
        con.close()
    out = []
    for u in users:
        d = profile_of(u)
        d.update(id=u['id'], enabled=bool(u.get('enabled')), roles=[r for r in ROLES if r in held.get(u['id'], [])],
                 created=u.get('createdTimestamp'), pending_request_id=pending.get(u['id']),
                 last_event=last.get(u['id']))
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


def set_user_status(user_id, body, actor):
    active = body.get('active')
    reason = (body.get('reason') or '').strip()[:2000] or None
    if not isinstance(active, bool):
        return 400, {'error': 'active must be true or false'}
    try:
        _, u, _ = kc('GET', '/users/%s' % user_id)
    except KCError as e:
        return (404, {'error': 'no such user'}) if e.status == 404 else (502, {'error': str(e)})
    if u['username'].startswith('service-account-'):
        return 400, {'error': 'service accounts are not managed here'}
    if bool(u.get('enabled')) == active:
        return 409, {'error': 'the account is already %s' % ('active' if active else 'inactive')}
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT request_id FROM iam.access_request WHERE keycloak_user_id = %s AND status = 'pending'", (user_id,))
        pending = cur.fetchone()
        if active and pending:
            return 409, {'error': 'this account is waiting for its access request (#%s) — approve or reject that instead' % pending[0]}
        if not active:
            if not reason:
                return 400, {'error': 'give a reason for the deactivation; it is recorded'}
            if u['username'] == actor:
                return 400, {'error': 'you cannot deactivate your own account'}
            _, admins, _ = kc('GET', '/roles/admin/users?max=2000')
            if any(a['id'] == user_id for a in admins or []) and \
                    not any(a.get('enabled') and a['id'] != user_id for a in admins or []):
                return 400, {'error': 'this is the last active administrator'}
        # The record first, Keycloak second, commit last: if Keycloak refuses,
        # nothing is recorded; if the record cannot be written, Keycloak is not touched.
        cur.execute('INSERT INTO iam.user_status_history (keycloak_user_id, username, action, reason, actor)'
                    ' VALUES (%s,%s,%s,%s,%s)', (user_id, u['username'], 'activated' if active else 'deactivated', reason, actor))
        kc_set_enabled(user_id, active)
        con.commit()
    except KCError as e:
        con.rollback()
        return 502, {'error': 'Keycloak refused the change: %s' % e}
    finally:
        con.close()
    if not active:
        try:                                     # end every open session now, not at token expiry
            kc('POST', '/users/%s/logout' % user_id)
        except Exception as e:                   # noqa: BLE001
            log('logout of %s failed: %s' % (u['username'], e))
    log('account %s %s by %s' % (u['username'], 'activated' if active else 'deactivated', actor))
    return 200, {'ok': True, 'enabled': active}


def set_user_role(user_id, body, actor):
    """One platform role per account: the new one replaces whatever it held."""
    role = (body.get('role') or '').strip()
    reason = (body.get('reason') or '').strip()[:2000]
    if role not in ROLES:
        return 400, {'error': 'choose one of: %s' % ', '.join(ROLES)}
    if not reason:
        return 400, {'error': 'give a reason for the role change; it is recorded'}
    try:
        _, u, _ = kc('GET', '/users/%s' % user_id)
    except KCError as e:
        return (404, {'error': 'no such user'}) if e.status == 404 else (502, {'error': str(e)})
    if u['username'].startswith('service-account-'):
        return 400, {'error': 'service accounts are not managed here'}
    if u['username'] == actor:
        return 400, {'error': 'you cannot change your own role — ask another administrator'}
    _, mapped, _ = kc('GET', '/users/%s/role-mappings/realm' % user_id)
    current = [r for r in mapped or [] if r['name'] in ROLES]
    if [r['name'] for r in current] == [role]:
        return 409, {'error': 'the account already has the role %s' % role}
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT request_id FROM iam.access_request WHERE keycloak_user_id = %s AND status = 'pending'", (user_id,))
        pending = cur.fetchone()
        if pending:
            return 409, {'error': 'this account is waiting for its access request (#%s) — choose the role there' % pending[0]}
        if any(r['name'] == 'admin' for r in current) and role != 'admin':
            _, admins, _ = kc('GET', '/roles/admin/users?max=2000')
            if not any(a.get('enabled') and a['id'] != user_id for a in admins or []):
                return 400, {'error': 'this is the last active administrator'}
        from_role = ','.join(r['name'] for r in current) or None
        cur.execute('INSERT INTO iam.user_status_history (keycloak_user_id, username, action, reason, actor, from_role, to_role)'
                    ' VALUES (%s,%s,%s,%s,%s,%s,%s)', (user_id, u['username'], 'role_changed', reason, actor, from_role, role))
        # Add first, remove second: a failure in between leaves the account with
        # both roles (visible, fixable), never with none.
        _, role_rep, _ = kc('GET', '/roles/%s' % role)
        kc('POST', '/users/%s/role-mappings/realm' % user_id, [role_rep])
        old = [r for r in current if r['name'] != role]
        if old:
            kc('DELETE', '/users/%s/role-mappings/realm' % user_id, old)
        con.commit()
    except KCError as e:
        con.rollback()
        return 502, {'error': 'Keycloak refused the change: %s' % e}
    finally:
        con.close()
    log('role of %s changed %s -> %s by %s' % (u['username'], from_role or 'none', role, actor))
    return 200, {'ok': True, 'role': role, 'from': from_role}


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


# ── HTTP ──────────────────────────────────────────────────────────────────────
class Base(BaseHTTPRequestHandler):
    server_version = 'medcea-access'

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
        except (ValueError, json.JSONDecodeError) as e:
            self.send(400, {'ok': False, 'error': str(e)})
        except Exception as e:                   # noqa: BLE001
            log('error on %s %s: %r' % (self.command, self.path, e))
            self.send(500, {'ok': False, 'error': 'Something went wrong on our side. Please try again later.'})


class Public(Base):
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
    def actor(self):
        # Set by oauth2-proxy (pass_user_headers). This port is only reachable
        # through that proxy, which admits realm role 'admin' only.
        h = self.headers
        return (h.get('X-Forwarded-Preferred-Username') or h.get('X-Forwarded-Email') or h.get('X-Forwarded-User') or '').strip()

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == '/healthz':
            return self.send(200, {'ok': True})
        if not self.actor():
            return self.send(401, {'error': 'not signed in'})
        if p.path in ('/', '/index.html'):
            return self.page('admin.html')
        if p.path == '/api/me':
            return self.guarded(lambda: (200, {
                'user': self.actor(), 'email': self.headers.get('X-Forwarded-Email', ''),
                'roles': [{'id': k, 'label': v} for k, v in ROLES.items()],
                'smtp': smtp_ready(mail_settings()), 'platform': PLATFORM,
                'portal_url': PORTAL_URL, 'admin_url': ACCESS_URL + '/'}))
        if p.path == '/api/settings':
            return self.guarded(lambda: (200, public_settings(mail_settings())))
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
            status = urllib.parse.parse_qs(p.query).get('status', ['pending'])[0]
            return self.guarded(lambda: (200, list_requests(status)))
        m = re.fullmatch(r'/api/requests/(\d+)/history', p.path)
        if m:
            return self.guarded(lambda: (200, request_history(int(m.group(1)))))
        self.send(404, {'error': 'not found'})

    def do_POST(self):
        actor = self.actor()
        if not actor:
            return self.send(401, {'error': 'not signed in'})
        path = urllib.parse.urlparse(self.path).path
        m = re.fullmatch(r'/api/requests/(\d+)/decision', path)
        if m:
            return self.guarded(lambda: decide(int(m.group(1)), self.body_json(), actor))
        if path == '/api/settings':
            return self.guarded(lambda: save_settings(self.body_json(), actor))
        if path == '/api/settings/test':
            def test():
                to = (self.body_json().get('to') or self.headers.get('X-Forwarded-Email') or '').strip()
                if not EMAIL_RE.match(to):
                    return 400, {'error': 'no address to send the test to'}
                sent, detail = send_mail([to], '[MedCEA] Test e-mail',
                                         'This is a test from the MedCEA User Manager, sent by %s.\n'
                                         'If you can read it, access-request e-mail works.\n' % actor)
                return (200 if sent else 502), {'sent': sent, 'detail': detail}
            return self.guarded(test)
        m = re.fullmatch(r'/api/users/(%s)/(status|role)' % UUID_RE, path)
        if m:
            fn = set_user_status if m.group(2) == 'status' else set_user_role
            return self.guarded(lambda: fn(m.group(1), self.body_json(), actor))
        m = re.fullmatch(r'/api/templates/([a-z-]+)(/reset)?', path)
        if m:
            if m.group(2):
                return self.guarded(lambda: reset_template(m.group(1), actor))
            return self.guarded(lambda: save_template(m.group(1), self.body_json(), actor))
        self.send(404, {'error': 'not found'})


class Profile(Base):
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
        if p in ('', '/', '/index.html'):
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
