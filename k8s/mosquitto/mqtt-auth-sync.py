"""Mosquitto auth sidecar: builds the broker's password and ACL files and reloads it.

Sources, merged every POLL seconds:
  /secrets/service-passwd, /secrets/service-acl   the platform's own clients
        (node-red, scheduler, and mqtt-explorer while IAM_MQTT_PERSON=false), hashed
        by deploy-infra.sh into the Secret mosquitto-service-auth; Secret updates
        reach the mount.
  medcea.mqtt_credential (+ medcea.device.is_active)   one row per board,
        written by onboarding through the register_mqtt_credential RPC.
  medcea.mqtt_service_credential + mqtt_service_acl (+ cea_unit, recipe_run)
        the MQTT Explorer's person credentials (iam-api, IAM 3.5), read only while
        MQTT_PERSON_CREDENTIALS=true (deploy-infra renders it from IAM_MQTT_PERSON).
All read as role mqtt_auth, SELECT only.

MQTT_PERSON_CREDENTIALS=false writes /mosquitto/auth/{passwd,acl} exactly as before
3.5 (services + boards; the conf has one auth for both listeners). true writes four
files for the per-listener conf (mosquitto-conf-person.yaml): passwd/acl for 1883
(services + boards; an explorer- name is never written there) and passwd-ws/acl-ws for
the WebSocket listener (person credentials only). Each person row is parsed into
(unit, zone, class) under the root PROJECT_NAME and re-derived on every sync:
  - a read row is kept as it is;
  - a write row is honoured only for a unit code of [A-Za-z0-9_-] flagged for
    commissioning with no run in R (start_run's own "running" test); a '+' unit
    expands to every such unit, the zone kept. So a write right ends at the next
    sync after the unit is unflagged or a run starts.
A credential with no row left is still written (it connects and reads nothing), so
"connected but no rights" stays distinct from "refused". With no person credential at
all, passwd-ws holds one placeholder, explorer-none, whose hash is random bytes of
the right shape: no password derives it.

The database lives in the apps stage and this pod in the infra stage, so a table may
not exist yet, or the DB may be down for a moment: the last successfully read device
set is kept (only a successful query can shrink the fleet). The person set is read in
its own transaction; when it fails, the last person set is kept minus credentials
expired by the local clock, and every person write row is dropped until a read
succeeds (fail closed). Files are written atomically (tmp + rename) — acl-ws,
passwd-ws, acl, passwd — then every process named `mosquitto` gets SIGHUP
(shareProcessNamespace), which makes Mosquitto 2 re-read them. A user that disappears
is refused on its next CONNECT, and its publishes are denied at once. status.json
(mode, counts per listener, write rows honoured and dropped by reason, last_db_ok)
holds no hash and no password. Nothing here hashes a password, and no hash is logged.
"""
import base64
import datetime
import json
import os
import re
import signal
import sys
import time

E = os.environ
AUTH_DIR = E.get('AUTH_DIR', '/mosquitto/auth')
SECRET_DIR = E.get('SECRET_DIR', '/secrets')
POLL = int(E.get('POLL_SECONDS', '15'))
MOSQ_UID = int(E.get('MOSQUITTO_UID', '1883'))
PERSON_MODE = E.get('MQTT_PERSON_CREDENTIALS', 'false') == 'true'
ROOT = E.get('PROJECT_NAME', 'medcea')
PERSON_PREFIX = 'explorer-'
PLACEHOLDER = 'explorer-none'
PG = dict(host=E.get('PG_HOST', 'rdbms-postgresql'), port=int(E.get('PG_PORT', '5432')),
          database=E.get('PG_DATABASE', 'medcea_db'), user=E.get('PG_USER', 'mqtt_auth'),
          password=E.get('PG_PASSWORD', ''), timeout=5)

QUERY = """
    SELECT c.username, c.password_hash, c.role, c.topic_base
      FROM medcea.mqtt_credential c
      JOIN medcea.device d ON d.device_id = c.device_id
     WHERE c.active AND d.is_active = 'Y'
     ORDER BY c.username"""
PERSONS = """
    SELECT c.username, c.password_hash, c.expires_at, a.access, a.topic
      FROM medcea.mqtt_service_credential c
      LEFT JOIN medcea.mqtt_service_acl a USING (username)
     WHERE c.active AND c.expires_at > now() AND c.person_sub IS NOT NULL AND c.username LIKE 'explorer-%'
     ORDER BY c.username, a.access, a.topic"""
UNITS = """
    SELECT u.unit_code, u.commissioning,
           EXISTS (SELECT 1 FROM medcea.recipe_run r WHERE r.unit_id = u.unit_id AND r.recipe_run_status = 'R')
      FROM medcea.cea_unit u
     ORDER BY u.unit_code"""
CODE = re.compile(r'^[A-Za-z0-9_-]+$')
CLASSES = ('sense', 'control', 'control_setpoint')


def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, flush=True)


def read_secret(name):
    try:
        with open(os.path.join(SECRET_DIR, name), encoding='utf-8') as fh:
            return fh.read().strip()
    except OSError:
        return ''


def _connect():
    import pg8000.dbapi
    return pg8000.dbapi.connect(**PG)


def fetch_devices():
    con = _connect()
    try:
        cur = con.cursor()
        cur.execute(QUERY)
        return cur.fetchall()
    finally:
        con.close()


def fetch_persons():
    """(persons, units) from one REPEATABLE READ transaction of their own, so a
    missing table or grant here never touches the board set."""
    con = _connect()
    try:
        cur = con.cursor()
        cur.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')   # first statement of pg8000's implicit BEGIN
        cur.execute(PERSONS)
        persons = cur.fetchall()
        cur.execute(UNITS)
        units = cur.fetchall()
        con.rollback()
        return persons, units
    finally:
        con.close()


def _usable(username, *topics):
    # mosquitto's files are line based: a ':' splits the passwd line and whitespace
    # splits the acl line. A legal slot or person name never produces either.
    return not (':' in username or any(ch.isspace() for ch in username)
                or any(ch.isspace() for t in topics for ch in (t or '')))


def render(service_passwd, service_acl, rows, refuse_prefix=None):
    """passwd, acl and the number of boards for the 1883 listener (the only one while
    MQTT_PERSON_CREDENTIALS=false). refuse_prefix drops service and board names with
    that prefix (person credentials never reach 1883)."""
    if refuse_prefix:
        service_passwd = '\n'.join(l for l in service_passwd.splitlines() if not l.startswith(refuse_prefix))
    passwd = [service_passwd.rstrip('\n')] if service_passwd else []
    acl = [service_acl.rstrip('\n')] if service_acl else []
    n = 0
    for username, pw_hash, role, base in rows:
        if not _usable(username, base):
            log('skipping credential with an unusable name/topic:', repr(username))
            continue
        if refuse_prefix and username.startswith(refuse_prefix):
            log('skipping board credential in the person namespace:', repr(username))
            continue
        passwd.append('%s:%s' % (username, pw_hash))
        acl.append('')
        acl.append('user %s' % username)
        if role == 'SENSE':
            acl.append('topic write %s/sense/#' % base)
        else:
            acl.append('topic read %s/control/#' % base)
            acl.append('topic write %s/control_setpoint/#' % base)
        n += 1
    return '\n'.join(passwd) + '\n', '\n'.join(acl) + '\n', n


def parse_topic(topic, root=ROOT):
    """(unit, zone, class) of <root>/<unit|+>/<zone|+>/<class>/#, else None."""
    parts = (topic or '').split('/')
    if len(parts) != 5 or parts[0] != root or parts[4] != '#' or parts[3] not in CLASSES:
        return None
    for seg in parts[1:3]:
        if seg != '+' and not CODE.match(seg):
            return None
    return parts[1], parts[2], parts[3]


def placeholder_hash():
    """A $7$ line no password derives: random bytes in the hash's shape (nothing hashed)."""
    return '$7$101$%s$%s' % (base64.b64encode(os.urandom(12)).decode(), base64.b64encode(os.urandom(64)).decode())


def render_persons(persons, units, root=ROOT, writes_ok=True, now=None, placeholder=None):
    """passwd-ws, acl-ws and stats for the WebSocket listener.

    persons: (username, hash, expires_at, access, topic) rows, access/topic None for a
    credential without rows; units: (unit_code, commissioning, running). writes_ok
    False (the last read failed) drops every write row. now: credentials expired by
    this clock are dropped (the database's filter cannot run on a kept set)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    eligible = sorted(code for code, flagged, running in units or []
                      if code and CODE.match(code) and flagged and not running)
    known = {code: (flagged, running) for code, flagged, running in units or []}
    stats = {'credentials': 0, 'read_rows': 0, 'write_rows': 0,
             'dropped': {'not_commissioning': 0, 'run_in_progress': 0, 'unknown_unit': 0,
                         'db_unavailable': 0, 'unparseable': 0}}
    creds = {}
    for username, pw_hash, expires_at, access, topic in persons or []:
        if not username.startswith(PERSON_PREFIX) or not _usable(username, topic):
            log('skipping person credential with an unusable name/topic:', repr(username))
            continue
        if expires_at is not None and expires_at <= now:
            continue
        c = creds.setdefault(username, {'hash': pw_hash, 'lines': []})
        if access is None:
            continue
        parsed = parse_topic(topic, root)
        if parsed is None or access not in ('read', 'write'):
            stats['dropped']['unparseable'] += 1
            log('skipping person ACL row of %s: %r is not %s/<unit|+>/<zone|+>/<class>/#' % (username, topic, root))
            continue
        unit, zone, cls = parsed
        if access == 'read':
            c['lines'].append('topic read %s/%s/%s/%s/#' % (root, unit, zone, cls))
            stats['read_rows'] += 1
            continue
        if not writes_ok:
            stats['dropped']['db_unavailable'] += 1
            continue
        targets = eligible if unit == '+' else [unit] if unit in eligible else []
        if not targets:
            why = ('unknown_unit' if unit != '+' and unit not in known
                   else 'run_in_progress' if unit != '+' and known[unit][1] and known[unit][0]
                   else 'not_commissioning')
            stats['dropped'][why] += 1
            continue
        for u in targets:
            c['lines'].append('topic write %s/%s/%s/%s/#' % (root, u, zone, cls))
            stats['write_rows'] += 1
    passwd, acl = [], ['# person credentials (mqtt-auth-sync; IAM_MQTT_PERSON=true)']
    for username in sorted(creds):
        passwd.append('%s:%s' % (username, creds[username]['hash']))
        acl.append('')
        acl.append('user %s' % username)
        acl.extend(creds[username]['lines'])
    stats['credentials'] = len(creds)
    if not creds:
        passwd.append('%s:%s' % (PLACEHOLDER, placeholder or placeholder_hash()))
    return '\n'.join(passwd) + '\n', '\n'.join(acl) + '\n', stats


def write_atomic(path, content, mode=0o600):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(content)
    os.chown(tmp, MOSQ_UID, MOSQ_UID)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def reload_mosquitto():
    sent = 0
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            with open('/proc/%s/comm' % pid) as fh:
                if fh.read().strip() != 'mosquitto':
                    continue
            os.kill(int(pid), signal.SIGHUP)
            sent += 1
        except (OSError, ProcessLookupError):
            pass
    return sent


def _iso(t):
    return t.strftime('%Y-%m-%dT%H:%M:%SZ') if t else None


def main():
    os.makedirs(AUTH_DIR, exist_ok=True)
    last_rows, db_state, written = [], None, None
    last_persons, last_units, persons_ok, person_state, last_db_ok = [], [], False, None, None
    placeholder = placeholder_hash()             # one per start, never logged
    while True:
        service_passwd, service_acl = read_secret('service-passwd'), read_secret('service-acl')
        try:
            last_rows = fetch_devices()
            state = 'ok'
            last_db_ok = datetime.datetime.now(datetime.timezone.utc)
        except Exception as e:                   # noqa: BLE001 — keep the last good set
            state = 'unavailable: %s' % str(e).splitlines()[0][:160]
        if state != db_state:
            log('device credentials:', 'from the database' if state == 'ok'
                else 'database %s — serving the last known set (%d) and the service accounts' % (state, len(last_rows)))
            db_state = state
        files = {}
        stats = None
        if PERSON_MODE:
            try:
                last_persons, last_units = fetch_persons()
                persons_ok, pstate = True, 'ok'
            except Exception as e:               # noqa: BLE001 — fail closed: no write row
                persons_ok, pstate = False, 'unavailable: %s' % str(e).splitlines()[0][:160]
            if pstate != person_state:
                log('person credentials:', 'from the database' if pstate == 'ok'
                    else 'database %s — last known set, reads only, until a read succeeds' % pstate)
                person_state = pstate
            files['passwd'], files['acl'], n = render(service_passwd, service_acl, last_rows, PERSON_PREFIX)
            files['passwd-ws'], files['acl-ws'], stats = render_persons(
                last_persons, last_units, ROOT, persons_ok, placeholder=placeholder)
        else:
            files['passwd'], files['acl'], n = render(service_passwd, service_acl, last_rows)
        if files != written:
            for name in ('acl-ws', 'passwd-ws', 'acl', 'passwd'):   # passwd last: the broker waits for it
                if name in files:
                    write_atomic(os.path.join(AUTH_DIR, name), files[name])
            written = files
            log('wrote %s: %d service account(s), %d device(s)%s; SIGHUP sent to %d mosquitto process(es)'
                % ('/'.join(n_ for n_ in ('passwd', 'acl', 'passwd-ws', 'acl-ws') if n_ in files),
                   service_passwd.count('\n') + 1 if service_passwd else 0, n,
                   '; %d person credential(s), %d write row(s)' % (stats['credentials'], stats['write_rows'])
                   if stats else '', reload_mosquitto()))
        status = {'mode': 'person' if PERSON_MODE else 'shared', 'written_at': _iso(datetime.datetime.now(datetime.timezone.utc)),
                  'last_db_ok': _iso(last_db_ok), 'devices': n,
                  'services': service_passwd.count('\n') + 1 if service_passwd else 0}
        if stats:
            status.update(persons=stats, persons_from_database=persons_ok)
        try:
            write_atomic(os.path.join(AUTH_DIR, 'status.json'), json.dumps(status, sort_keys=True) + '\n', 0o644)
        except OSError as e:
            log('could not write status.json:', e)
        time.sleep(POLL)


if __name__ == '__main__':
    if not PG['password']:
        log('warning: PG_PASSWORD is empty — device credentials cannot be read')
    log('mode: %s' % ('person credentials on the WebSocket listener (IAM_MQTT_PERSON=true)' if PERSON_MODE
                      else 'one password file for both listeners (IAM_MQTT_PERSON=false)'))
    main()
