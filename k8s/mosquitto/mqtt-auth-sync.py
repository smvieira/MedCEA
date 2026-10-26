"""Mosquitto auth sidecar: builds /mosquitto/auth/{passwd,acl} and reloads the broker.

Two sources, merged every POLL seconds:
  /secrets/service-passwd, /secrets/service-acl   the platform's own clients
        (node-red, scheduler, mqtt-explorer), hashed by deploy-infra.sh into
        the Secret mosquitto-service-auth; Secret updates reach the mount.
  medcea.mqtt_credential (+ medcea.device.is_active)   one row per board,
        written by onboarding through the register_mqtt_credential RPC.
        Read as role mqtt_auth, SELECT only.

The files are written atomically (tmp + rename), then every process named
`mosquitto` gets SIGHUP (shareProcessNamespace on the pod), which makes
Mosquitto 2 re-read password_file and acl_file. A user that disappears from
the files is refused on its next CONNECT, and its publishes are denied at once.

The database lives in the apps stage and this pod in the infra stage, so the
table may not exist yet, or the DB may be down for a moment: in both cases the
last successfully read device set is kept. Only a successful query can shrink
the fleet. Nothing here hashes a password, and no hash is ever logged.
"""
import os
import signal
import sys
import time

E = os.environ
AUTH_DIR = E.get('AUTH_DIR', '/mosquitto/auth')
SECRET_DIR = E.get('SECRET_DIR', '/secrets')
POLL = int(E.get('POLL_SECONDS', '15'))
MOSQ_UID = int(E.get('MOSQUITTO_UID', '1883'))
PG = dict(host=E.get('PG_HOST', 'rdbms-postgresql'), port=int(E.get('PG_PORT', '5432')),
          database=E.get('PG_DATABASE', 'medcea_db'), user=E.get('PG_USER', 'mqtt_auth'),
          password=E.get('PG_PASSWORD', ''), timeout=5)

QUERY = """
    SELECT c.username, c.password_hash, c.role, c.topic_base
      FROM medcea.mqtt_credential c
      JOIN medcea.device d ON d.device_id = c.device_id
     WHERE c.active AND d.is_active = 'Y'
     ORDER BY c.username"""


def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, flush=True)


def read_secret(name):
    try:
        with open(os.path.join(SECRET_DIR, name), encoding='utf-8') as fh:
            return fh.read().strip()
    except OSError:
        return ''


def fetch_devices():
    import pg8000.dbapi
    con = pg8000.dbapi.connect(**PG)
    try:
        cur = con.cursor()
        cur.execute(QUERY)
        return cur.fetchall()
    finally:
        con.close()


def render(service_passwd, service_acl, rows):
    passwd = [service_passwd.rstrip('\n')] if service_passwd else []
    acl = [service_acl.rstrip('\n')] if service_acl else []
    n = 0
    for username, pw_hash, role, base in rows:
        # mosquitto's files are line based: a ':' splits the passwd line and
        # whitespace splits the acl line. A legal slot never produces either.
        if ':' in username or any(ch.isspace() for ch in username) or any(ch.isspace() for ch in base):
            log('skipping credential with an unusable name/topic:', repr(username))
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


def write_atomic(path, content):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(content)
    os.chown(tmp, MOSQ_UID, MOSQ_UID)
    os.chmod(tmp, 0o600)
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


def main():
    os.makedirs(AUTH_DIR, exist_ok=True)
    last_rows, db_state, written = [], None, (None, None)
    while True:
        service_passwd, service_acl = read_secret('service-passwd'), read_secret('service-acl')
        try:
            last_rows = fetch_devices()
            state = 'ok'
        except Exception as e:                   # noqa: BLE001 — keep the last good set
            state = 'unavailable: %s' % str(e).splitlines()[0][:160]
        if state != db_state:
            log('device credentials:', 'from the database' if state == 'ok'
                else 'database %s — serving the last known set (%d) and the service accounts' % (state, len(last_rows)))
            db_state = state
        passwd, acl, n = render(service_passwd, service_acl, last_rows)
        if (passwd, acl) != written:
            write_atomic(os.path.join(AUTH_DIR, 'acl'), acl)
            write_atomic(os.path.join(AUTH_DIR, 'passwd'), passwd)   # passwd last: the broker waits for it
            written = (passwd, acl)
            log('wrote passwd/acl: %d service account(s), %d device(s); SIGHUP sent to %d mosquitto process(es)'
                % (service_passwd.count('\n') + 1 if service_passwd else 0, n, reload_mosquitto()))
        time.sleep(POLL)


if __name__ == '__main__':
    if not PG['password']:
        log('warning: PG_PASSWORD is empty — device credentials cannot be read')
    main()
