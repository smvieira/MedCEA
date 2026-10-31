import json, http.server, os, sys, re, hashlib, subprocess, datetime, decimal, importlib.util

PG_HOST = os.environ.get('PG_HOST', 'rdbms-postgresql.medcea.svc.cluster.local')
PG_PORT = int(os.environ.get('PG_PORT', '5432'))
PG_DB   = os.environ.get('PG_DATABASE', 'medcea_db')
PG_USER = os.environ.get('PG_USER', 'postgres')
PG_PASS = os.environ.get('PG_PASSWORD', '')
EXPORT_DIR = os.environ.get('DBMGMT_EXPORT_DIR', '/exports')   # hostPath apps/database/exports
MAX_BODY = 1 << 20

# Schemas whose members of the person's X groups are exported (IAM 2.6). medcea only by
# decision: the iam and iam_policy members of those groups (accounts, policy, the hash
# chain) stay out of Database Management although svc_dbexport may read them.
SCHEMAS = ('medcea',)
_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)

def _qi(s):
    return '"' + s.replace('"', '""') + '"'

def _clean(s, extra='_-. '):
    """Only safe characters, at most 80: for text that goes into a message, a log line
    or an SQL comment."""
    return ''.join(ch if ch.isalnum() or ch in extra else '?' for ch in str(s)[:80])

def connect():
    import pg8000.dbapi as pg
    return pg.connect(user=PG_USER, host=PG_HOST, port=PG_PORT, database=PG_DB, password=PG_PASS)

# Tables and views come from information_schema, which lists only what this login
# may read: on svc_dbexport (IAM 2.5) the credential and settings tables drop out,
# on purpose; the person's X groups narrow it further (exportable_objects). Sequences
# and types come from pg_catalog, which every role may read, because svc_dbexport
# holds no privilege on a sequence and information_schema would hide every one of them.
def catalog_objects(cur):
    cur.execute("""
        SELECT table_schema::text, table_name::text, 'table' AS type
        FROM information_schema.tables
        WHERE table_schema = ANY(%s) AND table_type = 'BASE TABLE'
        UNION ALL
        SELECT table_schema::text, table_name::text, 'view'
        FROM information_schema.views
        WHERE table_schema = ANY(%s)
        UNION ALL
        SELECT n.nspname::text, c.relname::text, 'sequence'
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY(%s) AND c.relkind = 'S'
        UNION ALL
        SELECT n.nspname::text, t.typname::text,
               CASE t.typtype WHEN 'e' THEN 'enum' WHEN 'd' THEN 'domain' ELSE 'type' END
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = ANY(%s) AND t.typtype IN ('e','d')
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_class c
              WHERE c.oid = t.typrelid AND c.relkind = 'c')
        ORDER BY 3, 1, 2
    """, (list(SCHEMAS),) * 4)
    return [{'schema': r[0], 'name': r[1], 'type': r[2]} for r in cur.fetchall()]

_UNREADABLE = set()

def export_groups(groups):
    """The person's X groups that have a member in SCHEMAS, sorted."""
    return sorted(g for g, objs in groups.items() if any(o.split('.', 1)[0] in SCHEMAS for o in objs))

def exportable_objects(cur, groups):
    """The catalog narrowed to the person's X groups (medcea_iam.exportable()): a table
    or view only when it is a member of one of them, with that group; sequences and types
    hold no rows (no last_value) and are offered DDL-only to anyone the route admits,
    with group None."""
    owner = {o: g for g, objs in groups.items() for o in objs if o.split('.', 1)[0] in SCHEMAS}
    out, seen = [], set()
    for o in catalog_objects(cur):
        key = o['schema'] + '.' + o['name']
        if o['type'] in ('table', 'view'):
            if key not in owner:
                continue
            seen.add(key)
            out.append(dict(o, group=owner[key]))
        else:
            out.append(dict(o, group=None))
    # a member the catalog does not show: ceiling drift (grants) or a missing table.
    # Reported once per set, not on every request.
    missing = frozenset(owner) - seen
    if missing and missing not in _UNREADABLE:
        _UNREADABLE.add(missing)
        print('dbmgmt: exportable but not readable: ' + ', '.join(sorted(missing)), file=sys.stderr, flush=True)
    return out

def _tbl_oid(cur, schema, name):
    cur.execute("""
        SELECT c.oid FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = %s AND n.nspname = %s
    """, (name, schema))
    row = cur.fetchone()
    return row[0] if row else None

def get_table_ddl(cur, schema, name):
    tbl_oid = _tbl_oid(cur, schema, name)
    if not tbl_oid:
        return ''

    # Columns
    cur.execute("""
        SELECT a.attname,
               pg_catalog.format_type(a.atttypid, a.atttypmod),
               a.attnotnull,
               pg_catalog.pg_get_expr(d.adbin, d.adrelid)
        FROM   pg_catalog.pg_attribute a
        LEFT   JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE  a.attrelid = %s AND a.attnum > 0 AND NOT a.attisdropped
        ORDER  BY a.attnum
    """, (tbl_oid,))
    cols = cur.fetchall()

    # PK
    cur.execute("""
        SELECT a.attname
        FROM   pg_catalog.pg_constraint c
        JOIN   pg_catalog.pg_attribute  a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
        WHERE  c.contype = 'p' AND c.conrelid = %s
        ORDER  BY array_position(c.conkey, a.attnum)
    """, (tbl_oid,))
    pk = [r[0] for r in cur.fetchall()]

    # UNIQUE constraints
    cur.execute("""
        SELECT c.conname, array_agg(a.attname ORDER BY array_position(c.conkey, a.attnum))
        FROM   pg_catalog.pg_constraint c
        JOIN   pg_catalog.pg_attribute  a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
        WHERE  c.contype = 'u' AND c.conrelid = %s
        GROUP  BY c.conname
    """, (tbl_oid,))
    uniques = cur.fetchall()

    # CHECK constraints (skip auto-generated pg_ ones)
    cur.execute("""
        SELECT c.conname, pg_catalog.pg_get_constraintdef(c.oid, true)
        FROM   pg_catalog.pg_constraint c
        WHERE  c.contype = 'c' AND c.conrelid = %s
          AND  c.conname NOT LIKE 'pg_%%'
    """, (tbl_oid,))
    checks = cur.fetchall()

    lines = []
    for col, dtype, notnull, default in cols:
        line = f'  {col} {dtype}'
        if default:  line += f' DEFAULT {default}'
        if notnull:  line += ' NOT NULL'
        lines.append(line)
    if pk:
        lines.append(f'  PRIMARY KEY ({", ".join(pk)})')
    for cname, ucols in uniques:
        lines.append(f'  CONSTRAINT {cname} UNIQUE ({", ".join(ucols)})')
    for cname, cdef in checks:
        lines.append(f'  CONSTRAINT {cname} {cdef}')

    ddl = f'-- Table: {schema}.{name}\nCREATE TABLE IF NOT EXISTS {schema}.{name} (\n' + ',\n'.join(lines) + '\n);\n'

    # FK constraints as ALTER TABLE (emitted after CREATE TABLE so parent tables exist)
    cur.execute("""
        SELECT c.conname, pg_catalog.pg_get_constraintdef(c.oid, true)
        FROM   pg_catalog.pg_constraint c
        WHERE  c.contype = 'f' AND c.conrelid = %s
        ORDER  BY c.conname
    """, (tbl_oid,))
    for cname, cdef in cur.fetchall():
        ddl += f'ALTER TABLE {schema}.{name} ADD CONSTRAINT {cname} {cdef};\n'

    # Indexes (exclude those backing PK/UNIQUE which are created implicitly)
    cur.execute("""
        SELECT i.indexname, i.indexdef
        FROM   pg_catalog.pg_indexes i
        WHERE  i.schemaname = %s AND i.tablename = %s
          AND  i.indexname NOT IN (
              SELECT conname FROM pg_catalog.pg_constraint
              WHERE conrelid = %s AND contype IN ('p','u'))
        ORDER  BY i.indexname
    """, (schema, name, tbl_oid))
    for iname, idef in cur.fetchall():
        ddl += idef + ';\n'

    return ddl

def get_view_ddl(cur, schema, name):
    cur.execute("""
        SELECT pg_catalog.pg_get_viewdef(c.oid, true)
        FROM   pg_catalog.pg_class c
        JOIN   pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE  c.relname = %s AND n.nspname = %s
    """, (name, schema))
    row = cur.fetchone()
    if row:
        return f'-- View: {schema}.{name}\nCREATE OR REPLACE VIEW {schema}.{name} AS\n{row[0]};\n'
    return ''

def get_sequence_ddl(cur, schema, name):
    cur.execute("""
        SELECT s.seqstart, s.seqmin, s.seqmax, s.seqincrement, CASE WHEN s.seqcycle THEN 'YES' ELSE 'NO' END
        FROM pg_catalog.pg_sequence s
        JOIN pg_catalog.pg_class c ON c.oid = s.seqrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relname = %s
    """, (schema, name))
    row = cur.fetchone()
    if not row:
        return ''
    start, minval, maxval, incr, cycle = row
    cycle_str = 'CYCLE' if cycle == 'YES' else 'NO CYCLE'
    return (f'-- Sequence: {schema}.{name}\n'
            f'CREATE SEQUENCE IF NOT EXISTS {schema}.{name}\n'
            f'  START WITH {start}\n'
            f'  INCREMENT BY {incr}\n'
            f'  MINVALUE {minval}\n'
            f'  MAXVALUE {maxval}\n'
            f'  {cycle_str};\n')

def get_type_ddl(cur, schema, name):
    cur.execute("""
        SELECT t.typtype
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE t.typname = %s AND n.nspname = %s
    """, (name, schema))
    row = cur.fetchone()
    if not row:
        return ''
    typtype = row[0]
    if typtype == 'e':
        cur.execute("""
            SELECT e.enumlabel
            FROM pg_catalog.pg_enum e
            JOIN pg_catalog.pg_type t ON t.oid = e.enumtypid
            JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
            WHERE t.typname = %s AND n.nspname = %s
            ORDER BY e.enumsortorder
        """, (name, schema))
        vals = ', '.join("'" + r[0].replace("'", "''") + "'" for r in cur.fetchall())
        return f'-- Enum type: {schema}.{name}\nCREATE TYPE {schema}.{name} AS ENUM ({vals});\n'
    elif typtype == 'd':
        cur.execute("""
            SELECT pg_catalog.format_type(t.typbasetype, t.typtypmod),
                   pg_catalog.pg_get_constraintdef(c.oid, true)
            FROM pg_catalog.pg_type t
            JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
            LEFT JOIN pg_catalog.pg_constraint c ON c.contypid = t.oid
            WHERE t.typname = %s AND n.nspname = %s
            LIMIT 1
        """, (name, schema))
        row2 = cur.fetchone()
        if row2:
            base, constraint = row2
            ddl = f'-- Domain: {schema}.{name}\nCREATE DOMAIN {schema}.{name} AS {base}'
            if constraint:
                ddl += f'\n  {constraint}'
            return ddl + ';\n'
    return ''

_JSON_OIDS = (114, 3802)   # json, jsonb: pg8000 hands back dict/list/str/number

def _array_elem(v):
    if v is None:                return 'NULL'
    if isinstance(v, (list, tuple)): return _array_literal(v)
    if isinstance(v, bool):      return 't' if v else 'f'
    if isinstance(v, bytes):     return '"\\\\x' + v.hex() + '"'
    if isinstance(v, dict):      v = json.dumps(v)
    return '"' + str(v).replace('\\', '\\\\').replace('"', '\\"') + '"'

def _array_literal(v):
    return '{' + ','.join(_array_elem(x) for x in v) + '}'

def val_to_sql(v, oid=None):
    """One value as an SQL literal. `oid` is the column's type (cursor.description): a
    json/jsonb value goes out as JSON text, a list of any other type as an array literal."""
    if v is None:                            return 'NULL'
    if oid in _JSON_OIDS or isinstance(v, dict):
        return "'" + json.dumps(v).replace("'", "''") + "'"
    if isinstance(v, bool):                  return 'TRUE' if v else 'FALSE'
    if isinstance(v, float) and v != v:      return "'NaN'"
    if isinstance(v, float) and v in (float('inf'), float('-inf')):
        return "'Infinity'" if v > 0 else "'-Infinity'"
    if isinstance(v, (int, float, decimal.Decimal)): return str(v)
    if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
        return "'" + str(v) + "'"
    if isinstance(v, bytes):
        return "E'\\\\x" + v.hex() + "'"
    if isinstance(v, (list, tuple)):
        return "'" + _array_literal(v).replace("'", "''") + "'"
    return "'" + str(v).replace("'", "''") + "'"

def get_data_inserts(cur, schema, name):
    """(INSERT statements, row count) for one table."""
    cur.execute(f'SELECT * FROM {_qi(schema)}.{_qi(name)} ORDER BY 1')
    rows = cur.fetchall()
    if not rows: return '', 0
    cols = [d[0] for d in cur.description]
    oids = [d[1] for d in cur.description]
    cols_str = ', '.join(cols)
    lines = [f'-- Data: {schema}.{name} ({len(rows)} rows)']
    for row in rows:
        vals = ', '.join(val_to_sql(v, oid) for v, oid in zip(row, oids))
        lines.append(f'INSERT INTO {schema}.{name} ({cols_str}) VALUES ({vals});')
    return '\n'.join(lines) + '\n', len(rows)


class Refused(Exception):
    """An export refused before anything was logged; status is the HTTP answer."""
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


def normalise_selections(selections):
    """[(schema, name, type, ddl, rows)] in first-seen order, without duplicates and
    without entries that select nothing; Refused(400) on a malformed one. A selection
    without a schema (a page from before 2.6) means medcea; data is for tables only."""
    out, seen = [], set()
    for sel in selections:
        if not isinstance(sel, dict):
            raise Refused(400, 'a selection is not an object')
        schema, name, kind = sel.get('schema', 'medcea'), sel.get('name'), sel.get('type')
        if not all(isinstance(x, str) and x for x in (schema, name, kind)):
            raise Refused(400, 'a selection needs schema, name and type as text')
        ddl = sel.get('ddl') is True
        data = sel.get('data') is True and kind == 'table'
        if not (ddl or data) or (schema, name, kind) in seen:
            continue
        seen.add((schema, name, kind))
        out.append((schema, name, kind, ddl, data))
    if not out:
        raise Refused(400, 'nothing selected')
    return out


def run_export(person, groups, selections):
    """One export in one REPEATABLE READ transaction: the person as actor → the objects
    checked against their X groups → DDL and rows → iam_policy.log_export → commit.
    Returns (bytes, export_id, sha256, meta) only after the commit; an object outside
    the groups refuses the whole export (Refused 403) and nothing is logged."""
    sub, person_id, username, role = person
    wanted = normalise_selections(selections)
    con = connect()
    try:
        cur = con.cursor()
        cur.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        cur.execute('SELECT medcea_auth.set_actor(%s, %s, %s, %s)', (sub, person_id, username, role))
        allowed = {(o['schema'], o['name'], o['type']): o for o in exportable_objects(cur, groups)}
        # a name goes into SQL text below: only what the catalog and the groups list
        refused = [f'{k} {s}.{n}' for s, n, k, _, _ in wanted if (s, n, k) not in allowed]
        if refused:
            raise Refused(403, 'not in your export groups: ' + ', '.join(_clean(r) for r in refused[:10]))
        parts, log_objects = [], []
        for schema, name, kind, ddl, rows in wanted:
            if ddl:
                parts.append('\n')
                if kind == 'table':
                    parts.append(get_table_ddl(cur, schema, name))
                elif kind == 'view':
                    parts.append(get_view_ddl(cur, schema, name))
                elif kind == 'sequence':
                    parts.append(get_sequence_ddl(cur, schema, name))
                elif kind in ('enum', 'domain', 'type'):
                    parts.append(get_type_ddl(cur, schema, name))
            what = ['ddl'] if ddl else []
            if rows:
                text, n = get_data_inserts(cur, schema, name)
                parts.append('\n')
                parts.append(text)
                what.append(f'data={n}')
            log_objects.append(f'{schema}.{name}:{kind}:' + ','.join(what))
        log_groups = sorted({allowed[(s, n, k)]['group'] for s, n, k, _, _ in wanted if allowed[(s, n, k)]['group']})
        cur.execute('SELECT iam_policy.log_export(%s::text[], %s::text[])', (log_groups, log_objects))
        export_id = cur.fetchone()[0]
        who = _clean(username or sub, '_-.@ ')
        header = (f'-- medcea_db export #{export_id} (iam_policy.export_log)\n'
                  f'-- Generated: {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M:%S} UTC\n'
                  f'-- Exported by: {who} ({_clean(role)})\n'
                  f'-- Groups: {", ".join(log_groups) or "none"}\n')
        data = (header + ''.join(parts)).encode('utf-8')
        sha = hashlib.sha256(data).hexdigest()
        con.commit()
    except BaseException:
        try:
            con.rollback()
        except Exception:  # noqa: BLE001 — the original error is the one to report
            pass
        raise
    finally:
        con.close()
    meta = (f'dbmgmt: export #{export_id} by {who} ({_clean(role)}): {len(wanted)} objects, '
            f'groups {",".join(log_groups) or "-"}, {len(data)} bytes, sha256 {sha}')
    return data, export_id, sha, meta

# ── Access policy check (IAM plan 1.2, 2.6) ─────────────────────────────────
# medcea_iam.py and the route table come from ConfigMap medcea-iam-lib at /iam/.
# Loaded from the mount and reloaded when it changes, so a ConfigMap that appears
# later heals and a new library needs no restart. An export takes data out of the
# platform, so dbmgmt refuses whatever IAM_ENFORCE says (http_check enforce=True, as
# the User Manager's admin port), and without the library it answers 503.
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
            print('medcea_iam: not loaded (%s); every request is refused' % e, file=sys.stderr, flush=True)
            _IAM['warned'] = True
    return _IAM['mod']


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass  # suppress access log

    def parse_request(self):
        if not super().parse_request():
            return False
        iam = _medcea_iam()
        if iam:
            return iam.http_check(self, 'dbmgmt', enforce=True)
        if self.path.split('?')[0] != '/healthz':
            self.send_error(503, 'access policy not loaded')
            return False
        return True

    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _person(self):
        """(sub, person, name, role) of the verified person behind this request, or None.
        Only the check's who counts (a verified token); never an X-Forwarded-* header."""
        d = getattr(self, 'medcea_iam', None)
        who = getattr(d, 'who', None) or {}
        sub = who.get('sub')
        if not sub or not _UUID.match(str(sub)):
            return None
        iam = _medcea_iam()
        if iam is not None and hasattr(iam, 'actor_role'):
            role = iam.actor_role(d)
        else:                               # a library from before actor_role
            roles = who.get('roles') or []
            role = roles[0] if len(roles) == 1 else None
        if not role:
            return None
        return (sub, who.get('person_id') or sub, who.get('username'), role)

    def _why_no_person(self):
        d = getattr(self, 'medcea_iam', None)
        if d is None:
            return 'access library not loaded'
        who = getattr(d, 'who', None)
        if not who:
            return getattr(d, 'reason', None) or 'no verified token'
        if not who.get('sub') or not _UUID.match(str(who.get('sub'))):
            return 'the token has no account uuid'
        return 'no single own platform role in %s' % (who.get('roles') or '[]')

    def _export_context(self):
        """(person, groups) for an export, or None after sending the refusal."""
        iam = _medcea_iam()
        d = getattr(self, 'medcea_iam', None)
        if iam is None:
            self.send_json(503, {'error': 'access policy not loaded'})
            return None
        groups = iam.exportable(d) if hasattr(iam, 'exportable') else None
        if groups is None:
            self.send_json(503, {'error': 'the route table has no exports (compiled before IAM 2.6): run ./deploy-infra.sh'})
            return None
        if d is None or not d.allow:      # http_check(enforce=True) has answered already
            self.send_json(getattr(d, 'status', None) or 403, {'error': getattr(d, 'reason', None) or 'refused'})
            return None
        person = self._person()
        if person is None:
            who = getattr(d, 'who', None) or {}
            code = 401 if not who.get('sub') or not _UUID.match(str(who.get('sub'))) else 403
            self.send_json(code, {'error': self._why_no_person()})
            return None
        return person, groups

    def do_GET(self):
        if self.path == '/objects' or self.path == '/objects/':
            ctx = self._export_context()
            if ctx is None:
                return
            _, groups = ctx
            try:
                con = connect()
                try:
                    objs = exportable_objects(con.cursor(), groups)
                finally:
                    con.close()
            except Exception as e:  # noqa: BLE001
                print('dbmgmt: /objects failed: %s' % e, file=sys.stderr, flush=True)
                self.send_json(500, {'error': 'database error'})
                return
            self.send_json(200, {'groups': export_groups(groups), 'objects': objs})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path == '/export' or self.path == '/export/':
            # JSON only: a cross-site form cannot send it without a CORS preflight,
            # which dbmgmt never answers
            if not (self.headers.get('Content-Type') or '').startswith('application/json'):
                self.send_json(415, {'error': 'Content-Type must be application/json'})
                return
            try:
                length = int(self.headers.get('Content-Length', 0))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_BODY:
                self.send_json(400, {'error': 'missing or oversized body'})
                return
            try:
                body = json.loads(self.rfile.read(length))
            except ValueError:
                self.send_json(400, {'error': 'invalid JSON'})
                return
            if not isinstance(body, dict) or not isinstance(body.get('selections'), list):
                self.send_json(400, {'error': 'selections must be a list'})
                return
            ctx = self._export_context()
            if ctx is None:
                return
            person, groups = ctx
            filename = str(body.get('filename') or 'medcea_export.sql').strip()
            # Sanitise: keep only safe filename chars
            filename = re.sub(r'[^A-Za-z0-9._\-]', '_', filename)
            if not filename.endswith('.sql'):
                filename += '.sql'
            target = body.get('target', 'local')
            if target not in ('local', 'platform'):
                self.send_json(400, {'error': "target must be 'local' or 'platform'"})
                return
            # its own directory, never the migration sources the database deploy runs,
            # and never over an earlier file ('xb' below closes the race)
            if target == 'platform' and os.path.exists(os.path.join(EXPORT_DIR, filename)):
                self.send_json(409, {'error': 'apps/database/exports/%s exists: choose another name' % filename})
                return
            try:
                data, export_id, sha, meta = run_export(person, groups, body['selections'])
            except Refused as e:
                self.send_json(e.status, {'error': str(e)})
                return
            except Exception as e:  # noqa: BLE001
                print('dbmgmt: export by %s failed: %s' % (_clean(person[2] or person[0], '_-.@ '), e),
                      file=sys.stderr, flush=True)
                self.send_json(500, {'error': 'export failed: database error'})
                return
            if target == 'platform':
                # logged before written: the rows were read and attributed either way
                try:
                    with open(os.path.join(EXPORT_DIR, filename), 'xb') as f:
                        f.write(data)
                except FileExistsError:
                    print(meta + ' target platform:' + filename + ' NOT WRITTEN: exists', file=sys.stderr, flush=True)
                    self.send_json(409, {'error': 'logged as export #%s but not written: %s exists' % (export_id, filename)})
                    return
                except OSError as e:
                    print(meta + ' target platform:' + filename + ' NOT WRITTEN: %s' % e, file=sys.stderr, flush=True)
                    self.send_json(500, {'error': 'logged as export #%s but not written: %s' % (export_id, e.strerror or e)})
                    return
                print(meta + ' target platform:' + filename, file=sys.stderr, flush=True)
                self.send_json(200, {'path': 'apps/database/exports/' + filename, 'size': len(data),
                                     'export_id': export_id, 'sha256': sha})
            else:
                print(meta + ' target local', file=sys.stderr, flush=True)
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="' + filename + '"')
                self.send_header('Content-Length', len(data))
                self.send_header('X-Medcea-Export-Id', str(export_id))
                self.send_header('X-Medcea-Export-Sha256', sha)
                self.end_headers()
                self.wfile.write(data)
        else:
            self.send_response(404); self.end_headers()

if __name__ == '__main__':
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pg8000', '--quiet', '--no-cache-dir'],
                   check=True, capture_output=True)
    # PyJWT for the access check; without it the check reports every request as
    # unverifiable instead of the service failing to start.
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyjwt[crypto]', '--quiet', '--no-cache-dir'],
                   check=False, capture_output=True)
    print('pg8000 ready — listening on :8081', flush=True)
    http.server.HTTPServer(('0.0.0.0', 8081), Handler).serve_forever()
