import json, http.server, os, sys, datetime, decimal, importlib.util

PG_HOST = os.environ.get('PG_HOST', 'rdbms-postgresql.medcea.svc.cluster.local')
PG_PORT = int(os.environ.get('PG_PORT', '5432'))
PG_DB   = os.environ.get('PG_DATABASE', 'medcea_db')
PG_USER = os.environ.get('PG_USER', 'postgres')
PG_PASS = os.environ.get('PG_PASSWORD', '')

def connect():
    import pg8000.dbapi as pg
    return pg.connect(user=PG_USER, host=PG_HOST, port=PG_PORT, database=PG_DB, password=PG_PASS)

def list_objects():
    con = connect()
    cur = con.cursor()
    cur.execute("""
        SELECT table_name, 'table' AS type
        FROM information_schema.tables
        WHERE table_schema = 'medcea' AND table_type = 'BASE TABLE'
        UNION ALL
        SELECT table_name, 'view'
        FROM information_schema.views
        WHERE table_schema = 'medcea'
        UNION ALL
        SELECT sequence_name, 'sequence'
        FROM information_schema.sequences
        WHERE sequence_schema = 'medcea'
        UNION ALL
        SELECT t.typname,
               CASE t.typtype WHEN 'e' THEN 'enum' WHEN 'd' THEN 'domain' ELSE 'type' END
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'medcea' AND t.typtype IN ('e','d')
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_class c
              WHERE c.oid = t.typrelid AND c.relkind = 'c')
        ORDER BY 2, 1
    """)
    result = [{'name': r[0], 'type': r[1]} for r in cur.fetchall()]
    con.close()
    return result

def _tbl_oid(cur, name):
    cur.execute("""
        SELECT c.oid FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = %s AND n.nspname = 'medcea'
    """, (name,))
    row = cur.fetchone()
    return row[0] if row else None

def get_table_ddl(cur, name):
    tbl_oid = _tbl_oid(cur, name)
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

    ddl = f'-- Table: medcea.{name}\nCREATE TABLE IF NOT EXISTS medcea.{name} (\n' + ',\n'.join(lines) + '\n);\n'

    # FK constraints as ALTER TABLE (emitted after CREATE TABLE so parent tables exist)
    cur.execute("""
        SELECT c.conname, pg_catalog.pg_get_constraintdef(c.oid, true)
        FROM   pg_catalog.pg_constraint c
        WHERE  c.contype = 'f' AND c.conrelid = %s
        ORDER  BY c.conname
    """, (tbl_oid,))
    for cname, cdef in cur.fetchall():
        ddl += f'ALTER TABLE medcea.{name} ADD CONSTRAINT {cname} {cdef};\n'

    # Indexes (exclude those backing PK/UNIQUE which are created implicitly)
    cur.execute("""
        SELECT i.indexname, i.indexdef
        FROM   pg_catalog.pg_indexes i
        WHERE  i.schemaname = 'medcea' AND i.tablename = %s
          AND  i.indexname NOT IN (
              SELECT conname FROM pg_catalog.pg_constraint
              WHERE conrelid = %s AND contype IN ('p','u'))
        ORDER  BY i.indexname
    """, (name, tbl_oid))
    for iname, idef in cur.fetchall():
        ddl += idef + ';\n'

    return ddl

def get_view_ddl(cur, name):
    cur.execute("""
        SELECT pg_catalog.pg_get_viewdef(c.oid, true)
        FROM   pg_catalog.pg_class c
        JOIN   pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE  c.relname = %s AND n.nspname = 'medcea'
    """, (name,))
    row = cur.fetchone()
    if row:
        return f'-- View: medcea.{name}\nCREATE OR REPLACE VIEW medcea.{name} AS\n{row[0]};\n'
    return ''

def get_sequence_ddl(cur, name):
    cur.execute("""
        SELECT start_value, minimum_value, maximum_value, increment, cycle_option
        FROM information_schema.sequences
        WHERE sequence_schema = 'medcea' AND sequence_name = %s
    """, (name,))
    row = cur.fetchone()
    if not row:
        return ''
    start, minval, maxval, incr, cycle = row
    cycle_str = 'CYCLE' if cycle == 'YES' else 'NO CYCLE'
    return (f'-- Sequence: medcea.{name}\n'
            f'CREATE SEQUENCE IF NOT EXISTS medcea.{name}\n'
            f'  START WITH {start}\n'
            f'  INCREMENT BY {incr}\n'
            f'  MINVALUE {minval}\n'
            f'  MAXVALUE {maxval}\n'
            f'  {cycle_str};\n')

def get_type_ddl(cur, name):
    cur.execute("""
        SELECT t.typtype
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE t.typname = %s AND n.nspname = 'medcea'
    """, (name,))
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
            WHERE t.typname = %s AND n.nspname = 'medcea'
            ORDER BY e.enumsortorder
        """, (name,))
        vals = ', '.join(f"'{r[0]}'" for r in cur.fetchall())
        return f'-- Enum type: medcea.{name}\nCREATE TYPE medcea.{name} AS ENUM ({vals});\n'
    elif typtype == 'd':
        cur.execute("""
            SELECT pg_catalog.format_type(t.typbasetype, t.typtypmod),
                   pg_catalog.pg_get_constraintdef(c.oid, true)
            FROM pg_catalog.pg_type t
            JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
            LEFT JOIN pg_catalog.pg_constraint c ON c.contypid = t.oid
            WHERE t.typname = %s AND n.nspname = 'medcea'
            LIMIT 1
        """, (name,))
        row2 = cur.fetchone()
        if row2:
            base, constraint = row2
            ddl = f'-- Domain: medcea.{name}\nCREATE DOMAIN medcea.{name} AS {base}'
            if constraint:
                ddl += f'\n  {constraint}'
            return ddl + ';\n'
    return ''

def val_to_sql(v):
    if v is None:                            return 'NULL'
    if isinstance(v, bool):                  return 'TRUE' if v else 'FALSE'
    if isinstance(v, (int, float, decimal.Decimal)): return str(v)
    if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
        return "'" + str(v) + "'"
    if isinstance(v, bytes):
        return "E'\\\\x" + v.hex() + "'"
    return "'" + str(v).replace("'", "''") + "'"

def get_data_inserts(cur, name):
    cur.execute(f'SELECT * FROM medcea.{name} ORDER BY 1')
    rows = cur.fetchall()
    if not rows: return ''
    cols = [d[0] for d in cur.description]
    cols_str = ', '.join(cols)
    lines = [f'-- Data: medcea.{name} ({len(rows)} rows)']
    for row in rows:
        vals = ', '.join(val_to_sql(v) for v in row)
        lines.append(f'INSERT INTO medcea.{name} ({cols_str}) VALUES ({vals});')
    return '\n'.join(lines) + '\n'

def build_export(selections):
    parts = ['-- medcea_db export\n-- Generated: ' + str(datetime.datetime.utcnow()) + ' UTC\n']
    con = connect()
    cur = con.cursor()
    for sel in selections:
        name, kind = sel['name'], sel['type']
        if sel.get('ddl'):
            parts.append('\n')
            if kind == 'table':
                parts.append(get_table_ddl(cur, name))
            elif kind == 'view':
                parts.append(get_view_ddl(cur, name))
            elif kind == 'sequence':
                parts.append(get_sequence_ddl(cur, name))
            elif kind in ('enum', 'domain', 'type'):
                parts.append(get_type_ddl(cur, name))
        if sel.get('data') and kind == 'table':
            parts.append('\n')
            parts.append(get_data_inserts(cur, name))
    con.close()
    return ''.join(parts)

# ── Access policy check (IAM plan 1.2) ──────────────────────────────────────
# medcea_iam.py and the route table come from ConfigMap medcea-iam-lib at /iam/.
# Loaded from the mount and reloaded when it changes, so a ConfigMap that appears
# later heals and a new library needs no restart. While IAM_ENFORCE is false the
# check only logs "would refuse ..." (stderr); nothing is refused.
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
            print('medcea_iam: not loaded (%s); requests are not checked' % e, file=sys.stderr, flush=True)
            _IAM['warned'] = True
    return _IAM['mod']


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass  # suppress access log

    def parse_request(self):
        if not super().parse_request():
            return False
        iam = _medcea_iam()
        if iam:
            return iam.http_check(self, 'dbmgmt')
        # No library: fail closed under enforcement (IAM_ENFORCE is also in the
        # pod's environment for this case), report-only otherwise.
        if os.environ.get('IAM_ENFORCE') == 'true' and self.path.split('?')[0] != '/healthz':
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

    def do_GET(self):
        if self.path == '/objects' or self.path == '/objects/':
            try:
                self.send_json(200, list_objects())
            except Exception as e:
                self.send_json(500, {'error': str(e)})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path == '/export' or self.path == '/export/':
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            try:
                sql = build_export(body.get('selections', []))
                data = sql.encode('utf-8')
                filename = (body.get('filename') or 'medcea_export.sql').strip()
                # Sanitise: keep only safe filename chars
                import re as _re
                filename = _re.sub(r'[^A-Za-z0-9._\-]', '_', filename)
                if not filename.endswith('.sql'):
                    filename += '.sql'
                target = body.get('target', 'local')
                if target == 'platform':
                    out_path = os.path.join('/exports', filename)
                    with open(out_path, 'wb') as f:
                        f.write(data)
                    self.send_json(200, {'path': 'apps/database/' + filename, 'size': len(data)})
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    self.send_header('Content-Disposition', 'attachment; filename="' + filename + '"')
                    self.send_header('Content-Length', len(data))
                    self.end_headers()
                    self.wfile.write(data)
            except Exception as e:
                self.send_json(500, {'error': str(e)})
        else:
            self.send_response(404); self.end_headers()

import subprocess, sys
subprocess.run([sys.executable, '-m', 'pip', 'install', 'pg8000', '--quiet', '--no-cache-dir'],
               check=True, capture_output=True)
# PyJWT for the access check; without it the check reports every request as
# unverifiable instead of the service failing to start.
subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyjwt[crypto]', '--quiet', '--no-cache-dir'],
               check=False, capture_output=True)
print('pg8000 ready — listening on :8081', flush=True)
http.server.HTTPServer(('0.0.0.0', 8081), Handler).serve_forever()