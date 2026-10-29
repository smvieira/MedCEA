"""apps/iam/compiler/grants.py — the database side of the access policy (plan Appendix B).

compile-time model
  privileges(p)        sorted [(grantee, kind, object, privilege)]: kind is table (tables and
                       views), function or schema. Sequences are resolved at run time from
                       the tables a grantee may INSERT into (owned / identity sequences).
  memberships(p)       [(role, member, inherit, set)] applied while IAM_DB_ROLES is true
  rls(p)               [{object, name, cmd, role, using, check}] row-level security policies
  compiled_functions(p, smoke)
                       CREATE OR REPLACE text of pre_request(), _own_role(), platform_roles(),
                       policy_holds(), object_group() and _token_clients()
  sql(p, mode, smoke, part)
                       the psql script apps/database/lib-db-apply.sh runs inside the mode
                       bundle's transaction; mode additive (IAM_DB_ROLES=false), enforce (true)
                       or verify (read-only: the assertions of the mode recorded in
                       medcea.platform_setting); part body | assert | all | functions
  check(p)             [errors]: the rules the YAML must follow for the above to be exact
  document(p, smoke)   the JSON form (`cli.py compile grants --format json`)

Rules (one place, so the Policy UI's explain and the database cannot drift):
  people     rr_<role>, composites flattened into each role's own grants (no rr -> rr
             membership); a constraint's `limits_dml_to` narrows its levels' DML
  services   the closure of their ceiling; `service_only: [svc...]` members only for those
  R, X       SELECT          C   INSERT (+ USAGE on the table's sequences)    U   UPDATE
  O, A       EXECUTE on function members of that level, and on every approval function of
             a group where the role holds A
  never      DELETE, TRUNCATE, REFERENCES, TRIGGER; nothing for K or D
  views      SELECT only     written_by: functions   SELECT only, for everyone
  regulated  a service's U compiles only on the `objects` of a waiver that covers it
  infra      infrastructure_functions by their `execute` list or `rule`
Out of scope until IAM Phase 2.7 (DEFERRED): schema iam and role access_svc — nothing is
compiled, revoked or compared there, except that I9 still asserts anon and PUBLIC hold
nothing in iam. Functions in NOT_BUILT do not exist yet and are skipped; every other
function the policy names must exist (asserted in both modes and in `verify`).
"""
import hashlib
import json
import re

SCHEMAS = ("medcea", "medcea_auth", "iam_policy")
MEMBER_SCHEMAS = ("medcea", "iam_policy", "iam")
DEFERRED = {"schema iam": "2.7", "role access_svc": "2.7"}
DEFERRED_ROLES = {"access_svc"}
NOT_BUILT = {
    "iam_policy.new_draft(integer,text)": "4.3",
    "iam_policy.save_entry(integer,text,text,text[],text,text[],text)": "4.3",
    "iam_policy.submit(integer,text)": "4.3",
    "iam_policy.approve(integer,text)": "4.3",
    "iam_policy.propose_zone(uuid,integer,text)": "2.7",
    "iam.confirm_decision(integer,text)": "2.7",
    "iam.sign_off_review(integer,text)": "2.7",
}
# The legacy grants of IAM_DB_ROLES=false (medcea_db_migrations_down_008b.sql): tables the
# blanket anon grant is taken back from. tests/test_policy.py checks the down file names
# each of them, so `verify` in false mode and the down file describe one set.
LEGACY_ANON_EXCLUDED = ("mqtt_credential", "platform_setting", "approval", "pending_change", "run_release",
                        "algorithm_state_event", "row_change", "unit_algorithm_params",
                        "mqtt_service_credential", "mqtt_service_acl")
LEGACY_ANON_READ_ONLY = ("device_slot_history",)
LEGACY_V1 = "medcea.register_mqtt_credential(text,text,integer,text,text)"
NEVER = ("DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
# The guard triggers medcea_db_migrations_008b_enforce.sql attaches (I15 in enforce mode
# checks they are all there and enabled; tests/test_policy.py checks the file names each).
ENFORCE_TRIGGERS = (
    ("medcea.recipe", "iam_draft_only_trg"), ("medcea.control_algorithm", "iam_draft_only_trg"),
    ("medcea.unit_algorithm_params", "iam_draft_only_trg"), ("medcea.recipe_line", "iam_draft_only_trg"),
    ("medcea.recipe_run", "iam_immutable_trg"), ("medcea.recipe_run", "iam_new_run_trg"),
    ("medcea.recipe_line_cycle_run", "iam_immutable_trg"), ("medcea.measurement", "iam_immutable_trg"),
    ("medcea.algorithm_state", "iam_state_guard_trg"), ("medcea.recipe_unit_permission", "iam_assign_only_trg"),
    ("medcea.device", "iam_existing_slot_trg"), ("medcea.recipe_run", "iam_no_truncate_trg"),
    ("medcea.recipe_line_cycle_run", "iam_no_truncate_trg"), ("medcea.measurement", "iam_no_truncate_trg"))
LEVEL_PRIV = {"R": "SELECT", "X": "SELECT", "C": "INSERT", "U": "UPDATE"}
_TYPE_ALIAS = {"int": "integer", "int4": "integer", "int8": "bigint", "bool": "boolean",
               "varchar": "character varying", "timestamptz": "timestamp with time zone"}
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


class GrantsError(ValueError):
    pass


# ── names ────────────────────────────────────────────────────────────────────────────
def norm_sig(sig):
    """'medcea.approve_change(text, bigint, text)' -> 'medcea.approve_change(text,bigint,text)'
    with int/bool/... spelled as PostgreSQL prints them."""
    m = re.match(r"^\s*([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)\s*\((.*)\)\s*$", sig)
    if not m:
        raise GrantsError(f"not a function signature: {sig!r}")
    args = [a.strip() for a in m.group(2).split(",") if a.strip()]
    args = [_TYPE_ALIAS.get(a, a) for a in args]
    return f"{m.group(1)}({','.join(args)})"


def _schema(name):
    return name.split(".", 1)[0]


def _q(ident):
    if not _IDENT.match(ident):
        raise GrantsError(f"unexpected identifier {ident!r}")
    return ident


def _lit(s):
    return "'" + str(s).replace("'", "''") + "'"


def _deferred(obj):
    return _schema(obj) == "iam"


# ── roles ────────────────────────────────────────────────────────────────────────────
def people(p):
    """{platform role: db role}"""
    return {r: rd.get("db_role", "rr_" + r) for r, rd in p.roles.items()}


def services(p, *, deferred=False):
    """{service key: db role}; access_svc (deferred) only when asked."""
    out = {}
    for s, sd in p.services.items():
        if sd["db_role"] in DEFERRED_ROLES and not deferred:
            continue
        out[s] = sd["db_role"]
    return out


def managed(p):
    """Roles grants.py creates and fully owns the privileges of: rr_*, rr_admin_login and
    every service role not managed by its own deploy."""
    out = list(people(p).values())
    out += [r for r, d in sorted(p.data.get("db_roles", {}).items()) if r.startswith("rr_")]
    out += [sd["db_role"] for s, sd in p.services.items() if not sd.get("managed_by")]
    return out


def login_roles(p):
    """Managed roles that LOG IN while IAM_DB_ROLES is true."""
    out = [sd["db_role"] for s, sd in p.services.items() if not sd.get("managed_by")]
    out += [r for r, d in sorted(p.data.get("db_roles", {}).items()) if r.startswith("rr_") and d.get("login")]
    return out


def passwords(p):
    """[(db role, config.env variable)] for the roles with a generated password."""
    out = [(sd["db_role"], sd["db_password"]) for s, sd in p.services.items() if sd.get("db_password")]
    out += [(r, d["password"]) for r, d in sorted(p.data.get("db_roles", {}).items()) if d.get("password")]
    return out


# ── levels ───────────────────────────────────────────────────────────────────────────
def _person_levels(p, g, role):
    """{level: None (unrestricted) | set of objects its DML is limited to}"""
    out = {}
    for r in p.effective_roles(role):
        c = p.cell(g, r)
        if not c:
            continue
        lv, con, applies = c
        lim = p.constraints.get(con, {}).get("limits_dml_to") if con else None
        for l in p.closure(lv):
            restr = set(lim) if (con and lim and l in applies) else None
            if l not in out:
                out[l] = restr
            elif out[l] is None or restr is None:
                out[l] = None
            else:
                out[l] = out[l] | restr
    return out


def _allows(levels, level, obj):
    if level not in levels:
        return False
    lim = levels[level]
    return lim is None or obj in lim


def _service_levels(p, s, g):
    return p.closure((p.services[s].get("ceiling") or {}).get(g, []))


def _waived_objects(p, s, g, level):
    out = set()
    for w in p.waivers:
        if w["invariant"] == "I10" and w["subject"] == s and w["target"] == g and level in w["levels"]:
            out |= set(w.get("objects") or [])
    return out


def policy_holds_table(p):
    """[(role, group, level, verdict)]: 'free' or the constraint(s) a level is held under."""
    out = []
    for r in p.roles:
        for g in p.groups:
            held, free = p.direct(g, r)
            for l in sorted(held):
                if l in free:
                    out.append((r, g, l, "free"))
                    continue
                cons = sorted({p.cell(g, e)[1] for e in p.effective_roles(r)
                               if p.cell(g, e) and p.cell(g, e)[1] and l in p.closure(p.cell(g, e)[0])})
                out.append((r, g, l, ",".join(cons)))
    return out


def _constrained_readers(p, rule):
    """Platform roles holding R on some group only under constraint `rule`."""
    out = set()
    for r in p.roles:
        for g in p.groups:
            held, free = p.direct(g, r)
            if "R" in held and "R" not in free:
                if any(p.cell(g, e) and p.cell(g, e)[1] == rule for e in p.effective_roles(r)):
                    out.add(r)
    return out


# ── the compiled set ─────────────────────────────────────────────────────────────────
def _data_members(p):
    for g, gd in p.groups.items():
        for m in gd["members"]:
            if m["type"] == "data":
                yield g, m


def member_objects(p):
    """{table or view: group} of every data object member (I15's classification)."""
    return {m["object"]: g for g, m in _data_members(p) if "object" in m}


def privileges(p):
    out = set()
    ppl, svc = people(p), services(p)

    def add(grantee, kind, obj, priv):
        if _deferred(obj) or grantee in DEFERRED_ROLES:
            return
        if kind == "function":
            obj = norm_sig(obj)
            if obj in NOT_BUILT:
                return
        out.add((grantee, kind, obj, priv))

    for g, m in _data_members(p):
        cls = p.group_class(g)
        so = m.get("service_only")
        if "object" in m:
            obj = m["object"]
            dml_ok = m.get("written_by") != "functions" and not m.get("view")
            if so is None:
                for r, dbr in ppl.items():
                    lv = _person_levels(p, g, r)
                    if "R" in lv or "X" in lv:
                        add(dbr, "table", obj, "SELECT")
                    if dml_ok and _allows(lv, "C", obj):
                        add(dbr, "table", obj, "INSERT")
                    if dml_ok and _allows(lv, "U", obj):
                        add(dbr, "table", obj, "UPDATE")
            for s, dbr in svc.items():
                if so is not None and s not in so:
                    continue
                lv = _service_levels(p, s, g)
                if lv & {"R", "X"}:
                    add(dbr, "table", obj, "SELECT")
                if dml_ok and "C" in lv:
                    add(dbr, "table", obj, "INSERT")
                if dml_ok and "U" in lv:
                    if cls not in ("regulated", "history") or obj in _waived_objects(p, s, g, "U"):
                        add(dbr, "table", obj, "UPDATE")
        else:
            fn, level = m["function"], m["level"]
            if so is None:
                for r, dbr in ppl.items():
                    if level in _person_levels(p, g, r):
                        add(dbr, "function", fn, "EXECUTE")
            for s, dbr in svc.items():
                if so is not None and s not in so:
                    continue
                if level in _service_levels(p, s, g):
                    add(dbr, "function", fn, "EXECUTE")
    # approval functions: the holders of A on every group whose rule names them
    for g, gd in p.groups.items():
        for fn in (gd.get("approval") or {}).get("functions", []):
            for r, dbr in ppl.items():
                if "A" in _person_levels(p, g, r):
                    add(dbr, "function", fn, "EXECUTE")
    # infrastructure functions
    for f in p.data.get("infrastructure_functions", []):
        grantees = list(f.get("execute") or [])
        if f.get("rule"):
            grantees += [ppl[r] for r in sorted(_constrained_readers(p, f["rule"]))]
        for gr in grantees:
            add(gr, "function", f["function"], "EXECUTE")
    # USAGE on every schema a grantee holds something in
    for (gr, kind, obj, _) in list(out):
        add(gr, "schema", _schema(obj), "USAGE")
    return sorted(out)


def declared_functions(p):
    """Every function signature the policy names (group members, approval functions,
    infrastructure_functions), normalised, minus NOT_BUILT and the deferred schema iam.
    Each must exist: a signature that no longer resolves would otherwise drop out of the
    grant, of I15's comparison and of the matrix test without a word."""
    sigs = set()
    for _, m in _data_members(p):
        if "function" in m:
            sigs.add(m["function"])
    for gd in p.groups.values():
        sigs.update((gd.get("approval") or {}).get("functions", []))
    for f in p.data.get("infrastructure_functions", []):
        sigs.add(f["function"])
    out = {norm_sig(x) for x in sigs if not _deferred(x)}
    return sorted(out - set(NOT_BUILT))


def memberships(p):
    out = [("anon", "authenticator", False, True)]
    out += [(dbr, "authenticator", False, True) for dbr in sorted(people(p).values())]
    for r, d in sorted(p.data.get("db_roles", {}).items()):
        if d.get("member_of"):
            out.append((people(p)[d["member_of"]], r, True, False))
    return out


def rls(p):
    privs = privileges(p)
    out = []
    ppl_rev = {v: k for k, v in people(p).items()}
    for cname, cd in sorted(p.constraints.items()):
        spec = cd.get("rls")
        if not spec:
            continue
        for obj in spec["objects"]:
            group = member_objects(p)[obj]
            for (gr, kind, o, priv) in privs:
                if o != obj or kind != "table" or priv not in ("SELECT", "INSERT"):
                    continue
                if priv == "SELECT":
                    using = "true"
                    if gr in ppl_rev:
                        held, free = p.direct(group, ppl_rev[gr])
                        if "R" not in free:
                            using = spec["using"]
                    cmd, expr = "SELECT", using
                else:
                    cmd, expr = "INSERT", "true"
                h = hashlib.sha256(f"{cmd}|{expr}".encode()).hexdigest()[:8]
                out.append({"object": obj, "role": gr, "cmd": cmd,
                            "using": expr if cmd == "SELECT" else None,
                            "check": expr if cmd == "INSERT" else None,
                            "name": f"iam_{cmd[0].lower()}_{gr}_{h}"})
    return sorted(out, key=lambda x: (x["object"], x["name"]))


def token_clients(p, smoke=False):
    """The clients whose tokens PostgREST accepts: those of the hosts serving config-api."""
    out = sorted({hd["client"] for hd in p.hosts.values() if "config-api" in hd["serves"]})
    return out + (["iam-test"] if smoke else [])


def document(p, smoke=False):
    body = {"privileges": [list(x) for x in privileges(p)],
            "memberships": [list(x) for x in memberships(p)],
            "rls": rls(p), "not_built": NOT_BUILT, "deferred": DEFERRED,
            "token_clients": token_clients(p, smoke)}
    body["digest"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return body


# ── compiled functions ───────────────────────────────────────────────────────────────
def _array(items):
    return "ARRAY[" + ", ".join(_lit(x) for x in items) + "]::text[]"


def _own_role_sql(p):
    """SQL (in a plpgsql body) that sets `own` (text[]) from the jsonb `grp`: the
    platform roles in the claim, minus every role another one in the set includes."""
    pairs = sorted((r, inc) for r in p.roles for inc in p.effective_roles(r) if inc != r)
    incl = " OR ".join(f"(o.x = {_lit(a)} AND r.x = {_lit(b)})" for a, b in pairs) or "false"
    return (f"SELECT coalesce(pg_catalog.array_agg(DISTINCT r.x ORDER BY r.x), '{{}}'::text[]) INTO own\n"
            f"      FROM pg_catalog.jsonb_array_elements_text(CASE WHEN pg_catalog.jsonb_typeof(grp) = 'array'\n"
            f"                                                 THEN grp ELSE '[]'::jsonb END) r(x)\n"
            f"     WHERE r.x = ANY ({_array(sorted(p.roles))})\n"
            f"       AND NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements_text(\n"
            f"               CASE WHEN pg_catalog.jsonb_typeof(grp) = 'array' THEN grp ELSE '[]'::jsonb END) o(x)\n"
            f"                        WHERE {incl});")


def compiled_functions(p, smoke=False):
    clients = token_clients(p, smoke)
    holds = ",\n        ".join(f"({_lit(r)}, {_lit(g)}, {_lit(l)}, {_lit(v)})" for r, g, l, v in policy_holds_table(p))
    groups = ",\n        ".join(f"({_lit(o)}, {_lit(g)})" for o, g in sorted(member_objects(p).items()) if not _deferred(o))
    own = _own_role_sql(p)
    dbrole_cases = "\n        ".join(f"WHEN {_lit(r)} THEN {_lit(d)}" for r, d in sorted(people(p).items()))
    return f"""
-- pre_request(): PostgREST's db-pre-request. SECURITY INVOKER and without a SET clause:
-- a function's SET clause would undo the SET LOCAL ROLE at its exit. A no-op unless the
-- database setting medcea.iam_db_roles is 'true' (IAM_DB_ROLES), so a rolled-back database
-- does not refuse PostgREST's new sessions (pooled ones keep the old setting: deploy.sh
-- restarts config-api on a flip); in enforce mode anon holds nothing, so even a no-op
-- fails closed.
CREATE OR REPLACE FUNCTION medcea_auth.pre_request() RETURNS void LANGUAGE plpgsql AS $pre$
DECLARE
    c    jsonb;
    grp  jsonb;
    own  text[];
BEGIN
    IF pg_catalog.current_setting('medcea.iam_db_roles', true) IS DISTINCT FROM 'true' THEN
        RETURN;
    END IF;
    c := nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::jsonb;
    -- without a token PostgREST 12 still sets the claims, to role = the anon role only
    IF c IS NULL OR c - 'role' = '{{}}'::jsonb THEN
        -- PostgREST runs the pre-request for its OpenAPI root too, and config-api's
        -- readiness probe is an anonymous GET /: refused, the pod never became
        -- Ready. It stays anon, which holds nothing here but USAGE on medcea_auth,
        -- so the document lists nothing (Phase 2b, P15).
        IF pg_catalog.current_setting('request.method', true) = 'GET'
           AND pg_catalog.current_setting('request.path', true) = '/' THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'no token' USING ERRCODE = '28000';
    END IF;
    IF (c ->> 'typ') IS DISTINCT FROM 'Bearer' THEN
        RAISE EXCEPTION 'not an access token' USING ERRCODE = '28000';
    END IF;
    IF NOT coalesce((c ->> 'azp') = ANY ({_array(clients)}), false) THEN
        RAISE EXCEPTION 'client % may not use the API', c ->> 'azp' USING ERRCODE = '28000';
    END IF;
    IF NOT coalesce(c -> 'aud' = '"medcea-api"'::jsonb
                    OR (pg_catalog.jsonb_typeof(c -> 'aud') = 'array' AND (c -> 'aud') ? 'medcea-api'), false) THEN
        RAISE EXCEPTION 'token audience is not medcea-api' USING ERRCODE = '28000';
    END IF;
    IF NOT coalesce((c ->> 'sub') ~* '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$', false) THEN
        RAISE EXCEPTION 'token subject is not a uuid' USING ERRCODE = '28000';
    END IF;
    grp := c -> 'groups';
    {own}
    IF pg_catalog.cardinality(own) = 0 THEN
        RAISE EXCEPTION 'no platform role' USING ERRCODE = '28000';
    ELSIF pg_catalog.cardinality(own) > 1 THEN
        RAISE EXCEPTION 'two own roles: %', own USING ERRCODE = '28000';
    END IF;
    -- the role's db_role, compiled from roles.<r>.db_role (never 'rr_' || the key)
    EXECUTE pg_catalog.format('SET LOCAL ROLE %I', CASE own[1]
        {dbrole_cases}
    END);
END $pre$;
ALTER FUNCTION medcea_auth.pre_request() OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION medcea_auth.pre_request() FROM PUBLIC;

CREATE OR REPLACE FUNCTION medcea_auth._own_role(grp jsonb) RETURNS text
    LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $own$
DECLARE own text[];
BEGIN
    {own}
    IF pg_catalog.cardinality(own) = 1 THEN RETURN own[1]; END IF;
    RETURN NULL;
END $own$;
ALTER FUNCTION medcea_auth._own_role(jsonb) OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION medcea_auth._own_role(jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION medcea_auth.platform_roles() RETURNS text[]
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $r$ SELECT {_array(sorted(p.roles))} $r$;
ALTER FUNCTION medcea_auth.platform_roles() OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION medcea_auth.platform_roles() FROM PUBLIC;

CREATE OR REPLACE FUNCTION medcea_auth._token_clients() RETURNS text[]
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $r$ SELECT {_array(clients)} $r$;
ALTER FUNCTION medcea_auth._token_clients() OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION medcea_auth._token_clients() FROM PUBLIC;

-- policy_holds(role, group, level): NULL (not held), 'free', or the constraint it is held under.
CREATE OR REPLACE FUNCTION medcea_auth.policy_holds(p_role text, p_group text, p_level text) RETURNS text
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $h$
    SELECT v FROM (VALUES
        {holds}
    ) t(r, g, l, v) WHERE r = p_role AND g = p_group AND l = p_level
$h$;
ALTER FUNCTION medcea_auth.policy_holds(text, text, text) OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION medcea_auth.policy_holds(text, text, text) FROM PUBLIC;

-- object_group('medcea.recipe') -> 'recipes': the group of a data member, NULL for anything else.
CREATE OR REPLACE FUNCTION medcea_auth.object_group(p_object text) RETURNS text
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $g$
    SELECT g FROM (VALUES
        {groups}
    ) t(o, g) WHERE o = p_object
$g$;
ALTER FUNCTION medcea_auth.object_group(text) OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION medcea_auth.object_group(text) FROM PUBLIC;
"""


# ── SQL ──────────────────────────────────────────────────────────────────────────────
def _values(rows):
    return ",\n        ".join("(" + ", ".join(_lit(x) for x in r) + ")" for r in rows)


def _expected_cte(p, grantees):
    """CTE `expected(g, k, o, p)`: the compiled privileges of `grantees`, resolved to the
    objects that exist (normalised names), plus the sequences of the tables they INSERT into."""
    rows = [r for r in privileges(p) if r[0] in grantees]
    vals = _values(rows) or "(NULL, NULL, NULL, NULL)"
    return f"""compiled(g, k, o, p) AS (VALUES
        {vals}),
    expected0 AS (
        SELECT c.g::text AS g, 'table'::text AS k, pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(cl.relname) AS o, c.p::text AS p, cl.oid AS rel
          FROM compiled c JOIN pg_catalog.pg_class cl ON cl.oid = pg_catalog.to_regclass(c.o)
          JOIN pg_catalog.pg_namespace n ON n.oid = cl.relnamespace WHERE c.k = 'table'
        UNION ALL
        SELECT c.g, 'function', pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(pr.proname)
               || '(' || pg_catalog.oidvectortypes(pr.proargtypes) || ')', c.p, NULL::oid
          FROM compiled c JOIN pg_catalog.pg_proc pr ON pr.oid = pg_catalog.to_regprocedure(c.o)
          JOIN pg_catalog.pg_namespace n ON n.oid = pr.pronamespace WHERE c.k = 'function'
        UNION ALL
        SELECT c.g, 'schema', pg_catalog.quote_ident(c.o), c.p, NULL::oid
          FROM compiled c JOIN pg_catalog.pg_namespace n ON n.nspname = c.o WHERE c.k = 'schema'),
    expected AS (
        SELECT g, k, o, p FROM expected0
        UNION
        SELECT e.g, 'sequence', pg_catalog.quote_ident(sn.nspname) || '.' || pg_catalog.quote_ident(s.relname), 'USAGE'
          FROM expected0 e
          JOIN pg_catalog.pg_depend d ON d.refobjid = e.rel AND d.refclassid = 'pg_catalog.pg_class'::regclass
                                      AND d.classid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i')
          JOIN pg_catalog.pg_class s ON s.oid = d.objid AND s.relkind = 'S'
          JOIN pg_catalog.pg_namespace sn ON sn.oid = s.relnamespace
         WHERE e.k = 'table' AND e.p = 'INSERT')"""


_ACTUAL_CTE = """actual AS (
        SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee)::text END AS g,
               CASE c.relkind WHEN 'S' THEN 'sequence' ELSE 'table' END AS k,
               pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname) AS o, a.privilege_type AS p
          FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
         WHERE n.nspname IN (%(schemas)s) AND c.relkind IN ('r', 'v', 'm', 'p', 'f', 'S') AND a.grantee <> c.relowner
        UNION ALL
        SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee)::text END,
               'function', pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(pr.proname)
               || '(' || pg_catalog.oidvectortypes(pr.proargtypes) || ')', a.privilege_type
          FROM pg_catalog.pg_proc pr JOIN pg_catalog.pg_namespace n ON n.oid = pr.pronamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(pr.proacl, pg_catalog.acldefault('f', pr.proowner))) a
         WHERE n.nspname IN (%(schemas)s) AND a.grantee <> pr.proowner
        UNION ALL
        SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee)::text END,
               'schema', pg_catalog.quote_ident(n.nspname), a.privilege_type
          FROM pg_catalog.pg_namespace n
          CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) a
         WHERE n.nspname IN (%(schemas)s) AND a.grantee <> n.nspowner)"""


def _actual_cte(schemas=SCHEMAS):
    return _ACTUAL_CTE % {"schemas": ", ".join(_lit(s) for s in schemas)}


def _legacy_cte():
    """CTE `legacy(g, k, o, p)`: anon, authenticator and mqtt_auth as the down file leaves them."""
    excl = ", ".join(_lit(t) for t in LEGACY_ANON_EXCLUDED + LEGACY_ANON_READ_ONLY)
    allx = ", ".join(_lit(t) for t in LEGACY_ANON_EXCLUDED)
    return f"""legacy AS (
        SELECT 'anon'::text AS g, 'table'::text AS k,
               pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname) AS o, pv.p
          FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) pv(p)
         WHERE n.nspname = 'medcea' AND c.relkind IN ('r', 'v', 'm', 'p', 'f') AND c.relname NOT IN ({excl})
        UNION ALL
        SELECT 'anon', 'table', 'medcea.' || t, 'SELECT' FROM pg_catalog.unnest(ARRAY[{", ".join(_lit(t) for t in LEGACY_ANON_READ_ONLY)}]) t
         WHERE pg_catalog.to_regclass('medcea.' || t) IS NOT NULL
        UNION ALL
        SELECT 'anon', 'sequence', pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(s.relname), pv.p
          FROM pg_catalog.pg_class s JOIN pg_catalog.pg_namespace n ON n.oid = s.relnamespace
          CROSS JOIN (VALUES ('USAGE'), ('SELECT')) pv(p)
         WHERE n.nspname = 'medcea' AND s.relkind = 'S'
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_class t ON t.oid = d.refobjid
                            WHERE d.objid = s.oid AND d.classid = 'pg_catalog.pg_class'::regclass
                              AND d.refclassid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i')
                              AND t.relnamespace = n.oid AND t.relname IN ({allx}))
        UNION ALL
        SELECT 'anon', 'function', 'medcea.register_mqtt_credential(text, text, integer, text, text)', 'EXECUTE'
         WHERE pg_catalog.to_regprocedure('{LEGACY_V1}') IS NOT NULL
        UNION ALL SELECT 'anon', 'function', 'medcea_auth.pre_request()', 'EXECUTE'
        UNION ALL SELECT 'anon', 'schema', 'medcea', 'USAGE'
        UNION ALL SELECT 'anon', 'schema', 'medcea_auth', 'USAGE'
        UNION ALL SELECT 'mqtt_auth', 'schema', 'medcea', 'USAGE'
        UNION ALL SELECT 'mqtt_auth', 'table', 'medcea.mqtt_credential', 'SELECT'
        UNION ALL SELECT 'mqtt_auth', 'table', 'medcea.device', 'SELECT')"""


def _role_ddl(p, mode):
    lines = []
    for r in managed(p):
        lines.append(f"DO $r$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = {_lit(r)}) "
                     f"THEN CREATE ROLE {_q(r)} NOLOGIN NOINHERIT; END IF; END $r$;")
    logins = set(login_roles(p))
    for r in managed(p):
        login = mode == "enforce" and r in logins
        lines.append(f"ALTER ROLE {_q(r)} {'LOGIN' if login else 'NOLOGIN'} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;")
    for r, d in sorted(p.data.get("db_roles", {}).items()):
        if r.startswith("rr_") and d.get("member_of"):
            lines.append(f"ALTER ROLE {_q(r)} INHERIT;")
    for r, var in passwords(p):
        if r not in managed(p):
            continue      # authenticator: its own password is applied in Phase 2b
        lines.append(f"\\if :{{?pw_{r}}}\nALTER ROLE {_q(r)} PASSWORD :'pw_{r}';\n\\endif")
    return "\n".join(lines)


def _grant_block(p, grantees, privs_label):
    rows = [r for r in privileges(p) if r[0] in grantees]
    vals = _values(rows)
    if not vals:
        return ""
    return f"""-- {privs_label}
DO $grant$
DECLARE r record; s record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        {vals}
    ) v(g, k, o, p) LOOP
        IF r.k = 'table' AND pg_catalog.to_regclass(r.o) IS NOT NULL THEN
            EXECUTE pg_catalog.format('GRANT %s ON TABLE %s TO %I', r.p, pg_catalog.to_regclass(r.o), r.g);
            IF r.p = 'INSERT' THEN
                FOR s IN SELECT d.objid::regclass AS seq FROM pg_catalog.pg_depend d
                          JOIN pg_catalog.pg_class c ON c.oid = d.objid AND c.relkind = 'S'
                         WHERE d.refobjid = pg_catalog.to_regclass(r.o) AND d.classid = 'pg_catalog.pg_class'::regclass
                           AND d.refclassid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i') LOOP
                    EXECUTE pg_catalog.format('GRANT USAGE ON SEQUENCE %s TO %I', s.seq, r.g);
                END LOOP;
            END IF;
        ELSIF r.k = 'function' AND pg_catalog.to_regprocedure(r.o) IS NOT NULL THEN
            EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION %s TO %I', pg_catalog.to_regprocedure(r.o), r.g);
        ELSIF r.k = 'schema' AND pg_catalog.to_regnamespace(r.o) IS NOT NULL THEN
            EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA %I TO %I', r.o, r.g);
        END IF;
    END LOOP;
END $grant$;"""


def _revoke_from(roles, public=False):
    arr = _array(roles)
    pub = """
    REVOKE ALL ON ALL TABLES IN SCHEMA medcea, medcea_auth, iam_policy FROM PUBLIC;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA medcea, medcea_auth, iam_policy FROM PUBLIC;
    REVOKE ALL ON SCHEMA medcea, medcea_auth, iam_policy FROM PUBLIC;""" if public else ""
    return f"""DO $revoke$
DECLARE g text;
BEGIN
    FOREACH g IN ARRAY {arr} LOOP
        CONTINUE WHEN NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = g);
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES IN SCHEMA medcea, medcea_auth, iam_policy FROM %I', g);
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA medcea, medcea_auth, iam_policy FROM %I', g);
        EXECUTE pg_catalog.format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA medcea, medcea_auth, iam_policy FROM %I', g);
        EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA medcea, medcea_auth, iam_policy FROM %I', g);
    END LOOP;
    -- PUBLIC executes nothing here, in both modes (trigger firing never checks EXECUTE)
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA medcea, medcea_auth, iam_policy FROM PUBLIC;{pub}
END $revoke$;"""


def _rls_sql(p):
    pols = rls(p)
    objs = sorted({x["object"] for x in pols})
    out = []
    for obj in objs:
        mine = [x for x in pols if x["object"] == obj]
        names = _array([x["name"] for x in mine])
        creates = []
        for x in mine:
            body = f"USING ({x['using']})" if x["cmd"] == "SELECT" else f"WITH CHECK ({x['check']})"
            creates.append(
                f"    IF NOT EXISTS (SELECT FROM pg_catalog.pg_policy WHERE polrelid = {_lit(obj)}::regclass AND polname = {_lit(x['name'])}) THEN\n"
                f"        CREATE POLICY {_q(x['name'])} ON {obj} AS PERMISSIVE FOR {x['cmd']} TO {_q(x['role'])} {body};\n"
                f"    END IF;")
        out.append(f"""DO $rls$
DECLARE pol text;
BEGIN
    IF pg_catalog.to_regclass({_lit(obj)}) IS NULL THEN RETURN; END IF;
    FOR pol IN SELECT polname FROM pg_catalog.pg_policy WHERE polrelid = {_lit(obj)}::regclass
                AND polname LIKE 'iam\\_%' AND NOT (polname = ANY ({names})) LOOP
        EXECUTE pg_catalog.format('DROP POLICY %I ON {obj}', pol);
    END LOOP;
{chr(10).join(creates)}
    IF NOT (SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid = {_lit(obj)}::regclass) THEN
        ALTER TABLE {obj} ENABLE ROW LEVEL SECURITY;
    END IF;
END $rls$;""")
    return "\n".join(out)


def rls_objects(p):
    return sorted({x["object"] for x in rls(p)})


def _membership_sql(p):
    out = []
    for role, member, inherit, setopt in memberships(p):
        out.append(f"DO $m$ BEGIN IF to_regrole({_lit(role)}) IS NOT NULL AND to_regrole({_lit(member)}) IS NOT NULL THEN "
                   f"GRANT {_q(role)} TO {_q(member)} WITH INHERIT {str(inherit).upper()}, SET {str(setopt).upper()}; END IF; END $m$;")
    return "\n".join(out)


def _connect_sql(p):
    logins = _array(login_roles(p) + ["authenticator", "mqtt_auth"])
    return f"""DO $c$
DECLARE g text;
BEGIN
    EXECUTE pg_catalog.format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', pg_catalog.current_database());
    FOREACH g IN ARRAY {logins} LOOP
        CONTINUE WHEN NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = g);
        EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO %I', pg_catalog.current_database(), g);
    END LOOP;
END $c$;"""


def _assert_equal(label, expected_cte, scope_sql):
    """A DO block raising when the catalog differs from `expected` for grantees in scope."""
    return f"""DO $a$
DECLARE missing text; extra text;
BEGIN
    WITH {expected_cte},
    {_actual_cte()}
    SELECT (SELECT pg_catalog.string_agg(g || ' ' || p || ' ' || k || ' ' || o, '; ' ORDER BY g, o, p)
              FROM (SELECT * FROM expected EXCEPT SELECT * FROM actual WHERE {scope_sql}) x),
           (SELECT pg_catalog.string_agg(g || ' ' || p || ' ' || k || ' ' || o, '; ' ORDER BY g, o, p)
              FROM (SELECT * FROM actual WHERE {scope_sql} EXCEPT SELECT * FROM expected) y)
      INTO missing, extra;
    IF missing IS NOT NULL OR extra IS NOT NULL THEN
        RAISE EXCEPTION '{label}: the catalog differs from the compiled policy'
            USING DETAIL = pg_catalog.left('missing: ' || coalesce(missing, '-') || ' | not compiled: ' || coalesce(extra, '-'), 4000),
                  ERRCODE = 'P0001';
    END IF;
END $a$;"""


def _common_asserts(p):
    mgd = _array(managed(p))
    fns = _array(declared_functions(p))
    return f"""DO $a$
DECLARE bad text;
BEGIN
    -- every function the policy names exists with that signature (NOT_BUILT is left out)
    SELECT pg_catalog.string_agg(x, ', ') INTO bad FROM pg_catalog.unnest({fns}) x
     WHERE pg_catalog.to_regprocedure(x) IS NULL;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'the policy names functions that do not exist (not in NOT_BUILT): %', bad;
    END IF;
    SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(m.member)::text, ', ') INTO bad
      FROM pg_catalog.pg_auth_members m WHERE m.roleid = 'medcea_owner'::regrole;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'medcea_owner has members (%): nobody may act as the owner', bad;
    END IF;
    WITH {_actual_cte()}
    SELECT pg_catalog.string_agg(o, ', ') INTO bad FROM actual
     WHERE g = 'PUBLIC' AND k = 'function';
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'PUBLIC may execute %', bad;
    END IF;
    WITH {_actual_cte()}
    SELECT pg_catalog.string_agg(g || ' ' || p || ' ' || o, ', ') INTO bad FROM actual
     WHERE g = ANY ({mgd}) AND p IN ('DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER');
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'a managed role holds %', bad;
    END IF;
END $a$;"""


def _additive_asserts(p):
    mgd = managed(p)
    return "\n".join([
        _common_asserts(p),
        _assert_equal("I15 (managed roles)", _expected_cte(p, set(mgd)), f"g = ANY ({_array(mgd)})"),
        f"""DO $a$
DECLARE bad text;
BEGIN
    WITH {_actual_cte()}
    SELECT pg_catalog.string_agg(o, ', ') INTO bad FROM actual
     WHERE g = 'anon' AND k = 'function'
       AND o NOT IN ('medcea_auth.pre_request()', 'medcea.register_mqtt_credential(text, text, integer, text, text)');
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'I9: anon may execute %', bad;
    END IF;
    -- the enforce-only memberships (authenticator -> rr_*, rr_admin_login -> rr_admin) are gone
    SELECT pg_catalog.string_agg(pg_catalog.pg_get_userbyid(m.member) || ' -> ' || pg_catalog.pg_get_userbyid(m.roleid), ', ')
      INTO bad FROM pg_catalog.pg_auth_members m
     WHERE pg_catalog.pg_get_userbyid(m.roleid) = ANY ({_array(sorted(people(p).values()))});
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'IAM_DB_ROLES=false: rr_ roles have members (%)', bad;
    END IF;
END $a$;"""])


def _i9_iam():
    return """DO $a$
DECLARE bad text;
BEGIN
    IF pg_catalog.to_regnamespace('iam') IS NULL THEN RETURN; END IF;
    WITH """ + _actual_cte(("iam",)) + """
    SELECT pg_catalog.string_agg(g || ' ' || p || ' ' || o, ', ') INTO bad FROM actual WHERE g IN ('anon', 'PUBLIC');
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'I9: anon/PUBLIC hold % in schema iam', bad;
    END IF;
END $a$;"""


def _enforce_asserts(p):
    # every grantee but the owner and the deferred access_svc is in scope
    every = set(managed(p)) | {"anon", "authenticator", "mqtt_auth", "PUBLIC"}
    members = _array(sorted(member_objects(p)))
    want = _values([(r, m, str(i).lower(), str(s).lower()) for r, m, i, s in memberships(p)])
    rr = _array(sorted(people(p).values()) + ["anon", "rr_admin_login"])
    return "\n".join([
        _common_asserts(p),
        _assert_equal("I15/I10/I9", _expected_cte(p, every), f"g <> ALL ({_array(sorted(DEFERRED_ROLES))})"),
        _i9_iam(),
        f"""DO $a$
DECLARE bad text;
BEGIN
    -- I15: every relation in the member schemas is a member of a group
    SELECT pg_catalog.string_agg(pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname), ', ') INTO bad
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ({", ".join(_lit(s) for s in MEMBER_SCHEMAS)}) AND c.relkind IN ('r', 'v', 'm', 'p', 'f')
       AND NOT (c.oid = ANY (SELECT pg_catalog.to_regclass(x) FROM pg_catalog.unnest({members}) x WHERE pg_catalog.to_regclass(x) IS NOT NULL));
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'I15: not a member of any group: %', bad;
    END IF;
    -- I15: no column-level privileges
    SELECT pg_catalog.string_agg(c.relname || '.' || a.attname, ', ') INTO bad
      FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy') AND a.attacl IS NOT NULL;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'I15: column privileges on %', bad;
    END IF;
    -- I15: memberships of the rr_ roles, anon and rr_admin_login are exactly the compiled ones
    WITH want(r, m, i, s) AS (VALUES {want}),
    have AS (SELECT pg_catalog.pg_get_userbyid(am.roleid)::text AS r, pg_catalog.pg_get_userbyid(am.member)::text AS m,
                    am.inherit_option::text AS i, am.set_option::text AS s
               FROM pg_catalog.pg_auth_members am
              WHERE pg_catalog.pg_get_userbyid(am.roleid) = ANY ({rr})
                 OR pg_catalog.pg_get_userbyid(am.member) = ANY ({rr}))
    SELECT pg_catalog.string_agg(x, '; ') INTO bad FROM (
        SELECT 'missing ' || r || ' <- ' || m || ' inherit=' || i || ' set=' || s AS x FROM (SELECT * FROM want EXCEPT SELECT * FROM have) a
        UNION ALL
        SELECT 'extra ' || r || ' <- ' || m || ' inherit=' || i || ' set=' || s FROM (SELECT * FROM have EXCEPT SELECT * FROM want) b) z;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'I15: role memberships differ: %', bad;
    END IF;
    -- the guard triggers are attached and enabled, and no other iam_ trigger exists
    WITH want(t, n) AS (VALUES {_values(ENFORCE_TRIGGERS)}),
    have AS (SELECT pg_catalog.quote_ident(ns.nspname) || '.' || pg_catalog.quote_ident(c.relname) AS t, tg.tgname::text AS n
               FROM pg_catalog.pg_trigger tg JOIN pg_catalog.pg_class c ON c.oid = tg.tgrelid
               JOIN pg_catalog.pg_namespace ns ON ns.oid = c.relnamespace
              WHERE ns.nspname = 'medcea' AND NOT tg.tgisinternal AND tg.tgname LIKE 'iam\\_%' AND tg.tgenabled <> 'D')
    SELECT pg_catalog.string_agg(x, '; ') INTO bad FROM (
        SELECT 'missing ' || t || ' ' || n AS x FROM (SELECT * FROM want EXCEPT SELECT * FROM have) a
        UNION ALL SELECT 'extra ' || t || ' ' || n FROM (SELECT * FROM have EXCEPT SELECT * FROM want) b) z;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'I15: guard triggers differ: %', bad;
    END IF;
    -- row-level security: on, with exactly the compiled policies
    WITH want(t, n) AS (VALUES {_values([(x["object"], x["name"]) for x in rls(p)]) or "(NULL, NULL)"}),
    have AS (SELECT pg_catalog.quote_ident(ns.nspname) || '.' || pg_catalog.quote_ident(c.relname) AS t, po.polname::text AS n
               FROM pg_catalog.pg_policy po JOIN pg_catalog.pg_class c ON c.oid = po.polrelid
               JOIN pg_catalog.pg_namespace ns ON ns.oid = c.relnamespace
              WHERE ns.nspname IN ('medcea', 'medcea_auth', 'iam_policy'))
    SELECT pg_catalog.string_agg(x, '; ') INTO bad FROM (
        SELECT 'missing ' || t || ' ' || n AS x FROM (SELECT * FROM want WHERE t IS NOT NULL EXCEPT SELECT * FROM have) a
        UNION ALL SELECT 'extra ' || t || ' ' || n FROM (SELECT * FROM have EXCEPT SELECT * FROM want) b
        UNION ALL SELECT 'row level security off on ' || t FROM (SELECT DISTINCT t FROM want WHERE t IS NOT NULL) w
                   WHERE NOT (SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid = pg_catalog.to_regclass(w.t))) z;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'I15: row-level security differs: %', bad;
    END IF;
END $a$;"""])


def _legacy_asserts():
    return _assert_equal("IAM_DB_ROLES=false legacy grants (down file)", _legacy_cte().replace("legacy AS", "expected AS", 1),
                         "g IN ('anon', 'authenticator', 'mqtt_auth')")


def _verify_sql(p):
    return f"""-- verify: read-only; the assertions of the mode recorded in medcea.platform_setting
SELECT coalesce((SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'), 'false') = 'true' AS iam_enforcing \\gset
\\if :iam_enforcing
{_enforce_asserts(p)}
\\else
{_additive_asserts(p)}
{_legacy_asserts()}
\\endif
SELECT 'grants verified' AS result;"""


def sql(p, mode, smoke=False, part="all"):
    if mode not in ("additive", "enforce", "verify"):
        raise GrantsError(f"unknown mode {mode}")
    doc = document(p, smoke)
    head = (f"-- grants.py --mode {mode}{' --smoke' if smoke else ''}  digest {doc['digest']}\n"
            f"-- Generated from apps/iam/policy/defaults.yaml; do not edit. Runs inside the\n"
            f"-- IAM_DB_ROLES bundle's transaction (apps/database/lib-db-apply.sh).\n")
    if mode == "verify":
        return head + _verify_sql(p) + "\n"
    if part == "functions":   # the compiled functions alone (lib-db-apply.sh step 4a: 008b's data steps need them)
        return head + compiled_functions(p, smoke)
    body, asserts = [], []
    body.append("-- 1. roles\n" + _role_ddl(p, mode))
    body.append("-- 2. compiled functions" + compiled_functions(p, smoke))
    if mode == "additive":
        body.append("-- 3. revokes (managed roles only; anon, authenticator and mqtt_auth keep the legacy set)\n"
                    + _revoke_from(managed(p)))
        body.append(_grant_block(p, set(managed(p)), "4. grants of the managed roles (all NOLOGIN while IAM_DB_ROLES=false)"))
        body.append(_grant_block(p, {"anon"}, "4b. anon: USAGE on medcea_auth, EXECUTE on pre_request() (both modes)"))
        asserts.append(_additive_asserts(p))
    else:
        every = managed(p) + ["anon", "authenticator", "mqtt_auth"]
        body.append("-- 3. revokes (plan Appendix B, step 2; schema iam deferred to 2.7)\n" + _revoke_from(every, public=True)
                    + "\nALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA medcea REVOKE ALL ON TABLES FROM anon;"
                    + "\nALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA medcea REVOKE ALL ON SEQUENCES FROM anon;\n"
                    + _connect_sql(p))
        body.append(_grant_block(p, set(every), "4. the compiled set"))
        body.append("-- 5. memberships\n" + _membership_sql(p))
        body.append("-- 6. row-level security\n" + _rls_sql(p))
        asserts.append(_enforce_asserts(p))
    text = head
    if part in ("all", "body"):
        text += "\n\n".join(b for b in body if b) + "\n"
    if part in ("all", "assert"):
        text += "-- assertions (I9, I10, I15): any difference rolls the whole bundle back\n" + "\n".join(asserts) + "\n"
    return text


# ── policy rules the compiler relies on ──────────────────────────────────────────────
def check(p):
    errors = []
    err = errors.append
    roles_known = set(people(p).values()) | {sd["db_role"] for sd in p.services.values()} | set(p.data.get("db_roles", {}))
    members = member_objects(p)
    funcs = {}
    for g, m in _data_members(p):
        if True in m or "on" in m:
            err(f"group {g}: member {m.get('function') or m.get('object')} uses the key `on` (YAML reads it as true); use `level`")
        so = m.get("service_only")
        if so is not None and (not isinstance(so, list) or any(s not in p.services for s in so)):
            err(f"group {g}: service_only of {m.get('function') or m.get('object')} must be a list of service_identities keys")
        if m.get("written_by") not in (None, "functions"):
            err(f"group {g}: written_by of {m.get('object')} must be 'functions'")
        if "function" in m:
            try:
                funcs[norm_sig(m["function"])] = g
            except GrantsError as e:
                err(f"group {g}: {e}")
            if m.get("level") not in p.levels:
                err(f"group {g}: function {m['function']} has no level")
            for t in m.get("writes") or []:
                if t not in members:
                    err(f"group {g}: {m['function']} writes {t}, which is not a member")
                else:
                    tm = next(x for _, x in _data_members(p) if x.get("object") == t)
                    if tm.get("written_by") != "functions":
                        err(f"written_by missing: {t} is written by {m['function']} but not `written_by: functions`")
        elif m.get("view") and m.get("written_by"):
            err(f"group {g}: view {m['object']} cannot be written_by functions")
    for g, gd in p.groups.items():
        ap = gd.get("approval")
        if ap is None:
            continue
        fl = ap.get("functions")
        if not isinstance(fl, list) or not fl:
            err(f"group {g}: approval.functions must be a list of exact signatures")
            continue
        for f in fl:
            try:
                if norm_sig(f) not in funcs:
                    err(f"group {g}: approval function {f} is not a function member of any group")
            except GrantsError as e:
                err(f"group {g}: {e}")
    for c, cd in p.constraints.items():
        lim = cd.get("limits_dml_to")
        if lim is not None:
            groups = {g for g, row in p.matrix.items() for r in row if isinstance(row[r], dict) and row[r].get("constraint") == c}
            for o in lim:
                if members.get(o) not in groups:
                    err(f"constraint {c}: limits_dml_to names {o}, not a member of a group the constraint is used on")
        spec = cd.get("rls")
        if spec is not None:
            for o in spec.get("objects", []):
                if o not in members:
                    err(f"constraint {c}: rls object {o} is not a member")
            if not spec.get("using"):
                err(f"constraint {c}: rls needs `using`")
    for w in p.waivers:
        for o in w.get("objects") or []:
            if members.get(o) != w["target"]:
                err(f"waiver {w['id']}: object {o} is not a member of its target group {w['target']}")
        if not w.get("objects"):
            err(f"waiver {w['id']}: objects missing")
    for f in p.data.get("infrastructure_functions", []):
        try:
            norm_sig(f["function"])
        except GrantsError as e:
            err(f"infrastructure_functions: {e}")
        for r in f.get("execute") or []:
            if r not in roles_known:
                err(f"infrastructure_functions: {f['function']} names {r}, not a database role")
        if f.get("rule") and f["rule"] not in p.constraints:
            err(f"infrastructure_functions: {f['function']} rule {f['rule']} is not a constraint")
        if "execute" not in f and "rule" not in f:
            err(f"infrastructure_functions: {f['function']} needs execute or rule")
    for s, sd in p.services.items():
        if not sd.get("managed_by") and not sd.get("db_password"):
            err(f"service {s}: db_password (a config.env variable) missing")
    for r, d in p.data.get("db_roles", {}).items():
        if d.get("member_of") and d["member_of"] not in p.roles:
            err(f"db_roles {r}: member_of {d['member_of']} is not a platform role")
    for t in p.groups:
        for m in p.groups[t]["members"]:
            if m["type"] == "data" and "object" in m and _schema(m["object"]) not in MEMBER_SCHEMAS:
                err(f"group {t}: {m['object']} is outside {MEMBER_SCHEMAS}")
    return errors
