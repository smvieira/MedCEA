#!/usr/bin/env bash
# tests/iam-db.sh — the database side of IAM Phase 2a (tasks 2.1-2.3) on a running
# PostgreSQL: catalog, role matrix, PostgREST role selection, the actor, write
# probes and drift detection.
#
#   tests/iam-db.sh [--namespace NS] [--pod POD] [--db DB] [--mode auto|false|true|legacy]
#                   [--write-probes] [--section NAME]...
#
#   catalog      ownership (schema iam too, IAM 2.7), the always-on triggers
#                (append-only ones ENABLE ALWAYS; iam's freeze and history triggers
#                too), security_invoker views, SECURITY DEFINER and search_path of
#                the functions, no PUBLIC EXECUTE, iam_* triggers and RLS iff mode
#                true, the EXECUTE holders of the iam functions equal the golden
#   matrix       has_table_privilege / has_function_privilege for every compiled
#                privilege and the hand-written negatives; authenticator's
#                memberships (true); then `grants --mode verify`
#   prerequest   pre_request() for a table of claims (true), a no-op (false)
#   actor        spoofed actor table, forged claims in a service / rr_admin_login
#                session, token actors, set_actor's argument checks
#   writes       W1 false-mode regression (today's callers), W2 always-on guards,
#                W3 flag-only probes, W4 true-mode workflow, W5 register v2,
#                W6 the scheduler's functions (2.4: retire, re-save, cycles, the
#                schedule's algorithm, the internal actor, e97aab6's scheduler SQL),
#                W7 unit assignments (apps/iam/units.sql, IAM 2.8: assign waits for
#                qa, --bootstrap acts at once, remove withdraws a waiting one); the own_unit RLS
#                probes run in W4
#   access       (not in the default set; write probes) IAM 2.7's account decisions,
#                D1-D18: record, withdraw, confirm, refuse, review as access_svc with
#                set_actor; the who-may rules, units.sql refusals, the attestation,
#                append-only histories, role_widening's stub, the review, template
#                reset, MQTT revocation, rr_qa without EXECUTE
#   drift        an extra grant, a revoked one, an extra policy, a dropped trigger:
#                each must make `grants --mode verify` fail
#
# Every `compile grants` call gets dba_iam_flag's answer (apps/database/lib-db-apply.sh):
# --without-iam while schema iam is absent; a half-present access component aborts.
#
# Read-only by default: every session runs with default_transaction_read_only=on and
# the write sections are skipped. --write-probes runs them, each inside
# BEGIN … ROLLBACK, and is refused unless the namespace is medcea-iamtest (the
# throwaway instance of tests/iam-db-fixture.sh) — there is no override.
# --mode auto reads medcea.platform_setting.iam_db_roles; legacy is the schema of the
# commit before Phase 2a (after the down file's full section): W1 only, without the
# attribution checks. Every negative probe asserts the SQLSTATE and a fragment of the
# message, and runs after its positive control on the same fixture.
# psql runs inside the pod as postgres, its password read there. Exit 1 on any FAIL.

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
source infra/lib-mk8s.sh
CLI="$REPO_ROOT/apps/iam/compiler/cli.py"

NS="medcea-iamtest"; POD="pg"; DB="medcea_db"; MODE="auto"; WRITES=false; SECTIONS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace) NS="$2"; shift 2 ;;
        --pod) POD="$2"; shift 2 ;;
        --db) DB="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --write-probes) WRITES=true; shift ;;
        --section) SECTIONS+=("$2"); shift 2 ;;
        *) echo "unknown option $1 (--help)" >&2; exit 2 ;;
    esac
done
if [[ "$WRITES" == true && "$NS" != "medcea-iamtest" ]]; then
    echo "REFUSED: --write-probes runs only against the throwaway instance (namespace medcea-iamtest), never $NS." >&2
    exit 2
fi
[[ ${#SECTIONS[@]} -gt 0 ]] || SECTIONS=(catalog matrix prerequest actor writes drift)
want() { local s; for s in "${SECTIONS[@]}"; do [[ "$s" == "$1" ]] && return 0; done; return 1; }

FAILS=0; PASSES=0
pass() { printf "  ${GREEN}PASS${NC}  %-10s %s\n" "$1" "$2"; PASSES=$((PASSES + 1)); }
fail() { printf "  ${RED}FAIL${NC}  %-10s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }
note() { printf "  ${YELLOW}NOTE${NC}  %-10s %s\n" "$1" "$2"; }

# db [RW] — psql in the pod, SQL on stdin; read-only unless the first argument is rw
db() {
    local opts="-c client_min_messages=warning -c default_transaction_read_only=on"
    [[ "${1:-}" == rw ]] && opts="-c client_min_messages=warning"
    $KUBECTL exec -i -n "$NS" "$POD" -- env PGOPTIONS="$opts" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -tA -F "|" -U postgres -d "$0" -v ON_ERROR_STOP=0' "$DB" 2>&1
}
q1() { db <<<"$1" | head -1; }

if [[ "$MODE" == auto ]]; then
    MODE="$(q1 "SELECT coalesce((SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'), 'legacy')")"
    [[ "$MODE" == true || "$MODE" == false || "$MODE" == legacy ]] || { echo "cannot read the mode: $MODE" >&2; exit 2; }
fi
echo -e "${BOLD}IAM Phase 2a database checks${NC} (namespace $NS, pod $POD, database $DB, mode $MODE, write probes $WRITES)"

# Schema iam compiled like the rest, or --without-iam: what the database deploy would
# decide (dba_iam_flag, IAM 2.7). An unreadable or half-present answer aborts.
IAM_FLAG=()
if [[ "$MODE" != legacy ]]; then
    source apps/database/lib-db-apply.sh
    _flag="$(dba_iam_flag "$NS" "$POD" "$DB")" || { echo "dba_iam_flag failed (above): cannot tell how schema iam is compiled" >&2; exit 2; }
    [[ -n "$_flag" ]] && IAM_FLAG=("$_flag") && echo "  schema iam absent: grants compiled $_flag"
fi

UUID_OP="11111111-1111-4111-8111-111111111111"; UUID_PM="22222222-2222-4222-8222-222222222222"
UUID_QA="33333333-3333-4333-8333-333333333333"; UUID_QP="44444444-4444-4444-8444-444444444444"
UUID_EN="55555555-5555-4555-8555-555555555555"; UUID_EN2="66666666-6666-4666-8666-666666666666"
UUID_AD="77777777-7777-4777-8777-777777777777"; UUID_OP2="88888888-8888-4888-8888-888888888888"
UUID_QA2="99999999-9999-4999-8999-999999999999"
# claims ROLE[,ROLE] SUB PERSON [azp] [typ] [aud] — a token's claims as PostgREST would set them
claims() {
    local groups="" r
    for r in ${1//,/ }; do groups+="${groups:+,}\"$r\""; done
    local aud="${6-\"medcea-api\"}"
    printf '{"typ":"%s","azp":"%s",%s"sub":"%s","person_id":"%s","preferred_username":"test-%s","groups":[%s]}' \
        "${5:-Bearer}" "${4:-config}" "${aud:+\"aud\":$aud,}" "$2" "$3" "$3" "$groups"
}
# as_token CLAIMS — SQL that turns the session into PostgREST's for that token
as_token() {
    cat <<SQL
RESET ROLE;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$1', true) \\g /dev/null
SELECT medcea_auth.pre_request() \\g /dev/null
SQL
}
as_anon() { printf 'RESET ROLE;\nRESET SESSION AUTHORIZATION;\nSET SESSION AUTHORIZATION authenticator;\nSET ROLE anon;\n'; }
as_postgres() { printf 'RESET ROLE;\nRESET SESSION AUTHORIZATION;\n'; }

# probe SECTION NAME EXPECT — SQL on stdin: setup, then the probe statement, then
# optionally a line '--CHECKS' and checks (run as postgres, only after a success) that
# print 'CHECK|label|t' for each truth. EXPECT is ok, or SQLSTATE:fragment of the
# message. The first ERROR in the transaction decides (verbose errors carry the
# SQLSTATE); everything is rolled back.
probe() {
    local section="$1" name="$2" expect="$3" input main checks out first state msg c v
    input="$(cat)"
    main="${input%%--CHECKS*}"
    checks=""; [[ "$input" == *--CHECKS* ]] && checks="${input#*--CHECKS}"
    out="$({
        echo '\set VERBOSITY verbose'
        echo "BEGIN;"
        echo "$main"
        echo '\warn PROBE_DONE'   # on stderr, ordered with the errors
        if [[ -n "$checks" ]]; then as_postgres; echo "$checks"; fi
        echo "ROLLBACK;"
    } | db rw)"
    first="$(sed -n '/PROBE_DONE/q;p' <<<"$out" | grep -m1 -E 'ERROR:  [0-9A-Z]{5}:' || true)"
    state="$(sed -E 's/.*ERROR:  ([0-9A-Z]{5}):.*/\1/' <<<"$first")"
    msg="$(sed -E 's/.*ERROR:  [0-9A-Z]{5}: //' <<<"$first")"
    if [[ "$expect" == ok ]]; then
        if [[ -n "$first" ]]; then
            fail "$section" "$name: expected success, got $state $msg"
            return
        fi
    else
        local want_state="${expect%%:*}" frag="${expect#*:}"
        if [[ "$state" != "$want_state" || "$msg" != *"$frag"* ]]; then
            fail "$section" "$name: expected $want_state '$frag', got ${first:-success}"
            return
        fi
        pass "$section" "$name ($expect)"
        return
    fi
    while IFS='|' read -r _ c v; do
        [[ "$v" == t ]] || { fail "$section" "$name: check '$c' is ${v:-missing}"; return; }
    done < <(grep '^CHECK|' <<<"$out")
    if [[ -n "$checks" ]] && ! grep -q '^CHECK|' <<<"$out"; then
        fail "$section" "$name: the checks did not run: $(grep -m1 'ERROR' <<<"$out")"
        return
    fi
    pass "$section" "$name"
}

# ── catalog ──────────────────────────────────────────────────────────────────────
if want catalog && [[ "$MODE" != legacy ]]; then
    echo ""
    out="$(db <<'SQL'
SELECT 'owner', count(*) FROM (
    SELECT c.relowner AS o FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam') AND c.relkind IN ('r', 'v', 'm', 'p', 'S', 'f')
    UNION ALL SELECT p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')
    UNION ALL SELECT nspowner FROM pg_namespace WHERE nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')) x
 WHERE o <> 'medcea_owner'::regrole;
SELECT 'iamschema', count(*) FROM pg_namespace WHERE nspname = 'iam';
-- IAM 2.7: the freeze triggers (account_decision, access_review) and the append-only
-- triggers of the three iam histories: every BEFORE trigger on those tables ALWAYS
SELECT 'iamalways', count(*) FILTER (WHERE t.tgenabled <> 'A'), count(*),
       coalesce(string_agg(c.relname || '.' || t.tgname, ',') FILTER (WHERE t.tgenabled <> 'A'), '')
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = to_regnamespace('iam') AND NOT t.tgisinternal AND (t.tgtype & 2) <> 0
   AND c.relname IN ('account_decision', 'access_review', 'user_status_history', 'access_request_history', 'config_history');
SELECT 'iamhist', count(DISTINCT c.relname) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = to_regnamespace('iam') AND NOT t.tgisinternal AND (t.tgtype & 2) <> 0
   AND c.relname IN ('user_status_history', 'access_request_history', 'config_history');
-- who may execute each iam function, besides its owner (compared with the golden below)
SELECT 'iamexec', r.rolname || ' ' || replace(p.oid::regprocedure::text, ' ', '')
  FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
  JOIN pg_roles r ON r.oid = a.grantee
 WHERE p.pronamespace = to_regnamespace('iam') AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner
 ORDER BY 2;
SELECT 'members', count(*) FROM pg_auth_members WHERE roleid = 'medcea_owner'::regrole;
SELECT 'changelog', count(*) FROM pg_class WHERE oid = to_regclass('medcea.databasechangeloglock');
SELECT 'invoker', count(*) FROM pg_class c WHERE c.relnamespace = 'medcea'::regnamespace AND c.relkind = 'v'
   AND NOT coalesce('security_invoker=true' = ANY (c.reloptions), false);
SELECT 'always', string_agg(c.relname || '.' || t.tgname, ',') FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE (t.tgname LIKE '%\_append\_only' OR t.tgname LIKE '%\_no\_truncate' OR t.tgname = 'schedule_retired_guard_trg')
   AND t.tgenabled <> 'A'
   AND c.relnamespace IN ('medcea'::regnamespace, 'iam_policy'::regnamespace);
SELECT 'appendonly', count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE t.tgname LIKE '%\_append\_only' AND c.relnamespace IN ('medcea'::regnamespace, 'iam_policy'::regnamespace);
SELECT 'stamp', count(*) FROM pg_trigger WHERE tgname = 'stamp_actor_trg';
SELECT 'rowchange', count(*) FROM pg_trigger WHERE tgname = 'row_change_trg';
SELECT 'guard', count(*) FROM pg_trigger WHERE tgname = 'status_guard_trg';
SELECT 'single', string_agg(n, ',') FROM unnest(ARRAY['measurement_zone_trg', 'device_serial_change_trg', 'mqtt_service_acl_root_trg',
       'algorithm_state_event_trg', 'algorithm_state_before_trg', 'user_zone_audit_trg', 'user_unit_audit_trg',
       'schedule_retired_guard_trg']) n
 WHERE NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = n);
SELECT 'definer', string_agg(p.oid::regprocedure::text, ',') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam') AND p.prosecdef
   AND NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%pg_temp');
SELECT 'invokerfn', string_agg(p.proname, ',') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'medcea' AND p.prosecdef
   AND p.proname IN ('guard_control_columns', 'schedule_retired_guard', 'reject_non_draft_update', 'immutable_row', 'algorithm_state_guard', 'algorithm_state_before');
SELECT 'prereq', p.prosecdef || '/' || coalesce(array_to_string(p.proconfig, ','), '') FROM pg_proc p WHERE p.oid = 'medcea_auth.pre_request()'::regprocedure;
SELECT 'public', count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
 WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy') AND a.grantee = 0;
SELECT 'iamtrg', count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = 'medcea'::regnamespace AND t.tgname LIKE 'iam\_%';
SELECT 'rls', count(*) FROM pg_class WHERE relnamespace = 'medcea'::regnamespace AND relrowsecurity;
SELECT 'unitalways', tgenabled FROM pg_trigger WHERE tgname = 'user_unit_audit_trg';
SELECT 'chain', ok FROM iam_policy.verify_chain();
SQL
)"
    get() { grep -m1 "^$1|" <<<"$out" | cut -d'|' -f2; }
    [[ "$(get owner)" == 0 ]] && pass catalog "every object in medcea, medcea_auth, iam_policy$([[ "$(get iamschema)" == 1 ]] && echo ', iam') is owned by medcea_owner" \
        || fail catalog "$(get owner) object(s) not owned by medcea_owner"
    if [[ "$(get iamschema)" == 1 ]]; then
        IFS='|' read -r _ n_off n_all off_list <<<"$(grep -m1 '^iamalways|' <<<"$out")"
        [[ "$n_off" == 0 && "${n_all:-0}" -ge 7 && "$(get iamhist)" == 3 ]] \
            && pass catalog "iam: $n_all freeze and append-only triggers (the three histories included), all ENABLE ALWAYS" \
            || fail catalog "iam triggers: ${n_all:-0} BEFORE trigger(s), not ALWAYS: ${off_list:-none}; histories with one: $(get iamhist) of 3"
        want_exec="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print("\n".join(sorted("%s %s" % (g, o.replace(" ", "")) for g, k, o, p in d["privileges"]
                        if k == "function" and o.startswith("iam.") and p == "EXECUTE")))' tests/iam-grants.golden.json | sort)"
        got_exec="$(grep '^iamexec|' <<<"$out" | cut -d'|' -f2 | sort)"
        if [[ "$got_exec" == "$want_exec" ]]; then
            pass catalog "the EXECUTE holders of the iam functions equal the golden ($(grep -c . <<<"$want_exec"))"
        else
            fail catalog "iam EXECUTE holders differ from tests/iam-grants.golden.json:"
            diff <(echo "$want_exec") <(echo "$got_exec") | grep '^[<>]' | sed 's/^</        golden only:/; s/^>/        database only:/' | head -20
        fi
    else
        note catalog "schema iam absent (no access component): its checks skipped"
    fi
    [[ "$(get members)" == 0 ]] && pass catalog "medcea_owner has no members" || fail catalog "medcea_owner has $(get members) member(s)"
    [[ "$(get changelog)" == 0 ]] && pass catalog "medcea.databasechangeloglock is gone" || fail catalog "databasechangeloglock still exists"
    [[ "$(get invoker)" == 0 ]] && pass catalog "every medcea view is security_invoker" || fail catalog "$(get invoker) view(s) without security_invoker"
    [[ -z "$(get always)" && "$(get appendonly)" -ge 8 ]] && pass catalog "$(get appendonly) append-only triggers, all ENABLE ALWAYS" \
        || fail catalog "append-only triggers not ENABLE ALWAYS: $(get always) (count $(get appendonly))"
    [[ "$(get stamp)" == 14 && "$(get rowchange)" == 14 ]] && pass catalog "stamp_actor_trg and row_change_trg on the 14 tables" \
        || fail catalog "stamp_actor_trg on $(get stamp), row_change_trg on $(get rowchange) table(s) (want 14)"
    [[ "$(get guard)" == 8 ]] && pass catalog "status_guard_trg on 8 tables" || fail catalog "status_guard_trg on $(get guard) table(s) (want 8)"
    [[ -z "$(get single)" ]] && pass catalog "zone, serial, ACL root, Q-table, zone- and unit-audit triggers present" || fail catalog "missing: $(get single)"
    [[ -z "$(get definer)" ]] && pass catalog "every SECURITY DEFINER function pins search_path ... pg_temp" || fail catalog "definer without search_path: $(get definer)"
    [[ -z "$(get invokerfn)" ]] && pass catalog "the current_user guards are SECURITY INVOKER" || fail catalog "SECURITY DEFINER guards: $(get invokerfn)"
    [[ "$(get prereq)" == "false/" ]] && pass catalog "pre_request() is INVOKER without a SET clause" || fail catalog "pre_request(): $(get prereq)"
    [[ "$(get public)" == 0 ]] && pass catalog "PUBLIC executes no function in the three schemas" || fail catalog "PUBLIC executes $(get public) function(s)"
    if [[ "$MODE" == true ]]; then
        [[ "$(get iamtrg)" -ge 14 && "$(get rls)" -ge 4 ]] && pass catalog "iam_* triggers ($(get iamtrg)) and RLS present (mode true)" \
            || fail catalog "mode true but iam_* triggers $(get iamtrg), RLS tables $(get rls)"
    else
        [[ "$(get iamtrg)" == 0 && "$(get rls)" == 0 ]] && pass catalog "no iam_* trigger and no RLS (mode false)" \
            || fail catalog "mode false but iam_* triggers $(get iamtrg), RLS tables $(get rls)"
    fi
    [[ "$(get unitalways)" == A ]] && pass catalog "user_unit_audit_trg is ENABLE ALWAYS" \
        || fail catalog "user_unit_audit_trg: tgenabled '$(get unitalways)' (want A)"
    [[ "$(get chain)" == t ]] && pass catalog "iam_policy.verify_chain() ok" || fail catalog "verify_chain: $(get chain)"
fi

# ── matrix ───────────────────────────────────────────────────────────────────────
if want matrix && [[ "$MODE" != legacy ]]; then
    echo ""
    sql="$(python3 - "$CLI" "$MODE" "${IAM_FLAG[@]}" <<'PY'
import json, subprocess, sys
cli, mode, flag = sys.argv[1], sys.argv[2], sys.argv[3:]
doc = json.loads(subprocess.check_output([sys.executable, cli, "compile", "grants", "--format", "json"] + flag))
mgd = set(subprocess.check_output([sys.executable, cli, "db-roles", "--names"], text=True).split())
q = lambda s: "'" + s.replace("'", "''") + "'"
lines = []
for g, k, o, p in doc["privileges"]:
    if mode == "false" and g not in mgd - {"mqtt_auth"} and g != "anon":
        continue
    if k == "table":
        e = f"has_table_privilege({q(g)}, {q(o)}, {q(p)})"
        guard = f"to_regclass({q(o)}) IS NOT NULL"
    elif k == "function":
        e = f"has_function_privilege({q(g)}, {q(o)}, 'EXECUTE')"
        guard = f"to_regprocedure({q(o)}) IS NOT NULL"
    else:
        e = f"has_schema_privilege({q(g)}, {q(o)}, 'USAGE')"
        guard = "true"
    lines.append(f"SELECT 'grant', {q(g + ' ' + p + ' ' + o)} WHERE {guard} AND NOT {e};")
neg = [("anon", "medcea.recipe", "SELECT") if mode == "true" else None,
       ("rr_operator", "medcea.recipe_run", "UPDATE"), ("svc_scheduler", "medcea.recipe_run", "UPDATE"),
       ("rr_production_manager", "medcea.recipe_line_cycle_run", "UPDATE"), ("svc_scheduler", "medcea.recipe_line_cycle_run", "INSERT"),
       ("rr_engineer", "medcea.recipe_unit_permission", "UPDATE"), ("rr_engineer", "medcea.mqtt_credential", "SELECT"),
       ("rr_admin", "medcea.measurement", "SELECT"), ("rr_auditor", "medcea.recipe", "INSERT"),
       ("rr_qa", "medcea.approval", "INSERT"), ("svc_grafana", "medcea.mqtt_service_credential", "SELECT"),
       ("rr_engineer", "medcea.mqtt_service_acl", "SELECT"), ("svc_ingest", "medcea.measurement", "UPDATE"),
       ("svc_ingest", "medcea.measurement", "DELETE"), ("rr_admin", "medcea.platform_setting", "SELECT")]
for n in neg:
    if n:
        lines.append(f"SELECT 'negative', {q(' '.join(n))} WHERE has_table_privilege({q(n[0])}, {q(n[1])}, {q(n[2])});")
if mode == "true":
    for r in sorted({m[0] for m in doc["memberships"] if m[1] == "authenticator"}):
        lines.append(f"SELECT 'member', {q(r)} WHERE NOT (pg_has_role('authenticator', {q(r)}, 'SET') AND NOT pg_has_role('authenticator', {q(r)}, 'USAGE'));")
    lines.append("SELECT 'member', 'rr_admin_login' WHERE NOT pg_has_role('rr_admin_login', 'rr_admin', 'USAGE');")
print("\n".join(lines))
PY
)"
    out="$(db <<<"$sql")"
    n_grant="$(grep -c '^grant|' <<<"$out" || true)"; n_neg="$(grep -c '^negative|' <<<"$out" || true)"
    n_mem="$(grep -c '^member|' <<<"$out" || true)"; n_err="$(grep -c 'ERROR' <<<"$out" || true)"
    [[ "$n_grant" == 0 && "$n_err" == 0 ]] && pass matrix "every compiled privilege is held ($(grep -c '^SELECT' <<<"$sql") checks)" \
        || fail matrix "$n_grant missing, $n_err error(s): $(grep -m3 '^grant\|ERROR' <<<"$out" | tr '\n' ';')"
    [[ "$n_neg" == 0 ]] && pass matrix "the hand-written negatives hold" || fail matrix "held but must not be: $(grep '^negative|' <<<"$out" | cut -d'|' -f2 | tr '\n' ';')"
    if [[ "$MODE" == true ]]; then
        [[ "$n_mem" == 0 ]] && pass matrix "authenticator: SET without INHERIT on every rr_ role and anon; rr_admin_login inherits rr_admin" \
            || fail matrix "memberships: $(grep '^member|' <<<"$out" | cut -d'|' -f2 | tr '\n' ' ')"
    fi
    vout="$(python3 "$CLI" compile grants --mode verify "${IAM_FLAG[@]}" | db)"
    grep -q 'grants verified' <<<"$vout" && ! grep -q ERROR <<<"$vout" && pass matrix "grants --mode verify passes" \
        || fail matrix "verify: $(grep -m2 -E 'ERROR|DETAIL' <<<"$vout" | tr '\n' ' ' | cut -c1-300)"
fi

# ── pre_request ──────────────────────────────────────────────────────────────────
if want prerequest && [[ "$MODE" != legacy ]]; then
    echo ""
    if [[ "$MODE" == true ]]; then
        pre() {  # NAME EXPECT CLAIMS
            probe prerequest "$1" "$2" <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$3', true) \\g /dev/null
SELECT medcea_auth.pre_request();
SQL
        }
        probe prerequest "operator token -> rr_operator" ok <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$(claims operator "$UUID_OP" p-op)', true) \g /dev/null
SELECT medcea_auth.pre_request();
SELECT current_user = 'rr_operator' AS ok \gset
--CHECKS
SELECT 'CHECK|current_user is rr_operator', :'ok'::boolean;
SQL
        probe prerequest "production_manager + its operator composite -> rr_production_manager" ok <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$(claims production_manager,operator,offline_access "$UUID_PM" p-pm)', true) \g /dev/null
SELECT medcea_auth.pre_request();
SELECT current_user = 'rr_production_manager' AS ok \gset
--CHECKS
SELECT 'CHECK|current_user is rr_production_manager', :'ok'::boolean;
SQL
        pre "two own roles" "28000:two own roles" "$(claims qa,engineer "$UUID_QA" p-qa)"
        pre "no platform role" "28000:no platform role" "$(claims offline_access "$UUID_QA" p-qa)"
        pre "a client the API does not accept" "28000:may not use the API" "$(claims operator "$UUID_OP" p-op grafana)"
        pre "an ID token" "28000:not an access token" "$(claims operator "$UUID_OP" p-op config ID)"
        pre "audience missing" "28000:audience" "$(claims operator "$UUID_OP" p-op config Bearer '')"
        pre "a sub that is not a uuid" "28000:uuid" "$(claims operator not-a-uuid p-op)"
        probe prerequest "no claims at all" "28000:no token" <<'SQL'
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT medcea_auth.pre_request();
SQL
        # what PostgREST 12 really sends without a token: claims holding only the anon
        # role, never NULL (the probe above alone let a broken check pass)
        pre "no token (claims hold only role anon)" "28000:no token" '{"role":"anon"}'
        probe prerequest "no token on GET / (the readiness probe) stays anon" ok <<'SQL'
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '{"role":"anon"}', true) \g /dev/null
SELECT set_config('request.method', 'GET', true) \g /dev/null
SELECT set_config('request.path', '/', true) \g /dev/null
SELECT medcea_auth.pre_request();
SELECT current_user = 'anon' AS ok \gset
--CHECKS
SELECT 'CHECK|current_user is anon', :'ok'::boolean;
SQL
    else
        probe prerequest "false mode: pre_request() is a no-op, the role stays anon" ok <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$(claims admin "$UUID_AD" p-ad)', true) \g /dev/null
SELECT medcea_auth.pre_request();
SELECT current_user = 'anon' AS ok \gset
--CHECKS
SELECT 'CHECK|current_user is anon', :'ok'::boolean;
SQL
    fi
fi

# ── actor ────────────────────────────────────────────────────────────────────────
if want actor && [[ "$MODE" != legacy ]]; then
    echo ""
    probe actor "control: the actor store answers" ok <<'SQL'
SELECT medcea_auth.request_actor();
SQL
    probe actor "a spoofed actor table" "42501:spoofed" <<'SQL'
SET ROLE anon;
CREATE TEMPORARY TABLE medcea_actor (kind text PRIMARY KEY, sub text, person text, name text, role text,
                                     source text, ref_kind text, ref_id bigint);
INSERT INTO pg_temp.medcea_actor VALUES ('actor', '11111111-1111-4111-8111-111111111111', 'p-x', 'x', 'qa', 'token', NULL, NULL);
RESET ROLE;
SELECT medcea_auth.request_actor();
SQL
    probe actor "set_actor with a sub that is not a uuid" "22023:uuid" <<'SQL'
SELECT medcea_auth.set_actor('system:x', 'p', 'n', 'operator');
SQL
    probe actor "set_actor with an unknown role" "22023:not a platform role" <<SQL
SELECT medcea_auth.set_actor('$UUID_OP', 'p', 'n', 'superuser');
SQL
    sched_insert="INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
SELECT u.unit_id, r.recipe_id, '0 1 * * *', 'iam-db probe' FROM medcea.cea_unit u, medcea.recipe r
 WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS sid \\gset"
    if [[ "$WRITES" == true ]]; then
        if [[ "$MODE" == false ]]; then
            probe actor "svc_scheduler with forged claims is db:svc_scheduler" ok <<SQL
SET SESSION AUTHORIZATION svc_scheduler;
SELECT set_config('request.jwt.claims', '$(claims production_manager "$UUID_PM" p-pm)', true) \g /dev/null
$sched_insert
--CHECKS
SELECT 'CHECK|stamped db:svc_scheduler', created_by_sub = 'db:svc_scheduler' AND created_by_source = 'db' FROM medcea.schedule WHERE schedule_id = :sid;
SQL
        else
            probe actor "svc_scheduler with forged claims and no set_actor" "42501:no actor" <<SQL
SET SESSION AUTHORIZATION svc_scheduler;
SELECT set_config('request.jwt.claims', '$(claims production_manager "$UUID_PM" p-pm)', true) \g /dev/null
$sched_insert
SQL
            probe actor "a production manager's token is source token" ok <<SQL
$(as_token "$(claims production_manager "$UUID_PM" p-pm)")
$sched_insert
--CHECKS
SELECT 'CHECK|stamped token', created_by_sub = '$UUID_PM' AND created_by_source = 'token' AND created_by_person = 'p-pm'
  FROM medcea.schedule WHERE schedule_id = :sid;
SQL
            probe actor "svc_scheduler after set_actor is 'person via svc_scheduler'" ok <<SQL
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_actor('$UUID_PM', 'p-pm', 'test-pm', 'production_manager');
$sched_insert
--CHECKS
SELECT 'CHECK|stamped person via', created_by_source = 'person via svc_scheduler' FROM medcea.schedule WHERE schedule_id = :sid;
SQL
        fi
        if [[ "$MODE" == true ]]; then
            # rr_admin_login inherits rr_admin (no SET): pgAdmin's session can never pass for a token
            probe actor "rr_admin_login (inheriting rr_admin) with forged claims has no actor" "42501:no actor" <<SQL
SET SESSION AUTHORIZATION rr_admin_login;
SELECT set_config('request.jwt.claims', '$(claims admin "$UUID_AD" p-ad)', true) \g /dev/null
SELECT medcea.propose_setting('log_delete_days', '45');
SQL
            probe actor "rr_admin_login cannot SET ROLE rr_admin" "42501:permission denied" <<'SQL'
SET SESSION AUTHORIZATION rr_admin_login;
SET ROLE rr_admin;
SQL
        fi
    fi
fi

# ── writes ───────────────────────────────────────────────────────────────────────
if want writes && [[ "$WRITES" == true ]]; then
    echo ""
    stamped() {  # TABLE WHERE — a CHECK that the row is stamped db:authenticator and logged
        [[ "$MODE" == legacy ]] && return 0
        echo "SELECT 'CHECK|$1 stamped', created_by_sub = 'db:authenticator' FROM medcea.$1 WHERE $2;"
        echo "SELECT 'CHECK|$1 in row_change', EXISTS (SELECT 1 FROM medcea.row_change WHERE target = 'medcea.$1' AND actor_sub = 'db:authenticator');"
    }
    # W1: today's callers keep working (after apply false, and again after true -> false)
    if [[ "$MODE" == false || "$MODE" == legacy ]]; then
        probe W1 "config UI: create a location (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.cea_location (name, is_active) VALUES ('IAMT probe site', 'Y');
--CHECKS
$(stamped cea_location "name = 'IAMT probe site'")
SQL
        probe W1 "config UI: edit a unit (anon)" ok <<SQL
$(as_anon)
UPDATE medcea.cea_unit SET description = 'edited by iam-db' WHERE unit_code = 'IAMT01';
--CHECKS
$([[ "$MODE" == legacy ]] || echo "SELECT 'CHECK|updated_by', updated_by_sub = 'db:authenticator' AND created_by_sub IS DISTINCT FROM 'db:authenticator' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';")
SQL
        probe W1 "config UI: create and delete a zone (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active) SELECT unit_id, 'ZDEL', 'Y' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
DELETE FROM medcea.cea_zone WHERE zone_code = 'ZDEL';
--CHECKS
$([[ "$MODE" == legacy ]] || echo "SELECT 'CHECK|delete logged', EXISTS (SELECT 1 FROM medcea.row_change WHERE target = 'medcea.cea_zone' AND op = 'D' AND old_values ->> 'zone_code' = 'ZDEL');")
SQL
        probe W1 "config UI: component create, edit, delete (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.component (component_id, device_id, component_type, model)
SELECT nextval('medcea.component_component_id_seq'), device_id, 'SENSOR', 'iamt' FROM medcea.device WHERE dns_name = 'iamt02-s-z01';
UPDATE medcea.component SET model = 'iamt2' WHERE model = 'iamt';
DELETE FROM medcea.component WHERE model = 'iamt2';
SQL
        probe W1 "config UI: recipe and line create, edit, delete (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.recipe (recipe_name) VALUES ('IAMT probe recipe');
INSERT INTO medcea.recipe_line (recipe_id, recipe_item_seq_id, recipe_item_seq_name, cycle_number,
    air_temperature_lower_limit, air_temperature_upper_limit, light_type, light_on_minutes, light_off_minutes,
    co2_lower_limit, co2_upper_limit, hr_lower_limit, hr_upper_limit)
SELECT recipe_id, 1, 'p', 1, 18, 24, 'BLUE', 1, 1, 400, 900, 70, 90 FROM medcea.recipe WHERE recipe_name = 'IAMT probe recipe';
UPDATE medcea.recipe_line SET light_on_minutes = 2 WHERE recipe_item_seq_name = 'p';
DELETE FROM medcea.recipe_line WHERE recipe_item_seq_name = 'p';
DELETE FROM medcea.recipe WHERE recipe_name = 'IAMT probe recipe';
SQL
        probe W1 "config UI: recipe x unit upsert (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.recipe_unit_permission (recipe_id, unit_id, allowed, algorithm_params)
SELECT r.recipe_id, u.unit_id, true, '{"x": 3}' FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01'
ON CONFLICT (recipe_id, unit_id) DO UPDATE SET allowed = EXCLUDED.allowed, algorithm_params = EXCLUDED.algorithm_params;
SQL
        probe W1 "wizard: device PATCH resending the same serial keeps the credential" ok <<SQL
$(as_anon)
UPDATE medcea.device SET serial_number = serial_number, model = 'iamt-model' WHERE dns_name = 'iamt01-c-z02';
--CHECKS
SELECT 'CHECK|credential still active', active FROM medcea.mqtt_credential WHERE username = 'iamt01-c-z02';
SQL
        probe W1 "wizard: a real serial change deactivates the credential" ok <<SQL
$(as_anon)
UPDATE medcea.device SET serial_number = 'iamt-aa:bb:cc:00:00:99' WHERE dns_name = 'iamt01-c-z02';
--CHECKS
$([[ "$MODE" == legacy ]] && echo "SELECT 'CHECK|done', true;" || echo "SELECT 'CHECK|credential deactivated', NOT active FROM medcea.mqtt_credential WHERE username = 'iamt01-c-z02';")
SQL
        probe W1 "wizard: register_mqtt_credential v1 (anon)" ok <<SQL
$(as_anon)
SELECT medcea.register_mqtt_credential('iamt01-c-z02', '\$7\$101\$c2FsdA==\$aGFzaA==',
       (SELECT device_id FROM medcea.device WHERE dns_name = 'iamt01-c-z02'), 'CONTROL', 'medcea/IAMT01/Z02');
SQL
        probe W1 "scheduler (postgres): run insert, status updates, cycle upsert" ok <<'SQL'
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y' FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT02' RETURNING recipe_run_id AS run \gset
UPDATE medcea.recipe_run SET recipe_run_status = 'R', timestamp_upd = now() WHERE recipe_run_id = :run;
INSERT INTO medcea.recipe_line_cycle_run (recipe_line_cycle_run_id, recipe_run_id, recipe_id, recipe_item_seq_id,
       recipe_item_seq_cycle_num, recipe_line_cycle_run_status)
SELECT nextval('medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq'), :run, recipe_id, 1, 1, 'R'
  FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1'
ON CONFLICT (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num)
DO UPDATE SET recipe_line_cycle_run_status = 'C';
UPDATE medcea.recipe_run SET recipe_run_status = 'C', recipe_run_end = now() WHERE recipe_run_id = :run;
SQL
        probe W1 "runner (postgres): Q-table upsert and delete are events" ok <<SQL
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state, updated_at)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{"q": 1}', now() FROM medcea.cea_unit WHERE unit_code = 'IAMT01'
ON CONFLICT (unit_id, algorithm, channel) DO UPDATE SET state = EXCLUDED.state, updated_at = now();
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state, updated_at)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{"q": 2}', now() FROM medcea.cea_unit WHERE unit_code = 'IAMT01'
ON CONFLICT (unit_id, algorithm, channel) DO UPDATE SET state = EXCLUDED.state, updated_at = now();
DELETE FROM medcea.algorithm_state WHERE channel = 'iamt';
--CHECKS
$([[ "$MODE" == legacy ]] && echo "SELECT 'CHECK|done', true;" || echo "SELECT 'CHECK|created, updated, deleted', (SELECT array_agg(event ORDER BY event_id) FROM medcea.algorithm_state_event WHERE channel = 'iamt') = ARRAY['created', 'updated', 'deleted'];")
SQL
        probe W1 "scheduler (postgres): schedule insert/delete, retention '5', algorithm edit" ok <<'SQL'
INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression)
SELECT u.unit_id, r.recipe_id, '0 3 * * *' FROM medcea.cea_unit u, medcea.recipe r
 WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS sid \gset
DELETE FROM medcea.schedule WHERE schedule_id = :sid;
INSERT INTO medcea.scheduler_config (key, value) VALUES ('log_compress_days', '5')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
UPDATE medcea.control_algorithm SET default_params = '{"kp": 1.5, "ki": 0.1, "kd": 0.05}' WHERE algorithm_code = 'PID';
SQL
        probe W1 "access service (access_svc): an access request" ok <<'SQL'
SET ROLE access_svc;
INSERT INTO iam.access_request (username, email, first_name, last_name, requested_role, justification)
VALUES ('iamt-probe', 'iamt-probe@medcea.invalid', 'I', 'T', 'operator', 'iam-db probe');
SQL
        # IAM 2.7: status records are written by the decision functions only
        probe W1 "access service (access_svc): a status record written directly" "42501:user_status_history" <<'SQL'
SET ROLE access_svc;
INSERT INTO iam.user_status_history (keycloak_user_id, username, action, reason, actor)
VALUES ('00000000-0000-4000-8000-000000000000', 'iamt-probe', 'deactivated', 'probe', 'iam-db');
SQL
        probe W1 "broker sidecar (mqtt_auth): its query" ok <<'SQL'
SET ROLE mqtt_auth;
SELECT c.username, c.password_hash, c.role, c.topic_base FROM medcea.mqtt_credential c
  JOIN medcea.device d ON d.device_id = c.device_id WHERE c.active AND d.is_active = 'Y' ORDER BY c.username;
SQL
        if [[ "$MODE" != legacy ]]; then
            probe W1 "config UI: deleting a unit whose assignment has a parameter set" ok <<SQL
INSERT INTO medcea.cea_unit (unit_type, location_id, is_active, unit_code)
SELECT 'Other', location_id, 'Y', 'IAMTDEL' FROM medcea.cea_location WHERE name = 'IAMTEST site' RETURNING unit_id AS ud \gset
INSERT INTO medcea.recipe_unit_permission (recipe_id, unit_id, allowed) SELECT recipe_id, :ud, true FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1';
SET ROLE medcea_owner;
INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params)
SELECT algorithm_id, :ud, 'iamt-del', '{}' FROM medcea.control_algorithm WHERE algorithm_code = 'PID' RETURNING params_id AS pd \gset
UPDATE medcea.recipe_unit_permission SET params_id = :pd WHERE unit_id = :ud;
RESET ROLE;
$(as_anon)
DELETE FROM medcea.cea_unit WHERE unit_id = :ud;
--CHECKS
SELECT 'CHECK|set kept', EXISTS (SELECT 1 FROM medcea.unit_algorithm_params WHERE params_id = :pd);
SQL
        fi
    fi

    # W2: the always-on guards (false mode; they hold in true mode too)
    if [[ "$MODE" != legacy ]]; then
        # the writer: anon while false; in true mode anon holds nothing, so an engineer's token
        if [[ "$MODE" == true ]]; then w2_writer="$(as_token "$(claims engineer "$UUID_EN" p-en)")"; w2_who="an engineer"
        else w2_writer="$(as_anon)"; w2_who="anon"; fi
        probe W2 "control: $w2_who edits a draft recipe" ok <<SQL
$w2_writer
INSERT INTO medcea.recipe (recipe_name) VALUES ('IAMT draft') RETURNING recipe_id AS rd \gset
UPDATE medcea.recipe SET recipe_description = 'x' WHERE recipe_id = :rd;
--CHECKS
SELECT 'CHECK|still draft', status = 'draft' FROM medcea.recipe WHERE recipe_id = :rd;
SQL
        if [[ "$MODE" == false ]]; then
            probe W2 "anon sets status approved" "42501:approval function" <<SQL
$(as_anon)
INSERT INTO medcea.recipe (recipe_name) VALUES ('IAMT draft') RETURNING recipe_id AS rd \gset
UPDATE medcea.recipe SET status = 'approved' WHERE recipe_id = :rd;
SQL
            probe W2 "anon sets commissioning" "42501:commissioning" <<SQL
$(as_anon)
UPDATE medcea.cea_unit SET commissioning = true WHERE unit_code = 'IAMT01';
SQL
            probe W2 "anon retires a schedule" "42501:retired_at" <<SQL
$(as_anon)
UPDATE medcea.schedule SET retired_at = now() WHERE description LIKE 'iamtest%';
SQL
            probe W2 "anon repoints an assignment's parameter set" "42501:params_id" <<SQL
$(as_anon)
UPDATE medcea.recipe_unit_permission SET params_id = NULL
 WHERE recipe_id = (SELECT recipe_id FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1') AND params_id IS NOT NULL;
SQL
            probe W2 "anon edits an approved recipe: it is a draft again" ok <<SQL
$(as_anon)
UPDATE medcea.recipe SET recipe_description = 'changed after approval' WHERE recipe_name = 'IAMTEST-R1';
--CHECKS
SELECT 'CHECK|demoted', status = 'draft' FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1';
SQL
            probe W2 "anon edits a line of an approved recipe: the recipe is a draft again" ok <<SQL
$(as_anon)
UPDATE medcea.recipe_line SET light_on_minutes = light_on_minutes + 1 WHERE recipe_id = (SELECT recipe_id FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1');
--CHECKS
SELECT 'CHECK|parent demoted', status = 'draft' FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1';
SQL
        fi
        probe W2 "control: postgres appends an approval" ok <<'SQL'
INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, approved_by_sub)
VALUES ('medcea.recipe', '[0]', 'x', 'recipes', 'review', 'system:test');
SQL
        probe W2 "replica mode does not open the approvals to UPDATE" "42501:append-only" <<'SQL'
SET session_replication_role = replica;
UPDATE medcea.approval SET note = 'x';
SQL
        probe W2 "postgres updates the device slot history" "42501:append-only" <<'SQL'
UPDATE medcea.device_slot_history SET to_dns_name = 'x';
SQL
        probe W2 "postgres deletes a row change" "42501:append-only" <<'SQL'
DELETE FROM medcea.row_change;
SQL
    fi

    # W3: the flag alone (IAM_DB_ROLES recorded true inside the transaction)
    if [[ "$MODE" == false ]]; then
        probe W3 "control: policy_refuse() only warns while false" ok <<'SQL'
SELECT medcea_auth.policy_refuse('iam-db probe');
SQL
        probe W3 "policy_refuse() raises once the flag is true" "42501:iam-db probe" <<'SQL'
UPDATE medcea.platform_setting SET value = 'true' WHERE key = 'iam_db_roles';
SELECT medcea_auth.policy_refuse('iam-db probe');
SQL
        probe W3 "a write without an actor is refused once the flag is true" "42501:no actor" <<SQL
UPDATE medcea.platform_setting SET value = 'true' WHERE key = 'iam_db_roles';
$(as_anon)
INSERT INTO medcea.cea_location (name, is_active) VALUES ('IAMT flagged', 'Y');
SQL
    fi

    # W4: the workflow, true mode only
    if [[ "$MODE" == true ]]; then
        T_PM="$(claims production_manager "$UUID_PM" p-pm)"; T_OP="$(claims operator "$UUID_OP" p-op)"
        T_OP2="$(claims operator "$UUID_OP2" p-op2)"; T_QA="$(claims qa "$UUID_QA" p-qa)"
        T_QAOP="$(claims qa "$UUID_QA2" p-op)"     # a qa account of the operator's person
        T_QP="$(claims qp "$UUID_QP" p-qp)"; T_QPOP="$(claims qp "$UUID_QP" p-op)"
        T_EN="$(claims engineer "$UUID_EN" p-en)"; T_EN2="$(claims engineer "$UUID_EN2" p-en2)"
        T_QAEN2="$(claims qa "$UUID_QA2" p-en2)"; T_AD="$(claims admin "$UUID_AD" p-ad)"
        run_setup="
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SELECT p.params_id AS set1 FROM medcea.recipe_unit_permission p JOIN medcea.recipe r USING (recipe_id) JOIN medcea.cea_unit u USING (unit_id)
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' \\gset
$(as_token "$T_PM")
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'R', 'Y', :set1 FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' RETURNING recipe_run_id AS run \\gset"
        probe W4 "control: an operator starts a run a production manager prepared for their unit" ok <<SQL
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
--CHECKS
SELECT 'CHECK|running, executed by the operator', recipe_run_status = 'R' AND executed_by_person = 'p-op' AND created_by_role = 'production_manager'
  FROM medcea.recipe_run WHERE recipe_run_id = :run;
SQL
        probe W4 "an operator without the run's unit" "42501:not one of your units" <<SQL
$run_setup
$(as_token "$T_OP2")
SELECT medcea.start_run(:run);
SQL
        probe W4 "a parameter set of another unit" "22023:belongs to unit" <<SQL
$run_setup
$(as_postgres)
SET ROLE medcea_owner;
INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params)
SELECT algorithm_id, (SELECT unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02'), 'iamt-other-unit', '{}'
  FROM medcea.control_algorithm WHERE algorithm_code = 'IF_THEN_ELSE' RETURNING params_id AS other \gset
$(as_token "$T_PM")
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :other FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01';
SQL
        probe W4 "a parameter set of another algorithm" "22023:is for algorithm" <<SQL
$run_setup
$(as_postgres)
SET ROLE medcea_owner;
INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params)
SELECT algorithm_id, (SELECT unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT01'), 'iamt-other-alg', '{}'
  FROM medcea.control_algorithm WHERE algorithm_code = 'MPC' RETURNING params_id AS other \gset
$(as_token "$T_PM")
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :other FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01';
SQL
        probe W4 "a recipe edited behind the triggers no longer matches its approval" "42501:changed since its approval" <<SQL
$run_setup
$(as_postgres)
SET session_replication_role = replica;
UPDATE medcea.recipe SET recipe_description = 'edited behind the triggers' WHERE recipe_name = 'IAMTEST-R1';
SET session_replication_role = origin;
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
SQL
        probe W4 "an operator updates a run directly" "42501:permission denied for table recipe_run" <<SQL
$run_setup
$(as_token "$T_OP")
UPDATE medcea.recipe_run SET recipe_run_status = 'C' WHERE recipe_run_id = :run;
SQL
        # only a role past the grants reaches the trigger: postgres is not medcea_owner
        probe W4 "a direct run update that passes the grants (postgres)" "42501:regulated record" <<SQL
$run_setup
$(as_postgres)
UPDATE medcea.recipe_run SET recipe_run_status = 'C' WHERE recipe_run_id = :run;
SQL
        rerun="
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
SELECT medcea.set_run_status(:run, 'F');
$(as_token "$T_PM")
SELECT medcea.set_run_status(:run, 'S');
$(as_postgres)
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP2'::uuid, unit_id FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP';
$(as_token "$T_OP2")
SELECT medcea.start_run(:run);
$(as_postgres)
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_system_actor('system:scheduler', 'run', :run);
SELECT medcea.finish_run(:run, 'C');
$(as_postgres)
-- the stored system actor lasts the transaction (the probe is one); a release is
-- PostgREST's own transaction in real life, so clear it before the token
DELETE FROM pg_temp.medcea_actor WHERE kind = 'actor';"
        probe W4 "control: re-executed run (F -> S -> R -> C) released by an independent qp" ok <<SQL
$rerun
$(as_token "$T_QP")
SELECT medcea.release_run(:run);
--CHECKS
SELECT 'CHECK|released', EXISTS (SELECT 1 FROM medcea.run_release WHERE recipe_run_id = :run AND released_by_person = 'p-qp');
SQL
        probe W4 "the first executor of an earlier attempt cannot release" "42501:not_own_author" <<SQL
$rerun
$(as_token "$T_QPOP")
SELECT medcea.release_run(:run);
SQL
        recipe_setup="
$(as_token "$T_EN")
INSERT INTO medcea.recipe (recipe_name) VALUES ('IAMT approval probe') RETURNING recipe_id AS ra \\gset"
        probe W4 "control: qa approves an engineer's draft" ok <<SQL
$recipe_setup
$(as_token "$T_QA")
SELECT medcea.approve_recipe(:ra);
--CHECKS
SELECT 'CHECK|approved', status = 'approved' FROM medcea.recipe WHERE recipe_id = :ra;
SELECT 'CHECK|approval recorded', EXISTS (SELECT 1 FROM medcea.approval WHERE target = 'medcea.recipe' AND row_key = jsonb_build_array(:ra) AND action = 'approve' AND approved_by_person = 'p-qa');
SELECT 'CHECK|approval covers the newest change (commit order)', ap.last_change_id = (SELECT max(c.change_id) FROM medcea.row_change c WHERE c.target = 'medcea.recipe' AND c.row_key = jsonb_build_array(:ra) AND c.op = 'I') FROM medcea.approval ap WHERE ap.target = 'medcea.recipe' AND ap.row_key = jsonb_build_array(:ra) AND ap.action = 'approve';
SQL
        probe W4 "an intermediate editor approves" "42501:not_own_author" <<SQL
$recipe_setup
$(as_token "$T_EN2")
UPDATE medcea.recipe SET recipe_description = 'edited by a second engineer' WHERE recipe_id = :ra;
$(as_token "$T_QAEN2")
SELECT medcea.approve_recipe(:ra);
SQL
        probe W4 "an unattributed change blocks approval" "42501:unattributed changes" <<SQL
$recipe_setup
$(as_postgres)
UPDATE medcea.recipe SET recipe_description = 'edited by postgres' WHERE recipe_id = :ra;
$(as_token "$T_QA")
SELECT medcea.approve_recipe(:ra);
SQL
        probe W4 "an engineer edits an approved recipe" "42501:draft_only" <<SQL
$(as_token "$T_EN")
UPDATE medcea.recipe SET recipe_description = 'x' WHERE recipe_name = 'IAMTEST-R1';
SQL
        probe W4 "a production manager edits a recipe (assign_only)" "42501:permission denied" <<SQL
$(as_token "$T_PM")
UPDATE medcea.recipe SET recipe_description = 'x' WHERE recipe_name = 'IAMTEST-R1';
SQL
        probe W4 "control: svc_scheduler writes a new Q-table state" ok <<SQL
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{"q": 1}' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SET ROLE medcea_owner;
UPDATE medcea.algorithm_state SET retired_at = now() WHERE channel = 'iamt';
RESET ROLE;
SET SESSION AUTHORIZATION svc_scheduler;
UPDATE medcea.algorithm_state SET state = '{"q": 2}', updated_at = now() WHERE channel = 'iamt';
--CHECKS
SELECT 'CHECK|unretired by the new state', retired_at IS NULL FROM medcea.algorithm_state WHERE channel = 'iamt';
SELECT 'CHECK|logged unretired', EXISTS (SELECT 1 FROM medcea.algorithm_state_event WHERE channel = 'iamt' AND event = 'unretired');
SQL
        probe W4 "svc_scheduler clears retired_at alone" "42501:only the scheduler's state writes" <<SQL
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{"q": 1}' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SET ROLE medcea_owner;
UPDATE medcea.algorithm_state SET retired_at = now() WHERE channel = 'iamt';
RESET ROLE;
SET SESSION AUTHORIZATION svc_scheduler;
UPDATE medcea.algorithm_state SET retired_at = NULL WHERE channel = 'iamt';
SQL
        # IAM 2.6: a Q-table is retired only through PostgREST by qa (the scheduler's
        # DELETE routes are gone)
        qstate="
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{\"q\": 1}' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';"
        probe W4 "control: qa retires a Q-table through PostgREST" ok <<SQL
$qstate
$(as_token "$T_QA")
SELECT medcea.retire_algorithm_state(unit_id, 'Q_LEARNING', 'iam-db probe') FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
--CHECKS
SELECT 'CHECK|retired, not deleted', retired_at IS NOT NULL FROM medcea.algorithm_state WHERE channel = 'iamt';
SELECT 'CHECK|retired event with the reason', EXISTS (SELECT 1 FROM medcea.algorithm_state_event WHERE channel = 'iamt' AND event = 'retired' AND reason = 'iam-db probe');
SELECT 'CHECK|approval by a token', EXISTS (SELECT 1 FROM medcea.approval WHERE target = 'medcea.algorithm_state' AND action = 'retire' AND row_key ->> 2 = 'iamt' AND approved_by_source = 'token');
SQL
        probe W4 "an engineer token cannot retire a Q-table" "42501:permission denied" <<SQL
$qstate
$(as_token "$T_EN")
SELECT medcea.retire_algorithm_state(unit_id, 'Q_LEARNING', 'iam-db probe') FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SQL
        probe W4 "svc_scheduler cannot retire a Q-table (no EXECUTE; set_actor is no token)" "42501:permission denied" <<SQL
$qstate
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea.retire_algorithm_state(unit_id, 'Q_LEARNING', 'iam-db probe') FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SQL
        retention() {  # VALUE EXPECT
            probe W4 "approve_change: log_delete_days = $1" "$2" <<SQL
$(as_token "$T_AD")
SELECT medcea.propose_setting('log_delete_days', '"$1"') AS chg \gset
$(as_token "$T_QA")
SELECT medcea.approve_change('medcea.pending_change', :chg, 'iam-db probe');
SQL
        }
        retention 30 ok
        retention 29 "42501:retention"
        # RLS (own_unit): every compiled reader of the four RLS tables sees every row;
        # only rr_operator is filtered, to the units in iam_policy.user_unit.
        # run_full: a run of IAMT01 with a cycle and a release, so no RLS table is empty
        # (an empty table passes every count check whatever the policy says)
        run_full="
SELECT recipe_id AS r1 FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1' \\gset
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
$(as_postgres)
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_system_actor('system:scheduler', 'run', :run);
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'R', 'run_params', '[{\"x\": 1}]'::jsonb));
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'C', 'end', now()));
SELECT medcea.finish_run(:run, 'C');
$(as_postgres)
DELETE FROM pg_temp.medcea_actor WHERE kind = 'actor';
$(as_token "$T_QP")
SELECT medcea.release_run(:run);
$(as_postgres)"
        for obj in medcea.measurement medcea.recipe_run medcea.recipe_line_cycle_run medcea.run_release; do
            for r in $(python3 "$CLI" compile grants --format json "${IAM_FLAG[@]}" | OBJ="$obj" python3 -c '
import json, os, sys
d = json.load(sys.stdin)
print(" ".join(sorted({g for g, k, o, p in d["privileges"] if o == os.environ["OBJ"] and p == "SELECT"})))'); do
                [[ "$r" == rr_operator ]] && continue
                probe RLS "$r sees every row of $obj" ok <<SQL
$run_full
SELECT count(*) AS total FROM $obj \gset
SET ROLE $r;
SELECT count(*) AS seen FROM $obj \gset
--CHECKS
SELECT 'CHECK|unfiltered (' || :seen || ' of ' || :total || ')', :seen = :total AND :total > 0;
SQL
            done
        done
        probe RLS "rr_operator sees only its units' telemetry" ok <<SQL
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
SELECT count(*) AS total, count(*) FILTER (WHERE zone_id IN (SELECT z.zone_id FROM medcea.cea_zone z JOIN medcea.cea_unit u USING (unit_id)
       WHERE u.unit_code = 'IAMT02')) AS mine FROM medcea.measurement \gset
$(as_token "$T_OP")
SELECT count(*) AS seen FROM medcea.measurement \gset
--CHECKS
SELECT 'CHECK|filtered (' || :seen || ' of ' || :total || ')', :seen = :mine AND :seen < :total;
SQL
        probe RLS "a zone added to an assigned unit is visible" ok <<SQL
SELECT medcea_auth._set_internal_actor('system:iam-db') \g /dev/null
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active) SELECT unit_id, 'ZNEW', 'Y' FROM medcea.cea_unit
 WHERE unit_code = 'IAMT02' RETURNING zone_id AS newz \gset
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
-- the internal actor that created the zone outranks the token's claims for this transaction
DELETE FROM pg_temp.medcea_actor WHERE kind = 'actor';
$(as_token "$T_OP")
SELECT :newz = ANY (medcea_auth.my_zones()) AS sees \gset
--CHECKS
SELECT 'CHECK|my_zones() has the new zone', :'sees'::boolean;
SQL
        # cross-unit: the second operator holds IAMT02, so my_units() is not empty and
        # only the policy expressions keep IAMT01's run, cycles and release from them
        probe RLS "rr_operator sees only its units' runs" ok <<SQL
$run_full
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP2'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
$(as_token "$T_OP")
SELECT (SELECT count(*) FROM medcea.recipe_run WHERE recipe_run_id = :run) AS own_run,
       (SELECT count(*) FROM medcea.recipe_line_cycle_run WHERE recipe_run_id = :run) AS own_cyc,
       (SELECT count(*) FROM medcea.run_release WHERE recipe_run_id = :run) AS own_rel,
       (SELECT count(*) FROM medcea.run_history WHERE recipe_run_id = :run) AS own_hist \gset
$(as_token "$T_OP2")
SELECT (SELECT count(*) FROM medcea.recipe_run WHERE recipe_run_id = :run) AS o_run,
       (SELECT count(*) FROM medcea.recipe_line_cycle_run WHERE recipe_run_id = :run) AS o_cyc,
       (SELECT count(*) FROM medcea.run_release WHERE recipe_run_id = :run) AS o_rel,
       (SELECT count(*) FROM medcea.run_history WHERE recipe_run_id = :run) AS o_hist,
       medcea_auth.my_units() <> '{}' AS o_has_unit \gset
$(as_token "$T_PM")
SELECT count(*) AS pm FROM medcea.recipe_run WHERE recipe_run_id = :run \gset
--CHECKS
SELECT 'CHECK|the operator of IAMT01 sees its run, cycles, release and history (' || :own_run || '/' || :own_cyc || '/' || :own_rel || '/' || :own_hist || ')',
       :own_run = 1 AND :own_cyc > 0 AND :own_rel = 1 AND :own_hist > 0;
SELECT 'CHECK|the second operator holds a unit', :'o_has_unit'::boolean;
SELECT 'CHECK|the operator of IAMT02 sees none of them (' || :o_run || '/' || :o_cyc || '/' || :o_rel || '/' || :o_hist || ')',
       :o_run = 0 AND :o_cyc = 0 AND :o_rel = 0 AND :o_hist = 0;
SELECT 'CHECK|the production manager sees it', :pm = 1;
SQL
        # IAM 2.6: the Monitor's and the scheduler's own_unit SQL (svc_* read through
        # permissive policies, so the services filter with a subquery on user_unit) returns
        # exactly what rr_operator's RLS returns: runs, cycles, and the measurements of the
        # unit's zones by their current unit (the seed's board moved IAMT01/Z01 -> IAMT02/Z01)
        own_runs="(SELECT uu.unit_id FROM iam_policy.user_unit uu WHERE uu.person_sub = '$UUID_OP'::uuid)"
        own_zones="(SELECT cz.zone_id FROM medcea.cea_zone cz JOIN iam_policy.user_unit uu ON uu.unit_id = cz.unit_id WHERE uu.person_sub = '$UUID_OP'::uuid)"
        rows_digest() {  # VAR FROM-AND-WHERE: \gset VAR to the md5 of the sorted rows / their count
            echo "SELECT md5(coalesce(string_agg(x, ',' ORDER BY x), '')) || '/' || count(*) AS $1 FROM (SELECT md5(t::text) AS x FROM $2) s \\gset"
        }
        probe RLS "the services' own_unit SQL returns what rr_operator's RLS returns" ok <<SQL
$run_full
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
SET SESSION AUTHORIZATION svc_monitor;
$(rows_digest s_run "medcea.recipe_run t WHERE t.unit_id IN $own_runs")
$(rows_digest s_meas "medcea.measurement t WHERE t.zone_id IN $own_zones")
$(as_postgres)
SET SESSION AUTHORIZATION svc_scheduler;
$(rows_digest s_cyc "medcea.recipe_line_cycle_run t WHERE t.recipe_run_id IN (SELECT x.recipe_run_id FROM medcea.recipe_run x WHERE x.unit_id IN $own_runs)")
$(as_token "$T_OP")
$(rows_digest o_run "medcea.recipe_run t")
$(rows_digest o_meas "medcea.measurement t")
$(rows_digest o_cyc "medcea.recipe_line_cycle_run t")
--CHECKS
SELECT 'CHECK|runs (' || :'s_run' || ')', :'s_run' = :'o_run' AND :'s_run' NOT LIKE '%/0';
SELECT 'CHECK|measurements (' || :'s_meas' || ')', :'s_meas' = :'o_meas' AND :'s_meas' NOT LIKE '%/0';
SELECT 'CHECK|cycles (' || :'s_cyc' || ')', :'s_cyc' = :'o_cyc' AND :'s_cyc' NOT LIKE '%/0';
SQL
        # start_run/set_run_status are SECURITY DEFINER (past the RLS): a run of another
        # unit and a run that does not exist get the same refusal, before any status check
        hidden="
$run_full
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP2'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
$(as_token "$T_OP2")"
        probe W4 "start_run on another unit's completed run says only 'not one of your units'" "42501:not one of your units" <<SQL
$hidden
SELECT medcea.start_run(:run);
SQL
        probe W4 "set_run_status on another unit's run says only 'not one of your units'" "42501:not one of your units" <<SQL
$hidden
SELECT medcea.set_run_status(:run, 'X');
SQL
        probe W4 "start_run on a run that does not exist says the same" "42501:not one of your units" <<SQL
$hidden
SELECT medcea.start_run(2147483000);
SQL
        probe W4 "set_run_status on a run that does not exist says the same" "42501:not one of your units" <<SQL
$hidden
SELECT medcea.set_run_status(2147483000, 'F');
SQL
    fi

    # W5: register_mqtt_credential v2 (as an engineer's role; every refusal structural)
    if [[ "$MODE" != legacy ]]; then
        reg() {  # NAME EXPECT DEVICE_DNS SERIAL [HASH]
            local h="${5:-\$7\$101\$c2FsdA==\$aGFzaA==}"
            probe W5 "$1" "$2" <<SQL
SET ROLE rr_engineer;
SELECT medcea.register_mqtt_credential((SELECT device_id FROM medcea.device WHERE dns_name = '$3'), '$4', '$h');
SQL
        }
        reg "control: the board's own serial" ok iamt02-s-z01 iamt-aa:bb:cc:00:00:01
        reg "another board's serial" "42501:is not device" iamt02-s-z01 iamt-aa:bb:cc:00:00:02
        probe W5 "a unit code that is not a topic segment" "22023:cannot be a topic segment" <<SQL
INSERT INTO medcea.device (zone_id, device_type, serial_number, dns_name, is_active)
SELECT z.zone_id, 'SENSE', 'iamt-wild', 'iamt-wild', 'Y' FROM medcea.cea_zone z JOIN medcea.cea_unit u USING (unit_id) WHERE u.unit_code = 'IAM+04';
SET ROLE rr_engineer;
SELECT medcea.register_mqtt_credential((SELECT device_id FROM medcea.device WHERE dns_name = 'iamt-wild'), 'iamt-wild', '\$7\$101\$c2FsdA==\$aGFzaA==');
SQL
        reg "a password instead of a hash" "22023:mosquitto" iamt02-s-z01 iamt-aa:bb:cc:00:00:01 not-a-hash
    fi
    # W6: the scheduler's functions and fixes (IAM plan 2.4): retire_schedule and the
    # retired-row guard, set_system_actor's re-save fallback, record_cycle never
    # reopening a completed cycle, the schedule's algorithm in _check_run_params, the
    # internal actor out of a service's reach; and (false) the SQL of the scheduler
    # before 2.4 (e97aab6) still working against this database
    if [[ "$MODE" != legacy ]]; then
        S1="(SELECT schedule_id FROM medcea.schedule WHERE description LIKE 'iamtest: inherits the assignment%')"
        S2="(SELECT schedule_id FROM medcea.schedule WHERE description = 'iamtest: algorithm differs from the assignment')"
        UNVERIFIED="SELECT medcea_auth._set_internal_actor('system:scheduler-unverified');"
        PM_ACTOR="SELECT medcea_auth.set_actor('$UUID_PM', 'p-pm', 'test-pm', 'production_manager');"
        W6_PM="$(claims production_manager "$UUID_PM" p-pm)"
        # who retires in the probes below: retire_schedule checks U on schedules, which
        # an internal actor (no role) passes only as a WARNING while false
        if [[ "$MODE" == true ]]; then RETIRER="$PM_ACTOR"; RETIRER_SUB="$UUID_PM"
        else RETIRER="$UNVERIFIED"; RETIRER_SUB="system:scheduler-unverified"; fi
        probe W6 "retire_schedule without an actor" "42501:no actor" <<SQL
SELECT medcea.retire_schedule($S1);
SQL
        probe W6 "control: retire_schedule keeps the schedule, disabled" ok <<SQL
$RETIRER
SELECT medcea.retire_schedule($S1);
--CHECKS
SELECT 'CHECK|retired and disabled', retired_at IS NOT NULL AND NOT enabled FROM medcea.schedule WHERE schedule_id = $S1;
SELECT 'CHECK|logged as the actor', EXISTS (SELECT 1 FROM medcea.row_change WHERE target = 'medcea.schedule'
       AND row_key = jsonb_build_array($S1) AND actor_sub = '$RETIRER_SUB' AND new_values ? 'enabled');
SQL
        probe W6 "retire_schedule twice" "22023:already retired" <<SQL
$RETIRER
SELECT medcea.retire_schedule($S1);
SELECT medcea.retire_schedule($S1);
SQL
        probe W6 "retire_schedule of a missing schedule" "22023:no schedule" <<SQL
$RETIRER
SELECT medcea.retire_schedule(-1);
SQL
        # retire_schedule checks the actor's role: an operator holds R on schedules only
        if [[ "$MODE" == true ]]; then
            probe W6 "an operator retires a schedule (U on schedules)" "42501:holds no U on schedules" <<SQL
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_actor('$UUID_OP', 'p-op', 'test-op', 'operator');
SELECT medcea.retire_schedule($S1);
SQL
        else
            probe W6 "an operator retires a schedule: a WARNING while false" ok <<SQL
SELECT medcea_auth.set_actor('$UUID_OP', 'p-op', 'test-op', 'operator');
SELECT medcea.retire_schedule($S1);
--CHECKS
SELECT 'CHECK|retired (advisory refusal only)', retired_at IS NOT NULL FROM medcea.schedule WHERE schedule_id = $S1;
SQL
        fi
        if [[ "$MODE" == true ]]; then
            probe W6 "svc_scheduler edits a retired schedule (T6)" "42501:is retired" <<SQL
$RETIRER
SELECT medcea.retire_schedule($S1);
SET SESSION AUTHORIZATION svc_scheduler;
$PM_ACTOR
UPDATE medcea.schedule SET enabled = true WHERE schedule_id = $S1;
SQL
        else
            probe W6 "postgres edits a retired schedule (T6)" "42501:is retired" <<SQL
$UNVERIFIED
SELECT medcea.retire_schedule($S1);
UPDATE medcea.schedule SET enabled = true WHERE schedule_id = $S1;
SQL
        fi
        probe W6 "set_system_actor: a migration:008 schedule nobody re-saved" "42501:no person-attributed creator" <<SQL
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', $S1);
SQL
        probe W6 "control: re-saved by a production manager, it fires as that person" ok <<SQL
$PM_ACTOR
UPDATE medcea.schedule SET description = description || ' (re-saved)' WHERE schedule_id = $S1;
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', $S1);
--CHECKS
SELECT 'CHECK|acts as the re-saving production manager', a.person = 'p-pm' AND a.role = 'production_manager' AND a.source = 'system'
  FROM medcea_auth.request_actor() a;
SQL
        probe W6 "re-saved by a role without C on runs (S6)" "42501:no person-attributed creator" <<SQL
SELECT medcea_auth.set_actor('$UUID_OP', 'p-op', 'test-op', 'operator');
UPDATE medcea.schedule SET description = description || ' (re-saved)' WHERE schedule_id = $S1;
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', $S1);
SQL
        probe W6 "re-saved by a system actor carrying a person (S6)" "42501:no person-attributed creator" <<SQL
$PM_ACTOR
INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
SELECT u.unit_id, r.recipe_id, '0 4 * * *', 'iamtest: W6 pm schedule' FROM medcea.cea_unit u, medcea.recipe r
 WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS spm \gset
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', :spm);
UPDATE medcea.schedule SET description = description || ' (re-saved)' WHERE schedule_id = $S1;
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', $S1);
SQL
        probe W6 "a service sets the IAM_DB_ROLES setting, then the internal actor (S8)" "42501:permission denied" <<'SQL'
SET SESSION AUTHORIZATION svc_scheduler;
SET medcea.iam_db_roles = 'false';
SELECT medcea_auth._set_internal_actor('system:scheduler');
SQL
        # a run in R on IAMT01 for the cycle probes: false as postgres with the
        # unverified actor; true created by a production manager's token and run by
        # svc_scheduler acting for it
        if [[ "$MODE" == true ]]; then
            cyc_setup="
SELECT p.params_id AS set1 FROM medcea.recipe_unit_permission p JOIN medcea.recipe r USING (recipe_id) JOIN medcea.cea_unit u USING (unit_id)
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' \\gset
$(as_token "$W6_PM")
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :set1 FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' RETURNING recipe_run_id AS run \\gset
SELECT medcea.start_run(:run);
$(as_postgres)
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_system_actor('system:scheduler', 'run', :run);"
        else
            cyc_setup="
$UNVERIFIED
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y' FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' RETURNING recipe_run_id AS run \\gset
SELECT medcea.start_run(:run);"
        fi
        cyc="SELECT recipe_id AS r1 FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1' \\gset
$cyc_setup
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'R', 'run_params', '[{\"x\": 1}]'::jsonb));
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'C', 'end', now()));"
        probe W6 "control: a cycle recorded R, then C" ok <<SQL
$cyc
--CHECKS
SELECT 'CHECK|completed, run_params a list', recipe_line_cycle_run_status = 'C' AND json_typeof(run_params) = 'array'
  FROM medcea.recipe_line_cycle_run WHERE recipe_run_id = :run;
SQL
        probe W6 "a completed cycle is not reopened (S7)" "22023:is complete" <<SQL
$cyc
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'R'));
SQL
        # B1: a run triggered by a schedule runs the schedule's algorithm (S2: FLC, while
        # its assignment says PID); the same set on a run without the schedule is refused
        if [[ "$MODE" == true ]]; then b1_writer="$(as_token "$W6_PM")"; else b1_writer="$UNVERIFIED"; fi
        b1="SELECT params_id AS s2set FROM medcea.schedule WHERE schedule_id = $S2 \\gset
SELECT $S2 AS s2 \\gset
$b1_writer"
        probe W6 "control: a schedule's run with the schedule's parameter set starts (B1)" ok <<SQL
$b1
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id, schedule_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :s2set, :s2 FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT02' RETURNING recipe_run_id AS run \gset
SELECT medcea.start_run(:run);
--CHECKS
SELECT 'CHECK|running', recipe_run_status = 'R' FROM medcea.recipe_run WHERE recipe_run_id = :run;
SQL
        probe W6 "the schedule's set on a run without the schedule (B1)" "22023:is for algorithm" <<SQL
$b1
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :s2set FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT02' RETURNING recipe_run_id AS run \gset
SELECT medcea.start_run(:run);
SQL
        if [[ "$MODE" == false ]]; then
            # T1: what the scheduler of e97aab6 sends, as postgres without an actor
            probe W6 "legacy scheduler (e97aab6): schedule PUT with inline parameters" ok <<SQL
UPDATE medcea.schedule
SET unit_id=unit_id, recipe_id=recipe_id, cron_expression='0 5 * * *', enabled=true, description=description,
    algorithm_id=NULL, algorithm_params='{"x": 2}'::jsonb, timestamp_upd=CURRENT_TIMESTAMP
WHERE schedule_id=$S1;
--CHECKS
SELECT 'CHECK|stamped db:postgres', updated_by_sub = 'db:postgres' FROM medcea.schedule WHERE schedule_id = $S1;
SQL
            # B4: the deploy-time listing uses set_system_actor()'s predicate, so a
            # schedule written without an actor (db:postgres) is listed, and one
            # re-saved by a production manager's token is not (rolled back)
            b4_sql="$(awk '/^-- ── B4 \(listing\)/,/^END \$\$;/' "$REPO_ROOT/apps/database/medcea_db_migrations.sql")"
            b4_out="$({
                echo "BEGIN;"
                echo "INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
                      SELECT u.unit_id, r.recipe_id, '0 6 * * *', 'iamtest: B4 db:postgres' FROM medcea.cea_unit u, medcea.recipe r
                       WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS sb4 \\gset"
                echo "$PM_ACTOR"
                echo "INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
                      SELECT u.unit_id, r.recipe_id, '0 7 * * *', 'iamtest: B4 by a person' FROM medcea.cea_unit u, medcea.recipe r
                       WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS spm4 \\gset"
                echo "$b4_sql"
                echo "SELECT 'B4IDS|' || :sb4 || '|' || :spm4;"
                echo "ROLLBACK;"
            } | db rw)"
            IFS='|' read -r _ b4_db b4_pm <<<"$(grep -m1 '^B4IDS|' <<<"$b4_out")"
            b4_warn="$(grep -m1 'schedules with no person behind them' <<<"$b4_out")"
            if [[ -z "$b4_db" || -z "$b4_sql" ]]; then
                fail W6 "B4 listing: setup failed: $(grep -m1 ERROR <<<"$b4_out")"
            elif [[ "$b4_warn" == *"$b4_db (db:postgres)"* && "$b4_warn" != *"$b4_pm ("* ]]; then
                pass W6 "B4 listing names a db:postgres schedule, not a person's"
            else
                fail W6 "B4 listing: want $b4_db (db:postgres) and not $b4_pm in: ${b4_warn:-no warning}"
            fi
            # T6 survives a revert: the migration file before 2.4 re-creates
            # guard_control_columns() (without the check) on every deploy
            prev_guard="$(git -C "$REPO_ROOT" show e97aab6:apps/database/medcea_db_migrations.sql 2>/dev/null \
              | awk '/^CREATE OR REPLACE FUNCTION medcea.guard_control_columns\(\)/,/^END \$\$;/')"
            if [[ "$prev_guard" != *"END \$\$;"* ]]; then
                fail W6 "retired-row guard after a revert: e97aab6's guard_control_columns() not found in git"
            else
                probe W6 "retired-row guard after e97aab6's guard_control_columns()" "42501:is retired" <<SQL
$prev_guard
$UNVERIFIED
SELECT medcea.retire_schedule($S1);
UPDATE medcea.schedule SET enabled = true WHERE schedule_id = $S1;
SQL
            fi
            probe W6 "legacy scheduler (e97aab6): PUT on a schedule retired since" "42501:is retired" <<SQL
$UNVERIFIED
SELECT medcea.retire_schedule($S1);
UPDATE medcea.schedule
SET unit_id=unit_id, recipe_id=recipe_id, cron_expression='0 5 * * *', enabled=true, description=description,
    algorithm_id=NULL, algorithm_params=NULL, timestamp_upd=CURRENT_TIMESTAMP
WHERE schedule_id=$S1;
SQL
            probe W6 "legacy scheduler (e97aab6): run, stop (F) and startup recovery" ok <<'SQL'
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
SELECT r.recipe_id, u.unit_id, CURRENT_TIMESTAMP, 'S', 'Y' FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT02' RETURNING recipe_run_id AS run \gset
UPDATE medcea.recipe_run SET recipe_run_status = 'R', timestamp_upd = now() WHERE recipe_run_id = :run;
UPDATE medcea.recipe_run SET recipe_run_status = 'F', timestamp_upd = now() WHERE recipe_run_id = :run;
UPDATE medcea.recipe_run SET recipe_run_end = CURRENT_TIMESTAMP WHERE recipe_run_id = :run;
UPDATE medcea.recipe_run SET recipe_run_status='S', recipe_run_end=NULL, timestamp_upd=CURRENT_TIMESTAMP WHERE recipe_run_id=:run;
UPDATE medcea.recipe_run SET recipe_run_status='F', recipe_run_end=CURRENT_TIMESTAMP, timestamp_upd=CURRENT_TIMESTAMP
 WHERE recipe_run_id=:run AND recipe_run_status IN ('R','S');
--CHECKS
SELECT 'CHECK|failed, never executed by anyone', recipe_run_status = 'F' AND executed_by_sub IS NULL FROM medcea.recipe_run WHERE recipe_run_id = :run;
SQL
        fi
    fi
    # W7: unit assignments (IAM 2.8): apps/iam/units.sql as apps/iam/units.sh runs it
    # (as postgres, one transaction): assign waits for qa (iam.confirm_decision inserts the
    # row, access section D8), --bootstrap and remove write iam_policy.user_unit, and no
    # person may write it directly
    if [[ "$MODE" != legacy ]]; then
        UNITS_SQL="$(cat "$REPO_ROOT/apps/iam/units.sql")"
        units_vars() {  # ASSIGN [BOOTSTRAP]
            cat <<SQL
SELECT unit_id AS uid FROM medcea.cea_unit WHERE unit_code = 'IAMT01' \gset
\set assign $1
\set bootstrap ${2:-false}
\set sub '$UUID_OP'
\set username test-op
\set person p-op
\set units :uid
\set reason 'iam-db probe'
\set by_sub '$UUID_AD'
\set by_person p-ad
\set by_name test-ad
SQL
        }
        probe W7 "an operator cannot write user_unit" "42501:permission denied" <<SQL
$(as_token "$(claims operator "$UUID_OP" p-op)")
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, 1;
SQL
        probe W7 "units.sql assign: decision pending_qa, not in effect, no chain event; a re-run writes nothing" ok <<SQL
$(units_vars true)
$UNITS_SQL
$UNITS_SQL
--CHECKS
SELECT 'CHECK|not assigned (waits for qa)', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP' AND unit_id = :uid);
SELECT 'CHECK|one pending_qa unit_assign by system:deploy (by the --by person, IAM 2.7)', count(*) = 1
          AND bool_and(widens AND status = 'pending_qa' AND made_by_name = 'system:deploy (by test-ad)'
                       AND made_by_sub = '$UUID_AD' AND made_by_person = 'p-ad'
                       AND unit_id = :uid AND subject_person = 'p-op' AND checked_at IS NULL)
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_assign';
SELECT 'CHECK|no unit_assigned event', NOT EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'unit_assigned' AND payload ->> 'person_sub' = '$UUID_OP');
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W7 "units.sql assign --bootstrap: in effect, decision pending_qa, chain event; a re-run writes nothing" ok <<SQL
$(units_vars true true)
$UNITS_SQL
$UNITS_SQL
--CHECKS
SELECT 'CHECK|assigned', EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP' AND unit_id = :uid);
SELECT 'CHECK|one pending_qa unit_assign by system:deploy (bootstrap, by the --by person)', count(*) = 1
          AND bool_and(widens AND status = 'pending_qa' AND made_by_name = 'system:deploy (bootstrap, by test-ad)'
                       AND made_by_sub = '$UUID_AD' AND made_by_person = 'p-ad'
                       AND unit_id = :uid AND subject_person = 'p-op' AND checked_at IS NULL)
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_assign';
SELECT 'CHECK|latest chain event unit_assigned by system:deploy', event = 'unit_assigned' AND actor_name = 'system:deploy'
          AND payload ->> 'person_sub' = '$UUID_OP'
  FROM iam_policy.history ORDER BY event_id DESC LIMIT 1;
SELECT 'CHECK|one unit_assigned event', count(*) = 1 FROM iam_policy.history
 WHERE event = 'unit_assigned' AND payload ->> 'person_sub' = '$UUID_OP';
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W7 "units.sql assign --bootstrap while an assignment waits: nothing written" ok <<SQL
$(units_vars true)
$UNITS_SQL
\set bootstrap true
$UNITS_SQL
--CHECKS
SELECT 'CHECK|not assigned', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP' AND unit_id = :uid);
SELECT 'CHECK|still one unit_assign, not a bootstrap one', count(*) = 1 AND bool_and(made_by_name = 'system:deploy (by test-ad)')
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_assign';
SQL
        probe W7 "units.sql remove: applied at once; a second remove writes nothing" ok <<SQL
$(units_vars true true)
$UNITS_SQL
\set assign false
\set bootstrap false
$UNITS_SQL
$UNITS_SQL
--CHECKS
SELECT 'CHECK|removed', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP' AND unit_id = :uid);
SELECT 'CHECK|one applied unit_remove', count(*) = 1 AND bool_and(NOT widens AND status = 'applied' AND unit_id = :uid)
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_remove';
SELECT 'CHECK|one unit_removed event', count(*) = 1 FROM iam_policy.history
 WHERE event = 'unit_removed' AND payload ->> 'person_sub' = '$UUID_OP';
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W7 "units.sql remove of a waiting assignment: withdrawn and chained; a second remove writes nothing" ok <<SQL
$(units_vars true)
$UNITS_SQL
\set assign false
$UNITS_SQL
$UNITS_SQL
DO \$\$ BEGIN IF current_user <> 'postgres' THEN RAISE EXCEPTION 'units.sql left the role at %', current_user; END IF; END \$\$;
--CHECKS
SELECT 'CHECK|withdrawn by the --by person', count(*) = 1
          AND bool_and(status = 'withdrawn' AND withdrawn_by_sub = '$UUID_AD' AND withdrawn_by_person = 'p-ad'
                       AND withdrawn_by_name = 'system:deploy (by test-ad)' AND withdraw_reason = 'iam-db probe'
                       AND withdrawn_at IS NOT NULL AND checked_at IS NULL)
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_assign';
SELECT 'CHECK|no unit_remove decision', NOT EXISTS (SELECT 1 FROM iam.account_decision
        WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_remove');
SELECT 'CHECK|one account_decision_withdrawn event by system:deploy', count(*) = 1 AND bool_and(actor_name = 'system:deploy')
  FROM iam_policy.history WHERE event = 'account_decision_withdrawn' AND payload ->> 'keycloak_user_id' = '$UUID_OP'
   AND (payload ->> 'unit_id')::int = :uid;
SELECT 'CHECK|no unit event', NOT EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event IN ('unit_assigned', 'unit_removed') AND payload ->> 'person_sub' = '$UUID_OP');
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W7 "a unit decision is final: UPDATE" "42501:may be added" <<SQL
$(units_vars true)
$UNITS_SQL
UPDATE iam.account_decision SET reason = 'x' WHERE kind = 'unit_assign';
SQL
        probe W7 "a unit decision is final: DELETE" "42501:append-only: DELETE refused" <<SQL
$(units_vars true)
$UNITS_SQL
DELETE FROM iam.account_decision WHERE kind = 'unit_assign';
SQL
    fi
elif want writes; then
    note writes "skipped (read-only; --write-probes runs them on medcea-iamtest only)"
fi

# ── access ───────────────────────────────────────────────────────────────────────
# IAM 2.7: the account decision functions in schema iam (D1-D18 of the spec, 8.2), as
# access-api runs them: SET SESSION AUTHORIZATION access_svc (session_user access_svc,
# so set_actor records 'person via access_svc'), then set_actor for the person of the
# token. Fresh accounts and persons each run: A (admin), Q and Q2 (qa), S (the subject).
if want access && [[ "$WRITES" == true && "$MODE" != legacy ]]; then
    echo ""
    _u() { python3 -c 'import uuid; print(uuid.uuid4())'; }
    A="$(_u)"; Q="$(_u)"; Q2="$(_u)"; S="$(_u)"; X="$(_u)"
    _h="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
    PA="p-a-$_h"; PQ="p-q-$_h"; PQ2="p-q2-$_h"; PS="p-s-$_h"; PX="p-x-$_h"
    ATTEST='attest: I did not run units.sh for this assignment.'
    sqlq() { if [[ -n "${1:-}" ]]; then printf "'%s'" "${1//\'/\'\'}"; else printf 'NULL'; fi; }
    # as_um SUB PERSON NAME ROLE — the User Manager acting for that person
    as_um() {
        printf 'RESET ROLE;\nRESET SESSION AUTHORIZATION;\nSET SESSION AUTHORIZATION access_svc;\n'
        echo "SELECT medcea_auth.set_actor('$1', $(sqlq "$2"), '$3', '$4') \\g /dev/null"
    }
    um_admin() { as_um "$A" "$PA" test-a admin; }
    um_qa()    { as_um "$Q" "$PQ" test-q qa; }
    um_qa2()   { as_um "$Q2" "$PQ2" test-q2 qa; }
    # rec VAR KIND FROM TO [NEW_PERSON_ID] — record_decision on S; sets :VAR, :VAR_st, :VAR_nw, :VAR_wd
    rec() {
        echo "SELECT decision_id AS $1, status AS ${1}_st, jsonb_array_length(widening) AS ${1}_nw, withdrawn AS ${1}_wd
  FROM iam.record_decision('$2', '$S', 'test-s', '$PS', $(sqlq "$3"), $(sqlq "$4"), $(sqlq "${5:-}"), 'iam-db probe', NULL) \\gset"
    }
    pending_d1() { um_admin; rec d1 role_change operator production_manager; }   # D1's row
    unit_id_sql="SELECT unit_id AS uid FROM medcea.cea_unit WHERE unit_code = 'IAMT01' \\gset"
    UNITS_SQL="$(cat "$REPO_ROOT/apps/iam/units.sql")"
    # units BY_SUB BY_PERSON BY_NAME ASSIGN [BOOTSTRAP] — apps/iam/units.sql on S's unit IAMT01, as postgres
    units() {
        as_postgres
        cat <<SQL
\\set assign $4
\\set bootstrap ${5:-false}
\\set sub '$S'
\\set username test-s
\\set person '$PS'
\\set units :uid
\\set reason 'iam-db probe'
\\set by_sub '$1'
\\set by_person '$2'
\\set by_name $3
$UNITS_SQL
SQL
    }
    # a bootstrap unit_assign written by postgres: no maker, and no subject person
    bootstrap_row() {
        as_postgres
        cat <<SQL
SELECT medcea_auth._set_internal_actor('system:deploy') \\g /dev/null
INSERT INTO iam_policy.user_unit (person_sub, unit_id) VALUES ('$S'::uuid, :uid) ON CONFLICT DO NOTHING;
INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id, widens, status, reason,
                                  made_by_sub, made_by_person, made_by_name)
VALUES ('unit_assign', '$S', 'test-s', NULL, :uid, true, 'pending_qa', 'iam-db probe', NULL, NULL, 'system:deploy')
RETURNING decision_id AS bd \\gset
SQL
    }

    # D1 / D2 — a widening waits, a narrowing applies with its status history
    probe D1 "operator -> production_manager: pending_qa with 12 widening pairs" ok <<SQL
$(pending_d1)
--CHECKS
SELECT 'CHECK|pending_qa', :'d1_st' = 'pending_qa';
SELECT 'CHECK|12 pairs', :d1_nw = 12;
SELECT 'CHECK|the row', widens AND made_by_sub = '$A' AND made_by_person = '$PA' AND from_role = 'operator'
          AND to_role = 'production_manager' AND checked_at IS NULL
  FROM iam.account_decision WHERE decision_id = :d1;
SELECT 'CHECK|no status history while pending', NOT EXISTS (SELECT 1 FROM iam.user_status_history WHERE decision_id = :d1);
SQL
    probe D2 "production_manager -> operator: applied, no pairs, status history with the decision" ok <<SQL
$(um_admin)
$(rec d2 role_change production_manager operator)
--CHECKS
SELECT 'CHECK|applied', :'d2_st' = 'applied';
SELECT 'CHECK|no pairs', :d2_nw = 0;
SELECT 'CHECK|role_changed by A as a person', count(*) = 1 FROM iam.user_status_history
 WHERE decision_id = :d2 AND action = 'role_changed' AND actor_sub = '$A' AND actor_person = '$PA'
   AND from_role = 'production_manager' AND to_role = 'operator';
SQL
    # an activation waits for qa even with no platform role (under IAM_GATES=false the AI workbench admits any enabled account)
    probe D2 "activate an account with no platform role: pending_qa, no pairs" ok <<SQL
$(um_admin)
$(rec d2 activate '' '')
--CHECKS
SELECT 'CHECK|pending_qa', :'d2_st' = 'pending_qa';
SELECT 'CHECK|no pairs', :d2_nw = 0;
SELECT 'CHECK|no status history while pending', NOT EXISTS (SELECT 1 FROM iam.user_status_history WHERE decision_id = :d2);
SQL
    # D3 — one open decision per account; deactivation is always allowed and withdraws it
    probe D3 "a second decision while D1 waits" "22023:is waiting for qa" <<SQL
$(pending_d1)
$(rec d3 person_id '' '' "p-new-$_h")
SQL
    probe D3 "a deactivation while D1 waits: allowed, D1 withdrawn" ok <<SQL
$(pending_d1)
$(rec d3 deactivate operator '')
--CHECKS
SELECT 'CHECK|applied', :'d3_st' = 'applied';
SELECT 'CHECK|returns D1 as withdrawn', :d1 = ANY (:'d3_wd'::bigint[]);
SELECT 'CHECK|D1 withdrawn by A', status = 'withdrawn' AND withdrawn_by_sub = '$A' AND withdrawn_at IS NOT NULL
          AND withdraw_reason LIKE 'withdrawn by deactivation #%'
  FROM iam.account_decision WHERE decision_id = :d1;
SELECT 'CHECK|deactivated in the status history', EXISTS (SELECT 1 FROM iam.user_status_history WHERE decision_id = :d3 AND action = 'deactivated');
SQL
    # D4 — who may propose: admin through the User Manager only
    probe D4 "record_decision as a qa person" "42501:holds no K on iam_users" <<SQL
$(um_qa)
$(rec d role_change operator engineer)
SQL
    probe D4 "record_decision without set_actor" "42501:made in the User Manager" <<SQL
SET SESSION AUTHORIZATION access_svc;
$(rec d role_change operator engineer)
SQL
    probe D4 "record_decision as postgres with the deploy's internal actor" "42501:not by system" <<SQL
SELECT medcea_auth._set_internal_actor('system:deploy') \\g /dev/null
$(rec d role_change operator engineer)
SQL
    probe D4 "access_svc cannot take the deploy's internal actor" "42501:permission denied for function" <<SQL
SET SESSION AUTHORIZATION access_svc;
SELECT medcea_auth._set_internal_actor('system:deploy');
SQL
    # D5 — who may confirm (rules 3-5)
    probe D5 "confirm as an admin" "42501:role admin holds no A on iam_users" <<SQL
$(pending_d1)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db probe');
SQL
    probe D5 "confirm by the subject's own account" "42501:you are its subject" <<SQL
$(pending_d1)
$(as_um "$S" "$PX" test-s qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db probe');
SQL
    probe D5 "confirm by the subject's person on another account" "42501:same person as the subject" <<SQL
$(pending_d1)
$(as_um "$Q" "$PS" test-q qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db probe');
SQL
    probe D5 "confirm with a token without person_id" "42501:no person_id" <<SQL
$(pending_d1)
$(as_um "$Q" "" test-q qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db probe');
SQL
    probe D5 "confirm a row whose maker is the same person (written by postgres)" "42501:same person as the maker" <<SQL
INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, from_role, to_role, widens, status,
                                  reason, made_by_sub, made_by_person, made_by_name)
VALUES ('role_change', '$S', 'test-s', '$PS', 'operator', 'engineer', true, 'pending_qa', 'iam-db probe', '$X', '$PQ', 'test-x')
RETURNING decision_id AS dm \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:dm, 'iam-db probe');
SQL
    # D6 / D7 — confirm, once
    probe D6 "qa confirms D1" ok <<SQL
$(pending_d1)
$(um_qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db D6') \\g /dev/null
--CHECKS
SELECT 'CHECK|confirmed by Q', status = 'confirmed' AND checked_by_sub = '$Q' AND checked_by_person = '$PQ' AND check_note = 'iam-db D6'
  FROM iam.account_decision WHERE decision_id = :d1;
SELECT 'CHECK|role_changed by Q', count(*) = 1 FROM iam.user_status_history
 WHERE decision_id = :d1 AND action = 'role_changed' AND actor_sub = '$Q' AND actor_person = '$PQ';
SQL
    probe D7 "confirm D1 again" "22023:already confirmed" <<SQL
$(pending_d1)
$(um_qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db D7') \\g /dev/null
SELECT * FROM iam.confirm_decision(:d1, 'iam-db D7');
SQL
    # D8 / D9 / D9b — a unit assignment takes effect when qa confirms it; refusing one
    # applies nothing, and refusing one in effect before the check (bootstrap) removes
    # it, only while it is the latest
    probe D8 "units.sql assign, then qa confirms it: the unit is assigned, unit_assigned with Q as the actor" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
SELECT NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid) AS pre \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, '$ATTEST') \\g /dev/null
--CHECKS
SELECT 'CHECK|not in effect before the confirm', :'pre'::boolean;
SELECT 'CHECK|user_unit row made by the confirm', EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid);
SELECT 'CHECK|confirmed by Q', status = 'confirmed' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :du;
SELECT 'CHECK|unit_assigned with Q as the actor', count(*) = 1 AND bool_and(actor_sub = '$Q'::uuid AND actor_person = '$PQ')
  FROM iam_policy.history WHERE event = 'unit_assigned' AND payload ->> 'person_sub' = '$S';
SELECT 'CHECK|account_decision_confirmed chained', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_confirmed' AND (payload ->> 'decision_id')::bigint = :du);
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
    probe D8 "units.sql assign, then qa refuses it: nothing was in effect, nothing removed" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT removed AS rm FROM iam.refuse_decision(:du, 'iam-db D8') \\gset
--CHECKS
SELECT 'CHECK|removed = false', NOT :'rm'::boolean;
SELECT 'CHECK|no user_unit row', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid);
SELECT 'CHECK|refused by Q', status = 'refused' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :du;
SELECT 'CHECK|no unit event', NOT EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event IN ('unit_assigned', 'unit_removed') AND payload ->> 'person_sub' = '$S');
SELECT 'CHECK|account_decision_refused, not removed', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_refused' AND (payload ->> 'decision_id')::bigint = :du AND NOT (payload ->> 'removed')::boolean);
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
    probe D8 "units.sql assign --bootstrap, then qa refuses it: the unit is removed, both events chained" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT removed AS rm FROM iam.refuse_decision(:du, 'iam-db D8') \\gset
--CHECKS
SELECT 'CHECK|removed = true', :'rm'::boolean;
SELECT 'CHECK|user_unit row gone', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid);
SELECT 'CHECK|refused by Q', status = 'refused' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :du;
SELECT 'CHECK|unit_removed with Q as the actor', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'unit_removed' AND actor_sub = '$Q'::uuid AND payload ->> 'person_sub' = '$S');
SELECT 'CHECK|account_decision_refused, removed', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_refused' AND (payload ->> 'decision_id')::bigint = :du AND (payload ->> 'removed')::boolean);
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
    probe D8 "confirm an assignment whose unit no longer exists" "22023:no longer exists" <<SQL
INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id, widens, status, reason,
                                  made_by_sub, made_by_person, made_by_name)
VALUES ('unit_assign', '$S', 'test-s', '$PS', -1, true, 'pending_qa', 'iam-db probe', '$A', '$PA', 'system:deploy (by test-a)')
RETURNING decision_id AS du \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, '$ATTEST');
SQL
    probe D9 "assign, remove: the waiting assign is withdrawn; refusing it" "22023:already withdrawn" <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
$(units "$A" "$PA" test-a false)
SELECT min(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT removed AS rm FROM iam.refuse_decision(:du, 'iam-db D9');
SQL
    probe D9 "assign --bootstrap, remove, assign --bootstrap; refusing the first assign removes nothing" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true true)
$(units "$A" "$PA" test-a false)
$(units "$A" "$PA" test-a true true)
SELECT min(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT removed AS rm FROM iam.refuse_decision(:du, 'iam-db D9') \\gset
--CHECKS
SELECT 'CHECK|removed = false', NOT :'rm'::boolean;
SELECT 'CHECK|user_unit row still there', EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid);
SELECT 'CHECK|account_decision_refused, not removed', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_refused' AND (payload ->> 'decision_id')::bigint = :du AND NOT (payload ->> 'removed')::boolean);
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
    probe D9b "assign --bootstrap, remove; confirming the first assign" "22023:superseded" <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true true)
$(units "$A" "$PA" test-a false)
SELECT min(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, 'iam-db D9b');
SQL
    # D10 — a bootstrap row without a maker or subject person (the production rows)
    probe D10 "bootstrap row: confirm without the attestation" "42501:needs the attestation" <<SQL
$unit_id_sql
$(bootstrap_row)
$(um_qa)
SELECT * FROM iam.confirm_decision(:bd, 'looks right');
SQL
    probe D10 "bootstrap row: confirm with the attestation, compared by account" ok <<SQL
$unit_id_sql
$(bootstrap_row)
$(um_qa)
SELECT * FROM iam.confirm_decision(:bd, '$ATTEST') \\g /dev/null
--CHECKS
SELECT 'CHECK|confirmed', status = 'confirmed' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :bd;
SELECT 'CHECK|the note holds the attestation and the account suffix', check_note LIKE '$ATTEST%'
          AND check_note LIKE '%[subject has no person_id: compared by account]'
  FROM iam.account_decision WHERE decision_id = :bd;
SELECT 'CHECK|account_decision_confirmed chained', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_confirmed' AND (payload ->> 'decision_id')::bigint = :bd);
SQL
    probe D10 "bootstrap row: confirm by the subject's account" "42501:you are its subject" <<SQL
$unit_id_sql
$(bootstrap_row)
$(as_um "$S" "$PX" test-s qa)
SELECT * FROM iam.confirm_decision(:bd, '$ATTEST');
SQL
    probe D10 "units.sql --by the qa person: that person cannot confirm it" "42501:you made this decision" <<SQL
$unit_id_sql
$(units "$Q" "$PQ" test-q true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, 'iam-db D10');
SQL
    # --by names an account the script cannot prove its runner holds: the attestation still applies
    probe D10 "units.sql --by another account: confirm without the attestation" "42501:needs the attestation" <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, 'looks right');
SQL
    probe D10 "units.sql --by another account: confirm with the attestation" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, '$ATTEST') \\g /dev/null
--CHECKS
SELECT 'CHECK|confirmed by Q', status = 'confirmed' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :du;
SQL
    # D11 — review an applied decision
    probe D11 "qa reviews D2 (applied)" ok <<SQL
$(um_admin)
$(rec d2 role_change production_manager operator)
$(um_qa)
SELECT iam.review_decision(:d2, NULL) \\g /dev/null
--CHECKS
SELECT 'CHECK|reviewed by Q', status = 'reviewed' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :d2;
SQL
    probe D11 "review a pending decision" "22023:only an applied decision is reviewed" <<SQL
$(pending_d1)
$(um_qa)
SELECT iam.review_decision(:d1, NULL);
SQL
    # D12 — access_svc writes the decision tables and histories only through the functions
    for stmt in "UPDATE iam.account_decision SET status = 'confirmed' WHERE false" \
                "INSERT INTO iam.account_decision (kind, keycloak_user_id, username, widens, status, reason, made_by_name) VALUES ('deactivate', '$S', 'x', false, 'applied', 'x', 'x')" \
                "DELETE FROM iam.account_decision WHERE false" \
                "UPDATE iam.user_status_history SET reason = reason WHERE false" "DELETE FROM iam.user_status_history WHERE false" \
                "UPDATE iam.access_request_history SET notes = notes WHERE false" "DELETE FROM iam.access_request_history WHERE false" \
                "UPDATE iam.config_history SET detail = detail WHERE false" "DELETE FROM iam.config_history WHERE false"; do
        probe D12 "access_svc: ${stmt%% WHERE*}" "42501:permission denied" <<SQL
SET SESSION AUTHORIZATION access_svc;
$stmt;
SQL
    done
    # D13 — postgres too: closing a record is the functions', the histories are append-only
    probe D13 "postgres closes a decision by UPDATE" "42501:close a record" <<SQL
$(pending_d1)
$(as_postgres)
UPDATE iam.account_decision SET status = 'confirmed', checked_at = now(), checked_by_name = 'x' WHERE decision_id = :d1;
SQL
    hist_rows="$(um_admin; rec d2 role_change production_manager operator; as_postgres)
INSERT INTO iam.access_request (username, email, first_name, last_name, requested_role, justification)
VALUES ('test-s-$_h', 'test-s-$_h@iamtest.invalid', 'T', 'S', 'operator', 'iam-db probe');
UPDATE iam.mail_settings SET from_name = 'IAMT probe $_h', updated_by = 'iam-db' WHERE id = 1;"
    for t in user_status_history access_request_history config_history; do
        for op in "UPDATE iam.$t SET event_id = event_id" "DELETE FROM iam.$t" "TRUNCATE iam.$t"; do
            probe D13 "postgres: ${op%% SET*}" "42501:append-only" <<SQL
$hist_rows
$op;
SQL
        done
    done
    # D13b — the stub role_widening of the migrations never answers
    stub="$(python3 - "$REPO_ROOT/apps/database/medcea_db_migrations.sql" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r"\n(\s*)IF pg_catalog\.to_regprocedure\('medcea_auth\.role_widening\(text, ?text\)'\) IS NULL THEN\n.*?\n\1END IF;", src, re.S)
print(m.group(0) if m else "")
PY
)"
    if [[ -n "$stub" ]]; then
        probe D13b "the uncompiled stub role_widening" "55000:not compiled" <<SQL
DROP FUNCTION medcea_auth.role_widening(text, text);
DO \$stub\$ BEGIN
$stub
END \$stub\$;
SELECT medcea_auth.role_widening('operator', 'qa');
SQL
    else
        fail D13b "the role_widening stub is not in apps/database/medcea_db_migrations.sql"
    fi
    # D13c — withdraw
    probe D13c "an admin withdraws D1" ok <<SQL
$(pending_d1)
SELECT iam.withdraw_decision(:d1, 'iam-db D13c') \\g /dev/null
--CHECKS
SELECT 'CHECK|withdrawn by A', status = 'withdrawn' AND withdrawn_by_sub = '$A' AND withdraw_reason = 'iam-db D13c'
  FROM iam.account_decision WHERE decision_id = :d1;
SQL
    probe D13c "withdraw an applied decision" "22023:already applied" <<SQL
$(um_admin)
$(rec d2 role_change production_manager operator)
SELECT iam.withdraw_decision(:d2, 'iam-db D13c');
SQL
    probe D13c "withdraw as qa" "42501:holds no K on iam_users" <<SQL
$(pending_d1)
$(um_qa)
SELECT iam.withdraw_decision(:d1, 'iam-db D13c');
SQL
    # D14 / D15 — the quarterly review
    probe D14 "qa creates this quarter's review" ok <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) AS rv \\gset
--CHECKS
SELECT 'CHECK|snapshot keys', snapshot ?& ARRAY['units', 'pending_decisions', 'decisions_since', 'policy_chain', 'iam_db_roles']
  FROM iam.access_review WHERE review_id = :rv;
SELECT 'CHECK|created by Q', created_by_sub = '$Q' AND created_by_person = '$PQ' FROM iam.access_review WHERE review_id = :rv;
SQL
    probe D14 "a second review this quarter" "23505:exists" <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) \\g /dev/null
SELECT iam.create_review('{}'::jsonb);
SQL
    probe D15 "sign-off as an auditor" "42501:holds no C on audit_histories" <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) AS rv \\gset
$(as_um "$X" "$PX" test-x auditor)
SELECT iam.sign_off_review(:rv, NULL);
SQL
    probe D15 "qa signs off (the creator may), once" ok <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) AS rv \\gset
SELECT iam.sign_off_review(:rv, 'iam-db D15') \\g /dev/null
--CHECKS
SELECT 'CHECK|signed off by Q', signed_off_by_sub = '$Q' AND signed_off_at IS NOT NULL FROM iam.access_review WHERE review_id = :rv;
SQL
    probe D15 "sign off twice" "22023:already signed off" <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) AS rv \\gset
SELECT iam.sign_off_review(:rv, NULL) \\g /dev/null
$(um_qa2)
SELECT iam.sign_off_review(:rv, NULL);
SQL
    # D16 — a template reset is an UPDATE, logged as reset
    probe D16 "access_svc resets a template by UPDATE" ok <<SQL
SET SESSION AUTHORIZATION access_svc;
INSERT INTO iam.mail_template (name, subject, body, updated_by, is_default) VALUES ('approved', 'IAMT', 'IAMT body', 'test-a', false)
ON CONFLICT (name) DO UPDATE SET subject = 'IAMT', body = 'IAMT body', updated_by = 'test-a', is_default = false;
UPDATE iam.mail_template SET subject = 'default', body = 'default body', is_default = true, updated_by = 'test-a-$_h', updated_at = now()
 WHERE name = 'approved' AND NOT is_default;
--CHECKS
SELECT 'CHECK|reset logged', EXISTS (SELECT 1 FROM iam.config_history WHERE item = 'template:approved' AND action = 'reset' AND actor = 'test-a-$_h');
SELECT 'CHECK|is_default', is_default FROM iam.mail_template WHERE name = 'approved';
SQL
    # D17 — MQTT person credentials, on deactivation and on a pure narrowing
    cred="$(as_postgres)
INSERT INTO medcea.mqtt_service_credential (username, password_hash, person_sub, expires_at)
VALUES ('iamt-person-$_h', '\$7\$101\$aaaa\$bbbb', '$S', now() + interval '1 day');"
    probe D17 "deactivate: revoke_person_mqtt in the same transaction" ok <<SQL
$cred
$(um_admin)
$(rec d3 deactivate operator '')
SELECT medcea.revoke_person_mqtt('$S'::uuid, 'deactivated') AS n \\gset
--CHECKS
SELECT 'CHECK|one credential revoked', :n = 1;
SELECT 'CHECK|inactive', NOT active FROM medcea.mqtt_service_credential WHERE username = 'iamt-person-$_h';
SQL
    probe D17 "narrowing (applied): revoke_person_mqtt in the same transaction" ok <<SQL
$cred
$(um_admin)
$(rec d2 role_change production_manager operator)
SELECT medcea.revoke_person_mqtt('$S'::uuid, 'role narrowed') AS n \\gset
--CHECKS
SELECT 'CHECK|applied', :'d2_st' = 'applied';
SELECT 'CHECK|one credential revoked', :n = 1;
SQL
    probe D17 "revoke_person_mqtt as a qa person" "42501:holds no K on iam_users" <<SQL
$cred
$(um_qa)
SELECT medcea.revoke_person_mqtt('$S'::uuid, 'x');
SQL
    # D18 — rr_qa (a qa token through PostgREST) executes no iam function
    if [[ "$MODE" == true ]]; then
        probe D18 "a qa token through PostgREST calls confirm_decision" "42501:permission denied" <<SQL
$(as_token "$(claims qa "$Q" "$PQ")")
SELECT * FROM iam.confirm_decision(1, 'x');
SQL
    else
        probe D18 "rr_qa calls confirm_decision" "42501:permission denied" <<SQL
SET SESSION AUTHORIZATION rr_qa;
SELECT * FROM iam.confirm_decision(1, 'x');
SQL
    fi
elif want access; then
    note access "skipped (needs --write-probes, on medcea-iamtest only, and a mode other than legacy)"
fi

# ── drift ────────────────────────────────────────────────────────────────────────
if want drift && [[ "$WRITES" == true && "$MODE" != legacy ]]; then
    echo ""
    VERIFY="$(python3 "$CLI" compile grants --mode verify "${IAM_FLAG[@]}")"
    drift() {  # NAME SQL
        probe drift "$1" "P0001:differ" <<SQL
$2
$VERIFY
SQL
    }
    probe drift "control: verify passes" ok <<SQL
$VERIFY
SQL
    drift "an extra grant" "GRANT SELECT ON medcea.recipe TO svc_grafana;"
    drift "a compiled grant revoked" "REVOKE SELECT ON medcea.cea_unit FROM rr_operator;"
    if [[ "$MODE" == true ]]; then
        drift "an extra iam_ policy" "CREATE POLICY iam_extra ON medcea.measurement FOR SELECT TO rr_admin USING (true);"
        drift "a dropped iam_ trigger" "DROP TRIGGER iam_immutable_trg ON medcea.recipe_run;"
    else
        drift "anon loses a legacy grant" "REVOKE SELECT ON medcea.recipe FROM anon;"
    fi
fi

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}${PASSES} check(s) passed (mode $MODE).${NC}"
else
    echo -e "${RED}${BOLD}${FAILS} of $((PASSES + FAILS)) check(s) failed (mode $MODE).${NC}"
    exit 1
fi
