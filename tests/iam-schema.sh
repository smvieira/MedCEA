#!/usr/bin/env bash
# tests/iam-schema.sh — the groundwork of the IAM plan's Phase 1.1 is in place on the
# running cluster.
#
#   routes   ConfigMap medcea-iam-lib holds the route table `cli.py compile routes`
#            prints now (same digest), and every Python service pod reads that same
#            file at /iam/routes.json
#   schema   migration 008a: schemas medcea_auth and iam_policy owned by medcea_owner,
#            the iam_policy tables, medcea.platform_setting with the MQTT topic root,
#            and iam.account_decision / iam.access_review (apps/access)
#   grants   the API role (anon) reaches nothing in iam_policy and holds, in both
#            IAM_DB_ROLES modes, USAGE on medcea_auth and EXECUTE on pre_request()
#            only there; the iam_policy functions are executable exactly by the roles
#            infrastructure_functions and the policy members name (append_history:
#            iam_svc, log_export: svc_dbexport; superusers bypass ACLs)
#   chain    iam_policy.verify_chain() passes on the live history, and inside a
#            transaction that is rolled back: two appends chain, verify, and an
#            UPDATE, DELETE and TRUNCATE are each refused
#
# Read-only: no lock, and the chain probe is rolled back (it only advances the
# history's id sequence). Run from the repository root:  tests/iam-schema.sh
# Exit 1 on any FAIL.

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
if [[ ! -f config.env ]]; then
    echo "config.env not found — run ./deploy-infra.sh first." >&2
    exit 2
fi
# shellcheck disable=SC1091
source config.env
source infra/lib-mk8s.sh

FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %-8s %s\n" "$1" "$2"; }
fail() { printf "  ${RED}FAIL${NC}  %-8s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }

# psql as postgres in medcea_db; the password is read inside the pod. SQL on stdin.
db() {
    $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' \
        "$POSTGRES_DB" 2>&1
}
digest_of() { grep -o '"digest":"[0-9a-f]*"' | head -1 | cut -d'"' -f4; }

echo -e "${BOLD}IAM Phase 1.1 groundwork${NC} (namespace $NAMESPACE, database $POSTGRES_DB)"

# ── routes ──────────────────────────────────────────────────────────────────────
echo ""
want="$(python3 apps/iam/compiler/cli.py compile routes | digest_of)"
have="$($KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o jsonpath='{.data.routes\.json}' 2>/dev/null | digest_of)"
annot="$($KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o jsonpath='{.metadata.annotations.medcea/routes-digest}' 2>/dev/null)"
if [[ -z "$want" ]]; then
    fail routes "cli.py compile routes failed"
elif [[ -z "$have" ]]; then
    fail routes "ConfigMap medcea-iam-lib is missing or has no routes.json (run ./deploy-infra.sh)"
elif [[ "$have" != "$want" || "$annot" != "$want" ]]; then
    fail routes "ConfigMap digest ${have:0:12} (annotation ${annot:0:12}) is not the policy's ${want:0:12} (run ./deploy-infra.sh)"
else
    pass routes "ConfigMap medcea-iam-lib matches the policy (${want:0:12})"
fi
# IAM 3.5: mqtt.json (the MQTT Explorer's credential rows, read by iam-api) is a fresh compile
want_mq="$(python3 apps/iam/compiler/cli.py compile mqtt | digest_of)"
have_mq="$($KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o jsonpath='{.data.mqtt\.json}' 2>/dev/null | digest_of)"
annot_mq="$($KUBECTL get configmap medcea-iam-lib -n "$NAMESPACE" -o jsonpath='{.metadata.annotations.medcea/mqtt-digest}' 2>/dev/null)"
if [[ -z "$want_mq" ]]; then
    fail mqtt "cli.py compile mqtt failed"
elif [[ "$have_mq" != "$want_mq" || "$annot_mq" != "$want_mq" ]]; then
    fail mqtt "ConfigMap mqtt.json ${have_mq:0:12} (annotation ${annot_mq:0:12}) is not the policy's ${want_mq:0:12} (run ./deploy-infra.sh)"
else
    pass mqtt "ConfigMap medcea-iam-lib mqtt.json matches the policy (${want_mq:0:12})"
fi
# deployment:container of every service that will call medcea_iam.check()
for dc in scheduler:api monitor:api dbmgmt:api config-ui:recipe-fileserver access:api iam-api:iam-api; do
    dep="${dc%%:*}" ctr="${dc#*:}"
    [[ "$dep" == iam-api ]] && ! $KUBECTL get deployment iam-api -n "$NAMESPACE" >/dev/null 2>&1 && continue   # IAM 3.5, optional
    got="$($KUBECTL exec -n "$NAMESPACE" "deployment/$dep" -c "$ctr" -- cat /iam/routes.json 2>/dev/null | digest_of)"
    if [[ -z "$got" ]]; then
        fail routes "$dep/$ctr cannot read /iam/routes.json (redeploy the component)"
    elif [[ -n "$want" && "$got" != "$want" ]]; then
        fail routes "$dep/$ctr reads digest ${got:0:12}, not ${want:0:12} (the kubelet syncs within a minute)"
    else
        pass routes "$dep/$ctr reads /iam/routes.json"
    fi
done

# ── schema + grants ─────────────────────────────────────────────────────────────
echo ""
out="$(db <<SQL
SELECT 'schema', n.nspname, pg_get_userbyid(n.nspowner) FROM pg_namespace n
 WHERE n.nspname IN ('medcea_auth', 'iam_policy') ORDER BY 2;
SELECT 'tables', count(*) FILTER (WHERE pg_get_userbyid(c.relowner) = 'medcea_owner'), count(*)
  FROM pg_class c WHERE c.relnamespace = 'iam_policy'::regnamespace AND c.relkind = 'r';
SELECT 'setting', coalesce((SELECT value FROM medcea.platform_setting WHERE key = 'mqtt_topic_root'), '<none>'), '';
SELECT 'access', count(*), '' FROM pg_class
 WHERE oid IN (to_regclass('iam.account_decision'), to_regclass('iam.access_review'));
SELECT 'unitdec', count(*), '' FROM (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'iam' AND table_name = 'account_decision' AND column_name = 'unit_id'
    UNION ALL
    SELECT 1 FROM pg_constraint WHERE conname = 'account_decision_kind_check'
       AND conrelid = to_regclass('iam.account_decision') AND pg_get_constraintdef(oid) LIKE '%unit_assign%') x;
SELECT 'anon', count(*), string_agg(what, ', ') FROM (
    SELECT 'medcea.platform_setting' AS what WHERE has_table_privilege('anon', 'medcea.platform_setting', 'SELECT,INSERT,UPDATE,DELETE')
    UNION ALL SELECT 'USAGE on iam_policy' WHERE has_schema_privilege('anon', 'iam_policy', 'USAGE')
    UNION ALL SELECT 'no USAGE on medcea_auth' WHERE NOT has_schema_privilege('anon', 'medcea_auth', 'USAGE')
    UNION ALL SELECT 'no EXECUTE on pre_request()' WHERE to_regprocedure('medcea_auth.pre_request()') IS NULL
       OR NOT has_function_privilege('anon', 'medcea_auth.pre_request()', 'EXECUTE')
    UNION ALL SELECT 'EXECUTE on medcea_auth.' || p.proname FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
     WHERE p.pronamespace = 'medcea_auth'::regnamespace AND a.grantee = 'anon'::regrole AND p.proname <> 'pre_request'
) x;
SELECT 'exec', count(*), string_agg(x, ', ') FROM (
    (SELECT p.proname || ' to ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS x
       FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.pronamespace = 'iam_policy'::regnamespace AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner
     EXCEPT SELECT unnest(ARRAY['append_history to iam_svc', 'log_export to svc_dbexport']))
    UNION ALL
    (SELECT unnest(ARRAY['append_history to iam_svc', 'log_export to svc_dbexport'])
     EXCEPT SELECT p.proname || ' to ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END
       FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
      WHERE p.pronamespace = 'iam_policy'::regnamespace AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner)
) y;
SQL
)"
if grep -q '^ERROR\|^psql' <<<"$out"; then
    fail schema "$(grep -m1 'ERROR' <<<"$out" || head -1 <<<"$out") — migration 008a not applied? (./apps/database/deploy.sh)"
else
    while IFS='|' read -r what a b; do
        case "$what" in
            schema)  [[ "$b" == medcea_owner ]] && pass schema "schema $a owned by medcea_owner" || fail schema "schema $a owned by $b" ;;
            tables)  [[ "$b" == 11 && "$a" == 11 ]] && pass schema "11 iam_policy tables, all owned by medcea_owner" \
                         || fail schema "iam_policy has $b table(s), $a owned by medcea_owner (want 11)" ;;
            setting) [[ "$a" == "$PROJECT_NAME" ]] && pass schema "platform_setting mqtt_topic_root = $a" \
                         || fail schema "platform_setting mqtt_topic_root is $a, PROJECT_NAME is $PROJECT_NAME" ;;
            access)  [[ "$a" == 2 ]] && pass schema "iam.account_decision and iam.access_review exist" \
                         || fail schema "iam.account_decision / iam.access_review missing (./apps/access/deploy.sh)" ;;
            unitdec) [[ "$a" == 2 ]] && pass schema "iam.account_decision records unit decisions (unit_id, unit_assign/unit_remove)" \
                         || fail schema "iam.account_decision has no unit_id or unit_* kinds (./apps/access/deploy.sh)" ;;
            anon)    [[ "$a" == 0 ]] && pass grants "anon: nothing in iam_policy, only USAGE on medcea_auth and EXECUTE on pre_request()" \
                         || fail grants "anon: $b" ;;
            exec)    [[ "$a" == 0 ]] && pass grants "iam_policy functions: append_history to iam_svc, log_export to svc_dbexport, nothing else" \
                         || fail grants "iam_policy EXECUTE differs (missing or extra): $b" ;;
        esac
    done <<<"$out"
    grep -q '^schema|medcea_auth' <<<"$out" || fail schema "schema medcea_auth missing"
    grep -q '^schema|iam_policy' <<<"$out" || fail schema "schema iam_policy missing"
fi

# ── chain ───────────────────────────────────────────────────────────────────────
echo ""
live="$(db <<<'SELECT ok, events, coalesce(first_bad_event::text, $$-$$), coalesce(detail, $$$$) FROM iam_policy.verify_chain();')"
IFS='|' read -r ok events bad detail <<<"$(grep -E '^[tf]\|' <<<"$live")"
case "$ok" in
    t) pass chain "live history intact ($events event(s))" ;;
    f) fail chain "live history broken at event $bad: $detail" ;;
    *) fail chain "verify_chain() did not run: $(head -1 <<<"$live")" ;;
esac

probe="$(db <<'SQL'
\set ON_ERROR_STOP 0
BEGIN;
SELECT 'append', iam_policy.append_history('test_probe', '{"version": 1}', 'tests/iam-schema.sh');
SELECT 'append', iam_policy.append_history('test_probe', '{}', 'tests/iam-schema.sh');
SELECT 'verify', ok, events FROM iam_policy.verify_chain();
SAVEPOINT s;
UPDATE iam_policy.history SET reason = 'x' WHERE event = 'test_probe';
ROLLBACK TO s;
DELETE FROM iam_policy.history WHERE event = 'test_probe';
ROLLBACK TO s;
TRUNCATE iam_policy.history;
ROLLBACK TO s;
ROLLBACK;
SQL
)"
n_append="$(grep -c '^append|' <<<"$probe" || true)"
verify="$(grep '^verify|' <<<"$probe" | cut -d'|' -f2)"
refused="$(grep -c 'is append-only: \(UPDATE\|DELETE\|TRUNCATE\) refused' <<<"$probe" || true)"
[[ "$n_append" == 2 && "$verify" == t ]] && pass chain "two appends chain and verify (rolled back)" \
    || fail chain "append/verify probe: $(grep -m1 'ERROR' <<<"$probe" || echo "$n_append append(s), verify=$verify")"
[[ "$refused" == 3 ]] && pass chain "UPDATE, DELETE and TRUNCATE on the history are refused" \
    || fail chain "only $refused of UPDATE/DELETE/TRUNCATE were refused"

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Phase 1.1 groundwork in place.${NC}"
else
    echo -e "${RED}${BOLD}${FAILS} check(s) failed.${NC}"
    exit 1
fi
