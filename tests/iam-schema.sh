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
#   grants   the API role (anon) reaches none of it; no role but the owner may
#            execute an iam_policy function (superusers bypass ACLs)
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
# deployment:container of every service that will call medcea_iam.check()
for dc in scheduler:api monitor:api dbmgmt:api config-ui:recipe-fileserver access:api; do
    dep="${dc%%:*}" ctr="${dc#*:}"
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
SELECT 'anon', count(*), string_agg(what, ', ') FROM (
    SELECT 'medcea.platform_setting' AS what WHERE has_table_privilege('anon', 'medcea.platform_setting', 'SELECT,INSERT,UPDATE,DELETE')
    UNION ALL SELECT 'USAGE on ' || s FROM unnest(ARRAY['iam_policy', 'medcea_auth']) s WHERE has_schema_privilege('anon', s, 'USAGE')
) x;
SELECT 'exec', count(*), string_agg(p.proname || ' to ' || CASE a.grantee WHEN 0 THEN 'PUBLIC'
                                    ELSE pg_get_userbyid(a.grantee) END, ', ')
  FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
 WHERE p.pronamespace = 'iam_policy'::regnamespace
   AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner;
SQL
)"
if grep -q '^ERROR\|^psql' <<<"$out"; then
    fail schema "$(grep -m1 'ERROR' <<<"$out" || head -1 <<<"$out") — migration 008a not applied? (./apps/database/deploy.sh)"
else
    while IFS='|' read -r what a b; do
        case "$what" in
            schema)  [[ "$b" == medcea_owner ]] && pass schema "schema $a owned by medcea_owner" || fail schema "schema $a owned by $b" ;;
            tables)  [[ "$b" == 10 && "$a" == 10 ]] && pass schema "10 iam_policy tables, all owned by medcea_owner" \
                         || fail schema "iam_policy has $b table(s), $a owned by medcea_owner (want 10)" ;;
            setting) [[ "$a" == "$PROJECT_NAME" ]] && pass schema "platform_setting mqtt_topic_root = $a" \
                         || fail schema "platform_setting mqtt_topic_root is $a, PROJECT_NAME is $PROJECT_NAME" ;;
            access)  [[ "$a" == 2 ]] && pass schema "iam.account_decision and iam.access_review exist" \
                         || fail schema "iam.account_decision / iam.access_review missing (./apps/access/deploy.sh)" ;;
            anon)    [[ "$a" == 0 ]] && pass grants "anon reaches no iam_policy, medcea_auth or platform setting" \
                         || fail grants "anon has: $b" ;;
            exec)    [[ "$a" == 0 ]] && pass grants "no iam_policy function is executable by anyone but its owner" \
                         || fail grants "executable by others: $b" ;;
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
