#!/usr/bin/env bash
# tests/iam-db-fixture.sh — IAM Phase 2a on a throwaway PostgreSQL, end to end.
#
#   tests/iam-db-fixture.sh up | load | fresh | apply MODE | cycle | logins MODE
#                           | fulldown | serverlog | purge | down | run [--keep]
#
#   up        namespace medcea-iamtest, Secret pg (a random password, on stdin), one
#             pod from production's image digest configured like rdbms-postgresql-0
#             (tests/k8s/iam-db-fixture.yaml); records the fresh image's roles; makes
#             one random password per database role (never printed)
#   load      under medcea_lock, only while it reads production: pg_dump --schema-only
#             --create, pg_dumpall --roles-only --no-role-passwords and pg_dump
#             --data-only --disable-triggers --schema=medcea (without the credential
#             tables; never schema iam). Loads roles (not postgres), schema, data and
#             tests/sql/iam-db-seed.sql, then snapshots the catalog as B0
#   apply M   apps/database/lib-db-apply.sh db_apply with IAM_DB_ROLES=M (false|true),
#             exactly what apps/database/deploy.sh runs; any psql ERROR fails it; the
#             hash chain must verify and an enforcement_* event appear on a transition only
#   cycle     false -> A; B0 vs A differs only by the declared delta; false = A;
#             true twice equal; false = A; true = the earlier true
#   logins M  every svc_* role and rr_admin_login logs in over TCP with its password
#             (M=true), or cannot (M=false)
#   fulldown  from true: medcea_db_migrations_down_008b.sql by hand (no logins), then
#             with -v full=1 (no logins, the managed roles hold nothing), then the
#             previous commit's DDL, migrations and grants (PREV_REV, default HEAD:
#             Phase 2a uncommitted); W1 must still pass (tests/iam-db.sh --mode legacy)
#   fresh     an empty database (medcea_fresh): apply false twice, then true; its
#             catalog must match the upgraded fixture's, apart from the seed
#   serverlog the pod's log holds none of the generated passwords
#   purge     drop the databases, run apps/database/purge.sql: pg_roles must equal the
#             fresh image's
#   down      delete the namespace
#   run       up, load, apply false, probes, logins false, apply true, probes, logins
#             true, apply false, probes (W1 again), cycle, fulldown, fresh, purge, the
#             server log holds no generated password, down (on exit, unless --keep)
#
# Production is only read (the dumps and the image lookup). Dumps, snapshots and the
# generated passwords live in $IAMTEST_DIR (default $TMPDIR/medcea-iamtest, mode 700).
# Exit 1 on any FAIL.

set -uo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
    sed -n '2,39p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
[[ -f config.env ]] || { echo "config.env not found" >&2; exit 2; }
# shellcheck disable=SC1091
source config.env
source infra/lib-mk8s.sh
source infra/lib-render.sh
source infra/lib-lock.sh
source apps/database/lib-db-apply.sh

FX_NS="medcea-iamtest"
FX_POD="pg"
PROD_NS="${NAMESPACE:-medcea}"
PROD_POD="rdbms-postgresql-0"
PROD_DB="${POSTGRES_DB:-medcea_db}"
CEA_DB="medcea_db"
PROJECT_NAME="${PROJECT_NAME:-medcea}"
IAMTEST_DIR="${IAMTEST_DIR:-${TMPDIR:-/tmp}/medcea-iamtest}"
PREV_REV="${PREV_REV:-HEAD}"
CLI="$REPO_ROOT/apps/iam/compiler/cli.py"
KEEP=false
for a in "$@"; do [[ "$a" == --keep ]] && KEEP=true; done

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %-9s %s\n" "$1" "$2"; }
fail() { printf "  ${RED}FAIL${NC}  %-9s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

mkdir -p "$IAMTEST_DIR" && chmod 700 "$IAMTEST_DIR"

# fx DB [psql args] — psql in the fixture pod as postgres; SQL on stdin
fx() {
    local db="$1"; shift
    $KUBECTL exec -i -n "$FX_NS" "$FX_POD" -- env PGOPTIONS="-c client_min_messages=warning" \
        sh -c 'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -U postgres -d "$0" "$@"' "$db" "$@"
}
# prod CMD... — a read-only client program in the production pod (pg_dump, pg_dumpall)
prod() {
    $KUBECTL exec -n "$PROD_NS" "$PROD_POD" -- env PGOPTIONS="-c default_transaction_read_only=on" \
        sh -c 'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec "$@"' prod "$@"
}
snapshot() {  # DB FILE — an error or an empty snapshot is a FAIL (it would prove nothing)
    local err
    err="$(fx "$1" -q -tA -v ON_ERROR_STOP=1 -f - < tests/sql/iam-db-catalog.sql 2>&1 > "$2")"
    if [[ -n "$err" || ! -s "$2" ]]; then
        fail snapshot "catalog snapshot of $1 -> $(basename "$2"): ${err:-empty}"
        return 1
    fi
}
# the generated passwords as DBPW_<role> for db_apply
load_passwords() {
    local r p
    [[ -f "$IAMTEST_DIR/passwords" ]] || { echo "no passwords: run '$0 up' first" >&2; exit 2; }
    while read -r r p; do printf -v "DBPW_$r" '%s' "$p"; done < "$IAMTEST_DIR/passwords"
}

cmd_up() {
    step "up: namespace $FX_NS"
    local image
    image="$($KUBECTL get pod "$PROD_POD" -n "$PROD_NS" -o jsonpath='{.status.containerStatuses[0].imageID}')"
    image="${image#docker-pullable://}"
    [[ "$image" == *@sha256:* ]] || { echo "cannot read production's image digest ($image)" >&2; exit 2; }
    $KUBECTL get namespace "$FX_NS" >/dev/null 2>&1 || $KUBECTL create namespace "$FX_NS" >/dev/null
    $KUBECTL label namespace "$FX_NS" medcea/test=iam-db --overwrite >/dev/null
    if ! $KUBECTL get secret pg -n "$FX_NS" >/dev/null 2>&1; then
        openssl rand -hex 24 | tr -d '\n' | $KUBECTL create secret generic pg -n "$FX_NS" --from-file=postgres-password=/dev/stdin >/dev/null
    fi
    FIXTURE_NS="$FX_NS" FIXTURE_IMAGE="$image" render tests/k8s/iam-db-fixture.yaml FIXTURE_NS FIXTURE_IMAGE \
        | $KUBECTL apply -f - >/dev/null
    $KUBECTL wait --for=condition=Ready "pod/$FX_POD" -n "$FX_NS" --timeout=300s >/dev/null \
        || { echo "the fixture pod did not become ready" >&2; exit 1; }
    # Ready can come from Bitnami's temporary init server, which then shuts down:
    # wait for the final start, then for a few queries in a row to succeed.
    local i ok=0
    for i in $(seq 1 90); do
        $KUBECTL logs -n "$FX_NS" "$FX_POD" 2>/dev/null | grep -q '\*\* Starting PostgreSQL \*\*' && break
        sleep 2
    done
    for i in $(seq 1 60); do
        if fx postgres -q -tA -c 'SELECT 1' >/dev/null 2>&1; then ok=$((ok + 1)); else ok=0; fi
        [[ $ok -ge 3 ]] && break
        sleep 2
    done
    [[ $ok -ge 3 ]] || { echo "the fixture's PostgreSQL does not answer steadily" >&2; exit 1; }
    fx postgres -q -tA -c "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY 1" > "$IAMTEST_DIR/roles-baseline.txt"
    if [[ ! -f "$IAMTEST_DIR/passwords" ]]; then
        ( umask 077
          { python3 "$CLI" db-roles --passwords | awk '{print $1}'; echo mqtt_auth; } | sort -u \
            | while read -r r; do printf '%s %s\n' "$r" "$(openssl rand -hex 16)"; done > "$IAMTEST_DIR/passwords" )
    fi
    pass up "pod $FX_POD ready ($image)"
}

cmd_load() {
    step "load: production's schema, roles and medcea data (read-only), then the seed"
    (   # the deploy lock, only while production is read
        medcea_lock
        prod pg_dump -U postgres -d "$PROD_DB" --schema-only --create > "$IAMTEST_DIR/schema.sql" &&
        prod pg_dumpall -U postgres --roles-only --no-role-passwords > "$IAMTEST_DIR/roles.sql" &&
        prod pg_dump -U postgres -d "$PROD_DB" --data-only --disable-triggers --schema=medcea \
             --exclude-table=medcea.mqtt_credential '--exclude-table=medcea.mqtt_service_*' > "$IAMTEST_DIR/data.sql"
    ) || { fail load "reading production failed"; return; }
    chmod 600 "$IAMTEST_DIR"/*.sql
    local out
    out="$(sed -E '/ROLE postgres( |;)/d' "$IAMTEST_DIR/roles.sql" | fx postgres -q 2>&1)"
    grep 'ERROR' <<<"$out" | grep -v 'already exists' && fail load "roles" || pass load "roles (without postgres)"
    out="$(fx postgres -q < "$IAMTEST_DIR/schema.sql" 2>&1)"
    if grep 'ERROR' <<<"$out" | grep -v 'already exists'; then fail load "schema"; else pass load "schema"; fi
    out="$(fx "$CEA_DB" -q -v ON_ERROR_STOP=1 < "$IAMTEST_DIR/data.sql" 2>&1)" && pass load "medcea data" || { echo "$out" | head; fail load "data"; }
    out="$(fx "$CEA_DB" -q < tests/sql/iam-db-seed.sql 2>&1)" && pass load "seed" || { echo "$out" | head; fail load "seed"; }
    snapshot "$CEA_DB" "$IAMTEST_DIR/B0.txt" && pass load "catalog snapshot B0 ($(wc -l < "$IAMTEST_DIR/B0.txt") lines)"
}

cmd_apply() {  # MODE [DB]
    local mode="$1" db="${2:-medcea_db}" out events
    step "apply IAM_DB_ROLES=$mode on $db"
    load_passwords
    out="$(CEA_DB="$db" db_apply "$FX_NS" "$FX_POD" "$mode" 2>&1)"
    local rc=$?
    if [[ $rc -ne 0 ]] || grep -q 'ERROR' <<<"$out"; then
        grep -E 'ERROR|DETAIL' <<<"$out" | head -20
        fail apply "db_apply $mode on $db (exit $rc)"
    else
        pass apply "db_apply $mode on $db"
    fi
    grep 'WARNING' <<<"$out" | sed 's/^/        /' | head -20
    out="$(fx "$db" -q -tA -c "SELECT ok FROM iam_policy.verify_chain()" 2>&1)"
    [[ "$out" == t ]] && pass chain "verify_chain() ok after apply $mode" || fail chain "verify_chain: $out"
    events="$(fx "$db" -q -tA -c "SELECT string_agg(left(event, 999), ',' ORDER BY event_id) FROM iam_policy.history WHERE payload ->> 'switch' = 'IAM_DB_ROLES'")"
    echo "        IAM_DB_ROLES events: ${events:-none}"
    local last="${events##*,}" want="enforcement_disabled"
    [[ "$mode" == true ]] && want="enforcement_enabled"
    [[ "$last" == "$want" ]] && pass chain "last IAM_DB_ROLES event is $want" || fail chain "last event is '${last:-none}', want $want"
    if python3 -c 'import sys; e=sys.argv[1].split(","); sys.exit(any(a == b for a, b in zip(e, e[1:])))' "$events"; then
        pass chain "an enforcement_* event only on transitions"
    else
        fail chain "repeated enforcement_* events: $events"
    fi
}

cmd_logins() {  # MODE
    local mode="$1" r p out ok=0 bad=0
    step "logins with IAM_DB_ROLES=$mode"
    load_passwords
    while read -r r p; do
        [[ "$r" == svc_* || "$r" == iam_svc || "$r" == rr_admin_login ]] || continue
        out="$(printf '%s\n' "$p" | $KUBECTL exec -i -n "$FX_NS" "$FX_POD" -- sh -c \
            'read -r PGPASSWORD; export PGPASSWORD; exec psql -X -h 127.0.0.1 -U "$0" -d medcea_db -tAc "SELECT current_user"' "$r" 2>&1)"
        if [[ "$mode" == true && "$out" == "$r" ]] || [[ "$mode" == false && "$out" != "$r" ]]; then
            ok=$((ok + 1))
        else
            bad=$((bad + 1)); fail logins "$r: ${out:0:120}"
        fi
    done < "$IAMTEST_DIR/passwords"
    [[ $bad -eq 0 ]] && pass logins "$ok role(s) $([[ "$mode" == true ]] && echo 'log in' || echo 'cannot log in')"
}

probes() {  # MODE
    step "tests/iam-db.sh --write-probes (mode $1)"
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --mode "$1" --write-probes || FAILS=$((FAILS + 1))
}

# The declared difference between production's catalog before 2a (B0) and after
# apply false (A), for anon, authenticator, mqtt_auth, access_svc and PUBLIC.
DELTA='^[<>] owner\|
^[<>] secdef\|
^[<>] trigger\|
^[<>] defacl\|
^[<>] .*databasechangeloglock
^< acl\|authenticator\|(table|sequence)\|medcea\.schedule
^> acl\|anon\|schema\|medcea_auth\|USAGE
^> acl\|anon\|function\|medcea_auth\.pre_request\(\)\|EXECUTE
^< acl\|PUBLIC\|function\|
^> reloption\|.*security_invoker=true
^> dbsetting\|\*\|medcea\.iam_db_roles=false
^> role\|(rr_|svc_|iam_svc)
^> constraint\|'
# every fact but the grants of roles outside the comparison (the managed roles are
# compared exactly by the bundle's own assertions)
scoped() { grep -vE '^acl\|' "$1"; grep -E '^acl\|(anon|authenticator|mqtt_auth|access_svc|PUBLIC)\|' "$1"; }

cmd_cycle() {
    step "cycle"
    cmd_apply false; snapshot medcea_db "$IAMTEST_DIR/A.txt"
    local left
    left="$(diff <(scoped "$IAMTEST_DIR/B0.txt") <(scoped "$IAMTEST_DIR/A.txt") | grep -E '^[<>]' | grep -vEf <(printf '%s\n' "$DELTA"))"
    if [[ -z "$left" ]]; then pass cycle "B0 -> A differs only by the declared delta"
    else fail cycle "B0 -> A, undeclared differences:"; sed 's/^/        /' <<<"$left" | head -40; fi
    grep -q '^trigger|.*|iam_' "$IAMTEST_DIR/A.txt" && fail cycle "A has iam_* triggers" || pass cycle "A has no iam_* trigger"
    cmd_apply false; snapshot medcea_db "$IAMTEST_DIR/A2.txt"
    diff -q "$IAMTEST_DIR/A.txt" "$IAMTEST_DIR/A2.txt" >/dev/null && pass cycle "apply false twice: identical" \
        || { fail cycle "apply false twice differs"; diff "$IAMTEST_DIR/A.txt" "$IAMTEST_DIR/A2.txt" | head -20; }
    cmd_apply true; snapshot medcea_db "$IAMTEST_DIR/T1.txt"
    cmd_apply true; snapshot medcea_db "$IAMTEST_DIR/T2.txt"
    diff -q "$IAMTEST_DIR/T1.txt" "$IAMTEST_DIR/T2.txt" >/dev/null && pass cycle "apply true twice: identical" \
        || { fail cycle "apply true twice differs"; diff "$IAMTEST_DIR/T1.txt" "$IAMTEST_DIR/T2.txt" | head -20; }
    cmd_apply false; snapshot medcea_db "$IAMTEST_DIR/A3.txt"
    diff -q "$IAMTEST_DIR/A.txt" "$IAMTEST_DIR/A3.txt" >/dev/null && pass cycle "true -> false: back to A" \
        || { fail cycle "true -> false differs from A"; diff "$IAMTEST_DIR/A.txt" "$IAMTEST_DIR/A3.txt" | head -20; }
    cmd_apply true; snapshot medcea_db "$IAMTEST_DIR/T3.txt"
    diff -q "$IAMTEST_DIR/T1.txt" "$IAMTEST_DIR/T3.txt" >/dev/null && pass cycle "false -> true: back to the first true" \
        || { fail cycle "false -> true differs"; diff "$IAMTEST_DIR/T1.txt" "$IAMTEST_DIR/T3.txt" | head -20; }
}

# managed_grants — privileges the managed roles (rr_*, svc_*, iam_svc) hold in the
# three schemas, their objects and the database, one per line
managed_grants() {
    fx medcea_db -q -tA -c "
      WITH o AS (
        SELECT c.relacl AS acl, c.oid::regclass::text AS obj FROM pg_class c
         WHERE c.relnamespace::regnamespace::text IN ('medcea', 'medcea_auth', 'iam_policy', 'medcea_retired_008b')
        UNION ALL SELECT p.proacl, p.oid::regprocedure::text FROM pg_proc p
         WHERE p.pronamespace::regnamespace::text IN ('medcea', 'medcea_auth', 'iam_policy')
        UNION ALL SELECT n.nspacl, 'schema ' || n.nspname FROM pg_namespace n
         WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'medcea_retired_008b')
        UNION ALL SELECT d.datacl, 'database ' || d.datname FROM pg_database d WHERE d.datname = current_database())
      SELECT r.rolname || ' ' || x.privilege_type || ' ' || o.obj
        FROM o CROSS JOIN LATERAL aclexplode(o.acl) x JOIN pg_roles r ON r.oid = x.grantee
       WHERE r.rolname ~ '^(rr_|svc_)' OR r.rolname = 'iam_svc' ORDER BY 1"
}

cmd_fulldown() {
    step "down by hand straight after IAM_DB_ROLES=true, then full down, then the code before Phase 2a ($PREV_REV)"
    local out left
    # the cycle ends in true; make sure, so the by-hand path starts from enforce
    [[ "$(fx medcea_db -q -tA -c "SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'")" == true ]] || cmd_apply true
    out="$(fx medcea_db -q -1 -v ON_ERROR_STOP=1 < apps/database/medcea_db_migrations_down_008b.sql 2>&1)" \
        && pass fulldown "medcea_db_migrations_down_008b.sql by hand after true" || { echo "$out" | grep ERROR; fail fulldown "the down file failed"; return; }
    cmd_logins false
    out="$(fx medcea_db -q -1 -v ON_ERROR_STOP=1 -v full=1 < apps/database/medcea_db_migrations_down_008b.sql 2>&1)" \
        && pass fulldown "medcea_db_migrations_down_008b.sql -v full=1" || { echo "$out" | grep ERROR; fail fulldown "the full down file failed"; return; }
    cmd_logins false
    left="$(managed_grants)"
    [[ -z "$left" ]] && pass fulldown "the managed roles hold nothing after the full down" \
        || { fail fulldown "managed roles still hold $(wc -l <<<"$left") privilege(s):"; sed 's/^/        /' <<<"$left" | head -20; }
    out="$(git show "$PREV_REV:apps/database/medcea_db_ddl.sql" | fx medcea_db -q 2>&1 | grep ERROR | grep -v 'already exists\|multiple primary keys')"
    [[ -z "$out" ]] && pass fulldown "previous DDL" || { echo "$out" | head; fail fulldown "previous DDL"; }
    out="$(git show "$PREV_REV:apps/database/medcea_db_migrations.sql" | fx medcea_db -q 2>&1 | grep ERROR)"
    [[ -z "$out" ]] && pass fulldown "previous migrations" || { echo "$out" | head; fail fulldown "previous migrations"; }
    out="$(git show "$PREV_REV:apps/database/deploy.sh" | sed -n "/cat > \"\$_GRANTS_SQL\" << 'SQLEOF'/,/^SQLEOF/p" | sed '1d;$d' \
           | fx medcea_db -q -v ON_ERROR_STOP=1 2>&1)" && pass fulldown "previous step-5 grants" || { echo "$out" | head; fail fulldown "previous grants"; }
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --mode legacy --write-probes --section writes || FAILS=$((FAILS + 1))
}

cmd_fresh() {
    step "fresh: an empty database"
    cmd_apply false medcea_fresh
    cmd_apply false medcea_fresh
    cmd_apply true medcea_fresh
    snapshot medcea_fresh "$IAMTEST_DIR/F.txt"
    cmd_apply true medcea_db
    snapshot medcea_db "$IAMTEST_DIR/T4.txt"
    # apart from the seed and production's own history: schema iam (apps/access),
    # the code CHECKs (the seed has codes that violate them), the database name
    local left
    left="$(diff <(grep -vE '\|iam\.|\|schema\|iam\||^acl\|access_svc\||^constraint\||\|database\|' "$IAMTEST_DIR/T4.txt") \
                 <(grep -vE '\|iam\.|\|schema\|iam\||^acl\|access_svc\||^constraint\||\|database\|' "$IAMTEST_DIR/F.txt") | grep -E '^[<>]')"
    [[ -z "$left" ]] && pass fresh "a fresh install's catalog equals the upgraded one" \
        || { fail fresh "fresh vs upgraded:"; sed 's/^/        /' <<<"$left" | head -40; }
}

cmd_purge() {
    step "purge"
    local roles out
    fx postgres -q -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS medcea_db WITH (FORCE);' -c 'DROP DATABASE IF EXISTS medcea_fresh WITH (FORCE);' >/dev/null
    fx postgres -q -c "DO \$\$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'access_svc') THEN DROP ROLE access_svc; END IF; END \$\$;" >/dev/null
    roles="$(python3 "$CLI" db-roles --names | paste -sd, -),medcea_owner,authenticator,anon"
    out="$({ printf "\\\\set roles '%s'\n" "$roles"; cat apps/database/purge.sql; } | fx postgres -q -v ON_ERROR_STOP=1 2>&1)" \
        || { echo "$out"; fail purge "purge.sql"; return; }
    if diff <(fx postgres -q -tA -c "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY 1") "$IAMTEST_DIR/roles-baseline.txt" >/dev/null; then
        pass purge "pg_roles equals the fresh image's"
    else
        fail purge "roles left: $(fx postgres -q -tA -c "SELECT string_agg(rolname, ',') FROM pg_roles WHERE rolname !~ '^pg_'")"
    fi
}

cmd_serverlog() {
    step "server log"
    local log r p n=0
    log="$($KUBECTL logs -n "$FX_NS" "$FX_POD" 2>&1)"
    while read -r r p; do
        grep -qF "$p" <<<"$log" && { fail serverlog "the password of $r is in the server log"; n=$((n + 1)); }
    done < "$IAMTEST_DIR/passwords"
    [[ $n -eq 0 ]] && pass serverlog "no generated password in the server log"
}

cmd_down() {
    step "down"
    $KUBECTL delete namespace "$FX_NS" --ignore-not-found --wait=true >/dev/null && pass down "namespace $FX_NS deleted"
}

case "$1" in
    up) cmd_up ;;
    load) cmd_load ;;
    apply) cmd_apply "${2:?apply false|true}" "${3:-medcea_db}" ;;
    logins) cmd_logins "${2:?logins false|true}" ;;
    cycle) cmd_cycle ;;
    fulldown) cmd_fulldown ;;
    fresh) cmd_fresh ;;
    purge) cmd_purge ;;
    serverlog) cmd_serverlog ;;
    down) cmd_down ;;
    run)
        [[ "$KEEP" == true ]] || trap cmd_down EXIT
        cmd_up; cmd_load
        cmd_apply false; probes false; cmd_logins false
        cmd_apply true; probes true; cmd_logins true
        cmd_apply false; probes false
        cmd_cycle
        cmd_fulldown
        cmd_fresh
        cmd_serverlog
        cmd_purge
        ;;
    *) echo "unknown command $1 (--help)" >&2; exit 2 ;;
esac

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}iam-db-fixture: $1 passed.${NC}"
else
    echo -e "${RED}${BOLD}iam-db-fixture: $FAILS failure(s).${NC}"
    exit 1
fi
