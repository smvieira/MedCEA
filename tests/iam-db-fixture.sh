#!/usr/bin/env bash
# tests/iam-db-fixture.sh — IAM Phase 2a on a throwaway PostgreSQL, end to end.
#
#   tests/iam-db-fixture.sh up | load | fresh | apply MODE | access MODE | cycle | logins MODE
#                           | preflight | postgrest MODE | pgrst-flip | services | runner MODE
#                           | fulldown | purge-access | rollback-27 | serverlog | purge | down
#                           | run [--keep]
#
#   up        namespace medcea-iamtest, Secret pg (a random password, on stdin), one
#             pod from production's image digest configured like rdbms-postgresql-0
#             and Service rdbms-postgresql (tests/k8s/iam-db-fixture.yaml); records
#             the fresh image's roles; makes one random password per database role,
#             plus authenticator_legacy (the legacy config-api's, Phase 2b) (never printed)
#   load      under medcea_lock, only while it reads production: pg_dump --schema-only
#             --create, pg_dumpall --roles-only --no-role-passwords and pg_dump
#             --data-only --disable-triggers --schema=medcea (without the credential
#             tables; never schema iam). Loads roles (not postgres), schema, data and
#             tests/sql/iam-db-seed.sql, then snapshots the catalog as B0
#   apply M   apps/database/lib-db-apply.sh db_apply with IAM_DB_ROLES=M (false|true),
#             exactly what apps/database/deploy.sh runs; any psql ERROR fails it; the
#             hash chain must verify and an enforcement_* event appear on a transition only;
#             schema iam belongs to medcea_owner and access_svc lost its legacy direct
#             grants (IAM 2.7)
#   access M  IAM 2.7's account decisions: tests/iam-db.sh --section access (D1-D18,
#             as access_svc with set_actor), then access_db.sql applied a second time
#             as apps/access/deploy.sh does, and the catalog (triggers still ALWAYS) and
#             matrix sections again
#   cycle     false -> A; B0 vs A differs only by the declared delta; false = A;
#             true twice equal; false = A; true = the earlier true
#   logins M  every svc_* role and rr_admin_login logs in over TCP with its password
#             (M=true), or cannot (M=false)
#   preflight infra/lib-postgrest.sh pgrst_preflight against the database as it is:
#             before 008b IAM_POSTGREST_JWT=true is refused; with 008b and false it
#             passes (realm keys published first); with IAM_DB_ROLES=true false is refused
#   postgrest M  tests/iam-postgrest.sh --mode M: config-api verifying tokens (P1–P16)
#   pgrst-flip   tests/iam-postgrest.sh --flip: the legacy/JWT switches and their undo
#   services  IAM Phase 2.5 (IAM_DB_SERVICE_ROLES): apply false with every login role
#             allowed to log in, logins svc, the services' own statements run as their
#             roles (svcprobes), runner false-svc, then apply false without them and
#             logins false again (the roles NOLOGIN once more)
#   runner M  tests/iam-runner.sh --mode M (false|false-svc|true|legacy, IAM 2.4) with this
#             tree's schd/ and e97aab6's (extracted with git archive); a NOTE when the
#             script is not there
#   fulldown  from true: medcea_db_migrations_down_008b.sql by hand (no logins), then
#             with -v full=1 (no logins, the managed roles hold nothing, 008b's and
#             2.4's functions gone), then the code before Phase 2a's commit (PREV_REV,
#             default 9ef9852: its DDL, migrations and step-5 grants — an empty grants
#             extract is a FAIL); W1 must still pass (tests/iam-db.sh --mode legacy)
#   fresh     an empty database (medcea_fresh): apply false twice (--without-iam: no
#             schema iam), then this tree's access_db.sql and apply true (with iam); its
#             catalog must match the upgraded fixture's, apart from the seed; a database
#             with PREV27_REV's (b65cb2d) access_db.sql — schema iam without IAM 2.7's
#             functions — is refused by db_apply ("run ./apps/access/deploy.sh first")
#   purge-access  apps/access/uninstall.sh --purge-data's SQL with a unit assigned:
#             apply false passes --without-iam; access_db.sql + unit_backfill.sql then
#             record a pending_qa decision for the surviving assignment; apply true again
#   rollback-27  one mail_settings decision committed, then apps/access/rollback-2.7.sql
#             and PREV27_REV's access_db.sql apply cleanly; access_svc then holds nothing
#             outside schema iam and the managed roles nothing in it; this tree's
#             access_db.sql then brings the parked decision back
#   serverlog the pod's log holds none of the generated passwords
#   purge     drop the databases, run apps/database/purge.sql: pg_roles must equal the
#             fresh image's
#   down      delete the namespace
#   run       up, load, runner legacy, preflight;
#             apply false, probes, access false, logins false, preflight, postgrest false,
#             runner false, pgrst-flip, services;
#             apply true, probes, access true, logins true, preflight, postgrest true,
#             runner true;
#             apply false, probes (W1 again), cycle, fulldown, fresh, purge-access,
#             rollback-27, serverlog, purge, down (on exit, unless --keep)
#
# Production is only read (the dumps and the image lookup). Dumps, snapshots and the
# generated passwords live in $IAMTEST_DIR (default $TMPDIR/medcea-iamtest, mode 700).
# Exit 1 on any FAIL.

set -uo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
    sed -n '2,75p' "$0" | sed 's/^# \{0,1\}//'
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
source infra/lib-postgrest.sh   # pgrst_preflight (preflight)

FX_NS="medcea-iamtest"
FX_POD="pg"
PROD_NS="${NAMESPACE:-medcea}"
PROD_POD="rdbms-postgresql-0"
PROD_DB="${POSTGRES_DB:-medcea_db}"
CEA_DB="medcea_db"
PROJECT_NAME="${PROJECT_NAME:-medcea}"
IAMTEST_DIR="${IAMTEST_DIR:-${TMPDIR:-/tmp}/medcea-iamtest}"
PREV_REV="${PREV_REV:-9ef9852}"   # the last commit before Phase 2a (e97aab6)
PREV_SCHD_REV="${PREV_SCHD_REV:-e97aab6}"   # the scheduler code before 2.4
PREV27_REV="${PREV27_REV:-b65cb2d}"   # the access component before IAM 2.7
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

# access_sql — this tree's access_db.sql as apps/access/deploy.sh feeds it (a throwaway
# access_svc password; the fixture never logs in as access_svc). Apply with -1.
access_sql() {
    echo "SET log_statement = 'none';"; printf '\\set access_pw %s\n' "$(openssl rand -hex 20)"; cat apps/access/access_db.sql
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
          { python3 "$CLI" db-roles --passwords | awk '{print $1}'; echo mqtt_auth; echo authenticator_legacy; } | sort -u \
            | while read -r r; do printf '%s %s\n' "$r" "$(openssl rand -hex 16)"; done > "$IAMTEST_DIR/passwords" )
    fi
    grep -q '^authenticator_legacy ' "$IAMTEST_DIR/passwords" \
        || ( umask 077; printf 'authenticator_legacy %s\n' "$(openssl rand -hex 16)" >> "$IAMTEST_DIR/passwords" )
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
    # this tree's access_db.sql, as apps/access/deploy.sh applies it: production's dump
    # may predate its idempotent ALTERs (IAM 2.8: account_decision.unit_id, unit_* kinds)
    out="$(access_sql | fx "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" && pass load "access_db.sql (one transaction)" || { echo "$out" | head; fail load "access_db.sql"; }
    out="$(fx "$CEA_DB" -q -v ON_ERROR_STOP=1 < "$IAMTEST_DIR/data.sql" 2>&1)" && pass load "medcea data" || { echo "$out" | head; fail load "data"; }
    # production's IAM_DB_ROLES, before the seed resets it (cmd_cycle picks its baseline by it)
    fx "$CEA_DB" -q -tA -c "SELECT coalesce((SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'), 'false')" \
        > "$IAMTEST_DIR/prod-mode" 2>/dev/null || echo false > "$IAMTEST_DIR/prod-mode"
    out="$(fx "$CEA_DB" -q < tests/sql/iam-db-seed.sql 2>&1)" && pass load "seed" || { echo "$out" | grep -E "ERROR|DETAIL|CONTEXT|HINT|LINE" | head -20; fail load "seed"; }
    snapshot "$CEA_DB" "$IAMTEST_DIR/B0.txt" && pass load "catalog snapshot B0 ($(wc -l < "$IAMTEST_DIR/B0.txt") lines)"
}

cmd_apply() {  # MODE [DB] — DBA_SERVICE_LOGINS (env): login roles allowed to log in (2.5)
    local mode="$1" db="${2:-medcea_db}" out events
    step "apply IAM_DB_ROLES=$mode on $db${DBA_SERVICE_LOGINS:+ (service logins: $DBA_SERVICE_LOGINS)}"
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
    # IAM 2.7: schema iam normalised to medcea_owner, access_svc's grants compiled
    # (I15 compares them exactly), and the legacy direct grants gone
    # two statements: a cast to an absent schema fails at parse time, in any branch
    out="$(fx "$db" -q -tA -c "SELECT to_regnamespace('iam') IS NULL" 2>&1)"
    [[ "$out" == t ]] && out=absent || out="$(fx "$db" -q -tA -c "SELECT
              (SELECT count(*) FROM (SELECT c.relowner AS o FROM pg_class c WHERE c.relnamespace = 'iam'::regnamespace
                                      UNION ALL SELECT p.proowner FROM pg_proc p WHERE p.pronamespace = 'iam'::regnamespace
                                      UNION ALL SELECT nspowner FROM pg_namespace WHERE nspname = 'iam') x
                WHERE x.o <> 'medcea_owner'::regrole)::text
              || '|' || has_table_privilege('access_svc', 'iam.mail_template', 'DELETE')
              || '|' || has_table_privilege('access_svc', 'iam.user_status_history', 'INSERT')" 2>&1)"
    if [[ "$out" == absent ]]; then
        echo "        schema iam absent (--without-iam)"
    elif [[ "$out" == "0|false|false" ]]; then
        pass apply "schema iam owned by medcea_owner; access_svc has no DELETE on mail_template, no INSERT on user_status_history"
    else
        fail apply "schema iam: objects not owned by medcea_owner | DELETE mail_template | INSERT user_status_history = $out"
    fi
}

cmd_access() {  # MODE (after apply MODE)
    step "IAM 2.7 account decisions (mode $1)"
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --mode "$1" --write-probes --section access || FAILS=$((FAILS + 1))
    # D13: a second access deploy replaces the triggers and leaves them ALWAYS
    local out
    out="$(access_sql | fx "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" \
        && pass access "access_db.sql applied a second time (one transaction)" || { echo "$out" | head; fail access "second access_db.sql"; }
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --mode "$1" --section catalog --section matrix || FAILS=$((FAILS + 1))
}

cmd_logins() {  # MODE: false | true | svc (false with the service logins, 2.5)
    local mode="$1" r p out ok=0 bad=0
    step "logins with IAM_DB_ROLES=$mode"
    load_passwords
    while read -r r p; do
        [[ "$r" == svc_* || "$r" == iam_svc || "$r" == rr_admin_login ]] || continue
        out="$(printf '%s\n' "$p" | $KUBECTL exec -i -n "$FX_NS" "$FX_POD" -- sh -c \
            'read -r PGPASSWORD; export PGPASSWORD; exec psql -X -h 127.0.0.1 -U "$0" -d medcea_db -tAc "SELECT current_user"' "$r" 2>&1)"
        if [[ "$mode" != false && "$out" == "$r" ]] || [[ "$mode" == false && "$out" != "$r" ]]; then
            ok=$((ok + 1))
        else
            bad=$((bad + 1)); fail logins "$r: ${out:0:120}"
        fi
    done < "$IAMTEST_DIR/passwords"
    [[ $bad -eq 0 ]] && pass logins "$ok role(s) $([[ "$mode" != false ]] && echo 'log in' || echo 'cannot log in')"
}

probes() {  # MODE
    step "tests/iam-db.sh --write-probes (mode $1)"
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --mode "$1" --write-probes || FAILS=$((FAILS + 1))
}

# The declared difference between production's catalog before 2a (B0) and after
# apply false (A), for anon, authenticator, mqtt_auth, access_svc and PUBLIC. Since
# IAM 2.7 every acl line of access_svc may change: production's legacy iam grants
# (and none elsewhere) become the compiled set.
# Production may run IAM_DB_SERVICE_ROLES=true (2.5): its service roles and
# rr_admin_login then log in, and rr_admin_login inherits rr_admin, in B0 only —
# the fixture's apply false runs without the service logins.
# Production may run IAM_DB_ROLES=true: B0 is then compared with the first apply
# true (T1) instead, and the seed has reset the database setting the flag lives in.
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
^> dbsetting\|\*\|medcea\.iam_db_roles=(false|true)
^> role\|(rr_|svc_|iam_svc)
^< role\|(rr_|svc_|iam_svc)
^< member\|rr_admin\|rr_admin_login\|
^> constraint\|
^[<>] acl\|access_svc\|'
# every fact but the grants of roles outside the comparison (the managed roles are
# compared exactly by the bundle's own assertions)
scoped() { grep -vE '^acl\|' "$1"; grep -E '^acl\|(anon|authenticator|mqtt_auth|access_svc|PUBLIC)\|' "$1"; }

cmd_cycle() {
    step "cycle"
    cmd_apply false; snapshot medcea_db "$IAMTEST_DIR/A.txt"
    # production before 2a, or still false, is compared with A; an enforcing one with T1
    local prod_mode left
    prod_mode="$(cat "$IAMTEST_DIR/prod-mode" 2>/dev/null || echo false)"
    if [[ "$prod_mode" != true ]]; then
        left="$(diff <(scoped "$IAMTEST_DIR/B0.txt") <(scoped "$IAMTEST_DIR/A.txt") | grep -E '^[<>]' | grep -vEf <(printf '%s\n' "$DELTA"))"
        if [[ -z "$left" ]]; then pass cycle "B0 -> A differs only by the declared delta"
        else fail cycle "B0 -> A, undeclared differences:"; sed 's/^/        /' <<<"$left" | head -40; fi
    fi
    grep -q '^trigger|.*|iam_' "$IAMTEST_DIR/A.txt" && fail cycle "A has iam_* triggers" || pass cycle "A has no iam_* trigger"
    cmd_apply false; snapshot medcea_db "$IAMTEST_DIR/A2.txt"
    diff -q "$IAMTEST_DIR/A.txt" "$IAMTEST_DIR/A2.txt" >/dev/null && pass cycle "apply false twice: identical" \
        || { fail cycle "apply false twice differs"; diff "$IAMTEST_DIR/A.txt" "$IAMTEST_DIR/A2.txt" | head -20; }
    cmd_apply true; snapshot medcea_db "$IAMTEST_DIR/T1.txt"
    if [[ "$prod_mode" == true ]]; then
        left="$(diff <(scoped "$IAMTEST_DIR/B0.txt") <(scoped "$IAMTEST_DIR/T1.txt") | grep -E '^[<>]' | grep -vEf <(printf '%s\n' "$DELTA"))"
        if [[ -z "$left" ]]; then pass cycle "B0 (production enforcing) -> T1 differs only by the declared delta"
        else fail cycle "B0 (production enforcing) -> T1, undeclared differences:"; sed 's/^/        /' <<<"$left" | head -40; fi
    fi
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

# managed_grants — privileges the managed roles (rr_*, svc_*, iam_svc) and, since IAM 2.7,
# access_svc hold in the three schemas, their objects and the database, one per line
# (access_svc's CONNECT, which access_db.sql grants, apart)
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
       WHERE (r.rolname ~ '^(rr_|svc_)' OR r.rolname IN ('iam_svc', 'access_svc'))
         AND NOT (r.rolname = 'access_svc' AND o.obj LIKE 'database %') ORDER BY 1"
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
    # 2.4's functions go with 008b's (the down file's drop list)
    left="$(fx medcea_db -q -tA -c "SELECT string_agg(f, ', ') FROM unnest(ARRAY['medcea.retire_schedule(integer)',
              'medcea._check_run_params(integer,integer,integer,integer)', 'medcea._check_run_params(integer,integer,integer)',
              'medcea.schedule_retired_guard()', 'medcea._refuse_hidden_run(integer)']) f
             WHERE pg_catalog.to_regprocedure(f) IS NOT NULL")"
    [[ -z "$left" ]] && pass fulldown "retire_schedule, _check_run_params, schedule_retired_guard and _refuse_hidden_run gone after the full down" \
        || fail fulldown "still there after the full down: $left"
    out="$(git show "$PREV_REV:apps/database/medcea_db_ddl.sql" | fx medcea_db -q 2>&1 | grep ERROR | grep -v 'already exists\|multiple primary keys')"
    [[ -z "$out" ]] && pass fulldown "previous DDL" || { echo "$out" | head; fail fulldown "previous DDL"; }
    out="$(git show "$PREV_REV:apps/database/medcea_db_migrations.sql" | fx medcea_db -q 2>&1 | grep ERROR)"
    [[ -z "$out" ]] && pass fulldown "previous migrations" || { echo "$out" | head; fail fulldown "previous migrations"; }
    local grants_sql
    grants_sql="$(git show "$PREV_REV:apps/database/deploy.sh" | sed -n "/cat > \"\$_GRANTS_SQL\" << 'SQLEOF'/,/^SQLEOF/p" | sed '1d;$d')"
    if [[ -z "${grants_sql//[[:space:]]/}" ]]; then
        fail fulldown "no step-5 grants in $PREV_REV:apps/database/deploy.sh (PREV_REV must predate Phase 2a)"
    else
        out="$(fx medcea_db -q -v ON_ERROR_STOP=1 2>&1 <<<"$grants_sql")" && pass fulldown "previous step-5 grants ($PREV_REV)" \
            || { echo "$out" | head; fail fulldown "previous grants"; }
    fi
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --mode legacy --write-probes --section writes || FAILS=$((FAILS + 1))
}

cmd_fresh() {
    step "fresh: an empty database"
    local flag out rc
    cmd_apply false medcea_fresh
    # no access component in this database (the role access_svc is cluster-wide and exists)
    flag="$(dba_iam_flag "$FX_NS" "$FX_POD" medcea_fresh 2>&1)"
    [[ "$flag" == "--without-iam" ]] && pass fresh "without schema iam the grants are compiled --without-iam" \
        || fail fresh "dba_iam_flag without schema iam: '${flag}'"
    cmd_apply false medcea_fresh
    # then the access component (as apps/access/deploy.sh: access_db.sql, one transaction)
    out="$(access_sql | fx medcea_fresh -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" \
        && pass fresh "access_db.sql on the fresh database" || { echo "$out" | head; fail fresh "access_db.sql on the fresh database"; }
    cmd_apply true medcea_fresh
    flag="$(dba_iam_flag "$FX_NS" "$FX_POD" medcea_fresh 2>&1)"
    [[ -z "$flag" ]] && pass fresh "with IAM 2.7's schema iam the grants are compiled with iam" || fail fresh "dba_iam_flag with schema iam: '$flag'"
    snapshot medcea_fresh "$IAMTEST_DIR/F.txt"
    # the access component before IAM 2.7: schema iam without its functions is refused,
    # before anything is written (db_apply step 1a)
    fx postgres -q -c 'DROP DATABASE IF EXISTS medcea_old27 WITH (FORCE);' -c "CREATE DATABASE medcea_old27 ENCODING 'UTF8' TEMPLATE template0;" >/dev/null
    out="$({ echo "SET log_statement = 'none';"; printf '\\set access_pw %s\n' "$(openssl rand -hex 20)"
             git show "$PREV27_REV:apps/access/access_db.sql"; } | fx medcea_old27 -q -v ON_ERROR_STOP=1 -f - 2>&1)" \
        || { echo "$out" | head; fail fresh "$PREV27_REV's access_db.sql on an empty database"; }
    load_passwords
    out="$(CEA_DB=medcea_old27 db_apply "$FX_NS" "$FX_POD" false 2>&1)"; rc=$?
    if [[ $rc -ne 0 ]] && grep -q 'run ./apps/access/deploy.sh first' <<<"$out"; then
        pass fresh "schema iam from $PREV27_REV (no IAM 2.7 functions): db_apply refuses"
    else
        fail fresh "db_apply with $PREV27_REV's schema iam: exit $rc, $(grep -m1 -E 'ERROR|access' <<<"$out")"
    fi
    out="$(fx medcea_old27 -q -tA -c "SELECT to_regnamespace('medcea') IS NULL")"
    [[ "$out" == t ]] && pass fresh "the refusal wrote nothing (no schema medcea)" || fail fresh "the refused db_apply created schema medcea"
    fx postgres -q -c 'DROP DATABASE IF EXISTS medcea_old27 WITH (FORCE);' >/dev/null
    local f got
    for f in 'medcea.retire_schedule(integer)' 'medcea._check_run_params(integer,integer,integer,integer)'; do
        if ! grep -q "${f%%(*}" apps/database/medcea_db_migrations.sql || ! grep -q 'retire_schedule' apps/database/medcea_db_migrations.sql; then
            echo "        NOTE  $f is not in this tree's migrations (2.4 not merged): not checked"
            continue
        fi
        got="$(fx medcea_fresh -q -tA -c "SELECT pg_catalog.to_regprocedure('$f') IS NOT NULL")"
        [[ "$got" == t ]] && pass fresh "$f exists on a fresh install" || fail fresh "$f missing on a fresh install"
    done
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

# apps/access/uninstall.sh --purge-data with a unit still assigned, then the database
# and access deploys again (IAM 2.7, spec 7.2 step 3)
cmd_purge_access() {
    step "purge-access: access --purge-data with a unit assigned, then both deploys"
    local out n flag
    # medcea_fresh (step fresh) holds grants of access_svc, which DROP ROLE would refuse
    fx postgres -q -c 'DROP DATABASE IF EXISTS medcea_fresh WITH (FORCE);' >/dev/null
    # one assignment in effect, committed, as apps/iam/units.sh assign --bootstrap makes it
    # (--by an admin account); a plain assign would only wait for qa, with nothing to survive
    out="$(fx "$CEA_DB" -q -1 -tA -v ON_ERROR_STOP=1 -f - 2>&1 <<SQL
SELECT unit_id AS uid FROM medcea.cea_unit WHERE unit_code = 'IAMT01' \\gset
\\set assign true
\\set bootstrap true
\\set sub '11111111-1111-4111-8111-1111111127a7'
\\set username test-purge
\\set person p-purge
\\set units :uid
\\set reason 'iam-db-fixture purge-access'
\\set by_sub '77777777-7777-4777-8777-7777777727a7'
\\set by_person p-ad-purge
\\set by_name test-ad-purge
$(cat apps/iam/units.sql)
SQL
)" || { echo "$out" | head; fail purge-access "units.sql assign"; return; }
    # what uninstall.sh --purge-data runs
    out="$(fx "$CEA_DB" -q -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS iam CASCADE;" \
              -c "DO \$\$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'access_svc') THEN DROP OWNED BY access_svc; END IF; END \$\$;" 2>&1 \
           && fx postgres -q -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS access_svc;" 2>&1)" \
        || { echo "$out" | head; fail purge-access "the purge"; return; }
    n="$(fx "$CEA_DB" -q -tA -c "SELECT count(*) FROM iam_policy.user_unit")"
    [[ "$n" -ge 1 ]] && pass purge-access "$n unit assignment(s) survive the purge" || fail purge-access "no assignment survived: $n"
    flag="$(dba_iam_flag "$FX_NS" "$FX_POD" "$CEA_DB" 2>&1)"
    [[ "$flag" == "--without-iam" ]] && pass purge-access "after the purge: --without-iam" || fail purge-access "dba_iam_flag after the purge: '$flag'"
    cmd_apply false
    # the access deploy: access_db.sql, then the backfill
    out="$(access_sql | fx "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" \
        && pass purge-access "access_db.sql after the purge" || { echo "$out" | head; fail purge-access "access_db.sql after the purge"; return; }
    out="$(fx "$CEA_DB" -q -1 -tA -v ON_ERROR_STOP=1 -f - < apps/access/unit_backfill.sql 2>&1)" \
        || { echo "$out" | head; fail purge-access "unit_backfill.sql"; return; }
    [[ "$(grep -c '^backfilled|' <<<"$out")" == "$n" ]] && pass purge-access "unit_backfill.sql recorded $n decision(s)" \
        || fail purge-access "unit_backfill.sql printed $(grep -c '^backfilled|' <<<"$out") line(s) for $n assignment(s)"
    out="$(fx "$CEA_DB" -q -tA -c "SELECT count(*) FROM iam_policy.user_unit uu WHERE NOT EXISTS (
              SELECT 1 FROM iam.account_decision d WHERE d.keycloak_user_id = uu.person_sub::text AND d.unit_id = uu.unit_id
                 AND d.kind = 'unit_assign' AND d.status = 'pending_qa' AND d.made_by_sub IS NULL AND d.subject_person IS NULL
                 AND d.made_by_name = 'system:deploy (backfill)')")"
    [[ "$out" == 0 ]] && pass purge-access "every surviving assignment has a pending_qa bootstrap decision" \
        || fail purge-access "$out assignment(s) without their backfilled decision"
    out="$(fx "$CEA_DB" -q -1 -tA -v ON_ERROR_STOP=1 -f - < apps/access/unit_backfill.sql 2>&1)"
    grep -q '^backfilled|' <<<"$out" && fail purge-access "a second backfill recorded again" || pass purge-access "a second backfill records nothing"
    cmd_apply true
}

# IAM 2.7's rollback (spec 7.4 steps 2-3) with a mail_settings decision committed
cmd_rollback27() {
    step "rollback-27: apps/access/rollback-2.7.sql, then $PREV27_REV's access_db.sql"
    local out left
    [[ -f apps/access/rollback-2.7.sql ]] || { fail rollback-27 "apps/access/rollback-2.7.sql is not in this tree"; return; }
    out="$(fx "$CEA_DB" -q -1 -tA -v ON_ERROR_STOP=1 -f - 2>&1 <<'SQL'
SET SESSION AUTHORIZATION access_svc;
SELECT medcea_auth.set_actor('77777777-7777-4777-8777-7777777727a8', 'p-ad-rollback', 'test-ad-rollback', 'admin') \g /dev/null
SELECT decision_id AS d FROM iam.record_decision('mail_settings', NULL, NULL, NULL, NULL, NULL, NULL, 'iam-db-fixture rollback-27', NULL) \gset
INSERT INTO iam.mail_settings_pending (smtp_user, smtp_pass, decision_id) VALUES ('iamt@example.invalid', 'x', :d);
SQL
)" && pass rollback-27 "a mail_settings decision committed" || { echo "$out" | head; fail rollback-27 "the mail_settings decision"; return; }
    out="$(fx "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - < apps/access/rollback-2.7.sql 2>&1)" \
        && pass rollback-27 "rollback-2.7.sql" || { echo "$out" | grep -E 'ERROR|DETAIL' | head; fail rollback-27 "rollback-2.7.sql"; return; }
    out="$({ echo "SET log_statement = 'none';"; printf '\\set access_pw %s\n' "$(openssl rand -hex 20)"
             git show "$PREV27_REV:apps/access/access_db.sql"; } | fx "$CEA_DB" -q -v ON_ERROR_STOP=1 -f - 2>&1)" \
        && pass rollback-27 "$PREV27_REV's access_db.sql applies after it" || { echo "$out" | grep -E 'ERROR|DETAIL' | head; fail rollback-27 "$PREV27_REV's access_db.sql"; }
    left="$(fx "$CEA_DB" -q -tA -c "
      WITH o AS (
        SELECT c.relacl AS acl, c.oid::regclass::text AS obj, c.relnamespace AS ns FROM pg_class c
        UNION ALL SELECT p.proacl, p.oid::regprocedure::text, p.pronamespace FROM pg_proc p
        UNION ALL SELECT n.nspacl, 'schema ' || n.nspname, n.oid FROM pg_namespace n)
      SELECT r.rolname || ' ' || x.privilege_type || ' ' || o.obj
        FROM o CROSS JOIN LATERAL aclexplode(o.acl) x JOIN pg_roles r ON r.oid = x.grantee
       WHERE (r.rolname = 'access_svc' AND o.ns::regnamespace::text IN ('medcea', 'medcea_auth', 'iam_policy'))
          OR ((r.rolname ~ '^(rr_|svc_)' OR r.rolname = 'iam_svc') AND o.ns = to_regnamespace('iam'))
       ORDER BY 1")"
    [[ -z "$left" ]] && pass rollback-27 "access_svc holds nothing outside iam, the managed roles nothing in iam" \
        || { fail rollback-27 "still held after the rollback:"; sed 's/^/        /' <<<"$left" | head -20; }
    out="$(fx "$CEA_DB" -q -tA -c "SELECT count(*) FROM iam.account_decision WHERE kind = 'mail_settings'" 2>&1)"
    [[ "$out" == 0 ]] && pass rollback-27 "the mail_settings decision is parked (not in iam.account_decision)" \
        || fail rollback-27 "iam.account_decision still holds $out mail_settings decision(s)"
    # and forward again: this tree's access_db.sql brings the parked rows back
    out="$(access_sql | fx "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" \
        && pass rollback-27 "this tree's access_db.sql applies after the rollback" || { echo "$out" | grep -E 'ERROR|DETAIL' | head; fail rollback-27 "access_db.sql after the rollback"; return; }
    out="$(fx "$CEA_DB" -q -tA -c "SELECT (SELECT count(*) FROM iam.account_decision WHERE kind = 'mail_settings' AND status = 'pending_qa')
                                    || '|' || (SELECT count(*) FROM iam.mail_settings_pending)
                                    || '|' || (to_regnamespace('iam_retired_27') IS NULL)" 2>&1)"
    [[ "$out" == "1|1|true" ]] && pass rollback-27 "the parked decision and its staged settings are back; iam_retired_27 is gone" \
        || fail rollback-27 "after re-applying access_db.sql: decisions|staged|retired schema gone = $out (want 1|1|true)"
}

cmd_purge() {
    step "purge"
    local roles out
    fx postgres -q -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS medcea_db WITH (FORCE);' -c 'DROP DATABASE IF EXISTS medcea_fresh WITH (FORCE);' \
        -c 'DROP DATABASE IF EXISTS medcea_old27 WITH (FORCE);' >/dev/null
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

cmd_preflight() {
    step "preflight: infra/lib-postgrest.sh pgrst_preflight against the database as it is"
    local out rc
    load_passwords
    # the fixture's authenticator passwords, as apps/frontend/deploy.sh would see config.env
    local AUTHENTICATOR_DB_PASS="$DBPW_authenticator" POSTGRES_PASS="$DBPW_authenticator_legacy"
    if ! pgrst_db_present "$FX_NS" "$FX_POD" "$CEA_DB"; then
        out="$(pgrst_preflight true "$FX_NS" "$FX_POD" "$CEA_DB" 2>&1)"; rc=$?
        [[ $rc -ne 0 ]] && grep -q 'pre_request' <<<"$out" \
            && pass preflight "before 008b: IAM_POSTGREST_JWT=true refused (no pre_request)" \
            || { echo "$out" | sed 's/^/        /'; fail preflight "before 008b: true was not refused for the missing pre_request"; }
        return
    fi
    # realm keys published as deploy-infra.sh does, so only the database decides
    tests/iam-postgrest.sh --namespace "$FX_NS" --keys --dir "$IAMTEST_DIR" >/dev/null 2>&1 \
        || { fail preflight "could not publish the test realm keys"; return; }
    if pgrst_db_enforcing "$FX_NS" "$FX_POD" "$CEA_DB"; then
        out="$(pgrst_preflight false "$FX_NS" "$FX_POD" "$CEA_DB" 2>&1)"; rc=$?
        [[ $rc -ne 0 ]] && grep -q 'IAM_DB_ROLES=true' <<<"$out" \
            && pass preflight "IAM_DB_ROLES=true: IAM_POSTGREST_JWT=false refused" \
            || { echo "$out" | sed 's/^/        /'; fail preflight "IAM_DB_ROLES=true: false was not refused"; }
        out="$(pgrst_preflight true "$FX_NS" "$FX_POD" "$CEA_DB" 2>&1)" \
            && pass preflight "IAM_DB_ROLES=true: IAM_POSTGREST_JWT=true passes" \
            || { echo "$out" | sed 's/^/        /'; fail preflight "IAM_DB_ROLES=true: true refused"; }
    else
        out="$(pgrst_preflight true "$FX_NS" "$FX_POD" "$CEA_DB" 2>&1)" \
            && pass preflight "008b, IAM_DB_ROLES=false: IAM_POSTGREST_JWT=true passes" \
            || { echo "$out" | sed 's/^/        /'; fail preflight "008b: true refused"; }
        out="$(pgrst_preflight false "$FX_NS" "$FX_POD" "$CEA_DB" 2>&1)" \
            && pass preflight "008b, IAM_DB_ROLES=false: IAM_POSTGREST_JWT=false passes" \
            || { echo "$out" | sed 's/^/        /'; fail preflight "008b: false refused"; }
        out="$(AUTHENTICATOR_DB_PASS="" pgrst_preflight true "$FX_NS" "$FX_POD" "$CEA_DB" 2>&1)" \
            && fail preflight "an empty AUTHENTICATOR_DB_PASS was not refused" \
            || pass preflight "an empty AUTHENTICATOR_DB_PASS is refused"
    fi
}

cmd_postgrest() {  # MODE
    step "tests/iam-postgrest.sh --mode $1"
    tests/iam-postgrest.sh --namespace "$FX_NS" --mode "$1" --dir "$IAMTEST_DIR" || FAILS=$((FAILS + 1))
}

# svcprobe ROLE LABEL WANT — SQL on stdin, as ROLE (SET SESSION AUTHORIZATION, so
# rr_admin_login inherits rr_admin as when it logs in), in BEGIN … ROLLBACK.
# WANT: ok, or "denied" (a permission error expected).
svcprobe() {
    local role="$1" label="$2" want="$3" out
    out="$( { echo "BEGIN;"; echo "SET SESSION AUTHORIZATION $role;"; cat; echo "SELECT 'probe-done';"; echo "ROLLBACK;"; } \
            | fx medcea_db -q -tA -v ON_ERROR_STOP=1 -f - 2>&1)"
    if [[ "$want" == ok ]]; then
        grep -q 'probe-done' <<<"$out" && pass svc "$role: $label" || fail svc "$role: $label: $(grep -m1 ERROR <<<"$out")"
    else
        grep -q 'permission denied' <<<"$out" && pass svc "$role: $label (refused)" \
            || fail svc "$role: $label: expected permission denied, got: $(grep -m1 -E 'ERROR|probe-done' <<<"$out")"
    fi
}

# Each service's own statements (the 2.5 inventory: monitor-api.py, dbmgmt-api.py,
# Node-RED's INSERT, the Grafana dashboard, pgAdmin's rr_admin), as its role. The
# scheduler's are tests/iam-runner.sh --mode false-svc.
cmd_svcprobes() {
    step "the services' statements as their own roles (IAM 2.5)"
    svcprobe svc_monitor "runs, cycles, telemetry views" ok <<'SQL'
SELECT count(*) FROM medcea.recipe_run r JOIN medcea.cea_unit u ON u.unit_id = r.unit_id JOIN medcea.recipe c ON c.recipe_id = r.recipe_id;
SELECT count(*) FROM medcea.recipe_line l, medcea.recipe_line_cycle_run x WHERE x.recipe_run_id IS NOT NULL LIMIT 1;
SELECT count(*) FROM medcea.v_ap_measurements;
SELECT count(*) FROM medcea.v_ct_measurements;
SQL
    svcprobe svc_dbexport "every listed table and view, every sequence's definition" ok <<'SQL'
DO $$
DECLARE r record; n int := 0;
BEGIN
    FOR r IN SELECT table_name FROM information_schema.tables WHERE table_schema = 'medcea'
             UNION SELECT table_name FROM information_schema.views WHERE table_schema = 'medcea' LOOP
        EXECUTE format('SELECT 1 FROM medcea.%I LIMIT 1', r.table_name);
        n := n + 1;
    END LOOP;
    IF n < 20 THEN RAISE EXCEPTION 'only % objects listed', n; END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_sequence s JOIN pg_catalog.pg_class c ON c.oid = s.seqrelid
         WHERE c.relnamespace = 'medcea'::regnamespace) = 0 THEN
        RAISE EXCEPTION 'no sequence readable through pg_catalog';
    END IF;
END $$;
SQL
    svcprobe svc_dbexport "a credential table" denied <<'SQL'
SELECT 1 FROM medcea.mqtt_credential LIMIT 1;
SQL
    svcprobe svc_ingest "Node-RED's INSERT of a reading" ok <<'SQL'
INSERT INTO medcea.measurement (measure_timestamp, device_id, device_dns, msg_type, msg)
VALUES (clock_timestamp(), 'iamt-aa:bb:cc:00:00:01', 'iamt02-s-z01', 'AP', '{"tag": "air_temperature", "value": 1}');
SQL
    svcprobe svc_ingest "changing a reading" denied <<'SQL'
UPDATE medcea.measurement SET msg = msg WHERE device_id = 'iamt-aa:bb:cc:00:00:01';
SQL
    svcprobe svc_grafana "the dashboard's queries" ok <<'SQL'
SELECT DISTINCT unit_code FROM medcea.msg_actual_points ORDER BY unit_code;
SELECT zone_code, device_dns, MAX(CASE WHEN tag = 'air_temperature' THEN ROUND(value::numeric, 1) END), MAX(record_timestamp)
  FROM medcea.msg_actual_points WHERE unit_code = 'IAMT02' GROUP BY zone_code, device_dns ORDER BY zone_code;
SQL
    svcprobe rr_admin_login "pgAdmin reads master data through rr_admin" ok <<'SQL'
SELECT count(*) FROM medcea.cea_unit;
SELECT count(*) FROM medcea.device;
SQL
    svcprobe rr_admin_login "pgAdmin writing master data" denied <<'SQL'
UPDATE medcea.cea_unit SET unit_code = unit_code;
SQL
}

cmd_services() {
    step "IAM Phase 2.5: IAM_DB_SERVICE_ROLES (database still IAM_DB_ROLES=false)"
    DBA_SERVICE_LOGINS="$(python3 apps/iam/compiler/cli.py db-roles --logins | paste -sd, -)" cmd_apply false
    cmd_logins svc
    cmd_svcprobes
    cmd_runner false-svc
    cmd_apply false
    cmd_logins false
}

cmd_pgrst_flip() {
    step "tests/iam-postgrest.sh --flip"
    tests/iam-postgrest.sh --namespace "$FX_NS" --flip --dir "$IAMTEST_DIR" || FAILS=$((FAILS + 1))
}

cmd_runner() {  # MODE (contract C2 of the Phase 2b/2.4 spec)
    step "tests/iam-runner.sh --mode $1"
    if [[ ! -x tests/iam-runner.sh ]]; then
        echo "        NOTE  tests/iam-runner.sh is not in this tree (IAM Phase 2.4): skipped"
        return
    fi
    local prev="$IAMTEST_DIR/prev-$PREV_SCHD_REV"
    if [[ ! -d "$prev/schd" ]]; then
        mkdir -p "$prev"
        git archive "$PREV_SCHD_REV" schd apps/scheduler apps/iam | tar -x -C "$prev" \
            || { fail runner "cannot extract $PREV_SCHD_REV's schd/"; return; }
    fi
    tests/iam-runner.sh --namespace "$FX_NS" --mode "$1" --dir "$IAMTEST_DIR" \
        --schd "$REPO_ROOT/schd" --prev-schd "$prev/schd" || FAILS=$((FAILS + 1))
}

cmd_down() {
    step "down"
    $KUBECTL delete namespace "$FX_NS" --ignore-not-found --wait=true >/dev/null && pass down "namespace $FX_NS deleted"
}

case "$1" in
    up) cmd_up ;;
    load) cmd_load ;;
    apply) cmd_apply "${2:?apply false|true}" "${3:-medcea_db}" ;;
    access) cmd_access "${2:?access false|true}" ;;
    purge-access) cmd_purge_access ;;
    rollback-27) cmd_rollback27 ;;
    logins) cmd_logins "${2:?logins false|true}" ;;
    preflight) cmd_preflight ;;
    postgrest) cmd_postgrest "${2:?postgrest false|true}" ;;
    pgrst-flip) cmd_pgrst_flip ;;
    services) cmd_services ;;
    svcprobes) cmd_svcprobes ;;
    runner) cmd_runner "${2:?runner false|true|legacy}" ;;
    cycle) cmd_cycle ;;
    fulldown) cmd_fulldown ;;
    fresh) cmd_fresh ;;
    purge) cmd_purge ;;
    serverlog) cmd_serverlog ;;
    down) cmd_down ;;
    run)
        [[ "$KEEP" == true ]] || trap cmd_down EXIT
        cmd_up; cmd_load; cmd_runner legacy
        cmd_preflight
        cmd_apply false; probes false; cmd_access false; cmd_logins false; cmd_preflight
        cmd_postgrest false; cmd_runner false; cmd_pgrst_flip
        cmd_services
        cmd_apply true; probes true; cmd_access true; cmd_logins true; cmd_preflight
        cmd_postgrest true; cmd_runner true
        cmd_apply false; probes false
        cmd_cycle
        cmd_fulldown
        cmd_fresh
        cmd_purge_access
        cmd_rollback27
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
