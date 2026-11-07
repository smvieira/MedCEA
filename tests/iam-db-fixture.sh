#!/usr/bin/env bash
# tests/iam-db-fixture.sh — IAM Phase 2a on a throwaway PostgreSQL, end to end.
#
#   tests/iam-db-fixture.sh up | load | fresh | apply MODE | access MODE | policy | policy-apply
#                           | cycle | logins MODE
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
#   policy    IAM 4.1 (migration 008c), after access true: tests/iam-db.sh --section policy
#             --write-probes (P1-P18); medcea_db_migrations_down_008c.sql on the database
#             without versions (wrappers gone, three tables parked), then apply true (008c
#             moves them back, P1 again); version 1 built COMMITTED from defaults.yaml through
#             the owner functions (the bootstrap's bundle without apply.sh); apply true again:
#             the 008c catalog (constraints, triggers, sha256 of every function, owners), the
#             version rows and entries_digest(1) unchanged, no policy event written; apply
#             false then true (a mode flip with v1); down_008c refused while v1 exists
#   policy-apply  IAM 4.2a, on a fresh database (medcea_pa, with this tree's access
#             component): tests/iam-db.sh --section policy --write-probes --mode false
#             (P2-P26 but the token path; P26 pre_request's only_rpc under false); P22:
#             apps/iam/apply_check.py simulate-state + bundle-sql, then dba_policy_bundle
#             auto --with-functions as system:apply COMMITTED (the bootstrap's bundle):
#             version 1 applied, entries_digest(1) = Python's, bootstrap_applied recorded,
#             audit_versions() empty; apply true twice (008c re-run with v1 and the 4.2a
#             bodies: the snapshot equal, no event under a version); down_008c refused. On
#             a second fresh database (medcea_pa2) a failing statement in the bundle and a
#             REPEATABLE READ default each roll the whole bundle back (no version row);
#             then, with the access component and apply true, the bundle under
#             IAM_DB_ROLES=true commits version 1 (POST runs as system:apply again).
#             IAM 4.5, under this run's lock (DBA_STAGED needs it; taken for these steps
#             only), every bundle compiled by cli.py --staged from the version's staged
#             host file: P38 a change version applied (true on medcea_pa, false on
#             medcea_pa2: superseded, the new grants, role_widening's digest, applied
#             recorded); P41 the PRE/POST asserts refuse a file of another version
#             (forward and revert), a skipped skeleton accept and a withdrawn version;
#             P39 the revert to the previous version (its grants back, partial_apply
#             {reverting} then {reverted} and applied {reverted_from}, one_open);
#             P40 a skeleton version (accepted, reviewed_by_version, apply_started);
#             P42 a rollback to the confirmed version 1 (its rows read in SQL, the open
#             draft withdrawn); P44 confirmed by another qa person only; P45 a forged
#             checker verdict refused by cli.py --staged check; P46 008c re-run twice
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
#             apply true, probes, access true, policy, policy-apply, logins true, preflight,
#             postgrest true, runner true;
#             apply false, probes (W1 again), cycle, fulldown, fresh, purge-access,
#             rollback-27, serverlog, purge, down (on exit, unless --keep)
#
# Production is only read (the dumps and the image lookup). Dumps, snapshots and the
# generated passwords live in $IAMTEST_DIR (default $TMPDIR/medcea-iamtest, mode 700).
# Exit 1 on any FAIL.

set -uo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
    sed -n '2,106p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
source infra/lib-log.sh; medcea_log "iam-db-fixture-$1"   # logs/iam-db-fixture-<command>-<ts>.log
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
fx() {  # with -f -, the whole script is read before psql starts (as _dba_psql)
    local db="$1"; shift
    local run='PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -U postgres -d "$0" "$@"'
    case " $* " in
        *" -f - "*) run='sql="$(cat; echo .)"; PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"; export PGPASSWORD
printf %s "${sql%.}" | psql -X -U postgres -d "$0" "$@"' ;;
    esac
    $KUBECTL exec -i -n "$FX_NS" "$FX_POD" -- env PGOPTIONS="-c client_min_messages=warning" \
        sh -c "$run" "$db" "$@"
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

# policy_snapshot — what a re-run of 008c must leave alone (IAM 4.1): version's
# constraints, the freeze triggers' modes, sha256 of every 008c function, the table owners,
# the version rows and entries_digest of each
policy_snapshot() {
    fx "$CEA_DB" -q -tA -v ON_ERROR_STOP=1 <<'SQL'
SELECT 'con|' || conname || '|' || pg_get_constraintdef(oid) FROM pg_constraint
 WHERE conrelid = 'iam_policy.version'::regclass ORDER BY conname;
SELECT 'trg|' || c.relname || '|' || t.tgname || '|' || t.tgenabled::text FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = 'iam_policy'::regnamespace AND NOT t.tgisinternal ORDER BY 1;
SELECT 'fn|' || p.oid::regprocedure::text || '|' || encode(sha256(convert_to(p.prosrc, 'UTF8')), 'hex') || '|' || pg_get_userbyid(p.proowner) || '|' || coalesce(p.proacl::text, '')
  FROM pg_proc p WHERE p.pronamespace = 'iam_policy'::regnamespace
     OR p.oid IN (to_regprocedure('medcea.approve_policy(integer,text,text,text,text)'), to_regprocedure('medcea.return_policy(integer,text)'),
                  to_regprocedure('medcea.confirm_policy(integer,text,text)'), to_regprocedure('medcea.dispute_policy(integer,text)'))
 ORDER BY 1;
SELECT 'own|' || c.relname || '|' || pg_get_userbyid(c.relowner) FROM pg_class c
 WHERE c.relnamespace = 'iam_policy'::regnamespace AND c.relkind = 'r' ORDER BY 1;
SELECT 'ver|' || v.version || '|' || v.status || '|' || v.kind || '|' || v.entries_digest || '|' || iam_policy.entries_digest(v.version)
  FROM iam_policy.version v ORDER BY v.version;
SQL
}

# snapshot_whole SNAP — every section is there (a query that fails half way, as the
# "char" || text one did, must not leave two equal partial snapshots that pass)
snapshot_whole() {
    local k
    for k in con trg fn own ver; do grep -q "^$k|" <<<"$1" || return 1; done
}

# v1_sql — version 1 from defaults.yaml, as apply.sh --bootstrap's bundle builds it
# (4.2a): accept the git skeleton, sync role/resource_group, build, apply, record
v1_sql() {
    python3 - "$REPO_ROOT" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1] + "/apps/iam")
from compiler import source
d = source.factory()
sk, ew = json.dumps(source.skeleton(d)), source.entries_and_waivers(d)
def dq(text, tag):
    assert f"${tag}$" not in text
    return f"${tag}${text}${tag}$"
print(f"SELECT iam_policy._accept_skeleton('{source.skeleton_digest(d)}', {dq(sk, 'sk')}::jsonb, 'iam-db-fixture', NULL, '{{}}'::jsonb);")
print(f"SELECT iam_policy._sync_skeleton({dq(sk, 'sk')}::jsonb, 'iam-db-fixture');")
print(f"SELECT iam_policy._build_version('bootstrap', {dq(json.dumps(ew['entries']), 'e')}::jsonb, "
      f"{dq(json.dumps(ew['waivers']), 'w')}::jsonb, NULL, NULL, 'iam-db-fixture: version 1 from defaults.yaml') AS v1 \\gset")
print("SELECT iam_policy._mark_applied(:v1, '{\"git_commit\": \"iam-db-fixture\"}'::jsonb, 'iam-db-fixture', NULL, NULL, NULL);")
print("SELECT iam_policy._record('bootstrap_applied', jsonb_build_object('version', :v1));")
print(f"SELECT 'digest|' || (iam_policy.entries_digest(:v1) = '{source.policy_entries_digest(d)}');")
PY
}

cmd_policy() {  # after apply true (IAM 4.1)
    step "IAM 4.1: migration 008c, the policy's versions"
    local out snap1 snap2 ev
    [[ "$(fx "$CEA_DB" -q -tA -c "SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'")" == true ]] || cmd_apply true
    if [[ "$(fx "$CEA_DB" -q -tA -c "SELECT count(*) FROM iam_policy.version")" != 0 ]]; then
        fail policy "versions exist already: the policy step needs a fixture without versions (run it once, after access true)"
        return
    fi
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --mode true --write-probes --section policy || FAILS=$((FAILS + 1))
    # the down file on a database without versions, then 008c brings everything back
    out="$(fx "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 < apps/database/medcea_db_migrations_down_008c.sql 2>&1)" \
        && pass policy "medcea_db_migrations_down_008c.sql without versions" || { echo "$out" | grep ERROR; fail policy "down_008c failed"; return; }
    out="$(fx "$CEA_DB" -q -tA -c "SELECT (SELECT count(*) FROM pg_proc WHERE proname IN ('approve_policy', 'return_policy', 'confirm_policy', 'dispute_policy'))
                                     || '|' || (SELECT count(*) FROM pg_class WHERE relnamespace = to_regnamespace('iam_policy_retired_008c') AND relkind = 'r')
                                     || '|' || (SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'freeze_policy%')")"
    [[ "$out" == "0|3|0" ]] && pass policy "down_008c: no wrapper, three tables parked, no freeze trigger" || fail policy "after down_008c (wrappers|parked|triggers): $out"
    cmd_apply true
    out="$(fx "$CEA_DB" -q -tA -c "SELECT to_regnamespace('iam_policy_retired_008c') IS NULL AND to_regclass('iam_policy.approval_evidence') IS NOT NULL")"
    [[ "$out" == t ]] && pass policy "008c moved the parked tables back and dropped the schema" || fail policy "parked tables not back: $out"
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --mode true --section policy || FAILS=$((FAILS + 1))
    # version 1, committed
    out="$(v1_sql | fx "$CEA_DB" -q -tA -1 -v ON_ERROR_STOP=1 2>&1)"
    if grep -q 'ERROR' <<<"$out"; then
        grep ERROR <<<"$out" | head; fail policy "version 1 through the owner functions"; return
    fi
    grep -q '^digest|true$' <<<"$out" && pass policy "version 1 committed; entries_digest(1) = source.policy_entries_digest(defaults.yaml)" \
        || fail policy "entries_digest(1) differs from compiler/source.py: $(grep '^digest|' <<<"$out")"
    snap1="$(policy_snapshot)" && snapshot_whole "$snap1" || { fail policy "policy_snapshot failed: the re-run checks would compare nothing"; return; }
    ev="$(fx "$CEA_DB" -q -tA -c "SELECT max(event_id) FROM iam_policy.history")"
    cmd_apply true
    snap2="$(policy_snapshot)" && snapshot_whole "$snap2" || { fail policy "policy_snapshot failed after the re-run"; return; }
    [[ "$snap1" == "$snap2" ]] && pass policy "008c re-run with v1: constraints, triggers, functions, owners, versions and digests unchanged" \
        || { fail policy "008c re-run with v1 changed the catalog or the versions:"; diff <(echo "$snap1") <(echo "$snap2") | head -20; }
    out="$(fx "$CEA_DB" -q -tA -c "SELECT coalesce(string_agg(event, ','), '') FROM iam_policy.history WHERE event_id > $ev AND version IS NOT NULL")"
    [[ -z "$out" ]] && pass policy "the re-run wrote no policy event" || fail policy "the re-run wrote policy events: $out"
    cmd_apply false
    cmd_apply true
    snap2="$(policy_snapshot)" && snapshot_whole "$snap2" || { fail policy "policy_snapshot failed after the mode flip"; return; }
    [[ "$(grep '^ver|' <<<"$snap1")" == "$(grep '^ver|' <<<"$snap2")" ]] && pass policy "a mode flip with v1 leaves the versions and digests alone" \
        || fail policy "the mode flip changed the versions: $(grep '^ver|' <<<"$snap2")"
    out="$(fx "$CEA_DB" -q -1 -v ON_ERROR_STOP=1 < apps/database/medcea_db_migrations_down_008c.sql 2>&1)"
    grep -q 'policy versions exist' <<<"$out" && pass policy "down_008c refused while version 1 exists" || fail policy "down_008c with v1: ${out:-it ran}"
}

# policy_bundle_sql DIR — apply.sh --bootstrap's PRE and POST (apps/iam/apply_check.py,
# IAM 4.2a §14.4.10) for a state document simulated from defaults.yaml, into DIR
policy_bundle_sql() {
    local dir="$1"
    python3 apps/iam/apply_check.py simulate-state --out "$dir/state.json" \
        && python3 apps/iam/apply_check.py bundle-sql --kind bootstrap --state "$dir/state.json" \
               --by-sub 77777777-7777-4777-8777-777777777777 --by-person p-iam-db-fixture \
               --log iam-db-fixture --out "$dir"
}

# pa_bundle DB DIR POST [MODE] — the bootstrap bundle as apply.sh runs it (IAM_DB_ROLES=MODE,
# default false)
pa_bundle() {
    load_passwords
    IAM_DB_ROLES="${4:-false}" CEA_DB="$1" DBA_ACTOR=system:apply DBA_SERVICE_LOGINS="" \
        dba_policy_bundle "$FX_NS" "$FX_POD" auto "$2/pre.sql" "$3" --with-functions 2>&1
}

cmd_policy_apply() {  # IAM 4.2a, after policy (a fresh database: medcea_pa, medcea_pa2)
    policy_apply_steps
    policy_apply_45   # IAM 4.5, on the same two databases (version 1 applied on each)
    # whatever the steps did: their applies ran IAM_DB_ROLES=false, and role LOGIN and
    # membership are cluster-wide, so medcea_db's mode goes back to the roles (as fresh
    # does); and the two databases go, or access_svc cannot be dropped by purge-access
    fx postgres -q -c "DROP DATABASE IF EXISTS medcea_pa WITH (FORCE);" -c "DROP DATABASE IF EXISTS medcea_pa2 WITH (FORCE);" >/dev/null
    cmd_apply true
}

policy_apply_steps() {
    step "IAM 4.2a: the bootstrap bundle, _record's actors, the filter (fresh databases)"
    local db=medcea_pa dir out rc snap1 snap2 ev
    dir="$(mktemp -d "$IAMTEST_DIR/pa-XXXXXX")"
    fx postgres -q -c "DROP DATABASE IF EXISTS medcea_pa WITH (FORCE);" -c "DROP DATABASE IF EXISTS medcea_pa2 WITH (FORCE);" >/dev/null
    cmd_apply false "$db"
    out="$(access_sql | fx "$db" -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" \
        && pass policy-apply "access_db.sql on $db" || { echo "$out" | head; fail policy-apply "access_db.sql on $db"; return; }
    cmd_apply false "$db"
    # every policy probe that needs no token, and P26 (pre_request's only_rpc under false)
    tests/iam-db.sh --namespace "$FX_NS" --pod "$FX_POD" --db "$db" --mode false --write-probes --section policy \
        || FAILS=$((FAILS + 1))
    # P22 — the bootstrap's bundle, committed
    if ! out="$(policy_bundle_sql "$dir" 2>&1)"; then
        fail P22 "apply_check.py simulate-state/bundle-sql: ${out:0:300}"; rm -rf "$dir"; return
    fi
    out="$(pa_bundle "$db" "$dir" "$dir/post.sql")"; rc=$?
    [[ $rc -eq 0 ]] && pass P22 "dba_policy_bundle auto --with-functions as system:apply: committed" \
        || { grep -E 'ERROR|DETAIL' <<<"$out" | head; fail P22 "the bootstrap bundle (exit $rc)"; rm -rf "$dir"; return; }
    out="$(python3 - "$REPO_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/apps/iam")
from compiler import source
print(source.policy_entries_digest(source.factory(), "bootstrap"))
PY
)"
    out="$(fx "$db" -q -tA -c "SELECT v.status || '|' || v.kind || '|' || (iam_policy.entries_digest(1) = '$out')::text
                                      || '|' || (v.skeleton_digest = iam_policy._accepted())::text
                                 FROM iam_policy.version v WHERE v.version = 1")"
    [[ "$out" == "applied|bootstrap|true|true" ]] && pass P22 "version 1 applied, kind bootstrap, entries_digest(1) = Python's, the accepted skeleton" \
        || fail P22 "version 1 (status|kind|digest|skeleton): ${out:-missing}"
    out="$(fx "$db" -q -tA -v ON_ERROR_STOP=1 2>&1 <<'SQL'
SELECT medcea_auth._set_internal_actor('system:apply') \g /dev/null
SELECT iam_policy._record('bootstrap_applied', '{"version": 1, "kind": "bootstrap", "os_user": "iam-db-fixture", "changed": [], "deferred": []}'::jsonb) \g /dev/null
SELECT (SELECT count(*) FROM iam_policy.audit_versions()) || '|' || (SELECT ok FROM iam_policy.verify_chain())::text
       || '|' || (SELECT string_agg(event, ',' ORDER BY event_id) FROM iam_policy.history WHERE version = 1 AND event <> 'status_changed');
SQL
)"
    [[ "$out" == "0|true|draft_created,apply_started,bootstrap_applied" ]] \
        && pass P22 "bootstrap_applied recorded: audit_versions() empty, the chain verifies" \
        || fail P22 "after bootstrap_applied (findings|chain|events): $out"
    # the 008c re-run with version 1 and the 4.2a bodies
    cmd_apply true "$db"
    snap1="$(CEA_DB="$db" policy_snapshot)" && snapshot_whole "$snap1" || { fail policy-apply "policy_snapshot failed"; rm -rf "$dir"; return; }
    ev="$(fx "$db" -q -tA -c "SELECT max(event_id) FROM iam_policy.history")"
    cmd_apply true "$db"
    snap2="$(CEA_DB="$db" policy_snapshot)" && snapshot_whole "$snap2" || { fail policy-apply "policy_snapshot failed after the re-run"; rm -rf "$dir"; return; }
    [[ "$snap1" == "$snap2" ]] && pass policy-apply "008c re-run with v1 and the 4.2a bodies: catalog and versions unchanged" \
        || { fail policy-apply "008c re-run changed the catalog or the versions:"; diff <(echo "$snap1") <(echo "$snap2") | head -20; }
    out="$(fx "$db" -q -tA -c "SELECT coalesce(string_agg(event, ','), '') FROM iam_policy.history WHERE event_id > $ev AND version IS NOT NULL")"
    [[ -z "$out" ]] && pass policy-apply "the re-run wrote no event under a version" || fail policy-apply "the re-run wrote: $out"
    out="$(fx "$db" -q -1 -v ON_ERROR_STOP=1 < apps/database/medcea_db_migrations_down_008c.sql 2>&1)"
    grep -q 'policy versions exist' <<<"$out" && pass policy-apply "down_008c refused while version 1 exists" || fail policy-apply "down_008c with v1: ${out:-it ran}"
    # P22 — a failing statement and a REPEATABLE READ default each roll the bundle back
    cmd_apply false medcea_pa2
    { cat "$dir/post.sql"; echo "DO \$\$ BEGIN RAISE EXCEPTION 'iam-db-fixture: a broken assert'; END \$\$;"; } > "$dir/post-broken.sql"
    out="$(pa_bundle medcea_pa2 "$dir" "$dir/post-broken.sql")"; rc=$?
    ev="$(fx medcea_pa2 -q -tA -c "SELECT (SELECT count(*) FROM iam_policy.version) || '|' || (SELECT count(*) FROM iam_policy.skeleton)")"
    [[ $rc -ne 0 && "$out" == *"a broken assert"* && "$ev" == "0|0" ]] \
        && pass P22 "a broken assert rolls the whole bundle back (no version, no skeleton)" \
        || fail P22 "broken assert: exit $rc, versions|skeletons $ev"
    fx postgres -q -c "ALTER DATABASE medcea_pa2 SET default_transaction_isolation = 'repeatable read';" >/dev/null
    local iso; iso="$(fx medcea_pa2 -q -tA -c "SELECT current_setting('transaction_isolation')" 2>&1)"
    [[ "$iso" == "repeatable read" ]] || fail P22 "the database default did not take: a new session on medcea_pa2 runs '$iso'"
    out="$(pa_bundle medcea_pa2 "$dir" "$dir/post.sql")"; rc=$?
    fx postgres -q -c "ALTER DATABASE medcea_pa2 RESET default_transaction_isolation;" >/dev/null
    ev="$(fx medcea_pa2 -q -tA -c "SELECT count(*) FROM iam_policy.version")"
    if [[ $rc -ne 0 && "$out" == *"needs READ COMMITTED"* && "$ev" == 0 ]]; then
        pass P22 "READ COMMITTED asserted inside the bundle (F-24)"
    else
        fail P22 "repeatable read: exit $rc, versions on medcea_pa2 $ev"
        local d
        for d in medcea_pa medcea_pa2; do
            echo "        $d versions: $(fx "$d" -q -tA -c "SELECT coalesce(string_agg(version || ':' || kind || ':' || status, ' ' ORDER BY version), 'none') FROM iam_policy.version" 2>&1)"
        done
        echo "        the bundle's output:"; sed 's/^/          /' <<<"$out" | head -60
    fi
    # P22 — the bootstrap under IAM_DB_ROLES=true, as production runs it: the enforce file
    # sets system:deploy for its demotion, and _mark_applied in POST needs system:apply
    out="$(access_sql | fx medcea_pa2 -q -1 -v ON_ERROR_STOP=1 -f - 2>&1)" || { echo "$out" | head; fail P22 "access_db.sql on medcea_pa2"; }
    cmd_apply true medcea_pa2
    out="$(pa_bundle medcea_pa2 "$dir" "$dir/post.sql" true)"; rc=$?
    ev="$(fx medcea_pa2 -q -tA -c "SELECT coalesce(string_agg(version || ':' || kind || ':' || status, ' '), 'none') FROM iam_policy.version")"
    [[ $rc -eq 0 && "$ev" == "1:bootstrap:applied" ]] \
        && pass P22 "the bootstrap bundle under IAM_DB_ROLES=true: committed, version 1 applied" \
        || { grep -E 'ERROR|DETAIL' <<<"$out" | head; fail P22 "the bootstrap under true: exit $rc, versions $ev"; }
    # apply.sh files bootstrap_applied after the COMMIT; without it new_draft refuses (P43)
    out="$(fx medcea_pa2 -q -tA -v ON_ERROR_STOP=1 2>&1 <<'SQL'
SELECT medcea_auth._set_internal_actor('system:apply') \g /dev/null
SELECT iam_policy._record('bootstrap_applied', '{"version": 1, "kind": "bootstrap", "os_user": "iam-db-fixture", "changed": [], "deferred": []}'::jsonb) \g /dev/null
SELECT (SELECT count(*) FROM iam_policy.audit_versions()) || '|' || (SELECT ok FROM iam_policy.verify_chain())::text;
SQL
)"
    [[ "$out" == "0|true" ]] && pass P22 "bootstrap_applied recorded on medcea_pa2: audit_versions() empty, the chain verifies" \
        || fail P22 "bootstrap_applied on medcea_pa2 (findings|chain): $out"
    rm -rf "$dir"
}

# ── IAM 4.5: apply for real, the database half (design §14.8.11 P38-P42, P44-P46) ──────
# The fixture has no Keycloak, realm key or proxies: approvals carry hand-set claims and an
# unsigned JWS (the database compares, apply.sh verifies), and the PRE/POST are apply.sh's
# own (apply_check.py bundle-sql, pa45_ship), run through the real dba_policy_bundle with
# DBA_STAGED: grants, asserts and functions
# compiled by cli.py --staged from the version's staged host file (sha256 pinned, under
# this run's verified lock).

# pa45_py CMD ARGS — the Python half: pick (a cell of a role nobody holds that loses a
# table privilege and passes the checker), forge (a cell the checker refuses), skel (a
# prose-only skeleton change: another digest, the same compile), stage (a version
# document from the database → the staged host file, as apply.sh's step 5 writes it,
# body-bound; prints its sha256, header version and entries digest), shipstage (bundle-sql's
# stage directory and version document from a staged file), rollback-doc
pa45_py() {
    python3 - "$REPO_ROOT" "$@" <<'PY'
import copy, datetime, json, os, sys
sys.path.insert(0, sys.argv[1] + "/apps/iam")
from compiler import grants, invariants, model, source

TAG = " (iam-db-fixture: a skeleton version)"


def alt():
    """factory() with one prose change: another skeleton digest, the same compile."""
    d = source.factory()
    r = sorted(d["roles"], key=source._bytes)[0]
    d["roles"][r]["description"] = (d["roles"][r].get("description") or "") + TAG
    return d


def cells(d):
    return {(r, g): c for g, row in d["matrix"].items() for r, c in row.items()}


def table_privs(p, role):
    return {(o, priv) for (g, k, o, priv) in grants.privileges(p) if g == role and k == "table"}


def pick(earlier):
    """role, group, save_entry levels after, the db role, and a table privilege it loses: one
    level less on an unconstrained cell, roles nobody on an install holds first
    (maintenance, qc; owner decision 11), passing the checker. `earlier`:
    role/group=<levels json> changes already in the version it is drafted on."""
    d = source.factory()
    for e in earlier:
        rg, _, lv = e.partition("=")
        r, g = rg.split("/")
        lv = list(json.loads(lv))
        if lv:
            d["matrix"][g][r] = lv
        else:
            del d["matrix"][g][r]
    p0 = model.Policy(d)
    done = {e.partition("=")[0] for e in earlier}
    for role in ["maintenance", "qc"] + [r for r in d["roles"] if r not in ("maintenance", "qc")]:
        db_role = d["roles"][role].get("db_role", "rr_" + role)
        before = table_privs(p0, db_role)
        for (r, g), c in sorted(cells(d).items()):
            if r != role or not isinstance(c, list) or f"{r}/{g}" in done:
                continue
            for lvl in c:
                d2 = copy.deepcopy(d)
                rest = [x for x in c if x != lvl]
                if rest:
                    d2["matrix"][g][r] = rest
                else:
                    del d2["matrix"][g][r]
                p2 = model.Policy(d2)
                if invariants.check(p2)[0]:
                    continue
                lost = sorted(before - table_privs(p2, db_role))
                if lost:
                    print("\t".join([r, g, json.dumps({x: None for x in rest}), db_role, lost[0][0], lost[0][1]]))
                    return
    sys.exit("no unconstrained cell loses a table privilege without failing the checker")


def forge():
    d = source.factory()
    for g in ("iam_policy", "iam_users"):
        for r in ("admin", "qa", "operator"):
            d2 = copy.deepcopy(d)
            d2["matrix"].setdefault(g, {})[r] = ["R", "C", "U", "A"]
            if invariants.check(model.Policy(d2))[0]:
                print("\t".join([r, g, json.dumps({x: None for x in "RCUA"})]))
                return
    sys.exit("no cell the checker refuses")


def stage(doc_path, out, data_kind):
    with open(doc_path) as f:
        doc = json.load(f)
    state = dict(doc, state=f"version-{doc['version']}")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = source.host_file_text(state, "unknown", now, data=alt() if data_kind == "alt" else source.factory())
    exp, dropped = source.expected_body(state)
    body = source.parse_body_header(text)
    if source.body_digest(exp) != body["body_digest"] or dropped != body["dropped"]:
        sys.exit("internal: the staged file is not the version's rows")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    head = source.parse_header(text)
    print("\t".join([source.file_sha256(out), str(head["version"]), head["entries_digest"]]))


def rollback_doc(k_doc, next_v, out):
    with open(k_doc) as f:
        k = json.load(f)
    acc = k["accepted"]
    groups = sorted(acc["body"].get("resource_groups") or {}, key=source._bytes)
    roles = sorted(acc["body"].get("roles") or {}, key=source._bytes)
    doc = {"version": int(next_v), "kind": "rollback", "groups": groups, "roles": roles,
           "entries": k["entries"], "waivers": k["waivers"], "accepted": acc,
           "entries_digest": source.entries_digest("rollback", groups, roles, k["entries"], k["waivers"])}
    with open(out, "w") as f:
        json.dump(doc, f)


def shipstage(kind, d, path, dd, *extra):
    """stage.json, the staged (or prev.yaml) file and the version document for bundle-sql."""
    import shutil
    text = open(path, encoding="utf-8").read()
    h = source.parse_header(text)
    os.makedirs(os.path.join(d, "staged"), mode=0o700)
    meta = {"version": int(h["version"]), "kind": kind, "entries_digest": h["entries_digest"],
            "skeleton_digest": h["skeleton_digest"]}
    doc = {"version": {"version": int(h["version"]), "diff_digest": dd, "skeleton_digest": h["skeleton_digest"]}}
    if kind == "revert":
        shutil.copy(path, os.path.join(d, "prev.yaml"))
        meta = {"version": int(extra[0]), "prev_version": int(h["version"]), "prev_entries_digest": h["entries_digest"]}
    else:
        shutil.copy(path, os.path.join(d, "staged", "policy-applied.yaml"))
    if kind == "skeleton":
        sd, bodyf = extra
        doc["version"]["skeleton_digest"] = sd
        doc["skeletons"] = {sd: {"body": json.load(open(bodyf)), "git_commit": "iam-db-fixture"}}
    if kind == "rollback":
        meta.update(rollback_of=int(extra[0]), prev_version=int(extra[1]))
    with open(os.path.join(d, "stage.json"), "w") as f:
        json.dump(meta, f)
    with open(os.path.join(d, "doc.json"), "w") as f:
        json.dump(doc, f)


cmd, args = sys.argv[2], sys.argv[3:]
if cmd == "pick":
    pick(args)
elif cmd == "forge":
    forge()
elif cmd == "skel":
    s = source.skeleton(alt())
    print(json.dumps({"digest": source.skeleton_digest(s), "body": json.loads(source.canonical(s))}, sort_keys=True))
elif cmd == "stage":
    stage(*args)
elif cmd == "rollback-doc":
    rollback_doc(*args)
elif cmd == "shipstage":
    shipstage(*args)
else:
    sys.exit(f"pa45_py: {cmd}?")
PY
}

# pa45_q DB — SQL on stdin, one psql session, stops at the first error (its output on stdout)
pa45_q() { fx "$1" -q -tA -v ON_ERROR_STOP=1 2>&1; }

# pa45_doc DB V OUT — version V as the state document shows a version (rows in byte order,
# waivers without their version), with the skeleton it applies under: a skeleton
# version's proposed one, else the accepted one
pa45_doc() {
    pa45_q "$1" > "$3" <<SQL
SELECT json_build_object('version', v.version, 'kind', v.kind, 'entries_digest', v.entries_digest,
       'groups', to_json(v.groups), 'roles', to_json(v.roles),
       'entries', coalesce((SELECT json_agg(json_build_object('role', e.role, 'group_code', e.group_code, 'level', e.level::text,
                                                          'constraint_name', e.constraint_name)
                                   ORDER BY e.role COLLATE "C", e.group_code COLLATE "C", e.level::text COLLATE "C")
                              FROM iam_policy.entry e WHERE e.version = v.version), '[]'),
       'waivers', coalesce((SELECT json_agg(to_jsonb(w) - 'version' ORDER BY w.id COLLATE "C")
                              FROM iam_policy.waiver w WHERE w.version = v.version), '[]'),
       'accepted', (SELECT json_build_object('digest', s.digest, 'body', s.body) FROM iam_policy.skeleton s
                     WHERE s.digest = CASE WHEN v.kind = 'skeleton' THEN v.skeleton_digest ELSE iam_policy._accepted() END))
  FROM iam_policy.version v WHERE v.version = $2;
SQL
}

# pa45_stage DB V NAME [alt] — the staged host file of version V in $PA45/NAME.yaml:
# sets ST_FILE, ST_SHA, ST_VER (its header's version) and ST_ED (its entries digest)
pa45_stage() {
    local out
    ST_FILE="$PA45/$3.yaml"; ST_SHA=""; ST_VER=""; ST_ED=""
    pa45_doc "$1" "$2" "$PA45/$3.json" || { fail P38 "version $2 on $1: $(head -c 300 "$PA45/$3.json")"; return 1; }
    out="$(pa45_py stage "$PA45/$3.json" "$ST_FILE" "${4:-factory}" 2>&1)" || { fail P38 "staging version $2: $out"; return 1; }
    IFS=$'\t' read -r ST_SHA ST_VER ST_ED <<<"$out"
}

# pa45_bundle DB PRE POST FILE SHA [MODE] — apply.sh's bundle (step 7): system:apply,
# compiled from FILE (DBA_STAGED, pinned by SHA, under this run's lock); IAM_DB_ROLES=MODE
pa45_bundle() {
    load_passwords
    IAM_DB_ROLES="${6:-true}" CEA_DB="$1" DBA_ACTOR=system:apply DBA_SERVICE_LOGINS="" \
        DBA_STAGED="$4" DBA_STAGED_BY="$MEDCEA_LOCK_HELD" DBA_STAGED_SHA256="$5" \
        dba_policy_bundle "$FX_NS" "$FX_POD" auto "$2" "$3" --with-functions 2>&1
}

pa45_uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
pa45_dd() { printf 'iam-db-fixture %s %s' "$1" "$PA45_H" | sha256sum | cut -d' ' -f1; }   # a diff digest per name
pa45_claims() {  # SUB PERSON — a policy-host qa token's claims, issued two minutes ago
    printf '{"typ":"Bearer","azp":"policy","aud":"medcea-api","sub":"%s","person_id":"%s","preferred_username":"test-%s","groups":["qa"],"iat":%s,"exp":%s,"jti":"%s"}' \
        "$1" "$2" "$2" "$PA45_IAT" "$((PA45_IAT + 300))" "$(pa45_uuid)"
}
# pa45_token SUB PERSON PATH — PostgREST's session for that token: claims, the
# Authorization header (an unsigned JWS of the claims), pre_request
pa45_token() {
    local c jws
    c="$(pa45_claims "$1" "$2")"
    jws="$(python3 -c 'import base64,sys; b=lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("="); print(b("{\"alg\":\"RS256\",\"kid\":\"iam-db-fixture\"}") + "." + b(sys.argv[1]) + ".c2ln")' "$c")"
    cat <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$c', true), set_config('request.method', 'POST', true),
       set_config('request.path', '$3', true), set_config('request.headers', '{"authorization": "Bearer $jws"}', true) \\g /dev/null
SELECT medcea_auth.pre_request() \\g /dev/null
SQL
}
pa45_iam() {  # SUB PERSON ROLE — iam-api (iam_svc) acting for that person
    printf 'SET SESSION AUTHORIZATION iam_svc;\n'
    echo "SELECT medcea_auth.set_actor('$1', '$2', 'test-$2', '$3') \\g /dev/null"
}

# pa45_change DB ROLE GROUP LEVELS DD — admin A drafts from the applied version, saves one
# cell, submits; qa Q approves it on diff digest DD: prints the version number
pa45_change() {
    local out v ed acc
    out="$(pa45_q "$1" <<SQL
BEGIN;
$(pa45_iam "$PA45_A" "$PA45_PA" admin)
SELECT iam_policy.new_draft('applied', 'iam-db-fixture: IAM 4.5', $PA45_IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
SELECT iam_policy.save_entry(:d, '$2', '$3', '$4'::jsonb, 'iam-db-fixture: IAM 4.5',
                             '{"ok": true, "errors": [], "checker_digest": "iam-db-fixture"}'::jsonb, $PA45_IAT) \\g /dev/null
SELECT iam_policy.submit(:d, 'iam-db-fixture: IAM 4.5', $PA45_IAT) AS ed \\gset
COMMIT;
RESET ROLE;
RESET SESSION AUTHORIZATION;
SELECT 'v|' || :d || '|' || :'ed' || '|' || iam_policy._accepted();
SQL
)" || { echo "$out" | grep -m3 ERROR >&2; return 1; }
    IFS='|' read -r _ v ed acc <<<"$(grep '^v|' <<<"$out")"
    out="$(pa45_q "$1" <<SQL
BEGIN;
$(pa45_token "$PA45_Q" "$PA45_PQ" /rpc/approve_policy)
SELECT medcea.approve_policy($v, 'iam-db-fixture note', '$ed', '$5', '$acc') \\g /dev/null
COMMIT;
SQL
)" || { echo "$out" | grep -m3 ERROR >&2; return 1; }
    echo "$v"
}

# The bundles are apply.sh's own (apply_check.py bundle-sql, design §14.8.4 step 7, §14.8.6,
# §14.8.7 step 7): pa45_ship builds the stage directory and version document bundle-sql
# reads (stage.json, staged/policy-applied.yaml, prev.yaml; {version, skeletons}) from a
# staged file, runs it, and leaves OUT.pre.sql / OUT.post.sql. A negative case changes one
# input of that SQL (another file's entries digest, the accept left out), never the asserts.
# pa45_ship KIND OUT FILE DD [K APPLIED | SD BODY_FILE | REVERTED] — BY is $PA45_BY
pa45_ship() {
    local kind="$1" out="$2" st="$2.stage" why
    rm -rf "$st"
    pa45_py shipstage "$kind" "$st" "$3" "${@:4}" || return 1
    why=()
    if [[ "$kind" == rollback || "$kind" == revert ]]; then
        printf 'iam-db-fixture: %s' "$kind" > "$st/why"
        why=(--reason-file "$st/why")
        [[ "$kind" == revert ]] && { echo iam-db-fixture > "$st/failed"; why+=(--failed "$st/failed"); }
    fi
    python3 "$REPO_ROOT/apps/iam/apply_check.py" bundle-sql --kind "$kind" --stage "$st" --doc "$st/doc.json" \
        --by-sub "${PA45_BY%%|*}" --by-person "${PA45_BY#*|}" --log iam-db-fixture --commit iam-db-fixture \
        "${why[@]}" --out "$st/out" || return 1
    cp "$st/out/pre.sql" "$out.pre.sql"
    cp "$st/out/post.sql" "$out.post.sql"
}

# pa45_forward OUT V FILE DD [WANT] — version V's bundle (change), staged from FILE; WANT
# replaces the staged entries digest PRE asserts (a stage of another version's file)
pa45_forward() {
    PA45_BY="$PA45_A|$PA45_PA" pa45_ship change "$1" "$3" "$4" || return 1
    [[ -z "${5:-}" ]] || sed -i "s/^\\\\set want_entries '[0-9a-f]*'\$/\\\\set want_entries '$5'/" "$1.pre.sql"
}
# pa45_forward_skel OUT FILE DD SD BODY_FILE [no-accept] — a skeleton version's bundle;
# no-accept drops the _accept_skeleton/_sync_skeleton lines, so its assert must refuse
pa45_forward_skel() {
    PA45_BY="$PA45_A|$PA45_PA" pa45_ship skeleton "$1" "$2" "$3" "$4" "$5" || return 1
    [[ "${6:-}" != no-accept ]] || sed -i '/iam_policy\._accept_skeleton(\|iam_policy\._sync_skeleton(/d' "$1.pre.sql"
}
# pa45_revert OUT V PREV_FILE — the revert of version V to the version in PREV_FILE
pa45_revert() { PA45_BY="$PA45_A|$PA45_PA" pa45_ship revert "$1" "$3" - "$2"; }
# pa45_rollback OUT K APPLIED FILE — the rollback to K staged in FILE, as qa Q2
pa45_rollback() { PA45_BY="$PA45_Q2|$PA45_PQ2" pa45_ship rollback "$1" "$4" - "$2" "$3"; }

# pa45_record DB EVENT PAYLOAD_JSON — apply.sh's record after the bundle (system:apply)
pa45_record() {
    pa45_q "$1" <<SQL
BEGIN;
SELECT medcea_auth._set_internal_actor('system:apply') \\g /dev/null
SELECT iam_policy._record('$2', '$3'::jsonb) \\g /dev/null
COMMIT;
SQL
}

# pa45_has DB ROLE OBJECT PRIV — has_table_privilege, t or f
pa45_has() { pa45_q "$1" <<<"SELECT has_table_privilege('$2', '$3', '$4');"; }

# pa45_status DB — every version as V:kind:status, in order
pa45_status() { pa45_q "$1" <<<"SELECT string_agg(version || ':' || kind || ':' || status, ' ' ORDER BY version) FROM iam_policy.version;"; }

# pa45_routes FILE SHA — the routes digest compiled from a staged file
pa45_routes() {
    MEDCEA_POLICY_STAGED_SHA256="$2" python3 "$CLI" --staged "$1" compile routes \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])'
}

policy_apply_45() {
    step "IAM 4.5: change, revert, skeleton and rollback bundles through DBA_STAGED (fresh databases)"
    # DBA_STAGED is honoured only under this run's verified lock (_dba_src): take it here,
    # in this shell, for the 4.5 steps only, unless a parent already holds it
    local took=false
    if [[ -z "${MEDCEA_LOCK_HELD:-}" ]]; then
        if ! ( exec 8>>"$MEDCEA_LOCK_FILE" && flock -n 8 ); then
            fail P38 "the deploy lock is held by another run: the staged bundles need it (DBA_STAGED_BY)"
            return
        fi
        medcea_lock
        took=true
    fi
    if medcea_lock_verify; then
        PA45="$(mktemp -d "$IAMTEST_DIR/pa45-XXXXXX")"
        policy_apply_45_steps
        rm -rf "$PA45"
    else
        fail P38 "medcea_lock_verify failed: this run does not hold the deploy lock"
    fi
    if [[ "$took" == true ]]; then
        exec 9>&-
        unset MEDCEA_LOCK_HELD
    fi
}

policy_apply_45_steps() {
    local db=medcea_pa out rc ok c1 c2 s r f snap1 snap2 ev acc sd hd v
    local r1 g1 l1 dbr1 obj1 priv1 r2 g2 l2 dbr2 obj2 priv2 c1_file c1_sha c1_ed c2_file c2_sha c2_ed
    local h; h="$(openssl rand -hex 3)"; PA45_H="$h"
    PA45_A="$(pa45_uuid)"; PA45_Q="$(pa45_uuid)"; PA45_Q2="$(pa45_uuid)"
    PA45_PA="p-pa45-a-$h"; PA45_PQ="p-pa45-q-$h"; PA45_PQ2="p-pa45-q2-$h"
    PA45_IAT=$(( $(date +%s) - 120 ))   # a token issued two minutes ago
    out="$(pa45_py pick 2>&1)" || { fail P38 "no cell to change: $out"; return; }
    IFS=$'\t' read -r r1 g1 l1 dbr1 obj1 priv1 <<<"$out"
    out="$(pa45_py pick "$r1/$g1=$l1" 2>&1)" || { fail P39 "no second cell to change: $out"; return; }
    IFS=$'\t' read -r r2 g2 l2 dbr2 obj2 priv2 <<<"$out"
    echo "        change 1: $r1/$g1 -> $l1 ($dbr1 loses $priv1 on $obj1); change 2: $r2/$g2 -> $l2 ($dbr2 loses $priv2 on $obj2)"

    # version 1 confirmed by qa Q (its recorded person is the bootstrap's): a rollback target
    out="$(pa45_q "$db" <<SQL
BEGIN;
$(pa45_token "$PA45_Q" "$PA45_PQ" /rpc/confirm_policy)
SELECT medcea.confirm_policy(1, 'iam-db-fixture', 'I did not run apply.sh for this version.') \\g /dev/null
COMMIT;
SQL
)" || { echo "$out" | grep -m3 ERROR; fail P42 "qa confirms version 1 on $db"; return; }

    # P38 — a change version committed through the bundle (IAM_DB_ROLES=true)
    [[ "$(pa45_has "$db" "$dbr1" "$obj1" "$priv1")" == t ]] || { fail P38 "$dbr1 lacks $priv1 on $obj1 before the change: the probe proves nothing"; return; }
    c1="$(pa45_change "$db" "$r1" "$g1" "$l1" "$(pa45_dd c1)")" || { fail P38 "drafting and approving change 1 on $db"; return; }
    pa45_stage "$db" "$c1" c1 || return
    c1_file="$ST_FILE"; c1_sha="$ST_SHA"; c1_ed="$ST_ED"
    pa45_forward "$PA45/c1" "$c1" "$c1_file" "$(pa45_dd c1)" || { fail P38 "bundle-sql for change $c1"; return; }
    out="$(pa45_bundle "$db" "$PA45/c1.pre.sql" "$PA45/c1.post.sql" "$c1_file" "$c1_sha")"; rc=$?
    [[ $rc -eq 0 ]] || { grep -E 'ERROR|DETAIL' <<<"$out" | head; fail P38 "the change bundle (true) exit $rc"; return; }
    out="$(pa45_status "$db")"
    [[ "$out" == "1:bootstrap:superseded $c1:change:applied" ]] && pass P38 "true: change $c1 applied by the bundle, version 1 superseded" \
        || fail P38 "true: versions after the change bundle: $out"
    [[ "$(pa45_has "$db" "$dbr1" "$obj1" "$priv1")" == f ]] && pass P38 "true: the new matrix's grants in the catalog ($dbr1 lost $priv1 on $obj1)" \
        || fail P38 "true: $dbr1 still holds $priv1 on $obj1 after the change"
    out="$(pa45_q "$db" <<<"SELECT obj_description('medcea_auth.role_widening(text,text)'::regprocedure, 'pg_proc');")"
    [[ "$out" == "policy $(pa45_routes "$c1_file" "$c1_sha")" ]] && pass P38 "true: role_widening()'s comment is the staged routes digest" \
        || fail P38 "true: role_widening()'s comment: $out"
    out="$(pa45_record "$db" applied "{\"version\": $c1, \"kind\": \"change\"}" && pa45_q "$db" <<SQL
SELECT (SELECT string_agg(event, ',' ORDER BY event_id) FROM iam_policy.history WHERE version = $c1 AND event <> 'status_changed')
       || '|' || (SELECT count(*) FROM iam_policy.audit_versions()) || '|' || (SELECT ok FROM iam_policy.verify_chain())::text;
SQL
)"
    [[ "$out" == "draft_created,entry_saved,submitted,approved,apply_started,applied|0|true" ]] \
        && pass P38 "true: applied recorded; audit_versions() empty, the chain verifies" || fail P38 "true: after the record (events|findings|chain): $out"

    # P41 — the forward PRE refuses a staged file of another version (the whole bundle rolls back)
    c2="$(pa45_change "$db" "$r2" "$g2" "$l2" "$(pa45_dd c2)")" || { fail P41 "drafting and approving change 2 on $db"; return; }
    pa45_stage "$db" "$c2" c2 || return
    c2_file="$ST_FILE"; c2_sha="$ST_SHA"; c2_ed="$ST_ED"
    pa45_forward "$PA45/c2-stale" "$c2" "$c2_file" "$(pa45_dd c2)" "$c1_ed" || { fail P41 "bundle-sql for change $c2"; return; }
    out="$(pa45_bundle "$db" "$PA45/c2-stale.pre.sql" "$PA45/c2-stale.post.sql" "$c1_file" "$c1_sha")"; rc=$?
    [[ $rc -ne 0 && "$out" == *"does not store the entries of the staged file"* && "$(pa45_status "$db")" == *"$c1:change:applied $c2:change:approved" ]] \
        && pass P41 "forward: a staged file of another version refused by PRE, nothing applied" \
        || fail P41 "forward with version $c1's file: exit $rc, versions $(pa45_status "$db")"

    # change 2 applied, then the revert (P39) to change 1
    pa45_forward "$PA45/c2" "$c2" "$c2_file" "$(pa45_dd c2)" || { fail P39 "bundle-sql for change $c2"; return; }
    out="$(pa45_bundle "$db" "$PA45/c2.pre.sql" "$PA45/c2.post.sql" "$c2_file" "$c2_sha")"; rc=$?
    [[ $rc -eq 0 && "$(pa45_has "$db" "$dbr2" "$obj2" "$priv2")" == f ]] && pass P39 "change $c2 applied ($dbr2 lost $priv2 on $obj2)" \
        || { grep -E 'ERROR|DETAIL' <<<"$out" | head; fail P39 "the change 2 bundle exit $rc"; return; }
    # P41 — the revert's PRE refuses a file of another version than the previous one
    pa45_revert "$PA45/rv-wrong" "$c2" "$c2_file" || { fail P41 "bundle-sql --kind revert"; return; }
    out="$(pa45_bundle "$db" "$PA45/rv-wrong.pre.sql" "$PA45/rv-wrong.post.sql" "$c2_file" "$c2_sha")"; rc=$?
    [[ $rc -ne 0 && "$out" == *"did not supersede version $c2"* && "$(pa45_status "$db")" == *"$c1:change:superseded $c2:change:applied" ]] \
        && pass P41 "revert: a staged file of another version refused by PRE, nothing reverted" \
        || fail P41 "revert with version $c2's file: exit $rc, versions $(pa45_status "$db")"
    # P39 — the previous version's file built from the database (as from the state document)
    pa45_stage "$db" "$c1" c1-prev || return
    [[ "$ST_VER" == "$c1" ]] || { fail P39 "the previous version's file is version $ST_VER"; return; }
    pa45_revert "$PA45/rv" "$c2" "$ST_FILE" || { fail P39 "bundle-sql --kind revert"; return; }
    out="$(pa45_bundle "$db" "$PA45/rv.pre.sql" "$PA45/rv.post.sql" "$ST_FILE" "$ST_SHA")"; rc=$?
    [[ $rc -eq 0 ]] || { grep -E 'ERROR|DETAIL' <<<"$out" | head; fail P39 "the revert bundle exit $rc"; return; }
    out="$(pa45_status "$db")"
    [[ "$out" == *"$c1:change:applied $c2:change:approved" ]] && pass P39 "the revert: change $c2 approved again, change $c1 applied" \
        || fail P39 "versions after the revert: $out"
    [[ "$(pa45_has "$db" "$dbr2" "$obj2" "$priv2")" == t && "$(pa45_has "$db" "$dbr1" "$obj1" "$priv1")" == f ]] \
        && pass P39 "the previous version's grants back ($dbr2 holds $priv2 on $obj2 again; $dbr1 still without $priv1)" \
        || fail P39 "grants after the revert are not version $c1's"
    out="$(pa45_record "$db" partial_apply "{\"version\": $c2, \"outcome\": \"reverted\", \"failed_targets\": [\"iam-db-fixture\"], \"attempts\": 3}" \
           && pa45_record "$db" applied "{\"version\": $c1, \"reverted_from\": $c2, \"resumed\": false}" && pa45_q "$db" <<SQL
SELECT (SELECT h.event || ':' || coalesce(h.payload ->> 'outcome', '') || ':' || coalesce(h.payload ->> 'reverted_version', '')
          FROM iam_policy.history h WHERE h.version = $c1 AND h.event = 'partial_apply' ORDER BY h.event_id DESC LIMIT 1)
       || '|' || (SELECT h.event FROM iam_policy.history h WHERE h.version = $c1
                   AND h.event IN ('apply_started', 'applied', 'bootstrap_applied', 'apply_reverted', 'partial_apply', 'apply_deferred')
                 ORDER BY h.event_id DESC LIMIT 1)
       || '|' || (SELECT string_agg(h.event, ',' ORDER BY h.event_id) FROM iam_policy.history h
                   WHERE h.version = $c2 AND h.event IN ('apply_reverted', 'partial_apply'))
       || '|' || (SELECT count(*) FROM iam_policy.audit_versions()) || '|' || (SELECT ok FROM iam_policy.verify_chain())::text;
SQL
)"
    [[ "$out" == "partial_apply:reverting:$c2|applied|apply_reverted,partial_apply|0|true" ]] \
        && pass P39 "partial_apply {reverting} under $c1, then {reverted} under $c2 and applied {reverted_from}: the latest apply event applied" \
        || fail P39 "the revert's records (reverting|latest|$c2's|findings|chain): $out"
    out="$(pa45_q "$db" <<SQL 2>&1
BEGIN;
$(pa45_iam "$PA45_A" "$PA45_PA" admin)
SELECT iam_policy.new_draft('applied', 'iam-db-fixture', $PA45_IAT, '[]'::jsonb, '[]'::jsonb);
ROLLBACK;
SQL
)"
    [[ "$out" == *"version $c2 is still open"* ]] && pass P39 "new_draft refused while the reverted change is open (one_open)" \
        || fail P39 "new_draft after the revert: ${out:0:300}"

    # P41 — a version no longer approved at the FOR UPDATE re-read: withdrawn, then its bundle
    out="$(pa45_q "$db" <<SQL
BEGIN;
$(pa45_iam "$PA45_A" "$PA45_PA" admin)
SELECT iam_policy.withdraw($c2, 'iam-db-fixture: P41', $PA45_IAT) \\g /dev/null
COMMIT;
SQL
)" || { echo "$out" | grep -m3 ERROR; fail P41 "withdrawing change $c2"; }
    out="$(pa45_bundle "$db" "$PA45/c2.pre.sql" "$PA45/c2.post.sql" "$c2_file" "$c2_sha")"; rc=$?
    [[ $rc -ne 0 && "$out" == *"is not approved any more"* && "$(pa45_status "$db")" == *"$c1:change:applied $c2:change:withdrawn" ]] \
        && pass P41 "a version withdrawn before its bundle: refused at the FOR UPDATE re-read, nothing applied" \
        || fail P41 "the withdrawn version's bundle: exit $rc, versions $(pa45_status "$db")"

    # P40 — a skeleton version: proposed (system:apply), approved with the attestation, applied
    out="$(pa45_py skel)" || { fail P40 "the skeleton change: $out"; return; }
    sd="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["digest"])' "$out")"
    python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])["body"], sort_keys=True))' "$out" > "$PA45/skel-body.json"
    acc="$(pa45_q "$db" <<<"SELECT iam_policy._accepted();")"
    hd="$(pa45_dd skel)"
    out="$(pa45_q "$db" <<SQL
BEGIN;
SELECT medcea_auth._set_internal_actor('system:apply') \\g /dev/null
SELECT iam_policy._propose_skeleton('$sd', \$sk\$$(cat "$PA45/skel-body.json")\$sk\$::jsonb, 'iam-db-fixture',
       '{"schema": 1, "kind": "skeleton", "skeleton": {"from": "$acc", "to": "$sd", "sections": []}, "cells": [],
         "waivers": {"added": [], "removed": []}, "roles": {}, "system": {"added": [], "removed": []}}'::jsonb,
       '$hd', '$PA45_A', '$PA45_PA', 'iam-db-fixture: P40') AS s \\gset
COMMIT;
SELECT 's|' || :s || '|' || entries_digest FROM iam_policy.version WHERE version = :s;
SQL
)" || { echo "$out" | grep -m3 ERROR; fail P40 "_propose_skeleton"; return; }
    local s_ed; IFS='|' read -r _ s s_ed <<<"$(grep '^s|' <<<"$out")"
    out="$(pa45_q "$db" <<SQL
BEGIN;
$(pa45_token "$PA45_Q" "$PA45_PQ" /rpc/approve_policy)
SELECT medcea.approve_policy($s, 'I did not run apply.sh --propose-skeleton for this version. iam-db-fixture',
       '$s_ed', '$hd', '$sd') \\g /dev/null
COMMIT;
SQL
)" || { echo "$out" | grep -m3 ERROR; fail P40 "qa approves skeleton version $s"; return; }
    pa45_stage "$db" "$s" skel alt || return
    # P41 — a skeleton version's bundle without the accept: the skeleton assert refuses
    pa45_forward_skel "$PA45/s-noaccept" "$ST_FILE" "$hd" "$sd" "$PA45/skel-body.json" no-accept || { fail P41 "bundle-sql --kind skeleton"; return; }
    out="$(pa45_bundle "$db" "$PA45/s-noaccept.pre.sql" "$PA45/s-noaccept.post.sql" "$ST_FILE" "$ST_SHA")"; rc=$?
    [[ $rc -ne 0 && "$out" == *"the accepted skeleton is not version ${s}'s"* && "$(pa45_q "$db" <<<"SELECT iam_policy._accepted();")" == "$acc" ]] \
        && pass P41 "a skeleton version whose accept was skipped: refused, the accepted skeleton unchanged" \
        || fail P41 "skeleton without the accept: exit $rc"
    pa45_forward_skel "$PA45/s" "$ST_FILE" "$hd" "$sd" "$PA45/skel-body.json" || { fail P40 "bundle-sql --kind skeleton"; return; }
    out="$(pa45_bundle "$db" "$PA45/s.pre.sql" "$PA45/s.post.sql" "$ST_FILE" "$ST_SHA")"; rc=$?
    [[ $rc -eq 0 ]] || { grep -E 'ERROR|DETAIL' <<<"$out" | head; fail P40 "the skeleton bundle exit $rc"; return; }
    pa45_record "$db" applied "{\"version\": $s, \"kind\": \"skeleton\"}" >/dev/null || fail P40 "applied record of $s"
    out="$(pa45_q "$db" <<SQL
SELECT (iam_policy._accepted() = '$sd')::text
       || '|' || (SELECT reviewed_by_version FROM iam_policy.skeleton WHERE digest = '$sd')
       || '|' || (SELECT h.payload ->> 'skeleton_digest' = '$sd' FROM iam_policy.history h
                   WHERE h.version = $s AND h.event = 'apply_started' ORDER BY h.event_id DESC LIMIT 1)::text
       || '|' || (SELECT status FROM iam_policy.version WHERE version = $s);
SQL
)"
    [[ "$out" == "true|$s|true|applied" ]] \
        && pass P40 "skeleton version $s applied: accepted, reviewed_by_version $s, apply_started names its digest" \
        || fail P40 "after the skeleton bundle (accepted|reviewed_by_version|apply_started|status): $out"

    # P42 — a rollback to version 1 (a confirmed bootstrap, superseded) with a draft open
    out="$(pa45_q "$db" <<SQL
BEGIN;
$(pa45_iam "$PA45_A" "$PA45_PA" admin)
SELECT 'o|' || iam_policy.new_draft('applied', 'iam-db-fixture: P42', $PA45_IAT, '[]'::jsonb, '[]'::jsonb);
COMMIT;
SQL
)" || { echo "$out" | grep -m3 ERROR; fail P42 "a draft to withdraw"; return; }
    local o; o="$(grep '^o|' <<<"$out" | cut -d'|' -f2)"
    v="$(pa45_q "$db" <<<"SELECT max(version) + 1 FROM iam_policy.version;")"
    pa45_doc "$db" 1 "$PA45/k.json" && pa45_py rollback-doc "$PA45/k.json" "$v" "$PA45/r.json" \
        || { fail P42 "the rollback's document"; return; }
    out="$(pa45_py stage "$PA45/r.json" "$PA45/r.yaml" alt 2>&1)" || { fail P42 "staging the rollback: $out"; return; }
    IFS=$'\t' read -r ST_SHA ST_VER ST_ED <<<"$out"
    pa45_rollback "$PA45/r" 1 "$s" "$PA45/r.yaml" || { fail P42 "bundle-sql --kind rollback"; return; }
    out="$(pa45_bundle "$db" "$PA45/r.pre.sql" "$PA45/r.post.sql" "$PA45/r.yaml" "$ST_SHA")"; rc=$?
    [[ $rc -eq 0 ]] || { grep -E 'ERROR|DETAIL' <<<"$out" | head; fail P42 "the rollback bundle exit $rc"; return; }
    r="$v"
    pa45_record "$db" applied "{\"version\": $r, \"kind\": \"rollback\", \"rollback_of\": 1}" >/dev/null || fail P42 "applied record of $r"
    out="$(pa45_q "$db" <<SQL
SELECT (SELECT status || ':' || kind || ':' || rollback_of || ':' || based_on FROM iam_policy.version WHERE version = $r)
       || '|' || (NOT EXISTS ((SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = $r
                               EXCEPT SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = 1)
                              UNION ALL
                              (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = 1
                               EXCEPT SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = $r)))::text
       || '|' || (SELECT status || ':' || withdrawn_by FROM iam_policy.version WHERE version = $o);
SQL
)"
    [[ "$out" == "applied:rollback:1:$s|true|withdrawn:system:apply" ]] \
        && pass P42 "rollback $r to version 1: applied, its rows version 1's (read in SQL), draft $o withdrawn by system:apply" \
        || fail P42 "after the rollback bundle (status:kind:rollback_of:based_on|rows equal|draft): $out"

    # P44 — the rollback is confirmed afterwards, never by the person apply.sh recorded
    out="$(pa45_q "$db" <<SQL 2>&1
BEGIN;
$(pa45_token "$PA45_Q2" "$PA45_PQ2" /rpc/confirm_policy)
SELECT medcea.confirm_policy($r, 'iam-db-fixture', 'I did not run apply.sh for this version.');
ROLLBACK;
SQL
)"
    [[ "$out" == *"recorded you as running"* ]] && pass P44 "confirm by the person apply.sh recorded: refused" \
        || fail P44 "confirm by the recorded person: ${out:0:300}"
    out="$(pa45_q "$db" <<SQL
BEGIN;
$(pa45_token "$PA45_Q" "$PA45_PQ" /rpc/confirm_policy)
SELECT medcea.confirm_policy($r, 'iam-db-fixture', 'I did not run apply.sh for this version.') \\g /dev/null
COMMIT;
RESET ROLE;
RESET SESSION AUTHORIZATION;
SELECT (SELECT confirmed_by_person FROM iam_policy.version WHERE version = $r) || '|' || (SELECT count(*) FROM iam_policy.audit_versions())
       || '|' || (SELECT ok FROM iam_policy.verify_chain())::text;
SQL
)"
    [[ "$out" == *"$PA45_PQ|0|true" ]] && pass P44 "confirmed by another qa person; audit_versions() empty, the chain verifies" \
        || fail P44 "confirm by another qa person (person|findings|chain): ${out:0:300}"

    # P45 — the forged verdict: a submitted version whose saved verdict says ok, rows the checker refuses
    out="$(pa45_py forge 2>&1)" || { fail P45 "$out"; return; }
    local fr fg fl; IFS=$'\t' read -r fr fg fl <<<"$out"
    out="$(pa45_q "$db" <<SQL
BEGIN;
$(pa45_iam "$PA45_A" "$PA45_PA" admin)
SELECT iam_policy.new_draft('applied', 'iam-db-fixture: P45', $PA45_IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
SELECT iam_policy.save_entry(:d, '$fr', '$fg', '$fl'::jsonb, 'iam-db-fixture: P45',
                             '{"ok": true, "errors": [], "checker_digest": "forged"}'::jsonb, $PA45_IAT) \\g /dev/null
SELECT iam_policy.submit(:d, 'iam-db-fixture: P45', $PA45_IAT) \\g /dev/null
COMMIT;
RESET ROLE;
RESET SESSION AUTHORIZATION;
SELECT 'f|' || :d || '|' || (SELECT checker_verdict FROM iam_policy.version WHERE version = :d)::text;
SQL
)" || { echo "$out" | grep -m3 ERROR; fail P45 "submitting the forged version"; return; }
    IFS='|' read -r _ f ok <<<"$(grep '^f|' <<<"$out")"
    pa45_stage "$db" "$f" forged alt || return
    out="$(MEDCEA_POLICY_STAGED_SHA256="$ST_SHA" python3 "$CLI" --staged "$ST_FILE" check 2>&1)"; rc=$?
    [[ "$ok" == true && $rc -ne 0 && "$out" == *"FAIL:"* && "$(pa45_status "$db")" == *"$r:rollback:applied $f:change:submitted" ]] \
        && pass P45 "version $f (checker_verdict true) fails cli.py --staged check before any bundle ($fr/$fg)" \
        || fail P45 "the forged verdict: verdict $ok, check exit $rc, versions $(pa45_status "$db")"

    # P46 — 008c re-run twice with change, skeleton and rollback versions present
    cmd_apply true "$db"
    snap1="$(CEA_DB="$db" policy_snapshot)" && snapshot_whole "$snap1" || { fail P46 "policy_snapshot failed"; return; }
    ev="$(pa45_q "$db" <<<"SELECT max(event_id) FROM iam_policy.history;")"
    cmd_apply true "$db"
    snap2="$(CEA_DB="$db" policy_snapshot)" && snapshot_whole "$snap2" || { fail P46 "policy_snapshot failed after the re-run"; return; }
    [[ "$snap1" == "$snap2" ]] && pass P46 "008c re-run with change, skeleton and rollback versions: catalog and versions unchanged" \
        || { fail P46 "008c re-run changed the catalog or the versions:"; diff <(echo "$snap1") <(echo "$snap2") | head -20; }
    out="$(pa45_q "$db" <<<"SELECT coalesce(string_agg(event, ','), '') FROM iam_policy.history WHERE event_id > $ev AND version IS NOT NULL;")"
    [[ -z "$out" ]] && pass P46 "the re-run wrote no event under a version" || fail P46 "the re-run wrote: $out"

    # P38 under IAM_DB_ROLES=false, on medcea_pa2 (version 1 applied there under true):
    # approved on the token path while true, then the database flipped to false
    db=medcea_pa2
    c1="$(pa45_change "$db" "$r1" "$g1" "$l1" "$(pa45_dd pa2)")" || { fail P38 "drafting and approving the change on $db"; return; }
    cmd_apply false "$db"
    [[ "$(pa45_has "$db" "$dbr1" "$obj1" "$priv1")" == t ]] || { fail P38 "false: $dbr1 lacks $priv1 on $obj1 before the change"; return; }
    pa45_stage "$db" "$c1" pa2 || return
    pa45_forward "$PA45/pa2" "$c1" "$ST_FILE" "$(pa45_dd pa2)" || { fail P38 "bundle-sql for change $c1 ($db)"; return; }
    out="$(pa45_bundle "$db" "$PA45/pa2.pre.sql" "$PA45/pa2.post.sql" "$ST_FILE" "$ST_SHA" false)"; rc=$?
    [[ $rc -eq 0 ]] || { grep -E 'ERROR|DETAIL' <<<"$out" | head; fail P38 "the change bundle (false) exit $rc"; return; }
    [[ "$(pa45_status "$db")" == "1:bootstrap:superseded $c1:change:applied" && "$(pa45_has "$db" "$dbr1" "$obj1" "$priv1")" == f ]] \
        && pass P38 "false: change $c1 applied, version 1 superseded, $dbr1 lost $priv1 on $obj1" \
        || fail P38 "false: versions $(pa45_status "$db")"
    out="$(pa45_q "$db" <<<"SELECT obj_description('medcea_auth.role_widening(text,text)'::regprocedure, 'pg_proc');")"
    [[ "$out" == "policy $(pa45_routes "$ST_FILE" "$ST_SHA")" ]] && pass P38 "false: role_widening()'s comment is the staged routes digest" \
        || fail P38 "false: role_widening()'s comment: $out"
    out="$(pa45_record "$db" applied "{\"version\": $c1, \"kind\": \"change\"}" && pa45_q "$db" <<<"SELECT count(*) FROM iam_policy.audit_versions();")"
    [[ "$out" == 0 ]] && pass P38 "false: applied recorded, audit_versions() empty" || fail P38 "false: findings after the record: $out"
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
# mqtt_auth reads master_data, so it executes that group's read function
# medcea.unit_commissioning() (approvals and test mode); the sidecar never calls it,
# and a caller without a person gets no names, reasons or rights from it.
# Production may run IAM_DB_ROLES=true: B0 is then compared with the first apply
# true (T1) instead, and the seed has reset the database setting the flag lives in.
# Superset stage C: until production applies the skeleton version that adds
# svc_superset, its RLS policy on measurement exists in the fixture's apply only.
DELTA='^[<>] owner\|
^[<>] secdef\|
^[<>] trigger\|
^[<>] defacl\|
^[<>] .*databasechangeloglock
^< acl\|authenticator\|(table|sequence)\|medcea\.schedule
^> acl\|anon\|schema\|medcea_auth\|USAGE
^> acl\|anon\|function\|medcea_auth\.pre_request\(\)\|EXECUTE
^> acl\|mqtt_auth\|function\|medcea\.unit_commissioning\(\)\|EXECUTE
^< acl\|PUBLIC\|function\|
^> reloption\|.*security_invoker=true
^> dbsetting\|\*\|medcea\.iam_db_roles=(false|true)
^> role\|(rr_|svc_|iam_svc)
^< role\|(rr_|svc_|iam_svc)
^< member\|rr_admin\|rr_admin_login\|
^> constraint\|
^[<>] acl\|access_svc\|
^> policy\|medcea\.measurement\|iam_s_svc_superset_[0-9a-f]+\|svc_superset\|'
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
    # IAM 4.1: no policy wrapper left in medcea, and no postgres-owned definer function there
    left="$(fx medcea_db -q -tA -c "SELECT string_agg(p.oid::regprocedure::text, ', ') FROM pg_proc p
             WHERE p.pronamespace = 'medcea'::regnamespace
               AND (p.proname IN ('approve_policy', 'return_policy', 'confirm_policy', 'dispute_policy')
                    OR (p.prosecdef AND p.proowner = 'postgres'::regrole AND p.proname IN ('approve_policy', 'return_policy', 'confirm_policy', 'dispute_policy')))")"
    [[ -z "$left" ]] && pass fulldown "no medcea.*_policy wrapper after the full down" || fail fulldown "policy wrappers left: $left"
    left="$(fx medcea_db -q -tA -c "SELECT string_agg(p.oid::regprocedure::text, ', ') FROM pg_proc p
             WHERE p.pronamespace = 'medcea'::regnamespace AND p.prosecdef AND p.proowner = 'postgres'::regrole
               AND p.oid NOT IN (to_regprocedure('medcea.register_mqtt_credential(text,text,integer,text,text)'),
                                 to_regprocedure('medcea.log_device_slot()'))")"
    [[ -z "$left" ]] && pass fulldown "no other postgres-owned SECURITY DEFINER function in medcea" || fail fulldown "postgres-owned definers: $left"
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
    # the Approve action's and the commissioning screen's functions and trigger (2026-10-31)
    left="$(fx medcea_db -q -tA -c "SELECT string_agg(f, ', ') FROM unnest(ARRAY['medcea.approve_recipe(integer,text)',
              'medcea.approve_algorithm(integer,text)', 'medcea.approve_params(integer,text)', 'medcea.return_change(text,bigint,text)',
              'medcea.withdraw_change(bigint,text)', 'medcea.approval_queue(boolean)', 'medcea.my_approvals()',
              'medcea.unit_commissioning()', 'medcea._unit_busy(integer)', 'medcea._unit_schedulable(integer)', 'medcea._pending_lock(bigint)',
              'medcea.log_commissioning()', 'medcea_auth._changes_since(text,jsonb)']) f
             WHERE pg_catalog.to_regprocedure(f) IS NOT NULL
             UNION ALL SELECT 'trigger commissioning_history_trg' FROM pg_catalog.pg_trigger WHERE tgname = 'commissioning_history_trg'")"
    [[ -z "${left//[[:space:]|]/}" ]] && pass fulldown "the approval queue, return/withdraw, commissioning functions and trigger gone after the full down" \
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
        -c 'DROP DATABASE IF EXISTS medcea_old27 WITH (FORCE);' -c 'DROP DATABASE IF EXISTS medcea_pa WITH (FORCE);' \
        -c 'DROP DATABASE IF EXISTS medcea_pa2 WITH (FORCE);' >/dev/null
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

# svcprobe ROLE LABEL WANT [ISOLATION] — SQL on stdin, as ROLE (SET SESSION AUTHORIZATION,
# so rr_admin_login inherits rr_admin as when it logs in), in BEGIN [ISOLATION LEVEL …]
# … ROLLBACK; the SQL must not end the transaction itself.
# WANT: ok, "denied" (a permission error expected) or err:TEXT (an error containing TEXT).
svcprobe() {
    local role="$1" label="$2" want="$3" iso="${4:+ ISOLATION LEVEL $4}" out
    out="$( { echo "BEGIN$iso;"; echo "SET SESSION AUTHORIZATION $role;"; cat; echo "SELECT 'probe-done';"; echo "ROLLBACK;"; } \
            | fx medcea_db -q -tA -v ON_ERROR_STOP=1 -f - 2>&1)"
    if [[ "$want" == ok ]]; then
        grep -q 'probe-done' <<<"$out" && pass svc "$role: $label" || fail svc "$role: $label: $(grep -m1 ERROR <<<"$out")"
    elif [[ "$want" == err:* ]]; then
        grep 'ERROR' <<<"$out" | grep -qF "${want#err:}" && pass svc "$role: $label (refused)" \
            || fail svc "$role: $label: expected an error with '${want#err:}', got: $(grep -m1 -E 'ERROR|probe-done' <<<"$out")"
    else
        grep -q 'permission denied' <<<"$out" && pass svc "$role: $label (refused)" \
            || fail svc "$role: $label: expected permission denied, got: $(grep -m1 -E 'ERROR|probe-done' <<<"$out")"
    fi
}

# Each service's own statements (the 2.5 inventory: monitor-api.py, dbmgmt-api.py,
# Node-RED's INSERT, the Grafana dashboard, pgAdmin's rr_admin), as its role. The
# scheduler's are tests/iam-runner.sh --mode false-svc, but for its own_unit reads (2.6).
cmd_svcprobes() {
    step "the services' statements as their own roles (IAM 2.5)"
    svcprobe svc_monitor "runs, cycles, telemetry views" ok <<'SQL'
SELECT count(*) FROM medcea.recipe_run r JOIN medcea.cea_unit u ON u.unit_id = r.unit_id JOIN medcea.recipe c ON c.recipe_id = r.recipe_id;
SELECT count(*) FROM medcea.recipe_line l, medcea.recipe_line_cycle_run x WHERE x.recipe_run_id IS NOT NULL LIMIT 1;
SELECT count(*) FROM medcea.v_ap_measurements;
SELECT count(*) FROM medcea.v_ct_measurements;
SQL
    # IAM 2.6 own_unit: the scoped reads with a literal sub (monitor-api.py, scheduler-api.py)
    svcprobe svc_monitor "own_unit scoped reads" ok <<'SQL'
SELECT count(*) FROM medcea.recipe_run rr WHERE rr.unit_id IN (SELECT uu.unit_id FROM iam_policy.user_unit uu WHERE uu.person_sub = '11111111-1111-4111-8111-111111111111'::uuid);
SELECT count(*) FROM medcea.measurement m WHERE m.msg_type::text IN ('AP', 'CT') AND m.msg ->> 'unit_code' = 'IAMT01'
   AND m.zone_id IN (SELECT cz.zone_id FROM medcea.cea_zone cz JOIN iam_policy.user_unit uu ON uu.unit_id = cz.unit_id WHERE uu.person_sub = '11111111-1111-4111-8111-111111111111'::uuid);
SQL
    svcprobe svc_scheduler "own_unit scoped reads" ok <<'SQL'
SELECT count(*) FROM medcea.recipe_run rr WHERE rr.unit_id IN (SELECT uu.unit_id FROM iam_policy.user_unit uu WHERE uu.person_sub = '11111111-1111-4111-8111-111111111111'::uuid);
SELECT count(*) FROM medcea.recipe_line_cycle_run rlcr WHERE rlcr.recipe_run_id IN (SELECT x.recipe_run_id FROM medcea.recipe_run x
 WHERE x.unit_id IN (SELECT uu.unit_id FROM iam_policy.user_unit uu WHERE uu.person_sub = '11111111-1111-4111-8111-111111111111'::uuid));
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
    # IAM 2.6: every export is one REPEATABLE READ transaction, set_actor → reads → log_export
    svcprobe svc_dbexport "set_actor then log_export" ok "REPEATABLE READ" <<'SQL'
SELECT medcea_auth.set_actor('00000000-0000-4000-8000-0000000000e1', '00000000-0000-4000-8000-0000000000e1', 'iamt-auditor', 'auditor');
SELECT count(*) FROM medcea.measurement;
SELECT iam_policy.log_export(ARRAY['measurements'], ARRAY['medcea.measurement:table:ddl']);
SQL
    svcprobe svc_dbexport "log_export without an actor" "err:no actor" <<'SQL'
SELECT iam_policy.log_export(ARRAY[]::text[], ARRAY[]::text[]);
SQL
    svcprobe svc_dbexport "writing export_log directly" denied <<'SQL'
INSERT INTO iam_policy.export_log (groups, objects) VALUES ('{}', '{}');
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
    policy) cmd_policy ;;
    policy-apply) cmd_policy_apply ;;
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
        cmd_apply true; probes true; cmd_access true; cmd_policy; cmd_policy_apply; cmd_logins true; cmd_preflight
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
