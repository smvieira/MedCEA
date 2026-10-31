#!/usr/bin/env bash
# infra/lib-db-roles.sh — which PostgreSQL role each database client logs in as
# (IAM plan Phase 2.5, IAM_DB_SERVICE_ROLES).
#
#   db_role_secret ROLE        the Secret apps/database/deploy.sh writes for ROLE
#   db_role_can_login NS ROLE  0 = ROLE exists and may log in, 1 = not, 2 = cannot tell
#   db_client NS ROLE          sets DBC_USER, DBC_PASS, DBC_SECRET, DBC_SECRET_KEY
#   db_clients_live NS         "<client> <user>" for every client that is deployed
#   db_client_role CLIENT      the role a client of db_clients_live moves to
#
# The clients and their roles:
#   scheduler (and the runner it spawns)  svc_scheduler   apps/scheduler/deploy.sh
#   monitor                               svc_monitor     apps/monitor/deploy.sh
#   dbmgmt                                svc_dbexport    apps/frontend/deploy.sh
#   node-red (ingest flow)                svc_ingest      apps/node-red/deploy.sh
#   grafana (datasource)                  svc_grafana     deploy-infra.sh
#   pgadmin (server entry)                rr_admin_login  deploy-infra.sh
#   iam-api (MQTT Explorer credentials)   iam_svc         apps/iam/deploy.sh (never postgres: it refuses)
#
# A client moves to its own role only when IAM_DB_SERVICE_ROLES=true AND the role
# can already log in; otherwise it stays on postgres and says why. The database
# deploy, for its part, keeps a role able to log in while a live client still uses
# it (db_clients_live). So infra, apps and database can be deployed in any order:
# nothing ever points a client at a role that cannot log in, and each later deploy
# moves the platform one step closer to the flag. Takes no lock (its callers hold
# medcea_lock). Needs KUBECTL, REPO_ROOT and config.env; never prints a password.

if ! declare -F _dba_psql >/dev/null; then
    # shellcheck source=/dev/null
    source "$REPO_ROOT/apps/database/lib-db-apply.sh"   # _dba_psql
fi

_dbr_warn() { echo -e "\033[0;33m[db-roles] $*\033[0m" >&2; }

db_role_secret() {
    case "$1" in
        svc_*)          echo "db-${1//_/-}" ;;
        iam_svc)        echo "db-iam-svc" ;;
        rr_admin_login) echo "db-rr-admin-login" ;;
        authenticator)  echo "db-authenticator" ;;
        *)              echo "db-${1//_/-}" ;;
    esac
}

db_client_role() {
    case "$1" in
        scheduler) echo svc_scheduler ;;
        monitor)   echo svc_monitor ;;
        dbmgmt)    echo svc_dbexport ;;
        node-red)  echo svc_ingest ;;
        grafana)   echo svc_grafana ;;
        pgadmin)   echo rr_admin_login ;;
        iam-api)   echo iam_svc ;;
        *)         return 1 ;;
    esac
}

# the config.env variable holding ROLE's password (empty: none)
_dbr_pass_var() {
    python3 "$REPO_ROOT/apps/iam/compiler/cli.py" db-roles --passwords | awk -v r="$1" '$1 == r {print $2}'
}

_dbr_pg_pod() {
    $KUBECTL get pod -n "$1" -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

db_role_can_login() {
    local ns="$1" role="$2" pod out
    pod="$(_dbr_pg_pod "$ns")" || return 2
    [[ -n "$pod" ]] || return 2
    out="$(_DBA_NS="$ns" _DBA_POD="$pod" _dba_psql postgres -tAq \
        -c "SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = '$role'" 2>/dev/null)" || return 2
    case "$(tr -d '[:space:]' <<<"$out")" in
        t) return 0 ;;
        *) return 1 ;;
    esac
}

db_client() {
    local ns="$1" role="$2" var why="" rc=0
    DBC_USER=postgres; DBC_PASS="${POSTGRES_PASS:-}"
    DBC_SECRET="${PG_RELEASE:-rdbms}-postgresql"; DBC_SECRET_KEY=postgres-password
    [[ "${IAM_DB_SERVICE_ROLES:-false}" == true ]] || return 0
    var="$(_dbr_pass_var "$role")"
    if [[ -z "$var" || -z "${!var:-}" ]]; then
        why="${var:-its password variable} is empty (run ./deploy-infra.sh, which runs infra/configure.sh)"
    elif ! $KUBECTL get secret "$(db_role_secret "$role")" -n "$ns" >/dev/null 2>&1; then
        why="Secret $(db_role_secret "$role") does not exist yet (./apps/database/deploy.sh writes it)"
    else
        db_role_can_login "$ns" "$role" || rc=$?
        case $rc in
            0) DBC_USER="$role"; DBC_PASS="${!var}"
               DBC_SECRET="$(db_role_secret "$role")"; DBC_SECRET_KEY=password
               return 0 ;;
            1) why="role $role cannot log in yet (./apps/database/deploy.sh with IAM_DB_SERVICE_ROLES=true lets it)" ;;
            *) why="PostgreSQL could not be asked whether $role may log in" ;;
        esac
    fi
    _dbr_warn "IAM_DB_SERVICE_ROLES=true, but this client stays on postgres: $why; deploy it again afterwards"
    return 0
}

# Reads only, and safe under set -e (every lookup may fail). A client that is not
# deployed prints nothing; one whose user cannot
# be read prints "<client> ?", which the database deploy treats as in use.
db_clients_live() {
    local ns="$1" d u
    for d in scheduler monitor dbmgmt iam-api; do
        $KUBECTL get deployment "$d" -n "$ns" >/dev/null 2>&1 || continue
        u="$($KUBECTL get deployment "$d" -n "$ns" \
            -o jsonpath='{range .spec.template.spec.containers[*].env[?(@.name=="PG_USER")]}{.value}{"\n"}{end}' 2>/dev/null | head -1)" || u=""
        echo "$d ${u:-?}"
    done
    if $KUBECTL get deployment node-red -n "$ns" >/dev/null 2>&1; then
        # A Node-RED with no flows deployed yet (a fresh persistent /data after
        # ./deploy-infra.sh, before ./apps/node-red/deploy.sh) opens no database
        # connection: not a live client. "?" stays for a pod that cannot be asked.
        f="$($KUBECTL exec -n "$ns" deployment/node-red -- sh -c 'test -f /data/flows.json && echo yes || echo no' 2>/dev/null)" || f=""
        if [[ "$f" == no ]]; then :; else
        u="$($KUBECTL exec -n "$ns" deployment/node-red -- cat /data/flows.json 2>/dev/null \
            | python3 -c 'import json,sys
try:
    print(next(n.get("user", "") for n in json.load(sys.stdin) if n.get("type") == "postgreSQLConfig"))
except Exception:
    pass' 2>/dev/null)" || u=""
        [[ "$f" == yes ]] || u=""
        echo "node-red ${u:-?}"
        fi
    fi
    if $KUBECTL get secret grafana-datasource -n "$ns" >/dev/null 2>&1; then
        u="$($KUBECTL get secret grafana-datasource -n "$ns" -o jsonpath='{.data.datasources\.yaml}' 2>/dev/null \
            | base64 -d 2>/dev/null | awk '$1 == "user:" {print $2; exit}')" || u=""
        echo "grafana ${u:-?}"
    fi
    if $KUBECTL get configmap pgadmin-servers -n "$ns" >/dev/null 2>&1; then
        u="$($KUBECTL get configmap pgadmin-servers -n "$ns" -o jsonpath='{.data.servers\.json}' 2>/dev/null \
            | python3 -c 'import json,sys
try:
    print(next(iter(json.load(sys.stdin)["Servers"].values()))["Username"])
except Exception:
    pass' 2>/dev/null)" || u=""
        echo "pgadmin ${u:-?}"
    fi
}
