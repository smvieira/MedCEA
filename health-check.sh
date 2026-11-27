#!/bin/bash
# health-check.sh — MedCEA deployment health checker
#
# Usage:
#   ./health-check.sh [OPTIONS]
#
# Options:
#   -c, --config FILE    Check config file (default: health-checks.conf in same dir)
#   -v, --verbose        Show detailed output for all checks, including passing ones
#   -t, --timeout SECS   Timeout per check in seconds (default: 8)
#   -h, --help           Show this help
#
# The config file lists services to check (see health-checks.conf for format).
# Variable references like $DOMAIN in targets are expanded from config.env.

# Colors (defined early for --help)
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/health-checks.conf"
VERBOSE=false
TIMEOUT=8

# Auto-detect kubectl: prefer microk8s (no sudo needed if user is in microk8s group)
if command -v microk8s &>/dev/null && microk8s kubectl version --client &>/dev/null 2>&1; then
    KUBECTL="microk8s kubectl"
elif command -v kubectl &>/dev/null; then
    KUBECTL="kubectl"
else
    KUBECTL="sudo microk8s kubectl"
fi

# =============================================================================
# --help
# =============================================================================
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo ""
    echo -e "${BOLD}health-check.sh${NC} — MedCEA deployment health checker"
    echo ""
    echo -e "${GREEN}Usage:${NC}"
    echo "  ./health-check.sh [OPTIONS]"
    echo ""
    echo -e "${GREEN}Options:${NC}"
    echo "  -c, --config FILE    Check config file (default: health-checks.conf)"
    echo "  -v, --verbose        Show detail for passing checks too"
    echo "  -t, --timeout SECS   Per-check timeout in seconds (default: 8)"
    echo "  -h, --help           Show this help"
    echo ""
    echo -e "${GREEN}Config file format (health-checks.conf):${NC}"
    echo "  # comment"
    echo "  Service Name  | type  | target            | [options]"
    echo ""
    echo "  Types:"
    echo -e "  ${CYAN}k8s${NC}    Kubernetes workload: NAMESPACE/KIND/NAME"
    echo -e "         e.g. medcea/deployment/keycloak"
    echo -e "              medcea/statefulset/rdbms-postgresql"
    echo ""
    echo -e "  ${CYAN}http${NC}   HTTP GET check: URL (\$VARs from config.env are expanded)"
    echo -e "         options: skip_tls       skip TLS certificate verification"
    echo -e "                  expect=CODE    e.g. expect=302, expect=30x, expect=2xx"
    echo ""
    echo -e "  ${CYAN}tcp${NC}    TCP port: HOST:PORT"
    echo -e "         e.g. localhost:5432"
    echo ""
    echo -e "  ${CYAN}mqtttls${NC} the boards' broker port: HOST:PORT answers TLS with a certificate that"
    echo -e "         verifies against the platform CA (.ca/ca.crt) for mqtt.\$DOMAIN, and the"
    echo -e "         plain port 31883 is closed; e.g. localhost:31884"
    echo ""
    echo -e "  ${CYAN}apparmor${NC} the stacked-peer rules in MicroK8s's container AppArmor profile"
    echo -e "         (infra/lib-apparmor.sh): units installed, rules loaded, no signal denial"
    echo -e "         inside a container since, no host profile attached inside one; no target"
    echo ""
    echo -e "  ${CYAN}pvc${NC}    a PersistentVolumeClaim is Bound: NAMESPACE/NAME"
    echo -e "         e.g. medcea/grafana; WARN when it is missing or not Bound (the service"
    echo -e "         then keeps nothing across a restart, or does not start)"
    echo ""
    echo -e "  ${CYAN}iamchain${NC} the access policy history's hash chain: DATABASE"
    echo -e "         e.g. \$POSTGRES_DB   (iam_policy.verify_chain(); SKIP before migration 008a); WARN when"
    echo -e "         verify_chain() is not SECURITY DEFINER or iam_svc may not execute it (the Policy UI's History)"
    echo ""
    echo -e "  ${CYAN}iamanchor${NC} the history chain's head anchored in the newest nightly backup (Phase 5): DATABASE"
    echo -e "         the event the newest complete backup's MANIFEST names must be in iam_policy.history with"
    echo -e "         the recorded hash (read-only psql). FAIL when it is missing or its hash differs; WARN"
    echo -e "         without a readable backup or head, a backup over 48 h old, an unreadable database."
    echo -e "         Not proof against a superuser who altered both the database and BACKUP_DIR"
    echo ""
    echo -e "  ${CYAN}iamdbroles${NC} IAM_DB_ROLES (Phase 2): DATABASE"
    echo -e "         WARN while it is false (the database still serves the pre-policy grants),"
    echo -e "         so a default install does not print \"All checks passed\" — on purpose"
    echo ""
    echo -e "  ${CYAN}dbclients${NC} which role each database client logs in as (IAM_DB_SERVICE_ROLES, Phase 2.5)"
    echo -e "         WARN while a client disagrees with the flag (deploy it again)"
    echo ""
    echo -e "  ${CYAN}iamgrants${NC} the database's grants equal the compiled policy: DATABASE"
    echo -e "         (cli.py compile grants --mode verify, in a read-only transaction; drift is a FAIL;"
    echo -e "         --without-iam while schema iam is absent, from dba_iam_flag; a stale"
    echo -e "         medcea_auth.role_widening digest is drift too). SKIP only when the first ERROR is the missing"
    echo -e "         medcea.platform_setting or a missing medcea_auth function (migration 008b), never on a DETAIL;"
    echo -e "         under IAM_DB_ROLES=false a medcea table or view in no group is a WARN (I15's classification)"
    echo ""
    echo -e "  ${CYAN}iamcatalog${NC} the database catalog (Phase 5, tests/iam-db.sh's statements): DATABASE"
    echo -e "         FAIL when an object in medcea, medcea_auth, iam_policy or iam is not owned by medcea_owner,"
    echo -e "         a freeze/append-only trigger (or user_unit_audit_trg, commissioning_history_trg) is not"
    echo -e "         ENABLE ALWAYS, or a medcea view lacks security_invoker (names the first five); WARN when"
    echo -e "         the database cannot be read; SKIP before ./apps/database/deploy.sh"
    echo ""
    echo -e "  ${CYAN}iampolicy${NC} the applied access policy version (IAM 4.2a): DATABASE"
    echo -e "         SKIP before migration 008c or without kubectl; FAIL when PostgreSQL cannot be read,"
    echo -e "         no version is applied yet (./apps/iam/deploy.sh bootstraps it), state/policy-applied.yaml"
    echo -e "         is absent or differs from the database (header or body), the git skeleton widens over"
    echo -e "         the accepted one, an earlier accept widened, an apply did not record its end, a policy"
    echo -e "         break-glass is still open, audit_versions() finds anything, the chain is broken, or a"
    echo -e "         waiver's review date has passed; WARN on queued account facts, an apply in progress,"
    echo -e "         a narrowing git skeleton, git lagging the applied matrix, a waiver due within 30 days,"
    echo -e "         the Policy UI's compiler_digest not this checkout's compiler (./apps/iam/deploy.sh)"
    echo ""
    echo -e "  ${CYAN}iamartefacts${NC} the live route table, MQTT rows and sign-in gates are the applied"
    echo -e "         version's compile (IAM 4.2a): NAMESPACE. SKIP without ConfigMap medcea-iam-lib;"
    echo -e "         FAIL on a digest or gate that differs (the message names the deploy); WARN while the"
    echo -e "         User Manager's gate is admin-only; hosts whose proxy is not deployed are counted"
    echo ""
    echo -e "  ${CYAN}iamloaded${NC} every Running pod of the six route-checking services loads the routes.json"
    echo -e "         the ConfigMap holds (read-only kubectl exec: python3 prints the digest and applied_version"
    echo -e "         only): NAMESPACE. FAIL when a pod's digest differs from medcea/routes-digest 120 s or more"
    echo -e "         after the ConfigMap's last write (its newest managedFields time; unreadable = past), or the file is missing"
    echo -e "         where the service enforces (access, dbmgmt, iam-api always; the rest under enforce=true);"
    echo -e "         WARN inside the 120 s, on a missing file otherwise, an unreadable pod; services not"
    echo -e "         deployed are counted; applied_version is information only"
    echo ""
    echo -e "  ${CYAN}jwks${NC}   the realm's signing keys against Secret medcea-jwks, always on: NAMESPACE"
    echo -e "         FAIL when the Secret or a key in it is missing, unparseable or without an RS256 signing"
    echo -e "         key, jwks-sig.json is not infra/jwks-sig.py's signing_keys(jwks.json), the Secret holds a"
    echo -e "         key id the realm no longer publishes, or the realm signs with a key id the Secret lacks"
    echo -e "         (./deploy-infra.sh); WARN when the realm does not answer (the Keycloak checks report it)"
    echo ""
    echo -e "  ${CYAN}kcscopes${NC} Keycloak's client scopes: REALM (Keycloak's database, read-only psql in the pod)"
    echo -e "         every client of infra/lib-keycloak-clients.sh has groups and medcea-identity as default"
    echo -e "         scopes, groups maps realm roles to the groups claim, medcea-identity carries the medcea-api"
    echo -e "         audience and person_id. FAIL for a scope or mapper missing in the realm, and for a missing"
    echo -e "         client or scope on a client whose tokens reach a platform API (KC_API_CLIENTS); WARN on a"
    echo -e "         tool-only client, an optional-only scope, full_scope_allowed=false, an audience in the ID"
    echo -e "         token, a client-level mapper writing groups/person_id/aud, an unreadable database."
    echo -e "         A client of KC_POLICY_TOKEN_CLIENTS (workbench-notebook) the applied policy no longer"
    echo -e "         names as a token client is retired: FAIL while it is enabled, OK when absent or disabled"
    echo ""
    echo -e "  ${CYAN}iamnetpol${NC} the application pods' NetworkPolicies (IAM_NETPOL): NAMESPACE"
    echo -e "         true: every compiled iam-<pod> policy present (else FAIL), a stale labelled one WARNs;"
    echo -e "         false: WARN, also while labelled policies remain (./deploy-infra.sh deletes them)"
    echo ""
    echo -e "  ${CYAN}rsnetpol${NC} the research zone's NetworkPolicies (research sandbox): NAMESPACE"
    echo -e "         every NetworkPolicy in RESEARCH_NAMESPACE (else NAMESPACE-research) against"
    echo -e "         cli.py compile netpol --zone research, specs compared, the default deny included:"
    echo -e "         FAIL when a compiled one is missing or differs, or any other policy is there"
    echo -e "         (labelled or not: it widens the zone); WARN when unreadable;"
    echo -e "         SKIP while RESEARCH_ENABLED is not true and the namespace is absent (WARN when it remains),"
    echo -e "         and while the applied policy has no research zone"
    echo ""
    echo -e "  ${CYAN}iamdecisions${NC} account decisions waiting for qa (IAM 2.7): DATABASE"
    echo -e "         SKIP without schema iam or role access_svc; FAIL without iam.confirm_decision"
    echo -e "         (./apps/access/deploy.sh) or when access_svc may not execute it"
    echo -e "         (./apps/database/deploy.sh); WARN on a decision pending for over 7 days"
    echo -e "         or a pending mail settings change"
    echo ""
    echo -e "  ${CYAN}iampending${NC} configuration changes waiting for qa: DATABASE"
    echo -e "         SKIP before the approval functions exist (./apps/database/deploy.sh);"
    echo -e "         WARN on a pending change (commissioning proposal, log setting, review of"
    echo -e "         a commissioning end) waiting for over 7 days: Config UI → Approvals"
    echo ""
    echo -e "  ${CYAN}iamdrift${NC} Keycloak's accounts against the account record (Phase 5): NAMESPACE"
    echo -e "         access-api computes the drift every 10 min and its admin /healthz gives counts only"
    echo -e "         (read-only kubectl exec, no token, no names). FAIL on an unexplained platform role or a"
    echo -e "         failed compensation; WARN on an account enabled while its grant waits for qa, an enabled"
    echo -e "         account with no record that was not seeded, a result older than 30 min, a failed or"
    echo -e "         truncated computation, a fresh pod, an access-api older than the report"
    echo -e "         (./apps/access/deploy.sh); SKIP without access"
    echo ""
    echo -e "  ${CYAN}controlloops${NC} the feedback control loops (Q11/Q20): DATABASE (read-only psql)"
    echo -e "         WARN on an active zone with actuators and no active medcea.control_loop rows (the"
    echo -e "         runner's default map), on such a zone whose tag has two or more named sensors (no_data"
    echo -e "         + ALARM ambiguous_source: choose the reference in onboarding) or with sensor problems"
    echo -e "         in _zone_inventory (re-onboard), and on an active loop medcea._loop_problems() rejects;"
    echo -e "         never FAIL; SKIP before migration 010"
    echo ""
    echo -e "  ${CYAN}controllers${NC} the controller libraries in the scheduler pod (MPC: gekko, FLC: scikit-fuzzy): NAMESPACE"
    echo -e "         read-only kubectl exec into each Running scheduler pod, versions only; WARN (never FAIL)"
    echo -e "         when either is missing, broken or not apps/scheduler/requirements-controllers.txt's pin"
    echo -e "         (MPC and FLC then run as bang-bang); SKIP without the scheduler"
    echo ""
    echo -e "  ${CYAN}postgrest${NC} config-api verifies tokens (IAM_POSTGREST_JWT, Phase 2b): NAMESPACE"
    echo -e "         true: config-api's env is the JWT template's, its key checksum matches"
    echo -e "         Secret medcea-jwks and a forged token gets 401; false: WARN. The realm's key ids"
    echo -e "         against the Secret are the jwks check's, in either mode"
    echo ""
    echo -e "  ${CYAN}iamenforce${NC} the Python services enforce the route table (IAM_ENFORCE, IAM 2.6): NAMESPACE"
    echo -e "         FAIL when ConfigMap medcea-iam-lib disagrees with config.env (./deploy-infra.sh),"
    echo -e "         and on IAM_ENFORCE=true with IAM_DB_ROLES=false (assigned_run unchecked) or a pod copy"
    echo -e "         still false (fails open without /iam/), and when settings.json has no enforce key; WARN on"
    echo -e "         a pod copy still true, while false, or when settings.json's switches differ from config.env"
    echo ""
    echo -e "  ${CYAN}iammqtt${NC} the MQTT Explorer's personal credentials (IAM_MQTT_PERSON, IAM 3.5): NAMESPACE"
    echo -e "         FAIL when config.env, the broker (pod annotation, sidecar, conf), the Explorer page"
    echo -e "         and iam-api disagree on the mode; under true also when the shared mqtt-explorer"
    echo -e "         account or a person credential is in the 1883 file, another name is in the"
    echo -e "         WebSocket file, or IAM_DB_ROLES is false; WARN while false, or when the broker's"
    echo -e "         sidecar last read the database over 5 minutes ago. Under true every Running iam-api pod's"
    echo -e "         mqtt_digest must be medcea/mqtt-digest: WARN within 120 s of the ConfigMap's last write,"
    echo -e "         FAIL after (./apps/iam/deploy.sh). Usernames only, never a hash"
    echo ""
    echo -e "  ${CYAN}grafanarole${NC} Grafana's role setting is the access policy's (IAM 3.1): NAMESPACE"
    echo -e "         FAIL when the live role path differs from the compiled one (./deploy-infra.sh),"
    echo -e "         strict is not true or Grafana may grant Grafana Admin; WARN while IAM_GATES=false"
    echo -e "         (any enabled account is at least Viewer); SKIP without the deployment"
    echo ""
    echo -e "  ${CYAN}iamworkbench${NC} the AI workbench's gate is the access policy's (IAM 3.2): NAMESPACE"
    echo -e "         FAIL when the hub's deployed allowed_groups differ from the compiled ones, hub"
    echo -e "         role workbench-admin's scopes are not exactly the decided ones or its members not"
    echo -e "         the compiled ones, anyone can hold the built-in admin role (admin_groups,"
    echo -e "         admin_users, admin role members), allow_all is set, delete_pvc or auth_state is"
    echo -e "         on, the notebooks' NetworkPolicy allows private addresses, or the hub pod runs"
    echo -e "         older values (./infra/deploy-workbench.sh); WARN while IAM_GATES=false; SKIP"
    echo -e "         while WORKBENCH_ENABLED is not true or there is no hub. The hub's namespace is the"
    echo -e "         access policy's (workbench_namespace): a release only in the other one WARNs (deferred:"
    echo -e "         ./infra/deploy-workbench.sh --move), in both FAILs. In the research zone also FAIL on the"
    echo -e "         chart's own NetworkPolicy, blockWithIptables, a missing medcea-a2 hook, a Role on secrets"
    echo -e "         or a hub pod without priorityClassName medcea-research-low (no platform egress rule there)"
    echo ""
    echo -e "  ${CYAN}wbaccounts${NC} the AI workbench's hub users (research sandbox Phase 2b): NAMESPACE"
    echo -e "         read-only kubectl exec into the hub (its sqlite opened mode=ro, names only) against"
    echo -e "         the realm's enabled accounts (read-only psql in Keycloak's database); WARN (never FAIL)"
    echo -e "         naming hub users without one: remove them in /hub/admin, their own hub API tokens"
    echo -e "         outlive the account; SKIP while WORKBENCH_ENABLED is not true or no hub runs"
    echo ""
    echo -e "  ${CYAN}onboardroles${NC} the onboarding wizard admits the access policy's roles (IAM 3.4): -"
    echo -e "         FAIL when the running daemon's --required-role differs from policy_tool edge-wizard"
    echo -e "         (./apps/edge-wizard/deploy.sh) or is missing while IAM_GATES=true; WARN while"
    echo -e "         IAM_GATES=false; SKIP when no daemon runs (the http check reports it)"
    echo ""
    echo -e "  ${CYAN}pgadminroles${NC} pgAdmin admits the access policy's roles (IAM 3.4): NAMESPACE"
    echo -e "         FAIL when OAUTH2_ADDITIONAL_CLAIMS in Secret pgadmin-config differs from policy_tool"
    echo -e "         pgadmin, or the deployment still holds the OAuth2 config or default password as plain"
    echo -e "         env (./deploy-infra.sh); WARN while IAM_GATES=false; SKIP without the deployment"
    echo ""
    echo -e "  ${CYAN}supersetroles${NC} Superset admits the access policy's roles (Superset stages B, C): NAMESPACE"
    echo -e "         FAIL when SUPERSET_ROLES_MAPPING in Secret superset-secrets differs from policy_tool"
    echo -e "         superset (or the policy has no superset tool, or gives no role a setting), a running"
    echo -e "         pod was started with another Secret or ConfigMap (medcea/config-checksum), a secret"
    echo -e "         is a plain env value in the deployment or a ReplicaSet, the secret key is empty or"
    echo -e "         the default, the connection is not svc_superset, or the image has no digest; WARN"
    echo -e "         while IAM_GATES=false or IAM_DB_SERVICE_ROLES is not true; SKIP without the deployment"
    echo ""
    echo -e "  ${CYAN}backupage${NC} the nightly backup (apps/backup): NAMESPACE"
    echo -e "         OK while the newest OK marker in BACKUP_DIR is at most 26 h old, WARN beyond,"
    echo -e "         FAIL beyond 72 h; SKIP without CronJob medcea-backup, and on its first day"
    echo ""
    echo -e "  ${CYAN}rsexport${NC} the research export's newest snapshot (apps/research-export): NAMESPACE"
    echo -e "         read-only psql in research-postgresql-0: OK while the newest lake.snapshot is at most"
    echo -e "         26 h old, WARN beyond, FAIL beyond 72 h; FAIL when rows of it fall in a held-out"
    echo -e "         reservation (vault.reserved_rows_in); WARN with no reservation or unreadable;"
    echo -e "         SKIP without CronJob research-export, and on its first day"
    echo ""
    echo -e "  ${CYAN}rsgrants${NC} Secrets and grants of the research zone (research sandbox Phase 2b): NAMESPACE"
    echo -e "         FAIL when a pod or pod template in the research namespace names a Secret outside its"
    echo -e "         allow-list (research-postgresql-auth, lake-api-auth, model-gateway-keys, hub for the hub and its proxy,"
    echo -e "         singleuser for notebooks, none for anything else), a Role there grants secrets or *, a"
    echo -e "         RoleBinding binds a ClusterRole, or apps/research/db/assert_grants.sql (read-only) prints a"
    echo -e "         line; WARN when unreadable; SKIP while switched off without the namespace or with no zone"
    echo ""
    echo -e "  ${CYAN}rslake${NC} the snapshot reader lake-api (research sandbox Phase 2b): NAMESPACE"
    echo -e "         SKIP without deployment/lake-api; FAIL when rs_lake_api or rs_lake_reader break"
    echo -e "         assert_grants.sql's rules; WARN when no pod runs, http://<podIP>:3000/ does not answer"
    echo -e "         200 from the host, or lake.snapshot_digest_check(<newest>) finds a digest that does not"
    echo -e "         recompute"
    echo ""
    echo -e "  ${CYAN}gwnetpol${NC} / ${CYAN}ranetpol${NC} the research-gw and research-agents zones' NetworkPolicies (Phase 4a): NAMESPACE"
    echo -e "         as rsnetpol, against cli.py compile netpol with zone_netpol_args; SKIP without the zone"
    echo ""
    echo -e "  ${CYAN}rschain${NC} the agent trace's hash chain (Phase 4a): NAMESPACE"
    echo -e "         agent_trace.verify_chain() and an independent recomputation; FAIL on a break; SKIP without the table"
    echo ""
    echo -e "  ${CYAN}rsanchor${NC} the agent trace's head anchored in the newest nightly backup (Phase 4a): NAMESPACE"
    echo -e "         FAIL when the event is missing or its hash differs on the same database identity;"
    echo -e "         WARN when the backup is of another database (predates it), too old or has no head line"
    echo ""
    echo -e "  ${CYAN}rsagent${NC} research-session and the agents' services (Phase 4a): NAMESPACE"
    echo -e "         FAIL when the live anchor research-session reports differs from the database;"
    echo -e "         WARN when a pod is not Running, /healthz does not answer or its key id is not the Secret's"
    echo ""
    echo -e "  ${CYAN}rsllm${NC} the local model research-llm (Phase 4b): NAMESPACE (SKIP while RESEARCH_LOCAL_MODEL is not true)"
    echo -e "         FAIL when the Deployment's or /props' model is not the pin in apps/research-model/pins.json;"
    echo -e "         WARN when the pod is not Ready, /health or /props do not answer, the context is not 4096 or generation since start averages below half the bench's rate at 4096 tokens of context; it generates nothing"
    echo ""
    echo -e "  ${CYAN}rsconsole${NC} the research console's page server (Phase 4e): NAMESPACE (SKIP until the policy has RESEARCH_CONSOLE_DOMAIN)"
    echo -e "         FAIL when the served page is not the ConfigMap's (after 120 s), / answers without a token, a vendor file"
    echo -e "         is not its VERSION's or the pod carries a Secret or a ServiceAccount token; WARN when it does not answer"
    echo ""
    echo -e "  ${CYAN}manual${NC} the portal serves the manual the repository builds now (/manual/): NAMESPACE"
    echo -e "         OK when ConfigMap portal-manual's medcea/manual-sha256 = its own content = a fresh"
    echo -e "         docs/manual/build.py --out --standalone (a temp file); WARN when it lags or is missing (./medcea.sh"
    echo -e "         → Infrastructure → Publish the manual to the portal), or the portal does not mount it;"
    echo -e "         FAIL when build.py refuses or the content differs from its annotation; SKIP without the portal"
    echo ""
    echo -e "  ${CYAN}juju${NC}   [unused] Juju model/app status — kept for older configs; Juju was"
    echo -e "         removed with Kubeflow, so these checks report SKIP."
    echo -e "         e.g. kubeflow            (all apps in model 'kubeflow')"
    echo -e "              kubeflow/dex-auth   (specific app within model)"
    echo ""
    exit 0
fi

# =============================================================================
# Parse args
# =============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --config|-c) CONFIG_FILE="$2"; shift 2 ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --timeout|-t) TIMEOUT="$2"; shift 2 ;;
        *) echo -e "${RED}Unknown option: $1${NC}" >&2; exit 1 ;;
    esac
done

# logs/health-check-<ts>.log (read-only, no lock; infra/lib-log.sh)
REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-log.sh"; REPO_ROOT="$SCRIPT_DIR" medcea_log health-check

# =============================================================================
# Load config.env for variable expansion in targets
# =============================================================================
if [[ -f "${SCRIPT_DIR}/config.env" ]]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/config.env" 2>/dev/null || true
fi

# backup_dir, backup_newest_ok, backup_age_status (check backupage); read-only
source "${SCRIPT_DIR}/apps/backup/lib-backup.sh"
# aa_status (check apparmor); read-only
source "${SCRIPT_DIR}/infra/lib-apparmor.sh"

# Every policy compile below reads what the deploys compiled (IAM Phase 4): an inherited
# MEDCEA_POLICY_FILE (break-glass) or a parent's "already verified" marker is dropped
# first, so a check never trusts a source it was handed; read-only, writes nothing.
source "${SCRIPT_DIR}/infra/lib-policy-source.sh"
policy_source_init "${NAMESPACE:-medcea}" --read-only
# its state document (check iampolicy) lives in a mktemp -d directory that is ours to remove
[[ -n "${POLICY_SOURCE_STATE_FILE:-}" ]] && trap 'rm -rf "$(dirname "$POLICY_SOURCE_STATE_FILE")"' EXIT

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}ERROR: Config file not found: $CONFIG_FILE${NC}" >&2
    exit 1
fi

# =============================================================================
# Helpers
# =============================================================================
_trim() {
    local s="${1#"${1%%[![:space:]]*}"}"
    echo "${s%"${s##*[![:space:]]}"}"
}

PASS=0; FAIL=0; WARN=0; SKIP=0
# Each entry: "STATUS|Name|detail message"
_RESULTS=()

_record() {
    local status="$1" name="$2" msg="$3"
    _RESULTS+=("${status}|${name}|${msg}")
    case "$status" in
        OK)   (( PASS++ )) ;;
        WARN) (( WARN++ )) ;;
        FAIL) (( FAIL++ )) ;;
        SKIP) (( SKIP++ )) ;;
    esac
}

# =============================================================================
# Check: Kubernetes workload readiness
# target: NAMESPACE/KIND/NAME
# =============================================================================
check_k8s() {
    local name="$1" target="$2"
    local ns kind res

    ns="$(  echo "$target" | cut -d/ -f1)"
    kind="$( echo "$target" | cut -d/ -f2)"
    res="$(  echo "$target" | cut -d/ -f3)"

    if [[ -z "$ns" || -z "$kind" || -z "$res" ]]; then
        _record FAIL "$name" "Invalid k8s target '${target}' — expected NAMESPACE/KIND/NAME"
        return
    fi

    # Fail fast if namespace doesn't exist
    if ! $KUBECTL get namespace "$ns" &>/dev/null 2>&1; then
        _record FAIL "$name" "Namespace '${ns}' does not exist"
        return
    fi

    # Get ready/desired replica counts before checking rollout status
    local ready total
    ready="$($KUBECTL get "${kind}/${res}" -n "$ns" \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "")"
    total="$($KUBECTL get "${kind}/${res}" -n "$ns" \
        -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "")"
    ready="${ready:-0}"; total="${total:-?}"

    # rollout status is the authoritative pass/fail signal
    local out exit_code=0
    out=$(timeout "$TIMEOUT" $KUBECTL rollout status "${kind}/${res}" \
        -n "$ns" --timeout="${TIMEOUT}s" 2>&1) || exit_code=$?

    local label="${kind}/${res} (${ns})"
    if [[ $exit_code -eq 0 ]]; then
        _record OK "$name" "${label}: ${ready}/${total} ready"
    else
        _record FAIL "$name" "${label}: ${ready}/${total} ready — ${out}"
    fi
}

# =============================================================================
# Check: a PersistentVolumeClaim is Bound — read-only
# target: NAMESPACE/NAME. WARN, not FAIL: the workload's own check says whether it
# runs; this says whether what people saved in it survives (Grafana since 1 Nov 2026).
# Also WARNs when the volume's hostPath root on this host is not 0700:
# microk8s-hostpath makes it 0777, and Grafana's init container closes it at each start.
# =============================================================================
check_pvc() {
    local name="$1" target="$2" ns claim out phase size
    ns="${target%%/*}"; claim="${target#*/}"
    if [[ -z "$ns" || -z "$claim" || "$claim" == "$target" ]]; then
        _record FAIL "$name" "Invalid pvc target '${target}' — expected NAMESPACE/NAME"
        return
    fi
    if ! out="$(timeout "$TIMEOUT" $KUBECTL get pvc "$claim" -n "$ns" \
            -o jsonpath='{.status.phase} {.status.capacity.storage}' 2>&1)"; then
        _record WARN "$name" "no PVC ${claim} in ${ns}: nothing it should hold survives a restart (./deploy-infra.sh)"
        return
    fi
    read -r phase size <<<"$out"
    if [[ "$phase" == Bound ]]; then
        local pv path mode
        pv="$(timeout "$TIMEOUT" $KUBECTL get pvc "$claim" -n "$ns" -o jsonpath='{.spec.volumeName}' 2>/dev/null)" || pv=""
        path=""
        [[ -n "$pv" ]] && { path="$(timeout "$TIMEOUT" $KUBECTL get pv "$pv" -o jsonpath='{.spec.hostPath.path}' 2>/dev/null)" || path=""; }
        mode=""
        [[ -n "$path" ]] && mode="$(stat -c %a "$path" 2>/dev/null)" || true
        if [[ -n "$mode" && "$mode" != 700 ]]; then
            _record WARN "$name" "pvc/${claim} (${ns}): Bound, but ${path} is mode ${mode}, not 700: any local account may replace its files (restart the workload: ./deploy-infra.sh)"
        else
            _record OK "$name" "pvc/${claim} (${ns}): Bound, ${size:-?}${mode:+, root mode $mode}"
        fi
    else
        _record WARN "$name" "pvc/${claim} (${ns}) is ${phase:-in no phase}, not Bound"
    fi
}

# =============================================================================
# Check: the nightly backup is recent — read-only
# target: NAMESPACE. SKIP before apps/backup is deployed (no CronJob medcea-backup);
# otherwise the age of the newest OK marker in BACKUP_DIR on this host (the job hands
# each folder to the account that deployed it): WARN over 26 h, FAIL over 72 h. With
# no complete backup yet, the CronJob's own age stands in (SKIP on its first day).
# =============================================================================
# =============================================================================
# Check: the AppArmor rules for containers (infra/lib-apparmor.sh) — read-only
# SKIP without AppArmor or MicroK8s; FAIL when the units are missing, the profile lacks
# the rules, the last run failed, a signal was denied inside a container since the
# rules were loaded, or a host profile (mosquitto) is attached inside a container.
# =============================================================================
check_apparmor() {
    local name="$1" res
    res="$(AA_KUBECTL="$KUBECTL" aa_status)"
    _record "${res%%|*}" "$name" "${res#*|}"
}

check_backupage() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" created created_epoch dir newest res
    if ! created="$(timeout "$TIMEOUT" $KUBECTL get cronjob medcea-backup -n "$ns" \
            -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)" || [[ -z "$created" ]]; then
        _record SKIP "$name" "no CronJob medcea-backup in ${ns} (./apps/backup/deploy.sh)"
        return
    fi
    dir="$(backup_dir)"
    if [[ ! -d "$dir" || ! -r "$dir" || ! -x "$dir" ]]; then
        _record FAIL "$name" "cannot read ${dir} (BACKUP_DIR): run this as the account that ran ./apps/backup/deploy.sh, which creates it"
        return
    fi
    created_epoch="$(date -u -d "$created" +%s 2>/dev/null || echo 0)"
    newest="$(backup_newest_ok "$dir")"
    res="$(backup_age_status "$(date -u +%s)" "${newest#* }" "$created_epoch" "${newest%% *}")"
    _record "${res%%|*}" "$name" "${res#*|}"
}

# rsexport_age_status NOW LAST CREATED  →  "STATUS|message" (pure; tests call it alone)
# NOW: epoch seconds; LAST: the newest lake.snapshot's created_at as epoch seconds, empty
# when there is none; CREATED: CronJob research-export's creationTimestamp as epoch seconds.
# The export runs daily at 03:00 UTC: OK up to 26 h, WARN beyond, FAIL beyond 72 h (the
# backup rule); no snapshot is SKIP while the CronJob is at most 26 h old.
RSEXPORT_WARN_H=26
RSEXPORT_FAIL_H=72
rsexport_age_status() {
    local now="$1" last="$2" created="${3:-0}" age h status limit
    local how="microk8s kubectl -n ${NAMESPACE:-medcea} get jobs -l app=research-export"
    if [[ -z "$last" ]]; then
        [[ "$created" =~ ^[0-9]+$ ]] || created=0
        age=$(( now - created )); h=$(( age / 3600 ))
        if (( age <= RSEXPORT_WARN_H * 3600 )); then
            echo "SKIP|no snapshot yet: the first export runs at 03:00 UTC (now: microk8s kubectl -n ${NAMESPACE:-medcea} create job --from=cronjob/research-export research-export-now)"
            return
        fi
        status=WARN; (( age > RSEXPORT_FAIL_H * 3600 )) && status=FAIL
        echo "$status|no snapshot since the CronJob was created ${h} h ago ($how)"
        return
    fi
    age=$(( now - last )); (( age < 0 )) && age=0
    h=$(( age / 3600 ))
    if (( age > RSEXPORT_FAIL_H * 3600 )); then
        status=FAIL; limit="$RSEXPORT_FAIL_H"
    elif (( age > RSEXPORT_WARN_H * 3600 )); then
        status=WARN; limit="$RSEXPORT_WARN_H"
    else
        echo "OK|newest snapshot ${h} h old"
        return
    fi
    echo "$status|newest snapshot is ${h} h old (over ${limit} h: $how)"
}

# =============================================================================
# Check: the research export (research sandbox Phase 2a) — read-only
# target: NAMESPACE (CronJob research-export lives there; the research database is
# research-postgresql-0 in RESEARCH_NAMESPACE, else NAMESPACE-research). One read-only psql
# as postgres (the chart's $POSTGRES_PASSWORD_FILE, as rdbms), SQL on stdin, guarded by
# to_regclass('lake.snapshot'): the newest snapshot's id and created_at,
# vault.reserved_rows_in(newest) and the number of reservations. FAIL when held-out rows
# reached the lake, and on the age past 72 h (rsexport_age_status); WARN past 26 h, with no
# reservation (nothing is held out for validation), and when anything cannot be read; SKIP
# without the CronJob and on its first day with no snapshot.
# =============================================================================
check_rsexport() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" rns created created_epoch out rc=0 line
    local sid="" sepoch="" reserved="" nres="" state="" res status _tag
    local fails=() warns=() oks=()
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    rns="${RESEARCH_NAMESPACE:-${ns}-research}"
    created="$(timeout "$TIMEOUT" $KUBECTL get cronjob research-export -n "$ns" \
        -o jsonpath='{.metadata.creationTimestamp}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -q 'NotFound' <<<"$created"; then
            _record SKIP "$name" "no CronJob research-export in ${ns} (./apps/research-export/deploy.sh)"
        else
            _record WARN "$name" "cannot read CronJob research-export in ${ns}: $(tail -n1 <<<"$created" | cut -c1-120)"
        fi
        return
    fi
    created_epoch="$(date -u -d "$created" +%s 2>/dev/null || echo 0)"
    rc=0
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$rns" research-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' medcea_research 2>&1 <<'SQL'
SELECT pg_catalog.to_regclass('lake.snapshot') IS NOT NULL AS has_lake \gset
\if :has_lake
SELECT pg_catalog.to_regclass('vault.reservation') IS NOT NULL
   AND pg_catalog.to_regprocedure('vault.reserved_rows_in(bigint)') IS NOT NULL AS has_vault \gset
\if :has_vault
SELECT 'snap|' || coalesce((SELECT s.snapshot_id::text || '|' || floor(extract(epoch FROM s.created_at))::bigint::text
                              FROM lake.snapshot s ORDER BY s.snapshot_id DESC LIMIT 1), '|');
SELECT 'reserved|' || coalesce((SELECT vault.reserved_rows_in(m.id)::text
                                  FROM (SELECT max(snapshot_id) AS id FROM lake.snapshot) m
                                 WHERE m.id IS NOT NULL), '-');
SELECT 'reservations|' || count(*) FROM vault.reservation;
\else
SELECT 'state|partial';
\endif
\else
SELECT 'state|unbuilt';
\endif
SQL
) || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read the research database in ${rns}: $(grep -m1 -E 'ERROR|error|NotFound' <<<"$out" | cut -c1-120)"
        return
    fi
    state="$(grep -m1 '^state|' <<<"$out" | cut -d'|' -f2)"
    if [[ -n "$state" ]]; then
        _record WARN "$name" "the research database in ${rns} has no lake.snapshot, vault.reservation or vault.reserved_rows_in yet (./apps/research/deploy.sh)"
        return
    fi
    line="$(grep -m1 '^snap|' <<<"$out")"
    IFS='|' read -r _tag sid sepoch <<<"$line"
    reserved="$(grep -m1 '^reserved|' <<<"$out" | cut -d'|' -f2)"
    nres="$(grep -m1 '^reservations|' <<<"$out" | cut -d'|' -f2)"
    if [[ -z "$line" || ! "$nres" =~ ^[0-9]+$ ]] \
        || { [[ -n "$sid" ]] && [[ ! "$sid" =~ ^[0-9]+$ || ! "$sepoch" =~ ^[0-9]+$ || ! "$reserved" =~ ^[0-9]+$ ]]; }; then
        _record WARN "$name" "cannot read the newest snapshot or the reservations in ${rns}"
        return
    fi
    if [[ -n "$sid" ]] && (( reserved > 0 )); then
        fails+=("${reserved} measurement rows of snapshot ${sid} fall in a reservation: held-out data reached the lake (./apps/research/reserve.sh list)")
    fi
    res="$(rsexport_age_status "$(date -u +%s)" "$sepoch" "$created_epoch")"
    status="${res%%|*}"
    case "$status" in
        FAIL) fails+=("${res#*|}") ;;
        WARN) warns+=("${res#*|}") ;;
        *)    oks+=("${res#*|}${sid:+ (snapshot ${sid}, no reserved rows in it)}") ;;
    esac
    if (( nres == 0 )); then
        warns+=("no reservation yet: nothing is held out for validation (./apps/research/reserve.sh add --by <qa user> --unit U --from T --to T --reason R)")
    else
        oks+=("${nres} reservation(s)")
    fi
    local IFS=';'
    if (( ${#fails[@]} )); then
        _record FAIL "$name" "${fails[*]}"
    elif (( ${#warns[@]} )); then
        _record WARN "$name" "${warns[*]}"
    elif [[ "$status" == SKIP ]]; then
        _record SKIP "$name" "${oks[*]}"
    else
        _record OK "$name" "${oks[*]}"
    fi
}

# =============================================================================
# Check: HTTP endpoint
# options (comma-separated): skip_tls, expect=CODE
# =============================================================================
check_http() {
    local name="$1" url="$2" options="$3"
    local curl_args=(-s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT")
    # The platform serves its own CA-signed certificates. Trust that CA here, so
    # a health check verifies the chain instead of blindly skipping TLS.
    [[ -f "$SCRIPT_DIR/.ca/ca.crt" ]] && curl_args+=(--cacert "$SCRIPT_DIR/.ca/ca.crt")
    local expect="2xx"

    IFS=',' read -ra opts <<< "$options"
    for opt in "${opts[@]}"; do
        opt="$(_trim "$opt")"
        case "$opt" in
            skip_tls)    curl_args+=(-k) ;;
            expect=*)    expect="${opt#expect=}" ;;
        esac
    done

    local http_code exit_code=0
    http_code=$(curl "${curl_args[@]}" "$url" 2>/dev/null) || exit_code=$?

    # Normalize: empty response from curl error
    [[ -z "$http_code" || "$http_code" == "000" ]] && http_code="000"

    # Match expected pattern
    local ok=false
    case "$expect" in
        2xx) [[ "$http_code" =~ ^2 ]] && ok=true ;;
        3xx) [[ "$http_code" =~ ^3 ]] && ok=true ;;
        30x) [[ "$http_code" =~ ^30 ]] && ok=true ;;
        4xx) [[ "$http_code" =~ ^4 ]] && ok=true ;;
        *)   [[ "$http_code" == "$expect" ]] && ok=true ;;
    esac

    if [[ "$http_code" == "000" ]]; then
        _record FAIL "$name" "No response (timeout/refused) — ${url}"
    elif $ok; then
        _record OK "$name" "HTTP ${http_code} — ${url}"
    else
        _record WARN "$name" "HTTP ${http_code} (expected ${expect}) — ${url}"
    fi
}

# =============================================================================
# Check: the access policy's hash-chained history
# target: DATABASE (iam_policy.verify_chain(), migration 008a). Runs as postgres
# inside the PostgreSQL pod in a read-only session (PGOPTIONS default_transaction_read_only,
# as every database check; verify_chain() is STABLE); the password is read there, never
# on a command line.
# Phase 5 (G13): the Policy UI's History tab runs verify_chain() as iam_svc, which may not
# execute the owner-only history functions, so verify_chain() must be SECURITY DEFINER and
# executable by iam_svc (tests/iam-db.sh's catalog check, here too): a WARN when either is
# false, nothing said when role iam_svc does not exist.
# =============================================================================
check_iamchain() {
    local name="$1" db="$2" out exit_code=0 definer
    # The SQL comes from the here-document, not the loop's stdin (the config file).
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -U postgres -d "$0" -tA -F "|"' "$db" 2>&1 <<'SQL'
SELECT CASE WHEN to_regprocedure('iam_policy.verify_chain()') IS NULL THEN 'absent' ELSE 'present' END;
SELECT 'definer|' || p.prosecdef::text || '|'
       || CASE WHEN NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'iam_svc') THEN 'norole'
               WHEN pg_catalog.has_function_privilege('iam_svc', p.oid, 'EXECUTE') THEN 'true' ELSE 'false' END
  FROM pg_catalog.pg_proc p WHERE p.oid = to_regprocedure('iam_policy.verify_chain()');
SELECT ok, events, first_bad_event, detail FROM iam_policy.verify_chain();
SQL
) || exit_code=$?
    definer="$(grep -m1 '^definer|' <<<"$out")"
    if grep -qx absent <<<"$out"; then   # stderr may come first: match the line
        _record SKIP "$name" "iam_policy.verify_chain() not in ${db} yet (migration 008a: ./apps/database/deploy.sh)"
        return
    fi
    out="$(grep -E '^[tf]\|' <<<"$out" || tail -1 <<<"$out")"
    local ok events bad detail
    IFS='|' read -r ok events bad detail <<<"$out"
    if [[ $exit_code -ne 0 || ( "$ok" != "t" && "$ok" != "f" ) ]]; then
        _record FAIL "$name" "verify_chain() did not run: ${out:0:120}"
    elif [[ "$ok" == "t" ]]; then
        local dwarn=()
        [[ -z "$definer" || "$definer" == "definer|true|"* ]] \
            || dwarn+=("verify_chain() is not SECURITY DEFINER: the Policy UI cannot verify the chain as iam_svc")
        [[ "$definer" == *"|false" ]] && dwarn+=("iam_svc may not execute verify_chain() (the Policy UI's History tab)")
        if ((${#dwarn[@]})); then
            local IFS=';'; _record WARN "$name" "hash chain intact, ${events} event(s), but ${dwarn[*]} (./apps/database/deploy.sh)"
        else
            _record OK "$name" "hash chain intact, ${events} event(s)"
        fi
    else
        _record FAIL "$name" "hash chain broken at event ${bad}: ${detail}"
    fi
}

# =============================================================================
# Check: the history chain's head is anchored outside the database (Phase 5, G12)
# target: DATABASE. The anchor is the chain head the newest complete nightly backup
# recorded in its MANIFEST (apps/backup/backup-job.sh chain_head, read before the dump;
# backup_newest_ok and backup_chain_head of apps/backup/lib-backup.sh, as backupage reads
# BACKUP_DIR: the account that deployed the backup owns it, mode 700, and nothing here uses
# sudo). That event must still be in iam_policy.history with the recorded hash: one psql
# as postgres in the PostgreSQL pod, read-only session, SQL on stdin, the event id (digits
# only) a psql variable. FAIL when the event is missing (or the table) or its hash differs:
# the history was cut or rewritten after the backup (or the database was restored from an
# older backup). WARN when BACKUP_DIR, a complete backup, its MANIFEST or a head in it is
# missing or unreadable, the newest backup is over 48 h old, the chain did not verify when
# the backup ran, or the database cannot be read, and (no anchor yet) when the newest
# backup completed before the chain's first event (h.at of the lowest event_id): a backup
# of an earlier database, kept in BACKUP_DIR across a new install or --purge-data. It does
# not prove what a superuser with host access did to both the database and BACKUP_DIR (one
# who rebuilds the whole history with a newer first event gets this WARN, not a FAIL).
# =============================================================================
check_iamanchor() {
    local name="$1" db="$2" max_h="${ANCHOR_MAX_H:-48}" dir newest bname ok_epoch rec kind id hash vc age h out exit_code=0 line got since genesis
    dir="$(backup_dir)"
    if [[ ! -d "$dir" ]]; then
        _record WARN "$name" "no anchor: ${dir} (BACKUP_DIR) does not exist (./apps/backup/deploy.sh)"; return
    fi
    if [[ ! -r "$dir" || ! -x "$dir" ]]; then
        _record WARN "$name" "no anchor: cannot read ${dir} (BACKUP_DIR, mode 700): run this as the account that ran ./apps/backup/deploy.sh"; return
    fi
    newest="$(backup_newest_ok "$dir")"
    if [[ -z "$newest" ]]; then
        _record WARN "$name" "no anchor: no complete backup in ${dir} yet (./apps/backup/backups.sh now)"; return
    fi
    bname="${newest%% *}"; ok_epoch="${newest#* }"
    if ! rec="$(backup_chain_head "$dir/$bname")"; then
        _record WARN "$name" "no anchor: cannot read the MANIFEST of backup ${bname}"; return
    fi
    case "$rec" in
        none) _record WARN "$name" "no anchor: backup ${bname} records no chain head (a backup from before IAM 4.5)"; return ;;
        unavailable*) _record WARN "$name" "no anchor: backup ${bname} could not read the chain head ${rec#unavailable }"; return ;;
    esac
    read -r kind id hash vc <<<"$rec"
    age=$(( $(date -u +%s) - ok_epoch )); (( age < 0 )) && age=0; h=$(( age / 3600 ))
    # The SQL comes from the here-document; the id goes in as psql variable anchor_id.
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|" -v "anchor_id=$1"' \
        "$db" "$id" 2>&1 <<'SQL'
SELECT pg_catalog.to_regclass('iam_policy.history') IS NOT NULL AS has_history \gset
\if :has_history
SELECT 'anchor', coalesce((SELECT h.hash FROM iam_policy.history h WHERE h.event_id = :anchor_id), '-'),
       (SELECT count(*) FROM iam_policy.history h WHERE h.event_id > :anchor_id),
       coalesce((SELECT floor(extract(epoch FROM h.at))::bigint::text FROM iam_policy.history h
                 ORDER BY h.event_id LIMIT 1), '-');
\else
SELECT 'nohistory';
\endif
SQL
) || exit_code=$?
    line="$(grep -m1 -E '^(anchor\||nohistory$)' <<<"$out")"
    if [[ $exit_code -ne 0 || -z "$line" ]]; then
        _record WARN "$name" "cannot read iam_policy.history to compare with backup ${bname}: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"
        return
    fi
    if [[ "$line" == nohistory ]]; then
        _record FAIL "$name" "backup ${bname} anchors event ${id}, but ${db} has no iam_policy.history (dropped, or restored from before IAM 4.5)"
        return
    fi
    IFS='|' read -r _ got since genesis <<<"$line"
    # A backup completed before this chain's first event was written belongs to an earlier
    # database (a new install, or --purge-data and a redeploy: BACKUP_DIR is kept on
    # purpose). Its head says nothing about this chain: WARN until the next nightly backup.
    # A restore from an older backup keeps the old first event, so it still FAILs below.
    if [[ "$got" != "$hash" && "$genesis" =~ ^[0-9]+$ ]] && (( genesis > ok_epoch )); then
        _record WARN "$name" "no anchor: the newest complete backup ${bname} predates this database (its first history event is newer; a new install or a purged database): no anchor until the next nightly backup"
        return
    fi
    if [[ "$got" == "-" ]]; then
        _record FAIL "$name" "event ${id}, the chain head backup ${bname} recorded, is missing from iam_policy.history: the history was cut after that backup (or restored from an older one)"
    elif [[ "$got" != "$hash" ]]; then
        _record FAIL "$name" "event ${id}'s hash is ${got:0:12}..., backup ${bname} recorded ${hash:0:12}...: the history was rewritten after that backup"
    else
        local warns=()
        (( age > max_h * 3600 )) && warns+=("the newest complete backup ${bname} is ${h} h old (over ${max_h} h: ./apps/backup/backups.sh list)")
        [[ "$vc" == f ]] && warns+=("the chain did not verify when backup ${bname} ran (verify_chain=f in its MANIFEST)")
        if ((${#warns[@]})); then
            local IFS=';'; _record WARN "$name" "event ${id} has the hash backup ${bname} recorded, but ${warns[*]}"
        else
            _record OK "$name" "event ${id} has the hash backup ${bname} recorded (${h} h old), ${since} event(s) since"
        fi
    fi
}

# =============================================================================
# Check: IAM_DB_ROLES (Phase 2) — the mode the database records, against config.env
# =============================================================================
check_iamdbroles() {
    local name="$1" db="$2" out
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -U postgres -d "$0" -tA' "$db" 2>&1 <<'SQL'
SELECT 'mode=' || coalesce((SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'), 'unset');
SQL
) || true
    local mode
    mode="$(grep -o 'mode=[a-z]*' <<<"$out" | head -1 | cut -d= -f2)"
    if [[ -z "$mode" ]]; then
        _record FAIL "$name" "could not read medcea.platform_setting: ${out:0:120}"
    elif [[ "$mode" == "unset" ]]; then
        _record SKIP "$name" "IAM_DB_ROLES not recorded yet (migration 008b: ./apps/database/deploy.sh)"
    elif [[ "$mode" != "${IAM_DB_ROLES:-false}" ]]; then
        _record FAIL "$name" "the database records IAM_DB_ROLES=$mode, config.env says ${IAM_DB_ROLES:-false} (./apps/database/deploy.sh)"
    elif [[ "$mode" == "false" ]]; then
        _record WARN "$name" "IAM_DB_ROLES=false: per-role database grants are compiled but not in force (IAM Phase 2)"
    else
        _record OK "$name" "IAM_DB_ROLES=true: per-role grants, RLS and guard triggers in force"
    fi
}

# =============================================================================
# Check: IAM_DB_SERVICE_ROLES (Phase 2.5) — which role each database client logs in as
# =============================================================================
check_dbclients() {
    local name="$1" cu c u want on_role=() off=() unreadable=()
    REPO_ROOT="$SCRIPT_DIR"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-db-roles.sh"
    local live=()
    mapfile -t live < <(db_clients_live "$NAMESPACE" 2>/dev/null)
    if [[ ${#live[@]} -eq 0 ]]; then
        _record SKIP "$name" "no database client is deployed"; return
    fi
    for cu in "${live[@]}"; do
        read -r c u <<<"$cu"
        want="$(db_client_role "$c")"
        if [[ "$u" == "?" ]]; then unreadable+=("$c")
        elif [[ "$u" == "-" ]]; then :   # no connection (Node-RED without flows: noderedflows reports it)
        elif [[ "$u" == "$want" ]]; then on_role+=("$c")
        else off+=("$c")
        fi
    done
    if [[ ${#unreadable[@]} -gt 0 ]]; then
        _record WARN "$name" "cannot read the database user of: ${unreadable[*]}"
    elif [[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" && ${#off[@]} -gt 0 ]]; then
        _record WARN "$name" "IAM_DB_SERVICE_ROLES=true, still on postgres: ${off[*]} (deploy them again; Grafana and pgAdmin: ./deploy-infra.sh)"
    elif [[ "${IAM_DB_SERVICE_ROLES:-false}" != "true" && ${#on_role[@]} -gt 0 ]]; then
        _record WARN "$name" "IAM_DB_SERVICE_ROLES=false, still on their own role: ${on_role[*]} (deploy them again, then ./apps/database/deploy.sh)"
    elif [[ "${IAM_DB_SERVICE_ROLES:-false}" == "true" ]]; then
        _record OK "$name" "all ${#on_role[@]} on their own role (IAM Phase 2.5)"
    else
        _record OK "$name" "all ${#off[@]} on postgres (IAM_DB_SERVICE_ROLES=false)"
    fi
}

# =============================================================================
# Check: the database's grants equal the compiled access policy (read-only)
# =============================================================================
check_iamgrants() {
    local name="$1" db="$2" sql out exit_code=0 flag rc=0
    # --without-iam exactly when the database deploy would compile it so (IAM 2.7):
    # the one helper decides, and an unreadable answer is a FAIL, never a default.
    # (dba_iam_flag, apps/database/lib-db-apply.sh, in a child bash that timeout bounds)
    out="$(timeout "$TIMEOUT" bash -c 'REPO_ROOT="$0"; KUBECTL="$1"; source "$0/apps/database/lib-db-apply.sh"
                                       dba_iam_flag "$2" rdbms-postgresql-0 "$3"' \
                "$SCRIPT_DIR" "$KUBECTL" "$NAMESPACE" "$db" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record FAIL "$name" "cannot tell whether schema iam is compiled (exit $rc): $(tail -1 <<<"$out" | cut -c1-160)"; return
    fi
    flag="$(grep -x -- '--without-iam' <<<"$out" || true)"
    sql="$(python3 "${SCRIPT_DIR}/apps/iam/compiler/cli.py" compile grants --mode verify $flag 2>&1)" || {
        _record FAIL "$name" "cli.py compile grants failed: ${sql:0:120}"; return; }
    # Phase 5 (G4): the assertion set that ran, and under IAM_DB_ROLES=false I15's classification
    # as a read-only query (a WARN, not drift); appended here, so the compiled verify SQL (a
    # recorded target) stays byte for byte what every applied version recorded
    local cls first mode unclassified
    cls="$(python3 "${SCRIPT_DIR}/apps/iam/apply_check.py" classify-sql $flag 2>&1)" || {
        _record FAIL "$name" "apply_check.py classify-sql failed: ${cls:0:120}"; return; }
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA' "$db" \
        2>&1 <<<"$sql"$'\n'"$cls") || exit_code=$?
    # G1: only the first ERROR line decides a SKIP, and only these two errors (migration 008b
    # missing); a DETAIL naming a medcea_auth function is drift, never a SKIP
    first="$(grep -m1 -E '(^|: )ERROR: ' <<<"$out")"
    mode="$(sed -n 's/^mode|//p' <<<"$out" | head -1)"
    unclassified="$(sed -n 's/^unclassified|//p' <<<"$out" | head -1)"
    if [[ $exit_code -ne 0 ]] && grep -qE 'ERROR: +(relation "medcea\.platform_setting" does not exist|function medcea_auth\.[a-z_0-9]+\(.*\) does not exist)' <<<"$first"; then
        _record SKIP "$name" "migration 008b not applied yet (./apps/database/deploy.sh)"
    elif [[ $exit_code -eq 0 ]] && grep -q 'grants verified' <<<"$out"; then
        local set_ran="IAM_DB_ROLES=true: every grantee, RLS, triggers and classification"
        [[ "$mode" == f ]] && set_ran="IAM_DB_ROLES=false: managed-role and legacy set only"
        if [[ "$mode" == f && -n "$unclassified" ]]; then
            _record WARN "$name" "grants equal the compiled policy ($set_ran), but ${unclassified%%|*} medcea object(s) belong to no group: $(cut -c1-120 <<<"${unclassified#*|}") (I15; a FAIL once IAM_DB_ROLES=true)"
        else
            _record OK "$name" "database grants equal the compiled policy ($set_ran)${flag:+ ($flag: no access component)}"
        fi
    else
        _record FAIL "$name" "grant drift: $(grep -m1 -E 'ERROR|DETAIL' <<<"$out" | cut -c1-200)"
    fi
}

# =============================================================================
# Check: the database catalog's tamper-relevant properties (Phase 5, G14)
# target: DATABASE. tests/iam-db.sh's catalog section checks these on the throwaway
# fixture; here the same statements run on the platform database, one psql as postgres in
# the PostgreSQL pod, read-only session, SQL on stdin. The decision statements (owner,
# iamalways, invoker, always, unitalways, commalways) are tests/iam-db.sh's text word for
# word (tests/test_health_phase5b.py CatalogParity); only the *names lines, which list the
# first five offenders for the message, are this check's own. FAIL on any hit: an object in
# medcea, medcea_auth, iam_policy or iam not owned by medcea_owner; a freeze or append-only
# trigger of schema iam, an append-only/no-truncate trigger of medcea or iam_policy, or
# user_unit_audit_trg / commissioning_history_trg not ENABLE ALWAYS (tgenabled 'A': an
# ENABLE REPLICA session would skip it); a medcea view without security_invoker. Object names
# are not secrets. WARN when the database cannot be read; SKIP before the database deploy
# (no role medcea_owner or schema medcea). The fixture's trigger counts (7, 8, 14) are not
# checked here: they pin the fixture's build, not a property of the live catalog.
# =============================================================================
check_iamcatalog() {
    local name="$1" db="$2" out exit_code=0
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' "$db" 2>&1 <<'SQL'
SELECT pg_catalog.to_regrole('medcea_owner') IS NOT NULL AND pg_catalog.to_regnamespace('medcea') IS NOT NULL AS has_owner,
       pg_catalog.to_regnamespace('iam_policy') IS NOT NULL AS has_policy \gset
\if :has_owner
SELECT 'owner', count(*) FROM (
    SELECT c.relowner AS o FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam') AND c.relkind IN ('r', 'v', 'm', 'p', 'S', 'f')
    UNION ALL SELECT p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')
    UNION ALL SELECT nspowner FROM pg_namespace WHERE nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')) x
 WHERE o <> 'medcea_owner'::regrole;
SELECT 'ownernames', coalesce(string_agg(x.n, ' ' ORDER BY x.n), '') FROM (SELECT y.n FROM (
    SELECT c.relowner AS o, n.nspname || '.' || c.relname AS n FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam') AND c.relkind IN ('r', 'v', 'm', 'p', 'S', 'f')
    UNION ALL SELECT p.proowner, replace(p.oid::regprocedure::text, ' ', '') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')
    UNION ALL SELECT nspowner, 'schema:' || nspname FROM pg_namespace WHERE nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')) y
 WHERE y.o <> 'medcea_owner'::regrole ORDER BY y.n LIMIT 5) x;
SELECT 'iamalways', count(*) FILTER (WHERE t.tgenabled <> 'A'), count(*),
       coalesce(string_agg(c.relname || '.' || t.tgname, ',') FILTER (WHERE t.tgenabled <> 'A'), '')
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = to_regnamespace('iam') AND NOT t.tgisinternal AND (t.tgtype & 2) <> 0
   AND c.relname IN ('account_decision', 'access_review', 'user_status_history', 'access_request_history', 'config_history');
SELECT 'invoker', count(*) FROM pg_class c WHERE c.relnamespace = 'medcea'::regnamespace AND c.relkind = 'v'
   AND NOT coalesce('security_invoker=true' = ANY (c.reloptions), false);
SELECT 'invokernames', coalesce(string_agg(x.relname, ',' ORDER BY x.relname), '') FROM (SELECT c.relname FROM pg_class c
 WHERE c.relnamespace = 'medcea'::regnamespace AND c.relkind = 'v'
   AND NOT coalesce('security_invoker=true' = ANY (c.reloptions), false) ORDER BY c.relname LIMIT 5) x;
\if :has_policy
SELECT 'always', string_agg(c.relname || '.' || t.tgname, ',') FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE (t.tgname LIKE '%\_append\_only' OR t.tgname LIKE '%\_no\_truncate' OR t.tgname = 'schedule_retired_guard_trg')
   AND t.tgenabled <> 'A'
   AND c.relnamespace IN ('medcea'::regnamespace, 'iam_policy'::regnamespace);
\endif
SELECT 'unitalways', tgenabled FROM pg_trigger WHERE tgname = 'user_unit_audit_trg';
SELECT 'commalways', tgenabled FROM pg_trigger WHERE tgname = 'commissioning_history_trg';
\else
SELECT 'nodb';
\endif
SQL
) || exit_code=$?
    if grep -qx nodb <<<"$out"; then
        _record SKIP "$name" "no role medcea_owner or schema medcea in ${db} yet (./apps/database/deploy.sh)"; return
    fi
    _cat_get() { grep -m1 "^$1|" <<<"$out" | cut -d'|' -f2-; }
    local owner invoker iam n_off n_all off_list always t hits=()
    owner="$(_cat_get owner)"; invoker="$(_cat_get invoker)"; iam="$(_cat_get iamalways)"
    if [[ $exit_code -ne 0 || ! "$owner" =~ ^[0-9]+$ || ! "$invoker" =~ ^[0-9]+$ || ! "$iam" =~ ^[0-9]+\|[0-9]+\| ]]; then
        _record WARN "$name" "cannot read the catalog of ${db}: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"; return
    fi
    _cat_first5() { local IFS=,; local a; read -ra a <<<"$1"; local s="${a[*]:0:5}"; (( ${#a[@]} > 5 )) && s+=",..."; echo "$s"; }
    (( owner > 0 )) && hits+=("${owner} object(s) not owned by medcea_owner: $(_cat_get ownernames)$( (( owner > 5 )) && echo ' ...')")
    IFS='|' read -r n_off n_all off_list <<<"$iam"
    (( n_off > 0 )) && hits+=("${n_off} iam freeze/append-only trigger(s) not ENABLE ALWAYS: $(_cat_first5 "$off_list")")
    always="$(_cat_get always)"
    [[ -n "$always" ]] && hits+=("append-only/no-truncate trigger(s) not ENABLE ALWAYS: $(_cat_first5 "$always")")
    for t in unitalways:user_unit_audit_trg commalways:commissioning_history_trg; do
        local v; v="$(_cat_get "${t%%:*}")"
        [[ -n "$v" && "$v" != A ]] && hits+=("${t#*:} is tgenabled '${v}', not ENABLE ALWAYS")
    done
    (( invoker > 0 )) && hits+=("${invoker} medcea view(s) without security_invoker: $(_cat_get invokernames)$( (( invoker > 5 )) && echo ',...')")
    if ((${#hits[@]})); then
        local IFS=';'; _record FAIL "$name" "${hits[*]} (./apps/database/deploy.sh; then find who changed it)"
    else
        _record OK "$name" "every object owned by medcea_owner, ${n_all} iam and all append-only triggers ENABLE ALWAYS, every medcea view security_invoker"
    fi
}

# =============================================================================
# Check: the applied access policy version (IAM 4.2a, design §14.4.14) — read-only
# target: DATABASE (informational: the state document is the one policy_source_init
# --read-only read at the top for $POSTGRES_DB, POLICY_SOURCE_STATE_FILE, bounded by
# TIMEOUT). apps/iam/apply_check.py health judges it: the host file (line 1, line 2 and the
# whole body against the database's rows), the skeleton gate against git, every unreviewed
# accept recomputed, the apply events, break-glass, audit_versions(), the chain, waivers,
# the seed queue. "An apply is running" = a holder of .medcea.lock (_lock_holders) whose
# command line is apps/iam/apply.sh: health never runs flock. The worst line wins; the
# detail lists every WARN and FAIL, 160 characters each. --policy-port: what iam-api's
# /healthz on :8083 answers (IAM 4.3; read in the pod, no secret in it): absent without the
# port (a bootstrap version is then OK while unconfirmed), true once the Policy UI runs —
# then an unconfirmed bootstrap WARNs, another applied version FAILs, another skeleton WARNs.
# =============================================================================
check_iampolicy() {
    local name="$1" out rc=0 lvl msg worst="" ok="" skip="" details=() holders tmo
    if [[ -z "${POLICY_SOURCE_STATE_FILE:-}" || ! -s "${POLICY_SOURCE_STATE_FILE:-}" ]]; then
        if [[ "${POLICY_SOURCE_VERDICT:-skip}" == fail ]]; then
            _record FAIL "$name" "cannot read the applied policy: ${POLICY_SOURCE_DETAIL:0:160}"
        else
            _record SKIP "$name" "${POLICY_SOURCE_DETAIL:-no usable kubectl}"
        fi
        return
    fi
    # The lock's holders only when they matter: scanning every /proc/<pid>/fd takes seconds
    # on a busy host, and only an unfinished apply_started asks whether an apply is running.
    holders=""
    if grep -q '"apply_started"' "$POLICY_SOURCE_STATE_FILE" 2>/dev/null; then
        holders="$(_lock_holders 2>/dev/null | paste -sd ' ')"
    fi
    tmo=$(( TIMEOUT > 30 ? TIMEOUT : 30 ))
    local live="" port=absent
    live="$(timeout "$TIMEOUT" $KUBECTL exec -n "${NAMESPACE:-medcea}" deployment/iam-api -c iam-api -- python3 -c \
        'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8083/healthz", timeout=5).read().decode())' 2>/dev/null)" || live=""
    if python3 -c 'import json, sys; sys.exit(0 if json.loads(sys.argv[1]).get("policy_port") is True else 1)' "$live" 2>/dev/null; then
        port=true
    else
        live=""
    fi
    out="$(timeout "$tmo" python3 "$SCRIPT_DIR/apps/iam/apply_check.py" health --state "$POLICY_SOURCE_STATE_FILE" \
        --host-file "$SCRIPT_DIR/state/policy-applied.yaml" --holders "$holders" --policy-port "$port" --live "$live" 2>&1)" || rc=$?
    while IFS='|' read -r lvl msg; do
        case "$lvl" in
            FAIL) worst=FAIL; details+=("${msg:0:160}") ;;
            WARN) [[ "$worst" == FAIL ]] || worst=WARN; details+=("${msg:0:160}") ;;
            OK)   ok="${msg:0:160}" ;;
            SKIP) skip="${msg:0:160}" ;;
        esac
    done <<<"$out"
    if [[ $rc -ne 0 || -z "$worst$ok$skip" ]]; then
        _record FAIL "$name" "apply_check.py health failed (exit $rc): $(tail -n1 <<<"$out" | cut -c1-160)"
    elif [[ -n "$worst" ]]; then
        local IFS=';'; _record "$worst" "$name" "${details[*]}"
    elif [[ -n "$ok" ]]; then
        _record OK "$name" "$ok"
    elif [[ "${POLICY_SOURCE_VERDICT:-}" == fail ]]; then
        # state none, yet the read-only init failed it: a host file without any policy version
        _record FAIL "$name" "${POLICY_SOURCE_DETAIL:0:160}"
    else
        _record SKIP "$name" "$skip"
    fi
}

# =============================================================================
# Check: the live policy artefacts are the applied version's compile (IAM 4.2a) — read-only
# target: NAMESPACE. (a) ConfigMap medcea-iam-lib: annotation medcea/routes-digest and
# routes.json's digest = cli.py compile routes; (b) medcea/mqtt-digest and mqtt.json's digest
# = cli.py compile mqtt; (c) every HOST → release of network.proxies (the compiled policy):
# ConfigMap <release> absent → "not deployed" (counted); else its oauth2_proxy.cfg
# allowed_groups (no secret in it) = policy_groups HOST (lib-oauth2-proxy.sh, which renders
# the IAM_GATES=false lists too). The User Manager's admin-only fallback (["admin"] while
# the compile differs: not every access pod proved it enforces) is a WARN. The tool hosts
# (Grafana, workbench, Node-RED, wizard, pgAdmin) keep their own checks.
# =============================================================================
check_iamartefacts() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" cm rc=0 cli="$SCRIPT_DIR/apps/iam/compiler/cli.py"
    local want_r want_m probs=() warns=() gates=0 absent=0 host rel live want owner line
    local -A LIVE=() OWNER=()
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    cm="$(timeout "$TIMEOUT" $KUBECTL get configmap medcea-iam-lib -n "$ns" -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -qiE 'NotFound|not found' <<<"$cm"; then
            _record SKIP "$name" "no ConfigMap medcea-iam-lib in $ns yet (./deploy-infra.sh)"
        else
            _record FAIL "$name" "cannot read ConfigMap medcea-iam-lib: $(tail -n1 <<<"$cm" | cut -c1-160)"
        fi
        return
    fi
    _digest() { python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])' 2>/dev/null; }
    want_r="$(python3 "$cli" compile routes 2>/dev/null | _digest)"
    want_m="$(python3 "$cli" compile mqtt 2>/dev/null | _digest)"
    if [[ -z "$want_r" || -z "$want_m" ]]; then
        unset -f _digest
        _record FAIL "$name" "the applied policy does not compile (python3 apps/iam/compiler/cli.py check)"; return
    fi
    unset -f _digest
    # (a), (b): one line per mismatch, never a value but the digests
    while IFS= read -r line; do
        [[ -n "$line" ]] && probs+=("$line")
    done < <(python3 -c '
import json, sys
cm, wr, wm = json.load(sys.stdin), sys.argv[1], sys.argv[2]
ann, data = cm["metadata"].get("annotations") or {}, cm.get("data") or {}
def dig(key):
    try:
        return json.loads(data.get(key) or "")["digest"]
    except Exception:
        return ""
for what, a, k, want in (("routes", "medcea/routes-digest", "routes.json", wr), ("mqtt", "medcea/mqtt-digest", "mqtt.json", wm)):
    have_a, have_d = ann.get(a, ""), dig(k)
    if have_a != want or have_d != want:
        print("%s: annotation %s, %s %s, the applied version compiles %s (./deploy-infra.sh)"
              % (what, have_a[:12] or "-", k, have_d[:12] or "-", want[:12]))
' "$want_r" "$want_m" <<<"$cm" 2>&1)
    # (c) the gates: HOST release, from the compiled policy
    local proxies
    proxies="$(python3 -c 'import sys
sys.path.insert(0, sys.argv[1])
from compiler import model
for h, r in (model.load().data.get("network", {}).get("proxies") or {}).items():
    print(h, r)' "$SCRIPT_DIR/apps/iam" 2>/dev/null)" || { _record FAIL "$name" "cannot read network.proxies from the applied policy"; return; }
    while IFS=$'\t' read -r host owner; do OWNER[$host]="${owner%% --*}"; done \
        < <(python3 "$SCRIPT_DIR/apps/iam/apply_check.py" owners 2>/dev/null)
    rc=0
    # shellcheck disable=SC2046  # one release name per word
    cm="$(timeout "$TIMEOUT" $KUBECTL get configmap $(awk '{print $2}' <<<"$proxies") -n "$ns" --ignore-not-found -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record FAIL "$name" "cannot read the sign-in proxies' ConfigMaps: $(tail -n1 <<<"$cm" | cut -c1-160)"; return
    fi
    REPO_ROOT="$SCRIPT_DIR"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh"
    # pa_live_groups: the one reader of a proxy's live gate, shared with the scoped modes (IAM 4.2b)
    while IFS=$'\t' read -r rel live; do [[ -n "$rel" ]] && LIVE[$rel]="$live"; done < <(pa_live_groups <<<"$cm" 2>/dev/null)
    while read -r host rel; do
        [[ -n "$host" ]] || continue
        if [[ -z "${LIVE[$rel]+x}" ]]; then absent=$((absent + 1)); continue; fi
        gates=$((gates + 1))
        if [[ ( "$host" == ACCESS_DOMAIN || "$host" == POLICY_DOMAIN ) && "${IAM_GATES:-true}" == false ]]; then
            want="admin"
        else
            want="$(policy_groups "$host" 2>/dev/null | grep -o '"[^"]*"' | tr -d '"' | sort -u | paste -sd ' ')"
        fi
        live="${LIVE[$rel]}"
        if [[ -z "$want" ]]; then
            probs+=("gate $host: policy_groups compiles nothing (python3 apps/iam/compiler/cli.py check)")
        elif [[ "$live" == "$want" ]]; then
            :
        elif [[ "$host" == ACCESS_DOMAIN && "$live" == admin ]]; then
            warns+=("the User Manager's gate is admin-only: not every access pod proved it enforces (./apps/access/deploy.sh)")
        elif [[ "$host" == POLICY_DOMAIN && "$live" == admin ]]; then
            warns+=("the Policy UI's gate is admin-only: not every iam-api pod proved it enforces (./apps/iam/deploy.sh)")
        elif [[ "$live" == "-" ]]; then
            probs+=("gate $host ($rel) has no allowed_groups: anyone signed in gets in (${OWNER[$host]:-./deploy-infra.sh})")
        else
            probs+=("gate $host ($rel) admits [$live], the applied version compiles [$want] (${OWNER[$host]:-./deploy-infra.sh})")
        fi
    done <<<"$proxies"
    if ((${#probs[@]})); then
        local IFS=';'; _record FAIL "$name" "${probs[*]}${warns:+;${warns[*]}}"
    elif ((${#warns[@]})); then
        local IFS=';'; _record WARN "$name" "${warns[*]}"
    else
        _record OK "$name" "routes, mqtt and $gates gates equal the applied version's compile; $absent hosts not deployed"
    fi
}

# =============================================================================
# Check: the platform manual the portal serves is the one the repository builds (3 Nov 2026)
# — read-only. target: NAMESPACE. ConfigMap portal-manual (infra/lib-manual.sh) carries the
# page gzipped and medcea/manual-sha256; the check rebuilds the page into a mktemp file
# (docs/manual/build.py --out --standalone, as infra/lib-manual.sh builds it; the working
# tree is not touched) and compares three digests:
# the annotation, the ConfigMap's own content (gunzipped) and the fresh build. A lag is a
# WARN with the fix; a ConfigMap whose content is not what its annotation says, or a manual
# that no longer builds, is a FAIL. The portal Deployment must mount the ConfigMap (WARN).
# =============================================================================
check_manual() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" rc=0 tmp out
    local fix="./medcea.sh → Infrastructure → Publish the manual to the portal"
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    # Files, not variables: the ConfigMap is ~210 KiB of JSON, over the 128 KiB a single
    # command-line argument may hold.
    tmp="$(mktemp -d)"
    timeout "$TIMEOUT" $KUBECTL get deployment portal -n "$ns" -o json >"$tmp/dep.json" 2>"$tmp/err" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -qiE 'NotFound|not found' "$tmp/err"; then
            _record SKIP "$name" "no portal deployment in $ns yet (./deploy-infra.sh)"
        else
            _record FAIL "$name" "cannot read deployment portal: $(tail -n1 "$tmp/err" | cut -c1-160)"
        fi
        rm -rf "$tmp"; return
    fi
    timeout "$TIMEOUT" $KUBECTL get configmap portal-manual -n "$ns" -o json >"$tmp/cm.json" 2>"$tmp/err" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -qiE 'NotFound|not found' "$tmp/err"; then
            _record WARN "$name" "the manual is not published: /manual/ answers 404 ($fix)"
        else
            _record FAIL "$name" "cannot read ConfigMap portal-manual: $(tail -n1 "$tmp/err" | cut -c1-160)"
        fi
        rm -rf "$tmp"; return
    fi
    if ! out="$(timeout $(( TIMEOUT > 30 ? TIMEOUT : 30 )) python3 "$SCRIPT_DIR/docs/manual/build.py" --out "$tmp/index.html" --standalone 2>&1)"; then
        rm -rf "$tmp"
        _record FAIL "$name" "docs/manual/build.py refuses to build the manual: $(grep -m1 'build:' <<<"$out" | cut -c1-160)"
        return
    fi
    out="$(python3 -c '
import base64, gzip, hashlib, json, sys
d = sys.argv[1]
cm, dep = json.load(open(d + "/cm.json")), json.load(open(d + "/dep.json"))
want = hashlib.sha256(open(d + "/index.html", "rb").read()).hexdigest()
meta = cm.get("metadata") or {}
ann = (meta.get("annotations") or {})
have_a, commit = ann.get("medcea/manual-sha256", ""), ann.get("medcea/manual-commit", "?")
try:
    have_c = hashlib.sha256(gzip.decompress(base64.b64decode((cm.get("binaryData") or {})["index.html.gz"]))).hexdigest()
except Exception:
    have_c = ""
mounted = any((v.get("configMap") or {}).get("name") == "portal-manual"
              for v in ((dep.get("spec") or {}).get("template") or {}).get("spec", {}).get("volumes") or [])
if not have_c or have_c != have_a:
    print("FAIL|ConfigMap portal-manual holds %s, its annotation says %s: republish it" % (have_c[:12] or "no readable page", have_a[:12] or "-"))
elif have_a != want:
    print("WARN|the portal serves the manual of %s (%s), the repository builds %s" % (commit, have_a[:12], want[:12]))
elif not mounted:
    print("WARN|the manual is published (%s) but the portal does not mount it yet: ./deploy-infra.sh" % want[:12])
else:
    print("OK|the portal serves the manual the repository builds (%s, commit %s)" % (want[:12], commit))
' "$tmp" 2>&1)" || out="FAIL|cannot compare the manual's digests: $(tail -n1 <<<"$out" | cut -c1-120)"
    rm -rf "$tmp"
    case "${out%%|*}" in
        OK)   _record OK "$name" "${out#*|}" ;;
        WARN) if [[ "$out" == *"repository builds"* ]]; then _record WARN "$name" "${out#*|} ($fix)"
              else _record WARN "$name" "${out#*|}"; fi ;;
        *)    _record FAIL "$name" "${out#*|}" ;;
    esac
}

# =============================================================================
# Check: account decisions waiting for qa (IAM 2.7) — read-only, no Keycloak
# target: DATABASE. Drift between Keycloak and the decisions is not computed here
# (that would mint admin tokens): access-api computes it and check_iamdrift reads it.
# =============================================================================
check_iamdecisions() {
    local name="$1" db="$2" out exit_code=0
    # each step only after the guards before it, so no query names a missing object
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' "$db" 2>&1 <<'SQL'
SELECT pg_catalog.to_regnamespace('iam') IS NOT NULL AND EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'access_svc') AS present,
       pg_catalog.to_regprocedure('iam.confirm_decision(integer,text)') IS NOT NULL AS built \gset
\if :present
\if :built
SELECT 'exec|' || CASE WHEN pg_catalog.has_function_privilege('access_svc', 'iam.confirm_decision(integer,text)', 'EXECUTE')
                       THEN 't' ELSE 'f' END;   -- text || boolean is 'true', not 't'
SELECT 'stale|' || count(*) || '|' || coalesce(min(decision_id)::text, '-')
  FROM iam.account_decision WHERE status = 'pending_qa' AND made_at < now() - interval '7 days';
SELECT 'mail|' || count(*) || '|' || coalesce(min(decision_id)::text, '-')
  FROM iam.account_decision WHERE status = 'pending_qa' AND kind = 'mail_settings';
SELECT 'pending|' || count(*) FROM iam.account_decision WHERE status = 'pending_qa';
\else
SELECT 'state|unbuilt';
\endif
\else
SELECT 'state|absent';
\endif
SQL
) || exit_code=$?
    local state can_exec stale stale_id mail mail_id pending
    state="$(grep -m1 '^state|' <<<"$out" | cut -d'|' -f2)"
    can_exec="$(grep -m1 '^exec|' <<<"$out" | cut -d'|' -f2)"
    IFS='|' read -r _ stale stale_id <<<"$(grep -m1 '^stale|' <<<"$out")"
    IFS='|' read -r _ mail mail_id <<<"$(grep -m1 '^mail|' <<<"$out")"
    pending="$(grep -m1 '^pending|' <<<"$out" | cut -d'|' -f2)"
    if [[ "$state" == absent ]]; then
        _record SKIP "$name" "schema iam or role access_svc absent (./apps/access/deploy.sh installs them)"
    elif [[ "$state" == unbuilt ]]; then
        _record FAIL "$name" "schema iam has no iam.confirm_decision: run ./apps/access/deploy.sh (IAM 2.7)"
    elif [[ $exit_code -ne 0 || -z "$can_exec" || -z "$pending" ]]; then
        _record FAIL "$name" "could not read the account decisions: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"
    elif [[ "$can_exec" != t ]]; then
        _record FAIL "$name" "access_svc may not execute iam.confirm_decision: run ./apps/database/deploy.sh"
    elif [[ "$stale" -gt 0 ]]; then
        _record WARN "$name" "${stale} decision(s) waiting for qa for over 7 days (oldest #${stale_id}): User Manager → Decisions"
    elif [[ "$mail" -gt 0 ]]; then
        _record WARN "$name" "a mail settings change waits for qa (decision #${mail_id}): the realm still sends with the old account"
    else
        _record OK "$name" "${pending} decision(s) waiting for qa, none older than 7 days"
    fi
}

# =============================================================================
# Check: configuration changes waiting for qa (Approvals tab) — read-only
# target: DATABASE. An open medcea.pending_change is one medcea._pending_open()
# says no approval, return or withdrawal closed (the queue's own rule): a waiting
# commissioning "on" or log setting, or the review of an "off" that applied at once.
# =============================================================================
check_iampending() {
    local name="$1" db="$2" out exit_code=0
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' "$db" 2>&1 <<'SQL'
-- the argument type first: to_regprocedure() may raise on a type that does not exist
SELECT pg_catalog.to_regclass('medcea.pending_change') IS NOT NULL AS has_table \gset
\if :has_table
SELECT pg_catalog.to_regprocedure('medcea._pending_open(medcea.pending_change)') IS NOT NULL AS built \gset
\else
SELECT false AS built \gset
\endif
\if :built
SELECT 'stale|' || count(*) || '|' || coalesce(min(x.change_id)::text, '-') || '|'
       || count(*) FILTER (WHERE x.target = 'medcea.cea_unit')
  FROM medcea.pending_change x
 WHERE medcea._pending_open(x) AND coalesce(x.applied_at, x.proposed_at) < now() - interval '7 days';
SELECT 'pending|' || count(*) FROM medcea.pending_change x WHERE medcea._pending_open(x);
\else
SELECT 'state|unbuilt';
\endif
SQL
) || exit_code=$?
    local state stale stale_id stale_comm pending
    state="$(grep -m1 '^state|' <<<"$out" | cut -d'|' -f2)"
    IFS='|' read -r _ stale stale_id stale_comm <<<"$(grep -m1 '^stale|' <<<"$out")"
    pending="$(grep -m1 '^pending|' <<<"$out" | cut -d'|' -f2)"
    if [[ "$state" == unbuilt ]]; then
        _record SKIP "$name" "no approval functions yet (./apps/database/deploy.sh)"
    elif [[ $exit_code -ne 0 || -z "$pending" || -z "$stale" ]]; then
        _record FAIL "$name" "could not read the pending changes: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"
    elif [[ "$stale" -gt 0 ]]; then
        _record WARN "$name" "${stale} change(s) waiting for qa for over 7 days (oldest #${stale_id}; ${stale_comm} commissioning): Config UI → Approvals"
    else
        _record OK "$name" "${pending} change(s) waiting for qa, none older than 7 days"
    fi
}

# =============================================================================
# Check: the feedback control loops (Q11, Q20) — read-only, WARN only
# target: DATABASE. One psql as postgres in rdbms-postgresql-0 (read-only session, SQL on
# stdin). A zone counts when it and its unit are active and it has an active ACTUATOR
# component on an active device (schd/cea/get_control_loops.py's selection). Such a zone
# without an active medcea.control_loop row runs on the default map; among those, a zone
# where one of the four loop tags (_loop_quantities) has two or more sensors (the named ones
# of _zone_inventory, plus 'default' when an old 5-segment board publishes the tag) gets
# no_data + ALARM ambiguous_source whenever two are fresh, until the reference is chosen in
# onboarding. A default-map zone whose _zone_inventory reports sensor problems (a sensor
# published as 'default', a topic's sensor that is not the component's instance, a sensor
# name two components claim, a malformed topic) WARNs too: those components still publish
# and the runner counts them on the default map, so the zone may get ambiguous_source
# without being named above. An active loop of an active zone whose
# medcea._loop_problems(...) is not empty is one the loop picker rejects; the runner refuses
# the rule errors and runs the inventory ones (sensor or actuator not on an active board of
# the zone) with no_data or an absent actuator. Never FAIL (the severity rule: nothing here lets anyone in); a check that cannot
# read WARNs; SKIP before migration 010.
# =============================================================================
check_controlloops() {
    local name="$1" db="$2" out exit_code=0
    out=$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' "$db" 2>&1 <<'SQL'
SELECT pg_catalog.to_regclass('medcea.control_loop') IS NOT NULL AS has_table \gset
\if :has_table
SELECT pg_catalog.to_regprocedure('medcea._loop_problems(jsonb,text,jsonb,jsonb)') IS NOT NULL
   AND pg_catalog.to_regprocedure('medcea._zone_inventory(integer)') IS NOT NULL
   AND pg_catalog.to_regprocedure('medcea._loop_quantities()') IS NOT NULL AS built \gset
\if :built
WITH zn AS (
    SELECT z.zone_id, z.zone_code::text AS zone_code, u.unit_code::text || '/' || z.zone_code::text AS zname,
           EXISTS (SELECT 1 FROM medcea.device d JOIN medcea.component c ON c.device_id = d.device_id
                    WHERE d.zone_id = z.zone_id AND coalesce(d.is_active, 'Y') = 'Y'
                      AND c.component_type = 'ACTUATOR' AND c.is_active = 'Y') AS has_act,
           EXISTS (SELECT 1 FROM medcea.control_loop l WHERE l.zone_id = z.zone_id AND l.is_active = 'Y') AS has_loops
      FROM medcea.cea_zone z JOIN medcea.cea_unit u ON u.unit_id = z.unit_id
     WHERE u.is_active = 'Y' AND z.is_active = 'Y'
), inv AS (
    SELECT zn.*, i.sensors, i.old_boards, i.problems, i.actuators
      FROM zn CROSS JOIN LATERAL medcea._zone_inventory(zn.zone_id) i
     WHERE zn.has_act OR zn.has_loops
), dm AS (
    SELECT * FROM inv WHERE has_act AND NOT has_loops
), amb AS (
    SELECT dm.zname, string_agg(t.tag || ': ' || t.names, ', ' ORDER BY t.tag) AS tags
      FROM dm CROSS JOIN LATERAL (
            SELECT q.tag, string_agg(s.sensor, ',' ORDER BY s.sensor) AS names
              FROM (SELECT DISTINCT v ->> 'tag' AS tag FROM jsonb_each(medcea._loop_quantities()) e(k, v)) q
              JOIN (SELECT n ->> 'instance' AS sensor, n -> 'tags' AS tags FROM jsonb_array_elements(dm.sensors) n
                    UNION ALL
                    SELECT 'default', b -> 'tags' FROM jsonb_array_elements(dm.old_boards) b) s
                ON jsonb_typeof(s.tags) = 'array' AND s.tags ? q.tag
             GROUP BY q.tag HAVING count(DISTINCT s.sensor) >= 2) t
     GROUP BY dm.zname
), sp AS (
    SELECT dm.zname, jsonb_array_length(dm.problems) AS n, dm.problems ->> 0 AS first
      FROM dm WHERE jsonb_typeof(dm.problems) = 'array' AND jsonb_array_length(dm.problems) > 0
), bad AS (
    SELECT inv.zname, l.loop_code::text AS code,
           medcea._loop_problems(jsonb_build_object('loop_code', l.loop_code::text)
                                 || CASE WHEN l.input IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('input', l.input) END
                                 || CASE WHEN l.output IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('output', l.output) END,
                                 inv.zone_code, inv.sensors, inv.actuators) AS p
      FROM inv JOIN medcea.control_loop l ON l.zone_id = inv.zone_id AND l.is_active = 'Y'
), half AS (
    SELECT inv.zname, l.loop_code::text AS code, CASE WHEN l.input IS NULL THEN 'input' ELSE 'output' END AS missing
      FROM inv JOIN medcea.control_loop l ON l.zone_id = inv.zone_id AND l.is_active = 'Y'
     WHERE l.input IS NULL OR l.output IS NULL
)
SELECT 'zones|' || (SELECT count(*) FROM zn WHERE has_act) || '|' || (SELECT count(*) FROM bad)
UNION ALL
SELECT 'half|' || (SELECT count(*) FROM half) || '|'
       || coalesce((SELECT string_agg(x.zname || ' ' || x.code || ' (no ' || x.missing || ')', '; ' ORDER BY x.zname, x.code)
                      FROM (SELECT zname, code, missing FROM half ORDER BY zname, code LIMIT 3) x), '')
UNION ALL
SELECT 'default|' || (SELECT count(*) FROM dm) || '|'
       || coalesce((SELECT string_agg(x.zname, ' ' ORDER BY x.zname) FROM (SELECT zname FROM dm ORDER BY zname LIMIT 5) x), '')
UNION ALL
SELECT 'ambiguous|' || (SELECT count(*) FROM amb) || '|'
       || coalesce((SELECT string_agg(x.zname || ' ' || x.tags, '; ' ORDER BY x.zname)
                      FROM (SELECT zname, tags FROM amb ORDER BY zname LIMIT 3) x), '')
UNION ALL
SELECT 'sensors|' || (SELECT count(*) FROM sp) || '|'
       || coalesce((SELECT string_agg(x.zname || ' ' || left(x.first, 120), '; ' ORDER BY x.zname)
                      FROM (SELECT zname, first FROM sp ORDER BY zname LIMIT 3) x), '')
UNION ALL
SELECT 'problems|' || (SELECT count(*) FROM bad WHERE cardinality(p) > 0) || '|'
       || coalesce((SELECT string_agg(x.zname || ' ' || left(x.p[1], 120), '; ' ORDER BY x.zname, x.code)
                      FROM (SELECT zname, code, p FROM bad WHERE cardinality(p) > 0 ORDER BY zname, code LIMIT 3) x), '');
\else
SELECT 'state|partial';
\endif
\else
SELECT 'state|unbuilt';
\endif
SQL
) || exit_code=$?
    local state zones loops n_def def_list n_amb amb_list n_sp sp_list n_bad bad_list n_half half_list hits=()
    state="$(grep -m1 '^state|' <<<"$out" | cut -d'|' -f2)"
    IFS='|' read -r _ zones loops <<<"$(grep -m1 '^zones|' <<<"$out")"
    IFS='|' read -r _ n_def def_list <<<"$(grep -m1 '^default|' <<<"$out")"
    IFS='|' read -r _ n_amb amb_list <<<"$(grep -m1 '^ambiguous|' <<<"$out")"
    IFS='|' read -r _ n_sp sp_list <<<"$(grep -m1 '^sensors|' <<<"$out")"
    IFS='|' read -r _ n_bad bad_list <<<"$(grep -m1 '^problems|' <<<"$out")"
    IFS='|' read -r _ n_half half_list <<<"$(grep -m1 '^half|' <<<"$out")"
    if [[ "$state" == unbuilt && $exit_code -eq 0 ]]; then
        _record SKIP "$name" "no medcea.control_loop table yet (./apps/database/deploy.sh, migration 010)"; return
    fi
    if [[ "$state" == partial && $exit_code -eq 0 ]]; then
        _record WARN "$name" "medcea.control_loop exists without _loop_problems/_zone_inventory/_loop_quantities: ./apps/database/deploy.sh"; return
    fi
    if [[ $exit_code -ne 0 || ! "$zones" =~ ^[0-9]+$ || ! "$loops" =~ ^[0-9]+$ || ! "$n_def" =~ ^[0-9]+$
          || ! "$n_amb" =~ ^[0-9]+$ || ! "$n_sp" =~ ^[0-9]+$ || ! "$n_bad" =~ ^[0-9]+$
          || ! "${n_half:-0}" =~ ^[0-9]+$ ]]; then
        _record WARN "$name" "cannot read the control loops of ${db}: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"; return
    fi
    (( n_def > 0 )) && hits+=("${n_def} zone(s) run on the default map (no control_loop rows; Q20): ${def_list}$( (( n_def > 5 )) && echo ' ...')")
    (( n_amb > 0 )) && hits+=("${n_amb} of them with several sensors on a tag (no_data + ALARM ambiguous_source: choose the reference in onboarding): ${amb_list}$( (( n_amb > 3 )) && echo '; ...')")
    (( ${n_half:-0} > 0 )) && hits+=("${n_half} loop(s) half-bound, running on the default map's other half until its onboarding chooses it: ${half_list}$( (( n_half > 3 )) && echo '; ...')")
    (( n_sp > 0 )) && hits+=("${n_sp} of them with sensor problems (their readings still count on the default map: re-onboard): ${sp_list}$( (( n_sp > 3 )) && echo '; ...')")
    (( n_bad > 0 )) && hits+=("${n_bad} active loop(s) break the loop rules (the loop picker rejects them; the runner refuses rule errors and gets no_data or no actuator for the rest; re-save in onboarding): ${bad_list}$( (( n_bad > 3 )) && echo '; ...')")
    if ((${#hits[@]})); then
        local IFS='|'; local msg="${hits[*]}"
        _record WARN "$name" "${msg//|/; }"
    elif (( zones == 0 )); then
        _record OK "$name" "no active zone has actuators"
    else
        _record OK "$name" "${zones} zone(s) with actuators, all on valid control_loop rows (${loops} active loop(s))"
    fi
}

# =============================================================================
# Check: account drift between Keycloak and the record (Phase 5, G6) — read-only
# target: NAMESPACE. access-api computes compute_drift() in a background thread (every
# DRIFT_INTERVAL_SECONDS, 600 by default) with its own service account and publishes
# counts only on its Admin port's /healthz (answered before the access check). One bounded
# `kubectl exec POD -c api -- python3 -c` per Running access pod GETs it on 127.0.0.1:8081;
# no token is minted, nothing is written, and no name, username, sub or e-mail is printed
# (the probe prints numbers and the error's kind only).
# FAIL: compensation_failed > 0 (Keycloak wider than the database says) or
# unexplained_role > 0 (a platform role no confirmed decision or signed-off review gives).
# WARN: enabled_while_pending > 0, unrecorded_account > 0 (an enabled account with no
# request, decision or status row that deploy-infra did not seed), the result older than
# 30 min, live_error set, the account list truncated at the ceiling, the seeded accounts
# unreadable, not computed yet (a fresh pod), an access-api that predates the report
# (./apps/access/deploy.sh), a pod that cannot be read. SKIP: access not deployed.
# =============================================================================
check_iamdrift() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" rc=0 pods pod got n=0 pre
    local state age accounts unexp ewp comp unrec trunc seeded interval err
    local probs=() warns=() oks=()
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    pods="$(_running_pods "$ns" access)" || rc=$?
    if [[ $rc -eq 3 ]]; then _record SKIP "$name" "access is not deployed (./apps/access/deploy.sh)"; return
    elif [[ $rc -ne 0 ]]; then _record WARN "$name" "cannot read the access pods in $ns"; return
    elif [[ -z "$pods" ]]; then _record WARN "$name" "no Running access pod: the drift report cannot be read"; return
    fi
    local probe='import json, re, time, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:8081/healthz", timeout=4) as r:
        d = json.load(r)
except Exception:
    print("unreachable"); raise SystemExit
x = d.get("drift")
if not isinstance(x, dict):
    print("predates"); raise SystemExit
c = x.get("counts") if isinstance(x.get("counts"), dict) else {}
num = lambda v: str(int(v)) if isinstance(v, (int, float)) and not isinstance(v, bool) else "-"
at = x.get("computed_at")
err = re.sub(r"[^A-Za-z0-9 ().:_-]", "", str(x.get("live_error") or ""))[:80]
print("ok" if isinstance(at, (int, float)) and c else "notyet",
      num(time.time() - at) if isinstance(at, (int, float)) else "-", num(x.get("accounts")),
      *(num(c.get(k)) for k in ("unexplained_role", "enabled_while_pending", "compensation_failed", "unrecorded_account")),
      int(x.get("truncated") is True), {True: "1", False: "0"}.get(x.get("seeded_readable"), "-"),
      num(x.get("interval_s")), err)'
    local npods; npods="$(wc -w <<<"$pods")"
    for pod in $pods; do
        n=$((n + 1))
        pre=""; (( npods > 1 )) && pre="pod $pod: "
        got="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" "$pod" -c api -- python3 -c "$probe" 2>/dev/null | tail -n1)" || got=""
        read -r state age accounts unexp ewp comp unrec trunc seeded interval err <<<"$got"
        case "$state" in
            ok) ;;
            predates) warns+=("${pre}this access-api predates the drift report: ./apps/access/deploy.sh"); continue ;;
            notyet)
                if [[ -n "$err" ]]; then warns+=("${pre}drift not computed yet; its last attempt failed: $err")
                else warns+=("${pre}drift not computed yet (the access pod started recently; every ${interval:-?} s)"); fi
                continue ;;
            unreachable) warns+=("${pre}access-api's admin /healthz does not answer in pod $pod"); continue ;;
            *) warns+=("cannot read the drift report in pod $pod"); continue ;;
        esac
        if ! [[ "$age" =~ ^[0-9]+$ && "$unexp" =~ ^[0-9]+$ && "$ewp" =~ ^[0-9]+$ && "$comp" =~ ^[0-9]+$ && "$unrec" =~ ^[0-9]+$ ]]; then
            warns+=("cannot read the drift report in pod $pod"); continue
        fi
        (( comp > 0 ))  && probs+=("${pre}${comp} failed compensation(s): Keycloak is wider than the record (User Manager → Decisions)")
        (( unexp > 0 )) && probs+=("${pre}${unexp} platform role(s) no confirmed decision or signed-off review explains (User Manager → Decisions)")
        (( ewp > 0 ))   && warns+=("${pre}${ewp} account(s) enabled while their grant or activation waits for qa")
        (( unrec > 0 )) && warns+=("${pre}${unrec} enabled account(s) with no request, decision or status record and not seeded: review them (User Manager → Users)")
        (( age > 1800 )) && warns+=("${pre}the drift was computed $((age / 60)) min ago (over 30 min)")
        [[ -n "$err" ]] && warns+=("${pre}the last drift computation failed: $err")
        [[ "$trunc" == 1 ]] && warns+=("${pre}Keycloak's account list was cut at access-api's ceiling: the counts are incomplete")
        [[ "$seeded" == 0 ]] && warns+=("${pre}the seeded accounts could not be read: none is exempt")
        oks+=("${pre}${accounts} accounts: ${unexp} unexplained roles, ${comp} failed compensations, ${ewp} enabled while pending, ${unrec} unrecorded; computed ${age} s ago (every ${interval} s)")
    done
    if ((${#probs[@]})); then
        local IFS=';'; _record FAIL "$name" "${probs[*]}${warns:+;${warns[*]}}"
    elif ((${#warns[@]})); then
        local IFS=';'; _record WARN "$name" "${warns[*]}"
    else
        local IFS=';'; _record OK "$name" "${oks[*]}"
    fi
}

# =============================================================================
# Check: config-api verifies tokens (IAM plan Phase 2b) — read-only
# target: NAMESPACE (default $NAMESPACE). The env contract, the key checksum config-api
# started with and a forged token; the realm's key ids are check_jwks's.
# =============================================================================
check_postgrest() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" envs mode want problems=() sum ann ip code
    envs="$(timeout "$TIMEOUT" $KUBECTL get deployment config-api -n "$ns" \
        -o jsonpath='{range .spec.template.spec.containers[*].env[*]}{.name}={.value}{.valueFrom.secretKeyRef.name}/{.valueFrom.secretKeyRef.key}{"\n"}{end}' 2>&1)" \
        || { _record FAIL "$name" "cannot read deployment config-api: ${envs:0:120}"; return; }
    mode=legacy; grep -q '^PGRST_JWT_SECRET=' <<<"$envs" && mode=jwt
    want=legacy; [[ "${IAM_POSTGREST_JWT:-false}" == "true" ]] && want=jwt
    if [[ "$mode" != "$want" ]]; then
        _record FAIL "$name" "config-api runs $mode, config.env says IAM_POSTGREST_JWT=${IAM_POSTGREST_JWT:-false} (./apps/frontend/deploy.sh)"
        return
    fi
    if [[ "$mode" == legacy ]]; then
        _record WARN "$name" "IAM_POSTGREST_JWT=false: config-api does not verify tokens (IAM Phase 2b)"
        return
    fi
    # contract C1 (apps/frontend/k8s/config-api-jwt.yaml)
    local line
    for line in 'PGRST_JWT_SECRET=medcea-jwks/jwks-sig.json' 'AUTHENTICATOR_PASSWORD=db-authenticator/password' \
                'PGRST_JWT_AUD=medcea-api/' 'PGRST_JWT_ROLE_CLAIM_KEY=.medcea_pgrst_role/' \
                'PGRST_DB_PRE_REQUEST=medcea_auth.pre_request/'; do
        grep -qxF "$line" <<<"$envs" || problems+=("env ${line%%=*} is not ${line#*=}")
    done
    grep -q '^PGRST_DB_URI=postgres://authenticator:\$(AUTHENTICATOR_PASSWORD)@' <<<"$envs" \
        || problems+=("PGRST_DB_URI does not take AUTHENTICATOR_PASSWORD")
    sum="$($KUBECTL get secret medcea-jwks -n "$ns" -o jsonpath='{.data.jwks-sig\.json}' 2>/dev/null | base64 -d 2>/dev/null | sha256sum | cut -c1-64)"
    ann="$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.spec.template.metadata.annotations.medcea/jwks-checksum}' 2>/dev/null)"
    [[ -n "$ann" && "$ann" == "$sum" ]] || problems+=("config-api runs other keys than Secret medcea-jwks (./deploy-infra.sh rolls it)")
    # the pod's password is read at start: the template names the Secret version it was made for
    ann="$($KUBECTL get deployment config-api -n "$ns" -o jsonpath='{.spec.template.metadata.annotations.medcea/auth-secret-version}' 2>/dev/null)"
    sum="$($KUBECTL get secret db-authenticator -n "$ns" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null)"
    [[ -n "$ann" && "$ann" == "$sum" ]] || problems+=("Secret db-authenticator changed since config-api started (./apps/frontend/deploy.sh)")
    # The realm's key ids against the Secret moved to the always-on jwks check (Phase 5, G3):
    # one FAIL, in either IAM_POSTGREST_JWT mode.
    # a forged token must be refused, never served as anon
    ip="$($KUBECTL get svc config-api -n "$ns" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
    code="$(curl -s -o /dev/null -w '%{http_code}' -m "$TIMEOUT" -H 'Authorization: Bearer x.y.z' "http://${ip}:3000/cea_unit?limit=1" 2>/dev/null)"
    [[ "$code" == 401 ]] || problems+=("a forged Bearer token got HTTP ${code:-no answer}, not 401")
    if [[ ${#problems[@]} -eq 0 ]]; then
        _record OK "$name" "config-api verifies tokens with Secret medcea-jwks; forged token refused (realm key ids: jwks)"
    else
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
    fi
}

# =============================================================================
# Check: the Python services enforce the route table (IAM_ENFORCE, IAM 2.6) — read-only
# target: NAMESPACE (default $NAMESPACE). Reads the ConfigMap and the deployments only:
# the NetworkPolicies admit no host traffic to scheduler, monitor or dbmgmt.
# Phase 5 (G11): settings.json without an enforce key FAILs (it read as false and passed
# silently under false); its switches block (IAM_GATES, IAM_NETPOL, IAM_POSTGREST_JWT,
# IAM_MQTT_PERSON as deploy-infra last wrote them, which the access review shows) is compared
# with config.env with the writer's defaults (lib-policy-artefacts.sh pa_iam_lib): a WARN.
# =============================================================================
check_iamenforce() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" json mode want dc v stale=() sw
    want=false; [[ "${IAM_ENFORCE:-false}" == "true" ]] && want=true
    json="$(timeout "$TIMEOUT" $KUBECTL get configmap medcea-iam-lib -n "$ns" -o jsonpath='{.data.settings\.json}' 2>/dev/null)"
    mode="$(python3 -c 'import json, sys
d = json.load(sys.stdin)
print("missing" if "enforce" not in d else str(d["enforce"] is True).lower())' <<<"$json" 2>/dev/null)"
    if [[ -z "$mode" ]]; then
        _record FAIL "$name" "ConfigMap medcea-iam-lib missing or unreadable (./deploy-infra.sh)"
        return
    fi
    if [[ "$mode" == missing ]]; then
        _record FAIL "$name" "settings.json in ConfigMap medcea-iam-lib has no enforce key: the services read it as false (./deploy-infra.sh)"
        return
    fi
    # the switches block against config.env, as pa_iam_lib derives each value (never a secret)
    sw="$(SW_GATES="${IAM_GATES:-true}" SW_NETPOL="${IAM_NETPOL:-true}" SW_JWT="${IAM_POSTGREST_JWT:-false}" \
        SW_MQTT="${IAM_MQTT_PERSON:-false}" python3 -c 'import json, os, sys
e = os.environ
want = {"IAM_GATES": e["SW_GATES"] != "false", "IAM_NETPOL": e["SW_NETPOL"] != "false",
        "IAM_POSTGREST_JWT": e["SW_JWT"] == "true", "IAM_MQTT_PERSON": e["SW_MQTT"] == "true"}
have = json.load(sys.stdin).get("switches")
if not isinstance(have, dict):
    print("settings.json has no switches block (./deploy-infra.sh writes it)")
else:
    bad = ["%s=%s (config.env %s)" % (k, str(have.get(k)).lower() if k in have else "absent", str(w).lower())
           for k, w in sorted(want.items()) if have.get(k) is not w]
    if bad:
        print("settings.json switches differ from config.env: %s, as of deploy-infra %s (./deploy-infra.sh)"
              % (", ".join(bad), have.get("written_at", "?")))' <<<"$json" 2>/dev/null)" || sw="cannot read settings.json switches"
    if [[ "$mode" != "$want" ]]; then
        _record FAIL "$name" "ConfigMap says enforce=$mode, config.env IAM_ENFORCE=${IAM_ENFORCE:-false} (./deploy-infra.sh)"
        return
    fi
    # the pods' copy, used only when /iam/ is missing (dbmgmt fails closed without it anyway);
    # an empty copy is false, as the services read it
    for dc in scheduler:api monitor:api config-ui:recipe-fileserver access:api; do
        v="$(timeout "$TIMEOUT" $KUBECTL get deployment "${dc%%:*}" -n "$ns" \
            -o jsonpath="{.spec.template.spec.containers[?(@.name==\"${dc#*:}\")].env[?(@.name==\"IAM_ENFORCE\")].value}" 2>/dev/null)" \
            || continue                                     # not deployed
        [[ "$v" == "true" ]] || v=false
        [[ "$v" == "$want" ]] || stale+=("${dc%%:*}")
    done
    # assigned_run (an operator's execute/stop/status/trigger) is checked only by the
    # database functions under IAM_DB_ROLES=true: no route-level check by decision
    if [[ "$want" == "true" && "${IAM_DB_ROLES:-false}" != "true" ]]; then
        _record FAIL "$name" "IAM_ENFORCE=true with IAM_DB_ROLES=false: operators can start and stop other units' runs (./medcea.sh IAM_DB_ROLES, or IAM_ENFORCE back to false)"
    elif [[ ${#stale[@]} -gt 0 && "$want" == "true" ]]; then
        _record FAIL "$name" "pod IAM_ENFORCE copy still false: ${stale[*]} (without /iam/ they let every request through: redeploy them, no run active)${sw:+; $sw}"
    elif [[ ${#stale[@]} -gt 0 ]]; then
        _record WARN "$name" "pod IAM_ENFORCE copy differs: ${stale[*]} (redeploy them; the copy is used only when /iam/ is missing)${sw:+; $sw}"
    elif [[ "$want" == "false" ]]; then
        _record WARN "$name" "IAM_ENFORCE=false: services only log what they would refuse (IAM 2.6)${sw:+; $sw}"
    elif [[ -n "$sw" ]]; then
        _record WARN "$name" "$sw"
    else
        _record OK "$name" "services refuse what the route table does not allow; every pod agrees; switches match config.env"
    fi
}

# =============================================================================
# Check: the MQTT Explorer's personal credentials (IAM_MQTT_PERSON, IAM 3.5) — read-only
# target: NAMESPACE. Every part must follow config.env: the broker pod's annotation
# medcea/mqtt-mode, the sidecar's MQTT_PERSON_CREDENTIALS, the conf (per_listener_settings),
# the page's data-mqtt-mode (ConfigMap mqtt-explorer-html) and iam-api's /healthz mode
# (through kubectl exec: its NetworkPolicy admits no host traffic but the kubelet's).
# Reads the broker's files' usernames (cut -d: -f1) and status.json, never a hash. The
# shared mqtt-explorer account was removed (1 Nov 2026): it FAILs in either mode if a
# password file still names it (a broker not redeployed since), and under false the page
# must be in mode "off" (no credential).
# =============================================================================
check_iammqtt() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" want ann env conf page api users ws st problems=() warns=()
    want=false; [[ "${IAM_MQTT_PERSON:-false}" == "true" ]] && want=true
    ann="$(timeout "$TIMEOUT" $KUBECTL get deployment mosquitto -n "$ns" \
        -o jsonpath='{.spec.template.metadata.annotations.medcea/mqtt-mode}' 2>/dev/null)" \
        || { _record FAIL "$name" "no Mosquitto deployment in $ns"; return; }
    env="$($KUBECTL get deployment mosquitto -n "$ns" \
        -o jsonpath='{.spec.template.spec.containers[?(@.name=="mqtt-auth-sync")].env[?(@.name=="MQTT_PERSON_CREDENTIALS")].value}' 2>/dev/null)"
    conf=false
    $KUBECTL get configmap mosquitto-config -n "$ns" -o jsonpath='{.data.mosquitto\.conf}' 2>/dev/null \
        | grep -qx 'per_listener_settings true' && conf=true
    [[ "${ann:-false}" == "$want" ]] || problems+=("broker pod annotation says ${ann:-false} (./deploy-infra.sh)")
    [[ "${env:-false}" == "$want" ]] || problems+=("broker sidecar runs ${env:-false} (./deploy-infra.sh)")
    [[ "$conf" == "$want" ]] || problems+=("broker conf per_listener_settings is $conf (./deploy-infra.sh)")
    page="$($KUBECTL get configmap mqtt-explorer-html -n "$ns" -o jsonpath='{.data.index\.html}' 2>/dev/null \
        | sed -n 's/.*data-mqtt-mode="\([a-z_]*\)".*/\1/p' | head -1)"
    if [[ -n "$page" || "$want" == true ]]; then
        [[ "$page" == "$([[ "$want" == true ]] && echo person || echo off)" ]] \
            || problems+=("the Explorer page is in mode '${page:-pre-3.5}' (./apps/mqtt-explorer/deploy.sh)")
    fi
    users="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/mosquitto -c mqtt-auth-sync -- cut -d: -f1 /mosquitto/auth/passwd 2>/dev/null)"
    grep -qx 'mqtt-explorer' <<<"$users" && problems+=("the removed shared mqtt-explorer account is still in the broker's password file (./deploy-infra.sh)")
    if [[ "$want" == true ]]; then
        # Phase 5 (G7): every Running iam-api pod, its mqtt_digest against medcea/mqtt-digest; a
        # credential is bound to the mqtt.json it was issued under, so a pod on an older one
        # issues stale rows. WARN inside the kubelet's sync (120 s after the ConfigMap's last
        # write, _iamlib_meta), FAIL after it.
        local meta mq_ann="" age="?" pods pod rcp=0 seen=0 got
        meta="$(_iamlib_meta "$ns")" && read -r _ mq_ann _ age <<<"$meta"
        pods="$(_running_pods "$ns" iam-api)" || rcp=$?
        for pod in $pods; do
            seen=$((seen + 1))
            api="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" "$pod" -c iam-api -- python3 -c \
                'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8085/healthz", timeout=5).read().decode())' 2>/dev/null)"
            got="$(python3 -c 'import json, sys; d = json.loads(sys.argv[1]); print(str(d.get("mode") is True).lower() + " " + (d.get("mqtt_digest") or "-"))' "$api" 2>/dev/null)"
            case "$got" in
                "true -") problems+=("iam-api pod $pod has no valid mqtt.json (./deploy-infra.sh)") ;;
                true\ *)
                    if [[ -z "$mq_ann" || "$mq_ann" == "-" ]]; then
                        warns+=("cannot read medcea/mqtt-digest of ConfigMap medcea-iam-lib: iam-api's mqtt.json not compared")
                    elif [[ "${got#true }" != "$mq_ann" ]]; then
                        if [[ "$age" =~ ^[0-9]+$ ]] && (( age < 120 )); then
                            warns+=("iam-api pod $pod reads mqtt.json ${got:5:12}, the ConfigMap holds ${mq_ann:0:12} since ${age} s (the kubelet syncs within 120 s)")
                        else
                            problems+=("iam-api pod $pod reads mqtt.json ${got:5:12}, the ConfigMap holds ${mq_ann:0:12} $(_iamlib_since "$age") (./apps/iam/deploy.sh)")
                        fi
                    fi ;;
                false\ *) problems+=("iam-api pod $pod still reads IAM_MQTT_PERSON=false (./deploy-infra.sh; it follows within a minute)") ;;
                *) problems+=("iam-mqttx does not answer in pod $pod (./apps/iam/deploy.sh)") ;;
            esac
        done
        ((seen)) || problems+=("iam-mqttx does not answer: no Running iam-api pod$( ((rcp == 3)) && echo ', no deployment iam-api') (./apps/iam/deploy.sh)")
        [[ "${IAM_DB_ROLES:-false}" == "true" ]] || problems+=("IAM_DB_ROLES=false: the broker cannot read person credentials (mqtt_auth's grants)")
        ws="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/mosquitto -c mqtt-auth-sync -- cut -d: -f1 /mosquitto/auth/passwd-ws 2>/dev/null)"
        grep -q '^explorer-' <<<"$users" && problems+=("a person credential is in the 1883 file")
        [[ -n "$ws" ]] || problems+=("no WebSocket password file (passwd-ws)")
        [[ -n "$ws" ]] && grep -qv '^explorer-' <<<"$ws" && problems+=("a name outside explorer- is in the WebSocket file")
    fi
    st="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/mosquitto -c mqtt-auth-sync -- cat /mosquitto/auth/status.json 2>/dev/null)"
    if [[ -n "$st" ]]; then
        python3 -c 'import datetime, json, sys
d = json.loads(sys.argv[1]).get("last_db_ok")
t = datetime.datetime.strptime(d, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) if d else None
sys.exit(0 if t and (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() < 300 else 1)' "$st" 2>/dev/null \
            || warns+=("the broker's sidecar has not read the database for over 5 minutes (it keeps the last set; person writes are dropped)")
    fi
    if [[ ${#problems[@]} -gt 0 ]]; then
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
    elif [[ "$want" == false ]]; then
        $KUBECTL get deployment iam-api -n "$ns" >/dev/null 2>&1 \
            || warns+=("iam-api is not deployed (./apps/iam/deploy.sh, needed before the switch)")
        _record WARN "$name" "IAM_MQTT_PERSON=false: the MQTT Explorer has no broker credential (no shared account any more); set it true with ./medcea.sh${warns:+; ${warns[*]}}"
    elif [[ ${#warns[@]} -gt 0 ]]; then
        local IFS=';'; _record WARN "$name" "${warns[*]}"
    else
        _record OK "$name" "personal credentials on the WebSocket listener only; broker, page and iam-api agree"
    fi
}

# =============================================================================
# Check: Grafana's role setting is the policy's (IAM 3.1) — read-only
# target: NAMESPACE (default $NAMESPACE). Compares the deployment's env with
# policy_grafana (infra/lib-oauth2-proxy.sh), the function deploy-infra renders.
# =============================================================================
check_grafanarole() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" envs path strict assign problems=()
    envs="$(timeout "$TIMEOUT" $KUBECTL get deployment grafana -n "$ns" \
        -o jsonpath='{range .spec.template.spec.containers[?(@.name=="grafana")].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null)" \
        || { _record SKIP "$name" "no Grafana deployment in $ns"; return; }
    path="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=//p' <<<"$envs")"
    strict="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT=//p' <<<"$envs")"
    assign="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ALLOW_ASSIGN_GRAFANA_ADMIN=//p' <<<"$envs")"
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        _record WARN "$name" "IAM_GATES=false: Grafana admits any enabled account, at least as Viewer (pre-3.1 setting)"
        return
    fi
    local GRAFANA_ROLE_PATH="" GRAFANA_ROLE_STRICT=""
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh" || ! REPO_ROOT="$SCRIPT_DIR" policy_grafana 2>/dev/null; then
        _record FAIL "$name" "cannot compile Grafana's role setting (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    [[ "$path" == "$GRAFANA_ROLE_PATH" ]] || problems+=("the live role path is not the compiled one (./deploy-infra.sh)")
    [[ "$strict" == "true" ]] || problems+=("role_attribute_strict is '${strict}', not true: a role without a setting still signs in")
    [[ "$assign" == "false" ]] || problems+=("allow_assign_grafana_admin is '${assign}', not false")
    if [[ ${#problems[@]} -eq 0 ]]; then
        _record OK "$name" "Editor/Viewer from the access policy; others refused; Grafana Admin only break-glass"
    else
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
    fi
}

# =============================================================================
# Check: the AI workbench's gate is the policy's (IAM 3.2) — read-only
# target: NAMESPACE (the platform namespace; the conf line never moves). Where the hub lives
# is the access policy's (research sandbox Phase 2b): workbench_placement /
# workbench_namespace (infra/lib-policy-tools.sh) print research and the research namespace
# while the policy has pod hub in the research zone, else platform and NAMESPACE. Reads the
# values helm deployed (Secret hub, values.yaml) on stdin — they hold the client secret, so
# only the verdict fields are printed — and compares them with policy_workbench
# (infra/lib-oauth2-proxy.sh). A hub Secret only in the other namespace WARNs (deferred:
# ./infra/deploy-workbench.sh --move); in both FAILs. Platform placement: today's rules,
# the notebooks' NetworkPolicy and egress hops included. Research placement: the gate
# rules, plus FAIL on the chart's own NetworkPolicy (hub, proxy, singleuser) in that
# namespace or singleuser.networkPolicy.enabled not false (the zone's rs-* policies are the
# only ones), cloudMetadata.blockWithIptables not false (its NET_ADMIN init container
# breaks PSA baseline), the hook hub.extraConfig.medcea-a2 missing (hub administration
# gives no workspace), a Role there granting secrets, or a hub pod without
# priorityClassName medcea-research-low; the platform's egress rule is not checked there.
# =============================================================================
# _wb_hub_secret NS → 0 Secret hub present, 1 absent (NotFound), 2 unreadable
_wb_hub_secret() {
    local out rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get secret hub -n "$1" -o name 2>&1)" || rc=$?
    [[ $rc -eq 0 ]] && return 0
    grep -q 'NotFound' <<<"$out" && return 1
    return 2
}
check_iamworkbench() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" live problems=() warns=() place wbns other rc_here rc_other
    if [[ "${WORKBENCH_ENABLED:-true}" != "true" ]]; then
        _record SKIP "$name" "WORKBENCH_ENABLED is not true"; return
    fi
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-policy-tools.sh"; then
        _record FAIL "$name" "cannot read infra/lib-policy-tools.sh"; return
    fi
    if ! place="$(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" workbench_placement 2>/dev/null)" \
            || ! wbns="$(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" workbench_namespace 2>/dev/null)" \
            || [[ -z "$wbns" || ! "$place" =~ ^(research|platform)$ ]]; then
        _record FAIL "$name" "cannot tell where the access policy places the AI workbench (python3 apps/iam/compiler/cli.py check)"; return
    fi
    if [[ "$place" == research ]]; then other="$ns"; else other="${RESEARCH_NAMESPACE:-${ns}-research}"; fi
    rc_here=0; _wb_hub_secret "$wbns" || rc_here=$?
    rc_other=1
    [[ "$other" != "$wbns" ]] && { rc_other=0; _wb_hub_secret "$other" || rc_other=$?; }
    if [[ $rc_here -eq 0 && $rc_other -eq 0 ]]; then
        _record FAIL "$name" "the workbench release is in two namespaces, $wbns and $other: remove the one the access policy does not place it in ($place) by hand"
        return
    elif [[ $rc_here -eq 1 && $rc_other -eq 0 ]]; then
        if [[ "$place" == research ]]; then
            _record WARN "$name" "deferred: ./infra/deploy-workbench.sh --move (the access policy places the AI workbench in the research zone, namespace $wbns; its hub still runs in $other)"
        else
            _record WARN "$name" "deferred: ./infra/deploy-workbench.sh --move (the access policy places the AI workbench in the platform namespace $wbns; its hub still runs in the research zone, $other)"
        fi
        return
    fi
    live="$(timeout "$TIMEOUT" $KUBECTL get secret hub -n "$wbns" -o jsonpath='{.data.values\.yaml}' 2>/dev/null \
        | base64 -d 2>/dev/null | python3 -c '
import json, sys, yaml
try:
    v = yaml.safe_load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(v, dict):
    sys.exit(1)
hub = v.get("hub") or {}
c = hub.get("config") or {}
a, g = c.get("Authenticator") or {}, c.get("GenericOAuthenticator") or {}
lr = hub.get("loadRoles") or {}
wa, ad = lr.get("workbench-admin") or {}, lr.get("admin") or {}
su = v.get("singleuser") or {}
np = su.get("networkPolicy") or {}
eg = np.get("egressAllowRules") or {}
hook = (hub.get("extraConfig") or {}).get("medcea-a2")
out = {"allow_all": a.get("allow_all"), "admin_users": sorted(a.get("admin_users") or []),
       "existing": a.get("allow_existing_users"), "auth_state": a.get("enable_auth_state"),
       "allowed": sorted(g.get("allowed_groups") or []), "admin_groups": sorted(g.get("admin_groups") or []),
       "key": g.get("auth_state_groups_key"),
       "role_scopes": sorted(wa.get("scopes") or []), "role_groups": sorted(wa.get("groups") or []),
       "role_users": sorted(wa.get("users") or []),
       "builtin_admins": ad.get("users") if isinstance(ad.get("users"), list) else "unpinned",
       "delete_pvc": (c.get("KubeSpawner") or {}).get("delete_pvc"),
       "netpol": np.get("enabled"), "private": eg.get("privateIPs"), "metadata": eg.get("cloudMetadataServer"),
       "imds": (su.get("cloudMetadata") or {}).get("blockWithIptables"),
       "hook": isinstance(hook, str) and "c.KubeSpawner.pre_spawn_hook = _medcea_a2" in hook,
       "egress": json.dumps(np.get("egress") or [], sort_keys=True, separators=(",", ":"))}
for k, x in out.items():
    print(f"{k}\t{json.dumps(x)}")')" || { _record SKIP "$name" "no hub Secret in $wbns (workbench not deployed)"; return; }
    declare -A L=()
    local k x
    while IFS=$'\t' read -r k x; do L[$k]="$x"; done <<<"$live"
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh"; then
        _record FAIL "$name" "cannot read infra/lib-oauth2-proxy.sh"; return
    fi
    # Hub administration is the custom role workbench-admin (values.yaml hub.loadRoles);
    # JupyterHub's built-in admin role carries tokens and access:servers (a token minted
    # for a person opens their server) and nobody may hold it. admin_access is deprecated
    # since JupyterHub 2.0 and does nothing, so it is not checked.
    [[ "${L[admin_users]}" == "[]" ]] || problems+=("admin_users is set: they are admitted whatever the policy says and get the built-in admin role")
    [[ "${L[admin_groups]}" == "[]" ]] || problems+=("admin_groups is set: its members get the built-in admin role (tokens, access:servers)")
    [[ "${L[builtin_admins]}" == "[]" ]] || problems+=("the built-in admin role's members are ${L[builtin_admins]}, not pinned to [] (stored admin flags survive)")
    local want_scopes forbidden
    want_scopes="$(python3 -c 'import json, sys; print(json.dumps(sorted(json.loads(sys.argv[1]))))' "$WORKBENCH_ADMIN_ROLE_SCOPES")"
    forbidden="$(python3 -c '
import json, sys
bad = set(json.loads(sys.argv[2]))
print(" ".join(s for s in json.loads(sys.argv[1]) if s.split("!")[0] in bad))' "${L[role_scopes]}" "$WORKBENCH_ADMIN_ROLE_FORBIDDEN")"
    [[ -z "$forbidden" ]] || problems+=("workbench-admin holds $forbidden: a hub admin can open others' servers")
    [[ "${L[role_scopes]}" == "$want_scopes" ]] || problems+=("workbench-admin's scopes ${L[role_scopes]} are not the decided $want_scopes")
    [[ "${L[delete_pvc]}" == false ]] || problems+=("delete_pvc is ${L[delete_pvc]}: removing a hub user deletes the home")
    [[ "${L[auth_state]}" != true ]] || problems+=("enable_auth_state is true: a hub admin can read people's Keycloak tokens")
    [[ "${L[existing]}" != true ]] || problems+=("allow_existing_users is true: every user in the hub database gets in")
    if [[ "$place" == platform ]]; then
        [[ "${L[netpol]}" == true && "${L[private]}" == false && "${L[metadata]}" == false ]] \
            || problems+=("the notebooks' NetworkPolicy is off or allows private addresses")
        # The notebooks' platform hops (IAM 3.2b): exactly the compiled ones, and none
        # unless IAM_POSTGREST_JWT and IAM_DB_ROLES are true (policy_workbench_egress).
        local WORKBENCH_EGRESS="" want_egress
        if REPO_ROOT="$SCRIPT_DIR" policy_workbench_egress 2>/dev/null; then
            want_egress="$(python3 -c 'import json, sys; print(json.dumps(json.dumps(json.loads(sys.argv[1]), sort_keys=True, separators=(",", ":"))))' "$WORKBENCH_EGRESS")"
            [[ "${L[egress]}" == "$want_egress" ]] \
                || problems+=("the notebooks' egress hops are not the compiled ones for this IAM_POSTGREST_JWT/IAM_DB_ROLES (./infra/deploy-workbench.sh)")
        else
            problems+=("cannot compile the notebooks' egress hops (python3 apps/iam/compiler/cli.py check)")
        fi
    else
        _wb_research_rules "$wbns"
    fi
    local tmpl pod
    tmpl="$($KUBECTL get deployment hub -n "$wbns" -o jsonpath='{.spec.template.metadata.annotations.checksum/secret}' 2>/dev/null)"
    pod="$($KUBECTL get pods -n "$wbns" -l component=hub --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.annotations.checksum/secret}{"\n"}{end}' 2>/dev/null | sort -u)"
    [[ -n "$tmpl" && "$pod" == "$tmpl" ]] || problems+=("the running hub pod does not carry the deployed values (rollout pending?)")
    # workbench-admin's members are policy_workbench's in either mode: the compiled admin
    # groups (IAM_GATES=true) or ADMIN_USER by name (IAM_GATES=false).
    local WORKBENCH_ALLOWED_GROUPS="" WORKBENCH_ADMIN_GROUPS="" WORKBENCH_ALLOW_ALL="" WORKBENCH_HUBADMIN_USERS="" WORKBENCH_403_MESSAGE=""
    if ! REPO_ROOT="$SCRIPT_DIR" policy_workbench 2>/dev/null; then
        _record FAIL "$name" "cannot compile the workbench's gate (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    local sorted_json='import json, sys; print(json.dumps(sorted(json.loads(sys.argv[1]))))'
    local want_admins want_hubadmins where=""
    [[ "$place" == research ]] && where="; in the research zone (namespace $wbns: no chart NetworkPolicy, no Role on secrets, the hub preemptible)"
    want_admins="$(python3 -c "$sorted_json" "$WORKBENCH_ADMIN_GROUPS")"
    want_hubadmins="$(python3 -c "$sorted_json" "$WORKBENCH_HUBADMIN_USERS")"
    [[ "${L[role_groups]}" == "$want_admins" ]] || problems+=("workbench-admin's groups ${L[role_groups]} are not the compiled $want_admins")
    [[ "${L[role_users]}" == "$want_hubadmins" ]] || problems+=("workbench-admin's users ${L[role_users]} are not $want_hubadmins")
    local IFS=';'
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        if [[ ${#problems[@]} -eq 0 ]]; then
            _record WARN "$name" "IAM_GATES=false: the workbench admits any realm account (pre-3.2 sign-in); hub administrator $want_hubadmins (workbench-admin)${warns[*]:+; ${warns[*]}}"
        else
            _record FAIL "$name" "${problems[*]}"
        fi
        return
    fi
    local want_allowed
    want_allowed="$(python3 -c "$sorted_json" "$WORKBENCH_ALLOWED_GROUPS")"
    [[ "${L[allow_all]}" == false ]] || problems+=("allow_all is ${L[allow_all]}")
    [[ "${L[allowed]}" == "$want_allowed" ]] || problems+=("allowed_groups ${L[allowed]} is not the compiled $want_allowed (./infra/deploy-workbench.sh)")
    [[ "${L[key]}" == '"oauth_user.groups"' ]] || problems+=("auth_state_groups_key is ${L[key]}")
    if [[ ${#problems[@]} -gt 0 ]]; then
        _record FAIL "$name" "${problems[*]}"
    elif [[ ${#warns[@]} -gt 0 ]]; then
        _record WARN "$name" "${warns[*]}"
    else
        _record OK "$name" "admits $want_allowed from the access policy; hub administrators $want_admins hold workbench-admin (no tokens, no access:servers), nobody the built-in admin role$where"
    fi
}
# _wb_research_rules WB_NS: the research placement's own rules, into the caller's
# problems/warns and L (check_iamworkbench); read-only.
_wb_research_rules() {
    local wbns="$1" out rc=0 x
    [[ "${L[netpol]}" == false ]] \
        || problems+=("singleuser.networkPolicy.enabled is ${L[netpol]}, not false: the chart's own policy is an allow-all in the research zone (./infra/deploy-workbench.sh)")
    [[ "${L[imds]}" == false ]] \
        || problems+=("singleuser.cloudMetadata.blockWithIptables is ${L[imds]}, not false: its NET_ADMIN init container breaks the namespace's PSA baseline (./infra/deploy-workbench.sh)")
    [[ "${L[hook]}" == true ]] \
        || problems+=("the hook hub.extraConfig.medcea-a2 is missing: hub administration would give a workspace (./infra/deploy-workbench.sh)")
    out="$(timeout "$TIMEOUT" $KUBECTL get netpol -n "$wbns" -o jsonpath='{.items[*].metadata.name}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        warns+=("cannot read the NetworkPolicies in $wbns: $(tail -n1 <<<"$out" | cut -c1-100)")
    else
        x="$(tr ' ' '\n' <<<"$out" | grep -xE 'hub|proxy|singleuser' | sort | paste -sd ' ')"
        [[ -z "$x" ]] || problems+=("the chart's own NetworkPolicy $x is in $wbns: it widens the research zone (microk8s kubectl delete networkpolicy -n $wbns <name>; ./infra/deploy-workbench.sh)")
    fi
    rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get roles -n "$wbns" -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        warns+=("cannot read the Roles in $wbns: $(tail -n1 <<<"$out" | cut -c1-100)")
    else
        x="$(python3 -c '
import json, sys
try:
    items = json.load(sys.stdin).get("items") or []
except Exception:
    print("?"); sys.exit()
print(" ".join(sorted(i["metadata"]["name"] for i in items
                      if any(set(r.get("resources") or []) & {"secrets", "*"} for r in i.get("rules") or []))))' <<<"$out")"
        if [[ "$x" == "?" ]]; then
            warns+=("cannot parse the Roles in $wbns")
        elif [[ -n "$x" ]]; then
            problems+=("Role(s) $x in $wbns grant secrets: the hub (or whoever holds them) can read every Secret of the research zone")
        fi
    fi
    rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get pods -n "$wbns" -l component=hub --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.name}={.spec.priorityClassName}{"\n"}{end}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        warns+=("cannot read the hub pod in $wbns: $(tail -n1 <<<"$out" | cut -c1-100)")
    else
        x="$(grep . <<<"$out" | grep -v '=medcea-research-low$' | cut -d= -f1 | paste -sd ' ')"
        [[ -z "$x" ]] || problems+=("hub pod $x runs without priorityClassName medcea-research-low: it could preempt the research database (./infra/deploy-workbench.sh)")
    fi
}

# =============================================================================
# Check: the onboarding wizard's roles are the policy's (IAM 3.4) — read-only
# Compares the running daemon's --required-role (argv: a role list, no secret)
# with policy_tool edge-wizard (infra/lib-policy-tools.sh), the list
# edge/wizard-daemon.sh passes.
# =============================================================================
check_onboardroles() {
    local name="$1" argv have want
    argv="$(pgrep -af '[w]izard_server.py .*--daemon' | head -1)"
    if [[ -z "$argv" ]]; then
        _record SKIP "$name" "no onboarding wizard daemon runs (systemctl --user status cea-edge-wizard)"
        return
    fi
    have="$(sed -n 's/.* --required-role \([^ ]*\).*/\1/p' <<<"$argv")"
    # shellcheck source=/dev/null
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-policy-tools.sh" \
            || ! want="$(REPO_ROOT="$SCRIPT_DIR" policy_tool edge-wizard 2>/dev/null)"; then
        _record FAIL "$name" "cannot compile the onboarding roles (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        if [[ "$have" == "$want" ]]; then
            _record WARN "$name" "IAM_GATES=false: the wizard admits ${want:-any signed-in account} (EDGE_WIZARD_ROLE, pre-policy)"
        else
            _record FAIL "$name" "the wizard admits ${have:-any signed-in account}, EDGE_WIZARD_ROLE says ${want:-any} (./apps/edge-wizard/deploy.sh)"
        fi
    elif [[ -z "$have" ]]; then
        _record FAIL "$name" "the wizard runs without --required-role: any signed-in account may erase a board (./apps/edge-wizard/deploy.sh)"
    elif [[ "$have" != "$want" ]]; then
        _record FAIL "$name" "the wizard admits $have, the policy compiles $want (./apps/edge-wizard/deploy.sh, no run active)"
    else
        _record OK "$name" "admits $want from the access policy"
    fi
}

# =============================================================================
# Check: pgAdmin's sign-in roles are the policy's (IAM 3.4) — read-only
# target: NAMESPACE. The OAuth2 config is in Secret pgadmin-config with the client
# secret: it reaches python on stdin, which prints only OAUTH2_ADDITIONAL_CLAIMS.
# A Deployment that still carries PGADMIN_CONFIG_OAUTH2_CONFIG or
# PGADMIN_DEFAULT_PASSWORD as a literal value (from before the Secret) FAILs;
# only the variables' names are printed.
# =============================================================================
check_pgadminroles() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" have want same literal oauth passfile
    timeout "$TIMEOUT" $KUBECTL get deployment pgadmin -n "$ns" >/dev/null 2>&1 \
        || { _record SKIP "$name" "no pgAdmin deployment in $ns"; return; }
    # The Deployment and every ReplicaSet it kept: an old one still holds its pod
    # template, plain env values included. "?" = unreadable, never a variable name.
    literal="$(timeout "$TIMEOUT" $KUBECTL get deployment,replicaset -n "$ns" -l app=pgadmin -o json 2>/dev/null \
        | python3 -c '
import json, sys
try:
    items, held = json.load(sys.stdin)["items"], []
    if not any(o["kind"] == "Deployment" for o in items):
        raise ValueError("no deployment")
    for o in items:
        env = o["spec"]["template"]["spec"]["containers"][0].get("env", [])
        names = [e["name"] for e in env if "value" in e
                 and e["name"] in ("PGADMIN_CONFIG_OAUTH2_CONFIG", "PGADMIN_DEFAULT_PASSWORD")]
        if names:
            held.append("%s/%s (%s)" % (o["kind"].lower(), o["metadata"]["name"], ", ".join(names)))
    print("; ".join(held))
except Exception:
    print("?")')"
    if [[ "$literal" == "?" ]]; then
        _record FAIL "$name" "cannot read pgAdmin's deployment and ReplicaSets in $ns"
        return
    elif [[ -n "$literal" ]]; then
        _record FAIL "$name" "pgAdmin's secrets are plain env values in $literal, not from Secret pgadmin-config (./deploy-infra.sh)"
        return
    fi
    if ! timeout "$TIMEOUT" $KUBECTL get secret pgadmin-config -n "$ns" >/dev/null 2>&1; then
        _record FAIL "$name" "Secret pgadmin-config is missing in $ns (./deploy-infra.sh)"
        return
    fi
    have="$($KUBECTL get secret pgadmin-config -n "$ns" -o jsonpath='{.data.oauth2-config}' 2>/dev/null \
        | base64 -d 2>/dev/null | python3 -c '
import ast, sys
try:
    print(repr(ast.literal_eval(sys.stdin.read())[0].get("OAUTH2_ADDITIONAL_CLAIMS")))
except Exception:
    print("unreadable")')"
    # shellcheck source=/dev/null
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-policy-tools.sh" \
            || ! want="$(REPO_ROOT="$SCRIPT_DIR" policy_tool pgadmin 2>/dev/null)"; then
        _record FAIL "$name" "cannot compile pgAdmin's roles (python3 apps/iam/compiler/cli.py check)"
        return
    fi
    same="$(python3 -c 'import ast, sys; print(ast.literal_eval(sys.argv[1]) == ast.literal_eval(sys.argv[2]))' "$have" "$want" 2>/dev/null)"
    if [[ "$same" != True ]]; then
        _record FAIL "$name" "OAUTH2_ADDITIONAL_CLAIMS is $have, the policy compiles $want (./deploy-infra.sh)"
    # libpq skips a passfile its user cannot read: the server entry then fails with
    # "no password supplied" (the file was root's until 1 Nov 2026). The pod says
    # which; no answer means kubectl could not reach the container at all.
    elif passfile="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/pgadmin -c pgadmin -- \
            sh -c 'test -r /pgpassfile && echo readable || echo unreadable' 2>/dev/null)"; [[ "$passfile" != readable ]]; then
        if [[ "$passfile" == unreadable ]]; then
            _record FAIL "$name" "pgAdmin's user cannot read /pgpassfile: its database server entry cannot connect (./deploy-infra.sh)"
        else
            _record FAIL "$name" "cannot reach pgAdmin's container (still starting? kubectl -n $ns get pods -l app=pgadmin)"
        fi
    # Each e-mail in the pod's PGADMIN_OAUTH2_SERVER_USERS must be an OAuth2 user
    # owning "IoT Postgres" (the postStart hook loads them). Read-only: python's
    # sqlite3 in the pod on pgAdmin's own database, opened mode=ro; prints e-mails
    # and counts, nothing else. "?" = unreadable.
    elif oauth="$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$ns" deployment/pgadmin -c pgadmin -- \
            /venv/bin/python3 - /var/lib/pgadmin/pgadmin4.db 2>/dev/null <<'PY'
import os, sqlite3, sys
try:
    want = sorted({u for u in os.environ.get("PGADMIN_OAUTH2_SERVER_USERS", "").split(",") if u})
    db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    have = {u.lower(): n for u, n in db.execute(
        "SELECT u.username, (SELECT count(*) FROM server s WHERE s.user_id = u.id"
        " AND s.name = 'IoT Postgres') FROM \"user\" u WHERE u.auth_source = 'oauth2'")}
    if not want:
        print("empty")
    else:
        bad = ["%s (no OAuth2 user)" % e for e in want if e not in have]
        bad += ["%s (no IoT Postgres entry)" % e for e in want if have.get(e) == 0]
        # its password file, where pgAdmin resolves "PassFile" (preprocess_username)
        folder = lambda e: (("pga_user_" + e) if e[:1].isdigit() else e).replace("@", "_")
        bad += ["%s (no password file)" % e for e in want if have.get(e) and not os.access(
            os.path.join(os.path.dirname(sys.argv[1]), "storage", folder(e), "pgpassfile"), os.R_OK)]
        print(("missing " + "; ".join(bad)) if bad else "ok %d" % len(want))
except Exception:
    print("?")
PY
)"; [[ "$oauth" == "?" || -z "$oauth" ]]; then
        _record FAIL "$name" "cannot read pgAdmin's users and servers in its pod (still starting? kubectl -n $ns logs deployment/pgadmin)"
    elif [[ "$oauth" == missing* ]]; then
        _record FAIL "$name" "pgAdmin's postStart hook did not give ${oauth#missing } its server (kubectl -n $ns logs deployment/pgadmin | grep oauth2-servers; ./deploy-infra.sh)"
    elif [[ "${IAM_GATES:-true}" == "false" ]]; then
        _record WARN "$name" "IAM_GATES=false: pgAdmin keeps the pre-policy $want"
    elif [[ "$oauth" == empty ]]; then
        _record WARN "$name" "admits $want, but PGADMIN_OAUTH2_SERVER_USERS is empty: no OAuth2 user has the IoT Postgres entry (./deploy-infra.sh)"
    else
        _record OK "$name" "admits $want from the access policy (checked at sign-in only); ${oauth#ok } OAuth2 user(s) have the IoT Postgres entry"
    fi
}

# =============================================================================
# Check: Superset's sign-in roles are the policy's (Superset stages B and C) — read-only
# target: NAMESPACE. Superset signs people in itself; the role each platform role gets
# (AUTH_ROLES_MAPPING) is SUPERSET_ROLES_MAPPING in Secret superset-secrets, next to
# its secret key and passwords, so the Deployment, its ReplicaSets and the Secret
# reach python on stdin, which prints only verdicts, variable names and the mapping
# (role names, no secret). SKIP without the Deployment: apps/superset/deploy.sh skips
# while the applied policy gives no role a Superset setting, and while
# IAM_DB_SERVICE_ROLES is not true (its connection is svc_superset).
# The pod reads the mapping as a secretKeyRef env, at start only (F10): so a running
# pod's medcea/config-checksum must equal superset_config_checksum
# (apps/superset/lib-superset.sh, the deploy's own function) of the live Secret and
# ConfigMap, or it still admits what an older Secret said.
# FAIL: a secret as a plain env value (in the Deployment or a ReplicaSet it kept, by
# name or because the value equals one of the Secret's), the Secret missing, its
# SUPERSET_SECRET_KEY empty or Superset's default, the mapping not policy_tool
# superset's (or the policy no longer has a superset tool, or gives no role a setting),
# a running pod started with another Secret or ConfigMap, the connection user not
# svc_superset, an image not pinned by digest; WARN while IAM_GATES=false, while
# IAM_DB_SERVICE_ROLES is not true (the next deploy stops it) and with no running pod.
# =============================================================================
check_supersetroles() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" doc have=() line want rc=0 same sum pods
    if ! timeout "$TIMEOUT" $KUBECTL get deployment superset -n "$ns" >/dev/null 2>&1; then
        if [[ "${IAM_DB_SERVICE_ROLES:-false}" != "true" ]]; then
            _record SKIP "$name" "no Superset deployment in $ns: it needs IAM_DB_SERVICE_ROLES=true (its data connection is svc_superset)"
        else
            _record SKIP "$name" "no Superset deployment in $ns (./apps/superset/deploy.sh installs it once the applied access policy gives a role a Superset setting)"
        fi
        return
    fi
    doc="$( { timeout "$TIMEOUT" $KUBECTL get deployment,replicaset -n "$ns" -l app=superset -o json 2>/dev/null || echo null
              echo
              timeout "$TIMEOUT" $KUBECTL get secret superset-secrets -n "$ns" -o json 2>/dev/null || echo null; } \
        | python3 -c '
import base64, json, re, sys
SECRET_NAMES = {"SUPERSET_SECRET_KEY", "SUPERSET_META_DB_PASS", "SUPERSET_CLIENT_SECRET", "SVC_SUPERSET_DB_PASS"}
DEFAULT_KEYS = {"CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET", "CHANGE_ME_SECRET_KEY", "thisISaSECRET_1234"}
text, dec, objs, i = sys.stdin.read(), json.JSONDecoder(), [], 0
try:
    while len(objs) < 2:
        while i < len(text) and text[i].isspace():
            i += 1
        o, i = dec.raw_decode(text, i)
        objs.append(o)
    lst, sec = objs
    if not lst or not any(o.get("kind") == "Deployment" for o in lst.get("items", [])):
        raise ValueError("no deployment")
except Exception:
    print("unreadable"); sys.exit(0)
data = {}
if sec:
    try:
        data = {k: base64.b64decode(v).decode() for k, v in (sec.get("data") or {}).items()}
    except Exception:
        print("unreadable"); sys.exit(0)
else:
    print("nosecret")
values = {v for k, v in data.items() if k != "SUPERSET_ROLES_MAPPING" and len(v) >= 8}
held, dbuser, images = [], [], set()
for o in lst["items"]:
    spec = o["spec"]["template"]["spec"]
    names = []
    for c in spec.get("initContainers", []) + spec.get("containers", []):
        images.add(c.get("image", ""))
        for e in c.get("env", []):
            if "value" not in e:
                continue
            if e["name"] in SECRET_NAMES or e["name"] == "SUPERSET_ROLES_MAPPING" \
                    or re.search(r"(?i)pass|secret|token", e["name"]) or e["value"] in values:
                names.append(e["name"])
            if o["kind"] == "Deployment" and e["name"] == "SUPERSET_DB_USER":
                dbuser.append(e["value"])
    if names:
        held.append("%s/%s (%s)" % (o["kind"].lower(), o["metadata"]["name"], ", ".join(sorted(set(names)))))
if held:
    print("plain " + "; ".join(held))
if sec:
    k = data.get("SUPERSET_SECRET_KEY", "")
    print("key " + ("empty" if not k else "default" if k in DEFAULT_KEYS else "short" if len(k) < 32 else "ok"))
    try:
        m = json.loads(data["SUPERSET_ROLES_MAPPING"])
        assert isinstance(m, dict)
        print("mapping " + json.dumps({r: sorted(v) for r, v in m.items()}, sort_keys=True))
    except Exception:
        print("mapping ?")
print("dbuser " + (dbuser[0] if dbuser else "-"))
bad = sorted(x for x in images if "@sha256:" not in x)
print("unpinned " + " ".join(bad) if bad else "pinned")
')"
    mapfile -t have <<<"$doc"
    _ssr_get() { local l; for l in "${have[@]}"; do [[ "$l" == "$1 "* ]] && { echo "${l#"$1" }"; return; }; done; }
    if [[ "$doc" == unreadable || -z "$doc" ]]; then
        _record FAIL "$name" "cannot read Superset's deployment, ReplicaSets or Secret superset-secrets in $ns"
        return
    elif [[ -n "$(_ssr_get plain)" ]]; then
        _record FAIL "$name" "Superset's secrets are plain env values in $(_ssr_get plain), not from Secret superset-secrets (./apps/superset/deploy.sh)"
        return
    elif printf '%s\n' "${have[@]}" | grep -qx nosecret; then
        _record FAIL "$name" "Secret superset-secrets is missing in $ns (./apps/superset/deploy.sh)"
        return
    elif [[ "$(_ssr_get key)" != ok ]]; then
        _record FAIL "$name" "Superset's SUPERSET_SECRET_KEY is $(_ssr_get key) in Secret superset-secrets (./deploy-infra.sh generates it, then ./apps/superset/deploy.sh)"
        return
    elif [[ "$(_ssr_get dbuser)" != svc_superset ]]; then
        _record FAIL "$name" "Superset's connection logs in as $(_ssr_get dbuser), not svc_superset (./apps/superset/deploy.sh)"
        return
    elif [[ "$(_ssr_get unpinned)" != "" ]]; then
        _record FAIL "$name" "Superset's image is not pinned by digest: $(_ssr_get unpinned)"
        return
    fi
    # shellcheck source=/dev/null
    declare -F policy_tool >/dev/null || REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-policy-tools.sh" \
        || { _record FAIL "$name" "cannot load infra/lib-policy-tools.sh"; return; }
    want="$(REPO_ROOT="$SCRIPT_DIR" policy_tool superset 2>/dev/null)" || rc=$?
    case "$rc" in
        0) ;;
        3) _record WARN "$name" "IAM_GATES=false: Superset has no pre-policy setting; it runs with $(_ssr_get mapping) (./apps/superset/uninstall.sh, or IAM_GATES=true)"
           return ;;
        5) _record FAIL "$name" "Superset is deployed, but the applied access policy has no superset tool, or no role is given a setting: it still admits $(_ssr_get mapping) (./apps/superset/deploy.sh --gate-only stops it)"
           return ;;
        *) _record FAIL "$name" "cannot compile Superset's roles (python3 apps/iam/compiler/cli.py check)"
           return ;;
    esac
    same="$(python3 -c 'import json, sys
try:
    a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
    print({r: sorted(v) for r, v in a.items()} == {r: sorted(v) for r, v in b.items()})
except Exception:
    print(False)' "$(_ssr_get mapping)" "$want" 2>/dev/null)"
    if [[ "$same" != True ]]; then
        _record FAIL "$name" "AUTH_ROLES_MAPPING is $(_ssr_get mapping), the policy compiles $want (./apps/superset/deploy.sh --gate-only)"
        return
    fi
    # The running pods against the live Secret and ConfigMap (F10): the deploy's own checksum.
    # shellcheck source=/dev/null
    declare -F superset_config_checksum >/dev/null || source "$SCRIPT_DIR/apps/superset/lib-superset.sh" \
        || { _record FAIL "$name" "cannot load apps/superset/lib-superset.sh"; return; }
    sum="$(KUBECTL="timeout $TIMEOUT $KUBECTL" superset_config_checksum "$ns")" || sum=""
    pods="$(KUBECTL="timeout $TIMEOUT $KUBECTL" superset_web_pods "$ns")" || pods="?"
    if [[ -z "$sum" || "$pods" == "?" ]]; then
        _record FAIL "$name" "cannot compare the running Superset with Secret superset-secrets and ConfigMap superset-config in $ns"
    elif [[ -z "$pods" ]]; then
        _record WARN "$name" "no running Superset pod in $ns (kubectl -n $ns get pod -l app=superset)"
    elif [[ -n "$(awk -v s="$sum" '$2 != s {print $1}' <<<"$pods")" ]]; then
        _record FAIL "$name" "pod $(awk -v s="$sum" '$2 != s {print $1; exit}' <<<"$pods") was started with another Secret or ConfigMap (medcea/config-checksum): it may still admit an older mapping (./apps/superset/deploy.sh)"
    elif [[ "${IAM_DB_SERVICE_ROLES:-false}" != "true" ]]; then
        _record WARN "$name" "IAM_DB_SERVICE_ROLES is not true: the next ./apps/superset/deploy.sh (or --gate-only) stops Superset, whose connection is svc_superset"
    else
        _record OK "$name" "maps $(python3 -c 'import json,sys; print(", ".join(sorted(json.loads(sys.argv[1]))))' "$want" 2>/dev/null) from the access policy (checked at sign-in only); connection svc_superset"
    fi
}

# =============================================================================
# Check: the flows Node-RED runs against git (IAM 3.3, waiver W1's control) — read-only
# target: NAMESPACE. Reads /data/flows.json as dbclients does; apps/node-red/flows_diff.py
# prints ids, types, names and key names, never a value (the ingest password is in it).
# FAIL: a git node missing or changed, or no flows; WARN: nodes or keys outside git.
# Phase 5 (G9): flows_diff.py reads the working tree, so a flow file that git does not have
# committed (git status --porcelain -- apps/node-red/flows; --no-optional-locks, so the index
# is never refreshed) is at least a WARN; without git or a checkout, only a note.
# =============================================================================
check_noderedflows() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" out rc dirty="" gitnote="" n
    timeout "$TIMEOUT" $KUBECTL get deployment node-red -n "$ns" >/dev/null 2>&1 \
        || { _record SKIP "$name" "no Node-RED deployment in $ns"; return; }
    REPO_ROOT="$SCRIPT_DIR"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-node-red.sh"
    out="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/node-red -- cat /data/flows.json 2>/dev/null \
        | python3 -I "$SCRIPT_DIR/apps/node-red/flows_diff.py" diff --git "$SCRIPT_DIR/apps/node-red/flows" \
            --values <(nr_flow_values "$ns") 2>/dev/null)"; rc=$?
    out="$(sed 's/^\(OK\|WARN\|FAIL\|UNREADABLE\) //' <<<"$out" | paste -sd ';' | cut -c1-300)"
    if ! command -v git >/dev/null 2>&1; then
        gitnote="no git: uncommitted flow files not checked"
    elif ! dirty="$(timeout "$TIMEOUT" git -C "$SCRIPT_DIR" --no-optional-locks status --porcelain -- apps/node-red/flows 2>/dev/null)"; then
        gitnote="not a git checkout (or git did not answer): uncommitted flow files not checked"
        dirty=""
    fi
    if [[ -n "$dirty" ]]; then
        n="$(grep -c . <<<"$dirty")"
        dirty="$n flow file(s) not committed to git: $(sed 's/^...//; s#^apps/node-red/flows/##' <<<"$dirty" | head -3 | paste -sd ' ' | cut -c1-120)$( ((n > 3)) && echo ' …') (W1 covers committed flows: commit them)"
    fi
    case "$rc" in
        0) if [[ -n "$dirty" ]]; then _record WARN "$name" "$out; $dirty"
           else _record OK "$name" "$out${gitnote:+ ($gitnote)}"; fi ;;
        1) _record WARN "$name" "$out (review them; W1 covers only flows from git)${dirty:+; $dirty}" ;;
        2) [[ "$out" == *deploy.sh* ]] || out+=" — ./apps/node-red/deploy.sh puts git's flows back; or commit the change to git"
           _record FAIL "$name" "$out${dirty:+; $dirty}" ;;
        *) _record FAIL "$name" "cannot read Node-RED's flows ($out)${dirty:+; $dirty}" ;;
    esac
}

# =============================================================================
# Check: Node-RED's editor rights are the policy's (IAM 3.3) — read-only
# target: NAMESPACE. adminAuth on, ConfigMap node-red-auth = `cli.py compile node-red`,
# the running settings.js = k8s/node-red/settings.js, the OIDC module installed, and the
# admin API refuses an unauthenticated call from the host (401). IAM_GATES=false changes
# nothing: Node-RED keeps its compiled rights.
# =============================================================================
check_noderedauth() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" auth live want sum tmpl pod ip code problems=()
    auth="$(timeout "$TIMEOUT" $KUBECTL get deployment node-red -n "$ns" \
        -o jsonpath='{range .spec.template.spec.containers[*].env[?(@.name=="NR_ADMIN_AUTH")]}{.value}{end}' 2>/dev/null)" \
        || { _record SKIP "$name" "no Node-RED deployment in $ns"; return; }
    if [[ "$auth" != "on" ]]; then
        _record FAIL "$name" "adminAuth is '${auth:-not set}': any pod and anyone the proxy admits has full editor rights (./deploy-infra.sh)"
        return
    fi
    live="$($KUBECTL get configmap node-red-auth -n "$ns" -o jsonpath='{.data.permissions\.json}' 2>/dev/null)"
    if ! want="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile node-red 2>/dev/null)"; then
        problems+=("cannot compile the editor rights (python3 apps/iam/compiler/cli.py check)")
    elif [[ "$(python3 -c 'import json, sys; print(json.loads(sys.argv[1]) == json.loads(sys.argv[2]))' "$live" "$want" 2>/dev/null)" != True ]]; then
        problems+=("ConfigMap node-red-auth is not the compiled policy (./deploy-infra.sh)")
    fi
    REPO_ROOT="$SCRIPT_DIR"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-node-red.sh"
    sum="$(nr_settings_checksum)"
    tmpl="$($KUBECTL get deployment node-red -n "$ns" -o jsonpath='{.spec.template.metadata.annotations.medcea/settings-checksum}' 2>/dev/null)"
    pod="$($KUBECTL get pods -n "$ns" -l app.kubernetes.io/name=node-red --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.annotations.medcea/settings-checksum}{"\n"}{end}' 2>/dev/null | sort -u)"
    [[ "$tmpl" == "$sum" && "$pod" == "$sum" ]] || problems+=("the running settings.js is not k8s/node-red/settings.js (./deploy-infra.sh)")
    timeout "$TIMEOUT" $KUBECTL exec -n "$ns" deployment/node-red -- \
        test -f /opt/nr-auth/node_modules/passport-openidconnect/package.json 2>/dev/null \
        || problems+=("the OIDC module is missing (init container nr-auth: npm registry?): the editor refuses everyone")
    ip="$($KUBECTL get svc node-red -n "$ns" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
    code="$(curl -s -o /dev/null -m "$TIMEOUT" -w '%{http_code}' "http://${ip}:1880/flows" 2>/dev/null)"
    [[ "$code" == 401 ]] || problems+=("GET /flows without a token answered ${code:-nothing}, not 401")
    if [[ ${#problems[@]} -eq 0 ]]; then
        _record OK "$name" "adminAuth on; editor rights from the access policy; the admin API refuses anonymous calls"
    else
        local IFS=';'; _record FAIL "$name" "${problems[*]}"
    fi
}

# =============================================================================
# Helpers of the Phase 5 checks (iamloaded, iammqtt) — read-only
# _iamlib_meta NS: ConfigMap medcea-iam-lib read once; prints
#   "<routes digest> <mqtt digest> <enforce: true|false|missing> <age in s|?>"
# (each digest the annotation, else the data's digest field, else "-"). The age is the time
# since the ConfigMap's last write: the newest metadata.managedFields[].time (the API server
# stamps it at every write that changes the object; a no-op apply stamps nothing), against
# this host's clock (the API server runs on this host). kubectl (1.21 and later) leaves
# managedFields out of -o json unless --show-managed-fields is given, hence the flag.
# Without a readable managedFields time the age is "?" (never creationTimestamp, which is
# the first install's time on an object updated in place): the callers count it as past
# the 120 s grace and say the write time is unknown. rc 3: no ConfigMap; rc 1: unreadable.
# =============================================================================
_iamlib_meta() {
    local ns="$1" cm rc=0
    cm="$(timeout "$TIMEOUT" $KUBECTL get configmap medcea-iam-lib -n "$ns" -o json --show-managed-fields 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        grep -qiE 'NotFound|not found' <<<"$cm" && return 3
        return 1
    fi
    python3 -c '
import datetime, json, sys
cm, now = json.load(sys.stdin), int(sys.argv[1])
meta, data = cm.get("metadata") or {}, cm.get("data") or {}
ann = meta.get("annotations") or {}
def dig(a, k):
    if ann.get(a):
        return ann[a]
    try:
        return json.loads(data.get(k) or "")["digest"] or "-"
    except Exception:
        return "-"
try:
    s = json.loads(data.get("settings.json") or "")
    enf = "missing" if "enforce" not in s else str(s["enforce"] is True).lower()
except Exception:
    enf = "missing"
def ts(x):
    return datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
times = []
for f in meta.get("managedFields") or []:
    try:
        times.append(ts(f["time"]))
    except Exception:
        pass
age = str(max(0, now - int(max(times)))) if times else "?"
print(dig("medcea/routes-digest", "routes.json"), dig("medcea/mqtt-digest", "mqtt.json"), enf, age)
' "$(date -u +%s)" <<<"$cm" 2>/dev/null || return 1
}

# _iamlib_since AGE: "since N s", or, for an unreadable write time ("?"), words that say so
# (the callers count it as past the 120 s grace).
_iamlib_since() {
    if [[ "$1" =~ ^[0-9]+$ ]]; then echo "since $1 s"; else echo "since an unknown time (no write time readable on the ConfigMap)"; fi
}

# _running_pods NS DEPLOYMENT: the Running pods (not terminating) of the Deployment's
# selector, one name per line. rc 3: no such Deployment; rc 1: unreadable.
_running_pods() {
    local ns="$1" dep="$2" js rc=0 sel pods
    js="$(timeout "$TIMEOUT" $KUBECTL get deployment "$dep" -n "$ns" -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        grep -qiE 'NotFound|not found' <<<"$js" && return 3
        return 1
    fi
    sel="$(python3 -c 'import json, sys
m = ((json.load(sys.stdin).get("spec") or {}).get("selector") or {}).get("matchLabels") or {}
print(",".join("%s=%s" % kv for kv in sorted(m.items())))' <<<"$js" 2>/dev/null)" || return 1
    [[ -n "$sel" ]] || return 1
    pods="$(timeout "$TIMEOUT" $KUBECTL get pods -n "$ns" -l "$sel" -o json 2>/dev/null)" || return 1
    python3 -c 'import json, sys
for p in json.load(sys.stdin).get("items") or []:
    if (p.get("status") or {}).get("phase") == "Running" and not (p.get("metadata") or {}).get("deletionTimestamp"):
        print(p["metadata"]["name"])' <<<"$pods" 2>/dev/null || return 1
}

# =============================================================================
# Check: the controller libraries in the scheduler pod (research sandbox Phase 1) — read-only
# target: NAMESPACE. MPC needs gekko and FLC scikit-fuzzy (with packaging, which 0.5.0 does
# not declare); without them both run as bang-bang (schd/cea/algorithms/, which now report
# each fallback). One bounded `kubectl exec POD -c api -- python3 -c` per Running scheduler
# pod imports both and prints only their versions (or which module is missing). The versions
# wanted are apps/scheduler/requirements-controllers.txt's pins (k8s/scheduler.yaml installs
# it with --require-hashes). WARN, never FAIL (the severity rule: nothing here lets anyone in):
# a library missing, broken or not the pinned version, the pins unreadable, no Running pod, a
# pod that cannot be read. SKIP without the scheduler.
# =============================================================================
check_controllers() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" rc=0 pods pod got gk sf want_gk want_sf reqs
    local warns=() oks=()
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    reqs="$SCRIPT_DIR/apps/scheduler/requirements-controllers.txt"
    want_gk="$(sed -n 's/^gekko==\([^ ]*\) .*/\1/p' "$reqs" 2>/dev/null | head -n1)"
    want_sf="$(sed -n 's/^scikit-fuzzy==\([^ ]*\) .*/\1/p' "$reqs" 2>/dev/null | head -n1)"
    pods="$(_running_pods "$ns" scheduler)" || rc=$?
    if [[ $rc -eq 3 ]]; then _record SKIP "$name" "the scheduler is not deployed (./apps/scheduler/deploy.sh)"; return
    elif [[ $rc -ne 0 ]]; then _record WARN "$name" "cannot read the scheduler pods in $ns"; return
    elif [[ -z "$pods" ]]; then _record WARN "$name" "no Running scheduler pod: its controller libraries cannot be read"; return
    fi
    if [[ -z "$want_gk" || -z "$want_sf" ]]; then
        warns+=("cannot read the pinned versions in apps/scheduler/requirements-controllers.txt")
    fi
    local probe='import importlib, re
def ver(mod, subs=()):
    try:
        m = importlib.import_module(mod)
        for s in subs:
            importlib.import_module(s)
    except ModuleNotFoundError as e:
        return "missing:" + re.sub(r"[^A-Za-z0-9._-]", "", str(e.name or mod))[:40]
    except Exception as e:
        return "broken:" + type(e).__name__
    return re.sub(r"[^A-Za-z0-9.+_-]", "", str(getattr(m, "__version__", "") or "unknown"))[:40]
print(ver("gekko"), ver("skfuzzy", ("skfuzzy.control",)))'
    for pod in $pods; do
        got="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" "$pod" -c api -- python3 -c "$probe" 2>/dev/null | tail -n1)" || got=""
        gk=""; sf=""; read -r gk sf <<<"$got"
        if [[ -z "$gk" || -z "$sf" ]]; then warns+=("cannot read the controller libraries in pod $pod"); continue; fi
        local lib v want label fb
        for lib in gekko:MPC skfuzzy:FLC; do
            label="${lib%%:*}"; fb="${lib##*:}"
            if [[ "$label" == gekko ]]; then v="$gk"; want="$want_gk"; else v="$sf"; want="$want_sf"; fi
            case "$v" in
                missing:*)
                    if [[ "${v#missing:}" == "$label" ]]; then
                        warns+=("pod $pod: $label is not installed: $fb runs as bang-bang (./apps/scheduler/deploy.sh)")
                    else
                        warns+=("pod $pod: $label cannot import ${v#missing:}: $fb runs as bang-bang (./apps/scheduler/deploy.sh)")
                    fi ;;
                broken:*) warns+=("pod $pod: $label fails to import (${v#broken:}): $fb runs as bang-bang") ;;
                *)  if [[ -n "$want" && "$v" != "$want" ]]; then
                        warns+=("pod $pod: $label $v is not the pinned $want (./apps/scheduler/deploy.sh)")
                    fi ;;
            esac
        done
        oks+=("pod $pod: gekko $gk, scikit-fuzzy $sf")
    done
    if ((${#warns[@]})); then
        local IFS=';'; _record WARN "$name" "${warns[*]}"
    else
        local IFS=';'; _record OK "$name" "${oks[*]} (the pinned versions)"
    fi
}

# =============================================================================
# Check: every service pod loads the route table the ConfigMap holds (Phase 5, G5) — read-only
# target: NAMESPACE. For each Running pod of the six route-checking services (apply.sh's
# wait_routes list; NotFound counts the service as not deployed), a read-only
# `kubectl exec POD -c CTR -- python3 -c` prints only /iam/routes.json's digest and
# applied_version ("missing" without the file). FAIL: a digest that is not ConfigMap
# medcea-iam-lib's medcea/routes-digest 120 s or more after its last write (_iamlib_meta),
# or no file where the service enforces (access, dbmgmt and iam-api always; the others while
# settings.json's enforce is true). WARN: a differing digest inside the 120 s, a missing file
# otherwise, a pod or service that cannot be read. applied_version is unhashed and only
# reported: the digest is the proof (an older applied_version with the current digest is OK).
# SKIP without kubectl or the ConfigMap (iamartefacts reports it).
# =============================================================================
check_iamloaded() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" meta rc=0 want enforce age dc dep ctr pods pod got dig ver
    local probs=() warns=() absent=() norun=() services=0 n=0 enforcing fix
    local -A VERS=()
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    meta="$(_iamlib_meta "$ns")" || rc=$?
    if [[ $rc -eq 3 ]]; then
        _record SKIP "$name" "no ConfigMap medcea-iam-lib in $ns yet (./deploy-infra.sh)"; return
    elif [[ $rc -ne 0 || -z "$meta" ]]; then
        _record WARN "$name" "cannot read ConfigMap medcea-iam-lib in $ns: the pods' route tables are not compared"; return
    fi
    read -r want _ enforce age <<<"$meta"
    [[ "$enforce" == missing ]] && enforce="${IAM_ENFORCE:-false}"   # iamenforce FAILs a missing key
    local probe='import json
try:
    d = json.load(open("/iam/routes.json"))
except FileNotFoundError:
    print("missing")
except Exception:
    print("unreadable")
else:
    print(d.get("digest") or "-", d.get("applied_version"))'
    for dc in scheduler:api:scheduler monitor:api:monitor dbmgmt:api:frontend config-ui:recipe-fileserver:frontend \
              access:api:access iam-api:iam-api:iam; do
        IFS=: read -r dep ctr fix <<<"$dc"
        fix="./apps/$fix/deploy.sh"
        rc=0; pods="$(_running_pods "$ns" "$dep")" || rc=$?
        if [[ $rc -eq 3 ]]; then absent+=("$dep"); continue
        elif [[ $rc -ne 0 ]]; then warns+=("cannot read the pods of $dep"); continue
        elif [[ -z "$pods" ]]; then norun+=("$dep"); continue
        fi
        services=$((services + 1))
        enforcing=false
        [[ "$dep" == access || "$dep" == dbmgmt || "$dep" == iam-api || "$enforce" == true ]] && enforcing=true
        for pod in $pods; do
            n=$((n + 1))
            got="$(timeout "$TIMEOUT" $KUBECTL exec -n "$ns" "$pod" -c "$ctr" -- python3 -c "$probe" 2>/dev/null | tail -n1)" || got=""
            read -r dig ver <<<"$got"
            if [[ -z "$dig" ]]; then
                warns+=("cannot read /iam/routes.json in pod $pod")
            elif [[ "$dig" == missing ]]; then
                if $enforcing; then probs+=("pod $pod has no /iam/routes.json while $dep enforces: it refuses every request ($fix)")
                else warns+=("pod $pod has no /iam/routes.json ($fix)"); fi
            elif [[ "$dig" == unreadable || "$dig" == "-" ]]; then
                if $enforcing; then probs+=("pod $pod cannot parse /iam/routes.json while $dep enforces ($fix)")
                else warns+=("pod $pod cannot parse /iam/routes.json ($fix)"); fi
            elif [[ "$dig" != "$want" ]]; then
                if [[ "$age" =~ ^[0-9]+$ ]] && (( age < 120 )); then
                    warns+=("pod $pod loads routes ${dig:0:12}, the ConfigMap holds ${want:0:12} since ${age} s (the kubelet syncs within 120 s)")
                else
                    probs+=("pod $pod loads routes ${dig:0:12}, the ConfigMap holds ${want:0:12} $(_iamlib_since "$age") ($fix)")
                fi
            else
                VERS[${ver:-None}]=1
            fi
        done
    done
    # research Phase 4a (stage 7a, R37): the copies of the route table in the two agent zones. A zone without
    # the Deployment (policy without the zone, not installed) adds nothing; a pod that answers another digest
    # is a stale route table in a service that always enforces.
    local zdc zns zdep zctr zk
    # research Phase 4e: the console (research-agents, container console) once ./apps/research-console/deploy.sh ran
    for zdc in research-gw:research-session:research-session research-agents:research-orchestrator:research-orchestrator \
               research-agents:research-console:console; do
        IFS=: read -r zk zdep zctr <<<"$zdc"
        zns="$(NAMESPACE="$ns" bash -c 'source "$1/infra/lib-policy-tools.sh"; zone_namespace "$2"' _ "$SCRIPT_DIR" "$zk" 2>/dev/null)" || continue
        [[ -n "$zns" ]] || continue
        rc=0; pods="$(_running_pods "$zns" "$zdep")" || rc=$?
        [[ $rc -eq 0 && -n "$pods" ]] || continue
        services=$((services + 1))
        for pod in $pods; do
            n=$((n + 1))
            got="$(timeout "$TIMEOUT" $KUBECTL exec -n "$zns" "$pod" -c "$zctr" -- python3 -c "$probe" 2>/dev/null | tail -n1)" || got=""
            read -r dig ver <<<"$got"
            if [[ -z "$dig" ]]; then warns+=("cannot read /iam/routes.json in pod $pod ($zns)")
            elif [[ "$dig" == missing || "$dig" == unreadable || "$dig" == "-" ]]; then
                probs+=("pod $pod ($zns) has no usable /iam/routes.json: it refuses every request (./apps/research-agents/deploy.sh)")
            elif [[ "$dig" != "$want" ]]; then
                if [[ "$age" =~ ^[0-9]+$ ]] && (( age < 120 )); then
                    warns+=("pod $pod ($zns) loads routes ${dig:0:12}, the platform's ConfigMap holds ${want:0:12} since ${age} s")
                else
                    probs+=("pod $pod ($zns) loads routes ${dig:0:12}, the platform's ConfigMap holds ${want:0:12}: ./deploy-infra.sh or ./infra/deploy-policy.sh refreshes the copy")
                fi
            fi
        done
    done
    local tail_=""
    ((${#absent[@]})) && tail_+="; ${#absent[@]} not deployed (${absent[*]})"
    ((${#norun[@]})) && tail_+="; no Running pod: ${norun[*]}"
    if ((${#probs[@]})); then
        local IFS=';'; _record FAIL "$name" "${probs[*]}${warns:+;${warns[*]}}"
    elif ((${#warns[@]})); then
        local IFS=';'; _record WARN "$name" "${warns[*]}"
    elif (( n == 0 )); then
        _record OK "$name" "no route-checking service runs a pod${tail_}"
    else
        _record OK "$name" "$n pods in $services services load routes ${want:0:12} (applied_version $(printf '%s\n' "${!VERS[@]}" | sort | paste -sd ',' -), information only)${tail_}"
    fi
}

# =============================================================================
# Check: the realm's signing keys and Secret medcea-jwks agree (Phase 5, G3) — read-only
# target: NAMESPACE. Always on, whatever IAM_POSTGREST_JWT says: six services verify tokens
# against /jwks/jwks.json and config-api against jwks-sig.json. The Secret (public keys only)
# reaches python on stdin; only key ids are printed. The realm's certs come from the keycloak
# Service (curl -m TIMEOUT). FAIL: the Secret or a key missing, unparseable or without an
# RS256 signing key; jwks-sig.json != infra/jwks-sig.py signing_keys(jwks.json); a key id of
# the Secret the realm no longer publishes; a realm RS256 signing key id the Secret lacks
# (tokens signed with it are refused everywhere). WARN: the realm does not answer (the
# Keycloak checks FAIL that; the Secret is not blamed), the Secret unreadable. SKIP: no kubectl.
# =============================================================================
check_jwks() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" sec rc=0 ip realm="" out lvl msg worst="" details=() ok=""
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    sec="$(timeout "$TIMEOUT" $KUBECTL get secret medcea-jwks -n "$ns" -o json 2>/dev/null)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if timeout "$TIMEOUT" $KUBECTL get secret medcea-jwks -n "$ns" -o name 2>&1 | grep -qiE 'NotFound|not found'; then
            _record FAIL "$name" "Secret medcea-jwks is missing in $ns: no service can verify a token (./deploy-infra.sh)"
        else
            _record WARN "$name" "cannot read Secret medcea-jwks in $ns"
        fi
        return
    fi
    ip="$(timeout "$TIMEOUT" $KUBECTL get svc keycloak -n "$ns" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)" || ip=""
    [[ -n "$ip" ]] && realm="$(curl -s -m "$TIMEOUT" "http://${ip}/realms/${KEYCLOAK_REALM:-medcea}/protocol/openid-connect/certs" 2>/dev/null)"
    out="$(REALM="$realm" python3 -c '
import base64, importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("jwks_sig", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
try:
    data = json.load(sys.stdin).get("data") or {}
except Exception:
    print("WARN|cannot parse Secret medcea-jwks"); sys.exit()
def key(n):
    if n not in data:
        return "absent"
    try:
        d = json.loads(base64.b64decode(data[n]))
        return d if isinstance(d, dict) and isinstance(d.get("keys"), list) else None
    except Exception:
        return None
full, sig = key("jwks.json"), key("jwks-sig.json")
bad = False
for n, d in (("jwks.json", full), ("jwks-sig.json", sig)):
    if d == "absent":
        print("FAIL|Secret medcea-jwks has no %s (./deploy-infra.sh)" % n); bad = True
    elif d is None:
        print("FAIL|%s in Secret medcea-jwks is not a JWKS (./deploy-infra.sh)" % n); bad = True
    elif not mod.signing_keys(d):
        print("FAIL|%s in Secret medcea-jwks holds no RS256 signing key: no token verifies (./deploy-infra.sh)" % n); bad = True
if bad:
    sys.exit()
if {"keys": mod.signing_keys(full)} != sig:
    print("FAIL|jwks-sig.json is not the RS256 signing keys of jwks.json (infra/jwks-sig.py): config-api and the services verify against different keys (./deploy-infra.sh)")
k12 = lambda xs: ", ".join(str(x)[:12] for x in xs)
ours_sig = sorted({k["kid"] for k in mod.signing_keys(sig)})
try:
    live = json.loads(os.environ.get("REALM") or "")
    assert isinstance(live, dict) and isinstance(live.get("keys"), list)
except Exception:
    print("WARN|the realm %s did not answer on the keycloak Service: its key ids are not compared (the Keycloak checks report the realm)" % sys.argv[2])
    sys.exit()
pub = {k.get("kid") for k in live["keys"] if isinstance(k, dict) and k.get("kid")}
ours = {k.get("kid") for d in (full, sig) for k in d["keys"] if isinstance(k, dict) and k.get("kid")}
gone = sorted(ours - pub)
new = sorted({k["kid"] for k in mod.signing_keys(live)} - set(ours_sig))
if gone:
    print("FAIL|Secret medcea-jwks holds key id(s) the realm no longer publishes: %s (./deploy-infra.sh)" % k12(gone))
if new:
    print("FAIL|the realm signs with key id(s) Secret medcea-jwks lacks: %s, every service refuses those tokens (./deploy-infra.sh)" % k12(new))
print("OK|%d signing key(s) (%s) equal the realm%s; jwks-sig.json = jwks.json%ss signing keys" % (len(ours_sig), k12(ours_sig), chr(39) + "s", chr(39)))
' "$SCRIPT_DIR/infra/jwks-sig.py" "${KEYCLOAK_REALM:-medcea}" <<<"$sec" 2>&1)" || out="FAIL|cannot compare the keys: $(tail -n1 <<<"$out" | cut -c1-120)"
    while IFS='|' read -r lvl msg; do
        case "$lvl" in
            FAIL) worst=FAIL; details+=("$msg") ;;
            WARN) [[ "$worst" == FAIL ]] || worst=WARN; details+=("$msg") ;;
            OK)   ok="$msg" ;;
        esac
    done <<<"$out"
    if [[ -n "$worst" ]]; then
        local IFS=';'; _record "$worst" "$name" "${details[*]}"
    elif [[ -n "$ok" ]]; then
        _record OK "$name" "$ok"
    else
        _record FAIL "$name" "cannot compare the keys: $(tail -n1 <<<"$out" | cut -c1-120)"
    fi
}

# =============================================================================
# Check: the Keycloak clients' scopes and mappers (Phase 5, G2) — read-only
# target: REALM. Keycloak's own database, as tests/iam-hosts.sh reads it: one psql as
# postgres in rdbms-postgresql-0, -d keycloak, PGOPTIONS default_transaction_read_only=on,
# the SQL on stdin, the password read inside the pod; no admin token, no port-forward, no
# lock. The clients are infra/lib-keycloak-clients.sh's (deploy-infra.sh's scope loop).
# FAIL: scope groups or medcea-identity absent from the realm; groups without its
# realm-role mapper (claim groups, access token); medcea-identity without the audience
# mapper (medcea-api, access token) or the person_id mapper; and on a client whose tokens
# reach a platform API (KC_API_CLIENTS): the client missing, or either scope not attached.
# WARN: the same on a tool-only client; a scope attached as optional only; full_scope_allowed
# false; the audience also in the ID token; a client-level mapper writing groups, person_id
# or aud (matched by type and claim, not by name); the database unreadable.
# =============================================================================
check_kcscopes() {
    local name="$1" realm="${2:-${KEYCLOAK_REALM:-medcea}}" ns="${NAMESPACE:-medcea}" out lvl msg worst="" details=() ok=""
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/infra/lib-keycloak-clients.sh" || { _record FAIL "$name" "cannot read infra/lib-keycloak-clients.sh"; return; }
    # Clients that exist only while the applied policy names them as a token_client
    # (KC_POLICY_TOKEN_CLIENTS, research sandbox Phase 2b): named → today's rules; not named
    # → retired: present and enabled FAILs, absent or disabled is OK, its scopes unchecked.
    local c rc retired=() unsure=()
    if [[ -n "${KC_POLICY_TOKEN_CLIENTS+x}" ]]; then
        for c in "${KC_POLICY_TOKEN_CLIENTS[@]}"; do
            rc=0
            python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" has-token-client "$c" >/dev/null 2>&1 || rc=$?
            case $rc in
                0) ;;
                1) retired+=("$c") ;;
                *) unsure+=("$c") ;;
            esac
        done
    fi
    # The research hosts' clients (KC_RESEARCH_HOST_CLIENTS, research Phase 4e): research-console exists only
    # while the applied policy has RESEARCH_CONSOLE_DOMAIN (cli.py has-host): then groups and medcea-research
    # default, never medcea-identity (one audience); otherwise present and enabled FAILs.
    local hostrc=0 rhosts="${KC_RESEARCH_HOST_CLIENTS[*]:-}"
    if [[ -n "$rhosts" ]]; then
        python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" has-host RESEARCH_CONSOLE_DOMAIN >/dev/null 2>&1 || hostrc=$?
    fi
    out="$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$ns" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d keycloak -tA -v realm="$0" -v clients="$1"' \
        "$realm" "${KC_SCOPE_CLIENTS[*]}${rhosts:+ $rhosts}" 2>/dev/null <<'SQL'
SELECT coalesce((
  SELECT json_build_object(
    'scopes', (SELECT coalesce(json_object_agg(s.name, json_build_object(
                  'mappers', (SELECT coalesce(json_agg(json_build_object('type', m.protocol_mapper_name, 'name', m.name,
                                  'config', (SELECT coalesce(json_object_agg(pc.name, pc.value), '{}'::json)
                                               FROM protocol_mapper_config pc WHERE pc.protocol_mapper_id = m.id))), '[]'::json)
                                FROM protocol_mapper m WHERE m.client_scope_id = s.id))), '{}'::json)
                 FROM client_scope s WHERE s.realm_id = r.id AND s.name IN ('groups', 'medcea-identity')),
    'clients', (SELECT coalesce(json_object_agg(c.client_id, json_build_object(
                  'enabled', c.enabled,
                  'full_scope', c.full_scope_allowed,
                  'default', (SELECT coalesce(json_agg(s.name), '[]'::json) FROM client_scope_client d
                                JOIN client_scope s ON s.id = d.scope_id
                               WHERE d.client_id = c.id AND d.default_scope AND s.name IN ('groups', 'medcea-identity', 'medcea-research')),
                  'optional', (SELECT coalesce(json_agg(s.name), '[]'::json) FROM client_scope_client d
                                 JOIN client_scope s ON s.id = d.scope_id
                                WHERE d.client_id = c.id AND NOT d.default_scope AND s.name IN ('groups', 'medcea-identity', 'medcea-research')),
                  'mappers', (SELECT coalesce(json_agg(json_build_object('type', m.protocol_mapper_name, 'name', m.name,
                                  'config', (SELECT coalesce(json_object_agg(pc.name, pc.value), '{}'::json)
                                               FROM protocol_mapper_config pc WHERE pc.protocol_mapper_id = m.id))), '[]'::json)
                                FROM protocol_mapper m WHERE m.client_id = c.id))), '{}'::json)
                  FROM client c WHERE c.realm_id = r.id
                   AND c.client_id = ANY (pg_catalog.string_to_array(:'clients', ' '))))
    FROM realm r WHERE r.name = :'realm'), 'null'::json);
SQL
)" || out=""
    out="$(python3 -c '
import json, sys
try:
    doc = json.loads(sys.stdin.read().strip().splitlines()[-1])
except Exception:
    print("WARN|cannot read Keycloak database keycloak: the client scopes are not checked"); sys.exit()
realm, wanted, api = sys.argv[1], sys.argv[2].split(), set(sys.argv[3].split())
retired, unsure = sys.argv[4].split(), sys.argv[5].split()
rhosts, hostrc = sys.argv[6].split(), sys.argv[7]
wanted = [c for c in wanted if c not in retired]
api -= set(retired)
if doc is None:
    print("FAIL|realm %s is not in Keycloak database keycloak (./deploy-infra.sh)" % realm); sys.exit()
cfg = lambda m: m.get("config") or {}
def has(mappers, pred):
    return any(pred(m) for m in mappers or [])
scopes = doc.get("scopes") or {}
for s in ("groups", "medcea-identity"):
    if s not in scopes:
        print("FAIL|client scope %s is not in realm %s: every client asking for it gets invalid_scope (./deploy-infra.sh)" % (s, realm))
g = (scopes.get("groups") or {}).get("mappers")
if "groups" in scopes and not has(g, lambda m: m.get("type") == "oidc-usermodel-realm-role-mapper"
                                   and cfg(m).get("claim.name") == "groups" and cfg(m).get("access.token.claim") == "true"):
    print("FAIL|scope groups has no realm-role mapper to claim groups in the access token: no gate admits anyone by role (./deploy-infra.sh)")
i = (scopes.get("medcea-identity") or {}).get("mappers")
aud = lambda m: m.get("type") == "oidc-audience-mapper" and cfg(m).get("included.custom.audience") == "medcea-api"
if "medcea-identity" in scopes:
    if not has(i, lambda m: aud(m) and cfg(m).get("access.token.claim") == "true"):
        print("FAIL|scope medcea-identity has no medcea-api audience mapper for the access token: every service refuses the tokens (./deploy-infra.sh)")
    elif has(i, lambda m: aud(m) and cfg(m).get("id.token.claim") == "true"):
        print("WARN|the medcea-api audience is also in the ID token (oauth2-proxy verifies the ID token audience as the client)")
    if not has(i, lambda m: m.get("type") == "oidc-usermodel-attribute-mapper" and cfg(m).get("claim.name") == "person_id"
               and cfg(m).get("user.attribute") == "person_id" and cfg(m).get("access.token.claim") == "true"):
        print("FAIL|scope medcea-identity has no person_id mapper for the access token: the services cannot tell the person (./deploy-infra.sh)")
clients = doc.get("clients") or {}
miss = {"FAIL": [], "WARN": []}
noscope = {}
optional, fullscope, own = [], [], []
for c in wanted:
    lvl = "FAIL" if c in api else "WARN"
    if c not in clients:
        miss[lvl].append(c); continue
    d = clients[c]
    for s in ("groups", "medcea-identity"):
        if s in (d.get("default") or []):
            continue
        if s in (d.get("optional") or []):
            optional.append("%s/%s" % (c, s))
        else:
            noscope.setdefault((lvl, s), []).append(c)
    if d.get("full_scope") is False:
        fullscope.append(c)
    for m in d.get("mappers") or []:
        claim = cfg(m).get("claim.name")
        if m.get("type") == "oidc-audience-mapper" or claim in ("groups", "person_id", "aud"):
            own.append("%s (%s)" % (c, claim or "aud"))
for lvl in ("FAIL", "WARN"):
    if miss[lvl]:
        print("%s|client(s) missing in realm %s: %s (./deploy-infra.sh)" % (lvl, realm, ", ".join(miss[lvl])))
    for s in ("groups", "medcea-identity"):
        if noscope.get((lvl, s)):
            print("%s|%s is not a default scope of %s (./deploy-infra.sh)" % (lvl, s, ", ".join(noscope[(lvl, s)])))
if optional:
    print("WARN|attached as optional scope only: %s (./deploy-infra.sh makes them default)" % ", ".join(optional))
if fullscope:
    print("WARN|full_scope_allowed is false on %s: the groups claim holds only the client role mappings" % ", ".join(fullscope))
if own:
    print("WARN|client-level mapper(s) writing a platform claim: %s; the scopes are its one source" % ", ".join(own))
for c in unsure:
    print("WARN|cannot tell whether the applied access policy still names %s as a token client (python3 apps/iam/compiler/cli.py check): checked as named" % c)
gone = []
for c in retired:
    if c in clients and clients[c].get("enabled") is not False:
        print("FAIL|client %s is enabled, yet the applied access policy names it as no token client: its tokens still reach the platform APIs that admit it (./deploy-infra.sh disables it)" % c)
    else:
        gone.append("%s (%s)" % (c, "disabled" if c in clients else "absent"))
rok = []
for c in rhosts:
    d = clients.get(c)
    if hostrc == "0":
        if d is None:
            print("FAIL|client %s is missing in realm %s, yet the applied access policy has its host: nobody can sign in to it (./deploy-infra.sh)" % (c, realm)); continue
        if d.get("enabled") is False:
            print("FAIL|client %s is disabled, yet the applied access policy has its host (./deploy-infra.sh)" % c)
        for s in ("groups", "medcea-research"):
            if s not in (d.get("default") or []):
                print("FAIL|%s is not a default scope of %s: the services of its host refuse its tokens (./deploy-infra.sh)" % (s, c))
        if "medcea-identity" in (d.get("default") or []) + (d.get("optional") or []):
            print("FAIL|%s carries medcea-identity: its tokens would carry two audiences, the research host has one (./deploy-infra.sh removes it)" % c)
        rok.append(c)
    elif hostrc == "1":
        if d is not None and d.get("enabled") is not False:
            print("FAIL|client %s is enabled, yet the applied access policy has no host for it (./deploy-infra.sh disables it)" % c)
    else:
        print("WARN|cannot tell whether the applied access policy has the host of %s (python3 apps/iam/compiler/cli.py check)" % c)
n = len([c for c in wanted if c in clients])
print("OK|%d clients: groups and medcea-identity default on each (%d of them reach a platform API)%s%s" % (
    n, len([c for c in wanted if c in clients and c in api]),
    "; retired by the access policy: " + ", ".join(gone) if gone else "",
    "; research host client(s) %s: groups and medcea-research only" % ", ".join(rok) if rok else ""))
' "$realm" "${KC_SCOPE_CLIENTS[*]}" "${KC_API_CLIENTS[*]}" "${retired[*]}" "${unsure[*]}" "$rhosts" "$hostrc" <<<"${out:-}" 2>&1)" \
        || out="FAIL|cannot judge the client scopes: $(tail -n1 <<<"$out" | cut -c1-120)"
    while IFS='|' read -r lvl msg; do
        case "$lvl" in
            FAIL) worst=FAIL; details+=("$msg") ;;
            WARN) [[ "$worst" == FAIL ]] || worst=WARN; details+=("$msg") ;;
            OK)   ok="$msg" ;;
        esac
    done <<<"$out"
    if [[ -n "$worst" ]]; then
        local IFS=';'; _record "$worst" "$name" "${details[*]}"
    else
        _record OK "$name" "$ok"
    fi
}

# =============================================================================
# Check: the application pods' NetworkPolicies follow IAM_NETPOL (Phase 5, G10) — read-only
# target: NAMESPACE. The labelled policies (medcea/iam-netpol=true) by name against
# `cli.py compile netpol` (names only: a placeholder node address, as apply_check's
# NETPOL_ARGS). true: a compiled one missing FAILs (its pod admits any caller), a labelled
# one not compiled WARNs (./deploy-infra.sh deletes it); false: WARN, naming any that remain.
# SKIP without kubectl.
# =============================================================================
check_iamnetpol() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" live rc=0 want missing extra
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    live="$(timeout "$TIMEOUT" $KUBECTL get netpol -n "$ns" -l medcea/iam-netpol=true -o jsonpath='{.items[*].metadata.name}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read the NetworkPolicies in $ns: $(tail -n1 <<<"$live" | cut -c1-120)"; return
    fi
    live="$(tr ' ' '\n' <<<"$live" | grep . | sort -u)"
    if [[ "${IAM_NETPOL:-true}" == false ]]; then
        if [[ -n "$live" ]]; then
            _record WARN "$name" "IAM_NETPOL=false, yet $(grep -c . <<<"$live") labelled NetworkPolicies remain: $(paste -sd ' ' <<<"$live" | cut -c1-120) (./deploy-infra.sh deletes them)"
        else
            _record WARN "$name" "IAM_NETPOL=false: the application pods accept connections from anywhere in the cluster"
        fi
        return
    fi
    want="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile netpol --namespace "$ns" --node-ip 192.0.2.1 2>/dev/null \
        | python3 -c 'import json, sys; print("\n".join(sorted(i["metadata"]["name"] for i in json.load(sys.stdin)["items"])))' 2>/dev/null)"
    if [[ -z "$want" ]]; then
        _record FAIL "$name" "the applied policy compiles no NetworkPolicy (python3 apps/iam/compiler/cli.py check)"; return
    fi
    missing="$(comm -23 <(printf '%s\n' "$want") <(printf '%s\n' "$live") | paste -sd ' ')"
    extra="$(comm -13 <(printf '%s\n' "$want") <(printf '%s\n' "$live" | grep .) | paste -sd ' ')"
    if [[ -n "$missing" ]]; then
        _record FAIL "$name" "IAM_NETPOL=true, missing: $missing: those pods admit any caller in the cluster (./deploy-infra.sh)${extra:+; not compiled: $extra}"
    elif [[ -n "$extra" ]]; then
        _record WARN "$name" "labelled NetworkPolicies the policy no longer compiles: $extra (./deploy-infra.sh deletes them)"
    else
        _record OK "$name" "$(grep -c . <<<"$want") NetworkPolicies of the application pods, the compiled set"
    fi
}

# =============================================================================
# Check: the research zone's NetworkPolicies (research sandbox Phase 2a) — read-only
# target: NAMESPACE (the platform namespace; the research namespace is RESEARCH_NAMESPACE,
# else NAMESPACE-research). The labelled policies (medcea/rs-netpol=true) in the research
# namespace against `cli.py compile netpol --zone research` with the node's addresses (the
# jsonpath pa_netpol reads), compared as {name: spec} in canonical JSON, the default deny
# and the DNS exception included. A compiled policy missing or with another spec FAILs (the
# zone admits more than the policy compiles). Every NetworkPolicy of the research namespace
# is read, labelled or not: policies are additive, so any one not in the compiled set (the
# Helm chart's own allow-all, a leftover labelled one, one made by hand) widens the zone
# past its default deny and FAILs too, named. SKIP
# without kubectl, while the sandbox is switched off and has no namespace, and while the
# applied policy has no research zone (commit A, before the skeleton version); WARN when
# switched off with the namespace left, when enabled without it, and when anything cannot
# be read.
# =============================================================================
check_rsnetpol() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" rns out rc=0 exists live want ip ips=() res kind names
    local fails=() count=""
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    rns="${RESEARCH_NAMESPACE:-${ns}-research}"
    out="$(timeout "$TIMEOUT" $KUBECTL get namespace "$rns" -o name 2>&1)" || rc=$?
    if [[ $rc -eq 0 ]]; then
        exists=yes
    elif grep -q 'NotFound' <<<"$out"; then
        exists=no
    else
        _record WARN "$name" "cannot read namespace $rns: $(tail -n1 <<<"$out" | cut -c1-120)"; return
    fi
    if [[ "${RESEARCH_ENABLED:-false}" != true ]]; then
        if [[ $exists == yes ]]; then
            _record WARN "$name" "RESEARCH_ENABLED is not true, yet namespace $rns exists: set RESEARCH_ENABLED=true and run ./deploy-infra.sh, or remove it with microk8s kubectl delete namespace $rns (this deletes the research database)"
        else
            _record SKIP "$name" "the research sandbox is switched off (RESEARCH_ENABLED is not true)"
        fi
        return
    fi
    rc=0
    python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" has-zone research >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 1 ]]; then
        _record SKIP "$name" "the applied access policy has no research zone yet"; return
    elif [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot tell whether the applied access policy has a research zone (python3 apps/iam/compiler/cli.py check)"; return
    fi
    if [[ $exists == no ]]; then
        _record WARN "$name" "RESEARCH_ENABLED=true, but namespace $rns does not exist (./deploy-infra.sh)"; return
    fi
    rc=0
    live="$(timeout "$TIMEOUT" $KUBECTL get netpol -n "$rns" -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read the NetworkPolicies in $rns: $(tail -n1 <<<"$live" | cut -c1-120)"; return
    fi
    rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="InternalIP")]}{.address}{" "}{end}{.metadata.annotations.projectcalico\.org/IPv4Address}{" "}{.metadata.annotations.projectcalico\.org/IPv4VXLANTunnelAddr}{" "}{.metadata.annotations.projectcalico\.org/IPv4IPIPTunnelAddr}{" "}{end}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read the node addresses: $(tail -n1 <<<"$out" | cut -c1-120)"; return
    fi
    for ip in $out; do ips+=(--node-ip "${ip%/*}"); done
    local _other=()
    mapfile -t _other < <(NAMESPACE="$ns" RESEARCH_NAMESPACE="$rns" SCRIPT_DIR="$SCRIPT_DIR" bash -c 'source "$SCRIPT_DIR/infra/lib-policy-tools.sh"; zone_other_args research' 2>/dev/null)
    if ! want="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile netpol --zone research --namespace "$rns" \
            --platform-namespace "$ns" "${_other[@]}" "${ips[@]}" 2>/dev/null)"; then
        _record WARN "$name" "the research NetworkPolicies do not compile (python3 apps/iam/compiler/cli.py check)"; return
    fi
    res="$(WANT="$want" python3 -c '
import json, os, sys
try:
    items = json.load(sys.stdin).get("items") or []
    live = {i["metadata"]["name"]: i.get("spec") for i in items}
    labelled = {i["metadata"]["name"] for i in items
                if (i["metadata"].get("labels") or {}).get("medcea/rs-netpol") == "true"}
    want = {i["metadata"]["name"]: i.get("spec") for i in json.loads(os.environ["WANT"]).get("items") or []}
except Exception:
    print("error|")
    sys.exit(0)
# the API server drops an empty ingress/egress list (omitempty): a send-only pod compiles "ingress": []
canon = lambda s: json.dumps({f: v for f, v in (s or {}).items() if not (f in ("ingress", "egress") and v == [])}, sort_keys=True)
print("count|%d" % len(want))
print("missing|" + " ".join(sorted(n for n in want if n not in live)))
print("differ|" + " ".join(sorted(n for n in want if n in live and canon(live[n]) != canon(want[n]))))
print("extra|" + " ".join(sorted(n for n in live if n not in want and n in labelled)))
print("foreign|" + " ".join(sorted(n for n in live if n not in want and n not in labelled)))' <<<"$live" 2>/dev/null)"
    while IFS='|' read -r kind names; do
        case "$kind" in
            count)   count="$names" ;;
            missing) [[ -n "$names" ]] && fails+=("missing: $names (./deploy-infra.sh)") ;;
            differ)  [[ -n "$names" ]] && fails+=("spec differs: $names (./deploy-infra.sh)") ;;
            extra)   [[ -n "$names" ]] && fails+=("labelled but not compiled: $names (./deploy-infra.sh deletes them)") ;;
            foreign) [[ -n "$names" ]] && fails+=("not the zone's, no medcea/rs-netpol=true label: $names, which widens the zone past its default deny (microk8s kubectl delete networkpolicy -n $rns <name>)") ;;
            error)   _record WARN "$name" "cannot parse the live or compiled research NetworkPolicies"; return ;;
        esac
    done <<<"$res"
    if [[ ! "$count" =~ ^[0-9]+$ ]]; then
        _record WARN "$name" "cannot compare the research NetworkPolicies with the compile"; return
    fi
    if (( count == 0 )); then
        _record WARN "$name" "the applied policy has a research zone but compiles no research NetworkPolicy (python3 apps/iam/compiler/cli.py check)"; return
    fi
    if (( ${#fails[@]} )); then
        local joined f
        joined="${fails[0]}"
        for f in "${fails[@]:1}"; do joined+="; $f"; done
        _record FAIL "$name" "the research zone admits more than the policy compiles: $joined"
    else
        _record OK "$name" "$count research NetworkPolicies, the compiled set (default deny included)"
    fi
}

# =============================================================================
# Check: the AI workbench's hub users are enabled realm accounts (research sandbox Phase 2b)
# — read-only, WARN only. target: NAMESPACE. The hub's namespace is workbench_namespace's
# (infra/lib-policy-tools.sh). One kubectl exec into the Running hub pod (container hub):
# python3 reads /srv/jupyterhub/jupyterhub.sqlite with mode=ro and prints the user names
# only; the realm's enabled accounts from Keycloak's database (read-only psql in
# rdbms-postgresql-0, as kcscopes). A hub user without an enabled account WARNs, named:
# offboarding is removing the hub user too (/hub/admin), since a person's own hub API
# tokens outlive the account. SKIP while WORKBENCH_ENABLED is not true or no hub runs;
# WARN when anything cannot be read. Never FAIL.
# =============================================================================
check_wbaccounts() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" realm="${KEYCLOAK_REALM:-medcea}" wbns pod out rc=0 hub kc
    if [[ "${WORKBENCH_ENABLED:-true}" != "true" ]]; then
        _record SKIP "$name" "WORKBENCH_ENABLED is not true"; return
    fi
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    if ! REPO_ROOT="$SCRIPT_DIR" source "$SCRIPT_DIR/infra/lib-policy-tools.sh" \
            || ! wbns="$(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" workbench_namespace 2>/dev/null)" || [[ -z "$wbns" ]]; then
        _record WARN "$name" "cannot tell where the access policy places the AI workbench (python3 apps/iam/compiler/cli.py check)"; return
    fi
    out="$(timeout "$TIMEOUT" $KUBECTL get pods -n "$wbns" -l app=jupyterhub,component=hub --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read the hub pod in $wbns: $(tail -n1 <<<"$out" | cut -c1-120)"; return
    fi
    pod="$(grep -m1 . <<<"$out")"
    if [[ -z "$pod" ]]; then
        _record SKIP "$name" "no running hub in $wbns"; return
    fi
    rc=0
    hub="$(timeout "$TIMEOUT" $KUBECTL exec -n "$wbns" "$pod" -c hub -- python3 -c '
import re, sqlite3
db = sqlite3.connect("file:/srv/jupyterhub/jupyterhub.sqlite?mode=ro", uri=True)
for (n,) in db.execute("SELECT name FROM users ORDER BY name"):
    print("user|" + re.sub(r"[^A-Za-z0-9._@-]", "?", n or "")[:64])
print("end|")' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]] || ! grep -q '^end|$' <<<"$hub"; then
        _record WARN "$name" "cannot read the hub's users in $pod: $(grep -v '^user|' <<<"$hub" | tail -n1 | cut -c1-120)"; return
    fi
    rc=0
    kc="$(timeout "$TIMEOUT" $KUBECTL exec -i -n "$ns" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d keycloak -tA -v realm="$0"' \
        "$realm" 2>&1 <<'SQL'
SELECT 'realm|' || count(*) FROM realm r WHERE r.name = :'realm';
SELECT 'account|' || lower(u.username)
  FROM user_entity u JOIN realm r ON r.id = u.realm_id
 WHERE r.name = :'realm' AND u.enabled AND u.service_account_client_link IS NULL;
SQL
)" || rc=$?
    if [[ $rc -ne 0 ]] || ! grep -q '^realm|1$' <<<"$kc"; then
        _record WARN "$name" "cannot read realm ${realm}'s accounts from Keycloak database keycloak: $(grep -m1 -E 'ERROR|error|realm\|0' <<<"$kc" | cut -c1-120)"; return
    fi
    local users stale n
    users="$(sed -n 's/^user|//p' <<<"$hub")"
    n="$(grep -c . <<<"$users")"
    stale="$(comm -23 <(grep . <<<"$users" | tr 'A-Z' 'a-z' | sort -u) <(sed -n 's/^account|//p' <<<"$kc" | sort -u) | paste -sd ' ')"
    if [[ -n "$stale" ]]; then
        _record WARN "$name" "hub user(s) without an enabled account in realm ${realm}: $stale — remove them in https://${WORKBENCH_DOMAIN:-workbench}/hub/admin (their own hub API tokens outlive the account)"
    else
        _record OK "$name" "$n hub user(s) in $wbns, each an enabled account of realm $realm"
    fi
}

# =============================================================================
# Helpers of the research zone's checks (rsgrants, rslake) — read-only
# _rs_zone_ns NAME NS: the research namespace in RS_NS, 0 to go on; 1 after recording a
# SKIP or WARN (switched off without the namespace, no research zone, a broken policy,
# the namespace missing or unreadable).
# _rs_assert_grants RNS: apps/research/db/assert_grants.sql as postgres in
# research-postgresql-0, read-only (PGOPTIONS, SQL on stdin), its lines on stdout; status 1
# when psql fails (its last error line on stdout).
# =============================================================================
_rs_zone_ns() {
    local name="$1" ns="$2" out rc=0 exists
    RS_NS="${RESEARCH_NAMESPACE:-${ns}-research}"
    out="$(timeout "$TIMEOUT" $KUBECTL get namespace "$RS_NS" -o name 2>&1)" || rc=$?
    if [[ $rc -eq 0 ]]; then
        exists=yes
    elif grep -q 'NotFound' <<<"$out"; then
        exists=no
    else
        _record WARN "$name" "cannot read namespace $RS_NS: $(tail -n1 <<<"$out" | cut -c1-120)"; return 1
    fi
    if [[ "${RESEARCH_ENABLED:-false}" != true && $exists == no ]]; then
        _record SKIP "$name" "the research sandbox is switched off (RESEARCH_ENABLED is not true)"; return 1
    fi
    rc=0
    python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" has-zone research >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 1 ]]; then
        _record SKIP "$name" "the applied access policy has no research zone yet"; return 1
    elif [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot tell whether the applied access policy has a research zone (python3 apps/iam/compiler/cli.py check)"; return 1
    fi
    if [[ $exists == no ]]; then
        _record SKIP "$name" "namespace $RS_NS does not exist (Research network policies reports it)"; return 1
    fi
    return 0
}
_rs_assert_grants() {
    local out rc=0
    [[ -r "$SCRIPT_DIR/apps/research/db/assert_grants.sql" ]] || { echo "cannot read apps/research/db/assert_grants.sql"; return 1; }
    out="$(timeout "$((TIMEOUT * 2))" $KUBECTL exec -i -n "$1" research-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA' medcea_research \
        <"$SCRIPT_DIR/apps/research/db/assert_grants.sql" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        local why
        why="$(grep -m1 -E 'ERROR|error|NotFound|FATAL' <<<"$out")" || why="$(tail -n1 <<<"$out")"
        cut -c1-120 <<<"${why:-psql exit $rc}"
        return 1
    fi
    grep -v '^[[:space:]]*$' <<<"$out"
    return 0
}

# =============================================================================
# Check: Secrets and grants of the research zone (research sandbox Phase 2b) — read-only
# target: NAMESPACE (the research namespace is RESEARCH_NAMESPACE, else NAMESPACE-research).
# FAIL when a pod or pod template there (secretKeyRef, envFrom, a secret volume, projected
# secret sources, imagePullSecrets) names a Secret outside its allow-list, which keys on the
# workload controlling it (its controller ownerReferences, matched by uid to the listed
# objects; labels alone never grant one, since the hub may create pods with any label):
# StatefulSet research-postgresql → research-postgresql-auth; Deployment lake-api →
# lake-api-auth; Deployments hub and proxy → hub; a pod with no controller labelled
# component=singleuser-server (KubeSpawner's) → singleuser; the probe
# (medcea/probe=iam-research), a forged owner and anything else → none. FAIL when a Role
# there grants secrets or *, a RoleBinding there binds a ClusterRole, a Service there is a
# NodePort or LoadBalancer or has externalIPs (the zone's pods admit `node`), or
# apps/research/db/assert_grants.sql (run read-only) prints a line.
# WARN when anything cannot be read; SKIP while switched off without the namespace and while
# the applied policy has no research zone. PSA baseline stops privileged pods; this detects
# what it cannot (a pod mounting another Secret of the zone).
# =============================================================================
check_rsgrants() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" RS_NS out rc=0 res kind msg fails=() warns=() oks=()
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    _rs_zone_ns "$name" "$ns" || return
    # The two Phase 4a zones' namespaces are scanned too, when they exist (research-gw, research-agents).
    local scan_ns scan_list=("$RS_NS") z zns count=0 total_ns=1 c1
    for z in research-gw research-agents; do
        zns="$(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" bash -c 'source "$REPO_ROOT/infra/lib-policy-tools.sh"; zone_namespace "$1"' _ "$z" 2>/dev/null)" || zns=""
        [[ -n "$zns" ]] || continue
        if timeout "$TIMEOUT" $KUBECTL get namespace "$zns" -o name >/dev/null 2>&1; then scan_list+=("$zns"); fi
    done
    for scan_ns in "${scan_list[@]}"; do
    rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get pods,deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs,roles,rolebindings,services \
        -n "$scan_ns" -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read the workloads and Roles in $scan_ns: $(tail -n1 <<<"$out" | cut -c1-120)"; return
    fi
    res="$(python3 -c '
import json, sys
try:
    items = json.load(sys.stdin).get("items") or []
except Exception:
    print("error|"); sys.exit()
# The allow-list keys on the workload that controls an object, followed through its
# controller ownerReferences by uid among the objects listed here (a pod the hub creates can
# carry any label, and any ownerReference: a reference whose uid is not the listed workload
# of that kind and name is no owner), never on labels alone (review of commit A, 19 Nov 2026).
WORKLOADS = ("StatefulSet", "ReplicaSet", "Deployment", "Job", "CronJob", "DaemonSet")
by_uid = {(i.get("metadata") or {}).get("uid"): i for i in items
          if i.get("kind") in WORKLOADS and (i.get("metadata") or {}).get("uid")}
def owner_of(i):
    for r in (i.get("metadata") or {}).get("ownerReferences") or []:
        if r.get("controller"):
            o = by_uid.get(r.get("uid"))
            if o is not None and o.get("kind") == r.get("kind") and o["metadata"].get("name") == r.get("name"):
                return o
            return False
    return None
def top(i, depth=0):
    o = owner_of(i) if i.get("kind") in ("Pod", "ReplicaSet", "Job") else None
    if o is False or depth > 3:
        return ("forged", None)
    if o is None:
        return (i.get("kind"), (i.get("metadata") or {}).get("name"))
    return top(o, depth + 1)
def allowed(i, labels):
    if labels.get("medcea/probe") == "iam-research":
        return set()
    w = top(i)
    if w == ("StatefulSet", "research-postgresql"):
        return {"research-postgresql-auth"}
    if w == ("Deployment", "lake-api"):
        return {"lake-api-auth"}
    if w == ("Deployment", "model-gateway"):
        return {"model-gateway-keys"}
    if w in (("Deployment", "hub"), ("Deployment", "proxy")):
        return {"hub"}
    if w == ("Deployment", "research-session"):
        return {"research-session-key", "research-session-db"}
    if w[0] == "Pod" and labels.get("component") == "singleuser-server":
        return {"singleuser"}
    return set()
def spec_of(i):
    k, s = i.get("kind"), i.get("spec") or {}
    if k == "Pod":
        return (i.get("metadata") or {}).get("labels") or {}, s
    if k == "CronJob":
        t = ((s.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        t = s.get("template") or {}
    return (t.get("metadata") or {}).get("labels") or {}, t.get("spec") or {}
def secrets(ps):
    out = set()
    for ctr in (ps.get("containers") or []) + (ps.get("initContainers") or []) + (ps.get("ephemeralContainers") or []):
        for e in ctr.get("env") or []:
            ref = ((e.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name")
            if ref:
                out.add(ref)
        for e in ctr.get("envFrom") or []:
            ref = (e.get("secretRef") or {}).get("name")
            if ref:
                out.add(ref)
    for v in ps.get("volumes") or []:
        if (v.get("secret") or {}).get("secretName"):
            out.add(v["secret"]["secretName"])
        for src in (v.get("projected") or {}).get("sources") or []:
            if (src.get("secret") or {}).get("name"):
                out.add(src["secret"]["name"])
    for r in ps.get("imagePullSecrets") or []:
        if r.get("name"):
            out.add(r["name"])
    return out
bad, roles, binds, exposed, forged, n = [], [], [], [], [], 0
for i in items:
    k, nm = i.get("kind"), (i.get("metadata") or {}).get("name")
    if k == "Service":
        sp = i.get("spec") or {}
        if sp.get("type") in ("NodePort", "LoadBalancer") or sp.get("externalIPs"):
            exposed.append("%s (%s)" % (nm, "externalIPs" if sp.get("externalIPs") else sp.get("type")))
        continue
    if k == "Role":
        if any(set(r.get("resources") or []) & {"secrets", "*"} for r in i.get("rules") or []):
            roles.append(nm)
        continue
    if k == "RoleBinding":
        if ((i.get("roleRef") or {}).get("kind")) == "ClusterRole":
            binds.append("%s (%s)" % (nm, i["roleRef"].get("name")))
        continue
    labels, ps = spec_of(i)
    n += 1
    # Phase 4a: a pod that claims one of the agent machinery identities (its label, or the
    # orchestrator ServiceAccount) must be controlled by that Deployment (uid-matched), whoever
    # created it: the hub may create pods in the research zone with any label or account.
    if k == "Pod":
        app = labels.get("app")
        # research Phase 4e: research-console too (its Deployment names no Secret: allowed() gives it none)
        want = ("Deployment", app) if app in ("research-orchestrator", "mcp-sim", "mcp-lake", "research-session",
                                              "research-console") else None
        if (ps.get("serviceAccountName") == "research-orchestrator") and want is None:
            want = ("Deployment", "research-orchestrator")
        if want is not None and top(i) != want:
            forged.append(nm)
    extra = sorted(secrets(ps) - allowed(i, labels))
    if extra:
        bad.append("%s/%s: %s" % (k.lower(), nm, ",".join(extra)))
print("count|%d" % n)
if bad:
    print("FAIL|Secrets outside the allow-list: " + "; ".join(sorted(bad)[:5]) + (" (and %d more)" % (len(bad) - 5) if len(bad) > 5 else ""))
if forged:
    print("FAIL|pod(s) using an agent service label or the orchestrator ServiceAccount without being the controlled Deployment: " + " ".join(sorted(forged)))
if roles:
    print("FAIL|Role(s) granting secrets or *: " + " ".join(sorted(roles)))
if binds:
    print("FAIL|RoleBinding(s) binding a ClusterRole: " + " ".join(sorted(binds)))
if exposed:
    print("FAIL|Service(s) reachable from outside the cluster (the zone admits node: a NodePort would open lake-api to the LAN): " + " ".join(sorted(exposed)))
' <<<"$out" 2>/dev/null)"
    c1=""
    while IFS='|' read -r kind msg; do
        case "$kind" in
            count) c1="$msg" ;;
            FAIL)  fails+=("$([[ "$scan_ns" == "$RS_NS" ]] || echo "$scan_ns: ")$msg") ;;
            error) _record WARN "$name" "cannot parse the workloads and Roles in $scan_ns"; return ;;
        esac
    done <<<"$res"
    [[ "$c1" =~ ^[0-9]+$ ]] || { _record WARN "$name" "cannot judge the workloads in $scan_ns"; return; }
    count=$((count + c1))
    done
    oks+=("$count pod spec(s) in ${scan_list[*]} name only their own Secrets; no Role on secrets, no ClusterRole bound, no Service exposed")
    rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get statefulset research-postgresql -n "$RS_NS" -o name 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -q 'NotFound' <<<"$out"; then
            oks+=("no research database yet")
        else
            warns+=("cannot read StatefulSet research-postgresql in $RS_NS: $(tail -n1 <<<"$out" | cut -c1-100)")
        fi
    else
        rc=0
        out="$(_rs_assert_grants "$RS_NS")" || rc=$?
        if [[ $rc -ne 0 ]]; then
            warns+=("cannot check the research database's grants: $out")
        elif [[ -n "$out" ]]; then
            fails+=("the research database's grants are not db/grants.sql's ($(grep -c . <<<"$out") problem(s)): $(head -n3 <<<"$out" | paste -sd ';' | sed 's/;/; /g' | cut -c1-200) (./apps/research/deploy.sh)")
        else
            oks+=("the research database's grants are db/grants.sql's")
        fi
    fi
    local IFS=';'
    if (( ${#fails[@]} )); then
        _record FAIL "$name" "${fails[*]}"
    elif (( ${#warns[@]} )); then
        _record WARN "$name" "${warns[*]}"
    else
        _record OK "$name" "${oks[*]}"
    fi
}

# =============================================================================
# Check: the research lake reader (lake-api, research sandbox Phase 2b) — read-only
# target: NAMESPACE (Deployment lake-api lives in the research namespace). SKIP without
# deployment/lake-api (and while switched off or the policy has no research zone). FAIL when
# apps/research/db/assert_grants.sql (read-only, the same queries as the deploy) prints a
# line about rs_lake_api, rs_lake_reader or schema lake_api. WARN when no lake-api pod is
# Running, its root (curl -m TIMEOUT http://<podIP>:3000/ from the host, which the zone's
# rs-lake-api admits as node) does not answer 200, lake.snapshot_digest_check(<newest>)
# reports a set whose recorded digest is not the one its rows give, or anything cannot be
# read.
# =============================================================================
check_rslake() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" RS_NS out rc=0 line ip phase pod code fails=() warns=() oks=()
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    _rs_zone_ns "$name" "$ns" || return
    out="$(timeout "$TIMEOUT" $KUBECTL get deployment lake-api -n "$RS_NS" -o name 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -q 'NotFound' <<<"$out"; then
            _record SKIP "$name" "no deployment lake-api in $RS_NS (./apps/lake-api/deploy.sh, once the policy has its pod)"
        else
            _record WARN "$name" "cannot read deployment lake-api in $RS_NS: $(tail -n1 <<<"$out" | cut -c1-120)"
        fi
        return
    fi
    rc=0
    out="$(_rs_assert_grants "$RS_NS")" || rc=$?
    if [[ $rc -ne 0 ]]; then
        warns+=("cannot check the lake reader's roles: $out")
    else
        line="$(grep -E 'rs_lake_api|rs_lake_reader|lake_api' <<<"$out")"
        if [[ -n "$line" ]]; then
            fails+=("rs_lake_api / rs_lake_reader break the lake reader's rules ($(grep -c . <<<"$line") problem(s)): $(head -n3 <<<"$line" | paste -sd ';' | sed 's/;/; /g' | cut -c1-200) (./apps/research/deploy.sh)")
        else
            oks+=("rs_lake_api reads only through lake_api")
        fi
    fi
    rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get pods -n "$RS_NS" -l app=lake-api \
        -o jsonpath='{range .items[*]}{.metadata.name} {.status.phase} {.status.podIP}{"\n"}{end}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        warns+=("cannot read the lake-api pods: $(tail -n1 <<<"$out" | cut -c1-100)")
    else
        read -r pod phase ip <<<"$(grep -m1 ' Running ' <<<"$out")"
        if [[ -z "$pod" || -z "$ip" ]]; then
            warns+=("no lake-api pod is Running in $RS_NS (microk8s kubectl -n $RS_NS describe deployment lake-api)")
        else
            code="$(curl -s -o /dev/null -m "$TIMEOUT" -w '%{http_code}' "http://$ip:3000/" 2>/dev/null)"
            if [[ "$code" == 200 ]]; then
                oks+=("$pod answers on :3000")
            else
                warns+=("$pod at $ip:3000 answered ${code:-nothing} from the host, not 200 (the snapshot reader is down, or rs-lake-api does not admit the node)")
            fi
        fi
    fi
    rc=0
    out="$(timeout "$((TIMEOUT * 4))" $KUBECTL exec -i -n "$RS_NS" research-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' medcea_research 2>&1 <<'SQL'
SELECT pg_catalog.to_regprocedure('lake.snapshot_digest_check(bigint)') IS NOT NULL AS has_check \gset
\if :has_check
SELECT 'newest|' || coalesce((SELECT max(snapshot_id)::text FROM lake.snapshot), '-');
SELECT CASE WHEN d.ok IS TRUE THEN 'good|' ELSE 'bad|' END || d."set"
  FROM lake.snapshot_digest_check((SELECT max(snapshot_id) FROM lake.snapshot)) d
 WHERE EXISTS (SELECT 1 FROM lake.snapshot);
\else
SELECT 'state|nocheck';
\endif
SQL
)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        warns+=("cannot recompute the newest snapshot's digests: $(grep -m1 -E 'ERROR|error|NotFound|FATAL' <<<"$out" | cut -c1-100)")
    elif grep -q '^state|nocheck$' <<<"$out"; then
        warns+=("the research database has no lake.snapshot_digest_check yet (./apps/research/deploy.sh)")
    else
        local newest bad sets
        newest="$(sed -n 's/^newest|//p' <<<"$out" | head -n1)"
        bad="$(sed -n 's/^bad|//p' <<<"$out" | paste -sd ' ')"
        sets="$(grep -cE '^(good|bad)\|' <<<"$out")"
        if [[ "$newest" == "-" ]]; then
            oks+=("no snapshot yet")
        elif [[ ! "$newest" =~ ^[0-9]+$ ]] || (( sets == 0 )); then
            warns+=("cannot read the newest snapshot's digest check")
        elif [[ -n "$bad" ]]; then
            warns+=("snapshot $newest: the recorded digest of $bad is not the one its lake rows give (lake.snapshot_digest_check($newest)): the lake changed after the export, or the digest rule did")
        else
            oks+=("snapshot $newest: its $sets set digest(s) recompute")
        fi
    fi
    local IFS=';'
    if (( ${#fails[@]} )); then
        _record FAIL "$name" "${fails[*]}"
    elif (( ${#warns[@]} )); then
        _record WARN "$name" "${warns[*]}"
    else
        _record OK "$name" "${oks[*]}"
    fi
}

# =============================================================================
# Check: the research gateway's and the agents' NetworkPolicies (research Phase 4a, R38)
# — read-only. gwnetpol and ranetpol are thin wrappers over check_zonenetpol ZONE.
# target: NAMESPACE. The labelled policies of the zone's namespace (zone_namespace, as
# infra/lib-policy-tools.sh) against `cli.py compile netpol` with zone_netpol_args (the other
# zones' namespaces are named for the cross-zone peers), compared as {name: spec} in canonical
# JSON, default deny and DNS included, as rsnetpol does: FAIL when a compiled one is missing or
# differs or any other NetworkPolicy is there (labelled or not: policies are additive). SKIP
# without kubectl, while the sandbox is switched off without the namespace, and while the applied
# policy has no such zone (before the skeleton version of Phase 4a); WARN when switched off with
# the namespace left, when enabled without it, and when anything cannot be read.
# =============================================================================
check_zonenetpol() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" zone="$3" zns out rc=0 exists live want ip ips=() res kind names
    local fails=() count="" label key args=()
    case "$zone" in
        research-gw)     label="gw-netpol"; key=gw ;;
        research-agents) label="ra-netpol"; key=ra ;;
        *) _record WARN "$name" "unknown research zone $zone"; return ;;
    esac
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    zns="$(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" bash -c 'source "$REPO_ROOT/infra/lib-policy-tools.sh"; zone_namespace "$1"' _ "$zone" 2>/dev/null)" || zns=""
    [[ -n "$zns" ]] || { _record WARN "$name" "cannot tell the namespace of zone $zone"; return; }
    out="$(timeout "$TIMEOUT" $KUBECTL get namespace "$zns" -o name 2>&1)" || rc=$?
    if [[ $rc -eq 0 ]]; then exists=yes
    elif grep -q 'NotFound' <<<"$out"; then exists=no
    else _record WARN "$name" "cannot read namespace $zns: $(tail -n1 <<<"$out" | cut -c1-120)"; return
    fi
    if [[ "${RESEARCH_ENABLED:-false}" != true ]]; then
        if [[ $exists == yes ]]; then
            _record WARN "$name" "RESEARCH_ENABLED is not true, yet namespace $zns exists (./apps/research-agents/uninstall.sh, then microk8s kubectl delete namespace $zns)"
        else
            _record SKIP "$name" "the research sandbox is switched off (RESEARCH_ENABLED is not true)"
        fi
        return
    fi
    rc=0
    python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" has-zone "$zone" >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 1 ]]; then
        _record SKIP "$name" "the applied access policy has no $zone zone yet"; return
    elif [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot tell whether the applied access policy has a $zone zone (python3 apps/iam/compiler/cli.py check)"; return
    fi
    if [[ $exists == no ]]; then
        _record WARN "$name" "RESEARCH_ENABLED=true, but namespace $zns does not exist (./deploy-infra.sh)"; return
    fi
    rc=0
    live="$(timeout "$TIMEOUT" $KUBECTL get netpol -n "$zns" -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read the NetworkPolicies in $zns: $(tail -n1 <<<"$live" | cut -c1-120)"; return
    fi
    rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="InternalIP")]}{.address}{" "}{end}{.metadata.annotations.projectcalico\.org/IPv4Address}{" "}{.metadata.annotations.projectcalico\.org/IPv4VXLANTunnelAddr}{" "}{.metadata.annotations.projectcalico\.org/IPv4IPIPTunnelAddr}{" "}{end}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read the node addresses: $(tail -n1 <<<"$out" | cut -c1-120)"; return
    fi
    for ip in $out; do ips+=(--node-ip "${ip%/*}"); done
    mapfile -t args < <(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" bash -c 'source "$REPO_ROOT/infra/lib-policy-tools.sh"; zone_netpol_args "$1"' _ "$zone" 2>/dev/null)
    if (( ${#args[@]} == 0 )) || ! want="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile netpol "${args[@]}" "${ips[@]}" 2>/dev/null)"; then
        _record WARN "$name" "the $zone NetworkPolicies do not compile (python3 apps/iam/compiler/cli.py check)"; return
    fi
    res="$(WANT="$want" LABEL="medcea/$label" python3 -c '
import json, os, sys
try:
    items = json.load(sys.stdin).get("items") or []
    live = {i["metadata"]["name"]: i.get("spec") for i in items}
    labelled = {i["metadata"]["name"] for i in items
                if (i["metadata"].get("labels") or {}).get(os.environ["LABEL"]) == "true"}
    want = {i["metadata"]["name"]: i.get("spec") for i in json.loads(os.environ["WANT"]).get("items") or []}
except Exception:
    print("error|")
    sys.exit(0)
# the API server drops an empty ingress/egress list (omitempty): a send-only pod compiles "ingress": []
canon = lambda s: json.dumps({f: v for f, v in (s or {}).items() if not (f in ("ingress", "egress") and v == [])}, sort_keys=True)
print("count|%d" % len(want))
print("missing|" + " ".join(sorted(n for n in want if n not in live)))
print("differ|" + " ".join(sorted(n for n in want if n in live and canon(live[n]) != canon(want[n]))))
print("extra|" + " ".join(sorted(n for n in live if n not in want and n in labelled)))
print("foreign|" + " ".join(sorted(n for n in live if n not in want and n not in labelled)))' <<<"$live" 2>/dev/null)"
    while IFS='|' read -r kind names; do
        case "$kind" in
            count)   count="$names" ;;
            missing) [[ -n "$names" ]] && fails+=("missing: $names (./deploy-infra.sh)") ;;
            differ)  [[ -n "$names" ]] && fails+=("spec differs: $names (./deploy-infra.sh)") ;;
            extra)   [[ -n "$names" ]] && fails+=("labelled but not compiled: $names (./deploy-infra.sh deletes them)") ;;
            foreign) [[ -n "$names" ]] && fails+=("not the zone's, no medcea/$label=true label: $names, which widens the zone past its default deny (microk8s kubectl delete networkpolicy -n $zns <name>)") ;;
            error)   _record WARN "$name" "cannot parse the live or compiled $zone NetworkPolicies"; return ;;
        esac
    done <<<"$res"
    if [[ ! "$count" =~ ^[0-9]+$ ]]; then
        _record WARN "$name" "cannot compare the $zone NetworkPolicies with the compile"; return
    fi
    if (( count == 0 )); then
        _record WARN "$name" "the applied policy has a $zone zone but compiles no NetworkPolicy for it (python3 apps/iam/compiler/cli.py check)"; return
    fi
    if (( ${#fails[@]} )); then
        local joined f
        joined="${fails[0]}"
        for f in "${fails[@]:1}"; do joined+="; $f"; done
        _record FAIL "$name" "the $zone zone admits more than the policy compiles: $joined"
    else
        _record OK "$name" "$count $zone NetworkPolicies, the compiled set (default deny included)"
    fi
}
check_gwnetpol() { check_zonenetpol "$1" "${2:-}" research-gw; }
check_ranetpol() { check_zonenetpol "$1" "${2:-}" research-agents; }

# =============================================================================
# The agent trace (research Phase 4a, R11) — read-only. _rs_trace_psql RNS [PSQL ARGS...]: one
# psql as postgres in research-postgresql-0, read-only session, SQL on stdin, `-tA -F '|'`;
# its status is psql's. _rs_trace_ready NAME NS: sets RS_NS, returns 1 after a SKIP/WARN when
# research is off, the zone is missing, there is no research database or no agent_trace.event.
# =============================================================================
_rs_trace_psql() {
    local rns="$1"; shift
    timeout "$((TIMEOUT * 2))" $KUBECTL exec -i -n "$rns" research-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d medcea_research -tA -F "|" "$@"' psql "$@" 2>&1
}
_rs_trace_ready() {
    local name="$1" ns="$2" out rc=0
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return 1; fi
    _rs_zone_ns "$name" "$ns" || return 1
    out="$(timeout "$TIMEOUT" $KUBECTL get statefulset research-postgresql -n "$RS_NS" -o name 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -q 'NotFound' <<<"$out"; then
            _record SKIP "$name" "no research database yet (./apps/research/deploy.sh)"
        else
            _record WARN "$name" "cannot read StatefulSet research-postgresql in $RS_NS: $(tail -n1 <<<"$out" | cut -c1-100)"
        fi
        return 1
    fi
    return 0
}

# =============================================================================
# Check: the agent trace's hash chain (research Phase 4a, R11). target: NAMESPACE. Two
# recomputations in one read-only session: agent_trace.verify_chain() (ok, events, first bad
# event) and an independent pass of the chain's own SQL over the rows (every hash against
# sha256 of event_record(...), every prev_hash against the previous row's hash, window
# functions rather than verify_chain's loop). FAIL when either finds a break, or verify_chain
# is missing while the table exists. SKIP without the table (the Phase 4a SQL not applied) and
# without a research database; WARN when unreadable. It does not see a tail cut off by a
# superuser: rsanchor and the live anchor (rsagent) do.
# =============================================================================
check_rschain() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" RS_NS out rc=0 line a b c d
    _rs_trace_ready "$name" "$ns" || return
    out="$(_rs_trace_psql "$RS_NS" <<'SQL'
SELECT pg_catalog.to_regclass('agent_trace.event') IS NOT NULL AS has_event,
       pg_catalog.to_regprocedure('agent_trace.verify_chain()') IS NOT NULL AS has_fn \gset
\if :has_event
\if :has_fn
SELECT 'chain', vc.ok, vc.events, coalesce(vc.first_bad_event::text, '-') FROM agent_trace.verify_chain() vc;
SELECT 'recompute', count(*) FILTER (WHERE e.hash <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           agent_trace.event_record(e.event_id, e.at, e.sid, e.sup_sub, e.sup_person, e.sup_role, e.actor, e.event,
                                    e.payload, e.prev_hash), 'UTF8')), 'hex')),
       count(*) FILTER (WHERE e.prev_hash <> coalesce(e.prev_row_hash, pg_catalog.repeat('0', 64))),
       count(*)
  FROM (SELECT x.*, pg_catalog.lag(x.hash) OVER (ORDER BY x.event_id) AS prev_row_hash FROM agent_trace.event x) e;
\else
SELECT 'nofn';
\endif
\else
SELECT 'notable';
\endif
SQL
)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        _record WARN "$name" "cannot read agent_trace: $(grep -m1 -E 'ERROR|error|NotFound' <<<"$out" | cut -c1-120)"; return
    fi
    if grep -q '^notable$' <<<"$out"; then
        _record SKIP "$name" "no agent_trace.event yet (the Phase 4a research database SQL: ./apps/research/deploy.sh)"; return
    fi
    if grep -q '^nofn$' <<<"$out"; then
        _record FAIL "$name" "agent_trace.event exists but agent_trace.verify_chain() does not (./apps/research/deploy.sh)"; return
    fi
    local vc rec
    vc="$(grep -m1 '^chain|' <<<"$out")"; rec="$(grep -m1 '^recompute|' <<<"$out")"
    if [[ -z "$vc" || -z "$rec" ]]; then
        _record WARN "$name" "agent_trace answered in an unexpected form"; return
    fi
    local pbad n
    IFS='|' read -r _ a b c <<<"$vc"
    IFS='|' read -r _ d pbad n <<<"$rec"      # recompute: hash mismatches | prev_hash mismatches | rows
    if [[ "$a" != t ]]; then
        _record FAIL "$name" "agent_trace.verify_chain() is not ok: the chain breaks at event ${c} (${b} events checked)"
    elif [[ "$d" != 0 || "$pbad" != 0 ]]; then
        _record FAIL "$name" "the recomputation finds ${d} row(s) whose hash does not match and ${pbad} whose prev_hash does not follow: the trace was edited"
    else
        _record OK "$name" "${b} event(s), every hash and link recomputed (verify_chain and an independent pass agree)"
    fi
}

# =============================================================================
# Check: the agent trace's anchor in the newest backup (research Phase 4a, R11). target:
# NAMESPACE. Mirrors iamanchor with backup_rs_chain_head (apps/backup/lib-backup.sh: the
# MANIFEST line `# agent_trace chain head (read before the dump): <id> <hash> db=<sysid>/<oid>`):
# that event must still be in agent_trace.event with the recorded hash (one read-only psql,
# the id as -v anchor_id=). The live database's identity (pg_control_system().system_identifier
# / the database's oid) is compared with the line's: a different one means the backup is of an
# earlier database (a new install, or --purge-data and a redeploy; BACKUP_DIR outlives both) and
# only WARNs "predates this database"; the same identity with the event missing or its hash
# different is a FAIL (the trace was cut or rewritten after the backup). WARN: no BACKUP_DIR, no
# complete backup, no or unavailable head line, a backup older than ANCHOR_MAX_H (48) h, an
# unreadable database. SKIP without a research database, without the table, and while the trace
# is still empty.
# =============================================================================
check_rsanchor() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" max_h="${ANCHOR_MAX_H:-48}" RS_NS dir newest bname ok_epoch rec kind id hash ident
    local age h out rc=0 line got since live nev
    _rs_trace_ready "$name" "$ns" || return
    dir="$(backup_dir)"
    if [[ ! -d "$dir" ]]; then
        _record WARN "$name" "no anchor: ${dir} (BACKUP_DIR) does not exist (./apps/backup/deploy.sh)"; return
    fi
    if [[ ! -r "$dir" || ! -x "$dir" ]]; then
        _record WARN "$name" "no anchor: cannot read ${dir} (BACKUP_DIR, mode 700): run this as the account that ran ./apps/backup/deploy.sh"; return
    fi
    newest="$(backup_newest_ok "$dir")"
    if [[ -z "$newest" ]]; then
        _record WARN "$name" "no anchor: no complete backup in ${dir} yet (./apps/backup/backups.sh now)"; return
    fi
    bname="${newest%% *}"; ok_epoch="${newest#* }"
    # The live side first: no events yet means nothing to anchor.
    out="$(_rs_trace_psql "$RS_NS" <<'SQL'
SELECT pg_catalog.to_regclass('agent_trace.event') IS NOT NULL AS has_event \gset
\if :has_event
SELECT 'live', (SELECT count(*) FROM agent_trace.event),
       (SELECT system_identifier FROM pg_catalog.pg_control_system()) || '/' ||
       (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database());
\else
SELECT 'notable';
\endif
SQL
)" || rc=$?
    line="$(grep -m1 -E '^(live\||notable$)' <<<"$out")"
    if [[ $rc -ne 0 || -z "$line" ]]; then
        _record WARN "$name" "cannot read agent_trace: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"; return
    fi
    if [[ "$line" == notable ]]; then _record SKIP "$name" "no agent_trace.event yet (./apps/research/deploy.sh)"; return; fi
    IFS='|' read -r _ nev live <<<"$line"
    if [[ "$nev" == 0 ]]; then _record SKIP "$name" "no agent session has been recorded yet"; return; fi
    if ! rec="$(backup_rs_chain_head "$dir/$bname")"; then
        _record WARN "$name" "no anchor: cannot read the MANIFEST of backup ${bname}"; return
    fi
    case "$rec" in
        none) _record WARN "$name" "no anchor: backup ${bname} records no agent_trace head (a backup from before Phase 4a, or ./apps/backup/deploy.sh has not run since)"; return ;;
        unavailable*) _record WARN "$name" "no anchor: backup ${bname} could not read the agent_trace head ${rec#unavailable }"; return ;;
    esac
    read -r kind id hash ident <<<"$rec"
    age=$(( $(date -u +%s) - ok_epoch )); (( age < 0 )) && age=0; h=$(( age / 3600 ))
    if [[ "$ident" != "$live" ]]; then
        _record WARN "$name" "no anchor: backup ${bname} predates this database (its identity ${ident} is not the live ${live}: a new install or a purged database): no anchor until the next nightly backup"; return
    fi
    rc=0
    out="$(_rs_trace_psql "$RS_NS" -v "anchor_id=$id" <<'SQL'
SELECT 'anchor', coalesce((SELECT e.hash FROM agent_trace.event e WHERE e.event_id = :anchor_id), '-'),
       (SELECT count(*) FROM agent_trace.event e WHERE e.event_id > :anchor_id);
SQL
)" || rc=$?
    line="$(grep -m1 '^anchor|' <<<"$out")"
    if [[ $rc -ne 0 || -z "$line" ]]; then
        _record WARN "$name" "cannot read agent_trace to compare with backup ${bname}: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-120)"; return
    fi
    IFS='|' read -r _ got since <<<"$line"
    if [[ "$got" == "-" ]]; then
        _record FAIL "$name" "event ${id}, the trace head backup ${bname} recorded for this database, is missing from agent_trace.event: the trace was cut after that backup"
    elif [[ "$got" != "$hash" ]]; then
        _record FAIL "$name" "event ${id}'s hash is ${got:0:12}..., backup ${bname} recorded ${hash:0:12}...: the trace was rewritten after that backup"
    elif (( age > max_h * 3600 )); then
        _record WARN "$name" "event ${id} has the hash backup ${bname} recorded, but that backup is ${h} h old (over ${max_h} h: ./apps/backup/backups.sh list)"
    else
        _record OK "$name" "event ${id} has the hash backup ${bname} recorded (${h} h old), ${since} event(s) since"
    fi
}

# =============================================================================
# Check: the agent sessions' services (research Phase 4a, R11/R38). target: NAMESPACE.
# SKIP while switched off, without the research-gw zone or without Deployment research-session.
# WARN when a pod of research-orchestrator, mcp-sim or mcp-lake (research-agents) is not Running,
# research-session's pod does not answer http://<podIP>:8100/healthz from the host within
# `curl -m`, its `kid` differs from annotation medcea/session-key-kid on Secret
# research-session-key (the key itself is never read), or the database cannot be read. FAIL when
# the live anchor research-session reports (the last event it wrote, `anchor.event_id`/`hash`)
# is missing from agent_trace.event or has another hash there: the trace was rewritten under a
# running service. Not built yet: orphan Jobs and the profile-inventory drift (4b).
# =============================================================================
check_rsagent() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" gwns agns rc=0 out ip code body info kid want_kid eid ehash line got
    local warns=() fails=() oks=() d pods
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    if [[ "${RESEARCH_ENABLED:-false}" != true ]]; then _record SKIP "$name" "the research sandbox is switched off (RESEARCH_ENABLED is not true)"; return; fi
    rc=0
    python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" has-zone research-gw >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 1 ]]; then _record SKIP "$name" "the applied access policy has no research-gw zone yet"; return
    elif [[ $rc -ne 0 ]]; then _record WARN "$name" "cannot tell whether the applied access policy has a research-gw zone"; return; fi
    gwns="$(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" bash -c 'source "$REPO_ROOT/infra/lib-policy-tools.sh"; zone_namespace research-gw' 2>/dev/null)"
    agns="$(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" bash -c 'source "$REPO_ROOT/infra/lib-policy-tools.sh"; zone_namespace research-agents' 2>/dev/null)"
    rc=0
    out="$(timeout "$TIMEOUT" $KUBECTL get deployment research-session -n "$gwns" -o name 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -q 'NotFound' <<<"$out"; then _record SKIP "$name" "no deployment research-session in $gwns (./apps/research-agents/deploy.sh)"
        else _record WARN "$name" "cannot read deployment research-session in $gwns: $(tail -n1 <<<"$out" | cut -c1-120)"; fi
        return
    fi
    for d in research-orchestrator mcp-sim mcp-lake; do
        rc=0
        pods="$(timeout "$TIMEOUT" $KUBECTL get pods -n "$agns" -l "app=$d" --field-selector=status.phase=Running -o name 2>&1)" || rc=$?
        if [[ $rc -ne 0 ]]; then warns+=("cannot read the pods of $d in $agns"); continue; fi
        grep -q . <<<"$pods" || warns+=("no Running pod of $d in $agns")
    done
    rc=0
    ip="$(timeout "$TIMEOUT" $KUBECTL get pods -n "$gwns" -l app=research-session --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].status.podIP}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 || ! "$ip" =~ ^[0-9.]+$ ]]; then
        warns+=("no Running research-session pod with an address in $gwns")
    else
        rc=0
        body="$(curl -s -m "$TIMEOUT" "http://${ip}:8100/healthz" 2>/dev/null)" || rc=$?
        info="$(python3 -c '
import json, re, sys
try:
    d = json.load(sys.stdin)
    kid = d.get("kid") or ""
    a = d.get("anchor") or {}
    print("%s|%s|%s" % (kid if re.fullmatch(r"[0-9a-f]{8}", kid) else "", a.get("event_id", "") if isinstance(a.get("event_id", ""), int) else "",
                        a.get("hash", "") if re.fullmatch(r"[0-9a-f]{64}", a.get("hash", "") or "") else ""))
except Exception:
    print("error")' <<<"$body" 2>/dev/null)"
        if [[ $rc -ne 0 || -z "$body" || "$info" == error ]]; then
            warns+=("research-session does not answer /healthz from the host (curl -m $TIMEOUT http://${ip}:8100/healthz)")
        else
            IFS='|' read -r kid eid ehash <<<"$info"
            want_kid="$(timeout "$TIMEOUT" $KUBECTL get secret research-session-key -n "$gwns" \
                -o jsonpath='{.metadata.annotations.medcea/session-key-kid}' 2>/dev/null)" || want_kid=""
            if [[ -z "$kid" ]]; then warns+=("research-session reports no key id")
            elif [[ -z "$want_kid" ]]; then warns+=("Secret research-session-key has no medcea/session-key-kid annotation (./apps/research-agents/deploy.sh)")
            elif [[ "$kid" != "$want_kid" ]]; then warns+=("research-session runs key ${kid}, Secret research-session-key says ${want_kid}: restart it (./apps/research-agents/deploy.sh)")
            else oks+=("key ${kid} is the Secret's"); fi
            if [[ -n "$eid" && -n "$ehash" ]]; then
                rc=0
                out="$(_rs_trace_psql "${RESEARCH_NAMESPACE:-${ns}-research}" -v "anchor_id=$eid" <<'SQL'
SELECT 'anchor', coalesce((SELECT e.hash FROM agent_trace.event e WHERE e.event_id = :anchor_id), '-');
SQL
)" || rc=$?
                line="$(grep -m1 '^anchor|' <<<"$out")"
                if [[ $rc -ne 0 || -z "$line" ]]; then
                    warns+=("cannot read agent_trace to check the live anchor: $(grep -m1 -E 'ERROR|error' <<<"$out" | cut -c1-100)")
                else
                    got="${line#anchor|}"
                    if [[ "$got" == "-" ]]; then fails+=("the live anchor, event ${eid}, is missing from agent_trace.event: the trace was cut under a running service")
                    elif [[ "$got" != "$ehash" ]]; then fails+=("the live anchor, event ${eid}, has hash ${got:0:12}... in the database, research-session wrote ${ehash:0:12}...: the trace was rewritten")
                    else oks+=("live anchor event ${eid} matches the database"); fi
                fi
            else
                oks+=("no event written since the service started")
            fi
        fi
    fi
    local IFS=';'
    if (( ${#fails[@]} )); then _record FAIL "$name" "${fails[*]}"
    elif (( ${#warns[@]} )); then _record WARN "$name" "${warns[*]}"
    else _record OK "$name" "research-session and the agents' services run; ${oks[*]}"; fi
}

# rsllm (Local model; research Phase 4b stage 1, design rs4 5.4): research-llm, the local model's server in
# research-gw. Read-only and it generates nothing: Deployment env pin = apps/research-model/pins.json, the pod
# Ready, /health, /props (alias carrying the pin, context 4096, a chat template), and /metrics against the
# bench (WARN when generation since the server started averages below half the bench's tg128 rate at the deployed
# context). The rate is tokens_predicted_total / tokens_predicted_seconds_total: llama-server's
# predicted_tokens_seconds covers only the time since the previous /metrics read, so it is 0 whenever nothing was
# generated in between (it made this check WARN "0 tok/s", 26 Nov 2026). The bench's empty-context rate is no
# baseline either: a session runs with thousands of tokens of context, which slows generation severalfold.
# SKIP while RESEARCH_LOCAL_MODEL is not true.
check_rsllm() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" gwns rc=0 out pin want_sha want_alias want_ctx base_gen
    local warns=() fails=() oks=() line phase ip ready got_sha body info metrics rate predicted
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    if [[ "${RESEARCH_LOCAL_MODEL:-false}" != true ]]; then _record SKIP "$name" "the local model is switched off (RESEARCH_LOCAL_MODEL is not true)"; return; fi
    if [[ "${RESEARCH_ENABLED:-false}" != true ]]; then _record SKIP "$name" "the research sandbox is switched off (RESEARCH_ENABLED is not true)"; return; fi
    gwns="$(NAMESPACE="$ns" REPO_ROOT="$SCRIPT_DIR" bash -c 'source "$REPO_ROOT/infra/lib-policy-tools.sh"; zone_namespace research-gw' 2>/dev/null)"
    pin="$(python3 - "$SCRIPT_DIR/apps/research-model/pins.json" "$SCRIPT_DIR/research/agents/bench" <<'PY' 2>/dev/null
import glob, json, sys
CTX = 4096
p = json.load(open(sys.argv[1]))["models"]["4b"]
base = ""
# the bench's best generation rate (tg*) of the 4b model at the deployed context, from the newest file that has one
for f in sorted(glob.glob(sys.argv[2] + "/*.json"), reverse=True):
    try:
        rows = json.load(open(f))["bench"]["rows"]
        g = [float(r["tok_s"]) for r in rows if r.get("model") == "4b" and str(r.get("test", "")).startswith("tg")
             and r.get("depth") == CTX and float(r.get("tok_s") or 0) > 0]
    except Exception:
        continue
    if g:
        base = "%g" % max(g)
        break
print("%s|%s-%s|%d|%s" % (p["sha256"], p["file"][:-5].lower(), p["sha256"][:12], CTX, base))
PY
)"
    IFS='|' read -r want_sha want_alias want_ctx base_gen <<<"$pin"
    if [[ ! "$want_sha" =~ ^[0-9a-f]{64}$ ]]; then _record WARN "$name" "cannot read the model pin from apps/research-model/pins.json"; return; fi
    rc=0
    got_sha="$(timeout "$TIMEOUT" $KUBECTL get deployment research-llm -n "$gwns" \
        -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="LLM_MODEL_SHA256")].value}' 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -q 'NotFound' <<<"$got_sha"; then
            _record WARN "$name" "RESEARCH_LOCAL_MODEL is true but there is no deployment research-llm in $gwns (./apps/research-model/deploy.sh; it skips until the applied access policy has the research-llm pod)"
        else
            _record WARN "$name" "cannot read deployment research-llm in $gwns: $(tail -n1 <<<"$got_sha" | cut -c1-120)"
        fi
        return
    fi
    if [[ "$got_sha" != "$want_sha" ]]; then
        fails+=("research-llm runs model ${got_sha:0:12}..., the pin is ${want_sha:0:12}...: ./apps/research-model/deploy.sh")
    else oks+=("model pin ${want_sha:0:12} matches"); fi
    rc=0
    line="$(timeout "$TIMEOUT" $KUBECTL get pods -n "$gwns" -l app=research-llm \
        -o jsonpath='{range .items[*]}{.status.phase}|{.status.podIP}|{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' 2>&1 | head -n1)" || rc=$?
    IFS='|' read -r phase ip ready <<<"$line"
    if [[ $rc -ne 0 || "$phase" != Running || "$ready" != True || ! "$ip" =~ ^[0-9.]+$ ]]; then
        warns+=("the research-llm pod is not Ready (${phase:-no pod}): microk8s kubectl -n $gwns describe pod -l app=research-llm")
    else
        rc=0
        body="$(curl -s -m "$TIMEOUT" "http://${ip}:8080/health" 2>/dev/null)" || rc=$?
        if [[ $rc -ne 0 ]] || ! python3 -c 'import json, sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ok" else 1)' <<<"$body" 2>/dev/null; then
            warns+=("research-llm does not answer /health ok from the host (curl -m $TIMEOUT http://${ip}:8080/health)")
        else
            oks+=("/health ok")
            rc=0
            body="$(curl -s -m "$TIMEOUT" "http://${ip}:8080/props" 2>/dev/null)" || rc=$?
            info="$(python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    g = d.get("default_generation_settings") or {}
    n = g.get("n_ctx", (g.get("params") or {}).get("n_ctx", ""))
    print("%s|%s|%s" % (d.get("model_alias", ""), n, "t" if (d.get("chat_template") or "").strip() else "f"))
except Exception:
    print("error")' <<<"$body" 2>/dev/null)"
            if [[ $rc -ne 0 || "$info" == error || -z "$info" ]]; then
                warns+=("research-llm /props does not answer or is not JSON")
            else
                local alias n_ctx tpl
                IFS='|' read -r alias n_ctx tpl <<<"$info"
                if [[ "$alias" != "$want_alias" ]]; then fails+=("research-llm answers as model '${alias:0:80}', the pin is '$want_alias'")
                else oks+=("alias is the pin's"); fi
                if [[ -n "$n_ctx" && "$n_ctx" != "$want_ctx" ]]; then warns+=("the context is $n_ctx tokens, the decision is $want_ctx")
                else oks+=("context ${n_ctx:-?}"); fi
                [[ "$tpl" == t ]] || warns+=("research-llm reports no chat template: tool calls would not parse")
            fi
            rc=0
            metrics="$(curl -s -m "$TIMEOUT" "http://${ip}:8080/metrics" 2>/dev/null)" || rc=$?
            if [[ $rc -eq 0 && -n "$metrics" ]]; then
                local gen_s
                predicted="$(awk '$1 == "llamacpp:tokens_predicted_total" {print $2}' <<<"$metrics" | head -n1)"
                gen_s="$(awk '$1 == "llamacpp:tokens_predicted_seconds_total" {print $2}' <<<"$metrics" | head -n1)"
                if [[ "$predicted" =~ ^[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$ && "$gen_s" =~ ^[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$ ]] \
                   && awk -v n="$predicted" -v t="$gen_s" 'BEGIN { exit !(n + 0 > 0 && t + 0 > 0) }'; then
                    rate="$(awk -v n="$predicted" -v t="$gen_s" 'BEGIN { printf "%.2f", n / t }')"
                    if [[ -z "$base_gen" ]]; then
                        oks+=("generation $rate tok/s since start (no bench rate at $want_ctx tokens of context to compare)")
                    elif awk -v r="$rate" -v b="$base_gen" 'BEGIN { exit !(r + 0 < 0.5 * b) }'; then
                        warns+=("generation has averaged $rate tok/s since the model server started, below half of the bench's $base_gen tok/s at $want_ctx tokens of context")
                    else oks+=("generation $rate tok/s since start (bench $base_gen at $want_ctx tokens of context)"); fi
                else
                    oks+=("no generation since start")
                fi
            fi
        fi
    fi
    local IFS=';'
    if (( ${#fails[@]} )); then _record FAIL "$name" "${fails[*]}"
    elif (( ${#warns[@]} )); then _record WARN "$name" "${warns[*]}"
    else _record OK "$name" "research-llm runs the pinned model; ${oks[*]}"; fi
}

# rsconsole (Research console; research Phase 4e, design rs4e §6): the console's page server in research-agents.
# Read-only. SKIP while the applied access policy has no RESEARCH_CONSOLE_DOMAIN (cli.py has-host 1) or there is
# no Deployment research-console. Read through `kubectl exec deploy/research-console -c console -- python3 -c`
# (the zone admits no node source on 8080): /healthz, GET / without a token, /srv/MANIFEST.json's file digests.
# FAIL when /healthz's manifest_sha256 differs from ConfigMap research-console-html's medcea/console-sha256 120 s
# or more after the ConfigMap's last write (managedFields, as iamloaded; the kubelet syncs the mount within that),
# when / answers anything but 401 without a token (the check proves the gate), when a vendor file's sha256 is not
# the one its html/vendor/<lib>/VERSION records, when the Deployment or a Running pod mounts a Secret or carries a
# ServiceAccount token. WARN: no Running pod, no answer, unreadable objects, a digest lag inside 120 s.
check_rsconsole() {
    local name="$1" ns="${2:-${NAMESPACE:-medcea}}" agns hrc=0 rc=0 dep pods cm probe d out lvl msg worst="" details=() ok=""
    if ! _ps_kubectl_usable; then _record SKIP "$name" "no usable kubectl"; return; fi
    python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" has-host RESEARCH_CONSOLE_DOMAIN >/dev/null 2>&1 || hrc=$?
    case "$hrc" in
        0) ;;
        1) _record SKIP "$name" "the applied access policy has no research console yet (RESEARCH_CONSOLE_DOMAIN)"; return ;;
        *) _record WARN "$name" "cannot tell whether the applied access policy has the research console (python3 apps/iam/compiler/cli.py check)"; return ;;
    esac
    agns="$(NAMESPACE="$ns" bash -c 'source "$1/infra/lib-policy-tools.sh"; zone_namespace research-agents' _ "$SCRIPT_DIR" 2>/dev/null)"
    [[ -n "$agns" ]] || { _record WARN "$name" "cannot tell the research-agents namespace"; return; }
    dep="$(timeout "$TIMEOUT" $KUBECTL get deployment research-console -n "$agns" -o json 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -qiE 'NotFound|not found' <<<"$dep"; then
            _record SKIP "$name" "no deployment research-console in $agns (./apps/research-console/deploy.sh)"
        else
            _record WARN "$name" "cannot read deployment research-console in $agns: $(tail -n1 <<<"$dep" | cut -c1-120)"
        fi
        return
    fi
    d="$(mktemp -d)"; chmod 700 "$d"
    printf '%s' "$dep" >"$d/dep.json"
    timeout "$TIMEOUT" $KUBECTL get pods -n "$agns" -l app=research-console -o json >"$d/pods.json" 2>/dev/null || : >"$d/pods.json"
    timeout "$TIMEOUT" $KUBECTL get configmap research-console-html -n "$agns" -o json --show-managed-fields >"$d/cm.json" 2>/dev/null || : >"$d/cm.json"
    timeout "$TIMEOUT" $KUBECTL exec -n "$agns" deploy/research-console -c console -- python3 -c '
import json, urllib.error, urllib.request
out = {}
try:
    out["healthz"] = json.load(urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=3))
except Exception:
    out["healthz"] = None
try:
    urllib.request.urlopen("http://127.0.0.1:8080/", timeout=3)
    out["root"] = 200
except urllib.error.HTTPError as e:
    out["root"] = e.code
except Exception:
    out["root"] = None
try:
    m = json.load(open("/srv/MANIFEST.json"))
    out["files"] = {k: (v or {}).get("sha256") for k, v in (m.get("files") or {}).items()}
except Exception:
    out["files"] = None
print(json.dumps(out))' 2>/dev/null | tail -n1 >"$d/probe.json" || : >"$d/probe.json"
    out="$(python3 - "$d" "$SCRIPT_DIR/apps/research-console/html/vendor" "$(date +%s)" <<'PY' 2>&1
import datetime, glob, json, os, re, sys
d, vendor, now = sys.argv[1], sys.argv[2], int(sys.argv[3])
def load(n):
    try:
        with open(os.path.join(d, n)) as f:
            t = f.read().strip()
        return json.loads(t.splitlines()[-1] if n == "probe.json" else t) if t else None
    except (OSError, ValueError, IndexError):
        return None
dep, pods, cm, probe = load("dep.json"), load("pods.json"), load("cm.json"), load("probe.json")
fails, warns = [], []
def leaks(spec):
    """what a pod spec carries that the console must not: a Secret (volume, projected, env, envFrom,
    imagePullSecrets) or a ServiceAccount token (automount not false, a projected serviceAccountToken)"""
    out = []
    if spec.get("automountServiceAccountToken") is not False:
        out.append("a ServiceAccount token (automountServiceAccountToken is not false)")
    for v in spec.get("volumes") or []:
        if v.get("secret"):
            out.append("Secret volume %s" % (v["secret"].get("secretName") or "?"))
        for s in (v.get("projected") or {}).get("sources") or []:
            if s.get("secret"):
                out.append("projected Secret %s" % (s["secret"].get("name") or "?"))
            if s.get("serviceAccountToken"):
                out.append("a projected ServiceAccount token")
    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        for e in c.get("env") or []:
            if ((e.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name"):
                out.append("Secret %s in env" % e["valueFrom"]["secretKeyRef"]["name"])
        for e in c.get("envFrom") or []:
            if (e.get("secretRef") or {}).get("name"):
                out.append("Secret %s in envFrom" % e["secretRef"]["name"])
    if spec.get("imagePullSecrets"):
        out.append("imagePullSecrets")
    return out
tspec = (((dep or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
for x in leaks(tspec):
    fails.append("the Deployment's pod carries %s" % x)
running = [p for p in ((pods or {}).get("items") or []) if (p.get("status") or {}).get("phase") == "Running"
           and not (p.get("metadata") or {}).get("deletionTimestamp")]
for p in running:
    for x in leaks(p.get("spec") or {}):
        fails.append("pod %s carries %s" % ((p.get("metadata") or {}).get("name"), x))
if not running:
    warns.append("no Running research-console pod (microk8s kubectl -n <research-agents ns> describe pod -l app=research-console)")
elif not isinstance(probe, dict) or not isinstance(probe.get("healthz"), dict):
    warns.append("research-console does not answer /healthz in its pod (kubectl exec deploy/research-console -c console)")
else:
    live = probe["healthz"].get("manifest_sha256")
    meta = (cm or {}).get("metadata") or {}
    want = (meta.get("annotations") or {}).get("medcea/console-sha256")
    times = [m.get("time") for m in meta.get("managedFields") or [] if m.get("time")]
    age = None
    if times:
        try:
            last = max(datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) for t in times)
            age = int(now - last.timestamp())
        except ValueError:
            age = None
    if cm is None or not want:
        warns.append("cannot read ConfigMap research-console-html's medcea/console-sha256 (./apps/research-console/deploy.sh)")
    elif live != want:
        if age is not None and age < 120:
            warns.append("the pod serves manifest %s, the ConfigMap holds %s since %d s (the kubelet syncs within 120 s)"
                         % ((live or "-")[:12], want[:12], age))
        else:
            fails.append("the pod serves manifest %s, the ConfigMap holds %s %s (./apps/research-console/deploy.sh)"
                         % ((live or "none")[:12], want[:12], "since %d s" % age if age is not None else "since an unknown time"))
    if probe.get("root") != 401:
        fails.append("GET / without a token answered %s, not 401: the console does not check the token" % probe.get("root"))
    served = probe.get("files")
    if not isinstance(served, dict):
        warns.append("cannot read /srv/MANIFEST.json in the pod")
    else:
        for vf in sorted(glob.glob(os.path.join(vendor, "*", "VERSION"))):
            lib = os.path.basename(os.path.dirname(vf))
            with open(vf) as f:
                for line in f:
                    m = re.match(r"^([0-9a-f]{64})\s+(\S+)\s*$", line)
                    if not m:
                        continue
                    nm = "%s/%s" % (lib, m.group(2))
                    if served.get(nm) != m.group(1):
                        fails.append("vendor file %s: served %s, VERSION records %s" % (nm, (served.get(nm) or "nothing")[:12], m.group(1)[:12]))
for x in fails:
    print("FAIL|" + x)
for x in warns:
    print("WARN|" + x)
if isinstance(probe, dict) and isinstance(probe.get("healthz"), dict):
    print("OK|research-console serves manifest %s (%s files); / refuses without a token (401); no Secret, no token"
          % ((probe["healthz"].get("manifest_sha256") or "-")[:12], probe["healthz"].get("files")))
PY
)" || out="WARN|cannot judge the research console: $(tail -n1 <<<"$out" | cut -c1-120)"
    rm -rf "$d"
    while IFS='|' read -r lvl msg; do
        case "$lvl" in
            FAIL) worst=FAIL; details+=("$msg") ;;
            WARN) [[ "$worst" == FAIL ]] || worst=WARN; details+=("$msg") ;;
            OK)   ok="$msg" ;;
        esac
    done <<<"$out"
    if [[ -n "$worst" ]]; then
        local IFS=';'; _record "$worst" "$name" "${details[*]}"
    else
        _record OK "$name" "${ok:-research-console answers}"
    fi
}

# =============================================================================
# Check: TCP port reachability
# target: HOST:PORT
# =============================================================================
check_tcp() {
    local name="$1" target="$2"
    local host="${target%:*}"
    local port="${target##*:}"

    if [[ -z "$host" || -z "$port" ]]; then
        _record FAIL "$name" "Invalid tcp target '${target}' — expected HOST:PORT"
        return
    fi

    if timeout "$TIMEOUT" bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null; then
        _record OK "$name" "TCP ${host}:${port} reachable"
    else
        _record FAIL "$name" "TCP ${host}:${port} unreachable"
    fi
}

# =============================================================================
# Check: the boards' MQTT port is TLS only (5 Nov 2026)
# target: HOST:PORT of the TLS NodePort (31884). FAIL when it does not answer TLS with a
# certificate the platform CA signed for mqtt.$DOMAIN (what each board checks), or when
# the plain NodePort 31883, closed that day, answers again.
# =============================================================================
check_mqtttls() {
    local name="$1" target="$2" host port ca out
    host="${target%:*}"; port="${target##*:}"
    ca="$SCRIPT_DIR/.ca/ca.crt"
    if [[ ! -r "$ca" ]]; then
        _record FAIL "$name" "the platform CA $ca is unreadable (run as the account that deploys)"
        return
    fi
    if timeout "$TIMEOUT" bash -c ">/dev/tcp/${host}/31883" 2>/dev/null; then
        _record FAIL "$name" "the plain MQTT port ${host}:31883 answers: boards must come in over TLS only (./deploy-infra.sh)"
        return
    fi
    out="$(timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" -servername "mqtt.${DOMAIN}" \
            -verify_hostname "mqtt.${DOMAIN}" -CAfile "$ca" -verify_return_error </dev/null 2>&1 || true)"
    if grep -q "Verify return code: 0 (ok)" <<<"$out"; then
        _record OK "$name" "TLS on ${host}:${port}, certificate mqtt.${DOMAIN} from the platform CA; plain 31883 closed"
    elif [[ -z "$out" ]] || grep -qi "connect:errno\|Connection refused\|connect error" <<<"$out"; then
        _record FAIL "$name" "nothing answers on ${host}:${port} (Mosquitto's TLS listener, ./deploy-infra.sh)"
    else
        _record FAIL "$name" "${host}:${port}: $(grep -m1 -i "verify error\|Verify return code\|error" <<<"$out" | tr -s ' ' | cut -c1-110)"
    fi
}

# =============================================================================
# Check: Juju model/application unit status
# target: MODEL_NAME or MODEL_NAME/APP_NAME
#   MODEL_NAME       — checks all applications in that Juju model
#   MODEL_NAME/APP   — checks a specific application within that model
# =============================================================================
check_juju() {
    local name="$1" target="$2"
    local model app=""

    if [[ "$target" == */* ]]; then
        model="${target%%/*}"
        app="${target#*/}"
    else
        model="$target"
    fi

    if ! command -v juju &>/dev/null; then
        _record SKIP "$name" "juju command not found — skipping"
        return
    fi

    local raw exit_code=0
    if [[ -n "$app" ]]; then
        raw=$(timeout "$TIMEOUT" juju status -m "$model" "$app" --format json 2>&1) || exit_code=$?
    else
        raw=$(timeout "$TIMEOUT" juju status -m "$model" --format json 2>&1) || exit_code=$?
    fi

    if [[ $exit_code -ne 0 || -z "$raw" ]]; then
        _record FAIL "$name" "juju status -m '${model}' failed: ${raw}"
        return
    fi

    # Parse unit statuses via python3 (always available on Ubuntu)
    # Note: use -c to avoid heredoc/pipe stdin conflict (both can't be stdin at once)
    local summary
    summary=$(printf '%s' "$raw" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception as e:
    print(f"parse error: {e}")
    sys.exit(0)
ok = blocked = maintenance = 0
issues = []
for app_name, app_data in d.get("applications", {}).items():
    for unit_name, unit_data in app_data.get("units", {}).items():
        ws  = unit_data.get("workload-status", {}).get("current", "unknown")
        js  = unit_data.get("juju-status",    {}).get("current", "unknown")
        msg = unit_data.get("workload-status", {}).get("message", "")
        if ws in ("error", "blocked") or js in ("error", "failed"):
            blocked += 1
            issues.append(f"{unit_name}: {ws}/{js}" + (f" ({msg})" if msg else ""))
        elif ws in ("maintenance", "waiting", "allocating") or js in ("allocating", "rebooting"):
            maintenance += 1
            issues.append(f"{unit_name}: {ws}/{js}")
        else:
            ok += 1
total = ok + blocked + maintenance
detail = f"{total} units: {ok} OK"
if maintenance: detail += f", {maintenance} not-ready"
if blocked: detail += f", {blocked} blocked/error"
if issues: detail += " — " + "; ".join(issues[:3]) + ("..." if len(issues) > 3 else "")
if not d.get("applications"):
    detail = "no applications found"
    print(f"WARN:{detail}")
elif blocked:
    print(f"FAIL:{detail}")
elif maintenance:
    print(f"WARN:{detail}")
else:
    print(f"OK:{detail}")
') || true

    local status_flag="${summary%%:*}"
    local detail="${summary#*:}"
    local label="model:${model}${app:+/}${app}"

    case "$status_flag" in
        OK)   _record OK   "$name" "juju ${label}: ${detail}" ;;
        FAIL) _record FAIL "$name" "juju ${label}: ${detail}" ;;
        WARN) _record WARN "$name" "juju ${label}: ${detail}" ;;
        *)    _record WARN "$name" "juju ${label}: ${summary}" ;;
    esac
}

# =============================================================================
# Print a single result line
# =============================================================================
COL_NAME=28

_print_result() {
    local status="$1" name="$2" msg="$3"
    local label
    case "$status" in
        OK)   label="${GREEN}[  OK  ]${NC}" ;;
        WARN) label="${YELLOW}[ WARN ]${NC}" ;;
        FAIL) label="${RED}[ FAIL ]${NC}"  ;;
        SKIP) label="${DIM}[ SKIP ]${NC}"  ;;
    esac

    if [[ "$status" != "OK" ]] || $VERBOSE; then
        printf "  %b  %-${COL_NAME}s  %b%s%b\n" "$label" "$name" "$DIM" "$msg" "$NC"
    else
        printf "  %b  %s\n" "$label" "$name"
    fi
}

# =============================================================================
# Main: read config, run checks, print results
# =============================================================================
echo ""
echo -e "  ${BOLD}MedCEA Health Check${NC}  $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "  ${DIM}Config: ${CONFIG_FILE}  |  Timeout: ${TIMEOUT}s${NC}"
echo ""

while IFS='|' read -r name type target options || [[ -n "$name" ]]; do
    # Skip comments and blank lines
    name="$(_trim "$name")"
    [[ "$name" =~ ^# ]] && continue
    [[ -z "$name" ]] && continue

    type="$(    _trim "$type")"
    target="$(  _trim "$target")"
    options="$( _trim "${options:-}")"

    # Expand $VAR references sourced from config.env
    # Using printf '%s' to avoid issues with backslashes in URLs
    target="$(eval printf '%s' "\"${target}\"" 2>/dev/null || echo "$target")"

    case "$type" in
        k8s)  check_k8s  "$name" "$target" ;;
        http) check_http "$name" "$target" "$options" ;;
        tcp)  check_tcp  "$name" "$target" ;;
        mqtttls) check_mqtttls "$name" "$target" ;;
        pvc)  check_pvc  "$name" "$target" ;;
        juju) check_juju "$name" "$target" ;;
        iamchain) check_iamchain "$name" "$target" ;;
        iamanchor)  check_iamanchor "$name" "$target" ;;
        iamdbroles) check_iamdbroles "$name" "$target" ;;
        iamgrants)  check_iamgrants "$name" "$target" ;;
        iamcatalog) check_iamcatalog "$name" "$target" ;;
        controlloops) check_controlloops "$name" "$target" ;;
        controllers)  check_controllers "$name" "$target" ;;
        iampolicy)    check_iampolicy "$name" "$target" ;;
        iamartefacts) check_iamartefacts "$name" "$target" ;;
        iamdecisions) check_iamdecisions "$name" "$target" ;;
        iampending)   check_iampending "$name" "$target" ;;
        iamdrift)     check_iamdrift "$name" "$target" ;;
        dbclients)  check_dbclients "$name" ;;
        postgrest)  check_postgrest "$name" "$target" ;;
        iamenforce)   check_iamenforce "$name" "$target" ;;
        iammqtt)      check_iammqtt "$name" "$target" ;;
        grafanarole)  check_grafanarole "$name" "$target" ;;
        iamworkbench) check_iamworkbench "$name" "$target" ;;
        noderedflows) check_noderedflows "$name" "$target" ;;
        noderedauth)  check_noderedauth "$name" "$target" ;;
        onboardroles) check_onboardroles "$name" ;;
        pgadminroles) check_pgadminroles "$name" "$target" ;;
        supersetroles) check_supersetroles "$name" "$target" ;;
        apparmor)     check_apparmor "$name" ;;
        backupage)    check_backupage "$name" "$target" ;;
        manual)       check_manual "$name" "$target" ;;
        iamloaded)    check_iamloaded "$name" "$target" ;;
        jwks)         check_jwks "$name" "$target" ;;
        kcscopes)     check_kcscopes "$name" "$target" ;;
        iamnetpol)    check_iamnetpol "$name" "$target" ;;
        rsnetpol)     check_rsnetpol "$name" "$target" ;;
        rsexport)     check_rsexport "$name" "$target" ;;
        rsgrants)     check_rsgrants "$name" "$target" ;;
        rslake)       check_rslake "$name" "$target" ;;
        gwnetpol)     check_gwnetpol "$name" "$target" ;;
        ranetpol)     check_ranetpol "$name" "$target" ;;
        rschain)      check_rschain "$name" "$target" ;;
        rsanchor)     check_rsanchor "$name" "$target" ;;
        rsagent)      check_rsagent "$name" "$target" ;;
        rsllm)        check_rsllm "$name" "$target" ;;
        rsconsole)    check_rsconsole "$name" "$target" ;;
        wbaccounts)   check_wbaccounts "$name" "$target" ;;
        "")   continue ;;  # blank type (trailing whitespace only line)
        *)    _record WARN "$name" "Unknown check type '${type}'" ;;
    esac

    # Print result immediately as each check completes
    last="${_RESULTS[-1]}"
    IFS='|' read -r _s _n _m <<< "$last"
    _print_result "$_s" "$_n" "$_m"

done < "$CONFIG_FILE"

# =============================================================================
# Summary
# =============================================================================
TOTAL=$(( PASS + WARN + FAIL + SKIP ))
echo ""
echo -n "  "
if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All ${TOTAL} checks passed.${NC}"
elif [[ $FAIL -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}${PASS} OK, ${WARN} warning(s), 0 failures${NC}${DIM} — ${TOTAL} checks${NC}"
else
    echo -e "${RED}${BOLD}${FAIL} failure(s)${NC}, ${YELLOW}${WARN} warning(s)${NC}, ${GREEN}${PASS} OK${NC}${DIM} — ${TOTAL} checks${NC}"
fi
echo ""

# Exit non-zero if any failures
[[ $FAIL -eq 0 ]]
