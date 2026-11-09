#!/usr/bin/env bash
#
# infra/deploy-policy.sh — ./deploy-infra.sh --policy-only (IAM 4.2b, design §14.5).
#
# Re-renders only deploy-infra's compiled policy artefacts that drifted from the
# applied policy, and nothing else: no configure, bootstrap, Docker Hub, TLS, DNS,
# Keycloak realm or PostgreSQL step. Each target (infra/lib-policy-artefacts.sh) is
# compared with its compile and left alone when equal, so a second run prints
# "unchanged" for every one and writes nothing:
#
#   medcea-iam-lib   route table, MQTT rows, library, settings (iam-api restarts only
#                    when the MQTT digest moved, and the person credentials of the old
#                    digest end, as a full deploy does)
#   netpol           the application pods' NetworkPolicies
#   node-red-auth    Node-RED's editor rights (a directory mount: no restart)
#   grafana          Grafana's role path — on a drift the whole Grafana section
#   NODE_RED_DOMAIN  Node-RED's gate (helm, no forced restart)
#   pgadmin          pgAdmin's sign-in claims — on a drift the whole pgAdmin section
#                    (only then does it ask Keycloak who gets the server entry)
#   PORTAL_DOMAIN    the portal's gate (helm, no forced restart)
#
# Run by deploy-infra.sh (exec, right after its --help branch), by apply.sh --resume
# and by ./medcea.sh → Policy → Re-render the policy artefacts. Takes the deploy lock
# unless a parent holds it.

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
if [[ $# -gt 0 ]]; then
    echo "ERROR: unknown arguments: $* (usage: ./deploy-infra.sh --policy-only)" >&2
    exit 2
fi

# SCRIPT_DIR is the repository, as in deploy-infra.sh: the moved blocks use it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$SCRIPT_DIR"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/infra/lib-log.sh"; medcea_log deploy-infra-policy   # logs/deploy-infra-policy-<ts>.log, unless a parent logs
source "$SCRIPT_DIR/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from apply.sh or the guide
[[ -f config.env ]] || { echo "ERROR: config.env not found in $SCRIPT_DIR (run ./deploy-infra.sh first)." >&2; exit 1; }
# shellcheck source=/dev/null
source config.env
set -e

case ":$PATH:" in *:/snap/bin:*) ;; *) PATH="$PATH:/snap/bin" ;; esac
if microk8s status --timeout 5 >/dev/null 2>&1; then MK8S="microk8s"; else MK8S="sudo microk8s"; fi
KUBECTL="$MK8S kubectl"
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; NC='\033[0m'
NAMESPACE="${NAMESPACE:-medcea}"
echo "mode: policy-only"

source "$SCRIPT_DIR/infra/lib-render.sh"
source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh"     # policy_groups, policy_grafana, pa_gate_state
source "$SCRIPT_DIR/infra/lib-keycloak-admin.sh"   # pgAdmin's server entry, on a claims drift only
source "$SCRIPT_DIR/infra/lib-db-roles.sh"         # db_client (Grafana, pgAdmin sections)
source "$SCRIPT_DIR/infra/lib-policy-source.sh"
source "$SCRIPT_DIR/infra/lib-policy-artefacts.sh"

# The API wait of deploy-infra.sh
echo -e "${YELLOW}Waiting for Kubernetes API to be ready...${NC}"
DEADLINE=$(($(date +%s) + 120))
until $KUBECTL cluster-info &>/dev/null; do
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo -e "${RED}ERROR: Kubernetes API did not become ready after 2 min.${NC}"
        exit 1
    fi
    sleep 5
done

# Write mode, as every compiling entry script: the skeleton gate, break-glass, the host file.
policy_source_init "$NAMESPACE" || exit $?

echo -e "\n${GREEN}[policy-only] The compiled policy artefacts of deploy-infra (unchanged ones are left alone)${NC}"
pa_iam_lib scoped
if [[ "$PA_MQTT_CHANGED" == 1 ]]; then
    # the database step of deploy-infra, for the MQTT digest only (IAM_MQTT_PERSON's
    # switch record stays with the full deploy: a switch, not a policy change)
    _PG_EXEC=($MK8S kubectl exec -n "$NAMESPACE" rdbms-postgresql-0 -- env PGPASSWORD="$POSTGRES_PASS" psql -U "$POSTGRES_USER" -d postgres -tAc)
    if [[ "$("${_PG_EXEC[@]}" "SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DB'" | tr -d '[:space:]')" == "1" ]]; then
        source "$SCRIPT_DIR/apps/database/lib-db-apply.sh"
        _MQP=false; [[ "${IAM_MQTT_PERSON:-false}" == "true" ]] && _MQP=true
        pa_mqtt_retire
    fi
fi
pa_netpol scoped
pa_node_red_auth scoped
policy_grafana || { echo -e "${RED}ERROR: cannot compile Grafana's role setting from the access policy (python3 apps/iam/compiler/cli.py check).${NC}" >&2; exit 1; }
pa_grafana scoped
pa_node_red_proxy scoped
pa_pgadmin scoped
pa_portal_proxy scoped

# The last command of the success path: ends an open policy break-glass for infra (IAM 4.2a)
policy_source_finish "$NAMESPACE" infra
