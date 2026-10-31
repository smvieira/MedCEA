#!/usr/bin/env bash
# apps/iam/uninstall.sh — the inverse of apps/iam/deploy.sh.
#
# Removes iam-api: Deployment iam-api, Service iam-mqttx and ConfigMap iam-api-code.
# Never the policy tables, their history, the MQTT person credentials or the database
# roles, which belong to apps/database and the Compliance Plane, and never ConfigMap
# medcea-iam-lib (deploy-infra.sh's). While IAM_MQTT_PERSON=true the MQTT Explorer then
# gets 502 on /_mqtt-credential: roll the switch back first (./guide.sh).
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
NAMESPACE="${NAMESPACE:-medcea}"

if [[ "${IAM_MQTT_PERSON:-false}" == "true" ]]; then
    echo -e "\033[0;33m[iam] IAM_MQTT_PERSON=true: the MQTT Explorer can no longer get a credential (502) until iam-api is back or the switch is rolled back (./guide.sh).\033[0m" >&2
fi
echo "[iam] Removing iam-api (Deployment, Service iam-mqttx, ConfigMap iam-api-code)..."
$KUBECTL delete deployment iam-api -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete service iam-mqttx -n "$NAMESPACE" --ignore-not-found
$KUBECTL delete configmap iam-api-code -n "$NAMESPACE" --ignore-not-found
echo "[iam] iam-api removed; the policy, its history and the credential tables stay."
