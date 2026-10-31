#!/usr/bin/env bash
# apps/node-red/deploy.sh — Deploy Node-RED flows and install required packages
#
# Idempotent: packages are skipped if already installed; flows are merged by node ID
# (existing nodes with the same ID are replaced, new nodes are appended).
#
# Run from the repository root: ./apps/node-red/deploy.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-db-roles.sh"   # db_client (IAM 2.5)
source "$REPO_ROOT/infra/lib-node-red.sh"   # nr_curl / nr_flow_values (IAM 3.3)

NAMESPACE="${NAMESPACE:-medcea}"
NR_LOCAL_PORT="${NR_LOCAL_PORT:-1880}"

# The flows' host names, topic root and database come from nr_flow_values, which
# health-check.sh noderedflows reads too. The broker admits nobody anonymously: Node-RED signs in as the service
# account "node-red" (read-only on the topic root). The password is generated
# once by deploy-infra.sh and hashed into the Secret mosquitto-service-auth.
if [[ -z "${MQTT_NODE_RED_PASS:-}" ]]; then
    echo "ERROR: MQTT_NODE_RED_PASS is not set in config.env — run ./deploy-infra.sh first." >&2
    exit 1
fi
# postgres, or svc_ingest once IAM_DB_SERVICE_ROLES=true and the role may log in (IAM 2.5)
db_client "$NAMESPACE" svc_ingest
PG_USER="$DBC_USER"
PG_PASS="$DBC_PASS"

NR_BASE="http://localhost:${NR_LOCAL_PORT}"
# Node-RED's admin API wants the deploy token since IAM 3.3 (adminAuth); nr_curl sends
# it as a header from a pipe. Read once here, so the $(nr_curl ...) calls reuse it.
nr_token "$NAMESPACE"

# ---------------------------------------------------------------------------
# Step 1: Apply database schema (prerequisite)
# ---------------------------------------------------------------------------
echo "==> [1/3] Applying database schema..."
"$SCRIPT_DIR/../database/deploy.sh"

# ---------------------------------------------------------------------------
# Step 2: Port-forward to Node-RED (bypasses oauth2-proxy ingress, not adminAuth)
# ---------------------------------------------------------------------------
echo "==> [2/3] Setting up Node-RED port-forward..."

NR_POD=$($KUBECTL get pod \
    -n "$NAMESPACE" \
    -l "app.kubernetes.io/name=node-red" \
    -o jsonpath='{.items[0].metadata.name}' || true)
# stderr kept, failure tolerated: see apps/database/deploy.sh (silent set -e exit).

if [[ -z "$NR_POD" ]]; then
    echo "ERROR: No Node-RED pod found in namespace $NAMESPACE" >&2
    echo "       Check: microk8s kubectl get pods -n $NAMESPACE" >&2
    exit 1
fi

echo "    Pod: $NR_POD"

# Working files in a private directory (mode 700), removed on exit: the rendered and
# merged flows hold the ingest database and broker passwords.
NR_TMP="$(mktemp -d)"
trap 'rm -rf "$NR_TMP"' EXIT

# Start port-forward in background; kill it on exit
$KUBECTL port-forward \
    -n "$NAMESPACE" \
    "pod/$NR_POD" \
    "${NR_LOCAL_PORT}:1880" &>"$NR_TMP/portforward.log" 9>&- &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true; rm -rf "$NR_TMP"' EXIT

# Wait for Node-RED to be reachable
echo -n "    Waiting for Node-RED"
for i in $(seq 1 30); do
    if nr_curl "$NAMESPACE" -sf "$NR_BASE/flows" -o /dev/null 2>/dev/null; then
        echo " ready"
        break
    fi
    if [[ "$i" -eq 30 ]]; then
        echo " TIMEOUT"
        echo "ERROR: Node-RED did not become reachable within 30 seconds" >&2
        exit 1
    fi
    sleep 1
    echo -n "."
done

# ---------------------------------------------------------------------------
# Step 3: Install packages and deploy flows
# ---------------------------------------------------------------------------
echo "==> [3/3] Installing packages and deploying flows..."

# Install packages listed in packages.txt
while IFS= read -r pkg || [[ -n "$pkg" ]]; do
    [[ -z "$pkg" || "$pkg" == \#* ]] && continue

    echo -n "    Package $pkg: "

    STATUS=$(nr_curl "$NAMESPACE" -sf "$NR_BASE/nodes/$pkg" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
    if [[ "$STATUS" == "200" ]]; then
        echo "already installed"
        continue
    fi

    HTTP=$(nr_curl "$NAMESPACE" -sf -X POST "$NR_BASE/nodes" \
        -H "Content-Type: application/json" \
        -d "{\"module\":\"$pkg\"}" \
        -o "$NR_TMP/pkg.log" \
        -w "%{http_code}" 2>/dev/null || echo "000")

    if [[ "$HTTP" == "200" ]]; then
        echo "installed"
    else
        echo "FAILED (HTTP $HTTP) — $(cat "$NR_TMP/pkg.log" 2>/dev/null)"
        echo "ERROR: Install $pkg manually via the Node-RED palette manager, then re-run." >&2
        exit 1
    fi

    # Give Node-RED time to reload after package install
    sleep 5
    echo -n "    Waiting for Node-RED to reload"
    for i in $(seq 1 20); do
        if nr_curl "$NAMESPACE" -sf "$NR_BASE/flows" -o /dev/null 2>/dev/null; then
            echo " ready"
            break
        fi
        sleep 2
        echo -n "."
    done

done < "$SCRIPT_DIR/packages.txt"

# Deploy each flow template
for flow_file in "$SCRIPT_DIR/flows/"*.json; do
    flow_name="$(basename "$flow_file" .json)"
    echo "    Deploying flow: $flow_name"

    # Fill the placeholders: the non-secret ones from nr_flow_values (health-check.sh
    # noderedflows diffs against the same), the passwords and the database user through
    # flows_diff.py's environment, never on a command line.
    NR_MQTT_PASS="$MQTT_NODE_RED_PASS" NR_PG_USER="$PG_USER" NR_PG_PASS="$PG_PASS" \
        python3 "$SCRIPT_DIR/flows_diff.py" render "$flow_file" \
        < <(nr_flow_values "$NAMESPACE") > "$NR_TMP/new-flow.json"

    # Get current flows from Node-RED
    nr_curl "$NAMESPACE" -sf "$NR_BASE/flows" > "$NR_TMP/current-flows.json" 2>/dev/null

    # Merge: drop any nodes whose IDs appear in the new flow, then append new nodes
    NR_TMP="$NR_TMP" python3 << 'PYEOF'
import json, os

d = os.environ['NR_TMP']
with open(os.path.join(d, 'new-flow.json')) as f:
    new_nodes = json.load(f)

with open(os.path.join(d, 'current-flows.json')) as f:
    current = json.load(f)

new_id_set = {n['id'] for n in new_nodes}
kept = [n for n in current if n.get('id') not in new_id_set]
merged = kept + new_nodes

with open(os.path.join(d, 'merged-flows.json'), 'w') as f:
    json.dump(merged, f)
PYEOF

    HTTP=$(nr_curl "$NAMESPACE" -sf -X POST "$NR_BASE/flows" \
        -H "Content-Type: application/json" \
        -d @"$NR_TMP/merged-flows.json" \
        -o "$NR_TMP/deploy.log" \
        -w "%{http_code}" 2>/dev/null || echo "000")

    if [[ "$HTTP" == "200" || "$HTTP" == "204" ]]; then
        echo "    Flow '$flow_name' deployed"
    else
        echo "ERROR: Flow deploy failed (HTTP $HTTP)" >&2
        echo "       $(cat "$NR_TMP/deploy.log" 2>/dev/null)" >&2
        exit 1
    fi
done

echo ""
echo "==> Deployment complete"
echo "    Node-RED: https://node-red.${DOMAIN:-<domain>}"
