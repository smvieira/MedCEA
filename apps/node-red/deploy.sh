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

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"

NAMESPACE="${NAMESPACE:-medcea}"
NR_LOCAL_PORT="${NR_LOCAL_PORT:-1880}"

# K8s service names (stable in-cluster DNS, independent of IP changes)
MQTT_HOST="mosquitto.${NAMESPACE}.svc.cluster.local"
PG_RELEASE_NAME="${PG_RELEASE:-rdbms}"
PG_HOST="${PG_RELEASE_NAME}-postgresql.${NAMESPACE}.svc.cluster.local"
PG_PORT="5432"
PG_DB="${POSTGRES_DB:-postgres}"
PG_USER="${POSTGRES_USER:-postgres}"
PG_PASS="${POSTGRES_PASS}"

NR_BASE="http://localhost:${NR_LOCAL_PORT}"

# ---------------------------------------------------------------------------
# Step 1: Apply database schema (prerequisite)
# ---------------------------------------------------------------------------
echo "==> [1/3] Applying database schema..."
"$SCRIPT_DIR/../database/deploy.sh"

# ---------------------------------------------------------------------------
# Step 2: Port-forward to Node-RED (bypasses oauth2-proxy ingress)
# ---------------------------------------------------------------------------
echo "==> [2/3] Setting up Node-RED port-forward..."

NR_POD=$(microk8s kubectl get pod \
    -n "$NAMESPACE" \
    -l "app.kubernetes.io/name=node-red" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [[ -z "$NR_POD" ]]; then
    echo "ERROR: No Node-RED pod found in namespace $NAMESPACE" >&2
    echo "       Check: sudo microk8s kubectl get pods -n $NAMESPACE" >&2
    exit 1
fi

echo "    Pod: $NR_POD"

# Start port-forward in background; kill it on exit
microk8s kubectl port-forward \
    -n "$NAMESPACE" \
    "pod/$NR_POD" \
    "${NR_LOCAL_PORT}:1880" &>/tmp/nr-portforward.log &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true' EXIT

# Wait for Node-RED to be reachable
echo -n "    Waiting for Node-RED"
for i in $(seq 1 30); do
    if curl -sf "$NR_BASE/flows" -o /dev/null 2>/dev/null; then
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

    STATUS=$(curl -sf "$NR_BASE/nodes/$pkg" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
    if [[ "$STATUS" == "200" ]]; then
        echo "already installed"
        continue
    fi

    HTTP=$(curl -sf -X POST "$NR_BASE/nodes" \
        -H "Content-Type: application/json" \
        -d "{\"module\":\"$pkg\"}" \
        -o /tmp/nr-pkg.log \
        -w "%{http_code}" 2>/dev/null || echo "000")

    if [[ "$HTTP" == "200" ]]; then
        echo "installed"
    else
        echo "FAILED (HTTP $HTTP) — $(cat /tmp/nr-pkg.log 2>/dev/null)"
        echo "ERROR: Install $pkg manually via the Node-RED palette manager, then re-run." >&2
        exit 1
    fi

    # Give Node-RED time to reload after package install
    sleep 5
    echo -n "    Waiting for Node-RED to reload"
    for i in $(seq 1 20); do
        if curl -sf "$NR_BASE/flows" -o /dev/null 2>/dev/null; then
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

    # Substitute connection placeholders into a temp file
    # __TOPIC_ROOT__ is the root the onboarding wizard configures on every board
    # it flashes (edge/flash-device.sh --topic-root, default PROJECT_NAME).
    sed \
        -e "s|__TOPIC_ROOT__|${PROJECT_NAME:-medcea}|g" \
        -e "s|__MQTT_HOST__|${MQTT_HOST}|g" \
        -e "s|__PG_HOST__|${PG_HOST}|g" \
        -e "s|__PG_PORT__|${PG_PORT}|g" \
        -e "s|__PG_DB__|${PG_DB}|g" \
        -e "s|__PG_USER__|${PG_USER}|g" \
        -e "s|__PG_PASS__|${PG_PASS}|g" \
        "$flow_file" > /tmp/nr-new-flow.json

    # Get current flows from Node-RED
    curl -sf "$NR_BASE/flows" > /tmp/nr-current-flows.json 2>/dev/null

    # Merge: drop any nodes whose IDs appear in the new flow, then append new nodes
    python3 << 'PYEOF'
import json

with open('/tmp/nr-new-flow.json') as f:
    new_nodes = json.load(f)

with open('/tmp/nr-current-flows.json') as f:
    current = json.load(f)

new_id_set = {n['id'] for n in new_nodes}
kept = [n for n in current if n.get('id') not in new_id_set]
merged = kept + new_nodes

with open('/tmp/nr-merged-flows.json', 'w') as f:
    json.dump(merged, f)
PYEOF

    HTTP=$(curl -sf -X POST "$NR_BASE/flows" \
        -H "Content-Type: application/json" \
        -d @/tmp/nr-merged-flows.json \
        -o /tmp/nr-deploy.log \
        -w "%{http_code}" 2>/dev/null || echo "000")

    if [[ "$HTTP" == "200" || "$HTTP" == "204" ]]; then
        echo "    Flow '$flow_name' deployed"
    else
        echo "ERROR: Flow deploy failed (HTTP $HTTP)" >&2
        echo "       $(cat /tmp/nr-deploy.log 2>/dev/null)" >&2
        exit 1
    fi
done

echo ""
echo "==> Deployment complete"
echo "    Node-RED: http://data-flow.${DOMAIN:-<domain>}"
