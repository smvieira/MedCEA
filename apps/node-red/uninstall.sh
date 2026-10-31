#!/usr/bin/env bash
# apps/node-red/uninstall.sh — remove the flows apps/node-red/deploy.sh pushed.
#
# deploy.sh merges by node id: it replaces nodes whose ids appear in
# apps/node-red/flows/*.json and appends the rest. This is the exact inverse:
# only nodes with those ids are removed, so flows a user built in the editor
# stay. Palette packages from packages.txt stay installed (other flows may use
# them). Node-RED itself is infrastructure and keeps running.
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"   # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-node-red.sh"   # nr_curl: the admin API's deploy token (IAM 3.3)

NAMESPACE="${NAMESPACE:-medcea}"
NR_LOCAL_PORT="${NR_LOCAL_PORT:-1880}"
NR_BASE="http://localhost:${NR_LOCAL_PORT}"

NR_POD=$($KUBECTL get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=node-red" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "$NR_POD" ]]; then
    echo "==> Node-RED is not running — no flows to remove."
    exit 0
fi

# Port-forward bypasses the oauth2-proxy ingress, as in deploy.sh; adminAuth still
# wants the deploy token (nr_curl). The Secrets, ConfigMaps and the /data volume
# belong to deploy-infra.sh and stay.
nr_token "$NAMESPACE"
$KUBECTL port-forward -n "$NAMESPACE" "pod/$NR_POD" "${NR_LOCAL_PORT}:1880" &>/tmp/nr-portforward.log 9>&- &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true; rm -f /tmp/nr-current-flows.json /tmp/nr-pruned-flows.json' EXIT

echo -n "==> Waiting for Node-RED"
for i in $(seq 1 30); do
    nr_curl "$NAMESPACE" -sf "$NR_BASE/flows" -o /tmp/nr-current-flows.json 2>/dev/null && { echo " ready"; break; }
    [[ "$i" -eq 30 ]] && { echo " TIMEOUT"; echo "ERROR: Node-RED did not answer within 30 seconds" >&2; exit 1; }
    sleep 1; echo -n "."
done

REMOVED=$(python3 - "$SCRIPT_DIR/flows" <<'PYEOF'
import glob, json, os, sys
shipped = set()
for f in glob.glob(os.path.join(sys.argv[1], "*.json")):
    shipped |= {n["id"] for n in json.load(open(f)) if "id" in n}
current = json.load(open("/tmp/nr-current-flows.json"))
kept = [n for n in current if n.get("id") not in shipped]
json.dump(kept, open("/tmp/nr-pruned-flows.json", "w"))
print(len(current) - len(kept))
PYEOF
)

if [[ "$REMOVED" -eq 0 ]]; then
    echo "==> No MedCEA flows deployed — nothing to remove."
    exit 0
fi

HTTP=$(nr_curl "$NAMESPACE" -s -X POST "$NR_BASE/flows" -H "Content-Type: application/json" \
    -d @/tmp/nr-pruned-flows.json -o /dev/null -w "%{http_code}" || echo "000")
if [[ "$HTTP" == "200" || "$HTTP" == "204" ]]; then
    echo "==> Removed $REMOVED Node-RED nodes shipped by apps/node-red/flows"
else
    echo "ERROR: could not update Node-RED flows (HTTP $HTTP)" >&2
    exit 1
fi
