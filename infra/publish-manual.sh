#!/usr/bin/env bash
# infra/publish-manual.sh — build the platform manual from docs/manual/chapters and publish
# it to the portal (https://<PORTAL_DOMAIN>/manual/), and nothing else.
#
#   ./infra/publish-manual.sh
#
# After a change to the manual: no full ./deploy-infra.sh needed (which publishes it too).
# Builds into a temporary file (docs/manual/build.py --out; the working tree is not
# touched), refuses when build.py refuses or the page would not fit in a ConfigMap,
# replaces ConfigMap portal-manual, restarts the portal and waits for it. Takes the deploy
# lock; logs to logs/publish-manual-<ts>.log. ./medcea.sh → Infrastructure → Publish the
# manual to the portal runs it. infra/lib-manual.sh does the work.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

case "${1:-}" in
    -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "") ;;
    *) echo "Unknown option '$1' (see --help)" >&2; exit 2 ;;
esac

source "$REPO_ROOT/infra/lib-log.sh"; medcea_log publish-manual    # logs/publish-manual-<ts>.log
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock                 # one deploy at a time
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$REPO_ROOT/infra/lib-mk8s.sh"    # mk8s / $MK8S / $KUBECTL (sudo fallback)
source "$REPO_ROOT/infra/lib-manual.sh"
NAMESPACE="${NAMESPACE:-medcea}"

echo "Publishing the platform manual to the portal (namespace $NAMESPACE)..."
manual_publish "$NAMESPACE"
if [[ "$MANUAL_SERVED" == yes ]]; then
    echo "Done: https://${PORTAL_DOMAIN:-portal.<domain>}/manual/ (the portal's Platform manual card)."
else
    echo "Done: the manual is stored, but not served yet (see above)."
fi
