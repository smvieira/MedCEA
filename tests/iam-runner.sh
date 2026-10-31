#!/usr/bin/env bash
# tests/iam-runner.sh — the scheduler API and its runner (IAM plan 2.4) end to end on
# the throwaway PostgreSQL of tests/iam-db-fixture.sh.
#
#   tests/iam-runner.sh --namespace medcea-iamtest --mode false|false-svc|true|legacy --dir DIR
#                       [--schd PATH] [--prev-schd PATH]
#
#   --mode      false / true: the database's IAM_DB_ROLES (the fixture step after
#               `logins MODE`); false-svc: false, with the scheduler on svc_scheduler
#               (IAM_DB_SERVICE_ROLES, plan 2.5; after `apply false` with the service
#               logins); legacy: before migration 008b (after `load`)
#   --dir       the fixture's IAMTEST_DIR: `passwords` (role password, mode 600)
#               gives svc_scheduler's password for --mode true and false-svc
#   --schd      the schd/ under test (default: this checkout's)
#   --prev-schd the schd/ of the commit before (R8 compares the two runners' runs)
#
# Starts pod iam-runner (tests/k8s/iam-runner.yaml: python:3.11-slim with the
# scheduler's packages) in the namespace, hands it the code as ConfigMap
# iam-runner-src (tarballs; nothing from the host is mounted, config.env least of
# all) and runs tests/runner/iam_runner_flow.py in it: the real scheduler-api.py
# through Flask's test client, as postgres (false) or svc_scheduler (false-svc, true), with
# tokens signed by a throwaway key made inside the pod, and run_recipe.py as the API
# spawns it. The pod, the ConfigMap and the Secret are deleted on exit.
#
# Refused unless the namespace is medcea-iamtest and carries the fixture's label
# medcea/test=iam-db — there is no override. Passwords go to the cluster on stdin,
# never in argv or the output. Takes the deploy lock (inherited from the fixture).
# Exit 1 on any FAIL.

set -uo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
source infra/lib-mk8s.sh
source infra/lib-render.sh
source infra/lib-lock.sh; medcea_lock

NS=""; MODE=""; DIR=""; SCHD="$REPO_ROOT/schd"; PREV=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace) NS="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --dir) DIR="$2"; shift 2 ;;
        --schd) SCHD="$2"; shift 2 ;;
        --prev-schd) PREV="$2"; shift 2 ;;
        *) echo "unknown option $1 (--help)" >&2; exit 2 ;;
    esac
done
if [[ "$NS" != "medcea-iamtest" ]]; then
    echo "REFUSED: tests/iam-runner.sh runs only against the throwaway namespace medcea-iamtest, never '${NS:-<none>}'." >&2
    exit 2
fi
if [[ "$($KUBECTL get namespace "$NS" -o jsonpath='{.metadata.labels.medcea/test}' 2>/dev/null)" != "iam-db" ]]; then
    echo "REFUSED: namespace $NS does not carry medcea/test=iam-db (start it with tests/iam-db-fixture.sh up)." >&2
    exit 2
fi
[[ "$MODE" == false || "$MODE" == false-svc || "$MODE" == true || "$MODE" == legacy ]] || { echo "--mode false|false-svc|true|legacy" >&2; exit 2; }
[[ -n "$DIR" && -d "$DIR" ]] || { echo "--dir: the fixture's IAMTEST_DIR" >&2; exit 2; }
[[ -f "$SCHD/run_recipe.py" ]] || { echo "--schd $SCHD has no run_recipe.py" >&2; exit 2; }
[[ -z "$PREV" || -f "$PREV/run_recipe.py" ]] || { echo "--prev-schd $PREV has no run_recipe.py" >&2; exit 2; }

BOLD='\033[1m'; NC='\033[0m'
echo -e "${BOLD}IAM 2.4 runner checks${NC} (namespace $NS, mode $MODE, schd $SCHD${PREV:+, previous $PREV})"

WORK="$(mktemp -d "$DIR/runner.XXXXXX")"
chmod 700 "$WORK"
cleanup() {
    $KUBECTL delete pod iam-runner -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1
    $KUBECTL delete configmap iam-runner-src -n "$NS" --ignore-not-found >/dev/null 2>&1
    $KUBECTL delete secret iam-runner-db -n "$NS" --ignore-not-found >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

# the code under test, as tarballs (no pid files, no bytecode)
tar czf "$WORK/src.tgz" --exclude=__pycache__ --exclude='*.pid' --exclude='*.pyc' \
    -C "$SCHD/.." "$(basename "$SCHD")" --transform "s,^$(basename "$SCHD"),schd," \
    -C "$REPO_ROOT" apps/scheduler/scheduler-api.py apps/scheduler/log_retention.py apps/iam/lib/medcea_iam.py tests/runner \
    || { echo "cannot pack the code under test" >&2; exit 1; }
if [[ -n "$PREV" ]]; then
    tar czf "$WORK/prev.tgz" --exclude=__pycache__ --exclude='*.pid' --exclude='*.pyc' \
        -C "$PREV/.." "$(basename "$PREV")" --transform "s,^$(basename "$PREV"),schd," \
        || { echo "cannot pack --prev-schd" >&2; exit 1; }
else
    : > "$WORK/prev.tgz"
fi
python3 apps/iam/compiler/cli.py compile routes > "$WORK/routes.json" || { echo "cannot compile the route table" >&2; exit 1; }
$KUBECTL create configmap iam-runner-src -n "$NS" --from-file=src.tgz="$WORK/src.tgz" \
    --from-file=prev.tgz="$WORK/prev.tgz" --from-file=routes.json="$WORK/routes.json" \
    --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null || exit 1

# svc_scheduler's password (IAM_DB_ROLES=true, or false-svc: false with the service
# roles logging in, IAM 2.5), from the fixture's file, on stdin
if [[ "$MODE" == true || "$MODE" == false-svc ]]; then
    [[ -f "$DIR/passwords" ]] || { echo "no $DIR/passwords (tests/iam-db-fixture.sh up)" >&2; exit 2; }
    awk '$1 == "svc_scheduler" { printf "%s", $2 }' "$DIR/passwords" \
        | $KUBECTL create secret generic iam-runner-db -n "$NS" --from-file=password=/dev/stdin \
            --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null || exit 1
fi

$KUBECTL delete pod iam-runner -n "$NS" --ignore-not-found --wait=true >/dev/null 2>&1
RUNNER_NS="$NS" render tests/k8s/iam-runner.yaml RUNNER_NS | $KUBECTL apply -f - >/dev/null || exit 1
if ! $KUBECTL wait --for=condition=Ready pod/iam-runner -n "$NS" --timeout=420s >/dev/null 2>&1; then
    echo "the runner pod did not become ready:" >&2
    $KUBECTL logs -n "$NS" iam-runner --tail=20 2>&1 | sed 's/^/    /' >&2
    exit 1
fi

$KUBECTL exec -n "$NS" iam-runner -- python3 /work/cur/tests/runner/iam_runner_flow.py --mode "$MODE"
rc=$?
exit $rc
