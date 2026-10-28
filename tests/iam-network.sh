#!/usr/bin/env bash
# tests/iam-network.sh — the application pods' NetworkPolicies (IAM plan 1.4) block what
# they should and nothing the platform needs.
#
#   blocked   a throwaway pod (busybox, no platform labels) cannot reach any application
#             pod: not through its Services, and not on the pods' internal ports
#             (Flask on :8082, the file server on :8081) — every attempt times out
#   control   the same pod does reach Keycloak (no policy of ours), so "blocked" is the
#             policy and not a pod without a network
#   allowed   the Config UI's nginx reaches config-api and the scheduler; the host reaches
#             config-api (edge wizard, platform_db.py); ingress-nginx serves the public
#             access request form
# Real sessions through every proxy are tests/iam-signin.sh.
#
# Takes the deploy lock (it starts a pod, deleted on exit). Run from the repository root:
#   tests/iam-network.sh        Exit 1 on any FAIL.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
if [[ ! -f config.env ]]; then
    echo "config.env not found — run ./deploy-infra.sh first." >&2
    exit 2
fi
# shellcheck disable=SC1091
source config.env
source infra/lib-lock.sh; medcea_lock
source infra/lib-mk8s.sh

FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %-8s %s\n" "$1" "$2"; }
fail() { printf "  ${RED}FAIL${NC}  %-8s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }

NS="$NAMESPACE"
PROBE="iam-net-probe-$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
cleanup() { $KUBECTL delete pod -n "$NS" "$PROBE" --ignore-not-found --wait=false >/dev/null 2>&1; }
trap cleanup EXIT
trap 'exit 130' INT TERM

echo -e "${BOLD}Application pod network policies${NC} (namespace $NS)"
n="$($KUBECTL get netpol -n "$NS" -l medcea/iam-netpol=true -o name 2>/dev/null | wc -l)"
if [[ "$n" -eq 0 ]]; then
    echo -e "${YELLOW}No policy labelled medcea/iam-netpol=true (IAM_NETPOL=false, or ./deploy-infra.sh not run).${NC}"
    exit 1
fi
echo "$n policies; starting $PROBE ..."
$KUBECTL run "$PROBE" -n "$NS" --image=busybox:1.36 --restart=Never --labels=medcea/test=iam-network \
    --command -- sleep 600 >/dev/null
if ! $KUBECTL wait -n "$NS" --for=condition=Ready "pod/$PROBE" --timeout=120s >/dev/null; then
    echo "The probe pod did not start." >&2
    exit 1
fi

# wget's own words decide: a timeout is a dropped connection; an HTTP answer or a
# refusal means the packet got through; anything else (kubectl exec failing, a DNS
# error) is "error" — never counted as either.
reach() {   # target container url → "open" | "blocked" | "error: …"
    local out rc
    out="$($KUBECTL exec -n "$NS" "$1" -c "$2" -- wget -q -T 4 -O /dev/null "$3" 2>&1)"; rc=$?
    case "$out" in
        *"timed out"*)                                              echo blocked ;;
        *"server returned error"*|*"HTTP/"*|*"Connection refused"*) echo open ;;
        "")  [[ $rc -eq 0 ]] && echo open || echo "error: exit $rc, no output" ;;
        *)   echo "error: ${out:0:100}" ;;
    esac
}
podip() {
    local ip; ip="$($KUBECTL get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)"
    echo "${ip:-no-pod-for-app-$1}"
}

echo ""
for url in http://scheduler.$NS/ http://monitor.$NS/ http://dbmgmt.$NS/ http://config-ui.$NS/ \
           http://config-api.$NS:3000/ http://access-admin.$NS/healthz http://access-profile.$NS/_account/ \
           http://access-public.$NS/register \
           "http://$(podip scheduler):8082/api/runs" "http://$(podip monitor):8082/api/runs" \
           "http://$(podip dbmgmt):8081/objects" "http://$(podip config-ui):8081/devices/" \
           "http://$(podip access):8080/register" "http://$(podip access):8081/healthz" "http://$(podip access):8082/_account/"; do
    r="$(reach "pod/$PROBE" "$PROBE" "$url")"
    case "$r" in
        blocked) pass blocked "$url" ;;
        open)    fail blocked "$url answered the probe pod" ;;
        *)       fail blocked "$url: the probe could not run ($r)" ;;
    esac
done

echo ""
r="$(reach "pod/$PROBE" "$PROBE" "http://keycloak.$NS/realms/$KEYCLOAK_REALM")"
[[ "$r" == open ]] && pass control "the probe pod reaches Keycloak, so its network works" \
    || fail control "the probe pod does not reach Keycloak ($r) — the blocked results above prove nothing"

echo ""
for url in "http://config-api.$NS.svc.cluster.local:3000/" "http://scheduler.$NS.svc.cluster.local/"; do
    r="$(reach deployment/config-ui nginx "$url")"
    [[ "$r" == open ]] && pass allowed "config-ui → $url" || fail allowed "config-ui → $url: $r (the Config UI breaks)"
done
api_ip="$($KUBECTL get svc -n "$NS" config-api -o jsonpath='{.spec.clusterIP}')"
code="$(curl -s -o /dev/null -m 6 -w '%{http_code}' "http://$api_ip:3000/")"
[[ "$code" =~ ^[2-4] ]] && pass allowed "host → config-api ($code; the edge wizard's path)" \
    || fail allowed "host cannot reach config-api ($code): onboarding cannot register boards"
code="$(curl -sk -o /dev/null -m 6 -w '%{http_code}' "https://$ACCESS_DOMAIN/register")"
[[ "$code" == 200 ]] && pass allowed "ingress → access-public (https://$ACCESS_DOMAIN/register: $code)" \
    || fail allowed "https://$ACCESS_DOMAIN/register answered $code: the request form is down"

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}The application pods admit exactly their proxies and the listed hops.${NC}"
else
    echo -e "${RED}${BOLD}${FAILS} check(s) failed.${NC}  Rollback: IAM_NETPOL=false and ./deploy-infra.sh,"
    echo "or at once: microk8s kubectl delete netpol -n $NS -l medcea/iam-netpol=true"
    exit 1
fi
