#!/usr/bin/env bash
# tests/iam-research.sh — the research zone keeps a notebook to what the access policy
# compiles for it (research sandbox Phase 2b): the hub, the snapshot reader and the
# internet on 443, nothing of the platform.
#
# Starts a throwaway pod in RESEARCH_NAMESPACE (default <NAMESPACE>-research) labelled as
# a notebook (app=jupyterhub, component=singleuser-server, release=workbench) plus
# medcea/probe=iam-research, so the zone's rs-notebooks NetworkPolicy applies to it and
# health-check rsgrants allows it no Secret: busybox 1.36 (already on the node), no
# service account token, PSA-baseline compliant, priorityClassName medcea-research-low;
# deleted on exit, also on Ctrl-C or failure.
#
#   blocked   every attempt times out: config-api :3000, the broker (mosquitto :1883,
#             mosquitto-ws :9001), PostgreSQL (rdbms-postgresql :5432), the scheduler (:80),
#             the research database (research-postgresql :5432: only lake-api, the export
#             and the backup may), the ingress controller's pods and the node on 80 and 443
#             (every platform host), the host's Tailscale address (when it has one) and,
#             with --wan-ip IP, the router's public address on 443 (a hairpin back to the
#             platform; the address is never looked up from an outside service)
#   reach     lake-api :3000 answers (HTTP), and one internet host on 443 answers
#             (--internet-host, default pypi.org: a plain HTTP request to its TLS port gets
#             an HTTP error back, which proves the connection)
# A timeout is a dropped connection; an HTTP answer or a refusal means the packet got
# through (on the WAN address a refusal is the router's own: no hairpin); anything else (kubectl exec failing, a DNS error) is an error, never counted as
# either. A hairpin that answers FAILs with the advice to add that address as a /32 to
# network.zones.research.internet_except by a skeleton version.
#
# Refuses (exit 2) unless the applied access policy places the AI workbench in the
# research zone (workbench_placement, infra/lib-policy-tools.sh). Read-only policy init;
# takes the deploy lock (it starts a pod). Run from the repository root:
#   tests/iam-research.sh [--wan-ip IP] [--internet-host HOST]      Exit 1 on any FAIL.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'

usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; }
WAN_IP="" INET_HOST="pypi.org"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --wan-ip)
            [[ "${2:-}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "--wan-ip needs an IPv4 address" >&2; exit 2; }
            WAN_IP="$2"; shift 2 ;;
        --internet-host)
            [[ "${2:-}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || { echo "--internet-host needs a host name" >&2; exit 2; }
            INET_HOST="$2"; shift 2 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
source infra/lib-log.sh; medcea_log iam-research   # logs/iam-research-<ts>.log, unless a parent logs
if [[ ! -f config.env ]]; then
    echo "config.env not found — run ./deploy-infra.sh first." >&2
    exit 2
fi
# shellcheck disable=SC1091
source config.env
source infra/lib-policy-source.sh; policy_source_init "${NAMESPACE:-medcea}" --read-only   # compile what the deploys compiled
source infra/lib-policy-tools.sh
PLACE="$(workbench_placement)" || { echo "Cannot read the access policy (python3 apps/iam/compiler/cli.py check)." >&2; exit 2; }
if [[ "$PLACE" != research ]]; then
    echo "The applied access policy places the AI workbench on the platform (no pod hub in the research zone):" >&2
    echo "nothing to test until its skeleton version is applied (./apps/iam/apply.sh --status)." >&2
    exit 2
fi
source infra/lib-lock.sh; medcea_lock
source infra/lib-mk8s.sh

FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %-8s %s\n" "$1" "$2"; }
fail() { printf "  ${RED}FAIL${NC}  %-8s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }
skip() { printf "  ${YELLOW}SKIP${NC}  %-8s %s\n" "$1" "$2"; }

NS="$NAMESPACE"
RNS="${RESEARCH_NAMESPACE:-${NS}-research}"
PROBE="iam-rs-probe-$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
cleanup() { $KUBECTL delete pod -n "$RNS" "$PROBE" --ignore-not-found --wait=false >/dev/null 2>&1; }
trap cleanup EXIT
trap 'exit 130' INT TERM

echo -e "${BOLD}Research zone network${NC} (namespace $RNS, a probe labelled as a notebook)"
if ! $KUBECTL get namespace "$RNS" >/dev/null 2>&1; then
    echo "Namespace $RNS does not exist (./deploy-infra.sh)." >&2
    exit 1
fi
n="$($KUBECTL get netpol -n "$RNS" -l medcea/rs-netpol=true -o name 2>/dev/null | grep -c 'rs-notebooks$' || true)"
if [[ "$n" -ne 1 ]]; then
    echo -e "${YELLOW}No NetworkPolicy rs-notebooks in $RNS: the zone's policies are not live (./deploy-infra.sh).${NC}" >&2
    exit 1
fi

# no service account token, no Secret, PSA baseline (no privilege, no host namespace)
OVERRIDES="$(python3 -c '
import json
print(json.dumps({"spec": {"automountServiceAccountToken": False, "enableServiceLinks": False,
                           "priorityClassName": "medcea-research-low",
                           "containers": [{"name": "probe", "image": "busybox:1.36", "command": ["sleep", "600"],
                                           "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                         "limits": {"memory": "32Mi"}},
                                           "securityContext": {"allowPrivilegeEscalation": False,
                                                               "capabilities": {"drop": ["ALL"]}}}]}}))')"
echo "Starting $PROBE ..."
if ! $KUBECTL run "$PROBE" -n "$RNS" --image=busybox:1.36 --restart=Never \
        --labels=app=jupyterhub,component=singleuser-server,release=workbench,medcea/probe=iam-research \
        --overrides="$OVERRIDES" >/dev/null; then
    echo "The probe pod could not be created (PSA, the quota?)." >&2
    exit 1
fi
if ! $KUBECTL wait -n "$RNS" --for=condition=Ready "pod/$PROBE" --timeout=120s >/dev/null; then
    echo "The probe pod did not start." >&2
    exit 1
fi

# wget's own words decide; the trailing rc= line proves the exec itself ran.
reach() {   # url → "open" | "refused" | "blocked" | "error: …"
    local out
    out="$($KUBECTL exec -n "$RNS" "$PROBE" -c probe -- sh -c 'wget -q -T 5 -O /dev/null "$0" 2>&1; echo "rc=$?"' "$1" 2>&1)"
    if ! grep -q '^rc=[0-9]*$' <<<"$out"; then
        echo "error: ${out:0:100}"; return
    fi
    out="$(grep -v '^rc=' <<<"$out")"
    case "$out" in
        *"timed out"*)                                                   echo blocked ;;
        *"Connection refused"*)                                          echo refused ;;
        *"server returned error"*|*"HTTP/"*|\
        *"error getting response"*|*"Connection reset"*|*"bad header"*) echo open ;;
        "")  echo open ;;
        *)   echo "error: ${out:0:100}" ;;
    esac
}
blocked() {   # what url: must time out
    local r; r="$(reach "$2")"
    case "$r" in
        blocked) pass blocked "$1 ($2)" ;;
        open|refused) fail blocked "$1 ($2) answered a notebook ($r: the packet got through)" ;;
        *)       fail blocked "$1 ($2): the probe could not run ($r)" ;;
    esac
}

echo ""
blocked "config-api"           "http://config-api.$NS.svc.cluster.local:3000/"
blocked "mosquitto"            "http://mosquitto.$NS.svc.cluster.local:1883/"
blocked "mosquitto-ws"         "http://mosquitto-ws.$NS.svc.cluster.local:9001/"
blocked "rdbms-postgresql"     "http://rdbms-postgresql.$NS.svc.cluster.local:5432/"
blocked "scheduler"            "http://scheduler.$NS.svc.cluster.local/"
blocked "research-postgresql"  "http://research-postgresql.$RNS.svc.cluster.local:5432/"
for ip in $($KUBECTL get pods -A -l name=nginx-ingress-microk8s -o jsonpath='{.items[*].status.podIP}' 2>/dev/null); do
    blocked "ingress (pod)" "http://$ip:80/"
    blocked "ingress (pod)" "http://$ip:443/"
done
for ip in $($KUBECTL get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="InternalIP")]}{.address}{" "}{end}{end}' 2>/dev/null); do
    blocked "node" "http://$ip:80/"
    blocked "node" "http://$ip:443/"
done
ts="$(command -v tailscale >/dev/null 2>&1 && tailscale ip -4 2>/dev/null | head -n1)"
if [[ "$ts" =~ ^100\. ]]; then
    blocked "Tailscale" "http://$ts:443/"
else
    skip blocked "the host has no Tailscale address"
fi
if [[ -n "$WAN_IP" ]]; then
    r="$(reach "http://$WAN_IP:443/")"
    case "$r" in
        blocked|refused) pass blocked "the router's WAN address $WAN_IP on 443 ($r: no hairpin to the platform)" ;;
        open)    fail hairpin "$WAN_IP:443 answered a notebook: the router forwards the platform back in. Add $WAN_IP/32 to network.zones.research.internet_except by a skeleton version (./apps/iam/apply.sh --propose-skeleton)" ;;
        *)       fail blocked "$WAN_IP:443: the probe could not run ($r)" ;;
    esac
else
    skip hairpin "no --wan-ip given: the router's hairpin is not checked"
fi

echo ""
r="$(reach "http://lake-api.$RNS.svc.cluster.local:3000/")"
[[ "$r" == open ]] && pass reach "lake-api :3000 (the snapshot reader)" \
    || fail reach "lake-api :3000: $r (./apps/lake-api/deploy.sh; the blocked results above prove nothing if the probe has no network)"
r="$(reach "http://$INET_HOST:443/")"
[[ "$r" == open ]] && pass reach "the internet on 443 ($INET_HOST)" \
    || fail reach "$INET_HOST:443: $r (pip and git over https need it)"

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}A notebook reaches the snapshot reader and the internet on 443, nothing of the platform.${NC}"
else
    echo -e "${RED}${BOLD}${FAILS} check(s) failed.${NC}  The zone's policies: ./health-check.sh (Research network policies),"
    echo "python3 apps/iam/compiler/cli.py compile netpol --zone research --namespace $RNS --platform-namespace $NS (plus --zone-namespace for each other research zone: zone_other_args research)"
    exit 1
fi
