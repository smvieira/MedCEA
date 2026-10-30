#!/usr/bin/env bash
# tests/iam-check.sh — every Python service runs medcea_iam.check() (IAM plan 1.2) and a
# forged request does not get past it.
#
# For each service pod (scheduler, monitor, dbmgmt, config-ui's platform-api, access):
#   files    /iam/medcea_iam.py, /iam/routes.json, /iam/settings.json (ConfigMap
#            medcea-iam-lib) and /jwks/jwks.json (Secret medcea-jwks) are mounted, the
#            settings name this realm, and PyJWT imports in the container
#   forged   a request sent inside the pod straight to the service's port, past the
#            proxy, with forged X-Forwarded-Preferred-Username/-Groups (admin) and a
#            forged access token, leaves a "would refuse" line (IAM_ENFORCE=false) or a
#            "refused" line and a 401 (true) in the service's log; the access Admin port
#            always a "refused" line and a 401/403 (IAM 2.7: it enforces regardless)
# Real sessions through every proxy are tests/iam-signin.sh.
#
# Read-only: no lock; the forged requests are GETs. Run from the repository root:
#   tests/iam-check.sh        Exit 1 on any FAIL.

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
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
source infra/lib-mk8s.sh

FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %-7s %s\n" "$1" "$2"; }
fail() { printf "  ${RED}FAIL${NC}  %-7s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }

ISSUER="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM"
echo -e "${BOLD}Access check in every service${NC} (namespace $NAMESPACE, issuer $ISSUER)"

# deployment:container:port:route-table service:path (a route that needs a role)
for spec in scheduler:api:8082:scheduler:/api/runs \
            monitor:api:8082:monitor:/api/runs \
            dbmgmt:api:8081:dbmgmt:/objects \
            config-ui:recipe-fileserver:8081:platform-api:/devices/ \
            access:api:8081:access:/api/users; do
    IFS=: read -r dep ctr port svc path <<<"$spec"
    echo ""
    echo -e "${BOLD}$svc${NC}  ($dep/$ctr :$port)"
    ex() { $KUBECTL exec -i -n "$NAMESPACE" "deployment/$dep" -c "$ctr" -- "$@"; }

    out="$(ex python3 - "$ISSUER" 2>&1 <<'PY'
import json, os, sys
missing = [f for f in ("/iam/medcea_iam.py", "/iam/routes.json", "/iam/settings.json", "/jwks/jwks.json")
           if not os.access(f, os.R_OK)]
if missing:
    print("missing", " ".join(missing)); sys.exit()
s = json.load(open("/iam/settings.json"))
if s.get("issuer") != sys.argv[1]:
    print("issuer", s.get("issuer")); sys.exit()
keys = [k for k in json.load(open("/jwks/jwks.json")).get("keys", []) if k.get("alg") == "RS256"]
try:
    import jwt
except ImportError:
    print("nojwt"); sys.exit()
print("ok", "enforce" if s.get("enforce") else "report-only", len(keys))
PY
)"
    case "$out" in
        ok\ *)    read -r _ mode nkeys <<<"$out"
                  pass files "library, table, settings and $nkeys RS256 key(s) mounted; PyJWT present; $mode" ;;
        missing*) fail files "not mounted: ${out#missing } (./deploy-infra.sh, then redeploy the component)" ;;
        issuer*)  fail files "settings name issuer ${out#issuer }, want $ISSUER (./deploy-infra.sh)" ;;
        nojwt)    fail files "PyJWT does not import in $ctr (did pip reach PyPI at start?)" ;;
        *)        fail files "could not inspect the pod: ${out:0:120}" ;;
    esac

    t0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    code="$(ex python3 - "$port" "$path" 2>/dev/null <<'PY'
import sys, urllib.error, urllib.request
req = urllib.request.Request(f"http://127.0.0.1:{sys.argv[1]}{sys.argv[2]}", headers={
    "X-Forwarded-Preferred-Username": "admin", "X-Forwarded-User": "admin", "X-Forwarded-Groups": "admin",
    "X-Forwarded-Email": "admin@example.invalid", "X-Forwarded-Access-Token": "forged.token.value"})
try:
    print(urllib.request.urlopen(req, timeout=15).status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print(0)
PY
)"
    sleep 1
    line="$($KUBECTL logs -n "$NAMESPACE" "deployment/$dep" -c "$ctr" --since-time="$t0" 2>/dev/null \
            | grep -m1 "medcea_iam: \(would refuse\|refused\) GET $path on $svc")"
    if [[ -z "$line" ]]; then
        fail forged "GET $path with forged headers (answered $code) left no refusal in the log"
    elif [[ "$svc" == access && ( "$line" == *"would refuse"* || ( "$code" != 401 && "$code" != 403 ) ) ]]; then
        # IAM 2.7: the User Manager's Admin port enforces whatever IAM_ENFORCE says
        fail forged "the access Admin port must refuse for real (\"refused\" and 401/403), got $code: ${line:0:120}"
    elif [[ "$line" == *"would refuse"* ]]; then
        pass forged "GET $path with forged headers: ${line#*: would refuse GET $path on $svc for }"
    elif [[ "$code" == 401 || ( "$svc" == access && "$code" == 403 ) ]]; then
        pass forged "GET $path with forged headers refused with $code"
    else
        fail forged "logged a refusal but answered $code: $line"
    fi
done

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Every service checks its requests.${NC}"
else
    echo -e "${RED}${BOLD}${FAILS} check(s) failed.${NC}"
    exit 1
fi
