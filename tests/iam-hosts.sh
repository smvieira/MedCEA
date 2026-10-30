#!/usr/bin/env bash
# tests/iam-hosts.sh — each signed-in host's live gate admits exactly the roles the
# access policy compiles for it (IAM plan, Phase 0 tests).
#
# For every host `cli.py hosts` marks [compiled] (ACCESS_DOMAIN too, since IAM 2.7), it
# checks on the running cluster:
#   gate     the allowed_groups in the proxy's rendered config equals `policy_groups HOST`
#            (as sets; IAM_GATES=false expects the pre-policy list instead — for
#            ACCESS_DOMAIN ["admin"], which apps/access/deploy.sh also deploys until every
#            access pod has proved it enforces)
#   page     the proxy serves a custom 403 page; on every host but the portal it names
#            the host and exactly the roles the live gate admits (cli.py describe-gate)
#   live     the proxy's pod started after that config and page were last written
#   sign-in  signed out, the host redirects to Keycloak, and Keycloak accepts the scopes
#            the proxy asks for (a missing `groups` client scope is invalid_scope)
#   reach    at least one enabled account holds a role the gate admits (composites
#            expanded), so no host is left that nobody can open
# Hosts whose gate is not compiled yet are listed as SKIP with the phase that adds it.
# Then the edge-wizard client (IAM 1.5): device authorization grant on, no service
# account, and the realm's discovery document lists device_authorization_endpoint.
#
# Read-only: no lock, no Keycloak account, no change to the cluster. It proves the
# configured gates, not a sign-in per role; that matrix is a Phase 1 test.
# Run from the repository root:  tests/iam-hosts.sh        Exit 1 on any FAIL.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
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
source infra/lib-oauth2-proxy.sh

FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %-8s %s\n" "$1" "$2"; }
fail() { printf "  ${RED}FAIL${NC}  %-8s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }
skip() { printf "  ${YELLOW}SKIP${NC}  %-8s %s\n" "$1" "$2"; }

# ["b", "a"] -> "a b"
roles_of() { grep -o '"[^"]*"' <<<"$1" | tr -d '"' | sort -u | tr '\n' ' ' | sed 's/ $//'; }

# Enabled, non-service accounts per effective realm role, from Keycloak's database.
# The password is read inside the pod, so it never appears on a command line.
declare -A HOLDERS=()
HOLDERS_OK=false
_holders="$($KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- sh -c \
    'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d keycloak -tA -F " " -v realm="$0"' \
    "$KEYCLOAK_REALM" 2>/dev/null <<'SQL'
WITH RECURSIVE eff(user_id, role_id) AS (
    SELECT m.user_id::text, m.role_id::text FROM user_role_mapping m
  UNION
    SELECT e.user_id, c.child_role::text FROM eff e JOIN composite_role c ON c.composite = e.role_id
)
SELECT r.name, count(DISTINCT u.id)
  FROM eff e
  JOIN keycloak_role r ON r.id = e.role_id AND NOT r.client_role
  JOIN realm re ON re.id = r.realm_id AND re.name = :'realm'
  JOIN user_entity u ON u.id = e.user_id AND u.enabled AND u.service_account_client_link IS NULL
 GROUP BY r.name;
SQL
)" && HOLDERS_OK=true
while read -r _r _n; do [[ -n "$_r" ]] && HOLDERS[$_r]=$_n; done <<<"$_holders"

echo -e "${BOLD}IAM host gates${NC} (namespace $NAMESPACE, realm $KEYCLOAK_REALM)"
[[ "${IAM_GATES:-true}" == "false" ]] && \
    echo -e "${YELLOW}IAM_GATES=false: expecting the pre-policy list on every compiled host.${NC}"
$HOLDERS_OK || echo -e "${YELLOW}Keycloak's database is not readable; the reach check is skipped.${NC}"

HOSTS="$(python3 apps/iam/compiler/cli.py hosts)" || { echo "cli.py hosts failed" >&2; exit 2; }
INGRESSES="$($KUBECTL get ingress -n "$NAMESPACE" -o \
    jsonpath='{range .items[*]}{.spec.rules[0].host}{" "}{.metadata.labels.app\.kubernetes\.io/instance}{"\n"}{end}')"

while IFS= read -r line; do
    [[ "$line" =~ ^([A-Z_]+)\ +\[([^]]*)\] ]] || continue
    var="${BASH_REMATCH[1]}" status="${BASH_REMATCH[2]}"
    host="${!var:-}"
    echo ""
    echo -e "${BOLD}${var}${NC}  ${host:-<unset>}"
    case "$status" in
        compiled)
            if [[ "$var" == ACCESS_DOMAIN && "${IAM_GATES:-true}" == false ]]; then
                expected='["admin"]'
            else
                expected="$(policy_groups "$var" 2>/dev/null)" || { fail gate "policy_groups $var failed"; continue; }
            fi ;;
        *)                     skip gate "$status"; continue ;;
    esac
    if [[ -z "$host" ]]; then fail gate "$var is not set in config.env"; continue; fi

    release="$(awk -v h="$host" '$1 == h && $2 != "" { print $2; exit }' <<<"$INGRESSES")"
    if [[ -z "$release" ]]; then fail gate "no oauth2-proxy Ingress for $host (not deployed?)"; continue; fi

    cfg="$($KUBECTL get configmap "$release" -n "$NAMESPACE" -o jsonpath='{.data.oauth2_proxy\.cfg}' 2>/dev/null)"
    gate_line="$(grep -E '^[[:space:]]*allowed_groups[[:space:]]*=' <<<"$cfg" | head -1)"
    want="$(roles_of "$expected")"
    if [[ -z "$gate_line" ]]; then
        have=""
        fail gate "$release has no allowed_groups: anyone signed in gets in (want: $want)"
    else
        have="$(roles_of "${gate_line#*=}")"
        if [[ "$have" == "$want" ]]; then
            pass gate "$want"
        else
            extra="$(comm -23 <(tr ' ' '\n' <<<"$have") <(tr ' ' '\n' <<<"$want") | xargs)"
            missing="$(comm -13 <(tr ' ' '\n' <<<"$have") <(tr ' ' '\n' <<<"$want") | xargs)"
            fail gate "$release admits [${have}]; extra: ${extra:-none}; missing: ${missing:-none}"
        fi
    fi

    # The 403 page: the proxy reads /templates, a ConfigMap is mounted there, and it
    # names this host and exactly the roles the live gate admits. The portal has its
    # own page (no platform role at all), so only its presence is checked there.
    page_cm="$release-templates"; [[ "$var" == "PORTAL_DOMAIN" ]] && page_cm="portal-templates"
    mounted="$($KUBECTL get deployment "$release" -n "$NAMESPACE" \
        -o jsonpath='{range .spec.template.spec.volumes[*]}{.configMap.name}{"\n"}{end}' 2>/dev/null)"
    page="$($KUBECTL get configmap "$page_cm" -n "$NAMESPACE" -o jsonpath='{.data.error\.html}' 2>/dev/null)"
    if ! grep -qE '^[[:space:]]*custom_templates_dir[[:space:]]*=[[:space:]]*"/templates"' <<<"$cfg"; then
        fail page "$release does not read custom templates: oauth2-proxy's bare 403 is shown"
    elif ! grep -qxF "$page_cm" <<<"$mounted"; then
        fail page "$release does not mount ConfigMap $page_cm"
    elif [[ -z "$page" ]]; then
        fail page "ConfigMap $page_cm has no error.html"
    elif [[ "$var" == "PORTAL_DOMAIN" ]]; then
        grep -qF "No access yet" <<<"$page" && pass page "portal's own 403 page" \
            || fail page "$page_cm is not the portal's 403 page"
    else
        live_json="[$(for r in $have; do printf '"%s",' "$r"; done | sed 's/,$//')]"
        desc="$(python3 apps/iam/compiler/cli.py describe-gate "$var" "$live_json" 2>&1)"
        svc="${desc%%$'\t'*}" labels="${desc#*$'\t'}"
        if grep -qF "No access to $svc</h1>" <<<"$page" && grep -qF ">$labels</span>" <<<"$page"; then
            pass page "403 names $svc and the roles it admits"
        else
            fail page "$page_cm does not match the live gate (want $svc: $labels)"
        fi
    fi

    # The chart mounts the config; a pod older than its last write runs the old gate.
    cfg_time="$({ $KUBECTL get configmap "$release" -n "$NAMESPACE" \
                    -o jsonpath='{range .metadata.managedFields[*]}{.time}{"\n"}{end}'
                  $KUBECTL get configmap "$page_cm" -n "$NAMESPACE" \
                    -o jsonpath='{range .metadata.managedFields[*]}{.time}{"\n"}{end}' 2>/dev/null
                } | sort | tail -1)"
    pod_time="$($KUBECTL get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=$release" \
        --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.status.startTime}{"\n"}{end}' | sort | head -1)"
    if [[ -z "$pod_time" ]]; then
        fail live "no running $release pod"
    elif [[ "$pod_time" < "$cfg_time" ]]; then
        fail live "$release pod started $pod_time, before its config changed at $cfg_time"
    else
        pass live "pod started $pod_time"
    fi

    first="$(curl -sk -o /dev/null -m 10 -w '%{http_code} %{redirect_url}' "https://$host/")"
    code="${first%% *}" url="${first#* }"
    if [[ "$code" != "302" || "$url" != "https://$KEYCLOAK_DOMAIN/"* ]]; then
        fail sign-in "signed out, https://$host/ answered $code ${url:0:80} (want 302 to $KEYCLOAK_DOMAIN)"
    else
        kc="$(curl -sk -o /dev/null -m 10 -w '%{http_code} %{redirect_url}' "$url")"
        if [[ "${kc%% *}" == "200" ]]; then
            pass sign-in "Keycloak shows the login page for scopes $(grep -o 'scope=[^&]*' <<<"$url" | cut -d= -f2)"
        else
            err="$(grep -o 'error=[^&]*' <<<"$kc" | head -1)"
            fail sign-in "Keycloak refused the sign-in request: ${err:-${kc:0:80}}"
        fi
    fi

    if $HOLDERS_OK && [[ -n "$gate_line" ]]; then
        who=""
        for r in $have; do [[ -n "${HOLDERS[$r]:-}" ]] && who+="$r:${HOLDERS[$r]} "; done
        if [[ -n "$who" ]]; then
            pass reach "enabled accounts by role: ${who% }"
        else
            fail reach "no enabled account holds any of [$have]: nobody can open $host"
        fi
    fi
done <<<"$HOSTS"

# The edge wizard signs a terminal in with the device grant (flash-device.sh,
# edge/src/host/edge_auth.py). Read from Keycloak's database like the holders above.
echo ""
echo -e "${BOLD}edge-wizard client${NC}  (terminal sign-in for flash-device.sh)"
_ew="$($KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- sh -c \
    'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d keycloak -tA -F " " -v realm="$0"' \
    "$KEYCLOAK_REALM" 2>/dev/null <<'SQL'
SELECT c.service_accounts_enabled,
       coalesce((SELECT a.value FROM client_attributes a
                  WHERE a.client_id = c.id AND a.name = 'oauth2.device.authorization.grant.enabled'), '-')
  FROM client c JOIN realm r ON r.id = c.realm_id AND r.name = :'realm'
 WHERE c.client_id = 'edge-wizard';
SQL
)" || _ew=""
read -r _ew_sa _ew_dev <<<"$_ew"
if [[ -z "$_ew" ]]; then
    fail client "edge-wizard not found in Keycloak's database (or it is not readable) — run ./deploy-infra.sh"
elif [[ "$_ew_dev" != "true" ]]; then
    fail client "edge-wizard has oauth2.device.authorization.grant.enabled=${_ew_dev}: a terminal cannot sign in — run ./deploy-infra.sh"
elif [[ "$_ew_sa" != "f" ]]; then
    fail client "edge-wizard has a service account (serviceAccountsEnabled=true) — run ./deploy-infra.sh"
else
    pass client "device grant on, no service account"
fi
if curl -sk -m 10 "https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM/.well-known/openid-configuration" \
        | grep -q '"device_authorization_endpoint"'; then
    pass device "the realm's discovery document lists device_authorization_endpoint"
else
    fail device "no device_authorization_endpoint in https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM discovery — run ./deploy-infra.sh"
fi

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All checked gates match the policy.${NC}"
else
    echo -e "${RED}${BOLD}${FAILS} check(s) failed.${NC}"
    exit 1
fi
