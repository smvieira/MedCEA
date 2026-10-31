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
# A host whose gate is the tool's own role setting [tool …] (GRAFANA_DOMAIN, IAM 3.1):
#   gate     the live Grafana env's role path equals `policy_grafana`, strict true and
#            allow_assign_grafana_admin false (IAM_GATES=false: the pre-3.1 path, strict
#            false — any enabled account is at least Viewer)
#   live     the Grafana pod started after its Deployment last changed
#   sign-in  Grafana's sign-in reaches Keycloak's login page with scope `groups`
#            (invalid_scope would refuse everyone: strict fails closed)
#   reach    some enabled account holds a role the policy gives a Grafana role
# The AI workbench [tool (JupyterHub …)] (WORKBENCH_DOMAIN, IAM 3.2):
#   gate     the hub's deployed values (Secret hub, read on stdin) carry allow_all false,
#            allowed_groups equal to `policy_workbench`, hub role workbench-admin with
#            exactly WORKBENCH_ADMIN_ROLE_SCOPES and the compiled admin groups (IAM_GATES
#            =false: allow_all true, ADMIN_USER as its one user), nobody in the built-in
#            admin role (admin_users [], no admin_groups, its members pinned to []),
#            delete_pvc false, no auth_state; SKIP while WORKBENCH_ENABLED is not true
#   live     the running hub pod carries the Deployment's checksum/secret
#   notebooks (IAM 3.2b) the singleuser egress equals `policy_workbench_egress` (Keycloak
#            and config-api only while IAM_POSTGREST_JWT and IAM_DB_ROLES are true, else
#            none), private addresses still closed, and the pod environment names no secret
#   sign-in  /hub/login (auto_login → /hub/oauth_login) reaches Keycloak's login page
#   reach    some enabled account holds a role the hub admits
# The onboarding wizard and pgAdmin [tool (…)] (ONBOARD_DOMAIN, PGADMIN_DOMAIN, IAM 3.4):
#   gate     the running wizard's --required-role equals `policy_tool edge-wizard`, and
#            pgAdmin's live OAUTH2_ADDITIONAL_CLAIMS (read on stdin: the same value holds
#            the client secret, and only the claims are printed) equals `policy_tool
#            pgadmin` (IAM_GATES=false: EDGE_WIZARD_ROLE, and {'groups': ['admin']})
#   sign-in  signed out, the host redirects to Keycloak (the wizard) or shows pgAdmin's
#            MedCEA sign-in button (pgAdmin)
#   reach    some enabled account holds a role the tool admits
# Hosts whose gate is not compiled yet are listed as SKIP with the phase that adds it.
# Then the edge-wizard client (IAM 1.5): device authorization grant on, no service
# account, and the realm's discovery document lists device_authorization_endpoint; and
# the workbench-notebook client (IAM 3.2b): public, device grant only (no browser flow,
# no password grant, no service account), default scopes groups and medcea-identity.
#
# Read-only: no lock, no Keycloak account, no change to the cluster. It proves the
# configured gates, not a sign-in per role; that matrix is a Phase 1 test.
# Run from the repository root:  tests/iam-hosts.sh        Exit 1 on any FAIL.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,53p' "$0" | sed 's/^# \{0,1\}//'
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
source infra/lib-policy-tools.sh

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
    echo -e "${YELLOW}IAM_GATES=false: expecting the pre-policy list on every compiled host but Node-RED and the MQTT Explorer.${NC}"
$HOLDERS_OK || echo -e "${YELLOW}Keycloak's database is not readable; the reach check is skipped.${NC}"

# Grafana signs people in itself (IAM 3.1): its gate is its own role setting.
check_grafana() {
    local host="$1" roles="$2" envs path strict assign GRAFANA_ROLE_PATH GRAFANA_ROLE_STRICT
    envs="$($KUBECTL get deployment grafana -n "$NAMESPACE" \
        -o jsonpath='{range .spec.template.spec.containers[?(@.name=="grafana")].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null)" \
        || { fail gate "no Grafana deployment in $NAMESPACE"; return; }
    path="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=//p' <<<"$envs")"
    strict="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT=//p' <<<"$envs")"
    assign="$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ALLOW_ASSIGN_GRAFANA_ADMIN=//p' <<<"$envs")"
    policy_grafana 2>/dev/null || { fail gate "policy_grafana failed (cli.py check)"; return; }
    if [[ "$path" != "$GRAFANA_ROLE_PATH" ]]; then
        fail gate "Grafana's live role path is not the compiled one: ${path:0:100}"
    elif [[ "$strict" != "$GRAFANA_ROLE_STRICT" ]]; then
        fail gate "role_attribute_strict is '$strict', want $GRAFANA_ROLE_STRICT"
    elif [[ "$assign" != "false" ]]; then
        fail gate "allow_assign_grafana_admin is '$assign', want false"
    elif [[ "$GRAFANA_ROLE_STRICT" == "true" ]]; then
        pass gate "role path compiled from the policy, strict, no Grafana Admin from SSO"
    else
        pass gate "IAM_GATES=false: the pre-3.1 role path, strict off"
    fi

    local dep_time pod_time
    # the spec's last write, not the controller's status updates
    dep_time="$($KUBECTL get deployment grafana -n "$NAMESPACE" -o json 2>/dev/null | python3 -c '
import json, sys
try:
    mf = json.load(sys.stdin)["metadata"].get("managedFields", [])
except Exception:
    sys.exit()
print(max((m.get("time", "") for m in mf if m.get("subresource") != "status"), default=""))')"
    pod_time="$($KUBECTL get pods -n "$NAMESPACE" -l app.kubernetes.io/name=grafana \
        --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.status.startTime}{"\n"}{end}' | sort | head -1)"
    if [[ -z "$pod_time" ]]; then
        fail live "no running Grafana pod"
    elif [[ "$pod_time" < "$dep_time" ]]; then
        fail live "Grafana pod started $pod_time, before its Deployment changed at $dep_time"
    else
        pass live "pod started $pod_time"
    fi

    local out code url
    out="$(curl -sk -L --max-redirs 6 -o /dev/null -m 15 -w '%{http_code} %{url_effective}' "https://$host/login/generic_oauth")"
    code="${out%% *}" url="${out#* }"
    if [[ "$code" == 200 && "$url" == "https://$KEYCLOAK_DOMAIN/"* && "$url" == *scope=*groups* ]]; then
        pass sign-in "Keycloak shows the login page for scopes $(grep -o 'scope=[^&]*' <<<"$url" | cut -d= -f2)"
    else
        fail sign-in "Grafana's sign-in ended at $code ${url:0:100} (want Keycloak's login page, scope with groups)"
    fi

    if [[ "$GRAFANA_ROLE_STRICT" != "true" ]]; then
        skip reach "IAM_GATES=false: any enabled account gets in"
    elif $HOLDERS_OK; then
        local who="" r
        for r in $roles; do [[ -n "${HOLDERS[$r]:-}" ]] && who+="$r:${HOLDERS[$r]} "; done
        if [[ -n "$who" ]]; then
            pass reach "enabled accounts by role: ${who% }"
        else
            fail reach "no enabled account holds any of [$roles]: nobody can open $host"
        fi
    fi
}

# JupyterHub signs people in itself (IAM 3.2): its gate is the hub's own settings.
check_workbench() {
    local host="$1" roles="$2" live k x
    local WORKBENCH_ALLOW_ALL WORKBENCH_HUBADMIN_USERS WORKBENCH_ALLOWED_GROUPS WORKBENCH_ADMIN_GROUPS WORKBENCH_403_MESSAGE WORKBENCH_EGRESS
    if [[ "${WORKBENCH_ENABLED:-true}" != "true" ]]; then skip gate "WORKBENCH_ENABLED is not true"; return; fi
    policy_workbench 2>/dev/null || { fail gate "policy_workbench failed (cli.py check)"; return; }
    # the values hold the client secret: parsed on stdin, only the gate's fields printed
    live="$($KUBECTL get secret hub -n "$NAMESPACE" -o jsonpath='{.data.values\.yaml}' 2>/dev/null | base64 -d 2>/dev/null \
        | python3 -c '
import json, sys, yaml
v = yaml.safe_load(sys.stdin)
if not isinstance(v, dict):
    sys.exit(1)
c = v["hub"]["config"]
a, g = c.get("Authenticator") or {}, c.get("GenericOAuthenticator") or {}
lr = v["hub"].get("loadRoles") or {}
wa, ad = lr.get("workbench-admin") or {}, lr.get("admin") or {}
# nobody holds the built-in admin role: no admin_users, no admin_groups, its members pinned to []
nobody = not a.get("admin_users") and not g.get("admin_groups") and ad.get("users") == []
for k, x in (("allow_all", a.get("allow_all")), ("nobody_admin", nobody),
             ("allowed", sorted(g.get("allowed_groups") or [])),
             ("role_scopes", sorted(wa.get("scopes") or [])), ("role_groups", sorted(wa.get("groups") or [])),
             ("role_users", sorted(wa.get("users") or [])),
             ("safe", (c.get("KubeSpawner") or {}).get("delete_pvc") is False
                      and a.get("enable_auth_state") is not True)):
    print(f"{k}\t{json.dumps(x)}")
s = v.get("singleuser") or {}
np = s.get("networkPolicy") or {}
eg = np.get("egressAllowRules") or {}
print("egress\t" + json.dumps(np.get("egress") or [], sort_keys=True, separators=(",", ":")))
print("closed\t" + json.dumps(np.get("enabled") is True and eg.get("privateIPs") is False))
env = s.get("extraEnv") or {}
names = list(env) if isinstance(env, dict) else [e.get("name", "") for e in env]
print("envsecret\t" + json.dumps(sorted(n for n in names if any(w in n.upper() for w in ("SECRET", "PASS", "TOKEN")))))')" \
        || { fail gate "no hub Secret in $NAMESPACE"; return; }
    declare -A L=()
    while IFS=$'\t' read -r k x; do L[$k]="$x"; done <<<"$live"
    local sorted_list='import json, sys; print(json.dumps(sorted(json.loads(sys.argv[1]))))'
    if [[ "${L[safe]}" != true ]]; then
        fail gate "delete_pvc or enable_auth_state is not as deployed by IAM 3.2"
    elif [[ "${L[nobody_admin]}" != true ]]; then
        fail gate "someone can hold JupyterHub's built-in admin role (admin_users, admin_groups or its members not pinned to []): it mints tokens that open others' servers"
    elif [[ "${L[role_scopes]}" != "$(python3 -c "$sorted_list" "$WORKBENCH_ADMIN_ROLE_SCOPES")" ]]; then
        fail gate "workbench-admin's scopes are ${L[role_scopes]}, decided $WORKBENCH_ADMIN_ROLE_SCOPES"
    elif [[ "${L[allow_all]}" != "$WORKBENCH_ALLOW_ALL" ]]; then
        fail gate "allow_all is ${L[allow_all]}, want $WORKBENCH_ALLOW_ALL"
    elif [[ "${L[allowed]}" != "$(python3 -c "$sorted_list" "$WORKBENCH_ALLOWED_GROUPS")" ]]; then
        fail gate "allowed_groups is ${L[allowed]}, the policy compiles $WORKBENCH_ALLOWED_GROUPS"
    elif [[ "${L[role_groups]}" != "$(python3 -c "$sorted_list" "$WORKBENCH_ADMIN_GROUPS")" ]]; then
        fail gate "workbench-admin's groups are ${L[role_groups]}, the policy compiles $WORKBENCH_ADMIN_GROUPS"
    elif [[ "${L[role_users]}" != "$(python3 -c "$sorted_list" "$WORKBENCH_HUBADMIN_USERS")" ]]; then
        fail gate "workbench-admin's users are ${L[role_users]}, want $WORKBENCH_HUBADMIN_USERS"
    elif [[ "$WORKBENCH_ALLOW_ALL" == "true" ]]; then
        pass gate "IAM_GATES=false: any realm account, $ADMIN_USER hub administrator (workbench-admin)"
    else
        pass gate "admits $(roles_of "${L[allowed]}"); hub administrators (workbench-admin) $(roles_of "${L[role_groups]}")"
    fi

    local tmpl pod
    tmpl="$($KUBECTL get deployment hub -n "$NAMESPACE" -o jsonpath='{.spec.template.metadata.annotations.checksum/secret}' 2>/dev/null)"
    pod="$($KUBECTL get pods -n "$NAMESPACE" -l component=hub --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.annotations.checksum/secret}{"\n"}{end}' 2>/dev/null | sort -u)"
    if [[ -n "$tmpl" && "$pod" == "$tmpl" ]]; then
        pass live "the hub pod runs the deployed values"
    else
        fail live "the running hub pod does not carry the Deployment's checksum/secret (rollout pending?)"
    fi

    local want_egress
    if ! policy_workbench_egress 2>/dev/null; then
        fail notebooks "policy_workbench_egress failed (cli.py check)"
    else
        want_egress="$(python3 -c 'import json, sys; print(json.dumps(json.loads(sys.argv[1]), sort_keys=True, separators=(",", ":")))' "$WORKBENCH_EGRESS")"
        if [[ "${L[closed]}" != true ]]; then
            fail notebooks "the notebooks' NetworkPolicy is off or allows private addresses"
        elif [[ "${L[egress]}" != "$want_egress" ]]; then
            fail notebooks "the notebooks' egress ${L[egress]:0:120} is not the compiled one for IAM_POSTGREST_JWT=${IAM_POSTGREST_JWT:-false}/IAM_DB_ROLES=${IAM_DB_ROLES:-false} (./infra/deploy-workbench.sh)"
        elif [[ "${L[envsecret]}" != "[]" ]]; then
            fail notebooks "the notebook environment names ${L[envsecret]}: no credential may reach a notebook pod"
        elif [[ "$want_egress" == "[]" ]]; then
            pass notebooks "no platform hop (IAM_POSTGREST_JWT and IAM_DB_ROLES are not both true)"
        else
            pass notebooks "Keycloak and config-api only, with each person's own sign-in"
        fi
    fi

    local out code url
    # auto_login: /hub/login → /hub/oauth_login → Keycloak
    out="$(curl -sk -L --max-redirs 6 -o /dev/null -m 15 -w '%{http_code} %{url_effective}' "https://$host/hub/login")"
    code="${out%% *}" url="${out#* }"
    if [[ "$code" == 200 && "$url" == "https://$KEYCLOAK_DOMAIN/"* ]]; then
        pass sign-in "Keycloak shows the login page for client workbench"
    else
        fail sign-in "the hub's sign-in ended at $code ${url:0:100} (want Keycloak's login page)"
    fi

    if [[ "$WORKBENCH_ALLOW_ALL" == "true" ]]; then
        skip reach "IAM_GATES=false: any enabled account gets in"
    elif $HOLDERS_OK; then
        local who="" r
        for r in $roles; do [[ -n "${HOLDERS[$r]:-}" ]] && who+="$r:${HOLDERS[$r]} "; done
        if [[ -n "$who" ]]; then
            pass reach "enabled accounts by role: ${who% }"
        else
            fail reach "no enabled account holds any of [$roles]: nobody can open $host"
        fi
    fi
}

# Some enabled account holds one of ROLES (space-separated), or FAIL: nobody can open HOST.
reach_of() {
    local host="$1" roles="$2" who="" r
    $HOLDERS_OK || return 0
    for r in $roles; do [[ -n "${HOLDERS[$r]:-}" ]] && who+="$r:${HOLDERS[$r]} "; done
    if [[ -n "$who" ]]; then
        pass reach "enabled accounts by role: ${who% }"
    else
        fail reach "no enabled account holds any of [$roles]: nobody can open $host"
    fi
}

# The onboarding wizard (IAM 3.4): its gate is the daemon's --required-role.
check_onboard() {
    local host="$1" want argv have first code url
    want="$(policy_tool edge-wizard 2>/dev/null)" || { fail gate "policy_tool edge-wizard failed (cli.py check)"; return; }
    argv="$(pgrep -af '[w]izard_server.py .*--daemon' | head -1)"
    have="$(sed -n 's/.* --required-role \([^ ]*\).*/\1/p' <<<"$argv")"
    if [[ -z "$argv" ]]; then
        fail gate "no onboarding wizard daemon runs (./apps/edge-wizard/deploy.sh)"
    elif [[ "$have" != "$want" ]]; then
        fail gate "the wizard admits ${have:-any signed-in account}, want ${want:-any signed-in account}"
    elif [[ -z "$want" ]]; then
        pass gate "IAM_GATES=false: EDGE_WIZARD_ROLE empty, any signed-in account"
    else
        pass gate "--required-role $want, from the policy"
    fi
    first="$(curl -sk -o /dev/null -m 10 -w '%{http_code} %{redirect_url}' "https://$host/")"
    code="${first%% *}" url="${first#* }"
    if [[ "$code" == 302 && "$url" == "https://$KEYCLOAK_DOMAIN/"* ]]; then
        pass sign-in "signed out, the wizard redirects to Keycloak"
    else
        fail sign-in "signed out, https://$host/ answered $code ${url:0:80} (want 302 to $KEYCLOAK_DOMAIN)"
    fi
    if [[ -z "$want" ]]; then skip reach "any signed-in account gets in"; else reach_of "$host" "${want//,/ }"; fi
}

# pgAdmin (IAM 3.4): its gate is OAUTH2_ADDITIONAL_CLAIMS. The env value also holds
# the client secret: python reads it on stdin and prints only the claims.
check_pgadmin() {
    local host="$1" want have same page
    want="$(policy_tool pgadmin 2>/dev/null)" || { fail gate "policy_tool pgadmin failed (cli.py check)"; return; }
    have="$($KUBECTL get deployment pgadmin -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="PGADMIN_CONFIG_OAUTH2_CONFIG")].value}' 2>/dev/null \
        | python3 -c '
import ast, sys
try:
    print(repr(ast.literal_eval(sys.stdin.read())[0].get("OAUTH2_ADDITIONAL_CLAIMS")))
except Exception:
    print("unreadable")')"
    same="$(python3 -c 'import ast, sys; print(ast.literal_eval(sys.argv[1]) == ast.literal_eval(sys.argv[2]))' "$have" "$want" 2>/dev/null)"
    if [[ "$same" == True ]]; then
        pass gate "OAUTH2_ADDITIONAL_CLAIMS $want"
    else
        fail gate "OAUTH2_ADDITIONAL_CLAIMS is $have, want $want (./deploy-infra.sh)"
    fi
    page="$(curl -sk -L -m 15 "https://$host/login")"
    if grep -q '"OAUTH2_NAME": "keycloak"' <<<"$page"; then
        pass sign-in "pgAdmin's login page offers the MedCEA sign-in"
    else
        fail sign-in "pgAdmin's login page has no keycloak sign-in button"
    fi
    reach_of "$host" "$(python3 -c 'import ast, sys; print(" ".join(ast.literal_eval(sys.argv[1])["groups"]))' "$want")"
}

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
        tool*)
            if [[ -z "$host" ]]; then fail gate "$var is not set in config.env"; continue; fi
            if [[ "$var" == WORKBENCH_DOMAIN ]]; then
                check_workbench "$host" "${line##*]}"
            elif [[ "$var" == ONBOARD_DOMAIN ]]; then
                check_onboard "$host"
            elif [[ "$var" == PGADMIN_DOMAIN ]]; then
                check_pgadmin "$host"
            else
                check_grafana "$host" "${line##*]}"
            fi
            continue ;;
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

# A notebook signs its person in on workbench-notebook (IAM 3.2b,
# k8s/workbench/examples/medcea_data.py): public, device grant only.
echo ""
echo -e "${BOLD}workbench-notebook client${NC}  (device sign-in from a notebook)"
_wn="$($KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0 -- sh -c \
    'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d keycloak -tA -F " " -v realm="$0"' \
    "$KEYCLOAK_REALM" 2>/dev/null <<'SQL'
SELECT c.public_client, c.standard_flow_enabled, c.direct_access_grants_enabled, c.service_accounts_enabled,
       coalesce((SELECT a.value FROM client_attributes a
                  WHERE a.client_id = c.id AND a.name = 'oauth2.device.authorization.grant.enabled'), '-'),
       (SELECT count(*) FROM client_scope_client d JOIN client_scope s ON s.id = d.scope_id
         WHERE d.client_id = c.id AND d.default_scope AND s.name IN ('groups', 'medcea-identity'))
  FROM client c JOIN realm r ON r.id = c.realm_id AND r.name = :'realm'
 WHERE c.client_id = 'workbench-notebook';
SQL
)" || _wn=""
read -r _wn_pub _wn_std _wn_pw _wn_sa _wn_dev _wn_scopes <<<"$_wn"
if [[ -z "$_wn" ]]; then
    fail client "workbench-notebook not found in Keycloak's database (or it is not readable) — run ./deploy-infra.sh"
elif [[ "$_wn_pub" != "t" || "$_wn_std" != "f" || "$_wn_pw" != "f" || "$_wn_sa" != "f" ]]; then
    fail client "workbench-notebook is not public device-only (public=$_wn_pub standard=$_wn_std password=$_wn_pw service=$_wn_sa) — run ./deploy-infra.sh"
elif [[ "$_wn_dev" != "true" ]]; then
    fail client "workbench-notebook has oauth2.device.authorization.grant.enabled=${_wn_dev} — run ./deploy-infra.sh"
elif [[ "$_wn_scopes" != "2" ]]; then
    fail client "workbench-notebook lacks the default scopes groups and medcea-identity — run ./deploy-infra.sh"
else
    pass client "public, device grant only, groups and medcea-api audience"
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
