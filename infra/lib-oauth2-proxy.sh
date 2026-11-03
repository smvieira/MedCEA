#!/usr/bin/env bash
# infra/lib-oauth2-proxy.sh — one oauth2-proxy (Keycloak SSO) release per host.
# Sourced by the app deploy scripts after config.env, lib-mk8s.sh and
# lib-render.sh.
#
#   deploy_oauth2_proxy RELEASE CLIENT_ID CLIENT_SECRET COOKIE_SECRET HOST VALUES_FILE [--set ...]
#
# VALUES_FILE is an already rendered values file (see k8s/oauth2-proxy/
# values-app.yaml, rendered with KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE
# APP_SERVICE). Extra arguments are passed to helm as they are. The release's
# own Ingress owns HOST, so the caller deletes the app's plain Ingress first:
# two Ingresses for one host is undefined behaviour in nginx-ingress.
#
# One release per host because a cookie cannot span the platform's one-label
# domain (browsers reject Domain=medcea), so portal, config, monitor … each
# keep their own session cookie. Needs $MK8S, $KUBECTL, NAMESPACE,
# KEYCLOAK_DOMAIN, KEYCLOAK_REALM and REPO_ROOT.

#   policy_groups HOST_VAR
#
# The allowed_groups of a host (a config.env variable name, e.g. CONFIG_DOMAIN),
# compiled from the access policy (apps/iam/policy/defaults.yaml), printed as
# ["a", "b"] for the values file's ${ALLOWED_GROUPS}. IAM_GATES=false in
# config.env renders the pre-policy list instead (the rollback of the IAM plan's
# Phase 0), except on Node-RED and the MQTT Explorer: they reach telemetry and
# device control, so they keep the compiled list (["engineer"] if the policy is
# broken) rather than open to admin (IAM 3.3 decision). A broken policy fails the
# deploy rather than opening a host.
policy_groups() {
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        case "$1" in
            NODE_RED_DOMAIN|MQTTX_DOMAIN)
                echo -e "\033[0;33mWARNING: IAM_GATES=false — $1 keeps the compiled role list (it reaches telemetry).\033[0m" >&2
                python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile proxy "$1" 2>/dev/null || echo '["engineer"]'
                return 0 ;;
        esac
        echo -e "\033[0;33mWARNING: IAM_GATES=false — $1 gets the pre-policy role list, not the access policy.\033[0m" >&2
        echo '["operator", "qa", "auditor", "admin"]'
        return 0
    fi
    python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile proxy "$1"
}

#   policy_grafana || exit 1
#
# Grafana signs people in itself, so its gate is its own role setting (IAM 3.1):
# sets GRAFANA_ROLE_PATH (GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH over the
# `groups` claim: Editor, Viewer or '' — compiled from the dashboards group's
# `tool:` block) and GRAFANA_ROLE_STRICT (true: '' is no sign-in). IAM_GATES=false
# renders the pre-3.1 expression byte for byte with strict off, so any enabled
# account is at least Viewer again. A broken policy returns 1 and changes nothing.
GRAFANA_PRE_31_PATH="contains(roles[*], 'grafana_admin') && 'Admin' || contains(roles[*], 'grafana_developer') && 'Editor' || 'Viewer'"
policy_grafana() {
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        echo -e "\033[0;33mWARNING: IAM_GATES=false — Grafana gets the pre-3.1 role setting: any enabled account is at least Viewer.\033[0m" >&2
        GRAFANA_ROLE_PATH="$GRAFANA_PRE_31_PATH" GRAFANA_ROLE_STRICT=false
        return 0
    fi
    GRAFANA_ROLE_PATH="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile grafana)" || return 1
    GRAFANA_ROLE_STRICT=true
}

#   policy_workbench || exit 1
#
# JupyterHub signs people in itself, so the AI workbench's gate is its own setting
# (IAM 3.2), compiled from the research_workbench group's `tool:` block. Sets, for
# k8s/workbench/values.yaml: WORKBENCH_ALLOW_ALL (false), WORKBENCH_ALLOWED_GROUPS and
# WORKBENCH_ADMIN_GROUPS (["a", "b"]: the members of the hub role workbench-admin),
# WORKBENCH_HUBADMIN_USERS ([]: the role's members by name) and WORKBENCH_403_MESSAGE
# (the refusal text, a JSON string: "No access to <service>", the roles, the portal).
# IAM_GATES=false renders the pre-3.2 authentication: any realm account, ADMIN_USER the
# only holder of workbench-admin. Nobody gets JupyterHub's built-in admin role in either
# mode (Authenticator.admin_users and the admin role's members are [] in values.yaml).
# A broken policy or an empty list returns 1 and changes nothing: the caller never
# falls back to allow_all.
policy_workbench() {
    local cli="$REPO_ROOT/apps/iam/compiler/cli.py" desc
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        echo -e "\033[0;33mWARNING: IAM_GATES=false — the AI workbench admits any realm account; ${ADMIN_USER} is hub administrator (workbench-admin).\033[0m" >&2
        WORKBENCH_ALLOW_ALL=true WORKBENCH_ALLOWED_GROUPS='[]' WORKBENCH_ADMIN_GROUPS='[]'
        WORKBENCH_HUBADMIN_USERS="$(python3 -c 'import json, sys; print(json.dumps([sys.argv[1]]))' "${ADMIN_USER:?}")"
        WORKBENCH_403_MESSAGE='"No access to AI Workbench. Ask an administrator."'
        return 0
    fi
    WORKBENCH_ALLOWED_GROUPS="$(python3 "$cli" compile jupyterhub --setting allowed_groups)" || return 1
    WORKBENCH_ADMIN_GROUPS="$(python3 "$cli" compile jupyterhub --setting admin_groups)" || return 1
    [[ -n "$WORKBENCH_ALLOWED_GROUPS" && "$WORKBENCH_ALLOWED_GROUPS" != '[]' ]] || return 1
    desc="$(python3 "$cli" describe-gate WORKBENCH_DOMAIN "$WORKBENCH_ALLOWED_GROUPS")" || return 1
    WORKBENCH_403_MESSAGE="$(python3 -c '
import html, json, sys
service, roles = html.unescape(sys.argv[1]).split("\t", 1)
print(json.dumps(f"No access to {service}. It is open to: {roles}. Ask an administrator for one of "
                 f"these roles. The platform portal: https://{sys.argv[2]}/"))' "$desc" "${PORTAL_DOMAIN:-}")" || return 1
    WORKBENCH_ALLOW_ALL=false WORKBENCH_HUBADMIN_USERS='[]'
}

# The scopes of the hub role workbench-admin, exactly as k8s/workbench/values.yaml
# writes them (sorted JSON): what health-check iamworkbench, tests/iam-hosts.sh and
# tests/test_workbench_render.py compare the deployed role with. Decided in the
# manual's decision record; WORKBENCH_ADMIN_ROLE_FORBIDDEN never appears in them.
WORKBENCH_ADMIN_ROLE_SCOPES='["admin-ui", "delete:users", "list:users", "read:users", "servers"]'
WORKBENCH_ADMIN_ROLE_FORBIDDEN='["access:servers", "admin:auth_state", "admin:users", "groups", "shares", "tokens"]'

# workbench_logout_url — prints where the hub's /hub/logout goes
# (GenericOAuthenticator.logout_redirect_url, decision of 1 Nov 2026, "short sessions +
# one-hop sign-out"): Keycloak's end-session for client workbench, returning to the
# portal's proxy sign-out (it clears the portal's own cookie, then the portal sends the
# browser to the Keycloak sign-in page). client_id and post_logout_redirect_uri only,
# never id_token_hint, so no token is in any URL (Keycloak then shows its "Do you want to
# log out?" page while a session exists). Uses KEYCLOAK_DOMAIN, KEYCLOAK_REALM and
# PORTAL_DOMAIN; the post-logout URI is registered on client workbench by deploy-infra.sh
# (_create_client, https://<PORTAL_DOMAIN>/*).
workbench_logout_url() {
    local rd
    rd="$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' \
          "https://${PORTAL_DOMAIN:?}/oauth2/sign_out?rd=%2F")" || return 1
    printf 'https://%s/realms/%s/protocol/openid-connect/logout?client_id=workbench&post_logout_redirect_uri=%s\n' \
        "${KEYCLOAK_DOMAIN:?}" "${KEYCLOAK_REALM:?}" "$rd"
}

#   policy_workbench_egress || exit 1
#
# The notebooks' platform hops (IAM 3.2b): WORKBENCH_EGRESS, the workbench chart's
# singleuser.networkPolicy.egress, compiled from the access policy's
# network.clients.notebooks (`cli.py compile egress notebooks`: Keycloak for the
# device sign-in, config-api for the person's own reads). Only while
# IAM_POSTGREST_JWT and IAM_DB_ROLES are both true: before that a verified token
# runs as anon, which still holds the legacy grants on medcea. Otherwise '[]' (no
# platform hop, as before). A policy that does not compile returns 1.
policy_workbench_egress() {
    if [[ "${IAM_POSTGREST_JWT:-false}" == "true" && "${IAM_DB_ROLES:-false}" == "true" ]]; then
        WORKBENCH_EGRESS="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile egress notebooks)" || return 1
        [[ "$WORKBENCH_EGRESS" == \[*\] ]] || return 1
    else
        WORKBENCH_EGRESS='[]'
    fi
}

#   n="$(workbench_egress_close NS)" || exit 1
#
# Closes the notebooks' platform hops on the running workbench at once (IAM 3.2b):
# removes from its NetworkPolicy `singleuser` every egress rule that names a hop of
# network.clients.notebooks (config-api, Keycloak) and prints how many it removed (0:
# none open, or no workbench). apps/database/deploy.sh and apps/frontend/deploy.sh call
# it whenever IAM_DB_ROLES or IAM_POSTGREST_JWT is not true, before they change the
# database or config-api: only deploy-workbench.sh renders the hops, and a rollback that
# left them open would let notebook code reach config-api while anon holds the legacy
# grants. The chart's values keep the hops until ./infra/deploy-workbench.sh renders []
# (health-check iamworkbench FAILs until then). Returns 1 when the NetworkPolicy or the
# policy cannot be read, or the patch fails. Needs $KUBECTL and REPO_ROOT.
workbench_egress_close() {
    local ns="$1" live hops ops
    live="$($KUBECTL get networkpolicy singleuser -n "$ns" --ignore-not-found -o json </dev/null)" || return 1
    if [[ -z "$live" ]]; then echo 0; return 0; fi
    hops="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile egress notebooks)" || return 1
    ops="$(python3 -c '
import json, sys
key = lambda sel: json.dumps(sel or {}, sort_keys=True)
hops = {key(peer["podSelector"]["matchLabels"]) for rule in json.loads(sys.argv[1]) for peer in rule["to"]}
ops = []
rules = (json.load(sys.stdin).get("spec") or {}).get("egress") or []
for i in reversed(range(len(rules))):
    peers = rules[i].get("to") or []
    if any("podSelector" in p and "namespaceSelector" not in p
           and key((p["podSelector"] or {}).get("matchLabels")) in hops for p in peers):
        ops += [{"op": "test", "path": "/spec/egress/%d" % i, "value": rules[i]},
                {"op": "remove", "path": "/spec/egress/%d" % i}]
print(json.dumps(ops))' "$hops" <<<"$live")" || return 1
    if [[ "$ops" == "[]" ]]; then echo 0; return 0; fi
    $KUBECTL patch networkpolicy singleuser -n "$ns" --type=json -p "$ops" >/dev/null </dev/null || return 1
    python3 -c 'import json, sys; print(len(json.loads(sys.argv[1])) // 2)' "$ops"
}

#   gate_error_page RELEASE HOST_VAR ALLOWED_GROUPS
#
# The proxy's 403 page: "No access to <service>", the roles that may open it and
# "ask an administrator", instead of oauth2-proxy's bare 403. ALLOWED_GROUPS is
# the list the gate is deployed with (from policy_groups, or a fixed one), so the
# page names exactly the roles that gate admits. Written to ConfigMap
# RELEASE-templates, which gate_helm_args mounts at the values files'
# custom_templates_dir; gate_helm_args also stamps its sha256 on the pod template,
# so a changed page rolls the proxy through helm (IAM 4.2b).
# The portal keeps its own page (k8s/portal/error.html): there a 403 means no
# platform role at all. gate_error_html prints the page without applying it
# (the scoped modes compare it with the live one first).
gate_error_html() {
    local host_var="$1" allowed="$2" desc
    desc="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" describe-gate "$host_var" "$allowed")" || return 1
    local GATE_SERVICE="${desc%%$'\t'*}" GATE_ROLES="${desc#*$'\t'}"
    local GATE_PORTAL_URL="https://$PORTAL_DOMAIN/" GATE_LOGOUT_RD
    # Sign out ends the Keycloak session too and lands on the portal (see the
    # portal's _PORTAL_LOGOUT_RD in deploy-infra.sh, whose redirect URI this reuses).
    GATE_LOGOUT_RD="$(python3 -c "
import urllib.parse, sys
inner = 'https://%s/realms/%s/protocol/openid-connect/logout?client_id=portal&post_logout_redirect_uri=%s' % (
    sys.argv[1], sys.argv[2], urllib.parse.quote('https://%s/' % sys.argv[3], safe=''))
print(urllib.parse.quote(inner, safe=''))
" "$KEYCLOAK_DOMAIN" "$KEYCLOAK_REALM" "$PORTAL_DOMAIN")"
    render "$REPO_ROOT/k8s/oauth2-proxy/error.html" GATE_SERVICE GATE_ROLES GATE_PORTAL_URL GATE_LOGOUT_RD
}
gate_error_page() {
    local release="$1" page
    page="$(gate_error_html "$2" "$3")" || return 1
    printf '%s\n' "$page" \
      | $MK8S kubectl create configmap "$release-templates" -n "$NAMESPACE" --from-file=error.html=/dev/stdin \
          --dry-run=client -o yaml | $MK8S kubectl apply -f - >/dev/null
}

#   gate_page_sha RELEASE
#
# sha256 of the 403 page in ConfigMap RELEASE-templates as the cluster has it, or
# "none" without the ConfigMap.
gate_page_sha() {
    local page
    page="$($MK8S kubectl get configmap "$1-templates" -n "$NAMESPACE" -o jsonpath='{.data.error\.html}' 2>/dev/null)" \
        || { echo none; return 0; }
    printf '%s\n' "$page" | sha256sum | cut -d' ' -f1   # $(…) dropped the page's last newline
}

#   mapfile -t ARR < <(gate_helm_args RELEASE)
#
# The helm --set arguments that mount RELEASE-templates at /templates. Optional,
# so a proxy deployed before its page still starts (with oauth2-proxy's page).
# The page's sha256 as a pod annotation: oauth2-proxy reads its templates at start
# only, so a changed page must change the pod template (IAM 4.2b).
gate_helm_args() {
    printf '%s\n' \
      --set "extraVolumes[0].name=gate-templates" \
      --set "extraVolumes[0].configMap.name=$1-templates" \
      --set "extraVolumes[0].configMap.optional=true" \
      --set "extraVolumeMounts[0].name=gate-templates" \
      --set "extraVolumeMounts[0].mountPath=/templates" \
      --set "extraVolumeMounts[0].readOnly=true" \
      --set "podAnnotations.medcea/gate-page-sha256=$(gate_page_sha "$1")"
}

# helm_dockerhub_login — log helm into Docker Hub as the identity that pulls.
#
# deploy-infra.sh logs in once, but on a fresh host it runs everything through
# `sudo microk8s` (the session has no microk8s group yet), so that login lands in
# root's helm config; install.sh then runs the apps stage as the user (sg
# microk8s), whose helm has none, and the bitnamicharts pulls went anonymous
# (rate-limited per IP). So every chart pull outside deploy-infra logs in first,
# once per process. Best effort: a failed login warns and the pull still runs.
# The token goes on stdin only.
helm_dockerhub_login() {
    [[ "${_MEDCEA_HELM_LOGIN_DONE:-}" == 1 ]] && return 0
    _MEDCEA_HELM_LOGIN_DONE=1
    if [[ -z "${DOCKERHUB_USER:-}" || -z "${DOCKERHUB_PAT:-}" ]]; then
        echo "WARNING: DOCKERHUB_USER/DOCKERHUB_PAT not set in config.env: pulling bitnamicharts anonymously." >&2
        return 0
    fi
    if ! printf '%s\n' "$DOCKERHUB_PAT" | $MK8S helm3 registry login registry-1.docker.io \
            -u "$DOCKERHUB_USER" --password-stdin >/dev/null 2>&1; then
        echo "WARNING: helm could not log in to Docker Hub as $DOCKERHUB_USER: pulling bitnamicharts anonymously." >&2
    fi
    return 0
}

deploy_oauth2_proxy() {
    local release="$1" client_id="$2" client_secret="$3" cookie_secret="$4" host="$5" values="$6"
    shift 6
    local gate_args
    mapfile -t gate_args < <(gate_helm_args "$release")
    if [[ -z "$client_secret" || -z "$cookie_secret" ]]; then
        echo "ERROR: no Keycloak client secret / cookie secret for '$client_id' in config.env." >&2
        echo "       Run ./deploy-infra.sh first — it creates the client and writes both." >&2
        return 1
    fi
    helm_dockerhub_login
    $MK8S helm3 upgrade --install "$release" \
      oci://registry-1.docker.io/bitnamicharts/oauth2-proxy \
      --version 8.0.2 \
      --namespace "$NAMESPACE" \
      --values "$REPO_ROOT/k8s/oauth2-proxy/values-common.yaml" \
      --values "$values" \
      --set configuration.clientID="$client_id" \
      --set configuration.clientSecret="$client_secret" \
      --set configuration.cookieSecret="$cookie_secret" \
      --set configuration.oidcIssuerUrl="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" \
      --set "extraArgs[0]=--whitelist-domain=$KEYCLOAK_DOMAIN" \
      --set ingress.hostname="$host" \
      --set "ingress.extraTls[0].hosts[0]=$host" \
      --set "ingress.extraTls[0].secretName=cea-tls" \
      "${gate_args[@]}" \
      --timeout 5m "$@"
    # A changed configuration.content rolls the pod by itself (the chart's
    # checksum/config annotation), and a changed 403 page through gate_helm_args'
    # annotation; the client and cookie secrets carry no checksum, so a full deploy
    # restarts to pick up a rotated one. The scoped modes (OAUTH2_PROXY_NO_RESTART=1,
    # IAM 4.2b) change only the gate and leave the restart to helm.
    [[ "${OAUTH2_PROXY_NO_RESTART:-}" == 1 ]] || $KUBECTL rollout restart "deployment/$release" -n "$NAMESPACE"
}

#   pa_gate_state RELEASE HOST_VAR ALLOWED_GROUPS
#
# Whether a proxy's gate is what this run would deploy (IAM 4.2b): the live
# allowed_groups in the release's ConfigMap (read as health-check iamartefacts reads
# it), the live 403 page and the pod template's gate-page-sha256 against the page
# ALLOWED_GROUPS renders. 0 equal, 1 drift (PA_DRIFT says what), 3 the release is
# not deployed, 4 a read failed.
pa_gate_state() {
    local release="$1" host_var="$2" allowed="$3" cm live want page want_sha live_sha ann
    PA_DRIFT=""
    $KUBECTL get deployment "$release" -n "$NAMESPACE" >/dev/null 2>&1 || return 3
    cm="$($KUBECTL get configmap "$release" -n "$NAMESPACE" -o json 2>/dev/null)" || return 4
    live="$(pa_live_groups <<<"$cm" | cut -f2)"
    want="$(grep -o '"[^"]*"' <<<"$allowed" | tr -d '"' | sort -u | paste -sd ' ')"
    [[ "$live" == "$want" ]] || PA_DRIFT="allowed_groups [$live] → [$want]"
    if [[ "$host_var" != PORTAL_DOMAIN ]]; then
        page="$(gate_error_html "$host_var" "$allowed")" || return 4
        want_sha="$(printf '%s\n' "$page" | sha256sum | cut -d' ' -f1)"
        live_sha="$(gate_page_sha "$release")"
        ann="$($KUBECTL get deployment "$release" -n "$NAMESPACE" \
            -o jsonpath='{.spec.template.metadata.annotations.medcea/gate-page-sha256}' 2>/dev/null)" || return 4
        [[ "$live_sha" == "$want_sha" && "$ann" == "$want_sha" ]] \
            || PA_DRIFT="${PA_DRIFT:+$PA_DRIFT; }403 page"
    fi
    [[ -z "$PA_DRIFT" ]]
}

#   pa_live_groups < CONFIGMAP_JSON
#
# RELEASE<TAB>roles (sorted, space-separated; "-" without allowed_groups) for each
# oauth2-proxy ConfigMap (a single one or a List) on stdin. The one reader of a
# proxy's live gate: health-check iamartefacts and the scoped modes both use it.
pa_live_groups() {
    python3 -c '
import json, re, sys
raw = sys.stdin.read().strip()
d = json.loads(raw) if raw else {"items": []}
for it in d.get("items") or ([d] if d.get("kind") == "ConfigMap" else []):
    cfg = (it.get("data") or {}).get("oauth2_proxy.cfg") or ""
    m = re.search(r"(?m)^\s*allowed_groups\s*=\s*(.*)$", cfg)
    roles = " ".join(sorted(set(re.findall(r"\"([^\"]*)\"", m.group(1))))) if m else "-"
    print(it["metadata"]["name"] + "\t" + (roles or "-"))'
}

#   app_gate MODE RELEASE CLIENT_ID CLIENT_SECRET COOKIE_SECRET HOST_VAR HOST VALUES_TEMPLATE [APP_SERVICE]
#
# An app's sign-in gate (the apps' _gate, IAM 4.2b). MODE full: what the app deploys
# did before 4.2b, command for command — policy_groups, the 403 page, the values
# file, deploy_oauth2_proxy (which restarts). MODE scoped (--gate-only): nothing when
# pa_gate_state says equal or the release is not deployed; else the same, without
# the restart, then rollout status. Prints one line per gate in scoped mode.
# Leaves ALLOWED_GROUPS set, as the inline blocks did.
app_gate() {
    local mode="$1" release="$2" client="$3" secret="$4" cookie="$5" host_var="$6" host="$7" tpl="$8" svc="${9:-}"
    local values rc=0
    ALLOWED_GROUPS="$(policy_groups "$host_var")"
    if [[ "$mode" == scoped ]]; then
        pa_gate_state "$release" "$host_var" "$ALLOWED_GROUPS" || rc=$?
        case $rc in
            0) echo "  $host_var ($release): unchanged"; return 0 ;;
            3) echo "  $host_var ($release): not deployed (the app's full deploy installs it)"; return 0 ;;
            4) echo "ERROR: cannot read $release's live gate." >&2; return 1 ;;
        esac
    fi
    # Bare calls, never `|| return`: the deploy scripts run under set -e, and a
    # function called in a || list runs without it (a failed helm would go on).
    values=$(mktemp "/tmp/$release-values-XXXXXX.yaml")
    gate_error_page "$release" "$host_var" "$ALLOWED_GROUPS"
    if [[ -n "$svc" ]]; then
        APP_SERVICE="$svc" render "$tpl" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE APP_SERVICE ALLOWED_GROUPS > "$values"
    else
        render "$tpl" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE ALLOWED_GROUPS > "$values"
    fi
    if [[ "$mode" == scoped ]]; then
        OAUTH2_PROXY_NO_RESTART=1 deploy_oauth2_proxy "$release" "$client" "$secret" "$cookie" "$host" "$values"
        rm -f "$values"
        $KUBECTL rollout status "deployment/$release" -n "$NAMESPACE" --timeout=4m
        echo "  $host_var ($release): re-rendered ($PA_DRIFT)"
    else
        deploy_oauth2_proxy "$release" "$client" "$secret" "$cookie" "$host" "$values"
        rm -f "$values"
    fi
}
