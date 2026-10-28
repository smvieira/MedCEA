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
# Phase 0). A broken policy fails the deploy rather than opening a host.
policy_groups() {
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        echo -e "\033[0;33mWARNING: IAM_GATES=false — $1 gets the pre-policy role list, not the access policy.\033[0m" >&2
        echo '["operator", "qa", "auditor", "admin"]'
        return 0
    fi
    python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile proxy "$1"
}

#   gate_error_page RELEASE HOST_VAR ALLOWED_GROUPS
#
# The proxy's 403 page: "No access to <service>", the roles that may open it and
# "ask an administrator", instead of oauth2-proxy's bare 403. ALLOWED_GROUPS is
# the list the gate is deployed with (from policy_groups, or a fixed one), so the
# page names exactly the roles that gate admits. Written to ConfigMap
# RELEASE-templates, which gate_helm_args mounts at the values files'
# custom_templates_dir; the caller restarts the pod (deploy_oauth2_proxy does).
# The portal keeps its own page (k8s/portal/error.html): there a 403 means no
# platform role at all.
gate_error_page() {
    local release="$1" host_var="$2" allowed="$3" desc
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
    render "$REPO_ROOT/k8s/oauth2-proxy/error.html" GATE_SERVICE GATE_ROLES GATE_PORTAL_URL GATE_LOGOUT_RD \
      | $MK8S kubectl create configmap "$release-templates" -n "$NAMESPACE" --from-file=error.html=/dev/stdin \
          --dry-run=client -o yaml | $MK8S kubectl apply -f - >/dev/null
}

#   mapfile -t ARR < <(gate_helm_args RELEASE)
#
# The helm --set arguments that mount RELEASE-templates at /templates. Optional,
# so a proxy deployed before its page still starts (with oauth2-proxy's page).
gate_helm_args() {
    printf '%s\n' \
      --set "extraVolumes[0].name=gate-templates" \
      --set "extraVolumes[0].configMap.name=$1-templates" \
      --set "extraVolumes[0].configMap.optional=true" \
      --set "extraVolumeMounts[0].name=gate-templates" \
      --set "extraVolumeMounts[0].mountPath=/templates" \
      --set "extraVolumeMounts[0].readOnly=true"
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
    # A changed values file alone does not roll the pod (the config lives in a
    # Secret the chart mounts); restart so the new configuration is live.
    $KUBECTL rollout restart "deployment/$release" -n "$NAMESPACE"
}
