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

deploy_oauth2_proxy() {
    local release="$1" client_id="$2" client_secret="$3" cookie_secret="$4" host="$5" values="$6"
    shift 6
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
      --timeout 5m "$@"
    # A changed values file alone does not roll the pod (the config lives in a
    # Secret the chart mounts); restart so the new configuration is live.
    $KUBECTL rollout restart "deployment/$release" -n "$NAMESPACE"
}
