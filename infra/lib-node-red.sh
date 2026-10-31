#!/usr/bin/env bash
# infra/lib-node-red.sh — Node-RED's admin API and its flows' placeholders (IAM 3.3).
#
#   nr_token NS               read that token once (before $(nr_curl ...) subshells)
#   nr_curl NS CURL_ARGS...   curl, with the deploy token of Secret node-red-admin-tokens
#                             sent as "Authorization: Bearer" from a pipe, never in argv
#   nr_flow_values NS         "PLACEHOLDER value" lines: the non-secret placeholders of
#                             apps/node-red/flows/*.json, for deploy.sh (which adds the
#                             passwords) and health-check.sh's diff against git
#   nr_settings_checksum      sha256 of k8s/node-red/settings.js (the pod's
#                             medcea/settings-checksum)
#
# Node-RED's editor and admin API answer 401 without a token since IAM 3.3 (adminAuth,
# k8s/node-red/settings.js); the deploy token is the scripts' way in (user system:deploy).
# nr_curl sends no header while the Secret does not exist yet: a Node-RED deployed before
# IAM 3.3 has no adminAuth and needs none, so the app scripts work before and after
# ./deploy-infra.sh. Needs KUBECTL and REPO_ROOT; takes no lock (the callers hold
# medcea_lock, or only read).

_NR_TOKEN="" _NR_TOKEN_NS=""

nr_token() {   # NS: read the token once; callers do this first so $(nr_curl ...) subshells reuse it
    [[ "$_NR_TOKEN_NS" == "$1" ]] && return 0
    _NR_TOKEN="$($KUBECTL get secret node-red-admin-tokens -n "$1" -o jsonpath='{.data.deploy}' 2>/dev/null \
        | base64 -d 2>/dev/null)" || _NR_TOKEN=""
    _NR_TOKEN_NS="$1"
    [[ -n "$_NR_TOKEN" ]] || echo "  (no Secret node-red-admin-tokens in $1: calling Node-RED without a token, as before IAM 3.3)" >&2
    return 0
}

nr_curl() {
    local ns="$1"; shift
    nr_token "$ns"
    if [[ -z "$_NR_TOKEN" ]]; then
        curl "$@"
    else
        curl -H @<(printf 'Authorization: Bearer %s\n' "$_NR_TOKEN") "$@"
    fi
}

nr_flow_values() {
    local ns="$1"
    # __TOPIC_ROOT__ is the root the onboarding wizard configures on every board it
    # flashes (edge/flash-device.sh --topic-root, default PROJECT_NAME).
    printf '%s %s\n' \
        __TOPIC_ROOT__ "${PROJECT_NAME:-medcea}" \
        __MQTT_HOST__  "mosquitto.${ns}.svc.cluster.local" \
        __MQTT_USER__  node-red \
        __PG_HOST__    "${PG_RELEASE:-rdbms}-postgresql.${ns}.svc.cluster.local" \
        __PG_PORT__    5432 \
        __PG_DB__      "${POSTGRES_DB:-postgres}"
}

nr_settings_checksum() {
    sha256sum "$REPO_ROOT/k8s/node-red/settings.js" | awk '{print $1}'
}
