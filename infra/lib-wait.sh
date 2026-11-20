#!/usr/bin/env bash
# infra/lib-wait.sh — readiness helpers, sourced by the deploy scripts.
#
# Exists because "kubectl rollout status returned, therefore the service is
# usable" is false, and believing it produced deploys that reported FAILED for
# work that had actually succeeded. A rollout completing means the Deployment
# reports available. It does not mean the Endpoints object has the new pod, that
# the ingress controller has reloaded, or that the process inside the container
# has finished starting. Between those is a window of seconds in which a request
# gets 502, 503 or a connection refusal.
#
# The rule these enforce: never claim a component is deployed, and never call its
# API, until it has actually answered.
#
#   wait_for_http URL [timeout_s] [label]   poll until the URL answers
#   wait_for_rollout DEPLOY NS [timeout]    rollout status, with pod state on failure
#
# wait_for_http treats any HTTP response as success, including 401/403/302 — a
# service behind oauth2-proxy answering 403 is up and serving. Only a connection
# failure or a 5xx counts as not-ready, because those are what the race produces.
#
# A platform name (the URL's host is $DOMAIN or ends in .$DOMAIN, with PLATFORM_IP
# an IPv4 address) is connected to at PLATFORM_IP directly (curl --resolve, the
# URL's port, else 443 and 80), so the wait asks whether the service answers, not
# whether this machine's DNS knows the name: a custom domain whose names did not
# resolve made healthy services look dead (fresh install, 20 Nov 2026). Whether
# the names resolve is deploy-infra's own check (dns_names_check, infra/lib-dns.sh).
# The certificate is still verified against the name and the platform CA.

wait_for_http() {
    local url="$1" timeout="${2:-120}" label="${3:-$1}"
    local deadline=$(( SECONDS + timeout )) code
    # The platform serves its own CA-signed certificates, so plain curl cannot
    # verify them and returns 000 — indistinguishable from "not up yet", which
    # made a perfectly healthy service look like a failed deploy. Trust the CA
    # rather than disabling verification.
    local -a ca=()
    local _root="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
    [[ -f "$_root/.ca/ca.crt" ]] && ca=(--cacert "$_root/.ca/ca.crt")
    local -a resolve=()
    platform_resolve "$url"
    while [ "$SECONDS" -lt "$deadline" ]; do
        # NOT `|| echo 000`: curl -w already prints 000 on failure, so the
        # fallback appends a second one and $code becomes "000\n000", which
        # matches neither branch below and reports a dead endpoint as ready.
        # Same trap as `grep -c ... || echo 0` in CLAUDE.md. Assign, don't echo.
        code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "${ca[@]}" "${resolve[@]}" "$url" 2>/dev/null) || code=000
        case "$code" in
            000|5??) ;;                       # unreachable or still starting
            *) return 0 ;;                    # anything else means it is serving
        esac
        sleep 2
    done
    echo "  ✗ ${label} did not answer within ${timeout}s (last HTTP ${code:-000}): ${url}" >&2
    return 1
}

# platform_resolve URL — fills the caller's array `resolve` with the curl --resolve
# arguments wait_for_http uses (see there); empty for any other host. Also for a
# deploy's own later curl to a platform name (apps/report).
platform_resolve() {
    local url="$1" host port d ip="${PLATFORM_IP:-}" p
    d="${DOMAIN:-}"; d="${d,,}"; d="${d%.}"
    [[ -n "$d" && "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 0
    [[ "$url" =~ ^(https?)://([^/:?#]+)(:([0-9]+))? ]] || return 0
    host="${BASH_REMATCH[2],,}"; port="${BASH_REMATCH[4]}"
    [[ "$host" == "$d" || "$host" == *".$d" ]] || return 0
    for p in ${port:-443 80}; do
        resolve+=(--resolve "${host}:${p}:${ip}")
    done
}

wait_for_rollout() {
    local deploy="$1" ns="$2" timeout="${3:-5m}" kubectl_cmd="${KUBECTL:-kubectl}"
    if ! $kubectl_cmd rollout status "deployment/$deploy" -n "$ns" --timeout="$timeout"; then
        echo "  ✗ ${deploy} did not finish rolling out. Current state:" >&2
        $kubectl_cmd get pods -l "app=$deploy" -n "$ns" >&2 2>/dev/null || true
        $kubectl_cmd describe deployment "$deploy" -n "$ns" 2>/dev/null | tail -15 >&2 || true
        return 1
    fi
    return 0
}
