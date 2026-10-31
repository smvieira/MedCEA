#!/usr/bin/env bash
#
# infra/deploy-workbench.sh — the AI workbench: JupyterHub, authenticated by Keycloak.
#
# This is infrastructure, not app content. deploy-infra.sh already creates the
# workbench Keycloak client, puts the card on the portal and prints the URL in
# its summary — so it deploys the service too, rather than minting an identity
# for something it then asks you to install separately. It is also what replaced
# Charmed Kubeflow, which bootstrap-infra.sh deployed.
#
# Called by deploy-infra.sh (unless WORKBENCH_ENABLED=false), and runnable on its
# own to redeploy just the workbench.
#
# Replaces Charmed Kubeflow. Kubeflow provided a Jupyter environment and, in this
# deployment, nothing else — no pipelines, no Katib, no KServe, and no reference
# to any of it in the application code. It cost 37 Juju charm units plus a Juju
# control plane, and it dragged in MetalLB, a static LAN IP, Istio, dex-auth and
# oidc-gatekeeper, none of which existed for any other reason.
#
# What this deploys instead:
#   - one Helm release (Zero-to-JupyterHub)
#   - per-user notebook pods, spawned on demand and culled when idle
#   - Keycloak directly via GenericOAuthenticator — no Dex in the middle
#   - its gate compiled from the access policy (IAM 3.2, policy_workbench in
#     infra/lib-oauth2-proxy.sh): allowed_groups and admin_groups from the
#     research_workbench group's `tool:` block, admin_access false (a hub admin
#     never opens another person's server), delete_pvc false (removing a hub user
#     keeps the home). A policy that does not compile stops the deploy before helm;
#     IAM_GATES=false renders the pre-policy sign-in (any realm account).
#   - the existing nginx ingress, on the same hostname Kubeflow used
#   - VS Code and real-time collaboration inside the user's own pod
#   - (IAM 3.2b) the example notebooks, read-only in every server (ConfigMap
#     workbench-examples from k8s/workbench/examples/), whose medcea_data.py signs the
#     person in with a device code and reads config-api with their own token; the
#     notebooks' only platform hops (Keycloak, config-api) are compiled from the
#     policy's network.clients.notebooks (policy_workbench_egress) and open only while
#     IAM_POSTGREST_JWT and IAM_DB_ROLES are true, in config.env and live (config-api
#     runs JWT, the database enforces); the database and frontend deploys close them
#     on a switch to false (workbench_egress_close); nbstripout as every home's global
#     git filter; WORKBENCH_NOTEBOOK_REPO, the research repository the guide names
#   - home volumes (claim-<name>) are kept by everything here; only deleting the
#     namespace deletes them, and every uninstall path warns first
#

# microk8s commands need sudo only when the invoking user is not in the microk8s
# group. Detecting that instead of hardcoding `sudo` lets a member of the group
# deploy without a password prompt, while leaving every other case unchanged.
if microk8s status --timeout 5 >/dev/null 2>&1; then
    MK8S="microk8s"
else
    MK8S="sudo microk8s"
fi
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-infra.sh
# shellcheck source=/dev/null
source config.env
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-wait.sh"
source "$SCRIPT_DIR/lib-render.sh"
source "$SCRIPT_DIR/lib-oauth2-proxy.sh"   # policy_workbench
source "$REPO_ROOT/apps/database/lib-db-apply.sh"   # _dba_psql, for pgrst_db_enforcing
source "$SCRIPT_DIR/lib-postgrest.sh"      # pgrst_live_mode, pgrst_db_enforcing (the hops' live check)

# When deploy-infra.sh calls this, $MK8S is already set; standalone it is not.
if [[ -z "${MK8S:-}" ]]; then
    if microk8s status --timeout 5 >/dev/null 2>&1; then MK8S="microk8s"; else MK8S="sudo microk8s"; fi
fi

KUBECTL="$MK8S kubectl"
HELM="$MK8S helm3"
CHART_VERSION="4.4.1"

log() { echo -e "\033[0;32m[workbench]\033[0m $*"; }
die() { echo -e "\033[0;31m[workbench] ERROR:\033[0m $*" >&2; exit 1; }

: "${NAMESPACE:?}" ; : "${KEYCLOAK_DOMAIN:?}" ; : "${DOMAIN:?}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-medcea}"
WORKBENCH_DOMAIN="${WORKBENCH_DOMAIN:-ai-workbench.$DOMAIN}"
PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.$DOMAIN}"   # named on the 403 page
# Pinned: the tag that ships JupyterLab 4.6.4 with the git panel (@jupyterlab/git
# 0.55.0) and nbdime 4.0.4, as verified on the running server on 2026-10-31. A date
# tag or a digest (name:tag@sha256:…) pins harder; `latest` is accepted with a warning.
WORKBENCH_IMAGE="${WORKBENCH_IMAGE:-quay.io/jupyter/scipy-notebook:latest@sha256:d416eea5c12a44981c2fcb56520649dbd92f7ae5983f4e68e14d1d0ebdf0c2ce}"
# Split here: the values template (k8s/workbench/values.yaml) is filled by
# envsubst, which cannot do ${VAR%:*} itself. A digest stays with the tag (the
# chart writes name:tag), and the name may carry a registry port.
_img="${WORKBENCH_IMAGE%%@*}" _digest=""
[[ "$WORKBENCH_IMAGE" == *@* ]] && _digest="@${WORKBENCH_IMAGE#*@}"
if [[ "${_img##*/}" == *:* ]]; then
    WORKBENCH_IMAGE_NAME="${_img%:*}" WORKBENCH_IMAGE_TAG="${_img##*:}$_digest"
else
    WORKBENCH_IMAGE_NAME="$_img" WORKBENCH_IMAGE_TAG="latest$_digest"
fi
WORKBENCH_STORAGE="${WORKBENCH_STORAGE:-10Gi}"
# The research repository on GitHub the git guide names (OWNER/REPO, IAM 3.2b);
# empty: the guide says to ask an administrator.
WORKBENCH_NOTEBOOK_REPO="${WORKBENCH_NOTEBOOK_REPO:-}"
[[ -z "$WORKBENCH_NOTEBOOK_REPO" || "$WORKBENCH_NOTEBOOK_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
    || die "WORKBENCH_NOTEBOOK_REPO='$WORKBENCH_NOTEBOOK_REPO' is not OWNER/REPO (e.g. smvieira/medcea-notebooks)"

[[ -n "${WORKBENCH_SECRET:-}" ]] || die "WORKBENCH_SECRET is not set in config.env.
       Run ./deploy-infra.sh to create the 'workbench' Keycloak client first."

# The retired Kubeflow stack published an Ingress for this exact hostname
# (kubeflow-domain, in the kubeflow namespace, pointing at istio-ingressgateway).
# Two Ingresses claiming one host is undefined behaviour in nginx-ingress and the
# older one generally keeps winning, so the workbench would deploy cleanly and
# still be unreachable. Remove it before taking the name.
if $KUBECTL get ingress kubeflow-domain -n kubeflow >/dev/null 2>&1; then
    log "Removing the old Kubeflow ingress that claims $WORKBENCH_DOMAIN"
    $KUBECTL delete ingress kubeflow-domain -n kubeflow --ignore-not-found
fi

# Fail closed: a policy that does not compile leaves the running hub as it is.
policy_workbench || die "the access policy does not compile to the workbench's gate (python3 apps/iam/compiler/cli.py check)"
if [[ "$WORKBENCH_ALLOW_ALL" == "true" ]]; then
    log "Gate: any realm account (IAM_GATES=false); hub admin: $ADMIN_USER"
else
    log "Gate: $WORKBENCH_ALLOWED_GROUPS; hub admins: $WORKBENCH_ADMIN_GROUPS (from the access policy)"
fi
policy_workbench_egress || die "the access policy does not compile to the notebooks' network hops (python3 apps/iam/compiler/cli.py check)"
# config.env is not enough: the documented order runs this (through ./deploy-infra.sh)
# before the frontend and database deploys switch, so the hops open only when config-api
# runs JWT and the database enforces now. Otherwise none, until this runs again.
if [[ "$WORKBENCH_EGRESS" != "[]" ]]; then
    _pg_pod="$($KUBECTL get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ "$(pgrst_live_mode "$NAMESPACE" 2>/dev/null || echo unknown)" != jwt || -z "$_pg_pod" ]] \
       || ! pgrst_db_enforcing "$NAMESPACE" "$_pg_pod" "${POSTGRES_DB:-medcea_db}"; then
        WORKBENCH_EGRESS='[]'
        log "WARNING: config.env says IAM_POSTGREST_JWT and IAM_DB_ROLES are true, but config-api or the database has not switched yet: the notebooks get no platform hop. Run ./infra/deploy-workbench.sh again after ./apps/frontend/deploy.sh and ./apps/database/deploy.sh"
    fi
fi
if [[ "$WORKBENCH_EGRESS" == "[]" ]]; then
    log "Notebooks reach no platform service (reading platform data needs IAM_POSTGREST_JWT and IAM_DB_ROLES true)"
else
    log "Notebooks may reach Keycloak and config-api, with each person's own sign-in (network.clients.notebooks)"
fi
[[ "$WORKBENCH_IMAGE_TAG" == latest ]] \
    && log "WARNING: WORKBENCH_IMAGE uses 'latest' without a digest: JupyterLab and its git panel can change under people at any pull"

log "Deploying JupyterHub $CHART_VERSION to https://$WORKBENCH_DOMAIN"

$HELM repo add jupyterhub https://hub.jupyter.org/helm-chart/ >/dev/null 2>&1 || true
$HELM repo update jupyterhub >/dev/null 2>&1 || true

VALUES=$(mktemp /tmp/workbench-values-XXXXXX.yaml)
trap 'rm -f "$VALUES"' EXIT

# The example notebooks and their helper, mounted read-only into every server (a
# running server sees a change within a minute; nothing restarts).
$KUBECTL create configmap workbench-examples -n "$NAMESPACE" --from-file="$REPO_ROOT/k8s/workbench/examples/" \
    --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
log "Example notebooks: ~/medcea-examples (read-only) in every server"

render "$REPO_ROOT/k8s/workbench/values.yaml" WORKBENCH_SECRET WORKBENCH_DOMAIN KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE \
    WORKBENCH_IMAGE_NAME WORKBENCH_IMAGE_TAG WORKBENCH_STORAGE WORKBENCH_NOTEBOOK_REPO WORKBENCH_EGRESS \
    WORKBENCH_ALLOW_ALL WORKBENCH_ADMIN_USERS WORKBENCH_ALLOWED_GROUPS WORKBENCH_ADMIN_GROUPS WORKBENCH_403_MESSAGE > "$VALUES"

$HELM upgrade --install workbench jupyterhub/jupyterhub \
  --version "$CHART_VERSION" \
  --namespace "$NAMESPACE" \
  --values "$VALUES" \
  --timeout 10m

log "Waiting for the hub to become ready..."
$KUBECTL rollout status deployment/hub -n "$NAMESPACE" --timeout=10m || {
    echo "--- hub pod ---"; $KUBECTL get pods -l app=jupyterhub -n "$NAMESPACE"
    echo "--- hub logs ---"; $KUBECTL logs -l component=hub -n "$NAMESPACE" --tail=40 2>/dev/null || true
    die "hub did not become ready"
}

wait_for_http "https://$WORKBENCH_DOMAIN/hub/login" 180 "JupyterHub" || {
    log "The hub rolled out but is not serving through the ingress yet."
    exit 1
}
log "AI Workbench is live: https://$WORKBENCH_DOMAIN"
log "Sign in with a Keycloak account in realm '$KEYCLOAK_REALM' holding a role the policy admits."
log "The first launch pulls the notebook image and installs VS Code into the"
log "user's home volume, so it is slow once and fast afterwards."
log "A running server keeps its old environment (the MEDCEA_* endpoints) until it is"
log "stopped and started again (File > Hub Control Panel, or culled after an hour idle);"
log "network hops and the example files change at once."
