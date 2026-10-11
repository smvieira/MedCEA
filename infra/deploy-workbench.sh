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
#   - the existing nginx ingress, on the same hostname Kubeflow used
#   - VS Code and real-time collaboration inside the user's own pod
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
# shellcheck source=/dev/null
source config.env
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-wait.sh"

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
WORKBENCH_IMAGE="${WORKBENCH_IMAGE:-quay.io/jupyter/scipy-notebook:latest}"
WORKBENCH_STORAGE="${WORKBENCH_STORAGE:-10Gi}"

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

log "Deploying JupyterHub $CHART_VERSION to https://$WORKBENCH_DOMAIN"

$HELM repo add jupyterhub https://hub.jupyter.org/helm-chart/ >/dev/null 2>&1 || true
$HELM repo update jupyterhub >/dev/null 2>&1 || true

VALUES=$(mktemp /tmp/workbench-values-XXXXXX.yaml)
trap 'rm -f "$VALUES"' EXIT

cat > "$VALUES" <<VALEOF
hub:
  config:
    JupyterHub:
      authenticator_class: generic-oauth
      admin_access: true
    Authenticator:
      admin_users: ["${ADMIN_USER}"]
      # Any authenticated realm user may sign in. To restrict, create a realm
      # role and switch to allowed_groups with a groups claim mapper.
      allow_all: true
    GenericOAuthenticator:
      client_id: workbench
      client_secret: "${WORKBENCH_SECRET}"
      oauth_callback_url: https://${WORKBENCH_DOMAIN}/hub/oauth_callback
      authorize_url: https://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth
      token_url: http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token
      userdata_url: http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo
      login_service: "Keycloak"
      username_claim: preferred_username
      scope: ["openid", "profile", "email"]

proxy:
  service:
    type: ClusterIP          # the nginx ingress fronts this; no LoadBalancer, no MetalLB

singleuser:
  image:
    name: ${WORKBENCH_IMAGE%:*}
    tag: ${WORKBENCH_IMAGE##*:}
  storage:
    capacity: ${WORKBENCH_STORAGE}
  memory: { guarantee: 512M, limit: 4G }
  cpu: { guarantee: 0.1, limit: 2 }
  defaultUrl: "/lab"
  # Installed into the user's persistent home, so only the first start pays for
  # it. Baking these into an image is the better answer at scale — see the
  # infra/workbench.Dockerfile — but this keeps the deployment to one Helm
  # release with no registry to run.
  lifecycleHooks:
    postStart:
      exec:
        command:
          - "sh"
          - "-c"
          - >
            test -x "\$HOME/.local/bin/code-server" ||
            (pip install --quiet --user jupyter-collaboration jupyter-vscode-proxy &&
             curl -fsSL https://code-server.dev/install.sh |
               sh -s -- --method=standalone --prefix="\$HOME/.local" ) || true

cull:
  enabled: true
  timeout: 3600            # reclaim a user pod after an hour idle
  every: 300

ingress:
  enabled: true
  ingressClassName: nginx
  hosts: ["${WORKBENCH_DOMAIN}"]
  tls:
    - hosts: ["${WORKBENCH_DOMAIN}"]
      secretName: cea-tls
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
VALEOF

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
log "Sign in with a Keycloak account in realm '$KEYCLOAK_REALM'."
log "The first launch pulls the notebook image and installs VS Code into the"
log "user's home volume, so it is slow once and fast afterwards."
