#!/bin/bash

# microk8s commands need sudo only when the invoking user is not in the microk8s
# group. Detecting that instead of hardcoding `sudo` lets a member of the group
# deploy without a password prompt, while leaving every other case unchanged.
if microk8s status --timeout 5 >/dev/null 2>&1; then
    MK8S="microk8s"
else
    MK8S="sudo microk8s"
fi
set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/config.env"

# Colors
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}--- Ubuntu PC: Environment Validation for $NAMESPACE (MicroK8s) ---${NC}"

# --- FAST EXIT: already deployed ---
# The guard used to require a Juju controller, because Kubeflow was the last
# thing bootstrap did. Juju is retired, so a running MicroK8s is now the whole
# condition — otherwise this would keep short-circuiting for as long as the old
# juju snap happened to still be installed.
# The API answering is not enough: a run that died between install and step 6
# leaves a live cluster with no ingress or storage, and skipping would make that
# permanent. Require the addons too.
_addons_done() {
    local st
    st=$($MK8S status --format short 2>/dev/null) || return 1
    for a in dns hostpath-storage rbac ingress helm3; do
        grep -q "/$a: enabled" <<<"$st" || return 1
    done
}
if snap list 2>/dev/null | grep -q microk8s && \
   $MK8S kubectl cluster-info &>/dev/null && _addons_done; then
    echo -e "${GREEN}MicroK8s already up — skipping bootstrap.${NC}"
    exit 0
fi

# Everything below installs, starts, configures or wipes MicroK8s, which needs a
# sudo that honours -E. Restored when this script exits, however it exits.
source "$REPO_ROOT/infra/lib-sudo.sh"
classic_sudo_begin

# --- 1. CLEANUP LEGACY KUBERNETES ---
if [ -f /usr/local/bin/k3s-uninstall.sh ]; then
    echo -e "${YELLOW}Legacy K3s detected. Purging...${NC}"
    sudo /usr/local/bin/k3s-uninstall.sh || true
    sudo rm -rf /etc/rancher /var/lib/rancher /var/lib/kubelet ~/.kube
fi

INSTALL_MK8S=false
source "$REPO_ROOT/infra/lib-mk8s-remove.sh"

# --- 2. MICROK8S RESET LOGIC ---
if snap list | grep -q microk8s; then
    read -p "🚨 Fully wipe MicroK8s and reinstall? (y/N): " K8S_WIPE
    if [[ "$K8S_WIPE" =~ ^[Yy]$ ]]; then
        # Remove Juju first so it doesn't leave orphaned controller state
        if snap list | grep -q juju; then
            echo -e "${YELLOW}Removing Juju...${NC}"
            sudo snap remove juju --purge || true
            sudo rm -rf ~/.local/share/juju
        fi
        echo -e "${RED}Uninstalling MicroK8s...${NC}"
        remove_microk8s
        INSTALL_MK8S=true
    fi
else
    INSTALL_MK8S=true
fi

# --- 3. MICROK8S INSTALLATION ---
if [ "$INSTALL_MK8S" = true ]; then
    # Pods an earlier removal left running get the new containerd SIGKILLed
    # as it starts, and snap rolls the install back.
    kill_orphan_pods
    echo -e "${YELLOW}Installing MicroK8s (${K8S_CHANNEL})...${NC}"
    sudo snap install microk8s --channel="${K8S_CHANNEL}" --classic

    echo -e "${YELLOW}Configuring user permissions...${NC}"
    sudo usermod -a -G microk8s "$USER"
    sudo mkdir -p "$HOME/.kube"
    sudo chown -f -R "$USER" "$HOME/.kube"

    echo -e "${YELLOW}Starting MicroK8s...${NC}"
    # snapd's CLI rather than `microk8s start`: one less step through the
    # wrapper's `sudo -E` (infra/lib-sudo.sh). Same effect on a fresh install.
    sudo snap start --enable microk8s
    sudo rm -f /var/snap/microk8s/current/var/lock/stopped.lock

    echo -e "${YELLOW}Waiting 15s for daemon to initialize...${NC}"
    sleep 15
fi

# --- 4. WAIT FOR API ---
# --wait-ready exits immediately if the daemon socket isn't up yet (fresh install),
# so we retry in a loop until it either succeeds or we hit the deadline.
echo -e "${YELLOW}Waiting for MicroK8s to be ready (up to 10 min)...${NC}"
DEADLINE=$(($(date +%s) + 600))
while true; do
    if $MK8S kubectl cluster-info &>/dev/null; then
        echo -e "${GREEN}MicroK8s is running!${NC}"
        break
    fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo -e "${RED}ERROR: MicroK8s did not become ready after 10 min.${NC}"
        echo -e "${YELLOW}Run '$MK8S inspect' to diagnose.${NC}"
        exit 1
    fi
    sleep 10
done

# --- 5. DOCKER HUB AUTH (before addon/image pulls) ---
# Calico, MetalLB, and Juju all pull from docker.io during addon enablement.
# Credentials must be in place before enabling addons to avoid 429 rate limits.
if [[ -n "${DOCKERHUB_USER:-}" && -n "${DOCKERHUB_PASS:-}" ]]; then
    echo -e "${YELLOW}Configuring Docker Hub credentials for containerd...${NC}"
    DOCKER_CERTS_DIR="/var/snap/microk8s/current/args/certs.d/docker.io"
    sudo mkdir -p "$DOCKER_CERTS_DIR"
    sudo tee "$DOCKER_CERTS_DIR/hosts.toml" > /dev/null <<EOF
server = "https://registry-1.docker.io"

[host."https://registry-1.docker.io"]
  capabilities = ["pull", "resolve"]
  [host."https://registry-1.docker.io".auth]
    username = "$DOCKERHUB_USER"
    password = "$DOCKERHUB_PASS"
EOF
    sudo systemctl restart snap.microk8s.daemon-containerd
    sleep 5
fi

# --- 6. ENABLE ADDONS ---
# dns:8.8.8.8      — reliable external DNS; default CoreDNS can fail on some routers
# hostpath-storage — PV provisioner for stateful workloads
# rbac             — required by Juju/Charmed Kubeflow
# ingress          — nginx ingress for Keycloak, Grafana, Node-RED
# helm3            — Helm for the MedCEA services
# metallb          — assigns real LAN IPs to LoadBalancer services (Kubeflow's istio-gateway)
echo -e "${YELLOW}Enabling add-ons...${NC}"
$MK8S enable dns:8.8.8.8
$MK8S enable hostpath-storage
$MK8S enable rbac
$MK8S enable ingress
$MK8S enable helm3
# MetalLB [RETIRED] — it existed solely to give Kubeflow's istio-ingressgateway a
# real LAN IP, which is also what forced KUBEFLOW_IP to be a static address with a
# DHCP reservation. Every remaining service is served by the nginx ingress.
# $MK8S enable metallb:"${METALLB_RANGE}"

# Increase inotify limits — Juju and Kubeflow open many file watches
sudo sysctl -w fs.inotify.max_user_instances=1280
sudo sysctl -w fs.inotify.max_user_watches=655360

# --- 7. WAIT FOR ALL NODES READY ---
echo -e "${YELLOW}Waiting for all nodes to be Ready (up to 5 min)...${NC}"
DEADLINE=$(($(date +%s) + 300))
while true; do
    NOT_READY=$($MK8S kubectl get nodes --no-headers 2>/dev/null | \
      grep -c "NotReady" || true)

    if [ "$NOT_READY" -eq 0 ]; then
        echo -e "${GREEN}All nodes are Ready!${NC}"
        break
    fi

    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo -e "${RED}ERROR: Nodes did not become Ready after 5 min.${NC}"
        echo -e "${YELLOW}Check: $MK8S kubectl get nodes${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Waiting for nodes to be Ready... ($NOT_READY not ready)${NC}"
    sleep 10
done

# --- 8. ALIASES & KUBECONFIG ---
sudo snap alias microk8s.kubectl kubectl 2>/dev/null || true
sudo snap alias microk8s.helm3 helm 2>/dev/null || true

# Write kubeconfig for the current user so Juju can reach the cluster
$MK8S config > "$HOME/.kube/config"
chmod 600 "$HOME/.kube/config"

# --- 9-11. JUJU CONTROLLER + KUBEFLOW MODEL ---   [RETIRED]
#
# Juju existed only to manage Charmed Kubeflow. With the workbench moved to
# JupyterHub (a single Helm release in infra/deploy-workbench.sh), there is nothing left for
# it to manage — so the controller, its MongoDB state store and the skip-guard
# built around them are all retired.
#
# Note the knock-on: the old fast-exit above returned early whenever a Juju
# controller existed, so bootstrap did almost nothing on a re-run. Without it,
# bootstrap now falls through to completion normally, which is what you want —
# the addon and sysctl steps above are all idempotent.
#
# # --- 9. SKIP IF KUBEFLOW ALREADY DEPLOYED ---
# # Juju controller existence is the authoritative skip guard.
# if snap list 2>/dev/null | grep -q juju && \
#    juju controllers 2>/dev/null | grep -q "k8s-controller"; then
#     echo -e "${GREEN}Juju controller exists — Kubeflow already deployed. Skipping.${NC}"
#     echo -e "${GREEN}Bootstrap complete!${NC}"
#     exit 0
# fi
#
# # --- 10. INSTALL JUJU ---
# if ! snap list | grep -q juju; then
#     echo -e "${YELLOW}Installing Juju (3.6/stable)...${NC}"
#     sudo snap install juju --channel=3.6/stable
# fi
#
# # --- 11. BOOTSTRAP JUJU CONTROLLER ---
# echo -e "${YELLOW}Bootstrapping Juju controller into MicroK8s...${NC}"
# juju add-k8s k8s-cloud --client 2>/dev/null || true
# juju bootstrap k8s-cloud k8s-controller
# juju add-model kubeflow
#

echo -e "${GREEN}Bootstrap complete.${NC}"

# --- 12. DEPLOY CHARMED KUBEFLOW ---   [RETIRED]
#
# Replaced by JupyterHub (infra/deploy-workbench.sh), which authenticates against Keycloak
# directly and is served by the existing nginx ingress. That removes Juju, its
# MongoDB state store, MetalLB, the static LAN IP, dex-auth, oidc-gatekeeper and
# Istio — none of which existed for any reason other than this one deployment.
#
# Measured before removal: 37 charm units (3 unhealthy), ~815 MB for the Juju
# control plane alone, and no reference to Kubeflow anywhere in the application
# code. Commented rather than deleted so the decision is reversible.
#
# To finish reclaiming the resources, after the workbench is proven:
#     juju destroy-model kubeflow --destroy-storage
#     sudo snap remove juju && rm -rf ~/.local/share/juju
#
# # --- 12. DEPLOY CHARMED KUBEFLOW ---
# echo -e "${YELLOW}Deploying Charmed Kubeflow ${KF_CHANNEL}...${NC}"
# juju deploy kubeflow --trust --channel="${KF_CHANNEL}"
#
# # Configure default credentials (can be overridden via patch-dex-keycloak.sh for SSO)
# # Note: oidc-gatekeeper public-url was removed in CKF 1.9; dex-auth issuer-url is sufficient.
# juju config dex-auth static-username="${ADMIN_USER}"
# juju config dex-auth static-password="${ADMIN_PASS}"
# juju config dex-auth issuer-url="http://${KUBEFLOW_IP}/dex"
#
# echo -e "${YELLOW}Kubeflow deployment initiated. Waiting for pods (up to 30 min)...${NC}"
# echo -e "${YELLOW}Monitor with: watch -c juju status --color${NC}"
#
# DEADLINE=$(($(date +%s) + 1800))
# while true; do
#     KFPODS=$($MK8S kubectl get pods -n kubeflow --no-headers 2>/dev/null | \
#       grep -c "Running" || true)
#
#     if [ "$KFPODS" -ge 10 ]; then
#         echo -e "${GREEN}Kubeflow is running ($KFPODS pods up).${NC}"
#         break
#     fi
#
#     if [ "$(date +%s)" -ge "$DEADLINE" ]; then
#         echo -e "${YELLOW}Warning: Kubeflow still starting ($KFPODS pods Running) — continuing anyway.${NC}"
#         echo -e "${YELLOW}Monitor: watch -c juju status --color${NC}"
#         break
#     fi
#
#     echo -e "${YELLOW}Kubeflow starting... ($KFPODS pods Running, waiting for ≥10)${NC}"
#     sleep 30
# done
#
# echo -e "${GREEN}Run ./patch-dex-keycloak.sh after Keycloak is live to wire SSO.${NC}"
# echo -e "${GREEN}Bootstrap complete!${NC}"
