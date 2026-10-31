#!/bin/bash

# Colors (defined early so --help can use them)

# microk8s commands need sudo only when the invoking user is not in the microk8s
# group. Detecting that instead of hardcoding `sudo` lets a member of the group
# deploy without a password prompt, while leaving every other case unchanged.

# All scripts are run from the repository root (config.env is read relatively),
# but locating a sibling script by path rather than by cwd is one less thing to
# get wrong.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# render FILE VAR... — the manifests are templates under k8s/ (infra/lib-render.sh).
source "$SCRIPT_DIR/infra/lib-render.sh"
# MicroK8s and Juju live in /snap/bin, which a shell started before snapd was
# installed (a clean minimal image) does not have on PATH.
case ":$PATH:" in *:/snap/bin:*) ;; *) PATH="$PATH:/snap/bin" ;; esac
if microk8s status --timeout 5 >/dev/null 2>&1; then
    MK8S="microk8s"
else
    MK8S="sudo microk8s"
fi
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# =============================================================================
# BANNER
# =============================================================================
_print_banner() {
    # Herb on the left, mushroom on the right: the two crops MedCEA grows.
    # Strings are $'...' so the backslashes and the backtick in the "d" stay literal;
    # printf %s prints them uninterpreted (echo -e would read \c, \b, ... as escapes).
    local -a plant=(
        $'   .--.  .--.'
        $'  (    \\/    )'
        $'   \'--.||.--\''
        $' .--.  ||  .--.'
        $'(    \\_||_/    )'
        $' \'--.__||__.--\''
        $'       ||'
        $'   ____||____'
        $'   \\        /'
        $'    \\______/'
    )
    local -a title=(
        ''
        ''
        $' __  __            _   ____  _____     _'
        $'|  \\/  |  ___   __| | / ___|| ____|   / \\'
        $'| |\\/| | / _ \\ / _` || |    |  _|    / _ \\'
        $'| |  | ||  __/| (_| || |___ | |___  / ___ \\'
        $'|_|  |_| \\___| \\__,_| \\____||_____|/_/   \\_\\'
        ''
        $' Medical Controlled Environment Agriculture'
        ''
    )
    local -a mush=(
        ''
        ''
        $'      .-~~~~-.'
        $'   .-\' o   .  \'-.'
        $'  /  .    O   o  \\'
        $' (  o   .     .   )'
        $'  \'-.__________.-\''
        $'       |    |'
        $'       |    |'
        $'    ,,,|____|,,,'
    )
    local B='\033[1m' CY='\033[0;36m' RD='\033[0;31m' i pc tc mc
    echo ""
    for i in "${!plant[@]}"; do
        pc="$GREEN"; (( i >= 7 )) && pc="$YELLOW"        # leaves / pot
        tc="$B$GREEN"; [[ "${title[$i]}" == *Medical* ]] && tc="$CY"
        mc="$RD"; (( i >= 7 )) && mc="$NC"; (( i == 9 )) && mc="$GREEN"  # cap / stem / grass
        printf " ${pc}%-16s${NC}  ${tc}%-44s${NC}  ${mc}%s${NC}\n" "${plant[$i]}" "${title[$i]}" "${mush[$i]}"
    done
    echo ""
}

# =============================================================================
# --help
# =============================================================================
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo -e "${GREEN}Usage:${NC}"
    echo "  ./deploy-infra.sh [--help|--configure|--reset [--secrets]|--uninstall]"
    echo ""
    echo -e "${GREEN}Description:${NC}"
    echo "  Deploys the full MedCEA IoT stack onto MicroK8s:"
    echo "  Postgres, Keycloak, Node-RED (+ OAuth2 Proxy), Grafana."
    echo "  ...and the AI workbench (JupyterHub), unless WORKBENCH_ENABLED=false."
    echo ""
    echo -e "${GREEN}First-time setup:${NC}"
    echo "  1. Run:  ./deploy-infra.sh"
    echo "     → Asks for the settings it needs (defaults in [brackets]), writes"
    echo "       config.env from config.env.example, then bootstraps MicroK8s,"
    echo "       deploys all services and creates the Keycloak realm and OAuth"
    echo "       clients automatically."
    echo "  2. Run:  ./deploy-apps.sh --all"
    echo ""
    echo -e "${GREEN}Re-runs are safe:${NC}"
    echo "  If MicroK8s is already set up, bootstrap is skipped."
    echo "  Keycloak realm and clients are created if missing, skipped if present."
    echo ""
    echo -e "${GREEN}Configuration:${NC}"
    echo "  All settings are read from config.env (see config.env.example)."
    echo "  Only empty required values are asked on later runs. To review them all:"
    echo "  ./deploy-infra.sh --configure     (or ./infra/configure.sh on its own)"
    echo ""
    echo -e "${GREEN}Uninstall:${NC}"
    echo "  ./deploy-infra.sh --reset            # wipe the namespace, keep MicroK8s (fast)"
    echo "  ./deploy-infra.sh --reset --secrets  # ...and blank generated credentials"
    echo "  ./deploy-infra.sh --uninstall        # remove MicroK8s entirely (slow)"
    echo "  Removes Juju, MicroK8s, and all associated data. Prompts for confirmation."
    exit 0
fi

# One deploy at a time — before --uninstall/--reset and before configure.sh
# (infra/lib-lock.sh).
source "$SCRIPT_DIR/infra/lib-lock.sh"
medcea_lock

# =============================================================================
# --uninstall
# =============================================================================
if [[ "${1:-}" == "--uninstall" ]]; then
    echo -e "${RED}--- MedCEA Uninstall ---${NC}"
    echo -e "${RED}This will permanently remove:${NC}"
    echo "  - All deployed services (Postgres, Keycloak, Node-RED, Grafana, JupyterHub)"
    echo "  - MicroK8s and all cluster data (PersistentVolumes, namespaces, pods)"
    echo "  - kubeconfig (~/.kube)"
    echo ""
    # install.sh --uninstall-all has already listed everything and asked.
    if [[ "${MEDCEA_CONFIRMED:-}" != "1" ]]; then
        read -p "Type 'yes' to confirm uninstall: " _CONFIRM
        if [[ "$_CONFIRM" != "yes" ]]; then
            echo "Aborted."
            exit 0
        fi
    fi

    echo -e "${YELLOW}Removing Juju...${NC}"
    if snap list 2>/dev/null | grep -q juju; then
        sudo snap remove juju --purge || true
        sudo rm -rf ~/.local/share/juju
    else
        echo "  Juju not installed — skipping."
    fi

    echo -e "${YELLOW}Removing MicroK8s...${NC}"
    source "$SCRIPT_DIR/infra/lib-mk8s-remove.sh"
    if snap list 2>/dev/null | grep -q microk8s; then
        remove_microk8s
    else
        echo "  MicroK8s not installed — skipping."
        kill_orphan_pods
    fi

    # The /etc/hosts entries for a name-based domain (infra/lib-dns.sh).
    source "$SCRIPT_DIR/infra/lib-dns.sh"
    hosts_block && echo "  Removed the MedCEA block from /etc/hosts (if there was one)."

    echo -e "${GREEN}Uninstall complete.${NC}"
    exit 0
fi

# =============================================================================
# --reset  —  clean slate WITHOUT reinstalling MicroK8s
# =============================================================================
# --uninstall removes the cluster itself, which means re-pulling every image and
# roughly fifteen minutes. That is almost never what you want. Everything this
# platform owns lives in one namespace plus its Helm releases, so deleting those
# gives a genuine clean reinstall in about a minute.
#
# Add --secrets to also blank the generated credentials in config.env. Without
# it they are kept, and deploy-infra will simply re-read whatever Keycloak
# returns for the recreated clients. With it, anything that fails to regenerate
# fails loudly instead of silently reusing a value that no longer means anything.
if [[ "${1:-}" == "--reset" ]]; then
    # The namespace comes from PROJECT_NAME, so read it before naming it.
    [[ -f config.env ]] && source config.env
    NAMESPACE="${NAMESPACE:-medcea}"
    # Log the reset too. It was previously above the logging setup, so the most
    # destructive operation in the script was the one leaving no record — which
    # made a half-rebuilt platform hard to explain after the fact.
    mkdir -p logs
    exec > >(tee "logs/deploy-infra-reset-$(date +%Y%m%d-%H%M%S).log") 2>&1
    echo -e "${RED}--- MedCEA Reset (namespace '${NAMESPACE:-medcea}') ---${NC}"
    echo -e "${RED}This permanently deletes:${NC}"
    echo "  - every Helm release in the namespace (Postgres, Keycloak, Grafana,"
    echo "    Node-RED, the oauth2-proxies, JupyterHub)"
    echo "  - the namespace itself: all pods, services, ingresses, ConfigMaps,"
    echo "    Secrets, and every PersistentVolumeClaim (so: all data)"
    echo "  - MicroK8s itself is KEPT, so images stay cached and the rebuild is fast"
    [[ "${2:-}" == "--secrets" ]] && echo "  - the generated secrets in config.env (--secrets)"
    echo ""
    # install.sh --uninstall-infra has already listed everything and asked.
    if [[ "${MEDCEA_CONFIRMED:-}" != "1" ]]; then
        read -p "Type 'reset' to confirm: " _CONFIRM
        [[ "$_CONFIRM" == "reset" ]] || { echo "Aborted."; exit 0; }
    fi

    echo -e "${YELLOW}Uninstalling Helm releases...${NC}"
    for _rel in $($MK8S helm3 list -n "$NAMESPACE" -q 2>/dev/null); do
        echo "  - $_rel"
        $MK8S helm3 uninstall "$_rel" -n "$NAMESPACE" --wait --timeout 3m >/dev/null 2>&1 || true
    done

    echo -e "${YELLOW}Deleting namespace '$NAMESPACE'...${NC}"
    $MK8S kubectl delete namespace "$NAMESPACE" --ignore-not-found --timeout=5m || true
    # Namespace deletion is asynchronous; deploy would race it and fail to create
    # objects in a namespace still Terminating.
    for _i in $(seq 1 60); do
        $MK8S kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || break
        sleep 5
    done
    if $MK8S kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
        echo -e "${RED}Namespace is still terminating. Check for stuck finalizers:${NC}"
        echo "  kubectl get all -n $NAMESPACE"
        exit 1
    fi

    if [[ "${2:-}" == "--secrets" ]]; then
        echo -e "${YELLOW}Blanking generated secrets in config.env...${NC}"
        for _v in OAUTH2_PROXY_SECRET GRAFANA_OAUTH_SECRET OAUTH2_COOKIE_SECRET \
                  PORTAL_OAUTH2_PROXY_SECRET PORTAL_COOKIE_SECRET \
                  CONFIG_OAUTH2_PROXY_SECRET CONFIG_COOKIE_SECRET \
                  ACCESS_CLIENT_SECRET ACCESS_COOKIE_SECRET \
                  MONITOR_CLIENT_SECRET MONITOR_COOKIE_SECRET SCHEDULER_CLIENT_SECRET SCHEDULER_COOKIE_SECRET \
                  DBMGMT_CLIENT_SECRET DBMGMT_COOKIE_SECRET MQTTX_CLIENT_SECRET MQTTX_COOKIE_SECRET \
                  PGADMIN_OAUTH_SECRET MQTT_NODE_RED_PASS MQTT_SCHEDULER_PASS MQTT_EXPLORER_PASS MQTT_AUTH_DB_PASS \
                  WORKBENCH_SECRET EDGE_WIZARD_SECRET; do
            sed -i "s|^${_v}=.*|${_v}=\"\"|" config.env
        done
        echo "  Blanked. User-set values (ADMIN_PASS, POSTGRES_PASS, DOCKERHUB_*) are untouched."
    fi

    echo -e "${GREEN}Reset complete.${NC}"
    echo -e "${YELLOW}BOTH commands are required — infra alone leaves the platform half-built${NC}"
    echo -e "${YELLOW}(no config UI, no workbench, no scheduler):${NC}"
    echo "  ./deploy-infra.sh && ./deploy-apps.sh --all"
    exit 0
fi

# =============================================================================
# CONFIGURATION — Q&A into config.env (template: config.env.example)
# =============================================================================
# Before logging starts, so the answers and any generated password stay out of
# logs/. --configure reviews every setting; otherwise only empty required ones
# are asked, and a complete config.env asks nothing.
if [[ "${1:-}" == "--configure" ]]; then
    bash "$SCRIPT_DIR/infra/configure.sh" || exit 1
else
    bash "$SCRIPT_DIR/infra/configure.sh" --missing || exit 1
fi

mkdir -p logs
LOG_FILE="logs/deploy-infra-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG_FILE") 2>&1
echo "Deploy started: $(date)"
_print_banner

source config.env
set -e

# Docker Hub credentials were asked for by infra/configure.sh if they were empty.
DOCKERHUB_PASS="$DOCKERHUB_PAT"
export DOCKERHUB_USER DOCKERHUB_PASS

# =============================================================================
# REGISTRY & CHART STRATEGY (verified via Artifact Hub, March 2025)
#
# Runtime images — Docker Hub auth configured by bootstrap-infra.sh (avoids 429):
#   Postgres:     docker.io/postgres:<tag>          (Docker Hub — needs auth for rate limit)
#   Keycloak:     quay.io/keycloak/keycloak:<tag>   (Red Hat Quay — no auth needed)
#   Grafana:      docker.io/grafana/grafana:<tag>   (Docker Hub — needs auth for rate limit)
#   Node-RED:     ghcr.io/node-red/node-red:<tag>   (GitHub Container Registry — no auth needed)
#   OAuth2 Proxy: quay.io/oauth2-proxy/oauth2-proxy:<tag> (Quay — no auth needed)
#
# Helm charts:
#   postgresql:   oci://registry-1.docker.io/bitnamicharts/postgresql (18.4.0)
#   keycloak:     oci://registry-1.docker.io/bitnamicharts/keycloak   (25.2.0)
#   grafana:      grafana/grafana (7.3.12) — official Grafana Helm repo
#   node-red:     node-red/node-red (0.40.0) — schwarzit
#   oauth2-proxy: oci://registry-1.docker.io/bitnamicharts/oauth2-proxy (8.0.2)
#
# Docker Hub login (DOCKERHUB_USER/PAT from config.env) handles both:
#   - Helm OCI chart pulls (bitnamicharts)
#   - docker.io image pulls (avoids 429 rate limit)
# =============================================================================

# =============================================================================
# PREFLIGHT CHECKS
# =============================================================================

# Validate essential configuration variables
MISSING_VARS=()
for var in PROJECT_NAME NAMESPACE DOMAIN ADMIN_USER ADMIN_EMAIL ADMIN_PASS QA_USER QA_EMAIL QA_INITIAL_PASS \
           ENGINEER_USER ENGINEER_EMAIL ENGINEER_INITIAL_PASS \
           KC_BREAKGLASS_USER KC_BREAKGLASS_PASS GRAFANA_BREAKGLASS_PASS POSTGRES_USER POSTGRES_PASS POSTGRES_DB DOCKERHUB_USER DOCKERHUB_PAT \
           STORAGE_SIZE KEYCLOAK_DOMAIN KEYCLOAK_REALM GRAFANA_DOMAIN NODE_RED_DOMAIN \
           WORKBENCH_DOMAIN PGADMIN_DOMAIN PORTAL_DOMAIN MQTTX_DOMAIN CONFIG_DOMAIN DBMGMT_DOMAIN \
           SCHEDULER_DOMAIN MONITOR_DOMAIN PLATFORM_IP; do
    if [[ -z "${!var}" ]]; then
        MISSING_VARS+=("$var")
    fi
done
if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
    echo -e "${RED}ERROR: The following required variables are not set in config.env:${NC}"
    for v in "${MISSING_VARS[@]}"; do echo "  - $v"; done
    exit 1
fi

# PROJECT_NAME is the MQTT topic root and, via config.env, the namespace and the
# Keycloak realm — so it has to be legal as all three at once.
if [[ ! "$PROJECT_NAME" =~ ^[a-z][a-z0-9-]{1,30}$ ]]; then
    echo -e "${RED}ERROR: PROJECT_NAME='$PROJECT_NAME' must match ^[a-z][a-z0-9-]{1,30}\$ (it is the MQTT topic root, namespace and realm).${NC}"
    exit 1
fi

# =============================================================================
# 1. BOOTSTRAP (MicroK8s + Kubeflow)
# Skipped automatically if both MicroK8s and the Juju controller already exist.
# =============================================================================
bash ./infra/bootstrap-infra.sh

# Wait for the API server to be reachable (handles fresh installs and restarts).
echo -e "${YELLOW}Waiting for Kubernetes API to be ready...${NC}"
DEADLINE=$(($(date +%s) + 120))
until $MK8S kubectl cluster-info &>/dev/null; do
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo -e "${RED}ERROR: Kubernetes API did not become ready after 2 min.${NC}"
        exit 1
    fi
    sleep 5
done
echo -e "${GREEN}API ready.${NC}"

# =============================================================================
# DOCKER HUB AUTH
# Runs every deploy — avoids 429 rate limits on all docker.io image pulls
# (postgres, grafana, mosquitto) and Helm OCI chart pulls (bitnamicharts).
# =============================================================================
echo -e "${YELLOW}Configuring Docker Hub credentials for image + OCI chart pulls...${NC}"
DOCKER_CERTS_DIR="/var/snap/microk8s/current/args/certs.d/docker.io"
# Writing this file is one of the few genuinely root-only steps, and it is
# followed by a containerd restart that briefly disrupts every running pod. Skip
# both when the credentials are already in place: re-running the deployment
# should not cost an outage for a file that is not changing.
#
# The directory is root-only, so the check itself needs sudo: a plain [ -r ]
# test always failed, which re-wrote the file and restarted containerd on every
# run — and stopped at a bare password prompt that never reaches the log. The
# custom prompt says why the password is wanted.
_SUDO_PROMPT="[sudo] password for %u (MicroK8s registry credentials): "
if sudo -p "$_SUDO_PROMPT" grep -qsF "username = \"${DOCKERHUB_USER}\"" "$DOCKER_CERTS_DIR/hosts.toml" && \
   sudo -p "$_SUDO_PROMPT" grep -qsF "password = \"${DOCKERHUB_PASS}\"" "$DOCKER_CERTS_DIR/hosts.toml"; then
    echo -e "${GREEN}  Docker Hub credentials already configured — skipping (no containerd restart).${NC}"
else
sudo -p "$_SUDO_PROMPT" mkdir -p "$DOCKER_CERTS_DIR"
sudo tee "$DOCKER_CERTS_DIR/hosts.toml" > /dev/null <<EOF
server = "https://registry-1.docker.io"

[host."https://registry-1.docker.io"]
  capabilities = ["pull", "resolve"]
  [host."https://registry-1.docker.io".auth]
    username = "$DOCKERHUB_USER"
    password = "$DOCKERHUB_PASS"
EOF
sudo systemctl restart snap.microk8s.daemon-containerd
# Give containerd a moment to come back up before any image pulls
sleep 5
fi

echo -e "${YELLOW}Logging Helm into Docker Hub for OCI chart pulls...${NC}"
echo "$DOCKERHUB_PASS" | $MK8S helm3 registry login registry-1.docker.io \
  -u "$DOCKERHUB_USER" --password-stdin

# =============================================================================
# PLATFORM CA + WILDCARD TLS
# =============================================================================
# Everything is served over HTTPS. These hostnames can never get a public
# certificate: DOMAIN resolves to a CGNAT/Tailscale address that Let's Encrypt
# cannot reach for HTTP-01, and nip.io's DNS is not ours for DNS-01. So the
# platform issues its own, and the CA certificate is the thing you trust once
# per client machine. It is the same CA the edge mTLS design needs for MQTT.
#
# Without this, JupyterHub disables its XSRF checks over plain HTTP and every
# session cookie crosses the network in clear.
# The namespace first: the TLS secret and CA ConfigMap below live in it. On a
# clean machine it does not exist yet, and creating it later failed the deploy
# with 'namespaces "medcea" not found'.
$MK8S kubectl create namespace "$NAMESPACE" \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -

# The access policy's check (codeplan IAM plan 1.1/1.2): ConfigMap medcea-iam-lib,
# mounted by every service at /iam/ — the route table, the check library
# (apps/iam/lib/medcea_iam.py) and its settings (issuer, audience, IAM_ENFORCE).
# Here, because this script runs before every app component. The table is
# compiled from defaults.yaml: the applied version in iam_policy is read instead
# once Phase 4 creates one. A policy that fails its invariants stops the deploy
# rather than shipping a table — unless IAM_GATES=false (the rollback), which
# leaves the ConfigMap as it is. Services re-read the mount when the kubelet
# updates it (about a minute), so a change here needs no restart.
echo -e "\n${GREEN}[IAM] Access check (ConfigMap medcea-iam-lib)...${NC}"
if IAM_ROUTES_JSON="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile routes)"; then
    IAM_ROUTES_DIGEST="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])' <<<"$IAM_ROUTES_JSON")"
    _IAM_DIR="$(mktemp -d)"
    printf '%s\n' "$IAM_ROUTES_JSON" > "$_IAM_DIR/routes.json"
    # switches: the other IAM flags as this run set them, with the time, for the
    # quarterly access review's record (IAM 2.7) — labelled there "as of
    # deploy-infra <written_at>", since only enforce is read live from this file.
    ISSUER="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" ENFORCE="${IAM_ENFORCE:-false}" \
    SW_GATES="${IAM_GATES:-true}" SW_NETPOL="${IAM_NETPOL:-true}" SW_JWT="${IAM_POSTGREST_JWT:-false}" python3 -c '
import datetime, json, os
e = os.environ
print(json.dumps({"issuer": e["ISSUER"], "audience": "medcea-api",
                  "enforce": e["ENFORCE"] == "true",
                  "switches": {"IAM_GATES": e["SW_GATES"] != "false", "IAM_NETPOL": e["SW_NETPOL"] != "false",
                               "IAM_POSTGREST_JWT": e["SW_JWT"] == "true",
                               "written_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}},
                 sort_keys=True))' > "$_IAM_DIR/settings.json"
    chmod 755 "$_IAM_DIR"; chmod 644 "$_IAM_DIR"/*   # readable by a sudo kubectl
    $MK8S kubectl create configmap medcea-iam-lib -n "$NAMESPACE" \
        --from-file=routes.json="$_IAM_DIR/routes.json" \
        --from-file=settings.json="$_IAM_DIR/settings.json" \
        --from-file=medcea_iam.py="$SCRIPT_DIR/apps/iam/lib/medcea_iam.py" \
        --dry-run=client -o yaml \
      | $MK8S kubectl label --local -f - medcea/iam-lib=true -o yaml \
      | $MK8S kubectl annotate --local -f - "medcea/routes-digest=$IAM_ROUTES_DIGEST" -o yaml \
      | $MK8S kubectl apply -f -
    rm -rf "$_IAM_DIR"
    [[ "${IAM_ENFORCE:-false}" == "true" ]] \
        && echo -e "${GREEN}  IAM_ENFORCE=true: services refuse what the policy does not allow (live within about a minute).${NC}" \
        || echo -e "${YELLOW}  IAM_ENFORCE=false: services only log what they would refuse (report-only; IAM 2.6 switch via ./guide.sh).${NC}"
elif [[ "${IAM_GATES:-true}" == "false" ]]; then
    echo -e "${YELLOW}WARNING: IAM_GATES=false and the access policy does not compile — ConfigMap medcea-iam-lib left as it is.${NC}" >&2
else
    echo -e "${RED}ERROR: the access policy did not compile (python3 apps/iam/compiler/cli.py check).${NC}" >&2
    exit 1
fi

# NetworkPolicies of the application pods (IAM plan 1.4), compiled from `network:`
# in the access policy: each pod admits only its proxy, the listed in-cluster hops
# and the node itself (kubelet probes, the edge wizard). The node's addresses are
# read now, because host traffic arrives from them. IAM_NETPOL=false removes them.
echo -e "\n${GREEN}[IAM] Network policies of the application pods...${NC}"
if [[ "${IAM_NETPOL:-true}" == "false" ]]; then
    $MK8S kubectl delete netpol -n "$NAMESPACE" -l medcea/iam-netpol=true --ignore-not-found
    echo -e "${YELLOW}  IAM_NETPOL=false: application pods accept connections from anywhere in the cluster.${NC}"
else
    _NODE_IPS=()
    for _ip in $($MK8S kubectl get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="InternalIP")]}{.address}{" "}{end}{.metadata.annotations.projectcalico\.org/IPv4Address}{" "}{.metadata.annotations.projectcalico\.org/IPv4VXLANTunnelAddr}{" "}{.metadata.annotations.projectcalico\.org/IPv4IPIPTunnelAddr}{" "}{end}'); do
        _NODE_IPS+=(--node-ip "${_ip%/*}")
    done
    if _NETPOL="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile netpol --namespace "$NAMESPACE" "${_NODE_IPS[@]}")"; then
        $MK8S kubectl apply -f - <<<"$_NETPOL"
        # A pod dropped from `network:` keeps no stale policy.
        _WANT="$(python3 -c 'import json, sys; print(" ".join(i["metadata"]["name"] for i in json.load(sys.stdin)["items"]))' <<<"$_NETPOL")"
        for _np in $($MK8S kubectl get netpol -n "$NAMESPACE" -l medcea/iam-netpol=true -o jsonpath='{.items[*].metadata.name}'); do
            [[ " $_WANT " == *" $_np "* ]] || $MK8S kubectl delete netpol -n "$NAMESPACE" "$_np"
        done
    elif [[ "${IAM_GATES:-true}" == "false" ]]; then
        echo -e "${YELLOW}WARNING: IAM_GATES=false and the access policy does not compile — network policies left as they are.${NC}" >&2
    else
        echo -e "${RED}ERROR: the network policies did not compile (python3 apps/iam/compiler/cli.py check).${NC}" >&2
        exit 1
    fi
fi

echo -e "\n${GREEN}[TLS] Platform CA and wildcard certificate...${NC}"
CA_DIR="$SCRIPT_DIR/.ca"; mkdir -p "$CA_DIR"; chmod 700 "$CA_DIR"
if [ ! -f "$CA_DIR/ca.key" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$CA_DIR/ca.key"
    openssl req -x509 -new -key "$CA_DIR/ca.key" -sha256 -days 3650 \
      -subj "/CN=CEA Platform CA/O=CEA" -out "$CA_DIR/ca.crt"
    echo -e "${GREEN}  CA created at $CA_DIR/ca.crt — trust this on each client machine.${NC}"
else
    echo -e "${GREEN}  Reusing existing CA (clients already trusting it keep working).${NC}"
fi
# Reissued every run so a changed DOMAIN is picked up. Cheap, and the CA is stable.
openssl ecparam -name prime256v1 -genkey -noout -out "$CA_DIR/server.key"
# Every service hostname is listed explicitly. A wildcard alone was enough for
# <ip>.nip.io, but browsers reject a wildcard sitting directly on a one-label
# name (*.medcea), so a name-based DOMAIN needs each host as its own SAN. The
# alias (old IP) domain is included so its redirects are served over valid TLS.
_SVC_DOMAINS=()
ONBOARD_DOMAIN="${ONBOARD_DOMAIN:-onboard-device.$DOMAIN}"   # older config.env files lack it
ACCESS_DOMAIN="${ACCESS_DOMAIN:-access.$DOMAIN}"             # likewise
for _v in KEYCLOAK_DOMAIN GRAFANA_DOMAIN NODE_RED_DOMAIN PGADMIN_DOMAIN DBMGMT_DOMAIN \
          SCHEDULER_DOMAIN MONITOR_DOMAIN CONFIG_DOMAIN MQTTX_DOMAIN PORTAL_DOMAIN WORKBENCH_DOMAIN \
          ONBOARD_DOMAIN ACCESS_DOMAIN; do
    [[ -n "${!_v:-}" ]] && _SVC_DOMAINS+=("${!_v}")
done
_ALIAS_ON=false
[[ -n "${ALIAS_DOMAIN:-}" && "$ALIAS_DOMAIN" != "$DOMAIN" ]] && _ALIAS_ON=true
_SANS="DNS:${DOMAIN}"
[[ "$DOMAIN" == *.* ]] && _SANS+=",DNS:*.${DOMAIN}"
for _d in "${_SVC_DOMAINS[@]}"; do _SANS+=",DNS:${_d}"; done
$_ALIAS_ON && _SANS+=",DNS:${ALIAS_DOMAIN},DNS:*.${ALIAS_DOMAIN}"
openssl req -new -key "$CA_DIR/server.key" -subj "/CN=${DOMAIN}" -out "$CA_DIR/server.csr"
openssl x509 -req -in "$CA_DIR/server.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
  -CAcreateserial -days 825 -sha256 -out "$CA_DIR/server.crt" \
  -extfile <(printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" "$_SANS")
chmod 600 "$CA_DIR"/*.key
$MK8S kubectl create secret tls cea-tls -n "$NAMESPACE" \
  --cert="$CA_DIR/server.crt" --key="$CA_DIR/server.key" \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -
# The CA cert itself, for anything in-cluster that must verify us later.
$MK8S kubectl create configmap cea-ca -n "$NAMESPACE" \
  --from-file=ca.crt="$CA_DIR/ca.crt" \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -

# =============================================================================
# NAME-BASED DOMAIN (LOCAL_DNS=true): DNS server + this machine's /etc/hosts
# =============================================================================
# name-dns answers every <anything>.$DOMAIN with PLATFORM_IP, bound to
# PLATFORM_IP:53 only (systemd-resolved keeps 127.0.0.53). Tailscale split DNS
# sends tailnet devices' lookups for $DOMAIN here — set once in the admin
# console; the end of this script checks it and prints the steps. It runs in the
# cluster rather than as a host package: nothing to apt-get, --reset removes it,
# and kubelet restarts it if Tailscale comes up after it.
source "$SCRIPT_DIR/infra/lib-dns.sh"
if [[ "${LOCAL_DNS:-false}" == "true" ]]; then
    echo -e "\n${GREEN}[DNS] Name server for '$DOMAIN' on $PLATFORM_IP:53...${NC}"
    # $(…) drops the file's trailing newline, so the string — and its checksum,
    # which restarts name-dns when the config changes — match the old inline one.
    _COREFILE="$(render "$SCRIPT_DIR/k8s/name-dns/Corefile" DOMAIN PLATFORM_IP)"
    $MK8S kubectl create configmap name-dns -n "$NAMESPACE" \
      --from-literal=Corefile="$_COREFILE" --dry-run=client -o yaml | $MK8S kubectl apply -f -
    _COREFILE_SUM="$(printf '%s' "$_COREFILE" | sha256sum | cut -c1-16)"
    render "$SCRIPT_DIR/k8s/name-dns/deployment.yaml" NAMESPACE _COREFILE_SUM | $MK8S kubectl apply -f -
    $MK8S kubectl rollout status deployment/name-dns -n "$NAMESPACE" --timeout=5m
    if [[ "$(dns_query "$PLATFORM_IP" "portal.$DOMAIN")" == "$PLATFORM_IP" ]]; then
        echo -e "${GREEN}  portal.$DOMAIN → $PLATFORM_IP (answered by name-dns)${NC}"
    else
        echo -e "${RED}  name-dns is running but did not answer for portal.$DOMAIN on $PLATFORM_IP:53.${NC}"
        echo "  Check: $MK8S kubectl logs -n $NAMESPACE deploy/name-dns"
    fi
    echo -e "${YELLOW}  Mapping $DOMAIN names to $PLATFORM_IP in /etc/hosts (this machine)...${NC}"
    hosts_block "$DOMAIN" "${_SVC_DOMAINS[@]}" "$PLATFORM_IP"
    # Said now as well as at the end: this machine resolves through /etc/hosts
    # either way, so a stale route only shows on other devices, and a deploy
    # that stops halfway would never reach the summary.
    _SPLIT_DNS_TARGET="$(split_dns_target "$DOMAIN" | paste -sd ' ')"
    if [[ -n "$_SPLIT_DNS_TARGET" && "$_SPLIT_DNS_TARGET" != "$PLATFORM_IP" ]]; then
        echo -e "${RED}  Tailscale split DNS sends '$DOMAIN' to $_SPLIT_DNS_TARGET, not to this server ($PLATFORM_IP).${NC}"
        echo -e "${RED}  Other devices cannot resolve *.$DOMAIN until it is changed (steps at the end).${NC}"
    fi
else
    # Switched back to an IP or external domain: take the name server down and
    # the managed hosts entries out, so nothing answers for a stale name.
    $MK8S kubectl delete deployment,configmap name-dns -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
    hosts_block
fi

echo -e "\n${GREEN}--- Deploying MedCEA to $NAMESPACE ---${NC}"

# =============================================================================
# 2. Postgres + Keycloak
# =============================================================================

# Postgres — prerequisite for Keycloak
# Chart:  bitnami/postgresql 18.4.0 (OCI via Docker Hub — needs Helm login)
# Image:  docker.io/bitnami/postgresql (chart default — Bitnami image handles
#         non-root startup correctly; official postgres:16 fails in K8s security context)
echo -e "\n${GREEN}[1/10] Deploying Postgres...${NC}"
$MK8S helm3 upgrade --install rdbms \
  oci://registry-1.docker.io/bitnamicharts/postgresql \
  --version 18.4.0 \
  --namespace "$NAMESPACE" \
  --set global.postgresql.auth.username="$POSTGRES_USER" \
  --set global.postgresql.auth.password="$POSTGRES_PASS" \
  --set global.postgresql.auth.database="$POSTGRES_DB" \
  --set primary.persistence.size="$STORAGE_SIZE" \
  --set primary.resources.requests.cpu=250m \
  --set primary.resources.requests.memory=512Mi \
  --set primary.resources.limits.memory=2Gi \
  --set readReplicas.resources.requests.cpu=250m \
  --set readReplicas.resources.requests.memory=512Mi \
  --set readReplicas.resources.limits.memory=2Gi \
  --timeout 20m \
  --wait
# Resources are explicit because unset ones fall back to Bitnami's "nano"
# preset: a 192Mi / 150m limit on the one database that serves Keycloak,
# Grafana, PostgREST, the scheduler and Node-RED. No CPU limit on purpose (on one
# PC a limit only throttles; the request guarantees the share), a memory limit so
# a runaway query cannot starve the host. readReplicas is not deployed
# (standalone); it is set only so nothing is left on a preset.

# Keycloak's own database. It used to share medcea_db (tables in public), so
# apps/database/uninstall.sh --purge-data — DROP DATABASE medcea_db — would have
# wiped every realm, user and client along with the app data. On an install
# that predates this, Keycloak starts once on the empty database and the realm
# step below recreates realm, clients, roles and users; old Keycloak tables left
# in medcea_db.public are unused.
_PG_EXEC=($MK8S kubectl exec -n "$NAMESPACE" rdbms-postgresql-0 -- env PGPASSWORD="$POSTGRES_PASS" psql -U "$POSTGRES_USER" -d postgres -tAc)
if [[ "$("${_PG_EXEC[@]}" "SELECT 1 FROM pg_database WHERE datname='keycloak'" | tr -d '[:space:]')" != "1" ]]; then
    echo -e "${YELLOW}  Creating database 'keycloak'...${NC}"
    "${_PG_EXEC[@]}" "CREATE DATABASE keycloak ENCODING 'UTF8' TEMPLATE template0"
fi

# IAM_ENFORCE in the access history (IAM 2.6): enforcement_enabled/_disabled
# {switch: IAM_ENFORCE} on a transition, as the database deploy records IAM_DB_ROLES.
# Best effort: the switch is in force through ConfigMap medcea-iam-lib either way.
# dba_record_switch reads the password inside the pod (not _PG_EXEC, which puts it in argv).
if [[ "$("${_PG_EXEC[@]}" "SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DB'" | tr -d '[:space:]')" == "1" ]]; then
    KUBECTL="$MK8S kubectl" REPO_ROOT="$SCRIPT_DIR"
    source "$SCRIPT_DIR/apps/database/lib-db-apply.sh"
    _ENF=false; [[ "${IAM_ENFORCE:-false}" == "true" ]] && _ENF=true
    if ! _OUT="$(dba_record_switch "$NAMESPACE" rdbms-postgresql-0 "$POSTGRES_DB" IAM_ENFORCE "$_ENF" 2>&1)"; then
        echo -e "${YELLOW}WARNING: could not record IAM_ENFORCE in iam_policy.history; the switch itself is in force: ${_OUT:0:200}${NC}" >&2
    elif [[ "$_OUT" == *skip* ]]; then
        echo -e "${YELLOW}  IAM_ENFORCE not recorded in the access history: migration 008b is not applied yet (./apps/database/deploy.sh).${NC}"
    fi
fi

# Keycloak
# Image: quay.io/keycloak/keycloak:26.0 (official, free)
# Note: bitnami/keycloak is behind a paywall since Aug 2025 — using kubectl manifests instead.
echo -e "\n${GREEN}[2/10] Deploying Keycloak...${NC}"

# Clean up any previous Helm-managed Keycloak release (idempotent)
$MK8S helm3 uninstall keycloak --namespace "$NAMESPACE" 2>/dev/null || true

# The medcea login theme: the one sign-in / request-access page of the platform.
# Only theme.properties is rendered — the .ftl files are FreeMarker, whose
# ${...} must reach Keycloak untouched. The background is the portal's (152 KB;
# a ConfigMap holds 1 MiB, so the 1.7 MB PNG fallback the portal uses cannot).
_KC_THEME="$SCRIPT_DIR/k8s/keycloak/theme/medcea/login"
_KC_THEME_TMP="$(mktemp -d)"
render "$_KC_THEME/theme.properties" ACCESS_DOMAIN PORTAL_DOMAIN > "$_KC_THEME_TMP/theme.properties"
if [[ -f "$SCRIPT_DIR/apps/portal/bg.jpg" ]]; then cp "$SCRIPT_DIR/apps/portal/bg.jpg" "$_KC_THEME_TMP/bg.jpg"; else : > "$_KC_THEME_TMP/bg.jpg"; fi
$MK8S kubectl create configmap keycloak-theme -n "$NAMESPACE" \
  --from-file="$_KC_THEME_TMP/theme.properties" --from-file="$_KC_THEME/template.ftl" --from-file="$_KC_THEME/login.ftl" \
  --from-file="$_KC_THEME/messages/messages_en.properties" --from-file="$_KC_THEME/resources/css/medcea.css" \
  --from-file="$_KC_THEME_TMP/bg.jpg" --dry-run=client -o yaml | $MK8S kubectl apply -f -
_KC_THEME_SUM="$(cat "$_KC_THEME_TMP"/* "$_KC_THEME"/*.ftl "$_KC_THEME"/messages/* "$_KC_THEME"/resources/css/* | sha256sum | cut -c1-16)"
rm -rf "$_KC_THEME_TMP"

# The bootstrap credentials of the break-glass console account live in a Secret,
# not as literal values in the Deployment (readable by anyone who can get it).
$MK8S kubectl create secret generic keycloak-bootstrap -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-literal=username="$KC_BREAKGLASS_USER" --from-literal=password="$KC_BREAKGLASS_PASS" \
  | $MK8S kubectl apply -f - >/dev/null
render "$SCRIPT_DIR/k8s/keycloak/keycloak.yaml" NAMESPACE POSTGRES_USER POSTGRES_PASS KEYCLOAK_DOMAIN _KC_THEME_SUM | $MK8S kubectl apply -n "$NAMESPACE" -f -

echo -e "${YELLOW}Waiting for Keycloak to be ready (up to 10 min)...${NC}"
$MK8S kubectl rollout status deployment/keycloak -n "$NAMESPACE" --timeout=10m

# =============================================================================
# 3. KEYCLOAK REALM + OAUTH CLIENTS
# Creates realm 'medcea', confidential clients, and writes secrets to config.env.
# Idempotent: 409 responses (already exists) are handled gracefully.
# =============================================================================
echo -e "\n${GREEN}[3/10] Configuring Keycloak realm '${KEYCLOAK_REALM}' and OAuth clients...${NC}"

# Grafana's role setting is compiled before the realm changes (IAM 3.1): the
# grafana_* roles and their claim are retired below, so a broken policy must stop
# the deploy here, not after the old role path has lost its claim.
REPO_ROOT="$SCRIPT_DIR"
source "$SCRIPT_DIR/infra/lib-oauth2-proxy.sh"
policy_grafana || { echo -e "${RED}ERROR: cannot compile Grafana's role setting from the access policy (python3 apps/iam/compiler/cli.py check).${NC}" >&2; exit 1; }

# Kill any stale port-forward on 18080 from a previous run
fuser -k 18080/tcp &>/dev/null || true
sleep 1
$MK8S kubectl port-forward svc/keycloak 18080:80 -n "$NAMESPACE" &>/dev/null 9>&- &
_KC_PF_PID=$!
sleep 5

# Helper: get a fresh admin token (Keycloak tokens expire in ~60s). Who the
# script is to Keycloak — the medcea-deployer client, the break-glass account or,
# on an install from before the split, the legacy admin — is decided once by
# kc_admin_select (infra/lib-keycloak-admin.sh).
source "$SCRIPT_DIR/infra/lib-keycloak-admin.sh"
_kc_token() { kc_admin_token; }

# Retry up to 12 times (60s) in case the port-forward needs extra time
_KC_TOKEN=""
for _i in $(seq 1 12); do
    kc_admin_select && _KC_TOKEN=$(_kc_token)
    [[ -n "$_KC_TOKEN" ]] && break
    echo -e "${YELLOW}  Waiting for Keycloak Admin API... (${_i}/12)${NC}"
    sleep 5
done
[[ -n "$_KC_TOKEN" ]] && echo -e "${GREEN}  Keycloak admin API as: ${KC_ADMIN_MODE}${NC}"
if [[ -z "$_KC_TOKEN" ]]; then
    echo -e "${RED}ERROR: Could not authenticate to Keycloak Admin API. Check Keycloak logs.${NC}"
    kill $_KC_PF_PID 2>/dev/null || true
    exit 1
fi

# Create realm
echo -e "${YELLOW}  Creating realm '${KEYCLOAK_REALM}'...${NC}"
_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "http://localhost:18080/admin/realms" \
  -H "Authorization: Bearer ${_KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"realm\":\"${KEYCLOAK_REALM}\",\"enabled\":true,\"sslRequired\":\"none\"}")
if [[ "$_HTTP" == "201" ]]; then
    echo -e "${GREEN}  Realm '${KEYCLOAK_REALM}' created.${NC}"
elif [[ "$_HTTP" == "409" ]]; then
    echo -e "${YELLOW}  Realm '${KEYCLOAK_REALM}' already exists — ensuring ssl_required=none.${NC}"
    _KC_TOKEN=$(_kc_token)
    curl -s -o /dev/null -X PUT \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}" \
      -H "Authorization: Bearer ${_KC_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{"sslRequired":"none"}' || true
else
    echo -e "${RED}ERROR: Failed to create realm '${KEYCLOAK_REALM}' (HTTP $_HTTP).${NC}"
    kill $_KC_PF_PID 2>/dev/null || true
    exit 1
fi

# Master-realm identities: the break-glass console account and the deployer
# client the scripts use from now on; the legacy admin is disabled once both
# work. Login and admin events on in both realms, so every change is recorded.
echo -e "${YELLOW}  Ensuring the break-glass console account and the deployer client...${NC}"
if ! kc_ensure_master_identities; then
    echo -e "${RED}  Master-realm identities incomplete — continuing as '${KC_ADMIN_MODE}'.${NC}" >&2
fi
kc_enable_events "$KEYCLOAK_REALM"

# Realm look. loginTheme=medcea is the platform's own sign-in page
# (k8s/keycloak/theme). Mail (smtpServer, resetPasswordAllowed) is deliberately
# not set here: the User Manager owns it (apps/access, E-mail settings) and
# pushes it to the realm, and a value written here would undo that on every run.
# accessTokenLifespan is pinned at Keycloak's default (300 s) because PostgREST
# (IAM_POSTGREST_JWT=true) refuses an expired token with 401 instead of falling
# back to anon: every oauth2-proxy refreshes its session at cookie_refresh = 4m
# (k8s/oauth2-proxy/values-app.yaml, the config proxy's), so the token it forwards
# has >= 60 s left.
# Keep cookie_refresh + 30 s below this value (tests/test_postgrest.py checks it),
# and never override access.token.lifespan per client.
echo -e "${YELLOW}  Applying login theme...${NC}"
curl -s -o /dev/null -X PUT "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}" \
  -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" \
  -d '{"loginTheme":"medcea","displayName":"MedCEA Platform","rememberMe":true,"accessTokenLifespan":300}' || true

# Create a confidential client and echo its secret (captured by caller via $())
_create_client() {
    local CLIENT_ID="$1"
    local REDIRECT_URI="$2"
    # Always stated: Keycloak reads a PUT that leaves serviceAccountsEnabled out
    # as "off", deletes the service-account user and makes a new one — and the
    # roles granted to the old one (the access client's) are gone.
    local SA_ENABLED="${3:-false}"
    local TOK
    # Keycloak 18+ will not end a session from a plain GET to the logout
    # endpoint — it shows a "Do you want to log out?" confirmation instead, so
    # the SSO session survives and the next visit silently re-authenticates.
    # RP-initiated logout needs client_id + post_logout_redirect_uri, and that
    # URI must be registered here or Keycloak answers 400.
    local ORIGIN="${REDIRECT_URI%%/oauth2/*}"; ORIGIN="${ORIGIN%%/login/*}"; ORIGIN="${ORIGIN%%/hub/*}"
    TOK=$(_kc_token)

    # Create client — 409 means already exists, both are fine
    curl -s -o /dev/null -X POST \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "{\"clientId\":\"${CLIENT_ID}\",\"enabled\":true,\"publicClient\":false,\"standardFlowEnabled\":true,\"serviceAccountsEnabled\":${SA_ENABLED},\"redirectUris\":[\"${REDIRECT_URI}\",\"${ORIGIN}/_account/*\"],\"attributes\":{\"post.logout.redirect.uris\":\"${ORIGIN}/*\"}}" || true

    # Look up internal UUID
    local UUID
    UUID=$(curl -sf \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${CLIENT_ID}" \
      -H "Authorization: Bearer ${TOK}" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'])" 2>/dev/null || echo "")
    if [[ -z "$UUID" ]]; then
        echo -e "${RED}ERROR: Could not get UUID for client '${CLIENT_ID}'.${NC}" >&2
        return 1
    fi

    # ${ORIGIN}/_account/* is where the user menu's Change password returns
    # (kc_action=UPDATE_PASSWORD, apps/access) — harmless on clients without it.
    # Re-apply the redirect URI on every run. The POST above returns 409 for an
    # existing client and changes nothing, so without this a client created once
    # keeps its original URI forever — which is why moving the platform to https
    # produced "Invalid parameter: redirect_uri" instead of a login page.
    TOK=$(_kc_token)
    curl -s -o /dev/null -X PUT \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${UUID}" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "{\"clientId\":\"${CLIENT_ID}\",\"enabled\":true,\"publicClient\":false,\"standardFlowEnabled\":true,\"serviceAccountsEnabled\":${SA_ENABLED},\"redirectUris\":[\"${REDIRECT_URI}\",\"${ORIGIN}/_account/*\"],\"attributes\":{\"post.logout.redirect.uris\":\"${ORIGIN}/*\"}}" || true

    # Retrieve the generated secret
    curl -sf \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${UUID}/client-secret" \
      -H "Authorization: Bearer ${TOK}" \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])" 2>/dev/null || echo ""
}

# Same as _create_client but takes a JSON array of redirect URIs. The edge
# wizard runs on the platform host itself and is opened on whichever address the
# operator can reach — LAN, Tailscale or loopback — so one URI is not enough.
# DEVICE_GRANT (third argument, default false) turns on the OAuth 2.0 device
# authorization grant, which is how flash-device.sh signs a person in from a
# terminal (IAM 1.5): an SSH session has no browser to receive a redirect. The
# client is confidential, so only someone who holds config.env can start a code,
# and it is the same client, so the token's azp stays edge-wizard — what Phase 2's
# PostgREST check admits.
# POST and PUT send the same full body. serviceAccountsEnabled is always sent
# (false): a PUT that omits it toggles the service account and recreates its
# user (CLAUDE.md pitfall). Password and implicit grants are off explicitly.
_create_client_multi() {
    local CLIENT_ID="$1" REDIRECT_JSON="$2" DEVICE_GRANT="${3:-false}" TOK UUID BODY
    BODY="{\"clientId\":\"${CLIENT_ID}\",\"enabled\":true,\"publicClient\":false,\"standardFlowEnabled\":true,\"directAccessGrantsEnabled\":false,\"implicitFlowEnabled\":false,\"serviceAccountsEnabled\":false,\"redirectUris\":${REDIRECT_JSON},\"attributes\":{\"post.logout.redirect.uris\":\"+\",\"oauth2.device.authorization.grant.enabled\":\"${DEVICE_GRANT}\"}}"
    TOK=$(_kc_token)
    curl -s -o /dev/null -X POST \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "$BODY" || true

    UUID=$(curl -sf \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${CLIENT_ID}" \
      -H "Authorization: Bearer ${TOK}" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'])" 2>/dev/null || echo "")
    if [[ -z "$UUID" ]]; then
        echo -e "${RED}ERROR: Could not get UUID for client '${CLIENT_ID}'.${NC}" >&2
        return 1
    fi
    # Re-apply the URI list on re-runs, so a changed LAN IP is picked up.
    TOK=$(_kc_token)
    curl -s -o /dev/null -X PUT \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${UUID}" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "$BODY" || true

    curl -sf \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${UUID}/client-secret" \
      -H "Authorization: Bearer ${TOK}" \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])" 2>/dev/null || echo ""
}

echo -e "${YELLOW}  Creating client 'node-red'...${NC}"
_NODE_RED_SECRET=$(_create_client "node-red" "https://${NODE_RED_DOMAIN}/oauth2/callback")
echo -e "${YELLOW}  Creating client 'grafana'...${NC}"
_GRAFANA_SECRET=$(_create_client "grafana" "https://${GRAFANA_DOMAIN}/login/generic_oauth")
echo -e "${YELLOW}  Creating client 'workbench'...${NC}"
# JupyterHub's GenericOAuthenticator talks to Keycloak directly — there is no Dex
# in between any more, so the callback is the hub's own, not /dex/callback.
_WORKBENCH_SECRET=$(_create_client "workbench" "https://${WORKBENCH_DOMAIN}/hub/oauth_callback")
echo -e "${YELLOW}  Creating client 'portal'...${NC}"
_PORTAL_SECRET=$(_create_client "portal" "https://${PORTAL_DOMAIN}/oauth2/callback")
echo -e "${YELLOW}  Creating client 'config'...${NC}"
_CONFIG_SECRET=$(_create_client "config" "https://${CONFIG_DOMAIN}/oauth2/callback")
# Cookie secrets are kept once generated: a new one on every run made every
# deploy log everybody out (existing cookies no longer decrypt).
_CONFIG_COOKIE_SECRET="${CONFIG_COOKIE_SECRET:-$(openssl rand -base64 24)}"
# Every remaining web UI gets its own oauth2-proxy (apps/*/deploy.sh) and so
# its own client; the proxies share k8s/oauth2-proxy/values-app.yaml.
echo -e "${YELLOW}  Creating clients 'monitor', 'scheduler', 'dbmgmt', 'mqtt-explorer'...${NC}"
_MONITOR_SECRET=$(_create_client "monitor" "https://${MONITOR_DOMAIN}/oauth2/callback")
_SCHEDULER_SECRET=$(_create_client "scheduler" "https://${SCHEDULER_DOMAIN}/oauth2/callback")
_DBMGMT_SECRET=$(_create_client "dbmgmt" "https://${DBMGMT_DOMAIN}/oauth2/callback")
_MQTTX_SECRET=$(_create_client "mqtt-explorer" "https://${MQTTX_DOMAIN}/oauth2/callback")
_MONITOR_COOKIE_SECRET="${MONITOR_COOKIE_SECRET:-$(openssl rand -base64 24)}"
_SCHEDULER_COOKIE_SECRET="${SCHEDULER_COOKIE_SECRET:-$(openssl rand -base64 24)}"
_DBMGMT_COOKIE_SECRET="${DBMGMT_COOKIE_SECRET:-$(openssl rand -base64 24)}"
_MQTTX_COOKIE_SECRET="${MQTTX_COOKIE_SECRET:-$(openssl rand -base64 24)}"
# pgAdmin signs in with Keycloak itself (k8s/pgadmin/pgadmin.yaml): its
# callback is /oauth2/authorize, not oauth2-proxy's /oauth2/callback.
echo -e "${YELLOW}  Creating client 'pgadmin'...${NC}"
_PGADMIN_SECRET=$(_create_client "pgadmin" "https://${PGADMIN_DOMAIN}/oauth2/authorize")
# MQTT: the broker admits nobody anonymously. These are the platform's own
# service accounts (hashed into the Secret mosquitto-service-auth below) and
# the password of mqtt_auth, the DB role the broker's auth sidecar reads device
# credentials with. Generated once and kept, like the cookie secrets; hex only,
# so they are safe in sed, YAML and a .env file.
_MQTT_NODE_RED_PASS="${MQTT_NODE_RED_PASS:-$(openssl rand -hex 20)}"
_MQTT_SCHEDULER_PASS="${MQTT_SCHEDULER_PASS:-$(openssl rand -hex 20)}"
_MQTT_EXPLORER_PASS="${MQTT_EXPLORER_PASS:-$(openssl rand -hex 20)}"
_MQTT_AUTH_DB_PASS="${MQTT_AUTH_DB_PASS:-$(openssl rand -hex 20)}"
echo -e "${YELLOW}  Creating client 'edge-wizard'...${NC}"
# The edge provisioning wizard (edge/flash-device.sh --ui) runs on this host and
# is opened from a laptop over SSH, so register every address it can answer on.
_EW_PORT="${EDGE_WIZARD_PORT:-8088}"
_EW_TS="$(tailscale ip -4 2>/dev/null | head -1 || true)"
_EW_URIS="$(EW_PORT="$_EW_PORT" EW_LAN="${_LAN_IP:-}" EW_TS="$_EW_TS" EW_ONBOARD="${ONBOARD_DOMAIN:-onboard-device.$DOMAIN}" python3 -c "
import json, os
e = os.environ; port = e['EW_PORT']
hosts = ['127.0.0.1', 'localhost'] + [h for h in (e.get('EW_LAN'), e.get('EW_TS')) if h]
uris = ['http://%s:%s/oauth2/callback' % (h, port) for h in hosts]
if e.get('EW_ONBOARD'): uris.append('https://%s/oauth2/callback' % e['EW_ONBOARD'])
print(json.dumps(uris))")"
_EDGE_WIZARD_SECRET=$(_create_client_multi "edge-wizard" "$_EW_URIS" true)
echo -e "${YELLOW}  Creating client 'access'...${NC}"
# Two jobs, one client: the browser login for the User Manager (its oauth2-proxy)
# and the service account apps/access uses to create, enable, role-map and
# delete users. The PUT in _create_client leaves serviceAccountsEnabled alone,
# so setting it once here survives later runs.
_ACCESS_SECRET=$(_create_client "access" "https://${ACCESS_DOMAIN}/oauth2/callback" true)
_ACCESS_COOKIE_SECRET="${ACCESS_COOKIE_SECRET:-$(openssl rand -base64 24)}"
_ACCESS_UUID=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients?clientId=access" \
  -H "Authorization: Bearer $(_kc_token)" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null || echo "")
if [[ -n "$_ACCESS_UUID" ]]; then
    curl -s -o /dev/null -X PUT "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_ACCESS_UUID}" \
      -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" \
      -d '{"clientId":"access","serviceAccountsEnabled":true}' || true
    # manage-users: create disabled, enable, map realm roles, delete on rejection.
    # view-users/query-users: duplicate checks and the admin e-mail list.
    # manage-realm: the User Manager's e-mail settings also become the realm's
    # SMTP server, so Keycloak's "Forgot password?" mail uses the same account.
    # view-events: each account's last login in the quarterly access review
    # (GET /events?type=LOGIN, IAM 2.7).
    _SA_ID=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_ACCESS_UUID}/service-account-user" \
      -H "Authorization: Bearer $(_kc_token)" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
    _RM_UUID=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients?clientId=realm-management" \
      -H "Authorization: Bearer $(_kc_token)" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null || echo "")
    _RM_ROLES=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_RM_UUID}/roles" \
      -H "Authorization: Bearer $(_kc_token)" | python3 -c "
import sys, json
print(json.dumps([r for r in json.load(sys.stdin) if r['name'] in ('manage-users', 'view-users', 'query-users', 'manage-realm', 'view-events')]))" 2>/dev/null || echo "")
    if [[ -n "$_SA_ID" && -n "$_RM_UUID" && "$_RM_ROLES" == \[*\] ]]; then
        curl -s -o /dev/null -X POST \
          "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users/${_SA_ID}/role-mappings/clients/${_RM_UUID}" \
          -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" -d "$_RM_ROLES" || true
    else
        echo -e "${RED}  Could not grant user-management roles to the 'access' service account.${NC}" >&2
    fi
fi
# 24 bytes → 32-char base64 → valid AES-256 key for oauth2-proxy. Kept once
# generated (see _CONFIG_COOKIE_SECRET above).
_COOKIE_SECRET="${OAUTH2_COOKIE_SECRET:-$(openssl rand -base64 24)}"
_PORTAL_COOKIE_SECRET="${PORTAL_COOKIE_SECRET:-$(openssl rand -base64 24)}"

# Helper: create a realm role (idempotent — 409 = already exists)
_create_realm_role() {
    local TOK ROLE="$1"
    TOK=$(_kc_token)
    curl -s -o /dev/null -X POST \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/roles" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"${ROLE}\"}" || true
}

# Helper: create a user with a temporary=false password (idempotent — 409 = already exists).
# Sets _KC_CREATED=1 when this call created the account, so a caller can do a
# one-time step (a first role) without redoing it on every deploy.
_create_kc_user() {
    local USERNAME="$1" FIRSTNAME="$2" LASTNAME="$3" EMAIL="$4" PASSWORD="$5"
    # TEMPORARY=true: Keycloak makes the person choose their own at first sign-in.
    local TEMPORARY="${6:-false}"
    local TOK CODE
    TOK=$(_kc_token)
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${USERNAME}\",\"firstName\":\"${FIRSTNAME}\",\"lastName\":\"${LASTNAME}\",\"email\":\"${EMAIL}\",\"enabled\":true,\"emailVerified\":true,\"credentials\":[{\"type\":\"password\",\"value\":\"${PASSWORD}\",\"temporary\":${TEMPORARY}}]}" || true)
    _KC_CREATED=0
    [[ "$CODE" == 201 ]] && _KC_CREATED=1
    if [[ "$CODE" != 201 && "$CODE" != 409 ]]; then
        echo -e "${RED}  Could not create Keycloak user '${USERNAME}' (HTTP ${CODE}).${NC}" >&2
    fi
    return 0
}

# Helper: set an existing user's e-mail, read-modify-write (a partial PUT would
# drop the rest of the representation). With ONLY_IF_SUFFIX, a user whose
# current address does not end in it is left alone.
_set_kc_email() {
    local USERNAME="$1" EMAIL="$2" ONLY_IF_SUFFIX="${3:-}"
    local USER_JSON
    USER_JSON=$(curl -sf \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users?username=${USERNAME}&exact=true" \
      -H "Authorization: Bearer $(_kc_token)" \
      | EMAIL="$EMAIL" SUFFIX="$ONLY_IF_SUFFIX" python3 -c '
import json, os, sys
d = json.load(sys.stdin)
if not d:
    sys.exit(0)
u, email, suffix = d[0], os.environ["EMAIL"], os.environ["SUFFIX"]
cur = u.get("email") or ""
if cur == email or (suffix and not cur.endswith(suffix)):
    sys.exit(0)
u["email"], u["emailVerified"] = email, True
print(json.dumps(u))' 2>/dev/null || true)
    [[ -z "$USER_JSON" ]] && return 0
    echo -e "${YELLOW}  Setting ${USERNAME}'s e-mail to ${EMAIL}...${NC}"
    curl -s -o /dev/null -X PUT \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users/$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$USER_JSON")" \
      -H "Authorization: Bearer $(_kc_token)" \
      -H "Content-Type: application/json" \
      -d "$USER_JSON" || true
}

# Helper: assign a realm role to a user by username
_assign_realm_role() {
    local USERNAME="$1" ROLE="$2"
    local TOK USER_ID ROLE_JSON
    TOK=$(_kc_token)
    USER_ID=$(curl -sf \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users?username=${USERNAME}&exact=true" \
      -H "Authorization: Bearer ${TOK}" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null || echo "")
    [[ -z "$USER_ID" ]] && { echo -e "${RED}  ERROR: user '${USERNAME}' not found for role assignment.${NC}" >&2; return 1; }
    TOK=$(_kc_token)
    ROLE_JSON=$(curl -sf \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE}" \
      -H "Authorization: Bearer ${TOK}" || echo "")
    [[ -z "$ROLE_JSON" ]] && { echo -e "${RED}  ERROR: role '${ROLE}' not found.${NC}" >&2; return 1; }
    TOK=$(_kc_token)
    curl -s -o /dev/null -X POST \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/role-mappings/realm" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "[${ROLE_JSON}]" || true
}

# --- Built-in users — usernames/passwords from config.env, fall back to ADMIN_PASS ---
# IAM 3.1: Grafana's role comes from the access policy (policy_grafana), so the
# grafana_* realm roles and the demo accounts developer/viewer are retired under
# IAM_GATES=true. Accounts are never created or deleted for that here: existing
# ones stay (deactivating them is a User Manager decision); a new install gets
# none. IAM_GATES=false keeps the pre-3.1 block, so the rollback restores it.
_GF_ADMIN_USER="${GRAFANA_ADMIN_USER:-admin}"
_GF_ADMIN_PASS="${GRAFANA_ADMIN_PASS:-$ADMIN_PASS}"
_GF_DEV_USER="${GRAFANA_DEVELOPER_USER:-developer}"
_GF_DEV_PASS="${GRAFANA_DEVELOPER_PASS:-$ADMIN_PASS}"
_GF_VIEW_USER="${GRAFANA_VIEWER_USER:-viewer}"
_GF_VIEW_PASS="${GRAFANA_VIEWER_PASS:-$ADMIN_PASS}"

# Only ADMIN_USER has a real address. The demo users still need one — oauth2-proxy
# rejects a session without an email claim, and Keycloak 26's user profile asks
# for it at login — so they get <user>@<project>.invalid, which RFC 2606 keeps
# undeliverable. They used to be <user>@cea.com, a domain someone else owns.
_demo_email() { echo "${1}@${PROJECT_NAME}.invalid"; }
_GF_ADMIN_EMAIL=$(_demo_email "$_GF_ADMIN_USER")
[[ "$_GF_ADMIN_USER" == "$ADMIN_USER" ]] && _GF_ADMIN_EMAIL="$ADMIN_EMAIL"

# _*_NEW: whether this run created the account; only a new account gets its
# platform role below (IAM 2.7: a role change is an account decision).
_GF_ADMIN_NEW=0; _GF_DEV_NEW=0; _GF_VIEW_NEW=0
if [[ "${IAM_GATES:-true}" == "false" ]]; then
    echo -e "${YELLOW}  IAM_GATES=false: creating the pre-3.1 Grafana roles and users...${NC}"
    _create_realm_role "grafana_admin"
    _create_realm_role "grafana_developer"
    _create_realm_role "grafana_viewer"
    _create_kc_user "$_GF_ADMIN_USER" "Platform" "Admin"     "$_GF_ADMIN_EMAIL"                 "$_GF_ADMIN_PASS"
    _GF_ADMIN_NEW=$_KC_CREATED
    _create_kc_user "$_GF_DEV_USER"   "Platform" "Developer" "$(_demo_email "$_GF_DEV_USER")"   "$_GF_DEV_PASS"
    _GF_DEV_NEW=$_KC_CREATED
    _create_kc_user "$_GF_VIEW_USER"  "Platform" "Viewer"    "$(_demo_email "$_GF_VIEW_USER")"  "$_GF_VIEW_PASS"
    _GF_VIEW_NEW=$_KC_CREATED
    _assign_realm_role "$_GF_ADMIN_USER" "grafana_admin"
    _assign_realm_role "$_GF_DEV_USER"   "grafana_developer"
    _assign_realm_role "$_GF_VIEW_USER"  "grafana_viewer"
else
    # The roles go; the accounts that held them stay, with their platform role.
    for _r in grafana_admin grafana_developer grafana_viewer; do
        _CODE=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
          "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/roles/${_r}" \
          -H "Authorization: Bearer $(_kc_token)" || true)
        case "$_CODE" in
            204) echo -e "${YELLOW}  Retired realm role ${_r} (IAM 3.1: Grafana's role comes from the access policy).${NC}" ;;
            404) ;;
            *)   echo -e "${RED}  Could not retire realm role ${_r} (HTTP ${_CODE}); it gives no Grafana role either way.${NC}" >&2 ;;
        esac
    done
fi

# The platform admin (portal, Node-RED, workbench admin, credentials file) is
# ADMIN_USER. Before IAM 3.1 it existed only because ADMIN_USER defaults to
# "admin" = GRAFANA_ADMIN_USER; it is now created on its own.
if [[ "${IAM_GATES:-true}" == "false" && "$ADMIN_USER" == "$_GF_ADMIN_USER" ]]; then
    _ADMIN_NEW=$_GF_ADMIN_NEW
else
    echo -e "${YELLOW}  Creating platform admin user '$ADMIN_USER'...${NC}"
    _create_kc_user "$ADMIN_USER" "Platform" "Administrator" "$ADMIN_EMAIL" "$ADMIN_PASS"
    _ADMIN_NEW=$_KC_CREATED
    if [[ "${IAM_GATES:-true}" == "false" ]]; then _assign_realm_role "$ADMIN_USER" "grafana_admin"; fi
fi

# _create_kc_user never touches an existing user. The admin's address follows
# ADMIN_EMAIL, because pgAdmin's default account must match it; a demo user's
# is replaced only while it is still the old @cea.com placeholder.
_set_kc_email "$ADMIN_USER" "$ADMIN_EMAIL"
if [[ "${IAM_GATES:-true}" == "false" ]]; then
    if [[ "$_GF_ADMIN_USER" != "$ADMIN_USER" ]]; then _set_kc_email "$_GF_ADMIN_USER" "$_GF_ADMIN_EMAIL" "@cea.com"; fi
    _set_kc_email "$_GF_DEV_USER"  "$(_demo_email "$_GF_DEV_USER")"  "@cea.com"
    _set_kc_email "$_GF_VIEW_USER" "$(_demo_email "$_GF_VIEW_USER")" "@cea.com"
fi

# --- Platform realm roles (apps/iam/policy/defaults.yaml) ---
# The eleven roles of the access policy; the host gates are compiled from it
# (policy_groups). People get a role through an access request (apps/access); the
# built-in users get one here when this run creates them, so the gate never locks
# them out. Two composites
# make the groups claim carry inherited roles: production_manager contains
# operator, qa contains auditor (the policy's roles.*.includes).
echo -e "${YELLOW}  Creating the eleven platform roles and their composites...${NC}"
for _r in operator production_manager maintenance qc qa qp engineer bio_scientist control_scientist admin auditor; do
    _create_realm_role "$_r"
done
# Helper: make PARENT a composite that contains CHILD (idempotent).
_add_composite() {
    local child
    child=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/roles/$2" -H "Authorization: Bearer $(_kc_token)") || return 0
    curl -s -o /dev/null -X POST "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/roles/$1/composites" \
      -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" -d "[${child}]" || true
}
_add_composite production_manager operator
_add_composite qa auditor
# Only to an account this run created (IAM 2.7). Every later change of a platform
# role is an account decision in the User Manager, which a qa person confirms when
# it widens: re-granting on every run would silently undo an applied narrowing,
# with no decision, and could leave an account with two platform roles.
[[ "$_ADMIN_NEW" == 1 ]] && _assign_realm_role "$ADMIN_USER" "admin"
if [[ "$_GF_ADMIN_NEW" == 1 && "$_GF_ADMIN_USER" != "$ADMIN_USER" ]]; then _assign_realm_role "$_GF_ADMIN_USER" "admin"; fi
[[ "$_GF_DEV_NEW" == 1 ]] && _assign_realm_role "$_GF_DEV_USER" "operator"
[[ "$_GF_VIEW_NEW" == 1 ]] && _assign_realm_role "$_GF_VIEW_USER" "auditor"

# _enabled_holders ROLE → how many enabled accounts hold realm role ROLE directly
# (qa and admin are no other role's composite children); empty when unreadable.
_enabled_holders() {
    curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/roles/$1/users?briefRepresentation=true&max=2000" \
      -H "Authorization: Bearer $(_kc_token)" \
      | python3 -c 'import json, sys; print(sum(1 for u in json.load(sys.stdin) if u.get("enabled")))' 2>/dev/null || true
}
# Break-glass: no enabled account holds admin, so nobody can open the User Manager
# to fix it. ADMIN_USER gets admin back, outside the account decisions: the qa
# screen's drift banner shows the mapping until a qa person has seen it.
_N_ADMINS="$(_enabled_holders admin)"
if [[ "$_N_ADMINS" == 0 ]]; then
    echo -e "${RED}  BREAK-GLASS: no enabled account holds realm role admin. Granting admin to '$ADMIN_USER'${NC}" >&2
    echo -e "${RED}  outside the account decisions; the User Manager's Decisions tab reports it as drift until qa sees it.${NC}" >&2
    _assign_realm_role "$ADMIN_USER" "admin" || true
    _ADMIN_ENABLED="$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users?username=${ADMIN_USER}&exact=true" \
        -H "Authorization: Bearer $(_kc_token)" \
        | python3 -c 'import json, sys; d = json.load(sys.stdin); print(str(bool(d and d[0].get("enabled"))).lower())' 2>/dev/null || echo unknown)"
    [[ "$_ADMIN_ENABLED" == true ]] \
        || echo -e "${RED}  '$ADMIN_USER' is disabled: enable it in the Keycloak console ($KC_BREAKGLASS_USER, realm $KEYCLOAK_REALM) and record why.${NC}" >&2
elif [[ -z "$_N_ADMINS" ]]; then
    echo -e "${YELLOW}  Could not count the enabled admin accounts; the admin break-glass was not checked.${NC}" >&2
fi

# The first qa person and the first engineer (infra/configure.sh asks for both).
# Every account grant and every policy change is confirmed by a qa person who is
# not the administrator, and only engineers reach Node-RED, MQTT Explorer and
# device onboarding — an install without them could approve nothing and edit no
# flow. Each is created once, with a temporary password, and gets its role only
# then: a later role change in the User Manager is never undone by a deploy.
# No first or last name: these are real people, and Keycloak asks them for their
# own name at first sign-in along with the new password, so every record they
# make carries their name, not a placeholder.
_seed_person() {   # USER EMAIL PASSWORD ROLE LABEL
    [[ -n "$1" ]] || return 0
    _create_kc_user "$1" "" "" "$2" "$3" true
    if [[ "$_KC_CREATED" == 1 ]]; then
        _assign_realm_role "$1" "$4"
        echo -e "${GREEN}  Created '$1' with role $4 (temporary password in the credentials file).${NC}"
    fi
}
echo -e "${YELLOW}  Ensuring the first qa person and the first engineer...${NC}"
_seed_person "${QA_USER:-}"       "${QA_EMAIL:-}"       "${QA_INITIAL_PASS:-}"       qa       "Quality Assurance"
_seed_person "${ENGINEER_USER:-}" "${ENGINEER_EMAIL:-}" "${ENGINEER_INITIAL_PASS:-}" engineer "Automation Engineer"
# No enabled qa person: every account decision that waits for qa — the grant of a
# new qa person included — can never be confirmed (IAM 2.7). Break-glass is a new
# QA_USER (a person who never held an account here) and another run of this
# script: _seed_person above then creates it with role qa, outside the account
# decisions (the drift banner shows it; record it in the operations log).
if [[ "$(_enabled_holders qa)" == 0 ]]; then
    echo -e "${RED}  No enabled account holds realm role qa: no account decision can be confirmed.${NC}" >&2
    echo -e "${RED}  Break-glass: set QA_USER and QA_EMAIL in config.env to a new person and run ./deploy-infra.sh again.${NC}" >&2
fi

# "organisation" as a declared user-profile attribute: Keycloak 26 drops any
# attribute the realm's user profile does not declare, so without this the
# registration form's and the profile page's organisation would vanish.
# "person_id" likewise, but visible and editable by realm administrators only:
# dual control compares persons, not accounts (the access policy's not_own_author
# and I17), so a person must never be able to set their own. It defaults to the
# account's own id (below) and reaches tokens through the medcea-identity scope.
_UP_JSON=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users/profile" -H "Authorization: Bearer $(_kc_token)" | python3 -c '
import json, sys
up = json.load(sys.stdin)
have = {a["name"] for a in up.get("attributes", [])}
changed = False
if "organisation" not in have:
    up["attributes"].append({"name": "organisation", "displayName": "Organisation",
        "validations": {"length": {"max": 200}},
        "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False})
    changed = True
if "person_id" not in have:
    up["attributes"].append({"name": "person_id", "displayName": "Person",
        "validations": {"length": {"max": 64}},
        "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False})
    changed = True
if changed:
    print(json.dumps(up))' 2>/dev/null || true)
if [[ -n "$_UP_JSON" ]]; then
    curl -s -o /dev/null -X PUT "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users/profile" \
      -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" -d "$_UP_JSON" || true
fi

# Every enabled account without a person_id gets its own id, so no two accounts
# share a person by accident; linking two accounts of one person is an admin
# decision confirmed by qa (apps/access). The IAM Phase 0.2 bootstrap: disabled
# accounts are left alone, because a registrant gets person_id = its id when qa
# confirms its grant, and that confirmation must be the only writer while the
# account waits (this loop holds no database lock). Read-modify-write: a partial
# PUT would drop the rest of the representation. Service-account users are skipped.
echo -e "${YELLOW}  Setting person_id on enabled accounts that have none...${NC}"
_PID_N=0
for _uid in $(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users?max=10000&briefRepresentation=true" \
        -H "Authorization: Bearer $(_kc_token)" | python3 -c '
import json, sys
for u in json.load(sys.stdin):
    if u.get("enabled") and not u["username"].startswith("service-account-"):
        print(u["id"])' 2>/dev/null); do
    _U_JSON=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users/${_uid}" -H "Authorization: Bearer $(_kc_token)" | python3 -c '
import json, sys
u = json.load(sys.stdin)
attrs = u.get("attributes") or {}
if attrs.get("person_id") or not u.get("enabled"):
    sys.exit(0)
attrs["person_id"] = [u["id"]]
u["attributes"] = attrs
print(json.dumps(u))' 2>/dev/null || true)
    if [[ -n "$_U_JSON" ]]; then
        curl -s -o /dev/null -X PUT "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users/${_uid}" \
          -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" -d "$_U_JSON" || true
        _PID_N=$((_PID_N + 1))
    fi
done
[[ $_PID_N -gt 0 ]] && echo -e "${GREEN}  person_id set on ${_PID_N} account(s).${NC}"

# Realm roles as a "groups" claim, which is what oauth2-proxy's allowed_groups
# reads. It has to be a client SCOPE named "groups", not just a mapper: with
# allowed_groups set, oauth2-proxy adds "groups" to the scopes it requests, and
# Keycloak refuses a login that asks for a scope it does not know
# (invalid_scope — every portal login failed until this existed).
curl -s -o /dev/null -X POST "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/client-scopes" \
  -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" \
  -d '{"name":"groups","protocol":"openid-connect","description":"Realm roles as the groups claim (oauth2-proxy allowed_groups)",
       "attributes":{"include.in.token.scope":"true","display.on.consent.screen":"false"}}' || true
_GS_ID=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/client-scopes" -H "Authorization: Bearer $(_kc_token)" \
  | python3 -c "import sys,json; print(next(s['id'] for s in json.load(sys.stdin) if s['name']=='groups'))" 2>/dev/null || echo "")

# "medcea-identity": what a service needs to trust a token (IAM plan, 3.1) — the
# person behind the account (person_id) and the audience every platform service
# checks (medcea-api). Only the access token carries the audience; the ID token's
# audience stays the client, which is what each oauth2-proxy verifies.
curl -s -o /dev/null -X POST "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/client-scopes" \
  -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" \
  -d '{"name":"medcea-identity","protocol":"openid-connect","description":"person_id claim and the medcea-api audience (apps/iam)",
       "attributes":{"include.in.token.scope":"false","display.on.consent.screen":"false"}}' || true
_IS_ID=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/client-scopes" -H "Authorization: Bearer $(_kc_token)" \
  | python3 -c "import sys,json; print(next(s['id'] for s in json.load(sys.stdin) if s['name']=='medcea-identity'))" 2>/dev/null || echo "")
if [[ -n "$_IS_ID" ]]; then
    curl -s -o /dev/null -X POST "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/client-scopes/${_IS_ID}/protocol-mappers/models" \
      -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" \
      -d '{"name":"person_id","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",
           "config":{"user.attribute":"person_id","claim.name":"person_id","jsonType.label":"String",
                     "id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true"}}' || true
    curl -s -o /dev/null -X POST "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/client-scopes/${_IS_ID}/protocol-mappers/models" \
      -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" \
      -d '{"name":"medcea-api-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
           "config":{"included.custom.audience":"medcea-api","access.token.claim":"true","id.token.claim":"false"}}' || true
else
    echo -e "${RED}  Could not create the 'medcea-identity' client scope.${NC}" >&2
fi
if [[ -n "$_GS_ID" ]]; then
    curl -s -o /dev/null -X POST "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/client-scopes/${_GS_ID}/protocol-mappers/models" \
      -H "Authorization: Bearer $(_kc_token)" -H "Content-Type: application/json" \
      -d '{"name":"realm-roles-as-groups","protocol":"openid-connect","protocolMapper":"oidc-usermodel-realm-role-mapper",
           "config":{"claim.name":"groups","jsonType.label":"String","multivalued":"true",
                     "id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true"}}' || true
    # Every client of the access policy's hosts (apps/iam/policy/defaults.yaml);
    # a client asking for "groups" without having the scope gets invalid_scope.
    for _c in portal access config monitor scheduler dbmgmt mqtt-explorer pgadmin edge-wizard node-red workbench grafana; do
        _C_UUID=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${_c}" \
          -H "Authorization: Bearer $(_kc_token)" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null || echo "")
        [[ -n "$_C_UUID" ]] || continue
        curl -s -o /dev/null -X PUT "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_C_UUID}/default-client-scopes/${_GS_ID}" \
          -H "Authorization: Bearer $(_kc_token)" || true
        [[ -n "$_IS_ID" ]] && curl -s -o /dev/null -X PUT \
          "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_C_UUID}/default-client-scopes/${_IS_ID}" \
          -H "Authorization: Bearer $(_kc_token)" || true
        # An earlier deploy put the same mapper on the client itself; one source only.
        _OLD_MAPPER=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_C_UUID}/protocol-mappers/models" \
          -H "Authorization: Bearer $(_kc_token)" | python3 -c "import sys,json; print(next((m['id'] for m in json.load(sys.stdin) if m['name']=='realm-roles-as-groups'),''))" 2>/dev/null || echo "")
        [[ -n "$_OLD_MAPPER" ]] && curl -s -o /dev/null -X DELETE \
          "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_C_UUID}/protocol-mappers/models/${_OLD_MAPPER}" \
          -H "Authorization: Bearer $(_kc_token)" || true
    done
else
    echo -e "${RED}  Could not create the 'groups' client scope — portal logins will fail with invalid_scope.${NC}" >&2
fi

# The realm's public signing keys, for medcea_iam.check() in every service (IAM
# plan 3.1: one key source, no runtime fetch). Secret medcea-jwks, mounted
# optional at /jwks/; the kubelet updates the mount in place, and the check
# re-reads it on an unknown key id, so after a key rotation in Keycloak a re-run
# of this script is all it takes. Only keys, nothing secret, but kept a Secret
# as the plan says so PostgREST (Phase 2) can take it as its jwt-secret file.
echo -e "${YELLOW}  Publishing the realm's signing keys (Secret medcea-jwks)...${NC}"
_JWKS="$(curl -sf "http://localhost:18080/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs" || true)"
# Two keys: jwks.json, the realm's set as published (medcea_iam.py), and
# jwks-sig.json, only the RS256 signing keys in a byte-stable form
# (infra/jwks-sig.py), which config-api reads as its jwt-secret when
# IAM_POSTGREST_JWT=true. PostgREST reads it only at start, so a changed set
# restarts config-api (pgrst_roll_if_changed). After rotating or removing a realm
# key, re-run this script; health-check.sh (postgrest) FAILs until then.
_JWKS_TMP="$(mktemp -d)"; chmod 700 "$_JWKS_TMP"
trap 'rm -rf "$_JWKS_TMP"' EXIT
if printf '%s' "$_JWKS" > "$_JWKS_TMP/jwks.json" \
   && python3 "$SCRIPT_DIR/infra/jwks-sig.py" < "$_JWKS_TMP/jwks.json" > "$_JWKS_TMP/jwks-sig.json"; then
    $MK8S kubectl create secret generic medcea-jwks -n "$NAMESPACE" \
        --from-file=jwks.json="$_JWKS_TMP/jwks.json" --from-file=jwks-sig.json="$_JWKS_TMP/jwks-sig.json" \
        --dry-run=client -o yaml | $MK8S kubectl apply -f - >/dev/null
    KUBECTL="$MK8S kubectl" REPO_ROOT="$SCRIPT_DIR"
    source "$SCRIPT_DIR/infra/lib-postgrest.sh"
    pgrst_roll_if_changed "$NAMESPACE" || echo -e "${RED}  Could not restart config-api for the new realm keys.${NC}" >&2
else
    echo -e "${RED}  Could not read an RS256 signing key from realm '${KEYCLOAK_REALM}' — services cannot verify tokens;${NC}" >&2
    echo -e "${RED}  Secret medcea-jwks left as it was.${NC}" >&2
fi
rm -rf "$_JWKS_TMP"
trap - EXIT

# --- Grafana's claim: `groups` (IAM 3.1), or `roles` under IAM_GATES=false ---
# The compiled role path reads the `groups` client scope (a default scope of
# grafana, above). The pre-3.1 path reads `roles`, from a mapper on the client
# itself, which only the rollback puts back: one claim source at a time.
_GF_UUID=$(curl -sf \
  "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients?clientId=grafana" \
  -H "Authorization: Bearer $(_kc_token)" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'])" 2>/dev/null || echo "")
if [[ -n "$_GF_UUID" && "${IAM_GATES:-true}" == "false" ]]; then
    echo -e "${YELLOW}  IAM_GATES=false: adding the realm-role mapper to the Grafana client...${NC}"
    curl -s -o /dev/null -X POST \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_GF_UUID}/protocol-mappers/models" \
      -H "Authorization: Bearer $(_kc_token)" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "grafana-realm-roles",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-realm-role-mapper",
        "config": {
          "claim.name": "roles",
          "jsonType.label": "String",
          "id.token.claim": "true",
          "access.token.claim": "true",
          "userinfo.token.claim": "true",
          "multivalued": "true"
        }
      }' || true
elif [[ -n "$_GF_UUID" ]]; then
    _OLD_MAPPER=$(curl -sf "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_GF_UUID}/protocol-mappers/models" \
      -H "Authorization: Bearer $(_kc_token)" | python3 -c "import sys,json; print(next((m['id'] for m in json.load(sys.stdin) if m['name']=='grafana-realm-roles'),''))" 2>/dev/null || echo "")
    if [[ -n "$_OLD_MAPPER" ]]; then
        echo -e "${YELLOW}  Removing the Grafana client's realm-role mapper (IAM 3.1: the role path reads groups)...${NC}"
        curl -s -o /dev/null -X DELETE \
          "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${_GF_UUID}/protocol-mappers/models/${_OLD_MAPPER}" \
          -H "Authorization: Bearer $(_kc_token)" || true
    fi
fi

# What the credentials file may show for each Keycloak password config.env holds.
# A person can change their own (user menu → Change password) and _create_kc_user
# never overwrites one, so a stale value must not be printed as if it worked. The
# answer comes from the admin API (kc_password_status: the password credential's
# date), never from signing in as the person — that would put a login they did
# not make on their record, and on the break-glass account's.
#   _shown_pass REALM USER PASS → the password, or why it is not shown
_shown_pass() {
    case "$(kc_password_status "$1" "$2")" in
        ok)        printf '%s' "$3" ;;
        temporary) printf '%s' "$3  (temporary: a new one is chosen at first sign-in)" ;;
        changed)   printf '%s' "(changed since the account was created; config.env's copy no longer works)" ;;
        *)         printf '%s' "(no such account yet)" ;;
    esac
}
_CRED_ADMIN_PASS="$(_shown_pass "$KEYCLOAK_REALM" "$ADMIN_USER" "$ADMIN_PASS")"
_CRED_MASTER_PASS="$(_shown_pass master "$KC_BREAKGLASS_USER" "$KC_BREAKGLASS_PASS")"
_CRED_QA_PASS="$(_shown_pass "$KEYCLOAK_REALM" "$QA_USER" "$QA_INITIAL_PASS")"
_CRED_ENG_PASS="$(_shown_pass "$KEYCLOAK_REALM" "$ENGINEER_USER" "$ENGINEER_INITIAL_PASS")"
# The demo accounts from before IAM 3.1, listed only while they exist (none on a
# new install under IAM_GATES=true); their Grafana role now follows their
# platform role like everyone's.
_CRED_GF_DEMO=""
for _u in "$_GF_ADMIN_USER:$_GF_ADMIN_PASS" "$_GF_DEV_USER:$_GF_DEV_PASS" "$_GF_VIEW_USER:$_GF_VIEW_PASS"; do
    [[ "${_u%%:*}" == "$ADMIN_USER" ]] && continue
    [[ "$(kc_password_status "$KEYCLOAK_REALM" "${_u%%:*}")" == missing ]] && continue
    _CRED_GF_DEMO+="$(printf '  %-19s %s' "${_u%%:*}" "$(_shown_pass "$KEYCLOAK_REALM" "${_u%%:*}" "${_u#*:}")")"$'\n'
done

kc_admin_done
kill $_KC_PF_PID 2>/dev/null || true

if [[ -z "$_NODE_RED_SECRET" || -z "$_GRAFANA_SECRET" || -z "$_WORKBENCH_SECRET" || -z "$_PORTAL_SECRET" \
      || -z "$_CONFIG_SECRET" || -z "$_ACCESS_SECRET" || -z "$_MONITOR_SECRET" || -z "$_SCHEDULER_SECRET" \
      || -z "$_DBMGMT_SECRET" || -z "$_MQTTX_SECRET" || -z "$_PGADMIN_SECRET" ]]; then
    echo -e "${RED}ERROR: One or more client secrets could not be retrieved.${NC}"
    exit 1
fi

# Patch config.env in place with the generated secrets
echo -e "${YELLOW}  Writing secrets to config.env...${NC}"
sed -i "s|^OAUTH2_PROXY_SECRET=.*|OAUTH2_PROXY_SECRET=\"${_NODE_RED_SECRET}\"|" config.env
sed -i "s|^GRAFANA_OAUTH_SECRET=.*|GRAFANA_OAUTH_SECRET=\"${_GRAFANA_SECRET}\"|" config.env
if grep -q '^WORKBENCH_SECRET=' config.env; then
    sed -i "s|^WORKBENCH_SECRET=.*|WORKBENCH_SECRET=\"${_WORKBENCH_SECRET}\"|" config.env
else
    printf '\n# JupyterHub workbench (infra/deploy-workbench.sh) — Keycloak client\nWORKBENCH_SECRET="%s"\n' \
        "${_WORKBENCH_SECRET}" >> config.env
fi
sed -i "s|^OAUTH2_COOKIE_SECRET=.*|OAUTH2_COOKIE_SECRET=\"${_COOKIE_SECRET}\"|" config.env
sed -i "s|^PORTAL_OAUTH2_PROXY_SECRET=.*|PORTAL_OAUTH2_PROXY_SECRET=\"${_PORTAL_SECRET}\"|" config.env
sed -i "s|^PORTAL_COOKIE_SECRET=.*|PORTAL_COOKIE_SECRET=\"${_PORTAL_COOKIE_SECRET}\"|" config.env
for _kv in "CONFIG_OAUTH2_PROXY_SECRET=${_CONFIG_SECRET}" "CONFIG_COOKIE_SECRET=${_CONFIG_COOKIE_SECRET}" \
           "ACCESS_CLIENT_SECRET=${_ACCESS_SECRET}" "ACCESS_COOKIE_SECRET=${_ACCESS_COOKIE_SECRET}" \
           "MONITOR_CLIENT_SECRET=${_MONITOR_SECRET}" "MONITOR_COOKIE_SECRET=${_MONITOR_COOKIE_SECRET}" \
           "SCHEDULER_CLIENT_SECRET=${_SCHEDULER_SECRET}" "SCHEDULER_COOKIE_SECRET=${_SCHEDULER_COOKIE_SECRET}" \
           "DBMGMT_CLIENT_SECRET=${_DBMGMT_SECRET}" "DBMGMT_COOKIE_SECRET=${_DBMGMT_COOKIE_SECRET}" \
           "MQTTX_CLIENT_SECRET=${_MQTTX_SECRET}" "MQTTX_COOKIE_SECRET=${_MQTTX_COOKIE_SECRET}" \
           "PGADMIN_OAUTH_SECRET=${_PGADMIN_SECRET}" \
           "MQTT_NODE_RED_PASS=${_MQTT_NODE_RED_PASS}" "MQTT_SCHEDULER_PASS=${_MQTT_SCHEDULER_PASS}" \
           "MQTT_EXPLORER_PASS=${_MQTT_EXPLORER_PASS}" "MQTT_AUTH_DB_PASS=${_MQTT_AUTH_DB_PASS}" \
           "KC_DEPLOYER_SECRET=${KC_DEPLOYER_SECRET:-}"; do
    _k="${_kv%%=*}"
    if grep -q "^${_k}=" config.env; then
        sed -i "s|^${_k}=.*|${_k}=\"${_kv#*=}\"|" config.env
    else
        printf '%s="%s"\n' "$_k" "${_kv#*=}" >> config.env
    fi
done

# EDGE_WIZARD_SECRET may not exist yet in an older config.env, so upsert rather
# than sed-replace: a plain sed would silently do nothing and the edge wizard
# would then refuse to start with no explanation.
if grep -q '^EDGE_WIZARD_SECRET=' config.env; then
    sed -i "s|^EDGE_WIZARD_SECRET=.*|EDGE_WIZARD_SECRET=\"${_EDGE_WIZARD_SECRET}\"|" config.env
else
    printf '\n# Edge provisioning wizard (edge/flash-device.sh --ui) — Keycloak client\nEDGE_WIZARD_SECRET="%s"\nEDGE_WIZARD_PORT="%s"\nEDGE_WIZARD_ROLE=""\n' \
        "${_EDGE_WIZARD_SECRET}" "${_EW_PORT}" >> config.env
fi
echo -e "${GREEN}  Secrets written to config.env.${NC}"

# Re-source config.env so the OAuth secrets are available for the services below.
source config.env

# =============================================================================
# 4. MOSQUITTO
#    Image:  eclipse-mosquitto:2.0 (Docker Hub Official — no registry auth needed)
#    NodePort 31883 → boards on the LAN (per-device credentials from onboarding)
#    ClusterIP 1883 → in-cluster services; 9001 (WebSocket) → the MQTT Explorer's
#    oauth2-proxy only. Nobody connects anonymously: the mqtt-auth-sync sidecar
#    merges the service accounts below with medcea.mqtt_credential (apps stage)
#    into the broker's passwd/acl files and reloads it. The Secret is re-hashed
#    (new salt) on every run, which costs one harmless reload.
# =============================================================================
echo -e "\n${GREEN}[4/10] Deploying Mosquitto MQTT broker...${NC}"
_H_NR=$(printf '%s' "$MQTT_NODE_RED_PASS"  | python3 "$SCRIPT_DIR/infra/mqtt-passwd.py")
_H_SC=$(printf '%s' "$MQTT_SCHEDULER_PASS" | python3 "$SCRIPT_DIR/infra/mqtt-passwd.py")
_H_EX=$(printf '%s' "$MQTT_EXPLORER_PASS"  | python3 "$SCRIPT_DIR/infra/mqtt-passwd.py")
# node-red only subscribes (its flows have no mqtt out node); the scheduler
# reads telemetry and writes setpoints; the explorer is the operator's tool.
# A subscription wider than these lines is accepted, but only messages the
# ACL allows are delivered — the filter is applied per message (tested on 2.0.22).
$MK8S kubectl create secret generic mosquitto-service-auth -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-literal=service-passwd="node-red:${_H_NR}
scheduler:${_H_SC}
mqtt-explorer:${_H_EX}" \
  --from-literal=service-acl="user node-red
topic read ${PROJECT_NAME}/#

user scheduler
topic read ${PROJECT_NAME}/+/+/sense/#
topic write ${PROJECT_NAME}/+/+/control/#

user mqtt-explorer
topic readwrite ${PROJECT_NAME}/#" \
  --from-literal=db-password="$MQTT_AUTH_DB_PASS" | $MK8S kubectl apply -f -
$MK8S kubectl create configmap mqtt-auth-sync -n "$NAMESPACE" \
  --from-file=mqtt-auth-sync.py="$SCRIPT_DIR/k8s/mosquitto/mqtt-auth-sync.py" \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -
render "$SCRIPT_DIR/k8s/mosquitto/mosquitto.yaml" NAMESPACE POSTGRES_DB | $MK8S kubectl apply -f -
# The sidecar reads its script once at start: restart so a changed script runs.
$MK8S kubectl rollout restart deployment/mosquitto -n "$NAMESPACE"
$MK8S kubectl rollout status deployment/mosquitto -n "$NAMESPACE" --timeout=5m

# Node-RED (schwarzit — HTTP repo, no auth)
$MK8S helm3 repo add node-red \
  https://schwarzit.github.io/node-red-chart/ --force-update

# Grafana official repo (HTTP, no auth) — cleaner than Bitnami for Grafana
$MK8S helm3 repo add grafana \
  https://grafana.github.io/helm-charts --force-update

$MK8S helm3 repo update

# =============================================================================
# 6. NODE-RED
#    Chart:  schwarzit/node-red 0.40.0 (HTTP repo — no auth)
#    Image:  docker.io/nodered/node-red:3.1.9 (Docker Hub official — auth configured)
# =============================================================================
echo -e "\n${GREEN}[5/10] Deploying Node-RED...${NC}"
$MK8S helm3 upgrade --install node-red \
  node-red/node-red \
  --version 0.40.0 \
  --namespace "$NAMESPACE" \
  --set image.registry=docker.io \
  --set image.repository=nodered/node-red \
  --set image.tag=3.1.9 \
  --set timezone="$NODE_RED_TZ" \
  --timeout 5m

echo -e "${YELLOW}Waiting for Node-RED to be ready (up to 20 min)...${NC}"
$MK8S kubectl rollout status deployment/node-red \
  -n "$NAMESPACE" --timeout=20m || {
    echo -e "${RED}--- Node-RED pod status ---${NC}"
    $MK8S kubectl get pods -l app.kubernetes.io/name=node-red -n "$NAMESPACE"
    echo -e "${RED}--- Node-RED pod events ---${NC}"
    $MK8S kubectl describe pod -l app.kubernetes.io/name=node-red \
      -n "$NAMESPACE" | tail -40
    exit 1
}

# =============================================================================
# 6. GRAFANA
#    Chart:  grafana/grafana 7.3.12 (official Grafana Helm repo — no auth)
#    Image:  docker.io/grafana/grafana (Docker Hub Official — NO auth needed)
# =============================================================================
echo -e "\n${GREEN}Pre-wiring Grafana Postgres datasource...${NC}"
# postgres, or svc_grafana once IAM_DB_SERVICE_ROLES=true and the role may log in
# (IAM 2.5). Grafana reads the datasource at start only: a changed user restarts it.
KUBECTL="$MK8S kubectl"; REPO_ROOT="$SCRIPT_DIR"
source "$SCRIPT_DIR/infra/lib-db-roles.sh"
_GF_PREV_USER="$(db_clients_live "$NAMESPACE" | awk '$1 == "grafana" {print $2}')"
db_client "$NAMESPACE" svc_grafana
DS_USER="$DBC_USER"; DS_PASS="$DBC_PASS"
render "$SCRIPT_DIR/k8s/grafana/datasource-secret.yaml" NAMESPACE POSTGRES_DB DS_USER DS_PASS | $MK8S kubectl apply -f -

echo -e "\n${GREEN}[6/10] Deploying Grafana...${NC}"
# grafana.ini with dotted section names (auth.generic_oauth) is unparseable by the chart
# template when passed via --set or values files. Use GF_* env vars instead — fully
# equivalent and supported by the chart's env: map.
# The datasource secret is mounted via extraSecretMounts into the provisioning directory.
# Grafana's own role (IAM 3.1): GRAFANA_ROLE_PATH/_STRICT from policy_grafana,
# compiled before the Keycloak section. Grafana keeps no state (no persistence),
# so the changed env rolls a pod with an empty database: every session ends and
# each person's org role is computed again at their next sign-in.
# The local admin — the only Grafana Admin, break-glass — reads its login from
# Secret grafana-admin, written from the environment, never from argv.
ADMIN_USER="$ADMIN_USER" GF_PASS="$GRAFANA_BREAKGLASS_PASS" NS="$NAMESPACE" python3 -c '
import json, os
print(json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                  "metadata": {"name": "grafana-admin", "namespace": os.environ["NS"]},
                  "stringData": {"admin-user": os.environ["ADMIN_USER"], "admin-password": os.environ["GF_PASS"]}}))' \
  | $MK8S kubectl apply -f - >/dev/null
_GF_VALUES=$(mktemp /tmp/grafana-values-XXXXXX.yaml)
render "$SCRIPT_DIR/k8s/grafana/values.yaml" GRAFANA_DOMAIN GRAFANA_OAUTH_SECRET KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE \
  GRAFANA_ROLE_PATH GRAFANA_ROLE_STRICT > "$_GF_VALUES"
$MK8S helm3 upgrade --install grafana \
  grafana/grafana \
  --version 7.3.12 \
  --namespace "$NAMESPACE" \
  --values "$_GF_VALUES" \
  --set ingress.enabled=true \
  --set "ingress.hosts[0]=$GRAFANA_DOMAIN" \
  --set "ingress.tls[0].hosts[0]=$GRAFANA_DOMAIN" \
  --set "ingress.tls[0].secretName=cea-tls" \
  --set assertNoLeakedSecrets=false \
  --timeout 10m \
  --wait
rm -f "$_GF_VALUES"
if [[ -n "$_GF_PREV_USER" && "$_GF_PREV_USER" != "$DS_USER" ]]; then
    echo "  Grafana's datasource now logs in as $DS_USER (was $_GF_PREV_USER): restarting Grafana..."
    $MK8S kubectl rollout restart deployment/grafana -n "$NAMESPACE"
    $MK8S kubectl rollout status deployment/grafana -n "$NAMESPACE" --timeout=5m
fi
DS_PASS=""
# The Secret is read at pod start; a pod that did not restart (nothing else
# changed) still has the previous password. Set it on the running Grafana too,
# on stdin. Best effort: the next restart reads the Secret anyway.
if ! printf '%s\n' "$GRAFANA_BREAKGLASS_PASS" | $MK8S kubectl exec -i -n "$NAMESPACE" deployment/grafana -c grafana -- \
        grafana cli --homepath /usr/share/grafana admin reset-admin-password --password-from-stdin >/dev/null 2>&1; then
    echo -e "${RED}  Could not set Grafana's break-glass password on the running pod; it applies at its next restart.${NC}" >&2
fi

# =============================================================================
# 7. OAUTH2 PROXY
#    Chart:  bitnami/oauth2-proxy 8.0.2 (OCI)
#    Image:  quay.io/oauth2-proxy/oauth2-proxy (Quay — NO auth needed)
# =============================================================================
echo -e "\n${GREEN}[7/10] Deploying OAuth2 Proxy (Node-RED SSO gateway)...${NC}"
_OP2_VALUES=$(mktemp /tmp/oauth2proxy-values-XXXXXX.yaml)
# allowed_groups compiled from the access policy for this host (policy_groups,
# infra/lib-oauth2-proxy.sh); IAM_GATES=false renders the pre-policy list.
# (lib-oauth2-proxy.sh was sourced before the Keycloak section, for policy_grafana.)
ALLOWED_GROUPS="$(policy_groups NODE_RED_DOMAIN)"
render "$SCRIPT_DIR/k8s/oauth2-proxy/values-node-red.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE ALLOWED_GROUPS > "$_OP2_VALUES"
gate_error_page oauth2-proxy NODE_RED_DOMAIN "$ALLOWED_GROUPS"
mapfile -t _OP2_GATE_ARGS < <(gate_helm_args oauth2-proxy)
$MK8S helm3 upgrade --install oauth2-proxy \
  oci://registry-1.docker.io/bitnamicharts/oauth2-proxy \
  --version 8.0.2 \
  --namespace "$NAMESPACE" \
  --values "$SCRIPT_DIR/k8s/oauth2-proxy/values-common.yaml" \
  --values "$_OP2_VALUES" \
  --set configuration.clientID="node-red" \
  --set configuration.clientSecret="$OAUTH2_PROXY_SECRET" \
  --set configuration.cookieSecret="$OAUTH2_COOKIE_SECRET" \
  --set configuration.oidcIssuerUrl="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" \
  --set "extraArgs[0]=--whitelist-domain=$KEYCLOAK_DOMAIN" \
  --set ingress.hostname="$NODE_RED_DOMAIN" \
  --set "ingress.extraTls[0].hosts[0]=$NODE_RED_DOMAIN" \
  --set "ingress.extraTls[0].secretName=cea-tls" \
  "${_OP2_GATE_ARGS[@]}" \
  --timeout 5m
rm -f "$_OP2_VALUES"

# Force pod restart so it picks up the updated ConfigMap (cookie_secret).
# The chart stores the secret in a ConfigMap volume, not in the pod template spec,
# so helm upgrade alone does not trigger a rollout.
$MK8S kubectl rollout restart deployment/oauth2-proxy -n "$NAMESPACE"

echo -e "${YELLOW}Waiting for OAuth2 Proxy to be ready (up to 10 min)...${NC}"
$MK8S kubectl rollout status deployment/oauth2-proxy \
  -n "$NAMESPACE" --timeout=10m || {
    echo -e "${RED}--- OAuth2 Proxy pod status ---${NC}"
    $MK8S kubectl get pods -l app.kubernetes.io/name=oauth2-proxy -n "$NAMESPACE"
    echo -e "${RED}--- OAuth2 Proxy pod logs ---${NC}"
    $MK8S kubectl logs -l app.kubernetes.io/name=oauth2-proxy \
      -n "$NAMESPACE" --tail=30 2>/dev/null || true
    echo -e "${RED}--- OAuth2 Proxy pod events ---${NC}"
    $MK8S kubectl describe pod -l app.kubernetes.io/name=oauth2-proxy \
      -n "$NAMESPACE" | tail -20
    exit 1
}

# =============================================================================
# 8. pgAdmin
#    Image: docker.io/dpage/pgadmin4:9 (Docker Hub — auth configured)
#    Pre-configured with IoT Postgres connection via servers.json + pgpassfile.
# =============================================================================
echo -e "\n${GREEN}[8/10] Deploying pgAdmin...${NC}"
# its server entry: postgres, or rr_admin_login (IAM 2.5); the pod annotation
# medcea/db-user restarts it when that changes
db_client "$NAMESPACE" rr_admin_login
PGA_DB_USER="$DBC_USER"; PGA_DB_PASS="$DBC_PASS"
render "$SCRIPT_DIR/k8s/pgadmin/pgadmin.yaml" NAMESPACE POSTGRES_DB PGA_DB_USER PGA_DB_PASS ADMIN_EMAIL ADMIN_PASS PGADMIN_DOMAIN \
       KEYCLOAK_DOMAIN KEYCLOAK_REALM PGADMIN_OAUTH_SECRET PLATFORM_IP | $MK8S kubectl apply -n "$NAMESPACE" -f -

# 10m, not 5m: pgAdmin's first boot creates and migrates its own SQLite config
# database before gunicorn starts, which took ~5.5 min on a clean install (pod
# created 10:36, Ready 10:42) and failed a 5m wait on a pod that was healthy.
$MK8S kubectl rollout status deployment/pgadmin \
  -n "$NAMESPACE" --timeout=10m

# =============================================================================
# 9. SERVICE PORTAL
#    nginx serving a static HTML service catalog, protected by OAuth2 Proxy.
#    Keycloak client: portal
#    Background image: place apps/portal/bg.jpg (or bg.png) to auto-embed it.
# =============================================================================

# Encode background image as data URI if provided (embedded inline in the HTML).
# Search order: apps/portal/bg.jpg, apps/portal/bg.png, apps/frontend/images/cea-background.png
_PORTAL_BG_STYLE=""
if [[ -f "apps/portal/bg.jpg" ]]; then
    echo -e "${YELLOW}  Encoding portal background image (apps/portal/bg.jpg)...${NC}"
    _PORTAL_BG_STYLE="background-image:url('data:image/jpeg;base64,$(base64 -w0 apps/portal/bg.jpg)');"
elif [[ -f "apps/portal/bg.png" ]]; then
    echo -e "${YELLOW}  Encoding portal background image (apps/portal/bg.png)...${NC}"
    _PORTAL_BG_STYLE="background-image:url('data:image/png;base64,$(base64 -w0 apps/portal/bg.png)');"
elif [[ -f "apps/frontend/images/cea-background.png" ]]; then
    echo -e "${YELLOW}  Encoding portal background image (apps/frontend/images/cea-background.png)...${NC}"
    _PORTAL_BG_STYLE="background-image:url('data:image/png;base64,$(base64 -w0 apps/frontend/images/cea-background.png)');"
fi
# The rd= target is a full RP-initiated logout: client_id tells Keycloak whose
# session to end and post_logout_redirect_uri brings the user back. With neither,
# Keycloak only renders a "Do you want to log out?" page and the SSO session
# survives — which is exactly "I signed out but I am still signed in".
_PORTAL_LOGOUT_RD=$(python3 -c "
import urllib.parse, sys
inner = 'https://%s/realms/%s/protocol/openid-connect/logout?client_id=portal&post_logout_redirect_uri=%s' % (
    sys.argv[1], sys.argv[2], urllib.parse.quote('https://%s/' % sys.argv[3], safe=''))
print(urllib.parse.quote(inner, safe=''))
" "$KEYCLOAK_DOMAIN" "$KEYCLOAK_REALM" "$PORTAL_DOMAIN")


echo -e "\n${GREEN}[9/9] Deploying Service Portal...${NC}"
# The background is a ~200 KB data URI — over the 128 KiB limit for one
# environment string, so render (envsubst) cannot carry it. It goes in through
# a file and a placeholder instead.
_PORTAL_BG_TMP="$(mktemp)"; printf '%s' "$_PORTAL_BG_STYLE" > "$_PORTAL_BG_TMP"
render "$SCRIPT_DIR/k8s/portal/portal.yaml" NAMESPACE _PORTAL_LOGOUT_RD GRAFANA_DOMAIN WORKBENCH_DOMAIN NODE_RED_DOMAIN DBMGMT_DOMAIN MQTTX_DOMAIN CONFIG_DOMAIN SCHEDULER_DOMAIN MONITOR_DOMAIN ACCESS_DOMAIN \
  | python3 -c 'import sys; sys.stdout.write(sys.stdin.read().replace("__PORTAL_BG_STYLE__", open(sys.argv[1]).read(), 1))' "$_PORTAL_BG_TMP" \
  | $MK8S kubectl apply -n "$NAMESPACE" -f -
rm -f "$_PORTAL_BG_TMP"

# The HTML is mounted with subPath, and a subPath ConfigMap mount does NOT
# update in a running pod — kubelet only refreshes whole-directory mounts. So an
# unchanged Deployment spec means a changed ConfigMap is simply never picked up,
# and the pod keeps serving the previous page indefinitely. Force the roll.
$MK8S kubectl rollout restart deployment/portal -n "$NAMESPACE"
$MK8S kubectl rollout status deployment/portal \
  -n "$NAMESPACE" --timeout=3m

# The portal proxy's error page (mainly the 403 for a user without a platform
# role), in the platform's look. Mounted at /templates, see values-portal.yaml.
$MK8S kubectl delete configmap portal-signin -n "$NAMESPACE" --ignore-not-found >/dev/null
render "$SCRIPT_DIR/k8s/portal/error.html" _PORTAL_LOGOUT_RD \
  | $MK8S kubectl create configmap portal-templates -n "$NAMESPACE" --from-file=error.html=/dev/stdin \
      --dry-run=client -o yaml | $MK8S kubectl apply -f -

# Portal OAuth2 Proxy (Keycloak client: portal)
_POP2_VALUES=$(mktemp /tmp/portal-oauth2proxy-values-XXXXXX.yaml)
ALLOWED_GROUPS="$(policy_groups PORTAL_DOMAIN)"
render "$SCRIPT_DIR/k8s/oauth2-proxy/values-portal.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE ALLOWED_GROUPS > "$_POP2_VALUES"
$MK8S helm3 upgrade --install portal-oauth2-proxy \
  oci://registry-1.docker.io/bitnamicharts/oauth2-proxy \
  --version 8.0.2 \
  --namespace "$NAMESPACE" \
  --values "$SCRIPT_DIR/k8s/oauth2-proxy/values-common.yaml" \
  --values "$_POP2_VALUES" \
  --set configuration.clientID="portal" \
  --set configuration.clientSecret="$PORTAL_OAUTH2_PROXY_SECRET" \
  --set configuration.cookieSecret="$PORTAL_COOKIE_SECRET" \
  --set configuration.oidcIssuerUrl="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" \
  --set "extraArgs[0]=--whitelist-domain=$KEYCLOAK_DOMAIN" \
  --set ingress.hostname="$PORTAL_DOMAIN" \
  --set "ingress.extraTls[0].hosts[0]=$PORTAL_DOMAIN" \
  --set "ingress.extraTls[0].secretName=cea-tls" \
  --timeout 5m
rm -f "$_POP2_VALUES"

$MK8S kubectl rollout restart deployment/portal-oauth2-proxy -n "$NAMESPACE"

# Redirect bare domain ($DOMAIN with no subdomain) to the portal so visitors
# don't see a raw nginx 404. Requires its own ingress because nginx-ingress
# matches by Host header — there's no implicit fallback.
render "$SCRIPT_DIR/k8s/portal/bare-domain-redirect.yaml" NAMESPACE PORTAL_DOMAIN DOMAIN | $MK8S kubectl apply -f -

echo -e "${YELLOW}Waiting for Portal OAuth2 Proxy to be ready (up to 10 min)...${NC}"
$MK8S kubectl rollout status deployment/portal-oauth2-proxy \
  -n "$NAMESPACE" --timeout=10m || {
    echo -e "${RED}--- Portal OAuth2 Proxy pod status ---${NC}"
    $MK8S kubectl get pods -l app.kubernetes.io/instance=portal-oauth2-proxy -n "$NAMESPACE"
    echo -e "${RED}--- Portal OAuth2 Proxy pod logs ---${NC}"
    $MK8S kubectl logs -l app.kubernetes.io/instance=portal-oauth2-proxy \
      -n "$NAMESPACE" --tail=30 2>/dev/null || true
    exit 1
  }

# (MQTT Explorer moved to apps/mqtt-explorer: it needs the Keycloak client
#  secret written above and an oauth2-proxy, like the other app UIs.)

# =============================================================================
# WIRE KUBEFLOW DEX -> KEYCLOAK   [RETIRED]
# =============================================================================
# Charmed Kubeflow has been replaced by JupyterHub (infra/deploy-workbench.sh), which
# authenticates against Keycloak directly with GenericOAuthenticator. Dex and
# oidc-gatekeeper existed only to translate OIDC for Kubeflow, so this entire
# section — the dex-auth connector, the issuer-url, and the MetalLB-backed
# ingress — has no counterpart in the new stack.
#
# Deliberately left commented rather than deleted: retiring 37 charm units is a
# decision worth being able to reverse. To restore, uncomment this block, restore
# the juju deploy in infra/bootstrap-infra.sh, and re-add METALLB_RANGE /
# KUBEFLOW_IP / KUBEFLOW_DOMAIN to config.env.
#
# The companion recovery script infra/patch-dex-keycloak.sh is retired with it.
#
# # =============================================================================
# # WIRE KUBEFLOW DEX → KEYCLOAK
# #    Configure dex-auth Juju charm with Keycloak OIDC connector.
# #    dex-auth is a StatefulSet managed by Juju — no ConfigMap to patch.
# # =============================================================================
# echo -e "\n${GREEN}[Wiring Kubeflow Dex → Keycloak]${NC}"
# echo -e "${YELLOW}Configuring dex-auth OIDC connector for Keycloak...${NC}"
#
# _CONNECTORS="- type: oidc
#   id: keycloak
#   name: Keycloak (${KEYCLOAK_REALM})
#   config:
#     issuer: http://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM}
#     clientID: kubeflow
#     clientSecret: ${KUBEFLOW_CLIENT_SECRET}
#     redirectURI: http://${KUBEFLOW_DOMAIN}/dex/callback
#     insecureSkipEmailVerified: true
#     insecureSkipVerify: true
#     scopes:
#       - openid
#       - profile
#       - email
#     userNameKey: email"
#
# juju config dex-auth "connectors=${_CONNECTORS}"
# # Set Dex issuer URL to the nip.io domain so OIDC_PROVIDER in oidc-authservice uses the
# # same domain that the browser uses. This keeps the CSRF cookie domain consistent with
# # the callback URL constructed by the authservice.
# juju config dex-auth "issuer-url=http://${KUBEFLOW_DOMAIN}/dex"
# echo -e "${GREEN}dex-auth connector and issuer-url set — Kubeflow will now redirect logins to Keycloak.${NC}"
#
# # Create nginx ingress for Kubeflow so it's accessible via Tailscale nip.io domain.
# # upstream-vhost is required so the oidc-authservice sees the correct Host header
# # and constructs the OIDC callback URL on the nip.io domain (matching the CSRF cookie).
# echo -e "${YELLOW}Creating Kubeflow domain ingress (${KUBEFLOW_DOMAIN})...${NC}"
# $MK8S kubectl apply -f - <<EOF
# apiVersion: networking.k8s.io/v1
# kind: Ingress
# metadata:
#   name: kubeflow-domain
#   namespace: kubeflow
#   annotations:
#     nginx.ingress.kubernetes.io/proxy-body-size: "0"
#     nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
#     nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
#     nginx.ingress.kubernetes.io/upstream-vhost: "${KUBEFLOW_DOMAIN}"
# spec:
#   ingressClassName: public
#   rules:
#   - host: ${KUBEFLOW_DOMAIN}
#     http:
#       paths:
#       - path: /
#         pathType: Prefix
#         backend:
#           service:
#             name: istio-ingressgateway-workload
#             port:
#               number: 80
# EOF
#

# =============================================================================
# AI WORKBENCH (JupyterHub)
# =============================================================================
# Deployed here rather than from deploy-apps.sh because everything else about it
# already lives in this script: its Keycloak client, its portal card, its URL in
# the summary below. Splitting the deploy off meant a rebuilt platform came back
# without a workbench, which is exactly what happened once.
if [[ "${WORKBENCH_ENABLED:-true}" == "true" ]]; then
    echo -e "\n${GREEN}[Deploying AI Workbench]${NC}"
    if ! "$SCRIPT_DIR/infra/deploy-workbench.sh"; then
        echo -e "${RED}The workbench failed to deploy. The rest of the platform is up;${NC}"
        echo -e "${RED}re-run ./infra/deploy-workbench.sh once the cause is fixed.${NC}"
    fi
else
    echo -e "\n${YELLOW}AI Workbench skipped (WORKBENCH_ENABLED is not \"true\").${NC}"
fi

# =============================================================================
# USB ONBOARDING PREREQUISITE (dialout)
# =============================================================================
# Device onboarding flashes boards over USB, and /dev/ttyACM* is root:dialout
# 0660. Without membership the wizard cannot open the port, and because it runs
# as a systemd --user service it cannot fall back to sudo either — there is no
# terminal to ask for a password on. Set it up here rather than leaving it to be
# discovered with a board already plugged in.
_ME="$(id -un)"
if [[ "$_ME" == "root" ]]; then
    echo -e "${YELLOW}[USB] Running as root — skipping the dialout check.${NC}"
elif id -nG "$_ME" | tr ' ' '\n' | grep -qx dialout; then
    echo -e "${GREEN}[USB] $_ME is already in the dialout group.${NC}"
else
    echo -e "\n${YELLOW}[USB] $_ME is not in the dialout group — device onboarding needs it.${NC}"
    if sudo -n true 2>/dev/null || sudo -v 2>/dev/null; then
        sudo usermod -aG dialout "$_ME"
        echo -e "${GREEN}  Added $_ME to dialout.${NC}"
        # usermod only updates the database. Every running process keeps the
        # group set it started with, and `systemctl --user restart` respawns from
        # user@.service, which is itself still holding the old set — so the
        # service manager is what has to be restarted, not the service.
        if sudo systemctl restart "user@$(id -u)" 2>/dev/null; then
            echo -e "${GREEN}  Restarted the user service manager, so the onboarding${NC}"
            echo -e "${GREEN}  wizard now has the new group.${NC}"
        else
            echo -e "${YELLOW}  Could not restart user@$(id -u). Run this, or log out and back in:${NC}"
            echo -e "${YELLOW}      sudo systemctl restart user@$(id -u)${NC}"
        fi
    else
        echo -e "${YELLOW}  No sudo available here. Run both, then restart onboarding:${NC}"
        echo -e "${YELLOW}      sudo usermod -aG dialout $_ME${NC}"
        echo -e "${YELLOW}      sudo systemctl restart user@$(id -u)${NC}"
    fi
fi

echo -e "\n${GREEN}Deployment complete.${NC}"

# =============================================================================
# ALIAS REDIRECTS — the previous IP domain forwards to $DOMAIN
# =============================================================================
# After a switch to a name, <svc>.<ip>.nip.io bookmarks keep working: each old
# host answers with a 301 to the same path on the new one. Sign-in stays on one
# domain, which is the only setup Keycloak, oauth2-proxy, Grafana and JupyterHub
# support with their single configured URL. The certificate carries the alias
# names (see TLS), so the redirect itself is served over valid HTTPS.
# Includes app hosts (config, dbmgmt, monitor, scheduler): a redirect to a host
# deploy-apps.sh has not moved yet is harmless and fixes itself when it runs.
$MK8S kubectl delete ingress -n "$NAMESPACE" -l medcea/alias=true --ignore-not-found >/dev/null 2>&1 || true
if $_ALIAS_ON; then
    echo -e "\n${GREEN}[ALIAS] Redirecting *.${ALIAS_DOMAIN} → *.${DOMAIN}...${NC}"
    _alias_ingress() {   # _alias_ingress NAME HOST TARGET
        local ALIAS_NAME="$1" ALIAS_HOST="$2" ALIAS_TARGET="$3"
        render "$SCRIPT_DIR/k8s/alias/ingress.yaml" ALIAS_NAME NAMESPACE ALIAS_TARGET ALIAS_HOST | $MK8S kubectl apply -f - >/dev/null
    }
    for _d in "${_SVC_DOMAINS[@]}"; do
        _sub="${_d%."$DOMAIN"}"
        _alias_ingress "alias-${_sub}" "${_sub}.${ALIAS_DOMAIN}" "https://${_d}\$request_uri"
    done
    _alias_ingress "alias-root" "${ALIAS_DOMAIN}" "https://${PORTAL_DOMAIN}/"
    echo -e "${GREEN}  ${#_SVC_DOMAINS[@]} hosts + the bare domain redirect.${NC}"
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "\n${GREEN}=================================================${NC}"
echo -e "${GREEN} SUCCESS: $NAMESPACE is live!${NC}"
echo -e "${GREEN}=================================================${NC}"
echo ""
echo -e "${GREEN}  START HERE${NC}"
echo -e "${GREEN}  ----------${NC}"
echo -e "  Service Portal:  https://$PORTAL_DOMAIN"
echo -e "    Login:         Keycloak SSO ($ADMIN_USER — password in the credentials file below)"
echo -e "    Shows:         Grafana · AI Workbench · Node-RED · Config · Scheduler · Monitor · DB Mgmt · MQTT Explorer · User Manager"
echo ""
echo -e "${GREEN}  DIRECT SERVICE ACCESS${NC}"
echo -e "${GREEN}  ---------------------${NC}"
echo -e "  Grafana:         https://$GRAFANA_DOMAIN"
if [[ "${IAM_GATES:-true}" == "false" ]]; then
echo -e "    SSO:           any enabled account (IAM_GATES=false: Admin/Editor from the grafana_* roles)"
else
echo -e "    SSO:           Editor: engineer; Viewer: roles holding R on dashboards; others refused"
fi
echo -e "    Break-glass:   local admin $ADMIN_USER at https://$GRAFANA_DOMAIN/login?disableAutoLogin (recovery only)"
echo ""
echo -e "  Node-RED:        https://$NODE_RED_DOMAIN"
echo -e "    SSO:           $ADMIN_USER"
echo ""
echo -e "  AI Workbench:    https://$WORKBENCH_DOMAIN   (JupyterHub — sign in with Keycloak)"
echo -e "    SSO:           $ADMIN_USER"
echo -e "    Note:          First login — enter a profile namespace name (e.g. 'admin')"
echo ""
echo -e "  pgAdmin:         https://$PGADMIN_DOMAIN"
echo -e "    Login:         Keycloak SSO (realm role admin only)"
echo -e "    DB:            'IoT Postgres' server pre-configured (no setup needed)"
echo ""
echo -e "${GREEN}  ADMIN${NC}"
echo -e "${GREEN}  -----${NC}"
echo -e "  Keycloak:        https://$KEYCLOAK_DOMAIN/admin   (break-glass only)"
echo -e "    Login:         $KC_BREAKGLASS_USER   (realm master; password in the credentials file)"
echo -e "    Realm:         $KEYCLOAK_REALM  (all SSO users managed here)"
echo -e "    User portal:   https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM/account"
echo -e "  User Manager:    https://$ACCESS_DOMAIN   (requests and users: admin; decisions and review: qa; ./deploy-apps.sh installs it)"
echo -e "    Register:      https://$ACCESS_DOMAIN/register   (the portal sign-in page links here)"
echo -e "    Portal gate:   the roles compiled for PORTAL_DOMAIN (python3 apps/iam/compiler/cli.py hosts)"
echo ""
echo -e "${GREEN}  INTERNAL (cluster-only)${NC}"
echo -e "${GREEN}  -----------------------${NC}"
echo -e "  MQTT Explorer:   https://$MQTTX_DOMAIN  (Keycloak SSO; ./deploy-apps.sh installs it)"
echo -e "  Mosquitto MQTT:  mqtt://$_LAN_IP:31883  (LAN NodePort — boards, per-device credentials from onboarding)"
echo -e "                   mqtt://mosquitto.$NAMESPACE.svc.cluster.local:1883  (in-cluster, service accounts)"
echo -e "                   wss://$MQTTX_DOMAIN/mqtt  (browsers, through the explorer's sign-in)"
echo -e "    Auth:          required for every client — service passwords MQTT_*_PASS in config.env"
echo -e "  MQTT topic root: ${PROJECT_NAME}/<UNIT>/<ZONE>/{sense,control,control_setpoint}/...  (PROJECT_NAME)"
echo -e "  ${YELLOW}Note:${NC} If LAN IP changes (router DHCP), re-run deploy or set a DHCP reservation."
echo -e "        IoT devices can also use $(hostname).local:31883 (mDNS via Avahi)."
echo -e "  Postgres:        rdbms-postgresql.$NAMESPACE.svc.cluster.local:5432"
echo -e "    DB / User:     $POSTGRES_DB / $POSTGRES_USER"
echo ""

# =============================================================================
# TAILSCALE SPLIT DNS — the one step that needs a person
# =============================================================================
# 100.100.100.100 is Tailscale's resolver on this node: if it already answers
# for $DOMAIN, the admin console setting is in place for every device.
if [[ "${LOCAL_DNS:-false}" == "true" ]]; then
    echo ""
    if [[ "$(dns_query 100.100.100.100 "portal.$DOMAIN" 2>/dev/null)" == "$PLATFORM_IP" ]]; then
        echo -e "${GREEN}  ✓ Tailscale split DNS is active: every tailnet device resolves *.$DOMAIN.${NC}"
    elif [[ -n "$_SPLIT_DNS_TARGET" && "$_SPLIT_DNS_TARGET" != "$PLATFORM_IP" ]]; then
        # Typically a rebuilt server: new Tailscale IP, the old route left behind.
        echo -e "${RED}=================================================${NC}"
        echo -e "${RED} TAILSCALE SPLIT DNS POINTS AT ANOTHER SERVER${NC}"
        echo -e "${RED}=================================================${NC}"
        echo "  '$DOMAIN' is routed to $_SPLIT_DNS_TARGET; this server is $PLATFORM_IP."
        _OLD_NODE="$(tailscale status 2>/dev/null | awk -v ip="${_SPLIT_DNS_TARGET%% *}" '$1 == ip { s = $2; if (match($0, /offline[^,]*(, last seen [^,]*)?/)) s = s " (" substr($0, RSTART, RLENGTH) ")"; print s; exit }')"
        [[ -n "$_OLD_NODE" ]] && echo "  $_SPLIT_DNS_TARGET is: $_OLD_NODE"
        echo "  This machine still resolves the names (/etc/hosts); every other device does not."
        echo ""
        echo "  1. Open https://login.tailscale.com/admin/dns"
        echo "  2. Nameservers → the entry restricted to '$DOMAIN' → Edit"
        echo "  3. Change $_SPLIT_DNS_TARGET to $PLATFORM_IP → Save"
        echo "     (If the old server is gone for good, remove it under Machines too.)"
        echo ""
        echo "  Test from any device:  nslookup portal.$DOMAIN   → $PLATFORM_IP"
        echo "  Re-running ./deploy-infra.sh reports ✓ once the setting is in place."
    else
        echo -e "${YELLOW}=================================================${NC}"
        echo -e "${YELLOW} ONE STEP LEFT: make *.$DOMAIN work on your other devices${NC}"
        echo -e "${YELLOW}=================================================${NC}"
        echo "  This machine already resolves the names (/etc/hosts). For laptops and phones"
        echo "  on your tailnet, tell Tailscale to ask this server about '$DOMAIN':"
        echo ""
        echo "  1. Open https://login.tailscale.com/admin/dns"
        echo "  2. Nameservers → Add nameserver → Custom..."
        echo "  3. Nameserver: $PLATFORM_IP"
        echo "     Turn on 'Restrict to domain' (Split DNS), domain: $DOMAIN → Save"
        echo "  4. Each device needs 'Use Tailscale DNS settings' on (the default)."
        echo "     Linux devices: sudo tailscale set --accept-dns=true"
        echo ""
        echo "  Test from any device:  nslookup portal.$DOMAIN   → $PLATFORM_IP"
        echo "  Then open https://portal.$DOMAIN — type the https:// the first time;"
        echo "  browsers read a one-word ending like .$DOMAIN as a search until visited."
        echo "  Re-running ./deploy-infra.sh reports ✓ once the setting is in place."
    fi
fi

# =============================================================================
# CREDENTIALS FILE
# =============================================================================
# Every password a person needs, in one file readable only by its owner. The
# content goes to the terminal through /dev/tty, never through stdout: stdout is
# teed into logs/, and that log must not hold the passwords. The summary above
# names users only, for the same reason.
CRED_FILE="$SCRIPT_DIR/credentials-$(date +%Y%m%d-%H%M%S).txt"

# _CRED_* were worked out in the Keycloak section (_shown_pass), from the admin
# API, while it was still reachable.
(
umask 077
cat > "$CRED_FILE" <<CREDS
MedCEA platform credentials
Generated by deploy-infra.sh on $(date '+%Y-%m-%d %H:%M') for $(hostname) — project '$PROJECT_NAME'

Save these in a password manager, then delete this file.
config.env keeps a copy (re-deploys need it); it is readable only by $(id -un).

PLATFORM ADMIN (Keycloak SSO: portal, Node-RED, AI workbench)
  Service portal      https://$PORTAL_DOMAIN
  Username            $ADMIN_USER
  Password            $_CRED_ADMIN_PASS

FIRST QA PERSON (confirms account grants, approves policy changes)
  Service portal      https://$PORTAL_DOMAIN
  Username            $QA_USER
  Password            $_CRED_QA_PASS

FIRST ENGINEER (Node-RED, MQTT Explorer, device onboarding)
  Service portal      https://$PORTAL_DOMAIN
  Username            $ENGINEER_USER
  Password            $_CRED_ENG_PASS

KEYCLOAK ADMIN CONSOLE — BREAK-GLASS ONLY (realm master)
  For recovery when the platform's own tools cannot do the job. Every use is
  recorded in Keycloak's admin events. Not the platform admin's account.
  URL                 https://$KEYCLOAK_DOMAIN/admin
  Username            $KC_BREAKGLASS_USER
  Password            $_CRED_MASTER_PASS

GRAFANA (Keycloak SSO; the role follows the access policy: Editor for engineer,
Viewer for the roles holding R on dashboards, no sign-in for the others)
  URL                 https://$GRAFANA_DOMAIN

GRAFANA LOCAL ADMIN — BREAK-GLASS ONLY (Grafana Admin; logged by Grafana)
  URL                 https://$GRAFANA_DOMAIN/login?disableAutoLogin
  Username            $ADMIN_USER
  Password            $GRAFANA_BREAKGLASS_PASS
${_CRED_GF_DEMO:+
DEMO ACCOUNTS FROM BEFORE IAM 3.1 (kept; deactivate in the User Manager if unused)
${_CRED_GF_DEMO}}
PGADMIN (Keycloak SSO — platform role admin only)
  URL                 https://$PGADMIN_DOMAIN

MQTT BROKER (every client authenticates)
  Service accounts    node-red / scheduler / mqtt-explorer — passwords MQTT_*_PASS in config.env
  Boards              one credential each, minted at onboarding (edge/provisioned/<name>.json)

POSTGRESQL SUPERUSER (cluster-internal)
  Host                rdbms-postgresql.$NAMESPACE.svc.cluster.local:5432
  Database            $POSTGRES_DB
  Username            $POSTGRES_USER
  Password            $POSTGRES_PASS

Not listed: your Docker Hub token (yours, not the platform's) and the OAuth
client and cookie secrets (used only by services; they stay in config.env).
CREDS
)

# install.sh shows the box itself once the apps are deployed too, so that it is
# the last thing on screen; a standalone run shows it here.
source "$SCRIPT_DIR/infra/lib-credentials.sh"
if [[ "${MEDCEA_INSTALLER:-}" == "1" ]]; then
    echo "Credentials written to $CRED_FILE — shown at the end of ./install.sh."
else
    show_ca_trust "$CA_DIR/ca.crt" "$PLATFORM_IP" "$PORTAL_DOMAIN"
    show_credentials "$CRED_FILE"
fi
