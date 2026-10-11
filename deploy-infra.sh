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
    if snap list 2>/dev/null | grep -q microk8s; then
        $MK8S stop || true
        $MK8S reset --destroy-storage || true
        sudo snap remove microk8s --purge
        sudo rm -rf ~/.kube /var/snap/microk8s
    else
        echo "  MicroK8s not installed — skipping."
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
for var in PROJECT_NAME NAMESPACE DOMAIN ADMIN_USER ADMIN_PASS POSTGRES_USER POSTGRES_PASS POSTGRES_DB DOCKERHUB_USER DOCKERHUB_PAT \
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
for _v in KEYCLOAK_DOMAIN GRAFANA_DOMAIN NODE_RED_DOMAIN PGADMIN_DOMAIN DBMGMT_DOMAIN \
          SCHEDULER_DOMAIN MONITOR_DOMAIN CONFIG_DOMAIN MQTTX_DOMAIN PORTAL_DOMAIN WORKBENCH_DOMAIN; do
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

# Keycloak
# Image: quay.io/keycloak/keycloak:26.0 (official, free)
# Note: bitnami/keycloak is behind a paywall since Aug 2025 — using kubectl manifests instead.
echo -e "\n${GREEN}[2/10] Deploying Keycloak...${NC}"

# Clean up any previous Helm-managed Keycloak release (idempotent)
$MK8S helm3 uninstall keycloak --namespace "$NAMESPACE" 2>/dev/null || true

render "$SCRIPT_DIR/k8s/keycloak/keycloak.yaml" NAMESPACE ADMIN_USER ADMIN_PASS POSTGRES_USER POSTGRES_PASS KEYCLOAK_DOMAIN | $MK8S kubectl apply -n "$NAMESPACE" -f -

echo -e "${YELLOW}Waiting for Keycloak to be ready (up to 10 min)...${NC}"
$MK8S kubectl rollout status deployment/keycloak -n "$NAMESPACE" --timeout=10m

# =============================================================================
# 3. KEYCLOAK REALM + OAUTH CLIENTS
# Creates realm 'medcea', confidential clients, and writes secrets to config.env.
# Idempotent: 409 responses (already exists) are handled gracefully.
# =============================================================================
echo -e "\n${GREEN}[3/10] Configuring Keycloak realm '${KEYCLOAK_REALM}' and OAuth clients...${NC}"

# Kill any stale port-forward on 18080 from a previous run
fuser -k 18080/tcp &>/dev/null || true
sleep 1
$MK8S kubectl port-forward svc/keycloak 18080:80 -n "$NAMESPACE" &>/dev/null &
_KC_PF_PID=$!
sleep 5

# Helper: get a fresh admin token (Keycloak tokens expire in ~60s)
_kc_token() {
    curl -sf -X POST \
      "http://localhost:18080/realms/master/protocol/openid-connect/token" \
      -d "client_id=admin-cli" \
      -d "username=${ADMIN_USER}" \
      -d "password=${ADMIN_PASS}" \
      -d "grant_type=password" \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo ""
}

# Retry up to 12 times (60s) in case the port-forward needs extra time
_KC_TOKEN=""
for _i in $(seq 1 12); do
    _KC_TOKEN=$(_kc_token)
    [[ -n "$_KC_TOKEN" ]] && break
    echo -e "${YELLOW}  Waiting for Keycloak Admin API... (${_i}/12)${NC}"
    sleep 5
done
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

# Create a confidential client and echo its secret (captured by caller via $())
_create_client() {
    local CLIENT_ID="$1"
    local REDIRECT_URI="$2"
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
      -d "{\"clientId\":\"${CLIENT_ID}\",\"enabled\":true,\"publicClient\":false,\"standardFlowEnabled\":true,\"redirectUris\":[\"${REDIRECT_URI}\"],\"attributes\":{\"post.logout.redirect.uris\":\"${ORIGIN}/*\"}}" || true

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

    # Re-apply the redirect URI on every run. The POST above returns 409 for an
    # existing client and changes nothing, so without this a client created once
    # keeps its original URI forever — which is why moving the platform to https
    # produced "Invalid parameter: redirect_uri" instead of a login page.
    TOK=$(_kc_token)
    curl -s -o /dev/null -X PUT \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${UUID}" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "{\"clientId\":\"${CLIENT_ID}\",\"enabled\":true,\"publicClient\":false,\"standardFlowEnabled\":true,\"redirectUris\":[\"${REDIRECT_URI}\"],\"attributes\":{\"post.logout.redirect.uris\":\"${ORIGIN}/*\"}}" || true

    # Retrieve the generated secret
    curl -sf \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients/${UUID}/client-secret" \
      -H "Authorization: Bearer ${TOK}" \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])" 2>/dev/null || echo ""
}

# Same as _create_client but takes a JSON array of redirect URIs. The edge
# wizard runs on the platform host itself and is opened on whichever address the
# operator can reach — LAN, Tailscale or loopback — so one URI is not enough.
_create_client_multi() {
    local CLIENT_ID="$1" REDIRECT_JSON="$2" TOK UUID
    TOK=$(_kc_token)
    curl -s -o /dev/null -X POST \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "{\"clientId\":\"${CLIENT_ID}\",\"enabled\":true,\"publicClient\":false,\"standardFlowEnabled\":true,\"redirectUris\":${REDIRECT_JSON},\"attributes\":{\"post.logout.redirect.uris\":\"+\"}}" || true

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
      -d "{\"clientId\":\"${CLIENT_ID}\",\"enabled\":true,\"publicClient\":false,\"standardFlowEnabled\":true,\"redirectUris\":${REDIRECT_JSON},\"attributes\":{\"post.logout.redirect.uris\":\"+\"}}" || true

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
echo -e "${YELLOW}  Creating client 'edge-wizard'...${NC}"
# The edge provisioning wizard (edge/flash-device.sh --ui) runs on this host and
# is opened from a laptop over SSH, so register every address it can answer on.
_EW_PORT="${EDGE_WIZARD_PORT:-8088}"
_EW_TS="$(tailscale ip -4 2>/dev/null | head -1 || true)"
_EW_URIS="$(EW_PORT="$_EW_PORT" EW_LAN="${_LAN_IP:-}" EW_TS="$_EW_TS" python3 -c "
import json, os
e = os.environ; port = e['EW_PORT']
hosts = ['127.0.0.1', 'localhost'] + [h for h in (e.get('EW_LAN'), e.get('EW_TS')) if h]
print(json.dumps(['http://%s:%s/oauth2/callback' % (h, port) for h in hosts]))")"
_EDGE_WIZARD_SECRET=$(_create_client_multi "edge-wizard" "$_EW_URIS")
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

# Helper: create a user with a temporary=false password (idempotent — 409 = already exists)
_create_kc_user() {
    local USERNAME="$1" FIRSTNAME="$2" LASTNAME="$3" EMAIL="$4" PASSWORD="$5"
    local TOK
    TOK=$(_kc_token)
    curl -s -o /dev/null -X POST \
      "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/users" \
      -H "Authorization: Bearer ${TOK}" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${USERNAME}\",\"firstName\":\"${FIRSTNAME}\",\"lastName\":\"${LASTNAME}\",\"email\":\"${EMAIL}\",\"enabled\":true,\"emailVerified\":true,\"credentials\":[{\"type\":\"password\",\"value\":\"${PASSWORD}\",\"temporary\":false}]}" || true
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

# --- Grafana realm roles ---
echo -e "${YELLOW}  Creating Grafana roles...${NC}"
_create_realm_role "grafana_admin"
_create_realm_role "grafana_developer"
_create_realm_role "grafana_viewer"

# --- Grafana users — usernames/passwords from config.env, fall back to ADMIN_PASS ---
_GF_ADMIN_USER="${GRAFANA_ADMIN_USER:-admin}"
_GF_ADMIN_PASS="${GRAFANA_ADMIN_PASS:-$ADMIN_PASS}"
_GF_DEV_USER="${GRAFANA_DEVELOPER_USER:-developer}"
_GF_DEV_PASS="${GRAFANA_DEVELOPER_PASS:-$ADMIN_PASS}"
_GF_VIEW_USER="${GRAFANA_VIEWER_USER:-viewer}"
_GF_VIEW_PASS="${GRAFANA_VIEWER_PASS:-$ADMIN_PASS}"

echo -e "${YELLOW}  Creating Grafana users...${NC}"
_create_kc_user "$_GF_ADMIN_USER" "Platform" "Admin"     "${_GF_ADMIN_USER}@cea.com" "$_GF_ADMIN_PASS"
_create_kc_user "$_GF_DEV_USER"   "Platform" "Developer" "${_GF_DEV_USER}@cea.com"   "$_GF_DEV_PASS"
_create_kc_user "$_GF_VIEW_USER"  "Platform" "Viewer"    "${_GF_VIEW_USER}@cea.com"  "$_GF_VIEW_PASS"

echo -e "${YELLOW}  Assigning roles to Grafana users...${NC}"
_assign_realm_role "$_GF_ADMIN_USER" "grafana_admin"
_assign_realm_role "$_GF_DEV_USER"   "grafana_developer"
_assign_realm_role "$_GF_VIEW_USER"  "grafana_viewer"

# The platform admin (portal, Node-RED, workbench admin, credentials file) is
# ADMIN_USER. It only existed in the realm because ADMIN_USER defaults to
# "admin" = GRAFANA_ADMIN_USER; with any other name the documented login did
# not exist. Create it explicitly unless it is the same user.
if [[ "$ADMIN_USER" != "$_GF_ADMIN_USER" ]]; then
    echo -e "${YELLOW}  Creating platform admin user '$ADMIN_USER'...${NC}"
    _create_kc_user "$ADMIN_USER" "Platform" "Administrator" "${ADMIN_USER}@cea.com" "$ADMIN_PASS"
    _assign_realm_role "$ADMIN_USER" "grafana_admin"
fi

# --- Add realm-role mapper to grafana client so roles[] appears in userinfo ---
echo -e "${YELLOW}  Adding realm-role mapper to Grafana client...${NC}"
_GF_UUID=$(curl -sf \
  "http://localhost:18080/admin/realms/${KEYCLOAK_REALM}/clients?clientId=grafana" \
  -H "Authorization: Bearer $(_kc_token)" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'])" 2>/dev/null || echo "")
if [[ -n "$_GF_UUID" ]]; then
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
    echo -e "${GREEN}  Grafana role mapper added.${NC}"
fi

kill $_KC_PF_PID 2>/dev/null || true

if [[ -z "$_NODE_RED_SECRET" || -z "$_GRAFANA_SECRET" || -z "$_WORKBENCH_SECRET" || -z "$_PORTAL_SECRET" ]]; then
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
for _kv in "CONFIG_OAUTH2_PROXY_SECRET=${_CONFIG_SECRET}" "CONFIG_COOKIE_SECRET=${_CONFIG_COOKIE_SECRET}"; do
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
#    Image:  eclipse-mosquitto:2.0 (Docker Hub Official — NO auth needed)
#    NodePort 31883 → external IoT devices
#    ClusterIP 1883  → internal Kubernetes services (Node-RED etc.)
# =============================================================================
echo -e "\n${GREEN}[4/10] Deploying Mosquitto MQTT broker...${NC}"
render "$SCRIPT_DIR/k8s/mosquitto/mosquitto.yaml" NAMESPACE | $MK8S kubectl apply -f -

$MK8S kubectl wait deployment/mosquitto \
    -n "$NAMESPACE" --for=condition=Available --timeout=5m

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
render "$SCRIPT_DIR/k8s/grafana/datasource-secret.yaml" NAMESPACE POSTGRES_DB POSTGRES_USER POSTGRES_PASS | $MK8S kubectl apply -f -

echo -e "\n${GREEN}[6/10] Deploying Grafana...${NC}"
# grafana.ini with dotted section names (auth.generic_oauth) is unparseable by the chart
# template when passed via --set or values files. Use GF_* env vars instead — fully
# equivalent and supported by the chart's env: map.
# The datasource secret is mounted via extraSecretMounts into the provisioning directory.
_GF_VALUES=$(mktemp /tmp/grafana-values-XXXXXX.yaml)
render "$SCRIPT_DIR/k8s/grafana/values.yaml" GRAFANA_DOMAIN GRAFANA_OAUTH_SECRET KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE > "$_GF_VALUES"
$MK8S helm3 upgrade --install grafana \
  grafana/grafana \
  --version 7.3.12 \
  --namespace "$NAMESPACE" \
  --values "$_GF_VALUES" \
  --set adminUser="$ADMIN_USER" \
  --set adminPassword="$ADMIN_PASS" \
  --set ingress.enabled=true \
  --set "ingress.hosts[0]=$GRAFANA_DOMAIN" \
  --set "ingress.tls[0].hosts[0]=$GRAFANA_DOMAIN" \
  --set "ingress.tls[0].secretName=cea-tls" \
  --set assertNoLeakedSecrets=false \
  --timeout 10m \
  --wait
rm -f "$_GF_VALUES"

# =============================================================================
# 7. OAUTH2 PROXY
#    Chart:  bitnami/oauth2-proxy 8.0.2 (OCI)
#    Image:  quay.io/oauth2-proxy/oauth2-proxy (Quay — NO auth needed)
# =============================================================================
echo -e "\n${GREEN}[7/10] Deploying OAuth2 Proxy (Node-RED SSO gateway)...${NC}"
_OP2_VALUES=$(mktemp /tmp/oauth2proxy-values-XXXXXX.yaml)
render "$SCRIPT_DIR/k8s/oauth2-proxy/values-node-red.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE > "$_OP2_VALUES"
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
  --set ingress.hostname="$NODE_RED_DOMAIN" \
  --set "ingress.extraTls[0].hosts[0]=$NODE_RED_DOMAIN" \
  --set "ingress.extraTls[0].secretName=cea-tls" \
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
render "$SCRIPT_DIR/k8s/pgadmin/pgadmin.yaml" NAMESPACE POSTGRES_DB POSTGRES_USER POSTGRES_PASS ADMIN_USER ADMIN_PASS PGADMIN_DOMAIN | $MK8S kubectl apply -n "$NAMESPACE" -f -

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


echo -e "\n${GREEN}[9/10] Deploying Service Portal...${NC}"
# The background is a ~200 KB data URI — over the 128 KiB limit for one
# environment string, so render (envsubst) cannot carry it. It goes in through
# a file and a placeholder instead.
_PORTAL_BG_TMP="$(mktemp)"; printf '%s' "$_PORTAL_BG_STYLE" > "$_PORTAL_BG_TMP"
render "$SCRIPT_DIR/k8s/portal/portal.yaml" NAMESPACE _PORTAL_LOGOUT_RD GRAFANA_DOMAIN WORKBENCH_DOMAIN NODE_RED_DOMAIN DBMGMT_DOMAIN MQTTX_DOMAIN CONFIG_DOMAIN SCHEDULER_DOMAIN MONITOR_DOMAIN \
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

# Portal OAuth2 Proxy (Keycloak client: portal)
_POP2_VALUES=$(mktemp /tmp/portal-oauth2proxy-values-XXXXXX.yaml)
render "$SCRIPT_DIR/k8s/oauth2-proxy/values-portal.yaml" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE > "$_POP2_VALUES"
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

# =============================================================================
# 10. MQTT EXPLORER
#    Custom lightweight MQTT explorer: nginx + HTML ConfigMap (no Docker Hub image).
#    Auto-connects to Mosquitto WebSocket using the Tailscale IP (stable — does
#    not change when the home router reassigns LAN IPs).
#    Uses mqtt.js@4 from CDN. No auth required — it's a read/write MQTT tool.
# =============================================================================
echo -e "\n${GREEN}[10/10] Deploying MQTT Explorer...${NC}"

# Tailscale IP is stable (assigned by Tailscale, not the home router). Taken
# from PLATFORM_IP, never from DOMAIN: DOMAIN may be a name (medcea).
_TAILSCALE_IP="$PLATFORM_IP"

# Write HTML to temp file using single-quote heredoc (no shell expansion),
# then substitute the Tailscale IP placeholder with sed.
cp "$SCRIPT_DIR/k8s/mqtt-explorer/index.html" /tmp/mqtt-explorer.html   # __WS_HOST__ is filled below

sed -i "s|__WS_HOST__|${_TAILSCALE_IP}|g" /tmp/mqtt-explorer.html

# Clean up old mqttx-web resources from previous deploy (renamed to mqtt-explorer)
$MK8S kubectl delete deployment/mqttx-web service/mqttx-web ingress/mqttx-web \
  -n "$NAMESPACE" 2>/dev/null || true

$MK8S kubectl create configmap mqtt-explorer-html \
  -n "$NAMESPACE" \
  --from-file=index.html=/tmp/mqtt-explorer.html \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -
rm -f /tmp/mqtt-explorer.html

render "$SCRIPT_DIR/k8s/mqtt-explorer/mqtt-explorer.yaml" NAMESPACE MQTTX_DOMAIN | $MK8S kubectl apply -n "$NAMESPACE" -f -

$MK8S kubectl rollout status deployment/mqtt-explorer \
  -n "$NAMESPACE" --timeout=5m

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
echo -e "    Shows:         Grafana · Node-RED · Kubeflow · pgAdmin · MQTTX Web"
echo ""
echo -e "${GREEN}  DIRECT SERVICE ACCESS${NC}"
echo -e "${GREEN}  ---------------------${NC}"
echo -e "  Grafana:         https://$GRAFANA_DOMAIN"
echo -e "    SSO:           $_GF_ADMIN_USER  (Admin)"
echo -e "                   $_GF_DEV_USER  (Editor)"
echo -e "                   $_GF_VIEW_USER  (Viewer)"
echo ""
echo -e "  Node-RED:        https://$NODE_RED_DOMAIN"
echo -e "    SSO:           $ADMIN_USER"
echo ""
echo -e "  AI Workbench:    https://$WORKBENCH_DOMAIN   (JupyterHub — sign in with Keycloak)"
echo -e "    SSO:           $ADMIN_USER"
echo -e "    Note:          First login — enter a profile namespace name (e.g. 'admin')"
echo ""
echo -e "  pgAdmin:         https://$PGADMIN_DOMAIN"
echo -e "    Login:         ${ADMIN_USER}@cea.com"
echo -e "    DB:            'IoT Postgres' server pre-configured (no setup needed)"
echo ""
echo -e "${GREEN}  ADMIN${NC}"
echo -e "${GREEN}  -----${NC}"
echo -e "  Keycloak:        https://$KEYCLOAK_DOMAIN/admin"
echo -e "    Login:         $ADMIN_USER"
echo -e "    Realm:         $KEYCLOAK_REALM  (all SSO users managed here)"
echo -e "    User portal:   https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM/account"
echo ""
echo -e "${GREEN}  INTERNAL (cluster-only)${NC}"
echo -e "${GREEN}  -----------------------${NC}"
echo -e "  MQTT Explorer:   https://$MQTTX_DOMAIN"
echo -e "    Auto-connect:  ws://${_TAILSCALE_IP}:31901  (Tailscale IP — stable)"
echo -e "  Mosquitto MQTT:  mqtt://$_LAN_IP:31883  (LAN NodePort — IoT devices)"
echo -e "                   ws://${_TAILSCALE_IP}:31901  (WebSocket — browsers, Tailscale-stable)"
echo -e "                   mqtt://mosquitto.$NAMESPACE.svc.cluster.local:1883  (in-cluster)"
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
  Password            $ADMIN_PASS

KEYCLOAK ADMIN CONSOLE
  URL                 https://$KEYCLOAK_DOMAIN/admin
  Username            $ADMIN_USER
  Password            $ADMIN_PASS

GRAFANA (Keycloak SSO)
  URL                 https://$GRAFANA_DOMAIN
  Admin               $_GF_ADMIN_USER / $_GF_ADMIN_PASS
  Editor              $_GF_DEV_USER / $_GF_DEV_PASS
  Viewer              $_GF_VIEW_USER / $_GF_VIEW_PASS

PGADMIN
  URL                 https://$PGADMIN_DOMAIN
  Username            ${ADMIN_USER}@cea.com
  Password            $ADMIN_PASS

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
