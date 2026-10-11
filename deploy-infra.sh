#!/bin/bash

# Colors (defined early so --help can use them)

# microk8s commands need sudo only when the invoking user is not in the microk8s
# group. Detecting that instead of hardcoding `sudo` lets a member of the group
# deploy without a password prompt, while leaving every other case unchanged.

# All scripts are run from the repository root (config.env is read relatively),
# but locating a sibling script by path rather than by cwd is one less thing to
# get wrong.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
    echo ""
    echo -e "${GREEN}     *            ${YELLOW}╔══════════════════════════════════╗${NC}       _____"
    echo -e "${GREEN}    \|/           ${YELLOW}║                                  ║${NC}      /     \\"
    echo -e "${GREEN}   --*--          ${YELLOW}║   ___  ___   _                   ║${NC}     / o * o \\"
    echo -e "${GREEN}    /|\           ${YELLOW}║  / __|| __| /_\                  ║${NC}    |   ~~~   |"
    echo -e "${GREEN}   ( ' )          ${YELLOW}║ | /__ | _| / _ \                 ║${NC}    |_________|"
    echo -e "${GREEN}  (  .  )         ${YELLOW}║  \___||___/_/ \_\                ║${NC}         |"
    echo -e "${GREEN}   ( ' )          ${YELLOW}║                                  ║${NC}        (|)"
    echo -e "${GREEN}    |||           ${YELLOW}║   I o T   P l a t f o r m        ║${NC}    ~~~(|)~~~"
    echo -e "${GREEN}    |||           ${YELLOW}╚══════════════════════════════════╝${NC}"
    echo -e "${GREEN}  ~~|||~~${NC}"
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
    read -p "Type 'yes' to confirm uninstall: " _CONFIRM
    if [[ "$_CONFIRM" != "yes" ]]; then
        echo "Aborted."
        exit 0
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
    read -p "Type 'reset' to confirm: " _CONFIRM
    [[ "$_CONFIRM" == "reset" ]] || { echo "Aborted."; exit 0; }

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
           WORKBENCH_DOMAIN PGADMIN_DOMAIN PORTAL_DOMAIN MQTTX_DOMAIN; do
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
if [ -r "$DOCKER_CERTS_DIR/hosts.toml" ] && \
   grep -q "username = \"${DOCKERHUB_USER}\"" "$DOCKER_CERTS_DIR/hosts.toml" 2>/dev/null; then
    echo -e "${GREEN}  Docker Hub credentials already configured — skipping (no containerd restart).${NC}"
else
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
openssl req -new -key "$CA_DIR/server.key" -subj "/CN=*.${DOMAIN}" -out "$CA_DIR/server.csr"
openssl x509 -req -in "$CA_DIR/server.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
  -CAcreateserial -days 825 -sha256 -out "$CA_DIR/server.crt" \
  -extfile <(printf "subjectAltName=DNS:*.%s,DNS:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" "$DOMAIN" "$DOMAIN")
chmod 600 "$CA_DIR"/*.key
$MK8S kubectl create secret tls cea-tls -n "$NAMESPACE" \
  --cert="$CA_DIR/server.crt" --key="$CA_DIR/server.key" \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -
# The CA cert itself, for anything in-cluster that must verify us later.
$MK8S kubectl create configmap cea-ca -n "$NAMESPACE" \
  --from-file=ca.crt="$CA_DIR/ca.crt" \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -

echo -e "\n${GREEN}--- Deploying MedCEA to $NAMESPACE ---${NC}"

$MK8S kubectl create namespace "$NAMESPACE" \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -

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
  --timeout 20m \
  --wait

# Keycloak
# Image: quay.io/keycloak/keycloak:26.0 (official, free)
# Note: bitnami/keycloak is behind a paywall since Aug 2025 — using kubectl manifests instead.
echo -e "\n${GREEN}[2/10] Deploying Keycloak...${NC}"

# Clean up any previous Helm-managed Keycloak release (idempotent)
$MK8S helm3 uninstall keycloak --namespace "$NAMESPACE" 2>/dev/null || true

$MK8S kubectl apply -n "$NAMESPACE" -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: $NAMESPACE
  labels:
    app: keycloak
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:26.0
        args:
        - start
        env:
        - name: KEYCLOAK_ADMIN
          value: "$ADMIN_USER"
        - name: KEYCLOAK_ADMIN_PASSWORD
          value: "$ADMIN_PASS"
        - name: KC_DB
          value: postgres
        - name: KC_DB_URL
          value: "jdbc:postgresql://rdbms-postgresql.$NAMESPACE.svc.cluster.local:5432/$POSTGRES_DB"
        - name: KC_DB_USERNAME
          value: "$POSTGRES_USER"
        - name: KC_DB_PASSWORD
          value: "$POSTGRES_PASS"
        - name: KC_HTTP_ENABLED
          value: "true"
        - name: KC_PROXY_HEADERS
          value: xforwarded
        - name: KC_HOSTNAME
          # https, because the browser now reaches Keycloak over TLS and the
          # issuer in every token has to match what the browser used. A mismatch
          # here is the "500 on portal login" failure from the deployment notes.
          value: "https://$KEYCLOAK_DOMAIN"
        - name: KC_HOSTNAME_STRICT
          value: "false"
        - name: KC_HEALTH_ENABLED
          value: "true"
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9000
          name: management
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 9000
          initialDelaySeconds: 60
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 18
        livenessProbe:
          httpGet:
            path: /health/live
            port: 9000
          initialDelaySeconds: 120
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: $NAMESPACE
spec:
  selector:
    app: keycloak
  ports:
  - name: http
    port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: keycloak
  namespace: $NAMESPACE
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffer-size: "128k"
    nginx.ingress.kubernetes.io/proxy-buffers-number: "8"
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "false"
spec:
  # TLS from the platform CA. Adding this also makes nginx-ingress redirect
  # plain HTTP here with a 308, which is why every registered redirect URI had
  # to move to https in the same change.
  tls:
  - hosts: [$KEYCLOAK_DOMAIN]
    secretName: cea-tls
  ingressClassName: nginx
  rules:
  - host: $KEYCLOAK_DOMAIN
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: keycloak
            port:
              number: 80
EOF

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
_CONFIG_COOKIE_SECRET=$(openssl rand -base64 24)
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
_COOKIE_SECRET=$(openssl rand -base64 24)  # 24 bytes → 32-char base64 → valid AES-256 key for oauth2-proxy
_PORTAL_COOKIE_SECRET=$(openssl rand -base64 24)

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
$MK8S kubectl apply -f - <<EOF
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mosquitto-config
  namespace: $NAMESPACE
data:
  mosquitto.conf: |
    listener 1883
    allow_anonymous true
    persistence true
    persistence_location /mosquitto/data/
    log_dest stdout
    listener 9001
    protocol websockets
    allow_anonymous true
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mosquitto-data
  namespace: $NAMESPACE
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: microk8s-hostpath
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mosquitto
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mosquitto
  template:
    metadata:
      labels:
        app: mosquitto
    spec:
      containers:
      - name: mosquitto
        image: eclipse-mosquitto:2.0
        ports:
        - containerPort: 1883
        - containerPort: 9001
        volumeMounts:
        - name: config
          mountPath: /mosquitto/config
        - name: data
          mountPath: /mosquitto/data
      volumes:
      - name: config
        configMap:
          name: mosquitto-config
      - name: data
        persistentVolumeClaim:
          claimName: mosquitto-data
---
apiVersion: v1
kind: Service
metadata:
  name: mosquitto
  namespace: $NAMESPACE
spec:
  type: NodePort
  selector:
    app: mosquitto
  ports:
  - name: mqtt
    port: 1883
    targetPort: 1883
    nodePort: 31883
  - name: websocket
    port: 9001
    targetPort: 9001
    nodePort: 31901
EOF

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
$MK8S kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: grafana-datasource
  namespace: $NAMESPACE
stringData:
  datasources.yaml: |
    apiVersion: 1
    datasources:
    - name: IoT Postgres
      type: postgres
      url: rdbms-postgresql.$NAMESPACE.svc.cluster.local:5432
      database: $POSTGRES_DB
      user: $POSTGRES_USER
      secureJsonData:
        password: "$POSTGRES_PASS"
      jsonData:
        sslmode: disable
        postgresVersion: 1500
EOF

echo -e "\n${GREEN}[6/10] Deploying Grafana...${NC}"
# grafana.ini with dotted section names (auth.generic_oauth) is unparseable by the chart
# template when passed via --set or values files. Use GF_* env vars instead — fully
# equivalent and supported by the chart's env: map.
# The datasource secret is mounted via extraSecretMounts into the provisioning directory.
_GF_VALUES=$(mktemp /tmp/grafana-values-XXXXXX.yaml)
cat > "$_GF_VALUES" <<EOF
env:
  GF_SERVER_ROOT_URL: "https://$GRAFANA_DOMAIN"
  GF_AUTH_GENERIC_OAUTH_ENABLED: "true"
  GF_AUTH_GENERIC_OAUTH_NAME: "Keycloak"
  GF_AUTH_GENERIC_OAUTH_CLIENT_ID: "grafana"
  GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: "$GRAFANA_OAUTH_SECRET"
  GF_AUTH_GENERIC_OAUTH_SCOPES: "openid profile email roles"
  GF_AUTH_GENERIC_OAUTH_AUTH_URL: "https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM/protocol/openid-connect/auth"
  GF_AUTH_GENERIC_OAUTH_TOKEN_URL: "http://keycloak.$NAMESPACE.svc.cluster.local/realms/$KEYCLOAK_REALM/protocol/openid-connect/token"
  GF_AUTH_GENERIC_OAUTH_API_URL: "http://keycloak.$NAMESPACE.svc.cluster.local/realms/$KEYCLOAK_REALM/protocol/openid-connect/userinfo"
  GF_AUTH_GENERIC_OAUTH_TLS_SKIP_VERIFY_INSECURE: "false"
  GF_AUTH_GENERIC_OAUTH_SKIP_ORG_ROLE_SYNC: "false"
  GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: "contains(roles[*], 'grafana_admin') && 'Admin' || contains(roles[*], 'grafana_developer') && 'Editor' || 'Viewer'"
extraSecretMounts:
- name: datasource-secret
  secretName: grafana-datasource
  defaultMode: 0440
  mountPath: /etc/grafana/provisioning/datasources
  readOnly: true
EOF
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
cat > "$_OP2_VALUES" <<EOF
configuration:
  content: |
    provider = "oidc"
    provider_display_name = "Keycloak"
    email_domains = ["*"]
    # The connection is TLS now, so the session cookie must not travel over
    # plain HTTP. Left false, a downgrade to http would still carry the cookie.
    cookie_secure = true
    # Discovery is fetched from the issuer above, which our own CA signs. The
    # proxy runs in-cluster on a private network talking to our own Keycloak;
    # trusting that specific chain is what this allows, not the open internet.
    ssl_insecure_skip_verify = true
    # Without these two, a session outlives Keycloak entirely: the cookie
    # defaults to 168h and cookie_refresh defaults to disabled, so oauth2-proxy
    # never asks Keycloak whether the session still exists. Signing out, an
    # admin killing the session, or disabling the user would all have no effect
    # for up to a week.
    #
    # cookie_refresh makes the proxy re-check with Keycloak on this cadence,
    # using the refresh token — if the SSO session is gone the refresh fails and
    # the user is bounced to the login page. Keep it below Keycloak's access
    # token lifespan (5 min by default). cookie_expire is the hard ceiling and
    # should not exceed the realm's SSO Session Max.
    cookie_refresh = "4m"
    cookie_expire = "8h"
    skip_provider_button = false
    skip_oidc_discovery = true
    login_url = "https://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth"
    redeem_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
    oidc_jwks_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
    profile_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
    upstreams = ["http://node-red.${NAMESPACE}.svc.cluster.local:1880"]
EOF
$MK8S helm3 upgrade --install oauth2-proxy \
  oci://registry-1.docker.io/bitnamicharts/oauth2-proxy \
  --version 8.0.2 \
  --namespace "$NAMESPACE" \
  --values "$_OP2_VALUES" \
  --set image.registry=quay.io \
  --set image.repository=oauth2-proxy/oauth2-proxy \
  --set image.tag=v7.6.0 \
  --set global.security.allowInsecureImages=true \
  --set redis.enabled=false \
  --set configuration.clientID="node-red" \
  --set configuration.clientSecret="$OAUTH2_PROXY_SECRET" \
  --set configuration.cookieSecret="$OAUTH2_COOKIE_SECRET" \
  --set configuration.oidcIssuerUrl="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" \
  --set ingress.enabled=true \
  --set ingress.hostname="$NODE_RED_DOMAIN" \
  --set "ingress.extraTls[0].hosts[0]=$NODE_RED_DOMAIN" \
  --set "ingress.extraTls[0].secretName=cea-tls" \
  --set "ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffer-size=16k" \
  --set-string "ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffers-number=4" \
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
$MK8S kubectl apply -n "$NAMESPACE" -f - <<EOF
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: pgadmin-servers
  namespace: $NAMESPACE
data:
  servers.json: |
    {
      "Servers": {
        "1": {
          "Name": "IoT Postgres",
          "Group": "MedCEA",
          "Host": "rdbms-postgresql.$NAMESPACE.svc.cluster.local",
          "Port": 5432,
          "MaintenanceDB": "$POSTGRES_DB",
          "Username": "$POSTGRES_USER",
          "PassFile": "/pgpassfile",
          "SSLMode": "disable"
        }
      }
    }
---
apiVersion: v1
kind: Secret
metadata:
  name: pgadmin-pgpassfile
  namespace: $NAMESPACE
stringData:
  pgpassfile: "rdbms-postgresql.$NAMESPACE.svc.cluster.local:5432:*:$POSTGRES_USER:$POSTGRES_PASS"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pgadmin
  namespace: $NAMESPACE
  labels:
    app: pgadmin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pgadmin
  template:
    metadata:
      labels:
        app: pgadmin
    spec:
      initContainers:
      - name: fix-pgpassfile-perms
        image: busybox:1.36
        command: ["sh", "-c", "cp /pgpassfile-src/pgpassfile /pgpassfile-rw/pgpassfile && chmod 0600 /pgpassfile-rw/pgpassfile"]
        volumeMounts:
        - name: pgpassfile-src
          mountPath: /pgpassfile-src
        - name: pgpassfile-rw
          mountPath: /pgpassfile-rw
      containers:
      - name: pgadmin
        image: dpage/pgadmin4:9
        env:
        - name: PGADMIN_DEFAULT_EMAIL
          value: "${ADMIN_USER}@cea.com"
        - name: PGADMIN_DEFAULT_PASSWORD
          value: "$ADMIN_PASS"
        - name: PGADMIN_SERVER_JSON_FILE
          value: "/pgadmin4/servers.json"
        - name: PGPASSFILE
          value: "/pgpassfile"
        ports:
        - containerPort: 80
          name: http
        readinessProbe:
          httpGet:
            path: /misc/ping
            port: 80
          initialDelaySeconds: 20
          periodSeconds: 10
          failureThreshold: 6
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: servers-config
          mountPath: /pgadmin4/servers.json
          subPath: servers.json
        - name: pgpassfile-rw
          mountPath: /pgpassfile
          subPath: pgpassfile
      volumes:
      - name: servers-config
        configMap:
          name: pgadmin-servers
      - name: pgpassfile-src
        secret:
          secretName: pgadmin-pgpassfile
      - name: pgpassfile-rw
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: pgadmin
  namespace: $NAMESPACE
spec:
  selector:
    app: pgadmin
  ports:
  - name: http
    port: 80
    targetPort: 80
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pgadmin
  namespace: $NAMESPACE
spec:
  # TLS from the platform CA. Adding this also makes nginx-ingress redirect
  # plain HTTP here with a 308, which is why every registered redirect URI had
  # to move to https in the same change.
  tls:
  - hosts: [$PGADMIN_DOMAIN]
    secretName: cea-tls
  ingressClassName: nginx
  rules:
  - host: $PGADMIN_DOMAIN
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: pgadmin
            port:
              number: 80
EOF

$MK8S kubectl rollout status deployment/pgadmin \
  -n "$NAMESPACE" --timeout=5m

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
$MK8S kubectl apply -n "$NAMESPACE" -f - <<EOF
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: portal-html
  namespace: $NAMESPACE
data:
  index.html: |
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>MedCEA Platform</title>
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { min-height: 100vh; background: #0d1321; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; -webkit-font-smoothing: antialiased; }
        #bg { position: fixed; inset: 0; z-index: 0; opacity: .22; background-size: cover; background-position: center; pointer-events: none; }
        #app { position: relative; z-index: 1; min-height: 100vh; }
        .view { display: none; }
        .view.active { display: block; }
        .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 72px 24px 48px; position: relative; }
        .hdr-btns { position: absolute; top: 20px; right: 20px; display: flex; gap: 10px; }
        .btn { display: inline-flex; align-items: center; gap: 7px; background: #1e293b; border: 1px solid #2a364e; color: #94a3b8; padding: 8px 16px; border-radius: 8px; cursor: pointer; font: 500 .875rem 'Segoe UI',system-ui,sans-serif; text-decoration: none; transition: background .15s, color .15s; }
        .btn:hover { background: #2a364e; color: #e2e8f0; }
        .ph { text-align: center; margin-bottom: 60px; }
        .ph-title { font-size: clamp(1.6rem,4vw,2.1rem); font-weight: 700; color: #fff; display: flex; align-items: center; justify-content: center; gap: 14px; letter-spacing: -.02em; }
        .ph-sub { margin-top: 10px; font-size: .9rem; color: #94a3b8; }
        .grid { width: 100%; max-width: 1100px; display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 22px; }
        .card { background: #1e2532; border: 1px solid #2a364e; border-radius: 12px; padding: 26px; text-decoration: none; color: inherit; display: flex; flex-direction: column; cursor: pointer; transition: border-color .25s, background .25s, box-shadow .25s, transform .2s; box-shadow: 0 4px 24px rgba(0,0,0,.4); }
        .card:hover { border-color: rgba(59,130,246,.5); background: #232d3d; box-shadow: 0 8px 32px rgba(30,60,120,.2); transform: translateY(-2px); }
        .card-dis { cursor: default; opacity: .5; pointer-events: none; }
        .ci { margin-bottom: 14px; }
        .ci svg { width: 38px; height: 38px; }
        .cl { font-size: .68rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: #475569; margin-bottom: 7px; }
        .ct { font-size: 1.15rem; font-weight: 600; color: #fff; margin-bottom: 10px; }
        .cd { font-size: .875rem; color: #94a3b8; line-height: 1.6; flex: 1; margin-bottom: 18px; }
        .ck { font-size: .78rem; color: #60a5fa; display: flex; align-items: center; gap: 4px; margin-top: auto; }
        .card:hover .ck { color: #93c5fd; }
        .ck-a { opacity: 0; transform: translateX(-4px); transition: opacity .2s, transform .2s; }
        .card:hover .ck-a { opacity: 1; transform: none; }
        .pfooter { margin-top: 72px; text-align: center; font-size: .75rem; color: #334155; display: flex; flex-direction: column; align-items: center; gap: 14px; }
        .iscte-lbl { font-size: .68rem; font-weight: 700; text-transform: uppercase; letter-spacing: .1em; color: #94a3b8; margin-bottom: 8px; }
        .iscte-w { background: #fff; padding: 10px 16px; border-radius: 10px; display: inline-block; transition: transform .2s; }
        .iscte-w:hover { transform: scale(1.05); }
        .iscte-w img { height: 34px; display: block; }
      </style>
    </head>
    <body>
      <div id="bg" style="${_PORTAL_BG_STYLE}"></div>
      <div id="app">
        <!-- MAIN PORTAL -->
        <div id="v-portal" class="view active">
          <div class="page">
            <div class="hdr-btns">
              <a href="/oauth2/sign_out?rd=${_PORTAL_LOGOUT_RD}" class="btn">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
                Sign Out
              </a>
            </div>
            <div class="ph">
              <h1 class="ph-title">
                <svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" style="width:54px;height:54px">
                  <path d="M2 21h20" stroke="#cbd5e1" stroke-width="1.5"/><path d="M4 21V8l4 3V8l4 3v9" stroke="#cbd5e1" stroke-width="1.5"/>
                  <path d="M6 18h2M10 18h2" stroke="#cbd5e1" stroke-width="1.5"/>
                  <path d="M18.5 21v-4" stroke="#fbbf24" stroke-width="2"/>
                  <path d="M15.5 17c0-3 6-3 6 0H15.5z" stroke="#fbbf24" stroke-width="1.5" fill="#fbbf24" fill-opacity=".2"/>
                  <path d="M14 21v-6c0-1.5-1-2.5-2.5-2.5" stroke="#4ade80" stroke-width="1.5"/>
                  <path d="M11.5 12.5c-1.5-1.5-3.5-.5-3.5 1.5s2 1.5 3.5.5Z" stroke="#4ade80" stroke-width="1.5" fill="#4ade80" fill-opacity=".2"/>
                  <path d="M11.5 12.5c0-1.5 1.5-2.5 2.5-1.5" stroke="#4ade80" stroke-width="1.5"/>
                </svg>
                MedCEA Platform
              </h1>
              <p class="ph-sub">Connected Environments &amp; Analytics &mdash; Service Catalog</p>
            </div>
            <div class="grid">
              <a class="card" href="https://$GRAFANA_DOMAIN" target="_blank" rel="noopener">
                <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/></svg></div>
                <div class="cl">Grafana</div><div class="ct">MedCEA Dashboard</div>
                <div class="cd">Visualize IoT sensor data, telemetry metrics, and analytics in real time.</div>
                <div class="ck">https://$GRAFANA_DOMAIN <span class="ck-a">&rarr;</span></div>
              </a>
              <a class="card" href="https://$WORKBENCH_DOMAIN" target="_blank" rel="noopener">
                <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#c084fc" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4.5a2.5 2.5 0 0 0-4.96-.46 2.5 2.5 0 0 0-1.98 3 2.5 2.5 0 0 0-1.32 4.24 3 3 0 0 0 .34 5.58 2.5 2.5 0 0 0 2.96 3.08 2.5 2.5 0 0 0 4.91.05L12 20V4.5Z"/><path d="M16 8V5c0-1.1.9-2 2-2"/><path d="M12 13h4"/><path d="M12 18h6a2 2 0 0 1 2 2v1"/><path d="M12 8h8"/><circle cx="20.5" cy="8" r=".5" fill="#c084fc"/><circle cx="16.5" cy="13" r=".5" fill="#c084fc"/><circle cx="20.5" cy="21" r=".5" fill="#c084fc"/><circle cx="18.5" cy="3" r=".5" fill="#c084fc"/></svg></div>
                <div class="cl">JupyterHub</div><div class="ct">AI Workbench</div>
                <div class="cd">Notebooks and VS Code on your IoT data. Sign in with your platform account; each user gets their own workspace.</div>
                <div class="ck">https://$WORKBENCH_DOMAIN <span class="ck-a">&rarr;</span></div>
              </a>
              <div class="card" onclick="show('management')">
                <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#cbd5e1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 7h-9"/><path d="M14 17H5"/><circle cx="17" cy="17" r="3"/><circle cx="7" cy="7" r="3"/></svg></div>
                <div class="cl">Administration</div><div class="ct">Platform Management</div>
                <div class="cd">Access backend services, database, system configuration, and recipe management.</div>
                <div class="ck">Open <span class="ck-a">&rarr;</span></div>
              </div>
            </div>
            <div class="pfooter">
              <p>MedCEA &mdash; Powered by Keycloak, JupyterHub &amp; MicroK8s</p>
              <div>
                <p class="iscte-lbl">Developed by</p>
                <a href="https://ciencia.iscte-iul.pt/centres/it-iul/groups/research-group-38" target="_blank" rel="noopener" class="iscte-w">
                  <img src="https://gci.iscte-iul.pt/2022/identidade/files/brand_v2/escolas/rgb/ista/en/small/horizontal/main/rgb_ista_en_small_horizontal_main.svg" alt="ISCTE-IUL" onerror="this.outerHTML='<span style=color:#1e293b;font-weight:700;padding:0 8px>ISCTE-IUL</span>'">
                </a>
              </div>
            </div>
          </div>
        </div>
        <!-- MANAGEMENT SUB-PORTAL -->
        <div id="v-management" class="view">
          <div class="page">
            <div class="hdr-btns">
              <button class="btn" onclick="show('portal')">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 19-7-7 7-7"/><path d="M19 12H5"/></svg>
                Back
              </button>
              <a href="/oauth2/sign_out?rd=${_PORTAL_LOGOUT_RD}" class="btn">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
                Sign Out
              </a>
            </div>
            <div class="ph">
              <h1 class="ph-title">
                <svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" style="width:46px;height:46px">
                  <path d="M2 21h20" stroke="#cbd5e1" stroke-width="1.5"/><path d="M4 21V8l4 3V8l4 3v9" stroke="#cbd5e1" stroke-width="1.5"/>
                  <path d="M6 18h2M10 18h2" stroke="#cbd5e1" stroke-width="1.5"/>
                  <path d="M18.5 21v-4" stroke="#fbbf24" stroke-width="2"/>
                  <path d="M15.5 17c0-3 6-3 6 0H15.5z" stroke="#fbbf24" stroke-width="1.5" fill="#fbbf24" fill-opacity=".2"/>
                  <path d="M14 21v-6c0-1.5-1-2.5-2.5-2.5" stroke="#4ade80" stroke-width="1.5"/>
                  <path d="M11.5 12.5c-1.5-1.5-3.5-.5-3.5 1.5s2 1.5 3.5.5Z" stroke="#4ade80" stroke-width="1.5" fill="#4ade80" fill-opacity=".2"/>
                  <path d="M11.5 12.5c0-1.5 1.5-2.5 2.5-1.5" stroke="#4ade80" stroke-width="1.5"/>
                </svg>
                Platform Management
              </h1>
              <p class="ph-sub">Administration, Database, and System Configuration</p>
            </div>
            <div class="grid">
              <a class="card" href="https://$NODE_RED_DOMAIN" target="_blank" rel="noopener">
                <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="8" x="3" y="3" rx="2"/><path d="M7 11v4a2 2 0 0 0 2 2h4"/><rect width="8" height="8" x="13" y="13" rx="2"/></svg></div>
                <div class="cl">Node-RED</div><div class="ct">Data Flow</div>
                <div class="cd">Build and manage data flows connecting sensors, APIs, and MQTT services.</div>
                <div class="ck">https://$NODE_RED_DOMAIN <span class="ck-a">&rarr;</span></div>
              </a>
              <a class="card" href="https://$DBMGMT_DOMAIN" target="_blank" rel="noopener">
                <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3"/></svg></div>
                <div class="cl">Database</div><div class="ct">Management</div>
                <div class="cd">Explore and manage the database, export DDL and data for medcea schema objects.</div>
                <div class="ck">https://$DBMGMT_DOMAIN <span class="ck-a">&rarr;</span></div>
              </a>
              <a class="card" href="https://$MQTTX_DOMAIN" target="_blank" rel="noopener">
                <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#2dd4bf" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.4"/><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.4"/><path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/></svg></div>
                <div class="cl">MQTT Explorer</div><div class="ct">MQTT Explorer</div>
                <div class="cd">Browse, publish and subscribe to MQTT topics on Mosquitto.</div>
                <div class="ck">https://$MQTTX_DOMAIN <span class="ck-a">&rarr;</span></div>
              </a>
              <a class="card" href="https://$CONFIG_DOMAIN" target="_blank" rel="noopener">
                <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#fb923c" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" x2="4" y1="21" y2="14"/><line x1="4" x2="4" y1="10" y2="3"/><line x1="12" x2="12" y1="21" y2="12"/><line x1="12" x2="12" y1="8" y2="3"/><line x1="20" x2="20" y1="21" y2="16"/><line x1="20" x2="20" y1="12" y2="3"/><line x1="2" x2="6" y1="14" y2="14"/><line x1="10" x2="14" y1="8" y2="8"/><line x1="18" x2="22" y1="16" y2="16"/></svg></div>
                <div class="cl">Configuration</div><div class="ct">System Configuration</div>
                <div class="cd">Manage production units, add and update recipes, and oversee device management.</div>
                <div class="ck">https://$CONFIG_DOMAIN <span class="ck-a">&rarr;</span></div>
              </a>
              <a class="card" href="https://$SCHEDULER_DOMAIN" target="_blank" rel="noopener">
                <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h3.5"/><path d="M16 2v4M8 2v4M3 10h5"/><path d="M17.5 17.5 16 16.3V14"/><circle cx="16" cy="16" r="6"/></svg></div>
                <div class="cl">Scheduling</div><div class="ct">Recipe Schedule Manager</div>
                <div class="cd">Schedule and manage recipe execution timelines across production units.</div>
                <div class="ck">https://$SCHEDULER_DOMAIN <span class="ck-a">&rarr;</span></div>
              </a>
            </div>
            <div class="pfooter">
              <p>MedCEA &mdash; Powered by Keycloak, JupyterHub &amp; MicroK8s</p>
            </div>
          </div>
        </div>
      </div>
      <script>
        function show(v) {
          document.querySelectorAll('.view').forEach(function(el) { el.classList.remove('active'); });
          document.getElementById('v-' + v).classList.add('active');
          window.scrollTo(0, 0);
        }
      </script>
    </body>
    </html>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: portal
  namespace: $NAMESPACE
  labels:
    app: portal
spec:
  replicas: 1
  selector:
    matchLabels:
      app: portal
  template:
    metadata:
      labels:
        app: portal
    spec:
      containers:
      - name: nginx
        image: nginx:1.27-alpine
        ports:
        - containerPort: 80
          name: http
        readinessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "32Mi"
            cpu: "50m"
          limits:
            memory: "64Mi"
            cpu: "200m"
        volumeMounts:
        - name: html
          mountPath: /usr/share/nginx/html/index.html
          subPath: index.html
      volumes:
      - name: html
        configMap:
          name: portal-html
---
apiVersion: v1
kind: Service
metadata:
  name: portal
  namespace: $NAMESPACE
spec:
  selector:
    app: portal
  ports:
  - name: http
    port: 80
    targetPort: 80
  type: ClusterIP
EOF

# The HTML is mounted with subPath, and a subPath ConfigMap mount does NOT
# update in a running pod — kubelet only refreshes whole-directory mounts. So an
# unchanged Deployment spec means a changed ConfigMap is simply never picked up,
# and the pod keeps serving the previous page indefinitely. Force the roll.
$MK8S kubectl rollout restart deployment/portal -n "$NAMESPACE"
$MK8S kubectl rollout status deployment/portal \
  -n "$NAMESPACE" --timeout=3m

# Portal OAuth2 Proxy (Keycloak client: portal)
_POP2_VALUES=$(mktemp /tmp/portal-oauth2proxy-values-XXXXXX.yaml)
cat > "$_POP2_VALUES" <<VALEOF
configuration:
  content: |
    provider = "oidc"
    provider_display_name = "Keycloak"
    email_domains = ["*"]
    # The connection is TLS now, so the session cookie must not travel over
    # plain HTTP. Left false, a downgrade to http would still carry the cookie.
    cookie_secure = true
    # Discovery is fetched from the issuer above, which our own CA signs. The
    # proxy runs in-cluster on a private network talking to our own Keycloak;
    # trusting that specific chain is what this allows, not the open internet.
    ssl_insecure_skip_verify = true
    # Without these two, a session outlives Keycloak entirely: the cookie
    # defaults to 168h and cookie_refresh defaults to disabled, so oauth2-proxy
    # never asks Keycloak whether the session still exists. Signing out, an
    # admin killing the session, or disabling the user would all have no effect
    # for up to a week.
    #
    # cookie_refresh makes the proxy re-check with Keycloak on this cadence,
    # using the refresh token — if the SSO session is gone the refresh fails and
    # the user is bounced to the login page. Keep it below Keycloak's access
    # token lifespan (5 min by default). cookie_expire is the hard ceiling and
    # should not exceed the realm's SSO Session Max.
    cookie_refresh = "4m"
    cookie_expire = "8h"
    skip_provider_button = false
    skip_oidc_discovery = true
    login_url = "https://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth"
    redeem_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
    oidc_jwks_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
    profile_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
    upstreams = ["http://portal.${NAMESPACE}.svc.cluster.local:80"]
VALEOF
$MK8S helm3 upgrade --install portal-oauth2-proxy \
  oci://registry-1.docker.io/bitnamicharts/oauth2-proxy \
  --version 8.0.2 \
  --namespace "$NAMESPACE" \
  --values "$_POP2_VALUES" \
  --set image.registry=quay.io \
  --set image.repository=oauth2-proxy/oauth2-proxy \
  --set image.tag=v7.6.0 \
  --set global.security.allowInsecureImages=true \
  --set redis.enabled=false \
  --set configuration.clientID="portal" \
  --set configuration.clientSecret="$PORTAL_OAUTH2_PROXY_SECRET" \
  --set configuration.cookieSecret="$PORTAL_COOKIE_SECRET" \
  --set configuration.oidcIssuerUrl="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" \
  --set "extraArgs[0]=--whitelist-domain=$KEYCLOAK_DOMAIN" \
  --set ingress.enabled=true \
  --set ingress.hostname="$PORTAL_DOMAIN" \
  --set "ingress.extraTls[0].hosts[0]=$PORTAL_DOMAIN" \
  --set "ingress.extraTls[0].secretName=cea-tls" \
  --set "ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffer-size=16k" \
  --set-string "ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffers-number=4" \
  --timeout 5m
rm -f "$_POP2_VALUES"

$MK8S kubectl rollout restart deployment/portal-oauth2-proxy -n "$NAMESPACE"

# Redirect bare domain ($DOMAIN with no subdomain) to the portal so visitors
# don't see a raw nginx 404. Requires its own ingress because nginx-ingress
# matches by Host header — there's no implicit fallback.
$MK8S kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bare-domain-redirect
  namespace: $NAMESPACE
  annotations:
    nginx.ingress.kubernetes.io/permanent-redirect: https://${PORTAL_DOMAIN}/
    nginx.ingress.kubernetes.io/permanent-redirect-code: "302"
spec:
  # TLS from the platform CA. Adding this also makes nginx-ingress redirect
  # plain HTTP here with a 308, which is why every registered redirect URI had
  # to move to https in the same change.
  tls:
  - hosts: [${DOMAIN}]
    secretName: cea-tls
  ingressClassName: public
  rules:
  - host: ${DOMAIN}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: portal
            port:
              number: 80
EOF

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

# Tailscale IP is stable (assigned by Tailscale, not the home router).
# Derive it from DOMAIN instead of running tailscale at this point.
_TAILSCALE_IP="${DOMAIN%.nip.io}"

# Write HTML to temp file using single-quote heredoc (no shell expansion),
# then substitute the Tailscale IP placeholder with sed.
cat > /tmp/mqtt-explorer.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MQTT Explorer</title>
  <script src="https://cdn.jsdelivr.net/npm/mqtt@4.3.7/dist/mqtt.min.js"></script>
  <style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
header { background: #1e293b; border-bottom: 1px solid #334155; padding: 10px 20px; display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
header h1 { font-size: 1rem; font-weight: 600; color: #f1f5f9; }
#st { font-size: 0.78rem; padding: 3px 10px; border-radius: 10px; background: #334155; color: #94a3b8; }
#st.ok { background: #064e3b; color: #34d399; }
#st.err { background: #7f1d1d; color: #f87171; }
.broker { font-size: 0.75rem; color: #475569; margin-left: auto; }
.main { display: flex; flex: 1; overflow: hidden; }
.topics { width: 280px; min-width: 180px; border-right: 1px solid #334155; overflow-y: auto; padding: 10px; flex-shrink: 0; }
.topics h2 { font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #64748b; margin-bottom: 8px; }
.tr { padding: 5px 8px; border-radius: 6px; cursor: pointer; margin-bottom: 2px; border: 1px solid transparent; }
.tr:hover { background: #1e293b; }
.tr.active { background: #1e293b; border-color: #334155; }
.tn { font-size: 0.78rem; color: #38bdf8; word-break: break-all; }
.tv { font-size: 0.7rem; color: #94a3b8; margin-top: 1px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 230px; }
.detail { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.msgs { flex: 1; overflow-y: auto; padding: 12px; }
.msgs h2 { font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #64748b; margin-bottom: 8px; }
.msg { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 8px 12px; margin-bottom: 6px; }
.mt { font-size: 0.7rem; color: #38bdf8; margin-bottom: 2px; }
.mp { font-size: 0.82rem; color: #e2e8f0; word-break: break-all; white-space: pre-wrap; }
.ms { font-size: 0.68rem; color: #475569; margin-top: 2px; }
.pub { background: #1e293b; border-top: 1px solid #334155; padding: 12px; display: flex; flex-direction: column; gap: 6px; flex-shrink: 0; }
.pub h2 { font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #64748b; }
.pr { display: flex; gap: 8px; }
input, textarea { background: #0f172a; border: 1px solid #334155; color: #e2e8f0; border-radius: 6px; padding: 6px 10px; font-size: 0.82rem; width: 100%; font-family: inherit; }
input:focus, textarea:focus { outline: none; border-color: #38bdf8; }
textarea { height: 48px; resize: none; }
button { background: #0ea5e9; color: #fff; border: none; border-radius: 6px; padding: 6px 14px; cursor: pointer; font-size: 0.82rem; font-weight: 600; white-space: nowrap; }
button:hover { background: #38bdf8; }
button:disabled { background: #334155; color: #64748b; cursor: default; }
.empty { color: #475569; font-size: 0.82rem; font-style: italic; }
  </style>
</head>
<body>
  <header>
    <h1>&#128225; MQTT Explorer</h1>
    <span id="st">Connecting&hellip;</span>
    <span class="broker">ws://__WS_HOST__:31901</span>
  </header>
  <div class="main">
    <div class="topics">
      <h2>Topics (<span id="tc">0</span>)</h2>
      <div id="tl"></div>
    </div>
    <div class="detail">
      <div class="msgs">
        <h2>Messages</h2>
        <div id="ml"><p class="empty">Select a topic to see messages</p></div>
      </div>
      <div class="pub">
        <h2>Publish</h2>
        <div class="pr">
          <input id="pt" type="text" placeholder="topic/path">
          <button id="pb" onclick="pub()" disabled>Send</button>
        </div>
        <textarea id="pp" placeholder="payload (text or JSON)"></textarea>
      </div>
    </div>
  </div>
<script>
var WS = 'ws://__WS_HOST__:31901/mqtt';
var MAX = 100;
var topics = {};
var sel = null;
var cli = null;
var st = document.getElementById('st');
var tl = document.getElementById('tl');
var tc = document.getElementById('tc');
var ml = document.getElementById('ml');
var pb = document.getElementById('pb');

function connect() {
  cli = mqtt.connect(WS, { clientId: 'explorer-' + Math.random().toString(16).slice(2, 8), reconnectPeriod: 3000 });
  cli.on('connect', function() { st.textContent = 'Connected'; st.className = 'ok'; pb.disabled = false; cli.subscribe('#'); });
  cli.on('offline', function() { st.textContent = 'Reconnecting\u2026'; st.className = ''; pb.disabled = true; });
  cli.on('error', function() { st.textContent = 'Error'; st.className = 'err'; });
  cli.on('message', function(topic, payload) {
    var v = payload.toString();
    var t = new Date().toLocaleTimeString();
    if (!topics[topic]) topics[topic] = { v: v, t: t, msgs: [] };
    else { topics[topic].v = v; topics[topic].t = t; }
    topics[topic].msgs.unshift({ v: v, t: t });
    if (topics[topic].msgs.length > MAX) topics[topic].msgs.pop();
    renderTopics();
    if (sel === topic) renderMsgs(topic);
  });
}

function renderTopics() {
  tc.textContent = Object.keys(topics).length;
  tl.innerHTML = Object.keys(topics).sort().map(function(k) {
    return '<div class="tr' + (k === sel ? ' active' : '') + '" onclick="pick(\'' + k.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + '\')">'
      + '<div class="tn">' + esc(k) + '</div>'
      + '<div class="tv">' + esc(topics[k].v) + '</div>'
      + '</div>';
  }).join('');
}

function pick(topic) {
  sel = topic;
  document.getElementById('pt').value = topic;
  renderTopics();
  renderMsgs(topic);
}

function renderMsgs(topic) {
  var msgs = (topics[topic] || {}).msgs || [];
  if (!msgs.length) { ml.innerHTML = '<p class="empty">No messages yet</p>'; return; }
  ml.innerHTML = msgs.map(function(m) {
    return '<div class="msg"><div class="mt">' + esc(topic) + '</div>'
      + '<div class="mp">' + esc(m.v) + '</div>'
      + '<div class="ms">' + m.t + '</div></div>';
  }).join('');
}

function pub() {
  var topic = document.getElementById('pt').value.trim();
  var payload = document.getElementById('pp').value;
  if (topic && cli) cli.publish(topic, payload);
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

connect();
</script>
</body>
</html>
HTMLEOF

sed -i "s|__WS_HOST__|${_TAILSCALE_IP}|g" /tmp/mqtt-explorer.html

# Clean up old mqttx-web resources from previous deploy (renamed to mqtt-explorer)
$MK8S kubectl delete deployment/mqttx-web service/mqttx-web ingress/mqttx-web \
  -n "$NAMESPACE" 2>/dev/null || true

$MK8S kubectl create configmap mqtt-explorer-html \
  -n "$NAMESPACE" \
  --from-file=index.html=/tmp/mqtt-explorer.html \
  --dry-run=client -o yaml | $MK8S kubectl apply -f -
rm -f /tmp/mqtt-explorer.html

$MK8S kubectl apply -n "$NAMESPACE" -f - <<EOF
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mqtt-explorer
  namespace: $NAMESPACE
  labels:
    app: mqtt-explorer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mqtt-explorer
  template:
    metadata:
      labels:
        app: mqtt-explorer
    spec:
      containers:
      - name: nginx
        image: nginx:1.27-alpine
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "32Mi"
            cpu: "50m"
          limits:
            memory: "64Mi"
            cpu: "200m"
        volumeMounts:
        - name: html
          mountPath: /usr/share/nginx/html/index.html
          subPath: index.html
      volumes:
      - name: html
        configMap:
          name: mqtt-explorer-html
---
apiVersion: v1
kind: Service
metadata:
  name: mqtt-explorer
  namespace: $NAMESPACE
spec:
  selector:
    app: mqtt-explorer
  ports:
  - name: http
    port: 80
    targetPort: 80
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mqtt-explorer
  namespace: $NAMESPACE
spec:
  # TLS from the platform CA. Adding this also makes nginx-ingress redirect
  # plain HTTP here with a 308, which is why every registered redirect URI had
  # to move to https in the same change.
  tls:
  - hosts: [$MQTTX_DOMAIN]
    secretName: cea-tls
  ingressClassName: nginx
  rules:
  - host: $MQTTX_DOMAIN
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: mqtt-explorer
            port:
              number: 80
EOF

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
# SUMMARY
# =============================================================================
echo -e "\n${GREEN}=================================================${NC}"
echo -e "${GREEN} SUCCESS: $NAMESPACE is live!${NC}"
echo -e "${GREEN}=================================================${NC}"
echo ""
echo -e "${GREEN}  START HERE${NC}"
echo -e "${GREEN}  ----------${NC}"
echo -e "  Service Portal:  https://$PORTAL_DOMAIN"
echo -e "    Login:         Keycloak SSO ($ADMIN_USER / $ADMIN_PASS)"
echo -e "    Shows:         Grafana · Node-RED · Kubeflow · pgAdmin · MQTTX Web"
echo ""
echo -e "${GREEN}  DIRECT SERVICE ACCESS${NC}"
echo -e "${GREEN}  ---------------------${NC}"
echo -e "  Grafana:         https://$GRAFANA_DOMAIN"
echo -e "    SSO:           $_GF_ADMIN_USER / $_GF_ADMIN_PASS  (Admin)"
echo -e "                   $_GF_DEV_USER / $_GF_DEV_PASS      (Editor)"
echo -e "                   $_GF_VIEW_USER / $_GF_VIEW_PASS    (Viewer)"
echo ""
echo -e "  Node-RED:        https://$NODE_RED_DOMAIN"
echo -e "    SSO:           $ADMIN_USER / $ADMIN_PASS"
echo ""
echo -e "  AI Workbench:    https://$WORKBENCH_DOMAIN   (JupyterHub — sign in with Keycloak)"
echo -e "    SSO:           $ADMIN_USER / $ADMIN_PASS"
echo -e "    Note:          First login — enter a profile namespace name (e.g. 'admin')"
echo ""
echo -e "  pgAdmin:         https://$PGADMIN_DOMAIN"
echo -e "    Login:         ${ADMIN_USER}@cea.com / $ADMIN_PASS"
echo -e "    DB:            'IoT Postgres' server pre-configured (no setup needed)"
echo ""
echo -e "${GREEN}  ADMIN${NC}"
echo -e "${GREEN}  -----${NC}"
echo -e "  Keycloak:        https://$KEYCLOAK_DOMAIN/admin"
echo -e "    Login:         $ADMIN_USER / $ADMIN_PASS"
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
