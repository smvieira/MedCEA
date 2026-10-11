#!/usr/bin/env bash
# apps/frontend/deploy.sh — Frontend deployments
#
# Deploys:
#   1. System Configuration UI (PostgREST + nginx SPA — Devices/Units/Recipes/Permissions)
#   2. Database Management portal (nginx SPA + Python export API)
#
# Idempotent: safe to re-run.


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
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"
# shellcheck source=/dev/null
source "$REPO_ROOT/infra/lib-wait.sh"

KUBECTL="microk8s kubectl"
NAMESPACE="${NAMESPACE:-medcea}"
CONFIG_DOMAIN="config.$DOMAIN"
DBMGMT_DOMAIN="${DBMGMT_DOMAIN:-dbmgmt.$DOMAIN}"
PGADMIN_URL="https://${PGADMIN_DOMAIN}"
PORTAL_URL="https://${PORTAL_DOMAIN}"

GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[frontend]${NC} $*"; }


# =============================================================================
# 1. config-api (PostgREST)
# =============================================================================
log "Deploying config-api (PostgREST)..."

$KUBECTL apply -n "$NAMESPACE" -f - <<EOF
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: config-api
  namespace: $NAMESPACE
  labels:
    app: config-api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: config-api
  template:
    metadata:
      labels:
        app: config-api
    spec:
      containers:
      - name: postgrest
        image: postgrest/postgrest:v12.2.3
        env:
        - name: PGRST_DB_URI
          value: "postgres://authenticator:$POSTGRES_PASS@rdbms-postgresql.$NAMESPACE.svc.cluster.local:5432/medcea_db"
        - name: PGRST_DB_SCHEMAS
          value: "medcea"
        - name: PGRST_DB_ANON_ROLE
          value: "anon"
        - name: PGRST_SERVER_PORT
          value: "3000"
        - name: PGRST_LOG_LEVEL
          value: "warn"
        ports:
        - containerPort: 3000
          name: http
        readinessProbe:
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: config-api
  namespace: $NAMESPACE
spec:
  selector:
    app: config-api
  ports:
  - port: 3000
    targetPort: 3000
  type: ClusterIP
EOF

# =============================================================================
# 3. config-ui nginx ConfigMap
# =============================================================================
log "Creating nginx config..."

$KUBECTL apply -n "$NAMESPACE" -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-ui-nginx
  namespace: $NAMESPACE
data:
  default.conf: |
    server {
      listen 80;
      location /api/ {
        proxy_pass http://config-api.$NAMESPACE.svc.cluster.local:3000/;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_pass_header Content-Range;
        proxy_pass_header Range;
        add_header Access-Control-Expose-Headers Content-Range;
      }
      location /scheduler-api/ {
        proxy_pass http://scheduler.$NAMESPACE.svc.cluster.local/api/;
        proxy_read_timeout 120s;
      }
      location /platform-api/ {
        proxy_pass http://localhost:8081/;
        proxy_set_header Host \$host;
      }
      location /recipes/ {
        alias /usr/share/nginx/html/recipes/;
        autoindex on;
        autoindex_format json;
        add_header Access-Control-Allow-Origin *;
      }
      location / {
        root /usr/share/nginx/html;
        index index.html;
      }
    }
EOF

# =============================================================================
# 4. config-ui HTML ConfigMap
# =============================================================================
log "Creating config UI HTML..."

# Onboarding runs on the platform host, not in the cluster: it needs the USB
# port. $DOMAIN is <tailscale-ip>.nip.io, so stripping the suffix gives the
# address a browser on the tailnet can reach the wizard daemon on.
_EDGE_WIZARD_URL="http://${DOMAIN%.nip.io}:${EDGE_WIZARD_PORT:-8088}/"
log "Onboarding wizard link: $_EDGE_WIZARD_URL"

# Full RP-initiated logout: without client_id and post_logout_redirect_uri,
# Keycloak shows a confirmation page and leaves the SSO session alive, so the
# next visit signs straight back in without asking.
_KEYCLOAK_LOGOUT_URL=$(python3 -c "
import urllib.parse, sys
inner = 'https://%s/realms/%s/protocol/openid-connect/logout?client_id=config&post_logout_redirect_uri=%s' % (
    sys.argv[1], sys.argv[2], urllib.parse.quote('https://%s/' % sys.argv[3], safe=''))
print(urllib.parse.quote(inner, safe=''))
" "$KEYCLOAK_DOMAIN" "$KEYCLOAK_REALM" "$CONFIG_DOMAIN")

sed -e "s|\$PORTAL_DOMAIN|$PORTAL_DOMAIN|g" \
    -e "s|\$EDGE_WIZARD_URL|$_EDGE_WIZARD_URL|g" \
    -e "s|\$KEYCLOAK_LOGOUT_URL|$_KEYCLOAK_LOGOUT_URL|g" "$SCRIPT_DIR/html/index.html" \
  | $KUBECTL create configmap config-ui-html -n "$NAMESPACE" \
    --from-file=index.html=/dev/stdin \
    --dry-run=client -o yaml | $KUBECTL apply -f -


# =============================================================================
# 5. Recipe file-server script ConfigMap
# =============================================================================
$KUBECTL apply -n "$NAMESPACE" -f - <<PYEOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: recipe-fileserver
  namespace: $NAMESPACE
data:
  server.py: |
    import os, json, socket, time
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from urllib.parse import unquote

    RECIPES_DIR    = '/recipes'
    DEVICES_DIR    = '/devices'
    UNITS_DIR      = '/units'
    LOCATIONS_DIR  = '/locations'

    def _resolve(path):
        """Returns (base_dir, fname_or_None, is_list)."""
        if path.startswith('/devices'):
            rest = path[len('/devices'):]
            if rest in ('', '/'):
                return DEVICES_DIR, None, True
            fname = unquote(rest.lstrip('/'))
            if '/' in fname or not fname.endswith('.json'):
                return DEVICES_DIR, None, False  # invalid
            return DEVICES_DIR, fname, False
        elif path.startswith('/locations'):
            rest = path[len('/locations'):]
            if rest in ('', '/'):
                return LOCATIONS_DIR, None, True
            fname = unquote(rest.lstrip('/'))
            if '/' in fname or not fname.endswith('.json'):
                return LOCATIONS_DIR, None, False  # invalid
            return LOCATIONS_DIR, fname, False
        elif path.startswith('/units'):
            rest = path[len('/units'):]
            if rest in ('', '/'):
                return UNITS_DIR, None, True
            fname = unquote(rest.lstrip('/'))
            if '/' in fname or not fname.endswith('.json'):
                return UNITS_DIR, None, False  # invalid
            return UNITS_DIR, fname, False
        else:
            if path.rstrip('/') == '' or path == '/':
                return RECIPES_DIR, None, True
            fname = unquote(path.lstrip('/'))
            if '/' in fname or not fname.endswith('.json'):
                return RECIPES_DIR, None, False  # invalid
            return RECIPES_DIR, fname, False

    def check_host(host, port=None, timeout=3):
        """ICMP ping via subprocess. Returns (online, latency_ms, error)."""
        import subprocess
        t0 = time.monotonic()
        try:
            r = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), host],
                capture_output=True, timeout=timeout + 1
            )
            ms = round((time.monotonic() - t0) * 1000)
            if r.returncode == 0:
                return True, ms, None
            else:
                return False, None, 'unreachable'
        except subprocess.TimeoutExpired:
            return False, None, 'timeout'
        except Exception as e:
            # Fallback: TCP connect to port 80
            try:
                sock = socket.create_connection((host, 80), timeout=timeout)
                sock.close()
                ms = round((time.monotonic() - t0) * 1000)
                return True, ms, None
            except socket.timeout:
                return False, None, 'timeout'
            except OSError as e2:
                return False, None, str(e2)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body=b'', ct='application/json'):
            self.send_response(code)
            self.send_header('Content-Type', ct)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        def do_OPTIONS(self):
            self._send(204)
        def do_GET(self):
            # Device online check: GET /check/<hostname>[/<port>]
            if self.path.startswith('/check/'):
                parts = unquote(self.path[len('/check/'):]).split('/')
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 80
                if not host:
                    self._send(400, b'{"error":"missing host"}'); return
                online, ms, err = check_host(host, port)
                result = {'online': online}
                if ms is not None: result['ms'] = ms
                if err: result['error'] = err
                self._send(200, json.dumps(result).encode())
                return
            base, fname, is_list = _resolve(self.path)
            if is_list:
                os.makedirs(base, exist_ok=True)
                files = sorted(f for f in os.listdir(base) if f.endswith('.json'))
                self._send(200, json.dumps(files).encode())
            elif not fname:
                self._send(400, b'{"error":"invalid filename"}')
            else:
                p = os.path.join(base, fname)
                if not os.path.exists(p):
                    self._send(404, b'{"error":"not found"}'); return
                with open(p, 'rb') as f:
                    self._send(200, f.read())
        def do_PUT(self):
            base, fname, _ = _resolve(self.path)
            if not fname:
                self._send(400, b'{"error":"invalid filename"}'); return
            n = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(n)
            try: json.loads(body)
            except: self._send(400, b'{"error":"invalid json"}'); return
            os.makedirs(base, exist_ok=True)
            with open(os.path.join(base, fname), 'wb') as f:
                f.write(body)
            self._send(200, b'{"ok":true}')

    HTTPServer(('', 8081), H).serve_forever()
PYEOF

# =============================================================================
# 6. config-ui Deployment + Service + Ingress
# =============================================================================
log "Deploying config-ui..."

RECIPES_HOST_PATH="$SCRIPT_DIR/recipes"
mkdir -p "$RECIPES_HOST_PATH"

$KUBECTL apply -n "$NAMESPACE" -f - <<EOF
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: config-ui
  namespace: $NAMESPACE
  labels:
    app: config-ui
spec:
  replicas: 1
  selector:
    matchLabels:
      app: config-ui
  template:
    metadata:
      labels:
        app: config-ui
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
        - name: nginx-conf
          mountPath: /etc/nginx/conf.d/default.conf
          subPath: default.conf
        - name: recipes
          mountPath: /usr/share/nginx/html/recipes
        - name: images
          mountPath: /usr/share/nginx/html/images
      - name: recipe-fileserver
        image: python:3.12-alpine
        command: ["python3", "/scripts/server.py"]
        ports:
        - containerPort: 8081
          name: fileserver
        resources:
          requests:
            memory: "32Mi"
            cpu: "20m"
          limits:
            memory: "64Mi"
            cpu: "100m"
        volumeMounts:
        - name: recipe-script
          mountPath: /scripts
        - name: recipes
          mountPath: /recipes
        - name: devices
          mountPath: /devices
        - name: units
          mountPath: /units
        - name: locations
          mountPath: /locations
      volumes:
      - name: html
        configMap:
          name: config-ui-html
      - name: nginx-conf
        configMap:
          name: config-ui-nginx
      - name: recipe-script
        configMap:
          name: recipe-fileserver
      - name: recipes
        hostPath:
          path: $RECIPES_HOST_PATH
          type: DirectoryOrCreate
      - name: devices
        hostPath:
          path: $SCRIPT_DIR/devices
          type: DirectoryOrCreate
      - name: units
        hostPath:
          path: $SCRIPT_DIR/units
          type: DirectoryOrCreate
      - name: locations
        hostPath:
          path: $SCRIPT_DIR/locations
          type: DirectoryOrCreate
      - name: images
        hostPath:
          path: $SCRIPT_DIR/images
          type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: config-ui
  namespace: $NAMESPACE
spec:
  selector:
    app: config-ui
  ports:
  - port: 80
    targetPort: 80
  type: ClusterIP
---
EOF

# =============================================================================
# 6b. Config UI authentication
# =============================================================================
# $CONFIG_DOMAIN used to be served by a plain Ingress with no authentication at
# all — the whole device inventory, every recipe, and the onboarding entry point
# were readable by anyone who could reach the host. It is now fronted by its own
# oauth2-proxy, the same shape portal already uses, and that proxy owns the
# hostname. Two Ingresses for one host is undefined behaviour in nginx-ingress,
# so the plain config-ui Ingress is deliberately gone rather than left disabled.
if [[ -z "${CONFIG_OAUTH2_PROXY_SECRET:-}" || -z "${CONFIG_COOKIE_SECRET:-}" ]]; then
    log "ERROR: CONFIG_OAUTH2_PROXY_SECRET / CONFIG_COOKIE_SECRET are not set."
    log "       Run ./deploy-infra.sh to create the 'config' Keycloak client first."
    exit 1
fi

# Remove any pre-existing unauthenticated Ingress from an earlier deploy.
$KUBECTL delete ingress config-ui -n "$NAMESPACE" --ignore-not-found

_CFG_VALUES=$(mktemp /tmp/config-oauth2proxy-values-XXXXXX.yaml)
cat > "$_CFG_VALUES" <<VALEOF
configuration:
  content: |
    provider = "oidc"
    provider_display_name = "Keycloak"
    email_domains = ["*"]
    cookie_secure = true
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
    # PostgREST sits behind this proxy at /api/ and reads the Authorization
    # header, expecting "Bearer <JWT>". oauth2-proxy defaults pass_basic_auth to
    # TRUE, which injects "Authorization: Basic <base64>" into every upstream
    # request — nginx ignores it and serves the page, then PostgREST rejects
    # every API call and the UI shows "Request failed". Portal never hit this
    # because nothing behind it parses Authorization.
    pass_basic_auth = false
    pass_authorization_header = false
    pass_access_token = false
    # X-Forwarded-User / -Email are harmless to PostgREST and are what a future
    # audit trail would attribute a config change to, so keep them.
    pass_user_headers = true
    login_url = "https://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth"
    redeem_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
    oidc_jwks_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
    profile_url = "http://keycloak.${NAMESPACE}.svc.cluster.local/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
    upstreams = ["http://config-ui.${NAMESPACE}.svc.cluster.local:80"]
VALEOF
# upstreams must live inside configuration.content: the content block overrides
# the configuration.upstreams helm value entirely.

$MK8S helm3 upgrade --install config-oauth2-proxy \
  oci://registry-1.docker.io/bitnamicharts/oauth2-proxy \
  --version 8.0.2 \
  --namespace "$NAMESPACE" \
  --values "$_CFG_VALUES" \
  --set image.registry=quay.io \
  --set image.repository=oauth2-proxy/oauth2-proxy \
  --set image.tag=v7.6.0 \
  --set global.security.allowInsecureImages=true \
  --set redis.enabled=false \
  --set configuration.clientID="config" \
  --set configuration.clientSecret="$CONFIG_OAUTH2_PROXY_SECRET" \
  --set configuration.cookieSecret="$CONFIG_COOKIE_SECRET" \
  --set configuration.oidcIssuerUrl="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" \
  --set "extraArgs[0]=--whitelist-domain=$KEYCLOAK_DOMAIN" \
  --set ingress.enabled=true \
  --set ingress.hostname="$CONFIG_DOMAIN" \
  --set "ingress.extraTls[0].hosts[0]=$CONFIG_DOMAIN" \
  --set "ingress.extraTls[0].secretName=cea-tls" \
  --set "ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffer-size=16k" \
  --set-string "ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffers-number=4" \
  --timeout 5m
rm -f "$_CFG_VALUES"
$KUBECTL rollout restart deployment/config-oauth2-proxy -n "$NAMESPACE"

# =============================================================================
# 7. Wait for rollouts
# =============================================================================
log "Waiting for config-api rollout..."
$KUBECTL rollout status deployment/config-api -n "$NAMESPACE" --timeout=3m

log "Waiting for config-ui rollout..."
$KUBECTL rollout restart deployment/config-ui -n "$NAMESPACE"
# config-ui restarts alongside its oauth2-proxy, and the old replica can sit in
# Terminating past the 3m default while the proxy settles — which failed the whole
# component for something that completed moments later. Give it longer, and if it
# still has not finished, say what to look at rather than just timing out.
if ! $KUBECTL rollout status deployment/config-ui -n "$NAMESPACE" --timeout=6m; then
    echo "  config-ui did not finish rolling out. Current state:" >&2
    $KUBECTL get pods -l app=config-ui -n "$NAMESPACE" >&2 || true
    exit 1
fi

# =============================================================================
# 8. Update portal: enable the System Configuration card
# =============================================================================
log "Updating portal to enable System Configuration card..."

$KUBECTL get cm portal-html -n "$NAMESPACE" -o jsonpath='{.data.index\.html}' \
  | python3 -c "
import sys
html = sys.stdin.read()
url  = 'https://$CONFIG_DOMAIN'

# Enable the System Configuration card (stroke=#fb923c is unique to this card)
html = html.replace(
    '<div class=\"card card-dis\">\n            <div class=\"ci\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#fb923c\"',
    '<a class=\"card\" href=\"' + url + '\" target=\"_blank\" rel=\"noopener\">\n            <div class=\"ci\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#fb923c\"',
    1
)
html = html.replace(
    '<div class=\"ck\" style=\"color:#475569\">Coming soon</div>\n          </div>\n          <div class=\"card card-dis\">',
    '<div class=\"ck\">' + url + ' <span class=\"ck-a\">&rarr;</span></div>\n          </a>\n          <div class=\"card card-dis\">',
    1
)
sys.stdout.write(html)
" \
  | $KUBECTL create configmap portal-html \
      -n "$NAMESPACE" \
      --from-file=index.html=/dev/stdin \
      --dry-run=client -o yaml \
  | $KUBECTL apply -f -


# =============================================================================
# 1. nginx ConfigMap
# =============================================================================
log "Creating nginx config..."
$KUBECTL create configmap dbmgmt-nginx -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-literal="default.conf=server {
    listen 80;
    location / { root /usr/share/nginx/html; index index.html; try_files \$uri /index.html; }
    location /api/ { proxy_pass http://localhost:8081/; proxy_read_timeout 120s; }
    location /images/ { alias /usr/share/nginx/html/images/; }
}" | $KUBECTL apply -f -

# =============================================================================
# 2. HTML SPA ConfigMap
# =============================================================================
log "Creating HTML ConfigMap..."
sed -e "s|\${PORTAL_URL}|$PORTAL_URL|g" -e "s|\${PGADMIN_URL}|$PGADMIN_URL|g" "$SCRIPT_DIR/html/dbmgmt.html" \
  | $KUBECTL create configmap dbmgmt-html -n "$NAMESPACE" \
    --from-file=index.html=/dev/stdin \
    --dry-run=client -o yaml | $KUBECTL apply -f -

# =============================================================================
# 3. Python API ConfigMap
# =============================================================================
log "Creating Python API ConfigMap..."
$KUBECTL create configmap dbmgmt-api -n "$NAMESPACE" \
  --from-file=server.py="$SCRIPT_DIR/html/dbmgmt-api.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f -

log "Deploying dbmgmt..."
cat << MANIFEST | $KUBECTL apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dbmgmt
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels: {app: dbmgmt}
  template:
    metadata:
      labels: {app: dbmgmt}
    spec:
      containers:
      - name: nginx
        image: nginx:1.27-alpine
        ports:
        - containerPort: 80
        volumeMounts:
        - name: html
          mountPath: /usr/share/nginx/html
        - name: nginx-conf
          mountPath: /etc/nginx/conf.d
        - name: images
          mountPath: /usr/share/nginx/html/images
      - name: api
        image: python:3.12-alpine
        command: ["python", "/scripts/server.py"]
        ports:
        - containerPort: 8081
        env:
        - name: PG_HOST
          value: rdbms-postgresql.$NAMESPACE.svc.cluster.local
        - name: PG_DATABASE
          value: medcea_db
        - name: PG_USER
          value: postgres
        - name: PG_PASSWORD
          value: "$POSTGRES_PASS"
        volumeMounts:
        - name: api-script
          mountPath: /scripts
        - name: db-exports
          mountPath: /exports
      volumes:
      - name: html
        configMap:
          name: dbmgmt-html
      - name: nginx-conf
        configMap:
          name: dbmgmt-nginx
      - name: api-script
        configMap:
          name: dbmgmt-api
      - name: images
        hostPath:
          path: $SCRIPT_DIR/images
          type: Directory
      - name: db-exports
        hostPath:
          path: $REPO_ROOT/apps/database
          type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: dbmgmt
  namespace: $NAMESPACE
spec:
  selector: {app: dbmgmt}
  ports:
  - port: 80
    targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: dbmgmt
  namespace: $NAMESPACE
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffer-size: "16k"
spec:
  tls:
  - hosts: [$DBMGMT_DOMAIN]
    secretName: cea-tls
  ingressClassName: nginx
  rules:
  - host: $DBMGMT_DOMAIN
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: dbmgmt
            port: {number: 80}
MANIFEST

log "Waiting for dbmgmt rollout..."
$KUBECTL rollout restart deployment/dbmgmt -n "$NAMESPACE"
$KUBECTL rollout status deployment/dbmgmt -n "$NAMESPACE" --timeout=120s

# =============================================================================
# 5. Update portal card: Database → dbmgmt sub-portal
# =============================================================================
log "Configuring portal nginx (images location)..."
$KUBECTL create configmap portal-nginx -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-literal="default.conf=server {
    listen 80;
    location /images/ { alias /usr/share/nginx/html/images/; }
    location / { root /usr/share/nginx/html; index index.html; }
}" | $KUBECTL apply -f -

log "Patching portal deployment (images volume)..."
if ! $KUBECTL get deployment portal -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.volumes[*].name}' | grep -q "images"; then
    $KUBECTL patch deployment portal -n "$NAMESPACE" --type=json -p='[
      {"op":"add","path":"/spec/template/spec/volumes/-",
       "value":{"name":"portal-nginx","configMap":{"name":"portal-nginx"}}},
      {"op":"add","path":"/spec/template/spec/volumes/-",
       "value":{"name":"images","hostPath":{"path":"'"$SCRIPT_DIR"'/images","type":"Directory"}}},
      {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-",
       "value":{"name":"portal-nginx","mountPath":"/etc/nginx/conf.d/default.conf","subPath":"default.conf","readOnly":true}},
      {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-",
       "value":{"name":"images","mountPath":"/usr/share/nginx/html/images","readOnly":true}}
    ]'
fi

log "Updating portal card and background..."
$KUBECTL get cm portal-html -n "$NAMESPACE" -o jsonpath='{.data.index\.html}' > /tmp/portal_current.html

python3 - "$PGADMIN_DOMAIN" "$DBMGMT_DOMAIN" /tmp/portal_current.html /tmp/portal_updated.html << 'PYEOF'
import re, sys
pgadmin_domain, dbmgmt_domain, src, dst = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
html = open(src).read()

# Update database card
old = re.compile(r'<a class="card" href="http://' + re.escape(pgadmin_domain) + r'".*?</a>', re.DOTALL)
new = (
    '<a class="card" href="http://' + dbmgmt_domain + '" target="_blank" rel="noopener">\n'
    '            <div class="ci"><svg viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3"/></svg></div>\n'
    '            <div class="cl">Database</div><div class="ct">Management</div>\n'
    '            <div class="cd">Explore and manage the database, export DDL and data for medcea schema objects.</div>\n'
    '            <div class="ck">↗ Database Management</div>\n'
    '          </a>'
)
html, n = old.subn(new, html, count=1)
print(f'Portal card replacements: {n}')

# Set background image (replace whatever style is on #bg div)
html = re.sub(
    r'<div id="bg"[^>]*>',
    '<div id="bg" style="background-image:url(\'/images/cea-background.png\');">',
    html, count=1
)

open(dst, 'w').write(html)
PYEOF

$KUBECTL create configmap portal-html -n "$NAMESPACE" \
    --from-file=index.html=/tmp/portal_updated.html \
    --dry-run=client -o yaml | $KUBECTL apply -f -

$KUBECTL rollout restart deployment/portal -n "$NAMESPACE"

echo ""

echo ""
echo -e "  ${BOLD}Frontend deployed${NC}"
# A finished rollout is not a served page: the ingress still has to pick up the
# new pod. Verify before claiming the component deployed.
wait_for_http "https://$CONFIG_DOMAIN/" 120 "Config UI" || exit 1

# The Devices tab links to the onboarding wizard, which runs on the host rather
# than in the cluster (it needs the USB port). Nothing here deploys it, so a
# stopped daemon shows up as "refused to connect" only when somebody clicks the
# button. Check it at deploy time instead, and say exactly how to fix it.
if ! curl -s -o /dev/null -m 5 "$_EDGE_WIZARD_URL" 2>/dev/null; then
    log "WARNING: the onboarding wizard is not answering at $_EDGE_WIZARD_URL"
    log "         The 'Onboard Device' button on the Devices tab will not work."
    log "         Start it with:"
    log "           systemctl --user enable --now cea-edge-wizard"
    log "         (create the unit first: ./edge/wizard-daemon.sh --install-unit)"
fi
wait_for_http "https://$DBMGMT_DOMAIN/" 120 "DB Mgmt"   || exit 1

echo -e "  Config UI:  https://$CONFIG_DOMAIN"
echo -e "  DB Mgmt:    https://${DBMGMT_DOMAIN}"
echo ""
