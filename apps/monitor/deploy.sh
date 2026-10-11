#!/usr/bin/env bash
# apps/monitor/deploy.sh — Run Monitor Dashboard
#
# Deploys:
#   1. nginx ConfigMap (proxy /api/ → localhost:8082)
#   2. HTML ConfigMap  (monitor.html with background image)
#   3. API ConfigMap   (monitor-api.py)
#   4. Deployment: nginx:1.27-alpine + python:3.11-slim
#   5. Service + Ingress on $MONITOR_DOMAIN
#   6. Updates portal card (Run Monitor)
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ ! -f "$REPO_ROOT/config.env" ]]; then
    echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2
    exit 1
fi
source "$REPO_ROOT/config.env"

KUBECTL="microk8s kubectl"
NAMESPACE="${NAMESPACE:-medcea}"
MONITOR_DOMAIN="${MONITOR_DOMAIN:-monitor.$DOMAIN}"

GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[monitor]${NC} $*"; }

# =============================================================================
# 1. nginx ConfigMap
# =============================================================================
log "Creating nginx config..."
$KUBECTL create configmap monitor-nginx -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-literal="default.conf=server {
    listen 80;
    location / { root /usr/share/nginx/html; index index.html; try_files \$uri /index.html; }
    location /api/ { proxy_pass http://localhost:8082/api/; proxy_read_timeout 30s; }
}" | $KUBECTL apply -f -

# =============================================================================
# 2. HTML ConfigMap (substitute $MONITOR_DOMAIN and embed background image)
# =============================================================================
log "Creating HTML ConfigMap..."
_BG_STYLE=""
for _BG_FILE in "$REPO_ROOT/apps/portal/bg.jpg" "$REPO_ROOT/apps/portal/bg.png" "$REPO_ROOT/apps/frontend/images/cea-background.png"; do
    if [[ -f "$_BG_FILE" ]]; then
        _MIME="image/png"; [[ "$_BG_FILE" == *.jpg ]] && _MIME="image/jpeg"
        _BG_STYLE="background-image:url('data:${_MIME};base64,$(base64 -w0 "$_BG_FILE")');"
        log "  Embedding background image: $_BG_FILE"
        break
    fi
done
_BG_TMP=$(mktemp)
echo -n "${_BG_STYLE}" > "$_BG_TMP"
python3 -c "
import sys
html  = open(sys.argv[1]).read()
style = open(sys.argv[2]).read()
sys.stdout.write(html.replace('__BG_STYLE__', style))
" "$SCRIPT_DIR/html/monitor.html" "$_BG_TMP" \
  | $KUBECTL create configmap monitor-html -n "$NAMESPACE" \
    --from-file=index.html=/dev/stdin \
    --dry-run=client -o yaml > /tmp/monitor-html-cm.yaml
rm -f "$_BG_TMP"
$KUBECTL replace -f /tmp/monitor-html-cm.yaml 2>/dev/null || $KUBECTL create -f /tmp/monitor-html-cm.yaml
rm -f /tmp/monitor-html-cm.yaml

# =============================================================================
# 3. API ConfigMap
# =============================================================================
log "Creating API script ConfigMap..."
$KUBECTL create configmap monitor-api -n "$NAMESPACE" \
  --from-file=monitor-api.py="$SCRIPT_DIR/monitor-api.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f -

# =============================================================================
# 4. Deployment + Service + Ingress
# =============================================================================
log "Deploying monitor..."
cat << MANIFEST | $KUBECTL apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: monitor
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels: {app: monitor}
  template:
    metadata:
      labels: {app: monitor}
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
      - name: api
        image: python:3.11-slim
        command:
        - bash
        - -c
        - |
          pip install --quiet flask psycopg2-binary && \
          python /scripts/monitor-api.py
        ports:
        - containerPort: 8082
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
      volumes:
      - name: html
        configMap:
          name: monitor-html
      - name: nginx-conf
        configMap:
          name: monitor-nginx
      - name: api-script
        configMap:
          name: monitor-api
---
apiVersion: v1
kind: Service
metadata:
  name: monitor
  namespace: $NAMESPACE
spec:
  selector: {app: monitor}
  ports:
  - port: 80
    targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: monitor
  namespace: $NAMESPACE
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffer-size: "16k"
spec:
  tls:
  - hosts: [$MONITOR_DOMAIN]
    secretName: cea-tls
  ingressClassName: nginx
  rules:
  - host: $MONITOR_DOMAIN
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: monitor
            port: {number: 80}
MANIFEST

log "Restarting monitor to pick up new ConfigMaps..."
$KUBECTL rollout restart deployment/monitor -n "$NAMESPACE"
log "Waiting for monitor rollout..."
$KUBECTL rollout status deployment/monitor -n "$NAMESPACE" --timeout=3m

# =============================================================================
# 5. Update portal: enable the Run Monitor card in the Reporting sub-portal
# =============================================================================
log "Updating portal Reporting sub-portal — enabling Run Monitor card..."
MONITOR_URL="https://$MONITOR_DOMAIN"

$KUBECTL get cm portal-html -n "$NAMESPACE" -o jsonpath='{.data.index\.html}' \
  | python3 -c "
import sys, re
html = sys.stdin.read()
url  = '${MONITOR_URL}'

# Replace the disabled Run Monitor card with an enabled anchor
disabled = re.compile(
    r'<div class=\"card card-dis\">\s*'
    r'<div class=\"ci\"><svg[^>]*stroke=\"#4ade80\"[^>]*>.*?</svg></div>\s*'
    r'<div class=\"cl\">Operations</div><div class=\"ct\">Run Monitor</div>.*?'
    r'</div>\s*</div>',
    re.DOTALL
)
new_card = (
    '<a class=\"card\" href=\"' + url + '\" target=\"_blank\" rel=\"noopener\">'
    '<div class=\"ci\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#4ade80\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">'
    '<circle cx=\"12\" cy=\"12\" r=\"10\"/><polyline points=\"12 6 12 12 16 14\"/></svg></div>'
    '<div class=\"cl\">Operations</div><div class=\"ct\">Run Monitor</div>'
    '<div class=\"cd\">Live view of active recipe runs, cycle progress, and sensor readings vs limits.</div>'
    '<div class=\"ck\">' + url + ' <span class=\"ck-a\">&rarr;</span></div>'
    '</a>'
)
html, n = disabled.subn(new_card, html, count=1)
print(f'Run Monitor card replacements: {n}', file=sys.stderr)
sys.stdout.write(html)
" \
  | $KUBECTL create configmap portal-html \
      -n "$NAMESPACE" \
      --from-file=index.html=/dev/stdin \
      --dry-run=client -o yaml \
  | $KUBECTL apply -f -

$KUBECTL rollout restart deployment/portal -n "$NAMESPACE"

log ""
log "Monitor deployed!"
log "  UI: https://$MONITOR_DOMAIN"
