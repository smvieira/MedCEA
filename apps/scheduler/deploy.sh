#!/usr/bin/env bash
# apps/scheduler/deploy.sh — Recipe Schedule Manager
#
# Deploys:
#   1. medcea.schedule table migration
#   2. scheduler-api  (Flask + APScheduler, port 8082)
#   3. scheduler-ui   (nginx SPA, port 80)
#   4. Ingress on $SCHEDULER_DOMAIN
#   5. Updates portal card (Scheduling — "Coming soon" → live link)
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
SCHEDULER_DOMAIN="${SCHEDULER_DOMAIN:-scheduler.$DOMAIN}"

GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${GREEN}[scheduler]${NC} $*"; }

# =============================================================================
# 1. Database migration — medcea.schedule table
# =============================================================================
log "Running database migration (medcea.schedule)..."
$KUBECTL exec -n "$NAMESPACE" rdbms-postgresql-0 -- \
    env PGPASSWORD="$POSTGRES_PASS" psql -U postgres -d medcea_db << 'SQL'
CREATE TABLE IF NOT EXISTS medcea.schedule (
    schedule_id      serial      PRIMARY KEY,
    unit_id          integer     NOT NULL REFERENCES medcea.cea_unit(unit_id)  ON DELETE CASCADE,
    recipe_id        integer     NOT NULL REFERENCES medcea.recipe(recipe_id)  ON DELETE CASCADE,
    cron_expression  varchar(100) NOT NULL,
    enabled          boolean     NOT NULL DEFAULT true,
    description      text,
    timestamp_cre    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    timestamp_upd    timestamptz
);

-- PostgREST/app roles
GRANT SELECT, INSERT, UPDATE, DELETE ON medcea.schedule TO authenticator;
GRANT USAGE, SELECT ON SEQUENCE medcea.schedule_schedule_id_seq TO authenticator;
SQL
log "Migration done."

# =============================================================================
# 2. nginx ConfigMap
# =============================================================================
log "Creating nginx config..."
$KUBECTL create configmap scheduler-nginx -n "$NAMESPACE" --dry-run=client -o yaml \
  --from-literal="default.conf=server {
    listen 80;
    location / { root /usr/share/nginx/html; index index.html; try_files \$uri /index.html; }
    location /api/ { proxy_pass http://localhost:8082/api/; proxy_read_timeout 120s; }
}" | $KUBECTL apply -f -

# =============================================================================
# 3. HTML ConfigMap  (substitute $PORTAL_DOMAIN and embed background image)
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
html  = html.replace('\$PORTAL_DOMAIN', sys.argv[3])
html  = html.replace('__BG_STYLE__', style)
sys.stdout.write(html)
" "$SCRIPT_DIR/html/scheduler.html" "$_BG_TMP" "${PORTAL_DOMAIN}" \
  | $KUBECTL create configmap scheduler-html -n "$NAMESPACE" \
    --from-file=index.html=/dev/stdin \
    --dry-run=client -o yaml > /tmp/scheduler-html-cm.yaml
rm -f "$_BG_TMP"
$KUBECTL replace -f /tmp/scheduler-html-cm.yaml 2>/dev/null || $KUBECTL create -f /tmp/scheduler-html-cm.yaml
rm -f /tmp/scheduler-html-cm.yaml

# =============================================================================
# 4. Python API ConfigMap
# =============================================================================
log "Creating API script ConfigMap..."
$KUBECTL create configmap scheduler-api -n "$NAMESPACE" \
  --from-file=scheduler-api.py="$SCRIPT_DIR/scheduler-api.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f -

# =============================================================================
# 5. Deployment
# =============================================================================
log "Deploying scheduler..."
cat << MANIFEST | $KUBECTL apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scheduler
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels: {app: scheduler}
  template:
    metadata:
      labels: {app: scheduler}
    spec:
      containers:
      # --- nginx: serves the HTML SPA ---
      - name: nginx
        image: nginx:1.27-alpine
        ports:
        - containerPort: 80
        volumeMounts:
        - name: html
          mountPath: /usr/share/nginx/html
        - name: nginx-conf
          mountPath: /etc/nginx/conf.d
      # --- scheduler-api: Flask + APScheduler ---
      - name: api
        image: python:3.11-slim
        command:
        - bash
        - -c
        - |
          pip install --quiet flask apscheduler \
            paho-mqtt python-dotenv pandas pytz psycopg2-binary requests dnspython && \
          python /scripts/scheduler-api.py
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
        - name: MQTT_URL
          value: mosquitto.$NAMESPACE.svc.cluster.local
        - name: MQTT_PORT
          value: "1883"
        - name: PROJECT_NAME
          value: "$PROJECT_NAME"
        - name: SCHD_DIR
          value: /schd
        - name: LOG_DIR
          value: /logs
        volumeMounts:
        - name: api-script
          mountPath: /scripts
        - name: schd
          mountPath: /schd
        - name: logs
          mountPath: /logs
      volumes:
      - name: html
        configMap:
          name: scheduler-html
      - name: nginx-conf
        configMap:
          name: scheduler-nginx
      - name: api-script
        configMap:
          name: scheduler-api
      - name: schd
        hostPath:
          path: $REPO_ROOT/schd
          type: Directory
      - name: logs
        hostPath:
          path: $REPO_ROOT/logs
          type: DirectoryOrCreate
---
apiVersion: v1
kind: Service
metadata:
  name: scheduler
  namespace: $NAMESPACE
spec:
  selector: {app: scheduler}
  ports:
  - port: 80
    targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: scheduler
  namespace: $NAMESPACE
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffer-size: "16k"
spec:
  tls:
  - hosts: [$SCHEDULER_DOMAIN]
    secretName: cea-tls
  ingressClassName: nginx
  rules:
  - host: $SCHEDULER_DOMAIN
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: scheduler
            port: {number: 80}
MANIFEST

log "Restarting scheduler to pick up new ConfigMaps..."
$KUBECTL rollout restart deployment/scheduler -n "$NAMESPACE"
log "Waiting for scheduler rollout..."
$KUBECTL rollout status deployment/scheduler -n "$NAMESPACE" --timeout=3m

# =============================================================================
# 6. Update portal: enable the Scheduling card
# =============================================================================
log "Updating portal Scheduling card..."
SCHEDULER_URL="https://$SCHEDULER_DOMAIN"

$KUBECTL get cm portal-html -n "$NAMESPACE" -o jsonpath='{.data.index\.html}' \
  | python3 -c "
import sys, re
html = sys.stdin.read()
url  = '${SCHEDULER_URL}'

# Match the disabled Scheduling card by its unique stroke colour (#4ade80) + 'Coming soon'
pattern = re.compile(
    r'<div class=\"card card-dis\">\s*'
    r'<div class=\"ci\"><svg[^>]*stroke=\"#4ade80\".*?</svg></div>\s*'
    r'<div class=\"cl\">Scheduling</div>.*?'
    r'Coming soon.*?'
    r'</div>\s*</div>',
    re.DOTALL
)
new_card = (
    '<a class=\"card\" href=\"' + url + '\" target=\"_blank\" rel=\"noopener\">'
    '<div class=\"ci\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#4ade80\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">'
    '<path d=\"M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h3.5\"/>'
    '<path d=\"M16 2v4M8 2v4M3 10h5\"/>'
    '<path d=\"M17.5 17.5 16 16.3V14\"/><circle cx=\"16\" cy=\"16\" r=\"6\"/></svg></div>'
    '<div class=\"cl\">Scheduling</div><div class=\"ct\">Recipe Schedule Manager</div>'
    '<div class=\"cd\">Schedule and manage recipe execution timelines across production units.</div>'
    '<div class=\"ck\">' + url + ' <span class=\"ck-a\">&rarr;</span></div>'
    '</a>'
)
html, n = pattern.subn(new_card, html, count=1)
print(f'Scheduling card replacements: {n}', file=sys.stderr)
sys.stdout.write(html)
" \
  | $KUBECTL create configmap portal-html \
      -n "$NAMESPACE" \
      --from-file=index.html=/dev/stdin \
      --dry-run=client -o yaml \
  | $KUBECTL apply -f -

$KUBECTL rollout restart deployment/portal -n "$NAMESPACE"

log ""
log "Scheduler deployed!"
log "  UI: https://$SCHEDULER_DOMAIN"
