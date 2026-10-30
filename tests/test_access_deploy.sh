#!/usr/bin/env bash
# tests/test_access_deploy.sh — apps/access/deploy.sh keeps invariant W (IAM 2.7): the
# access proxy admits more than admin only once every Ready access pod has proved it
# enforces its route table. Offline: no cluster, no network.
#
# Runs the real deploy.sh (and the real infra/lib-*.sh it sources) in a scratch copy of
# the tree with a fake `microk8s` on PATH (kubectl and helm3), a stub compiler CLI and a
# stub apps/database/deploy.sh. The fake writes one line per call that matters to a log
# — PSQL, DBDEPLOY, ROLLOUT, PROOF <pod> ok|bad, HELM <allowed_groups> — and each case
# checks the order:
#   1  every pod proves enforce_always   → helm gets the compiled roles, after every PROOF
#   2  an old pod still answers without   → helm gets ["admin"] only, deploy exits 1
#   3  ConfigMap older than 2.7           → refused before any psql, rollout or helm call
#   4  IAM_GATES=false                    → ["admin"], exit 0
#   5  the database deploy fails          → exit 1, no rollout, no helm
#   6  access_svc already holds its grants → no database deploy
#
#   tests/test_access_deploy.sh      exit 1 on any FAIL

set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %s\n" "$1"; }
fail() { printf "  ${RED}FAIL${NC}  %s\n" "$1"; FAILS=$((FAILS + 1)); }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# ── the scratch tree ─────────────────────────────────────────────────────────────
R="$T/repo"
mkdir -p "$R/apps/access" "$R/apps/iam/compiler" "$R/apps/database" "$R/infra" "$R/k8s/oauth2-proxy" "$T/bin" "$T/fake"
cp -r "$REPO/apps/access/." "$R/apps/access/"
for f in lib-lock.sh lib-mk8s.sh lib-render.sh lib-oauth2-proxy.sh lib-portal.sh; do cp "$REPO/infra/$f" "$R/infra/"; done
cp "$REPO/k8s/oauth2-proxy/error.html" "$REPO/k8s/oauth2-proxy/values-common.yaml" "$R/k8s/oauth2-proxy/"
cat > "$R/config.env" <<'ENV'
PROJECT_NAME=medcea
NAMESPACE=medcea
DOMAIN=medcea
ACCESS_DOMAIN=access.medcea
PORTAL_DOMAIN=portal.medcea
KEYCLOAK_DOMAIN=keycloak.medcea
KEYCLOAK_REALM=medcea
POSTGRES_PASS=pgpass
ACCESS_CLIENT_SECRET=client-secret
ACCESS_COOKIE_SECRET=cookie-secret-cookie-secret-1234
IAM_ENFORCE=false
IAM_GATES="true"
ENV
# the compiler: the compiled gate and the 403 page's text
cat > "$R/apps/iam/compiler/cli.py" <<'PY'
import sys
a = sys.argv[1:]
if a[:2] == ["compile", "proxy"]:
    print('["admin", "auditor", "qa", "qp"]')
elif a[:1] == ["describe-gate"]:
    print("User Manager\tadmin")
else:
    sys.exit(2)
PY
cat > "$R/apps/database/deploy.sh" <<'SH'
#!/usr/bin/env bash
echo "DBDEPLOY lock=${MEDCEA_LOCK_HELD:-none}" >> "$FAKE_LOG"
[[ "${FAKE_DB_FAILS:-0}" == 1 ]] && exit 1
touch "$FAKE_DIR/granted"
SH
chmod +x "$R/apps/database/deploy.sh"

# ConfigMap medcea-iam-lib: 2.7's and an older one
cat > "$T/fake/routes-27.json" <<'JSON'
{"digest": "x", "widening": {"-": {"operator": [["portal", "R"]]}},
 "services": {"access": {"routes": {"GET /": {"group": "user_manager"}}}}}
JSON
cat > "$T/fake/routes-old.json" <<'JSON'
{"digest": "x", "services": {"access": {"routes": {"GET /": {"group": "iam_users"}}}}}
JSON
printf 'def allows(roles, service, method, path):\n    pass\n\ndef http_check(handler, service, enforce=None):\n    pass\n' > "$T/fake/lib-27.py"
printf 'def http_check(handler, service):\n    pass\n' > "$T/fake/lib-old.py"

# the fake microk8s: status, kubectl, helm3
cat > "$T/bin/microk8s" <<'SH'
#!/usr/bin/env bash
L="$FAKE_LOG"; D="$FAKE_DIR"
case "$1" in
    status) exit 0 ;;
    helm3)
        shift
        vals=(); prev=""
        for a in "$@"; do [[ "$prev" == --values ]] && vals+=("$a"); prev="$a"; done
        g="$(grep -h 'allowed_groups' "${vals[@]}" 2>/dev/null | sed 's/.*= *//')"
        echo "HELM ${g:-none}" >> "$L"
        exit 0 ;;
    kubectl) shift ;;
    *) echo "fake microk8s: $*" >&2; exit 2 ;;
esac
a="$*"
case "$a" in
    *"get configmap medcea-iam-lib"*routes*) cat "$D/routes.json" ;;
    *"get configmap medcea-iam-lib"*medcea_iam*) cat "$D/lib.py" ;;
    *"get pod "*"app.kubernetes.io/name=postgresql"*) printf 'rdbms-postgresql-0' ;;
    *"get secret access-secrets"*) exit 1 ;;
    *"get cm portal-html"*) exit 1 ;;
    *"exec -i"*rdbms-postgresql-0*psql*)
        if [[ "$a" == *has_function_privilege* ]]; then
            echo "PSQL grants" >> "$L"
            [[ -f "$D/granted" ]] && echo true || echo false
        else
            sql="$(cat)"
            if [[ "$sql" == *"unit_backfill.sql"* ]]; then echo "PSQL backfill" >> "$L"; echo "backfilled|7|11111111-1111-4111-8111-111111111111|3"
            elif [[ "$sql" == *"access_pw"* ]]; then echo "PSQL access_db -1=$([[ "$a" == *" -1 "* ]] && echo yes || echo no)" >> "$L"
            else echo "PSQL other" >> "$L"; fi
        fi ;;
    *"get pods"*"app=access"*) cat "$D/pods" ;;
    *"exec -n medcea "*" -c api -- python3"*)
        p="${a#*exec -n medcea }"; p="${p%% *}"
        if grep -qx "$p" "$D/enforcing" 2>/dev/null; then echo "PROOF $p ok" >> "$L"; echo enforce_always
        else echo "PROOF $p bad" >> "$L"; echo 'answered {"ok": true}'; exit 1; fi ;;
    *"rollout "*) echo "ROLLOUT ${a#rollout }" | cut -d' ' -f1-3 >> "$L" ;;
    *"--from-file=error.html=/dev/stdin"*) cat > /dev/null; echo "kind: ConfigMap" ;;
    *"--dry-run=client"*) echo "kind: Something" ;;
    *"apply -f -"*) cat > /dev/null ;;
    *) echo "OTHER $a" | cut -c1-120 >> "$L" ;;
esac
SH
chmod +x "$T/bin/microk8s"

# run CASE [env...] — one deploy; sets OUT, RC, LOG
run() {
    local name="$1"; shift
    rm -f "$T/fake/log" "$T/fake/granted"
    : > "$T/fake/log"
    OUT="$(cd "$R" && env -i HOME="$HOME" PATH="$T/bin:$PATH" TMPDIR="$T" FAKE_LOG="$T/fake/log" FAKE_DIR="$T/fake" \
             "$@" bash "$R/apps/access/deploy.sh" 2>&1)"
    RC=$?
    LOG="$(cat "$T/fake/log")"
    echo -e "\n${BOLD}$name${NC} (exit $RC)"
}
line_of() { grep -n -m1 -- "$1" <<<"$LOG" | cut -d: -f1; }       # first line matching
last_of() { grep -n -- "$1" <<<"$LOG" | tail -1 | cut -d: -f1; }  # last line matching
setup() {  # ROUTES LIB PODS ENFORCING
    cp "$T/fake/routes-$1.json" "$T/fake/routes.json"; cp "$T/fake/lib-$2.py" "$T/fake/lib.py"
    printf '%b' "$3" > "$T/fake/pods"; printf '%b' "$4" > "$T/fake/enforcing"
}

# 1 — every Ready pod proves it: widened, and only after the last proof
setup 27 27 'access-new True\naccess-gone False\n' 'access-new\n'
run "1 every Ready pod enforces"
[[ $RC -eq 0 ]] && pass "exit 0" || { fail "exit $RC"; echo "$OUT" | tail -15; }
h="$(grep '^HELM' <<<"$LOG")"
[[ "$h" == 'HELM ["admin", "auditor", "qa", "qp"]' ]] && pass "helm got the compiled roles once" || fail "helm calls: $h"
[[ -n "$(line_of '^PROOF access-new ok')" && "$(last_of '^PROOF')" -lt "$(line_of '^HELM')" ]] \
    && pass "every PROOF precedes the helm call" || fail "order: $LOG"
grep -q '^PROOF access-gone' <<<"$LOG" && fail "a pod that is not Ready was asked" || pass "only Ready pods are asked"
[[ "$(line_of '^PSQL access_db -1=yes')" -lt "$(line_of '^DBDEPLOY')" && "$(line_of '^DBDEPLOY')" -lt "$(line_of '^ROLLOUT restart deployment/access$')" ]] \
    && pass "access_db.sql (one transaction) → database deploy → rollout" || fail "order: $(tr '\n' ';' <<<"$LOG")"
grep -q '^DBDEPLOY lock=[0-9]' <<<"$LOG" && pass "the database deploy inherits the lock" || fail "database deploy: $(grep DBDEPLOY <<<"$LOG")"
grep -q 'decision #7: account 11111111' <<<"$OUT" && pass "a backfilled unit decision is listed" || fail "backfill not listed"
[[ "$(line_of '^ROLLOUT status deployment/access$')" -lt "$(line_of '^PROOF')" ]] && pass "rollout status before the proof" || fail "rollout status after the proof"

# 2 — an old pod still answers without enforce_always: admin only, exit 1
setup 27 27 'access-new True\naccess-old True\n' 'access-new\n'
run "2 an old Ready pod does not enforce" ACCESS_PROOF_TIMEOUT=1
[[ $RC -ne 0 ]] && pass "exit $RC" || fail "exit 0"
h="$(grep '^HELM' <<<"$LOG")"
[[ "$h" == 'HELM ["admin"]' ]] && pass "helm got [\"admin\"] only" || fail "helm calls: $h"
grep -q 'PROOF access-old bad' <<<"$LOG" && pass "the old pod was asked" || fail "the old pod was not asked"
grep -q 'stays admin-only' <<<"$OUT" && pass "says the gate stays admin-only" || fail "no explanation: $(tail -3 <<<"$OUT")"

# 3 — the ConfigMap predates 2.7: nothing changes
setup old old 'access-new True\n' 'access-new\n'
run "3 ConfigMap older than IAM 2.7"
[[ $RC -ne 0 ]] && pass "exit $RC" || fail "exit 0"
grep -qE '^(PSQL|DBDEPLOY|ROLLOUT|HELM)' <<<"$LOG" && fail "changed something: $(tr '\n' ';' <<<"$LOG")" || pass "no psql, database deploy, rollout or helm call"
grep -q 'deploy-infra.sh first' <<<"$OUT" && pass "says run ./deploy-infra.sh first" || fail "message: $(tail -3 <<<"$OUT")"
setup 27 old 'access-new True\n' 'access-new\n'
run "3b library without http_check(enforce=)"
[[ $RC -ne 0 ]] && ! grep -qE '^(PSQL|HELM)' <<<"$LOG" && pass "refused before any change" || fail "exit $RC, log $(tr '\n' ';' <<<"$LOG")"

# 4 — IAM_GATES=false: admin only even though every pod proves it
setup 27 27 'access-new True\n' 'access-new\n'
run "4 IAM_GATES=false" IAM_GATES=false
[[ $RC -eq 0 ]] && pass "exit 0" || { fail "exit $RC"; echo "$OUT" | tail -5; }
[[ "$(grep '^HELM' <<<"$LOG")" == 'HELM ["admin"]' ]] && pass "helm got [\"admin\"]" || fail "helm calls: $(grep '^HELM' <<<"$LOG")"

# 5 — the database deploy fails: the pod and the gate stay as they are
setup 27 27 'access-new True\n' 'access-new\n'
run "5 the database deploy fails" FAKE_DB_FAILS=1
[[ $RC -ne 0 ]] && pass "exit $RC" || fail "exit 0"
grep -qE '^(ROLLOUT|HELM)' <<<"$LOG" && fail "rolled out or deployed the gate: $(tr '\n' ';' <<<"$LOG")" || pass "no rollout, no helm"

# 6 — grants already in place: no database deploy
setup 27 27 'access-new True\n' 'access-new\n'
rm -f "$T/fake/log"; : > "$T/fake/log"
OUT="$(cd "$R" && touch "$T/fake/granted" && env -i HOME="$HOME" PATH="$T/bin:$PATH" TMPDIR="$T" FAKE_LOG="$T/fake/log" FAKE_DIR="$T/fake" \
         bash "$R/apps/access/deploy.sh" 2>&1)"; RC=$?; LOG="$(cat "$T/fake/log")"
echo -e "\n${BOLD}6 access_svc already holds its grants${NC} (exit $RC)"
[[ $RC -eq 0 ]] && ! grep -q '^DBDEPLOY' <<<"$LOG" && pass "no database deploy" || fail "exit $RC, log $(tr '\n' ';' <<<"$LOG")"

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}test_access_deploy: all cases passed.${NC}"
else
    echo -e "${RED}${BOLD}test_access_deploy: $FAILS failure(s).${NC}"
    exit 1
fi
