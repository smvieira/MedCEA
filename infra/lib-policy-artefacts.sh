#!/usr/bin/env bash
# infra/lib-policy-artefacts.sh — deploy-infra's compiled policy artefacts (IAM 4.2b).
#
# Each pa_* function is a block that deploy-infra.sh ran inline until 4.2b, moved
# here word for word and called at the same place, so a full deploy issues the same
# commands as before. MODE full (the default) is that block. MODE scoped is
# ./deploy-infra.sh --policy-only (infra/deploy-policy.sh): it compares the compiled
# artefact with the live one first, prints "<target>: unchanged" and changes nothing
# when they are equal, and otherwise runs the block (without the restarts a full
# deploy makes for secret rotation; a proxy rolls through helm). One line per target:
# unchanged, re-rendered or not deployed.
#
# The blocks keep their `exit 1` and are called bare: deploy-infra runs under set -e,
# and a function called in a || list would run without it. They read deploy-infra's
# variables (SCRIPT_DIR = the repository, MK8S, KUBECTL, NAMESPACE, config.env, the
# colours) and the libraries it sourced; deploy-policy.sh sets the same.

_pa_line() { echo -e "  ${GREEN:-}[policy-only]${NC:-} $1: $2"; }

#   pa_iam_lib [full|scoped]
#
# ConfigMap medcea-iam-lib: routes.json, mqtt.json, settings.json, medcea_iam.py
# (deploy-infra's "[IAM] Access check"). Sets IAM_MQTT_DIGEST and _OLD_MQTT_DIGEST;
# restarts iam-api when the MQTT digest moved. Scoped: equal when both digests
# (annotation and data), the library and settings.json but its written_at are what
# this run would write, so written_at keeps the time of the last real change.
pa_iam_lib() {
    local _pa_mode="${1:-full}"
    PA_MQTT_CHANGED=0
    if [[ "$_pa_mode" == scoped ]]; then
        local _rc=0
        _pa_iam_lib_equal || _rc=$?
        if [[ $_rc == 0 ]]; then _pa_line medcea-iam-lib unchanged; return 0; fi
        [[ $_rc == 1 ]] || { echo -e "${RED:-}ERROR: cannot compare ConfigMap medcea-iam-lib with the compile.${NC:-}" >&2; exit 1; }
    fi
# The access policy's check (codeplan IAM plan 1.1/1.2): ConfigMap medcea-iam-lib,
# mounted by every service at /iam/ — the route table, the check library
# (apps/iam/lib/medcea_iam.py) and its settings (issuer, audience, IAM_ENFORCE).
# Here, because this script runs before every app component. The table is
# compiled by the source rule (infra/lib-policy-source.sh, compiler/source.py): the
# applied version once IAM Phase 4 slice 4.2a writes one, defaults.yaml until then. A policy that fails its invariants stops the deploy
# rather than shipping a table — unless IAM_GATES=false (the rollback), which
# leaves the ConfigMap as it is. Services re-read the mount when the kubelet
# updates it (about a minute), so a change here needs no restart.
echo -e "\n${GREEN}[IAM] Access check (ConfigMap medcea-iam-lib)...${NC}"
# mqtt.json (IAM 3.5, compiler/mqtt.py): the MQTT Explorer's per-person rows, read by
# iam-api; its own key and annotation, so routes.json's digest does not move with it.
if IAM_ROUTES_JSON="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile routes)" \
   && IAM_MQTT_JSON="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile mqtt)"; then
    IAM_ROUTES_DIGEST="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])' <<<"$IAM_ROUTES_JSON")"
    IAM_MQTT_DIGEST="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])' <<<"$IAM_MQTT_JSON")"
    _IAM_DIR="$(mktemp -d)"
    printf '%s\n' "$IAM_ROUTES_JSON" > "$_IAM_DIR/routes.json"
    printf '%s\n' "$IAM_MQTT_JSON" > "$_IAM_DIR/mqtt.json"
    # switches: the other IAM flags as this run set them, with the time, for the
    # quarterly access review's record (IAM 2.7) — labelled there "as of
    # deploy-infra <written_at>". enforce is read live from this file by every
    # service, and IAM_MQTT_PERSON by iam-api (IAM 3.5: no app redeploy for it).
    ISSUER="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" ENFORCE="${IAM_ENFORCE:-false}" \
    SW_GATES="${IAM_GATES:-true}" SW_NETPOL="${IAM_NETPOL:-true}" SW_JWT="${IAM_POSTGREST_JWT:-false}" \
    SW_MQTT="${IAM_MQTT_PERSON:-false}" python3 -c '
import datetime, json, os
e = os.environ
print(json.dumps({"issuer": e["ISSUER"], "audience": "medcea-api",
                  "enforce": e["ENFORCE"] == "true",
                  "switches": {"IAM_GATES": e["SW_GATES"] != "false", "IAM_NETPOL": e["SW_NETPOL"] != "false",
                               "IAM_POSTGREST_JWT": e["SW_JWT"] == "true", "IAM_MQTT_PERSON": e["SW_MQTT"] == "true",
                               "written_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}},
                 sort_keys=True))' > "$_IAM_DIR/settings.json"
    chmod 755 "$_IAM_DIR"; chmod 644 "$_IAM_DIR"/*   # readable by a sudo kubectl
    _OLD_MQTT_DIGEST="$($MK8S kubectl get configmap medcea-iam-lib -n "$NAMESPACE" \
        -o jsonpath='{.metadata.annotations.medcea/mqtt-digest}' 2>/dev/null || true)"
    $MK8S kubectl create configmap medcea-iam-lib -n "$NAMESPACE" \
        --from-file=routes.json="$_IAM_DIR/routes.json" \
        --from-file=settings.json="$_IAM_DIR/settings.json" \
        --from-file=mqtt.json="$_IAM_DIR/mqtt.json" \
        --from-file=medcea_iam.py="$SCRIPT_DIR/apps/iam/lib/medcea_iam.py" \
        --dry-run=client -o yaml \
      | $MK8S kubectl label --local -f - medcea/iam-lib=true -o yaml \
      | $MK8S kubectl annotate --local -f - "medcea/routes-digest=$IAM_ROUTES_DIGEST" "medcea/mqtt-digest=$IAM_MQTT_DIGEST" -o yaml \
      | $MK8S kubectl apply -f -
    rm -rf "$_IAM_DIR"
    # A changed MQTT policy: restart iam-api so it issues from the new mqtt.json at once
    # (the mount follows in about a minute); the database step below then ends every
    # person credential issued under another digest (dba_retire_person_mqtt).
    if [[ -n "$_OLD_MQTT_DIGEST" && "$_OLD_MQTT_DIGEST" != "$IAM_MQTT_DIGEST" ]] \
       && $MK8S kubectl get deployment iam-api -n "$NAMESPACE" >/dev/null 2>&1; then
        echo -e "${GREEN}  MQTT policy changed: restarting iam-api...${NC}"
        $MK8S kubectl rollout restart deployment/iam-api -n "$NAMESPACE" >/dev/null
        $MK8S kubectl rollout status deployment/iam-api -n "$NAMESPACE" --timeout=3m \
            || echo -e "${YELLOW}WARNING: iam-api did not restart; it may issue from the old mqtt.json for about a minute.${NC}" >&2
    fi
    [[ "${IAM_ENFORCE:-false}" == "true" ]] \
        && echo -e "${GREEN}  IAM_ENFORCE=true: services refuse what the policy does not allow (live within about a minute).${NC}" \
        || echo -e "${YELLOW}  IAM_ENFORCE=false: services only log what they would refuse (report-only; IAM 2.6 switch via ./medcea.sh).${NC}"
elif [[ "${IAM_GATES:-true}" == "false" ]]; then
    echo -e "${YELLOW}WARNING: IAM_GATES=false and the access policy does not compile — ConfigMap medcea-iam-lib left as it is.${NC}" >&2
else
    echo -e "${RED}ERROR: the access policy did not compile (python3 apps/iam/compiler/cli.py check).${NC}" >&2
    exit 1
fi
    if [[ -n "${_OLD_MQTT_DIGEST:-}" && "$_OLD_MQTT_DIGEST" != "${IAM_MQTT_DIGEST:-}" ]]; then PA_MQTT_CHANGED=1; fi
    [[ "$_pa_mode" == scoped ]] && _pa_line medcea-iam-lib re-rendered
    return 0
}

# 0 equal, 1 different, 2 cannot tell (a compile or a read failed)
_pa_iam_lib_equal() {
    local routes mqtt cm
    routes="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile routes)" || return 2
    mqtt="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile mqtt)" || return 2
    cm="$($MK8S kubectl get configmap medcea-iam-lib -n "$NAMESPACE" -o json 2>/dev/null)" || return 1
    ROUTES="$routes" MQTT="$mqtt" LIB="$SCRIPT_DIR/apps/iam/lib/medcea_iam.py" \
    ISSUER="https://$KEYCLOAK_DOMAIN/realms/$KEYCLOAK_REALM" ENFORCE="${IAM_ENFORCE:-false}" \
    SW_GATES="${IAM_GATES:-true}" SW_NETPOL="${IAM_NETPOL:-true}" SW_JWT="${IAM_POSTGREST_JWT:-false}" \
    SW_MQTT="${IAM_MQTT_PERSON:-false}" python3 -c '
import json, os, sys
e = os.environ
cm = json.load(sys.stdin)
ann, data = cm["metadata"].get("annotations") or {}, cm.get("data") or {}
def dig(text):
    try:
        return json.loads(text or "")["digest"]
    except Exception:
        return None
wr, wm = dig(e["ROUTES"]), dig(e["MQTT"])
# settings.json as deploy-infra writes it (pa_iam_lib), but written_at
want = {"issuer": e["ISSUER"], "audience": "medcea-api", "enforce": e["ENFORCE"] == "true",
        "switches": {"IAM_GATES": e["SW_GATES"] != "false", "IAM_NETPOL": e["SW_NETPOL"] != "false",
                     "IAM_POSTGREST_JWT": e["SW_JWT"] == "true", "IAM_MQTT_PERSON": e["SW_MQTT"] == "true"}}
try:
    have = json.loads(data.get("settings.json") or "")
    have.get("switches", {}).pop("written_at", None)
except Exception:
    have = None
with open(e["LIB"], encoding="utf-8") as f:
    lib = f.read()
ok = (ann.get("medcea/routes-digest") == wr and dig(data.get("routes.json")) == wr
      and ann.get("medcea/mqtt-digest") == wm and dig(data.get("mqtt.json")) == wm
      and data.get("medcea_iam.py") == lib and have == want)
sys.exit(0 if ok else 1)' <<<"$cm"
}

#   pa_mqtt_retire
#
# Ends the MQTT person credentials issued under another mqtt.json digest (or every
# one on a switch transition); needs lib-db-apply.sh and _MQP. deploy-infra calls it
# in its database step; --policy-only only when pa_iam_lib moved the MQTT digest.
pa_mqtt_retire() {
    if [[ -n "${IAM_MQTT_DIGEST:-}" ]]; then
        if ! _OUT="$(dba_retire_person_mqtt "$NAMESPACE" rdbms-postgresql-0 "$POSTGRES_DB" "$IAM_MQTT_DIGEST" "$_MQP" 2>&1)"; then
            echo -e "${YELLOW}WARNING: could not end the MQTT person credentials of an older policy or switch state; they lapse within 8 h: ${_OUT:0:200}${NC}" >&2
        elif [[ "$_OUT" =~ ^[1-9][0-9]*$ ]]; then
            echo -e "${GREEN}  Ended $_OUT MQTT person credential(s) issued under an older MQTT policy or switch state (the Explorer asks for a new one).${NC}"
        fi
    fi
}

#   pa_netpol [full|scoped]
#
# The application pods' NetworkPolicies (iam-<pod>, label medcea/iam-netpol=true).
# Scoped: equal when the labelled set has exactly the compiled names and specs.
pa_netpol() {
    local _pa_mode="${1:-full}"
    if [[ "$_pa_mode" == scoped ]]; then
        local _rc=0
        _pa_netpol_equal || _rc=$?
        if [[ $_rc == 0 ]]; then _pa_line netpol unchanged; return 0; fi
        [[ $_rc == 1 ]] || { echo -e "${RED:-}ERROR: cannot compare the application pods' NetworkPolicies with the compile.${NC:-}" >&2; exit 1; }
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
    [[ "$_pa_mode" == scoped ]] && _pa_line netpol re-rendered
    return 0
}

# 0 equal, 1 different, 2 cannot tell
_pa_netpol_equal() {
    local live want="" ips=() ip
    live="$($MK8S kubectl get netpol -n "$NAMESPACE" -l medcea/iam-netpol=true -o json 2>/dev/null)" || return 2
    if [[ "${IAM_NETPOL:-true}" != "false" ]]; then
        for ip in $($MK8S kubectl get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="InternalIP")]}{.address}{" "}{end}{.metadata.annotations.projectcalico\.org/IPv4Address}{" "}{.metadata.annotations.projectcalico\.org/IPv4VXLANTunnelAddr}{" "}{.metadata.annotations.projectcalico\.org/IPv4IPIPTunnelAddr}{" "}{end}'); do
            ips+=(--node-ip "${ip%/*}")
        done
        want="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile netpol --namespace "$NAMESPACE" "${ips[@]}")" || return 2
    fi
    WANT="$want" python3 -c '
import json, os, sys
live = {i["metadata"]["name"]: i.get("spec") for i in json.load(sys.stdin).get("items") or []}
want = {i["metadata"]["name"]: i.get("spec") for i in (json.loads(os.environ["WANT"])["items"] if os.environ["WANT"] else [])}
canon = lambda d: json.dumps(d, sort_keys=True)
sys.exit(0 if canon(live) == canon(want) else 1)' <<<"$live"
}

#   pa_node_red_auth [full|scoped]
#
# ConfigMap node-red-auth (permissions.json, cli.py compile node-red). A directory
# mount, read at every login and API call: no restart in either mode.
pa_node_red_auth() {
    local _pa_mode="${1:-full}"
    if [[ "$_pa_mode" == scoped ]]; then
        local _want _live
        if _want="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile node-red)" \
           && _live="$($KUBECTL get configmap node-red-auth -n "$NAMESPACE" -o jsonpath='{.data.permissions\.json}' 2>/dev/null)" \
           && [[ "$_live" == "$_want" ]]; then
            _pa_line node-red-auth unchanged; return 0
        fi
    fi
if _NR_PERMS="$(python3 "$SCRIPT_DIR/apps/iam/compiler/cli.py" compile node-red)"; then
    $KUBECTL create configmap node-red-auth -n "$NAMESPACE" --from-literal=permissions.json="$_NR_PERMS" \
      --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
elif [[ "${IAM_GATES:-true}" == "false" ]]; then
    echo -e "${YELLOW}WARNING: IAM_GATES=false and the access policy does not compile — ConfigMap node-red-auth left as it is.${NC}" >&2
else
    echo -e "${RED}ERROR: cannot compile Node-RED's editor rights (python3 apps/iam/compiler/cli.py check).${NC}" >&2
    exit 1
fi
    [[ "$_pa_mode" == scoped ]] && _pa_line node-red-auth re-rendered
    return 0
}

#   pa_grafana [full|scoped]
#
# The whole Grafana section (datasource, admin Secret, helm, break-glass password):
# Grafana's role path is one input of a helm release that needs all the others, so
# a drift re-renders the section as a full deploy does (a restart; sessions survive,
# Grafana being persistent). Scoped: equal when the Deployment's
# GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH/_STRICT are policy_grafana's (as health
# grafanarole reads them). policy_grafana has run before (deploy-infra: before the
# Keycloak section; deploy-policy: right before this).
pa_grafana() {
    local _pa_mode="${1:-full}"
    if [[ "$_pa_mode" == scoped ]]; then
        local _envs
        if ! _envs="$($MK8S kubectl get deployment grafana -n "$NAMESPACE" \
                -o jsonpath='{range .spec.template.spec.containers[?(@.name=="grafana")].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null)"; then
            _pa_line grafana "not deployed (./deploy-infra.sh installs it)"; return 0
        fi
        if [[ "$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH=//p' <<<"$_envs")" == "$GRAFANA_ROLE_PATH" \
           && "$(sed -n 's/^GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT=//p' <<<"$_envs")" == "$GRAFANA_ROLE_STRICT" ]]; then
            _pa_line grafana unchanged; return 0
        fi
    fi
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
# compiled before the Keycloak section. Grafana's database is persistent (PVC
# grafana, decision of 1 Nov 2026), so a changed env restarts the pod without
# ending sessions: each person's org role is computed again at their next sign-in,
# within 5 minutes of no use or the hour a session lasts at most (values.yaml).
# The local admin — the only Grafana Admin, break-glass — reads its login from
# Secret grafana-admin, written from the environment, never from argv.
ADMIN_USER="$ADMIN_USER" GF_PASS="$GRAFANA_BREAKGLASS_PASS" NS="$NAMESPACE" python3 -c '
import json, os
print(json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                  "metadata": {"name": "grafana-admin", "namespace": os.environ["NS"]},
                  "stringData": {"admin-user": os.environ["ADMIN_USER"], "admin-password": os.environ["GF_PASS"]}}))' \
  | $MK8S kubectl apply -f - >/dev/null
# The volume's size: GRAFANA_STORAGE (default 2Gi). A bound claim cannot shrink, and
# microk8s-hostpath cannot grow one, so an existing PVC keeps its own size.
GRAFANA_STORAGE="${GRAFANA_STORAGE:-2Gi}"
if [[ ! "$GRAFANA_STORAGE" =~ ^[1-9][0-9]*(Mi|Gi|Ti)$ ]]; then
    echo -e "${RED}ERROR: GRAFANA_STORAGE='$GRAFANA_STORAGE' must be a size such as 2Gi (Mi, Gi or Ti).${NC}" >&2
    exit 1
fi
_GF_LIVE_SIZE="$($MK8S kubectl get pvc grafana -n "$NAMESPACE" -o jsonpath='{.spec.resources.requests.storage}' 2>/dev/null || true)"
if [[ -n "$_GF_LIVE_SIZE" && "$_GF_LIVE_SIZE" != "$GRAFANA_STORAGE" ]]; then
    echo -e "${YELLOW}  Grafana's volume stays $_GF_LIVE_SIZE (GRAFANA_STORAGE=$GRAFANA_STORAGE applies to a new volume only).${NC}"
    GRAFANA_STORAGE="$_GF_LIVE_SIZE"
fi
_GF_VALUES=$(mktemp /tmp/grafana-values-XXXXXX.yaml)
render "$SCRIPT_DIR/k8s/grafana/values.yaml" GRAFANA_DOMAIN GRAFANA_OAUTH_SECRET KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE \
  GRAFANA_ROLE_PATH GRAFANA_ROLE_STRICT GRAFANA_STORAGE > "$_GF_VALUES"
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
# The Secret seeds the admin password only when Grafana creates its database; the
# database is persistent, so a rotated GRAFANA_BREAKGLASS_PASS reaches Grafana only
# here, on stdin, in its database. (A changed ADMIN_USER does not rename the
# existing admin login: that stays the name the database was created with.)
if ! printf '%s\n' "$GRAFANA_BREAKGLASS_PASS" | $MK8S kubectl exec -i -n "$NAMESPACE" deployment/grafana -c grafana -- \
        grafana cli --homepath /usr/share/grafana admin reset-admin-password --password-from-stdin >/dev/null 2>&1; then
    echo -e "${RED}  Could not set Grafana's break-glass password; Grafana keeps the previous one until ./deploy-infra.sh sets it.${NC}" >&2
fi
    [[ "$_pa_mode" == scoped ]] && _pa_line grafana "re-rendered (the whole section: Grafana restarted)"
    return 0
}

#   pa_node_red_proxy [full|scoped]
#
# Node-RED's oauth2-proxy (release oauth2-proxy, NODE_RED_DOMAIN). Scoped: equal when
# pa_gate_state says so; else the helm upgrade without the restart (a changed
# configuration.content or 403 page rolls the pod through helm), then rollout status.
pa_node_red_proxy() {
    local _pa_mode="${1:-full}"
    if [[ "$_pa_mode" == scoped ]]; then
        local _rc=0
        pa_gate_state oauth2-proxy NODE_RED_DOMAIN "$(policy_groups NODE_RED_DOMAIN)" || _rc=$?
        case $_rc in
            0) _pa_line "NODE_RED_DOMAIN (oauth2-proxy)" unchanged; return 0 ;;
            3) _pa_line "NODE_RED_DOMAIN (oauth2-proxy)" "not deployed (./deploy-infra.sh installs it)"; return 0 ;;
            4) echo -e "${RED:-}ERROR: cannot read oauth2-proxy's live gate.${NC:-}" >&2; exit 1 ;;
        esac
        helm_dockerhub_login   # the chart pull as this process's identity (deploy-infra logged in for its own)
    fi
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
[[ "$_pa_mode" == scoped ]] || $MK8S kubectl rollout restart deployment/oauth2-proxy -n "$NAMESPACE"

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
    [[ "$_pa_mode" == scoped ]] && _pa_line "NODE_RED_DOMAIN (oauth2-proxy)" "re-rendered ($PA_DRIFT)"
    return 0
}

#   pa_pgadmin [full|scoped]
#
# The whole pgAdmin section (server entry, sign-in claims, Secret, manifest): the
# claims are one input of a manifest whose checksum covers them all, so a drift
# re-renders the section as a full deploy does (pgAdmin restarts and its sessions
# end). Scoped: equal when Secret pgadmin-config's OAUTH2_ADDITIONAL_CLAIMS (read on
# stdin, never printed) is policy_tool pgadmin's; only then is Keycloak not asked.
pa_pgadmin() {
    local _pa_mode="${1:-full}"
    if [[ "$_pa_mode" == scoped ]]; then
        local _want _have
        if ! $MK8S kubectl get deployment pgadmin -n "$NAMESPACE" >/dev/null 2>&1; then
            _pa_line pgadmin "not deployed (./deploy-infra.sh installs it)"; return 0
        fi
        source "$SCRIPT_DIR/infra/lib-policy-tools.sh"
        _want="$(REPO_ROOT="$SCRIPT_DIR" policy_tool pgadmin)" \
            || { echo -e "${RED:-}ERROR: cannot compile pgAdmin's sign-in roles from the access policy (python3 apps/iam/compiler/cli.py check).${NC:-}" >&2; exit 1; }
        _have="$($MK8S kubectl get secret pgadmin-config -n "$NAMESPACE" -o jsonpath='{.data.oauth2-config}' 2>/dev/null \
            | base64 -d 2>/dev/null | python3 -c '
import ast, sys
try:
    print(repr(ast.literal_eval(sys.stdin.read())[0].get("OAUTH2_ADDITIONAL_CLAIMS")))
except Exception:
    print("unreadable")')"
        if [[ "$(python3 -c 'import ast, sys; print(ast.literal_eval(sys.argv[1]) == ast.literal_eval(sys.argv[2]))' "$_have" "$_want" 2>/dev/null)" == True ]]; then
            _pa_line pgadmin unchanged; return 0
        fi
    fi
echo -e "\n${GREEN}[8/10] Deploying pgAdmin...${NC}"
# its server entry: postgres, or rr_admin_login (IAM 2.5); the pod annotation
# medcea/db-user restarts it when that changes
db_client "$NAMESPACE" rr_admin_login
PGA_DB_USER="$DBC_USER"; PGA_DB_PASS="$DBC_PASS"
# its sign-in roles (IAM 3.4): OAUTH2_ADDITIONAL_CLAIMS compiled from the policy;
# a policy that does not compile stops here and the running pgAdmin stays
source "$SCRIPT_DIR/infra/lib-policy-tools.sh"
PGADMIN_OAUTH2_CLAIMS="$(REPO_ROOT="$SCRIPT_DIR" policy_tool pgadmin)" \
    || { echo -e "${RED}ERROR: cannot compile pgAdmin's sign-in roles from the access policy (python3 apps/iam/compiler/cli.py check).${NC}" >&2; exit 1; }
# Who gets the IoT Postgres entry (1 Nov 2026): pgAdmin does not share a server's
# username or passfile, so each OAuth2 user needs its own copy of servers.json,
# loaded by the pod's postStart hook (k8s/pgadmin/pgadmin.yaml) for the e-mails
# listed here — the enabled accounts holding a role in the claims compiled above.
# A plain env value (no secret); a changed list restarts pgAdmin, which also ends
# its sessions. The realm's port-forward closed with section 3, so it is opened
# again on the same port for this one read. Never stops the deploy: a failed read
# keeps the running pgAdmin's list (a shorter one would restart pgAdmin with a
# fresh database and drop the other admins' entries), and only without one
# goes on with ADMIN_EMAIL alone.
_pgadmin_server_users() {
    local pf ok=0 out live
    fuser -k 18080/tcp &>/dev/null || true
    $MK8S kubectl port-forward svc/keycloak 18080:80 -n "$NAMESPACE" &>/dev/null 9>&- &
    pf=$!
    for _ in $(seq 1 12); do
        kc_admin_select && { ok=1; break; }
        sleep 2
    done
    if (( ok )) && out="$(kc_claim_emails "$KEYCLOAK_REALM" "$PGADMIN_OAUTH2_CLAIMS" "$ADMIN_EMAIL")"; then
        printf '%s\n' "$out"
    else
        # the live list; only plain address characters, since it is rendered again
        live="$($MK8S kubectl get deployment pgadmin -n "$NAMESPACE" \
            -o jsonpath='{.spec.template.spec.containers[?(@.name=="pgadmin")].env[?(@.name=="PGADMIN_OAUTH2_SERVER_USERS")].value}' \
            2>/dev/null || true)"
        if [[ -n "$live" && "$live" =~ ^[a-z0-9._%+@,-]+$ ]]; then
            echo -e "${YELLOW}  WARNING: cannot read Keycloak's role holders; pgAdmin keeps its current list (${live}).${NC}" >&2
            printf '%s\n' "$live"
        else
            echo -e "${YELLOW}  WARNING: cannot read Keycloak's role holders and pgAdmin has no list yet; its server entry goes to ${ADMIN_EMAIL,,} alone.${NC}" >&2
            printf '%s\n' "${ADMIN_EMAIL,,}"
        fi
    fi
    kc_admin_done
    kill "$pf" 2>/dev/null || true
}
PGADMIN_OAUTH2_SERVER_USERS="$(_pgadmin_server_users)"
echo -e "${GREEN}  pgAdmin server entry for: ${PGADMIN_OAUTH2_SERVER_USERS:-nobody}${NC}"
# Secret pgadmin-config holds the OAuth2 config (client secret, claims) and the
# default password; pgAdmin reads them as secretKeyRef env, at start only, and the
# postStart hook and servers.json (ConfigMap pgadmin-servers) act only at start too,
# as does the init container's copy of Secret pgadmin-pgpassfile (and the hook's copies
# of it in each user's storage folder), so the sha256 of all three is the pod
# annotation medcea/config-checksum: a rotated rr_admin_login password restarts pgAdmin. The rendered
# manifest reaches python on stdin and only the hash is printed.
PGADMIN_CONFIG_CHECKSUM="$(set -o pipefail
    render "$SCRIPT_DIR/k8s/pgadmin/pgadmin.yaml" NAMESPACE POSTGRES_DB PGA_DB_USER PGA_DB_PASS ADMIN_EMAIL ADMIN_PASS PGADMIN_DOMAIN PGADMIN_OAUTH2_CLAIMS \
           KEYCLOAK_DOMAIN KEYCLOAK_REALM PGADMIN_OAUTH_SECRET PLATFORM_IP PGADMIN_OAUTH2_SERVER_USERS \
    | python3 -c '
import hashlib, json, sys, yaml
try:  # a YAML error quotes the input, which holds the secrets: say nothing of it
    docs = {(d.get("kind"), d["metadata"]["name"]): d for d in yaml.safe_load_all(sys.stdin) if d}
    both = {"secret": docs[("Secret", "pgadmin-config")]["stringData"],
            "pgpassfile": docs[("Secret", "pgadmin-pgpassfile")]["stringData"],
            "configmap": docs[("ConfigMap", "pgadmin-servers")]["data"]}
    print(hashlib.sha256(json.dumps(both, sort_keys=True).encode()).hexdigest())
except Exception:
    sys.exit(1)')" \
    || { echo -e "${RED}ERROR: cannot render pgAdmin's Secret pgadmin-config (k8s/pgadmin/pgadmin.yaml).${NC}" >&2; exit 1; }
render "$SCRIPT_DIR/k8s/pgadmin/pgadmin.yaml" NAMESPACE POSTGRES_DB PGA_DB_USER PGA_DB_PASS ADMIN_EMAIL ADMIN_PASS PGADMIN_DOMAIN PGADMIN_OAUTH2_CLAIMS \
       KEYCLOAK_DOMAIN KEYCLOAK_REALM PGADMIN_OAUTH_SECRET PLATFORM_IP PGADMIN_OAUTH2_SERVER_USERS PGADMIN_CONFIG_CHECKSUM | $MK8S kubectl apply -n "$NAMESPACE" -f -

# 10m, not 5m: pgAdmin's first boot creates and migrates its own SQLite config
# database before gunicorn starts, which took ~5.5 min on a clean install (pod
# created 10:36, Ready 10:42) and failed a 5m wait on a pod that was healthy.
# 16m since the postStart hook (up to 15 min of waiting, then setup.py per user):
# the pod is Ready only after it.
$MK8S kubectl rollout status deployment/pgadmin \
  -n "$NAMESPACE" --timeout=16m
    [[ "$_pa_mode" == scoped ]] && _pa_line pgadmin "re-rendered (the whole section: pgAdmin restarted)"
    return 0
}

#   pa_portal_proxy [full|scoped]
#
# The portal's oauth2-proxy (release portal-oauth2-proxy, PORTAL_DOMAIN; its 403 page
# is the portal's own, not compiled). Full: helm and the restart; deploy-infra waits
# for it after the bare-domain redirect. Scoped: equal when allowed_groups is
# policy_groups'; else helm without the restart, then rollout status.
pa_portal_proxy() {
    local _pa_mode="${1:-full}"
    if [[ "$_pa_mode" == scoped ]]; then
        local _rc=0
        pa_gate_state portal-oauth2-proxy PORTAL_DOMAIN "$(policy_groups PORTAL_DOMAIN)" || _rc=$?
        case $_rc in
            0) _pa_line "PORTAL_DOMAIN (portal-oauth2-proxy)" unchanged; return 0 ;;
            3) _pa_line "PORTAL_DOMAIN (portal-oauth2-proxy)" "not deployed (./deploy-infra.sh installs it)"; return 0 ;;
            4) echo -e "${RED:-}ERROR: cannot read portal-oauth2-proxy's live gate.${NC:-}" >&2; exit 1 ;;
        esac
        helm_dockerhub_login   # the chart pull as this process's identity (deploy-infra logged in for its own)
    fi
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

[[ "$_pa_mode" == scoped ]] || $MK8S kubectl rollout restart deployment/portal-oauth2-proxy -n "$NAMESPACE"
    if [[ "$_pa_mode" == scoped ]]; then
        $MK8S kubectl rollout status deployment/portal-oauth2-proxy -n "$NAMESPACE" --timeout=10m
        _pa_line "PORTAL_DOMAIN (portal-oauth2-proxy)" "re-rendered ($PA_DRIFT)"
    fi
    return 0
}
