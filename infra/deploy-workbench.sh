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
#   - its gate compiled from the access policy (IAM 3.2, policy_workbench in
#     infra/lib-oauth2-proxy.sh): allowed_groups from the research_workbench
#     group's `tool:` block; hub administration is the custom role workbench-admin
#     (hub.loadRoles: admin page, list users, start/stop servers, remove hub users;
#     never tokens or access:servers, so a hub admin never opens another person's
#     server), held by the policy's admin groups; nobody holds JupyterHub's built-in
#     admin role (admin_access is deprecated and does nothing); delete_pvc false
#     (removing a hub user keeps the home). A policy that does not compile stops the deploy before helm;
#     IAM_GATES=false renders the pre-policy sign-in (any realm account).
#   - the existing nginx ingress, on the same hostname Kubeflow used
#   - VS Code and real-time collaboration inside the user's own pod, installed into
#     the home by a before-notebook script (singleuser.extraFiles), before the server
#     starts; the same script sets nbstripout and git up, and shows the person (git
#     author name, terminal prompt) instead of the container account jovyan
#   - (IAM 3.2b) the example notebooks, read-only in every server (ConfigMap
#     workbench-examples from k8s/workbench/examples/), whose medcea_data.py signs the
#     person in with a device code and reads config-api with their own token; the
#     notebooks' only platform hops (Keycloak, config-api) are compiled from the
#     policy's network.clients.notebooks (policy_workbench_egress) and open only while
#     IAM_POSTGREST_JWT and IAM_DB_ROLES are true, in config.env and live (config-api
#     runs JWT, the database enforces); the database and frontend deploys close them
#     on a switch to false (workbench_egress_close); nbstripout as every home's global
#     git filter; WORKBENCH_NOTEBOOK_REPO, the research repository the guide names
#   - home volumes (claim-<name>) are kept by everything here; only deleting the
#     namespace deletes them, and every uninstall path warns first
#
# Where it runs (research sandbox Phase 2b): the access policy places it. With a pod `hub`
# of zone research in network.pods (commit B's skeleton; workbench_placement in
# infra/lib-policy-tools.sh) the release lives in the research namespace
# (RESEARCH_NAMESPACE): a second values file k8s/workbench/values-research.yaml (the
# chart's NetworkPolicies, RBAC, user-scheduler and cloud-metadata init container off; the
# research PriorityClass; the snapshot reader lake-api instead of Keycloak and config-api;
# the A2 pre-spawn hook: hub administration gives no workspace), our Role medcea-hub
# without Secrets (k8s/workbench/hub-rbac.yaml) and a certificate of its own (Secret
# workbench-tls). Without it the release stays in the platform namespace exactly as before.
# A release found in the other namespace is never moved by a plain run: exit 4 and the line
# "the AI workbench moves with ./infra/deploy-workbench.sh --move" (deploy-infra.sh reports
# it as still to do). --move stops the hub, keeps every home volume (Retain), copies each
# home with sudo into a new volume of the target namespace, installs there with a fresh hub
# database and prints what is left behind for an administrator to remove; nothing on disk
# is ever deleted by a script. Both ways: source = the other namespace, target = the
# placement's.
#
#   ./infra/deploy-workbench.sh                 deploy (or re-deploy) where the policy places it
#   ./infra/deploy-workbench.sh --policy-only   the gate (and hops, or the A2 hook) only, on drift
#   ./infra/deploy-workbench.sh --move          move the release, and the homes, to the placement
#
# Exit 0 done or skipped, 1 failed or refused, 2 usage, 4 the release must move first
# (--policy-only: deferred; apply.sh records it).
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
# --policy-only (IAM 4.2b): re-render only the gate and the notebooks' hops, and only
# when they drifted from the compile; nothing else is applied. --move (research Phase 2b):
# the release and the homes to the namespace the access policy places the workbench in.
_MODE=full
case "$*" in
    "") ;;
    --policy-only) _MODE=scoped ;;
    --move) _MODE=move ;;
    *) echo "ERROR: unknown arguments: $* (usage: ./infra/deploy-workbench.sh [--policy-only | --move])" >&2; exit 2 ;;
esac
source "$REPO_ROOT/infra/lib-log.sh"; medcea_log deploy-workbench   # logs/deploy-workbench-<ts>.log, unless a parent logs
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-infra.sh
[[ "$_MODE" == scoped ]] && echo "mode: policy-only"
# shellcheck source=/dev/null
source config.env
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-wait.sh"
source "$SCRIPT_DIR/lib-render.sh"
source "$SCRIPT_DIR/lib-oauth2-proxy.sh"   # policy_workbench
source "$REPO_ROOT/apps/database/lib-db-apply.sh"   # _dba_psql, for pgrst_db_enforcing
source "$SCRIPT_DIR/lib-postgrest.sh"      # pgrst_live_mode, pgrst_db_enforcing (the hops' live check)
source "$SCRIPT_DIR/lib-policy-tools.sh"   # workbench_placement, workbench_namespace (research Phase 2b)
source "$SCRIPT_DIR/lib-workbench.sh"      # workbench_release_ns, workbench_tls_issue, workbench_zone_ready, the move

# When deploy-infra.sh calls this, $MK8S is already set; standalone it is not.
if [[ -z "${MK8S:-}" ]]; then
    if microk8s status --timeout 5 >/dev/null 2>&1; then MK8S="microk8s"; else MK8S="sudo microk8s"; fi
fi

KUBECTL="$MK8S kubectl"
HELM="$MK8S helm3"
# Zero-to-JupyterHub 4.4.4 (JupyterHub 5.5.4, 1 Nov 2026). It differs from 4.4.1 only in
# image tags and versions: templates and values.schema.json are byte-identical.
CHART_VERSION="4.4.4"

log() { echo -e "\033[0;32m[workbench]\033[0m $*"; }
warn() { echo -e "\033[0;33m[workbench] WARNING:\033[0m $*" >&2; }
die() { echo -e "\033[0;31m[workbench] ERROR:\033[0m $*" >&2; exit 1; }

: "${NAMESPACE:?}" ; : "${KEYCLOAK_DOMAIN:?}" ; : "${DOMAIN:?}"
source "$SCRIPT_DIR/lib-policy-source.sh"   # where every compile reads the policy (IAM Phase 4)
policy_source_init "$NAMESPACE" || exit $?   # 2: a widening git skeleton (the gate's message above)

# Where the workbench runs, and where its release is now (research Phase 2b), before any
# compile of the gate: the decision table of codeplan SPEC §2.1. WB_NS is the namespace of
# the placement; NAMESPACE stays the platform's (Keycloak's address, the policy source).
WB_PLACEMENT="$(workbench_placement)" \
    || die "cannot tell where the access policy places the AI workbench (python3 apps/iam/compiler/cli.py pod-zone hub)"
WB_NS="$(workbench_namespace)" || die "cannot tell the AI workbench's namespace from the access policy"
RESEARCH_NAMESPACE="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
RESEARCH_AGENTS_NAMESPACE="${RESEARCH_AGENTS_NAMESPACE:-${RESEARCH_NAMESPACE}-agents}"   # medcea_agent.py reaches the orchestrator there (Phase 4a)
_rc=0; _LIVE_NS="$(workbench_release_ns)" || _rc=$?
case "$_rc" in
    0) ;;
    3) die "Helm release workbench exists in two namespaces ($_LIVE_NS): remove the one that is not in use (helm3 uninstall workbench -n <namespace>), keeping its home volumes, then re-run" ;;
    *) die "cannot list the Helm releases (helm3 list -A)" ;;
esac
if [[ "$WB_PLACEMENT" == research ]]; then
    _WB_MOVE_LINE="the AI workbench moves with ./infra/deploy-workbench.sh --move"
else
    _WB_MOVE_LINE="the AI workbench moves back with ./infra/deploy-workbench.sh --move"
fi
log "Placement: $WB_PLACEMENT (namespace $WB_NS); release: ${_LIVE_NS:-none}"
if [[ "$WB_PLACEMENT" == research && "${RESEARCH_ENABLED:-false}" != "true" ]]; then
    case "$_MODE" in
        scoped) log "WORKBENCH_DOMAIN (workbench): not deployed (RESEARCH_ENABLED is not true; a running hub is left as it is)" ;;
        move)   die "the access policy places the AI workbench in the research zone, but RESEARCH_ENABLED is not true (config.env): nothing moved" ;;
        *)      log "skipped: the AI workbench lives in the research zone (the access policy) and RESEARCH_ENABLED is not true"
                [[ -n "$_LIVE_NS" ]] && warn "the hub running in namespace $_LIVE_NS is left as it is" ;;
    esac
    policy_source_finish "$NAMESPACE" workbench
    exit 0
fi
if [[ "$_MODE" != move && -n "$_LIVE_NS" && "$_LIVE_NS" != "$WB_NS" ]]; then
    if [[ "$_MODE" == scoped ]]; then
        log "WORKBENCH_DOMAIN (workbench): deferred ($_WB_MOVE_LINE)"
    else
        log "$_WB_MOVE_LINE"
        log "(its release is in namespace $_LIVE_NS; the access policy places it in $WB_NS)"
    fi
    exit 4
fi
if [[ "$WB_PLACEMENT" == research && "$_MODE" != scoped ]]; then
    workbench_zone_ready "$WB_NS" \
        || die "the research zone is not ready for the AI workbench (above); nothing changed"
fi
KEYCLOAK_REALM="${KEYCLOAK_REALM:-medcea}"
# The other namespace (where a move comes from) and the hub administrator's own home, which a
# move never copies (O7).
if [[ "$WB_PLACEMENT" == research ]]; then SRC_NS="$NAMESPACE"; else SRC_NS="$RESEARCH_NAMESPACE"; fi
_ADMIN_CLAIM=""
[[ "${ADMIN_USER:-}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] && _ADMIN_CLAIM="claim-$ADMIN_USER"
# A fresh install (the release in no namespace) never starts next to homes a move has not taken
# yet (a --move that stopped after the uninstall): a person signing in would get an empty home in
# WB_NS and their real one would be shadowed. The move finishes the job.
if [[ "$_MODE" == full && -z "$_LIVE_NS" && "$SRC_NS" != "$WB_NS" ]]; then
    _unmoved="$(workbench_unmoved_homes "$SRC_NS" "$WB_NS" "$_ADMIN_CLAIM")" \
        || die "cannot read the home volumes of $SRC_NS and $WB_NS (kubectl get pvc/pv); nothing changed"
    if [[ -n "$_unmoved" ]]; then
        log "$_WB_MOVE_LINE"
        log "(no release is installed, and $SRC_NS still holds homes not moved to $WB_NS: $(echo $_unmoved))"
        exit 4
    fi
fi

# ── --move (research Phase 2b, codeplan SPEC §2.2) ─────────────────────────────────────────
# Target = the placement's namespace (WB_NS), source = the other one, whichever way. Steps 1
# and 2 (refusals, the typed yes) run here, before anything is compiled or changed; steps 3-8
# in _move once the values have rendered; 9-10 are the install below; 11 is _move_report.
if [[ "$_MODE" == move ]]; then
    [[ "${WORKBENCH_ENABLED:-true}" == "true" ]] || die "WORKBENCH_ENABLED is not true (config.env): nothing moved"
    [[ "$SRC_NS" != "$WB_NS" ]] || die "RESEARCH_NAMESPACE equals NAMESPACE ($WB_NS): there is nothing to move between"
    [[ "$($KUBECTL get namespace "$WB_NS" -o name 2>/dev/null || true)" == "namespace/$WB_NS" ]] \
        || die "namespace $WB_NS does not exist (./deploy-infra.sh creates it): nothing moved"
    _servers="$($KUBECTL get pods -n "$SRC_NS" -l component=singleuser-server -o name 2>/dev/null || true)"
    [[ -z "$_servers" ]] || die "servers still run in $SRC_NS ($(echo $_servers | tr '\n' ' ')): ask their people to stop them (File > Hub Control Panel > Stop My Server), or stop them on the hub's admin page, then run --move again; nothing moved"
    log "Moving the AI workbench from namespace $SRC_NS to $WB_NS:"
    log "  - the hub and its proxy stop (nobody can start a server meanwhile);"
    log "  - every home volume is kept (Retain) and copied with sudo into a new volume in $WB_NS;"
    log "  - the hub's database starts fresh: hub users and their personal API tokens are dropped"
    log "    (people sign in again; their homes and notebooks move with them);"
    [[ -n "$_ADMIN_CLAIM" ]] && log "  - $_ADMIN_CLAIM, the hub administrator's own home, is not copied;"
    log "  - the old directories stay on this host until an administrator removes them (listed at the end)."
    if [[ "${MEDCEA_CONFIRMED:-}" != "1" ]]; then
        [[ -t 0 ]] || die "no terminal to confirm the move on: run it at a terminal (or through ./medcea.sh); nothing moved"
        read -r -p "Type 'yes' to move the AI workbench to $WB_NS: " _ans
        [[ "$_ans" == "yes" ]] || die "not confirmed; nothing moved"
    fi
fi

_MOVE_SCALED=0
_move_fail() {   # MESSAGE: give the source its hub back while the release is still there, then stop
    if [[ "$_MOVE_SCALED" == 1 ]]; then
        $KUBECTL scale deployment hub proxy --replicas=1 -n "$SRC_NS" >/dev/null 2>&1 || true
        warn "the hub and its proxy in $SRC_NS were started again"
    fi
    warn "kept as they are: the volumes made Retain above (they now outlive their claims; harmless) and, if step 5 ran, Keycloak client workbench-notebook disabled (./deploy-infra.sh enables it again only while the access policy names it)"
    die "$1"
}

_move() {
    local tmp line kind claim arg arg2 uid dst_dir pvdir state rc=0 _pf i n mounted
    _MOVE_TMP="$(mktemp -d)"; tmp="$_MOVE_TMP"   # removed by the EXIT trap, also on a failure
    # 3. Stop the hub and the proxy where the release is, so no server can start between the
    #    check above and the copy; then make sure no pod there mounts a home any more.
    if [[ "$_LIVE_NS" == "$SRC_NS" ]]; then
        log "Stopping the hub and its proxy in $SRC_NS..."
        $KUBECTL scale deployment hub proxy --replicas=0 -n "$SRC_NS" >/dev/null || die "could not stop the hub in $SRC_NS; nothing moved"
        _MOVE_SCALED=1
        for i in $(seq 1 60); do
            n="$($KUBECTL get pods -n "$SRC_NS" -l app=jupyterhub -o json 2>/dev/null | python3 -c '
import json, sys
try:
    items = json.load(sys.stdin).get("items") or []
except ValueError:
    items = [None]
print(sum(1 for p in items if p is None or (p["metadata"].get("labels") or {}).get("component") in ("hub", "proxy")))')" || n=1
            [[ "$n" == 0 ]] && break
            (( i == 60 )) && _move_fail "the hub in $SRC_NS did not stop within 3 minutes; nothing moved"
            sleep 3
        done
    fi
    $KUBECTL get pods -n "$SRC_NS" -o json > "$tmp/pods.json" 2>/dev/null || _move_fail "cannot list the pods of $SRC_NS; nothing moved"
    mounted="$(python3 -c '
import json, sys
names = set()
for p in json.load(open(sys.argv[1])).get("items") or []:
    if (p.get("status") or {}).get("phase") in ("Succeeded", "Failed"):
        continue   # a pod that ended mounts nothing
    for v in (p.get("spec") or {}).get("volumes") or []:
        c = (v.get("persistentVolumeClaim") or {}).get("claimName") or ""
        if c.startswith("claim-"):
            names.add("%s (%s)" % (c, p["metadata"]["name"]))
print(" ".join(sorted(names)))' "$tmp/pods.json")" || _move_fail "cannot read the pods of $SRC_NS; nothing moved"
    [[ -z "$mounted" ]] || _move_fail "a pod in $SRC_NS still mounts a home: $mounted; nothing moved"

    # 4. Every home and the hub's database volume: Retain, before anything is uninstalled.
    $KUBECTL get pvc -n "$SRC_NS" -o json > "$tmp/src.json" || _move_fail "cannot list the claims of $SRC_NS; nothing moved"
    $KUBECTL get pv -o json > "$tmp/pv.json" || _move_fail "cannot list the volumes; nothing moved"
    log "Volumes of the workbench in $SRC_NS (claim, volume, directory on this host, size, node):"
    while IFS=$'\t' read -r claim arg line; do
        [[ -n "$claim" ]] || continue
        log "  $claim  $arg  $line"
        if [[ "$line" != *"Retain"* ]]; then
            $KUBECTL patch pv "$arg" -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}' >/dev/null \
                || _move_fail "could not keep volume $arg ($claim) with Retain; nothing moved"
            log "    kept: $arg is Retain now (it outlives its claim)"
        fi
    done < <(python3 -c '
import json, sys
pvs = {p["metadata"]["name"]: p for p in json.load(open(sys.argv[2])).get("items") or []}
for c in sorted(json.load(open(sys.argv[1])).get("items") or [], key=lambda i: i["metadata"]["name"]):
    name = c["metadata"]["name"]
    if not (name.startswith("claim-") or name == "hub-db-dir"):
        continue
    vol = (c.get("spec") or {}).get("volumeName") or ""
    pv = pvs.get(vol)
    if not pv:
        continue
    s = pv.get("spec") or {}
    node = ",".join(v for t in (((s.get("nodeAffinity") or {}).get("required") or {}).get("nodeSelectorTerms") or [])
                    for e in t.get("matchExpressions") or [] for v in e.get("values") or [])
    print("%s\t%s\t%s %s %s %s" % (name, vol, (s.get("hostPath") or {}).get("path") or "-",
                                   (s.get("capacity") or {}).get("storage") or "?", node or "-",
                                   s.get("persistentVolumeReclaimPolicy") or "?"))' "$tmp/src.json" "$tmp/pv.json")

    # 5. Keycloak (D2): the notebooks' device-sign-in client is disabled once the access policy
    #    no longer names it as a token client (never created, never deleted). While the policy
    #    still names it (a move back after a revert), deploy-infra brings it back.
    rc=0; python3 "$REPO_ROOT/apps/iam/compiler/cli.py" has-token-client workbench-notebook >/dev/null || rc=$?
    case "$rc" in
        0) log "Keycloak: the access policy names client workbench-notebook; left as it is (./deploy-infra.sh keeps it)" ;;
        1) fuser -k 18095/tcp >/dev/null 2>&1 || true
           $KUBECTL port-forward svc/keycloak 18095:80 -n "$NAMESPACE" >/dev/null 2>&1 9>&- &
           _pf=$!
           state="$( KC_URL="http://localhost:18095"
                     source "$REPO_ROOT/infra/lib-keycloak-admin.sh"
                     for i in $(seq 1 12); do kc_admin_select && break; (( i == 12 )) && exit 1; sleep 5; done
                     kc_client_disable "${KEYCLOAK_REALM:-medcea}" workbench-notebook; r=$?
                     kc_admin_done; exit $r )" || state=""
           kill "$_pf" 2>/dev/null || true; wait "$_pf" 2>/dev/null || true
           case "$state" in
               absent)           log "Keycloak: client workbench-notebook does not exist (nothing created)" ;;
               disabled)         log "Keycloak: client workbench-notebook disabled (kept, never deleted)" ;;
               already-disabled) log "Keycloak: client workbench-notebook was disabled already" ;;
               *)                _move_fail "could not disable Keycloak client workbench-notebook (port-forward 18095); nothing moved" ;;
           esac ;;
        *) _move_fail "cannot tell whether the access policy names client workbench-notebook (cli.py has-token-client exited $rc); nothing moved" ;;
    esac

    # 6. The release goes from the source; hub-db-dir's claim with it, its volume stays (Retain).
    if [[ "$_LIVE_NS" == "$SRC_NS" ]]; then
        log "Removing release workbench from $SRC_NS (the homes stay)..."
        $HELM uninstall workbench --namespace "$SRC_NS" --timeout 5m || _move_fail "helm3 uninstall workbench -n $SRC_NS failed"
        _MOVE_SCALED=0
    fi

    # 7. The homes, one by one; re-run safe (a home already in WB_NS is left as it is).
    pvdir="$(workbench_pv_dir)"
    [[ "$pvdir" =~ ^/[A-Za-z0-9._/-]+$ && "$pvdir/" != */../* ]] || die "the volumes' directory '$pvdir' is not a plain path"
    $KUBECTL get pvc -n "$WB_NS" -o json > "$tmp/dst.json" 2>/dev/null || echo '{"items": []}' > "$tmp/dst.json"
    workbench_home_plan "$SRC_NS" "$WB_NS" "$_ADMIN_CLAIM" "$tmp/src.json" "$tmp/dst.json" "$tmp/pv.json" > "$tmp/plan" \
        || die "cannot plan the homes' move"
    python3 -c '
import json, sys
pvs = {p["metadata"]["name"]: p for p in json.load(open(sys.argv[2])).get("items") or []}
for c in json.load(open(sys.argv[1])).get("items") or []:
    v = pvs.get((c.get("spec") or {}).get("volumeName") or "") or {}
    print("%s\t%s" % (c["metadata"]["name"], ((v.get("spec") or {}).get("hostPath") or {}).get("path") or ""))' \
        "$tmp/src.json" "$tmp/pv.json" > "$tmp/srcdirs" || die "cannot read the claims of $SRC_NS"
    while IFS=$'\t' read -r kind claim arg arg2; do
        [[ -n "$kind" ]] || continue
        if [[ "$kind" == rebind ]] \
           && ! sudo -p "[sudo] password for %u (to check the kept home $claim still has its directory): " test -d "$arg2"; then
            warn "  $claim: its kept volume $arg names $arg2, which is not on this host: copied from $SRC_NS instead"
            kind=copy
            arg="$(awk -F'\t' -v c="$claim" '$1 == c { print $2 }' "$tmp/srcdirs")"
            [[ "$arg" =~ ^/[A-Za-z0-9._/-]+$ && "$arg/" != */../* ]] \
                || { warn "  $claim: no plain directory to copy it from; not moved"; continue; }
        fi
        case "$kind" in
            skip)
                log "  $claim: not copied ($arg)" ;;
            conflict)
                warn "  $claim: not moved: $arg"
                _MOVE_CONFLICTS="${_MOVE_CONFLICTS:+$_MOVE_CONFLICTS }$claim" ;;
            rebind)
                $KUBECTL patch pv "$arg" --type merge -p '{"spec":{"claimRef":{"uid":null,"resourceVersion":null}}}' >/dev/null \
                    || die "could not free volume $arg for $claim"
                workbench_rebind_manifest "$WB_NS" "$claim" "$arg" "$tmp/pv.json" \
                    | $KUBECTL apply --server-side --field-manager=medcea-workbench-move -f - >/dev/null \
                    || die "could not bind $claim in $WB_NS to volume $arg"
                $KUBECTL label pvc "$claim" -n "$SRC_NS" "medcea/moved-to=$WB_NS" --overwrite >/dev/null \
                    || warn "could not label $claim in $SRC_NS as moved"
                log "  $claim: bound again to its kept volume $arg (no copy)" ;;
            replace|copy)
                if [[ "$kind" == replace ]]; then
                    log "  $claim: $WB_NS holds the copy an earlier move left there; replacing it (its volume stays, Retain)"
                    # never a rebind candidate again: the copy is older than what SRC holds now
                    if [[ -n "$arg2" && "$arg2" != - ]]; then
                        $KUBECTL label pv "$arg2" medcea/workbench-home- "medcea/superseded=true" --overwrite >/dev/null \
                            || die "could not mark volume $arg2 (the old copy of $claim in $WB_NS) as superseded; nothing copied for $claim"
                    fi
                    $KUBECTL delete pvc "$claim" -n "$WB_NS" --timeout=120s >/dev/null || die "could not remove the old claim $claim in $WB_NS"
                fi
                uid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
                dst_dir="$pvdir/$WB_NS-$claim-pvc-$uid"
                if sudo -p "[sudo] password for %u (to copy the home $claim into $WB_NS): " test -e "$dst_dir"; then
                    die "$dst_dir exists already; nothing copied for $claim"
                fi
                log "  $claim: copying $arg -> $dst_dir"
                sudo -p "[sudo] password for %u (to copy the home $claim into $WB_NS): " \
                    cp -a --no-target-directory "$arg" "$dst_dir" \
                    || die "could not copy the home $claim (sudo cp -a); $dst_dir (a partial copy, used by nothing) is listed by the next --move for removal"
                $KUBECTL get pvc "$claim" -n "$SRC_NS" -o json > "$tmp/claim.json" \
                    || die "cannot read claim $claim in $SRC_NS ($dst_dir, its copy used by nothing, is listed by the next --move for removal)"
                workbench_home_manifests "$SRC_NS" "$WB_NS" "$claim" "$uid" "$dst_dir" "$tmp/claim.json" "$tmp/pv.json" \
                    | $KUBECTL apply --server-side --field-manager=medcea-workbench-move -f - >/dev/null \
                    || die "could not create the volume of $claim in $WB_NS ($dst_dir, its copy used by nothing, is listed by the next --move for removal)"
                $KUBECTL label pvc "$claim" -n "$SRC_NS" "medcea/moved-to=$WB_NS" --overwrite >/dev/null \
                    || warn "could not label $claim in $SRC_NS as moved"
                log "  $claim: in $WB_NS (volume pvc-$uid)" ;;
        esac
    done < "$tmp/plan"
    rm -rf "$tmp"; _MOVE_TMP=""
    # 8. hub-db-dir in WB_NS: the chart creates it fresh at the install.
}

# 11. What the move left behind: nothing on disk is deleted by a script. Removal commands only
# for a home this or an earlier move copied (the source claim labelled medcea/moved-to=WB_NS,
# WB_NS holding a claim of that name, no conflict this run),
# for the old hub database and for copies a failed run left without a volume; the hub
# administrator's own home is kept (O7), and a home not moved is named without any command.
_move_report() {
    local pvs src dst orphans pvdir
    src="$($KUBECTL get pvc -n "$SRC_NS" -o json 2>/dev/null || echo '{}')"
    dst="$($KUBECTL get pvc -n "$WB_NS" -o json 2>/dev/null || echo '{}')"
    pvs="$($KUBECTL get pv -o json 2>/dev/null || echo '{}')"
    pvdir="$(workbench_pv_dir)"
    orphans=""
    if [[ "$pvdir" =~ ^/[A-Za-z0-9._/-]+$ && "$pvdir/" != */../* ]]; then
        orphans="$(sudo -p "[sudo] password for %u (to list the copies in $pvdir): " \
                     find "$pvdir" -mindepth 1 -maxdepth 1 -type d -name "$WB_NS-claim-*-pvc-*" 2>/dev/null || true)"
    fi
    log ""
    log "Left behind by the move (remove each only after checking the copy in $WB_NS works):"
    SRC_JSON="$src" DST_JSON="$dst" PV_JSON="$pvs" ORPHANS="$orphans" CONFLICTS="${_MOVE_CONFLICTS:-}" python3 -c '
import json, os, sys
src_ns, dst_ns, admin = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    claims = json.loads(os.environ["SRC_JSON"]).get("items") or []
    there = {c["metadata"]["name"] for c in json.loads(os.environ["DST_JSON"]).get("items") or []}
    pvs = json.loads(os.environ["PV_JSON"]).get("items") or []
except (ValueError, KeyError, TypeError):
    claims, there, pvs = [], set(), []
conflicts = set(os.environ.get("CONFLICTS", "").split())
by = {p["metadata"]["name"]: p for p in pvs}
path = lambda p: ((p.get("spec") or {}).get("hostPath") or {}).get("path") or "?"
any_, kept = False, []
for c in sorted(claims, key=lambda i: i["metadata"]["name"]):
    n = c["metadata"]["name"]
    if not n.startswith("claim-"):
        continue
    v = (c.get("spec") or {}).get("volumeName") or ""
    if n == admin:
        kept.append("  - claim %s in %s (the hub administrator\x27s own home, not moved), volume %s, directory %s: kept"
                    % (n, src_ns, v, path(by.get(v, {}))))
        continue
    if ((c["metadata"].get("labels") or {}).get("medcea/moved-to")) != dst_ns or n not in there or n in conflicts:
        kept.append("  - claim %s in %s was NOT moved (see the warnings above): nothing to remove; it is the only "
                    "copy of that home" % (n, src_ns))
        continue
    print("  - claim %s in %s, volume %s, directory %s:" % (n, src_ns, v, path(by.get(v, {}))))
    print("      microk8s kubectl -n %s delete pvc %s; microk8s kubectl delete pv %s; sudo rm -rf %s" % (src_ns, n, v, path(by.get(v, {}))))
    any_ = True
for p in pvs:
    ref = (p.get("spec") or {}).get("claimRef") or {}
    if ref.get("namespace") == src_ns and ref.get("name") == "hub-db-dir" and (p.get("status") or {}).get("phase") == "Released":
        print("  - the old hub database (hub-db-dir), volume %s, directory %s:" % (p["metadata"]["name"], path(p)))
        print("      microk8s kubectl delete pv %s; sudo rm -rf %s" % (p["metadata"]["name"], path(p)))
        any_ = True
used = {path(p) for p in pvs}
for d in sorted(x for x in os.environ.get("ORPHANS", "").splitlines() if x):
    if d not in used:
        print("  - %s: a copy an earlier run made, used by no volume:" % d)
        print("      sudo rm -rf %s" % d)
        any_ = True
if not any_:
    print("  (nothing)")
for line in kept:
    print(line)' "$SRC_NS" "$WB_NS" "${_ADMIN_CLAIM:-}" | while IFS= read -r line; do log "$line"; done
    log "The nightly backup keeps copying these until they are removed (manual: Moving the AI workbench)."
    [[ -z "${_MOVE_CONFLICTS:-}" ]] \
        || warn "not moved, an administrator decides (above): $_MOVE_CONFLICTS"
}
WORKBENCH_DOMAIN="${WORKBENCH_DOMAIN:-ai-workbench.$DOMAIN}"
PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.$DOMAIN}"   # named on the 403 page; where sign-out lands
# Pinned: the tag that ships JupyterLab 4.6.4 with the git panel (@jupyterlab/git
# 0.55.0) and nbdime 4.0.4, as verified on the running server on 2026-10-31. A date
# tag or a digest (name:tag@sha256:…) pins harder; `latest` is accepted with a warning.
WORKBENCH_IMAGE="${WORKBENCH_IMAGE:-quay.io/jupyter/scipy-notebook:latest@sha256:d416eea5c12a44981c2fcb56520649dbd92f7ae5983f4e68e14d1d0ebdf0c2ce}"
# Split here: the values template (k8s/workbench/values.yaml) is filled by
# envsubst, which cannot do ${VAR%:*} itself. A digest stays with the tag (the
# chart writes name:tag), and the name may carry a registry port.
_img="${WORKBENCH_IMAGE%%@*}" _digest=""
[[ "$WORKBENCH_IMAGE" == *@* ]] && _digest="@${WORKBENCH_IMAGE#*@}"
if [[ "${_img##*/}" == *:* ]]; then
    WORKBENCH_IMAGE_NAME="${_img%:*}" WORKBENCH_IMAGE_TAG="${_img##*:}$_digest"
else
    WORKBENCH_IMAGE_NAME="$_img" WORKBENCH_IMAGE_TAG="latest$_digest"
fi
WORKBENCH_STORAGE="${WORKBENCH_STORAGE:-10Gi}"
# The research repository on GitHub the git guide names (OWNER/REPO, IAM 3.2b);
# empty: the guide says to ask an administrator.
WORKBENCH_NOTEBOOK_REPO="${WORKBENCH_NOTEBOOK_REPO:-}"
[[ -z "$WORKBENCH_NOTEBOOK_REPO" || "$WORKBENCH_NOTEBOOK_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
    || die "WORKBENCH_NOTEBOOK_REPO='$WORKBENCH_NOTEBOOK_REPO' is not OWNER/REPO (e.g. smvieira/medcea-notebooks)"

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

# The policy part (IAM 4.2b: a function, shared with --policy-only): the gate and the
# notebooks' hops compiled from the access policy, the hops checked against what runs.
_policy() {
# Fail closed: a policy that does not compile leaves the running hub as it is.
policy_workbench || die "the access policy does not compile to the workbench's gate (python3 apps/iam/compiler/cli.py check)"
if [[ "$WORKBENCH_ALLOW_ALL" == "true" ]]; then
    log "Gate: any realm account (IAM_GATES=false); hub administrator (workbench-admin): $ADMIN_USER"
else
    log "Gate: $WORKBENCH_ALLOWED_GROUPS; hub administrators (workbench-admin): $WORKBENCH_ADMIN_GROUPS (from the access policy)"
fi
# In the research zone the notebooks' hops are the zone's NetworkPolicies (rs-notebooks,
# pa_rsnetpol), never the chart's: no egress list is rendered there.
if [[ "$WB_PLACEMENT" == research ]]; then
    WORKBENCH_EGRESS='[]'
else
policy_workbench_egress || die "the access policy does not compile to the notebooks' network hops (python3 apps/iam/compiler/cli.py check)"
fi
# The A2 hook's switch (values-research.yaml), a Python literal: never `true` inside Python.
if [[ "$WORKBENCH_ALLOW_ALL" == "true" ]]; then WORKBENCH_A2_ALLOW_ALL=True; else WORKBENCH_A2_ALLOW_ALL=False; fi
# Where /hub/logout goes: Keycloak's end-session, then the portal (one-hop sign-out,
# 1 Nov 2026; infra/lib-oauth2-proxy.sh workbench_logout_url).
WORKBENCH_LOGOUT_URL="$(workbench_logout_url)" || die "could not build the workbench's logout URL (python3 missing?)"
# config.env is not enough: the documented order runs this (through ./deploy-infra.sh)
# before the frontend and database deploys switch, so the hops open only when config-api
# runs JWT and the database enforces now. Otherwise none, until this runs again.
if [[ "$WORKBENCH_EGRESS" != "[]" ]]; then
    _pg_pod="$($KUBECTL get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=${PG_RELEASE:-rdbms}" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ "$(pgrst_live_mode "$NAMESPACE" 2>/dev/null || echo unknown)" != jwt || -z "$_pg_pod" ]] \
       || ! pgrst_db_enforcing "$NAMESPACE" "$_pg_pod" "${POSTGRES_DB:-medcea_db}"; then
        WORKBENCH_EGRESS='[]'
        log "WARNING: config.env says IAM_POSTGREST_JWT and IAM_DB_ROLES are true, but config-api or the database has not switched yet: the notebooks get no platform hop. Run ./infra/deploy-workbench.sh again after ./apps/frontend/deploy.sh and ./apps/database/deploy.sh"
    fi
fi
if [[ "$WB_PLACEMENT" == research ]]; then
    log "Notebooks run in the research zone: they read snapshots through lake-api ($RESEARCH_NAMESPACE) and reach no platform service"
elif [[ "$WORKBENCH_EGRESS" == "[]" ]]; then
    log "Notebooks reach no platform service (reading platform data needs IAM_POSTGREST_JWT and IAM_DB_ROLES true)"
else
    log "Notebooks may reach Keycloak and config-api, with each person's own sign-in (network.clients.notebooks)"
fi
}
_policy
[[ "$WORKBENCH_IMAGE_TAG" == latest ]] \
    && log "WARNING: WORKBENCH_IMAGE uses 'latest' without a digest: JupyterLab and its git panel can change under people at any pull"

log "Deploying JupyterHub $CHART_VERSION to https://$WORKBENCH_DOMAIN"

$HELM repo add jupyterhub https://hub.jupyter.org/helm-chart/ >/dev/null 2>&1 || true
$HELM repo update jupyterhub >/dev/null 2>&1 || true

VALUES=$(mktemp /tmp/workbench-values-XXXXXX.yaml)
_MOVE_TMP=""
_cleanup() { rm -f "$VALUES" "${VALUES_RS:-}" "${_LIVE:-}"; [[ -z "${_MOVE_TMP:-}" ]] || rm -rf "$_MOVE_TMP"; }
trap _cleanup EXIT

# --policy-only: the values this run would deploy against the hub's (Secret hub,
# values.yaml, read on stdin as health iamworkbench reads it: it holds the client
# secret), on the policy keys only. Equal: nothing is applied. _policy_keys LIVE WANT
# [OVERLAY]: the overlay (research placement) is merged over WANT as Helm merges values
# (a mapping key by key, anything else replaced, a null removes the key), and the A2
# hook (hub.extraConfig.medcea-a2) is compared too: absent on both sides in the platform.
_policy_keys() {
    python3 -c '
import json, sys, yaml
def merge(a, b):
    out = dict(a)
    for k, v in (b or {}).items():
        if v is None:
            out.pop(k, None)
        elif isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = v
    return out
def keys(v):
    v = v or {}
    c = (v.get("hub") or {}).get("config") or {}
    g = c.get("GenericOAuthenticator") or {}
    wa = ((v.get("hub") or {}).get("loadRoles") or {}).get("workbench-admin") or {}
    return {"allow_all": (c.get("Authenticator") or {}).get("allow_all"),
            "allowed": sorted(g.get("allowed_groups") or []), "message": g.get("custom_403_message"),
            "role_groups": sorted(wa.get("groups") or []), "role_users": sorted(wa.get("users") or []),
            "egress": ((v.get("singleuser") or {}).get("networkPolicy") or {}).get("egress") or [],
            "a2": ((v.get("hub") or {}).get("extraConfig") or {}).get("medcea-a2")}
docs = [yaml.safe_load(open(f)) for f in sys.argv[1:]]
live, want = docs[0], docs[1] or {}
for extra in docs[2:]:
    want = merge(want, extra)
sys.exit(0 if json.dumps(keys(live), sort_keys=True) == json.dumps(keys(want), sort_keys=True) else 1)' "$@"
}

# The example notebooks and their helper, mounted read-only into every server (a
# running server sees a change within a minute; nothing restarts).
if [[ "$_MODE" != scoped ]]; then
$KUBECTL create configmap workbench-examples -n "$WB_NS" --from-file="$REPO_ROOT/k8s/workbench/examples/" \
    --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
log "Example notebooks: ~/medcea-examples (read-only) in every server"
fi

render "$REPO_ROOT/k8s/workbench/values.yaml" WORKBENCH_SECRET WORKBENCH_DOMAIN KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE \
    WORKBENCH_IMAGE_NAME WORKBENCH_IMAGE_TAG WORKBENCH_STORAGE WORKBENCH_NOTEBOOK_REPO WORKBENCH_EGRESS \
    WORKBENCH_ALLOW_ALL WORKBENCH_HUBADMIN_USERS WORKBENCH_ALLOWED_GROUPS WORKBENCH_ADMIN_GROUPS WORKBENCH_403_MESSAGE \
    WORKBENCH_LOGOUT_URL > "$VALUES"
# The research placement's overlay (a second --values): the zone's settings and the A2 hook.
# The base's three platform endpoints (Keycloak, config-api, the device client) are taken out
# of the rendered base, line by line, everything else left byte for byte: Helm 3.9 keeps a
# null an overlay sets for a key the chart's defaults lack, so the overlay cannot remove them.
_research_base() {
    python3 - "$1" <<'PY'
import re, sys
path = sys.argv[1]
lines = open(path).read().splitlines(keepends=True)
drop = re.compile(r"^    (MEDCEA_KEYCLOAK|MEDCEA_API|MEDCEA_CLIENT_ID): ")
kept = [l for l in lines if not drop.match(l)]
if len(lines) - len(kept) != 3:
    sys.exit("the base values' singleuser.extraEnv does not hold exactly the three platform endpoints")
open(path, "w").write("".join(kept))
PY
}
_VALUES_ARGS=(--values "$VALUES")
if [[ "$WB_PLACEMENT" == research ]]; then
    _research_base "$VALUES" || die "cannot take the platform endpoints out of the workbench's values"
    VALUES_RS=$(mktemp /tmp/workbench-values-research-XXXXXX.yaml)
    render "$REPO_ROOT/k8s/workbench/values-research.yaml" RESEARCH_NAMESPACE WORKBENCH_DOMAIN WORKBENCH_ALLOWED_GROUPS \
        WORKBENCH_ADMIN_GROUPS WORKBENCH_HUBADMIN_USERS WORKBENCH_A2_ALLOW_ALL RESEARCH_AGENTS_NAMESPACE > "$VALUES_RS"
    _VALUES_ARGS+=(--values "$VALUES_RS")
fi

if [[ "$_MODE" == scoped ]]; then
    _LIVE=$(mktemp /tmp/workbench-live-XXXXXX.yaml)
    if ! $KUBECTL get secret hub -n "$WB_NS" -o jsonpath='{.data.values\.yaml}' 2>/dev/null | base64 -d > "$_LIVE" 2>/dev/null \
       || [[ ! -s "$_LIVE" ]]; then
        log "WORKBENCH_DOMAIN (workbench): not deployed (./infra/deploy-workbench.sh installs it)"
        policy_source_finish "$NAMESPACE" workbench
        exit 0
    fi
    if _policy_keys "$_LIVE" "$VALUES" ${VALUES_RS:+"$VALUES_RS"}; then
        log "WORKBENCH_DOMAIN (workbench): unchanged"
        policy_source_finish "$NAMESPACE" workbench
        exit 0
    fi
fi

# --move (research Phase 2b): the release and the homes from the other namespace into WB_NS
# (steps 3-8 of codeplan SPEC §2.2; the refusals and the confirmation came first, above).
if [[ "$_MODE" == move ]]; then
    _move
fi

# The research zone: a certificate of its own (before the install, so the ingress never
# serves its default certificate for the host), our Role without Secrets, and the homes of
# an earlier install bound again.
if [[ "$WB_PLACEMENT" == research && "$_MODE" != scoped ]]; then
    workbench_tls_issue "$WB_NS" || die "could not issue the workbench's certificate (Secret workbench-tls in $WB_NS)"
    log "Certificate: Secret workbench-tls in $WB_NS (this host only, from the platform CA)"
    render "$REPO_ROOT/k8s/workbench/hub-rbac.yaml" WB_NS | $KUBECTL apply -f - >/dev/null
    log "Hub permissions: Role medcea-hub in $WB_NS (pods, claims, events; no Secrets, no Services)"
    if [[ -z "$_LIVE_NS" ]]; then
        for _pv in $(workbench_rebind_released "$WB_NS"); do
            log "Volume $_pv (a home kept from an earlier install) can be bound again in $WB_NS"
        done
    fi
fi

$HELM upgrade --install workbench jupyterhub/jupyterhub \
  --version "$CHART_VERSION" \
  --namespace "$WB_NS" \
  "${_VALUES_ARGS[@]}" \
  --timeout 10m

log "Waiting for the hub to become ready..."
$KUBECTL rollout status deployment/hub -n "$WB_NS" --timeout=10m || {
    echo "--- hub pod ---"; $KUBECTL get pods -l app=jupyterhub -n "$WB_NS"
    echo "--- hub logs ---"; $KUBECTL logs -l component=hub -n "$WB_NS" --tail=40 2>/dev/null || true
    die "hub did not become ready"
}

wait_for_http "https://$WORKBENCH_DOMAIN/hub/login" 180 "JupyterHub" || {
    log "The hub rolled out but is not serving through the ingress yet."
    exit 1
}
if [[ "$_MODE" == scoped ]]; then
    log "WORKBENCH_DOMAIN (workbench): re-rendered (gate or notebook hops)"
    policy_source_finish "$NAMESPACE" workbench
    exit 0
fi
log "AI Workbench is live: https://$WORKBENCH_DOMAIN"
log "Sign in with a Keycloak account in realm '$KEYCLOAK_REALM' holding a role the policy admits."
log "The first start of a new home pulls the notebook image and installs real-time"
log "collaboration and VS Code into it before the server answers: a few minutes once,"
log "fast afterwards (the hub waits up to 15 minutes)."
log "A server started before this deploy keeps its old setup (a postStart hook before"
log "1 Nov 2026) until it is stopped and started again."
log "A running server keeps its old environment (the MEDCEA_* endpoints) and its old"
log "mounts until it is stopped and started again (File > Hub Control Panel, or culled"
log "after an hour idle): a server started before ~/medcea-examples existed shows it only"
log "after that restart. Network hops change at once, and the example files refresh"
log "within about a minute in servers that already have the folder."
[[ "$_MODE" == move ]] && _move_report

# The last command of the success path: ends an open policy break-glass for workbench (IAM 4.2a)
policy_source_finish "$NAMESPACE" workbench
