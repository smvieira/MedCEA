#!/usr/bin/env bash
# infra/lib-policy-tools.sh — the role setting of a tool outside the cluster's
# oauth2-proxies, compiled from the access policy (IAM 3.4). Sourced; defines
# functions only, takes no lock. Needs REPO_ROOT, and config.env sourced first.
#
#   policy_tool edge-wizard   the onboarding wizard's --required-role, e.g.
#                             engineer,maintenance (any one admits)
#   policy_tool pgadmin       pgAdmin's OAUTH2_ADDITIONAL_CLAIMS, a Python literal,
#                             e.g. {'groups': ['admin']}
#   policy_tool superset      Superset's AUTH_ROLES_MAPPING, one JSON line, e.g.
#                             {"engineer": ["Alpha", "sql_lab"], "qp": ["Gamma", "MedCEA Viewer"]}
#                             (Superset stages B and C, 6–7 Nov 2026)
#
# Each comes from `cli.py compile <tool>` (apps/iam/compiler/tools.py, the group's
# `tool:` block). IAM_GATES=false prints the pre-policy setting with a warning:
# EDGE_WIZARD_ROLE for the wizard (empty: any signed-in account may onboard) and
# {'groups': ['admin']} for pgAdmin. Superset has no pre-policy setting: under
# IAM_GATES=false it returns 3 and prints nothing (apps/superset/deploy.sh skips). While the
# policy has no group with a superset tool block (`cli.py has-tool superset --admitting`
# exit 1), or that group gives no role a setting yet (exit 3: the skeleton version before
# the change version with its cells), it returns 5 and prints nothing, so the deploy can
# tell "not in the applied policy, or nobody admitted" (skip) from a broken policy (1,
# refuse). With IAM_GATES=true a set EDGE_WIZARD_ROLE is
# ignored with a warning: the policy is the one source. A broken policy returns 1
# and prints nothing, so a caller stops rather than open the tool.
# Used by deploy-infra.sh (pgAdmin), edge/wizard-daemon.sh, edge/flash-device.sh,
# apps/edge-wizard/deploy.sh, apps/superset/deploy.sh, health-check.sh and tests/iam-hosts.sh.
#
# The source (IAM Phase 4): this library never chooses one (it does not source
# lib-policy-source.sh), but it refuses MEDCEA_POLICY_FILE unless this run's entry script
# recorded it (IAM 4.2a): MEDCEA_POLICY_SOURCE_DONE, MEDCEA_POLICY_BREAK_GLASS_EVENT
# (the break_glass_seen event) and MEDCEA_POLICY_BREAK_GLASS_SHA256 set, and the file's
# sha256 equal to the last (policy_source_init points MEDCEA_POLICY_FILE at its snapshot
# in state/break-glass/). The edge scripts never run the init, so a break-glass draft
# exported in an operator's shell cannot silently set who may onboard; health-check
# drops the override.
policy_tool() {
    local out
    case "$1" in
        edge-wizard|pgadmin|superset) ;;
        *) echo "policy_tool: unknown tool '$1' (edge-wizard, pgadmin, superset)" >&2; return 2 ;;
    esac
    if [[ "${IAM_GATES:-true}" == "false" && "$1" == superset ]]; then
        echo -e "\033[0;33mWARNING: IAM_GATES=false — Superset has no pre-policy setting: it is not deployed.\033[0m" >&2
        return 3
    fi
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        echo -e "\033[0;33mWARNING: IAM_GATES=false — $1 gets the pre-policy setting, not the access policy.\033[0m" >&2
        if [[ "$1" == pgadmin ]]; then
            echo "{'groups': ['admin']}"
        else
            echo "${EDGE_WIZARD_ROLE:-}"
        fi
        return 0
    fi
    if [[ -n "${MEDCEA_POLICY_FILE:-}" ]]; then
        if [[ -z "${MEDCEA_POLICY_SOURCE_DONE:-}" || -z "${MEDCEA_POLICY_BREAK_GLASS_EVENT:-}" \
              || -z "${MEDCEA_POLICY_BREAK_GLASS_SHA256:-}" ]]; then
            echo -e "\033[0;31mERROR: MEDCEA_POLICY_FILE is set: $1 compiles the applied policy only, unless this run's deploy recorded the break-glass first. Unset MEDCEA_POLICY_FILE (and MEDCEA_POLICY_BREAK_GLASS) and re-run.\033[0m" >&2
            return 1
        fi
        if [[ ! -r "$MEDCEA_POLICY_FILE" \
              || "$(sha256sum <"$MEDCEA_POLICY_FILE" | cut -d' ' -f1)" != "$MEDCEA_POLICY_BREAK_GLASS_SHA256" ]]; then
            echo -e "\033[0;31mERROR: MEDCEA_POLICY_FILE ($MEDCEA_POLICY_FILE) is not the break-glass file this run recorded (event ${MEDCEA_POLICY_BREAK_GLASS_EVENT}): its sha256 differs.\033[0m" >&2
            return 1
        fi
    fi
    if [[ "$1" == superset ]]; then
        local rc=0
        python3 "$REPO_ROOT/apps/iam/compiler/cli.py" has-tool superset --admitting || rc=$?
        case "$rc" in
            0) ;;
            1) echo "policy_tool: Superset is not in the applied access policy (no group has a superset tool block)." >&2
               return 5 ;;
            3) echo "policy_tool: Superset's policy group gives no role a setting yet" >&2
               return 5 ;;
            *) return 1 ;;
        esac
    fi
    out="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile "$1")" || return 1
    [[ -n "$out" ]] || return 1
    if [[ "$1" == edge-wizard && -n "${EDGE_WIZARD_ROLE:-}" ]]; then
        echo -e "\033[0;33mWARNING: EDGE_WIZARD_ROLE=${EDGE_WIZARD_ROLE} is ignored: the access policy decides ($out); remove it from config.env.\033[0m" >&2
    fi
    echo "$out"
}

# ── where the AI workbench runs (research sandbox Phase 2b) ──────────────────────────────
#
#   workbench_placement   prints `research` when the access policy names the hub as a pod of
#                         the research zone (network.pods.hub, zone: research: commit B),
#                         `platform` otherwise (no hub pod, or one without a zone); returns 1
#                         and prints nothing when the policy cannot be read (cli.py pod-zone
#                         exit 2). Placement is skeleton: IAM_GATES does not change it, and it
#                         never keys on research_workbench's zone (the 2a policy has that).
#   workbench_namespace   the namespace of that placement: ${RESEARCH_NAMESPACE:-<NAMESPACE>-research}
#                         for research, $NAMESPACE for platform; returns 1 likewise.
#
# Like _pa_rs_zone, no MEDCEA_POLICY_FILE guard: the answer is the skeleton's, which a
# break-glass file may not change (policy_source_init refuses one whose skeleton differs).
workbench_placement() {
    local _out _rc=0
    _out="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" pod-zone hub)" || _rc=$?
    case "$_rc" in
        0) if [[ "$_out" == research ]]; then echo research; else echo platform; fi ;;
        1) echo platform ;;
        *) echo "workbench_placement: cannot read the access policy (python3 apps/iam/compiler/cli.py pod-zone hub exited $_rc)" >&2
           return 1 ;;
    esac
}

workbench_namespace() {
    local _pl
    _pl="$(workbench_placement)" || return 1
    if [[ "$_pl" == research ]]; then
        echo "${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
    else
        echo "$NAMESPACE"
    fi
}

# ── the research zones' namespaces and their NetworkPolicy arguments (research Phase 4a, R2/R18) ──
#
#   zone_namespace ZONE    the namespace of a research zone: research, research-gw or research-agents
#                          (RESEARCH_NAMESPACE, RESEARCH_GW_NAMESPACE, RESEARCH_AGENTS_NAMESPACE, each
#                          defaulting to ${RESEARCH_NAMESPACE:-${NAMESPACE}-research} plus -gw / -agents).
#   zone_netpol_args ZONE  prints, one per line, what `cli.py compile netpol` needs for that zone:
#                          --zone Z --namespace NS --platform-namespace $NAMESPACE and a
#                          --zone-namespace pair for each of the other two zones. The caller adds its
#                          --node-ip arguments. (research Phase 4a stage 6b1: the two new zones' scripts
#                          use it; pa_rsnetpol keeps its own argument list until commit B moves it, since
#                          the tests pin that argv.)
zone_namespace() {
    local _rns="${RESEARCH_NAMESPACE:-${NAMESPACE}-research}"
    case "$1" in
        research)        echo "$_rns" ;;
        research-gw)     echo "${RESEARCH_GW_NAMESPACE:-${_rns}-gw}" ;;
        research-agents) echo "${RESEARCH_AGENTS_NAMESPACE:-${_rns}-agents}" ;;
        *) echo "zone_namespace: unknown zone '$1'" >&2; return 2 ;;
    esac
}

zone_netpol_args() {
    local _z="$1" _o
    zone_namespace "$_z" >/dev/null || return 2
    printf '%s\n' --zone "$_z" --namespace "$(zone_namespace "$_z")" --platform-namespace "$NAMESPACE"
    for _o in research research-gw research-agents; do
        [[ "$_o" == "$_z" ]] || printf '%s\n' --zone-namespace "$_o=$(zone_namespace "$_o")"
    done
}
