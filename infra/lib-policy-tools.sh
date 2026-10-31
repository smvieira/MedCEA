#!/usr/bin/env bash
# infra/lib-policy-tools.sh — the role setting of a tool outside the cluster's
# oauth2-proxies, compiled from the access policy (IAM 3.4). Sourced; defines
# functions only, takes no lock. Needs REPO_ROOT, and config.env sourced first.
#
#   policy_tool edge-wizard   the onboarding wizard's --required-role, e.g.
#                             engineer,maintenance (any one admits)
#   policy_tool pgadmin       pgAdmin's OAUTH2_ADDITIONAL_CLAIMS, a Python literal,
#                             e.g. {'groups': ['admin']}
#
# Both come from `cli.py compile <tool>` (apps/iam/compiler/tools.py, the group's
# `tool:` block). IAM_GATES=false prints the pre-policy setting with a warning:
# EDGE_WIZARD_ROLE for the wizard (empty: any signed-in account may onboard) and
# {'groups': ['admin']} for pgAdmin. With IAM_GATES=true a set EDGE_WIZARD_ROLE is
# ignored with a warning: the policy is the one source. A broken policy returns 1
# and prints nothing, so a caller stops rather than open the tool.
# Used by deploy-infra.sh (pgAdmin), edge/wizard-daemon.sh, edge/flash-device.sh,
# apps/edge-wizard/deploy.sh, health-check.sh and tests/iam-hosts.sh.
policy_tool() {
    local out
    case "$1" in
        edge-wizard|pgadmin) ;;
        *) echo "policy_tool: unknown tool '$1' (edge-wizard, pgadmin)" >&2; return 2 ;;
    esac
    if [[ "${IAM_GATES:-true}" == "false" ]]; then
        echo -e "\033[0;33mWARNING: IAM_GATES=false — $1 gets the pre-policy setting, not the access policy.\033[0m" >&2
        if [[ "$1" == pgadmin ]]; then
            echo "{'groups': ['admin']}"
        else
            echo "${EDGE_WIZARD_ROLE:-}"
        fi
        return 0
    fi
    out="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile "$1")" || return 1
    [[ -n "$out" ]] || return 1
    if [[ "$1" == edge-wizard && -n "${EDGE_WIZARD_ROLE:-}" ]]; then
        echo -e "\033[0;33mWARNING: EDGE_WIZARD_ROLE=${EDGE_WIZARD_ROLE} is ignored: the access policy decides ($out); remove it from config.env.\033[0m" >&2
    fi
    echo "$out"
}
