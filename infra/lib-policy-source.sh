#!/usr/bin/env bash
# infra/lib-policy-source.sh — where every compile of the access policy reads it
# (IAM Phase 4, design §3.4). Sourced by each ENTRY script that compiles the policy,
# after config.env and lib-mk8s.sh; defines functions only, takes no lock.
#
#   policy_source_init NS              before the first compile of a deploy
#   policy_source_init NS --read-only  health-check.sh and the live tests: never writes,
#                                      and first unsets an inherited MEDCEA_POLICY_FILE,
#                                      MEDCEA_POLICY_BREAK_GLASS and MEDCEA_POLICY_SOURCE_DONE,
#                                      so a check never trusts a source its parent chose
#
# cli.py itself picks the source (compiler/source.py): MEDCEA_POLICY_FILE with
# MEDCEA_POLICY_BREAK_GLASS, else the host applied file state/policy-applied.yaml, else
# apps/iam/policy/defaults.yaml. From slice 4.2a this function reads the database's
# applied version, runs the skeleton gate and (re)writes the host file under the lock.
#
# Slice 4.0 (now): no applied version exists anywhere and nothing reads the database
# here (no kubectl). Every compile therefore reads defaults.yaml exactly as before. What
# already holds:
#   - a deploy refuses MEDCEA_POLICY_FILE: break-glass is recorded in the hash chain
#     before it is used, and that record arrives with slice 4.2a;
#   - a deploy refuses a state/policy-applied.yaml: nothing can have written one yet, and
#     nothing verifies it against the database before 4.2a;
#   - --read-only reports a host file it finds and changes nothing.
# It runs once per process: MEDCEA_POLICY_SOURCE_DONE (not exported here) makes a second
# call a no-op when it names the lock this process holds (MEDCEA_LOCK_HELD). A parent
# that verifies for its children (deploy-apps, install, apply.sh; from 4.2a) exports it.
#
# NOT sourced by infra/lib-policy-tools.sh or edge/: the onboarding daemon and
# flash-device.sh compile at boot or without the microk8s group; they only read the host
# file through cli.py (an unreadable state/ is exit 2 there, never a silent defaults).
# policy_tool refuses an inherited MEDCEA_POLICY_FILE unless this function has run in
# the same shell (MEDCEA_POLICY_SOURCE_DONE), so edge/ never compiles a break-glass file.

POLICY_HOST_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/state/policy-applied.yaml"

policy_source_init() {
    local ns="${1:-}" mode="${2:-}"
    if [[ -z "$ns" ]]; then
        echo "policy_source_init: usage: policy_source_init NS [--read-only]" >&2
        return 2
    fi
    if [[ "$mode" == --read-only ]]; then
        unset MEDCEA_POLICY_FILE MEDCEA_POLICY_BREAK_GLASS MEDCEA_POLICY_SOURCE_DONE
        if [[ -e "$POLICY_HOST_FILE" ]]; then
            echo -e "\033[0;33mWARNING: $POLICY_HOST_FILE exists, but nothing writes it before IAM Phase 4 slice 4.2a: every compile here reads it instead of defaults.yaml.\033[0m" >&2
        fi
        return 0
    elif [[ -n "$mode" ]]; then
        echo "policy_source_init: unknown option '$mode' (--read-only)" >&2
        return 2
    fi
    if [[ -n "${MEDCEA_POLICY_SOURCE_DONE:-}" && "$MEDCEA_POLICY_SOURCE_DONE" == "${MEDCEA_LOCK_HELD:-}" ]]; then
        return 0
    fi
    if [[ -n "${MEDCEA_POLICY_FILE:-}" ]]; then
        echo -e "\033[0;31mERROR: MEDCEA_POLICY_FILE is set: a deploy compiles the applied policy only. Break-glass needs its hash-chain record, which arrives with IAM Phase 4 slice 4.2a. Unset MEDCEA_POLICY_FILE (and MEDCEA_POLICY_BREAK_GLASS) and re-run.\033[0m" >&2
        return 1
    fi
    if [[ -e "$POLICY_HOST_FILE" ]]; then
        echo -e "\033[0;31mERROR: $POLICY_HOST_FILE exists, but nothing writes or verifies it before IAM Phase 4 slice 4.2a. Move it away (it would replace defaults.yaml in every compile) and re-run.\033[0m" >&2
        return 1
    fi
    MEDCEA_POLICY_SOURCE_DONE="${MEDCEA_LOCK_HELD:-$$}"
    return 0
}
