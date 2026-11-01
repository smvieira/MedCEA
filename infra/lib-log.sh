#!/usr/bin/env bash
# infra/lib-log.sh — medcea_log NAME: tee this script's output (stdout and stderr)
# to logs/NAME-<timestamp>.log, mode 600, and say where.
#
# A no-op when a parent already logs (MEDCEA_LOG_FILE, exported here and by
# deploy-infra.sh and deploy-apps.sh), so a component deploy run by deploy-apps
# lands in deploy-apps' log once, not twice. Call it BEFORE medcea_lock: tee is a
# child of this shell and would otherwise inherit the lock's fd 9 and hold the
# lock for as long as anything still writes to it.
#
# Everything on stdout and stderr is kept, so the same rule as deploy-infra's log
# applies: never echo a password or a token (CLAUDE.md, Common Pitfalls). A prompt
# still reaches the terminal (through tee); what is typed at it is not logged.
# MEDCEA_NO_LOG=1 turns it off for one run.

medcea_log() {
    local name="$1" root dir
    [[ -n "${MEDCEA_LOG_FILE:-}" || "${MEDCEA_NO_LOG:-}" == 1 ]] && return 0
    root="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
    dir="$root/logs"
    mkdir -p "$dir" || return 0
    MEDCEA_LOG_FILE="$dir/$name-$(date +%Y%m%d-%H%M%S).log"
    (umask 077; : >> "$MEDCEA_LOG_FILE") || { MEDCEA_LOG_FILE=""; return 0; }
    export MEDCEA_LOG_FILE
    exec > >(tee -a "$MEDCEA_LOG_FILE") 2>&1
    echo "Log: $MEDCEA_LOG_FILE"
}
