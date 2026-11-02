#!/usr/bin/env bash
# infra/lib-lock.sh — one deploy at a time.
#
#   medcea_lock         take the platform lock, or exit naming the run that has it
#   medcea_lock_verify  return 0 only when this run really holds it (IAM 4.2a: every write
#                       of the access policy's state checks it; medcea_lock itself trusts
#                       an inherited MEDCEA_LOCK_HELD, which its callers and tests rely on)
#
# Every script that changes the cluster or config.env calls it once, after its
# --help branch: two runs side by side interleave helm releases, Keycloak
# clients and config.env rewrites, and a run waiting at a prompt reads its own
# script from disk, so it must not be edited (or rerun) underneath.
#
# The lock is flock(2) on fd 9 of .medcea.lock, not a PID file: the kernel
# drops it the moment the holder dies (kill -9, closed terminal), so there is
# never a stale lock to judge, and no PID-reuse or check-then-write race. The
# file's text — PID, start time, terminal, command — only explains the refusal;
# nothing decides on it.
#
# The first script to lock exports MEDCEA_LOCK_HELD, so the scripts it runs
# (install.sh → deploy-infra.sh → configure.sh, deploy-apps.sh → apps/*/deploy.sh)
# skip it instead of blocking on their own parent.
#
# A background job inherits fd 9 and would keep holding the lock after the
# script ends: start it with `9>&-` (see the kubectl port-forwards).

MEDCEA_LOCK_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.medcea.lock"

# PIDs (own user's, or all when root) with the lock file open — the real
# holders, which includes a leftover child of a run that is already gone.
_lock_holders() {
    local fd pid
    for fd in /proc/[0-9]*/fd/*; do
        [[ "$(readlink "$fd" 2>/dev/null)" == "$MEDCEA_LOCK_FILE" ]] || continue
        pid="${fd#/proc/}"; echo "${pid%%/*}"
    done | sort -un
}

medcea_lock() {
    [[ -n "${MEDCEA_LOCK_HELD:-}" ]] && return 0
    # >> not >: opening must not wipe the holder's line before we know we hold it.
    exec 9>>"$MEDCEA_LOCK_FILE"
    if ! flock -n 9; then
        local holder pid holders
        IFS=$'\t' read -r pid holder < "$MEDCEA_LOCK_FILE" 2>/dev/null || true
        exec 9>&-
        holders="$(_lock_holders)"
        echo -e "\033[0;31mAnother MedCEA deploy is already running:\033[0m" >&2
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            # The group, not the PID: a helm --wait or rollout status the run is
            # waiting on would outlive a plain kill and keep holding the lock.
            local pgid; pgid="$(ps -o pgid= -p "$pid" | tr -d ' ')"
            echo "  PID $pid  $holder" >&2
            echo "Wait for it to finish, or stop it with:  kill -- -$pgid" >&2
        elif [[ -n "$holders" ]]; then
            # The run that wrote the file is gone; what is left is a child it started.
            echo "  The run that started it has ended; these leftover processes still hold the lock:" >&2
            ps -o pid=,lstart=,args= -p "$(paste -sd, <<<"$holders")" | sed 's/^/  /' >&2
            echo "Stop them with:  kill $(paste -sd' ' <<<"$holders")" >&2
        else
            # Held by a process this user cannot inspect (a run under sudo).
            echo "  ${holder:-(unknown)} — possibly as another user (sudo)." >&2
            echo "Find it with:  sudo fuser -v $MEDCEA_LOCK_FILE" >&2
        fi
        exit 1
    fi
    local term
    term="$(tty 2>/dev/null)" || term="none"
    printf '%s\tstarted %s, terminal %s: %s\n' "$$" "$(date '+%F %T')" \
        "${term#/dev/}" "$(ps -o args= -p $$)" > "$MEDCEA_LOCK_FILE"
    export MEDCEA_LOCK_HELD=$$
}

# medcea_lock_verify — 0 only when MEDCEA_LOCK_HELD names a live process that is this
# shell or an ancestor of it (/proc/<pid>/stat's 4th field, walked up from $$), whose fd 9
# is $MEDCEA_LOCK_FILE, and a fresh flock -n on a new descriptor of that file fails (the
# lock is really held). Prints nothing; 1 otherwise. Takes no lock (the probe's own
# descriptor is closed with its subshell; on success it held nothing worth keeping).
medcea_lock_verify() {
    local held="${MEDCEA_LOCK_HELD:-}" p="$$" stat rest
    [[ "$held" =~ ^[1-9][0-9]*$ ]] || return 1
    while [[ "$p" != "$held" ]]; do
        [[ "$p" =~ ^[0-9]+$ && "$p" -gt 1 ]] || return 1
        stat="$(cat "/proc/$p/stat" 2>/dev/null)" || return 1
        rest="${stat##*) }"            # after the command name, which may hold spaces
        read -r _ p _ <<<"$rest"       # state, ppid
    done
    [[ "$(readlink "/proc/$held/fd/9" 2>/dev/null)" == "$MEDCEA_LOCK_FILE" ]] || return 1
    # a new open file description of the lock file must not get the lock
    ! ( exec 8>>"$MEDCEA_LOCK_FILE" && flock -n 8 ) 2>/dev/null
}
