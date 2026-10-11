#!/usr/bin/env bash
# infra/lib-sudo.sh — borrow classic sudo while MicroK8s is being managed.
#
#   classic_sudo_begin   if sudo is sudo-rs, point the `sudo` alternative at
#                        classic sudo (sudo.ws) and arm a trap that puts it back
#                        when this process exits, fails or is interrupted
#   classic_sudo_end     put it back now (also what the trap runs)
#
# Why: every privileged step inside the MicroK8s snap — `microk8s start`, addon
# enables, apiserver restarts — goes through run_with_sudo in
# $SNAP/actions/common/utils.sh, which runs `sudo -E …` unconditionally, even as
# root. sudo-rs, the default sudo since Ubuntu 25.10, ignores -E, so those steps
# lose SNAP/SNAP_DATA/SNAP_COOKIE and fail ("snapctl … from outside of a snap";
# `enable rbac` dying after "No callback tokens file."). A running cluster never
# goes through that path (systemd starts the daemons, snapd runs refresh hooks),
# so only bootstrap-infra.sh needs it, and only for as long as it runs
# (remove_microk8s uses snapd directly and never needs it). The machine keeps
# the sudo its Ubuntu release chose.
#
# The trap takes EXIT, INT and TERM, so a script that sources this must not set
# its own traps on those. Only SIGKILL or a power cut can leave classic sudo in
# place, which is harmless; `sudo update-alternatives --auto sudo` undoes it.

_SUDO_RESTORE=""   # the update-alternatives arguments that undo the switch

classic_sudo_begin() {
    [[ -n "$_SUDO_RESTORE" ]] && return 0
    sudo --version 2>/dev/null | grep -q '^sudo-rs' || return 0
    if [[ ! -x /usr/bin/sudo.ws ]]; then
        echo -e "\033[0;31mERROR: sudo is sudo-rs, which MicroK8s cannot work under, and classic sudo\033[0m" >&2
        echo -e "\033[0;31m(/usr/bin/sudo.ws) is not installed. Install it: sudo apt-get install sudo\033[0m" >&2
        exit 1
    fi
    local mode prev
    mode=$(update-alternatives --query sudo | awk '/^Status:/ {print $2}')
    prev=$(update-alternatives --query sudo | awk '/^Value:/ {print $2}')
    if [[ "$mode" == auto ]]; then _SUDO_RESTORE="--auto sudo"; else _SUDO_RESTORE="--set sudo $prev"; fi

    echo -e "\033[0;33mUsing classic sudo while MicroK8s is managed (sudo-rs ignores 'sudo -E'; restored afterwards).\033[0m"
    sudo -p "[sudo] password for %u (switching to classic sudo for MicroK8s): " \
        update-alternatives --set sudo /usr/bin/sudo.ws >/dev/null \
        || { _SUDO_RESTORE=""; echo -e "\033[0;31mERROR: could not switch sudo.\033[0m" >&2; exit 1; }
    trap classic_sudo_end EXIT
    trap 'classic_sudo_end; exit 130' INT
    trap 'classic_sudo_end; exit 143' TERM
}

classic_sudo_end() {
    [[ -n "$_SUDO_RESTORE" ]] || return 0
    # Classic sudo keeps its own credential cache, so this may ask once more.
    # shellcheck disable=SC2086
    sudo -p "[sudo] password for %u (restoring the system sudo): " \
        update-alternatives $_SUDO_RESTORE >/dev/null \
        && echo -e "\033[0;32mSystem sudo restored.\033[0m" \
        || echo -e "\033[0;31mWARNING: could not restore sudo — run: sudo update-alternatives $_SUDO_RESTORE\033[0m" >&2
    _SUDO_RESTORE=""
}
