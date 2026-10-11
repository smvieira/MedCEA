#!/usr/bin/env bash
# infra/lib-mk8s.sh — how to call MicroK8s from this process. Sourced by every
# apps/<component>/{deploy,uninstall}.sh.
#
#   mk8s ARGS...      microk8s directly when this process has the microk8s
#                     group, otherwise through sudo
#   MK8S="mk8s"       for "$MK8S helm3 …"
#   KUBECTL="mk8s kubectl"   for "$KUBECTL get …"
#
# Why: bootstrap-infra.sh adds the user to the microk8s group on a fresh
# install, but group membership only reaches new login sessions. A hardcoded
# `microk8s kubectl` then fails with "Insufficient permissions" for the rest of
# the first install — which failed every app on a clean machine. A function,
# not a string, so the explanatory sudo prompt survives word splitting.
# (install.sh avoids the sudo path altogether by running the apps under
# `sg microk8s`.)

if microk8s status --timeout 5 >/dev/null 2>&1; then
    mk8s() { microk8s "$@"; }
else
    mk8s() {
        sudo -p "[sudo] password for %u (MicroK8s — the microk8s group applies after you log in again): " \
            microk8s "$@"
    }
fi
MK8S="mk8s"
KUBECTL="mk8s kubectl"
