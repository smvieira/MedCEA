#!/usr/bin/env bash
# infra/lib-prereqs.sh — host packages the scripts need, sourced by
# infra/configure.sh (so every ./deploy-infra.sh run checks them first) and by
# deploy-apps.sh.
#
# The target is a clean Ubuntu, and "clean" differs by flavour: 24.04 desktop
# ships without curl, server and cloud images without python3-venv, minimal and
# LXD images sometimes without snapd. Each of those otherwise surfaces as an
# obscure failure deep in a deploy (an empty Keycloak token, a `sh` that
# "succeeds" on an empty pipe), so they are checked up front, by default.
#
#   check_prereqs    report what is missing; offer to apt-get install it;
#                    exit if it is still missing. A no-op when all present.
#
# Only host-side tools are listed. psql, for instance, runs inside the Postgres
# pod through kubectl exec, and MicroK8s/Helm/kubectl come from the snap that
# bootstrap-infra.sh installs.

# test|apt-package|what needs it — the test is evaluated, so it can check more
# than a command (python3-venv is a module, not a binary).
_PREREQS=(
    "command -v curl|curl|Keycloak/Grafana API calls, readiness checks, downloads"
    "[ -s /etc/ssl/certs/ca-certificates.crt ]|ca-certificates|HTTPS downloads (Docker Hub, Tailscale, Helm charts)"
    "command -v openssl|openssl|the platform CA, TLS certificate and cookie secrets"
    "command -v python3|python3|JSON handling in the deploy scripts"
    "python3 -c 'import ensurepip' 2>/dev/null|python3-venv|edge/flash-device.sh (builds its esptool/mpremote venv)"
    "command -v envsubst|gettext-base|filling the manifest templates in k8s/ (infra/lib-render.sh)"
    "command -v ip|iproute2|LAN IP detection"
    "command -v flock|util-linux|one deploy at a time (infra/lib-lock.sh)"
    "python3 -c 'import yaml' 2>/dev/null|python3-yaml|the access-policy compiler (apps/iam/compiler)"
    "command -v snap|snapd|installing MicroK8s"
)

check_prereqs() {
    local entry test pkg why sudo="" ans
    local -a missing=() reasons=()
    for entry in "${_PREREQS[@]}"; do
        IFS='|' read -r test pkg why <<<"$entry"
        eval "$test" >/dev/null 2>&1 && continue
        missing+=("$pkg"); reasons+=("$(printf '%-16s %s' "$pkg" "$why")")
    done
    [[ ${#missing[@]} -eq 0 ]] && return 0

    if [[ $EUID -ne 0 ]]; then
        command -v sudo >/dev/null 2>&1 \
            || { echo -e "\033[0;31mERROR: missing ${missing[*]}, and sudo is not available. Run as root or install sudo.\033[0m" >&2; exit 1; }
        sudo="sudo"
    fi
    local cmd="$sudo apt-get update && $sudo apt-get install -y ${missing[*]}"

    echo ""
    echo -e "\033[0;33mThis machine is missing packages the installer needs:\033[0m"
    printf '  %s\n' "${reasons[@]}"
    echo "  Install them with:"
    echo -e "    \033[0;36m${cmd# }\033[0m"
    if [[ ! -t 0 ]]; then
        echo -e "\033[0;31mERROR: no terminal to ask on — run the command above, then run this again.\033[0m" >&2
        exit 1
    fi
    while true; do
        read -r -p "  Install them now? (y/n) [y]: " ans || { echo ""; exit 1; }
        case "${ans:-y}" in
            [yY]|yes) break ;;
            [nN]|no)  echo -e "\033[0;31mERROR: cannot continue without: ${missing[*]}\033[0m" >&2; exit 1 ;;
        esac
    done

    $sudo apt-get update \
        && $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" \
        || { echo -e "\033[0;31mERROR: apt-get failed — see the output above.\033[0m" >&2; exit 1; }
    # A freshly installed snapd is socket-activated and its binaries live in
    # /snap/bin, which this shell's PATH predates.
    if [[ " ${missing[*]} " == *" snapd "* ]]; then
        $sudo systemctl enable --now snapd.socket >/dev/null 2>&1 || true
        export PATH="$PATH:/snap/bin"
    fi

    for entry in "${_PREREQS[@]}"; do
        IFS='|' read -r test pkg why <<<"$entry"
        eval "$test" >/dev/null 2>&1 \
            || { echo -e "\033[0;31mERROR: $pkg is still missing after apt-get.\033[0m" >&2; exit 1; }
    done
    echo -e "\033[0;32mInstalled: ${missing[*]}\033[0m"
}
