#!/usr/bin/env bash
# infra/lib-dockerhub.sh — MicroK8s's Docker Hub credentials for containerd
# (certs.d/docker.io/hosts.toml), written only when its content differs.
#
# Sourced by deploy-infra.sh and infra/bootstrap-infra.sh. Until 17 Nov 2026 deploy-infra
# decided with two `sudo grep`s whether to rewrite the file and restart containerd: a
# mistyped sudo password made both greps fail, which read as "the credentials differ", so
# the file was rewritten unchanged and containerd restarted. On kernels from 7.0.0-41 a
# containerd restart leaves the pods already running on MicroK8s's stock AppArmor profile
# (infra/lib-apparmor.sh), and their signals are denied until each is restarted.
#
# dockerhub_hosts_sync asks sudo first (-v, with the caller's prompt; a refusal stops there)
# and passes the same prompt to the comparison and the write, so a host whose sudo keeps no
# timestamp (timestamp_timeout=0) asks again instead of failing; it keeps "sudo refused"
# apart from "the content differs": the comparison is the whole file, byte for
# byte, against what this library renders. The password reaches the file through a pipe
# (printf is a builtin), never through argv.

DOCKERHUB_HOSTS_DIR="${DOCKERHUB_HOSTS_DIR:-/var/snap/microk8s/current/args/certs.d/docker.io}"

# The file as deploy-infra and the bootstrap have always written it (byte for byte, so an
# existing file compares equal and nothing is restarted).
_dockerhub_hosts_content() {
    printf '%s\n' \
        'server = "https://registry-1.docker.io"' \
        '' \
        '[host."https://registry-1.docker.io"]' \
        '  capabilities = ["pull", "resolve"]' \
        '  [host."https://registry-1.docker.io".auth]' \
        "    username = \"${DOCKERHUB_USER}\"" \
        "    password = \"${DOCKERHUB_PASS}\""
}

# dockerhub_hosts_sync PROMPT
#   0  the file already holds exactly these credentials: nothing written
#   10 written (absent or different): the caller decides whether containerd must restart
#   1  could not check or write (sudo refused, no credentials, a write that failed):
#      nothing was restarted, and the caller must not restart either
dockerhub_hosts_sync() {
    local prompt="${1:-[sudo] password for %u (MicroK8s registry credentials): }"
    local sudo="${DOCKERHUB_SUDO:-sudo}" file="$DOCKERHUB_HOSTS_DIR/hosts.toml" rc
    [[ -n "${DOCKERHUB_USER:-}" && -n "${DOCKERHUB_PASS:-}" ]] || return 1
    $sudo -p "$prompt" -v || return 1
    # The comparison prints its own exit code, so a sudo that fails here (empty output)
    # is never read as "differs".
    rc="$(_dockerhub_hosts_content | $sudo -p "$prompt" sh -c \
        'if [ -f "$1" ]; then cmp -s - "$1"; echo "$?"; else cat >/dev/null; echo absent; fi' \
        sh "$file" 2>/dev/null)" || return 1
    case "$rc" in
        0) return 0 ;;
        1|2|absent) ;;
        *) return 1 ;;
    esac
    _dockerhub_hosts_content | $sudo -p "$prompt" sh -c \
        'umask 077 && mkdir -p "$1" && cat > "$1/.hosts.toml.new" && mv -f "$1/.hosts.toml.new" "$1/hosts.toml"' \
        sh "$DOCKERHUB_HOSTS_DIR" || return 1
    return 10
}
