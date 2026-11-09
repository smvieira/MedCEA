# infra/lib-apparmor.sh — the stacked-peer rules in MicroK8s's container AppArmor profile.
#
# Sourced by deploy-infra.sh (aa_containerd_fix before the bootstrap; aa_containerd_remove
# in --uninstall) and health-check.sh (aa_status, check "Container AppArmor").
#
# From Ubuntu kernel 7.0.0-41, Ubuntu's default kernel.apparmor_restrict_unprivileged_unconfined=1
# turns runc's change to the container profile into a stack: a container's processes are
# labelled "cri-containerd.apparmor.d//&unconfined", which MicroK8s's profile does not name,
# so signals inside a container are denied (PostgreSQL hangs in recovery, nginx cannot
# reload, Go loses SIGURG; 8 Nov 2026, kernels 42 and 43; containerd#14485). The fix:
#   - infra/apparmor/containerd-apparmor.sh, installed root-owned as
#     $AA_LIB_DIR/reapply: MicroK8s's profile + four rules (signal and ptrace with the
#     plain and the stacked label), loaded; host profiles that attach inside a container
#     (mosquitto) disabled while the host lacks their binary;
#   - <project>-containerd-apparmor.path watches /etc/apparmor.d/cri-containerd.apparmor.d,
#     which MicroK8s's containerd wrapper overwrites at every containerd start, and
#     starts <project>-containerd-apparmor.service, which also runs at boot.
# The sysctl stays as Ubuntu sets it. Nothing here restarts containerd or a pod: a
# replaced profile applies to running processes at once.
#
# Test overrides: AA_SECURITYFS AA_SRC AA_DIR AA_SYSTEMD_DIR AA_LIB_ROOT AA_PROC
# AA_SYSTEMCTL AA_JOURNALCTL AA_SUDO.

_AA_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AA_MARKER="# medcea: stacked-peer rules (containerd#14485)"

aa_names() {
    AA_UNIT="${PROJECT_NAME:-medcea}-containerd-apparmor"
    AA_LIB_DIR="${AA_LIB_ROOT:-/usr/local/lib}/${PROJECT_NAME:-medcea}-apparmor"
    AA_SYSTEMD="${AA_SYSTEMD_DIR:-/etc/systemd/system}"
    AA_SECFS="${AA_SECURITYFS:-/sys/kernel/security/apparmor}"
    AA_MK8S_PROFILE="${AA_SRC:-/snap/microk8s/current/containerd-profile}"
    AA_ETC="${AA_DIR:-/etc/apparmor.d}"
    AA_DST="$AA_ETC/cri-containerd.apparmor.d"
    _AA_SYSTEMCTL="${AA_SYSTEMCTL:-systemctl}"
    _AA_SUDO="${AA_SUDO-sudo -p}"
}

# the two units, rendered into DIR
_aa_render_units() {
    local dir="$1" u
    declare -F render >/dev/null || source "$_AA_HERE/lib-render.sh"
    for u in service path; do
        AA_UNIT="$AA_UNIT" AA_LIB_DIR="$AA_LIB_DIR" PROJECT_NAME="${PROJECT_NAME:-medcea}" \
            render "$_AA_HERE/apparmor/containerd-apparmor.$u" AA_UNIT AA_LIB_DIR PROJECT_NAME \
            > "$dir/$AA_UNIT.$u" || return 1
    done
}

_aa_sudo() {
    # shellcheck disable=SC2086
    if [[ -z "$_AA_SUDO" ]]; then "$@"; else $_AA_SUDO "[sudo] password for %u (AppArmor rules for the cluster's containers): " "$@"; fi
}

# 0 when the installed files equal the repository's, the path unit is enabled and
# active, and the live profile carries the rules
_aa_in_place() {
    local tmpd="$1" u
    cmp -s "$_AA_HERE/apparmor/containerd-apparmor.sh" "$AA_LIB_DIR/reapply" || return 1
    for u in service path; do cmp -s "$tmpd/$AA_UNIT.$u" "$AA_SYSTEMD/$AA_UNIT.$u" || return 1; done
    [[ "$($_AA_SYSTEMCTL is-enabled "$AA_UNIT.path" 2>/dev/null)" == enabled ]] || return 1
    [[ "$($_AA_SYSTEMCTL is-enabled "$AA_UNIT.service" 2>/dev/null)" == enabled ]] || return 1
    [[ "$($_AA_SYSTEMCTL is-active "$AA_UNIT.path" 2>/dev/null)" == active ]] || return 1
    [[ "$($_AA_SYSTEMCTL show -p Result --value "$AA_UNIT.service" 2>/dev/null)" == success ]] || return 1
    # with MicroK8s present, the file must carry the rules (else the next run puts them back)
    [[ ! -f "$AA_MK8S_PROFILE" ]] || grep -qF "$AA_MARKER" "$AA_DST" 2>/dev/null || return 1
}

# Installs or refreshes the fix; sudo only when something differs. Never fails the
# caller's deploy on a kernel that does not need it: a failure is a loud warning and
# return 1 (deploy-infra goes on; health check "Container AppArmor" FAILs).
aa_containerd_fix() {
    aa_names
    if [[ ! -d "$AA_SECFS" ]]; then
        echo "  AppArmor is not enabled on this host: nothing to do."
        return 0
    fi
    local tmpd rc=0
    tmpd="$(mktemp -d)" || return 1
    if ! _aa_render_units "$tmpd"; then rm -rf "$tmpd"; return 1; fi
    if _aa_in_place "$tmpd"; then
        echo -e "${GREEN:-}  AppArmor rules for containers already in place ($AA_UNIT).${NC:-}"
        rm -rf "$tmpd"; return 0
    fi
    echo "  Installing $AA_UNIT (MicroK8s's container profile + the stacked-peer rules; Ubuntu kernels from 7.0.0-41)..."
    if _aa_sudo install -d -m 755 -o root -g root "$AA_LIB_DIR" \
       && _aa_sudo install -m 755 -o root -g root "$_AA_HERE/apparmor/containerd-apparmor.sh" "$AA_LIB_DIR/reapply" \
       && _aa_sudo install -m 644 -o root -g root "$tmpd/$AA_UNIT.service" "$tmpd/$AA_UNIT.path" "$AA_SYSTEMD/" \
       && _aa_sudo "$_AA_SYSTEMCTL" daemon-reload \
       && _aa_sudo "$_AA_SYSTEMCTL" enable --quiet "$AA_UNIT.service" \
       && _aa_sudo "$_AA_SYSTEMCTL" enable --quiet --now "$AA_UNIT.path"; then
        # runs it once now (a oneshot: start waits for it); without MicroK8s it exits 0
        # and the path unit runs it again when MicroK8s's containerd writes the profile
        if _aa_sudo "$_AA_SYSTEMCTL" start "$AA_UNIT.service"; then
            echo -e "${GREEN:-}  AppArmor rules for containers in place ($AA_UNIT).${NC:-}"
        else
            rc=1
        fi
    else
        rc=1
    fi
    if (( rc )); then
        echo -e "${RED:-}WARNING: the AppArmor rules for containers are not in place (journalctl -u $AA_UNIT.service). On an Ubuntu kernel from 7.0.0-41 PostgreSQL, nginx and Mosquitto then hang or fail inside the cluster; boot an older kernel until it is fixed.${NC:-}" >&2
    fi
    rm -rf "$tmpd"
    return "$rc"
}

# deploy-infra.sh --uninstall, after MicroK8s is gone: the units, the root-owned copy,
# and the host profiles this disabled (put back and loaded). The profile file stays,
# as MicroK8s's own removal leaves it.
aa_containerd_remove() {
    aa_names
    [[ -e "$AA_SYSTEMD/$AA_UNIT.path" || -e "$AA_SYSTEMD/$AA_UNIT.service" || -d "$AA_LIB_DIR" ]] || return 0
    _aa_sudo "$_AA_SYSTEMCTL" disable --quiet --now "$AA_UNIT.path" 2>/dev/null || true
    _aa_sudo "$_AA_SYSTEMCTL" disable --quiet "$AA_UNIT.service" 2>/dev/null || true
    _aa_sudo rm -f "$AA_SYSTEMD/$AA_UNIT.path" "$AA_SYSTEMD/$AA_UNIT.service"
    _aa_sudo "$_AA_SYSTEMCTL" daemon-reload 2>/dev/null || true
    local name
    if [[ -f "$AA_LIB_DIR/disabled-profiles" ]]; then
        while IFS= read -r name; do
            [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || continue
            if [[ -L "$AA_ETC/disable/$name" && "$(readlink "$AA_ETC/disable/$name")" == "$AA_ETC/$name" ]]; then
                _aa_sudo rm -f "$AA_ETC/disable/$name"
                [[ -d "$AA_SECFS" ]] && _aa_sudo "${AA_PARSER:-apparmor_parser}" -r "$AA_ETC/$name" 2>/dev/null || true
                echo "  Re-enabled host AppArmor profile $name."
            fi
        done < "$AA_LIB_DIR/disabled-profiles"
    fi
    _aa_sudo rm -rf "$AA_LIB_DIR"
    echo "  Removed $AA_UNIT."
}

# kubepods processes whose label stacks a host profile ("cri-containerd.apparmor.d//&X",
# X not unconfined): "<X> <comm>" per line, unique
_aa_collisions() {
    local proc="${AA_PROC:-/proc}" p label comm
    for p in "$proc"/[0-9]*; do
        label="$(cat "$p/attr/apparmor/current" 2>/dev/null)" || continue
        [[ "$label" == *'//&'* ]] || continue
        label="${label% (*)}"
        [[ "${label#*//&}" == unconfined ]] && continue
        grep -q kubepods "$p/cgroup" 2>/dev/null || continue
        comm="$(cat "$p/comm" 2>/dev/null)"
        echo "${label#*//&} ${comm:-?}"
    done | sort -u
}

# One line "STATUS|message" for health check "Container AppArmor"; read-only, no sudo.
aa_status() {
    aa_names
    if [[ ! -d "$AA_SECFS" ]]; then echo "SKIP|AppArmor is not enabled on this host"; return; fi
    if [[ ! -f "$AA_MK8S_PROFILE" ]]; then echo "SKIP|MicroK8s is not installed (no $AA_MK8S_PROFILE)"; return; fi
    local problems=() result since since_epoch denials coll sysctl
    if [[ "$($_AA_SYSTEMCTL is-enabled "$AA_UNIT.path" 2>/dev/null)" != enabled ]]; then
        echo "FAIL|$AA_UNIT is not installed: signals inside containers are denied on Ubuntu kernels from 7.0.0-41 (./deploy-infra.sh installs it)"
        return
    fi
    [[ "$($_AA_SYSTEMCTL is-active "$AA_UNIT.path" 2>/dev/null)" == active ]] \
        || problems+=("$AA_UNIT.path is not active (sudo systemctl start $AA_UNIT.path)")
    result="$($_AA_SYSTEMCTL show -p Result --value "$AA_UNIT.service" 2>/dev/null)"
    [[ "$result" == success ]] || problems+=("its last run ended '${result:-?}' (journalctl -u $AA_UNIT.service)")
    grep -qF "$AA_MARKER" "$AA_DST" 2>/dev/null \
        || problems+=("$AA_DST lacks the rules (sudo systemctl start $AA_UNIT.service)")
    coll="$(_aa_collisions | awk '{a[$1]=a[$1] (a[$1]?",":"") $2} END {for (k in a) printf "%s%s (%s)", (n++?"; ":""), k, a[k]}')"
    [[ -n "$coll" ]] && problems+=("host profile attached inside a container: $coll (sudo systemctl start $AA_UNIT.service, then restart that pod)")
    since="$($_AA_SYSTEMCTL show -p ExecMainExitTimestamp --value "$AA_UNIT.service" 2>/dev/null)"
    since_epoch="$(date -d "$since" +%s 2>/dev/null)" || since_epoch=""
    if [[ -n "$since_epoch" ]]; then
        if denials="$(${AA_JOURNALCTL:-journalctl} -k -b --no-pager -q --since "@$since_epoch" 2>/dev/null)"; then
            denials="$(grep -c 'apparmor="DENIED" operation="signal".*profile="cri-containerd\.apparmor\.d' <<<"$denials" || true)"
            (( denials > 0 )) && problems+=("$denials signal denial(s) inside containers since the rules were loaded ($since): journalctl -k -b | grep 'DENIED.*signal'")
        else
            denials="?"
        fi
    fi
    if (( ${#problems[@]} )); then
        local IFS=';'; echo "FAIL|${problems[*]}"; return
    fi
    sysctl="$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined 2>/dev/null || echo -)"
    echo "OK|kernel $(uname -r), restrict_unprivileged_unconfined=$sysctl; rules loaded ${since:-at boot}${denials:+, $( [[ "$denials" == "?" ]] && echo "kernel log unreadable" || echo "no signal denials since")}$( [[ -f "$AA_LIB_DIR/disabled-profiles" ]] && printf ', host profile(s) off: %s' "$(paste -sd, "$AA_LIB_DIR/disabled-profiles")")"
}
