#!/bin/sh
# containerd-apparmor.sh — keeps the stacked-peer rules in MicroK8s's container profile.
#
# Installed by infra/lib-apparmor.sh (aa_containerd_fix) as root-owned
# /usr/local/lib/<project>-apparmor/reapply and run, as root, by the systemd units
# <project>-containerd-apparmor.{path,service}: at boot, and whenever
# /etc/apparmor.d/cri-containerd.apparmor.d changes. Never run from the repository
# (a root service must not run a file the deploying account can edit).
#
# Why: from Ubuntu kernel 7.0.0-41, with kernel.apparmor_restrict_unprivileged_unconfined=1
# (Ubuntu's default), runc's change to the container profile becomes a stack, and a
# container's processes are labelled "cri-containerd.apparmor.d//&unconfined". MicroK8s's
# profile only allows signals between processes with the identical label, so signals
# inside one container are denied: PostgreSQL's latch wake-ups (SIGURG), nginx reloads
# (HUP), Go's preemption. containerd#14485 (fix proposed in #14487, not released).
# MicroK8s's containerd wrapper (run-containerd-with-args) copies its own profile over
# /etc/apparmor.d/cri-containerd.apparmor.d and reloads AppArmor at every containerd
# start; containerd itself keeps a profile of that name once one is loaded. So this
# rebuilds the file from MicroK8s's (whatever a refresh put there) plus RULES, and
# loads it; replacing a loaded profile applies to the running containers at once.
#
# Also: a host profile that attaches by path (Ubuntu's apparmor package ships
# /etc/apparmor.d/mosquitto for /usr/sbin/mosquitto) attaches inside a container
# through the stack's "unconfined" half; the ones listed in CONTAINER_ONLY are disabled
# (symlink in disable/, unloaded) while the host has no such binary, and recorded in
# $STATE_DIR/disabled-profiles so the uninstall puts them back.
#
# Exit 0 when there is nothing to do (no AppArmor, no MicroK8s); 1 on a failure, which
# the service records (health check "Container AppArmor" reads it). POSIX sh.
set -u

SRC="${AA_SRC:-/snap/microk8s/current/containerd-profile}"
APPARMOR_D="${AA_DIR:-/etc/apparmor.d}"
DST="${AA_DST:-$APPARMOR_D/cri-containerd.apparmor.d}"
PARSER="${AA_PARSER:-apparmor_parser}"
SECURITYFS="${AA_SECURITYFS:-/sys/kernel/security/apparmor}"
HOST_ROOT="${AA_HOST_ROOT:-}"
STATE_DIR="${AA_STATE_DIR:-$(dirname "$0")}"
SETTLE="${AA_SETTLE:-3}"
WAIT_MAX="${AA_WAIT_MAX:-60}"
MARKER="# medcea: stacked-peer rules (containerd#14485)"
CONTAINER_ONLY="${AA_CONTAINER_ONLY:-mosquitto}"

log() { echo "containerd-apparmor: $*"; }

[ -d "$SECURITYFS" ] || { log "AppArmor is not enabled: nothing to do"; exit 0; }
[ -f "$SRC" ] || { log "no $SRC (MicroK8s not installed): nothing to do"; exit 0; }

# MicroK8s's wrapper runs "service apparmor reload" right after its copy: wait for it,
# or its reload could load the file it read before ours replaced it.
waited=0
while pgrep -x apparmor_parser >/dev/null 2>&1 || pgrep -f '[a]pparmor.systemd' >/dev/null 2>&1; do
    [ "$waited" -ge "$WAIT_MAX" ] && { log "an AppArmor reload is still running after ${WAIT_MAX}s; going on"; break; }
    sleep 1; waited=$((waited + 1))
done
[ "$SETTLE" -gt 0 ] 2>/dev/null && sleep "$SETTLE"

tmp="$(mktemp)" || exit 1
trap 'rm -f "$tmp"' EXIT

# MicroK8s's profile ends with the closing brace of its one profile (no newline after
# it); everything before it is kept as it is, then our rules, then the brace.
last="$(sed -e 's/[[:space:]]*$//' "$SRC" | grep -v '^$' | tail -n 1)"
if [ "$last" != "}" ]; then
    log "ERROR: $SRC does not end with the profile's closing brace; not changed (MicroK8s's profile format changed: update infra/apparmor/containerd-apparmor.sh)"
    exit 1
fi
if grep -qF "$MARKER" "$SRC"; then
    log "ERROR: $SRC already carries the medcea rules; not changed"
    exit 1
fi
awk -v marker="$MARKER" '
    { lines[NR] = $0 }
    END {
        n = NR
        while (n > 0 && lines[n] ~ /^[[:space:]]*$/) n--
        for (i = 1; i < n; i++) print lines[i]
        sub(/}[[:space:]]*$/, "", lines[n]); if (lines[n] !~ /^[[:space:]]*$/) print lines[n]
        print ""
        print "  " marker
        print "  signal (send,receive) peer=cri-containerd.apparmor.d,"
        print "  signal (send,receive) peer=cri-containerd.apparmor.d//&unconfined,"
        print "  ptrace (trace,tracedby,read,readby) peer=cri-containerd.apparmor.d,"
        print "  ptrace (trace,tracedby,read,readby) peer=cri-containerd.apparmor.d//&unconfined,"
        print "}"
    }' "$SRC" > "$tmp" || exit 1

if ! "$PARSER" -Q -K -I "$APPARMOR_D" "$tmp" >/dev/null 2>&1; then
    log "ERROR: the profile with the medcea rules does not parse ($PARSER -Q); $DST not changed"
    "$PARSER" -Q -K -I "$APPARMOR_D" "$tmp" 2>&1 | sed 's/^/  /'
    exit 1
fi

if cmp -s "$tmp" "$DST"; then
    log "$DST already carries the rules"
else
    # written in place (cat >), never a temporary file in apparmor.d, which a
    # concurrent "service apparmor reload" would try to load as a profile
    cat "$tmp" > "$DST" || { log "ERROR: cannot write $DST"; exit 1; }
    chmod 644 "$DST"
    log "wrote $DST (MicroK8s's profile + the stacked-peer rules)"
fi
if ! "$PARSER" -r -I "$APPARMOR_D" "$DST"; then
    log "ERROR: $PARSER -r $DST failed"
    exit 1
fi
log "loaded cri-containerd.apparmor.d with the stacked-peer rules"

# Host profiles that attach inside containers.
rc=0
for name in $CONTAINER_ONLY; do
    prof="$APPARMOR_D/$name"
    [ -f "$prof" ] || continue
    bin="$(sed -n "s/^[[:space:]]*profile[[:space:]][[:space:]]*$name[[:space:]][[:space:]]*\(\/[^[:space:]{]*\).*/\1/p" "$prof" | head -n 1)"
    [ -n "$bin" ] || continue
    if [ -e "$HOST_ROOT$bin" ]; then
        if [ ! -e "$APPARMOR_D/disable/$name" ]; then
            log "WARNING: $bin is installed on this host, so profile $name stays on; it also attaches inside the cluster's $name container (health check \"Container AppArmor\")"
        fi
        continue
    fi
    if [ ! -e "$APPARMOR_D/disable/$name" ]; then
        mkdir -p "$APPARMOR_D/disable"
        ln -s "$prof" "$APPARMOR_D/disable/$name" || { rc=1; continue; }
        grep -qx "$name" "$STATE_DIR/disabled-profiles" 2>/dev/null || echo "$name" >> "$STATE_DIR/disabled-profiles"
        log "disabled host profile $name ($bin is not installed on this host; it attached inside the $name container)"
    fi
    if [ -d "$SECURITYFS/policy/profiles" ] && ls "$SECURITYFS/policy/profiles" | grep -q "^$name\.[0-9]*$"; then
        "$PARSER" -R "$prof" >/dev/null 2>&1 && log "unloaded host profile $name" || { log "ERROR: cannot unload $name"; rc=1; }
    fi
done
exit "$rc"
