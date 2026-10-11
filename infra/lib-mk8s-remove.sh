#!/usr/bin/env bash
# infra/lib-mk8s-remove.sh — remove_microk8s: wipe MicroK8s without leaving its
# pods running; kill_orphan_pods: clear pods a previous removal left behind.
# Sourced by deploy-infra.sh (--uninstall) and bootstrap-infra.sh (the wipe
# prompt, and before every install).
#
# Why not `microk8s reset`: reset returns a cluster to a fresh state while
# keeping the snap — it disables every addon one by one and deletes every
# resource through the API (3-4 minutes). Removing the snap makes all of that
# moot. Its remove hook already stops the services, drops the pod-CIDR iptables
# rules, unmounts every pod volume and deletes containerd's data, and --purge
# takes SNAP_COMMON, where hostpath PVs live. Two things survive it:
#   - the pod processes, in /sys/fs/cgroup/kubepods (cgroupfs driver), outside
#     every systemd unit;
#   - containerd-shims, which live in containerd's unit and outlive it (the
#     unit uses KillMode=process).
#
# Order matters, and the shims are the reason. When containerd's unit stops
# with shims still in it ("Unit process … remains running after unit
# stopped"), the next install's containerd is SIGKILLed within a millisecond
# of starting, even after the shims are gone, and snapd rolls the install
# back. Measured on 2026-10-11: every removal that left shims behind (17, 3
# and 27 of them) broke the next install; the one through `microk8s reset`,
# which had deleted every pod first and left 0, did not. So the unit is
# emptied while containerd is still up: kubelet first (nothing restarts the
# pods), then the pods, then the shims, and only then the rest.
#
# This path never goes through the snap's `sudo -E` (infra/lib-sudo.sh).

KUBEPODS_CG=/sys/fs/cgroup/kubepods

# Kill every process left in the kubepods cgroup and remove the tree. Only
# with kubelet stopped or MicroK8s gone: while it runs, these are its live pods.
kill_orphan_pods() {
    [ -e "$KUBEPODS_CG/cgroup.kill" ] || return 0
    if [ -z "$(cat $(find "$KUBEPODS_CG" -name cgroup.procs) 2>/dev/null)" ]; then
        sudo find "$KUBEPODS_CG" -depth -type d -exec rmdir {} \; 2>/dev/null || true
        return 0
    fi
    echo "  Killing pod processes left over from a previous MicroK8s..."
    echo 1 | sudo -p "[sudo] password for %u (clearing orphaned MicroK8s pods): " \
        tee "$KUBEPODS_CG/cgroup.kill" >/dev/null
    sleep 2
    sudo find "$KUBEPODS_CG" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}

remove_microk8s() {
    sudo snap stop microk8s.daemon-kubelite || true
    kill_orphan_pods
    # Only MicroK8s's shims — the path keeps a Docker on the same host alone.
    sudo pkill -KILL -f '^/snap/microk8s/[^ ]*/containerd-shim' || true
    sleep 2
    sudo snap stop --disable microk8s || true
    sudo snap remove microk8s --purge
    sudo ip link delete vxlan.calico 2>/dev/null || true
    sudo rm -rf ~/.kube /var/snap/microk8s
}
