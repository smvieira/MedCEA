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
# takes SNAP_COMMON, where hostpath PVs live. Two things survive it, which are
# what left calico-node orphaned and got the next install's containerd
# SIGKILLed at start:
#   - the pod processes, in /sys/fs/cgroup/kubepods (cgroupfs driver), outside
#     every systemd unit;
#   - containerd-shims, which stay in containerd's unit after it stops.
# This path also never goes through the snap's `sudo -E` (infra/lib-sudo.sh).

KUBEPODS_CG=/sys/fs/cgroup/kubepods

# Kill every process left in the kubepods cgroup and remove the tree. Only
# with MicroK8s stopped or gone: while it runs, these are its live pods.
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
    sudo snap stop --disable microk8s || true
    sudo systemctl kill --signal=SIGKILL \
        snap.microk8s.daemon-kubelite.service snap.microk8s.daemon-containerd.service 2>/dev/null || true
    # Before the remove, so its hook can unmount pod volumes that nothing holds.
    kill_orphan_pods
    sudo snap remove microk8s --purge
    sudo ip link delete vxlan.calico 2>/dev/null || true
    sudo rm -rf ~/.kube /var/snap/microk8s
}
