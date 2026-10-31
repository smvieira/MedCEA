#!/usr/bin/env bash
# infra/lib-workbench-homes.sh — say which AI workbench homes an uninstall would delete.
#
#   workbench_homes_warn NS
#
# Each person's notebooks live in their home volume, PersistentVolumeClaim
# claim-<name> in the platform namespace (KubeSpawner; delete_pvc false keeps it
# when a server stops or a hub user is removed). Nothing backs it up. Deleting the
# namespace deletes every claim, and hostpath-storage deletes the data with it, so
# every path that deletes the namespace or MicroK8s calls this BEFORE it asks for
# confirmation: deploy-infra.sh --reset and --uninstall, install.sh
# --uninstall-infra and --uninstall-all, and bootstrap-infra.sh's "Fully wipe
# MicroK8s and reinstall?" (every ./deploy-infra.sh run on an unwell cluster). It prints each home with the directory
# that holds it on this host and how to keep it; it changes nothing and never
# fails the caller (no claims: it says nothing; no cluster answer: a short warning).
#
# Needs $KUBECTL (e.g. "microk8s kubectl"). Read-only.
workbench_homes_warn() {
    local ns="${1:-medcea}" json rows
    if ! json="$(timeout 20 ${KUBECTL:-microk8s kubectl} get pvc -n "$ns" -o json 2>/dev/null </dev/null)"; then
        echo -e "\033[0;31mCould not list the AI workbench homes in '$ns' (claim-<name>). If people keep\033[0m"
        echo -e "\033[0;31mnotebooks there, this deletes them: answer no and have them push to git first.\033[0m"
        echo ""
        return 0
    fi
    rows="$(python3 -c '
import json, sys
try:
    items = json.load(sys.stdin).get("items") or []
except ValueError:
    sys.exit(0)
for i in items:
    name = i["metadata"]["name"]
    if name.startswith("claim-"):
        print("%s\t%s\t%s" % (name, (i.get("spec") or {}).get("volumeName") or "-",
                              ((i.get("status") or {}).get("capacity") or {}).get("storage") or "?"))
' <<<"$json" 2>/dev/null)" || return 0
    [[ -n "$rows" ]] || return 0
    local line claim pv size path
    echo -e "\033[0;31m\033[1mAI workbench homes that this deletes (nothing backs them up):\033[0m"
    while IFS= read -r line; do
        IFS=$'\t' read -r claim pv size <<<"$line"
        path="$(timeout 10 ${KUBECTL:-microk8s kubectl} get pv "$pv" -o jsonpath='{.spec.hostPath.path}' 2>/dev/null </dev/null || true)"
        echo "  - ${claim#claim-}: $claim ($size)${path:+, on this host in $path}"
    done <<<"$rows"
    echo "  To keep them, answer no now and first either:"
    echo "    - have each person commit and push their notebooks to the research repository"
    echo "      (Git panel; ~/medcea-examples/SAVE_TO_GIT.md), or"
    echo "    - copy each directory above off the volume, e.g."
    echo "        sudo cp -a <directory> ~/workbench-homes-backup/"
    echo "      and after the reinstall copy a person's files back into their new home once their"
    echo "      server has started once (the JupyterLab upload, or kubectl -n $ns cp)."
    echo ""
}
