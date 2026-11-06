#!/usr/bin/env bash
# infra/lib-data-volumes.sh — say which people's data an uninstall would delete.
#
#   data_volumes_warn NS
#
# Two kinds of volume in the platform namespace hold what people made in the
# browser; only the nightly backup (apps/backup, when deployed) copies them, into
# BACKUP_DIR on this host, which no uninstall deletes:
#   - each person's AI workbench home, PersistentVolumeClaim claim-<name>
#     (KubeSpawner; delete_pvc false keeps it when a server stops or a hub user is
#     removed): their notebooks;
#   - Grafana's database, PersistentVolumeClaim grafana (decision of 1 Nov 2026):
#     the dashboards Editors created or saved as copies, folders, annotations,
#     alert rules. The provisioned dashboards come from git and come back.
# One more thing people make in the browser lives in no volume of its own: Superset's
# dashboards, charts, saved queries and its users are its metadata database
# `superset`, inside PostgreSQL's volume (data-rdbms-postgresql-0) with the platform
# database and Keycloak's; the nightly backup dumps it (db/superset.dump) when it
# exists. It is named while deployment/superset exists.
# Deleting the namespace (or a Helm uninstall of grafana) deletes the claims, and
# hostpath-storage deletes the data with them, so every path that deletes the
# namespace or MicroK8s calls this BEFORE it asks for confirmation:
# deploy-infra.sh --reset and --uninstall, install.sh --uninstall-infra and
# --uninstall-all, and bootstrap-infra.sh's "Fully wipe MicroK8s and reinstall?"
# (every ./deploy-infra.sh run on an unwell cluster). It prints each volume with
# the directory that holds it on this host and how to keep it; it changes nothing
# and never fails the caller (no such claims: it says nothing; no cluster answer:
# a short warning).
#
# Needs $KUBECTL (e.g. "microk8s kubectl"). Read-only. BACKUP_DIR comes from the
# caller's config.env; the newest complete backup in it is named when there is one.
data_volumes_warn() {
    local ns="${1:-medcea}" json rows backed="nothing backs them up" backed1="nothing backs it up" nb
    # shellcheck source=../apps/backup/lib-backup.sh
    if source "$(dirname "${BASH_SOURCE[0]}")/../apps/backup/lib-backup.sh" 2>/dev/null \
            && nb="$(backup_newest_ok "$(backup_dir)" 2>/dev/null)" && [[ -n "$nb" ]]; then
        backed="newest nightly backup: ${nb%% *} in $(backup_dir), which this keeps"
        backed1="$backed"
    fi
    if ! json="$(timeout 20 ${KUBECTL:-microk8s kubectl} get pvc -n "$ns" -o json 2>/dev/null </dev/null)"; then
        echo -e "\033[0;31mCould not list the AI workbench homes (claim-<name>) or Grafana's volume in '$ns'.\033[0m"
        echo -e "\033[0;31mIf people keep notebooks or their own dashboards there, this deletes them: answer no,\033[0m"
        echo -e "\033[0;31mhave them push notebooks to git and export their dashboards first.\033[0m"
        echo -e "\033[0;31mWith Superset installed, its dashboards and charts (database superset, inside PostgreSQL) go too.\033[0m"
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
    if name.startswith("claim-") or name == "grafana":
        print("%s\t%s\t%s" % (name, (i.get("spec") or {}).get("volumeName") or "-",
                              ((i.get("status") or {}).get("capacity") or {}).get("storage") or "?"))
' <<<"$json" 2>/dev/null)" || rows=""
    local line claim pv size path homes=() grafana="" superset=""
    # -o name, compared exactly: anything else (no such deployment, no answer) is "not installed"
    [[ "$(timeout 10 ${KUBECTL:-microk8s kubectl} get deployment superset -n "$ns" -o name 2>/dev/null </dev/null || true)" \
        == deployment.apps/superset ]] && superset=yes
    [[ -n "$rows" || -n "$superset" ]] || return 0
    [[ -n "$rows" ]] && while IFS= read -r line; do
        IFS=$'\t' read -r claim pv size <<<"$line"
        path="$(timeout 10 ${KUBECTL:-microk8s kubectl} get pv "$pv" -o jsonpath='{.spec.hostPath.path}' 2>/dev/null </dev/null || true)"
        if [[ "$claim" == grafana ]]; then
            grafana="$claim ($size)${path:+, on this host in $path}"
        else
            homes+=("${claim#claim-}: $claim ($size)${path:+, on this host in $path}")
        fi
    done <<<"$rows"
    if (( ${#homes[@]} )); then
        echo -e "\033[0;31m\033[1mAI workbench homes that this deletes ($backed):\033[0m"
        for line in "${homes[@]}"; do echo "  - $line"; done
        echo "  To keep them, answer no now and first either (or restore them from the nightly backup"
        echo "  afterwards: ./apps/backup/backups.sh restore-help):"
        echo "    - have each person commit and push their notebooks to the research repository"
        echo "      (Git panel; ~/medcea-examples/SAVE_TO_GIT.md), or"
        echo "    - copy each directory above off the volume, e.g."
        echo "        sudo cp -a <directory> ~/workbench-homes-backup/"
        echo "      and after the reinstall copy a person's files back into their new home once their"
        echo "      server has started once (the JupyterLab upload, or kubectl -n $ns cp)."
        echo ""
    fi
    if [[ -n "$grafana" ]]; then
        echo -e "\033[0;31m\033[1mGrafana's volume, which this deletes ($backed1):\033[0m"
        echo "  - $grafana"
        echo "  It holds the dashboards Editors made in the browser (new ones and \"Save as\" copies),"
        echo "  their folders, annotations and alert rules. The platform's own dashboards come from"
        echo "  git and come back with ./apps/report/deploy.sh. To keep the rest, answer no now and first:"
        echo "    - have each Editor export the dashboards they want (dashboard → Share → Export →"
        echo "      Save to file) and import them after the reinstall (Dashboards → New → Import), and/or"
        echo "    - copy the directory above off the volume, e.g."
        echo "        sudo cp -a <directory> ~/grafana-backup/"
        echo "      (grafana.db, Grafana's whole database: a copy to look things up in, or to hand back"
        echo "      to an administrator; it also holds the old accounts and sessions)."
        echo ""
    fi
    if [[ -n "$superset" ]]; then
        echo -e "\033[0;31m\033[1mSuperset's database, which this deletes ($backed1):\033[0m"
        echo "  - database superset, inside PostgreSQL's volume (data-rdbms-postgresql-0)"
        echo "  It holds the dashboards, charts, datasets and saved queries people made in Superset,"
        echo "  and its own copy of the accounts that signed in. The connection to the platform data"
        echo "  and the platform's own dashboards come back with ./apps/superset/deploy.sh. To keep the"
        echo "  rest, answer no now and first:"
        echo "    - have each builder export what they want (Dashboards → select → Export) and import it"
        echo "      after the reinstall (Dashboards → Import), and/or"
        echo "    - rely on the nightly backup's db/superset.dump (./apps/backup/backups.sh now takes one)."
        echo ""
    fi
}
