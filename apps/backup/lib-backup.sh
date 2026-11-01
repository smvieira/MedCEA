#!/usr/bin/env bash
# apps/backup/lib-backup.sh — read the nightly backups in BACKUP_DIR from the host.
# Sourced by health-check.sh (check backupage) and apps/backup/backups.sh. Read-only.
#
#   backup_dir                     BACKUP_DIR as config.env sets it (default
#                                  /var/backups/$PROJECT_NAME)
#   backup_folders DIR             the dated folders, oldest first (names only)
#   backup_ok_epoch DIR/NAME       the epoch an OK marker records; status 1 without one
#   backup_newest_ok DIR           "NAME EPOCH" of the newest complete folder, or nothing
#   backup_age_status NOW OK_EPOCH CREATED_EPOCH [NAME]
#                                  "STATUS|message" for the health check: OK up to
#                                  BACKUP_WARN_H hours (26) since the newest OK marker,
#                                  WARN beyond, FAIL beyond BACKUP_FAIL_H (72). Without
#                                  any OK, the CronJob's age stands in, and SKIP while
#                                  it is younger than the WARN limit (the first night).
#
# A folder is complete only with OK in it, written last by the job (backup-job.sh);
# a folder without OK is a run that failed or is still running.

BACKUP_STAMP_RE='^[0-9]{8}-[0-9]{6}Z$'
BACKUP_WARN_H="${BACKUP_WARN_H:-26}"
BACKUP_FAIL_H="${BACKUP_FAIL_H:-72}"

backup_dir() {
    echo "${BACKUP_DIR:-/var/backups/${PROJECT_NAME:-medcea}}"
}

backup_folders() {
    local d n
    for d in "$1"/*; do
        n="${d##*/}"
        [[ "$n" =~ $BACKUP_STAMP_RE && -d "$d" && ! -L "$d" ]] && echo "$n"
    done
    return 0
}

backup_ok_epoch() {
    local e
    [[ -f "$1/OK" && -r "$1/OK" ]] || return 1
    read -r e _ <"$1/OK" || true
    [[ "$e" =~ ^[0-9]+$ ]] || return 1
    echo "$e"
}

backup_newest_ok() {
    local n e best=""
    while IFS= read -r n; do
        e="$(backup_ok_epoch "$1/$n")" && best="$n $e"
    done < <(backup_folders "$1")
    [[ -n "$best" ]] && echo "$best"
    return 0
}

backup_age_status() {
    local now="$1" ok="$2" created="$3" name="${4:-}" age h status limit
    if [[ -z "$ok" ]]; then
        age=$(( now - ${created:-0} )); h=$(( age / 3600 ))
        if (( age <= BACKUP_WARN_H * 3600 )); then
            echo "SKIP|no complete backup yet: the first runs at 02:30 UTC (now: ./apps/backup/backups.sh now)"
            return
        fi
        status=WARN; (( age > BACKUP_FAIL_H * 3600 )) && status=FAIL
        echo "$status|no complete backup since the CronJob was created ${h} h ago (./apps/backup/backups.sh list; microk8s kubectl -n ${NAMESPACE:-medcea} get jobs -l app=medcea-backup)"
        return
    fi
    age=$(( now - ok )); h=$(( age / 3600 ))
    (( age < 0 )) && { age=0; h=0; }
    if (( age > BACKUP_FAIL_H * 3600 )); then
        status=FAIL; limit="$BACKUP_FAIL_H"
    elif (( age > BACKUP_WARN_H * 3600 )); then
        status=WARN; limit="$BACKUP_WARN_H"
    else
        echo "OK|newest complete backup ${name:-?}, ${h} h old"
        return
    fi
    echo "$status|newest complete backup ${name:-?} is ${h} h old (over ${limit} h: ./apps/backup/backups.sh list; microk8s kubectl -n ${NAMESPACE:-medcea} get jobs -l app=medcea-backup)"
}
