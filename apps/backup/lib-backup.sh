#!/usr/bin/env bash
# apps/backup/lib-backup.sh — read the nightly backups in BACKUP_DIR from the host.
# Sourced by health-check.sh (checks backupage, iamanchor) and apps/backup/backups.sh. Read-only.
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
#   backup_chain_head DIR/NAME     the access policy's chain head MANIFEST records (Phase 5,
#                                  health-check iamanchor): "head EVENT_ID HASH VERIFY" (VERIFY
#                                  t or f) when the line is well formed; "unavailable REASON"
#                                  when the job could not read it; "none" without the line (a
#                                  backup from before IAM 4.5); status 1 when MANIFEST cannot
#                                  be read. Only digits and lowercase hex pass as id and hash.
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

backup_chain_head() {
    local m="$1/MANIFEST" line id hash vc rest
    [[ -f "$m" && -r "$m" ]] || return 1
    line="$(grep -m1 '^# policy chain head' "$m" 2>/dev/null)" || { echo none; return 0; }
    if [[ "$line" =~ ^#\ policy\ chain\ head\ \(read\ before\ the\ dump\):\ ([0-9]+)\ ([0-9a-f]+)\ verify_chain=([tf])$ ]]; then
        id="${BASH_REMATCH[1]}"; hash="${BASH_REMATCH[2]}"; vc="${BASH_REMATCH[3]}"
        echo "head $id $hash $vc"
    elif [[ "$line" == "# policy chain head: unavailable"* ]]; then
        rest="${line#\# policy chain head: unavailable}"; rest="${rest# }"
        echo "unavailable $(printf '%s' "${rest:0:160}" | tr -c '[:alnum:] ().:_/-' ' ')"
    else
        echo "unavailable (an unexpected chain head line in MANIFEST)"
    fi
}
