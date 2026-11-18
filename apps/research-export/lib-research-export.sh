#!/usr/bin/env bash
# apps/research-export/lib-research-export.sh — pure helpers for the research export,
# sourced by health-check.sh (check rsexport). Reads nothing, writes nothing.
#
#   rsexport_age_status NOW LAST_EPOCH CREATED_EPOCH [SNAPSHOT_ID]
#       "STATUS|message": OK up to RSEXPORT_WARN_H hours (26) since the newest snapshot's
#       created_at (LAST_EPOCH), WARN beyond, FAIL beyond RSEXPORT_FAIL_H (72), the
#       backups' limits for a job of the same daily cadence. Without any snapshot
#       (LAST_EPOCH empty) the CronJob's age (CREATED_EPOCH) stands in, and SKIP while it
#       is younger than the WARN limit (the first night).

RSEXPORT_WARN_H="${RSEXPORT_WARN_H:-26}"
RSEXPORT_FAIL_H="${RSEXPORT_FAIL_H:-72}"

rsexport_age_status() {
    local now="$1" last="$2" created="$3" snap="${4:-}" age h status limit
    local hint="microk8s kubectl -n ${NAMESPACE:-medcea} get jobs -l app=research-export; run one: microk8s kubectl -n ${NAMESPACE:-medcea} create job --from=cronjob/research-export research-export-now"
    if [[ -z "$last" ]]; then
        age=$(( now - ${created:-0} )); h=$(( age / 3600 ))
        if (( age <= RSEXPORT_WARN_H * 3600 )); then
            echo "SKIP|no snapshot yet: the first export runs at 03:00 UTC ($hint)"
            return
        fi
        status=WARN; (( age > RSEXPORT_FAIL_H * 3600 )) && status=FAIL
        echo "$status|no snapshot since the CronJob was created ${h} h ago ($hint)"
        return
    fi
    age=$(( now - last )); h=$(( age / 3600 ))
    (( age < 0 )) && { age=0; h=0; }
    if (( age > RSEXPORT_FAIL_H * 3600 )); then
        status=FAIL; limit="$RSEXPORT_FAIL_H"
    elif (( age > RSEXPORT_WARN_H * 3600 )); then
        status=WARN; limit="$RSEXPORT_WARN_H"
    else
        echo "OK|newest snapshot ${snap:-?}, ${h} h old"
        return
    fi
    echo "$status|newest snapshot ${snap:-?} is ${h} h old (over ${limit} h: $hint)"
}
