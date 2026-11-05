#!/usr/bin/env bash
# apps/backup/backups.sh — the nightly backups (apps/backup/), from the host.
#
#   ./apps/backup/backups.sh now [--timeout SECS]   run CronJob medcea-backup once now
#                                                   (a Job), wait for it, print its log
#   ./apps/backup/backups.sh list                   the dated folders in BACKUP_DIR
#   ./apps/backup/backups.sh verify [FOLDER]        sha256sum -c of a folder's SHA256SUMS
#                                                   (default: the newest complete one)
#   ./apps/backup/backups.sh restore-help [FOLDER]  the restore steps with this install's
#                                                   names and that folder's paths; runs
#                                                   nothing
#
# Only "now" changes the cluster (one Job), so only it takes the deploy lock. The
# folders belong to the account that ran ./apps/backup/deploy.sh (mode 700): list,
# verify and restore-help read them without sudo. Nothing here prints a secret: the
# Job's log names files and sizes only.
#
# The restore is shown, not run: it stops services and drops databases, and which
# parts to restore (one person's home, or everything after a reinstall) is a decision
# this script cannot take. ./guide.sh → Backups asks for each of these.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}
case "${1:-}" in
    -h|--help|"") usage; [[ -n "${1:-}" ]]; exit $? ;;
    now|list|verify|restore-help) ;;
    *) echo "Unknown command '$1' (see --help)" >&2; exit 2 ;;
esac
CMD="$1"; shift

source "$REPO_ROOT/infra/lib-log.sh"; medcea_log "backups-$CMD"   # logs/backups-<cmd>-<ts>.log
[[ -f "$REPO_ROOT/config.env" ]] || { echo "ERROR: config.env not found at $REPO_ROOT/config.env" >&2; exit 1; }
source "$REPO_ROOT/config.env"
source "$SCRIPT_DIR/lib-backup.sh"
NAMESPACE="${NAMESPACE:-medcea}"
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"
DIR="$(backup_dir)"

die() { echo "ERROR: $*" >&2; exit 1; }

need_dir() {
    [[ -d "$DIR" ]] || die "$DIR (BACKUP_DIR) does not exist: ./apps/backup/deploy.sh creates it."
    [[ -r "$DIR" && -x "$DIR" ]] || die "cannot read $DIR: it belongs to $(stat -c %U "$DIR" 2>/dev/null || echo '?'); run this as that account."
}

# folder_arg [NAME] → FOLDER: the named folder (it must exist and be complete) or the
# newest complete one.
folder_arg() {
    local n="${1:-}"
    if [[ -z "$n" ]]; then
        n="$(backup_newest_ok "$DIR")"; n="${n%% *}"
        [[ -n "$n" ]] || die "no complete backup in $DIR yet (./apps/backup/backups.sh now)."
    fi
    [[ "$n" =~ $BACKUP_STAMP_RE ]] || die "'$n' is not a backup folder name (like 20261102-023000Z)."
    [[ -d "$DIR/$n" && ! -L "$DIR/$n" ]] || die "no folder $n in $DIR (./apps/backup/backups.sh list)."
    backup_ok_epoch "$DIR/$n" >/dev/null || die "$n has no OK marker: that run did not finish; choose a complete one."
    FOLDER="$n"
}

cmd_list() {
    local n e size files status any=false
    need_dir
    echo "Backups in $DIR (kept ${BACKUP_KEEP_DAYS:-14} days; newest first):"
    printf '  %-18s %-11s %8s %6s  %s\n' FOLDER STATUS SIZE FILES "FINISHED (UTC)"
    while IFS= read -r n; do
        any=true
        size="$(du -sh "$DIR/$n" 2>/dev/null | cut -f1)"
        files="$(grep -c . "$DIR/$n/SHA256SUMS" 2>/dev/null || echo 0)"
        if e="$(backup_ok_epoch "$DIR/$n")"; then
            status=complete; e="$(date -u -d "@$e" '+%Y-%m-%d %H:%M')"
        else
            status=incomplete; e="-"
        fi
        printf '  %-18s %-11s %8s %6s  %s\n' "$n" "$status" "${size:-?}" "$files" "$e"
    done < <(backup_folders "$DIR" | sort -r)
    $any || echo "  (none yet: the first runs at 02:30 UTC, or ./apps/backup/backups.sh now)"
    n="$(backup_newest_ok "$DIR")"
    if [[ -n "$n" ]]; then
        echo "Newest complete: ${n%% *}, $(( ($(date -u +%s) - ${n#* }) / 3600 )) h old."
    fi
}

cmd_verify() {
    need_dir
    folder_arg "${1:-}"
    local f="$DIR/$FOLDER" listed actual head
    [[ -f "$f/SHA256SUMS" ]] || die "$FOLDER has no SHA256SUMS."
    echo "Checking $f against its SHA256SUMS..."
    (cd "$f" && sha256sum --quiet --strict -c SHA256SUMS) || die "$FOLDER: a file is missing or differs from the checksum written at backup time."
    listed="$(sed -E 's/^[0-9a-f]{64}  //' "$f/SHA256SUMS" | LC_ALL=C sort)"
    actual="$(cd "$f" && find db volumes -type f -print | LC_ALL=C sort)"
    [[ "$listed" == "$actual" ]] || die "$FOLDER: files present that SHA256SUMS does not list: $(comm -13 <(echo "$listed") <(echo "$actual") | tr '\n' ' ')"
    echo "OK: $FOLDER, $(grep -c . "$f/SHA256SUMS") files match the checksums written at backup time."
    # IAM 4.5 (design §14.8.10): the access policy's chain head the job read before the dump
    # (a folder from before 4.5 has no such line)
    head="$(grep -m1 '^# policy chain head' "$f/MANIFEST" 2>/dev/null || true)"
    echo "${head:-# policy chain head: not recorded (a backup from before IAM 4.5)}" | sed 's/^# //'
}

cmd_now() {
    local timeout=3600 job waited=0 st ok fail
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout) [[ "${2:-}" =~ ^[1-9][0-9]*$ ]] || die "--timeout needs a number of seconds"; timeout="$2"; shift 2 ;;
            *) die "unknown option '$1' for now (see --help)" ;;
        esac
    done
    source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # it starts a Job: one deploy at a time
    source "$REPO_ROOT/infra/lib-mk8s.sh"
    $KUBECTL get cronjob medcea-backup -n "$NAMESPACE" -o name >/dev/null 2>&1 \
        || die "no CronJob medcea-backup in $NAMESPACE: ./apps/backup/deploy.sh first."
    job="medcea-backup-now-$(date -u +%Y%m%d-%H%M%S)"
    echo "Starting Job $job from CronJob medcea-backup..."
    $KUBECTL create job "$job" --from=cronjob/medcea-backup -n "$NAMESPACE" >/dev/null
    while :; do
        st="$($KUBECTL get job "$job" -n "$NAMESPACE" -o jsonpath='{.status.succeeded} {.status.failed}' 2>/dev/null || true)"
        read -r ok fail <<<"$st"
        [[ "${ok:-0}" -ge 1 || "${fail:-0}" -ge 1 ]] && break
        (( waited >= timeout )) && break
        sleep 5; waited=$(( waited + 5 ))
    done
    echo "--- the Job's log ---"
    $KUBECTL logs -n "$NAMESPACE" "job/$job" --tail=200 2>&1 || true
    echo "---------------------"
    if [[ "${ok:-0}" -ge 1 ]]; then
        echo "Job $job succeeded."
        cmd_list
    elif [[ "${fail:-0}" -ge 1 ]]; then
        die "Job $job failed; its folder has no OK marker. The log above says why (microk8s kubectl -n $NAMESPACE describe job $job)."
    else
        die "Job $job still runs after ${timeout} s; follow it with: microk8s kubectl -n $NAMESPACE logs -f job/$job"
    fi
}

cmd_restore_help() {
    need_dir
    folder_arg "${1:-}"
    local f="$DIR/$FOLDER" ns="$NAMESPACE" db="$POSTGRES_DB" k="microk8s kubectl -n $NAMESPACE" head
    head="$(grep -m1 '^# policy chain head' "$f/MANIFEST" 2>/dev/null | sed 's/^# //')" || true
    head="${head:-policy chain head: not recorded (a backup from before IAM 4.5)}"
    # shellcheck disable=SC2016  # $(cat …), $POSTGRES_PASSWORD_FILE, $PV and $D are printed for the reader's shell or the pod's
    local pw='PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"'
    cat <<EOF
Restore from $f — the steps, in order. This command runs none of them.
Check the folder first:  ./apps/backup/backups.sh verify $FOLDER
Restore only the parts you need. psql and pg_restore run in the PostgreSQL pod and read
the password there (never on a command line); the dump goes in on stdin.
After a reinstall: restore once ./install.sh has finished, and before $(( ${BACKUP_KEEP_DAYS:-14} )) days have
passed (the new install's nightly run deletes older folders, except the newest complete one).

A. The platform database ($db)
  1. Stop the services that write to it (one not installed is reported "not found"):
       $k scale deployment node-red scheduler monitor config-api dbmgmt access iam-api --replicas=0
  2. Drop it and restore it from the dump:
       $k exec -i rdbms-postgresql-0 -- sh -c '$pw exec psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS $db WITH (FORCE)"'
       $k exec -i rdbms-postgresql-0 -- sh -c '$pw exec pg_restore -U postgres -d postgres --create --exit-on-error' < $f/db/$db.dump
  2a. (IAM 4.2a) Move the host's policy file aside, so the next deploy writes it again from the
     restored database (it moves state/policy-applied.yaml, the queued account facts and any
     break-glass copies into state/retired-<time>-restore/; nothing is deleted):
       bash -c 'source infra/lib-lock.sh && medcea_lock && source infra/lib-policy-source.sh && policy_state_retire restore'
  3. ./apps/database/deploy.sh   (migrations, grants and the role passwords of this config.env)
  4. $k scale deployment node-red scheduler monitor config-api dbmgmt access iam-api --replicas=1
     then ./health-check.sh (Access policy history must be OK: the restored hash chain verifies).
  5. (IAM 4.5) Compare the chain with the head the backup recorded before its dump
     ($head):
       $k exec -i rdbms-postgresql-0 -- sh -c '$pw exec psql -X -U postgres -d $db -tA' <<<"SELECT (SELECT ok FROM iam_policy.verify_chain()), (SELECT hash FROM iam_policy.history WHERE event_id = <id>)"
     verify_chain() must be true and event <id> must carry that hash: a chain that ends below it,
     or holds another hash there, was cut or rewritten after the backup.

B. Keycloak (accounts, roles, password hashes, clients)
  1. $k scale deployment keycloak --replicas=0
  2. $k exec -i rdbms-postgresql-0 -- sh -c '$pw exec psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS keycloak WITH (FORCE)"'
     $k exec -i rdbms-postgresql-0 -- sh -c '$pw exec pg_restore -U postgres -d postgres --create --exit-on-error' < $f/db/keycloak.dump
  3. $k scale deployment keycloak --replicas=1, then ./deploy-infra.sh (client secrets, break-glass
     and realm settings back to this config.env). Every account change since $FOLDER is lost.

C. One person's AI workbench home (claim-<name>; the list: ls $f/volumes)
  1. The person's server is stopped (they sign out, or AI Workbench admin page → Stop). After a
     reinstall they sign in once first, so the new home exists, and stop it again.
  2. Its directory on this host:
       PV=\$($k get pvc claim-<name> -o jsonpath='{.spec.volumeName}')
       D=\$(microk8s kubectl get pv "\$PV" -o jsonpath='{.spec.hostPath.path}'); echo "\$D"
  3. Put the copy back over what is there (newer files of the same name are overwritten):
       sudo tar -C "\$D" -xzpf $f/volumes/claim-<name>.tar.gz --numeric-owner
     One file only: tar -tzf $f/volumes/claim-<name>.tar.gz lists them; name it after the archive
     (e.g. ./notebooks/a.ipynb) in the same tar -x command.

D. Node-RED (/data: flows, flows_cred.json and its key, palette modules)
  1. $k scale deployment node-red --replicas=0
  2. D as in C.2 with pvc node-red, then replace its content:
       test -n "\$D" && sudo find "\$D" -mindepth 1 -delete && sudo tar -C "\$D" -xzpf $f/volumes/node-red.tar.gz --numeric-owner
  3. $k scale deployment node-red --replicas=1, then ./deploy-infra.sh and ./apps/node-red/deploy.sh
     (settings, credentials and the repository's flows); ./health-check.sh names flows only the backup had.

E. Grafana (grafana.db: Editors' dashboards, folders, annotations, alert rules)
  1. $k scale deployment grafana --replicas=0
  2. D as in C.2 with pvc grafana, then replace its content:
       test -n "\$D" && sudo find "\$D" -mindepth 1 -delete && sudo tar -C "\$D" -xzpf $f/volumes/grafana.tar.gz --numeric-owner && sudo chmod 0700 "\$D"
     (tar -p brings back the 0777 of '.'; Grafana's init container closes it again at each start)
  3. $k scale deployment grafana --replicas=1, then ./deploy-infra.sh (Grafana's break-glass password)
     and ./apps/report/deploy.sh (the platform's dashboards from the repository).

Manual: Running the platform → Backup and restore. Namespace $ns.
EOF
}

case "$CMD" in
    now)          cmd_now "$@" ;;
    list)         cmd_list ;;
    verify)       cmd_verify "${1:-}" ;;
    restore-help) cmd_restore_help "${1:-}" ;;
esac
