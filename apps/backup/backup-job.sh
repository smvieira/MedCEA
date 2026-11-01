#!/bin/sh
# apps/backup/backup-job.sh — one backup run, inside the pod of CronJob medcea-backup
# (ConfigMap medcea-backup-script; apps/backup/deploy.sh).
#
#   backup-job.sh run      dump the databases, copy the volumes, write MANIFEST,
#                          SHA256SUMS and finally OK, then delete folders older
#                          than KEEP_DAYS
#   backup-job.sh prune    only the deleting (the tests call it on its own)
#
# POSIX sh: it runs in the image rdbms-postgresql runs (so pg_dump is the server's
# version), which promises a Debian userland but not bash.
#
# Environment (the CronJob sets every one; nothing comes as an argument):
#   BACKUP_OUT     the host's BACKUP_DIR, mounted read-write
#   STORAGE        microk8s-hostpath's PV directory, mounted read-only; each volume
#                  is <NAMESPACE>-<claim>-pvc-<uid> in it
#   NAMESPACE      the platform namespace
#   DATABASES      the databases to dump, custom format (pg_restore reads them)
#   VOLUMES        claim name patterns to copy, e.g. "claim-* node-red grafana"
#   PGHOST PGUSER  libpq's own variables; PGPASSWORD comes from Secret
#   PGPASSWORD     rdbms-postgresql (secretKeyRef), so libpq reads it from the
#                  environment: it reaches no command line, and nothing here prints it
#   KEEP_DAYS      dated folders older than this are deleted after a good run
#   OWNER_UID OWNER_GID   the host account that owns BACKUP_DIR; each folder is
#                  handed to it, mode 700, so the host reads it without sudo
#   BACKUP_NOW     epoch seconds to use instead of the clock (tests only)
#
# One folder per run, named by its UTC start: 20261102-023000Z. It is complete only
# when it holds OK (written last, by rename): the health check and the host command
# (apps/backup/backups.sh) trust nothing else. A failed run leaves its folder without
# OK and exits 1 (the Job shows Failed); it is deleted with the others once it is
# older than KEEP_DAYS. Deleting touches only names of that exact form, never the
# folder just written, never the newest complete one, and never a symbolic link.

set -eu
umask 077

say() { echo "backup: $*"; }
die() { echo "backup: ERROR: $*" >&2; exit 1; }

now() {
    if [ -n "${BACKUP_NOW:-}" ]; then echo "$BACKUP_NOW"; else date -u +%s; fi
}
stamp_of() { date -u -d "@$1" +%Y%m%d-%H%M%SZ; }
iso_of() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }

is_stamp() {
    case "$1" in
        [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]Z) return 0 ;;
    esac
    return 1
}

# older A B: status 0 when stamp A sorts before stamp B (same width, so text order
# is time order).
older() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | LC_ALL=C sort | head -n 1)" = "$1" ]
}

owner() {   # owner PATH: hand PATH (recursively) to the host account
    [ -n "${OWNER_UID:-}" ] || return 0
    chown -R "$OWNER_UID:${OWNER_GID:-$OWNER_UID}" "$1"
}

# wanted CLAIM: status 0 when CLAIM matches a pattern in VOLUMES. Globbing is off
# while the list is split, or "claim-*" would expand against the working directory.
wanted() {
    _hit=1
    set -f
    for _p in $VOLUMES; do
        case "$1" in $_p) _hit=0 ;; esac
    done
    set +f
    return "$_hit"
}

prune() {
    _keep="${KEEP_DAYS:-14}"
    case "$_keep" in ''|*[!0-9]*) die "KEEP_DAYS '$_keep' is not a whole number of days" ;; esac
    [ "$_keep" -ge 1 ] || die "KEEP_DAYS must be 1 or more"
    [ -d "${BACKUP_OUT:-}" ] || die "BACKUP_OUT is not a directory"
    _cutoff="$(stamp_of $(( $(now) - _keep * 86400 )))"
    # The newest complete folder is never deleted, however old: a host that was off
    # for weeks keeps its last good backup.
    _newest_ok=""
    for _d in "$BACKUP_OUT"/*; do
        _n="${_d##*/}"
        is_stamp "$_n" && [ -d "$_d" ] && [ ! -L "$_d" ] && [ -f "$_d/OK" ] && _newest_ok="$_n"
    done
    for _d in "$BACKUP_OUT"/*; do
        _n="${_d##*/}"
        is_stamp "$_n" || continue
        [ -d "$_d" ] && [ ! -L "$_d" ] || continue
        [ "$_n" = "${CURRENT:-}" ] && continue
        [ "$_n" = "$_newest_ok" ] && continue
        older "$_n" "$_cutoff" || continue
        rm -rf -- "$_d"
        say "deleted $_n (older than $_keep days)"
    done
}

run() {
    [ -n "${BACKUP_OUT:-}" ] && [ -d "$BACKUP_OUT" ] || die "BACKUP_OUT is not a directory"
    [ -n "${STORAGE:-}" ] && [ -d "$STORAGE" ] || die "STORAGE is not a directory"
    : "${NAMESPACE:?}" "${DATABASES:?}" "${VOLUMES:?}"
    for _c in pg_dump pg_dumpall tar gzip sha256sum find stat sort sed; do
        command -v "$_c" >/dev/null 2>&1 || die "this image has no $_c"
    done

    _start="$(now)"
    CURRENT="$(stamp_of "$_start")"
    DIR="$BACKUP_OUT/$CURRENT"
    [ ! -e "$DIR" ] || die "$DIR exists already"
    mkdir -p "$DIR/db" "$DIR/volumes"
    # The folder goes to the host account whatever happens next, so a failed run
    # can still be read (and deleted) without sudo.
    trap 'owner "$DIR" 2>/dev/null || true; [ -f "$DIR/OK" ] || echo "backup: FAILED: $CURRENT has no OK marker" >&2' EXIT
    say "folder $CURRENT in BACKUP_DIR"

    # --- databases -----------------------------------------------------------
    for _db in $DATABASES; do
        say "pg_dump $_db"
        pg_dump --no-password --format=custom --file="$DIR/db/$_db.dump" --dbname="$_db" \
            || die "pg_dump of $_db failed"
    done
    # Roles and memberships without their passwords: a reference for a restore into
    # a new install, whose own deploys set the passwords from its config.env.
    say "pg_dumpall --globals-only --no-role-passwords"
    pg_dumpall --no-password --globals-only --no-role-passwords --file="$DIR/db/globals.sql" \
        || die "pg_dumpall failed"

    # --- volumes -------------------------------------------------------------
    _count=0
    for _v in "$STORAGE/$NAMESPACE"-*; do
        [ -d "$_v" ] && [ ! -L "$_v" ] || continue
        _base="${_v##*/}"
        _rest="${_base#"$NAMESPACE"-}"
        _claim="$(printf '%s\n' "$_rest" | sed -E 's/-pvc-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$//')"
        [ "$_claim" != "$_rest" ] || continue      # not a provisioner directory
        wanted "$_claim" || continue
        _out="$DIR/volumes/$_claim.tar.gz"
        # Two directories for one claim (a volume left behind by an older install):
        # keep both, the second named by its volume.
        [ -e "$_out" ] && _out="$DIR/volumes/$_claim.${_base##*-pvc-}.tar.gz"
        say "tar $_claim"
        _rc=0
        tar --create --gzip --numeric-owner --one-file-system \
            --file="$_out" --directory="$_v" . || _rc=$?
        case "$_rc" in
            0) ;;
            1) say "note: files of $_claim changed while they were read (tar exit 1); the copy is kept" ;;
            *) die "tar of $_claim failed (exit $_rc)" ;;
        esac
        _count=$((_count + 1))
    done
    say "$_count volume(s) copied"

    # --- manifest and checksums ----------------------------------------------
    (
        cd "$DIR"
        find db volumes -type f -print | LC_ALL=C sort | while IFS= read -r _f; do
            sha256sum -- "$_f"
        done > SHA256SUMS
        {
            echo "# MedCEA backup $CURRENT (started $(iso_of "$_start"))"
            echo "# namespace: $NAMESPACE"
            echo "# databases: $DATABASES"
            echo "# volume patterns: $VOLUMES"
            echo "# bytes	sha256	path"
            _total=0
            while read -r _sum _f; do
                _bytes="$(stat -c %s -- "$_f")"
                _total=$((_total + _bytes))
                printf '%s\t%s\t%s\n' "$_bytes" "$_sum" "$_f"
            done < SHA256SUMS
            echo "# total bytes: $_total"
        } > MANIFEST
    )
    chmod -R go-rwx "$DIR"
    owner "$DIR"

    # --- the OK marker, last -------------------------------------------------
    _end="$(now)"
    printf '%s %s started %s\n' "$_end" "$(iso_of "$_end")" "$CURRENT" > "$DIR/OK.tmp"
    owner "$DIR/OK.tmp"
    mv "$DIR/OK.tmp" "$DIR/OK"
    say "OK: $CURRENT complete ($(grep -c . "$DIR/SHA256SUMS") files)"

    # A pruning failure does not undo a good backup.
    ( prune ) || say "warning: deleting old folders failed; this backup is complete"
}

case "${1:-run}" in
    run)   run ;;
    prune) prune ;;
    *)     die "usage: backup-job.sh run|prune" ;;
esac
