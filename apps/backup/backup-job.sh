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
#   DATABASES      the databases to dump, custom format (pg_restore reads them);
#                  one that cannot be dumped fails the run
#   OPTIONAL_DATABASES  databases dumped the same way only when they exist (asked in
#                  database postgres first): "superset", which only an install with
#                  Superset has. An absent one is a MANIFEST line and a log line, never
#                  a failure; a question psql cannot answer fails the run, since the
#                  database might exist and would then be missing from the backup.
#   RESEARCH_DB_HOST  the research sandbox's PostgreSQL (research-postgresql.<ns>-research),
#                  always rendered by the deploy, whatever RESEARCH_ENABLED says (research
#                  sandbox Phase 2a), so research enabled later is backed up without a
#                  backup redeploy
#   RESEARCH_DB    its database (medcea_research), dumped like the others into
#                  db/<RESEARCH_DB>.dump only when the host is set, RESEARCH_PGPASSWORD is
#                  set (Secret research-backup, optional) and the database exists. Without
#                  the Secret: "skipped … (no research database on this install: no Secret
#                  research-backup)" and "# databases skipped (no Secret research-backup, …)"
#                  in MANIFEST; a server that answers without it: "# databases skipped
#                  (absent)". A server that does not answer while the Secret exists is no
#                  failure of the platform's backup: its line is "# databases not reached"
#                  (the health check rsexport reports the research database itself). A dump
#                  that fails once the database is known to exist fails the run, as any
#                  dump does.
#   RESEARCH_PGUSER RESEARCH_PGPASSWORD  its login (rs_backup, pg_read_all_data), given to
#                  psql and pg_dump only as PGUSER/PGPASSWORD in their own environment
#   POLICY_DB      the platform database whose access-policy hash chain head goes into
#                  MANIFEST (default: the first of DATABASES)
#   VOLUMES        claim name patterns to copy, e.g. "claim-* node-red grafana"
#   RESEARCH_NAMESPACE  the research sandbox's namespace (research Phase 2b: the AI workbench
#                  lives there once the access policy places it in the research zone). Its
#                  directories are never taken for the platform's (a research namespace named
#                  <NAMESPACE>-research would otherwise look like one of the platform's)
#   RESEARCH_VOLUMES    claim name patterns to copy from RESEARCH_NAMESPACE, e.g.
#                  "claim-* hub-db-dir"; each is volumes/research-<claim>.tar.gz. Empty, or
#                  RESEARCH_NAMESPACE empty: no research volume is copied
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
#
# MANIFEST also names the head of the access policy's hash chain (iam_policy.history,
# IAM 4.5, design §14.8.10), read before the dumps: the chain is append-only, so the
# dump holds at least that head, and a restore that verifies a shorter chain was cut.
# Without the schema, or when the read fails, the line says unavailable and the
# backup goes on.

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
wanted() {   # wanted CLAIM [PATTERNS]: PATTERNS default to VOLUMES
    _hit=1
    _pats="${2-$VOLUMES}"
    set -f
    for _p in $_pats; do
        case "$1" in $_p) _hit=0 ;; esac
    done
    set +f
    return "$_hit"
}

# copy_volumes NAMESPACE PATTERNS PREFIX — tar every provisioner directory
# <NAMESPACE>-<claim>-pvc-<uid> whose claim matches PATTERNS into volumes/<PREFIX><claim>.tar.gz;
# adds to _count and one line "volumes/<archive> <directory> <newest file's epoch|->" to
# $DIR/.volume-sources (MANIFEST's "# volume" lines). For the platform (PREFIX empty) a
# directory of RESEARCH_NAMESPACE is skipped.
copy_volumes() {
    _cns="$1"; _cpats="$2"; _cpre="$3"
    for _v in "$STORAGE/$_cns"-*; do
        [ -d "$_v" ] && [ ! -L "$_v" ] || continue
        _base="${_v##*/}"
        if [ -z "$_cpre" ] && [ -n "${RESEARCH_NAMESPACE:-}" ] && [ "$RESEARCH_NAMESPACE" != "$_cns" ]; then
            case "$_base" in "$RESEARCH_NAMESPACE"-*) continue ;; esac
        fi
        _rest="${_base#"$_cns"-}"
        _claim="$(printf '%s\n' "$_rest" | sed -E 's/-pvc-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$//')"
        [ "$_claim" != "$_rest" ] || continue      # not a provisioner directory
        wanted "$_claim" "$_cpats" || continue
        _out="$DIR/volumes/$_cpre$_claim.tar.gz"
        # Two directories for one claim (a volume left behind by an older install, or by a
        # move: its Retain volume stays until removed by hand): keep both, the second named
        # by its volume.
        [ -e "$_out" ] && _out="$DIR/volumes/$_cpre$_claim.${_base##*-pvc-}.tar.gz"
        say "tar $_cpre$_claim"
        _rc=0
        tar --create --gzip --numeric-owner --one-file-system \
            --file="$_out" --directory="$_v" . || _rc=$?
        case "$_rc" in
            0) ;;
            1) say "note: files of $_cpre$_claim changed while they were read (tar exit 1); the copy is kept" ;;
            *) die "tar of $_cpre$_claim failed (exit $_rc)" ;;
        esac
        # Which directory the archive holds, and when its newest file changed: with two
        # directories for one claim (a move's Retain copy beside the live one) restore-help
        # picks by these MANIFEST lines, never by the archive's name.
        _newest="$(find "$_v" -xdev -type f -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | tail -n 1 | cut -d. -f1)"
        case "$_newest" in ''|*[!0-9]*) _newest="" ;; esac
        printf '%s %s %s\n' "volumes/${_out##*/}" "$_base" "${_newest:--}" >> "$DIR/.volume-sources"
        _count=$((_count + 1))
    done
}

# chain_head: one line for MANIFEST, never fails. psql reads the query on stdin; the
# \if keeps a database without iam_policy (no access policy yet) from an error.
chain_head() {
    _hdb="${POLICY_DB:-${DATABASES%% *}}"
    _rc=0
    _ans="$(psql --no-password --no-psqlrc -X -q -tA -v ON_ERROR_STOP=1 --dbname="$_hdb" 2>&1 <<'SQL'
BEGIN TRANSACTION READ ONLY;
SELECT pg_catalog.to_regclass('iam_policy.history') IS NOT NULL
   AND pg_catalog.to_regprocedure('iam_policy.verify_chain()') IS NOT NULL AS has_chain \gset
\if :has_chain
SELECT 'head ' || coalesce((SELECT h.event_id || ' ' || h.hash FROM iam_policy.history h ORDER BY h.event_id DESC LIMIT 1),
                           'none -')
       || ' ' || CASE WHEN (SELECT vc.ok FROM iam_policy.verify_chain() vc) THEN 't' ELSE 'f' END;
\else
SELECT 'no-schema';
\endif
COMMIT;
SQL
)" || _rc=$?
    # one line, no control characters, bounded: it goes into MANIFEST and the Job's log
    _one="$(printf '%s\n' "$_ans" | tr -d '\r' | grep -v '^[[:space:]]*$' | tail -n 1 | tr -c '[:print:]\n' ' ' | cut -c1-200)"
    if [ "$_rc" -ne 0 ]; then
        echo "# policy chain head: unavailable (psql exit $_rc: ${_one:-no message})"
        return 0
    fi
    set -f; set -- $_one; set +f
    case "${1:-}" in
        no-schema) echo "# policy chain head: unavailable (no iam_policy schema in $_hdb)"; return 0 ;;
        head) ;;
        *) echo "# policy chain head: unavailable (unexpected answer from psql)"; return 0 ;;
    esac
    if [ "${2:-}" = none ]; then
        echo "# policy chain head: unavailable (iam_policy.history is empty)"
        return 0
    fi
    case "${2:-}" in ''|*[!0-9]*) echo "# policy chain head: unavailable (unexpected answer from psql)"; return 0 ;; esac
    case "${3:-}" in ''|*[!0-9a-f]*) echo "# policy chain head: unavailable (unexpected answer from psql)"; return 0 ;; esac
    case "${4:-}" in t|f) ;; *) echo "# policy chain head: unavailable (unexpected answer from psql)"; return 0 ;; esac
    echo "# policy chain head (read before the dump): $2 $3 verify_chain=$4"
}

# db_exists NAME: prints t or f; fails when psql cannot answer. The name goes in as
# a psql variable, quoted by psql (:'name'), and must look like a database name.
db_exists() {
    case "$1" in ''|*[!a-z0-9_]*) die "OPTIONAL_DATABASES: '$1' is not a plain database name" ;; esac
    _ex="$(psql --no-password --no-psqlrc -X -q -tA -v ON_ERROR_STOP=1 --dbname=postgres -v "name=$1" 2>/dev/null <<'SQL'
SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = :'name');
SQL
)" || return 1
    case "$(printf '%s' "$_ex" | tr -d '[:space:]')" in
        t) echo t ;;
        f) echo f ;;
        *) return 1 ;;
    esac
}

# research_db_exists: t or f for RESEARCH_DB on RESEARCH_DB_HOST, asked as RESEARCH_PGUSER
# in database postgres; fails when psql cannot answer. Its password goes into psql's own
# environment only.
research_db_exists() {
    _ex="$(PGHOST="$RESEARCH_DB_HOST" PGPORT="${RESEARCH_PGPORT:-5432}" PGUSER="${RESEARCH_PGUSER:-rs_backup}" \
        PGPASSWORD="$RESEARCH_PGPASSWORD" \
        psql --no-password --no-psqlrc -X -q -tA -v ON_ERROR_STOP=1 --dbname=postgres -v "name=$RESEARCH_DB" 2>/dev/null <<'SQL'
SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = :'name');
SQL
)" || return 1
    case "$(printf '%s' "$_ex" | tr -d '[:space:]')" in
        t) echo t ;;
        f) echo f ;;
        *) return 1 ;;
    esac
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
    for _c in pg_dump pg_dumpall psql tar gzip sha256sum find stat sort sed; do
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
    # The policy chain's head first: the dump then holds at least this head.
    _head="$(chain_head)"
    say "${_head#\# }"
    for _db in $DATABASES; do
        say "pg_dump $_db"
        pg_dump --no-password --format=custom --file="$DIR/db/$_db.dump" --dbname="$_db" \
            || die "pg_dump of $_db failed"
    done
    _dumped="$DATABASES"
    _absent=""
    for _db in ${OPTIONAL_DATABASES:-}; do
        _e="$(db_exists "$_db")" || die "could not ask PostgreSQL whether database $_db exists"
        if [ "$_e" = f ]; then
            say "skipped $_db (no such database on this install)"
            _absent="${_absent:+$_absent }$_db"
            continue
        fi
        say "pg_dump $_db"
        pg_dump --no-password --format=custom --file="$DIR/db/$_db.dump" --dbname="$_db" \
            || die "pg_dump of $_db failed"
        _dumped="$_dumped $_db"
    done
    # The research sandbox's database, on its own server (Phase 2a). Three outcomes
    # kept apart in the log and in MANIFEST: no Secret research-backup (research is not
    # installed here, or ./apps/research/deploy.sh has not run yet), a server that
    # answers without the database, and a server that does not answer.
    _unreached=""
    _nosecret=""
    if [ -n "${RESEARCH_DB:-}" ]; then
        case "$RESEARCH_DB" in *[!a-z0-9_]*) die "RESEARCH_DB: '$RESEARCH_DB' is not a plain database name" ;; esac
        _e=nosecret
        if [ -n "${RESEARCH_DB_HOST:-}" ] && [ -n "${RESEARCH_PGPASSWORD:-}" ]; then
            _e="$(research_db_exists)" || _e=unreached
        fi
        case "$_e" in
            nosecret)
                say "skipped $RESEARCH_DB (no research database on this install: no Secret research-backup)"
                _nosecret="$RESEARCH_DB" ;;
            f)  say "skipped $RESEARCH_DB (${RESEARCH_DB_HOST} answered: no such database on it)"
                _absent="${_absent:+$_absent }$RESEARCH_DB" ;;
            unreached)
                say "warning: $RESEARCH_DB_HOST did not answer although Secret research-backup exists: $RESEARCH_DB is not in this backup (the platform's databases are)"
                _unreached="$RESEARCH_DB" ;;
            t)  say "pg_dump $RESEARCH_DB ($RESEARCH_DB_HOST)"
                PGHOST="$RESEARCH_DB_HOST" PGPORT="${RESEARCH_PGPORT:-5432}" PGUSER="${RESEARCH_PGUSER:-rs_backup}" \
                    PGPASSWORD="$RESEARCH_PGPASSWORD" \
                    pg_dump --no-password --format=custom --file="$DIR/db/$RESEARCH_DB.dump" --dbname="$RESEARCH_DB" \
                    || die "pg_dump of $RESEARCH_DB failed"
                _dumped="$_dumped $RESEARCH_DB" ;;
        esac
    fi
    # Roles and memberships without their passwords: a reference for a restore into
    # a new install, whose own deploys set the passwords from its config.env.
    say "pg_dumpall --globals-only --no-role-passwords"
    pg_dumpall --no-password --globals-only --no-role-passwords --file="$DIR/db/globals.sql" \
        || die "pg_dumpall failed"

    # --- volumes -------------------------------------------------------------
    _count=0
    copy_volumes "$NAMESPACE" "$VOLUMES" ""
    # The research sandbox's namespace (Phase 2b): the AI workbench's homes and hub database
    # once the access policy places the workbench there; a home the move copied is
    # <RESEARCH_NAMESPACE>-<claim>-pvc-<uuid>, as the provisioner names its own.
    _rs_pats=""
    case "${RESEARCH_NAMESPACE:-}" in
        ''|*[!a-z0-9-]*) ;;
        "$NAMESPACE") ;;
        *) _rs_pats="${RESEARCH_VOLUMES:-}"
           [ -z "$_rs_pats" ] || copy_volumes "$RESEARCH_NAMESPACE" "$_rs_pats" "research-" ;;
    esac
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
            echo "# databases: $_dumped"
            [ -z "$_absent" ] || echo "# databases skipped (absent): $_absent"
            [ -z "$_nosecret" ] || echo "# databases skipped (no Secret research-backup, no research database on this install): $_nosecret"
            [ -z "$_unreached" ] || echo "# databases not reached: $_unreached"
            echo "# volume patterns: $VOLUMES"
            [ -z "$_rs_pats" ] \
                || echo "# research volume patterns ($RESEARCH_NAMESPACE, as volumes/research-<claim>): $_rs_pats"
            echo "$_head"
            # one line per volume archive: the directory it holds and its newest file's time
            if [ -f .volume-sources ]; then
                while read -r _a _src _t; do
                    if [ "$_t" = "-" ]; then _t="unknown"; else _t="$(iso_of "$_t")"; fi
                    echo "# volume $_a from $_src newest file $_t"
                done < .volume-sources
            fi
            echo "# bytes	sha256	path"
            _total=0
            while read -r _sum _f; do
                _bytes="$(stat -c %s -- "$_f")"
                _total=$((_total + _bytes))
                printf '%s\t%s\t%s\n' "$_bytes" "$_sum" "$_f"
            done < SHA256SUMS
            echo "# total bytes: $_total"
        } > MANIFEST
        rm -f .volume-sources
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
