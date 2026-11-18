#!/bin/sh
# apps/research-export/export-job.sh — one export run, inside the pod of CronJob
# research-export (ConfigMap research-export-script; apps/research-export/deploy.sh).
# Research sandbox Phase 2a (codeplan/research-sandbox-plan.md, owner decisions P/F/S of
# 18 Nov 2026): the operational database is read only through the owner-run functions
# medcea.research_*() (EXECUTE only, migration 013), and the research database gets an
# append-only snapshot up to a high-water mark ("the cut").
#
#   1. research side: the latest cut, lake.latest_cut() (none before the first snapshot)
#   2. operational side: cut = the server's now() - 2 minutes (a reading inserted by a
#      transaction that started before the cut has committed by then), the contract
#      version medcea.research_contract_version(); refused (exit 1, nothing written)
#      when the cut is not after the latest one
#   3. operational side, one REPEATABLE READ READ ONLY transaction: every
#      medcea.research_*() function \copy'd TO a file in a private folder under /tmp
#      (measurements only in (previous cut, cut]; the small sets whole)
#   4. research side, one transaction (psql -1, ON_ERROR_STOP): every lake.stage_* table
#      \copy'd FROM its file, then lake.close_snapshot(cut, previous, contract), which
#      moves the staged rows into the lake minus every reserved range, digests them,
#      records the snapshot and empties staging. Any error rolls the whole of it back.
#   5. one line: research-export: snapshot N cut <cut> measurements M
#
# POSIX sh: it runs in research-postgresql's image (the Bitnami PostgreSQL image, psql
# of the server's version), which promises a Debian userland but not bash.
#
# Environment (the CronJob sets every one; nothing comes as an argument):
#   PGHOST_OP OP_PORT OP_DB OP_USER    the operational database and its login
#                                      (svc_research_export, Secret db-svc-research-export)
#   OP_PASSWORD                        that login's password (secretKeyRef)
#   RS_HOST RS_PORT RS_DB RS_USER      the research database and its writer
#                                      (rs_export_writer, Secret research-export-writer)
#   RS_PASSWORD                        the writer's password (secretKeyRef)
#   TMPDIR                             where the private work folder goes (default /tmp)
# The passwords reach psql only as PGPASSWORD in its own environment, never in an
# argument, and nothing here prints them. The files hold no person column (decision P):
# the functions return none.

set -eu
umask 077

say() { printf 'research-export: %s\n' "$*"; }
die() { printf 'research-export: ERROR: %s\n' "$*" >&2; exit 1; }

: "${PGHOST_OP:?}" "${OP_DB:?}" "${OP_USER:?}" "${RS_HOST:?}" "${RS_DB:?}" "${RS_USER:?}"
[ -n "${OP_PASSWORD:-}" ] || die "OP_PASSWORD is empty (Secret db-svc-research-export)"
[ -n "${RS_PASSWORD:-}" ] || die "RS_PASSWORD is empty (Secret research-export-writer)"
for _c in psql mktemp wc tr grep cut tail; do
    command -v "$_c" >/dev/null 2>&1 || die "this image has no $_c"
done

op_psql() {   # op_psql ARGS...: the operational database, SQL on stdin
    PGPASSWORD="$OP_PASSWORD" PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-30}" \
        psql --no-password --no-psqlrc -X -q -v ON_ERROR_STOP=1 \
        --host="$PGHOST_OP" --port="${OP_PORT:-5432}" --username="$OP_USER" --dbname="$OP_DB" "$@"
}
rs_psql() {   # rs_psql ARGS...: the research database, SQL on stdin
    PGPASSWORD="$RS_PASSWORD" PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-30}" \
        psql --no-password --no-psqlrc -X -q -v ON_ERROR_STOP=1 \
        --host="$RS_HOST" --port="${RS_PORT:-5432}" --username="$RS_USER" --dbname="$RS_DB" "$@"
}

# A timestamptz as PostgreSQL prints it under TimeZone UTC ("2026-11-18 03:00:00.123456+00"):
# only digits, - : . + and one space pass, so it can be spliced into SQL as a literal.
is_ts() {
    case "$1" in
        ''|*[!0-9:.+\ -]*) return 1 ;;
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]*) return 0 ;;
    esac
    return 1
}
one_line() { tr -d '\r' | grep -v '^[[:space:]]*$' | tail -n 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/research-export.XXXXXX")" || die "cannot create a work folder in ${TMPDIR:-/tmp}"
case "$WORK" in *[!A-Za-z0-9/._-]*) die "unexpected work folder name $WORK" ;; esac
trap 'rm -rf "$WORK"' EXIT

# --- 1. the latest cut (research side) -----------------------------------------
# (psql's own status is checked before its output is read: dash has no pipefail)
_raw="$(rs_psql -tA <<'SQL'
SET TIME ZONE 'UTC';
SELECT coalesce(lake.latest_cut()::text, 'none');
SQL
)" || die "could not read lake.latest_cut() in $RS_DB on $RS_HOST"
_prev="$(printf '%s\n' "$_raw" | one_line)"
if [ "$_prev" = none ]; then
    PREV_SQL="NULL::timestamptz"
    say "no snapshot yet: this one starts from the beginning"
else
    is_ts "$_prev" || die "lake.latest_cut() gave an unexpected answer"
    PREV_SQL="'$_prev'::timestamptz"
    say "latest cut $_prev"
fi

# --- 2. the cut and the contract (operational side) ----------------------------
_raw="$(op_psql -tA <<SQL
SET TIME ZONE 'UTC';
SELECT (now() - interval '2 minutes')::text
       || '|' || medcea.research_contract_version()::text
       || '|' || CASE WHEN $PREV_SQL IS NOT NULL AND now() - interval '2 minutes' <= $PREV_SQL
                      THEN 'stale' ELSE 'ok' END;
SQL
)" || die "could not read the cut and medcea.research_contract_version() in $OP_DB on $PGHOST_OP"
_ans="$(printf '%s\n' "$_raw" | one_line)"
CUT="${_ans%%|*}"; _rest="${_ans#*|}"
CONTRACT="${_rest%%|*}"; VERDICT="${_rest#*|}"
is_ts "$CUT" || die "the operational database gave an unexpected cut"
case "$CONTRACT" in ''|*[!0-9]*) die "medcea.research_contract_version() gave an unexpected answer" ;; esac
case "$VERDICT" in
    ok) ;;
    stale) die "refused: the cut $CUT is not after the latest snapshot's cut $_prev; nothing was exported" ;;
    *) die "the operational database gave an unexpected answer" ;;
esac
CUT_SQL="'$CUT'::timestamptz"
say "cut $CUT, contract version $CONTRACT"

# --- 3. every function to a file (operational side, one snapshot of it) --------
# stage|function arguments|columns: the stage table lake.stage_<stage> has exactly the
# columns medcea.research_<stage>() returns (migration 013, apps/research/db/); both
# sides name them, so a reordered column cannot shift a value into another one.
TABLES='measurements|'"$PREV_SQL, $CUT_SQL"'|ingested_at, measured_at, unit_code, zone_code, tag, sensor, value, uom
units||unit_code, recipe_type, area, height, is_active
zones||unit_code, zone_code, is_active
recipes||recipe_id, recipe_type, status
recipe_lines||recipe_id, seq, cycle_number, light_type, light_on_minutes, light_off_minutes, setpoints
runs||run_id, recipe_id, unit_code, started_at, ended_at, status
cycles||run_id, seq, cycle_num, started_at, ended_at, status, algorithm_code, algorithm_params, control_loops
control_loops||unit_code, zone_code, loop_code, input, output
param_sets||params_id, algorithm_code, unit_code, params
catalogue||kind, code, doc'

# printf, never echo: dash's echo reads "\c" in "\copy" as "stop the output here".
{
    printf '%s\n' "SET TIME ZONE 'UTC';" "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;"
    printf '%s\n' "$TABLES" | while IFS='|' read -r _t _args _cols; do
        printf '\\copy (SELECT %s FROM medcea.research_%s(%s)) TO %s\n' "$_cols" "$_t" "$_args" "'$WORK/$_t.copy'"
    done
    printf '%s\n' "COMMIT;"
} > "$WORK/dump.sql"
op_psql -f "$WORK/dump.sql" >/dev/null || die "reading the medcea.research_*() functions failed; nothing was written"

# --- 4. one research transaction: stage, then close the snapshot ---------------
for _t in $(printf '%s\n' "$TABLES" | cut -d'|' -f1); do
    [ -f "$WORK/$_t.copy" ] || die "reading medcea.research_$_t() left no file; nothing was written"
done
{
    printf '%s\n' "SET TIME ZONE 'UTC';"
    printf '%s\n' "$TABLES" | while IFS='|' read -r _t _args _cols; do
        printf '\\copy lake.stage_%s (%s) FROM %s\n' "$_t" "$_cols" "'$WORK/$_t.copy'"
    done
    printf '%s\n' "SELECT 'snapshot=' || lake.close_snapshot($CUT_SQL, $PREV_SQL, $CONTRACT);"
} > "$WORK/load.sql"
_raw="$(rs_psql -tA -1 -f "$WORK/load.sql")" \
    || die "loading the snapshot into $RS_DB failed; the research transaction was rolled back, nothing was written"
_out="$(printf '%s\n' "$_raw" | tr -d '\r' | grep '^snapshot=' | tail -n 1)" || _out=""
SNAP="${_out#snapshot=}"
case "$SNAP" in ''|*[!0-9]*) die "lake.close_snapshot() gave an unexpected answer" ;; esac

_m="$(wc -l < "$WORK/measurements.copy" | tr -d '[:space:]')"
say "snapshot $SNAP cut $CUT measurements $_m"
