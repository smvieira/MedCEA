#!/usr/bin/env bash
# infra/lib-policy-source.sh — where every compile of the access policy reads it
# (IAM Phase 4, design §3.4, §14.4.4). Sourced by each ENTRY script that compiles the
# policy, after config.env and lib-mk8s.sh; defines functions only, takes no lock (its
# writing modes require the lock the caller holds, verified with medcea_lock_verify).
#
#   policy_source_init NS              before the first compile of a deploy (write mode)
#   policy_source_init NS --precheck   deploy-infra only, right after the API wait:
#                                      read-only, the skeleton gate only; 2 on a widening
#   policy_source_init NS --read-only  health-check.sh and the live tests: never writes,
#                                      never accepts, never locks, always returns 0; first
#                                      unsets every inherited MEDCEA_POLICY_* source variable;
#                                      sets POLICY_SOURCE_VERDICT (ok|warn|fail|skip),
#                                      POLICY_SOURCE_DETAIL, POLICY_SOURCE_STATE (the state
#                                      word) and POLICY_SOURCE_STATE_FILE (the --full state
#                                      document, kept for the run; the caller removes its
#                                      directory)
#   policy_source_finish NS COMPONENT  the last command of a compiling entry script's
#                                      success path: ends an open policy break-glass for
#                                      COMPONENT (break_glass_ended); never fails
#   policy_db_state NS OUT [--full] [--no-wait]
#                                      read the applied version (read-only): prints the state
#                                      word (none | empty | partial | version-N | unreachable),
#                                      writes the JSON document to OUT (mode 600; its "pod"
#                                      names the PostgreSQL pod it asked, so a caller that ran it
#                                      in $(...) still has it: _ps_doc_pod OUT) and sets
#                                      POLICY_DB_POD (lost in a $(...) subshell); returns 1 when
#                                      PostgreSQL answered with an error. Also apply.sh,
#                                      deploy-apps and health
#   policy_state_retire WHY            under a verified lock: move state/policy-applied.yaml,
#                                      state/seed-facts.jsonl, state/break-glass/ and (except
#                                      for WHY=restore) state/.policy-versioned into
#                                      state/retired-<UTC ts>-<WHY>/ (purge-data, reset,
#                                      uninstall: called by those scripts; restore, rollback:
#                                      by hand, docs/manual); deletes nothing
#   _ps_flush_seed_facts NS POD SYSTEM_AS
#                                      record the queued account_seeded facts (one
#                                      transaction); a failure warns and keeps the queue
#
# Write mode, in order (design §14.4.4): the lock is verified (1 otherwise); the marker
# path (MEDCEA_POLICY_SOURCE_DONE == MEDCEA_LOCK_HELD: a parent verified for this run; a
# set MEDCEA_POLICY_FILE still needs its recorded event and sha256, a host file its own
# checks); MEDCEA_POLICY_FILE needs MEDCEA_POLICY_BREAK_GLASS; then the database's state:
#   none | empty   defaults.yaml; a host file then is fatal, and so is break-glass (no
#                  applied version to break away from); empty flushes the seed queue
#   partial        fatal: ./apps/iam/apply.sh --status
#   unreachable    fatal, with or without a host file: nothing is compiled unverified
#   version-N      the skeleton gate (equal; narrowing: accepted as system:deploy and
#                  recorded; widening: return 2, nothing written, under break-glass too),
#                  then break-glass (asked at the terminal, snapshotted into
#                  state/break-glass/, checked, recorded as break_glass_seen), then the
#                  host file rewritten when absent or different, then the seed queue
# then the marker is exported (MEDCEA_POLICY_SOURCE_DONE, MEDCEA_POLICY_STATE,
# MEDCEA_POLICY_BG_OPEN) for the children of this run.
# Returns: 0 go on; 1 refused (or failed); 2 a widening git skeleton (callers `|| exit $?`).
#
# Break-glass does NOT bypass the skeleton gate: MEDCEA_POLICY_FILE changes which matrix
# and waivers are compiled, never the skeleton (OA-a, design §3.5).
#
# NOT sourced by infra/lib-policy-tools.sh or edge/: the onboarding daemon and
# flash-device.sh compile at boot or without the microk8s group; they only read the host
# file through cli.py (an unreadable state/ is exit 2 there, never a silent defaults).
# policy_tool refuses MEDCEA_POLICY_FILE unless this run recorded it.
#
# Needs: KUBECTL (lib-mk8s.sh), POSTGRES_DB (config.env), optionally PG_RELEASE, TIMEOUT,
# WORKBENCH_ENABLED, MEDCEA_POLICY_COMPONENTS (deploy-apps: the compiling components it runs).
# It finds its own libraries from its own path, whatever REPO_ROOT and the working directory.

_PS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_HOST_FILE="$_PS_ROOT/state/policy-applied.yaml"
_PS_CLI="$_PS_ROOT/apps/iam/compiler/cli.py"

# lib-lock.sh (medcea_lock_verify), lib-db-apply.sh (_dba_psql, dba_record_event) and
# lib-db-roles.sh (_dbr_pg_pod), from this tree; REPO_ROOT only for their sourcing.
_ps_load() {
    local REPO_ROOT="$_PS_ROOT"
    declare -F medcea_lock_verify >/dev/null || source "$_PS_ROOT/infra/lib-lock.sh"
    declare -F _dba_psql >/dev/null || source "$_PS_ROOT/apps/database/lib-db-apply.sh"
    declare -F _dbr_pg_pod >/dev/null || source "$_PS_ROOT/infra/lib-db-roles.sh"
}
_ps_load

_ps_say()  { echo -e "\033[0;32m[policy]\033[0m $*"; }
_ps_warn() { echo -e "\033[0;33mWARNING: [policy] $*\033[0m" >&2; }
_ps_err()  { echo -e "\033[0;31mERROR: [policy] $*\033[0m" >&2; }

# _ps_py CODE ARGS... — python3 with apps/iam on sys.path (from compiler import source)
_ps_py() {
    python3 -c "import sys; sys.path.insert(0, sys.argv.pop(1)); $1" "$_PS_ROOT/apps/iam" "${@:2}"
}

# _ps_get FILE EXPR — one value of a JSON file (EXPR over `d`), printed; JSON for lists/dicts
_ps_get() {
    _ps_py 'import json
d = json.load(open(sys.argv[1]))
v = eval(sys.argv[2], {"d": d})
print(json.dumps(v) if isinstance(v, (list, dict)) else ("" if v is None else v))' "$1" "$2"
}

_ps_db() { echo "${POSTGRES_DB:-${CEA_DB:-medcea_db}}"; }

# _ps_kubectl_usable — the first word of KUBECTL resolves (a function counts: mk8s), and
# for mk8s/sudo/microk8s the microk8s command exists too
_ps_kubectl_usable() {
    local first
    read -r first _ <<<"${KUBECTL:-}"
    [[ -n "$first" ]] && command -v "$first" >/dev/null 2>&1 || return 1
    case "$first" in
        mk8s|sudo|microk8s) command -v microk8s >/dev/null 2>&1 || return 1 ;;
    esac
}

_ps_killtree() {
    local c
    for c in $(pgrep -P "$1" 2>/dev/null); do _ps_killtree "$c"; done
    kill -TERM "$1" 2>/dev/null
}

# _ps_bounded SECONDS INFILE CMD... — CMD (a function too) with stdin from INFILE, killed
# with its children after SECONDS; no bound when SECONDS is empty
_ps_bounded() {
    local t="$1" in="$2" p w rc
    shift 2
    if [[ -z "$t" ]]; then
        "$@" <"$in"
        return
    fi
    "$@" <"$in" 9>&- &
    p=$!
    ( sleep "$t"; _ps_killtree "$p" ) </dev/null >/dev/null 2>&1 9>&- &
    w=$!
    wait "$p"; rc=$?
    _ps_killtree "$w"; wait "$w" 2>/dev/null
    return $rc
}

# _ps_doc OUT STATE DETAIL — a state document without a database answer
_ps_doc() {
    _ps_py 'import json
json.dump({"state": sys.argv[2], "detail": sys.argv[3], "break_glass_open": []}, open(sys.argv[1], "w"))' "$1" "$2" "$3"
}

# The policy history events a person reads as "the policy's" (last_events)
_PS_POLICY_EVENTS="h.version IS NOT NULL OR h.event IN ('account_seeded', 'break_glass_seen', 'break_glass_ended')
                   OR h.event LIKE 'skeleton\\_%' OR h.event LIKE 'apply\\_%' OR h.event LIKE 'bootstrap\\_%'
                   OR h.event LIKE 'waiver\\_%' OR h.event LIKE 'policy\\_%'"

# _ps_state_sql FULL — the read-only query (psql, -tA): one JSON line
_ps_state_sql() {
    local full="$1" extra="" pre=""
    if [[ "$full" == true ]]; then
        # apply_reverted's account decisions still waiting for qa's review (design §14.4.14
        # WARN, F-18): per apply_reverted event, the decisions made between the reverted
        # version's apply and the revert that are still 'applied' (a pure narrowing qa has
        # not reviewed). iam.account_decision belongs to the access component, so the
        # query runs only when it exists (psql \if; a static reference would fail without it).
        pre="SELECT pg_catalog.to_regclass('iam.account_decision') IS NOT NULL AS has_decisions \\gset
\\if :has_decisions
SELECT coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('event_id', r.event_id, 'version', r.version,
        'at', r.at, 'unreviewed', r.n) ORDER BY r.event_id)
        FROM (SELECT h.event_id, h.at, (h.payload ->> 'version')::int AS version,
                     (SELECT pg_catalog.count(*) FROM iam.account_decision d
                       WHERE d.status = 'applied' AND d.made_at <= h.at
                         AND d.made_at >= (SELECT pg_catalog.max(a.at) FROM iam_policy.history a
                                            WHERE a.event IN ('applied', 'bootstrap_applied') AND a.event_id < h.event_id
                                              AND a.version = (h.payload ->> 'version')::int)) AS n
                FROM iam_policy.history h
               WHERE h.event = 'apply_reverted' AND h.payload ->> 'version' ~ '^[0-9]+\$') r
       WHERE r.n > 0), '[]')::text AS reverted_unreviewed \\gset
\\else
SELECT '[]' AS reverted_unreviewed \\gset
\\endif"
        extra="|| pg_catalog.jsonb_build_object(
  'reverted_unreviewed', :'reverted_unreviewed'::jsonb,
  'open_versions', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('version', v.version, 'status', v.status,
        'kind', v.kind, 'age_days', pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.now() - v.created_at) / 86400)::int)
        ORDER BY v.version) FROM iam_policy.version v WHERE v.status IN ('draft', 'submitted', 'approved')), '[]'),
  'unconfirmed', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('version', v.version, 'kind', v.kind,
        'status', v.status) ORDER BY v.version) FROM iam_policy.version v
        WHERE v.kind IN ('bootstrap', 'rollback') AND v.status IN ('applied', 'superseded')
          AND v.confirmed_at IS NULL AND v.disputed_at IS NULL), '[]'),
  'disputed_not_superseded', coalesce((SELECT pg_catalog.jsonb_agg(v.version ORDER BY v.version) FROM iam_policy.version v
        WHERE v.disputed_at IS NOT NULL AND v.status = 'applied'), '[]'),
  'audit_findings', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(a)) FROM iam_policy.audit_versions() a), '[]'),
  'chain_ok', (SELECT vc.ok FROM iam_policy.verify_chain() vc),
  'apply_deferred_open', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('event_id', h.event_id, 'at', h.at)
        ORDER BY h.event_id) FROM iam_policy.history h WHERE h.event = 'apply_deferred' AND h.version = ap.version
          AND h.event_id > coalesce((SELECT max(c.event_id) FROM iam_policy.history c
                                      WHERE c.event IN ('applied', 'bootstrap_applied') AND c.version = ap.version), 0)), '[]'),
  'waivers_review', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', w.id, 'review_by', w.review_by)
        ORDER BY w.id COLLATE \"C\") FROM iam_policy.waiver w WHERE w.version = ap.version), '[]'),
  'last_events', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) ORDER BY x.event_id DESC)
        FROM (SELECT h.event_id, h.event, h.version, h.actor_name AS actor, h.at FROM iam_policy.history h
               WHERE $_PS_POLICY_EVENTS ORDER BY h.event_id DESC LIMIT 10) x), '[]'),
  'seeded', coalesce((SELECT pg_catalog.jsonb_object_agg(z.sub, z.facts) FROM (
        SELECT h.payload ->> 'sub' AS sub, pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('event_id', h.event_id,
               'fact', h.payload -> 'fact', 'username', h.payload -> 'username', 'role', h.payload -> 'role',
               'person_id', h.payload -> 'person_id') ORDER BY h.event_id) AS facts
          FROM iam_policy.history h WHERE h.event = 'account_seeded' AND h.payload ? 'sub' GROUP BY 1) z), '{}'),
  'accepts', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('event_id', h.event_id,
        'from', h.payload ->> 'from', 'to', h.payload ->> 'digest', 'from_body', fs.body, 'to_body', ts.body,
        'version', h.version, 'reviewed_by_version', h.payload -> 'reviewed_by_version',
        'entries', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('role', e.role, 'group_code', e.group_code,
                   'level', e.level::text, 'constraint_name', e.constraint_name)) FROM iam_policy.entry e WHERE e.version = h.version), '[]'),
        'waivers', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(w) - 'version' ORDER BY w.id COLLATE \"C\")
                   FROM iam_policy.waiver w WHERE w.version = h.version), '[]')) ORDER BY h.event_id)
        FROM iam_policy.history h
        LEFT JOIN iam_policy.skeleton fs ON fs.digest = h.payload ->> 'from'
        LEFT JOIN iam_policy.skeleton ts ON ts.digest = h.payload ->> 'digest'
       WHERE h.event = 'skeleton_accepted' AND h.payload ->> 'from' IS NOT NULL), '[]'))"
    fi
    cat <<SQL
BEGIN TRANSACTION READ ONLY;
SELECT pg_catalog.to_regclass('iam_policy.skeleton') IS NOT NULL
   AND pg_catalog.to_regclass('iam_policy.version') IS NOT NULL
   AND pg_catalog.to_regprocedure('iam_policy._accepted()') IS NOT NULL AS has008c \\gset
\\if :has008c
$pre
SELECT (pg_catalog.jsonb_build_object(
  'state', CASE WHEN NOT EXISTS (SELECT 1 FROM iam_policy.version) THEN 'empty'
                WHEN ap.version IS NULL THEN 'partial' ELSE 'version-' || ap.version END,
  'version', ap.version, 'kind', ap.kind, 'status', ap.status, 'entries_digest', ap.entries_digest,
  'groups', pg_catalog.to_jsonb(ap.groups), 'roles', pg_catalog.to_jsonb(ap.roles), 'based_on', ap.based_on,
  'confirmed_at', ap.confirmed_at, 'disputed_at', ap.disputed_at, 'claimed_by_person', ap.claimed_by_person,
  'accepted', (SELECT pg_catalog.jsonb_build_object('digest', s.digest, 'body', s.body, 'git_commit', s.git_commit)
                 FROM iam_policy.skeleton s WHERE s.digest = iam_policy._accepted()),
  'entries', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('role', e.role, 'group_code', e.group_code,
                 'level', e.level::text, 'constraint_name', e.constraint_name)
                 ORDER BY e.role COLLATE "C", e.group_code COLLATE "C", e.level::text COLLATE "C")
                 FROM iam_policy.entry e WHERE e.version = ap.version), '[]'),
  'waivers', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(w) - 'version' ORDER BY w.id COLLATE "C")
                 FROM iam_policy.waiver w WHERE w.version = ap.version), '[]'),
  'last_apply_event', (SELECT pg_catalog.jsonb_build_object('event', h.event, 'event_id', h.event_id, 'at', h.at)
                 FROM iam_policy.history h WHERE h.version = ap.version
                  AND h.event IN ('apply_started', 'applied', 'bootstrap_applied', 'apply_reverted', 'partial_apply', 'apply_deferred')
                 ORDER BY h.event_id DESC LIMIT 1),
  'break_glass_open', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('event_id', b.event_id, 'at', b.at,
                 'reason', b.payload ->> 'reason', 'components', b.payload -> 'components', 'open', b.open) ORDER BY b.event_id)
                 FROM (SELECT h.event_id, h.at, h.payload,
                              (SELECT coalesce(pg_catalog.jsonb_agg(c.value ORDER BY c.value), '[]')
                                 FROM pg_catalog.jsonb_array_elements_text(CASE WHEN pg_catalog.jsonb_typeof(h.payload -> 'components') = 'array'
                                                                               THEN h.payload -> 'components' ELSE '[]' END) AS c(value)
                                WHERE NOT EXISTS (SELECT 1 FROM iam_policy.history e
                                                   WHERE e.event = 'break_glass_ended'
                                                     AND e.payload ->> 'since_event' = h.event_id::text
                                                     AND e.payload ->> 'component' = c.value)) AS open
                         FROM iam_policy.history h
                        WHERE h.event = 'break_glass_seen' AND h.payload ->> 'source' = 'file') b
                WHERE b.open <> '[]'::jsonb), '[]'),
  'system_functions', pg_catalog.jsonb_build_object(
                 'system_as', pg_catalog.to_regprocedure('iam_policy._system_as(text[])') IS NOT NULL,
                 'record', pg_catalog.to_regprocedure('iam_policy._record(text,jsonb)') IS NOT NULL)
) $extra)::text
  FROM (SELECT 1) one LEFT JOIN iam_policy.version ap ON ap.status = 'applied';
\\else
SELECT '{"state": "none", "detail": "no migration 008c (iam_policy.skeleton): ./apps/database/deploy.sh", "break_glass_open": []}';
\\endif
COMMIT;
SQL
}

# policy_db_state NS OUT [--full] [--no-wait] — see the header. Read-only.
policy_db_state() {
    local ns="${1:-}" out="${2:-}" full=false wait=true a
    if [[ -z "$ns" || -z "$out" ]]; then
        echo "policy_db_state: usage: policy_db_state NS OUT [--full] [--no-wait]" >&2
        return 2
    fi
    shift 2
    for a in "$@"; do
        case "$a" in
            --full) full=true ;;
            --no-wait) wait=false ;;
            *) echo "policy_db_state: unknown option '$a' (--full, --no-wait)" >&2; return 2 ;;
        esac
    done
    ( umask 077; : >"$out" ) || return 1
    POLICY_DB_POD=""
    if ! _ps_kubectl_usable; then
        _ps_doc "$out" none "no usable kubectl (${KUBECTL:-KUBECTL unset})"; echo none; return 0
    fi
    local KUBECTL="$KUBECTL" tmo="" rel="${PG_RELEASE:-rdbms}-postgresql" err rc pod ready sqlf res
    if ! $wait; then
        tmo="${TIMEOUT:-8}"
        # read-only callers never stop at a sudo password prompt
        [[ "$KUBECTL" == "sudo "* && "$KUBECTL" != "sudo -n "* ]] && KUBECTL="sudo -n ${KUBECTL#sudo }"
    fi
    rc=0
    err="$( { _ps_bounded "$tmo" /dev/null $KUBECTL get statefulset "$rel" -n "$ns" -o name >/dev/null; } 2>&1 )" || rc=$?
    if (( rc != 0 )); then
        if grep -qiE 'NotFound|not found' <<<"$err"; then
            _ps_doc "$out" none "no StatefulSet $rel in $ns"; echo none; return 0
        fi
        grep -qiE 'sudo|password' <<<"$err" && err="kubectl needs sudo"
        _ps_doc "$out" unreachable "the cluster did not answer: $(head -n1 <<<"$err")"; echo unreachable; return 0
    fi
    pod="$(_ps_bounded "$tmo" /dev/null _dbr_pg_pod "$ns")" || pod=""
    if [[ -z "$pod" ]]; then
        _ps_doc "$out" unreachable "no pod of $rel"; echo unreachable; return 0
    fi
    if $wait; then
        $KUBECTL wait --for=condition=Ready "pod/$pod" -n "$ns" --timeout=120s >/dev/null 2>&1 || {
            _ps_doc "$out" unreachable "$pod is not Ready after 120 s"; echo unreachable; return 0; }
    else
        ready="$(_ps_bounded "$tmo" /dev/null $KUBECTL get pod "$pod" -n "$ns" \
                   -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" || ready=""
        if [[ "$ready" != True ]]; then
            _ps_doc "$out" unreachable "$pod is not Ready"; echo unreachable; return 0
        fi
    fi
    POLICY_DB_POD="$pod"
    local _DBA_NS="$ns" _DBA_POD="$pod" db
    db="$(_ps_db)"
    sqlf="$(dirname "$out")/.state-$$.sql"
    printf "SELECT 1 FROM pg_catalog.pg_database WHERE datname = :'db';\n" >"$sqlf"
    rc=0
    res="$(_ps_bounded "$tmo" "$sqlf" _dba_psql postgres -q -tA -v ON_ERROR_STOP=1 -v db="$db" 2>"$sqlf.err")" || rc=$?
    if (( rc != 0 )); then
        _ps_err "cannot read the applied policy from PostgreSQL: $(grep -m1 -E 'ERROR|FATAL|error' "$sqlf.err" || head -n1 "$sqlf.err")"
        rm -f "$sqlf" "$sqlf.err"; return 1
    fi
    if [[ "$(tr -d '[:space:]' <<<"$res")" != 1 ]]; then
        rm -f "$sqlf" "$sqlf.err"
        _ps_doc "$out" none "no database $db"; echo none; return 0
    fi
    _ps_state_sql "$full" >"$sqlf"
    rc=0
    res="$(_ps_bounded "$tmo" "$sqlf" _dba_psql "$db" -q -tA -v ON_ERROR_STOP=1 2>"$sqlf.err")" || rc=$?
    if (( rc != 0 )); then
        _ps_err "cannot read the applied policy from PostgreSQL: $(grep -m1 -E 'ERROR|FATAL|error' "$sqlf.err" || head -n1 "$sqlf.err")"
        rm -f "$sqlf" "$sqlf.err"; return 1
    fi
    rm -f "$sqlf" "$sqlf.err"
    _ps_py 'import json
lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
try:
    d = json.loads(lines[-1])
    assert isinstance(d, dict) and isinstance(d.get("state"), str)
except Exception:
    sys.exit("the policy state query answered no JSON document")
d["pod"] = sys.argv[2]
json.dump(d, open(sys.argv[1], "w"))
print(d["state"])' "$out" "$pod" <<<"$res" || { _ps_err "cannot read the applied policy from PostgreSQL: no state document"; return 1; }
}

# _ps_doc_pod F — the PostgreSQL pod policy_db_state asked for document F (empty: none).
# policy_db_state runs in $(...) everywhere, where the POLICY_DB_POD it sets is lost.
_ps_doc_pod() { _ps_get "$1" 'd.get("pod") or ""'; }

# _ps_host_present — present | absent on stdout; 1 (and the reason) when state/ cannot be read
_ps_host_present() {
    _ps_py 'from compiler import source
try:
    print("present" if source._host_file_present(source.HOST_FILE) else "absent")
except source.SourceError as e:
    print(e, file=sys.stderr); sys.exit(1)'
}

_ps_host_check() {
    _ps_py 'from compiler import source
try:
    source.read_host_file()
except source.SourceError as e:
    print(e, file=sys.stderr); sys.exit(1)'
}

_ps_sha256() { sha256sum <"$1" | cut -d' ' -f1; }

# The components a break-glass of this run covers (design §14.4.6), as a JSON list
_ps_components() {
    local c
    if [[ -n "${MEDCEA_POLICY_COMPONENTS:-}" ]]; then
        c="$MEDCEA_POLICY_COMPONENTS"
    else
        case "$0" in
            *deploy-infra.sh)      c=infra; [[ "${WORKBENCH_ENABLED:-true}" == true ]] && c+=",workbench" ;;
            *deploy-workbench.sh)  c=workbench ;;
            */apps/*/deploy.sh|apps/*/deploy.sh) c="$(basename "$(dirname "$0")")" ;;
            *)                     c="$(basename "$0" .sh)" ;;
        esac
    fi
    _ps_py 'import json; print(json.dumps(sorted({c.strip() for c in sys.argv[1].split(",") if c.strip()})))' "$c"
}

# _ps_gate NS F DIR — the skeleton gate (state version-N): 0 equal or narrowing accepted
# (F re-read), 2 widening, 1 an error
_ps_gate() {
    local ns="$1" f="$2" dir="$3" rc=0 verdict st
    python3 "$_PS_CLI" skeleton-gate --state "$f" >"$dir/gate.json" || rc=$?
    case $rc in
        0) ;;
        3) return 2 ;;
        *) _ps_err "the skeleton gate refused the git skeleton or could not be computed (see above): nothing was changed"; return 1 ;;
    esac
    verdict="$(_ps_get "$dir/gate.json" 'd["verdict"]')" || return 1
    [[ "$verdict" == equal || "$verdict" == narrowing ]] || { _ps_err "unexpected gate verdict '$verdict'"; return 1; }
    [[ "$verdict" == equal ]] && return 0
    # narrowing, a help-text change, or anything that adds nothing: accepted as a deploy
    _ps_py 'import json
from compiler import source
g = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(source.accept_sql(g, g["commit"], g["compiler_digest"]))' "$dir/gate.json" "$dir/accept.sql" || return 1
    local _DBA_NS="$ns" _DBA_POD="$POLICY_DB_POD"
    if ! _dba_psql "$(_ps_db)" -q -tA -1 -v ON_ERROR_STOP=1 <"$dir/accept.sql" >/dev/null; then
        _ps_err "could not accept the narrowing skeleton (see above): nothing was changed"
        return 1
    fi
    _ps_say "accepted skeleton $(_ps_get "$dir/gate.json" 'd["git_digest"][:12]') (narrows or changes no access: $(_ps_get "$dir/gate.json" '", ".join(d["narrowed"]) or "help text or keys no role holds"'))"
    st="$(policy_db_state "$ns" "$f")" || return 1
    if [[ "$st" != version-* ]]; then
        _ps_err "after the accept the database answers $st"; return 1
    fi
    [[ "$(_ps_get "$f" 'd["accepted"]["digest"]')" == "$(_ps_get "$dir/gate.json" 'd["git_digest"]')" ]] || {
        _ps_err "the accepted skeleton did not become the git one"; return 1; }
}

# _ps_break_glass NS F DIR — design §14.4.4 step 5
_ps_break_glass() {
    local ns="$1" f="$2" dir="$3" reason="${MEDCEA_POLICY_BREAK_GLASS}" word snap rc id
    if [[ "${MEDCEA_POLICY_BREAK_GLASS_ASKED:-}" != "${MEDCEA_LOCK_HELD}" ]]; then
        if ! ( : <>/dev/tty ) 2>/dev/null; then
            _ps_err "break-glass needs a person at the terminal to type the word break-glass (also through ./deploy-apps.sh or ./install.sh --break-glass \"<reason>\", which ask once for the whole run): nothing was changed"
            return 1
        fi
        {
            echo -e "\033[0;31mBREAK-GLASS requested\033[0m: compile $MEDCEA_POLICY_FILE"
            echo "  reason: $reason"
            echo "  this changes the matrix and waivers every compile of this run reads; it is recorded"
            echo -n "Type break-glass to go on: "
        } >/dev/tty
        word=""
        read -r word </dev/tty || word=""
        if [[ "$word" != break-glass ]]; then
            _ps_err "break-glass not confirmed: nothing was changed"; return 1
        fi
    fi
    snap="$(_ps_py 'from compiler import source
try:
    print(source.snapshot_break_glass(sys.argv[1]))
except (source.SourceError, OSError) as e:
    print(e, file=sys.stderr); sys.exit(1)' "$MEDCEA_POLICY_FILE")" || { _ps_err "cannot snapshot $MEDCEA_POLICY_FILE"; return 1; }
    if ! python3 "$_PS_CLI" --file "$snap" --label "break-glass:$reason" check >"$dir/bg-check.txt" 2>&1; then
        cat "$dir/bg-check.txt" >&2
        _ps_err "the break-glass policy fails the checker: nothing was changed"; return 1
    fi
    rc=0
    _ps_py 'import json
from compiler import source
state = json.load(open(sys.argv[2]))
try:
    c = source.break_glass_check(sys.argv[1], state)
except source.SourceError as e:
    print(e, file=sys.stderr); sys.exit(1)
for p in c["problems"]:
    print(p, file=sys.stderr)
if c["problems"]:
    sys.exit(1)
payload = {"version": state["version"], "source": "file", "file_sha256": c["sha256"],
           "snapshot": source.os.path.relpath(sys.argv[1], source.REPO_ROOT),
           "skeleton_digest": c["skeleton_digest"], "entries_digest": c["entries_digest"],
           "reason": sys.argv[3], "os_user": sys.argv[4], "entry_script": sys.argv[5],
           "components": json.loads(sys.argv[6]), "lock_holder": sys.argv[7]}
open(sys.argv[8], "w").write(source.record_sql("break_glass_seen", payload))' \
        "$snap" "$f" "$reason" "$(id -un)" "$(basename "$0")" "$(_ps_components)" "$MEDCEA_LOCK_HELD" \
        "$dir/bg-record.sql" || rc=$?
    if (( rc != 0 )); then
        _ps_err "break-glass refused (above): nothing was changed"; return 1
    fi
    if [[ "$(_ps_get "$f" '(d.get("system_functions") or {}).get("system_as")')" != True ]]; then
        _ps_err "break-glass needs its record, which needs the IAM 4.2a database functions: run ./apps/database/deploy.sh first"
        return 1
    fi
    local _DBA_NS="$ns" _DBA_POD="$POLICY_DB_POD"
    id="$(_dba_psql "$(_ps_db)" -q -tA -1 -v ON_ERROR_STOP=1 <"$dir/bg-record.sql" | tr -d '[:space:]')"
    if [[ ! "$id" =~ ^[0-9]+$ ]]; then
        _ps_err "could not record break_glass_seen: nothing was compiled"; return 1
    fi
    export MEDCEA_POLICY_FILE="$snap"
    export MEDCEA_POLICY_BREAK_GLASS_EVENT="$id"
    export MEDCEA_POLICY_BREAK_GLASS_SHA256="$(_ps_sha256 "$snap")"
    export MEDCEA_POLICY_ACCEPTED_SKELETON="$(_ps_get "$f" 'd["accepted"]["digest"]')"
    echo -e "\033[0;31mBREAK-GLASS: compiling $snap ($reason), recorded as event $id\033[0m" >&2
}

# _ps_write_host F — the host file from the state document, when absent or different
_ps_write_host() {
    local out
    if ! out="$(python3 "$_PS_CLI" write-applied --state "$1" --if-different)"; then
        _ps_err "cannot write state/policy-applied.yaml (above): nothing was compiled"
        return 1
    fi
    [[ "$out" == *unchanged ]] || echo "$out"
}

# _ps_flush_seed_facts NS POD SYSTEM_AS — design §14.4.12: one transaction, then the queue
# is renamed and deleted; any failure is a WARNING and the queue stays (returns 1)
_ps_flush_seed_facts() {
    local ns="$1" pod="$2" sysas="$3" q="$_PS_ROOT/state/seed-facts.jsonl" sql n
    [[ -e "$q" ]] || return 0
    [[ "$sysas" == true || "$sysas" == True ]] || return 0
    sql="$(mktemp)" || return 1
    if ! n="$(_ps_py 'from compiler import source
try:
    facts = source.seed_lines(sys.argv[1])
except (source.SourceError, OSError, UnicodeDecodeError) as e:
    print(e, file=sys.stderr); sys.exit(1)
open(sys.argv[2], "w").write(source.seed_flush_sql(facts))
print(len(facts))' "$q" "$sql" 2>&1)"; then
        rm -f "$sql"
        _ps_warn "the queued account facts are not recorded ($n); state/seed-facts.jsonl stays"
        return 1
    fi
    if ! _DBA_NS="$ns" _DBA_POD="$pod" _dba_psql "$(_ps_db)" -q -tA -1 -v ON_ERROR_STOP=1 <"$sql" >/dev/null; then
        rm -f "$sql"
        _ps_warn "the queued account facts are not recorded (above); state/seed-facts.jsonl stays for the next deploy"
        return 1
    fi
    rm -f "$sql"
    local done_q
    done_q="$q.flushed-$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$q" "$done_q" && rm -f "$done_q"
    _ps_say "$n queued account fact(s) recorded (account_seeded)"
}

# _ps_marker_ok — the marker path's own checks (design §14.4.4 step 1)
_ps_marker_ok() {
    local pres
    if [[ -n "${MEDCEA_POLICY_FILE:-}" ]]; then
        if [[ -z "${MEDCEA_POLICY_BREAK_GLASS_EVENT:-}" || -z "${MEDCEA_POLICY_BREAK_GLASS_SHA256:-}" ]]; then
            _ps_err "MEDCEA_POLICY_FILE is set but this run recorded no break-glass for it: unset MEDCEA_POLICY_FILE, or run the entry script with MEDCEA_POLICY_BREAK_GLASS=<reason>"
            return 1
        fi
        if [[ ! -r "$MEDCEA_POLICY_FILE" || "$(_ps_sha256 "$MEDCEA_POLICY_FILE")" != "$MEDCEA_POLICY_BREAK_GLASS_SHA256" ]]; then
            _ps_err "$MEDCEA_POLICY_FILE is not the break-glass file this run recorded (sha256 differs)"
            return 1
        fi
    fi
    pres="$(_ps_host_present)" || { _ps_err "cannot read state/: run as the account that deploys the platform"; return 1; }
    if [[ "$pres" == present ]] && ! _ps_host_check; then
        _ps_err "state/policy-applied.yaml fails its own checks (above)"
        return 1
    fi
    return 0
}

policy_source_init() {
    local ns="${1:-}" mode="${2:-}"
    if [[ -z "$ns" || $# -gt 2 ]]; then
        echo "policy_source_init: usage: policy_source_init NS [--read-only|--precheck]" >&2
        return 2
    fi
    case "$mode" in
        "") ;;
        --read-only) _ps_read_only "$ns"; return 0 ;;
        --precheck) _ps_precheck "$ns"; return $? ;;
        *) echo "policy_source_init: unknown option '$mode' (--read-only, --precheck)" >&2; return 2 ;;
    esac
    # 0. the lock, verified (critique sec-2)
    if ! medcea_lock_verify; then
        _ps_err "policy_source_init runs under the deploy lock held by this run (MEDCEA_LOCK_HELD=${MEDCEA_LOCK_HELD:-unset} is not a live holder of .medcea.lock above this process)"
        return 1
    fi
    # 1. the marker path: a parent of this run has verified the source
    if [[ -n "${MEDCEA_POLICY_SOURCE_DONE:-}" && "$MEDCEA_POLICY_SOURCE_DONE" == "$MEDCEA_LOCK_HELD" ]]; then
        _ps_marker_ok
        return $?
    fi
    # 2. break-glass needs its reason
    if [[ -n "${MEDCEA_POLICY_FILE:-}" && -z "${MEDCEA_POLICY_BREAK_GLASS//[[:space:]]/}" ]]; then
        _ps_err "MEDCEA_POLICY_FILE is a break-glass override: set MEDCEA_POLICY_BREAK_GLASS=<reason>, or unset MEDCEA_POLICY_FILE"
        return 1
    fi
    local dir rc=0
    dir="$(mktemp -d)" || return 1
    _ps_init_write "$ns" "$dir" || rc=$?
    rm -rf "$dir"
    return $rc
}

_ps_init_write() {
    local ns="$1" dir="$2" f="$2/state.json" st pres bg=false
    [[ -n "${MEDCEA_POLICY_FILE:-}" ]] && bg=true
    st="$(policy_db_state "$ns" "$f")" || { _ps_err "nothing was compiled"; return 1; }
    POLICY_DB_POD="$(_ps_doc_pod "$f")"   # set in the $(...) above, where it was lost
    if ! pres="$(_ps_host_present)"; then
        _ps_err "cannot read state/ (above): run as the account that deploys the platform"
        return 1
    fi
    case "$st" in
        none|empty)
            if [[ "$pres" == present ]]; then
                if [[ "$st" == none ]]; then
                    _ps_err "state/policy-applied.yaml names a version but the database has no policy versions (no PostgreSQL, no database, or no migration 008c). After a purge or a reset the scripts move it away themselves; otherwise restore the database, or read docs/manual (admin: Policy source) before moving it into state/retired-…"
                else
                    _ps_err "state/policy-applied.yaml names a version but the database has no applied version (after a restore: docs/manual, admin: Policy source, and backups.sh restore-help step 2a)"
                fi
                return 1
            fi
            if [[ -e "$_PS_ROOT/state/.policy-versioned" ]]; then
                # a version was applied on this host before: retire the mark only when the
                # database itself answered that it has none (a restore of an older dump, a
                # database dropped by hand), never when it could not be asked
                if [[ "$st" == empty || -n "$POLICY_DB_POD" || "$(_ps_get "$f" 'd.get("detail") or ""')" == "no database "* ]]; then
                    _ps_retire no-version .policy-versioned || return 1
                else
                    _ps_err "a policy version was applied on this host (state/.policy-versioned), but the database cannot be asked ($(_ps_get "$f" 'd.get("detail")')): nothing is compiled from defaults.yaml. After a purge or a reset the scripts move the mark away themselves; otherwise read docs/manual (admin: Policy source)"
                    return 1
                fi
            fi
            if $bg; then
                _ps_err "break-glass needs an applied policy version: there is none"
                return 1
            fi
            if [[ "$st" == empty ]]; then
                _ps_flush_seed_facts "$ns" "$POLICY_DB_POD" "$(_ps_get "$f" '(d.get("system_functions") or {}).get("system_as")')" || true
            fi
            ;;
        partial)
            _ps_err "policy versions exist but none is applied: ./apps/iam/apply.sh --status"
            return 1 ;;
        unreachable)
            _ps_err "PostgreSQL is not Ready: the applied policy cannot be read, so nothing is compiled (wait for ${PG_RELEASE:-rdbms}-postgresql-0, or check: microk8s kubectl -n $ns get pods). deploy-infra.sh repairs PostgreSQL before it reads the policy. ($(_ps_get "$f" 'd.get("detail")'))"
            return 1 ;;
        version-*)
            local rc=0
            _ps_gate "$ns" "$f" "$dir" || rc=$?
            (( rc == 0 )) || return $rc
            if $bg; then
                _ps_break_glass "$ns" "$f" "$dir" || return 1
            fi
            _ps_write_host "$f" || return 1
            _ps_flush_seed_facts "$ns" "$POLICY_DB_POD" "$(_ps_get "$f" '(d.get("system_functions") or {}).get("system_as")')" || true
            ;;
        *)
            _ps_err "unknown policy state '$st'"
            return 1 ;;
    esac
    export MEDCEA_POLICY_SOURCE_DONE="$MEDCEA_LOCK_HELD" MEDCEA_POLICY_STATE="$st"
    export MEDCEA_POLICY_BG_OPEN="$(_ps_get "$f" 'd.get("break_glass_open") or []')"
    return 0
}

# --precheck: read-only, no marker, no accept, no write (deploy-infra after the API wait)
_ps_precheck() {
    local ns="$1" dir f st rc=0
    dir="$(mktemp -d)" || return 1
    f="$dir/state.json"
    if ! st="$(policy_db_state "$ns" "$f" --no-wait)"; then
        _ps_warn "precheck: the policy state could not be read; the full read after PostgreSQL decides"
        rm -rf "$dir"; return 0
    fi
    if [[ -n "${MEDCEA_POLICY_FILE:-}" && -z "${MEDCEA_POLICY_BREAK_GLASS//[[:space:]]/}" ]]; then
        _ps_err "MEDCEA_POLICY_FILE is a break-glass override: set MEDCEA_POLICY_BREAK_GLASS=<reason>, or unset MEDCEA_POLICY_FILE"
        rm -rf "$dir"; return 1
    fi
    if [[ "$st" == version-* ]]; then
        python3 "$_PS_CLI" skeleton-gate --state "$f" --check >/dev/null || rc=$?
        case $rc in
            0) ;;
            3) rm -rf "$dir"; return 2 ;;
            *) _ps_err "the skeleton gate could not be computed (above)"; rm -rf "$dir"; return 1 ;;
        esac
        if [[ -n "${MEDCEA_POLICY_FILE:-}" ]]; then
            if ! _ps_py 'import json
from compiler import source
try:
    data = source._read_yaml(sys.argv[1], "break-glass policy file")[1]
except source.SourceError as e:
    sys.exit(str(e))
if source.skeleton_digest(data) != json.load(open(sys.argv[2]))["accepted"]["digest"]:
    sys.exit("break-glass changes only the matrix and the waivers; a skeleton change goes through git and the skeleton gate")' \
                "$MEDCEA_POLICY_FILE" "$f"; then
                rm -rf "$dir"; return 1
            fi
        fi
    fi
    _ps_say "precheck: $st"
    rm -rf "$dir"
    return 0
}

# --read-only: health-check and the live tests (see the header)
_ps_read_only() {
    local ns="$1" dir f st rc pres probs worst=ok details=() tmo lvl
    unset MEDCEA_POLICY_FILE MEDCEA_POLICY_BREAK_GLASS MEDCEA_POLICY_SOURCE_DONE \
          MEDCEA_POLICY_BREAK_GLASS_EVENT MEDCEA_POLICY_BREAK_GLASS_SHA256 MEDCEA_POLICY_ACCEPTED_SKELETON
    POLICY_SOURCE_VERDICT=skip POLICY_SOURCE_DETAIL="" POLICY_SOURCE_STATE="" POLICY_SOURCE_STATE_FILE=""
    tmo="$(( ${TIMEOUT:-8} > 30 ? ${TIMEOUT:-8} : 30 ))"
    if ! _ps_kubectl_usable; then
        POLICY_SOURCE_DETAIL="no usable kubectl"; return 0
    fi
    dir="$(mktemp -d)" || { POLICY_SOURCE_VERDICT=fail POLICY_SOURCE_DETAIL="mktemp failed"; return 0; }
    f="$dir/state.json"
    POLICY_SOURCE_STATE_FILE="$f"
    if ! st="$(policy_db_state "$ns" "$f" --full --no-wait 2>"$dir/err")"; then
        POLICY_SOURCE_VERDICT=fail POLICY_SOURCE_DETAIL="$(sed 's/\x1b\[[0-9;]*m//g' "$dir/err" | head -n1)"
        return 0
    fi
    POLICY_SOURCE_STATE="$st"
    _worse() {   # LEVEL DETAIL
        details+=("$2")
        case "$1:$worst" in
            fail:*) worst=fail ;;
            warn:ok) worst=warn ;;
        esac
    }
    case "$st" in
        none)
            POLICY_SOURCE_VERDICT=skip POLICY_SOURCE_DETAIL="$(_ps_get "$f" 'd.get("detail")')"
            if pres="$(_ps_host_present 2>/dev/null)" && [[ "$pres" == present ]]; then
                POLICY_SOURCE_VERDICT=fail
                POLICY_SOURCE_DETAIL="state/policy-applied.yaml exists but the database has no policy versions"
            fi
            return 0 ;;
        unreachable)
            POLICY_SOURCE_VERDICT=fail POLICY_SOURCE_DETAIL="PostgreSQL is not Ready: $(_ps_get "$f" 'd.get("detail")')"
            return 0 ;;
        partial)
            POLICY_SOURCE_VERDICT=fail POLICY_SOURCE_DETAIL="policy versions exist but none is applied: ./apps/iam/apply.sh --status"
            return 0 ;;
    esac
    if ! probs="$(timeout "$tmo" python3 -c 'import sys, json
sys.path.insert(0, sys.argv[1])
from compiler import source
for level, detail in source.host_file_problems(json.load(open(sys.argv[2]))):
    print(f"{level.lower()}\t{detail}")' "$_PS_ROOT/apps/iam" "$f" 2>&1)"; then
        _worse fail "the host file could not be checked: $(tail -n1 <<<"$probs")"
        probs=""
    fi
    local line
    while IFS=$'\t' read -r lvl line; do
        [[ -n "$lvl" ]] && _worse "$lvl" "$line"
    done <<<"$probs"
    if [[ "$st" == empty ]]; then
        _worse fail "no applied version: a widening git change is not gated until version 1 exists; ./apps/iam/deploy.sh bootstraps it"
    elif [[ "$st" == version-* ]]; then
        rc=0
        timeout "$tmo" python3 "$_PS_CLI" skeleton-gate --state "$f" --check >"$dir/gate.json" 2>"$dir/gate.err" || rc=$?
        case $rc in
            0) [[ "$(_ps_get "$dir/gate.json" 'd["verdict"]')" == narrowing ]] \
                   && _worse warn "the git skeleton narrows: accepted at the next deploy" ;;
            3) _worse fail "the git skeleton widens over the accepted one: a deploy would refuse it (cli.py skeleton-gate)" ;;
            *) _worse fail "the skeleton gate refused the git skeleton or could not be computed: $(sed 's/\x1b\[[0-9;]*m//g' "$dir/gate.err" | grep -m1 . )" ;;
        esac
    fi
    unset -f _worse
    POLICY_SOURCE_VERDICT="$worst"
    if ((${#details[@]})); then
        POLICY_SOURCE_DETAIL="$(printf '%s; ' "${details[@]}")"; POLICY_SOURCE_DETAIL="${POLICY_SOURCE_DETAIL%; }"
    else
        POLICY_SOURCE_DETAIL="$st, host file matches, skeleton equal"
    fi
    return 0
}

# policy_source_finish NS COMPONENT — see the header (design §14.4.4, critique sec-8)
policy_source_finish() {
    local ns="${1:-}" comp="${2:-}" ids id pod out payload
    [[ -n "$ns" && -n "$comp" ]] || { echo "policy_source_finish: usage: policy_source_finish NS COMPONENT" >&2; return 0; }
    [[ -z "${MEDCEA_POLICY_FILE:-}" ]] || return 0
    [[ -n "${MEDCEA_POLICY_BG_OPEN:-}" && "$MEDCEA_POLICY_BG_OPEN" != "[]" ]] || return 0
    ids="$(_ps_py 'import json
try:
    for e in json.loads(sys.argv[1]):
        if sys.argv[2] in (e.get("open") or []):
            print(int(e["event_id"]))
except (ValueError, TypeError, KeyError, AttributeError):
    pass' "$MEDCEA_POLICY_BG_OPEN" "$comp" 2>/dev/null)" || ids=""
    [[ -n "$ids" ]] || return 0
    pod="$(_dbr_pg_pod "$ns" 2>/dev/null)" || pod=""
    for id in $ids; do
        payload="$(_ps_py 'import json; print(json.dumps({"since_event": int(sys.argv[1]), "component": sys.argv[2],
    "os_user": sys.argv[3], "entry_script": sys.argv[4]}))' "$id" "$comp" "$(id -un)" "$(basename "$0")")"
        out=""
        if [[ -z "$pod" ]] || ! out="$(dba_record_event "$ns" "$pod" "$(_ps_db)" break_glass_ended "$payload" \
                                       "$comp deployed again without the break-glass file" 2>&1)" || [[ "$out" == *skip* ]]; then
            _ps_warn "the break-glass end of $comp is not recorded${out:+ ($out)}; health keeps reporting it open until the next deploy of $comp"
        else
            _ps_say "break-glass event $id ended for $comp (break_glass_ended)"
        fi
    done
    return 0
}

# policy_state_retire WHY — see the header (critique ops-1, ops-2). state/.policy-versioned
# (the "a version was applied here" mark, source.VERSIONED_MARK) goes too, except for
# `restore`: the restored database may hold a version, so the edge tools keep refusing
# defaults.yaml until a deploy has asked it (the write-mode init retires the mark itself
# when the database answers that it has no applied version).
policy_state_retire() {
    local why="${1:-}" p cand=(policy-applied.yaml seed-facts.jsonl break-glass)
    if [[ ! "$why" =~ ^[a-z][a-z0-9-]{0,30}$ ]]; then
        echo "policy_state_retire: usage: policy_state_retire WHY (purge-data, reset, uninstall, restore, rollback)" >&2
        return 2
    fi
    if ! medcea_lock_verify; then
        _ps_err "policy_state_retire runs under the deploy lock held by this run"
        return 1
    fi
    [[ "$why" == restore ]] || cand+=(.policy-versioned)
    _ps_retire "$why" "${cand[@]}"
}

# _ps_retire WHY NAME... — move the existing state/NAMEs into state/retired-<UTC ts>-<WHY>/
_ps_retire() {
    local why="$1" d="$_PS_ROOT/state" t p moved=()
    shift
    for p in "$@"; do
        [[ -e "$d/$p" || -L "$d/$p" ]] && moved+=("$p")
    done
    if ((${#moved[@]} == 0)); then
        _ps_say "no host policy state to retire (state/policy-applied.yaml, seed-facts.jsonl, break-glass/)"
        return 0
    fi
    t="$d/retired-$(date -u +%Y%m%dT%H%M%SZ)-$why"
    [[ -d "$t" ]] || mkdir -m 700 "$t" || return 1
    for p in "${moved[@]}"; do
        mv "$d/$p" "$t/" || { _ps_err "could not move state/$p into ${t#"$_PS_ROOT"/}"; return 1; }
    done
    _ps_say "moved $(printf 'state/%s ' "${moved[@]}")to ${t#"$_PS_ROOT"/}: the next deploy writes them again from the database"
}
