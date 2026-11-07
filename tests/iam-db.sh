#!/usr/bin/env bash
# tests/iam-db.sh — the database side of IAM Phase 2a (tasks 2.1-2.3) on a running
# PostgreSQL: catalog, role matrix, PostgREST role selection, the actor, write
# probes and drift detection.
#
#   tests/iam-db.sh [--namespace NS] [--pod POD] [--db DB] [--mode auto|false|true|legacy]
#                   [--write-probes] [--section NAME]...
#
#   catalog      ownership (schema iam too, IAM 2.7), the always-on triggers
#                (append-only ones ENABLE ALWAYS; iam's freeze and history triggers
#                too), security_invoker views, SECURITY DEFINER and search_path of
#                the functions, no PUBLIC EXECUTE, iam_* triggers and RLS iff mode
#                true, the EXECUTE holders of the iam functions equal the golden
#   matrix       has_table_privilege / has_function_privilege for every compiled
#                privilege and the hand-written negatives; authenticator's
#                memberships (true); then `grants --mode verify`
#   prerequest   pre_request() for a table of claims (true), a no-op (false)
#   actor        spoofed actor table, forged claims in a service / rr_admin_login
#                session, token actors, set_actor's argument checks
#   writes       W1 false-mode regression (today's callers), W2 always-on guards,
#                W3 flag-only probes, W4 true-mode workflow, W5 register v2,
#                W6 the scheduler's functions (2.4: retire, re-save, cycles, the
#                schedule's algorithm, the internal actor, e97aab6's scheduler SQL),
#                W7 unit assignments (apps/iam/units.sql, IAM 2.8: assign waits for
#                qa, --bootstrap acts at once, remove withdraws a waiting one); the own_unit RLS
#                probes run in W4, and so do the Approve action's (noted approvals,
#                approval_queue() against the approve functions, return, my_approvals())
#                and the Release's (release_run with a note, the queue's run rows
#                against release_run, who sees them, a run from before 008b);
#                W8 commissioning (propose, approve, return, withdraw, off at once with
#                qa's review, runs in R/S, unit_commissioning() per role, the chain events)
#   access       (not in the default set; write probes) IAM 2.7's account decisions,
#                D1-D19: record, withdraw, confirm, refuse, review as access_svc with
#                set_actor; the who-may rules, units.sql refusals, the attestation,
#                append-only histories, role_widening's stub, the review, template
#                reset, MQTT revocation, rr_qa without EXECUTE
#   policy       (not in the default set) IAM 4.1, migration 008c: P1 the catalog
#                (read-only: 14 tables, the freeze trigger ALWAYS, ownership, the
#                wrappers, the constraints, the nonce); with --write-probes P2-P18: the
#                entries digest against compiler/source.py, the freeze trigger and the
#                state machine, the author path as iam_svc and its refusals, one_open,
#                rr_admin_login, apply_started, the audit and a tampered chain, READ
#                COMMITTED, the access guard; with --mode true the token path: approve
#                and return (evidence, events), every approve refusal (P7a-i), pre_request's
#                only_rpc block, the blank person_id (G9), confirm and dispute.
#                IAM 4.2a, P19-P26: _withdraw_open, _mark_reverted (its applies need
#                --mode true), _propose_skeleton, _record's actors and account_seeded,
#                the filter (iam_svc writes only mqtt_credential_issued), dba_record_event
#                through _record, a deploy's _accept_skeleton, and (--mode false)
#                pre_request's only_rpc block under IAM_DB_ROLES=false.
#                IAM 4.4, P27-P37: approve refused while a policy break-glass is open,
#                a skeleton version's approval (digests, the attestation, the --by
#                author), the approval's inputs, return, withdraw by any admin and by
#                _withdraw_open, submit's and save_entry's refusals and the whole-cell
#                rule, new_draft's bases and merge, why_not as iam_svc, a stale
#                skeleton proposal, a proposal widening the approver's own role, and
#                iam_svc taking the version lock before save_entry.
#                IAM 4.5, P42-P44 (--mode true): the rollback bundle's PRE (K's rows read
#                in SQL, the open version withdrawn, an unconfirmed or withdrawn K
#                refused), new_draft's guard on the apply events only (a seed fact or a
#                skeleton accept no longer masks apply_started or partial_apply), and a
#                rollback confirmed by another qa person, never the recorded one
#   drift        an extra grant, a revoked one, an extra policy, a dropped trigger:
#                each must make `grants --mode verify` fail
#
# Every `compile grants` call gets dba_iam_flag's answer (apps/database/lib-db-apply.sh):
# --without-iam while schema iam is absent; a half-present access component aborts.
#
# Read-only by default: every session runs with default_transaction_read_only=on and
# the write sections are skipped. --write-probes runs them, each inside
# BEGIN … ROLLBACK, and is refused unless the namespace is medcea-iamtest (the
# throwaway instance of tests/iam-db-fixture.sh) — there is no override.
# --mode auto reads medcea.platform_setting.iam_db_roles; legacy is the schema of the
# commit before Phase 2a (after the down file's full section): W1 only, without the
# attribution checks. Every negative probe asserts the SQLSTATE and a fragment of the
# message, and runs after its positive control on the same fixture.
# psql runs inside the pod as postgres, its password read there. Exit 1 on any FAIL.

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,77p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
source infra/lib-log.sh; medcea_log iam-db   # logs/iam-db-<ts>.log, unless a parent logs
source infra/lib-mk8s.sh
CLI="$REPO_ROOT/apps/iam/compiler/cli.py"

NS="medcea-iamtest"; POD="pg"; DB="medcea_db"; MODE="auto"; WRITES=false; SECTIONS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace) NS="$2"; shift 2 ;;
        --pod) POD="$2"; shift 2 ;;
        --db) DB="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --write-probes) WRITES=true; shift ;;
        --section) SECTIONS+=("$2"); shift 2 ;;
        *) echo "unknown option $1 (--help)" >&2; exit 2 ;;
    esac
done
if [[ "$WRITES" == true && "$NS" != "medcea-iamtest" ]]; then
    echo "REFUSED: --write-probes runs only against the throwaway instance (namespace medcea-iamtest), never $NS." >&2
    exit 2
fi
# Which policy the expected grants come from (IAM Phase 4): the throwaway fixture was
# built from the factory policy (db_apply compiles --defaults there); any other namespace
# from the source rule, i.e. what its deploys compiled (infra/lib-policy-source.sh).
SRC=()
if [[ "$NS" == "medcea-iamtest" ]]; then
    SRC=(--defaults)
else
    source infra/lib-policy-source.sh; policy_source_init "$NS" --read-only
fi
[[ ${#SECTIONS[@]} -gt 0 ]] || SECTIONS=(catalog matrix prerequest actor writes drift)
want() { local s; for s in "${SECTIONS[@]}"; do [[ "$s" == "$1" ]] && return 0; done; return 1; }

FAILS=0; PASSES=0
pass() { printf "  ${GREEN}PASS${NC}  %-10s %s\n" "$1" "$2"; PASSES=$((PASSES + 1)); }
fail() { printf "  ${RED}FAIL${NC}  %-10s %s\n" "$1" "$2"; FAILS=$((FAILS + 1)); }
note() { printf "  ${YELLOW}NOTE${NC}  %-10s %s\n" "$1" "$2"; }

# db [RW] — psql in the pod, SQL on stdin; read-only unless the first argument is rw
db() {
    local opts="-c client_min_messages=warning -c default_transaction_read_only=on"
    [[ "${1:-}" == rw ]] && opts="-c client_min_messages=warning"
    $KUBECTL exec -i -n "$NS" "$POD" -- env PGOPTIONS="$opts" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -tA -F "|" -U postgres -d "$0" -v ON_ERROR_STOP=0' "$DB" 2>&1
}
q1() { db <<<"$1" | head -1; }

if [[ "$MODE" == auto ]]; then
    MODE="$(q1 "SELECT coalesce((SELECT value FROM medcea.platform_setting WHERE key = 'iam_db_roles'), 'legacy')")"
    [[ "$MODE" == true || "$MODE" == false || "$MODE" == legacy ]] || { echo "cannot read the mode: $MODE" >&2; exit 2; }
fi
echo -e "${BOLD}IAM Phase 2a database checks${NC} (namespace $NS, pod $POD, database $DB, mode $MODE, write probes $WRITES)"

# Schema iam compiled like the rest, or --without-iam: what the database deploy would
# decide (dba_iam_flag, IAM 2.7). An unreadable or half-present answer aborts.
IAM_FLAG=()
if [[ "$MODE" != legacy ]]; then
    source apps/database/lib-db-apply.sh
    _flag="$(dba_iam_flag "$NS" "$POD" "$DB")" || { echo "dba_iam_flag failed (above): cannot tell how schema iam is compiled" >&2; exit 2; }
    [[ -n "$_flag" ]] && IAM_FLAG=("$_flag") && echo "  schema iam absent: grants compiled $_flag"
fi

UUID_OP="11111111-1111-4111-8111-111111111111"; UUID_PM="22222222-2222-4222-8222-222222222222"
UUID_QA="33333333-3333-4333-8333-333333333333"; UUID_QP="44444444-4444-4444-8444-444444444444"
UUID_EN="55555555-5555-4555-8555-555555555555"; UUID_EN2="66666666-6666-4666-8666-666666666666"
UUID_AD="77777777-7777-4777-8777-777777777777"; UUID_OP2="88888888-8888-4888-8888-888888888888"
UUID_QA2="99999999-9999-4999-8999-999999999999"
# claims ROLE[,ROLE] SUB PERSON [azp] [typ] [aud] — a token's claims as PostgREST would set them
claims() {
    local groups="" r
    for r in ${1//,/ }; do groups+="${groups:+,}\"$r\""; done
    local aud="${6-\"medcea-api\"}"
    printf '{"typ":"%s","azp":"%s",%s"sub":"%s","person_id":"%s","preferred_username":"test-%s","groups":[%s]}' \
        "${5:-Bearer}" "${4:-config}" "${aud:+\"aud\":$aud,}" "$2" "$3" "$3" "$groups"
}
# as_token CLAIMS — SQL that turns the session into PostgREST's for that token
as_token() {
    cat <<SQL
RESET ROLE;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$1', true) \\g /dev/null
SELECT medcea_auth.pre_request() \\g /dev/null
SQL
}
as_anon() { printf 'RESET ROLE;\nRESET SESSION AUTHORIZATION;\nSET SESSION AUTHORIZATION authenticator;\nSET ROLE anon;\n'; }
as_postgres() { printf 'RESET ROLE;\nRESET SESSION AUTHORIZATION;\n'; }

# probe SECTION NAME EXPECT — SQL on stdin: setup, then the probe statement, then
# optionally a line '--CHECKS' and checks (run as postgres, only after a success) that
# print 'CHECK|label|t' for each truth. EXPECT is ok, or SQLSTATE:fragment of the
# message. The first ERROR in the transaction decides (verbose errors carry the
# SQLSTATE); everything is rolled back.
probe() {
    local section="$1" name="$2" expect="$3" input main checks out first state msg c v
    input="$(cat)"
    main="${input%%--CHECKS*}"
    checks=""; [[ "$input" == *--CHECKS* ]] && checks="${input#*--CHECKS}"
    out="$({
        echo '\set VERBOSITY verbose'
        echo "BEGIN;"
        echo "$main"
        echo '\warn PROBE_DONE'   # on stderr, ordered with the errors
        if [[ -n "$checks" ]]; then as_postgres; echo "$checks"; fi
        echo "ROLLBACK;"
    } | db rw)"
    first="$(sed -n '/PROBE_DONE/q;p' <<<"$out" | grep -m1 -E 'ERROR:  [0-9A-Z]{5}:' || true)"
    state="$(sed -E 's/.*ERROR:  ([0-9A-Z]{5}):.*/\1/' <<<"$first")"
    msg="$(sed -E 's/.*ERROR:  [0-9A-Z]{5}: //' <<<"$first")"
    if [[ "$expect" == ok ]]; then
        if [[ -n "$first" ]]; then
            fail "$section" "$name: expected success, got $state $msg"
            return
        fi
    else
        local want_state="${expect%%:*}" frag="${expect#*:}"
        if [[ "$state" != "$want_state" || "$msg" != *"$frag"* ]]; then
            fail "$section" "$name: expected $want_state '$frag', got ${first:-success}"
            return
        fi
        pass "$section" "$name ($expect)"
        return
    fi
    while IFS='|' read -r _ c v; do
        [[ "$v" == t ]] || { fail "$section" "$name: check '$c' is ${v:-missing}"; return; }
    done < <(grep '^CHECK|' <<<"$out")
    if [[ -n "$checks" ]] && ! grep -q '^CHECK|' <<<"$out"; then
        fail "$section" "$name: the checks did not run: $(grep -m1 'ERROR' <<<"$out")"
        return
    fi
    pass "$section" "$name"
}

# ── catalog ──────────────────────────────────────────────────────────────────────
if want catalog && [[ "$MODE" != legacy ]]; then
    echo ""
    out="$(db <<'SQL'
SELECT 'owner', count(*) FROM (
    SELECT c.relowner AS o FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam') AND c.relkind IN ('r', 'v', 'm', 'p', 'S', 'f')
    UNION ALL SELECT p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')
    UNION ALL SELECT nspowner FROM pg_namespace WHERE nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam')) x
 WHERE o <> 'medcea_owner'::regrole;
SELECT 'iamschema', count(*) FROM pg_namespace WHERE nspname = 'iam';
-- IAM 2.7: the freeze triggers (account_decision, access_review) and the append-only
-- triggers of the three iam histories: every BEFORE trigger on those tables ALWAYS
SELECT 'iamalways', count(*) FILTER (WHERE t.tgenabled <> 'A'), count(*),
       coalesce(string_agg(c.relname || '.' || t.tgname, ',') FILTER (WHERE t.tgenabled <> 'A'), '')
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = to_regnamespace('iam') AND NOT t.tgisinternal AND (t.tgtype & 2) <> 0
   AND c.relname IN ('account_decision', 'access_review', 'user_status_history', 'access_request_history', 'config_history');
SELECT 'iamhist', count(DISTINCT c.relname) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = to_regnamespace('iam') AND NOT t.tgisinternal AND (t.tgtype & 2) <> 0
   AND c.relname IN ('user_status_history', 'access_request_history', 'config_history');
-- who may execute each iam function, besides its owner (compared with the golden below)
SELECT 'iamexec', r.rolname || ' ' || replace(p.oid::regprocedure::text, ' ', '')
  FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
  JOIN pg_roles r ON r.oid = a.grantee
 WHERE p.pronamespace = to_regnamespace('iam') AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner
 ORDER BY 2;
SELECT 'members', count(*) FROM pg_auth_members WHERE roleid = 'medcea_owner'::regrole;
SELECT 'changelog', count(*) FROM pg_class WHERE oid = to_regclass('medcea.databasechangeloglock');
SELECT 'invoker', count(*) FROM pg_class c WHERE c.relnamespace = 'medcea'::regnamespace AND c.relkind = 'v'
   AND NOT coalesce('security_invoker=true' = ANY (c.reloptions), false);
SELECT 'always', string_agg(c.relname || '.' || t.tgname, ',') FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE (t.tgname LIKE '%\_append\_only' OR t.tgname LIKE '%\_no\_truncate' OR t.tgname = 'schedule_retired_guard_trg')
   AND t.tgenabled <> 'A'
   AND c.relnamespace IN ('medcea'::regnamespace, 'iam_policy'::regnamespace);
SELECT 'appendonly', count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE t.tgname LIKE '%\_append\_only' AND c.relnamespace IN ('medcea'::regnamespace, 'iam_policy'::regnamespace);
SELECT 'stamp', count(*) FROM pg_trigger WHERE tgname = 'stamp_actor_trg';
SELECT 'rowchange', count(*) FROM pg_trigger WHERE tgname = 'row_change_trg';
SELECT 'guard', count(*) FROM pg_trigger WHERE tgname = 'status_guard_trg';
SELECT 'single', string_agg(n, ',') FROM unnest(ARRAY['measurement_zone_trg', 'device_serial_change_trg', 'mqtt_service_acl_root_trg',
       'algorithm_state_event_trg', 'algorithm_state_before_trg', 'user_zone_audit_trg', 'user_unit_audit_trg',
       'schedule_retired_guard_trg', 'commissioning_history_trg']) n
 WHERE NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = n);
SELECT 'definer', string_agg(p.oid::regprocedure::text, ',') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam') AND p.prosecdef
   AND NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%pg_temp');
SELECT 'invokerfn', string_agg(p.proname, ',') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'medcea' AND p.prosecdef
   AND p.proname IN ('guard_control_columns', 'schedule_retired_guard', 'reject_non_draft_update', 'immutable_row', 'algorithm_state_guard', 'algorithm_state_before');
SELECT 'prereq', p.prosecdef || '/' || coalesce(array_to_string(p.proconfig, ','), '') FROM pg_proc p WHERE p.oid = 'medcea_auth.pre_request()'::regprocedure;
SELECT 'public', count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
 WHERE n.nspname IN ('medcea', 'medcea_auth', 'iam_policy') AND a.grantee = 0;
SELECT 'iamtrg', count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = 'medcea'::regnamespace AND t.tgname LIKE 'iam\_%';
SELECT 'rls', count(*) FROM pg_class WHERE relnamespace = 'medcea'::regnamespace AND relrowsecurity;
SELECT 'unitalways', tgenabled FROM pg_trigger WHERE tgname = 'user_unit_audit_trg';
SELECT 'commalways', tgenabled FROM pg_trigger WHERE tgname = 'commissioning_history_trg';
SELECT 'chain', ok FROM iam_policy.verify_chain();
SELECT 'chaindef', p.prosecdef FROM pg_proc p WHERE p.oid = 'iam_policy.verify_chain()'::regprocedure;
SQL
)"
    get() { grep -m1 "^$1|" <<<"$out" | cut -d'|' -f2; }
    [[ "$(get owner)" == 0 ]] && pass catalog "every object in medcea, medcea_auth, iam_policy$([[ "$(get iamschema)" == 1 ]] && echo ', iam') is owned by medcea_owner" \
        || fail catalog "$(get owner) object(s) not owned by medcea_owner"
    if [[ "$(get iamschema)" == 1 ]]; then
        IFS='|' read -r _ n_off n_all off_list <<<"$(grep -m1 '^iamalways|' <<<"$out")"
        [[ "$n_off" == 0 && "${n_all:-0}" -ge 7 && "$(get iamhist)" == 3 ]] \
            && pass catalog "iam: $n_all freeze and append-only triggers (the three histories included), all ENABLE ALWAYS" \
            || fail catalog "iam triggers: ${n_all:-0} BEFORE trigger(s), not ALWAYS: ${off_list:-none}; histories with one: $(get iamhist) of 3"
        want_exec="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print("\n".join(sorted("%s %s" % (g, o.replace(" ", "")) for g, k, o, p in d["privileges"]
                        if k == "function" and o.startswith("iam.") and p == "EXECUTE")))' tests/iam-grants.golden.json | sort)"
        got_exec="$(grep '^iamexec|' <<<"$out" | cut -d'|' -f2 | sort)"
        if [[ "$got_exec" == "$want_exec" ]]; then
            pass catalog "the EXECUTE holders of the iam functions equal the golden ($(grep -c . <<<"$want_exec"))"
        else
            fail catalog "iam EXECUTE holders differ from tests/iam-grants.golden.json:"
            diff <(echo "$want_exec") <(echo "$got_exec") | grep '^[<>]' | sed 's/^</        golden only:/; s/^>/        database only:/' | head -20
        fi
    else
        note catalog "schema iam absent (no access component): its checks skipped"
    fi
    [[ "$(get members)" == 0 ]] && pass catalog "medcea_owner has no members" || fail catalog "medcea_owner has $(get members) member(s)"
    [[ "$(get changelog)" == 0 ]] && pass catalog "medcea.databasechangeloglock is gone" || fail catalog "databasechangeloglock still exists"
    [[ "$(get invoker)" == 0 ]] && pass catalog "every medcea view is security_invoker" || fail catalog "$(get invoker) view(s) without security_invoker"
    [[ -z "$(get always)" && "$(get appendonly)" -ge 8 ]] && pass catalog "$(get appendonly) append-only triggers, all ENABLE ALWAYS" \
        || fail catalog "append-only triggers not ENABLE ALWAYS: $(get always) (count $(get appendonly))"
    [[ "$(get stamp)" == 14 && "$(get rowchange)" == 14 ]] && pass catalog "stamp_actor_trg and row_change_trg on the 14 tables" \
        || fail catalog "stamp_actor_trg on $(get stamp), row_change_trg on $(get rowchange) table(s) (want 14)"
    [[ "$(get guard)" == 8 ]] && pass catalog "status_guard_trg on 8 tables" || fail catalog "status_guard_trg on $(get guard) table(s) (want 8)"
    [[ -z "$(get single)" ]] && pass catalog "zone, serial, ACL root, Q-table, zone- and unit-audit triggers present" || fail catalog "missing: $(get single)"
    [[ -z "$(get definer)" ]] && pass catalog "every SECURITY DEFINER function pins search_path ... pg_temp" || fail catalog "definer without search_path: $(get definer)"
    [[ -z "$(get invokerfn)" ]] && pass catalog "the current_user guards are SECURITY INVOKER" || fail catalog "SECURITY DEFINER guards: $(get invokerfn)"
    [[ "$(get prereq)" == "false/" ]] && pass catalog "pre_request() is INVOKER without a SET clause" || fail catalog "pre_request(): $(get prereq)"
    [[ "$(get public)" == 0 ]] && pass catalog "PUBLIC executes no function in the three schemas" || fail catalog "PUBLIC executes $(get public) function(s)"
    if [[ "$MODE" == true ]]; then
        [[ "$(get iamtrg)" -ge 14 && "$(get rls)" -ge 4 ]] && pass catalog "iam_* triggers ($(get iamtrg)) and RLS present (mode true)" \
            || fail catalog "mode true but iam_* triggers $(get iamtrg), RLS tables $(get rls)"
    else
        [[ "$(get iamtrg)" == 0 && "$(get rls)" == 0 ]] && pass catalog "no iam_* trigger and no RLS (mode false)" \
            || fail catalog "mode false but iam_* triggers $(get iamtrg), RLS tables $(get rls)"
    fi
    [[ "$(get unitalways)" == A ]] && pass catalog "user_unit_audit_trg is ENABLE ALWAYS" \
        || fail catalog "user_unit_audit_trg: tgenabled '$(get unitalways)' (want A)"
    [[ "$(get commalways)" == A ]] && pass catalog "commissioning_history_trg is ENABLE ALWAYS" \
        || fail catalog "commissioning_history_trg: tgenabled '$(get commalways)' (want A)"
    [[ "$(get chain)" == t ]] && pass catalog "iam_policy.verify_chain() ok" || fail catalog "verify_chain: $(get chain)"
    [[ "$(get chaindef)" == t ]] && pass catalog "verify_chain() is SECURITY DEFINER (iam_svc runs it without history_record)" \
        || fail catalog "verify_chain() prosecdef '$(get chaindef)': the Policy UI cannot verify the chain as iam_svc"
fi

# ── matrix ───────────────────────────────────────────────────────────────────────
if want matrix && [[ "$MODE" != legacy ]]; then
    echo ""
    sql="$(python3 - "$CLI" "$MODE" "${SRC[*]}" "${IAM_FLAG[@]}" <<'PY'
import json, subprocess, sys
cli, mode, src, flag = sys.argv[1], sys.argv[2], sys.argv[3].split(), sys.argv[4:]
doc = json.loads(subprocess.check_output([sys.executable, cli] + src + ["compile", "grants", "--format", "json"] + flag))
mgd = set(subprocess.check_output([sys.executable, cli, "db-roles", "--names"], text=True).split())
q = lambda s: "'" + s.replace("'", "''") + "'"
lines = []
for g, k, o, p in doc["privileges"]:
    if mode == "false" and g not in mgd - {"mqtt_auth"} and g != "anon":
        continue
    if k == "table":
        e = f"has_table_privilege({q(g)}, {q(o)}, {q(p)})"
        guard = f"to_regclass({q(o)}) IS NOT NULL"
    elif k == "function":
        e = f"has_function_privilege({q(g)}, {q(o)}, 'EXECUTE')"
        guard = f"to_regprocedure({q(o)}) IS NOT NULL"
    else:
        e = f"has_schema_privilege({q(g)}, {q(o)}, 'USAGE')"
        guard = "true"
    lines.append(f"SELECT 'grant', {q(g + ' ' + p + ' ' + o)} WHERE {guard} AND NOT {e};")
neg = [("anon", "medcea.recipe", "SELECT") if mode == "true" else None,
       ("rr_operator", "medcea.recipe_run", "UPDATE"), ("svc_scheduler", "medcea.recipe_run", "UPDATE"),
       ("rr_production_manager", "medcea.recipe_line_cycle_run", "UPDATE"), ("svc_scheduler", "medcea.recipe_line_cycle_run", "INSERT"),
       ("rr_engineer", "medcea.recipe_unit_permission", "UPDATE"), ("rr_engineer", "medcea.mqtt_credential", "SELECT"),
       ("rr_admin", "medcea.measurement", "SELECT"), ("rr_auditor", "medcea.recipe", "INSERT"),
       ("rr_qa", "medcea.approval", "INSERT"), ("svc_grafana", "medcea.mqtt_service_credential", "SELECT"),
       ("rr_engineer", "medcea.mqtt_service_acl", "SELECT"), ("svc_ingest", "medcea.measurement", "UPDATE"),
       ("svc_ingest", "medcea.measurement", "DELETE"), ("rr_admin", "medcea.platform_setting", "SELECT")]
for n in neg:
    if n:
        lines.append(f"SELECT 'negative', {q(' '.join(n))} WHERE has_table_privilege({q(n[0])}, {q(n[1])}, {q(n[2])});")
if mode == "true":
    for r in sorted({m[0] for m in doc["memberships"] if m[1] == "authenticator"}):
        lines.append(f"SELECT 'member', {q(r)} WHERE NOT (pg_has_role('authenticator', {q(r)}, 'SET') AND NOT pg_has_role('authenticator', {q(r)}, 'USAGE'));")
    lines.append("SELECT 'member', 'rr_admin_login' WHERE NOT pg_has_role('rr_admin_login', 'rr_admin', 'USAGE');")
print("\n".join(lines))
PY
)"
    out="$(db <<<"$sql")"
    n_grant="$(grep -c '^grant|' <<<"$out" || true)"; n_neg="$(grep -c '^negative|' <<<"$out" || true)"
    n_mem="$(grep -c '^member|' <<<"$out" || true)"; n_err="$(grep -c 'ERROR' <<<"$out" || true)"
    [[ "$n_grant" == 0 && "$n_err" == 0 ]] && pass matrix "every compiled privilege is held ($(grep -c '^SELECT' <<<"$sql") checks)" \
        || fail matrix "$n_grant missing, $n_err error(s): $(grep -m3 '^grant\|ERROR' <<<"$out" | tr '\n' ';')"
    [[ "$n_neg" == 0 ]] && pass matrix "the hand-written negatives hold" || fail matrix "held but must not be: $(grep '^negative|' <<<"$out" | cut -d'|' -f2 | tr '\n' ';')"
    if [[ "$MODE" == true ]]; then
        [[ "$n_mem" == 0 ]] && pass matrix "authenticator: SET without INHERIT on every rr_ role and anon; rr_admin_login inherits rr_admin" \
            || fail matrix "memberships: $(grep '^member|' <<<"$out" | cut -d'|' -f2 | tr '\n' ' ')"
    fi
    vout="$(python3 "$CLI" "${SRC[@]}" compile grants --mode verify "${IAM_FLAG[@]}" | db)"
    grep -q 'grants verified' <<<"$vout" && ! grep -q ERROR <<<"$vout" && pass matrix "grants --mode verify passes" \
        || fail matrix "verify: $(grep -m2 -E 'ERROR|DETAIL' <<<"$vout" | tr '\n' ' ' | cut -c1-300)"
fi

# ── pre_request ──────────────────────────────────────────────────────────────────
if want prerequest && [[ "$MODE" != legacy ]]; then
    echo ""
    if [[ "$MODE" == true ]]; then
        pre() {  # NAME EXPECT CLAIMS
            probe prerequest "$1" "$2" <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$3', true) \\g /dev/null
SELECT medcea_auth.pre_request();
SQL
        }
        probe prerequest "operator token -> rr_operator" ok <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$(claims operator "$UUID_OP" p-op)', true) \g /dev/null
SELECT medcea_auth.pre_request();
SELECT current_user = 'rr_operator' AS ok \gset
--CHECKS
SELECT 'CHECK|current_user is rr_operator', :'ok'::boolean;
SQL
        probe prerequest "production_manager + its operator composite -> rr_production_manager" ok <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$(claims production_manager,operator,offline_access "$UUID_PM" p-pm)', true) \g /dev/null
SELECT medcea_auth.pre_request();
SELECT current_user = 'rr_production_manager' AS ok \gset
--CHECKS
SELECT 'CHECK|current_user is rr_production_manager', :'ok'::boolean;
SQL
        pre "two own roles" "28000:two own roles" "$(claims qa,engineer "$UUID_QA" p-qa)"
        pre "no platform role" "28000:no platform role" "$(claims offline_access "$UUID_QA" p-qa)"
        pre "a client the API does not accept" "28000:may not use the API" "$(claims operator "$UUID_OP" p-op grafana)"
        pre "an ID token" "28000:not an access token" "$(claims operator "$UUID_OP" p-op config ID)"
        pre "audience missing" "28000:audience" "$(claims operator "$UUID_OP" p-op config Bearer '')"
        pre "a sub that is not a uuid" "28000:uuid" "$(claims operator not-a-uuid p-op)"
        probe prerequest "no claims at all" "28000:no token" <<'SQL'
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT medcea_auth.pre_request();
SQL
        # what PostgREST 12 really sends without a token: claims holding only the anon
        # role, never NULL (the probe above alone let a broken check pass)
        pre "no token (claims hold only role anon)" "28000:no token" '{"role":"anon"}'
        probe prerequest "no token on GET / (the readiness probe) stays anon" ok <<'SQL'
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '{"role":"anon"}', true) \g /dev/null
SELECT set_config('request.method', 'GET', true) \g /dev/null
SELECT set_config('request.path', '/', true) \g /dev/null
SELECT medcea_auth.pre_request();
SELECT current_user = 'anon' AS ok \gset
--CHECKS
SELECT 'CHECK|current_user is anon', :'ok'::boolean;
SQL
    else
        probe prerequest "false mode: pre_request() is a no-op, the role stays anon" ok <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$(claims admin "$UUID_AD" p-ad)', true) \g /dev/null
SELECT medcea_auth.pre_request();
SELECT current_user = 'anon' AS ok \gset
--CHECKS
SELECT 'CHECK|current_user is anon', :'ok'::boolean;
SQL
    fi
fi

# ── actor ────────────────────────────────────────────────────────────────────────
if want actor && [[ "$MODE" != legacy ]]; then
    echo ""
    probe actor "control: the actor store answers" ok <<'SQL'
SELECT medcea_auth.request_actor();
SQL
    probe actor "a spoofed actor table" "42501:spoofed" <<'SQL'
SET ROLE anon;
CREATE TEMPORARY TABLE medcea_actor (kind text PRIMARY KEY, sub text, person text, name text, role text,
                                     source text, ref_kind text, ref_id bigint);
INSERT INTO pg_temp.medcea_actor VALUES ('actor', '11111111-1111-4111-8111-111111111111', 'p-x', 'x', 'qa', 'token', NULL, NULL);
RESET ROLE;
SELECT medcea_auth.request_actor();
SQL
    probe actor "set_actor with a sub that is not a uuid" "22023:uuid" <<'SQL'
SELECT medcea_auth.set_actor('system:x', 'p', 'n', 'operator');
SQL
    probe actor "set_actor with an unknown role" "22023:not a platform role" <<SQL
SELECT medcea_auth.set_actor('$UUID_OP', 'p', 'n', 'superuser');
SQL
    sched_insert="INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
SELECT u.unit_id, r.recipe_id, '0 1 * * *', 'iam-db probe' FROM medcea.cea_unit u, medcea.recipe r
 WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS sid \\gset"
    if [[ "$WRITES" == true ]]; then
        if [[ "$MODE" == false ]]; then
            probe actor "svc_scheduler with forged claims is db:svc_scheduler" ok <<SQL
SET SESSION AUTHORIZATION svc_scheduler;
SELECT set_config('request.jwt.claims', '$(claims production_manager "$UUID_PM" p-pm)', true) \g /dev/null
$sched_insert
--CHECKS
SELECT 'CHECK|stamped db:svc_scheduler', created_by_sub = 'db:svc_scheduler' AND created_by_source = 'db' FROM medcea.schedule WHERE schedule_id = :sid;
SQL
        else
            probe actor "svc_scheduler with forged claims and no set_actor" "42501:no actor" <<SQL
SET SESSION AUTHORIZATION svc_scheduler;
SELECT set_config('request.jwt.claims', '$(claims production_manager "$UUID_PM" p-pm)', true) \g /dev/null
$sched_insert
SQL
            probe actor "a production manager's token is source token" ok <<SQL
$(as_token "$(claims production_manager "$UUID_PM" p-pm)")
$sched_insert
--CHECKS
SELECT 'CHECK|stamped token', created_by_sub = '$UUID_PM' AND created_by_source = 'token' AND created_by_person = 'p-pm'
  FROM medcea.schedule WHERE schedule_id = :sid;
SQL
            probe actor "svc_scheduler after set_actor is 'person via svc_scheduler'" ok <<SQL
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_actor('$UUID_PM', 'p-pm', 'test-pm', 'production_manager');
$sched_insert
--CHECKS
SELECT 'CHECK|stamped person via', created_by_source = 'person via svc_scheduler' FROM medcea.schedule WHERE schedule_id = :sid;
SQL
        fi
        if [[ "$MODE" == true ]]; then
            # rr_admin_login inherits rr_admin (no SET): pgAdmin's session can never pass for a token
            probe actor "rr_admin_login (inheriting rr_admin) with forged claims has no actor" "42501:no actor" <<SQL
SET SESSION AUTHORIZATION rr_admin_login;
SELECT set_config('request.jwt.claims', '$(claims admin "$UUID_AD" p-ad)', true) \g /dev/null
SELECT medcea.propose_setting('log_delete_days', '45');
SQL
            probe actor "rr_admin_login cannot SET ROLE rr_admin" "42501:permission denied" <<'SQL'
SET SESSION AUTHORIZATION rr_admin_login;
SET ROLE rr_admin;
SQL
        fi
    fi
fi

# ── writes ───────────────────────────────────────────────────────────────────────
if want writes && [[ "$WRITES" == true ]]; then
    echo ""
    stamped() {  # TABLE WHERE — a CHECK that the row is stamped db:authenticator and logged
        [[ "$MODE" == legacy ]] && return 0
        echo "SELECT 'CHECK|$1 stamped', created_by_sub = 'db:authenticator' FROM medcea.$1 WHERE $2;"
        echo "SELECT 'CHECK|$1 in row_change', EXISTS (SELECT 1 FROM medcea.row_change WHERE target = 'medcea.$1' AND actor_sub = 'db:authenticator');"
    }
    # W1: today's callers keep working (after apply false, and again after true -> false)
    if [[ "$MODE" == false || "$MODE" == legacy ]]; then
        probe W1 "config UI: create a location (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.cea_location (name, is_active) VALUES ('IAMT probe site', 'Y');
--CHECKS
$(stamped cea_location "name = 'IAMT probe site'")
SQL
        probe W1 "config UI: edit a unit (anon)" ok <<SQL
$(as_anon)
UPDATE medcea.cea_unit SET description = 'edited by iam-db' WHERE unit_code = 'IAMT01';
--CHECKS
$([[ "$MODE" == legacy ]] || echo "SELECT 'CHECK|updated_by', updated_by_sub = 'db:authenticator' AND created_by_sub IS DISTINCT FROM 'db:authenticator' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';")
SQL
        probe W1 "config UI: create and delete a zone (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active) SELECT unit_id, 'ZDEL', 'Y' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
DELETE FROM medcea.cea_zone WHERE zone_code = 'ZDEL';
--CHECKS
$([[ "$MODE" == legacy ]] || echo "SELECT 'CHECK|delete logged', EXISTS (SELECT 1 FROM medcea.row_change WHERE target = 'medcea.cea_zone' AND op = 'D' AND old_values ->> 'zone_code' = 'ZDEL');")
SQL
        probe W1 "config UI: component create, edit, delete (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.component (component_id, device_id, component_type, model)
SELECT nextval('medcea.component_component_id_seq'), device_id, 'SENSOR', 'iamt' FROM medcea.device WHERE dns_name = 'iamt02-s-z01';
UPDATE medcea.component SET model = 'iamt2' WHERE model = 'iamt';
DELETE FROM medcea.component WHERE model = 'iamt2';
SQL
        probe W1 "config UI: recipe and line create, edit, delete (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.recipe (recipe_name) VALUES ('IAMT probe recipe');
INSERT INTO medcea.recipe_line (recipe_id, recipe_item_seq_id, recipe_item_seq_name, cycle_number,
    air_temperature_lower_limit, air_temperature_upper_limit, light_type, light_on_minutes, light_off_minutes,
    co2_lower_limit, co2_upper_limit, hr_lower_limit, hr_upper_limit)
SELECT recipe_id, 1, 'p', 1, 18, 24, 'BLUE', 1, 1, 400, 900, 70, 90 FROM medcea.recipe WHERE recipe_name = 'IAMT probe recipe';
UPDATE medcea.recipe_line SET light_on_minutes = 2 WHERE recipe_item_seq_name = 'p';
DELETE FROM medcea.recipe_line WHERE recipe_item_seq_name = 'p';
DELETE FROM medcea.recipe WHERE recipe_name = 'IAMT probe recipe';
SQL
        probe W1 "config UI: recipe x unit upsert (anon)" ok <<SQL
$(as_anon)
INSERT INTO medcea.recipe_unit_permission (recipe_id, unit_id, allowed, algorithm_params)
SELECT r.recipe_id, u.unit_id, true, '{"x": 3}' FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01'
ON CONFLICT (recipe_id, unit_id) DO UPDATE SET allowed = EXCLUDED.allowed, algorithm_params = EXCLUDED.algorithm_params;
SQL
        probe W1 "wizard: device PATCH resending the same serial keeps the credential" ok <<SQL
$(as_anon)
UPDATE medcea.device SET serial_number = serial_number, model = 'iamt-model' WHERE dns_name = 'iamt01-c-z02';
--CHECKS
SELECT 'CHECK|credential still active', active FROM medcea.mqtt_credential WHERE username = 'iamt01-c-z02';
SQL
        probe W1 "wizard: a real serial change deactivates the credential" ok <<SQL
$(as_anon)
UPDATE medcea.device SET serial_number = 'iamt-aa:bb:cc:00:00:99' WHERE dns_name = 'iamt01-c-z02';
--CHECKS
$([[ "$MODE" == legacy ]] && echo "SELECT 'CHECK|done', true;" || echo "SELECT 'CHECK|credential deactivated', NOT active FROM medcea.mqtt_credential WHERE username = 'iamt01-c-z02';")
SQL
        probe W1 "wizard: register_mqtt_credential v1 (anon)" ok <<SQL
$(as_anon)
SELECT medcea.register_mqtt_credential('iamt01-c-z02', '\$7\$101\$c2FsdA==\$aGFzaA==',
       (SELECT device_id FROM medcea.device WHERE dns_name = 'iamt01-c-z02'), 'CONTROL', 'medcea/IAMT01/Z02');
SQL
        probe W1 "scheduler (postgres): run insert, status updates, cycle upsert" ok <<'SQL'
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y' FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT02' RETURNING recipe_run_id AS run \gset
UPDATE medcea.recipe_run SET recipe_run_status = 'R', timestamp_upd = now() WHERE recipe_run_id = :run;
INSERT INTO medcea.recipe_line_cycle_run (recipe_line_cycle_run_id, recipe_run_id, recipe_id, recipe_item_seq_id,
       recipe_item_seq_cycle_num, recipe_line_cycle_run_status)
SELECT nextval('medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq'), :run, recipe_id, 1, 1, 'R'
  FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1'
ON CONFLICT (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num)
DO UPDATE SET recipe_line_cycle_run_status = 'C';
UPDATE medcea.recipe_run SET recipe_run_status = 'C', recipe_run_end = now() WHERE recipe_run_id = :run;
SQL
        probe W1 "runner (postgres): Q-table upsert and delete are events" ok <<SQL
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state, updated_at)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{"q": 1}', now() FROM medcea.cea_unit WHERE unit_code = 'IAMT01'
ON CONFLICT (unit_id, algorithm, channel) DO UPDATE SET state = EXCLUDED.state, updated_at = now();
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state, updated_at)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{"q": 2}', now() FROM medcea.cea_unit WHERE unit_code = 'IAMT01'
ON CONFLICT (unit_id, algorithm, channel) DO UPDATE SET state = EXCLUDED.state, updated_at = now();
DELETE FROM medcea.algorithm_state WHERE channel = 'iamt';
--CHECKS
$([[ "$MODE" == legacy ]] && echo "SELECT 'CHECK|done', true;" || echo "SELECT 'CHECK|created, updated, deleted', (SELECT array_agg(event ORDER BY event_id) FROM medcea.algorithm_state_event WHERE channel = 'iamt') = ARRAY['created', 'updated', 'deleted'];")
SQL
        probe W1 "scheduler (postgres): schedule insert/delete, retention '5', algorithm edit" ok <<'SQL'
INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression)
SELECT u.unit_id, r.recipe_id, '0 3 * * *' FROM medcea.cea_unit u, medcea.recipe r
 WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS sid \gset
DELETE FROM medcea.schedule WHERE schedule_id = :sid;
INSERT INTO medcea.scheduler_config (key, value) VALUES ('log_compress_days', '5')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
UPDATE medcea.control_algorithm SET default_params = '{"kp": 1.5, "ki": 0.1, "kd": 0.05}' WHERE algorithm_code = 'PID';
SQL
        probe W1 "access service (access_svc): an access request" ok <<'SQL'
SET ROLE access_svc;
INSERT INTO iam.access_request (username, email, first_name, last_name, requested_role, justification)
VALUES ('iamt-probe', 'iamt-probe@medcea.invalid', 'I', 'T', 'operator', 'iam-db probe');
SQL
        # IAM 2.7: status records are written by the decision functions only
        probe W1 "access service (access_svc): a status record written directly" "42501:user_status_history" <<'SQL'
SET ROLE access_svc;
INSERT INTO iam.user_status_history (keycloak_user_id, username, action, reason, actor)
VALUES ('00000000-0000-4000-8000-000000000000', 'iamt-probe', 'deactivated', 'probe', 'iam-db');
SQL
        probe W1 "broker sidecar (mqtt_auth): its query" ok <<'SQL'
SET ROLE mqtt_auth;
SELECT c.username, c.password_hash, c.role, c.topic_base FROM medcea.mqtt_credential c
  JOIN medcea.device d ON d.device_id = c.device_id WHERE c.active AND d.is_active = 'Y' ORDER BY c.username;
SQL
        if [[ "$MODE" == true ]]; then   # IAM 3.5: the person credentials, read through the compiled grants
            probe W1 "broker sidecar (mqtt_auth): its person and unit queries" ok <<'SQL'
SET ROLE mqtt_auth;
SELECT c.username, c.password_hash, c.expires_at, a.access, a.topic FROM medcea.mqtt_service_credential c
  LEFT JOIN medcea.mqtt_service_acl a USING (username)
 WHERE c.active AND c.expires_at > now() AND c.person_sub IS NOT NULL AND c.username LIKE 'explorer-%';
SELECT u.unit_code, u.commissioning,
       EXISTS (SELECT 1 FROM medcea.recipe_run r WHERE r.unit_id = u.unit_id AND r.recipe_run_status = 'R')
  FROM medcea.cea_unit u;
SQL
        fi
        if [[ "$MODE" != legacy ]]; then
            probe W1 "config UI: deleting a unit whose assignment has a parameter set" ok <<SQL
INSERT INTO medcea.cea_unit (unit_type, location_id, is_active, unit_code)
SELECT 'Other', location_id, 'Y', 'IAMTDEL' FROM medcea.cea_location WHERE name = 'IAMTEST site' RETURNING unit_id AS ud \gset
INSERT INTO medcea.recipe_unit_permission (recipe_id, unit_id, allowed) SELECT recipe_id, :ud, true FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1';
SET ROLE medcea_owner;
INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params)
SELECT algorithm_id, :ud, 'iamt-del', '{}' FROM medcea.control_algorithm WHERE algorithm_code = 'PID' RETURNING params_id AS pd \gset
UPDATE medcea.recipe_unit_permission SET params_id = :pd WHERE unit_id = :ud;
RESET ROLE;
$(as_anon)
DELETE FROM medcea.cea_unit WHERE unit_id = :ud;
--CHECKS
SELECT 'CHECK|set kept', EXISTS (SELECT 1 FROM medcea.unit_algorithm_params WHERE params_id = :pd);
SQL
        fi
    fi

    # W2: the always-on guards (false mode; they hold in true mode too)
    if [[ "$MODE" != legacy ]]; then
        # the writer: anon while false; in true mode anon holds nothing, so an engineer's token
        if [[ "$MODE" == true ]]; then w2_writer="$(as_token "$(claims engineer "$UUID_EN" p-en)")"; w2_who="an engineer"
        else w2_writer="$(as_anon)"; w2_who="anon"; fi
        probe W2 "control: $w2_who edits a draft recipe" ok <<SQL
$w2_writer
INSERT INTO medcea.recipe (recipe_name) VALUES ('IAMT draft') RETURNING recipe_id AS rd \gset
UPDATE medcea.recipe SET recipe_description = 'x' WHERE recipe_id = :rd;
--CHECKS
SELECT 'CHECK|still draft', status = 'draft' FROM medcea.recipe WHERE recipe_id = :rd;
SQL
        if [[ "$MODE" == false ]]; then
            probe W2 "anon sets status approved" "42501:approval function" <<SQL
$(as_anon)
INSERT INTO medcea.recipe (recipe_name) VALUES ('IAMT draft') RETURNING recipe_id AS rd \gset
UPDATE medcea.recipe SET status = 'approved' WHERE recipe_id = :rd;
SQL
            probe W2 "anon sets commissioning" "42501:commissioning" <<SQL
$(as_anon)
UPDATE medcea.cea_unit SET commissioning = true WHERE unit_code = 'IAMT01';
SQL
            probe W2 "anon retires a schedule" "42501:retired_at" <<SQL
$(as_anon)
UPDATE medcea.schedule SET retired_at = now() WHERE description LIKE 'iamtest%';
SQL
            probe W2 "anon repoints an assignment's parameter set" "42501:params_id" <<SQL
$(as_anon)
UPDATE medcea.recipe_unit_permission SET params_id = NULL
 WHERE recipe_id = (SELECT recipe_id FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1') AND params_id IS NOT NULL;
SQL
            probe W2 "anon edits an approved recipe: it is a draft again" ok <<SQL
$(as_anon)
UPDATE medcea.recipe SET recipe_description = 'changed after approval' WHERE recipe_name = 'IAMTEST-R1';
--CHECKS
SELECT 'CHECK|demoted', status = 'draft' FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1';
SQL
            probe W2 "anon edits a line of an approved recipe: the recipe is a draft again" ok <<SQL
$(as_anon)
UPDATE medcea.recipe_line SET light_on_minutes = light_on_minutes + 1 WHERE recipe_id = (SELECT recipe_id FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1');
--CHECKS
SELECT 'CHECK|parent demoted', status = 'draft' FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1';
SQL
        fi
        probe W2 "control: postgres appends an approval" ok <<'SQL'
INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, approved_by_sub)
VALUES ('medcea.recipe', '[0]', 'x', 'recipes', 'review', 'system:test');
SQL
        probe W2 "replica mode does not open the approvals to UPDATE" "42501:append-only" <<'SQL'
SET session_replication_role = replica;
UPDATE medcea.approval SET note = 'x';
SQL
        probe W2 "postgres updates the device slot history" "42501:append-only" <<'SQL'
UPDATE medcea.device_slot_history SET to_dns_name = 'x';
SQL
        probe W2 "postgres deletes a row change" "42501:append-only" <<'SQL'
DELETE FROM medcea.row_change;
SQL
    fi

    # W3: the flag alone (IAM_DB_ROLES recorded true inside the transaction)
    if [[ "$MODE" == false ]]; then
        probe W3 "control: policy_refuse() only warns while false" ok <<'SQL'
SELECT medcea_auth.policy_refuse('iam-db probe');
SQL
        probe W3 "policy_refuse() raises once the flag is true" "42501:iam-db probe" <<'SQL'
UPDATE medcea.platform_setting SET value = 'true' WHERE key = 'iam_db_roles';
SELECT medcea_auth.policy_refuse('iam-db probe');
SQL
        probe W3 "a write without an actor is refused once the flag is true" "42501:no actor" <<SQL
UPDATE medcea.platform_setting SET value = 'true' WHERE key = 'iam_db_roles';
$(as_anon)
INSERT INTO medcea.cea_location (name, is_active) VALUES ('IAMT flagged', 'Y');
SQL
    fi

    # W4: the workflow, true mode only
    if [[ "$MODE" == true ]]; then
        T_PM="$(claims production_manager "$UUID_PM" p-pm)"; T_OP="$(claims operator "$UUID_OP" p-op)"
        T_OP2="$(claims operator "$UUID_OP2" p-op2)"; T_QA="$(claims qa "$UUID_QA" p-qa)"
        T_QAOP="$(claims qa "$UUID_QA2" p-op)"     # a qa account of the operator's person
        T_QP="$(claims qp "$UUID_QP" p-qp)"; T_QPOP="$(claims qp "$UUID_QP" p-op)"
        T_EN="$(claims engineer "$UUID_EN" p-en)"; T_EN2="$(claims engineer "$UUID_EN2" p-en2)"
        T_QAEN2="$(claims qa "$UUID_QA2" p-en2)"; T_AD="$(claims admin "$UUID_AD" p-ad)"
        run_setup="
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SELECT p.params_id AS set1 FROM medcea.recipe_unit_permission p JOIN medcea.recipe r USING (recipe_id) JOIN medcea.cea_unit u USING (unit_id)
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' \\gset
$(as_token "$T_PM")
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'R', 'Y', :set1 FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' RETURNING recipe_run_id AS run \\gset"
        probe W4 "control: an operator starts a run a production manager prepared for their unit" ok <<SQL
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
--CHECKS
SELECT 'CHECK|running, executed by the operator', recipe_run_status = 'R' AND executed_by_person = 'p-op' AND created_by_role = 'production_manager'
  FROM medcea.recipe_run WHERE recipe_run_id = :run;
SQL
        probe W4 "an operator without the run's unit" "42501:not one of your units" <<SQL
$run_setup
$(as_token "$T_OP2")
SELECT medcea.start_run(:run);
SQL
        probe W4 "a parameter set of another unit" "22023:belongs to unit" <<SQL
$run_setup
$(as_postgres)
SET ROLE medcea_owner;
INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params)
SELECT algorithm_id, (SELECT unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02'), 'iamt-other-unit', '{}'
  FROM medcea.control_algorithm WHERE algorithm_code = 'IF_THEN_ELSE' RETURNING params_id AS other \gset
$(as_token "$T_PM")
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :other FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01';
SQL
        probe W4 "a parameter set of another algorithm" "22023:is for algorithm" <<SQL
$run_setup
$(as_postgres)
SET ROLE medcea_owner;
INSERT INTO medcea.unit_algorithm_params (algorithm_id, unit_id, name, params)
SELECT algorithm_id, (SELECT unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT01'), 'iamt-other-alg', '{}'
  FROM medcea.control_algorithm WHERE algorithm_code = 'MPC' RETURNING params_id AS other \gset
$(as_token "$T_PM")
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :other FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01';
SQL
        probe W4 "a recipe edited behind the triggers no longer matches its approval" "42501:changed since its approval" <<SQL
$run_setup
$(as_postgres)
SET session_replication_role = replica;
UPDATE medcea.recipe SET recipe_description = 'edited behind the triggers' WHERE recipe_name = 'IAMTEST-R1';
SET session_replication_role = origin;
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
SQL
        probe W4 "an operator updates a run directly" "42501:permission denied for table recipe_run" <<SQL
$run_setup
$(as_token "$T_OP")
UPDATE medcea.recipe_run SET recipe_run_status = 'C' WHERE recipe_run_id = :run;
SQL
        # only a role past the grants reaches the trigger: postgres is not medcea_owner
        probe W4 "a direct run update that passes the grants (postgres)" "42501:regulated record" <<SQL
$run_setup
$(as_postgres)
UPDATE medcea.recipe_run SET recipe_run_status = 'C' WHERE recipe_run_id = :run;
SQL
        # rerun_by TOKEN: the run of run_setup started by p-op, failed, rescheduled (F -> S)
        # by TOKEN, started again by p-op2 and completed by the scheduler
        rerun_by() { cat <<RERUN
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
SELECT medcea.set_run_status(:run, 'F');
$(as_token "$1")
SELECT medcea.set_run_status(:run, 'S');
$(as_postgres)
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP2'::uuid, unit_id FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP';
$(as_token "$T_OP2")
SELECT medcea.start_run(:run);
$(as_postgres)
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_system_actor('system:scheduler', 'run', :run);
SELECT medcea.finish_run(:run, 'C');
$(as_postgres)
-- the stored system actor lasts the transaction (the probe is one); a release is
-- PostgREST's own transaction in real life, so clear it before the token
DELETE FROM pg_temp.medcea_actor WHERE kind = 'actor';
RERUN
        }
        rerun="$(rerun_by "$T_PM")"
        probe W4 "control: re-executed run (F -> S -> R -> C) released by an independent qp" ok <<SQL
$rerun
$(as_token "$T_QP")
SELECT medcea.release_run(:run);
--CHECKS
SELECT 'CHECK|released', EXISTS (SELECT 1 FROM medcea.run_release WHERE recipe_run_id = :run AND released_by_person = 'p-qp');
SQL
        probe W4 "the first executor of an earlier attempt cannot release" "42501:not_own_author" <<SQL
$rerun
$(as_token "$T_QPOP")
SELECT medcea.release_run(:run);
SQL
        # Release in the Approvals tab (2026-10-31): release_run(run, note), the queue's run
        # rows for qp (approval_queue kind 'run') and their may_approve against release_run
        T_QPPM="$(claims qp "$UUID_QP" p-pm)"; T_QPOP2="$(claims qp "$UUID_QP" p-op2)"
        T_QPPM2="$(claims qp "$UUID_QP" p-pm2)"; T_PM2="$(claims production_manager "$UUID_PM" p-pm2)"
        T_QP2="$(claims qp "$UUID_QA2" p-qp2)"; T_AU="$(claims auditor "$UUID_QA2" p-au)"
        run_row="SELECT may_approve AS ma, coalesce(why_not_code, 'none') AS wn FROM medcea.approval_queue() WHERE kind = 'run' AND id = :run \gset"
        probe W4 "control: approval_queue lists the completed run for qp, with its summary and may_approve" ok <<SQL
$rerun
$(as_token "$T_QP")
SELECT may_approve AS ma, may_return AS mr, state AS st, group_name AS g, target AS tg,
       (SELECT array_agg(x ORDER BY x) FROM unnest(authors) x)::text AS au,
       (detail ->> 'attempts')::integer AS att, detail ->> 'status' AS rs, detail ->> 'created_by_person' AS cp,
       detail ->> 'executed_by_person' AS ep,
       (SELECT array_agg(e ->> 'by_person' ORDER BY i) FROM jsonb_array_elements(detail -> 'executors') WITH ORDINALITY x(e, i))::text AS exs,
       (detail -> 'cycles' ->> 'total')::integer AS cyc, detail ? 'recipe_approval_id' AND detail ? 'params_approval_id' AS apr,
       detail ? 'log' AS lg
  FROM medcea.approval_queue() WHERE kind = 'run' AND id = :run \gset
--CHECKS
SELECT 'CHECK|waiting, may release, never return', :'st' = 'waiting' AND :'ma'::boolean AND NOT :'mr'::boolean;
SELECT 'CHECK|group runs, target recipe_run', :'g' = 'runs' AND :'tg' = 'medcea.recipe_run';
SELECT 'CHECK|authors: creator and both executors (' || :'au' || ')', :'au' = '{p-op,p-op2,p-pm}';
SELECT 'CHECK|two attempts, executors p-op then p-op2 (' || :'exs' || ')', :att = 2 AND :'exs' = '{p-op,p-op2}';
SELECT 'CHECK|completed, created by p-pm, executed by p-op2', :'rs' = 'C' AND :'cp' = 'p-pm' AND :'ep' = 'p-op2';
SELECT 'CHECK|cycles counted, approvals named', :cyc >= 0 AND :'apr'::boolean;
SELECT 'CHECK|no run log in the summary', NOT :'lg'::boolean;
SQL
        probe W4 "control: qp releases with a note (2-argument overload); the run leaves the queue" ok <<SQL
$rerun
$(as_token "$T_QP")
SELECT medcea.release_run(:run, ' iam-db release note ') AS rel \gset
SELECT count(*) AS left_in_queue FROM medcea.approval_queue() WHERE kind = 'run' AND id = :run \gset
--CHECKS
SELECT 'CHECK|run_release.note trimmed', note = 'iam-db release note' AND released_by_person = 'p-qp'
  FROM medcea.run_release WHERE recipe_run_id = :run;
SELECT 'CHECK|approval release row with the note', action = 'release' AND note = 'iam-db release note' AND group_name = 'runs'
  FROM medcea.approval WHERE approval_id = :rel;
SELECT 'CHECK|no longer in the queue', :left_in_queue = 0;
SQL
        probe W4 "control: the 1-argument release_run still releases, without a note" ok <<SQL
$rerun
$(as_token "$T_QP")
SELECT medcea.release_run(:run);
--CHECKS
SELECT 'CHECK|released, note NULL', note IS NULL FROM medcea.run_release WHERE recipe_run_id = :run;
SQL
        probe W4 "a run released twice" "22023:is already released" <<SQL
$rerun
$(as_token "$T_QP")
SELECT medcea.release_run(:run, 'first');
$(as_token "$T_QP2")
SELECT medcea.release_run(:run, 'second');
SQL
        probe W4 "release of a run that is not completed" "22023:not completed" <<SQL
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
$(as_token "$T_QP")
SELECT medcea.release_run(:run, NULL);
SQL
        probe W4 "approval_queue: a run that is not completed is not listed" ok <<SQL
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
$(as_token "$T_QP")
SELECT count(*) AS n FROM medcea.approval_queue() WHERE kind = 'run' AND id = :run \gset
--CHECKS
SELECT 'CHECK|not listed', :n = 0;
SQL
        # own_author for each way of authoring a run; each queue row, then release_run itself
        for who in "creator:T_QPPM" "first executor:T_QPOP" "last executor:T_QPOP2" "rescheduler (changer only):T_QPPM2"; do
            tok="${who#*:}"
            probe W4 "approval_queue: the run's $(cut -d: -f1 <<<"$who") reads own_author" ok <<SQL
$(rerun_by "$T_PM2")
$(as_token "${!tok}")
$run_row
--CHECKS
SELECT 'CHECK|own_author, not may_approve', :'wn' = 'own_author' AND NOT :'ma'::boolean;
SQL
            probe W4 "parity: the run's $(cut -d: -f1 <<<"$who") releases" "42501:not_own_author" <<SQL
$(rerun_by "$T_PM2")
$(as_token "${!tok}")
SELECT medcea.release_run(:run, 'parity');
SQL
        done
        probe W4 "control: with a rescheduler p-pm2, an independent qp may still release" ok <<SQL
$(rerun_by "$T_PM2")
$(as_token "$T_QP")
$run_row
SELECT medcea.release_run(:run, 'parity');
--CHECKS
SELECT 'CHECK|may_approve agreed with the release', :'ma'::boolean AND :'wn' = 'none';
SQL
        # an unattributed change to the run (as a pre-IAM writer left them): a row_change
        # with no person, appended as postgres
        unattributed_run="
$(as_postgres)
INSERT INTO medcea.row_change (target, row_key, op, old_values, new_values, actor_sub, actor_name, actor_source)
VALUES ('medcea.recipe_run', jsonb_build_array(:run), 'U', '{\"is_active\": \"N\"}', '{\"is_active\": \"Y\"}', 'db:postgres', 'postgres', 'db');"
        probe W4 "approval_queue: an unattributed change to the run reads unattributed" ok <<SQL
$rerun
$unattributed_run
$(as_token "$T_QP")
$run_row
--CHECKS
SELECT 'CHECK|unattributed, not may_approve', :'wn' = 'unattributed' AND NOT :'ma'::boolean;
SQL
        probe W4 "parity: release of a run with an unattributed change" "42501:unattributed changes" <<SQL
$rerun
$unattributed_run
$(as_token "$T_QP")
SELECT medcea.release_run(:run, 'parity');
SQL
        # a completed run from before 008b, as B4 left it: created migration:008, no person,
        # no row_change (replica skips stamp_actor and row_change_trg), executed_by_person NULL
        legacy_run="
$(as_postgres)
SET LOCAL session_replication_role = replica;
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_end, recipe_run_status, is_active,
                               created_by_sub, created_by_name, created_by_source)
SELECT r.recipe_id, u.unit_id, now() - interval '2 days', now() - interval '1 day', 'C', 'Y',
       'migration:008', 'migration:008', 'migration'
  FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' RETURNING recipe_run_id AS run \\gset
SET LOCAL session_replication_role = origin;"
        probe W4 "approval_queue: a run from before 008b (migration:008, no history) reads no_attribution" ok <<SQL
$legacy_run
SELECT count(*) AS hist FROM medcea.row_change WHERE target = 'medcea.recipe_run' AND row_key = jsonb_build_array(:run) \gset
$(as_token "$T_QP")
$run_row
--CHECKS
SELECT 'CHECK|no row_change for the legacy run (' || :hist || ')', :hist = 0;
SELECT 'CHECK|no_attribution, not may_approve', :'wn' = 'no_attribution' AND NOT :'ma'::boolean;
SQL
        probe W4 "parity: release of a run from before 008b" "42501:no attributed history" <<SQL
$legacy_run
$(as_token "$T_QP")
SELECT medcea.release_run(:run, 'parity');
SQL
        probe W4 "approval_queue: a qp token without person_id reads no_person" ok <<SQL
$rerun
$(as_token "$(claims qp "$UUID_QP" p-qp | sed 's/"person_id":"p-qp",//')")
$run_row
--CHECKS
SELECT 'CHECK|no_person', :'wn' = 'no_person' AND NOT :'ma'::boolean;
SQL
        probe W4 "approval_queue: qa and auditor (R on runs, no A) get no run rows" ok <<SQL
$rerun
$(as_token "$T_QA")
SELECT count(*) AS qa FROM medcea.approval_queue() WHERE kind = 'run' \gset
$(as_token "$T_AU")
SELECT count(*) AS au FROM medcea.approval_queue() WHERE kind = 'run' \gset
--CHECKS
SELECT 'CHECK|qa none (' || :qa || '), auditor none (' || :au || ')', :qa = 0 AND :au = 0;
SQL
        probe W4 "an operator of another unit reads no approval_queue" "42501:permission denied for function approval_queue" <<SQL
$rerun
$(as_token "$T_OP2")
SELECT count(*) FROM medcea.approval_queue();
SQL
        probe W4 "an operator of another unit reads none of the run's release (RLS)" ok <<SQL
$rerun
$(as_token "$T_QP")
SELECT medcea.release_run(:run, 'rls');
$(as_postgres)
DELETE FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP2'::uuid;
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP2'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
$(as_token "$T_OP2")
SELECT count(*) AS n FROM medcea.run_release WHERE recipe_run_id = :run \gset
--CHECKS
SELECT 'CHECK|nothing (' || :n || ')', :n = 0;
SQL
        probe W4 "a production manager cannot release" "42501:permission denied for function release_run" <<SQL
$rerun
$(as_token "$T_PM2")
SELECT medcea.release_run(:run, 'not mine to release');
SQL
        recipe_setup="
$(as_token "$T_EN")
INSERT INTO medcea.recipe (recipe_name) VALUES ('IAMT approval probe') RETURNING recipe_id AS ra \\gset"
        probe W4 "control: qa approves an engineer's draft" ok <<SQL
$recipe_setup
$(as_token "$T_QA")
SELECT medcea.approve_recipe(:ra);
--CHECKS
SELECT 'CHECK|approved', status = 'approved' FROM medcea.recipe WHERE recipe_id = :ra;
SELECT 'CHECK|approval recorded', EXISTS (SELECT 1 FROM medcea.approval WHERE target = 'medcea.recipe' AND row_key = jsonb_build_array(:ra) AND action = 'approve' AND approved_by_person = 'p-qa');
SELECT 'CHECK|approval covers the newest change (commit order)', ap.last_change_id = (SELECT max(c.change_id) FROM medcea.row_change c WHERE c.target = 'medcea.recipe' AND c.row_key = jsonb_build_array(:ra) AND c.op = 'I') FROM medcea.approval ap WHERE ap.target = 'medcea.recipe' AND ap.row_key = jsonb_build_array(:ra) AND ap.action = 'approve';
SQL
        probe W4 "an intermediate editor approves" "42501:not_own_author" <<SQL
$recipe_setup
$(as_token "$T_EN2")
UPDATE medcea.recipe SET recipe_description = 'edited by a second engineer' WHERE recipe_id = :ra;
$(as_token "$T_QAEN2")
SELECT medcea.approve_recipe(:ra);
SQL
        probe W4 "an unattributed change blocks approval" "42501:unattributed changes" <<SQL
$recipe_setup
$(as_postgres)
UPDATE medcea.recipe SET recipe_description = 'edited by postgres' WHERE recipe_id = :ra;
$(as_token "$T_QA")
SELECT medcea.approve_recipe(:ra);
SQL
        # The Approve action (2026-10-31): the noted overloads, approval_queue()'s advisory
        # may_approve against the approve functions' own refusals, return and my_approvals()
        # a unit of its own, created by an engineer token (so the engineer is its only author,
        # and no run of the seed or of the runner fixture stands on it)
        new_unit="
$(as_token "$T_EN")
INSERT INTO medcea.cea_unit (unit_type, description, location_id, is_active, unit_code)
SELECT 'Mushrooms', 'iam-db commissioning probe', location_id, 'Y', 'IAMTC1' FROM medcea.cea_location
 WHERE name = 'IAMTEST site' RETURNING unit_id AS cu \\gset"
        line_by_en2="
$(as_token "$T_EN2")
INSERT INTO medcea.recipe_line (recipe_id, recipe_item_seq_id, recipe_item_seq_name, cycle_number,
    air_temperature_lower_limit, air_temperature_upper_limit, light_type, light_on_minutes, light_off_minutes,
    co2_lower_limit, co2_upper_limit, hr_lower_limit, hr_upper_limit)
VALUES (:ra, 1, 'iam-db step', 1, 18, 24, 'BLUE', 60, 60, 400, 1200, 70, 90);"
        probe W4 "control: qa approves with a note (2-argument overload)" ok <<SQL
$recipe_setup
$(as_token "$T_QA")
SELECT medcea.approve_recipe(:ra, ' iam-db note ');
--CHECKS
SELECT 'CHECK|note recorded (trimmed)', note = 'iam-db note' AND approved_by_source = 'token'
  FROM medcea.approval WHERE target = 'medcea.recipe' AND row_key = jsonb_build_array(:ra) AND action = 'approve';
SQL
        probe W4 "control: approval_queue lists an engineer's draft, may_approve for qa" ok <<SQL
$recipe_setup
$(as_token "$T_QA")
SELECT state AS st, may_approve AS ma, may_return AS mr, array_to_string(authors, ',') AS au, changes_total AS n,
       jsonb_array_length(changes) AS nc FROM medcea.approval_queue() WHERE target = 'medcea.recipe' AND id = :ra \gset
SELECT changes IS NULL AS brief FROM medcea.approval_queue(false) WHERE target = 'medcea.recipe' AND id = :ra \gset
--CHECKS
SELECT 'CHECK|waiting, may approve and return', :'st' = 'waiting' AND :'ma'::boolean AND :'mr'::boolean;
SELECT 'CHECK|authors {p-en}', :'au' = 'p-en';
SELECT 'CHECK|its changes listed (' || :n || ')', :n >= 1 AND :nc = :n;
SELECT 'CHECK|approval_queue(false) leaves the changes out', :'brief'::boolean;
SELECT 'CHECK|_authors() equals _changes_since() authors', (SELECT persons FROM medcea_auth._authors('medcea.recipe', jsonb_build_array(:ra)))
       = (SELECT coalesce(array_agg(DISTINCT actor_person) FILTER (WHERE actor_person IS NOT NULL), '{}')
            FROM medcea_auth._changes_since('medcea.recipe', jsonb_build_array(:ra)) WHERE authors);
SQL
        probe W4 "approval_queue: a line editor reads own_author, with the line in the changes" ok <<SQL
$recipe_setup
$line_by_en2
$(as_token "$T_QAEN2")
SELECT why_not_code AS wn, may_approve AS ma,
       EXISTS (SELECT 1 FROM jsonb_array_elements(changes) c WHERE c ->> 'target' = 'medcea.recipe_line' AND c ->> 'by_person' = 'p-en2') AS line
  FROM medcea.approval_queue() WHERE target = 'medcea.recipe' AND id = :ra \gset
--CHECKS
SELECT 'CHECK|own_author, not may_approve', :'wn' = 'own_author' AND NOT :'ma'::boolean;
SELECT 'CHECK|the recipe_line change is listed', :'line'::boolean;
SQL
        probe W4 "parity: the line editor approves" "42501:not_own_author" <<SQL
$recipe_setup
$line_by_en2
$(as_token "$T_QAEN2")
SELECT medcea.approve_recipe(:ra, 'parity');
SQL
        probe W4 "approval_queue: an unattributed change reads unattributed" ok <<SQL
$recipe_setup
$(as_postgres)
UPDATE medcea.recipe SET recipe_description = 'edited by postgres' WHERE recipe_id = :ra;
$(as_token "$T_QA")
SELECT why_not_code AS wn FROM medcea.approval_queue() WHERE target = 'medcea.recipe' AND id = :ra \gset
--CHECKS
SELECT 'CHECK|unattributed', :'wn' = 'unattributed';
SQL
        params_setup="
$(as_token "$T_EN")
INSERT INTO medcea.control_algorithm (algorithm_code, algorithm_name) VALUES ('IAMTDRAFT', 'iam-db draft algorithm')
RETURNING algorithm_id AS da \\gset
INSERT INTO medcea.unit_algorithm_params (algorithm_id, name, params) VALUES (:da, 'iam-db set of a draft', '{}')
RETURNING params_id AS dp \\gset"
        probe W4 "approval_queue: a parameter set of a draft algorithm reads algorithm_not_approved" ok <<SQL
$params_setup
$(as_token "$T_QA")
SELECT why_not_code AS wn FROM medcea.approval_queue() WHERE target = 'medcea.unit_algorithm_params' AND id = :dp \gset
SELECT coalesce(why_not_code, 'none') AS wa FROM medcea.approval_queue() WHERE target = 'medcea.control_algorithm' AND id = :da \gset
--CHECKS
SELECT 'CHECK|params: algorithm_not_approved', :'wn' = 'algorithm_not_approved';
SELECT 'CHECK|the algorithm itself may be approved', :'wa' = 'none';
SQL
        probe W4 "parity: approve_params on a draft algorithm" "42501:its algorithm" <<SQL
$params_setup
$(as_token "$T_QA")
SELECT medcea.approve_params(:dp, NULL);
SQL
        probe W4 "an engineer token reads no approval_queue" "42501:permission denied for function approval_queue" <<SQL
$(as_token "$T_EN")
SELECT count(*) FROM medcea.approval_queue();
SQL
        probe W4 "svc_dbexport holds EXECUTE on approval_queue, which refuses it" "42501:with your own sign-in" <<SQL
SET SESSION AUTHORIZATION svc_dbexport;
SELECT count(*) FROM medcea.approval_queue();
SQL
        probe W4 "approval_queue for qp: master_data rows only, without approval" ok <<SQL
$recipe_setup
$new_unit
SELECT medcea.propose_commissioning(:cu, true, 'iam-db: qp view') AS chg \gset
$(as_token "$T_QP")
SELECT count(*) FILTER (WHERE kind IN ('recipe', 'algorithm', 'params', 'setting')) AS other,
       count(*) FILTER (WHERE kind = 'commissioning' AND id = :chg AND why_not_code = 'no_role' AND NOT may_approve) AS comm
  FROM medcea.approval_queue() \gset
--CHECKS
SELECT 'CHECK|no recipe, controller or setting rows (' || :other || ')', :other = 0;
SELECT 'CHECK|the commissioning proposal, no_role', :comm = 1;
SQL
        # settings_clear: production's data may hold a waiting log-setting proposal of
        # another person, which propose_setting() now refuses to replace; close each
        # open one (a withdraw by its proposer, written as the owner; rolled back)
        settings_clear="
$(as_postgres)
SET ROLE medcea_owner;
INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                             approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source)
SELECT 'medcea.pending_change', jsonb_build_array(pc.change_id), 'iam-db', 'scheduler_settings', 'withdraw',
       'iam-db: cleared for the probe', array_remove(ARRAY[pc.proposed_by_person], NULL), pc.proposed_by_sub,
       pc.proposed_by_person, pc.proposed_by_name, pc.proposed_by_role, pc.proposed_by_source
  FROM medcea.pending_change pc WHERE pc.target = 'medcea.scheduler_config' AND medcea._pending_open(pc);
RESET ROLE;"
        retention_queue() {  # VALUE
            probe W4 "approval_queue: log_delete_days = $1 reads retention_minimum" ok <<SQL
$settings_clear
$(as_token "$T_AD")
SELECT medcea.propose_setting('log_delete_days', '"$1"') AS chg \gset
$(as_token "$T_QA")
SELECT why_not_code AS wn FROM medcea.approval_queue() WHERE target = 'medcea.pending_change' AND id = :chg \gset
--CHECKS
SELECT 'CHECK|retention_minimum', :'wn' = 'retention_minimum';
SQL
        }
        retention_queue 29
        retention_queue abc
        probe W4 "control: qa returns a draft with a reason; the author sees it" ok <<SQL
$recipe_setup
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.recipe', :ra, 'iam-db: fix step 1');
SELECT state AS st, return_reason AS rr FROM medcea.approval_queue() WHERE target = 'medcea.recipe' AND id = :ra \gset
$(as_token "$T_EN")
SELECT state AS mst, return_reason AS mrr FROM medcea.my_approvals() WHERE target = 'medcea.recipe' AND id = :ra \gset
UPDATE medcea.recipe SET recipe_description = 'fixed' WHERE recipe_id = :ra;
$(as_token "$T_QA")
SELECT state AS st2 FROM medcea.approval_queue() WHERE target = 'medcea.recipe' AND id = :ra \gset
--CHECKS
SELECT 'CHECK|still a draft', status = 'draft' FROM medcea.recipe WHERE recipe_id = :ra;
SELECT 'CHECK|approval action return with the reason', EXISTS (SELECT 1 FROM medcea.approval WHERE target = 'medcea.recipe'
       AND row_key = jsonb_build_array(:ra) AND action = 'return' AND note = 'iam-db: fix step 1' AND approved_by_person = 'p-qa');
SELECT 'CHECK|queue: returned', :'st' = 'returned' AND :'rr' = 'iam-db: fix step 1';
SELECT 'CHECK|my_approvals: returned with the reason', :'mst' = 'returned' AND :'mrr' = 'iam-db: fix step 1';
SELECT 'CHECK|waiting again after the edit', :'st2' = 'waiting';
SELECT 'CHECK|a return is no approval (authors unchanged)', (SELECT persons FROM medcea_auth._authors('medcea.recipe', jsonb_build_array(:ra))) = '{p-en}';
SQL
        probe W4 "a draft returned twice without a change" "22023:has not changed since" <<SQL
$recipe_setup
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.recipe', :ra, 'once');
SELECT medcea.return_change('medcea.recipe', :ra, 'twice');
SQL
        probe W4 "a return needs a reason" "22023:a reason is required" <<SQL
$recipe_setup
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.recipe', :ra, '  ');
SQL
        probe W4 "return of an approved recipe" "22023:not a draft" <<SQL
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.recipe', recipe_id, 'iam-db') FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1';
SQL
        probe W4 "return of a target return_change does not handle" "22023:is not returned by return_change()" <<SQL
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.cea_unit', 1, 'iam-db');
SQL
        # a log-setting proposal is closed only by qa or its proposer (review fix): another
        # person's proposal for the same key is refused while one waits
        probe W4 "control: an admin replaces their own waiting log-setting proposal" ok <<SQL
$settings_clear
$(as_token "$T_AD")
SELECT medcea.propose_setting('log_delete_days', '90') AS c1 \gset
SELECT medcea.propose_setting('log_delete_days', '365') AS c2 \gset
SELECT state AS st1 FROM medcea.my_approvals() WHERE id = :c1 AND kind = 'setting' \gset
--CHECKS
SELECT 'CHECK|the first reads superseded', :'st1' = 'superseded';
SELECT 'CHECK|the second waits', medcea._pending_open(pc) FROM medcea.pending_change pc WHERE change_id = :c2;
SQL
        probe W4 "another person's log-setting proposal while one waits" "22023:already waits for qa" <<SQL
$settings_clear
$(as_token "$T_AD")
SELECT medcea.propose_setting('log_delete_days', '90');
$(as_token "$(claims admin "$UUID_EN2" p-ad2)")
SELECT medcea.propose_setting('log_delete_days', '365');
SQL
        probe W4 "control: another person proposes once qa returned the waiting one" ok <<SQL
$settings_clear
$(as_token "$T_AD")
SELECT medcea.propose_setting('log_delete_days', '90') AS c1 \gset
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.pending_change', :c1, 'iam-db: not now');
$(as_token "$(claims admin "$UUID_EN2" p-ad2)")
SELECT medcea.propose_setting('log_delete_days', '365');
SQL
        probe W4 "a log-setting proposal from a token without person_id" "42501:carries no person_id" <<SQL
$(as_token "$(claims admin "$UUID_AD" p-ad | sed 's/"person_id":"p-ad",//')")
SELECT medcea.propose_setting('log_delete_days', '90');
SQL
        probe W4 "an engineer cannot return" "42501:permission denied for function return_change" <<SQL
$recipe_setup
$(as_token "$T_EN")
SELECT medcea.return_change('medcea.recipe', :ra, 'x');
SQL
        probe W4 "an engineer edits an approved recipe" "42501:draft_only" <<SQL
$(as_token "$T_EN")
UPDATE medcea.recipe SET recipe_description = 'x' WHERE recipe_name = 'IAMTEST-R1';
SQL
        probe W4 "a production manager edits a recipe (assign_only)" "42501:permission denied" <<SQL
$(as_token "$T_PM")
UPDATE medcea.recipe SET recipe_description = 'x' WHERE recipe_name = 'IAMTEST-R1';
SQL
        # The Config UI's Retire (it replaced Delete: nobody holds DELETE on recipes) and
        # its parameter-set editor, as the page sends them through PostgREST
        probe W4 "control: an engineer retires an approved recipe (status alone, Config UI Retire…)" ok <<SQL
$recipe_setup
$(as_token "$T_QA")
SELECT medcea.approve_recipe(:ra);
$(as_token "$T_EN")
UPDATE medcea.recipe SET status = 'retired' WHERE recipe_id = :ra;
--CHECKS
SELECT 'CHECK|retired', status = 'retired' FROM medcea.recipe WHERE recipe_id = :ra;
SELECT 'CHECK|retiring makes nobody an author', (medcea_auth._authors('medcea.recipe', jsonb_build_array(:ra))).persons = '{}';
SQL
        # under true the draft_only guard (iam_*, it fires before status_guard_trg) refuses first
        probe W4 "a retired recipe stays retired" "42501:is retired, not a draft" <<SQL
$recipe_setup
$(as_token "$T_EN")
UPDATE medcea.recipe SET status = 'retired' WHERE recipe_id = :ra;
UPDATE medcea.recipe SET status = 'draft' WHERE recipe_id = :ra;
SQL
        probe W4 "control: an engineer creates and edits a draft parameter set (Config UI editor)" ok <<SQL
$(as_token "$T_EN")
INSERT INTO medcea.unit_algorithm_params (name, algorithm_id, unit_id, params)
SELECT 'IAMT ui params', algorithm_id, NULL, '{"kp": 1}' FROM medcea.control_algorithm WHERE status = 'approved'
 ORDER BY algorithm_id LIMIT 1 RETURNING params_id AS pu \\gset
UPDATE medcea.unit_algorithm_params SET params = '{"kp": 2}' WHERE params_id = :pu;
--CHECKS
SELECT 'CHECK|a draft', status = 'draft' FROM medcea.unit_algorithm_params WHERE params_id = :pu;
SELECT 'CHECK|the edit is the engineer''s', (medcea_auth._authors('medcea.unit_algorithm_params', jsonb_build_array(:pu))).persons = '{p-en}';
SQL
        probe W4 "an engineer edits an approved parameter set" "42501:draft_only" <<SQL
$(as_token "$T_EN")
INSERT INTO medcea.unit_algorithm_params (name, algorithm_id, unit_id, params)
SELECT 'IAMT ui params', algorithm_id, NULL, '{"kp": 1}' FROM medcea.control_algorithm WHERE status = 'approved'
 ORDER BY algorithm_id LIMIT 1 RETURNING params_id AS pu \\gset
$(as_token "$T_QA")
SELECT medcea.approve_params(:pu, 'iam-db');
$(as_token "$T_EN")
UPDATE medcea.unit_algorithm_params SET params = '{"kp": 3}' WHERE params_id = :pu;
SQL
        probe W4 "control: svc_scheduler writes a new Q-table state" ok <<SQL
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{"q": 1}' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SET ROLE medcea_owner;
UPDATE medcea.algorithm_state SET retired_at = now() WHERE channel = 'iamt';
RESET ROLE;
SET SESSION AUTHORIZATION svc_scheduler;
UPDATE medcea.algorithm_state SET state = '{"q": 2}', updated_at = now() WHERE channel = 'iamt';
--CHECKS
SELECT 'CHECK|unretired by the new state', retired_at IS NULL FROM medcea.algorithm_state WHERE channel = 'iamt';
SELECT 'CHECK|logged unretired', EXISTS (SELECT 1 FROM medcea.algorithm_state_event WHERE channel = 'iamt' AND event = 'unretired');
SQL
        probe W4 "svc_scheduler clears retired_at alone" "42501:only the scheduler's state writes" <<SQL
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{"q": 1}' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SET ROLE medcea_owner;
UPDATE medcea.algorithm_state SET retired_at = now() WHERE channel = 'iamt';
RESET ROLE;
SET SESSION AUTHORIZATION svc_scheduler;
UPDATE medcea.algorithm_state SET retired_at = NULL WHERE channel = 'iamt';
SQL
        # IAM 2.6: a Q-table is retired only through PostgREST by qa (the scheduler's
        # DELETE routes are gone)
        qstate="
INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state)
SELECT unit_id, 'Q_LEARNING', 'iamt', '{\"q\": 1}' FROM medcea.cea_unit WHERE unit_code = 'IAMT01';"
        probe W4 "control: qa retires a Q-table through PostgREST" ok <<SQL
$qstate
$(as_token "$T_QA")
SELECT medcea.retire_algorithm_state(unit_id, 'Q_LEARNING', 'iam-db probe') FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
--CHECKS
SELECT 'CHECK|retired, not deleted', retired_at IS NOT NULL FROM medcea.algorithm_state WHERE channel = 'iamt';
SELECT 'CHECK|retired event with the reason', EXISTS (SELECT 1 FROM medcea.algorithm_state_event WHERE channel = 'iamt' AND event = 'retired' AND reason = 'iam-db probe');
SELECT 'CHECK|approval by a token', EXISTS (SELECT 1 FROM medcea.approval WHERE target = 'medcea.algorithm_state' AND action = 'retire' AND row_key ->> 2 = 'iamt' AND approved_by_source = 'token');
SQL
        probe W4 "an engineer token cannot retire a Q-table" "42501:permission denied" <<SQL
$qstate
$(as_token "$T_EN")
SELECT medcea.retire_algorithm_state(unit_id, 'Q_LEARNING', 'iam-db probe') FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SQL
        probe W4 "svc_scheduler cannot retire a Q-table (no EXECUTE; set_actor is no token)" "42501:permission denied" <<SQL
$qstate
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea.retire_algorithm_state(unit_id, 'Q_LEARNING', 'iam-db probe') FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SQL
        retention() {  # VALUE EXPECT
            probe W4 "approve_change: log_delete_days = $1" "$2" <<SQL
$settings_clear
$(as_token "$T_AD")
SELECT medcea.propose_setting('log_delete_days', '"$1"') AS chg \gset
$(as_token "$T_QA")
SELECT medcea.approve_change('medcea.pending_change', :chg, 'iam-db probe');
SQL
        }
        retention 30 ok
        retention 29 "42501:retention"
        # RLS (own_unit): every compiled reader of the four RLS tables sees every row;
        # only rr_operator is filtered, to the units in iam_policy.user_unit.
        # run_full: a run of IAMT01 with a cycle and a release, so no RLS table is empty
        # (an empty table passes every count check whatever the policy says)
        run_full="
SELECT recipe_id AS r1 FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1' \\gset
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
$(as_postgres)
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_system_actor('system:scheduler', 'run', :run);
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'R', 'run_params', '[{\"x\": 1}]'::jsonb));
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'C', 'end', now()));
SELECT medcea.finish_run(:run, 'C');
$(as_postgres)
DELETE FROM pg_temp.medcea_actor WHERE kind = 'actor';
$(as_token "$T_QP")
SELECT medcea.release_run(:run);
$(as_postgres)"
        for obj in medcea.measurement medcea.recipe_run medcea.recipe_line_cycle_run medcea.run_release; do
            for r in $(python3 "$CLI" "${SRC[@]}" compile grants --format json "${IAM_FLAG[@]}" | OBJ="$obj" python3 -c '
import json, os, sys
d = json.load(sys.stdin)
print(" ".join(sorted({g for g, k, o, p in d["privileges"] if o == os.environ["OBJ"] and p == "SELECT"})))'); do
                [[ "$r" == rr_operator ]] && continue
                probe RLS "$r sees every row of $obj" ok <<SQL
$run_full
SELECT count(*) AS total FROM $obj \gset
SET ROLE $r;
SELECT count(*) AS seen FROM $obj \gset
--CHECKS
SELECT 'CHECK|unfiltered (' || :seen || ' of ' || :total || ')', :seen = :total AND :total > 0;
SQL
            done
        done
        probe RLS "rr_operator sees only its units' telemetry" ok <<SQL
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
SELECT count(*) AS total, count(*) FILTER (WHERE zone_id IN (SELECT z.zone_id FROM medcea.cea_zone z JOIN medcea.cea_unit u USING (unit_id)
       WHERE u.unit_code = 'IAMT02')) AS mine FROM medcea.measurement \gset
$(as_token "$T_OP")
SELECT count(*) AS seen FROM medcea.measurement \gset
--CHECKS
SELECT 'CHECK|filtered (' || :seen || ' of ' || :total || ')', :seen = :mine AND :seen < :total;
SQL
        probe RLS "a zone added to an assigned unit is visible" ok <<SQL
SELECT medcea_auth._set_internal_actor('system:iam-db') \g /dev/null
INSERT INTO medcea.cea_zone (unit_id, zone_code, is_active) SELECT unit_id, 'ZNEW', 'Y' FROM medcea.cea_unit
 WHERE unit_code = 'IAMT02' RETURNING zone_id AS newz \gset
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
-- the internal actor that created the zone outranks the token's claims for this transaction
DELETE FROM pg_temp.medcea_actor WHERE kind = 'actor';
$(as_token "$T_OP")
SELECT :newz = ANY (medcea_auth.my_zones()) AS sees \gset
--CHECKS
SELECT 'CHECK|my_zones() has the new zone', :'sees'::boolean;
SQL
        # cross-unit: the second operator holds IAMT02, so my_units() is not empty and
        # only the policy expressions keep IAMT01's run, cycles and release from them
        probe RLS "rr_operator sees only its units' runs" ok <<SQL
$run_full
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP2'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
$(as_token "$T_OP")
SELECT (SELECT count(*) FROM medcea.recipe_run WHERE recipe_run_id = :run) AS own_run,
       (SELECT count(*) FROM medcea.recipe_line_cycle_run WHERE recipe_run_id = :run) AS own_cyc,
       (SELECT count(*) FROM medcea.run_release WHERE recipe_run_id = :run) AS own_rel,
       (SELECT count(*) FROM medcea.run_history WHERE recipe_run_id = :run) AS own_hist \gset
$(as_token "$T_OP2")
SELECT (SELECT count(*) FROM medcea.recipe_run WHERE recipe_run_id = :run) AS o_run,
       (SELECT count(*) FROM medcea.recipe_line_cycle_run WHERE recipe_run_id = :run) AS o_cyc,
       (SELECT count(*) FROM medcea.run_release WHERE recipe_run_id = :run) AS o_rel,
       (SELECT count(*) FROM medcea.run_history WHERE recipe_run_id = :run) AS o_hist,
       medcea_auth.my_units() <> '{}' AS o_has_unit \gset
$(as_token "$T_PM")
SELECT count(*) AS pm FROM medcea.recipe_run WHERE recipe_run_id = :run \gset
--CHECKS
SELECT 'CHECK|the operator of IAMT01 sees its run, cycles, release and history (' || :own_run || '/' || :own_cyc || '/' || :own_rel || '/' || :own_hist || ')',
       :own_run = 1 AND :own_cyc > 0 AND :own_rel = 1 AND :own_hist > 0;
SELECT 'CHECK|the second operator holds a unit', :'o_has_unit'::boolean;
SELECT 'CHECK|the operator of IAMT02 sees none of them (' || :o_run || '/' || :o_cyc || '/' || :o_rel || '/' || :o_hist || ')',
       :o_run = 0 AND :o_cyc = 0 AND :o_rel = 0 AND :o_hist = 0;
SELECT 'CHECK|the production manager sees it', :pm = 1;
SQL
        # IAM 2.6: the Monitor's and the scheduler's own_unit SQL (svc_* read through
        # permissive policies, so the services filter with a subquery on user_unit) returns
        # exactly what rr_operator's RLS returns: runs, cycles, and the measurements of the
        # unit's zones by their current unit (the seed's board moved IAMT01/Z01 -> IAMT02/Z01)
        own_runs="(SELECT uu.unit_id FROM iam_policy.user_unit uu WHERE uu.person_sub = '$UUID_OP'::uuid)"
        own_zones="(SELECT cz.zone_id FROM medcea.cea_zone cz JOIN iam_policy.user_unit uu ON uu.unit_id = cz.unit_id WHERE uu.person_sub = '$UUID_OP'::uuid)"
        rows_digest() {  # VAR FROM-AND-WHERE: \gset VAR to the sha256 of the sorted rows / their count (md5() is unsupported in production's image)
            echo "SELECT encode(sha256(convert_to(coalesce(string_agg(x, ',' ORDER BY x), ''), 'UTF8')), 'hex') || '/' || count(*) AS $1 FROM (SELECT encode(sha256(convert_to(t::text, 'UTF8')), 'hex') AS x FROM $2) s \\gset"
        }
        # the scheduler's run reads LEFT JOIN run_release for the Released badge (2026-10-31):
        # with a released run, the joined rows equal what rr_operator reads of both tables
        rel_cols="(SELECT r.recipe_run_id, rl.released_by_name, rl.released_at FROM medcea.recipe_run r LEFT JOIN medcea.run_release rl ON rl.recipe_run_id = r.recipe_run_id"
        probe RLS "the services' own_unit SQL returns what rr_operator's RLS returns" ok <<SQL
$run_full
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
INSERT INTO medcea.run_release (recipe_run_id, row_hash, released_by_sub, released_by_person, released_by_name, released_by_role)
SELECT x.recipe_run_id, 'iam-db', '$UUID_QP', 'p-qp', 'iam-db qp', 'qp' FROM medcea.recipe_run x
  JOIN medcea.cea_unit u ON u.unit_id = x.unit_id AND u.unit_code = 'IAMT02'
 WHERE NOT EXISTS (SELECT 1 FROM medcea.run_release y WHERE y.recipe_run_id = x.recipe_run_id) ORDER BY x.recipe_run_id LIMIT 1;
SET SESSION AUTHORIZATION svc_monitor;
$(rows_digest s_run "medcea.recipe_run t WHERE t.unit_id IN $own_runs")
$(rows_digest s_meas "medcea.measurement t WHERE t.zone_id IN $own_zones")
$(as_postgres)
SET SESSION AUTHORIZATION svc_scheduler;
$(rows_digest s_cyc "medcea.recipe_line_cycle_run t WHERE t.recipe_run_id IN (SELECT x.recipe_run_id FROM medcea.recipe_run x WHERE x.unit_id IN $own_runs)")
$(rows_digest s_rel "$rel_cols WHERE r.unit_id IN $own_runs) t")
$(as_token "$T_OP")
$(rows_digest o_run "medcea.recipe_run t")
$(rows_digest o_meas "medcea.measurement t")
$(rows_digest o_cyc "medcea.recipe_line_cycle_run t")
$(rows_digest o_rel "$rel_cols) t")
SELECT count(*) AS o_reln FROM medcea.run_release \gset
--CHECKS
SELECT 'CHECK|the operator reads the release of their unit''s run', :o_reln >= 1;
SELECT 'CHECK|runs with their release (' || :'s_rel' || ')', :'s_rel' = :'o_rel' AND :'s_rel' NOT LIKE '%/0';
SELECT 'CHECK|runs (' || :'s_run' || ')', :'s_run' = :'o_run' AND :'s_run' NOT LIKE '%/0';
SELECT 'CHECK|measurements (' || :'s_meas' || ')', :'s_meas' = :'o_meas' AND :'s_meas' NOT LIKE '%/0';
SELECT 'CHECK|cycles (' || :'s_cyc' || ')', :'s_cyc' = :'o_cyc' AND :'s_cyc' NOT LIKE '%/0';
SQL
        # start_run/set_run_status are SECURITY DEFINER (past the RLS): a run of another
        # unit and a run that does not exist get the same refusal, before any status check
        hidden="
$run_full
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP2'::uuid, unit_id FROM medcea.cea_unit WHERE unit_code = 'IAMT02';
$(as_token "$T_OP2")"
        probe W4 "start_run on another unit's completed run says only 'not one of your units'" "42501:not one of your units" <<SQL
$hidden
SELECT medcea.start_run(:run);
SQL
        probe W4 "set_run_status on another unit's run says only 'not one of your units'" "42501:not one of your units" <<SQL
$hidden
SELECT medcea.set_run_status(:run, 'X');
SQL
        probe W4 "start_run on a run that does not exist says the same" "42501:not one of your units" <<SQL
$hidden
SELECT medcea.start_run(2147483000);
SQL
        probe W4 "set_run_status on a run that does not exist says the same" "42501:not one of your units" <<SQL
$hidden
SELECT medcea.set_run_status(2147483000, 'F');
SQL
    fi

    # W5: register_mqtt_credential v2 (as an engineer's role; every refusal structural)
    if [[ "$MODE" != legacy ]]; then
        reg() {  # NAME EXPECT DEVICE_DNS SERIAL [HASH]
            local h="${5:-\$7\$101\$c2FsdA==\$aGFzaA==}"
            probe W5 "$1" "$2" <<SQL
SET ROLE rr_engineer;
SELECT medcea.register_mqtt_credential((SELECT device_id FROM medcea.device WHERE dns_name = '$3'), '$4', '$h');
SQL
        }
        reg "control: the board's own serial" ok iamt02-s-z01 iamt-aa:bb:cc:00:00:01
        reg "another board's serial" "42501:is not device" iamt02-s-z01 iamt-aa:bb:cc:00:00:02
        probe W5 "a unit code that is not a topic segment" "22023:cannot be a topic segment" <<SQL
INSERT INTO medcea.device (zone_id, device_type, serial_number, dns_name, is_active)
SELECT z.zone_id, 'SENSE', 'iamt-wild', 'iamt-wild', 'Y' FROM medcea.cea_zone z JOIN medcea.cea_unit u USING (unit_id) WHERE u.unit_code = 'IAM+04';
SET ROLE rr_engineer;
SELECT medcea.register_mqtt_credential((SELECT device_id FROM medcea.device WHERE dns_name = 'iamt-wild'), 'iamt-wild', '\$7\$101\$c2FsdA==\$aGFzaA==');
SQL
        reg "a password instead of a hash" "22023:mosquitto" iamt02-s-z01 iamt-aa:bb:cc:00:00:01 not-a-hash
    fi
    # W6: the scheduler's functions and fixes (IAM plan 2.4): retire_schedule and the
    # retired-row guard, set_system_actor's re-save fallback, record_cycle never
    # reopening a completed cycle, the schedule's algorithm in _check_run_params, the
    # internal actor out of a service's reach; and (false) the SQL of the scheduler
    # before 2.4 (e97aab6) still working against this database
    if [[ "$MODE" != legacy ]]; then
        S1="(SELECT schedule_id FROM medcea.schedule WHERE description LIKE 'iamtest: inherits the assignment%')"
        S2="(SELECT schedule_id FROM medcea.schedule WHERE description = 'iamtest: algorithm differs from the assignment')"
        UNVERIFIED="SELECT medcea_auth._set_internal_actor('system:scheduler-unverified');"
        PM_ACTOR="SELECT medcea_auth.set_actor('$UUID_PM', 'p-pm', 'test-pm', 'production_manager');"
        W6_PM="$(claims production_manager "$UUID_PM" p-pm)"
        # who retires in the probes below: retire_schedule checks U on schedules, which
        # an internal actor (no role) passes only as a WARNING while false
        if [[ "$MODE" == true ]]; then RETIRER="$PM_ACTOR"; RETIRER_SUB="$UUID_PM"
        else RETIRER="$UNVERIFIED"; RETIRER_SUB="system:scheduler-unverified"; fi
        probe W6 "retire_schedule without an actor" "42501:no actor" <<SQL
SELECT medcea.retire_schedule($S1);
SQL
        probe W6 "control: retire_schedule keeps the schedule, disabled" ok <<SQL
$RETIRER
SELECT medcea.retire_schedule($S1);
--CHECKS
SELECT 'CHECK|retired and disabled', retired_at IS NOT NULL AND NOT enabled FROM medcea.schedule WHERE schedule_id = $S1;
SELECT 'CHECK|logged as the actor', EXISTS (SELECT 1 FROM medcea.row_change WHERE target = 'medcea.schedule'
       AND row_key = jsonb_build_array($S1) AND actor_sub = '$RETIRER_SUB' AND new_values ? 'enabled');
SQL
        probe W6 "retire_schedule twice" "22023:already retired" <<SQL
$RETIRER
SELECT medcea.retire_schedule($S1);
SELECT medcea.retire_schedule($S1);
SQL
        probe W6 "retire_schedule of a missing schedule" "22023:no schedule" <<SQL
$RETIRER
SELECT medcea.retire_schedule(-1);
SQL
        # retire_schedule checks the actor's role: an operator holds R on schedules only
        if [[ "$MODE" == true ]]; then
            probe W6 "an operator retires a schedule (U on schedules)" "42501:holds no U on schedules" <<SQL
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_actor('$UUID_OP', 'p-op', 'test-op', 'operator');
SELECT medcea.retire_schedule($S1);
SQL
        else
            probe W6 "an operator retires a schedule: a WARNING while false" ok <<SQL
SELECT medcea_auth.set_actor('$UUID_OP', 'p-op', 'test-op', 'operator');
SELECT medcea.retire_schedule($S1);
--CHECKS
SELECT 'CHECK|retired (advisory refusal only)', retired_at IS NOT NULL FROM medcea.schedule WHERE schedule_id = $S1;
SQL
        fi
        if [[ "$MODE" == true ]]; then
            probe W6 "svc_scheduler edits a retired schedule (T6)" "42501:is retired" <<SQL
$RETIRER
SELECT medcea.retire_schedule($S1);
SET SESSION AUTHORIZATION svc_scheduler;
$PM_ACTOR
UPDATE medcea.schedule SET enabled = true WHERE schedule_id = $S1;
SQL
        else
            probe W6 "postgres edits a retired schedule (T6)" "42501:is retired" <<SQL
$UNVERIFIED
SELECT medcea.retire_schedule($S1);
UPDATE medcea.schedule SET enabled = true WHERE schedule_id = $S1;
SQL
        fi
        probe W6 "set_system_actor: a migration:008 schedule nobody re-saved" "42501:no person-attributed creator" <<SQL
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', $S1);
SQL
        probe W6 "control: re-saved by a production manager, it fires as that person" ok <<SQL
$PM_ACTOR
UPDATE medcea.schedule SET description = description || ' (re-saved)' WHERE schedule_id = $S1;
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', $S1);
--CHECKS
SELECT 'CHECK|acts as the re-saving production manager', a.person = 'p-pm' AND a.role = 'production_manager' AND a.source = 'system'
  FROM medcea_auth.request_actor() a;
SQL
        probe W6 "re-saved by a role without C on runs (S6)" "42501:no person-attributed creator" <<SQL
SELECT medcea_auth.set_actor('$UUID_OP', 'p-op', 'test-op', 'operator');
UPDATE medcea.schedule SET description = description || ' (re-saved)' WHERE schedule_id = $S1;
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', $S1);
SQL
        probe W6 "re-saved by a system actor carrying a person (S6)" "42501:no person-attributed creator" <<SQL
$PM_ACTOR
INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
SELECT u.unit_id, r.recipe_id, '0 4 * * *', 'iamtest: W6 pm schedule' FROM medcea.cea_unit u, medcea.recipe r
 WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS spm \gset
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', :spm);
UPDATE medcea.schedule SET description = description || ' (re-saved)' WHERE schedule_id = $S1;
SELECT medcea_auth.set_system_actor('system:scheduler', 'schedule', $S1);
SQL
        probe W6 "a service sets the IAM_DB_ROLES setting, then the internal actor (S8)" "42501:permission denied" <<'SQL'
SET SESSION AUTHORIZATION svc_scheduler;
SET medcea.iam_db_roles = 'false';
SELECT medcea_auth._set_internal_actor('system:scheduler');
SQL
        # a run in R on IAMT01 for the cycle probes: false as postgres with the
        # unverified actor; true created by a production manager's token and run by
        # svc_scheduler acting for it
        if [[ "$MODE" == true ]]; then
            cyc_setup="
SELECT p.params_id AS set1 FROM medcea.recipe_unit_permission p JOIN medcea.recipe r USING (recipe_id) JOIN medcea.cea_unit u USING (unit_id)
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' \\gset
$(as_token "$W6_PM")
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :set1 FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' RETURNING recipe_run_id AS run \\gset
SELECT medcea.start_run(:run);
$(as_postgres)
SET SESSION AUTHORIZATION svc_scheduler;
SELECT medcea_auth.set_system_actor('system:scheduler', 'run', :run);"
        else
            cyc_setup="
$UNVERIFIED
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y' FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT01' RETURNING recipe_run_id AS run \\gset
SELECT medcea.start_run(:run);"
        fi
        cyc="SELECT recipe_id AS r1 FROM medcea.recipe WHERE recipe_name = 'IAMTEST-R1' \\gset
$cyc_setup
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'R', 'run_params', '[{\"x\": 1}]'::jsonb));
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'C', 'end', now()));"
        probe W6 "control: a cycle recorded R, then C" ok <<SQL
$cyc
--CHECKS
SELECT 'CHECK|completed, run_params a list', recipe_line_cycle_run_status = 'C' AND json_typeof(run_params) = 'array'
  FROM medcea.recipe_line_cycle_run WHERE recipe_run_id = :run;
SQL
        probe W6 "a completed cycle is not reopened (S7)" "22023:is complete" <<SQL
$cyc
SELECT medcea.record_cycle(:run, jsonb_build_object('recipe_id', :r1, 'recipe_item_seq_id', 1, 'recipe_item_seq_cycle_num', 1, 'status', 'R'));
SQL
        # B1: a run triggered by a schedule runs the schedule's algorithm (S2: FLC, while
        # its assignment says PID); the same set on a run without the schedule is refused
        if [[ "$MODE" == true ]]; then b1_writer="$(as_token "$W6_PM")"; else b1_writer="$UNVERIFIED"; fi
        b1="SELECT params_id AS s2set FROM medcea.schedule WHERE schedule_id = $S2 \\gset
SELECT $S2 AS s2 \\gset
$b1_writer"
        probe W6 "control: a schedule's run with the schedule's parameter set starts (B1)" ok <<SQL
$b1
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id, schedule_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :s2set, :s2 FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT02' RETURNING recipe_run_id AS run \gset
SELECT medcea.start_run(:run);
--CHECKS
SELECT 'CHECK|running', recipe_run_status = 'R' FROM medcea.recipe_run WHERE recipe_run_id = :run;
SQL
        probe W6 "the schedule's set on a run without the schedule (B1)" "22023:is for algorithm" <<SQL
$b1
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active, params_id)
SELECT r.recipe_id, u.unit_id, now(), 'S', 'Y', :s2set FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT02' RETURNING recipe_run_id AS run \gset
SELECT medcea.start_run(:run);
SQL
        if [[ "$MODE" == false ]]; then
            # T1: what the scheduler of e97aab6 sends, as postgres without an actor
            probe W6 "legacy scheduler (e97aab6): schedule PUT with inline parameters" ok <<SQL
UPDATE medcea.schedule
SET unit_id=unit_id, recipe_id=recipe_id, cron_expression='0 5 * * *', enabled=true, description=description,
    algorithm_id=NULL, algorithm_params='{"x": 2}'::jsonb, timestamp_upd=CURRENT_TIMESTAMP
WHERE schedule_id=$S1;
--CHECKS
SELECT 'CHECK|stamped db:postgres', updated_by_sub = 'db:postgres' FROM medcea.schedule WHERE schedule_id = $S1;
SQL
            # B4: the deploy-time listing uses set_system_actor()'s predicate, so a
            # schedule written without an actor (db:postgres) is listed, and one
            # re-saved by a production manager's token is not (rolled back)
            b4_sql="$(awk '/^-- ── B4 \(listing\)/,/^END \$\$;/' "$REPO_ROOT/apps/database/medcea_db_migrations.sql")"
            b4_out="$({
                echo "BEGIN;"
                echo "INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
                      SELECT u.unit_id, r.recipe_id, '0 6 * * *', 'iamtest: B4 db:postgres' FROM medcea.cea_unit u, medcea.recipe r
                       WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS sb4 \\gset"
                echo "$PM_ACTOR"
                echo "INSERT INTO medcea.schedule (unit_id, recipe_id, cron_expression, description)
                      SELECT u.unit_id, r.recipe_id, '0 7 * * *', 'iamtest: B4 by a person' FROM medcea.cea_unit u, medcea.recipe r
                       WHERE u.unit_code = 'IAMT01' AND r.recipe_name = 'IAMTEST-R1' RETURNING schedule_id AS spm4 \\gset"
                echo "$b4_sql"
                echo "SELECT 'B4IDS|' || :sb4 || '|' || :spm4;"
                echo "ROLLBACK;"
            } | db rw)"
            IFS='|' read -r _ b4_db b4_pm <<<"$(grep -m1 '^B4IDS|' <<<"$b4_out")"
            b4_warn="$(grep -m1 'schedules with no person behind them' <<<"$b4_out")"
            if [[ -z "$b4_db" || -z "$b4_sql" ]]; then
                fail W6 "B4 listing: setup failed: $(grep -m1 ERROR <<<"$b4_out")"
            elif [[ "$b4_warn" == *"$b4_db (db:postgres)"* && "$b4_warn" != *"$b4_pm ("* ]]; then
                pass W6 "B4 listing names a db:postgres schedule, not a person's"
            else
                fail W6 "B4 listing: want $b4_db (db:postgres) and not $b4_pm in: ${b4_warn:-no warning}"
            fi
            # T6 survives a revert: the migration file before 2.4 re-creates
            # guard_control_columns() (without the check) on every deploy
            prev_guard="$(git -C "$REPO_ROOT" show e97aab6:apps/database/medcea_db_migrations.sql 2>/dev/null \
              | awk '/^CREATE OR REPLACE FUNCTION medcea.guard_control_columns\(\)/,/^END \$\$;/')"
            if [[ "$prev_guard" != *"END \$\$;"* ]]; then
                fail W6 "retired-row guard after a revert: e97aab6's guard_control_columns() not found in git"
            else
                probe W6 "retired-row guard after e97aab6's guard_control_columns()" "42501:is retired" <<SQL
$prev_guard
$UNVERIFIED
SELECT medcea.retire_schedule($S1);
UPDATE medcea.schedule SET enabled = true WHERE schedule_id = $S1;
SQL
            fi
            probe W6 "legacy scheduler (e97aab6): PUT on a schedule retired since" "42501:is retired" <<SQL
$UNVERIFIED
SELECT medcea.retire_schedule($S1);
UPDATE medcea.schedule
SET unit_id=unit_id, recipe_id=recipe_id, cron_expression='0 5 * * *', enabled=true, description=description,
    algorithm_id=NULL, algorithm_params=NULL, timestamp_upd=CURRENT_TIMESTAMP
WHERE schedule_id=$S1;
SQL
            probe W6 "legacy scheduler (e97aab6): run, stop (F) and startup recovery" ok <<'SQL'
INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active)
SELECT r.recipe_id, u.unit_id, CURRENT_TIMESTAMP, 'S', 'Y' FROM medcea.recipe r, medcea.cea_unit u
 WHERE r.recipe_name = 'IAMTEST-R1' AND u.unit_code = 'IAMT02' RETURNING recipe_run_id AS run \gset
UPDATE medcea.recipe_run SET recipe_run_status = 'R', timestamp_upd = now() WHERE recipe_run_id = :run;
UPDATE medcea.recipe_run SET recipe_run_status = 'F', timestamp_upd = now() WHERE recipe_run_id = :run;
UPDATE medcea.recipe_run SET recipe_run_end = CURRENT_TIMESTAMP WHERE recipe_run_id = :run;
UPDATE medcea.recipe_run SET recipe_run_status='S', recipe_run_end=NULL, timestamp_upd=CURRENT_TIMESTAMP WHERE recipe_run_id=:run;
UPDATE medcea.recipe_run SET recipe_run_status='F', recipe_run_end=CURRENT_TIMESTAMP, timestamp_upd=CURRENT_TIMESTAMP
 WHERE recipe_run_id=:run AND recipe_run_status IN ('R','S');
--CHECKS
SELECT 'CHECK|failed, never executed by anyone', recipe_run_status = 'F' AND executed_by_sub IS NULL FROM medcea.recipe_run WHERE recipe_run_id = :run;
SQL
        fi
    fi
    # W7: unit assignments (IAM 2.8): apps/iam/units.sql as apps/iam/units.sh runs it
    # (as postgres, one transaction): assign waits for qa (iam.confirm_decision inserts the
    # row, access section D8), --bootstrap and remove write iam_policy.user_unit, and no
    # person may write it directly
    if [[ "$MODE" != legacy ]]; then
        UNITS_SQL="$(cat "$REPO_ROOT/apps/iam/units.sql")"
        units_vars() {  # ASSIGN [BOOTSTRAP]
            cat <<SQL
SELECT unit_id AS uid FROM medcea.cea_unit WHERE unit_code = 'IAMT01' \gset
\set assign $1
\set bootstrap ${2:-false}
\set sub '$UUID_OP'
\set username test-op
\set person p-op
\set units :uid
\set reason 'iam-db probe'
\set by_sub '$UUID_AD'
\set by_person p-ad
\set by_name test-ad
SQL
        }
        probe W7 "an operator cannot write user_unit" "42501:permission denied" <<SQL
$(as_token "$(claims operator "$UUID_OP" p-op)")
INSERT INTO iam_policy.user_unit (person_sub, unit_id) SELECT '$UUID_OP'::uuid, 1;
SQL
        probe W7 "units.sql assign: decision pending_qa, not in effect, no chain event; a re-run writes nothing" ok <<SQL
$(units_vars true)
$UNITS_SQL
$UNITS_SQL
--CHECKS
SELECT 'CHECK|not assigned (waits for qa)', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP' AND unit_id = :uid);
SELECT 'CHECK|one pending_qa unit_assign by system:deploy (by the --by person, IAM 2.7)', count(*) = 1
          AND bool_and(widens AND status = 'pending_qa' AND made_by_name = 'system:deploy (by test-ad)'
                       AND made_by_sub = '$UUID_AD' AND made_by_person = 'p-ad'
                       AND unit_id = :uid AND subject_person = 'p-op' AND checked_at IS NULL)
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_assign';
SELECT 'CHECK|no unit_assigned event', NOT EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'unit_assigned' AND payload ->> 'person_sub' = '$UUID_OP');
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W7 "units.sql assign --bootstrap: in effect, decision pending_qa, chain event; a re-run writes nothing" ok <<SQL
$(units_vars true true)
$UNITS_SQL
$UNITS_SQL
--CHECKS
SELECT 'CHECK|assigned', EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP' AND unit_id = :uid);
SELECT 'CHECK|one pending_qa unit_assign by system:deploy (bootstrap, by the --by person)', count(*) = 1
          AND bool_and(widens AND status = 'pending_qa' AND made_by_name = 'system:deploy (bootstrap, by test-ad)'
                       AND made_by_sub = '$UUID_AD' AND made_by_person = 'p-ad'
                       AND unit_id = :uid AND subject_person = 'p-op' AND checked_at IS NULL)
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_assign';
SELECT 'CHECK|latest chain event unit_assigned by system:deploy', event = 'unit_assigned' AND actor_name = 'system:deploy'
          AND payload ->> 'person_sub' = '$UUID_OP'
  FROM iam_policy.history ORDER BY event_id DESC LIMIT 1;
SELECT 'CHECK|one unit_assigned event', count(*) = 1 FROM iam_policy.history
 WHERE event = 'unit_assigned' AND payload ->> 'person_sub' = '$UUID_OP';
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W7 "units.sql assign --bootstrap while an assignment waits: nothing written" ok <<SQL
$(units_vars true)
$UNITS_SQL
\set bootstrap true
$UNITS_SQL
--CHECKS
SELECT 'CHECK|not assigned', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP' AND unit_id = :uid);
SELECT 'CHECK|still one unit_assign, not a bootstrap one', count(*) = 1 AND bool_and(made_by_name = 'system:deploy (by test-ad)')
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_assign';
SQL
        probe W7 "units.sql remove: applied at once; a second remove writes nothing" ok <<SQL
$(units_vars true true)
$UNITS_SQL
\set assign false
\set bootstrap false
$UNITS_SQL
$UNITS_SQL
--CHECKS
SELECT 'CHECK|removed', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$UUID_OP' AND unit_id = :uid);
SELECT 'CHECK|one applied unit_remove', count(*) = 1 AND bool_and(NOT widens AND status = 'applied' AND unit_id = :uid)
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_remove';
SELECT 'CHECK|one unit_removed event', count(*) = 1 FROM iam_policy.history
 WHERE event = 'unit_removed' AND payload ->> 'person_sub' = '$UUID_OP';
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W7 "units.sql remove of a waiting assignment: withdrawn and chained; a second remove writes nothing" ok <<SQL
$(units_vars true)
$UNITS_SQL
\set assign false
$UNITS_SQL
$UNITS_SQL
DO \$\$ BEGIN IF current_user <> 'postgres' THEN RAISE EXCEPTION 'units.sql left the role at %', current_user; END IF; END \$\$;
--CHECKS
SELECT 'CHECK|withdrawn by the --by person', count(*) = 1
          AND bool_and(status = 'withdrawn' AND withdrawn_by_sub = '$UUID_AD' AND withdrawn_by_person = 'p-ad'
                       AND withdrawn_by_name = 'system:deploy (by test-ad)' AND withdraw_reason = 'iam-db probe'
                       AND withdrawn_at IS NOT NULL AND checked_at IS NULL)
  FROM iam.account_decision WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_assign';
SELECT 'CHECK|no unit_remove decision', NOT EXISTS (SELECT 1 FROM iam.account_decision
        WHERE keycloak_user_id = '$UUID_OP' AND kind = 'unit_remove');
SELECT 'CHECK|one account_decision_withdrawn event by system:deploy', count(*) = 1 AND bool_and(actor_name = 'system:deploy')
  FROM iam_policy.history WHERE event = 'account_decision_withdrawn' AND payload ->> 'keycloak_user_id' = '$UUID_OP'
   AND (payload ->> 'unit_id')::int = :uid;
SELECT 'CHECK|no unit event', NOT EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event IN ('unit_assigned', 'unit_removed') AND payload ->> 'person_sub' = '$UUID_OP');
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W7 "a unit decision is final: UPDATE" "42501:may be added" <<SQL
$(units_vars true)
$UNITS_SQL
UPDATE iam.account_decision SET reason = 'x' WHERE kind = 'unit_assign';
SQL
        probe W7 "a unit decision is final: DELETE" "42501:append-only: DELETE refused" <<SQL
$(units_vars true)
$UNITS_SQL
DELETE FROM iam.account_decision WHERE kind = 'unit_assign';
SQL
    fi
    # W8: commissioning (2026-10-31): on waits for a qa person other than the proposer
    # and is refused while the unit has a run in R or S; off applies at once and waits
    # for qa's review; return, withdraw, unit_commissioning()'s per-role view, the
    # _authors exclusion and the hash-chain events. The tokens are W4's.
    if [[ "$MODE" == true ]]; then
        propose_on="
$new_unit
SELECT medcea.propose_commissioning(:cu, true, 'iam-db: commission it') AS chg \\gset"
        flag_on="
$propose_on
$(as_token "$T_QA")
SELECT medcea.approve_change('medcea.pending_change', :chg, 'iam-db: flag') \\g /dev/null"
        probe W8 "control: an engineer proposes commissioning" ok <<SQL
$propose_on
--CHECKS
SELECT 'CHECK|pending, attributed to p-en by token', proposed_by_person = 'p-en' AND proposed_by_source = 'token' AND applied_at IS NULL
  FROM medcea.pending_change WHERE change_id = :chg;
SELECT 'CHECK|the flag is still off', NOT commissioning FROM medcea.cea_unit WHERE unit_id = :cu;
SQL
        probe W8 "a proposal needs a reason" "22023:a reason is required" <<SQL
$new_unit
SELECT medcea.propose_commissioning(:cu, true, ' ');
SQL
        probe W8 "a qa token cannot propose" "42501:permission denied for function propose_commissioning" <<SQL
$new_unit
$(as_token "$T_QA")
SELECT medcea.propose_commissioning(:cu, true, 'x');
SQL
        probe W8 "an operator token cannot propose" "42501:permission denied for function propose_commissioning" <<SQL
$new_unit
$(as_token "$T_OP")
SELECT medcea.propose_commissioning(:cu, true, 'x');
SQL
        probe W8 "a proposal that changes nothing" "22023:is already off" <<SQL
$new_unit
SELECT medcea.propose_commissioning(:cu, false, 'x');
SQL
        probe W8 "a second 'on' while one waits (nobody replaces another's proposal)" "22023:already waits for qa" <<SQL
$propose_on
$(as_token "$T_EN2")
SELECT medcea.propose_commissioning(:cu, true, 'mine instead');
SQL
        probe W8 "control: a qa person applies it" ok <<SQL
$flag_on
--CHECKS
SELECT 'CHECK|flag on', commissioning FROM medcea.cea_unit WHERE unit_id = :cu;
SELECT 'CHECK|approval apply, master_data, author p-en, by token', count(*) = 1 FROM medcea.approval
 WHERE target = 'medcea.pending_change' AND row_key = jsonb_build_array(:chg) AND action = 'apply' AND group_name = 'master_data'
   AND author_persons = '{p-en}' AND approved_by_person = 'p-qa' AND approved_by_source = 'token' AND note = 'iam-db: flag';
SELECT 'CHECK|row_change by p-qa', EXISTS (SELECT 1 FROM medcea.row_change WHERE target = 'medcea.cea_unit'
       AND row_key = jsonb_build_array(:cu) AND new_values -> 'commissioning' = 'true' AND actor_person = 'p-qa');
SELECT 'CHECK|commissioning_enabled in the hash chain with the change and its reason', EXISTS (SELECT 1 FROM iam_policy.history
       WHERE event = 'commissioning_enabled' AND (payload ->> 'unit_id')::int = :cu AND (payload ->> 'change_id')::bigint = :chg
         AND reason = 'iam-db: commission it' AND actor_person = 'p-qa');
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
        probe W8 "the proposer's person on a qa account approves" "42501:not_own_author" <<SQL
$new_unit
$(as_token "$T_EN2")
SELECT medcea.propose_commissioning(:cu, true, 'iam-db') AS chg \gset
$(as_token "$T_QAEN2")
SELECT medcea.approve_change('medcea.pending_change', :chg, NULL);
SQL
        probe W8 "the proposer's person on a qa account returns" "42501:withdraw it instead" <<SQL
$new_unit
$(as_token "$T_EN2")
SELECT medcea.propose_commissioning(:cu, true, 'iam-db') AS chg \gset
$(as_token "$T_QAEN2")
SELECT medcea.return_change('medcea.pending_change', :chg, 'iam-db: my own');
SQL
        probe W8 "a token without person_id proposes" "42501:carries no person_id" <<SQL
$new_unit
$(as_token "$(claims engineer "$UUID_EN" p-en | sed 's/"person_id":"p-en",//')")
SELECT medcea.propose_commissioning(:cu, true, 'iam-db');
SQL
        probe W8 "an engineer token cannot approve" "42501:permission denied for function approve_change" <<SQL
$propose_on
$(as_token "$T_EN2")
SELECT medcea.approve_change('medcea.pending_change', :chg, NULL);
SQL
        probe W8 "approved twice" "22023:no longer pending" <<SQL
$flag_on
SELECT medcea.approve_change('medcea.pending_change', :chg, NULL);
SQL
        probe W8 "control: ending commissioning applies at once and waits for qa's review" ok <<SQL
$flag_on
$(as_token "$T_EN2")
SELECT medcea.propose_commissioning(:cu, false, 'iam-db: done') AS off \gset
$(as_token "$T_QA")
SELECT state AS st, may_approve AS ma FROM medcea.approval_queue() WHERE target = 'medcea.pending_change' AND id = :off \gset
$(as_token "$T_EN2")
SELECT state AS mst, may_withdraw AS mw FROM medcea.my_approvals() WHERE id = :off AND kind = 'commissioning' \gset
--CHECKS
SELECT 'CHECK|flag off at once', NOT commissioning FROM medcea.cea_unit WHERE unit_id = :cu;
SELECT 'CHECK|recorded as applied at once', applied_at IS NOT NULL FROM medcea.pending_change WHERE change_id = :off;
SELECT 'CHECK|commissioning_disabled by p-en2', EXISTS (SELECT 1 FROM iam_policy.history WHERE event = 'commissioning_disabled'
       AND (payload ->> 'change_id')::bigint = :off AND actor_person = 'p-en2' AND (payload ->> 'applied_at_once')::boolean);
SELECT 'CHECK|queued for review, qa may review it', :'st' = 'review' AND :'ma'::boolean;
SELECT 'CHECK|the proposer reads applied_review_pending, no withdraw', :'mst' = 'applied_review_pending' AND NOT :'mw'::boolean;
SQL
        probe W8 "control: qa reviews the off; nothing changes" ok <<SQL
$flag_on
$(as_token "$T_EN2")
SELECT medcea.propose_commissioning(:cu, false, 'iam-db: done') AS off \gset
$(as_token "$T_QA")
SELECT medcea.approve_change('medcea.pending_change', :off, 'seen');
--CHECKS
SELECT 'CHECK|a review, not an apply', action = 'review' AND note = 'seen' FROM medcea.approval
 WHERE target = 'medcea.pending_change' AND row_key = jsonb_build_array(:off);
SELECT 'CHECK|still off', NOT commissioning FROM medcea.cea_unit WHERE unit_id = :cu;
SQL
        probe W8 "an off that applied at once cannot be withdrawn" "22023:applied at once" <<SQL
$flag_on
$(as_token "$T_EN2")
SELECT medcea.propose_commissioning(:cu, false, 'iam-db: done') AS off \gset
SELECT medcea.withdraw_change(:off, NULL);
SQL
        probe W8 "an off that applied at once cannot be returned" "22023:applied at once" <<SQL
$flag_on
$(as_token "$T_EN2")
SELECT medcea.propose_commissioning(:cu, false, 'iam-db: done') AS off \gset
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.pending_change', :off, 'no');
SQL
        # a run of IAMT01: S from the production manager, R once the operator starts it
        probe W8 "a run in S refuses the proposal" "42501:in S; flag it when no run" <<SQL
$run_setup
$(as_token "$T_EN")
SELECT medcea.propose_commissioning(unit_id, true, 'iam-db') FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SQL
        probe W8 "a run in R refuses the proposal" "42501:in R; flag it when no run" <<SQL
$run_setup
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
$(as_token "$T_EN")
SELECT medcea.propose_commissioning(unit_id, true, 'iam-db') FROM medcea.cea_unit WHERE unit_code = 'IAMT01';
SQL
        probe W8 "a run scheduled after the proposal refuses the approval" "42501:in S; flag it when no run" <<SQL
$(as_token "$T_EN")
SELECT medcea.propose_commissioning(unit_id, true, 'iam-db') AS chg FROM medcea.cea_unit WHERE unit_code = 'IAMT01' \gset
$(as_postgres)
$run_setup
$(as_token "$T_QA")
SELECT medcea.approve_change('medcea.pending_change', :chg, NULL);
SQL
        # the other half (review fix): nothing schedules a run on a flagged unit, and the
        # unit row is read FOR SHARE first (_unit_schedulable), so a scheduling in flight
        # and approve_change's _unit_busy() are serialised
        flag_t01="
$(as_token "$T_EN")
SELECT medcea.propose_commissioning(unit_id, true, 'iam-db') AS chg FROM medcea.cea_unit WHERE unit_code = 'IAMT01' \\gset
$(as_token "$T_QA")
SELECT medcea.approve_change('medcea.pending_change', :chg, NULL) \\g /dev/null
$(as_postgres)"
        probe W8 "a new run on a flagged unit" "42501:schedule its run once commissioning ends" <<SQL
$flag_t01
$run_setup
SQL
        probe W8 "a failed run back to S on a flagged unit" "42501:schedule its run once commissioning ends" <<SQL
$run_setup
$(as_token "$T_OP")
SELECT medcea.set_run_status(:run, 'F');
$(as_postgres)
$flag_t01
$(as_token "$T_OP")
SELECT medcea.set_run_status(:run, 'S');
SQL
        probe W8 "control: F -> S on an unflagged unit" ok <<SQL
$run_setup
$(as_token "$T_OP")
SELECT medcea.set_run_status(:run, 'F');
SELECT medcea.set_run_status(:run, 'S');
--CHECKS
SELECT 'CHECK|back in S', recipe_run_status = 'S' FROM medcea.recipe_run WHERE recipe_run_id = :run;
SQL
        probe W8 "control: _unit_schedulable reads the unit FOR SHARE" ok <<SQL
RESET ROLE;
SELECT pg_get_functiondef('medcea._unit_schedulable(integer)'::regprocedure) ~ 'FOR SHARE' AS fs,
       pg_get_functiondef('medcea.new_run_defaults()'::regprocedure) ~ '_unit_schedulable' AS nrd,
       pg_get_functiondef('medcea.set_run_status(integer, text)'::regprocedure) ~ '_unit_schedulable' AS srs \gset
--CHECKS
SELECT 'CHECK|FOR SHARE, called by new_run_defaults and set_run_status', :'fs'::boolean AND :'nrd'::boolean AND :'srs'::boolean;
SQL
        # start_run keeps its own check, for a unit flagged with a run already in S
        # (a flag set by hand by the owner, or before this rule)
        probe W8 "start_run on a flagged unit" "42501:is flagged for commissioning" <<SQL
$run_setup
$(as_postgres)
SET ROLE medcea_owner;
UPDATE medcea.cea_unit SET commissioning = true WHERE unit_code = 'IAMT01';
$(as_token "$T_OP")
SELECT medcea.start_run(:run);
SQL
        probe W8 "control: qa returns a proposal; it never applies and can be proposed again" ok <<SQL
$propose_on
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.pending_change', :chg, 'iam-db: not this week');
$(as_token "$T_EN")
SELECT state AS mst, return_reason AS mrr FROM medcea.my_approvals() WHERE id = :chg AND kind = 'commissioning' \gset
SELECT medcea.propose_commissioning(:cu, true, 'iam-db: again') AS again \gset
--CHECKS
SELECT 'CHECK|approval action return', action = 'return' AND note = 'iam-db: not this week' FROM medcea.approval
 WHERE target = 'medcea.pending_change' AND row_key = jsonb_build_array(:chg);
SELECT 'CHECK|the proposer reads returned with the reason', :'mst' = 'returned' AND :'mrr' = 'iam-db: not this week';
SELECT 'CHECK|still off', NOT commissioning FROM medcea.cea_unit WHERE unit_id = :cu;
SQL
        probe W8 "a returned proposal cannot be approved" "22023:no longer pending" <<SQL
$propose_on
$(as_token "$T_QA")
SELECT medcea.return_change('medcea.pending_change', :chg, 'no');
SELECT medcea.approve_change('medcea.pending_change', :chg, NULL);
SQL
        probe W8 "control: the proposer withdraws" ok <<SQL
$propose_on
SELECT medcea.withdraw_change(:chg, 'iam-db: changed my mind');
SELECT state AS mst FROM medcea.my_approvals() WHERE id = :chg AND kind = 'commissioning' \gset
--CHECKS
SELECT 'CHECK|approval action withdraw by p-en', action = 'withdraw' AND approved_by_person = 'p-en' AND note = 'iam-db: changed my mind'
  FROM medcea.approval WHERE target = 'medcea.pending_change' AND row_key = jsonb_build_array(:chg);
SELECT 'CHECK|my_approvals: withdrawn', :'mst' = 'withdrawn';
SQL
        probe W8 "another person withdraws" "42501:not a proposal of yours" <<SQL
$propose_on
$(as_token "$T_EN2")
SELECT medcea.withdraw_change(:chg, NULL);
SQL
        probe W8 "a withdrawn proposal cannot be approved" "22023:no longer pending" <<SQL
$propose_on
SELECT medcea.withdraw_change(:chg, NULL);
$(as_token "$T_QA")
SELECT medcea.approve_change('medcea.pending_change', :chg, NULL);
SQL
        probe W8 "control: unit_commissioning per role" ok <<SQL
$propose_on
$(as_token "$T_EN")
SELECT pending_change_id = :chg AS en_pend, pending_mine AS en_mine, pending_reason AS en_reason, can_propose AS en_prop,
       can_approve AS en_appr FROM medcea.unit_commissioning() WHERE unit_id = :cu \gset
$(as_token "$T_EN2")
SELECT pending_reason AS en2_reason, NOT pending_mine AS en2_notmine FROM medcea.unit_commissioning() WHERE unit_id = :cu \gset
$(as_token "$T_PM")
SELECT pending_change_id = :chg AS pm_pend, pending_reason IS NULL AND pending_by IS NULL AS pm_hidden,
       NOT can_propose AND NOT can_approve AS pm_none FROM medcea.unit_commissioning() WHERE unit_id = :cu \gset
$(as_token "$T_QA")
SELECT can_approve AND can_read_history AS qa_can, pending_by = 'test-p-en' AS qa_by FROM medcea.unit_commissioning() WHERE unit_id = :cu \gset
$(as_postgres)
$run_setup
$(as_token "$T_OP")
SELECT count(*) FILTER (WHERE blocking_run_id IS NOT NULL) AS op_runs FROM medcea.unit_commissioning() \gset
$(as_token "$T_PM")
SELECT blocking_run_id = :run AS pm_run FROM medcea.unit_commissioning() WHERE unit_code = 'IAMT01' \gset
--CHECKS
SELECT 'CHECK|engineer: own pending with its reason, may propose, not approve',
       :'en_pend'::boolean AND :'en_mine'::boolean AND :'en_reason' = 'iam-db: commission it' AND :'en_prop'::boolean AND NOT :'en_appr'::boolean;
SELECT 'CHECK|another engineer sees the reason (decision), not as theirs', :'en2_reason' = 'iam-db: commission it' AND :'en2_notmine'::boolean;
SELECT 'CHECK|production manager: waiting, no name or reason, no action', :'pm_pend'::boolean AND :'pm_hidden'::boolean AND :'pm_none'::boolean;
SELECT 'CHECK|qa: may approve and read the history, sees the proposer', :'qa_can'::boolean AND :'qa_by'::boolean;
SELECT 'CHECK|operator: no unit''s run state', :op_runs = 0;
SELECT 'CHECK|production manager: the blocking run', :'pm_run'::boolean;
SQL
        probe W8 "the qa person who applied the flag still reviews the unit (commissioning makes no author)" ok <<SQL
$flag_on
SELECT medcea.approve_change('medcea.cea_unit', :cu, 'iam-db: master data review');
--CHECKS
SELECT 'CHECK|review authored by p-en only', author_persons = '{p-en}' FROM medcea.approval
 WHERE target = 'medcea.cea_unit' AND row_key = jsonb_build_array(:cu) AND action = 'review';
SQL
        # health-check.sh iampending reads the open changes as postgres with this predicate
        # (keep the two in step): a fresh proposal is open and not yet stale, an applied
        # one is not open
        probe W8 "control: the health check's iampending predicate" ok <<SQL
$propose_on
$(as_postgres)
SELECT count(*) FILTER (WHERE x.change_id = :chg) AS open_new,
       count(*) FILTER (WHERE x.change_id = :chg AND coalesce(x.applied_at, x.proposed_at) < now() - interval '7 days') AS stale_new
  FROM medcea.pending_change x WHERE medcea._pending_open(x) \\gset
--CHECKS
SELECT 'CHECK|the waiting proposal is open, not stale', :open_new = 1 AND :stale_new = 0;
SQL
    fi
    if [[ "$MODE" == false ]]; then
        for fn in "medcea.unit_commissioning()" "medcea.approval_queue()" "medcea.my_approvals()"; do
            probe W8 "anon cannot execute $fn while false" "42501:permission denied for function" <<SQL
$(as_anon)
SELECT count(*) FROM $fn;
SQL
        done
        probe W8 "anon cannot withdraw while false" "42501:permission denied for function withdraw_change" <<SQL
$(as_anon)
SELECT medcea.withdraw_change(1, NULL);
SQL
        probe W8 "anon cannot return while false" "42501:permission denied for function return_change" <<SQL
$(as_anon)
SELECT medcea.return_change('medcea.pending_change', 1, 'x');
SQL
    fi
elif want writes; then
    note writes "skipped (read-only; --write-probes runs them on medcea-iamtest only)"
fi

# ── access ───────────────────────────────────────────────────────────────────────
# IAM 2.7: the account decision functions in schema iam (D1-D18 of the spec, 8.2), as
# access-api runs them: SET SESSION AUTHORIZATION access_svc (session_user access_svc,
# so set_actor records 'person via access_svc'), then set_actor for the person of the
# token. Fresh accounts and persons each run: A (admin), Q and Q2 (qa), S (the subject).
if want access && [[ "$WRITES" == true && "$MODE" != legacy ]]; then
    echo ""
    _u() { python3 -c 'import uuid; print(uuid.uuid4())'; }
    A="$(_u)"; Q="$(_u)"; Q2="$(_u)"; S="$(_u)"; X="$(_u)"
    _h="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
    PA="p-a-$_h"; PQ="p-q-$_h"; PQ2="p-q2-$_h"; PS="p-s-$_h"; PX="p-x-$_h"
    ATTEST='attest: I did not run units.sh for this assignment.'
    sqlq() { if [[ -n "${1:-}" ]]; then printf "'%s'" "${1//\'/\'\'}"; else printf 'NULL'; fi; }
    # as_um SUB PERSON NAME ROLE — the User Manager acting for that person
    as_um() {
        printf 'RESET ROLE;\nRESET SESSION AUTHORIZATION;\nSET SESSION AUTHORIZATION access_svc;\n'
        echo "SELECT medcea_auth.set_actor('$1', $(sqlq "$2"), '$3', '$4') \\g /dev/null"
    }
    um_admin() { as_um "$A" "$PA" test-a admin; }
    um_qa()    { as_um "$Q" "$PQ" test-q qa; }
    um_qa2()   { as_um "$Q2" "$PQ2" test-q2 qa; }
    # rec VAR KIND FROM TO [NEW_PERSON_ID] — record_decision on S; sets :VAR, :VAR_st, :VAR_nw, :VAR_wd
    rec() {
        echo "SELECT decision_id AS $1, status AS ${1}_st, jsonb_array_length(widening) AS ${1}_nw, withdrawn AS ${1}_wd
  FROM iam.record_decision('$2', '$S', 'test-s', '$PS', $(sqlq "$3"), $(sqlq "$4"), $(sqlq "${5:-}"), 'iam-db probe', NULL) \\gset"
    }
    pending_d1() { um_admin; rec d1 role_change operator production_manager; }   # D1's row
    unit_id_sql="SELECT unit_id AS uid FROM medcea.cea_unit WHERE unit_code = 'IAMT01' \\gset"
    UNITS_SQL="$(cat "$REPO_ROOT/apps/iam/units.sql")"
    # units BY_SUB BY_PERSON BY_NAME ASSIGN [BOOTSTRAP] — apps/iam/units.sql on S's unit IAMT01, as postgres
    units() {
        as_postgres
        cat <<SQL
\\set assign $4
\\set bootstrap ${5:-false}
\\set sub '$S'
\\set username test-s
\\set person '$PS'
\\set units :uid
\\set reason 'iam-db probe'
\\set by_sub '$1'
\\set by_person '$2'
\\set by_name $3
$UNITS_SQL
SQL
    }
    # a bootstrap unit_assign written by postgres: no maker, and no subject person
    bootstrap_row() {
        as_postgres
        cat <<SQL
SELECT medcea_auth._set_internal_actor('system:deploy') \\g /dev/null
INSERT INTO iam_policy.user_unit (person_sub, unit_id) VALUES ('$S'::uuid, :uid) ON CONFLICT DO NOTHING;
INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id, widens, status, reason,
                                  made_by_sub, made_by_person, made_by_name)
VALUES ('unit_assign', '$S', 'test-s', NULL, :uid, true, 'pending_qa', 'iam-db probe', NULL, NULL, 'system:deploy')
RETURNING decision_id AS bd \\gset
SQL
    }

    # D1 / D2 — a widening waits, a narrowing applies with its status history
    # 13 since Superset stage C: (analysis, R) is the 13th pair production_manager holds.
    probe D1 "operator -> production_manager: pending_qa with 13 widening pairs" ok <<SQL
$(pending_d1)
--CHECKS
SELECT 'CHECK|pending_qa', :'d1_st' = 'pending_qa';
SELECT 'CHECK|13 pairs', :d1_nw = 13;
SELECT 'CHECK|the row', widens AND made_by_sub = '$A' AND made_by_person = '$PA' AND from_role = 'operator'
          AND to_role = 'production_manager' AND checked_at IS NULL
  FROM iam.account_decision WHERE decision_id = :d1;
SELECT 'CHECK|no status history while pending', NOT EXISTS (SELECT 1 FROM iam.user_status_history WHERE decision_id = :d1);
SQL
    probe D2 "production_manager -> operator: applied, no pairs, status history with the decision" ok <<SQL
$(um_admin)
$(rec d2 role_change production_manager operator)
--CHECKS
SELECT 'CHECK|applied', :'d2_st' = 'applied';
SELECT 'CHECK|no pairs', :d2_nw = 0;
SELECT 'CHECK|role_changed by A as a person', count(*) = 1 FROM iam.user_status_history
 WHERE decision_id = :d2 AND action = 'role_changed' AND actor_sub = '$A' AND actor_person = '$PA'
   AND from_role = 'production_manager' AND to_role = 'operator';
SQL
    # an activation waits for qa even with no platform role (under IAM_GATES=false the AI workbench admits any enabled account)
    probe D2 "activate an account with no platform role: pending_qa, no pairs" ok <<SQL
$(um_admin)
$(rec d2 activate '' '')
--CHECKS
SELECT 'CHECK|pending_qa', :'d2_st' = 'pending_qa';
SELECT 'CHECK|no pairs', :d2_nw = 0;
SELECT 'CHECK|no status history while pending', NOT EXISTS (SELECT 1 FROM iam.user_status_history WHERE decision_id = :d2);
SQL
    # D3 — one open decision per account; deactivation is always allowed and withdraws it
    probe D3 "a second decision while D1 waits" "22023:is waiting for qa" <<SQL
$(pending_d1)
$(rec d3 person_id '' '' "p-new-$_h")
SQL
    probe D3 "a deactivation while D1 waits: allowed, D1 withdrawn" ok <<SQL
$(pending_d1)
$(rec d3 deactivate operator '')
--CHECKS
SELECT 'CHECK|applied', :'d3_st' = 'applied';
SELECT 'CHECK|returns D1 as withdrawn', :d1 = ANY (:'d3_wd'::bigint[]);
SELECT 'CHECK|D1 withdrawn by A', status = 'withdrawn' AND withdrawn_by_sub = '$A' AND withdrawn_at IS NOT NULL
          AND withdraw_reason LIKE 'withdrawn by deactivation #%'
  FROM iam.account_decision WHERE decision_id = :d1;
SELECT 'CHECK|deactivated in the status history', EXISTS (SELECT 1 FROM iam.user_status_history WHERE decision_id = :d3 AND action = 'deactivated');
SQL
    # D4 — who may propose: admin through the User Manager only
    probe D4 "record_decision as a qa person" "42501:holds no K on iam_users" <<SQL
$(um_qa)
$(rec d role_change operator engineer)
SQL
    probe D4 "record_decision without set_actor" "42501:made in the User Manager" <<SQL
SET SESSION AUTHORIZATION access_svc;
$(rec d role_change operator engineer)
SQL
    probe D4 "record_decision as postgres with the deploy's internal actor" "42501:not by system" <<SQL
SELECT medcea_auth._set_internal_actor('system:deploy') \\g /dev/null
$(rec d role_change operator engineer)
SQL
    probe D4 "access_svc cannot take the deploy's internal actor" "42501:permission denied for function" <<SQL
SET SESSION AUTHORIZATION access_svc;
SELECT medcea_auth._set_internal_actor('system:deploy');
SQL
    # D5 — who may confirm (rules 3-5)
    probe D5 "confirm as an admin" "42501:role admin holds no A on iam_users" <<SQL
$(pending_d1)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db probe');
SQL
    probe D5 "confirm by the subject's own account" "42501:you are its subject" <<SQL
$(pending_d1)
$(as_um "$S" "$PX" test-s qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db probe');
SQL
    probe D5 "confirm by the subject's person on another account" "42501:same person as the subject" <<SQL
$(pending_d1)
$(as_um "$Q" "$PS" test-q qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db probe');
SQL
    probe D5 "confirm with a token without person_id" "42501:no person_id" <<SQL
$(pending_d1)
$(as_um "$Q" "" test-q qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db probe');
SQL
    probe D5 "confirm a row whose maker is the same person (written by postgres)" "42501:same person as the maker" <<SQL
INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, from_role, to_role, widens, status,
                                  reason, made_by_sub, made_by_person, made_by_name)
VALUES ('role_change', '$S', 'test-s', '$PS', 'operator', 'engineer', true, 'pending_qa', 'iam-db probe', '$X', '$PQ', 'test-x')
RETURNING decision_id AS dm \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:dm, 'iam-db probe');
SQL
    # D6 / D7 — confirm, once
    probe D6 "qa confirms D1" ok <<SQL
$(pending_d1)
$(um_qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db D6') \\g /dev/null
--CHECKS
SELECT 'CHECK|confirmed by Q', status = 'confirmed' AND checked_by_sub = '$Q' AND checked_by_person = '$PQ' AND check_note = 'iam-db D6'
  FROM iam.account_decision WHERE decision_id = :d1;
SELECT 'CHECK|role_changed by Q', count(*) = 1 FROM iam.user_status_history
 WHERE decision_id = :d1 AND action = 'role_changed' AND actor_sub = '$Q' AND actor_person = '$PQ';
SQL
    probe D7 "confirm D1 again" "22023:already confirmed" <<SQL
$(pending_d1)
$(um_qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db D7') \\g /dev/null
SELECT * FROM iam.confirm_decision(:d1, 'iam-db D7');
SQL
    # D8 / D9 / D9b — a unit assignment takes effect when qa confirms it; refusing one
    # applies nothing, and refusing one in effect before the check (bootstrap) removes
    # it, only while it is the latest
    probe D8 "units.sql assign, then qa confirms it: the unit is assigned, unit_assigned with Q as the actor" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
SELECT NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid) AS pre \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, '$ATTEST') \\g /dev/null
--CHECKS
SELECT 'CHECK|not in effect before the confirm', :'pre'::boolean;
SELECT 'CHECK|user_unit row made by the confirm', EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid);
SELECT 'CHECK|confirmed by Q', status = 'confirmed' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :du;
SELECT 'CHECK|unit_assigned with Q as the actor', count(*) = 1 AND bool_and(actor_sub = '$Q'::uuid AND actor_person = '$PQ')
  FROM iam_policy.history WHERE event = 'unit_assigned' AND payload ->> 'person_sub' = '$S';
SELECT 'CHECK|account_decision_confirmed chained', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_confirmed' AND (payload ->> 'decision_id')::bigint = :du);
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
    probe D8 "units.sql assign, then qa refuses it: nothing was in effect, nothing removed" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT removed AS rm FROM iam.refuse_decision(:du, 'iam-db D8') \\gset
--CHECKS
SELECT 'CHECK|removed = false', NOT :'rm'::boolean;
SELECT 'CHECK|no user_unit row', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid);
SELECT 'CHECK|refused by Q', status = 'refused' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :du;
SELECT 'CHECK|no unit event', NOT EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event IN ('unit_assigned', 'unit_removed') AND payload ->> 'person_sub' = '$S');
SELECT 'CHECK|account_decision_refused, not removed', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_refused' AND (payload ->> 'decision_id')::bigint = :du AND NOT (payload ->> 'removed')::boolean);
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
    probe D8 "units.sql assign --bootstrap, then qa refuses it: the unit is removed, both events chained" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT removed AS rm FROM iam.refuse_decision(:du, 'iam-db D8') \\gset
--CHECKS
SELECT 'CHECK|removed = true', :'rm'::boolean;
SELECT 'CHECK|user_unit row gone', NOT EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid);
SELECT 'CHECK|refused by Q', status = 'refused' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :du;
SELECT 'CHECK|unit_removed with Q as the actor', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'unit_removed' AND actor_sub = '$Q'::uuid AND payload ->> 'person_sub' = '$S');
SELECT 'CHECK|account_decision_refused, removed', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_refused' AND (payload ->> 'decision_id')::bigint = :du AND (payload ->> 'removed')::boolean);
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
    probe D8 "confirm an assignment whose unit no longer exists" "22023:no longer exists" <<SQL
INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, unit_id, widens, status, reason,
                                  made_by_sub, made_by_person, made_by_name)
VALUES ('unit_assign', '$S', 'test-s', '$PS', -1, true, 'pending_qa', 'iam-db probe', '$A', '$PA', 'system:deploy (by test-a)')
RETURNING decision_id AS du \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, '$ATTEST');
SQL
    probe D9 "assign, remove: the waiting assign is withdrawn; refusing it" "22023:already withdrawn" <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
$(units "$A" "$PA" test-a false)
SELECT min(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT removed AS rm FROM iam.refuse_decision(:du, 'iam-db D9');
SQL
    probe D9 "assign --bootstrap, remove, assign --bootstrap; refusing the first assign removes nothing" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true true)
$(units "$A" "$PA" test-a false)
$(units "$A" "$PA" test-a true true)
SELECT min(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT removed AS rm FROM iam.refuse_decision(:du, 'iam-db D9') \\gset
--CHECKS
SELECT 'CHECK|removed = false', NOT :'rm'::boolean;
SELECT 'CHECK|user_unit row still there', EXISTS (SELECT 1 FROM iam_policy.user_unit WHERE person_sub = '$S' AND unit_id = :uid);
SELECT 'CHECK|account_decision_refused, not removed', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_refused' AND (payload ->> 'decision_id')::bigint = :du AND NOT (payload ->> 'removed')::boolean);
SELECT 'CHECK|chain verifies', (SELECT ok FROM iam_policy.verify_chain());
SQL
    probe D9b "assign --bootstrap, remove; confirming the first assign" "22023:superseded" <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true true)
$(units "$A" "$PA" test-a false)
SELECT min(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, 'iam-db D9b');
SQL
    # D10 — a bootstrap row without a maker or subject person (the production rows)
    probe D10 "bootstrap row: confirm without the attestation" "42501:needs the attestation" <<SQL
$unit_id_sql
$(bootstrap_row)
$(um_qa)
SELECT * FROM iam.confirm_decision(:bd, 'looks right');
SQL
    probe D10 "bootstrap row: confirm with the attestation, compared by account" ok <<SQL
$unit_id_sql
$(bootstrap_row)
$(um_qa)
SELECT * FROM iam.confirm_decision(:bd, '$ATTEST') \\g /dev/null
--CHECKS
SELECT 'CHECK|confirmed', status = 'confirmed' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :bd;
SELECT 'CHECK|the note holds the attestation and the account suffix', check_note LIKE '$ATTEST%'
          AND check_note LIKE '%[subject has no person_id: compared by account]'
  FROM iam.account_decision WHERE decision_id = :bd;
SELECT 'CHECK|account_decision_confirmed chained', EXISTS (SELECT 1 FROM iam_policy.history
        WHERE event = 'account_decision_confirmed' AND (payload ->> 'decision_id')::bigint = :bd);
SQL
    probe D10 "bootstrap row: confirm by the subject's account" "42501:you are its subject" <<SQL
$unit_id_sql
$(bootstrap_row)
$(as_um "$S" "$PX" test-s qa)
SELECT * FROM iam.confirm_decision(:bd, '$ATTEST');
SQL
    probe D10 "units.sql --by the qa person: that person cannot confirm it" "42501:you made this decision" <<SQL
$unit_id_sql
$(units "$Q" "$PQ" test-q true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, 'iam-db D10');
SQL
    # --by names an account the script cannot prove its runner holds: the attestation still applies
    probe D10 "units.sql --by another account: confirm without the attestation" "42501:needs the attestation" <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, 'looks right');
SQL
    probe D10 "units.sql --by another account: confirm with the attestation" ok <<SQL
$unit_id_sql
$(units "$A" "$PA" test-a true)
SELECT max(decision_id) AS du FROM iam.account_decision WHERE keycloak_user_id = '$S' AND kind = 'unit_assign' \\gset
$(um_qa)
SELECT * FROM iam.confirm_decision(:du, '$ATTEST') \\g /dev/null
--CHECKS
SELECT 'CHECK|confirmed by Q', status = 'confirmed' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :du;
SQL
    # D11 — review an applied decision
    probe D11 "qa reviews D2 (applied)" ok <<SQL
$(um_admin)
$(rec d2 role_change production_manager operator)
$(um_qa)
SELECT iam.review_decision(:d2, NULL) \\g /dev/null
--CHECKS
SELECT 'CHECK|reviewed by Q', status = 'reviewed' AND checked_by_sub = '$Q' FROM iam.account_decision WHERE decision_id = :d2;
SQL
    probe D11 "review a pending decision" "22023:only an applied decision is reviewed" <<SQL
$(pending_d1)
$(um_qa)
SELECT iam.review_decision(:d1, NULL);
SQL
    # D12 — access_svc writes the decision tables and histories only through the functions
    for stmt in "UPDATE iam.account_decision SET status = 'confirmed' WHERE false" \
                "INSERT INTO iam.account_decision (kind, keycloak_user_id, username, widens, status, reason, made_by_name) VALUES ('deactivate', '$S', 'x', false, 'applied', 'x', 'x')" \
                "DELETE FROM iam.account_decision WHERE false" \
                "UPDATE iam.user_status_history SET reason = reason WHERE false" "DELETE FROM iam.user_status_history WHERE false" \
                "UPDATE iam.access_request_history SET notes = notes WHERE false" "DELETE FROM iam.access_request_history WHERE false" \
                "UPDATE iam.config_history SET detail = detail WHERE false" "DELETE FROM iam.config_history WHERE false"; do
        probe D12 "access_svc: ${stmt%% WHERE*}" "42501:permission denied" <<SQL
SET SESSION AUTHORIZATION access_svc;
$stmt;
SQL
    done
    # D13 — postgres too: closing a record is the functions', the histories are append-only
    probe D13 "postgres closes a decision by UPDATE" "42501:close a record" <<SQL
$(pending_d1)
$(as_postgres)
UPDATE iam.account_decision SET status = 'confirmed', checked_at = now(), checked_by_name = 'x' WHERE decision_id = :d1;
SQL
    hist_rows="$(um_admin; rec d2 role_change production_manager operator; as_postgres)
INSERT INTO iam.access_request (username, email, first_name, last_name, requested_role, justification)
VALUES ('test-s-$_h', 'test-s-$_h@iamtest.invalid', 'T', 'S', 'operator', 'iam-db probe');
UPDATE iam.mail_settings SET from_name = 'IAMT probe $_h', updated_by = 'iam-db' WHERE id = 1;"
    for t in user_status_history access_request_history config_history; do
        for op in "UPDATE iam.$t SET event_id = event_id" "DELETE FROM iam.$t" "TRUNCATE iam.$t"; do
            probe D13 "postgres: ${op%% SET*}" "42501:append-only" <<SQL
$hist_rows
$op;
SQL
        done
    done
    # D13b — the stub role_widening of the migrations never answers
    stub="$(python3 - "$REPO_ROOT/apps/database/medcea_db_migrations.sql" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r"\n(\s*)IF pg_catalog\.to_regprocedure\('medcea_auth\.role_widening\(text, ?text\)'\) IS NULL THEN\n.*?\n\1END IF;", src, re.S)
print(m.group(0) if m else "")
PY
)"
    if [[ -n "$stub" ]]; then
        probe D13b "the uncompiled stub role_widening" "55000:not compiled" <<SQL
DROP FUNCTION medcea_auth.role_widening(text, text);
DO \$stub\$ BEGIN
$stub
END \$stub\$;
SELECT medcea_auth.role_widening('operator', 'qa');
SQL
    else
        fail D13b "the role_widening stub is not in apps/database/medcea_db_migrations.sql"
    fi
    # D13c — withdraw
    probe D13c "an admin withdraws D1" ok <<SQL
$(pending_d1)
SELECT iam.withdraw_decision(:d1, 'iam-db D13c') \\g /dev/null
--CHECKS
SELECT 'CHECK|withdrawn by A', status = 'withdrawn' AND withdrawn_by_sub = '$A' AND withdraw_reason = 'iam-db D13c'
  FROM iam.account_decision WHERE decision_id = :d1;
SQL
    probe D13c "withdraw an applied decision" "22023:already applied" <<SQL
$(um_admin)
$(rec d2 role_change production_manager operator)
SELECT iam.withdraw_decision(:d2, 'iam-db D13c');
SQL
    probe D13c "withdraw as qa" "42501:holds no K on iam_users" <<SQL
$(pending_d1)
$(um_qa)
SELECT iam.withdraw_decision(:d1, 'iam-db D13c');
SQL
    # D14 / D15 — the quarterly review
    probe D14 "qa creates this quarter's review" ok <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) AS rv \\gset
--CHECKS
SELECT 'CHECK|snapshot keys', snapshot ?& ARRAY['units', 'pending_decisions', 'decisions_since', 'policy_chain', 'iam_db_roles']
  FROM iam.access_review WHERE review_id = :rv;
SELECT 'CHECK|created by Q', created_by_sub = '$Q' AND created_by_person = '$PQ' FROM iam.access_review WHERE review_id = :rv;
SQL
    probe D14 "a second review this quarter" "23505:exists" <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) \\g /dev/null
SELECT iam.create_review('{}'::jsonb);
SQL
    probe D15 "sign-off as an auditor" "42501:holds no C on audit_histories" <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) AS rv \\gset
$(as_um "$X" "$PX" test-x auditor)
SELECT iam.sign_off_review(:rv, NULL);
SQL
    probe D15 "qa signs off (the creator may), once" ok <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) AS rv \\gset
SELECT iam.sign_off_review(:rv, 'iam-db D15') \\g /dev/null
--CHECKS
SELECT 'CHECK|signed off by Q', signed_off_by_sub = '$Q' AND signed_off_at IS NOT NULL FROM iam.access_review WHERE review_id = :rv;
SQL
    probe D15 "sign off twice" "22023:already signed off" <<SQL
$(um_qa)
SELECT iam.create_review('{}'::jsonb) AS rv \\gset
SELECT iam.sign_off_review(:rv, NULL) \\g /dev/null
$(um_qa2)
SELECT iam.sign_off_review(:rv, NULL);
SQL
    # D16 — a template reset is an UPDATE, logged as reset
    probe D16 "access_svc resets a template by UPDATE" ok <<SQL
SET SESSION AUTHORIZATION access_svc;
INSERT INTO iam.mail_template (name, subject, body, updated_by, is_default) VALUES ('approved', 'IAMT', 'IAMT body', 'test-a', false)
ON CONFLICT (name) DO UPDATE SET subject = 'IAMT', body = 'IAMT body', updated_by = 'test-a', is_default = false;
UPDATE iam.mail_template SET subject = 'default', body = 'default body', is_default = true, updated_by = 'test-a-$_h', updated_at = now()
 WHERE name = 'approved' AND NOT is_default;
--CHECKS
SELECT 'CHECK|reset logged', EXISTS (SELECT 1 FROM iam.config_history WHERE item = 'template:approved' AND action = 'reset' AND actor = 'test-a-$_h');
SELECT 'CHECK|is_default', is_default FROM iam.mail_template WHERE name = 'approved';
SQL
    # D17 — MQTT person credentials, on deactivation and on a pure narrowing
    cred="$(as_postgres)
INSERT INTO medcea.mqtt_service_credential (username, password_hash, person_sub, expires_at)
VALUES ('iamt-person-$_h', '\$7\$101\$aaaa\$bbbb', '$S', now() + interval '1 day');"
    probe D17 "deactivate: revoke_person_mqtt in the same transaction" ok <<SQL
$cred
$(um_admin)
$(rec d3 deactivate operator '')
SELECT medcea.revoke_person_mqtt('$S'::uuid, 'deactivated') AS n \\gset
--CHECKS
SELECT 'CHECK|one credential revoked', :n = 1;
SELECT 'CHECK|inactive', NOT active FROM medcea.mqtt_service_credential WHERE username = 'iamt-person-$_h';
SQL
    probe D17 "narrowing (applied): revoke_person_mqtt in the same transaction" ok <<SQL
$cred
$(um_admin)
$(rec d2 role_change production_manager operator)
SELECT medcea.revoke_person_mqtt('$S'::uuid, 'role narrowed') AS n \\gset
--CHECKS
SELECT 'CHECK|applied', :'d2_st' = 'applied';
SELECT 'CHECK|one credential revoked', :n = 1;
SQL
    probe D17 "revoke_person_mqtt as a qa person" "42501:holds no K on iam_users" <<SQL
$cred
$(um_qa)
SELECT medcea.revoke_person_mqtt('$S'::uuid, 'x');
SQL
    # D18 — rr_qa (a qa token through PostgREST) executes no iam function
    if [[ "$MODE" == true ]]; then
        probe D18 "a qa token through PostgREST calls confirm_decision" "42501:permission denied" <<SQL
$(as_token "$(claims qa "$Q" "$PQ")")
SELECT * FROM iam.confirm_decision(1, 'x');
SQL
    else
        probe D18 "rr_qa calls confirm_decision" "42501:permission denied" <<SQL
SET SESSION AUTHORIZATION rr_qa;
SELECT * FROM iam.confirm_decision(1, 'x');
SQL
    fi
    # D19 — IAM 3.5: a confirmed role change ends the subject's MQTT Explorer credentials
    probe D19 "qa confirms a role change: the subject's MQTT credentials go inactive" ok <<SQL
$cred
$(pending_d1)
$(um_qa)
SELECT * FROM iam.confirm_decision(:d1, 'iam-db D19') \\g /dev/null
--CHECKS
SELECT 'CHECK|inactive', NOT active FROM medcea.mqtt_service_credential WHERE username = 'iamt-person-$_h';
SQL
    probe D19 "qa refuses a role change: the credentials stay" ok <<SQL
$cred
$(pending_d1)
$(um_qa)
SELECT * FROM iam.refuse_decision(:d1, 'iam-db D19') \\g /dev/null
--CHECKS
SELECT 'CHECK|still active', active FROM medcea.mqtt_service_credential WHERE username = 'iamt-person-$_h';
SQL
elif want access; then
    note access "skipped (needs --write-probes, on medcea-iamtest only, and a mode other than legacy)"
fi

# ── policy (IAM Phase 4, slice 4.1: migration 008c) ─────────────────────────────
# P1 reads the catalog (any namespace); P2-P44 (4.2a: P19-P26; 4.4: P27-P37; 4.5: P42-P44) are write probes on medcea-iamtest, each
# in BEGIN … ROLLBACK, building version 1 inside the probe through the owner functions
# (a reduced skeleton: the factory's role and group keys). The token probes (P7-P10,
# P12, P20's applies, P27-P30, P31's approved versions, P35-P37, P42-P44) need IAM_DB_ROLES=true
# (authenticator's memberships, pre_request's role); P26 needs IAM_DB_ROLES=false.
if want policy && [[ "$MODE" != legacy ]]; then
    echo ""
    out="$(db <<'SQL'
SELECT 'tables', count(*), count(*) FILTER (WHERE c.relowner = 'medcea_owner'::regrole)
  FROM pg_class c WHERE c.relnamespace = 'iam_policy'::regnamespace AND c.relkind = 'r';
SELECT 'freeze', count(*) FILTER (WHERE t.tgenabled = 'A'), count(*)
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = 'iam_policy'::regnamespace AND t.tgname IN ('freeze_policy_trg', 'freeze_policy_truncate_trg')
   AND c.relname IN ('version', 'entry', 'waiver', 'skeleton', 'version_diff', 'approval_evidence');
SELECT 'fnowner', count(*) FROM pg_proc p WHERE p.pronamespace = 'iam_policy'::regnamespace AND p.proowner <> 'medcea_owner'::regrole;
SELECT 'fnpublic', count(*) FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
 WHERE (p.pronamespace = 'iam_policy'::regnamespace OR p.proname IN ('approve_policy', 'return_policy', 'confirm_policy', 'dispute_policy'))
   AND a.grantee = 0;
SELECT 'wrappers', count(*) FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
 WHERE p.pronamespace = 'medcea'::regnamespace AND p.proname IN ('approve_policy', 'return_policy', 'confirm_policy', 'dispute_policy')
   AND p.prosecdef AND l.lanname = 'plpgsql' AND p.proowner = 'medcea_owner'::regrole;
SELECT 'checks', count(*) FROM pg_constraint WHERE conrelid = 'iam_policy.version'::regclass
   AND conname IN ('version_status_check', 'version_kind_check', 'version_rollback_check', 'version_built_check',
                   'version_based_on_fkey', 'version_rollback_of_fkey', 'version_skeleton_digest_fkey', 'version_approved_skeleton_fkey');
SELECT 'oneopen', count(*) FROM pg_indexes WHERE schemaname = 'iam_policy' AND indexname = 'one_open'
   AND indexdef LIKE '%kind = ANY%';
SELECT 'retired', count(*) FROM pg_attribute WHERE attrelid = 'iam_policy.resource_group'::regclass AND attname = 'retired';
SELECT 'nonce', (SELECT value FROM medcea.platform_setting WHERE key = '008c:last_nonce')
              = (SELECT value FROM medcea.platform_setting WHERE key = '008b:last_nonce');
SELECT 'rpcclient', medcea_auth._rpc_client('approve_policy') = 'policy' AND medcea_auth._rpc_client('approve_change') IS NULL;
SELECT 'changedsince', to_regprocedure('iam._changed_since(text,text,double precision)') IS NOT NULL
                       OR to_regnamespace('iam') IS NULL;
SQL
)"
    get() { grep -m1 "^$1|" <<<"$out" | cut -d'|' -f2-; }
    [[ "$(get tables)" == "14|14" ]] && pass P1 "14 iam_policy tables, all owned by medcea_owner" || fail P1 "iam_policy tables (count|owned): $(get tables)"
    [[ "$(get freeze)" == "12|12" ]] && pass P1 "freeze_policy_trg and _truncate_trg on the six tables, ENABLE ALWAYS" || fail P1 "freeze triggers (always|all): $(get freeze)"
    [[ "$(get fnowner)" == 0 ]] && pass P1 "every iam_policy function owned by medcea_owner" || fail P1 "$(get fnowner) iam_policy function(s) not owned by medcea_owner"
    [[ "$(get fnpublic)" == 0 ]] && pass P1 "no PUBLIC EXECUTE on the 008c functions" || fail P1 "PUBLIC executes $(get fnpublic) 008c function(s)"
    [[ "$(get wrappers)" == 4 ]] && pass P1 "the four medcea.*_policy wrappers: plpgsql, SECURITY DEFINER, medcea_owner" || fail P1 "wrappers: $(get wrappers) of 4"
    [[ "$(get checks)" == 8 ]] && pass P1 "version's four named CHECKs and four foreign keys" || fail P1 "version constraints: $(get checks) of 8"
    [[ "$(get oneopen)" == 1 ]] && pass P1 "one_open counts change and skeleton versions only" || fail P1 "one_open index missing or without its kind predicate"
    [[ "$(get retired)" == 1 ]] && pass P1 "iam_policy.resource_group.retired exists (_sync_skeleton writes it)" || fail P1 "resource_group.retired missing"
    [[ "$(get nonce)" == t ]] && pass P1 "008c committed with this deploy's nonce" || fail P1 "008c nonce differs from 008b's: $(get nonce)"
    [[ "$(get rpcclient)" == t ]] && pass P1 "_rpc_client compiled: approve_policy -> policy, nothing else" || fail P1 "_rpc_client: $(get rpcclient)"
    [[ "$(get changedsince)" == t ]] && pass P1 "iam._changed_since present (or no access component)" || fail P1 "schema iam without iam._changed_since"
fi

if want policy && [[ "$WRITES" == true && "$MODE" != legacy ]]; then
    _u() { python3 -c 'import uuid; print(uuid.uuid4())'; }
    A="$(_u)"; A2="$(_u)"; Q="$(_u)"; Q2="$(_u)"; X="$(_u)"
    _h="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
    PA="p-pa-$_h"; PQ="p-pq-$_h"; PQ2="p-pq2-$_h"
    IAT=$(( $(date +%s) - 120 ))   # a token issued two minutes ago: rows written now are newer
    DD="$(printf 'iam-db diff %s' "$_h" | sha256sum | cut -d' ' -f1)"
    sqlq() { if [[ -n "${1:-}" ]]; then printf "'%s'" "${1//\'/\'\'}"; else printf "''"; fi; }
    # the factory policy's rows and a reduced skeleton (its role and group keys), from Python
    P_SKEL=""; P_DG=""; P_ENTRIES=""; P_WAIVERS=""; P_ED=""
    eval "$(python3 - "$REPO_ROOT" <<'PY'
import hashlib, json, shlex, sys
sys.path.insert(0, sys.argv[1] + "/apps/iam")
from compiler import source
d = source.factory()
body = {"roles": {r: {"db_role": rd.get("db_role", "rr_" + r), "includes": list(rd.get("includes") or [])}
                  for r, rd in d["roles"].items()},
        "resource_groups": {g: {"class": gd["class"]} for g, gd in d["resource_groups"].items()}}
ew = source.entries_and_waivers(d)
ws = [source.waiver_row(w) for w in ew["waivers"]]
out = {"P_SKEL": json.dumps(body, sort_keys=True), "P_DG": hashlib.sha256(source.canonical(body)).hexdigest(),
       "P_ENTRIES": json.dumps(ew["entries"]), "P_WAIVERS": json.dumps(ws),
       "P_ED": source.entries_digest("bootstrap", list(body["resource_groups"]), list(body["roles"]), ew["entries"], ws)}
for k, v in out.items():
    assert "$j$" not in v
    print(f"{k}={shlex.quote(v)}")
PY
)" || { fail policy "cannot compute the factory rows (python3, compiler/source.py)"; P_SKEL=""; }

    clear_actor() {
        echo 'DO $c$ BEGIN IF pg_catalog.to_regclass($q$pg_temp.medcea_actor$q$) IS NOT NULL THEN DELETE FROM pg_temp.medcea_actor; END IF; END $c$;'
    }
    # clear_marker — _begin()'s iam_policy.transition is transaction-local and outlives the
    # function that set it, so a probe's own write after build_v1/draft_chain would carry the
    # last function's marker; the "without a marker" probes need none, the forged ones set theirs
    clear_marker() {
        echo "SELECT pg_catalog.set_config('iam_policy.transition', '', true) \\g /dev/null"
    }
    # build_v1 [record|no-record] [CLAIMED_SUB CLAIMED_PERSON] — version 1 (bootstrap) applied: :v1
    build_v1() {
        as_postgres
        local by_sub=NULL by_person=NULL
        [[ -n "${2:-}" ]] && by_sub="'$2'::uuid" && by_person="$(sqlq "$3")"
        cat <<SQL
SELECT iam_policy._accept_skeleton('$P_DG', \$j\$$P_SKEL\$j\$::jsonb, 'iam-db', NULL, '{}'::jsonb) \\g /dev/null
SELECT iam_policy._sync_skeleton(\$j\$$P_SKEL\$j\$::jsonb, 'iam-db') \\g /dev/null
SELECT iam_policy._build_version('bootstrap', \$j\$$P_ENTRIES\$j\$::jsonb, \$j\$$P_WAIVERS\$j\$::jsonb, NULL, NULL, 'iam-db probe') AS v1 \\gset
SELECT iam_policy._mark_applied(:v1, '{"git_commit": "iam-db"}'::jsonb, 'iam-db', $by_sub, $by_person, NULL) \\g /dev/null
SQL
        [[ "${1:-record}" == record ]] && echo "SELECT iam_policy._record('bootstrap_applied', jsonb_build_object('version', :v1)) \\g /dev/null"
        clear_actor
        clear_marker
    }
    # as_iam SUB PERSON NAME ROLE — iam-api (iam_svc) acting for that person
    as_iam() {
        printf 'RESET ROLE;\nRESET SESSION AUTHORIZATION;\nSET SESSION AUTHORIZATION iam_svc;\n'
        echo "SELECT medcea_auth.set_actor('$1', $(sqlq "$2"), '$3', '$4') \\g /dev/null"
    }
    # as_system NAME — postgres acting as an internal actor (apply.sh's system:apply, a
    # deploy's system:deploy), with no person actor left over from an earlier step
    as_system() {
        as_postgres
        clear_actor
        echo "SELECT medcea_auth._set_internal_actor('$1') \\g /dev/null"
    }
    # draft_chain [EDITOR_SUB EDITOR_PERSON] — admin A drafts from the applied version, an
    # editor (default A) saves one cell, A submits: :d submitted, :ed its entries digest
    draft_chain() {
        as_iam "$A" "$PA" test-pa admin
        echo "SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset"
        [[ -n "${1:-}" ]] && as_iam "$1" "$2" test-editor admin
        cat <<SQL
SELECT iam_policy.save_entry(:d, 'qa', 'portal', '{"R": null, "X": null}'::jsonb, 'iam-db probe',
                             '{"ok": true, "errors": [], "checker_digest": "iam-db"}'::jsonb, $IAT) \\g /dev/null
SQL
        as_iam "$A" "$PA" test-pa admin
        echo "SELECT iam_policy.submit(:d, 'iam-db probe', $IAT) AS ed \\gset"
        clear_marker
    }
    # pclaims SUB PERSON [AZP] [ROLE] — a policy-host token's claims, iat two minutes ago
    pclaims() {
        printf '{"typ":"Bearer","azp":"%s","aud":"medcea-api","sub":"%s","person_id":"%s","preferred_username":"test-%s","groups":["%s"],"iat":%s,"exp":%s,"jti":"%s"}' \
            "${3:-policy}" "$1" "$2" "${2:-none}" "${4:-qa}" "$IAT" "$((IAT + 300))" "$(_u)"
    }
    # an unsigned JWS whose payload is the claims (the database compares, apply.sh verifies)
    jws_of() { python3 -c 'import base64,sys; b=lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("="); print(b("{\"alg\":\"RS256\",\"kid\":\"iam-db\"}") + "." + b(sys.argv[1]) + ".c2ln")' "$1"; }
    # qa_token CLAIMS METHOD PATH [header|no-header] — PostgREST's session for that token
    qa_token() {
        as_postgres
        clear_actor
        cat <<SQL
SET SESSION AUTHORIZATION authenticator;
SET ROLE anon;
SELECT set_config('request.jwt.claims', '$1', true), set_config('request.method', '$2', true),
       set_config('request.path', '$3', true) \\g /dev/null
SQL
        [[ "${4:-header}" == header ]] && echo "SELECT set_config('request.headers', '{\"authorization\": \"Bearer $(jws_of "$1")\"}', true) \\g /dev/null"
        echo "SELECT medcea_auth.pre_request() \\g /dev/null"
    }
    approve_sql() { echo "SELECT medcea.approve_policy(:d, 'iam-db note', ${1:-:'ed'}, '$DD', '${2:-$P_DG}');"; }
    QA_CLAIMS="$(pclaims "$Q" "$PQ")"

    if [[ -z "$P_SKEL" ]]; then
        :
    else
    # P2 — the entries digest: SQL equals compiler/source.py for the same rows
    probe P2 "version 1 built and applied through the owner functions; entries_digest = source.entries_digest" ok <<SQL
$(build_v1)
--CHECKS
SELECT 'CHECK|SQL digest = Python digest', iam_policy.entries_digest(:v1) = '$P_ED';
SELECT 'CHECK|stored at build', entries_digest = '$P_ED' FROM iam_policy.version WHERE version = :v1;
SELECT 'CHECK|bootstrap, applied, the accepted skeleton', kind = 'bootstrap' AND status = 'applied' AND skeleton_digest = '$P_DG'
  FROM iam_policy.version WHERE version = :v1;
SELECT 'CHECK|accepted', iam_policy._accepted() = '$P_DG';
SELECT 'CHECK|actor system:apply', bool_and(actor_name = 'system:apply') FROM iam_policy.history
 WHERE version = :v1 AND event IN ('draft_created', 'apply_started');
SELECT 'CHECK|roles and groups synced', (SELECT count(*) FROM iam_policy.role WHERE NOT retired) = 11
       AND (SELECT count(*) FROM iam_policy.resource_group WHERE NOT retired) = $(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])['resource_groups']))" "$P_SKEL");
SQL
    # P3 — the freeze trigger
    probe P3 "medcea_owner without a marker: UPDATE version" "42501:written only by the policy functions" <<SQL
$(build_v1)
SET ROLE medcea_owner;
UPDATE iam_policy.version SET reason = 'forged' WHERE version = :v1;
SQL
    probe P3 "postgres (superuser) without a marker: DELETE version" "42501:written only by the policy functions" <<SQL
$(build_v1)
DELETE FROM iam_policy.version WHERE version = :v1;
SQL
    probe P3 "medcea_owner with a forged marker: DELETE version" "42501:never deleted" <<SQL
$(build_v1)
SET ROLE medcea_owner;
SELECT set_config('iam_policy.transition', '_mark_applied:' || :v1 || ':' || txid_current(), true) \\g /dev/null
DELETE FROM iam_policy.version WHERE version = :v1;
SQL
    probe P3 "TRUNCATE approval_evidence" "42501:cannot be truncated" <<SQL
$(build_v1)
TRUNCATE iam_policy.approval_evidence;
SQL
    probe P3 "an entry for an applied version, even with a marker" "22023:are frozen" <<SQL
$(build_v1)
SET ROLE medcea_owner;
SELECT set_config('iam_policy.transition', 'save_entry:' || :v1 || ':' || txid_current(), true) \\g /dev/null
INSERT INTO iam_policy.entry (version, role, group_code, level) VALUES (:v1, 'operator', 'portal', 'X');
SQL
    probe P3 "a transition no function makes (applied -> draft)" "22023:is not a transition" <<SQL
$(build_v1)
SET ROLE medcea_owner;
SELECT set_config('iam_policy.transition', 'submit:' || :v1 || ':' || txid_current(), true) \\g /dev/null
UPDATE iam_policy.version SET status = 'draft' WHERE version = :v1;
SQL
    probe P3 "a column outside the function's edge" "42501:may not change" <<SQL
$(build_v1)
SET ROLE medcea_owner;
SELECT set_config('iam_policy.transition', 'save_entry:' || :v1 || ':' || txid_current(), true) \\g /dev/null
UPDATE iam_policy.version SET reason = 'forged' WHERE version = :v1;
SQL
    probe P3 "a stored skeleton's body" "42501:never changes" <<SQL
$(build_v1)
SET ROLE medcea_owner;
SELECT set_config('iam_policy.transition', '_accept_skeleton::' || txid_current(), true) \\g /dev/null
UPDATE iam_policy.skeleton SET body = '{}'::jsonb WHERE digest = '$P_DG';
SQL
    # P5/P4 — the author path, its columns and events
    probe P5 "admin through iam_svc: new_draft, save_entry, submit" ok <<SQL
$(build_v1)
$(draft_chain)
--CHECKS
SELECT 'CHECK|submitted change on v1', status = 'submitted' AND kind = 'change' AND based_on = :v1 FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|created and submitted by A', created_by_sub = '$A' AND created_by_person = '$PA' AND submitted_by_person = '$PA'
          AND submitted_by_sub = '$A' FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|digests', entries_digest = :'ed' AND entries_digest = iam_policy.entries_digest(:d) AND skeleton_digest = '$P_DG'
          AND checker_verdict FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|the cell, one row per level', array_agg(level::text ORDER BY level) = '{R,X}'
  FROM iam_policy.entry WHERE version = :d AND role = 'qa' AND group_code = 'portal';
SELECT 'CHECK|the rest copied from v1', (SELECT count(*) FROM iam_policy.entry WHERE version = :d AND NOT (role = 'qa' AND group_code = 'portal'))
          = (SELECT count(*) FROM iam_policy.entry WHERE version = :v1 AND NOT (role = 'qa' AND group_code = 'portal'));
SELECT 'CHECK|draft_created, entry_saved, submitted by A', array_agg(event ORDER BY event_id) = '{draft_created,entry_saved,submitted}'
          AND bool_and(actor_sub = '$A' AND actor_person = '$PA')
  FROM iam_policy.history WHERE version = :d AND event <> 'status_changed';
SELECT 'CHECK|_authors is A', (SELECT array_agg(sub || '/' || person) FROM iam_policy._authors(:d)) = ARRAY['$A/$PA'];
SQL
    probe P4 "every status change is a status_changed event, every policy event names its version" ok <<SQL
$(build_v1)
$(draft_chain)
--CHECKS
SELECT 'CHECK|status_changed for d', array_agg(coalesce(payload ->> 'from', '-') || '>' || (payload ->> 'to') || ':' || (payload ->> 'by_function') ORDER BY event_id)
          = '{->draft:new_draft,draft>submitted:submit}' FROM iam_policy.history WHERE version = :d AND event = 'status_changed';
SELECT 'CHECK|status_changed for v1', array_agg(coalesce(payload ->> 'from', '-') || '>' || (payload ->> 'to') ORDER BY event_id)
          = '{->draft,draft>applied}' FROM iam_policy.history WHERE version = :v1 AND event = 'status_changed';
SELECT 'CHECK|version in every payload', bool_and(payload ? 'version') FROM iam_policy.history
 WHERE version IN (:v1, :d);
SELECT 'CHECK|chain ok', ok FROM iam_policy.verify_chain();
SQL
    probe P5 "new_draft before any version is applied" "22023:no policy version is applied" <<SQL
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
    probe P5 "admin through iam_svc: withdraw the submitted change, then a new draft" ok <<SQL
$(build_v1)
$(draft_chain)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.withdraw(:d, 'iam-db probe', $IAT) \\g /dev/null
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d2 \\gset
--CHECKS
SELECT 'CHECK|withdrawn by A', status = 'withdrawn' AND withdrawn_by = '$PA' AND withdrawn_by_sub = '$A' AND withdrawn_at IS NOT NULL
  FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|a withdrawn event', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d AND event = 'withdrawn'
                                           AND actor_sub = '$A' AND actor_person = '$PA');
SELECT 'CHECK|status_changed submitted>withdrawn:withdraw', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d
          AND event = 'status_changed' AND payload ->> 'from' = 'submitted' AND payload ->> 'to' = 'withdrawn'
          AND payload ->> 'by_function' = 'withdraw');
SELECT 'CHECK|the new draft is open (one_open freed)', status = 'draft' FROM iam_policy.version WHERE version = :d2;
SQL
    probe P5 "withdraw the applied bootstrap version" "22023:is not open" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.withdraw(:v1, 'iam-db probe', $IAT);
SQL
    # (_withdraw_open, _mark_reverted and _propose_skeleton, apply.sh's: P19-P21, IAM 4.2a)
    # P18 — iam_svc may append its own event (iam-api's, the only one since 4.2a), never a
    # policy version event
    probe P18 "iam_svc appends mqtt_credential_issued, as iam-api does (the control)" ok <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.append_history('mqtt_credential_issued', '{"username": "explorer-iam-db"}'::jsonb, 'iam-db') \\g /dev/null
--CHECKS
SELECT 'CHECK|appended for A', EXISTS (SELECT 1 FROM iam_policy.history WHERE event = 'mqtt_credential_issued' AND actor_sub = '$A'
                                       AND event_id = (SELECT max(event_id) FROM iam_policy.history));
SQL
    for ev in applied status_changed entry_saved skeleton_accepted break_glass_seen break_glass_ended account_seeded; do
        probe P18 "iam_svc forges '$ev' for the half-applied version" "42501:is a policy version event" <<SQL
$(build_v1 no-record)
RESET ROLE;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION iam_svc;
SELECT iam_policy.append_history('$ev', jsonb_build_object('version', :v1), 'forged');
SQL
    done
    probe P18 "iam_svc calls the writer itself" "42501:permission denied for function _append_history" <<SQL
$(build_v1 no-record)
RESET ROLE;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION iam_svc;
SELECT iam_policy._append_history('applied', jsonb_build_object('version', :v1), 'forged');
SQL
    # P6 — who may author
    probe P6 "a blank person_id" "42501:carries no person_id" <<SQL
$(build_v1)
$(as_iam "$A" "" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
    probe P6 "a role without C on iam_policy (qa)" "42501:holds no C on iam_policy" <<SQL
$(build_v1)
$(as_iam "$Q" "$PQ" test-pq qa)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
    if [[ "$(q1 "SELECT to_regprocedure('medcea_auth.set_actor(text,text,text,text)') IS NOT NULL AND EXISTS (SELECT FROM pg_roles WHERE rolname = 'access_svc')")" == t ]]; then
        probe P6 "set_actor through access_svc (source person via access_svc)" "42501:made in the Policy UI" <<SQL
$(build_v1)
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION access_svc;
SELECT medcea_auth.set_actor('$A', '$PA', 'test-pa', 'admin') \\g /dev/null
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION iam_svc;
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
    fi
    probe P6 "access changed since the token's iat (a status history row)" "42501:your access changed since you signed in" <<SQL
$(build_v1)
INSERT INTO iam.user_status_history (keycloak_user_id, username, action, reason, actor) VALUES ('$A', 'test-pa', 'deactivated', 'iam-db probe', 'iam-db');
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
    # P11 — one version in flight; a bootstrap does not count (P5 drafted after one)
    probe P11 "a second change draft" "23505:still open" <<SQL
$(build_v1)
$(draft_chain)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
    probe P11 "the unique index backs it (a second open row inserted under a marker)" "23505:one_open" <<SQL
$(build_v1)
$(draft_chain)
$(as_postgres)
SET ROLE medcea_owner;
SELECT set_config('iam_policy.transition', 'new_draft::' || txid_current(), true) \\g /dev/null
INSERT INTO iam_policy.version (version, status, kind, reason, based_on) VALUES (:d + 1, 'draft', 'change', 'forged', :v1);
SQL
    # P13 — pgAdmin's login cannot move a status (under false it has no USAGE on the schema at all)
    p13="42501:permission denied for table version"
    [[ "$MODE" == true ]] || p13="42501:permission denied for schema iam_policy"
    probe P13 "rr_admin_login: UPDATE iam_policy.version SET status = 'approved'" "$p13" <<SQL
$(build_v1)
SET SESSION AUTHORIZATION rr_admin_login;
UPDATE iam_policy.version SET status = 'approved';
SQL
    # P14 — no draft while the applied version's apply is open
    probe P14 "new_draft while the applied version's latest event is apply_started" "22023:is being applied" <<SQL
$(build_v1 no-record)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
    # P15 — the audit and the chain
    probe P15 "audit_versions() on the built versions: no finding" ok <<SQL
$(build_v1)
$(draft_chain)
--CHECKS
SELECT 'CHECK|no finding', NOT EXISTS (SELECT 1 FROM iam_policy.audit_versions());
SQL
    probe P15 "a history row tampered with (triggers off, as postgres)" ok <<SQL
$(build_v1)
ALTER TABLE iam_policy.history DISABLE TRIGGER USER;
UPDATE iam_policy.history SET reason = 'tampered' WHERE event_id = (SELECT max(event_id) FROM iam_policy.history);
--CHECKS
SELECT 'CHECK|verify_chain false', NOT ok FROM iam_policy.verify_chain();
SELECT 'CHECK|audit finding chain', EXISTS (SELECT 1 FROM iam_policy.audit_versions() WHERE finding = 'chain');
SQL
    # P16 — the chain needs READ COMMITTED (append_history), so every owner function does
    probe P16 "an owner function under REPEATABLE READ" "P0001:READ COMMITTED" <<SQL
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
$(build_v1)
SQL
    # P17 — the access guard: without iam._changed_since a policy change fails closed
    probe P17 "iam._changed_since missing: an author function" "55000:need the access component" <<SQL
$(build_v1)
ALTER FUNCTION iam._changed_since(text, text, double precision) RENAME TO _changed_since_gone;
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL

    # ── IAM 4.2a: apply.sh's owner functions, _record's actors, the filter, the deploy's accept ──
    # a second skeleton (another digest, the same keys) for P21 and P25
    P_SKEL2="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["probe"]=True; print(json.dumps(d, sort_keys=True))' "$P_SKEL")"
    P_DG2="$(printf 'iam-db skeleton 2 %s' "$_h" | sha256sum | cut -d' ' -f1)"
    # an account_seeded fact and its content hash (design §14.4.2 item 3: source.pg_jsonb_text)
    seed_fact() {  # USERNAME SUB ROLE PERSON [FACT_ID]
        python3 - "$REPO_ROOT" "$@" <<'PY'
import hashlib, json, sys
sys.path.insert(0, sys.argv[1] + "/apps/iam")
from compiler import source
u, sub, role, person = sys.argv[2:6]
core = {"fact": "observed", "username": u, "sub": sub, "role": role, "person_id": person}
fid = sys.argv[6] if len(sys.argv) > 6 else hashlib.sha256(source.pg_jsonb_text(core).encode()).hexdigest()
print(json.dumps({**core, "created": False, "observed": True, "by": "iam-db", "os_user": "iam-db", "fact_id": fid}))
PY
    }
    SEED="$(seed_fact test-pq "$Q" qa "$PQ")"
    # P19 — _withdraw_open (apply.sh, a rollback withdraws the open change)
    probe P19 "_withdraw_open as system:apply withdraws the open draft" ok <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
$(as_system system:apply)
SELECT iam_policy._withdraw_open('iam-db probe') AS w \\gset
$(clear_marker)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d2 \\gset
--CHECKS
SELECT 'CHECK|returns the draft', :w = :d;
SELECT 'CHECK|withdrawn by system:apply', status = 'withdrawn' AND withdrawn_by = 'system:apply' AND withdrawn_at IS NOT NULL
  FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|withdrawn event', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d AND event = 'withdrawn'
          AND payload ->> 'by' = 'system:apply' AND actor_name = 'system:apply');
SELECT 'CHECK|status_changed draft>withdrawn:_withdraw_open', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d
          AND event = 'status_changed' AND payload ->> 'from' = 'draft' AND payload ->> 'to' = 'withdrawn'
          AND payload ->> 'by_function' = '_withdraw_open');
SELECT 'CHECK|one_open freed: a second draft', status = 'draft' FROM iam_policy.version WHERE version = :d2;
SQL
    probe P19 "_withdraw_open with nothing open: NULL, nothing appended" ok <<SQL
$(build_v1)
$(as_system system:apply)
SELECT max(event_id) AS h0 FROM iam_policy.history \\gset
SELECT iam_policy._withdraw_open('iam-db probe') IS NULL AS none \\gset
--CHECKS
SELECT 'CHECK|NULL', :'none'::boolean;
SELECT 'CHECK|nothing appended', (SELECT max(event_id) FROM iam_policy.history) = :h0;
SQL
    probe P19 "_withdraw_open as system:deploy" "42501:not by system:deploy" <<SQL
$(build_v1)
$(as_system system:deploy)
SELECT iam_policy._withdraw_open('iam-db probe');
SQL
    probe P19 "_withdraw_open as iam_svc" "42501:permission denied for function _withdraw_open" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy._withdraw_open('iam-db probe');
SQL
    # P20 — _mark_reverted's refusals (the positive paths need an approved version: --mode true)
    probe P20 "_mark_reverted with a blank reason" "22023:a reason is required" <<SQL
$(build_v1)
$(as_system system:apply)
SELECT iam_policy._mark_reverted(:v1, NULL, ' ');
SQL
    probe P20 "_mark_reverted of a version that is not applied" "22023:is not the applied one" <<SQL
$(build_v1)
$(draft_chain)
$(as_system system:apply)
SELECT iam_policy._mark_reverted(:d, :v1, 'iam-db probe');
SQL
    # P21 — _propose_skeleton (apply.sh --propose-skeleton, 4.4)
    probe P21 "_propose_skeleton of the accepted skeleton" "22023:nothing to approve" <<SQL
$(build_v1)
$(as_system system:apply)
SELECT iam_policy._propose_skeleton('$P_DG', \$j\$$P_SKEL\$j\$::jsonb, 'iam-db', '{"added": {}}'::jsonb, '$DD',
                                    '$A', '$PA', 'iam-db probe');
SQL
    probe P21 "_propose_skeleton of another skeleton: a submitted skeleton version" ok <<SQL
$(build_v1)
$(as_system system:apply)
SELECT iam_policy._propose_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', '{"added": {"qa": []}}'::jsonb, '$DD',
                                    '$A', '$PA', 'iam-db probe') AS s \\gset
--CHECKS
SELECT 'CHECK|submitted skeleton version on v1', status = 'submitted' AND kind = 'skeleton' AND based_on = :v1
          AND skeleton_digest = '$P_DG2' AND submitted_by_sub = '$A' AND submitted_by_person = '$PA'
  FROM iam_policy.version WHERE version = :s;
SELECT 'CHECK|entries = v1''s', (SELECT count(*) FROM iam_policy.entry WHERE version = :s)
          = (SELECT count(*) FROM iam_policy.entry WHERE version = :v1);
SELECT 'CHECK|entries_digest set', entries_digest IS NOT NULL AND entries_digest = iam_policy.entries_digest(:s)
  FROM iam_policy.version WHERE version = :s;
SELECT 'CHECK|version_diff computed on the host', EXISTS (SELECT 1 FROM iam_policy.version_diff
          WHERE version = :s AND computed_on = 'host' AND diff_digest = '$DD');
SELECT 'CHECK|submitted event', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :s AND event = 'submitted'
          AND payload ->> 'kind' = 'skeleton' AND payload ->> 'skeleton_digest' = '$P_DG2'
          AND payload ->> 'diff_digest' = '$DD');
SELECT 'CHECK|not accepted by proposing', iam_policy._accepted() = '$P_DG';
SQL
    probe P21 "a second skeleton proposal while one is open" "23505:still open" <<SQL
$(build_v1)
$(as_system system:apply)
SELECT iam_policy._propose_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', '{}'::jsonb, '$DD', '$A', '$PA', 'iam-db probe') \\g /dev/null
SELECT iam_policy._propose_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', '{}'::jsonb, '$DD', '$A', '$PA', 'iam-db probe');
SQL
    probe P21 "_propose_skeleton with a blank proposer person" "22023:the proposer (--by)" <<SQL
$(build_v1)
$(as_system system:apply)
SELECT iam_policy._propose_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', '{}'::jsonb, '$DD', '$A', ' ', 'iam-db probe');
SQL
    # P23 — _record's actors, account_seeded, and the filter (critique sec-10, sec-11)
    probe P23 "system:deploy records account_seeded once per content, under the applied version" ok <<SQL
$(build_v1)
$(as_system system:deploy)
SELECT iam_policy._record('account_seeded', \$j\$$SEED\$j\$::jsonb) AS e1 \\gset
SELECT iam_policy._record('account_seeded', \$j\$$SEED\$j\$::jsonb) AS e2 \\gset
--CHECKS
SELECT 'CHECK|the same event id', :e1 = :e2;
SELECT 'CHECK|appended once', count(*) = 1 FROM iam_policy.history
 WHERE event = 'account_seeded' AND payload ->> 'fact_id' = (\$j\$$SEED\$j\$::jsonb ->> 'fact_id');
SELECT 'CHECK|filed under v1 by system:deploy', version = :v1 AND (payload ->> 'version')::int = :v1 AND actor_name = 'system:deploy'
  FROM iam_policy.history WHERE event_id = :e1;
SQL
    probe P23 "account_seeded whose fact_id is not the content hash" "22023:not the content hash" <<SQL
$(build_v1)
$(as_system system:deploy)
SELECT iam_policy._record('account_seeded', \$j\$$(seed_fact test-pq "$Q" qa "$PQ" "$DD")\$j\$::jsonb);
SQL
    for ev in Applied break_glass_end apply_note; do
        probe P23 "iam_svc appends '$ev'" "42501:is a policy version event" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.append_history('$ev', '{}'::jsonb, 'forged');
SQL
    done
    probe P23 "iam_svc appends another service event" "42501:iam_svc writes only mqtt_credential_issued" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.append_history('test_probe', '{}'::jsonb, 'iam-db');
SQL
    probe P23 "iam_svc's mqtt_credential_issued naming a version is filed under none" ok <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.append_history('mqtt_credential_issued', jsonb_build_object('version', :v1, 'username', 'explorer-iam-db'), 'iam-db') AS e \\gset
--CHECKS
SELECT 'CHECK|no version', version IS NULL AND NOT payload ? 'version' FROM iam_policy.history WHERE event_id = :e;
SQL
    probe P23 "break_glass_seen (source file) without an applied version" "22023:needs an applied version" <<SQL
$(as_system system:deploy)
SELECT iam_policy._record('break_glass_seen', '{"source": "file", "reason": "iam-db", "version": null}'::jsonb);
SQL
    probe P23 "system:deploy records 'applied'" "42501:not by system:deploy" <<SQL
$(build_v1)
$(as_system system:deploy)
SELECT iam_policy._record('applied', jsonb_build_object('version', :v1));
SQL
    probe P23 "system:scheduler records account_seeded" "42501:not by system:scheduler" <<SQL
$(build_v1)
$(as_system system:scheduler)
SELECT iam_policy._record('account_seeded', \$j\$$SEED\$j\$::jsonb);
SQL
    # P24 — the 4.1 defect (ops-3): dba_record_event's own SQL reaches _record as system:deploy
    probe P24 "dba_record_event break_glass_seen (Node-RED): through _record, under v1" ok <<SQL
$(build_v1)
\\set ev break_glass_seen
\\set payload '{"identity": "node-red NR_ADMIN_AUTH=off", "ended_by": "iam-db"}'
\\set why 'iam-db probe'
$(_dba_record_event_sql)
--CHECKS
SELECT 'CHECK|filed under v1 by system:deploy with its reason', event = 'break_glass_seen' AND version = :v1
          AND (payload ->> 'version')::int = :v1 AND actor_name = 'system:deploy' AND reason = 'iam-db probe'
  FROM iam_policy.history WHERE event_id = (SELECT max(event_id) FROM iam_policy.history);
SQL
    probe P24 "dba_record_event break_glass_seen with no applied version: filed under none" ok <<SQL
\\set ev break_glass_seen
\\set payload '{"identity": "node-red NR_ADMIN_AUTH=off"}'
\\set why 'iam-db probe'
$(_dba_record_event_sql)
--CHECKS
SELECT 'CHECK|the applied version (none here), system:deploy', event = 'break_glass_seen'
          AND version IS NOT DISTINCT FROM (SELECT x.version FROM iam_policy.version x WHERE x.status = 'applied')
          AND payload ? 'version' AND actor_name = 'system:deploy'
  FROM iam_policy.history WHERE event_id = (SELECT max(event_id) FROM iam_policy.history);
SQL
    # P25 — a deploy's skeleton gate accepts a non-widening skeleton (system:deploy)
    probe P25 "_accept_skeleton and _sync_skeleton as system:deploy; the event names what it replaced" ok <<SQL
$(build_v1)
$(as_system system:deploy)
SELECT iam_policy._accept_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', NULL,
                                   '{"narrowed": [], "unchanged": [], "reviewed_by_version": null}'::jsonb) \\g /dev/null
SELECT iam_policy._sync_skeleton(\$j\$$P_SKEL2\$j\$::jsonb, 'iam-db') \\g /dev/null
--CHECKS
SELECT 'CHECK|accepted', iam_policy._accepted() = '$P_DG2';
SELECT 'CHECK|skeleton_accepted from the earlier digest, by system:deploy', payload ->> 'from' = '$P_DG'
          AND payload ->> 'digest' = '$P_DG2' AND actor_name = 'system:deploy'
  FROM iam_policy.history WHERE event = 'skeleton_accepted' ORDER BY event_id DESC LIMIT 1;
SELECT 'CHECK|the first accept has from null', payload -> 'from' = 'null'::jsonb
  FROM iam_policy.history WHERE event = 'skeleton_accepted' AND payload ->> 'digest' = '$P_DG' ORDER BY event_id DESC LIMIT 1;
SELECT 'CHECK|skeleton_synced by system:deploy', actor_name = 'system:deploy'
  FROM iam_policy.history WHERE event = 'skeleton_synced' ORDER BY event_id DESC LIMIT 1;
SQL
    probe P25 "_accept_skeleton as iam_svc" "42501:permission denied for function _accept_skeleton" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy._accept_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', NULL, '{}'::jsonb);
SQL
    probe P25 "_accept_skeleton as system:scheduler" "42501:not by system:scheduler" <<SQL
$(build_v1)
$(as_system system:scheduler)
SELECT iam_policy._accept_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', NULL, '{}'::jsonb);
SQL

    # ── IAM 4.4: drafting and approval (design §14.7.1, §14.7.8) ──────────────────────
    # a third skeleton: the factory keys plus one group (P33's merge, P35's later accept)
    P_SKEL3="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); g=sorted(d["resource_groups"])[0]; d["resource_groups"]["iam_db_probe"]=dict(d["resource_groups"][g]); print(json.dumps(d, sort_keys=True))' "$P_SKEL")"
    P_DG3="$(printf 'iam-db skeleton 3 %s' "$_h" | sha256sum | cut -d' ' -f1)"
    DD2="$(printf 'iam-db diff 2 %s' "$_h" | sha256sum | cut -d' ' -f1)"
    # a cell of the factory matrix with two levels or more: role, group and its whole level map
    P_CELL2="$(python3 -c '
import json, sys
cells = {}
for e in json.loads(sys.argv[1]):
    cells.setdefault((e["role"], e["group_code"]), {})[e["level"]] = e["constraint_name"]
r, g = sorted(k for k, v in cells.items() if len(v) >= 2)[0]
print("\t".join([r, g, json.dumps(cells[(r, g)], sort_keys=True), sorted(cells[(r, g)])[0]]))' "$P_ENTRIES")"
    IFS=$'\t' read -r C2_ROLE C2_GROUP C2_LEVELS C2_FIRST <<<"$P_CELL2"
    C2_ONE="$(python3 -c 'import json,sys; m=json.loads(sys.argv[1]); print(json.dumps({sys.argv[2]: m[sys.argv[2]]}))' "$C2_LEVELS" "$C2_FIRST")"
    ATTEST='I did not run apply.sh --propose-skeleton for this version.'
    # skel_diff ROLE… — a host diff document from the accepted skeleton (P_DG, or SKEL_FROM) to
    # P_DG2, adding one reach tuple to each ROLE
    skel_diff() {
        python3 - "${SKEL_FROM:-$P_DG}" "$P_DG2" "$@" <<'PY'
import json, sys
roles = {r: {"added": [["route", "iam-db", "GET /probe"]], "removed": []} for r in sys.argv[3:]}
print(json.dumps({"schema": 1, "kind": "skeleton", "skeleton": {"from": sys.argv[1], "to": sys.argv[2], "sections": []},
                  "cells": [], "waivers": {"added": [], "removed": []}, "roles": roles,
                  "system": {"added": [], "removed": []}}, sort_keys=True))
PY
    }
    # propose_skel [ROLE…] — apply.sh --propose-skeleton (system:apply) with --by SKEL_BY /
    # SKEL_BY_PERSON (default the admin A), a diff adding to each ROLE (default engineer):
    # :d the submitted skeleton version (P_DG2, diff digest DD), :ed its entries digest
    propose_skel() {
        local roles=("$@")
        [[ ${#roles[@]} -gt 0 ]] || roles=(engineer)
        as_system system:apply
        cat <<SQL
SELECT iam_policy._propose_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', \$j\$$(skel_diff "${roles[@]}")\$j\$::jsonb, '$DD',
                                    '${SKEL_BY:-$A}', $(sqlq "${SKEL_BY_PERSON:-$PA}"), 'iam-db probe') AS d \\gset
SELECT entries_digest AS ed FROM iam_policy.version WHERE version = :d \\gset
SQL
        clear_actor
        clear_marker
    }
    # skel_approve_sql NOTE [DIFF_DIGEST] [SKELETON_DIGEST] — approve the skeleton version :d
    skel_approve_sql() { echo "SELECT medcea.approve_policy(:d, $(sqlq "$1"), :'ed', '${2:-$DD}', '${3:-$P_DG2}');"; }
    # break_glass COMPONENT… — a policy break-glass (source file) recorded as a deploy does: :bg
    break_glass() {
        local comps
        comps="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@")"
        as_system system:deploy
        echo "SELECT iam_policy._record('break_glass_seen', jsonb_build_object('source', 'file', 'reason', 'iam-db probe', 'components', '$comps'::jsonb, 'file_sha256', '$DD')) AS bg \\gset"
        clear_actor
    }
    # break_glass_end COMPONENT — the next normal deploy of COMPONENT ends :bg for it
    break_glass_end() {
        as_system system:deploy
        echo "SELECT iam_policy._record('break_glass_ended', jsonb_build_object('since_event', :bg, 'component', '$1')) \\g /dev/null"
        clear_actor
    }

    # P31 — withdraw (any admin, owner decision 3): a submitted skeleton version, then again
    probe P31 "an admin withdraws a submitted skeleton version" ok <<SQL
$(build_v1)
$(propose_skel)
$(as_iam "$A2" "p-pa2-$_h" test-pa2 admin)
SELECT iam_policy.withdraw(:d, 'iam-db probe', $IAT) \\g /dev/null
--CHECKS
SELECT 'CHECK|withdrawn by an admin who is no author', status = 'withdrawn' AND withdrawn_by = 'p-pa2-$_h' AND withdrawn_by_sub = '$A2'
  FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|withdrawn event', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d AND event = 'withdrawn');
SQL
    probe P31 "a second withdraw" "22023:is not open" <<SQL
$(build_v1)
$(propose_skel)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.withdraw(:d, 'iam-db probe', $IAT) \\g /dev/null
SELECT iam_policy.withdraw(:d, 'iam-db probe', $IAT);
SQL
    # P32 — submit and save_entry's refusals; save_entry replaces the whole cell
    probe P32 "submit a draft whose checker verdict is false" "22023:does not pass the checker" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
SELECT iam_policy.save_entry(:d, 'qa', 'portal', '{"R": null}'::jsonb, 'iam-db probe',
                             '{"ok": false, "errors": ["iam-db"], "checker_digest": "iam-db"}'::jsonb, $IAT) \\g /dev/null
SELECT iam_policy.submit(:d, 'iam-db probe', $IAT);
SQL
    probe P32 "save_entry on the applied version" "22023:is not a draft" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.save_entry(:v1, 'qa', 'portal', '{"R": null}'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT);
SQL
    probe P32 "save_entry on a submitted skeleton version" "22023:is not a draft" <<SQL
$(build_v1)
$(propose_skel)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.save_entry(:d, 'qa', 'portal', '{"R": null}'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT);
SQL
    probe P32 "save_entry for an unknown role" "22023:no role iam_db_nobody or group portal" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
SELECT iam_policy.save_entry(:d, 'iam_db_nobody', 'portal', '{"R": null}'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT);
SQL
    probe P32 "save_entry for an unknown group" "22023:no role qa or group iam_db_nothing" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
SELECT iam_policy.save_entry(:d, 'qa', 'iam_db_nothing', '{"R": null}'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT);
SQL
    probe P32 "save_entry for a retired group" "22023:no role qa or group portal" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
$(as_postgres)
UPDATE iam_policy.resource_group SET retired = true WHERE code = 'portal';
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.save_entry(:d, 'qa', 'portal', '{"R": null}'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT);
SQL
    probe P32 "save_entry with levels that are not an object" "22023:levels must be an object" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
SELECT iam_policy.save_entry(:d, 'qa', 'portal', '["R"]'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT);
SQL
    probe P32 "save_entry with an unknown level letter" "22023:levels must be an object" <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
SELECT iam_policy.save_entry(:d, 'qa', 'portal', '{"Z": null}'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT);
SQL
    probe P32 "save_entry replaces the whole cell ($C2_ROLE/$C2_GROUP): the full map keeps the digest, one level drops the rest" ok <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
$(as_postgres)
SELECT iam_policy.entries_digest(:d) AS e0 \\gset
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.save_entry(:d, '$C2_ROLE', '$C2_GROUP', '$C2_LEVELS'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT) \\g /dev/null
$(as_postgres)
SELECT iam_policy.entries_digest(:d) AS e1 \\gset
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.save_entry(:d, '$C2_ROLE', '$C2_GROUP', '$C2_ONE'::jsonb, 'iam-db probe', '{"ok": true}'::jsonb, $IAT) \\g /dev/null
--CHECKS
SELECT 'CHECK|the whole cell saved unchanged: entries digest unchanged', :'e0' = :'e1';
SELECT 'CHECK|one level saved: only that row is left', array_agg(level::text) = ARRAY['$C2_FIRST']
  FROM iam_policy.entry WHERE version = :d AND role = '$C2_ROLE' AND group_code = '$C2_GROUP';
SELECT 'CHECK|the digest moved', iam_policy.entries_digest(:d) <> :'e0';
SQL
    # P33 — new_draft from defaults, from a version number, and the merge of a key the base lacks
    probe P33 "new_draft from defaults: the cells and waivers passed" ok <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('defaults', 'iam-db probe', $IAT, \$j\$$P_ENTRIES\$j\$::jsonb, \$j\$$P_WAIVERS\$j\$::jsonb) AS d \\gset
--CHECKS
SELECT 'CHECK|the entries are the factory''s', NOT EXISTS (
          (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :d)
          EXCEPT (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :v1))
       AND NOT EXISTS (
          (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :v1)
          EXCEPT (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :d));
SELECT 'CHECK|the waivers too', (SELECT count(*) FROM iam_policy.waiver WHERE version = :d)
          = (SELECT count(*) FROM iam_policy.waiver WHERE version = :v1);
SELECT 'CHECK|draft_created from defaults', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d
          AND event = 'draft_created' AND payload ->> 'from' = 'defaults');
SQL
    probe P33 "new_draft from a withdrawn version's number" ok <<SQL
$(build_v1)
$(draft_chain)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.withdraw(:d, 'iam-db probe', $IAT) \\g /dev/null
SELECT iam_policy.new_draft(:'d', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d2 \\gset
--CHECKS
SELECT 'CHECK|the rows of the withdrawn version', NOT EXISTS (
          (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :d)
          EXCEPT (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :d2))
       AND (SELECT count(*) FROM iam_policy.entry WHERE version = :d) = (SELECT count(*) FROM iam_policy.entry WHERE version = :d2);
SELECT 'CHECK|its qa/portal cell, not v1''s', array_agg(level::text ORDER BY level) = '{R,X}'
  FROM iam_policy.entry WHERE version = :d2 AND role = 'qa' AND group_code = 'portal';
SELECT 'CHECK|based on the applied version', based_on = :v1 FROM iam_policy.version WHERE version = :d2;
SQL
    probe P33 "new_draft after a deploy added a group: its proposed cell merged, the base's cells kept, no duplicate" ok <<SQL
$(build_v1)
$(as_system system:deploy)
SELECT iam_policy._accept_skeleton('$P_DG3', \$j\$$P_SKEL3\$j\$::jsonb, 'iam-db', NULL, '{"narrowed": [], "unchanged": []}'::jsonb) \\g /dev/null
SELECT iam_policy._sync_skeleton(\$j\$$P_SKEL3\$j\$::jsonb, 'iam-db') \\g /dev/null
$(clear_marker)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT,
    '[{"role": "qa", "group_code": "iam_db_probe", "level": "R", "constraint_name": null},
      {"role": "qa", "group_code": "portal", "level": "K", "constraint_name": null}]'::jsonb, '[]'::jsonb) AS d \\gset
--CHECKS
SELECT 'CHECK|the new key''s cell, once', count(*) = 1 FROM iam_policy.entry
 WHERE version = :d AND role = 'qa' AND group_code = 'iam_db_probe' AND level = 'R';
SELECT 'CHECK|a key the base covers keeps the base''s cell', NOT EXISTS (SELECT 1 FROM iam_policy.entry
          WHERE version = :d AND role = 'qa' AND group_code = 'portal' AND level = 'K');
SELECT 'CHECK|no duplicate rows', count(*) = count(DISTINCT (role, group_code, level)) FROM iam_policy.entry WHERE version = :d;
SELECT 'CHECK|the version''s groups are the accepted skeleton''s', 'iam_db_probe' = ANY (groups) FROM iam_policy.version WHERE version = :d;
SQL
    # P34 — why_not as iam-api asks it (iam_svc, set_actor): never on the token path
    probe P34 "why_not as iam_svc for a qa person: may approve, needs the token path" ok <<SQL
$(build_v1)
$(draft_chain)
$(as_iam "$Q" "$PQ" test-pq qa)
SELECT may_approve AS wm, coalesce(why_not_code, '-') AS wc, needs_token_path AS wn FROM iam_policy.why_not(:d) \\gset
--CHECKS
SELECT 'CHECK|may approve, no code, needs the token path', :'wm'::boolean AND :'wc' = '-' AND :'wn'::boolean;
SQL
    probe P34 "why_not as iam_svc for an admin: not_approver" ok <<SQL
$(build_v1)
$(draft_chain)
$(as_iam "$A2" "p-pa2-$_h" test-pa2 admin)
SELECT may_approve AS wm, coalesce(why_not_code, '-') AS wc FROM iam_policy.why_not(:d) \\gset
--CHECKS
SELECT 'CHECK|not_approver', NOT :'wm'::boolean AND :'wc' = 'not_approver';
SQL
    probe P34 "why_not as iam_svc for a qa person who saved a cell: own_author" ok <<SQL
$(build_v1)
$(draft_chain "$A2" "$PQ")
$(as_iam "$Q" "$PQ" test-pq qa)
SELECT may_approve AS wm, coalesce(why_not_code, '-') AS wc FROM iam_policy.why_not(:d) \\gset
--CHECKS
SELECT 'CHECK|own_author', NOT :'wm'::boolean AND :'wc' = 'own_author';
SQL

    if [[ "$MODE" == true ]]; then
        # P8 — approve, positive, through the token path (the control for P7)
        probe P8 "qa approves through PostgREST with the policy host's token" ok <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
--CHECKS
SELECT 'CHECK|approved by Q', status = 'approved' AND approved_by_person = '$PQ' AND approved_by_sub = '$Q'
          AND approved_skeleton_digest = '$P_DG' AND diff_digest = '$DD' AND approved_iat = $IAT
  FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|one evidence row with the JWS', count(*) = 1 AND bool_and(jws = '$(jws_of "$QA_CLAIMS")' AND event = 'approved')
  FROM iam_policy.approval_evidence WHERE version = :d;
SELECT 'CHECK|approved event', payload ?& ARRAY['version', 'source', 'role', 'person', 'sub', 'iat', 'jti', 'azp', 'entries_digest',
                                                'diff_digest', 'skeleton_digest', 'jws_sha256']
          AND payload ->> 'source' = 'token' AND payload ->> 'azp' = 'policy' AND actor_person = '$PQ'
          AND payload ->> 'jws_sha256' = encode(sha256(convert_to('$(jws_of "$QA_CLAIMS")', 'UTF8')), 'hex')
          AND history.version = :d
  FROM iam_policy.history WHERE version = :d AND event = 'approved';
SELECT 'CHECK|evidence keyed by the event', EXISTS (SELECT 1 FROM iam_policy.approval_evidence e JOIN iam_policy.history h
          ON h.event_id = e.history_id AND h.event = 'approved' WHERE e.version = :d);
SELECT 'CHECK|audit: no finding', NOT EXISTS (SELECT 1 FROM iam_policy.audit_versions());
SQL
        probe P8 "qa returns a submitted change to its draft" ok <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/return_policy)
SELECT medcea.return_policy(:d, 'iam-db: please fix');
--CHECKS
SELECT 'CHECK|back to draft with the note', status = 'draft' AND return_note = 'iam-db: please fix' FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|returned event and evidence', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d AND event = 'returned')
          AND EXISTS (SELECT 1 FROM iam_policy.approval_evidence WHERE version = :d AND event = 'returned');
SQL
        probe P8 "why_not for the qa token: may approve" ok <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT may_approve AS wm, coalesce(why_not_code, '-') AS wc, needs_token_path AS wn FROM iam_policy.why_not(:d) \\gset
--CHECKS
SELECT 'CHECK|may approve, no code, on the token path', :'wm'::boolean AND :'wc' = '-' AND NOT :'wn'::boolean;
SQL
        # P7 — the approve refusals, each after the control above
        probe P7a "iam_svc with set_actor as a qa person" "42501:permission denied for function approve_policy" <<SQL
$(build_v1)
$(draft_chain)
$(as_iam "$Q" "$PQ" test-pq qa)
$(approve_sql)
SQL
        probe P7a "the internal as postgres with a set_actor qa: not token-sourced" "42501:approvals are made by a person signed in through the API" <<SQL
$(build_v1)
$(draft_chain)
$(as_postgres)
SELECT medcea_auth.set_actor('$Q', '$PQ', 'test-pq', 'qa') \\g /dev/null
SELECT iam_policy.approve(:d, 'iam-db note', :'ed', '$DD', '$P_DG');
SQL
        probe P7b "hand-set claims and no Authorization header" "42501:needs the signed token as evidence" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy no-header)
$(approve_sql)
SQL
        probe P7b "a header whose token is not the verified one" "42501:not the one verified" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy no-header)
SELECT set_config('request.headers', '{"authorization": "Bearer $(jws_of "$(pclaims "$Q2" "$PQ2")")"}', true) \\g /dev/null
$(approve_sql)
SQL
        probe P7c "a Config UI token (azp config)" "42501:approve access-policy versions in the Policy UI" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$(pclaims "$Q" "$PQ" config)" POST /rpc/approve_policy)
$(approve_sql)
SQL
        probe P7d "a blank person_id" "42501:carries no person_id" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$(pclaims "$Q" "")" POST /rpc/approve_policy)
$(approve_sql)
SQL
        probe P7e "an author by entry_saved only (another account of the approver's person)" "42501:you are an author" <<SQL
$(build_v1)
$(draft_chain "$A2" "$PQ")
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
SQL
        probe P7f "a stale based_on" "22023:was drafted on version" <<SQL
$(build_v1)
$(draft_chain)
$(as_postgres)
ALTER TABLE iam_policy.version DISABLE TRIGGER freeze_policy_trg;
UPDATE iam_policy.version SET based_on = NULL WHERE version = :d;
ALTER TABLE iam_policy.version ENABLE ALWAYS TRIGGER freeze_policy_trg;
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
SQL
        probe P7g "an entries_digest mismatch" "22023:changed since you opened it" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql "'$(printf '0%.0s' {1..64})'")
SQL
        probe P7h "a skeleton digest other than the accepted one" "22023:another platform skeleton" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql ":'ed'" "$(printf 'f%.0s' {1..64})")
SQL
        probe P7i "a confirmed person_id decision about another account of the approver's person, after the iat" "42501:your access changed since you signed in" <<SQL
$(build_v1)
$(draft_chain)
$(as_postgres)
INSERT INTO iam.account_decision (kind, keycloak_user_id, username, subject_person, new_person_id, widens, status, reason,
                                  made_by_name, checked_by_name, checked_by_person, checked_at)
VALUES ('person_id', '$X', 'test-other', '$PQ', 'p-new-$_h', true, 'confirmed', 'iam-db probe', 'iam-db', 'iam-db', 'p-checker-$_h', now());
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
SQL
        probe P7 "an author returns their own version" "42501:you are an author" <<SQL
$(build_v1)
$(draft_chain "$A2" "$PQ")
$(qa_token "$QA_CLAIMS" POST /rpc/return_policy)
SELECT medcea.return_policy(:d, 'iam-db');
SQL
        # P9 — pre_request's only_rpc block for the policy host's tokens
        probe P9 "policy token: GET /recipe" "28000:may only call" <<SQL
$(qa_token "$QA_CLAIMS" GET /recipe)
SQL
        probe P9 "policy token: POST /rpc/approve_change" "28000:may only call" <<SQL
$(qa_token "$QA_CLAIMS" POST /rpc/approve_change)
SQL
        probe P9 "policy token: POST /rpc/approve_policy -> rr_qa" ok <<SQL
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT current_user AS cu \\gset
--CHECKS
SELECT 'CHECK|SET LOCAL ROLE rr_qa', :'cu' = 'rr_qa';
SQL
        # P10 — G9: a blank person_id is no approver anywhere (approve_change too)
        probe P10 "approve_recipe with a person_id: past the approver (control)" "22023:does not exist" <<SQL
$(qa_token "$(pclaims "$Q" "$PQ" config)" POST /rpc/approve_recipe)
SELECT medcea.approve_recipe(-1, 'iam-db');
SQL
        probe P10 "approve_recipe with a blank person_id (passed before 4.1)" "42501:carries no person_id" <<SQL
$(qa_token "$(pclaims "$Q" "" config)" POST /rpc/approve_recipe)
SELECT medcea.approve_recipe(-1, 'iam-db');
SQL
        # P12 — confirm and dispute a bootstrap version
        probe P12 "confirm by another qa person" ok <<SQL
$(build_v1 record "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:v1, 'iam-db', 'I did not run apply.sh for this version.');
--CHECKS
SELECT 'CHECK|confirmed by Q', confirmed_by_person = '$PQ' AND confirmed_at IS NOT NULL FROM iam_policy.version WHERE version = :v1;
SELECT 'CHECK|confirmed event', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :v1 AND event = 'confirmed');
SQL
        probe P12 "confirm by the person apply.sh recorded" "42501:recorded you as running" <<SQL
$(build_v1 record "$Q" "$PQ")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:v1, 'iam-db', 'I did not run apply.sh for this version.');
SQL
        probe P12 "confirm without the attestation" "22023:needs the attestation" <<SQL
$(build_v1 record "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:v1, 'iam-db', 'yes');
SQL
        probe P12 "dispute, then confirm" "22023:already disputed" <<SQL
$(build_v1 record "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/dispute_policy)
SELECT medcea.dispute_policy(:v1, 'iam-db: not what was agreed');
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:v1, 'iam-db', 'I did not run apply.sh for this version.');
SQL
        # P20 — _mark_reverted: an approved change applied, then reverted (a full revert)
        probe P20 "apply an approved change, then _mark_reverted puts v1 back" ok <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
$(as_system system:apply)
SELECT iam_policy._mark_applied(:d, '{"git_commit": "iam-db"}'::jsonb, 'iam-db', NULL, NULL, NULL) \\g /dev/null
SELECT status = 'superseded' AS sup FROM iam_policy.version WHERE version = :v1 \\gset
SELECT iam_policy._mark_reverted(:d, :v1, 'iam-db probe') \\g /dev/null
--CHECKS
SELECT 'CHECK|v1 was superseded by the apply', :'sup'::boolean;
SELECT 'CHECK|the change back to approved', status = 'approved' AND applied_at IS NULL FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|v1 applied again', status = 'applied' AND superseded_at IS NULL FROM iam_policy.version WHERE version = :v1;
SELECT 'CHECK|apply_reverted with decisions_in_window', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d
          AND event = 'apply_reverted' AND payload ? 'decisions_in_window' AND (payload ->> 'prev')::int = :v1);
SELECT 'CHECK|status_changed on both', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d AND event = 'status_changed'
          AND payload ->> 'to' = 'approved' AND payload ->> 'by_function' = '_mark_reverted')
          AND EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :v1 AND event = 'status_changed'
          AND payload ->> 'to' = 'applied' AND payload ->> 'by_function' = '_mark_reverted');
SQL
        probe P20 "a rollback version applied, then reverted: withdrawn, never approved (F-16)" ok <<SQL
$(build_v1 record "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:v1, 'iam-db', 'I did not run apply.sh for this version.') \\g /dev/null
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
$(as_system system:apply)
SELECT iam_policy._mark_applied(:d, '{"git_commit": "iam-db"}'::jsonb, 'iam-db', NULL, NULL, NULL) \\g /dev/null
SELECT iam_policy._withdraw_open('iam-db probe') IS NULL AS none_open \\gset
SELECT iam_policy._build_version('rollback', \$j\$$P_ENTRIES\$j\$::jsonb, \$j\$$P_WAIVERS\$j\$::jsonb, :d, :v1, 'iam-db rollback') AS r \\gset
SELECT iam_policy._mark_applied(:r, '{"git_commit": "iam-db"}'::jsonb, 'iam-db', NULL, NULL, NULL) \\g /dev/null
SELECT iam_policy._mark_reverted(:r, :d, 'iam-db probe') \\g /dev/null
--CHECKS
SELECT 'CHECK|nothing was open', :'none_open'::boolean;
SELECT 'CHECK|the rollback withdrawn by system:apply', status = 'withdrawn' AND withdrawn_by = 'system:apply' AND kind = 'rollback'
          AND rollback_of = :v1 FROM iam_policy.version WHERE version = :r;
SELECT 'CHECK|the change applied again', status = 'applied' FROM iam_policy.version WHERE version = :d;
SQL
        # ── IAM 4.4 on the token path (design §14.7.1, §14.7.8) ──
        # P27 — no approval while a policy break-glass (source file) is open
        probe P27 "approve while a policy break-glass is open for frontend and iam" "22023:a policy break-glass is open" <<SQL
$(build_v1)
$(draft_chain)
$(break_glass frontend iam)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
SQL
        probe P27 "the frontend's deploy ended it: still open, naming iam only" "22023:approvals wait until a normal deploy of iam ends it" <<SQL
$(build_v1)
$(draft_chain)
$(break_glass frontend iam)
$(break_glass_end frontend)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
SQL
        probe P27 "why_not while it is open: break_glass_open" ok <<SQL
$(build_v1)
$(draft_chain)
$(break_glass frontend iam)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT may_approve AS wm, coalesce(why_not_code, '-') AS wc FROM iam_policy.why_not(:d) \\gset
--CHECKS
SELECT 'CHECK|break_glass_open', NOT :'wm'::boolean AND :'wc' = 'break_glass_open';
SQL
        probe P27 "both components ended: approved (a break-glass of another source never blocks)" ok <<SQL
$(build_v1)
$(draft_chain)
$(break_glass frontend iam)
$(break_glass_end frontend)
$(break_glass_end iam)
$(as_system system:deploy)
SELECT iam_policy._record('break_glass_seen', '{"source": "node-red", "reason": "iam-db probe", "components": ["node-red"]}'::jsonb) \\g /dev/null
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
--CHECKS
SELECT 'CHECK|approved', status = 'approved' FROM iam_policy.version WHERE version = :d;
SQL
        # P28 — approving a skeleton version (apply.sh --propose-skeleton's, P21)
        probe P28 "a diff digest other than the stored one" "22023:the diff you saw is not the one the host stored" <<SQL
$(build_v1)
$(propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST iam-db" "$DD2")
SQL
        probe P28 "the accepted skeleton's digest instead of the proposed one" "22023:another platform skeleton" <<SQL
$(build_v1)
$(propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST iam-db" "$DD" "$P_DG")
SQL
        probe P28 "a note without the attestation" "22023:needs the attestation" <<SQL
$(build_v1)
$(propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "iam-db: reviewed the diff")
SQL
        probe P28 "the attestation with nothing after it" "22023:needs the attestation" <<SQL
$(build_v1)
$(propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST   ")
SQL
        probe P28 "the attestation not at the start of the note" "22023:needs the attestation" <<SQL
$(build_v1)
$(propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "iam-db: $ATTEST")
SQL
        probe P28 "qa approves a skeleton version with both digests and the attestation" ok <<SQL
$(build_v1)
$(propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST iam-db: reviewed the diff")
--CHECKS
SELECT 'CHECK|approved by Q, both digests stored', status = 'approved' AND approved_by_person = '$PQ' AND diff_digest = '$DD'
          AND approved_skeleton_digest = '$P_DG2' FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|the attested note stored whole', approval_note = $(sqlq "$ATTEST iam-db: reviewed the diff")
  FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|on the chain as the approved event''s reason', reason = $(sqlq "$ATTEST iam-db: reviewed the diff")
          AND payload ->> 'skeleton_digest' = '$P_DG2' AND payload ->> 'diff_digest' = '$DD'
  FROM iam_policy.history WHERE version = :d AND event = 'approved';
SQL
        probe P28 "the --by person approves the skeleton version" "42501:you are an author" <<SQL
$(build_v1)
$(SKEL_BY="$Q" SKEL_BY_PERSON="$PQ" propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST iam-db")
SQL
        # P29 — the approval's own inputs (a change version)
        probe P29 "no diff digest" "22023:the approval names no diff digest" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT medcea.approve_policy(:d, 'iam-db note', :'ed', NULL, '$P_DG');
SQL
        probe P29 "a diff digest that is not hex" "22023:the approval names no diff digest" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT medcea.approve_policy(:d, 'iam-db note', :'ed', '$(printf 'Z%.0s' {1..64})', '$P_DG');
SQL
        probe P29 "a blank note" "22023:a note is required" <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT medcea.approve_policy(:d, '  ', :'ed', '$DD', '$P_DG');
SQL
        # P30 — return: a skeleton version ends withdrawn; a change goes back to its draft
        probe P30 "qa returns a skeleton version: withdrawn, with the note" ok <<SQL
$(build_v1)
$(propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/return_policy)
SELECT medcea.return_policy(:d, 'iam-db: propose it again') \\g /dev/null
--CHECKS
SELECT 'CHECK|withdrawn, returned_at and return_note', status = 'withdrawn' AND returned_at IS NOT NULL
          AND return_note = 'iam-db: propose it again' AND withdrawn_by = '$PQ' FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|returned event and evidence', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d AND event = 'returned')
          AND EXISTS (SELECT 1 FROM iam_policy.approval_evidence WHERE version = :d AND event = 'returned');
SQL
        probe P30 "a returned change: saved again, submitted again, approved" ok <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/return_policy)
SELECT medcea.return_policy(:d, 'iam-db: please fix') \\g /dev/null
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.save_entry(:d, 'qa', 'portal', '{"R": null}'::jsonb, 'iam-db probe',
                             '{"ok": true, "errors": [], "checker_digest": "iam-db"}'::jsonb, $IAT) \\g /dev/null
SELECT iam_policy.submit(:d, 'iam-db probe', $IAT) AS ed \\gset
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
--CHECKS
SELECT 'CHECK|approved with the new digest', status = 'approved' AND entries_digest = :'ed' AND returned_at IS NOT NULL
  FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|returned, then submitted and approved', (SELECT array_agg(event ORDER BY event_id) FROM iam_policy.history
          WHERE version = :d AND event IN ('returned', 'submitted', 'approved')) = '{submitted,returned,submitted,approved}';
SQL
        # P31 — withdrawing an approved version: by an admin, or by apply.sh --withdraw-open
        probe P31 "an admin withdraws an approved change" ok <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
$(as_iam "$A2" "p-pa2-$_h" test-pa2 admin)
SELECT iam_policy.withdraw(:d, 'iam-db probe', $IAT) \\g /dev/null
--CHECKS
SELECT 'CHECK|withdrawn after approval', status = 'withdrawn' AND approved_at IS NOT NULL AND withdrawn_by = 'p-pa2-$_h'
  FROM iam_policy.version WHERE version = :d;
SELECT 'CHECK|status_changed approved>withdrawn', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :d
          AND event = 'status_changed' AND payload ->> 'from' = 'approved' AND payload ->> 'to' = 'withdrawn');
SQL
        probe P31 "_withdraw_open withdraws an approved version (apply.sh --withdraw-open)" ok <<SQL
$(build_v1)
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
$(as_system system:apply)
SELECT iam_policy._withdraw_open('iam-db probe') AS w \\gset
--CHECKS
SELECT 'CHECK|returns it', :w = :d;
SELECT 'CHECK|withdrawn by system:apply', status = 'withdrawn' AND withdrawn_by = 'system:apply' FROM iam_policy.version WHERE version = :d;
SQL
        # P35 — a skeleton version whose proposal a later accept made stale
        probe P35 "approve after a deploy accepted another skeleton" "22023:was proposed against skeleton" <<SQL
$(build_v1)
$(propose_skel)
$(as_system system:deploy)
SELECT iam_policy._accept_skeleton('$P_DG3', \$j\$$P_SKEL3\$j\$::jsonb, 'iam-db', NULL, '{"narrowed": [], "unchanged": []}'::jsonb) \\g /dev/null
$(clear_marker)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST iam-db")
SQL
        probe P35 "why_not for it: stale_skeleton" ok <<SQL
$(build_v1)
$(propose_skel)
$(as_system system:deploy)
SELECT iam_policy._accept_skeleton('$P_DG3', \$j\$$P_SKEL3\$j\$::jsonb, 'iam-db', NULL, '{"narrowed": [], "unchanged": []}'::jsonb) \\g /dev/null
$(clear_marker)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT may_approve AS wm, coalesce(why_not_code, '-') AS wc FROM iam_policy.why_not(:d) \\gset
--CHECKS
SELECT 'CHECK|stale_skeleton', NOT :'wm'::boolean AND :'wc' = 'stale_skeleton';
SQL
        probe P35 "a proposal whose stored diff names another 'from'" "22023:was proposed against skeleton" <<SQL
$(build_v1)
$(SKEL_FROM="$P_DG3" propose_skel)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST iam-db")
SQL
        # P36 — a skeleton version that widens a role the approver holds (qa includes auditor)
        probe P36 "a diff adding to auditor, approved by qa" "42501:widens role auditor, which you hold" <<SQL
$(build_v1)
$(propose_skel engineer auditor)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST iam-db")
SQL
        probe P36 "a diff adding to qa and auditor: the first in byte order" "42501:widens role auditor, which you hold" <<SQL
$(build_v1)
$(propose_skel qa auditor)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(skel_approve_sql "$ATTEST iam-db")
SQL
        probe P36 "why_not for it: own_widening" ok <<SQL
$(build_v1)
$(propose_skel qa)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT may_approve AS wm, coalesce(why_not_code, '-') AS wc FROM iam_policy.why_not(:d) \\gset
--CHECKS
SELECT 'CHECK|own_widening', NOT :'wm'::boolean AND :'wc' = 'own_widening';
SQL
        probe P36 "a diff adding only to engineer passes (P28's positive case); why_not: may approve" ok <<SQL
$(build_v1)
$(propose_skel engineer)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT may_approve AS wm, coalesce(why_not_code, '-') AS wc FROM iam_policy.why_not(:d) \\gset
--CHECKS
SELECT 'CHECK|may approve', :'wm'::boolean AND :'wc' = '-';
SQL
        # P37 — iam-api's lock: iam_svc takes the version lock, then save_entry re-enters it
        probe P37 "iam_svc takes pg_advisory_xact_lock(hashtext('iam_policy.version')), then save_entry in the same transaction" ok <<SQL
$(build_v1)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d \\gset
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version')) \\g /dev/null
SELECT iam_policy.save_entry(:d, 'qa', 'portal', '{"R": null, "X": null}'::jsonb, 'iam-db probe',
                             '{"ok": true, "errors": [], "checker_digest": "iam-db"}'::jsonb, $IAT) \\g /dev/null
SELECT count(*) > 0 AS held FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND pid = pg_catalog.pg_backend_pid() \\gset
--CHECKS
SELECT 'CHECK|the lock held by this session', :'held'::boolean;
SELECT 'CHECK|the cell saved', array_agg(level::text ORDER BY level) = '{R,X}'
  FROM iam_policy.entry WHERE version = :d AND role = 'qa' AND group_code = 'portal';
SQL
        # ── IAM 4.5: apply for real (design §14.8.3, §14.8.7, §14.8.11; the committed
        # bundles, P38-P42, P45 and P46, are tests/iam-db-fixture.sh's policy-apply) ──
        # applied_change — draft_chain's :d approved by Q and applied by system:apply (the
        # bundle's _mark_applied: apply_started under :d, :v1 superseded), no record yet
        applied_change() {
            cat <<SQL
$(draft_chain)
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
$(approve_sql)
$(as_system system:apply)
SELECT iam_policy._mark_applied(:d, '{"git_commit": "iam-db"}'::jsonb, 'iam-db', NULL, NULL, NULL) \\g /dev/null
SQL
        }
        # later_events — what a deploy files under the applied version after the apply (the
        # S-D4 mask): a seed fact (system:deploy) and a narrowing accepted (P_DG2)
        later_events() {
            as_system system:deploy
            cat <<SQL
SELECT iam_policy._record('account_seeded', \$j\$$SEED\$j\$::jsonb) \\g /dev/null
SELECT iam_policy._accept_skeleton('$P_DG2', \$j\$$P_SKEL2\$j\$::jsonb, 'iam-db', NULL,
                                   '{"narrowed": [], "unchanged": [], "reviewed_by_version": null}'::jsonb) \\g /dev/null
SQL
            clear_actor
        }
        # rollback_to K BASED_ON [CLAIMED_SUB CLAIMED_PERSON] — the rollback bundle's PRE and
        # POST (§14.8.7 step 7) as SQL: the open version withdrawn, K's rows read in this
        # transaction, :r applied and recorded
        rollback_to() {
            local by_sub=NULL by_person=NULL
            [[ -n "${3:-}" ]] && by_sub="'$3'::uuid" && by_person="$(sqlq "$4")"
            as_system system:apply
            cat <<SQL
SELECT iam_policy._withdraw_open('withdrawn by rollback to version ' || $1 || ': iam-db probe') \\g /dev/null
SELECT iam_policy._build_version('rollback',
    (SELECT coalesce(jsonb_agg(jsonb_build_object('role', e.role, 'group_code', e.group_code, 'level', e.level::text,
                                                  'constraint_name', e.constraint_name)), '[]')
       FROM iam_policy.entry e WHERE e.version = $1),
    (SELECT coalesce(jsonb_agg(to_jsonb(w) - 'version'), '[]') FROM iam_policy.waiver w WHERE w.version = $1),
    $2, $1, 'iam-db rollback') AS r \\gset
SELECT iam_policy._mark_applied(:r, '{"git_commit": "iam-db"}'::jsonb, 'iam-db', $by_sub, $by_person, NULL) \\g /dev/null
SELECT iam_policy._record('applied', jsonb_build_object('version', :r, 'rollback_of', $1)) \\g /dev/null
SQL
            clear_actor
        }
        # P43 — new_draft's S-D4 guard reads the apply events only: a seed fact or a skeleton
        # accept filed under the applied version no longer masks an unfinished apply
        probe P43 "after applied, a seed fact and a skeleton accept: new_draft goes on (the control)" ok <<SQL
$(build_v1)
$(applied_change)
SELECT iam_policy._record('applied', jsonb_build_object('version', :d)) \\g /dev/null
$(later_events)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS d2 \\gset
--CHECKS
SELECT 'CHECK|account_seeded and skeleton_accepted filed under the applied change',
       count(DISTINCT event) = 2 FROM iam_policy.history WHERE version = :d AND event IN ('account_seeded', 'skeleton_accepted');
SELECT 'CHECK|a draft on the applied change', status = 'draft' AND based_on = :d FROM iam_policy.version WHERE version = :d2;
SQL
        probe P43 "after apply_started, a seed fact and a skeleton accept (the D1 mask)" "22023:is being applied (apply_started)" <<SQL
$(build_v1)
$(applied_change)
$(later_events)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
        probe P43 "after partial_apply, then a seed fact" "22023:is being applied (partial_apply)" <<SQL
$(build_v1)
$(applied_change)
SELECT iam_policy._record('partial_apply', jsonb_build_object('version', :d, 'outcome', 'mixed')) \\g /dev/null
$(later_events)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb);
SQL
        # P42 — the rollback bundle's PRE: K's rows read in SQL, the open version withdrawn
        probe P42 "a rollback to a confirmed bootstrap: K's rows read in SQL, an open draft withdrawn by system:apply" ok <<SQL
$(build_v1 record "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:v1, 'iam-db', 'I did not run apply.sh for this version.') \\g /dev/null
$(applied_change)
SELECT iam_policy._record('applied', jsonb_build_object('version', :d)) \\g /dev/null
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.new_draft('applied', 'iam-db probe', $IAT, '[]'::jsonb, '[]'::jsonb) AS o \\gset
$(rollback_to :v1 :d)
--CHECKS
SELECT 'CHECK|applied, kind rollback of v1, based on the change', status = 'applied' AND kind = 'rollback' AND rollback_of = :v1
          AND based_on = :d FROM iam_policy.version WHERE version = :r;
SELECT 'CHECK|its entries are v1''s (EXCEPT both ways empty)', NOT EXISTS (
          (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :r
           EXCEPT SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :v1)
          UNION ALL
          (SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :v1
           EXCEPT SELECT role, group_code, level, constraint_name FROM iam_policy.entry WHERE version = :r));
SELECT 'CHECK|its waivers are v1''s', NOT EXISTS (
          (SELECT to_jsonb(w) - 'version' FROM iam_policy.waiver w WHERE version = :r
           EXCEPT SELECT to_jsonb(w) - 'version' FROM iam_policy.waiver w WHERE version = :v1)
          UNION ALL
          (SELECT to_jsonb(w) - 'version' FROM iam_policy.waiver w WHERE version = :v1
           EXCEPT SELECT to_jsonb(w) - 'version' FROM iam_policy.waiver w WHERE version = :r));
SELECT 'CHECK|the same entries digest as v1 but for the kind', entries_digest IS NOT NULL
          AND entries_digest = iam_policy.entries_digest(:r) FROM iam_policy.version WHERE version = :r;
SELECT 'CHECK|the open draft withdrawn by system:apply', status = 'withdrawn' AND withdrawn_by = 'system:apply'
  FROM iam_policy.version WHERE version = :o;
SELECT 'CHECK|its withdrawn event names system:apply', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :o
          AND event = 'withdrawn' AND payload ->> 'by' = 'system:apply');
SQL
        probe P42 "a rollback to a bootstrap K nobody confirmed" "22023:cannot be rolled back to" <<SQL
$(build_v1 record "$Q2" "$PQ2")
$(applied_change)
SELECT iam_policy._record('applied', jsonb_build_object('version', :d)) \\g /dev/null
$(rollback_to :v1 :d)
SQL
        probe P42 "a rollback to a withdrawn K" "22023:cannot be rolled back to" <<SQL
$(build_v1)
$(draft_chain)
$(as_iam "$A" "$PA" test-pa admin)
SELECT iam_policy.withdraw(:d, 'iam-db probe', $IAT) \\g /dev/null
$(rollback_to :d :v1)
SQL
        # P44 — a rollback is confirmed afterwards, never by the person apply.sh recorded
        probe P44 "confirm_applied of the rollback by the person apply.sh recorded" "42501:recorded you as running" <<SQL
$(build_v1 record "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:v1, 'iam-db', 'I did not run apply.sh for this version.') \\g /dev/null
$(applied_change)
SELECT iam_policy._record('applied', jsonb_build_object('version', :d)) \\g /dev/null
$(rollback_to :v1 :d "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q2" "$PQ2")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:r, 'iam-db', 'I did not run apply.sh for this version.');
SQL
        probe P44 "confirm_applied of the rollback by another qa person: confirmed, audit_versions() clean" ok <<SQL
$(build_v1 record "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:v1, 'iam-db', 'I did not run apply.sh for this version.') \\g /dev/null
$(applied_change)
SELECT iam_policy._record('applied', jsonb_build_object('version', :d)) \\g /dev/null
$(rollback_to :v1 :d "$Q2" "$PQ2")
$(qa_token "$(pclaims "$Q" "$PQ")" POST /rpc/confirm_policy)
SELECT medcea.confirm_policy(:r, 'iam-db', 'I did not run apply.sh for this version.') \\g /dev/null
--CHECKS
SELECT 'CHECK|confirmed by Q', confirmed_by_person = '$PQ' AND confirmed_at IS NOT NULL AND disputed_at IS NULL
  FROM iam_policy.version WHERE version = :r;
SELECT 'CHECK|a confirmed event under the rollback', EXISTS (SELECT 1 FROM iam_policy.history WHERE version = :r AND event = 'confirmed');
SELECT 'CHECK|audit_versions(): no finding', NOT EXISTS (SELECT 1 FROM iam_policy.audit_versions());
SQL
    else
        note policy "P7-P10, P12, P20's applies, P27-P31's, P35-P37 and P42-P44 (the token path) need --mode true"
        # P26 — pre_request's only_rpc block under IAM_DB_ROLES=false (L6)
        probe P26 "IAM_DB_ROLES=false, policy token: GET /recipe" "28000:may only call" <<SQL
$(qa_token "$QA_CLAIMS" GET /recipe)
SQL
        probe P26 "IAM_DB_ROLES=false, policy token: POST /rpc/approve_policy passes pre_request, anon may not execute it" "42501:permission denied for function approve_policy" <<SQL
$(qa_token "$QA_CLAIMS" POST /rpc/approve_policy)
SELECT medcea.approve_policy(1, 'iam-db', '$DD', '$DD', '$P_DG');
SQL
    fi
    fi
elif want policy; then
    note policy "P2-P44 skipped (needs --write-probes, on medcea-iamtest only, and a mode other than legacy)"
fi

# ── drift ────────────────────────────────────────────────────────────────────────
if want drift && [[ "$WRITES" == true && "$MODE" != legacy ]]; then
    echo ""
    VERIFY="$(python3 "$CLI" "${SRC[@]}" compile grants --mode verify "${IAM_FLAG[@]}")"
    drift() {  # NAME SQL
        probe drift "$1" "P0001:differ" <<SQL
$2
$VERIFY
SQL
    }
    probe drift "control: verify passes" ok <<SQL
$VERIFY
SQL
    drift "an extra grant" "GRANT SELECT ON medcea.recipe TO svc_grafana;"
    drift "a compiled grant revoked" "REVOKE SELECT ON medcea.cea_unit FROM rr_operator;"
    if [[ "$MODE" == true ]]; then
        drift "an extra iam_ policy" "CREATE POLICY iam_extra ON medcea.measurement FOR SELECT TO rr_admin USING (true);"
        drift "a dropped iam_ trigger" "DROP TRIGGER iam_immutable_trg ON medcea.recipe_run;"
    else
        drift "anon loses a legacy grant" "REVOKE SELECT ON medcea.recipe FROM anon;"
    fi
fi

echo ""
if [[ $FAILS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}${PASSES} check(s) passed (mode $MODE).${NC}"
else
    echo -e "${RED}${BOLD}${FAILS} of $((PASSES + FAILS)) check(s) failed (mode $MODE).${NC}"
    exit 1
fi
