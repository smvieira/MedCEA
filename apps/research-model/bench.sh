#!/usr/bin/env bash
# apps/research-model/bench.sh — research Phase 4b step 0: measure the local model before
# anything is designed around it (codeplan/rs4-design.md §5.1, §7.2(b), R24-R28; owner
# decisions of 21 Nov 2026: Qwen3-8B Q4_K_M, Qwen3-4B-Instruct-2507 Q4_K_M as the fallback,
# chosen by these measurements). Everything runs in the platform namespace, outside the
# research zones, at low priority; nothing here is a deploy and nothing stays running.
#
#   apps/research-model/bench.sh plan    [bench options]   print what bench would measure and its runtime
#   apps/research-model/bench.sh fetch   [--models 8b,4b] [--verify-only]
#   apps/research-model/bench.sh bench   [--models 8b,4b] [--threads 6,12] [--numa none,isolate]
#                                        [--depths 0,4096,12288] [--depth-threads 6] [--depth-numa none]
#                                        [--socket 0] [--max-hours 4] [--during-run]
#   apps/research-model/bench.sh eval    [--models 8b,4b] [--eval-threads 6] [--ctx 24576] [--socket 0] [--max-hours 4] [--during-run]
#   apps/research-model/bench.sh report  [--date YYYY-MM-DD]
#   apps/research-model/bench.sh cleanup
#
# fetch   Job research-model-fetch (the pinned python image, stdlib urllib + hashlib) downloads
#         the pinned GGUF files (apps/research-model/pins.json: repo, revision, sha256) into
#         RESEARCH_MODEL_DIR (default /var/lib/<PROJECT_NAME>/research-models), resuming a
#         <sha256>.gguf.partial with a Range request and renaming it to <sha256>.gguf only once
#         its sha256 is the pin's. The folder is created mode 700 for you (sudo when its parent
#         is not yours), never inside or around the StorageClass's volume folder, never root's.
#         About 7.5 GB for both models. --verify-only re-hashes what is there.
# bench   Job research-llm-bench (the pinned llama.cpp full image): first a llama-server start
#         that prints system_info (the check AVX = 1 | AVX2 = 0: the sandybridge CPU variant),
#         then llama-bench (-r 1, -o json) per plan line: per model pp512 + pp4096 + tg128 at
#         depth 0, then pp512 + tg128 at each depth (R26's measurements, --depth-numa none: a
#         NUMA strategy resets ggml's workers to the whole node), and last the optional sweep
#         (pp512 + tg128 at depth 0 for the other thread counts and NUMA modes), all pinned to
#         one socket (one hardware thread per physical core for -t 6, the socket's
#         hyper-threads too for -t 12; R24) under nice 19. It prints the plan and its estimated
#         runtime FIRST (the design's throughput ranges, the context part doubled without
#         F16C) and refuses (exit 2) when the PESSIMISTIC runtime is above --max-hours
#         (default 4: one model per run fits; both models together are about 3.7 h expected
#         and 6.4 h pessimistic, so run --models 8b, then --models 4b: the report merges them).
# eval    Per model, Pod research-llm-eval-<model> (the pinned llama.cpp server image,
#         --jinja, -np 1, greedy, --api-key-file from a one-time Secret) answers the fixture
#         conversations of research/agents/evals/fixtures (no lake data, no session), graded on
#         the host (research/agents/evals/grader.py: valid tool calls against the declared
#         schemas, specs the harness accepts, CPU-hour budgets, no undeclared tool, prompt
#         injection resisted), plus a 5-turn transcript measuring prefix reuse. The Pod and the
#         key are deleted at the end. Runtime printed first, refused above --max-hours; one end
#         time for the whole eval (now + --max-hours + 30 min): each Pod's deadline is what is
#         left of it, and run_eval stops between conversations once it has passed.
# report  Merges every bench and eval result of the date (logs/research-llm-*) into
#         research/agents/bench/<date>.json with the machine's facts, the pins and the
#         recommendation, never dropping an earlier run's rows: 4B when 8B generates below
#         1.5 tok/s or processes prompts below 3 tok/s, or is clearly worse (15 points) on a
#         graded outcome of the eval (pass rate, valid calls, valid specs, budgets, refusals,
#         injections); none until both the bench and the eval are in. bench and eval run it.
#         The file is evidence, not code: the sandbox's dirty check leaves it out
#         (research/harness/algorithms_loader.py), so campaigns still run before it is committed.
# cleanup Deletes this script's Jobs, Pods, ConfigMaps and Secrets (label
#         app=research-llm-bench); never the model folder.
#
# fetch, bench, eval and cleanup take the deploy lock (bench holds it for its runtime, so no
# deploy disturbs the measurement). Stopped (Ctrl-C, SIGTERM, a closed terminal), bench and
# fetch delete their Job and eval its Pod before they exit, so nothing runs on without the
# lock. bench and eval refuse while a recipe run is R or S (one read-only psql in
# rdbms-postgresql-0 on medcea.recipe_run, as health-check.sh reads), and look again every
# 5 minutes while they run: a run that starts stops the Job or the Pod (exit 1, "stopped:
# run N started", the partial results kept in the report). They also refuse while the host
# has less memory available than the Job needs plus 2 GiB. A Job's CPU request
# is 100m with no CPU limit and nice 19: it yields to every Burstable or Guaranteed pod; the
# BestEffort production pods (owner decision OD24, not built yet) still share the CPUs with
# it, hence the refusal while a run is active. --during-run (owner decision of 21 Nov 2026: a
# fruiting run lasts days) lets bench and eval run beside an active run: the runs are listed
# and the measurements are marked as taken during one; instead of the run check, every 5 min
# the host must keep MemAvailable >= 3 GiB and a 1-minute load below the CPU count minus 2,
# or the Job or Pod is stopped (exit 1, partial results kept). medcea.recipe_run must still
# be readable. Logs: logs/research-llm-bench-<ts>.log; the
# raw and parsed results: logs/research-llm-{bench,eval}-<ts>*.
#
# Exit 0 done; 1 refused (a run R or S, the folder, too little memory, a held lock, a Job
# that failed, a sha256 mismatch); 2 a usage error, no config.env, over --max-hours,
# the models not fetched, the cluster not reachable.
# Run from anywhere:  apps/research-model/bench.sh --help

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || -z "${1:-}" ]]; then
    sed -n "2,$(grep -n '^# Run from anywhere' "$0" | cut -d: -f1)p" "$0" | sed 's/^# \{0,1\}//'
    [[ -n "${1:-}" ]] && exit 0
    exit 2
fi

YELLOW='\033[0;33m'; RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
log()  { echo -e "${GREEN}[bench]${NC} $*"; }
warn() { echo -e "${YELLOW}[bench] $*${NC}" >&2; }
die()  { local c="$1"; shift; echo -e "${RED}[bench] $*${NC}" >&2; exit "$c"; }
usage() { die 2 "$*  (apps/research-model/bench.sh --help)"; }

# ── Arguments (before the log and the lock, so a usage error needs neither) ──────
CMD="$1"; shift
DURING_RUN=0; RUNS_AT_START=""
MODELS="8b,4b"; THREADS="6,12"; NUMA="none,isolate"; DEPTHS="0,4096,12288"
DEPTH_THREADS=6; DEPTH_NUMA=none; SOCKET=0; MAX_HOURS=4; EVAL_THREADS=6; CTX=24576
DATE=""; VERIFY_ONLY=0
case "$CMD" in
    plan|fetch|bench|eval|report|cleanup) ;;
    *) usage "unknown command '$CMD' (plan, fetch, bench, eval, report or cleanup)" ;;
esac
_value() { [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || usage "$1 needs a value"; }
_only() { local c; for c in "$@"; do [[ "$CMD" == "$c" ]] && return 0; done; usage "$OPT is not an option of $CMD"; }
LIST_RE='^[a-z0-9]+(,[a-z0-9]+)*$'
NUMS_RE='^[0-9]+(,[0-9]+)*$'
while [[ $# -gt 0 ]]; do
    OPT="$1"
    case "$1" in
        --verify-only)   _only fetch; VERIFY_ONLY=1; shift; continue ;;
        --during-run)    _only bench eval; DURING_RUN=1; shift; continue ;;
        --models)        _only plan fetch bench eval; _value "$@"; MODELS="$2" ;;
        --threads)       _only plan bench; _value "$@"; THREADS="$2" ;;
        --numa)          _only plan bench; _value "$@"; NUMA="$2" ;;
        --depths)        _only plan bench; _value "$@"; DEPTHS="$2" ;;
        --depth-threads) _only plan bench; _value "$@"; DEPTH_THREADS="$2" ;;
        --depth-numa)    _only plan bench; _value "$@"; DEPTH_NUMA="$2" ;;
        --socket)        _only plan bench eval; _value "$@"; SOCKET="$2" ;;
        --max-hours)     _only plan bench eval; _value "$@"; MAX_HOURS="$2" ;;
        --eval-threads)  _only eval; _value "$@"; EVAL_THREADS="$2" ;;
        --ctx)           _only eval; _value "$@"; CTX="$2" ;;
        --date)          _only report; _value "$@"; DATE="$2" ;;
        *) usage "unknown argument '$1'" ;;
    esac
    shift 2
done
[[ "$MODELS" =~ $LIST_RE ]] || usage "--models '$MODELS': a comma list such as 8b,4b"
for _m in ${MODELS//,/ }; do [[ "$_m" == 8b || "$_m" == 4b ]] || usage "--models: unknown model '$_m' (8b, 4b)"; done
[[ "$THREADS" =~ $NUMS_RE ]] || usage "--threads '$THREADS': a comma list of numbers"
[[ "$DEPTHS" =~ $NUMS_RE ]]  || usage "--depths '$DEPTHS': a comma list of numbers"
[[ "$NUMA" =~ ^(none|isolate|distribute)(,(none|isolate|distribute))*$ ]] || usage "--numa '$NUMA': none, isolate or distribute"
[[ "$DEPTH_NUMA" =~ ^(none|isolate|distribute)$ ]] || usage "--depth-numa '$DEPTH_NUMA': none, isolate or distribute"
[[ "$DEPTH_THREADS" =~ ^[0-9]{1,2}$ && "$DEPTH_THREADS" -ge 1 ]] || usage "--depth-threads: a number of threads"
[[ "$EVAL_THREADS" =~ ^[0-9]{1,2}$ && "$EVAL_THREADS" -ge 1 && "$EVAL_THREADS" -le 12 ]] || usage "--eval-threads: 1 to 12 (R25)"
[[ "$SOCKET" =~ ^[0-9]$ ]] || usage "--socket: a socket number"
[[ "$MAX_HOURS" =~ ^[0-9]+(\.[0-9]+)?$ ]] || usage "--max-hours: a number of hours"
[[ "$CTX" =~ ^[0-9]{3,6}$ && "$CTX" -ge 2048 && "$CTX" -le 131072 ]] || usage "--ctx: a context size 2048..131072"
[[ -z "$DATE" || "$DATE" =~ ^20[0-9]{2}-[01][0-9]-[0-3][0-9]$ ]] || usage "--date: YYYY-MM-DD"
for _t in ${THREADS//,/ }; do (( _t >= 1 && _t <= 12 )) || usage "--threads: 1 to 12 (R25: at most 12, on one socket)"; done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
if [[ ! -f config.env ]]; then
    echo "config.env not found — run ./deploy-infra.sh first." >&2
    exit 2
fi
# shellcheck disable=SC1091
source config.env
set -euo pipefail
source infra/lib-log.sh; medcea_log research-llm-bench   # logs/research-llm-bench-<ts>.log
case "$CMD" in
    fetch|bench|eval|cleanup) source infra/lib-lock.sh; medcea_lock ;;
esac
source infra/lib-mk8s.sh
source infra/lib-render.sh

NAMESPACE="${NAMESPACE:-medcea}"
POSTGRES_DB="${POSTGRES_DB:-medcea_db}"
HERE="$REPO_ROOT/apps/research-model"
LIB="$HERE/benchlib.py"
PINS="$HERE/pins.json"
FIXTURES="$REPO_ROOT/research/agents/evals/fixtures"
LABEL="app=research-llm-bench"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUTDIR="$REPO_ROOT/logs"
mkdir -p "$OUTDIR"; chmod 700 "$OUTDIR" 2>/dev/null || true
TMPD="$(mktemp -d)"; chmod 700 "$TMPD"
POLL="${MEDCEA_BENCH_POLL:-30}"          # seconds between looks at a Job or the eval (tests: 1)
RECHECK="${MEDCEA_BENCH_RECHECK:-300}"   # seconds between looks at medcea.recipe_run while it runs
EVAL_PODS=()
BENCH_JOB=""        # the Job this invocation created and has not collected yet (bench, fetch)
EVAL_PID=""         # run_eval while it runs
SLEEP_PID=""
_cleanup() {
    local p
    trap '' PIPE                         # a Ctrl-C also ends the log's tee
    [[ -n "$SLEEP_PID" ]] && kill "$SLEEP_PID" 2>/dev/null
    [[ -n "$EVAL_PID" ]] && kill "$EVAL_PID" 2>/dev/null
    if [[ -n "$BENCH_JOB" ]]; then
        # an interrupted bench or fetch: its Job must not run on without the lock and the run
        # guard (propagationPolicy Background removes its pod too)
        $KUBECTL delete job "$BENCH_JOB" -n "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        echo "[bench] Stopped before Job $BENCH_JOB finished: it was deleted (bench.sh cleanup removes anything left)." >&2 || true
    fi
    for p in "${EVAL_PODS[@]}"; do
        $KUBECTL delete pod "$p" -n "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    done
    if [[ "$CMD" == eval ]]; then
        $KUBECTL delete secret research-llm-bench-key -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
    fi
    rm -rf "$TMPD"
}
trap _cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

nap() {   # nap SECONDS: a sleep a signal interrupts at once (bash runs a trap only between commands)
    sleep "$1" >/dev/null 2>&1 9>&- &
    SLEEP_PID=$!
    wait "$SLEEP_PID" 2>/dev/null || true
    SLEEP_PID=""
}

pin() {   # pin KEY FIELD → a value of pins.json's model KEY (or llama_cpp/python_image)
    python3 - "$PINS" "$@" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
a = sys.argv[2:]
v = p["models"][a[0]][a[1]] if a[0] in p["models"] else (p[a[0]][a[1]] if len(a) > 1 else p[a[0]])
print(v)
PY
}

# ── the model folder (Superset's wheel-cache checks, apps/superset/lib-superset.sh) ──
MODEL_DIR="${RESEARCH_MODEL_DIR:-/var/lib/${PROJECT_NAME:-medcea}/research-models}"
if [[ ! "$MODEL_DIR" =~ ^/[A-Za-z0-9._/-]+$ || "$MODEL_DIR" == */../* || "$MODEL_DIR" == */.. || "$MODEL_DIR" == */./* ]]; then
    usage "RESEARCH_MODEL_DIR='$MODEL_DIR' must be an absolute path of letters, digits and . _ - /"
fi
MODEL_DIR="${MODEL_DIR%/}"
[[ -n "$MODEL_DIR" ]] || usage "RESEARCH_MODEL_DIR must not be /"

model_dir_ok() {   # the folder exists (created when MAKE=1), is ours, mode 700, outside the volumes
    local make="${1:-0}" storage uid gid me
    me="$(id -u)"
    [[ "$me" != 0 ]] || die 1 "Run bench.sh as the deploying account, not root: the Jobs run as the model folder's owner, never root."
    storage="$($KUBECTL get storageclass microk8s-hostpath -o jsonpath='{.parameters.pvDir}' 2>/dev/null || true)"
    storage="${storage:-/var/snap/microk8s/common/default-storage}"
    case "$MODEL_DIR/" in "$storage"/*) die 1 "RESEARCH_MODEL_DIR=$MODEL_DIR is inside the volumes' folder $storage: choose another folder." ;; esac
    case "$storage/" in "$MODEL_DIR"/*) die 1 "RESEARCH_MODEL_DIR=$MODEL_DIR contains the volumes' folder $storage: choose another folder." ;; esac
    if [[ ! -d "$MODEL_DIR" ]]; then
        [[ "$make" == 1 ]] || die 2 "No model folder $MODEL_DIR: run apps/research-model/bench.sh fetch first."
        local parent; parent="$(dirname "$MODEL_DIR")"
        if [[ -d "$parent" && -w "$parent" ]]; then
            install -d -m 700 "$MODEL_DIR"
        else
            sudo -p "[sudo] password for %u (to create $MODEL_DIR for the research models): " \
                install -d -m 700 -o "$me" -g "$(id -g)" "$MODEL_DIR" || die 1 "Could not create $MODEL_DIR."
        fi
        log "Created $MODEL_DIR (mode 700, yours)."
    fi
    uid="$(stat -L -c %u "$MODEL_DIR")"; gid="$(stat -L -c %g "$MODEL_DIR")"
    [[ "$uid" == "$me" ]] || die 1 "$MODEL_DIR belongs to uid $uid, not to you ($(id -un)): the Jobs run as its owner. sudo chown $(id -un): $MODEL_DIR, then re-run."
    if [[ "$(stat -L -c %a "$MODEL_DIR")" != 700 ]]; then
        chmod 700 "$MODEL_DIR"; log "$MODEL_DIR set to mode 700."
    fi
    MODEL_UID="$uid"; MODEL_GID="$gid"
}

models_fetched() {
    local m sha
    for m in ${MODELS//,/ }; do
        sha="$(pin "$m" sha256)"
        [[ -f "$MODEL_DIR/$sha.gguf" ]] || die 2 "Model $m is not fetched ($MODEL_DIR/$sha.gguf): apps/research-model/bench.sh fetch --models $m first."
    done
}

runs_query() {   # → 0 no run R or S, 1 some (RUNS_FOUND: "run N status X" lines), 2 unreadable (RUNS_ERR)
    local out rc=0
    RUNS_FOUND=""; RUNS_ERR=""
    out=$($KUBECTL exec --request-timeout=60s -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' "$POSTGRES_DB" 2>&1 <<'SQL'
SELECT 'run|' || r.recipe_run_id || '|' || r.recipe_run_status
  FROM medcea.recipe_run r WHERE r.recipe_run_status IN ('R', 'S') ORDER BY r.recipe_run_id;
SELECT 'checked|ok';
SQL
) || rc=$?
    if [[ "$rc" != 0 ]] || ! grep -q '^checked|ok$' <<<"$out"; then
        RUNS_ERR="$(tail -n1 <<<"$out" | cut -c1-160)"
        return 2
    fi
    if grep -q '^run|' <<<"$out"; then
        RUNS_FOUND="$(grep '^run|' <<<"$out" | awk -F'|' '{printf "run %s status %s\n", $2, $3}')"
        return 1
    fi
    return 0
}

runs_active() {   # refuse while a recipe run is R or S (read-only psql, as health-check.sh)
    local rc=0
    runs_query || rc=$?
    if [[ "$rc" == 2 ]]; then
        die 1 "Cannot read medcea.recipe_run (read-only psql in rdbms-postgresql-0): refused, the bench never runs unchecked. $RUNS_ERR"
    fi
    if [[ "$rc" == 1 ]]; then
        echo "Recipe runs running (R) or scheduled (S):" >&2
        sed 's/^run \([^ ]*\) status /  run \1  status /' <<<"$RUNS_FOUND" >&2
        if [[ "$DURING_RUN" == 1 ]]; then
            RUNS_AT_START="$(paste -sd ';' <<<"$RUNS_FOUND")"
            warn "--during-run: going on beside these runs (owner decision of 21 Nov 2026); the numbers are taken during a run, and the host's memory and load are watched every $(( RECHECK / 60 )) min instead."
            host_ok || die 1 "$STOP_WHY: refused."
            LAST_CHECK="$(date +%s)"; CHECK_FAILS=0
            return 0
        fi
        die 1 "Refused while a recipe run is R or S: the bench would take CPU from the scheduler's control loops (R25). Run it when no run is active or scheduled."
    fi
    log "No recipe run is R or S."
    LAST_CHECK="$(date +%s)"; CHECK_FAILS=0
}

STOP_WHY=""
guard_tick() {   # while a Job or the eval runs: every RECHECK s look again → 0 go on, 3 stop (STOP_WHY)
    local now rc=0
    now="$(date +%s)"
    (( now - ${LAST_CHECK:-0} >= RECHECK )) || return 0
    LAST_CHECK="$now"
    runs_query || rc=$?
    if [[ "$rc" == 1 && "$DURING_RUN" == 1 ]]; then
        host_ok || return 3
        rc=0
    fi
    if [[ "$rc" == 1 ]]; then
        STOP_WHY="$(head -n1 <<<"$RUNS_FOUND" | awk '{print "run " $2 " started (status " $4 ")"}')"
        return 3
    fi
    if [[ "$rc" == 2 ]]; then
        CHECK_FAILS=$(( ${CHECK_FAILS:-0} + 1 ))
        warn "Could not read medcea.recipe_run ($CHECK_FAILS in a row): $RUNS_ERR"
        if (( CHECK_FAILS >= 2 )); then
            STOP_WHY="medcea.recipe_run could not be read twice in a row (the bench never runs unchecked)"
            return 3
        fi
        return 0
    fi
    CHECK_FAILS=0
    return 0
}

host_ok() {   # --during-run's guard: MemAvailable >= 3 GiB and the 1-min load below nproc - 2 (else STOP_WHY, 1)
    local avail load cpus
    avail="$(awk '/^MemAvailable:/ {printf "%d", $2/1048576}' "${MEDCEA_BENCH_MEMINFO:-/proc/meminfo}")"
    load="$(awk '{printf "%d", $1}' "${MEDCEA_BENCH_LOADAVG:-/proc/loadavg}")"
    cpus="${MEDCEA_BENCH_NPROC:-$(nproc)}"
    if (( avail < 3 )); then STOP_WHY="only $avail GiB of memory available beside an active run (3 GiB kept free)"; return 1; fi
    if (( load > cpus - 2 )); then STOP_WHY="the 1-minute load is $load on $cpus CPUs beside an active run (at most $(( cpus - 2 )))"; return 1; fi
    return 0
}

memory_ok() {   # memory_ok GIB: MemAvailable must exceed the Job's memory + 2 GiB
    local need=$(( $1 + 2 )) avail
    avail="$(awk '/^MemAvailable:/ {printf "%d", $2/1048576}' "${MEDCEA_BENCH_MEMINFO:-/proc/meminfo}")"
    (( avail >= need )) || die 1 "Only $avail GiB of memory available, $need GiB needed (the Job's $1 GiB + 2): refused, a memory overcommit kills BestEffort production pods first."
    log "$avail GiB of memory available ($need GiB needed)."
}

priority_class() {
    if $KUBECTL get priorityclass medcea-research-low -o name >/dev/null 2>&1; then echo medcea-research-low; else echo ""; fi
}

apply_cm() {   # apply_cm NAME KEY=FILE...: a labelled ConfigMap (no secret in it)
    local name="$1"; shift
    local args=() kv
    for kv in "$@"; do args+=(--from-file="$kv"); done
    $KUBECTL create configmap "$name" -n "$NAMESPACE" "${args[@]}" --dry-run=client -o yaml \
        | $KUBECTL label --local -f - "$LABEL" -o yaml | $KUBECTL apply -f - >/dev/null
}

wait_job() {   # wait_job NAME DEADLINE_S [guard] → 0 succeeded, 1 failed or out of time, 3 stopped by guard_tick
    local name="$1" deadline=$(( $(date +%s) + $2 + 120 )) guard="${3:-}" st last=0
    while :; do
        st="$($KUBECTL get job "$name" -n "$NAMESPACE" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null || echo "?/?")"
        [[ "$st" == 1/* ]] && return 0
        [[ "$st" == */1 ]] && return 1
        (( $(date +%s) < deadline )) || return 1
        if [[ "$guard" == guard ]]; then
            guard_tick || return 3
        fi
        if (( $(date +%s) - last >= 300 )); then
            last="$(date +%s)"
            log "$name: running ($(date -u +%H:%M:%SZ)); last line: $($KUBECTL logs "job/$name" -n "$NAMESPACE" --tail=1 2>/dev/null | cut -c1-140)"
        fi
        nap "$POLL"
    done
}

report() {   # report [extra benchlib report args...]: merge into research/agents/bench/<date>.json
    local date="${DATE:-$(date -u +%Y-%m-%d)}" out machine
    out="$REPO_ROOT/research/agents/bench/$date.json"
    mkdir -p "$(dirname "$out")"
    machine="$TMPD/machine.json"
    python3 "$LIB" machine >"$machine"
    python3 "$LIB" report --out "$out" --date "$date" --machine "$machine" "$@"
}

# ── plan ─────────────────────────────────────────────────────────────────────────
PROC="${MEDCEA_BENCH_PROC:-/proc}"       # /proc/cpuinfo's F16C flag feeds the estimate (tests: a fake)
plan_args=(--models "$MODELS" --threads "$THREADS" --numa "$NUMA" --depths "$DEPTHS"
           --depth-threads "$DEPTH_THREADS" --depth-numa "$DEPTH_NUMA" --socket "$SOCKET" --max-hours "$MAX_HOURS"
           --proc "$PROC")
if [[ "$CMD" == plan ]]; then
    rc=0; python3 "$LIB" plan "${plan_args[@]}" || rc=$?
    exit "$rc"
fi

# ── cleanup ──────────────────────────────────────────────────────────────────────
if [[ "$CMD" == cleanup ]]; then
    $KUBECTL delete job,pod,configmap,secret -l "$LABEL" -n "$NAMESPACE" --ignore-not-found
    log "Removed this script's Jobs, Pods, ConfigMaps and Secrets in $NAMESPACE; $MODEL_DIR is kept."
    exit 0
fi

# ── report ───────────────────────────────────────────────────────────────────────
if [[ "$CMD" == report ]]; then
    # every result of the date, oldest first (stamps are UTC), so a split or repeated bench
    # never replaces an earlier one's rows and the newest eval per model wins
    day="${DATE:-$(date -u +%Y-%m-%d)}"; compact="${day//-/}"
    args=()
    shopt -s nullglob
    for b in "$OUTDIR"/research-llm-bench-"$compact"-*.parsed.json; do args+=(--bench "$b"); done
    for e in "$OUTDIR"/research-llm-eval-"$compact"-*-8b.json "$OUTDIR"/research-llm-eval-"$compact"-*-4b.json; do
        args+=(--eval "$e")
    done
    shopt -u nullglob
    [[ ${#args[@]} -gt 0 ]] || die 2 "No bench or eval results of $day in logs/: run bench.sh bench or eval first (or --date)."
    report "${args[@]}"
    exit 0
fi

$KUBECTL get namespace "$NAMESPACE" >/dev/null 2>&1 || die 2 "Cannot reach the cluster (namespace $NAMESPACE)."

# ── fetch ────────────────────────────────────────────────────────────────────────
if [[ "$CMD" == fetch ]]; then
    model_dir_ok 1
    python3 - "$PINS" "$MODELS" >"$TMPD/models.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
out = {}
for k in sys.argv[2].split(","):
    m = dict(p["models"][k])
    m["url"] = "https://huggingface.co/%s/resolve/%s/%s" % (m["repo"], m["revision"], m["file"])
    out[k] = {x: m[x] for x in ("name", "repo", "revision", "file", "url", "size_bytes", "sha256", "licence")}
print(json.dumps(out, indent=1, sort_keys=True))
PY
    log "Fetching into $MODEL_DIR (models: $MODELS; sizes and pins in apps/research-model/pins.json)."
    apply_cm research-model-fetch-script "fetch_model.py=$HERE/fetch_model.py" "models.json=$TMPD/models.json"
    $KUBECTL delete job research-model-fetch -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
    PYTHON_IMAGE="$(pin python_image)"; FETCH_DEADLINE_S=10800; PRIORITY_CLASS="$(priority_class)"
    render "$HERE/k8s/fetch-job.yaml" NAMESPACE PYTHON_IMAGE MODEL_DIR MODEL_UID MODEL_GID FETCH_DEADLINE_S PRIORITY_CLASS \
        >"$TMPD/job.yaml"
    [[ "$VERIFY_ONLY" == 1 ]] && sed -i 's#"/script/models.json"\]#"/script/models.json", "--verify-only"]#' "$TMPD/job.yaml"
    BENCH_JOB=research-model-fetch
    $KUBECTL apply -f "$TMPD/job.yaml" >/dev/null
    rc=0; wait_job research-model-fetch 10800 || rc=$?
    $KUBECTL logs job/research-model-fetch -n "$NAMESPACE" 2>&1 | tee "$OUTDIR/research-llm-fetch-$STAMP.out" || true
    [[ "$rc" == 0 ]] || $KUBECTL delete job research-model-fetch -n "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    BENCH_JOB=""
    [[ "$rc" == 0 ]] || die 1 "The fetch did not finish (its log is above): run bench.sh fetch again, it resumes."
    ls -l "$MODEL_DIR"
    log "Fetched and verified: $MODELS. Next: apps/research-model/bench.sh bench"
    exit 0
fi

# ── bench ────────────────────────────────────────────────────────────────────────
if [[ "$CMD" == bench ]]; then
    model_dir_ok 0
    models_fetched
    rc=0; python3 "$LIB" plan "${plan_args[@]}" --tsv "$TMPD/plan.tsv" --json "$TMPD/plan.json" || rc=$?
    [[ "$rc" == 0 ]] || exit "$rc"
    runs_active
    MEM="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["memory_gi"])' "$TMPD/plan.json")"
    memory_ok "$MEM"
    DEADLINE="$(python3 -c 'import sys; print(int(float(sys.argv[1]) * 3600) + 1800)' "$MAX_HOURS")"
    first="${MODELS%%,*}"
    apply_cm research-llm-bench-script "bench-run.sh=$HERE/container/bench-run.sh" "plan.tsv=$TMPD/plan.tsv"
    $KUBECTL delete job research-llm-bench -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
    LLAMA_IMAGE_FULL="$(pin llama_cpp image_full)"; BENCH_DEADLINE_S="$DEADLINE"; BENCH_MEMORY="${MEM}Gi"
    PRIORITY_CLASS="$(priority_class)"; SYSINFO_MODEL="/models/$(pin "$first" sha256).gguf"
    BENCH_JOB=research-llm-bench
    render "$HERE/k8s/bench-job.yaml" NAMESPACE LLAMA_IMAGE_FULL MODEL_DIR MODEL_UID MODEL_GID BENCH_DEADLINE_S \
        BENCH_MEMORY PRIORITY_CLASS SYSINFO_MODEL | $KUBECTL apply -f - >/dev/null
    log "Job research-llm-bench started ($(date -u +%H:%M:%SZ)); it stops by itself after $(( DEADLINE / 60 )) min at most. The deploy lock is held until it ends; medcea.recipe_run is read again every $(( RECHECK / 60 )) min."
    rc=0; wait_job research-llm-bench "$DEADLINE" guard || rc=$?
    RAW="$OUTDIR/research-llm-bench-$STAMP.out"
    $KUBECTL logs job/research-llm-bench -n "$NAMESPACE" >"$RAW" 2>&1 || true
    chmod 600 "$RAW"
    [[ "$rc" == 0 ]] || $KUBECTL delete job research-llm-bench -n "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    BENCH_JOB=""
    cp "$TMPD/plan.json" "$OUTDIR/research-llm-bench-$STAMP.plan.json"
    stopped=(); [[ "$rc" == 3 ]] && stopped=(--stopped "$STOP_WHY")
    [[ "$DURING_RUN" == 1 && -n "$RUNS_AT_START" ]] && stopped+=(--during-run "$RUNS_AT_START")
    prc=0; python3 "$LIB" parse-bench "$RAW" "$OUTDIR/research-llm-bench-$STAMP.parsed.json" "${stopped[@]}" || prc=$?
    report --bench "$OUTDIR/research-llm-bench-$STAMP.parsed.json"
    [[ "$rc" == 3 ]] && die 1 "stopped: $STOP_WHY. Job research-llm-bench was deleted; what it measured is in the report (raw log: $RAW)."
    [[ "$rc" == 0 && "$prc" == 0 ]] || die 1 "The bench did not finish every run (raw log: $RAW); what it measured is in the report."
    log "Bench done. Next: apps/research-model/bench.sh eval"
    exit 0
fi

# ── eval ─────────────────────────────────────────────────────────────────────────
if [[ "$CMD" == eval ]]; then
    model_dir_ok 0
    models_fetched
    rc=0; python3 "$LIB" eval-estimate --models "$MODELS" --fixtures "$FIXTURES" --max-hours "$MAX_HOURS" --proc "$PROC" || rc=$?
    [[ "$rc" == 0 ]] || exit "$rc"
    runs_active
    TOPO="$(python3 "$LIB" topology)"
    CPUS="$(python3 - "$TOPO" "$SOCKET" "$EVAL_THREADS" <<'PY'
import json, sys
sys.path.insert(0, "apps/research-model")
import benchlib
t = json.loads(sys.argv[1])
t["sockets"] = {int(k): v for k, v in t["sockets"].items()}
c = benchlib.cpus_for(t, int(sys.argv[2]), int(sys.argv[3]))
print(",".join(map(str, c)), benchlib.cpu_mask(c))
PY
)" || die 2 "No CPU set for --eval-threads $EVAL_THREADS on socket $SOCKET."
    LLM_CPUS="${CPUS% *}"; LLM_MASK="${CPUS#* }"
    ( umask 077; openssl rand -hex 32 >"$TMPD/key" )
    $KUBECTL create secret generic research-llm-bench-key -n "$NAMESPACE" --from-file=key="$TMPD/key" --dry-run=client -o yaml \
        | $KUBECTL label --local -f - "$LABEL" -o yaml | $KUBECTL apply -f - >/dev/null
    apply_cm research-llm-eval-script "serve.sh=$HERE/container/serve.sh"
    # one end time for the whole eval: every Pod's deadline is what is left of it
    END="$(python3 -c 'import sys; print(int(sys.argv[2]) + int(float(sys.argv[1]) * 3600) + 1800)' "$MAX_HOURS" "$(date +%s)")"
    results=()
    eval_stop() {   # eval_stop WHY: merge what was graded, then stop (the trap removes the Pod and the key)
        [[ ${#results[@]} -gt 0 ]] && report "${results[@]}"
        die 1 "$1"
    }
    for m in ${MODELS//,/ }; do
        left=$(( END - $(date +%s) ))
        (( left >= 600 )) || eval_stop "Out of time before the eval of $m (the end time from --max-hours $MAX_HOURS has passed or is under 10 min away); what was graded is in the report."
        if [[ ${#results[@]} -gt 0 ]]; then   # the runs again before the next model (the first was checked above)
            qrc=0; runs_query || qrc=$?
            if [[ "$qrc" == 1 && "$DURING_RUN" == 1 ]]; then host_ok || eval_stop "stopped: $STOP_WHY, before the eval of $m; what was graded is in the report."; qrc=0; fi
            [[ "$qrc" == 1 ]] && eval_stop "stopped: $(head -n1 <<<"$RUNS_FOUND") before the eval of $m; what was graded is in the report."
            [[ "$qrc" == 2 ]] && eval_stop "Cannot read medcea.recipe_run before the eval of $m (the bench never runs unchecked): $RUNS_ERR"
            LAST_CHECK="$(date +%s)"
        fi
        memory_ok "$(pin "$m" server_memory_gi)"
        pod="research-llm-eval-$m"
        EVAL_PODS+=("$pod")
        $KUBECTL delete pod "$pod" -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
        LLAMA_IMAGE_SERVER="$(pin llama_cpp image_server)"; EVAL_DEADLINE_S="$left"
        SERVER_MEMORY="$(pin "$m" server_memory_gi)Gi"; PRIORITY_CLASS="$(priority_class)"
        MODEL_KEY="$m"; MODEL_FILE="$(pin "$m" sha256).gguf"; MODEL_ALIAS="$(pin "$m" file)"
        LLM_THREADS="$EVAL_THREADS"; LLM_CTX="$CTX"
        render "$HERE/k8s/eval-pod.yaml" NAMESPACE LLAMA_IMAGE_SERVER MODEL_DIR MODEL_UID MODEL_GID EVAL_DEADLINE_S \
            SERVER_MEMORY PRIORITY_CLASS MODEL_KEY MODEL_FILE MODEL_ALIAS LLM_THREADS LLM_CPUS LLM_MASK LLM_CTX \
            | $KUBECTL apply -f - >/dev/null
        log "Pod $pod started; waiting for llama-server to load $(pin "$m" name) (up to 20 min)."
        ready=""
        for _i in $(seq 1 120); do
            ready="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
            [[ "$ready" == True ]] && break
            phase="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
            [[ "$phase" == Failed || "$phase" == Succeeded ]] && break
            guard_tick || eval_stop "stopped: $STOP_WHY, while llama-server for $m was loading; Pod $pod was deleted."
            nap 10
        done
        SLOG="$OUTDIR/research-llm-eval-$STAMP-$m.server.log"
        if [[ "$ready" != True ]]; then
            $KUBECTL logs "$pod" -n "$NAMESPACE" >"$SLOG" 2>&1 || true
            die 1 "llama-server for $m never became ready (its log: $SLOG)."
        fi
        ip="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.podIP}')"
        [[ "$ip" =~ ^[0-9.]+$ ]] || die 2 "No pod IP for $pod."
        OUT="$OUTDIR/research-llm-eval-$STAMP-$m.json"
        erc=0
        python3 -m research.agents.evals.run_eval --url "http://$ip:8080" --key-file "$TMPD/key" \
            --model-key "$m" --alias "$(pin "$m" file)" --out "$OUT" --deadline "$(( END - 60 ))" 9>&- &
        EVAL_PID=$!
        while kill -0 "$EVAL_PID" 2>/dev/null; do
            if ! guard_tick; then
                kill "$EVAL_PID" 2>/dev/null; wait "$EVAL_PID" 2>/dev/null; EVAL_PID=""
                $KUBECTL logs "$pod" -n "$NAMESPACE" >"$SLOG" 2>&1 || true
                chmod 600 "$SLOG"
                [[ -f "$OUT" ]] && { chmod 600 "$OUT"; results+=(--eval "$OUT"); }
                eval_stop "stopped: $STOP_WHY, during the eval of $m; Pod $pod was deleted, what was graded is in the report."
            fi
            nap "$POLL"
        done
        wait "$EVAL_PID" || erc=$?
        EVAL_PID=""
        $KUBECTL logs "$pod" -n "$NAMESPACE" >"$SLOG" 2>&1 || true
        chmod 600 "$SLOG"
        if [[ "$erc" == 3 ]]; then
            [[ -f "$OUT" ]] && { chmod 600 "$OUT"; results+=(--eval "$OUT"); }
            eval_stop "Out of time during the eval of $m (--max-hours $MAX_HOURS); what was graded is in the report."
        fi
        [[ "$erc" == 0 ]] || die 1 "The eval of $m failed (server log: $SLOG)."
        python3 - "$OUT" "$SLOG" <<'PY'
import json, re, sys
sys.path.insert(0, "apps/research-model")
import benchlib
out, slog = sys.argv[1], sys.argv[2]
d = json.load(open(out))
lines = [l.rstrip() for l in open(slog, errors="replace") if re.search(r"system_info|load_backend|chat template|chat_template|tool call|serve:", l)]
d["server_log"] = lines[:20]
d["avx_check"] = benchlib.avx_check(lines)
open(out, "w").write(json.dumps(d, indent=1, sort_keys=True) + "\n")
print("avx check (server log): %s" % d["avx_check"])
PY
        chmod 600 "$OUT"
        $KUBECTL delete pod "$pod" -n "$NAMESPACE" --ignore-not-found >/dev/null
        results+=(--eval "$OUT")
    done
    report "${results[@]}"
    log "Eval done; the key Secret and the Pods are removed on exit."
    exit 0
fi
