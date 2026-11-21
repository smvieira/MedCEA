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
#                                        [--depths 0,4096,12288] [--depth-threads 6] [--depth-numa isolate]
#                                        [--socket 0] [--max-hours 3.5]
#   apps/research-model/bench.sh eval    [--models 8b,4b] [--eval-threads 6] [--ctx 24576] [--socket 0] [--max-hours 3.5]
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
#         then llama-bench (-r 1, -o json) per plan line: pp512 + tg128 at depth 0 for every
#         thread count and NUMA mode (the sweep), pp4096 at depth 0, then pp512 + tg128 at each
#         depth, all pinned to one socket (one hardware thread per physical core for -t 6,
#         the socket's hyper-threads too for -t 12; R24) under nice 19. It prints the plan and
#         its estimated runtime FIRST (the design's throughput ranges) and refuses (exit 2)
#         above --max-hours (default 3.5: the full plan is about 3 h expected, 5 h pessimistic).
# eval    Per model, Pod research-llm-eval-<model> (the pinned llama.cpp server image,
#         --jinja, -np 1, greedy, --api-key-file from a one-time Secret) answers the fixture
#         conversations of research/agents/evals/fixtures (no lake data, no session), graded on
#         the host (research/agents/evals/grader.py: valid tool calls against the declared
#         schemas, specs the harness accepts, CPU-hour budgets, no undeclared tool, prompt
#         injection resisted), plus a 5-turn transcript measuring prefix reuse. The Pod and the
#         key are deleted at the end. Runtime printed first, refused above --max-hours.
# report  Merges the newest bench and eval results (logs/research-llm-*.json) into
#         research/agents/bench/<date>.json with the machine's facts, the pins and the
#         recommendation: 4B when 8B generates below 1.5 tok/s, processes prompts below
#         3 tok/s, or its tool-call validity is clearly worse (15 points). bench and eval run it.
# cleanup Deletes this script's Jobs, Pods, ConfigMaps and Secrets (label
#         app=research-llm-bench); never the model folder.
#
# fetch, bench, eval and cleanup take the deploy lock (bench holds it for its runtime, so no
# deploy disturbs the measurement). bench and eval refuse while a recipe run is R or S (one
# read-only psql in rdbms-postgresql-0 on medcea.recipe_run, as health-check.sh reads) and
# while the host has less memory available than the Job needs plus 2 GiB. A Job's CPU request
# is 100m with no CPU limit and nice 19: it yields to every Burstable or Guaranteed pod; the
# BestEffort production pods (owner decision OD24, not built yet) still share the CPUs with
# it, hence the refusal while a run is active. Logs: logs/research-llm-bench-<ts>.log; the
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
MODELS="8b,4b"; THREADS="6,12"; NUMA="none,isolate"; DEPTHS="0,4096,12288"
DEPTH_THREADS=6; DEPTH_NUMA=isolate; SOCKET=0; MAX_HOURS=3.5; EVAL_THREADS=6; CTX=24576
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
EVAL_PODS=()
_cleanup() {
    local p
    for p in "${EVAL_PODS[@]}"; do
        $KUBECTL delete pod "$p" -n "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    done
    if [[ "$CMD" == eval ]]; then
        $KUBECTL delete secret research-llm-bench-key -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
    fi
    rm -rf "$TMPD"
}
trap _cleanup EXIT

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

runs_active() {   # refuse while a recipe run is R or S (read-only psql, as health-check.sh)
    local out rc=0
    out=$($KUBECTL exec --request-timeout=60s -i -n "$NAMESPACE" rdbms-postgresql-0 -- \
        env PGOPTIONS="-c default_transaction_read_only=on -c client_min_messages=warning" sh -c \
        'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$0" -tA -F "|"' "$POSTGRES_DB" 2>&1 <<'SQL'
SELECT 'run|' || r.recipe_run_id || '|' || r.recipe_run_status
  FROM medcea.recipe_run r WHERE r.recipe_run_status IN ('R', 'S') ORDER BY r.recipe_run_id;
SELECT 'checked|ok';
SQL
) || rc=$?
    if [[ "$rc" != 0 ]] || ! grep -q '^checked|ok$' <<<"$out"; then
        die 1 "Cannot read medcea.recipe_run (read-only psql in rdbms-postgresql-0): refused, the bench never runs unchecked. $(tail -n1 <<<"$out" | cut -c1-160)"
    fi
    if grep -q '^run|' <<<"$out"; then
        echo "Recipe runs running (R) or scheduled (S):" >&2
        grep '^run|' <<<"$out" | awk -F'|' '{printf "  run %s  status %s\n", $2, $3}' >&2
        die 1 "Refused while a recipe run is R or S: the bench would take CPU from the scheduler's control loops (R25). Run it when no run is active or scheduled."
    fi
    log "No recipe run is R or S."
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

wait_job() {   # wait_job NAME DEADLINE_S → 0 succeeded, 1 failed or out of time
    local name="$1" deadline=$(( $(date +%s) + $2 + 120 )) st last=0
    while :; do
        st="$($KUBECTL get job "$name" -n "$NAMESPACE" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null || echo "?/?")"
        [[ "$st" == 1/* ]] && return 0
        [[ "$st" == */1 ]] && return 1
        (( $(date +%s) < deadline )) || return 1
        if (( $(date +%s) - last >= 300 )); then
            last="$(date +%s)"
            log "$name: running ($(date -u +%H:%M:%SZ)); last line: $($KUBECTL logs "job/$name" -n "$NAMESPACE" --tail=1 2>/dev/null | cut -c1-140)"
        fi
        sleep 30
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

newest() { ls -1t $1 2>/dev/null | head -n1 || true; }

# ── plan ─────────────────────────────────────────────────────────────────────────
plan_args=(--models "$MODELS" --threads "$THREADS" --numa "$NUMA" --depths "$DEPTHS"
           --depth-threads "$DEPTH_THREADS" --depth-numa "$DEPTH_NUMA" --socket "$SOCKET" --max-hours "$MAX_HOURS")
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
    args=()
    b="$(newest "$OUTDIR/research-llm-bench-*.parsed.json")"
    if [[ -n "$b" ]]; then
        args+=(--bench "$b")
        [[ -f "${b%.parsed.json}.plan.json" ]] && args+=(--plan "${b%.parsed.json}.plan.json")
    fi
    for m in 8b 4b; do
        e="$(newest "$OUTDIR/research-llm-eval-*-$m.json")"
        [[ -n "$e" ]] && args+=(--eval "$e")
    done
    [[ ${#args[@]} -gt 0 ]] || die 2 "No bench or eval results in logs/: run bench.sh bench or eval first."
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
    $KUBECTL apply -f "$TMPD/job.yaml" >/dev/null
    rc=0; wait_job research-model-fetch 10800 || rc=$?
    $KUBECTL logs job/research-model-fetch -n "$NAMESPACE" 2>&1 | tee "$OUTDIR/research-llm-fetch-$STAMP.out" || true
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
    render "$HERE/k8s/bench-job.yaml" NAMESPACE LLAMA_IMAGE_FULL MODEL_DIR MODEL_UID MODEL_GID BENCH_DEADLINE_S \
        BENCH_MEMORY PRIORITY_CLASS SYSINFO_MODEL | $KUBECTL apply -f - >/dev/null
    log "Job research-llm-bench started ($(date -u +%H:%M:%SZ)); it stops by itself after $(( DEADLINE / 60 )) min at most. The deploy lock is held until it ends."
    rc=0; wait_job research-llm-bench "$DEADLINE" || rc=$?
    RAW="$OUTDIR/research-llm-bench-$STAMP.out"
    $KUBECTL logs job/research-llm-bench -n "$NAMESPACE" >"$RAW" 2>&1 || true
    chmod 600 "$RAW"
    cp "$TMPD/plan.json" "$OUTDIR/research-llm-bench-$STAMP.plan.json"
    prc=0; python3 "$LIB" parse-bench "$RAW" "$OUTDIR/research-llm-bench-$STAMP.parsed.json" || prc=$?
    report --bench "$OUTDIR/research-llm-bench-$STAMP.parsed.json" --plan "$OUTDIR/research-llm-bench-$STAMP.plan.json"
    [[ "$rc" == 0 && "$prc" == 0 ]] || die 1 "The bench did not finish every run (raw log: $RAW); what it measured is in the report."
    log "Bench done. Next: apps/research-model/bench.sh eval"
    exit 0
fi

# ── eval ─────────────────────────────────────────────────────────────────────────
if [[ "$CMD" == eval ]]; then
    model_dir_ok 0
    models_fetched
    rc=0; python3 "$LIB" eval-estimate --models "$MODELS" --fixtures "$FIXTURES" --max-hours "$MAX_HOURS" || rc=$?
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
    DEADLINE="$(python3 -c 'import sys; print(int(float(sys.argv[1]) * 3600) + 1800)' "$MAX_HOURS")"
    results=()
    for m in ${MODELS//,/ }; do
        memory_ok "$(pin "$m" server_memory_gi)"
        pod="research-llm-eval-$m"
        EVAL_PODS+=("$pod")
        $KUBECTL delete pod "$pod" -n "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
        LLAMA_IMAGE_SERVER="$(pin llama_cpp image_server)"; EVAL_DEADLINE_S="$DEADLINE"
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
            sleep 10
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
            --model-key "$m" --alias "$(pin "$m" file)" --out "$OUT" || erc=$?
        $KUBECTL logs "$pod" -n "$NAMESPACE" >"$SLOG" 2>&1 || true
        chmod 600 "$SLOG"
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
