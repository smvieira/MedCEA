#!/bin/sh
# apps/research-model/container/bench-run.sh — runs INSIDE Job research-llm-bench (the
# llama.cpp full image, as the model folder's owner, read-only root, /tmp an emptyDir).
# research Phase 4b step 0 (codeplan/rs4-design.md §5.1, R24-R28). Shipped in ConfigMap
# research-llm-bench-script beside plan.tsv, which apps/research-model/benchlib.py wrote:
#   name <TAB> cpu list <TAB> hex mask <TAB> numa <TAB> 1 if --numa is required <TAB> args
#
# Output (the Job's log, read back by bench.sh and benchlib.py parse-bench):
#   @@HELP flag=0|1 ...       which optional llama-bench options this build has
#   @@TASKSET 0|1             whether taskset is in the image (the CPU pinning)
#   @@SYSINFO ... lines       llama-server's system_info / load_backend lines (AVX = 1 | AVX2 = 0)
#   @@SYSINFO_RC n
#   @@BEGIN name / @@JSON / <llama-bench -o json> / @@STDERR / <lines> / @@END name rc= seconds=
#   @@SKIP name why           a run this build cannot do (no --numa, no -d)
#   @@FATAL why               stop (a signal: SIGILL means the binary does not suit this CPU)
#   @@DONE
set -u
# the overrides are for tests/test_research_bench.py
B="${LLAMA_BENCH:-/app/llama-bench}"
S="${LLAMA_SERVER:-/app/llama-server}"
PLAN="${BENCH_PLAN:-/script/plan.tsv}"
WORK="${BENCH_WORK:-/tmp}"
[ -x "$B" ] || { echo "@@FATAL no $B in this image"; exit 3; }
[ -r "$PLAN" ] || { echo "@@FATAL no $PLAN"; exit 3; }

HELP="$("$B" --help 2>&1 </dev/null)"
has() { printf '%s\n' "$HELP" | grep -Eq -- "(^|[ ,])$1([ ,=]|\$)"; }
f() { if has "$1"; then echo 1; else echo 0; fi; }
echo "@@HELP cpu_mask=$(f --cpu-mask) cpu_strict=$(f --cpu-strict) n_depth=$(f --n-depth) numa=$(f --numa) no_warmup=$(f --no-warmup)"
TS=0; command -v taskset >/dev/null 2>&1 && TS=1
echo "@@TASKSET $TS"

# system_info: a llama-server start on loopback prints the CPU features it was built for
if [ -n "${SYSINFO_MODEL:-}" ] && [ -x "$S" ] && [ -r "$SYSINFO_MODEL" ]; then
    nice -n 19 "$S" -m "$SYSINFO_MODEL" --host 127.0.0.1 --port 18081 -c 256 -t 1 -np 1 \
        >"$WORK/sysinfo.txt" 2>&1 </dev/null &
    pid=$!
    i=0
    while [ "$i" -lt 180 ]; do
        grep -q 'system_info' "$WORK/sysinfo.txt" 2>/dev/null && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1; i=$((i + 1))
    done
    alive=0; kill -0 "$pid" 2>/dev/null && alive=1
    [ "$alive" = 1 ] && kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null; rc=$?
    echo "@@SYSINFO"
    grep -E 'system_info|load_backend|AVX|CPU :' "$WORK/sysinfo.txt" | head -n 12
    [ "$alive" = 1 ] && rc=0
    echo "@@SYSINFO_RC $rc"
    if [ "$rc" -ge 128 ]; then
        echo "@@FATAL llama-server died of signal $((rc - 128)) (4 = SIGILL: a CPU variant this host lacks)"
        exit 4
    fi
fi

TAB="$(printf '\t')"
while IFS="$TAB" read -r name cpus mask numa need args; do
    case "$name" in ''|\#*) continue ;; esac
    extra=""
    if [ "$numa" != none ]; then
        if has --numa; then extra="$extra --numa $numa"
        elif [ "$need" = 1 ]; then echo "@@SKIP $name this llama-bench has no --numa"; continue
        fi
    fi
    if has --cpu-mask; then
        extra="$extra -C $mask"
        has --cpu-strict && extra="$extra --cpu-strict 1"
    fi
    has --no-warmup && extra="$extra --no-warmup"
    case " $args " in
        *" -d "*) has --n-depth || { echo "@@SKIP $name this llama-bench has no -d/--n-depth"; continue; } ;;
    esac
    pre=""
    [ "$TS" = 1 ] && pre="taskset -c $cpus"
    echo "@@BEGIN $name"
    echo "# llama-bench $args$extra -o json  (nice 19${pre:+, $pre})"
    start=$(date +%s)
    # shellcheck disable=SC2086  # the plan's tokens are checked by benchlib.py (no spaces)
    nice -n 19 $pre "$B" $args $extra -o json >"$WORK/out.json" 2>"$WORK/err.txt" </dev/null
    rc=$?
    end=$(date +%s)
    echo "@@JSON"
    cat "$WORK/out.json"
    echo
    echo "@@STDERR"
    grep -E 'load_backend|system_info|AVX|error|failed|warning' "$WORK/err.txt" | tail -n 20
    echo "@@END $name rc=$rc seconds=$((end - start))"
    if [ "$rc" -ge 128 ]; then
        echo "@@FATAL $name: llama-bench died of signal $((rc - 128))"
        exit 4
    fi
done < "$PLAN"
echo "@@DONE"
