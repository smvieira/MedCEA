#!/bin/sh
# apps/research-model/container/serve.sh — runs INSIDE Pod research-llm-eval-<model> (the
# llama.cpp server image, as the model folder's owner, read-only root). research Phase 4b
# step 0's offline tool-call eval (codeplan/rs4-design.md R26). Shipped in ConfigMap
# research-llm-eval-script. Environment (from the Pod, no secret): MODEL, ALIAS, THREADS,
# CPUS, MASK, CTX. The API key is a file (/keys/key, Secret research-llm-bench-key):
# llama-server reads it with --api-key-file, so it is never on a command line.
#
# Optional flags are added only when this build's --help lists them, so a renamed flag
# cannot stop the server: --metrics, --no-webui, --cache-prompt, -C/--cpu-strict/-Cb.
# Sampling is greedy and fixed (--temp 0 --top-k 1 --seed 1), one slot (-np 1), the
# model's own chat template (--jinja).
set -u
S="${LLAMA_SERVER:-/app/llama-server}"   # the override is for tests/test_research_bench.py
[ -x "$S" ] || { echo "serve: no $S in this image" >&2; exit 3; }
HELP="$("$S" --help 2>&1 </dev/null)"
has() { printf '%s\n' "$HELP" | grep -Eq -- "(^|[ ,])$1([ ,=]|\$)"; }

args="-m $MODEL --alias $ALIAS --host 0.0.0.0 --port 8080 -t $THREADS -tb $THREADS -c $CTX -np 1"
args="$args --jinja --temp 0 --top-k 1 --seed 1 --api-key-file /keys/key"
has --metrics && args="$args --metrics"
has --no-webui && args="$args --no-webui"
has --cache-prompt && args="$args --cache-prompt"
if has --cpu-mask; then
    args="$args -C $MASK"
    has --cpu-strict && args="$args --cpu-strict 1"
    has --cpu-mask-batch && args="$args -Cb $MASK"
fi
pre=""
command -v taskset >/dev/null 2>&1 && pre="taskset -c $CPUS"
echo "serve: llama-server $args (nice 19${pre:+, $pre})"
# shellcheck disable=SC2086  # every value comes from the Pod's own env, checked by bench.sh
exec nice -n 19 $pre "$S" $args
