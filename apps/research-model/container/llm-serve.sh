#!/bin/sh
# apps/research-model/container/llm-serve.sh — runs INSIDE Deployment research-llm (the pinned llama.cpp
# server image, read-only root; research Phase 4b stage 1, codeplan/rs4-design.md 5.2 with the owner's
# decisions of 21 Nov 2026: Qwen3-4B-Instruct-2507 Q4_K_M, -c 4096). Shipped in ConfigMap
# research-llm-script. Environment (from the Deployment, no secret): MODEL, ALIAS, THREADS, CTX.
#
# Optional flags are added only when this build's --help lists them (as serve.sh of the bench), so a
# renamed flag cannot stop the server. Sampling is greedy and fixed, one slot (-np 1), the model's own
# chat template (--jinja). No API key: the compiled NetworkPolicy admits only model-gateway and the node.
set -u
S="${LLAMA_SERVER:-/app/llama-server}"   # the override is for tests/test_research_model_deploy.py
[ -x "$S" ] || { echo "llm-serve: no $S in this image" >&2; exit 3; }
HELP="$("$S" --help 2>&1 </dev/null)"
has() { printf '%s\n' "$HELP" | grep -Eq -- "(^|[ ,])$1([ ,=]|\$)"; }

args="-m $MODEL --alias $ALIAS --host 0.0.0.0 --port 8080 -t $THREADS -tb $THREADS -c $CTX -np 1"
args="$args --jinja --temp 0 --top-k 1 --seed 1"
has --samplers && args="$args --samplers top_k"
has --metrics && args="$args --metrics"
has --no-webui && args="$args --no-webui"
has --cache-prompt && args="$args --cache-prompt"
has --slot-save-path && args="$args --slot-save-path /slots"
echo "llm-serve: llama-server $args"
# shellcheck disable=SC2086  # every value comes from the Deployment's own env, set by the deploy
exec "$S" $args
