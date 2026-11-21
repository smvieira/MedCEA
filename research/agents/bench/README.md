# research/agents/bench

One JSON file per day the local model was measured (research Phase 4b step 0,
`codeplan/rs4-design.md` §5.1, R26): `<YYYY-MM-DD>.json`, written by
`apps/research-model/bench.sh report` (bench and eval run it at their end) from every bench
and eval of that day. It holds the machine's facts, the pins (llama.cpp images, model
revisions and sha256s), every llama-bench rate (each bench run kept under its own name), the
offline tool-call eval's scores, the prefix-reuse verdict and the recommendation (none until
both the bench and the evals are in; Qwen3-8B, or Qwen3-4B-Instruct-2507 when 8B is too slow
or clearly worse on a graded outcome). The sandbox's dirty check leaves these JSON files out
(`research/harness/algorithms_loader.py` `SANDBOX_EVIDENCE`), so campaigns still run before
one is committed. It is committed: it is the baseline `rsllm` compares with (4b) and the
evidence for the model choice in the AI inventory.
