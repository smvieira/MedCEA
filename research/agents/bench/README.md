# research/agents/bench

One JSON file per day the local model was measured (research Phase 4b step 0,
`codeplan/rs4-design.md` §5.1, R26): `<YYYY-MM-DD>.json`, written by
`apps/research-model/bench.sh report` (bench and eval run it at their end). It holds the
machine's facts, the pins (llama.cpp images, model revisions and sha256s), every
llama-bench rate, the offline tool-call eval's scores, the prefix-reuse verdict and the
recommendation (Qwen3-8B, or Qwen3-4B-Instruct-2507 when 8B is too slow or calls tools
clearly worse). It is committed: it is the baseline `rsllm` compares with (4b) and the
evidence for the model choice in the AI inventory.
