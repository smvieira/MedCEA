#!/usr/bin/env bash
# research/lib-venv.sh — ensure_research_venv: build or update research/.venv,
# the research sandbox's Python environment (numpy, scipy, scikit-fuzzy,
# gekko), from research/requirements.txt.
#
# The edge/lib-venv.sh pattern, with one difference: every wheel is installed
# hash-checked (--require-hashes) and binary only (--only-binary=:all:), so
# nothing is built from source and a changed upload on PyPI is refused.
#
# Returns non-zero instead of exiting; each caller reports failure its own way.
# pip is quiet and skips what is already satisfied, so a re-run is fast.
#
# Usage: source research/lib-venv.sh && ensure_research_venv

RESEARCH_VENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.venv"

ensure_research_venv() {
    local research_dir; research_dir="$(dirname "$RESEARCH_VENV_DIR")"
    if [ ! -x "$RESEARCH_VENV_DIR/bin/python" ]; then
        python3 -m venv "$RESEARCH_VENV_DIR" || { echo "python3 -m venv failed. Install python3-venv." >&2; return 1; }
    fi
    "$RESEARCH_VENV_DIR/bin/pip" install --quiet --disable-pip-version-check \
        --require-hashes --only-binary=:all: -r "$research_dir/requirements.txt" \
        || { echo "pip install failed — see $research_dir/requirements.txt" >&2; return 1; }
}
