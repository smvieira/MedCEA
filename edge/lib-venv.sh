#!/usr/bin/env bash
# edge/lib-venv.sh — ensure_edge_venv: build or update edge/.venv, the
# provisioning toolchain (esptool, mpremote) from edge/requirements.txt.
#
# Sourced by edge/flash-device.sh and apps/edge-wizard/deploy.sh. The wizard
# daemon refuses to start without the venv, and it used to be built only by a
# first manual flash, so a fresh install had an Onboard Device button that
# pointed at nothing. One definition, so the two can't drift.
#
# Returns non-zero instead of exiting; each caller reports failure its own way.
# pip is quiet and skips what is already satisfied, so a re-run is fast.

EDGE_VENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.venv"

ensure_edge_venv() {
    local edge_dir; edge_dir="$(dirname "$EDGE_VENV_DIR")"
    if [ ! -x "$EDGE_VENV_DIR/bin/python" ]; then
        python3 -m venv "$EDGE_VENV_DIR" || { echo "python3 -m venv failed. Install python3-venv." >&2; return 1; }
    fi
    "$EDGE_VENV_DIR/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
    "$EDGE_VENV_DIR/bin/pip" install --quiet -r "$edge_dir/requirements.txt" \
        || { echo "pip install failed — see $edge_dir/requirements.txt" >&2; return 1; }
}
