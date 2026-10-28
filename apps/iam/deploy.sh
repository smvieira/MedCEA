#!/usr/bin/env bash
# apps/iam/deploy.sh — the access policy (codeplan IAM plan, Phase 0)
#
# Phase 0 deploys nothing into the cluster. It reports whether the policy
# (apps/iam/policy/defaults.yaml) passes its own invariants and which roles each
# signed-in host admits, marking the gates that are not compiled yet. It is not
# the gate itself: deploy-apps.sh runs components alphabetically, so frontend's
# gates are compiled before this runs — what stops a broken policy is
# `cli.py compile`, which every gate goes through and which refuses to compile
# from a policy that violates its invariants.
#
# Later phases add iam-api, the Policy UI, apply.sh and the bootstrap of
# version 1 here. Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[iam]${NC} $*"; }

log "Checking the access policy..."
if ! python3 "$SCRIPT_DIR/compiler/cli.py" check; then
    echo -e "${RED}[iam] The access policy violates its invariants — fix apps/iam/policy/defaults.yaml.${NC}" >&2
    exit 1
fi

log "Roles each signed-in host admits (policy; [status] = enforced today?):"
python3 "$SCRIPT_DIR/compiler/cli.py" hosts | sed 's/^/  /'
