#!/usr/bin/env bash
# apps/iam/uninstall.sh — the inverse of apps/iam/deploy.sh.
#
# Phase 0 deploys nothing into the cluster, so there is nothing to remove. When
# later phases add iam-api and the Policy UI, this removes only those (UI,
# proxy, Deployment) — never the policy tables, their history or the database
# roles, which belong to apps/database and the Compliance Plane.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO_ROOT/infra/lib-lock.sh"; medcea_lock   # one deploy at a time; inherited from deploy-apps.sh

echo "[iam] Nothing deployed in the cluster yet (Phase 0); nothing to remove."
