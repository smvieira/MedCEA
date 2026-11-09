#!/usr/bin/env bash
# guide.sh — the old name of ./medcea.sh (renamed 9 Nov 2026, owner decision), kept as a
# forwarding alias for now: it says so on stderr, then runs medcea.sh from its own folder
# with every argument; the exit code is medcea.sh's. This name will be removed in a later
# release: use ./medcea.sh.
echo "guide.sh is now ./medcea.sh (this name will be removed in a later release)" >&2
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/medcea.sh" "$@"
