#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export EGRESS_SOURCE_ROOT="$root/egress"
exec bash "$root/test/e2e/lib/egress/run.sh" "$@"
