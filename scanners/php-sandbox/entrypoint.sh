#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "run" ]]; then
    shift
    exec /usr/local/bin/run-reproducer "$@"
fi
exec tail -f /dev/null
