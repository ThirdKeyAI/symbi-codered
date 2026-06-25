#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "scan" ]]; then
    shift
    exec /usr/local/bin/scanner-runner "$@"
fi

# Default: stay alive forever so `docker exec` can reach us.
exec tail -f /dev/null
