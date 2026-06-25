#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="/opt/codered"
export SYMBIONT_PROJECT_DIR="$PROJECT_DIR"

cd "$PROJECT_DIR"

case "${1:-help}" in
    --help|-h|help)
        codered --help
        ;;
    versions)
        codered --version
        symbi --version || echo "symbi: not available"
        ;;
    tools)
        shift
        codered tools "$@"
        ;;
    audit)
        shift
        codered audit "$@"
        ;;
    server)
        # Symbiont runtime server, with agents loaded.
        shift
        exec symbi server --agents-dir "$PROJECT_DIR/agents" --policies-dir "$PROJECT_DIR/policies" "$@"
        ;;
    *)
        # Default: forward everything to codered
        exec codered "$@"
        ;;
esac
