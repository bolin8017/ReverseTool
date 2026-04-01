#!/bin/bash
set -euo pipefail

case "${1:-}" in
  reverse-tool)
    shift
    exec reverse-tool "$@"
    ;;
  bash|sh|r2|r2pm|rabin2|ragg2|rahash2|rafind2|rarun2|rax2|analyzeHeadless|python|python3)
    exec "$@"
    ;;
  *)
    # All other arguments (including flags) are passed to reverse-tool
    exec reverse-tool "$@"
    ;;
esac
