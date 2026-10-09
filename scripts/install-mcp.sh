#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "${NODE:-node}" "$ROOT/scripts/install-mcp.mjs" "$@"
