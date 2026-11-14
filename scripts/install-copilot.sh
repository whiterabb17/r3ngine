#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
exec "${NODE:-node}" "$ROOT/scripts/install-copilot.mjs" "$@"
