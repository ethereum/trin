#!/usr/bin/env bash
set -eo pipefail

BOOK_ROOT="$(dirname "$(dirname "$0")")"
TRIN=${1:-"$(dirname "$BOOK_ROOT")/target/debug/trin"}

cmd=(
  "$(dirname "$0")/help.rs"
  --root-dir "$BOOK_ROOT/"
  --root-indentation 6
  --root-summary
  --out-dir "$BOOK_ROOT/cli/"
  "$TRIN"
)
echo "Running: $" "${cmd[*]}"
"${cmd[@]}"
