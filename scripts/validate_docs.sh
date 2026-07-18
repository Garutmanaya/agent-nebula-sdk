#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

find "$ROOT" -type f -name '*.md' -print0 | xargs -0 grep -L '^#' && {
  echo "Every Markdown file must contain a heading." >&2
  exit 1
} || true

if grep -RInE 'TODO|TBD|FIXME' "$ROOT" --include='*.md'; then
  echo "Unresolved design markers found." >&2
  exit 1
fi

echo "Documentation structure validation passed."
