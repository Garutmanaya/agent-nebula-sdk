#!/usr/bin/env bash
# Validate Markdown structure and reject unresolved design markers.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
missing_heading=0

while IFS= read -r -d '' file; do
  if ! grep -q '^#' "$file"; then
    printf 'Missing Markdown heading: %s\n' "$file" >&2
    missing_heading=1
  fi
done < <(find "$ROOT" -type f -name '*.md' -print0)

if [[ "$missing_heading" -ne 0 ]]; then
  exit 1
fi

if grep -RInE 'TODO|TBD|FIXME' "$ROOT" --include='*.md'; then
  echo "Unresolved design markers found." >&2
  exit 1
fi

echo "Documentation structure validation passed."
