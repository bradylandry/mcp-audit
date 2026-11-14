#!/usr/bin/env bash
set -euo pipefail

if [ ! -f pyproject.toml ] || [ ! -d audit ]; then
  echo "Run this from the mcp-audit repo root" >&2
  exit 1
fi

EVIDENCE_DIR="${EVIDENCE_DIR:-${TMPDIR:-/tmp}/verify-mcp-audit-evidence}"
mkdir -p "$EVIDENCE_DIR"

# The CLI is pure stdlib. Do not pip-install on launch; python3 -m audit.cli
# works from the repo root. A leftover .venv is unused by the default drive.
if ! python3 -c "import audit.cli" 2>/dev/null; then
  echo "python3 cannot import audit.cli from the repo root" >&2
  exit 1
fi
echo "launch: python3 can import audit.cli"
