#!/usr/bin/env bash
set -euo pipefail

if [ ! -f pyproject.toml ] || [ ! -d audit ]; then
  echo "Run this from the mcp-audit repo root" >&2
  exit 1
fi

EVIDENCE_DIR="${EVIDENCE_DIR:-${TMPDIR:-/tmp}/verify-mcp-audit-evidence}"
mkdir -p "$EVIDENCE_DIR"

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
.venv/bin/pip install -e ".[test]"
echo "launch: venv ready"
