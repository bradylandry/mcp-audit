#!/usr/bin/env bash
set -euo pipefail
# No server is started. Leave .venv and EVIDENCE_DIR in place.
rm -rf ${TMPDIR:-/tmp}/verify-mcp-audit-scratch*
echo "cleanup: done (evidence directory and .venv left in place)"
