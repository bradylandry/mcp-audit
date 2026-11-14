#!/usr/bin/env bash
set -euo pipefail
problems=0
ok() { echo "ok: $1"; }
bad() { echo "not ok: $1"; problems=1; }

if ! python3 -c "import audit.cli" 2>/dev/null; then
  echo "doctor: NOT usable"
  echo "python3 cannot import audit.cli from the repo root"
  exit 1
fi
ok "python3 can import audit.cli"

HELP="$(python3 -m audit.cli --help 2>&1)" || { echo "doctor: NOT usable"; echo "$HELP"; exit 1; }
printf '%s\n' "$HELP" | grep -q -- "--json-report" && ok "help mentions --json-report" || bad "help missing --json-report"
printf '%s\n' "$HELP" | grep -q -- "--score-only" && ok "help mentions --score-only" || bad "help missing --score-only"
[ -d tests/fixtures/bad_mcp ] && ok "bad_mcp fixture present" || bad "bad_mcp fixture missing"
[ -d tests/fixtures/clean_mcp ] && ok "clean_mcp fixture present" || bad "clean_mcp fixture missing"

if [ "$problems" -eq 0 ]; then
  echo "doctor: usable"
  exit 0
fi
echo "doctor: NOT usable"
exit 1
