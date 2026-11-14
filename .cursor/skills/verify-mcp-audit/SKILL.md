---
name: verify-mcp-audit
description: Verify mcp-audit, the stdlib CLI that scores a Python MCP server package. Use before opening or updating a PR, against the shipped fixtures only.
---

# Verify mcp-audit

Users run a CLI from the repo root: `python -m audit.cli /path/to/mcp/package` (or the `mcp-audit` console script after install). There is no web UI, HTTP API, port, or database. Runtime dependencies are none; pytest is an optional extra.

The two shipped fixtures are the official targets:

- `tests/fixtures/clean_mcp` must score at least 8
- `tests/fixtures/bad_mcp` must score 0 and include the high-risk findings

Never point this skill at a live MCP deployment or at Brady's production packages unless a later feature explicitly says so. The default drive stays on fixtures.

Isolation: each drive is a short-lived CLI process. Two runs can share the same checkout. Do not write into the fixtures. Put reports under `$EVIDENCE_DIR`. Never kill a process by name.

## Launch

From the repo root. There is no server to keep alive. Launch means install the package once, then start each drive as its own command.

```bash
set -euo pipefail
export EVIDENCE_DIR="${EVIDENCE_DIR:-${TMPDIR:-/tmp}/verify-mcp-audit-evidence}"
mkdir -p "$EVIDENCE_DIR"
bash .cursor/skills/verify-mcp-audit/helpers/launch.sh
```

`helpers/launch.sh` creates `.venv` if needed and installs `.[test]`. Readiness is Doctor printing `doctor: usable`.

Teardown: Cleanup. The venv may be left in the checkout (it is gitignored). Cleanup does not delete evidence.

## Doctor

One read-only check. It does not scan a package or write a report.

```bash
set -euo pipefail
bash .cursor/skills/verify-mcp-audit/helpers/doctor.sh | tee "$EVIDENCE_DIR/doctor.txt"
```

Doctor exits 0 and prints `doctor: usable` when `.venv/bin/python -m audit.cli --help` exits 0, the help text mentions `--json-report` and `--score-only`, and both fixture directories exist. Otherwise it prints `doctor: NOT usable` and exits 1.

## Drive

The harness is the CLI itself (`python -m audit.cli`). Drive the mapped feature `bad-fixture` first. Commands live in that feature file.

## Evidence

Store proof under `$EVIDENCE_DIR`. Capture:

- `doctor.txt`
- `bad-score.txt` (a single integer, must be `0`)
- `bad-report.json` from `--json-report`
- `clean-score.txt` (integer >= 8) when that feature is also driven

Proof standards: run the real CLI on the shipped fixtures, not an imported helper alone. Confirm the score and at least one expected finding in the JSON report. Cleanup must not delete `$EVIDENCE_DIR`.

## Cleanup

```bash
set -euo pipefail
bash .cursor/skills/verify-mcp-audit/helpers/cleanup.sh
```

No server is started. Cleanup only removes scratch files the helpers may have written under `/tmp/verify-mcp-audit-scratch*` and leaves `$EVIDENCE_DIR` and `.venv` in place.

## Helpers

From the repo root:

- `bash .cursor/skills/verify-mcp-audit/helpers/launch.sh`
- `bash .cursor/skills/verify-mcp-audit/helpers/doctor.sh`
- `bash .cursor/skills/verify-mcp-audit/helpers/cleanup.sh`

Keep the map honest with `/maintain-verification-skill` as the scanner changes.
