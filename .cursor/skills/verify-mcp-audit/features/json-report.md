# JSON report

`--json-report` is the CI-oriented output: score, findings, capabilities, and a scan summary.

## Sub-features

- JSON object includes `score`, `findings`, and `scan_summary`
- Suitable for a script that fails when score is too low

## How to get to it (user POV)

```bash
python -m audit.cli tests/fixtures/clean_mcp --json-report > report.json
```

## Driving it with the CLI

```bash
set -euo pipefail
.venv/bin/python -m audit.cli tests/fixtures/clean_mcp --json-report | tee "$EVIDENCE_DIR/clean-report.json"
.venv/bin/python -c "import json,os; r=json.load(open(os.environ['EVIDENCE_DIR']+'/clean-report.json')); assert 'score' in r and 'findings' in r and 'scan_summary' in r; print('json-report keys ok')"
```

## Gotchas

- `--json` is a different flag (raw AST scan). Do not use it when you need the score.
