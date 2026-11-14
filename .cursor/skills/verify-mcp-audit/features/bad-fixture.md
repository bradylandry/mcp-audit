# Bad fixture

`tests/fixtures/bad_mcp` deliberately violates the scanner's dimensions and must score 0.

## Sub-features

- Score is exactly 0
- Findings include subprocess use and dynamic code execution
- TLS disabled (`verify=False`) is detected

## How to get to it (user POV)

A user points the CLI at a package path:

```bash
python -m audit.cli tests/fixtures/bad_mcp --score-only
python -m audit.cli tests/fixtures/bad_mcp --json-report
```

They read the integer score, or the JSON report's `score` and `findings`.

## Driving it with the CLI

After Launch and a passing Doctor:

```bash
set -euo pipefail
PY=".venv/bin/python"

"$PY" -m audit.cli tests/fixtures/bad_mcp --score-only | tee "$EVIDENCE_DIR/bad-score.txt"
test "$(tr -d '[:space:]' < "$EVIDENCE_DIR/bad-score.txt")" = "0"

"$PY" -m audit.cli tests/fixtures/bad_mcp --json-report | tee "$EVIDENCE_DIR/bad-report.json"
"$PY" - <<'PY'
import json, sys
from pathlib import Path
import os
p = Path(os.environ["EVIDENCE_DIR"]) / "bad-report.json"
rep = json.loads(p.read_text())
assert rep["score"] == 0, rep["score"]
titles = [f["title"] for f in rep["findings"]]
assert any("Subprocess" in t for t in titles), titles
assert any("Dynamic code execution" in t for t in titles), titles
print("bad-fixture: score 0 with expected findings")
PY
```

## Gotchas

- Do not edit the fixture to force a pass. If the score is no longer 0, the scanner or the fixture drifted; record it and stop.
- `--json` is the raw scan, not the scored report. Use `--json-report` for score and findings.
