# Clean fixture

`tests/fixtures/clean_mcp` mirrors a well-scoped MCP server and must score at least 8. It is not required to be a perfect 10; a low-severity f-string URL is a deliberate remaining signal.

## Sub-features

- Score >= 8
- No subprocess, filesystem-write, or inbound-network findings

## How to get to it (user POV)

```bash
python -m audit.cli tests/fixtures/clean_mcp --score-only
```

## Driving it with the CLI

```bash
set -euo pipefail
PY=python3
"$PY" -m audit.cli tests/fixtures/clean_mcp --score-only | tee "$EVIDENCE_DIR/clean-score.txt"
"$PY" -m audit.cli tests/fixtures/clean_mcp --json-report | tee "$EVIDENCE_DIR/clean-report.json"
"$PY" - <<'PY'
import json, os
from pathlib import Path
score = int(Path(os.environ["EVIDENCE_DIR"]).joinpath("clean-score.txt").read_text().strip())
assert score >= 8, score
rep = json.loads(Path(os.environ["EVIDENCE_DIR"]).joinpath("clean-report.json").read_text())
titles = [f["title"] for f in rep["findings"]]
for prefix in ("Subprocess", "Filesystem writes", "Inbound network listener"):
    assert not any(t.startswith(prefix) for t in titles), titles
print(f"clean-fixture: score {score} with no risky findings")
PY
```

## Gotchas

- Do not treat a score of 9 or 8 as a failure. Only a score below 8 is a failure.
