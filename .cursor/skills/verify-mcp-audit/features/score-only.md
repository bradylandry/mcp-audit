# Score-only

`--score-only` prints a single integer from 0 to 10, for shell checks and CI.

## Sub-features

- One integer on stdout
- Exit 0 even when the score is 0, unless `--max-severity` is also used to gate

## How to get to it (user POV)

```bash
python -m audit.cli tests/fixtures/bad_mcp --score-only
```

## Driving it with the CLI

```bash
set -euo pipefail
python3 -m audit.cli tests/fixtures/bad_mcp --score-only | tee "$EVIDENCE_DIR/score-only.txt"
test "$(tr -d '[:space:]' < "$EVIDENCE_DIR/score-only.txt")" = "0"
```

## Gotchas

- A 0 score with a 0 exit status is expected for the bad fixture when `--max-severity` is not set.
