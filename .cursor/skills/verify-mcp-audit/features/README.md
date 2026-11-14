# Feature map

Verification source for the mcp-audit CLI. Drive these against the shipped fixtures only.

| Feature | What a user cares about | File |
| --- | --- | --- |
| Bad fixture | A deliberately unsafe MCP package scores 0 and lists high-risk findings | [bad-fixture.md](bad-fixture.md) |
| Clean fixture | A well-scoped MCP package scores at least 8 | [clean-fixture.md](clean-fixture.md) |
| JSON report | `--json-report` is the programmatic / CI output and includes score plus findings | [json-report.md](json-report.md) |
| Score-only | `--score-only` prints a single integer 0-10 | [score-only.md](score-only.md) |
