# mcp-audit

Static-analysis security audit for Python MCP server packages.
Produces a capability map + risk findings + 0–10 score, without
running the code.

**Why:** [MCP](https://modelcontextprotocol.io/) servers run with the
same trust as a local subprocess of your Claude session. If you `pip
install` a community MCP, you're betting that the maintainer didn't —
intentionally or accidentally — ship code that `subprocess.run`s shell
commands, writes to your filesystem, opens an inbound listener, or
exfiltrates env vars beyond what's needed. Most installers don't audit.
This tool is a 1-command static check that takes ~1 second to run.

## What it detects

8 audit dimensions. Pure stdlib (`ast`, `pathlib`, `tomllib`). No LLM.
No network. No third-party deps. Same input always produces the same
output.

| Dimension | Detected via AST patterns for |
| --- | --- |
| **1. Network egress** | `requests.*`, `httpx.*`, `urllib.request.urlopen`, `aiohttp.ClientSession.*`, plus instance-method heuristic for `session.get(...)` / `client.post(...)`. Records hostnames from literal URLs. Flags `verify=False`. |
| **2. Code execution** | `subprocess.run/call/Popen/...`, `os.system`, `os.exec*`, `os.spawn*`, `pty.spawn`, `pexpect.spawn`, plus bare `eval` / `exec` / `compile` / `__import__`. |
| **3. Filesystem** | `open(..., 'w'/'a'/'x'/'+')`, `os.remove/unlink/mkdir/chmod/...`, `shutil.copy/move/rmtree/...`, `Path.write_text/write_bytes/...`. Reads tracked separately. |
| **4. Env vars** | `os.environ.get`, `os.environ['NAME']`, `os.getenv`. Flags broad-credential names (AWS, GCP, GitHub, OpenAI, etc.). |
| **5. Stdio** | `sys.stdin.read*`, `input`, `sys.stdout.write/flush`, `sys.stderr.write`. Reports presence as expected behavior for stdio MCP servers. |
| **6. Inbound network** | `socket.bind`, `http.server`, `flask.Flask.run`, `fastapi.FastAPI(...)`, `uvicorn.run`, etc. Unusual for an MCP and flagged. |
| **7. URL construction safety** | URLs built via f-string or string concatenation are flagged as needing manual review (potential injection vector if user data flows in). |
| **8. Dependencies** | Parses `pyproject.toml` `project.dependencies` or `requirements.txt`. Flags loose pins (no `==`). |

## Install

```bash
pip install git+https://github.com/bradylandry/mcp-audit.git
```

Or run from a local clone without installing:

```bash
git clone https://github.com/bradylandry/mcp-audit.git
cd mcp-audit
python -m audit.cli /path/to/mcp/package
```

## Usage

```bash
# Audit a directory containing an MCP package
mcp-audit /path/to/mcp/package

# Audit a single file
mcp-audit /path/to/server.py

# Get just the score (for CI)
mcp-audit /path/to/package --score-only
# → prints "8" (or whatever)

# Raw JSON for programmatic consumption
mcp-audit /path/to/package --json > scan.json
```

The default output is a markdown report on stdout — pipe to a file
or pager as you would `git diff`.

## Example: real-world audit

The first published audit on a real MCP — see
[examples/jarvis-trading-mcp-audit.md](examples/jarvis-trading-mcp-audit.md)
for a full report on
[bradylandry/jarvis-trading-mcp](https://github.com/bradylandry/jarvis-trading-mcp).

**Score: 10/10 — low-risk.** Single resolved outbound host
(`trading.landrycmd.com`), two named env-var reads for auth + base URL,
stdio-only I/O, no subprocess, no filesystem writes, no inbound
network, no eval, TLS verification on. Only declared dep is `requests`.
Capability surface exactly matches the security claims in that repo's
README — reproducible by anyone via `mcp-audit /path/to/clone`.

Earlier versions scored 8/10 due to f-string URL construction
(`f"{base}{path}"`); the package switched to `urljoin(base, path)` in
response to this audit, eliminating the warning without changing
behavior.

## Scoring methodology

Score starts at 10. Each finding deducts a fixed amount based on
severity:

- **High** (−2 to −3 each): subprocess with `shell=True`, dynamic exec, TLS verification disabled, suspicious env var reads (AWS/GitHub/OpenAI tokens)
- **Medium** (−1 to −2 each): subprocess without shell, filesystem writes, inbound network listeners, dynamic URL destinations
- **Low** (0 to −1 each): URL constructed via f-string/concat, multiple outbound hosts, loose version pins
- **Info** (no deduction): observed behavior worth noting (e.g., reads from filesystem)

Recommendation thresholds:

- **8–10**: Low-risk for friend distribution. Audit confirms a narrow capability surface.
- **5–7**: Medium-risk. Document the flagged behaviors; install with awareness.
- **0–4**: High-risk. Do NOT install without a full manual review of the flagged sites.

## What this DOES NOT do

Be aware of the boundaries:

- ❌ **Doesn't run your code.** All analysis is static. Anything that's only true at runtime — environment-specific behavior, network state, response content — is invisible.
- ❌ **Doesn't follow dynamic dispatch.** `getattr(requests, "get")(url)` won't be detected as an HTTP call. `getattr` results are opaque to AST.
- ❌ **Doesn't audit C extensions.** A Python package wrapping a `.so` / `.pyd` library is opaque past the import boundary.
- ❌ **Doesn't audit transitive deps.** Reports your declared deps but doesn't recurse — if you trust `requests`, fine; if not, audit the dep tree separately (e.g. `pip-audit`).
- ❌ **Doesn't detect sophisticated obfuscation.** Anyone determined to hide malicious code via dynamic-only paths can evade. The tool is for catching *common* concerns, not nation-state-level adversaries.
- ❌ **Doesn't audit non-Python code.** Python only. TypeScript MCP servers (also common) need a different tool.

If you need stronger guarantees, combine mcp-audit with: `bandit`
(broader Python security linter), `pip-audit` (CVE check on deps),
manual review of the AST scanner's flagged sites, and runtime sandboxing
(e.g., `firejail`, `bubblewrap`, or just running the MCP in a restricted
user account).

## Roadmap

- **v0.1** (this release) — deterministic AST scanner, markdown report, fixtures, CLI
- **v0.2** — add an LLM-narrative section: feed AST findings to Claude with a "produce a Carlos-style risk summary" prompt. ~$0.005 per audit. Strictly additive on top of the deterministic findings.
- **v0.3** — TypeScript MCP support (walk TS AST via `tree-sitter-typescript`)
- **v0.4** — GitHub Action: auto-audit on every PR to a configured MCP repo, post the report as a PR comment
- **v0.5** — `mcp-audit github.com/foo/bar-mcp@<sha>` clones and audits a remote repo. Lets users vet before pip install.

## Development

```bash
git clone https://github.com/bradylandry/mcp-audit.git
cd mcp-audit
python -m audit.cli tests/fixtures/clean_mcp   # should score ~8-10
python -m audit.cli tests/fixtures/bad_mcp     # should score 0
```

The `bad_mcp` fixture deliberately violates every dimension at once
(subprocess + shell, eval, TLS off, filesystem writes, inbound socket,
multiple hosts, suspicious env reads, f-string URL with user input).
A scan that rates it above 0 has a regression in the heuristics.

## Contributing

Bug reports + PRs welcome. Please include a minimal repro fixture
showing the false positive or false negative.

## License

MIT. See `LICENSE`.
