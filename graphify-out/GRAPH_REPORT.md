# Graph Report - .  (2026-06-06)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 225 nodes · 424 edges · 14 communities (9 shown, 5 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 23 edges (avg confidence: 0.51)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `41eb5036`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]

## God Nodes (most connected - your core abstractions)
1. `_ast_scan_str()` - 40 edges
2. `build_report()` - 28 edges
3. `ScanResult` - 27 edges
4. `scan()` - 21 edges
5. `AuditReport` - 18 edges
6. `_Scanner` - 15 edges
7. `Finding` - 15 edges
8. `TestBadFixture` - 14 edges
9. `ScanResult` - 12 edges
10. `mcp-audit` - 11 edges

## Surprising Connections (you probably didn't know these)
- `TestBadFixture` --uses--> `ScanResult`  [INFERRED]
  tests/test_audit.py → audit/ast_scan.py
- `TestCleanFixture` --uses--> `ScanResult`  [INFERRED]
  tests/test_audit.py → audit/ast_scan.py
- `TestCli` --uses--> `ScanResult`  [INFERRED]
  tests/test_audit.py → audit/ast_scan.py
- `TestMaxSeverityCli` --uses--> `ScanResult`  [INFERRED]
  tests/test_audit.py → audit/ast_scan.py
- `TestRuleIDs` --uses--> `ScanResult`  [INFERRED]
  tests/test_audit.py → audit/ast_scan.py

## Import Cycles
- None detected.

## Communities (14 total, 5 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.06
Nodes (19): All findings from a full scan, organized by dimension., ScanResult, RuleID, _ast_scan_str(), Helper to scan a source-string snippet via the AST visitor.      Bypasses the fi, Regression test for a false-positive caught during dev:     `os.environ.get(KEY), `os.environ.get('FOO', 'https://default.com')` should record the     default URL, `# mcp-audit: ignore MCP00X` directive must remove the matching     finding whil (+11 more)

### Community 1 - "Community 1"
Cohesion: 0.07
Nodes (36): _is_excluded(), _parse_deps(), _parse_suppression_map(), For one .py source string, return {line_number: frozenset of rule IDs}     suppr, Return (deps_list, source_filename)., Should this .py file be skipped by default scan logic?, Walk every .py file under target_path. Returns a ScanResult.      By default, ex, Convenience: scan + dump as JSON. (+28 more)

### Community 2 - "Community 2"
Cohesion: 0.14
Nodes (18): AST, _call_dict(), CallSite, _dotted_name(), _extract_url_arg(), _get_kwarg_value(), _hosts_from_string(), _is_falsey_constant() (+10 more)

### Community 3 - "Community 3"
Cohesion: 0.26
Nodes (23): AuditReport, build_report(), _check_code_execution(), _check_dependencies(), _check_env_vars(), _check_filesystem(), _check_inbound_network(), _check_network_egress() (+15 more)

### Community 4 - "Community 4"
Cohesion: 0.14
Nodes (13): CI integration, Contributing, Development, Example: real-world audit, Install, License, mcp-audit, Roadmap (+5 more)

### Community 6 - "Community 6"
Cohesion: 0.18
Nodes (10): Capabilities (auto-detected), Dependencies, Findings, Low (1), [MCP011] All 1 dep(s) use loose version pins, Score: 10/10 — low risk, Scoring methodology, Security Audit: jarvis-trading-mcp (+2 more)

### Community 10 - "Community 10"
Cohesion: 0.60
Nodes (4): _api_get(), get_thing(), main(), Minimal clean MCP fixture — should score 10/10.  Mirrors the friend_mcp pattern:

## Knowledge Gaps
- **18 isolated node(s):** `Constant`, `What it detects`, `Install`, `CI integration`, `Suppressing findings` (+13 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ScanResult` connect `Community 0` to `Community 1`, `Community 2`, `Community 3`, `Community 5`, `Community 7`, `Community 9`, `Community 11`?**
  _High betweenness centrality (0.182) - this node is a cross-community bridge._
- **Why does `_ast_scan_str()` connect `Community 0` to `Community 1`, `Community 2`?**
  _High betweenness centrality (0.157) - this node is a cross-community bridge._
- **Why does `_Scanner` connect `Community 2` to `Community 0`, `Community 1`?**
  _High betweenness centrality (0.091) - this node is a cross-community bridge._
- **Are the 20 inferred relationships involving `ScanResult` (e.g. with `AuditReport` and `Finding`) actually correct?**
  _`ScanResult` has 20 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `AuditReport` (e.g. with `ScanResult` and `AuditReport`) actually correct?**
  _`AuditReport` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Constant`, `AST-based security scanner for Python packages.  Walks every .py file in a targe`, `For one .py source string, return {line_number: frozenset of rule IDs}     suppr` to the rest of the system?**
  _57 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.061495457721872815 - nodes in this community are weakly interconnected._