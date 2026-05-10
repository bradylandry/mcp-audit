"""mcp-audit CLI entry point.

Usage:
    mcp-audit /path/to/mcp/package
    mcp-audit /path/to/mcp/package --json
    mcp-audit /path/to/mcp/package --json-report
    mcp-audit /path/to/mcp/package --score-only
    mcp-audit /path/to/mcp/package --include-tests
    mcp-audit /path/to/mcp/package --ascii

The default output is a markdown report on stdout — pipe to a file
or pager as you would `git diff`.

Output modes:
  default    : markdown report
  --json     : raw scan results (the AST findings, no scoring)
  --json-report : full audit report including score, findings, severities,
                  capabilities — the right thing for CI / programmatic use
  --score-only : a single integer 0-10
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from audit.ast_scan import scan, scan_to_json
from audit.findings import build_report, Finding
from audit.report import render_markdown


def _get_version() -> str:
    """Read version from package metadata (single source of truth — pyproject.toml)."""
    try:
        from importlib.metadata import version
        return version("mcp-audit")
    except Exception:
        return "0.0.0+unknown"


__version__ = _get_version()


def _reconfigure_stdout_utf8() -> None:
    """Force stdout to UTF-8 so emoji + em-dash don't crash on Windows
    cp1252 / non-UTF-8 terminals. Caught 2026-05-10 by external auditor:
    test_markdown_output_has_score_line was failing on Windows because
    the renderer emits ✅/❌/— and the default Windows console codec
    couldn't decode them. Best-effort — older interpreters without
    .reconfigure() silently fall through to the original behavior."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass


def _report_to_dict(report) -> dict:
    """Serialize an AuditReport to a JSON-safe dict including score,
    findings, capabilities, and the underlying scan summary. Preferred
    over `--json` for CI: a script that wants to fail when score < 8 or
    when any high-severity finding fires can read this output directly."""
    return {
        "score": report.score,
        "score_explanation": report.score_explanation,
        "capabilities_yes": report.capabilities_yes,
        "capabilities_no":  report.capabilities_no,
        "findings": [
            {
                "dimension": f.dimension,
                "severity":  f.severity,
                "title":     f.title,
                "detail":    f.detail,
                "deduction": f.deduction,
            }
            for f in report.findings
        ],
        "scan_summary": {
            "target_path":   report.scan.target_path,
            "files_scanned": report.scan.files_scanned,
            "lines_scanned": report.scan.lines_scanned,
            "hosts":         sorted(report.scan.hosts),
            "dependencies":  report.scan.dependencies,
            "dep_source":    report.scan.dep_source,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description=(
            "Static-analysis security audit for a Python MCP package. "
            "Walks every .py file under the target path (excluding tests "
            "+ fixtures + examples by default), classifies imports and "
            "function calls into 9 audit dimensions, produces a markdown "
            "report on stdout. Pure stdlib — no network, no LLM."
        ),
    )
    parser.add_argument(
        "target",
        help="Path to the package to audit (directory containing .py files OR a single .py file)",
    )

    out = parser.add_mutually_exclusive_group()
    out.add_argument(
        "--json",
        action="store_true",
        help="Emit raw scan results as JSON (AST findings, no scoring or severity)",
    )
    out.add_argument(
        "--json-report",
        action="store_true",
        help="Emit the full audit report (score + findings + capabilities) as JSON. Recommended for CI.",
    )
    out.add_argument(
        "--score-only",
        action="store_true",
        help="Print only the integer score 0-10 (useful for CI exit-code thresholds)",
    )

    parser.add_argument(
        "--include-tests",
        action="store_true",
        help=(
            "Include test/fixture/example directories in the scan. "
            "By default these are excluded because they often deliberately "
            "violate audit dimensions (e.g., a bad_mcp fixture testing the "
            "audit tool itself). Use this for full-coverage audits."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcp-audit {_get_version()}",
    )
    args = parser.parse_args(argv)

    _reconfigure_stdout_utf8()

    target = Path(args.target)
    if not target.exists():
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 2

    try:
        scan_result = scan(target, include_tests=args.include_tests)

        if args.json:
            sys.stdout.write(scan_to_json(target, include_tests=args.include_tests))
            sys.stdout.write("\n")
            return 0

        report = build_report(scan_result)

        if args.score_only:
            print(report.score)
            return 0

        if args.json_report:
            sys.stdout.write(json.dumps(_report_to_dict(report), indent=2))
            sys.stdout.write("\n")
            return 0

        sys.stdout.write(render_markdown(report, tool_version=_get_version()))
        return 0

    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: unexpected failure during scan: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
