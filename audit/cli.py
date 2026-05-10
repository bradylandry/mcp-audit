"""mcp-audit CLI entry point.

Usage:
    mcp-audit /path/to/mcp/package
    mcp-audit /path/to/mcp/package --json
    mcp-audit /path/to/mcp/package --json > raw.json
    mcp-audit /path/to/mcp/package --score-only

The default output is a markdown report on stdout — pipe to a file
or pager as you would `git diff`. JSON mode emits the raw scan
result for programmatic consumption (e.g., a CI script that wants
to fail builds when the score drops below a threshold).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from audit.ast_scan import scan, scan_to_json
from audit.findings import build_report
from audit.report import render_markdown


__version__ = "0.1.0"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description=(
            "Static-analysis security audit for a Python MCP package. "
            "Walks every .py file under the target path, classifies imports "
            "and function calls into 8 audit dimensions, produces a markdown "
            "report on stdout. Pure stdlib — no network, no LLM."
        ),
    )
    parser.add_argument(
        "target",
        help="Path to the package to audit (directory containing .py files OR a single .py file)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit raw scan results as JSON instead of markdown",
    )
    parser.add_argument(
        "--score-only",
        action="store_true",
        help="Print only the integer score 0-10 (useful for CI exit-code thresholds)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcp-audit {__version__}",
    )
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 2

    try:
        if args.json:
            sys.stdout.write(scan_to_json(target))
            sys.stdout.write("\n")
            return 0

        scan_result = scan(target)
        report = build_report(scan_result)

        if args.score_only:
            print(report.score)
            return 0

        sys.stdout.write(render_markdown(report, tool_version=__version__))
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
