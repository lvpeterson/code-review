"""CLI entry point for the appsec code review skeleton.

Usage:
    python main.py <target_path>
    python main.py <target_path> --json out.json
    python main.py <target_path> --html report.html
    python main.py <target_path> --language python --framework flask
    python main.py <target_path> --allow-path "/health" --allow-path "/api/public/*"
    python main.py <target_path> --fail-on medium   # exit 1 if any medium+ finding exists (CI use)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.allowlist import apply_allowlist
from core.html_report import write_html
from core.report import meets_or_exceeds, print_console, worst_severity, write_json
from enumerator import enumerate_target


def main() -> int:
    parser = argparse.ArgumentParser(description="Baseline appsec code review scaffold")
    parser.add_argument("target", type=Path, help="Path to the codebase to analyze")
    parser.add_argument("--json", type=Path, default=None, help="Write results as JSON to this path")
    parser.add_argument("--html", type=Path, default=None, help="Write an interactive HTML report to this path")
    parser.add_argument("--language", default=None, help="Skip detection, force this language (e.g. python)")
    parser.add_argument("--framework", default=None, help="Skip detection, force this framework (e.g. flask)")
    parser.add_argument(
        "--allow-path",
        action="append",
        default=None,
        metavar="GLOB",
        help="Glob pattern (repeatable) for routes that are intentionally public -- "
        "suppresses AUTH-001 findings on matching routes, e.g. --allow-path '/health'",
    )
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "info"],
        default=None,
        help="Exit 1 if any finding at or above this severity exists (for CI use)",
    )
    args = parser.parse_args()

    if not args.target.exists():
        print(f"error: target path does not exist: {args.target}", file=sys.stderr)
        return 1

    target_path = args.target.resolve()
    results = enumerate_target(
        target_path,
        force_language=args.language,
        force_framework=args.framework,
    )

    if args.allow_path:
        apply_allowlist(results, args.allow_path)

    print_console(results)

    if args.json:
        write_json(results, args.json)
        print(f"\nwrote JSON report to {args.json}")

    if args.html:
        write_html(results, target_path, args.html)
        print(f"\nwrote HTML report to {args.html}")

    if args.fail_on:
        worst = worst_severity(results)
        if worst and meets_or_exceeds(worst, args.fail_on):
            print(f"\nfail-on threshold '{args.fail_on}' met (worst finding: {worst})", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
