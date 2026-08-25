"""CLI entry point for the appsec code review skeleton.

Usage:
    python main.py <target_path>
    python main.py <target_path> --json out.json
    python main.py <target_path> --html report.html
    python main.py <target_path> --language python --framework flask
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.html_report import write_html
from core.report import print_console, write_json
from enumerator import enumerate_target


def main() -> int:
    parser = argparse.ArgumentParser(description="Baseline appsec code review scaffold")
    parser.add_argument("target", type=Path, help="Path to the codebase to analyze")
    parser.add_argument("--json", type=Path, default=None, help="Write results as JSON to this path")
    parser.add_argument("--html", type=Path, default=None, help="Write an interactive HTML report to this path")
    parser.add_argument("--language", default=None, help="Skip detection, force this language (e.g. python)")
    parser.add_argument("--framework", default=None, help="Skip detection, force this framework (e.g. flask)")
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

    print_console(results)

    if args.json:
        write_json(results, args.json)
        print(f"\nwrote JSON report to {args.json}")

    if args.html:
        write_html(results, target_path, args.html)
        print(f"\nwrote HTML report to {args.html}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
