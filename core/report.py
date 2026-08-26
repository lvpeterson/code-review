"""Turns ScanResults into human-readable console output, JSON, or a single
worst-severity verdict for CI exit-code purposes.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from core.models import Finding, ScanResult

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def print_console(results: list[ScanResult]) -> None:
    if not results:
        print("No supported language/framework detected in target.")
        return

    for result in results:
        header = f"=== {result.language} / {result.framework} ==="
        print(f"\n{header}")
        print(f"routes found: {len(result.routes)}")

        for route in result.routes:
            methods = ",".join(route.methods) or "?"
            auth = ",".join(route.auth_decorators) if route.auth_decorators else "-"
            print(f"  [{methods}] {route.path} -> {route.handler_name}  ({route.file}:{route.line})  auth={auth}")

        if result.findings:
            print(f"\nbaseline findings: {len(result.findings)}")
            for finding in sorted(result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9)):
                print(f"  [{finding.severity.upper():6}] {finding.check_id}  {finding.title}")
                print(f"           {finding.description}")
                print(f"           {finding.file}:{finding.line}")
        else:
            print("\nbaseline findings: none")

        for note in result.notes:
            print(f"note: {note}")

        if result.global_auth_source:
            gfile, gline, gdescription = result.global_auth_source
            print(f"global auth: {gfile}:{gline} -- {gdescription}")


def _finding_to_dict(finding: Finding) -> dict:
    # Deliberately excludes `finding.route` -- it's a full copy of a Route
    # already present in this same ScanResult's `routes` list (dataclasses
    # asdict() would otherwise recursively re-embed the whole object here),
    # and `file`/`line` already say exactly which route this finding is
    # about without the duplication.
    return {
        "check_id": finding.check_id,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "file": finding.file,
        "line": finding.line,
    }


def _scan_result_to_dict(result: ScanResult) -> dict:
    return {
        "language": result.language,
        "framework": result.framework,
        "routes": [asdict(route) for route in result.routes],
        "findings": [_finding_to_dict(f) for f in result.findings],
        "notes": result.notes,
        "global_auth_source": list(result.global_auth_source) if result.global_auth_source else None,
    }


def write_json(results: list[ScanResult], out_path: Path) -> None:
    payload = [_scan_result_to_dict(result) for result in results]
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def worst_severity(results: list[ScanResult]) -> str | None:
    """The single worst finding severity across every result, or None if
    there are no findings at all -- used to decide a CI exit code.
    """
    all_findings = [f for r in results for f in r.findings]
    if not all_findings:
        return None
    return min(all_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9)).severity


def meets_or_exceeds(severity: str, threshold: str) -> bool:
    """True if `severity` is at least as bad as `threshold` (e.g. a "high"
    finding meets_or_exceeds("medium")). Unknown severities never trigger.
    """
    if severity not in _SEVERITY_ORDER or threshold not in _SEVERITY_ORDER:
        return False
    return _SEVERITY_ORDER[severity] <= _SEVERITY_ORDER[threshold]
