"""Turns ScanResults into human-readable console output or JSON."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from core.models import ScanResult

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


def write_json(results: list[ScanResult], out_path: Path) -> None:
    payload = [asdict(result) for result in results]
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
