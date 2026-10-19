"""Oracle PL/SQL deep-dive: runs the checks/plsql.py rule set over every
PL/SQL source file in the target and converts each hit into a project-wide
Finding (route=None), so it lands in the HTML report's Findings tab, the
SARIF export, and --fail-on like any other check.

There are no routes to extract -- stored code is reached through whatever
application calls it, so tracing a hit back to an HTTP route (or a
scheduler job, or a DB link) is always manual. See languages/sql/README.md.
"""
from __future__ import annotations

from pathlib import Path

from checks import plsql
from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route
from core.registry import register

_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def hit_to_finding(hit: plsql.PlsqlHit, relative_file: str) -> Finding:
    guidance = hit.block_note or hit.rule.note
    if hit.block_note and hit.rule.note:
        guidance = f"{hit.block_note} {hit.rule.note}"
    return Finding(
        check_id=hit.rule.id,
        severity=_SEVERITY[hit.rule.severity],
        title=f"{hit.rule.category}: {hit.title}",
        description=guidance,
        file=relative_file,
        line=hit.line_no,
        route=None,
        confidence=hit.confidence,
    )


@register("sql", "plsql")
class PlsqlAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings = []
        for hit in plsql.scan_project(self.target_path):
            relative_file = str(Path(hit.file).relative_to(self.target_path))
            findings.append(hit_to_finding(hit, relative_file))
        return findings
