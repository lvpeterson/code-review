"""STUB deep-dive analyzer for ASP.NET Core targets.

Not implemented yet -- see languages/java/spring_analyzer.py for the
closest pattern to follow (attribute-based routing: [HttpGet("path")],
[Route("path")] on controller actions; class-level [Route] prefix;
[Authorize]/[AllowAnonymous] for auth).
"""
from __future__ import annotations

from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route
from core.registry import register


@register("dotnet", "aspnet")
class AspNetAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        return []

    def analyze(self):
        result = super().analyze()
        result.notes.append(
            "aspnet analyzer is a stub -- route extraction not implemented yet."
        )
        return result
