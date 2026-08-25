"""STUB deep-dive analyzer for Sinatra targets. See rails_analyzer.py for the pattern to follow."""
from __future__ import annotations

from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route
from core.registry import register


@register("ruby", "sinatra")
class SinatraAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        return []

    def analyze(self):
        result = super().analyze()
        result.notes.append(
            "sinatra analyzer is a stub -- route extraction not implemented yet."
        )
        return result
