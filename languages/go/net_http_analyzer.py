"""STUB deep-dive analyzer for plain net/http Go targets.

Not implemented yet -- returns an empty result with a note so the
enumerator output makes it obvious this framework was detected but not
analyzed. Follow languages/python/flask_analyzer.py as a template: extract
routes from http.HandleFunc("/path", handler) / mux.HandleFunc(...) calls,
then run checks.idor / checks.auth against them.
"""
from __future__ import annotations

from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route
from core.registry import register


@register("go", "net_http")
class NetHTTPAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        return []

    def analyze(self):
        result = super().analyze()
        result.notes.append(
            "net/http analyzer is a stub -- route extraction not implemented yet."
        )
        return result
