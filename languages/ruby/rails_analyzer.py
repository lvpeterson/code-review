"""STUB deep-dive analyzer for Ruby on Rails targets.

Not implemented yet -- see languages/python/flask_analyzer.py for the
pattern to follow. Routes live in config/routes.rb (resources :x,
get "/path" => "controller#action", etc); auth is usually a
before_action :authenticate_user! in the controller.
"""
from __future__ import annotations

from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route
from core.registry import register


@register("ruby", "rails")
class RailsAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        return []

    def analyze(self):
        result = super().analyze()
        result.notes.append(
            "rails analyzer is a stub -- route extraction not implemented yet."
        )
        return result
