"""Base class every framework-specific deep-dive analyzer implements."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from core.models import Finding, Route, ScanResult


class BaseFrameworkAnalyzer(ABC):
    """Deep-dive analyzer for one (language, framework) pair.

    Subclasses live under languages/<language>/<framework>_analyzer.py and
    register themselves with @registry.register("language", "framework").
    """

    language: str = "unknown"
    framework: str = "unknown"

    def __init__(self, target_path: Path):
        self.target_path = target_path

    @abstractmethod
    def find_routes(self) -> list[Route]:
        """Locate routes/endpoints defined in the target codebase.

        This is intentionally framework-specific -- Flask decorators, Spring
        annotations, Express router calls, etc. all look different. Return
        as much as you can determine cheaply (path, methods, handler, any
        visible auth decorator/middleware name); leave the rest for the
        checks in checks/ to reason about.
        """
        raise NotImplementedError

    @abstractmethod
    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        """Run baseline appsec checks (IDOR/auth/etc) against found routes.

        Prefer composing the shared heuristics in checks/idor.py and
        checks/auth.py, then layering framework-specific checks on top
        (e.g. Spring @PreAuthorize, Django permission_classes, Express
        auth middleware chains).
        """
        raise NotImplementedError

    def analyze(self) -> ScanResult:
        routes = self.find_routes()
        findings = self.run_baseline_checks(routes)
        return ScanResult(
            language=self.language,
            framework=self.framework,
            routes=routes,
            findings=findings,
        )
