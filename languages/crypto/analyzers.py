"""Crypto analyzers -- findings-only, like the infra ones."""
from __future__ import annotations

from checks import crypto
from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route
from core.registry import register
from core.rulescan import dedupe


@register("crypto", "java")
class JavaCryptoAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        return dedupe(crypto.scan_java(self.target_path))


@register("crypto", "php")
class PhpCryptoAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        return dedupe(crypto.scan_php(self.target_path))
