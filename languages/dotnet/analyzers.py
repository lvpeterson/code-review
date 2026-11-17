"""Analyzer registrations for the ASP.NET Core (modern .NET) package.

Four analyzers share one ProjectModel view (the `dotnet` projects of the scan, prepared once by the
enumerator so the Roslyn helper runs once for both .NET packages): controllers, razorpages and
minimalapi split the routes and auth findings by route kind, config reports the route-less findings
(never-denying handlers / policies / filters, middleware order). Route discovery and auth resolution
happen once per model and are cached on `model.cache`. In degraded mode (no helper) the same rules
run on the tree-sitter C# IR, so findings can differ in confidence; every result carries the flag.
"""
from __future__ import annotations

import sys
from pathlib import Path

from checks.dnl import project, routes_core, rules_auth_core, rules_crypto, rules_deser_xml, rules_integrity, rules_sca_core
from checks.dnl.project import ProjectModel
from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route, ScanResult
from core.registry import register
from languages.dotnet import detector

_KINDS = ("controllers", "razorpages", "minimalapi", "config")
# Flip to True in the same change that wires rules_taint into _code_results, otherwise DESER-001 /
# XXE-001 on tainted lines are lost or doubled (rules_deser_xml leaves those lines to rules_taint).
CORE_RUNS_TAINT = False
_ROUTELESS = ("config", "deps")   # analyzers that never take routes or route-less code findings
# route.meta["kind"] -> analyzer
_KIND_OWNER = {"controller": "controllers", "razorpage": "razorpages", "minimalapi": "minimalapi",
               "hub": "minimalapi", "grpc": "minimalapi", "blazor": "minimalapi", "health": "minimalapi",
               "fallback": "minimalapi", "openapi": "minimalapi"}


def _running(model: ProjectModel) -> list[str]:
    """Frameworks of this package that actually run in this scan: what the enumerator recorded (a forced
    --framework included), else what the detector finds."""
    shared = model.parent or model
    rec = shared.cache.get("running", {}).get("dotnet")
    if rec is not None:
        return list(rec)
    cached = model.cache.get("enumerated")
    if cached is None:
        cached = model.cache["enumerated"] = detector.detect_frameworks(model.root)
    return cached


def _code_results(model: ProjectModel) -> dict[str, tuple[list[Route], list[Finding]]]:
    """{analyzer: (routes, findings)}, computed once per model."""
    cached = model.cache.get("code_results")
    if cached is not None:
        return cached
    out: dict[str, tuple[list[Route], list[Finding]]] = {k: ([], []) for k in _KINDS}
    # Deeply nested expressions recurse through the evaluator; give it headroom.
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 4000))
    refs = routes_core.discover_all(model)
    findings: list[Finding] = []

    def guarded(name: str, fn):
        # One crashing rule module must not hide the others; say so in the report.
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            note = f"{name} failed ({type(exc).__name__}: {exc}); its findings are missing"
            if note not in model.notes:
                model.notes.append(note)
            return []

    findings += guarded("rules_auth_core", lambda: rules_auth_core.check(model, refs))
    findings += guarded("rules_crypto", lambda: rules_crypto.check(model, refs))
    findings += guarded("rules_deser_xml", lambda: rules_deser_xml.check(model, refs, taint_reports=CORE_RUNS_TAINT))
    findings += guarded("rules_integrity", lambda: rules_integrity.check(model, refs))
    running = _running(model)

    def owner_of(kind: str) -> str:
        # A route whose analyzer does not run (not detected, or not forced) goes to the first route
        # analyzer that does, else to config: routes and their findings are never dropped.
        want = _KIND_OWNER.get(kind, "minimalapi")
        if want in running or not running:
            return want
        return next((k for k in running if k not in _ROUTELESS), "config")

    # Route-less findings go to config; without it, the first analyzer that runs takes them.
    fallback = "config" if "config" in running or not running else next(
        (k for k in running if k not in _ROUTELESS), "config")
    for ref in refs:
        out[owner_of(ref.route.meta["kind"])][0].append(ref.route)
    for f in findings:
        owner = owner_of(f.route.meta["kind"]) if f.route is not None else fallback
        out[owner][1].append(f)
    model.cache["code_results"] = out
    return out


class _CoreAnalyzer(BaseFrameworkAnalyzer):
    language = "dotnet"

    def __init__(self, target_path: Path):
        super().__init__(target_path)
        self._model: ProjectModel | None = None

    @property
    def model(self) -> ProjectModel:
        if self._model is None:
            self._model = project.get_model(self.target_path, "dotnet")
        return self._model

    def find_routes(self) -> list[Route]:
        return list(_code_results(self.model)[self.framework][0])

    def run_baseline_checks(self, routes_: list[Route]) -> list[Finding]:
        return list(_code_results(self.model)[self.framework][1])

    def analyze(self) -> ScanResult:
        result = super().analyze()
        result.degraded = self.model.degraded
        # Model notes describe the whole scan: each analyzer reports those added since the last report
        # (one pointer shared with dotnet_legacy).
        result.notes = self.model.take_notes()
        return result


@register("dotnet", "controllers")
class ControllersAnalyzer(_CoreAnalyzer):
    framework = "controllers"


@register("dotnet", "razorpages")
class RazorPagesAnalyzer(_CoreAnalyzer):
    framework = "razorpages"


@register("dotnet", "minimalapi")
class MinimalApiAnalyzer(_CoreAnalyzer):
    framework = "minimalapi"


@register("dotnet", "config")
class ConfigAnalyzer(_CoreAnalyzer):
    """Route-less findings; also takes routes when no route analyzer runs."""
    framework = "config"


@register("dotnet", "deps")
class DepsAnalyzer(_CoreAnalyzer):
    """Offline SCA for SDK projects (PackageReference, lock file, end-of-support frameworks, wwwroot
    libraries); needs no IR, so it also runs in degraded mode. Has no routes."""
    framework = "deps"

    def __init__(self, target_path: Path):
        super().__init__(target_path)
        self._notes: list[str] = []

    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes_: list[Route]) -> list[Finding]:
        try:
            findings, self._notes = rules_sca_core.check(self.model)
        except Exception as exc:  # noqa: BLE001
            self._notes = [f"rules_sca_core failed ({type(exc).__name__}: {exc}); its findings are missing"]
            return []
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        result.notes += self._notes
        return result
