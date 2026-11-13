"""Analyzer registrations for the legacy .NET Framework package.

Five analyzers share one ProjectModel (prepared once by the enumerator, so the
Roslyn helper runs once per scan): mvc, webapi, webforms and wcf split the routes
and auth findings by route kind, config runs the web.config rules. Route
discovery and auth resolution happen once per model and are cached on
`model.cache`. In degraded mode (no helper) the code-driven analyzers return
nothing and only config still reports.
"""
from __future__ import annotations

import sys
from pathlib import Path

from checks.dnl import auth, project, routes, rules_auth, rules_config, rules_crypto, rules_deser_xml, rules_integrity, rules_object, rules_session, rules_taint, rules_wcf_config, rules_xss
from checks.dnl.files import iter_dnl_files
from checks.dnl.project import ProjectModel
from checks.dnl.webconfig import load_configs
from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route, ScanResult
from core.registry import register
from languages.dotnet_legacy import detector

_MVC_REF = "system.web.mvc"
_API_REF = "system.web.http"
_WCF_REF = "system.servicemodel"


def _real_projects(model: ProjectModel) -> list[project.Project]:
    # The "(loose)" pseudo-projects sit at the scan root and would claim every dir.
    return [p for p in model.projects if p.path is not None]


def _enumerated(model: ProjectModel) -> list[str]:
    """Frameworks the enumerator runs for this scan (detector order), cached on the model."""
    cached = model.cache.get("enumerated")
    if cached is None:
        cached = model.cache["enumerated"] = detector.detect_frameworks(model.root)
    return cached


def _owner_kind(model: ProjectModel, f: Finding) -> str:
    """Which analyzer reports a route-less finding (AUTHZ-003 on an auth filter type):
    mvc when the type's project references System.Web.Mvc, wcf when it references
    System.ServiceModel, else webapi when any project references System.Web.Http,
    else mvc / webforms by what the solution has.
    The owner must actually be enumerated; otherwise the first code analyzer that
    runs takes it, and with none, the config analyzer."""
    proj = model.project_of(f.file)
    if proj is None:
        # Markup (views, layouts) is not a compile item: use the deepest project dir holding it.
        abs_f = (model.root / f.file).resolve()
        # Resolved project dirs and the references union are computed once per model.
        pdirs = model.cache.get("owner_dirs")
        if pdirs is None:
            pdirs = model.cache["owner_dirs"] = [(p, p.dir.resolve()) for p in _real_projects(model)]
        dirs = [(p, d) for p, d in pdirs if abs_f.is_relative_to(d)]
        proj = max(dirs, key=lambda pd: len(pd[1].parts), default=(None, None))[0]
    refs = model.cache.get("refs_union")
    if refs is None:
        refs = model.cache["refs_union"] = (set().union(*(p.references for p in model.projects))
                                            if model.projects else set())
    running = [k for k in _enumerated(model) if k != "config"]
    if f.file.lower().endswith((".aspx", ".ascx", ".master")):
        want = "webforms"
    elif proj is not None and _MVC_REF in proj.references:
        want = "mvc"
    elif proj is not None and _WCF_REF in proj.references and "wcf" in running:
        want = "wcf"
    elif _API_REF in refs:
        want = "webapi"
    else:
        want = "mvc" if _MVC_REF in refs else "webforms"
    if not running:
        return "config"
    return want if want in running else running[0]


def _code_results(model: ProjectModel) -> dict[str, tuple[list[Route], list[Finding]]]:
    """{kind: (routes, findings)} for mvc / webapi / webforms / wcf, computed once per model."""
    cached = model.cache.get("code_results")
    if cached is not None:
        return cached
    out: dict[str, tuple[list[Route], list[Finding]]] = {k: ([], []) for k in ("mvc", "webapi", "webforms", "wcf", "config")}
    if not model.degraded:
        # Deeply nested expressions recurse through the evaluator; give it headroom.
        sys.setrecursionlimit(max(sys.getrecursionlimit(), 4000))
        refs = routes.discover_mvc_webapi(model) + routes.discover_webforms(model) + routes.discover_wcf(model)
        findings = rules_auth.check_routes(model, refs, auth.global_filters(model), auth.chain_for_model(model))
        findings += rules_taint.check(model, refs)
        findings += rules_xss.check(model, refs)
        findings += rules_object.check(model, refs)
        findings += rules_crypto.check(model, refs)
        findings += rules_deser_xml.check(model, refs)
        findings += rules_integrity.check(model, refs)
        findings += rules_session.check(model, refs)
        for ref in refs:
            out[ref.route.meta["kind"]][0].append(ref.route)
        for f in findings:
            kind = f.route.meta["kind"] if f.route is not None else _owner_kind(model, f)
            out[kind][1].append(f)
    model.cache["code_results"] = out
    return out


class _DnlAnalyzer(BaseFrameworkAnalyzer):
    language = "dotnet_legacy"

    def __init__(self, target_path: Path):
        super().__init__(target_path)
        self._model: ProjectModel | None = None
        self._notes: list[str] = []

    @property
    def model(self) -> ProjectModel:
        if self._model is None:
            self._model = project.get_model(self.target_path)
        return self._model

    def find_routes(self) -> list[Route]:
        return list(_code_results(self.model)[self.framework][0])

    def run_baseline_checks(self, routes_: list[Route]) -> list[Finding]:
        return list(_code_results(self.model)[self.framework][1])

    def analyze(self) -> ScanResult:
        result = super().analyze()
        result.degraded = self.model.degraded
        # Model notes describe the whole scan: the first analyzer to report takes them.
        notes = [] if self.model.cache.get("notes_taken") else list(self.model.notes)
        self.model.cache["notes_taken"] = True
        result.notes = notes + self._notes
        return result


@register("dotnet_legacy", "mvc")
class MvcAnalyzer(_DnlAnalyzer):
    framework = "mvc"


@register("dotnet_legacy", "webapi")
class WebApiAnalyzer(_DnlAnalyzer):
    framework = "webapi"


@register("dotnet_legacy", "webforms")
class WebFormsAnalyzer(_DnlAnalyzer):
    framework = "webforms"


@register("dotnet_legacy", "wcf")
class WcfAnalyzer(_DnlAnalyzer):
    framework = "wcf"


@register("dotnet_legacy", "config")
class ConfigAnalyzer(_DnlAnalyzer):
    """web.config rules; needs no IR, so it also runs in degraded mode."""
    framework = "config"

    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes_: list[Route]) -> list[Finding]:
        model = self.model
        projects = _real_projects(model)
        api_dirs = {p.dir for p in projects if _API_REF in p.references}
        aspx_dirs = {p.dir for p in projects if next(iter_dnl_files(p.dir, (".aspx",)), None) is not None}
        aspx_dirs |= routes.webforms_site_dirs(model)
        configs = load_configs(model.root)
        findings, self._notes = rules_config.check_configs(
            configs, api_dirs, aspx_dirs, project_dirs={p.dir for p in projects})
        wcf_findings, wcf_notes = rules_wcf_config.check_configs(configs, rules_wcf_config.hosted_services(model))
        findings += wcf_findings
        self._notes += wcf_notes + rules_wcf_config.non_web_config_notes(model.root)
        if model.degraded:
            # Markup rules need no IR; in degraded mode they run here, without page routes.
            findings += rules_integrity.check(model)
        # Route-less findings whose owning code analyzer is not enumerated land here.
        return findings + list(_code_results(model)["config"][1])
