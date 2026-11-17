"""dotnet (ASP.NET Core) detector, analyzers, AUTHZ findings and OWASP tags on the synthetic fixtures."""
import shutil
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project
from core.allowlist import apply_allowlist
from core.owasp_web import tag_results
from languages.dotnet import detector as core_detector
from languages.dotnet_legacy import detector as legacy_detector

FIX = Path(__file__).parent / "fixtures"
FX = FIX / "aspnetcore"
CONTROLLERS, RAZOR, MINIMAL, MIXED = (FX / n for n in ("controllers_api", "razor_app", "minimal_api", "mixed_solution"))


@pytest.fixture(autouse=True)
def _fresh():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


def _degraded(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)


def _dotnet(root, **kw):
    return [r for r in enumerator.enumerate_target(root, **kw) if r.language == "dotnet"]


def _found(results):
    """{(check_id, severity, confidence, handler-or-file)} of every finding."""
    out = set()
    for res in results:
        for f in res.findings:
            out.add((f.check_id, f.severity, f.confidence, f.route.handler_name if f.route else Path(f.file).name))
    return out


def _by_path(results, check_id, path):
    return [f for r in results for f in r.findings if f.check_id == check_id and f.route and f.route.path == path]


def _by_handler(results, check_id, handler):
    return [f for r in results for f in r.findings
            if f.check_id == check_id and f.route and f.route.handler_name == handler]


# -- detector ------------------------------------------------------------------

def test_detector():
    for root, fw in ((CONTROLLERS, ["controllers", "config"]), (RAZOR, ["razorpages", "config"]),
                     (MINIMAL, ["minimalapi", "config"]), (MIXED, ["controllers", "config"])):
        assert core_detector.detect_language(root), root
        assert core_detector.detect_frameworks(root) == fw, root
    assert legacy_detector.detect_language(MIXED)
    assert "mvc" in legacy_detector.detect_frameworks(MIXED)


def test_detector_ignores_legacy_only(tmp_path):
    root = tmp_path / "mvc5_app"
    shutil.copytree(FIX / "dotnet_legacy" / "mvc5_app", root, ignore=shutil.ignore_patterns("CoreSide"))
    assert not core_detector.detect_language(root)
    assert core_detector.detect_frameworks(root) == []
    assert legacy_detector.detect_language(root)


def test_detector_loose_core_source(tmp_path):
    (tmp_path / "Program.cs").write_text(
        'var app = WebApplication.CreateBuilder(args).Build();\napp.MapGet("/x", () => 1);\n')
    assert core_detector.detect_language(tmp_path)
    assert core_detector.detect_frameworks(tmp_path) == ["minimalapi", "config"]


# -- analyzers -----------------------------------------------------------------

def test_analyzers_split_routes(roslyn_helper):
    results = _dotnet(MINIMAL)
    by_fw = {r.framework: r for r in results}
    assert set(by_fw) == {"minimalapi", "config"}
    assert {"/api/orders/{id}", "/chat"} <= {r.path for r in by_fw["minimalapi"].routes}
    assert by_fw["config"].routes == []
    assert all(r.language == "dotnet" and not r.degraded for r in results)


def test_findings(roslyn_helper):
    ctrl = _found(_dotnet(CONTROLLERS))
    assert ("DNL-AUTHZ-001", "medium", None, "HealthController.Get") in ctrl
    assert ("DNL-AUTHZ-001", "medium", "REVIEW", "ReportsController.List") in ctrl
    assert ("DNL-AUTHZ-001", "info", None, "OrdersController.Public") in ctrl
    assert ("DNL-AUTHZ-003", "high", None, "AuditHandler.cs") in ctrl
    assert not [c for c in ctrl if c[0] == "DNL-AUTHZ-001" and c[3] == "OrdersController.Get"]
    # The "Audit" policy only has an always-succeeding handler: the action stays unprotected.
    assert ("DNL-AUTHZ-001", "medium", None, "AuditController.Log") in ctrl

    razor = _dotnet(RAZOR)
    (edit,) = _by_handler(razor, "DNL-AUTHZ-001", "EditModel.OnPostSave")
    assert edit.severity == "high" and edit.confidence is None
    assert "ignored" in edit.description and "OnPostSave" in edit.description
    assert ("DNL-AUTHZ-001", "medium", "REVIEW", "MissingModel") in _found(razor)

    mini = _dotnet(MINIMAL)
    for path in ("/orphan", "/audit/a"):
        (f,) = _by_path(mini, "DNL-AUTHZ-001", path)
        assert f.severity == "medium" and f.confidence == "REVIEW" and "Reasons:" in f.description, path
    for path in ("/", "/v2/users", "/healthz"):
        (f,) = _by_path(mini, "DNL-AUTHZ-001", path)
        assert f.confidence is None, path
    assert not _by_path(mini, "DNL-AUTHZ-001", "/debug/env")   # Development only


def test_auth_source_on_route(roslyn_helper):
    res = _dotnet(MINIMAL)
    route = next(r for x in res for r in x.routes if r.path == "/api/orders/{id}")
    assert route.auth_decorators == ["group:/api RequireAuthorization"]
    assert route.meta["auth"]["state"] == "protected"
    anon = next(r for x in res for r in x.routes if r.path == "/api/status")
    assert anon.explicit_access == "PermitAll" and anon.auth_decorators == []


def test_allow_path_suppresses_core_missing_auth(roslyn_helper):
    results = _dotnet(MINIMAL)
    assert _by_path(results, "DNL-AUTHZ-001", "/healthz") and _by_path(results, "DNL-AUTHZ-001", "/")
    apply_allowlist(results, ["/healthz"])
    assert not _by_path(results, "DNL-AUTHZ-001", "/healthz")
    assert _by_path(results, "DNL-AUTHZ-001", "/")


def test_owasp_tags(roslyn_helper):
    mini, razor = _dotnet(MINIMAL), _dotnet(RAZOR)
    tag_results(mini + razor)
    (api,) = _by_path(mini, "DNL-AUTHZ-001", "/v2/users")
    assert api.owasp["api2023"].startswith("API5:2023")
    (page,) = _by_handler(razor, "DNL-AUTHZ-001", "IndexModel.OnGet")
    assert "api2023" not in page.owasp and page.owasp["2025"].startswith("A01:2025")


def test_authz_008_finding(roslyn_helper):
    results = _dotnet(FX / "pipelines" / "startup")
    cfg = next(r for r in results if r.framework == "config")
    hits = [f for f in cfg.findings if f.check_id == "DNL-AUTHZ-008"]
    assert len(hits) == 1 and hits[0].severity == "medium" and hits[0].route is None
    assert hits[0].owasp["api2023"].startswith("API5:2023")
    assert not [f for r in results if r is not cfg for f in r.findings if f.check_id == "DNL-AUTHZ-008"]


def test_never_denying_filter_attribute(roslyn_helper, tmp_path):
    root = tmp_path / "app"
    shutil.copytree(CONTROLLERS, root)
    (root / "Auth" / "OpenFilter.cs").write_text(
        "using Microsoft.AspNetCore.Mvc.Filters;\n"
        "public class OpenFilterAttribute : System.Attribute, IAuthorizationFilter {\n"
        "  public void OnAuthorization(AuthorizationFilterContext context) { var x = 1; }\n}\n")
    hits = [f for r in _dotnet(root) for f in r.findings if f.check_id == "DNL-AUTHZ-003" and "OpenFilter" in f.title]
    assert len(hits) == 1 and hits[0].severity == "high" and hits[0].route is None


def _keys(results):
    return {(f.check_id, f.route.path if f.route else None) for r in results for f in r.findings}


def test_degraded_end_to_end(roslyn_helper, monkeypatch):
    full = _dotnet(MINIMAL)
    project._CACHE.clear()
    _degraded(monkeypatch)
    degraded = _dotnet(MINIMAL, allow_degraded=True)
    assert degraded and all(r.degraded for r in degraded)
    assert _keys(degraded) == _keys(full)


# -- fix round 1 ---------------------------------------------------------------

def _with_program(tmp_path, extra):
    root = tmp_path / "app"
    shutil.copytree(CONTROLLERS, root)
    prog = root / "Program.cs"
    text = prog.read_text()
    assert "app.Run();" in text
    prog.write_text(text.replace("app.Run();", extra + "\napp.Run();"))
    return root


def test_detector_enables_minimalapi_for_any_map_call(tmp_path):
    calls = ('app.MapBlazorHub();', 'app.MapRazorComponents<App>();', 'app.MapOpenApi();',
             'app.MapFallbackToFile("index.html");', 'app.MapHealthChecks("/h");')
    for n, call in enumerate(calls):
        root = tmp_path / f"app{n}"
        shutil.copytree(CONTROLLERS, root)
        prog = root / "Program.cs"
        prog.write_text(prog.read_text().replace("app.Run();", call + "\napp.Run();"))
        assert core_detector.detect_frameworks(root) == ["controllers", "minimalapi", "config"], call
    assert core_detector.detect_frameworks(CONTROLLERS) == ["controllers", "config"]


def test_route_of_unrunning_analyzer_is_not_dropped(roslyn_helper, tmp_path):
    root = _with_program(tmp_path, 'app.MapHealthChecks("/h");')
    results = enumerator.enumerate_target(root, force_language="dotnet", force_framework="controllers")
    assert [r.framework for r in results] == ["controllers"]
    assert _by_path(results, "DNL-AUTHZ-001", "/h")
    assert any(r.path == "/h" for r in results[0].routes)


def test_forced_framework_still_reports_route_less_findings(roslyn_helper):
    results = enumerator.enumerate_target(FX / "pipelines" / "startup", force_language="dotnet",
                                          force_framework="controllers")
    assert [r.framework for r in results] == ["controllers"]
    assert [f for f in results[0].findings if f.check_id == "DNL-AUTHZ-008"]


def test_legacy_crash_note_survives_mixed_solution(roslyn_helper, monkeypatch):
    from checks.dnl import rules_auth

    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(rules_auth, "check_routes", boom)
    results = enumerator.enumerate_target(MIXED)
    legacy = [r for r in results if r.language == "dotnet_legacy"]
    assert any("rules_auth failed" in n for r in legacy for n in r.notes)


def test_one_route_crash_is_isolated(roslyn_helper, monkeypatch):
    from checks.dnl import auth_core, rules_auth_core
    real = auth_core.resolve

    def flaky(model, ref, pipe):
        if ref.route.handler_name == "HealthController.Get":
            raise RuntimeError("kaput")
        return real(model, ref, pipe)
    monkeypatch.setattr(rules_auth_core.auth_core, "resolve", flaky)
    results = _dotnet(CONTROLLERS)
    (bad,) = _by_handler(results, "DNL-AUTHZ-001", "HealthController.Get")
    assert bad.severity == "medium" and bad.confidence == "REVIEW" and "kaput" in bad.description
    route = next(r for x in results for r in x.routes if r.handler_name == "HealthController.Get")
    assert route.meta["auth"]["state"] == "unknown" and route.auth_decorators == []
    assert _by_handler(results, "DNL-AUTHZ-001", "ReportsController.List")   # the rest continue


def test_dotnet_only_target_without_helper_fails_preflight(monkeypatch):
    from checks.dnl import helper
    _degraded(monkeypatch)
    with pytest.raises(helper.PreflightError):
        enumerator.enumerate_target(MINIMAL)
