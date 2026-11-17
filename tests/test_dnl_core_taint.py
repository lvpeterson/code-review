"""Request sources of the shared taint engine on ASP.NET Core: the synthetic taint_app fixture, with the
Roslyn helper (sym rows) and without it (text fallbacks), and the dotnet analyzer wiring."""
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project, routes_core, rules_taint
from core.owasp_web import tag_results

ROOT = Path(__file__).parent / "fixtures" / "aspnetcore" / "taint_app"


def _prepare(allow_degraded=False):
    project._CACHE.clear()
    project.prepare(ROOT, allow_degraded)
    model = project.get_model(ROOT, "dotnet")
    return model, routes_core.discover_all(model)


@pytest.fixture(scope="module")
def app(roslyn_helper):
    model, refs = _prepare()
    yield model, rules_taint.check(model, refs)
    project._CACHE.clear()


@pytest.fixture
def degraded_app(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    model, refs = _prepare(True)
    yield model, rules_taint.check(model, refs)
    project._CACHE.clear()


def hits(findings, rule, handler):
    return [f for f in findings if f.check_id == rule and f.route is not None
            and f.route.handler_name == handler]


def test_query_source_reaches_command_sink(app):
    got = hits(app[1], "DNL-INJ-002", "EchoController.Cmd")
    assert len(got) == 1 and got[0].severity == "high"
    assert "Source: Request" in got[0].description


def test_body_route_and_header_sources(app):
    for h in ("Body", "Route", "Hdr"):
        assert hits(app[1], "DNL-PATH-001", f"EchoController.{h}"), h


def test_constant_is_not_a_source(app):
    assert not [f for f in app[1] if f.route is not None and f.route.handler_name == "EchoController.Const"]


def _walk(o):
    if isinstance(o, dict):
        yield o
        for v in o.values():
            yield from _walk(v)
    elif isinstance(o, (list, tuple)):
        for v in o:
            yield from _walk(v)


def test_core_sym_rows_resolve(app):
    model, _ = app
    ref = next(r for r in routes_core.discover_all(model) if r.route.handler_name == "EchoController.Cmd")
    members = [n for n in _walk(ref.method.body) if n.get("k") == "member" and n.get("name") == "Query"]
    assert members and members[0].get("sym") == "Microsoft.AspNetCore.Http.HttpRequest.Query"
    got = hits(app[1], "DNL-INJ-002", "EchoController.Cmd")[0]
    assert "Source: Request (" in got.description


def test_degraded_core_sources(degraded_app):
    findings = degraded_app[1]
    assert hits(findings, "DNL-INJ-002", "EchoController.Cmd")
    for h in ("Body", "Route", "Hdr"):
        assert hits(findings, "DNL-PATH-001", f"EchoController.{h}"), h
    assert not [f for f in findings if f.route is not None and f.route.handler_name == "EchoController.Const"]


def test_dotnet_analyzer_reports_taint(roslyn_helper):
    project._CACHE.clear()
    results = [r for r in enumerator.enumerate_target(ROOT) if r.language == "dotnet"]
    tag_results(results)
    found = [f for r in results for f in r.findings if f.check_id == "DNL-INJ-002"]
    assert found and found[0].route.meta["kind"] == "controller"
    assert found[0].owasp and "A05:2025" in str(found[0].owasp)
    project._CACHE.clear()
