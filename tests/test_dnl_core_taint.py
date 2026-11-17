"""Request sources of the shared taint engine on ASP.NET Core: the synthetic taint_app fixture, with the
Roslyn helper (sym rows) and without it (text fallbacks), and the dotnet analyzer wiring."""
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project, routes_core, rules_taint, taint_solver
from checks.dnl.ir import MethodIR, ParamIR
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


# -- parameter binding, [BindProperty], minimal-API handler reach -----------------------------

def _route_hits(findings, rule, handler=None, path=None):
    return [f for f in findings if f.check_id == rule and f.route is not None
            and (handler is None or f.route.handler_name == handler)
            and (path is None or f.route.path == path)]


def test_di_and_framework_params_are_not_sources(app):
    for h in ("Di", "Fs", "Ctx"):
        assert not _route_hits(app[1], "DNL-INJ-002", f"BindController.{h}"), h


def test_dto_upload_and_decoy_are_sources(app):
    # Decoy: a request DTO named like the registered service (Models.Auditor vs the global Auditor).
    for h in ("Dto", "Upload", "Decoy"):
        assert _route_hits(app[1], "DNL-INJ-002", f"BindController.{h}"), h


def _line_of(rel, text):
    src = (ROOT / rel).read_text(encoding="utf-8").splitlines()
    return next(i for i, ln in enumerate(src, 1) if text in ln)


def test_bind_property_respects_supports_get(app):
    page = "Pages/Comment.cshtml.cs"
    get = _route_hits(app[1], "DNL-INJ-002", "CommentModel.OnGet")
    # `Text` is not SupportsGet, so only the `tool2` sink (fed by Q) is a hit on GET.
    assert len(get) == 1 and get[0].line == _line_of(page, '"tool2"') and "[BindProperty] Q" in get[0].description
    post = _route_hits(app[1], "DNL-INJ-002", "CommentModel.OnPost")
    assert len(post) == 1 and "[BindProperty] Text" in post[0].description


def test_bound_properties_by_verb(app):
    model, _ = app
    page = next(r for r in routes_core.discover_all(model) if r.route.handler_name == "CommentModel.OnGet")
    post = next(r for r in routes_core.discover_all(model) if r.route.handler_name == "CommentModel.OnPost")
    assert taint_solver.bound_properties(model, page.type, page.method) == {"q"}
    assert taint_solver.bound_properties(model, post.type, post.method) == {"q", "text"}


def test_minimal_api_params_and_as_parameters(app):
    for p in ("/m/cmd", "/m/args"):
        assert _route_hits(app[1], "DNL-INJ-002", path=p), p


def test_lambda_handler_owns_helper_callee(app):
    got = [f for f in app[1] if f.check_id == "DNL-INJ-002" and f.file.endswith("Program.cs")
           and f.route is not None and f.route.path == "/m/helper"]
    assert len(got) == 1


def test_legacy_binding_unchanged(app):
    # Legacy refs keep `_entry_taint`: every non-primitive parameter is a source, DI-looking ones included.
    model, _ = app
    t = next(t for t in model.types() if t.name == "BindController")
    m = MethodIR("A", params=[ParamIR("a", "IReport"), ParamIR("b", "HttpContext"), ParamIR("n", "int")], line=1)
    assert set(taint_solver._entry_taint(model, t, m)) == {0, 1}


def test_degraded_binding(degraded_app):
    findings = degraded_app[1]
    for h in ("Di", "Fs", "Ctx"):
        assert not _route_hits(findings, "DNL-INJ-002", f"BindController.{h}"), h
    # Parameter types are source text in both modes, so the decoy (Models.Auditor vs the registered global
    # Auditor) is told apart by namespace even without symbols.
    for h in ("Dto", "Upload", "Decoy"):
        assert _route_hits(findings, "DNL-INJ-002", f"BindController.{h}"), h
    get = _route_hits(findings, "DNL-INJ-002", "CommentModel.OnGet")
    assert len(get) == 1 and "[BindProperty] Q" in get[0].description
    assert len(_route_hits(findings, "DNL-INJ-002", "CommentModel.OnPost")) == 1
    for p in ("/m/cmd", "/m/args"):
        assert _route_hits(findings, "DNL-INJ-002", path=p), p


# -- declared-type request receivers, same-type helpers, verb rules -----------------------------

def _typed_request_checks(findings):
    for p in ("/m/helper", "/m/req", "/m/ctx"):
        assert _route_hits(findings, "DNL-INJ-002", path=p), p
    for h in ("Req", "Req2"):
        assert _route_hits(findings, "DNL-INJ-002", f"BindController.{h}"), h


def test_typed_request_receivers(app):
    _typed_request_checks(app[1])


def test_typed_request_receivers_degraded(degraded_app):
    _typed_request_checks(degraded_app[1])


def _same_type_helper_checks(findings):
    got = _route_hits(findings, "DNL-INJ-002", "NotesModel.OnPost")
    assert len(got) == 1 and got[0].line == _line_of("Pages/Notes.cshtml.cs", '"tool4"')
    assert "[BindProperty] Text" in got[0].description


def test_helper_on_same_type_sees_bound_property(app):
    _same_type_helper_checks(app[1])


def test_helper_on_same_type_sees_bound_property_degraded(degraded_app):
    _same_type_helper_checks(degraded_app[1])


def test_controller_action_named_like_page_handler_uses_its_attribute(app):
    # `OnGetX` on a controller is an ordinary [HttpPost] action: the bound property is request input.
    got = _route_hits(app[1], "DNL-INJ-002", "BindController.OnGetX")
    assert len(got) == 1 and "[BindProperty] Note" in got[0].description


def test_supports_get_only_literal_false_drops_the_property():
    from checks.dnl.ir import Attr
    assert not taint_solver._supports_get(Attr("BindProperty"))
    assert not taint_solver._supports_get(Attr("BindProperty", named={"SupportsGet": {"k": "lit", "v": False}}))
    assert taint_solver._supports_get(Attr("BindProperty", named={"SupportsGet": {"k": "lit", "v": True}}))
    assert taint_solver._supports_get(Attr("BindProperty", named={"SupportsGet": {"k": "name", "id": "Flag"}}))


def test_model_binder_overrides_type_exclusions(app):
    from types import SimpleNamespace
    from checks.dnl.ir import Attr
    model, _ = app
    t = next(t for t in model.types() if t.name == "BindController")

    def taint(attrs):
        m = MethodIR("A", params=[ParamIR("a", "IReport", attrs)], line=1)
        return set(taint_solver.core_param_taint(model, SimpleNamespace(method=m, type=t, project=None)))
    assert taint([]) == set()
    assert taint([Attr("ModelBinder")]) == {0}
