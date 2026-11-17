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


# -- sinks and sanitizers -----------------------------------------------------------------------

def _sink_handlers(findings, rule):
    return {f.route.handler_name for f in findings if f.check_id == rule and f.route is not None}


def _sink_hits(findings, rule, handler, path=None):
    return _route_hits(findings, rule, handler, path)


def _check_sinks(findings, skip=()):
    """One assertion per action, shared by the helper and degraded runs. `skip` names entries a mode cannot
    decide (with the reason at the call site)."""
    def pos(rule, handler=None, path=None):
        if (rule, handler or path) in skip:
            return
        assert _sink_hits(findings, rule, handler, path), (rule, handler or path)

    def neg(rule, handler):
        if (rule, handler) in skip:
            return
        assert not _sink_hits(findings, rule, f"SinkController.{handler}"), (rule, handler)

    for h in ("RawConcat", "RawInterp", "Exec", "SqlCmd"):
        pos("DNL-INJ-001", f"SinkController.{h}")
    for h in ("Interp", "FromSqlSafe"):
        neg("DNL-INJ-001", h)
    pos("DNL-REDIR-001", "SinkController.Go")
    pos("DNL-REDIR-001", path="/m/r")
    for h in ("GoLocal", "GoGuarded"):
        neg("DNL-REDIR-001", h)
    pos("DNL-PATH-001", "SinkController.FileGet")
    neg("DNL-PATH-001", "FileSafe")
    for h in ("Hdr", "Cookie"):
        pos("DNL-INJ-005", f"SinkController.{h}")
    for h in ("LogInterp", "LogConcat"):
        pos("DNL-LOG-001", f"SinkController.{h}")
    neg("DNL-LOG-001", "LogTemplate")
    pos("DNL-XSS-001", "SinkController.Html")
    pos("DNL-XSS-001", path="/m/c")
    pos("DNL-XSS-001", path="/m/w")
    for h in ("JsonOk", "Encoded"):
        neg("DNL-XSS-001", h)
    pos("DNL-SSRF-001", "SinkController.Fetch")


def test_ef_core_raw_sql(app):
    for h in ("RawConcat", "RawInterp", "Exec", "SqlCmd"):
        assert _sink_hits(app[1], "DNL-INJ-001", f"SinkController.{h}"), h
    for h in ("Interp", "FromSqlSafe"):
        assert not _sink_hits(app[1], "DNL-INJ-001", f"SinkController.{h}"), h


def test_redirects(app):
    assert _sink_hits(app[1], "DNL-REDIR-001", "SinkController.Go")
    assert _route_hits(app[1], "DNL-REDIR-001", path="/m/r")
    for h in ("GoLocal", "GoGuarded"):
        assert not _sink_hits(app[1], "DNL-REDIR-001", f"SinkController.{h}"), h


def test_paths(app):
    assert _sink_hits(app[1], "DNL-PATH-001", "SinkController.FileGet")
    assert not _sink_hits(app[1], "DNL-PATH-001", "SinkController.FileSafe")


def test_headers_and_cookies(app):
    for h in ("Hdr", "Cookie"):
        assert _sink_hits(app[1], "DNL-INJ-005", f"SinkController.{h}"), h


def test_logging_templates(app):
    for h in ("LogInterp", "LogConcat"):
        assert _sink_hits(app[1], "DNL-LOG-001", f"SinkController.{h}"), h
    assert not _sink_hits(app[1], "DNL-LOG-001", "SinkController.LogTemplate")


def test_html_results(app):
    assert _sink_hits(app[1], "DNL-XSS-001", "SinkController.Html")
    for p in ("/m/c", "/m/w"):
        assert _route_hits(app[1], "DNL-XSS-001", path=p), p
    for h in ("JsonOk", "Encoded"):
        assert not _sink_hits(app[1], "DNL-XSS-001", f"SinkController.{h}"), h


def test_ssrf_request_message(app):
    assert _sink_hits(app[1], "DNL-SSRF-001", "SinkController.Fetch")


def test_all_sinks_helper(app):
    _check_sinks(app[1])


def test_degraded_sinks(degraded_app):
    _check_sinks(degraded_app[1])


def test_content_type_condition():
    from checks.dnl import taint_tables as T
    assert T.html_content_type(None) is False
    assert T.html_content_type({"k": "lit", "v": "text/html; charset=utf-8"}) is True
    assert T.html_content_type({"k": "lit", "v": "application/json"}) is False
    assert T.html_content_type({"k": "name", "id": "ct"}) is True


def test_core_request_member_rows_resolve(app):
    # Extra request-derived members must be sources, not merely unmatched syms (R2).
    for sym in ("Microsoft.AspNetCore.Http.HttpRequest.Protocol", "Microsoft.AspNetCore.Http.HttpRequest.ContentLength",
                "Microsoft.AspNetCore.Http.Extensions.UriHelper.GetDisplayUrl",
                "Microsoft.AspNetCore.Http.Extensions.UriHelper.GetEncodedUrl",
                "Microsoft.AspNetCore.Http.Extensions.UriHelper.GetEncodedPathAndQuery",
                "Microsoft.AspNetCore.Http.HeaderDictionaryTypeExtensions.GetTypedHeaders",
                "Microsoft.AspNetCore.Http.IFormFile.Length", "Microsoft.AspNetCore.Http.IFormFile.ContentDisposition"):
        from checks.dnl import taint
        assert any(sr.match(sym) for _s, sr, _t in taint._SOURCE_RES), sym


def _check_sink_extras(findings):
    def has(rule, handler):
        return bool(_route_hits(findings, rule, f"SinkExtraController.{handler}"))
    # The message template is the sink, whatever precedes it; placeholder arguments never are.
    assert has("DNL-LOG-001", "LogEx") and not has("DNL-LOG-001", "LogExTemplate")
    # Content: no content type is text/plain, a MediaTypeNames constant that is not HTML is known.
    assert not has("DNL-XSS-001", "ContentPlain") and not has("DNL-XSS-001", "ContentMedia")
    assert has("DNL-INJ-005", "HdrAppend") and not has("DNL-INJ-005", "DictAdd")
    assert has("DNL-XSS-001", "HtmlStr") and not has("DNL-XSS-001", "UrlEnc")
    assert has("DNL-REDIR-001", "RespRedirect") and has("DNL-REDIR-001", "NewRedirect")
    for h in ("DisplayUrl", "Protocol"):
        assert has("DNL-INJ-002", h), h


def test_sink_extras(app):
    _check_sink_extras(app[1])


def test_sink_extras_degraded(degraded_app):
    _check_sink_extras(degraded_app[1])


# -- fix round 1: EF Core SqlQuery, JSON clients, Text/ContentResult, headers, casts, log names -----------

def _check_more_sinks(findings):
    def has(rule, handler):
        return bool(_route_hits(findings, rule, f"SinkMoreController.{handler}"))
    # EF Core's parameterized Database.SqlQuery<T>(FormattableString) is not the EF6 string form.
    assert not has("DNL-INJ-001", "SqlQuerySafe")
    for h in ("JsonFetch", "JsonPost", "PatchIt", "FetchInit"):
        assert has("DNL-SSRF-001", h), h
    for h in ("TextHtml", "ContentResultHtml", "ContentXml", "ContentSvg", "MarkupCast", "UnsafeEnc"):
        assert has("DNL-XSS-001", h), h
    for h in ("TextPlain", "ContentResultPlain", "ContentResultJson"):
        assert not has("DNL-XSS-001", h), h
    for h in ("LogLevelVar", "LogEventVar", "ScopeNamed"):
        assert has("DNL-LOG-001", h), h
    for h in ("LocationHdr", "TypedLoc"):
        assert has("DNL-REDIR-001", h), h
    for h in ("SendFile", "Virt", "FileResultCtor"):
        assert has("DNL-PATH-001", h), h


def test_more_sinks(app):
    _check_more_sinks(app[1])


def test_more_sinks_degraded(degraded_app):
    _check_more_sinks(degraded_app[1])


def test_content_type_condition_renderable():
    from checks.dnl import taint_tables as T
    for v in ("application/xml", "text/xml", "image/svg+xml", "application/xhtml+xml"):
        assert T.html_content_type({"k": "lit", "v": v}), v
    assert not T.html_content_type({"k": "lit", "v": "text/plain"})
    media = {"k": "member", "name": "Xml", "obj": {"k": "member", "name": "Text",
                                                   "obj": {"k": "name", "id": "MediaTypeNames"}}}
    assert T.html_content_type(media)


# Taint findings (rule|file|line) of the legacy fixture app, with and without the helper, captured at the
# commit before the Core sink rows (f9348e4): the Core rows must not change a legacy finding.
_LEGACY_KEYS = {
    "DNL-DESER-001|TaintCs/DeserXml/FormatterController.cs|16",
    "DNL-DESER-001|TaintCs/DeserXml/FormatterController.cs|37",
    "DNL-DESER-001|TaintCs/DeserXml/FormatterController.cs|43",
    "DNL-INJ-001|TaintCs/Chain.cs|55",
    "DNL-INJ-001|TaintCs/CycleSrc.cs|10",
    "DNL-INJ-001|TaintCs/Dup1.cs|9",
    "DNL-INJ-001|TaintCs/Ext.cs|14",
    "DNL-INJ-001|TaintCs/Ext.cs|19",
    "DNL-INJ-001|TaintCs/Ext.cs|24",
    "DNL-INJ-001|TaintCs/Ext.cs|35",
    "DNL-INJ-001|TaintCs/Flow.cs|12",
    "DNL-INJ-001|TaintCs/Flow.cs|20",
    "DNL-INJ-001|TaintCs/Flow.cs|27",
    "DNL-INJ-001|TaintCs/Flow.cs|34",
    "DNL-INJ-001|TaintCs/Flow.cs|39",
    "DNL-INJ-001|TaintCs/Gaps.cs|23",
    "DNL-INJ-001|TaintCs/Gaps.cs|25",
    "DNL-INJ-001|TaintCs/Gaps.cs|30",
    "DNL-INJ-001|TaintCs/Gaps.cs|42",
    "DNL-INJ-001|TaintCs/Gaps.cs|143",
    "DNL-INJ-001|TaintCs/Gaps.cs|150",
    "DNL-INJ-001|TaintCs/Lonely.cs|10",
    "DNL-INJ-001|TaintCs/Misc.cs|10",
    "DNL-INJ-001|TaintCs/Misc/OutboundExtras.cs|50",
    "DNL-INJ-001|TaintCs/OrderRepository.cs|10",
    "DNL-INJ-001|TaintCs/Orders.cs|11",
    "DNL-INJ-001|TaintCs/Out.cs|14",
    "DNL-INJ-001|TaintCs/Props.cs|12",
    "DNL-INJ-001|TaintCs/Props.cs|20",
    "DNL-INJ-001|TaintCs/Props.cs|26",
    "DNL-INJ-001|TaintCs/Props.cs|34",
    "DNL-INJ-001|TaintCs/Rec.cs|14",
    "DNL-INJ-001|TaintCs/SelfRec.cs|10",
    "DNL-INJ-001|TaintCs/SetSink.cs|10",
    "DNL-INJ-001|TaintCs/Shared.cs|9",
    "DNL-INJ-001|TaintCs/SqlImplA.cs|9",
    "DNL-INJ-001|TaintCs/SqlImplB.cs|9",
    "DNL-INJ-001|TaintCs/Tables.cs|27",
    "DNL-INJ-001|TaintCs/Tables.cs|33",
    "DNL-INJ-001|TaintCs/Tables.cs|39",
    "DNL-INJ-001|TaintCs/Tables.cs|45",
    "DNL-INJ-001|TaintCs/Tables.cs|51",
    "DNL-INJ-001|TaintCs/Tables.cs|57",
    "DNL-INJ-001|TaintCs/UsesAccum.cs|11",
    "DNL-INJ-001|TaintCs/UsesExt.cs|17",
    "DNL-INJ-001|TaintCs/UsesExt.cs|43",
    "DNL-INJ-001|TaintCs/UsesExt.cs|57",
    "DNL-INJ-001|TaintCs/UsesSetters.cs|28",
    "DNL-INJ-001|TaintCs/UsesSetters.cs|41",
    "DNL-INJ-001|TaintCs/Variadic.cs|9",
    "DNL-INJ-001|TaintVb/Gaps.vb|8",
    "DNL-INJ-001|TaintVb/Pages/Search.aspx.vb|12",
    "DNL-INJ-001|TaintVb/Search.vb|9",
    "DNL-INJ-001|TaintVb/Search.vb|15",
    "DNL-INJ-001|TaintVb/Search.vb|21",
    "DNL-INJ-001|TaintVb/Search.vb|27",
    "DNL-INJ-001|TaintVb/Search.vb|31",
    "DNL-INJ-002|TaintCs/CodeSinksController.cs|25",
    "DNL-INJ-003|TaintCs/CodeSinksController.cs|39",
    "DNL-INJ-003|TaintCs/Tables.cs|84",
    "DNL-INJ-004|TaintCs/CodeSinksController.cs|58",
    "DNL-INJ-005|TaintCs/CodeSinksController.cs|67",
    "DNL-INJ-005|TaintCs/Crlf.cs|7",
    "DNL-INJ-005|TaintCs/Crlf.cs|18",
    "DNL-INJ-005|TaintCs/Crlf.cs|23",
    "DNL-INJ-006|TaintCs/Linq.cs|9",
    "DNL-INJ-006|TaintCs/Linq.cs|15",
    "DNL-LOG-001|TaintCs/CodeSinksController.cs|114",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|15",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|21",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|28",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|34",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|40",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|53",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|59",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|22",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|28",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|34",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|41",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|47",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|53",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|60",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|78",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|115",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|162",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|209",
    "DNL-LOG-001|TaintCs/Misc/LoginShapes.cs|37",
    "DNL-LOG-001|TaintCs/Tables.cs|63",
    "DNL-LOG-001|TaintCs/Tables.cs|74",
    "DNL-LOG-001|TaintVb/Misc/MiscVb.vb|21",
    "DNL-LOG-001|TaintVb/Misc/MiscVb.vb|27",
    "DNL-LOG-001|TaintVb/Misc/MiscVb.vb|32",
    "DNL-PATH-001|TaintCs/CodeSinksController.cs|81",
    "DNL-REDIR-001|TaintCs/CodeSinksController.cs|88",
    "DNL-REDIR-001|TaintCs/Guards.cs|14",
    "DNL-REDIR-001|TaintCs/Guards.cs|25",
    "DNL-REDIR-001|TaintCs/Nav.cs|17",
    "DNL-SSRF-001|TaintCs/ApiSsrfController.cs|12",
    "DNL-SSRF-001|TaintCs/CodeSinksController.cs|102",
    "DNL-SSRF-001|TaintCs/Misc/OutboundCalls.cs|60",
    "DNL-SSRF-001|TaintCs/Misc/OutboundCalls.cs|65",
    "DNL-SSRF-001|TaintCs/Misc/OutboundCalls.cs|95",
    "DNL-XSS-001|TaintCs/CodeSinksController.cs|74",
    "DNL-XSS-001|TaintCs/Misc/LoggingCases.cs|87",
    "DNL-XSS-001|TaintCs/Tables.cs|14",
    "DNL-XSS-001|TaintCs/Tables.cs|16",
    "DNL-XSS-001|TaintCs/Tables.cs|18",
    "DNL-XSS-001|TaintCs/Tables.cs|20",
    "DNL-XXE-001|Legacy40/Parse.cs|11",
    "DNL-XXE-001|Legacy40/Parse.cs|31",
    "DNL-XXE-001|Legacy40/Parse.cs|41",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|98",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|127",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|163",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|180",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|193",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|220",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|236",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|242",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|254",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|260",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|284",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|291",
    "DNL-XXE-001|TaintCs/DeserXml/Round4.cs|37",
    "DNL-XXE-001|TaintCs/DeserXml/Round4.cs|83",
    "DNL-XXE-001|TaintCs/DeserXml/Round4.cs|90",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|16",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|44",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|52",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|96",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|124",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|132",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|155",
}
_LEGACY_KEYS_DEGRADED = {
    "DNL-DESER-001|TaintCs/DeserXml/FormatterController.cs|16",
    "DNL-DESER-001|TaintCs/DeserXml/FormatterController.cs|37",
    "DNL-DESER-001|TaintCs/DeserXml/FormatterController.cs|43",
    "DNL-INJ-001|TaintCs/Chain.cs|55",
    "DNL-INJ-001|TaintCs/CycleSrc.cs|10",
    "DNL-INJ-001|TaintCs/Dup1.cs|9",
    "DNL-INJ-001|TaintCs/Ext.cs|14",
    "DNL-INJ-001|TaintCs/Ext.cs|19",
    "DNL-INJ-001|TaintCs/Ext.cs|24",
    "DNL-INJ-001|TaintCs/Ext.cs|35",
    "DNL-INJ-001|TaintCs/Flow.cs|12",
    "DNL-INJ-001|TaintCs/Flow.cs|20",
    "DNL-INJ-001|TaintCs/Flow.cs|27",
    "DNL-INJ-001|TaintCs/Flow.cs|34",
    "DNL-INJ-001|TaintCs/Flow.cs|39",
    "DNL-INJ-001|TaintCs/Gaps.cs|23",
    "DNL-INJ-001|TaintCs/Gaps.cs|25",
    "DNL-INJ-001|TaintCs/Gaps.cs|30",
    "DNL-INJ-001|TaintCs/Gaps.cs|42",
    "DNL-INJ-001|TaintCs/Gaps.cs|143",
    "DNL-INJ-001|TaintCs/Gaps.cs|150",
    "DNL-INJ-001|TaintCs/Lonely.cs|10",
    "DNL-INJ-001|TaintCs/Misc.cs|10",
    "DNL-INJ-001|TaintCs/Misc/OutboundExtras.cs|50",
    "DNL-INJ-001|TaintCs/OrderRepository.cs|10",
    "DNL-INJ-001|TaintCs/Orders.cs|11",
    "DNL-INJ-001|TaintCs/Out.cs|14",
    "DNL-INJ-001|TaintCs/Props.cs|12",
    "DNL-INJ-001|TaintCs/Props.cs|20",
    "DNL-INJ-001|TaintCs/Props.cs|26",
    "DNL-INJ-001|TaintCs/Props.cs|34",
    "DNL-INJ-001|TaintCs/Rec.cs|14",
    "DNL-INJ-001|TaintCs/SelfRec.cs|10",
    "DNL-INJ-001|TaintCs/SetSink.cs|10",
    "DNL-INJ-001|TaintCs/Shared.cs|9",
    "DNL-INJ-001|TaintCs/SqlImplA.cs|9",
    "DNL-INJ-001|TaintCs/SqlImplB.cs|9",
    "DNL-INJ-001|TaintCs/Tables.cs|27",
    "DNL-INJ-001|TaintCs/Tables.cs|33",
    "DNL-INJ-001|TaintCs/Tables.cs|39",
    "DNL-INJ-001|TaintCs/Tables.cs|45",
    "DNL-INJ-001|TaintCs/Tables.cs|51",
    "DNL-INJ-001|TaintCs/Tables.cs|57",
    "DNL-INJ-001|TaintCs/UsesAccum.cs|11",
    "DNL-INJ-001|TaintCs/UsesExt.cs|17",
    "DNL-INJ-001|TaintCs/UsesExt.cs|43",
    "DNL-INJ-001|TaintCs/UsesExt.cs|57",
    "DNL-INJ-001|TaintCs/UsesSetters.cs|28",
    "DNL-INJ-001|TaintCs/UsesSetters.cs|41",
    "DNL-INJ-001|TaintCs/Variadic.cs|9",
    "DNL-INJ-002|TaintCs/CodeSinksController.cs|25",
    "DNL-INJ-003|TaintCs/CodeSinksController.cs|39",
    "DNL-INJ-003|TaintCs/Tables.cs|84",
    "DNL-INJ-004|TaintCs/CodeSinksController.cs|58",
    "DNL-INJ-005|TaintCs/CodeSinksController.cs|67",
    "DNL-INJ-005|TaintCs/Crlf.cs|7",
    "DNL-INJ-005|TaintCs/Crlf.cs|18",
    "DNL-INJ-005|TaintCs/Crlf.cs|23",
    "DNL-INJ-006|TaintCs/Gaps.cs|83",
    "DNL-INJ-006|TaintCs/Gaps.cs|95",
    "DNL-INJ-006|TaintCs/Linq.cs|9",
    "DNL-INJ-006|TaintCs/Linq.cs|15",
    "DNL-LOG-001|TaintCs/CodeSinksController.cs|114",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|15",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|21",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|28",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|34",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|40",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|53",
    "DNL-LOG-001|TaintCs/Misc/LogLeakExtras.cs|59",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|22",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|28",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|34",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|41",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|47",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|53",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|60",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|78",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|115",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|162",
    "DNL-LOG-001|TaintCs/Misc/LoggingCases.cs|209",
    "DNL-LOG-001|TaintCs/Misc/LoginShapes.cs|37",
    "DNL-LOG-001|TaintCs/Tables.cs|63",
    "DNL-LOG-001|TaintCs/Tables.cs|74",
    "DNL-PATH-001|TaintCs/CodeSinksController.cs|81",
    "DNL-REDIR-001|TaintCs/CodeSinksController.cs|88",
    "DNL-REDIR-001|TaintCs/Guards.cs|14",
    "DNL-REDIR-001|TaintCs/Guards.cs|25",
    "DNL-REDIR-001|TaintCs/Nav.cs|17",
    "DNL-SSRF-001|TaintCs/ApiSsrfController.cs|12",
    "DNL-SSRF-001|TaintCs/CodeSinksController.cs|102",
    "DNL-SSRF-001|TaintCs/Misc/OutboundCalls.cs|60",
    "DNL-SSRF-001|TaintCs/Misc/OutboundCalls.cs|65",
    "DNL-SSRF-001|TaintCs/Misc/OutboundCalls.cs|95",
    "DNL-XSS-001|TaintCs/CodeSinksController.cs|74",
    "DNL-XSS-001|TaintCs/Misc/LoggingCases.cs|87",
    "DNL-XSS-001|TaintCs/Tables.cs|14",
    "DNL-XSS-001|TaintCs/Tables.cs|16",
    "DNL-XSS-001|TaintCs/Tables.cs|18",
    "DNL-XSS-001|TaintCs/Tables.cs|20",
    "DNL-XXE-001|Legacy40/Parse.cs|11",
    "DNL-XXE-001|Legacy40/Parse.cs|31",
    "DNL-XXE-001|Legacy40/Parse.cs|41",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|98",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|127",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|163",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|180",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|193",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|220",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|236",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|242",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|254",
    "DNL-XXE-001|TaintCs/DeserXml/Escapes.cs|260",
    "DNL-XXE-001|TaintCs/DeserXml/Round4.cs|37",
    "DNL-XXE-001|TaintCs/DeserXml/Round4.cs|83",
    "DNL-XXE-001|TaintCs/DeserXml/Round4.cs|90",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|16",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|44",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|52",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|96",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|124",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|132",
    "DNL-XXE-001|TaintCs/DeserXml/XmlController.cs|155",
}


def _legacy_run(name, allow_degraded):
    from checks.dnl import routes
    fx = Path(__file__).parent / "fixtures" / "dotnet_legacy"
    project._CACHE.clear()
    model = project.prepare(fx / name, allow_degraded)
    refs = routes.discover_mvc_webapi(model) + routes.discover_webforms(model)
    return {f"{f.check_id}|{f.file.replace(chr(92), '/')}|{f.line}" for f in rules_taint.check(model, refs)}


def test_legacy_findings_unchanged_with_helper(roslyn_helper):
    assert _legacy_run("taint_app", False) == _LEGACY_KEYS
    for name in ("mvc5_app", "webapi_global"):
        assert _legacy_run(name, False) == set(), name
    project._CACHE.clear()


def test_legacy_findings_unchanged_degraded(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    assert _legacy_run("taint_app", True) == _LEGACY_KEYS_DEGRADED
    for name in ("mvc5_app", "webapi_global"):
        assert _legacy_run(name, True) == set(), name
    project._CACHE.clear()
