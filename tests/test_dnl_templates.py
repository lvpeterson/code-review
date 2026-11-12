"""Razor / ASPX output scanning and the XSS-003 / XSS-004 findings."""
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_xss
from checks.dnl.templates import scan

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


def test_razor_scan_finds_raw_not_encoded(tmp_path):
    p = tmp_path / "v.cshtml"
    p.write_text('<p>@Model.Name</p>\n@Html.Raw(Model.Bio)\n@Html.Raw(fn("a)b"))\n')
    assert [(o.line, o.kind, o.expr) for o in scan(p, "v.cshtml")] == [
        (2, "razor_raw", "Model.Bio"), (3, "razor_raw", 'fn("a)b")')]


def test_razor_scan_blocks_helpers_and_comments(tmp_path):
    p = tmp_path / "v.cshtml"
    p.write_text('@* @Html.Raw(skipped) *@\n@{\n  var x = Html.Raw(Request["q"]);\n}\n'
                 '@(new HtmlString(Model.A))\n@MvcHtmlString.Create(Model.B)\nmail a@b.com @@Html.Raw(x)\n')
    got = [(o.line, o.kind, o.expr) for o in scan(p, "v.cshtml")]
    assert got == [(3, "razor_raw", 'Request["q"]'), (5, "razor_helper", "Model.A"),
                   (6, "razor_helper", "Model.B")]


def test_aspx_scan(tmp_path):
    p = tmp_path / "s.aspx"
    p.write_text('<%= Request["q"] %>\n<%: Request["q"] %>\n<%# Eval("Name") %>\n'
                 '<%# Server.HtmlEncode(Eval("N")) %>\n<%-- <%= x %> --%>\n<%@ Page Language="C#" %>\n')
    assert [(o.line, o.kind, o.encoded) for o in scan(p, "s.aspx")] == [
        (1, "aspx_raw", False), (2, "aspx_encoded", True), (3, "aspx_bind", False), (4, "aspx_bind", True)]


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


@pytest.fixture(scope="module")
def findings(model):
    refs = routes.discover_mvc_webapi(model) + routes.discover_webforms(model)
    return rules_xss.check(model, refs)


def line_text(model, f):
    return (model.root / f.file).read_text().splitlines()[f.line - 1]


def hits(findings, rule, file_endswith=None, line_has=None, model=None):
    out = [f for f in findings if f.check_id == rule]
    if file_endswith:
        out = [f for f in out if f.file.endswith(file_endswith)]
    if line_has:
        out = [f for f in out if line_has in line_text(model, f)]
    return out


def one(findings, rule, model=None, **kw):
    found = hits(findings, rule, model=model, **kw)
    assert len(found) == 1, [(f.file, f.line, f.description) for f in found]
    return found[0]


def test_viewbag_link_is_proven(findings, model):
    f = one(findings, "DNL-XSS-003", model=model, file_endswith="Show.cshtml", line_has="ViewBag.Msg")
    assert f.severity == "high" and f.confidence is None and f.route.handler_name == "HomeController.Show"


def test_model_link_is_proven(findings, model):
    f = one(findings, "DNL-XSS-003", model=model, file_endswith="Show.cshtml", line_has="Model.Bio")
    assert f.severity == "high" and f.confidence is None


def test_request_in_razor_block_is_proven(findings, model):
    f = one(findings, "DNL-XSS-003", model=model, file_endswith="Show.cshtml", line_has="Request.QueryString")
    assert f.severity == "high" and f.confidence is None


def test_literal_raw_ignored(findings, model):
    assert not hits(findings, "DNL-XSS-003", model=model, file_endswith="Show.cshtml", line_has='"<b>x</b>"')


def test_aspx_request_raw_high_encoded_none(findings):
    fs = hits(findings, "DNL-XSS-003", file_endswith="Show.aspx")
    assert [(f.line, f.severity) for f in fs if f.confidence is None] == [(1, "high")]
    assert not [f for f in fs if f.line in (2, 4)]
    bind = [f for f in fs if f.line == 3]
    assert len(bind) == 1 and bind[0].severity == "low" and bind[0].confidence == "REVIEW"
    assert next(f for f in fs if f.line == 1).route.handler_name == "ShowPage"


def test_unknown_provenance_is_review(tmp_path, roslyn_helper):
    (tmp_path / "App.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>'
        '<Reference Include="System.Web.Mvc" /></ItemGroup></Project>')
    (tmp_path / "Views" / "Shared").mkdir(parents=True)
    (tmp_path / "Views" / "Shared" / "_P.cshtml").write_text("@Html.Raw(Model.Html)\n")
    project._CACHE.clear()
    m = project.prepare(tmp_path, False)
    fs = rules_xss.check(m, [])
    assert [(f.severity, f.confidence, f.route) for f in fs] == [("low", "REVIEW", None)]


def test_xss_004_variants(findings):
    fs = hits(findings, "DNL-XSS-004")
    kinds = sorted(f.title.split("Request validation bypassed: ", 1)[1] for f in fs)
    assert kinds == ["AllowHtml", "Request.Unvalidated", "ValidateInput(false)"]
    assert all(f.severity == "medium" for f in fs)


# -- fix round 1 ----------------------------------------------------------

def _mvc_proj(tmp_path, files):
    (tmp_path / "App.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>'
        '<Reference Include="System.Web.Mvc" /></ItemGroup></Project>')
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    project._CACHE.clear()
    return project.prepare(tmp_path, False)


@pytest.mark.parametrize("expr", [
    'Request.QueryString["q"]', 'Page.Request.QueryString["q"]', 'Context.Request["q"]', 'this.Request["q"]',
    'Me.Request("q")', 'HttpContext.Current.Request.Form["q"]', 'ViewContext.HttpContext.Request["q"]'])
def test_qualified_request_forms_are_proven(tmp_path, roslyn_helper, expr):
    m = _mvc_proj(tmp_path, {"Views/Shared/a.cshtml": f"@Html.Raw({expr})\n", "p.aspx": f"<%= {expr} %>\n"})
    fs = rules_xss.check(m, [])
    assert sorted((f.file, f.severity, f.confidence) for f in fs) == [
        ("Views/Shared/a.cshtml", "high", None), ("p.aspx", "high", None)]


def test_aspx_response_write_block(tmp_path):
    p = tmp_path / "s.aspx"
    p.write_text('<% Response.Write(Request["q"]); %>\n<% foreach (var x in y) { %>\n<% Response.Write("a)" + x) %>\n')
    assert [(o.line, o.kind, o.expr) for o in scan(p, "s.aspx")] == [
        (1, "aspx_raw", 'Request["q"]'), (3, "aspx_raw", '"a)" + x')]


def test_encoder_whitelist(tmp_path):
    p = tmp_path / "v.cshtml"
    p.write_text("\n".join(f"@Html.Raw({e}(x))" for e in (
        "Html.Encode", "HttpUtility.HtmlEncode", "Server.HtmlEncode", "WebUtility.HtmlEncode",
        "AntiXssEncoder.HtmlAttributeEncode", "Encoder.HtmlEncode", "Sanitizer.GetSafeHtmlFragment", "Json.Encode",
        "Url.Encode", "HttpUtility.UrlEncode", "Foo.Encode")))
    assert [o.encoded for o in scan(p, "v.cshtml")] == [True] * 8 + [False] * 3


def test_unbalanced_expr_falls_back_to_rest_of_line(tmp_path):
    p = tmp_path / "v.cshtml"
    p.write_text('@Html.Raw(foo(x, "a")\n<p>next</p>\n')
    got = scan(p, "v.cshtml")
    assert len(got) == 1 and got[0].line == 1 and got[0].kind == "razor_raw" and got[0].expr.startswith("foo(x")


def test_view_model_only_for_mvc_view(tmp_path, roslyn_helper):
    m = _mvc_proj(tmp_path, {"C.cs": (
        "using System.Web.Mvc;\nnamespace N { public class C : Controller {\n"
        "  public ActionResult A(string s) { return View(s); }\n}\n"
        "public class D { public object View(string t) { return null; }\n"
        "  public object B(string s) { return View(s); } } }\n")})
    from checks.dnl import taint, taint_solver
    taint_solver.solve(m)
    state = m.cache["taint"]
    got = {}
    for t in m.types():
        for meth in t.methods:
            if meth.name in ("A", "B"):
                r = taint.analyze_method(m, t, meth, param_taint=taint_solver._entry_taint(m, t, meth),
                                         summaries=state["summaries"])
                got[meth.name] = r.view_model is not None
    assert got == {"A": True, "B": False}


# -- final review: helper allowlist and unknown-provenance severity ---------------

_BENIGN = ['Url.Content("~/Scripts/a.js")', 'Url.Action("Index", "Home")', 'ResolveUrl("~/a.css")',
           'Html.Partial("_Nav")', 'Html.AntiForgeryToken()', 'Scripts.Render("~/bundles/app")',
           'Styles.Render("~/Content/css")', 'Html.ActionLink("Home", "Index")', 'Html.RenderAction("Menu")']
_NOT_BENIGN = ['Url.Action("Index", Request["x"])', 'Url.Content(Model.Path)', 'Html.Partial("_Nav", Model)',
               'ResolveUrl(ViewBag.U)', 'Html.Action("A", new { id = 1 })', 'Url.Content("~/x") + Request["q"]',
               'ResolveClientUrl(Eval("U"))', 'Html.Partial(name)']


def test_benign_helper_predicate():
    from checks.dnl import templates
    assert all(templates.is_benign_helper(e) for e in _BENIGN)
    assert not any(templates.is_benign_helper(e) for e in _NOT_BENIGN)


def test_benign_helper_outputs_are_not_reported(tmp_path, roslyn_helper):
    files = {"Views/Shared/a.cshtml": "\n".join(f"@Html.Raw({e})" for e in _BENIGN) + "\n",
             "p.aspx": "\n".join(f"<%= {e} %>" for e in _BENIGN) + "\n"}
    m = _mvc_proj(tmp_path, files)
    assert rules_xss.check(m, []) == []


def test_non_benign_helper_outputs_stay_reported(tmp_path, roslyn_helper):
    m = _mvc_proj(tmp_path, {"Views/Shared/a.cshtml": "\n".join(f"@Html.Raw({e})" for e in _NOT_BENIGN) + "\n"})
    fs = rules_xss.check(m, [])
    assert len(fs) == len(_NOT_BENIGN)
    assert all(f.check_id == "DNL-XSS-003" for f in fs)


def test_unknown_provenance_is_low_proven_unchanged(tmp_path, roslyn_helper):
    m = _mvc_proj(tmp_path, {"Views/Shared/a.cshtml": "@Html.Raw(Model.Html)\n@Html.Raw(Request.QueryString[\"q\"])\n"})
    fs = {f.line: f for f in rules_xss.check(m, [])}
    assert (fs[1].severity, fs[1].confidence) == ("low", "REVIEW")
    assert (fs[2].severity, fs[2].confidence) == ("high", None)
