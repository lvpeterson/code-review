"""Razor Core views and Razor Pages in the template XSS rules (DNL-XSS-003) on the synthetic taint_app
fixture, with the Roslyn helper and without it, plus the dotnet analyzer wiring."""
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project, routes_core, rules_xss, templates

ROOT = Path(__file__).parent / "fixtures" / "aspnetcore" / "taint_app"


def _prepare(allow_degraded=False):
    project._CACHE.clear()
    project.prepare(ROOT, allow_degraded)
    model = project.get_model(ROOT, "dotnet")
    return model, routes_core.discover_all(model)


@pytest.fixture(scope="module")
def app(roslyn_helper):
    model, refs = _prepare()
    yield model, refs, rules_xss.check(model, refs)
    project._CACHE.clear()


@pytest.fixture
def degraded_app(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    model, refs = _prepare(True)
    yield model, refs, rules_xss.check(model, refs)
    project._CACHE.clear()


def _line(rel, text):
    for i, s in enumerate((ROOT / rel).read_text().splitlines(), 1):
        if text in s:
            return i
    raise AssertionError(f"{text!r} not in {rel}")


def _xss(findings, rel, line=None):
    return [f for f in findings if f.check_id == "DNL-XSS-003" and f.file == rel
            and (line is None or f.line == line)]


def _proven(findings, rel, line, handler):
    got = _xss(findings, rel, line)
    assert len(got) == 1, (rel, line, got)
    f = got[0]
    assert (f.severity, f.confidence) == ("high", None), f
    assert f.route is not None and f.route.handler_name == handler, f.route
    return f


def _check(findings):
    _proven(findings, "Views/Home/Index.cshtml", 1, "HomeController.Index")
    _proven(findings, "Views/Home/Profile.cshtml", _line("Views/Home/Profile.cshtml", "Html.Raw(Model.Bio)"),
            "HomeController.Profile")
    # `@Model.Bio` is encoded by the framework, so it is not an output the rule looks at.
    assert not _xss(findings, "Views/Home/Profile.cshtml", _line("Views/Home/Profile.cshtml", "<div>@Model.Bio"))
    lay = _xss(findings, "Views/Shared/_Layout.cshtml")
    assert len(lay) == 1 and (lay[0].severity, lay[0].confidence) == ("high", None)
    c = "Pages/Comment.cshtml"
    f = _proven(findings, c, _line(c, "Html.Raw(Model.Text)"), "CommentModel.OnPost")
    assert f.route.meta["kind"] == "razorpage"
    _proven(findings, c, _line(c, "HtmlString(Model.Q)"), "CommentModel.OnGet")
    fixed = _xss(findings, "Pages/Fixed.cshtml")
    assert all((f.severity, f.confidence) in (("low", "REVIEW"),) for f in fixed)
    assert not _xss(findings, "Pages/Encoded.cshtml")
    assert not [f for f in findings if f.check_id == "DNL-XSS-004"]


def test_viewbag_proof(app):
    _proven(app[2], "Views/Home/Index.cshtml", 1, "HomeController.Index")


def test_view_model_proof(app):
    p = "Views/Home/Profile.cshtml"
    f = _proven(app[2], p, _line(p, "Html.Raw(Model.Bio)"), "HomeController.Profile")
    assert "view model" in f.description
    assert not _xss(app[2], p, _line(p, "<div>@Model.Bio"))
    # Static() renders the same view with a constant model, it must not be the proof route.
    assert f.route.handler_name != "HomeController.Static"


def test_layout_request_read(app):
    lay = _xss(app[2], "Views/Shared/_Layout.cshtml")
    assert len(lay) == 1 and (lay[0].severity, lay[0].confidence) == ("high", None)


def test_page_bind_property_proof(app):
    c = "Pages/Comment.cshtml"
    _proven(app[2], c, _line(c, "Html.Raw(Model.Text)"), "CommentModel.OnPost")
    _proven(app[2], c, _line(c, "HtmlString(Model.Q)"), "CommentModel.OnGet")


def test_page_constant_is_review_at_most(app):
    got = _xss(app[2], "Pages/Fixed.cshtml")
    assert all((f.severity, f.confidence) == ("low", "REVIEW") for f in got)


def test_encoder_is_recognised(app):
    assert not _xss(app[2], "Pages/Encoded.cshtml")
    from checks.dnl.templates import is_encoded_wrapper
    assert is_encoded_wrapper("HtmlEncoder.Default.Encode(Model.Text)")
    assert is_encoded_wrapper("System.Text.Encodings.Web.JavaScriptEncoder.Default.Encode(x)")
    assert not is_encoded_wrapper("HtmlEncoder.Default.Encode(a) + b")


def test_xss004_never_fires_on_core(app):
    assert not [f for f in app[2] if f.check_id == "DNL-XSS-004"]


def test_razor_core_helpers(tmp_path):
    p = tmp_path / "a.cshtml"
    p.write_text('@(new Microsoft.AspNetCore.Html.HtmlString(Model.Q))\n'
                 '@(new HtmlString(Model.R))\n')
    out = templates.scan(p, "a.cshtml")
    assert [o.kind for o in out] == ["razor_helper", "razor_helper"]
    for e in ("Html.PartialAsync(\"_Nav\")", "Html.RenderPartialAsync(\"_Nav\")", "Component.InvokeAsync(\"Cart\")",
              "Url.Page(\"/Index\")", "Url.RouteUrl(\"default\")"):
        assert templates.is_benign_helper(e), e
    assert not templates.is_benign_helper("Html.PartialAsync(Model.Name)")


def test_page_file_on_ref(app):
    refs = [r for r in app[1] if r.route.meta.get("kind") == "razorpage" and r.type is not None]
    files = {r.route.meta["page"]: r.route.meta["page_file"] for r in refs}
    assert files["/Comment"] == "Pages/Comment.cshtml"
    assert files["/Fixed"] == "Pages/Fixed.cshtml"
    assert templates.views_for(app[0], next(r for r in refs if r.route.meta["page"] == "/Fixed"))[0].name == "Fixed.cshtml"


def test_view_candidates_for_controller(app):
    model, refs = app[0], app[1]
    r = next(r for r in refs if r.route.handler_name == "HomeController.Static")
    got = {p.name for p in templates.views_for(model, r)}
    assert got == {"Profile.cshtml"}


def test_core_findings_through_analyzer(roslyn_helper):
    project._CACHE.clear()
    res = [r for r in enumerator.enumerate_target(ROOT) if r.language == "dotnet"]
    fs = [f for r in res for f in r.findings if f.check_id == "DNL-XSS-003"]
    proven = {(f.file, f.route.meta["kind"]) for f in fs if f.confidence is None and f.route}
    assert ("Views/Home/Index.cshtml", "controller") in proven
    assert ("Pages/Comment.cshtml", "razorpage") in proven
    assert not [f for r in res for f in r.findings if f.check_id == "DNL-XSS-004"]
    project._CACHE.clear()


def test_degraded_xss(degraded_app):
    _check(degraded_app[2])


def test_degraded_analyzer(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    project._CACHE.clear()
    res = [r for r in enumerator.enumerate_target(ROOT, allow_degraded=True) if r.language == "dotnet"]
    proven = {(f.file, f.route.meta["kind"]) for r in res for f in r.findings
              if f.check_id == "DNL-XSS-003" and f.confidence is None and f.route}
    assert ("Views/Home/Index.cshtml", "controller") in proven
    assert ("Pages/Comment.cshtml", "razorpage") in proven
    project._CACHE.clear()
