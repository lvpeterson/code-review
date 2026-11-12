"""WebForms (.aspx/.asmx) route discovery and auth for VB code-behind."""
from pathlib import Path

import pytest

from checks.dnl import auth, project, rules_auth
from checks.dnl.routes import discover_webforms
from checks.dnl.webconfig import load_configs

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def wf(roslyn_helper):
    project._CACHE.clear()
    model = project.prepare(FX / "webforms_vb", False)
    refs = discover_webforms(model)
    configs = load_configs(model.root)
    infos = {r.route.path: auth.resolve_webforms(model, r, configs) for r in refs}
    findings = rules_auth.check_routes(model, refs, auth.global_filters(model), auth.chain_for_model(model))
    return model, refs, infos, findings


@pytest.fixture
def wf_refs(wf):
    return wf[1]


@pytest.fixture
def wf_auth(wf):
    return wf[2]


@pytest.fixture
def wf_findings(wf):
    return wf[3]


def test_pages_found_controls_skipped(wf_refs):
    assert {r.route.path for r in wf_refs} == {"/Default.aspx", "/Secure/Edit.aspx", "/Members/List.aspx"}


def test_case_mismatched_codebehind_linked(wf_refs):
    r = next(r for r in wf_refs if r.route.path == "/Secure/Edit.aspx")
    assert r.type is not None and r.route.meta["codebehind"].lower() == "secure/edit.aspx.vb"
    assert r.route.handler_name == "EditPage"


def test_inherits_matches_case_insensitively_and_route_shape(wf_refs):
    r = next(r for r in wf_refs if r.route.path == "/Members/List.aspx")
    assert r.type.name == "ListPage" and r.route.handler_name == "ListPage"
    assert r.route.methods == ["GET", "POST"] and r.route.line == 1
    assert r.route.file.endswith("Members/List.aspx")
    assert r.route.source_start_line == r.type.line
    assert r.route.meta["kind"] == "webforms" and r.route.meta["api_surface"] is False
    assert r.route.meta["codebehind"] == "Members/List.aspx.vb"


def test_webforms_auth_sources(wf_auth):
    assert wf_auth["/Secure/Edit.aspx"].source == "web.config"
    m = wf_auth["/Members/List.aspx"]
    assert m.source == "code-behind check" and m.review and m.detail == "ListPage.Page_Load"
    assert not wf_auth["/Default.aspx"].protected and wf_auth["/Default.aspx"].source == "none"


def test_public_page_flagged(wf_findings):
    got = [f for f in wf_findings if f.check_id == "DNL-AUTHZ-001" and f.route.path == "/Default.aspx"]
    assert len(got) == 1 and got[0].severity == "medium"
    got = [f for f in wf_findings if f.check_id == "DNL-AUTHZ-001" and f.route.path == "/Members/List.aspx"]
    assert len(got) == 1 and got[0].severity == "low" and got[0].confidence == "REVIEW"
    assert "ListPage.Page_Load" in got[0].description
    assert not [f for f in wf_findings if f.route is not None and f.route.path == "/Secure/Edit.aspx"]


def test_asmx_and_multiline_directive(tmp_path, roslyn_helper):
    app = tmp_path / "A"
    app.mkdir()
    (app / "A.vbproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Compile Include="Svc.asmx.vb" /></ItemGroup></Project>')
    (app / "Svc.asmx").write_text('<%@ WebService Language="VB"\n  Class="Svc" CodeBehind="Svc.asmx.vb" %>\n')
    (app / "Svc.asmx.vb").write_text("Public Class Svc\n    Inherits System.Web.Services.WebService\nEnd Class\n")
    project._CACHE.clear()
    model = project.prepare(app, False)
    (ref,) = discover_webforms(model)
    assert ref.route.path == "/Svc.asmx" and ref.route.meta["api_surface"] is True
    assert ref.type is not None and ref.type.name == "Svc"


def test_page_without_codebehind(tmp_path, roslyn_helper):
    app = tmp_path / "B"
    app.mkdir()
    (app / "B.vbproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"/>')
    (app / "Plain.aspx").write_text('<%@ Page Language="VB" %>\n')
    project._CACHE.clear()
    model = project.prepare(app, False)
    (ref,) = discover_webforms(model)
    assert ref.type is None and ref.route.handler_name == "Plain.aspx" and ref.route.meta["codebehind"] == ""
    info = auth.resolve_webforms(model, ref, load_configs(model.root))
    assert not info.protected


def test_inherits_with_vb_root_namespace_prefix(tmp_path, roslyn_helper):
    # VB prepends <RootNamespace> implicitly: `Public Class Orders` compiles to
    # WebApp.Orders, which is what the designer writes into Inherits.
    app = tmp_path / "C"
    app.mkdir()
    (app / "C.vbproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<PropertyGroup><RootNamespace>WebApp</RootNamespace></PropertyGroup>'
        '<ItemGroup><Compile Include="Code\\OrdersPage.vb" /></ItemGroup></Project>')
    (app / "Code").mkdir()
    (app / "Code" / "OrdersPage.vb").write_text(
        "Public Class Orders\n    Inherits System.Web.UI.Page\n"
        "    Protected Sub Page_Load(sender As Object, e As EventArgs)\n    End Sub\nEnd Class\n")
    (app / "Orders.aspx").write_text('<%@ Page Language="VB" Inherits="WebApp.Orders" %>\n')
    project._CACHE.clear()
    model = project.prepare(app, False)
    assert next(p for p in model.projects if p.name == "C").root_namespace == "WebApp"
    (ref,) = discover_webforms(model)
    assert ref.type is not None and ref.type.name == "Orders"
    assert ref.route.handler_name == "Orders" and ref.route.meta["codebehind"] == "Code/OrdersPage.vb"


def test_conditional_login_redirect_is_review_check(tmp_path, roslyn_helper):
    # Classic session gate: a branch that sends the user to a login page.
    app = tmp_path / "D"
    app.mkdir()
    (app / "D.vbproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Compile Include="Gate.aspx.vb" /><Compile Include="Sel.aspx.vb" />'
        '<Compile Include="Bye.aspx.vb" /></ItemGroup></Project>')
    pages = {
        "Gate": "        If Session(\"UserId\") Is Nothing Then\n            Response.Redirect(\"~/Login.aspx\")\n        End If\n",
        "Sel": "        Select Case Session(\"State\")\n            Case 1\n"
               "                Response.Redirect(\"Login.aspx?ReturnUrl=\" & Request.RawUrl)\n        End Select\n",
        # Unconditional redirect (a logout page) is not a gate.
        "Bye": "        Session.Abandon()\n        Response.Redirect(\"Login.aspx\")\n",
    }
    for name, body in pages.items():
        (app / f"{name}.aspx").write_text(f'<%@ Page Language="VB" Inherits="{name}" CodeBehind="{name}.aspx.vb" %>\n')
        (app / f"{name}.aspx.vb").write_text(
            f"Public Class {name}\n    Inherits System.Web.UI.Page\n"
            "    Private Sub Page_Load(sender As Object, e As EventArgs) Handles Me.Load\n"
            f"{body}    End Sub\nEnd Class\n")
    project._CACHE.clear()
    model = project.prepare(app, False)
    configs = load_configs(model.root)
    infos = {r.route.path: auth.resolve_webforms(model, r, configs) for r in discover_webforms(model)}
    for p in ("/Gate.aspx", "/Sel.aspx"):
        assert infos[p].protected and infos[p].review and infos[p].source == "code-behind check", p
        assert "login redirect" in infos[p].detail
    assert not infos["/Bye.aspx"].protected


def test_login_redirect_in_helper_called_from_base_page_load(tmp_path, roslyn_helper):
    # Base page's Page_Load delegates to a private ValidateSession(); one call level is followed.
    app = tmp_path / "E"
    app.mkdir()
    (app / "E.vbproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Compile Include="BasePage.vb" /><Compile Include="Upload.aspx.vb" /></ItemGroup></Project>')
    (app / "BasePage.vb").write_text(
        "Public MustInherit Class BasePage\n    Inherits System.Web.UI.Page\n"
        "    Private Sub Page_Load(sender As Object, e As EventArgs) Handles MyBase.Load\n"
        "        ValidateSession()\n    End Sub\n"
        "    Private Sub ValidateSession()\n"
        "        If Session(\"UserId\") Is Nothing Then\n            Response.Redirect(\"Login.aspx\")\n        End If\n"
        "    End Sub\nEnd Class\n")
    (app / "Upload.aspx").write_text('<%@ Page Language="VB" Inherits="Upload" CodeBehind="Upload.aspx.vb" %>\n')
    (app / "Upload.aspx.vb").write_text("Partial Class Upload\n    Inherits BasePage\nEnd Class\n")
    project._CACHE.clear()
    model = project.prepare(app, False)
    (ref,) = discover_webforms(model)
    info = auth.resolve_webforms(model, ref, load_configs(model.root))
    assert info.protected and info.review and info.detail == "a conditional login redirect in BasePage.ValidateSession"


def _page_infos(tmp_path, bodies):
    app = tmp_path / "H"
    app.mkdir()
    compiles = "".join(f'<Compile Include="{n}.aspx.vb" />' for n in bodies)
    (app / "H.vbproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        f'<ItemGroup>{compiles}</ItemGroup></Project>')
    for name, body in bodies.items():
        (app / f"{name}.aspx").write_text(f'<%@ Page Language="VB" Inherits="{name}" CodeBehind="{name}.aspx.vb" %>\n')
        (app / f"{name}.aspx.vb").write_text(
            f"Public Class {name}\n    Inherits System.Web.UI.Page\n"
            "    Private Sub Page_Load(sender As Object, e As EventArgs) Handles Me.Load\n"
            f"{body}    End Sub\nEnd Class\n")
    project._CACHE.clear()
    model = project.prepare(app, False)
    configs = load_configs(model.root)
    return {r.route.path: auth.resolve_webforms(model, r, configs) for r in discover_webforms(model)}


def test_false_protected_heuristics_rejected(tmp_path, roslyn_helper):
    infos = _page_infos(tmp_path, {
        # Redirect to a "login"-named page on an unrelated condition.
        "Help": "        If Request.QueryString(\"help\") = \"1\" Then\n            Response.Redirect(\"LoginHelp.aspx\")\n        End If\n",
        # IsInRole only toggles a button; nothing is rejected.
        "Toggle": "        If User.IsInRole(\"Admin\") Then\n            btnDelete.Visible = True\n        End If\n",
        # RedirectToLoginPage outside any condition is not a gate.
        "Bare": "        FormsAuthentication.RedirectToLoginPage()\n",
    })
    for p in ("/Help.aspx", "/Toggle.aspx", "/Bare.aspx"):
        assert not infos[p].protected, p


def test_real_gates_stay_protected(tmp_path, roslyn_helper):
    infos = _page_infos(tmp_path, {
        "Role": "        If Not User.IsInRole(\"Admin\") Then\n            Response.Redirect(\"~/Denied.aspx\")\n        End If\n",
        "Auth": "        If Not Request.IsAuthenticated Then\n            FormsAuthentication.RedirectToLoginPage()\n        End If\n",
        "Ident": "        If HttpContext.Current.User.Identity Is Nothing Then\n            Response.Redirect(\"Login.aspx\")\n        End If\n",
    })
    for p in ("/Role.aspx", "/Auth.aspx", "/Ident.aspx"):
        assert infos[p].protected and infos[p].review, p


def test_project_less_web_site_routes_pages(tmp_path, roslyn_helper):
    # A WebForms Web Site has no .csproj/.vbproj: pages still get routes, relative to the
    # nearest web.config dir, with CodeFile / Inherits resolving the code-behind.
    site = tmp_path / "Site"
    (site / "Admin").mkdir(parents=True)
    (site / "Web.config").write_text(
        '<configuration><location path="Admin"><system.web><authorization><deny users="?"/>'
        '</authorization></system.web></location></configuration>')
    (site / "Default.aspx").write_text('<%@ Page Language="VB" CodeFile="Default.aspx.vb" Inherits="_Default" %>\n')
    (site / "Default.aspx.vb").write_text(
        "Partial Class _Default\n    Inherits System.Web.UI.Page\n"
        "    Protected Sub Page_Load(sender As Object, e As EventArgs) Handles Me.Load\n"
        "    End Sub\nEnd Class\n")
    (site / "Admin" / "Secret.aspx").write_text('<%@ Page Language="VB" %>\n')
    (site / "Svc.asmx").write_text('<%@ WebService Language="VB" Class="Svc" %>\n')
    project._CACHE.clear()
    model = project.prepare(site, False)
    refs = {r.route.path: r for r in discover_webforms(model)}
    assert set(refs) == {"/Default.aspx", "/Admin/Secret.aspx", "/Svc.asmx"}
    assert refs["/Default.aspx"].type is not None and refs["/Default.aspx"].route.handler_name == "_Default"
    assert refs["/Svc.asmx"].route.meta["api_surface"] is True
    configs = load_configs(model.root)
    assert auth.resolve_webforms(model, refs["/Admin/Secret.aspx"], configs).source == "web.config"
    assert not auth.resolve_webforms(model, refs["/Default.aspx"], configs).protected
