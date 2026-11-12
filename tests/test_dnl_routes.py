"""MVC 5 / Web API 2 route discovery over the real mvc5_app fixture."""
from pathlib import Path

import pytest

from checks.dnl import project
from checks.dnl.routes import discover_mvc_webapi

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def refs(roslyn_helper):
    project._CACHE.clear()
    return discover_mvc_webapi(project.prepare(FX / "mvc5_app", False))


def paths(refs):
    return {(r.route.handler_name, r.route.path, tuple(r.route.methods)) for r in refs}


def test_conventional_mvc(refs):
    assert ("HomeController.Index", "/Home/Index/{id}", ("GET", "POST")) in paths(refs)


def test_nonaction_and_override_excluded(refs):
    names = {r.route.handler_name for r in refs}
    assert "HomeController.Helper" not in names and "HomeController.Dispose" not in names


def test_webapi_conventional_and_verbs(refs):
    p = paths(refs)
    assert ("OrdersApiController.GetOrder", "/api/OrdersApi/{id}", ("GET",)) in p
    assert ("OrdersApiController.Remove", "/api/OrdersApi/{id}", ("DELETE",)) in p
    assert ("OrdersApiController.PostOrder", "/api/OrdersApi/{id}", ("POST",)) in p
    r = next(r for r in refs if r.route.handler_name == "OrdersApiController.PostOrder")
    assert r.route.meta == {"kind": "webapi", "api_surface": True, "controller": "MvcApp.Controllers.OrdersApiController"}


def test_attribute_routes(refs):
    p = {r.route.handler_name: r.route.path for r in refs}
    assert p["ReportsController.Year"] == "/reports/{year}" and p["ReportsController.Latest"] == "/r/latest"


def test_area_route(refs):
    assert ("UsersController.Index", "/Admin/Users/Index/{id}", ("GET", "POST")) in paths(refs)


def test_ref_carries_type_method_project_and_range(refs):
    r = next(r for r in refs if r.route.handler_name == "HomeController.Index")
    assert r.type.full_name == "MvcApp.Controllers.HomeController" and r.method.name == "Index"
    assert r.project.name == "MvcApp"
    assert r.route.file.endswith("HomeController.cs") and r.route.line == r.route.source_start_line
    assert r.route.source_end_line >= r.route.line and r.route.meta["kind"] == "mvc"
    assert not r.route.meta.get("api_surface")
    assert not any(x.route.handler_name.startswith("BaseController") for x in refs)


def test_acceptverbs_bitwise_or_stacked_routes_and_default_tokens(refs):
    multi = [r for r in refs if r.route.handler_name == "ReportsController.Multi"]
    assert sorted(r.route.path for r in multi) == ["/reports/multi/{id}", "/reports/multi2"]
    assert all(r.route.methods == ["GET", "POST"] for r in multi)


def _vb_model(roslyn_helper):
    full = project.prepare(FX / "mvc5_app", False)
    files = {k: v for k, v in full.files.items() if v.language == "vb"}
    assert files
    return project.ProjectModel(full.root, full.projects, files, None, [])


def test_vb_case_insensitive_and_default_public(roslyn_helper):
    got = {(r.route.handler_name, r.route.path, tuple(r.route.methods))
           for r in discover_mvc_webapi(_vb_model(roslyn_helper))}
    # lowercase `ordersController` suffix + `routes.maproute` call picked up, no-modifier VB Function is public
    assert ("ordersController.Index", "/vb/orders/Index", ("GET", "POST")) in got
    assert ("ordersController.Both", "/vb/orders/Both", ("GET", "POST")) in got
    assert not any(h == "ordersController.Secret" for h, _, _ in got)


def test_area_registration_never_defines_global_template():
    from checks.dnl import ir

    def call(recv):
        return {"k": "call", "fn": {"k": "member", "name": "MapRoute", "obj": {"k": "name", "id": recv}},
                "args": [{"k": "lit", "v": "n", "t": "string"},
                         {"k": "lit", "v": "Admin/{controller}/{action}/{id}", "t": "string"}], "named": {}}
    reg_m = ir.MethodIR("RegisterArea", ["public", "override"], body=[{"k": "expr", "expr": call("ctx")}])
    reg = ir.TypeIR("AdminAreaRegistration", "App.Areas.Admin", "class", ["public"], ["AreaRegistration"],
                    [], [], [], [reg_m], 1, 9, "a.cs")
    ctl = ir.TypeIR("HomeController", "App.Controllers", "class", ["public"], ["Controller"], [], [], [],
                    [ir.MethodIR("Index", ["public"], line=3, end_line=4)], 1, 9, "b.cs")
    files = {"a.cs": ir.FileIR("a.cs", "cs", "p", 0, [reg]), "b.cs": ir.FileIR("b.cs", "cs", "p", 0, [ctl])}
    refs = discover_mvc_webapi(project.ProjectModel(FX, [], files, None, []))
    assert [r.route.path for r in refs] == ["/Home/Index/{id}"]


def test_route_template_from_nameof(tmp_path, roslyn_helper):
    # `[Route(nameof(Ping))]` is a compile-time constant "Ping", common in newer Web API 2 code.
    app = tmp_path / "N"
    app.mkdir()
    (app / "N.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Reference Include="System.Web.Http" /><Compile Include="PingController.cs" /></ItemGroup></Project>')
    (app / "PingController.cs").write_text(
        "using System.Web.Http;\n"
        "[RoutePrefix(\"PingApi\")]\n"
        "public class PingController : ApiController {\n"
        "    [HttpPost, Route(nameof(Ping))] public IHttpActionResult Ping() { return Ok(); }\n"
        "    [HttpGet, Route(nameof(PingController.Echo) + \"/{id}\")] public IHttpActionResult Echo(int id) { return Ok(); }\n"
        "}\n")
    project._CACHE.clear()
    got = {(r.route.handler_name, r.route.path) for r in discover_mvc_webapi(project.prepare(app, False))}
    assert got == {("PingController.Ping", "/PingApi/Ping"), ("PingController.Echo", "/PingApi/Echo/{id}")}


def _generic_base_app(tmp_path):
    app = tmp_path / "G"
    app.mkdir()
    (app / "G.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Reference Include="System.Web.Http" /><Compile Include="Crud.cs" />'
        '<Compile Include="OrdersController.cs" /></ItemGroup></Project>')
    (app / "Crud.cs").write_text(
        "using System.Web.Http;\n"
        "public abstract class CrudApiController<T> : ApiController {\n"
        "    public void Delete(int id) { }\n"
        "    public T GetItem(int id) { return default(T); }\n"
        "    public virtual void PostItem(T item) { }\n"
        "    public static void Util() { }\n"
        "    [NonAction] public void Hidden() { }\n"
        "    protected void Internal() { }\n"
        "}\n")
    (app / "OrdersController.cs").write_text(
        "using System.Web.Http;\n"
        "public class Order { }\n"
        "public class OrdersController : CrudApiController<Order> {\n"
        "    public override void PostItem(Order item) { }\n"
        "    public void Own() { }\n"
        "}\n")
    return app


def test_inherited_public_actions_from_generic_abstract_base(tmp_path, roslyn_helper):
    project._CACHE.clear()
    refs = discover_mvc_webapi(project.prepare(_generic_base_app(tmp_path), False))
    got = {(r.route.handler_name, r.route.path, tuple(r.route.methods)) for r in refs}
    assert ("OrdersController.Delete", "/api/Orders/{id}", ("DELETE",)) in got
    assert ("OrdersController.GetItem", "/api/Orders/{id}", ("GET",)) in got
    assert not any(n.endswith((".Util", ".Hidden", ".Internal")) for n, _, _ in got)
    assert not any(n.startswith("CrudApiController") for n, _, _ in got)
    # PostItem is overridden in the derived type: listed once, from the derived declaration.
    post = [r for r in refs if r.route.handler_name == "OrdersController.PostItem"]
    assert len(post) == 1 and post[0].route.file.endswith("OrdersController.cs")
    d = next(r for r in refs if r.route.handler_name == "OrdersController.Delete")
    assert d.route.file.endswith("Crud.cs") and d.route.line == d.method.line and d.type.name.startswith("OrdersController")


def _multilevel_app(tmp_path, base_decl):
    app = tmp_path / "M"
    app.mkdir()
    (app / "M.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Reference Include="System.Web.Http" /><Compile Include="Chain.cs" />'
        '<Compile Include="OrdersController.cs" /></ItemGroup></Project>')
    (app / "Chain.cs").write_text(
        "using System.Web.Http;\n"
        f"public abstract class Base : ApiController {{\n    {base_decl}\n}}\n"
        "public abstract class Mid : Base {\n"
        "    public override void Delete(int id) { }\n"
        "}\n")
    (app / "OrdersController.cs").write_text(
        "using System.Web.Http;\n"
        "public class OrdersController : Mid {\n"
        "}\n")
    return app


def test_multilevel_override_routes_once_at_most_derived_declaration(tmp_path, roslyn_helper):
    project._CACHE.clear()
    app = _multilevel_app(tmp_path, "public virtual void Delete(int id) { }")
    refs = discover_mvc_webapi(project.prepare(app, False))
    d = [r for r in refs if r.route.handler_name == "OrdersController.Delete"]
    assert len(d) == 1
    assert d[0].route.path == "/api/Orders/{id}" and tuple(d[0].route.methods) == ("DELETE",)
    assert d[0].route.file.endswith("Chain.cs") and d[0].route.line == d[0].method.line
    assert d[0].type.name.startswith("OrdersController")
    assert d[0].method.modifiers and "override" in [x.lower() for x in d[0].method.modifiers]


def test_multilevel_override_of_nonaction_base_stays_unrouted(tmp_path, roslyn_helper):
    # Framework override in an intermediate type is not an action.
    project._CACHE.clear()
    app = _multilevel_app(tmp_path, "protected virtual void Delete(int id) { }")
    refs = discover_mvc_webapi(project.prepare(app, False))
    assert not [r for r in refs if r.route.handler_name == "OrdersController.Delete"]
