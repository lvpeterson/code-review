"""ASP.NET Core controller route discovery over the synthetic controllers_api fixture."""
import shutil
from pathlib import Path

import pytest

from checks.dnl import helper, project
from checks.dnl.routes_core import discover_all, discover_controllers, discover_endpoints, discover_pages

FX = Path(__file__).parent / "fixtures" / "aspnetcore" / "controllers_api"


def _discover(root: Path, allow_degraded: bool = False):
    project._CACHE.clear()
    project.prepare(root, allow_degraded)
    return discover_controllers(project.get_model(root, "dotnet"))


@pytest.fixture(scope="module")
def refs(roslyn_helper):
    return _discover(FX)


def rt(refs, handler):
    hits = [r for r in refs if r.route.handler_name == handler]
    assert len(hits) == 1, handler
    return hits[0]


def triples(refs):
    return {(r.route.handler_name, r.route.path, tuple(r.route.methods)) for r in refs}


def test_attribute_routes_and_tokens(refs):
    get = rt(refs, "OrdersController.Get").route
    assert (get.path, get.methods) == ("/api/Orders/{id}", ["GET"])
    assert rt(refs, "OrdersController.Delete").route.methods == ["DELETE"]
    assert rt(refs, "OrdersController.Legacy").route.path == "/legacy/orders"
    assert rt(refs, "OrdersController.Public").route.path == "/api/Orders/public"
    assert rt(refs, "HealthController.Get").route.path == "/health"


def test_nonaction_and_noncontroller_excluded(refs):
    names = {r.route.handler_name for r in refs}
    assert "OrdersController.Helper" not in names
    assert "NotAController.Run" not in names and "PlainService.Run" not in names


def test_conventional_route(refs):
    idx = rt(refs, "HomeController.Index")
    assert (idx.route.path, idx.route.methods) == ("/Home/Index/{id?}", ["ANY"])
    assert rt(refs, "HomeController.Save").route.methods == ["POST"]
    assert "route_assumed" not in idx.route.meta


def test_area_token(refs):
    assert rt(refs, "ManageController.Reset").route.path == "/Admin/Manage/Reset"


def test_inherited_base_controller(refs):
    r = rt(refs, "InvoicesController.Create")
    assert (r.route.path, r.route.methods) == ("/invoices", ["POST"])
    assert r.route.meta["api_surface"] is True
    assert not any(x.route.handler_name.startswith("BaseApiController") for x in refs)


def test_api_surface_flag(refs):
    assert rt(refs, "HomeController.Index").route.meta["api_surface"] is False
    assert rt(refs, "OrdersController.Get").route.meta["api_surface"] is True
    assert rt(refs, "HealthController.Get").route.meta["api_surface"] is True
    meta = rt(refs, "OrdersController.Get").route.meta
    assert meta["kind"] == "controller" and meta["controller"] == "Shop.Controllers.OrdersController"
    assert "env" not in meta


def test_convention_calls_attached(roslyn_helper, tmp_path):
    root = tmp_path / "app"
    shutil.copytree(FX, root)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace("app.MapControllers();", "app.MapControllers().RequireAuthorization();"))
    out = _discover(root)
    assert [c["fn"]["name"] for c in rt(out, "OrdersController.Get").convention_calls] == ["RequireAuthorization"]
    assert rt(out, "HomeController.Index").convention_calls == []
    assert rt(out, "OrdersController.Get").style == "controller"


def test_handler_range_for_code_view(refs):
    r = rt(refs, "OrdersController.Get").route
    assert r.file.replace("\\", "/").endswith("Controllers/OrdersController.cs")
    assert r.source_start_line == r.line
    assert r.source_end_line >= r.source_start_line


def test_route_assumed_without_any_route(roslyn_helper, tmp_path):
    root = tmp_path / "app"
    shutil.copytree(FX, root)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace(
        'app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");', ""))
    out = _discover(root)
    idx = rt(out, "HomeController.Index")
    assert idx.route.path == "/Home/Index/{id?}"
    assert idx.route.meta["route_assumed"] is True


def test_degraded_controller_routes(roslyn_helper, monkeypatch):
    full = triples(_discover(FX))
    monkeypatch.setattr(helper, "find_helper", lambda *a, **k: None)
    monkeypatch.setattr(helper, "sdk_available", lambda *a, **k: False)
    assert triples(_discover(FX, True)) == full


def test_env_guarded_mappings_set_meta_env(roslyn_helper, tmp_path):
    root = tmp_path / "app"
    shutil.copytree(FX, root)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text()
                    .replace("app.MapControllers();", "if (app.Environment.IsDevelopment()) { app.MapControllers(); }")
                    .replace('app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");',
                             'if (app.Environment.IsDevelopment()) { app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}"); }'))
    out = _discover(root)
    assert rt(out, "OrdersController.Get").route.meta["env"] == "Development"
    assert rt(out, "HomeController.Index").route.meta["env"] == "Development"


def _copy(tmp_path):
    root = tmp_path / "app"
    shutil.copytree(FX, root)
    return root


def _split_halves(root, second_extra=""):
    d = root / "Controllers"
    (d / "SplitController.Meta.cs").write_text(
        "using Microsoft.AspNetCore.Authorization;\nusing Microsoft.AspNetCore.Mvc;\n\nnamespace Shop.Controllers;\n\n"
        '[ApiController]\n[Route("api/split")]\n[AllowAnonymous]\n'
        "public partial class SplitController : ControllerBase\n{\n}\n")
    (d / "SplitController.Actions.cs").write_text(
        "using Microsoft.AspNetCore.Mvc;\n\nnamespace Shop.Controllers;\n\n"
        f"{second_extra}public partial class SplitController\n{{\n"
        '    [HttpGet("x")]\n    public IActionResult Get() => Ok();\n}\n')


def test_partial_controller_halves_are_merged(roslyn_helper, tmp_path):
    root = _copy(tmp_path)
    _split_halves(root)
    out = _discover(root)
    r = rt(out, "SplitController.Get")
    assert (r.route.path, r.route.methods) == ("/api/split/x", ["GET"])
    assert r.route.meta["api_surface"] is True
    assert "route_assumed" not in r.route.meta
    assert r.route.file.replace("\\", "/").endswith("SplitController.Actions.cs")
    assert "AllowAnonymous" in {a.name.split(".")[-1].removesuffix("Attribute") for a in r.type.attributes}
    assert len(r.partials) == 2


def test_noncontroller_on_one_half_excludes_both(roslyn_helper, tmp_path):
    root = _copy(tmp_path)
    _split_halves(root, second_extra="[NonController]\n")
    out = _discover(root)
    assert not any(r.route.handler_name.startswith("SplitController") for r in out)


def test_defaults_only_conventional_route_is_assumed_and_unknown(roslyn_helper, tmp_path):
    root = _copy(tmp_path)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace(
        'app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");',
        'app.MapControllerRoute("d", "home");'))
    idx = rt(_discover(root), "HomeController.Index")
    assert idx.route.meta["route_assumed"] is True
    assert idx.unknown and any("defaults" in u and "'d'" in u for u in idx.unknown)


# -- Razor Pages ---------------------------------------------------------------

RAZOR = Path(__file__).parent / "fixtures" / "aspnetcore" / "razor_app"


def _discover_pages(root: Path, allow_degraded: bool = False):
    project._CACHE.clear()
    project.prepare(root, allow_degraded)
    return discover_pages(project.get_model(root, "dotnet"))


@pytest.fixture(scope="module")
def pages(roslyn_helper):
    return _discover_pages(RAZOR)


def test_page_paths(pages):
    got = triples(pages)
    assert ("IndexModel.OnGet", "/", ("GET",)) in got
    assert ("UsersModel.OnGet", "/Admin/Users/{id?}", ("GET",)) in got
    assert ("UsersModel.OnPostDeleteAsync", "/Admin/Users/{id?}", ("POST",)) in got
    assert ("CartModel.OnPostCheckout", "/Shop/Cart", ("POST",)) in got
    assert ("EditModel.OnPostSave", "/Orders/Edit/{id}", ("POST",)) in got
    assert not any(h == "UsersModel.Describe" for h, _, _ in got)
    assert all(r.style == "razorpage" for r in pages)


def test_handler_meta(pages):
    d = rt(pages, "UsersModel.OnPostDeleteAsync").route.meta
    assert d["handler"] == "Delete" and d["page"] == "/Admin/Users"
    assert d["kind"] == "razorpage" and d["api_surface"] is False and "area" not in d
    assert rt(pages, "IndexModel.OnGet").route.meta["handler"] == ""
    assert rt(pages, "CartModel.OnGet").route.meta["area"] == "Shop"


def test_convention_calls_and_source_range(pages):
    r = rt(pages, "UsersModel.OnPostDeleteAsync")
    assert r.convention_calls == [] and r.method is not None
    assert r.route.file.endswith("Users.cshtml.cs")
    assert (r.route.source_start_line, r.route.source_end_line) == (r.method.line, r.method.end_line)


def test_layout_not_a_route(pages):
    assert not any(r.route.file.endswith("_Layout.cshtml") for r in pages)


def test_orphan_page_unknown(pages):
    hits = [r for r in pages if r.route.file.replace("\\", "/").endswith("Orphan.cshtml")]
    assert len(hits) == 1
    r = hits[0]
    assert r.type is None and r.method is None and r.route.methods == ["GET"]
    assert r.unknown and "MissingModel" in r.unknown[0]
    assert r.route.source_start_line == 1 and r.route.source_end_line >= 3


def test_page_without_handlers(pages):
    hits = [r for r in pages if r.route.path == "/Privacy"]
    assert len(hits) == 1
    assert hits[0].method is None and hits[0].type.name == "PrivacyModel"
    assert hits[0].route.methods == ["GET"]


def test_model_resolved_via_area_viewimports(pages):
    cart = rt(pages, "CartModel.OnGet")
    assert cart.type.full_name == "RazorApp.Areas.Shop.Pages.CartModel"
    assert not cart.unknown


def test_degraded_pages(pages, monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    deg = _discover_pages(RAZOR, True)
    assert triples(deg) == triples(pages)


def test_template_overrides_and_indexes(roslyn_helper, tmp_path):
    root = tmp_path / "app"
    shutil.copytree(RAZOR, root)
    nl = chr(10)
    (root / "Pages" / "Admin" / "Index.cshtml").write_text('@page "/dash/{n:int}"' + nl + "@model IndexModel" + nl)
    (root / "Pages" / "Admin" / "Index.cshtml.cs").write_text(
        "using Microsoft.AspNetCore.Mvc.RazorPages;" + nl + "namespace RazorApp.Pages.Admin;" + nl
        + "public class IndexModel : PageModel { public void OnGet() { } public void OnPutAsync() { } }" + nl)
    out = _discover_pages(root)
    got = triples(out)
    assert ("IndexModel.OnGet", "/dash/{n}", ("GET",)) in got
    assert ("IndexModel.OnPutAsync", "/dash/{n}", ("PUT",)) in got
    # the root IndexModel still binds to the root page
    assert ("IndexModel.OnGet", "/", ("GET",)) in got


def _razor_copy(tmp_path):
    root = tmp_path / "rz"
    shutil.copytree(RAZOR, root)
    return root


def _names(calls):
    from checks.dnl.ir import call_name
    return [call_name(c) for c in calls]


def test_qualified_model_with_other_namespace_is_not_bound(roslyn_helper, tmp_path):
    root = _razor_copy(tmp_path)
    idx = root / "Pages" / "Index.cshtml"
    idx.write_text(idx.read_text().replace("@model IndexModel", "@model Other.Ns.IndexModel"))
    out = _discover_pages(root)
    hit = [r for r in out if r.route.file.replace("\\", "/").endswith("Pages/Index.cshtml")]
    assert len(hit) == 1 and hit[0].type is None
    assert "Other.Ns.IndexModel" in hit[0].unknown[0]


def test_qualified_model_matching_namespace_binds(roslyn_helper, tmp_path):
    root = _razor_copy(tmp_path)
    idx = root / "Pages" / "Index.cshtml"
    idx.write_text(idx.read_text().replace("@model IndexModel", "@model RazorApp.Pages.IndexModel"))
    assert rt(_discover_pages(root), "IndexModel.OnGet").type.full_name == "RazorApp.Pages.IndexModel"


def test_page_convention_calls_chain(roslyn_helper, tmp_path):
    root = _razor_copy(tmp_path)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace("app.MapRazorPages();", "app.MapRazorPages().RequireAuthorization();"))
    out = _discover_pages(root)
    assert all(_names(r.convention_calls) == ["RequireAuthorization"] for r in out)
    assert not any("chained differently" in u for r in out for u in r.unknown)


def test_dev_only_page_conventions_do_not_protect_production(roslyn_helper, tmp_path):
    root = _razor_copy(tmp_path)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace(
        "app.MapRazorPages();",
        "if (app.Environment.IsDevelopment()) { app.MapRazorPages().RequireAuthorization(); } else { app.MapRazorPages(); }"))
    out = _discover_pages(root)
    assert out and all(r.convention_calls == [] for r in out)


def test_dev_only_controller_conventions_do_not_protect_production(roslyn_helper, tmp_path):
    root = _copy(tmp_path)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace(
        "app.MapControllers();",
        "if (app.Environment.IsDevelopment()) { app.MapControllers().RequireAuthorization(); } else { app.MapControllers(); }"))
    out = _discover(root)
    get = rt(out, "OrdersController.Get")
    assert get.convention_calls == []


def test_controller_convention_calls_chain(roslyn_helper, tmp_path):
    root = _copy(tmp_path)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace("app.MapControllers();", "app.MapControllers().RequireAuthorization();"))
    assert _names(rt(_discover(root), "OrdersController.Get").convention_calls) == ["RequireAuthorization"]


def test_dev_only_mapping_notes_unknown(roslyn_helper, tmp_path):
    root = _razor_copy(tmp_path)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace(
        "app.MapRazorPages();", "if (app.Environment.IsDevelopment()) { app.MapRazorPages().RequireAuthorization(); }"))
    out = _discover_pages(root)
    assert out and all(r.convention_calls == [] for r in out)
    assert all(any("outside Production" in u for u in r.unknown) for r in out)


def test_dev_only_controller_mappings_note_attribute_and_assumed_routes(roslyn_helper, tmp_path):
    root = _copy(tmp_path)
    prog = root / "Program.cs"
    text = prog.read_text().replace(
        'app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");', "")
    prog.write_text(text.replace(
        "app.MapControllers();", "if (app.Environment.IsDevelopment()) { app.MapControllers(); }"))
    out = _discover(root)
    attr = rt(out, "OrdersController.Get")
    assumed = rt(out, "HomeController.Index")
    assert assumed.route.meta["route_assumed"] is True
    for r in (attr, assumed):
        assert any("outside Production" in u for u in r.unknown), r.route.handler_name


def test_differently_chained_page_mappings_keep_shared_prefix_and_note(roslyn_helper, tmp_path):
    root = _razor_copy(tmp_path)
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace(
        "app.MapRazorPages();",
        "if (app.Configuration[\"x\"] == \"1\") { app.MapRazorPages().RequireAuthorization().WithDisplayName(\"a\"); }"
        " else { app.MapRazorPages().RequireAuthorization(); }"))
    out = _discover_pages(root)
    assert out
    for r in out:
        assert _names(r.convention_calls) == ["RequireAuthorization"]
        assert any("chained differently" in u for u in r.unknown)


# -- Minimal API and other endpoints ---------------------------------------------

MINIMAL = Path(__file__).parent / "fixtures" / "aspnetcore" / "minimal_api"


def _discover_eps(root: Path, allow_degraded: bool = False):
    project._CACHE.clear()
    project.prepare(root, allow_degraded)
    return discover_endpoints(project.get_model(root, "dotnet"))


@pytest.fixture(scope="module")
def eps(roslyn_helper):
    return _discover_eps(MINIMAL)


def ep(refs, path):
    hits = [r for r in refs if r.route.path == path]
    assert len(hits) == 1, path
    return hits[0]


def pm(refs):
    return {(r.route.path, tuple(r.route.methods)) for r in refs}


def test_minimal_paths_and_verbs(eps):
    got = pm(eps)
    for want in [("/", ("GET",)), ("/api/orders/{id}", ("GET",)), ("/api/orders", ("POST",)),
                 ("/api/status", ("GET",)), ("/api/admin/users/{id}", ("DELETE",)),
                 ("/v2/users", ("GET",)), ("/audit/a", ("GET",))]:
        assert want in got, want
    r = ep(eps, "/api/orders")
    assert r.style == "minimalapi" and r.route.meta["kind"] == "minimalapi"
    assert r.route.meta["api_surface"] is True and "env" not in r.route.meta


def test_lambda_handler_body_and_params(eps):
    r = ep(eps, "/api/orders/{id}")
    assert r.method.name.startswith("<lambda@")
    assert [p.name for p in r.method.params] == ["id", "store"]
    assert [p.type for p in r.method.params] == ["int", "OrderStore"]
    assert r.method.body and r.method.body[0]["k"] == "return"
    assert r.type.name == "Program"
    assert r.route.source_start_line <= r.method.line <= r.method.end_line <= r.route.source_end_line


def test_method_group_handler(eps):
    r = ep(eps, "/api/orders")
    assert r.method.name == "CreateOrder"
    assert [p.name for p in r.method.params] == ["o"]


def test_group_calls_recorded(eps):
    r = ep(eps, "/api/admin/users/{id}")
    assert [g.prefix for g in r.groups] == ["/api", "/admin"]
    assert all(_names(g.calls) == ["RequireAuthorization"] for g in r.groups)
    assert _names(ep(eps, "/api/status").endpoint_calls) == ["AllowAnonymous"]
    assert ep(eps, "/api/orders").endpoint_calls == []
    assert ep(eps, "/").groups == []


def test_extension_method_followed(eps):
    r = ep(eps, "/v2/users")
    assert [g.prefix for g in r.groups] == ["/v2"]
    assert r.caller_unknown is False and r.unknown == []


def test_untraced_chain_marked(eps):
    for path in ("/audit/a", "/audit/b"):
        r = ep(eps, path)
        assert not any("RequireAuthorization" in _names(g.calls) for g in r.groups)
        assert any("MapAuditEndpoints" in u for u in r.unknown), path
        assert r.caller_unknown is False


def test_unreached_method_caller_unknown(eps):
    r = ep(eps, "/orphan")
    assert r.caller_unknown is True and r.route.methods == ["POST"]
    assert ep(eps, "/").caller_unknown is False


def test_other_endpoints(eps):
    hub = ep(eps, "/chat")
    assert hub.route.meta["kind"] == "hub" and hub.type.name == "ChatHub" and hub.style == "endpoint"
    assert ep(eps, "/healthz").route.meta["kind"] == "health"
    sw = ep(eps, "/swagger")
    assert sw.route.meta["kind"] == "openapi" and sw.route.meta["middleware"] is True
    assert sw.route.meta["env"] == "Development"
    assert ep(eps, "/swagger/{documentName}/swagger.json").route.meta["middleware"] is True
    assert ep(eps, "/debug/env").route.meta["env"] == "Development"


def _copy_minimal(tmp_path):
    root = tmp_path / "mini"
    shutil.copytree(MINIMAL, root)
    return root


def test_resolved_sym_elsewhere_is_not_a_route(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    (root / "Router.cs").write_text(
        "public class Router { public void MapGet(string p, Func<int> h) { } }" + chr(10)
        + 'public static class RouterUse { public static void Go() { new Router().MapGet("/x", () => 1); } }' + chr(10))
    out = _discover_eps(root)
    assert not any(r.route.path == "/x" for r in out)
    assert ("/" , ("GET",)) in pm(out)


def test_degraded_minimal_routes(roslyn_helper, monkeypatch):
    full = pm(_discover_eps(MINIMAL))
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    assert pm(_discover_eps(MINIMAL, True)) == full


def test_discover_all_combines_and_caches(roslyn_helper):
    project._CACHE.clear()
    project.prepare(MINIMAL, False)
    model = project.get_model(MINIMAL, "dotnet")
    allr = discover_all(model)
    assert allr is discover_all(model) and model.cache["core_routes"] is allr
    assert {r.style for r in allr} == {"minimalapi", "endpoint"}
    assert len(allr) == len(discover_endpoints(model)) + len(discover_controllers(model)) + len(discover_pages(model))


def _edit(root, name, old, new):
    f = root / name
    text = f.read_text()
    assert old in text, (name, old)
    f.write_text(text.replace(old, new))


def test_convention_after_followed_group_applies_as_extra_group(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", 'app.MapGroup("/v2").MapUserEndpoints();',
          'app.MapGroup("/v2").MapUserEndpoints().RequireAuthorization();')
    r = ep(_discover_eps(root), "/v2/users")
    assert [g.prefix for g in r.groups] == ["/v2", ""]
    assert _names(r.groups[1].calls) == ["RequireAuthorization"] and r.groups[0].calls == []
    assert r.unknown == []


def test_convention_after_returned_route_applies_to_that_route_only(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "AuditEndpoints.cs", 'var b = e.MapGet("/audit/b", () => 2);\n        return new CompositeConventionBuilder(a, b);',
          'e.MapGet("/audit/b", () => 2);\n        return a;')
    out = _discover_eps(root)
    a, b = ep(out, "/audit/a"), ep(out, "/audit/b")
    assert _names(a.endpoint_calls) == ["RequireAuthorization"] and a.unknown == []
    assert b.endpoint_calls == [] and b.unknown == []


def test_group_bound_from_a_local_through_static_call_form(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", 'app.MapGroup("/v2").MapUserEndpoints();',
          'var v2 = app.MapGroup("/v2").RequireAuthorization();\nUserEndpoints.MapUserEndpoints(v2);')
    r = ep(_discover_eps(root), "/v2/users")
    assert [g.prefix for g in r.groups] == ["/v2"] and _names(r.groups[0].calls) == ["RequireAuthorization"]


STARTUP = """using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

public class Startup
{
    public void ConfigureServices(IServiceCollection services) { services.AddGrpc(); }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseRouting();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapMethods("/m", new[] { "get", "put" }, () => "m");
            var g = endpoints.MapGroup("/g").WithTags("t");
            g.MapGet("/one", Handlers.One);
            g.MapGet("/two", Missing);
            endpoints.MapGrpcService<GreeterService>();
            endpoints.MapFallbackToFile("index.html");
            if (env.IsDevelopment()) { endpoints.MapGet("/dev", () => 1); }
            Local(endpoints);
            void Local(IEndpointRouteBuilder b) { b.MapPut("/local", () => 2); }
        });
    }
}

public static class Handlers { public static string One() => "1"; }
public class GreeterService { }
"""


def _startup_app(tmp_path):
    root = tmp_path / "su"
    root.mkdir()
    (root / "Su.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup>'
                                     "<TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings>"
                                     "</PropertyGroup></Project>")
    (root / "Startup.cs").write_text(STARTUP)
    return root


def test_useendpoints_lambda_groups_handlers_and_other_maps(roslyn_helper, tmp_path):
    out = _discover_eps(_startup_app(tmp_path))
    got = {(r.route.path, tuple(r.route.methods)) for r in out}
    assert ("/m", ("GET", "PUT")) in got
    assert ("/g/one", ("GET",)) in got and ("/g/two", ("GET",)) in got
    assert ("/local", ("PUT",)) in got
    one, two = ep(out, "/g/one"), ep(out, "/g/two")
    assert one.method.name == "One" and one.type.name == "Handlers" and one.route.handler_name == "Handlers.One"
    assert two.method is None and any("handler Missing not resolved" in u for u in two.unknown)
    assert _names(one.groups[0].calls) == ["WithTags"]
    grpc = ep(out, "/GreeterService/*")
    assert grpc.route.meta["kind"] == "grpc" and grpc.route.meta["api_surface"] is True
    assert grpc.type.name == "GreeterService"
    assert ep(out, "/{**path}").route.meta["kind"] == "fallback"
    assert ep(out, "/dev").route.meta["env"] == "Development"
    assert ep(out, "/local").route.meta.get("env") is None


def test_dev_only_local_function_call_carries_env(roslyn_helper, tmp_path):
    root = _startup_app(tmp_path)
    _edit(root, "Startup.cs", "            Local(endpoints);", "            if (env.IsDevelopment()) { Local(endpoints); }")
    assert ep(_discover_eps(root), "/local").route.meta["env"] == "Development"


def test_unresolved_group_receiver_is_marked(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", 'var admin = api.MapGroup("/admin").RequireAuthorization("AdminOnly");',
          'var admin = args.Length > 0 ? api.MapGroup("/admin") : api.MapGroup("/other");')
    r = ep(_discover_eps(root), "/users/{id}")
    assert any("could not be traced" in u for u in r.unknown)


def test_extension_methods_nobody_calls_are_all_caller_unknown(roslyn_helper, tmp_path):
    root = tmp_path / "empty"
    shutil.copytree(MINIMAL, root)
    (root / "Program.cs").write_text("var app = WebApplication.CreateBuilder(args).Build(); app.Run();")
    out = _discover_eps(root)
    assert {r.route.path for r in out} == {"/orphan", "/users", "/audit/a", "/audit/b"}
    assert all(r.caller_unknown for r in out)


# -- fix round 1 -----------------------------------------------------------------

def _degraded(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)


def test_map_in_unwalked_branch_lambda_is_swept(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", "app.Run();",
          'app.MapWhen(c => true, b => { b.UseEndpoints(e => e.MapGet("/branch", () => 1)); });\napp.Run();')
    r = ep(_discover_eps(root), "/branch")
    assert r.caller_unknown is True and r.route.methods == ["GET"]
    assert any("not reached by the pipeline walk" in u for u in r.unknown)
    assert sum(1 for x in _discover_eps(root) if x.route.path == "/") == 1   # nothing registered twice


def test_unreached_application_builder_and_nullable_builder_methods(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    (root / "Late.cs").write_text(
        "public static class Late {" + chr(10)
        + '  public static void Wire(IApplicationBuilder app) { app.UseEndpoints(e => { e.MapGet("/late", () => 1); }); }' + chr(10)
        + '  public static void Wire2(IEndpointRouteBuilder? e) { e.MapGet("/nullable", () => 1); }' + chr(10)
        + '  public static void Wire3(WebApplication? a) { a.MapGet("/nullapp", () => 1); }' + chr(10) + "}" + chr(10))
    out = _discover_eps(root)
    for path in ("/late", "/nullable", "/nullapp"):
        assert ep(out, path).caller_unknown is True, path


FACTORY = """var app = AppFactory.Make(args);
var g = args.Length > 0 ? app.MapGroup("/a") : app.MapGroup("/b");
g.MapGet("/t", () => 1);
foreach (var grp in new[] { g }) { grp.MapGet("/each", () => 3); }
app.MapGet("/f", () => 2);
public static class AppFactory { public static WebApplication Make(string[] a) => WebApplication.CreateBuilder(a).Build(); }
"""


def _factory_app(tmp_path):
    root = _copy_minimal(tmp_path)
    (root / "Program.cs").write_text(FACTORY)
    return root


def test_unknown_receivers_still_register_with_and_without_helper(roslyn_helper, tmp_path, monkeypatch):
    root = _factory_app(tmp_path)
    full = _discover_eps(root)
    got = pm(full)
    assert {("/f", ("GET",)), ("/t", ("GET",)), ("/each", ("GET",))} <= got
    assert any("could not be traced" in u for u in ep(full, "/t").unknown)
    _degraded(monkeypatch)
    deg = _discover_eps(root, True)
    assert {("/f", ("GET",)), ("/t", ("GET",)), ("/each", ("GET",))} <= pm(deg)
    assert any("could not be traced" in u for u in ep(deg, "/t").unknown)


def test_conditional_conventions_are_not_trusted(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", "app.Run();", """var cg = app.MapGroup("/cg");
if (args.Length > 0) cg.RequireAuthorization();
cg.MapGet("/c", () => 1);
var ce = app.MapGet("/ce", () => 2);
if (args.Length > 1) { ce.RequireAuthorization(); }
var lg = app.MapGroup("/lg");
foreach (var x in args) { lg.RequireAuthorization(); }
lg.MapGet("/l", () => 1);
app.Run();""")
    out = _discover_eps(root)
    for path in ("/cg/c", "/ce", "/lg/l"):
        r = ep(out, path)
        assert any("RequireAuthorization applied conditionally" in u for u in r.unknown), path
    assert ep(out, "/").unknown == [] and ep(out, "/api/orders").unknown == []


def test_handler_source_ranges(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    (root / "Handlers.cs").write_text("public static class Handlers" + chr(10) + "{" + chr(10)
                                      + '    public static string One()' + chr(10) + "    {" + chr(10)
                                      + '        return "1";' + chr(10) + "    }" + chr(10) + "}" + chr(10))
    _edit(root, "Program.cs", "app.Run();", 'app.MapGet("/h", Handlers.One);\napp.Run();')
    out = _discover_eps(root)
    h = ep(out, "/h")
    assert h.route.source_file.replace("\\", "/").endswith("Handlers.cs")
    assert (h.route.source_start_line, h.route.source_end_line) == (h.method.line, h.method.end_line) == (3, 6)
    assert h.route.file.replace("\\", "/").endswith("Program.cs")
    o = ep(out, "/api/orders")
    assert o.route.source_file.replace("\\", "/").endswith("Program.cs")
    assert (o.route.source_start_line, o.route.source_end_line) == (o.method.line, o.method.end_line)
    assert ep(out, "/").route.source_file is None


ATTRS = """app.MapGet("/attr", [Authorize] () => 1);
app.MapGet("/anon", [AllowAnonymous] static (int id) => id);
[Authorize(Roles = "x")] static int Loc() => 1;
app.MapGet("/loc", Loc);
app.MapGet("/plain", () => 1);
"""


def _attr_names(r):
    return [a.name for a in r.method.attributes]


def test_lambda_and_local_function_attributes_reach_the_handler(roslyn_helper, tmp_path, monkeypatch):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", "app.Run();", ATTRS + "app.Run();")
    for degraded in (False, True):
        if degraded:
            _degraded(monkeypatch)
        out = _discover_eps(root, degraded)
        assert _attr_names(ep(out, "/attr")) == ["Authorize"]
        assert _attr_names(ep(out, "/anon")) == ["AllowAnonymous"]
        assert _attr_names(ep(out, "/loc")) == ["Authorize"]
        assert ep(out, "/plain").method.attributes == []


def test_external_call_in_chain_does_not_pass_conventions_through(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", "app.Run();", """var rg = app.MapGroup("/r");
rg.MapIdentityApi<IdentityUser>().RequireAuthorization();
rg.MapGet("/r1", () => 1);
app.Run();""")
    r = ep(_discover_eps(root), "/r/r1")
    assert not any("RequireAuthorization" in _names(g.calls) for g in r.groups)
    assert any("RequireAuthorization applied to the result of MapIdentityApi could not be traced" in u for u in r.unknown)


def test_unmodelled_map_extension_is_noted_on_model_and_group(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", "app.Run();", """app.MapGroup("/account").MapIdentityApi<IdentityUser>();
var ag = app.MapGroup("/acct2");
ag.MapGet("/me", () => 1);
ag.MapIdentityApi<IdentityUser>();
app.Run();""")
    project._CACHE.clear()
    project.prepare(root, False)
    model = project.get_model(root, "dotnet")
    out = discover_endpoints(model)
    assert any("MapIdentityApi" in n and "Program.cs:" in n and "review them manually" in n for n in model.notes)
    # called on a group local: routes on that group, registered before or after, carry the note
    assert any("MapIdentityApi registers endpoints" in u for u in ep(out, "/acct2/me").unknown)
    assert ep(out, "/").unknown == []


def test_dev_only_swept_registration_is_flagged(roslyn_helper, tmp_path):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", "app.Run();",
          'app.MapWhen(c => true, b => { if (app.Environment.IsDevelopment()) b.UseEndpoints(e => e.MapGet("/dv", () => 1)); });'
          + chr(10) + "app.Run();")
    r = ep(_discover_eps(root), "/dv")
    assert any("environment and group prefix" in u for u in r.unknown)


@pytest.mark.parametrize("wrapper", [
    "for (var i = 0; i < args.Length; i++) { G.RequireAuthorization(); }",
    "try { G.RequireAuthorization(); } catch (Exception) { }",
    "switch (args.Length) { case 0: G.RequireAuthorization(); break; default: break; }",
    "while (args.Length > 5) { G.RequireAuthorization(); }",
])
def test_conditional_conventions_in_loop_try_and_switch(roslyn_helper, tmp_path, wrapper):
    root = _copy_minimal(tmp_path)
    _edit(root, "Program.cs", "app.Run();",
          'var G = app.MapGroup("/cx");' + chr(10) + wrapper + chr(10) + 'G.MapGet("/x", () => 1);' + chr(10) + "app.Run();")
    r = ep(_discover_eps(root), "/cx/x")
    assert any("RequireAuthorization applied conditionally" in u for u in r.unknown), wrapper
