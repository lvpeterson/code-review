"""ASP.NET Core controller route discovery over the synthetic controllers_api fixture."""
import shutil
from pathlib import Path

import pytest

from checks.dnl import helper, project
from checks.dnl.routes_core import discover_controllers, discover_pages

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
