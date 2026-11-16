"""ASP.NET Core controller route discovery over the synthetic controllers_api fixture."""
import shutil
from pathlib import Path

import pytest

from checks.dnl import helper, project
from checks.dnl.routes_core import discover_controllers

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
