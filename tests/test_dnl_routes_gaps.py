"""Route-discovery gaps found on real-world shapes, reproduced on synthetic fixtures: third-party controller
bases, middleware branches, group prefixes through unresolved calls, prefix conventions, open generics and
MapMethods verb members. Each case runs with the Roslyn helper and degraded (tree-sitter)."""
import shutil
from pathlib import Path

import pytest

from checks.dnl import auth_core, project
from checks.dnl.auth_core import UNKNOWN, UNPROTECTED
from checks.dnl.pipeline import pipeline_for
from checks.dnl.routes_core import discover_all

FX = Path(__file__).parent / "fixtures" / "aspnetcore"
GAPS, PREFIX = FX / "routes_gaps", FX / "routes_prefix"


def _degrade(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)


class App:
    def __init__(self, root: Path, degraded: bool):
        project._CACHE.clear()
        project.prepare(root, degraded)
        self.model = project.get_model(root, "dotnet")
        self.refs = discover_all(self.model)

    def by_path(self, path: str):
        hits = [r for r in self.refs if r.route.path == path]
        assert len(hits) == 1, (path, [(r.route.path, r.route.handler_name) for r in self.refs])
        return hits[0]

    def by_handler(self, name: str):
        hits = [r for r in self.refs if r.route.handler_name == name]
        assert len(hits) == 1, (name, [(r.route.path, r.route.handler_name) for r in self.refs])
        return hits[0]

    def auth(self, ref):
        return auth_core.resolve(self.model, ref, pipeline_for(self.model, ref.project))


@pytest.fixture(params=[False, True], ids=["helper", "degraded"])
def degraded(request, roslyn_helper, monkeypatch):
    if request.param:
        _degrade(monkeypatch)
    return request.param


@pytest.fixture
def gaps(degraded):
    return App(GAPS, degraded)


def _copy(tmp_path: Path, src: Path, edits: dict) -> Path:
    root = tmp_path / "app"
    shutil.copytree(src, root)
    for rel, (old, new) in edits.items():
        p = root / rel
        text = p.read_text()
        assert old in text, (rel, old)
        p.write_text(text.replace(old, new))
    return root


@pytest.fixture
def clean(degraded, tmp_path):
    """routes_gaps without the unresolved NewVersionedApi call, which blocks every route's auth on its own."""
    root = _copy(tmp_path, GAPS, {"Program.cs": (
        'var catalog = app.NewVersionedApi("Catalog").MapGroup("api/catalog");\ncatalog.MapGet("/items", () => "items");\n',
        "")})
    return App(root, degraded)


def _reasons(a, ref):
    info = a.auth(ref)
    return info.state, info.reasons


def _calls(ref):
    return [c.get("fn", {}).get("name") for g in ref.groups for c in g.calls]


# -- D1: third-party controller base ------------------------------------------------------------

def test_third_party_base_class_with_route_attributes_is_a_controller(gaps):
    ping = gaps.by_handler("PingEndpoint.HandleAsync")
    assert (ping.route.path, ping.route.methods) == ("/api/ping", ["GET"])
    assert ping.route.meta["kind"] == "controller" and ping.route.meta["api_surface"] is True
    assert any("base type WithActionResult not in solution; "
               "controller semantics assumed" in u for u in ping.unknown)

    status = gaps.by_handler("StatusEndpoint.HandleAsync")
    assert (status.route.path, status.route.methods) == ("/api/status", ["POST"])
    assert status.route.meta["api_surface"] is True and status.unknown

    old = gaps.by_handler("LegacyThing.Old")
    assert old.route.path == "/old/thing" and old.route.meta["api_surface"] is False and old.unknown


def test_plain_class_with_only_an_interface_base_is_not_a_controller(gaps):
    assert not any(r.route.handler_name.startswith("Helper.") for r in gaps.refs)


# -- D8: open generic controllers ------------------------------------------------------------------

def test_open_generic_controller_is_not_a_route(gaps):
    assert not any(r.route.handler_name.startswith("GenericBase.") for r in gaps.refs)
    closed = gaps.by_handler("StringController.G")
    assert closed.route.path == "/api/gen/g"


# -- D5: Map(path, Action<IApplicationBuilder>) branches --------------------------------------------

def test_map_branch_is_listed_as_unprotected_middleware_route(gaps):
    r = gaps.by_path("/internal")
    assert r.route.methods == ["ANY"] and r.route.meta["middleware"] is True
    assert r.route.meta["kind"] == "branch" and r.style == "endpoint"
    assert r.route.file.endswith("Program.cs") and r.route.line > 0
    assert gaps.auth(r).state == UNPROTECTED
    # a MapWhen predicate has no path: it stays a model note naming file:line
    assert any("MapWhen at Program.cs:" in n for n in gaps.model.notes)


# -- D6: group prefix through unresolved extension calls ---------------------------------------------

def test_group_prefix_survives_an_unresolved_extension(gaps):
    r = gaps.by_path("/api/orders")
    assert r.route.methods == ["GET"]
    assert [g.prefix for g in r.groups] == ["/api/orders"] and r.groups[0].calls == []
    assert any("HasVersionInfo is not analysed" in u for u in r.unknown)


def test_versioned_api_builder_is_root_like(gaps):
    r = gaps.by_path("/api/catalog/items")
    assert r.groups[0].prefix == "api/catalog" and r.unknown == []


def test_convention_after_helper_on_a_passed_through_group_applies(gaps):
    r = gaps.by_path("/api/billing/invoices")
    assert [g.prefix for g in r.groups][0] == "/api/billing"
    assert "RequireAuthorization" in _calls(r)
    assert any("HasVersionInfo is not analysed" in u for u in r.unknown)   # auth stays REVIEW


def test_auth_convention_directly_after_an_unresolved_call_is_not_credited(degraded, tmp_path):
    root = _copy(tmp_path, GAPS, {"Program.cs": (
        "app.Run();\n\npublic static", 'app.MapGroup("/api/x").HasVersionInfo(1.0).RequireAuthorization()'
        '.MapGet("/y", () => "y");\napp.Run();\n\npublic static')})
    a = App(root, degraded)
    r = a.by_path("/api/x/y")
    assert "RequireAuthorization" not in _calls(r)
    assert any("RequireAuthorization applied to the result of HasVersionInfo could not be traced" in u
               for u in r.unknown)
    assert a.auth(r).state == UNKNOWN


# -- MapMethods with HttpMethods members ---------------------------------------------------------------

def test_mapmethods_reads_httpmethods_members(gaps):
    assert gaps.by_path("/probe").route.methods == ["OPTIONS"]
    r = gaps.by_path("/probe2")
    assert r.route.methods == ["POST", "PUT"]
    assert not any("HTTP methods" in u for u in r.unknown)


# -- D6b: route prefix conventions -------------------------------------------------------------------------

def test_solution_prefix_convention_with_literal_is_applied(degraded):
    a = App(PREFIX, degraded)
    assert a.by_handler("ItemsController.List").route.path == "/v9/items/list"
    assert a.by_handler("ItemsController.Rooted").route.path == "/rooted"     # a rooted template ignores the prefix
    assert not any("convention prefix" in n for n in a.model.notes)


@pytest.mark.parametrize("edit", [
    ('new ApiPrefixConvention("v9")', 'new ApiPrefixConvention(builder.Configuration["p"])'),
    ('new ApiPrefixConvention("v9")', 'new VendorPrefixConvention("v9")'),
], ids=["non-literal", "third-party"])
def test_unprovable_prefix_convention_is_a_model_note_only(tmp_path, degraded, edit):
    root = _copy(tmp_path, PREFIX, {"Program.cs": edit})
    a = App(root, degraded)
    cls = edit[1].split("(")[0].removeprefix("new ")
    assert any(f"controller paths may lack a convention prefix ({cls})" in n for n in a.model.notes)
    r = a.by_handler("ItemsController.List")
    assert r.route.path == "/items/list" and r.unknown == []                  # paths only, not auth


def test_use_general_route_prefix_is_noted(tmp_path, degraded):
    root = _copy(tmp_path, PREFIX, {"Program.cs": (
        'o.Conventions.Add(new ApiPrefixConvention("v9"));', 'o.UseGeneralRoutePrefix("api");')})
    a = App(root, degraded)
    assert any("controller paths may lack a convention prefix (UseGeneralRoutePrefix)" in n for n in a.model.notes)
    assert a.by_handler("ItemsController.List").unknown == []


# -- the notes reach auth (blocker-free variant: nothing else makes these routes UNKNOWN) -------------------

def test_third_party_base_note_makes_auth_unknown(clean):
    for name, base in [("PingEndpoint.HandleAsync", "WithActionResult"), ("StatusEndpoint.HandleAsync", "VendorEndpointBase"),
                       ("LegacyThing.Old", "VendorBase")]:
        state, reasons = _reasons(clean, clean.by_handler(name))
        assert state == UNKNOWN, name
        assert any(f"base type {base} not in solution; controller semantics assumed" in r for r in reasons), name
    # a controller without the note is not UNKNOWN for that reason
    assert not any("controller semantics" in r for r in _reasons(clean, clean.by_handler("StringController.G"))[1])


def test_unresolved_group_call_note_makes_auth_unknown(clean):
    for path in ("/api/orders", "/api/billing/invoices"):
        state, reasons = _reasons(clean, clean.by_path(path))
        assert state == UNKNOWN, path
        assert any("HasVersionInfo is not analysed" in r for r in reasons), path


def test_ancestor_group_convention_is_not_credited_through_a_pass_through(degraded, tmp_path):
    root = _copy(tmp_path, GAPS, {"Program.cs": (
        'var catalog = app.NewVersionedApi("Catalog").MapGroup("api/catalog");\ncatalog.MapGet("/items", () => "items");\n',
        'app.MapGroup("/p").RequireAuthorization().MapGroup("/q").HasVersionInfo(1.0).MapGet("/z", () => "z");\n')})
    a = App(root, degraded)
    r = a.by_path("/p/q/z")
    assert [g.prefix for g in r.groups][:2] == ["/p", "/q"]
    assert "RequireAuthorization" not in _calls(r) and r.groups[0].calls == []
    state, reasons = _reasons(a, r)
    assert state == UNKNOWN and any("HasVersionInfo is not analysed" in x for x in reasons)


# -- prefix convention scope ------------------------------------------------------------------------------

def test_conditional_prefix_convention_is_noted_not_applied(tmp_path, degraded):
    root = _copy(tmp_path, PREFIX, {"Program.cs": (
        'builder.Services.AddControllers(o => { o.Conventions.Add(new ApiPrefixConvention("v9")); });',
        'builder.Services.AddControllers(o => { if (args.Length > 0) { o.Conventions.Add(new ApiPrefixConvention("v9")); } });')})
    a = App(root, degraded)
    assert a.by_handler("ItemsController.List").route.path == "/items/list"
    assert any("ApiPrefixConvention is applied conditionally" in n for n in a.model.notes)


def test_two_literal_prefix_conventions_are_both_noted(tmp_path, degraded):
    root = _copy(tmp_path, PREFIX, {"Program.cs": (
        'o.Conventions.Add(new ApiPrefixConvention("v9"));',
        'o.Conventions.Add(new ApiPrefixConvention("v9")); o.Conventions.Add(new ApiPrefixConvention("v8"));')})
    a = App(root, degraded)
    assert a.by_handler("ItemsController.List").route.path == "/items/list"
    assert sum("several prefix conventions" in n for n in a.model.notes) >= 1


def test_prefix_convention_applies_only_to_the_registering_project(tmp_path, degraded):
    root = tmp_path / "sln"
    shutil.copytree(PREFIX, root / "host")
    (root / "lib").mkdir()
    (root / "lib" / "Lib.csproj").write_text((PREFIX / "RoutesPrefix.csproj").read_text())
    (root / "lib" / "Other.cs").write_text(
        "using Microsoft.AspNetCore.Mvc;\n[ApiController, Route(\"other\")]\npublic class OtherController : ControllerBase\n"
        "{\n    [HttpGet(\"x\")]\n    public IActionResult X() => Ok();\n}\n")
    a = App(root, degraded)
    assert a.by_handler("ItemsController.List").route.path == "/v9/items/list"
    assert a.by_handler("OtherController.X").route.path == "/other/x"
    assert any("controller paths may lack a convention prefix (ApiPrefixConvention)" in n for n in a.model.notes)
