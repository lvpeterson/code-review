"""Object- and property-level rules (IDOR, over-posting, excessive exposure) on ASP.NET Core routes of the
synthetic taint_app fixture, with the Roslyn helper and without it, plus the dotnet analyzer wiring."""
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project, routes_core, rules_object
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
    yield model, refs, rules_object.check(model, refs)
    project._CACHE.clear()


@pytest.fixture
def degraded_app(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    model, refs = _prepare(True)
    yield model, refs, rules_object.check(model, refs)
    project._CACHE.clear()


def on(findings, rule):
    """Handler names (or the route path for a minimal-API lambda) the rule fired on."""
    out = set()
    for f in findings:
        if f.check_id == rule and f.route is not None:
            h = f.route.handler_name
            out.add(f.route.path if h.startswith("<lambda") else h)
    return out


def _check(findings):
    # Edit / EditSafe look the record up by id with no ownership check: real IDORs too.
    assert on(findings, "DNL-AUTHZ-005") == {"OrdersController.Get", "/m/users/{id}", "FormsController.Edit",
                                             "FormsController.EditSafe"}
    assert on(findings, "DNL-AUTHZ-006") == {"OrdersController.Put", "FormsController.Edit", "EditOrderModel.OnPost",
                                             "/m/orders"}
    assert on(findings, "DNL-AUTHZ-007") == {"OrdersController.Users", "/m/users/{id}"}


def test_entity_types(app):
    assert rules_object.entity_types(app[0]) == {"Order", "User"}


def test_idor(app):
    got = on(app[2], "DNL-AUTHZ-005")
    assert {"OrdersController.Get", "/m/users/{id}"} <= got
    assert not got & {"OrdersController.Mine", "OrdersController.Authz"}
    assert all(f.confidence == "REVIEW" and f.severity == "low" for f in app[2] if f.check_id == "DNL-AUTHZ-005")


def test_overposting(app):
    got = on(app[2], "DNL-AUTHZ-006")
    assert {"OrdersController.Put", "FormsController.Edit", "EditOrderModel.OnPost", "/m/orders"} <= got
    assert not got & {"OrdersController.PutDto", "FormsController.EditSafe", "FormsController.Bound"}


def test_exposure(app):
    got = on(app[2], "DNL-AUTHZ-007")
    assert {"OrdersController.Users", "/m/users/{id}"} <= got
    assert "OrdersController.All" not in got


def test_exact_sets(app):
    _check(app[2])


def test_owasp_tags(app):
    from core.models import ScanResult
    res = ScanResult(language="dotnet", framework="minimalapi", findings=list(app[2]))
    tag_results([res])
    def tags(rule, path):
        f = next(f for f in res.findings if f.check_id == rule and f.route.path == path)
        return str(f.owasp)
    assert "API1:2023" in tags("DNL-AUTHZ-005", "/m/users/{id}")
    assert "API3:2023" in tags("DNL-AUTHZ-006", "/m/orders")
    assert "API3:2023" in tags("DNL-AUTHZ-007", "/m/users/{id}")


def test_dotnet_analyzer_reports_object_rules(roslyn_helper):
    project._CACHE.clear()
    results = [r for r in enumerator.enumerate_target(ROOT) if r.language == "dotnet"]
    fs = [f for r in results for f in r.findings]
    for rule in ("DNL-AUTHZ-005", "DNL-AUTHZ-006", "DNL-AUTHZ-007"):
        assert on(fs, rule), rule
    project._CACHE.clear()


def test_degraded_object_rules(degraded_app):
    _check(degraded_app[2])


# -- finer cases on a throwaway project -----------------------------------------------------------

_EXTRA = '''
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
public class Doc { public int Id { get; set; } public string OwnerId { get; set; } public string ApiToken { get; set; } }
public class Db : DbContext { public DbSet<Doc> Docs { get; set; } }
public class DocController : ControllerBase
{
    private readonly Db db;
    [HttpGet("a/{id}")] public IActionResult A(int id) { var d = db.Docs.Find(id); if (d == null) return StatusCode(500); return Ok(d); }
    [HttpGet("b/{id}")] public IActionResult B(int id) { var d = db.Docs.Find(id); if (d == null) return StatusCode(404); return Ok(1); }
    [HttpPost("c/{id}")] public async Task<IActionResult> C(int id) { var d = db.Docs.Find(id); await TryUpdateModelAsync(d, "", new[] { "OwnerId" }); return Ok(); }
    [HttpPost("d/{id}")] public async Task<IActionResult> D(int id) { var d = new Doc(); await TryUpdateModelAsync(d); return Ok(); }
    [HttpGet("e")] public IActionResult E([FromServices] Db other) => Ok(1);
}
public static class M
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/x/{id}", (int id, ClaimsPrincipal user, Db db) => { var d = db.Docs.Find(id); return d.OwnerId == user.FindFirstValue("sub") ? Results.Ok(1) : Results.Forbid(); });
        app.MapGet("/y/{id}", (int id, Db db) => db.Docs.Find(id) == null ? TypedResults.NotFound() : TypedResults.Ok(db.Docs.Find(id)));
    }
}
'''


def test_finer_cases(tmp_path, monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    (tmp_path / "A.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup>'
                                       '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
    (tmp_path / "A.cs").write_text(_EXTRA)
    project._CACHE.clear()
    project.prepare(tmp_path, True)
    model = project.get_model(tmp_path, "dotnet")
    fs = rules_object.check(model, routes_core.discover_all(model))
    idor = on(fs, "DNL-AUTHZ-005")
    # StatusCode(500) is not a denial, StatusCode(404) after the lookup alone is no ownership check either.
    assert {"DocController.A", "DocController.B"} <= idor
    # A ClaimsPrincipal parameter compared with the record, then rejecting, is an ownership check.
    assert "/x/{id}" not in idor
    assert on(fs, "DNL-AUTHZ-006") == {"DocController.D"}
    assert {"DocController.A", "/y/{id}"} <= on(fs, "DNL-AUTHZ-007")
    assert "DocController.E" not in on(fs, "DNL-AUTHZ-005")
    project._CACHE.clear()
