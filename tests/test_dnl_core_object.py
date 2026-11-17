"""Object- and property-level rules (IDOR, over-posting, excessive exposure) on ASP.NET Core routes of the
synthetic taint_app fixture, with the Roslyn helper and without it, plus the dotnet analyzer wiring."""
import shutil
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
                                             "FormsController.EditSafe", "OrdersController.Probe"}
    assert on(findings, "DNL-AUTHZ-006") == {"OrdersController.Put", "FormsController.Edit", "EditOrderModel.OnPost",
                                             "/m/orders"}
    assert on(findings, "DNL-AUTHZ-007") == {"OrdersController.Users", "/m/users/{id}", "AccountsController.Me"}


def test_entity_types(app):
    assert rules_object.entity_types(app[0]) == {"Order", "User", "ApplicationUser"}


def test_idor(app):
    got = on(app[2], "DNL-AUTHZ-005")
    assert {"OrdersController.Get", "/m/users/{id}", "OrdersController.Probe"} <= got
    assert not got & {"OrdersController.Mine", "OrdersController.Authz"}
    assert all(f.confidence == "REVIEW" and f.severity == "low" for f in app[2] if f.check_id == "DNL-AUTHZ-005")


def test_overposting(app):
    got = on(app[2], "DNL-AUTHZ-006")
    assert {"OrdersController.Put", "FormsController.Edit", "EditOrderModel.OnPost", "/m/orders"} <= got
    assert not got & {"OrdersController.PutDto", "FormsController.EditSafe", "FormsController.Bound"}


def test_exposure(app):
    got = on(app[2], "DNL-AUTHZ-007")
    assert {"OrdersController.Users", "/m/users/{id}", "AccountsController.Me"} <= got
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


# -- fix round: authorization gating, identity entities, [JsonIgnore], isolation, mixed solution ----

_CSPROJ = ('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup>'
           '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')

_FIX2 = '''
using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
public class Doc { public int Id { get; set; } public string OwnerId { get; set; } public decimal Total { get; set; } }
public class Db : DbContext { public DbSet<Doc> Docs { get; set; } public DbSet<Acct> Accts { get; set; }
                              public DbSet<Key> Keys { get; set; } public DbSet<Hidden> Hiddens { get; set; } }
public class Acct { public int Id { get; set; } public string ApiKeys { get; set; } }
public class Key { public int Id { get; set; } public string SecretKey { get; set; } }
public class Hidden { public int Id { get; set; } [JsonIgnore] public string PasswordHash { get; set; }
                      [IgnoreDataMember] public string Salt { get; set; }
                      [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string Token { get; set; } }
public class Hidden2 { public int Id { get; set; } [JsonIgnore] public string PasswordHash { get; set; } }
public class Db2 : DbContext { public DbSet<Hidden2> Hidden2s { get; set; } }
[ApiController]
public class ADocController : ControllerBase
{
    private readonly Db db;
    private readonly IAuthorizationService authz;
    private readonly UserManager<IdentityUser> userManager;
    [HttpGet("n/{id}")] public async Task<IActionResult> NullOnly(int id)
    { var o = db.Docs.Find(id); if (o == null) return NotFound(); var r = await authz.AuthorizeAsync(User, o, "p"); if (r.Succeeded) { Audit(); } return Ok(o); }
    [HttpGet("p1/{id}")] public async Task<IActionResult> Pos(int id)
    { var o = db.Docs.Find(id); var r = await authz.AuthorizeAsync(User, o, "p"); if (r.Succeeded) { return Ok(o); } return Forbid(); }
    [HttpGet("p2/{id}")] public async Task<IActionResult> Neg(int id)
    { var o = db.Docs.Find(id); var r = await authz.AuthorizeAsync(User, o, "p"); if (r.Succeeded == false) return Forbid(); return Ok(o); }
    [HttpGet("p3/{id}")] public async Task<IActionResult> Else(int id)
    { var o = db.Docs.Find(id); var r = await authz.AuthorizeAsync(User, o, "p"); if (r.Succeeded) { Audit(); } else { return Forbid(); } return Ok(o); }
    [HttpGet("p4/{id}")] public async Task<IActionResult> Inline(int id)
    { var o = db.Docs.Find(id); if (!(await authz.AuthorizeAsync(User, o, "p")).Succeeded) return Forbid(); return Ok(o); }
    [HttpGet("um/{id}")] public IActionResult Um(int id)
    { var o = db.Docs.Find(id); if (o.OwnerId != userManager.GetUserId(User)) return Forbid(); return Ok(o); }
    [HttpPost("bf")] public IActionResult BindBody([Bind("Total")][FromBody] Doc d) { db.Update(d); return Ok(); }
    [HttpPost("ba")] public IActionResult BindApi([Bind("Total")] Doc d) { db.Update(d); return Ok(); }
    [HttpGet("ak")] public IActionResult Keys() => Ok(db.Accts.ToList());
    [HttpGet("sk")] public IActionResult Sk() => Ok(db.Keys.ToList());
    [HttpGet("hd")] public IActionResult Hd() => Ok(db.Hiddens.ToList());
    [HttpGet("u1/{id}")] public async Task<IActionResult> Unknown(int id)
    { var o = db.Docs.Find(id); var r = await authz.AuthorizeAsync(User, o, "p"); if (r == null) return NotFound(); return Ok(o); }
    [HttpGet("u2/{id}")] public async Task<IActionResult> CondFollow(int id, bool flag)
    { var o = db.Docs.Find(id); var r = await authz.AuthorizeAsync(User, o, "p"); if (r.Succeeded) return Ok(o); if (flag) return Forbid(); return Ok(o); }
    [HttpGet("u3/{id}")] public async Task<IActionResult> CondElse(int id, bool flag)
    { var o = db.Docs.Find(id); var r = await authz.AuthorizeAsync(User, o, "p"); if (r.Succeeded) { Audit(); } else { if (flag) return Forbid(); } return Ok(o); }
    private void Audit() { }
}
public class FormBodyController : Controller
{
    private readonly Db db;
    [HttpPost("fb")] public IActionResult FromBodyBind([Bind("Total")][FromBody] Doc d) { db.Update(d); return Ok(); }
    [HttpPost("fi")] public IActionResult FormInclude([Bind("Total")] Doc d) { db.Update(d); return Ok(); }
}
'''

_LEGACY_SHAPE = '''
using System.Web.Mvc;
namespace Legacy.Controllers
{
    public class Doc { public int Id { get; set; } public string OwnerId { get; set; } }
    public class LegacyDb : System.Data.Entity.DbContext { public System.Data.Entity.DbSet<Doc> Docs { get; set; } }
    public class DocsController : Controller
    {
        private readonly LegacyDb db = new LegacyDb();
        public ActionResult Show(int id)
        {
            var d = db.Docs.Find(id);
            if (d.OwnerId != User.FindFirstValue("sub")) return new HttpUnauthorizedResult();
            return View(d);
        }
    }
}
'''

_MODERN_SHAPE = '''
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
public class MDoc { public int Id { get; set; } public string OwnerId { get; set; } }
public class MDb : DbContext { public DbSet<MDoc> Docs { get; set; } }
[ApiController]
public class DocsController : ControllerBase
{
    private readonly MDb db;
    [HttpGet("docs/{id}")] public IActionResult Show(int id)
    {
        var d = db.Docs.Find(id);
        if (d.OwnerId != User.FindFirstValue("sub")) return Forbid();
        return Ok(1);
    }
}
'''


def _scan(tmp_path, monkeypatch, files):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    (tmp_path / "A.csproj").write_text(_CSPROJ)
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    project._CACHE.clear()
    project.prepare(tmp_path, True)
    model = project.get_model(tmp_path, "dotnet")
    return model, routes_core.discover_all(model)


def test_authz_result_must_gate_a_rejection(tmp_path, monkeypatch):
    model, refs = _scan(tmp_path, monkeypatch, {"A.cs": _FIX2})
    idor = on(rules_object.check(model, refs), "DNL-AUTHZ-005")
    # A null-check NotFound next to an AuthorizeAsync whose failure rejects nothing is no guard.
    assert {"ADocController.NullOnly", "ADocController.Unknown", "ADocController.CondFollow",
            "ADocController.CondElse"} <= idor
    for ok in ("Pos", "Neg", "Else", "Inline", "Um"):
        assert f"ADocController.{ok}" not in idor, ok
    project._CACHE.clear()


def test_bind_rules_on_json_and_api_controllers(tmp_path, monkeypatch):
    model, refs = _scan(tmp_path, monkeypatch, {"A.cs": _FIX2})
    over = on(rules_object.check(model, refs), "DNL-AUTHZ-006")
    assert {"ADocController.BindBody", "ADocController.BindApi", "FormBodyController.FromBodyBind"} <= over
    # Plain form binding on a non-ApiController honours [Bind(Include)].
    assert "FormBodyController.FormInclude" not in over
    project._CACHE.clear()


def test_sensitive_variants_and_json_ignore(tmp_path, monkeypatch):
    model, refs = _scan(tmp_path, monkeypatch, {"A.cs": _FIX2})
    exposed = on(rules_object.check(model, refs), "DNL-AUTHZ-007")
    # ApiKeys (plural) and SecretKey are sensitive; Hiddens still has a Token that is only ignored when
    # null (JsonIgnore with a Condition other than Always), so it is exposed through that member.
    assert {"ADocController.Keys", "ADocController.Sk", "ADocController.Hd"} <= exposed
    sens = rules_object._sensitive_entities(model, {"Hidden", "Hidden2"})
    assert sens == {"Hidden"}
    project._CACHE.clear()


def test_identity_user_is_sensitive_and_entity(app):
    model = app[0]
    assert "ApplicationUser" in rules_object.entity_types(model)
    assert "ApplicationUser" in rules_object._sensitive_entities(model, {"ApplicationUser", "Order"})
    assert "Order" not in rules_object._sensitive_entities(model, {"Order"})


def test_one_route_failure_is_isolated(tmp_path, monkeypatch):
    model, refs = _scan(tmp_path, monkeypatch, {"A.cs": _FIX2})
    real = rules_object._idor

    def boom(model_, summaries, ref, entities):
        if ref.route.handler_name == "ADocController.Pos":
            raise RuntimeError("synthetic")
        return real(model_, summaries, ref, entities)

    monkeypatch.setattr(rules_object, "_idor", boom)
    fs = rules_object.check(model, refs)
    assert any("ADocController.Pos" in n and "synthetic" in n for n in model.notes)
    assert "ADocController.NullOnly" in on(fs, "DNL-AUTHZ-005")
    assert rules_object._MODE["core"] is False
    project._CACHE.clear()


def test_legacy_result_unchanged_in_mixed_solution(tmp_path, monkeypatch):
    root = tmp_path / "sol"
    shutil.copytree(Path(__file__).parent / "fixtures" / "aspnetcore" / "mixed_solution", root)
    (root / "Legacy" / "Controllers" / "DocsController.cs").write_text(_LEGACY_SHAPE)
    proj = root / "Legacy" / "Legacy.csproj"
    proj.write_text(proj.read_text().replace(
        '<Compile Include="Controllers\\HomeController.cs" />',
        '<Compile Include="Controllers\\HomeController.cs" /><Compile Include="Controllers\\DocsController.cs" />'))
    (root / "Modern" / "Controllers" / "DocsController.cs").write_text(_MODERN_SHAPE)
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    project._CACHE.clear()
    res = enumerator.enumerate_target(root, allow_degraded=True)
    by_lang = {(r.language, f.route.handler_name) for r in res for f in r.findings
               if f.check_id == "DNL-AUTHZ-005" and f.route is not None}
    # Legacy MVC keeps its tables: User.FindFirstValue is not an ownership signal there, so it reports.
    assert ("dotnet_legacy", "DocsController.Show") in by_lang
    # The same shape in the Core project is an ownership check.
    assert ("dotnet", "DocsController.Show") not in by_lang
    project._CACHE.clear()


_IDENT = '''
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
public class ApplicationUser : IdentityUser { }
public class ApplicationRole : IdentityRole { }
public class AppIdentityDb
    : IdentityDbContext<
        ApplicationUser,
        ApplicationRole,
        string>
{
}
public class Salted { public int Id { get; set; } public string Salt { get; set; } }
public class Stamped { public int Id { get; set; } public string SecurityStamp { get; set; } }
public class Tokened { public int Id { get; set; } public string Tokens { get; set; } }
public class Plain { public int Id { get; set; } public string Name { get; set; } }
public class Db : DbContext { public DbSet<Salted> Salteds { get; set; } public DbSet<Stamped> Stampeds { get; set; }
                              public DbSet<Tokened> Tokeneds { get; set; } public DbSet<Plain> Plains { get; set; } }
[ApiController]
public class RolesController : ControllerBase
{
    private readonly Db db;
    private readonly RoleManager<ApplicationRole> roles;
    [HttpGet("r")] public async Task<IActionResult> R(string name) { var role = await roles.FindByNameAsync(name); return Ok(role); }
    [HttpGet("s")] public IActionResult S() => Ok(db.Salteds.ToList());
    [HttpGet("t")] public IActionResult T() => Ok(db.Stampeds.ToList());
    [HttpGet("k")] public IActionResult K() => Ok(db.Tokeneds.ToList());
    [HttpGet("p")] public IActionResult P() => Ok(db.Plains.ToList());
}
'''


def test_identity_multiline_bases_and_member_variants(tmp_path, monkeypatch):
    model, refs = _scan(tmp_path, monkeypatch, {"A.cs": _IDENT})
    assert {"ApplicationUser", "ApplicationRole"} <= rules_object.entity_types(model)
    assert {"ApplicationUser", "ApplicationRole"} <= rules_object._sensitive_entities(
        model, rules_object.entity_types(model))
    exposed = on(rules_object.check(model, refs), "DNL-AUTHZ-007")
    assert {"RolesController.R", "RolesController.S", "RolesController.T", "RolesController.K"} <= exposed
    assert "RolesController.P" not in exposed
    project._CACHE.clear()
