"""Three-state ASP.NET Core authorization over the synthetic controllers_api, razor_app and
minimal_api fixtures, plus tmp-copy variants for each mechanism."""
import shutil
from pathlib import Path

import pytest

from checks.dnl import auth_core, helper, project
from checks.dnl.auth_core import ANONYMOUS, PROTECTED, UNKNOWN, UNPROTECTED, middleware_issue, never_denying_handlers, resolve
from checks.dnl.pipeline import pipeline_for
from checks.dnl.routes_core import discover_all

FX = Path(__file__).parent / "fixtures" / "aspnetcore"
CONTROLLERS, RAZOR, MINIMAL = FX / "controllers_api", FX / "razor_app", FX / "minimal_api"
FALLBACK_AUTHED = "o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();"


class App:
    def __init__(self, root: Path, allow_degraded: bool = False):
        project._CACHE.clear()
        project.prepare(root, allow_degraded)
        self.model = project.get_model(root, "dotnet")
        self.refs = discover_all(self.model)

    def ref(self, key: str):
        hits = [r for r in self.refs if r.route.handler_name == key or r.route.path == key]
        assert len(hits) == 1, (key, [r.route.handler_name for r in self.refs])
        return hits[0]

    def pipe(self, ref=None):
        return pipeline_for(self.model, ref.project if ref is not None else self.model.projects[0])

    def __call__(self, key: str):
        ref = self.ref(key)
        return resolve(self.model, ref, self.pipe(ref))

    def states(self):
        return {(r.route.handler_name, r.route.path, tuple(r.route.methods)):
                (a.state, a.source, tuple(a.policies), tuple(a.roles))
                for r in self.refs for a in [resolve(self.model, r, self.pipe(r))]}


def copy(src: Path, tmp_path: Path, edits: dict | None = None, extra: dict | None = None) -> Path:
    root = tmp_path / "app"
    shutil.copytree(src, root)
    for rel, (old, new) in (edits or {}).items():
        p = root / rel
        text = p.read_text()
        assert old in text, (rel, old)
        p.write_text(text.replace(old, new))
    for rel, text in (extra or {}).items():
        (root / rel).write_text(text)
    return root


@pytest.fixture(scope="module")
def ctrl(roslyn_helper):
    return App(CONTROLLERS)


@pytest.fixture(scope="module")
def razor(roslyn_helper):
    return App(RAZOR)


@pytest.fixture(scope="module")
def minimal(roslyn_helper):
    return App(MINIMAL)


# -- controllers_api -----------------------------------------------------------------------------

def test_controller_states(ctrl):
    a = ctrl("OrdersController.Get")
    assert (a.state, a.source) == (PROTECTED, "attribute:Authorize")
    d = ctrl("OrdersController.Delete")
    assert d.state == PROTECTED and d.policies == ["Admin"] and d.roles == ["Admin"]
    assert ctrl("OrdersController.Public").state == ANONYMOUS
    assert ctrl("HealthController.Get").state == UNPROTECTED
    r = ctrl("ReportsController.List")
    assert r.state == UNKNOWN and any("Missing" in x for x in r.reasons)
    au = ctrl("AuditController.Log")
    assert au.state == UNPROTECTED and any("Audit" in n and "never denies" in n for n in au.notes)
    inv = ctrl("InvoicesController.Create")
    assert (inv.state, inv.source) == (PROTECTED, "base:BaseApiController")


def test_never_denying_handlers_and_policies(ctrl):
    assert [t.name for t in never_denying_handlers(ctrl.model)] == ["AuditHandler"]
    pols = auth_core.policies(ctrl.model, ctrl.pipe())
    assert pols["Admin"].roles == ["Admin"] and not pols["Admin"].never_denies
    assert pols["Audit"].never_denies


def test_allowanonymous_beats_authorize(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Controllers/OrdersController.cs": ("[Authorize]\npublic class", "[Authorize]\n[AllowAnonymous]\npublic class")})
    app = App(root)
    assert app("OrdersController.Delete").state == ANONYMOUS


def test_global_authorize_filter(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": ("AddControllers();", "AddControllers(o => o.Filters.Add(new AuthorizeFilter()));")})
    a = App(root)("HealthController.Get")
    assert (a.state, a.source) == (PROTECTED, "filter:AuthorizeFilter")


def test_global_filter_under_unparseable_condition_is_unknown(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": (
        "AddControllers();", "AddControllers(o => { if (Flags.On) o.Filters.Add(new AuthorizeFilter()); });")})
    a = App(root)("HealthController.Get")
    assert a.state == UNKNOWN and a.reasons


def _fallback_root(tmp_path, stmt):
    return copy(CONTROLLERS, tmp_path, {"Program.cs": ('o.AddPolicy("Admin"', f'{stmt}\n    o.AddPolicy("Admin"')})


def test_fallback_policy(roslyn_helper, tmp_path):
    a = App(_fallback_root(tmp_path, FALLBACK_AUTHED))("HealthController.Get")
    assert (a.state, a.source) == (PROTECTED, "fallback policy")


def test_fallback_never_denies(roslyn_helper, tmp_path):
    stmt = "o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAssertion(_ => true).Build();"
    a = App(_fallback_root(tmp_path, stmt))("HealthController.Get")
    assert a.state == UNPROTECTED and any("never denies" in n for n in a.notes)


def test_fallback_null_is_no_fallback(roslyn_helper, tmp_path):
    a = App(_fallback_root(tmp_path, "o.FallbackPolicy = null;"))("HealthController.Get")
    assert a.state == UNPROTECTED


def test_dev_only_registration_is_absent(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": (
        "var app = builder.Build();",
        f"if (builder.Environment.IsDevelopment()) {{ builder.Services.AddAuthorization(o => {{ {FALLBACK_AUTHED} }}); }}\n"
        "var app = builder.Build();")})
    assert App(root)("HealthController.Get").state == UNPROTECTED


def test_dev_only_if_inside_lambda_is_absent(roslyn_helper, tmp_path):
    stmt = f"if (builder.Environment.IsDevelopment()) {{ {FALLBACK_AUTHED} }}"
    assert App(_fallback_root(tmp_path, stmt))("HealthController.Get").state == UNPROTECTED


def test_unparseable_condition_in_lambda_never_protects(roslyn_helper, tmp_path):
    stmt = f"if (Flags.On) {{ {FALLBACK_AUTHED} }}"
    a = App(_fallback_root(tmp_path, stmt))("HealthController.Get")
    assert a.state == UNKNOWN and a.reasons


def test_default_policy_never_denies_makes_plain_authorize_unprotected(roslyn_helper, tmp_path):
    stmt = "o.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAssertion(_ => true).Build();"
    app = App(_fallback_root(tmp_path, stmt))
    a = app("OrdersController.Get")
    assert a.state == UNPROTECTED and any("DefaultPolicy never denies" in n for n in a.notes)
    # A role requirement does not use the default policy.
    assert app("OrdersController.Delete").state == PROTECTED


def test_policy_provider_makes_policies_unknown(roslyn_helper, tmp_path):
    # Fix round 1 (I9, controller ruling R22): a custom provider also supplies the default and fallback
    # policy, so plain [Authorize] and the policy-named routes are UNKNOWN too.
    root = copy(CONTROLLERS, tmp_path,
                {"Program.cs": ("var app = builder.Build();",
                                "builder.Services.AddSingleton<IAuthorizationPolicyProvider, MyProvider>();\nvar app = builder.Build();")},
                {"MyProvider.cs": "public class MyProvider { }\n"})
    app = App(root)
    for h in ("OrdersController.Delete", "OrdersController.Get"):
        d = app(h)
        assert d.state == UNKNOWN and any("IAuthorizationPolicyProvider" in r for r in d.reasons), h
    a = app("AuditController.Log")
    assert a.state == UNKNOWN and any("IAuthorizationPolicyProvider" in r for r in a.reasons)
    assert app("HealthController.Get").state == UNKNOWN


def test_unresolved_extension_is_unknown_for_unprotected_routes(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": ("var app = builder.Build();",
                                                       "builder.Services.AddCompanyAuth();\nvar app = builder.Build();")})
    app = App(root)
    h = app("HealthController.Get")
    assert h.state == UNKNOWN and any("AddCompanyAuth" in r for r in h.reasons)
    assert app("OrdersController.Get").state == PROTECTED


def test_custom_filter_attribute(roslyn_helper, tmp_path):
    filt = ("using Microsoft.AspNetCore.Mvc.Filters;\n\npublic class DenyAttribute : System.Attribute, IAuthorizationFilter\n{\n"
            "    public void OnAuthorization(AuthorizationFilterContext context) { context.Result = new Microsoft.AspNetCore.Mvc.ForbidResult(); }\n}\n"
            "public class NoopAttribute : System.Attribute, IAuthorizationFilter\n{\n"
            "    public void OnAuthorization(AuthorizationFilterContext context) { }\n}\n")
    root = copy(CONTROLLERS, tmp_path,
                {"Controllers/HealthController.cs": ("[HttpGet]\n    public IActionResult Get", "[HttpGet]\n    [Deny]\n    public IActionResult Get"),
                 "Controllers/HomeController.cs": ("public IActionResult Index", "[Noop]\n    public IActionResult Index")},
                {"Filters.cs": filt})
    app = App(root)
    assert app("HealthController.Get").state == PROTECTED
    h = app("HomeController.Index")
    assert h.state == UNPROTECTED and any("never sets context.Result" in n for n in h.notes)


def test_derived_attributes_roles_and_constants(roslyn_helper, tmp_path):
    attrs = ('using Microsoft.AspNetCore.Authorization;\n\npublic static class Names { public const string Admin = "Admin"; }\n'
             'public class StaffAttribute : AuthorizeAttribute { public StaffAttribute() { Roles = "Staff"; } }\n'
             'public class SeniorStaffAttribute : StaffAttribute { }\n'
             'public class PolicyAttr : AuthorizeAttribute { public PolicyAttr(string p) { Policy = p; } }\n')
    root = copy(CONTROLLERS, tmp_path,
                {"Controllers/HealthController.cs": ("[HttpGet]\n    public IActionResult Get", "[HttpGet]\n    [SeniorStaff]\n    public IActionResult Get"),
                 "Controllers/HomeController.cs": ("public IActionResult Index", '[PolicyAttr("Nope")]\n    public IActionResult Index'),
                 "Controllers/InvoicesController.cs": ("[HttpPost]", "[HttpPost]\n    [Authorize(Policy = Names.Admin)]")},
                {"Attrs.cs": attrs})
    app = App(root)
    h = app("HealthController.Get")
    assert (h.state, h.source) == (PROTECTED, "attribute:SeniorStaff") and h.roles == ["Staff"]
    assert app("HomeController.Index").state == UNKNOWN
    i = app("InvoicesController.Create")
    assert i.state == PROTECTED and i.policies == ["Admin"]


def test_authorize_roles_attribute(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Controllers/HealthController.cs": (
        "[HttpGet]\n    public IActionResult Get", '[HttpGet]\n    [Authorize(Roles = "Ops,Dev")]\n    public IActionResult Get')})
    a = App(root)("HealthController.Get")
    assert a.state == PROTECTED and a.roles == ["Ops", "Dev"]


def test_global_authorize_filter_with_policy_name(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": (
        "AddControllers();", 'AddControllers().AddMvcOptions(o => o.Filters.Add(new AuthorizeFilter("Nope")));')})
    a = App(root)("HealthController.Get")
    assert a.state == UNKNOWN and any('"Nope"' in r for r in a.reasons)
    root2 = copy(CONTROLLERS, tmp_path / "b", {"Program.cs": (
        "AddControllers();", 'AddControllers().AddMvcOptions(o => o.Filters.Add(new AuthorizeFilter("Admin")));')})
    b = App(root2)("HealthController.Get")
    assert (b.state, b.source) == (PROTECTED, "filter:AuthorizeFilter")


def test_unknown_authorize_like_attribute(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Controllers/HealthController.cs": ("[HttpGet]\n    public IActionResult Get", "[HttpGet]\n    [RequirePermission(\"x\")]\n    public IActionResult Get")})
    a = App(root)("HealthController.Get")
    assert a.state == UNKNOWN and any("RequirePermission" in r for r in a.reasons)


def test_mvc_conventions_add_is_unknown(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": ("AddControllers();", "AddControllers(o => o.Conventions.Add(new MyConvention()));")})
    app = App(root)
    h = app("HealthController.Get")
    assert h.state == UNKNOWN and any("Conventions.Add" in r for r in h.reasons)
    # Fix round 1 (C5): an unanalysed convention could add an anonymous opt-out, so it blocks PROTECTED.
    o = app("OrdersController.Get")
    assert o.state == UNKNOWN and any("Conventions.Add" in r for r in o.reasons)


def test_map_controllers_require_authorization(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": ("app.MapControllers();", "app.MapControllers().RequireAuthorization();")})
    a = App(root)("HealthController.Get")
    assert (a.state, a.source) == (PROTECTED, "MapControllers().RequireAuthorization")


# -- razor_app -----------------------------------------------------------------------------------

def test_razor_states(razor):
    for h in ("UsersModel.OnGet", "UsersModel.OnPostDeleteAsync"):
        a = razor(h)
        assert (a.state, a.source) == (PROTECTED, "convention:AuthorizeFolder(/Admin)")
    assert razor("LoginModel.OnGet").state == ANONYMOUS
    e = razor("EditModel.OnPostSave")
    assert e.state == UNPROTECTED
    assert "[Authorize] on handler method OnPostSave is ignored by Razor Pages" in e.notes
    c = razor("CartModel.OnGet")
    assert (c.state, c.source) == (PROTECTED, "attribute:Authorize")
    assert razor("IndexModel.OnGet").state == UNPROTECTED


def test_orphan_page_folder_convention_and_unknown(roslyn_helper, tmp_path):
    root = copy(RAZOR, tmp_path)
    shutil.copy(root / "Pages" / "Orphan.cshtml", root / "Pages" / "Admin" / "Orphan.cshtml")
    app = App(root)
    refs = [r for r in app.refs if r.route.meta.get("page") in ("/Orphan", "/Admin/Orphan")]
    got = {r.route.meta["page"]: resolve(app.model, r, app.pipe(r)) for r in refs}
    # Fix round 1 (R21): the unseen page model could carry [AllowAnonymous], so the folder convention
    # alone does not make the page PROTECTED.
    assert got["/Admin/Orphan"].state == UNKNOWN and any("not found" in r for r in got["/Admin/Orphan"].reasons)
    assert got["/Orphan"].state == UNKNOWN and any("not found" in r for r in got["/Orphan"].reasons)


def test_razor_folder_match_is_by_segment_and_case_insensitive(roslyn_helper, tmp_path):
    root = copy(RAZOR, tmp_path, {"Program.cs": ('AuthorizeFolder("/Admin")', 'AuthorizeFolder("/adm")')})
    assert App(root)("UsersModel.OnGet").state == UNPROTECTED
    root2 = copy(RAZOR, tmp_path / "b", {"Program.cs": ('AuthorizeFolder("/Admin")', 'AuthorizeFolder("/aDMIN/")')})
    assert App(root2)("UsersModel.OnGet").state == PROTECTED


def test_razor_authorize_page_and_policy_convention(roslyn_helper, tmp_path):
    root = copy(RAZOR, tmp_path, {"Program.cs": ('o.Conventions.AllowAnonymousToPage("/Admin/Login");',
                                                 'o.Conventions.AllowAnonymousToPage("/Admin/Login");\n    o.Conventions.AuthorizePage("/Privacy", "Nope");\n    o.Conventions.AuthorizeAreaFolder("Shop", "/");')})
    app = App(root)
    p = app("PrivacyModel")
    assert p.state == UNKNOWN and any("Nope" in r for r in p.reasons)


def test_razor_anonymous_convention_under_unparseable_condition_blocks_protection(roslyn_helper, tmp_path):
    root = copy(RAZOR, tmp_path, {"Program.cs": ('o.Conventions.AllowAnonymousToPage("/Admin/Login");',
                                                 'o.Conventions.AllowAnonymousToPage("/Admin/Login");\n    if (Flags.On) o.Conventions.AllowAnonymousToFolder("/Admin");')})
    a = App(root)("UsersModel.OnGet")
    assert a.state == UNKNOWN


def test_razor_conventions_add_is_unknown(roslyn_helper, tmp_path):
    root = copy(RAZOR, tmp_path, {"Program.cs": ('o.Conventions.AllowAnonymousToPage("/Admin/Login");',
                                                 'o.Conventions.AllowAnonymousToPage("/Admin/Login");\n    o.Conventions.Add(new MyPageConvention());')})
    app = App(root)
    assert app("IndexModel.OnGet").state == UNKNOWN
    # Fix round 1 (C5): an unanalysed page convention could opt the folder out, so it blocks PROTECTED.
    assert app("UsersModel.OnGet").state == UNKNOWN


# -- minimal_api ---------------------------------------------------------------------------------

def test_minimal_states(minimal):
    assert minimal("/").state == UNPROTECTED
    a = minimal("/api/orders/{id}")
    assert (a.state, a.source) == (PROTECTED, "group:/api RequireAuthorization")
    assert minimal("/api/status").state == ANONYMOUS
    adm = minimal("/api/admin/users/{id}")
    assert adm.state == PROTECTED and adm.policies == ["AdminOnly"]
    assert minimal("/v2/users").state == UNPROTECTED
    au = minimal("/audit/a")
    assert au.state == UNKNOWN and au.reasons
    o = minimal("/orphan")
    assert o.state == UNKNOWN and any("caller" in r for r in o.reasons)
    chat = minimal("/chat")
    assert (chat.state, chat.source) == (PROTECTED, "attribute:Authorize")
    assert minimal("/healthz").state == UNPROTECTED
    sw = minimal("/swagger")
    assert sw.state == UNPROTECTED and sw.source == "middleware (not endpoint-routed; authorization does not apply)"


def _minimal_with(tmp_path, line):
    return copy(MINIMAL, tmp_path, {"Program.cs": ("var app = builder.Build();", f"{line}\nvar app = builder.Build();")})


def test_orphan_with_fallback_is_unknown(roslyn_helper, tmp_path):
    root = copy(MINIMAL, tmp_path, {"Program.cs": (
        "builder.Services.AddSignalR();",
        f"builder.Services.AddAuthorization(o => {{ {FALLBACK_AUTHED} }});\nbuilder.Services.AddSignalR();")})
    app = App(root)
    # Fix round 1 (R21): a caller that is not visible can carry .AllowAnonymous(), so the fallback
    # policy alone does not make /orphan and /audit/a PROTECTED.
    for path in ("/orphan", "/audit/a"):
        a = app(path)
        assert a.state == UNKNOWN and a.reasons, path
    assert app("/").state == PROTECTED


def test_unresolved_extensions(roslyn_helper, tmp_path):
    app = App(_minimal_with(tmp_path, "builder.Services.AddDbContext<Db>();\nbuilder.Services.AddSwaggerGen();"))
    assert app("/").state == UNPROTECTED
    root = copy(MINIMAL, tmp_path / "b", {"Program.cs": ("var app = builder.Build();", "builder.Services.AddCompanyAuth();\nvar app = builder.Build();")})
    app2 = App(root)
    u = app2("/")
    assert u.state == UNKNOWN and any("AddCompanyAuth" in r for r in u.reasons)
    assert app2("/api/orders/{id}").state == PROTECTED


def test_endpoint_filter_is_unknown(roslyn_helper, tmp_path):
    root = copy(MINIMAL, tmp_path, {"Program.cs": ('app.MapGet("/", () => "hello");', 'app.MapGet("/", () => "hello");\napp.MapGet("/f", () => 1).AddEndpointFilter<GateFilter>();')})
    a = App(root)("/f")
    assert a.state == UNKNOWN and any("AddEndpointFilter" in r for r in a.reasons)


def test_group_endpoint_filter_is_unknown_for_its_routes_only(roslyn_helper, tmp_path):
    root = copy(MINIMAL, tmp_path, {"Program.cs": ('app.MapGroup("/v2").MapUserEndpoints();', 'app.MapGroup("/v2").AddEndpointFilter<GateFilter>().MapUserEndpoints();')})
    app = App(root)
    assert app("/v2/users").state == UNKNOWN
    assert app("/").state == UNPROTECTED


def test_lambda_attributes_and_conditional_calls(roslyn_helper, tmp_path):
    root = copy(MINIMAL, tmp_path, {"Program.cs": ('app.MapGet("/", () => "hello");', (
        'app.MapGet("/", [AllowAnonymous] () => "hello");\n'
        'app.MapGet("/secure", [Authorize] () => 1);\n'
        'app.MapGet("/wm", () => 1).WithMetadata(new AuthorizeAttribute());\n'
        'var cond = app.MapGroup("/cond");\nif (Flags.On) cond.RequireAuthorization();\ncond.MapGet("/x", () => 1);'))})
    app = App(root)
    assert app("/").state == ANONYMOUS
    assert app("/secure").state == PROTECTED
    assert app("/wm").state == PROTECTED
    c = app("/cond/x")
    assert c.state == UNKNOWN and any("conditionally" in r for r in c.reasons)


def test_policy_defined_via_authorization_builder(roslyn_helper, tmp_path):
    root = copy(MINIMAL, tmp_path, {"Program.cs": ('builder.Services.AddSignalR();', (
        'builder.Services.AddAuthorizationBuilder().AddPolicy("Open", p => p.RequireAssertion(_ => true)).AddPolicy("Staff", p => p.RequireRole("Staff"));\n'
        'builder.Services.AddSignalR();')),
        })
    text = (root / "Program.cs").read_text().replace('app.MapGet("/", () => "hello");',
                                                     'app.MapGet("/", () => "hello");\napp.MapGet("/open", () => 1).RequireAuthorization("Open");\napp.MapGet("/staff", () => 1).RequireAuthorization("Staff");\napp.MapGet("/gone", () => 1).RequireAuthorization("Gone");')
    (root / "Program.cs").write_text(text)
    app = App(root)
    o = app("/open")
    assert o.state == UNPROTECTED and any("never denies" in n for n in o.notes)
    s = app("/staff")
    assert s.state == PROTECTED and s.roles == ["Staff"] and s.policies == ["Staff"]
    g = app("/gone")
    assert g.state == UNKNOWN and any('"Gone"' in r and "not defined" in r for r in g.reasons)


# -- middleware ----------------------------------------------------------------------------------

def _pipe_issue(root):
    project._CACHE.clear()
    project.prepare(root, False)
    model = project.get_model(root, "dotnet")
    return middleware_issue(pipeline_for(model, model.projects[0]))


def test_middleware_issue(roslyn_helper, tmp_path):
    issue = _pipe_issue(FX / "pipelines" / "startup")
    assert issue is not None and "UseAuthorization" in issue[0] and "UseRouting" in issue[0] and issue[3] is False
    assert _pipe_issue(FX / "pipelines" / "minimal") is None
    root = copy(FX / "pipelines" / "minimal", tmp_path / "a", {"App.csproj": ("net8.0", "net6.0"), "Program.cs": ("app.UseAuthorization();", "")})
    issue = _pipe_issue(root)
    assert issue is not None and "UseAuthorization" in issue[0]
    root = copy(FX / "pipelines" / "startup", tmp_path / "b", {"Startup.Services.cs": (
        "services.AddControllers();", "services.AddControllers();\n        services.Configure<RouteOptions>(o => o.SuppressCheckForUnhandledSecurityMetadata = true);")})
    issue = _pipe_issue(root)
    assert issue is not None and issue[3] is True


def test_suppressed_check_downgrades_endpoint_metadata(roslyn_helper, tmp_path):
    root = copy(FX / "pipelines" / "startup", tmp_path, {"Startup.Services.cs": (
        "services.AddControllers();", "services.AddControllers();\n        services.Configure<RouteOptions>(o => o.SuppressCheckForUnhandledSecurityMetadata = true);")},
        {"SecureController.cs": ("using Microsoft.AspNetCore.Authorization;\nusing Microsoft.AspNetCore.Mvc;\n\n[Authorize]\n[Route(\"secure\")]\n"
                                 "public class SecureController : ControllerBase\n{\n    [HttpGet]\n    public IActionResult Get() => Ok();\n}\n")})
    app = App(root)
    a = app("SecureController.Get")
    assert a.state == UNPROTECTED and any("not enforced" in n for n in a.notes)
    # Without the flag the broken pipeline fails closed: the route stays protected.
    root2 = copy(FX / "pipelines" / "startup", tmp_path / "b", None,
                 {"SecureController.cs": (root / "SecureController.cs").read_text()})
    assert App(root2)("SecureController.Get").state == PROTECTED


# -- degraded mode -------------------------------------------------------------------------------

def test_degraded_auth_matches(roslyn_helper, monkeypatch):
    full = {n: App(root).states() for n, root in (("ctrl", CONTROLLERS), ("razor", RAZOR), ("minimal", MINIMAL))}
    monkeypatch.setattr(helper, "find_helper", lambda *a, **k: None)
    monkeypatch.setattr(helper, "sdk_available", lambda *a, **k: False)
    for n, root in (("ctrl", CONTROLLERS), ("razor", RAZOR), ("minimal", MINIMAL)):
        assert App(root, True).states() == full[n], n


# -- fix round 1 -----------------------------------------------------------------------------------

STARTUP = FX / "pipelines" / "startup"
PLAIN_CONTROLLER = ("using Microsoft.AspNetCore.Mvc;\n\n[Route(\"plain\")]\npublic class PlainController : ControllerBase\n"
                    "{\n    [HttpGet]\n    public IActionResult Get() => Ok();\n}\n")
SECURE_CONTROLLER = ("using Microsoft.AspNetCore.Authorization;\nusing Microsoft.AspNetCore.Mvc;\n\n[Authorize]\n[Route(\"secure\")]\n"
                     "public class SecureController : ControllerBase\n{\n    [HttpGet]\n    public IActionResult Get() => Ok();\n}\n")
SUPPRESS = "services.Configure<RouteOptions>(o => o.SuppressCheckForUnhandledSecurityMetadata = true);"


def test_c1_fallback_only_route_with_unresolved_extension_is_unknown(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": ("o.AddPolicy(\"Admin\"", f"{FALLBACK_AUTHED}\n    o.AddPolicy(\"Admin\"")})
    assert App(root)("HealthController.Get").state == PROTECTED
    root2 = copy(CONTROLLERS, tmp_path / "b", {"Program.cs": (
        "o.AddPolicy(\"Admin\"", f"{FALLBACK_AUTHED}\n    o.AddPolicy(\"Admin\""),
        })
    prog = root2 / "Program.cs"
    prog.write_text(prog.read_text().replace("var app = builder.Build();", "builder.Services.AddCompanyAuth();\nvar app = builder.Build();"))
    a = App(root2)("HealthController.Get")
    assert a.state == UNKNOWN and any("AddCompanyAuth" in r for r in a.reasons)


def test_c1_fallback_with_method_group_options_and_provider_is_unknown(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": ("AddControllers();", "AddControllers(ConfigureMvc);")})
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace("o.AddPolicy(\"Admin\"", f"{FALLBACK_AUTHED}\n    o.AddPolicy(\"Admin\""))
    a = App(root)("HealthController.Get")
    assert a.state == UNKNOWN and any("ConfigureMvc" in r for r in a.reasons)
    root2 = copy(CONTROLLERS, tmp_path / "b", {"Program.cs": ("var app = builder.Build();",
                 "builder.Services.AddSingleton<IAuthorizationPolicyProvider, MyProvider>();\nvar app = builder.Build();")},
                 {"MyProvider.cs": "public class MyProvider { }\n"})
    prog = root2 / "Program.cs"
    prog.write_text(prog.read_text().replace("o.AddPolicy(\"Admin\"", f"{FALLBACK_AUTHED}\n    o.AddPolicy(\"Admin\""))
    assert App(root2)("HealthController.Get").state == UNKNOWN


def test_c2_razor_attribute_directives(roslyn_helper, tmp_path):
    root = copy(RAZOR, tmp_path)
    users = root / "Pages" / "Admin" / "Users.cshtml"
    users.write_text(users.read_text().replace("@model UsersModel", "@model UsersModel\n@attribute [AllowAnonymous]"))
    priv = root / "Pages" / "Privacy.cshtml"
    priv.write_text(priv.read_text().replace("@model PrivacyModel", "@model PrivacyModel\n@attribute [Authorize]"))
    app = App(root)
    u = app("UsersModel.OnGet")
    assert u.state == ANONYMOUS and "AllowAnonymous" in u.source
    p = app("PrivacyModel")
    assert p.state == PROTECTED and "Authorize" in p.source


def test_c2_view_imports_attribute_and_unparseable_directive(roslyn_helper, tmp_path):
    root = copy(RAZOR, tmp_path)
    imp = root / "Pages" / "Admin" / "_ViewImports.cshtml"
    imp.write_text("@attribute [AllowAnonymous]\n")
    app = App(root)
    assert app("UsersModel.OnGet").state == ANONYMOUS
    root2 = copy(RAZOR, tmp_path / "b")
    users = root2 / "Pages" / "Admin" / "Users.cshtml"
    users.write_text(users.read_text().replace("@model UsersModel", "@model UsersModel\n@attribute Policies.Unreadable"))
    u = App(root2)("UsersModel.OnGet")
    assert u.state == UNKNOWN and any("@attribute" in r for r in u.reasons)


def test_c3_null_guard_throw_does_not_make_a_filter_protective(roslyn_helper, tmp_path):
    filt = ("using Microsoft.AspNetCore.Mvc.Filters;\n\npublic class GuardAttribute : System.Attribute, IAuthorizationFilter\n{\n"
            "    public void OnAuthorization(AuthorizationFilterContext context)\n    {\n"
            "        if (context == null) throw new System.ArgumentNullException(nameof(context));\n    }\n}\n")
    root = copy(CONTROLLERS, tmp_path,
                {"Controllers/HomeController.cs": ("public IActionResult Index", "[Guard]\n    public IActionResult Index")},
                {"Filters.cs": filt})
    a = App(root)("HomeController.Index")
    assert a.state == UNPROTECTED and any("never sets context.Result" in n for n in a.notes)


def test_c4_project_authorize_attribute_is_analysed(roslyn_helper, tmp_path):
    attr = "public class AuthorizeAttribute : Microsoft.AspNetCore.Mvc.Filters.ActionFilterAttribute\n{\n}\n"
    root = copy(CONTROLLERS, tmp_path,
                {"Controllers/HealthController.cs": ("[HttpGet]\n    public IActionResult Get", "[HttpGet]\n    [Authorize]\n    public IActionResult Get")},
                {"MyAuthorize.cs": attr})
    a = App(root)("HealthController.Get")
    assert a.state == UNKNOWN


def test_c5_unresolved_convention_after_require_authorization_blocks_protection(roslyn_helper, tmp_path):
    root = copy(MINIMAL, tmp_path, {"Program.cs": ('app.MapGet("/", () => "hello");',
                                                   'app.MapGet("/", () => "hello");\napp.MapGet("/p", () => 1).RequireAuthorization().AllowPublic();')})
    a = App(root)("/p")
    assert a.state == UNKNOWN and any("AllowPublic" in r for r in a.reasons)


def test_c6_iallowanonymous_attribute_and_anonymous_like_names(roslyn_helper, tmp_path):
    attrs = ("public class OpenAttribute : System.Attribute, Microsoft.AspNetCore.Authorization.IAllowAnonymous { }\n")
    root = copy(CONTROLLERS, tmp_path,
                {"Controllers/OrdersController.cs": ("[HttpGet(\"{id:int}\")]", "[HttpGet(\"{id:int}\")]\n    [Open]")},
                {"Open.cs": attrs})
    assert App(root)("OrdersController.Get").state == ANONYMOUS
    root2 = copy(CONTROLLERS, tmp_path / "b",
                 {"Controllers/OrdersController.cs": ("[HttpGet(\"{id:int}\")]", "[HttpGet(\"{id:int}\")]\n    [AllowPublic]")})
    a = App(root2)("OrdersController.Get")
    assert a.state == UNKNOWN and any("AllowPublic" in r for r in a.reasons)


def _startup_with(tmp_path, services_extra="", configure_edit=None, drop_company=True):
    edits = {"Startup.Services.cs": ("services.AddCompanyAuth();", services_extra if drop_company else "services.AddCompanyAuth();\n" + services_extra)}
    if configure_edit:
        edits["Startup.Pipeline.cs"] = configure_edit
    return copy(STARTUP, tmp_path, edits, {"PlainController.cs": PLAIN_CONTROLLER, "SecureController.cs": SECURE_CONTROLLER})


def test_i7_fallback_without_authorization_middleware_is_not_enforced(roslyn_helper, tmp_path):
    root = _startup_with(tmp_path, f"services.AddAuthorization(o => {{ {FALLBACK_AUTHED} }});")
    app = App(root)
    a = app("PlainController.Get")
    assert a.state == UNPROTECTED and any("not enforced" in n for n in a.notes)
    # An [Authorize] route in the same broken pipeline fails closed (500), it is not exposed.
    assert app("SecureController.Get").state == PROTECTED


def test_i8_handler_shapes(roslyn_helper, tmp_path):
    def handler(body):
        return ("using Microsoft.AspNetCore.Authorization;\n\npublic class AuditRequirement : IAuthorizationRequirement { }\n\n"
                "public class AuditHandler : AuthorizationHandler<AuditRequirement>\n{\n"
                "    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AuditRequirement requirement)\n    {\n"
                f"{body}\n        return Task.CompletedTask;\n    }}\n}}\n")
    cases = {
        "try { context.Succeed(requirement); } catch { }": UNKNOWN,
        "Helpers.Approve(context);": UNKNOWN,
        "if (context.User.IsInRole(\"Auditor\")) context.Succeed(requirement);": PROTECTED,
        "context.Fail();": PROTECTED,
        "context.Succeed(requirement);": UNPROTECTED,
    }
    for i, (body, want) in enumerate(cases.items()):
        root = copy(CONTROLLERS, tmp_path / f"c{i}", None, {"Auth/AuditHandler.cs": handler(body)})
        assert App(root)("AuditController.Log").state == want, body


def test_i10_uncertain_use_authorization_with_certain_suppress_is_unknown(roslyn_helper, tmp_path):
    root = _startup_with(tmp_path, SUPPRESS, ("app.UseAuthorization();", "if (app.Environment.IsEnvironment(Settings.Env)) { app.UseAuthorization(); }"))
    a = App(root)("SecureController.Get")
    assert a.state == UNKNOWN and a.reasons


def test_r23_statement_kinds_and_ternary_and_policy_case(roslyn_helper):
    from checks.dnl.auth_core import _expr_events, _stmt_events
    call = lambda n: {"k": "call", "fn": {"k": "member", "obj": {"k": "name", "id": "o"}, "name": n}, "args": []}
    tern = {"k": "cond", "c": {"k": "name", "id": "x"}, "a": call("First"), "b": call("Second")}
    assert [c["fn"]["name"] for kind, c, _g, _r in _expr_events(tern, ()) if kind == "call"] == ["First", "Second"]
    opaque = {"k": "other", "text": "o.Conventions.AllowAnonymousToFolder(\"/\")"}
    assert [kind for kind, *_ in _stmt_events([opaque], ())] == ["opaque"]
    assert list(_stmt_events([{"k": "other", "text": "goto done;"}], ())) == []


def test_r23_policy_names_are_case_insensitive(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Controllers/OrdersController.cs": ('Policy = "Admin"', 'Policy = "ADMIN"')})
    d = App(root)("OrdersController.Delete")
    assert d.state == PROTECTED and d.roles == ["Admin"]


def test_r23_opaque_statement_blocks_protection(roslyn_helper, tmp_path):
    # A statement the lowering keeps as text and that mentions an anonymous opt-out cannot be read.
    root = copy(RAZOR, tmp_path, {"Program.cs": ('o.Conventions.AllowAnonymousToPage("/Admin/Login");',
                                                 'o.Conventions.AllowAnonymousToPage("/Admin/Login");\n    switch (Mode) { case 1: o.Conventions.AllowAnonymousToFolder("/Admin"); break; }')})
    assert App(root)("UsersModel.OnGet").state == UNKNOWN


# -- fix round 2 -----------------------------------------------------------------------------------

def test_n1_use_authorization_under_non_environment_condition_is_uncertain(roslyn_helper, tmp_path):
    root = copy(STARTUP, tmp_path, {"Startup.Pipeline.cs": ("app.UseAuthorization();", "if (Config.On) { app.UseAuthorization(); }")})
    project._CACHE.clear()
    project.prepare(root, False)
    model = project.get_model(root, "dotnet")
    pipe = pipeline_for(model, model.projects[0])
    assert "UseAuthorization" in {c.name for c in pipe.uncertain()}
    assert not pipe.named("UseAuthorization")
    assert middleware_issue(pipe) is None


def test_n1_fallback_under_non_environment_condition_is_unknown(roslyn_helper, tmp_path):
    root = copy(CONTROLLERS, tmp_path, {"Program.cs": (
        "var app = builder.Build();",
        f"if (Config.On) {{ builder.Services.AddAuthorization(o => {{ {FALLBACK_AUTHED} }}); }}\nvar app = builder.Build();")})
    a = App(root)("HealthController.Get")
    assert a.state == UNKNOWN and a.reasons


def test_n1_page_convention_under_non_environment_condition_is_unknown(roslyn_helper, tmp_path):
    root = copy(RAZOR, tmp_path, {"Program.cs": ("builder.Services.AddRazorPages(o =>", "if (Config.On) builder.Services.AddRazorPages(o =>")})
    a = App(root)("UsersModel.OnGet")
    assert a.state == UNKNOWN and a.reasons


def _razor_net6(tmp_path, use_authorization):
    return copy(RAZOR, tmp_path, {
        "RazorApp.csproj": ("net8.0", "net6.0"),
        "Program.cs": ("app.UseAuthorization();", use_authorization),
    })


def test_n2_page_convention_with_suppressed_missing_middleware(roslyn_helper, tmp_path):
    root = _razor_net6(tmp_path, "")
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace(
        "var app = builder.Build();",
        "builder.Services.Configure<RouteOptions>(o => o.SuppressCheckForUnhandledSecurityMetadata = true);\nvar app = builder.Build();"))
    a = App(root)("UsersModel.OnGet")
    assert a.state == UNPROTECTED and any("not enforced" in n for n in a.notes)
    # Without the flag the broken pipeline fails closed: the page stays protected.
    assert App(_razor_net6(tmp_path / "b", ""))("UsersModel.OnGet").state == PROTECTED


def test_n2_page_convention_with_uncertain_middleware_and_suppress_is_unknown(roslyn_helper, tmp_path):
    root = _razor_net6(tmp_path, "if (app.Environment.IsEnvironment(Settings.Env)) { app.UseAuthorization(); }")
    prog = root / "Program.cs"
    prog.write_text(prog.read_text().replace(
        "var app = builder.Build();",
        "builder.Services.Configure<RouteOptions>(o => o.SuppressCheckForUnhandledSecurityMetadata = true);\nvar app = builder.Build();"))
    a = App(root)("UsersModel.OnGet")
    assert a.state == UNKNOWN and a.reasons


def test_n3_succeed_on_every_branch_is_never_denying(roslyn_helper, tmp_path):
    def handler(body):
        return ("using Microsoft.AspNetCore.Authorization;\n\npublic class AuditRequirement : IAuthorizationRequirement { }\n\n"
                "public class AuditHandler : AuthorizationHandler<AuditRequirement>\n{\n"
                "    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AuditRequirement requirement)\n    {\n"
                f"{body}\n        return Task.CompletedTask;\n    }}\n}}\n")
    cases = {
        "if (context.User.IsInRole(\"a\")) { context.Succeed(requirement); } else { context.Succeed(requirement); }": UNPROTECTED,
        "if (X) { context.Succeed(requirement); } else if (Y) { context.Succeed(requirement); } else { context.Succeed(requirement); }": UNPROTECTED,
        "if (X) { context.Succeed(requirement); } else if (Y) { context.Succeed(requirement); }": PROTECTED,
    }
    for i, (body, want) in enumerate(cases.items()):
        root = copy(CONTROLLERS, tmp_path / f"c{i}", None, {"Auth/AuditHandler.cs": handler(body)})
        assert App(root)("AuditController.Log").state == want, body


def test_n4_trailing_untraced_call_on_followed_result_is_noted(roslyn_helper, tmp_path):
    root = copy(MINIMAL, tmp_path, {"Program.cs": (
        'app.MapGet("/", () => "hello");',
        'app.MapGet("/", () => "hello");\nWrap(app.MapGroup("/x").RequireAuthorization()).AllowPublic();\n'
        'static RouteGroupBuilder Wrap(RouteGroupBuilder g) { g.MapGet("/y", () => 1); return g; }')})
    a = App(root)("/x/y")
    assert a.state == UNKNOWN and any("AllowPublic" in r for r in a.reasons)
