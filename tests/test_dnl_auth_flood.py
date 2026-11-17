"""Auth UNKNOWN flood (acceptance fixes N1.1-N1.4, N6, D9): registrations, conventions and endpoint filters that
cannot change authorization no longer block a provably protected route, while every fail-closed case stays
UNKNOWN. Each case runs with the Roslyn helper and degraded (tree-sitter)."""
from pathlib import Path

import pytest

from checks.dnl import auth_core, project, rules_auth_core
from checks.dnl.auth_core import PROTECTED, UNKNOWN, UNPROTECTED
from checks.dnl.pipeline import pipeline_for
from checks.dnl.routes_core import discover_all

CSPROJ = ('<Project Sdk="Microsoft.NET.Sdk.Web">\n  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n'
          '    <ImplicitUsings>enable</ImplicitUsings>\n  </PropertyGroup>\n</Project>\n')
USINGS = "using Microsoft.AspNetCore.Authorization;\nusing Microsoft.AspNetCore.Mvc;\n"
CONTROLLERS = '''
[ApiController, Route("api/things")]
public class ThingsController : ControllerBase
{
    [HttpGet("secure"), Authorize] public IActionResult Secure() => Ok();
    [HttpGet("open")] public IActionResult Open() => Ok();
}
'''
FALLBACK = "o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();"
AUTHZ = 'builder.Services.AddAuthentication().AddJwtBearer();\nbuilder.Services.AddAuthorization();\n'


def _program(services: str = "", authz: str = AUTHZ, tail: str = "app.MapControllers();", extra: str = CONTROLLERS) -> str:
    return (USINGS + "var builder = WebApplication.CreateBuilder(args);\nbuilder.Services.AddControllers();\n" + authz
            + services + "\nvar app = builder.Build();\napp.UseAuthentication();\napp.UseAuthorization();\n"
            + tail + "\napp.Run();\n" + extra)


@pytest.fixture(params=[False, True], ids=["helper", "degraded"])
def mode(request, roslyn_helper, monkeypatch):
    if request.param:
        monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
        monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    return request.param


class App:
    def __init__(self, tmp_path: Path, degraded: bool, program: str, files: dict | None = None):
        root = tmp_path / "app"
        root.mkdir(parents=True, exist_ok=False)
        (root / "App.csproj").write_text(CSPROJ)
        (root / "Program.cs").write_text(program)
        for name, text in (files or {}).items():
            (root / name).write_text(text)
        project._CACHE.clear()
        project.prepare(root, degraded)
        self.model = project.get_model(root, "dotnet")
        self.refs = discover_all(self.model)

    def __call__(self, key: str):
        hits = [r for r in self.refs if r.route.handler_name == key or r.route.path == key]
        assert len(hits) == 1, (key, [(r.route.handler_name, r.route.path) for r in self.refs])
        return auth_core.resolve(self.model, hits[0], pipeline_for(self.model, hits[0].project))


def _state(tmp_path, mode, program, key="ThingsController.Secure", files=None):
    return App(tmp_path, mode, program, files)(key)


# -- N1.1 Configure<T> / AddOptions<T> ----------------------------------------------------------

def test_n11_configure_of_a_plain_options_type_does_not_block(tmp_path, mode):
    svc = ('builder.Services.Configure<CatalogOptions>(builder.Configuration);\n'
           'builder.Services.Configure<CatalogOptions>(builder.Configuration.GetSection("Catalog"));\n'
           'builder.Services.Configure<CatalogOptions>(SetUp);\n'
           'builder.Services.AddOptions<CatalogOptions>().Bind(builder.Configuration.GetSection("Catalog"));\n')
    prog = _program(svc, extra=CONTROLLERS + "public class CatalogOptions { public string Name { get; set; } = \"\"; }\n"
                    "public partial class Program { static void SetUp(CatalogOptions o) { } }\n")
    assert _state(tmp_path, mode, prog).state == PROTECTED


@pytest.mark.parametrize("stmt", [
    "builder.Services.Configure<AuthorizationOptions>(builder.Configuration);",
    "builder.Services.Configure<MvcOptions>(builder.Configuration.GetSection(\"Mvc\"));",
    "builder.Services.Configure<RazorPagesOptions>(SetUp);",
    "builder.Services.Configure<CookieAuthenticationOptions>(builder.Configuration);",
    "builder.Services.Configure<RouteOptions>(builder.Configuration);",
    "builder.Services.Configure<CustomAuthorizationOptions>(builder.Configuration);",
    "builder.Services.AddOptions<AuthorizationOptions>().Bind(builder.Configuration);",
    "builder.Services.Configure(builder.Configuration);",
])
def test_n11_configure_of_an_auth_relevant_type_still_blocks(tmp_path, mode, stmt):
    prog = _program(stmt + "\n", extra=CONTROLLERS + "public partial class Program { static void SetUp(object o) { } }\n")
    a = _state(tmp_path, mode, prog)
    assert a.state == UNKNOWN and a.reasons, stmt


def test_i2_alias_and_chained_options_types(tmp_path, mode):
    strip = "public partial class Program { static void Strip(object o) { } }\n"
    prog = "using Opts = Microsoft.AspNetCore.Mvc.MvcOptions;\n" + _program(
        "builder.Services.Configure<Opts>(o => Strip(o));\n", extra=CONTROLLERS + strip)
    assert _state(tmp_path / "a", mode, prog).state == UNKNOWN
    chained = _program("builder.Services.AddOptions<MvcOptions>().Configure<IFoo>((o, f) => Strip(o));\n"
                       "builder.Services.AddOptions<MvcOptions>().PostConfigure<IFoo>((o, f) => Strip(o));\n",
                       extra=CONTROLLERS + "public interface IFoo { }\n" + strip)
    assert _state(tmp_path / "b", mode, chained).state == UNKNOWN


def test_i2_solution_options_class_deriving_from_an_auth_type_and_unresolved_t(tmp_path, mode):
    strip = "public partial class Program { static void Strip(object o) { } }\n"
    derived = _program("builder.Services.Configure<MyMvcOptions>(builder.Configuration);\n",
                       extra=CONTROLLERS + "public class MyMvcOptions : Microsoft.AspNetCore.Mvc.MvcOptions { }\n")
    assert _state(tmp_path / "a", mode, derived).state == UNKNOWN
    handed = _program("builder.Services.Configure<VendorOptions>(o => Strip(o));\n", extra=CONTROLLERS + strip)
    assert _state(tmp_path / "b", mode, handed).state == UNKNOWN
    quiet = _program("builder.Services.Configure<VendorOptions>(o => o.Name = \"x\");\n")
    assert _state(tmp_path / "c", mode, quiet).state == PROTECTED


@pytest.mark.parametrize("t", ["OpenIdConnectOptions", "IdentityOptions", "CookiePolicyOptions", "HubOptions", "T1", "TOptions"])
def test_m6_more_auth_relevant_option_types(tmp_path, mode, t):
    prog = _program(f"builder.Services.Configure<{t}>(builder.Configuration);\n")
    assert _state(tmp_path, mode, prog).state == UNKNOWN, t


# -- N1.2 Conventions.Add(new X()) --------------------------------------------------------------

CONV_BASE = ("using Microsoft.AspNetCore.Mvc.ApplicationModels;\n"
             "public class {name} : IApplicationModelConvention\n{{\n    public void Apply(ApplicationModel application)\n    {{\n{body}\n    }}\n}}\n")


def _conv(name, body):
    return {f"{name}.cs": CONV_BASE.format(name=name, body=body)}


def _with_convention(tmp_path, mode, expr, files=None):
    prog = _program(f'builder.Services.AddControllers(o => {{ o.Conventions.Add({expr}); }});\n')
    return _state(tmp_path, mode, prog, files=files)


def test_n12_selector_only_solution_convention_is_benign(tmp_path, mode):
    files = _conv("SlugConvention", "foreach (var c in application.Controllers) { foreach (var s in c.Selectors) "
                  "{ s.AttributeRouteModel!.Template = s.AttributeRouteModel.Template!.ToLowerInvariant(); } }")
    assert _with_convention(tmp_path, mode, "new SlugConvention()", files).state == PROTECTED


@pytest.mark.parametrize("body", [
    "application.Filters.Add(new AllowAnonymousFilter());",
    "foreach (var c in application.Controllers) { foreach (var s in c.Selectors) { s.EndpointMetadata.Add(new AllowAnonymousAttribute()); } }",
    "foreach (var c in application.Controllers) { c.Filters.Clear(); }",
    "foreach (var c in application.Controllers) { Strip(c); }",
    "Strip(application);",
])
def test_n12_solution_convention_touching_authorization_blocks(tmp_path, mode, body):
    files = _conv("OpenConvention", body)
    a = _with_convention(tmp_path, mode, "new OpenConvention()", files)
    assert a.state == UNKNOWN and any("Conventions.Add" in r for r in a.reasons), body


@pytest.mark.parametrize("body, extra", [
    # C1: an in-solution extension does the work
    ("foreach (var c in application.Controllers) { c.OpenUp(); }",
     {"Ext.cs": "using Microsoft.AspNetCore.Mvc.ApplicationModels;\npublic static class Ext { public static void OpenUp(this ControllerModel c) { c.Filters.Add(new AllowAnonymousFilter()); } }\n"}),
    # C2: a helper object receives the model
    ("var h = new Opener(); h.Run(application);",
     {"Opener.cs": "using Microsoft.AspNetCore.Mvc.ApplicationModels;\npublic class Opener { public void Run(ApplicationModel m) { foreach (var c in m.Controllers) { c.Filters.Add(new AllowAnonymousFilter()); } } }\n"}),
    # C3: an unresolved third-party static
    ("VendorHelpers.Tweak(application);", {}),
    # C4: an unresolved extension
    ("application.Tweak();", {}),
])
def test_n12_indirection_cannot_hide_an_anonymous_opt_out(tmp_path, mode, body, extra):
    files = _conv("SneakyConvention", body)
    files.update(extra)
    a = _with_convention(tmp_path, mode, "new SneakyConvention()", files)
    assert a.state == UNKNOWN and any("Conventions.Add" in r for r in a.reasons), body


def test_n12_exact_names_only_for_framework_conventions(tmp_path, mode):
    for i, name in enumerate(("ApiExplorerAnythingConvention", "ApiVersionSneakyConvention")):
        assert _with_convention(tmp_path / str(i), mode, f"new {name}()").state == UNKNOWN


def test_n12_unresolved_convention_blocks_and_framework_one_does_not(tmp_path, mode):
    assert _with_convention(tmp_path / "a", mode, "new ThirdPartyConvention()").state == UNKNOWN
    assert _with_convention(tmp_path / "c", mode, "someVariable").state == UNKNOWN
    ok = _with_convention(tmp_path / "b", mode, "new RouteTokenTransformerConvention(new SlugTransformer())",
                          {"Slug.cs": "public class SlugTransformer : Microsoft.AspNetCore.Routing.IOutboundParameterTransformer "
                           "{ public string? TransformOutbound(object? value) => value?.ToString(); }\n"})
    assert ok.state == PROTECTED


def test_n12_convention_with_unresolved_base_blocks(tmp_path, mode):
    files = {"Odd.cs": "public class OddConvention : VendorConventionBase\n{\n    public void Apply(object app) { }\n}\n"}
    assert _with_convention(tmp_path, mode, "new OddConvention()", files).state == UNKNOWN


# -- N1.3 unresolved third-party registrations --------------------------------------------------

def test_n13_plain_unresolved_registration_keeps_an_unprotected_route_unprotected(tmp_path, mode):
    prog = _program("builder.Services.AddMediator();\nbuilder.Services.AddSqliteStore();\n")
    app = App(tmp_path, mode, prog)
    assert app("ThingsController.Open").state == UNPROTECTED
    assert app("ThingsController.Secure").state == PROTECTED


@pytest.mark.parametrize("stmt", [
    "builder.Services.AddTenantAccessRules();",
    "builder.Services.AddVendorPolicies();",
    "builder.Services.AddPermissionGate();",
    "builder.Services.AddThing(o => o.Mode = \"Role\");",
    "builder.Services.AddThing<IdentityShim>();",
])
def test_n13_auth_looking_unresolved_registration_is_still_unknown(tmp_path, mode, stmt):
    a = _state(tmp_path, mode, _program(stmt + "\n"), "ThingsController.Open")
    assert a.state == UNKNOWN and a.reasons, stmt


def test_n13_fallback_only_route_still_blocked_by_any_unresolved_registration(tmp_path, mode):
    authz = ("builder.Services.AddAuthentication().AddJwtBearer();\nbuilder.Services.AddAuthorization(o => { " + FALLBACK + " });\n")
    prog = _program("builder.Services.AddMediator();\n", authz=authz)
    a = _state(tmp_path, mode, prog, "ThingsController.Open")
    assert a.state == UNKNOWN and any("AddMediator" in r for r in a.reasons)
    clean = _program("", authz=authz)
    assert _state(tmp_path / "b", mode, clean, "ThingsController.Open").state == PROTECTED


# -- N1.4 in-solution policy extension, endpoint filters ----------------------------------------

MINIMAL_EXT = '''
public static class PolicyExt
{
    public static AuthorizationPolicyBuilder RequireCurrentUser(this AuthorizationPolicyBuilder builder)
    {
        return builder.RequireAuthenticatedUser();
    }
    public static AuthorizationPolicyBuilder RequireMagic(this AuthorizationPolicyBuilder builder)
    {
        return builder.RequireVendorMagic();
    }
    public static AuthorizationPolicyBuilder RequireNothing(this AuthorizationPolicyBuilder builder)
    {
        return builder.RequireAssertion(_ => true);
    }
}
'''


def test_n14_in_solution_policy_extension_is_followed(tmp_path, mode):
    tail = ('var g = app.MapGroup("/g").RequireAuthorization(pb => pb.RequireCurrentUser());\n'
            'g.MapGet("/a", () => "a");\n'
            'var m = app.MapGroup("/m").RequireAuthorization(pb => pb.RequireMagic());\n'
            'm.MapGet("/a", () => "a");\n'
            'var n = app.MapGroup("/n").RequireAuthorization(pb => pb.RequireNothing());\n'
            'n.MapGet("/a", () => "a");\n')
    app = App(tmp_path, mode, _program(tail=tail, extra=MINIMAL_EXT))
    assert app("/g/a").state == PROTECTED
    assert app("/m/a").state == UNKNOWN
    assert app("/n/a").state == UNPROTECTED


def test_n14_endpoint_filter_does_not_block_protection_from_another_source(tmp_path, mode):
    tail = ('app.MapGet("/p", () => "p").RequireAuthorization().AddEndpointFilter(async (c, n) => await n(c));\n'
            'app.MapGet("/q", () => "q").AddEndpointFilter(async (c, n) => await n(c));\n'
            'app.MapGroup("/gp").RequireAuthorization().AddEndpointFilter(async (c, n) => await n(c)).MapGet("/x", () => "x");\n')
    app = App(tmp_path, mode, _program(tail=tail))
    assert app("/p").state == PROTECTED
    q = app("/q")
    assert q.state == UNKNOWN and any("AddEndpointFilter" in r for r in q.reasons)
    assert app("/gp/x").state == PROTECTED


# -- N6 / D9 ------------------------------------------------------------------------------------

def _findings(tmp_path, mode, program):
    app = App(tmp_path, mode, program)
    return rules_auth_core.check(app.model, app.refs)


def test_n6_anonymous_by_design_actions_are_not_state_changing_findings(tmp_path, mode):
    ctl = '''
[ApiController, Route("api/account")]
public class AccountController : ControllerBase
{
    [HttpPost("login"), AllowAnonymous] public IActionResult Login() => Ok();
    [HttpPost, AllowAnonymous] public IActionResult Register() => Ok();
    [HttpPost("a1"), AllowAnonymous] public IActionResult ForgotPassword() => Ok();
    [HttpPost("reset-password"), AllowAnonymous] public IActionResult Submit() => Ok();
    [HttpPost("a3"), AllowAnonymous] public IActionResult ConfirmEmail() => Ok();
    [HttpPost("refresh"), AllowAnonymous] public IActionResult Renew() => Ok();
    [HttpPost("a4"), AllowAnonymous] public IActionResult LogOut() => Ok();
    [HttpPost("wipe"), AllowAnonymous] public IActionResult WipeAll() => Ok();
    [HttpPost("login/delete-all"), AllowAnonymous] public IActionResult Purge() => Ok();
}
'''
    fs = _findings(tmp_path, mode, _program(extra=ctl))
    flagged = {f.route.handler_name for f in fs if f.check_id == "DNL-AUTHZ-002"}
    assert flagged == {"AccountController.WipeAll", "AccountController.Purge"}
    assert "AccountController.Login" in {f.route.handler_name for f in fs if f.check_id == "DNL-AUTHZ-001"}


MINIMAL_NO_AUTHZ_MW = (USINGS + "var builder = WebApplication.CreateBuilder(args);\nbuilder.Services.AddControllers();\n"
                       "var app = builder.Build();\napp.UseAuthentication();\napp.MapControllers();\napp.Run();\n" + CONTROLLERS)
STARTUP_MAIN = ("Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(w => w.UseStartup<Startup>()).Build().Run();\n"
                + CONTROLLERS)
STARTUP_CLASS = (USINGS + "public class Startup\n{\n    public void ConfigureServices(IServiceCollection services)\n    {\n"
                 "        services.AddControllers();\n    }\n    public void Configure(IApplicationBuilder app)\n    {\n"
                 "        app.UseRouting();\n        app.UseEndpoints(e => e.MapControllers());\n    }\n}\n")


def test_i3_destructive_or_privileged_names_are_not_anonymous_by_design(tmp_path, mode):
    ctl = '''
[ApiController, Route("api/admin")]
public class AdminController : ControllerBase
{
    [HttpPost("a"), AllowAnonymous] public IActionResult ResetUserPassword() => Ok();
    [HttpPost("b"), AllowAnonymous] public IActionResult ResetDatabase() => Ok();
    [HttpPost("c"), AllowAnonymous] public IActionResult TokenPurge() => Ok();
}
[ApiController, Route("api/ops")]
public class OpsController : ControllerBase
{
    [HttpPost("reset-database"), AllowAnonymous] public IActionResult Run1() => Ok();
    [HttpPost("token-purge"), AllowAnonymous] public IActionResult Run2() => Ok();
    [HttpPost("confirm-email"), AllowAnonymous] public IActionResult Run3() => Ok();
    [HttpPost("reset-password"), AllowAnonymous] public IActionResult Run4() => Ok();
    [HttpPost("login"), AllowAnonymous] public IActionResult Run5() => Ok();
}
'''
    fs = _findings(tmp_path, mode, _program(extra=ctl))
    flagged = {f.route.handler_name for f in fs if f.check_id == "DNL-AUTHZ-002"}
    assert flagged == {"AdminController.ResetUserPassword", "AdminController.ResetDatabase", "AdminController.TokenPurge",
                       "OpsController.Run1", "OpsController.Run2"}


TAGS = ("using Microsoft.AspNetCore.Mvc.ApplicationModels;\n"
        "public class Tags { public static void Add(ApplicationModel m) { foreach (var c in m.Controllers) "
        "{ c.Filters.Add(new AllowAnonymousFilter()); } }\n"
        "  public void Run(ApplicationModel m) { Add(m); }\n"
        "  public override string ToString() { Tags.Add(null!); return \"\"; } }\n")
GATE = ("using Microsoft.AspNetCore.Mvc.ApplicationModels;\n"
        "public static class Gate { public static bool Open(ControllerModel c) { c.Filters.Add(new AllowAnonymousFilter()); return true; } }\n")


@pytest.mark.parametrize("body, extra", [
    # R2-1: an allowlisted callee name on a solution receiver (type name, local, own-type instance)
    ("Tags.Add(application);", {"Tags.cs": TAGS}),
    ("var t = new Tags(); t.Add(application);", {"Tags.cs": TAGS}),
    ("new Tags().ToString();", {"Tags.cs": TAGS}),
    ("var t = new Tags(); t.Equals(application);", {"Tags.cs": TAGS}),
    # R2-2: a method group handed to a framework call
    ("var q = application.Controllers.Where(Gate.Open).ToList();", {"Gate.cs": GATE}),
    ("application.Controllers.Any(VendorGate.Open);", {}),
])
def test_r2_allowlisted_names_and_method_groups_cannot_hide_an_opt_out(tmp_path, mode, body, extra):
    files = _conv("SneakyConvention", body)
    files.update(extra)
    a = _with_convention(tmp_path, mode, "new SneakyConvention()", files)
    assert a.state == UNKNOWN and any("Conventions.Add" in r for r in a.reasons), body


def test_r2_framework_receivers_and_own_members_stay_benign(tmp_path, mode):
    body = ("foreach (var c in application.Controllers.Where(x => x.ControllerName.StartsWith(\"A\")).ToList()) "
            "{ foreach (var s in c.Selectors) { s.AttributeRouteModel!.Template = string.Join(\"/\", Prefix, "
            "s.AttributeRouteModel.Template!.Trim().ToLowerInvariant()); } }")
    files = {"Pre.cs": CONV_BASE.format(name="PrefixConvention", body=body).replace(
        "{\n    public void Apply", "{\n    private const string Prefix = \"v1\";\n    public void Apply", 1)}
    assert _with_convention(tmp_path, mode, "new PrefixConvention()", files).state == PROTECTED


@pytest.mark.parametrize("t", ["GoogleOptions", "FacebookOptions", "TwitterOptions", "MicrosoftAccountOptions", "OAuthOptions",
                               "NegotiateOptions", "CertificateAuthenticationOptions", "BearerTokenOptions",
                               "IdentityCookieOptions", "VendorAuthenticationOptions", "VendorAuthenticationSchemeOptions"])
def test_r2_more_authentication_option_types(tmp_path, mode, t):
    prog = _program(f"builder.Services.Configure<{t}>(builder.Configuration.GetSection(\"x\"));\n")
    assert _state(tmp_path, mode, prog).state == UNKNOWN, t


def test_r2_global_using_alias_from_another_file(tmp_path, mode):
    prog = _program("builder.Services.Configure<Opts>(builder.Configuration.GetSection(\"x\"));\n")
    files = {"Globals.cs": "global using Opts = Microsoft.AspNetCore.Mvc.MvcOptions;\n"}
    assert _state(tmp_path, mode, prog, files=files).state == UNKNOWN


def test_r2_account_closure_names_are_not_anonymous_by_design(tmp_path, mode):
    ctl = '''
[ApiController, Route("api/account")]
public class AccountController : ControllerBase
{
    [HttpPost("confirm-account-deletion"), AllowAnonymous] public IActionResult ConfirmAccountDeletion() => Ok();
    [HttpPost("a"), AllowAnonymous] public IActionResult ResetPasswordAndCloseAccount() => Ok();
    [HttpPost("login"), AllowAnonymous] public IActionResult WipeEverything() => Ok();
    [HttpPost("b"), AllowAnonymous] public IActionResult DisableTwoFactor() => Ok();
    [HttpPost("c"), AllowAnonymous] public IActionResult VerifyTwoFactorCode() => Ok();
    [HttpPost("d"), AllowAnonymous] public IActionResult ConfirmEmail() => Ok();
}
'''
    fs = _findings(tmp_path, mode, _program(extra=ctl))
    flagged = {f.route.handler_name for f in fs if f.check_id == "DNL-AUTHZ-002"}
    assert flagged == {"AccountController.ConfirmAccountDeletion", "AccountController.ResetPasswordAndCloseAccount",
                       "AccountController.WipeEverything", "AccountController.DisableTwoFactor"}


def test_d9_minimal_hosting_adds_authorization_middleware_itself(tmp_path, mode):
    assert not any(f.check_id == "DNL-AUTHZ-008" for f in _findings(tmp_path, mode, MINIMAL_NO_AUTHZ_MW))


def test_d9_startup_style_without_authorization_middleware_is_flagged(tmp_path, mode):
    app = App(tmp_path, mode, STARTUP_MAIN, {"Startup.cs": STARTUP_CLASS})
    assert any(f.check_id == "DNL-AUTHZ-008" for f in rules_auth_core.check(app.model, app.refs))
