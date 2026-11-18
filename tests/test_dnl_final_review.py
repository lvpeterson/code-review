"""Final-review fixes: local functions followed, generic-host / branch lambdas walked, custom authorization
services block PROTECTED, constant-true assertions, nested controllers. Helper and degraded mode each."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from cfgutil import ids, mode, scan  # noqa: F401,E402
from test_dnl_auth_flood import App, mode as auth_mode  # noqa: F401,E402
from checks.dnl.auth_core import PROTECTED, UNKNOWN, UNPROTECTED  # noqa: E402

CTRLS = '''using Microsoft.AspNetCore.Mvc; using Microsoft.AspNetCore.Authorization;
[Authorize] public class SecController : ControllerBase { [HttpGet("/sec")] public string Get() => "x"; }
'''
NEVER = ('b.Services.AddAuthorization(o => o.DefaultPolicy = new AuthorizationPolicyBuilder()'
         '.RequireAssertion(c => true).Build());')
TAIL = "app.UseRouting(); app.UseAuthentication(); app.UseAuthorization(); app.MapControllers(); app.Run();\n"
USINGS = "using Microsoft.AspNetCore.Authorization;\n"


def _local_fn(body):
    return (USINGS + "var builder = WebApplication.CreateBuilder(args);\nConfigureServices(builder);\n"
            "var app = builder.Build();\n" + TAIL
            + "static void ConfigureServices(WebApplicationBuilder b) {\n  b.Services.AddControllers();\n  " + body + "\n}\n")


def _ext(body):
    return (USINGS + "var builder = WebApplication.CreateBuilder(args);\nbuilder.AddMine();\n"
            "var app = builder.Build();\n" + TAIL), {
        "E.cs": USINGS + "public static class E { public static void AddMine(this WebApplicationBuilder b) {\n"
                "  b.Services.AddControllers();\n  " + body + "\n} }\n", "C.cs": CTRLS}


@pytest.mark.parametrize("variant", ["localfn", "ext"])
def test_never_denying_default_policy(tmp_path, auth_mode, variant):
    if variant == "localfn":
        prog, files = _local_fn(NEVER), {"C.cs": CTRLS}
    else:
        prog, files = _ext(NEVER)
    a = App(tmp_path, auth_mode, prog, files)("SecController.Get")
    assert a.state == UNPROTECTED, (a.state, a.reasons, a.notes)
    assert "never denies" in (a.source or "") or any("never denies" in n for n in a.notes + a.reasons)


@pytest.mark.parametrize("variant", ["localfn", "ext"])
def test_devpage_is_cfg008(tmp_path, mode, variant):
    if variant == "localfn":
        prog = ("var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\nSetup(app);\napp.Run();\n"
                "static void Setup(WebApplication a) { a.UseDeveloperExceptionPage(); }\n")
        files = {"Program.cs": prog}
    else:
        files = {"Program.cs": "var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.Setup();\napp.Run();\n",
                 "E.cs": "public static class E { public static void Setup(this WebApplication a) { a.UseDeveloperExceptionPage(); } }\n"}
    f = scan(tmp_path, files, mode)
    assert any(x.check_id == "DNL-CFG-008" for x in f), [x.check_id for x in f]


def test_local_function_cors_and_cycle(tmp_path, mode):
    prog = ("var builder = WebApplication.CreateBuilder(args);\nConfigureServices(builder);\nvar app = builder.Build();\napp.Run();\n"
            "static void ConfigureServices(WebApplicationBuilder b) {\n"
            "  b.Services.AddCors(o => o.AddPolicy(\"a\", p => p.AllowAnyOrigin().AllowCredentials()));\n"
            "  if (b.Services == null) ConfigureServices(b);\n}\n")
    f = scan(tmp_path, {"Program.cs": prog}, mode)
    assert any(x.check_id.startswith("DNL-CFG") for x in f), [x.check_id for x in f]


# -- item 3: custom authorization services block PROTECTED -----------------------------------------

def _plain(reg, files=None):
    prog = (USINGS + "var b = WebApplication.CreateBuilder(args);\nb.Services.AddControllers(); b.Services.AddAuthorization();\n"
            + reg + "\nvar app = b.Build();\n" + TAIL)
    return prog, {"C.cs": CTRLS, **(files or {})}


_PROVIDER = ('using Microsoft.AspNetCore.Mvc.ApplicationModels;\npublic class Prov : IApplicationModelProvider { public int Order => 1;\n'
             'public void OnProvidersExecuting(ApplicationModelProviderContext c) {}\n'
             'public void OnProvidersExecuted(ApplicationModelProviderContext c) { foreach (var x in c.Result.Controllers) '
             'foreach (var a in x.Actions) a.Selectors[0].EndpointMetadata.Add(new AllowAnonymousAttribute()); } }\n')


@pytest.mark.parametrize("reg,extra", [
    ("b.Services.AddSingleton<Microsoft.AspNetCore.Authorization.Policy.IPolicyEvaluator, Ev>();", "public class Ev {}"),
    ("b.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, Rh>();", "public class Rh {}"),
    ("b.Services.AddScoped<IAuthorizationService, As>();", "public class As {}"),
    ("b.Services.TryAddTransient<IAuthorizationHandlerProvider, Hp>();", "public class Hp {}"),
    ("b.Services.Replace(ServiceDescriptor.Singleton<IPolicyEvaluator, Ev>());", "public class Ev {}"),
    ("b.Services.Add(new ServiceDescriptor(typeof(IAuthorizationService), typeof(As), ServiceLifetime.Singleton));", "public class As {}"),
    ("b.Services.AddSingleton<IApplicationModelProvider, Prov>();", _PROVIDER),
    ("b.Services.AddSingleton<IApplicationModelProvider, ThirdParty.Prov>();", ""),
])
def test_custom_authz_service_registration_blocks_protected(tmp_path, auth_mode, reg, extra):
    prog, files = _plain(reg, {"X.cs": extra})
    a = App(tmp_path, auth_mode, prog, files)("SecController.Get")
    assert a.state == UNKNOWN and a.reasons, (a.state, a.reasons)


def test_unrelated_registration_keeps_protected(tmp_path, auth_mode):
    prog, files = _plain("b.Services.AddSingleton<IClock, Clock>();", {"X.cs": "public interface IClock {} public class Clock : IClock {}"})
    assert App(tmp_path, auth_mode, prog, files)("SecController.Get").state == PROTECTED


# -- item 4: constant-true assertions never deny -----------------------------------------------------

_NEVER_SHAPES = {
    "lit": "c => true", "true_or": 'c => true || c.User.IsInRole("a")', "not_false": "c => !false", "eq": "c => 1 == 1",
    "taut": 'c => c.User.IsInRole("a") || !c.User.IsInRole("a")', "default_or": "c => default(bool) || true",
    "not_ne": "c => !(1 != 1)", "str_eq": 'c => "a" == "a"', "block": "c => { return true || c.Flag; }",
}
_DENY_SHAPES = {
    "false_and": "c => false && true", "ident": "c => c.Flag", "false_or": "c => false || c.Flag",
    "ne": "c => 1 != 1", "diff": 'c => c.User.IsInRole("a") || !c.User.IsInRole("b")', "call": "c => Ok()",
    "and_true": "c => c.Flag && true",
}


def _assertion_app(shapes):
    pols = " ".join(f'o.AddPolicy("{k}", p => p.RequireAssertion({v}));' for k, v in shapes.items())
    ctrls = "using Microsoft.AspNetCore.Mvc; using Microsoft.AspNetCore.Authorization;\n" + "\n".join(
        f'public class {k.replace("_", "")}Controller : ControllerBase {{ [Authorize(Policy="{k}"), HttpGet("/{k}")] public string Get() => "x"; }}'
        for k in shapes)
    prog = (USINGS + "var b = WebApplication.CreateBuilder(args);\nb.Services.AddControllers(); b.Services.AddAuthorization(o => { "
            + pols + " });\nvar app = b.Build();\n" + TAIL)
    return prog, {"C.cs": ctrls}


def test_constant_true_assertions_never_deny(tmp_path, auth_mode):
    prog, files = _assertion_app(_NEVER_SHAPES)
    app = App(tmp_path, auth_mode, prog, files)
    for k in _NEVER_SHAPES:
        a = app(f"/{k}")
        assert a.state == UNPROTECTED, (k, a.state, a.reasons, a.notes)


def test_non_constant_assertions_still_deny(tmp_path, auth_mode):
    prog, files = _assertion_app(_DENY_SHAPES)
    app = App(tmp_path, auth_mode, prog, files)
    for k in _DENY_SHAPES:
        a = app(f"/{k}")
        assert a.state == PROTECTED, (k, a.state, a.reasons, a.notes)


# -- item 5: nested controller types are not MVC controllers -----------------------------------------

def test_nested_controller_types_are_not_routes(tmp_path, auth_mode):
    prog = (USINGS + "var b = WebApplication.CreateBuilder(args);\nb.Services.AddControllers();\nvar app = b.Build();\napp.MapControllers(); app.Run();\n")
    files = {"C.cs": 'using Microsoft.AspNetCore.Mvc;\npublic class Outer { public class NestedController : ControllerBase '
                     '{ [HttpGet("/nested")] public string Get() => "x"; } }\n'
                     'public class TopController : ControllerBase { [HttpGet("/top")] public string Get() => "x"; }\n'}
    app = App(tmp_path, auth_mode, prog, files)
    paths = {r.route.path for r in app.refs}
    assert "/top" in paths and "/nested" not in paths, paths


# -- item 2: generic-host and branch lambdas ----------------------------------------------------------

GENERIC_HOST = '''using Microsoft.AspNetCore.Builder; using Microsoft.AspNetCore.Hosting; using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
public class Program { public static void Main(string[] args) {
  Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(wb => {
    wb.ConfigureServices(s => { s.AddControllers(); %s });
    wb.Configure(app => { %s app.UseRouting(); app.UseEndpoints(e => { e.MapGet("/x", () => "x"); }); });
  }).Build().Run(); } }
'''


def _cfg(f, check):
    return [x for x in f if x.check_id == check]


def test_generic_host_pipeline_is_walked(tmp_path, mode):
    prog = GENERIC_HOST % ('s.AddCors(o => o.AddPolicy("a", p => p.AllowAnyOrigin()));', "app.UseDeveloperExceptionPage();")
    f = scan(tmp_path, {"Program.cs": prog}, mode)
    assert _cfg(f, "DNL-CFG-008"), [x.check_id for x in f]
    assert _cfg(f, "DNL-CFG-007"), [x.check_id for x in f]


def test_generic_host_protective_middleware_counts(tmp_path, mode):
    prog = GENERIC_HOST % ("", "app.UseExceptionHandler(\"/e\"); app.UseHttpsRedirection(); app.UseHsts();")
    f = scan(tmp_path, {"Program.cs": prog}, mode)
    got = {x.check_id for x in f}
    assert not got & {"DNL-CFG-009", "DNL-CFG-010", "DNL-CFG-011"}, got


def test_generic_host_never_denying_default_policy(tmp_path, auth_mode):
    prog = '''using Microsoft.AspNetCore.Builder; using Microsoft.AspNetCore.Hosting; using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authorization; using Microsoft.Extensions.DependencyInjection;
public class Program { public static void Main(string[] args) {
  Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(wb => {
    wb.ConfigureServices(s => { s.AddControllers(); s.AddAuthorization(o => o.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAssertion(c => true).Build()); });
    wb.Configure(app => { app.UseRouting(); app.UseAuthentication(); app.UseAuthorization(); app.UseEndpoints(e => { e.MapControllers(); }); });
  }).Build().Run(); } }
'''
    a = App(tmp_path, auth_mode, prog, {"C.cs": CTRLS})("SecController.Get")
    assert a.state == UNPROTECTED, (a.state, a.reasons, a.notes)


def _branch(body, tail="app.MapGet(\"/\", () => 1);"):
    return ("var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\n" + body + "\n" + tail + "\napp.Run();\n")


@pytest.mark.parametrize("branch", [
    'app.Map("/x", a => a.UseDeveloperExceptionPage());',
    'app.MapWhen(c => c.Request.Path.StartsWithSegments("/y"), a => { a.UseDeveloperExceptionPage(); });',
    'app.UseWhen(c => c.Request.Path.StartsWithSegments("/y"), a => { a.UseDeveloperExceptionPage(); });',
])
def test_dev_page_in_branch_is_a_finding(tmp_path, mode, branch):
    f = scan(tmp_path, {"Program.cs": _branch(branch)}, mode)
    assert _cfg(f, "DNL-CFG-008"), [x.check_id for x in f]


def test_protective_middleware_in_branch_does_not_cover_the_app(tmp_path, mode):
    branch = ('app.UseWhen(c => c.Request.Path.StartsWithSegments("/api"), a => '
              '{ a.UseHttpsRedirection(); a.UseHsts(); a.UseExceptionHandler("/e"); });')
    f = scan(tmp_path, {"Program.cs": _branch(branch)}, mode)
    got = {x.check_id for x in f}
    assert {"DNL-CFG-009", "DNL-CFG-010", "DNL-CFG-011"} <= got, got


def test_unfollowable_branch_adds_note(tmp_path, auth_mode):
    from checks.dnl.pipeline import pipeline_for
    prog = _branch('app.UseWhen(c => true, Vendor.Branch);')
    app = App(tmp_path, auth_mode, prog, {})
    pipe = pipeline_for(app.model, app.model.projects[0] if hasattr(app.model, "projects") and app.model.projects else None)
    assert any("branch" in n for n in pipe.notes), pipe.notes
