"""rules_limits_core: request-size limits (DNL-RES-001 reused), missing rate limiting on login / token /
reset endpoints (DNL-RES-004) and an unbounded page size reaching Take (DNL-RES-005)."""
from cfgutil import ids, mode, scan  # noqa: F401

BUILDER = ("var builder = WebApplication.CreateBuilder(args);\n{services}\nvar app = builder.Build();\n"
           "{body}\napp.Run();\n")
USINGS = "using Microsoft.AspNetCore.Mvc;\nusing Microsoft.AspNetCore.RateLimiting;\nusing System.ComponentModel.DataAnnotations;\n"


def prog(services: str = "", body: str = "") -> dict:
    return {"Program.cs": BUILDER.format(services=services, body=body)}


def mvc(ctl: str, services: str = "", body: str = "", cls_attrs: str = "") -> dict:
    files = prog("builder.Services.AddControllers();\n" + services, "app.MapControllers();\n" + body)
    files["ApiController.cs"] = USINGS + f"{cls_attrs}\n[ApiController]\npublic class ApiController : ControllerBase {{\n{ctl}\n}}\n"
    return files


def got(found, cid):
    return {(f.check_id, f.severity, f.confidence) for f in found if f.check_id == cid}


def of(found, cid):
    return [f for f in found if f.check_id == cid]


# -- RES-001 -----------------------------------------------------------------------------------------

def kestrel(expr: str) -> dict:
    return prog(f"builder.WebHost.ConfigureKestrel(o => {expr});")


def test_res001_kestrel_null_is_firm_and_route_less(tmp_path, mode):
    f = scan(tmp_path, kestrel("o.Limits.MaxRequestBodySize = null"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    assert of(f, "DNL-RES-001")[0].route is None


def test_res001_small_limit_is_clean(tmp_path, mode):
    f = scan(tmp_path, kestrel("o.Limits.MaxRequestBodySize = 10 * 1024 * 1024"), mode)
    assert not got(f, "DNL-RES-001")


def test_res001_computed_constant_over_limit(tmp_path, mode):
    f = scan(tmp_path / "a", kestrel("o.Limits.MaxRequestBodySize = 2000L * 1024 * 1024"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    f = scan(tmp_path / "b", kestrel("o.Limits.MaxRequestBodySize = 100L * 1024 * 1024"), mode)
    assert not got(f, "DNL-RES-001")        # exactly 100 MiB is the limit, not above it


def test_res001_non_literal_is_review(tmp_path, mode):
    f = scan(tmp_path, kestrel("o.Limits.MaxRequestBodySize = cfg.MaxBody"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}


def test_res001_conditional_values(tmp_path, mode):
    bad_cond = kestrel("{ if (cfg.Big) o.Limits.MaxRequestBodySize = null; }")
    assert got(scan(tmp_path / "a", bad_cond, mode), "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}
    good_cond = kestrel("{ o.Limits.MaxRequestBodySize = null; if (cfg.Small) o.Limits.MaxRequestBodySize = 1000; }")
    assert got(scan(tmp_path / "b", good_cond, mode), "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}
    fixed = kestrel("{ o.Limits.MaxRequestBodySize = null; o.Limits.MaxRequestBodySize = 1000; }")
    assert not got(scan(tmp_path / "c", fixed, mode), "DNL-RES-001")


def test_res001_development_only_is_skipped_unparsed_guard_is_review(tmp_path, mode):
    dev = ("if (builder.Environment.IsDevelopment()) { builder.WebHost.ConfigureKestrel(o => "
           "o.Limits.MaxRequestBodySize = null); }")
    assert not got(scan(tmp_path / "a", prog(dev), mode), "DNL-RES-001")
    odd = ("if (Helper.Flag()) { builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = null); }")
    assert got(scan(tmp_path / "b", prog(odd), mode), "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}


def test_res001_form_options_and_other_servers(tmp_path, mode):
    f = scan(tmp_path / "a", prog("builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = long.MaxValue);"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    f = scan(tmp_path / "b", prog("builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = 50 * 1024 * 1024);"), mode)
    assert not got(f, "DNL-RES-001")
    f = scan(tmp_path / "c", prog("builder.Services.Configure<IISServerOptions>(o => o.MaxRequestBodySize = null);"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    f = scan(tmp_path / "d", prog("builder.Services.Configure<KestrelServerOptions>(o => o.Limits.MaxRequestBodySize = int.MaxValue);"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}


def test_res001_opaque_options_are_review(tmp_path, mode):
    f = scan(tmp_path / "a", prog('builder.Services.Configure<KestrelServerOptions>(builder.Configuration.GetSection("K"));'), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}
    f = scan(tmp_path / "b", prog("builder.WebHost.ConfigureKestrel(o => Harden(o.Limits));"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}
    f = scan(tmp_path / "c", prog("builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(5000));"), mode)
    assert not got(f, "DNL-RES-001")


def test_res001_attributes_on_routes(tmp_path, mode):
    up = "[HttpPost(\"up\")] public IActionResult Up() => Ok();"
    f = scan(tmp_path / "a", mvc("[DisableRequestSizeLimit]\n" + up), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    assert of(f, "DNL-RES-001")[0].route is not None
    f = scan(tmp_path / "b", mvc("[RequestSizeLimit(300000000)]\n" + up), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    f = scan(tmp_path / "c", mvc("[RequestSizeLimit(1000)]\n" + up), mode)
    assert not got(f, "DNL-RES-001")
    f = scan(tmp_path / "d", mvc("[RequestSizeLimit(Limits.Max)]\n" + up), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}
    f = scan(tmp_path / "e", mvc(up, cls_attrs="[DisableRequestSizeLimit]"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}


def test_res001_minimal_api_metadata(tmp_path, mode):
    body = 'app.MapPost("/up", () => Results.Ok()).WithMetadata(new DisableRequestSizeLimitAttribute());'
    f = scan(tmp_path, prog("", body), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    assert of(f, "DNL-RES-001")[0].route is not None


def test_res001_appsettings(tmp_path, mode):
    cfg = '{\n  "Kestrel": {\n    "Limits": {\n      "MaxRequestBodySize": 2147483648\n    }\n  }\n}\n'
    f = scan(tmp_path / "a", {**prog(), "appsettings.json": cfg}, mode)
    hit = of(f, "DNL-RES-001")
    assert [(x.confidence, x.file, x.line) for x in hit] == [(None, "appsettings.json", 4)]
    fixed = '{\n  "Kestrel": {\n    "Limits": {\n      "MaxRequestBodySize": 1000\n    }\n  }\n}\n'
    f = scan(tmp_path / "b", {**prog(), "appsettings.json": cfg, "appsettings.Production.json": fixed}, mode)
    assert not got(f, "DNL-RES-001")
    nul = '{\n  "Kestrel": {\n    "Limits": {\n      "MaxRequestBodySize": null\n    }\n  }\n}\n'
    f = scan(tmp_path / "c", {**prog(), "appsettings.json": nul}, mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}


# -- RES-004 -----------------------------------------------------------------------------------------

LOGIN = "[HttpPost(\"login\")] public IActionResult Login() => Ok();"
LIMITER = "builder.Services.AddRateLimiter(o => { });\n"


def test_res004_login_without_limiter(tmp_path, mode):
    f = scan(tmp_path, mvc(LOGIN), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", None)}
    assert len(of(f, "DNL-RES-004")) == 1 and of(f, "DNL-RES-004")[0].route is not None


def test_res004_global_limiter_clears(tmp_path, mode):
    f = scan(tmp_path, mvc(LOGIN, LIMITER, "app.UseRateLimiter();"), mode)
    assert not got(f, "DNL-RES-004")


def test_res004_limiter_only_in_development_does_not_count(tmp_path, mode):
    body = "if (app.Environment.IsDevelopment()) { app.UseRateLimiter(); }"
    f = scan(tmp_path, mvc(LOGIN, LIMITER, body), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", None)}


def test_res004_production_branch_counts(tmp_path, mode):
    body = "if (!app.Environment.IsDevelopment()) { app.UseRateLimiter(); }"
    f = scan(tmp_path, mvc(LOGIN, LIMITER, body), mode)
    assert not got(f, "DNL-RES-004")


def test_res004_unparsed_guard_is_review(tmp_path, mode):
    f = scan(tmp_path / "a", mvc(LOGIN, LIMITER, "if (Helper.Flag()) { app.UseRateLimiter(); }"), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", "REVIEW")}
    f = scan(tmp_path / "b", mvc(LOGIN, LIMITER, "if (Helper.Flag()) { app.UseHsts(); }"), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", "REVIEW")}


def test_res004_third_party_limiters_count(tmp_path, mode):
    for i, (svc, call) in enumerate([("", "app.UseIpRateLimiting();"), ("", "app.UseClientRateLimiting();"),
                                     ("builder.Services.AddInMemoryRateLimiting();", ""),
                                     ("", "app.UseRateLimitingMiddleware();")]):
        f = scan(tmp_path / str(i), mvc(LOGIN, svc, call), mode)
        assert not got(f, "DNL-RES-004"), call or svc


def test_res004_no_sensitive_endpoint_is_clean(tmp_path, mode):
    f = scan(tmp_path, mvc("[HttpGet(\"items\")] public IActionResult List() => Ok();"), mode)
    assert not got(f, "DNL-RES-004")


def test_res004_unresolved_extension_is_review(tmp_path, mode):
    f = scan(tmp_path, mvc(LOGIN, "", "app.UseCompanyDefaults();"), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", "REVIEW")}


def test_res004_route_level_limiter_counts_for_that_route(tmp_path, mode):
    f = scan(tmp_path / "a", mvc("[EnableRateLimiting(\"auth\")]\n" + LOGIN, LIMITER, "app.UseRateLimiter();"), mode)
    assert not got(f, "DNL-RES-004")
    f = scan(tmp_path / "b", mvc(LOGIN, LIMITER, "app.UseRateLimiter();", cls_attrs="[EnableRateLimiting(\"auth\")]"), mode)
    assert not got(f, "DNL-RES-004")
    f = scan(tmp_path / "c", mvc(LOGIN, body=""), mode)
    assert got(f, "DNL-RES-004")


def test_res004_minimal_api_group_and_endpoint(tmp_path, mode):
    f = scan(tmp_path / "a", prog("", 'app.MapPost("/login", () => Results.Ok());'), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", None)}
    body = 'app.UseRateLimiter();\napp.MapPost("/login", () => Results.Ok()).RequireRateLimiting("auth");'
    f = scan(tmp_path / "b", prog(LIMITER, body), mode)
    assert not got(f, "DNL-RES-004")
    body = 'app.UseRateLimiter();\nvar g = app.MapGroup("/auth").RequireRateLimiting("auth");\ng.MapPost("/login", () => Results.Ok());'
    f = scan(tmp_path / "c", prog(LIMITER, body), mode)
    assert not got(f, "DNL-RES-004")


def test_res004_only_the_first_route_carries_the_finding(tmp_path, mode):
    ctl = LOGIN + "\n[HttpPost(\"forgot\")] public IActionResult Forgot() => Ok();\n[HttpGet(\"token\")] public IActionResult Token() => Ok();"
    f = scan(tmp_path, mvc(ctl), mode)
    hit = of(f, "DNL-RES-004")
    assert len(hit) == 1
    assert all(w in hit[0].description for w in ("login", "forgot", "token"))


def test_res004_read_only_login_page_is_not_a_target(tmp_path, mode):
    f = scan(tmp_path, mvc("[HttpGet(\"login\")] public IActionResult Login() => Ok();"), mode)
    assert not got(f, "DNL-RES-004")


def test_res004_disable_rate_limiting_reported_even_with_limiter(tmp_path, mode):
    ctl = "[HttpPost(\"login\")]\n[DisableRateLimiting]\npublic IActionResult Login() => Ok();"
    f = scan(tmp_path / "a", mvc(ctl, LIMITER, "app.UseRateLimiter();"), mode)
    hit = of(f, "DNL-RES-004")
    assert [(x.severity, x.confidence) for x in hit] == [("low", None)]
    assert hit[0].route is not None and "DisableRateLimiting" in hit[0].description
    body = 'app.MapPost("/login", () => Results.Ok()).DisableRateLimiting();'
    f = scan(tmp_path / "b", prog(LIMITER, "app.UseRateLimiter();\n" + body), mode)
    assert [(x.severity, x.confidence) for x in of(f, "DNL-RES-004")] == [("low", None)]


def test_res004_route_enable_overrides_class_disable(tmp_path, mode):
    ctl = "[EnableRateLimiting(\"auth\")]\n" + LOGIN
    f = scan(tmp_path, mvc(ctl, LIMITER, "app.UseRateLimiter();", cls_attrs="[DisableRateLimiting]"), mode)
    assert not got(f, "DNL-RES-004")


def test_res004_identity_api_endpoints(tmp_path, mode):
    f = scan(tmp_path / "a", prog("", "app.MapIdentityApi<IdentityUser>();"), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", "REVIEW")}
    f = scan(tmp_path / "b", prog(LIMITER, "app.UseRateLimiter();\napp.MapIdentityApi<IdentityUser>();"), mode)
    assert not got(f, "DNL-RES-004")


# -- RES-005 -----------------------------------------------------------------------------------------

def test_res005_unbounded_take(tmp_path, mode):
    f = scan(tmp_path, mvc("[HttpGet] public IActionResult List(int pageSize) => Ok(db.Items.Take(pageSize).ToList());"), mode)
    assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", None)}
    assert of(f, "DNL-RES-005")[0].route is not None


def test_res005_bounded_by_min_clamp_comparison_or_range(tmp_path, mode):
    ok = {
        "min": "[HttpGet] public IActionResult List(int pageSize) { pageSize = Math.Min(pageSize, 100); return Ok(db.Items.Take(pageSize).ToList()); }",
        "clamp": "[HttpGet] public IActionResult List(int limit) => Ok(db.Items.Take(Math.Clamp(limit, 1, 50)).ToList());",
        "cmp": "[HttpGet] public IActionResult List(int pageSize) { if (pageSize > 100) return BadRequest(); return Ok(db.Items.Take(pageSize).ToList()); }",
        "cmp2": "[HttpGet] public IActionResult List(int take) { if (take <= 100) return Ok(db.Items.Take(take).ToList()); return BadRequest(); }",
        "range": "[HttpGet] public IActionResult List([Range(1, 100)] int pageSize) => Ok(db.Items.Take(pageSize).ToList());",
        "local": "[HttpGet] public IActionResult List(int count) { var n = Math.Min(count, 25); return Ok(db.Items.Take(n).ToList()); }",
    }
    for name, ctl in ok.items():
        assert not got(scan(tmp_path / name, mvc(ctl), mode), "DNL-RES-005"), name


def test_res005_through_one_local(tmp_path, mode):
    ctl = "[HttpGet] public IActionResult List(int perPage) { var n = perPage; return Ok(db.Items.Take(n).ToList()); }"
    assert got(scan(tmp_path / "a", mvc(ctl), mode), "DNL-RES-005") == {("DNL-RES-005", "low", None)}
    ctl = ("[HttpGet] public IActionResult List(int perPage) { var n = perPage; if (n > 10) n = 10; "
           "return Ok(db.Items.Take(n).ToList()); }")
    assert not got(scan(tmp_path / "b", mvc(ctl), mode), "DNL-RES-005")


def test_res005_lower_bound_is_not_a_bound(tmp_path, mode):
    ctl = ("[HttpGet] public IActionResult List(int pageSize) { if (pageSize < 1) pageSize = 1; "
           "return Ok(db.Items.Take(pageSize).ToList()); }")
    assert got(scan(tmp_path, mvc(ctl), mode), "DNL-RES-005") == {("DNL-RES-005", "low", None)}


def test_res005_hand_off_is_not_reported(tmp_path, mode):
    ctl = "[HttpGet] public IActionResult List(int pageSize) => Ok(repo.List(pageSize));"
    assert not got(scan(tmp_path, mvc(ctl), mode), "DNL-RES-005")


def test_res005_name_and_type_filter(tmp_path, mode):
    ctl = "[HttpGet] public IActionResult List(int other) => Ok(db.Items.Take(other).ToList());"
    assert not got(scan(tmp_path / "a", mvc(ctl), mode), "DNL-RES-005")
    ctl = "[HttpGet] public IActionResult List(string limit) => Ok(db.Items.Take(int.Parse(limit)).ToList());"
    assert not got(scan(tmp_path / "b", mvc(ctl), mode), "DNL-RES-005")
    ctl = "[HttpGet] public IActionResult List(int? limit) => Ok(db.Items.Take(limit ?? 10).ToList());"
    assert got(scan(tmp_path / "c", mvc(ctl), mode), "DNL-RES-005") == {("DNL-RES-005", "low", None)}


def test_res005_minimal_api(tmp_path, mode):
    body = 'app.MapGet("/items", (int pageSize, AppDb db) => db.Items.Take(pageSize).ToList());'
    f = scan(tmp_path / "a", prog("", body), mode)
    assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", None)}
    body = 'app.MapGet("/items", (int pageSize, AppDb db) => db.Items.Take(Math.Min(pageSize, 100)).ToList());'
    assert not got(scan(tmp_path / "b", prog("", body), mode), "DNL-RES-005")


def test_res005_development_only_route_is_skipped(tmp_path, mode):
    body = ('if (app.Environment.IsDevelopment()) {\n'
            'app.MapGet("/items", (int pageSize, AppDb db) => db.Items.Take(pageSize).ToList());\n}')
    assert not got(scan(tmp_path, prog("", body), mode), "DNL-RES-005")


# -- fix round 1 ---------------------------------------------------------------------------------------

ENABLED = "[EnableRateLimiting(\"auth\")]\n" + LOGIN


def test_res004_route_policy_without_middleware_is_unenforced(tmp_path, mode):
    f = scan(tmp_path / "a", mvc(ENABLED, LIMITER), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", None)}
    assert "unenforced" in of(f, "DNL-RES-004")[0].description
    dev = "if (app.Environment.IsDevelopment()) { app.UseRateLimiter(); }"
    f = scan(tmp_path / "b", mvc(ENABLED, LIMITER, dev), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", None)}
    f = scan(tmp_path / "c", mvc(ENABLED, LIMITER, "if (Helper.Flag()) { app.UseRateLimiter(); }"), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", "REVIEW")}
    f = scan(tmp_path / "d", mvc(ENABLED, LIMITER, "app.UseRateLimiter();"), mode)
    assert not got(f, "DNL-RES-004")
    body = 'app.MapPost("/login", () => Results.Ok()).RequireRateLimiting("auth");'
    f = scan(tmp_path / "e", prog(LIMITER, body), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", None)}


def test_res004_identity_api_also_reported_next_to_routes(tmp_path, mode):
    f = scan(tmp_path, mvc(LOGIN, body="app.MapIdentityApi<IdentityUser>();"), mode)
    titles = [x.title for x in of(f, "DNL-RES-004")]
    assert len(titles) == 2 and any("Identity" in t for t in titles)
    f = scan(tmp_path / "b", mvc(LOGIN, LIMITER, "app.UseRateLimiter();\napp.MapIdentityApi<IdentityUser>();"), mode)
    assert not got(f, "DNL-RES-004")


def test_res005_comparison_that_guards_nothing_is_review(tmp_path, mode):
    cases = {
        "warn": "if (pageSize > 100) _log.Warn(\"big\");",
        "count": "if (items.Count > pageSize) _log.Info(\"x\");",
        "unused_min": "Math.Min(pageSize, 100);",
        "other_local": "var capped = Math.Min(pageSize, 100);",
    }
    for name, stmt in cases.items():
        ctl = ("[HttpGet] public IActionResult List(int pageSize) { " + stmt +
               " return Ok(db.Items.Take(pageSize).ToList()); }")
        f = scan(tmp_path / name, mvc(ctl), mode)
        assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", "REVIEW")}, name


def test_res005_guarding_forms_stay_clean(tmp_path, mode):
    cases = {
        "throw": "if (pageSize > 100) throw new ArgumentException();",
        "clamp_assign": "if (pageSize > 100) pageSize = 100;",
        "ternary": "pageSize = pageSize > 100 ? 100 : pageSize;",
        "or": "if (pageSize < 1 || pageSize > 100) return BadRequest();",
    }
    for name, stmt in cases.items():
        ctl = ("[HttpGet] public IActionResult List(int pageSize) { " + stmt +
               " return Ok(db.Items.Take(pageSize).ToList()); }")
        assert not got(scan(tmp_path / name, mvc(ctl), mode), "DNL-RES-005"), name


def razor(attr: str) -> dict:
    files = prog("builder.Services.AddRazorPages();", "app.MapRazorPages();")
    files["Pages/Index.cshtml"] = f"@page\n@model IndexModel\n@attribute {attr}\n"
    files["Pages/Index.cshtml.cs"] = ("using Microsoft.AspNetCore.Mvc.RazorPages;\nnamespace App;\n"
                                      "public class IndexModel : PageModel { public void OnGet() { } }\n")
    return files


def test_res001_razor_directives(tmp_path, mode):
    f = scan(tmp_path / "a", razor("[DisableRequestSizeLimit()]"), mode)
    assert len(of(f, "DNL-RES-001")) == 1 and got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    f = scan(tmp_path / "b", razor("[DisableRequestSizeLimit]"), mode)
    assert len(of(f, "DNL-RES-001")) == 1
    f = scan(tmp_path / "c", razor("[RequestSizeLimit(100 * 1024 * 1024)]"), mode)
    assert not got(f, "DNL-RES-001")
    f = scan(tmp_path / "d", razor("[RequestSizeLimit(2000L * 1024 * 1024)]"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    f = scan(tmp_path / "e", razor("[RequestFormLimits(MultipartBodyLengthLimit = long.MaxValue)]"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}
    f = scan(tmp_path / "f", razor("[RequestFormLimits(MultipartBodyLengthLimit = 1000)]"), mode)
    assert not got(f, "DNL-RES-001")
    f = scan(tmp_path / "g", razor("[RequestSizeLimit(Limits.Max)]"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}


# -- fix round 2 ---------------------------------------------------------------------------------------

def test_res001_razor_directive_never_evaluates_hostile_text(tmp_path, mode):
    import time
    for i, expr in enumerate(["9**9**9", "1 << 999999", "(" * 150 + "1" + ")" * 150, "(((1)",
                              "99999999999 * 99999999999 * 99999999999 * 99999999999"]):
        t0 = time.monotonic()
        f = scan(tmp_path / str(i), razor(f"[RequestSizeLimit({expr})]"), mode)
        assert time.monotonic() - t0 < 60, expr
        assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}, expr
    f = scan(tmp_path / "ok", razor("[RequestSizeLimit(100 * 1024 * 1024)]"), mode)
    assert not got(f, "DNL-RES-001")
    f = scan(tmp_path / "nested", razor("[RequestSizeLimit((100 * 1024) * (1024 * 1000))]"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}      # nested parentheses are read, not skipped
    f = scan(tmp_path / "shift", razor("[RequestSizeLimit(1L << 40)]"), mode)
    assert got(f, "DNL-RES-001") == {("DNL-RES-001", "low", None)}


def _list(stmt: str, fields: str = "") -> dict:
    return mvc(fields + "\n[HttpGet] public IActionResult List(int pageSize, bool isAdmin) { " + stmt +
               " return Ok(db.Items.Take(pageSize).ToList()); }")


def test_res005_only_constant_caps_on_unconditional_guards_count(tmp_path, mode):
    review = {
        "count_cmp": "if (items.Count < pageSize) return BadRequest();",
        "and_conjunct": "if (pageSize > 100 && !user.IsAdmin) return Forbid();",
        "nested_under_other_if": "if (!isAdmin) { if (pageSize > 100) return BadRequest(); }",
        "lambda_return": "if (pageSize > 100) { var f = () => { return 1; }; _log.Warn(\"x\"); }",
        "variable_threshold": "if (pageSize > limits.Max) return BadRequest();",
        "min_with_variable": "pageSize = Math.Min(pageSize, userLimit);",
        "else_if": "if (isAdmin) { } else if (pageSize > 100) return BadRequest();",
    }
    for name, stmt in review.items():
        f = scan(tmp_path / name, _list(stmt), mode)
        assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", "REVIEW")}, name
    clean = {
        "const_field": ("if (pageSize > MaxPage) return BadRequest();", "private const int MaxPage = 100;"),
        "or_chain": ("if (pageSize < 1 || pageSize > 100) throw new ArgumentException();", ""),
        "folded": ("if (pageSize >= 10 * 10 + 1) return BadRequest();", ""),
        "flipped": ("if (100 < pageSize) return BadRequest();", ""),
        "within_else": ("if (pageSize <= 100) { } else return BadRequest();", ""),
        "after_other_guard": ("if (!ModelState.IsValid) return BadRequest(); if (pageSize > 100) pageSize = 100;", ""),
    }
    for name, (stmt, fields) in clean.items():
        assert not got(scan(tmp_path / name, _list(stmt, fields), mode), "DNL-RES-005"), name


def test_res004_unenforced_lead_sentence(tmp_path, mode):
    f = scan(tmp_path, mvc(ENABLED, LIMITER), mode)
    d = of(f, "DNL-RES-004")[0].description
    assert "no RequireRateLimiting" not in d and "unenforced" in d


# -- fix round 3 ---------------------------------------------------------------------------------------

def test_fold_and_num_are_total():
    from checks.dnl.options import UNKNOWN
    from checks.dnl.rules_limits_core import _fold, _num
    for text in ["(1", "(1, 2)", "1 +", "/0", "1 / 0", "9" * 5000, "(" * 150 + "1" + ")" * 150, ")", "", "-", "1 << ",
                 "1 2", "* 3", "1 << -1", "9**9"]:
        assert _fold(text) is UNKNOWN, text[:20]
    assert _fold("100 * 1024 * 1024") == 104857600
    deep = {"k": "lit", "v": 1, "t": "number"}
    for _ in range(3000):
        deep = {"k": "bin", "op": "+", "l": deep, "r": {"k": "lit", "v": 1, "t": "number"}}
    assert _num(deep) is UNKNOWN or isinstance(_num(deep), int)
    assert _num({"k": "bin", "op": "<<", "l": {"k": "lit", "v": 1.5, "t": "number"},
                 "r": {"k": "lit", "v": 2, "t": "number"}}) is UNKNOWN
    assert _num({"k": "bin", "op": "/", "l": {"k": "lit", "v": 1, "t": "number"},
                 "r": {"k": "lit", "v": 0, "t": "number"}}) is UNKNOWN


def test_malformed_directives_never_drop_other_findings(tmp_path, mode):
    bad = ["[RequestFormLimits(MultipartBodyLengthLimit = (1, 2))]", "[RequestSizeLimit(1 +)]",
           "[RequestSizeLimit(/0)]", "[RequestSizeLimit(" + "9" * 5000 + ")]",
           "[RequestSizeLimit(" + "(" * 150 + "1" + ")" * 150 + ")]"]
    for i, attr in enumerate(bad):
        files = razor(attr)
        files["Program.cs"] = BUILDER.format(
            services="builder.Services.AddRazorPages();",
            body='app.MapRazorPages();\napp.MapGet("/items", (int pageSize, AppDb db) => db.Items.Take(pageSize).ToList());')
        f = scan(tmp_path / str(i), files, mode)
        assert ("DNL-RES-005", "low", None) in ids(f), attr[:40]
        assert ("DNL-RES-001", "low", "REVIEW") in got(f, "DNL-RES-001"), attr[:40]


def test_each_limits_sub_rule_is_isolated(tmp_path, monkeypatch, mode):
    from cfgutil import make_app, prepare_model
    from checks.dnl import rules_limits_core, rules_pipeline

    def boom(ctx):
        raise RuntimeError("synthetic")

    files = {**mvc(LOGIN, body=""), "Program.cs": BUILDER.format(
        services="builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = null);\nbuilder.Services.AddControllers();",
        body="app.MapControllers();\napp.MapGet(\"/i\", (int pageSize, AppDb db) => db.Items.Take(pageSize).ToList());")}
    for victim, expect_missing in (("_rate_limiting", "DNL-RES-004"), ("_page_sizes", "DNL-RES-005"),
                                   ("_code_limits", "DNL-RES-001")):
        root = make_app(tmp_path / victim, files)
        monkeypatch.setattr(rules_limits_core, victim, boom)
        model, refs = prepare_model(root, mode == "degraded")
        found = rules_pipeline.check(model, refs)
        have = {f.check_id for f in found}
        assert expect_missing not in have
        assert {"DNL-RES-001", "DNL-RES-004", "DNL-RES-005"} - {expect_missing} <= have, victim
        assert any(victim.strip("_") in n and "failed" in n for n in model.notes), model.notes
        monkeypatch.undo()


def _page(body: str, fields: str = "", params: str = "int pageSize") -> dict:
    return mvc(fields + f"\n[HttpGet] public IActionResult List({params}) {{ {body} }}")


def test_res005_ternary_arm_order_and_guard_order(tmp_path, mode):
    review = {
        "reversed_ternary": "var n = pageSize > 100 ? pageSize : 100; return Ok(db.Items.Take(n).ToList());",
        "reversed_within": "var n = pageSize <= 100 ? 100 : pageSize; return Ok(db.Items.Take(n).ToList());",
        "guard_after_take": "var r = db.Items.Take(pageSize).ToList(); if (pageSize > 100) return BadRequest(); return Ok(r);",
        "assign_after_take": "var r = db.Items.Take(pageSize).ToList(); if (pageSize > 100) pageSize = 100; return Ok(r);",
        "min_after_take": "var r = db.Items.Take(pageSize).ToList(); pageSize = Math.Min(pageSize, 100); return Ok(r);",
    }
    for name, body in review.items():
        f = scan(tmp_path / name, _page(body), mode)
        assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", "REVIEW")}, name
    clean = {
        "ternary": "var n = pageSize > 100 ? 100 : pageSize; return Ok(db.Items.Take(n).ToList());",
        "ternary_within": "var n = pageSize <= 100 ? pageSize : 100; return Ok(db.Items.Take(n).ToList());",
        "guard_before": "if (pageSize > 100) return BadRequest(); var r = db.Items.Take(pageSize).ToList(); return Ok(r);",
    }
    for name, body in clean.items():
        assert not got(scan(tmp_path / name, _page(body), mode), "DNL-RES-005"), name


def test_res005_parameters_and_locals_shadow_class_constants(tmp_path, mode):
    fields = "private const int max = 100;"
    take = " return Ok(db.Items.Take(pageSize).ToList());"
    f = scan(tmp_path / "param", _page("if (pageSize > max) return BadRequest();" + take, fields,
                                       "int pageSize, int max"), mode)
    assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", "REVIEW")}
    f = scan(tmp_path / "local", _page("var max = Config.Max(); if (pageSize > max) return BadRequest();" + take, fields), mode)
    assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", "REVIEW")}
    f = scan(tmp_path / "const", _page("if (pageSize > max) return BadRequest();" + take, fields), mode)
    assert not got(f, "DNL-RES-005")


def test_res004_unenforced_lead_with_review_guarded_limiter(tmp_path, mode):
    f = scan(tmp_path, mvc(ENABLED, LIMITER, "if (Helper.Flag()) { app.UseRateLimiter(); }"), mode)
    d = of(f, "DNL-RES-004")[0].description
    assert "runs no rate limiter" not in d and "certainly runs in Production" in d


# -- fix round 4 ---------------------------------------------------------------------------------------

def test_res005_conditional_carriers_do_not_cap(tmp_path, mode):
    take = " return Ok(db.Items.Take(n).ToList());"
    review = {
        "if": "var n = pageSize; if (Flag()) { n = pageSize > 100 ? 100 : pageSize; }" + take,
        "foreach": "var n = pageSize; foreach (var x in xs) { n = Math.Min(pageSize, 100); }" + take,
        "else": "var n = pageSize; if (Flag()) { } else { n = Math.Min(pageSize, 100); }" + take,
        "try": "var n = pageSize; try { n = Math.Min(pageSize, 100); } catch (Exception) { }" + take,
        "lambda": "var n = pageSize; Action a = () => { n = Math.Min(pageSize, 100); };" + take,
        "later_raw": "var n = Math.Min(pageSize, 100); if (Flag()) { n = pageSize; }" + take,
    }
    for name, body in review.items():
        f = scan(tmp_path / name, _page(body), mode)
        assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", "REVIEW")}, name
    clean = {
        "top_level": "var n = pageSize; n = Math.Min(pageSize, 100);" + take,
        "last_wins": "var n = pageSize; if (Flag()) { n = pageSize; } n = Math.Min(pageSize, 100);" + take,
        "declared": "var n = Math.Min(pageSize, 100);" + take,
    }
    for name, body in clean.items():
        assert not got(scan(tmp_path / name, _page(body), mode), "DNL-RES-005"), name


def test_res005_every_binder_shadows_a_class_constant(tmp_path, mode):
    fields = "private const int max = 100;"
    tail = " if (pageSize > max) return BadRequest(); return Ok(db.Items.Take(pageSize).ToList());"
    binders = {
        "foreach": "foreach (var max in xs) { }",
        "out_var": "int.TryParse(s, out var max);",
        "out_int": "int.TryParse(s, out int max);",
        "for": "for (int max = 0; max < 3; max++) { }",
        "catch": "try { } catch (Exception max) { }",
        "is_pattern": "if (o is int max) { }",
        "case_pattern": "switch (o) { case int max: break; }",
        "tuple": "var (max, other) = Get();",
        "lambda": "Func<int, int> f = max => max;",
        "local_fn": "int Local(int max) => max;",
    }
    for name, stmt in binders.items():
        f = scan(tmp_path / name, _page(stmt + tail, fields), mode)
        assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", "REVIEW")}, name
    assert not got(scan(tmp_path / "plain", _page(tail, fields), mode), "DNL-RES-005")


def test_malformed_directive_open_paren(tmp_path, mode):
    f = scan(tmp_path, razor("[RequestFormLimits(MultipartBodyLengthLimit = (1, 2))]"), mode)
    assert ("DNL-RES-001", "low", "REVIEW") in got(f, "DNL-RES-001")
    f = scan(tmp_path / "b", razor("[RequestSizeLimit((1)]"), mode)
    assert ("DNL-RES-001", "low", "REVIEW") in got(f, "DNL-RES-001")


def test_res004_review_guarded_limiter_wording(tmp_path, mode):
    for i, files in enumerate([mvc(ENABLED, LIMITER, "if (Helper.Flag()) { app.UseRateLimiter(); }"),
                               mvc(LOGIN, LIMITER, "if (Helper.Flag()) { app.UseRateLimiter(); }")]):
        d = of(scan(tmp_path / str(i), files, mode), "DNL-RES-004")[0].description
        assert ("none certain in Production" in d or "certainly runs in Production" in d) and "no UseRateLimiter, no third-party" not in d
        assert "certainly runs in Production (none certain in Production)" not in d


def test_unexpected_folding_error_is_a_model_note(tmp_path, monkeypatch, mode):
    from cfgutil import make_app, prepare_model
    from checks.dnl import rules_limits_core, rules_pipeline

    def boom(*a):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(rules_limits_core, "_apply", boom)
    root = make_app(tmp_path, kestrel("o.Limits.MaxRequestBodySize = 1 * 2"))
    model, refs = prepare_model(root, mode == "degraded")
    found = rules_pipeline.check(model, refs)
    assert got(found, "DNL-RES-001") == {("DNL-RES-001", "low", "REVIEW")}
    assert any("unexpected error" in n and "RuntimeError" in n for n in model.notes), model.notes


# -- fix round 5 ---------------------------------------------------------------------------------------

def test_res005_short_circuit_right_operand_is_not_a_certain_carrier(tmp_path, mode):
    take = " return Ok(db.Items.Take(n).ToList());"
    cases = {
        "and": "var n = pageSize; var ok = Flag() && (n = Math.Min(pageSize, 100)) > 0;",
        "or": "var n = pageSize; var ok = Flag() || (n = Math.Min(pageSize, 100)) > 0;",
        "coalesce": "var n = pageSize; var q = maybe ?? (n = Math.Min(pageSize, 100));",
    }
    for name, body in cases.items():
        f = scan(tmp_path / name, _page(body + take), mode)
        assert got(f, "DNL-RES-005") == {("DNL-RES-005", "low", "REVIEW")}, name


def test_res005_unreadable_source_with_a_switch_fails_closed(tmp_path, monkeypatch, mode):
    from cfgutil import make_app, prepare_model
    from checks.dnl import files, rules_pipeline

    fields = "private const int max = 100;"
    tail = " if (pageSize > max) return BadRequest(); return Ok(db.Items.Take(pageSize).ToList());"
    for name, stmt, expect in (("switch", "switch (o) { case int max: break; }", {("DNL-RES-005", "low", "REVIEW")}),
                               ("plain", "", set())):
        root = make_app(tmp_path / name, _page(stmt + tail, fields, "int pageSize, object o"))
        model, refs = prepare_model(root, mode == "degraded")

        def unreadable(path, *a, **k):
            raise OSError("synthetic")

        monkeypatch.setattr(files, "read_source", unreadable)
        found = rules_pipeline.check(model, refs)
        monkeypatch.undo()
        assert got(found, "DNL-RES-005") == expect, name
        if expect:
            assert any("case-pattern binders" in n for n in model.notes), model.notes
