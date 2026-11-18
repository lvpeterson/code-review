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
    f = scan(tmp_path / "a", mvc("[EnableRateLimiting(\"auth\")]\n" + LOGIN), mode)
    assert not got(f, "DNL-RES-004")
    f = scan(tmp_path / "b", mvc(LOGIN, cls_attrs="[EnableRateLimiting(\"auth\")]"), mode)
    assert not got(f, "DNL-RES-004")
    f = scan(tmp_path / "c", mvc(LOGIN, body=""), mode)
    assert got(f, "DNL-RES-004")


def test_res004_minimal_api_group_and_endpoint(tmp_path, mode):
    f = scan(tmp_path / "a", prog("", 'app.MapPost("/login", () => Results.Ok());'), mode)
    assert got(f, "DNL-RES-004") == {("DNL-RES-004", "low", None)}
    f = scan(tmp_path / "b", prog("", 'app.MapPost("/login", () => Results.Ok()).RequireRateLimiting("auth");'), mode)
    assert not got(f, "DNL-RES-004")
    body = 'var g = app.MapGroup("/auth").RequireRateLimiting("auth");\ng.MapPost("/login", () => Results.Ok());'
    f = scan(tmp_path / "c", prog("", body), mode)
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
