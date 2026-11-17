"""rules_pipeline_auth: cookie and session configuration (DNL-SESS-001/002/003/009) and antiforgery (DNL-CSRF-001/002)."""
from cfgutil import ids, mode, scan  # noqa: F401

BUILDER = ("var builder = WebApplication.CreateBuilder(args);\n{services}\nvar app = builder.Build();\n"
           "{body}\napp.Run();\n")


def prog(services: str, body: str = "") -> dict:
    return {"Program.cs": BUILDER.format(services=services, body=body)}


def cookie(lines: str) -> dict:
    return prog("builder.Services.AddAuthentication().AddCookie(o => { " + lines + " });")


def sess(found, cid):
    return {(f.check_id, f.severity, f.confidence) for f in found if f.check_id == cid}


def test_secure_policy_same_as_request(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;"), mode)
    assert ("DNL-SESS-001", "medium", None) in ids(f)


def test_secure_policy_none_and_always(tmp_path, mode):
    f = scan(tmp_path / "a", cookie("o.Cookie.SecurePolicy = CookieSecurePolicy.None;"), mode)
    assert ("DNL-SESS-001", "medium", None) in ids(f)
    f = scan(tmp_path / "b", cookie("o.Cookie.SecurePolicy = CookieSecurePolicy.Always;"), mode)
    assert not sess(f, "DNL-SESS-001")


def test_httponly_false(tmp_path, mode):
    f = scan(tmp_path / "a", cookie("o.Cookie.HttpOnly = false;"), mode)
    assert ("DNL-SESS-002", "low", None) in ids(f)
    f = scan(tmp_path / "b", cookie("o.Cookie.HttpOnly = true;"), mode)
    assert not sess(f, "DNL-SESS-002")


def test_samesite_none(tmp_path, mode):
    f = scan(tmp_path / "a", cookie("o.Cookie.SameSite = SameSiteMode.None;"), mode)
    assert ("DNL-SESS-009", "low", None) in ids(f)
    f = scan(tmp_path / "b", cookie("o.Cookie.SameSite = SameSiteMode.Lax;"), mode)
    assert not sess(f, "DNL-SESS-009")
    f = scan(tmp_path / "c", cookie("o.Cookie.SameSite = fromCfg;"), mode)
    assert sess(f, "DNL-SESS-009") == {("DNL-SESS-009", "low", "REVIEW")}


def test_expiry_long_sliding(tmp_path, mode):
    f = scan(tmp_path / "a", cookie("o.ExpireTimeSpan = TimeSpan.FromDays(30);"), mode)
    assert ("DNL-SESS-003", "low", None) in ids(f)
    f = scan(tmp_path / "b", cookie("o.ExpireTimeSpan = TimeSpan.FromDays(30); o.SlidingExpiration = false;"), mode)
    assert not sess(f, "DNL-SESS-003")
    f = scan(tmp_path / "c", cookie("o.ExpireTimeSpan = TimeSpan.FromMinutes(30);"), mode)
    assert not sess(f, "DNL-SESS-003")


def test_expiry_long_sliding_not_literal_is_review(tmp_path, mode):
    f = scan(tmp_path, cookie("o.ExpireTimeSpan = TimeSpan.FromDays(30); o.SlidingExpiration = slide;"), mode)
    assert sess(f, "DNL-SESS-003") == {("DNL-SESS-003", "low", "REVIEW")}


def test_session_options(tmp_path, mode):
    f = scan(tmp_path / "a", prog("builder.Services.AddSession(o => o.Cookie.HttpOnly = false);"), mode)
    assert ("DNL-SESS-002", "low", None) in ids(f)
    f = scan(tmp_path / "b", prog("builder.Services.AddSession(o => { o.IdleTimeout = TimeSpan.FromHours(48); });"), mode)
    assert ("DNL-SESS-003", "low", None) in ids(f)
    f = scan(tmp_path / "c", prog("builder.Services.AddSession(o => { o.Cookie.MaxAge = TimeSpan.FromDays(3); });"), mode)
    assert ("DNL-SESS-003", "low", None) in ids(f)
    f = scan(tmp_path / "d", prog("builder.Services.AddSession(o => { o.IdleTimeout = TimeSpan.FromMinutes(20); });"), mode)
    assert not sess(f, "DNL-SESS-003")


def test_antiforgery_cookie(tmp_path, mode):
    f = scan(tmp_path, prog("builder.Services.AddAntiforgery(o => o.Cookie.SecurePolicy = CookieSecurePolicy.None);"), mode)
    assert ("DNL-SESS-001", "medium", None) in ids(f)


def test_cookie_policy_middleware(tmp_path, mode):
    f = scan(tmp_path / "a", prog("", "app.UseCookiePolicy(new CookiePolicyOptions { Secure = CookieSecurePolicy.None });"), mode)
    assert ("DNL-SESS-001", "medium", None) in ids(f)
    f = scan(tmp_path / "b", prog("", "app.UseCookiePolicy(new CookiePolicyOptions { MinimumSameSitePolicy = SameSiteMode.None, "
                                      "HttpOnly = HttpOnlyPolicy.None });"), mode)
    assert {"DNL-SESS-009", "DNL-SESS-002"} <= {i[0] for i in ids(f)}


def test_configure_cookie_policy_options(tmp_path, mode):
    f = scan(tmp_path, prog("builder.Services.Configure<CookiePolicyOptions>(o => { o.Secure = CookieSecurePolicy.None; });"), mode)
    assert ("DNL-SESS-001", "medium", None) in ids(f)


def test_application_and_external_cookie(tmp_path, mode):
    f = scan(tmp_path / "a", prog("builder.Services.ConfigureApplicationCookie(o => { o.Cookie.HttpOnly = false; });"), mode)
    assert ("DNL-SESS-002", "low", None) in ids(f)
    f = scan(tmp_path / "b", prog("builder.Services.ConfigureExternalCookie(o => { o.Cookie.SameSite = SameSiteMode.None; });"), mode)
    assert ("DNL-SESS-009", "low", None) in ids(f)


def test_add_cookie_with_scheme(tmp_path, mode):
    f = scan(tmp_path, prog('builder.Services.AddAuthentication().AddCookie("Cookies", o => { o.Cookie.HttpOnly = false; });'), mode)
    assert ("DNL-SESS-002", "low", None) in ids(f)


def test_cookie_builder_initializer(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie = new CookieBuilder { HttpOnly = false, SameSite = SameSiteMode.None, "
                              "SecurePolicy = CookieSecurePolicy.None };"), mode)
    assert {"DNL-SESS-001", "DNL-SESS-002", "DNL-SESS-009"} <= {i[0] for i in ids(f)}


def test_non_literal_secure_policy_is_review(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie.SecurePolicy = policy;"), mode)
    assert ("DNL-SESS-001", "medium", "REVIEW") in ids(f)


def test_member_of_runtime_value_is_review(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie.SecurePolicy = settings.Policy;"), mode)
    assert ("DNL-SESS-001", "medium", "REVIEW") in ids(f)


def test_unknown_enum_member_is_review(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie.SecurePolicy = CookieSecurePolicy.Custom;"), mode)
    assert ("DNL-SESS-001", "medium", "REVIEW") in ids(f)


def test_non_literal_httponly_is_review(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie.HttpOnly = flag;"), mode)
    assert ("DNL-SESS-002", "low", "REVIEW") in ids(f)


def test_cookie_builder_from_elsewhere_is_review(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie = MakeCookie();"), mode)
    got = {i[0] for i in ids(f) if i[2] == "REVIEW"}
    assert {"DNL-SESS-001", "DNL-SESS-002"} <= got


def test_conditional_good_does_not_clear_bad(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie.SecurePolicy = CookieSecurePolicy.None; "
                              "if (x) { o.Cookie.SecurePolicy = CookieSecurePolicy.Always; }"), mode)
    assert sess(f, "DNL-SESS-001") == {("DNL-SESS-001", "medium", "REVIEW")}


def test_conditional_bad_is_review(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie.HttpOnly = true; if (x) { o.Cookie.HttpOnly = false; } "
                              "if (y) { o.Cookie.SameSite = SameSiteMode.None; }"), mode)
    assert sess(f, "DNL-SESS-002") == {("DNL-SESS-002", "low", "REVIEW")}
    assert sess(f, "DNL-SESS-009") == {("DNL-SESS-009", "low", "REVIEW")}


def test_later_unconditional_good_clears(tmp_path, mode):
    f = scan(tmp_path, cookie("o.Cookie.SecurePolicy = CookieSecurePolicy.None; "
                              "o.Cookie.SecurePolicy = CookieSecurePolicy.Always;"), mode)
    assert not sess(f, "DNL-SESS-001")


def test_conditional_long_expiry_is_review(tmp_path, mode):
    f = scan(tmp_path, cookie("o.ExpireTimeSpan = TimeSpan.FromMinutes(30); if (x) { o.ExpireTimeSpan = TimeSpan.FromDays(30); }"), mode)
    assert sess(f, "DNL-SESS-003") == {("DNL-SESS-003", "low", "REVIEW")}


def test_conditional_sliding_false_does_not_clear(tmp_path, mode):
    f = scan(tmp_path, cookie("o.ExpireTimeSpan = TimeSpan.FromDays(30); if (x) { o.SlidingExpiration = false; }"), mode)
    assert sess(f, "DNL-SESS-003") == {("DNL-SESS-003", "low", "REVIEW")}


def test_early_exit_makes_later_option_conditional(tmp_path, mode):
    f = scan(tmp_path, cookie("if (x) { return; } o.Cookie.HttpOnly = false;"), mode)
    assert sess(f, "DNL-SESS-002") == {("DNL-SESS-002", "low", "REVIEW")}


def test_development_guard_not_flagged(tmp_path, mode):
    svc = ("if (builder.Environment.IsDevelopment()) { builder.Services.AddSession(o => { "
           "o.Cookie.HttpOnly = false; o.Cookie.SecurePolicy = CookieSecurePolicy.None; "
           "o.Cookie.SameSite = SameSiteMode.None; }); }")
    f = scan(tmp_path, prog(svc), mode)
    assert not {i for i in ids(f) if i[0].startswith("DNL-SESS")}


def test_unparseable_guard_is_review(tmp_path, mode):
    svc = "if (UseWeak()) { builder.Services.AddSession(o => { o.Cookie.HttpOnly = false; }); }"
    f = scan(tmp_path, prog(svc), mode)
    assert sess(f, "DNL-SESS-002") == {("DNL-SESS-002", "low", "REVIEW")}


def test_default_add_cookie_no_options(tmp_path, mode):
    f = scan(tmp_path, prog("builder.Services.AddAuthentication().AddCookie();"), mode)
    assert not {i for i in ids(f) if i[0].startswith("DNL-SESS")}


def test_finding_points_at_the_setting(tmp_path, mode):
    src = ("var builder = WebApplication.CreateBuilder(args);\n"
           "builder.Services.AddSession(o =>\n{\n    o.Cookie.HttpOnly = false;\n});\n"
           "var app = builder.Build();\napp.Run();\n")
    f = [x for x in scan(tmp_path, {"Program.cs": src}, mode) if x.check_id == "DNL-SESS-002"]
    assert len(f) == 1 and f[0].file == "Program.cs" and f[0].line == 4


FOUR = {"DNL-SESS-001", "DNL-SESS-002", "DNL-SESS-003", "DNL-SESS-009"}


def review_ids(f):
    return {i[0] for i in ids(f) if i[2] == "REVIEW" and i[0] in FOUR}


def test_opaque_option_sources_are_review(tmp_path, mode):
    shapes = {
        "helper": "builder.Services.AddAuthentication().AddCookie(o => Configure(o));",
        "group": "builder.Services.AddAuthentication().AddCookie(ConfigureCookie);",
        "section": "builder.Services.Configure<CookiePolicyOptions>(builder.Configuration.GetSection(\"Cookie\"));",
        "variable": "builder.Services.AddSession(sessionSetup);",
        "session_helper": "builder.Services.AddSession(o => { Harden(o.Cookie); });",
        "antiforgery": "builder.Services.AddAntiforgery(Setup.Antiforgery);",
        "middleware": "",
    }
    for name, svc in shapes.items():
        body = "app.UseCookiePolicy(policyVar);" if name == "middleware" else ""
        f = scan(tmp_path / name, prog(svc, body), mode)
        # antiforgery and cookie-policy options carry no lifetime
        want = FOUR - {"DNL-SESS-003"} if name in ("section", "antiforgery", "middleware") else FOUR
        assert review_ids(f) == want, name
        assert all(x.line > 0 for x in f if x.check_id in FOUR)


def test_calls_without_options_are_silent(tmp_path, mode):
    svc = ('builder.Services.AddAuthentication().AddCookie();'
           'builder.Services.AddAuthentication().AddCookie("Cookies");'
           'builder.Services.AddAuthentication().AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);'
           'builder.Services.AddSession();')
    f = scan(tmp_path, prog(svc), mode)
    assert not review_ids(f)


def test_scheme_name_with_readable_lambda_is_not_opaque(tmp_path, mode):
    f = scan(tmp_path, prog("builder.Services.AddAuthentication().AddCookie("
                            "CookieAuthenticationDefaults.AuthenticationScheme, o => { o.Cookie.Name = \"x\"; });"), mode)
    assert not review_ids(f)


def test_non_literal_expiry_is_review(tmp_path, mode):
    f = scan(tmp_path / "a", cookie("o.ExpireTimeSpan = TimeSpan.FromMinutes(cfgMinutes);"), mode)
    assert sess(f, "DNL-SESS-003") == {("DNL-SESS-003", "low", "REVIEW")}
    f = scan(tmp_path / "b", prog("builder.Services.AddSession(o => { o.IdleTimeout = idle; });"), mode)
    assert sess(f, "DNL-SESS-003") == {("DNL-SESS-003", "low", "REVIEW")}
    f = scan(tmp_path / "c", prog("builder.Services.AddSession(o => { o.Cookie.MaxAge = null; });"), mode)
    assert not sess(f, "DNL-SESS-003")


def test_configure_filter_matches_type_names_exactly(tmp_path, mode):
    f = scan(tmp_path / "a", prog("builder.Services.Configure<MyCookiePolicyOptionsX>(o => { o.Secure = CookieSecurePolicy.None; });"), mode)
    assert not sess(f, "DNL-SESS-001")
    f = scan(tmp_path / "b", prog("builder.Services.Configure<Microsoft.AspNetCore.Builder.CookiePolicyOptions>("
                                  "o => { o.Secure = CookieSecurePolicy.None; });"), mode)
    assert ("DNL-SESS-001", "medium", None) in ids(f)


def test_method_group_on_defaults_class_is_review(tmp_path, mode):
    f = scan(tmp_path, prog("builder.Services.AddAuthentication().AddCookie(AuthDefaults.ConfigureCookie);"), mode)
    assert review_ids(f) == FOUR


def test_scheme_constants_and_bare_names(tmp_path, mode):
    f = scan(tmp_path / "a", prog("builder.Services.AddAuthentication().AddCookie("
                                  "CookieAuthenticationDefaults.AuthenticationScheme);"), mode)
    assert not review_ids(f)
    f = scan(tmp_path / "b", prog('builder.Services.AddAuthentication().AddCookie("Cookies");'), mode)
    assert not review_ids(f)
    f = scan(tmp_path / "c", prog("builder.Services.AddAuthentication().AddCookie(schemeName);"), mode)
    assert review_ids(f) == FOUR


def test_review_ids_follow_the_call_type(tmp_path, mode):
    no_life = {"DNL-SESS-001", "DNL-SESS-002", "DNL-SESS-009"}
    f = scan(tmp_path / "a", prog("", "app.UseCookiePolicy(policyVar);"), mode)
    assert review_ids(f) == no_life
    f = scan(tmp_path / "b", prog("builder.Services.AddAntiforgery(setup);"), mode)
    assert review_ids(f) == no_life
    f = scan(tmp_path / "c", prog("builder.Services.Configure<CookiePolicyOptions>(cfg.GetSection(\"C\"));"), mode)
    assert review_ids(f) == no_life
    f = scan(tmp_path / "d", prog("builder.Services.Configure<SessionOptions>(cfg.GetSection(\"S\"));"), mode)
    assert review_ids(f) == FOUR
    f = scan(tmp_path / "e", prog("builder.Services.ConfigureApplicationCookie(setup);"), mode)
    assert review_ids(f) == FOUR


# -- antiforgery (DNL-CSRF-001 reused for ASP.NET Core, DNL-CSRF-002) ----------------------------------

AF = "using Microsoft.AspNetCore.Mvc;\nnamespace App;\n"
COOKIES = "builder.Services.AddAuthentication().AddCookie();\n"


def mvc(services: str = COOKIES, body: str = "app.MapDefaultControllerRoute();", ctl: str = "",
        mvc_opts: str = "") -> dict:
    """An MVC app: `ctl` is the body of `HomeController : Controller`; `mvc_opts` the AddControllersWithViews args."""
    files = prog(f"builder.Services.AddControllersWithViews({mvc_opts});\n{services}", body)
    files["HomeController.cs"] = AF + f"public class HomeController : Controller {{\n{ctl}\n}}\n"
    return files


def af(found, *cids):
    return {(f.check_id, f.severity, f.confidence) for f in found if f.check_id in (cids or ("DNL-CSRF-001", "DNL-CSRF-002"))}


def n_of(found, cid):
    return len([x for x in found if x.check_id == cid])


SAVE = "[HttpPost] public IActionResult Save() => Ok();"
FILTER = "o => { o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()); }"


def test_csrf001_mvc_post_without_filter(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl=SAVE), mode)
    assert ("DNL-CSRF-001", "medium", None) in ids(f)
    hits = [x for x in f if x.check_id == "DNL-CSRF-001"]
    assert len(hits) == 1 and hits[0].route is not None


def test_csrf001_global_filter_clears(tmp_path, mode):
    assert not af(scan(tmp_path / "a", mvc(ctl=SAVE, mvc_opts=FILTER), mode))
    f = scan(tmp_path / "b", mvc(ctl=SAVE, mvc_opts="o => { o.Filters.Add<AutoValidateAntiforgeryTokenAttribute>(); }"), mode)
    assert not af(f)
    f = scan(tmp_path / "c", mvc(ctl=SAVE, mvc_opts="o => { o.Filters.Add(new ValidateAntiForgeryTokenAttribute()); }"), mode)
    assert not af(f)
    f = scan(tmp_path / "d", mvc(ctl=SAVE, services=COOKIES + "builder.Services.Configure<MvcOptions>(" + FILTER + ");"), mode)
    assert not af(f)


def test_csrf001_attribute_on_action_class_or_base(tmp_path, mode):
    assert not af(scan(tmp_path / "a", mvc(ctl="[HttpPost, ValidateAntiForgeryToken] public IActionResult Save() => Ok();"), mode))
    src = {"HomeController.cs": AF + "[AutoValidateAntiforgeryToken]\npublic class HomeController : Controller {\n"
                                + SAVE + "\n}\n"}
    assert not af(scan(tmp_path / "b", {**mvc(), **src}, mode))
    src = {"HomeController.cs": AF + "[AutoValidateAntiforgeryToken]\npublic abstract class BaseCtl : Controller { }\n"
                                "public class HomeController : BaseCtl {\n" + SAVE + "\n}\n"}
    assert not af(scan(tmp_path / "c", {**mvc(), **src}, mode))


def test_csrf001_not_for_token_only_app(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl=SAVE, services="builder.Services.AddAuthentication().AddJwtBearer();\n"), mode)
    assert not af(f)


def test_csrf001_not_for_api_controller_or_get_or_no_verb(tmp_path, mode):
    api = {"HomeController.cs": AF + "[ApiController]\npublic class HomeController : ControllerBase {\n" + SAVE + "\n}\n"}
    assert not af(scan(tmp_path / "a", {**mvc(), **api}, mode))
    assert not af(scan(tmp_path / "b", mvc(ctl="[HttpGet] public IActionResult Show() => Ok();"), mode))
    assert not af(scan(tmp_path / "c", mvc(ctl="public IActionResult Save() => Ok();"), mode))


def razor(model_src: str, services: str = COOKIES) -> dict:
    files = prog("builder.Services.AddRazorPages();\n" + services, "app.MapRazorPages();")
    files["Pages/Index.cshtml"] = "@page\n@model IndexModel\n"
    files["Pages/Index.cshtml.cs"] = ("using Microsoft.AspNetCore.Mvc;\nusing Microsoft.AspNetCore.Mvc.RazorPages;\n"
                                      "namespace App;\n" + model_src)
    return files


def test_razor_page_post_is_not_csrf001(tmp_path, mode):
    f = scan(tmp_path, razor("public class IndexModel : PageModel { public void OnPost() { } }"), mode)
    assert not af(f)


def test_csrf002_ignore_on_action(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl="[HttpPost, IgnoreAntiforgeryToken] public IActionResult Save() => Ok();"), mode)
    assert af(f) == {("DNL-CSRF-002", "medium", None)}
    assert all(x.route is not None for x in f if x.check_id == "DNL-CSRF-002")


def test_csrf002_ignore_on_controller_class_and_base(tmp_path, mode):
    src = {"HomeController.cs": AF + "[IgnoreAntiforgeryToken]\npublic class HomeController : Controller {\n"
                                + SAVE + "\n[HttpGet] public IActionResult Show() => Ok();\n}\n"}
    f = scan(tmp_path / "a", {**mvc(), **src}, mode)
    assert af(f) == {("DNL-CSRF-002", "medium", None)} and n_of(f, "DNL-CSRF-002") == 1
    src = {"HomeController.cs": AF + "[IgnoreAntiforgeryToken]\npublic abstract class BaseCtl : Controller { }\n"
                                "public class HomeController : BaseCtl {\n" + SAVE + "\n}\n"}
    assert af(scan(tmp_path / "b", {**mvc(), **src}, mode)) == {("DNL-CSRF-002", "medium", None)}


def test_csrf002_validate_on_action_beats_class_ignore(tmp_path, mode):
    src = {"HomeController.cs": AF + "[IgnoreAntiforgeryToken]\npublic class HomeController : Controller {\n"
                                "[HttpPost, ValidateAntiForgeryToken] public IActionResult Save() => Ok();\n}\n"}
    assert not af(scan(tmp_path, {**mvc(), **src}, mode))


def test_csrf002_ignore_on_razor_page_class_and_handler(tmp_path, mode):
    f = scan(tmp_path / "a", razor("[IgnoreAntiforgeryToken]\npublic class IndexModel : PageModel { public void OnPost() { } "
                                   "public void OnGet() { } }"), mode)
    assert af(f) == {("DNL-CSRF-002", "medium", None)} and n_of(f, "DNL-CSRF-002") == 1
    f = scan(tmp_path / "b", razor("public class IndexModel : PageModel { [IgnoreAntiforgeryToken] public void OnPost() { } }"), mode)
    assert af(f) == {("DNL-CSRF-002", "medium", None)}


def test_csrf002_global_ignore_filter(tmp_path, mode):
    opts = "o => { o.Filters.Add(new IgnoreAntiforgeryTokenAttribute()); }"
    f = scan(tmp_path / "a", mvc(ctl=SAVE + "\n[HttpGet] public IActionResult Show() => Ok();", mvc_opts=opts), mode)
    assert af(f) == {("DNL-CSRF-002", "medium", None)} and n_of(f, "DNL-CSRF-002") == 1
    # an explicit [ValidateAntiForgeryToken] on the action is the nearer policy
    f = scan(tmp_path / "b", mvc(ctl="[HttpPost, ValidateAntiForgeryToken] public IActionResult Save() => Ok();",
                                 mvc_opts=opts), mode)
    assert not af(f)
    # a global ignore that sits under a condition is only REVIEW
    cond = "o => { if (flag) { o.Filters.Add(new IgnoreAntiforgeryTokenAttribute()); } }"
    f = scan(tmp_path / "c", mvc(ctl=SAVE, mvc_opts=cond), mode)
    assert ("DNL-CSRF-002", "medium", "REVIEW") in af(f)


FORM = 'app.MapPost("/up", ([FromForm] IFormFile f) => 1).DisableAntiforgery();'


def minimal(body: str, services: str = COOKIES) -> dict:
    return prog(services, body)


def test_csrf002_minimal_api_disable_antiforgery_with_form(tmp_path, mode):
    f = scan(tmp_path / "a", minimal(FORM), mode)
    assert af(f) == {("DNL-CSRF-002", "medium", None)}
    f = scan(tmp_path / "b", minimal('app.MapPost("/up", (IFormCollection c) => 1).DisableAntiforgery();'), mode)
    assert af(f) == {("DNL-CSRF-002", "medium", None)}
    # no form binding: antiforgery does not apply, so nothing is switched off
    f = scan(tmp_path / "c", minimal('app.MapPost("/up", (int id) => 1).DisableAntiforgery();'), mode)
    assert not af(f)
    # form binding but antiforgery stays on
    f = scan(tmp_path / "d", minimal('app.MapPost("/up", ([FromForm] IFormFile f) => 1);'), mode)
    assert not af(f)
    # token-only app: no cookie to ride on
    f = scan(tmp_path / "e", minimal(FORM, "builder.Services.AddAuthentication().AddJwtBearer();\n"), mode)
    assert not af(f)


def test_csrf002_minimal_api_group_and_unresolved_handler(tmp_path, mode):
    grp = 'var g = app.MapGroup("/g").DisableAntiforgery();\ng.MapPost("/up", ([FromForm] IFormFile f) => 1);'
    assert af(scan(tmp_path / "a", minimal(grp), mode)) == {("DNL-CSRF-002", "medium", None)}
    f = scan(tmp_path / "b", minimal('app.MapPost("/up", Handlers.Upload).DisableAntiforgery();'), mode)
    assert af(f) == {("DNL-CSRF-002", "medium", "REVIEW")}


def test_csrf002_development_guard(tmp_path, mode):
    dev = "if (app.Environment.IsDevelopment()) {\n" + FORM + "\n}"
    assert not af(scan(tmp_path / "a", minimal(dev), mode))
    odd = "if (Flag()) {\n" + FORM + "\n}"
    assert af(scan(tmp_path / "b", minimal(odd), mode)) == {("DNL-CSRF-002", "medium", "REVIEW")}
    src = {"HomeController.cs": AF + "[IgnoreAntiforgeryToken]\npublic class HomeController : Controller {\n" + SAVE + "\n}\n"}
    f = scan(tmp_path / "c", {**mvc(body="if (app.Environment.IsDevelopment()) { app.MapDefaultControllerRoute(); }"), **src}, mode)
    assert not af(f, "DNL-CSRF-002")


def test_csrf001_unresolved_services_call_is_review(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl=SAVE, services="builder.Services.AddCompanyAuth();\n"), mode)
    assert af(f) == {("DNL-CSRF-001", "medium", "REVIEW")}


def test_csrf001_opaque_add_authentication_is_review(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl=SAVE, services="builder.Services.AddAuthentication(SetupAuth).AddJwtBearer();\n"), mode)
    assert af(f) == {("DNL-CSRF-001", "medium", "REVIEW")}


def test_csrf001_other_cookie_registrations(tmp_path, mode):
    for i, svc in enumerate(("builder.Services.AddDefaultIdentity<IdentityUser>();\n",
                             "builder.Services.AddIdentity<IdentityUser, IdentityRole>();\n",
                             "builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);\n")):
        f = scan(tmp_path / str(i), mvc(ctl=SAVE, services=svc), mode)
        assert ("DNL-CSRF-001", "medium", None) in af(f), svc


def test_csrf001_cookie_under_unparsed_guard_is_review(tmp_path, mode):
    svc = "if (Flag()) { builder.Services.AddAuthentication().AddCookie(); }\n"
    f = scan(tmp_path, mvc(ctl=SAVE, services=svc), mode)
    assert af(f) == {("DNL-CSRF-001", "medium", "REVIEW")}


def test_csrf001_conditional_or_guarded_global_filter_is_review(tmp_path, mode):
    cond = "o => { if (flag) { o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()); } }"
    assert af(scan(tmp_path / "a", mvc(ctl=SAVE, mvc_opts=cond), mode)) == {("DNL-CSRF-001", "medium", "REVIEW")}
    guarded = COOKIES + "if (Flag()) { builder.Services.Configure<MvcOptions>(" + FILTER + "); }\n"
    assert af(scan(tmp_path / "b", mvc(ctl=SAVE, services=guarded), mode)) == {("DNL-CSRF-001", "medium", "REVIEW")}
    # a filter that only runs in Development never clears it
    dev = COOKIES + "if (builder.Environment.IsDevelopment()) { builder.Services.Configure<MvcOptions>(" + FILTER + "); }\n"
    assert af(scan(tmp_path / "c", mvc(ctl=SAVE, services=dev), mode)) == {("DNL-CSRF-001", "medium", None)}


def test_csrf_opaque_mvc_options(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl=SAVE, mvc_opts="ConfigureMvc"), mode)
    assert af(f, "DNL-CSRF-001") == {("DNL-CSRF-001", "medium", "REVIEW")}
    assert ("DNL-CSRF-002", "medium", "REVIEW") in af(f)
    f = scan(tmp_path / "b", mvc(ctl=SAVE, mvc_opts="o => Harden(o)"), mode)
    assert af(f, "DNL-CSRF-001") == {("DNL-CSRF-001", "medium", "REVIEW")}
    assert ("DNL-CSRF-002", "medium", "REVIEW") in af(f)


def test_csrf_no_opaque_review_for_default_mvc_calls(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl="[HttpGet] public IActionResult Show() => Ok();"), mode)
    assert not af(f)


# -- antiforgery fix round 1 -----------------------------------------------------------------------------

def test_csrf001_unresolved_services_call_may_add_a_global_filter(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl=SAVE, services=COOKIES + "builder.Services.AddCompanyMvc();\n"), mode)
    got = af(f, "DNL-CSRF-001")
    assert got == {("DNL-CSRF-001", "medium", "REVIEW")}
    assert "AddCompanyMvc" in [x for x in f if x.check_id == "DNL-CSRF-001"][0].description


def test_csrf001_route_environment(tmp_path, mode):
    dev = "if (app.Environment.IsDevelopment()) { app.MapDefaultControllerRoute(); }"
    assert not af(scan(tmp_path / "a", mvc(ctl=SAVE, body=dev), mode), "DNL-CSRF-001")
    odd = "if (Flag()) { app.MapDefaultControllerRoute(); }"
    assert af(scan(tmp_path / "b", mvc(ctl=SAVE, body=odd), mode), "DNL-CSRF-001") == {("DNL-CSRF-001", "medium", "REVIEW")}


def test_csrf001_no_host_project_is_review(tmp_path, mode):
    files = {"HomeController.cs": AF + "public class HomeController : Controller {\n" + SAVE + "\n}\n"}
    f = scan(tmp_path, files, mode, sdk="Microsoft.NET.Sdk")
    assert af(f, "DNL-CSRF-001") == {("DNL-CSRF-001", "medium", "REVIEW")}
    assert "no host project" in [x for x in f if x.check_id == "DNL-CSRF-001"][0].description


def test_csrf002_form_types_in_arrays_and_generics(tmp_path, mode):
    for i, t in enumerate(("IFormFile[]", "List<IFormFile>", "IEnumerable<IFormFile>", "IFormFileCollection")):
        body = f'app.MapPost("/up", ({t} f) => 1).DisableAntiforgery();'
        assert af(scan(tmp_path / str(i), minimal(body), mode)) == {("DNL-CSRF-002", "medium", None)}, t


def test_csrf002_untraced_disable_antiforgery_is_review(tmp_path, mode):
    body = 'app.MapPost("/up", ([FromForm] IFormFile f) => 1).Foo().DisableAntiforgery();'
    assert af(scan(tmp_path / "a", minimal(body), mode)) == {("DNL-CSRF-002", "medium", "REVIEW")}
    body = 'app.MapPost("/up", (int id) => 1).Foo().DisableAntiforgery();'
    assert not af(scan(tmp_path / "b", minimal(body), mode))


def test_csrf002_page_attribute_directive(tmp_path, mode):
    files = prog("builder.Services.AddRazorPages();\n" + COOKIES, "app.MapRazorPages();")
    files["Pages/Index.cshtml"] = "@page\n@model MissingModel\n@attribute [IgnoreAntiforgeryToken]\n"
    assert af(scan(tmp_path / "a", files, mode)) == {("DNL-CSRF-002", "medium", "REVIEW")}
    f = razor("public class IndexModel : PageModel { public void OnPost() { } }")
    f["Pages/Index.cshtml"] = "@page\n@model IndexModel\n@attribute [IgnoreAntiforgeryToken]\n"
    assert af(scan(tmp_path / "b", f, mode)) == {("DNL-CSRF-002", "medium", None)}


def test_csrf001_expression_bodied_options_lambda_clears(tmp_path, mode):
    f = scan(tmp_path, mvc(ctl=SAVE, mvc_opts="o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute())"), mode)
    assert not af(f)


# -- JWT and OIDC validation (DNL-SESS-010, DNL-SESS-011, DNL-CFG-012, DNL-SEC-004) -------------------------

def jwt(lines: str, extra: str = "") -> dict:
    return prog(extra + "builder.Services.AddAuthentication().AddJwtBearer(o => { " + lines + " });")


def tvp(inits: str) -> dict:
    return jwt("o.TokenValidationParameters = new TokenValidationParameters { " + inits + " };")


def tok(found, *cids):
    return {(f.check_id, f.severity, f.confidence) for f in found if f.check_id in cids}


def test_validate_flags_false_are_medium(tmp_path, mode):
    f = scan(tmp_path, tvp("ValidateIssuer = false, ValidateAudience = false"), mode)
    hits = [x for x in f if x.check_id == "DNL-SESS-010"]
    assert len(hits) == 2 and tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", None)}


def test_lifetime_and_expiration_false(tmp_path, mode):
    f = scan(tmp_path, tvp("ValidateLifetime = false, RequireExpirationTime = false"), mode)
    assert len([x for x in f if x.check_id == "DNL-SESS-010"]) == 2
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", None)}


def test_signature_checks_off_are_high(tmp_path, mode):
    f = scan(tmp_path / "a", tvp("ValidateIssuerSigningKey = false"), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "high", None)}
    f = scan(tmp_path / "b", tvp("RequireSignedTokens = false"), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "high", None)}


def test_signature_validator_returning_token_unchecked(tmp_path, mode):
    f = scan(tmp_path / "a", tvp("SignatureValidator = (t, p) => new JwtSecurityToken(t)"), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "high", None)}
    f = scan(tmp_path / "b", tvp("SignatureValidator = (t, p) => { return new JsonWebToken(t); }"), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "high", None)}


def test_custom_signature_validator_is_review(tmp_path, mode):
    f = scan(tmp_path, tvp("SignatureValidator = (t, p) => MyLib.Verify(t)"), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "high", "REVIEW")}


def test_non_literal_validate_value_is_review(tmp_path, mode):
    f = scan(tmp_path / "a", tvp('ValidateIssuer = cfg.GetValue<bool>("V")'), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", "REVIEW")}
    assert "cfg.GetValue" in [x for x in f if x.check_id == "DNL-SESS-010"][0].description
    f = scan(tmp_path / "b", tvp("ValidateAudience = Flags.Audience"), mode)     # enum-looking member
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", "REVIEW")}


def test_validation_on_is_clean(tmp_path, mode):
    f = scan(tmp_path, tvp('ValidateLifetime = true, ValidateIssuer = true, ValidAudience = "api"'), mode)
    assert not tok(f, "DNL-SESS-010", "DNL-SESS-011")


def test_valid_audience_does_not_excuse_literal_false(tmp_path, mode):
    f = scan(tmp_path, tvp('ValidateAudience = false, ValidAudience = "api"'), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", None)}


def test_member_assignment_form(tmp_path, mode):
    f = scan(tmp_path, jwt("o.TokenValidationParameters.ValidateIssuer = false;"), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", None)}


def test_tvp_in_local_resolved(tmp_path, mode):
    lines = ("var p = new TokenValidationParameters { ValidateIssuer = false };\n"
             "p.ValidateLifetime = false;\no.TokenValidationParameters = p;")
    f = scan(tmp_path, jwt(lines), mode)
    assert len([x for x in f if x.check_id == "DNL-SESS-010"]) == 2
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", None)}


def test_tvp_in_enclosing_method_local(tmp_path, mode):
    files = prog("var p = new TokenValidationParameters { ValidateIssuer = false };\n"
                 "builder.Services.AddAuthentication().AddJwtBearer(o => { o.TokenValidationParameters = p; });")
    assert tok(scan(tmp_path, files, mode), "DNL-SESS-010") == {("DNL-SESS-010", "medium", None)}


def test_tvp_from_helper_or_unknown_local_is_review(tmp_path, mode):
    for i, expr in enumerate(("Build(cfg)", "unknownLocal", "_field", "this.Params")):
        f = scan(tmp_path / str(i), jwt(f"o.TokenValidationParameters = {expr};"), mode)
        assert ("DNL-SESS-010", "medium", "REVIEW") in tok(f, "DNL-SESS-010"), expr


def test_tvp_local_handed_to_helper_is_review(tmp_path, mode):
    lines = "var p = new TokenValidationParameters();\nHarden(p);\no.TokenValidationParameters = p;"
    f = scan(tmp_path, jwt(lines), mode)
    assert ("DNL-SESS-010", "medium", "REVIEW") in tok(f, "DNL-SESS-010")


def test_options_handed_to_helper_or_method_group_is_review(tmp_path, mode):
    f = scan(tmp_path / "a", prog("builder.Services.AddAuthentication().AddJwtBearer(o => Harden(o));"), mode)
    assert ("DNL-SESS-010", "medium", "REVIEW") in tok(f, "DNL-SESS-010")
    assert ("DNL-CFG-012", "medium", "REVIEW") in tok(f, "DNL-CFG-012")
    f = scan(tmp_path / "b", prog("builder.Services.AddAuthentication().AddJwtBearer(ConfigureJwt);"), mode)
    assert ("DNL-SESS-010", "medium", "REVIEW") in tok(f, "DNL-SESS-010")
    f = scan(tmp_path / "c", prog("builder.Services.AddAuthentication().AddJwtBearer();"), mode)
    assert not tok(f, "DNL-SESS-010", "DNL-CFG-012")


def test_conditional_values(tmp_path, mode):
    f = scan(tmp_path / "a", jwt("if (cfg.Strict) { o.TokenValidationParameters.ValidateIssuer = false; }"), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", "REVIEW")}
    lines = ("o.TokenValidationParameters.ValidateIssuer = false;\n"
             "if (cfg.Strict) { o.TokenValidationParameters.ValidateIssuer = true; }")
    f = scan(tmp_path / "b", jwt(lines), mode)      # a conditional good value never clears a bad one
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "medium", "REVIEW")}


def test_development_guard_in_lambda(tmp_path, mode):
    lines = ("if (builder.Environment.IsDevelopment()) { o.RequireHttpsMetadata = false;\n"
             " o.TokenValidationParameters.ValidateIssuer = false; }")
    assert not tok(scan(tmp_path / "a", jwt(lines), mode), "DNL-SESS-010", "DNL-CFG-012")
    lines = ("if (builder.Environment.IsDevelopment()) { o.RequireHttpsMetadata = true; }\n"
             "else { o.RequireHttpsMetadata = false; }")
    assert tok(scan(tmp_path / "b", jwt(lines), mode), "DNL-CFG-012") == {("DNL-CFG-012", "medium", None)}
    lines = "if (Check(builder.Environment)) { o.RequireHttpsMetadata = false; }"
    assert tok(scan(tmp_path / "c", jwt(lines), mode), "DNL-CFG-012") == {("DNL-CFG-012", "medium", "REVIEW")}


def test_development_only_registration_not_flagged(tmp_path, mode):
    files = prog("if (builder.Environment.IsDevelopment()) { builder.Services.AddAuthentication()"
                 ".AddJwtBearer(o => { o.RequireHttpsMetadata = false; }); }")
    assert not tok(scan(tmp_path, files, mode), "DNL-CFG-012")


def test_clock_skew(tmp_path, mode):
    f = scan(tmp_path / "a", tvp("ClockSkew = TimeSpan.FromHours(1)"), mode)
    assert tok(f, "DNL-SESS-011") == {("DNL-SESS-011", "low", None)}
    for i, v in enumerate(("TimeSpan.Zero", "TimeSpan.FromMinutes(5)", "TimeSpan.FromMinutes(10)")):
        assert not tok(scan(tmp_path / f"ok{i}", tvp(f"ClockSkew = {v}"), mode), "DNL-SESS-011"), v
    f = scan(tmp_path / "r", tvp("ClockSkew = cfg.Skew"), mode)
    assert tok(f, "DNL-SESS-011") == {("DNL-SESS-011", "low", "REVIEW")}


def test_require_https_metadata_false(tmp_path, mode):
    f = scan(tmp_path / "a", jwt("o.RequireHttpsMetadata = false;"), mode)
    assert tok(f, "DNL-CFG-012") == {("DNL-CFG-012", "medium", None)}
    f = scan(tmp_path / "b", jwt("o.RequireHttpsMetadata = !builder.Environment.IsDevelopment();"), mode)
    assert tok(f, "DNL-CFG-012") == {("DNL-CFG-012", "medium", "REVIEW")}
    f = scan(tmp_path / "c", jwt("o.RequireHttpsMetadata = true;"), mode)
    assert not tok(f, "DNL-CFG-012")


def test_require_https_metadata_oidc_and_configure(tmp_path, mode):
    f = scan(tmp_path / "a", prog("builder.Services.AddAuthentication().AddOpenIdConnect(o => "
                                  "{ o.RequireHttpsMetadata = false; });"), mode)
    assert tok(f, "DNL-CFG-012") == {("DNL-CFG-012", "medium", None)}
    f = scan(tmp_path / "b", prog("builder.Services.Configure<JwtBearerOptions>(o => "
                                  "{ o.RequireHttpsMetadata = false; });"), mode)
    assert tok(f, "DNL-CFG-012") == {("DNL-CFG-012", "medium", None)}
    f = scan(tmp_path / "c", prog("builder.Services.Configure<SomethingElse>(o => { o.RequireHttpsMetadata = false; });"),
             mode)
    assert not tok(f, "DNL-CFG-012")


def test_appsettings_require_https_metadata(tmp_path, mode):
    base = prog("builder.Services.AddAuthentication().AddJwtBearer();")
    f = scan(tmp_path / "a", {**base, "appsettings.json": '{\n  "Auth": {\n    "RequireHttpsMetadata": false\n  }\n}\n'}, mode)
    hits = [x for x in f if x.check_id == "DNL-CFG-012"]
    assert [(h.file, h.line, h.severity, h.confidence) for h in hits] == [("appsettings.json", 3, "medium", None)]
    f = scan(tmp_path / "b", {**base, "appsettings.json": '{"Auth": {"RequireHttpsMetadata": false}}',
                              "appsettings.Production.json": '{"Auth": {"RequireHttpsMetadata": true}}'}, mode)
    assert not tok(f, "DNL-CFG-012")
    f = scan(tmp_path / "c", {**base, "appsettings.Development.json": '{"Auth": {"RequireHttpsMetadata": false}}'}, mode)
    assert not tok(f, "DNL-CFG-012")
    f = scan(tmp_path / "d", {**base, "appsettings.json": '{"Auth": {"RequireHttpsMetadata": "${X}"}}'}, mode)
    assert tok(f, "DNL-CFG-012") == {("DNL-CFG-012", "medium", "REVIEW")}


KEY = 'new SymmetricSecurityKey(Encoding.UTF8.GetBytes("super-secret-signing-key-123456"))'


def test_symmetric_key_literal(tmp_path, mode):
    f = scan(tmp_path, tvp("IssuerSigningKey = " + KEY), mode)
    assert tok(f, "DNL-SEC-004") == {("DNL-SEC-004", "high", None)}
    hit = [x for x in f if x.check_id == "DNL-SEC-004"][0]
    assert (hit.file, hit.line) == ("Program.cs", 2)


def test_symmetric_key_other_literal_forms(tmp_path, mode):
    for i, src in enumerate(('Convert.FromBase64String("c3VwZXItc2VjcmV0LXNpZ25pbmcta2V5")',
                             'Encoding.ASCII.GetBytes("changeme")')):
        f = scan(tmp_path / str(i), prog(f"var k = new SymmetricSecurityKey({src});"), mode)
        assert tok(f, "DNL-SEC-004") == {("DNL-SEC-004", "high", None)}, src


def test_symmetric_key_via_const_and_field(tmp_path, mode):
    files = prog('const string K = "super-secret-signing-key-123456";\n'
                 "var k = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(K));")
    assert tok(scan(tmp_path / "a", files, mode), "DNL-SEC-004") == {("DNL-SEC-004", "high", None)}
    files = {"Keys.cs": 'public static class Keys { public const string Jwt = "super-secret-signing-key-123456"; }\n'
                        "public class Maker { public object Make() => new SymmetricSecurityKey("
                        "Encoding.UTF8.GetBytes(Keys.Jwt)); }\n"}
    assert tok(scan(tmp_path / "b", files, mode), "DNL-SEC-004") == {("DNL-SEC-004", "high", None)}
    files = {"Maker.cs": 'public class Maker { private static readonly string K = "super-secret-signing-key-123456";\n'
                         "public object Make() => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(K)); }\n"}
    assert tok(scan(tmp_path / "c", files, mode), "DNL-SEC-004") == {("DNL-SEC-004", "high", None)}


def test_symmetric_key_from_config_is_silent(tmp_path, mode):
    for i, src in enumerate(('Encoding.UTF8.GetBytes(config["Jwt:Key"])', "Encoding.UTF8.GetBytes(unknownLocal)",
                             'Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("K"))',
                             'Encoding.UTF8.GetBytes("")', 'Encoding.UTF8.GetBytes("<your key here>")',
                             'Encoding.UTF8.GetBytes("{JwtKey}")')):
        f = scan(tmp_path / str(i), prog(f"var k = new SymmetricSecurityKey({src});"), mode)
        assert not tok(f, "DNL-SEC-004"), src


def test_symmetric_key_reassigned_local_is_review(tmp_path, mode):
    files = prog('var s = "super-secret-signing-key-123456";\ns = config["Jwt:Key"];\n'
                 "var k = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(s));")
    assert tok(scan(tmp_path, files, mode), "DNL-SEC-004") == {("DNL-SEC-004", "high", "REVIEW")}


def test_symmetric_key_environment_guards(tmp_path, mode):
    dev = prog("if (builder.Environment.IsDevelopment()) { var k = " + KEY + "; }")
    assert not tok(scan(tmp_path / "a", dev, mode), "DNL-SEC-004")
    odd = prog("if (Check(builder.Environment)) { var k = " + KEY + "; }")
    assert tok(scan(tmp_path / "b", odd, mode), "DNL-SEC-004") == {("DNL-SEC-004", "high", "REVIEW")}
    prod = prog("if (!builder.Environment.IsDevelopment()) { var k = " + KEY + "; }")
    assert tok(scan(tmp_path / "c", prod, mode), "DNL-SEC-004") == {("DNL-SEC-004", "high", None)}


def test_microsoft_identity_web_api_config_section_is_not_opaque(tmp_path, mode):
    files = prog("builder.Services.AddAuthentication().AddMicrosoftIdentityWebApi("
                 'builder.Configuration.GetSection("AzureAd"));')
    assert not tok(scan(tmp_path, files, mode), "DNL-SESS-010", "DNL-CFG-012")


def test_tvp_constructor_arguments_are_review(tmp_path, mode):
    f = scan(tmp_path / "a", jwt("o.TokenValidationParameters = new TokenValidationParameters(source);"), mode)
    assert ("DNL-SESS-010", "medium", "REVIEW") in tok(f, "DNL-SESS-010")
    assert ("DNL-SESS-011", "low", "REVIEW") in tok(f, "DNL-SESS-011")
    f = scan(tmp_path / "b", jwt("var p = new TokenValidationParameters(source);\no.TokenValidationParameters = p;"), mode)
    assert ("DNL-SESS-010", "medium", "REVIEW") in tok(f, "DNL-SESS-010")
    f = scan(tmp_path / "c", jwt("o.TokenValidationParameters = new TokenValidationParameters();"), mode)
    assert not tok(f, "DNL-SESS-010", "DNL-SESS-011")
    f = scan(tmp_path / "d", jwt("o.TokenValidationParameters = source.Clone();"), mode)
    assert ("DNL-SESS-010", "medium", "REVIEW") in tok(f, "DNL-SESS-010")


def test_block_signature_validator_with_checks_is_review(tmp_path, mode):
    body = "SignatureValidator = (t, p) => { Verify(t); return new JwtSecurityToken(t); }"
    f = scan(tmp_path / "a", tvp(body), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "high", "REVIEW")}
    f = scan(tmp_path / "b", tvp("SignatureValidator = (t, p) => { return new JwtSecurityToken(t); }"), mode)
    assert tok(f, "DNL-SESS-010") == {("DNL-SESS-010", "high", None)}


def test_symmetric_key_field_reassigned_elsewhere_is_review(tmp_path, mode):
    keys = 'public static class Keys { public static string Jwt = "super-secret-signing-key-123456"; }\n'
    maker = "public class Maker { public object Make() => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Keys.Jwt)); }\n"
    other = 'public class Boot { public void Load(IConfiguration c) { Keys.Jwt = c["Jwt:Key"]; } }\n'
    f = scan(tmp_path / "a", {"Keys.cs": keys, "Maker.cs": maker, "Boot.cs": other}, mode)
    assert tok(f, "DNL-SEC-004") == {("DNL-SEC-004", "high", "REVIEW")}
    f = scan(tmp_path / "b", {"Keys.cs": keys, "Maker.cs": maker}, mode)
    assert tok(f, "DNL-SEC-004") == {("DNL-SEC-004", "high", None)}
    ctor = ('public class Maker { private static string K = "super-secret-signing-key-123456";\n'
            'public Maker(IConfiguration c) { K = c["Jwt:Key"]; }\n'
            "public object Make() => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(K)); }\n")
    f = scan(tmp_path / "c", {"Maker.cs": ctor}, mode)
    assert tok(f, "DNL-SEC-004") == {("DNL-SEC-004", "high", "REVIEW")}


def test_ms_identity_method_group_named_like_config_is_opaque(tmp_path, mode):
    for i, arg in enumerate(("ConfigureJwt", "configureJwt")):
        files = prog(f"builder.Services.AddAuthentication().AddMicrosoftIdentityWebApi({arg});")
        f = scan(tmp_path / str(i), files, mode)
        assert ("DNL-SESS-010", "medium", "REVIEW") in tok(f, "DNL-SESS-010"), arg
