"""rules_pipeline_auth: cookie and session configuration (DNL-SESS-001/002/003/009)."""
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
