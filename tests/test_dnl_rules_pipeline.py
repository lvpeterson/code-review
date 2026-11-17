"""rules_pipeline skeleton: shared config context, per-project pipelines, absence confidence."""
from cfgutil import ids, make_app, mode, prepare_model, run_check, scan  # noqa: F401

from checks.dnl import cfgctx, rules_pipeline

PROGRAM = "var app = WebApplication.CreateBuilder(args).Build();\n{body}\napp.Run();\n"
WITH_BUILDER = ("var builder = WebApplication.CreateBuilder(args);\n{services}\nvar app = builder.Build();\n"
                "{body}\napp.Run();\n")


def ctx_of(tmp_path, files, mode_):
    model, refs = prepare_model(make_app(tmp_path, files), degraded=(mode_ == "degraded"))
    return cfgctx.build_ctx(model, refs)


def test_library_project_reports_nothing(tmp_path, mode):
    files = {"Thing.cs": "public class Thing { public int Value() => 1; }\n"}
    root = make_app(tmp_path, files, sdk="Microsoft.NET.Sdk")
    assert run_check(root, degraded=(mode == "degraded")) == []
    model, refs = prepare_model(root, degraded=(mode == "degraded"))
    assert cfgctx.build_ctx(model, refs).pipes == []


def test_two_web_projects_reported_separately(tmp_path, mode):
    prog = PROGRAM.format(body="app.UseDeveloperExceptionPage();")
    csproj = make_app(tmp_path / "tmpl", {}) / "App.csproj"
    for d in ("A", "B"):
        sub = tmp_path / d
        sub.mkdir(parents=True, exist_ok=True)
        (sub / f"{d}.csproj").write_text(csproj.read_text(), encoding="utf-8")
        (sub / "Program.cs").write_text(prog, encoding="utf-8")
    (tmp_path / "tmpl" / "App.csproj").unlink()
    model, refs = prepare_model(tmp_path, degraded=(mode == "degraded"))
    ctx = cfgctx.build_ctx(model, refs)
    assert len(ctx.pipes) == 2
    assert len({p.project.name for p in ctx.pipes}) == 2
    found = [f for f in rules_pipeline.check(model, refs) if f.check_id == "DNL-CFG-008"]
    assert sorted(f.file.split("/")[0] for f in found) == ["A", "B"]


def test_startup_configure_split_across_helpers(tmp_path, mode):
    startup = """
public class Startup
{
    public void ConfigureServices(IServiceCollection services) { services.AddControllers(); }
    public void Configure(IApplicationBuilder app)
    {
        ConfigureSecurity(app);
        app.UseRouting();
    }
    private void ConfigureSecurity(IApplicationBuilder app)
    {
        app.UseHsts();
    }
}
"""
    ctx = ctx_of(tmp_path, {"Startup.cs": startup}, mode)
    assert len(ctx.pipes) == 1
    assert ctx.pipes[0].named("UseHsts")
    assert ctx.prod_calls(ctx.pipes[0], "UseHsts", kinds=("app",))


def test_absent_confidence_unresolved_extension(tmp_path, mode):
    prog = WITH_BUILDER.format(services="builder.Services.AddCompanyDefaults();", body="app.UseRouting();")
    ctx = ctx_of(tmp_path, {"Program.cs": prog}, mode)
    conf, note = ctx.absent_confidence(ctx.pipes[0])
    assert conf == "REVIEW" and "AddCompanyDefaults" in note


def test_absent_confidence_known_extension_is_firm(tmp_path, mode):
    prog = WITH_BUILDER.format(services="builder.Services.AddDbContext<Db>();", body="app.UseRouting();")
    prog += "public class Db {}\n"
    ctx = ctx_of(tmp_path, {"Program.cs": prog}, mode)
    assert ctx.absent_confidence(ctx.pipes[0]) == (None, "")


def test_absent_confidence_unparseable_guard(tmp_path, mode):
    prog = PROGRAM.format(body="if (Flag.Check()) { app.UseHsts(); }\napp.UseRouting();")
    ctx = ctx_of(tmp_path, {"Program.cs": prog}, mode)
    pipe = ctx.pipes[0]
    assert pipe.named("UseHsts") == [] and ctx.uncertain_calls(pipe, "UseHsts")
    conf, note = ctx.absent_confidence(pipe)
    assert conf == "REVIEW" and "UseHsts" in note


def test_ctx_add_goes_through_dnl_finding(tmp_path, mode):
    ctx = ctx_of(tmp_path, {"Program.cs": PROGRAM.format(body="")}, mode)
    ctx.add("DNL-AUTHZ-001", "low", "t", "d", "Program.cs", 1, confidence="REVIEW", api_surface=True)
    f = ctx.out[0]
    assert (f.check_id, f.severity, f.confidence, f.route) == ("DNL-AUTHZ-001", "low", "REVIEW", None)
    assert f.owasp


# -- errors and exception pages (DNL-CFG-008, DNL-CFG-009, DNL-ERR-002) ---------------------------

def _scan(tmp_path, mode, body, services="", extra=None):
    files = {"Program.cs": WITH_BUILDER.format(services=services, body=body)}
    files.update(extra or {})
    return scan(tmp_path, files, mode)


def _of(findings, check_id):
    return [f for f in findings if f.check_id == check_id]


def test_developer_page_unguarded(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseDeveloperExceptionPage();")
    assert ("DNL-CFG-008", "medium", None) in ids(found)


def test_developer_page_guarded_is_clean(tmp_path, mode):
    body = ("if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); }\n"
            "else { app.UseExceptionHandler(\"/e\"); }")
    found = _scan(tmp_path, mode, body)
    assert not _of(found, "DNL-CFG-008") and not _of(found, "DNL-CFG-009")


def test_developer_page_unparseable_guard_is_review(tmp_path, mode):
    found = _scan(tmp_path, mode, "if (Flags.Debug()) { app.UseDeveloperExceptionPage(); }")
    assert ("DNL-CFG-008", "medium", "REVIEW") in ids(found)


def test_detailed_errors_in_settings(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseExceptionHandler(\"/e\");",
                  extra={"appsettings.json": '{\n  "Logging": {},\n  "DetailedErrors": true\n}\n'})
    hits = _of(found, "DNL-CFG-008")
    assert [(f.file, f.line, f.severity, f.confidence) for f in hits] == [("appsettings.json", 3, "medium", None)]


def test_detailed_errors_fixed_by_production_override(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseExceptionHandler(\"/e\");",
                  extra={"appsettings.json": '{"DetailedErrors": true}',
                         "appsettings.Production.json": '{"DetailedErrors": false}'})
    assert not _of(found, "DNL-CFG-008")


def test_detailed_errors_only_in_development_file_is_clean(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseExceptionHandler(\"/e\");",
                  extra={"appsettings.Development.json": '{"DetailedErrors": true}'})
    assert not _of(found, "DNL-CFG-008")


def test_detailed_errors_in_circuit_options(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseExceptionHandler(\"/e\");",
                  services="builder.Services.AddServerSideBlazor(o => { o.DetailedErrors = true; });")
    assert ("DNL-CFG-008", "medium", None) in ids(found)


def test_detailed_errors_from_expression_is_review(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseExceptionHandler(\"/e\");",
                  services="builder.Services.AddServerSideBlazor(o => { o.DetailedErrors = Flags.Verbose(); });")
    assert ("DNL-CFG-008", "medium", "REVIEW") in ids(found)


def test_detailed_errors_false_is_clean(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseExceptionHandler(\"/e\");",
                  services="builder.Services.AddServerSideBlazor(o => { o.DetailedErrors = false; });")
    assert not _of(found, "DNL-CFG-008")


def test_no_exception_handler_is_review(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();")
    assert ("DNL-CFG-009", "low", "REVIEW") in ids(found)


def test_exception_handler_present_is_clean(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseExceptionHandler(\"/e\");\napp.UseRouting();")
    assert not _of(found, "DNL-CFG-009")


def test_status_code_pages_count_as_handler(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseStatusCodePagesWithReExecute(\"/s/{0}\");\napp.UseRouting();")
    assert not _of(found, "DNL-CFG-009")


def test_handler_only_in_development_is_missing(tmp_path, mode):
    body = "if (app.Environment.IsDevelopment()) { app.UseExceptionHandler(\"/e\"); }\napp.UseRouting();"
    assert ("DNL-CFG-009", "low", "REVIEW") in ids(_scan(tmp_path, mode, body))


def test_library_project_has_no_missing_handler(tmp_path, mode):
    files = {"Thing.cs": "public class Thing { public int Value() => 1; }\n"}
    found = scan(tmp_path, files, mode, sdk="Microsoft.NET.Sdk")
    assert found == []


LEAKY = ('app.UseExceptionHandler(a => a.Run(async c => {{ var f = c.Features.Get<IExceptionHandlerFeature>(); '
         'await c.Response.WriteAsync({expr}); }}));')


def test_handler_lambda_leaks_exception(tmp_path, mode):
    found = _scan(tmp_path, mode, LEAKY.format(expr="f.Error.Message"))
    assert ("DNL-ERR-002", "medium", None) in ids(found)


def test_handler_lambda_constant_message_is_clean(tmp_path, mode):
    found = _scan(tmp_path, mode, LEAKY.format(expr='"Something went wrong"'))
    assert not _of(found, "DNL-ERR-002")


def test_handler_lambda_leak_through_local_and_interpolation(tmp_path, mode):
    body = ('app.UseExceptionHandler(a => a.Run(async c => { var f = c.Features.Get<IExceptionHandlerFeature>(); '
            'var ex = f.Error; var text = $"failed: {ex.StackTrace}"; await c.Response.WriteAsync(text); }));')
    assert ("DNL-ERR-002", "medium", None) in ids(_scan(tmp_path, mode, body))


def test_handler_lambda_logging_only_is_clean(tmp_path, mode):
    body = ('app.UseExceptionHandler(a => a.Run(async c => { var f = c.Features.Get<IExceptionHandlerFeature>(); '
            'Log.Write(f.Error.Message); await c.Response.WriteAsync(f.Error.GetType().Name); }));')
    assert not _of(_scan(tmp_path, mode, body), "DNL-ERR-002")


def test_exception_handler_option_leaks_via_results(tmp_path, mode):
    body = ('app.UseExceptionHandler(o => { o.ExceptionHandler = async c => { var f = c.Features.Get<IExceptionHandlerFeature>(); '
            'await Results.Problem(detail: f.Error.ToString()).ExecuteAsync(c); }; });')
    assert ("DNL-ERR-002", "medium", None) in ids(_scan(tmp_path, mode, body))


def test_problem_details_customize_leaks_detail(tmp_path, mode):
    services = ('builder.Services.AddProblemDetails(o => { o.CustomizeProblemDetails = c => '
                '{ c.ProblemDetails.Detail = c.Exception.Message; }; });')
    assert ("DNL-ERR-002", "medium", None) in ids(_scan(tmp_path, mode, "app.UseExceptionHandler();", services))


def test_problem_details_extensions_leak(tmp_path, mode):
    services = ('builder.Services.AddProblemDetails(o => { o.CustomizeProblemDetails = c => '
                '{ c.ProblemDetails.Extensions["trace"] = c.Exception.StackTrace; }; });')
    assert ("DNL-ERR-002", "medium", None) in ids(_scan(tmp_path, mode, "app.UseExceptionHandler();", services))


def test_problem_details_without_exception_is_clean(tmp_path, mode):
    services = ('builder.Services.AddProblemDetails(o => { o.CustomizeProblemDetails = c => '
                '{ c.ProblemDetails.Detail = "failed"; c.ProblemDetails.Extensions["id"] = c.HttpContext.TraceIdentifier; }; });')
    assert not _of(_scan(tmp_path, mode, "app.UseExceptionHandler();", services), "DNL-ERR-002")


def test_leaking_handler_in_development_only_is_clean(tmp_path, mode):
    body = "if (app.Environment.IsDevelopment()) {\n" + LEAKY.format(expr="f.Error.Message") + "\n}"
    assert not _of(_scan(tmp_path, mode, body), "DNL-ERR-002")


def test_leaking_handler_under_unparseable_guard_is_review(tmp_path, mode):
    body = "if (Flags.Debug()) {\n" + LEAKY.format(expr="f.Error.Message") + "\n}"
    assert ("DNL-ERR-002", "medium", "REVIEW") in ids(_scan(tmp_path, mode, body))


# -- transport (DNL-CFG-010, 011, 013, 014) ----------------------------------------------------------

def test_no_https_redirection_or_hsts_is_firm(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();")
    assert ("DNL-CFG-010", "low", None) in ids(found)
    assert ("DNL-CFG-011", "low", None) in ids(found)


def test_https_redirection_and_hsts_present_is_clean(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseHttpsRedirection();\napp.UseHsts();\napp.UseRouting();")
    assert not _of(found, "DNL-CFG-010") and not _of(found, "DNL-CFG-011")


def test_hsts_outside_development_counts(tmp_path, mode):
    body = "if (!app.Environment.IsDevelopment()) { app.UseHsts(); }\napp.UseHttpsRedirection();"
    assert not _of(_scan(tmp_path, mode, body), "DNL-CFG-011")


def test_hsts_only_in_development_is_reported(tmp_path, mode):
    body = "if (app.Environment.IsDevelopment()) { app.UseHsts(); }\napp.UseHttpsRedirection();"
    assert ("DNL-CFG-011", "low", None) in ids(_scan(tmp_path, mode, body))


def test_add_hsts_alone_does_not_count(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();", services="builder.Services.AddHsts(o => { });")
    assert ("DNL-CFG-011", "low", None) in ids(found)


def test_hsts_header_literal_counts(tmp_path, mode):
    body = ('app.Use(async (c, next) => { c.Response.Headers["Strict-Transport-Security"] = "max-age=31536000"; '
            'await next(); });\napp.UseHttpsRedirection();')
    assert not _of(_scan(tmp_path, mode, body), "DNL-CFG-011")


def test_hsts_header_append_counts(tmp_path, mode):
    body = ('app.Use(async (c, next) => { c.Response.Headers.Append("strict-transport-security", "max-age=1"); '
            'await next(); });\napp.UseHttpsRedirection();')
    assert not _of(_scan(tmp_path, mode, body), "DNL-CFG-011")


def test_hsts_header_in_development_only_does_not_count(tmp_path, mode):
    body = ('if (app.Environment.IsDevelopment()) { app.Use(async (c, next) => '
            '{ c.Response.Headers["Strict-Transport-Security"] = "max-age=1"; await next(); }); }')
    assert ("DNL-CFG-011", "low", None) in ids(_scan(tmp_path, mode, body))


def test_unresolved_extension_makes_transport_review(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseCompanyDefaults();\napp.UseRouting();")
    for cid in ("DNL-CFG-010", "DNL-CFG-011"):
        hits = _of(found, cid)
        assert [f.confidence for f in hits] == ["REVIEW"]
        assert "UseCompanyDefaults" in hits[0].description


def test_known_logging_extension_stays_firm(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseSerilogRequestLogging();\napp.UseRouting();")
    assert ("DNL-CFG-010", "low", None) in ids(found)
    assert ("DNL-CFG-011", "low", None) in ids(found)


def test_unparseable_guard_around_hsts_is_review(tmp_path, mode):
    body = "if (Flags.Secure()) { app.UseHsts(); }\napp.UseHttpsRedirection();"
    hits = _of(_scan(tmp_path, mode, body), "DNL-CFG-011")
    assert [f.confidence for f in hits] == ["REVIEW"]


def test_custom_middleware_may_set_hsts_is_review(tmp_path, mode):
    body = "app.UseMiddleware<SecurityHeaders>();\napp.UseHttpsRedirection();"
    hits = _of(_scan(tmp_path, mode, body), "DNL-CFG-011")
    assert [f.confidence for f in hits] == ["REVIEW"] and "SecurityHeaders" in hits[0].description


def test_redirect_rewrite_rule_counts_as_redirection(tmp_path, mode):
    body = "app.UseRewriter(new RewriteOptions().AddRedirectToHttps());\napp.UseHsts();"
    assert not _of(_scan(tmp_path, mode, body), "DNL-CFG-010")


def test_library_project_has_no_transport_findings(tmp_path, mode):
    files = {"Thing.cs": "public class Thing { public int Value() => 1; }\n",
             "appsettings.json": '{"AllowedHosts": "*"}'}
    found = scan(tmp_path, files, mode, sdk="Microsoft.NET.Sdk")
    assert not [f for f in found if f.check_id in ("DNL-CFG-010", "DNL-CFG-011", "DNL-CFG-013", "DNL-CFG-014")]


def test_worker_host_has_no_transport_findings(tmp_path, mode):
    prog = "var host = Host.CreateApplicationBuilder(args).Build();\nhost.Run();\n"
    found = scan(tmp_path, {"Program.cs": prog}, mode, sdk="Microsoft.NET.Sdk.Worker")
    assert not [f for f in found if f.check_id in ("DNL-CFG-010", "DNL-CFG-011")]


HTTP_ONLY = "builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8080));"


def test_kestrel_http_only(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();", services=HTTP_ONLY)
    hits = _of(found, "DNL-CFG-013")
    assert ("DNL-CFG-013", "low", None) in ids(found)
    assert [(f.file, f.line) for f in hits] == [("Program.cs", 2)]


def test_kestrel_with_https_listener_is_clean(tmp_path, mode):
    services = ("builder.WebHost.ConfigureKestrel(o => { o.ListenAnyIP(8080); "
                "o.ListenAnyIP(8443, l => l.UseHttps()); });")
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", services=services), "DNL-CFG-013")


def test_kestrel_https_in_another_lambda_clears(tmp_path, mode):
    services = HTTP_ONLY + "\nbuilder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8443, l => l.UseHttps()));"
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", services=services), "DNL-CFG-013")


def test_kestrel_https_defaults_clear(tmp_path, mode):
    services = "builder.WebHost.ConfigureKestrel(o => { o.ConfigureHttpsDefaults(h => { }); o.ListenAnyIP(8080); });"
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", services=services), "DNL-CFG-013")


def test_kestrel_listen_variants_http_only(tmp_path, mode):
    services = "builder.WebHost.ConfigureKestrel(o => { o.Listen(IPAddress.Any, 5000); });"
    assert ("DNL-CFG-013", "low", None) in ids(_scan(tmp_path, mode, "app.UseRouting();", services=services))


def test_use_urls_http_only(tmp_path, mode):
    services = 'builder.WebHost.UseUrls("http://*:5000");'
    assert ("DNL-CFG-013", "low", None) in ids(_scan(tmp_path, mode, "app.UseRouting();", services=services))


def test_use_urls_with_https_is_clean(tmp_path, mode):
    services = 'builder.WebHost.UseUrls("http://*:5000", "https://*:5001");'
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", services=services), "DNL-CFG-013")


def test_use_urls_semicolon_list_with_https_is_clean(tmp_path, mode):
    services = 'builder.WebHost.UseUrls("http://*:5000;https://*:5001");'
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", services=services), "DNL-CFG-013")


def test_use_urls_loopback_is_clean(tmp_path, mode):
    services = 'builder.WebHost.UseUrls("http://localhost:5000");'
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", services=services), "DNL-CFG-013")


def test_use_urls_in_development_only_is_clean(tmp_path, mode):
    prog = ('var builder = WebApplication.CreateBuilder(args);\n'
            'if (builder.Environment.IsDevelopment()) { builder.WebHost.UseUrls("http://*:5000"); }\n'
            'var app = builder.Build();\napp.UseRouting();\napp.Run();\n')
    assert not _of(scan(tmp_path, {"Program.cs": prog}, mode), "DNL-CFG-013")


def test_use_urls_unreadable_value_next_to_http_listener_is_review(tmp_path, mode):
    services = HTTP_ONLY + "\nbuilder.WebHost.UseUrls(Settings.Urls());"
    assert ("DNL-CFG-013", "low", "REVIEW") in ids(_scan(tmp_path, mode, "app.UseRouting();", services=services))


def test_kestrel_endpoint_http_in_settings(tmp_path, mode):
    cfg = '{\n  "Kestrel": {\n    "Endpoints": {\n      "Http": { "Url": "http://0.0.0.0:80" }\n    }\n  }\n}\n'
    found = _scan(tmp_path, mode, "app.UseRouting();", extra={"appsettings.json": cfg})
    hits = _of(found, "DNL-CFG-013")
    assert [(f.file, f.line, f.confidence) for f in hits] == [("appsettings.json", 4, None)]


def test_kestrel_endpoint_loopback_in_settings_is_clean(tmp_path, mode):
    cfg = '{"Kestrel": {"Endpoints": {"Http": {"Url": "http://localhost:5000"}}}}'
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", extra={"appsettings.json": cfg}), "DNL-CFG-013")


def test_kestrel_endpoint_with_https_sibling_is_clean(tmp_path, mode):
    cfg = ('{"Kestrel": {"Endpoints": {"Http": {"Url": "http://0.0.0.0:80"}, '
           '"Https": {"Url": "https://0.0.0.0:443"}}}}')
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", extra={"appsettings.json": cfg}), "DNL-CFG-013")


def test_urls_setting_http_only(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();", extra={"appsettings.json": '{"Urls": "http://*:5000"}'})
    assert ("DNL-CFG-013", "low", None) in ids(found)


def test_urls_setting_fixed_by_production_override(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();",
                  extra={"appsettings.json": '{"Urls": "http://*:5000"}',
                         "appsettings.Production.json": '{"Urls": "https://*:5001"}'})
    assert not _of(found, "DNL-CFG-013")


def test_settings_https_clears_code_http_listener(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();", services=HTTP_ONLY,
                  extra={"appsettings.json": '{"Urls": "https://*:5001"}'})
    assert not _of(found, "DNL-CFG-013")


def test_allowed_hosts_wildcard(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();",
                  extra={"appsettings.json": '{\n  "AllowedHosts": "*"\n}\n'})
    hits = _of(found, "DNL-CFG-014")
    assert [(f.file, f.line, f.severity, f.confidence) for f in hits] == [("appsettings.json", 2, "low", None)]
    assert ("DNL-CFG-014", "low", None) in ids(found)


def test_allowed_hosts_wildcard_segment(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();", extra={"appsettings.json": '{"AllowedHosts": "*;x.test"}'})
    assert ("DNL-CFG-014", "low", None) in ids(found)


def test_allowed_hosts_specific_is_clean(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();", extra={"appsettings.json": '{"AllowedHosts": "example.test"}'})
    assert not _of(found, "DNL-CFG-014")


def test_allowed_hosts_subdomain_wildcard_is_clean(tmp_path, mode):
    cfg = '{"AllowedHosts": "*.example.test;api.example.test"}'
    assert not _of(_scan(tmp_path, mode, "app.UseRouting();", extra={"appsettings.json": cfg}), "DNL-CFG-014")


def test_allowed_hosts_fixed_by_production_override(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();",
                  extra={"appsettings.json": '{"AllowedHosts": "*"}',
                         "appsettings.Production.json": '{"AllowedHosts": "example.test"}'})
    assert not _of(found, "DNL-CFG-014")


def test_allowed_hosts_wildcard_only_in_development_file_is_clean(tmp_path, mode):
    found = _scan(tmp_path, mode, "app.UseRouting();",
                  extra={"appsettings.Development.json": '{"AllowedHosts": "*"}'})
    assert not _of(found, "DNL-CFG-014")
