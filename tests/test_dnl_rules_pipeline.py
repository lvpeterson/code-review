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
