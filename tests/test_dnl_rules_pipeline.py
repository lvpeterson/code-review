"""rules_pipeline skeleton: shared config context, per-project pipelines, absence confidence."""
from cfgutil import ids, make_app, mode, prepare_model, run_check, scan  # noqa: F401

from checks.dnl import cfgctx

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
