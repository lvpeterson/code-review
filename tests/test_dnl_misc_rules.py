"""Logging, business-flow, resource, inventory and API-consumption rules: DNL-LOG-002..004, DES-001,
RES-002..003, INV-002, CONSUME-001..002, and the `external` taint source kind they share."""
import re
import shutil
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_misc, rules_taint, taint_solver
from checks.dnl.webconfig import load_configs
from core.owasp_web import owasp_for

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


def _refs(model):
    return routes.discover_mvc_webapi(model) + routes.discover_webforms(model) + routes.discover_wcf(model)


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


@pytest.fixture(scope="module")
def refs(model):
    return _refs(model)


@pytest.fixture(scope="module")
def findings(model, refs):
    out, _notes = rules_misc.check(model, refs, load_configs(model.root))
    return out


def where(f):
    m = re.search(r"\(in ([^)]+)\)\.?$", f.description)
    return m.group(1) if m else ""


def hits(findings, rule, prefix="", file_part=""):
    return sorted(where(f) for f in findings
                  if f.check_id == rule and where(f).startswith(prefix) and file_part in f.file)


def build(tmp_path, files, language="cs"):
    """A throwaway solution: one legacy project holding `files` ({relative path: source})."""
    ext = ".vb" if language == "vb" else ".cs"
    comp = "".join(f'<Compile Include="{p.replace("/", chr(92))}" />' for p in files if p.endswith(ext))
    proj = "App.vbproj" if language == "vb" else "App.csproj"
    (tmp_path / proj).write_text(
        '<Project ToolsVersion="15.0"><PropertyGroup><TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion>'
        '</PropertyGroup><ItemGroup><Reference Include="System.Web" /><Reference Include="System.Web.Mvc" />'
        f'<Reference Include="System.Web.Http" /></ItemGroup><ItemGroup>{comp}</ItemGroup></Project>')
    for p, src in files.items():
        f = tmp_path / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(src)
    project._CACHE.clear()
    m = project.prepare(tmp_path, False)
    return m, _refs(m)


def run(tmp_path, files, language="cs"):
    m, r = build(tmp_path, files, language)
    out, _ = rules_misc.check(m, r, load_configs(m.root))
    return out


# -- LOG-003 --------------------------------------------------------------------

def test_log003_positives(findings):
    assert hits(findings, "DNL-LOG-003", "LogLeakController.") == [
        "LogLeakController.Direct", "LogLeakController.Format", "LogLeakController.Interp",
        "LogLeakController.NamedArg", "LogLeakController.TraceToken", "LogLeakController.ViaLocal"]


def test_log003_negatives(findings):
    got = hits(findings, "DNL-LOG-003")
    for safe in ("UserOnly", "LiteralWord", "LengthOnly", "SettingName", "NotALogger"):
        assert f"LogLeakController.{safe}" not in got


def test_log003_vb_case_insensitive(findings):
    assert hits(findings, "DNL-LOG-003", "VbMiscController.") == ["VbMiscController.LeakInterp", "VbMiscController.LeakPwd"]


def test_log003_severity_and_tags(findings):
    f = next(f for f in findings if f.check_id == "DNL-LOG-003")
    assert f.severity == "medium" and f.confidence is None
    assert f.owasp["2025"].startswith("A09") and "api2023" not in f.owasp


# -- LOG-004 --------------------------------------------------------------------

def test_log004_unlogged_branches(findings):
    assert hits(findings, "DNL-LOG-004", "LoginLogController.") == [
        "LoginLogController.Login", "LoginLogController.Login1_LoginError", "LoginLogController.LoginHelperSilent",
        "LoginLogController.LoginLogBefore", "LoginLogController.LoginNested", "LoginLogController.LoginTail"]


def test_log004_logged_branches_not_reported(findings):
    got = hits(findings, "DNL-LOG-004")
    for ok in ("LoginLogged", "LoginTailLogged", "LoginHelperLogs", "Login2_LoginError", "Logout"):
        assert f"LoginLogController.{ok}" not in got


def test_log004_review_low(findings):
    f = next(f for f in findings if f.check_id == "DNL-LOG-004")
    assert f.severity == "low" and f.confidence == "REVIEW"


# -- LOG-002 --------------------------------------------------------------------

def test_log002_no_logging_app(roslyn_helper):
    project._CACHE.clear()
    m = project.prepare(FX / "misc_nolog_app", False)
    out, _ = rules_misc.check(m, _refs(m), load_configs(m.root))
    got = [f for f in out if f.check_id == "DNL-LOG-002"]
    assert len(got) == 1
    assert got[0].file == "App.csproj" and got[0].severity == "low" and got[0].confidence == "REVIEW"
    assert got[0].owasp["2025"].startswith("A09")


def test_log002_log4net_config_yields_none(roslyn_helper):
    project._CACHE.clear()
    m = project.prepare(FX / "misc_log4net_app", False)
    out, _ = rules_misc.check(m, _refs(m), load_configs(m.root))
    assert not [f for f in out if f.check_id == "DNL-LOG-002"]


def test_log002_taint_app_uses_log4net(findings):
    assert not [f for f in findings if f.check_id == "DNL-LOG-002"]


def test_log002_degraded_model_still_reports(roslyn_helper):
    project._CACHE.clear()
    m = project.prepare(FX / "misc_nolog_app", False)
    m.files = {}
    out, _ = rules_misc.check(m, [], load_configs(m.root))
    assert [f.check_id for f in out if f.check_id == "DNL-LOG-002"] == ["DNL-LOG-002"]


@pytest.mark.parametrize("name,text", [
    ("Serilog", 'using Serilog;\nnamespace N { public class A { } }'),
    ("TraceSource", 'namespace N { public class A { void M() { var s = new System.Diagnostics.TraceSource("x"); } } }'),
])
def test_log002_code_evidence_counts(tmp_path, roslyn_helper, name, text):
    out = run(tmp_path, {"A.cs": text})
    assert not [f for f in out if f.check_id == "DNL-LOG-002"]


def test_log002_elmah_config_counts(tmp_path, roslyn_helper):
    (tmp_path / "Web.config").write_text('<configuration><elmah><errorLog type="Elmah.XmlFileErrorLog, Elmah" '
                                         'logPath="~/App_Data" /></elmah></configuration>')
    out = run(tmp_path, {"A.cs": "namespace N { public class A { } }"})
    assert not [f for f in out if f.check_id == "DNL-LOG-002"]


def test_log002_commented_out_config_does_not_count(tmp_path, roslyn_helper):
    (tmp_path / "Web.config").write_text('<configuration><!-- <log4net><root/></log4net> --></configuration>')
    out = run(tmp_path, {"A.cs": "namespace N { public class A { } }"})
    assert len([f for f in out if f.check_id == "DNL-LOG-002"]) == 1


# -- DES-001 --------------------------------------------------------------------

def test_des001_flagged_actions(findings):
    assert hits(findings, "DNL-DES-001", "FlowController.") == [
        "FlowController.ChangePassword", "FlowController.Checkout", "FlowController.ForgotPassword",
        "FlowController.Login", "FlowController.LoginDeadBranch", "FlowController.LoginDebugOnly",
        "FlowController.LoginNoLock", "FlowController.LoginNoLockPositional", "FlowController.LoginViaWeakService",
        "FlowController.PayInvoice", "FlowController.ResetPassword"]


def test_des001_protected_actions_not_flagged(findings):
    got = hits(findings, "DNL-DES-001")
    for ok in ("Register", "LoginLockout", "LoginLockPositional", "LoginMembership", "LoginViaService",
               "LoginCaptcha", "LoginAfterGuard", "LoginInsideValid", "Index", "Logout"):
        assert f"FlowController.{ok}" not in got
    assert not hits(findings, "DNL-DES-001", "ThrottledAccountController.")   # throttle on the base controller


def test_des001_throttle_on_other_action_does_not_count(findings):
    assert "FlowController.ForgotPassword" in hits(findings, "DNL-DES-001")    # [RateLimit] is on Index only


def test_des001_noop_attribute_does_not_count(findings):
    assert "FlowController.ChangePassword" in hits(findings, "DNL-DES-001")


def test_des001_get_only_login_not_a_flow(findings):
    # two Login actions: only the POST one counts, so exactly one finding
    assert hits(findings, "DNL-DES-001", "FlowController.Login").count("FlowController.Login") == 1


def test_des001_web_api_actions(findings):
    assert hits(findings, "DNL-DES-001", "AccountApiController.") == [
        "AccountApiController.Login", "AccountApiController.Register"]


def test_des001_vb_case_insensitive(findings):
    assert hits(findings, "DNL-DES-001", "VbMiscController.") == ["VbMiscController.Login", "VbMiscController.LoginDebug"]


def test_des001_shape(findings):
    f = next(f for f in findings if f.check_id == "DNL-DES-001")
    assert f.severity == "low" and f.confidence == "REVIEW" and f.route is not None
    assert f.owasp["2025"].startswith("A06") and f.owasp["2021"].startswith("A04")
    assert "API6" in str(f.owasp)


def test_des001_global_filter_is_protection(roslyn_helper):
    """Review Focus 4: a throttle filter registered globally at startup covers every sensitive action."""
    project._CACHE.clear()
    m = project.prepare(FX / "misc_throttle_app", False)
    out, _ = rules_misc.check(m, _refs(m), load_configs(m.root))
    assert not [f for f in out if f.check_id == "DNL-DES-001"]


def _throttle_variant(tmp_path, edit):
    dst = tmp_path / "app"
    shutil.copytree(FX / "misc_throttle_app", dst)
    edit(dst)
    project._CACHE.clear()
    m = project.prepare(dst, False)
    out, _ = rules_misc.check(m, _refs(m), load_configs(m.root))
    return sorted(where(f) for f in out if f.check_id == "DNL-DES-001")


def _replace(path, old, new):
    p = Path(path)
    p.write_text(p.read_text().replace(old, new))


def test_des001_no_registration_is_flagged(tmp_path, roslyn_helper):
    got = _throttle_variant(tmp_path, lambda d: _replace(d / "App_Start/FilterConfig.cs",
                                                         "filters.Add(new ThrottleAttribute(20));", ""))
    assert got == ["AccountController.Checkout", "AccountController.Login", "AccountController.Register"]


def test_des001_conditional_registration_is_flagged(tmp_path, roslyn_helper):
    got = _throttle_variant(tmp_path, lambda d: _replace(
        d / "App_Start/FilterConfig.cs", "filters.Add(new ThrottleAttribute(20));",
        "if (System.Configuration.ConfigurationManager.AppSettings[\"t\"] == \"1\") { filters.Add(new ThrottleAttribute(20)); }"))
    assert len(got) == 3


def test_des001_unreached_registration_is_flagged(tmp_path, roslyn_helper):
    got = _throttle_variant(tmp_path, lambda d: _replace(
        d / "Global.asax.cs", "FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);", ""))
    assert len(got) == 3


def test_des001_noop_global_filter_is_flagged(tmp_path, roslyn_helper):
    def edit(d):
        _replace(d / "Filters/ThrottleAttribute.cs", "if (Hits.Count(key) > _max)", "if (false)")
        (d / "Filters/ThrottleAttribute.cs").write_text(
            "using System.Web.Mvc;\nnamespace Throttled { public class ThrottleAttribute : ActionFilterAttribute {\n"
            "public ThrottleAttribute(int max) { }\n"
            "public override void OnActionExecuting(ActionExecutingContext c) { base.OnActionExecuting(c); } } }\n")
    assert len(_throttle_variant(tmp_path, edit)) == 3


# -- RES-002 --------------------------------------------------------------------

def test_res002_unbounded(findings):
    assert hits(findings, "DNL-RES-002", "OrdersListController.") == [
        "OrdersListController.GetAll", "OrdersListController.GetODataNoSize", "OrdersListController.GetOtherQueryPaged",
        "OrdersListController.GetPageIgnored", "OrdersListController.GetPagedUnclamped", "OrdersListController.GetRaw",
        "OrdersListController.GetTakeAfterList", "OrdersListController.GetTakeMax",
        "OrdersListController.GetViaLocalUnpaged", "OrdersListController.GetViaRepo"]
    assert hits(findings, "DNL-RES-002", "MvcListController.") == ["MvcListController.Index"]


def test_res002_bounded_not_flagged(findings):
    got = hits(findings, "DNL-RES-002")
    for ok in ("GetPaged", "GetViaLocal", "GetCount", "GetFirst", "GetOData", "GetViaRepoPaged"):
        assert f"OrdersListController.{ok}" not in got


def test_res002_shape(findings):
    f = next(f for f in findings if f.check_id == "DNL-RES-002")
    assert f.severity == "low" and f.route is not None and f.confidence is None
    assert f.owasp["2025"].startswith("A06") and "API4" in str(f.owasp)


def test_res002_skip_alone_does_not_bound(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": (
        "using System.Linq; using System.Web.Http; using System.Data.Entity;\n"
        "namespace N { public class Ctx : DbContext { public DbSet<O> Orders { get; set; } } public class O { }\n"
        "public class XController : ApiController { Ctx db = new Ctx();\n"
        "public object Get(int p) { return db.Orders.Skip(p).ToList(); } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-RES-002"] == ["XController.Get"]


# -- RES-003 --------------------------------------------------------------------

def test_res003_unchecked_uploads(findings):
    assert hits(findings, "DNL-RES-003", "UploadController.") == [
        "UploadController.Save", "UploadController.SaveCheckAfter", "UploadController.SaveCheckDoesNotStop",
        "UploadController.SaveCopy", "UploadController.SaveFiles", "UploadController.SaveLowerOnly",
        "UploadController.SaveViaHelper"]
    assert hits(findings, "DNL-RES-003", "ApiUploadController.") == ["ApiUploadController.Post"]


def test_res003_guarded_uploads_not_flagged(findings):
    got = hits(findings, "DNL-RES-003")
    for ok in ("SaveChecked", "SaveCheckedInside", "SaveElseRejects", "SaveViaAlias", "SaveFilesChecked",
               "SaveViaHelperChecked", "NotUpload"):
        assert f"UploadController.{ok}" not in got


def test_res003_shape(findings):
    f = next(f for f in findings if f.check_id == "DNL-RES-003" and where(f) == "ApiUploadController.Post")
    assert f.severity == "medium" and f.route is not None
    assert "API4" in str(f.owasp)
    mvc = next(f for f in findings if f.check_id == "DNL-RES-003" and where(f) == "UploadController.Save")
    assert "api2023" not in mvc.owasp          # API4 only on an API surface


def test_res003_max_request_length_is_not_protection(tmp_path, roslyn_helper):
    (tmp_path / "Web.config").write_text('<configuration><system.web><httpRuntime maxRequestLength="4096" />'
                                         '</system.web></configuration>')
    out = run(tmp_path, {"A.cs": (
        "using System.Web; using System.Web.Mvc;\nnamespace N { public class UController : Controller {\n"
        "[HttpPost] public ActionResult Up(HttpPostedFileBase f) { f.SaveAs(\"x\"); return null; } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-RES-003"] == ["UController.Up"]


# -- INV-002 --------------------------------------------------------------------

def test_inv002_helppage_controller(findings):
    got = [f for f in findings if f.check_id == "DNL-INV-002" and "HelpPage" in f.title]
    assert len(got) == 1 and got[0].file.endswith("Areas/HelpPage/Controllers/HelpController.cs")
    assert got[0].severity == "low" and "API9" in str(got[0].owasp)


def test_inv002_swagger_ui(findings):
    got = [f for f in findings if f.check_id == "DNL-INV-002" and "Swagger" in f.title]
    assert len(got) == 1 and got[0].file.endswith("Misc/Inventory.cs")


def test_inv002_test_and_debug_controllers(findings):
    got = sorted(f.title.split(": ")[1] for f in findings if f.check_id == "DNL-INV-002" and "controller shipped" in f.title)
    assert got == ["DebugController", "DiagnosticsController", "OrdersTestController"]


def test_inv002_always_carries_api_tag(findings):
    assert all("API9" in str(f.owasp) for f in findings if f.check_id == "DNL-INV-002")


_HELP_CTRL = ("using System.Web.Mvc;\nnamespace App.Areas.HelpPage.Controllers { public class HelpController : Controller {\n"
              "public ActionResult Index() { return null; } } }")


def test_inv002_help_controller_with_authorize_is_protected(tmp_path, roslyn_helper):
    out = run(tmp_path, {"Areas/HelpPage/HelpController.cs": _HELP_CTRL.replace(
        "public class HelpController", "[Authorize] public class HelpController")})
    assert not [f for f in out if f.check_id == "DNL-INV-002"]


def _global_auth(call):
    return {
        "Areas/HelpPage/HelpController.cs": _HELP_CTRL,
        "F.cs": ("using System.Web; using System.Web.Mvc;\nnamespace App { public static class FilterConfig {\n"
                 "public static void Reg(GlobalFilterCollection filters) { filters.Add(new AuthorizeAttribute()); } }\n"
                 "public class MvcApplication : HttpApplication { protected void Application_Start() {\n"
                 + call + " } } }")}


def test_inv002_help_controller_with_global_authorize_is_protected(tmp_path, roslyn_helper):
    out = run(tmp_path, _global_auth("FilterConfig.Reg(GlobalFilters.Filters);"))
    assert not [f for f in out if f.check_id == "DNL-INV-002"]


@pytest.mark.parametrize("call", [
    "",
    'if (System.Environment.MachineName == "x") { FilterConfig.Reg(GlobalFilters.Filters); }',
    "if (false) { FilterConfig.Reg(GlobalFilters.Filters); }",
])
def test_inv002_unreached_or_conditional_global_authorize_does_not_protect(tmp_path, roslyn_helper, call):
    out = run(tmp_path, _global_auth(call))
    assert len([f for f in out if f.check_id == "DNL-INV-002"]) == 1


def test_inv002_authorize_added_under_condition_in_registering_method(tmp_path, roslyn_helper):
    files = _global_auth("FilterConfig.Reg(GlobalFilters.Filters);")
    files["F.cs"] = files["F.cs"].replace("filters.Add(new AuthorizeAttribute());",
                                          "if (false) { filters.Add(new AuthorizeAttribute()); }")
    out = run(tmp_path, files)
    assert len([f for f in out if f.check_id == "DNL-INV-002"]) == 1


def test_inv002_help_controller_without_auth_is_reported(tmp_path, roslyn_helper):
    out = run(tmp_path, {"Areas/HelpPage/HelpController.cs": _HELP_CTRL})
    assert len([f for f in out if f.check_id == "DNL-INV-002"]) == 1


def test_inv002_swagger_denied_in_web_config(tmp_path, roslyn_helper):
    (tmp_path / "Web.config").write_text('<configuration><location path="swagger"><system.web><authorization>'
                                         '<deny users="?" /></authorization></system.web></location></configuration>')
    out = run(tmp_path, {"S.cs": ("using System.Web.Http;\nnamespace N { public static class SwaggerConfig { public static void R() {\n"
                                  "GlobalConfiguration.Configuration.EnableSwagger(c => c.SingleApiVersion(\"v1\", \"x\")).EnableSwaggerUi(); } } }")})
    assert not [f for f in out if f.check_id == "DNL-INV-002"]


def test_inv002_global_authorize_does_not_cover_swagger(tmp_path, roslyn_helper):
    out = run(tmp_path, {"S.cs": (
        "using System.Web.Http; using System.Web.Mvc;\nnamespace N { public static class SwaggerConfig { public static void R() {\n"
        "GlobalConfiguration.Configuration.EnableSwagger(c => c.SingleApiVersion(\"v1\", \"x\")).EnableSwaggerUi(); } }\n"
        "public static class FilterConfig { public static void Reg(GlobalFilterCollection filters) {\n"
        "filters.Add(new AuthorizeAttribute()); } } }")})
    assert len([f for f in out if f.check_id == "DNL-INV-002" and "Swagger" in f.title]) == 1


def test_inv002_test_project_is_skipped(tmp_path, roslyn_helper):
    src = "using System.Web.Mvc;\nnamespace N { public class HarnessTestController : Controller { } }"
    (tmp_path / "ok").mkdir()
    (tmp_path / "ok" / "App.csproj").write_text(
        '<Project ToolsVersion="15.0"><PropertyGroup><TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion></PropertyGroup>'
        '<ItemGroup><Compile Include="C.cs" /></ItemGroup></Project>')
    (tmp_path / "ok" / "C.cs").write_text(src)
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "App.Tests.csproj").write_text(
        '<Project ToolsVersion="15.0"><PropertyGroup><TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion></PropertyGroup>'
        '<ItemGroup><Compile Include="C.cs" /></ItemGroup></Project>')
    (tmp_path / "t" / "C.cs").write_text(src.replace("HarnessTest", "OtherTest"))
    project._CACHE.clear()
    m = project.prepare(tmp_path, False)
    out, _ = rules_misc.check(m, _refs(m), [])
    got = [f for f in out if f.check_id == "DNL-INV-002"]
    assert [f.file for f in got] == ["ok/C.cs"]


# -- CONSUME-001 ----------------------------------------------------------------

def test_consume001_code_positives(findings):
    assert hits(findings, "DNL-CONSUME-001", "OutboundCalls.") == [
        "OutboundCalls.BaseAddr", "OutboundCalls.BaseAssign", "OutboundCalls.Concat", "OutboundCalls.Interp",
        "OutboundCalls.Plain", "OutboundCalls.Rest", "OutboundCalls.ViaConst", "OutboundCalls.ViaField",
        "OutboundCalls.ViaLocal", "OutboundCalls.ViaOwnField"]


def test_consume001_negatives(findings):
    got = hits(findings, "DNL-CONSUME-001")
    for ok in ("OutboundCalls.Secure", "OutboundCalls.SecureConst", "OutboundCalls.Local",
               "OutboundCalls.Loopback", "OutboundCalls.FromConfig"):
        assert ok not in got
    assert not hits(findings, "DNL-CONSUME-001", "NotOutboundController.")


def test_consume001_vb(findings):
    assert hits(findings, "DNL-CONSUME-001", "VbMiscController.") == ["VbMiscController.Outbound", "VbMiscController.OutboundConst"]


def test_consume001_web_config_client_endpoint(roslyn_helper):
    project._CACHE.clear()
    m = project.prepare(FX / "misc_nolog_app", False)
    out, _ = rules_misc.check(m, _refs(m), load_configs(m.root))
    got = [f for f in out if f.check_id == "DNL-CONSUME-001"]
    assert len(got) == 1 and got[0].file == "Web.config" and "pay.example.net" in got[0].description
    assert got[0].severity == "low" and got[0].confidence == "REVIEW"
    assert "API10" in str(got[0].owasp)


# -- CONSUME-002 and the `external` source kind ---------------------------------

def _ext(findings):
    return [f for f in findings if f.check_id == "DNL-CONSUME-002"]


def test_consume002_flows(model, findings):
    got = _ext(findings)
    lines = sorted((model.root / f.file).read_text().splitlines()[f.line - 1].strip() for f in got
                   if f.file.endswith("ExternalApi.cs"))
    assert any("new SqlCommand(\"SELECT * FROM T WHERE N='\" + order.Name" in x for x in lines)
    assert any("File.ReadAllText(o.Path)" in x for x in lines)
    assert any("Redirect(o.Next)" in x for x in lines)
    assert sum("new SqlCommand(\"SELECT * FROM T WHERE N='\" + s" in x for x in lines) == 2   # WebClient + unrouted helper
    assert len(lines) == 5
    assert all(f.severity == "low" and f.confidence == "REVIEW" and "API10" in str(f.owasp) for f in got)


def test_consume002_safe_forms_not_reported(model, findings):
    text = [(model.root / f.file).read_text().splitlines()[f.line - 1] for f in _ext(findings)]
    assert not any("@n" in t or '"SELECT * FROM T WHERE Id="' in t for t in text)


def test_external_flow_invisible_to_request_rules(model, refs):
    """The injection / path / redirect rules must not report a flow whose only source is a response."""
    got = rules_taint.check(model, refs)
    assert not [f for f in got if f.file.endswith("Misc/ExternalApi.cs")]
    rows = taint_solver.entry_hits(model, refs)
    assert not [r for r in rows if r.hit.file.endswith("Misc/ExternalApi.cs")]
    assert taint_solver.external_hits(model)           # the engine still sees them


def test_request_source_findings_unchanged_by_external_kind(model, refs):
    """A request-sourced flow in the same engine run keeps its proven rows and request-only sources."""
    got = rules_taint.check(model, refs)
    assert any(f.check_id == "DNL-INJ-001" for f in got)
    rows = taint_solver.entry_hits(model, refs)
    assert all(o.kind == "source" for r in rows for o in r.sources)


# -- OWASP mapping ---------------------------------------------------------------

@pytest.mark.parametrize("rule,c25,c21,api,always", [
    ("DNL-LOG-002", "A09", "A09", None, False), ("DNL-LOG-003", "A09", "A09", None, False),
    ("DNL-LOG-004", "A09", "A09", None, False), ("DNL-DES-001", "A06", "A04", "API6", True),
    ("DNL-RES-002", "A06", "A04", "API4", False), ("DNL-RES-003", "A06", "A04", "API4", False),
    ("DNL-INV-002", "A02", "A05", "API9", True), ("DNL-CONSUME-001", "A08", "A08", "API10", True),
    ("DNL-CONSUME-002", "A08", "A08", "API10", True)])
def test_owasp_mapping(rule, c25, c21, api, always):
    plain = owasp_for(rule, False)
    surf = owasp_for(rule, True)
    assert plain["2025"].startswith(c25) and plain["2021"].startswith(c21)
    if api is None:
        assert "api2023" not in plain and "api2023" not in surf
    else:
        assert api in surf["api2023"]
        assert ("api2023" in plain) == always


# -- adversarial cases: a protection that only looks like one --------------------

_DB = ("using System.Linq; using System.Web.Http; using System.Data.Entity;\n"
       "namespace N { public class Ctx : DbContext { public DbSet<O> Orders { get; set; } } public class O { }\n")


def test_res002_take_after_materializing_does_not_bound(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _DB + (
        "public class XController : ApiController { Ctx db = new Ctx();\n"
        "public object Get() { return db.Orders.ToList().Take(10); }\n"
        "public object Page() { return db.Orders.Take(10).ToList(); } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-RES-002"] == ["XController.Get"]


def test_res002_branch_that_pages_only_sometimes_is_flagged(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _DB + (
        "public class XController : ApiController { Ctx db = new Ctx();\n"
        "public object Get(bool paged) { var q = db.Orders.Where(o => o != null);\n"
        "if (paged) { q = q.Take(10); } return q.ToList(); } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-RES-002"] == ["XController.Get"]


_MVC = "using System.Web.Mvc; using System.Web.Security;\nnamespace N {\n"


def test_des001_plain_attribute_type_is_not_a_throttle(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _MVC + (
        "public class ThrottleAttribute : System.Attribute { public int Max; public bool Allowed() { return true; } }\n"
        "public class XController : Controller { [HttpPost] [Throttle] public ActionResult Login(string u) { return null; } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-DES-001"] == ["XController.Login"]


def test_des001_lockout_in_conditional_callee_is_not_protection(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _MVC + (
        "public class Svc { public bool Check(string u, bool strict) { if (strict) { return Membership.ValidateUser(u, \"\"); } return true; } }\n"
        "public class XController : Controller { Svc s = new Svc();\n"
        "[HttpPost] public ActionResult Login(string u) { s.Check(u, false); return null; } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-DES-001"] == ["XController.Login"]


def test_des001_lockout_in_lambda_is_not_protection(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _MVC + (
        "public class XController : Controller {\n"
        "[HttpPost] public ActionResult Login(string u) { System.Action a = () => Membership.ValidateUser(u, \"\"); return null; } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-DES-001"] == ["XController.Login"]


def test_log004_helper_with_conditional_log_does_not_count(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _MVC + (
        "public class XController : Controller { static log4net.ILog Log; bool verbose;\n"
        "void Note(string u) { if (verbose) { Log.Warn(u); } }\n"
        "public ActionResult Login(string u) { if (!Membership.ValidateUser(u, \"\")) { Note(u); ModelState.AddModelError(\"\", \"Invalid login\"); return null; } return null; } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-LOG-004"] == ["XController.Login"]


# -- fix round 1 ------------------------------------------------------------------

def test_res003_bytes_read_from_upload_then_written(findings):
    got = hits(findings, "DNL-RES-003", "UploadBytesController.")
    assert got == ["UploadBytesController.BinaryReaderWrite", "UploadBytesController.BufferWrite",
                   "UploadBytesController.CheckOnOtherFile"]


def test_res003_check_tied_to_saved_file(findings):
    got = hits(findings, "DNL-RES-003")
    for ok in ("BinaryReaderWriteChecked", "CheckOnSameIndexedFile", "CheckOnWholeRequest"):
        assert f"UploadBytesController.{ok}" not in got
    assert "UploadBytesController.CheckOnOtherFile" in got


_ASPX = ('<%@ Page Language="C#" CodeBehind="Up.aspx.cs" Inherits="N.Up" %>\n<html><body><form runat="server">'
         '<asp:FileUpload ID="FileUpload1" runat="server" /></form></body></html>')
_DESIGNER = "namespace N { public partial class Up { protected global::System.Web.UI.WebControls.FileUpload FileUpload1; } }"


def _webforms_upload(tmp_path, body):
    code = ("using System; namespace N { public partial class Up : System.Web.UI.Page {\n"
            "const int Max = 1000; protected void Save_Click(object s, EventArgs e) {" + body + "} } }")
    return run(tmp_path, {"Up.aspx": _ASPX, "Up.aspx.cs": code, "Up.aspx.designer.cs": _DESIGNER})


def test_res003_webforms_fileupload_saveas(tmp_path, roslyn_helper):
    out = _webforms_upload(tmp_path, 'if (FileUpload1.HasFile) { FileUpload1.SaveAs("x"); }')
    assert [where(f) for f in out if f.check_id == "DNL-RES-003"] == ["Up.Save_Click"]


def test_res003_webforms_fileupload_with_check_is_guarded(tmp_path, roslyn_helper):
    out = _webforms_upload(tmp_path, 'if (FileUpload1.HasFile && FileUpload1.PostedFile.ContentLength < Max) '
                                     '{ FileUpload1.SaveAs("x"); }')
    assert not [f for f in out if f.check_id == "DNL-RES-003"]


def test_res003_webforms_filebytes_write(tmp_path, roslyn_helper):
    out = _webforms_upload(tmp_path, 'System.IO.File.WriteAllBytes("x", FileUpload1.FileBytes);')
    assert [where(f) for f in out if f.check_id == "DNL-RES-003"] == ["Up.Save_Click"]


def test_consume002_excludes_incoming_request_body(model, findings):
    assert not [f for f in _ext(findings) if f.file.endswith("OutboundExtras.cs")]


def test_login_shapes_log004(findings):
    assert hits(findings, "DNL-LOG-004", "LoginShapesController.") == [
        "LoginShapesController.Login1_Authenticate", "LoginShapesController.LoginContent",
        "LoginShapesController.LoginJson", "LoginShapesController.LoginNullUser",
        "LoginShapesController.LoginRedirect", "LoginShapesController.LoginTempData"]
    for ok in ("LoginJsonLogged", "LoginNullUserLogged", "Login3_Authenticate"):
        assert f"LoginShapesController.{ok}" not in hits(findings, "DNL-LOG-004")


def test_login_by_controller_context_and_oauth_provider(findings):
    assert "AuthController.Post" in hits(findings, "DNL-LOG-004")           # Request.CreateResponse(Unauthorized)
    assert hits(findings, "DNL-LOG-004", "AccountShapesController.") == ["AccountShapesController.Post"]
    assert hits(findings, "DNL-LOG-004", "ApplicationOAuthProvider.") == ["ApplicationOAuthProvider.GrantResourceOwnerCredentials"]
    assert hits(findings, "DNL-DES-001", "ApplicationOAuthProvider.") == ["ApplicationOAuthProvider.GrantResourceOwnerCredentials"]


def test_des001_post_on_login_controller_is_a_login(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _MVC + (
        "public class LoginController : Controller { [HttpPost] public ActionResult Post(string u) { return null; } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-DES-001"] == ["LoginController.Post"]


def test_log003_request_keys_pw_segments_and_event_log(findings):
    assert hits(findings, "DNL-LOG-003", "LogLeakExtraController.") == [
        "LogLeakExtraController.EventLogSink", "LogLeakExtraController.FormKey", "LogLeakExtraController.IndexerKey",
        "LogLeakExtraController.ParamsKey", "LogLeakExtraController.PasswdName", "LogLeakExtraController.PwSegment"]


def test_consume001_more_shapes_and_loopback_lookalikes(findings):
    assert hits(findings, "DNL-CONSUME-001", "OutboundExtras.") == [
        "OutboundExtras.LoopbackLookalike", "OutboundExtras.LoopbackSubdomain", "OutboundExtras.PostJson",
        "OutboundExtras.PutXml", "OutboundExtras.SendMessage"]


def test_consume001_endpoint_inside_location(tmp_path, roslyn_helper):
    (tmp_path / "Web.config").write_text(
        '<configuration><location path="x"><system.serviceModel><client>'
        '<endpoint name="E" address="http://loc.example.net/s" binding="basicHttpBinding" contract="I" />'
        '</client></system.serviceModel></location></configuration>')
    out = run(tmp_path, {"A.cs": "namespace N { public class A { } }"})
    assert len([f for f in out if f.check_id == "DNL-CONSUME-001"]) == 1


def test_des001_lockout_on_right_of_short_circuit_or_ternary_branch_not_protection(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _MVC + (
        "public class XController : Controller {\n"
        "[HttpPost] public ActionResult LoginAnd(string u, bool x) { if (x && Membership.ValidateUser(u, \"\")) { } return null; }\n"
        "[HttpPost] public ActionResult LoginTernary(string u, bool x) { var ok = x ? Membership.ValidateUser(u, \"\") : false; return null; }\n"
        "[HttpPost] public ActionResult LoginLeft(string u, bool x) { if (Membership.ValidateUser(u, \"\") && x) { } return null; } } }")})
    assert sorted(where(f) for f in out if f.check_id == "DNL-DES-001") == ["XController.LoginAnd", "XController.LoginTernary"]


def test_inv002_swagger_prefix_must_match_exactly(tmp_path, roslyn_helper):
    cfg = ('<configuration><location path="%s"><system.web><authorization><deny users="?" /></authorization>'
           '</system.web></location></configuration>')
    src = {"S.cs": ("using System.Web.Http;\nnamespace N { public static class SwaggerConfig { public static void R() {\n"
                    "GlobalConfiguration.Configuration.EnableSwagger(c => c.SingleApiVersion(\"v1\", \"x\")).EnableSwaggerUi(); } } }")}
    (tmp_path / "Web.config").write_text(cfg % "swagger/ui")
    out = run(tmp_path, src)
    assert len([f for f in out if f.check_id == "DNL-INV-002" and "Swagger" in f.title]) == 1
    (tmp_path / "Web.config").write_text(cfg % "swagger")
    out = run(tmp_path, src)
    assert not [f for f in out if f.check_id == "DNL-INV-002" and "Swagger" in f.title]


def test_inv002_test_controller_names(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": "using System.Web.Mvc;\nnamespace N {\n" + "\n".join(
        f"public class {n}Controller : Controller {{ }}" for n in
        ("TestResults", "SmokeTest", "UnitTest", "Tests", "Test", "Debug", "Diagnostics", "Latest")) + "}"})
    got = sorted(f.title.split(": ")[1] for f in out if f.check_id == "DNL-INV-002")
    assert got == ["DebugController", "DiagnosticsController", "SmokeTestController", "TestController",
                   "TestsController", "UnitTestController"]


def test_res002_unclamped_parameter_take_is_review(findings):
    f = next(f for f in findings if f.check_id == "DNL-RES-002" and where(f) == "OrdersListController.GetPagedUnclamped")
    assert f.confidence == "REVIEW"
    g = next(f for f in findings if f.check_id == "DNL-RES-002" and where(f) == "OrdersListController.GetTakeMax")
    assert g.confidence is None
    assert "OrdersListController.GetPaged" not in hits(findings, "DNL-RES-002")      # Math.Min clamp


# -- fix round 2 ------------------------------------------------------------------

def test_res003_raw_body_uploads(findings):
    assert hits(findings, "DNL-RES-003", "RawBodyUploadController.") == [
        "RawBodyUploadController.CheckOnOtherIndex", "RawBodyUploadController.CheckOnOtherPosition",
        "RawBodyUploadController.RawBinaryReader", "RawBodyUploadController.RawInputStreamCopy"]
    assert hits(findings, "DNL-RES-003", "RawBodyApiController.") == [
        "RawBodyApiController.PostBytes", "RawBodyApiController.PostStream"]


def test_res003_request_length_check_guards_raw_body(findings):
    got = hits(findings, "DNL-RES-003")
    assert "RawBodyUploadController.RawInputStreamCopyChecked" not in got
    assert "RawBodyApiController.PostBytesChecked" not in got
    assert "RawBodyUploadController.CheckOnSameLiteralIndex" not in got


def test_global_authorize_after_conditional_early_return_does_not_protect(tmp_path, roslyn_helper):
    out = run(tmp_path, _global_auth('if (System.Environment.MachineName == "x") return;\n'
                                     "FilterConfig.Reg(GlobalFilters.Filters);"))
    assert len([f for f in out if f.check_id == "DNL-INV-002"]) == 1


def test_global_authorize_after_response_end_branch_does_not_protect(tmp_path, roslyn_helper):
    out = run(tmp_path, _global_auth('if (System.Environment.MachineName == "x") { Response.End(); }\n'
                                     "FilterConfig.Reg(GlobalFilters.Filters);"))
    assert len([f for f in out if f.check_id == "DNL-INV-002"]) == 1


def test_des001_lockout_after_conditional_early_return_is_not_protection(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": _MVC + (
        "public class XController : Controller {\n"
        "[HttpPost] public ActionResult Login(string u) { if (System.Configuration.ConfigurationManager.AppSettings[\"x\"] == \"1\") "
        "{ return View(); } Membership.ValidateUser(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginGuarded(string u) { if (!ModelState.IsValid) { return View(); } "
        "Membership.ValidateUser(u, \"\"); return null; } } }")})
    assert [where(f) for f in out if f.check_id == "DNL-DES-001"] == ["XController.Login"]


_GATE_TYPES = (
    "public static class ThrottleLog { public static void Record(string ip) { } public static bool Allow(string ip) { return true; } }\n"
    "public static class ReCaptcha { public static bool Validate(string r) { return true; } }\n"
    "public static class Users { public static object FindAsync(string u, string p) { return null; } }\n")


def _des(tmp_path, actions):
    out = run(tmp_path, {"A.cs": _MVC + _GATE_TYPES + "public class XController : Controller {\n" + actions + "} }"})
    return sorted(where(f).split(".")[1] for f in out if f.check_id == "DNL-DES-001")


def test_des001_throttle_named_recording_call_is_not_protection(tmp_path, roslyn_helper):
    got = _des(tmp_path, (
        "[HttpPost] public ActionResult LoginRecord(string u) { ThrottleLog.Record(u); Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginIgnored(string u) { var ok = ReCaptcha.Validate(u); Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginGate(string u) { if (!ThrottleLog.Allow(u)) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginViaLocal(string u) { var ok = ReCaptcha.Validate(u); if (!ok) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginElse(string u) { if (ReCaptcha.Validate(u)) { Users.FindAsync(u, \"\"); } else { return View(); } return null; }\n"
        "[HttpPost] public ActionResult LoginEqFalse(string u) { if (ReCaptcha.Validate(u) == false) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"))
    assert got == ["LoginIgnored", "LoginRecord"]


def test_des001_gate_must_end_the_flow(tmp_path, roslyn_helper):
    got = _des(tmp_path, (
        "[HttpPost] public ActionResult LoginError(string u) { if (!ReCaptcha.Validate(u)) { ModelState.AddModelError(\"\", \"x\"); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginBraceless(string u) { if (!ReCaptcha.Validate(u)) ModelState.AddModelError(\"\", \"x\"); Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginErrorThenGate(string u) { if (!ReCaptcha.Validate(u)) { ModelState.AddModelError(\"\", \"x\"); } "
        "if (!ModelState.IsValid) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginEndsRequest(string u) { if (!ReCaptcha.Validate(u)) { Response.End(); } Users.FindAsync(u, \"\"); return null; }\n"))
    assert got == ["LoginBraceless", "LoginError"]


def test_des001_gate_polarity_must_reject_on_failure(tmp_path, roslyn_helper):
    got = _des(tmp_path, (
        "[HttpPost] public ActionResult LoginWrongWay(string u) { if (ReCaptcha.Validate(u)) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginWrongWayThrottle(string u) { if (ThrottleLog.Allow(u)) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginWrongLocal(string u) { var ok = ReCaptcha.Validate(u); if (ok) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"))
    assert got == ["LoginWrongLocal", "LoginWrongWay", "LoginWrongWayThrottle"]


def test_des001_gate_must_precede_the_attempt(tmp_path, roslyn_helper):
    got = _des(tmp_path, (
        "[HttpPost] public ActionResult LoginAfter(string u) { Users.FindAsync(u, \"\"); if (!ReCaptcha.Validate(u)) { return View(); } return null; }\n"
        "[HttpPost] public ActionResult LoginBefore(string u) { if (!ReCaptcha.Validate(u)) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"))
    assert got == ["LoginAfter"]


def test_res003_keyless_save_not_guarded_by_a_per_file_check(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": (
        "using System.IO; using System.Web; using System.Web.Mvc;\nnamespace N { public class UController : Controller {\n"
        "const int Max = 100;\n"
        "[HttpPost] public ActionResult Other() { if (Request.Files[\"a\"].ContentLength > Max) { return null; }\n"
        "File.WriteAllBytes(\"p\", new BinaryReader(Request.Files[\"b\"].InputStream).ReadBytes(10)); return null; }\n"
        "[HttpPost] public ActionResult Same() { if (Request.Files[\"b\"].ContentLength > Max) { return null; }\n"
        "File.WriteAllBytes(\"p\", new BinaryReader(Request.Files[\"b\"].InputStream).ReadBytes(10)); return null; }\n"
        "[HttpPost] public ActionResult Whole() { if (Request.ContentLength > Max) { return null; }\n"
        "File.WriteAllBytes(\"p\", new BinaryReader(Request.Files[\"b\"].InputStream).ReadBytes(10)); return null; }\n"
        "[HttpPost] public ActionResult Ctx() { if (System.Web.HttpContext.Current.Request.ContentLength > Max) { return null; }\n"
        "Request.Files[0].SaveAs(\"x\"); return null; } } }")})
    assert sorted(where(f) for f in out if f.check_id == "DNL-RES-003") == ["UController.Other"]


def test_res003_index_variable_reassigned_between_check_and_save(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": (
        "using System.Web; using System.Web.Mvc;\nnamespace N { public class UController : Controller {\n"
        "const int Max = 100;\n"
        "[HttpPost] public ActionResult Moved() { var i = 0; if (Request.Files[i].ContentLength > Max) { return null; }\n"
        "i = 1; Request.Files[i].SaveAs(\"x\"); return null; }\n"
        "[HttpPost] public ActionResult Kept() { var i = 0; if (Request.Files[i].ContentLength > Max) { return null; }\n"
        "Request.Files[i].SaveAs(\"x\"); return null; } } }")})
    assert sorted(where(f) for f in out if f.check_id == "DNL-RES-003") == ["UController.Moved"]


def test_incoming_web_api_body_is_a_request_source(tmp_path, roslyn_helper):
    from checks.dnl import taint_solver  # noqa: F401
    m, r = build(tmp_path, {"A.cs": (
        "using System.Data.SqlClient; using System.Threading.Tasks; using System.Web.Http;\n"
        "namespace N { public class BodyController : ApiController {\n"
        "public async Task<IHttpActionResult> Post() { var s = await Request.Content.ReadAsStringAsync();\n"
        "var cmd = new SqlCommand(\"select \" + s); return Ok(); } } }")})
    got = rules_taint.check(m, r)
    assert [f.check_id for f in got] == ["DNL-INJ-001"]
    assert got[0].route is not None


def test_incoming_body_fixture_reports_injection_not_consume002(model, refs):
    got = rules_taint.check(model, refs)
    assert any(f.check_id == "DNL-INJ-001" and f.file.endswith("Misc/OutboundExtras.cs") for f in got)


def test_vb_webforms_fileupload_saveas_without_size_check(tmp_path, roslyn_helper):
    out = run(tmp_path, {
        "Up.aspx": '<%@ Page Language="VB" CodeBehind="Up.aspx.vb" Inherits="N.Up" %>\n<html><body><form runat="server"></form></body></html>',
        "Up.aspx.vb": ("Imports System\nNamespace N\nPartial Public Class Up\nInherits System.Web.UI.Page\n"
                       "Protected Sub Save_Click(s As Object, e As EventArgs)\nIf FILEUPLOAD1.HasFile Then\n"
                       "FileUpload1.SaveAs(\"x\")\nEnd If\nEnd Sub\nEnd Class\nEnd Namespace\n"),
        "Up.aspx.designer.vb": ("Namespace N\nPartial Public Class Up\n"
                                "Protected WithEvents FileUpload1 As Global.System.Web.UI.WebControls.FileUpload\n"
                                "End Class\nEnd Namespace\n")}, "vb")
    assert [where(f) for f in out if f.check_id == "DNL-RES-003"] == ["Up.Save_Click"]


def test_vb_authenticate_handler_without_log(tmp_path, roslyn_helper):
    out = run(tmp_path, {"L.vb": (
        "Imports System\nImports System.Web.Security\nPublic Class LoginPage\n"
        "Protected Sub Login1_Authenticate(sender As Object, e As AuthenticateEventArgs)\n"
        "e.Authenticated = Membership.ValidateUser(\"u\", \"p\")\nEnd Sub\nEnd Class\n")}, "vb")
    assert [where(f) for f in out if f.check_id == "DNL-LOG-004"] == ["LoginPage.Login1_Authenticate"]


def test_vb_global_filter_after_conditional_early_return(tmp_path, roslyn_helper):
    out = run(tmp_path, {
        "Areas/HelpPage/HelpController.vb": ("Imports System.Web.Mvc\nNamespace App.Areas.HelpPage.Controllers\n"
                                             "Public Class HelpController\nInherits Controller\n"
                                             "Public Function Index() As ActionResult\nReturn Nothing\nEnd Function\n"
                                             "End Class\nEnd Namespace\n"),
        "G.vb": ("Imports System.Web\nImports System.Web.Mvc\nNamespace App\nPublic Class FilterConfig\n"
                 "Public Shared Sub Reg(filters As GlobalFilterCollection)\nfilters.Add(New AuthorizeAttribute())\nEnd Sub\nEnd Class\n"
                 "Public Class MvcApplication\nInherits HttpApplication\nProtected Sub Application_Start()\n"
                 "If Environment.MachineName = \"x\" Then Return\nFilterConfig.Reg(GlobalFilters.Filters)\n"
                 "End Sub\nEnd Class\nEnd Namespace\n")}, "vb")
    assert len([f for f in out if f.check_id == "DNL-INV-002"]) == 1


# -- controller fix (round 3 residuals) ------------------------------------------

def test_des001_gate_in_or_and_conditions(tmp_path, roslyn_helper):
    got = _des(tmp_path, (
        "[HttpPost] public ActionResult LoginOrValid(string u) { if (!ReCaptcha.Validate(u) || !ModelState.IsValid) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginValidOr(string u) { if (!ModelState.IsValid || !ReCaptcha.Validate(u)) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginLocalOr(string u) { var ok = ReCaptcha.Validate(u); if (!ok || !ModelState.IsValid) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginNotAnd(string u, bool x) { if (!ReCaptcha.Validate(u) && x) { return View(); } Users.FindAsync(u, \"\"); return null; }\n"
        "[HttpPost] public ActionResult LoginPosOr(string u, bool x) { if (ReCaptcha.Validate(u) || x) { Users.FindAsync(u, \"\"); } else { return View(); } return null; }\n"))
    # `!check && x` and `check || x` let a failed check through when x says so: not gates.
    assert got == ["LoginNotAnd", "LoginPosOr"]


def test_res003_expression_index_and_out_argument_invalidate_the_check(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": (
        "using System.Web; using System.Web.Mvc;\nnamespace N { public class UController : Controller {\n"
        "const int Max = 100; static void Next(out int n) { n = 1; }\n"
        "[HttpPost] public ActionResult Expr() { var i = 0; if (Request.Files[i + 1].ContentLength > Max) { return null; }\n"
        "i = 1; Request.Files[i + 1].SaveAs(\"x\"); return null; }\n"
        "[HttpPost] public ActionResult ExprKept() { var i = 0; if (Request.Files[i + 1].ContentLength > Max) { return null; }\n"
        "Request.Files[i + 1].SaveAs(\"x\"); return null; }\n"
        "[HttpPost] public ActionResult OutArg() { var i = 0; if (Request.Files[i].ContentLength > Max) { return null; }\n"
        "Next(out i); Request.Files[i].SaveAs(\"x\"); return null; } } }")})
    assert sorted(where(f) for f in out if f.check_id == "DNL-RES-003") == ["UController.Expr", "UController.OutArg"]


# -- acceptance-run precision fixes (synthetic reproductions) ---------------------

def test_log003_call_result_is_not_the_password(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": (
        "namespace N { public class Repo { public User Login(string e, string p) { return null; } }\n"
        "public class User { public string Email; }\n"
        "public static class Log { public static void Info(string s) { } }\n"
        "public class S { Repo repo = new Repo(); static log4net.ILog log;\n"
        "public void SignIn(string email, string pwd) { var account = repo.Login(email, pwd);\n"
        "  log.Info(\"locked: \" + account.Email); }\n"
        "public void Leak(string email, string pwd) { var text = string.Format(\"{0}/{1}\", email, pwd);\n"
        "  log.Info(text); }\n"
        "public void Direct(string pwd) { log.Info(Describe(pwd)); }\n"
        "string Describe(string s) { return s; } } }")})
    got = sorted(where(f) for f in out if f.check_id == "DNL-LOG-003")
    assert got == ["S.Direct", "S.Leak"]


def test_res002_entity_navigation_property_and_comparison_are_not_lists(tmp_path, roslyn_helper):
    out = run(tmp_path, {"A.cs": (
        "using System.Data.Entity; using System.Linq; using System.Web.Mvc;\n"
        "namespace N { public class Setting { public int Id; public Setting ApplicationSetting; public string Value; }\n"
        "public class User { public string Role; }\n"
        "public class Ctx : DbContext { public DbSet<Setting> ApplicationSetting { get; set; } public DbSet<User> Role { get; set; } }\n"
        "public class XController : Controller { Ctx db = new Ctx();\n"
        "public ActionResult Nav(int id) { var s = db.ApplicationSetting.Find(id); return Json(s == null ? \"\" : s.ApplicationSetting.Value); }\n"
        "public ActionResult Cmp(string n) { var u = db.Role.FirstOrDefault(); return Json(new { ok = u.Role != \"admin\" }); }\n"
        "public ActionResult All() { return Json(db.ApplicationSetting.ToList()); }\n"
        "public ActionResult Coalesce() { return Json(db.Role.ToList() ?? null); } } }")})
    got = sorted(where(f) for f in out if f.check_id == "DNL-RES-002")
    assert got == ["XController.All", "XController.Coalesce"]


def _mixed_model(tmp_path):
    (tmp_path / "W.csproj").write_text(
        '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<PropertyGroup><TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>'
        '<ItemGroup><Reference Include="System.Web.Mvc"/><Compile Include="C.cs"/></ItemGroup></Project>')
    (tmp_path / "C.cs").write_text('''using System.Data.SqlClient;
using System.Net;
using System.Web.Mvc;
namespace W {
public class C : Controller {
    public ActionResult Mixed() {
        var s = new WebClient().DownloadString("https://upstream.example.net/name");
        var cmd = new SqlCommand("SELECT * FROM T WHERE N='" + s + Request["q"] + "'");
        return Content("ok");
    }
    public ActionResult Pure() {
        var s = new WebClient().DownloadString("https://upstream.example.net/name");
        var cmd = new SqlCommand("SELECT * FROM T WHERE M='" + s + "'");
        return Content("ok");
    }
}}''')
    project._CACHE.clear()
    return project.prepare(tmp_path, True)


def test_external_hits_skip_flows_that_also_carry_request_input(tmp_path):
    m = _mixed_model(tmp_path)
    got = _ext(rules_misc.check(m, _refs(m), load_configs(m.root))[0])
    lines = [(m.root / f.file).read_text().splitlines()[f.line - 1] for f in got]
    assert len(lines) == 1 and "M='" in lines[0]
    inj = [f for f in rules_taint.check(m, _refs(m)) if f.check_id.startswith("DNL-INJ")]
    assert any("N='" in (m.root / f.file).read_text().splitlines()[f.line - 1] for f in inj)
