"""WCF operations as routes: discovery, effective auth, taint entry points."""
from pathlib import Path

import pytest

from checks.dnl import auth, project, rules_auth, rules_taint
from checks.dnl.routes import discover_wcf
from checks.dnl.webconfig import load_configs
from languages.dotnet_legacy import detector

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def wcf(roslyn_helper):
    project._CACHE.clear()
    model = project.prepare(FX / "wcf_app", False)
    refs = discover_wcf(model)
    configs = load_configs(model.root)
    infos = {r.route.handler_name: auth.resolve_wcf(model, r, configs) for r in refs}
    findings = rules_auth.check_routes(model, refs, auth.global_filters(model), auth.chain_for_model(model))
    findings += rules_taint.check(model, refs)
    return model, refs, infos, findings


@pytest.fixture
def refs(wcf):
    return wcf[1]


@pytest.fixture
def wcf_auth(wcf):
    return wcf[2]


@pytest.fixture
def findings(wcf):
    return wcf[3]


@pytest.fixture
def wcf_model(wcf):
    return wcf[0]


def one(findings, rule, handler=None, file_endswith=None):
    out = [f for f in findings if f.check_id == rule
           and (handler is None or (f.route is not None and f.route.handler_name == handler))
           and (file_endswith is None or f.file.endswith(file_endswith))]
    assert len(out) == 1, [(f.file, f.line, f.description) for f in out]
    return out[0]


def test_wcf_operations_become_routes(refs):
    p = {(r.route.handler_name, r.route.path) for r in refs if r.route.meta["kind"] == "wcf"}
    assert ("OrderService.Find", "/OrderService.svc/Find") in p and ("BillingService.Charge", "/Billing.svc/Charge") in p
    assert all(r.route.meta["api_surface"] for r in refs if r.route.meta["kind"] == "wcf")


def test_route_shape(refs):
    r = next(r for r in refs if r.route.handler_name == "OrderService.Delete")
    assert r.route.methods == ["POST"] and r.route.file.endswith("OrderService.cs")
    assert r.route.line == r.method.line and r.route.source_end_line == r.method.end_line
    assert r.route.meta["contract"] == "WcfSvc.IOrderService" and r.route.meta["svc"] == "OrderService.svc"
    assert {x.route.handler_name for x in refs} == {
        "OrderService.Find", "OrderService.Delete", "BillingService.Charge"}


def test_principal_permission_protects(wcf_auth):
    assert wcf_auth["OrderService.Delete"].protected and wcf_auth["OrderService.Delete"].roles == ["Admin"]
    assert wcf_auth["OrderService.Delete"].source == "attribute:PrincipalPermission"
    assert not wcf_auth["OrderService.Find"].protected


def test_unprotected_operation_flagged(findings):
    f = one(findings, "DNL-AUTHZ-001", "OrderService.Find")
    assert f.route.meta["kind"] == "wcf" and f.owasp["api2023"].startswith("API5:2023")
    assert not [x for x in findings if x.check_id == "DNL-AUTHZ-001" and x.route.handler_name == "OrderService.Delete"]


def test_wcf_param_taint_reaches_sql(findings):
    f = one(findings, "DNL-INJ-001", file_endswith="OrderService.cs")
    assert f.confidence is None and f.route.handler_name == "OrderService.Find"


def test_unresolved_factory_is_noted(wcf_model):
    # Ghost.svc: <%@ ServiceHost Factory="X.Factory" Service="Nope.Missing" %> -- no type in the model
    refs = discover_wcf(wcf_model)
    assert not [r for r in refs if r.route.meta["svc"].endswith("Ghost.svc")]
    notes = [n for n in wcf_model.notes if "Ghost.svc: WCF service type not resolved" in n]
    assert len(notes) == 1 and "Factory=X.Factory" in notes[0]


def test_detector_finds_wcf():
    assert detector.detect_frameworks(FX / "wcf_app") == ["wcf", "config", "deps"]


def _app(tmp_path, files, cfg=""):
    app = tmp_path / "A"
    app.mkdir(parents=True)
    comp = "".join(f'<Compile Include="{n}" />' for n in files if n.endswith(".cs"))
    (app / "A.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        f'<ItemGroup>{comp}</ItemGroup></Project>')
    for n, text in files.items():
        (app / n).write_text(text)
    if cfg:
        (app / "Web.config").write_text(cfg)
    project._CACHE.clear()
    return project.prepare(app, False)


_IFACE = ('using System.ServiceModel; namespace N { [ServiceContract] public interface IS {'
          ' [OperationContract(Name = "Look")] string Find(string a); [OperationContract] void Ping(); } }')
_PLAIN = 'namespace N { public class S : IS { public string Find(string a) { return a; } public void Ping() { } } }'
_SVC = '<%@ ServiceHost Service="N.S" %>'


def _first_auth(model):
    return auth.resolve_wcf(model, discover_wcf(model)[0], load_configs(model.root))


def test_operation_name_and_inline_body_checks(tmp_path, roslyn_helper):
    impl = ('namespace N { public class S : IS {'
            ' public string Find(string a) { if (!System.Threading.Thread.CurrentPrincipal.IsInRole("X")) throw new System.Exception(); return a; }'
            ' public void Ping() { new System.Security.Permissions.PrincipalPermission(null, "R").Demand(); } } }')
    model = _app(tmp_path, {"IS.cs": _IFACE, "S.cs": impl, "S.svc": "<%@ ServiceHost\n  service='N.S' %>"})
    refs = discover_wcf(model)
    assert {r.route.path for r in refs} == {"/S.svc/Look", "/S.svc/Ping"}
    for r in refs:
        info = auth.resolve_wcf(model, r, load_configs(model.root))
        assert info.protected and info.review and info.source == "operation body check", r.route.path


_BEHAVIOR_CFG = (
    '<configuration><system.serviceModel>'
    '<services><service name="N.S" behaviorConfiguration="B">'
    '<endpoint address="" binding="BINDING" contract="N.IS" />'
    '<endpoint address="mex" binding="mexHttpBinding" contract="IMetadataExchange" /></service></services>'
    '<behaviors><serviceBehaviors><behavior name="B"><serviceAuthorization principalPermissionMode="UseWindowsGroups" />'
    '</behavior></serviceBehaviors></behaviors></system.serviceModel></configuration>')


def test_service_authorization_behavior_and_binding(tmp_path, roslyn_helper):
    files = {"IS.cs": _IFACE, "S.cs": _PLAIN, "S.svc": _SVC}
    info = _first_auth(_app(tmp_path, files, _BEHAVIOR_CFG.replace("BINDING", "wsHttpBinding")))
    assert info.protected and info.review and info.source == "wcf binding/behavior"


def test_anonymous_binding_leaves_operation_open(tmp_path, roslyn_helper):
    files = {"IS.cs": _IFACE, "S.cs": _PLAIN, "S.svc": _SVC}
    info = _first_auth(_app(tmp_path, files, _BEHAVIOR_CFG.replace("BINDING", "basicHttpBinding")))
    assert not info.protected and info.source == "none"


def test_web_config_deny_needs_aspnet_compat(tmp_path, roslyn_helper):
    cfg = ('<configuration><system.web><authorization><deny users="?" /></authorization></system.web>'
           '<system.serviceModel><serviceHostingEnvironment aspNetCompatibilityEnabled="{v}" /></system.serviceModel></configuration>')
    files = {"IS.cs": _IFACE, "S.cs": _PLAIN, "S.svc": _SVC}
    model = _app(tmp_path, files, cfg.replace("{v}", "true"))
    info = _first_auth(model)
    assert info.protected and info.source == "web.config"
    (tmp_path / "A" / "Web.config").write_text(cfg.replace("{v}", "false"))
    assert not auth.resolve_wcf(model, discover_wcf(model)[0], load_configs(model.root)).protected


# -- fix round 1 ----------------------------------------------------------------

def _routes(model):
    return {r.route.path: r for r in discover_wcf(model)}


def test_overloads_with_distinct_names_keep_their_own_auth(tmp_path, roslyn_helper):
    iface = ('using System.ServiceModel; namespace N { [ServiceContract] public interface IS {'
             ' [OperationContract(Name = "FindById")] string Find(int id);'
             ' [OperationContract(Name = "FindByName")] string Find(string n); } }')
    impl = ('using System.Security.Permissions; namespace N { public class S : IS {'
            ' [PrincipalPermission(SecurityAction.Demand, Role = "A")] public string Find(int id) { return ""; }'
            ' public string Find(string n) { return n; } } }')
    model = _app(tmp_path, {"IS.cs": iface, "S.cs": impl, "S.svc": _SVC})
    rs = _routes(model)
    assert set(rs) == {"/S.svc/FindById", "/S.svc/FindByName"}
    cfgs = load_configs(model.root)
    assert auth.resolve_wcf(model, rs["/S.svc/FindById"], cfgs).protected
    assert not auth.resolve_wcf(model, rs["/S.svc/FindByName"], cfgs).protected


def test_ambiguous_overload_is_noted_and_not_routed(tmp_path, roslyn_helper):
    iface = ('using System.ServiceModel; namespace N { [ServiceContract] public interface IS {'
             ' [OperationContract] string Find(Foo f); } public class Foo {} }')
    impl = ('namespace N { public class S : IS { public string Find(A.Foo f) { return ""; }'
            ' public string Find(B.Foo f) { return ""; } } }')
    model = _app(tmp_path, {"IS.cs": iface, "S.cs": impl, "S.svc": _SVC})
    assert discover_wcf(model) == []
    assert any("S.svc: operation IS.Find is ambiguous" in n for n in model.notes)


def test_missing_implementation_is_noted(tmp_path, roslyn_helper):
    iface = ('using System.ServiceModel; namespace N { [ServiceContract] public interface IS {'
             ' [OperationContract] string Find(string a); [OperationContract] void Gone(); } }')
    impl = 'namespace N { public class S : IS { public string Find(string a) { return a; } } }'
    model = _app(tmp_path, {"IS.cs": iface, "S.cs": impl, "S.svc": _SVC})
    assert list(_routes(model)) == ["/S.svc/Find"]
    assert any("S.svc: operation IS.Gone has no implementation in the scanned sources" in n for n in model.notes)


def test_missing_contract_is_noted(tmp_path, roslyn_helper):
    orphan = 'namespace N { public class S : IMissing { public string Find(string a) { return a; } } }'
    model = _app(tmp_path, {"S.cs": orphan, "S.svc": _SVC})
    assert discover_wcf(model) == []
    assert any("S.svc: contract IMissing not found in the scanned sources" in n for n in model.notes)


def test_vb_implements_clause_links_operation(tmp_path, roslyn_helper):
    app = tmp_path / "V"
    app.mkdir(parents=True)
    (app / "V.vbproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Compile Include="S.vb" /></ItemGroup></Project>')
    (app / "S.vb").write_text(
        "Imports System.ServiceModel\nImports System.Security.Permissions\nNamespace N\n"
        "<ServiceContract()> Public Interface IOrderService\n"
        "    <OperationContract()> Function Find(term As String) As String\nEnd Interface\n"
        "Public Class OrderService\n    Implements IOrderService\n"
        '    <PrincipalPermission(SecurityAction.Demand, Role:="Admin")>\n'
        "    Public Function Lookup(term As String) As String Implements IOrderService.Find\n"
        '        Return ""\n    End Function\nEnd Class\nEnd Namespace\n')
    (app / "S.svc").write_text('<%@ ServiceHost Service="N.OrderService" %>')
    project._CACHE.clear()
    model = project.prepare(app, False)
    rs = _routes(model)
    assert list(rs) == ["/S.svc/Find"] and rs["/S.svc/Find"].route.handler_name == "OrderService.Lookup"
    assert auth.resolve_wcf(model, rs["/S.svc/Find"], load_configs(model.root)).roles == ["Admin"]


def test_service_contract_on_class_and_assert_does_not_protect(tmp_path, roslyn_helper):
    impl = ('using System.ServiceModel; using System.Security.Permissions; namespace N { [ServiceContract] public class S {'
            ' [OperationContract] [PrincipalPermission(SecurityAction.Assert, Role = "A")] public string Find(string a) { return a; }'
            ' [OperationContract] [PrincipalPermission(SecurityAction.LinkDemand, Role = "A")] public void Ping() { } } }')
    model = _app(tmp_path, {"S.cs": impl, "S.svc": _SVC})
    rs = _routes(model)
    assert set(rs) == {"/S.svc/Find", "/S.svc/Ping"}
    for r in rs.values():
        assert not auth.resolve_wcf(model, r, load_configs(model.root)).protected


def test_body_check_emits_review_finding(tmp_path, roslyn_helper):
    impl = ('namespace N { public class S : IS {'
            ' public string Find(string a) { if (!System.Threading.Thread.CurrentPrincipal.IsInRole("X")) throw new System.Exception(); return a; }'
            ' public void Ping() { } } }')
    model = _app(tmp_path, {"IS.cs": _IFACE, "S.cs": impl, "S.svc": _SVC})
    fs = rules_auth.check_routes(model, discover_wcf(model), [], auth.chain_for_model(model))
    f = one(fs, "DNL-AUTHZ-001", "S.Find")
    assert f.severity == "low" and f.confidence == "REVIEW"


def test_behavior_protection_says_authentication_only(tmp_path, roslyn_helper):
    files = {"IS.cs": _IFACE, "S.cs": _PLAIN, "S.svc": _SVC}
    model = _app(tmp_path, files, _BEHAVIOR_CFG.replace("BINDING", "wsHttpBinding"))
    info = _first_auth(model)
    assert "authenticate" in info.detail and "no per-operation authorization found" in info.detail
    fs = rules_auth.check_routes(model, discover_wcf(model), [], auth.chain_for_model(model))
    assert "no per-operation authorization found" in one(fs, "DNL-AUTHZ-001", "S.Find").description


@pytest.mark.parametrize("endpoint", [
    '<endpoint address="" binding="customBinding" bindingConfiguration="C" contract="N.IS" />',
    '<endpoint address="" binding="fancyBinding" contract="N.IS" />',
    '<endpoint address="" binding="" contract="N.IS" />',
    '<endpoint address="" kind="webHttpEndpoint" contract="N.IS" />',
])
def test_unknown_bindings_are_not_credentialed(tmp_path, roslyn_helper, endpoint):
    cfg = ('<configuration><system.serviceModel>'
           '<services><service name="N.S" behaviorConfiguration="B">' + endpoint + '</service></services>'
           '<bindings><customBinding><binding name="C"><textMessageEncoding /><httpTransport /></binding></customBinding></bindings>'
           '<behaviors><serviceBehaviors><behavior name="B"><serviceAuthorization principalPermissionMode="UseWindowsGroups" />'
           '</behavior></serviceBehaviors></behaviors></system.serviceModel></configuration>')
    info = _first_auth(_app(tmp_path, {"IS.cs": _IFACE, "S.cs": _PLAIN, "S.svc": _SVC}, cfg))
    assert not info.protected


def test_credential_follows_security_mode(tmp_path, roslyn_helper):
    def cfg(mode, inner):
        return ('<configuration><system.serviceModel><services><service name="N.S" behaviorConfiguration="B">'
                '<endpoint address="" binding="basicHttpBinding" bindingConfiguration="X" contract="N.IS" /></service></services>'
                f'<bindings><basicHttpBinding><binding name="X"><security mode="{mode}">{inner}</security></binding></basicHttpBinding></bindings>'
                '<behaviors><serviceBehaviors><behavior name="B"><serviceAuthorization principalPermissionMode="UseWindowsGroups" />'
                '</behavior></serviceBehaviors></behaviors></system.serviceModel></configuration>')
    files = {"IS.cs": _IFACE, "S.cs": _PLAIN, "S.svc": _SVC}
    # a stray message element does not count in Transport mode
    stray = '<transport clientCredentialType="None" /><message clientCredentialType="UserName" />'
    assert not _first_auth(_app(tmp_path / "a", files, cfg("Transport", stray))).protected
    ok = '<transport clientCredentialType="Basic" /><message clientCredentialType="None" />'
    assert _first_auth(_app(tmp_path / "b", files, cfg("Transport", ok))).protected
    msg = '<transport clientCredentialType="None" /><message clientCredentialType="UserName" />'
    assert _first_auth(_app(tmp_path / "c", files, cfg("Message", msg))).protected


def test_detector_reads_service_model_from_any_config(tmp_path):
    def fw(n, cfg):
        d = tmp_path / f"d{n}"
        d.mkdir()
        (d / "App.config").write_text(cfg)
        return detector.detect_frameworks(d)
    assert fw(1, '<configuration><system.serviceModel><services><service name="A" /></services>'
                 '</system.serviceModel></configuration>') == ["wcf"]
    assert fw(2, '<configuration><system.serviceModel><serviceHostingEnvironment><serviceActivations>'
                 '<add relativeAddress="a.svc" service="A" /></serviceActivations></serviceHostingEnvironment>'
                 '</system.serviceModel></configuration>') == ["wcf"]
    assert fw(3, '<configuration><!-- <system.serviceModel><services /></system.serviceModel> --></configuration>') == []
    assert fw(4, '<configuration><system.serviceModel><client><endpoint name="e" /></client>'
                 '</system.serviceModel></configuration>') == []


# -- fix round 2 ----------------------------------------------------------------

def _custom_cfg(mode, endpoint_extra=""):
    return ('<configuration><system.serviceModel><services><service name="N.S" behaviorConfiguration="B">'
            '<endpoint address="" binding="customBinding" bindingConfiguration="C" contract="N.IS" />' + endpoint_extra +
            '</service></services><bindings><customBinding><binding name="C">'
            f'<security authenticationMode="{mode}" /><httpTransport /></binding></customBinding></bindings>'
            '<behaviors><serviceBehaviors><behavior name="B"><serviceAuthorization principalPermissionMode="UseWindowsGroups" />'
            '</behavior></serviceBehaviors></behaviors></system.serviceModel></configuration>')


def test_custom_binding_anonymous_modes_are_not_credentials(tmp_path, roslyn_helper):
    files = {"IS.cs": _IFACE, "S.cs": _PLAIN, "S.svc": _SVC}
    for i, mode in enumerate(("AnonymousForSslNegotiated", "anonymousForCertificate")):
        assert not _first_auth(_app(tmp_path / str(i), files, _custom_cfg(mode))).protected
    assert _first_auth(_app(tmp_path / "ok", files, _custom_cfg("UserNameForCertificate"))).protected


def test_mex_kind_endpoint_is_ignored_but_other_kinds_count(tmp_path, roslyn_helper):
    files = {"IS.cs": _IFACE, "S.cs": _PLAIN, "S.svc": _SVC}
    mex = '<endpoint address="mex" kind="mexEndpoint" />'
    assert _first_auth(_app(tmp_path / "a", files, _custom_cfg("UserNameForCertificate", mex))).protected
    other = '<endpoint address="web" kind="webHttpEndpoint" contract="N.IS" />'
    assert not _first_auth(_app(tmp_path / "b", files, _custom_cfg("UserNameForCertificate", other))).protected


def test_unresolved_interface_noted_alongside_resolved_contract(tmp_path, roslyn_helper):
    impl = ('namespace N { public class S : IS, IExtra { public string Find(string a) { return a; }'
            ' public void Ping() { } } }')
    model = _app(tmp_path, {"IS.cs": _IFACE, "S.cs": impl, "S.svc": _SVC})
    assert len(discover_wcf(model)) == 2
    assert any("S.svc: contract IExtra not found in the scanned sources" in n for n in model.notes)


def test_duplicate_effective_operation_name_is_noted(tmp_path, roslyn_helper):
    iface = ('using System.ServiceModel; namespace N { [ServiceContract] public interface IS {'
             ' [OperationContract(Name = "Same")] string A(string x); [OperationContract(Name = "Same")] string B(string x); } }')
    impl = 'namespace N { public class S : IS { public string A(string x) { return x; } public string B(string x) { return x; } } }'
    model = _app(tmp_path, {"IS.cs": iface, "S.cs": impl, "S.svc": _SVC})
    assert list(_routes(model)) == ["/S.svc/Same"]
    assert any("S.svc: operation IS.B repeats the operation name Same" in n for n in model.notes)


def test_detector_falls_back_on_malformed_config(tmp_path):
    (tmp_path / "Web.config").write_text(
        '<configuration><system.serviceModel><serviceHostingEnvironment><serviceActivations>'
        '<add relativeAddress="a.svc" service="A" /></serviceActivations></serviceHostingEnvironment>'
        '</system.serviceModel><oops></configuration>')
    assert "wcf" in detector.detect_frameworks(tmp_path)


def test_framework_ifaces_make_no_missing_contract_note(tmp_path, roslyn_helper):
    # R4: WCF extension-point / BCL interfaces carry no operations, so an unresolved one is not a gap.
    impl = ('namespace N { public class S : IS, IErrorHandler, IServiceBehavior, IEquatable<S>, ISerializable'
            ' { public string Find(string a) { return a; } public void Ping() { } } }')
    model = _app(tmp_path, {"IS.cs": _IFACE, "S.cs": impl, "S.svc": _SVC})
    assert len(discover_wcf(model)) == 2
    assert not [n for n in model.notes if "not found in the scanned sources" in n], model.notes


def test_missing_operations_aggregate_into_one_note(tmp_path, roslyn_helper):
    ops = "".join(f" [OperationContract] void Op{i}();" for i in range(6))
    iface = f'using System.ServiceModel; namespace N {{ [ServiceContract] public interface IS {{{ops} }} }}'
    model = _app(tmp_path, {"IS.cs": iface, "S.cs": "namespace N { public class S : IS { } }", "S.svc": _SVC})
    discover_wcf(model)
    notes = [n for n in model.notes if "no implementation" in n]
    assert len(notes) == 1, model.notes
    assert notes[0] == ("S.svc: 6 operations of IS have no implementation in the scanned sources "
                        "(first: IS.Op0, IS.Op1, IS.Op2)")


def test_few_missing_operations_are_listed(tmp_path, roslyn_helper):
    iface = ('using System.ServiceModel; namespace N { [ServiceContract] public interface IS {'
             ' [OperationContract] void A(); [OperationContract] void B(); } }')
    model = _app(tmp_path, {"IS.cs": iface, "S.cs": "namespace N { public class S : IS { } }", "S.svc": _SVC})
    discover_wcf(model)
    assert ("S.svc: 2 operations of IS have no implementation in the scanned sources (IS.A, IS.B)") in model.notes


def test_missing_content_includes_aggregate_per_project(tmp_path):
    app = tmp_path / "A"
    app.mkdir()
    items = "".join(f'<Content Include="m{i}.svc" />' for i in range(5))
    (app / "A.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        f'<ItemGroup>{items}</ItemGroup></Project>')
    notes: list[str] = []
    project.load_projects(app, notes)
    assert notes == ["A.csproj: 5 Content includes not found (first: m0.svc, m1.svc, m2.svc)"]


def _wcf_site(tmp_path, helper_src):
    """A project referencing System.ServiceModel with a service, a helper class and a WebForms page."""
    app = tmp_path / "W"
    app.mkdir()
    (app / "W.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>'
        '<Reference Include="System.ServiceModel" /><Compile Include="IS.cs" /><Compile Include="S.cs" />'
        '<Compile Include="H.cs" /><Content Include="S.svc" /><Content Include="P.aspx" /></ItemGroup></Project>')
    (app / "IS.cs").write_text(_IFACE)
    (app / "S.cs").write_text(_PLAIN)
    (app / "H.cs").write_text(helper_src)
    (app / "S.svc").write_text(_SVC)
    (app / "P.aspx").write_text('<%@ Page Language="C#" %>')
    (app / "Web.config").write_text("<configuration><system.web /></configuration>")
    return app


def test_route_less_finding_in_service_model_project_goes_to_wcf(tmp_path, roslyn_helper):
    from core.registry import get_analyzer  # noqa: PLC0415
    import languages.dotnet_legacy.analyzers  # noqa: F401,PLC0415
    app = _wcf_site(tmp_path, 'using System.Security.Cryptography; namespace N { public class H {'
                              ' public object M() { return MD5.Create(); } } }')
    project._CACHE.clear()
    owners = {fw: [f for f in get_analyzer("dotnet_legacy", fw)(app).analyze().findings
                   if f.check_id == "DNL-CRY-001" and f.file == "H.cs"]
              for fw in ("mvc", "webapi", "webforms", "wcf", "config")}
    project._CACHE.clear()
    assert {k: len(v) for k, v in owners.items() if v} == {"wcf": 1}, owners


def _body_gate(tmp_path, roslyn_helper, body):
    impl = ('using System.Security.Permissions; namespace N { public class S : IS {'
            ' public string Find(string a) { return a; } public void Ping() { ' + body + ' } } }')
    model = _app(tmp_path, {"IS.cs": _IFACE, "S.cs": impl, "S.svc": _SVC})
    ref = next(r for r in discover_wcf(model) if r.route.handler_name == "S.Ping")
    return auth.resolve_wcf(model, ref, load_configs(model.root))


def test_demand_counts_only_on_a_principal_permission(tmp_path, roslyn_helper):
    unrelated = _body_gate(tmp_path / "a", roslyn_helper,
                           'var f = new FileIOPermission(PermissionState.Unrestricted); f.Demand();'
                           ' new PrincipalPermission(null, "R"); ')
    assert not unrelated.protected
    held = _body_gate(tmp_path / "b", roslyn_helper,
                      'var p = new PrincipalPermission(null, "R"); p.Demand();')
    assert held.protected and held.review
    chained = _body_gate(tmp_path / "c", roslyn_helper, 'new PrincipalPermission(null, "R").Demand();')
    assert chained.protected


def test_wcf_fixture_project_includes_all_resolve(wcf):
    assert not [n for n in wcf[0].notes if "include not found" in n or "includes not found" in n], wcf[0].notes
