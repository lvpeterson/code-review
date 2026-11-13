"""Tests for checks/dnl/rules_wcf_config.py: WCF binding and behavior configuration rules."""
from pathlib import Path

import pytest

from checks.dnl.rules_wcf_config import Hosted, check_configs, non_web_config_notes
from checks.dnl.webconfig import load_configs

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy" / "wcf_app" / "WcfSvc"
CFG = FX / "Web.config"
LINES = CFG.read_text(encoding="utf-8").splitlines()


def line_of(needle: str, nth: int = 1) -> int:
    """1-based line of the nth Web.config line containing `needle`."""
    hits = [i + 1 for i, ln in enumerate(LINES) if needle in ln]
    return hits[nth - 1]


@pytest.fixture(scope="module")
def res():
    return check_configs(load_configs(FX))


@pytest.fixture(scope="module")
def findings(res):
    return res[0]


def at(findings, cid, line):
    return [f for f in findings if f.check_id == cid and f.line == line and f.file.endswith("Web.config")]


def lines_of(findings, cid):
    return sorted(f.line for f in findings if f.check_id == cid)


def test_wcf001_binding_security_none(findings):
    f = at(findings, "DNL-WCF-001", line_of('<security mode="None" />', 2))  # wsHttp secNone
    assert len(f) == 1 and f[0].severity == "high"
    assert f[0].owasp["2025"].startswith("A02:2025") and f[0].owasp["2021"].startswith("A05:2021")
    assert f[0].owasp["api2023"].startswith("API8:2023")


def test_default_basichttp_is_none(findings):
    # No bindingConfiguration and no default binding element: framework default (mode None), anchored on the endpoint.
    assert len(at(findings, "DNL-WCF-001", line_of('address="plain"'))) == 1


def test_binding_name_shared_across_types(findings):
    # basicHttpBinding "shared" is insecure, wsHttpBinding "shared" is not: only the former is reported.
    assert len(at(findings, "DNL-WCF-001", line_of('<binding name="shared"><security mode="None" />'))) == 1
    assert not at(findings, "DNL-WCF-001", line_of('<binding name="shared" />'))
    assert not at(findings, "DNL-WCF-001", line_of('address="shared" binding="wsHttpBinding"'))


def test_message_credential_none_over_http(findings):
    assert len(at(findings, "DNL-WCF-001", line_of('<binding name="msgAnon">'))) == 1


def test_transport_credential_none_over_https_is_safe(findings):
    assert not at(findings, "DNL-WCF-001", line_of('<binding name="transportAnon">'))


def test_safe_bindings_not_flagged(findings):
    assert not at(findings, "DNL-WCF-001", line_of('<binding name="httpsOnly">'))
    assert not at(findings, "DNL-WCF-001", line_of('address="https" binding="basicHttpBinding"'))


def test_local_endpoint_exempt(findings):
    assert not at(findings, "DNL-WCF-001", line_of('address="http://localhost:8733/local"'))
    # the net.pipe endpoint names a basicHttp "secNone" that does not exist, so it falls back to the
    # default (mode None) and is exempt; the secNone element is reported once, for OpenSvc.
    assert len(at(findings, "DNL-WCF-001", line_of('<security mode="None" />', 2))) == 1


def test_wcf001_only_the_expected_findings(findings):
    # plain, shared(basic), secNone, msgAnon, bigMsg(default None), relLocal, credOnly
    assert len(lines_of(findings, "DNL-WCF-001")) == 7


def test_wcf002_exception_detail(findings):
    f = at(findings, "DNL-WCF-002", line_of('includeExceptionDetailInFaults="true"'))
    assert len(f) == 1
    assert f[0].severity == "info" and "Removed by the Web.Release.config" in f[0].description
    assert not at(findings, "DNL-WCF-002", line_of('includeExceptionDetailInFaults="false"'))
    assert len([x for x in findings if x.check_id == "DNL-WCF-002"]) == 1


def test_wcf002_stays_medium_without_transform(tmp_path):
    (tmp_path / "Web.config").write_text(CFG.read_text(encoding="utf-8"), encoding="utf-8")
    f = [x for x in check_configs(load_configs(tmp_path))[0] if x.check_id == "DNL-WCF-002"]
    assert len(f) == 1 and f[0].severity == "medium"


def test_wcf003_metadata_http_get_and_mex(findings):
    get = at(findings, "DNL-WCF-003", line_of('<serviceMetadata httpGetEnabled="true"'))
    mex = at(findings, "DNL-WCF-003", line_of('contract="IMetadataExchange"'))
    assert len(get) == 1 and len(mex) == 1
    assert get[0].severity == "low" and get[0].owasp["api2023"].startswith("API9:2023")
    assert not at(findings, "DNL-WCF-003", line_of('httpGetEnabled="false"'))


def test_wcf003_api9_always_tagged(findings):
    # WCF-003 carries API9 in "always" mode, independent of the api_surface flag
    from core.owasp_web import owasp_for
    assert owasp_for("DNL-WCF-003", False)["api2023"].startswith("API9")
    assert all(f.owasp["api2023"].startswith("API9") for f in findings if f.check_id == "DNL-WCF-003")


def test_wcf004_oversize_binding_one_finding(findings):
    f = at(findings, "DNL-WCF-004", line_of('<binding name="bigMsg"'))
    assert len(f) == 1 and f[0].severity == "low"
    assert "maxReceivedMessageSize" in f[0].description and "maxStringContentLength" in f[0].description


def test_wcf004_missing_throttling(findings):
    assert len(at(findings, "DNL-WCF-004", line_of('<behavior name="debugOn">'))) == 1
    assert not at(findings, "DNL-WCF-004", line_of('<behavior name="safeBeh">'))
    assert len([x for x in findings if x.check_id == "DNL-WCF-004"]) == 3  # + customBig


def test_views_and_unparsable_configs(tmp_path):
    (tmp_path / "Views").mkdir()
    (tmp_path / "Views" / "Web.config").write_text("<configuration/>", encoding="utf-8")
    (tmp_path / "Web.config").write_text("<configuration><oops>", encoding="utf-8")
    assert check_configs(load_configs(tmp_path)) == ([], [])  # parse failures are noted by rules_config


def test_default_behavior_used_when_service_names_none(tmp_path):
    (tmp_path / "Web.config").write_text(
        '<configuration><system.serviceModel>'
        '<services><service name="A.S"><endpoint address="x" binding="netTcpBinding" contract="A.I" /></service></services>'
        '<behaviors><serviceBehaviors><behavior><serviceDebug includeExceptionDetailInFaults="true" /></behavior>'
        '</serviceBehaviors></behaviors></system.serviceModel></configuration>', encoding="utf-8")
    f = check_configs(load_configs(tmp_path))[0]
    assert [x.check_id for x in f if x.check_id != "DNL-WCF-004"] == ["DNL-WCF-002"]
    assert len([x for x in f if x.check_id == "DNL-WCF-004"]) == 1  # default behavior lacks serviceThrottling


def test_config_analyzer_runs_wcf_rules(roslyn_helper):
    import languages.dotnet_legacy.analyzers  # noqa: F401, PLC0415 -- registers the analyzers
    from core.registry import get_analyzer  # noqa: PLC0415
    res = get_analyzer("dotnet_legacy", "config")(FX.parent).analyze()
    assert {"DNL-WCF-001", "DNL-WCF-002", "DNL-WCF-003", "DNL-WCF-004"} <= {f.check_id for f in res.findings}


def test_relative_localhost_address_not_exempt(findings):
    # "localhost/x" has no scheme: it is relative to the host base address, not loopback.
    assert len(at(findings, "DNL-WCF-001", line_of('<binding name="relLocal">') + 1)) == 1


def test_transport_credential_only_over_http(findings):
    f = at(findings, "DNL-WCF-001", line_of('mode="TransportCredentialOnly"'))
    assert len(f) == 1 and f[0].severity == "high" and "clear" in f[0].description


def test_shared_binding_lists_every_endpoint(findings):
    f = at(findings, "DNL-WCF-001", line_of('<binding name="shared"><security mode="None" />'))[0]
    assert '"shared"' in f.description and '"shared2"' in f.description and "Cfg.OpenSvc" in f.description


def test_custom_binding_nested_limits(findings):
    f = at(findings, "DNL-WCF-004", line_of('<binding name="customBig">'))
    assert len(f) == 1
    assert "httpTransport maxReceivedMessageSize" in f[0].description and "readerQuotas maxArrayLength" in f[0].description


def test_custom_binding_is_noted(res):
    assert any('WCF binding "customBinding" of service "Cfg.ExtraSvc"' in n for n in res[1]), res[1]


@pytest.fixture(scope="module")
def wcf_hosted(roslyn_helper):
    from checks.dnl import project  # noqa: PLC0415
    from checks.dnl.rules_wcf_config import hosted_services  # noqa: PLC0415
    project._CACHE.clear()
    return hosted_services(project.prepare(FX.parent, False))


@pytest.fixture(scope="module")
def hosted_findings(wcf_hosted):
    return check_configs(load_configs(FX), wcf_hosted)[0]


def test_hosted_service_without_service_element_gets_default_endpoint(hosted_findings):
    # Billing.svc comes from <serviceActivations> and has no <service>/<endpoint>: basicHttp default, mode None.
    f = at(hosted_findings, "DNL-WCF-001", line_of('<add relativeAddress="Billing.svc"'))
    assert len(f) == 1 and "WcfSvc.BillingService" in f[0].description and "default" in f[0].description
    # .svc-hosted services with no <service> element anchor on <system.serviceModel>
    g = at(hosted_findings, "DNL-WCF-001", line_of("<system.serviceModel>"))
    assert len(g) == 1 and "WcfSvc.OrderService" in g[0].description


def _tmp_cfg(tmp_path, body):
    (tmp_path / "Web.config").write_text(
        '<configuration><system.serviceModel>' + body + '</system.serviceModel></configuration>', encoding="utf-8")
    return load_configs(tmp_path)


def test_protocol_mapping_to_secured_binding_is_safe(tmp_path):
    body = ('<protocolMapping><add scheme="http" binding="wsHttpBinding" /></protocolMapping>'
            '<serviceHostingEnvironment><serviceActivations><add relativeAddress="A.svc" service="N.A" />'
            '</serviceActivations></serviceHostingEnvironment>')
    f = check_configs(_tmp_cfg(tmp_path, body), [("N.A", tmp_path.resolve(), tmp_path.resolve())])[0]
    assert not [x for x in f if x.check_id == "DNL-WCF-001"]


def test_protocol_mapping_to_insecure_binding_and_framework_default(tmp_path):
    act = ('<serviceHostingEnvironment><serviceActivations><add relativeAddress="A.svc" service="N.A" />'
           '</serviceActivations></serviceHostingEnvironment>')
    mapped = '<protocolMapping><add scheme="http" binding="basicHttpBinding" bindingConfiguration="m" /></protocolMapping>'
    bind = '<bindings><basicHttpBinding><binding name="m"><security mode="None" /></binding></basicHttpBinding></bindings>'
    f = check_configs(_tmp_cfg(tmp_path, mapped + bind + act), [("N.A", tmp_path.resolve(), tmp_path.resolve())])[0]
    assert len([x for x in f if x.check_id == "DNL-WCF-001"]) == 1
    # a <service> with no endpoints and an https base address maps to basicHttpsBinding: secure
    svc = ('<services><service name="N.B"><host><baseAddresses><add baseAddress="https://x.test/b" /></baseAddresses></host>'
           '</service></services>')
    f = check_configs(_tmp_cfg(tmp_path, svc))[0]
    assert not [x for x in f if x.check_id == "DNL-WCF-001"]
    # same service over http: default basicHttpBinding, mode None, anchored at the <service>
    f = check_configs(_tmp_cfg(tmp_path, svc.replace("https://", "http://")))[0]
    assert len([x for x in f if x.check_id == "DNL-WCF-001"]) == 1


def test_endpoint_without_binding_uses_protocol_mapping(tmp_path):
    svc = '<services><service name="N.C"><endpoint address="x" contract="N.I" /></service></services>'
    f = check_configs(_tmp_cfg(tmp_path, svc))[0]
    assert len([x for x in f if x.check_id == "DNL-WCF-001"]) == 1


def test_kind_with_explicit_binding_uses_the_binding(tmp_path):
    # kind only matters when binding is absent: the explicit secured wsHttpBinding wins over the mapping.
    svc = ('<services><service name="N.D"><endpoint address="x" kind="basicHttpEndpoint" '
           'binding="wsHttpBinding" contract="N.I" /></service></services>')
    f = check_configs(_tmp_cfg(tmp_path, svc))[0]
    assert not [x for x in f if x.check_id == "DNL-WCF-001"]
    bad = svc.replace('binding="wsHttpBinding"', 'binding="basicHttpBinding"')
    assert len([x for x in check_configs(_tmp_cfg(tmp_path, bad))[0] if x.check_id == "DNL-WCF-001"]) == 1


def test_unknown_kind_and_unmapped_scheme_are_noted(tmp_path):
    svc = ('<services><service name="N.E"><endpoint address="x" kind="fooEndpoint" contract="N.I" />'
           '<endpoint address="soap.tcp://h/x" contract="N.I" /></service></services>')
    notes = check_configs(_tmp_cfg(tmp_path, svc))[1]
    assert any('service "N.E"' in n and 'unknown kind "fooEndpoint"' in n for n in notes), notes
    assert any('scheme "soap.tcp"' in n and 'service "N.E"' in n for n in notes), notes


def test_default_endpoints_with_different_bindings_keep_their_own_text(tmp_path):
    svc = ('<protocolMapping><add scheme="https" binding="webHttpBinding" /></protocolMapping>'
           '<services><service name="N.F"><host><baseAddresses><add baseAddress="http://x.test/f" />'
           '<add baseAddress="https://x.test/f" /></baseAddresses></host></service></services>')
    f = [x for x in check_configs(_tmp_cfg(tmp_path, svc))[0] if x.check_id == "DNL-WCF-001"]
    assert len(f) == 1
    assert "basicHttpBinding" in f[0].description and "webHttpBinding" in f[0].description


def test_svc_in_subfolder_uses_nearest_config_above(tmp_path):
    (tmp_path / "sub").mkdir()
    cfgs = _tmp_cfg(tmp_path, "")
    hosted = [("N.G", (tmp_path / "sub").resolve(), tmp_path.resolve())]
    f = check_configs(cfgs, hosted)[0]
    assert len([x for x in f if x.check_id == "DNL-WCF-001"]) == 1
    # a config above the project dir does not count
    assert check_configs(cfgs, [("N.G", (tmp_path / "sub").resolve(), (tmp_path / "sub").resolve())])[0] == []


def test_svc_without_any_config_gets_default_unsecured_finding(tmp_path):
    (tmp_path / "S.svc").write_text('<%@ ServiceHost\n    Service="N.S" %>\n', encoding="utf-8")
    d = tmp_path.resolve()
    f, notes = check_configs(load_configs(tmp_path), [Hosted("N.S", d, d, "S.svc", 1)])
    assert len(f) == 1 and f[0].check_id == "DNL-WCF-001" and f[0].severity == "high"
    assert f[0].file == "S.svc" and f[0].line == 1
    assert "No web.config" in f[0].description and "basicHttpBinding" in f[0].description


def test_svc_with_unparsable_owning_config_is_noted_not_guessed(tmp_path):
    (tmp_path / "Web.config").write_text("<configuration><oops>", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    d = tmp_path.resolve()
    f, notes = check_configs(load_configs(tmp_path), [Hosted("N.S", d / "sub", d, "sub/S.svc", 1)])
    assert f == []
    assert "sub/S.svc: owning web.config could not be parsed; WCF security not evaluated" in notes


def test_different_kinds_on_one_line_share_one_finding(tmp_path):
    # The merge keys hits by (file, line): two anchors on one line must not drop the second.
    body = ('<services><service name="N.A">'
            '<endpoint address="a" binding="wsHttpBinding" bindingConfiguration="m" contract="c" />'
            '<endpoint address="b" binding="basicHttpBinding" bindingConfiguration="c" contract="c" />'
            '</service></services><bindings><wsHttpBinding><binding name="m"><security>'
            '<message clientCredentialType="None" /></security></binding></wsHttpBinding>'
            '<basicHttpBinding><binding name="c"><security mode="TransportCredentialOnly" /></binding>'
            '</basicHttpBinding></bindings>')
    f = [x for x in check_configs(_tmp_cfg(tmp_path, body))[0] if x.check_id == "DNL-WCF-001"]
    assert len(f) == 1
    d = f[0].description
    assert '"a"' in d and '"b"' in d and "clientCredentialType" in d and "TransportCredentialOnly" in d


def test_hosted_services_on_real_fixture(wcf_hosted):
    by = {h.name: h for h in wcf_hosted}
    assert by["Nope.Nested"].dir == (FX / "Sub").resolve() and by["Nope.Nested"].stop == FX.resolve()
    assert by["WcfSvc.OrderService"].dir == FX.resolve() and by["WcfSvc.OrderService"].src.endswith("OrderService.svc")
    assert by["WcfSvc.OrderService"].line == 1
    # the nested .svc resolves to the nearest config above it (FX/Web.config) and joins its default-endpoint finding
    f = check_configs(load_configs(FX), wcf_hosted)[0]
    g = at(f, "DNL-WCF-001", line_of("<system.serviceModel>"))
    assert len(g) == 1 and "Nope.Nested" in g[0].description


def _wcf001(findings):
    return [x for x in findings if x.check_id == "DNL-WCF-001"]


def test_parent_config_binding_is_resolved_for_child_service(tmp_path):
    (tmp_path / "Web.config").write_text(
        '<configuration><system.serviceModel><bindings><wsHttpBinding><binding name="open">'
        '<security mode="None" /></binding></wsHttpBinding></bindings></system.serviceModel></configuration>',
        encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "Web.config").write_text(
        '<configuration><system.serviceModel><services><service name="N.Child">'
        '<endpoint address="x" binding="wsHttpBinding" bindingConfiguration="open" contract="N.I" />'
        '</service></services></system.serviceModel></configuration>', encoding="utf-8")
    got = _wcf001(check_configs(load_configs(tmp_path))[0])
    assert len(got) == 1 and got[0].file == "sub/Web.config" and "wsHttpBinding" in got[0].description
    # the child's own binding of the same name still wins over the parent's
    (tmp_path / "sub" / "Web.config").write_text(
        '<configuration><system.serviceModel><services><service name="N.Child">'
        '<endpoint address="x" binding="wsHttpBinding" bindingConfiguration="open" contract="N.I" />'
        '</service></services><bindings><wsHttpBinding><binding name="open"><security mode="Message" />'
        '</binding></wsHttpBinding></bindings></system.serviceModel></configuration>', encoding="utf-8")
    assert _wcf001(check_configs(load_configs(tmp_path))[0]) == []


def test_parent_config_protocol_mapping_and_behavior(tmp_path):
    (tmp_path / "Web.config").write_text(
        '<configuration><system.serviceModel><protocolMapping><add scheme="http" binding="wsHttpBinding" />'
        '</protocolMapping><behaviors><serviceBehaviors><behavior name="B"><serviceThrottling />'
        '</behavior></serviceBehaviors></behaviors></system.serviceModel></configuration>', encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "Web.config").write_text(
        '<configuration><system.serviceModel><services><service name="N.Child" behaviorConfiguration="B">'
        '<endpoint address="x" contract="N.I" /></service></services></system.serviceModel></configuration>',
        encoding="utf-8")
    f = check_configs(load_configs(tmp_path))[0]
    # mapped to the secured wsHttpBinding by the parent; the parent's behavior has throttling
    assert _wcf001(f) == [] and not [x for x in f if x.check_id == "DNL-WCF-004"]


_REVIEW_NOTE = "Assumes the site is served over plain http"


def test_default_endpoint_findings_are_review(tmp_path):
    svc = '<services><service name="N.B"><host><baseAddresses><add baseAddress="http://x.test/b" /></baseAddresses></host></service></services>'
    (g,) = _wcf001(check_configs(_tmp_cfg(tmp_path, svc))[0])
    assert g.severity == "high" and g.confidence == "REVIEW"
    assert _REVIEW_NOTE in g.description and "basicHttpsBinding" in g.description
    # an explicit endpoint keeps its confidence
    ex = ('<services><service name="N.B"><endpoint address="x" binding="basicHttpBinding" contract="N.I" />'
          '</service></services>')
    (e,) = _wcf001(check_configs(_tmp_cfg(tmp_path, ex))[0])
    assert e.confidence is None and _REVIEW_NOTE not in e.description


def test_svc_without_config_default_is_review(tmp_path):
    (tmp_path / "S.svc").write_text('<%@ ServiceHost Service="N.S" %>\n', encoding="utf-8")
    d = tmp_path.resolve()
    (f,) = check_configs(load_configs(tmp_path), [Hosted("N.S", d, d, "S.svc", 1)])[0]
    assert f.confidence == "REVIEW" and _REVIEW_NOTE in f.description


def test_nettcp_transport_anonymous_wording(tmp_path):
    body = ('<services><service name="N.T"><endpoint address="net.tcp://h/t" binding="netTcpBinding" '
            'bindingConfiguration="t" contract="N.I" /></service></services>'
            '<bindings><netTcpBinding><binding name="t"><security mode="Transport"><transport '
            'clientCredentialType="None" /></security></binding></netTcpBinding></bindings>')
    (f,) = _wcf001(check_configs(_tmp_cfg(tmp_path, body))[0])
    assert "anonymous callers (no client credential)" in f.description and "HTTPS" not in f.description
    assert "HTTPS" not in f.title and "anonymous" in f.title.lower()


def test_services_in_non_web_config_are_noted(tmp_path):
    (tmp_path / "App.config").write_text(
        '<configuration><system.serviceModel><services><service name="N.S">'
        '<endpoint address="x" binding="basicHttpBinding" contract="N.I" /></service></services>'
        '</system.serviceModel></configuration>', encoding="utf-8")
    assert non_web_config_notes(tmp_path) == [
        "App.config: WCF services declared outside web.config hosting are not discovered"]
    (tmp_path / "App.config").rename(tmp_path / "Web.config")
    assert non_web_config_notes(tmp_path) == []
