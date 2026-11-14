from pathlib import Path
from core.html_report import render_html
from core.models import Finding, ScanResult, Route
from core.report import _finding_to_dict, _scan_result_to_dict
from core.sarif_report import build_sarif
from core.allowlist import apply_allowlist
from checks.dnl.findings import dnl_finding

def _result(**kw):
    f = dnl_finding("DNL-CFG-001", "medium", "debug on", "d", "Web.config", 5, api_surface=True)
    return ScanResult(language="dotnet_legacy", framework="config", findings=[f], **kw)

def test_json_carries_owasp_and_degraded():
    r = _result(degraded="Roslyn helper not available")
    d = _scan_result_to_dict(r)
    assert d["degraded"] == "Roslyn helper not available"
    assert d["findings"][0]["owasp"]["2025"].startswith("A02:2025")

def test_sarif_tags():
    rule = build_sarif([_result()])["runs"][0]["tool"]["driver"]["rules"][0]
    assert {"owasp-2025:A02", "owasp-2021:A05", "owasp-api-2023:API8"} <= set(rule["properties"]["tags"])

def test_sarif_result_and_run_properties():
    sarif = build_sarif([_result(degraded="x")])
    run = sarif["runs"][0]
    assert run["properties"]["degraded"] == "x"
    assert run["results"][0]["properties"]["owasp"]["2021"].startswith("A05:2021")

def test_console_owasp_line(capsys):
    from core.report import print_console
    print_console([_result()])
    assert "OWASP A02:2025 | A05:2021 | API8:2023" in capsys.readouterr().out

def test_html_owasp_tab_and_coverage(tmp_path):
    html = render_html([_result()], tmp_path)
    assert 'id="tab-panel-owasp"' in html and 'data-owasp="2025:A02"' in html
    assert html.count('class="owasp-row') == 30
    assert "degraded-banner" not in html

def test_html_degraded_banner(tmp_path):
    assert "degraded-banner" in render_html([_result(degraded="x")], tmp_path)

def test_allowlist_drops_dnl_missing_auth():
    route = Route(path="/health", methods=["GET"], handler_name="H.Get", file="a.cs", line=1)
    f = dnl_finding("DNL-AUTHZ-001", "medium", "t", "d", "a.cs", 1, route=route)
    r = ScanResult(language="dotnet_legacy", framework="mvc", routes=[route], findings=[f])
    apply_allowlist([r], ["/health"])
    assert r.findings == []

def test_dnl_authz_findings_render_in_auth_tab():
    from core.html_report import _is_auth_finding
    assert _is_auth_finding(dnl_finding("DNL-AUTHZ-001", "medium", "t", "d", "a.cs", 1))
    assert _is_auth_finding(dnl_finding("DNL-AUTHZ-004", "low", "t", "d", "a.cs", 1))
    assert not _is_auth_finding(dnl_finding("DNL-CSRF-001", "medium", "t", "d", "a.cs", 1))
    assert not _is_auth_finding(dnl_finding("DNL-CFG-001", "medium", "t", "d", "a.cs", 1))


def test_sarif_download_is_named_after_the_report():
    from pathlib import Path
    from core.html_report import render_html
    h = render_html([], Path("."))
    assert "function sarifFileName()" in h
    assert "suggestedName: fileName" in h and "a.download = fileName" in h
    assert "'appsec-review.sarif'" not in h  # the fixed name is only the fallback base now
    assert "(base || 'appsec-review') + '.sarif'" in h
