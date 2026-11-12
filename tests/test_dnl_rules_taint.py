"""Code-sink findings (11 kinds: SQL, Dynamic LINQ, command, LDAP, XPath, header, XSS, path, redirect, SSRF,
log) built from the taint engine."""
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_taint

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def findings(roslyn_helper):
    project._CACHE.clear()
    model = project.prepare(FX / "taint_app", False)
    refs = routes.discover_mvc_webapi(model) + routes.discover_webforms(model)
    return rules_taint.check(model, refs)


def hits(findings, rule, file_endswith=None, method_hint=None):
    out = [f for f in findings if f.check_id == rule]
    if file_endswith:
        out = [f for f in out if f.file.endswith(file_endswith)]
    if method_hint:
        out = [f for f in out if f"in {method_hint}" in f.description or f".{method_hint}" in f.description]
    return out


def one(findings, rule, **kw):
    found = hits(findings, rule, **kw)
    assert len(found) == 1, [(f.file, f.line, f.description) for f in found]
    return found[0]


def test_sql_injection_proven_on_route(findings):
    f = one(findings, "DNL-INJ-001", file_endswith="OrderRepository.cs")
    assert f.severity == "high" and f.confidence is None and f.route.handler_name == "OrdersController.Search"
    assert "Source: request parameter term" in f.description and " -> " in f.description
    assert "in OrderRepository.FindByTerm" in f.description


def test_parameterized_query_never_fires(findings):
    assert not hits(findings, "DNL-INJ-001", file_endswith="SafeRepository.cs")


def test_unproven_is_review_one_level_lower(findings):
    f = one(findings, "DNL-INJ-001", method_hint="Orphan")
    assert f.severity == "medium" and f.confidence == "REVIEW" and f.route is None
    assert "from parameter 's' of Misc.Orphan" in f.description and "verify how it is called" in f.description


def test_dynamic_linq(findings):
    linq = hits(findings, "DNL-INJ-006", file_endswith="Linq.cs")
    assert linq and all(f.severity == "high" and f.confidence is None for f in linq)
    assert linq[0].description.startswith("Dynamic LINQ injection -- untrusted input reaches ")


def test_one_finding_per_rule_file_line(findings):
    keys = [(f.check_id, f.file, f.line) for f in findings]
    assert len(keys) == len(set(keys))


def test_unconverged_note(roslyn_helper):
    project._CACHE.clear()
    model = project.prepare(FX / "taint_app", False)
    rules_taint.check(model, [])
    assert not [n for n in model.notes if "converging" in n]
    model.cache["taint"]["converged"] = False
    model.cache["taint"]["rounds"] = 12
    rules_taint.check(model, [])
    rules_taint.check(model, [])
    notes = [n for n in model.notes if "without converging" in n]
    assert len(notes) == 1 and "12 rounds" in notes[0]


_KINDS = [
    ("DNL-INJ-002", "Cmd", "high"), ("DNL-INJ-003", "Ldap", "high"), ("DNL-INJ-004", "Xpath", "medium"),
    ("DNL-INJ-005", "Header", "medium"), ("DNL-XSS-001", "Xss", "high"), ("DNL-PATH-001", "Path", "high"),
    ("DNL-REDIR-001", "Redirect", "medium"), ("DNL-SSRF-001", "Ssrf", "high"), ("DNL-LOG-001", "Log", "low"),
]


@pytest.mark.parametrize("rule,kind,sev", _KINDS)
def test_code_sink_bad_fires_good_does_not(findings, rule, kind, sev):
    f = one(findings, rule, file_endswith="CodeSinksController.cs", method_hint=f"{kind}Bad")
    assert f.severity == sev and f.confidence is None
    assert f.route is not None and f.route.handler_name.startswith("CodeSinksController.")
    assert not hits(findings, rule, method_hint=f"{kind}Good")


def test_ssrf_api_tag(findings):
    f = one(findings, "DNL-SSRF-001", file_endswith="ApiSsrfController.cs")
    assert f.route is not None and f.route.handler_name == "ApiSsrfController.Get"
    assert f.owasp["api2023"].startswith("API7:2023")


def test_two_routes_one_sink_names_first_route(roslyn_helper):
    # Refs are passed in reversed order: the named route must not depend on discovery order.
    project._CACHE.clear()
    model = project.prepare(FX / "taint_app", False)
    refs = routes.discover_mvc_webapi(model) + routes.discover_webforms(model)
    for order in (refs, list(reversed(refs))):
        found = rules_taint.check(model, order)
        f = one(found, "DNL-INJ-001", file_endswith="Shared.cs")
        assert f.route.handler_name == "TwoRoutesController.Left"
        assert f.description.endswith("; also reached from 1 more route(s)")
        # a sink reached by a single route carries no suffix
        assert "also reached" not in one(found, "DNL-INJ-001", file_endswith="OrderRepository.cs").description
