"""Effective auth resolution and AUTHZ / CSRF rules for MVC 5 / Web API 2."""
from pathlib import Path

import pytest

from checks.dnl import auth, ir, project, rules_auth
from checks.dnl.routes import discover_mvc_webapi

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


def _run(app: str):
    project._CACHE.clear()
    model = project.prepare(FX / app, False)
    refs = discover_mvc_webapi(model)
    filters = auth.global_filters(model)
    chain_for = auth.chain_for_model(model)
    results = [(r, auth.resolve(model, r, filters, chain_for)) for r in refs]
    findings = rules_auth.check_routes(model, refs, filters, chain_for)
    return model, refs, results, findings


@pytest.fixture(scope="module")
def mvc(roslyn_helper):
    return _run("mvc5_app")


@pytest.fixture(scope="module")
def glob(roslyn_helper):
    return _run("webapi_global")


@pytest.fixture
def auth_results(mvc):
    return mvc[2]


@pytest.fixture
def findings(mvc):
    return mvc[3]


@pytest.fixture
def global_results(glob):
    return glob[2]


@pytest.fixture
def global_findings(glob):
    return glob[3]


def info_of(results, handler):
    return next(i for r, i in results if r.route.handler_name == handler)


def hits(findings, check_id, handler=None):
    return [f for f in findings if f.check_id == check_id
            and (handler is None or (f.route is not None and f.route.handler_name == handler))]


def one(findings, check_id, handler=None):
    got = hits(findings, check_id, handler)
    assert len(got) == 1, (check_id, handler, got)
    return got[0]


# -- brief tests ------------------------------------------------------------

def test_base_controller_authorize_inherited(auth_results):
    i = info_of(auth_results, "HomeController.Index")
    assert i.protected and i.source == "base:BaseController"


def test_public_controller_flagged(findings):
    f = one(findings, "DNL-AUTHZ-001", "PublicController.Index")
    assert f.severity == "medium" and f.route.meta["kind"] == "mvc"


def test_never_denying_attribute(findings, auth_results):
    assert one(findings, "DNL-AUTHZ-003").file.endswith("AlwaysAllowAttribute.cs")
    assert not info_of(auth_results, "LooseController.Index").protected


def test_custom_real_attribute_counts(auth_results):
    assert info_of(auth_results, "OrdersApiController.GetOrder").source == "attribute:RealAuth"


def test_allow_anonymous_post(findings):
    assert one(findings, "DNL-AUTHZ-002", "PublicController.Register").confidence == "REVIEW"
    assert one(findings, "DNL-CSRF-001", "PublicController.Register")
    assert not hits(findings, "DNL-CSRF-001", "HomeController.Save")


def test_admin_without_roles(findings):
    assert one(findings, "DNL-AUTHZ-004", "AdminController.DeleteUser").severity == "low"


def test_webapi_global_filter(global_results):
    i = info_of(global_results, "ValuesController.Get")
    assert i.protected and i.source == "global filter (webapi)"


def test_class_level_finding_has_no_api_tag(findings):
    assert "api2023" not in one(findings, "DNL-AUTHZ-003").owasp


def test_api_route_gets_api_tag(global_findings):
    f = one(global_findings, "DNL-AUTHZ-001", "HealthController.Get")   # webapi_global: [AllowAnonymous] HealthController
    assert f.owasp["api2023"].startswith("API5:2023")


# -- R5 and extra coverage ----------------------------------------------------

def test_allow_anonymous_is_info_authz_001(findings, global_findings):
    for fs, h in ((findings, "PublicController.Register"), (global_findings, "HealthController.Get")):
        f = one(fs, "DNL-AUTHZ-001", h)
        assert f.severity == "info"
        assert "explicitly public via [AllowAnonymous]; confirm this is intended" in f.description


def test_unprotected_description_and_never_denying_source(findings, auth_results):
    f = one(findings, "DNL-AUTHZ-001", "LooseController.Index")
    assert f.severity == "medium" and "AlwaysAllow" in f.description
    assert info_of(auth_results, "LooseController.Index").source == "attribute:AlwaysAllow"
    f = one(findings, "DNL-AUTHZ-001", "ReportsController.Year")
    assert "No [Authorize], global filter, base controller or web.config rule covers this action." in f.description


def test_protected_routes_quiet_and_decorated(mvc, findings):
    for h in ("HomeController.Index", "HomeController.Save", "OrdersApiController.Remove", "AdminController.DeleteUser"):
        assert not hits(findings, "DNL-AUTHZ-001", h)
    refs = mvc[1]
    home = next(r for r in refs if r.route.handler_name == "HomeController.Index")
    assert home.route.auth_decorators == ["base:BaseController"]
    pub = next(r for r in refs if r.route.handler_name == "PublicController.Index")
    assert pub.route.auth_decorators == []


def test_webapi_routes_never_get_csrf(findings, global_findings):
    assert not hits(findings, "DNL-CSRF-001", "OrdersApiController.Remove")
    assert not hits(global_findings, "DNL-CSRF-001")


def test_global_filters_listed(mvc, glob):
    assert [(k, t) for k, t, _, _ in auth.global_filters(mvc[0])] == [("mvc", "HandleErrorAttribute")]
    (k, t, f, line), = auth.global_filters(glob[0])
    assert (k, t) == ("webapi", "AuthorizeAttribute") and f.endswith("WebApiConfig.cs") and line > 0


def test_auth_attribute_types_and_is_auth_attr(mvc):
    model = mvc[0]
    assert set(auth.auth_attribute_types(model)) == {"alwaysallow", "realauth"}
    assert auth.is_auth_attr(model, "Authorize") and auth.is_auth_attr(model, "realauth")
    assert not auth.is_auth_attr(model, "HandleError")


# -- never_denies unit cases (synthetic IR) ---------------------------------

def _t(*methods, bases=("AuthorizeAttribute",)):
    return ir.TypeIR("X", "N", "class", ["public"], list(bases), [], [], [], list(methods), 1, 9, "x.cs")


def _ret(v):
    return {"k": "return", "value": v}


TRUE = {"k": "lit", "v": True, "t": "bool"}
FALSE = {"k": "lit", "v": False, "t": "bool"}


def test_never_denies_cases():
    assert auth.never_denies(_t(ir.MethodIR("AuthorizeCore", body=[_ret(TRUE)])))
    assert not auth.never_denies(_t(ir.MethodIR("AuthorizeCore", body=[_ret(TRUE), _ret(FALSE)])))
    assert not auth.never_denies(_t(ir.MethodIR("IsAuthorized", body=[_ret({"k": "name", "id": "ok"})])))
    assert not auth.never_denies(_t())
    # OnAuthorization that only logs never denies; one that sets Result / throws / calls base does.
    log = {"k": "expr", "expr": {"k": "call", "fn": {"k": "name", "id": "Log"}, "args": []}}
    assert auth.never_denies(_t(ir.MethodIR("onauthorization", body=[log])))
    deny = {"k": "assign", "op": "=", "target": {"k": "member", "name": "Result", "obj": {"k": "name", "id": "ctx"}},
            "value": {"k": "new", "type": "HttpUnauthorizedResult", "args": [], "init": []}}
    assert not auth.never_denies(_t(ir.MethodIR("OnAuthorization", body=[deny])))
    assert not auth.never_denies(_t(ir.MethodIR("OnAuthorization", body=[{"k": "throw", "value": None}])))
    base = {"k": "expr", "expr": {"k": "call", "args": [],
                                  "fn": {"k": "member", "name": "OnAuthorization", "obj": {"k": "name", "id": "base"}}}}
    assert not auth.never_denies(_t(ir.MethodIR("OnAuthorization", body=[base])))


# -- fix round 1 ----------------------------------------------------------------

@pytest.fixture(scope="module")
def hand(roslyn_helper):
    return _run("mvc_handrolled")


def test_allow_anonymous_inherited_from_base_controller(glob):
    _, _, results, fs = glob
    i = info_of(results, "StatusController.Get")
    assert i.anonymous and not i.protected and i.source == "AllowAnonymous"
    assert i.file.endswith("StatusController.cs")
    assert one(fs, "DNL-AUTHZ-001", "StatusController.Get").severity == "info"


def test_allow_anonymous_qualified_with_suffix(glob):
    _, refs, results, fs = glob
    assert info_of(results, "PingController.Ping").anonymous
    assert next(r for r in refs if r.route.handler_name == "PingController.Ping").route.methods == ["PUT"]
    assert one(fs, "DNL-AUTHZ-002", "PingController.Ping").confidence == "REVIEW"
    assert "accepts PUT without" in one(fs, "DNL-AUTHZ-002", "PingController.Ping").description


def test_allow_anonymous_vb_lowercase_suffix_synthetic():
    a = ir.Attr("AllowAnonymousattribute")
    assert ir.has_attr([a], "AllowAnonymous") is a
    assert ir.attr_simple("System.Web.Mvc.AuthorizeAttribute") == "Authorize"


def test_web_config_deny_protects(hand):
    _, _, results, fs = hand
    i = info_of(results, "SecureController.Index")
    assert i.protected and i.source == "web.config" and i.file.endswith("Web.config") and i.line > 0
    assert not hits(fs, "DNL-AUTHZ-001", "SecureController.Index")


def test_hand_rolled_on_authorization_is_review(hand):
    _, refs, results, fs = hand
    i = info_of(results, "VaultController.Index")
    assert i.protected and i.review and i.source == "base OnAuthorization override"
    f = one(fs, "DNL-AUTHZ-001", "VaultController.Index")
    assert f.severity == "low" and f.confidence == "REVIEW"
    assert "hand-rolled check in GuardedBase.OnAuthorization" in f.description
    assert "verify it actually denies unauthenticated requests" in f.description
    vault = next(r for r in refs if r.route.handler_name == "VaultController.Index")
    assert vault.route.auth_decorators == ["base OnAuthorization override"]


def test_viewbag_is_authenticated_read_is_not_a_check(hand):
    _, _, results, fs = hand
    i = info_of(results, "GreetController.Index")
    assert not i.protected and not i.review and i.source == "none"
    f = one(fs, "DNL-AUTHZ-001", "GreetController.Index")
    assert f.severity == "medium" and f.confidence is None


def _ctl(attrs, method_attrs=(), name="AdminController", file="c.cs"):
    m = ir.MethodIR("DeleteUser", ["public"], attributes=list(method_attrs), line=3, end_line=4)
    return ir.TypeIR(name, "App.Controllers", "class", ["public"], ["Controller"], list(attrs), [], [], [m], 1, 9, file)


def _synthetic(types, extra_files=()):
    files = {t.file: ir.FileIR(t.file, "cs", "p", 0, [t]) for t in list(types) + list(extra_files)}
    return project.ProjectModel(FX, [], files, None, [])


def test_non_literal_roles_suppress_authz_004():
    roles = {"Roles": {"k": "member", "name": "Admin", "obj": {"k": "name", "id": "RoleNames"}}}
    model = _synthetic([_ctl([ir.Attr("Authorize", named=roles)])])
    refs = discover_mvc_webapi(model)
    info = auth.resolve(model, refs[0], [], lambda r: [])
    assert info.roles == ["RoleNames.Admin"] and info.source == "attribute:Authorize"
    assert not hits(rules_auth.check_routes(model, refs, [], lambda r: []), "DNL-AUTHZ-004")


def test_source_uses_stripped_attribute_name():
    model = _synthetic([_ctl([ir.Attr("System.Web.Mvc.AuthorizeAttribute")])])
    refs = discover_mvc_webapi(model)
    assert auth.resolve(model, refs[0], [], lambda r: []).source == "attribute:Authorize"


def test_qualified_verb_attribute_counts_for_csrf():
    model = _synthetic([_ctl([], [ir.Attr("System.Web.Mvc.HttpPostattribute")], name="ThingsController")])
    refs = discover_mvc_webapi(model)
    assert refs[0].route.methods == ["POST"]
    f = one(rules_auth.check_routes(model, refs, [], lambda r: []), "DNL-CSRF-001")
    assert "accepts POST but no" in f.description


def test_global_filter_needs_known_matching_project():
    # Synthetic model has no projects: a global filter cannot be attributed, so it does not protect.
    model = _synthetic([_ctl([], name="ThingsController")])
    refs = discover_mvc_webapi(model)
    info = auth.resolve(model, refs[0], [("mvc", "AuthorizeAttribute", "f.cs", 3)], lambda r: [])
    assert not info.protected and info.source == "none"


# -- final review fixes ------------------------------------------------------------

def test_never_denies_follows_base_when_override_calls_base():
    base_call = {"k": "expr", "expr": {"k": "call", "args": [], "fn": {
        "k": "member", "name": "OnAuthorization", "obj": {"k": "name", "id": "base"}}}}
    allow = ir.TypeIR("AlwaysAllow", "N", "class", ["public"], ["AuthorizeAttribute"], [], [], [],
                      [ir.MethodIR("AuthorizeCore", body=[_ret(TRUE)])], 1, 9, "a.cs")
    derived = ir.TypeIR("Derived", "N", "class", ["public"], ["AlwaysAllow"], [], [], [],
                        [ir.MethodIR("OnAuthorization", body=[base_call])], 1, 9, "d.cs")
    ctl = _ctl([ir.Attr("Derived")], name="ThingsController")
    model = _synthetic([allow, derived, ctl])
    assert auth.never_denies(derived, model)
    refs = discover_mvc_webapi(model)
    info = auth.resolve(model, refs[0], [], lambda r: [])
    assert not info.protected
    fs = rules_auth.check_routes(model, refs, [], lambda r: [])
    assert {f.check_id for f in fs} >= {"DNL-AUTHZ-003", "DNL-AUTHZ-001"}
    assert any(f.check_id == "DNL-AUTHZ-003" and "Derived" in f.title for f in fs)
