"""Exception-handling rules DNL-ERR-001 (fail-open auth catch), 002 (exception detail returned to the
client) and 003 (swallowed exception)."""
import re
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_errors, rules_taint, rules_xss
from core.owasp_web import owasp_for

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


@pytest.fixture(scope="module")
def refs(model):
    return routes.discover_mvc_webapi(model) + routes.discover_webforms(model) + routes.discover_wcf(model)


@pytest.fixture(scope="module")
def findings(model, refs):
    return rules_errors.check(model, refs)


def where(f):
    """`Type.Method` out of the trailing `(in Type.Method)`."""
    return re.search(r"\(in ([^)]+)\)\.?$", f.description).group(1)


def hits(findings, rule, prefix="", file_part=""):
    return sorted(where(f) for f in findings
                  if f.check_id == rule and where(f).startswith(prefix) and file_part in f.file)


# -- ERR-002 --------------------------------------------------------------------

def test_err002_controller_positives(findings):
    assert hits(findings, "DNL-ERR-002", "ErrLeakController.") == [
        "ErrLeakController.Direct", "ErrLeakController.ViaInnerAndConcat", "ErrLeakController.ViaInterpolation",
        "ErrLeakController.ViaJson", "ErrLeakController.ViaLocal", "ErrLeakController.ViaModel",
        "ErrLeakController.ViaViewBag", "ErrLeakController.ViaWholeException"]


def test_err002_review_focus_local(findings):
    # Review Focus 3: `var msg = ex.Message; return Content(msg);` must be flagged.
    assert "ErrLeakController.ViaLocal" in hits(findings, "DNL-ERR-002")


def test_err002_safe_catches_not_flagged(findings):
    got = hits(findings, "DNL-ERR-002")
    for safe in ("GenericMessage", "TypeNameOnly", "Swallowed", "SwallowedBare", "NarrowEmpty"):
        assert f"ErrLeakController.{safe}" not in got


def test_err002_webapi_and_wcf(findings):
    assert hits(findings, "DNL-ERR-002", "ErrApiController.") == [
        "ErrApiController.Get", "ErrApiController.Post", "ErrApiController.Put"]
    assert hits(findings, "DNL-ERR-002", "ErrSvc.") == ["ErrSvc.Run"]


def test_err002_vb_case_insensitive(findings):
    assert hits(findings, "DNL-ERR-002", "VbErrController.") == ["VbErrController.Leak", "VbErrController.LeakBag"]


def test_err002_routed_and_api_tag(findings):
    f = next(f for f in findings if f.check_id == "DNL-ERR-002" and where(f) == "ErrApiController.Post")
    assert f.route is not None and f.severity == "medium"
    assert f.owasp["2025"].startswith("A10") and f.owasp["2021"].startswith("A05")
    assert "API8" in str(f.owasp)


# -- ERR-001 --------------------------------------------------------------------

def test_err001_positives(findings):
    got = hits(findings, "DNL-ERR-001")
    for want in ("FailOpenAttribute.AuthorizeCore", "EmptyCatchAuth.AuthorizeCore", "LogOnlyFilter.OnAuthorization",
                 "CalleeAuth.Allowed", "VbAuth.AuthorizeCore", "VbAuthEmpty.AuthorizeCore"):
        assert want in got, want


def test_err001_negatives(findings):
    got = hits(findings, "DNL-ERR-001")
    for safe in ("FailSafeAttribute.AuthorizeCore", "DefaultDenyHelper.CanSee", "ActionWithRole.Purge",
                 "VbAuthSafe.AuthorizeCore"):
        assert safe not in got, safe
    assert all(f.severity == "medium" for f in findings if f.check_id == "DNL-ERR-001")


def test_err001_not_double_reported_as_err003(findings):
    e1 = set(hits(findings, "DNL-ERR-001"))
    e3 = set(hits(findings, "DNL-ERR-003"))
    assert e1 & e3 == set()
    assert "EmptyCatchAuth.AuthorizeCore" in e1 and "EmptyCatchAuth.AuthorizeCore" not in e3
    assert "VbAuthEmpty.AuthorizeCore" in e1 and "VbAuthEmpty.AuthorizeCore" not in e3


# -- ERR-003 --------------------------------------------------------------------

def test_err003_positives_and_narrow_type_skipped(findings):
    assert hits(findings, "DNL-ERR-003", "ErrLeakController.") == [
        "ErrLeakController.Swallowed", "ErrLeakController.SwallowedBare"]
    assert hits(findings, "DNL-ERR-003", "VbErrController.") == ["VbErrController.Swallow", "VbErrController.SwallowTyped"]
    assert all(f.severity == "low" for f in findings if f.check_id == "DNL-ERR-003")


def test_err003_owasp():
    o = owasp_for("DNL-ERR-003", False)
    assert o["2025"].startswith("A10") and o["2021"].startswith("A04")
    o = owasp_for("DNL-ERR-001", False)
    assert o["2025"].startswith("A10") and o["2021"].startswith("A04")


# -- isolation from the request-source rules --------------------------------------

def test_exception_flow_does_not_feed_injection_or_xss_rules(model, refs):
    # `Content(ex.Message)` is an exception flow, not a request source: no INJ/XSS finding there.
    others = rules_taint.check(model, refs) + rules_xss.check(model, refs)
    assert not [f for f in others if "Errors" in f.file]


# -- fix round 1 ------------------------------------------------------------------

def test_err001_assignment_and_value_variants(findings):
    got = hits(findings, "DNL-ERR-001", "R1Auth.")
    want = ["B1Basic", "B1Outer", "B3Call", "B3Const", "B3Not", "B3NotAssign", "B3Unknown", "B3Var"]
    assert got == [f"R1Auth.{w}" for w in want]
    assert hits(findings, "DNL-ERR-001", "VbR1.") == ["VbR1.Fn1", "VbR1.Fn2"]


def test_err001_resolvable_true_is_definite_unknown_is_review(findings):
    conf = {where(f): f.confidence for f in findings if f.check_id == "DNL-ERR-001"}
    assert conf["R1Auth.B3Var"] is None and conf["R1Auth.B3Const"] is None and conf["R1Auth.B1Basic"] is None
    assert conf["R1Auth.B3Unknown"] == "REVIEW"


def test_err001_non_bool_action_catch_falls_through_to_success(findings):
    assert hits(findings, "DNL-ERR-001", "R1Controller.") == ["R1Controller.B2Empty", "R1Controller.B2Log"]


def test_empty_catch_all_always_yields_a_finding(findings):
    e3 = hits(findings, "DNL-ERR-003")
    assert "R1Controller.CheckPermissionsLater" in e3
    assert "DefaultDenyHelper.CanSee" in e3          # safe auth tail, but still swallowed
    e1 = hits(findings, "DNL-ERR-001")
    assert not set(e1) & set(e3)


def test_err002_detail_sunk_after_the_try(findings):
    got = hits(findings, "DNL-ERR-002", "R1Controller.")
    for want in ("ErrAfter", "ErrModelAfter", "RedirectLeak", "RedirectActionLeak", "HeaderLeak", "Application_Error"):
        assert f"R1Controller.{want}" in got, want
    assert "R1Controller.ErrConstAfter" not in got


def test_catch_lines_two_catches_on_one_line(model, refs, findings):
    ctx = rules_errors._Ctx(model, refs)
    t = next(t for t in model.types() if t.name == "R1Controller")
    m = next(m for m in t.methods if m.name == "TwoOnLine")
    tr = next(n for n in rules_errors.walk(m.body) if n.get("k") == "try")
    src = (model.root / t.file).read_text(encoding="utf-8-sig").splitlines()
    want = 1 + next(i for i, l in enumerate(src) if "catch (FormatException) { } catch { }" in l)
    assert ctx.catch_lines(t.file, tr) == [want, want]
    got = [f for f in findings if where(f) == "R1Controller.TwoOnLine"]
    assert [(f.check_id, f.line) for f in got] == [("DNL-ERR-003", want)]


# -- fix round 2 ------------------------------------------------------------------

def test_err001_locals_with_several_value_sources(findings):
    got = hits(findings, "DNL-ERR-001", "R2Auth.")
    assert got == ["R2Auth.T1NoInit", "R2Auth.T1Reassigned", "R2Auth.T1TryAssignsTrue", "R2Auth.T2Bare",
                   "R2Auth.T2This"]
    assert hits(findings, "DNL-ERR-001", "VbR2.") == ["VbR2.V1", "VbR2.V2"]
    conf = {where(f): f.confidence for f in findings if f.check_id == "DNL-ERR-001"}
    assert conf["R2Auth.T1NoInit"] is None                      # one source, resolves to true
    assert conf["R2Auth.T1Reassigned"] == "REVIEW" and conf["R2Auth.T1TryAssignsTrue"] == "REVIEW"
    assert "DNL-ERR-001" not in {f.check_id for f in findings if where(f) in ("R2Auth.T1Safe", "R2Auth.T2Safe")}


def test_err001_conditional_deny_in_tail_does_not_make_it_safe(findings):
    assert hits(findings, "DNL-ERR-001", "R2Controller.") == ["R2Controller.T3Redirect", "R2Controller.T3Throw"]
    # An unconditional deny after the try is safe, and the empty catch-all still reports ERR-003.
    assert hits(findings, "DNL-ERR-003", "R2Controller.") == ["R2Controller.T3SafeReturn", "R2Controller.T3SafeThrow"]


def test_err002_add_header_and_headers_add(findings):
    assert hits(findings, "DNL-ERR-002", "R2Controller.") == ["R2Controller.HeaderAdd", "R2Controller.HeadersAdd"]


# -- tail flow ----------------------------------------------------------------------

def test_err001_try_body_assignments_are_value_sources(findings):
    assert hits(findings, "DNL-ERR-001", "TfAuth.") == ["TfAuth.TryCall", "TfAuth.TryConst", "TfAuth.TryNot",
                                                        "TfAuth.TryOrTrue"]


def test_err001_redirect_is_a_refusal_only_when_it_runs_first(findings):
    assert hits(findings, "DNL-ERR-001", "TfController.") == [
        "TfController.ConditionalSuccessThenThrow", "TfController.NestedSuccessThenThrow",
        "TfController.RedirectIsSuccess"]
    assert hits(findings, "DNL-ERR-003", "TfController.") == ["TfController.OnlyThrowReachable",
                                                              "TfController.RedirectFirst"]


def test_err001_vb_function_name_result_after_the_try(findings):
    assert hits(findings, "DNL-ERR-001", "VbTf.") == ["VbTf.W1", "VbTf.W3", "VbTf.X3"]
    assert hits(findings, "DNL-ERR-003", "VbTf.") == ["VbTf.W2"]


# -- fix round 4 --------------------------------------------------------------------

def test_err001_only_real_stops_are_refusals(findings):
    assert hits(findings, "DNL-ERR-001", "RfController.") == [
        "RfController.N1", "RfController.N2", "RfController.N3", "RfController.N4", "RfController.N5",
        "RfController.N6", "RfController.N7", "RfController.N8", "RfController.N9", "RfController.OneAct"]
    # real stops (return of a deny, Response.Redirect, Response.End, Server.Transfer ...) stay quiet
    for safe in ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "LambdaOnly"):
        assert not [f for f in findings if where(f) == f"RfController.{safe}"], safe


def test_err001_statements_sharing_the_try_line(findings):
    assert hits(findings, "DNL-ERR-001", "RfBool.") == ["RfBool.OneLine"]
    assert hits(findings, "DNL-ERR-001", "VbRf.") == ["VbRf.X3", "VbRf.X4"]
    assert hits(findings, "DNL-ERR-003", "VbRf.") == ["VbRf.X5"]


def test_tail_walk_ignores_lambda_bodies(findings):
    assert not [f for f in findings if where(f) == "RfController.LambdaOnly"]
    assert [f.check_id for f in findings if where(f) == "RfBool.LambdaTail"] == ["DNL-ERR-003"]


# -- fix round 5 --------------------------------------------------------------------

def test_err001_catch_judged_by_unconditional_path(findings):
    assert hits(findings, "DNL-ERR-001", "CpController.") == [
        "CpController.A1", "CpController.A2", "CpController.A3", "CpController.B1", "CpController.B2"]
    for safe in ("S1", "S2", "S3", "C1"):
        assert not [f for f in findings if where(f) == f"CpController.{safe}"], safe
    assert hits(findings, "DNL-ERR-001", "CpBool.") == ["CpBool.TrueOnAPath"]
    assert hits(findings, "DNL-ERR-001", "VbCp.") == ["VbCp.A1", "VbCp.B1"]


def test_err003_in_constructors(findings):
    assert hits(findings, "DNL-ERR-003", "CpStatic.") == ["CpStatic.constructor", "CpStatic.constructor"]
    assert len(hits(findings, "DNL-ERR-003", "VbCpStatic.")) == 1
    assert hits(findings, "DNL-ERR-003", "CpStaticClass.") == ["CpStaticClass.constructor"]


# -- acceptance-run precision fix: an error result is a refusal ------------------

def test_err001_error_result_in_catch_is_a_refusal(tmp_path, roslyn_helper):
    from tests.test_dnl_misc_rules import build
    m, r = build(tmp_path, {"A.cs": (
        "using System; using System.Net; using System.Web.Http; using System.Web.Mvc;\n"
        "namespace N { public class AController : ApiController {\n"
        "public IHttpActionResult E500(int id) { try { if (!User.IsInRole(\"a\")) return Unauthorized(); return Ok(); }\n"
        "  catch (Exception e) { return InternalServerError(e); } }\n"
        "public IHttpActionResult E400(int id) { try { if (!User.IsInRole(\"a\")) return Unauthorized(); return Ok(); }\n"
        "  catch (Exception) { return BadRequest(\"x\"); } }\n"
        "public IHttpActionResult ECode(int id) { try { if (!User.IsInRole(\"a\")) return Unauthorized(); return Ok(); }\n"
        "  catch (Exception) { return StatusCode(HttpStatusCode.ServiceUnavailable); } }\n"
        "public IHttpActionResult EOk(int id) { try { if (!User.IsInRole(\"a\")) return Unauthorized(); return Ok(); }\n"
        "  catch (Exception) { return StatusCode(HttpStatusCode.OK); } }\n"
        "public IHttpActionResult EOpen(int id) { try { if (!User.IsInRole(\"a\")) return Unauthorized(); return Ok(); }\n"
        "  catch (Exception) { return Ok(); } } } }")})
    got = sorted(where(f) for f in rules_errors.check(m, r) if f.check_id == "DNL-ERR-001")
    assert got == ["AController.EOk", "AController.EOpen"]


# -- final review: refusal shapes ------------------------------------------------------

def _c(name, *args, obj=None):
    fn = {"k": "name", "id": name} if obj is None else {"k": "member", "name": name, "obj": obj}
    return {"k": "call", "fn": fn, "args": list(args)}


def _n(name):
    return {"k": "name", "id": name}


def _m(obj, name):
    return {"k": "member", "obj": _n(obj), "name": name}


_STATUS = lambda s: _m("HttpStatusCode", s)  # noqa: E731


@pytest.mark.parametrize("v,expected", [
    (_c("CreateResponse", _STATUS("OK"), _c("Take", _n("items"), {"k": "lit", "v": 500})), False),
    (_c("CreateResponse", _STATUS("Unauthorized"), _n("x")), True),
    (_c("StatusCode", {"k": "lit", "v": 403}), True),
    (_c("StatusCode", {"k": "lit", "v": 200}, {"k": "lit", "v": 500}), False),
    ({"k": "new", "type": "HttpStatusCodeResult", "args": [{"k": "lit", "v": 200}, {"k": "lit", "v": 404}]}, False),
    ({"k": "new", "type": "HttpStatusCodeResult", "args": [{"k": "lit", "v": 403}]}, True),
    ({"k": "cond", "c": _n("ok"), "t": _c("Ok"), "f": _c("Unauthorized")}, False),
    ({"k": "cond", "c": _n("ok"), "t": _c("Forbid"), "f": _c("Unauthorized")}, True),
    ({"k": "bin", "op": "??", "l": _n("r"), "r": _c("Unauthorized")}, False),
    ({"k": "bin", "op": "??", "l": _c("Forbid"), "r": _c("Unauthorized")}, True),
    (_c("Ok", _c("Unauthorized")), False),
    (_c("Json", {"k": "new", "type": "anon", "args": [_c("BadRequest")]}), False),
    ({"k": "cast", "type": "IHttpActionResult", "e": _c("Unauthorized")}, True),
    ({"k": "cast", "type": "ActionResult", "e": {"k": "cond", "c": _n("a"), "t": _c("Ok"), "f": _c("Unauthorized")}}, False),
    (_c("Unauthorized"), True),
    (_c("ResponseMessage", _c("CreateErrorResponse", _STATUS("Unauthorized"), {"k": "lit", "v": "no"}, obj=_n("Request"))), True),
    (_c("ResponseMessage", _c("CreateResponse", _STATUS("OK"), _n("x"), obj=_n("Request"))), False),
    ({"k": "new", "type": "HttpResponseMessage", "args": [_STATUS("Forbidden")]}, True),
    ({"k": "new", "type": "HttpResponseMessage", "args": [_STATUS("OK")]}, False),
    (dict(_c("StatusCode"), named={"statusCode": _STATUS("Forbidden")}), True),
    (_c("FromResult", _c("Unauthorized"), obj=_n("Task")), True),
])
def test_deny_value_shapes(v, expected):
    assert rules_errors._deny_value(v) is expected


def test_status_assignment_still_counts():
    s = {"k": "assign", "target": _m("Response", "StatusCode"), "value": {"k": "lit", "v": 401}}
    assert rules_errors._status_deny_stmt(s, {"k": "return"})
    s2 = dict(s, value={"k": "lit", "v": 200})
    assert not rules_errors._status_deny_stmt(s2, {"k": "return"})
