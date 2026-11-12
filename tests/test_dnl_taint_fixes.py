"""Final-review fixes for the taint engine: robustness, conservative IR gaps, lambdas, source / sink tables."""
import sys
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_taint, taint, taint_solver
from checks.dnl.ir import MethodIR

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


def _fresh(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


@pytest.fixture(scope="module")
def model(roslyn_helper):
    m = _fresh(roslyn_helper)
    taint_solver.solve(m)
    return m


@pytest.fixture(scope="module")
def findings(model):
    refs = routes.discover_mvc_webapi(model) + routes.discover_webforms(model)
    return rules_taint.check(model, refs)


def _type(m, full):
    return next(t for t in m.types() if t.full_name == full)


def analyze(m, full, meth):
    t = _type(m, full)
    me = next(x for x in t.methods if x.name == meth)
    return taint.analyze_method(m, t, me, summaries=taint_solver.solve(m))


# -- item 1 / robustness: truncated and failed methods are surfaced ----------

def test_deep_expression_marks_truncated(model):
    t = _type(model, "Cs.Orders")
    deep = {"k": "name", "id": "x", "line": 1}
    for _ in range(3000):
        deep = {"k": "bin", "op": "+", "l": deep, "r": {"k": "lit", "v": "a"}, "line": 1}
    meth = MethodIR(name="Deep", body=[{"k": "expr", "expr": deep, "line": 1}], line=1)
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(1000)
    try:
        r = taint.analyze_method(model, t, meth)
    finally:
        sys.setrecursionlimit(old)
    assert r.truncated is True


def test_truncated_methods_recorded_and_noted(roslyn_helper, monkeypatch):
    m = _fresh(roslyn_helper)
    orig = taint._Analysis.block

    def block(self, stmts):
        if self.t.name == "Orders" and self.m.name == "Find":
            raise RecursionError
        return orig(self, stmts)

    monkeypatch.setattr(taint._Analysis, "block", block)
    taint_solver.solve(m)
    assert "Orders.Find" in m.cache["taint"]["truncated_methods"]
    rules_taint.check(m, routes.discover_mvc_webapi(m) + routes.discover_webforms(m))
    assert any("analysed partially" in n and "expression nesting too deep" in n for n in m.notes)


def test_failed_method_recorded_noted_and_scan_continues(roslyn_helper, monkeypatch):
    m = _fresh(roslyn_helper)
    orig = taint.analyze_method

    def boom(model, t, me, **kw):
        if t.name == "Orders" and me.name == "Find":
            raise ValueError("synthetic")
        return orig(model, t, me, **kw)

    monkeypatch.setattr(taint, "analyze_method", boom)
    sums = taint_solver.solve(m)
    assert sums and "Orders.Find" in m.cache["taint"]["failed_methods"]
    out = rules_taint.check(m, routes.discover_mvc_webapi(m) + routes.discover_webforms(m))
    assert any("could not be analysed" in n for n in m.notes)
    assert any(f.check_id == "DNL-INJ-001" for f in out)


def test_analysis_raises_recursion_limit(roslyn_helper):
    from languages.dotnet_legacy import analyzers
    m = _fresh(roslyn_helper)
    sys.setrecursionlimit(1000)
    m.cache.pop("code_results", None)
    analyzers._code_results(m)
    assert sys.getrecursionlimit() >= 4000


def test_max_rounds_is_24():
    assert taint_solver.MAX_ROUNDS == 24


def kinds(model, full, meth):
    return [h.kind for h in analyze(model, full, meth).hits]


# -- item 2: unknown / other nodes are scanned conservatively ----------------

def test_switch_expression_source_reaches_sink(model):
    assert kinds(model, "Cs.Fixes.Gaps", "SwitchExpr") == ["sql"]
    assert kinds(model, "Cs.Fixes.Gaps", "SwitchConst") == []


def test_vb_bang_access_source_reaches_sink(model):
    assert kinds(model, "Vb.Gaps", "Bang") == ["sql"]
    assert kinds(model, "Vb.Gaps", "BangConst") == []


def test_unknown_node_merges_env_identifiers(model):
    t = _type(model, "Cs.Fixes.Gaps")
    a = taint._Analysis(model, t, t.methods[0], None, None, None)
    tv = taint.Taint(frozenset({taint.Origin("source", "Request", "x.cs", 1)}), frozenset())
    a.env["abc"] = tv
    assert a.ev({"k": "unknown", "text": "foo(abc) + 1", "line": 1}) is tv
    assert a.ev({"k": "unknown", "text": "foo(zzz)", "line": 1}) is None
    got = a.ev({"k": "unknown", "text": 'Request.QueryString["q"]', "line": 3})
    assert got is not None and got.origins and next(iter(got.origins)).kind == "source"


# -- item 4: body-less targets pass argument taint through --------------------

def test_bodyless_interface_target_passes_taint(model):
    assert kinds(model, "Cs.Fixes.Gaps", "BodylessTarget") == ["sql"]


# -- item 5: lambda bodies -----------------------------------------------------

def test_lambda_sinks_are_reported(model):
    assert kinds(model, "Cs.Fixes.Gaps", "TaskRun") == ["sql"]
    assert kinds(model, "Cs.Fixes.Gaps", "TaskRunConst") == []
    assert kinds(model, "Cs.Fixes.Gaps", "SelectClosure") == ["sql"]


def test_linq_lambda_param_binds_receiver_taint(model):
    assert kinds(model, "Cs.Fixes.Gaps", "ForEachLambda") == ["sql"]
    assert kinds(model, "Cs.Fixes.Gaps", "ForEachLambdaClean") == []
    assert kinds(model, "Cs.Fixes.Gaps", "SelectParamClean") == []


def test_lambda_env_changes_are_discarded(model):
    assert kinds(model, "Cs.Fixes.Gaps", "LambdaDoesNotLeak") == []


# -- minors ----------------------------------------------------------------------

def test_tuple_foreach_taints_every_identifier(model):
    assert kinds(model, "Cs.Fixes.Gaps", "TupleLoop") == ["sql"]


def test_non_name_callee_merges_argument_taint(model):
    assert kinds(model, "Cs.Fixes.Gaps", "IndexedCallee") == ["sql"]


def test_ir_lambda_carries_param_names(model):
    t = _type(model, "Cs.Fixes.Gaps")
    me = next(x for x in t.methods if x.name == "ForEachLambda")
    lam = me.body[1]["expr"]["args"][0]
    assert lam["k"] == "lambda" and lam["params"] == ["x"]
    run = next(x for x in t.methods if x.name == "TaskRun").body[1]["expr"]["args"][0]
    assert run["k"] == "lambda" and "params" not in run


# -- item 8: more request sources -------------------------------------------------

@pytest.mark.parametrize("meth", ["ReflectPathInfo", "ReflectPath", "ReflectUserAgent", "ReflectContentType"])
def test_request_path_style_sources_reach_xss(model, meth):
    assert kinds(model, "Cs.Fixes.Tables", meth) == ["xss"]


def test_http_method_is_not_a_source(model):
    assert kinds(model, "Cs.Fixes.Tables", "ReflectMethod") == []


def test_source_text_fallback_covers_new_members(model):
    t = _type(model, "Cs.Fixes.Tables")
    a = taint._Analysis(model, t, t.methods[0], None, None, None)
    for member in ("Path", "PathInfo", "UserAgent", "ContentType", "FilePath", "CurrentExecutionFilePath",
                   "AppRelativeCurrentExecutionFilePath"):
        e = {"k": "member", "obj": {"k": "name", "id": "Request"}, "name": member, "line": 1}
        assert a.ev(e) is not None, member
    e = {"k": "member", "obj": {"k": "name", "id": "Request"}, "name": "HttpMethod", "line": 1}
    assert a.ev(e) is None


# -- minors: regex guard, format-style log sinks, LDAP escape ---------------------

def test_regex_ismatch_no_longer_cleanses(model):
    for meth in ("RegexLoose", "RegexStrict", "RegexGreedy", "RegexTopLevelAlt", "RegexGroupedAlt",
                 "RegexWildcardEquiv"):
        assert kinds(model, "Cs.Fixes.Tables", meth) == ["sql"], meth


def test_format_style_log_sinks_check_all_arguments(model):
    assert kinds(model, "Cs.Fixes.Tables", "LogFormatArgs") == ["log"]
    assert kinds(model, "Cs.Fixes.Tables", "LogFormatConst") == []
    assert kinds(model, "Cs.Fixes.Tables", "TraceFormatArgs") == ["log"]


def test_noop_project_ldap_escape_does_not_cleanse(model):
    assert kinds(model, "Cs.Fixes.Tables", "LdapNoop") == ["ldap"]
    assert kinds(model, "Cs.Fixes.Tables", "LdapReal") == []


# -- residual gaps -------------------------------------------------------------------

def test_sync_callback_env_writes_merge_back(model):
    assert kinds(model, "Cs.Fixes.Gaps", "ForEachWritesBack") == ["sql"]
    assert kinds(model, "Cs.Fixes.Gaps", "ForEachWritesBackClean") == []


def test_static_linq_form_binds_first_argument(model):
    assert kinds(model, "Cs.Fixes.Gaps", "StaticWhere") == ["sql"]
    assert kinds(model, "Cs.Fixes.Gaps", "StaticWhereClean") == []
    assert kinds(model, "Cs.Fixes.Gaps", "StaticSelect") == ["sql"]


def test_tuple_assignment_from_request_reaches_sink(model):
    assert kinds(model, "Cs.Fixes.Gaps", "TupleAssign") == ["sql"]
    assert kinds(model, "Cs.Fixes.Gaps", "TupleAssignClean") == []


def _bare(model):
    t = _type(model, "Cs.Fixes.Gaps")
    return taint._Analysis(model, t, t.methods[0], None, None, None)


def test_string_literal_with_request_text_is_not_a_source(model):
    a = _bare(model)
    assert a.ev({"k": "unknown", "text": '"request.xml"', "line": 1}) is None
    assert a.ev({"k": "unknown", "text": "'r' + \"Request[0]\"", "line": 1}) is None
    a.block([{"k": "other", "text": 'doc = "request.xml";', "line": 1}])
    assert a.env.get("doc") is None
    a.block([{"k": "other", "text": "doc = Request.Form;", "line": 2}])
    assert a.env.get("doc") is not None


def test_other_statement_multi_target_and_tuple_assignments(model):
    a = _bare(model)
    tv = taint.Taint(frozenset({taint.Origin("source", "Request", "x.cs", 1)}), frozenset())
    a.env["src"] = tv
    a.block([{"k": "other", "text": "(x, y) = (src, 1);", "line": 1}])
    assert a.env["x"] is tv and a.env["y"] is tv
    a.block([{"k": "other", "text": "p = q = src;", "line": 2}])
    assert a.env["p"] is tv and a.env["q"] is tv
    a.block([{"k": "other", "text": "m == src", "line": 3}])
    assert "m" not in a.env
