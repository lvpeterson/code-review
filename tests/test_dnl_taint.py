"""Intra-procedural taint engine: sources, sinks, sanitizers and guards."""
from pathlib import Path

import pytest

from checks.dnl import project, taint

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def m(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


def _type(model, full):
    return next(t for t in model.types() if t.full_name == full)


def analyze(model, full, meth, **kw):
    t = _type(model, full)
    me = next(x for x in t.methods if x.name == meth)
    return taint.analyze_method(model, t, me, **kw)


def line_of(model, full, text):
    """1-based line of the first source line of the type's file containing text."""
    t = _type(model, full)
    lines = (model.root / t.file).read_text(encoding="utf-8").splitlines()
    return next(i for i, ln in enumerate(lines, 1) if text in ln)


def param(i):
    return taint.Taint(frozenset({taint.Origin("param", str(i), "x.cs", 1)}), frozenset())


def test_request_concat_into_commandtext_hits_sql(m):
    r = analyze(m, "Cs.Orders", "Find")
    assert [(h.kind, h.line) for h in r.hits] == [("sql", line_of(m, "Cs.Orders", "CommandText"))]
    assert r.hits[0].method == "Orders.Find"


def test_string_format_builder_interp_propagate(m):
    for meth in ("ViaFormat", "ViaBuilder", "ViaInterp", "ViaPlusEquals"):
        assert [h.kind for h in analyze(m, "Cs.Props", meth).hits] == ["sql"], meth


def test_int_parse_cleanses(m):
    assert analyze(m, "Cs.Orders", "ByIntId").hits == []


def test_html_encode_cleanses_xss_only(m):
    r = analyze(m, "Cs.Out", "Encoded")
    assert [h.kind for h in r.hits] == ["sql"]


def test_vb_case_insensitive_vars(m):
    r = analyze(m, "Vb.Search", "Go")
    assert [h.kind for h in r.hits] == ["sql"]


def test_param_origin_and_return(m):
    r = analyze(m, "Cs.Helpers", "Wrap", param_taint={0: param(0)})
    assert r.param_to_ret == frozenset({0}) and r.hits == []


def test_islocalurl_guard(m):
    assert analyze(m, "Cs.Nav", "Safe").hits == []
    assert [h.kind for h in analyze(m, "Cs.Nav", "Unsafe").hits] == ["redirect"]


def test_constant_only_never_hits(m):
    assert analyze(m, "Cs.Orders", "Constant").hits == []


def test_merge_and_cleanse_helpers():
    a = taint.Taint(frozenset({taint.Origin("source", "a", "f", 1)}), frozenset({"xss", "sql"}))
    b = taint.Taint(frozenset({taint.Origin("source", "b", "f", 2)}), frozenset({"xss"}))
    mg = taint.merge(a, b)
    assert len(mg.origins) == 2 and mg.cleansed == frozenset({"xss"})
    assert taint.merge(None, a) is a and taint.merge(a, None) is a and taint.merge(None, None) is None
    assert taint.cleanse(b, {"sql"}).cleansed == frozenset({"xss", "sql"})
    assert taint.cleanse(None, {"sql"}) is None


def kinds(model, full, meth, **kw):
    return [h.kind for h in analyze(model, full, meth, **kw).hits]


def test_vb_bare_functions_and_default_property(m):
    assert kinds(m, "Vb.Search", "Funcs") == ["sql"]
    assert kinds(m, "Vb.Search", "DefaultProp") == ["sql"]
    assert kinds(m, "Vb.Search", "QsCall") == ["sql"]


def test_split_list_join_and_tainted_receiver_default(m):
    for meth in ("SplitFirst", "ListJoin", "UnknownReceiverMethod", "NamedArgument"):
        assert kinds(m, "Cs.Flow", meth) == ["sql"], meth


def test_bool_members_and_parameterized_stay_clean(m):
    assert kinds(m, "Cs.Flow", "BoolMemberIsNotData") == []
    assert kinds(m, "Cs.Flow", "ParameterizedStaysClean") == []


def test_crlf_needs_both_removed(m):
    assert kinds(m, "Cs.Crlf", "OnlyCr") == ["header"]
    assert kinds(m, "Cs.Crlf", "BothViaChain") == []
    assert kinds(m, "Cs.Crlf", "SwapLfForCr") == ["header"]


def test_contains_guard_checks_receiver(m):
    assert kinds(m, "Cs.Guards", "StringContains") == ["redirect"]
    assert kinds(m, "Cs.Guards", "ListContains") == []


def test_dynamic_linq_on_unresolved_receiver(m):
    assert kinds(m, "Cs.Linq", "DynamicConcat") == ["linq"]
    assert kinds(m, "Cs.Linq", "DynamicParameterized") == []


def test_urlencode_does_not_cleanse_xss():
    from checks.dnl import taint_tables as T
    xss = next(s for s in T.SANITIZERS if s.name == "HttpUtility.HtmlEncode")
    import re
    assert not re.match(xss.member, "UrlEncode") and re.match(xss.member, "HtmlEncode")


def test_crlf_pair_then_cr_still_hits(m):
    assert kinds(m, "Cs.Crlf", "PairThenCr") == ["header"]


def test_mutator_name_on_project_type_dispatches_to_project(m):
    assert kinds(m, "Cs.Flow", "MutatorOnProjectType") == ["sql"]


def test_vb_local_named_like_string_function(m):
    assert kinds(m, "Vb.Search", "LocalNamedLeft") == ["sql"]


def test_contains_on_inferred_string_local_is_not_a_guard(m):
    assert kinds(m, "Cs.Guards", "InferredStringContains") == ["redirect"]


def test_dynamic_linq_static_form_checks_arg1(m):
    assert kinds(m, "Cs.Linq", "StaticForm") == ["linq"]
