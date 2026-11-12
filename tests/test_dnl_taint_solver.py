"""Inter-procedural taint: summaries, call resolution and entry points."""
from pathlib import Path

import pytest

from checks.dnl import project, routes, taint, taint_solver
from checks.dnl.taint_solver import entry_hits, resolve_call, solve

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


@pytest.fixture(scope="module")
def hits(model):
    refs = routes.discover_mvc_webapi(model) + routes.discover_webforms(model)
    return entry_hits(model, refs)


def one_hit(hits, kind, file_endswith):
    found = [x for x in hits if x.hit.kind == kind and x.hit.file.endswith(file_endswith)]
    assert len(found) == 1, [(x.hit.file, x.hit.line, x.hit.via) for x in found]
    return found[0]


def _type(model, full):
    return next(t for t in model.types() if t.full_name == full)


def test_layered_flow_controller_to_repository(hits):
    h = one_hit(hits, "sql", file_endswith="OrderRepository.cs")
    assert h.ref.route.handler_name == "OrdersController.Search" and h.hit.via[0].startswith("OrdersController.Search")
    assert any(o.detail == "request parameter term" for o in h.sources)
    assert h.hit.method == "OrderRepository.FindByTerm"


def test_numeric_action_param_is_not_a_source(hits):
    assert not [x for x in hits if x.ref is not None and x.ref.route.handler_name == "OrdersController.ById"]


def test_interface_dispatch_reaches_both_impls(hits):
    assert {x.hit.file.rsplit("/", 1)[-1] for x in hits if x.hit.kind == "sql" and "Impl" in x.hit.method} \
        == {"SqlImplA.cs", "SqlImplB.cs"}


def test_mutual_recursion_terminates_and_reports(model):
    sums = solve(model)                    # must return within the round cap
    assert any(h.kind == "sql" for s in sums.values() for hs in s.param_sinks.values() for h in hs)
    a = sums[("Cs.Layered.Rec", "A", _type(model, "Cs.Layered.Rec").methods[0].line)]
    assert 0 in a.param_sinks


def test_webforms_field_flow(hits):
    h = one_hit(hits, "sql", file_endswith="Search.aspx.vb")
    assert h.ref.route.path.endswith("/Search.aspx") and h.hit.method.endswith("btnGo_Click")


def test_uncalled_helper_is_unproven(hits):
    u = [x for x in hits if x.ref is None and x.hit.method.endswith("Orphan")]
    assert len(u) == 1 and all(o.kind == "param" for o in u[0].hit.taint.origins)


def test_called_with_constant_is_dropped(hits):
    assert not [x for x in hits if x.hit.method.endswith("OnlyConstCaller")]


# -- R4: an argument stored into the receiver's fields ----------------------

def _analyze(model, full, meth):
    t = _type(model, full)
    me = next(x for x in t.methods if x.name == meth)
    return taint.analyze_method(model, t, me, summaries=solve(model))


def test_param_to_this_taints_receiver(model):
    assert [h.kind for h in _analyze(model, "Cs.UsesAccum", "Dirty").hits] == ["sql"]
    assert _analyze(model, "Cs.UsesAccum", "Clean").hits == []
    add = solve(model)[("Cs.Accum", "Add", _type(model, "Cs.Accum").methods[0].line)]
    assert add.param_to_this == frozenset({0})


def test_sink_recv_text_guard_tolerates_none(model, monkeypatch):
    from checks.dnl import taint_tables as T
    sink = next(s for s in T.SINKS if s.recv_text and not s.assign)
    t = _type(model, "Cs.Orders")
    a = taint._Analysis(model, t, t.methods[0], None, None, None)
    monkeypatch.setattr(a, "_text", lambda e: None)
    assert a._sink_matches(sink, sink.member, None, {"k": "name", "id": "zz"}, False) in (True, False)


# -- call resolution --------------------------------------------------------

def _call(name, recv=None, nargs=0, sym=None):
    fn = {"k": "name", "id": name} if recv is None else {"k": "member", "name": name, "obj": recv}
    c = {"k": "call", "fn": fn, "args": [{"k": "lit", "v": 1}] * nargs}
    if sym:
        c["sym"] = sym
    return c


def test_resolve_interface_receiver_yields_all_impls(model):
    t = _type(model, "Cs.Layered.WriteController")
    got = resolve_call(model, t, _call("Save", {"k": "name", "id": "_w"}, 2), {"_w": "IWriter"})
    assert {ty.name for ty, _ in got} == {"IWriter", "SqlImplA", "SqlImplB"}


def test_resolve_implicit_static_and_overloads(model):
    rec = _type(model, "Cs.Layered.Rec")
    got = resolve_call(model, rec, _call("B", None, 2), {})
    assert [(ty.name, m.name) for ty, m in got] == [("Rec", "B")]
    ctrl = _type(model, "Cs.Layered.OrdersController")
    static = resolve_call(model, ctrl, _call("Wrap", {"k": "name", "id": "Helpers"}, 1), {})
    assert [(ty.name, m.name) for ty, m in static] == [("Helpers", "Wrap")]
    assert resolve_call(model, ctrl, _call("Nope", None, 1), {}) == []
    # by symbol, an external type resolves to nothing
    assert resolve_call(model, ctrl, _call("Find", {"k": "name", "id": "x"}, 1, sym="System.String.Find"), {}) == []


def test_resolve_vb_case_insensitive(model):
    page = _type(model, "Vb.Pages.SearchPage")
    got = resolve_call(model, page, _call("BTNGO_CLICK", None, 2), {})
    assert [m.name for _, m in got] == ["btnGo_Click"]


def test_solve_is_cached(model):
    assert solve(model) is solve(model)


# -- fix round 1 ------------------------------------------------------------

def _kinds(model, full, meth):
    return [h.kind for h in _analyze(model, full, meth).hits]


def test_extension_method_binds_receiver_to_this_param(model):
    assert _kinds(model, "Cs.UsesExt", "Sink") == ["sql"]
    assert _kinds(model, "Cs.UsesExt", "Ret") == ["sql"]
    assert _kinds(model, "Cs.UsesExt", "ConstReceiver") == []


def test_params_array_takes_every_trailing_argument(model):
    assert _kinds(model, "Cs.Variadic", "Dirty") == ["sql"]
    assert _kinds(model, "Cs.Variadic", "Clean") == []


def test_property_setter_sink_and_initializer(model):
    assert _kinds(model, "Cs.UsesSetters", "Assign") == ["sql"]
    assert _kinds(model, "Cs.UsesSetters", "Init") == ["sql"]
    assert _kinds(model, "Cs.UsesSetters", "AssignConst") == []


def test_setter_stores_into_receiver_fields(model):
    assert _kinds(model, "Cs.UsesSetters", "Stored") == ["sql"]
    assert _kinds(model, "Cs.UsesSetters", "StoredConst") == []


def test_constructor_argument_reaches_object_state(model):
    assert _kinds(model, "Cs.UsesSetters", "Ctor") == ["sql"]


def test_uncalled_setter_is_unproven(hits):
    u = [x for x in hits if x.hit.method == "Lonely.set_T"]
    assert len(u) == 1 and u[0].ref is None and not u[0].proven


def test_proven_flag_and_ref_none(hits):
    direct = [x for x in hits if x.ref is None and x.hit.method == "Orders.Find"]
    assert len(direct) == 1 and direct[0].proven
    assert all(x.proven for x in hits if x.ref is not None)
    orphan = next(x for x in hits if x.hit.method.endswith("Orphan"))
    assert not orphan.proven


def test_recursion_without_outside_caller_is_unproven(hits):
    for name in ("SelfRec.Loop", "Rec.A"):
        u = [x for x in hits if x.ref is None and x.hit.method == name]
        assert len(u) == 1 and not u[0].proven, name


def test_ten_deep_chain_converges_within_cap(model):
    sums = solve(model)
    st = model.cache["taint"]
    assert st["converged"] and st["rounds"] <= taint_solver.MAX_ROUNDS == 24
    h0 = _type(model, "Cs.Chain").methods[0]
    assert any(h.kind == "sql" for h in sums[("Cs.Chain", "H0", h0.line)].param_sinks[0])


def test_chained_hit_not_duplicated_with_unchained(hits):
    # a callee hit reached through an entry keeps the chained copy only
    found = [x for x in hits if x.hit.file.endswith("OrderRepository.cs")]
    assert len(found) == 1 and found[0].hit.via


# -- fix round 2 ------------------------------------------------------------

def _rows(hs, file_endswith):
    return [x for x in hs if x.hit.file.endswith(file_endswith)]


def test_cycle_sink_proven_has_no_unproven_row(hits):
    rows = _rows(hits, "CycleSrc.cs")
    assert rows and all(x.proven for x in rows), [(x.hit.method, x.hit.via, x.proven) for x in rows]


def test_cycle_with_outside_caller_is_not_unproven(hits):
    assert not _rows(hits, "CycleOuter.cs")


def test_per_route_attribution_for_shared_sink(hits):
    rows = _rows(hits, "Shared.cs")
    assert sorted(x.ref.route.handler_name for x in rows) == ["TwoRoutesController.Left", "TwoRoutesController.Right"]
    for x in rows:
        assert x.hit.via[0] == x.ref.route.handler_name


def _norm(hs):
    return sorted((x.ref.route.handler_name if x.ref else "", x.hit.kind, x.hit.sink, x.hit.file, x.hit.line,
                   x.hit.via, x.proven) for x in hs)


def test_entry_hits_are_order_independent(model, hits):
    import dataclasses
    rev = dataclasses.replace(model, files=dict(reversed(list(model.files.items()))), cache={})
    refs = routes.discover_mvc_webapi(rev) + routes.discover_webforms(rev)
    assert _norm(entry_hits(rev, refs)) == _norm(hits)


def test_extension_receiver_named_like_class_is_a_variable(model):
    assert _kinds(model, "Cs.UsesExt", "VarNamedLikeClass") == ["sql"]


def test_extension_on_framework_supertype_applies(model):
    # `this IEnumerable<string>` on a List<string>: a framework type never rejects an extension
    assert _kinds(model, "Cs.UsesExt", "FrameworkSupertype") == ["sql"]


def test_extension_on_framework_receiver_applies_by_name(model):
    # `this string` called on a List<string>: a framework-typed receiver applies by name
    assert _kinds(model, "Cs.UsesExt", "WrongType") == ["sql"]


def test_alias_qualified_static_extension_call_fires_sink(model):
    # `using U = Cs;` ... `U.Ext.RunSql(q, c)` is the static form: no argument shift
    assert _kinds(model, "Cs.Alias.UsesExtAlias", "Static") == ["sql"]


def test_ext_applies_resolves_keyword_aliases_on_both_sides():
    from types import SimpleNamespace as NS
    t = NS(full_name="X")
    m = NS(params=[NS(type="Int32")])
    stub = NS(find_types=lambda n: [t], base_chain=lambda _t: [])
    assert taint_solver._ext_applies(stub, m, "int")
    assert taint_solver._ext_applies(stub, NS(params=[NS(type="string")]), "String")
    assert not taint_solver._ext_applies(stub, NS(params=[NS(type="Int32")]), "long")


def test_extension_rejected_for_unrelated_project_type(model):
    assert _kinds(model, "Cs.UsesExt", "UnrelatedProjectType") == []


def test_external_sym_call_does_not_take_extension_summary(model):
    assert _kinds(model, "Cs.UsesExt", "ExternalSameName") == ["sql"]
    t = _type(model, "Cs.UsesExt")
    call = {"k": "call", "sym": "System.String.Substring", "args": [{"k": "lit", "v": 1}],
            "fn": {"k": "member", "name": "Substring", "obj": {"k": "name", "id": "q"}}}
    assert resolve_call(model, t, call, {"q": "string"}) == []


def test_dotted_receiver_named_like_class_is_instance(model):
    assert _kinds(model, "Cs.UsesExtField", "Dotted") == ["sql"]


def test_simple_name_prefers_caller_namespace(model):
    assert [t.namespace for t in taint_solver._types_for(model, "Dup", "Cs.Ns2")] == ["Cs.Ns2"]
    assert [t.namespace for t in taint_solver._types_for(model, "Dup", "Cs.Ns1")] == ["Cs.Ns1"]
    assert _kinds(model, "Cs.Ns1.UsesDup1", "M") == ["sql"]
    assert _kinds(model, "Cs.Ns2.UsesDup2", "M") == []


def test_extension_arity_mismatch_never_loses_taint(model):
    assert _kinds(model, "Cs.UsesExt", "LostArgument") == ["sql"]


def test_setter_lookup_uses_full_type_name(model):
    assert _kinds(model, "Cs.UsesDup", "Qualified") == []
    assert _kinds(model, "Cs.UsesDup", "QualifiedInit") == []
    assert _kinds(model, "Cs.UsesDup", "Other") == ["sql"]


def test_convergence_state_is_exposed(model, hits):
    st = model.cache["taint"]
    assert st["converged"] is True and 1 <= st["rounds"] <= taint_solver.MAX_ROUNDS


def test_extension_forms_property_ambiguous_and_expression_receivers(model):
    assert _kinds(model, "Cs.Forms.UsesExtForms", "PropertyNamedLikeClass") == ["sql"]
    # unknown head, last segment equals the class name: both bindings are evaluated
    assert _kinds(model, "Cs.Forms.UsesExtForms", "UnknownHead") == ["sql"]
    assert _kinds(model, "Cs.Forms.UsesExtForms", "CallReceiver") == ["sql"]
