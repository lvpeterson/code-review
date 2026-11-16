"""Degraded mode (no Roslyn helper): tree-sitter C# lowering, VB pattern fallback, helper parity."""
import json
import sys
from pathlib import Path

import pytest

import main
from checks.dnl import frontend_ts, helper, project, vb_regex
from checks.dnl.ir import load_file_ir
from core.registry import get_analyzer
import languages.dotnet_legacy.analyzers  # noqa: F401  (registration)

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"
FRAMEWORKS = ("mvc", "webapi", "webforms", "wcf", "config")


@pytest.fixture(autouse=True)
def _fresh_cache():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


@pytest.fixture
def no_helper(monkeypatch):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)


# -- lowering unit tests ------------------------------------------------------

def lower(tmp_path, src: str) -> dict:
    f = tmp_path / "A.cs"
    f.write_text(src, encoding="utf-8")
    return frontend_ts.lower_file(f, "A.cs", "P")


def body(tmp_path, stmts: str, sig: str = "void M(string id)") -> list:
    rec = lower(tmp_path, "namespace N { class C { %s { %s } } }" % (sig, stmts))
    return rec["types"][0]["methods"][0]["body"]


def expr(tmp_path, e: str) -> dict:
    return body(tmp_path, f"var x = {e};")[0]["init"]


def test_file_record_and_type_shape(tmp_path):
    rec = lower(tmp_path, """
namespace A.B {
  [Authorize(Roles = "admin"), HttpPost]
  public class C<T> : Base, IFoo {
    public const int K = 5, J = 2;
    private string s = "x";
    [Required] public string P { get; set; } = "d";
    public int Q => 3;
    public int R { get { return 1; } set { s = value; } }
    protected internal static void Stat() { }
    public class Inner { }
  }
  public enum E { A = 1, B }
  public struct S { }
  public interface IFoo { }
}""")
    assert (rec["path"], rec["language"], rec["project"], rec["parse_errors"]) == ("A.cs", "cs", "P", 0)
    names = [(t["name"], t["namespace"], t["kind"]) for t in rec["types"]]
    assert names == [("C", "A.B", "class"), ("C.Inner", "A.B", "class"), ("E", "A.B", "class"),
                     ("S", "A.B", "struct"), ("IFoo", "A.B", "interface")]
    c = rec["types"][0]
    assert c["bases"] == ["Base", "IFoo"] and c["modifiers"] == ["public"]
    assert c["attributes"][0]["name"] == "Authorize" and c["attributes"][0]["named"]["Roles"]["v"] == "admin"
    assert c["attributes"][1]["name"] == "HttpPost" and c["attributes"][1]["args"] == []
    fields = {f["name"]: f for f in c["fields"]}
    assert fields["K"]["is_const"] and fields["K"]["init"]["v"] == 5 and fields["J"]["init"]["v"] == 2
    assert not fields["s"]["is_const"] and fields["s"]["type"] == "string"
    props = {p["name"]: p for p in c["properties"]}
    assert props["P"]["init"]["v"] == "d" and "get" not in props["P"] and props["P"]["attributes"][0]["name"] == "Required"
    assert props["Q"]["get"][0]["k"] == "return"
    assert props["R"]["get"][0]["value"]["v"] == 1 and props["R"]["set"][0]["k"] == "assign"
    stat = c["methods"][0]
    assert stat["modifiers"] == ["protected internal", "static"] and stat["return_type"] == "void"
    enum = rec["types"][2]
    assert [(f["name"], f["type"], f["is_const"]) for f in enum["fields"]] == [("A", "E", True), ("B", "E", True)]


def test_no_semantic_keys_ever(tmp_path):
    rec = lower(tmp_path, 'class C { void M(string a) { var x = new Foo(); a.Trim(); Request.Form["q"].ToString(); } }')

    def walk(o):
        if isinstance(o, dict):
            assert "sym" not in o and "type_full" not in o
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(rec)


def test_method_params_modifiers_and_attributes(tmp_path):
    rec = lower(tmp_path, """class C {
  [HttpGet] public async Task<ActionResult> Idx([FromBody] string id, params int[] xs, int o = 4) { }
  static void Ext(this string a, ref int b, out int c, in int d) { }
  public C(int a) : base(a) { }
  string IFoo.Bar() => "";
}""")
    ms = {m["name"]: m for m in rec["types"][0]["methods"]}
    idx = ms["Idx"]
    assert idx["return_type"] == "Task<ActionResult>" and idx["modifiers"] == ["public", "async"]
    assert idx["attributes"][0]["name"] == "HttpGet"
    p = {x["name"]: x for x in idx["params"]}
    assert p["id"]["attributes"][0]["name"] == "FromBody" and p["id"]["type"] == "string"
    assert p["xs"]["modifiers"] == ["params"] and p["xs"]["type"] == "int[]"
    assert p["o"]["type"] == "int" and "modifiers" not in p["o"]
    mods = {x["name"]: x.get("modifiers") for x in ms["Ext"]["params"]}
    assert mods == {"a": ["this"], "b": ["ref"], "c": ["out"], "d": ["in"]}
    ctor = ms[".ctor"]
    assert ctor["return_type"] is None
    call = ctor["body"][0]["expr"]
    assert call["k"] == "call" and call["fn"]["id"] == "base" and call["args"][0]["id"] == "a"
    bar = ms["Bar"]
    assert bar["implements"] == ["IFoo.Bar"] and bar["body"][0]["k"] == "return"


def test_locals_assign_and_calls(tmp_path):
    out = body(tmp_path, 'string q = "a"; x += 1; y ??= 2; this.f = id; var r = Foo.Bar(1, name: id);')
    assert out[0] == {"k": "local", "line": 1, "name": "q", "type": "string", "init": {"k": "lit", "line": 1, "v": "a", "t": "string"}}
    assert out[1]["k"] == "assign" and out[1]["op"] == "+="
    # Other compound operators lower as `x = (x op y)`.
    assert out[2]["op"] == "=" and out[2]["value"]["k"] == "bin" and out[2]["value"]["op"] == "??"
    assert out[3]["target"] == {"k": "member", "line": 1, "obj": {"k": "name", "line": 1, "id": "this"}, "name": "f"}
    call = out[4]["init"]
    assert call["k"] == "call" and call["fn"]["k"] == "member" and call["fn"]["name"] == "Bar"
    assert call["args"][0]["v"] == 1 and call["named"]["name"]["id"] == "id"


def test_literals(tmp_path):
    assert expr(tmp_path, r'"a\n\"b\\"')["v"] == 'a\n"b\\'
    assert expr(tmp_path, '@"v""q"')["v"] == 'v"q'
    assert expr(tmp_path, '"""raw"""')["v"] == "raw"
    assert expr(tmp_path, "'c'") == {"k": "lit", "line": 1, "v": "c", "t": "char"}
    assert expr(tmp_path, "0x1F")["v"] == 31 and expr(tmp_path, "10L")["v"] == 10 and expr(tmp_path, "1_000")["v"] == 1000
    assert expr(tmp_path, "-5") == {"k": "lit", "line": 1, "v": -5, "t": "number"}
    assert expr(tmp_path, "1.5f")["v"] == 1.5
    assert expr(tmp_path, "true")["v"] is True and expr(tmp_path, "false")["t"] == "bool"
    assert expr(tmp_path, "null") == {"k": "lit", "line": 1, "v": None, "t": "null"}


def test_member_index_name_unary_and_wrappers(tmp_path):
    m = expr(tmp_path, "a.B.C")
    assert m["k"] == "member" and m["name"] == "C" and m["obj"]["name"] == "B" and m["obj"]["obj"]["id"] == "a"
    ix = expr(tmp_path, 'Request.Form["q"]')
    assert ix["k"] == "index" and ix["obj"]["name"] == "Form" and ix["args"][0]["v"] == "q"
    assert expr(tmp_path, "!a") == {"k": "unary", "line": 1, "op": "!", "e": {"k": "name", "line": 1, "id": "a"}}
    assert expr(tmp_path, "i++")["op"] == "++" and expr(tmp_path, "-a")["op"] == "-"
    # Parentheses, await, `!` suppression and checked() are transparent.
    for wrapped in ("(a)", "await a", "a!", "checked(a)"):
        assert expr(tmp_path, wrapped) == {"k": "name", "line": 1, "id": "a"}
    assert expr(tmp_path, "this")["id"] == "this" and expr(tmp_path, "base.Foo")["obj"]["id"] == "base"
    assert body(tmp_path, "return this;")[0]["value"]["id"] == "this"
    assert body(tmp_path, "Go(this);")[0]["expr"]["args"][0]["id"] == "this"
    assert expr(tmp_path, "x.Y<int>(1)")["fn"]["name"] == "Y"


def test_conditional_access_binds_receiver(tmp_path):
    e = expr(tmp_path, "x?.Y?.Z(1)")
    assert e["k"] == "call" and e["fn"]["name"] == "Z" and e["fn"]["obj"]["name"] == "Y"
    assert e["fn"]["obj"]["obj"]["id"] == "x"
    ix = expr(tmp_path, "x?[0]")
    assert ix["k"] == "index" and ix["obj"]["id"] == "x"


def test_new_initializers_arrays_anonymous(tmp_path):
    n = expr(tmp_path, "new Foo(1) { A = 1, B = x }")
    assert n["k"] == "new" and n["type"] == "Foo" and n["args"][0]["v"] == 1
    assert [(e["name"], e["value"]["k"]) for e in n["init"]] == [("A", "lit"), ("B", "name")]
    imp = expr(tmp_path, "new() { A = 1 }")
    assert imp["type"] is None and imp["init"][0]["name"] == "A"
    coll = expr(tmp_path, "new List<int> { 1, 2 }")
    assert coll["type"] == "List<int>" and [e["name"] for e in coll["init"]] == [None, None]
    arr = expr(tmp_path, "new byte[] { 1, 2, 3 }")
    assert arr["type"] == "byte[]" and len(arr["init"]) == 3
    assert len(expr(tmp_path, "new[] { 1, 2 }")["init"]) == 2
    anon = expr(tmp_path, "new { A = 1, x.B }")
    assert anon["type"] is None and [e["name"] for e in anon["init"]] == ["A", "B"]


def test_bin_interp_cond_cast_lambda(tmp_path):
    b = expr(tmp_path, '"a" + id')
    assert b["k"] == "bin" and b["op"] == "+" and b["l"]["v"] == "a" and b["r"]["id"] == "id"
    assert expr(tmp_path, "a && b")["op"] == "&&" and expr(tmp_path, "a ?? b")["op"] == "??"
    i = expr(tmp_path, '$"a{id}b{{c}}{x,5:N2}"')
    assert i["k"] == "interp"
    assert [p.get("v") or p.get("id") for p in i["parts"]] == ["a", "id", "b{c}", "x"]
    c = expr(tmp_path, "a ? b : c")
    assert c["k"] == "cond" and c["c"]["id"] == "a" and c["t"]["id"] == "b" and c["f"]["id"] == "c"
    cast = expr(tmp_path, "(Foo)x")
    assert cast["k"] == "cast" and cast["type"] == "Foo" and cast["e"]["id"] == "x"
    assert expr(tmp_path, "x as Bar") == {"k": "cast", "line": 1, "type": "Bar", "e": {"k": "name", "line": 1, "id": "x"}}
    lam = expr(tmp_path, "x => x.Id")
    assert lam["k"] == "lambda" and lam["params"] == ["x"] and lam["body"]["k"] == "member"
    lam2 = expr(tmp_path, "(p, q) => { return p; }")
    assert lam2["params"] == ["p", "q"] and lam2["body"][0]["k"] == "return"
    assert expr(tmp_path, "() => Go()")["k"] == "lambda" and "params" not in expr(tmp_path, "() => Go()")
    assert expr(tmp_path, "delegate { return 1; }")["body"][0]["k"] == "return"
    assert expr(tmp_path, "a is Foo") == {"k": "bin", "line": 1, "op": "is",
                                          "l": {"k": "name", "line": 1, "id": "a"}, "r": {"k": "name", "line": 1, "id": "Foo"}}


def test_multiplication_in_argument_is_not_a_declaration(tmp_path):
    # tree-sitter reads `page * size` in an argument as the declaration of `size`.
    call = expr(tmp_path, "Skip(page * size)")
    arg = call["args"][0]
    assert arg["k"] == "bin" and arg["op"] == "*" and arg["l"]["id"] == "page" and arg["r"]["id"] == "size"


def test_using_alias_is_expanded(tmp_path):
    rec = lower(tmp_path, "using Sha = System.Security.Cryptography.SHA1;\n"
                          "class C { object M() { var a = new Sha(); return Sha.Create(); } }")
    b = rec["types"][0]["methods"][0]["body"]
    assert b[0]["init"]["type"] == "System.Security.Cryptography.SHA1"
    recv = b[1]["value"]["fn"]["obj"]
    assert recv["k"] == "member" and recv["name"] == "SHA1"


def test_statements(tmp_path):
    out = body(tmp_path, """
        if (a) b(); else if (c) d(); else e();
        foreach (var i in xs) { f(i); }
        for (int i = 0; i < 3; i++) { g(); }
        while (w) { h(); }
        do { k(); } while (w);
        try { t(); } catch (Exception ex) { throw; } catch { } finally { fin(); }
        using (var c = new Conn()) { c.Open(); }
        using (res) { z(); }
        lock (o) { l(); }
        return id;
    """)
    kinds = [s["k"] for s in out]
    assert kinds == ["if", "loop", "loop", "loop", "loop", "try", "using", "using", "expr", "return"]
    assert out[0]["then"][0]["k"] == "expr" and out[0]["else"][0]["k"] == "if"
    assert out[1]["header"][0] == {"k": "name", "line": 3, "id": "i"} and out[1]["header"][1]["id"] == "xs"
    assert len(out[2]["header"]) == 3 and out[3]["header"][0]["id"] == "w" and out[4]["header"][0]["id"] == "w"
    t = out[5]
    assert [(c["type"], c["name"]) for c in t["catches"]] == [("Exception", "ex"), (None, None)]
    assert t["catches"][0]["body"][0] == {"k": "throw", "line": 7, "value": None}
    assert t["finally"][0]["k"] == "expr"
    assert out[6]["resource"][0]["k"] == "local" and out[6]["body"][0]["k"] == "expr"
    assert out[7]["resource"][0]["k"] == "expr"
    assert out[8]["expr"]["fn"]["id"] == "l"       # lock is inlined


def test_using_declaration_wraps_rest_of_block(tmp_path):
    out = body(tmp_path, "using var c = new Conn(); c.Open(); return 1;")
    assert [s["k"] for s in out] == ["using"]
    assert [s["k"] for s in out[0]["body"]] == ["expr", "return"]


def test_switch_sections_and_local_function(tmp_path):
    out = body(tmp_path, "switch (id) { case 1: a(); break; default: b(); break; } int Loc(int p) { return p; }")
    assert [s["k"] for s in out[:2]] == ["if", "if"] and out[0]["cond"]["id"] == "id"
    assert out[0]["then"][0]["expr"]["fn"]["id"] == "a"
    loc = out[2]
    assert loc["k"] == "local" and loc["name"] == "Loc" and loc["init"]["k"] == "lambda" and loc["init"]["params"] == ["p"]


def test_switch_expression_lowers_to_nested_cond(tmp_path):
    init = body(tmp_path, "var s = k switch { 1 => p, 2 when z => q, _ => r };")[0]["init"]
    assert init["k"] == "cond" and init["c"]["id"] == "k" and init["t"]["id"] == "p"
    assert init["f"]["k"] == "cond" and init["f"]["t"]["id"] == "q" and init["f"]["f"]["id"] == "r"


def test_deconstruction_and_unknown_nodes_keep_text(tmp_path):
    out = body(tmp_path, "var (u, v) = z; goto L; var s = default(int); var t = typeof(int);")
    assert out[0]["k"] == "assign" and out[0]["target"]["k"] == "unknown" and out[0]["value"]["id"] == "z"
    assert out[1] == {"k": "other", "line": 1, "text": "goto L;"}
    assert out[2]["init"] == {"k": "unknown", "line": 1, "text": "default(int)"}
    assert out[3]["init"] == {"k": "unknown", "line": 1, "text": "typeof(int)"}


# -- modern C# lowering parity (mirrors the helper tests in test_dnl_helper_ir.py, minus `sym`) --

TOP_SRC = ('var b = WebApplication.CreateBuilder(args);\nvar app = b.Build();\n'
           'app.MapGet("/", () => "x");\napp.Run();\nstatic int Helper() => 1;\n')


def walk_nodes(o):
    if isinstance(o, dict):
        yield o
        for v in o.values():
            yield from walk_nodes(v)
    elif isinstance(o, list):
        for v in o:
            yield from walk_nodes(v)


def test_top_level_statements_lowered(tmp_path):
    rec = lower(tmp_path, TOP_SRC)
    t = rec["types"][0]
    assert (t["name"], t["namespace"], t["kind"], t["modifiers"]) == ("Program", "", "class", ["static", "partial"])
    assert [m["name"] for m in t["methods"]] == ["<Main>$"]
    m = t["methods"][0]
    assert (m["modifiers"], m["return_type"], m["params"]) == (["static"], "void", [])
    assert (m["line"], m["end_line"], t["line"], t["end_line"]) == (1, 5, 1, 5)
    stmts = m["body"]
    assert [s["k"] for s in stmts] == ["local", "local", "expr", "expr", "local"]
    assert stmts[4]["name"] == "Helper" and stmts[4]["init"]["k"] == "lambda"
    assert not any("sym" in n for n in walk_nodes(rec))


def test_top_level_with_partial_program(tmp_path):
    rec = lower(tmp_path, TOP_SRC + "public partial class Program { }\n")
    assert [t["name"] for t in rec["types"]] == ["Program", "Program"]
    assert [m["name"] for m in rec["types"][0]["methods"]] == ["<Main>$"]
    assert rec["types"][1]["methods"] == []


def test_no_top_level_statements_no_synthetic_program(tmp_path):
    rec = lower(tmp_path, "class C { void M() { a(); } }")
    assert [t["name"] for t in rec["types"]] == ["C"]


def test_top_level_if_directive_branches(tmp_path):
    rec = lower(tmp_path, "#if DEBUG\nvar a = new Dbg();\n#else\nvar b = new Rel();\n#endif\nGo();\n")
    t = rec["types"][0]
    assert t["name"] == "Program" and [m["name"] for m in t["methods"]] == ["<Main>$"]
    assert {n["type"] for n in walk_nodes(t) if n.get("k") == "new"} == {"Dbg", "Rel"}
    assert [s["k"] for s in t["methods"][0]["body"]][-1] == "expr"


def test_top_level_statement_crash_is_contained(tmp_path, monkeypatch):
    real = frontend_ts._Lowering._stmt

    def flaky(self, s):
        if self.text(s).startswith("Bad"):
            raise RuntimeError("boom")
        return real(self, s)
    monkeypatch.setattr(frontend_ts._Lowering, "_stmt", flaky)
    # stmt() isolates a crashing statement into an `other` node; the file survives.
    rec = lower(tmp_path, "Good();\nBad();\nAlso();\n")
    assert "error" not in rec
    kinds = [s["k"] for s in rec["types"][0]["methods"][0]["body"]]
    assert kinds == ["expr", "other", "expr"]


def test_lambda_param_info_and_end_line(tmp_path):
    src = ('app.MapGet("/o/{id}", ([FromRoute] int id, [FromServices] IStore s) =>\n{\n'
           ' return s.Get(id);\n});\n')
    rec = lower(tmp_path, src)
    lam = next(n for n in walk_nodes(rec) if n.get("k") == "lambda")
    info = lam["param_info"]
    assert [p["name"] for p in info] == ["id", "s"]
    assert [p["type"] for p in info] == ["int", "IStore"]
    assert [[a["name"] for a in p["attributes"]] for p in info] == [["FromRoute"], ["FromServices"]]
    assert [p["modifiers"] for p in info] == [[], []]
    assert lam["params"] == ["id", "s"] and lam["end_line"] == 4


def test_lambda_param_info_untyped_and_modifiers(tmp_path):
    lam = expr(tmp_path, "(a, b) => a")
    assert [(p["name"], p["type"], p["attributes"], p["modifiers"]) for p in lam["param_info"]] == [
        ("a", None, [], []), ("b", None, [], [])]
    lam = expr(tmp_path, "x => x")
    assert [p["name"] for p in lam["param_info"]] == ["x"] and lam["param_info"][0]["type"] is None
    lam = expr(tmp_path, "(ref int r) => r")
    assert lam["param_info"][0]["modifiers"] == ["ref"]
    lam = expr(tmp_path, "delegate (int q) { return q; }")
    assert lam["param_info"][0]["type"] == "int"
    loc = body(tmp_path, "int Loc(int p) { return p; }")[0]["init"]
    assert loc["param_info"][0]["type"] == "int" and loc["end_line"] == 1


def test_lambda_without_params_omits_param_info(tmp_path):
    lam = expr(tmp_path, '() => "x"')
    assert "param_info" not in lam and "params" not in lam and lam["end_line"] == 1


def test_primary_constructor_and_record(tmp_path):
    src = ("public class Svc(ILogger<Svc> log, IStore store) : Base(store) { }\n"
           "public record OrderDto([property: Required] string Name, int Qty);\n")
    svc, dto = lower(tmp_path, src)["types"]
    assert svc["bases"] == ["Base"]
    ctor = next(m for m in svc["methods"] if m["name"] == ".ctor")
    assert [p["name"] for p in ctor["params"]] == ["log", "store"]
    assert [p["type"] for p in ctor["params"]] == ["ILogger<Svc>", "IStore"]
    first = ctor["body"][0]
    assert first["k"] == "expr" and first["expr"]["k"] == "call" and first["expr"]["fn"]["id"] == "base"
    assert [a["id"] for a in first["expr"]["args"]] == ["store"]
    assert (ctor["modifiers"], ctor["return_type"], ctor["attributes"]) == ([], None, [])
    assert [p["name"] for p in dto["properties"]] == ["Name", "Qty"]
    assert [p["type"] for p in dto["properties"]] == ["string", "int"]
    assert [a["name"] for a in dto["properties"][0]["attributes"]] == ["Required"]
    assert any(m["name"] == ".ctor" for m in dto["methods"])


def test_primary_constructor_variants(tmp_path):
    rec = lower(tmp_path, "public struct P(int x);\n"
                          "public record struct RS(int A);\n"
                          "public class Plain { }\n"
                          "public record R(int Name) { public int Name { get; init; } public int Other { get; } }\n"
                          "public class E() { void M() { } }\n")
    p, rs, plain, r, e = rec["types"]
    assert [m["name"] for m in p["methods"]] == [".ctor"] and p["properties"] == []
    assert rs["kind"] == "struct" and [q["name"] for q in rs["properties"]] == ["A"]
    assert plain["methods"] == []
    # A positional parameter the body redeclares adds no second property.
    assert [q["name"] for q in r["properties"]] == ["Name", "Other"]
    assert [m["name"] for m in e["methods"]] == [".ctor", "M"] and e["methods"][0]["params"] == []


def test_collection_switch_is_with(tmp_path):
    src = ("class C { void M(object o, R r) {\n int[] a = [x, ..ys];\n var s = k switch { 1 => p, _ => q };\n"
           " if (o is string t) {}\n var r2 = r with { Name = n };\n } }\n")
    b = lower(tmp_path, src)["types"][0]["methods"][0]["body"]
    coll, sw, ifs, wth = b[0]["init"], b[1]["init"], b[2], b[3]["init"]
    ids = lambda e: {n["id"] for n in walk_nodes(e) if n.get("k") == "name"}

    assert coll["k"] == "new" and coll["type"] is None and coll["args"] == []
    assert [e["value"]["id"] for e in coll["init"]] == ["x", "ys"]

    assert sw["k"] == "cond" and sw["c"]["id"] == "k" and sw["t"]["id"] == "p"
    assert sw["f"]["id"] == "q"

    isx = ifs["cond"]
    assert isx["k"] == "bin" and isx["op"] == "is" and isx["l"]["id"] == "o"
    assert isx["r"]["k"] == "unknown" and "string t" in isx["r"]["text"]

    assert wth["k"] == "new" and wth["type"] is None and [a["id"] for a in wth["args"]] == ["r"]
    assert [(e["name"], e["value"]["id"]) for e in wth["init"]] == [("Name", "n")]
    assert ids(coll) | ids(sw) | ids(isx) | ids(wth) >= {"x", "ys", "p", "q", "o", "r", "n"}


def test_is_pattern_forms_lower_to_bin_is(tmp_path):
    for pat in ("null", "not null", "{ Length: > 0 }", "string t"):
        e = expr(tmp_path, f"o is {pat}")
        assert e["k"] == "bin" and e["op"] == "is" and e["l"]["id"] == "o", pat
    assert expr(tmp_path, "o is null")["r"] == {"k": "unknown", "line": 1, "text": "null"}
    assert expr(tmp_path, "o is not null")["r"]["text"] == "not null"


def test_empty_collection_and_nested_spread(tmp_path):
    e = expr(tmp_path, "[]")
    assert e["k"] == "new" and e["init"] == []
    e = expr(tmp_path, "[..a, [b]]")
    assert [i["value"].get("id") or i["value"]["k"] for i in e["init"]] == ["a", "new"]


def test_raw_string_literal(tmp_path):
    src = 'class C { void M() { var q = """SELECT 1"""; var m = """\n    a\n     b\n    """; } }'
    f = tmp_path / "R.cs"
    f.write_bytes(src.encode("utf-8"))      # LF kept: the value carries the file's own newlines
    b = frontend_ts.lower_file(f, "R.cs", "P")["types"][0]["methods"][0]["body"]
    assert b[0]["init"]["k"] == "lit" and b[0]["init"]["v"] == "SELECT 1"
    assert b[1]["init"]["k"] == "lit" and b[1]["init"]["v"] == "a\n b"


def test_deep_nesting_degrades_instead_of_raising(tmp_path):
    terms = " + ".join(["a"] * 2500)
    rec = lower(tmp_path, "class C { string M(string a) { return %s; } }" % terms)
    ret = rec["types"][0]["methods"][0]["body"][0]["value"]
    depth, node = 0, ret
    while node.get("k") == "bin":
        node, depth = node["l"], depth + 1
    assert node["k"] == "unknown" and depth <= frontend_ts.MAX_DEPTH + 1
    deep_if = "".join("if (a) {" for _ in range(500)) + "x();" + "}" * 500
    rec = lower(tmp_path, "class C { void M(bool a) { %s } }" % deep_if)
    assert rec["types"][0]["methods"][0]["body"]


def test_syntax_errors_are_counted_not_raised(tmp_path):
    rec = lower(tmp_path, "class C { void M( { var = ; } } class D { int X { get; } }")
    assert rec["parse_errors"] > 0 and "error" not in rec
    rec = lower(tmp_path, "class C { void M() { var x = ; Go(); } }")
    assert rec["parse_errors"] > 0 and rec["types"][0]["methods"]


def test_unreadable_file_returns_error_record(tmp_path):
    rec = frontend_ts.lower_file(tmp_path / "missing.cs", "missing.cs", "P")
    assert "error" in rec and load_file_ir(rec) is None


def test_lowering_bug_in_one_member_is_contained(tmp_path, monkeypatch):
    f = tmp_path / "A.cs"
    f.write_text("class C { void Good() { a(); } void Bad() { b(); } }")
    real = frontend_ts._Lowering.method

    def flaky(self, m):
        if self.text(m.child_by_field_name("name")) == "Bad":
            raise RuntimeError("boom")
        return real(self, m)
    monkeypatch.setattr(frontend_ts._Lowering, "method", flaky)
    rec = frontend_ts.lower_file(f, "A.cs", "P")
    assert [m["name"] for m in rec["types"][0]["methods"]] == ["Good"]


def test_loaded_ir_is_usable_by_ir_loader(tmp_path):
    fir = load_file_ir(lower(tmp_path, '[A(1)] class C : B { [HttpGet] void M(int a) { x(a); } }'))
    t = fir.types[0]
    assert t.bases == ["B"] and t.attributes[0].args[0]["v"] == 1
    assert t.methods[0].params[0].name == "a" and t.methods[0].body[0]["k"] == "expr"


# -- VB pattern fallback -----------------------------------------------------

def vb_scan(tmp_path, text: str):
    f = tmp_path / "A.vb"
    f.write_text(text, encoding="utf-8")
    model = project.ProjectModel(tmp_path, [], {}, helper.DEGRADED_REASON, [], vb_files=["A.vb"])
    return vb_regex.scan(model)


def ids(findings) -> list[tuple[str, int]]:
    return sorted((f.check_id, f.line) for f in findings)


VB_POSITIVES = [
    ("DNL-INJ-001", 'Dim cmd As New SqlCommand("select * from t where n = \'" & name & "\'", conn)'),
    ("DNL-INJ-001", 'cmd.CommandText = "delete from t where id = " + id'),
    ("DNL-INJ-001", 'Dim q = "select * from t where n = \'" & name & "\'"'),
    ("DNL-INJ-001", 'Dim cmd As New SqlCommand(Request.QueryString("q"), conn)'),
    ("DNL-INJ-001", 'Dim q = String.Format("select * from t where n = \'{0}\'", name)'),
    ("DNL-XSS-001", 'Response.Write(Request("q"))'),
    ("DNL-XSS-001", 'RESPONSE.WRITE("<b>" & Request.QueryString("q") & "</b>")'),
    ("DNL-DESER-001", 'Dim o = New BinaryFormatter().Deserialize(stream)'),
    ("DNL-DESER-001", 'Return New LosFormatter().Deserialize(s)'),
    ("DNL-CRY-001", 'Dim h As MD5 = MD5.Create()'),
    ("DNL-CRY-001", 'Dim h = New SHA1CryptoServiceProvider()'),
    ("DNL-CRY-001", 'Dim h = HashAlgorithm.Create("MD5")'),
    ("DNL-CRY-002", 'Dim c = New DESCryptoServiceProvider()'),
    ("DNL-CRY-002", 'Dim c = TripleDES.Create()'),
    ("DNL-SEC-003", 'Dim cs = "Server=db;User Id=sa;Password=Hunter2;"'),
    ("DNL-SEC-003", 'Dim cs = "Data Source=x;pwd=abc123"'),
    ("DNL-CRY-006", 'ServicePointManager.ServerCertificateValidationCallback = Function(s, c, ch, e) True'),
    ("DNL-CRY-006", 'ServicePointManager.ServerCertificateValidationCallback += Function(s, c, ch, e) True'),
]


@pytest.mark.parametrize("rule,line", VB_POSITIVES)
def test_vb_positive(tmp_path, rule, line):
    out = vb_scan(tmp_path, f"Public Class X\nSub M()\n{line}\nEnd Sub\nEnd Class\n")
    assert (rule, 3) in ids(out), ids(out)
    assert all(f.confidence == "REVIEW" and f.file == "A.vb" for f in out)
    assert all(f.owasp for f in out)


VB_NEGATIVES = [
    'Dim cmd As New SqlCommand("select * from t where id = @id", conn)',
    'Dim cmd As New SqlCommand("select * from " & "t", conn)',
    "cmd.CommandText = sql",
    'Response.Write("hello")',
    'Response.Write(Server.HtmlEncode(Request("q")))',
    'Dim o = New JavaScriptSerializer().Deserialize(Of Foo)(s)',
    'Dim h As SHA256 = SHA256.Create()',
    'Dim h = New HMACSHA1(key)',
    'Dim c = Aes.Create()',
    'Dim cs = "Server=db;Integrated Security=True;"',
    'Dim cs = "Server=db;Password={DbPassword};"',
    'ServicePointManager.ServerCertificateValidationCallback = Function(s, c, ch, e) e = SslPolicyErrors.None',
    'Dim msg = "do not use MD5.Create() here"',
]


@pytest.mark.parametrize("line", VB_NEGATIVES)
def test_vb_negative(tmp_path, line):
    out = vb_scan(tmp_path, f"Public Class X\nSub M()\n{line}\nEnd Sub\nEnd Class\n")
    assert [f for f in out if f.line == 3] == []


@pytest.mark.parametrize("line", [
    "' Dim h = MD5.Create()",
    "    ' Response.Write(Request(\"q\"))",
    "REM Dim h = New DESCryptoServiceProvider()",
    "   rem Dim h = MD5.Create()",
    "Dim x = 1 ' Dim h = MD5.Create()",
    'Dim x = "it\'s" \' MD5.Create()',
])
def test_vb_comments_never_match(tmp_path, line):
    assert vb_scan(tmp_path, f"Sub M()\n{line}\nEnd Sub\n") == []


def test_vb_string_with_apostrophe_is_not_a_comment(tmp_path):
    out = vb_scan(tmp_path, "Sub M()\nDim q = \"it's\" : Dim h = MD5.Create()\nEnd Sub\n")
    assert ids(out) == [("DNL-CRY-001", 2)]


def test_vb_line_continuation_joins_statement(tmp_path):
    out = vb_scan(tmp_path, 'Sub M()\nDim cmd As New SqlCommand("select * from t where n = \'" & _\n    name & "\'", conn)\nEnd Sub\n')
    assert ids(out) == [("DNL-INJ-001", 2)]


def test_vb_compound_concat_on_sql_variable(tmp_path):
    out = vb_scan(tmp_path, 'Sub M()\nDim Sql = "select * from t where n = \'"\nsql &= txtName.Text\nSql += "\'"\nEnd Sub\n')
    assert ids(out) == [("DNL-INJ-001", 3)]


def test_vb_formatter_variable_deserialize(tmp_path):
    out = vb_scan(tmp_path, "Sub M()\nDim bf As New BinaryFormatter()\nDim o = bf.Deserialize(s)\nEnd Sub\n")
    assert ids(out) == [("DNL-DESER-001", 3)]


def test_vb_cert_callback_variants(tmp_path):
    out = vb_scan(tmp_path, """Sub A()
    ServicePointManager.ServerCertificateValidationCallback = AddressOf Always
    ServicePointManager.ServerCertificateValidationCallback = AddressOf Real
    ServicePointManager.ServerCertificateValidationCallback = Function(s, c, ch, e)
        Return True
    End Function
End Sub
Function Always(s As Object, c As Object, ch As Object, e As Object) As Boolean
    Return True
End Function
Function Real(s As Object, c As Object, ch As Object, e As Object) As Boolean
    Return e = SslPolicyErrors.None
End Function
""")
    assert ids(out) == [("DNL-CRY-006", 2), ("DNL-CRY-006", 4)]


def test_vb_scan_ignores_unreadable_file(tmp_path):
    model = project.ProjectModel(tmp_path, [], {}, helper.DEGRADED_REASON, [], vb_files=["gone.vb"])
    assert vb_regex.scan(model) == [] and "gone.vb" in model.notes[0]


def test_vb_scan_rule_ids_have_owasp_entries():
    from core.owasp_web import RULES
    for rid in ("DNL-INJ-001", "DNL-XSS-001", "DNL-DESER-001", "DNL-CRY-001", "DNL-CRY-002", "DNL-SEC-003", "DNL-CRY-006"):
        assert rid in RULES or any(rid in k for k in RULES)


# -- degraded end to end -------------------------------------------------------

def test_degraded_reason_text():
    assert helper.DEGRADED_REASON == (
        "Roslyn helper not available (--allow-degraded): C# parsed with tree-sitter (no semantic symbols), "
        "VB scanned with patterns (REVIEW); findings may be incomplete.")


def test_no_helper_without_flag_still_exits_2(monkeypatch, no_helper, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", str(FX / "mvc5_app")])
    assert main.main() == 2
    assert "--allow-degraded" in capsys.readouterr().err


def test_degraded_prepare_builds_cs_ir_and_lists_vb(no_helper):
    model = project.prepare(FX / "mvc5_app", True)
    assert model.degraded == helper.DEGRADED_REASON
    assert "MvcApp/Controllers/HomeController.cs" in model.files and "Scratch/Loose.cs" in model.files
    assert model.vb_files and all(f.lower().endswith(".vb") for f in model.vb_files)
    assert not any(f.lower().endswith(".vb") for f in model.files)
    assert model.derives_from(model.find_types("HomeController")[0], {"controller"})


def test_degraded_cli_end_to_end(tmp_path, monkeypatch, no_helper):
    out = tmp_path / "r.json"
    monkeypatch.setattr(sys, "argv", ["main.py", str(FX / "taint_app"), "--allow-degraded", "--json", str(out),
                                      "--html", str(tmp_path / "r.html")])
    assert main.main() == 0
    data = [r for r in json.loads(out.read_text()) if r["language"] == "dotnet_legacy"]
    assert data and all(r["degraded"] == helper.DEGRADED_REASON for r in data)
    assert any(r["routes"] for r in data)
    findings = [f for r in data for f in r["findings"]]
    ids_ = {f["check_id"] for f in findings}
    assert {"DNL-INJ-001", "DNL-XSS-001", "DNL-AUTHZ-001"} <= ids_
    assert all(f["owasp"] for f in findings)
    vb = [f for f in findings if f["file"].endswith(".vb")]
    assert vb and all(f["confidence"] == "REVIEW" for f in vb)
    # C# findings keep the confidence the rule itself gives them (no blanket downgrade).
    cs_inj = [f for f in findings if f["file"].endswith(".cs") and f["check_id"] == "DNL-INJ-001"]
    assert cs_inj and any(f.get("confidence") != "REVIEW" for f in cs_inj)
    assert "degraded-banner" in (tmp_path / "r.html").read_text()


def test_vb_scan_runs_only_degraded(roslyn_helper):
    model = project.prepare(FX / "taint_app", False)
    assert model.degraded is None and model.vb_files == []
    res = [get_analyzer("dotnet_legacy", fw)(FX / "taint_app").analyze() for fw in FRAMEWORKS]
    assert not any(f.confidence == "REVIEW" and f.title.endswith("(VB pattern)") for r in res for f in r.findings)


# -- parity with the helper ----------------------------------------------------

def _all_results(target: Path):
    project._CACHE.clear()
    return [get_analyzer("dotnet_legacy", fw)(target).analyze() for fw in FRAMEWORKS]


def _cs_routes(results):
    return {(tuple(r.methods) if not isinstance(r.methods, str) else r.methods, r.path, r.file, r.line)
            for res in results for r in res.routes if r.file.endswith(".cs")}


def _cs_findings(results):
    return {(f.check_id, f.file, f.line) for res in results for f in res.findings if f.file.endswith(".cs")}


CORE_PREFIXES = ("DNL-INJ-", "DNL-XSS-", "DNL-AUTHZ-", "DNL-AUTH-")

# C# findings the helper reports that the tree-sitter run does not, with the reason. Kept exact: a
# fix (or a regression) changes the set and the test says so.
EXPECTED_MISSES = {
    # `var d = Mk();` -- the local's type is the return type of a project method; only the helper's
    # semantic model (type_full) knows it is an XmlDocument built with an unsafe resolver.
    ("DNL-XXE-001", "TaintCs/DeserXml/Escapes.cs", 284),
    ("DNL-XXE-001", "TaintCs/DeserXml/Escapes.cs", 291),
}
# Findings only the tree-sitter run reports: without `sym`, dynamic-LINQ-named static calls
# (`Enumerable.Where(list, ..)`) cannot be told from System.Linq.Dynamic, so the rule fires on the
# member name alone (extra noise, never a missed finding).
EXPECTED_EXTRAS = {
    ("DNL-INJ-006", "TaintCs/Gaps.cs", 83),
    ("DNL-INJ-006", "TaintCs/Gaps.cs", 95),
}


@pytest.fixture(scope="module", params=["taint_app", "mvc5_app"])
def parity(request, roslyn_helper):
    target = FX / request.param
    full = _all_results(target)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(helper, "find_helper", lambda *a: None)
        mp.setattr(helper, "sdk_available", lambda: False)
        project.prepare(target, True)
        degraded = _all_results_keep_model(target)
    return request.param, full, degraded


def _all_results_keep_model(target: Path):
    return [get_analyzer("dotnet_legacy", fw)(target).analyze() for fw in FRAMEWORKS]


def test_parity_routes(parity):
    _, full, degraded = parity
    assert _cs_routes(full), "fixture has no C# routes"
    assert _cs_routes(full) <= _cs_routes(degraded)


def test_parity_core_findings(parity):
    _, full, degraded = parity
    core = {x for x in _cs_findings(full) if x[0].startswith(CORE_PREFIXES)}
    assert core
    missing = core - _cs_findings(degraded)
    assert not missing, f"injection / XSS / auth findings lost without symbols: {sorted(missing)}"


def test_parity_all_cs_findings_and_documented_gaps(parity):
    name, full, degraded = parity
    helper_set, ts_set = _cs_findings(full), _cs_findings(degraded)
    assert helper_set - ts_set == (EXPECTED_MISSES if name == "taint_app" else set())
    assert ts_set - helper_set == (EXPECTED_EXTRAS if name == "taint_app" else set())


def test_parity_degraded_flag_and_vb_review(parity):
    _, full, degraded = parity
    assert all(r.degraded is None for r in full)
    assert all(r.degraded == helper.DEGRADED_REASON for r in degraded)
    for r in degraded:
        for f in r.findings:
            if f.file.endswith(".vb") and f.title.endswith("(VB pattern)"):
                assert f.confidence == "REVIEW"


# Files whose lowered IR is not identical to the helper's, with the reason: `using` aliases are
# expanded in place (no symbols to resolve them).
IR_DIFFERENT = {"TaintCs/Crypto/Alias.cs", "TaintCs/UsesExtAlias.cs"}


def _strip(o):
    if isinstance(o, dict):
        return {k: _strip(v) for k, v in o.items() if k not in ("sym", "type_full")}
    if isinstance(o, list):
        return [_strip(x) for x in o]
    return o


@pytest.mark.parametrize("name", ["taint_app", "mvc5_app", "mvc_handrolled", "model_with_props", "webapi_global",
                                  "wcf_app", "misc_log4net_app", "misc_nolog_app", "misc_throttle_app"])
def test_lowered_ir_equals_helper_ir_minus_semantic_keys(roslyn_helper, name):
    root = (FX / name).resolve()
    projects = project.load_projects(root, [])
    objs = helper.parse_projects(Path(roslyn_helper), root, project._request(projects))
    checked = 0
    for o in objs:
        if o.get("language") != "cs" or "types" not in o or o["path"] in IR_DIFFERENT:
            continue
        ts = frontend_ts.lower_file(root / o["path"], o["path"], o["project"])
        assert ts == _strip(o), o["path"]
        checked += 1
    assert checked or name in ("webapi_global", "wcf_app")


MODERN_SRC = """var b = WebApplication.CreateBuilder(args);
var app = b.Build();
app.MapGet("/o/{id}", ([FromRoute] int id, IStore st) =>
{
    return st.Get(id);
});
object o = app;
if (o is string t && o is not null) { Go(t); }
var r2 = rec with { Name = "n" };
int[] arr = [1, ..more, 3];
var sw = k switch { 1 => "a", 2 => "b", _ => "c" };
var raw = \"\"\"
    select 1
      from t
    \"\"\";
int Local(int a) => a;
app.Run();
public class Svc(ILogger<Svc> log, IStore store) : Base(store)
{
    public void Do() { log.Info("x"); }
}
public record OrderDto([property: Required] string Name, int Qty);
public partial class Program { }
"""


# `#if` regions are left out of this source on purpose: Roslyn lowers only the active branch, the
# tree-sitter frontend lowers every branch (covered by test_top_level_if_directive_branches).
def test_modern_csharp_ir_equals_helper_ir_minus_semantic_keys(roslyn_helper, tmp_path):
    (tmp_path / "Modern.cs").write_bytes(MODERN_SRC.encode("utf-8"))
    projects = project.load_projects(tmp_path, [])
    objs = [o for o in helper.parse_projects(Path(roslyn_helper), tmp_path, project._request(projects))
            if o.get("language") == "cs" and "types" in o]
    assert len(objs) == 1
    ts = frontend_ts.lower_file(tmp_path / "Modern.cs", objs[0]["path"], objs[0]["project"])
    assert ts == _strip(objs[0])


# -- fix round 1: preprocessor regions, syntax errors, VB forms --------------------------------

def _sinks(rec) -> list[str]:
    """Names of every `new` type found anywhere in the lowered file."""
    out = []

    def walk(o):
        if isinstance(o, dict):
            if o.get("k") == "new" and o.get("type"):
                out.append(o["type"])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(rec)
    return out


def test_preproc_statement_level_branches_are_all_lowered(tmp_path):
    rec = lower(tmp_path, """class C {
  ActionResult M(string id) {
#if DEBUG
    var x = new Dbg();
#elif STAGE
    var y = new Stage();
#else
    var c = new SqlCommand("select " + id);
#endif
    return View();
  }
}""")
    assert _sinks(rec) == ["Dbg", "Stage", "SqlCommand"]
    assert [s["k"] for s in rec["types"][0]["methods"][0]["body"]][-1] == "return"


def test_preproc_member_level_branches_are_all_lowered(tmp_path):
    rec = lower(tmp_path, """#if DEBUG
namespace N {
#endif
class C {
#if DEBUG
  void A() { a(); }
#else
  void B() { b(); }
#endif
  int F;
#if X
  public string P { get; set; }
#endif
}
#if DEBUG
}
#endif""")
    t = rec["types"][0]
    assert [m["name"] for m in t["methods"]] == ["A", "B"]
    assert [p["name"] for p in t["properties"]] == ["P"] and [f["name"] for f in t["fields"]] == ["F"]


def test_preproc_splitting_a_signature_keeps_every_method(tmp_path):
    rec = lower(tmp_path, """class C {
  void Before() { b(); }
#if NET40
  public ActionResult Get(string id)
#else
  public ActionResult Get(string id, int x = 0)
#endif
  { var c = new SqlCommand(id); }
  void After() { a(); }
}""")
    ms = rec["types"][0]["methods"]
    assert [m["name"] for m in ms].count("Get") == 2
    assert {"Before", "After"} <= {m["name"] for m in ms}
    assert all("SqlCommand" in _sinks(m) for m in ms if m["name"] == "Get")
    # Lines stay those of the original file.
    assert next(m for m in ms if m["name"] == "After")["line"] == 9


def test_unbalanced_brace_never_silently_empties_the_file(tmp_path, no_helper):
    d = tmp_path / "app"
    d.mkdir()
    (d / "App.csproj").write_text('<Project ToolsVersion="15.0"><ItemGroup><Compile Include="A.cs" />'
                                  '<Compile Include="B.cs" /></ItemGroup></Project>')
    (d / "A.cs").write_text('class A { void M(string id) { var c = new SqlCommand(id);\n')
    (d / "B.cs").write_text('class B { void M() { { { } } \n')
    (d / "Empty.cs").write_text("// nothing here\n")
    model = project.prepare(d, True)
    notes = [n for n in model.notes if "parse errors in degraded mode" in n]
    assert any(n.startswith("A.cs:") for n in notes) and any(n.startswith("B.cs:") for n in notes)
    # Whatever tree-sitter can recover is kept.
    assert "A.cs" in model.files and any("SqlCommand" in str(m.body) for t in model.files["A.cs"].types for m in t.methods)


def test_non_trivial_file_without_types_gets_a_note(tmp_path, no_helper, monkeypatch):
    d = tmp_path / "app"
    d.mkdir()
    (d / "App.csproj").write_text('<Project ToolsVersion="15.0"><ItemGroup><Compile Include="A.cs" /></ItemGroup></Project>')
    (d / "A.cs").write_text("namespace N { public class A { void M() { x(); } }\n" * 1)
    monkeypatch.setattr(frontend_ts._Lowering, "collect_types", lambda self, root: [])
    model = project.prepare(d, True)
    assert any("A.cs" in n and "no types" in n for n in model.notes)


def test_preproc_variants_only_when_needed(tmp_path):
    # A clean file with directives is parsed once (no duplicate methods).
    rec = lower(tmp_path, "class C {\n#if X\n void A() { }\n#endif\n void B() { }\n}")
    assert [m["name"] for m in rec["types"][0]["methods"]] == ["A", "B"]


@pytest.mark.parametrize("decl", [
    "Dim f = New BinaryFormatter()",
    "Dim f As New BinaryFormatter()",
    "Dim f As BinaryFormatter = New BinaryFormatter()",
    "Private _f As New BinaryFormatter()",
    "Public Shared ReadOnly _f As BinaryFormatter = New BinaryFormatter()",
    "Protected Friend _f = New LosFormatter()",
])
def test_vb_formatter_declarations(tmp_path, decl):
    name = "_f" if "_f" in decl else "f"
    out = vb_scan(tmp_path, f"Class X\n{decl}\nSub M()\nDim o = {name}.Deserialize(s)\nEnd Sub\nEnd Class\n")
    assert ("DNL-DESER-001", 4) in ids(out)


def test_vb_response_write_without_parentheses(tmp_path):
    out = vb_scan(tmp_path, 'Sub M()\nResponse.Write Request.QueryString("x")\nResponse.Write "<b>" & Request("q")\n'
                            'Response.Write Server.HtmlEncode(Request("q"))\nResponse.Write "hi"\nEnd Sub\n')
    assert ids(out) == [("DNL-XSS-001", 2), ("DNL-XSS-001", 3)]


def test_u8_literal_value_has_no_quotes(tmp_path):
    assert expr(tmp_path, '"abc"u8')["v"] == "abc"


# -- controller fix: variant merge keeps differing same-signature members ---------

def test_variant_merge_keeps_same_signature_member_with_different_body(tmp_path):
    f = tmp_path / "A.cs"
    f.write_text(
        "using System.Data.SqlClient;\nnamespace N { public class C {\n"
        "#if DEBUG\n"
        "  [Authorize] public string Run(string id) { var c = new SqlCommand(\"select \" + id); int = ; c.ExecuteNonQuery(); return id; }\n"
        "#else\n"
        "  public string Run(string id) { return \"safe\"; }\n"
        "#endif\n"
        "} }\n")
    rec = frontend_ts.lower_file(f, "A.cs", "P")
    runs = [m for t in rec["types"] for m in t["methods"] if m["name"] == "Run"]
    assert any("SqlCommand" in json.dumps(m) for m in runs), runs
    assert any("Authorize" in json.dumps(m.get("attrs") or m.get("attributes") or []) for m in runs), runs


def test_brace_count_ignores_braces_in_strings_with_letter_n(tmp_path):
    assert frontend_ts._NOISE.sub(b"", b'x = "need {"; y = \'{\';') == b"x = ; y = ;"
    assert frontend_ts._NOISE.sub(b"", b'x = "a\\"{";') == b"x = ;"


def test_generic_names_carry_targs(tmp_path):
    rec = lower(tmp_path, 'var app = b.Build();\napp.MapHub<ChatHub>("/c");\nMapOf<A.B, int>();\n'
                          'var x = Outer.Make<Dict<string, int>>();\n')
    body = rec["types"][0]["methods"][0]["body"]
    fn = body[1]["expr"]["fn"]
    assert (fn["k"], fn["name"], fn["targs"]) == ("member", "MapHub", ["ChatHub"])
    bare = body[2]["expr"]["fn"]
    assert (bare["k"], bare["id"], bare["targs"]) == ("name", "MapOf", ["A.B", "int"])
    assert body[3]["init"]["fn"]["targs"] == ["Dict<string, int>"]
    assert "targs" not in body[0]["init"]["fn"]


def test_lambda_and_local_function_attributes(tmp_path):
    src = ('app.MapGet("/a", [Authorize] () => 1);\n'
           'app.MapGet("/b", [AllowAnonymous] static (int id) => id);\n'
           '[Authorize(Roles = "x")] static int Loc(int p) => p;\n'
           'app.MapGet("/c", () => 2);\n')
    lams = [n for n in walk_nodes(lower(tmp_path, src)) if n.get("k") == "lambda"]
    assert [[a["name"] for a in l.get("attributes", [])] for l in lams] == [
        ["Authorize"], ["AllowAnonymous"], ["Authorize"], []]
    assert "attributes" not in lams[3]
    assert lams[2]["attributes"][0]["named"]["Roles"]["v"] == "x"
