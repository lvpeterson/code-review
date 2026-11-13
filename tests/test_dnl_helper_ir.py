"""Drives the built roslyn-ir helper binary end to end (schema 1 IR)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("dotnet") is None,
                                reason="dotnet SDK not on PATH")


@pytest.fixture
def helper(roslyn_helper):
    return roslyn_helper


def run_parse(helper, root, projects, imports=None):
    """projects: [(name, language, [paths])] -> list of decoded JSON Lines.
    imports: optional {project name: [VB global imports]}."""
    req = {"root": str(root), "projects": [
        {"name": n, "language": lang, "files": [str(p) for p in files], "references": [],
         **({"imports": imports[n]} if imports and n in imports else {})}
        for n, lang, files in projects]}
    req_path = root / "_request.json"
    req_path.write_text(json.dumps(req), encoding="utf-8")
    proc = subprocess.run([helper, "parse", "--input", str(req_path)],
                          capture_output=True, check=True)
    out = proc.stdout.decode("utf-8")
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def parse_file(helper, root, path, language):
    lines = run_parse(helper, root, [("p", language, [path])])
    assert len(lines) == 1
    return lines[0]


def parse_one(helper, root, name, language, text):
    path = root / name
    path.write_bytes(text.encode("utf-8"))
    return parse_file(helper, root, path, language)


def test_probe(helper):
    out = subprocess.run([helper, "probe"], capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == {"ok": True, "schema": 1}


def test_csharp_controller_ir(helper, tmp_path):
    ir = parse_one(helper, tmp_path, "HomeController.cs", "cs",
        '﻿using System.Web.Mvc;\nnamespace A {\n[Authorize]\npublic class HomeController : Controller {\n'
        '  [HttpPost, ValidateAntiForgeryToken]\n  public ActionResult Save(int id) { var s = "x" + id; return View(); }\n}}\n')
    assert ir["path"] == "HomeController.cs" and ir["language"] == "cs" and ir["project"] == "p"
    assert ir["parse_errors"] == 0
    t = ir["types"][0]
    assert (t["name"], t["namespace"], t["bases"]) == ("HomeController", "A", ["Controller"])
    assert [a["name"] for a in t["attributes"]] == ["Authorize"]
    m = t["methods"][0]
    assert [a["name"] for a in m["attributes"]] == ["HttpPost", "ValidateAntiForgeryToken"]
    assert m["line"] == 6 and m["params"][0] == {"name": "id", "type": "int", "attributes": []}
    assert m["body"][0]["k"] == "local" and m["body"][0]["init"]["op"] == "+"


def test_vb_codebehind_ir(helper, tmp_path):
    src = ('Partial Class _Default\n    Inherits System.Web.UI.Page\n'
           '    Protected Sub btnGo_Click(sender As Object, e As EventArgs) Handles btnGo.Click\n'
           '        Dim sql As String = "SELECT * FROM T WHERE N = \'" & _\n            txtName.Text & "\'"\n'
           '        Dim s = "caf\xe9"\n    End Sub\nEnd Class\n')
    path = tmp_path / "Default.aspx.vb"; path.write_bytes(src.encode("cp1252"))
    ir = parse_file(helper, tmp_path, path, "vb")
    t = ir["types"][0]
    assert t["bases"] == ["Page"]
    m = t["methods"][0]
    assert m["handles"] == ["btnGo.Click"] and m["modifiers"] == ["protected"]
    init = m["body"][0]["init"]
    assert init["op"] == "concat" and m["body"][0]["line"] == 4
    assert m["body"][1]["init"]["v"] == "café"


def test_bad_file_does_not_lose_others(helper, tmp_path):
    good = tmp_path / "A.cs"; good.write_text("class A {}")
    missing = tmp_path / "Missing.cs"
    lines = run_parse(helper, tmp_path, [("p", "cs", [missing, good])])
    assert "error" in lines[0] and lines[1]["types"][0]["name"] == "A"


# -- beyond the brief: pin the rest of the schema that later tasks consume --

def test_csharp_schema_details(helper, tmp_path):
    src = (
        'namespace N.M {\n'
        'public class Outer : Base, IFoo {\n'
        '  private const string K = "k";\n'
        '  [Required] public string Name { get; set; }\n'
        '  public Outer() : base() { }\n'
        '  [Route("a/{id}", Name = "r")]\n'
        '  public static async Task<int> Go(string q, [FromBody] Dto d) {\n'
        '    q += "x";\n'
        '    if (q == null) { throw new ArgumentException("bad"); } else { Run(this.x[0]); }\n'
        '    foreach (var i in items) { Do(i); }\n'
        '    try { using (var c = new SqlConnection(cs)) { c.Open(); } }\n'
        '    catch (Exception ex) { Log(ex); } finally { Done(); }\n'
        '    var s = $"a{q}b";\n'
        '    var o = new Dto { A = 1 };\n'
        '    Func<int> f = () => 1;\n'
        '    return (int)(q != null ? 1 : 0);\n'
        '  }\n'
        '  class Inner { }\n'
        '}\n'
        'enum E { A }\n'
        '}\n')
    (tmp_path / "sub").mkdir()
    ir = parse_one(helper, tmp_path, "sub/Outer.cs", "cs", src)
    assert ir["path"] == "sub/Outer.cs"
    by_name = {t["name"]: t for t in ir["types"]}
    assert set(by_name) == {"Outer", "Outer.Inner", "E"}
    outer = by_name["Outer"]
    assert outer["namespace"] == "N.M" and outer["bases"] == ["Base", "IFoo"]
    assert by_name["Outer.Inner"]["namespace"] == "N.M" and by_name["E"]["kind"] == "enum"
    assert outer["fields"][0] == {"name": "K", "type": "string", "line": 3,
                                  "init": {"k": "lit", "v": "k", "t": "string", "line": 3},
                                  "is_const": True}
    prop = outer["properties"][0]
    assert prop["name"] == "Name" and prop["attributes"][0]["name"] == "Required"
    ctor, go = outer["methods"]
    assert ctor["name"] == ".ctor"
    assert go["modifiers"] == ["public", "static", "async"] and go["return_type"] == "Task<int>"
    route = go["attributes"][0]
    assert route["args"][0]["v"] == "a/{id}" and route["named"]["Name"]["v"] == "r"
    assert go["params"][1]["attributes"][0]["name"] == "FromBody"
    kinds = [s["k"] for s in go["body"]]
    assert kinds == ["assign", "if", "loop", "try", "local", "local", "local", "return"]
    assert go["body"][0]["op"] == "+="
    iff = go["body"][1]
    assert iff["then"][0]["k"] == "throw" and iff["then"][0]["value"]["k"] == "new"
    call = iff["else"][0]["expr"]
    assert call["k"] == "call" and call["args"][0]["k"] == "index"
    assert call["args"][0]["obj"]["obj"] == {"k": "name", "id": "this", "line": 9}
    tr = go["body"][3]
    assert tr["body"][0]["k"] == "using" and tr["body"][0]["resource"][0]["k"] == "local"
    assert tr["catches"][0]["type"] == "Exception" and tr["catches"][0]["name"] == "ex"
    assert tr["finally"][0]["k"] == "expr"
    assert go["body"][4]["init"]["k"] == "interp"
    assert [p["k"] for p in go["body"][4]["init"]["parts"]] == ["lit", "name", "lit"]
    assert go["body"][5]["init"]["init"][0]["name"] == "A"
    assert go["body"][6]["init"]["k"] == "lambda"
    ret = go["body"][7]["value"]
    assert ret["k"] == "cast" and ret["type"] == "int"


def test_vb_modifiers_and_module(helper, tmp_path):
    src = ('Namespace App\n'
           'Public MustInherit Class Base\n'
           '    Protected Friend Overridable Function F() As Integer\n'
           '        Return 1\n'
           '    End Function\n'
           '    Public Shared Sub S()\n'
           '        Dim x = Me.Foo(1)\n'
           '        x &= "a"\n'
           '        For Each r In rows\n'
           '            Use(r)\n'
           '        Next\n'
           '        With cmd\n'
           '            .Execute()\n'
           '        End With\n'
           '    End Sub\n'
           'End Class\n'
           'Module Util\n'
           'End Module\n'
           'End Namespace\n')
    ir = parse_one(helper, tmp_path, "Base.vb", "vb", src)
    base, util = ir["types"]
    assert base["namespace"] == "App" and base["modifiers"] == ["public", "abstract"]
    assert util["kind"] == "module"
    f, s = base["methods"]
    assert f["modifiers"] == ["protected internal", "virtual"] and f["return_type"] == "Integer"
    assert s["modifiers"] == ["public", "static"]
    local, assign, loop, with_ = s["body"]
    assert local["init"]["k"] == "call" and local["init"]["fn"]["obj"]["id"] == "this"
    assert assign["op"] == "concat="
    assert loop["k"] == "loop" and loop["body"][0]["k"] == "expr"
    assert with_["k"] == "with" and with_["target"]["id"] == "cmd"


# -- fix round 1: depth-cap fallbacks must not drop code; VB ?. lowering --

def _json_depth(o):
    if isinstance(o, dict):
        return 1 + max([_json_depth(v) for v in o.values()] + [0])
    if isinstance(o, list):
        return 1 + max([_json_depth(v) for v in o] + [0])
    return 0


def test_vb_elseif_chain_past_cap_keeps_later_arms(helper, tmp_path):
    arms = "".join(f"        ElseIf a = {i} Then\n            X({i})\n" for i in range(1, 200))
    src = ("Module M\n    Sub S()\n        If a = 0 Then\n            X(0)\n" + arms +
           "        Else\n            Sink(Request(\"q\"))\n        End If\n        After()\n"
           "    End Sub\nEnd Module\n")
    ir = parse_one(helper, tmp_path, "Chain.vb", "vb", src)
    assert "error" not in ir
    body = ir["types"][0]["methods"][0]["body"]
    dumped = json.dumps(body)
    assert "a = 199" in dumped and 'Sink(Request(\\"q\\"))' in dumped
    assert body[-1]["k"] == "expr" and body[-1]["expr"]["fn"]["id"] == "After"


def test_csharp_using_var_chain_past_cap_keeps_rest_of_block(helper, tmp_path):
    usings = "".join(f"    using var c{i} = Open({i});\n" for i in range(400))
    src = "class C {\n  void M() {\n" + usings + "    Sink(Request[\"q\"]);\n  }\n}\n"
    ir = parse_one(helper, tmp_path, "Using.cs", "cs", src)
    assert "error" not in ir
    dumped = json.dumps(ir)
    assert "c399" in dumped and 'Sink(Request[\\"q\\"])' in dumped


def test_json_depth_bounded_for_try_and_new_init_nesting(helper, tmp_path):
    inner = "x"
    for _ in range(300):
        inner = f"new A {{ X = {inner} }}"
    stmt = f"var v = {inner};"
    for _ in range(200):
        stmt = f"try {{ T(); }} catch (Exception e) {{ {stmt} }}"
    src = "class C { void M() { " + stmt + " } }\n"
    ir = parse_one(helper, tmp_path, "Deep.cs", "cs", src)
    assert "error" not in ir
    assert _json_depth(ir) <= 420


def test_vb_conditional_access(helper, tmp_path):
    src = ('Module M\n    Sub S()\n'
           '        Dim n = Request?.QueryString("q")\n'
           '        Dim c = a?.b?.c\n'
           '        With cmd\n'
           '            x = a?.Foo(.Bar)\n'
           '        End With\n'
           '    End Sub\nEnd Module\n')
    ir = parse_one(helper, tmp_path, "Ca.vb", "vb", src)
    n, c, with_ = ir["types"][0]["methods"][0]["body"]
    call = n["init"]
    assert call["k"] == "call" and call["fn"]["name"] == "QueryString"
    assert call["fn"]["obj"]["id"] == "Request" and call["args"][0]["v"] == "q"
    m = c["init"]
    assert (m["k"], m["name"], m["obj"]["name"], m["obj"]["obj"]["id"]) == ("member", "c", "b", "a")
    foo = with_["body"][0]["value"]
    assert foo["fn"]["obj"]["id"] == "a" and foo["args"][0]["obj"] is None


# -- Task 5: semantic symbols against .NET Framework 4.8 reference assemblies --

def test_semantic_symbols(helper, tmp_path):
    ir = parse_one(helper, tmp_path, "D.cs", "cs",
        'using System.Data.SqlClient;\nclass D { void Q(string n) {\n'
        '  var cmd = new SqlCommand("SELECT 1");\n  cmd.ExecuteReader();\n} }\n')
    body = ir["types"][0]["methods"][0]["body"]
    assert body[0]["type_full"] == "System.Data.SqlClient.SqlCommand"
    assert body[1]["expr"]["sym"] == "System.Data.SqlClient.SqlCommand.ExecuteReader"


def test_vb_semantic_symbols(helper, tmp_path):
    ir = parse_one(helper, tmp_path, "D.vb", "vb",
        'Imports System.Data.SqlClient\nModule D\n  Sub Q()\n    Dim cmd As New SqlCommand("x")\n'
        '    cmd.ExecuteNonQuery()\n  End Sub\nEnd Module\n')
    body = ir["types"][0]["methods"][0]["body"]
    assert body[1]["expr"]["sym"] == "System.Data.SqlClient.SqlCommand.ExecuteNonQuery"


def test_reference_assemblies_published_next_to_helper(helper):
    from pathlib import Path
    refs = Path(helper).parent / "refs" / "net48"
    names = {p.name.lower() for p in refs.glob("*.dll")}
    assert {"mscorlib.dll", "system.data.dll", "system.web.dll", "netstandard.dll"} <= names


def test_semantic_details_cs(helper, tmp_path):
    ir = parse_one(helper, tmp_path, "E.cs", "cs",
        'using System.Web;\nusing Acme.Missing;\nclass E { void Q(HttpRequest r) {\n'
        '  var s = r.QueryString["q"];\n'            # member on a framework type
        '  var w = new Widget();\n'                  # third-party: unresolved
        '  w.Run(s);\n'
        '  var sb = new System.Text.StringBuilder();\n'
        '} }\n')
    body = ir["types"][0]["methods"][0]["body"]
    qs = body[0]["init"]["obj"]
    assert qs["k"] == "member" and qs["sym"] == "System.Web.HttpRequest.QueryString"
    assert body[0]["type_full"] == "System.String"  # the indexer result, not the collection
    assert "type_full" not in body[1] and "type_full" not in body[1]["init"]
    assert "sym" not in body[2]["expr"] and "sym" not in body[2]["expr"]["fn"]
    assert body[3]["init"]["type_full"] == "System.Text.StringBuilder"
    assert body[3]["type_full"] == "System.Text.StringBuilder"
    assert ir["types"][0]["methods"][0]["params"][0]["type"] == "HttpRequest"


def test_vb_inferred_local_and_new(helper, tmp_path):
    ir = parse_one(helper, tmp_path, "F.vb", "vb",
        'Imports System.Data.SqlClient\nModule F\n  Sub Q()\n'
        '    Dim cn = New SqlConnection("x")\n    Dim cmd As New SqlCommand("y", cn)\n'
        '    Dim t As String = cmd.CommandText\n  End Sub\nEnd Module\n')
    body = ir["types"][0]["methods"][0]["body"]
    assert body[0]["type_full"] == "System.Data.SqlClient.SqlConnection"
    assert body[0]["init"]["type_full"] == "System.Data.SqlClient.SqlConnection"
    assert body[1]["type_full"] == "System.Data.SqlClient.SqlCommand"
    assert body[2]["type_full"] == "System.String"
    assert body[2]["init"]["sym"] == "System.Data.SqlClient.SqlCommand.CommandText"


def test_one_compilation_per_project_resolves_across_files(helper, tmp_path):
    (tmp_path / "Repo.cs").write_text(
        "namespace App { public class Repo { public void Find(string q) {} } }\n")
    (tmp_path / "Use.cs").write_text(
        "namespace App { class Use { void M() { new Repo().Find(\"x\"); } } }\n")
    (tmp_path / "Other.cs").write_text(
        "namespace App { class Other { void M() { new Repo().Find(\"x\"); } } }\n")
    lines = run_parse(helper, tmp_path, [("a", "cs", ["Repo.cs", "Use.cs"]),
                                         ("b", "cs", ["Other.cs"])])
    by_path = {ir["path"]: ir for ir in lines}
    call = by_path["Use.cs"]["types"][0]["methods"][0]["body"][0]["expr"]
    assert call["sym"] == "App.Repo.Find" and call["fn"]["obj"]["type_full"] == "App.Repo"
    # Project b does not contain Repo.cs: no cross-project resolution.
    other = by_path["Other.cs"]["types"][0]["methods"][0]["body"][0]["expr"]
    assert "sym" not in other


def test_semantic_with_bad_file_in_project(helper, tmp_path):
    (tmp_path / "A.cs").write_text(
        "class A { void M() { var sb = new System.Text.StringBuilder(); } }\n")
    lines = run_parse(helper, tmp_path, [("p", "cs", ["Missing.cs", "A.cs", "Gone.cs"])])
    assert [ir["path"] for ir in lines] == ["Missing.cs", "A.cs", "Gone.cs"]
    assert "error" in lines[0] and "error" in lines[2]
    assert lines[1]["types"][0]["methods"][0]["body"][0]["type_full"] == "System.Text.StringBuilder"


def test_semantic_edge_shapes(helper, tmp_path):
    cs = parse_one(helper, tmp_path, "G.cs", "cs",
        'using System.Linq;\nclass G { void M(string[] a, System.Text.StringBuilder sb) {\n'
        '  var n = a.Count();\n  var l = sb?.Length;\n  var arr = new string[2];\n} }\n')
    body = cs["types"][0]["methods"][0]["body"]
    assert body[0]["init"]["sym"] == "System.Linq.Enumerable.Count"
    assert body[1]["init"]["sym"] == "System.Text.StringBuilder.Length"
    assert body[2]["type_full"] == "System.String[]"
    # VB: project-level default imports (System.Data) apply without an Imports line.
    vb = parse_one(helper, tmp_path, "G.vb", "vb",
        'Module G\n  Sub M()\n    Dim t = New DataTable()\n    Dim a(3) As String\n  End Sub\nEnd Module\n')
    vbody = vb["types"][0]["methods"][0]["body"]
    assert vbody[0]["type_full"] == "System.Data.DataTable"
    assert vbody[1]["type_full"] == "System.String[]"


def test_probe_fails_without_reference_assemblies(roslyn_helper, tmp_path):
    """A publish missing refs/net48 must not look healthy (ruling R10)."""
    src = Path(roslyn_helper).parent
    dst = tmp_path / "bin"
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("refs"))
    proc = subprocess.run([str(dst / Path(roslyn_helper).name), "probe"],
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "no reference assemblies" in proc.stderr
    assert proc.stdout.strip() == ""


def test_unary_ir(roslyn_helper, tmp_path):
    ir = parse_one(roslyn_helper, tmp_path, "U.cs", "cs", "class U { bool F(bool b, int i) { i++; return !b; } }")
    body = ir["types"][0]["methods"][0]["body"]
    assert body[0]["expr"] == {"k": "unary", "op": "++", "e": {"k": "name", "id": "i", "line": 1}, "line": 1}
    assert body[1]["value"]["k"] == "unary" and body[1]["value"]["op"] == "!"


def test_vb_not_unary(roslyn_helper, tmp_path):
    ir = parse_one(roslyn_helper, tmp_path, "U.vb", "vb", "Module U\n Function F(b As Boolean) As Boolean\n  Return Not b\n End Function\nEnd Module\n")
    assert ir["types"][0]["methods"][0]["body"][0]["value"]["op"] == "Not"


def test_property_accessor_bodies(roslyn_helper, tmp_path):
    ir = parse_one(roslyn_helper, tmp_path, "P.cs", "cs",
        "class P { string _q; public string Q { get { return _q; } set { _q = value; } } public int A { get; set; } public int B => 1; }")
    props = {p["name"]: p for p in ir["types"][0]["properties"]}
    assert props["Q"]["get"][0]["k"] == "return" and props["Q"]["set"][0]["value"] == {"k": "name", "id": "value", "line": 1}
    assert "get" not in props["A"] and "set" not in props["A"]
    assert props["B"]["get"][0]["k"] == "return" and "set" not in props["B"]


def test_vb_property_accessor_bodies(roslyn_helper, tmp_path):
    ir = parse_one(roslyn_helper, tmp_path, "P.vb", "vb",
        "Class P\n Private _q As String\n Public Property Q As String\n  Get\n   Return _q\n  End Get\n  Set(v As String)\n   _q = v\n  End Set\n End Property\n Public Property A As Integer\nEnd Class\n")
    props = {p["name"]: p for p in ir["types"][0]["properties"]}
    assert props["Q"]["get"][0]["k"] == "return"
    assert props["Q"]["set"][0]["value"]["id"] == "v"
    assert "get" not in props["A"] and "set" not in props["A"]


def test_index_and_name_sym(roslyn_helper, tmp_path):
    ir = parse_one(roslyn_helper, tmp_path, "W.cs", "cs",
        "using System.Web; class W { HttpRequest r; string F(string s) { return r.QueryString[\"q\"] + r + s; } }")
    ret = ir["types"][0]["methods"][0]["body"][0]["value"]
    inner = ret["l"]
    assert inner["l"]["k"] == "index" and inner["l"]["sym"] == "System.Collections.Specialized.NameValueCollection.Item"
    assert inner["r"]["sym"] == "W.r"
    assert "sym" not in ret["r"]  # parameter


def test_vb_name_sym(roslyn_helper, tmp_path):
    ir = parse_one(roslyn_helper, tmp_path, "N.vb", "vb",
        "Class N\n Private t As String\n Function F(s As String) As String\n  Dim l = s\n  Return t & s & l\n End Function\nEnd Class\n")
    v = ir["types"][0]["methods"][0]["body"][1]["value"]
    assert v["l"]["l"]["sym"] == "N.t"
    assert "sym" not in v["l"]["r"] and "sym" not in v["r"]


def test_vb_project_imports(roslyn_helper, tmp_path):
    src = tmp_path / "I.vb"; src.write_text("Module I\n Function F() As Object\n  Return New SqlCommand(\"x\")\n End Function\nEnd Module\n")
    lines = run_parse(roslyn_helper, tmp_path, [("p", "vb", [src])], imports={"p": ["System.Data.SqlClient"]})
    assert lines[0]["types"][0]["methods"][0]["body"][0]["value"]["type_full"] == "System.Data.SqlClient.SqlCommand"


def test_param_modifiers_and_vb_set_param(roslyn_helper, tmp_path):
    cs = parse_one(roslyn_helper, tmp_path, "E.cs", "cs",
        "static class E { public static void F(this string s, params object[] a) {} public static void G(int x, ref int y) {} }")
    ms = {m["name"]: m for m in cs["types"][0]["methods"]}
    assert ms["F"]["params"][0]["modifiers"] == ["this"] and ms["F"]["params"][1]["modifiers"] == ["params"]
    assert "modifiers" not in ms["G"]["params"][0] and ms["G"]["params"][1]["modifiers"] == ["ref"]
    vb = parse_one(roslyn_helper, tmp_path, "E.vb", "vb",
        "Class E\n Sub F(ParamArray a As Object(), Optional b As Integer = 1)\n End Sub\n"
        " Private _q As String\n Public Property Q As String\n  Get\n   Return _q\n  End Get\n  Set(v As String)\n   _q = v\n  End Set\n End Property\nEnd Class\n")
    f = vb["types"][0]["methods"][0]
    assert f["params"][0]["modifiers"] == ["paramarray"] and f["params"][1]["modifiers"] == ["optional"]
    assert vb["types"][0]["properties"][0]["set_param"] == "v"


def test_implements_clause_ir(helper, tmp_path):
    vb = tmp_path / "S.vb"
    vb.write_text("Public Class S\n    Implements IFoo\n"
                  "    Public Function Lookup(a As String) As String Implements IFoo.Find, IBar.Find\n"
                  "        Return a\n    End Function\n    Public Sub Plain()\n    End Sub\nEnd Class\n")
    cs = tmp_path / "S.cs"
    cs.write_text("class S : IFoo { string IFoo.Find(string a) { return a; } public void Plain() {} }")
    for path, lang in ((vb, "vb"), (cs, "cs")):
        ir = parse_file(helper, tmp_path, path, lang)
        ms = {m["name"]: m for m in ir["types"][0]["methods"]}
        assert ms["Plain"]["implements"] == []
        got = ms["Lookup" if lang == "vb" else "Find"]["implements"]
        assert got == (["IFoo.Find", "IBar.Find"] if lang == "vb" else ["IFoo.Find"])


def test_property_initializer_ir(helper, tmp_path):
    cs = parse_one(helper, tmp_path, "P.cs", "cs",
        'public class P {\n  public string A { get; set; } = "x";\n  public int B { get; } = 3;\n  public int C { get; set; }\n}\n')
    props = {p["name"]: p for p in cs["types"][0]["properties"]}
    assert props["A"]["init"]["v"] == "x" and props["B"]["init"]["v"] == 3 and "init" not in props["C"]
    vb = parse_one(helper, tmp_path, "P.vb", "vb",
        'Public Class P\n  Public Property A As String = "x"\n  Public Property B As New System.Text.StringBuilder()\n'
        '  Public Property C As Integer\nEnd Class\n')
    props = {p["name"]: p for p in vb["types"][0]["properties"]}
    assert props["A"]["init"]["v"] == "x" and props["B"]["init"]["k"] == "new" and "init" not in props["C"]


def test_vb_addressof_lowers_to_the_operand(helper, tmp_path):
    vb = parse_one(helper, tmp_path, "A.vb", "vb",
        'Public Class A\n  Sub M()\n    Dim h As System.EventHandler = AddressOf Go\n  End Sub\n  Sub Go(s As Object, e As System.EventArgs)\n  End Sub\nEnd Class\n')
    init = vb["types"][0]["methods"][0]["body"][0]["init"]
    assert init["k"] == "name" and init["id"] == "Go"
