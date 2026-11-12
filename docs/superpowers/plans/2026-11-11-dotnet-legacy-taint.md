# dotnet_legacy Taint Implementation Plan (Plan 2 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Track untrusted input (request values, action parameters, WebForms control values) through C#/VB code, across methods and layers, into dangerous sinks, and report SQL / command / LDAP / XPath / header injection, XSS (code and Razor/ASPX templates), path traversal, open redirect, SSRF, log injection, IDOR and over-posting -- each tagged with OWASP 2025 / 2021 / API 2023.

**Architecture:** The Roslyn helper gains the IR pieces taint needs (unary exprs, property accessor bodies, indexer symbols, VB project imports). A Python taint engine (`checks/dnl/taint.py`) evaluates method bodies over the IR with a value lattice of origins plus per-sink-kind cleansing, driven by data tables of sources, sinks, sanitizers and guards. Method summaries (param -> sink, param -> return) are computed to a fixpoint across the solution, and entry points (MVC/Web API actions, WebForms page methods) seed request taint. Rule modules turn sink hits into findings attached to the route they trace back to.

**Tech Stack:** Python 3.10+, pytest; .NET 8 + Roslyn 4.11.0 (existing helper).

**Spec:** `docs/superpowers/specs/2026-11-11-dotnet-legacy-design.md` (Taint, Templates, Rule catalog sections). Plan 1 (`docs/superpowers/plans/2026-11-11-dotnet-legacy-foundation.md`) is done; its modules are the base.

**Checkpoints:** 2a = Tasks 1-5 (IR additions, engine, SQL injection, end-to-end). 2b = Tasks 6-9 (other sinks, templates/XSS, IDOR/over-posting, wrap-up). Each checkpoint leaves the suite green and the analyzer usable.

## Global Constraints

- Public repo: nothing committed (code, fixtures, tests, README, docs, commit messages) may name a client, engagement, target app, local path or user. Fixtures are synthetic. Scan outputs of real targets go outside the repo.
- Prose and comments use `--`, never em-dashes; comment density like `checks/tf_graph.py`.
- Tests: `.venv\Scripts\python -m pytest -q` from the repo root (Windows) -- baseline 482 passing; must also pass on Linux.
- Helper IR schema stays `1`; all IR changes are additive (new optional keys, one new Expr kind `unary`). Update `tools/roslyn-ir/README.md` for every IR change.
- VB identifiers are case-insensitive everywhere in the taint engine (variables, members, methods, types).
- Every new rule id gets an entry in `core/owasp_web.RULES` and a row in `languages/dotnet_legacy/README.md` (the README test enforces it) in the task that adds it.
- Severity: `high | medium | low | info`; `confidence="REVIEW"` when a human must decide.
- A finding is never emitted for constant-only input. Parameterized queries (constant CommandText + `Parameters.Add*`) never fire.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Branch `feature/dotnet-legacy-taint`.

## Review Focus

1. Mutual recursion and call cycles must terminate (fixpoint cap) and still report sinks reached inside the cycle (test in Task 4).
2. VB variables differing only in case (`Dim Sql`, later `sql &= ...`) are the same variable (test in Task 3).
3. `String.Format`, `String.Concat`, `StringBuilder.Append(...).ToString()`, interpolation and `+=`/`&=` all propagate taint (test in Task 3).
4. A constant `CommandText` with `cmd.Parameters.AddWithValue("@n", userValue)` must not fire, while the same value concatenated into `CommandText` must (test in Task 5).
5. WebForms page fields assigned from `Request`/controls in `Page_Load` and used in a button handler of the same page are tainted (test in Task 4).

---

### Task 1: Helper IR additions

**Files:**
- Modify: `tools/roslyn-ir/src/CSharpLowering.cs`, `VbLowering.cs`, `IrWriter.cs`, `Semantics.cs`, `Program.cs`, `tools/roslyn-ir/README.md`
- Test: `tests/test_dnl_helper_ir.py` (add)

**Interfaces (all additive, schema 1):**
- New Expr kind `unary {op, e}`: C# `!x` -> op `!`, `-x` -> `-`, `++x`/`x++` -> `++`, `--` likewise, `~` -> `~`; VB `Not x` -> `Not`, `-x` -> `-`. (Existing negative-literal folding stays.)
- Prop gains optional `get` and `set` (Stmt lists) when the accessor has a body or expression body (auto-properties omit both). C# `value` / VB setter parameter appear as `name {id: "value"}` / the VB parameter name.
- C# `index` Expr gains optional `sym` (the indexer's containing type + `.Item`, e.g. `System.Collections.Specialized.NameValueCollection.Item`, `System.Web.HttpRequest.Item`).
- `name` Expr gains optional `sym` when it binds to a field or property of a type (containing type + `.` + member), e.g. a WebForms designer field `txtName` -> `MyPage.txtName`; locals and parameters get no `sym`.
- Request project object accepts optional `imports: [str]` (VB only): added to the VB compilation's global imports in addition to the template defaults.

- [ ] **Step 1: Write failing tests**

```python
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
        "class P { string _q; public string Q { get { return _q; } set { _q = value; } } public int A { get; set; } }")
    props = {p["name"]: p for p in ir["types"][0]["properties"]}
    assert props["Q"]["get"][0]["k"] == "return" and props["Q"]["set"][0]["value"] == {"k": "name", "id": "value", "line": 1}
    assert "get" not in props["A"] and "set" not in props["A"]

def test_index_and_name_sym(roslyn_helper, tmp_path):
    ir = parse_one(roslyn_helper, tmp_path, "W.cs", "cs",
        "using System.Web; class W { HttpRequest r; string F() { return r.QueryString[\"q\"] + r; } }")
    ret = ir["types"][0]["methods"][0]["body"][0]["value"]
    assert ret["l"]["k"] == "index" and ret["l"]["sym"] == "System.Collections.Specialized.NameValueCollection.Item"
    assert ret["r"]["sym"] == "W.r"

def test_vb_project_imports(roslyn_helper, tmp_path):
    src = tmp_path / "I.vb"; src.write_text("Module I\n Function F() As Object\n  Return New SqlCommand(\"x\")\n End Function\nEnd Module\n")
    lines = run_parse(roslyn_helper, tmp_path, [("p", "vb", [src])], imports={"p": ["System.Data.SqlClient"]})
    assert lines[0]["types"][0]["methods"][0]["body"][0]["value"]["type_full"] == "System.Data.SqlClient.SqlCommand"
```

(`run_parse` gains an optional `imports` mapping project name -> list, written into the request.)

- [ ] **Step 2: Run** `.venv\Scripts\python -m pytest tests/test_dnl_helper_ir.py -v` -- expected FAIL (no `unary`, no `get`, no `sym` on index/name, imports ignored).
- [ ] **Step 3: Implement** the lowering/semantic changes and README updates.
- [ ] **Step 4: Run** the file then the full suite -- expected PASS.
- [ ] **Step 5: Commit** `git commit -m "roslyn-ir: unary exprs, property accessor bodies, index/name symbols, VB project imports"`

---

### Task 2: IR loader, project imports, taint rule ids

**Files:**
- Modify: `checks/dnl/ir.py` (`PropertyIR.get`, `PropertyIR.set`: `list[dict] | None`), `checks/dnl/project.py` (parse `<Import Include="...">` from `.vbproj` into `Project.imports: list[str]`; `_request` sends `imports` for VB projects), `core/owasp_web.py` (new RULES rows below), `languages/dotnet_legacy/README.md` (rows for the new ids, marked "Plan 2" in a status column or note)
- Test: `tests/test_dnl_project.py`, `tests/test_owasp_web.py` (add)

**New rule ids (2025 / 2021 / API, mode api_surface unless noted):**

| id | sev | 2025 | 2021 | API |
|---|---|---|---|---|
| DNL-INJ-001 SQL injection | high | A05 | A03 | API8 |
| DNL-INJ-002 command injection | high | A05 | A03 | API8 |
| DNL-INJ-003 LDAP injection | high | A05 | A03 | API8 |
| DNL-INJ-004 XPath injection | medium | A05 | A03 | API8 |
| DNL-INJ-005 HTTP header injection | medium | A05 | A03 | API8 |
| DNL-INJ-006 Dynamic LINQ injection | high | A05 | A03 | API8 |
| DNL-XSS-001 XSS via code sink | high | A05 | A03 | -- |
| DNL-XSS-003 XSS via Razor/ASPX output | high | A05 | A03 | -- |
| DNL-XSS-004 request validation bypassed in code | medium | A05 | A03 | -- |
| DNL-PATH-001 path traversal | high | A01 | A01 | -- |
| DNL-REDIR-001 open redirect | medium | A01 | A01 | -- |
| DNL-SSRF-001 SSRF | high | A01 | A10 | API7 |
| DNL-LOG-001 log injection | low | A09 | A09 | -- |
| DNL-AUTHZ-005 object-level authz (IDOR) | medium | A01 | A01 | API1 |
| DNL-AUTHZ-006 over-posting (entity bound from request) | medium | A06 | A04 | API3 |
| DNL-AUTHZ-007 entity returned from API (over-exposure) | low | A06 | A04 | API3 |

- [ ] **Step 1: Failing tests**

```python
def test_property_bodies_loaded(model_with_props):  # small fixture class with a non-auto property
    p = next(p for t in model_with_props.types() for p in t.properties if p.name == "Q")
    assert p.get and p.get[0]["k"] == "return" and p.set is not None

def test_vbproj_imports_parsed(mvc_vb_project):  # MvcVb fixture gains <Import Include="System.Data.SqlClient" />
    assert "System.Data.SqlClient" in mvc_vb_project.imports

def test_taint_rule_ids_tagged():
    from core.owasp_web import owasp_for
    assert owasp_for("DNL-SSRF-001", api_surface=True) == {"2025": "A01:2025 Broken Access Control",
        "2021": "A10:2021 Server-Side Request Forgery", "api2023": "API7:2023 Server Side Request Forgery"}
    assert owasp_for("DNL-AUTHZ-005", api_surface=True)["api2023"].startswith("API1:2023")
```

- [ ] **Step 2: Run**, expected FAIL. **Step 3: Implement.** **Step 4: Run** file + full suite, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: load accessor bodies, VB project imports, taint rule ids"`

---

### Task 3: Taint engine core (intra-procedural)

**Files:**
- Create: `checks/dnl/taint.py`, `checks/dnl/taint_tables.py`
- Create fixture: `tests/fixtures/dotnet_legacy/taint_app/` -- legacy C# project `TaintCs/TaintCs.csproj` (refs System.Web, System.Web.Mvc, System.Data) and VB project `TaintVb/TaintVb.vbproj`, each with small classes exercising the cases in the tests below (add files to the project `<Compile Include>` lists).
- Test: `tests/test_dnl_taint.py`

**Interfaces:**
- `taint.Origin(kind: str, detail: str, file: str, line: int)` -- frozen dataclass; `kind` in `{"source", "param", "field"}`; for `param` the `detail` is the param index as string.
- `taint.Taint(origins: frozenset[Origin], cleansed: frozenset[str])` -- frozen; `cleansed` holds sink kinds the value is safe for (`"*"` = all). Helpers: `merge(a, b)` (union origins, intersect cleansed; None-safe), `cleanse(t, kinds)`.
- `taint.SinkHit(kind: str, sink: str, file: str, line: int, taint: Taint, method: str)` (`sink` = matched table entry name, `method` = `Type.Method`).
- `taint.MethodResult(hits: list[SinkHit], ret: Taint | None, param_to_ret: frozenset[int])`.
- `taint.analyze_method(model, t: TypeIR, m: MethodIR, *, param_taint: dict[int, Taint] | None = None, field_taint: dict[str, Taint] | None = None, summaries: dict | None = None) -> MethodResult` -- `summaries` is consumed in Task 4 (pass None here: calls to project methods then propagate argument taint to the return value conservatively, and record no inner sinks).
- `taint_tables.py` -- plain data, each entry a small dataclass:
  - `SOURCES`: (name, sym regex, text regex fallback). Request collections and members on `System.Web.HttpRequest`/`HttpRequestBase`/`HttpRequestWrapper` (`QueryString`, `Form`, `Params`, `Cookies`, `Headers`, `ServerVariables`, `RawUrl`, `Url`, `UrlReferrer`, `Files`, `InputStream`, `Item`/indexer, `Unvalidated`), `RouteData.Values`, WebForms `TextBox.Text`, `HiddenField.Value`, `ListControl.SelectedValue`/`SelectedItem`, `HtmlInputText.Value`. Text fallback when `sym` is absent: receiver text matches `(?i)^((this|me)\.)?((httpcontext\.current|context|page)\.)?request(\.(querystring|form|params|cookies|headers|servervariables|rawurl|url|files|unvalidated))?$` used as call/index receiver, or a member `.Text`/`.Value`/`.SelectedValue` on a field whose declared type simple name is `TextBox|HiddenField|DropDownList|ListBox|RadioButtonList|HtmlInputText|HtmlInputHidden`.
  - `SINKS`: (kind, name, match by sym regex or (receiver type simple-name regex + member name), what is checked: `arg:N` or `assign`). Kinds: `sql`, `linq`, `cmd`, `ldap`, `xpath`, `header`, `xss`, `path`, `redirect`, `ssrf`, `log`. Entries (C# and VB names, sym-first, type-name fallback from local `type_full`/declared type):
    - sql: `SqlCommand|OleDbCommand|OdbcCommand|OracleCommand|DbCommand|IDbCommand` `.ctor` arg 0 and `CommandText` assign; `SqlDataAdapter|OleDbDataAdapter|OracleDataAdapter` `.ctor` arg 0; `System.Data.Entity.Database.SqlQuery|ExecuteSqlCommand|ExecuteSqlCommandAsync` arg 0; `DbSet.SqlQuery` arg 0.
    - linq: `System.Linq.Dynamic(.Core)?.DynamicQueryable(Extensions)?.(Where|OrderBy|Select|GroupBy)` string arg (arg 1 for extension form, arg 0 when called on the receiver).
    - cmd: `System.Diagnostics.Process.Start` arg 0/1; `ProcessStartInfo` `.ctor` arg 0/1, `FileName`/`Arguments` assign.
    - ldap: `DirectorySearcher.Filter` assign, `DirectorySearcher..ctor` arg 0 (string) / arg 1; `DirectoryEntry..ctor` arg 0.
    - xpath: `XmlNode.SelectNodes|SelectSingleNode` arg 0; `XPathNavigator.Select|Evaluate|SelectSingleNode` arg 0; `XPathExpression.Compile` arg 0.
    - header: `HttpResponse(Base)?.(AddHeader|AppendHeader)` arg 1; `HttpCookie..ctor` arg 1, `HttpCookie.Value` assign.
    - xss: `HttpResponse(Base)?.Write` arg 0; `Literal.Text`, `Label.Text`, `HtmlGenericControl.InnerHtml`, `HtmlContainerControl.InnerHtml` assign; `HtmlString..ctor` arg 0; `MvcHtmlString.Create` arg 0; `HtmlHelper.Raw` arg 0; `Controller.Content` arg 0.
    - path: `System.IO.File.(ReadAllText|ReadAllBytes|ReadAllLines|WriteAllText|WriteAllBytes|AppendAllText|Open|OpenRead|OpenWrite|OpenText|Delete|Copy|Move)` arg 0 (and arg 1 for Copy/Move); `FileStream|StreamReader|StreamWriter|FileInfo..ctor` arg 0 when string; `HttpServerUtility(Base)?.MapPath` arg 0; `HttpResponse(Base)?.(WriteFile|TransmitFile)` arg 0; `Controller.File` arg 0 when its static type is string; `Directory.(GetFiles|Delete|CreateDirectory)` arg 0.
    - redirect: `HttpResponse(Base)?.(Redirect|RedirectPermanent)` arg 0; `Controller.Redirect|RedirectPermanent` arg 0; `RedirectResult..ctor` arg 0; `ApiController.Redirect` arg 0.
    - ssrf: `WebClient.(DownloadString|DownloadData|DownloadFile|OpenRead|UploadString|UploadData|UploadValues)` arg 0; `WebRequest.Create|HttpWebRequest.Create|WebRequest.CreateHttp` arg 0; `HttpClient.(GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsync|PutAsync|DeleteAsync|SendAsync)` arg 0; `RestClient..ctor` arg 0, `RestRequest..ctor` arg 0, `RestClient.BaseUrl` assign.
    - log: log4net `ILog.(Debug|Info|Warn|Error|Fatal|DebugFormat|InfoFormat|WarnFormat|ErrorFormat|FatalFormat)` arg 0; `System.Diagnostics.Trace.(Write|WriteLine|TraceInformation|TraceWarning|TraceError)` arg 0.
  - `SANITIZERS`: call -> cleansed kinds. `*`: `int/long/short/decimal/double/Guid/DateTime/bool .Parse|TryParse`, `Convert.To(Int16|Int32|Int64|Decimal|Double|Boolean|DateTime)`, VB `CInt|CLng|CDbl|CDec|CBool|CDate|Val`, `.Count`/`.Length` members. `xss`: `HttpUtility.HtmlEncode|HtmlAttributeEncode|JavaScriptStringEncode`, `HttpServerUtility.HtmlEncode`, `WebUtility.HtmlEncode`, `AntiXssEncoder.*Encode`, `Encoder.HtmlEncode`. `path`: `Path.GetFileName`. `ldap`: any method whose name matches `(?i)ldap.*(escape|encode)`. `header`, `log`: `.Replace("\r", ...)`/`Replace("\n", ...)` chains removing CR or LF (match a `Replace` call whose first arg literal contains `\r` or `\n` or `vbCr`/`vbLf`/`vbCrLf`/`Environment.NewLine`). `redirect`: `HttpUtility.UrlEncode` does NOT cleanse redirect (it does not stop off-site URLs).
  - `GUARDS`: an `if` condition that calls `Url.IsLocalUrl(x)` (or `UrlHelper.IsLocalUrl`) cleanses `redirect` for `x` in the then-branch; `<collection>.Contains(x)` / `Array.IndexOf(arr, x) >= 0` / `Regex.IsMatch(x, "^...$")` with an anchored literal pattern cleanse `*` for `x` in the then-branch; `full.StartsWith(base)` where `full` came from `Path.GetFullPath(...)` cleanses `path` for `full` in the then-branch.
- Evaluation semantics (pinned): statements in order; `local`/`assign` bind the evaluated value (VB names lower-cased); `+=`/`concat=` merge with the old value; `if` evaluates both branches from a copy of the env and merges (guards applied to the then-branch); loops run the body twice; `try` merges body, catches and finally; `using` evaluates the resource then the body; `with` binds the target for `member {obj: null}`. Expr values: literals/numbers -> None; `bin` -> merge of operands (comparison/boolean ops -> None); `interp` -> merge of parts; `cond` -> merge of branches; `cast` to a numeric/bool/Guid/DateTime type -> cleansed `*`; `new` of a sink type records sink hits on its args, otherwise merges args; `member` -> source check, else the receiver's value (property reads on a tainted object stay tainted); `index`/VB `call` on a tainted receiver -> receiver taint; calls: sanitizer -> cleansed result; string helpers (`String.Format`, `String.Concat`, `String.Join`, `.ToString`, `.Trim*`, `.ToUpper/ToLower`, `.Substring`, `.Replace`, `.PadLeft/PadRight`, `StringBuilder.Append*/Insert/ToString`, `Uri..ctor`, `Path.Combine`) -> merge of receiver and args; `StringBuilder.Append*` also updates the receiver variable's value; out/ref arguments of `TryParse` -> cleansed `*`; other external calls -> None (unknown external methods do not propagate); project methods -> handled per `summaries` (Task 4).
- A sink hit is recorded when the checked argument/assigned value is tainted and its kind is not in `cleansed` and `"*"` is not in `cleansed`.

- [ ] **Step 1: Failing tests** (each builds the model from `taint_app` via the real helper and calls `analyze_method` on a named method with no params tainted unless stated):

```python
def test_request_concat_into_commandtext_hits_sql(m):
    r = analyze(m, "Cs.Orders", "Find")       # cmd.CommandText = "select ... '" + Request.QueryString["q"] + "'"
    assert [(h.kind, h.line) for h in r.hits] == [("sql", line_of(m, "Cs.Orders", "CommandText"))]

def test_string_format_builder_interp_propagate(m):
    for meth in ("ViaFormat", "ViaBuilder", "ViaInterp", "ViaPlusEquals"):
        assert [h.kind for h in analyze(m, "Cs.Props", meth).hits] == ["sql"], meth

def test_int_parse_cleanses(m):
    assert analyze(m, "Cs.Orders", "ByIntId").hits == []

def test_html_encode_cleanses_xss_only(m):
    r = analyze(m, "Cs.Out", "Encoded")       # Response.Write(HttpUtility.HtmlEncode(q)); cmd.CommandText = "..." + HttpUtility.HtmlEncode(q)
    assert [h.kind for h in r.hits] == ["sql"]

def test_vb_case_insensitive_vars(m):
    r = analyze(m, "Vb.Search", "Go")         # Dim Sql = "..." : sql &= txtName.Text : New SqlCommand(SQL, conn)
    assert [h.kind for h in r.hits] == ["sql"]

def test_param_origin_and_return(m):
    r = analyze(m, "Cs.Helpers", "Wrap", param_taint={0: param(0)})   # return "x" + s;
    assert r.param_to_ret == frozenset({0}) and r.hits == []

def test_islocalurl_guard(m):
    assert analyze(m, "Cs.Nav", "Safe").hits == [] and [h.kind for h in analyze(m, "Cs.Nav", "Unsafe").hits] == ["redirect"]

def test_constant_only_never_hits(m):
    assert analyze(m, "Cs.Orders", "Constant").hits == []
```

(`analyze`, `line_of`, `param` are small helpers in the test module; `m` is the module-scoped model fixture.)

- [ ] **Step 2: Run** `python -m pytest tests/test_dnl_taint.py -v`, expected FAIL (module missing).
- [ ] **Step 3: Implement** `taint_tables.py` (data only) and `taint.py`.
- [ ] **Step 4: Run** file + full suite, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: intra-procedural taint engine with source/sink/sanitizer tables"`

---

### Task 4: Inter-procedural summaries, call resolution, entry points

**Files:**
- Modify: `checks/dnl/taint.py`
- Create: `checks/dnl/taint_solver.py`
- Extend fixture `taint_app`: layered flow (controller action -> service via interface -> repository builds SQL), mutual recursion pair, a WebForms page (`Search.aspx` + VB code-behind with designer file declaring `txtName As TextBox`) assigning a field in `Page_Load` and using it in `btnGo_Click`, an interface with two implementations, and a static helper call.
- Test: `tests/test_dnl_taint_solver.py`

**Interfaces:**
- `taint_solver.Summary(param_sinks: dict[int, list[SinkHit]], param_to_ret: frozenset[int], ret_source: Taint | None)`.
- `taint_solver.resolve_call(model, caller_t: TypeIR, call: dict, env_types: dict[str, str]) -> list[tuple[TypeIR, MethodIR]]` -- order: `sym` -> type by full name (+ base chain) and method by name + arg count; else `this`/`base`/implicit receiver -> caller type and its base chain; else receiver local/field/param declared type (from `env_types`, field types, param types) -> that type; if the resolved type is an interface or the method is abstract -> every project type that implements/derives it with that method; else static `Type.Method` by simple type name. Overloads: prefer exact arg count, else all with that name. Case-insensitive for VB.
- `taint_solver.solve(model) -> dict[tuple[str, str, int], Summary]` keyed `(type full name, method name, method line)`; iterates all project methods (legacy projects only) until no summary changes, **max 6 rounds**; recursion is safe because each round reads the previous round's summaries.
- `taint.analyze_method(..., summaries=...)` now: for a project call, resolves targets; each target's `param_sinks[i]` fires as a hit at the target's sink when argument i is tainted (the hit keeps the target's file/line, `method` = target, and records the call chain in `SinkHit.via: tuple[str, ...]` -- add this field, default `()`); result taint = merge over targets of (`ret_source` and args i in `param_to_ret`).
- Fields: before analyzing methods of a type, compute `field_taint` for that type = merge of every value assigned to `this.<field>`/bare field names across all its methods (and property setters) evaluated with request sources only; pass it to every method of the type. Property getters with bodies are evaluated like methods; a read of such a property returns its getter's result.
- `taint_solver.entry_hits(model, refs: list[RouteRef]) -> list[EntryHit]` with `EntryHit(ref: RouteRef | None, hit: SinkHit, sources: list[Origin])`:
  - MVC/Web API action: params tainted as `Origin("source", "request parameter <name>", ...)` except params whose type is numeric/bool/Guid/DateTime/enum-like/`CancellationToken`/`HttpPostedFileBase`(still taints `FileName`... treat `HttpPostedFileBase` as tainted); complex types tainted (member reads stay tainted).
  - WebForms page types (from `discover_webforms` refs with a type): every method of the page type is analyzed with request/control sources active; hits map to that page's ref.
  - A hit whose taint includes a `source` origin -> proven. A hit inside a non-entry method whose taint has only `param` origins, where no caller in the solution passes a tainted argument and the method has no resolved caller at all -> `EntryHit(ref=None, ...)` flagged unproven (used for REVIEW in Task 5); if callers exist but none passes taint -> dropped.
- Results cached on `model.cache["taint"]`.

- [ ] **Step 1: Failing tests**

```python
def test_layered_flow_controller_to_repository(hits):
    h = one_hit(hits, "sql", file_endswith="OrderRepository.cs")
    assert h.ref.route.handler_name == "OrdersController.Search" and h.hit.via[0].startswith("OrdersController.Search")
    assert any(o.detail == "request parameter term" for o in h.sources)

def test_interface_dispatch_reaches_both_impls(hits):
    assert {x.hit.file.rsplit("/", 1)[-1] for x in hits if x.hit.kind == "sql" and "Impl" in x.hit.method} == {"SqlImplA.cs", "SqlImplB.cs"}

def test_mutual_recursion_terminates_and_reports(model):
    sums = solve(model)                    # must return within the round cap
    assert any(h.kind == "sql" for s in sums.values() for hs in s.param_sinks.values() for h in hs)

def test_webforms_field_flow(hits):
    h = one_hit(hits, "sql", file_endswith="Search.aspx.vb")
    assert h.ref.route.path.endswith("/Search.aspx") and h.hit.method.endswith("btnGo_Click")

def test_uncalled_helper_is_unproven(hits):
    u = [x for x in hits if x.ref is None and x.hit.method.endswith("Orphan")]
    assert len(u) == 1 and all(o.kind == "param" for o in u[0].hit.taint.origins)

def test_called_with_constant_is_dropped(hits):
    assert not [x for x in hits if x.hit.method.endswith("OnlyConstCaller")]
```

- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run** file + full suite, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: taint summaries, call resolution, entry points"`

---

### Task 5: SQL / Dynamic LINQ injection rules and analyzer wiring (checkpoint 2a)

**Files:**
- Create: `checks/dnl/rules_taint.py`
- Modify: `languages/dotnet_legacy/analyzers.py` (`_code_results` also runs `rules_taint.check(model, refs)`; findings with a route go to that route's kind, route-less ones via `_owner_kind`), `languages/dotnet_legacy/README.md` (how taint works, what is a proven vs REVIEW finding, limits)
- Test: `tests/test_dnl_rules_taint.py`, extend `tests/test_dnl_end_to_end.py`

**Interfaces:**
- `rules_taint.RULE_FOR_KIND = {"sql": "DNL-INJ-001", "linq": "DNL-INJ-006"}` (Task 6 extends it).
- `rules_taint.check(model, refs) -> list[Finding]` -- one finding per `(rule id, sink file, sink line)`: proven hits -> table severity, no confidence, `route=ref.route`, `api_surface=route.meta["api_surface"]`; unproven -> severity one level lower (high->medium, medium->low, low->info), `confidence="REVIEW"`, no route. Description pinned format: `"<Kind label> -- untrusted input reaches <sink name> (<file>:<line>). Source: <first source detail> (<source file>:<line>)[; +N more]. Path: <via joined by ' -> '>."` For unproven: `"... reaches <sink> from parameter '<name>' of <Type.Method>, and no caller passing untrusted data was found -- verify how it is called."`
- Kind labels: sql `SQL injection`, linq `Dynamic LINQ injection`.

- [ ] **Step 1: Failing tests**

```python
def test_sql_injection_proven_on_route(findings):
    f = one(findings, "DNL-INJ-001", file_endswith="OrderRepository.cs")
    assert f.severity == "high" and f.confidence is None and f.route.handler_name == "OrdersController.Search"
    assert "Source: request parameter term" in f.description and " -> " in f.description

def test_parameterized_query_never_fires(findings):
    assert not hits(findings, "DNL-INJ-001", file_endswith="SafeRepository.cs")   # constant CommandText + Parameters.AddWithValue

def test_unproven_is_review_one_level_lower(findings):
    f = one(findings, "DNL-INJ-001", method_hint="Orphan")
    assert f.severity == "medium" and f.confidence == "REVIEW" and f.route is None

def test_dynamic_linq(findings):
    assert one(findings, "DNL-INJ-006").severity == "high"

def test_end_to_end_taint_app(tmp_path, monkeypatch):
    out = tmp_path / "r.json"
    monkeypatch.setattr(sys, "argv", ["main.py", str(FX / "taint_app"), "--json", str(out)])
    assert main.main() == 0
    inj = [f for r in json.loads(out.read_text()) for f in r["findings"] if f["check_id"] == "DNL-INJ-001"]
    assert inj and all(f["owasp"]["2025"].startswith("A05:2025") for f in inj)
```

- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run** file + full suite, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: SQL and Dynamic LINQ injection findings from taint"`

---

### Task 6: Remaining code-sink rules (start of 2b)

**Files:**
- Modify: `checks/dnl/rules_taint.py` (extend `RULE_FOR_KIND`: cmd `DNL-INJ-002`, ldap `DNL-INJ-003`, xpath `DNL-INJ-004`, header `DNL-INJ-005`, xss `DNL-XSS-001`, path `DNL-PATH-001`, redirect `DNL-REDIR-001`, ssrf `DNL-SSRF-001`, log `DNL-LOG-001`; labels "Command injection", "LDAP injection", "XPath injection", "HTTP header injection", "Cross-site scripting", "Path traversal", "Open redirect", "Server-side request forgery", "Log injection"), README
- Extend fixture `taint_app`: one positive and one sanitized/guarded negative per kind (e.g. `Path.GetFileName` + `Path.Combine(base, ...)`, `Url.IsLocalUrl` guard, CR/LF `Replace` before `AddHeader`, `HtmlEncode` before `Response.Write`, allowlist `Contains` before `Process.Start`).
- Test: `tests/test_dnl_rules_taint.py` (add)

- [ ] **Step 1: Failing tests** -- for each kind: `one(findings, rule_id, method_hint="<Kind>Bad")` exists with the table severity, and `not hits(findings, rule_id, method_hint="<Kind>Good")`; plus `test_ssrf_api_tag` (`owasp["api2023"]` startswith `API7:2023` on a Web API route).
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: command/LDAP/XPath/header/XSS/path/redirect/SSRF/log findings"`

---

### Task 7: Razor/ASPX templates, XSS-003 and XSS-004

**Files:**
- Create: `checks/dnl/templates.py`, `checks/dnl/rules_xss.py`
- Modify: `languages/dotnet_legacy/analyzers.py` (wire `rules_xss.check`), README
- Extend fixture `taint_app`: `Views/Home/Show.cshtml` (`@Html.Raw(ViewBag.Msg)`, `@Html.Raw(Model.Bio)`, `@Model.Name` encoded, `@Html.Raw("<b>x</b>")` literal), `HomeController.Show(string msg)` setting `ViewBag.Msg = msg` and `return View(new Profile { Bio = msg })`, a WebForms `Show.aspx` with `<%= Request.QueryString["q"] %>`, `<%: Request.QueryString["q"] %>` and `<%# Eval("Name") %>`, a model class with `[AllowHtml]` property, an action with `[ValidateInput(false)]`, and a `Request.Unvalidated` read.
- Test: `tests/test_dnl_templates.py`

**Interfaces:**
- `templates.Output(file: str, line: int, expr: str, encoded: bool, kind: str)` -- `kind` in `{"razor_raw", "razor_helper", "aspx_raw", "aspx_encoded", "aspx_bind"}`.
- `templates.scan(path: Path, rel: str) -> list[Output]` -- Razor: `@Html.Raw(<balanced expr>)`, `@(new HtmlString(...))`, `@MvcHtmlString.Create(...)`, `@Html.Raw` inside `@{ }` blocks; plain `@expr`/`@(expr)` are encoded (not returned). ASPX/ASCX/Master: `<%= expr %>` (raw), `<%: expr %>` (encoded, returned with `encoded=True` for completeness), `<%# expr %>` (raw bind unless wrapped in `Server.HtmlEncode`/`HttpUtility.HtmlEncode`/`: `). Balanced-paren scanning respects string literals; line numbers are 1-based.
- `templates.view_for(model, ref: RouteRef) -> Path | None` -- MVC convention: `View()`/`View(model)`/`View("Name", ...)` in the action body -> `Views/<Controller>/<Name or Action>.(cshtml|vbhtml)` under the project dir, then `Views/Shared/`.
- `rules_xss.check(model, refs) -> list[Finding]`:
  - XSS-003 (high, no REVIEW) when a raw output's expr references `Request`/`Request.QueryString`/`Request.Form`/`Request[` directly, or `ViewBag.<X>`/`ViewData["X"]` where the rendering action assigns a tainted value to that key (taint engine on the action body, request-parameter sources), or `Model.<X>` where the action's `View(model)` argument value is tainted (object-level: any tainted member assignment in its initializer or the model expression itself tainted).
  - XSS-003 (medium, REVIEW) for any other raw output with a non-literal expr (unknown provenance).
  - No finding for literal-only raw output or encoded output.
  - XSS-004 (medium; the test helper reads `title_kind` as the text after `"Request validation bypassed: "` in the finding title, so titles are exactly `Request validation bypassed: AllowHtml` / `...: ValidateInput(false)` / `...: Request.Unvalidated`): `[AllowHtml]` on a property of a type bound as an action parameter, `[ValidateInput(false)]` on an action/controller, any read of `Request.Unvalidated`.
  - Findings attach to the route (MVC: the action that renders the view; WebForms: the page) when known.

- [ ] **Step 1: Failing tests**

```python
def test_razor_scan_finds_raw_not_encoded(tmp_path):
    p = tmp_path / "v.cshtml"; p.write_text('<p>@Model.Name</p>\n@Html.Raw(Model.Bio)\n@Html.Raw(fn("a)b"))\n')
    assert [(o.line, o.kind, o.expr) for o in scan(p, "v.cshtml")] == [(2, "razor_raw", "Model.Bio"), (3, "razor_raw", 'fn("a)b")')]

def test_aspx_scan(tmp_path):
    p = tmp_path / "s.aspx"; p.write_text('<%= Request["q"] %>\n<%: Request["q"] %>\n<%# Eval("Name") %>\n')
    assert [(o.line, o.kind, o.encoded) for o in scan(p, "s.aspx")] == [(1, "aspx_raw", False), (2, "aspx_encoded", True), (3, "aspx_bind", False)]
def test_viewbag_link_is_proven(findings):
    f = one(findings, "DNL-XSS-003", file_endswith="Show.cshtml", line_has="ViewBag.Msg")
    assert f.severity == "high" and f.confidence is None and f.route.handler_name == "HomeController.Show"
def test_model_link_is_proven(findings):
    assert one(findings, "DNL-XSS-003", file_endswith="Show.cshtml", line_has="Model.Bio").severity == "high"

def test_literal_raw_ignored(findings):
    assert not hits(findings, "DNL-XSS-003", file_endswith="Show.cshtml", line_has='"<b>x</b>"')

def test_aspx_request_raw_high_encoded_none(findings):
    fs = hits(findings, "DNL-XSS-003", file_endswith="Show.aspx")
    assert [(f.line, f.severity) for f in fs if f.confidence is None] == [(1, "high")]
    assert not [f for f in fs if f.line == 2]

def test_xss_004_variants(findings):
    fs = hits(findings, "DNL-XSS-004")
    assert sorted(f.title_kind for f in fs) == ["AllowHtml", "Request.Unvalidated", "ValidateInput(false)"]
```

- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: Razor/ASPX output scanning, XSS-003/XSS-004"`

---

### Task 8: Object-level authz (IDOR) and over-posting / over-exposure

**Files:**
- Create: `checks/dnl/rules_object.py`
- Modify: `languages/dotnet_legacy/analyzers.py`, README
- Extend fixture `taint_app`: a `DbContext` subclass with `DbSet<Order> Orders`, entity `Order` (`[Key] Id`, `OwnerId`), actions: `Get(int id)` doing `db.Orders.Find(id)` with no user check (positive), `Mine(int id)` comparing `order.OwnerId == User.Identity.GetUserId()` (negative), `Update(Order order)` binding the entity (over-posting positive), `UpdateBound([Bind(Include="Name")] Order order)` (negative), Web API `GetRaw(int id)` returning `Order` (over-exposure positive), one returning a DTO (negative).
- Test: `tests/test_dnl_rules_object.py`

**Interfaces / rules:**
- `rules_object.entity_types(model) -> set[str]` -- simple names of `T` in properties typed `DbSet<T>`/`IDbSet<T>` on types deriving `DbContext`/`ObjectContext`, plus types carrying `[Table]` or a `[Key]` property.
- DNL-AUTHZ-005 (medium, REVIEW): an MVC/Web API action that is protected (or not -- independent of auth) with an id-like parameter (reuse `checks/idor.py` `_is_id_like` semantics) whose value reaches a data access: EF `Find`/`FirstOrDefault`/`SingleOrDefault`/`Where`/`Any` on a `DbSet`, a `sql` sink, or a project method whose summary routes that param to such access; and neither the action body nor the reached methods reference `User.Identity`, `User.IsInRole`, `GetUserId`, `Session[...]` user keys, `HttpContext.Current.User`, `Thread.CurrentPrincipal`, `ClaimsPrincipal` -> finding on the route, `api_surface` per route.
- DNL-AUTHZ-006 (medium): an action parameter whose type is an entity type, without `[Bind(Include=...)]` (or `[Bind(Exclude=...)]`) on that parameter or the entity class, and the action is POST/PUT/PATCH (explicit verb or Web API name prefix) -> finding on the route.
- DNL-AUTHZ-007 (low): a Web API action whose declared return type is an entity type, `IEnumerable<Entity>`/`List<Entity>`/`IQueryable<Entity>`, or returns `Ok(<entity value>)`/`Json(<entity value>)` resolved through the IR -> finding on the route.

- [ ] **Step 1: Failing tests** -- one positive and the negative per rule as listed; `owasp["api2023"]` is `API1:2023 ...` for AUTHZ-005 and `API3:2023 ...` for 006/007 on Web API routes.
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: IDOR, over-posting and over-exposure findings"`

---

### Task 9: Wrap-up -- README, performance guard, Linux run, real-target smoke run

**Files:**
- Modify: `languages/dotnet_legacy/README.md` (taint section: sources, sinks, sanitizers, guards, proven vs REVIEW, depth cap, known limits -- reflection/dynamic, DI container wiring beyond interface->implementations, stored-then-read data, cross-solution calls), root `README.md` if the feature list mentions dotnet_legacy coverage.
- Test: `tests/test_dnl_end_to_end.py` (add a performance guard: solving `taint_app` completes in under 20 s on the dev box; mark it so it never flakes on slower CI -- generous bound, assert rounds <= 6 instead of wall time if time varies).

- [ ] **Step 1:** Full suite on Windows, then the Linux container run (same docker command as Plan 1 Task 13: copy repo to /tmp in `mcr.microsoft.com/dotnet/sdk:8.0`, install python3, venv, pytest). Expected all PASS; report the tail.
- [ ] **Step 2:** Real-target smoke run: `python main.py <target dir> --html <scratch>/target.html --json <scratch>/target.json` with outputs outside the repo. Report exit code, runtime, taint finding counts per rule and proven vs REVIEW split, any crash or obviously wrong result. Fix generic bugs only via synthetic fixture reproductions. Never copy target code or names into the repo or commit messages.
- [ ] **Step 3: Commit** `git commit -m "dotnet_legacy: taint README and end-to-end checks"`
