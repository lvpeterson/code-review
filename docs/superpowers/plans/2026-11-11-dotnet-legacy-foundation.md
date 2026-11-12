# dotnet_legacy Foundation Implementation Plan (Plan 1 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect .NET Framework web apps, parse C# and VB through a Roslyn helper (with a hard install preflight), build a solution model, and report route inventory with effective auth, auth/CSRF findings and web.config findings, every finding tagged with OWASP Web 2025 / Web 2021 / API 2023.

**Architecture:** A .NET 8 console tool (`tools/roslyn-ir/`) lowers C# and VB into one JSON IR; Python (`checks/dnl/`) loads it into a cached `ProjectModel`, evaluates web.config plus XDT transforms, discovers MVC / Web API / WebForms routes, resolves effective auth, and emits findings through `dnl_finding()`, which attaches OWASP tags from `core/owasp_web.py`. `languages/dotnet_legacy` registers one analyzer per framework.

**Tech Stack:** Python 3.10+, pytest, stdlib `xml.parsers.expat`/`ElementTree`; .NET 8, Microsoft.CodeAnalysis.CSharp + Microsoft.CodeAnalysis.VisualBasic 4.x, Microsoft.NETFramework.ReferenceAssemblies.net48.

**Spec:** `docs/superpowers/specs/2026-11-11-dotnet-legacy-design.md`

**Later plans (not in scope here):**
- Plan 2: taint engine + Razor/ASPX template tokenizer + INJ / XSS / PATH / REDIR / SSRF / LDAP / log-injection rules + object-level authz (API1) and over-posting (API3).
- Plan 3: WCF (routes, bindings, behaviors), crypto, secrets in code, deserialization, XXE, integrity (SRI), session/auth code rules.
- Plan 4: deps/SCA (NuGet + bundled JS), ERR / LOG / DES / RES / INV / CONSUME code rules, tree-sitter C# + regex VB degraded mode, the "every OWASP category has a rule" coverage test, real-target acceptance pass.

## Global Constraints

- No target/client code or identifying names/paths in the repo (public repo): fixtures are synthetic, written from scratch; scan outputs go to a scratch dir, never committed.
- Prose and comments use `--`, never em-dashes; comment density like `checks/tf_graph.py`.
- Run Python tests from a venv outside the repo: `pip install -r requirements.txt pytest`, then `python -m pytest` from `code-review/`.
- Must run on Linux: no Windows-only APIs in the helper or Python; all file resolution is case-insensitive and accepts `\` or `/`.
- Source decoding everywhere: UTF-8 with BOM stripped (`utf-8-sig`), falling back to cp1252.
- Skip dirs for this package: everything in `core/fsutil._SKIP_DIRS` plus `packages`, `.vs`, `node_modules`, and any dir whose name starts with `Precompiled` (case-insensitive).
- Every `DNL-` rule id has a 2025 and a 2021 tag in `core/owasp_web.py`; API 2023 tag only where it honestly applies.
- Severity values: `high | medium | low | info`. `confidence="REVIEW"` when a human must decide.
- Preflight failure exits the CLI with code **2**; `--allow-degraded` is the only opt-out.
- Helper discovery env var: `CODE_REVIEW_ROSLYN_IR`. IR schema version: `1`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Work on branch `feature/dotnet-legacy`.

## Review Focus

1. Windows-authored paths on Linux: `<Compile Include="Controllers\homeController.cs">` when the file is `Controllers/HomeController.cs` must still resolve (test in Task 3).
2. A VB file saved as cp1252 with a BOM-less `é` in a string, and a C# file with a UTF-8 BOM, must both parse with correct line numbers (test in Task 4).
3. A malformed or BOM-prefixed web.config must not crash the scan; it yields a note and no findings for that file (test in Task 8).
4. One unparseable/unreadable source file must not lose the other files' IR (test in Task 4).
5. A 1,000+ file solution must be parsed in one helper process, not one per file (test in Task 6).

---

### Task 1: OWASP Web mapping module and finding helper

**Files:**
- Create: `core/owasp_web.py`
- Create: `checks/dnl/__init__.py` (docstring only), `checks/dnl/findings.py`
- Modify: `core/models.py` (`Finding`, `ScanResult`)
- Test: `tests/test_owasp_web.py`

**Interfaces:**
- Produces: `core.models.Finding.owasp: dict[str, str]` (default `{}`; keys `"2025"`, `"2021"`, `"api2023"`; values full labels like `"A05:2025 Injection"`).
- Produces: `core.models.ScanResult.degraded: Optional[str] = None` (reason text when a degraded run).
- Produces: `core.owasp_web.TITLES: dict[str, dict[str, str]]` keyed `"2025"|"2021"|"api2023"` then code (`"A01"`, `"API5"`).
- Produces: `core.owasp_web.owasp_for(check_id: str, api_surface: bool = False) -> dict[str, str]` (exact id, then longest prefix, like `owasp_isr.isr_for`).
- Produces: `core.owasp_web.RULES: dict[str, tuple[str, str, Optional[str], str]]` = `(code2025, code2021, api_code_or_None, api_mode)`, `api_mode` in `{"always", "api_surface"}`.
- Produces: `checks.dnl.findings.dnl_finding(check_id: str, severity: str, title: str, description: str, file: str, line: int, *, route: Route | None = None, api_surface: bool = False, confidence: str | None = None) -> Finding`.

Titles (verify against owasp.org before coding; if the published 2025 wording differs, use the published wording):
- 2025: A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions.
- 2021: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components, A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures, A09 Security Logging and Monitoring Failures, A10 Server-Side Request Forgery.
- API 2023: API1 Broken Object Level Authorization, API2 Broken Authentication, API3 Broken Object Property Level Authorization, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authorization, API6 Unrestricted Access to Sensitive Business Flows, API7 Server Side Request Forgery, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe Consumption of APIs.

Rule table for this plan (all `api_mode="api_surface"` unless noted):

| id | 2025 | 2021 | API |
|---|---|---|---|
| DNL-CFG-001..007 | A02 | A05 | API8 |
| DNL-XSS-002 | A05 | A03 | -- |
| DNL-SESS-001..004 | A07 | A07 | API2 |
| DNL-SESS-005 | A04 | A02 | API2 |
| DNL-INT-001, 002 | A08 | A08 | -- |
| DNL-SEC-001, 002 | A07 | A07 | API2 |
| DNL-INV-001 | A02 | A05 | API9 (`always`) |
| DNL-RES-001 | A06 | A04 | API4 |
| DNL-AUTHZ-001..004 | A01 | A01 | API5 |
| DNL-CSRF-001 | A01 | A01 | -- |

- [ ] **Step 1: Write the failing tests**

```python
from core.owasp_web import RULES, TITLES, owasp_for
from checks.dnl.findings import dnl_finding

def test_every_dnl_rule_has_2025_and_2021_tags():
    for rid, (c25, c21, api, mode) in RULES.items():
        assert rid.startswith("DNL-")
        assert c25 in TITLES["2025"] and c21 in TITLES["2021"]
        assert api is None or api in TITLES["api2023"]
        assert mode in ("always", "api_surface")

def test_titles_have_ten_entries_per_list():
    assert [len(TITLES[k]) for k in ("2025", "2021", "api2023")] == [10, 10, 10]

def test_api_tag_only_on_api_surface():
    assert owasp_for("DNL-CFG-001") == {"2025": "A02:2025 Security Misconfiguration",
                                        "2021": "A05:2021 Security Misconfiguration"}
    assert owasp_for("DNL-CFG-001", api_surface=True)["api2023"] == "API8:2023 Security Misconfiguration"
    assert owasp_for("DNL-INV-001")["api2023"] == "API9:2023 Improper Inventory Management"

def test_unknown_id_has_no_tags():
    assert owasp_for("TF-S3-001") == {}

def test_dnl_finding_sets_owasp_and_leaves_isr_category_alone():
    f = dnl_finding("DNL-AUTHZ-001", "high", "t", "d", "a.cs", 3, api_surface=True)
    assert f.owasp["api2023"].startswith("API5:2023") and f.category is None
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_owasp_web.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'core.owasp_web'`

- [ ] **Step 3: Implement** `core/owasp_web.py`, the two dataclass fields (with comments in the style of the surrounding fields), and `checks/dnl/findings.py`. Label format: `f"{code}:{year} {title}"` with year `2025`, `2021`, `2023`.

- [ ] **Step 4: Run to verify pass** -- same command, expected PASS; then `python -m pytest -q` (whole suite stays green).

- [ ] **Step 5: Commit** `git add core/owasp_web.py core/models.py checks/dnl tests/test_owasp_web.py && git commit -m "Add OWASP Web 2025/2021/API 2023 mapping and dnl_finding helper"`

---

### Task 2: Report plumbing (console, JSON, SARIF, HTML OWASP tab, degraded banner, allowlist)

**Files:**
- Modify: `core/report.py`, `core/sarif_report.py`, `core/html_report.py`, `core/allowlist.py`
- Test: `tests/test_report_owasp.py`

**Interfaces:**
- Consumes: `Finding.owasp`, `ScanResult.degraded`, `owasp_web.TITLES` (Task 1).
- Produces: `core.allowlist.MISSING_AUTH_IDS = {"AUTH-001", "DNL-AUTHZ-001"}` used by `apply_allowlist` and by `html_report._render_auth_tab` (replace the literal `"AUTH-001"` comparisons).
- Produces: `html_report._render_owasp_tab(results, target_path, item_ids) -> str`; tab button id `tab-btn-owasp`, panel id `tab-panel-owasp`, `data-tab="owasp"`; coverage rows `class="owasp-row"` with `data-owasp="2025:A01"` style keys; finding divs carry `data-owasp="2025:A01 2021:A01 api2023:API5"` (space-separated).

Behavior:
- Console: under each finding with tags print `           OWASP A01:2025 | A01:2021 | API5:2023` (only present keys, in that order).
- JSON: `"owasp": {...}` on each finding; `"degraded": <str|null>` on each scan result.
- SARIF: rule `properties.tags` gains `owasp-2025:A01`, `owasp-2021:A01`, `owasp-api-2023:API5` for present keys (merged with any ISR tags); result `properties.owasp` = the dict; run `properties.degraded` = first non-null reason.
- HTML: badges for each tag next to the ISR badge (`class="finding-owasp"`). OWASP tab lists every finding with non-empty `owasp`, preceded by a coverage table: three groups (2025, 2021, API 2023) each with all 10 categories, severity count columns + total, zero rows show `manual` like `_render_isr_coverage`; click/Enter on a row filters the tab's findings (copy the `_ISR_FILTER_JS` pattern, scoped to the panel). If any result has `degraded`, a banner `<div class="degraded-banner" role="alert">` at the top of the page body with the reason(s), red background.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run to verify failure** -- `python -m pytest tests/test_report_owasp.py -v`, expected FAIL (no `owasp` key / no tab).
- [ ] **Step 3: Implement** the changes listed under Behavior.
- [ ] **Step 4: Run** `python -m pytest tests/test_report_owasp.py tests/test_report.py tests/test_infra.py -v`, expected PASS; then full suite.
- [ ] **Step 5: Commit** `git commit -m "Report OWASP Web tags: console, JSON, SARIF, HTML OWASP tab, degraded banner"`

---

### Task 3: Package skeleton, file walker, path resolution, detector

**Files:**
- Create: `checks/dnl/files.py`
- Create: `languages/dotnet_legacy/__init__.py`, `languages/dotnet_legacy/detector.py`, `languages/dotnet_legacy/analyzers.py` (empty registrations come in Task 13; for now the module exists with its docstring), `languages/dotnet_legacy/README.md` (stub heading + "see spec")
- Modify: `languages/__init__.py`, `enumerator.py` (`LANGUAGE_MODULES["dotnet_legacy"]`), `pyproject.toml` (`languages.dotnet_legacy`, description mentions .NET Framework)
- Create fixtures: `tests/fixtures/dotnet_legacy/mvc5_app/` (minimal now: `MvcApp/MvcApp.csproj` legacy-style with `ToolsVersion="15.0"`, `<TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion>`, `<Reference Include="System.Web.Mvc, Version=5.2.7.0" />`, `<Compile Include="Controllers\homeController.cs" />` pointing at `Controllers/HomeController.cs`; `MvcApp/Web.config` with `<system.web>`; `MvcApp/Views/Web.config`; `PrecompiledWeb/Default.aspx`; `packages/Foo.1.0/content/x.aspx`), and `tests/fixtures/dotnet_legacy/core_app/App.csproj` (`<Project Sdk="Microsoft.NET.Sdk.Web">`).
- Test: `tests/test_dnl_detect.py`

**Interfaces:**
- Produces: `checks.dnl.files.iter_dnl_files(root: Path, extensions: tuple[str, ...]) -> Iterator[Path]` (suffix match case-insensitive; extensions given lowercase with dot).
- Produces: `checks.dnl.files.resolve_ci(base: Path, rel: str) -> Path | None` (splits on `\` and `/`, matches each segment case-insensitively, returns existing path or None).
- Produces: `checks.dnl.files.read_source(path: Path) -> str` (utf-8-sig, fallback cp1252).
- Produces: `checks.dnl.files.is_legacy_project(text: str) -> bool` (no `<Project Sdk=` and (`ToolsVersion=` or `<TargetFrameworkVersion>v`)).
- Produces: `languages.dotnet_legacy.detector.detect_language(target: Path) -> bool`, `detect_frameworks(target: Path) -> list[str]` returning a subset of `["mvc", "webapi", "webforms", "config"]` in that order. Rules: `mvc` = a legacy project references `System.Web.Mvc` or a `packages.config` lists `Microsoft.AspNet.Mvc`; `webapi` = `System.Web.Http` / `Microsoft.AspNet.WebApi`; `webforms` = any `.aspx`; `config` = any `web.config` (case-insensitive name) not inside a `Views` dir containing `<system.web` or `<system.webServer`. `detect_language` is true if any legacy project, `packages.config`, qualifying `web.config`, or `.aspx/.ascx/.svc/.asmx` exists.

- [ ] **Step 1: Write the failing tests**

```python
from pathlib import Path
from checks.dnl.files import iter_dnl_files, resolve_ci, read_source, is_legacy_project
from languages.dotnet_legacy import detector

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"

def test_walker_skips_packages_and_precompiled():
    found = {p.name for p in iter_dnl_files(FX / "mvc5_app", (".aspx",))}
    assert found == set()

def test_resolve_ci_handles_backslashes_and_case():
    p = resolve_ci(FX / "mvc5_app" / "MvcApp", r"Controllers\homeController.cs")
    assert p is not None and p.name == "HomeController.cs"
    assert resolve_ci(FX / "mvc5_app", "nope\\x.cs") is None

def test_read_source_bom_and_cp1252(tmp_path):
    (tmp_path / "a.vb").write_bytes(b"\xef\xbb\xbfDim x = 1")
    (tmp_path / "b.vb").write_bytes(b'Dim s = "caf\xe9"')
    assert read_source(tmp_path / "a.vb") == "Dim x = 1"
    assert read_source(tmp_path / "b.vb") == 'Dim s = "café"'

def test_legacy_vs_sdk_projects():
    assert is_legacy_project((FX / "mvc5_app/MvcApp/MvcApp.csproj").read_text())
    assert not is_legacy_project((FX / "core_app/App.csproj").read_text())

def test_detector():
    assert detector.detect_frameworks(FX / "mvc5_app") == ["mvc", "config"]
    assert not detector.detect_language(FX / "core_app")
```

- [ ] **Step 2: Run** `python -m pytest tests/test_dnl_detect.py -v`, expected FAIL (module missing).
- [ ] **Step 3: Implement** the files above. In `enumerator.py`, import `dotnet_legacy` and add to `LANGUAGE_MODULES` after `dotnet`. Until Task 13 registers analyzers the enumerator prints its "no analyzer registered yet" line, which is fine.
- [ ] **Step 4: Run** the test file, expected PASS; then full suite (the ASP.NET Core tests must not change).
- [ ] **Step 5: Commit** `git commit -m "Add dotnet_legacy package skeleton, walker and detector"`

---

### Task 4: Roslyn helper -- syntax IR for C# and VB

**Files:**
- Create: `tools/roslyn-ir/src/RoslynIr.csproj` (net8.0, OutputType Exe, AssemblyName `roslyn-ir`, PackageReferences Microsoft.CodeAnalysis.CSharp and Microsoft.CodeAnalysis.VisualBasic pinned to the same 4.x version), `tools/roslyn-ir/src/Program.cs`, `tools/roslyn-ir/src/CSharpLowering.cs`, `tools/roslyn-ir/src/VbLowering.cs`, `tools/roslyn-ir/src/IrWriter.cs`, `tools/roslyn-ir/README.md`
- Modify: `.gitignore` (`tools/roslyn-ir/bin/`, `tools/roslyn-ir/src/bin/`, `tools/roslyn-ir/src/obj/`)
- Test: `tests/test_dnl_helper_ir.py` (drives the built binary)

**Interfaces (CLI contract, schema 1):**
- `roslyn-ir probe` writes `{"ok": true, "schema": 1}` and exits 0 (it parses one embedded C# and one embedded VB snippet first; any exception means non-zero exit).
- `roslyn-ir parse --input <request.json>`; request `{"root": "<abs>", "projects": [{"name": str, "language": "cs"|"vb", "files": ["<abs>"...], "references": [str...]}]}`. Writes JSON Lines to stdout, one object per file, in input order. Per-file failure writes `{"path": rel, "error": "<message>"}` and continues.
- FileIR object: `{"path": rel_posix, "language": "cs"|"vb", "project": name, "parse_errors": int, "types": [Type]}`.
- Type: `{"name","namespace","kind": "class"|"interface"|"struct"|"module"|"enum","modifiers":[...],"bases":[simple names],"attributes":[Attr],"fields":[Field],"properties":[Prop],"methods":[Method],"line","end_line"}`; nested types appear flattened with `namespace` = outer namespace and `name` = `Outer.Inner`.
- Attr: `{"name","args":[Expr],"named":{k: Expr},"line"}`, name with namespace qualifier and `Attribute` suffix stripped.
- Field `{"name","type","line","init":Expr|null,"is_const":bool}`; Prop `{"name","type","attributes","line"}`.
- Method `{"name","modifiers","return_type","params":[{"name","type","attributes"}],"attributes","handles":[str],"body":[Stmt],"line","end_line"}`; constructors use name `.ctor`; VB `Handles btnSave.Click` -> `handles: ["btnSave.Click"]`.
- Stmt `k` values: `local {name,type,init}`, `assign {target,value,op}` (`op` one of `=`, `+=`, `-=`, `concat=`), `expr {expr}`, `return {value}`, `throw {value}`, `if {cond,then,else}`, `loop {header:[Expr],body}`, `try {body,catches:[{type,name,body}],finally}`, `using {resource:[Stmt],body}`, `with {target,body}`, `other {text}`; every Stmt has `line`.
- Expr `k` values: `lit {v,t}` (`t` in `string|number|bool|null|char`), `name {id}`, `member {obj,name}`, `call {fn,args,named}`, `new {type,args,init:[{name,value}]}`, `bin {op,l,r}` (VB `&` and C# string `+` keep their own ops: `concat` for VB `&`, `+` for C#), `interp {parts:[Expr]}` (literal text parts as `lit` string), `cond {c,t,f}`, `index {obj,args}` (C# element access only; VB `x(1)` stays `call`), `cast {type,e}`, `lambda {body}` (body Stmt list or single Expr), `unknown {text}`; every Expr has `line`. `Me`/`this` -> `name {id:"this"}`, `MyBase`/`base` -> `name {id:"base"}`.
- Modifiers lowercased, VB normalized: Shared->static, Overrides->override, Overridable->virtual, MustOverride->abstract, MustInherit->abstract, NotInheritable->sealed, Friend->internal, Protected Friend->protected internal.
- Encoding: helper reads bytes and decodes UTF-8 (BOM-aware), falling back to Windows-1252 on invalid UTF-8 (register `CodePagesEncodingProvider`). Line numbers are 1-based and match the original file.
- Lines and paths: `path` is relative to `root`, forward slashes.

- [ ] **Step 1: Write the failing tests** (module-level skip only when `dotnet` is absent: `pytest.importorskip` is not applicable; use `shutil.which("dotnet")` + `pytest.mark.skipif`). A session fixture builds the helper once with `dotnet publish tools/roslyn-ir/src/RoslynIr.csproj -c Release -o <tmp>/bin` and returns the binary path.

```python
def test_probe(helper):
    out = subprocess.run([helper, "probe"], capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == {"ok": True, "schema": 1}

def test_csharp_controller_ir(helper, tmp_path):
    ir = parse_one(helper, tmp_path, "HomeController.cs", "cs",
        '\ufeffusing System.Web.Mvc;\nnamespace A {\n[Authorize]\npublic class HomeController : Controller {\n'
        '  [HttpPost, ValidateAntiForgeryToken]\n  public ActionResult Save(int id) { var s = "x" + id; return View(); }\n}}\n')
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
```

(`parse_one`, `parse_file`, `run_parse` are small helpers in the test module that write the request JSON and decode the JSON Lines.)

- [ ] **Step 2: Run** `python -m pytest tests/test_dnl_helper_ir.py -v`, expected FAIL (publish fails: project missing).
- [ ] **Step 3: Implement** the helper: `Program.cs` (arg parsing, probe, request reading, per-file try/catch, streaming JSON Lines with `System.Text.Json` `Utf8JsonWriter`), `CSharpLowering`/`VbLowering` as `CSharpSyntaxWalker`/`VisualBasicSyntaxWalker`-based lowerers to the shared writer, unmapped syntax -> `other`/`unknown` with source text (never throw on unknown node kinds).
- [ ] **Step 4: Run** the tests, expected PASS.
- [ ] **Step 5: Commit** `git commit -m "Add roslyn-ir helper: C# and VB syntax lowering to JSON IR"`

---

### Task 5: Roslyn helper -- semantic symbols via .NET Framework reference assemblies

**Files:**
- Modify: `tools/roslyn-ir/src/RoslynIr.csproj` (PackageReference `Microsoft.NETFramework.ReferenceAssemblies.net48` with `GeneratePathProperty="true"`, copy its `build/.NETFramework/v4.8/*.dll` and `Facades/*.dll` to `$(OutDir)refs/net48/`), `Program.cs`, both lowerings
- Test: `tests/test_dnl_helper_ir.py` (add)

**Interfaces:**
- Per project the helper builds one compilation (C# or VB) from that project's files plus all `refs/net48` assemblies; project-to-project references are ignored (cross-project resolution is the Python model's job).
- `call` and `member` Exprs gain optional `"sym"`: the resolved symbol's containing type full name + `.` + member name (e.g. `"System.Data.SqlClient.SqlCommand.ExecuteReader"`); `new` gains optional `"type_full"`; `local` Stmt gains optional `"type_full"` (inferred type, including `var`/`Dim x = New ...`). Omit the key when unresolved (missing third-party assemblies are expected).
- Probe still works with no target files.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run**, expected FAIL (`KeyError: 'type_full'`).
- [ ] **Step 3: Implement.** Annotation is best-effort; a semantic exception on one node must not drop the file.
- [ ] **Step 4: Run**, expected PASS.
- [ ] **Step 5: Commit** `git commit -m "roslyn-ir: resolve symbols against .NET Framework 4.8 reference assemblies"`

---

### Task 6: Helper discovery, build-on-first-use, preflight, CLI flag

**Files:**
- Create: `checks/dnl/helper.py`
- Modify: `main.py` (`--allow-degraded`; catch `PreflightError` -> print to stderr, return 2), `enumerator.py` (`enumerate_target(..., allow_degraded: bool = False)`; before running `dotnet_legacy` frameworks call `checks.dnl.project.prepare(target_path, allow_degraded)` -- `prepare` arrives in Task 7; in this task call `helper.preflight(...)` directly and switch to `prepare` in Task 7)
- Modify: `README.md` (CLI usage line for `--allow-degraded`, Linux install note), `tools/roslyn-ir/README.md` (build/publish commands)
- Test: `tests/test_dnl_preflight.py`

**Interfaces:**
- `REPO_ROOT: Path` (code-review dir), `SCHEMA_VERSION = 1`, `HELPER_ENV = "CODE_REVIEW_ROSLYN_IR"`.
- `class PreflightError(Exception)` (message is the full user-facing text).
- `find_helper(repo_root: Path = REPO_ROOT) -> Path | None` -- order: `$CODE_REVIEW_ROSLYN_IR`, `tools/roslyn-ir/bin/roslyn-ir` (`.exe` on Windows), `shutil.which("roslyn-ir")`. A repo-local binary older than any file under `tools/roslyn-ir/src/` (excluding `bin/obj`) counts as missing when the SDK is available (so it gets rebuilt).
- `sdk_available() -> bool` -- `dotnet --list-sdks` lists a major version >= 8.
- `build_helper(repo_root: Path = REPO_ROOT) -> Path` -- `dotnet publish tools/roslyn-ir/src/RoslynIr.csproj -c Release -o tools/roslyn-ir/bin --nologo`; prints `[dotnet_legacy] building Roslyn helper (first run)...`.
- `probe(binary: Path) -> None` -- raises `PreflightError` if exit != 0, stdout not JSON, or `schema != SCHEMA_VERSION` (message says the helper is broken/outdated and how to rebuild).
- `detection_summary(target: Path) -> str` -- e.g. `"Found 159 .vb / 1050 .cs files in .NET Framework projects"` (counts via `iter_dnl_files`).
- `install_instructions(platform: str = sys.platform) -> str` -- Linux text includes `apt install dotnet-sdk-8.0`, `dnf install dotnet-sdk-8.0`, and `./dotnet-install.sh --channel 8.0`; Windows text includes `winget install Microsoft.DotNet.SDK.8`; both include the no-install option (`dotnet publish -r linux-x64 --self-contained -p:PublishSingleFile=true` on a machine with the SDK, then copy the binary to `tools/roslyn-ir/bin/` or point `CODE_REVIEW_ROSLYN_IR` at it), the re-run hint, and `--allow-degraded`.
- `preflight(target: Path, allow_degraded: bool) -> Path | None` -- returns the probed binary; if none can be found or built: `allow_degraded` -> returns `None`; else raises `PreflightError` whose message starts with `error: .NET Framework code detected but the Roslyn helper is not available.` followed by the summary line, why it is needed (full-context C#/VB analysis), and `install_instructions()`.
- `parse_projects(binary: Path, root: Path, projects: list[dict], timeout: int = 1800) -> list[dict]` -- writes the request to a temp file, runs `parse` **once**, returns decoded JSON Lines; raises `PreflightError` on non-zero exit.
- Degraded reason constant: `DEGRADED_REASON = "Roslyn helper not available (--allow-degraded): C#/VB code analysis was skipped; only project and web.config checks ran."` (Plan 4 replaces the skip with the tree-sitter/regex fallback and updates this text.)

- [ ] **Step 1: Write the failing tests** (monkeypatch `find_helper`, `sdk_available`, `build_helper`, `subprocess.run`)

```python
def test_missing_helper_raises_with_install_text(monkeypatch, mvc_fixture):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    with pytest.raises(helper.PreflightError) as e:
        helper.preflight(mvc_fixture, allow_degraded=False)
    msg = str(e.value)
    assert msg.startswith("error: .NET Framework code detected")
    assert re.search(r"Found 0 \.vb / \d+ \.cs files in \.NET Framework projects", msg)
    assert "--allow-degraded" in msg

def test_install_text_per_os():
    assert "apt install dotnet-sdk-8.0" in helper.install_instructions("linux")
    assert "winget install Microsoft.DotNet.SDK.8" in helper.install_instructions("win32")

def test_allow_degraded_returns_none(monkeypatch, mvc_fixture):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    assert helper.preflight(mvc_fixture, allow_degraded=True) is None

def test_sdk_present_builds_then_probes(monkeypatch, mvc_fixture, tmp_path):
    built = tmp_path / "roslyn-ir"
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: True)
    monkeypatch.setattr(helper, "build_helper", lambda *a: built)
    monkeypatch.setattr(helper, "probe", lambda b: None)
    assert helper.preflight(mvc_fixture, allow_degraded=False) == built

def test_broken_helper_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "not json", ""))
    with pytest.raises(helper.PreflightError):
        helper.probe(tmp_path / "roslyn-ir")

def test_parse_projects_single_process(monkeypatch, tmp_path):
    calls = []
    def fake_run(cmd, **k):
        calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, '{"path":"a.cs","types":[]}\n' * 1200, "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    out = helper.parse_projects(tmp_path / "roslyn-ir", tmp_path,
                                [{"name": "p", "language": "cs", "files": [str(tmp_path / f"{i}.cs") for i in range(1200)], "references": []}])
    assert len(calls) == 1 and len(out) == 1200

def test_cli_exits_2_on_preflight(monkeypatch, mvc_fixture, capsys):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    monkeypatch.setattr(sys, "argv", ["main.py", str(mvc_fixture)])
    assert main.main() == 2 and "Roslyn helper is not available" in capsys.readouterr().err

def test_non_dotnet_target_never_preflights(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n")
    monkeypatch.setattr(helper, "preflight", lambda *a, **k: pytest.fail("preflight ran"))
    enumerate_target(tmp_path)
```

(`mvc_fixture` = `tests/fixtures/dotnet_legacy/mvc5_app`.)

- [ ] **Step 2: Run** `python -m pytest tests/test_dnl_preflight.py -v`, expected FAIL.
- [ ] **Step 3: Implement** `helper.py`, the enumerator hook, and the CLI handling.
- [ ] **Step 4: Run** the file, expected PASS; full suite.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy preflight: find/build/probe Roslyn helper, exit 2 with install steps, --allow-degraded"`

---

### Task 7: IR loader and project model

**Files:**
- Create: `checks/dnl/ir.py`, `checks/dnl/project.py`
- Modify: `enumerator.py` (call `project.prepare` instead of `helper.preflight`)
- Extend fixture `mvc5_app`: `MvcApp/Controllers/HomeController.cs` (class `HomeController : BaseController`), `MvcApp/Controllers/BaseController.cs` (`public abstract class BaseController : Controller`), a second project `MvcApp.Data/MvcApp.Data.csproj` with `Repo.cs`, referenced via `<ProjectReference Include="..\MvcApp.Data\MvcApp.Data.csproj" />`, and a loose `Scratch/Loose.cs` not in any project.
- Test: `tests/test_dnl_project.py`

**Interfaces:**
- `ir.py` dataclasses mirroring the schema: `FileIR(path, language, project, parse_errors, types)`, `TypeIR(name, namespace, kind, modifiers, bases, attributes, fields, properties, methods, line, end_line, file)` with property `full_name`, `Attr(name, args, named, line)`, `MethodIR(name, modifiers, return_type, params, attributes, handles, body, line, end_line)`, `ParamIR(name, type, attributes)`, `FieldIR(name, type, line, init, is_const)`, `PropertyIR(name, type, attributes, line)`. Stmts/Exprs stay plain dicts.
- `ir.load_file_ir(obj: dict) -> FileIR | None` (None for error lines); `ir.walk(node) -> Iterator[dict]` (pre-order over nested Stmt/Expr dicts and lists); `ir.call_name(expr) -> str | None` (`"Add"` for `x.Filters.Add(...)`, `"MapRoute"`); `ir.receiver_text(expr) -> str` (dotted text of a member chain, `"config.Filters"`); `ir.literal_str(expr) -> str | None`; `ir.has_attr(attrs, *names) -> Attr | None` (case-insensitive).
- `project.Project(name, path, language, dir, target_framework, references: set[str] (lowercased simple names), project_refs: list[Path], compile_files: list[Path], content_files: list[Path], is_legacy: bool)`.
- `project.ProjectModel(root, projects, files: dict[str, FileIR], degraded: str | None, notes: list[str])` with: `types() -> Iterator[TypeIR]`, `find_types(simple_name: str) -> list[TypeIR]` (case-insensitive), `base_chain(t: TypeIR) -> list[str]` (simple names, transitive through project types, cycle-safe, external names kept as the last element), `derives_from(t: TypeIR, names: set[str]) -> bool` (case-insensitive over `base_chain`), `project_of(rel: str) -> Project | None`, `rel(path: Path) -> str`.
- `project.load_projects(root: Path) -> list[Project]` (parses every `.csproj`/`.vbproj` via `iter_dnl_files`; `Compile`/`Content` includes resolved with `resolve_ci`; unresolvable includes recorded in notes; source files under the root not claimed by any project go to a synthetic project `"(loose)"` per language).
- `project.prepare(target: Path, allow_degraded: bool) -> ProjectModel` -- runs `helper.preflight`, then `helper.parse_projects` for all `.cs`/`.vb` compile files (legacy projects and loose), builds and caches the model by resolved path; when preflight returns None, builds the model with `files={}` and `degraded=helper.DEGRADED_REASON`.
- `project.get_model(target: Path) -> ProjectModel` -- cached model, or `prepare(target, False)`.

- [ ] **Step 1: Write the failing tests**

```python
def test_projects_and_references(model):
    names = {p.name for p in model.projects}
    assert {"MvcApp", "MvcApp.Data", "(loose)"} <= names
    web = next(p for p in model.projects if p.name == "MvcApp")
    assert "system.web.mvc" in web.references and web.target_framework == "v4.7.2"
    assert any(p.name == "MvcApp.Data.csproj" for p in web.project_refs)

def test_case_mismatched_compile_include_resolves(model):
    web = next(p for p in model.projects if p.name == "MvcApp")
    assert any(f.name == "HomeController.cs" for f in web.compile_files)

def test_base_chain_through_project_types(model):
    home = model.find_types("homecontroller")[0]
    assert model.base_chain(home) == ["BaseController", "Controller"]
    assert model.derives_from(home, {"controller"})

def test_degraded_model(monkeypatch, mvc_fixture):
    monkeypatch.setattr(helper, "preflight", lambda *a, **k: None)
    project._CACHE.clear()
    m = project.prepare(mvc_fixture, allow_degraded=True)
    assert m.files == {} and m.degraded == helper.DEGRADED_REASON
```

(`model` fixture: `project.prepare(mvc_fixture, False)` with the real helper; skip when the helper cannot be built.)

- [ ] **Step 2: Run** `python -m pytest tests/test_dnl_project.py -v`, expected FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run**, expected PASS; full suite.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: IR loader and cached solution model"`

---

### Task 8: web.config loading, XDT transforms, authorization evaluation

**Files:**
- Create: `checks/dnl/webconfig.py`
- Create fixture: `tests/fixtures/dotnet_legacy/config_variants/Site/Web.config`, `Web.Release.config`, `Web.Debug.config`, `Admin/Web.config`, `Views/Web.config`, `Broken/Web.config` (malformed), plus a BOM-prefixed variant.
- Test: `tests/test_dnl_webconfig.py`

**Interfaces:**
- `LINE = "{dnl}line"`, `ORIGIN = "{dnl}file"` -- reserved attribute keys stored on every element (source line, rel path of the file the element came from).
- `parse_xml_with_lines(text: str, origin: str) -> ET.Element` (expat-based; raises `ValueError` on malformed XML).
- `WebConfig(path: Path, rel: str, root: ET.Element | None, transforms: dict[str, ET.Element], is_views: bool, error: str | None)`.
- `load_configs(root: Path) -> list[WebConfig]` -- every `web.config` (case-insensitive) via `iter_dnl_files`; sibling `web.<Name>.config` files become `transforms[Name]`; malformed -> `root=None, error=...`; `is_views` when any path segment is `Views`.
- `apply_transform(base: ET.Element, transform: ET.Element) -> ET.Element` -- deep copy of base; supports `xdt:Transform` `Replace`, `Insert`, `InsertIfMissing`, `Remove`, `RemoveAll`, `SetAttributes(a,b)`, `RemoveAttributes(a,b)` and `xdt:Locator="Match(attr[,attr])"`; other locators (`Condition`, `XPath`) match all same-tag siblings and append a note `"xdt:Locator <x> approximated"`. Inserted/replaced elements keep the transform file's `ORIGIN`/`LINE`.
- `effective(cfg: WebConfig) -> list[tuple[str, ET.Element]]` -- `[("base", root)] + [(name, apply_transform(root, t)) ...]`.
- `anonymous_denied(chain: list[ET.Element], url_path: str) -> tuple[bool, ET.Element | None]` -- `chain` is effective roots ordered app root first, deepest config last; candidate rule sets are each config's root `<system.web><authorization>` and its `<location path>` blocks, deepest config + longest matching location path (case-insensitive prefix on `/`-segments) evaluated first; within a set the first rule matching an anonymous user decides (`deny` with users containing `?` or `*` -> denied; `allow` with users containing `?` or `*` -> allowed; role- or name-only rules don't match anonymous); a set with no matching rule defers to the next; nothing matched -> `(False, None)`. Returns the deciding element.
- `config_chain(configs: list[WebConfig], app_dir: Path, page_dir: Path, variant: str = "base") -> list[ET.Element]` -- effective roots from `app_dir` down to `page_dir`.

- [ ] **Step 1: Write the failing tests**

```python
def test_lines_and_bom(cfgs):
    site = cfg(cfgs, "Site/Web.config")
    comp = site.root.find("system.web/compilation")
    assert comp.get(LINE) == "4" and comp.get(ORIGIN) == "Site/Web.config"

def test_malformed_is_reported_not_raised(cfgs):
    assert cfg(cfgs, "Broken/Web.config").root is None and cfg(cfgs, "Broken/Web.config").error

def test_release_transform_removes_debug(cfgs):
    eff = dict(effective(cfg(cfgs, "Site/Web.config")))
    assert eff["base"].find("system.web/compilation").get("debug") == "true"
    assert eff["Release"].find("system.web/compilation").get("debug") is None

def test_match_locator_set_attributes(cfgs):
    eff = dict(effective(cfg(cfgs, "Site/Web.config")))
    add = [a for a in eff["Release"].iter("add") if a.get("name") == "Main"][0]
    assert "Server=prod" in add.get("connectionString") and add.get(ORIGIN) == "Site/Web.Release.config"

def test_anonymous_denied_location_and_nested(cfgs):
    chain = config_chain(cfgs, FX / "Site", FX / "Site" / "Admin")
    assert anonymous_denied(chain, "/Admin/Users.aspx")[0] is True
    assert anonymous_denied(chain[:1], "/Public/Home.aspx")[0] is False
    assert anonymous_denied(chain[:1], "/Reports/x.aspx")[0] is True   # <location path="Reports"><deny users="?"/>

def test_allow_star_before_deny_means_public(tmp_path):
    root = parse_xml_with_lines('<configuration><system.web><authorization><allow users="*"/><deny users="?"/></authorization></system.web></configuration>', "w")
    assert anonymous_denied([root], "/x")[0] is False
```

(Fixture content must make these assertions true: `Site/Web.config` line 4 is `<compilation debug="true" ...>`, a `<connectionStrings><add name="Main" .../>`, a `<location path="Reports">` with `<deny users="?"/>`; `Web.Release.config` has `RemoveAttributes(debug)` on compilation and `SetAttributes` + `Match(name)` on `Main`; `Site/Admin/Web.config` denies `?`.)

- [ ] **Step 2: Run**, expected FAIL. **Step 3: Implement.** **Step 4: Run**, expected PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: web.config loader with line numbers, XDT transforms, authorization evaluation"`

---

### Task 9: web.config rules

**Files:**
- Create: `checks/dnl/rules_config.py`
- Extend fixture `config_variants` so each rule below has one positive and the safe counterpart where noted.
- Test: `tests/test_dnl_rules_config.py`

**Interfaces:**
- Consumes: `load_configs`, `effective`, `anonymous_denied`, `config_chain` (Task 8); `dnl_finding` (Task 1).
- Produces: `check_configs(configs: list[WebConfig], api_surface_dirs: set[Path], has_aspx_dirs: set[Path]) -> tuple[list[Finding], list[str]]` (findings, notes). `api_surface_dirs`/`has_aspx_dirs` are project dirs; a config's `api_surface` is true when its dir is inside one.

Rules (paths relative to `<configuration>`; attribute comparisons case-insensitive; Views configs skipped entirely; malformed configs produce a note `"<rel>: could not parse web.config (<error>)"`):

| id | sev | condition |
|---|---|---|
| DNL-CFG-001 | medium | `system.web/compilation@debug="true"` |
| DNL-CFG-002 | medium | `system.web/customErrors@mode="Off"` or `system.webServer/httpErrors@errorMode="Detailed"` |
| DNL-CFG-003 | medium (high if `localOnly="false"`) | `system.web/trace@enabled="true"` |
| DNL-CFG-004 | high | `elmah/security@allowRemoteAccess` in `true/yes/1` |
| DNL-CFG-005 | low | `system.web` present and `httpRuntime@enableVersionHeader` != `false` (anchor: httpRuntime, else system.web) |
| DNL-CFG-006 | low | `system.web` present and `system.webServer/httpProtocol/customHeaders` lacks any of `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Content-Security-Policy`; one finding naming the missing ones |
| DNL-CFG-007 | medium | customHeaders `add@name="Access-Control-Allow-Origin" value="*"` |
| DNL-XSS-002 | medium | (`pages@validateRequest="false"` and the config's dir is in `has_aspx_dirs`) or `httpRuntime@requestValidationMode` starts with `2.` |
| DNL-SESS-001 | medium | `authentication@mode="Forms"` and `forms@requireSSL` != `true` |
| DNL-SESS-002 | low | `system.web` present and (`httpCookies` missing or `httpOnlyCookies` != `true`) |
| DNL-SESS-003 | low | `forms@timeout` integer > 60 |
| DNL-SESS-004 | medium | `forms@cookieless` in `UseUri/AutoDetect` or `sessionState@cookieless` in `true/UseUri/AutoDetect` |
| DNL-SESS-005 | high (`Clear`) / medium (`Encrypted`) | `membership/providers/add@passwordFormat` |
| DNL-INT-001 | high | `pages@enableViewStateMac="false"` |
| DNL-INT-002 | medium | `machineKey@validationKey` or `@decryptionKey` present and not starting with `AutoGenerate` |
| DNL-SEC-001 | high | `connectionStrings/add@connectionString` matches `(?i)\b(password|pwd)\s*=\s*([^;"]+)` with a non-placeholder value |
| DNL-SEC-002 | medium | `appSettings/add@key` matches `(?i)password|pwd|secret|apikey|api_key|token|privatekey|clientsecret` and `@value` is a non-placeholder of length >= 4 |
| DNL-INV-001 | medium (low if `anonymous_denied(chain, "/" + handler path)` is true) | `system.web/httpHandlers/add` or `system.webServer/handlers/add` with `path` ending `elmah.axd` or `trace.axd` |
| DNL-RES-001 | low | `httpRuntime@maxRequestLength` > 102400 or `requestFiltering/requestLimits@maxAllowedContentLength` > 104857600 |

Placeholder regex (skip): `(?i)^(\$\(.*\)|\{.*\}|#\{.*\}|__.*__|\*+|x+|changeme|)$`.

Transform-aware merge (the algorithm the tests pin): evaluate every rule on each `effective()` variant; key hits by `(rule id, ORIGIN, LINE)`. A hit present in `base`:
- no transforms exist -> emit as-is;
- absent from every transform variant -> severity `info`, description appends `" Removed by the Web.<names>.config transform(s); still present in the base Web.config used by local/debug builds."`;
- absent from some -> severity unchanged, description appends `" Still present in: <variants>."`.
A hit only in transform variants -> emitted at the transform's `ORIGIN`/`LINE`, description appends `" Introduced by Web.<name>.config."`.

- [ ] **Step 1: Write the failing tests** (Tasks 9, 11, 12 define two helpers at the top of each test module: `hits(findings, cid, handler=None)` returns matching findings, filtered on `f.route.handler_name` when `handler` is given; `one(...)` asserts exactly one hit and returns it. The `findings` fixture here is `check_configs(load_configs(FX), set(), set())[0]`.)

```python
def test_debug_removed_in_release_is_info(findings):
    f = one(findings, "DNL-CFG-001")
    assert f.severity == "info" and "Removed by the Web.Release.config" in f.description

def test_connection_string_password(findings):
    f = one(findings, "DNL-SEC-001")   # fixture also has a Password=$(DbPassword) entry, which must not fire
    assert f.severity == "high" and f.file == "Site/Web.config"

def test_introduced_by_transform(findings):
    f = one(findings, "DNL-CFG-002")
    assert f.file == "Site/Web.Debug.config" and "Introduced by Web.Debug.config" in f.description

def test_views_config_ignored(findings):
    assert not [f for f in findings if "Views" in f.file]

def test_elmah_handler_low_when_location_denies(findings):
    assert one(findings, "DNL-INV-001").severity == "low"

def test_api_surface_tag(cfgs):
    fs, _ = check_configs(cfgs, api_surface_dirs={FX / "Site"}, has_aspx_dirs=set())
    assert one(fs, "DNL-SEC-001").owasp["api2023"].startswith("API2:2023")

def test_malformed_note(cfgs):
    _, notes = check_configs(cfgs, set(), set())
    assert any("Broken/Web.config: could not parse" in n for n in notes)

def test_each_rule_fires_once(findings):
    ids = {f.check_id for f in findings}
    assert ids >= {"DNL-CFG-001", "DNL-CFG-002", "DNL-CFG-003", "DNL-CFG-004", "DNL-CFG-005", "DNL-CFG-006",
                   "DNL-CFG-007", "DNL-XSS-002", "DNL-SESS-001", "DNL-SESS-002", "DNL-SESS-003", "DNL-SESS-004",
                   "DNL-SESS-005", "DNL-INT-001", "DNL-INT-002", "DNL-SEC-001", "DNL-SEC-002", "DNL-INV-001", "DNL-RES-001"}
```

- [ ] **Step 2: Run**, expected FAIL. **Step 3: Implement.** **Step 4: Run**, expected PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: web.config rules with transform-aware severity"`

---

### Task 10: MVC 5 and Web API 2 route discovery

**Files:**
- Create: `checks/dnl/routes.py`
- Extend fixture `mvc5_app`: `App_Start/RouteConfig.cs` (`routes.MapRoute(name: "Default", url: "{controller}/{action}/{id}", ...)`), `App_Start/WebApiConfig.cs` (`config.Routes.MapHttpRoute("DefaultApi", "api/{controller}/{id}", ...)`), `Controllers/OrdersApiController.cs` (`: ApiController`, methods `GetOrder(int id)`, `PostOrder(Order o)`, `[HttpDelete] Remove(int id)`), `Controllers/ReportsController.cs` with `[RoutePrefix("reports")]` and `[Route("{year:int}")] Year(int year)` and `[Route("~/r/latest")] Latest()`, `Areas/Admin/Controllers/UsersController.cs` (namespace `MvcApp.Areas.Admin.Controllers`) plus `Areas/Admin/AdminAreaRegistration.cs` (`context.MapRoute("Admin_default", "Admin/{controller}/{action}/{id}", ...)`), a `[NonAction]` method `Helper()` and an `override` method `Dispose(bool)` in `HomeController`. Add `<Reference Include="System.Web.Http" />` to `MvcApp.csproj` and update `test_detector` in `tests/test_dnl_detect.py` to expect `["mvc", "webapi", "config"]`.
- Test: `tests/test_dnl_routes.py`

**Interfaces:**
- `RouteRef(route: Route, type: TypeIR, method: MethodIR | None, project: Project | None)`.
- `discover_mvc_webapi(model: ProjectModel) -> list[RouteRef]`.
- `Route.meta` keys set here: `"kind"` (`"mvc"`|`"webapi"`), `"api_surface"` (True for webapi), `"controller"` (type full name). `handler_name` = `"<Controller>.<Action>"`; `file`/`line` = method; `source_start_line`/`source_end_line` = method range; `explicit_access="PermitAll"` when the action or class has `[AllowAnonymous]`.

Rules (pinned):
- Controller: non-abstract class, simple name ends with `Controller`, `derives_from(t, {"Controller", "AsyncController", "ApiController"})`; Web API when chain contains `ApiController`.
- Action: `public`, not `static`, not `override`, not `.ctor`, no `[NonAction]`.
- Verbs: `HttpGet/HttpPost/HttpPut/HttpDelete/HttpPatch/HttpHead/HttpOptions` attributes and `AcceptVerbs("A","B")`; else Web API name prefix (case-insensitive `Get|Post|Put|Delete|Patch|Head|Options`) else `["POST"]`; else MVC `["GET", "POST"]`.
- Attribute routes: `[RoutePrefix(p)]` on class + `[Route(t)]` on action -> `"/" + p + "/" + t`; `t` starting `~/` replaces the prefix; constraints stripped (`{year:int}` -> `{year}`); `[Route]` on class with action-level absent -> class template.
- Conventional MVC: first `MapRoute` call whose receiver is not `context` and whose `url` (named or 2nd positional) contains `{controller}` and `{action}`; fallback `"{controller}/{action}/{id}"`. Area controllers (namespace contains `.Areas.<X>.`): `context.MapRoute` in a type deriving `AreaRegistration` whose url starts with `<X>/`; fallback `"<X>/{controller}/{action}/{id}"`.
- Conventional Web API: first `MapHttpRoute` template (named `routeTemplate` or 2nd positional); fallback `"api/{controller}/{id}"`; `{action}` substituted when present.
- Substitute `{controller}` with the name minus `Controller`, `{action}` with the method name; other tokens kept; result starts with `/`.

- [ ] **Step 1: Write the failing tests**

```python
def paths(refs): return {(r.route.handler_name, r.route.path, tuple(r.route.methods)) for r in refs}

def test_conventional_mvc(refs):
    assert ("HomeController.Index", "/Home/Index/{id}", ("GET", "POST")) in paths(refs)

def test_nonaction_and_override_excluded(refs):
    names = {r.route.handler_name for r in refs}
    assert "HomeController.Helper" not in names and "HomeController.Dispose" not in names

def test_webapi_conventional_and_verbs(refs):
    p = paths(refs)
    assert ("OrdersApiController.GetOrder", "/api/OrdersApi/{id}", ("GET",)) in p
    assert ("OrdersApiController.Remove", "/api/OrdersApi/{id}", ("DELETE",)) in p
    r = next(r for r in refs if r.route.handler_name == "OrdersApiController.PostOrder")
    assert r.route.meta == {"kind": "webapi", "api_surface": True, "controller": "MvcApp.Controllers.OrdersApiController"}

def test_attribute_routes(refs):
    p = {r.route.handler_name: r.route.path for r in refs}
    assert p["ReportsController.Year"] == "/reports/{year}" and p["ReportsController.Latest"] == "/r/latest"

def test_area_route(refs):
    assert ("UsersController.Index", "/Admin/Users/Index/{id}", ("GET", "POST")) in paths(refs)
```

- [ ] **Step 2: Run**, expected FAIL. **Step 3: Implement.** **Step 4: Run**, expected PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: MVC 5 / Web API 2 route discovery"`

---

### Task 11: Effective auth, AUTHZ and CSRF rules for MVC / Web API

**Files:**
- Create: `checks/dnl/auth.py`, `checks/dnl/rules_auth.py`
- Extend fixture `mvc5_app`: `App_Start/FilterConfig.cs` (`filters.Add(new HandleErrorAttribute());` only -- no global auth), `Filters/AlwaysAllowAttribute.cs` (`: AuthorizeAttribute` with `protected override bool AuthorizeCore(HttpContextBase c) { return true; }`), `Filters/RealAuthAttribute.cs` (`: AuthorizeAttribute` with a conditional return), `BaseController` carrying `[Authorize]`, a `PublicController : Controller` with no auth containing `Index()` and `[HttpPost] [AllowAnonymous] Register(...)` without anti-forgery, `HomeController.[HttpPost] [ValidateAntiForgeryToken] Save(...)`, an `AdminController : Controller` with class-level `[Authorize]` and `DeleteUser(int id)`, a `LooseController : Controller` with class-level `[AlwaysAllow]` and `Index()`, `OrdersApiController` decorated with `[RealAuth]`; and a second fixture app `tests/fixtures/dotnet_legacy/webapi_global/` (legacy project referencing `System.Web.Http`, `ValuesController : ApiController` with `Get()`, `HealthController : ApiController` with `[AllowAnonymous] Get()`) whose `WebApiConfig` does `config.Filters.Add(new AuthorizeAttribute());` and whose Web.config has `<location path="health"><system.web><authorization><allow users="*"/></authorization></system.web></location>`.
- Test: `tests/test_dnl_auth.py`

**Interfaces:**
- `AuthInfo(protected: bool, source: str, roles: list[str], users: list[str], anonymous: bool, review: bool, file: str | None, line: int | None)`; `source` one of `"AllowAnonymous"`, `"attribute:<Name>"`, `"base:<Type>"`, `"global filter (mvc)"`, `"global filter (webapi)"`, `"web.config"`, `"base OnAuthorization override"`, `"none"`.
- `auth.auth_attribute_types(model) -> dict[str, TypeIR]` -- project types (keyed by simple name without `Attribute` suffix, case-insensitive) with `derives_from(t, {"AuthorizeAttribute", "AuthorizationFilterAttribute", "IAuthorizationFilter", "IAuthenticationFilter"})`.
- `auth.is_auth_attr(model, name: str) -> bool` -- `name == "Authorize"` or in `auth_attribute_types`.
- `auth.never_denies(t: TypeIR) -> bool` -- true when an `AuthorizeCore`/`IsAuthorized` override exists and every `return` in it returns literal `true`; or an `OnAuthorization` override exists whose body contains no assignment to a member named `Result`/`Response`, no `throw`, no call named `HandleUnauthorizedRequest`, and no `base.OnAuthorization` call.
- `auth.global_filters(model) -> list[tuple[str, str, str, int]]` -- `(kind, type_name, file, line)` for every `Add(new X(...))` call whose receiver text ends with `Filters` (case-insensitive); `kind="webapi"` when receiver text contains `config.` or the method's type is named `WebApiConfig`, else `"mvc"`.
- `auth.resolve(model, ref: RouteRef, filters, config_chain_for: Callable[[RouteRef], list[ET.Element]]) -> AuthInfo` in this order: action `[AllowAnonymous]` -> unprotected/anonymous; auth attribute on action, class, then base chain types (first found; a `never_denies` type counts as unprotected with that source); global filter of the matching kind (auth-like type); `webconfig.anonymous_denied(chain, route.path)`; a project base type in the chain overriding `OnAuthorization`/`OnActionExecuting` whose body references `IsAuthenticated`, calls `IsInRole`, or assigns `filterContext.Result` -> protected, `review=True`; else `"none"`. Roles/Users from `[Authorize(Roles=..., Users=...)]` named args.
- `rules_auth.check_routes(model, refs, filters, chain_for) -> list[Finding]` setting `route.auth_decorators = [info.source]` (when protected) on every ref.

Rules:
- DNL-AUTHZ-001: `not info.protected` -> `high` when verbs include POST/PUT/DELETE/PATCH explicitly declared, else `medium`; description names the source checked (`"No [Authorize], global filter, base controller or web.config rule covers this action."`).
- DNL-AUTHZ-002: `info.anonymous` and the action has an explicit mutating verb attribute -> `medium`, `REVIEW`.
- DNL-AUTHZ-003: one finding per `never_denies` auth attribute type, at its class line, `high` (emitted even when no route uses it).
- DNL-AUTHZ-004: protected by an attribute with no Roles/Users and (controller name minus `Controller` matches `(?i)admin|manage|role|permission|setting|config` or action name matches `(?i)^(delete|remove|purge|approve|grant|revoke|reset)`) -> `low`, `REVIEW`.
- DNL-CSRF-001: MVC (not webapi) action with an explicit POST/PUT/DELETE/PATCH verb attribute, no `ValidateAntiForgeryToken` attribute on action/class/base chain, and no global filter whose type is `ValidateAntiForgeryToken` or derives from it -> `medium`.
- All findings pass `route=ref.route` and `api_surface=ref.route.meta.get("api_surface", False)`.

- [ ] **Step 1: Write the failing tests**

```python
def info_of(results, handler): return next(i for r, i in results if r.route.handler_name == handler)

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
```

- [ ] **Step 2: Run**, expected FAIL. **Step 3: Implement.** **Step 4: Run**, expected PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: effective auth resolution, AUTHZ and CSRF rules"`

---

### Task 12: WebForms routes and auth (VB code-behind)

**Files:**
- Modify: `checks/dnl/routes.py` (`discover_webforms`), `checks/dnl/auth.py` (`resolve_webforms`)
- Create fixture `tests/fixtures/dotnet_legacy/webforms_vb/WebApp/`: `WebApp.vbproj` (legacy, VB), `Web.config` (`<authentication mode="Forms">`, root authorization allows all, `<location path="Secure">` denies `?`), `Default.aspx` + `Default.aspx.vb` (public), `Secure/Edit.aspx` + `Edit.aspx.vb` (`CodeBehind="edit.aspx.vb"` lowercase mismatch), `Members/List.aspx` + `List.aspx.vb` whose `Page_Load` does `If Not User.Identity.IsAuthenticated Then FormsAuthentication.RedirectToLoginPage()`, `Members/Base.vb` page base class, `Controls/Menu.ascx` + `.ascx.vb`.
- Test: `tests/test_dnl_webforms.py`

**Interfaces:**
- `routes.discover_webforms(model) -> list[RouteRef]` -- one per `.aspx`/`.asmx` (not `.ascx`) under each project dir; `path = "/" + posix path relative to the project dir`; methods `["GET", "POST"]`; `handler_name` = code-behind type simple name or page file name; code-behind from the `<%@ Page|WebService ... %>` directive's `Inherits` (full or simple name, case-insensitive) falling back to `CodeBehind`/`CodeFile` resolved with `resolve_ci`; `file`/`line` = the .aspx file line 1 (directive), `source_*` = code-behind type range when found; `meta = {"kind": "webforms", "api_surface": <True for .asmx>, "codebehind": rel or ""}`.
- `auth.resolve_webforms(model, ref, configs) -> AuthInfo` -- `anonymous_denied(config_chain(...), path)` -> source `"web.config"`; else the page type or a project base type in its chain has `Page_Load`/`Page_Init`/`OnInit`/`OnLoad`/`OnPreInit` whose body references member `IsAuthenticated`, calls `IsInRole`, or calls `RedirectToLoginPage` -> protected, source `"code-behind check"`, `review=True`; else `"none"`.
- `rules_auth.check_routes` handles webforms refs: DNL-AUTHZ-001 at `medium` (pages accept POST implicitly; severity does not escalate).

- [ ] **Step 1: Write the failing tests**

```python
def test_pages_found_controls_skipped(wf_refs):
    assert {r.route.path for r in wf_refs} == {"/Default.aspx", "/Secure/Edit.aspx", "/Members/List.aspx"}

def test_case_mismatched_codebehind_linked(wf_refs):
    r = next(r for r in wf_refs if r.route.path == "/Secure/Edit.aspx")
    assert r.type is not None and r.route.meta["codebehind"].lower() == "secure/edit.aspx.vb"

def test_webforms_auth_sources(wf_auth):
    assert wf_auth["/Secure/Edit.aspx"].source == "web.config"
    m = wf_auth["/Members/List.aspx"]; assert m.source == "code-behind check" and m.review
    assert not wf_auth["/Default.aspx"].protected

def test_public_page_flagged(wf_findings):
    f = one(wf_findings, "DNL-AUTHZ-001")
    assert f.route.path == "/Default.aspx" and f.severity == "medium"
```

- [ ] **Step 2: Run**, expected FAIL. **Step 3: Implement.** **Step 4: Run**, expected PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: WebForms routes and auth from web.config and code-behind"`

---

### Task 13: Analyzer wiring, README, end-to-end run, Linux check, real-target smoke run

**Files:**
- Modify: `languages/dotnet_legacy/analyzers.py`, `languages/dotnet_legacy/README.md`, `README.md` (supported-frameworks list), `code-review` memory note is updated by the session owner, not in repo
- Test: `tests/test_dnl_end_to_end.py`

**Interfaces:**
- `@register("dotnet_legacy", "mvc")`, `"webapi"`, `"webforms"`, `"config"` analyzers, each subclassing `BaseFrameworkAnalyzer`, overriding `analyze()` to set `ScanResult.degraded = model.degraded` and `notes` from `model.notes` (config analyzer adds config notes). Each uses `project.get_model(self.target_path)`; routes/auth computed once per model and cached on it (`model.cache` dict). `mvc` returns mvc routes + their findings + AUTHZ-003 for attribute types in projects referencing `system.web.mvc`; `webapi` likewise for webapi routes and remaining AUTHZ-003; `webforms` its routes/findings; `config` returns `check_configs(...)` findings with `api_surface_dirs` = dirs of projects referencing `system.web.http` and `has_aspx_dirs` = dirs of projects containing `.aspx`. In degraded mode the code-driven analyzers return no routes and the config analyzer still runs.
- README: rule table (id, severity, what, OWASP 2025/2021/API), detection, preflight/`--allow-degraded`, Linux install, what still needs a human, the "later plans" coverage gaps.

- [ ] **Step 1: Write the failing test**

```python
def test_end_to_end_cli(tmp_path, monkeypatch):
    out = tmp_path / "r.json"
    monkeypatch.setattr(sys, "argv", ["main.py", str(FX / "mvc5_app"), "--json", str(out), "--html", str(tmp_path / "r.html")])
    assert main.main() == 0
    data = json.loads(out.read_text())
    fw = {r["framework"] for r in data if r["language"] == "dotnet_legacy"}
    assert fw == {"mvc", "webapi", "config"}
    ids = {f["check_id"] for r in data for f in r["findings"]}
    assert {"DNL-AUTHZ-001", "DNL-AUTHZ-003", "DNL-CFG-001"} <= ids
    assert all(f["owasp"] for r in data if r["language"] == "dotnet_legacy" for f in r["findings"])
    assert 'id="tab-panel-owasp"' in (tmp_path / "r.html").read_text()

def test_degraded_cli(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    project._CACHE.clear()
    monkeypatch.setattr(sys, "argv", ["main.py", str(FX / "mvc5_app"), "--allow-degraded", "--html", str(tmp_path / "r.html")])
    assert main.main() == 0 and "degraded-banner" in (tmp_path / "r.html").read_text()
```

- [ ] **Step 2: Run**, expected FAIL. **Step 3: Implement** analyzers + READMEs. **Step 4: Run** the file, then `python -m pytest -q`, expected all PASS.
- [ ] **Step 5: Linux check.** Run the full suite on Linux: `wsl -e bash -lc "cd <repo path under /mnt/c> && python3 -m venv /tmp/cr && /tmp/cr/bin/pip install -q -r requirements.txt pytest && /tmp/cr/bin/python -m pytest -q"` (WSL must have `dotnet-sdk-8.0`), or the equivalent in a `mcr.microsoft.com/dotnet/sdk:8.0` container with python3 installed. Expected: all PASS. If neither WSL nor Docker is available, stop and tell the user; do not claim Linux verification.
- [ ] **Step 6: Real-target smoke run** (nothing committed): `python main.py <target dir> --html <scratch>/target.html --json <scratch>/target.json`. Expected: exit 0, routes listed for every MVC / Web API / WebForms app in the target, web.config findings present, no findings under `packages/` or `Precompiled*`, helper run once. Record per-rule counts and any crash/notes for the user; tune only with synthetic fixture reproductions.
- [ ] **Step 7: Commit** `git commit -m "dotnet_legacy: register analyzers, README, end-to-end tests"`
