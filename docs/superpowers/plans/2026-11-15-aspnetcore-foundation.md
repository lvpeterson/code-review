# ASP.NET Core Foundation Implementation Plan (Plan 1 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Send SDK-style ASP.NET Core projects through the shared C# engine (`checks/dnl`): the Roslyn helper compiles them against ASP.NET Core reference assemblies, routes are found for controllers, Razor Pages and minimal APIs, effective auth is resolved per route (three-state), and a rewritten `dotnet` language package reports them, replacing the tree-sitter `aspnet_analyzer`.

**Architecture:** One `ProjectModel` per scan holds every project; each project gets a reference profile (`net48` / `netcore`) and an owner package (`dotnet_legacy` / `dotnet`), and each language package reads a filtered view of the model, so the helper runs once and a project is never analyzed by both packages. A new `pipeline.py` turns `Program.cs` / `Startup` code into ordered, environment-tagged call facts that `routes_core.py` (route discovery) and `auth_core.py` (auth resolution) share. `rules_auth_core.py` turns resolved auth into the existing `DNL-AUTHZ-*` findings.

**Tech Stack:** Python 3.10+, pytest, Roslyn helper (C#, .NET 8 SDK), tree-sitter-c-sharp (degraded mode).

**Spec:** `docs/superpowers/specs/2026-11-14-aspnetcore-design.md` (Goals; Project model; Roslyn helper; Routes; Auth; Decisions 1-8). Plans 2-4 cover taint/object rules, configuration rules, and SCA/coverage/acceptance.

## Global Constraints

- Public repo: nothing committed (code, fixtures, tests, README, docs, commit messages) may name a client, engagement, target app, local path or user. All fixtures synthetic, generic names. Grep the diff before every commit.
- Prose and comments use `--`, never em-dashes; comment density like the existing `checks/dnl/*.py`.
- Tests: `.venv\Scripts\python -m pytest -q` from the repo root. Baseline on `main` at branch time: 1210 passed (about 5 minutes); every existing test stays green except the ones this plan explicitly replaces (`tests/test_aspnet_analyzer.py`, the `dotnet` case in `tests/test_owasp_all_rules.py`, schema-1 asserts in `tests/test_dnl_helper_ir.py`). Must also pass on Linux.
- Helper-dependent tests use the `roslyn_helper` fixture (skipped without the SDK); degraded tests monkeypatch `helper.find_helper` and `helper.sdk_available` (setting `CODE_REVIEW_ROSLYN_IR` to a missing file is not enough).
- A false "safe" is the worst outcome: unknown auth is reported as REVIEW, never as protected. Noise is secondary.
- No regression for dotnet_legacy: existing dotnet_legacy tests pass unchanged; a mixed solution produces the same legacy findings; the helper runs once per scan.
- Rule ids are quoted literals. Every new id gets a `core/owasp_web.RULES` entry and a row in `languages/dotnet_legacy/README.md` (the DNL rule table, enforced by `test_readme_lists_every_rule_with_tags`) in the task that adds it.
- .NET 8 SDK is the only toolchain; reference assemblies come from NuGet packages pinned to 8.0.x, never the local SDK `packs/` folder.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Branch `feature/aspnetcore-foundation`. No push, no merge.

## Builder notes vs the spec (decided here)

1. **Middleware sanity (spec Auth step 5).** In ASP.NET Core, an endpoint carrying auth metadata with no authorization middleware does not run unprotected: `EndpointMiddleware` throws ("contains authorization metadata, but a middleware was not found that supports authorization") unless `RouteOptions.SuppressCheckForUnhandledSecurityMetadata = true`. Since .NET 7, `WebApplication` also adds `UseAuthentication`/`UseAuthorization` itself when the services are registered and the app did not call them. So: a missing or misordered `UseAuthorization` is reported as its own finding (`DNL-AUTHZ-008`, the app is broken and fails closed); routes are downgraded to unprotected only when the suppress flag is set. Minimal-hosting apps targeting net7.0+ never get "missing UseAuthorization".
2. **Unresolved extension calls (Decision 2).** Third-party registrations are routinely unresolved (EF Core, Swashbuckle, JWT bearer are NuGet packages outside the ref packs). A fixed table `_NON_AUTHZ_EXTENSIONS` (Task 9) lists well-known registrations that cannot change authorization (scheme handlers, data, docs, logging); every other unresolved extension on a services/app/endpoint builder makes affected routes unknown, as the spec says.
3. **Rule ids.** Missing/anonymous/inferred auth reuse `DNL-AUTHZ-001`/`002`/`004`; never-denying handlers and policies reuse `DNL-AUTHZ-003`. One new id: `DNL-AUTHZ-008`.
4. **Coverage accounting (Decision 6) moves into this plan.** Retiring `aspnet_analyzer` removes the only non-DNL ids from `languages/dotnet`, and `tests/test_owasp_readme.py::test_every_family_has_rules` requires the `dotnet` row to be non-empty, so the inventory's DNL pass lands in Task 11.
5. **Verbs.** A controller action with no `[Http*]`/`[AcceptVerbs]` accepts any verb in ASP.NET Core; its route gets `methods=["ANY"]`.

## New and reused rule ids

| id | sev | 2025 | 2021 | API (mode) | what (dotnet) |
|---|---|---|---|---|---|
| DNL-AUTHZ-001 | medium/high; low REVIEW; medium REVIEW; info | A01 | A01 | API5 (api_surface) | reused: route unprotected (high when an explicit mutating verb); unknown auth (medium REVIEW, reasons listed); `[AllowAnonymous]`/`.AllowAnonymous()` (info) |
| DNL-AUTHZ-002 | medium REVIEW | A01 | A01 | API5 | reused: anonymous route with an explicit mutating verb |
| DNL-AUTHZ-003 | high | A01 | A01 | API5 | reused: `AuthorizationHandler<T>`/`IAuthorizationHandler` that succeeds unconditionally, policy built only from `RequireAssertion(_ => true)`, or a custom authorization filter attribute that never sets `context.Result` |
| DNL-AUTHZ-004 | low REVIEW | A01 | A01 | API5 | reused: privileged-looking controller/action/page protected without roles or a policy |
| DNL-AUTHZ-008 | medium | A01 | A01 | API5 (api_surface) | new: `UseAuthorization` missing, before `UseRouting`, or before `UseAuthentication` in an app with explicit routing (Startup style, or minimal hosting below net7.0); high when `SuppressCheckForUnhandledSecurityMetadata = true` |

## Review Focus

1. `[Authorize]` on a Razor Pages handler method (`OnPostDelete`) is ignored by the framework; a page whose PageModel class has no auth must still be reported unprotected, with a note saying the method attribute has no effect (test in Task 9).
2. Endpoints registered inside an extension method that no entry point reaches (or reaches through a chain the engine cannot trace) must resolve to unknown (REVIEW) when nothing else protects them, never to protected (tests in Tasks 8 and 9).
3. A project with both top-level statements and `partial class Program`, and a project using `Startup` via `UseStartup<Startup>()`, must both yield their service registrations and middleware in order (test in Task 5).
4. Nested projects (a test project or sample under another project's folder) own their own files: no file is sent to the helper twice or analyzed under two projects (test in Task 4).
5. `AddJwtBearer`/`AddDbContext`/`AddSwaggerGen` left unresolved must not make every route unknown, while an unresolved `services.AddCompanyAuth()` must (test in Task 9).

---

### Task 1: Helper `netcore` reference profile and request keys

**Files:**
- Modify: `tools/roslyn-ir/src/RoslynIr.csproj`, `tools/roslyn-ir/src/Semantics.cs`, `tools/roslyn-ir/src/Program.cs`, `tools/roslyn-ir/src/IrWriter.cs` (schema constant), `tools/roslyn-ir/README.md`
- Modify: `checks/dnl/helper.py` (`SCHEMA_VERSION = 2`)
- Test: `tests/test_dnl_helper_ir.py`

**Interfaces:**
- Produces: request project keys `"refs": "net48" | "netcore"` (default `"net48"`) and `"global_usings": [str]` (optional, namespaces); probe output `{"ok": true, "schema": 2}`; helper.SCHEMA_VERSION == 2.
- The `references` key stays accepted and ignored.

- [ ] **Step 1: Write the failing tests** in `tests/test_dnl_helper_ir.py` (extend `run_parse` to pass optional per-project `refs` and `global_usings`):
  - `test_probe` now asserts `{"ok": True, "schema": 2}`.
  - `test_netcore_profile_resolves_aspnetcore_symbols`: a file `using Microsoft.AspNetCore.Mvc; public class C : ControllerBase { public IActionResult A() { return Ok(); } }` sent with `refs="netcore"`: the call node for `Ok()` has `sym == "Microsoft.AspNetCore.Mvc.ControllerBase.Ok"`.
  - `test_net48_default_unchanged`: the same request without `refs` gives no `sym` on `Ok()` (net48 has no ASP.NET Core).
  - `test_global_usings_apply`: file `public class C { void M(HttpContext c) { var q = c.Request.Query["x"]; } }` with `refs="netcore"`, `global_usings=["Microsoft.AspNetCore.Http"]`: the member node for `Query` has `sym == "Microsoft.AspNetCore.Http.HttpRequest.Query"`.
  - `test_probe_rejects_schema_1` in `tests/test_dnl_preflight.py` (no helper build; reuse that file's fake-binary pattern): a fake helper printing `{"ok": true, "schema": 1}` makes `probe()` raise `PreflightError` whose message contains `schema 1` and `expected 2`.

- [ ] **Step 2: Run them to verify they fail**
  Run: `.venv\Scripts\python -m pytest tests/test_dnl_helper_ir.py tests/test_dnl_preflight.py -q`
  Expected: FAIL (schema 1, no sym on `Ok`).

- [ ] **Step 3: Copy the netcore refs at build time.** In `RoslynIr.csproj` add `<PackageDownload Include="Microsoft.NETCore.App.Ref" Version="[8.0.11]" />` and `<PackageDownload Include="Microsoft.AspNetCore.App.Ref" Version="[8.0.11]" />` (these are DotnetPlatform packages: `PackageReference` fails with NU1213, `PackageDownload` works; if 8.0.11 does not restore, use the newest 8.0.x and record it). Copy `$(NuGetPackageRoot)microsoft.netcore.app.ref/<ver>/ref/net8.0/*.dll` and the AspNetCore equivalent to `refs/netcore/` with the same `None ... Link=... CopyToOutputDirectory/CopyToPublishDirectory` pattern as `refs/net48`. Lower-case package folder names keep Linux working.

- [ ] **Step 4: Profile-keyed references in `Semantics.cs`.** Replace the single `Refs` with a per-profile lazy cache: `static IReadOnlyList<MetadataReference> RefsFor(string profile)` loading `refs/<profile>/*.dll`; `public static int RefCount(string profile)`. `Compile(language, project, trees, extraImports, string profile = "net48", IReadOnlyList<string>? globalUsings = null)`: for C# with global usings, add one extra syntax tree whose text is `global using global::<ns>;` per namespace (parsed with the same parse options). Unknown profile names fall back to `net48` with a stderr warning.

- [ ] **Step 5: Request keys and probe in `Program.cs`.** Read optional `refs` and `global_usings` per project and pass them to `Compile`. `Probe` fails (exit 1, message naming the missing folder) when either `RefCount("net48")` or `RefCount("netcore")` is 0, and also compiles a third snippet (`using Microsoft.AspNetCore.Mvc; [ApiController] public class C : ControllerBase { public IActionResult A() => Ok(); }`) with `netcore`. Bump `IrWriter.Schema` to 2. Update the CLI doc comment and `tools/roslyn-ir/README.md` (request keys, refs folders, schema 2).

- [ ] **Step 6: Bump `checks/dnl/helper.py` `SCHEMA_VERSION` to 2** and fix any test asserting schema 1.

- [ ] **Step 7: Run tests to verify they pass**
  Run: `.venv\Scripts\python -m pytest tests/test_dnl_helper_ir.py tests/test_dnl_preflight.py -q`
  Expected: PASS. Then the full suite: PASS.

- [ ] **Step 8: Commit** `feat(roslyn-ir): netcore reference profile, global usings, schema 2`

---

### Task 2: Helper lowering for modern C#

**Files:**
- Modify: `tools/roslyn-ir/src/CSharpLowering.cs`
- Modify: `checks/dnl/ir.py` (constant and helper only)
- Test: `tests/test_dnl_helper_ir.py`

**Interfaces:**
- Produces in IR (schema 2):
  - A file with top-level statements gets a synthetic type `{"name": "Program", "namespace": "", "kind": "class", "modifiers": ["static", "partial"], ...}` holding one method named `<Main>$` whose body is the global statements in order (local functions stay `local` statements with a `lambda` init, as today). Emitted before the file's declared types. A declared `partial class Program` in the same project stays a separate TypeIR.
  - Lambdas gain optional `"param_info": [{"name": str, "type": str | null, "attributes": [Attr], "modifiers": [str]}]` (omitted when there are no parameters) and `"end_line": int`. The existing `params` (names) stays.
  - Primary constructors (class/struct/record `ParameterList`) lower to a `.ctor` method with those params (attributes kept); a base-list argument list (`: Base(x)`) becomes the leading `base(...)` call statement as for constructor initializers. Positional record parameters also emit one property each (name, type, attributes, line).
  - Collection expressions `[a, ..b]` lower to `new` with `type: null`, `args: []`, `init` entries (spread elements contribute their inner expression).
  - Switch expressions lower to nested `cond` nodes: `c` = governing expression, `t` = arm expression, `f` = the rest (last arm's `f` is the last arm's expression).
  - `is` patterns lower to `bin` with `op: "is"`, `l` = the tested expression, `r` = an `unknown` node carrying the pattern text. Binding the declared variable of `x is T v` to `x` is left to Plan 2 (taint), which owns that decision.
  - `with` expressions lower to `new` with `type: null`, `args: [receiver]`, `init` entries from the initializer.
  - Raw string literals (single and multi-line) lower to `lit` strings (verify; add the case if Roslyn reports a different kind).
- `checks/dnl/ir.py`: `TOP_LEVEL_MAIN = "<Main>$"` and `def is_top_level(m: MethodIR) -> bool`.

- [ ] **Step 1: Write the failing tests** (all parse with `refs="netcore"`):
  - `test_top_level_statements_lowered`: `var b = WebApplication.CreateBuilder(args);\nvar app = b.Build();\napp.MapGet("/", () => "x");\napp.Run();\nstatic int Helper() => 1;\n` -> types[0] is `Program` with one method `<Main>$`; its body has 4 statements before the `local` for `Helper`; the `MapGet` call has `sym == "Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions.MapGet"`.
  - `test_top_level_with_partial_program`: same file plus `public partial class Program { }` -> two TypeIR named `Program`, the synthetic one first.
  - `test_lambda_param_info_and_end_line`: `app.MapGet("/o/{id}", ([FromRoute] int id, [FromServices] IStore s) =>\n{\n return s.Get(id);\n});` -> lambda `param_info` names `["id", "s"]`, types `["int", "IStore"]`, attribute names `["FromRoute"]`, `["FromServices"]`; `end_line` is the line of the closing brace.
  - `test_primary_constructor_and_record`: `public class Svc(ILogger<Svc> log, IStore store) : Base(store) { }` and `public record OrderDto([property: Required] string Name, int Qty);` -> Svc has `.ctor` with params `log`, `store` and a leading `base` call; OrderDto has properties `Name`, `Qty` and a `.ctor`.
  - `test_collection_switch_is_with`: in a method, `int[] a = [x, ..ys];`, `var s = k switch { 1 => p, _ => q };`, `if (o is string t) {}`, `var r2 = r with { Name = n };` -> the four shapes above (`new`/`cond`/`bin is`/`new`), and `walk()` over each finds the `name` nodes `x`, `ys`, `p`, `q`, `o`, `r`, `n`.
  - `test_raw_string_literal`: `var q = """SELECT 1""";` -> `lit` with `v == "SELECT 1"`.

- [ ] **Step 2: Run to verify they fail** (`pytest tests/test_dnl_helper_ir.py -q -k "top_level or lambda_param or primary or collection or raw_string"`). Expected: FAIL.

- [ ] **Step 3: Implement in `CSharpLowering.cs`.** Top-level: in `WriteFile`, collect `root.Members.OfType<GlobalStatementSyntax>()` and, if any, write the synthetic type first (statements through `Seq`, so `using var` keeps its wrapping). Lambda `param_info`/`end_line` in the `AnonymousFunctionExpressionSyntax` case. Primary ctor in `Type` via `TypeDeclarationSyntax.ParameterList` and `PrimaryConstructorBaseTypeSyntax`. New `ExprCore` cases for `CollectionExpressionSyntax`, `SwitchExpressionSyntax`, `IsPatternExpressionSyntax`, `WithExpressionSyntax`. Keep the "never throws on an unfamiliar node" contract. Add `TOP_LEVEL_MAIN`/`is_top_level` to `ir.py`.

- [ ] **Step 4: Run to verify they pass**, then the full suite (legacy IR shape unchanged for legacy code). Expected: PASS.

- [ ] **Step 5: Commit** `feat(roslyn-ir): lower top-level statements, primary ctors, records, lambda params, modern expressions`

---

### Task 3: Degraded-mode lowering parity

**Files:**
- Modify: `checks/dnl/frontend_ts.py`
- Test: `tests/test_dnl_degraded.py`

**Interfaces:**
- Consumes: the IR shapes Task 2 produces.
- Produces: `frontend_ts.lower_file` emits the same synthetic `Program`/`<Main>$` type for `global_statement` nodes, lambda `param_info`/`end_line`, primary-ctor `.ctor` and record properties, and the collection/switch/is/with shapes. No `sym`/`type_full` keys (unchanged rule).

- [ ] **Step 1: Write the failing tests** in `tests/test_dnl_degraded.py` mirroring Task 2's six tests through the module's `lower()` helper (same sources, same structural asserts, minus every `sym` assert). Add `test_top_level_if_directive_branches`: top-level statements inside `#if DEBUG ... #else ... #endif` keep both branches (the module's `_variants` rule).

- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.

- [ ] **Step 3: Implement** in `_Lowering` (collect `global_statement` children of `compilation_unit`, including inside unwrapped `#if` regions; the rest as listed). Keep per-member crash isolation.

- [ ] **Step 4: Run to verify they pass**, then `tests/test_dnl_degraded.py` in full. Expected: PASS.

- [ ] **Step 5: Commit** `feat(dnl): degraded lowering for top-level statements and modern C#`

---

### Task 4: SDK project model, profiles, ownership views, one helper run

**Files:**
- Modify: `checks/dnl/project.py`, `checks/dnl/files.py` (only if a helper is needed), `enumerator.py`, `languages/dotnet_legacy/detector.py`, `languages/dotnet_legacy/analyzers.py`
- Create: `tests/fixtures/aspnetcore/mixed_solution/` (see Step 1), `tests/test_dnl_sdk_projects.py`

**Interfaces:**
- Produces in `checks/dnl/project.py`:
  - `Project` new fields: `sdk: str | None = None`, `target_frameworks: list[str]`, `packages: dict[str, str]` (lower-cased id -> version string), `framework_refs: set[str]`, `profile: str = "net48"`, `global_usings: list[str]`; property `owner -> "dotnet" | "dotnet_legacy"` (`"dotnet"` iff `profile == "netcore"`).
  - `def profile_for(tfms: list[str]) -> str`: `"netcore"` if any of `netcoreapp*`, `netstandard*`, `net5.0`+ (dotted, optional `-platform` suffix); `"net48"` for `net4x`/`net4xx` (undotted) and for an empty list on a legacy project. An SDK project with no TFM at all -> `"netcore"` plus a model note.
  - `def implicit_usings(sdk: str | None) -> list[str]`: `Microsoft.NET.Sdk` -> `System, System.Collections.Generic, System.IO, System.Linq, System.Net.Http, System.Threading, System.Threading.Tasks`; `Microsoft.NET.Sdk.Web` adds `System.Net.Http.Json, Microsoft.AspNetCore.Builder, Microsoft.AspNetCore.Hosting, Microsoft.AspNetCore.Http, Microsoft.AspNetCore.Routing, Microsoft.Extensions.Configuration, Microsoft.Extensions.DependencyInjection, Microsoft.Extensions.Hosting, Microsoft.Extensions.Logging`; `Microsoft.NET.Sdk.Worker` adds the last four Extensions namespaces. Applied only when `ImplicitUsings` is `enable`/`true`; `<Using Include>` adds, `<Using Remove>` removes.
  - `ProjectModel.parent: ProjectModel | None = None` and `def view(self, owner: str) -> ProjectModel` (cached; projects filtered by `owner`; files filtered to those whose project's owner matches; shares `root`, `degraded`, `notes` list object; own `cache`; `parent` set). Loose files: a `(loose)` C# project per owner, split by `def is_core_source(text: str) -> bool` (true when the text mentions `WebApplication`, `using Microsoft.AspNetCore`, `ControllerBase` or `IEndpointRouteBuilder`, comments ignored).
  - net48-profile SDK projects map `PackageReference` ids onto the legacy `references` names the legacy package already reads: `Microsoft.AspNet.Mvc` -> `system.web.mvc`, `Microsoft.AspNet.WebApi.Core` -> `system.web.http`, `Microsoft.AspNet.WebPages` -> `system.web.webpages`; the legacy detector registers `mvc`/`webapi` from those package ids too.
  - `def get_model(target: Path, owner: str | None = None) -> ProjectModel` (None = full model).
  - `_request` sends legacy, loose and SDK C# projects, each with `"refs": p.profile` and, for netcore, `"global_usings"`. SDK `.vbproj` projects targeting netcore are skipped with one note (non-goal).
- Produces in `enumerator.py`: the model is prepared once per `enumerate_target` call when `dotnet` or `dotnet_legacy` runs (a `prepared` flag passed to `_run_frameworks`).
- dotnet_legacy: its detector claims SDK projects whose profile is `net48` (decision 1) using `profile_for`; `languages/dotnet_legacy/analyzers.py` reads `project.get_model(target, "dotnet_legacy")`; the "notes taken" flag lives on `(model.parent or model).cache`.

- [ ] **Step 1: Create the `mixed_solution` fixture** (synthetic): `Legacy/Legacy.csproj` (old-style, `ToolsVersion`, `<Reference Include="System.Web.Mvc" />`, `<Compile Include="Controllers\HomeController.cs" />`) with an MVC 5 `HomeController : Controller` (`Index`, unauthenticated `[HttpPost] Delete(int id)`); `Modern/Modern.csproj` (`Microsoft.NET.Sdk.Web`, `net8.0`, `ImplicitUsings enable`, `<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />`) with top-level `Program.cs` (`AddControllers`, `MapControllers`) and `Controllers/PingController.cs` (`[ApiController][Route("ping")] : ControllerBase`, `[HttpGet] Get()`); `Framework/Framework.csproj` (`Microsoft.NET.Sdk`, `<TargetFramework>net472</TargetFramework>`, `<PackageReference Include="Microsoft.AspNet.Mvc" Version="5.2.9" />`) with `Controllers/OldController.cs : System.Web.Mvc.Controller`; `Modern/tests/Modern.Tests/Modern.Tests.csproj` (`Microsoft.NET.Sdk`, `net8.0`) with `PingTests.cs`; `Directory.Packages.props` at the root with `<PackageVersion Include="Serilog" Version="3.1.1" />` and `Modern` also referencing `<PackageReference Include="Serilog" />` (central version).

- [ ] **Step 2: Write the failing tests** in `tests/test_dnl_sdk_projects.py`:
  - `test_profile_for`: `["net8.0"]`, `["net8.0-windows"]`, `["netcoreapp3.1"]`, `["netstandard2.0"]` -> netcore; `["net472"]`, `["net48"]` -> net48; `["net48", "net8.0"]` -> netcore.
  - `test_sdk_project_parsed` (no helper; `load_projects`): Modern has `sdk == "Microsoft.NET.Sdk.Web"`, `target_frameworks == ["net8.0"]`, `packages == {"newtonsoft.json": "13.0.3", "serilog": "3.1.1"}`, `profile == "netcore"`, `"Microsoft.AspNetCore.Http" in global_usings`; Framework has `profile == "net48"`, `owner == "dotnet_legacy"`, `"system.web.mvc" in references`; `languages.dotnet_legacy.detector.detect_frameworks(mixed_solution)` includes `"mvc"`.
  - `test_nested_project_owns_its_files`: `PingTests.cs` is in `Modern.Tests.compile_files` and not in `Modern.compile_files`; across all projects every file appears once.
  - `test_compile_remove_and_include`: tmp project with `<Compile Remove="Generated\**" />` and `<Compile Include="..\Shared\Common.cs" />` -> the generated file is excluded and the shared file included.
  - `test_directory_build_props_tfm`: tmp root `Directory.Build.props` setting `<TargetFramework>net8.0</TargetFramework>` and `<ImplicitUsings>enable</ImplicitUsings>`, project with neither -> netcore with implicit usings.
  - `test_request_carries_profiles` (no helper): `project._request(load_projects(...))` has one entry per C# project, `refs` values match profiles, Modern has `global_usings`, no file path appears twice.
  - `test_views_split_by_owner` (roslyn_helper): `prepare(mixed_solution, False)`; `get_model(root, "dotnet")` types include `PingController` and `Program`, not `HomeController`/`OldController`; the legacy view includes both legacy controllers and not `PingController`.
  - `test_helper_runs_once_for_both_packages` (roslyn_helper): monkeypatch `helper.parse_projects` with a counting wrapper; `enumerate_target(mixed_solution)` -> count == 1.
  - `test_legacy_findings_unchanged_in_mixed_solution` (roslyn_helper): dotnet_legacy findings (check id, file, line) for `mixed_solution` restricted to `Legacy/` equal those from scanning a tmp copy of `Legacy/` alone.
  - `test_loose_core_file_goes_to_dotnet` (no helper): a loose `Program.cs` using `WebApplication` lands in the netcore loose project; a loose plain class in the net48 one.

- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.

- [ ] **Step 4: Implement** `_load_sdk_project` (properties from `Directory.Build.props` up to the scan root, nearest wins, project file overrides; `PackageReference` `Version` attribute or child element, else `Directory.Packages.props` `PackageVersion`; `VersionOverride` wins), deepest-project-wins file ownership, `profile_for`, `implicit_usings`, `view`, `get_model(owner)`, `_request`/`_degraded_files` over all C# projects, enumerator once-per-scan prepare, legacy detector/analyzer switch to the legacy view.

- [ ] **Step 5: Run to verify they pass**, then the full suite (every dotnet_legacy test, including `mvc5_app` with its `CoreSide` SDK project). Expected: PASS.

- [ ] **Step 6: Commit** `feat(dnl): parse SDK projects, reference profiles and per-package model views`

---

### Task 5: Pipeline facts (`pipeline.py`)

**Files:**
- Create: `checks/dnl/pipeline.py`
- Modify: `checks/dnl/ir.py` (add `call_chain`)
- Create: `tests/fixtures/aspnetcore/pipelines/` (small projects, see Step 1), `tests/test_dnl_pipeline.py`

**Interfaces:**
- Produces in `checks/dnl/ir.py`: `def call_chain(expr: dict) -> tuple[dict | None, list[dict]]` -- for `a.B(x).C().D(y)` returns (`name a` node, [call B, call C, call D]) innermost first; for a non-chain returns `(expr, [])`.
- Produces in `checks/dnl/pipeline.py`:
  ```python
  @dataclass
  class PipeCall:
      name: str            # method name, e.g. "UseAuthorization"
      kind: str            # "services" | "app" | "endpoints" | "other"
      node: dict           # the call expr
      chain: list[dict]    # the full fluent chain this call sits in (call_chain order)
      file: str
      line: int
      env: str | None      # None = always; "Development"; "!Development"; other env names as written
      resolved: bool       # sym present, or name in _FRAMEWORK_CALLS, or a followed solution method
      order: int           # execution order within the pipeline

  @dataclass
  class Pipeline:
      project: Project | None
      style: str           # "minimal" | "startup" | "none"
      calls: list[PipeCall]
      target_framework: str | None
      def named(self, *names: str, kinds: tuple[str, ...] = (), include_dev: bool = False) -> list[PipeCall]: ...
      def unresolved(self) -> list[PipeCall]: ...

  def pipeline_for(model: ProjectModel, proj: Project | None) -> Pipeline   # cached on model.cache["pipelines"]
  ```
- Entry points per netcore project: `<Main>$` bodies; else a `Startup` class (named `Startup`, or the `T` of `UseStartup<T>()`) with `ConfigureServices` then `Configure` (all partial halves); else a static `Main`. Calls to solution methods (a unique method by name in the project, or an extension method whose first parameter has `this`) are followed inline at the call site, depth limit 8, cycle guard; lambdas passed as arguments (`AddAuthorization(o => ...)`, `UseEndpoints(e => ...)`) are not separate calls -- rules read them from `node`.
- `env` comes from enclosing `if` conditions: `IsDevelopment()` (then -> `"Development"`, else -> `"!Development"`), `!IsDevelopment()`, `IsEnvironment("X")`, `IsProduction()`/`IsStaging()`.
- `kind`: by resolved `sym` owner (`Microsoft.Extensions.DependencyInjection.*` or `IServiceCollection` -> services; `Microsoft.AspNetCore.Builder.*EndpointRouteBuilder*`/`*Endpoint*Extensions` -> endpoints; other `Microsoft.AspNetCore.Builder.*`/`IApplicationBuilder`/`WebApplication` -> app), else by the chain root (`*.Services`/`services` -> services; `endpoints`/`e` inside `UseEndpoints` -> endpoints; locals assigned from `.Build()`, parameters typed `IApplicationBuilder`/`WebApplication` -> app; `Map*` names -> endpoints).
- `_FRAMEWORK_CALLS`: frozenset of ASP.NET Core/Extensions method names treated as resolved in degraded mode (at least: `AddControllers, AddControllersWithViews, AddMvc, AddRazorPages, AddRazorPagesOptions, AddAuthentication, AddAuthorization, AddAuthorizationBuilder, AddCookie, AddPolicy, SetFallbackPolicy, SetDefaultPolicy, AddCors, AddSession, AddAntiforgery, AddRateLimiter, AddHealthChecks, AddSignalR, AddGrpc, AddEndpointsApiExplorer, AddHttpClient, AddDataProtection, Configure, UseRouting, UseAuthentication, UseAuthorization, UseEndpoints, UseHttpsRedirection, UseHsts, UseStaticFiles, UseCors, UseSession, UseExceptionHandler, UseDeveloperExceptionPage, UseRateLimiter, UseAntiforgery, Map, MapGet, MapPost, MapPut, MapPatch, MapDelete, MapMethods, MapGroup, MapControllers, MapControllerRoute, MapDefaultControllerRoute, MapAreaControllerRoute, MapRazorPages, MapHub, MapGrpcService, MapHealthChecks, MapFallback, MapFallbackToFile, MapFallbackToPage, MapFallbackToController, MapRazorComponents, MapBlazorHub, MapOpenApi, RequireAuthorization, AllowAnonymous, Build, Run, RunAsync`).

- [ ] **Step 1: Create the fixtures**: `pipelines/minimal/` (top-level Program.cs: `AddAuthentication`, `AddAuthorization(o => o.FallbackPolicy = ...)`, `if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); } else { app.UseExceptionHandler("/error"); }`, `UseRouting`, `UseAuthentication`, `UseAuthorization`, `app.AddAppServices()` style call into `ServiceSetup.cs` holding `public static void AddAppServices(this IServiceCollection s) { s.AddCors(); }`, plus `public partial class Program { }`); `pipelines/startup/` (static `Main` -> `Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(w => w.UseStartup<Startup>())`; `Startup` split across two partial files, `ConfigureServices` in one calling `AddControllers()` and `services.AddCompanyAuth()` (defined nowhere), `Configure` in the other with `UseAuthorization()` before `UseRouting()`).

- [ ] **Step 2: Write the failing tests** in `tests/test_dnl_pipeline.py`:
  - `test_call_chain`: hand-built IR for `app.MapGroup("/a").RequireAuthorization().MapGet("/b", h)` -> root `name app`, call names `["MapGroup", "RequireAuthorization", "MapGet"]`.
  - `test_minimal_pipeline_order_and_env` (roslyn_helper): names in order include `AddAuthentication, AddAuthorization, AddCors, UseDeveloperExceptionPage, UseExceptionHandler, UseRouting, UseAuthentication, UseAuthorization`; `UseDeveloperExceptionPage.env == "Development"`, `UseExceptionHandler.env == "!Development"`, `UseRouting.env is None`; `AddCors` came from the followed extension (its `file` is `ServiceSetup.cs`); `style == "minimal"`.
  - `test_startup_pipeline_partial_and_order` (roslyn_helper): `style == "startup"`; `AddControllers` before `UseAuthorization` before `UseRouting`; `AddCompanyAuth` is in `unresolved()` with `kind == "services"`.
  - `test_degraded_pipeline_same_facts` (no helper, monkeypatched): the minimal fixture gives the same name order and env tags; `AddAuthorization.resolved` is True by `_FRAMEWORK_CALLS`.
  - `test_follow_depth_and_cycles`: two solution extension methods calling each other -> terminates, each call appears once.

- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.

- [ ] **Step 4: Implement** `call_chain` and `pipeline.py` per the interface.

- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.

- [ ] **Step 6: Commit** `feat(dnl): ASP.NET Core pipeline facts from Program.cs and Startup`

---

### Task 6: Controller routes

**Files:**
- Create: `checks/dnl/routes_core.py`, `tests/fixtures/aspnetcore/controllers_api/` (see Step 1), `tests/test_dnl_routes_core.py`
- Modify: `checks/dnl/routes.py` (make `_action_candidates` and `_strip_constraints` public as `action_candidates`/`strip_constraints`, keeping legacy callers working)

**Interfaces:**
- Consumes: `pipeline_for` (Task 5), `RouteRef`, `action_candidates`, `strip_constraints`.
- Produces:
  ```python
  @dataclass
  class Group:
      prefix: str
      calls: list[dict]        # fluent calls applied to the group (RequireAuthorization, AllowAnonymous, AddEndpointFilter, ...)
      file: str
      line: int

  @dataclass
  class CoreRouteRef(RouteRef):
      style: str = "controller"                  # "controller" | "razorpage" | "minimalapi" | "endpoint"
      endpoint_calls: list[dict] = field(default_factory=list)
      groups: list[Group] = field(default_factory=list)       # outermost first
      convention_calls: list[dict] = field(default_factory=list)  # chain on MapControllers()/MapControllerRoute()/MapRazorPages()
      caller_unknown: bool = False
      unknown: list[str] = field(default_factory=list)        # discovery-time reasons auth may be incomplete

  def discover_controllers(model: ProjectModel) -> list[CoreRouteRef]
  ```
  `Route.meta` keys: `kind` (`"controller"`), `api_surface` (bool), `controller` (full name), `env` (only when every mapping call is env-guarded).
- Controller detection, templates, tokens, `~/` and leading-`/` overrides, conventional routes and `[NonAction]`/`[NonController]` exactly as the spec's Routes/Controllers bullet. Conventional templates come from `MapControllerRoute(name, pattern)`, `MapDefaultControllerRoute()` (`{controller=Home}/{action=Index}/{id?}`) and `MapAreaControllerRoute(name, areaName, pattern)`; a controller with neither attribute routes nor a conventional route registered is still listed with the default template and `meta["route_assumed"] = True`. `[Area("X")]` fills `{area}`/`[area]`. Verbs from `Http*`/`AcceptVerbs`, else `["ANY"]`.
- `api_surface`: `[ApiController]` on the class or a base, or the base chain reaches `ControllerBase` without `Controller`.
- `convention_calls` holds the chain after `MapControllers()` for attribute-routed actions and after the matching conventional mapping call for conventional ones.

- [ ] **Step 1: Create `controllers_api`** (synthetic, `Microsoft.NET.Sdk.Web`, `net8.0`, implicit usings): `Program.cs` with `AddControllers()`, `AddAuthentication().AddJwtBearer()`, `AddAuthorization(o => { o.AddPolicy("Admin", p => p.RequireRole("Admin")); o.AddPolicy("Audit", p => p.AddRequirements(new AuditRequirement())); })`, `UseAuthentication()`, `UseAuthorization()`, `app.MapControllers();`, `app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");`. Controllers: `OrdersController` (`[ApiController][Route("api/[controller]")][Authorize]`, `[HttpGet("{id:int}")] Get(int id)`, `[HttpDelete("{id}")][Authorize(Policy = "Admin")] Delete(int id)`, `[HttpGet("public")][AllowAnonymous] Public()`, `[HttpGet("~/legacy/orders")] Legacy()`, `[NonAction] public void Helper()`); `HealthController` (`[Route("health")] : ControllerBase`, `[HttpGet] Get()`); `HomeController : Controller` (no route attributes, `Index()`, `[HttpPost] Save()`); `ReportsController` (`[ApiController][Route("reports")][Authorize(Policy = "Missing")]`, `[HttpGet] List()`); `AuditController` (`[ApiController][Route("audit")][Authorize(Policy = "Audit")]`, `[HttpGet] Log()`); `Admin/ManageController` (`[Area("Admin")][Route("[area]/[controller]/[action]")] : Controller`, `Reset()`); `BaseApiController` (abstract, `[ApiController][Authorize]`) and `InvoicesController : BaseApiController` (`[Route("invoices")]`, `[HttpPost] Create()`); `Auth/AuditHandler.cs` (`AuthorizationHandler<AuditRequirement>` whose `HandleRequirementAsync` calls `context.Succeed(requirement)` unconditionally) and `AuditRequirement : IAuthorizationRequirement`; `NotAController` (public class, no base, method `Run()`).

- [ ] **Step 2: Write the failing tests** in `tests/test_dnl_routes_core.py` (module fixture: `prepare(controllers_api)`, `discover_controllers(get_model(root, "dotnet"))`; a helper `rt(handler)` returns the single route):
  - `test_attribute_routes_and_tokens`: `OrdersController.Get` -> `/api/Orders/{id}`, `["GET"]`; `OrdersController.Delete` -> `["DELETE"]`; `OrdersController.Legacy` -> `/legacy/orders`.
  - `test_nonaction_and_noncontroller_excluded`: no `OrdersController.Helper`, no `NotAController.Run`.
  - `test_conventional_route`: `HomeController.Index` -> `/Home/Index/{id?}`, `["ANY"]`; `HomeController.Save` -> `["POST"]`; `route_assumed` absent.
  - `test_area_token`: `ManageController.Reset` -> `/Admin/Manage/Reset`.
  - `test_inherited_base_controller`: `InvoicesController.Create` -> `/invoices`, `["POST"]`, `meta["api_surface"] is True`.
  - `test_api_surface_flag`: `HomeController.Index.meta["api_surface"] is False`, `OrdersController.Get` True.
  - `test_convention_calls_attached`: in a tmp copy whose Program.cs has `app.MapControllers().RequireAuthorization();`, `OrdersController.Get` has `convention_calls` names `["RequireAuthorization"]`, and `HomeController.Index` (conventional) has none.
  - `test_handler_range_for_code_view`: `OrdersController.Get` has `source_start_line`/`source_end_line` spanning the method in `Controllers/OrdersController.cs`.
  - `test_degraded_controller_routes` (monkeypatched no helper): the same set of `(handler, path, methods)` as with the helper.

- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.

- [ ] **Step 4: Implement** `discover_controllers` and the `routes.py` renames.

- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.

- [ ] **Step 6: Commit** `feat(dnl): ASP.NET Core controller route discovery`

---

### Task 7: Razor Pages routes

**Files:**
- Modify: `checks/dnl/routes_core.py`
- Create: `tests/fixtures/aspnetcore/razor_app/` (see Step 1)
- Test: `tests/test_dnl_routes_core.py`

**Interfaces:**
- Produces: `def discover_pages(model: ProjectModel) -> list[CoreRouteRef]` (style `"razorpage"`).
- Pages: `.cshtml` under `<project>/Pages/` or `<project>/Areas/<A>/Pages/` whose first directive line is `@page` (optional quoted template). Path = folder path + file name without extension, `Index` dropping to its folder; template starting with `/` or `~/` replaces it, otherwise is appended; area pages prefixed `/<A>`; constraints stripped with `strip_constraints`. Files starting with `_` are never routes.
- Model linking per Decision 4: `@model` name resolved by full name, then by simple name among the project's types, preferring namespaces from the page's `@namespace`/`@using` and every `_ViewImports.cshtml` up the folder chain to the project root (nearest `@namespace` wins).
- Handlers: public instance methods of the PageModel (and its project bases) matching `^On(Get|Post|Put|Delete|Patch)(\w*?)(Async)?$`; one route per handler, verb from the name, `meta["handler"]` = the middle group (empty for the default handler), `handler_name = f"{ModelSimpleName}.{method}"`, source range = the method. A page with a resolved model but no handlers gets one `GET` route with `method=None`. A page whose model is not found gets one `GET` route with `type=None`, `method=None`, `unknown=["page model <name> not found; handlers unknown"]`, source = the `.cshtml` file lines 1..end.
- `Route.meta`: `kind="razorpage"`, `api_surface=False`, `page` (the page path, e.g. `/Admin/Users`), `area` when present.
- `convention_calls`: the chain after `MapRazorPages()`.

- [ ] **Step 1: Create `razor_app`** (synthetic, `Microsoft.NET.Sdk.Web`): `Program.cs` with `builder.Services.AddRazorPages(o => { o.Conventions.AuthorizeFolder("/Admin"); o.Conventions.AllowAnonymousToPage("/Admin/Login"); });`, `AddAuthentication(...).AddCookie()`, `UseAuthentication`, `UseAuthorization`, `app.MapRazorPages();`. `Pages/_ViewImports.cshtml` (`@namespace RazorApp.Pages`, `@using RazorApp`); `Pages/Index.cshtml` + `Index.cshtml.cs` (`IndexModel : PageModel`, `OnGet`); `Pages/Admin/Users.cshtml` (`@page "{id:int?}"`, `@model UsersModel`) + cs (`OnGet`, `OnPostDeleteAsync`); `Pages/Admin/Login.cshtml` + cs (`LoginModel`, `OnGet`, `OnPost`); `Pages/Orders/Edit.cshtml` + cs (`EditModel`, no class auth, `[Authorize] public IActionResult OnPostSave()`); `Pages/Orphan.cshtml` (`@page`, `@model MissingModel`); `Pages/Shared/_Layout.cshtml` (no `@page`); `Pages/Privacy.cshtml` (`@page`, `@model PrivacyModel`) + cs with no handlers; `Areas/Shop/Pages/Cart.cshtml` + cs (`[Authorize] CartModel`, `OnGet`, `OnPostCheckout`), with `Areas/Shop/Pages/_ViewImports.cshtml` setting `@namespace RazorApp.Areas.Shop.Pages`.

- [ ] **Step 2: Write the failing tests**:
  - `test_page_paths`: `{(r.handler_name, r.path, tuple(r.methods))}` contains `("IndexModel.OnGet", "/", ("GET",))`, `("UsersModel.OnGet", "/Admin/Users/{id?}", ("GET",))`, `("UsersModel.OnPostDeleteAsync", "/Admin/Users/{id?}", ("POST",))`, `("CartModel.OnPostCheckout", "/Shop/Cart", ("POST",))`.
  - `test_handler_meta`: `UsersModel.OnPostDeleteAsync.meta["handler"] == "Delete"`, `IndexModel.OnGet.meta["handler"] == ""`, `meta["page"] == "/Admin/Users"`.
  - `test_layout_not_a_route`: no route whose file ends in `_Layout.cshtml`.
  - `test_orphan_page_unknown`: one route for `Orphan.cshtml`, `type is None`, `unknown` mentions `MissingModel`.
  - `test_page_without_handlers`: one `GET /Privacy` route with `method is None`, `type.name == "PrivacyModel"`.
  - `test_model_resolved_via_area_viewimports`: `CartModel` route's `type.full_name == "RazorApp.Areas.Shop.Pages.CartModel"` even when a second `CartModel` exists in another namespace (add one under `Models/`).
  - `test_degraded_pages`: same set of `(handler, path, methods)` without the helper.

- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 4: Implement** `discover_pages`.
- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.
- [ ] **Step 6: Commit** `feat(dnl): Razor Pages route discovery`

---

### Task 8: Minimal API and other endpoint routes

**Files:**
- Modify: `checks/dnl/routes_core.py`
- Create: `tests/fixtures/aspnetcore/minimal_api/` (see Step 1)
- Test: `tests/test_dnl_routes_core.py`

**Interfaces:**
- Produces: `def discover_endpoints(model: ProjectModel) -> list[CoreRouteRef]` and `def discover_all(model: ProjectModel) -> list[CoreRouteRef]` (controllers + pages + endpoints, cached on `model.cache["core_routes"]`).
- Map calls: `Map{Get,Post,Put,Patch,Delete}`, `MapMethods(pattern, verbs, h)`, `Map(pattern, h)` (`["ANY"]`) whose call `sym` is an ASP.NET Core endpoint-builder extension, or, with no `sym`, whose receiver chain root is a known builder (pipeline `kind == "endpoints"`/`"app"`, a group local, a `UseEndpoints` lambda parameter, a parameter typed `IEndpointRouteBuilder`/`RouteGroupBuilder`/`WebApplication`). A resolved `sym` on another type is not a route.
- Handler: a lambda argument becomes a synthetic `MethodIR(name=f"<lambda@{line}>", params=from param_info, body=lambda body (an expression body wrapped as one `return`), line, end_line)`; `type` = the enclosing TypeIR. A method group (`name` -> local function in the same body or a method on the enclosing type; `member` -> a type's static method) resolves to that method. Unresolved handler -> `method=None`, `unknown=["handler <text> not resolved"]`.
- Groups: `MapGroup(prefix)` followed through locals (`var g = app.MapGroup("/a")...`), fluent chains and nested groups; chain calls after `MapGroup` go into `Group.calls`; chain calls after the Map call go into `endpoint_calls`.
- Solution methods called on a builder (`app.MapGroup("/v2").MapUserEndpoints()`, `MapUserEndpoints(app)`) are followed (depth 8, cycle guard) with the builder bound to the receiving parameter. Chain calls after such a call apply as a `Group(prefix="", calls=...)` only to routes registered on what the method provably returns: the bound parameter when it is a group (a `RouteGroupBuilder`, by declared type or because the caller bound a `MapGroup` result to it), or a group local derived from it -> all routes on that group; a returned `Map*` call, or a local holding one -> that route only; anything else -> not applied, and each route registered inside gets `unknown=["<call> applied to the result of <Method> could not be traced"]`.
- Methods that register routes on a builder parameter but are never reached from a pipeline entry are still scanned with prefix `""` and `caller_unknown=True`.
- Other endpoints (style `"endpoint"`), `meta["kind"]` in parentheses: `MapHub<T>(p)` (`"hub"`, `type`=T), `MapGrpcService<T>()` (`"grpc"`, path `/{T}/*`, `type`=T, `api_surface=True`), `MapRazorComponents<T>()`/`MapBlazorHub()` (`"blazor"`, path `/_blazor` or `/*`), `MapHealthChecks(p)` (`"health"`), `MapFallback*` (`"fallback"`, path `/{**path}`), `MapOpenApi()`/`MapSwagger()` (`"openapi"`), and `UseSwagger()`/`UseSwaggerUI()` (`"openapi"`, `meta["middleware"]=True`, paths `/swagger/{documentName}/swagger.json` and `/swagger`).
- `Route.meta["env"]` = the pipeline env of the registering call when not None; minimal-API and gRPC routes have `api_surface=True`.

- [ ] **Step 1: Create `minimal_api`** (synthetic, `Microsoft.NET.Sdk.Web`): top-level `Program.cs`:
  ```csharp
  var builder = WebApplication.CreateBuilder(args);
  builder.Services.AddAuthentication().AddJwtBearer();
  builder.Services.AddAuthorization(o => o.AddPolicy("AdminOnly", p => p.RequireRole("Admin")));
  builder.Services.AddSignalR();
  builder.Services.AddHealthChecks();
  var app = builder.Build();
  if (app.Environment.IsDevelopment()) { app.MapGet("/debug/env", () => "dev"); app.UseSwagger(); }
  app.MapGet("/", () => "hello");
  var api = app.MapGroup("/api").RequireAuthorization();
  api.MapGet("/orders/{id:int}", (int id, OrderStore store) => store.Find(id));
  api.MapPost("/orders", CreateOrder);
  api.MapGet("/status", () => "ok").AllowAnonymous();
  var admin = api.MapGroup("/admin").RequireAuthorization("AdminOnly");
  admin.MapDelete("/users/{id}", (int id) => Results.NoContent());
  app.MapGroup("/v2").MapUserEndpoints();
  app.MapAuditEndpoints().RequireAuthorization();
  app.MapHub<ChatHub>("/chat");
  app.MapHealthChecks("/healthz");
  app.Run();
  static IResult CreateOrder(Order o) => Results.Ok(o);
  ```
  `UserEndpoints.cs` (`public static RouteGroupBuilder MapUserEndpoints(this RouteGroupBuilder g) { g.MapGet("/users", () => "list"); return g; }`), `AuditEndpoints.cs` (`public static IEndpointConventionBuilder MapAuditEndpoints(this IEndpointRouteBuilder e) { var a = e.MapGet("/audit/a", () => 1); var b = e.MapGet("/audit/b", () => 2); return new CompositeConventionBuilder(a, b); }` plus `CompositeConventionBuilder : IEndpointConventionBuilder` forwarding `Add` to both -- the engine cannot prove what the returned builder covers, so the trailing `RequireAuthorization()` is not applied and both routes are marked untraced), `OrphanEndpoints.cs` (`public static void MapOrphans(this IEndpointRouteBuilder e) { e.MapPost("/orphan", () => 1); }`, never called), `ChatHub.cs` (`[Authorize] public class ChatHub : Hub { }`), `Models.cs` (`OrderStore`, `Order`).

- [ ] **Step 2: Write the failing tests**:
  - `test_minimal_paths_and_verbs`: contains `("/", ("GET",))`, `("/api/orders/{id}", ("GET",))`, `("/api/orders", ("POST",))`, `("/api/status", ("GET",))`, `("/api/admin/users/{id}", ("DELETE",))`, `("/v2/users", ("GET",))`, `("/audit/a", ("GET",))`.
  - `test_lambda_handler_body_and_params`: `/api/orders/{id}` has `method.name.startswith("<lambda@")`, params `["id", "store"]`, and a source range covering the lambda.
  - `test_method_group_handler`: `/api/orders` `method.name == "CreateOrder"`.
  - `test_group_calls_recorded`: `/api/admin/users/{id}` has two groups, prefixes `["/api", "/admin"]`, each with a `RequireAuthorization` call; `/api/status` has `endpoint_calls` names `["AllowAnonymous"]`.
  - `test_extension_method_followed`: `/v2/users` group prefixes `["/v2"]`, `caller_unknown is False`.
  - `test_untraced_chain_marked`: `/audit/a` and `/audit/b` have no group with `RequireAuthorization` and `unknown` mentions `MapAuditEndpoints`.
  - `test_unreached_method_caller_unknown`: `/orphan` exists with `caller_unknown is True`.
  - `test_other_endpoints`: `/chat` kind `"hub"` with `type.name == "ChatHub"`; `/healthz` kind `"health"`; `/swagger` kind `"openapi"` with `meta["middleware"] is True` and `meta["env"] == "Development"`; `/debug/env` `meta["env"] == "Development"`.
  - `test_resolved_sym_elsewhere_is_not_a_route`: a class `Router { public void MapGet(string p, Func<int> h) {} }` used as `new Router().MapGet("/x", () => 1)` yields no `/x` route (helper run).
  - `test_degraded_minimal_routes`: same `(path, methods)` set without the helper (the `Router` case is allowed to differ and is excluded).

- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 4: Implement** `discover_endpoints` and `discover_all`.
- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.
- [ ] **Step 6: Commit** `feat(dnl): minimal API, group and endpoint route discovery`

---

### Task 9: Auth resolution (`auth_core.py`)

**Files:**
- Create: `checks/dnl/auth_core.py`, `tests/test_dnl_auth_core.py`
- Modify: fixtures from Tasks 6-8 only where a test below needs one more case (prefer tmp copies in the test)

**Interfaces:**
- Consumes: `CoreRouteRef`, `pipeline_for`, `auth.never_denies`-style helpers from `checks/dnl/auth.py` where they fit.
- Produces:
  ```python
  PROTECTED, ANONYMOUS, UNPROTECTED, UNKNOWN = "protected", "anonymous", "unprotected", "unknown"

  @dataclass
  class CoreAuth:
      state: str
      source: str              # e.g. "attribute:Authorize", "base:BaseApiController", "endpoint:RequireAuthorization",
                               # "group:/api RequireAuthorization", "MapControllers().RequireAuthorization",
                               # "filter:AuthorizeFilter", "convention:AuthorizeFolder(/Admin)", "fallback policy", "none"
      roles: list[str] = field(default_factory=list)
      policies: list[str] = field(default_factory=list)
      file: str | None = None
      line: int | None = None
      reasons: list[str] = field(default_factory=list)   # why unknown
      notes: list[str] = field(default_factory=list)     # e.g. ignored handler-level [Authorize]

  @dataclass
  class PolicyInfo:
      name: str
      file: str
      line: int
      roles: list[str]
      never_denies: bool       # RequireAssertion(_ => true) only, or every requirement's handlers never deny

  def policies(model: ProjectModel, pipe: Pipeline) -> dict[str, PolicyInfo]
  def never_denying_handlers(model: ProjectModel) -> list[TypeIR]
  def resolve(model: ProjectModel, ref: CoreRouteRef, pipe: Pipeline) -> CoreAuth
  def middleware_issue(pipe: Pipeline) -> tuple[str, str, int, bool] | None   # (message, file, line, suppressed) for DNL-AUTHZ-008
  ```
- Order (spec Auth 1-4, with Decision 2 and Builder note 1):
  1. `ANONYMOUS` if `[AllowAnonymous]` is on the action, the class or a base (for Razor Pages: the PageModel class or a base only), `.AllowAnonymous()` is in `endpoint_calls`, any group's calls, or `convention_calls`, or an `AllowAnonymousToPage`/`AllowAnonymousToFolder`/`AllowAnonymousToAreaPage`/`AllowAnonymousToAreaFolder` convention covers the page.
  2. `PROTECTED` from `[Authorize]` (or a project attribute deriving from `AuthorizeAttribute`) on action/class/base (Razor Pages: class/base only; a handler-method `[Authorize]` adds the note `"[Authorize] on handler method <m> is ignored by Razor Pages"`), hub/gRPC service class attributes, `RequireAuthorization(...)` in `endpoint_calls`, any group, or `convention_calls`. A project attribute implementing `IAuthorizationFilter`/`IAsyncAuthorizationFilter` protects only when its `OnAuthorization[Async]` can set `context.Result`; otherwise it is a never-denies candidate (`DNL-AUTHZ-003`). An attribute named like `*Authorize*`/`*Permission*`/`*Role*` that is not defined in the solution -> `UNKNOWN` with a reason.
  3. `PROTECTED` from a global `AuthorizeFilter` (`Filters.Add(new AuthorizeFilter(...))` or `Filters.Add<AuthorizeFilter>()` inside `AddControllers`/`AddControllersWithViews`/`AddMvc`/`Configure<MvcOptions>` lambdas) for controllers and pages; from `AuthorizeFolder`/`AuthorizePage`/`AuthorizeAreaFolder`/`AuthorizeAreaPage` conventions for pages (folder match is prefix by path segment, case-insensitive).
  4. `PROTECTED` from a fallback policy (`FallbackPolicy = ...` in `AddAuthorization`, `SetFallbackPolicy(...)` on `AddAuthorizationBuilder()`), for every endpoint with no auth metadata from steps 1-3.
  - Policy checks: a policy name used by steps 2-4 and defined in `policies()` with `never_denies` -> not protective (`UNPROTECTED`, source names the policy, note says it never denies); not defined anywhere -> `UNKNOWN` (reason `policy "<name>" is not defined in the solution`) unless a defined, protective mechanism also applies; a registered custom `IAuthorizationPolicyProvider` (`AddSingleton<IAuthorizationPolicyProvider, X>`) makes every named policy `UNKNOWN`. `DefaultPolicy` assigned a never-deny policy makes plain `[Authorize]`/`RequireAuthorization()` not protective. A `FallbackPolicy = null` is no fallback.
  - Anything registered only under `env == "Development"` counts as absent.
  - `UNKNOWN` (when the route would otherwise be `UNPROTECTED`): `ref.unknown` reasons; `ref.caller_unknown` and no fallback; `AddEndpointFilter`/`AddEndpointFilterFactory` on the endpoint or a group, or `options.Conventions.Add(...)`/`Conventions.Add(...)` on MVC/Razor options (reason names the call); any `pipe.unresolved()` call with `kind in ("services", "app")` whose name is not in `_NON_AUTHZ_EXTENSIONS` (global: every route without endpoint auth), or with `kind == "endpoints"` on a group (that group's routes only).
  - `_NON_AUTHZ_EXTENSIONS` (frozenset, extend only with names that cannot grant or remove authorization): `AddJwtBearer, AddOpenIdConnect, AddMicrosoftIdentityWebApi, AddMicrosoftIdentityWebApp, AddGoogle, AddFacebook, AddMicrosoftAccount, AddNegotiate, AddCertificate, AddDbContext, AddDbContextPool, AddDbContextFactory, AddEntityFrameworkStores, AddDefaultIdentity, AddIdentity, AddIdentityCore, AddDefaultTokenProviders, AddDefaultUI, AddSwaggerGen, UseSwagger, UseSwaggerUI, AddAutoMapper, AddMediatR, AddValidatorsFromAssembly, AddFluentValidationAutoValidation, AddSerilog, UseSerilog, UseSerilogRequestLogging, AddApplicationInsightsTelemetry, AddStackExchangeRedisCache, AddHangfire, AddHangfireServer, AddMassTransit, AddOpenTelemetry, AddNewtonsoftJson`.
  - Middleware-served routes (`meta["middleware"]`) are `UNPROTECTED` with source `"middleware (not endpoint-routed; authorization does not apply)"`.
  - `middleware_issue`: `UseAuthorization` (outside dev-only) missing, before `UseRouting`, or before `UseAuthentication`, when the pipeline uses explicit routing in `style == "startup"`, or in `style == "minimal"` with a target framework below net7.0. Any env-unguarded `SuppressCheckForUnhandledSecurityMetadata = true` sets `suppressed=True`, and only then does `resolve` downgrade endpoint-metadata protection (steps 2 and 4) to `UNPROTECTED` with a note.

- [ ] **Step 1: Write the failing tests** in `tests/test_dnl_auth_core.py` (module fixtures prepare the three apps; `auth(app, handler_or_path)` resolves one route):
  - controllers_api: `OrdersController.Get` -> protected, source `attribute:Authorize`; `OrdersController.Delete` -> protected, `policies == ["Admin"]`, `roles == ["Admin"]`; `OrdersController.Public` -> anonymous; `HealthController.Get` -> unprotected; `ReportsController.List` -> unknown, reason mentions `Missing`; `AuditController.Log` -> unprotected, notes mention `Audit` never denies; `InvoicesController.Create` -> protected, source `base:BaseApiController`; `never_denying_handlers` names `AuditHandler`.
  - `test_allowanonymous_beats_authorize`: tmp copy with `[AllowAnonymous]` on `OrdersController` class -> `Delete` is anonymous.
  - `test_global_authorize_filter`: tmp copy with `AddControllers(o => o.Filters.Add(new AuthorizeFilter()))` -> `HealthController.Get` protected, source `filter:AuthorizeFilter`.
  - `test_fallback_policy`: tmp copy adding `o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();` -> `HealthController.Get` protected, source `fallback policy`; and `o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAssertion(_ => true).Build();` -> unprotected with a never-denies note.
  - `test_dev_only_registration_is_absent`: fallback policy assigned inside `if (builder.Environment.IsDevelopment())` -> `HealthController.Get` unprotected.
  - razor_app: `/Admin/Users` both handlers protected, source `convention:AuthorizeFolder(/Admin)`; `/Admin/Login` anonymous; `EditModel.OnPostSave` unprotected with the ignored-attribute note; `/Shop/Cart` protected `attribute:Authorize`; `Orphan.cshtml` route under `/Admin` in a tmp copy -> protected by the folder convention, outside -> unknown (model not found).
  - minimal_api: `/` unprotected; `/api/orders/{id}` protected source `group:/api RequireAuthorization`; `/api/status` anonymous; `/api/admin/users/{id}` protected with `policies == ["AdminOnly"]`; `/v2/users` unprotected; `/audit/a` unknown (untraced reason); `/orphan` unknown (caller unknown); `/chat` protected `attribute:Authorize`; `/healthz` unprotected; `/swagger` unprotected with the middleware source.
  - `test_orphan_protected_by_fallback`: minimal_api tmp copy with a fallback policy -> `/orphan` protected, `/audit/a` protected.
  - `test_unresolved_extensions`: minimal_api tmp copy adding `builder.Services.AddDbContext<Db>(); builder.Services.AddSwaggerGen();` -> `/` still unprotected; adding `builder.Services.AddCompanyAuth();` -> `/` unknown with a reason naming `AddCompanyAuth`, while `/api/orders/{id}` stays protected.
  - `test_endpoint_filter_is_unknown`: `app.MapGet("/f", () => 1).AddEndpointFilter<GateFilter>();` -> unknown naming `AddEndpointFilter`.
  - `test_policy_provider_makes_named_policies_unknown`: controllers_api tmp copy registering `AddSingleton<IAuthorizationPolicyProvider, MyProvider>()` -> `OrdersController.Delete` still protected (class `[Authorize]` applies) but `AuditController.Log` unknown.
  - `test_middleware_issue`: pipelines/startup -> message mentions `UseAuthorization` before `UseRouting`, `suppressed is False`; pipelines/minimal (net8.0) -> None; minimal tmp copy targeting `net6.0` without `UseAuthorization` -> issue; startup tmp copy with `o.SuppressCheckForUnhandledSecurityMetadata = true` -> `suppressed is True` and an `[Authorize]` controller route there resolves unprotected with a note.
  - `test_degraded_auth_matches` (no helper): the controllers_api, razor_app and minimal_api states above are identical without the helper, except routes whose only difference is a resolved-`sym` decision (list any exclusions explicitly in the test).

- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement** `auth_core.py`.
- [ ] **Step 4: Run to verify they pass**, then the full suite. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): three-state ASP.NET Core auth resolution`

---

### Task 10: `dotnet` analyzers, auth rules, retire the tree-sitter analyzer

**Files:**
- Create: `checks/dnl/rules_auth_core.py`, `languages/dotnet/analyzers.py`, `tests/test_dotnet_core_analyzers.py`
- Modify: `languages/dotnet/__init__.py`, `languages/dotnet/detector.py`, `languages/dotnet/README.md`, `languages/dotnet_legacy/README.md` (DNL table: `DNL-AUTHZ-008` row; a line saying DNL is the shared C#/.NET engine used by both packages), `core/owasp_web.py` (`DNL-AUTHZ-008`), `enumerator.py` (prepare also for `dotnet`), `tests/test_owasp_all_rules.py` (dotnet case)
- Delete: `languages/dotnet/aspnet_analyzer.py`, `languages/dotnet/_ts_utils.py` (if nothing else imports it), `tests/test_aspnet_analyzer.py`

**Interfaces:**
- Consumes: `discover_all`, `resolve`, `policies`, `never_denying_handlers`, `middleware_issue`, `pipeline_for`, `dnl_finding`.
- Produces:
  - `rules_auth_core.check(model: ProjectModel, refs: list[CoreRouteRef]) -> list[Finding]`: per route, `Route.auth_decorators = [auth.source]` when protected (else `[]`), `Route.explicit_access = "PermitAll"` when anonymous, `Route.meta["auth"] = {"state", "source", "reasons", "notes"}`; findings as in the rule table (unknown: `DNL-AUTHZ-001` medium `confidence="REVIEW"`, description lists `reasons`; unprotected: medium, high when `explicit mutating`, description names the source chain checked and any notes; anonymous: info plus `DNL-AUTHZ-002` when mutating; `DNL-AUTHZ-004` for a protected controller/page with no roles or policy whose controller/page/action name matches the legacy `_SENSITIVE_*` patterns). Routes with `meta["env"] == "Development"` get no AUTHZ findings. `DNL-AUTHZ-003` once per never-denying handler type, policy or filter attribute (route-less). `DNL-AUTHZ-008` once per pipeline (route-less), high when suppressed.
  - `languages/dotnet/analyzers.py`: `@register("dotnet", fw)` for `controllers`, `razorpages`, `minimalapi`, `config`, same shape as `languages/dotnet_legacy/analyzers.py` (one cached `_code_results(model)` per model view `get_model(target, "dotnet")`, per-module crash isolation, notes emitted once). Kind -> analyzer: `controller` -> controllers, `razorpage` -> razorpages, `minimalapi`/`hub`/`grpc`/`blazor`/`health`/`fallback`/`openapi` -> minimalapi; route-less findings -> `config` (or the first enumerated analyzer when config is not enumerated). `language = "dotnet"`; `ScanResult.degraded` set as in dotnet_legacy.
  - `languages/dotnet/detector.py`: `detect_language` true iff a netcore-profile SDK project exists or a loose `.cs` passes `is_core_source`; `detect_frameworks` returns, in order, `controllers` (a `.cs` in a netcore project/loose-core file with a class carrying `[ApiController]`/`[Controller]` or a base `Controller`/`ControllerBase`), `razorpages` (a `.cshtml` with `@page` under a `Pages` folder of such a project), `minimalapi` (a `.Map(Get|Post|Put|Patch|Delete|Methods|Group|Hub|GrpcService|HealthChecks|Fallback)` call or `.Map(` with a string first argument), `config` (always when the language is detected). Text scans only; no helper.
- The old `aspnet` framework name disappears; `--framework aspnet` is no longer valid.

- [ ] **Step 1: Write the failing tests** in `tests/test_dotnet_core_analyzers.py`:
  - `test_detector`: controllers_api -> `["controllers", "config"]`; razor_app -> `["razorpages", "config"]`; minimal_api -> `["minimalapi", "config"]`; mixed_solution -> `dotnet` detects `["controllers", "config"]` (its `Program.cs` only calls `MapControllers`), and `dotnet_legacy` still detects `mvc`.
  - `test_detector_ignores_legacy_only`: `tests/fixtures/dotnet_legacy/mvc5_app` minus `CoreSide` (tmp copy) -> `dotnet` not detected.
  - `test_analyzers_split_routes` (roslyn_helper): `enumerate_target(minimal_api)` -> one `dotnet/minimalapi` result holding `/api/orders/{id}` and `/chat`, one `dotnet/config` result with no routes.
  - `test_findings` (roslyn_helper), as `(check_id, severity, confidence, handler or path)` sets: controllers_api has `DNL-AUTHZ-001 medium None HealthController.Get`, `DNL-AUTHZ-001 medium REVIEW ReportsController.List`, `DNL-AUTHZ-001 info None OrdersController.Public`, `DNL-AUTHZ-003 high` on `AuditHandler`, and no AUTHZ-001 on `OrdersController.Get`; razor_app has `DNL-AUTHZ-001 high None EditModel.OnPostSave` (explicit POST by handler name counts as explicit mutating) whose description mentions the ignored attribute; minimal_api has REVIEW AUTHZ-001 on `/orphan` and `/audit/a`, plain AUTHZ-001 on `/`, `/v2/users`, `/healthz`, none on `/debug/env`.
  - `test_auth_source_on_route`: `/api/orders/{id}` `auth_decorators == ["group:/api RequireAuthorization"]`; `meta["auth"]["state"] == "protected"`.
  - `test_allow_path_suppresses_core_missing_auth` (roslyn_helper): `apply_allowlist(results, ["/healthz"])` removes the `/healthz` AUTHZ-001 finding and keeps the one on `/`.
  - `test_owasp_tags`: an AUTHZ-001 finding on a minimal-API route carries `owasp["api2023"]` starting `API5:2023`; on a razor page it has none.
  - `test_authz_008_finding` (roslyn_helper): pipelines/startup yields one `DNL-AUTHZ-008` medium in the `config` result.
  - `test_degraded_end_to_end` (no helper): `enumerate_target(minimal_api, allow_degraded=True)` produces the same `(check_id, path)` set as with the helper and `degraded` is set on each result.
  - `tests/test_owasp_all_rules.py`: change the dotnet case to framework `controllers`, require the helper for it (`pytest.importorskip`-style skip via the `roslyn_helper` fixture), and assert the tagged finding is `DNL-AUTHZ-001` with `API5` (keep the other languages' IDOR-001 asserts unchanged by parametrizing the expected id).

- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement** `rules_auth_core.py`, the analyzers, the detector; register `DNL-AUTHZ-008` in `core/owasp_web.py` (`_add(["DNL-AUTHZ-008"], "A01", "A01", "API5")`) and its README row; delete the tree-sitter analyzer files and test; rewrite `languages/dotnet/README.md` (what the package covers in Plan 1, frameworks, auth sources and states, helper requirement and degraded mode, link to the DNL rule table).
- [ ] **Step 4: Run to verify they pass**, then the full suite. Expected: PASS except `tests/test_owasp_readme.py` (fixed in Task 11).
- [ ] **Step 5: Commit** `feat(dotnet): ASP.NET Core analyzers on the shared C# engine; retire tree-sitter analyzer`

---

### Task 11: Coverage accounting, README, Linux run

**Files:**
- Modify: `tests/owasp_inventory.py`, `README.md` (dotnet framework list, coverage table, OWASP tagging prose), `tests/test_owasp_readme.py` (only if a new assert is needed)
- Test: `tests/test_owasp_inventory_dnl.py` (create)

**Interfaces:**
- Produces in `tests/owasp_inventory.py`: `def dnl_ids_for_dotnet() -> set[str]` -- `DNL-*` id literals in `checks/dnl/*.py` modules reachable by imports (transitively, within `checks/dnl`) from `languages/dotnet/*.py`; `families_of`/`coverage_rows` count those ids for the `dotnet` family. Ids in modules reachable only from `languages/dotnet_legacy` do not count. `rule_ids()` keeps returning non-DNL ids for every other family.

- [ ] **Step 1: Write the failing tests** in `tests/test_owasp_inventory_dnl.py`:
  - `test_dotnet_counts_reachable_dnl_ids`: `dnl_ids_for_dotnet()` contains `DNL-AUTHZ-001` and `DNL-AUTHZ-008`, and does not contain `DNL-WCF-001` or `DNL-CFG-001` (legacy-only modules).
  - `test_dotnet_row_nonempty_and_api5`: the `dotnet` row from `coverage_rows(RULES)` has a rule count >= 5 and `API5` in its covered API column.
  - `test_unreachable_module_not_counted`: monkeypatch the import scan so `languages/dotnet/analyzers.py` stops importing `rules_auth_core` -> `DNL-AUTHZ-008` disappears from `dnl_ids_for_dotnet()`.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement** the DNL pass; regenerate the README coverage table from `coverage_rows` (paste the generated rows); update the README frameworks line (`dotnet`: controllers, razorpages, minimalapi, config -- ASP.NET Core on the shared C# engine; needs the Roslyn helper, `--allow-degraded` applies) and the OWASP prose (DNL ids reachable from `languages/dotnet` count for `dotnet`).
- [ ] **Step 4: Run the full suite.** Expected: PASS, count = baseline - removed old tests + new tests.
- [ ] **Step 5: Linux run.** Copy the repo into a container and run the suite there (keeps the Windows `tools/roslyn-ir/bin` untouched):
  `docker run --rm -v "%CD%":/src:ro mcr.microsoft.com/dotnet/sdk:8.0 bash -c "cp -r /src /work && cd /work && rm -rf tools/roslyn-ir/bin tools/roslyn-ir/src/bin tools/roslyn-ir/src/obj && apt-get update -qq && apt-get install -y -qq python3-venv >/dev/null && python3 -m venv /tmp/v && /tmp/v/bin/pip install -q -r requirements.txt pytest && /tmp/v/bin/python -m pytest -q"`
  Expected: same pass count as Windows. If Docker is unavailable, say so in the task report; do not skip silently.
- [ ] **Step 6: Scrub and commit.** `git diff main --stat` and grep the diff and the branch's commit messages for client/target names and local paths (none expected). Commit `test(owasp): count DNL rules reachable from dotnet; README coverage for ASP.NET Core`.
