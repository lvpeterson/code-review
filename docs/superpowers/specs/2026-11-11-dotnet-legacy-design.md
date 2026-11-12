# dotnet_legacy: .NET Framework appsec analyzer with combined OWASP mapping

Date: 2026-11-11
Status: draft, awaiting approval

## Intent

The user reviews legacy Microsoft web applications built on .NET
Framework 4.x -- ASP.NET MVC 5, Web API 2, WCF, WebForms, C# and VB.NET. The existing `languages/dotnet` analyzer only
detects ASP.NET Core, so code-review currently finds almost nothing in them.

Goal: a new `languages/dotnet_legacy` package that reviews these apps with
**full-context analysis** (parsed code, resolved symbols, source-to-sink
data flow across layers), not grep, and tags every finding against a
**conglomerate of OWASP lists** so the report shows coverage of "everything":

- OWASP Top 10 **2025** (Web)
- OWASP Top 10 **2021** (Web)
- OWASP **API Security** Top 10 **2023**

This follows the shape of the 2026-11-03 IaC work (`core/owasp_isr.py`,
dedicated report tab with coverage table, mapping-enforcing tests).

## Goals

1. Detect and analyze .NET Framework web apps: MVC 5, Web API 2, WebForms
   (.aspx/.ascx + code-behind), WCF (.svc + contracts + bindings), ASMX if
   present, web.config (+ XDT transforms), Razor .cshtml, packages.config.
2. Same depth for **C# and VB.NET** (user explicitly chose full-context for
   VB: "way more accurate").
3. Every `dotnet_legacy` rule carries OWASP tags from all three lists where
   they honestly apply; every category in all three lists has at least one
   rule (that's what "checks for everything" means here).
4. Route inventory (MVC/Web API actions, WebForms pages, WCF operations)
   rendered in the existing Routes view, with resolved effective auth.
5. Report: a new OWASP tab with a three-column coverage table and click-to-
   filter, like the Infrastructure tab's ISR table.

## Non-goals

- Not touching the ASP.NET Core `languages/dotnet` analyzer.
- No compiling, building or running the target apps; no NuGet restore.
- No dynamic testing; findings remain pointers for a human (tool philosophy).
- Not decompiling DLLs in `packages/` or `Precompiled*` folders.

## Anti-goals (would be a failure even if it "works")

- Grep-level matching passed off as analysis. Regex is acceptable only as a
  documented fallback for files the parser can't handle, and those findings
  must say so (confidence REVIEW).
- Any target/client code copied into the repo, tests, fixtures, docs or
  committed reports, or anything that names a target, engagement or local
  path (this is a public repo). Fixtures are synthetic apps written from scratch.
- Findings duplicated across `packages/`, `bin/`, `obj/`, `.vs/`,
  `Precompiled*` copies.
- Forcing an OWASP tag that doesn't fit just to fill a column.

## Constraints

- Python tool; deps pinned in `requirements.txt`; tests run from a scratch
  venv (`pip install -r requirements.txt pytest`).
- `tree-sitter-c-sharp` already a dependency.
- .NET 8 SDK is installed on the user's Windows machine; the user mostly
  runs the tool on Linux (see Parsing decision).
- Follow repo idiom: `@register(language, framework)`, `core/rulescan.make_finding`,
  `dedupe`, per-package README with rule table, `--` instead of em-dashes in
  prose, comment density like `checks/tf_graph.py`.

## Typical target patterns

Legacy .NET Framework solutions of this kind commonly mix C# and VB
projects, Razor views, WebForms pages/controls and WCF services, and show:
string-built SQL (C# `+`, VB `&`), raw ADO.NET commands, EF6
`SqlQuery`/`ExecuteSqlCommand`; `Html.Raw`, `AllowHtml`/
`ValidateInput(false)`, `Response.Write`; mixed `[Authorize]` /
`[AllowAnonymous]` usage; web.config `customErrors Off`, `debug="true"`,
ELMAH `allowRemoteAccess`, connection-string passwords, WCF
`includeExceptionDetailInFaults`/`httpGetEnabled`; MD5/SHA1/DES/Rijndael;
`XmlDocument`; file IO via `Server.MapPath`; FormsAuthentication; AD via
`PrincipalContext`/`DirectorySearcher`; RestSharp/HttpClient; outdated
NuGet packages (old iTextSharp, jQuery, ELMAH, Ninject) plus unversioned
in-house DLL packages.

## Architecture

```
languages/dotnet_legacy/
  __init__.py, detector.py, README.md
  analyzers.py          one @register per framework: mvc, webapi, webforms, wcf, config, deps
checks/dnl/
  project.py            solution/project model (cached, like tf_graph.py)
  ir.py                 language-neutral IR
  frontend_cs.py        C# -> IR
  frontend_vb.py        VB.NET -> IR
  templates.py          Razor / ASPX markup -> embedded code expressions -> IR
  webconfig.py          web.config + XDT transform evaluation
  routes.py             MVC/Web API/WebForms/WCF route + effective-auth resolution
  taint.py              source -> sink engine with method summaries
  rules_*.py            rule groups (auth, injection, xss, config, wcf, crypto, deps, ...)
core/owasp_web.py       rule id -> {2025, 2021, api2023} tags
data/nuget_advisories.json, data/js_lib_advisories.json   offline advisory tables
```

### Detection (`detector.py`)

Language `dotnet_legacy` when any of: an old-style project file
(`.csproj`/`.vbproj` with `ToolsVersion` or `<TargetFrameworkVersion>v4`),
`packages.config`, a `web.config` with `<system.web>`, or `.aspx/.ascx/.svc/
.asmx` files. Frameworks reported: `mvc` (System.Web.Mvc reference),
`webapi` (System.Web.Http), `webforms` (.aspx/.ascx), `wcf` (.svc or
`<system.serviceModel>`), `config` (any web.config), `deps` (packages.config
or Scripts/*.js). Must not fire on SDK-style ASP.NET Core projects (those
stay with `languages/dotnet`). Walker excludes `packages/ bin/ obj/ .vs/
Precompiled*/ node_modules/`.

### Project model (`project.py`)

Built once per scan and cached (same pattern as `tf_graph.py`). Parses every
.sln/.csproj/.vbproj: project references, assembly references, `Compile`
items, `Content` items, root namespace. Builds a symbol table across the
whole solution: types (name, namespace, base type chain, attributes,
interfaces), members (fields, properties, methods with params/attributes),
constants. Resolves cross-project calls (UI -> Business -> Data,
WebAPIClient -> WebAPIService) so taint can follow layers. Code-behind
linkage for WebForms via `CodeBehind`/`CodeFile`/`Inherits`, and
designer-file control declarations (`TextBox`, `HiddenField`, ...).

### IR (`ir.py`)

Both frontends lower to one IR so rules and taint are written once:
Type, Method (params with type + attributes, attributes, body), statements
(Assign, LocalDecl, Call, Return, If/Loop/Try/Using/With as blocks with
children, Catch with handler body), expressions (Literal, Name, Member,
Call, New, Binary incl. concat, Interpolated, Conditional, Index, Lambda
opaque). Each node keeps file + line + span for findings and the report's
code view.

### Frontends

Both via the Roslyn helper (see Parsing decision below); tree-sitter-c-sharp
is the C# fallback when the helper is unavailable.
- **VB.NET**: the IR lowering must handle:
  case-insensitive keywords, `'`/`REM` comments, `_` and implicit line
  continuation (after `&`, `,`, `(`, operators), `""` string escapes,
  `Handles` clauses (event wiring for WebForms), `With` blocks, `Module`,
  `Shared`, `Me`/`MyBase`, XML literals (parse-and-skip), `Option Strict
  Off` late binding (treat member access on Object as opaque but tainted
  if receiver tainted).
- **Templates**: Razor and ASPX markup are tokenized into literal markup vs
  embedded code (`@expr`, `@{}`, `@Html.X(...)`, `<%= %>`, `<%: %>`,
  `<%# %>`, `<%= Eval() %>`, server controls and their attributes). Embedded
  code is parsed by the matching frontend so `@Html.Raw(Model.Comment)`
  resolves `Model` to the view's `@model` type and the property's origin.
  `<%: %>` and Razor `@expr` are encoded; `<%= %>`, `Html.Raw`, `Literal
  Mode="PassThrough"`, `Response.Write` are not.

### web.config (`webconfig.py`)

Stdlib ElementTree. Evaluates base `Web.config` plus each
`Web.<Config>.config` XDT transform (Replace, SetAttributes,
RemoveAttributes, Insert, Remove with Locator) so a finding knows its
effective value per build config: e.g. `debug="true"` in Web.config but
removed by Web.Release.config becomes low/info with a note rather than high.
Also reads `<location path>` blocks (per-path auth), `<authorization>`,
`<authentication mode=Forms>` (`<forms requireSSL timeout slidingExpiration
cookieless protection>`), `<httpCookies>`, `<sessionState>`,
`<machineKey>`, `<httpRuntime>` (`enableVersionHeader`, `requestValidationMode`,
`maxRequestLength`), `<pages validateRequest viewStateEncryptionMode
enableViewStateMac enableEventValidation>`, `<customErrors>`,
`<trace>`, `<httpHandlers>/<handlers>` (elmah.axd, trace.axd),
`<system.webServer><httpProtocol><customHeaders>` (missing security
headers, CORS `*`), `<connectionStrings>`, `<appSettings>` secrets,
`<system.serviceModel>` (bindings, behaviors, endpoints, mex), ELMAH
`<security allowRemoteAccess>`, `<membership passwordFormat>`.

### Routes and effective auth (`routes.py`)

- MVC 5 / Web API 2: controllers = types whose base chain reaches
  `Controller`/`ApiController` (through project base classes). Actions =
  public non-`[NonAction]` methods. Paths from `RouteConfig.MapRoute` /
  `WebApiConfig.Routes.MapHttpRoute` templates (resolved from the parsed
  registration calls, not assumed) plus `[RoutePrefix]`/`[Route]`. HTTP
  verbs from `[HttpGet]`... or Web API name-prefix convention.
- Effective auth combines: global filters (`FilterConfig`
  `filters.Add(new AuthorizeAttribute())`, `config.Filters.Add(...)`), base
  controller attributes, class and action `[Authorize(Roles/Users)]`,
  `[AllowAnonymous]`, and **custom attributes resolved to their source**
  (a class deriving `AuthorizeAttribute` whose `AuthorizeCore` always
  returns true, or an `ActionFilterAttribute` that never short-circuits, is
  not auth). web.config `<authorization><deny users="?"/>` (and matching
  `<location path>`) also counts for MVC routes, since UrlAuthorizationModule
  enforces it on extensionless URLs; such routes are marked with that source
  and a note that attribute routing can bypass path-based location rules
  (designer's call).
- WebForms: each .aspx/.ascx is a route; auth from web.config
  `<authorization>` + `<location path>` + code-behind checks in
  `Page_Load`/`Page_Init` (`User.IsInRole`, redirect-if-not-authenticated
  patterns).
- WCF: .svc `Service=` -> implementation type -> `[ServiceContract]`
  interface `[OperationContract]`s; auth from `[PrincipalPermission]`,
  binding security mode, `serviceAuthorization` behaviors.
- Emits `core.models.Route` objects (with source ranges) so the existing
  Routes view works. API surface flag in `route.meta["api_surface"]` for
  ApiController/WCF/ASMX/JSON-returning MVC actions.

### Taint (`taint.py`)

Sources: action/operation parameters (model binding, incl. complex type
properties), `Request.QueryString/Form/Params/Cookies/Headers/
ServerVariables/RawUrl/Url/Files`, `Request["x"]`, WebForms control values
(`TextBox.Text`, `SelectedValue`, `HiddenField.Value`, `Request.Form` via
`UniqueID`), ViewState when MAC is off, WCF operation params, RouteData,
deserialized external API responses (for API10).

Sinks: SQL (`SqlCommand`/`OracleCommand`/`OleDbCommand` CommandText and
ctor, `SqlDataAdapter`, EF6 `SqlQuery`/`ExecuteSqlCommand`, Dynamic LINQ
string predicates), XSS (template unencoded outputs, `Response.Write`,
`Literal.Text`, `Label.Text` in PassThrough-equivalent contexts,
`HtmlString`/`MvcHtmlString`), path (`File.*`, `FileStream`, `Server.MapPath`,
`Response.WriteFile/TransmitFile`, `File()` action result), open redirect
(`Redirect`, `Response.Redirect`, `RedirectResult`), SSRF (`HttpClient`,
`WebClient`, `WebRequest.Create`, `RestClient`/`RestRequest` URLs), LDAP
(`DirectorySearcher.Filter`, `DirectoryEntry` path), XPath, command
(`Process.Start`), log injection (log4net/ELMAH/`Trace` messages),
header injection (`Response.AddHeader/AppendCookie`), XXE-capable parsers
fed external XML, deserializers.

Sanitizers/barriers: `SqlParameter`/`Parameters.Add*` for the placeholder
in question, numeric parse/convert, `HttpUtility.HtmlEncode`/
`AntiXssEncoder`/`Server.HtmlEncode`, `Path.GetFileName` (+ base-dir
`StartsWith` check), `Url.IsLocalUrl`, allowlist comparisons.

Method summaries: per method, which params (and `this` fields) reach which
sink kinds unsanitized, computed to a fixpoint across the solution (depth
cap, documented). Severity/confidence: source-to-sink proven -> rule's
severity, no REVIEW; sink fed only by a parameter with no resolved caller
-> one level lower, `confidence="REVIEW"`; constant-only input -> no
finding.

## Finding model and OWASP mapping

- New `core/owasp_web.py`: `TAGS = {rule_id: {"2025": "A05", "2021": "A03",
  "api2023": "API8" | None}}`, titles for all three lists, exact-then-prefix
  lookup like `owasp_isr.py`. **Builder verifies 2025 titles against
  owasp.org before coding** (expected: A01 Broken Access Control, A02
  Security Misconfiguration, A03 Software Supply Chain Failures, A04
  Cryptographic Failures, A05 Injection, A06 Insecure Design, A07
  Authentication Failures, A08 Software or Data Integrity Failures, A09
  Security Logging and Alerting Failures, A10 Mishandling of Exceptional
  Conditions).
- `Finding` gets `owasp: dict[str, str]` (default empty). `category` keeps
  its ISR meaning untouched. JSON emits it; SARIF adds each as a rule tag
  (`owasp-2025:A05`, `owasp-2021:A03`, `owasp-api-2023:API8`).
- API tag policy: rules that are inherently API (e.g. WCF metadata exposed)
  always carry it; route-level rules carry their API tag **only when the
  route is an API surface** (`meta["api_surface"]`). 2025 tag required on
  every rule; 2021 required where a mapping exists (all should); API tag
  optional.
- Rule IDs: `DNL-<AREA>-NNN`, areas AUTH, AUTHZ, INJ, XSS, PATH, REDIR,
  SSRF, XXE, DESER, CSRF, SESS, CFG, WCF, CRY, SEC, SCA, LOG, ERR, DES
  (design), RES (resource consumption), INT (integrity).

## Rule catalog (minimum set; builder may add)

Tags shown as 2025 / 2021 / API2023.

| Area | Example rules | Tags |
|---|---|---|
| AUTHZ | action/page/operation with no effective auth; mutating `[AllowAnonymous]`; custom authorize attribute that never denies; WebForms page outside any `<location>` deny | A01 / A01 / API5 |
| AUTHZ (object) | action takes id-like param, loads by it, never compares to current user/tenant (body check, extends `checks/idor.py` heuristics) | A01 / A01 / API1 |
| AUTHZ (function) | admin-ish controller/action (`Admin`, `Delete`, `Approve`, `Manage`...) with `[Authorize]` but no Roles/policy | A01 / A01 / API5 |
| AUTHZ (property) | EF entity bound directly as action param without `[Bind(Include)]` (over-posting); EF entity returned from API action (over-exposure) | A06 / A04 / API3 |
| CSRF | POST/PUT/DELETE MVC action without `[ValidateAntiForgeryToken]` (global filter aware); WebForms ViewStateUserKey not set | A01 / A01 / -- |
| INJ | SQL, LDAP, XPath, command, Dynamic LINQ, header via taint | A05 / A03 / API8 (if API) |
| XSS | unencoded template output, `Response.Write`, `HtmlString` of tainted; `AllowHtml`/`ValidateInput(false)`/`validateRequest=false`/`requestValidationMode=2.0` | A05 / A03 / -- |
| PATH | tainted file paths, unrestricted upload (no extension/size/content check, saved under web root) | A01 / A01 / -- |
| REDIR | tainted redirect without `Url.IsLocalUrl` | A01 / A01 / -- |
| SSRF | tainted outbound URL | A01 / A10 / API7 |
| XXE | `XmlDocument` (pre-4.5.2 default resolver), `XmlTextReader` without `DtdProcessing.Prohibit`, `XmlReaderSettings` with `DtdProcessing.Parse`/resolver set, target framework < 4.5.2 noted | A02 / A05 / API8 |
| DESER | `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `ObjectStateFormatter`, Json.NET `TypeNameHandling != None`, `JavaScriptSerializer(SimpleTypeResolver)` | A08 / A08 / -- |
| INT | `enableViewStateMac=false`, hardcoded `<machineKey>` committed, CDN scripts without SRI in layouts/master pages | A08 / A08 / -- |
| SESS / AUTH | forms `requireSSL=false`, long timeout, `cookieless=UseUri`, `httpOnlyCookies=false`, no `Session.Abandon` on logout, session fixation (no new session id at login), plaintext password compare (`==` on password), `passwordFormat="Clear"`, no lockout on login action, AD bind creds in code/config | A07 / A07 / API2 |
| CFG | `debug=true`, `customErrors Off`/RemoteOnly with detail, `trace enabled`, `elmah allowRemoteAccess`, `enableVersionHeader`, missing security headers, CORS `*` (`EnableCors("*")`/header), `Server` header | A02 / A05 / API8 |
| WCF | security mode None / no transport on non-local binding, `includeExceptionDetailInFaults`, metadata `httpGetEnabled`/mex in prod, huge `maxReceivedMessageSize`/no throttling | A02 / A05 / API8, API9, API4 |
| CRY | MD5/SHA1 for passwords or integrity, DES/3DES/RC2, ECB, static IV/key, `RNGCryptoServiceProvider` vs `Random` for tokens, `ServerCertificateValidationCallback => true`, `SecurityProtocol` forcing SSL3/TLS1.0; hooks into existing `languages/crypto` style | A04 / A02 / -- |
| SEC | connection-string passwords, `appSettings` secrets/API keys, hardcoded creds in code | A04 / A02 / API8 |
| SCA | vulnerable NuGet versions (packages.config + HintPath), vulnerable bundled JS libs (Scripts/ banners: jQuery, jQuery UI, Bootstrap, Modernizr...), EOL target framework (< 4.6.2), unversioned/local DLL packages with no NuGet source (REVIEW), `nuget.config` http feeds | A03 / A06 / API9 for EOL API stacks |
| LOG | no logging framework configured, user input into log messages unencoded, passwords/PII logged, login failure not logged | A09 / A09 / -- |
| ERR | empty catch, catch-all swallowing in auth/authorization paths (fail-open), `ex.Message`/`ex.ToString()`/stack trace returned to client or view | A10 / A04 (fail-open) or A05 (leak) / API8 |
| DES | sensitive flows (login, password reset, register, payment-like) with no throttling/CAPTCHA/lockout (REVIEW) | A06 / A04 / API6 |
| RES | unbounded list endpoints (no paging / `Take`), huge `maxRequestLength`/`maxAllowedContentLength`, file upload with no size limit | A06 / A04 / API4 |
| INV | Web API HelpPage area reachable, WCF mex endpoints, `elmah.axd`/`trace.axd` handlers registered, test/debug controllers in prod projects | A02 / A05 / API9 |
| CONSUME | external API responses deserialized and used without validation; outbound calls over `http://` (service references, RestClient base URLs in config); cert validation disabled for outbound | A08 / A08 / API10 |

Coverage test (below) enforces at least one rule per category in all
three lists.

## Report

- New **OWASP** tab: one coverage table, rows = categories grouped by list
  (2025, 2021, API 2023), columns = severity counts + total; empty
  categories show "manual" like the ISR table. Click a row to filter
  findings to that tag (same JS pattern as `_ISR_FILTER_JS`).
- Each finding shows badges for each tag it carries.
- Routes view shows dotnet_legacy routes with effective auth and its
  source (global filter / base class / attribute / web.config location).
- Generic, non-tab: any future analyzer that sets `owasp` lands in this tab.

## Testing

- Synthetic fixtures under `tests/fixtures/dotnet_legacy/`: `mvc5_app`
  (C#, global filter, base controller, custom authorize attr, layered
  Business/Data project with SQL sink), `webapi_app`, `webforms_vb` (VB
  code-behind, designer file, Handles wiring, `&` SQL concat across a
  helper Module), `wcf_service`, `config_variants` (base + Release
  transform). Each fixture has positive and negative (safe) cases.
- `test_dotnet_legacy_*.py` per area; VB frontend unit tests for the
  syntax listed above; template tokenizer tests; XDT transform tests.
- `test_owasp_web.py`: every `DNL-` rule id has a 2025 + 2021 tag; every
  category in all three lists has >= 1 rule; titles match the module.
- Preflight tests (helper/SDK discovery mocked): missing -> non-zero exit +
  OS-specific install text; broken helper -> error; `--allow-degraded` ->
  scan completes with the banner/JSON flag; non-.NET target -> no preflight.
- Existing suite must stay green (ASP.NET Core detector must not start
  matching legacy projects and vice versa).
- Acceptance: scan a real legacy target outside the repo (report written to
  a scratch dir, not the repo); triage a sample of findings per
  rule area with the user; record false-positive tuning in the package
  README. Nothing from that run is committed.

## Parsing decision: Roslyn helper (user chose Option A)

A small .NET 8 console tool in the repo, `tools/roslyn-ir/`, uses
Microsoft.CodeAnalysis.CSharp + .VisualBasic to parse C# and VB sources and
emit the IR (above) as JSON on stdout; `checks/dnl/frontend_cs.py` /
`frontend_vb.py` become thin loaders of that JSON. No build or restore of
the target app is needed.

**Must run on Linux** -- the user mostly runs code-review on a Linux box.
- Roslyn and .NET 8 are cross-platform; nothing here may use Windows-only
  APIs. CI-style test: the helper's own tests and the Python
  `dotnet_legacy` tests pass on Linux (the builder verifies in WSL or a
  Linux container if no Linux box is at hand).
- Semantic model: reference assemblies for .NET Framework come from the
  `Microsoft.NETFramework.ReferenceAssemblies.net48` NuGet package (works
  on Linux), restored once when the helper itself is built, so
  System.Web/System.Data types resolve without Windows.
- Distribution, in order of preference at runtime: (1) a prebuilt
  `roslyn-ir` binary found on PATH or at `tools/roslyn-ir/bin/`; (2) if
  the `dotnet` SDK is present, build the helper on first use and cache it;
  (3) neither present -> **preflight error** (below).
- **Preflight check (user requirement).** Runs as soon as the detector
  reports `dotnet_legacy`, before any analysis. If no helper binary is found
  and no `dotnet` SDK (>= 8) is on PATH, the scan **stops with a flagged
  error and a non-zero exit code**, printing:
  - what was detected and why it needs the helper (e.g. "Found 159 .vb /
    1050 .cs files in .NET Framework projects; full-context analysis needs
    the Roslyn helper"),
  - install instructions for the current OS: Linux via
    `dotnet-install.sh --channel 8.0` or the distro package
    (`apt install dotnet-sdk-8.0` / `dnf install dotnet-sdk-8.0`), Windows
    via `winget install Microsoft.DotNet.SDK.8`, and the no-install
    option (copy a self-contained `roslyn-ir` binary built with the publish
    command below),
  - how to re-run, and the opt-out flag.
  The same check also fails if the helper exists but crashes or emits
  invalid JSON on a probe file (a broken install is reported, not ignored).
- **Opt-out:** `--allow-degraded` continues without the helper: C# falls
  back to tree-sitter-c-sharp, VB to a regex fallback whose findings are
  `confidence="REVIEW"`. A degraded run prints the warning again at the end
  of the scan and puts a red banner at the top of the HTML report (and a
  `degraded: true` field + reason in JSON / a SARIF run property), so a
  degraded report can never be mistaken for a full one.
- Scans that don't detect `dotnet_legacy` never run the preflight, so
  other languages are unaffected on machines without .NET.
  A documented `dotnet publish -r linux-x64 --self-contained -p:PublishSingleFile=true`
  command produces a binary that needs no .NET install on the Linux box.
  Binaries are not committed (gitignored).
- Paths: Windows-authored projects reference files with the wrong case and
  backslashes (`CodeBehind="default.aspx.vb"`, `<Compile Include="Models\X.cs">`);
  all project/code-behind/include resolution must be case-insensitive and
  separator-agnostic so it works on a case-sensitive Linux filesystem.
  Handle CRLF and UTF-8 BOM / Windows-1252 source encodings.
- Performance: one helper process per scan (batch all files over stdin or
  a file list), not one per file.

## Left to the builder

- Exact module split under `checks/dnl/`, taint depth cap, caching format.
- Advisory table contents/format and refresh process (osv-scanner via
  `--sca` stays optional, as today).
- Additional rules beyond the catalog, severities per rule, README wording.
- Order of phases (suggested: IR + C# + project model + routes/auth + OWASP
  module/tab, then taint rules, then config/WCF/templates, then VB, then
  SCA/crypto/remaining categories, then the real-target acceptance pass).
