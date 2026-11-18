# dotnet: ASP.NET Core (modern .NET)

## What it is

An appsec review package for ASP.NET Core apps: SDK-style projects on net5.0+,
netcoreapp and netstandard, plus loose `.cs` files that are clearly ASP.NET
Core. It runs on the shared C#/.NET engine in `checks/dnl` -- the same project
model, Roslyn helper IR and finding conventions as
[`languages/dotnet_legacy`](../dotnet_legacy/README.md), which keeps .NET
Framework apps. In a mixed solution each package takes its own projects and the
helper runs once for both. The earlier tree-sitter analyzer (`aspnet`) is
retired; `--framework aspnet` is no longer valid.

The package covers route discovery and authorization, request-to-sink taint,
Razor template XSS, object-level rules, configuration rules (pipeline code and
`appsettings*.json`), offline dependency (SCA) rules and the rule families
carried over from the legacy engine. Every finding carries OWASP Web 2025 /
2021 and API 2023 tags (see "OWASP mapping").

## Which projects belong here

The project files decide, not the source text (`checks/dnl/project.py`; the
detector uses the same logic):

| Project | Package |
|---|---|
| SDK-style, effective target framework `net5.0`+, `netcoreapp*` or `netstandard*` | `dotnet` |
| non-SDK project, or SDK-style on `net4x` / `v4.x` | `dotnet_legacy` |
| multi-targeted SDK project holding a net4x and a modern moniker (`net48;net8.0`) | both: each package sees it under its own reference profile |
| C# files no project claims that use `WebApplication`, `Microsoft.AspNetCore`, `ControllerBase` or `IEndpointRouteBuilder` | `dotnet`, as a loose project |
| SDK project with no resolvable `TargetFramework` | `dotnet`, with a note saying so |

- **Target framework resolution.** `TargetFramework(s)` is read from the project
  file and from `Directory.Build.props` (the nearest file, plus parents it chains
  to through `GetPathOfFileAbove` / an explicit `Import`). `$(Property)` values
  are substituted from the known properties; an unresolved one is noted. Only
  unconditional values decide ownership; a file with only conditional values does
  not override a farther unconditional one, and when no unconditional value exists
  the last conditional value decides, with a note. End-of-support checks look at
  every value named.
- **Multi-targeted projects** are compiled twice by the helper: once with the
  modern reference profile (`dotnet` view) and once with the net48 profile
  (`dotnet_legacy` view). Each build gets the preprocessor symbols of the
  highest framework of that profile plus `TRACE` and the project's own
  `DefineConstants`, so `#if NET8_0_OR_GREATER` style code is lowered the way the
  build sees it. A file that uses a symbol only a dropped (lower) moniker defines
  gets a note. Visual Basic on modern .NET is not analyzed (a note says so); a
  multi-targeted VB project is analyzed by the legacy package only.
- Files of test projects (a project or folder named `*.Tests`, `tests`, ...) do
  not produce hard-coded-credential (DNL-SEC-003) or SSRF findings.

## Frameworks reported as separate results

| Framework | Detected when | Routes |
|---|---|---|
| `controllers` | a class carries `[ApiController]` / `[Controller]` or derives from `Controller` / `ControllerBase` | attribute and conventional MVC / API controller actions |
| `razorpages` | a `.cshtml` with `@page` as its first directive under a `Pages` folder | one route per page handler |
| `minimalapi` | a `MapGet/Post/Put/Patch/Delete/Methods/Group/Hub/GrpcService/HealthChecks/Fallback/...` call, or `.Map("...")` | minimal API endpoints, SignalR hubs, gRPC services, health checks, fallbacks, OpenAPI endpoints, `MapRazorComponents` (Blazor) |
| `config` | always, once the language is detected | no routes; route-less findings (see below) |
| `deps` | a modern project with package references, a `packages.lock.json` beside it, bundled JS under a `lib` / `libs` / `scripts` / `content` folder, or an end-of-support target framework | no routes; offline SCA |

Route-less findings (never-denying handlers / policies / filters, middleware
order, pipeline and settings rules, hard-coded secrets and other code findings
outside a route) go to `config`; if `config` is not enumerated, the first
enumerated code analyzer reports them. A route whose analyzer does not run goes
to the first one that does, so routes and findings are never dropped. Forcing
`--framework deps` alone therefore drops the route-level and configuration
findings.

Route discovery handles attribute routing (`[Route]`, `[HttpX]`, `[Area]`,
`[ApiVersion]` paths), conventional controller routes, Razor Pages under `Pages/`
and `Areas/<A>/Pages/` (with `_ViewImports` directives), minimal-API lambdas,
`MapGroup` prefixes and conventions, `UseEndpoints` lambdas and `Startup`
classes. Code calling a solution method is followed inline.

## What is analysed

| Area | Where | Described under |
|---|---|---|
| Routes and authorization | `routes_core`, `auth_core`, `rules_auth_core` | Authorization |
| Request-to-sink taint, Razor XSS, object-level rules | `rules_taint`, `rules_xss`, `rules_object` | Taint, templates and object rules |
| Configuration: pipeline, options, `appsettings*.json` | `rules_pipeline` and its modules | Configuration rules |
| Dependencies | `rules_sca_core` and shared `rules_sca` | Dependencies (SCA) |
| Crypto, secrets, deserialization, XXE, integrity, errors, session, logging, flows, resources | shared legacy modules | Carried-over families |

## Requirements and degraded mode

The Roslyn helper (`tools/roslyn-ir`, .NET 8 SDK) is required, exactly as for
dotnet_legacy: found through `CODE_REVIEW_ROSLYN_IR`, then `tools/roslyn-ir/bin/`,
then `PATH`, and built automatically when the SDK is present. Without it the
scan exits 2 with install steps.

With `--allow-degraded` the C# is lowered by tree-sitter instead (no semantic
symbols):

- the same rule modules run, on the same IR shape; every result carries the
  `degraded` flag and a banner;
- framework types are matched by name instead of by symbol, so overloads told
  apart only by type and receivers typed only through another method's return are
  not resolved; confidence is never higher than with the helper;
- tree-sitter does not know the build's symbols, so every `#if` branch is lowered
  (extra findings from compiled-out code are possible), and a multi-targeted
  project's two views share one parse (a note says so);
- `deps` needs no IR and runs as usual; `appsettings*.json` rules are unaffected.

## Authorization

Every route is resolved to one of four states (`checks/dnl/auth_core.py`):

| State | Meaning |
|---|---|
| **PROTECTED** | a denying mechanism is proven (sources below) |
| **ANONYMOUS** | `[AllowAnonymous]`, `.AllowAnonymous()` or an `AllowAnonymousTo*` convention (`Route.explicit_access = "PermitAll"`) |
| **UNPROTECTED** | nothing protects the route, or the only candidate never denies (for example a policy whose handler always succeeds) |
| **UNKNOWN** | something could affect authorization that the analyzer cannot trace (an unresolved extension call, an untraced caller, a policy defined conditionally, a custom policy provider) |

The analysis fails closed: every path that cannot prove a denying mechanism ends
in UNKNOWN, a medium REVIEW finding that lists the reasons, never in PROTECTED.
UNKNOWN reasons only apply to a route that would otherwise be UNPROTECTED; they
never downgrade a route that a definite mechanism protects.

Order of evaluation, most specific first (anonymous beats everything, as in
ASP.NET Core):

1. ANONYMOUS markers (action, class, base class, endpoint, group, Map call, Razor
   Pages convention).
2. PROTECTED by `[Authorize]` (or a project attribute deriving from it, or an
   authorization filter that can deny), or `RequireAuthorization` on the endpoint,
   a `MapGroup` or the Map call. Razor Pages read the PageModel class and its
   bases; a handler-method attribute is noted and ignored.
3. PROTECTED by a global `AuthorizeFilter` (controllers, pages) or an `Authorize*`
   Razor Pages convention.
4. PROTECTED by a fallback policy, only for endpoints with no authorization
   metadata at all.

Policies are protective when a requirement can deny; `RequireAssertion(_ => true)`
and requirements whose handlers only ever `Succeed` never deny. `Route.auth_decorators`
holds the source (for example `group:/api RequireAuthorization`) and the decision is
stored in `Route.meta["auth"]`.

Registrations count only when they certainly run in Production: a call under an
environment condition the reader cannot evaluate is never a protective source, it
becomes a reason for UNKNOWN. Routes that exist only in Development get no AUTHZ
finding. `--allow-path` suppresses DNL-AUTHZ-001 for matching route paths
(case-insensitive).

| Rule | Where |
|---|---|
| DNL-AUTHZ-001 | unprotected (medium, high when an explicit mutating verb), unknown (medium REVIEW), anonymous (info) |
| DNL-AUTHZ-002 | anonymous route with an explicit mutating verb (credential flows such as login or register are anonymous by design and skipped) |
| DNL-AUTHZ-003 | authorization handler, policy or filter attribute that never denies |
| DNL-AUTHZ-004 | privileged-looking controller / page / action protected with no roles or policy |
| DNL-AUTHZ-008 | `UseAuthorization` missing or misordered; high when `SuppressCheckForUnhandledSecurityMetadata` is true |

## Taint, templates and object rules

The shared taint engine runs on Core routes (`checks/dnl/rules_taint.py`,
`rules_xss.py`, `rules_object.py`); rule ids and tags are those in the
dotnet_legacy [rule table](../dotnet_legacy/README.md#rules).

- **Sources**: query, form, route values, headers, cookies, body and
  `IFormFile` members of `HttpRequest` (reached through `HttpContext`,
  `Request`, a parameter or `GetTypedHeaders()`), request URL helpers, and
  bound input (below).
- **Binding**: a parameter is request input unless it is `[FromServices]` /
  `[FromKeyedServices]`, a framework type (`HttpContext`, `ILogger<T>`,
  `IConfiguration`, `UserManager<T>`, ...), a type registered as a service, a
  `DbContext`, or an interface / abstract type other than `IFormFile`,
  `IFormFileCollection`, `IFormCollection`. `[ModelBinder]` overrides the
  exclusions. DTOs, `[AsParameters]` types and files are tainted. In Razor
  Pages and controllers a `[BindProperty]` property (or every settable property
  under `[BindProperties]`) is input for non-GET handlers, and for GET only when
  `SupportsGet` is not literally `false`. Minimal-API lambdas are analysed as the
  route handler, including the helpers they call.
- **Sinks**: SQL (`FromSqlRaw`, `ExecuteSqlRaw`, ADO.NET commands), command and
  path APIs, redirects (including `Location` headers), SSRF (`HttpClient`,
  `HttpClientJson*`, `HttpRequestMessage`), deserialization, XXE, header and
  cookie writes, `ILogger` message templates (not placeholder arguments), and
  HTML responses (`Content`, `Results.Content`, `Results.Text`, `WriteAsync`,
  `MarkupString`, `Html.Raw`).
- **Templates**: DNL-XSS-003 reads Razor views, layouts and Razor Pages
  (`.cshtml`) and ties each output to the controller action or page handler that
  renders it (by `Views/<Controller>/<Action>`, `[Area]`, `Views/Shared`, or a
  page's own file); HTML encoders cleanse, `Html.Raw` and `HtmlString` do not.
  For a page, `Model.X` is proven when a `[BindProperty]` source for that verb or
  a handler write reaches `X`.
- **Object rules**: DNL-AUTHZ-005 (IDOR: a record looked up by a request id with
  no ownership or `AuthorizeAsync` check that can reject; `User.FindFirstValue`
  and `Results.*` rejections count as signals), DNL-AUTHZ-006 (over-posting: a
  bound entity or model with sensitive members reaching the context without a
  `[Bind]` allow-list), DNL-AUTHZ-007 (an entity with a sensitive-looking member
  returned directly).

A request source reaching a sink is proven and takes the rule's severity. A sink
fed only by its own method's parameters, with nothing in the solution passing
untrusted data, is reported as REVIEW, one severity lower, with no route.

## Configuration rules

Run on the pipeline of each web project (`Program.cs` top-level code, a `Startup`
class, or a static `Main`; solution methods are followed at the call site) and on
`appsettings*.json`. Modules: `rules_pipeline`, `rules_pipeline_auth`,
`rules_secrets_core`, `rules_limits_core`, with `pipeline.py`, `options.py`,
`cfgctx.py` and `appsettings.py` as readers. The ids and severities are in the
dotnet_legacy rule table; the full behaviour (the Production assumption, what
degrades to REVIEW, `appsettings` merge order, reused ids and limits) is under
[Configuration rules for ASP.NET Core](../dotnet_legacy/README.md#configuration-rules-for-aspnet-core).

| Group | Ids |
|---|---|
| Errors and exposure | DNL-CFG-008 (developer exception page, `DetailedErrors`), DNL-CFG-009 (no exception handler), DNL-ERR-002 (exception text in the response), DNL-INV-003 (Swagger / OpenAPI in Production), DNL-INV-004 (old API versions) |
| Transport and hosting | DNL-CFG-010 (no HTTPS redirection), DNL-CFG-011 (no HSTS), DNL-CFG-012 (`RequireHttpsMetadata = false`), DNL-CFG-013 (HTTP-only listeners), DNL-CFG-014 (`AllowedHosts: *`) |
| CORS and CSRF | DNL-CFG-007 (wildcard CORS), DNL-CFG-015 (per-route CORS), DNL-CSRF-001 / 002 (antiforgery) |
| Cookies, tokens, Identity | DNL-SESS-001..003, 009 (cookie flags, `SameSite`, lifetime), DNL-SESS-010 / 011 (token validation switched off, clock skew), DNL-SEC-004 (hard-coded signing key), DNL-SEC-005 / 006 / 007 (weak password, lockout, confirmation options) |
| Secrets in settings | DNL-SEC-001 / 002 (`appsettings*.json`, `launchSettings.json`) |
| Limits | DNL-RES-001 (request size), DNL-RES-004 (no rate limiting on login / token), DNL-RES-005 (unbounded page size) |
| Data protection | DNL-CRY-009 (persisted keys not protected) |

The scan assumes Production: code under `env.IsDevelopment()` is not reported, and
a guard it cannot evaluate keeps the finding as REVIEW. A value that is not a
literal, a conditional assignment, an option set by code it cannot follow, or an
absence finding while the pipeline is not fully read (an unresolved extension could
register the missing piece) is REVIEW, never clean. `appsettings.Production.json`
is merged over the base file per app directory; `appsettings.Development.json` is
never used for the Production verdict.

## Dependencies (SCA)

Offline, from the advisory data in `checks/dnl/data`; `--sca` (osv-scanner) stays
the authoritative online path.

- DNL-SCA-001: `PackageReference` versions (inline, central
  `Directory.Packages.props`, `VersionOverride`) and `packages.lock.json` resolved
  versions, transitive entries included, against known-vulnerable ranges.
- DNL-SCA-003: a `netcoreapp*` / `net5.0`+ target past its Microsoft end-of-support
  date (dated table in the advisory data; the run date is the system date).
- DNL-SCA-006 (REVIEW): a package whose version cannot be resolved (floating
  `1.*`, `$(Prop)`, no central entry, unparsable range) is never reported as clean.
- DNL-SCA-002 (bundled JS under `wwwroot/lib` and similar), plus the shared
  `packages.config`, `HintPath` and `nuget.config` checks, run as for legacy.

## Carried-over families

Rule modules shared with dotnet_legacy that also run on SDK projects; the per-id
detail is in [`CARRIED_RULES.md`](CARRIED_RULES.md).

| Family | Ids | Notes |
|---|---|---|
| Crypto and secrets in code | DNL-CRY-001..008, DNL-SEC-003 | matched by symbol when resolved, else by the names written |
| Deserialization, XXE | DNL-DESER-001..003, DNL-XXE-001 | Json.NET and `JavaScriptSerializer` matched by name |
| Integrity | DNL-INT-003 | SRI on `.cshtml` layouts and views |
| Errors | DNL-ERR-001..003 | Core idioms (`IAuthorizationFilter`, `IActionResult` sinks) matched by name |
| Logging | DNL-LOG-001, 003, 004 | `ILogger<T>` / Serilog by declared type or name |
| Flows, API consumption | DNL-DES-001, DNL-CONSUME-001 / 002 | `[EnableRateLimiting]` and `lockoutOnFailure: true` count as protection |
| Resources, inventory | DNL-RES-002, 003, DNL-INV-002 | `IFormFile` uploads; Swagger outside Production is not reported |
| Session | DNL-SESS-008 | plaintext password comparison |

Never fire on Core, because the constructs do not exist there: DNL-INT-004
(WebForms ViewState), DNL-SESS-006 / 007 (`FormsAuthentication`), DNL-XXE-002 and
DNL-LOG-002. A `Web.config` inside an SDK project is not read by this package: no
DNL-CFG-001..006 or DNL-WCF-* finding is reported for it.

## OWASP mapping

Rule ids, categories and tags are defined in `core/owasp_web.py` and shown in the
HTML report's OWASP tab, JSON `owasp` and SARIF rule tags. The per-category
coverage table for `dotnet` is in the [root README](../../README.md#owasp-tagging);
the rule table with severities and tags is in the dotnet_legacy
[Rules](../dotnet_legacy/README.md#rules) section.

## What still needs a human

- Anything REVIEW: read the listed reasons and confirm by hand.
- Authorization done inside handler bodies (manual `User.IsInRole` checks) is not
  modelled.
- Third-party extension registrations that are not in the known-harmless table make
  affected routes UNKNOWN by design.
- Infrastructure outside the code: a reverse proxy or gateway may supply HTTPS
  redirection, HSTS, error pages, rate limiting or authentication.

## Known limits

A report is a floor, not a clean bill.

**Routes and authorization**

- Unresolved attributes with neutral names are ignored: only names that look like
  authorize / anonymous attributes block a PROTECTED verdict.
- Unresolved global extensions only affect routes without explicit endpoint auth:
  a route with its own `RequireAuthorization` stays protected.
- `RequireAssertion` with a non-literal lambda counts as a deny (it may always
  succeed).
- `MapGroup(...).MapControllers()` / `MapRazorPages()` / `MapControllerRoute()`:
  the group prefix and conventions are not applied; the routes are REVIEW with a
  reason.
- A `[Route]` whose template is not a constant, and a `MapHub<T>` /
  `MapGrpcService<T>` whose type is not in the solution (its `[Authorize]` cannot
  be read), are REVIEW.
- Extension methods defined in another project are not followed; routes registered
  there are found by a sweep and carry the "caller unknown" reason.
- Blazor `.razor` components are not analysed (only `MapRazorComponents` is listed
  as an endpoint).
- IR nesting cap: code nested deeper than the helper's JSON depth cap (a fluent
  chain of a few hundred links) is not lowered. A model note says where, and a
  `MapGet` / `MapPost` / ... call with a literal pattern inside it is reported as a
  REVIEW route recovered from source text.
- Two lambdas on one source line share a key, so findings may be attributed to
  both.

**Taint and object rules**

- EF Core, SqlClient, Npgsql and other NuGet types are matched by name: the helper
  resolves framework types only. A same-named type from another library can match,
  and a renamed wrapper is missed.
- `IdentityUser` / `IdentityRole` are matched by exact base name (generic arguments
  ignored); `IdentityUserLogin`, `IdentityUserClaim` and similar are not user
  records. `UserManager`-style lookups (`FindByIdAsync`) are recognised as record
  lookups by name.
- `[BindProperties]` counts every settable property as input, including ones the
  page never reads; a helper method of a type with bound properties is analysed as
  if the non-GET properties were set, so GET-only helpers may over-report.
  `[BindProperty]` over-posting is reported on any non-GET handler.
- Not recognised: exposure through `Created*` results, helper methods or a bare
  `DbSet`; a `View("/Views/...")` path with a leading slash; layouts, partials and
  view components are REVIEW at most.
- Kestrel rejects CR/LF in header values, so header-injection findings are defence
  in depth rather than an exploitable response split.
- The general taint limits (reflection, stored-then-read data, DI beyond
  interface-to-implementation, solver round cap) are those listed in
  dotnet_legacy.

**Configuration**

- Identity, cookie and JWT options set from a `ConfigureOptions<T>` /
  `IConfigureOptions<T>` class are not read; options bound from configuration or
  passed as a variable are REVIEW where the call is visible.
- Minimal-API versioning (`HasApiVersion`, `ApiVersionSet`, `[MapToApiVersion]`) is
  not read; INV-004 says so in one route-less REVIEW per pipeline.
- Secrets: URL credentials (`https://user:pw@host`) and `AccountKey` /
  `Passphrase` style keys are not detected.
- Kestrel certificate settings clear CFG-013 even when the configured URL is
  HTTP-only.
- More limits (CORS policy names, RES-005 clamps, SEC-004 key tracking, web-project
  recognition) are under
  [Configuration rules for ASP.NET Core](../dotnet_legacy/README.md#configuration-rules-for-aspnet-core).

**Project model**

- A multi-targeted project is compiled with the highest moniker of each profile;
  `#if` code specific to a lower moniker is inactive in that build (a note names
  the file).
- Visual Basic on modern .NET is not analysed.
