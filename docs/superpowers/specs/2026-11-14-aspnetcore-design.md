# ASP.NET Core: full OWASP coverage on the shared C# engine

## Intent

The `dotnet` (ASP.NET Core) analyzer is the thinnest in the scanner: it finds
routes with tree-sitter and checks only for a literal `[Authorize]`. A review
of a modern .NET app therefore says almost nothing beyond "these routes have no
attribute", and much of that is wrong (global fallback policies and
`RequireAuthorization()` are invisible to it).

The `dotnet_legacy` engine (Roslyn helper, IR, taint solver, about 90 rules)
already covers every OWASP Web 2025 and API 2023 category for .NET Framework.
Most of what it checks is plain C# (ADO.NET, crypto, deserialization, errors,
logging, resources). What differs in ASP.NET Core is the edges: how input
arrives, how responses leave, how routes and auth are declared, and where
configuration lives (`Program.cs` and `appsettings*.json` instead of
`Web.config`).

The goal is a report on an ASP.NET Core codebase that is as complete and as
trustworthy as one on a .NET Framework codebase, with every finding tagged with
OWASP Web 2025, Web 2021 and API 2023 like the rest of the scanner.

This is the first of the per-language gap-filling projects (order agreed:
ASP.NET Core, Ruby, Go, JavaScript, Java, Python, SQL). Ruby is brainstormed
separately afterwards.

## Goals

- SDK-style C# projects (`<Project Sdk="...">`) are compiled by the Roslyn
  helper against ASP.NET Core reference assemblies and analyzed by the same
  IR, taint solver and rule modules as legacy projects.
- Routes for all three ASP.NET Core styles: controllers (attribute and
  conventional routing), Razor Pages, and minimal APIs (including `MapGroup`
  prefixes), each with the handler body resolved so the report shows code,
  not just the registration line.
- Effective auth per route, including global mechanisms: fallback policy,
  global `AuthorizeFilter`, `RequireAuthorization()` on endpoints, groups and
  `MapControllers()`, `[Authorize]`/`[AllowAnonymous]` precedence, and policies
  or handlers that never deny.
- Every OWASP Web 2025 category (A01-A10) and API 2023 category (API1-API10)
  is reachable by at least one rule for an ASP.NET Core target, enforced by a
  test, like the dotnet_legacy coverage test.
- Works in degraded mode (no helper) through the existing tree-sitter C#
  frontend, with the same caveats as dotnet_legacy.
- Runs on Linux (the user's usual box) and Windows.

## Non-goals

- Blazor component analysis (`.razor` files). Blazor endpoints are listed as
  routes when found, but component code is not taint-analyzed in this project.
- F#, VB on .NET Core (rare), Azure Functions, gRPC service internals and
  SignalR hub internals beyond listing them as routes with auth.
- Live NuGet vulnerability lookups. SCA stays offline, from bundled advisory
  data, like `rules_sca`.
- Full MSBuild evaluation (conditions, imported props beyond
  `Directory.Build.props` / `Directory.Packages.props`).

## Anti-goals (a failure even if it "works")

- **A false "safe".** A route reported as authenticated when it is not, or a
  sink silently skipped because a type did not resolve, is the worst outcome.
  Unknown is reported as REVIEW, never as clean. Noise is secondary.
- Regressing dotnet_legacy: a mixed solution (legacy and SDK projects) must
  produce the same legacy findings as today, and the helper still runs once
  per scan.
- Two route or auth models for the same code that can disagree in one report.
- Anything in the repo naming a client, engagement, target app, local path or
  user. All fixtures are synthetic.

## Constraints

- Public repo: generic fixtures, tests, docs and commit messages only.
- Real targets are read-only; scan outputs stay outside the repo.
- .NET 8 SDK is already the helper's build requirement; no new toolchain.
- Rule ids must be quoted literals (the OWASP inventory reads source).
- Existing test suite (about 1210 tests) stays green; the venv is used.

## Approaches

1. **Extend the shared C# engine (chosen).** Send SDK-style projects through
   the Roslyn helper and rule modules, add ASP.NET Core sources, sinks, route
   discovery, auth resolution and configuration rules. Inherits five rounds of
   hardening (taint solver, crypto, deserialization, error handling, degraded
   mode). Cost: some modules need ASP.NET Core variants, and the package is no
   longer "legacy only".
2. Grow the tree-sitter `dotnet` analyzer. Independent, but rebuilds taint
   tracking and every rule family from scratch with no resolved types.
3. Hybrid: keep the tree-sitter routes, send only code to the C# engine. Less
   work up front, but two route models to keep in sync, which conflicts with
   the anti-goal above.

The user picked option 1.

## Design

### Packaging and naming

- The engine stays in `checks/dnl/`. New ASP.NET Core modules sit beside the
  legacy ones (for example `routes_core.py`, `auth_core.py`,
  `rules_pipeline.py`, `appsettings.py`), and shared modules gain ASP.NET Core
  table rows rather than forks.
- `languages/dotnet/` keeps the `dotnet` language name in the report. Its
  analyzers are rewritten on top of the shared `ProjectModel` (same pattern as
  `languages/dotnet_legacy/analyzers.py`: one model, cached results, split by
  route kind). The tree-sitter `aspnet_analyzer.py` is retired; its two rules
  (AUTH-001, IDOR-001 via the shared idor check) are superseded.
- Frameworks reported for `dotnet`: `controllers`, `razorpages`, `minimalapi`,
  `config` (Program.cs pipeline and appsettings), `deps` (SCA). The detector
  stops being a stub.
- **Rule ids (builder's call, recorded here):** checks that are the same C#
  check on either platform keep their existing `DNL-*` ids (one catalog, one
  OWASP mapping). ASP.NET Core-only checks get new ids in the same `DNL-`
  families (for example `DNL-CFG-0xx` for pipeline config, `DNL-AUTHZ-0xx` for
  fallback-policy gaps) so they reuse the DNL mapping and coverage test. The
  README explains that `DNL` is the C#/.NET engine, not legacy-only.

### Project model

- `load_projects` parses SDK-style projects instead of only claiming them:
  `TargetFramework(s)`, `PackageReference` (name and version, into
  `references` plus a new `packages` map), `FrameworkReference`,
  `ProjectReference`, `Compile Remove`/`Include` adjustments to the implicit
  glob, and `Directory.Build.props` / `Directory.Packages.props` (central
  package versions).
- Each project gets a reference profile: `net48` for legacy projects and SDK
  projects targeting `net4x`; `netcore` for `netcoreapp*`, `net5.0+` and
  `netstandard*`. Multi-targeted projects use the newest .NET Core target.
- `_request` sends every project with its profile. A mixed solution still runs
  the helper once.
- `get_model` is shared by both language packages, so a solution with both
  kinds of project builds the model once.

### Roslyn helper

- A second reference set, `refs/netcore/`, copied at build time from the
  `Microsoft.NETCore.App.Ref` and `Microsoft.AspNetCore.App.Ref` NuGet
  packages (pinned 8.0.x), the same way `refs/net48` comes from
  `Microsoft.NETFramework.ReferenceAssemblies.net48`. Using NuGet packages, not
  the local SDK `packs/` folder, keeps Linux and Windows identical.
- Request key `refs: "net48" | "netcore"` per project; default `net48` keeps
  old requests working.
- Lowering gaps to close for modern C#: top-level statements (lowered into a
  synthetic `Program.<Main>$` method so `Program.cs` pipeline code is in the
  IR), file-scoped namespaces, records and primary constructors, global
  usings (including the SDK's implicit usings when `ImplicitUsings` is on),
  lambdas as minimal-API handlers, `await` and `using` declarations, raw and
  interpolated string literals, collection expressions, pattern matching
  enough that taint does not stop at it.
- The tree-sitter frontend (`frontend_ts.py`) gets the same lowering where
  practical so degraded mode still sees `Program.cs`.

### Routes (`routes_core.py`)

- **Controllers:** types deriving from `ControllerBase`/`Controller`, or
  carrying `[ApiController]`/`[Controller]`, or named `*Controller` and public
  (the MVC convention), minus `[NonController]`. Templates from class and
  method `[Route]` and `[Http*("template")]`, `[controller]`/`[action]`/`[area]`
  tokens, `~/` overrides, conventional `MapControllerRoute`/
  `MapDefaultControllerRoute`/`MapAreaControllerRoute`. `[NonAction]`
  excluded. `api_surface` true for `[ApiController]` or `ControllerBase`
  without views.
- **Razor Pages:** `.cshtml` files under `Pages/` (and area `Pages/`) with an
  `@page` directive, route from the path or the directive template, handlers
  `OnGet`/`OnPost`/`On{Verb}{Handler}[Async]` on the `@model` PageModel.
  `[BindProperty]` properties are request input.
- **Minimal APIs:** `Map{Get,Post,Put,Patch,Delete,Methods}` and `Map` on any
  receiver typed (or, unresolved, named) as an endpoint route builder, with
  `MapGroup` prefixes followed through locals and fluent chains. The handler is
  the lambda or method group argument, resolved to its body. `api_surface`
  true.
- **Also listed as routes, with auth only:** `MapHub<T>`, `MapGrpcService<T>`,
  `MapRazorComponents`/`MapBlazorHub`, `MapHealthChecks`, `MapFallback*`,
  `UseSwagger`/`MapOpenApi` endpoints (feeds API9 inventory).

### Auth (`auth_core.py`)

Per route, the effective requirement is resolved in ASP.NET Core's order and
recorded with its source so the report can say why:

1. Endpoint metadata: `[AllowAnonymous]` / `.AllowAnonymous()` wins over any
   `[Authorize]` on the same endpoint or its class (as the framework does).
2. `[Authorize]` (roles, policy, schemes) on method, class or base class;
   `.RequireAuthorization(...)` on the endpoint, its group chain, or on
   `MapControllers()`/`MapRazorPages()`.
3. Global `AuthorizeFilter` added in `AddControllers`/`AddMvc` options, and
   Razor Pages conventions (`AuthorizeFolder`, `AuthorizePage`,
   `AllowAnonymousToFolder`).
4. `FallbackPolicy` set in `AddAuthorization`/`AddAuthorizationBuilder`.
5. Middleware sanity: `UseAuthorization` present and after `UseRouting` and
   `UseAuthentication` when explicit routing is used; an endpoint that relies
   on auth while `UseAuthorization` is missing is unprotected.

Policies and custom `IAuthorizationHandler`/`AuthorizationHandler<T>` types are
checked the way `never_denies` checks legacy filters: a handler that calls
`context.Succeed` unconditionally, or a policy built only from
`RequireAssertion(_ => true)`, is reported. Unknown policy names (defined in a
library) are REVIEW, not "protected".

### Taint

New sources (`taint_tables.py` rows plus binding logic):

- Action and handler parameters bound from the request: every parameter of a
  controller action, Razor Pages handler or minimal-API handler, except those
  marked `[FromServices]`/`[FromKeyedServices]`, typed as a registered service
  or framework type (`HttpContext`, `CancellationToken`, `ILogger<T>`,
  `ClaimsPrincipal`), or `[AsParameters]` (expanded instead). Complex types are
  tainted in every property.
- `HttpRequest.Query/Form/Headers/Cookies/RouteValues/Body/BodyReader/Path/
  QueryString/Host`, `ReadFromJsonAsync`, `ReadFormAsync`, `IFormFile`
  (`FileName`, `OpenReadStream`), `[BindProperty]` properties,
  `HttpContext.GetRouteValue`.

New sinks and sanitizers:

- SQL: EF Core `FromSqlRaw`, `ExecuteSqlRaw[Async]`, `SqlQueryRaw`,
  `Database.SqlQueryRaw`; interpolated `FromSql`/`FromSqlInterpolated`/
  `ExecuteSql` are safe; Dapper and ADO.NET rows already exist.
- XSS: `Html.Raw`, `HtmlString`/`MarkupString` construction, `Content(...,
  "text/html")`, `Results.Content`/`TypedResults.Content` with HTML, Razor
  `@Html.Raw` and unencoded tag helpers in `.cshtml` (the existing templates
  module learns Razor Core syntax).
- Redirect: `Redirect`, `RedirectPermanent`, `Results.Redirect`,
  `Response.Redirect`; `LocalRedirect` and an `Url.IsLocalUrl` guard cleanse.
- Path: `PhysicalFile`, `File(path)` overloads, `Results.File`,
  `IFormFile.FileName` used in a path; `Path.GetFileName` cleanses traversal.
- SSRF: `HttpClient`/`IHttpClientFactory` clients, `HttpRequestMessage`.
- Header and log: `Response.Headers[...]` / `Append`; `ILogger` calls where an
  interpolated or concatenated message carries taint (message templates with
  placeholders are safe).
- Command, LDAP, XPath, deserialization and XXE rows are platform-neutral and
  carry over unchanged.

### Object-level and property-level (API1, API3, API6)

- IDOR: a route parameter or bound id used to load an entity
  (`Find`, `FirstOrDefault`, `SingleOrDefault`, repository `Get*ById`) with no
  comparison against the current user (`User`, claims, `IAuthorizationService.
  AuthorizeAsync` with the resource) on the path. Reuses `rules_object` logic.
- Over-posting: an EF entity type (a `DbSet<T>` element) bound directly as an
  action or handler parameter, or via `TryUpdateModelAsync` without an include
  list.
- Excessive exposure: returning an entity type (or `IQueryable` of one) from an
  API action instead of a DTO, when the entity has sensitive-looking members
  (`Password*`, `*Hash`, `*Token`, `*Secret`, `IsAdmin`, `Role*`).

### Configuration (`rules_pipeline.py`, `appsettings.py`)

Reads the lowered `Program.cs`/`Startup.cs` pipeline (service registrations and
middleware calls, in order, with `IsDevelopment()` branches understood) and
`appsettings*.json` (merged per environment, `launchSettings.json` for which
environment runs). Checks:

- Errors: `UseDeveloperExceptionPage` or `app.UseExceptionHandler` missing
  outside a development guard; `DetailedErrors`; `ProblemDetails` with
  exception details in production.
- Transport: no `UseHttpsRedirection`/`UseHsts`, `RequireHttpsMetadata =
  false`, Kestrel HTTP-only endpoints, `AllowedHosts: "*"` (low).
- CORS: `AllowAnyOrigin` with `AllowCredentials` (the framework throws, so it
  is a config smell), `SetIsOriginAllowed(_ => true)` with credentials,
  wildcard origins on authenticated APIs, `[EnableCors]` on sensitive routes.
- Cookies and session: cookie auth or session cookies without `Secure`
  (`CookieSecurePolicy.None`/`SameAsRequest`), `HttpOnly = false`,
  `SameSite = None` without need, long `ExpireTimeSpan` with sliding expiry.
- Antiforgery: cookie-authenticated MVC or Razor Pages without
  `AutoValidateAntiforgeryToken`, `[IgnoreAntiforgeryToken]` on mutating
  actions, minimal-API form endpoints with `DisableAntiforgery()`.
- JWT and OIDC: `ValidateIssuer`/`ValidateAudience`/`ValidateLifetime`/
  `ValidateIssuerSigningKey = false`, `RequireSignedTokens = false`,
  `SignatureValidator` that returns the token, symmetric keys in config or
  code, `ClockSkew` very large.
- Identity: weak `PasswordOptions`, lockout disabled, `RequireConfirmedAccount
  = false` (low).
- Secrets: connection strings with passwords, JWT signing keys, API keys in
  `appsettings*.json` (not `appsettings.Development.json` placeholders) or
  code; user-secrets and Key Vault references are fine.
- Resource limits (API4): `MaxRequestBodySize = null`, `[DisableRequestSizeLimit]`,
  no rate limiting (`AddRateLimiter`/`UseRateLimiter`) when login, token or
  password-reset endpoints exist, unbounded paging parameters.
- Inventory (API9, A02): Swagger/OpenAPI UI enabled outside development,
  multiple API versions where an old one stays mapped.
- Data protection: keys persisted to a plain file system path with no
  `ProtectKeysWith*` (low).

### SCA and versions (A03, A06)

- `PackageReference` and central versions checked against bundled advisories
  (extend `dnl_advisories.json` with ASP.NET Core packages: for example
  `Microsoft.AspNetCore.*`, `System.Text.Json`, `Newtonsoft.Json`,
  `Microsoft.IdentityModel.*`, `System.IdentityModel.Tokens.Jwt`).
- End-of-support target frameworks (`netcoreapp*`, `net5.0`, `net6.0`,
  `net7.0`, and so on, from a dated table in the data file).
- `packages.lock.json` used when present for transitive versions.
- Bundled JS under `wwwroot/lib` reuses the existing banner scan.

### Other rule families carried over

Crypto, deserialization (Newtonsoft `TypeNameHandling`, `BinaryFormatter`,
`JavaScriptSerializer` type resolvers), XXE, integrity (SRI on CDN scripts in
`.cshtml`), error handling (swallowed exceptions, stack traces returned),
logging (sensitive data in logs, missing auth-failure logging), business flows,
resources and API consumption (trusting outbound HTTP responses) run on SDK
projects unchanged. Rules that only make sense for System.Web (WebForms
ViewState, `Web.config` sections, WCF) stay legacy-only.

## Finding model and OWASP

- Findings are tagged through `core/owasp_web.py` like every DNL rule; new ids
  get mapping rows.
- `api_surface` set on controller (API), minimal-API and gRPC routes.
- A coverage test asserts that, for an ASP.NET Core target, the rules
  reachable from the `dotnet` analyzers map to all of A01-A10 and API1-API10.
- The README coverage table counts DNL rules reachable from `dotnet` in the
  `dotnet` row (today the inventory excludes DNL packages).

## Report

- Same tabs as today. Routes show the handler body for all three styles.
- Each route's auth line names its source (fallback policy, group, filter,
  attribute) so a reviewer can check the reasoning.
- Degraded-mode and helper notes as for dotnet_legacy.

## Testing

- Synthetic fixture apps under `tests/fixtures/` (generic names): a
  controllers API, a Razor Pages app, a minimal-API app with groups, and a
  mixed solution with one legacy and one SDK project.
- Unit tests per rule (positive, negative, REVIEW), each proven to fail before
  the rule exists.
- Helper tests for the `netcore` profile (symbols resolve to
  `Microsoft.AspNetCore.*`) and top-level statement lowering.
- Degraded-mode tests (monkeypatch `helper.find_helper` and
  `helper.sdk_available`).
- Regression: existing dotnet_legacy tests unchanged; mixed solution yields the
  same legacy findings.
- Linux container run at the end of each plan, as before.
- Acceptance: scans of public open-source ASP.NET Core apps cloned into the
  session scratchpad only, never committed or named in the repo.

## Suggested plan split

1. Foundation: SDK project parsing, helper `netcore` profile and modern-C#
   lowering, routes for the three styles, auth resolution, new `dotnet`
   analyzers, retire the tree-sitter analyzer.
2. Taint, XSS, object and property level: sources, sinks, Razor Core
   templates, IDOR, over-posting, exposure.
3. Configuration: pipeline and appsettings rules, JWT, CORS, cookies,
   antiforgery, identity, secrets, limits, inventory.
4. SCA, carried-over families verified on SDK projects, coverage test, README,
   degraded mode, acceptance.

## Decisions settled after the builder check (author's calls)

1. **Ownership.** `dotnet` owns projects with the `netcore` profile.
   `dotnet_legacy` owns legacy projects and SDK-style projects targeting
   `net4x` (they are MVC 5 / Web API 2 code, so the legacy route and auth
   model applies; one model per project, never both). Loose C# files go to
   `dotnet` when they use ASP.NET Core (`WebApplication`,
   `Microsoft.AspNetCore` usings, `ControllerBase`), otherwise to
   `dotnet_legacy` as today.
2. **Auth is three-state.** The resolver returns protected (with source),
   unprotected, or unknown. Unknown covers: a policy name never defined in the
   solution, a custom `IAuthorizationPolicyProvider`, conventions or endpoint
   filters the engine cannot read, and auth registered through an unresolved
   extension method on `IServiceCollection`/`IApplicationBuilder`/an endpoint
   builder. An unknown route is never reported as protected: it gets the
   missing-auth finding at `confidence="REVIEW"` with a note naming what could
   not be resolved. An unresolved global extension call affects every route
   without explicit endpoint auth; an unresolved group-level call affects only
   that group. Auth registered only inside an `IsDevelopment()` branch counts
   as absent. Partial `Startup` classes and pipeline code split across helper
   methods in the solution are followed through the IR.
3. **Environments.** When the environment cannot be determined (the usual
   case), rules assume Production, because that is what ships. Code inside an
   `IsDevelopment()` guard is not flagged. `appsettings.Development.json` is
   read only for secrets that look real (not placeholders), at one severity
   lower. Pipeline facts are tagged with the guarding environment so a rule
   can tell "dev only" from "always".
4. **Razor Pages linking.** `@model` and `@inherits` names resolve against the
   project's IR types by simple then full name (as WebForms code-behind does),
   with `@namespace` and `@using` from the page and from `_ViewImports.cshtml`
   files up the folder chain. No Roslyn compilation of `.cshtml`. A page whose
   model cannot be found is still a route, its handlers are unknown, and auth
   follows the folder conventions only.
5. **Reference assemblies.** NuGet packages restored at helper build time,
   like the net48 refs (the build already needs a NuGet restore; no new
   offline requirement). Pinned to 8.0.x. Projects targeting net9 or newer
   compile against the 8.0 refs, and the model adds one note per scan saying
   so; APIs added after 8.0 may not resolve and fall back to the name tables.
6. **Coverage accounting is static.** `tests/owasp_inventory.py` gains a DNL
   pass: rule id literals in `checks/dnl/` modules that the `languages/dotnet`
   analyzers import (directly or transitively) count for the `dotnet` row, and
   ids in modules only reachable from `dotnet_legacy` do not. A fixture-based
   end-to-end test also asserts every A01-A10 and API1-API10 category appears
   on the synthetic fixture apps.
7. **Retired ids.** AUTH-001 is shared by other languages and stays; nothing in
   the repo stores baselines. The new missing-auth rule for `dotnet` must
   honour `--allow-path`, which today suppresses AUTH-001 on matching routes.
   The old IDOR-001 on ASP.NET Core is superseded by the DNL IDOR rule.
8. **Degraded-mode minimum.** Without the helper: top-level statements and
   minimal-API lambdas are lowered, routes and auth are found for all three
   styles, and the code rules run as they do for legacy degraded mode (no
   symbols, name-table fallback). Degraded tests assert route and auth
   results for each style plus one taint finding per style.

## Left to the builder

- Exact module boundaries and names inside `checks/dnl/`.
- Severity per rule, following existing DNL conventions.
- Which modern C# constructs need IR changes versus being ignorable for
  taint (verify with tests, not assumptions).
- New rule numbering within the DNL families.
