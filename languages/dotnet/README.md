# dotnet: ASP.NET Core (modern .NET)

## What it is

An appsec review package for ASP.NET Core apps (SDK-style projects on net5.0+,
netcoreapp, netstandard, plus loose `.cs` files that are clearly ASP.NET Core).
It runs on the shared C#/.NET engine in `checks/dnl` -- the same project model,
Roslyn helper IR and finding conventions as `languages/dotnet_legacy`, which
keeps .NET Framework apps. In a mixed solution each package takes its own
projects and the helper runs once for both. The earlier tree-sitter analyzer
(`aspnet`) is retired; `--framework aspnet` is no longer valid.

Route discovery and authorization, offline dependency (SCA) rules and the carried-over rule families
(see `CARRIED_RULES.md`) run on Core. Taint and config rules for Core come later. Forcing
`--framework deps` alone drops the route-level findings: they go to the `config` analyzer, which then does not run.

## Frameworks reported as separate results

| Framework | Detected when | Routes |
|---|---|---|
| `controllers` | a class carries `[ApiController]` / `[Controller]` or derives from `Controller` / `ControllerBase` | attribute and conventional MVC / API controller actions |
| `razorpages` | a `.cshtml` with `@page` under a `Pages` folder | one route per page handler |
| `minimalapi` | a `MapGet/Post/Put/Patch/Delete/Methods/Group/Hub/GrpcService/HealthChecks/Fallback` call, or `.Map("...")` | minimal API endpoints, SignalR hubs, gRPC services, health checks, fallbacks, OpenAPI endpoints |
| `config` | always, once the language is detected | no routes; route-less findings (never-denying handlers / policies / filters, middleware order) |
| `deps` | a netcore project with package references, a `packages.lock.json` beside it, bundled JS under a `lib` / `libs` / `scripts` / `content` folder, or an end-of-support target framework | no routes; offline SCA (DNL-SCA-001/002/003/006, plus the shared packages.config / HintPath / nuget.config checks) |

Route-less findings go to `config`; if `config` is not enumerated, the first
enumerated analyzer reports them.

## Authorization

Every route is resolved to one of four states (`checks/dnl/auth_core.py`):

- **protected**: `[Authorize]` (or a project attribute deriving from it, or an
  authorization filter that can deny), `RequireAuthorization` on an endpoint,
  group or Map call, a global `AuthorizeFilter`, a Razor Pages convention, or a
  fallback policy for endpoints with no authorization metadata. `Route.auth_decorators`
  holds the source (for example `group:/api RequireAuthorization`).
- **anonymous**: `[AllowAnonymous]`, `.AllowAnonymous()` or an
  `AllowAnonymousTo*` convention (`Route.explicit_access = "PermitAll"`).
- **unprotected**: nothing protects the route, or the only candidate never
  denies (for example a policy whose handler always succeeds).
- **unknown**: something could affect authorization that the analyzer cannot
  trace (an unresolved extension call, an untraced caller, a policy defined
  conditionally, a custom policy provider). Reported as a REVIEW finding that
  lists the reasons; never as protected.

The decision is stored in `Route.meta["auth"]`. Routes that only exist when the
environment is Development get no AUTHZ finding. Registrations count only when
they certainly run in Production.

## Rules

The rule table (severity, OWASP tags) lives in
[`languages/dotnet_legacy/README.md`](../dotnet_legacy/README.md#rules).
This package emits:

| Rule | Where |
|---|---|
| DNL-AUTHZ-001 | unprotected (medium, high when an explicit mutating verb), unknown (medium REVIEW), anonymous (info) |
| DNL-AUTHZ-002 | anonymous route with an explicit mutating verb |
| DNL-AUTHZ-003 | authorization handler, policy or filter attribute that never denies |
| DNL-AUTHZ-004 | privileged-looking controller / page / action protected with no roles or policy |
| DNL-AUTHZ-008 | `UseAuthorization` missing or misordered; high when `SuppressCheckForUnhandledSecurityMetadata` is true |

`--allow-path` suppresses DNL-AUTHZ-001 for matching route paths
(case-insensitive).

## Requirements and degraded mode

The Roslyn helper (`tools/roslyn-ir`, .NET 8 SDK) is required, exactly as for
dotnet_legacy. With `--allow-degraded` the C# is lowered by tree-sitter instead
(no semantic symbols); the same rules run, every result carries `degraded`, and
findings can be less precise.

## What still needs a human

- Anything REVIEW: read the listed reasons and confirm by hand.
- Authorization done inside handler bodies (manual `User.IsInRole` checks) is
  not modelled.
- Third-party extension registrations that are not in the known-harmless table
  make affected routes unknown by design.

## Known limits

- Unresolved attributes with neutral names are ignored (parked N5): only names that look like
  authorize / anonymous attributes block a PROTECTED verdict.
- Unresolved global extensions only affect routes without explicit endpoint auth (parked N6, spec
  Decision 2): a route with its own `RequireAuthorization` stays protected.
- `RequireAssertion` with a non-literal lambda is counted as a deny (it may in fact always succeed).
- `MapGroup(...).MapControllers()` / `MapRazorPages()` / `MapControllerRoute()`: the group prefix and
  conventions are not applied; the routes are reported REVIEW with a reason.
- IR nesting cap: code nested deeper than the helper's JSON depth cap (for example a fluent chain of a
  few hundred links) is not lowered. A model note says where, and a `MapGet`/`MapPost`/... call with a
  literal pattern inside it is reported as a REVIEW route recovered from source text.
- Blazor `.razor` components are not analyzed (only `MapRazorComponents` is listed as an endpoint).
- Extension methods defined in another project are not followed; routes registered there are found by a
  sweep and carry the "caller unknown" reason.
- A `MapHub<T>` / `MapGrpcService<T>` whose type is not in the solution is REVIEW (its `[Authorize]`
  cannot be read), as is a `[Route]` whose template is not a constant.
- Behaviour change in dotnet_legacy (intended): modern C# lowering removes a false positive on a
  constant-only `switch`.
