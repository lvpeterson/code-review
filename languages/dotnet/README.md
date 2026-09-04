# .NET: aspnet

Route extraction uses `tree-sitter-c-sharp`, which gives real start/end
positions natively (unlike javalang for Spring, which needs manual
brace-counting).

## Detection

`detector.py` is an explicit stub per its own docstring: any `.csproj`
containing `"Microsoft.AspNetCore"`/`"Microsoft.NET.Sdk.Web"` (or, failing
that, any `.cs` file containing `"Microsoft.AspNetCore"`) → `aspnet`. **MVC,
Web API, and Minimal API are not distinguished** -- all three map to the
same `"aspnet"` framework string and get analyzed by the same file.

## What's recognized

Two independent routing conventions, extracted separately and merged into
one route list:

- **Minimal APIs**: `<obj>.MapGet/MapPost/MapPut/MapPatch/MapDelete(path,
  handler, ...)`. No router-object confirmation the way gin's veto pattern
  works -- any object with one of these method names is claimed as a route.
  `auth_decorators` comes from any identifier argument before the handler
  (middleware-position args), described as `<inline handler>` if it isn't a
  bare identifier. **`source_file`/`source_start_line`/`source_end_line`
  are never set for Minimal API routes** -- the HTML report always falls
  back to showing just the registration line for these, never the handler
  body.
- **Attribute routing**: only inside a `class` carrying `[ApiController]`
  or `[Controller]` -- a plain class with neither is skipped entirely. The
  controller name is the class name with a trailing `Controller` suffix
  stripped (`UsersController` → `Users`), substituted into a class-level
  `[Route("api/[controller]")]`'s `[controller]` token. Method-level
  `[HttpGet]`/`[HttpPost]`/`[HttpPut]`/`[HttpPatch]`/`[HttpDelete]`
  attributes are matched regardless of their order relative to other
  attributes (e.g. `[Authorize]` before or after `[HttpDelete(...)]` both
  work). This variant **does** get real source-range resolution (the
  method's own start/end).
- **Auth**: `KNOWN_AUTH_INDICATORS = {"Authorize"}` -- a single-entry set,
  and it **only applies to attribute-routing routes**. A Minimal API
  middleware argument (e.g. `app.MapPost("/orders", RequireAuth,
  CreateOrder)`) gets captured into `auth_decorators` as `"RequireAuth"`,
  but since that string isn't `"Authorize"`, **AUTH-001 will still fire on
  that route** even though something auth-shaped is visibly right there in
  the registration -- this is a real, potentially confusing gap, not a bug
  in the check itself: the known-indicators set was written for the
  attribute-routing convention and was never extended to cover common
  Minimal API middleware naming.
- **No global-auth detection, no CONFIG checks, no `extra_param_names` at
  all** -- `core/bodyscan.py` isn't imported by this analyzer.

## What still needs a human

- **Every Minimal API route's handler body is unresolved** -- the report
  can't show you the actual handler code, only the registration line.
  Whatever the handler does (validation, ownership checks, raw SQL) has to
  be found and read manually every time.
- **`RequireAuth`-shaped Minimal API middleware will always trip AUTH-001**
  -- before treating any Minimal API AUTH-001 finding as a real gap, check
  whether there's a middleware argument sitting right there in the
  `MapGet`/`MapPost`/etc. call that just isn't literally named
  `"Authorize"`. If your codebase has a consistent custom auth-middleware
  name, that's the first thing worth tuning in `KNOWN_AUTH_INDICATORS`
  before trusting this framework's findings.
- **No global-auth-mechanism detection at all** -- if auth is enforced via
  `app.UseAuthorization()` + policy-based middleware rather than
  per-endpoint `[Authorize]`, there's no equivalent check here (unlike
  Spring's `SecurityFilterChain` detection) and **every route without an
  explicit `[Authorize]` will be flagged**, no caveat attached.
- **No query/body parameter extraction at all** -- `[FromQuery]`/
  `[FromBody]` parameter attributes are structurally precise (like
  Spring/FastAPI) but simply not built yet, so IDOR-001 only ever fires on
  path parameters here, never query/body ones.
- **No CORS-wildcard check** despite `[EnableCors("AllowAll")]` being a
  real, checkable, single-pattern mechanism -- not built yet.
- **No SQL/command/path/SSRF injection checks** -- trace
  string-interpolated `SqlCommand`/EF Core raw SQL
  (`.FromSqlRaw($"...")`), `Process.Start`, `File.Open(userPath)`,
  `HttpClient.GetAsync(userUrl)` patterns by hand.
- **No framework-version detection** -- an outdated
  `Microsoft.AspNetCore.*` package version isn't flagged.
- **Ownership-check tracing** -- IDOR-001 (where it fires) only flags the
  id-like param exists, never whether an ownership check happens.
