# ASP.NET Core Taint, XSS, Object and Property Level Implementation Plan (Plan 2 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the shared taint engine, the template XSS rules and the object/property-level rules on ASP.NET Core routes, with ASP.NET Core request sources, parameter binding, sinks, sanitizers, Razor Core view and page linking, and Core idioms for IDOR, over-posting and excessive exposure.

**Architecture:** The engine (`checks/dnl/taint.py`, `taint_solver.py`, `taint_tables.py`) already accepts any `RouteRef` with `type`/`method`/`route`, and `CoreRouteRef` subclasses it. This plan adds ASP.NET Core table rows (sym rows plus degraded text fallbacks) next to the legacy ones, makes parameter binding profile-aware (Core refs exclude DI services and framework types), lets minimal-API lambda handlers own their callees in the reach graph, teaches `templates.py`/`rules_xss.py` the Core view and Razor Pages conventions, and extends `rules_object.py` to Core kinds. Each rule module is wired into `languages/dotnet/analyzers.py` in the task that makes it correct for Core.

**Tech Stack:** Python 3.10+, pytest, the Roslyn helper (netcore profile from Plan 1), tree-sitter-c-sharp for degraded mode.

**Spec:** `docs/superpowers/specs/2026-11-14-aspnetcore-design.md` (Taint; Object-level and property-level; Report; Testing; Decision 8). Plan 1 (`docs/superpowers/plans/2026-11-15-aspnetcore-foundation.md`) is done on `feature/aspnetcore-foundation`; this plan's branch `feature/aspnetcore-taint` is stacked on it.

**Reference:** an interface map of the taint engine written for this plan is at `.superpowers/plan2-notes/taint-map.md` (gitignored scratch; table formats, matching rules, file:line of every legacy-only assumption). Implementers read the section their task names.

## Global Constraints

- Public repo: nothing committed (code, fixtures, tests, README, docs, commit messages) may name a client, engagement, target app, local path or user. Fixtures synthetic, generic names. Grep the diff before every commit.
- Prose and comments use `--`, never em-dashes; comment density like the existing `checks/dnl/*.py`.
- Tests: `.venv\Scripts\python -m pytest -q` from the repo root. Baseline at branch time: 1424 passed. Must also pass on Linux.
- No regression for dotnet_legacy: every existing dotnet_legacy test passes unchanged; a legacy table change that alters a legacy finding is a regression unless a task names it. Core-only behaviour is gated on the ref being a `CoreRouteRef` or its project profile being `netcore`, never on guesses.
- A false "safe" is the worst outcome: a resolved sym that matches no Core row must not silently hide a real Core source -- add the row; an unresolved Core construct falls back to the text tables; anything the engine cannot see stays REVIEW where the rule has a REVIEW form. Noise is secondary.
- Rule ids are reused (one catalog): DNL-INJ-001..006, DNL-XSS-001/003, DNL-PATH-001, DNL-REDIR-001, DNL-SSRF-001, DNL-LOG-001, DNL-DESER-001, DNL-XXE-001, DNL-AUTHZ-005/006/007. No new ids unless a task names one (none does). Rule ids stay quoted literals.
- Helper tests use the `roslyn_helper` fixture; degraded tests monkeypatch `checks.dnl.helper.find_helper` -> None and `helper.sdk_available` -> False, then `project.prepare(root, True)`. Clear `project._CACHE` between fixtures.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Branch `feature/aspnetcore-taint`. No push, no merge. Do not stage `.superpowers`.

## Decisions taken here (builder's calls)

1. **Binding exclusions apply to Core refs only.** Legacy `_entry_taint` keeps tainting every non-primitive parameter (legacy MVC has no DI parameter injection by default). For a `CoreRouteRef`, a parameter is NOT a source when: it has `[FromServices]`/`[FromKeyedServices]`; its type is a framework type (`HttpContext`, `HttpRequest`, `HttpResponse`, `CancellationToken`, `ClaimsPrincipal`, `ILogger`/`ILogger<T>`, `ILoggerFactory`, `IConfiguration`, `IWebHostEnvironment`, `IHostEnvironment`, `IServiceProvider`, `IOptions<T>`/`IOptionsSnapshot<T>`/`IOptionsMonitor<T>`, `IHttpClientFactory`, `HttpClient`, `IAuthorizationService`, `UserManager<T>`, `SignInManager<T>`, `LinkGenerator`, `IUrlHelper`); its type is registered as a service in the project's pipeline (`AddScoped/AddTransient/AddSingleton/AddKeyed*` type arguments, `AddDbContext<T>`, `AddDbContextPool<T>`, `AddHttpClient<T>`); its type derives from `DbContext`; or its type is an interface or abstract class other than `IFormFile`, `IFormFileCollection`, `IFormCollection` (interfaces cannot be bound from the request body). Everything else, including complex DTOs and `IFormFile`, is tainted; `[AsParameters]` parameters are tainted as complex types.
2. **`[BindProperty]` is a source.** On a Razor Pages PageModel or a controller, a property with `[BindProperty]` (or any public settable property when the class has `[BindProperties]`) is request input for non-GET handlers/actions, and for GET ones only when `SupportsGet = true`.
3. **Log sink precision.** `ILogger` calls (`Log`, `LogTrace`..`LogCritical`, `BeginScope`) are a `log` sink only on the message-template argument (the first `string` argument after any `EventId`/`Exception`), and only when that argument is an interpolated string, a concatenation, or a non-literal value; placeholder arguments are never sinks.
4. **HTML content results.** `ControllerBase.Content`, `Results.Content`, `TypedResults.Content` and `HttpResponse.WriteAsync` are `xss` sinks. The three `Content` forms count only when their content-type argument is a constant containing `html` or is not a constant (conservative); with no content-type argument they produce `text/plain` and are not sinks. `WriteAsync` always counts (it sets no content type and browsers may sniff).
5. **Excessive exposure for Core** requires an entity with a sensitive-looking member (`Password*`, `*Hash`, `*Token`, `*Secret`, `IsAdmin`, `Role*`, matched on member names, case-insensitive), per the spec. Legacy `DNL-AUTHZ-007` keeps its current behaviour.
6. **Plan 4 owns the other families** (crypto, deserialization rule module, XXE configuration, integrity, errors, logging-config, flows, resources, misc). `rules_taint` imports `rules_deser_xml` for the XXE filter, so the coverage inventory will start counting those ids for `dotnet` in this plan; that is accepted and Plan 4 wires and verifies them.

## Review Focus

1. A DI service and a request DTO with the same simple name in different namespaces: the service registration must not make the DTO a non-source (match registrations by resolved full name when available, else by simple name AND the parameter's declared namespace context) (test in Task 2).
2. `FromSqlRaw($"... {x}")` is injectable (an interpolated string passed to a Raw API is concatenated), while `FromSqlInterpolated($"... {x}")` and `FromSql($"... {x}")` are parameterised (test in Task 3).
3. A minimal-API lambda that only calls a project helper which reads `HttpContext.Request` must attribute the helper's sink to the lambda's route, not to `ref=None` (test in Task 2).
4. A Razor Page GET handler reading a `[BindProperty]` property without `SupportsGet` is not a finding; the same property read in `OnPost` is (test in Task 2).
5. `@Html.Raw(Model.X)` on a page whose handler assigns `X` from a tainted source is a proven DNL-XSS-003 tied to the page route; the same with `X` from a constant is REVIEW-low at most (test in Task 4).

---

### Task 1: Core request sources, taint fixture, wire rules_taint

**Files:**
- Modify: `checks/dnl/taint_tables.py` (Core `Source` rows, `REQUEST_TEXT`/related text regexes, `INCOMING_REQUEST_TEXT`/`INCOMING_BODY_READS`), `checks/dnl/taint.py` (`_REQUEST_RE`, `_REQUEST_PROP_RE`, `_REQUEST_ANY_RE` text fallbacks for Core spellings), `languages/dotnet/analyzers.py` (run `rules_taint.check`)
- Create: `tests/fixtures/aspnetcore/taint_app/` (see Step 1), `tests/test_dnl_core_taint.py`

**Interfaces:**
- Consumes: Plan 1 `routes_core.discover_all`, `project.get_model(root, "dotnet")`, `taint_solver.entry_hits`, `rules_taint.check(model, refs)`.
- Produces: Core sources by sym (`Microsoft.AspNetCore.Http.HttpRequest.(Query|Form|Headers|Cookies|RouteValues|Body|BodyReader|Path|PathBase|QueryString|Host|Method|Scheme|ContentType)`, `Microsoft.AspNetCore.Http.HttpRequest.ReadFormAsync`, `Microsoft.AspNetCore.Http.HttpRequestJsonExtensions.ReadFromJsonAsync`, `Microsoft.AspNetCore.Http.RoutingHttpContextExtensions.GetRouteValue`, `Microsoft.AspNetCore.Routing.RouteData.Values`, `Microsoft.AspNetCore.Http.IFormFile.(FileName|Name|ContentType|OpenReadStream)`, `Microsoft.AspNetCore.Http.IFormCollection.Item`) with origin detail names `"Request"` / `"Request.Body"` / `"RouteValues"` / `"IFormFile"`; text fallbacks accept `Request`, `HttpContext.Request`, `Context.Request`, `context.Request`, `ctx.Request`, `httpContext.Request` with the Core member names above. Legacy rows unchanged.
- `languages/dotnet/analyzers.py` `_code_results` adds `findings += guarded("rules_taint", lambda: rules_taint.check(model, refs))`.

- [ ] **Step 1: Create the fixture** `tests/fixtures/aspnetcore/taint_app/` (`TaintApp.csproj`: `Microsoft.NET.Sdk.Web`, `net8.0`, `ImplicitUsings enable`; synthetic): `Data/AppDb.cs` (`AppDb : DbContext` with `DbSet<Order> Orders`, `DbSet<User> Users`), `Models/Order.cs` (`Id`, `OwnerId`, `Total`), `Models/User.cs` (`Id`, `Email`, `PasswordHash`, `IsAdmin`), `Models/OrderDto.cs`; `Controllers/EchoController.cs` (`[ApiController][Route("echo")] : ControllerBase`, actions `[HttpGet("q")] Q()` -> `var q = Request.Query["q"]; return Content(q);`... (later tasks add sinks; this task needs only sources reaching an existing neutral sink): `[HttpGet("cmd")] Cmd() { var a = HttpContext.Request.Query["a"].ToString(); System.Diagnostics.Process.Start("tool", a); return Ok(); }`, `[HttpPost("body")] async Task<IActionResult> Body() { var s = await new StreamReader(Request.Body).ReadToEndAsync(); System.IO.File.ReadAllText(s); return Ok(); }`, `[HttpGet("route/{v}")] Route() { var v = HttpContext.GetRouteValue("v")?.ToString(); System.IO.File.Delete(v!); return Ok(); }`, `[HttpGet("hdr")] Hdr() { var h = Request.Headers["X-Path"].ToString(); System.IO.File.ReadAllText(h); return Ok(); }`, `[HttpGet("const")] Const() { System.Diagnostics.Process.Start("tool", "fixed"); return Ok(); }`); `Program.cs` (top-level: `AddControllers`, `AddDbContext<AppDb>()`, `MapControllers`).

- [ ] **Step 2: Write the failing tests** in `tests/test_dnl_core_taint.py` (module fixture: prepare `taint_app` with the helper; `refs = routes_core.discover_all(get_model(root, "dotnet"))`; helper `hits(findings, rule, handler)`):
  - `test_query_source_reaches_command_sink`: `rules_taint.check` yields `DNL-INJ-002` high on `EchoController.Cmd`, description contains `Source: Request`.
  - `test_body_route_and_header_sources`: `DNL-PATH-001` on `EchoController.Body`, `EchoController.Route`, `EchoController.Hdr`.
  - `test_constant_is_not_a_source`: no finding on `EchoController.Const`.
  - `test_core_sym_rows_resolve`: for `EchoController.Cmd`, the source origin detail is `Request` and the helper resolved the sym (assert the IR member node for `Query` carries `sym == "Microsoft.AspNetCore.Http.HttpRequest.Query"`, guarding against a silent no-source because sym is authoritative).
  - `test_degraded_core_sources`: the same three PATH/INJ findings without the helper (text fallbacks).
  - `test_dotnet_analyzer_reports_taint`: `enumerate_target(taint_app)` dotnet results contain `DNL-INJ-002` with a route whose `meta["kind"] == "controller"` and OWASP `A05:2025`.
  - `test_legacy_sources_unchanged`: `tests/test_dnl_taint.py` and `tests/test_dnl_rules_taint.py` still pass (run them; no edits).

- [ ] **Step 3: Run to verify they fail.** Expected: FAIL (no Core rows; rules_taint not wired).
- [ ] **Step 4: Implement** the rows, text fallbacks and wiring.
- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.
- [ ] **Step 6: Commit** `feat(dnl): ASP.NET Core request sources; taint rules on dotnet routes`

---

### Task 2: Parameter binding, [BindProperty], minimal-API handler reach

**Files:**
- Modify: `checks/dnl/taint_solver.py` (`_entry_taint`/`_tainted_param_type` profile-aware; entry replay seeds `[BindProperty]` field taint; reach graph includes synthetic lambda / local-function handler methods), `checks/dnl/taint.py` only if field seeding needs a hook
- Modify: `tests/fixtures/aspnetcore/taint_app/` (add files below)
- Test: `tests/test_dnl_core_taint.py`

**Interfaces:**
- Consumes: `pipeline.pipeline_for(model, proj)` (service registrations: `PipeCall` with `kind == "services"`, generic type args from IR `targs`), `CoreRouteRef`.
- Produces: `taint_solver.core_param_taint(model, ref) -> dict[int, Taint]` (used by `entry_hits` for `CoreRouteRef`; legacy refs keep `_entry_taint`); `taint_solver.bound_properties(model, t, method) -> set[str]` (lower-cased property names that are request input for that handler per Decision 2). Entry replay passes those as field taint with origin detail `"[BindProperty] <Name>"`. `entry_hits` registers the replay result's `calls` for an entry whose method key is not in the solved `results` (synthetic handler), so callees reached from a lambda are attributed to its route.

- [ ] **Step 1: Extend the fixture**: `Services/IReport.cs` + `Report.cs` (`IReport { string Query { get; } }`), registered `builder.Services.AddScoped<IReport, Report>();` and `builder.Services.AddScoped<Auditor>();` (concrete class `Auditor { public string Sql = ""; }`); `Models/ReportRequest.cs` (`Query`), `Models/SearchArgs.cs` (`Sql`), and a decoy `Models/Auditor.cs` in namespace `TaintApp.Models` (`Auditor { public string Sql { get; set; } = ""; }` -- a request DTO with the same simple name as the registered service); `Controllers/BindController.cs` (`[ApiController][Route("bind")] : ControllerBase`, all sinking into `System.Diagnostics.Process.Start("tool", x)`): `Di(IReport report)` (x = report.Query), `Fs([FromServices] Auditor a)` (x = a.Sql), `Dto(ReportRequest req)` (x = req.Query), `Decoy(TaintApp.Models.Auditor a)` (x = a.Sql), `Ctx(HttpContext ctx, CancellationToken ct, ILogger<BindController> log)` (x = log.ToString()), `Upload(IFormFile file)` (x = file.FileName); `Pages/Comment.cshtml` (`@page`, `@model CommentModel`) + `Pages/Comment.cshtml.cs` (`CommentModel : PageModel`, `[BindProperty] public string Text { get; set; } = "";`, `[BindProperty(SupportsGet = true)] public string Q { get; set; } = "";`, `OnGet() { Process.Start("tool", Text); Process.Start("tool2", Q); }`, `OnPost() { Process.Start("tool3", Text); }`); in `Program.cs`: `app.MapGet("/m/cmd", (string q) => Process.Start("tool", q));`, `app.MapGet("/m/args", ([AsParameters] SearchArgs a) => Process.Start("tool", a.Sql));`, `app.MapGet("/m/helper", (HttpContext ctx) => Helpers.Run(ctx));` with `static class Helpers { public static IResult Run(HttpContext c) { var x = c.Request.Query["x"].ToString(); Process.Start("tool", x); return Results.Ok(); } }`.

- [ ] **Step 2: Write the failing tests**:
  - `test_di_and_framework_params_are_not_sources`: no `DNL-INJ-002` on `BindController.Di`, `BindController.Fs`, `BindController.Ctx`.
  - `test_dto_upload_and_decoy_are_sources`: `DNL-INJ-002` on `BindController.Dto`, `BindController.Upload`, `BindController.Decoy` (Review Focus 1).
  - `test_bind_property_respects_supports_get`: on `CommentModel.OnGet` exactly one hit (sink `tool2`, source detail contains `[BindProperty] Q`); on `CommentModel.OnPost` one hit with detail `[BindProperty] Text` (Review Focus 4).
  - `test_minimal_api_params_and_as_parameters`: `DNL-INJ-002` on routes `/m/cmd` and `/m/args`.
  - `test_lambda_handler_owns_helper_callee`: the `DNL-INJ-002` in `Helpers.Run` is routed to `/m/helper` (finding.route.path == "/m/helper"), not route-less (Review Focus 3).
  - `test_legacy_binding_unchanged`: a legacy MVC action parameter typed as an interface stays a source (use an existing `taint_app` legacy action or add one to `tests/fixtures/dotnet_legacy/taint_app` only if none exists; prefer an existing assertion in `tests/test_dnl_taint_solver.py` -- run it unchanged).
  - `test_degraded_binding`: the same set of findings as with the helper for `BindController` and the page (registrations matched by simple name in degraded mode; the decoy case may be excluded from parity only if the test names it and asserts it is REVIEW or still a finding -- never silently dropped).
- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 4: Implement** per Decisions 1-2 and the Interfaces.
- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.
- [ ] **Step 6: Commit** `feat(dnl): ASP.NET Core parameter binding, [BindProperty] and lambda handler reach`

---

### Task 3: Core sinks and sanitizers

**Files:**
- Modify: `checks/dnl/taint_tables.py` (Sink rows, Sanitizer rows; a `Sink` field for the content-type condition if needed), `checks/dnl/taint.py` (only for the log message-argument rule and the content-type condition)
- Modify: `tests/fixtures/aspnetcore/taint_app/` (add `Controllers/SinkController.cs` and minimal-API lines below)
- Test: `tests/test_dnl_core_taint.py`

**Interfaces:**
- Produces Sink rows (kind -> members), all gated by resolved type when sym is present and by receiver/derives text otherwise:
  - sql: `Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw` (arg: sql), `Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw` (arg: sql), `Microsoft.EntityFrameworkCore.Infrastructure.DatabaseFacade` equivalents, `Microsoft.Data.SqlClient.SqlCommand` (`.ctor` arg 0, `CommandText` assign), `Npgsql.NpgsqlCommand`, `Microsoft.Data.Sqlite.SqliteCommand`, `MySqlConnector.MySqlCommand`, `MySql.Data.MySqlClient.MySqlCommand` (same shape). `FromSqlInterpolated`, `FromSql`, `ExecuteSqlInterpolated[Async]`, `ExecuteSql[Async]`, `SqlQuery` are NOT sinks. In degraded mode `FromSqlRaw`/`ExecuteSqlRaw[Async]`/`SqlQueryRaw` match by name with `unresolved_ok=True`.
  - redirect: `Microsoft.AspNetCore.Mvc.ControllerBase.Redirect|RedirectPermanent|RedirectPreserveMethod|RedirectPermanentPreserveMethod` (derives `ControllerBase` and `Controller`), `Microsoft.AspNetCore.Http.Results.Redirect`, `Microsoft.AspNetCore.Http.TypedResults.Redirect`, `Microsoft.AspNetCore.Http.HttpResponse.Redirect`, `Microsoft.AspNetCore.Mvc.RedirectResult` `.ctor`. `LocalRedirect*` and `Results.LocalRedirect` are not sinks; the existing `IsLocalUrl` guard keeps working.
  - path: `ControllerBase.PhysicalFile|File` (path argument when it is a `string`), `Results.File|PhysicalFile`, `TypedResults.PhysicalFile`; existing `System.IO` rows cover `IFormFile.FileName` flows.
  - header: `Microsoft.AspNetCore.Http.IHeaderDictionary.Item` assign, `Append|Add|TryAdd` value argument; `Microsoft.AspNetCore.Http.IResponseCookies.Append` value argument.
  - ssrf: `System.Net.Http.HttpRequestMessage` `.ctor` uri argument (HttpClient rows already exist).
  - xss: `Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper.Raw`, `Microsoft.AspNetCore.Html.HtmlString` `.ctor`, `Microsoft.AspNetCore.Components.MarkupString` `.ctor`, `ControllerBase.Content` / `Results.Content` / `TypedResults.Content` per Decision 4, `Microsoft.AspNetCore.Http.HttpResponseWritingExtensions.WriteAsync`.
  - log: `Microsoft.Extensions.Logging.LoggerExtensions.Log|LogTrace|LogDebug|LogInformation|LogWarning|LogError|LogCritical|BeginScope` and `Microsoft.Extensions.Logging.ILogger.Log` per Decision 3.
- Sanitizers: `System.Text.Encodings.Web.HtmlEncoder|JavaScriptEncoder|UrlEncoder` `.Encode` (xss; `UrlEncoder` also redirect is NOT cleansed -- it encodes but does not restrict host; only xss), `System.Net.WebUtility.HtmlEncode` already present.

- [ ] **Step 1: Extend the fixture** with `Controllers/SinkController.cs` (`[ApiController][Route("sink")]`, injecting `AppDb db` and `ILogger<SinkController> log` via constructor; actions with `string term`/`string url`/`string name`/`string user` parameters): `RawConcat` (`db.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Id = " + term)`), `RawInterp` (`db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE Id = {term}")`), `Interp` (`db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Id = {term}")`), `FromSqlSafe` (`db.Orders.FromSql($"... {term}")`), `Exec` (`db.Database.ExecuteSqlRaw("DELETE FROM Orders WHERE Id = " + term)`), `SqlCmd` (`new Microsoft.Data.SqlClient.SqlCommand("SELECT " + term)` -- add the `Microsoft.Data.SqlClient` PackageReference; if the helper cannot resolve it the degraded name rule still fires), `Go` (`return Redirect(url);`), `GoLocal` (`return LocalRedirect(url);`), `GoGuarded` (`if (Url.IsLocalUrl(url)) return Redirect(url); return BadRequest();`), `FileGet` (`return PhysicalFile(Path.Combine("/srv", name), "text/plain");`), `FileSafe` (`return PhysicalFile(Path.Combine("/srv", Path.GetFileName(name)), "text/plain");`), `Hdr` (`Response.Headers["X-Echo"] = name; return Ok();`), `Cookie` (`Response.Cookies.Append("c", name); return Ok();`), `LogInterp` (`log.LogInformation($"login {user}");`), `LogTemplate` (`log.LogInformation("login {User}", user);`), `LogConcat` (`log.LogWarning("login " + user);`), `Html` (`return Content(name, "text/html");`), `JsonOk` (`return Content(name, "application/json");`), `Encoded` (`return Content(HtmlEncoder.Default.Encode(name), "text/html");`), `Fetch` (`new HttpRequestMessage(HttpMethod.Get, url)` sent through an `HttpClient`); in `Program.cs`: `app.MapGet("/m/r", (string u) => Results.Redirect(u));`, `app.MapGet("/m/c", (string s) => Results.Content(s, "text/html"));`, `app.MapGet("/m/w", async (HttpContext c, string s) => await c.Response.WriteAsync(s));`.

- [ ] **Step 2: Write the failing tests** (one assertion per action; rule ids from the taint-map severity table):
  - `test_ef_core_raw_sql`: `DNL-INJ-001` on `RawConcat`, `RawInterp`, `Exec`, `SqlCmd`; none on `Interp`, `FromSqlSafe` (Review Focus 2).
  - `test_redirects`: `DNL-REDIR-001` on `Go` and `/m/r`; none on `GoLocal`, `GoGuarded`.
  - `test_paths`: `DNL-PATH-001` on `FileGet`; none on `FileSafe`.
  - `test_headers_and_cookies`: `DNL-INJ-005` on `Hdr` and `Cookie`.
  - `test_logging_templates`: `DNL-LOG-001` on `LogInterp` and `LogConcat`; none on `LogTemplate`.
  - `test_html_results`: `DNL-XSS-001` on `Html`, `/m/c`, `/m/w`; none on `JsonOk`, `Encoded`.
  - `test_ssrf_request_message`: `DNL-SSRF-001` on `Fetch`.
  - `test_degraded_sinks`: the same positive/negative sets without the helper, except entries the test lists explicitly with the reason (only allowed where degraded mode lacks types, e.g. `Content` content-type const reading still works by text).
  - `test_legacy_sinks_unchanged`: run `tests/test_dnl_rules_taint.py`, `tests/test_dnl_taint_fixes.py` unchanged.
- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 4: Implement** the rows and the two small engine rules (log message argument, content-type condition).
- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.
- [ ] **Step 6: Commit** `feat(dnl): ASP.NET Core sinks and encoders (EF Core raw SQL, results, headers, logging)`

---

### Task 4: Razor Core templates, view and page linking, wire rules_xss

**Files:**
- Modify: `checks/dnl/templates.py` (`views_for` for kind `controller` and `razorpage`; `_RAZOR_HELPER` accepts `Microsoft.AspNetCore.Html.HtmlString`; `_ENCODER` adds `HtmlEncoder.Default.Encode(`/`JavaScriptEncoder.Default.Encode(`; `_BENIGN_CALL` adds `Html.PartialAsync`, `Html.RenderPartialAsync`, `Component.InvokeAsync`, `Url.Page`, `Url.RouteUrl`), `checks/dnl/taint.py` (`_is_mvc_view` accepts `Microsoft.AspNetCore.Mvc.Controller.View|PartialView` by sym and `Controller` base by name; Razor Pages `Page()` returns make the PageModel's own property taint the view model), `checks/dnl/rules_xss.py` (Core page refs: link each page `.cshtml` to its handler refs; `Model.X` proof from the PageModel property taint after handler replay; XSS-004 stays legacy-only and must not fire on Core), `checks/dnl/routes_core.py` (only if the page `.cshtml` path is not already available on the ref: add `meta["page_file"]`), `languages/dotnet/analyzers.py` (run `rules_xss.check`)
- Modify: `tests/fixtures/aspnetcore/taint_app/` (add files below)
- Test: `tests/test_dnl_core_xss.py` (create)

**Interfaces:**
- Produces: `templates.views_for(model, ref) -> list[Path]` returns MVC view candidates for `meta["kind"] == "controller"` (same conventions as legacy: `Views/<Controller>/<Name>.cshtml`, `Areas/<A>/Views/...`, `Views/Shared/<Name>.cshtml`; area from `[Area]` on the controller when the namespace has no `Areas.` segment) and the page file for `meta["kind"] == "razorpage"`. `rules_xss` treats a page's `Model.X` as proven when the handler replay leaves the property `x` tainted with a source origin (including `[BindProperty]` sources from Task 2).

- [ ] **Step 1: Extend the fixture**: `Controllers/HomeController.cs` (`HomeController : Controller`): `Index(string name) { ViewBag.Name = name; return View(); }`, `Profile(string bio) => View(new ProfileVm { Bio = bio })`, `Static() => View("Profile", new ProfileVm { Bio = "fixed" })`; `Models/ProfileVm.cs`; `Views/Home/Index.cshtml` (`<p>@Html.Raw(ViewBag.Name)</p>`), `Views/Home/Profile.cshtml` (`@model ProfileVm`, `@Html.Raw(Model.Bio)`, plus `@Model.Bio` which is encoded), `Views/Shared/_Layout.cshtml` (`@Html.Raw(Request.Query["t"])`), `Views/_ViewImports.cshtml` (`@using TaintApp.Models`); `Pages/Comment.cshtml` (from Task 2) gains `@Html.Raw(Model.Text)` and `@(new Microsoft.AspNetCore.Html.HtmlString(Model.Q))`; `Pages/Fixed.cshtml` + `.cs` (`FixedModel`, `public string Note { get; set; } = "";`, `OnGet() { Note = "constant"; }`, page `@Html.Raw(Model.Note)`); `Pages/Encoded.cshtml` (`@Html.Raw(HtmlEncoder.Default.Encode(Model.Text))` with `@model CommentModel`).

- [ ] **Step 2: Write the failing tests** in `tests/test_dnl_core_xss.py`:
  - `test_viewbag_proof`: `DNL-XSS-003` high, confidence None, at `Views/Home/Index.cshtml`, route handler `HomeController.Index`.
  - `test_view_model_proof`: `DNL-XSS-003` high at the `Html.Raw(Model.Bio)` line of `Views/Home/Profile.cshtml` linked to `HomeController.Profile`; the plain `@Model.Bio` line has no finding.
  - `test_layout_request_read`: `DNL-XSS-003` high at `_Layout.cshtml`.
  - `test_page_bind_property_proof`: `DNL-XSS-003` high at both lines of `Pages/Comment.cshtml`, route handler `CommentModel.OnPost` (for `Text`) and `CommentModel.OnGet` (for `Q`, SupportsGet) (Review Focus 5).
  - `test_page_constant_is_review_at_most`: `Pages/Fixed.cshtml` has at most a low REVIEW `DNL-XSS-003`.
  - `test_encoder_is_recognised`: no finding on `Pages/Encoded.cshtml`.
  - `test_xss004_never_fires_on_core`: no `DNL-XSS-004` in the dotnet results.
  - `test_dotnet_analyzer_reports_xss`: `enumerate_target(taint_app)` dotnet results contain the proven XSS-003 findings with routes of kind `controller` / `razorpage`.
  - `test_degraded_xss`: same proven findings without the helper.
  - Legacy: `tests/test_dnl_templates.py` unchanged and passing.
- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 4: Implement**.
- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.
- [ ] **Step 6: Commit** `feat(dnl): Razor Core views and pages in template XSS; xss rules on dotnet routes`

---

### Task 5: IDOR, over-posting and excessive exposure on Core routes

**Files:**
- Modify: `checks/dnl/rules_object.py` (kind gates accept `controller`, `razorpage`, `minimalapi`; Core user markers and reject calls; Core over-posting rules; Core exposure with sensitive members), `languages/dotnet/analyzers.py` (run `rules_object.check`)
- Modify: `tests/fixtures/aspnetcore/taint_app/` (add files below)
- Test: `tests/test_dnl_core_object.py` (create)

**Interfaces:**
- Produces (Core refs only, legacy unchanged):
  - IDOR (`DNL-AUTHZ-005`, low REVIEW as today): user markers add `user.findfirst`, `user.findfirstvalue`, `httpcontext.user`, `usermanager.getuserid`, `usermanager.getuserasync`, `claimsprincipal` reads, and `IAuthorizationService.AuthorizeAsync(User, <record>, ...)` whose result gates a rejection; reject calls add `Results.NotFound|Forbid|Unauthorized|Challenge`, `TypedResults.NotFound|Forbid|Unauthorized|Challenge`, `NotFound()`, `Forbid()`, `Unauthorized()`, `Challenge()`, `StatusCode(401|403|404)`. Route parameters come from the action, handler or lambda parameters (`ref.method.params`).
  - Over-posting (`DNL-AUTHZ-006`): write verbs come from `route.methods` (POST/PUT/PATCH from attributes, handler names or `MapPost/MapPut/MapPatch`; `ANY` never qualifies); an entity type (or `List<T>`/`T[]` of one) bound as a parameter that is a request source under Task 2's rules; `[Bind("a,b")]`/`[Bind(Include=...)]` on the parameter or entity class suppresses it only for non-`[FromBody]` parameters of non-`[ApiController]` controllers and Razor Pages (JSON input ignores `[Bind]`); a `[BindProperty]` entity property on a PageModel/controller used in a non-GET handler; `TryUpdateModelAsync(entity)` / `TryUpdateModelAsync(entity, prefix)` without include expressions or an include-property list in a write-verb action or handler.
  - Exposure (`DNL-AUTHZ-007`, low): Core routes with `meta["api_surface"]` True; declared return type tokens contain an entity, or the handler returns `Ok(e)`, `Results.Ok(e)`, `TypedResults.Ok(e)`, `Json(e)`, or (minimal API) the bare expression of an entity, `List<Entity>`, `IEnumerable<Entity>`, `IQueryable<Entity>` or a DbSet chain without a non-entity `Select`; only when the entity has a sensitive-looking member per Decision 5.

- [ ] **Step 1: Extend the fixture**: `Controllers/OrdersController.cs` (`[ApiController][Route("orders")] : ControllerBase`, injecting `AppDb db`, `IAuthorizationService authz`): `[HttpGet("{id}")] Get(int id) => Ok(db.Orders.Find(id))`; `[HttpGet("mine/{id}")] Mine(int id) { var uid = User.FindFirstValue(ClaimTypes.NameIdentifier); var o = db.Orders.Find(id); if (o == null || o.OwnerId != uid) return Forbid(); return Ok(o); }`; `[HttpGet("authz/{id}")] async Task<IActionResult> Authz(int id) { var o = db.Orders.Find(id); var r = await authz.AuthorizeAsync(User, o, "Owner"); if (!r.Succeeded) return Forbid(); return Ok(o); }`; `[HttpPut("{id}")] Put(int id, Order o) { db.Update(o); db.SaveChanges(); return Ok(); }`; `[HttpPut("dto/{id}")] PutDto(int id, OrderDto dto) { ... return Ok(); }`; `[HttpGet("users")] Users() => Ok(db.Users.ToList())`; `[HttpGet("orders")] All() => Ok(db.Orders.ToList())`; `Controllers/FormsController.cs` (`FormsController : Controller`): `[HttpPost] async Task<IActionResult> Edit(int id) { var o = db.Orders.Find(id); await TryUpdateModelAsync(o); db.SaveChanges(); return View(); }`, `[HttpPost] async Task<IActionResult> EditSafe(int id) { var o = db.Orders.Find(id); await TryUpdateModelAsync(o, "", x => x.Total); db.SaveChanges(); return View(); }`, `[HttpPost] Bound([Bind("Total")] Order o) { db.Update(o); return View(); }`; `Pages/EditOrder.cshtml` + `.cs` (`[BindProperty] public Order Item { get; set; } = new();`, `OnPost() { db.Update(Item); db.SaveChanges(); return Page(); }`); in `Program.cs`: `app.MapPost("/m/orders", (Order o, AppDb db) => { db.Orders.Add(o); db.SaveChanges(); return Results.Ok(); });`, `app.MapGet("/m/users/{id}", (int id, AppDb db) => db.Users.Find(id));`.

- [ ] **Step 2: Write the failing tests** in `tests/test_dnl_core_object.py` (helper `on(findings, rule)` -> set of handler names or paths):
  - `test_entity_types`: `rules_object.entity_types(model) == {"Order", "User"}` for the dotnet view.
  - `test_idor`: `DNL-AUTHZ-005` on `OrdersController.Get` and `/m/users/{id}`; not on `OrdersController.Mine`, `OrdersController.Authz`.
  - `test_overposting`: `DNL-AUTHZ-006` on `OrdersController.Put`, `FormsController.Edit`, `EditOrderModel.OnPost`, `/m/orders`; not on `OrdersController.PutDto`, `FormsController.EditSafe`, `FormsController.Bound`.
  - `test_exposure`: `DNL-AUTHZ-007` on `OrdersController.Users` and `/m/users/{id}` (User has `PasswordHash`, `IsAdmin`); not on `OrdersController.All` (Order has no sensitive member).
  - `test_owasp_tags`: AUTHZ-005 on a minimal-API route carries `API1:2023`; AUTHZ-006/007 carry `API3:2023`.
  - `test_dotnet_analyzer_reports_object_rules`: present in `enumerate_target(taint_app)` dotnet results.
  - `test_degraded_object_rules`: same sets without the helper.
  - Legacy: `tests/test_dnl_rules_object.py` unchanged and passing.
- [ ] **Step 3: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 4: Implement**.
- [ ] **Step 5: Run to verify they pass**, then the full suite. Expected: PASS.
- [ ] **Step 6: Commit** `feat(dnl): IDOR, over-posting and excessive exposure on ASP.NET Core routes`

---

### Task 6: Degraded parity per style, inventory, README, Linux run

**Files:**
- Modify: `tests/test_dnl_core_taint.py` (or create `tests/test_dnl_core_degraded.py`), `README.md` (coverage table regenerated from `tests/owasp_inventory.coverage_rows`; dotnet prose), `languages/dotnet/README.md` (what Plan 2 adds: sources, binding rules, sinks, templates, object rules; Known limits additions), `tests/test_owasp_inventory_dnl.py` (expected reachable ids)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing tests**:
  - `test_degraded_one_taint_finding_per_style` (spec Decision 8): without the helper, `taint_app` yields at least one proven taint finding on a `controller` route, a `razorpage` route and a `minimalapi` route, and the full proven set equals the helper run's proven set for the fixture minus an explicit, commented exclusion list (each exclusion names why degraded mode cannot see it).
  - `test_inventory_counts_plan2_ids`: `dnl_ids_for_dotnet()` now includes `DNL-INJ-001`, `DNL-XSS-003`, `DNL-AUTHZ-005`, `DNL-AUTHZ-006`, `DNL-AUTHZ-007` and still excludes `DNL-WCF-001`, `DNL-CFG-001`.
  - `test_readme_coverage_table_matches_rules` (existing) fails until the README table is regenerated.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL (inventory/README).
- [ ] **Step 3: Implement**: regenerate the README coverage table rows from `coverage_rows`; update both READMEs; adjust the inventory test.
- [ ] **Step 4: Run the full suite.** Expected: PASS.
- [ ] **Step 5: Linux run** (only if Docker Desktop's daemon is running; check `docker info` first and report its state either way, never start Docker Desktop yourself): `docker run --rm -v "<repo>":/src:ro mcr.microsoft.com/dotnet/sdk:8.0 bash -c "cp -r /src /work && cd /work && rm -rf tools/roslyn-ir/bin tools/roslyn-ir/src/bin tools/roslyn-ir/src/obj && apt-get update -qq && apt-get install -y -qq python3-venv >/dev/null && python3 -m venv /tmp/v && /tmp/v/bin/pip install -q -r requirements.txt pytest && /tmp/v/bin/python -m pytest -q"`. Expected: same pass count as Windows.
- [ ] **Step 6: Scrub and commit.** Grep `git diff main` and `git log main..HEAD` for client/target names, local user paths and person names. Commit `docs(dotnet): ASP.NET Core taint, XSS and object rules in coverage and READMEs`.
