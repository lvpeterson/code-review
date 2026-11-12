# dotnet_legacy: .NET Framework (MVC 5, Web API 2, WebForms, web.config)

Appsec review for classic ASP.NET on the .NET Framework, C# and VB alike.
ASP.NET Core (SDK-style projects) stays with `languages/dotnet`.

Frameworks reported as separate results:

- **mvc** -- controllers deriving (transitively) from `Controller` /
  `AsyncController`.
- **webapi** -- controllers deriving from `ApiController`.
- **webforms** -- one route per `.aspx` / `.asmx` (`.ascx` user controls are
  not routable). Pages under no `.csproj` / `.vbproj` (a WebForms Web Site)
  are routed too, relative to the nearest dir holding a `web.config` (else the
  scan root); the code-behind is resolved through `Inherits` / `Class` /
  `CodeFile` / `CodeBehind` when it can be, else the route has no type.
- **config** -- `Web.config` rules, transform aware (`Web.Release.config`
  etc. via XDT).

Every finding carries OWASP Web Top 10 2025 and 2021 tags, plus an API
Security Top 10 2023 tag when it applies (see the table). They show in the
HTML report's OWASP tab, the JSON `owasp` field and SARIF rule tags.

## How it works

C# and VB are parsed by a small .NET 8 console tool, `tools/roslyn-ir`
(Roslyn), which lowers both languages into one JSON IR. Python
(`checks/dnl/`) loads that into a cached `ProjectModel`: projects from every
legacy `.csproj` / `.vbproj` (references, `Compile` / `Content` items,
`RootNamespace`), source files nobody claims as a `(loose)` project, and
cross-file / cross-project type lookup by simple name. The helper runs
**once per scan**: the enumerator prepares the model before the four
analyzers run, and they share it (routes and auth are computed once and
cached on `model.cache`). Model notes (unparsable project files, missing
includes) appear once, on the first result that reports. A route-less
DNL-AUTHZ-003 goes to the analyzer that owns the filter's project when it is
enumerated, else to the first code analyzer that runs, else to config.

- `routes.py` -- MVC / Web API routes from attribute routing
  (`[RoutePrefix]` / `[Route]`, stacked routes, `~/` overrides) or the
  conventional templates in `RouteConfig` / `WebApiConfig` / area
  registrations; verbs from `[HttpX]` / `[AcceptVerbs]` or Web API name
  prefixes. Public actions inherited from a project base controller (abstract
  or generic included) are routed under each concrete controller, with the
  file / line of the declaring method. WebForms pages link to their code-behind via `Inherits` /
  `Class` (with the VB `RootNamespace` prefix stripped when needed), then
  `CodeBehind` / `CodeFile`.
- `auth.py` -- effective auth per route, most specific first:
  `[AllowAnonymous]` (action, controller, base controllers), an auth
  attribute on the action / controller / base controllers, a global filter
  registered in the same project, `web.config` `<authorization>` /
  `<location>` rules, then a hand-rolled `OnAuthorization` override (or, for
  WebForms, a `Page_Load`-style lifecycle check, including a branch that
  redirects to a login page). Inferred checks are reported for review.
  A hand-rolled check only counts when its `if` condition is about the
  caller: a login redirect needs `Session` / `User` / `Identity` /
  `IsAuthenticated` / `Principal` in the condition, `IsInRole` needs a
  rejecting branch, and `RedirectToLoginPage` must sit inside such an `if`
  (a redirect to `LoginHelp.aspx` on an unrelated condition, or an `IsInRole`
  that only toggles a button, protects nothing).
  Custom auth attributes are only trusted when their own code can deny a
  request; an override that calls `base.OnAuthorization` / `AuthorizeCore`
  takes the verdict of its project base type (a derived filter over an
  always-allow base is still DNL-AUTHZ-003).
- `webconfig.py` / `rules_config.py` -- line-tracked `Web.config` parsing,
  XDT transforms, and the config rules below. A risky setting that every
  non-Debug transform removes drops to `info` ("Removed by ..."); a setting
  a transform introduces says so. Committed secrets (DNL-SEC-001 / SEC-002)
  are exempt: they keep their severity and say the transform overrides the
  value while the base Web.config still holds it.

## Taint analysis

`checks/dnl/taint.py` (per-method flow), `taint_solver.py` (cross-method
summaries) and `taint_tables.py` (data tables: adding a source, sink or
sanitizer is a one-line change there) follow untrusted data through the code.

- **Sources** -- action parameters other than plain numbers, bools, chars, enums, dates /
  `DateTimeOffset` / `TimeSpan`, GUIDs and `CancellationToken`, `Request.QueryString` / `Form` / `Params` / `Cookies` / `Headers` and
  similar request collections, `Request.Path` / `PathInfo` / `UserAgent` /
  `ContentType` / `FilePath` (not `HttpMethod`), `RouteData.Values`, and WebForms control
  values (`TextBox.Text`, `HiddenField.Value`, list selections, ...). Values
  put into `ViewBag` / `ViewData` from these carry their taint into the view:
  `ViewBag` per key, `ViewData` per dictionary (any tainted `ViewData` write
  taints every `ViewData` read).
- **Sinks** -- ADO.NET command text and adapters, EF `SqlQuery` /
  `ExecuteSqlCommand` (sql); Dynamic LINQ expressions (linq); process start
  (cmd); LDAP filters and paths (ldap); XPath queries (xpath); response
  headers and cookie values (header); HTML output from code (xss); file paths (path); redirect
  targets (redirect); outbound request URLs (ssrf); log messages (log).
- **Sanitizers** cleanse only the sink kinds they are valid for: numeric
  `Parse` / `Convert.ToX` / `Val` and safe-type casts (every kind),
  `HtmlEncode` / `JavaScriptEncode` (xss), `Path.GetFileName` (path), LDAP
  escape helpers (ldap; a project method merely named like one must contain a
  `Replace` call to count). CR/LF removal cleanses header and log only once
  both CR and LF have been removed by constant `Replace` calls (a constant
  replacement without CR/LF); removing just one, or the CRLF pair, does nothing. `UrlEncode` does not
  stop an off-site redirect and is deliberately not a sanitizer.
  Parameterized queries (constant `CommandText` + `Parameters.Add*`) never
  fire, and a constant-only value never produces a finding.
- **Guards** -- an `if` that proves a value safe inside its branch (or after
  an early return on the negated test): `Url.IsLocalUrl` (redirect),
  whitelist `Contains` (only on a non-string, untainted collection
  receiver; `text.Contains(x)` searches inside text and whitelists nothing) /
  `Array.IndexOf` (all kinds), and `Path.GetFullPath` + `StartsWith`
  (path). `Regex.IsMatch` is deliberately not a guard: wildcard-equivalent patterns and `$` / `\Z` (which admit a trailing newline) make a regex check unreliable.

Each project method gets a summary of which sinks its parameters reach, what
flows to its return value and which fields it stores. Summaries are
recomputed until nothing changes, so a value passed controller -> service ->
repository is followed across files, through interface / abstract dispatch
(interface -> implementations) and through recursion.

- **Proven** finding: a request source reaches the sink. It takes the rule's
  severity, names the source and the call path, and carries the route of the
  entry point when one reaches it.
- **REVIEW** finding: the sink is fed only by its own method's parameters and
  no caller passing untrusted data was found (dead code, reflection, a caller
  outside the solution). It is one severity level lower, marked
  `confidence: REVIEW`, has no route and asks you to verify how it is called.
- Findings are deduplicated per rule, sink file and line.
- When several routes reach the same sink, the finding names the route that is
  the minimum of (handler name, path, file, line) and its description ends
  with "; also reached from N more route(s)".
- **Depth cap**: the solver stops after 24 rounds. Whether it converged and
  how many rounds it took are recorded on the model; when it did not
  converge, the scan carries a note saying some deep flows may be missing.
  Methods whose expressions nest too deeply to evaluate fully, and methods
  whose analysis raised an internal error, are counted in scan notes too
  (the scan continues without them).
- **IDOR gating** (DNL-AUTHZ-005): fires only when an id-like action
  parameter selects a record (EF `Find` / `FirstOrDefault` / `Where` on a
  `DbSet`, a sql sink, or a project method that does either) and nothing ties
  the access to the signed-in user. It is independent of `[Authorize]` and
  always REVIEW. A user reference suppresses it only inside the data-access
  call itself (an argument, a lambda, an earlier `Where` in the chain), or in
  an `if` / ternary that compares the user with the accessed record (the
  fetched entity, its members, or the id) and rejects the request or holds
  the access. An unrelated reference does not suppress: a log line that
  mentions the user, a null / sign-in check, or a comparison against a
  different record.
- **Over-posting** (DNL-AUTHZ-006): an entity bound with no `[Bind]`. An
  Exclude-only `[Bind(Exclude=...)]` leaves every other field bindable, so
  that case is marked REVIEW.

Known limits, not modelled:

- Reflection and `dynamic` calls are not followed.
- DI container wiring beyond interface -> implementations (named
  registrations, factories, decorators) is not resolved.
- Stored-then-read data (a value written to a database or file in one request
  and used in another) is not tracked.
- Calls across solutions (an assembly referenced only as a binary) are not
  followed.
- Lambda bodies are evaluated on a copy of the environment: sinks inside are
  reported, assignments inside are discarded, and the first parameter takes
  the receiver's taint only for LINQ-style calls (`Select`, `Where`,
  `ForEach`, `Any`, `First*`, ...). A delegate stored and invoked later is
  not followed.
- Syntax the IR could not lower (`unknown` / `other` nodes, e.g. a switch
  expression or VB `Request.QueryString!q`) is scanned conservatively: a
  request access in its text is a source, otherwise it carries the taint of
  the variables it mentions. It is never a sink.
- An external call that no helper table covers propagates only the
  receiver's taint, not its arguments.
- Fluent receivers (`GetSvc().Find(x)`) are not resolved to a project
  method.
- `ViewData` / `ViewBag` taint is tracked per dictionary, not per key.
- The AUTHZ-005/006/007 heuristics work from names written in source:
  AUTHZ-005 is always REVIEW (and `low`, since a name heuristic is weak evidence), AUTHZ-006 is REVIEW only when the `[Bind]` is
  Exclude-only, and AUTHZ-007 is a plain `low` finding with no REVIEW mark.

## Detection

`detector.py` walks the target once (skipping `bin`, `obj`, `packages`,
`.git` / `.hg` / `.svn`, `.vs`, `node_modules`, `__pycache__`, `venv` /
`.venv` and any `Precompiled*` dir; `Vendor`, `Build`, `Dist` and `Target`
are ordinary .NET folder names and are scanned):

- legacy project referencing `System.Web.Mvc` (or `packages.config` with
  `Microsoft.AspNet.Mvc`) -> mvc
- legacy project referencing `System.Web.Http` (or
  `Microsoft.AspNet.WebApi`) -> webapi
- any `.aspx` -> webforms
- a non-Views `Web.config` with `<system.web>` / `<system.webServer>` -> config

SDK-style projects are claimed whole (every source under their dir, even
when they list some `Compile` items, so nothing is "loose") but never parsed
here.

## Rules

Severity shows every value a rule can emit; config rules also drop to `info`
when all release transforms remove the setting. The API 2023 tag is emitted
only for findings on an API surface (a Web API project, an `.asmx`), except
DNL-INV-001, which always carries it.

| Rule | Severity | What | OWASP 2025 | OWASP 2021 | API 2023 |
|---|---|---|---|---|---|
| DNL-AUTHZ-001 | info/low/medium/high | Route with no effective auth (high when mutating); low + REVIEW when only an inferred hand-rolled check protects it; info when explicitly `[AllowAnonymous]` | A01:2025 | A01:2021 | API5:2023 |
| DNL-AUTHZ-002 | medium | `[AllowAnonymous]` action with an explicit mutating verb (REVIEW) | A01:2025 | A01:2021 | API5:2023 |
| DNL-AUTHZ-003 | high | Custom auth filter whose override never denies a request | A01:2025 | A01:2021 | API5:2023 |
| DNL-AUTHZ-004 | low | Admin-looking controller / action gated by `[Authorize]` with no Roles / Users (REVIEW) | A01:2025 | A01:2021 | API5:2023 |
| DNL-CSRF-001 | medium | Mutating MVC action without `[ValidateAntiForgeryToken]` (action, controller, bases, global filters) | A01:2025 | A01:2021 | -- |
| DNL-CFG-001 | medium | `compilation debug="true"` | A02:2025 | A05:2021 | API8:2023 |
| DNL-CFG-002 | medium | `customErrors mode="Off"` or `httpErrors errorMode="Detailed"` | A02:2025 | A05:2021 | API8:2023 |
| DNL-CFG-003 | medium/high | `trace enabled="true"` (high with `localOnly="false"`) | A02:2025 | A05:2021 | API8:2023 |
| DNL-CFG-004 | high | ELMAH `allowRemoteAccess` | A02:2025 | A05:2021 | API8:2023 |
| DNL-CFG-005 | low | `enableVersionHeader` not disabled (app-root configs only) | A02:2025 | A05:2021 | API8:2023 |
| DNL-CFG-006 | low | Security response headers missing (app-root configs only) | A02:2025 | A05:2021 | API8:2023 |
| DNL-CFG-007 | medium | `Access-Control-Allow-Origin: *` | A02:2025 | A05:2021 | API8:2023 |
| DNL-XSS-002 | medium | `validateRequest="false"` (in a WebForms project dir) or `requestValidationMode="2.x"` | A05:2025 | A03:2021 | -- |
| DNL-SESS-001 | medium | Forms auth cookie without `requireSSL="true"` | A07:2025 | A07:2021 | API2:2023 |
| DNL-SESS-002 | low | `httpOnlyCookies` not enforced (app-root configs only) | A07:2025 | A07:2021 | API2:2023 |
| DNL-SESS-003 | low | Forms timeout over 60 minutes | A07:2025 | A07:2021 | API2:2023 |
| DNL-SESS-004 | medium | Cookieless forms auth or session state | A07:2025 | A07:2021 | API2:2023 |
| DNL-SESS-005 | medium/high | Membership `passwordFormat` Encrypted (medium) / Clear (high) | A04:2025 | A02:2021 | API2:2023 |
| DNL-INT-001 | high | `enableViewStateMac="false"` | A08:2025 | A08:2021 | -- |
| DNL-INT-002 | medium | Hard-coded `machineKey` | A08:2025 | A08:2021 | -- |
| DNL-SEC-001 | high | Password in a connection string (a whole-value placeholder such as `$(Pw)`, `{DbPassword}` or `#{Pw}` is ignored; braced ADO.NET values like `{a;b}` are real) | A07:2025 | A07:2021 | API2:2023 |
| DNL-SEC-002 | medium | Secret-named `appSettings` key with a literal value (keys with a word naming a setting, such as `PasswordResetUrl`, `Password_Format`, `PasswordRegex`, `TokenExpiration`, are skipped; matched on camelCase / `_` words, so `InformationApiKey` still fires) | A07:2025 | A07:2021 | API2:2023 |
| DNL-INV-001 | low/medium | `elmah.axd` / `trace.axd` handler registered (low when anonymous access is denied) | A02:2025 | A05:2021 | API9:2023 |
| DNL-RES-001 | low | `maxRequestLength` / `maxAllowedContentLength` over 100 MB | A06:2025 | A04:2021 | API4:2023 |
| DNL-INJ-001 | high | SQL injection (tainted input reaches a query sink) | A05:2025 | A03:2021 | API8:2023 |
| DNL-INJ-002 | high | Command injection | A05:2025 | A03:2021 | API8:2023 |
| DNL-INJ-003 | high | LDAP injection | A05:2025 | A03:2021 | API8:2023 |
| DNL-INJ-004 | medium | XPath injection | A05:2025 | A03:2021 | API8:2023 |
| DNL-INJ-005 | medium | HTTP header injection | A05:2025 | A03:2021 | API8:2023 |
| DNL-INJ-006 | high | Dynamic LINQ injection | A05:2025 | A03:2021 | API8:2023 |
| DNL-XSS-001 | high | XSS via a code sink | A05:2025 | A03:2021 | -- |
| DNL-XSS-003 | high/low | XSS via Razor/ASPX output: raw `Html.Raw` / `<%= %>` / `<%# %>` fed by the request, ViewBag or view model (high); other non-literal raw output for review (low); a single `Url.Content` / `Html.Partial` / `Scripts.Render`-style helper call with constant arguments is ignored | A05:2025 | A03:2021 | -- |
| DNL-XSS-004 | medium | Request validation bypassed in code: `[AllowHtml]` on a bound model property, `[ValidateInput(false)]`, `Request.Unvalidated` | A05:2025 | A03:2021 | -- |
| DNL-PATH-001 | high | Path traversal | A01:2025 | A01:2021 | -- |
| DNL-REDIR-001 | medium | Open redirect | A01:2025 | A01:2021 | -- |
| DNL-SSRF-001 | high | Server-side request forgery | A01:2025 | A10:2021 | API7:2023 |
| DNL-LOG-001 | low | Log injection | A09:2025 | A09:2021 | -- |
| DNL-AUTHZ-005 | low | Object-level authorization gap (IDOR), always REVIEW | A01:2025 | A01:2021 | API1:2023 |
| DNL-AUTHZ-006 | medium | Over-posting (entity bound from request); REVIEW when only an Exclude-only `[Bind]` is present | A06:2025 | A04:2021 | API3:2023 |
| DNL-AUTHZ-007 | low | Entity returned from an API (over-exposure) | A06:2025 | A04:2021 | API3:2023 |

`tests/test_dnl_end_to_end.py` fails if a rule in `core/owasp_web.RULES` is
missing here or its tags drift.

## Preflight and `--allow-degraded`

When .NET Framework code is detected, the scan needs the Roslyn helper. It
is found via `CODE_REVIEW_ROSLYN_IR`, else `tools/roslyn-ir/bin/` (rebuilt
when older than its sources), else `roslyn-ir` on PATH (a hit inside the current directory is ignored, as
is a `dotnet` found there: Windows searches the cwd first and a scanned repo
could plant one), and is built
automatically (`dotnet publish`) when the .NET 8 SDK is on PATH. If no
helper can be found, built or probed, the CLI prints install steps and
**exits 2**.

`--allow-degraded` continues without it: mvc / webapi / webforms report no
routes or findings, config still runs, and every result carries a degraded
banner in the HTML report (and `degraded` in JSON / SARIF). A degraded run
cannot pass for a clean one on the console either: preflight prints
`DEGRADED: <reason>` to stderr, the console report prints the same line under
each affected result header, and `main` repeats it on stderr at the very end.

## Linux install

Everything is cross-platform (paths resolve case-insensitively and accept
`\` or `/`, as Windows-authored project files expect).

```
sudo apt install dotnet-sdk-8.0        # Debian/Ubuntu; Fedora/RHEL: sudo dnf install dotnet-sdk-8.0
# or: ./dotnet-install.sh --channel 8.0  (https://dot.net/v1/dotnet-install.sh)
python3 -m venv ~/.venvs/cr && ~/.venvs/cr/bin/pip install -r requirements.txt pytest
~/.venvs/cr/bin/python main.py /path/to/app --html report.html
```

Without an SDK on the scan machine, publish a self-contained helper
elsewhere (`dotnet publish tools/roslyn-ir/src/RoslynIr.csproj -c Release
-r linux-x64 --self-contained -p:PublishSingleFile=true`) and copy it (with
its `refs/` folder) to `tools/roslyn-ir/bin/`, or point
`CODE_REVIEW_ROSLYN_IR` at it.

## What still needs a human

- `REVIEW` findings: hand-rolled auth checks (inferred from code),
  anonymous mutating actions, admin-looking actions without roles.
- `info` AUTHZ-001 on `[AllowAnonymous]` routes: confirm each is meant to be
  public.
- Auth decided outside what is modelled: OWIN middleware, `Global.asax`
  `Application_AuthenticateRequest`, IIS / reverse-proxy rules, custom
  `HttpModule`s, `RouteTable` constraints.
- Conventional routes are the first matching template; custom route
  handlers and `MapPageRoute` URLs for WebForms are not expanded.
- XDT verbs other than `Replace` / `Insert` / `InsertIfMissing` / `Remove`
  / `RemoveAll` / `SetAttributes` / `RemoveAttributes` (e.g. `InsertBefore`,
  `Merge`) are not applied; the scan notes each one.
- Whether a flagged secret is real and still valid.
- `--allow-path` globs match DNL routes case-insensitively (ASP.NET URLs
  are); other analyzers keep the platform's `fnmatch` behavior.
- Known limits, not modelled: MVC auth only considers the app-root
  `web.config` (a physical `Admin/Web.config` deny is ignored, which yields
  noise, never a false "protected"); authorization comes from the base
  config, not the Release transforms.

## Coverage gaps (later plans)

This is plan 1 of 4. Not covered yet:

- Plan 2: taint engine, Razor / ASPX template tokenizer, injection / XSS /
  path / redirect / SSRF / LDAP / log-injection rules, object-level authz
  (API1) and over-posting (API3).
- Plan 3: WCF (routes, bindings, behaviors), crypto, secrets in code,
  deserialization, XXE, integrity (SRI), session / auth code rules.
- Plan 4: NuGet and bundled-JS SCA, ERR / LOG / DES / RES / INV / CONSUME
  code rules, a tree-sitter C# + regex VB degraded mode, and the "every
  OWASP category has a rule" coverage test.
