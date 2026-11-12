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
