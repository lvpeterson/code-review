# ASP.NET Core Configuration Rules Implementation Plan (Plan 3 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Report insecure ASP.NET Core configuration -- error handling, transport, CORS, cookies, antiforgery, JWT/OIDC, Identity, secrets, resource limits, inventory, data protection -- from the `Program.cs` / `Startup` pipeline facts and from `appsettings*.json`, with every finding tagged for OWASP Web 2025, Web 2021 and API 2023.

**Architecture:** An option reader (`options.py`) turns option lambdas and object initializers inside `PipeCall.node` into `(path, value, line)` assignments; an `appsettings.py` reader gives merged, line-numbered settings per environment. Rule modules read `pipeline_for(...)` facts (`PipeCall.runs_in("Production")`, `Pipeline.named()`, `Pipeline.uncertain()`) plus the route refs from `routes_core.discover_all`, and one aggregator, `rules_pipeline.check(model, refs)`, is wired into the `dotnet` analyzers with a single `guarded(...)` line. Route-less findings land in the `config` analyzer through the existing owner logic; route-bound ones carry their `Route`.

**Tech Stack:** Python 3.10+, pytest, the existing Roslyn-helper IR (degraded tree-sitter IR as fallback).

**Spec:** `docs/superpowers/specs/2026-11-14-aspnetcore-design.md` (section "Configuration (`rules_pipeline.py`, `appsettings.py`)", Decisions 2-3, "Testing"). Plan 1 (`docs/superpowers/plans/2026-11-15-aspnetcore-foundation.md`) built the pipeline, routes and auth; Plan 2 (taint, XSS, object rules) and Plan 4 (SCA, coverage, acceptance) are separate.

## Global Constraints

- Public repo: nothing committed (code, fixtures, tests, README, docs, commit messages) may name a client, engagement, target app, local path or person. All fixtures are synthetic with generic names. Grep the diff and commit messages before every commit.
- Prose and comments use `--`, never em-dashes; comment density like the existing `checks/dnl/*.py`.
- Tests: `.venv\Scripts\python -m pytest -q` from the repo root (create the venv with `python -m venv .venv` and `pip install -r requirements.txt pytest` if absent). Every existing test stays green. Must also pass on Linux.
- Helper-dependent tests use the `roslyn_helper` fixture; degraded tests monkeypatch `helper.find_helper` and `helper.sdk_available` (setting `CODE_REVIEW_ROSLYN_IR` to a missing file is not enough).
- A false "safe" is the worst outcome. Unknown is REVIEW, never clean: a value that is not a literal, a condition that cannot be parsed, or a call the engine cannot resolve downgrades a finding to `confidence="REVIEW"` (or adds one); it never silences it.
- Environment rule (spec Decision 3): assume Production. Code under an `IsDevelopment()` guard is not flagged (`PipeCall.runs_in("Production") is False`); an unparseable guard (`runs_in(...) is None`, listed by `Pipeline.uncertain()`) is flagged as REVIEW with a note.
- No regression for dotnet_legacy: its tests pass unchanged; this plan touches only `languages/dotnet/analyzers.py` (one wiring line), new `checks/dnl/` modules, and shared tables (`core/owasp_web.py`, `languages/dotnet_legacy/README.md`).
- Rule ids are quoted literals. Every new id gets a `core/owasp_web.RULES` entry and a row in the DNL rule table of `languages/dotnet_legacy/README.md` (enforced by `test_readme_lists_every_rule_with_tags`) in the task that adds it. Ids already used by a legacy check keep it when the check is the same.
- Do not edit the README OWASP coverage table, `languages/dotnet/README.md`, or `tests/test_owasp_inventory_dnl.py` (Plan 2 edits them too; the combining step merges them). Task 13 leaves a hand-over note instead.
- Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Work stays on the current branch. No push, no merge.

## Rule ids

New ids (all `dotnet`-only, route-less unless marked). OWASP columns follow the `_add` rows in `core/owasp_web.py`; the API column applies on an API surface unless "always".

| id | sev | 2025 | 2021 | API | what |
|---|---|---|---|---|---|
| DNL-CFG-008 | medium | A02 | A05 | API8 | developer exception page or `DetailedErrors` reachable in Production |
| DNL-CFG-009 | low REVIEW | A02 | A05 | API8 | no exception-handler middleware in the Production pipeline |
| DNL-CFG-010 | low | A02 | A05 | API8 | no `UseHttpsRedirection` |
| DNL-CFG-011 | low | A02 | A05 | API8 | no `UseHsts` |
| DNL-CFG-012 | medium | A02 | A05 | API8 | `RequireHttpsMetadata = false` |
| DNL-CFG-013 | low | A02 | A05 | API8 | Kestrel / URL configuration listens on HTTP only |
| DNL-CFG-014 | low | A02 | A05 | API8 | `AllowedHosts: "*"` |
| DNL-CFG-015 | low REVIEW | A02 | A05 | API8 | `[EnableCors]` on a sensitive route (route-bound) |
| DNL-SESS-009 | low | A07 | A07 | API2 | cookie `SameSite = None` |
| DNL-SESS-010 | medium/high | A07 | A07 | API2 | token validation switched off (high when signature related) |
| DNL-SESS-011 | low | A07 | A07 | API2 | `ClockSkew` over 10 minutes |
| DNL-SEC-004 | high | A07 | A07 | API2 | literal symmetric signing key in code |
| DNL-SEC-005 | medium/low | A07 | A07 | API2 | weak Identity `PasswordOptions` |
| DNL-SEC-006 | medium | A07 | A07 | API2 | lockout disabled |
| DNL-SEC-007 | low | A07 | A07 | API2 | `RequireConfirmedAccount/Email = false` |
| DNL-CSRF-002 | medium | A01 | A01 | -- | antiforgery explicitly disabled (route-bound) |
| DNL-RES-004 | low | A06 | A04 | API4 | login / token / reset endpoints with no rate limiting |
| DNL-RES-005 | low | A06 | A04 | API4 | paging size parameter reaches `Take` with no upper bound (route-bound) |
| DNL-INV-003 | low | A02 | A05 | API9 always | Swagger / OpenAPI UI or document served in Production |
| DNL-INV-004 | low REVIEW | A02 | A05 | API9 always | older API version still mapped (route-bound) |
| DNL-CRY-009 | low | A04 | A02 | -- | data-protection keys persisted to the file system with no `ProtectKeysWith*` |

Reused ids (same check as legacy, `dotnet` flavour): `DNL-CFG-007` (CORS wildcard origin), `DNL-SESS-001` (cookie without Secure), `DNL-SESS-002` (HttpOnly off), `DNL-SESS-003` (long cookie expiry), `DNL-CSRF-001` (mutating MVC action with no antiforgery validation), `DNL-SEC-001` / `DNL-SEC-002` (secrets in `appsettings*.json`), `DNL-RES-001` (very large request limit), `DNL-ERR-002` (exception detail written by a production exception handler). Task 13 adds one README note per reused id saying it also fires for ASP.NET Core.

## Builder notes vs the spec (decided here)

1. **Module split.** `options.py` and `cfgctx.py` (shared), `appsettings.py`, then `rules_pipeline.py` (aggregator plus errors, transport, CORS, inventory, data protection), `rules_pipeline_auth.py` (cookies, antiforgery, JWT/OIDC, Identity), `rules_secrets_core.py`, `rules_limits_core.py`. `rules_pipeline.check` calls the other three; the analyzers wire only `rules_pipeline`.
2. **Absence findings** (no HSTS, no HTTPS redirection, no exception handler, no rate limiter, no global antiforgery) are firm only when the pipeline is fully read. When `pipe.uncertain()` is non-empty, or an unresolved `services`/`app` call that is not in `auth_core._NON_AUTHZ_EXTENSIONS` exists (it could register the missing piece), the finding is `confidence="REVIEW"` and the description names the call. A pipeline with `style == "none"` (a library project) gets no absence findings.
3. **`launchSettings.json`** never changes the environment assumption (it only applies to `dotnet run`); its `environmentVariables` values are read as a Development-level secret source (Task 10).
4. **Code secrets.** `DNL-SEC-003` (hard-coded credential in code) lives in `rules_crypto`, whose wiring for `dotnet` belongs to Plans 2 and 4; this plan adds `DNL-SEC-004` (literal signing key) and the `appsettings` secrets only. Task 13 records the dependency.

## Review Focus

1. A setting that is bad only inside an `IsDevelopment()` branch (developer exception page, `AllowAnyOrigin`, weak password options, `DisableAntiforgery()`, Swagger) is not flagged; the same under an unparseable guard is REVIEW (tests in Tasks 3, 5, 12).
2. An absence check (HSTS, HTTPS redirection, exception handler, rate limiter, antiforgery) with an unresolved company-specific extension in the pipeline is REVIEW, never a firm "missing", and a library project with no pipeline reports nothing (tests in Tasks 1 and 4).
3. An option whose value is not a literal (`ValidateIssuer = cfg.GetValue<bool>("V")`, `RequireHttpsMetadata = !isDev`) is REVIEW, not silently clean (test in Task 8).
4. `appsettings.json` with comments and trailing commas parses; malformed JSON is a note, never a crash; a bad base value overridden to a good one in `appsettings.Production.json` is not reported, and an `appsettings.Development.json` placeholder secret is ignored (tests in Tasks 2 and 10).
5. A solution with two web projects reports each project's pipeline separately (file and line point at the right project), and a Startup-style `Configure` split across helper methods still yields its middleware (test in Task 1).

---

### Task 1: Option reader, shared context, aggregator skeleton, analyzer wiring

**Files:**
- Create: `checks/dnl/options.py`, `checks/dnl/cfgctx.py`, `checks/dnl/rules_pipeline.py`, `tests/cfgutil.py`, `tests/test_dnl_options.py`, `tests/test_dnl_rules_pipeline.py`
- Modify: `languages/dotnet/analyzers.py` (one `guarded("rules_pipeline", ...)` line after `rules_auth_core`)

**Interfaces:**
- Produces in `checks/dnl/options.py`:
  ```python
  @dataclass
  class Opt:
      path: str        # dotted, relative to the lambda parameter or initializer root: "Password.RequiredLength"
      value: dict      # the assigned Expr
      line: int
  def lambda_args(call: dict) -> list[dict]             # lambda Exprs among call args (positional and named)
  def assignments(node: dict) -> list[Opt]              # all `p.A.B = v` in a lambda body (any depth, incl. nested lambdas
                                                        # and if/else), plus `new T { A = v, B = { C = v } }` initializers
                                                        # (path prefixed by the member they sit under)
  def options_of(call: dict) -> list[Opt]               # assignments over every lambda argument and `new` argument of a call
  def const(expr: dict | None) -> object                # bool | int | float | str | None (literal null) | UNKNOWN; enum members
                                                        # give "Type.Member" text ("CookieSecurePolicy.None"); `-1`, `true`, `"x"`, `null`
  UNKNOWN: object                                       # sentinel: not a compile-time value
  def always_true(expr: dict | None) -> bool            # `_ => true`, `(a,b) => true`, `x => { return true; }`
  def timespan_minutes(expr: dict | None) -> float | None   # TimeSpan.FromMinutes/Hours/Days/Seconds(literal), new TimeSpan(h,m,s), else None
  def opt(opts: list[Opt], path: str) -> Opt | None     # last assignment whose path equals `path` case-insensitively
  ```
- Produces in `checks/dnl/cfgctx.py`:
  ```python
  @dataclass
  class Ctx:
      model: ProjectModel; refs: list[CoreRouteRef]; pipes: list[Pipeline]      # one per netcore project with style != "none"
      settings: object | None                                                  # appsettings.Settings (Task 2), None until then
      out: list[Finding]
      def add(self, check_id, severity, title, description, file, line, *, route=None, confidence=None, api_surface=False) -> None
      def absent_confidence(self, pipe: Pipeline) -> tuple[str | None, str]    # (None | "REVIEW", note) per builder note 2
      def prod_calls(self, pipe, *names, kinds=()) -> list[PipeCall]           # pipe.named(...) in Production
      def uncertain_calls(self, pipe, *names, kinds=()) -> list[PipeCall]      # pipe.uncertain() filtered by name
  def build_ctx(model, refs) -> Ctx
  ```
  `api_surface` defaults from the route when `route` is given. All findings go through `dnl_finding`.
- Produces in `checks/dnl/rules_pipeline.py`: `def check(model: ProjectModel, refs: list[CoreRouteRef]) -> list[Finding]` calling each rule group in a fixed order inside per-group `try/except` that appends a model note (like `guarded`) -- later tasks add their group by one line.
- Produces in `tests/cfgutil.py`: `make_app(tmp_path, files: dict[str, str], *, sdk="Microsoft.NET.Sdk.Web", tfm="net8.0") -> Path` (writes `App.csproj` with `ImplicitUsings` enabled plus the files); `run_check(root, degraded=False) -> list[Finding]` (prepare the model, `get_model(root, "dotnet")`, `discover_all`, `rules_pipeline.check`); a pytest fixture `mode` parametrized `["helper", "degraded"]` (helper mode requests `roslyn_helper`; degraded monkeypatches `helper.find_helper` and `helper.sdk_available`) and `scan(tmp_path, files, mode)`; `ids(findings) -> set[tuple[str, str, str | None]]` of `(check_id, severity, confidence)`.

- [ ] **Step 1: Write the failing tests.** `tests/test_dnl_options.py` (hand-built IR dicts, no helper): `assignments` of `o => { o.Password.RequiredLength = 4; if (x) { o.Cookie.HttpOnly = false; } }` yields paths `Password.RequiredLength` and `Cookie.HttpOnly`; an initializer `new TokenValidationParameters { ValidateIssuer = false, Nested = { A = 1 } }` yields `ValidateIssuer` and `Nested.A`; `const` of `null`, `true`, `5`, `"x"`, `CookieSecurePolicy.None` (member of a name) gives `None`, `True`, `5`, `"x"`, `"CookieSecurePolicy.None"` and of a call gives `UNKNOWN`; `always_true` is True for `_ => true` and a block lambda returning only `true`, False for `x => x.Ok`; `timespan_minutes` of `TimeSpan.FromHours(2)` is 120 and of `TimeSpan.FromDays(30)` 43200; `opt` is case-insensitive and returns the last match. `tests/test_dnl_rules_pipeline.py` (uses `mode`): `test_library_project_reports_nothing` (a `Microsoft.NET.Sdk` project with a plain class: `run_check` returns `[]`); `test_two_web_projects_reported_separately`: two projects `A/` and `B/` in one root, each `Program.cs` with `app.UseDeveloperExceptionPage();` and no guard (the Task 3 rule is not there yet, so this test is added in Task 3 -- here assert instead that `build_ctx(...).pipes` has two pipelines whose `project` differ); `test_startup_configure_split_across_helpers`: `Startup.Configure` calling `ConfigureSecurity(app)` defined in the same class -> `build_ctx(...).pipes[0].named("UseHsts")` non-empty; `test_absent_confidence`: a pipeline with an unresolved `services.AddCompanyDefaults()` -> `absent_confidence` is `"REVIEW"` with the call name in the note; with `AddDbContext<Db>()` unresolved -> `None`; a guard on an unparseable condition (`if (Flag.Check())`) around `UseHsts()` -> `"REVIEW"`.
- [ ] **Step 2: Run to verify they fail** (`.venv\Scripts\python -m pytest tests/test_dnl_options.py tests/test_dnl_rules_pipeline.py -q`). Expected: FAIL (modules missing).
- [ ] **Step 3: Implement `options.py`, `cfgctx.py`, `rules_pipeline.check`** as specified. `assignments` walks `walk(node)` for `assign` statements with `op == "="` whose target is a member chain rooted at a lambda parameter (or any name for initializers) and for `new` nodes' `init` entries. Wire `findings += guarded("rules_pipeline", lambda: rules_pipeline.check(model, refs))` in `languages/dotnet/analyzers.py` directly after the `rules_auth_core` line.
- [ ] **Step 4: Run to verify they pass**, then `tests/test_dotnet_core_analyzers.py tests/test_dnl_pipeline.py -q` (wiring did not break). Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): option reader, shared config context and rules_pipeline skeleton`

---

### Task 2: `appsettings*.json` reader

**Files:**
- Create: `checks/dnl/appsettings.py`, `tests/test_dnl_appsettings.py`
- Modify: `checks/dnl/cfgctx.py` (`build_ctx` fills `ctx.settings`; one `appsettings` load per model, cached on `model.cache`)

**Interfaces:**
- Produces:
  ```python
  @dataclass
  class Entry:
      key: str        # colon path, original case: "Jwt:Key", "Kestrel:Endpoints:Http:Url", arrays "Hosts:0"
      value: object   # str | int | float | bool | None
      file: str       # repo-relative posix path
      line: int
      env: str | None # None for appsettings.json, else the environment in the file name ("Development")
  @dataclass
  class SettingsFile: path: str; env: str | None; entries: list[Entry]; error: str | None
  @dataclass
  class Settings:
      files: list[SettingsFile]
      def effective(self, env: str) -> dict[str, Entry]     # lower-cased key -> the entry that wins: base file, overridden by appsettings.<env>.json
      def entries(self, env: str | None = None) -> list[Entry]   # raw entries of the files for that env (None = base files)
  def load_settings(model: ProjectModel) -> Settings         # appsettings*.json and Properties/launchSettings.json (profiles' environmentVariables as env "launch") of
                                                            # files the model owns (model.owns), skipping bin/obj/node_modules/wwwroot
  ```
- JSON reader: own tolerant parser (comments `//` and `/* */`, trailing commas, BOM, duplicate keys last-wins) so line numbers are exact; malformed file -> `SettingsFile.error` set and a model note, never an exception. Environment variable style keys in launch profiles (`Jwt__Key`) normalise to `Jwt:Key`.

- [ ] **Step 1: Write the failing tests** (tmp files, no helper): nested object and array flattening with correct lines (`Jwt:Key` on its own line number); comments and trailing commas accepted; BOM accepted; `effective("Production")` takes `appsettings.Production.json` over base while `effective("Development")` reads the Development file; keys case-insensitive in `effective`; malformed file -> `error` mentions the file and `load_settings` still returns the other files; `launchSettings.json` `environmentVariables` `{"Db__Password": "x"}` -> entry key `Db:Password`, env `"launch"`; a file under `bin/` or `wwwroot/` is ignored; a file owned by another model view is skipped.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement `appsettings.py`; hook into `build_ctx`.**
- [ ] **Step 4: Run to verify they pass**, then Task 1's tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): appsettings and launchSettings reader`

---

### Task 3: Errors and exception pages (DNL-CFG-008, CFG-009, ERR-002)

**Files:**
- Modify: `checks/dnl/rules_pipeline.py` (group `_errors`), `core/owasp_web.py` (`_add(["DNL-CFG-008", ..., "DNL-CFG-015"], "A02", "A05", "API8")` for the whole CFG range now), `languages/dotnet_legacy/README.md` (rows CFG-008, CFG-009)
- Test: `tests/test_dnl_rules_pipeline.py`

**Interfaces:** Consumes `Ctx`, `options`, `appsettings`. Produces `rules_pipeline._errors(ctx)`.
- **CFG-008** (medium): a `UseDeveloperExceptionPage` call with `runs_in("Production") is True` (or in a Startup `Configure` with no guard); `DetailedErrors` true in `effective("Production")` (key `DetailedErrors`), or `options.opt(..., "DetailedErrors")` literal true in `AddRazorComponents`/`AddServerSideBlazor`/`AddCircuitOptions`; `AddProblemDetails`/`CustomizeProblemDetails` is covered by the ERR-002 bullet. A `UseDeveloperExceptionPage` under an unparseable guard (`pipe.uncertain()`) -> same id, `confidence="REVIEW"`.
- **CFG-009** (low, REVIEW): the Production pipeline has no `UseExceptionHandler` and no `UseStatusCodePages*`/`UseProblemDetails`-style handler call; `confidence` is always `"REVIEW"` (description: unhandled exceptions give a bare 500, and a reverse proxy or global filter may provide the page). Skipped for `style == "none"`.
- **ERR-002** (medium): inside the lambda of `UseExceptionHandler(app => app.Run(async ctx => ...))`, `UseExceptionHandler(o => o.ExceptionHandler = ...)`, or `AddProblemDetails(o => o.CustomizeProblemDetails = ...)`, a read of `.Error.Message`, `.Error.StackTrace`, `.Error.ToString()`, `.Exception.Message|StackTrace|ToString()` or `IExceptionHandlerFeature` `Error` that reaches a `WriteAsync`, `WriteAsJsonAsync`, `Results.*`, `Extensions[...]`, `Detail =` or `Title =` assignment in that same lambda body (use `walk`; no cross-method flow), only when the call runs in Production. Environment-guarded (`Development`) handlers are not flagged.

- [ ] **Step 1: Write the failing tests** (`mode`): `test_developer_page_unguarded` (`app.UseDeveloperExceptionPage();`) -> `("DNL-CFG-008", "medium", None)`; `test_developer_page_guarded_is_clean` (`if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); } else { app.UseExceptionHandler("/e"); }`) -> no CFG-008, no CFG-009; `test_developer_page_unparseable_guard_is_review` (`if (Flags.Debug()) { app.UseDeveloperExceptionPage(); }`) -> CFG-008 REVIEW; `test_detailed_errors_in_settings` (`appsettings.json` `{"DetailedErrors": true}`) -> CFG-008 at that file and line; `{"DetailedErrors": true}` in base but `appsettings.Production.json` `{"DetailedErrors": false}` -> none; `test_no_exception_handler_is_review` -> `("DNL-CFG-009", "low", "REVIEW")` on a minimal app with `UseRouting` but no handler; `UseExceptionHandler("/e")` present -> none; `test_handler_lambda_leaks_exception` (`app.UseExceptionHandler(a => a.Run(async c => { var f = c.Features.Get<IExceptionHandlerFeature>(); await c.Response.WriteAsync(f.Error.Message); }));`) -> `("DNL-ERR-002", "medium", None)`; the same handler writing a constant string -> none; `test_two_web_projects_reported_separately` (finishes the Task 1 test): both projects report CFG-008 with files under `A/` and `B/`.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement `_errors`; add the OWASP rows and README rows.**
- [ ] **Step 4: Run to verify they pass**, then `tests/test_owasp_web.py tests/test_owasp_readme.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core error-handling configuration rules`

---

### Task 4: Transport (DNL-CFG-010, 011, 013, 014)

**Files:**
- Modify: `checks/dnl/rules_pipeline.py` (group `_transport`), `languages/dotnet_legacy/README.md` (rows CFG-010, 011, 013, 014)
- Test: `tests/test_dnl_rules_pipeline.py`

**Interfaces:** Produces `rules_pipeline._transport(ctx)`. (`RequireHttpsMetadata` is Task 8.)
- **CFG-010** (low): no Production `UseHttpsRedirection`; **CFG-011** (low): no Production `UseHsts` (`AddHsts` alone does not count; `UseHsts`, or a `Strict-Transport-Security` header literal added in the pipeline via `Headers[...]`/`Append`, does). Both use `absent_confidence` (REVIEW per builder note 2) and are skipped for `style == "none"`. Always reported (API-only apps too); the description says a TLS-terminating proxy can satisfy it.
- **CFG-013** (low): Kestrel or URL config that serves HTTP only: `ConfigureKestrel`/`UseKestrel` option lambdas with `ListenAnyIP`/`Listen`/`ListenLocalhost` calls where no `UseHttps` is chained or configured and no HTTPS listener exists in the same lambda; `UseUrls("http://...")` / `builder.WebHost.UseUrls` with only `http://` literals; `effective("Production")` `Urls` or `Kestrel:Endpoints:*:Url` values that are all `http://` (loopback `localhost`/`127.0.0.1`/`[::1]` hosts exempt). Any `https://` listener in the same source clears it.
- **CFG-014** (low): `AllowedHosts` equals `"*"` in `effective("Production")` (also a value containing a `*`-only segment `*;x.com` is reported).

- [ ] **Step 1: Write the failing tests** (`mode`): minimal app with only `UseRouting` -> CFG-010 and CFG-011 both firm (`confidence None`); with `UseHttpsRedirection(); UseHsts();` -> neither; `UseHsts()` inside `if (!app.Environment.IsDevelopment())` -> counts as present (Production); `UseHsts()` only inside `IsDevelopment()` -> CFG-011 reported; unresolved `app.UseCompanyDefaults();` -> both REVIEW with the call named; unresolved `app.UseSerilogRequestLogging();` -> still firm; library project -> none; `test_kestrel_http_only` (`builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8080));`) -> `("DNL-CFG-013", "low", None)`; adding `o.ListenAnyIP(8443, l => l.UseHttps());` -> none; `appsettings.json` `{"Kestrel": {"Endpoints": {"Http": {"Url": "http://0.0.0.0:80"}}}}` -> CFG-013 at the key line, `http://localhost:5000` only -> none; `{"AllowedHosts": "*"}` -> `("DNL-CFG-014", "low", None)`, `{"AllowedHosts": "example.test"}` -> none, `*` overridden by a Production file -> none.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement `_transport`; README rows.**
- [ ] **Step 4: Run to verify they pass**, plus `tests/test_owasp_readme.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core transport configuration rules`

---

### Task 5: CORS (DNL-CFG-007 reused, DNL-CFG-015)

**Files:**
- Modify: `checks/dnl/rules_pipeline.py` (group `_cors`), `languages/dotnet_legacy/README.md` (row CFG-015)
- Test: `tests/test_dnl_rules_pipeline.py`

**Interfaces:** Produces `rules_pipeline._cors(ctx)`. Policies come from the option lambdas of Production `AddCors` calls (`o.AddPolicy("n", b => b.AllowAnyOrigin()...)`, `o.AddDefaultPolicy(b => ...)`); a policy builder lambda's fluent chain is read with `call_chain`.
- **CFG-007** (medium; high when the same chain has `AllowCredentials()`; title says which): `AllowAnyOrigin()`, `WithOrigins("*")`, `SetIsOriginAllowed(f)` where `options.always_true(f)`, `SetIsOriginAllowedToAllowWildcardSubdomains()` with a bare `*` origin. `AllowAnyOrigin()` + `AllowCredentials()` is reported once (high) with the note that the framework throws at runtime. A policy defined only under `IsDevelopment()` is not reported. `UseCors(b => b.AllowAnyOrigin())` inline policy is read the same way.
- **CFG-015** (low, REVIEW, route-bound): a route whose action/class/page model (or minimal-API `endpoint_calls`/group calls `RequireCors("n")`) carries `[EnableCors]`/`RequireCors` and whose handler is "sensitive" per `rules_auth_core._sensitive(ref)` or mutating; skipped when the named policy is reported by CFG-007 (already covered); `[DisableCors]` is ignored.

- [ ] **Step 1: Write the failing tests** (`mode`): `AddCors(o => o.AddPolicy("p", b => b.AllowAnyOrigin().AllowAnyHeader()))` -> `("DNL-CFG-007", "medium", None)`; adding `.AllowCredentials()` -> `("DNL-CFG-007", "high", None)` once; `b.SetIsOriginAllowed(_ => true).AllowCredentials()` -> high; `b.SetIsOriginAllowed(o => o.EndsWith(".example.test"))` -> none; `b.WithOrigins("https://a.example.test")` -> none; policy inside `if (builder.Environment.IsDevelopment())` -> none; `app.UseCors(b => b.AllowAnyOrigin())` -> medium; `test_enable_cors_on_sensitive_route` (controller `AdminController` with `[EnableCors("tight")]` on `Reset()` and a tight policy) -> `("DNL-CFG-015", "low", "REVIEW")` with a `Route`; the same under a wildcard policy -> CFG-007 only.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement `_cors`; README row (CFG-007 note is Task 13).**
- [ ] **Step 4: Run to verify they pass.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core CORS configuration rules`

---

### Task 6: Cookies and session (SESS-001/002/003 reused, SESS-009)

**Files:**
- Create: `checks/dnl/rules_pipeline_auth.py` (group `cookies`)
- Modify: `checks/dnl/rules_pipeline.py` (call `rules_pipeline_auth.check_cookies(ctx)`), `core/owasp_web.py` (`_add(["DNL-SESS-009", "DNL-SESS-010", "DNL-SESS-011"], "A07", "A07", "API2")`), `languages/dotnet_legacy/README.md` (row SESS-009)
- Test: `tests/test_dnl_rules_pipeline_auth.py`

**Interfaces:** Produces `rules_pipeline_auth.check_cookies(ctx: Ctx) -> None`. Cookie option sources (Production calls only): `AddCookie(o => ...)` and `AddCookie(scheme, o => ...)` (`Cookie.*`, `ExpireTimeSpan`, `SlidingExpiration`), `ConfigureApplicationCookie`/`ConfigureExternalCookie`, `AddSession(o => ...)` (`Cookie.*`), `AddAntiforgery(o => ...)` (`Cookie.*`), `Configure<CookiePolicyOptions>`, `UseCookiePolicy(new CookiePolicyOptions { ... })` (`Secure`, `HttpOnly`, `MinimumSameSitePolicy`), and a `new CookieBuilder { ... }` initializer anywhere in those lambdas.
- **SESS-001** (medium): `Cookie.SecurePolicy` (or `SecurePolicy`, `Secure`) set to `CookieSecurePolicy.None` or `SameAsRequest`, or `Secure = CookieSecurePolicy.None` in `CookiePolicyOptions`.
- **SESS-002** (low): `Cookie.HttpOnly = false` (or `HttpOnly = HttpOnlyPolicy.None`).
- **SESS-009** (low): `Cookie.SameSite = SameSiteMode.None` (or `MinimumSameSitePolicy = SameSiteMode.None`).
- **SESS-003** (low): `ExpireTimeSpan` with `timespan_minutes > 1440` while `SlidingExpiration` is not literally false; `Cookie.MaxAge`/`IdleTimeout` over 1440 on session cookies.
- A non-literal value (`Cookie.SecurePolicy = policyFromConfig`) -> the same id with `confidence="REVIEW"` and a note (SESS-001/002 only).

- [ ] **Step 1: Write the failing tests** (`mode`): `AddCookie(o => { o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; })` -> `("DNL-SESS-001", "medium", None)`; `Always` -> none; `o.Cookie.HttpOnly = false;` -> `("DNL-SESS-002", "low", None)`; `o.Cookie.SameSite = SameSiteMode.None;` -> `("DNL-SESS-009", "low", None)`; `o.ExpireTimeSpan = TimeSpan.FromDays(30);` -> `("DNL-SESS-003", "low", None)`, with `o.SlidingExpiration = false;` -> none, `FromMinutes(30)` -> none; `AddSession(o => o.Cookie.HttpOnly = false)` -> SESS-002; `AddAntiforgery(o => o.Cookie.SecurePolicy = CookieSecurePolicy.None)` -> SESS-001; `UseCookiePolicy(new CookiePolicyOptions { Secure = CookieSecurePolicy.None })` -> SESS-001; `o.Cookie.SecurePolicy = policy;` (a local) -> `("DNL-SESS-001", "medium", "REVIEW")`; the same weak cookie inside `IsDevelopment()` -> none; default `AddCookie()` with no options -> none.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement; OWASP rows and README row.**
- [ ] **Step 4: Run to verify they pass**, plus `tests/test_owasp_readme.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core cookie and session configuration rules`

---

### Task 7: Antiforgery (DNL-CSRF-001 reused, DNL-CSRF-002)

**Files:**
- Modify: `checks/dnl/rules_pipeline_auth.py` (group `antiforgery`), `core/owasp_web.py` (`_add(["DNL-CSRF-002"], "A01", "A01", None)`), `languages/dotnet_legacy/README.md` (row CSRF-002)
- Test: `tests/test_dnl_rules_pipeline_auth.py`

**Interfaces:** Produces `rules_pipeline_auth.check_antiforgery(ctx: Ctx) -> None`.
- Cookie auth present: Production `AddCookie`, `AddIdentity*`, `AddDefaultIdentity`, `AddAuthentication(CookieAuthenticationDefaults...)`. When none is present but an unresolved `services` call outside `_NON_AUTHZ_EXTENSIONS` exists, treat as "unknown" and report CSRF-001 as REVIEW; with token-only auth (only `AddJwtBearer`) report nothing.
- Global protection: `Filters.Add(new AutoValidateAntiforgeryTokenAttribute())`, `Filters.Add<AutoValidateAntiforgeryTokenAttribute>()`, `Filters.Add(new ValidateAntiForgeryTokenAttribute())` inside `AddControllers*`/`AddMvc`/`Configure<MvcOptions>` lambdas.
- **CSRF-001** (medium; route-bound): controller routes with `api_surface == False`, an explicit mutating verb, cookie auth present, no global protection, and no `[ValidateAntiForgeryToken]`/`[AutoValidateAntiforgeryToken]` on action, class or a base class. `[ApiController]` routes and Razor Pages (antiforgery is automatic) are never CSRF-001. Skipped when the action has `[IgnoreAntiforgeryToken]` (that is CSRF-002).
- **CSRF-002** (medium; route-bound): `[IgnoreAntiforgeryToken]` on a mutating action, controller class, Razor PageModel class or handler, or a global `Filters.Add(new IgnoreAntiforgeryTokenAttribute())`; minimal-API endpoint whose `endpoint_calls`/group calls include `DisableAntiforgery()` and whose handler takes a `[FromForm]`/`IFormFile`/`IFormCollection` parameter, with cookie auth present (no form binding -> not reported). Routes with `meta["env"] == "Development"` are skipped.

- [ ] **Step 1: Write the failing tests** (`mode`): MVC controller (`: Controller`) with `[HttpPost] Save()`, `AddAuthentication().AddCookie()`, no filter -> `("DNL-CSRF-001", "medium", None)` with a Route; adding `o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute())` in `AddControllersWithViews(...)` -> none; `[ValidateAntiForgeryToken]` on the action -> none; JWT-only app (`AddAuthentication().AddJwtBearer()`) -> none; `[ApiController]` controller -> none; Razor page `OnPost` -> none; `[IgnoreAntiforgeryToken]` on a `[HttpPost]` action -> `("DNL-CSRF-002", "medium", None)` and no CSRF-001 for it; `[IgnoreAntiforgeryToken]` on a Razor PageModel class -> CSRF-002 on its POST handler; `app.MapPost("/up", ([FromForm] IFormFile f) => 1).DisableAntiforgery();` with cookie auth -> CSRF-002; the same without a form parameter -> none; unresolved `services.AddCompanyAuth()` and no cookie registration -> CSRF-001 REVIEW.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement; OWASP row and README row.**
- [ ] **Step 4: Run to verify they pass**, plus `tests/test_owasp_readme.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core antiforgery rules`

---

### Task 8: JWT and OIDC validation (SESS-010, SESS-011, CFG-012, SEC-004)

**Files:**
- Modify: `checks/dnl/rules_pipeline_auth.py` (group `tokens`), `core/owasp_web.py` (`DNL-SEC-004` joins `_add(["DNL-SEC-004", "DNL-SEC-005", "DNL-SEC-006", "DNL-SEC-007"], "A07", "A07", "API2")`), `languages/dotnet_legacy/README.md` (rows SESS-010, SESS-011, CFG-012, SEC-004)
- Test: `tests/test_dnl_rules_pipeline_auth.py`

**Interfaces:** Produces `rules_pipeline_auth.check_tokens(ctx: Ctx) -> None`. Sources (Production calls only): `AddJwtBearer`/`AddOpenIdConnect`/`AddMicrosoftIdentityWebApi`/`AddCookie`-chained option lambdas and `Configure<JwtBearerOptions>`; `TokenValidationParameters` as `o.TokenValidationParameters = new TokenValidationParameters { ... }`, `o.TokenValidationParameters.ValidateX = ...`, or a `new TokenValidationParameters` held in a local/field the lambda references (resolve one level through the enclosing method's locals).
- **SESS-010**: `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, `RequireExpirationTime` set to literal false -> medium; `ValidateIssuerSigningKey = false`, `RequireSignedTokens = false`, or a `SignatureValidator` assigned a lambda that returns its token argument unchecked (`(token, p) => new JwtSecurityToken(token)` / `new JsonWebToken(token)`) -> high; `ValidateAudience` is not reported when `ValidAudience`/`ValidAudiences` is set AND the flag is not false (only literal false counts). A non-literal value -> same id REVIEW (medium) naming the expression text. Also `JwtSecurityTokenHandler.ReadJwtToken`/`ReadToken` used where `ValidateToken` is absent anywhere in the solution is out of scope.
- **SESS-011** (low): `ClockSkew` with `timespan_minutes > 10`.
- **CFG-012** (medium): `RequireHttpsMetadata = false` (any option lambda, incl. `AddOpenIdConnect`), non-literal -> REVIEW; `appsettings` `RequireHttpsMetadata: false` (any section) in `effective("Production")` likewise.
- **SEC-004** (high): `new SymmetricSecurityKey(<bytes>)` where the byte source is `Encoding.*.GetBytes("literal")`, `Convert.FromBase64String("literal")` or a `const`/static readonly string field/local initialised with a literal, resolved one level; a placeholder-looking literal (`"changeme"` counts as real; empty or `"<...>"`/`"{...}"` does not) -- reuse `rules_config`'s placeholder test where available. Reported at the `new` line.

- [ ] **Step 1: Write the failing tests** (`mode`): `AddJwtBearer(o => o.TokenValidationParameters = new TokenValidationParameters { ValidateIssuer = false, ValidateAudience = false })` -> two `("DNL-SESS-010", "medium", None)`; `ValidateIssuerSigningKey = false` -> `("DNL-SESS-010", "high", None)`; `RequireSignedTokens = false` -> high; `SignatureValidator = (t, p) => new JwtSecurityToken(t)` -> high; `ValidateIssuer = cfg.GetValue<bool>("V")` -> `("DNL-SESS-010", "medium", "REVIEW")`; `ValidateLifetime = true` -> none; `ClockSkew = TimeSpan.FromHours(1)` -> `("DNL-SESS-011", "low", None)`, `TimeSpan.Zero` -> none; `o.RequireHttpsMetadata = false;` -> `("DNL-CFG-012", "medium", None)`, `= !env.IsDevelopment()` -> CFG-012 REVIEW; the same inside `IsDevelopment()` -> none; `appsettings.json` `{"Auth": {"RequireHttpsMetadata": false}}` -> CFG-012 at the line; `new SymmetricSecurityKey(Encoding.UTF8.GetBytes("super-secret-signing-key-123456"))` -> `("DNL-SEC-004", "high", None)`; key via `const string K = "..."` -> SEC-004; `GetBytes(config["Jwt:Key"])` -> none.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement; OWASP rows and README rows.**
- [ ] **Step 4: Run to verify they pass**, plus `tests/test_owasp_readme.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core JWT and OIDC validation rules`

---

### Task 9: Identity options (SEC-005, SEC-006, SEC-007)

**Files:**
- Modify: `checks/dnl/rules_pipeline_auth.py` (group `identity`), `languages/dotnet_legacy/README.md` (rows SEC-005, 006, 007)
- Test: `tests/test_dnl_rules_pipeline_auth.py`

**Interfaces:** Produces `rules_pipeline_auth.check_identity(ctx: Ctx) -> None`. Sources: option lambdas of Production `AddIdentity`, `AddDefaultIdentity`, `AddIdentityCore`, `Configure<IdentityOptions>`; code that calls `PasswordSignInAsync`/`CheckPasswordSignInAsync` (any receiver) from the solution's IR.
- **SEC-005**: `Password.RequiredLength` literal below 8 -> medium (the framework default is 6, unset is not reported); `Password.RequireDigit/RequireLowercase/RequireUppercase/RequireNonAlphanumeric = false` -> low, one finding per assignment; `Password.RequiredUniqueChars` below 2 is ignored.
- **SEC-006** (medium): `Lockout.AllowedForNewUsers = false`; `Lockout.MaxFailedAccessAttempts` above 20; a `PasswordSignInAsync(...)`/`CheckPasswordSignInAsync(...)` call whose named or fourth/third positional `lockoutOnFailure` argument is literal false (named-argument and positional forms: `PasswordSignInAsync(u, p, remember, false)`).
- **SEC-007** (low): `SignIn.RequireConfirmedAccount = false`, `SignIn.RequireConfirmedEmail = false` (explicit only; an absent option is not reported).
- A non-literal value is REVIEW for SEC-005 (`RequiredLength`) and SEC-006 only.

- [ ] **Step 1: Write the failing tests** (`mode`): `AddIdentity<U, R>(o => { o.Password.RequiredLength = 4; })` -> `("DNL-SEC-005", "medium", None)`; `RequiredLength = 12` -> none; `o.Password.RequireDigit = false;` -> `("DNL-SEC-005", "low", None)`; `o.Lockout.AllowedForNewUsers = false;` -> `("DNL-SEC-006", "medium", None)`; `MaxFailedAccessAttempts = 1000` -> SEC-006; `signIn.PasswordSignInAsync(u, p, false, lockoutOnFailure: false)` inside a controller -> SEC-006 at that line; positional `false` fourth argument -> SEC-006; `lockoutOnFailure: true` -> none; `o.SignIn.RequireConfirmedAccount = false;` -> `("DNL-SEC-007", "low", None)`; `AddDefaultIdentity<U>()` with no options -> none; `o.Password.RequiredLength = n;` (a local) -> REVIEW; weak options inside `IsDevelopment()` -> none.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement; README rows.**
- [ ] **Step 4: Run to verify they pass**, plus `tests/test_owasp_readme.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core Identity option rules`

---

### Task 10: Secrets in `appsettings*.json` (SEC-001, SEC-002)

**Files:**
- Create: `checks/dnl/rules_secrets_core.py`, `tests/test_dnl_rules_secrets_core.py`
- Modify: `checks/dnl/rules_pipeline.py` (call `rules_secrets_core.check(ctx)`)
- Reuse (import, do not copy): the key pattern and placeholder helpers in `checks/dnl/rules_config.py` (`_is_setting_key` and its secret-key regexes); if they are private, expose public aliases there without changing legacy behaviour.

**Interfaces:** Produces `rules_secrets_core.check(ctx: Ctx) -> None`, reading every `Entry` of `ctx.settings` (raw entries per file, not merged: a secret in a file is reported where it is).
- **SEC-001** (high): a value under `ConnectionStrings:*` (or any key ending `ConnectionString`) containing a `Password=`/`Pwd=` part with a real value. **SEC-002** (medium): a key whose last segment matches the SEC-002 secret pattern (password, secret, apikey, token, `Jwt:Key`, `SigningKey`, `ClientSecret`, ...) with a non-empty string literal value; setting-name keys (`PasswordMinLength`, `TokenExpiration`, ...) are skipped by the shared helper.
- Ignored values: empty, `null`, whole-value placeholders (`$(Pw)`, `{DbPassword}`, `#{Pw}#`, `${ENV}`, `%VAR%`, `<set me>`, `changeme`-style stays real), Key Vault / user-secrets style references (`@Microsoft.KeyVault(...)`, `vault:`, `keyvault:`, `secret://`), and `Integrated Security=true` strings without a password.
- Development rule (spec Decision 3): entries from `appsettings.Development.json` and from `launchSettings.json` (env `"launch"`) are read only when the value looks real (at least 8 characters, not a placeholder word such as `password`, `secret`, `test`, `dev`, `local`, `example`, `changeme`... and not all one repeated character) and are reported one severity lower (high -> medium, medium -> low). Other environment files (Production, Staging, base) are full severity.

- [ ] **Step 1: Write the failing tests** (no helper needed; `make_app` plus `run_check`): base `appsettings.json` `{"ConnectionStrings": {"Default": "Server=db;Database=a;User Id=app;Password=Zx9!kLm3pQ"}}` -> `("DNL-SEC-001", "high", None)` at the key's line; `Integrated Security=true` -> none; `Password=$(DbPassword)` -> none; `{"Jwt": {"Key": "k8s9d7f6g5h4j3k2"}}` -> `("DNL-SEC-002", "medium", None)`; `{"Jwt": {"Key": "@Microsoft.KeyVault(SecretUri=https://v.example.test/secrets/k)"}}` -> none; `{"Logging": {"TokenExpiration": "00:10:00"}}` -> none; `appsettings.Development.json` with `"Password=password"` placeholder -> none, with `"Password=Zx9!kLm3pQ"` -> `("DNL-SEC-001", "medium", None)`; `appsettings.Production.json` secret -> high; `Properties/launchSettings.json` `{"profiles": {"p": {"environmentVariables": {"Db__Password": "Zx9!kLm3pQ"}}}}` -> `("DNL-SEC-002", "low", None)`; commented-out and malformed file -> a model note naming the file and no crash; an `appsettings.json` in a legacy (`net48`) project directory is not read (owner rule).
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement `rules_secrets_core.py`; wire.**
- [ ] **Step 4: Run to verify they pass**, plus `tests/test_dnl_rules_config.py -q` (legacy unchanged). Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): secrets in appsettings and launchSettings`

---

### Task 11: Resource limits (RES-001 reused, RES-004, RES-005)

**Files:**
- Create: `checks/dnl/rules_limits_core.py`, `tests/test_dnl_rules_limits_core.py`
- Modify: `checks/dnl/rules_pipeline.py` (call `rules_limits_core.check(ctx)`), `core/owasp_web.py` (`_add(["DNL-RES-004", "DNL-RES-005"], "A06", "A04", "API4")`), `languages/dotnet_legacy/README.md` (rows RES-004, RES-005)

**Interfaces:** Produces `rules_limits_core.check(ctx: Ctx) -> None`.
- **RES-001** (low; route-less or route-bound): `MaxRequestBodySize` set to literal `null` or above 100 MiB in `ConfigureKestrel`/`Configure<KestrelServerOptions>`/`Configure<IISServerOptions>`/`Configure<HttpSysOptions>` lambdas (`Limits.MaxRequestBodySize`), `FormOptions.MultipartBodyLengthLimit` above 100 MiB (`long.MaxValue`, `int.MaxValue`, `null`-like), and `[DisableRequestSizeLimit]` or `[RequestSizeLimit(n > 100 MiB)]` on a route's action/class/page model, and minimal-API `.WithMetadata(new DisableRequestSizeLimitAttribute())`. appsettings `Kestrel:Limits:MaxRequestBodySize` literal over the limit too.
- **RES-004** (low; REVIEW per builder note 2 when the pipeline is not fully read): the solution has a login, token or password-reset endpoint (route path or handler name matches `(?i)login|signin|token|authenticate|forgot|reset|password`, mutating or any verb for token) and no rate limiting in Production: no `UseRateLimiter`, no `RequireRateLimiting`/`[EnableRateLimiting]` on that route or its group, and none of the third-party names `UseIpRateLimiting`, `UseClientRateLimiting`, `AddInMemoryRateLimiting`, `UseRateLimitingMiddleware`. One finding per pipeline, at the first matching route (route-bound), listing up to five routes. A sensitive route with `[DisableRateLimiting]` / `.DisableRateLimiting()` is reported itself even when a limiter exists.
- **RES-005** (low, route-bound): an action/handler parameter named like `(?i)^(page_?size|limit|take|count|per_?page|top|max_?results)$` of integer type that reaches `Take(...)` (directly or through one local) with no bound in the handler body: a comparison of the parameter, `Math.Min`/`Math.Clamp`/`Clamp` over it, or a `[Range(...)]` attribute on the parameter. Any route style; unresolved hand-offs to another method (`repo.List(pageSize)`) are not reported.

- [ ] **Step 1: Write the failing tests** (`mode`): `ConfigureKestrel(o => o.Limits.MaxRequestBodySize = null)` -> `("DNL-RES-001", "low", None)`; `= 10 * 1024 * 1024` -> none; `= 2000L * 1024 * 1024` -> RES-001; `[DisableRequestSizeLimit]` on an upload action -> RES-001 with a Route; `Configure<FormOptions>(o => o.MultipartBodyLengthLimit = long.MaxValue)` -> RES-001; app with `[HttpPost("login")] Login()` and no limiter -> `("DNL-RES-004", "low", None)`; with `builder.Services.AddRateLimiter(...)` and `app.UseRateLimiter()` -> none; `UseRateLimiter` only under `IsDevelopment()` -> RES-004; `UseIpRateLimiting()` -> none; app with no sensitive endpoints -> none; unresolved `app.UseCompanyDefaults()` -> REVIEW; `[DisableRateLimiting]` on the login action with a limiter present -> RES-004 on that route; `[HttpGet] List(int pageSize) => db.Items.Take(pageSize).ToList()` -> `("DNL-RES-005", "low", None)`; with `pageSize = Math.Min(pageSize, 100)` or `if (pageSize > 100) return BadRequest();` -> none; `[Range(1, 100)] int pageSize` -> none; `repo.List(pageSize)` -> none.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement; wire; OWASP rows and README rows.**
- [ ] **Step 4: Run to verify they pass**, plus `tests/test_owasp_readme.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core resource-limit rules`

---

### Task 12: Inventory and data protection (INV-003, INV-004, CRY-009)

**Files:**
- Modify: `checks/dnl/rules_pipeline.py` (groups `_inventory`, `_data_protection`), `core/owasp_web.py` (`_add(["DNL-INV-003", "DNL-INV-004"], "A02", "A05", "API9", "always")`, `_add(["DNL-CRY-009"], "A04", "A02", None)`), `languages/dotnet_legacy/README.md` (rows INV-003, INV-004, CRY-009)
- Test: `tests/test_dnl_rules_pipeline.py`

**Interfaces:** Produces `rules_pipeline._inventory(ctx)` and `rules_pipeline._data_protection(ctx)`.
- **INV-003** (low): a Production call (`runs_in("Production") is True`) to `UseSwagger`, `UseSwaggerUI`, `UseReDoc`, `MapOpenApi`, `MapScalarApiReference`, `MapSwagger`, or `UseOpenApi`/`UseKnife4j`-style names (`UseOpenApi`); under an unparseable guard -> REVIEW; `MapOpenApi()` inside `IsDevelopment()` -> none. One finding per call; the description says whether it also sits behind `RequireAuthorization` (info only, still reported).
- **INV-004** (low, REVIEW, route-bound): API versions read from `[ApiVersion("1.0")]` attribute arguments and from a leading `/v<N>[.<M>]` path segment of route paths; two or more distinct versions among the solution's routes -> every route of a version lower than the highest, one finding per distinct older version at its first route, unless that version is marked `Deprecated = true` on `[ApiVersion]`/`HasDeprecatedApiVersion`. A single version -> none.
- **CRY-009** (low): Production `AddDataProtection().PersistKeysToFileSystem(...)` (also Redis / blob / EF `PersistKeysTo*`) with no `ProtectKeysWithCertificate`/`ProtectKeysWithDpapi`/`ProtectKeysWithDpapiNG`/`ProtectKeysWithAzureKeyVault` in the same fluent chain or elsewhere in the Production pipeline; `style == "none"` skipped; an unresolved services call -> REVIEW.

- [ ] **Step 1: Write the failing tests** (`mode`): `app.UseSwagger(); app.UseSwaggerUI();` -> two `("DNL-INV-003", "low", None)`; inside `if (app.Environment.IsDevelopment())` -> none; `app.MapOpenApi();` -> INV-003; unparseable guard -> REVIEW; two controllers `[Route("api/v1/orders")]` and `[Route("api/v2/orders")]` -> `("DNL-INV-004", "low", "REVIEW")` on the v1 route, nothing on v2; `[ApiVersion("1.0", Deprecated = true)]` on v1 -> none; only v1 -> none; `AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo("/keys"))` -> `("DNL-CRY-009", "low", None)`; with `.ProtectKeysWithCertificate(cert)` chained -> none; `.SetApplicationName("a")` only -> CRY-009; library project -> none.
- [ ] **Step 2: Run to verify they fail.** Expected: FAIL.
- [ ] **Step 3: Implement; OWASP rows and README rows.**
- [ ] **Step 4: Run to verify they pass**, plus `tests/test_owasp_readme.py -q`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dnl): ASP.NET Core inventory and data-protection rules`

---

### Task 13: End-to-end fixture, degraded parity, docs, Linux run

**Files:**
- Create: `tests/fixtures/aspnetcore/config_app/` (synthetic `Microsoft.NET.Sdk.Web`, `net8.0`: a `Program.cs` that trips one rule of every group in Tasks 3-12 with a deliberately weak configuration, `appsettings.json`, `appsettings.Production.json`, `appsettings.Development.json`, `Properties/launchSettings.json`, two controllers), `tests/test_dnl_config_end_to_end.py`
- Modify: `languages/dotnet_legacy/README.md` (a "Configuration rules for ASP.NET Core" subsection: the Production assumption, REVIEW degradations, appsettings handling, the reused-ids note for every reused id, the SEC-003 dependency)

**Interfaces:** none new.

- [ ] **Step 1: Write the failing tests** in `tests/test_dnl_config_end_to_end.py`: `test_fixture_reports_every_group` (roslyn_helper): `enumerate_target(config_app)` yields, in the `dotnet/config` result, at least one finding of each new id in the Rule ids table that is route-less, and route-bound ones (`DNL-CFG-015`, `DNL-CSRF-002`, `DNL-RES-005`, `DNL-INV-004`) on the right routes in the route analyzer results; `test_degraded_parity`: with the helper unavailable (`allow_degraded=True`) the `(check_id, file, line)` set of every `DNL-CFG-*`, `DNL-SESS-009..011`, `DNL-SEC-004..007`, `DNL-CSRF-002`, `DNL-RES-004/005`, `DNL-INV-003/004`, `DNL-CRY-009` finding equals the helper run, and every degraded result has `degraded` set; `test_every_new_id_registered`: each id in the Rule ids table is in `core.owasp_web.RULES` and in the README rule table, and a grep of `checks/dnl/rules_pipeline*.py`, `rules_secrets_core.py`, `rules_limits_core.py` finds each as a quoted literal; `test_legacy_unchanged`: `dotnet_legacy` enumeration of `tests/fixtures/dotnet_legacy/mvc5_app` equals its pre-change `(check_id, file, line)` set recorded in the test; `test_no_dev_noise`: the fixture's `IsDevelopment()`-guarded weak settings produce no finding.
- [ ] **Step 2: Run to verify they fail** (fixture absent). Expected: FAIL.
- [ ] **Step 3: Create the fixture and the README subsection.** Write the hand-over note (merge points with Plan 2: `languages/dotnet/analyzers.py` wiring line, README coverage table, `languages/dotnet/README.md`, `tests/test_owasp_inventory_dnl.py` expectations for the new ids reachable from `languages/dotnet`; the `rules_crypto` wiring needed for `DNL-SEC-003`) to the shared notes folder.
- [ ] **Step 4: Run the full suite.** Run: `.venv\Scripts\python -m pytest -q`. Expected: PASS (baseline plus this plan's tests). Fix any README-table or OWASP-enforcement failures in the owning task's files.
- [ ] **Step 5: Linux run only if the Docker daemon is up.** `docker info` must show a Server section; never start Docker Desktop. If it is running, run the command from Plan 1 Task 11 Step 5 and expect the same pass count; otherwise say "Docker daemon not running; Linux run not performed" in the report.
- [ ] **Step 6: Scrub and commit.** `git diff feature/aspnetcore-foundation --stat`; grep the diff and the branch's commit messages for client/target names, local paths and em-dashes (none expected). Commit `test(dnl): ASP.NET Core configuration end-to-end fixture, degraded parity and docs`.
