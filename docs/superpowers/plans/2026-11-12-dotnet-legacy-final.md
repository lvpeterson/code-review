# dotnet_legacy Final Plan: SCA, Remaining Categories, Degraded Mode, Acceptance (Plan 4 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining OWASP coverage (vulnerable/outdated components, exceptional-condition handling, sensitive business flows, plus the spec's remaining LOG / RES / INV / CONSUME rows), enforce "every category in all three lists has at least one rule" with a test, give the analyzer a useful degraded mode when the Roslyn helper is unavailable, and finish with a real-target acceptance pass.

**Architecture:** An offline advisory table (data file, every entry carrying a verified advisory id) drives package/library rules over `packages.config`, project `HintPath`s, `nuget.config` and bundled `Scripts/*.js` banners. New IR rule modules add error-handling, logging, business-flow, resource, inventory and API-consumption checks using the existing route index, body enumeration and taint summaries. Degraded mode lowers C# with the already-installed tree-sitter grammar into the same IR subset the rule modules read, and falls back to marked regex scanning for VB.

**Tech Stack:** Python 3.10+, pytest, tree-sitter-c-sharp (already a dependency); existing Roslyn helper.

**Spec:** `docs/superpowers/specs/2026-11-11-dotnet-legacy-design.md` (SCA, LOG, ERR, DES, RES, INV, CONSUME rows; Preflight/degraded mode; Testing). Plans 1-3 are done.

**Checkpoints:** 4a = Tasks 1-4 (rules + coverage test). 4b = Tasks 5-6 (degraded mode, acceptance + docs).

## Global Constraints

- Public repo: nothing committed (code, fixtures, tests, README, docs, data files, commit messages) may name a client, engagement, target app, local path or user. Fixtures synthetic. Real-target outputs outside the repo.
- Prose and comments use `--`, never em-dashes; comment density like `checks/tf_graph.py`.
- Tests: `.venv\Scripts\python -m pytest -q` from the repo root -- baseline 821; must also pass on Linux.
- VB identifiers case-insensitive. A false "safe" is the worst outcome; noise is secondary.
- Every new rule id gets a `core/owasp_web.RULES` entry and a README row (enforced by the README test) in the task that adds it.
- Advisory data must be accurate: every entry has an advisory id (GHSA or CVE) and the affected version range copied from the advisory; no entry from memory alone -- verify against the advisory source (OSV/GHSA pages via web lookup) or leave it out.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Branch `feature/dotnet-legacy-final`.

## New rule ids

| id | sev | 2025 | 2021 | API (mode) | what |
|---|---|---|---|---|---|
| DNL-SCA-001 | from advisory (high/medium/low) | A03 | A06 | -- | NuGet package version (packages.config, or `HintPath` `packages\<Id>.<Version>\`) inside a known-vulnerable range |
| DNL-SCA-002 | from advisory | A03 | A06 | -- | bundled JS library (`Scripts/`, `Content/`, `lib/` banners: jQuery, jQuery UI, jQuery Validation, Bootstrap, Moment, Knockout, AngularJS, Handlebars, Lodash) inside a known-vulnerable range |
| DNL-SCA-003 | medium | A03 | A06 | API9 (always) | target framework end of support (< v4.6.2) |
| DNL-SCA-004 | low REVIEW | A03 | A06 | -- | DLL referenced from `packages\` or a lib folder with no matching `packages.config` entry / no version in the path (unmanaged binary dependency) |
| DNL-SCA-005 | medium | A03 | A08 | -- | `nuget.config` package source over `http://` |
| DNL-ERR-001 | medium | A10 | A04 | -- | empty catch, or catch that only logs/continues, around an authentication/authorization decision (fail-open): catch inside a method whose body or callees decide auth (`IsInRole`, `IsAuthenticated`, `AuthorizeCore`, `OnAuthorization`, a hand-rolled check) and the catch path returns true/continues to the protected action |
| DNL-ERR-002 | medium | A10 | A05 | API8 | exception detail returned to the client: `ex.Message`/`ex.ToString()`/`ex.StackTrace`/`ex.InnerException` flowing to `Response.Write`, a view (`ViewBag`/model), `Content`/`Json`/`Ok`/`BadRequest`/`InternalServerError`/`CreateErrorResponse`/`HttpResponseException`, or a WCF `FaultException<string>` |
| DNL-ERR-003 | low | A10 | A04 | -- | swallowed exception: `catch { }` / `catch (Exception) { }` with an empty body (outside the ERR-001 auth case) |
| DNL-LOG-002 | low REVIEW | A09 | A09 | -- | no logging framework configured anywhere (no log4net/NLog/Serilog/EntLib/ELMAH/TraceSource config or package) |
| DNL-LOG-003 | medium | A09 | A09 | -- | password/secret logged: a value whose name matches the SEC key pattern passed to a log sink |
| DNL-LOG-004 | low REVIEW | A09 | A09 | -- | login failure not logged: a login action/handler branch that rejects credentials without any log call in that branch |
| DNL-DES-001 | low REVIEW | A06 | A04 | API6 (always) | sensitive flow without throttling: login, password reset/forgot, register, change password, payment/checkout/transfer actions (by name) with no lockout (`Membership.ValidateUser`, `PasswordSignInAsync(..., shouldLockout: true)`, `UserManager.AccessFailedAsync`), CAPTCHA, or rate-limit attribute/filter in the action, controller or global filters |
| DNL-RES-002 | low | A06 | A04 | API4 | unbounded list endpoint: a Web API/MVC action returning a collection from an EF `DbSet`/query with no `Take`/`Skip`/paging parameter and no `[EnableQuery(PageSize=...)]` |
| DNL-RES-003 | medium | A06 | A04 | API4 | file upload with no size check: `HttpPostedFile(Base)`/`Request.Files` saved (`SaveAs`, stream copy) without a `ContentLength` comparison in the action |
| DNL-INV-002 | low | A02 | A05 | API9 (always) | Web API HelpPage area or Swagger UI reachable without auth; test/debug controllers (`*Test*Controller`, `DebugController`, `DiagnosticsController`) in non-test projects |
| DNL-CONSUME-001 | low REVIEW | A08 | A08 | API10 (always) | outbound call to a hard-coded `http://` URL (HttpClient/WebClient/RestClient/WebRequest base or request URL literal, service-reference `endpoint address="http://..."` in web.config `<client>`) |
| DNL-CONSUME-002 | low REVIEW | A08 | A08 | API10 (always) | external API response deserialized and used without validation: result of `ReadAsAsync<T>`/`JsonConvert.DeserializeObject` on an outbound response flowing into a SQL/command/path/redirect sink (taint source kind `external`) |

## Review Focus

1. A package referenced only by `HintPath` (no packages.config) with an unusual folder name (`packages\Foo.Bar.1.2.3-beta\lib\net45\Foo.Bar.dll`) parses id and version correctly, including prerelease suffixes (test in Task 1).
2. A minified JS file whose banner is on the first line of a single-line file, and a non-minified file whose banner is a `/*! ... */` block (test in Task 1).
3. ERR-002 must follow the exception variable through a local (`var msg = ex.Message; return Content(msg);`) and through string building (test in Task 2).
4. DES-001 must count a global/base-controller throttling filter as protection (test in Task 3).
5. The coverage test fails loudly naming the uncovered category when a rule mapping is removed (test in Task 4).

---

### Task 1: Offline advisory data and SCA rules

**Files:**
- Create: `data/dnl_advisories.json`, `checks/dnl/rules_sca.py`
- Modify: `core/owasp_web.py` (SCA-001..005), README rows + an "Advisory data" section (source, how to refresh, that `--sca` osv-scanner remains the authoritative online path), `languages/dotnet_legacy/detector.py` + `analyzers.py` (new framework `deps` registered when packages.config, HintPath packages, nuget.config or bundled JS exist; `@register("dotnet_legacy", "deps")`), `pyproject.toml` package data if needed
- Create fixtures: `tests/fixtures/dotnet_legacy/deps_app/` (packages.config with a vulnerable and a fixed version of the same package family, a HintPath-only prerelease package, an unversioned local DLL, nuget.config with an http source, `Scripts/jquery-1.12.4.min.js` and `Scripts/jquery-3.7.1.min.js` stubs carrying only realistic banner comments, a legacy csproj targeting v4.5 and one targeting v4.8)
- Test: `tests/test_dnl_sca.py`

**Interfaces:**
- `data/dnl_advisories.json`: `{"nuget": [{"id": "<package id, case-insensitive>", "advisory": "GHSA-...|CVE-...", "url": "...", "affected": "<range, e.g. \"<13.0.1\" or \">=5.0.0 <5.5.12\">", "severity": "high|medium|low", "summary": "..."}], "js": [{"library": "jquery", ...same keys...}]}`. Ship a small, verified set covering at least: Newtonsoft.Json, jQuery, jQuery UI, jQuery Validation, Bootstrap, RestSharp, iTextSharp/itext7 (if an advisory applies), Microsoft.AspNet.Mvc / WebApi packages (only if a published advisory exists), log4net, elmah (only advisories with ids). Each entry verified against its advisory page (record the URL); if verification isn't possible, omit the entry and say so in the report.
- `rules_sca.version_in(range: str, version: str) -> bool` -- NuGet/semver comparison incl. prerelease ordering and 4-part versions.
- `rules_sca.check(model) -> tuple[list[Finding], list[str]]`; package/library findings anchor at the packages.config line, the csproj `HintPath` line, or line 1 of the JS file; SCA-003 at the `<TargetFrameworkVersion>` line; SCA-005 at the `<add key value="http://...">` line. Description includes the advisory id and URL.

- [ ] **Step 1: Failing tests** -- version range edge cases (`<13.0.1` vs `13.0.1`, `>=5.0 <5.5.12` vs `5.5.12`, prerelease `1.2.3-beta < 1.2.3`), each rule positive + negative, Review Focus 1 and 2, and a data-file schema test (every entry has advisory, url, affected, severity).
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement** (advisory data verified per the constraint). **Step 4: Run** file + full suite, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: offline advisory data and SCA rules"`

---

### Task 2: Exceptional-condition rules (ERR)

**Files:**
- Create: `checks/dnl/rules_errors.py`
- Modify: `core/owasp_web.py` (ERR-001..003), README rows, analyzers wiring (`_code_results`)
- Extend fixture `taint_app` (new files): fail-open auth catch (custom AuthorizeAttribute `AuthorizeCore` with `catch { return true; }`), a safe one (`catch { return false; }`), `ex.Message` returned via `Content`, via a local, via `Json(new { error = ex.ToString() })`, via `ViewBag.Error`, a Web API `InternalServerError(ex)`, a WCF `throw new FaultException(ex.Message)`, a safe generic-message catch, and empty catches.
- Test: `tests/test_dnl_errors.py`

**Interfaces:**
- `rules_errors.check(model, refs) -> list[Finding]` -- uses `typestate.iter_bodies` and `typestate.RouteIndex` for route attachment. ERR-002 tracks the catch variable through locals, member reads (`ex.Message`, `ex.InnerException.Message`), string building and `ToString()` within the catch block (a small local flow; reuse taint helpers if convenient: treat the catch variable as a source of kind `exception` -- if you add that kind to the taint engine, keep it out of the existing request-source rules).
- ERR-001 reuses `auth.never_denies`-style literal-return analysis: a catch whose block returns literal true (or falls through to the success path) inside an auth decision method.

- [ ] **Step 1: Failing tests** -- positives/negatives per rule; Review Focus 3.
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: exception-handling rules"`

---

### Task 3: Logging, business-flow, resource, inventory and API-consumption rules

**Files:**
- Create: `checks/dnl/rules_misc.py` (or `rules_logging.py` + `rules_flows.py` if it grows past ~400 lines)
- Modify: `core/owasp_web.py` (LOG-002..004, DES-001, RES-002..003, INV-002, CONSUME-001..002), README rows, analyzers wiring; `checks/dnl/taint_tables.py` (source kind `external` for outbound-response deserialization, used only by CONSUME-002 -- request-source rules must ignore it)
- Extend fixtures (new files in taint_app / webapi fixtures): a solution with no logging config (separate tiny fixture app) and one with log4net config; password logged; a login action whose failure branch logs and one that doesn't; login/reset/register actions with and without lockout/throttle (incl. a global throttle filter -- Review Focus 4); an unbounded `db.Orders.ToList()` API and a paged one; an upload with and without a `ContentLength` check; HelpPage area registration and a `DebugController`; outbound `http://` literal and an `https://` one; an outbound JSON response deserialized into a SQL string.
- Test: `tests/test_dnl_misc_rules.py`

**Interfaces:** `rules_misc.check(model, refs, configs) -> tuple[list[Finding], list[str]]`; rules as in the table; route attachment via `RouteIndex`; DES-001 one finding per action; LOG-002 one finding per scan (anchored at the first legacy project file); CONSUME-001 also reads web.config `<system.serviceModel><client><endpoint address>`.

- [ ] **Step 1: Failing tests** -- positives/negatives per rule; Review Focus 4.
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: logging, business-flow, resource, inventory and API-consumption rules"`

---

### Task 4: OWASP coverage test (end of 4a)

**Files:**
- Create: `tests/test_owasp_coverage.py`
- Modify: README (coverage table: each category of the three lists -> the rule ids covering it, generated from RULES or test-enforced)

**Interfaces:** `test_every_category_has_a_rule` iterates `TITLES["2025"]`, `TITLES["2021"]`, `TITLES["api2023"]` and asserts each code is mapped by at least one `DNL-` rule (API: rules with that api code in either mode); the failure message names the uncovered list and category (Review Focus 5 -- also add a test that monkeypatches RULES to drop the only API6 rule and asserts the message names "API6"). README coverage table test: every category row lists exactly the rule ids that RULES maps to it.

- [ ] **Step 1: Failing tests.** **Step 2: Run**, FAIL (or PASS if Tasks 1-3 already cover everything -- then prove the negative test fails correctly). **Step 3: Implement** README table. **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: enforce OWASP coverage across all three lists"`

---

### Task 5: Degraded mode -- tree-sitter C# lowering and marked VB regex fallback (start of 4b)

**Files:**
- Create: `checks/dnl/frontend_ts.py` (tree-sitter-c-sharp -> IR subset), `checks/dnl/vb_regex.py`
- Modify: `checks/dnl/project.py` (`prepare` with `allow_degraded` and no helper: build `files` from `frontend_ts` for C# instead of `{}`; VB files go to `vb_regex`), `checks/dnl/helper.py` (`DEGRADED_REASON` text updated: "Roslyn helper not available (--allow-degraded): C# parsed with tree-sitter (no semantic symbols), VB scanned with patterns (REVIEW); findings may be incomplete."), analyzers (degraded runs execute the code rules on the tree-sitter IR; VB regex findings carry `confidence="REVIEW"`), README (degraded mode section)
- Test: `tests/test_dnl_degraded.py`

**Interfaces:**
- `frontend_ts.lower_file(path: Path, rel: str, project: str) -> dict` producing the documented IR schema (types, methods, attributes, params with modifiers, fields/properties incl. init/get/set, statements and expressions) WITHOUT `sym`/`type_full` keys; unknown syntax -> `unknown`/`other` with text, never raising. Must cover what routes/auth/taint/rules read: classes, base lists, attributes with args/named args, methods, params, locals, assignments, calls, member access, `new` with initializers, binary/interp/cond/cast/lambda/unary, if/loop/try/using/return/throw.
- `vb_regex.scan(model) -> list[Finding]` -- a small set of high-signal VB patterns with `confidence="REVIEW"`: string-concatenated SQL into `SqlCommand`/`CommandText`, `Response.Write(Request(...))`, `BinaryFormatter`/`LosFormatter` `.Deserialize`, MD5/SHA1/DES creation, hardcoded `Password=` connection strings, `ServerCertificateValidationCallback = ... True`.
- Parity test: run routes/auth/taint/rules on `taint_app` and `mvc5_app` C# with the Roslyn helper and with tree-sitter; assert the tree-sitter run finds every route and at least the injection/auth findings the helper run finds on the C# fixtures (findings may differ in confidence; document misses due to missing `sym`). The preflight tests from Plan 1 keep passing (no helper + no flag still exits 2).

- [ ] **Step 1: Failing tests** (lowering unit tests per node kind; degraded end-to-end on fixtures; VB regex positives/negatives; parity).
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run** file + full suite, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: tree-sitter C# and VB pattern fallback for degraded mode"`

---

### Task 6: Acceptance pass, docs, Linux

**Files:**
- Modify: `languages/dotnet_legacy/README.md` (overview reorganised for a reader new to the tool: what is detected per category, proven vs REVIEW, degraded mode, data refresh, known limits consolidated from Plans 1-4), root `README.md`, `docs/superpowers/specs/2026-11-11-dotnet-legacy-design.md` status line ("implemented; see README for limits").
- Test: extend `tests/test_dnl_end_to_end.py` (deps_app end-to-end; coverage of all frameworks: mvc, webapi, webforms, wcf, config, deps).

- [ ] **Step 1:** Full suite on Windows; Linux container run (same docker command as Plan 3). Report tails.
- [ ] **Step 2:** Real-target acceptance run (outputs outside the repo): exit code, runtime, findings per rule and per OWASP category, proven vs REVIEW split, note count, degraded-mode run (`--allow-degraded` with the helper hidden via `CODE_REVIEW_ROSLYN_IR` pointing nowhere and `dotnet` removed from PATH for the subprocess) with its own counts. Spot-check 2-3 findings per new rule for plausibility and report precision observations. Fix generic bugs only via synthetic reproductions. Never copy target code or names into the repo or commit messages.
- [ ] **Step 3: Commit** `git commit -m "dotnet_legacy: final docs and acceptance checks"`
