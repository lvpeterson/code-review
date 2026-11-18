# ASP.NET Core SCA and Carried-Over Families Implementation Plan (Plan 4a of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `dotnet` (ASP.NET Core) package an offline SCA analyzer (`deps`) and run the platform-neutral rule families (crypto, deserialization/XXE, integrity, errors, logging/flows/resources/inventory/consumption, session) on SDK projects, each proven on a synthetic Core fixture, with legacy findings unchanged.

**Architecture:** SCA reuses the helpers in `checks/dnl/rules_sca.py` (version compare, advisory match, JS banner scan) from a new `checks/dnl/rules_sca_core.py` that adds what SDK projects have (`PackageReference` versions from `Project.packages`, `packages.lock.json`, end-of-support target frameworks from a dated table, `wwwroot/lib` JS). The carried families are wired into `languages/dotnet/analyzers.py::_code_results` through the existing `guarded(...)` pattern; Web.config-only checks are not passed any config on Core.

**Tech Stack:** Python 3.10+, pytest, Roslyn helper (already built by Plan 1), tree-sitter-c-sharp (degraded mode).

**Spec:** `docs/superpowers/specs/2026-11-14-aspnetcore-design.md` ("SCA and versions (A03, A06)", "Other rule families carried over", Decision 8, "Testing"); foundation: `docs/superpowers/plans/2026-11-15-aspnetcore-foundation.md` (structure model, Builder notes). Out of scope (Plan 4b, after Plans 2 and 3 are combined): the every-OWASP-category coverage test, real-target acceptance, the README coverage table and the final docs pass.

## Global Constraints

- Public repo: nothing committed (code, fixtures, tests, docs, commit messages) may name a client, engagement, target app, local path or person. All fixtures synthetic, generic names. Grep the diff before every commit.
- Prose and comments use `--`, never em-dashes; comment density like the existing `checks/dnl/*.py`.
- Tests: `.venv\Scripts\python -m pytest -q` from the repo root (create with `python -m venv .venv`, then `.venv\Scripts\python -m pip install -r requirements.txt pytest`). Every existing test stays green. Must also pass on Linux.
- Helper-dependent tests use the `roslyn_helper` fixture; degraded tests monkeypatch `checks.dnl.helper.find_helper` and `checks.dnl.helper.sdk_available` (see `tests/test_dotnet_core_analyzers.py::_degraded`).
- A false "safe" is the worst outcome: a package or framework the scanner cannot judge is reported REVIEW, never skipped silently. Noise is secondary.
- No regression for dotnet_legacy: legacy findings are byte-identical before and after (golden test in Task 1); the helper still runs once per scan.
- **Advisory data is verified, never from memory.** Every `nuget` entry needs a real GHSA id whose page or OSV record was fetched in this session; the affected range is converted from that record. An entry that cannot be verified is left out. The Microsoft support dates are likewise copied from the lifecycle page.
- The Roslyn helper compiles only against framework reference packs: NuGet types (Newtonsoft, EF Core, BouncyCastle, Serilog...) never resolve to symbols, so rules must work by name for them. Do not assume `sym` for them in fixtures or rules.
- Rule ids are quoted literals. Every new id gets a `core/owasp_web.RULES` entry and a row in `languages/dotnet_legacy/README.md` (enforced by `test_readme_lists_every_rule_with_tags`) in the task that adds it.
- Do not touch the README coverage table, `tests/owasp_inventory.py` expectations beyond what a failing existing test forces (change only the numbers it asserts and record a ledger line), nor write the coverage test (Plan 4b). Expect merge conflicts with Plans 2 and 3 in `languages/dotnet/analyzers.py`, `languages/dotnet/detector.py`, the README table, `languages/dotnet/README.md` and `tests/test_owasp_inventory_dnl.py`; keep edits there minimal and local so the combining step is mechanical.
- Subagent models: Sonnet for implementers and reviewers, Haiku for scoped re-reviews; always pass `model` explicitly; never Opus.
- Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Branch `claude/funny-neumann-c8d9ee`. No push, no merge.

## Rule ids

| id | sev | 2025 / 2021 / API | status | what (dotnet) |
|---|---|---|---|---|
| DNL-SCA-001 | from advisory | A03 / A06 / -- | reused | `PackageReference` / central version / lock-file resolved version inside an advisory range |
| DNL-SCA-002 | from advisory | A03 / A06 / -- | reused | bundled JS under `wwwroot/lib` (and `Scripts`, `Content`, `lib`) by banner |
| DNL-SCA-003 | medium | A03 / A06 / API9 | reused | target framework past end of support per the dated table (`netcoreapp*`, `net5.0`...) |
| DNL-SCA-004, 005 | -- | -- | reused as is | unmanaged HintPath DLL; http `nuget.config` source (both already run through `rules_sca`) |
| DNL-SCA-006 | low REVIEW | A03 / A06 / -- | **new** | package whose version cannot be resolved (floating `1.*`, property `$(X)`, missing central version, unparsable range): it cannot be matched against advisories, so it is never reported as clean |

Carried families (existing ids, no new ones expected): DNL-CRY-001..008, DNL-DESER-001..003, DNL-DES-001, DNL-XXE-001/002, DNL-INT-003 (SRI on CDN scripts), DNL-ERR-001..003, DNL-LOG-002..004, DNL-RES-002/003, DNL-INV-002, DNL-CONSUME-001/002, DNL-SEC-003, DNL-SESS-006..008, DNL-INT-004 (WebForms ViewState: legacy-only).

## Review Focus

1. A `PackageReference` with `Version="1.*"`, `Version="$(JsonVer)"`, `[1.0,2.0)`, or no version and no central entry must produce DNL-SCA-006 (or, for a range, be matched on its lower bound), never silence (Task 2).
2. A vulnerable package that appears only as a `Transitive` entry in `packages.lock.json` is reported (with "transitive" in the description and the lock file as the location); a package present both directly and in the lock file is reported once, using the lock file's resolved version (Task 2).
3. A `Web.config` that only holds the IIS `aspNetCore` hosting stub inside an SDK project, or one with legacy `system.web` sections, produces no config-rule findings and no crash notes for `dotnet` (Task 6).
4. In a mixed solution each package/file is owned by exactly one package: the legacy `deps` and the Core `deps` never report the same file; `bin/`, `obj/` and `node_modules/` copies of `wwwroot/lib` JS are not reported (Tasks 2, 3).
5. One crashing carried module must not hide the others, and the crash note appears in the result notes (Task 4).

---

### Task 1: Environment, fixtures skeleton, legacy golden baseline

**Files:**
- Create: `tests/test_dnl_core_carried.py`
- Create: `tests/fixtures/aspnetcore/sca_app/` (`App.csproj`, `Directory.Packages.props`, `packages.lock.json`, `Program.cs`, `wwwroot/lib/...`, see Task 2)
- Modify: none in `checks/` or `languages/`

**Interfaces:**
- Produces in `tests/test_dnl_core_carried.py`: `SCA_APP = FX / "sca_app"`, `CARRIED_APP = FX / "carried_app"`, `_fresh` autouse fixture clearing `project._CACHE`, `_degraded(monkeypatch)`, `_dotnet(root)`, `_legacy(root)` (each `enumerator.enumerate_target(root)` filtered by `r.language`), `_ids(results)` -> `set[(check_id, file_name)]`. Same shape as the helpers in `tests/test_dotnet_core_analyzers.py`; import nothing from that module.

- [ ] **Step 1: Create the venv** if `.venv` is absent and install requirements; run `.venv\Scripts\python -m pytest -q -x tests/test_dotnet_core_analyzers.py tests/test_dnl_sca.py` to confirm the toolchain works (note the pass count in the ledger).
- [ ] **Step 2: Write `test_legacy_findings_unchanged_on_mixed_solution`.** Run `_legacy(FX / "mixed_solution")` once on the unmodified code, dump `sorted((f.check_id, f.file, f.line) for r in results for f in r.findings)` and the sorted framework list, and paste both as literals into the test as the golden value. The test asserts equality. It must pass now and in every later task.
- [ ] **Step 3: Write `test_legacy_deps_unchanged`**: `rules_sca.check` on a model of `tests/fixtures/dotnet_legacy`'s existing SCA fixture (reuse whichever fixture `tests/test_dnl_sca.py` uses) equals a golden list captured the same way.
- [ ] **Step 4: Run both** -- PASS. Commit `test: golden legacy baselines for the Core SCA and carried-family work`.

---

### Task 2: Advisory data, end-of-support table and `rules_sca_core`

**Files:**
- Modify: `checks/dnl/data/dnl_advisories.json` (new `nuget` entries; new top-level `"eol"` list and `"eol_as_of"` string)
- Modify: `checks/dnl/rules_sca.py` (only: loader tolerates the new keys, `_load` returns them unchanged for legacy; export a public `eol_table()`)
- Create: `checks/dnl/rules_sca_core.py`
- Modify: `core/owasp_web.py` (DNL-SCA-006 row, same tags as DNL-SCA-001), `languages/dotnet_legacy/README.md` (SCA-006 row, SCA table, mention Core), README rule list in `languages/dotnet/README.md` only if it lists rules
- Create fixture: `tests/fixtures/aspnetcore/sca_app/`
- Test: `tests/test_dnl_sca_core.py`

**Interfaces:**
- Consumes: `Project.packages: dict[str, str]` (lower-cased id -> version string, `""` when unresolved), `Project.target_frameworks: list[str]`, `Project.profile`, `ProjectModel.projects/iter_files/rel`, and from `rules_sca`: `_match`, `_describe`, `_parse_version`, `version_in`, `_check_js`, `_check_nuget_config`, `_check_packages`, `_check_projects`, `_advisories`, `_line_of`, `_blank_comments`.
- Produces: `rules_sca_core.check(model: ProjectModel, today: datetime.date | None = None) -> tuple[list[Finding], list[str]]` (findings, notes; `today` defaults to `datetime.date.today()`); `rules_sca_core.resolved_version(spec: str) -> tuple[str | None, str]` (version, how: `"exact"`, `"range-lower"`, or `"unresolved"`); `rules_sca_core.eol_tfms() -> set[str]` (lower-cased TFMs that are past support as of today, used by the detector in Task 3).
- Data format: `{"eol_as_of": "YYYY-MM-DD", "eol": [{"tfm": "net6.0", "eol": "YYYY-MM-DD", "source": "<lifecycle URL>"}]}`; `nuget` entries unchanged in shape (`id`, `advisory` = GHSA id, `cve`, `url` = `https://github.com/advisories/<GHSA>`, `affected`, `severity`, `summary`).

- [ ] **Step 1: Verify and add advisories (research step, no code).** For each candidate package -- `Microsoft.AspNetCore.App`/`Microsoft.AspNetCore.*` individual packages that were shipped as NuGet (e.g. `Microsoft.AspNetCore.Server.Kestrel.Core`, `Microsoft.AspNetCore.Http.Connections`, `Microsoft.AspNetCore.SignalR.*`, `Microsoft.AspNetCore.Authentication.*`), `System.Text.Json`, `Newtonsoft.Json` (existing entry stays), `Microsoft.IdentityModel.*` (`Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.IdentityModel.Protocols.OpenIdConnect`), `System.IdentityModel.Tokens.Jwt`, plus `Microsoft.Data.SqlClient`, `System.Net.Http`, `System.Text.RegularExpressions` if found -- query OSV (`POST https://api.osv.dev/v1/query` with `{"package": {"ecosystem": "NuGet", "name": "<id>"}}`, from a throwaway Python snippet in the scratchpad, not committed) and open the GHSA page for each advisory kept. Keep only advisories with a GHSA id; convert OSV ranges to the data-file range syntax (`introduced` X -> `>=X`, `fixed` Y -> `<Y`, `last_affected` Z -> `<=Z`, several events joined with `||`, an `introduced` of `0` has no lower bound); GHSA severity CRITICAL/HIGH -> `high`, MODERATE -> `medium`, LOW -> `low`; `summary` is the GHSA title. One entry per (package, advisory). Anything unverifiable (page not reachable, range ambiguous) is omitted and listed in the ledger. Record in the ledger one line per kept entry: package, GHSA, range, date verified.
- [ ] **Step 2: Verify the support dates.** From the Microsoft .NET support policy page, copy the end-of-support date of every (.NET Core 1.0, 1.1, 2.0, 2.1, 2.2, 3.0, 3.1, .NET 5, 6, 7, 8, 9, 10) release to the `eol` list under the TFMs `netcoreapp1.0` .. `netcoreapp3.1`, `net5.0` .. `net10.0` (the TFM, lower case, no suffix like `-windows`); set `eol_as_of` to the day verified. A release with no end date yet is omitted. Ledger: the source URL and the date.
- [ ] **Step 3: Write failing tests** in `tests/test_dnl_sca_core.py` against the `sca_app` fixture (`App.csproj` `Microsoft.NET.Sdk.Web`, `net6.0` + `net8.0` multi-target via `TargetFrameworks`; `Directory.Packages.props` central versions; `packages.lock.json`; `wwwroot/lib/jquery/jquery.js` with a `jQuery v3.3.1` banner and a `wwwroot/lib/bootstrap/bootstrap.js` with a current version; a copy under `bin/Debug/net8.0/wwwroot/lib/jquery/jquery.js` that must be ignored). Package references use only entries verified in Step 1 plus these unresolved shapes: one `Version="1.*"`, one `Version="$(JsonVer)"`, one with no `Version` and no central entry, one `Version="[2.0.0,3.0.0)"` on a package that has an advisory covering 2.0.0. Tests:
  - `test_vulnerable_package_direct` / `test_central_version_used` / `test_version_override_wins`: SCA-001 with the severity of the advisory, `file` = the csproj, `line` = the `PackageReference` line.
  - `test_fixed_package_clean`: a package at a fixed version yields no SCA-001.
  - `test_unresolved_versions_are_review` (Review Focus 1): exactly three DNL-SCA-006 findings, all `confidence == "REVIEW"`, severity `low`; the bracket-range package yields SCA-001 on its lower bound with "range lower bound" in the description.
  - `test_lock_file_transitive` and `test_lock_file_wins_over_csproj` (Review Focus 2): a transitive-only vulnerable entry is reported once, `file` = `packages.lock.json`, "transitive" in the description; a direct package whose csproj version is vulnerable but whose lock `resolved` is fixed yields no finding (and a note line is not required); direct vulnerable in both -> one finding.
  - `test_eol_tfm`: with `today=date(2026, 11, 16)` the multi-target project gets SCA-003 for `net6.0` (medium, message names the TFM, the end date and the source) and none for a TFM whose end date is after `today`; `test_eol_uses_injected_today`: the same project with `today=date(2020, 1, 1)` has none for `net6.0`.
  - `test_wwwroot_lib_js`: SCA-002 for the jQuery 3.3.1 file only (`wwwroot/lib/jquery/jquery.js`), none for the `bin/` copy, none for the current Bootstrap.
  - `test_data_file_entries_well_formed`: every `nuget` entry has `url == "https://github.com/advisories/" + advisory`, `advisory` matches `^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`, a range `rules_sca._range_valid` accepts, and the pair (id, advisory, affected) is unique; every `eol` entry has an ISO date, a `source` starting `https://`, and `eol_as_of` is an ISO date.
  - `test_unknown_data_keys_do_not_break_legacy`: the golden legacy tests from Task 1 still pass (run them in this task's verification).
- [ ] **Step 4: Run them to verify they fail** (`.venv\Scripts\python -m pytest tests/test_dnl_sca_core.py -q`): FAIL (module missing).
- [ ] **Step 5: Implement `resolved_version(spec)`**: strip whitespace; `1.2.3` / `[1.2.3]` -> exact; `[a,b)`, `[a,]`, `(a,b)` and a bare minimum `1.2.3` is already exact -> `range-lower` with `a` when `a` parses (NuGet restores the lowest applicable version); floating (`*`), `$(...)`, empty, unparsable -> `(None, "unresolved")`.
- [ ] **Step 6: Implement `check`.** For each project in `model.projects` with a real path and `is_sdk`: for each `(pkg, spec)` in `p.packages` locate the `PackageReference` line by text search in the csproj (`Directory.Packages.props` line when the version came from there; fall back to line 1); if a lock file next to the csproj lists the package as `Direct`/`Transitive`, use its `resolved` version and skip the csproj version; otherwise `resolved_version`. Match with `_match(_advisories()["nuget"].get(id), version)`, `_describe`, `dnl_finding("DNL-SCA-001", ...)`. Unresolved -> `DNL-SCA-006`. Lock-file entries not in `p.packages` (transitive) -> SCA-001 with "transitive" in the title and `file` = the lock path. Lock files are read with `model.iter_files((".json",))` filtered on the name `packages.lock.json` and attached to the project that owns the directory (nearest project dir; a lock file malformed or of an unknown `version` adds a note and is ignored). TFMs: for each project TFM (`p.target_frameworks`, normalised lower case, `-windows`-style suffix stripped) in the table with `eol <= today` -> `DNL-SCA-003` at the csproj `TargetFramework(s)` line. Then append `rules_sca._check_projects`, `_check_packages` (packages.config in a Core project is rare but possible), `_check_nuget_config` and `_check_js` results (these already skip `bin`/`obj`/`packages`/`node_modules` through `iter_dnl_files`, and `wwwroot/lib` matches `_BUNDLE_DIRS` through `lib`; add `wwwroot` itself is not needed). Notes: advisory-data problems exactly as `rules_sca.check` reports them, plus one note stating `eol_as_of`.
- [ ] **Step 7: Implement `eol_tfms()`** and run the tests: PASS. Add the SCA-006 `RULES` row and README rows (SCA-006, plus widen the SCA-001/-003 wording to name `PackageReference`). Run `tests/test_owasp_web.py tests/test_owasp_readme.py tests/test_dnl_sca.py` -- PASS (if a table-count test fails only because the ids list changed, update that expectation and add a ledger line).
- [ ] **Step 8: Commit** `feat(dotnet): offline SCA for SDK projects (PackageReference, lock file, EOL frameworks, wwwroot libs)`.

---

### Task 3: `deps` analyzer for `dotnet`, detector, owner fix

**Files:**
- Modify: `languages/dotnet/analyzers.py` (new `DepsAnalyzer`; `_KINDS`, `owner_of` and `fallback` exclude `deps`), `languages/dotnet/detector.py` (`_FRAMEWORK_ORDER` gains `deps` last; detection), `languages/dotnet/README.md` (frameworks line only)
- Test: `tests/test_dnl_sca_core.py` (end-to-end part), `tests/test_dotnet_core_analyzers.py` only if an existing detector assert lists frameworks (then add `deps` where the fixture qualifies and ledger it)

**Interfaces:**
- Consumes: `rules_sca_core.check`, `rules_sca_core.eol_tfms`.
- Produces: `@register("dotnet", "deps")` `DepsAnalyzer` (no routes; findings from `rules_sca_core.check(self.model)`, a crash is caught like the legacy one and becomes a note); `detector.detect_frameworks` returns `deps` for a scan with a netcore project that has package references, or a `packages.lock.json` it owns, or JS under `wwwroot/lib` (any dir part named `lib`/`libs`/`scripts`/`content` below the project dir), or a TFM in `rules_sca_core.eol_tfms()`.

- [ ] **Step 1: Failing tests.** `test_detector_registers_deps` (sca_app -> frameworks end with `["...", "config", "deps"]`; `controllers_api` fixture, which has no packages, gets `deps` only if it has a PackageReference or an EOL TFM -- assert by reading its csproj, not by hard-coding; a netcore project with `net8.0`, no packages, no lock file, no wwwroot and a non-EOL TFM does not get it, using a `tmp_path` project); `test_deps_end_to_end`: `enumerator.enumerate_target(SCA_APP)` has a `dotnet`/`deps` result with the SCA ids above, no routes, and `result.degraded` equal to the model's; `test_route_less_findings_never_go_to_deps`: with `controllers` and `deps` both running, a route-less AUTHZ finding on the `controllers_api` fixture lands in `config`, never `deps` (this needs `owner_of` and `fallback` to skip `deps`); `test_mixed_solution_each_file_once`: on `mixed_solution` (add a `Modern/wwwroot/lib/jquery/jquery.js` vulnerable banner file and a `Framework/Scripts/jquery.js` one, both in the fixture) legacy `deps` reports only the `Framework` copy and `dotnet` `deps` only the `Modern` copy (Review Focus 4), and the Task 1 golden test is updated in the same commit ONLY by the new legacy line for the added Framework file (record the old/new lines in the ledger).
- [ ] **Step 2: Run to verify they fail**, **Step 3: implement** (`DepsAnalyzer` mirrors `languages/dotnet_legacy/analyzers.py::DepsAnalyzer`; `_running` must report it when detected; `owner_of`'s fallback `next(k for k in running if k != "config")` and `fallback` become `... not in ("config", "deps")`), **Step 4: run** the new tests plus `tests/test_dotnet_core_analyzers.py tests/test_dnl_detect.py` -- PASS.
- [ ] **Step 5: Commit** `feat(dotnet): deps analyzer and detector registration`.

---

### Task 4: Carried families, part 1 -- crypto, deserialization/XXE, integrity

**Files:**
- Modify: `languages/dotnet/analyzers.py` (`_code_results`: `guarded("rules_crypto", ...)`, `rules_deser_xml`, `rules_integrity`), module files in `checks/dnl/` only for Core gaps found by the tests
- Create fixture: `tests/fixtures/aspnetcore/carried_app/` (`CarriedApp.csproj` `Microsoft.NET.Sdk.Web` net8.0; `Program.cs` top-level; `Controllers/*.cs`; `Views/Shared/_Layout.cshtml`; `Views/Home/Index.cshtml`; `Web.config` stub, see Task 6; `Directory.Build.props` not needed)
- Test: `tests/test_dnl_core_carried.py`

**Interfaces:**
- Consumes: Task 1 helpers; `routes_core.discover_all(model)` returns `CoreRouteRef`s (`.route`, ...). The legacy modules take `refs` of the legacy `RouteRef` shape: for each module, read how it uses `refs` (route association by `ref.route`, `ref.type`, `meta["kind"]`...) and either pass the Core refs unchanged when the module only needs `.route`, or fix the module to accept both. Do NOT duplicate module logic.
- Produces: each wired module's findings flow through the existing owner logic (`owner_of` for routed, `fallback` for route-less); the fixture files named below are consumed again in Tasks 5 and 6.

Fixture content (each family has a positive class/method and a negative twin; names generic):
- crypto: `Crypto/WeakCrypto.cs` (MD5 `HashPassword`, `DES`/`TripleDES`, `AesCryptoServiceProvider` with `CipherMode.ECB`, hardcoded key literal, `new Random()` for a token, `SHA1`, `RSA` with 1024-bit key size) and `Crypto/SafeCrypto.cs` (`SHA256`, `RandomNumberGenerator`, `Aes.Create()` with GCM-style `AesGcm`, `Rfc2898DeriveBytes.Pbkdf2` with 600000 iterations). Positive expectations: whichever `DNL-CRY-00x` ids the module reports for these constructs on legacy (the implementer reads `rules_crypto` and `tests/test_dnl_crypto.py` to pick constructs per id; every CRY id that is not System.Web-specific gets one positive).
- deserialization/XXE: `Deser/UnsafeDeser.cs` (`BinaryFormatter.Deserialize`, Newtonsoft `JsonConvert.DeserializeObject` with `TypeNameHandling.All` in `JsonSerializerSettings`, `new JavaScriptSerializer(new MyResolver())`, `XmlDocument` with `XmlResolver = new XmlUrlResolver()`, `XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }`) and `Deser/SafeDeser.cs` (`System.Text.Json.JsonSerializer.Deserialize<T>`, Newtonsoft with `TypeNameHandling.None`, `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }`, `XmlDocument { XmlResolver = null }`).
- integrity: `Views/Shared/_Layout.cshtml` with `<script src="https://cdn.example.test/lib.js">` without `integrity` (positive) and one with `integrity="sha384-..." crossorigin="anonymous"` (negative), plus `<script src="~/lib/local.js">` (never flagged).

- [ ] **Step 1: Write the failing tests**, one pair per family: `test_crypto_findings_on_core` (set of `(id, file)` for the positive file equals the expected ids; `SafeCrypto.cs` yields no CRY finding), `test_deser_xxe_findings_on_core`, `test_integrity_sri_on_core` (INT-003 on `_Layout.cshtml` for the CDN script without integrity, none for the other two, line numbers asserted), and `test_no_failed_notes`: no `result.notes` entry contains `failed (` for any dotnet result on the fixture. Each asserts the positive ids explicitly (written from the legacy tests' expectations for the same constructs) so a rule that stays silent on Core fails the test. A positive that is name-only (Newtonsoft) must be asserted at the same severity legacy gives it.
- [ ] **Step 2: Run to verify they fail.**
- [ ] **Step 3: Wire the three modules** into `_code_results` after `rules_auth_core`, each in `guarded(name, lambda: module.check(model, refs))`. Then run the tests, and for each missing finding fix the Core gap in the module (usually a System.Web-only name table, a `.cshtml` path assumption, or a `refs` attribute); each fix gets its own sub-assert in the family test. A construct that is System.Web-only (`FormsAuthentication`, `MachineKey`, `HttpContext.Current`) stays out of the Core fixture and is listed in `languages/dotnet/CARRIED_RULES.md` (created here: a table `family | ids | runs on Core | reason`, one row per family; Plan 4b merges it into the dotnet README).
- [ ] **Step 4: Run** the family tests, `tests/test_dnl_crypto.py tests/test_dnl_deser_xml.py tests/test_dnl_integrity_session.py tests/test_dnl_end_to_end.py` and the Task 1 goldens -- PASS.
- [ ] **Step 5: Commit** `feat(dotnet): run crypto, deserialization/XXE and integrity rules on SDK projects`.

---

### Task 5: Carried families, part 2 -- errors, logging/flows/resources/inventory/consumption, session

**Files:**
- Modify: `languages/dotnet/analyzers.py` (`rules_errors`, `rules_misc`, `rules_session`), `checks/dnl/` modules only for Core gaps
- Extend fixture: `carried_app` (`Controllers/ErrorsController.cs`, `Controllers/FlowsController.cs`, `Services/Logging.cs`, `Services/Outbound.cs`, `Controllers/UploadController.cs`, `Controllers/SessionController.cs`)
- Test: `tests/test_dnl_core_carried.py`

**Interfaces:**
- Consumes: Task 4's wiring pattern and fixture. `rules_misc.check(model, refs, configs) -> (findings, notes)`: on Core it is called with `configs=()` (**Web.config-only checks stay legacy-only**: no `load_configs`), and its notes are merged exactly as the legacy analyzer does (`misc_notes`).
- Produces: wired modules; `CARRIED_RULES.md` rows.

Fixture constructs (positive + negative twin per id the module can emit; the implementer reads `tests/test_dnl_errors.py`, `tests/test_dnl_misc_rules.py`, `tests/test_dnl_integrity_session.py` for the construct list and ports the C# generic-framework ones to Core idioms: `ILogger<T>`, `IActionResult`, `HttpClient`/`IHttpClientFactory`, `IFormFile`, `Session.SetString`, `CookieOptions`):
- errors: swallowed `catch {}`, `return Ok(ex.ToString())`/`ex.StackTrace` to the client (ERR), `catch (Exception) { return Ok(); }`, with negatives that log and return `Problem()`.
- logging: password/token interpolated into `_logger.LogInformation($"...{password}")` (LOG-003), login action without any failure logging (LOG-002 / LOG-004 per rule), negatives using templates and logging the failure.
- flows/consume: `HttpClient.GetStringAsync(url)` result trusted/deserialized without validation (CONSUME-001), redirect-following or no-timeout outbound client (CONSUME-002), business-flow endpoints without throttling per `DNL-DES-001`.
- resources: `IFormFile` copied without a size check (RES-003), unbounded list endpoint with `int pageSize` (RES-002), `UseSwagger()` outside a development guard (INV-002; only if Plan 3's Core swagger rule does not already own it -- read `rules_resources.check_inv002` and, if it depends on Web.config denial, restrict the Core positive to the code path).
- session: `rules_session` ids that apply to Core idioms (`CookieOptions { HttpOnly = false }`, session id from request, `FormsAuthentication`-style items excluded). Rules that cannot fire on Core are listed in `CARRIED_RULES.md` with the reason.

- [ ] **Step 1: Write the failing tests** (`test_errors_findings_on_core`, `test_logging_findings_on_core`, `test_flows_consume_on_core`, `test_resources_inventory_on_core`, `test_session_on_core`), each asserting positives by `(id, file, line)` and negatives absent. For each rule id that has no Core positive the test file carries a single `EXCLUDED = {"DNL-SESS-00x": "System.Web only: ..."}` dict with a reason, asserted non-empty per entry (so exclusions are explicit).
- [ ] **Step 2: Run to verify they fail**; **Step 3: wire and fix Core gaps** as in Task 4; keep every module change guarded by a test and make sure the legacy tests (`tests/test_dnl_errors.py tests/test_dnl_misc_rules.py tests/test_dnl_integrity_session.py tests/test_dnl_resources*.py` if present) and the Task 1 goldens still pass.
- [ ] **Step 4: Crash isolation test** (Review Focus 5): `test_one_crashing_module_does_not_hide_others`: monkeypatch `checks.dnl.rules_errors.check` to raise `RuntimeError("boom")`, clear the cache, enumerate `CARRIED_APP`: the result notes contain `rules_errors failed (RuntimeError: boom)` and the crypto findings from Task 4 are still present.
- [ ] **Step 5: Run and commit** `feat(dotnet): run error, logging, flow, resource, inventory and session rules on SDK projects`.

---

### Task 6: Degraded parity, Web.config guard, final verification

**Files:**
- Test: `tests/test_dnl_core_carried.py`
- Modify: `languages/dotnet/CARRIED_RULES.md`; `checks/dnl/` modules only for gaps these tests expose
- Create fixture: `carried_app/Web.config` (IIS `aspNetCore` hosting stub plus legacy `<system.web><compilation debug="true"/><httpRuntime enableVersionHeader="true"/><customErrors mode="Off"/></system.web>` and `<system.webServer><httpErrors errorMode="Detailed"/></system.webServer>`), `tests/fixtures/aspnetcore/web_config_only_core/` (`App.csproj`, `Program.cs` and a `Web.config` with only the hosting stub)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Web.config guard** (Review Focus 3): `test_web_config_checks_do_not_run_on_core`: on `carried_app` and `web_config_only_core`, no `dotnet` finding has a `check_id` starting `DNL-CFG-` or `DNL-WCF-` and none has `file` ending in `Web.config`; no note contains `failed (` ; `test_legacy_still_reads_web_config_in_mixed_solution`: the legacy side of `mixed_solution` still reports its Web.config findings (covered by the Task 1 golden).
- [ ] **Step 2: Degraded parity.** `test_degraded_parity_per_family`: run `CARRIED_APP` and `SCA_APP` with the helper (the `roslyn_helper` fixture) and with `_degraded(monkeypatch)`; compute `{(check_id, file)}` per family prefix (SCA, CRY, DESER/DES/XXE, INT, ERR, LOG/CONSUME/DES, RES/INV, SESS). Assert: the SCA and INT sets are identical (text scans); for every other family the degraded set is a subset of the helper set and equal outside `JUSTIFIED_DEGRADED = {id: reason}` (a dict at the top of the test, each reason a non-empty string naming the symbol the id needs); a degraded finding that has no helper counterpart fails the test; `result.degraded` is True and a degraded note is present on every dotnet result. If a family differs only in confidence (REVIEW in degraded), compare ids and files, and add a separate assert that the degraded confidence is never higher than the helper's.
- [ ] **Step 3: Fix** whatever the parity test exposes in the modules (each fix with its own assertion) or justify it in `JUSTIFIED_DEGRADED` and `CARRIED_RULES.md`.
- [ ] **Step 4: Final verification.** Full suite `.venv\Scripts\python -m pytest -q` -- all pass (count in the ledger). `git diff <plan-base>..HEAD --stat` shows no edits under `languages/dotnet_legacy/` other than README rows and no edits to existing legacy tests other than the one golden line from Task 3. Grep the diff for em-dashes, `C:\`, `/home/`, `Users`, and any real-looking company, client or host names; fix any hit. If `docker info` reports a running server (not just the client), build and run the existing container smoke step used by Plan 1 (see `tools/` and the Plan 1 Task for the Linux run) once; otherwise record "Linux container not run: daemon not running".
- [ ] **Step 5: Commit** `test(dotnet): degraded parity and Web.config guard for carried families`.

---

## Self-review (spec coverage)

- SCA: package references and central versions (T2), advisory extension with verification (T2 Step 1), EOL table (T2 Step 2/6), lock file (T2), `wwwroot/lib` (T2/T3), `deps` analyzer + detector (T3), ids reused/new with OWASP and README rows (T2).
- Carried families: crypto/deser/XXE/integrity (T4), errors/logging/flows/resources/inventory/consumption/session (T5), Web.config-only and System.Web-only exclusions with reasons (T4-T6, `CARRIED_RULES.md`), legacy unchanged (T1 goldens, T3 note).
- Degraded mode for these families (T6). Decision 8 (taint degraded) is not here.
- Out of scope respected: no coverage test, acceptance, README table or docs pass.

## Ledger

Every ruling and measured fact is appended here by the controller during execution, one `Ruling:` line each.

- Ruling: unresolvable package versions are reported (DNL-SCA-006, low, REVIEW) rather than skipped, to avoid a false "safe".
- Ruling: end-of-support target frameworks reuse DNL-SCA-003 (same check as legacy .NET Framework below 4.6.2); the table is dated (`eol_as_of`) and compared with the run date.
- Ruling: `rules_misc` runs on Core with no Web.config configs; Web.config-only checks stay legacy-only.
- Ruling: the lock file's `resolved` version is authoritative over the csproj version for the same package.
- Ruling: `deps` for `dotnet` is also registered for a project whose TFM is past end of support, so an old framework with no package references is still reported.
