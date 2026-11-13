# dotnet_legacy WCF, Crypto, Deserialization, XXE, Integrity Plan (Plan 3 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add WCF services (operations as routes with effective auth, binding/behavior misconfiguration), crypto and hardcoded-secret rules in code, insecure deserialization, XXE, integrity (SRI, ViewState MAC in page directives) and session/auth code rules to the `dotnet_legacy` analyzer, each tagged with OWASP 2025 / 2021 / API 2023.

**Architecture:** WCF operations become `RouteRef`s (kind `wcf`, api_surface) so the existing auth rules, taint engine and object rules apply to them unchanged. web.config `<system.serviceModel>` is evaluated by a new config rule module on the existing `webconfig` loader. Code-shape rules (crypto, secrets, deserializer configuration, XML parser configuration, session flows) run over the IR in new `rules_*` modules; where input matters (deserialize/XML-load of request data) new taint sink kinds `deser` and `xxe` make findings proven, otherwise they are configuration findings.

**Tech Stack:** Python 3.10+, pytest; existing Roslyn helper (no helper changes expected).

**Spec:** `docs/superpowers/specs/2026-11-11-dotnet-legacy-design.md` (WCF, XXE, DESER, INT, SESS/AUTH, CRY, SEC rows of the rule catalog). Plans 1 and 2 are done.

**Checkpoints:** 3a = Tasks 1-3 (WCF routes+auth, WCF config, crypto+secrets). 3b = Tasks 4-6 (deserialization+XXE, integrity+session/auth code, wrap-up).

## Global Constraints

- Public repo: nothing committed (code, fixtures, tests, README, docs, commit messages) may name a client, engagement, target app, local path or user. Fixtures are synthetic. Real-target scan outputs go outside the repo.
- Prose and comments use `--`, never em-dashes; comment density like `checks/tf_graph.py`.
- Tests: `.venv\Scripts\python -m pytest -q` from the repo root (Windows) -- baseline 638 passing; must also pass on Linux.
- VB identifiers case-insensitive everywhere.
- Every new rule id gets a `core/owasp_web.RULES` entry and a README row (enforced by the README test) in the task that adds it.
- Severity `high | medium | low | info`; `confidence="REVIEW"` when a human must decide. A false "safe" is the worst outcome; noise is secondary.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Branch `feature/dotnet-legacy-wcf-crypto`.

## New rule ids (added in the task that implements them)

| id | sev | 2025 | 2021 | API (mode) | what |
|---|---|---|---|---|---|
| DNL-WCF-001 | high | A02 | A05 | API8 | binding used by a non-local endpoint has `security mode="None"` (or Transport/Message with `clientCredentialType="None"` where the endpoint is not https) |
| DNL-WCF-002 | medium | A02 | A05 | API8 | `serviceDebug includeExceptionDetailInFaults="true"` |
| DNL-WCF-003 | low | A02 | A05 | API9 (always) | metadata exposed: `serviceMetadata httpGetEnabled/httpsGetEnabled="true"` or an `IMetadataExchange` (mex) endpoint |
| DNL-WCF-004 | low | A06 | A04 | API4 | `maxReceivedMessageSize`/`maxBufferSize` > 10485760, or `readerQuotas maxStringContentLength/maxArrayLength` > 10485760, or no `serviceThrottling` on a service behavior used by an endpoint |
| DNL-CRY-001 | medium (high when hashing a password) | A04 | A02 | -- | MD5/SHA1 (`MD5.Create`, `MD5CryptoServiceProvider`, `SHA1Managed`, `SHA1.Create`, `HashPasswordForStoringInConfigFile(x, "MD5"/"SHA1")`) |
| DNL-CRY-002 | high | A04 | A02 | -- | DES/3DES/RC2 (`DESCryptoServiceProvider`, `TripleDES*`, `RC2*`, `DES.Create`) |
| DNL-CRY-003 | high | A04 | A02 | -- | `CipherMode.ECB` assigned to `.Mode` |
| DNL-CRY-004 | high | A04 | A02 | -- | constant key/IV: byte-array literal or `Encoding.*.GetBytes("literal")` / `Convert.FromBase64String("literal")` assigned to `.Key`/`.IV` or passed to `CreateEncryptor/CreateDecryptor` |
| DNL-CRY-005 | medium REVIEW | A04 | A02 | -- | `System.Random` (`new Random`, `.Next*`) whose result flows into a variable/field/return of a method named like `token|password|salt|otp|nonce|secret|key|code|reset` |
| DNL-CRY-006 | high | A08 | A08 | API10 (always) | certificate validation disabled: `ServerCertificateValidationCallback` assigned a lambda/method returning `true` unconditionally |
| DNL-CRY-007 | medium | A04 | A02 | -- | `ServicePointManager.SecurityProtocol` set to include `Ssl3`, `Tls` (1.0) or `Tls11` |
| DNL-CRY-008 | medium | A04 | A02 | -- | `PasswordDeriveBytes`, or `Rfc2898DeriveBytes` with a constant iteration count < 10000 (default 1000 counts as < 10000) |
| DNL-SEC-003 | high | A07 | A07 | API2 | hardcoded credential in code: string literal (length >= 4, not a placeholder) assigned to a local/field/property/named arg whose name matches the SEC-002 key pattern (same `_is_setting_key` exclusions), or as the password argument of `new NetworkCredential(u, "lit")`, `new DirectoryEntry(path, u, "lit")`, `new SqlConnection/SqlConnectionStringBuilder` connection strings containing `Password=`/`Pwd=` literal |
| DNL-DESER-001 | high proven / medium REVIEW | A08 | A08 | -- | `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter` `.Deserialize`/`.ReadObject` -- proven (taint sink kind `deser`) when the stream/string is request-derived, otherwise REVIEW (dangerous formatter in use) |
| DNL-DESER-002 | high | A08 | A08 | -- | Json.NET `TypeNameHandling` set to anything but `None` (settings object property, `JsonSerializerSettings` initializer, `[JsonProperty(TypeNameHandling=...)]`) |
| DNL-DESER-003 | high | A08 | A08 | -- | `new JavaScriptSerializer(new SimpleTypeResolver())` |
| DNL-XXE-001 | high proven / medium | A02 | A05 | API8 | XML parsing that resolves DTDs/external entities: `XmlDocument` with `XmlResolver` set to non-null (or never set when the owning project targets < v4.5.2), `XmlTextReader` without `DtdProcessing = Prohibit/Ignore` (or `ProhibitDtd = true`), `XmlReaderSettings` with `DtdProcessing = Parse` (and `XmlResolver` not null), `XPathDocument`/`XmlReader.Create` over such settings -- proven (taint sink kind `xxe`) when the loaded content/stream/path is request-derived |
| DNL-XXE-002 | low | A02 | A05 | API8 | project targets .NET Framework < v4.5.2 and parses XML anywhere (insecure parser defaults) |
| DNL-INT-003 | medium | A08 | A08 | -- | `<script src>`/`<link rel="stylesheet" href>` to an absolute external host (`http(s)://` or `//`, not the app's own relative paths) without an `integrity` attribute, in .cshtml/.vbhtml/.master/.aspx/.ascx/.html |
| DNL-INT-004 | high | A08 | A08 | -- | page/control directive `EnableViewStateMac="false"`; `ViewStateEncryptionMode="Never"` is low |
| DNL-SESS-006 | low REVIEW | A07 | A07 | API2 | logout action/handler (name matches `logout|logoff|signout`) that calls `FormsAuthentication.SignOut`/`AuthenticationManager.SignOut` but never `Session.Abandon`/`Session.Clear` |
| DNL-SESS-007 | low REVIEW | A07 | A07 | API2 | login flow (calls `FormsAuthentication.SetAuthCookie`/`RedirectFromLoginPage`/`AuthenticationManager.SignIn`) that never abandons the session or regenerates the session cookie (`Session.Abandon`, `SessionIDManager.CreateSessionID`/`SaveSessionID`, clearing `ASP.NET_SessionId`) |
| DNL-SESS-008 | medium REVIEW | A07 | A07 | API2 | plaintext password comparison: `==`/`!=`/`Equals`/`String.Compare` where one operand's name (local/field/property/member) matches `(?i)pass(word)?|pwd` and neither side is passed through a hash/verify call (`Crypto.VerifyHashedPassword`, `PasswordHasher`, `*Hash*`, `*Verify*`, `BCrypt.*`) |

AUTHZ rules from Plan 1 apply to WCF routes unchanged (DNL-AUTHZ-001 for an operation with no effective auth).

## Review Focus

1. A WCF service declared through `<serviceActivations>` or a `.svc` with `Factory=` and no `Service=` match must still produce routes, or a scan note when the implementation can't be resolved (test in Task 1).
2. web.config with several services/bindings sharing a binding name across binding types (`basicHttpBinding` and `wsHttpBinding` both have a `name="Default"`) resolves each endpoint to the right binding element (test in Task 2).
3. A crypto object created in one method and configured/used in another (field `_aes`, `.Mode = CipherMode.ECB` in the constructor, encrypt in a method) is still flagged (test in Task 3).
4. `TypeNameHandling` set via a settings object passed into `JsonConvert.DeserializeObject(json, settings)` from another method or a static field (test in Task 4).
5. Layout pages inherited by every view: one finding per offending tag (not per view), and app-relative `~/` or `/` paths never flagged (test in Task 5).

---

### Task 1: WCF routes, effective auth, taint entry points

**Files:**
- Modify: `languages/dotnet_legacy/detector.py` (`_FRAMEWORK_ORDER` gains `wcf` after `webforms`; `wcf` detected when any `.svc` exists or a qualifying web.config has `<system.serviceModel>`), `checks/dnl/routes.py` (`discover_wcf`), `checks/dnl/auth.py` (`resolve_wcf`), `checks/dnl/rules_auth.py` (route kind `wcf` handled), `languages/dotnet_legacy/analyzers.py` (`@register("dotnet_legacy", "wcf")`; `_code_results` includes WCF refs in auth, taint, xss, object rules)
- Create fixture: `tests/fixtures/dotnet_legacy/wcf_app/` -- legacy C# project `WcfSvc/WcfSvc.csproj` (refs System.ServiceModel, System.Runtime.Serialization), `OrderService.svc` (`<%@ ServiceHost Service="WcfSvc.OrderService" %>`), `IOrderService.cs` (`[ServiceContract]` with `[OperationContract] string Find(string term)`, `void Delete(int id)`), `OrderService.cs` implementing it (Find builds SQL from `term`; Delete has `[PrincipalPermission(SecurityAction.Demand, Role = "Admin")]`), `Web.config` with `<system.serviceModel>` (used in Task 2 too) and `<serviceHostingEnvironment><serviceActivations><add relativeAddress="Billing.svc" service="WcfSvc.BillingService"/></serviceActivations>`; `BillingService.cs` + `IBillingService.cs`; a VB variant service optional.
- Test: `tests/test_dnl_wcf.py`

**Interfaces:**
- `routes.discover_wcf(model) -> list[RouteRef]` -- one ref per operation: `.svc` files (directive `Service=` case-insensitive, quotes/multiline like page directives; `Factory=` with no resolvable Service -> scan note `"<rel>: WCF service type not resolved (Factory=...)"`) plus `<serviceActivations>` entries. Implementation type -> its interfaces carrying `[ServiceContract]` (or the class itself when it carries `[ServiceContract]`) -> methods with `[OperationContract]` -> the implementing method on the service type (same name + arity; base chain). Route: `path = "/<svc relative path>/<OperationName>"` (`OperationContract(Name=...)` wins over the method name), `methods = ["POST"]`, `handler_name = "<ServiceType>.<Method>"`, `file/line` = implementing method, `source_*` = its range, `meta = {"kind": "wcf", "api_surface": True, "contract": "<interface full name>", "svc": "<rel>"}`.
- `auth.resolve_wcf(model, ref, configs) -> AuthInfo` order: `[PrincipalPermission(SecurityAction.Demand, ...)]` with Role/Name/Authenticated=true on the method or service class -> protected (`attribute:PrincipalPermission`, roles); `PrincipalPermission.Demand()` call or `Thread.CurrentPrincipal.IsInRole`/`ServiceSecurityContext.Current` check gating the body (reuse the hand-rolled gating logic: review=True, R17 low REVIEW finding); a `serviceAuthorization` behavior with `serviceAuthorizationManagerType` or `principalPermissionMode="UseAspNetRoles|UseWindowsGroups"` plus a binding whose effective `clientCredentialType` is not `None` -> protected (`source "wcf binding/behavior"`, review=True); web.config `<authorization>` deny on the .svc path with `aspNetCompatibilityEnabled="true"` -> `web.config`; else `none`.
- Taint: `taint_solver.entry_hits` treats `kind == "wcf"` refs like Web API actions (operation params are request-controlled, same safe-type exclusions), so existing injection/XSS/SSRF/IDOR rules report on WCF operations without further changes; verify with a test that `OrderService.Find` yields a proven DNL-INJ-001 on the WCF route.

- [ ] **Step 1: Failing tests**

```python
def test_wcf_operations_become_routes(refs):
    p = {(r.route.handler_name, r.route.path) for r in refs if r.route.meta["kind"] == "wcf"}
    assert ("OrderService.Find", "/OrderService.svc/Find") in p and ("BillingService.Charge", "/Billing.svc/Charge") in p
    assert all(r.route.meta["api_surface"] for r in refs if r.route.meta["kind"] == "wcf")

def test_principal_permission_protects(wcf_auth):
    assert wcf_auth["OrderService.Delete"].protected and wcf_auth["OrderService.Delete"].roles == ["Admin"]
    assert not wcf_auth["OrderService.Find"].protected

def test_unprotected_operation_flagged(findings):
    f = one(findings, "DNL-AUTHZ-001", "OrderService.Find")
    assert f.route.meta["kind"] == "wcf" and f.owasp["api2023"].startswith("API5:2023")

def test_wcf_param_taint_reaches_sql(findings):
    f = one(findings, "DNL-INJ-001", file_endswith="OrderService.cs")
    assert f.confidence is None and f.route.handler_name == "OrderService.Find"

def test_unresolved_factory_is_noted(wcf_model):
    # Ghost.svc: <%@ ServiceHost Factory="X.Factory" Service="Nope.Missing" %> -- no type in the model
    refs = discover_wcf(wcf_model)
    assert not [r for r in refs if r.route.meta["svc"].endswith("Ghost.svc")]
    assert any("Ghost.svc: WCF service type not resolved" in n for n in wcf_model.notes)
```

- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run** file + full suite, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: WCF operations as routes with effective auth and taint entry points"`

---

### Task 2: WCF configuration rules

**Files:**
- Create: `checks/dnl/rules_wcf_config.py`
- Modify: `core/owasp_web.py` (DNL-WCF-001..004), `languages/dotnet_legacy/README.md` (rows), `languages/dotnet_legacy/analyzers.py` (config analyzer also runs `rules_wcf_config.check_configs`)
- Extend fixture `wcf_app/WcfSvc/Web.config` (and a Release transform) so each rule has a positive and a safe counterpart.
- Test: `tests/test_dnl_wcf_config.py`

**Interfaces:**
- `rules_wcf_config.check_configs(configs: list[WebConfig]) -> tuple[list[Finding], list[str]]` -- uses `webconfig.effective()` per variant and the same transform-aware merge as `rules_config` (reuse its merge helper; do not duplicate it -- extract a shared function into `rules_config` if needed). Views configs skipped.
- Binding resolution: `endpoint@binding` (type) + `endpoint@bindingConfiguration` (name) -> `bindings/<type>/binding[@name]`; missing `bindingConfiguration` -> the type's default (unnamed) binding element, else the framework default (`basicHttpBinding` default security mode None; `wsHttpBinding` default Message). Endpoints with `address` starting `net.pipe://` or `localhost`/`127.0.0.1` are local and exempt from WCF-001. Behaviors: `service@behaviorConfiguration` -> `behaviors/serviceBehaviors/behavior[@name]`, missing -> the unnamed default behavior.
- Rules as in the table. WCF-001 anchors on the binding element (or the endpoint when the default applies); WCF-003 always tags API9; WCF-004 one finding per offending binding/behavior.

- [ ] **Step 1: Failing tests** -- per rule: positive and safe counterpart; `test_binding_name_shared_across_types` (Review Focus 2); `test_local_endpoint_exempt`; `test_default_basichttp_is_none` (no bindingConfiguration on a basicHttpBinding endpoint -> WCF-001 at the endpoint); transform: a Release transform setting `includeExceptionDetailInFaults="false"` turns WCF-002 to info (R3 semantics as in rules_config).
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: WCF binding and behavior configuration rules"`

---

### Task 3: Crypto and hardcoded secrets in code (end of 3a)

**Files:**
- Create: `checks/dnl/rules_crypto.py`
- Modify: `core/owasp_web.py` (DNL-CRY-001..008, DNL-SEC-003), README rows, `languages/dotnet_legacy/analyzers.py` (`_code_results` runs `rules_crypto.check(model)`; route-less findings via `_owner_kind`)
- Create fixture: `tests/fixtures/dotnet_legacy/taint_app/TaintCs/Crypto/*.cs` and one VB file in `TaintVb` -- one positive and one safe case per rule (e.g. `Aes` with random IV vs constant IV; `RNGCryptoServiceProvider` token vs `Random` token; `SHA256` vs `MD5` password hash; callback with a real chain check vs `=> true`; `SecurityProtocol = Tls12` vs `Tls | Tls11`; `Rfc2898DeriveBytes(pw, salt, 100000)` vs `(pw, salt)`; credential from config vs literal).
- Test: `tests/test_dnl_crypto.py`

**Interfaces:**
- `rules_crypto.check(model) -> list[Finding]` -- walks every method/accessor body (and field initializers) of legacy-project types. Type identification `sym`-first (`type_full` / call `sym` on `System.Security.Cryptography.*`, `System.Net.ServicePointManager`, `System.Net.NetworkCredential`, `System.DirectoryServices.DirectoryEntry`, `System.Web.Security.FormsAuthentication`), then source-written type names as fallback.
- Object state across methods (Review Focus 3): track, per type, fields/properties holding crypto objects (field type or initializer type) and assignments to `.Mode`/`.Key`/`.IV` on them in any method of the type (constructor included).
- CRY-001 password context: the hashed input expression or the enclosing method/variable name matches `(?i)pass(word)?|pwd` -> high, else medium.
- CRY-005 uses the taint engine's local value flow is NOT required -- a syntactic check suffices: a `Random` instance's `Next*`/`NextBytes` result assigned (directly or through string building in the same method) to a variable/field/return whose name, or the enclosing method name, matches the pattern in the table.
- CRY-006: lambda body returns literal `true` on every path (reuse `auth._is_true`-style literal check), or a method group whose method returns literal `true` on every path; also `ServicePointManager.CertificatePolicy` set to a type whose `CheckValidationResult` returns literal true.
- SEC-003 reuses `rules_config._is_setting_key` and the placeholder regex (import, don't copy).
- Findings carry `route=None` unless the code is inside a route handler (then attach the route and its api_surface).

- [ ] **Step 1: Failing tests** -- one positive + one negative per rule (`hits(findings, id, file_endswith=...)`), plus `test_crypto_state_across_methods` (Review Focus 3), `test_vb_md5_password_high`, `test_sec003_ignores_placeholders_and_setting_keys`.
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: crypto and hardcoded-credential rules in code"`

---

### Task 4: Insecure deserialization and XXE (start of 3b)

**Files:**
- Create: `checks/dnl/rules_deser_xml.py`
- Modify: `checks/dnl/taint_tables.py` (new sink kinds `deser` -- the stream/string argument of `BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter` `.Deserialize`/`ReadObject` and of `JsonConvert.DeserializeObject`/`JsonSerializer.Deserialize` when TypeNameHandling is unsafe is NOT a taint concern -- keep `deser` for the dangerous formatters only; and `xxe` -- the content/path/stream argument of `XmlDocument.Load|LoadXml`, `XmlTextReader..ctor`, `XmlReader.Create`, `XPathDocument..ctor`, `DataSet.ReadXml`, `XDocument.Load`/`XElement.Load` when given an `XmlReader` built from insecure settings), `checks/dnl/rules_taint.py` (`RULE_FOR_KIND`: `deser` -> DNL-DESER-001, `xxe` -> DNL-XXE-001; labels "Insecure deserialization", "XML external entity (XXE)"), `core/owasp_web.py` (DESER-001..003, XXE-001..002), README rows, analyzers wiring.
- Extend fixture `taint_app`: formatter deserializing `Request.InputStream` (proven) and a file stream (REVIEW); `JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }` in a static field passed to `DeserializeObject` from another method (Review Focus 4) vs `TypeNameHandling.None`; `JavaScriptSerializer(new SimpleTypeResolver())` vs default ctor; `XmlDocument { XmlResolver = new XmlUrlResolver() }.LoadXml(Request.Form["x"])` (proven) vs `XmlResolver = null`; `XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }` vs `Prohibit`; a second small legacy project targeting `v4.0` that uses `XmlDocument` without setting a resolver (XXE-001 config-shape + XXE-002).
- Test: `tests/test_dnl_deser_xml.py`

**Interfaces:**
- `rules_deser_xml.check(model, refs) -> list[Finding]` -- config-shape findings: DESER-001 REVIEW (formatter used, input not proven -- suppressed for a sink that already has a proven taint finding at the same file/line), DESER-002, DESER-003, XXE-001 (insecure parser configuration, not proven -> medium), XXE-002 (one per project). Track settings objects across methods and static fields within the solution (Review Focus 4): a settings value is unsafe if any assignment/initializer on it sets `TypeNameHandling` to a value other than `None`; a call `DeserializeObject(..., settings)` / `JsonSerializer.Create(settings)` / `new JsonSerializer { TypeNameHandling = ... }` with an unsafe value -> DESER-002 at the call (and at the setting site when no call is found).
- Proven DESER-001 / XXE-001 come from `rules_taint` via the new sink kinds (high, attached to routes); `rules_deser_xml` must not duplicate them.
- XmlDocument safety per project target framework: `< v4.5.2` -> unsafe unless `XmlResolver = null` is set on the instance before Load; `>= v4.5.2` -> unsafe only when `XmlResolver` is set to a non-null resolver.

- [ ] **Step 1: Failing tests** -- positives/negatives per rule; proven vs REVIEW split for DESER-001 and XXE-001; Review Focus 4 test; XXE-002 once per project.
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: insecure deserialization and XXE rules"`

---

### Task 5: Integrity (SRI, ViewState MAC) and session/auth code rules

**Files:**
- Create: `checks/dnl/rules_integrity.py`, `checks/dnl/rules_session.py`
- Modify: `core/owasp_web.py` (INT-003..004, SESS-006..008), README rows, analyzers wiring (`rules_integrity.check(model)` in the config analyzer's results or `_code_results` -- markup findings attach to the WebForms page route when the file is a routed page; layouts/masters are route-less)
- Extend fixtures: `taint_app` MVC `Views/Shared/_Layout.cshtml` with a CDN script without integrity, one with `integrity`, and `~/Scripts/app.js` (never flagged); a WebForms `Site.master` with an external stylesheet without integrity; a page directive with `EnableViewStateMac="false"` and one with `ViewStateEncryptionMode="Never"`; an `AccountController` with `LogOff` (SignOut without Session.Abandon), `Login` (SetAuthCookie without session renewal), a `LoginSafe` doing `Session.Abandon()`, a plaintext `user.Password == model.Password` compare and a `Crypto.VerifyHashedPassword` compare.
- Test: `tests/test_dnl_integrity_session.py`

**Interfaces:**
- `rules_integrity.check(model) -> list[Finding]` -- markup scan of .cshtml/.vbhtml/.master/.aspx/.ascx/.html/.htm under legacy project dirs (via `iter_dnl_files`, `read_source`); tag attributes parsed case-insensitively with single/double/unquoted values; Razor `@Url.Content("~/...")` and `<%: ResolveUrl("~/...") %>` values are relative; INT-003 one finding per (file, line) (Review Focus 5); INT-004 from `<%@ Page|Control|Master ... %>` directives.
- `rules_session.check(model, refs) -> list[Finding]` -- SESS-006/007 per action/handler (MVC/Web API actions from refs, WebForms page methods, plus any project method whose name matches), call names matched case-insensitively with `sym` when available; SESS-008 per comparison expression, anchored at its line; attach the route when inside a route handler.

- [ ] **Step 1: Failing tests** -- positives/negatives per rule; Review Focus 5 (layout tag reported once; `~/` and `/` paths never).
- [ ] **Step 2: Run**, FAIL. **Step 3: Implement.** **Step 4: Run**, PASS.
- [ ] **Step 5: Commit** `git commit -m "dotnet_legacy: SRI, ViewState MAC and session/auth code rules"`

---

### Task 6: Wrap-up -- README, Linux run, real-target smoke run

**Files:**
- Modify: `languages/dotnet_legacy/README.md` (WCF section: discovery, auth sources, config rules; crypto/secrets/deser/XXE/integrity/session sections with known limits), root `README.md` feature line.
- Test: extend `tests/test_dnl_end_to_end.py` -- `wcf_app` end-to-end: JSON contains a `wcf` framework result with routes, DNL-WCF-* and DNL-INJ-001 on a WCF route.

- [ ] **Step 1:** Full suite on Windows, then the Linux container run (same docker command as Plan 2 Task 9). Report the tail.
- [ ] **Step 2:** Real-target smoke run with outputs outside the repo; report exit code, runtime, per-rule counts for the new rules, proven vs REVIEW split, crashes/notes. Fix generic bugs only via synthetic reproductions. Never copy target code or names into the repo or commit messages.
- [ ] **Step 3: Commit** `git commit -m "dotnet_legacy: WCF/crypto/deser/XXE/integrity README and end-to-end checks"`
