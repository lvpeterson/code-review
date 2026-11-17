# Rule families carried over from the legacy engine

Rule modules shared with `dotnet_legacy` that also run on SDK projects. The Core route refs
(`CoreRouteRef`) subclass the legacy `RouteRef`, so the modules take them unchanged.

| family | ids | runs on Core | reason |
|---|---|---|---|
| crypto and hardcoded secrets | DNL-CRY-001..008, DNL-SEC-003 | yes | pure code rules; types are matched by symbol when resolved, else by the names written in source |
| deserialization / XXE | DNL-DESER-001..003, DNL-XXE-001 | yes | Json.NET is matched by name (it never resolves against the framework packs); the taint solver is not run on Core, so every insecure parse / formatter call is reported by the rule itself (`CORE_RUNS_TAINT` in `analyzers.py`; flip it when `rules_taint` is wired in) |
| XML parser defaults | DNL-XXE-002 | no effect | only fires below .NET Framework 4.5.2, which SDK projects never target |
| integrity (SRI) | DNL-INT-003 | yes | text scan of `.cshtml` layouts and views |
| ViewState | DNL-INT-004 | no | WebForms directives (`.aspx`, `.ascx`, `.master`) do not exist in SDK projects |
| exception handling | DNL-ERR-001..003 | yes | read the IR `try` statements; Core idioms (`IAuthorizationFilter.OnAuthorization`, `IActionResult` sinks such as `Ok` / `Content` / `Problem`) are matched by name |
| logging | DNL-LOG-003, DNL-LOG-004 | yes | `ILogger<T>` / Serilog receivers are recognised by declared type or name, never by `sym` (they are NuGet types and do not resolve against the framework packs) |
| no logging framework | DNL-LOG-002 | no | the finding is anchored on a legacy project file; an SDK-only model has no anchor, so it is never emitted for Core |
| business flows, API consumption | DNL-DES-001, DNL-CONSUME-001, DNL-CONSUME-002 | yes | `[EnableRateLimiting]` / `CheckPasswordSignInAsync(.., lockoutOnFailure: true)` count as protection. CONSUME-002 reads the taint solver's outbound-response flows and only reaches the sinks the shared taint tables list for Core (for example `Process.Start`); the System.Web.Mvc-only sinks (`Controller.Redirect`) are not in it, so a response flowing into them is not reported until the Core taint tables arrive with `CORE_RUNS_TAINT` |
| resources and inventory | DNL-RES-002, DNL-RES-003, DNL-INV-002 | yes | Core gaps closed in `rules_resources`: the `controller` route kind, `IFormFile.CopyTo(Async)` as the save and `IFormFile.Length` as the size check (uploads passed as `IFormFileCollection` / loop variables are not followed), and a `UseSwagger()` call that the pipeline only runs outside Production (`if (env.IsDevelopment())`) is not reported. The Web.config swagger deny rule is legacy-only (no config is loaded for Core) |
| session | DNL-SESS-008 | yes | plaintext password comparison; hashed comparison through `IPasswordHasher` / `VerifyHashedPassword` is not flagged |
| session lifecycle | DNL-SESS-006, DNL-SESS-007 | no | match `FormsAuthentication` / OWIN `AuthenticationManager` sign-in and sign-out only; Core's `SignInAsync` / `SignOutAsync` are not matched |
| System.Web-only constructs | `FormsAuthentication`, `MachineKey`, `HttpContext.Current`: legacy rules DNL-SESS-006 / DNL-SESS-007 (rules_session), DNL-INT-002 (machineKey in Web.config) and the legacy source tables (taint_tables, rules_object, rules_resources) match them | no | the types are absent on Core and Web.config checks are not run on Core, so none fire; not in the Core fixture. DNL-CRY-001 itself still fires on Core through MD5 / SHA1; only its `HashPasswordForStoringInConfigFile` branch is System.Web-specific |

Caveat: DNL-DESER-003 (see the deserialization row) is by-name on Core. `JavaScriptSerializer` and
`SimpleTypeResolver` do not exist in the net8.0 reference packs; the rule matches the name, so a ported or
shimmed type is still flagged.
