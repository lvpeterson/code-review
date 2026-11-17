# Rule families carried over from the legacy engine

Rule modules shared with `dotnet_legacy` that also run on SDK projects. The Core route refs
(`CoreRouteRef`) subclass the legacy `RouteRef`, so the modules take them unchanged.

| family | ids | runs on Core | reason |
|---|---|---|---|
| crypto and hardcoded secrets | DNL-CRY-001..008, DNL-SEC-003 | yes | pure code rules; types are matched by symbol when resolved, else by the names written in source |
| deserialization / XXE | DNL-DESER-001..003, DNL-XXE-001 | yes | Json.NET is matched by name (it never resolves against the framework packs); the taint solver is not run on Core, so every insecure parse / formatter call is reported by the rule itself (`taint_reports=False`) |
| XML parser defaults | DNL-XXE-002 | no effect | only fires below .NET Framework 4.5.2, which SDK projects never target |
| integrity (SRI) | DNL-INT-003 | yes | text scan of `.cshtml` layouts and views |
| ViewState | DNL-INT-004 | no | WebForms directives (`.aspx`, `.ascx`, `.master`) do not exist in SDK projects |
| System.Web-only constructs | `FormsAuthentication`, `MachineKey`, `HttpContext.Current` | no | the types do not exist in ASP.NET Core; not part of the Core fixture |
