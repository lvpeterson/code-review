# Go: gin, net_http

Route extraction uses `tree-sitter-go`. `_ts_utils.py` is the same trivial
node-text/walk-helper pattern duplicated per language (not shared) as every
other tree-sitter-based analyzer in this repo -- plus one Go-specific
helper, `bare_name()`, that both `gin_analyzer.py` and `net_http_analyzer.py`
use to resolve a receiver-method call-site reference (`s.getOrder`) down to
the method's own bare name (`getOrder`), matching how the function/method
index below is keyed.

## Detection

`detector.py` checks `go.mod` text for `"gin-gonic/gin"` → gin. Any `.go`
file containing `.HandleFunc(` or `http.NewServeMux` → net_http. **Not
mutually exclusive** -- a real app commonly uses gin for its main API plus
a raw net/http health-check or pprof endpoint, and both get their own
section in the report. TODO in source: gorilla/mux, echo, fiber aren't
detected yet.

## Gin

- **Router confirmation**: only identifiers proven to be assigned from
  `gin.Default()`/`gin.New()` are trusted as a gin router -- an arbitrary
  struct's own `.GET`/`.POST` method (e.g. an HTTP client wrapper) is never
  mistaken for a route registration, unlike net/http's looser matching
  below.
- **Routes**: `<confirmedRouter>.<GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS>(path, ...handlers)`.
- **Handler resolution**: a project-wide index of both top-level function
  declarations **and** receiver methods (`func (s *Server) getOrder(...)`)
  -- keyed by bare method name via `bare_name()`, so a handler passed as
  `s.getOrder` (extremely common once handlers live on a struct holding
  dependencies, e.g. a DB connection) resolves to its real body just like a
  plain function reference would. Middleware args go through the same
  `bare_name()` resolution, so `s.authMiddleware` matches
  `KNOWN_AUTH_INDICATORS`'s `authMiddleware` too, not just a bare
  `authMiddleware` reference.
- **Auth**: `auth_decorators` = every middleware arg before the final
  handler, **plus** a body-text scan of the resolved handler for any known
  indicator called *inside* the function (not just passed as a router-chain
  middleware arg) -- the union of both is what other frameworks here don't
  do (most only check one or the other). `KNOWN_AUTH_INDICATORS =
  {authMiddleware, AuthMiddleware, requireAuth, AuthRequired, JWTAuth,
  requireToken, RequireToken}` (same set reused verbatim by net/http below).
- **extra_param_names**: `c.Query(...)`/`c.PostForm(...)` via
  `core/bodyscan.py`.
- **No global-auth detection, no CONFIG checks.**
- **Known gap (TODO in source)**: `router.Group("/api")` prefix nesting
  (gin's version of Express's sub-router mounting) **is not resolved** --
  routes registered on a group report only their bare sub-path, missing the
  group's prefix entirely. If a codebase uses `.Group()`, treat every
  gin route's reported path as potentially incomplete until verified.

## net/http

- **Routes**: any `<x>.HandleFunc(path, handler)` call -- matches both
  `http.HandleFunc` (package-level) and `mux.HandleFunc` on a `ServeMux`,
  with **no router-confirmation step** (unlike gin's veto pattern above --
  any object with this exact method name qualifies).
- **Method extraction, three-tier fallback**: (1) Go 1.22+ `"GET /path"`
  prefix syntax split directly; (2) sniff `r.Method == "GET"`-style
  comparisons in the resolved handler body; (3) default to
  `["GET","POST","PUT","PATCH","DELETE"]` if neither yields anything,
  rather than under-reporting.
- **Auth**: body-text scan of the resolved handler, **plus** handler-arg
  unwrapping -- `HandleFunc(path, handler)` has no separate middleware-chain
  argument position the way gin's variadic call does, but wrapping the
  handler is net/http's idiomatic equivalent
  (`mux.HandleFunc("/db", n.requireToken(n.handleCreateDB))`).
  `_unwrap_handler_arg()` recurses through arbitrarily stacked wrapping
  (`log(requireToken(handler))` unwraps fully), resolving the real handler
  name for indexing and capturing each wrapper's name as an
  `auth_decorator` -- the same role gin's middleware-chain args play. Same
  `KNOWN_AUTH_INDICATORS` set as gin.
- **extra_param_names**: `.URL.Query().Get(...)` via `core/bodyscan.py`,
  scanned off the unwrapped handler's real body.
- **No global-auth detection, no CONFIG checks.**
- **Remaining gap**: only a wrapping *call* is unwrapped -- middleware
  applied via a separately-built `http.Handler` chain assigned to a
  variable first (`h := authMiddleware(handleCreateDB); mux.Handle("/db",
  h)`) isn't traced back to the `HandleFunc`/`Handle` call that registers
  it, since that's a different statement this tool doesn't connect.

## Dangerous sinks (CMD-001/PATH-001/SSRF-001/REDIRECT-001)

One shared module, `languages/go/dangerous_sinks.py` (built on the same
`_ts_utils.py` helpers gin/net_http already share), called from both
frameworks' `run_baseline_checks`. Presence-only, same philosophy as every
other dangerous-sink check in this tool: flags a call with a non-literal
argument, never a real taint trace.

- **CMD-001**: `exec.Command(...)`/`exec.CommandContext(...)` flagged when
  *any* argument is non-literal -- covers both a non-literal program name
  and the classic `exec.Command("sh", "-c", userInput)` gadget, since
  either position being attacker-controlled is worth a look. Go's
  `os/exec` doesn't invoke a shell by default, unlike Java's
  `Runtime.exec`, so the risk is specifically the program/args themselves,
  not implicit shell interpretation.
- **PATH-001**: `os.Open/ReadFile/WriteFile/Create/Remove` with a
  non-literal first argument.
- **SSRF-001**: `http.Get/Post/PostForm` (URL is the 1st arg),
  `http.NewRequest` (URL is the 2nd arg, after the method string),
  `http.NewRequestWithContext` (URL is the 3rd arg, after ctx and method)
  -- three different argument positions for the same "is the URL literal"
  check, since the stdlib's own signatures differ.
- **REDIRECT-001**: two distinct call shapes, matched by object name:
  `http.Redirect(w, r, url, code)` (net/http package-level func, url is
  the 3rd arg) and gin's `c.Redirect(code, url)` (url is the 2nd arg,
  since gin has no separate writer/request args to thread through).
- **Not covered**: any HTTP client other than the stdlib's own `http.Get/
  Post/PostForm/NewRequest*` (a third-party client like `resty` or
  `go-resty` isn't recognized), and SQL injection -- no
  `fmt.Sprintf`-built-query check exists for Go at all.

## What still needs a human

- **Ownership-check tracing** -- IDOR-001 flags the id-like param exists,
  never whether the handler actually checks ownership.
- **No global-auth-mechanism detection for either framework** -- unlike
  Flask/FastAPI/Django/Express/Spring, there's no equivalent check here at
  all. If auth is enforced entirely via a global middleware chain, **every
  route without an explicit per-route indicator will be flagged**, and
  you'll need to manually confirm the global mechanism's coverage yourself
  -- there's no caveat auto-attached to the finding the way other languages
  get.
- **gin's `.Group()` prefix is unresolved** -- verify every gin route's
  actual mounted path by hand if the codebase uses route groups; the
  reported path may be missing a prefix.
- **net/http's wrapped-middleware chains are unwrapped only at the
  `HandleFunc(path, wrapper(handler))` call site itself** -- a chain built
  as a separate statement first (`h := authMiddleware(handleCreateDB);
  mux.Handle("/db", h)`) isn't traced back to it, and `mux.Handle` (as
  opposed to `HandleFunc`) isn't recognized as a route registration at all;
  check either pattern by hand if the codebase uses them.
- **No SQL injection check** -- unlike Spring's SQLI-001, `fmt.Sprintf`-built
  SQL isn't detected; trace it by hand. CMD-001/PATH-001/SSRF-001/
  REDIRECT-001 *are* covered now -- see above.
- **No CONFIG checks** for either -- no CORS-wildcard, no debug-mode
  equivalent, no framework-version detection.
