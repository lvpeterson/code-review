# Go: gin, net_http

Route extraction uses `tree-sitter-go`. `_ts_utils.py` is the same trivial
node-text/walk-helper pattern duplicated per language (not shared) as every
other tree-sitter-based analyzer in this repo.

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
- **Handler resolution**: a project-wide index of top-level function
  declarations (Go handlers are almost always separate named functions,
  unlike JS's frequent inline arrows).
- **Auth**: `auth_decorators` = every middleware arg before the final
  handler, **plus** a body-text scan of the resolved handler for any known
  indicator called *inside* the function (not just passed as a router-chain
  middleware arg) -- the union of both is what other frameworks here don't
  do (most only check one or the other). `KNOWN_AUTH_INDICATORS =
  {authMiddleware, AuthMiddleware, requireAuth, AuthRequired, JWTAuth}`
  (same set reused verbatim by net/http below).
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
- **Auth**: body-text scan of the resolved handler only -- `HandleFunc(path,
  handler)` has no middleware-chain argument position the way gin's
  variadic call does, so there's no separate middleware-arg capture here.
  Same `KNOWN_AUTH_INDICATORS` set as gin.
- **extra_param_names**: `.URL.Query().Get(...)` via `core/bodyscan.py`.
- **No global-auth detection, no CONFIG checks.**
- **Known gap (TODO in source)**: manual `http.Handler`-wrapping middleware
  chains (`loggingMiddleware(authMiddleware(handler))`) **are not traced**
  -- an auth wrapper applied this way is invisible to `auth_decorators`
  entirely, since it never appears as a call *inside* the handler body (the
  only place net/http's auth detection looks).

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
- **net/http's wrapped-middleware chains are invisible** -- if auth is
  applied via `http.Handler` wrapping rather than an in-body call, AUTH-001
  will false-positive; check the actual `HandleFunc` registration and
  anything wrapping it by hand.
- **No SQL/command/path/SSRF injection checks** -- none of the
  dangerous-sink checks built for Spring exist here yet. Trace
  `fmt.Sprintf`-built SQL, `exec.Command`, `os.Open(userPath)`,
  `http.Get(userUrl)` patterns manually.
- **No CONFIG checks** for either -- no CORS-wildcard, no debug-mode
  equivalent, no framework-version detection.
