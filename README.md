# appsec code review scaffold

Point it at a codebase; it detects language(s) and framework(s), then runs a
framework-specific "deep dive" that extracts routes and runs baseline
IDOR/auth-coverage heuristics to point a human auditor at what to look at
first. Nothing here proves a vulnerability -- it's triage tooling.

## Testing

```
pip install -e ".[dev]"
pytest
```

`tests/` has pure-logic unit tests for the framework-agnostic pieces
(`checks/idor.py`, `checks/auth.py`, `core/paths.py`, `core/bodyscan.py`,
`core/allowlist.py`) plus one integration test file per implemented analyzer
that writes small fixture files into `tmp_path` and runs the real
`find_routes()`/`run_baseline_checks()` pipeline -- these are what would
have caught several of the bugs found and fixed along the way (the
class-level `@RequestMapping` double-count, the `unittest.mock.patch`
collision, the project-wide-vs-per-file supertest resolution bug) as actual
regressions instead of one-off manual fixtures. `pyproject.toml` also makes
this pip-installable (`appsec-review` console script via `main:main`).

## Usage

```
pip install -r requirements.txt
python main.py <target_path>
python main.py <target_path> --json report.json
python main.py <target_path> --html report.html
python main.py <target_path> --language python --framework flask   # skip detection
python main.py <target_path> --allow-path "/health" --allow-path "/api/public/*"
python main.py <target_path> --fail-on medium   # exit 1 if any medium+ finding exists (CI use)
```

`--allow-path` (repeatable, glob-style) suppresses AUTH-001 on routes you've
already confirmed are intentionally public -- health checks, login itself,
public webhooks -- so they don't get reflagged every run. It only suppresses
AUTH-001; an allowlisted route's IDOR-001/CONFIG-* findings still show up,
since "safe to be unauthenticated" doesn't mean "safe to have no ownership
check" or "not a config problem." See `core/allowlist.py`.

`--fail-on {high,medium,low,info}` exits 1 if any finding at or above that
severity exists anywhere in the scan -- for wiring this into CI so a build
actually fails on new findings instead of just printing them.

`--html` writes a single self-contained HTML file (no external assets, so it
opens fine offline) with one collapsible card per route, syntax-highlighted.
Expanding a card shows the full handler source with line numbers, the
associated baseline findings, and an "open in editor" link
(`vscode://file/...`) that jumps straight to that file:line if VS Code is
installed. Every occurrence of a path parameter (`user_id`, `orderId`, ...)
inside the handler body is also underlined -- this is *only* a visual
pointer to where user-controlled input enters the function (see
`core/paths.py:extract_path_param_names()` + `core/html_report.py:_highlight_params()`),
not a traced dataflow to any sink; it can't tell you whether that value
actually reaches something dangerous, only where it shows up textually.
Routes are sorted worst-severity-first within each section by default; the
"Sort" dropdown re-orders by path/method/file instead. The sidebar has
severity/method/language filters plus a text search box, all composable
together.

Each route also has a checkbox to mark it reviewed as you triage through
the list -- reviewed routes dim and get a strikethrough, and "Hide reviewed"
in the topbar filters them out entirely so you can watch the remaining list
shrink. This persists in the browser's local storage keyed to the target
path, so it survives closing and reopening the same report file (but not a
fresh `--html` run somewhere else, or opening it in a different browser).
"Reset reviewed" clears it.

## Layout

```
main.py                  CLI entry point
enumerator.py             detects language(s)/framework(s), dispatches to analyzers
core/
  models.py                Route / Finding / ScanResult dataclasses
  base.py                   BaseFrameworkAnalyzer -- every analyzer subclasses this
  registry.py                @register("language", "framework") decorator + lookup
  fsutil.py                   file-walking helpers shared by detectors/analyzers
  report.py                    console + JSON output, --fail-on severity comparison
  html_report.py                self-contained interactive HTML report
  paths.py                     path-param extraction + mount-prefix resolution (shared)
  bodyscan.py                  regex scan for request.X/req.X field reads (shared)
  allowlist.py                 --allow-path glob suppression of AUTH-001
checks/                    framework-agnostic heuristics, operate on Route objects
  idor.py                    flags routes with id-like path or query/body params
  auth.py                    flags routes with no recognized auth decorator/middleware
  config.py                  debug-mode / CORS-wildcard finding builders
languages/<lang>/
  detector.py               detect_language() / detect_frameworks() for that language
  <framework>_analyzer.py    route extraction + baseline checks for one framework
tests/                     pytest suite -- pure-logic unit tests + one integration
                             test file per implemented analyzer (tmp_path fixtures)
```

Currently implemented (route extraction + baseline checks):
- **python**: flask, fastapi, django
- **java**: spring
- **javascript**: express, nextjs
- **go**: gin, net_http
- **dotnet**: aspnet
- **ruby**: rails, sinatra

`detect_frameworks()` returns a *list* -- a codebase can trip more than one
framework in the same language (e.g. a Flask app that's grown FastAPI
services alongside it mid-migration, or a Go service using gin for its main
API plus a raw net/http health-check endpoint), and each gets its own
deep-dive and its own section in the report, rather than one silently
winning detection and the other's routes going unscanned. See "Multiple
frameworks in one language" below for how Flask/FastAPI specifically avoid
double-counting the same route when both are present.

Nothing is a pure detection-only stub anymore, but feature depth varies --
see "Feature depth by framework" below for exactly what each one does and
doesn't have yet (mount-prefix composition, query/body param IDOR, debug/CORS
checks, controller-to-source resolution).

## Adding a new framework to an existing language

1. Create `languages/<lang>/<framework>_analyzer.py`, subclassing
   `BaseFrameworkAnalyzer` and implementing `find_routes()` +
   `run_baseline_checks()`. Decorate the class with
   `@register("<lang>", "<framework>")`.
2. Teach `languages/<lang>/detector.py`'s `detect_frameworks()` to recognize it.
3. Import the new module in `languages/<lang>/__init__.py`.

## Adding a new language

1. Create `languages/<newlang>/` with `detector.py` (`detect_language()` +
   `detect_frameworks()`) and one `<framework>_analyzer.py` per framework.
2. Add an `__init__.py` that imports the detector and every analyzer module
   (this is what triggers registration).
3. Import the new package in `languages/__init__.py` and add it to
   `LANGUAGE_MODULES` in `enumerator.py`.

## How route extraction works per language

Every implemented analyzer parses a real AST instead of pattern-matching
text -- this is what lets them tell "the class-level `@RequestMapping`" from
"a route", or find `@login_required` regardless of which line it's on
relative to the route decorator.

- **python** (`flask_analyzer.py`, `fastapi_analyzer.py`, `django_analyzer.py`):
  stdlib `ast` module, no dependency. Shared decorator/call-parsing helpers
  live in `languages/python/_ast_utils.py`.
- **java** (`spring_analyzer.py`): the `javalang` package -- a pure-Python
  Java parser, so no JDK/Node is required to run this.
- **javascript** (`express_analyzer.py`, `nextjs_analyzer.py`): `tree-sitter`
  with the `tree-sitter-javascript`/`tree-sitter-typescript` grammars --
  prebuilt wheels, no Node.js or compiler required either.
- **go** (`gin_analyzer.py`, `net_http_analyzer.py`): `tree-sitter-go`.
- **dotnet** (`aspnet_analyzer.py`): `tree-sitter-c-sharp`. tree-sitter gives
  real start/end positions natively here, unlike javalang for Spring, which
  needed manual brace-counting (`_method_end_line()`).
- **ruby** (`rails_analyzer.py`, `sinatra_analyzer.py`): `tree-sitter-ruby`.

All five tree-sitter grammars are prebuilt wheels (no JDK/Node/Go/.NET/Ruby
toolchain needed on the machine actually running this tool) -- every
`languages/<lang>/_ts_utils.py` is the same trivial node-text/walk-helper
pattern duplicated per language rather than shared, matching this repo's
existing convention (`_ast_utils.py` is the one deliberately shared module,
for Python specifically).

## Next.js: file-based routing is a different shape of problem

Every other JS/Go/C#/Ruby framework here registers routes via an explicit
call (`app.get(path, handler)`, `router.GET(path, handler)`, `[HttpGet(...)]`
-- something to pattern-match against). Next.js doesn't: a route's URL comes
from the *file's own path* in the tree, not from anything textually inside
it. `nextjs_analyzer.py` supports both routing conventions:

- **App Router** (`app/**/route.{js,ts}`): named exports `GET`/`POST`/...,
  each becomes its own route. Dynamic segments (`[id]`, `[...slug]`,
  `[[...slug]]`) become path params; route groups (`(group)`) are stripped
  since they don't appear in the URL at all.
- **Pages Router** (`pages/api/**/*.{js,ts}`): one default-export handler,
  typically branching on `req.method` -- sniffed the same way Go's
  net/http analyzer sniffs `r.Method` when there's no more explicit signal.

Global auth is `middleware.ts`'s exported `middleware` function (Next.js's
equivalent of Flask's `before_request`/Express's `app.use()`), detected the
same presence-only way as every other framework's global-auth check.

## Rails: routes.rb is a DSL, not a list of calls

`config/routes.rb` wraps everything in `Rails.application.routes.draw do
... end`, and most of it isn't "one call = one route" the way everything
else here is: `resources :orders` alone expands to the 7 standard RESTful
routes (index/new/create/show/edit/update/destroy), and `namespace`/`scope`
blocks add a path prefix to everything nested inside them, so
`rails_analyzer.py` walks the DSL recursively tracking an accumulated
prefix stack rather than doing a flat scan. Global auth is a
`before_action :authenticate_user!`-shaped call in
`app/controllers/application_controller.rb`, which every controller
inherits from by default -- same shape as Flask's `before_request` check,
just Ruby's version of "runs before everything."

## Route mount-prefix composition

A route's *registered* path and its *real* path can differ once you mount
routers/blueprints under a prefix -- `@items_router.get("/{id}")` mounted via
`app.include_router(items_router, prefix="/api/v1")` really serves
`/api/v1/{id}`, not `/{id}`. Reporting the bare path would be actively
wrong, not just incomplete -- you could end up reviewing/testing the wrong
endpoint. Each analyzer resolves this by recording every "this thing got
mounted under this prefix" call project-wide, then walking the chain (a
router can itself be mounted into another router, e.g. FastAPI
`v1_router.include_router(items_router, prefix="/items")` then
`app.include_router(v1_router, prefix="/v1")`) via the shared
`core/paths.py:resolve_mount_prefix()`:

- **FastAPI**: `parent.include_router(child, prefix="...")`
- **Flask**: `Blueprint(..., url_prefix="...")` and/or
  `app.register_blueprint(bp, url_prefix="...")` (the latter wins if both
  are present, matching Flask's own precedence)
- **Express**: `parent.use('/prefix', child)` -- matched by variable name
  across files, same limitation as the handler-resolution index (a router
  required under one name and re-exported under a different name won't
  resolve)
- **Spring**: doesn't need this -- class-level `@RequestMapping` + method-level
  already live in the same file and were already being combined
- **Rails**: `namespace`/`scope` blocks in routes.rb are this same concept in
  DSL form -- `rails_analyzer.py` handles it directly as part of its
  recursive walk rather than a separate resolution pass
- **Not yet handled**: gin's `router.Group("/api")` (returns a sub-router
  you then call `.GET`/`.POST` on, same shape as Express) and Next.js's App
  Router (`route.js`'s directory path *is* the mount, so this doesn't apply
  there at all) -- .NET's two conventions don't have an equivalent either
  (Minimal API has no sub-router concept; attribute routing's `[Route]` is
  already same-file, same as Spring)

## Query/body parameters and IDOR

`checks/idor.py`'s IDOR-001 originally only looked at path parameters
(`/users/{user_id}`) -- but `/search?user_id=123` or a JSON body
`{"user_id": 123}` is just as much an object reference. Each analyzer now
also populates `Route.extra_param_names`, best-effort:

- **FastAPI**: every handler parameter that isn't a path param and doesn't
  have a `Depends(...)` default -- structurally precise, since FastAPI binds
  query/body params directly as typed function parameters.
- **Spring**: parameters annotated `@RequestParam`/`@RequestBody` -- also
  signature-based and precise.
- **Flask/Django/Express/Next.js/Go**: the same shared regex scan
  (`core/bodyscan.py`) of the handler body, one accessor pattern added per
  framework as it came up -- `request.args/form/json/GET/POST/data.get(...)`
  (Flask/Django), `req.query/body.x` (Express, also Pages Router),
  `searchParams.get(...)` (Next.js App Router), `.URL.Query().Get(...)` /
  `.Query(...)` / `.PostForm(...)` (Go). Shallower than the signature-based
  two above -- it can't see a field nested inside a larger dict/object/struct
  -- but catches the common direct-access case.
- **Not yet handled**: .NET (`[FromQuery]`/`[FromBody]` parameter
  attributes -- structurally precise like Spring/FastAPI, just not built
  yet) and Rails (routes.rb doesn't have a handler body to scan at all --
  this needs the controller#action resolution mentioned below first).

## Debug mode and CORS checks

Two new project-level checks (not tied to a specific route, so
`Finding.route` stays `None` for these) live in `checks/config.py`:

- **CONFIG-001** (debug mode): `app.run(debug=True)` / `app.debug = True`
  (Flask), `DEBUG = True` in settings.py (Django).
- **CONFIG-002** (CORS wildcard): a bare `@CrossOrigin` or explicit
  `origins="*"` (Spring), a bare `cors()` call or `origin: '*'`/`origin: true`
  (Express). Flask-CORS isn't covered yet -- same pattern (`CORS(app)` with
  no restriction defaults permissive) if you want to add it.

Neither check exists yet for Next.js, Go, .NET, or Ruby -- each has its own
version of both problems (Next.js CORS via `next.config.js` `headers()`;
Go's own `cors` middleware packages; ASP.NET's `[EnableCors]`; Rails'
`rack-cors` gem) but none of it's wired in.

## Rails routes aren't resolved to their controller source yet

Every other analyzer resolves a route's handler to its actual source
location -- Django's urls.py entry to the real view in views.py, Express's
named handler to wherever it's actually defined, even across files.
`rails_analyzer.py` doesn't do this yet: routes.rb tells you `orders#show`
maps to `/orders/:id`, but the report can only point you at the routes.rb
registration line, not `app/controllers/orders_controller.rb`'s `show`
method itself. This also means Rails routes get no per-route auth detection
or query/body param scanning (both need the controller body to look at) --
only the global `before_action` check and path-param IDOR currently apply.
Building the resolution (matching `resource_name#action` to
`app/controllers/<resource_name>_controller.rb`'s `def action`) would
unlock all three at once, the same way it did for Django.

## Global auth mechanisms

`checks/auth.py`'s AUTH-001 check only sees *per-route* auth decorators --
but a lot of real apps enforce auth globally instead: a Flask
`@before_request`, FastAPI's `dependencies=[Depends(...)]` on the app/router
constructor, Django REST Framework's `DEFAULT_PERMISSION_CLASSES` in
settings.py, a Spring `SecurityFilterChain` bean (arguably the *primary* way
most real Spring apps do auth -- `@PreAuthorize` is often just extra
restriction on top), or an Express `app.use(authMiddleware)`. Without
detecting these, an app that does auth entirely through one of them would
get every single route flagged.

Each analyzer's `analyze()` override (see `_detect_global_*` in each
`<framework>_analyzer.py`) checks for its framework's version of this and,
if found, calls `checks/auth.py:apply_global_auth_note()`, which attaches a
caveat both as a group-level note and appended to every AUTH-001 finding's
description.

This is deliberately **presence-only, not per-route**: it tells you *some*
global mechanism exists somewhere in the project, not which specific routes
it actually covers. Determining that precisely would mean simulating each
framework's real path-matching/registration-order semantics (Express's
registration order + path prefixes across mounted sub-routers, Spring
Security's Ant-style path patterns, Flask blueprint registration order) --
a lot of surface area for a heuristic tool to get wrong silently, especially
since getting it wrong here means *suppressing* a real finding rather than
just adding noise. If you want to build the precise version for a specific
framework later, Express is the most mechanically tractable one (linear
`app.use()`/`router.use()` call order + string path prefixes, no separate
path-pattern DSL to interpret).

## Multiple frameworks in one language

Flask 2.x's shortcut decorators (`@app.get(...)`, `@app.post(...)`) are
syntactically identical to FastAPI's -- decorator name alone can't tell them
apart. So `flask_analyzer.py` and `fastapi_analyzer.py` both consult a
shared index (`languages/python/_app_index.py`) built by scanning every
module for the actual constructor call (`Flask(...)`, `Blueprint(...)`,
`FastAPI(...)`, `APIRouter(...)`) each variable name is assigned to, and
each analyzer **vetoes** a match only when it can prove the object belongs
to the *other* framework.

If a name can't be resolved at all (most commonly: `app` constructed in one
module and imported into the blueprint/router modules that decorate
routes on it -- extremely common in both frameworks), both analyzers claim
it by default rather than either dropping it. That means a handful of
ambiguous cases can appear in both the Flask and FastAPI sections of the
report; that's the deliberate tradeoff, since under-reporting (silently
missing routes) is worse for an appsec triage tool than an occasional
duplicate you can tell apart by which app object it actually decorates.
Django doesn't need this treatment -- its urls.py registration syntax
doesn't overlap with Flask/FastAPI's decorator syntax at all.

There's a second, unrelated collision worth knowing about if you extend
these analyzers: `unittest.mock.patch` -- used constantly in test files as
`@patch(...)` or `@mock.patch(...)` -- parses to a decorator literally named
"patch", identical to `@app.patch(...)`. `mock_import_names()` in
`_ast_utils.py` tracks what a file imports from `unittest.mock` (module
alias, `from ... import patch`, `from unittest import mock`, etc) so both
analyzers can exclude it before it's ever treated as a route. If you add a
new HTTP-verb-named check anywhere, check whether some other common
decorator happens to share that name the same way.

## Populating the HTML report's code view

The HTML report's expandable code block comes from three optional `Route`
fields: `source_file` (defaults to `file` when unset), `source_start_line`,
`source_end_line`. When an analyzer can resolve a handler's full body range
it should set these -- see `languages/python/_ast_utils.py:source_range()`
(stdlib `ast` gives exact start/end lines for free), the brace-counting
`_method_end_line()` in `spring_analyzer.py` (javalang doesn't expose an end
position), or tree-sitter's `node.start_point`/`end_point` in
`express_analyzer.py` (exact by construction). If an analyzer leaves them
unset, the report just falls back to showing the single registration line
with a note that the body wasn't automatically resolved -- the stub
languages (go, ruby, dotnet) currently do this since they don't extract
routes at all yet.

## Notes on the current heuristics

- `checks/auth.py` only knows about auth indicators you list per-analyzer
  (`KNOWN_AUTH_INDICATORS`) -- tune those to match each codebase's actual
  auth decorators/middleware names, or you'll get noisy false positives on
  intentionally-public routes.
- `checks/idor.py` flags the presence of an id-like path *or* query/body
  param -- it doesn't inspect the handler body for an actual ownership
  check (`if resource.owner_id != current_user.id`). That's the natural
  next thing to build now that route extraction is AST-precise. It's also
  whole-word-aware (`_is_id_like()`), not substring matching --
  `valid`/`width`/`hidden`/`provider`/`guide` all *contain* "id"/"uuid"
  as a substring without being object identifiers, so a naive substring
  check drowns real findings in noise.
- `_extract_route_call()` in `express_analyzer.py` only skips a match when
  *this same file* locally shadows `app`/`router` with something proven
  not to be `express()`/`.Router()` **and** the file imports `supertest`
  (`agent.get('/path')` from a persistent supertest agent named "app"
  parses identically to a real route registration). Deliberately per-file,
  not project-wide, since JS variable binding is scoped per file -- the
  same name being a real Express object in one file says nothing about
  what it is in another.
- Two lower-probability collisions along the same lines that aren't handled
  yet, if you run into them: a Flask app coexisting with the (unrelated)
  Bottle framework, which also exports a bare `@route(...)` decorator; and
  `auth_decorators` in Flask/FastAPI/Express currently lists *every*
  non-route decorator/middleware/`Depends()` target, not just ones
  matching `KNOWN_AUTH_INDICATORS` (Spring and Django already filter to
  known indicators only) -- so the HTML report's "auth: ..." line can show
  an unrelated decorator (e.g. a caching one) on an actually-unprotected
  route. Harmless to the AUTH-001 check itself (it only alerts on the
  *absence* of a known indicator), just a cosmetic mismatch worth tightening
  if it causes confusion in practice.
- Express's `_ROUTER_OBJECT_NAMES` only recognizes variables literally named
  `app`/`router` -- it doesn't trace `const foo = express.Router()` to catch
  arbitrary variable names. Extend `_extract_route_call` if this codebase
  uses different naming.
