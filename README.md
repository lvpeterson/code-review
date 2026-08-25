# appsec code review scaffold

Point it at a codebase; it detects language(s) and framework(s), then runs a
framework-specific "deep dive" that extracts routes and runs baseline
IDOR/auth-coverage heuristics to point a human auditor at what to look at
first. Nothing here proves a vulnerability -- it's triage tooling.

## Usage

```
pip install -r requirements.txt
python main.py <target_path>
python main.py <target_path> --json report.json
python main.py <target_path> --html report.html
python main.py <target_path> --language python --framework flask   # skip detection
```

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
  report.py                    console + JSON output
  html_report.py                self-contained interactive HTML report
checks/                    framework-agnostic heuristics, operate on Route objects
  idor.py                    flags routes with id-like path params
  auth.py                    flags routes with no recognized auth decorator/middleware
languages/<lang>/
  detector.py               detect_language() / detect_frameworks() for that language
  <framework>_analyzer.py    route extraction + baseline checks for one framework
```

Currently implemented (route extraction + baseline checks):
- **python**: flask, fastapi, django
- **java**: spring
- **javascript**: express

`detect_frameworks()` returns a *list* -- a codebase can trip more than one
framework in the same language (e.g. a Flask app that's grown FastAPI
services alongside it mid-migration), and each gets its own deep-dive and
its own section in the report, rather than one silently winning detection
and the other's routes going unscanned. See "Multiple frameworks in one
language" below for how Flask/FastAPI specifically avoid double-counting
the same route when both are present.

Detection-only stubs (framework gets identified but analyzer returns empty +
a note -- fill these in following the pattern of an implemented one):
- **go**: net/http, gin
- **ruby**: rails, sinatra
- **dotnet**: aspnet

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
- **javascript** (`express_analyzer.py`): `tree-sitter` with the
  `tree-sitter-javascript`/`tree-sitter-typescript` grammars -- prebuilt
  wheels, no Node.js or compiler required either.

The stub languages (go, ruby, dotnet) don't have a parser wired in yet.
Reasonable options when you get there: `go/ast` via a small Go helper
binary for Go, `tree-sitter-ruby`/`tree-sitter-c-sharp` (same tree-sitter
pattern as Express) for Ruby/.NET.

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
- `checks/idor.py` only flags the presence of an id-like path param -- it
  doesn't (yet) inspect the handler body for an ownership check. That's the
  natural next thing to build now that route extraction is AST-precise.
  It's also whole-word-aware (`_is_id_like()`), not substring matching --
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
