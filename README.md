# appsec code review scaffold

Point it at a codebase; it detects language(s) and framework(s), then runs a
framework-specific "deep dive" that extracts routes and runs baseline
appsec heuristics (auth coverage, input validation, injection sinks, and
more depending on the framework -- see per-language READMEs below) to point
a human auditor at what to look at first. **Nothing here proves a
vulnerability -- every finding is a heuristic pointer, not a verdict.** It
can't trace whether user input actually reaches a flagged sink, whether a
manual check elsewhere already covers a gap, or whether something's
enforced entirely outside the scanned repo (a gateway, a separate frontend).
That trace is always yours.

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
collision, the project-wide-vs-per-file supertest resolution bug, the
regex-truncated `produces`/`consumes` array) as actual regressions instead
of one-off manual fixtures. `pyproject.toml` also makes this pip-installable
(`appsec-review` console script via `main:main`).

## Usage

```
pip install -r requirements.txt
python main.py <target_path>
python main.py <target_path> --json report.json
python main.py <target_path> --html report.html
python main.py <target_path> --sarif report.sarif
python main.py <target_path> --language python --framework flask   # skip detection
python main.py <target_path> --allow-path "/health" --allow-path "/api/public/*"
python main.py <target_path> --fail-on medium   # exit 1 if any medium+ finding exists (CI use)
```

`--allow-path` (repeatable, glob-style) suppresses AUTH-001 on routes you've
already confirmed are intentionally public -- health checks, login itself,
public webhooks -- so they don't get reflagged every run. It only suppresses
AUTH-001; an allowlisted route's other findings still show up, since "safe
to be unauthenticated" doesn't mean "safe to have no ownership check" or
"not a config problem." See `core/allowlist.py`.

`--fail-on {high,medium,low,info}` exits 1 if any finding at or above that
severity exists anywhere in the scan -- for wiring this into CI so a build
actually fails on new findings instead of just printing them.

### `--sarif`: for GitHub Code Scanning / VS Code's SARIF Viewer

Writes every finding across the whole scan (route-tied and project-wide
alike) as a SARIF 2.1.0 document (`core/sarif_report.py`), grouped by
`check_id` into SARIF "rules" -- every SARIF-aware viewer groups/filters by
rule automatically, which is what gives a "work through one category at a
time" triage experience without this tool needing to build that UI itself.
Upload it via `github/codeql-action/upload-sarif` for PR annotations and
Security-tab alerts, or open it in VS Code's SARIF Viewer extension.

### `--html`: the interactive report

Writes a single self-contained HTML file (no external assets, so it opens
fine offline), split into three tabs:

- **Routes** -- one collapsible card per route, syntax-highlighted.
  Expanding a card shows the full handler source with line numbers, an
  `input:` line calling out every attacker-controlled value flowing in
  (path/query/body params, regardless of whether it looks like an object
  id), a `validation:` line where the framework supports it, and the
  associated input/validation findings (IDOR, framework-specific validation
  checks). Every occurrence of a path/query parameter name inside the
  handler body is also underlined -- purely a visual pointer to where
  user-controlled input enters the function
  (`core/paths.py:extract_path_param_names()` +
  `core/html_report.py:_highlight_params()`), not a traced dataflow to any
  sink. Routes are sorted worst-severity-first by default; the sidebar has
  severity/method/language filters plus a text search box.
- **Authentication** -- every auth-related finding gathered in one place:
  project-wide auth-infrastructure findings (is the enforcement mechanism
  even wired up at all -- see "Auth coverage vs. auth infrastructure"
  below) plus a per-route table showing each route's resolved auth status.
  Kept separate from the Routes tab so a route card's severity/sort
  reflects only input/validation coverage, not a mix of two concerns.
- **Findings** -- every other project-wide finding that doesn't attach to
  a single route and isn't specifically about authentication (dangerous-
  sink checks, deserialization, AOP bypass, general config findings).
- **Download SARIF** button (topbar) -- exports just the Authentication +
  Findings tab items (route-tied findings already have a richer view on
  their own card, so including them here would just be re-triaging the
  same thing twice). Uses a native "Save As" picker where the browser
  supports it (`showSaveFilePicker` -- Chrome/Edge; Firefox/Safari fall
  back to a normal browser download).

Every route card and every standalone finding has a checkbox to mark it
reviewed as you triage -- reviewed items dim and get a strikethrough, "Hide
reviewed" in the topbar filters them out entirely, and each
finding-listing section shows its own "X / Y reviewed" count. This persists
in the browser's local storage keyed to the target path, so it survives
closing and reopening the same report file (but not a fresh `--html` run
somewhere else, or a different browser). "Reset reviewed" clears it.

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
  html_report.py                self-contained interactive HTML report (3 tabs)
  sarif_report.py                SARIF 2.1.0 export, shared by --sarif and the HTML report's download button
  paths.py                     path-param extraction + mount-prefix resolution (shared)
  bodyscan.py                  regex scan for request.X/req.X field reads (shared)
  allowlist.py                 --allow-path glob suppression of AUTH-001
checks/                    heuristics that build Finding objects from Route data
  idor.py                    IDOR-001 -- id-like path or query/body params (all languages)
  auth.py                    AUTH-001..006 -- auth coverage + infrastructure (AUTH-001 all languages, 002-006 Spring only so far)
  config.py                  CONFIG-001..003 -- debug mode / CORS wildcard / outdated framework version
  validation.py               VALID-001/002 -- Bean Validation wiring (Spring only)
  xml.py                       XML-001 -- XXE-adjacent produces/consumes detection (Spring only)
  deserialization.py            DESER-001 -- unsafe Jackson polymorphic typing (Spring only)
  injection.py                   CMD-001/PATH-001/SSRF-001/REDIRECT-001 -- dangerous-sink checks (Spring only)
  binding.py                      MASS-001/SORT-001 -- request-binding shape checks (Spring only)
  sqli.py                          SQLI-001 -- SQL/JPQL built via string concatenation (Spring only)
  aop.py                            PROXY-001 -- AOP proxy self-invocation bypass (Spring only)
languages/<lang>/
  README.md                 what this language's analyzer(s) check, and what's still manual -- READ THIS FIRST when reviewing a codebase in this language
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

**Every `languages/<lang>/README.md` is the fast reference for that
language** -- exactly which checks run, exactly what triggers each one, and
a checklist of what still needs a human look, so you're not duplicating
effort the tool already covers or missing a gap it doesn't. Start there
before reviewing a codebase in that language. Java/Spring's is by far the
most detailed, since that's where most of this tool's check coverage lives
today -- the other five languages currently share a much smaller baseline
(mainly IDOR-001 + AUTH-001, plus one or two framework-specific extras).

`detect_frameworks()` returns a *list* -- a codebase can trip more than one
framework in the same language (e.g. a Flask app that's grown FastAPI
services alongside it mid-migration, or a Go service using gin for its main
API plus a raw net/http health-check endpoint), and each gets its own
deep-dive and its own section in the report, rather than one silently
winning detection and the other's routes going unscanned.

## Adding a new framework to an existing language

1. Create `languages/<lang>/<framework>_analyzer.py`, subclassing
   `BaseFrameworkAnalyzer` and implementing `find_routes()` +
   `run_baseline_checks()`. Decorate the class with
   `@register("<lang>", "<framework>")`.
2. Teach `languages/<lang>/detector.py`'s `detect_frameworks()` to recognize it.
3. Import the new module in `languages/<lang>/__init__.py`.
4. Update `languages/<lang>/README.md` with what it checks and what it doesn't.

## Adding a new language

1. Create `languages/<newlang>/` with `detector.py` (`detect_language()` +
   `detect_frameworks()`), one `<framework>_analyzer.py` per framework, and
   a `README.md` (see any existing one for the expected shape).
2. Add an `__init__.py` that imports the detector and every analyzer module
   (this is what triggers registration).
3. Import the new package in `languages/__init__.py` and add it to
   `LANGUAGE_MODULES` in `enumerator.py`.

## How route extraction works per language

Every implemented analyzer parses a real AST instead of pattern-matching
text -- this is what lets them tell "the class-level `@RequestMapping`" from
"a route", or find an auth decorator regardless of which line it's on
relative to the route decorator.

- **python**: stdlib `ast` module, no dependency. Shared decorator/call-parsing
  helpers live in `languages/python/_ast_utils.py`.
- **java**: the `javalang` package -- a pure-Python Java parser, so no
  JDK/Node is required to run this.
- **javascript**: `tree-sitter` with the `tree-sitter-javascript`/
  `tree-sitter-typescript` grammars -- prebuilt wheels, no Node.js or
  compiler required either.
- **go**: `tree-sitter-go`.
- **dotnet**: `tree-sitter-c-sharp`. tree-sitter gives real start/end
  positions natively here, unlike javalang for Spring, which needed manual
  brace-counting (`_method_end_line()`).
- **ruby**: `tree-sitter-ruby`.

All five tree-sitter grammars are prebuilt wheels (no JDK/Node/Go/.NET/Ruby
toolchain needed on the machine actually running this tool) -- every
`languages/<lang>/_ts_utils.py` is the same trivial node-text/walk-helper
pattern duplicated per language rather than shared, matching this repo's
existing convention (`_ast_utils.py` is the one deliberately shared module,
for Python specifically).

## Auth coverage vs. auth infrastructure

`checks/auth.py`'s **AUTH-001** only checks *per-route* auth decorators/
middleware. That's necessary but not sufficient -- a route can carry a
perfectly good `@PreAuthorize`/`@login_required`/etc. and still be
completely unenforced if the framework-level mechanism that's supposed to
evaluate it was never wired up (Spring's `@EnableMethodSecurity` missing
entirely is the clearest example -- see `languages/java/README.md`), or a
route can carry *no* decorator at all and still be fully covered by a
global mechanism (a Flask `@before_request`, FastAPI's app-level
`dependencies=[Depends(...)]`, Django REST Framework's
`DEFAULT_PERMISSION_CLASSES`, a Spring `SecurityFilterChain` bean, an
Express `app.use(authMiddleware)`). Without detecting the global case, an
app that does auth entirely through one of these would get every single
route flagged; without detecting the infrastructure case, a route that
*looks* protected gets treated as done when it isn't.

Global-mechanism detection (where implemented -- see each language's
README for which frameworks have it) is deliberately **presence-only, not
per-route**: it tells you *some* global mechanism exists somewhere in the
project, not which specific routes it actually covers. Determining that
precisely means simulating each framework's real path-matching/
registration-order semantics -- Spring's Ant-style matcher chain is the one
framework here that goes further and actually resolves this per-route (see
`languages/java/README.md`); every other framework just attaches a caveat
to each AUTH-001 finding pointing at where the global mechanism lives, for
you to verify by hand.

## Notes on the current heuristics

- `checks/auth.py` only knows about auth indicators listed per-analyzer
  (`KNOWN_AUTH_INDICATORS`) -- tune those to match a specific codebase's
  actual auth decorator/middleware names, or you'll get noisy false
  positives on intentionally-public routes.
- `checks/idor.py` flags the presence of an id-like path *or* query/body
  param -- it doesn't inspect the handler body for an actual ownership
  check (`if resource.owner_id != current_user.id`). It's whole-word-aware
  (`_is_id_like()`), not substring matching -- `valid`/`width`/`hidden`/
  `provider`/`guide` all *contain* "id"/"uuid" as a substring without being
  object identifiers, so a naive substring check would drown real findings
  in noise. Also splits on hyphens (`order-id`) and camelCase boundaries,
  not just underscores.
- Every dangerous-sink-style check across this tool (SQL/command/path/SSRF
  injection, open redirect -- Spring-only today, see
  `languages/java/README.md`) is **presence-only**: it flags that a
  dangerous API was called with a non-literal (or, for SQL specifically,
  concatenated) argument, not that user input actually reaches it. That
  trace is always manual.
